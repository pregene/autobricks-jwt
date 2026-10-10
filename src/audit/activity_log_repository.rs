use std::path::Path;

use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::{
    log_drain::MAX_LOG_RETENTION_SECONDS, server_configuration::LoggingSelection,
    service_error::ServiceError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityKind {
    Request,
    Query,
    Issuance,
}

pub struct ActivityRecord {
    pub record_id: Uuid,
    pub request_id: Uuid,
    pub client_id: Uuid,
    pub service_id: Option<Uuid>,
    pub event: String,
    pub result: String,
    pub error_code: Option<u16>,
    pub stored_at: u64,
}

pub struct ActivityLogRepository {
    connection: Connection,
    selection: LoggingSelection,
}

impl ActivityLogRepository {
    pub fn open(
        path: &Path,
        database_key: &[u8; 32],
        selection: LoggingSelection,
    ) -> Result<Self, ServiceError> {
        let connection = Connection::open(path).map_err(database_error)?;
        let key = database_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
            .map_err(database_error)?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(database_error)?;
        if cipher_version.trim().is_empty() {
            return Err(database_error("SQLCipher runtime is unavailable"));
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS activity_logs (
                record_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK(kind IN ('REQUEST', 'QUERY', 'ISSUANCE')),
                request_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                service_id TEXT,
                event TEXT NOT NULL,
                result TEXT NOT NULL,
                error_code INTEGER,
                stored_at INTEGER NOT NULL,
                retention_expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS activity_logs_retention
                ON activity_logs(retention_expires_at);",
            )
            .map_err(database_error)?;
        Ok(Self {
            connection,
            selection,
        })
    }

    pub fn store(
        &mut self,
        kind: ActivityKind,
        record: &ActivityRecord,
    ) -> Result<bool, ServiceError> {
        if !self.enabled(kind) {
            return Ok(false);
        }
        let stored_at = to_i64(record.stored_at)?;
        let expires = record
            .stored_at
            .checked_add(MAX_LOG_RETENTION_SECONDS)
            .ok_or_else(|| database_error("activity retention overflowed"))?;
        self.connection
            .execute(
                "INSERT INTO activity_logs (
                record_id, kind, request_id, client_id, service_id, event,
                result, error_code, stored_at, retention_expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    record.record_id.to_string(),
                    kind_name(kind),
                    record.request_id.to_string(),
                    record.client_id.to_string(),
                    record.service_id.map(|id| id.to_string()),
                    record.event,
                    record.result,
                    record.error_code,
                    stored_at,
                    to_i64(expires)?,
                ],
            )
            .map_err(database_error)?;
        Ok(true)
    }

    pub fn count(&self, kind: ActivityKind) -> Result<u64, ServiceError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM activity_logs WHERE kind = ?1",
                [kind_name(kind)],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        u64::try_from(count).map_err(|_| database_error("activity count is invalid"))
    }

    pub fn drain_expired(&mut self, now: u64) -> Result<usize, ServiceError> {
        self.connection
            .execute(
                "DELETE FROM activity_logs WHERE retention_expires_at <= ?1",
                [to_i64(now)?],
            )
            .map_err(database_error)
    }

    fn enabled(&self, kind: ActivityKind) -> bool {
        match kind {
            ActivityKind::Request => self.selection.request,
            ActivityKind::Query => self.selection.query,
            ActivityKind::Issuance => self.selection.issuance,
        }
    }
}

fn kind_name(kind: ActivityKind) -> &'static str {
    match kind {
        ActivityKind::Request => "REQUEST",
        ActivityKind::Query => "QUERY",
        ActivityKind::Issuance => "ISSUANCE",
    }
}

fn to_i64(value: u64) -> Result<i64, ServiceError> {
    i64::try_from(value).map_err(|_| database_error("activity time is out of range"))
}

fn database_error(error: impl std::fmt::Display) -> ServiceError {
    let _ = error;
    ServiceError::classified(8081, "activity log database operation failed")
        .expect("8081 must be assigned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn record(stored_at: u64) -> ActivityRecord {
        ActivityRecord {
            record_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            service_id: Some(Uuid::new_v4()),
            event: "JWT_QUERY".into(),
            result: "SUCCESS".into(),
            error_code: None,
            stored_at,
        }
    }

    #[test]
    fn stores_only_enabled_categories_and_drains_exact_boundary() {
        let path = std::env::temp_dir().join(format!("ab-jwt-activity-{}.db", Uuid::new_v4()));
        let selection = LoggingSelection {
            request: false,
            query: true,
            issuance: true,
            audit: false,
        };
        let mut repository = ActivityLogRepository::open(&path, &[0xa1; 32], selection).unwrap();
        assert!(
            !repository
                .store(ActivityKind::Request, &record(1_000))
                .unwrap()
        );
        assert!(
            repository
                .store(ActivityKind::Query, &record(1_000))
                .unwrap()
        );
        assert!(
            repository
                .store(ActivityKind::Issuance, &record(1_001))
                .unwrap()
        );
        assert_eq!(repository.count(ActivityKind::Request).unwrap(), 0);
        assert_eq!(
            repository
                .drain_expired(1_000 + MAX_LOG_RETENTION_SECONDS)
                .unwrap(),
            1
        );
        assert_eq!(repository.count(ActivityKind::Query).unwrap(), 0);
        assert_eq!(repository.count(ActivityKind::Issuance).unwrap(), 1);
        drop(repository);
        fs::remove_file(path).unwrap();
    }
}

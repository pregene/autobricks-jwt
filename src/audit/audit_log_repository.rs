use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

use crate::log_drain::MAX_LOG_RETENTION_SECONDS;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptBoundary {
    pub file: String,
    pub filesize: u64,
    pub checksum: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrueLogReceipt {
    pub hostname: String,
    pub service: String,
    pub before: ReceiptBoundary,
    pub after: ReceiptBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditLogRecord {
    pub audit_id: Uuid,
    pub event: String,
    pub event_at: String,
    pub service_id: String,
    pub subject_type: Option<String>,
    pub result: String,
    pub error_code: Option<u16>,
    pub error: Option<String>,
    pub request_id: Option<Uuid>,
    pub token_id: Option<Uuid>,
    pub administrator_uid: Option<u32>,
    pub receipt_state: String,
    pub receipt: Option<TrueLogReceipt>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuditLogFilter {
    pub event: Option<String>,
    pub receipt_state: Option<String>,
    pub from_event_at: Option<String>,
    pub to_event_at: Option<String>,
    pub service_id: Option<String>,
    pub result: Option<String>,
    pub error_code: Option<u16>,
    pub limit: u16,
}

pub struct AuditLogRepository {
    connection: Connection,
}

impl TrueLogReceipt {
    pub fn validate(&self, expected_hostname: &str) -> Result<(), String> {
        if self.hostname != expected_hostname {
            return Err("TrueLog receipt hostname does not match the configured hostname".into());
        }
        if self.service != "autobricks-jwt" {
            return Err("TrueLog receipt service is not autobricks-jwt".into());
        }
        if self.before.file != self.after.file || !valid_file_name(&self.before.file) {
            return Err("TrueLog receipt file boundary is invalid".into());
        }
        if self.after.filesize <= self.before.filesize {
            return Err("TrueLog receipt does not contain a positive append boundary".into());
        }
        if !valid_sha256(&self.before.checksum) || !valid_sha256(&self.after.checksum) {
            return Err("TrueLog receipt checksum is not lowercase SHA-256".into());
        }
        Ok(())
    }
}

impl AuditLogRepository {
    pub fn open_if_enabled(
        path: &Path,
        database_key: &[u8; 32],
        enabled: bool,
    ) -> Result<Option<Self>, String> {
        if enabled {
            Self::open(path, database_key).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn open(path: &Path, database_key: &[u8; 32]) -> Result<Self, String> {
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
            return Err("SQLCipher runtime did not report a cipher version".into());
        }

        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    event TEXT NOT NULL,
                    event_at TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    subject_type TEXT,
                    result TEXT NOT NULL,
                    error_code INTEGER,
                    error TEXT,
                    receipt_state TEXT NOT NULL CHECK (receipt_state IN ('PENDING', 'STORED', 'RECONCILE')),
                    request_id TEXT,
                    token_id TEXT,
                    administrator_uid INTEGER,
                    receipt_hostname TEXT,
                    receipt_service TEXT,
                    before_file TEXT,
                    before_filesize INTEGER,
                    before_checksum TEXT,
                    after_file TEXT,
                    after_filesize INTEGER,
                    after_checksum TEXT,
                    retention_expires_at INTEGER NOT NULL
                );",
            )
            .map_err(database_error)?;

        Ok(Self { connection })
    }

    pub fn cipher_version(&self) -> Result<String, String> {
        self.connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(database_error)
    }

    pub fn store_completed(&mut self, record: &AuditLogRecord) -> Result<(), String> {
        if record.receipt_state != "STORED" {
            return Err("a completed TrueLog receipt must use STORED state".into());
        }
        let receipt = record
            .receipt
            .as_ref()
            .ok_or("STORED audit record requires a receipt")?;
        receipt.validate("autobricks-jwt")?;
        let before_filesize = i64::try_from(receipt.before.filesize)
            .map_err(|_| "before filesize exceeds the SQLCipher integer range")?;
        let after_filesize = i64::try_from(receipt.after.filesize)
            .map_err(|_| "after filesize exceeds the SQLCipher integer range")?;
        let retention_seconds = i64::try_from(MAX_LOG_RETENTION_SECONDS)
            .map_err(|_| "audit retention exceeds the SQLCipher integer range")?;
        let retention_expires_at: i64 = self
            .connection
            .query_row(
                "SELECT unixepoch(?1) + ?2",
                params![record.event_at, retention_seconds],
                |row| row.get(0),
            )
            .map_err(database_error)?;

        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO audit_logs (
                    audit_id, event, event_at, service_id, subject_type, result,
                    error_code, error, request_id, token_id, administrator_uid,
                    receipt_state, receipt_hostname,
                    receipt_service, before_file, before_filesize,
                    before_checksum, after_file, after_filesize, after_checksum,
                    retention_expires_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                          ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    record.audit_id.to_string(),
                    record.event,
                    record.event_at,
                    record.service_id,
                    record.subject_type,
                    record.result,
                    record.error_code,
                    record.error,
                    record.request_id.map(|id| id.to_string()),
                    record.token_id.map(|id| id.to_string()),
                    record.administrator_uid,
                    record.receipt_state,
                    receipt.hostname,
                    receipt.service,
                    receipt.before.file,
                    before_filesize,
                    receipt.before.checksum,
                    receipt.after.file,
                    after_filesize,
                    receipt.after.checksum,
                    retention_expires_at,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn store_pending(&mut self, record: &AuditLogRecord) -> Result<(), String> {
        if record.receipt_state != "PENDING" || record.receipt.is_some() {
            return Err("a pending audit record cannot contain a receipt".into());
        }
        let retention_expires_at = retention_expiration(&self.connection, &record.event_at)?;
        self.connection
            .execute(
                "INSERT INTO audit_logs (
                audit_id, event, event_at, service_id, subject_type, result,
                error_code, error, request_id, token_id, administrator_uid,
                receipt_state, retention_expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'PENDING', ?12)",
                params![
                    record.audit_id.to_string(),
                    record.event,
                    record.event_at,
                    record.service_id,
                    record.subject_type,
                    record.result,
                    record.error_code,
                    record.error,
                    record.request_id.map(|id| id.to_string()),
                    record.token_id.map(|id| id.to_string()),
                    record.administrator_uid,
                    retention_expires_at
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn complete_pending(
        &mut self,
        audit_id: Uuid,
        receipt: &TrueLogReceipt,
    ) -> Result<(), String> {
        receipt.validate("autobricks-jwt")?;
        let updated = self
            .connection
            .execute(
                "UPDATE audit_logs SET receipt_state = 'STORED', receipt_hostname = ?2,
                receipt_service = ?3, before_file = ?4, before_filesize = ?5,
                before_checksum = ?6, after_file = ?7, after_filesize = ?8,
                after_checksum = ?9 WHERE audit_id = ?1 AND receipt_state = 'PENDING'",
                params![
                    audit_id.to_string(),
                    receipt.hostname,
                    receipt.service,
                    receipt.before.file,
                    i64::try_from(receipt.before.filesize)
                        .map_err(|_| "before filesize is invalid")?,
                    receipt.before.checksum,
                    receipt.after.file,
                    i64::try_from(receipt.after.filesize)
                        .map_err(|_| "after filesize is invalid")?,
                    receipt.after.checksum
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err("pending audit record is not available".into());
        }
        Ok(())
    }

    pub fn mark_reconcile(&mut self, audit_id: Uuid) -> Result<(), String> {
        let updated = self
            .connection
            .execute(
                "UPDATE audit_logs SET receipt_state = 'RECONCILE'
              WHERE audit_id = ?1 AND receipt_state = 'PENDING'",
                [audit_id.to_string()],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err("pending audit record is not available".into());
        }
        Ok(())
    }

    pub fn find(&self, audit_id: Uuid) -> Result<Option<AuditLogRecord>, String> {
        self.connection
            .query_row(
                "SELECT event, event_at, service_id, subject_type, result,
                        error_code, error, request_id, token_id, administrator_uid,
                        receipt_state, receipt_hostname,
                        receipt_service, before_file, before_filesize,
                        before_checksum, after_file, after_filesize, after_checksum
                   FROM audit_logs WHERE audit_id = ?1",
                [audit_id.to_string()],
                |row| {
                    Ok(AuditLogRecord {
                        audit_id,
                        event: row.get(0)?,
                        event_at: row.get(1)?,
                        service_id: row.get(2)?,
                        subject_type: row.get(3)?,
                        result: row.get(4)?,
                        error_code: row.get(5)?,
                        error: row.get(6)?,
                        request_id: optional_uuid(row.get(7)?)?,
                        token_id: optional_uuid(row.get(8)?)?,
                        administrator_uid: row.get(9)?,
                        receipt_state: row.get(10)?,
                        receipt: match row.get::<_, Option<String>>(11)? {
                            Some(hostname) => Some(TrueLogReceipt {
                                hostname,
                                service: row.get(12)?,
                                before: ReceiptBoundary {
                                    file: row.get(13)?,
                                    filesize: row.get(14)?,
                                    checksum: row.get(15)?,
                                },
                                after: ReceiptBoundary {
                                    file: row.get(16)?,
                                    filesize: row.get(17)?,
                                    checksum: row.get(18)?,
                                },
                            }),
                            None => None,
                        },
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    pub fn drain_expired(&mut self, now: u64) -> Result<usize, String> {
        let now =
            i64::try_from(now).map_err(|_| "Drain time exceeds the SQLCipher integer range")?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let removed = transaction
            .execute(
                "DELETE FROM audit_logs WHERE retention_expires_at <= ?1",
                [now],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(removed)
    }

    pub fn list(
        &self,
        receipt_state: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditLogRecord>, String> {
        if limit == 0 || limit > 1000 {
            return Err("audit query limit is invalid".into());
        }
        if receipt_state.is_some_and(|state| !matches!(state, "PENDING" | "STORED" | "RECONCILE")) {
            return Err("audit receipt-state filter is invalid".into());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT audit_id FROM audit_logs
              WHERE (?1 IS NULL OR receipt_state = ?1)
              ORDER BY event_at DESC LIMIT ?2",
            )
            .map_err(database_error)?;
        let ids = statement
            .query_map(params![receipt_state, limit], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        ids.into_iter()
            .map(|id| {
                let id =
                    Uuid::parse_str(&id).map_err(|_| "stored audit UUID is invalid".to_owned())?;
                self.find(id)?
                    .ok_or_else(|| "stored audit record disappeared".to_owned())
            })
            .collect()
    }

    pub fn query(&self, filter: &AuditLogFilter) -> Result<Vec<AuditLogRecord>, String> {
        if filter.limit == 0 || filter.limit > 1000 {
            return Err("audit query limit must be between 1 and 1000".into());
        }
        if filter
            .receipt_state
            .as_deref()
            .is_some_and(|value| !matches!(value, "PENDING" | "STORED" | "RECONCILE"))
        {
            return Err("audit receipt-state filter is invalid".into());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT audit_id FROM audit_logs
                  WHERE (?1 IS NULL OR event = ?1)
                    AND (?2 IS NULL OR receipt_state = ?2)
                    AND (?3 IS NULL OR event_at >= ?3)
                    AND (?4 IS NULL OR event_at <= ?4)
                    AND (?5 IS NULL OR service_id = ?5)
                    AND (?6 IS NULL OR result = ?6)
                    AND (?7 IS NULL OR error_code = ?7)
                  ORDER BY event_at DESC, audit_id DESC
                  LIMIT ?8",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    filter.event,
                    filter.receipt_state,
                    filter.from_event_at,
                    filter.to_event_at,
                    filter.service_id,
                    filter.result,
                    filter.error_code,
                    filter.limit,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(database_error)?;
        let identifiers = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        identifiers
            .into_iter()
            .map(|identifier| {
                let audit_id = Uuid::parse_str(&identifier)
                    .map_err(|_| "stored audit identifier is invalid".to_owned())?;
                self.find(audit_id)?
                    .ok_or_else(|| "stored audit record is missing".to_owned())
            })
            .collect()
    }
}

fn retention_expiration(connection: &Connection, event_at: &str) -> Result<i64, String> {
    let retention = i64::try_from(MAX_LOG_RETENTION_SECONDS)
        .map_err(|_| "audit retention exceeds the SQLCipher integer range")?;
    connection
        .query_row(
            "SELECT unixepoch(?1) + ?2",
            params![event_at, retention],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn optional_uuid(value: Option<String>) -> rusqlite::Result<Option<Uuid>> {
    value
        .map(|value| {
            Uuid::parse_str(&value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    value.len(),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

fn valid_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && !file_name.contains('/')
        && !file_name.contains('\\')
        && file_name != "."
        && file_name != ".."
}

fn valid_sha256(checksum: &str) -> bool {
    checksum.len() == 64
        && checksum
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn database_error(error: rusqlite::Error) -> String {
    format!("SQLCipher operation failed: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_audit_logging_creates_no_database() {
        let path = std::env::temp_dir().join(format!("ab-jwt-audit-off-{}.db", Uuid::new_v4()));
        assert!(
            AuditLogRepository::open_if_enabled(&path, &[0x19; 32], false)
                .unwrap()
                .is_none()
        );
        assert!(!path.exists());
    }
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn drains_sqlcipher_audit_record_at_exact_ninety_day_boundary() {
        let database_path = temporary_database_path("drain");
        let mut repository = AuditLogRepository::open(&database_path, &[0x4b; 32]).unwrap();
        let receipt = test_receipt();
        let old_id = Uuid::new_v4();
        let current_id = Uuid::new_v4();

        repository
            .store_completed(&test_record(
                old_id,
                "2026-01-01T00:00:00Z",
                receipt.clone(),
            ))
            .unwrap();
        repository
            .store_completed(&test_record(current_id, "2026-03-31T00:00:01Z", receipt))
            .unwrap();

        let exact_boundary: u64 = repository
            .connection
            .query_row(
                "SELECT unixepoch('2026-01-01T00:00:00Z') + ?1",
                [i64::try_from(MAX_LOG_RETENTION_SECONDS).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repository.drain_expired(exact_boundary).unwrap(), 1);
        assert!(repository.find(old_id).unwrap().is_none());
        assert!(repository.find(current_id).unwrap().is_some());

        drop(repository);
        fs::remove_file(database_path).unwrap();
    }

    #[test]
    #[ignore = "requires a receipt returned by the configured TrueLog service"]
    fn persists_and_reloads_truelog_receipt_in_sqlcipher() {
        let receipt_json = std::env::var("AUTOBRICKS_JWT_TEST_TRUELOG_RECEIPT")
            .expect("AUTOBRICKS_JWT_TEST_TRUELOG_RECEIPT must contain the write receipt");
        let event_at = std::env::var("AUTOBRICKS_JWT_TEST_AUDIT_EVENT_AT")
            .expect("AUTOBRICKS_JWT_TEST_AUDIT_EVENT_AT must be set");
        let receipt: TrueLogReceipt =
            serde_json::from_str(&receipt_json).expect("receipt must be valid JSON");
        receipt
            .validate("autobricks-jwt")
            .expect("receipt must satisfy the JWT audit contract");

        let database_path = temporary_database_path("receipt");
        let database_key = [0x5a; 32];
        let mut repository =
            AuditLogRepository::open(&database_path, &database_key).expect("open SQLCipher");
        let audit_id = Uuid::new_v4();
        let record = AuditLogRecord {
            audit_id,
            event: "JWT_ISSUED".into(),
            event_at,
            service_id: "jwtd-test-audit".into(),
            subject_type: Some("USER".into()),
            result: "SUCCESS".into(),
            error_code: None,
            error: None,
            request_id: Some(Uuid::new_v4()),
            token_id: Some(Uuid::new_v4()),
            administrator_uid: None,
            receipt_state: "STORED".into(),
            receipt: Some(receipt.clone()),
        };

        let cipher_version = repository.cipher_version().expect("read cipher version");
        repository
            .store_completed(&record)
            .expect("store the audit record and receipt");
        let stored = repository
            .find(audit_id)
            .expect("query the audit record")
            .expect("stored audit record must exist");

        assert_eq!(stored, record);
        println!("Audit SQLCipher runtime: {cipher_version}");
        println!("Audit record stored: audit_id={audit_id}");
        println!("Audit receipt state: {}", stored.receipt_state);
        println!(
            "Audit receipt reloaded: service={} file={} before={} after={}",
            stored.receipt.as_ref().unwrap().service,
            stored.receipt.as_ref().unwrap().after.file,
            stored.receipt.as_ref().unwrap().before.filesize,
            stored.receipt.as_ref().unwrap().after.filesize
        );

        drop(repository);
        fs::remove_file(&database_path).expect("remove temporary SQLCipher database");
        println!("Audit test database cleanup: removed");
    }

    fn temporary_database_path(purpose: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "autobricks-jwt-audit-{purpose}-{}-{unique}.db",
            std::process::id()
        ))
    }

    fn test_receipt() -> TrueLogReceipt {
        TrueLogReceipt {
            hostname: "autobricks-jwt".into(),
            service: "autobricks-jwt".into(),
            before: ReceiptBoundary {
                file: "truelog-2026-01-01.log".into(),
                filesize: 0,
                checksum: "0".repeat(64),
            },
            after: ReceiptBoundary {
                file: "truelog-2026-01-01.log".into(),
                filesize: 128,
                checksum: "1".repeat(64),
            },
        }
    }

    fn test_record(audit_id: Uuid, event_at: &str, receipt: TrueLogReceipt) -> AuditLogRecord {
        AuditLogRecord {
            audit_id,
            event: "JWT_ISSUED".into(),
            event_at: event_at.into(),
            service_id: "retention-test".into(),
            subject_type: Some("USER".into()),
            result: "SUCCESS".into(),
            error_code: None,
            error: None,
            request_id: None,
            token_id: None,
            administrator_uid: None,
            receipt_state: "STORED".into(),
            receipt: Some(receipt),
        }
    }

    #[test]
    fn transitions_pending_to_stored_or_reconcile_and_lists_locally() {
        let path = temporary_database_path("workflow");
        let mut repository = AuditLogRepository::open(&path, &[0x6a; 32]).unwrap();
        let pending_id = Uuid::new_v4();
        let reconcile_id = Uuid::new_v4();
        let pending = |audit_id| AuditLogRecord {
            audit_id,
            event: "JWT_SESSION_INVALID".into(),
            event_at: "2026-10-11T00:00:00Z".into(),
            service_id: "query-service".into(),
            subject_type: None,
            result: "ERROR".into(),
            error_code: Some(8060),
            error: Some("SESSION_NOT_FOUND_OR_EXPIRED".into()),
            request_id: Some(Uuid::new_v4()),
            token_id: None,
            administrator_uid: None,
            receipt_state: "PENDING".into(),
            receipt: None,
        };
        repository.store_pending(&pending(pending_id)).unwrap();
        repository.store_pending(&pending(reconcile_id)).unwrap();
        repository
            .complete_pending(pending_id, &test_receipt())
            .unwrap();
        repository.mark_reconcile(reconcile_id).unwrap();
        let stored = repository.find(pending_id).unwrap().unwrap();
        assert_eq!(stored.receipt_state, "STORED");
        assert!(stored.receipt.is_some());
        let reconcile = repository.find(reconcile_id).unwrap().unwrap();
        assert_eq!(reconcile.receipt_state, "RECONCILE");
        assert!(reconcile.receipt.is_none());
        assert_eq!(repository.list(Some("STORED"), 10).unwrap().len(), 1);
        assert_eq!(repository.list(Some("RECONCILE"), 10).unwrap().len(), 1);
        assert!(
            repository
                .complete_pending(reconcile_id, &test_receipt())
                .is_err()
        );
        drop(repository);
        fs::remove_file(path).unwrap();
    }
}

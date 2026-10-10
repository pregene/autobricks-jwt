use crate::{
    activity_log_repository::ActivityLogRepository, audit_log_repository::AuditLogRepository,
    service_error::ServiceError,
};

pub const DEFAULT_DRAIN_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

pub struct SqlCipherDrainScheduler {
    next_run_at: u64,
    interval: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DrainResult {
    pub activity_records: usize,
    pub audit_records: usize,
}

impl SqlCipherDrainScheduler {
    pub fn new(start_at: u64) -> Self {
        Self {
            next_run_at: start_at,
            interval: DEFAULT_DRAIN_INTERVAL_SECONDS,
        }
    }

    pub fn run_if_due(
        &mut self,
        now: u64,
        activities: &mut ActivityLogRepository,
        audits: Option<&mut AuditLogRepository>,
    ) -> Result<Option<DrainResult>, ServiceError> {
        if now < self.next_run_at {
            return Ok(None);
        }
        let activity_records = activities.drain_expired(now)?;
        let audit_records = audits
            .map(|repository| repository.drain_expired(now).map_err(audit_error))
            .transpose()?
            .unwrap_or(0);
        self.next_run_at = now.saturating_add(self.interval);
        Ok(Some(DrainResult {
            activity_records,
            audit_records,
        }))
    }
}

fn audit_error(_: String) -> ServiceError {
    ServiceError::classified(8081, "audit Drain database operation failed")
        .expect("8081 must be assigned")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use uuid::Uuid;

    use super::*;
    use crate::{
        activity_log_repository::{ActivityKind, ActivityRecord},
        log_drain::MAX_LOG_RETENTION_SECONDS,
        server_configuration::LoggingSelection,
    };

    #[test]
    fn runs_automatically_only_when_injected_schedule_is_due() {
        let path = std::env::temp_dir().join(format!("ab-jwt-drain-{}.db", Uuid::new_v4()));
        let mut activities = ActivityLogRepository::open(
            &path,
            &[0xb1; 32],
            LoggingSelection {
                request: true,
                query: true,
                issuance: true,
                audit: false,
            },
        )
        .unwrap();
        activities
            .store(
                ActivityKind::Request,
                &ActivityRecord {
                    record_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                    client_id: Uuid::new_v4(),
                    service_id: None,
                    event: "JWT_CREATE".into(),
                    result: "SUCCESS".into(),
                    error_code: None,
                    stored_at: 1_000,
                },
            )
            .unwrap();
        let due = 1_000 + MAX_LOG_RETENTION_SECONDS;
        let mut scheduler = SqlCipherDrainScheduler::new(due);
        assert_eq!(
            scheduler
                .run_if_due(due - 1, &mut activities, None)
                .unwrap(),
            None
        );
        assert_eq!(activities.count(ActivityKind::Request).unwrap(), 1);
        let result = scheduler
            .run_if_due(due, &mut activities, None)
            .unwrap()
            .unwrap();
        assert_eq!(result.activity_records, 1);
        assert_eq!(activities.count(ActivityKind::Request).unwrap(), 0);
        assert_eq!(
            scheduler
                .run_if_due(due + 1, &mut activities, None)
                .unwrap(),
            None
        );
        drop(activities);
        fs::remove_file(path).unwrap();
    }
}

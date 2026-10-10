const SECONDS_PER_DAY: u64 = 86_400;
pub const MAX_LOG_RETENTION_SECONDS: u64 = 90 * SECONDS_PER_DAY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedRecordClass {
    RequestLog,
    QueryLog,
    IssuanceLog,
    AuditLog,
    ConnectionAccessLog,
    ActiveSession,
}

impl RetainedRecordClass {
    pub const fn is_internal_log_drain_target(self) -> bool {
        matches!(
            self,
            Self::RequestLog | Self::QueryLog | Self::IssuanceLog | Self::AuditLog
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRecord {
    pub record_id: String,
    pub class: RetainedRecordClass,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainResult {
    pub examined: usize,
    pub removed: usize,
    pub retained: usize,
    pub completed_at: u64,
}

#[derive(Debug)]
pub struct LogDrainScheduler {
    interval_seconds: u64,
    next_run_at: u64,
}

impl LogDrainScheduler {
    pub fn new(first_run_at: u64, interval_seconds: u64) -> Result<Self, &'static str> {
        if interval_seconds == 0 {
            return Err("log Drain interval must be positive");
        }
        Ok(Self {
            interval_seconds,
            next_run_at: first_run_at,
        })
    }

    pub fn run_if_due(
        &mut self,
        now: u64,
        records: &mut Vec<RetainedRecord>,
    ) -> Option<DrainResult> {
        if now < self.next_run_at {
            return None;
        }

        let result = drain_expired_internal_logs(now, records);
        self.next_run_at = now.saturating_add(self.interval_seconds);
        Some(result)
    }

    pub const fn next_run_at(&self) -> u64 {
        self.next_run_at
    }
}

pub fn drain_expired_internal_logs(now: u64, records: &mut Vec<RetainedRecord>) -> DrainResult {
    let examined = records.len();
    records.retain(|record| {
        !record.class.is_internal_log_drain_target()
            || now.saturating_sub(record.created_at) < MAX_LOG_RETENTION_SECONDS
    });
    let retained = records.len();
    DrainResult {
        examined,
        removed: examined - retained,
        retained,
        completed_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 20_000_000;

    #[test]
    fn drains_every_internal_log_class_at_the_ninety_day_boundary() {
        let boundary = NOW - MAX_LOG_RETENTION_SECONDS;
        let mut records = vec![
            record("request-old", RetainedRecordClass::RequestLog, boundary - 1),
            record("query-boundary", RetainedRecordClass::QueryLog, boundary),
            record(
                "issuance-old",
                RetainedRecordClass::IssuanceLog,
                boundary - 10,
            ),
            record("audit-old", RetainedRecordClass::AuditLog, boundary - 100),
            record(
                "request-current",
                RetainedRecordClass::RequestLog,
                boundary + 1,
            ),
            record(
                "connection-old",
                RetainedRecordClass::ConnectionAccessLog,
                boundary - 1,
            ),
            record(
                "session-old",
                RetainedRecordClass::ActiveSession,
                boundary - 1,
            ),
        ];

        let result = drain_expired_internal_logs(NOW, &mut records);

        assert_eq!(result.examined, 7);
        assert_eq!(result.removed, 4);
        assert_eq!(result.retained, 3);
        assert_eq!(
            records
                .iter()
                .map(|record| record.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["request-current", "connection-old", "session-old"]
        );
    }

    #[test]
    fn scheduler_runs_only_at_or_after_its_injected_deadline() {
        let mut scheduler = LogDrainScheduler::new(NOW, SECONDS_PER_DAY).unwrap();
        let mut records = vec![record(
            "audit-old",
            RetainedRecordClass::AuditLog,
            NOW - MAX_LOG_RETENTION_SECONDS,
        )];

        assert_eq!(scheduler.run_if_due(NOW - 1, &mut records), None);
        assert_eq!(records.len(), 1);

        let result = scheduler.run_if_due(NOW, &mut records).unwrap();
        assert_eq!(result.removed, 1);
        assert!(records.is_empty());
        assert_eq!(scheduler.next_run_at(), NOW + SECONDS_PER_DAY);

        assert_eq!(scheduler.run_if_due(NOW + 1, &mut records), None);
    }

    #[test]
    fn future_timestamp_is_retained_without_unsigned_time_underflow() {
        let mut records = vec![record(
            "future-audit",
            RetainedRecordClass::AuditLog,
            NOW + 1,
        )];
        let result = drain_expired_internal_logs(NOW, &mut records);
        assert_eq!(result.removed, 0);
        assert_eq!(records.len(), 1);
    }

    fn record(id: &str, class: RetainedRecordClass, created_at: u64) -> RetainedRecord {
        RetainedRecord {
            record_id: id.into(),
            class,
            created_at,
        }
    }
}

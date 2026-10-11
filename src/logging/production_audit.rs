use std::path::Path;

use uuid::Uuid;

use crate::{
    audit_log_repository::AuditLogRepository,
    operational_logger::{LogSink, OperationalLogger, SyslogSink},
    service_error::ServiceError,
    truelog_audit::{
        AuditCoordinator, AuditEvent, AuditRecorder, CommandTrueLogWriter, TrueLogWriter,
    },
};

pub struct ProductionAuditRecorder<S, W> {
    logger: OperationalLogger<S>,
    coordinator: Option<AuditCoordinator<W>>,
    enabled: bool,
}

impl<S: LogSink, W: TrueLogWriter> ProductionAuditRecorder<S, W> {
    pub fn new(
        logger: OperationalLogger<S>,
        coordinator: Option<AuditCoordinator<W>>,
        enabled: bool,
    ) -> Self {
        Self {
            logger,
            coordinator,
            enabled,
        }
    }

    fn record(
        &mut self,
        event: AuditEvent,
        request_id: Option<Uuid>,
        token_id: Option<Uuid>,
        administrator_uid: Option<u32>,
    ) -> Result<(), ServiceError> {
        if !self.enabled {
            return Ok(());
        }
        self.logger.audit_event(&event);
        if let Some(coordinator) = &mut self.coordinator {
            coordinator.record(event, request_id, token_id, administrator_uid)?;
        }
        Ok(())
    }

    pub fn evidence_enabled(&self) -> bool {
        self.enabled && self.coordinator.is_some()
    }

    pub fn into_parts(self) -> (OperationalLogger<S>, Option<AuditCoordinator<W>>) {
        (self.logger, self.coordinator)
    }
}

impl ProductionAuditRecorder<SyslogSink, CommandTrueLogWriter> {
    pub fn open(
        database_path: &Path,
        database_key: &[u8; 32],
        enabled: bool,
        truelog_client: Option<&Path>,
    ) -> Result<Self, ServiceError> {
        let coordinator = if enabled {
            truelog_client
                .map(|executable| {
                    let repository = AuditLogRepository::open(database_path, database_key)
                        .map_err(|_| classified(8072, "audit repository cannot be opened"))?;
                    Ok(AuditCoordinator::new(
                        repository,
                        CommandTrueLogWriter::new(executable),
                    ))
                })
                .transpose()?
        } else {
            None
        };
        Ok(Self::new(
            OperationalLogger::new(SyslogSink),
            coordinator,
            enabled,
        ))
    }
}

impl<S: LogSink, W: TrueLogWriter> AuditRecorder for ProductionAuditRecorder<S, W> {
    fn issued(
        &mut self,
        service_id: Uuid,
        subject_type: &str,
        request_id: Uuid,
        token_id: Uuid,
        event_at: &str,
    ) -> Result<(), ServiceError> {
        self.record(
            AuditEvent::issued(service_id, subject_type, event_at)?,
            Some(request_id),
            Some(token_id),
            None,
        )
    }

    fn invalid_session(
        &mut self,
        service_id: Uuid,
        request_id: Uuid,
        event_at: &str,
    ) -> Result<(), ServiceError> {
        self.record(
            AuditEvent::invalid_session(service_id, event_at),
            Some(request_id),
            None,
            None,
        )
    }

    fn privileged_inspection(
        &mut self,
        service_id: Uuid,
        request_id: Uuid,
        token_id: Uuid,
        administrator_uid: u32,
        event_at: &str,
    ) -> Result<(), ServiceError> {
        self.record(
            AuditEvent::privileged_inspection(service_id, event_at),
            Some(request_id),
            Some(token_id),
            Some(administrator_uid),
        )
    }
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::audit_log_repository::{ReceiptBoundary, TrueLogReceipt};

    use super::*;

    #[derive(Default)]
    struct CaptureLog(Vec<String>);
    impl LogSink for CaptureLog {
        fn write(&mut self, message: &str) {
            self.0.push(message.into());
        }
    }

    struct ReceiptWriter;
    impl TrueLogWriter for ReceiptWriter {
        fn append(&mut self, _: &str) -> Result<TrueLogReceipt, ServiceError> {
            Ok(TrueLogReceipt {
                hostname: "autobricks-jwt".into(),
                service: "autobricks-jwt".into(),
                before: ReceiptBoundary {
                    file: "truelog-2026-10-11.log".into(),
                    filesize: 10,
                    checksum: "11".repeat(32),
                },
                after: ReceiptBoundary {
                    file: "truelog-2026-10-11.log".into(),
                    filesize: 20,
                    checksum: "22".repeat(32),
                },
            })
        }
    }

    #[test]
    fn composes_syslog_copy_optional_truelog_and_durable_receipt_storage() {
        let path = std::env::temp_dir().join(format!("ab-jwt-prod-audit-{}.db", Uuid::new_v4()));
        let repository = AuditLogRepository::open(&path, &[0x29; 32]).unwrap();
        let coordinator = AuditCoordinator::new(repository, ReceiptWriter);
        let mut audit = ProductionAuditRecorder::new(
            OperationalLogger::new(CaptureLog::default()),
            Some(coordinator),
            true,
        );
        let request_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        audit
            .issued(
                Uuid::new_v4(),
                "USER",
                request_id,
                token_id,
                "2026-10-11T00:00:00Z",
            )
            .unwrap();
        assert!(audit.evidence_enabled());
        let (logger, coordinator) = audit.into_parts();
        let capture = logger.into_inner();
        assert_eq!(capture.0.len(), 1);
        assert!(capture.0[0].contains("JWT_ISSUED"));
        let records = coordinator
            .unwrap()
            .repository()
            .list(Some("STORED"), 10)
            .unwrap();
        let stored = records
            .into_iter()
            .find(|record| {
                record.request_id == Some(request_id) && record.token_id == Some(token_id)
            })
            .unwrap();
        assert_eq!(stored.receipt_state, "STORED");
        assert_eq!(stored.receipt.unwrap().after.filesize, 20);
        fs::remove_file(path).unwrap();

        let mut syslog_only = ProductionAuditRecorder::<CaptureLog, ReceiptWriter>::new(
            OperationalLogger::new(CaptureLog::default()),
            None,
            true,
        );
        syslog_only
            .invalid_session(Uuid::new_v4(), Uuid::new_v4(), "2026-10-11T00:00:01Z")
            .unwrap();
        assert!(!syslog_only.evidence_enabled());
        let (logger, coordinator) = syslog_only.into_parts();
        assert!(coordinator.is_none());
        assert_eq!(logger.into_inner().0.len(), 1);
    }
}

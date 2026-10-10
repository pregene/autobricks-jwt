use std::{path::PathBuf, process::Command};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    audit_log_repository::{AuditLogRecord, AuditLogRepository, TrueLogReceipt},
    service_error::ServiceError,
};

#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    pub event: &'static str,
    pub service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    pub event_at: String,
}

pub trait TrueLogWriter {
    fn append(&mut self, event_json: &str) -> Result<TrueLogReceipt, ServiceError>;
}

pub trait AuditRecorder {
    fn issued(
        &mut self,
        service_id: Uuid,
        subject_type: &str,
        request_id: Uuid,
        token_id: Uuid,
        event_at: &str,
    ) -> Result<(), ServiceError>;

    fn invalid_session(
        &mut self,
        service_id: Uuid,
        request_id: Uuid,
        event_at: &str,
    ) -> Result<(), ServiceError>;

    fn privileged_inspection(
        &mut self,
        service_id: Uuid,
        request_id: Uuid,
        token_id: Uuid,
        administrator_uid: u32,
        event_at: &str,
    ) -> Result<(), ServiceError>;
}

pub struct CommandTrueLogWriter {
    executable: PathBuf,
}

pub struct AuditCoordinator<W> {
    repository: AuditLogRepository,
    writer: W,
}

impl AuditEvent {
    pub fn issued(
        service_id: Uuid,
        subject_type: &str,
        event_at: &str,
    ) -> Result<Self, ServiceError> {
        if !matches!(subject_type, "USER" | "DEVICE" | "WORKLOAD") {
            return Err(ServiceError::invalid_subject(
                "audit subject type is invalid",
            ));
        }
        Ok(Self {
            event: "JWT_ISSUED",
            service_id: service_id.to_string(),
            subject_type: Some(subject_type.into()),
            result: "SUCCESS",
            error_code: None,
            error: None,
            event_at: event_at.into(),
        })
    }

    pub fn invalid_session(service_id: Uuid, event_at: &str) -> Self {
        Self {
            event: "JWT_SESSION_INVALID",
            service_id: service_id.to_string(),
            subject_type: None,
            result: "ERROR",
            error_code: Some(8060),
            error: Some("SESSION_NOT_FOUND_OR_EXPIRED"),
            event_at: event_at.into(),
        }
    }

    pub fn privileged_inspection(service_id: Uuid, event_at: &str) -> Self {
        Self {
            event: "JWT_TOKEN_INSPECTED",
            service_id: service_id.to_string(),
            subject_type: None,
            result: "SUCCESS",
            error_code: None,
            error: None,
            event_at: event_at.into(),
        }
    }
}

impl CommandTrueLogWriter {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }
}

impl TrueLogWriter for CommandTrueLogWriter {
    fn append(&mut self, event_json: &str) -> Result<TrueLogReceipt, ServiceError> {
        let output = Command::new(&self.executable)
            .args(["write", "--service", "autobricks-jwt", "--data", event_json])
            .output()
            .map_err(|_| classified(8070, "TrueLog write failed"))?;
        if !output.status.success() {
            return Err(classified(8070, "TrueLog write failed"));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|_| classified(8071, "TrueLog receipt is invalid"))
    }
}

impl<W: TrueLogWriter> AuditCoordinator<W> {
    pub fn new(repository: AuditLogRepository, writer: W) -> Self {
        Self { repository, writer }
    }

    pub fn record(
        &mut self,
        event: AuditEvent,
        request_id: Option<Uuid>,
        token_id: Option<Uuid>,
        administrator_uid: Option<u32>,
    ) -> Result<Uuid, ServiceError> {
        let audit_id = Uuid::new_v4();
        let pending = AuditLogRecord {
            audit_id,
            event: event.event.into(),
            event_at: event.event_at.clone(),
            service_id: event.service_id.clone(),
            subject_type: event.subject_type.clone(),
            result: event.result.into(),
            error_code: event.error_code,
            error: event.error.map(str::to_owned),
            request_id,
            token_id,
            administrator_uid,
            receipt_state: "PENDING".into(),
            receipt: None,
        };
        self.repository
            .store_pending(&pending)
            .map_err(|_| classified(8072, "audit pending record could not be stored"))?;
        let json = serde_json::to_string(&event)
            .map_err(|_| classified(8070, "audit event serialization failed"))?;
        let receipt = self.writer.append(&json)?;
        if receipt.validate("autobricks-jwt").is_err() {
            self.repository
                .mark_reconcile(audit_id)
                .map_err(|_| classified(8073, "audit reconciliation is required"))?;
            return Err(classified(8071, "TrueLog receipt is invalid"));
        }
        if self
            .repository
            .complete_pending(audit_id, &receipt)
            .is_err()
        {
            let _ = self.repository.mark_reconcile(audit_id);
            return Err(classified(8073, "audit reconciliation is required"));
        }
        Ok(audit_id)
    }

    pub fn repository(&self) -> &AuditLogRepository {
        &self.repository
    }
}

impl<W: TrueLogWriter> AuditRecorder for AuditCoordinator<W> {
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
        )?;
        Ok(())
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
        )?;
        Ok(())
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
        )?;
        Ok(())
    }
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::audit_log_repository::ReceiptBoundary;

    use super::*;

    struct CaptureWriter {
        events: Vec<String>,
        valid: bool,
    }
    impl TrueLogWriter for CaptureWriter {
        fn append(&mut self, event_json: &str) -> Result<TrueLogReceipt, ServiceError> {
            self.events.push(event_json.into());
            Ok(TrueLogReceipt {
                hostname: "autobricks-jwt".into(),
                service: "autobricks-jwt".into(),
                before: ReceiptBoundary {
                    file: "truelog-2026-10-11.log".into(),
                    filesize: 10,
                    checksum: "0".repeat(64),
                },
                after: ReceiptBoundary {
                    file: if self.valid {
                        "truelog-2026-10-11.log".into()
                    } else {
                        "../bad".into()
                    },
                    filesize: 20,
                    checksum: "1".repeat(64),
                },
            })
        }
    }

    #[test]
    fn stores_exact_issued_and_invalid_session_events_with_receipts() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-audit-coordinator-{}.db", Uuid::new_v4()));
        let repository = AuditLogRepository::open(&path, &[0xf1; 32]).unwrap();
        let writer = CaptureWriter {
            events: vec![],
            valid: true,
        };
        let mut coordinator = AuditCoordinator::new(repository, writer);
        let service_id = Uuid::new_v4();
        let issued_id = coordinator
            .record(
                AuditEvent::issued(service_id, "USER", "2026-10-11T00:00:00Z").unwrap(),
                Some(Uuid::new_v4()),
                Some(Uuid::new_v4()),
                None,
            )
            .unwrap();
        let invalid_id = coordinator
            .record(
                AuditEvent::invalid_session(service_id, "2026-10-11T00:01:00Z"),
                Some(Uuid::new_v4()),
                None,
                None,
            )
            .unwrap();
        for id in [issued_id, invalid_id] {
            let record = coordinator.repository().find(id).unwrap().unwrap();
            assert_eq!(record.receipt_state, "STORED");
            assert!(record.receipt.is_some());
        }
        let events = &coordinator.writer.events;
        assert_eq!(events.len(), 2);
        assert!(
            !events
                .iter()
                .any(|event| event.contains("token_id") || event.contains("request_id"))
        );
        assert!(events[1].contains("\"error_code\":8060"));
        drop(coordinator);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_receipt_moves_event_to_reconcile_without_reappend() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-audit-reconcile-{}.db", Uuid::new_v4()));
        let repository = AuditLogRepository::open(&path, &[0xf2; 32]).unwrap();
        let writer = CaptureWriter {
            events: vec![],
            valid: false,
        };
        let mut coordinator = AuditCoordinator::new(repository, writer);
        let error = coordinator
            .record(
                AuditEvent::invalid_session(Uuid::new_v4(), "2026-10-11T00:00:00Z"),
                None,
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(error.code(), 8071);
        let records = coordinator
            .repository()
            .list(Some("RECONCILE"), 10)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].receipt.is_none());
        assert_eq!(coordinator.writer.events.len(), 1);
        drop(coordinator);
        fs::remove_file(path).unwrap();
    }
}

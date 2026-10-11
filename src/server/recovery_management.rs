use std::{path::PathBuf, sync::Arc, time::Duration};

use serde_json::{Value, json};

use crate::{
    database_key_rotation::{CommandHsmDatabaseKeys, DatabaseProtectionManager, HsmDatabaseKeys},
    management_protocol::ManagementRequest,
    management_service::RecoveryManagement,
    operational_logger::{OperationalLogger, SyslogSink},
    recovery_authorization::RecoveryAuthorizationRepository,
    runtime_context::RuntimeServiceContext,
    runtime_supervisor::RuntimeSupervisor,
    server_configuration::ServerConfiguration,
    service_error::ServiceError,
};

pub struct ProductionRecoveryManagement {
    supervisor: Arc<RuntimeSupervisor>,
    configuration: ServerConfiguration,
    executable: PathBuf,
}

impl ProductionRecoveryManagement {
    pub fn new(
        supervisor: Arc<RuntimeSupervisor>,
        configuration: ServerConfiguration,
        executable: PathBuf,
    ) -> Self {
        Self {
            supervisor,
            configuration,
            executable,
        }
    }

    fn manager(&self) -> Result<DatabaseProtectionManager<CommandHsmDatabaseKeys>, ServiceError> {
        let hsm = CommandHsmDatabaseKeys::new(
            &self.configuration.hsm_helper,
            &self.configuration.hsm_key_namespace,
        )?;
        let key = hsm.current()?;
        let verifier =
            RecoveryAuthorizationRepository::open(&self.configuration.database_path, &key)?
                .require()?;
        DatabaseProtectionManager::new(
            &self.configuration.database_path,
            &self.configuration.backup_directory,
            hsm,
            verifier,
        )
    }

    fn reopen(&self) -> Result<RuntimeServiceContext, ServiceError> {
        open_runtime(&self.configuration, &self.executable)
    }

    fn finalize_result(
        &self,
        event: &str,
        mut result: Result<Value, ServiceError>,
    ) -> Result<Value, ServiceError> {
        let mut logger = OperationalLogger::new(SyslogSink);
        let completed_at = unix_time().unwrap_or(0);
        let evidence = (|| {
            let hsm = CommandHsmDatabaseKeys::new(
                &self.configuration.hsm_helper,
                &self.configuration.hsm_key_namespace,
            )?;
            let key = hsm.current()?;
            let mut repository =
                RecoveryAuthorizationRepository::open(&self.configuration.database_path, &key)?;
            repository.record_operation(
                event,
                if result.is_ok() { "SUCCESS" } else { "FAILURE" },
                result.as_ref().err().map(ServiceError::code),
                completed_at,
            )
        })();
        if result.is_ok() {
            if let Err(error) = evidence {
                result = Err(error);
            }
        }
        let event_at = completed_at.to_string();
        match &result {
            Ok(_) => logger.lifecycle_event(event, "SUCCESS", &event_at),
            Err(error) => logger.classified_error(error, &event_at),
        }
        result
    }

    pub fn scheduled_backup_and_rotate(&self, now: u64) -> Result<Value, ServiceError> {
        let result = self.manager().and_then(|mut manager| self.supervisor.maintenance(
            || manager.scheduled_backup_and_rotate(now),
            || self.reopen(),
        )).map(|backup| json!({ "generation": backup.generation, "completed_at": backup.completed_at }));
        self.finalize_result("DATABASE_SCHEDULED_BACKUP_AND_ROTATE", result)
    }

    pub fn latest_backup_completed_at(&self) -> Result<Option<u64>, ServiceError> {
        self.manager()
            .and_then(|manager| manager.recovery_points())
            .map(|points| points.into_iter().map(|point| point.completed_at).max())
    }

    pub fn drain_internal_logs(&self, now: u64) -> Result<Value, ServiceError> {
        let hsm = CommandHsmDatabaseKeys::new(
            &self.configuration.hsm_helper,
            &self.configuration.hsm_key_namespace,
        )?;
        let key = hsm.current()?;
        let mut activities = crate::activity_log_repository::ActivityLogRepository::open(
            &self.configuration.database_path,
            &key,
            self.configuration.logging,
        )?;
        let activity_records = activities.drain_expired(now)?;
        let audit_records = if self.configuration.logging.audit {
            let mut audits = crate::audit_log_repository::AuditLogRepository::open(
                &self.configuration.database_path,
                &key,
            )
            .map_err(|_| {
                ServiceError::classified(8081, "audit Drain database operation failed")
                    .expect("assigned error")
            })?;
            audits.drain_expired(now).map_err(|_| {
                ServiceError::classified(8081, "audit Drain database operation failed")
                    .expect("assigned error")
            })?
        } else {
            0
        };
        let result =
            Ok(json!({ "activity_records": activity_records, "audit_records": audit_records }));
        self.finalize_result("INTERNAL_LOG_DRAIN", result)
    }
}

impl RecoveryManagement for ProductionRecoveryManagement {
    fn process(&self, request: &ManagementRequest) -> Option<Result<Value, ServiceError>> {
        let (event, result) = match request {
            ManagementRequest::ListRecoveryPoints => {
                let result = self
                    .manager()
                    .and_then(|manager| manager.recovery_points())
                    .map(|points| {
                        json!(points.iter().map(|point| json!({
                    "generation": point.generation,
                    "completed_at": point.completed_at,
                    "validation": format!("{:?}", point.validation).to_ascii_uppercase()
                })).collect::<Vec<_>>())
                    });
                ("RECOVERY_POINTS_LIST", result)
            }
            ManagementRequest::ForceBackupAndRotate { recovery_key } => {
                let result = self.manager().and_then(|mut manager| self.supervisor.maintenance(
                    || manager.force_backup_and_rotate(recovery_key, unix_time()?),
                    || self.reopen(),
                )).map(|backup| json!({ "generation": backup.generation, "completed_at": backup.completed_at }));
                ("DATABASE_BACKUP_AND_ROTATE", result)
            }
            ManagementRequest::RestoreDatabase {
                recovery_key,
                generation,
            } => {
                let result = self
                    .manager()
                    .and_then(|mut manager| {
                        self.supervisor.maintenance(
                            || manager.restore_generation(recovery_key, *generation),
                            || self.reopen(),
                        )
                    })
                    .map(|restored| {
                        json!({
                            "generation": restored.target_generation,
                            "invalidated_sessions": restored.invalidated_sessions,
                            "runtime_reloaded": true,
                            "cache_rebuilt": true,
                            "listeners_restarted": true
                        })
                    });
                ("DATABASE_RESTORE", result)
            }
            _ => return None,
        };
        Some(self.finalize_result(event, result))
    }
}

pub fn open_runtime(
    configuration: &ServerConfiguration,
    executable: &std::path::Path,
) -> Result<RuntimeServiceContext, ServiceError> {
    let hsm =
        CommandHsmDatabaseKeys::new(&configuration.hsm_helper, &configuration.hsm_key_namespace)?;
    let mut context = RuntimeServiceContext::open_with_cache(
        &configuration.database_path,
        &hsm,
        Duration::from_secs(configuration.timeout_seconds),
        configuration.require_token_for_query_and_revoke,
        executable,
        &configuration.cache_library,
    )?;
    let key = hsm.current()?;
    context.configure_audit(
        &key,
        configuration.logging.audit,
        configuration.truelog_client.as_deref(),
    )?;
    context.enable_session_cache(executable, &configuration.cache_library, &key, unix_time()?)?;
    Ok(context)
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::internal("system time is before the Unix epoch"))
}

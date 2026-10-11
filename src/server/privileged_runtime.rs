use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    audit_log_repository::AuditLogRepository, audit_query::serve_audit_query_socket_until,
    production_audit::ProductionAuditRecorder, server_configuration::ServerConfiguration,
    service_error::ServiceError, sqlcipher_token_repository::SqlCipherTokenRepository,
    token_inspection::serve_inspection_socket_until,
};

pub struct PrivilegedRuntime {
    shutdown: Arc<AtomicBool>,
    inspection: Option<JoinHandle<Result<(), ServiceError>>>,
    audit_query: Option<JoinHandle<Result<(), ServiceError>>>,
}

impl PrivilegedRuntime {
    pub fn start(
        configuration: &ServerConfiguration,
        database_key: [u8; 32],
    ) -> Result<Self, ServiceError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let inspection_resources =
            if configuration.logging.audit && configuration.truelog_client.is_some() {
                Some((
                    SqlCipherTokenRepository::open(&configuration.database_path, &database_key)?,
                    ProductionAuditRecorder::open(
                        &configuration.database_path,
                        &database_key,
                        true,
                        configuration.truelog_client.as_deref(),
                    )?,
                ))
            } else {
                None
            };
        let audit_query_repository = if configuration.logging.audit {
            Some(
                AuditLogRepository::open(&configuration.database_path, &database_key).map_err(
                    |_| {
                        ServiceError::service_unavailable("audit query repository cannot be opened")
                    },
                )?,
            )
        } else {
            None
        };
        let mut inspection = if let Some((tokens, mut audit)) = inspection_resources {
            let socket = configuration.inspection_socket.clone();
            let flag = Arc::clone(&shutdown);
            Some(thread::spawn(move || {
                serve_inspection_socket_until(
                    &socket,
                    0,
                    0,
                    usize::MAX,
                    &tokens,
                    &mut audit,
                    Some(flag),
                )
            }))
        } else {
            None
        };
        let mut audit_query = if let Some(repository) = audit_query_repository {
            let socket = configuration.audit_query_socket.clone();
            let flag = Arc::clone(&shutdown);
            Some(thread::spawn(move || {
                serve_audit_query_socket_until(&socket, 0, usize::MAX, &repository, Some(flag))
            }))
        } else {
            None
        };
        wait_until_ready(
            &configuration.inspection_socket,
            &mut inspection,
            configuration.logging.audit && configuration.truelog_client.is_some(),
        )?;
        wait_until_ready(
            &configuration.audit_query_socket,
            &mut audit_query,
            configuration.logging.audit,
        )?;
        Ok(Self {
            shutdown,
            inspection,
            audit_query,
        })
    }

    pub fn shutdown(mut self) -> Result<(), ServiceError> {
        self.shutdown.store(true, Ordering::Release);
        join(&mut self.inspection)?;
        join(&mut self.audit_query)
    }
}

impl Drop for PrivilegedRuntime {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

fn wait_until_ready(
    socket: &Path,
    thread: &mut Option<JoinHandle<Result<(), ServiceError>>>,
    enabled: bool,
) -> Result<(), ServiceError> {
    if !enabled {
        return Ok(());
    }
    for _ in 0..200 {
        if socket.exists() {
            return Ok(());
        }
        if thread.as_ref().is_some_and(JoinHandle::is_finished) {
            return thread
                .take()
                .expect("finished thread exists")
                .join()
                .map_err(|_| {
                    ServiceError::service_unavailable(
                        "privileged local service failed during startup",
                    )
                })?
                .and_then(|_| {
                    Err(ServiceError::service_unavailable(
                        "privileged local service stopped during startup",
                    ))
                });
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(ServiceError::service_unavailable(
        "privileged local service did not become ready",
    ))
}

fn join(handle: &mut Option<JoinHandle<Result<(), ServiceError>>>) -> Result<(), ServiceError> {
    let Some(handle) = handle.take() else {
        return Ok(());
    };
    handle.join().map_err(|_| {
        ServiceError::service_unavailable("privileged local service did not stop cleanly")
    })?
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use uuid::Uuid;

    use super::*;

    #[test]
    fn starts_and_stops_server_owned_privileged_sockets() {
        let identity = Uuid::new_v4().simple().to_string();
        let root = std::path::PathBuf::from(format!("/tmp/abjwt-p-{}", &identity[..12]));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let database = root.join("jwt.db");
        let key = [0x63; 32];
        SqlCipherTokenRepository::open(&database, &key).unwrap();
        AuditLogRepository::open(&database, &key).unwrap();
        let configuration = ServerConfiguration::parse(&format!(
            "timeout: 3600\nbackup_directory: {}\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\nmanagement_socket: {}\ninspection_socket: {}\naudit_query_socket: {}\ndatabase_path: {}\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test/privileged\nruntime_transports: UNIX\nservice_socket: {}\ntruelog_client: /usr/bin/false\n",
            root.join("backups").display(),
            root.join("management.sock").display(),
            root.join("inspection.sock").display(),
            root.join("audit.sock").display(),
            database.display(),
            root.join("service.sock").display(),
        )).unwrap();
        let runtime = PrivilegedRuntime::start(&configuration, key).unwrap();
        assert!(configuration.inspection_socket.exists());
        assert!(configuration.audit_query_socket.exists());
        runtime.shutdown().unwrap();
        assert!(!configuration.inspection_socket.exists());
        assert!(!configuration.audit_query_socket.exists());
        fs::remove_file(database).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

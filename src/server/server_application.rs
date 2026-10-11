use std::{
    ffi::OsString,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    VERSION,
    database_key_rotation::{CommandHsmDatabaseKeys, HsmDatabaseKeys},
    helper_service, management_service,
    privileged_runtime::PrivilegedRuntime,
    production_scheduler::{ProductionSchedulerRuntime, ScheduledCertificateRenewal},
    recovery_management::ProductionRecoveryManagement,
    runtime_context::RuntimeServiceContext,
    runtime_supervisor::RuntimeSupervisor,
    server_arguments::{self, ServerCommand},
    server_certificate_renewal::ProductionServerCertificateRenewal,
    server_configuration::ServerConfiguration,
    service_certificate_management::ProductionCertificateManagement,
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    worker_process,
};

const PRODUCT: &str = "Autobricks JWT Server";
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

fn install_shutdown_handlers() -> Result<Arc<AtomicBool>, ServiceError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Release);
    let handler = request_shutdown as *const () as libc::sighandler_t;
    if unsafe { libc::signal(libc::SIGTERM, handler) } == libc::SIG_ERR
        || unsafe { libc::signal(libc::SIGINT, handler) } == libc::SIG_ERR
    {
        return Err(ServiceError::service_unavailable(
            "shutdown signal handlers cannot be installed",
        ));
    }
    Ok(Arc::new(AtomicBool::new(false)))
}

pub fn execute<I>(arguments: I) -> Result<String, ServiceError>
where
    I: IntoIterator<Item = OsString>,
{
    match server_arguments::parse(arguments)? {
        ServerCommand::Help => Ok(help()),
        ServerCommand::Version => Ok(format!("{PRODUCT} {VERSION}\n")),
        ServerCommand::CheckConfiguration(path) => {
            let configuration = ServerConfiguration::load(&path)?;
            Ok(render_configuration(&configuration))
        }
        ServerCommand::Initialize(path) => {
            let configuration = ServerConfiguration::load(&path)?;
            let hsm = CommandHsmDatabaseKeys::new(
                &configuration.hsm_helper,
                &configuration.hsm_key_namespace,
            )?;
            hsm.initialize_current()?;
            let current = hsm.current()?;
            let mut recovery =
                crate::recovery_authorization::RecoveryAuthorizationRepository::open(
                    &configuration.database_path,
                    &current,
                )?;
            let recovery_key = recovery.initialize(unix_time()?)?;
            let verifier = recovery.require()?;
            drop(recovery);
            let mut protection = crate::database_key_rotation::DatabaseProtectionManager::new(
                &configuration.database_path,
                &configuration.backup_directory,
                hsm,
                verifier,
            )?;
            let initialization = protection
                .initialize_schema()
                .and_then(|_| protection.scheduled_backup_and_rotate(unix_time()?));
            if let Err(error) = initialization {
                if let Ok(mut recovery) =
                    crate::recovery_authorization::RecoveryAuthorizationRepository::open(
                        &configuration.database_path,
                        &current,
                    )
                {
                    let _ = recovery.clear_failed_initialization();
                }
                return Err(error);
            }
            Ok(format!("Recovery authorization key: {recovery_key}\n"))
        }
        ServerCommand::Serve(path) => {
            let shutdown = install_shutdown_handlers()?;
            let configuration = ServerConfiguration::load(&path)?;
            let hsm = CommandHsmDatabaseKeys::new(
                &configuration.hsm_helper,
                &configuration.hsm_key_namespace,
            )?;
            let executable = std::env::current_exe().map_err(|_| {
                ServiceError::service_unavailable("server executable path is unavailable")
            })?;
            let mut context = RuntimeServiceContext::open_with_cache(
                &configuration.database_path,
                &hsm,
                std::time::Duration::from_secs(configuration.timeout_seconds),
                configuration.require_token_for_query_and_revoke,
                &executable,
                &configuration.cache_library,
            )?;
            let database_key = hsm.current()?;
            context.configure_audit(
                &database_key,
                configuration.logging.audit,
                configuration.truelog_client.as_deref(),
            )?;
            context.enable_session_cache(
                &executable,
                &configuration.cache_library,
                &database_key,
                unix_time()?,
            )?;
            let privileged = PrivilegedRuntime::start(&configuration, database_key)?;
            let supervisor = Arc::new(RuntimeSupervisor::start(configuration.clone(), context)?);
            let context = supervisor.context();
            let recovery = Arc::new(ProductionRecoveryManagement::new(
                Arc::clone(&supervisor),
                configuration.clone(),
                executable,
            ));
            let certificate_renewal: Option<Arc<dyn ScheduledCertificateRenewal>> = if configuration
                .pki_client
                .is_some()
                && configuration.runtime_transports.iter().any(|transport| {
                    matches!(
                        transport,
                        crate::server_configuration::RuntimeTransport::Tls
                            | crate::server_configuration::RuntimeTransport::MutualTls
                    )
                }) {
                Some(Arc::new(ProductionServerCertificateRenewal::new(
                    configuration.clone(),
                    Arc::clone(&supervisor),
                )))
            } else {
                None
            };
            let scheduler = ProductionSchedulerRuntime::start(
                &configuration,
                Arc::clone(&recovery),
                certificate_renewal,
            )?;
            let certificates =
                Arc::new(ProductionCertificateManagement::new(configuration.clone()));
            let signal_bridge = Arc::clone(&shutdown);
            let signal_thread = std::thread::spawn(move || {
                while !SHUTDOWN_REQUESTED.load(Ordering::Acquire)
                    && !signal_bridge.load(Ordering::Acquire)
                {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
                    signal_bridge.store(true, Ordering::Release);
                }
            });
            let server_result = management_service::serve_runtime_server(
                &configuration.management_socket,
                usize::MAX,
                Arc::clone(&context),
                management_service::ManagementCapabilities {
                    transports: configuration
                        .runtime_transports
                        .iter()
                        .map(|transport| match transport {
                            crate::server_configuration::RuntimeTransport::Unix => "UNIX",
                            crate::server_configuration::RuntimeTransport::Tcp => "TCP",
                            crate::server_configuration::RuntimeTransport::Tls => "TLS",
                            crate::server_configuration::RuntimeTransport::MutualTls => "MTLS",
                        })
                        .map(str::to_owned)
                        .collect(),
                    encryption_profiles: vec![
                        "JWE_DIR_A128GCM".into(),
                        "JWE_DIR_A192GCM".into(),
                        "JWE_DIR_A256GCM".into(),
                    ],
                    pki_available: configuration.pki_client.is_some(),
                },
                recovery,
                certificates,
                Arc::clone(&shutdown),
            );
            shutdown.store(true, Ordering::Release);
            let _ = signal_thread.join();
            let scheduler_result = scheduler.shutdown();
            let supervisor_result = supervisor.shutdown();
            let privileged_result = privileged.shutdown();
            server_result?;
            scheduler_result?;
            supervisor_result?;
            privileged_result?;
            Ok("Autobricks JWT server stopped\n".into())
        }
        ServerCommand::ManagementTestServer(path, request_count) => {
            management_service::serve_server(
                &path,
                request_count,
                Arc::new(Mutex::new(ServiceRegistry::default())),
            )?;
            Ok("Management test server stopped\n".into())
        }
        ServerCommand::CacheWorker => {
            worker_process::run_worker()?;
            Ok(String::new())
        }
        ServerCommand::HsmHelper => {
            helper_service::run_from_environment()?;
            Ok(String::new())
        }
    }
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::internal("system time is before the Unix epoch"))
}

#[cfg(test)]
fn open_management_registry<H: HsmDatabaseKeys>(
    configuration: &ServerConfiguration,
    hsm: &H,
) -> Result<Arc<Mutex<ServiceRegistry>>, ServiceError> {
    RuntimeServiceContext::open(
        &configuration.database_path,
        hsm,
        std::time::Duration::from_secs(configuration.timeout_seconds),
        configuration.require_token_for_query_and_revoke,
    )
    .map(|context| context.registry())
}

fn help() -> String {
    format!(
        "{PRODUCT} {VERSION} (C) 2026 Autobricks, Co.\n\
Usage:\n\
  ab-jwtd --initialize PATH\n\
  ab-jwtd --check-config PATH\n\
  ab-jwtd --config PATH\n\
  ab-jwtd --help\n\
  ab-jwtd --version\n\
\n\
Options:\n\
  --check-config PATH  Validate the server configuration without starting listeners.\n\
  -h, --help           Show this help and exit.\n\
  -V, --version        Show the program version and exit.\n"
    )
}

fn render_configuration(configuration: &ServerConfiguration) -> String {
    format!(
        "{PRODUCT} {VERSION}\n\
Configuration: valid\n\
Keep-alive timeout: {} seconds\n\
Require complete token for query and revoke: {}\n\
Certificate renewal time: {}\n\
Backup directory: {}\n\
Backup interval: {} days\n",
        configuration.timeout_seconds,
        configuration.require_token_for_query_and_revoke,
        configuration.certificate_renewal_time,
        configuration.backup_directory.display(),
        configuration.backup_interval_days
    )
}

#[cfg(test)]
mod tests {
    use super::{execute, open_management_registry};
    use crate::{
        VERSION,
        database_key_rotation::HsmDatabaseKeys,
        server_configuration::ServerConfiguration,
        service_error::ServiceError,
        service_registry::{OperationClass, ServiceRegistry},
    };
    use std::{ffi::OsString, fs};
    use uuid::Uuid;

    struct StartupHsm {
        current: [u8; 32],
        available: bool,
    }

    impl HsmDatabaseKeys for StartupHsm {
        fn current(&self) -> Result<[u8; 32], ServiceError> {
            if self.available {
                Ok(self.current)
            } else {
                Err(ServiceError::classified(8085, "HSM is unavailable").unwrap())
            }
        }

        fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
            Ok(None)
        }

        fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
            unreachable!()
        }

        fn commit(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    #[test]
    fn version_uses_repository_version() {
        let output = execute([OsString::from("--version")]).unwrap();
        assert_eq!(output, format!("Autobricks JWT Server {VERSION}\n"));
    }

    #[test]
    fn help_names_the_server_program() {
        let output = execute([OsString::from("--help")]).unwrap();
        assert!(output.contains("ab-jwtd --check-config PATH"));
    }

    #[test]
    fn startup_uses_hsm_current_key_and_restores_durable_management_state() {
        let database_path =
            std::env::temp_dir().join(format!("ab-jwt-startup-{}.db", Uuid::new_v4()));
        let key = [0x71; 32];
        let client_id = {
            let mut registry = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            let client_id = registry
                .register_client("durable-startup-client", OperationClass::Write)
                .unwrap();
            registry
                .register_service(client_id, "durable-startup-service")
                .unwrap();
            client_id
        };
        let configuration = ServerConfiguration::parse(&format!(
            "timeout: 3600\nbackup_directory: /tmp/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\ndatabase_path: {}\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test/startup\n",
            database_path.display()
        ))
        .unwrap();

        let context = open_management_registry(
            &configuration,
            &StartupHsm {
                current: key,
                available: true,
            },
        )
        .expect("startup context");
        let registry = context.lock().unwrap();
        assert_eq!(registry.clients().len(), 1);
        assert_eq!(registry.clients()[0].client_id, client_id);
        assert_eq!(registry.services(client_id).len(), 1);
        drop(registry);
        drop(context);
        fs::remove_file(database_path).unwrap();
    }

    #[test]
    fn startup_fails_closed_when_hsm_current_key_is_unavailable() {
        let configuration = ServerConfiguration::parse(
            "timeout: 3600\nbackup_directory: /tmp/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\ndatabase_path: /tmp/unopened-jwt.db\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test/startup\n",
        )
        .unwrap();
        let error = match open_management_registry(
            &configuration,
            &StartupHsm {
                current: [0; 32],
                available: false,
            },
        ) {
            Ok(_) => panic!("startup must reject an unavailable HSM key"),
            Err(error) => error,
        };
        assert_eq!(error.code(), 8085);
        assert!(!configuration.database_path.exists());
    }
}

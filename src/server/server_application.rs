use std::{
    ffi::OsString,
    sync::{Arc, Mutex},
};

use crate::{
    VERSION,
    database_key_rotation::CommandHsmDatabaseKeys,
    management_service,
    runtime_context::RuntimeServiceContext,
    runtime_listeners::RuntimeListenerSet,
    server_arguments::{self, ServerCommand},
    server_configuration::ServerConfiguration,
    service_error::ServiceError,
    service_registry::ServiceRegistry,
};

#[cfg(test)]
use crate::database_key_rotation::HsmDatabaseKeys;

const PRODUCT: &str = "Autobricks JWT Server";

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
        ServerCommand::Serve(path) => {
            let configuration = ServerConfiguration::load(&path)?;
            let hsm = CommandHsmDatabaseKeys::new(
                &configuration.hsm_helper,
                &configuration.hsm_key_namespace,
            )?;
            let context = RuntimeServiceContext::open(
                &configuration.database_path,
                &hsm,
                std::time::Duration::from_secs(configuration.timeout_seconds),
                configuration.require_token_for_query_and_revoke,
            )?;
            let _runtime_listeners = RuntimeListenerSet::bind(&configuration)?;
            management_service::serve_server(
                &configuration.management_socket,
                usize::MAX,
                context.registry(),
            )?;
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
    }
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

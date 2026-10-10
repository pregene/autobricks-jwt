use std::{
    ffi::OsString,
    sync::{Arc, Mutex},
};

use crate::{
    VERSION, management_service,
    server_arguments::{self, ServerCommand},
    server_configuration::ServerConfiguration,
    service_error::ServiceError,
    service_registry::ServiceRegistry,
};

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
            management_service::serve_server(
                &configuration.management_socket,
                usize::MAX,
                Arc::new(Mutex::new(ServiceRegistry::default())),
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
    use super::execute;
    use crate::VERSION;
    use std::ffi::OsString;

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
}

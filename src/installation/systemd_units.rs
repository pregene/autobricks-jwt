use std::path::Path;

use crate::service_error::ServiceError;

pub struct SystemdUnits {
    pub server: String,
    pub management_broker: String,
}

pub fn validate_service_identities(
    server_user: &str,
    broker_user: &str,
) -> Result<(), ServiceError> {
    if server_user.trim().is_empty()
        || broker_user.trim().is_empty()
        || server_user == broker_user
        || server_user == "root"
        || broker_user == "root"
    {
        return Err(ServiceError::configuration_invalid(
            "server and management broker require distinct non-root identities",
        ));
    }
    Ok(())
}

pub fn render(
    server_binary: &Path,
    cli_binary: &Path,
    configuration: &Path,
) -> Result<SystemdUnits, ServiceError> {
    validate_service_identities("autobricks-jwt", "autobricks-jwt-cli")?;
    for path in [server_binary, cli_binary, configuration] {
        if !path.is_absolute() {
            return Err(ServiceError::configuration_invalid(
                "systemd executable and configuration paths must be absolute",
            ));
        }
    }
    let server_binary = server_binary.display();
    let cli_binary = cli_binary.display();
    let configuration = configuration.display();
    Ok(SystemdUnits {
        server: format!(
            "[Unit]\nDescription=Autobricks JWT Server\nAfter=network.target\n\n\
             [Service]\nType=simple\nUser=autobricks-jwt\nGroup=autobricks-jwt\n\
             ExecStart={server_binary} --config {configuration}\nRestart=on-failure\n\
             NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n\
             ReadWritePaths=/var/lib/autobricks-jwt /run/autobricks-jwt\n\n\
             [Install]\nWantedBy=multi-user.target\n"
        ),
        management_broker: format!(
            "[Unit]\nDescription=Autobricks JWT Management Broker\n\
             After=autobricks-jwt.service\nRequires=autobricks-jwt.service\n\n\
             [Service]\nType=simple\nUser=autobricks-jwt-cli\nGroup=autobricks-jwt-cli\n\
             SupplementaryGroups=autobricks-jwt\n\
             ExecStart={cli_binary} broker --client-socket /run/autobricks-jwt-cli/ab-jwt-cli.sock \
             --server-socket /run/autobricks-jwt/management.sock\nRestart=on-failure\n\
             NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n\
             ReadWritePaths=/run/autobricks-jwt-cli\n\n\
             [Install]\nWantedBy=multi-user.target\n"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_separate_hardened_server_and_broker_services() {
        let units = render(
            Path::new("/usr/sbin/ab-jwtd"),
            Path::new("/usr/bin/ab-jwt-cli"),
            Path::new("/etc/autobricks-jwt/server.conf"),
        )
        .unwrap();
        assert!(units.server.contains("User=autobricks-jwt\n"));
        assert!(
            units
                .server
                .contains("ExecStart=/usr/sbin/ab-jwtd --config")
        );
        assert!(
            units
                .management_broker
                .contains("User=autobricks-jwt-cli\n")
        );
        assert!(
            units
                .management_broker
                .contains("SupplementaryGroups=autobricks-jwt")
        );
        assert!(
            units
                .management_broker
                .contains("--server-socket /run/autobricks-jwt/management.sock")
        );
        assert!(!units.server.contains("User=root"));
        assert!(!units.management_broker.contains("User=root"));
    }

    #[test]
    fn rejects_relative_installation_paths() {
        let error = render(
            Path::new("ab-jwtd"),
            Path::new("/usr/bin/ab-jwt-cli"),
            Path::new("/etc/autobricks-jwt/server.conf"),
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), 8090);
    }

    #[test]
    fn rejects_shared_or_root_service_identities() {
        assert_eq!(
            validate_service_identities("jwt", "jwt")
                .unwrap_err()
                .code(),
            8090
        );
        assert_eq!(
            validate_service_identities("root", "broker")
                .unwrap_err()
                .code(),
            8090
        );
        validate_service_identities("autobricks-jwt", "autobricks-jwt-cli").unwrap();
    }
}

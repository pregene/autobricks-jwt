use std::path::{Path, PathBuf};

use crate::{service_error::ServiceError, systemd_units};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationLayout {
    pub server_binary: PathBuf,
    pub client_binary: PathBuf,
    pub configuration: PathBuf,
    pub state_directory: PathBuf,
    pub server_runtime_directory: PathBuf,
    pub broker_runtime_directory: PathBuf,
    pub server_unit: PathBuf,
    pub broker_unit: PathBuf,
}

impl InstallationLayout {
    pub fn production(prefix: &Path) -> Result<Self, ServiceError> {
        if !prefix.is_absolute() {
            return Err(ServiceError::configuration_invalid(
                "installation prefix must be absolute",
            ));
        }
        let root = |path: &str| prefix.join(path.trim_start_matches('/'));
        let layout = Self {
            server_binary: root("/usr/sbin/ab-jwtd"),
            client_binary: root("/usr/bin/ab-jwt-cli"),
            configuration: root("/etc/autobricks-jwt/server.conf"),
            state_directory: root("/var/lib/autobricks-jwt"),
            server_runtime_directory: root("/run/autobricks-jwt"),
            broker_runtime_directory: root("/run/autobricks-jwt-cli"),
            server_unit: root("/usr/lib/systemd/system/autobricks-jwt.service"),
            broker_unit: root("/usr/lib/systemd/system/autobricks-jwt-cli.service"),
        };
        systemd_units::render(
            &layout.server_binary,
            &layout.client_binary,
            &layout.configuration,
        )?;
        Ok(layout)
    }

    pub fn required_runtime_dependencies() -> &'static [&'static str] {
        &["autobricks-cache", "softhsm2"]
    }

    pub fn optional_security_dependencies() -> &'static [&'static str] {
        &["autobricks-pki-client", "autobricks-truelog-client"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defines_complete_installable_runtime_layout_and_dependency_boundary() {
        let layout = InstallationLayout::production(Path::new("/")).unwrap();
        assert_eq!(layout.server_binary, Path::new("/usr/sbin/ab-jwtd"));
        assert_eq!(layout.client_binary, Path::new("/usr/bin/ab-jwt-cli"));
        assert_eq!(
            layout.server_unit,
            Path::new("/usr/lib/systemd/system/autobricks-jwt.service")
        );
        assert_ne!(
            layout.server_runtime_directory,
            layout.broker_runtime_directory
        );
        assert_eq!(
            InstallationLayout::required_runtime_dependencies(),
            ["autobricks-cache", "softhsm2"]
        );
        assert_eq!(
            InstallationLayout::optional_security_dependencies(),
            ["autobricks-pki-client", "autobricks-truelog-client"]
        );
        assert!(InstallationLayout::production(Path::new("relative")).is_err());
    }
}

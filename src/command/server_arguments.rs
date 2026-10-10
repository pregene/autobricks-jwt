use std::{ffi::OsString, path::PathBuf};

use crate::service_error::ServiceError;

#[derive(Debug, Eq, PartialEq)]
pub enum ServerCommand {
    Help,
    Version,
    CheckConfiguration(PathBuf),
    Serve(PathBuf),
    ManagementTestServer(PathBuf, usize),
}

pub fn parse<I>(arguments: I) -> Result<ServerCommand, ServiceError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments: Vec<OsString> = arguments.into_iter().collect();

    match arguments.as_slice() {
        [] => Ok(ServerCommand::Help),
        [flag] if flag == "-h" || flag == "--help" => Ok(ServerCommand::Help),
        [flag] if flag == "-V" || flag == "--version" => Ok(ServerCommand::Version),
        [flag, path] if flag == "--check-config" => {
            if path.is_empty() {
                return Err(ServiceError::configuration_invalid(
                    "configuration path is empty",
                ));
            }
            Ok(ServerCommand::CheckConfiguration(PathBuf::from(path)))
        }
        [flag, path] if flag == "--config" => {
            if path.is_empty() {
                return Err(ServiceError::configuration_invalid(
                    "configuration path is empty",
                ));
            }
            Ok(ServerCommand::Serve(PathBuf::from(path)))
        }
        [flag, path, request_count] if flag == "--management-test-server" => {
            let request_count = request_count
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    ServiceError::configuration_invalid(
                        "management request count must be a positive integer",
                    )
                })?;
            Ok(ServerCommand::ManagementTestServer(
                PathBuf::from(path),
                request_count,
            ))
        }
        _ => Err(ServiceError::configuration_invalid(
            "invalid ab-jwtd command-line arguments",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerCommand, parse};
    use std::{ffi::OsString, path::PathBuf};

    #[test]
    fn no_arguments_selects_help() {
        assert_eq!(parse(Vec::new()).unwrap(), ServerCommand::Help);
    }

    #[test]
    fn parses_configuration_check() {
        let command = parse([
            OsString::from("--check-config"),
            OsString::from("/etc/autobricks-jwt/server.conf"),
        ])
        .unwrap();

        assert_eq!(
            command,
            ServerCommand::CheckConfiguration(PathBuf::from("/etc/autobricks-jwt/server.conf"))
        );
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = parse([OsString::from("--serve")]).unwrap_err();
        assert_eq!(error.code(), 8090);
    }
}

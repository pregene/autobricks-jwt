use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::service_error::ServiceError;

const MINIMUM_TIMEOUT_SECONDS: u64 = 1;
const MAXIMUM_TIMEOUT_SECONDS: u64 = 86_400;

#[derive(Debug, Eq, PartialEq)]
pub struct ServerConfiguration {
    pub timeout_seconds: u64,
    pub require_token_for_query_and_revoke: bool,
    pub certificate_renewal_time: DailyTime,
    pub backup_directory: PathBuf,
    pub backup_interval_days: u8,
    pub logging: LoggingSelection,
    pub management_socket: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoggingSelection {
    pub request: bool,
    pub query: bool,
    pub issuance: bool,
    pub audit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DailyTime {
    hour: u8,
    minute: u8,
}

impl DailyTime {
    pub fn parse(value: &str) -> Result<Self, ServiceError> {
        let (hour, minute) = value.split_once(':').ok_or_else(|| {
            ServiceError::configuration_invalid(
                "certificate_renewal_time must use 24-hour HH:MM format",
            )
        })?;

        if hour.len() != 2 || minute.len() != 2 {
            return Err(ServiceError::configuration_invalid(
                "certificate_renewal_time must use 24-hour HH:MM format",
            ));
        }

        let hour = hour.parse::<u8>().map_err(|_| {
            ServiceError::configuration_invalid("certificate renewal hour is invalid")
        })?;
        let minute = minute.parse::<u8>().map_err(|_| {
            ServiceError::configuration_invalid("certificate renewal minute is invalid")
        })?;

        if hour > 23 || minute > 59 {
            return Err(ServiceError::configuration_invalid(
                "certificate_renewal_time is outside the valid daily range",
            ));
        }

        Ok(Self { hour, minute })
    }

    pub fn seconds_since_midnight(self) -> u32 {
        u32::from(self.hour) * 3600 + u32::from(self.minute) * 60
    }
}

impl std::fmt::Display for DailyTime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:02}:{:02}", self.hour, self.minute)
    }
}

impl ServerConfiguration {
    pub fn load(path: &Path) -> Result<Self, ServiceError> {
        let contents = fs::read_to_string(path).map_err(|_| {
            ServiceError::configuration_invalid("configuration file cannot be read")
        })?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self, ServiceError> {
        let mut values = BTreeMap::new();

        for (index, raw_line) in contents.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = line.split_once(':').ok_or_else(|| {
                ServiceError::configuration_invalid(format!(
                    "configuration line {} must contain ':'",
                    index + 1
                ))
            })?;
            let key = key.trim();
            let value = value.trim();

            if key.is_empty() || value.is_empty() {
                return Err(ServiceError::configuration_invalid(format!(
                    "configuration line {} has an empty key or value",
                    index + 1
                )));
            }
            if values.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(ServiceError::configuration_invalid(format!(
                    "configuration key '{key}' is duplicated"
                )));
            }
        }

        const KNOWN_KEYS: &[&str] = &[
            "timeout",
            "require_token_for_query_and_revoke",
            "certificate_renewal_time",
            "backup_directory",
            "backup_interval_days",
            "log_request",
            "log_query",
            "log_issuance",
            "log_audit",
            "management_socket",
        ];
        if let Some(key) = values
            .keys()
            .find(|key| !KNOWN_KEYS.contains(&key.as_str()))
        {
            return Err(ServiceError::configuration_invalid(format!(
                "unknown configuration key '{key}'"
            )));
        }

        let timeout_seconds = take_required(&mut values, "timeout")?
            .parse::<u64>()
            .map_err(|_| ServiceError::configuration_invalid("timeout must be an integer"))?;
        if !(MINIMUM_TIMEOUT_SECONDS..=MAXIMUM_TIMEOUT_SECONDS).contains(&timeout_seconds) {
            return Err(ServiceError::configuration_invalid(
                "timeout must be between 1 and 86400 seconds",
            ));
        }

        let require_token_for_query_and_revoke = values
            .remove("require_token_for_query_and_revoke")
            .map(|value| parse_boolean(&value, "require_token_for_query_and_revoke"))
            .transpose()?
            .unwrap_or(true);

        let certificate_renewal_time = values
            .remove("certificate_renewal_time")
            .map(|value| DailyTime::parse(&value))
            .transpose()?
            .unwrap_or(DailyTime { hour: 4, minute: 0 });

        let backup_directory = PathBuf::from(take_required(&mut values, "backup_directory")?);
        if !backup_directory.is_absolute() {
            return Err(ServiceError::configuration_invalid(
                "backup_directory must be an absolute path",
            ));
        }
        let backup_interval_days = values
            .remove("backup_interval_days")
            .map(|value| {
                value.parse::<u8>().map_err(|_| {
                    ServiceError::configuration_invalid("backup_interval_days must be an integer")
                })
            })
            .transpose()?
            .unwrap_or(30);
        if !(7..=30).contains(&backup_interval_days) {
            return Err(ServiceError::configuration_invalid(
                "backup_interval_days must be between 7 and 30",
            ));
        }

        let logging = LoggingSelection {
            request: parse_boolean(&take_required(&mut values, "log_request")?, "log_request")?,
            query: parse_boolean(&take_required(&mut values, "log_query")?, "log_query")?,
            issuance: parse_boolean(&take_required(&mut values, "log_issuance")?, "log_issuance")?,
            audit: parse_boolean(&take_required(&mut values, "log_audit")?, "log_audit")?,
        };

        let management_socket = values
            .remove("management_socket")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/autobricks-jwt/management.sock"));
        if !management_socket.is_absolute() {
            return Err(ServiceError::configuration_invalid(
                "management_socket must be an absolute path",
            ));
        }

        Ok(Self {
            timeout_seconds,
            require_token_for_query_and_revoke,
            certificate_renewal_time,
            backup_directory,
            backup_interval_days,
            logging,
            management_socket,
        })
    }
}

fn take_required(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, ServiceError> {
    values
        .remove(key)
        .ok_or_else(|| ServiceError::configuration_invalid(format!("missing '{key}' setting")))
}

fn parse_boolean(value: &str, key: &str) -> Result<bool, ServiceError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ServiceError::configuration_invalid(format!(
            "'{key}' must be true or false"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{DailyTime, ServerConfiguration};

    #[test]
    fn parses_secure_defaults() {
        let configuration = ServerConfiguration::parse(
            "timeout: 3600\nbackup_directory: /var/lib/autobricks-jwt/backups\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\n",
        )
        .unwrap();

        assert_eq!(configuration.timeout_seconds, 3600);
        assert!(configuration.require_token_for_query_and_revoke);
        assert_eq!(
            configuration.certificate_renewal_time,
            DailyTime::parse("04:00").unwrap()
        );
        assert_eq!(configuration.backup_interval_days, 30);
    }

    #[test]
    fn parses_explicit_values() {
        let configuration = ServerConfiguration::parse(
            "timeout: 900\nrequire_token_for_query_and_revoke: false\ncertificate_renewal_time: 23:45\nbackup_directory: /secure/backup\nbackup_interval_days: 7\nlog_request: false\nlog_query: true\nlog_issuance: false\nlog_audit: true\n",
        )
        .unwrap();

        assert_eq!(configuration.timeout_seconds, 900);
        assert!(!configuration.require_token_for_query_and_revoke);
        assert_eq!(configuration.certificate_renewal_time.to_string(), "23:45");
        assert_eq!(configuration.backup_interval_days, 7);
        assert!(!configuration.logging.request);
        assert!(configuration.logging.query);
    }

    #[test]
    fn rejects_missing_timeout() {
        let error = ServerConfiguration::parse("certificate_renewal_time: 04:00\n").unwrap_err();
        assert_eq!(error.code(), 8090);
    }

    #[test]
    fn rejects_unknown_setting() {
        let error = ServerConfiguration::parse(
            "timeout: 3600\nbackup_directory: /secure/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\nsecret: value\n",
        )
        .unwrap_err();
        assert_eq!(error.code(), 8090);
    }

    #[test]
    fn rejects_invalid_daily_time() {
        let error = ServerConfiguration::parse(
            "timeout: 3600\ncertificate_renewal_time: 24:00\nbackup_directory: /secure/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\n",
        )
        .unwrap_err();
        assert_eq!(error.code(), 8090);
    }

    #[test]
    fn rejects_missing_relative_or_out_of_range_backup_settings() {
        assert_eq!(
            ServerConfiguration::parse("timeout: 3600\n")
                .unwrap_err()
                .code(),
            8090
        );
        assert_eq!(
            ServerConfiguration::parse(
                "timeout: 3600\nbackup_directory: relative\nbackup_interval_days: 30\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\n"
            )
            .unwrap_err()
            .code(),
            8090
        );
        for interval in [6, 31] {
            let input = format!(
                "timeout: 3600\nbackup_directory: /secure/backup\nbackup_interval_days: {interval}\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\n"
            );
            assert_eq!(ServerConfiguration::parse(&input).unwrap_err().code(), 8090);
        }
    }

    #[test]
    fn requires_every_optional_logging_choice() {
        let error = ServerConfiguration::parse(
            "timeout: 3600\nbackup_directory: /secure/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\n",
        )
        .unwrap_err();
        assert_eq!(error.code(), 8090);
    }
}

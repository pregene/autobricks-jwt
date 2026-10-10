use std::ffi::CString;

use serde::Serialize;
use uuid::Uuid;

use crate::service_error::ServiceError;

pub trait LogSink {
    fn write(&mut self, message: &str);
}

pub struct SyslogSink;

impl LogSink for SyslogSink {
    fn write(&mut self, message: &str) {
        let Ok(message) = CString::new(message) else {
            return;
        };
        let format = c"%s";
        // SAFETY: The format is a fixed C string and message is a valid NUL-terminated string.
        unsafe { libc::syslog(libc::LOG_INFO, format.as_ptr(), message.as_ptr()) };
    }
}

pub struct OperationalLogger<S> {
    sink: S,
}

#[derive(Serialize)]
struct ErrorEntry<'a> {
    level: &'static str,
    error_code: u16,
    error_name: &'a str,
    event_at: &'a str,
}

#[derive(Serialize)]
struct ConnectionEntry<'a> {
    event: &'static str,
    result: &'a str,
    transport: &'a str,
    source: &'a str,
    client_id: Option<Uuid>,
    event_at: &'a str,
}

impl<S: LogSink> OperationalLogger<S> {
    pub fn new(sink: S) -> Self {
        Self { sink }
    }

    pub fn classified_error(&mut self, error: &ServiceError, event_at: &str) {
        if let Ok(message) = serde_json::to_string(&ErrorEntry {
            level: "ERROR",
            error_code: error.code(),
            error_name: error.name(),
            event_at,
        }) {
            self.sink.write(&message);
        }
    }

    pub fn connection_access(
        &mut self,
        accepted: bool,
        transport: &str,
        source: &str,
        client_id: Option<Uuid>,
        event_at: &str,
    ) {
        if let Ok(message) = serde_json::to_string(&ConnectionEntry {
            event: "CONNECTION_ACCESS",
            result: if accepted { "ACCEPTED" } else { "REJECTED" },
            transport,
            source,
            client_id,
            event_at,
        }) {
            self.sink.write(&message);
        }
    }

    pub fn into_inner(self) -> S {
        self.sink
    }
}

#[cfg(test)]
mod tests {
    use crate::error_registry::ERROR_REGISTRY;

    use super::*;

    #[derive(Default)]
    struct Capture(Vec<String>);

    impl LogSink for Capture {
        fn write(&mut self, message: &str) {
            self.0.push(message.to_owned());
        }
    }

    #[test]
    fn logs_every_classified_root_error_without_sensitive_detail() {
        let mut logger = OperationalLogger::new(Capture::default());
        for definition in ERROR_REGISTRY {
            let error =
                ServiceError::classified(definition.code, "token=secret apikey=secret").unwrap();
            logger.classified_error(&error, "2026-10-11T00:00:00Z");
        }
        let capture = logger.into_inner();
        assert_eq!(capture.0.len(), ERROR_REGISTRY.len());
        for (message, definition) in capture.0.iter().zip(ERROR_REGISTRY) {
            let value: serde_json::Value = serde_json::from_str(message).unwrap();
            assert_eq!(value["error_code"], definition.code);
            assert_eq!(value["error_name"], definition.name);
            assert!(!message.contains("secret"));
            assert!(value.get("message").is_none());
        }
    }

    #[test]
    fn connection_access_is_mandatory_and_redacted() {
        let mut logger = OperationalLogger::new(Capture::default());
        logger.connection_access(
            true,
            "MTLS",
            "192.0.2.10",
            Some(Uuid::nil()),
            "2026-10-11T00:00:00Z",
        );
        logger.connection_access(false, "TCP", "198.51.100.20", None, "2026-10-11T00:00:01Z");
        let capture = logger.into_inner();
        assert_eq!(capture.0.len(), 2);
        assert!(capture.0[0].contains("ACCEPTED"));
        assert!(capture.0[1].contains("REJECTED"));
        assert!(
            capture
                .0
                .iter()
                .all(|entry| !entry.contains("apikey") && !entry.contains("token"))
        );
    }
}

use std::borrow::Cow;

use crate::error_registry::{ErrorDefinition, definition};

#[derive(Debug, Eq, PartialEq)]
pub enum ClientDisposition {
    Respond(ServiceError),
    Close,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ServiceError {
    code: u16,
    name: &'static str,
    public_message: Cow<'static, str>,
}

impl ServiceError {
    pub fn classified(
        code: u16,
        message: impl Into<Cow<'static, str>>,
    ) -> Result<Self, &'static str> {
        definition(code)
            .map(|definition| Self::from_definition(definition, message))
            .ok_or("error code is not assigned by ERROR.md")
    }

    pub fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8000, "INTERNAL_ERROR", message)
    }

    pub fn invalid_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8001, "INVALID_REQUEST", message)
    }

    pub fn service_unavailable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8009, "SERVICE_UNAVAILABLE", message)
    }

    pub fn client_registration_inactive(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8020, "CLIENT_REGISTRATION_INACTIVE", message)
    }

    pub fn service_not_registered(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8040, "SERVICE_NOT_REGISTERED", message)
    }

    pub fn configuration_invalid(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8090, "CONFIGURATION_INVALID", message)
    }

    pub fn invalid_subject(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8051, "INVALID_SUBJECT", message)
    }

    pub fn source_data_unavailable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8053, "SOURCE_DATA_UNAVAILABLE", message)
    }

    pub fn jwt_encryption_failed(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8055, "JWT_ENCRYPTION_FAILED", message)
    }

    pub fn jwt_invalid(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8061, "JWT_INVALID", message)
    }

    pub fn jwt_audience_invalid(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8062, "JWT_AUDIENCE_INVALID", message)
    }

    pub fn field_not_authorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(8064, "FIELD_NOT_AUTHORIZED", message)
    }

    fn new(code: u16, name: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            name,
            public_message: message.into(),
        }
    }

    fn from_definition(
        definition: &ErrorDefinition,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(definition.code, definition.name, message)
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn public_message(&self) -> &str {
        &self.public_message
    }

    pub fn client_disposition(&self) -> ClientDisposition {
        use crate::error_registry::ErrorExposure;
        match definition(self.code).map(|value| value.exposure) {
            Some(ErrorExposure::Public) => ClientDisposition::Respond(Self::new(
                self.code,
                self.name,
                self.public_message.clone(),
            )),
            Some(ErrorExposure::Generic) => ClientDisposition::Respond(Self::new(
                self.code,
                self.name,
                "request could not be completed",
            )),
            Some(ErrorExposure::Close) => ClientDisposition::Close,
            Some(ErrorExposure::Internal) | None => {
                ClientDisposition::Respond(Self::internal("request could not be completed"))
            }
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} {}: {}",
            self.code, self.name, self.public_message
        )
    }
}

impl std::error::Error for ServiceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_registry::ERROR_REGISTRY;

    #[test]
    fn constructs_every_assigned_error_and_rejects_reserved_codes() {
        for definition in ERROR_REGISTRY {
            let error = ServiceError::classified(definition.code, "safe test message")
                .expect("assigned error must be constructible");
            assert_eq!(error.code(), definition.code);
            assert_eq!(error.name(), definition.name);
            assert_eq!(error.public_message(), "safe test message");
        }

        for reserved in [8033, 8045, 8057, 8067, 8074, 8087, 8094, 8100] {
            assert!(ServiceError::classified(reserved, "reserved").is_err());
        }
    }

    #[test]
    fn maps_every_exposure_without_disclosing_internal_messages() {
        use crate::error_registry::ErrorExposure;
        for definition in ERROR_REGISTRY {
            let root = ServiceError::classified(definition.code, "sensitive root detail").unwrap();
            match (definition.exposure, root.client_disposition()) {
                (ErrorExposure::Close, ClientDisposition::Close) => {}
                (ErrorExposure::Public, ClientDisposition::Respond(mapped)) => {
                    assert_eq!(mapped.code(), definition.code);
                    assert_eq!(mapped.public_message(), "sensitive root detail");
                }
                (ErrorExposure::Generic, ClientDisposition::Respond(mapped)) => {
                    assert_eq!(mapped.code(), definition.code);
                    assert!(!mapped.public_message().contains("sensitive"));
                }
                (ErrorExposure::Internal, ClientDisposition::Respond(mapped)) => {
                    assert_eq!(mapped.code(), 8000);
                    assert!(!mapped.public_message().contains("sensitive"));
                }
                other => panic!("incorrect error exposure mapping: {other:?}"),
            }
        }
    }
}

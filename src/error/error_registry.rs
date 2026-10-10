#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorExposure {
    Public,
    Generic,
    Close,
    Internal,
}

impl ErrorExposure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Generic => "GENERIC",
            Self::Close => "CLOSE",
            Self::Internal => "INTERNAL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorDefinition {
    pub code: u16,
    pub name: &'static str,
    pub exposure: ErrorExposure,
}

use ErrorExposure::{Close, Generic, Internal, Public};

pub const ERROR_REGISTRY: &[ErrorDefinition] = &[
    error(8000, "INTERNAL_ERROR", Generic),
    error(8001, "INVALID_REQUEST", Public),
    error(8002, "UNSUPPORTED_OPERATION", Public),
    error(8003, "UNSUPPORTED_PROTOCOL_VERSION", Public),
    error(8004, "REQUEST_TOO_LARGE", Public),
    error(8005, "MALFORMED_FRAME", Close),
    error(8006, "REQUEST_TIMEOUT", Public),
    error(8007, "RATE_LIMITED", Public),
    error(8008, "TOO_MANY_REQUESTS", Public),
    error(8009, "SERVICE_UNAVAILABLE", Generic),
    error(8010, "CLIENT_CERTIFICATE_REQUIRED", Close),
    error(8011, "CERTIFICATE_CHAIN_INVALID", Close),
    error(8012, "CERTIFICATE_TIME_INVALID", Close),
    error(8013, "CERTIFICATE_PURPOSE_INVALID", Close),
    error(8014, "CERTIFICATE_AIA_OCSP_MISSING", Close),
    error(8015, "OCSP_UNAVAILABLE", Close),
    error(8016, "OCSP_RESPONSE_INVALID", Close),
    error(8017, "CERTIFICATE_REVOKED", Close),
    error(8018, "CERTIFICATE_STATUS_UNKNOWN", Close),
    error(8019, "CERTIFICATE_NOT_REGISTERED", Close),
    error(8020, "CLIENT_REGISTRATION_INACTIVE", Close),
    error(8021, "CERTIFICATE_USAGE_INVALID", Close),
    error(8022, "CERTIFICATE_USAGE_MISMATCH", Close),
    error(8023, "CONNECTION_IDENTITY_CHANGED", Close),
    error(8024, "CONNECTION_IDLE_TIMEOUT", Close),
    error(8025, "CONNECTION_LIFETIME_EXCEEDED", Close),
    error(8026, "CERTIFICATE_CONNECTION_EXPIRED", Close),
    error(8027, "CERTIFICATE_REGISTRATION_KEY_INVALID", Close),
    error(8028, "SERVICE_CERTIFICATE_BINDING_MISMATCH", Close),
    error(8029, "CERTIFICATE_HANDOVER_FAILED", Internal),
    error(8030, "APIKEY_AUTHENTICATION_FAILED", Generic),
    error(8031, "APIKEY_OPERATION_FORBIDDEN", Public),
    error(8032, "OPERATION_CLASS_MISMATCH", Public),
    error(8040, "SERVICE_NOT_REGISTERED", Generic),
    error(8041, "SERVICE_REGISTRATION_INACTIVE", Generic),
    error(8042, "SUBJECT_TYPE_FORBIDDEN", Public),
    error(8043, "FIELD_QUERY_FORBIDDEN", Public),
    error(8044, "SERVICE_CERTIFICATE_PROVISIONING_FAILED", Internal),
    error(8050, "JWT_ISSUANCE_FAILED", Generic),
    error(8051, "INVALID_SUBJECT", Public),
    error(8052, "SOURCE_NOT_CONFIGURED", Public),
    error(8053, "SOURCE_DATA_UNAVAILABLE", Generic),
    error(8054, "SOURCE_DATA_INVALID", Generic),
    error(8055, "JWT_ENCRYPTION_FAILED", Internal),
    error(8056, "SESSION_CREATE_FAILED", Internal),
    error(8060, "SESSION_NOT_FOUND_OR_EXPIRED", Generic),
    error(8061, "JWT_INVALID", Generic),
    error(8062, "JWT_AUDIENCE_INVALID", Generic),
    error(8063, "FIELD_LIST_INVALID", Public),
    error(8064, "FIELD_NOT_AUTHORIZED", Public),
    error(8065, "FIELD_VALUE_UNAVAILABLE", Generic),
    error(8066, "SESSION_RETENTION_FAILED", Internal),
    error(8070, "AUDIT_WRITE_FAILED", Internal),
    error(8071, "AUDIT_RECEIPT_INVALID", Internal),
    error(8072, "AUDIT_RECEIPT_STORE_FAILED", Internal),
    error(8073, "AUDIT_RECONCILIATION_REQUIRED", Internal),
    error(8080, "DATABASE_UNAVAILABLE", Internal),
    error(8081, "DATABASE_OPERATION_FAILED", Internal),
    error(8082, "CACHE_UNAVAILABLE", Internal),
    error(8083, "CACHE_OPERATION_FAILED", Internal),
    error(8084, "KEY_STORE_UNAVAILABLE", Internal),
    error(8085, "HSM_UNAVAILABLE", Internal),
    error(8086, "KEY_OPERATION_FAILED", Internal),
    error(8090, "CONFIGURATION_INVALID", Internal),
    error(8091, "DEPENDENCY_UNAVAILABLE", Internal),
    error(8092, "SHUTTING_DOWN", Generic),
    error(8093, "CAPACITY_EXCEEDED", Generic),
];

const fn error(code: u16, name: &'static str, exposure: ErrorExposure) -> ErrorDefinition {
    ErrorDefinition {
        code,
        name,
        exposure,
    }
}

pub fn definition(code: u16) -> Option<&'static ErrorDefinition> {
    ERROR_REGISTRY
        .binary_search_by_key(&code, |definition| definition.code)
        .ok()
        .map(|index| &ERROR_REGISTRY[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const EXPECTED_CODES: &[u16] = &[
        8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011, 8012, 8013, 8014,
        8015, 8016, 8017, 8018, 8019, 8020, 8021, 8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029,
        8030, 8031, 8032, 8040, 8041, 8042, 8043, 8044, 8050, 8051, 8052, 8053, 8054, 8055, 8056,
        8060, 8061, 8062, 8063, 8064, 8065, 8066, 8070, 8071, 8072, 8073, 8080, 8081, 8082, 8083,
        8084, 8085, 8086, 8090, 8091, 8092, 8093,
    ];

    #[test]
    fn registry_contains_every_non_reserved_error_once() {
        let actual_codes = ERROR_REGISTRY
            .iter()
            .map(|definition| definition.code)
            .collect::<Vec<_>>();
        assert_eq!(actual_codes, EXPECTED_CODES);
        assert!(ERROR_REGISTRY.iter().all(|definition| {
            (8000..=8100).contains(&definition.code) && !definition.name.is_empty()
        }));
        assert_eq!(
            ERROR_REGISTRY
                .iter()
                .map(|definition| definition.name)
                .collect::<HashSet<_>>()
                .len(),
            ERROR_REGISTRY.len()
        );
    }

    #[test]
    #[ignore = "prints the complete ERROR.md registry for the executable test report"]
    fn prints_every_non_reserved_error() {
        for definition in ERROR_REGISTRY {
            println!(
                "Error registry: {} {} {}",
                definition.code,
                definition.name,
                definition.exposure.as_str()
            );
        }
        println!("Error registry count: {}", ERROR_REGISTRY.len());
    }
}

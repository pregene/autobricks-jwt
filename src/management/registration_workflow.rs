use std::path::Path;

use uuid::Uuid;

use crate::{
    connection_policy::ConnectionPolicy,
    database_source::{DatabaseSourceInput, DatabaseSourcePlan},
    management_protocol::ManagementRequest,
    service_error::ServiceError,
    service_registry::{ClientJsonField, ClientUpdate, OperationClass},
};

const SUPPORTED_TRANSPORTS: [&str; 4] = ["UNIX", "TCP", "TLS", "MTLS"];

#[derive(Clone, Debug)]
pub struct ClientRegistrationForm {
    pub client_name: String,
    pub operation_class: OperationClass,
    pub allowed_source_cidr: String,
    pub transports: Vec<String>,
    pub keep_alive_timeout: u64,
    pub peer_uid: Option<u32>,
    pub peer_gid: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum ServiceSourceForm {
    Read {
        allowed_fields: Vec<String>,
        allowed_issuer_service_ids: Vec<Uuid>,
    },
    ClientJson {
        encryption_profile: String,
        fields: Vec<ClientJsonField>,
    },
    Database {
        encryption_profile: String,
        source: DatabaseSourceInput,
    },
}

#[derive(Clone, Debug)]
pub struct ServiceRegistrationForm {
    pub client_id: Uuid,
    pub service_name: String,
    pub subject_type: String,
    pub operation_class: OperationClass,
    pub source: ServiceSourceForm,
}

impl ClientRegistrationForm {
    pub fn register_request(
        &self,
        enabled_transports: &[String],
    ) -> Result<ManagementRequest, ServiceError> {
        validate_client(self, enabled_transports)?;
        Ok(ManagementRequest::RegisterClient {
            client_name: self.client_name.trim().into(),
            operation_class: self.operation_class,
            allowed_source_cidr: self.allowed_source_cidr.trim().into(),
            transports: self.transports.clone(),
            keep_alive_timeout: self.keep_alive_timeout,
            peer_uid: self.peer_uid,
            peer_gid: self.peer_gid,
        })
    }

    pub fn modification_request(
        &self,
        client_id: Uuid,
        enabled_transports: &[String],
    ) -> Result<ManagementRequest, ServiceError> {
        validate_client(self, enabled_transports)?;
        Ok(ManagementRequest::ModifyClient {
            client_id,
            update: ClientUpdate {
                client_name: self.client_name.trim().into(),
                allowed_source_cidr: self.allowed_source_cidr.trim().into(),
                transports: self.transports.clone(),
                keep_alive_timeout: self.keep_alive_timeout,
                peer_uid: self.peer_uid,
                peer_gid: self.peer_gid,
            },
        })
    }
}

impl ServiceRegistrationForm {
    pub fn request(&self) -> Result<ManagementRequest, ServiceError> {
        if self.service_name.trim().is_empty()
            || !matches!(self.subject_type.as_str(), "USER" | "DEVICE" | "WORKLOAD")
        {
            return Err(invalid("service registration identity is invalid"));
        }
        let (allowed_fields, issuers, source_type, encryption, schema, database_source) =
            match (&self.operation_class, &self.source) {
                (
                    OperationClass::Read,
                    ServiceSourceForm::Read {
                        allowed_fields,
                        allowed_issuer_service_ids,
                    },
                ) if !allowed_fields.is_empty() && !allowed_issuer_service_ids.is_empty() => (
                    unique_fields(allowed_fields)?,
                    allowed_issuer_service_ids.clone(),
                    None,
                    None,
                    None,
                    None,
                ),
                (
                    OperationClass::Write,
                    ServiceSourceForm::ClientJson {
                        encryption_profile,
                        fields,
                    },
                ) if !fields.is_empty() => (
                    Vec::new(),
                    Vec::new(),
                    Some("CLIENT_JSON".into()),
                    Some(valid_profile(encryption_profile)?),
                    Some(fields.clone()),
                    None,
                ),
                (
                    OperationClass::Write,
                    ServiceSourceForm::Database {
                        encryption_profile,
                        source,
                    },
                ) => {
                    DatabaseSourcePlan::build(source.clone())?;
                    (
                        Vec::new(),
                        Vec::new(),
                        Some("DATABASE".into()),
                        Some(valid_profile(encryption_profile)?),
                        None,
                        Some(source.clone()),
                    )
                }
                _ => {
                    return Err(invalid(
                        "service source does not match the client permission",
                    ));
                }
            };
        Ok(ManagementRequest::RegisterService {
            client_id: self.client_id,
            service_name: self.service_name.trim().into(),
            subject_type: self.subject_type.clone(),
            allowed_jwt_query_fields: allowed_fields,
            allowed_issuer_service_ids: issuers,
            source_type,
            encryption_profile: encryption,
            client_json_schema: schema,
            database_source,
        })
    }

    pub fn test_database_connection(&self, cache_library: &Path) -> Result<(), ServiceError> {
        let ServiceSourceForm::Database { source, .. } = &self.source else {
            return Err(invalid("DATABASE source is not selected"));
        };
        let cache = DatabaseSourcePlan::build(source.clone())?.test_connection(cache_library)?;
        cache.uninitialize()
    }
}

pub fn comma_fields(value: &str) -> Result<Vec<String>, ServiceError> {
    unique_fields(
        &value
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    )
}

fn validate_client(
    form: &ClientRegistrationForm,
    enabled_transports: &[String],
) -> Result<(), ServiceError> {
    if form.client_name.trim().is_empty() || form.transports.is_empty() {
        return Err(invalid("client registration fields are incomplete"));
    }
    ConnectionPolicy::new(
        form.allowed_source_cidr.trim(),
        form.keep_alive_timeout,
        form.keep_alive_timeout.saturating_mul(2),
    )?;
    for (index, transport) in form.transports.iter().enumerate() {
        if !SUPPORTED_TRANSPORTS.contains(&transport.as_str())
            || !enabled_transports.contains(transport)
            || form.transports[..index].contains(transport)
        {
            return Err(invalid("client transport is unavailable or duplicated"));
        }
    }
    let unix = form.transports.iter().any(|value| value == "UNIX");
    if unix != (form.peer_uid.is_some() || form.peer_gid.is_some()) {
        return Err(invalid(
            "UNIX transport requires peer UID or GID only when enabled",
        ));
    }
    Ok(())
}

fn unique_fields(fields: &[String]) -> Result<Vec<String>, ServiceError> {
    if fields.is_empty()
        || fields.iter().any(|field| field.trim().is_empty())
        || fields.iter().enumerate().any(|(index, field)| {
            fields[..index]
                .iter()
                .any(|prior| prior.trim() == field.trim())
        })
    {
        return Err(invalid("field list is empty or contains duplicates"));
    }
    Ok(fields.iter().map(|field| field.trim().into()).collect())
}

fn valid_profile(profile: &str) -> Result<String, ServiceError> {
    matches!(
        profile,
        "JWE_DIR_A128GCM" | "JWE_DIR_A192GCM" | "JWE_DIR_A256GCM"
    )
    .then(|| profile.to_owned())
    .ok_or_else(|| invalid("JWT encryption profile is invalid"))
}

fn invalid(message: &'static str) -> ServiceError {
    ServiceError::invalid_request(message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::database_source::{DatabaseConnectionInput, DatabaseTlsMode, QueryBinding};

    use super::*;

    #[test]
    fn builds_client_registration_and_modification_from_enabled_transport_selection() {
        let form = ClientRegistrationForm {
            client_name: "web-write".into(),
            operation_class: OperationClass::Write,
            allowed_source_cidr: "192.0.2.0/24".into(),
            transports: vec!["UNIX".into(), "MTLS".into()],
            keep_alive_timeout: 3600,
            peer_uid: Some(1000),
            peer_gid: None,
        };
        let enabled = vec!["UNIX".into(), "TCP".into(), "TLS".into(), "MTLS".into()];
        assert!(matches!(
            form.register_request(&enabled).unwrap(),
            ManagementRequest::RegisterClient { .. }
        ));
        assert!(matches!(
            form.modification_request(Uuid::new_v4(), &enabled).unwrap(),
            ManagementRequest::ModifyClient { .. }
        ));
        assert!(form.register_request(&["UNIX".into()]).is_err());
    }

    #[test]
    fn builds_independent_read_or_write_service_registration() {
        let issuer = Uuid::new_v4();
        let read = ServiceRegistrationForm {
            client_id: Uuid::new_v4(),
            service_name: "session-query".into(),
            subject_type: "USER".into(),
            operation_class: OperationClass::Read,
            source: ServiceSourceForm::Read {
                allowed_fields: comma_fields("user_id, role").unwrap(),
                allowed_issuer_service_ids: vec![issuer],
            },
        };
        let value = serde_json::to_value(read.request().unwrap()).unwrap();
        assert_eq!(value["operation"], "REGISTER_SERVICE");
        assert_eq!(
            value["allowed_jwt_query_fields"],
            json!(["user_id", "role"])
        );
        assert_eq!(value["allowed_issuer_service_ids"], json!([issuer]));
        assert!(value["source_type"].is_null());

        let write = ServiceRegistrationForm {
            client_id: Uuid::new_v4(),
            service_name: "session-create".into(),
            subject_type: "USER".into(),
            operation_class: OperationClass::Write,
            source: ServiceSourceForm::ClientJson {
                encryption_profile: "JWE_DIR_A256GCM".into(),
                fields: vec![ClientJsonField {
                    name: "user_id".into(),
                    value_type: crate::service_registry::ClientJsonValueType::String,
                    required: true,
                }],
            },
        };
        let value = serde_json::to_value(write.request().unwrap()).unwrap();
        assert_eq!(value["source_type"], "CLIENT_JSON");
        assert!(
            value["allowed_jwt_query_fields"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn builds_complete_cache_database_registration_without_insert_or_delete() {
        let source = DatabaseSourceInput {
            connection: DatabaseConnectionInput {
                name: "subjects".into(),
                driver: "postgresql".into(),
                host: "db.example".into(),
                port: 5432,
                database: "subjects".into(),
                queue_directory: "/var/lib/autobricks-jwt/queue".into(),
                username: "jwt".into(),
                password: "secret".into(),
                tls_mode: DatabaseTlsMode::Tls,
                ca_file: Some("/etc/autobricks-jwt/db-trust.pem".into()),
                certificate: None,
                private_key: None,
                connect_timeout_ms: 2000,
                query_timeout_ms: 5000,
                pool_size: 4,
                sqlite_options: None,
            },
            primary_key: vec!["user_id".into()],
            maps: vec![vec!["user_id".into()]],
            select: QueryBinding {
                query: "SELECT user_id, role FROM users WHERE user_id=$1".into(),
                fields: vec!["user_id".into()],
            },
            update: Some(QueryBinding {
                query: "UPDATE users SET last_ip=$1 WHERE user_id=$2".into(),
                fields: vec!["last_ip".into(), "user_id".into()],
            }),
            retention_seconds: 3600,
        };
        let request = ServiceRegistrationForm {
            client_id: Uuid::new_v4(),
            service_name: "database-issuer".into(),
            subject_type: "USER".into(),
            operation_class: OperationClass::Write,
            source: ServiceSourceForm::Database {
                encryption_profile: "JWE_DIR_A256GCM".into(),
                source,
            },
        }
        .request()
        .unwrap();
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["source_type"], "DATABASE");
        assert_eq!(value["database_source"]["connection"]["tls_mode"], "TLS");
        assert!(value.get("insert").is_none());
        assert!(value.get("delete").is_none());
    }
}

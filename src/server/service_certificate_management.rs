use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::{
    database_key_rotation::{CommandHsmDatabaseKeys, HsmDatabaseKeys},
    management_protocol::ManagementRequest,
    management_service::{CertificateManagement, ManagementOperationResult},
    pki_provisioning::PkiProvisioner,
    server_configuration::ServerConfiguration,
    service_certificate::{CertificateTools, ServiceCertificateRepository},
    service_error::ServiceError,
    service_registry::ServiceRegistry,
};

pub struct ProductionCertificateManagement {
    configuration: ServerConfiguration,
}

impl ProductionCertificateManagement {
    pub fn new(configuration: ServerConfiguration) -> Self {
        Self { configuration }
    }
}

impl CertificateManagement for ProductionCertificateManagement {
    fn process(
        &self,
        registry: &Arc<Mutex<ServiceRegistry>>,
        request: &ManagementRequest,
    ) -> Option<Result<ManagementOperationResult, ServiceError>> {
        let ManagementRequest::RegisterService {
            client_id,
            service_name,
            subject_type,
            allowed_jwt_query_fields,
            allowed_issuer_service_ids,
            source_type,
            encryption_profile,
            client_json_schema,
            database_source,
        } = request
        else {
            return None;
        };
        let client = match registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))
            .and_then(|registry| {
                registry
                    .clients()
                    .into_iter()
                    .find(|client| client.client_id == *client_id)
                    .ok_or_else(|| {
                        ServiceError::invalid_request("client registration is not available")
                    })
            }) {
            Ok(client) => client,
            Err(error) => return Some(Err(error)),
        };
        if !client
            .transports
            .iter()
            .any(|transport| transport == "MTLS")
        {
            return None;
        }
        let result = (|| {
            let pki_client = self.configuration.pki_client.as_ref().ok_or_else(|| {
                ServiceError::classified(8044, "PKI client is unavailable").expect("assigned error")
            })?;
            let issuer = self.configuration.pki_issuer.as_deref().ok_or_else(|| {
                ServiceError::classified(8044, "PKI issuer is unavailable").expect("assigned error")
            })?;
            let staging = self
                .configuration
                .pki_staging_directory
                .as_deref()
                .ok_or_else(|| {
                    ServiceError::classified(8044, "PKI staging is unavailable")
                        .expect("assigned error")
                })?;
            let credential = {
                let mut registry = registry
                    .lock()
                    .map_err(|_| ServiceError::internal("service registry lock failed"))?;
                if let Some(source) = database_source.clone() {
                    if source_type.as_deref() != Some("DATABASE")
                        || !allowed_jwt_query_fields.is_empty()
                        || !allowed_issuer_service_ids.is_empty()
                        || client_json_schema.is_some()
                    {
                        return Err(ServiceError::invalid_request(
                            "DATABASE service registration fields conflict",
                        ));
                    }
                    registry
                        .register_database_service(
                            *client_id,
                            service_name,
                            subject_type,
                            encryption_profile.as_deref().unwrap_or_default(),
                            source,
                        )?
                        .0
                } else {
                    registry.register_service_with_source_schema_and_issuers(
                        *client_id,
                        service_name,
                        subject_type,
                        allowed_jwt_query_fields.clone(),
                        source_type.clone(),
                        encryption_profile.clone(),
                        client_json_schema.clone(),
                        allowed_issuer_service_ids.clone(),
                    )?
                }
            };
            let provisioner = PkiProvisioner::new(pki_client, issuer);
            let tools = certificate_tools(&self.configuration, pki_client);
            let common_name = certificate_common_name(credential.service_id);
            let package = match provisioner.provision_and_verify_client(
                &common_name,
                client.operation_class,
                staging,
                &tools,
            ) {
                Ok(package) => package,
                Err(error) => {
                    if let Ok(mut registry) = registry.lock() {
                        let _ = registry.delete_service(*client_id, credential.service_id);
                    }
                    return Err(error);
                }
            };
            let pending = (|| {
                let hsm = CommandHsmDatabaseKeys::new(
                    &self.configuration.hsm_helper,
                    &self.configuration.hsm_key_namespace,
                )?;
                let key = hsm.current()?;
                let mut certificates =
                    ServiceCertificateRepository::open(&self.configuration.database_path, &key)?;
                certificates.begin_initial_registration(
                    credential.service_id,
                    *client_id,
                    client.operation_class,
                    &package.metadata,
                    unix_time()?,
                    self.configuration.timeout_seconds,
                )
            })();
            let pending = match pending {
                Ok(pending) => pending,
                Err(error) => {
                    if let Ok(mut registry) = registry.lock() {
                        let _ = registry.delete_service(*client_id, credential.service_id);
                    }
                    return Err(error);
                }
            };
            let value = json!({
                "service": credential,
                "certificate": {
                    "certificate_id": pending.certificate_id,
                    "request_id": pending.request_id,
                    "fingerprint": package.fingerprint,
                    "uri_san": package.uri_san,
                    "status": "PENDING",
                    "not_after": package.metadata.not_after,
                    "expires_at": pending.expires_at
                },
                "temporary_certificate_registration_key": pending.registration_key
            });
            Ok(ManagementOperationResult {
                value,
                attachment_name: Some(package.archive_name),
                attachment: Some(package.archive),
            })
        })();
        Some(result)
    }
}

fn certificate_common_name(service_id: uuid::Uuid) -> String {
    let identifier = service_id.simple().to_string();
    format!("jwt-{}", &identifier[..20])
}

fn certificate_tools(
    configuration: &ServerConfiguration,
    pki_client: &std::path::Path,
) -> CertificateTools {
    let tools = CertificateTools::new(&configuration.openssl, pki_client);
    configuration
        .ocsp_responder_override
        .as_ref()
        .map_or(tools.clone(), |url| tools.with_ocsp_responder_override(url))
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::internal("system time is before the Unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::certificate_common_name;
    use crate::server_configuration::ServerConfiguration;

    #[test]
    fn creates_pki_compatible_unique_service_certificate_common_name() {
        let service_id = uuid::Uuid::parse_str("12345678-90ab-cdef-1234-567890abcdef").unwrap();
        let common_name = certificate_common_name(service_id);
        assert_eq!(common_name, "jwt-1234567890abcdef1234");
        assert_eq!(common_name.len(), 24);
    }

    #[test]
    fn validates_optional_ocsp_responder_override() {
        let base = "timeout: 3600\nbackup_directory: /secure/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\ndatabase_path: /secure/jwt.db\nhsm_helper: /usr/libexec/autobricks-jwt-hsm\nhsm_key_namespace: autobricks-jwt/database\n";
        let valid = ServerConfiguration::parse(&format!(
            "{base}ocsp_responder_override: https://192.0.2.10:5546/ocsp/\n"
        ))
        .unwrap();
        assert_eq!(
            valid.ocsp_responder_override.as_deref(),
            Some("https://192.0.2.10:5546/ocsp/")
        );
        assert_eq!(
            ServerConfiguration::parse(&format!("{base}ocsp_responder_override: file:///unsafe\n"))
                .unwrap_err()
                .code(),
            8090
        );
    }
}

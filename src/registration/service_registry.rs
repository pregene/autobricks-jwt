use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{digest, pbkdf2};
use uuid::Uuid;

use crate::{
    database_source::{DatabaseSourceInput, DatabaseSourcePlan},
    service_error::ServiceError,
    sqlcipher_registration_repository::SqlCipherRegistrationRepository,
};

const APIKEY_LENGTH: usize = 32;
const APIKEY_SALT_LENGTH: usize = 16;
const APIKEY_VERIFIER_LENGTH: usize = digest::SHA256_OUTPUT_LEN;
const APIKEY_ITERATIONS: u32 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OperationClass {
    Read,
    Write,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ClientRegistration {
    pub client_id: Uuid,
    pub client_name: String,
    pub operation_class: OperationClass,
    pub allowed_source_cidr: String,
    pub transports: Vec<String>,
    pub keep_alive_timeout: u64,
    pub peer_uid: Option<u32>,
    pub peer_gid: Option<u32>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ClientUpdate {
    pub client_name: String,
    pub allowed_source_cidr: String,
    pub transports: Vec<String>,
    pub keep_alive_timeout: u64,
    pub peer_uid: Option<u32>,
    pub peer_gid: Option<u32>,
}

#[derive(Debug, serde::Serialize)]
pub struct ServiceCredential {
    pub service_id: Uuid,
    pub client_id: Uuid,
    pub service_name: String,
    pub apikey: String,
    pub subject_type: String,
    pub allowed_jwt_query_fields: Vec<String>,
    pub source_type: Option<String>,
    pub encryption_profile: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ServiceSummary {
    pub service_id: Uuid,
    pub client_id: Uuid,
    pub service_name: String,
    pub subject_type: String,
    pub allowed_jwt_query_fields: Vec<String>,
    pub source_type: Option<String>,
    pub encryption_profile: Option<String>,
    pub client_json_schema: Option<Vec<ClientJsonField>>,
    pub database_source: Option<DatabaseSourcePlan>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ClientJsonField {
    pub name: String,
    pub value_type: ClientJsonValueType,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClientJsonValueType {
    String,
    Number,
    Boolean,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClientDeletionResult {
    pub client_id: Uuid,
    pub deleted_service_count: usize,
    pub revoked_apikey_count: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredServiceRegistration {
    pub(crate) service_id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) service_name: String,
    pub(crate) apikey_salt: [u8; APIKEY_SALT_LENGTH],
    pub(crate) apikey_verifier: [u8; APIKEY_VERIFIER_LENGTH],
    pub(crate) subject_type: String,
    pub(crate) allowed_jwt_query_fields: Vec<String>,
    pub(crate) source_type: Option<String>,
    pub(crate) encryption_profile: Option<String>,
    pub(crate) client_json_schema: Option<Vec<ClientJsonField>>,
    pub(crate) database_source: Option<DatabaseSourcePlan>,
}

#[derive(Default)]
pub struct ServiceRegistry {
    clients: BTreeMap<Uuid, ClientRegistration>,
    services: BTreeMap<Uuid, StoredServiceRegistration>,
    repository: Option<SqlCipherRegistrationRepository>,
}

impl ServiceRegistry {
    pub fn open_sqlcipher(path: &Path, key: &[u8; 32]) -> Result<Self, ServiceError> {
        let repository = SqlCipherRegistrationRepository::open(path, key)?;
        let clients = repository
            .load_active_clients()?
            .into_iter()
            .map(|client| (client.client_id, client))
            .collect();
        let services = repository
            .load_active_services()?
            .into_iter()
            .map(|service| (service.service_id, service))
            .collect();
        Ok(Self {
            clients,
            services,
            repository: Some(repository),
        })
    }

    pub fn register_client(
        &mut self,
        client_name: &str,
        operation_class: OperationClass,
    ) -> Result<Uuid, ServiceError> {
        self.register_client_with_configuration(
            client_name,
            operation_class,
            "127.0.0.1/32",
            vec!["UNIX".to_owned()],
            3600,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_client_with_configuration(
        &mut self,
        client_name: &str,
        operation_class: OperationClass,
        allowed_source_cidr: &str,
        transports: Vec<String>,
        keep_alive_timeout: u64,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
    ) -> Result<Uuid, ServiceError> {
        if client_name.trim().is_empty()
            || self
                .clients
                .values()
                .any(|client| client.client_name == client_name)
            || allowed_source_cidr.trim().is_empty()
            || transports.is_empty()
            || keep_alive_timeout == 0
        {
            return Err(ServiceError::invalid_request(
                "client name is empty or already registered",
            ));
        }

        let client_id = Uuid::new_v4();
        let client = ClientRegistration {
            client_id,
            client_name: client_name.to_owned(),
            operation_class,
            allowed_source_cidr: allowed_source_cidr.to_owned(),
            transports,
            keep_alive_timeout,
            peer_uid,
            peer_gid,
        };
        if let Some(repository) = &mut self.repository {
            repository.insert_client(&client, unix_time())?;
        }
        self.clients.insert(client_id, client);
        Ok(client_id)
    }

    pub fn register_service(
        &mut self,
        client_id: Uuid,
        service_name: &str,
    ) -> Result<ServiceCredential, ServiceError> {
        let operation_class = self
            .clients
            .get(&client_id)
            .map(|client| client.operation_class)
            .ok_or_else(|| ServiceError::invalid_request("client registration is not available"))?;
        let (fields, source_type, encryption_profile) = match operation_class {
            OperationClass::Read => (vec!["user_id".to_owned()], None, None),
            OperationClass::Write => (
                Vec::new(),
                Some("CLIENT_JSON".to_owned()),
                Some("JWE_DIR_A256GCM".to_owned()),
            ),
        };
        let schema = (operation_class == OperationClass::Write).then(|| {
            vec![
                ClientJsonField {
                    name: "user_id".into(),
                    value_type: ClientJsonValueType::String,
                    required: true,
                },
                ClientJsonField {
                    name: "role".into(),
                    value_type: ClientJsonValueType::String,
                    required: false,
                },
            ]
        });
        self.register_service_with_source_schema(
            client_id,
            service_name,
            "USER",
            fields,
            source_type,
            encryption_profile,
            schema,
        )
    }

    pub fn register_service_with_configuration(
        &mut self,
        client_id: Uuid,
        service_name: &str,
        subject_type: &str,
        allowed_jwt_query_fields: Vec<String>,
        source_type: Option<String>,
        encryption_profile: Option<String>,
    ) -> Result<ServiceCredential, ServiceError> {
        let client_json_schema = (source_type.as_deref() == Some("CLIENT_JSON")).then(|| {
            let subject_field = match subject_type {
                "DEVICE" => "device_id",
                "WORKLOAD" => "workload_id",
                _ => "user_id",
            };
            vec![ClientJsonField {
                name: subject_field.into(),
                value_type: ClientJsonValueType::String,
                required: true,
            }]
        });
        self.register_service_with_source_schema(
            client_id,
            service_name,
            subject_type,
            allowed_jwt_query_fields,
            source_type,
            encryption_profile,
            client_json_schema,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_service_with_source_schema(
        &mut self,
        client_id: Uuid,
        service_name: &str,
        subject_type: &str,
        allowed_jwt_query_fields: Vec<String>,
        source_type: Option<String>,
        encryption_profile: Option<String>,
        client_json_schema: Option<Vec<ClientJsonField>>,
    ) -> Result<ServiceCredential, ServiceError> {
        let client = self
            .clients
            .get(&client_id)
            .ok_or_else(|| ServiceError::invalid_request("client registration is not available"))?;
        if !matches!(subject_type, "USER" | "DEVICE" | "WORKLOAD") {
            return Err(ServiceError::invalid_request("subject type is invalid"));
        }
        match client.operation_class {
            OperationClass::Read if allowed_jwt_query_fields.is_empty() => {
                return Err(ServiceError::invalid_request(
                    "READ service requires allowed JWT query fields",
                ));
            }
            OperationClass::Write if source_type.is_none() || encryption_profile.is_none() => {
                return Err(ServiceError::invalid_request(
                    "WRITE service requires source and encryption profile",
                ));
            }
            _ => {}
        }
        if client.operation_class == OperationClass::Write
            && !matches!(
                encryption_profile.as_deref(),
                Some("JWE_DIR_A128GCM" | "JWE_DIR_A192GCM" | "JWE_DIR_A256GCM")
            )
        {
            return Err(ServiceError::invalid_request(
                "WRITE service encryption profile is invalid",
            ));
        }
        if source_type.as_deref() == Some("CLIENT_JSON") {
            let schema = client_json_schema.as_ref().ok_or_else(|| {
                ServiceError::invalid_request("CLIENT_JSON source requires a field schema")
            })?;
            if schema.is_empty()
                || schema.iter().any(|field| field.name.is_empty())
                || schema.iter().enumerate().any(|(index, field)| {
                    schema[..index].iter().any(|prior| prior.name == field.name)
                })
            {
                return Err(ServiceError::invalid_request(
                    "CLIENT_JSON field schema is invalid",
                ));
            }
        }
        if service_name.trim().is_empty()
            || self
                .services
                .values()
                .any(|service| service.service_name == service_name)
        {
            return Err(ServiceError::invalid_request(
                "service name is empty or already registered",
            ));
        }

        let service_id = Uuid::new_v4();
        let mut apikey_bytes = [0_u8; APIKEY_LENGTH];
        let mut apikey_salt = [0_u8; APIKEY_SALT_LENGTH];
        getrandom::fill(&mut apikey_bytes)
            .map_err(|_| ServiceError::internal("APIKEY generation failed"))?;
        getrandom::fill(&mut apikey_salt)
            .map_err(|_| ServiceError::internal("APIKEY salt generation failed"))?;
        let apikey = URL_SAFE_NO_PAD.encode(apikey_bytes);
        let apikey_verifier = derive_apikey_verifier(&apikey, &apikey_salt);

        let stored_service = StoredServiceRegistration {
            service_id,
            client_id,
            service_name: service_name.to_owned(),
            apikey_salt,
            apikey_verifier,
            subject_type: subject_type.to_owned(),
            allowed_jwt_query_fields: allowed_jwt_query_fields.clone(),
            source_type: source_type.clone(),
            encryption_profile: encryption_profile.clone(),
            client_json_schema: client_json_schema.clone(),
            database_source: None,
        };
        if let Some(repository) = &mut self.repository {
            repository.insert_service(&stored_service, unix_time())?;
        }
        self.services.insert(service_id, stored_service);

        Ok(ServiceCredential {
            service_id,
            client_id,
            service_name: service_name.to_owned(),
            apikey,
            subject_type: subject_type.to_owned(),
            allowed_jwt_query_fields,
            source_type,
            encryption_profile,
        })
    }

    pub fn register_database_service(
        &mut self,
        client_id: Uuid,
        service_name: &str,
        subject_type: &str,
        encryption_profile: &str,
        source: DatabaseSourceInput,
    ) -> Result<(ServiceCredential, DatabaseSourcePlan), ServiceError> {
        let plan = DatabaseSourcePlan::build(source)?;
        let credential = self.register_service_with_source_schema(
            client_id,
            service_name,
            subject_type,
            vec![],
            Some("DATABASE".into()),
            Some(encryption_profile.into()),
            None,
        )?;
        if let Some(repository) = &mut self.repository {
            repository.set_database_source(credential.service_id, &plan)?;
        }
        self.services
            .get_mut(&credential.service_id)
            .expect("registered service exists")
            .database_source = Some(plan.clone());
        Ok((credential, plan))
    }

    pub fn clients(&self) -> Vec<ClientRegistration> {
        self.clients.values().cloned().collect()
    }

    pub fn update_client(
        &mut self,
        client_id: Uuid,
        update: ClientUpdate,
    ) -> Result<ClientRegistration, ServiceError> {
        if update.client_name.trim().is_empty()
            || update.allowed_source_cidr.trim().is_empty()
            || update.transports.is_empty()
            || update.keep_alive_timeout == 0
            || self.clients.values().any(|client| {
                client.client_id != client_id && client.client_name == update.client_name
            })
        {
            return Err(ServiceError::invalid_request(
                "client modification contains an invalid or duplicate value",
            ));
        }
        let current = self.clients.get(&client_id).cloned().ok_or_else(|| {
            ServiceError::client_registration_inactive("client registration is not active")
        })?;
        if let Some(repository) = &mut self.repository {
            repository.update_client(
                client_id,
                &update.client_name,
                &update.allowed_source_cidr,
                &update.transports,
                update.keep_alive_timeout,
                update.peer_uid,
                update.peer_gid,
                unix_time(),
            )?;
        }
        let replacement = ClientRegistration {
            client_id,
            client_name: update.client_name,
            operation_class: current.operation_class,
            allowed_source_cidr: update.allowed_source_cidr,
            transports: update.transports,
            keep_alive_timeout: update.keep_alive_timeout,
            peer_uid: update.peer_uid,
            peer_gid: update.peer_gid,
        };
        self.clients.insert(client_id, replacement.clone());
        Ok(replacement)
    }

    pub fn set_client_active(&mut self, client_id: Uuid, active: bool) -> Result<(), ServiceError> {
        let repository = self.repository.as_mut().ok_or_else(|| {
            ServiceError::configuration_invalid(
                "durable client lifecycle requires SQLCipher registration storage",
            )
        })?;
        repository.set_client_active(client_id, active, unix_time())?;
        self.clients = repository
            .load_active_clients()?
            .into_iter()
            .map(|client| (client.client_id, client))
            .collect();
        self.services = repository
            .load_active_services()?
            .into_iter()
            .map(|service| (service.service_id, service))
            .collect();
        Ok(())
    }

    pub fn services(&self, client_id: Uuid) -> Vec<ServiceSummary> {
        self.services
            .values()
            .filter(|service| service.client_id == client_id)
            .map(|service| ServiceSummary {
                service_id: service.service_id,
                client_id: service.client_id,
                service_name: service.service_name.clone(),
                subject_type: service.subject_type.clone(),
                allowed_jwt_query_fields: service.allowed_jwt_query_fields.clone(),
                source_type: service.source_type.clone(),
                encryption_profile: service.encryption_profile.clone(),
                client_json_schema: service.client_json_schema.clone(),
                database_source: service.database_source.clone(),
            })
            .collect()
    }

    pub fn authorize(
        &self,
        client_id: Uuid,
        service_id: Uuid,
        apikey: &str,
        required_operation: OperationClass,
    ) -> Result<(), ServiceError> {
        let client = self.clients.get(&client_id).ok_or_else(|| {
            ServiceError::client_registration_inactive("client registration is not active")
        })?;
        if client.operation_class != required_operation {
            return Err(ServiceError::invalid_request(
                "client operation class is not authorized",
            ));
        }

        let service = self.services.get(&service_id).ok_or_else(|| {
            ServiceError::service_not_registered("service registration is not available")
        })?;
        if service.service_id != service_id || service.client_id != client_id {
            return Err(ServiceError::invalid_request(
                "service is not bound to the client",
            ));
        }

        let submitted_verifier = derive_apikey_verifier(apikey, &service.apikey_salt);
        if !constant_time_equal(&submitted_verifier, &service.apikey_verifier) {
            return Err(ServiceError::invalid_request(
                "service APIKEY is not authorized",
            ));
        }
        Ok(())
    }

    pub fn authorize_service_by_apikey(
        &self,
        client_id: Uuid,
        apikey: &str,
        required_operation: OperationClass,
    ) -> Result<ServiceSummary, ServiceError> {
        let client = self.clients.get(&client_id).ok_or_else(|| {
            ServiceError::client_registration_inactive("client registration is not active")
        })?;
        if client.operation_class != required_operation {
            return Err(ServiceError::classified(
                8031,
                "APIKEY does not permit the requested operation",
            )
            .expect("8031 must be assigned"));
        }

        let mut authorized = None;
        for service in self
            .services
            .values()
            .filter(|service| service.client_id == client_id)
        {
            let submitted = derive_apikey_verifier(apikey, &service.apikey_salt);
            if constant_time_equal(&submitted, &service.apikey_verifier) {
                authorized = Some(ServiceSummary {
                    service_id: service.service_id,
                    client_id: service.client_id,
                    service_name: service.service_name.clone(),
                    subject_type: service.subject_type.clone(),
                    allowed_jwt_query_fields: service.allowed_jwt_query_fields.clone(),
                    source_type: service.source_type.clone(),
                    encryption_profile: service.encryption_profile.clone(),
                    client_json_schema: service.client_json_schema.clone(),
                    database_source: service.database_source.clone(),
                });
            }
        }
        authorized.ok_or_else(|| {
            ServiceError::classified(8030, "APIKEY authentication failed")
                .expect("8030 must be assigned")
        })
    }

    pub fn service_count(&self, client_id: Uuid) -> usize {
        self.services
            .values()
            .filter(|service| service.client_id == client_id)
            .count()
    }

    pub fn delete_service(
        &mut self,
        client_id: Uuid,
        service_id: Uuid,
    ) -> Result<(), ServiceError> {
        let service = self.services.get(&service_id).ok_or_else(|| {
            ServiceError::service_not_registered("service registration is not available")
        })?;
        if service.client_id != client_id {
            return Err(ServiceError::service_not_registered(
                "service registration is not available",
            ));
        }
        if let Some(repository) = &mut self.repository {
            repository.delete_service(service_id, unix_time())?;
        }
        self.services.remove(&service_id);
        Ok(())
    }

    pub fn delete_client(&mut self, client_id: Uuid) -> Result<ClientDeletionResult, ServiceError> {
        if !self.clients.contains_key(&client_id) {
            return Err(ServiceError::client_registration_inactive(
                "client registration is not active",
            ));
        }

        let service_ids: Vec<Uuid> = self
            .services
            .values()
            .filter(|service| service.client_id == client_id)
            .map(|service| service.service_id)
            .collect();
        if let Some(repository) = &mut self.repository {
            let deleted = repository.delete_client_cascade(client_id, unix_time())?;
            if deleted != service_ids.len() {
                return Err(ServiceError::classified(
                    8081,
                    "registration cascade count does not match active state",
                )
                .expect("8081 must be assigned"));
            }
        }
        self.clients.remove(&client_id);
        for service_id in &service_ids {
            self.services.remove(service_id);
        }

        Ok(ClientDeletionResult {
            client_id,
            deleted_service_count: service_ids.len(),
            revoked_apikey_count: service_ids.len(),
        })
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn derive_apikey_verifier(
    apikey: &str,
    salt: &[u8; APIKEY_SALT_LENGTH],
) -> [u8; APIKEY_VERIFIER_LENGTH] {
    let mut verifier = [0_u8; APIKEY_VERIFIER_LENGTH];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(APIKEY_ITERATIONS).expect("APIKEY iterations must be nonzero"),
        salt,
        apikey.as_bytes(),
        &mut verifier,
    );
    verifier
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use crate::{autobricks_cache::AutobricksCache, jwe_token::IssuedToken};

    use super::{OperationClass, ServiceRegistry};

    #[test]
    fn sqlcipher_registry_survives_restart_and_preserves_deleted_history() {
        let database_path = std::env::temp_dir().join(format!(
            "autobricks-jwt-registration-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = [0x37; 32];

        let (client_id, service_id, apikey) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            let client_id = registry
                .register_client_with_configuration(
                    "persistent-write",
                    OperationClass::Write,
                    "192.0.2.0/24",
                    vec!["UNIX".into(), "MTLS".into()],
                    3600,
                    Some(501),
                    Some(20),
                )
                .unwrap();
            let service = registry
                .register_service_with_configuration(
                    client_id,
                    "persistent-issuer",
                    "USER",
                    Vec::new(),
                    Some("DATABASE".into()),
                    Some("JWE_DIR_A256GCM".into()),
                )
                .unwrap();
            (client_id, service.service_id, service.apikey)
        };

        {
            let mut reopened = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            assert_eq!(reopened.clients().len(), 1);
            assert_eq!(reopened.services(client_id).len(), 1);
            reopened
                .authorize(client_id, service_id, &apikey, OperationClass::Write)
                .unwrap();
            reopened.delete_service(client_id, service_id).unwrap();
        }

        {
            let reopened = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            assert_eq!(reopened.clients().len(), 1);
            assert!(reopened.services(client_id).is_empty());
            assert_eq!(
                reopened
                    .repository
                    .as_ref()
                    .unwrap()
                    .status("services", service_id)
                    .unwrap()
                    .as_deref(),
                Some("DELETED")
            );
        }

        {
            let mut reopened = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            reopened.delete_client(client_id).unwrap();
        }

        {
            let reopened = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
            assert!(reopened.clients().is_empty());
            assert_eq!(
                reopened
                    .repository
                    .as_ref()
                    .unwrap()
                    .status("clients", client_id)
                    .unwrap()
                    .as_deref(),
                Some("DELETED")
            );
        }

        assert!(ServiceRegistry::open_sqlcipher(&database_path, &[0x38; 32]).is_err());
        fs::remove_file(database_path).unwrap();
    }

    #[test]
    fn modifies_and_transitions_durable_client_lifecycle() {
        let database_path = std::env::temp_dir().join(format!(
            "autobricks-jwt-lifecycle-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key = [0x47; 32];
        let mut registry = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
        let client_id = registry
            .register_client("lifecycle-write", OperationClass::Write)
            .unwrap();
        let service = registry
            .register_service(client_id, "lifecycle-service")
            .unwrap();
        let updated = registry
            .update_client(
                client_id,
                super::ClientUpdate {
                    client_name: "lifecycle-write-updated".into(),
                    allowed_source_cidr: "192.0.2.0/24".into(),
                    transports: vec!["UNIX".into(), "MTLS".into()],
                    keep_alive_timeout: 900,
                    peer_uid: Some(501),
                    peer_gid: Some(20),
                },
            )
            .unwrap();
        assert_eq!(updated.operation_class, OperationClass::Write);
        assert_eq!(updated.keep_alive_timeout, 900);
        registry.set_client_active(client_id, false).unwrap();
        assert!(registry.clients().is_empty());
        assert!(registry.services(client_id).is_empty());
        assert_eq!(
            registry
                .authorize(
                    client_id,
                    service.service_id,
                    &service.apikey,
                    OperationClass::Write,
                )
                .unwrap_err()
                .code(),
            8020
        );
        assert_eq!(
            registry
                .repository
                .as_ref()
                .unwrap()
                .status("clients", client_id)
                .unwrap()
                .as_deref(),
            Some("INACTIVE")
        );
        registry.set_client_active(client_id, true).unwrap();
        registry
            .authorize(
                client_id,
                service.service_id,
                &service.apikey,
                OperationClass::Write,
            )
            .unwrap();
        drop(registry);

        let reopened = ServiceRegistry::open_sqlcipher(&database_path, &key).unwrap();
        let client = &reopened.clients()[0];
        assert_eq!(client.client_name, "lifecycle-write-updated");
        assert_eq!(client.allowed_source_cidr, "192.0.2.0/24");
        assert_eq!(client.transports, ["UNIX", "MTLS"]);
        assert_eq!(client.keep_alive_timeout, 900);
        drop(reopened);
        fs::remove_file(database_path).unwrap();
    }

    #[test]
    fn registers_multiple_services_for_one_client() {
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("web-service-write", OperationClass::Write)
            .unwrap();
        registry
            .register_service(client_id, "web-service-login")
            .unwrap();
        registry
            .register_service(client_id, "web-service-refresh")
            .unwrap();
        registry
            .register_service(client_id, "web-service-logout")
            .unwrap();
        assert_eq!(registry.service_count(client_id), 3);
    }

    #[test]
    fn rejects_apikey_from_another_service() {
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("web-service-write", OperationClass::Write)
            .unwrap();
        let login = registry
            .register_service(client_id, "web-service-login")
            .unwrap();
        let refresh = registry
            .register_service(client_id, "web-service-refresh")
            .unwrap();

        let error = registry
            .authorize(
                client_id,
                refresh.service_id,
                &login.apikey,
                OperationClass::Write,
            )
            .unwrap_err();
        assert_eq!(error.code(), 8001);
    }

    #[test]
    fn deletes_service_and_cascades_remaining_services_with_client() {
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("web-service-write", OperationClass::Write)
            .unwrap();
        let login = registry
            .register_service(client_id, "web-service-login")
            .unwrap();
        registry
            .register_service(client_id, "web-service-refresh")
            .unwrap();
        registry
            .register_service(client_id, "web-service-logout")
            .unwrap();

        registry
            .delete_service(client_id, login.service_id)
            .unwrap();
        assert_eq!(registry.service_count(client_id), 2);
        let result = registry.delete_client(client_id).unwrap();
        assert_eq!(result.deleted_service_count, 2);
        assert_eq!(result.revoked_apikey_count, 2);
        assert_eq!(registry.service_count(client_id), 0);
        let error = registry
            .authorize(
                client_id,
                login.service_id,
                &login.apikey,
                OperationClass::Write,
            )
            .unwrap_err();
        assert_eq!(error.code(), 8020);
    }

    #[test]
    #[ignore = "requires Autobricks Cache and the local web-service PostgreSQL database"]
    fn cache_registration_token_and_cleanup_flow() {
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("web-service-write", OperationClass::Write)
            .unwrap();
        let login_service = registry
            .register_service(client_id, "web-service-login")
            .unwrap();
        let refresh_service = registry
            .register_service(client_id, "web-service-refresh")
            .unwrap();
        let logout_service = registry
            .register_service(client_id, "web-service-logout")
            .unwrap();

        assert_eq!(registry.service_count(client_id), 3);
        registry
            .authorize(
                client_id,
                login_service.service_id,
                &login_service.apikey,
                OperationClass::Write,
            )
            .unwrap();
        let mismatched_apikey = registry
            .authorize(
                client_id,
                refresh_service.service_id,
                &login_service.apikey,
                OperationClass::Write,
            )
            .unwrap_err();
        assert_eq!(mismatched_apikey.code(), 8001);

        let library_path = required_path("AUTOBRICKS_JWT_TEST_CACHE_LIBRARY");
        let connection_config =
            fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_CONNECTION")).unwrap();
        let cache_config =
            fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_DEFINITION")).unwrap();
        let cache =
            AutobricksCache::initialize(&library_path, &connection_config, &cache_config).unwrap();
        let initial_status = cache.status("jwt-user-cache").unwrap();
        assert_eq!(initial_status["record_count"], 0);
        let records = cache
            .query("jwt-user-cache", &json!({"user_id": "user-0001"}))
            .unwrap();
        assert_eq!(records.len(), 1);
        let mut claims = records[0].as_object().unwrap().clone();
        claims.remove("id");
        assert!(!claims.contains_key("password_hash"));
        assert!(!claims.contains_key("last_ip"));
        assert_eq!(claims["user_id"], "user-0001");
        let loaded_status = cache.status("jwt-user-cache").unwrap();
        assert_eq!(loaded_status["record_count"], 1);
        let cached_records = cache
            .query("jwt-user-cache", &json!({"user_id": "user-0001"}))
            .unwrap();
        assert_eq!(cached_records, records);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let audience = login_service.service_id.to_string();
        let issued = IssuedToken::issue(
            "autobricks-jwt",
            &audience,
            "user-0001",
            claims,
            now,
            Duration::from_secs(3_600),
        )
        .unwrap();
        let fields = issued
            .verify_and_query(
                &issued.token,
                &audience,
                now,
                &["user_id", "display_name", "role", "status"],
            )
            .unwrap();
        assert_eq!(fields["user_id"], "user-0001");

        let mut modified = issued.token.clone();
        modified.push('A');
        assert_eq!(
            issued
                .verify_and_query(&modified, &audience, now, &["user_id"])
                .unwrap_err()
                .code(),
            8061
        );

        println!("Client issued: {client_id} (WRITE)");
        println!(
            "Service issued: {} ({})",
            login_service.service_id, login_service.service_name
        );
        println!(
            "Service issued: {} ({})",
            refresh_service.service_id, refresh_service.service_name
        );
        println!(
            "Service issued: {} ({})",
            logout_service.service_id, logout_service.service_name
        );
        println!("Service APIKEY verification: matching service accepted");
        println!("Service APIKEY isolation: cross-service use rejected with 8001 INVALID_REQUEST");
        println!("Autobricks Cache library: loaded");
        println!("Autobricks Cache mode: ON_DEMAND");
        println!("Autobricks Cache MAP: user_id");
        println!("Autobricks Cache initial records: 0");
        println!("Autobricks Cache loaded records: 1");
        println!("Autobricks Cache repeated lookup: matched");
        println!("Token created: {}", issued.token_id);
        println!("Token format: JWE Compact A256GCM");
        println!("Token verification: authorized fields matched");
        println!("Token tamper check: rejected with 8061 JWT_INVALID");

        cache.uninitialize().unwrap();
        println!("Autobricks Cache shutdown: completed");

        registry
            .delete_service(client_id, login_service.service_id)
            .unwrap();
        println!("Service deleted: {}", login_service.service_id);
        let deletion = registry.delete_client(client_id).unwrap();
        assert_eq!(deletion.deleted_service_count, 2);
        assert_eq!(deletion.revoked_apikey_count, 2);
        assert_eq!(registry.service_count(client_id), 0);
        assert_eq!(
            registry
                .authorize(
                    client_id,
                    refresh_service.service_id,
                    &refresh_service.apikey,
                    OperationClass::Write,
                )
                .unwrap_err()
                .code(),
            8020
        );
        println!("Client deleted: {client_id}");
        println!("Cascaded services deleted: 2");
        println!("APIKEYs revoked: 3 total");
        println!("Registration cleanup: no active client or service remains");
    }

    fn required_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
    }
}

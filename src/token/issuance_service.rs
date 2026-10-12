use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    database_source::DatabaseSourceCache,
    jwe_token::{EncryptionProfile, IssuedToken},
    service_error::ServiceError,
    service_registry::{OperationClass, ServiceRegistry},
    session_cache::SessionCache,
    sqlcipher_token_repository::SqlCipherTokenRepository,
    truelog_audit::AuditRecorder,
};

const ISSUER: &str = "autobricks-jwt";
const RESERVED_CLAIMS: [&str; 9] = [
    "iss",
    "sub",
    "aud",
    "iat",
    "nbf",
    "exp",
    "jti",
    "subject_type",
    "claims",
];

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtCreateRequest {
    pub client_id: Uuid,
    pub apikey: String,
    pub request_id: Uuid,
    pub data: Map<String, Value>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtCreateResponse {
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: String,
}

pub struct IssuanceService<'a> {
    registry: &'a ServiceRegistry,
    tokens: &'a mut SqlCipherTokenRepository,
    lifetime: Duration,
}

impl<'a> IssuanceService<'a> {
    pub fn new(
        registry: &'a ServiceRegistry,
        tokens: &'a mut SqlCipherTokenRepository,
        lifetime: Duration,
    ) -> Result<Self, ServiceError> {
        if lifetime.is_zero() {
            return Err(ServiceError::configuration_invalid(
                "token lifetime must be greater than zero",
            ));
        }
        Ok(Self {
            registry,
            tokens,
            lifetime,
        })
    }

    pub fn create(
        &mut self,
        request: JwtCreateRequest,
        now: u64,
    ) -> Result<JwtCreateResponse, ServiceError> {
        validate_create_request(&request)?;
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        if let Some(existing) = self
            .tokens
            .load_active_by_request(request.client_id, request.request_id)?
        {
            return Ok(response(request.request_id, existing));
        }

        if service.source_type.as_deref() != Some("CLIENT_JSON") {
            return Err(ServiceError::assigned(
                8052,
                "CLIENT_JSON is not configured for this service",
            ));
        }

        reject_reserved_claims(&request.data)?;
        if let Some(schema) = &service.client_json_schema {
            if request
                .data
                .keys()
                .any(|name| !schema.iter().any(|field| &field.name == name))
            {
                return Err(ServiceError::assigned(
                    8054,
                    "subject data contains an unregistered field",
                ));
            }
            for field in schema {
                let value = request.data.get(&field.name);
                if field.required && value.is_none() {
                    return Err(ServiceError::assigned(
                        8054,
                        "required subject field is missing",
                    ));
                }
                if let Some(value) = value {
                    use crate::service_registry::ClientJsonValueType;
                    let matches = match field.value_type {
                        ClientJsonValueType::String => value.is_string(),
                        ClientJsonValueType::Number => value.is_number(),
                        ClientJsonValueType::Boolean => value.is_boolean(),
                    };
                    if !matches {
                        return Err(ServiceError::assigned(
                            8054,
                            "subject field type is invalid",
                        ));
                    }
                }
            }
        }
        self.issue_subject(request, &service, now)
    }

    pub fn create_from_database<C: DatabaseSourceCache>(
        &mut self,
        request: JwtCreateRequest,
        now: u64,
        cache: &C,
    ) -> Result<JwtCreateResponse, ServiceError> {
        validate_create_request(&request)?;
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        if let Some(existing) = self
            .tokens
            .load_active_by_request(request.client_id, request.request_id)?
        {
            return Ok(response(request.request_id, existing));
        }
        if service.source_type.as_deref() != Some("DATABASE") {
            return Err(ServiceError::assigned(
                8052,
                "DATABASE is not configured for this service",
            ));
        }
        let plan = service
            .database_source
            .as_ref()
            .ok_or_else(|| ServiceError::assigned(8052, "DATABASE source plan is unavailable"))?;
        let conditions = Value::Object(request.data);
        let record = plan.load_subject(cache, &conditions)?;
        let data = record
            .as_object()
            .cloned()
            .ok_or_else(|| ServiceError::assigned(8054, "DATABASE subject record is invalid"))?;
        reject_reserved_claims(&data)?;
        self.issue_subject(
            JwtCreateRequest {
                client_id: request.client_id,
                apikey: request.apikey,
                request_id: request.request_id,
                data,
            },
            &service,
            now,
        )
    }

    fn issue_subject(
        &mut self,
        request: JwtCreateRequest,
        service: &crate::service_registry::ServiceSummary,
        now: u64,
    ) -> Result<JwtCreateResponse, ServiceError> {
        let encryption_profile = EncryptionProfile::from_registration(
            service.encryption_profile.as_deref().unwrap_or_default(),
        )?;
        let subject_field = subject_field(&service.subject_type)?;
        let subject = request
            .data
            .get(subject_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ServiceError::invalid_subject("subject identifier is invalid"))?;
        let issued = IssuedToken::issue_with_profile(
            ISSUER,
            &service.service_id.to_string(),
            subject,
            request.data.clone(),
            now,
            self.lifetime,
            encryption_profile,
        )?;
        self.tokens.store_issued(
            request.client_id,
            service.service_id,
            request.request_id,
            &issued,
        )?;
        Ok(response(request.request_id, issued))
    }

    pub fn create_audited<A: AuditRecorder>(
        &mut self,
        request: JwtCreateRequest,
        now: u64,
        event_at: &str,
        audit: &mut A,
    ) -> Result<JwtCreateResponse, ServiceError> {
        let request_id = request.request_id;
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        let service_id = service.service_id;
        let subject_type = service.subject_type.clone();
        let response = self.create(request, now)?;
        audit.issued(
            service_id,
            &subject_type,
            request_id,
            response.token_id,
            event_at,
        )?;
        Ok(response)
    }

    pub fn create_cached<C: SessionCache>(
        &mut self,
        request: JwtCreateRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<JwtCreateResponse, ServiceError> {
        let response = self.create(request, now)?;
        let token = self
            .tokens
            .load_active(response.token_id)?
            .ok_or_else(|| ServiceError::internal("issued token was not persisted"))?;
        cache.insert(token.token_id, &token.token, token.expires_at)?;
        Ok(response)
    }
}

fn validate_create_request(request: &JwtCreateRequest) -> Result<(), ServiceError> {
    if request.apikey.is_empty() || request.data.is_empty() {
        Err(ServiceError::invalid_request(
            "APIKEY and subject data are required",
        ))
    } else {
        Ok(())
    }
}

fn reject_reserved_claims(data: &Map<String, Value>) -> Result<(), ServiceError> {
    if RESERVED_CLAIMS
        .iter()
        .any(|field| data.contains_key(*field))
    {
        Err(ServiceError::assigned(
            8054,
            "subject data contains a JWT-controlled field",
        ))
    } else {
        Ok(())
    }
}

fn subject_field(subject_type: &str) -> Result<&'static str, ServiceError> {
    match subject_type {
        "USER" => Ok("user_id"),
        "DEVICE" => Ok("device_id"),
        "WORKLOAD" => Ok("workload_id"),
        _ => Err(ServiceError::invalid_subject("subject type is invalid")),
    }
}

fn response(request_id: Uuid, issued: IssuedToken) -> JwtCreateResponse {
    JwtCreateResponse {
        request_id,
        token_id: issued.token_id,
        token: issued.token,
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, fs};

    use base64::Engine;
    use serde_json::{Map, Value};

    use super::*;
    use crate::database_source::{
        DatabaseConnectionInput, DatabaseSourceCache, DatabaseSourceInput, DatabaseTlsMode,
        QueryBinding,
    };
    use crate::session_cache::tests::MemorySessionCache;

    struct SubjectCache {
        queries: Cell<usize>,
    }

    impl DatabaseSourceCache for SubjectCache {
        fn query(&self, _: &str, input: &Value) -> Result<Vec<Value>, ServiceError> {
            self.queries.set(self.queries.get() + 1);
            assert_eq!(input["user_id"], "database-user");
            Ok(vec![serde_json::json!({
                "id": 7,
                "user_id": "database-user",
                "role": "member"
            })])
        }

        fn update(&self, _: &str, _: &Value) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct AuditCapture {
        issued: Vec<(Uuid, String, Uuid, Uuid, String)>,
    }

    impl AuditRecorder for AuditCapture {
        fn issued(
            &mut self,
            service_id: Uuid,
            subject_type: &str,
            request_id: Uuid,
            token_id: Uuid,
            event_at: &str,
        ) -> Result<(), ServiceError> {
            self.issued.push((
                service_id,
                subject_type.into(),
                request_id,
                token_id,
                event_at.into(),
            ));
            Ok(())
        }

        fn invalid_session(
            &mut self,
            _service_id: Uuid,
            _request_id: Uuid,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }

        fn privileged_inspection(
            &mut self,
            _service_id: Uuid,
            _request_id: Uuid,
            _token_id: Uuid,
            _administrator_uid: u32,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    #[test]
    fn creates_persisted_token_and_returns_same_result_for_retry() {
        let registration_path =
            std::env::temp_dir().join(format!("ab-jwt-create-reg-{}.db", Uuid::new_v4()));
        let token_path =
            std::env::temp_dir().join(format!("ab-jwt-create-token-{}.db", Uuid::new_v4()));
        let key = [0x61; 32];
        let mut registry = ServiceRegistry::open_sqlcipher(&registration_path, &key).unwrap();
        let client_id = registry
            .register_client("issuer", OperationClass::Write)
            .unwrap();
        let credential = registry.register_service(client_id, "login").unwrap();
        let mut tokens = SqlCipherTokenRepository::open(&token_path, &key).unwrap();
        let request_id = Uuid::new_v4();
        let request = || JwtCreateRequest {
            client_id,
            apikey: credential.apikey.clone(),
            request_id,
            data: Map::from_iter([
                ("user_id".to_owned(), Value::String("user-1".to_owned())),
                ("role".to_owned(), Value::String("member".to_owned())),
            ]),
        };
        let (first, retry) = {
            let mut service =
                IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300)).unwrap();
            let first = service.create(request(), 1_000).unwrap();
            let retry = service.create(request(), 1_100).unwrap();
            (first, retry)
        };
        assert_eq!(first, retry);
        assert_eq!(first.token.split('.').count(), 5);
        drop(tokens);

        let reopened = SqlCipherTokenRepository::open(&token_path, &key).unwrap();
        assert!(reopened.load_active(first.token_id).unwrap().is_some());
        drop(reopened);
        drop(registry);
        fs::remove_file(registration_path).unwrap();
        fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn registered_database_source_loads_one_subject_and_idempotently_issues_the_token() {
        let path = std::env::temp_dir().join(format!("ab-jwt-db-issue-{}.db", Uuid::new_v4()));
        let key = [0x60; 32];
        let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
        let client_id = registry
            .register_client("database-issuer", OperationClass::Write)
            .unwrap();
        let (credential, _) = registry
            .register_database_service(
                client_id,
                "database-login",
                "USER",
                "JWE_DIR_A256GCM",
                DatabaseSourceInput {
                    connection: DatabaseConnectionInput {
                        name: "subjects".into(),
                        driver: "postgresql".into(),
                        host: "database.invalid".into(),
                        port: 5432,
                        database: "identity".into(),
                        queue_directory: "/var/lib/autobricks-jwt/queue".into(),
                        username: "jwt".into(),
                        password: "secret".into(),
                        tls_mode: DatabaseTlsMode::Disabled,
                        ca_file: None,
                        certificate: None,
                        private_key: None,
                        connect_timeout_ms: 1_000,
                        query_timeout_ms: 2_000,
                        pool_size: 2,
                        sqlite_options: None,
                    },
                    primary_key: vec!["id".into()],
                    maps: vec![vec!["user_id".into()]],
                    select: QueryBinding {
                        query: "SELECT id,user_id,role FROM users WHERE user_id=$1".into(),
                        fields: vec!["user_id".into()],
                    },
                    update: None,
                    retention_seconds: 3_600,
                },
            )
            .unwrap();
        let mut tokens = SqlCipherTokenRepository::open(&path, &key).unwrap();
        let request_id = Uuid::new_v4();
        let request = || JwtCreateRequest {
            client_id,
            apikey: credential.apikey.clone(),
            request_id,
            data: Map::from_iter([("user_id".into(), Value::String("database-user".into()))]),
        };
        let cache = SubjectCache {
            queries: Cell::new(0),
        };
        let mut issuance =
            IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300)).unwrap();
        let first = issuance
            .create_from_database(request(), 1_000, &cache)
            .unwrap();
        let retry = issuance
            .create_from_database(request(), 1_100, &cache)
            .unwrap();
        assert_eq!(first, retry);
        assert_eq!(cache.queries.get(), 1);
        let issued = tokens.load_active(first.token_id).unwrap().unwrap();
        let fields = issued
            .verify_and_query(
                &first.token,
                &credential.service_id.to_string(),
                1_101,
                &["user_id"],
            )
            .unwrap();
        assert_eq!(fields["user_id"], "database-user");
        drop(tokens);
        drop(registry);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn production_create_path_records_issued_audit_correlation() {
        let path = std::env::temp_dir().join(format!("ab-jwt-create-audit-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x62; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("audited-writer", OperationClass::Write)
            .unwrap();
        let credential = registry
            .register_service(client_id, "audited-login")
            .unwrap();
        let request_id = Uuid::new_v4();
        let mut audit = AuditCapture::default();
        let response = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create_audited(
                JwtCreateRequest {
                    client_id,
                    apikey: credential.apikey,
                    request_id,
                    data: Map::from_iter([("user_id".into(), Value::String("user-audit".into()))]),
                },
                1_000,
                "2026-10-11T01:00:00Z",
                &mut audit,
            )
            .unwrap();
        assert_eq!(audit.issued.len(), 1);
        assert_eq!(audit.issued[0].2, request_id);
        assert_eq!(audit.issued[0].3, response.token_id);
        assert_eq!(audit.issued[0].1, "USER");
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn successful_create_inserts_active_encrypted_session_into_cache() {
        let path = std::env::temp_dir().join(format!("ab-jwt-create-cache-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x63; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("cached-writer", OperationClass::Write)
            .unwrap();
        let credential = registry
            .register_service(client_id, "cached-login")
            .unwrap();
        let mut cache = MemorySessionCache::default();
        let response = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create_cached(
                JwtCreateRequest {
                    client_id,
                    apikey: credential.apikey,
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([("user_id".into(), Value::String("user-cache".into()))]),
                },
                1_000,
                &mut cache,
            )
            .unwrap();
        assert_eq!(cache.inserted, vec![response.token_id]);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn registered_profile_controls_encryption_and_persisted_key_size() {
        for (profile, expected_enc) in [
            ("JWE_DIR_A128GCM", "A128GCM"),
            ("JWE_DIR_A192GCM", "A192GCM"),
            ("JWE_DIR_A256GCM", "A256GCM"),
        ] {
            let path = std::env::temp_dir().join(format!("ab-jwt-profile-{}.db", Uuid::new_v4()));
            let mut tokens = SqlCipherTokenRepository::open(&path, &[0x64; 32]).unwrap();
            let mut registry = ServiceRegistry::default();
            let client_id = registry
                .register_client(&format!("writer-{expected_enc}"), OperationClass::Write)
                .unwrap();
            let credential = registry
                .register_service_with_configuration(
                    client_id,
                    &format!("service-{expected_enc}"),
                    "USER",
                    vec![],
                    Some("CLIENT_JSON".into()),
                    Some(profile.into()),
                )
                .unwrap();
            let response = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
                .unwrap()
                .create(
                    JwtCreateRequest {
                        client_id,
                        apikey: credential.apikey,
                        request_id: Uuid::new_v4(),
                        data: Map::from_iter([(
                            "user_id".into(),
                            Value::String("profile-user".into()),
                        )]),
                    },
                    1_000,
                )
                .unwrap();
            let restored = tokens.load_active(response.token_id).unwrap().unwrap();
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(response.token.split('.').next().unwrap())
                .unwrap();
            let header: Value = serde_json::from_slice(&header).unwrap();
            assert_eq!(header["enc"], expected_enc);
            restored
                .verify_and_query(
                    &response.token,
                    &credential.service_id.to_string(),
                    1_001,
                    &["user_id"],
                )
                .unwrap();
            drop(tokens);
            fs::remove_file(path).unwrap();
        }
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("invalid-profile", OperationClass::Write)
            .unwrap();
        assert_eq!(
            registry
                .register_service_with_configuration(
                    client_id,
                    "invalid-profile-service",
                    "USER",
                    vec![],
                    Some("CLIENT_JSON".into()),
                    Some("caller-supplied-algorithm".into()),
                )
                .unwrap_err()
                .code(),
            8001
        );
    }

    #[test]
    fn rejects_read_client_bad_apikey_reserved_claim_and_wrong_source() {
        let token_path =
            std::env::temp_dir().join(format!("ab-jwt-create-reject-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&token_path, &[0x71; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let write_client = registry
            .register_client("write", OperationClass::Write)
            .unwrap();
        let write = registry
            .register_service(write_client, "write-service")
            .unwrap();
        let read_client = registry
            .register_client("read", OperationClass::Read)
            .unwrap();
        let read = registry
            .register_service_with_issuers(
                read_client,
                "read-service",
                "USER",
                vec!["user_id".into()],
                None,
                None,
                vec![write.service_id],
            )
            .unwrap();
        let database_client = registry
            .register_client("database", OperationClass::Write)
            .unwrap();
        let database = registry
            .register_service_with_configuration(
                database_client,
                "database-service",
                "USER",
                vec![],
                Some("DATABASE".into()),
                Some("JWE_DIR_A256GCM".into()),
            )
            .unwrap();
        let make = |client_id, apikey: String, data: Map<String, Value>| JwtCreateRequest {
            client_id,
            apikey,
            request_id: Uuid::new_v4(),
            data,
        };
        let valid_data =
            || Map::from_iter([("user_id".to_owned(), Value::String("user-1".to_owned()))]);
        {
            let mut service =
                IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300)).unwrap();
            assert_eq!(
                service
                    .create(make(read_client, read.apikey, valid_data()), 1_000)
                    .unwrap_err()
                    .code(),
                8031
            );
            assert_eq!(
                service
                    .create(make(write_client, "wrong".into(), valid_data()), 1_000)
                    .unwrap_err()
                    .code(),
                8030
            );
            let mut reserved = valid_data();
            reserved.insert("iss".into(), Value::String("attacker".into()));
            assert_eq!(
                service
                    .create(make(write_client, write.apikey, reserved), 1_000)
                    .unwrap_err()
                    .code(),
                8054
            );
            assert_eq!(
                service
                    .create(make(database_client, database.apikey, valid_data()), 1_000)
                    .unwrap_err()
                    .code(),
                8052
            );
        }
        drop(tokens);
        fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn enforces_registered_client_json_field_contract() {
        use crate::service_registry::{ClientJsonField, ClientJsonValueType};

        let path = std::env::temp_dir().join(format!("ab-jwt-json-schema-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x72; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("json-write", OperationClass::Write)
            .unwrap();
        let credential = registry
            .register_service_with_source_schema(
                client_id,
                "json-service",
                "USER",
                vec![],
                Some("CLIENT_JSON".into()),
                Some("JWE_DIR_A256GCM".into()),
                Some(vec![
                    ClientJsonField {
                        name: "user_id".into(),
                        value_type: ClientJsonValueType::String,
                        required: true,
                    },
                    ClientJsonField {
                        name: "enabled".into(),
                        value_type: ClientJsonValueType::Boolean,
                        required: true,
                    },
                    ClientJsonField {
                        name: "risk".into(),
                        value_type: ClientJsonValueType::Number,
                        required: false,
                    },
                ]),
            )
            .unwrap();
        {
            let mut service =
                IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300)).unwrap();
            let request = |data| JwtCreateRequest {
                client_id,
                apikey: credential.apikey.clone(),
                request_id: Uuid::new_v4(),
                data,
            };
            let valid = Map::from_iter([
                ("user_id".into(), Value::String("user-1".into())),
                ("enabled".into(), Value::Bool(true)),
                ("risk".into(), Value::from(7)),
            ]);
            assert!(service.create(request(valid), 1_000).is_ok());
            let missing = Map::from_iter([("user_id".into(), Value::String("user-2".into()))]);
            assert_eq!(
                service.create(request(missing), 1_000).unwrap_err().code(),
                8054
            );
            let wrong_type = Map::from_iter([
                ("user_id".into(), Value::String("user-3".into())),
                ("enabled".into(), Value::String("yes".into())),
            ]);
            assert_eq!(
                service
                    .create(request(wrong_type), 1_000)
                    .unwrap_err()
                    .code(),
                8054
            );
            let extra = Map::from_iter([
                ("user_id".into(), Value::String("user-4".into())),
                ("enabled".into(), Value::Bool(true)),
                ("password".into(), Value::String("secret".into())),
            ]);
            assert_eq!(
                service.create(request(extra), 1_000).unwrap_err().code(),
                8054
            );
        }
        drop(tokens);
        fs::remove_file(path).unwrap();
    }
}

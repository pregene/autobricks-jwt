use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
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
        if request.apikey.is_empty() || request.data.is_empty() {
            return Err(ServiceError::invalid_request(
                "APIKEY and subject data are required",
            ));
        }
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        if service.source_type.as_deref() != Some("CLIENT_JSON") {
            return Err(ServiceError::classified(
                8052,
                "CLIENT_JSON is not configured for this service",
            )
            .expect("8052 must be assigned"));
        }
        let encryption_profile = EncryptionProfile::from_registration(
            service.encryption_profile.as_deref().unwrap_or_default(),
        )?;

        if let Some(existing) = self
            .tokens
            .load_active_by_request(request.client_id, request.request_id)?
        {
            return Ok(response(request.request_id, existing));
        }

        for reserved in RESERVED_CLAIMS {
            if request.data.contains_key(reserved) {
                return Err(ServiceError::classified(
                    8054,
                    "subject data contains a JWT-controlled field",
                )
                .expect("8054 must be assigned"));
            }
        }
        if let Some(schema) = &service.client_json_schema {
            if request
                .data
                .keys()
                .any(|name| !schema.iter().any(|field| &field.name == name))
            {
                return Err(ServiceError::classified(
                    8054,
                    "subject data contains an unregistered field",
                )
                .expect("8054 must be assigned"));
            }
            for field in schema {
                let value = request.data.get(&field.name);
                if field.required && value.is_none() {
                    return Err(ServiceError::classified(
                        8054,
                        "required subject field is missing",
                    )
                    .expect("8054 must be assigned"));
                }
                if let Some(value) = value {
                    use crate::service_registry::ClientJsonValueType;
                    let matches = match field.value_type {
                        ClientJsonValueType::String => value.is_string(),
                        ClientJsonValueType::Number => value.is_number(),
                        ClientJsonValueType::Boolean => value.is_boolean(),
                    };
                    if !matches {
                        return Err(ServiceError::classified(
                            8054,
                            "subject field type is invalid",
                        )
                        .expect("8054 must be assigned"));
                    }
                }
            }
        }
        let subject_field = match service.subject_type.as_str() {
            "USER" => "user_id",
            "DEVICE" => "device_id",
            "WORKLOAD" => "workload_id",
            _ => return Err(ServiceError::invalid_subject("subject type is invalid")),
        };
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

fn response(request_id: Uuid, issued: IssuedToken) -> JwtCreateResponse {
    JwtCreateResponse {
        request_id,
        token_id: issued.token_id,
        token: issued.token,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine;
    use serde_json::{Map, Value};

    use super::*;
    use crate::session_cache::tests::MemorySessionCache;

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
            .register_service(read_client, "read-service")
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

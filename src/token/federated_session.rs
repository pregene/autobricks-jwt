use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    session_cache::SessionCache,
    session_service::{JwtQueryRequest, SessionService},
    sqlcipher_token_repository::SqlCipherTokenRepository,
};

pub struct FederatedSessionRequest {
    pub client_id: Uuid,
    pub apikey: String,
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: Option<String>,
    pub identity_fields: Vec<String>,
}

#[derive(Debug)]
pub struct FederatedSessionResult {
    pub token_id: Uuid,
    pub identity: Map<String, Value>,
}

pub struct FederatedSessionValidator<'a> {
    sessions: SessionService<'a>,
}

impl<'a> FederatedSessionValidator<'a> {
    pub fn new(
        registry: &'a ServiceRegistry,
        tokens: &'a mut SqlCipherTokenRepository,
        require_complete_token: bool,
    ) -> Self {
        Self {
            sessions: SessionService::new(registry, tokens, require_complete_token),
        }
    }

    pub fn validate_sso<C: SessionCache>(
        &mut self,
        request: FederatedSessionRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<FederatedSessionResult, ServiceError> {
        self.validate(request, now, cache)
    }

    pub fn validate_oauth_authorization_session<C: SessionCache>(
        &mut self,
        request: FederatedSessionRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<FederatedSessionResult, ServiceError> {
        self.validate(request, now, cache)
    }

    fn validate<C: SessionCache>(
        &mut self,
        request: FederatedSessionRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<FederatedSessionResult, ServiceError> {
        if request.identity_fields.is_empty() {
            return Err(
                ServiceError::classified(8063, "identity field list is empty")
                    .expect("8063 must be assigned"),
            );
        }
        let response = self.sessions.query_cached(
            JwtQueryRequest {
                client_id: request.client_id,
                apikey: request.apikey,
                request_id: request.request_id,
                token_id: request.token_id,
                token: request.token,
                fields: Some(request.identity_fields),
            },
            now,
            cache,
        )?;
        Ok(FederatedSessionResult {
            token_id: response.token_id,
            identity: response.fields.ok_or_else(|| {
                ServiceError::classified(8065, "identity fields are unavailable")
                    .expect("8065 must be assigned")
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use serde_json::{Map, Value};

    use crate::{
        issuance_service::{IssuanceService, JwtCreateRequest},
        service_registry::{ClientJsonField, ClientJsonValueType, OperationClass, ServiceRegistry},
        session_cache::tests::MemorySessionCache,
    };

    use super::*;

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn sso_and_oauth_use_independent_minimum_read_credentials_and_fail_closed() {
        let path = std::env::temp_dir().join(format!("ab-jwt-federated-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xd1; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let writer_id = registry
            .register_client("federated-writer", OperationClass::Write)
            .unwrap();
        let writer = registry
            .register_service_with_source_schema(
                writer_id,
                "login-create",
                "USER",
                vec![],
                Some("CLIENT_JSON".into()),
                Some("JWE_DIR_A256GCM".into()),
                Some(
                    ["user_id", "authentication_level", "consent_state"]
                        .into_iter()
                        .map(|name| ClientJsonField {
                            name: name.into(),
                            value_type: ClientJsonValueType::String,
                            required: true,
                        })
                        .collect(),
                ),
            )
            .unwrap();
        let sso_id = registry
            .register_client("sso-reader", OperationClass::Read)
            .unwrap();
        let sso = registry
            .register_service_with_configuration(
                sso_id,
                "sso-session",
                "USER",
                vec!["user_id".into(), "authentication_level".into()],
                None,
                None,
            )
            .unwrap();
        let oauth_id = registry
            .register_client("oauth-reader", OperationClass::Read)
            .unwrap();
        let oauth = registry
            .register_service_with_configuration(
                oauth_id,
                "oauth-session",
                "USER",
                vec!["user_id".into(), "consent_state".into()],
                None,
                None,
            )
            .unwrap();
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id: writer_id,
                    apikey: writer.apikey,
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([
                        ("user_id".into(), Value::String("federated-user".into())),
                        (
                            "authentication_level".into(),
                            Value::String("passkey".into()),
                        ),
                        ("consent_state".into(), Value::String("granted".into())),
                    ]),
                },
                1_000,
            )
            .unwrap();
        let mut cache = MemorySessionCache::default();
        let mut validator = FederatedSessionValidator::new(&registry, &mut tokens, false);
        let sso_result = validator
            .validate_sso(
                FederatedSessionRequest {
                    client_id: sso_id,
                    apikey: sso.apikey.clone(),
                    request_id: Uuid::new_v4(),
                    token_id: issued.token_id,
                    token: None,
                    identity_fields: vec!["user_id".into(), "authentication_level".into()],
                },
                1_010,
                &mut cache,
            )
            .unwrap();
        assert_eq!(sso_result.identity["authentication_level"], "passkey");
        let oauth_result = validator
            .validate_oauth_authorization_session(
                FederatedSessionRequest {
                    client_id: oauth_id,
                    apikey: oauth.apikey,
                    request_id: Uuid::new_v4(),
                    token_id: issued.token_id,
                    token: None,
                    identity_fields: vec!["user_id".into(), "consent_state".into()],
                },
                1_020,
                &mut cache,
            )
            .unwrap();
        assert_eq!(oauth_result.identity["consent_state"], "granted");
        let escalation = validator
            .validate_sso(
                FederatedSessionRequest {
                    client_id: sso_id,
                    apikey: sso.apikey,
                    request_id: Uuid::new_v4(),
                    token_id: issued.token_id,
                    token: None,
                    identity_fields: vec!["consent_state".into()],
                },
                1_030,
                &mut cache,
            )
            .unwrap_err();
        assert_eq!(escalation.code(), 8064);
        assert_eq!(cache.touched.len(), 2);
        drop(validator);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }
}

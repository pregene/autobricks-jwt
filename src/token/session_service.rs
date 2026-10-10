use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    service_error::ServiceError,
    service_registry::{OperationClass, ServiceRegistry},
    session_cache::SessionCache,
    sqlcipher_token_repository::{ActiveTokenRecord, SqlCipherTokenRepository},
    truelog_audit::AuditRecorder,
};

pub struct SessionService<'a> {
    registry: &'a ServiceRegistry,
    tokens: &'a mut SqlCipherTokenRepository,
    require_complete_token: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtQueryRequest {
    pub client_id: Uuid,
    pub apikey: String,
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: Option<String>,
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct JwtQueryResponse {
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub status: &'static str,
    pub fields: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtUpdateRequest {
    pub client_id: Uuid,
    pub apikey: String,
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: String,
    pub updates: Map<String, Value>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct JwtUpdateResponse {
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: String,
    pub version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtRevokeRequest {
    pub client_id: Uuid,
    pub apikey: String,
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub token: Option<String>,
}

impl<'a> SessionService<'a> {
    pub fn new(
        registry: &'a ServiceRegistry,
        tokens: &'a mut SqlCipherTokenRepository,
        require_complete_token: bool,
    ) -> Self {
        Self {
            registry,
            tokens,
            require_complete_token,
        }
    }

    pub fn query(
        &mut self,
        request: JwtQueryRequest,
        now: u64,
    ) -> Result<JwtQueryResponse, ServiceError> {
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Read,
        )?;
        let record = self.active_record(request.token_id)?;
        if record.token.subject_type()? != service.subject_type {
            return Err(classified(8042, "subject type is not authorized"));
        }
        let selected = select_token(
            request.token.as_deref(),
            &record.token.token,
            self.require_complete_token,
        )?;
        let fields = match request.fields {
            None => {
                record.token.verify_and_query(
                    selected,
                    &record.service_id.to_string(),
                    now,
                    &[],
                )?;
                None
            }
            Some(fields) => {
                if fields.is_empty() || has_duplicate(&fields) {
                    return Err(classified(8063, "field list is invalid"));
                }
                if fields
                    .iter()
                    .any(|field| !service.allowed_jwt_query_fields.contains(field))
                {
                    return Err(ServiceError::field_not_authorized(
                        "query field is not authorized",
                    ));
                }
                let references = fields.iter().map(String::as_str).collect::<Vec<_>>();
                Some(record.token.verify_and_query(
                    selected,
                    &record.service_id.to_string(),
                    now,
                    &references,
                )?)
            }
        };
        Ok(JwtQueryResponse {
            request_id: request.request_id,
            token_id: request.token_id,
            status: "ACTIVE",
            fields,
        })
    }

    pub fn query_audited<A: AuditRecorder>(
        &mut self,
        request: JwtQueryRequest,
        now: u64,
        event_at: &str,
        audit: &mut A,
    ) -> Result<JwtQueryResponse, ServiceError> {
        let request_id = request.request_id;
        let service_id = self
            .registry
            .authorize_service_by_apikey(request.client_id, &request.apikey, OperationClass::Read)?
            .service_id;
        match self.query(request, now) {
            Ok(response) => Ok(response),
            Err(error) if error.code() == 8060 => {
                audit.invalid_session(service_id, request_id, event_at)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn query_cached<C: SessionCache>(
        &mut self,
        request: JwtQueryRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<JwtQueryResponse, ServiceError> {
        let token_id = request.token_id;
        let renew_retention = request.fields.is_some();
        let response = self.query(request, now)?;
        if renew_retention {
            cache.touch(token_id)?;
        }
        Ok(response)
    }

    pub fn update(
        &mut self,
        request: JwtUpdateRequest,
        now: u64,
    ) -> Result<JwtUpdateResponse, ServiceError> {
        if request.updates.is_empty() || request.updates.keys().any(|key| is_reserved(key)) {
            return Err(ServiceError::invalid_request(
                "JWT update fields are invalid",
            ));
        }
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        let record = self.active_record(request.token_id)?;
        require_issuing_service(&record, request.client_id, service.service_id)?;
        record
            .token
            .verify_and_query(&request.token, &record.service_id.to_string(), now, &[])?;
        let replacement = record.token.replace_claims(&request.updates, now)?;
        let response_token = replacement.token.clone();
        let version = self
            .tokens
            .replace_active(request.request_id, &replacement)?;
        Ok(JwtUpdateResponse {
            request_id: request.request_id,
            token_id: request.token_id,
            token: response_token,
            version,
        })
    }

    pub fn revoke(&mut self, request: JwtRevokeRequest, now: u64) -> Result<(), ServiceError> {
        let service = self.registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            OperationClass::Write,
        )?;
        let record = self.active_record(request.token_id)?;
        require_issuing_service(&record, request.client_id, service.service_id)?;
        let selected = select_token(
            request.token.as_deref(),
            &record.token.token,
            self.require_complete_token,
        )?;
        record
            .token
            .verify_and_query(selected, &record.service_id.to_string(), now, &[])?;
        self.tokens.revoke_active(request.token_id)
    }

    pub fn revoke_cached<C: SessionCache>(
        &mut self,
        request: JwtRevokeRequest,
        now: u64,
        cache: &mut C,
    ) -> Result<(), ServiceError> {
        let token_id = request.token_id;
        self.revoke(request, now)?;
        cache.remove(token_id)
    }

    fn active_record(&self, token_id: Uuid) -> Result<ActiveTokenRecord, ServiceError> {
        self.tokens
            .load_active_record(token_id)?
            .ok_or_else(session_missing)
    }
}

fn select_token<'a>(
    submitted: Option<&'a str>,
    stored: &'a str,
    required: bool,
) -> Result<&'a str, ServiceError> {
    match submitted {
        Some(value) if value == stored => Ok(value),
        Some(_) => Err(ServiceError::jwt_invalid("encrypted token does not match")),
        None if required => Err(ServiceError::invalid_request("complete token is required")),
        None => Ok(stored),
    }
}

fn require_issuing_service(
    record: &ActiveTokenRecord,
    client_id: Uuid,
    service_id: Uuid,
) -> Result<(), ServiceError> {
    if record.client_id == client_id && record.service_id == service_id {
        Ok(())
    } else {
        Err(classified(8040, "service registration is not available"))
    }
}

fn has_duplicate(fields: &[String]) -> bool {
    let mut sorted = fields.to_vec();
    sorted.sort();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

fn is_reserved(field: &str) -> bool {
    matches!(
        field,
        "iss" | "sub" | "aud" | "iat" | "nbf" | "exp" | "jti" | "subject_type" | "claims"
    )
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

fn session_missing() -> ServiceError {
    classified(8060, "session is not found or expired")
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use serde_json::{Map, Value};

    use crate::session_cache::tests::MemorySessionCache;
    use crate::{
        issuance_service::{IssuanceService, JwtCreateRequest},
        service_registry::OperationClass,
        truelog_audit::AuditRecorder,
    };

    use super::*;

    #[derive(Default)]
    struct AuditCapture {
        invalid: Vec<(Uuid, Uuid, String)>,
    }

    impl AuditRecorder for AuditCapture {
        fn issued(
            &mut self,
            _service_id: Uuid,
            _subject_type: &str,
            _request_id: Uuid,
            _token_id: Uuid,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }

        fn invalid_session(
            &mut self,
            service_id: Uuid,
            request_id: Uuid,
            event_at: &str,
        ) -> Result<(), ServiceError> {
            self.invalid.push((service_id, request_id, event_at.into()));
            Ok(())
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
    fn queries_updates_and_revokes_with_separated_permissions() {
        let token_path = std::env::temp_dir().join(format!("ab-jwt-session-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&token_path, &[0x81; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let write_client = registry
            .register_client("write", OperationClass::Write)
            .unwrap();
        let write = registry.register_service(write_client, "issuer").unwrap();
        let read_client = registry
            .register_client("read", OperationClass::Read)
            .unwrap();
        let read = registry
            .register_service_with_configuration(
                read_client,
                "reader",
                "USER",
                vec![
                    "user_id".into(),
                    "role".into(),
                    "authentication_context".into(),
                ],
                None,
                None,
            )
            .unwrap();
        let create_request = JwtCreateRequest {
            client_id: write_client,
            apikey: write.apikey.clone(),
            request_id: Uuid::new_v4(),
            data: Map::from_iter([
                ("user_id".into(), Value::String("user-1".into())),
                ("role".into(), Value::String("member".into())),
            ]),
        };
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(create_request, 1_000)
            .unwrap();
        {
            let mut sessions = SessionService::new(&registry, &mut tokens, true);
            let queried = sessions
                .query(
                    JwtQueryRequest {
                        client_id: read_client,
                        apikey: read.apikey.clone(),
                        request_id: Uuid::new_v4(),
                        token_id: issued.token_id,
                        token: Some(issued.token.clone()),
                        fields: Some(vec!["user_id".into(), "role".into()]),
                    },
                    1_050,
                )
                .unwrap();
            assert_eq!(queried.fields.unwrap()["role"], "member");

            let updated = sessions
                .update(
                    JwtUpdateRequest {
                        client_id: write_client,
                        apikey: write.apikey.clone(),
                        request_id: Uuid::new_v4(),
                        token_id: issued.token_id,
                        token: issued.token.clone(),
                        updates: Map::from_iter([(
                            "authentication_context".into(),
                            Value::String("passkey".into()),
                        )]),
                    },
                    1_100,
                )
                .unwrap();
            assert_eq!(updated.token_id, issued.token_id);
            assert_eq!(updated.version, 2);
            assert_ne!(updated.token, issued.token);
            assert_eq!(
                sessions
                    .query(
                        JwtQueryRequest {
                            client_id: read_client,
                            apikey: read.apikey.clone(),
                            request_id: Uuid::new_v4(),
                            token_id: issued.token_id,
                            token: Some(issued.token),
                            fields: None,
                        },
                        1_120
                    )
                    .unwrap_err()
                    .code(),
                8061
            );
            let replacement = sessions
                .query(
                    JwtQueryRequest {
                        client_id: read_client,
                        apikey: read.apikey.clone(),
                        request_id: Uuid::new_v4(),
                        token_id: issued.token_id,
                        token: Some(updated.token.clone()),
                        fields: Some(vec!["authentication_context".into()]),
                    },
                    1_120,
                )
                .unwrap();
            assert_eq!(
                replacement.fields.unwrap()["authentication_context"],
                "passkey"
            );
            sessions
                .revoke(
                    JwtRevokeRequest {
                        client_id: write_client,
                        apikey: write.apikey.clone(),
                        request_id: Uuid::new_v4(),
                        token_id: issued.token_id,
                        token: Some(updated.token),
                    },
                    1_150,
                )
                .unwrap();
            assert_eq!(
                sessions
                    .revoke(
                        JwtRevokeRequest {
                            client_id: write_client,
                            apikey: write.apikey,
                            request_id: Uuid::new_v4(),
                            token_id: issued.token_id,
                            token: None,
                        },
                        1_160
                    )
                    .unwrap_err()
                    .code(),
                8060
            );
        }
        assert!(tokens.load_active(issued.token_id).unwrap().is_none());
        drop(tokens);
        fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn token_optional_mode_still_rejects_supplied_mismatch_and_field_escalation() {
        let path = std::env::temp_dir().join(format!("ab-jwt-query-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x91; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let write_client = registry
            .register_client("write-optional", OperationClass::Write)
            .unwrap();
        let write = registry
            .register_service(write_client, "issuer-optional")
            .unwrap();
        let read_client = registry
            .register_client("read-optional", OperationClass::Read)
            .unwrap();
        let read = registry
            .register_service_with_configuration(
                read_client,
                "reader-optional",
                "USER",
                vec!["user_id".into()],
                None,
                None,
            )
            .unwrap();
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id: write_client,
                    apikey: write.apikey,
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([("user_id".into(), Value::String("user-2".into()))]),
                },
                2_000,
            )
            .unwrap();
        {
            let mut sessions = SessionService::new(&registry, &mut tokens, false);
            assert_eq!(
                sessions
                    .query(
                        JwtQueryRequest {
                            client_id: read_client,
                            apikey: read.apikey.clone(),
                            request_id: Uuid::new_v4(),
                            token_id: issued.token_id,
                            token: None,
                            fields: None,
                        },
                        2_010
                    )
                    .unwrap()
                    .status,
                "ACTIVE"
            );
            assert_eq!(
                sessions
                    .query(
                        JwtQueryRequest {
                            client_id: read_client,
                            apikey: read.apikey.clone(),
                            request_id: Uuid::new_v4(),
                            token_id: issued.token_id,
                            token: Some("wrong".into()),
                            fields: None,
                        },
                        2_010
                    )
                    .unwrap_err()
                    .code(),
                8061
            );
            assert_eq!(
                sessions
                    .query(
                        JwtQueryRequest {
                            client_id: read_client,
                            apikey: read.apikey,
                            request_id: Uuid::new_v4(),
                            token_id: issued.token_id,
                            token: None,
                            fields: Some(vec!["role".into()]),
                        },
                        2_010
                    )
                    .unwrap_err()
                    .code(),
                8064
            );
        }
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_or_expired_session_records_common_audit_event() {
        let path = std::env::temp_dir().join(format!("ab-jwt-invalid-audit-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x92; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("audited-reader", OperationClass::Read)
            .unwrap();
        let credential = registry
            .register_service_with_configuration(
                client_id,
                "audited-query",
                "USER",
                vec!["user_id".into()],
                None,
                None,
            )
            .unwrap();
        let request_id = Uuid::new_v4();
        let mut audit = AuditCapture::default();
        let error = SessionService::new(&registry, &mut tokens, false)
            .query_audited(
                JwtQueryRequest {
                    client_id,
                    apikey: credential.apikey,
                    request_id,
                    token_id: Uuid::new_v4(),
                    token: None,
                    fields: None,
                },
                1_000,
                "2026-10-11T01:01:00Z",
                &mut audit,
            )
            .unwrap_err();
        assert_eq!(error.code(), 8060);
        assert_eq!(audit.invalid.len(), 1);
        assert_eq!(audit.invalid[0].1, request_id);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn query_refreshes_cache_retention_and_revoke_removes_cache_record() {
        let path = std::env::temp_dir().join(format!("ab-jwt-session-cache-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0x93; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let writer_id = registry
            .register_client("cache-writer", OperationClass::Write)
            .unwrap();
        let writer = registry
            .register_service(writer_id, "cache-issuer")
            .unwrap();
        let reader_id = registry
            .register_client("cache-reader", OperationClass::Read)
            .unwrap();
        let reader = registry
            .register_service_with_configuration(
                reader_id,
                "cache-query",
                "USER",
                vec!["user_id".into()],
                None,
                None,
            )
            .unwrap();
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id: writer_id,
                    apikey: writer.apikey.clone(),
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([(
                        "user_id".into(),
                        Value::String("user-cache-session".into()),
                    )]),
                },
                1_000,
            )
            .unwrap();
        let mut cache = MemorySessionCache::default();
        let mut sessions = SessionService::new(&registry, &mut tokens, false);
        sessions
            .query_cached(
                JwtQueryRequest {
                    client_id: reader_id,
                    apikey: reader.apikey,
                    request_id: Uuid::new_v4(),
                    token_id: issued.token_id,
                    token: None,
                    fields: Some(vec!["user_id".into()]),
                },
                1_010,
                &mut cache,
            )
            .unwrap();
        sessions
            .revoke_cached(
                JwtRevokeRequest {
                    client_id: writer_id,
                    apikey: writer.apikey,
                    request_id: Uuid::new_v4(),
                    token_id: issued.token_id,
                    token: None,
                },
                1_020,
                &mut cache,
            )
            .unwrap();
        assert_eq!(cache.touched, vec![issued.token_id]);
        assert_eq!(cache.removed, vec![issued.token_id]);
        drop(sessions);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }
}

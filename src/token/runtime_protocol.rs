use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    issuance_service::{IssuanceService, JwtCreateRequest},
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    session_cache::SessionCache,
    session_service::{JwtQueryRequest, JwtRevokeRequest, JwtUpdateRequest, SessionService},
    sqlcipher_token_repository::SqlCipherTokenRepository,
    truelog_audit::AuditRecorder,
    worker_process::CacheWorkerSet,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum RuntimeRequest {
    CertificateActivate(CertificateActivationRequest),
    JwtCreate(JwtCreateRequest),
    JwtStatus(JwtQueryRequest),
    JwtQuery(JwtQueryRequest),
    JwtUpdate(JwtUpdateRequest),
    JwtRevoke(JwtRevokeRequest),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertificateActivationRequest {
    pub client_id: uuid::Uuid,
    pub apikey: String,
    pub request_id: uuid::Uuid,
    pub operation_class: crate::service_registry::OperationClass,
    pub temporary_registration_key: String,
}

impl RuntimeRequest {
    pub fn client_id(&self) -> uuid::Uuid {
        match self {
            Self::CertificateActivate(request) => request.client_id,
            Self::JwtCreate(request) => request.client_id,
            Self::JwtStatus(request) | Self::JwtQuery(request) => request.client_id,
            Self::JwtUpdate(request) => request.client_id,
            Self::JwtRevoke(request) => request.client_id,
        }
    }

    pub fn apikey(&self) -> &str {
        match self {
            Self::CertificateActivate(request) => &request.apikey,
            Self::JwtCreate(request) => &request.apikey,
            Self::JwtStatus(request) | Self::JwtQuery(request) => &request.apikey,
            Self::JwtUpdate(request) => &request.apikey,
            Self::JwtRevoke(request) => &request.apikey,
        }
    }

    pub fn operation_class(&self) -> crate::service_registry::OperationClass {
        match self {
            Self::CertificateActivate(request) => request.operation_class,
            Self::JwtCreate(_) | Self::JwtUpdate(_) | Self::JwtRevoke(_) => {
                crate::service_registry::OperationClass::Write
            }
            Self::JwtStatus(_) | Self::JwtQuery(_) => crate::service_registry::OperationClass::Read,
        }
    }

    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::CertificateActivate(_) => "CERTIFICATE_ACTIVATE",
            Self::JwtCreate(_) => "JWT_CREATE",
            Self::JwtStatus(_) => "JWT_STATUS",
            Self::JwtQuery(_) => "JWT_QUERY",
            Self::JwtUpdate(_) => "JWT_UPDATE",
            Self::JwtRevoke(_) => "JWT_REVOKE",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuntimeResponse {
    pub status: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RuntimeError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuntimeError {
    pub code: u16,
    pub name: String,
    pub message: String,
}

pub struct RuntimeDispatcher<'a> {
    registry: &'a ServiceRegistry,
    tokens: &'a mut SqlCipherTokenRepository,
    token_lifetime: Duration,
    require_complete_token: bool,
    database_caches: Option<&'a CacheWorkerSet>,
    audit: Option<&'a mut dyn AuditRecorder>,
    session_cache: Option<&'a mut dyn SessionCache>,
}

impl<'a> RuntimeDispatcher<'a> {
    pub fn new(
        registry: &'a ServiceRegistry,
        tokens: &'a mut SqlCipherTokenRepository,
        token_lifetime: Duration,
        require_complete_token: bool,
    ) -> Result<Self, ServiceError> {
        if token_lifetime.is_zero() {
            return Err(ServiceError::configuration_invalid(
                "token lifetime must be greater than zero",
            ));
        }
        Ok(Self {
            registry,
            tokens,
            token_lifetime,
            require_complete_token,
            database_caches: None,
            audit: None,
            session_cache: None,
        })
    }

    pub fn with_database_caches(mut self, caches: &'a CacheWorkerSet) -> Self {
        self.database_caches = Some(caches);
        self
    }

    pub fn with_audit(mut self, audit: &'a mut dyn AuditRecorder) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn with_session_cache(mut self, cache: &'a mut dyn SessionCache) -> Self {
        self.session_cache = Some(cache);
        self
    }

    pub fn dispatch_json(&mut self, frame: &[u8], now: u64) -> Vec<u8> {
        let response = match serde_json::from_slice::<RuntimeRequest>(frame) {
            Ok(request) => self.dispatch(request, now),
            Err(_) => failure(
                "UNKNOWN",
                ServiceError::invalid_request("runtime request JSON is invalid"),
            ),
        };
        serde_json::to_vec(&response).unwrap_or_else(|_| {
            br#"{\"status\":\"ERROR\",\"operation\":\"UNKNOWN\",\"error\":{\"error_code\":8000,\"error_name\":\"INTERNAL_ERROR\",\"message\":\"request could not be completed\"}}"#.to_vec()
        })
    }

    pub fn dispatch(&mut self, request: RuntimeRequest, now: u64) -> RuntimeResponse {
        match request {
            RuntimeRequest::CertificateActivate(_) => failure(
                "CERTIFICATE_ACTIVATE",
                ServiceError::invalid_request("certificate activation requires an mTLS connection"),
            ),
            RuntimeRequest::JwtCreate(request) => {
                let request_id = request.request_id;
                let result = (|| {
                    let registered = self.registry.authorize_service_by_apikey(
                        request.client_id,
                        &request.apikey,
                        crate::service_registry::OperationClass::Write,
                    )?;
                    let service_id = registered.service_id;
                    let subject_type = registered.subject_type.clone();
                    let result = {
                        let mut issuance =
                            IssuanceService::new(self.registry, self.tokens, self.token_lifetime)?;
                        if registered.source_type.as_deref() == Some("DATABASE") {
                            let caches = self.database_caches.ok_or_else(|| {
                                ServiceError::assigned(
                                    8052,
                                    "DATABASE Cache runtime is unavailable",
                                )
                            })?;
                            issuance.create_from_database(
                                request,
                                now,
                                caches.cache_for(service_id)?,
                            )
                        } else {
                            issuance.create(request, now)
                        }?
                    };
                    if let Some(cache) = self.session_cache.as_deref_mut() {
                        let stored = self
                            .tokens
                            .load_active(result.token_id)?
                            .ok_or_else(|| ServiceError::internal("issued token is unavailable"))?;
                        if cache
                            .insert(stored.token_id, &stored.token, stored.expires_at)
                            .is_err()
                        {
                            cache.replace(stored.token_id, &stored.token, stored.expires_at)?;
                        }
                    }
                    if let Some(audit) = self.audit.as_deref_mut() {
                        audit.issued(
                            service_id,
                            &subject_type,
                            request_id,
                            result.token_id,
                            &event_time(now),
                        )?;
                    }
                    Ok(result)
                })();
                mapped("JWT_CREATE", result)
            }
            RuntimeRequest::JwtStatus(mut request) => {
                request.fields = None;
                let request_id = request.request_id;
                let audit_service_id = self
                    .registry
                    .authorize_service_by_apikey(
                        request.client_id,
                        &request.apikey,
                        crate::service_registry::OperationClass::Read,
                    )
                    .map(|service| service.service_id);
                let mut sessions =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token);
                let result = if let Some(cache) = self.session_cache.as_deref_mut() {
                    let mut result = sessions.query_cached(request, now, cache);
                    if result.as_ref().is_err_and(|error| error.code() == 8060)
                        && let (Ok(service_id), Some(audit)) =
                            (audit_service_id, self.audit.as_deref_mut())
                    {
                        if let Err(error) =
                            audit.invalid_session(service_id, request_id, &event_time(now))
                        {
                            result = Err(error);
                        }
                    }
                    result
                } else if let Some(audit) = self.audit.as_deref_mut() {
                    sessions.query_audited(request, now, &event_time(now), audit)
                } else {
                    sessions.query(request, now)
                };
                mapped("JWT_STATUS", result)
            }
            RuntimeRequest::JwtQuery(request) => {
                let request_id = request.request_id;
                let audit_service_id = self
                    .registry
                    .authorize_service_by_apikey(
                        request.client_id,
                        &request.apikey,
                        crate::service_registry::OperationClass::Read,
                    )
                    .map(|service| service.service_id);
                let mut sessions =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token);
                let result = if let Some(cache) = self.session_cache.as_deref_mut() {
                    let mut result = sessions.query_cached(request, now, cache);
                    if result.as_ref().is_err_and(|error| error.code() == 8060)
                        && let (Ok(service_id), Some(audit)) =
                            (audit_service_id, self.audit.as_deref_mut())
                    {
                        if let Err(error) =
                            audit.invalid_session(service_id, request_id, &event_time(now))
                        {
                            result = Err(error);
                        }
                    }
                    result
                } else if let Some(audit) = self.audit.as_deref_mut() {
                    sessions.query_audited(request, now, &event_time(now), audit)
                } else {
                    sessions.query(request, now)
                };
                mapped("JWT_QUERY", result)
            }
            RuntimeRequest::JwtUpdate(request) => {
                let token_id = request.token_id;
                let result =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token)
                        .update(request, now)
                        .and_then(|response| {
                            if let Some(cache) = self.session_cache.as_deref_mut() {
                                let stored =
                                    self.tokens.load_active(token_id)?.ok_or_else(|| {
                                        ServiceError::internal("updated token is unavailable")
                                    })?;
                                cache.replace(token_id, &stored.token, stored.expires_at)?;
                            }
                            Ok(response)
                        });
                mapped("JWT_UPDATE", result)
            }
            RuntimeRequest::JwtRevoke(request) => {
                let mut sessions =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token);
                let result = if let Some(cache) = self.session_cache.as_deref_mut() {
                    sessions.revoke_cached(request, now, cache)
                } else {
                    sessions.revoke(request, now)
                }
                .map(|()| json!({ "status": "REVOKED" }));
                mapped_value("JWT_REVOKE", result)
            }
        }
    }
}

fn event_time(epoch: u64) -> String {
    let raw = epoch as libc::time_t;
    let mut value = unsafe { std::mem::zeroed::<libc::tm>() };
    // SAFETY: raw and value remain valid for the duration of gmtime_r.
    if unsafe { libc::gmtime_r(&raw, &mut value) }.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec
    )
}

fn mapped<T: Serialize>(operation: &str, result: Result<T, ServiceError>) -> RuntimeResponse {
    mapped_value(
        operation,
        result.and_then(|value| {
            serde_json::to_value(value)
                .map_err(|_| ServiceError::internal("runtime result serialization failed"))
        }),
    )
}

fn mapped_value(operation: &str, result: Result<Value, ServiceError>) -> RuntimeResponse {
    match result {
        Ok(result) => RuntimeResponse {
            status: "SUCCESS".into(),
            operation: operation.into(),
            result: Some(result),
            error: None,
        },
        Err(error) => failure(operation, error),
    }
}

fn failure(operation: &str, error: ServiceError) -> RuntimeResponse {
    RuntimeResponse {
        status: "ERROR".into(),
        operation: operation.into(),
        result: None,
        error: Some(RuntimeError {
            code: error.code(),
            name: error.name().into(),
            message: error.public_message().into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Map, Value};
    use uuid::Uuid;

    use crate::{
        issuance_service::JwtCreateRequest,
        service_registry::{OperationClass, ServiceRegistry},
        session_cache::tests::MemorySessionCache,
        session_service::{JwtQueryRequest, JwtRevokeRequest},
    };

    use super::*;

    #[derive(Default)]
    struct AuditCapture {
        issued: Vec<(Uuid, Uuid)>,
        invalid: Vec<Uuid>,
    }

    impl AuditRecorder for AuditCapture {
        fn issued(
            &mut self,
            _: Uuid,
            _: &str,
            request_id: Uuid,
            token_id: Uuid,
            event_at: &str,
        ) -> Result<(), ServiceError> {
            assert!(event_at.ends_with('Z'));
            self.issued.push((request_id, token_id));
            Ok(())
        }

        fn invalid_session(
            &mut self,
            _: Uuid,
            request_id: Uuid,
            event_at: &str,
        ) -> Result<(), ServiceError> {
            assert!(event_at.ends_with('Z'));
            self.invalid.push(request_id);
            Ok(())
        }

        fn privileged_inspection(
            &mut self,
            _: Uuid,
            _: Uuid,
            _: Uuid,
            _: u32,
            _: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    #[test]
    fn runtime_dispatcher_composes_issued_and_invalid_session_audit_paths() {
        let path = std::env::temp_dir().join(format!("ab-jwt-runtime-audit-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xa3; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let writer_id = registry
            .register_client("runtime-audit-writer", OperationClass::Write)
            .unwrap();
        let writer = registry
            .register_service(writer_id, "runtime-audit-issuer")
            .unwrap();
        let reader_id = registry
            .register_client("runtime-audit-reader", OperationClass::Read)
            .unwrap();
        let reader = registry
            .register_service_with_issuers(
                reader_id,
                "runtime-audit-query",
                "USER",
                vec!["user_id".into()],
                None,
                None,
                vec![writer.service_id],
            )
            .unwrap();
        let create_request_id = Uuid::new_v4();
        let missing_request_id = Uuid::new_v4();
        let mut audit = AuditCapture::default();
        let mut dispatcher =
            RuntimeDispatcher::new(&registry, &mut tokens, Duration::from_secs(300), false)
                .unwrap()
                .with_audit(&mut audit);
        let created = dispatcher.dispatch(
            RuntimeRequest::JwtCreate(JwtCreateRequest {
                client_id: writer_id,
                apikey: writer.apikey,
                request_id: create_request_id,
                data: Map::from_iter([("user_id".into(), Value::String("audit-user".into()))]),
            }),
            1_000,
        );
        assert_eq!(created.status, "SUCCESS");
        let missing = dispatcher.dispatch(
            RuntimeRequest::JwtQuery(JwtQueryRequest {
                client_id: reader_id,
                apikey: reader.apikey,
                request_id: missing_request_id,
                token_id: Uuid::new_v4(),
                token: None,
                fields: Some(vec!["user_id".into()]),
            }),
            1_001,
        );
        assert_eq!(missing.error.unwrap().code, 8060);
        drop(dispatcher);
        assert_eq!(audit.issued.len(), 1);
        assert_eq!(audit.issued[0].0, create_request_id);
        assert_eq!(audit.invalid, vec![missing_request_id]);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn dispatches_one_shared_complete_session_lifecycle() {
        let path = std::env::temp_dir().join(format!("ab-jwt-runtime-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xa1; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let writer_id = registry
            .register_client("runtime-writer", OperationClass::Write)
            .unwrap();
        let writer = registry
            .register_service(writer_id, "runtime-create")
            .unwrap();
        let reader_id = registry
            .register_client("runtime-reader", OperationClass::Read)
            .unwrap();
        let reader = registry
            .register_service_with_issuers(
                reader_id,
                "runtime-query",
                "USER",
                vec!["user_id".into(), "role".into()],
                None,
                None,
                vec![writer.service_id],
            )
            .unwrap();
        let mut dispatcher =
            RuntimeDispatcher::new(&registry, &mut tokens, Duration::from_secs(300), false)
                .unwrap();
        let created = dispatcher.dispatch(
            RuntimeRequest::JwtCreate(JwtCreateRequest {
                client_id: writer_id,
                apikey: writer.apikey.clone(),
                request_id: Uuid::new_v4(),
                data: Map::from_iter([
                    ("user_id".into(), Value::String("user-runtime".into())),
                    ("role".into(), Value::String("member".into())),
                ]),
            }),
            1_000,
        );
        assert_eq!(created.status, "SUCCESS");
        let token_id =
            serde_json::from_value::<Uuid>(created.result.as_ref().unwrap()["token_id"].clone())
                .unwrap();
        let token = created.result.as_ref().unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();

        let updated = dispatcher.dispatch(
            RuntimeRequest::JwtUpdate(JwtUpdateRequest {
                client_id: writer_id,
                apikey: writer.apikey.clone(),
                request_id: Uuid::new_v4(),
                token_id,
                token,
                updates: Map::from_iter([
                    ("role".into(), Value::String("administrator".into())),
                    ("last_ip".into(), Value::String("192.0.2.10".into())),
                ]),
            }),
            1_005,
        );
        assert_eq!(updated.status, "SUCCESS");
        assert_eq!(updated.result.as_ref().unwrap()["version"], 2);

        let status = dispatcher.dispatch(
            RuntimeRequest::JwtStatus(JwtQueryRequest {
                client_id: reader_id,
                apikey: reader.apikey.clone(),
                request_id: Uuid::new_v4(),
                token_id,
                token: None,
                fields: Some(vec!["role".into()]),
            }),
            1_010,
        );
        assert_eq!(status.result.unwrap()["status"], "ACTIVE");

        let queried = dispatcher.dispatch(
            RuntimeRequest::JwtQuery(JwtQueryRequest {
                client_id: reader_id,
                apikey: reader.apikey,
                request_id: Uuid::new_v4(),
                token_id,
                token: None,
                fields: Some(vec!["user_id".into(), "role".into()]),
            }),
            1_020,
        );
        assert_eq!(queried.result.unwrap()["fields"]["role"], "administrator");

        let revoked = dispatcher.dispatch(
            RuntimeRequest::JwtRevoke(JwtRevokeRequest {
                client_id: writer_id,
                apikey: writer.apikey,
                request_id: Uuid::new_v4(),
                token_id,
                token: None,
            }),
            1_030,
        );
        assert_eq!(revoked.result.unwrap()["status"], "REVOKED");
        drop(dispatcher);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_json_returns_classified_response() {
        let path = std::env::temp_dir().join(format!("ab-jwt-runtime-json-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xa2; 32]).unwrap();
        let registry = ServiceRegistry::default();
        let response =
            RuntimeDispatcher::new(&registry, &mut tokens, Duration::from_secs(300), true)
                .unwrap()
                .dispatch_json(b"not-json", 1_000);
        let response: RuntimeResponse = serde_json::from_slice(&response).unwrap();
        assert_eq!(response.error.unwrap().code, 8001);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cache_backed_query_requires_authoritative_active_durable_session() {
        let path = std::env::temp_dir().join(format!("ab-jwt-cache-auth-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xa4; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let writer_id = registry
            .register_client("cache-authority-writer", OperationClass::Write)
            .unwrap();
        let writer = registry
            .register_service(writer_id, "cache-authority-issuer")
            .unwrap();
        let reader_id = registry
            .register_client("cache-authority-reader", OperationClass::Read)
            .unwrap();
        let reader = registry
            .register_service_with_issuers(
                reader_id,
                "cache-authority-query",
                "USER",
                vec!["user_id".into()],
                None,
                None,
                vec![writer.service_id],
            )
            .unwrap();
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id: writer_id,
                    apikey: writer.apikey,
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([(
                        "user_id".into(),
                        Value::String("authoritative-user".into()),
                    )]),
                },
                1_000,
            )
            .unwrap();
        tokens.revoke_active(issued.token_id).unwrap();
        let mut cache = MemorySessionCache::default();
        cache.inserted.push(issued.token_id);
        let response =
            RuntimeDispatcher::new(&registry, &mut tokens, Duration::from_secs(300), false)
                .unwrap()
                .with_session_cache(&mut cache)
                .dispatch(
                    RuntimeRequest::JwtQuery(JwtQueryRequest {
                        client_id: reader_id,
                        apikey: reader.apikey,
                        request_id: Uuid::new_v4(),
                        token_id: issued.token_id,
                        token: None,
                        fields: Some(vec!["user_id".into()]),
                    }),
                    1_010,
                );
        assert_eq!(response.error.unwrap().code, 8060);
        assert!(cache.touched.is_empty());
        drop(tokens);
        fs::remove_file(path).unwrap();
    }
}

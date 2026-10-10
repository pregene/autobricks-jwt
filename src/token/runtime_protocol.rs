use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    issuance_service::{IssuanceService, JwtCreateRequest},
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    session_service::{JwtQueryRequest, JwtRevokeRequest, JwtUpdateRequest, SessionService},
    sqlcipher_token_repository::SqlCipherTokenRepository,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "request",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum RuntimeRequest {
    JwtCreate(JwtCreateRequest),
    JwtStatus(JwtQueryRequest),
    JwtQuery(JwtQueryRequest),
    JwtUpdate(JwtUpdateRequest),
    JwtRevoke(JwtRevokeRequest),
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
        })
    }

    pub fn dispatch_json(&mut self, frame: &[u8], now: u64) -> Vec<u8> {
        let response = match serde_json::from_slice::<RuntimeRequest>(frame) {
            Ok(request) => self.dispatch(request, now),
            Err(_) => failure(
                "UNKNOWN",
                ServiceError::invalid_request("runtime request JSON is invalid"),
            ),
        };
        serde_json::to_vec(&response).expect("runtime response serialization cannot fail")
    }

    pub fn dispatch(&mut self, request: RuntimeRequest, now: u64) -> RuntimeResponse {
        match request {
            RuntimeRequest::JwtCreate(request) => {
                let result = IssuanceService::new(self.registry, self.tokens, self.token_lifetime)
                    .and_then(|mut service| service.create(request, now));
                mapped("JWT_CREATE", result)
            }
            RuntimeRequest::JwtStatus(mut request) => {
                request.fields = None;
                let result =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token)
                        .query(request, now);
                mapped("JWT_STATUS", result)
            }
            RuntimeRequest::JwtQuery(request) => {
                let result =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token)
                        .query(request, now);
                mapped("JWT_QUERY", result)
            }
            RuntimeRequest::JwtUpdate(request) => {
                let result =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token)
                        .update(request, now);
                mapped("JWT_UPDATE", result)
            }
            RuntimeRequest::JwtRevoke(request) => {
                let result =
                    SessionService::new(self.registry, self.tokens, self.require_complete_token)
                        .revoke(request, now)
                        .map(|()| json!({ "status": "REVOKED" }));
                mapped_value("JWT_REVOKE", result)
            }
        }
    }
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
        session_service::{JwtQueryRequest, JwtRevokeRequest},
    };

    use super::*;

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn dispatches_complete_create_status_query_and_revoke_contract() {
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
            .register_service_with_configuration(
                reader_id,
                "runtime-query",
                "USER",
                vec!["user_id".into(), "role".into()],
                None,
                None,
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
        assert_eq!(queried.result.unwrap()["fields"]["role"], "member");

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
}

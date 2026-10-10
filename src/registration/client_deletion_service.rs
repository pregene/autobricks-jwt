use uuid::Uuid;

use crate::{
    service_error::ServiceError,
    service_registry::{ClientDeletionResult, OperationClass, ServiceRegistry},
    sqlcipher_token_repository::SqlCipherTokenRepository,
};

#[derive(Debug, Eq, PartialEq)]
pub struct CascadedClientDeletion {
    pub registration: ClientDeletionResult,
    pub revoked_session_count: usize,
}

pub fn delete_client(
    registry: &mut ServiceRegistry,
    tokens: &mut SqlCipherTokenRepository,
    client_id: Uuid,
) -> Result<CascadedClientDeletion, ServiceError> {
    let client = registry
        .clients()
        .into_iter()
        .find(|client| client.client_id == client_id)
        .ok_or_else(|| {
            ServiceError::client_registration_inactive("client registration is not active")
        })?;
    let revoked_session_count = if client.operation_class == OperationClass::Write {
        tokens.revoke_active_by_client(client_id)?
    } else {
        0
    };
    let registration = registry.delete_client(client_id)?;
    Ok(CascadedClientDeletion {
        registration,
        revoked_session_count,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use serde_json::{Map, Value};

    use crate::{
        issuance_service::{IssuanceService, JwtCreateRequest},
        service_registry::OperationClass,
    };

    use super::*;

    #[test]
    fn write_client_deletion_revokes_sessions_and_preserves_history() {
        let registration_path =
            std::env::temp_dir().join(format!("ab-jwt-delete-reg-{}.db", Uuid::new_v4()));
        let token_path =
            std::env::temp_dir().join(format!("ab-jwt-delete-token-{}.db", Uuid::new_v4()));
        let key = [0xc1; 32];
        let mut registry = ServiceRegistry::open_sqlcipher(&registration_path, &key).unwrap();
        let client_id = registry
            .register_client("delete-write", OperationClass::Write)
            .unwrap();
        let service = registry
            .register_service(client_id, "delete-issuer")
            .unwrap();
        let mut tokens = SqlCipherTokenRepository::open(&token_path, &key).unwrap();
        let mut token_ids = Vec::new();
        for user in ["user-1", "user-2"] {
            let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
                .unwrap()
                .create(
                    JwtCreateRequest {
                        client_id,
                        apikey: service.apikey.clone(),
                        request_id: Uuid::new_v4(),
                        data: Map::from_iter([("user_id".into(), Value::String(user.into()))]),
                    },
                    1_000,
                )
                .unwrap();
            token_ids.push(issued.token_id);
        }
        let deleted = delete_client(&mut registry, &mut tokens, client_id).unwrap();
        assert_eq!(deleted.revoked_session_count, 2);
        assert_eq!(deleted.registration.deleted_service_count, 1);
        for token_id in token_ids {
            assert!(tokens.load_active(token_id).unwrap().is_none());
            assert_eq!(tokens.history_version_count(token_id).unwrap(), 1);
        }
        drop(tokens);
        drop(registry);
        let reopened = ServiceRegistry::open_sqlcipher(&registration_path, &key).unwrap();
        assert!(reopened.clients().is_empty());
        drop(reopened);
        fs::remove_file(registration_path).unwrap();
        fs::remove_file(token_path).unwrap();
    }

    #[test]
    fn read_client_deletion_does_not_revoke_write_sessions() {
        let token_path =
            std::env::temp_dir().join(format!("ab-jwt-delete-read-{}.db", Uuid::new_v4()));
        let mut registry = ServiceRegistry::default();
        let write_id = registry
            .register_client("keep-write", OperationClass::Write)
            .unwrap();
        let write = registry.register_service(write_id, "keep-issuer").unwrap();
        let read_id = registry
            .register_client("delete-read", OperationClass::Read)
            .unwrap();
        registry.register_service(read_id, "delete-reader").unwrap();
        let mut tokens = SqlCipherTokenRepository::open(&token_path, &[0xd1; 32]).unwrap();
        let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id: write_id,
                    apikey: write.apikey,
                    request_id: Uuid::new_v4(),
                    data: Map::from_iter([("user_id".into(), Value::String("user-3".into()))]),
                },
                1_000,
            )
            .unwrap();
        let deleted = delete_client(&mut registry, &mut tokens, read_id).unwrap();
        assert_eq!(deleted.revoked_session_count, 0);
        assert!(tokens.load_active(issued.token_id).unwrap().is_some());
        drop(tokens);
        fs::remove_file(token_path).unwrap();
    }
}

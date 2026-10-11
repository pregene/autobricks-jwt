use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    database_key_rotation::HsmDatabaseKeys, runtime_protocol::RuntimeDispatcher,
    service_error::ServiceError, service_registry::ServiceRegistry,
    sqlcipher_token_repository::SqlCipherTokenRepository,
};

pub struct RuntimeServiceContext {
    registry: Arc<Mutex<ServiceRegistry>>,
    tokens: Mutex<SqlCipherTokenRepository>,
    token_lifetime: Duration,
    require_complete_token: bool,
}

impl RuntimeServiceContext {
    pub fn open<H: HsmDatabaseKeys>(
        database_path: &Path,
        hsm: &H,
        token_lifetime: Duration,
        require_complete_token: bool,
    ) -> Result<Self, ServiceError> {
        if token_lifetime.is_zero() {
            return Err(ServiceError::configuration_invalid(
                "token lifetime must be greater than zero",
            ));
        }
        let database_key = hsm.current()?;
        let registry = ServiceRegistry::open_sqlcipher(database_path, &database_key)?;
        let tokens = SqlCipherTokenRepository::open(database_path, &database_key)?;
        Ok(Self {
            registry: Arc::new(Mutex::new(registry)),
            tokens: Mutex::new(tokens),
            token_lifetime,
            require_complete_token,
        })
    }

    pub fn registry(&self) -> Arc<Mutex<ServiceRegistry>> {
        Arc::clone(&self.registry)
    }

    pub fn dispatch_frame(&self, frame: &[u8], now: u64) -> Result<Vec<u8>, ServiceError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| ServiceError::internal("token repository lock failed"))?;
        let mut dispatcher = RuntimeDispatcher::new(
            &registry,
            &mut tokens,
            self.token_lifetime,
            self.require_complete_token,
        )?;
        Ok(dispatcher.dispatch_json(frame, now))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        sync::Arc,
        thread,
        time::Duration,
    };

    use serde_json::{Map, Value, json};
    use uuid::Uuid;

    use crate::{
        connection_policy::ConnectionPolicy,
        database_key_rotation::HsmDatabaseKeys,
        service_error::ServiceError,
        service_registry::{OperationClass, ServiceRegistry},
        tcp_listener::TcpListenerEndpoint,
    };

    use super::RuntimeServiceContext;

    struct StartupHsm([u8; 32]);

    impl HsmDatabaseKeys for StartupHsm {
        fn current(&self) -> Result<[u8; 32], ServiceError> {
            Ok(self.0)
        }

        fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
            Ok(None)
        }

        fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
            unreachable!()
        }

        fn commit(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    fn seeded_context() -> (Arc<RuntimeServiceContext>, Uuid, String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ab-jwt-context-{}.db", Uuid::new_v4()));
        let key = [0x81; 32];
        let (client_id, apikey) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
            let client_id = registry
                .register_client("runtime-context-writer", OperationClass::Write)
                .unwrap();
            let service = registry
                .register_service(client_id, "runtime-context-service")
                .unwrap();
            (client_id, service.apikey)
        };
        let context =
            RuntimeServiceContext::open(&path, &StartupHsm(key), Duration::from_secs(300), true)
                .unwrap();
        (Arc::new(context), client_id, apikey, path)
    }

    fn create_frame(client_id: Uuid, apikey: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "operation": "JWT_CREATE",
            "request": {
                "client_id": client_id,
                "apikey": apikey,
                "request_id": Uuid::new_v4(),
                "data": Map::from_iter([(
                    "user_id".to_owned(),
                    Value::String("runtime-user".to_owned())
                )])
            }
        }))
        .unwrap()
    }

    #[test]
    fn composes_registry_token_repository_and_dispatcher_from_one_database() {
        let (context, client_id, apikey, path) = seeded_context();
        let response = context
            .dispatch_frame(&create_frame(client_id, &apikey), 1_000)
            .unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["status"], "SUCCESS");
        assert_eq!(response["operation"], "JWT_CREATE");
        drop(context);
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "creates a local TCP listener"]
    fn tcp_listener_frames_reach_the_runtime_dispatcher() {
        let (context, client_id, apikey, path) = seeded_context();
        let endpoint = TcpListenerEndpoint::bind("127.0.0.1:0").unwrap();
        let address = endpoint.local_addr().unwrap();
        let policy = ConnectionPolicy::new("127.0.0.1/32", 30, 300).unwrap();
        let server_context = Arc::clone(&context);
        let server = thread::spawn(move || {
            endpoint
                .serve_one(&policy, |frame| server_context.dispatch_frame(frame, 1_000))
                .unwrap()
        });

        let request = create_frame(client_id, &apikey);
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&request).unwrap();
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).unwrap();
        drop(stream);
        assert_eq!(server.join().unwrap(), 1);
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["status"], "SUCCESS");
        drop(context);
        fs::remove_file(path).unwrap();
    }
}

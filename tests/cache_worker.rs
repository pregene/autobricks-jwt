use std::{fs, path::PathBuf};

use autobricks_jwt::worker_process::CacheWorkerProcess;
use autobricks_jwt::{
    database_source::{
        DatabaseConnectionInput, DatabaseSourceInput, DatabaseTlsMode, QueryBinding,
    },
    runtime_protocol::RuntimeDispatcher,
    service_registry::{OperationClass, ServiceRegistry},
    sqlcipher_token_repository::SqlCipherTokenRepository,
    worker_process::CacheWorkerSet,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
#[ignore = "requires the packaged Autobricks Cache library and test configuration"]
fn initializes_and_cleanly_stops_an_isolated_cache_runtime() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ab-jwtd"));
    let library = required_path("AUTOBRICKS_JWT_TEST_CACHE_LIBRARY");
    let connection: Value = serde_json::from_str(
        &fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_CONNECTION")).unwrap(),
    )
    .unwrap();
    let caches: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_DEFINITION")).unwrap(),
    )
    .unwrap();
    let worker = CacheWorkerProcess::start(&executable, &library, connection, caches).unwrap();
    println!("CACHE_WORKER_INITIALIZED=PASS");
    worker.shutdown().unwrap();
    println!("CACHE_WORKER_SHUTDOWN=PASS");
}

#[test]
#[ignore = "requires the packaged Autobricks Cache library and test database"]
fn dispatches_registered_database_issuance_through_its_isolated_worker() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_ab-jwtd"));
    let library = required_path("AUTOBRICKS_JWT_TEST_CACHE_LIBRARY");
    let connection: Value = serde_json::from_str(
        &fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_CONNECTION")).unwrap(),
    )
    .unwrap();
    let definitions: Vec<Value> = serde_json::from_str(
        &fs::read_to_string(required_path("AUTOBRICKS_JWT_TEST_CACHE_DEFINITION")).unwrap(),
    )
    .unwrap();
    let definition = &definitions[0];
    let authentication = &connection["authentication"];
    let queue_directory = std::env::temp_dir().join(format!("ab-jwt-queue-{}", Uuid::new_v4()));
    let source = DatabaseSourceInput {
        connection: DatabaseConnectionInput {
            name: connection["name"].as_str().unwrap().into(),
            driver: connection["driver"].as_str().unwrap().into(),
            host: connection["host"].as_str().unwrap().into(),
            port: connection["port"].as_u64().unwrap() as u16,
            database: connection["database"].as_str().unwrap().into(),
            queue_directory: queue_directory.to_string_lossy().into_owned(),
            username: authentication["username"].as_str().unwrap().into(),
            password: authentication["password"].as_str().unwrap().into(),
            tls_mode: DatabaseTlsMode::Disabled,
            ca_file: None,
            certificate: None,
            private_key: None,
            connect_timeout_ms: connection["connect_timeout_ms"].as_u64().unwrap(),
            query_timeout_ms: connection["query_timeout_ms"].as_u64().unwrap(),
            pool_size: connection["pool_size"].as_u64().unwrap() as u16,
            sqlite_options: None,
        },
        primary_key: serde_json::from_value(definition["primary_key"].clone()).unwrap(),
        maps: serde_json::from_value(definition["maps"].clone()).unwrap(),
        select: serde_json::from_value(definition["select"].clone()).unwrap(),
        update: Some(serde_json::from_value::<QueryBinding>(definition["update"].clone()).unwrap()),
        retention_seconds: definition["retention"]["value"].as_u64().unwrap(),
    };
    let mut registry = ServiceRegistry::default();
    let client_id = registry
        .register_client("worker-database-writer", OperationClass::Write)
        .unwrap();
    let (credential, _) = registry
        .register_database_service(
            client_id,
            "worker-database-service",
            "USER",
            "JWE_DIR_A256GCM",
            source,
        )
        .unwrap();
    let workers = CacheWorkerSet::start_registered(&executable, &library, &registry).unwrap();
    assert_eq!(workers.worker_count(), 1);
    let token_path = std::env::temp_dir().join(format!("ab-jwt-worker-{}.db", Uuid::new_v4()));
    let mut tokens = SqlCipherTokenRepository::open(&token_path, &[0x44; 32]).unwrap();
    let response = RuntimeDispatcher::new(
        &registry,
        &mut tokens,
        std::time::Duration::from_secs(300),
        true,
    )
    .unwrap()
    .with_database_caches(&workers)
    .dispatch_json(
        &serde_json::to_vec(&json!({
            "operation": "JWT_CREATE",
            "request": {
                "client_id": client_id,
                "apikey": credential.apikey,
                "request_id": Uuid::new_v4(),
                "data": {"user_id": "user-0001"}
            }
        }))
        .unwrap(),
        1_000,
    );
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["status"], "SUCCESS");
    assert!(response["result"]["token_id"].as_str().is_some());
    println!("DATABASE_RUNTIME_ISSUANCE=PASS");
    drop(tokens);
    fs::remove_file(token_path).unwrap();
    workers.shutdown().unwrap();
    if queue_directory.exists() {
        fs::remove_dir_all(queue_directory).unwrap();
    }
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
}

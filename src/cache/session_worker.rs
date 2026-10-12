use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::json;
use uuid::Uuid;

use crate::{
    database_source::DatabaseSourceCache, service_error::ServiceError, session_cache::SessionCache,
    worker_process::CacheWorkerProcess,
};

const SESSION_CACHE_ID: &str = "autobricks-jwt-sessions";

pub struct SessionCacheWorker {
    worker: CacheWorkerProcess,
    database_path: PathBuf,
    queue_directory: PathBuf,
}

impl SessionCacheWorker {
    pub fn start(
        executable: &Path,
        library_path: &Path,
        authoritative_database: &Path,
        database_key: &[u8; 32],
    ) -> Result<Self, ServiceError> {
        Self::start_rebuilt(
            executable,
            library_path,
            authoritative_database,
            database_key,
            &[],
        )
    }

    pub fn start_rebuilt(
        executable: &Path,
        library_path: &Path,
        authoritative_database: &Path,
        database_key: &[u8; 32],
        records: &[crate::jwe_token::IssuedToken],
    ) -> Result<Self, ServiceError> {
        let database_path = authoritative_database.with_extension("session-cache.db");
        let queue_directory = authoritative_database.with_extension("session-cache-queue");
        prepare_database(&database_path, database_key, true)?;
        std::fs::create_dir_all(&queue_directory).map_err(|_| {
            ServiceError::service_unavailable("session Cache queue cannot be created")
        })?;
        let connection_id = Uuid::new_v4().to_string();
        let key = format!("x'{}'", encode_key(database_key));
        let connection = json!({
            "connection_id": connection_id,
            "name": "Autobricks JWT session Cache",
            "kind": "DATABASE",
            "driver": "sqlite",
            "host": "",
            "port": 0,
            "database": database_path,
            "queue_directory": queue_directory,
            "authentication": {"username": "", "password": ""},
            "tls_used": false,
            "connect_timeout_ms": 2000,
            "query_timeout_ms": 5000,
            "pool_used": true,
            "pool_size": 2,
            "opt": {
                "key": key,
                "open_mode": "READ_WRITE",
                "mutex": "FULL",
                "uri": false,
                "cache": "DEFAULT",
                "journal_mode": "WAL",
                "synchronous": "FULL",
                "foreign_keys": true
            }
        });
        let definition = json!({
            "cache_id": SESSION_CACHE_ID,
            "connection_id": connection_id,
            "cache_type": "ON_DEMAND",
            "retention": {"type": "TIMESTAMP", "value": 3600},
            "primary_key": ["token_id"],
            "select": {
                "query": "SELECT token_id, token, expires_at FROM session_cache WHERE token_id=$1",
                "fields": ["token_id"]
            },
            "insert": {
                "query": "INSERT INTO session_cache(token_id,token,expires_at) VALUES($1,$2,$3)",
                "fields": ["token_id","token","expires_at"]
            },
            "update": {
                "query": "UPDATE session_cache SET token=$1,expires_at=$2 WHERE token_id=$3",
                "fields": ["token","expires_at","token_id"]
            },
            "delete": {
                "query": "DELETE FROM session_cache WHERE token_id=$1",
                "fields": ["token_id"]
            },
            "maps": [["token_id"]]
        });
        let worker =
            CacheWorkerProcess::start(executable, library_path, connection, vec![definition])?;
        let mut cache = Self {
            worker,
            database_path,
            queue_directory,
        };
        for record in records {
            cache.insert(record.token_id, &record.token, record.expires_at)?;
        }
        Ok(cache)
    }

    pub fn clear_persistent_records(&self, database_key: &[u8; 32]) -> Result<(), ServiceError> {
        let connection = open(&self.database_path, database_key)?;
        connection
            .execute("DELETE FROM session_cache", [])
            .map_err(database_error)?;
        Ok(())
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn queue_directory(&self) -> &Path {
        &self.queue_directory
    }
}

impl SessionCache for SessionCacheWorker {
    fn insert(&mut self, token_id: Uuid, token: &str, expires_at: u64) -> Result<(), ServiceError> {
        self.worker.insert_record(
            SESSION_CACHE_ID,
            &json!({"token_id": token_id, "token": token, "expires_at": expires_at}),
        )
    }

    fn replace(
        &mut self,
        token_id: Uuid,
        token: &str,
        expires_at: u64,
    ) -> Result<(), ServiceError> {
        self.worker.update(
            SESSION_CACHE_ID,
            &json!({"token_id": token_id, "token": token, "expires_at": expires_at}),
        )
    }

    fn touch(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
        let records = self
            .worker
            .query(SESSION_CACHE_ID, &json!({"token_id": token_id}))?;
        if records.len() == 1 {
            Ok(())
        } else {
            Err(ServiceError::assigned(
                8060,
                "session is not found or expired",
            ))
        }
    }

    fn remove(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
        self.worker
            .delete_record(SESSION_CACHE_ID, &json!({"token_id": token_id}))
    }
}

fn prepare_database(path: &Path, key: &[u8; 32], clear: bool) -> Result<(), ServiceError> {
    let connection = open(path, key)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS session_cache(
                token_id TEXT PRIMARY KEY,
                token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );",
        )
        .map_err(database_error)?;
    if clear {
        connection
            .execute("DELETE FROM session_cache", [])
            .map_err(database_error)?;
    }
    Ok(())
}

fn open(path: &Path, key: &[u8; 32]) -> Result<Connection, ServiceError> {
    let connection = Connection::open(path).map_err(database_error)?;
    connection
        .execute_batch(&format!("PRAGMA key = \"x'{}'\";", encode_key(key)))
        .map_err(database_error)?;
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(database_error)?;
    Ok(connection)
}

fn encode_key(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn database_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::assigned(8082, format!("session Cache database error: {error}"))
}

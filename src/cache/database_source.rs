use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{autobricks_cache::AutobricksCache, service_error::ServiceError};

pub trait DatabaseSourceCache {
    fn query(&self, cache_id: &str, input: &Value) -> Result<Vec<Value>, ServiceError>;
    fn update(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError>;
}

impl DatabaseSourceCache for AutobricksCache {
    fn query(&self, cache_id: &str, input: &Value) -> Result<Vec<Value>, ServiceError> {
        AutobricksCache::query(self, cache_id, input)
    }

    fn update(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        AutobricksCache::update(self, cache_id, input)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseConnectionInput {
    pub name: String,
    pub driver: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub queue_directory: String,
    pub username: String,
    pub password: String,
    pub tls_mode: DatabaseTlsMode,
    pub ca_file: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub connect_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub pool_size: u16,
    pub sqlite_options: Option<Value>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DatabaseTlsMode {
    Disabled,
    Tls,
    Mtls,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QueryBinding {
    pub query: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseSourceInput {
    pub connection: DatabaseConnectionInput,
    pub primary_key: Vec<String>,
    pub maps: Vec<Vec<String>>,
    pub select: QueryBinding,
    pub update: Option<QueryBinding>,
    pub retention_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseSourcePlan {
    pub connection_id: Uuid,
    pub cache_id: Uuid,
    pub connection_json: Value,
    pub cache_definition_json: Value,
}

impl DatabaseSourcePlan {
    pub fn build(input: DatabaseSourceInput) -> Result<Self, ServiceError> {
        validate_connection(&input.connection)?;
        validate_fields(&input.primary_key, "primary key")?;
        if input.maps.is_empty() {
            return Err(invalid("at least one MAP is required"));
        }
        for map in &input.maps {
            validate_fields(map, "MAP")?;
        }
        validate_binding(&input.select, true)?;
        if let Some(update) = &input.update {
            validate_binding(update, false)?;
        }
        if input.retention_seconds == 0 {
            return Err(invalid("DATABASE source Retention must be positive"));
        }
        let connection_id = Uuid::new_v4();
        let cache_id = Uuid::new_v4();
        let tls = match input.connection.tls_mode {
            DatabaseTlsMode::Disabled => None,
            DatabaseTlsMode::Tls => Some(json!({ "ca_file": input.connection.ca_file })),
            DatabaseTlsMode::Mtls => Some(json!({
                "ca_file": input.connection.ca_file,
                "cert": input.connection.certificate,
                "key": input.connection.private_key
            })),
        };
        let mut connection_json = json!({
            "connection_id": connection_id,
            "name": input.connection.name,
            "kind": "DATABASE",
            "driver": input.connection.driver,
            "host": input.connection.host,
            "port": input.connection.port,
            "database": input.connection.database,
            "queue_directory": input.connection.queue_directory,
            "authentication": {
                "username": input.connection.username,
                "password": input.connection.password
            },
            "tls_used": input.connection.tls_mode != DatabaseTlsMode::Disabled,
            "connect_timeout_ms": input.connection.connect_timeout_ms,
            "query_timeout_ms": input.connection.query_timeout_ms,
            "pool_used": true,
            "pool_size": input.connection.pool_size
        });
        if let Some(tls) = tls {
            connection_json["tls"] = tls;
        }
        if let Some(options) = input.connection.sqlite_options {
            connection_json["opt"] = options;
        }
        let update = input.update.unwrap_or(QueryBinding {
            query: String::new(),
            fields: vec![],
        });
        let cache_definition_json = json!({
            "cache_id": cache_id,
            "connection_id": connection_id,
            "cache_type": "ON_DEMAND",
            "retention": { "type": "TIMESTAMP", "value": input.retention_seconds },
            "primary_key": input.primary_key,
            "select": input.select,
            "insert": { "query": "", "fields": [] },
            "update": update,
            "delete": { "query": "", "fields": [] },
            "maps": input.maps
        });
        Ok(Self {
            connection_id,
            cache_id,
            connection_json,
            cache_definition_json,
        })
    }

    pub fn test_connection(
        &self,
        library_path: &std::path::Path,
    ) -> Result<AutobricksCache, ServiceError> {
        AutobricksCache::initialize(
            library_path,
            &self.connection_json.to_string(),
            &self.cache_definition_json.to_string(),
        )
    }

    pub fn load_subject<C: DatabaseSourceCache>(
        &self,
        cache: &C,
        conditions: &Value,
    ) -> Result<Value, ServiceError> {
        let records = cache.query(&self.cache_id.to_string(), conditions)?;
        if records.len() != 1 || !records[0].is_object() {
            return Err(ServiceError::source_data_unavailable(
                "DATABASE subject lookup did not return exactly one record",
            ));
        }
        Ok(records.into_iter().next().expect("one record exists"))
    }

    pub fn execute_registered_update<C: DatabaseSourceCache>(
        &self,
        cache: &C,
        complete_record: &Value,
    ) -> Result<(), ServiceError> {
        let update = &self.cache_definition_json["update"];
        if update["query"].as_str().is_none_or(str::is_empty) {
            return Err(ServiceError::classified(8052, "UPDATE is not configured")
                .expect("8052 must be assigned"));
        }
        cache.update(&self.cache_id.to_string(), complete_record)
    }
}

fn validate_connection(input: &DatabaseConnectionInput) -> Result<(), ServiceError> {
    if input.name.trim().is_empty()
        || input.database.trim().is_empty()
        || input.queue_directory.trim().is_empty()
        || input.connect_timeout_ms == 0
        || input.query_timeout_ms == 0
        || input.pool_size < 2
        || !matches!(input.driver.as_str(), "postgresql" | "mariadb" | "sqlite")
    {
        return Err(invalid("DATABASE Connection is invalid"));
    }
    let sqlite = input.driver == "sqlite";
    if sqlite {
        if input.tls_mode != DatabaseTlsMode::Disabled || input.sqlite_options.is_none() {
            return Err(invalid("SQLite Connection options are invalid"));
        }
    } else if input.host.trim().is_empty() || input.port == 0 {
        return Err(invalid("network DATABASE host and port are required"));
    }
    match input.tls_mode {
        DatabaseTlsMode::Disabled
            if input.ca_file.is_some()
                || input.certificate.is_some()
                || input.private_key.is_some() =>
        {
            Err(invalid("disabled TLS cannot contain certificate paths"))
        }
        DatabaseTlsMode::Tls
            if input.ca_file.is_none()
                || input.certificate.is_some()
                || input.private_key.is_some() =>
        {
            Err(invalid("TLS requires only a trust chain"))
        }
        DatabaseTlsMode::Mtls
            if input.ca_file.is_none()
                || input.certificate.is_none()
                || input.private_key.is_none() =>
        {
            Err(invalid(
                "mTLS requires trust chain, certificate, and private key",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_fields(fields: &[String], label: &str) -> Result<(), ServiceError> {
    if fields.is_empty()
        || fields.iter().any(|field| field.trim().is_empty())
        || fields
            .iter()
            .enumerate()
            .any(|(index, field)| fields[..index].contains(field))
    {
        return Err(invalid(format!("{label} fields are invalid")));
    }
    Ok(())
}

fn validate_binding(binding: &QueryBinding, select: bool) -> Result<(), ServiceError> {
    if binding.query.trim().is_empty() || (select && binding.fields.is_empty()) {
        return Err(invalid("query and binding fields are required"));
    }
    if !binding.fields.is_empty() {
        validate_fields(&binding.fields, "query binding")?;
    }
    let placeholder_count = binding.query.matches('$').count();
    if placeholder_count != binding.fields.len() {
        return Err(invalid("query placeholder and field counts do not match"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ServiceError {
    ServiceError::invalid_request(message.into())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use super::*;

    #[derive(Default)]
    struct CacheCapture {
        updates: RefCell<Vec<Value>>,
    }

    impl DatabaseSourceCache for CacheCapture {
        fn query(&self, _cache_id: &str, _input: &Value) -> Result<Vec<Value>, ServiceError> {
            Ok(vec![
                json!({"id": 1, "user_id": "user-1", "last_ip": "192.0.2.1"}),
            ])
        }

        fn update(&self, _cache_id: &str, input: &Value) -> Result<(), ServiceError> {
            self.updates.borrow_mut().push(input.clone());
            Ok(())
        }
    }
    use crate::service_registry::{OperationClass, ServiceRegistry};

    fn input(tls_mode: DatabaseTlsMode) -> DatabaseSourceInput {
        DatabaseSourceInput {
            connection: DatabaseConnectionInput {
                name: "users".into(),
                driver: "postgresql".into(),
                host: "db.internal".into(),
                port: 5432,
                database: "web-service".into(),
                queue_directory: "/var/lib/autobricks-jwt/queue".into(),
                username: "jwt".into(),
                password: "secret".into(),
                tls_mode,
                ca_file: (tls_mode != DatabaseTlsMode::Disabled).then(|| "/pki/trust".into()),
                certificate: (tls_mode == DatabaseTlsMode::Mtls).then(|| "/pki/cert".into()),
                private_key: (tls_mode == DatabaseTlsMode::Mtls).then(|| "/pki/key".into()),
                connect_timeout_ms: 2000,
                query_timeout_ms: 5000,
                pool_size: 10,
                sqlite_options: None,
            },
            primary_key: vec!["id".into()],
            maps: vec![vec!["id".into()], vec!["user_id".into()]],
            select: QueryBinding {
                query: "SELECT id, user_id, role, last_ip FROM users WHERE user_id=$1".into(),
                fields: vec!["user_id".into()],
            },
            update: Some(QueryBinding {
                query: "UPDATE users SET last_ip=$1 WHERE user_id=$2".into(),
                fields: vec!["last_ip".into(), "user_id".into()],
            }),
            retention_seconds: 3600,
        }
    }

    #[test]
    fn generates_cache_connection_map_select_and_update_contract() {
        for mode in [
            DatabaseTlsMode::Disabled,
            DatabaseTlsMode::Tls,
            DatabaseTlsMode::Mtls,
        ] {
            let plan = DatabaseSourcePlan::build(input(mode)).unwrap();
            assert_eq!(
                plan.connection_json["connection_id"],
                plan.connection_id.to_string()
            );
            assert_eq!(plan.cache_definition_json["cache_type"], "ON_DEMAND");
            assert_eq!(plan.cache_definition_json["maps"][1], json!(["user_id"]));
            assert_eq!(plan.cache_definition_json["insert"]["query"], "");
            assert_eq!(plan.cache_definition_json["delete"]["query"], "");
            assert_eq!(
                plan.cache_definition_json["update"]["fields"],
                json!(["last_ip", "user_id"])
            );
        }
    }

    #[test]
    fn rejects_inapplicable_tls_and_mismatched_binding_order_counts() {
        let mut invalid_tls = input(DatabaseTlsMode::Tls);
        invalid_tls.connection.certificate = Some("/pki/client".into());
        assert_eq!(
            DatabaseSourcePlan::build(invalid_tls).unwrap_err().code(),
            8001
        );
        let mut invalid_query = input(DatabaseTlsMode::Disabled);
        invalid_query.update.as_mut().unwrap().fields.pop();
        assert_eq!(
            DatabaseSourcePlan::build(invalid_query).unwrap_err().code(),
            8001
        );
    }

    #[test]
    fn binds_generated_connection_and_cache_plan_to_durable_write_service() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-database-source-{}.db", Uuid::new_v4()));
        let key = [0xd2; 32];
        let (client_id, service_id, connection_id) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
            let client_id = registry
                .register_client("database-writer", OperationClass::Write)
                .unwrap();
            let (credential, plan) = registry
                .register_database_service(
                    client_id,
                    "database-login",
                    "USER",
                    "JWE_DIR_A256GCM",
                    input(DatabaseTlsMode::Mtls),
                )
                .unwrap();
            (client_id, credential.service_id, plan.connection_id)
        };
        let registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
        let service = registry
            .services(client_id)
            .into_iter()
            .find(|service| service.service_id == service_id)
            .unwrap();
        assert_eq!(
            service.database_source.unwrap().connection_id,
            connection_id
        );
        drop(registry);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn loads_one_mapped_record_and_executes_only_registered_update() {
        let plan = DatabaseSourcePlan::build(input(DatabaseTlsMode::Disabled)).unwrap();
        let cache = CacheCapture::default();
        let record = plan
            .load_subject(&cache, &json!({"user_id": "user-1"}))
            .unwrap();
        assert_eq!(record["last_ip"], "192.0.2.1");
        let changed = json!({"id": 1, "user_id": "user-1", "last_ip": "192.0.2.2"});
        plan.execute_registered_update(&cache, &changed).unwrap();
        assert_eq!(cache.updates.borrow().as_slice(), &[changed]);

        let mut without_update = input(DatabaseTlsMode::Disabled);
        without_update.update = None;
        let without_update = DatabaseSourcePlan::build(without_update).unwrap();
        assert_eq!(
            without_update
                .execute_registered_update(&cache, &json!({"id": 1}))
                .unwrap_err()
                .code(),
            8052
        );
    }
}

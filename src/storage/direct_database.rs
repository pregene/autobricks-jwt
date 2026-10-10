use std::collections::BTreeMap;

use mysql::{Opts, Pool, Row as MySqlRow, prelude::Queryable};
use postgres::{Client, NoTls};
use rusqlite::{Connection, types::ValueRef};
use serde_json::Value;

use crate::service_error::ServiceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseKind {
    PostgreSql,
    MariaDb,
    MySql,
    Sqlite,
    SqlCipher,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectDatabaseConfiguration {
    pub kind: DatabaseKind,
    pub connection: String,
    pub sqlcipher_key: Option<Vec<u8>>,
}

pub trait DirectDatabase {
    fn query(&mut self, statement: &str) -> Result<Vec<BTreeMap<String, Value>>, ServiceError>;
    fn update(&mut self, statement: &str) -> Result<u64, ServiceError>;
}

pub fn connect(
    configuration: &DirectDatabaseConfiguration,
) -> Result<Box<dyn DirectDatabase>, ServiceError> {
    match configuration.kind {
        DatabaseKind::PostgreSql => Ok(Box::new(PostgreSqlDatabase {
            client: Client::connect(&configuration.connection, NoTls).map_err(|_| unavailable())?,
        })),
        DatabaseKind::MariaDb | DatabaseKind::MySql => {
            let options = Opts::from_url(&configuration.connection).map_err(|_| invalid())?;
            Ok(Box::new(MySqlDatabase {
                pool: Pool::new(options).map_err(|_| unavailable())?,
            }))
        }
        DatabaseKind::Sqlite | DatabaseKind::SqlCipher => {
            let connection =
                Connection::open(&configuration.connection).map_err(|_| unavailable())?;
            if configuration.kind == DatabaseKind::SqlCipher {
                let key = configuration.sqlcipher_key.as_deref().ok_or_else(invalid)?;
                let key_hex = key
                    .iter()
                    .map(|value| format!("{value:02x}"))
                    .collect::<String>();
                connection
                    .execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))
                    .map_err(|_| unavailable())?;
                connection
                    .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(|_| unavailable())?;
            } else if configuration.sqlcipher_key.is_some() {
                return Err(invalid());
            }
            Ok(Box::new(SqliteDatabase { connection }))
        }
    }
}

struct PostgreSqlDatabase {
    client: Client,
}
impl DirectDatabase for PostgreSqlDatabase {
    fn query(&mut self, statement: &str) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
        let rows = self.client.query(statement, &[]).map_err(|_| operation())?;
        rows.into_iter()
            .map(|row| {
                let mut output = BTreeMap::new();
                for (index, column) in row.columns().iter().enumerate() {
                    let value = if let Ok(value) = row.try_get::<_, Option<String>>(index) {
                        value.map(Value::String).unwrap_or(Value::Null)
                    } else if let Ok(value) = row.try_get::<_, Option<i64>>(index) {
                        value.map(Value::from).unwrap_or(Value::Null)
                    } else if let Ok(value) = row.try_get::<_, Option<bool>>(index) {
                        value.map(Value::from).unwrap_or(Value::Null)
                    } else {
                        return Err(operation());
                    };
                    output.insert(column.name().to_owned(), value);
                }
                Ok(output)
            })
            .collect()
    }
    fn update(&mut self, statement: &str) -> Result<u64, ServiceError> {
        self.client.execute(statement, &[]).map_err(|_| operation())
    }
}

struct MySqlDatabase {
    pool: Pool,
}
impl DirectDatabase for MySqlDatabase {
    fn query(&mut self, statement: &str) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
        let mut connection = self.pool.get_conn().map_err(|_| unavailable())?;
        let rows: Vec<MySqlRow> = connection.query(statement).map_err(|_| operation())?;
        rows.into_iter().map(mysql_row).collect()
    }
    fn update(&mut self, statement: &str) -> Result<u64, ServiceError> {
        let mut connection = self.pool.get_conn().map_err(|_| unavailable())?;
        connection.query_drop(statement).map_err(|_| operation())?;
        Ok(connection.affected_rows())
    }
}

fn mysql_row(row: MySqlRow) -> Result<BTreeMap<String, Value>, ServiceError> {
    let columns = row
        .columns_ref()
        .iter()
        .map(|column| column.name_str().into_owned())
        .collect::<Vec<_>>();
    let values = row.unwrap();
    columns
        .into_iter()
        .zip(values)
        .map(|(name, value)| {
            let value = match value {
                mysql::Value::NULL => Value::Null,
                mysql::Value::Bytes(value) => String::from_utf8(value)
                    .map(Value::String)
                    .map_err(|_| operation())?,
                mysql::Value::Int(value) => Value::from(value),
                mysql::Value::UInt(value) => Value::from(value),
                mysql::Value::Float(value) => Value::from(value),
                mysql::Value::Double(value) => Value::from(value),
                _ => return Err(operation()),
            };
            Ok((name, value))
        })
        .collect()
}

struct SqliteDatabase {
    connection: Connection,
}
impl DirectDatabase for SqliteDatabase {
    fn query(&mut self, statement: &str) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
        let mut prepared = self
            .connection
            .prepare(statement)
            .map_err(|_| operation())?;
        let names = prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let rows = prepared
            .query_map([], |row| {
                let mut output = BTreeMap::new();
                for (index, name) in names.iter().enumerate() {
                    let value = match row.get_ref(index)? {
                        ValueRef::Null => Value::Null,
                        ValueRef::Integer(value) => Value::from(value),
                        ValueRef::Real(value) => Value::from(value),
                        ValueRef::Text(value) => {
                            Value::String(String::from_utf8_lossy(value).into_owned())
                        }
                        ValueRef::Blob(value) => Value::String(base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            value,
                        )),
                    };
                    output.insert(name.clone(), value);
                }
                Ok(output)
            })
            .map_err(|_| operation())?;
        rows.map(|row| row.map_err(|_| operation())).collect()
    }
    fn update(&mut self, statement: &str) -> Result<u64, ServiceError> {
        self.connection
            .execute(statement, [])
            .map(|count| count as u64)
            .map_err(|_| operation())
    }
}

fn invalid() -> ServiceError {
    ServiceError::configuration_invalid("direct database configuration is invalid")
}
fn unavailable() -> ServiceError {
    ServiceError::classified(8080, "direct database is unavailable").expect("8080 assigned")
}
fn operation() -> ServiceError {
    ServiceError::classified(8081, "direct database operation failed").expect("8081 assigned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn exercise(kind: DatabaseKind, key: Option<Vec<u8>>) {
        let path = std::env::temp_dir().join(format!("ab-jwt-direct-{}.db", Uuid::new_v4()));
        let configuration = DirectDatabaseConfiguration {
            kind,
            connection: path.to_string_lossy().into_owned(),
            sqlcipher_key: key,
        };
        let mut database = connect(&configuration).unwrap();
        assert_eq!(
            database
                .update("CREATE TABLE subjects(user_id TEXT, active INTEGER)")
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .update("INSERT INTO subjects VALUES('user-1', 1)")
                .unwrap(),
            1
        );
        let result = database
            .query("SELECT user_id, active FROM subjects")
            .unwrap();
        assert_eq!(result[0]["user_id"], "user-1");
        assert_eq!(result[0]["active"], 1);
        drop(database);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn sqlite_adapter_executes_query_and_update() {
        exercise(DatabaseKind::Sqlite, None);
    }
    #[test]
    fn sqlcipher_adapter_executes_query_and_update() {
        exercise(DatabaseKind::SqlCipher, Some(vec![7; 32]));
    }
    #[test]
    fn mysql_and_mariadb_use_the_mysql_protocol_adapter() {
        for kind in [DatabaseKind::MySql, DatabaseKind::MariaDb] {
            let error = match connect(&DirectDatabaseConfiguration {
                kind,
                connection: "not-a-url".into(),
                sqlcipher_key: None,
            }) {
                Ok(_) => panic!("invalid endpoint accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code(), 8090);
        }
    }
    #[test]
    fn postgresql_adapter_attempts_a_native_connection() {
        let error = match connect(&DirectDatabaseConfiguration {
            kind: DatabaseKind::PostgreSql,
            connection: "host=127.0.0.1 port=1 connect_timeout=1".into(),
            sqlcipher_key: None,
        }) {
            Ok(_) => panic!("unreachable endpoint accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), 8080);
    }
}

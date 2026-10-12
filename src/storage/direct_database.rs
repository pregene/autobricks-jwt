use std::collections::BTreeMap;

use mysql::{
    ClientIdentity, Opts, OptsBuilder, Params, Pool, Row as MySqlRow, SslOpts, Value as MySqlValue,
    prelude::Queryable,
};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
use postgres::{Client, NoTls, types::ToSql};
use postgres_openssl::MakeTlsConnector;
use rusqlite::{Connection, params_from_iter, types::ValueRef};
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
    pub tls: DirectDatabaseTls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectDatabaseTls {
    Disabled,
    Tls {
        trust_chain: std::path::PathBuf,
    },
    MutualTls {
        trust_chain: std::path::PathBuf,
        certificate: std::path::PathBuf,
        private_key: std::path::PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum DatabaseValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Real(f64),
    Text(String),
    Binary(Vec<u8>),
}

pub trait DirectDatabase {
    fn query(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<Vec<BTreeMap<String, Value>>, ServiceError>;
    fn update(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<u64, ServiceError>;
}

pub fn connect(
    configuration: &DirectDatabaseConfiguration,
) -> Result<Box<dyn DirectDatabase>, ServiceError> {
    match configuration.kind {
        DatabaseKind::PostgreSql => {
            let client = match &configuration.tls {
                DirectDatabaseTls::Disabled => {
                    Client::connect(&configuration.connection, NoTls).map_err(|_| unavailable())?
                }
                tls => {
                    let connector = postgres_tls_connector(tls)?;
                    Client::connect(&configuration.connection, connector)
                        .map_err(|_| unavailable())?
                }
            };
            Ok(Box::new(PostgreSqlDatabase { client }))
        }
        DatabaseKind::MariaDb | DatabaseKind::MySql => {
            let options = mysql_options(configuration)?;
            Ok(Box::new(MySqlDatabase {
                pool: Pool::new(options).map_err(|_| unavailable())?,
            }))
        }
        DatabaseKind::Sqlite | DatabaseKind::SqlCipher => {
            if configuration.tls != DirectDatabaseTls::Disabled {
                return Err(invalid());
            }
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

fn postgres_tls_connector(tls: &DirectDatabaseTls) -> Result<MakeTlsConnector, ServiceError> {
    let (trust_chain, identity) = tls_files(tls)?;
    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|_| invalid())?;
    builder.set_ca_file(trust_chain).map_err(|_| invalid())?;
    if let Some((certificate, private_key)) = identity {
        builder
            .set_certificate_file(certificate, SslFiletype::PEM)
            .and_then(|_| builder.set_private_key_file(private_key, SslFiletype::PEM))
            .and_then(|_| builder.check_private_key())
            .map_err(|_| invalid())?;
    }
    Ok(MakeTlsConnector::new(builder.build()))
}

fn mysql_options(configuration: &DirectDatabaseConfiguration) -> Result<Opts, ServiceError> {
    let base = Opts::from_url(&configuration.connection).map_err(|_| invalid())?;
    if configuration.tls == DirectDatabaseTls::Disabled {
        return Ok(base);
    }
    let (trust_chain, identity) = tls_files(&configuration.tls)?;
    let mut ssl = SslOpts::default().with_root_cert_path(Some(trust_chain.to_path_buf()));
    if let Some((certificate, private_key)) = identity {
        ssl = ssl.with_client_identity(Some(ClientIdentity::new(
            certificate.to_path_buf(),
            private_key.to_path_buf(),
        )));
    }
    Ok(OptsBuilder::from_opts(base).ssl_opts(Some(ssl)).into())
}

fn tls_files(
    tls: &DirectDatabaseTls,
) -> Result<
    (
        &std::path::Path,
        Option<(&std::path::Path, &std::path::Path)>,
    ),
    ServiceError,
> {
    let result = match tls {
        DirectDatabaseTls::Disabled => return Err(invalid()),
        DirectDatabaseTls::Tls { trust_chain } => (trust_chain.as_path(), None),
        DirectDatabaseTls::MutualTls {
            trust_chain,
            certificate,
            private_key,
        } => (
            trust_chain.as_path(),
            Some((certificate.as_path(), private_key.as_path())),
        ),
    };
    if !result.0.is_file()
        || result.1.is_some_and(|(certificate, private_key)| {
            !certificate.is_file() || !private_key.is_file()
        })
    {
        return Err(invalid());
    }
    Ok(result)
}

struct PostgreSqlDatabase {
    client: Client,
}
impl DirectDatabase for PostgreSqlDatabase {
    fn query(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
        let owned = postgres_parameters(parameters);
        let references = owned
            .iter()
            .map(|value| value.as_ref() as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = self
            .client
            .query(statement, &references)
            .map_err(|_| operation())?;
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
    fn update(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<u64, ServiceError> {
        let owned = postgres_parameters(parameters);
        let references = owned
            .iter()
            .map(|value| value.as_ref() as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        self.client
            .execute(statement, &references)
            .map_err(|_| operation())
    }
}

struct MySqlDatabase {
    pool: Pool,
}
impl DirectDatabase for MySqlDatabase {
    fn query(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
        let mut connection = self.pool.get_conn().map_err(|_| unavailable())?;
        let rows: Vec<MySqlRow> = connection
            .exec(statement, mysql_parameters(parameters))
            .map_err(|_| operation())?;
        rows.into_iter().map(mysql_row).collect()
    }
    fn update(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<u64, ServiceError> {
        let mut connection = self.pool.get_conn().map_err(|_| unavailable())?;
        connection
            .exec_drop(statement, mysql_parameters(parameters))
            .map_err(|_| operation())?;
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
    fn query(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<Vec<BTreeMap<String, Value>>, ServiceError> {
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
            .query_map(
                params_from_iter(parameters.iter().map(sqlite_parameter)),
                |row| {
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
                },
            )
            .map_err(|_| operation())?;
        rows.map(|row| row.map_err(|_| operation())).collect()
    }
    fn update(
        &mut self,
        statement: &str,
        parameters: &[DatabaseValue],
    ) -> Result<u64, ServiceError> {
        self.connection
            .execute(
                statement,
                params_from_iter(parameters.iter().map(sqlite_parameter)),
            )
            .map(|count| count as u64)
            .map_err(|_| operation())
    }
}

fn postgres_parameters(parameters: &[DatabaseValue]) -> Vec<Box<dyn ToSql + Sync>> {
    parameters
        .iter()
        .map(|value| match value {
            DatabaseValue::Null => Box::new(None::<String>) as Box<dyn ToSql + Sync>,
            DatabaseValue::Boolean(value) => Box::new(*value),
            DatabaseValue::Integer(value) => Box::new(*value),
            DatabaseValue::Real(value) => Box::new(*value),
            DatabaseValue::Text(value) => Box::new(value.clone()),
            DatabaseValue::Binary(value) => Box::new(value.clone()),
        })
        .collect()
}

fn mysql_parameters(parameters: &[DatabaseValue]) -> Params {
    Params::Positional(
        parameters
            .iter()
            .map(|value| match value {
                DatabaseValue::Null => MySqlValue::NULL,
                DatabaseValue::Boolean(value) => MySqlValue::Int(i64::from(*value)),
                DatabaseValue::Integer(value) => MySqlValue::Int(*value),
                DatabaseValue::Real(value) => MySqlValue::Double(*value),
                DatabaseValue::Text(value) => MySqlValue::Bytes(value.as_bytes().to_vec()),
                DatabaseValue::Binary(value) => MySqlValue::Bytes(value.clone()),
            })
            .collect(),
    )
}

fn sqlite_parameter(value: &DatabaseValue) -> rusqlite::types::Value {
    match value {
        DatabaseValue::Null => rusqlite::types::Value::Null,
        DatabaseValue::Boolean(value) => rusqlite::types::Value::Integer(i64::from(*value)),
        DatabaseValue::Integer(value) => rusqlite::types::Value::Integer(*value),
        DatabaseValue::Real(value) => rusqlite::types::Value::Real(*value),
        DatabaseValue::Text(value) => rusqlite::types::Value::Text(value.clone()),
        DatabaseValue::Binary(value) => rusqlite::types::Value::Blob(value.clone()),
    }
}

fn invalid() -> ServiceError {
    ServiceError::configuration_invalid("direct database configuration is invalid")
}
fn unavailable() -> ServiceError {
    ServiceError::assigned(8080, "direct database is unavailable")
}
fn operation() -> ServiceError {
    ServiceError::assigned(8081, "direct database operation failed")
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
            tls: DirectDatabaseTls::Disabled,
        };
        let mut database = connect(&configuration).unwrap();
        assert_eq!(
            database
                .update("CREATE TABLE subjects(user_id TEXT, active INTEGER)", &[])
                .unwrap(),
            0
        );
        assert_eq!(
            database
                .update(
                    "INSERT INTO subjects VALUES(?1, ?2)",
                    &[
                        DatabaseValue::Text("user-1".into()),
                        DatabaseValue::Integer(1),
                    ],
                )
                .unwrap(),
            1
        );
        let result = database
            .query(
                "SELECT user_id, active FROM subjects WHERE user_id=?1",
                &[DatabaseValue::Text("user-1".into())],
            )
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
                tls: DirectDatabaseTls::Disabled,
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
            tls: DirectDatabaseTls::Disabled,
        }) {
            Ok(_) => panic!("unreachable endpoint accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), 8080);
    }

    #[test]
    fn validates_tls_and_mtls_material_for_network_database_adapters() {
        let missing = std::env::temp_dir().join(format!("missing-{}", Uuid::new_v4()));
        for kind in [
            DatabaseKind::PostgreSql,
            DatabaseKind::MariaDb,
            DatabaseKind::MySql,
        ] {
            let tls = DirectDatabaseConfiguration {
                kind,
                connection: if kind == DatabaseKind::PostgreSql {
                    "host=127.0.0.1 port=1 connect_timeout=1".into()
                } else {
                    "mysql://127.0.0.1:1/database".into()
                },
                sqlcipher_key: None,
                tls: DirectDatabaseTls::Tls {
                    trust_chain: missing.clone(),
                },
            };
            let error = connect(&tls).err().expect("missing trust chain accepted");
            assert_eq!(error.code(), 8090);
            let mtls = DirectDatabaseConfiguration {
                tls: DirectDatabaseTls::MutualTls {
                    trust_chain: missing.clone(),
                    certificate: missing.clone(),
                    private_key: missing.clone(),
                },
                ..tls
            };
            let error = connect(&mtls)
                .err()
                .expect("missing mTLS identity accepted");
            assert_eq!(error.code(), 8090);
        }
    }
}

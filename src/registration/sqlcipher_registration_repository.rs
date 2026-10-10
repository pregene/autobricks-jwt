use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::{
    database_source::DatabaseSourcePlan,
    service_error::ServiceError,
    service_registry::{ClientRegistration, OperationClass, StoredServiceRegistration},
};

pub struct SqlCipherRegistrationRepository {
    connection: Connection,
}

impl SqlCipherRegistrationRepository {
    pub fn open(path: &Path, database_key: &[u8; 32]) -> Result<Self, ServiceError> {
        let connection = Connection::open(path).map_err(database_unavailable)?;
        let key = database_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
            .map_err(database_unavailable)?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(database_unavailable)?;
        if cipher_version.trim().is_empty() {
            return Err(classified(8084, "SQLCipher key store is unavailable"));
        }
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL UNIQUE,
                    operation_class TEXT NOT NULL CHECK (operation_class IN ('READ', 'WRITE')),
                    allowed_source_cidr TEXT NOT NULL,
                    transports_json TEXT NOT NULL,
                    keep_alive_timeout INTEGER NOT NULL CHECK (keep_alive_timeout > 0),
                    peer_uid INTEGER,
                    peer_gid INTEGER,
                    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'INACTIVE', 'DELETED')),
                    created_at INTEGER NOT NULL,
                    modified_at INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS services (
                    service_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL REFERENCES clients(client_id),
                    service_name TEXT NOT NULL UNIQUE,
                    apikey_salt BLOB NOT NULL,
                    apikey_verifier BLOB NOT NULL,
                    subject_type TEXT NOT NULL CHECK (subject_type IN ('USER', 'DEVICE', 'WORKLOAD')),
                    allowed_fields_json TEXT NOT NULL,
                    source_type TEXT,
                    encryption_profile TEXT,
                    client_json_schema TEXT,
                    database_source_json TEXT,
                    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DELETED')),
                    created_at INTEGER NOT NULL,
                    modified_at INTEGER NOT NULL
                 );",
            )
            .map_err(database_operation_failed)?;
        Ok(Self { connection })
    }

    pub fn insert_client(
        &mut self,
        client: &ClientRegistration,
        now: u64,
    ) -> Result<(), ServiceError> {
        let transports = serde_json::to_string(&client.transports)
            .map_err(|_| database_operation_failed_message("client transports are invalid"))?;
        let now = to_i64(now)?;
        self.connection
            .execute(
                "INSERT INTO clients (
                    client_id, client_name, operation_class, allowed_source_cidr,
                    transports_json, keep_alive_timeout, peer_uid, peer_gid,
                    status, created_at, modified_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ACTIVE', ?9, ?9)",
                params![
                    client.client_id.to_string(),
                    client.client_name,
                    operation_name(client.operation_class),
                    client.allowed_source_cidr,
                    transports,
                    to_i64(client.keep_alive_timeout)?,
                    client.peer_uid,
                    client.peer_gid,
                    now,
                ],
            )
            .map_err(database_operation_failed)?;
        Ok(())
    }

    pub(crate) fn insert_service(
        &mut self,
        service: &StoredServiceRegistration,
        now: u64,
    ) -> Result<(), ServiceError> {
        let fields = serde_json::to_string(&service.allowed_jwt_query_fields)
            .map_err(|_| database_operation_failed_message("service fields are invalid"))?;
        let now = to_i64(now)?;
        self.connection
            .execute(
                "INSERT INTO services (
                    service_id, client_id, service_name, apikey_salt,
                    apikey_verifier, subject_type, allowed_fields_json,
                    source_type, encryption_profile, client_json_schema,
                    database_source_json, status, created_at, modified_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'ACTIVE', ?12, ?12)",
                params![
                    service.service_id.to_string(),
                    service.client_id.to_string(),
                    service.service_name,
                    service.apikey_salt.as_slice(),
                    service.apikey_verifier.as_slice(),
                    service.subject_type,
                    fields,
                    service.source_type,
                    service.encryption_profile,
                    service
                        .client_json_schema
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|_| database_operation_failed_message(
                            "CLIENT_JSON schema is invalid"
                        ))?,
                    service
                        .database_source
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|_| database_operation_failed_message(
                            "DATABASE source is invalid"
                        ))?,
                    now,
                ],
            )
            .map_err(database_operation_failed)?;
        Ok(())
    }

    pub fn load_active_clients(&self) -> Result<Vec<ClientRegistration>, ServiceError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT client_id, client_name, operation_class, allowed_source_cidr,
                        transports_json, keep_alive_timeout, peer_uid, peer_gid
                   FROM clients WHERE status = 'ACTIVE' ORDER BY client_id",
            )
            .map_err(database_operation_failed)?;
        let rows = statement
            .query_map([], |row| {
                let client_id: String = row.get(0)?;
                let operation_class: String = row.get(2)?;
                let transports: String = row.get(4)?;
                Ok((
                    client_id,
                    row.get::<_, String>(1)?,
                    operation_class,
                    row.get::<_, String>(3)?,
                    transports,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<u32>>(6)?,
                    row.get::<_, Option<u32>>(7)?,
                ))
            })
            .map_err(database_operation_failed)?;
        rows.map(|row| {
            let (id, name, operation, cidr, transports, timeout, uid, gid) =
                row.map_err(database_operation_failed)?;
            Ok(ClientRegistration {
                client_id: Uuid::parse_str(&id)
                    .map_err(|_| database_operation_failed_message("client UUID is invalid"))?,
                client_name: name,
                operation_class: parse_operation(&operation)?,
                allowed_source_cidr: cidr,
                transports: serde_json::from_str(&transports).map_err(|_| {
                    database_operation_failed_message("client transports are invalid")
                })?,
                keep_alive_timeout: u64::try_from(timeout)
                    .map_err(|_| database_operation_failed_message("client timeout is invalid"))?,
                peer_uid: uid,
                peer_gid: gid,
            })
        })
        .collect()
    }

    pub(crate) fn load_active_services(
        &self,
    ) -> Result<Vec<StoredServiceRegistration>, ServiceError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT services.service_id, services.client_id, services.service_name,
                        services.apikey_salt, services.apikey_verifier,
                        services.subject_type, services.allowed_fields_json,
                        services.source_type, services.encryption_profile,
                        services.client_json_schema
                        , services.database_source_json
                   FROM services
                   JOIN clients ON clients.client_id = services.client_id
                  WHERE services.status = 'ACTIVE' AND clients.status = 'ACTIVE'
                  ORDER BY service_id",
            )
            .map_err(database_operation_failed)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(database_operation_failed)?;
        rows.map(|row| {
            let (
                service_id,
                client_id,
                name,
                salt,
                verifier,
                subject,
                fields,
                source,
                profile,
                schema,
                database_source,
            ) = row.map_err(database_operation_failed)?;
            Ok(StoredServiceRegistration {
                service_id: parse_uuid(&service_id, "service")?,
                client_id: parse_uuid(&client_id, "client")?,
                service_name: name,
                apikey_salt: fixed_bytes(salt, "APIKEY salt")?,
                apikey_verifier: fixed_bytes(verifier, "APIKEY verifier")?,
                subject_type: subject,
                allowed_jwt_query_fields: serde_json::from_str(&fields)
                    .map_err(|_| database_operation_failed_message("service fields are invalid"))?,
                source_type: source,
                encryption_profile: profile,
                client_json_schema: schema
                    .map(|value| serde_json::from_str(&value))
                    .transpose()
                    .map_err(|_| {
                        database_operation_failed_message("CLIENT_JSON schema is invalid")
                    })?,
                database_source: database_source
                    .map(|value| serde_json::from_str(&value))
                    .transpose()
                    .map_err(|_| database_operation_failed_message("DATABASE source is invalid"))?,
            })
        })
        .collect()
    }

    pub fn set_database_source(
        &mut self,
        service_id: Uuid,
        source: &DatabaseSourcePlan,
    ) -> Result<(), ServiceError> {
        let source = serde_json::to_string(source)
            .map_err(|_| database_operation_failed_message("DATABASE source is invalid"))?;
        let updated = self.connection.execute(
            "UPDATE services SET database_source_json = ?2 WHERE service_id = ?1 AND status = 'ACTIVE'",
            params![service_id.to_string(), source],
        ).map_err(database_operation_failed)?;
        if updated != 1 {
            return Err(classified(8040, "service registration is not available"));
        }
        Ok(())
    }

    pub fn delete_service(&mut self, service_id: Uuid, now: u64) -> Result<(), ServiceError> {
        let updated = self
            .connection
            .execute(
                "UPDATE services SET status = 'DELETED', modified_at = ?2
                  WHERE service_id = ?1 AND status = 'ACTIVE'",
                params![service_id.to_string(), to_i64(now)?],
            )
            .map_err(database_operation_failed)?;
        if updated != 1 {
            return Err(classified(8040, "service registration is not available"));
        }
        Ok(())
    }

    pub fn set_client_active(
        &mut self,
        client_id: Uuid,
        active: bool,
        now: u64,
    ) -> Result<(), ServiceError> {
        let target = if active { "ACTIVE" } else { "INACTIVE" };
        let expected = if active { "INACTIVE" } else { "ACTIVE" };
        let updated = self
            .connection
            .execute(
                "UPDATE clients SET status = ?2, modified_at = ?3
                  WHERE client_id = ?1 AND status = ?4",
                params![client_id.to_string(), target, to_i64(now)?, expected],
            )
            .map_err(database_operation_failed)?;
        if updated != 1 {
            return Err(classified(
                8020,
                "client lifecycle transition is not available",
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_client(
        &mut self,
        client_id: Uuid,
        client_name: &str,
        allowed_source_cidr: &str,
        transports: &[String],
        keep_alive_timeout: u64,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
        now: u64,
    ) -> Result<(), ServiceError> {
        let transports = serde_json::to_string(transports)
            .map_err(|_| database_operation_failed_message("client transports are invalid"))?;
        let updated = self
            .connection
            .execute(
                "UPDATE clients
                    SET client_name = ?2, allowed_source_cidr = ?3,
                        transports_json = ?4, keep_alive_timeout = ?5,
                        peer_uid = ?6, peer_gid = ?7, modified_at = ?8
                  WHERE client_id = ?1 AND status = 'ACTIVE'",
                params![
                    client_id.to_string(),
                    client_name,
                    allowed_source_cidr,
                    transports,
                    to_i64(keep_alive_timeout)?,
                    peer_uid,
                    peer_gid,
                    to_i64(now)?,
                ],
            )
            .map_err(database_operation_failed)?;
        if updated != 1 {
            return Err(classified(8020, "client registration is not active"));
        }
        Ok(())
    }

    pub fn delete_client_cascade(
        &mut self,
        client_id: Uuid,
        now: u64,
    ) -> Result<usize, ServiceError> {
        let now = to_i64(now)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(database_operation_failed)?;
        let client_count = transaction
            .execute(
                "UPDATE clients SET status = 'DELETED', modified_at = ?2
                  WHERE client_id = ?1 AND status = 'ACTIVE'",
                params![client_id.to_string(), now],
            )
            .map_err(database_operation_failed)?;
        if client_count != 1 {
            return Err(classified(8020, "client registration is not active"));
        }
        let service_count = update_child_services(&transaction, client_id, now)?;
        transaction.commit().map_err(database_operation_failed)?;
        Ok(service_count)
    }

    pub fn status(&self, table: &str, id: Uuid) -> Result<Option<String>, ServiceError> {
        let (table, column) = match table {
            "clients" => ("clients", "client_id"),
            "services" => ("services", "service_id"),
            _ => return Err(database_operation_failed_message("status table is invalid")),
        };
        self.connection
            .query_row(
                &format!("SELECT status FROM {table} WHERE {column} = ?1"),
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_operation_failed)
    }
}

fn update_child_services(
    transaction: &Transaction<'_>,
    client_id: Uuid,
    now: i64,
) -> Result<usize, ServiceError> {
    transaction
        .execute(
            "UPDATE services SET status = 'DELETED', modified_at = ?2
              WHERE client_id = ?1 AND status = 'ACTIVE'",
            params![client_id.to_string(), now],
        )
        .map_err(database_operation_failed)
}

fn operation_name(operation: OperationClass) -> &'static str {
    match operation {
        OperationClass::Read => "READ",
        OperationClass::Write => "WRITE",
    }
}

fn parse_operation(value: &str) -> Result<OperationClass, ServiceError> {
    match value {
        "READ" => Ok(OperationClass::Read),
        "WRITE" => Ok(OperationClass::Write),
        _ => Err(database_operation_failed_message(
            "stored operation class is invalid",
        )),
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ServiceError> {
    Uuid::parse_str(value)
        .map_err(|_| database_operation_failed_message(format!("stored {field} UUID is invalid")))
}

fn fixed_bytes<const N: usize>(value: Vec<u8>, field: &str) -> Result<[u8; N], ServiceError> {
    value
        .try_into()
        .map_err(|_| database_operation_failed_message(format!("stored {field} is invalid")))
}

fn to_i64(value: u64) -> Result<i64, ServiceError> {
    i64::try_from(value)
        .map_err(|_| database_operation_failed_message("numeric value is out of range"))
}

fn classified(code: u16, message: impl Into<std::borrow::Cow<'static, str>>) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

fn database_unavailable(error: rusqlite::Error) -> ServiceError {
    let _ = error;
    classified(8080, "registration database is unavailable")
}

fn database_operation_failed(error: rusqlite::Error) -> ServiceError {
    let _ = error;
    classified(8081, "registration database operation failed")
}

fn database_operation_failed_message(
    message: impl Into<std::borrow::Cow<'static, str>>,
) -> ServiceError {
    classified(8081, message)
}

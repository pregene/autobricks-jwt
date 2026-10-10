use std::path::Path;

use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::{jwe_token::IssuedToken, service_error::ServiceError};

pub struct SqlCipherTokenRepository {
    connection: Connection,
}

pub struct ActiveTokenRecord {
    pub client_id: Uuid,
    pub service_id: Uuid,
    pub token: IssuedToken,
}

impl SqlCipherTokenRepository {
    pub fn open(path: &Path, database_key: &[u8; 32]) -> Result<Self, ServiceError> {
        let connection = Connection::open(path).map_err(database_error)?;
        let key = database_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
            .map_err(database_error)?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(database_error)?;
        if cipher_version.trim().is_empty() {
            return Err(database_error("SQLCipher runtime is unavailable"));
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS token_keys (
                    kid TEXT PRIMARY KEY,
                    token_id TEXT NOT NULL,
                    token_key BLOB NOT NULL CHECK(length(token_key) IN (16, 24, 32)),
                    algorithm TEXT NOT NULL CHECK(algorithm = 'dir'),
                    encryption TEXT NOT NULL CHECK(encryption IN ('A128GCM','A192GCM','A256GCM')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REPLACED', 'REVOKED'))
                );
                CREATE TABLE IF NOT EXISTS token_versions (
                    token_id TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version >= 1),
                    client_id TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    kid TEXT NOT NULL,
                    token TEXT NOT NULL,
                    token_digest BLOB NOT NULL CHECK(length(token_digest) = 32),
                    iv BLOB NOT NULL CHECK(length(iv) = 12),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REPLACED', 'REVOKED')),
                    PRIMARY KEY(token_id, version),
                    UNIQUE(client_id, request_id),
                    FOREIGN KEY(kid) REFERENCES token_keys(kid)
                );",
            )
            .map_err(database_error)?;
        Ok(Self { connection })
    }

    pub fn store_issued(
        &mut self,
        client_id: Uuid,
        service_id: Uuid,
        request_id: Uuid,
        token: &IssuedToken,
    ) -> Result<(), ServiceError> {
        let issued_at = integer_time(token.issued_at)?;
        let expires_at = integer_time(token.expires_at)?;
        let token_digest = digest(&SHA256, token.token.as_bytes());
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO token_keys (
                    kid, token_id, token_key, algorithm, encryption,
                    created_at, expires_at, status
                ) VALUES (?1, ?2, ?3, 'dir', ?4, ?5, ?6, 'ACTIVE')",
                params![
                    token.kid.to_string(),
                    token.token_id.to_string(),
                    token.key.as_slice(),
                    token.profile.encryption_name(),
                    issued_at,
                    expires_at,
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO token_versions (
                    token_id, version, client_id, service_id, request_id, kid,
                    token, token_digest, iv, issued_at, expires_at, status
                ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'ACTIVE')",
                params![
                    token.token_id.to_string(),
                    client_id.to_string(),
                    service_id.to_string(),
                    request_id.to_string(),
                    token.kid.to_string(),
                    token.token,
                    token_digest.as_ref(),
                    token.iv.as_slice(),
                    issued_at,
                    expires_at,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn load_active(&self, token_id: Uuid) -> Result<Option<IssuedToken>, ServiceError> {
        Ok(self
            .load_active_record(token_id)?
            .map(|record| record.token))
    }

    pub fn load_active_record(
        &self,
        token_id: Uuid,
    ) -> Result<Option<ActiveTokenRecord>, ServiceError> {
        let record = self
            .connection
            .query_row(
                "SELECT v.token_id, v.client_id, v.service_id, v.token, v.kid, k.token_key,
                        v.iv, v.issued_at, v.expires_at, v.token_digest
                   FROM token_versions v
                   JOIN token_keys k ON k.kid = v.kid
                  WHERE v.token_id = ?1 AND v.status = 'ACTIVE' AND k.status = 'ACTIVE'",
                [token_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        record.map(restore_record).transpose()
    }

    pub fn load_active_by_request(
        &self,
        client_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<IssuedToken>, ServiceError> {
        let token_id = self
            .connection
            .query_row(
                "SELECT token_id FROM token_versions
                  WHERE client_id = ?1 AND request_id = ?2 AND status = 'ACTIVE'",
                params![client_id.to_string(), request_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?;
        token_id
            .map(|value| {
                Uuid::parse_str(&value)
                    .map_err(|_| database_error("stored token identifier is invalid"))
                    .and_then(|token_id| self.load_active(token_id))
            })
            .transpose()
            .map(Option::flatten)
    }

    pub fn load_by_correlation(
        &self,
        request_id: Uuid,
        token_id: Uuid,
    ) -> Result<Option<ActiveTokenRecord>, ServiceError> {
        let record = self
            .connection
            .query_row(
                "SELECT v.token_id, v.client_id, v.service_id, v.token, v.kid, k.token_key,
                        v.iv, v.issued_at, v.expires_at, v.token_digest
                   FROM token_versions v
                   JOIN token_keys k ON k.kid = v.kid
                  WHERE v.request_id = ?1 AND v.token_id = ?2
                  ORDER BY v.version DESC LIMIT 1",
                params![request_id.to_string(), token_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        record.map(restore_record).transpose()
    }

    pub fn replace_active(
        &mut self,
        request_id: Uuid,
        replacement: &IssuedToken,
    ) -> Result<u64, ServiceError> {
        let current = self
            .load_active_record(replacement.token_id)?
            .ok_or_else(session_missing)?;
        let token_digest = digest(&SHA256, replacement.token.as_bytes());
        let issued_at = integer_time(replacement.issued_at)?;
        let expires_at = integer_time(replacement.expires_at)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let version: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM token_versions WHERE token_id = ?1",
                [replacement.token_id.to_string()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "UPDATE token_versions SET status = 'REPLACED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                [replacement.token_id.to_string()],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "UPDATE token_keys SET status = 'REPLACED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                [replacement.token_id.to_string()],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO token_keys (
                    kid, token_id, token_key, algorithm, encryption,
                    created_at, expires_at, status
                 ) VALUES (?1, ?2, ?3, 'dir', ?4, ?5, ?6, 'ACTIVE')",
                params![
                    replacement.kid.to_string(),
                    replacement.token_id.to_string(),
                    replacement.key.as_slice(),
                    replacement.profile.encryption_name(),
                    issued_at,
                    expires_at,
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO token_versions (
                    token_id, version, client_id, service_id, request_id, kid,
                    token, token_digest, iv, issued_at, expires_at, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'ACTIVE')",
                params![
                    replacement.token_id.to_string(),
                    version,
                    current.client_id.to_string(),
                    current.service_id.to_string(),
                    request_id.to_string(),
                    replacement.kid.to_string(),
                    replacement.token,
                    token_digest.as_ref(),
                    replacement.iv.as_slice(),
                    issued_at,
                    expires_at,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        u64::try_from(version).map_err(|_| database_error("token version is invalid"))
    }

    pub fn revoke_active(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let versions = transaction
            .execute(
                "UPDATE token_versions SET status = 'REVOKED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                [token_id.to_string()],
            )
            .map_err(database_error)?;
        if versions != 1 {
            return Err(session_missing());
        }
        transaction
            .execute(
                "UPDATE token_keys SET status = 'REVOKED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                [token_id.to_string()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn revoke_active_by_client(&mut self, client_id: Uuid) -> Result<usize, ServiceError> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let token_ids = {
            let mut statement = transaction
                .prepare(
                    "SELECT token_id FROM token_versions
                  WHERE client_id = ?1 AND status = 'ACTIVE'",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([client_id.to_string()], |row| row.get::<_, String>(0))
                .map_err(database_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        for token_id in &token_ids {
            transaction
                .execute(
                    "UPDATE token_versions SET status = 'REVOKED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                    [token_id],
                )
                .map_err(database_error)?;
            transaction
                .execute(
                    "UPDATE token_keys SET status = 'REVOKED'
                  WHERE token_id = ?1 AND status = 'ACTIVE'",
                    [token_id],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(token_ids.len())
    }

    pub fn history_version_count(&self, token_id: Uuid) -> Result<u64, ServiceError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM token_versions WHERE token_id = ?1",
                [token_id.to_string()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        u64::try_from(count).map_err(|_| database_error("token history count is invalid"))
    }

    #[cfg(test)]
    fn tamper_token(&self, token_id: Uuid) {
        self.connection
            .execute(
                "UPDATE token_versions SET token = token || 'A' WHERE token_id = ?1",
                [token_id.to_string()],
            )
            .unwrap();
    }
}

#[allow(clippy::type_complexity)]
fn restore_record(
    record: (
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
    ),
) -> Result<ActiveTokenRecord, ServiceError> {
    let (
        token_id,
        client_id,
        service_id,
        token,
        kid,
        key,
        iv,
        issued_at,
        expires_at,
        stored_digest,
    ) = record;
    if digest(&SHA256, token.as_bytes()).as_ref() != stored_digest.as_slice() {
        return Err(ServiceError::jwt_invalid(
            "stored token digest does not match",
        ));
    }
    let token_id = Uuid::parse_str(&token_id)
        .map_err(|_| database_error("stored token identifier is invalid"))?;
    let iv: [u8; 12] = iv
        .try_into()
        .map_err(|_| database_error("stored token IV length is invalid"))?;
    Ok(ActiveTokenRecord {
        client_id: Uuid::parse_str(&client_id)
            .map_err(|_| database_error("stored client identifier is invalid"))?,
        service_id: Uuid::parse_str(&service_id)
            .map_err(|_| database_error("stored service identifier is invalid"))?,
        token: IssuedToken::restore(
            token_id,
            token,
            Uuid::parse_str(&kid).map_err(|_| database_error("stored kid is invalid"))?,
            key,
            iv,
            unsigned_time(issued_at)?,
            unsigned_time(expires_at)?,
        )?,
    })
}

fn integer_time(value: u64) -> Result<i64, ServiceError> {
    i64::try_from(value).map_err(|_| database_error("token time exceeds SQLCipher range"))
}

fn unsigned_time(value: i64) -> Result<u64, ServiceError> {
    u64::try_from(value).map_err(|_| database_error("stored token time is invalid"))
}

fn database_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::classified(8080, format!("SQLCipher token repository error: {error}"))
        .expect("8080 must be assigned")
}

fn session_missing() -> ServiceError {
    ServiceError::classified(8060, "session is not found or expired")
        .expect("8060 must be assigned")
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use serde_json::{Map, Value};

    use super::*;

    fn issue() -> IssuedToken {
        IssuedToken::issue(
            "autobricks-jwt",
            "service-1",
            "user-1",
            Map::from_iter([("user_id".to_owned(), Value::String("user-1".to_owned()))]),
            1_000,
            Duration::from_secs(300),
        )
        .unwrap()
    }

    #[test]
    fn persists_and_restores_encrypted_token_state_across_restart() {
        let path = std::env::temp_dir().join(format!("ab-jwt-token-{}.db", Uuid::new_v4()));
        let database_key = [0x31; 32];
        let client_id = Uuid::new_v4();
        let service_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let issued = issue();
        let token_id = issued.token_id;
        let submitted = issued.token.clone();

        {
            let mut repository = SqlCipherTokenRepository::open(&path, &database_key).unwrap();
            repository
                .store_issued(client_id, service_id, request_id, &issued)
                .unwrap();
        }

        let repository = SqlCipherTokenRepository::open(&path, &database_key).unwrap();
        let restored = repository.load_active(token_id).unwrap().unwrap();
        let fields = restored
            .verify_and_query(&submitted, "service-1", 1_100, &["user_id"])
            .unwrap();
        assert_eq!(fields["user_id"], "user-1");
        drop(repository);
        assert!(SqlCipherTokenRepository::open(&path, &[0x32; 32]).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn detects_persisted_token_tampering_before_decryption() {
        let path = std::env::temp_dir().join(format!("ab-jwt-token-{}.db", Uuid::new_v4()));
        let database_key = [0x41; 32];
        let issued = issue();
        let token_id = issued.token_id;
        let mut repository = SqlCipherTokenRepository::open(&path, &database_key).unwrap();
        repository
            .store_issued(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), &issued)
            .unwrap();
        repository.tamper_token(token_id);
        let error = repository.load_active(token_id).unwrap_err();
        assert_eq!(error.code(), 8061);
        drop(repository);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_duplicate_client_request_without_creating_another_token() {
        let path = std::env::temp_dir().join(format!("ab-jwt-token-{}.db", Uuid::new_v4()));
        let database_key = [0x51; 32];
        let client_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let mut repository = SqlCipherTokenRepository::open(&path, &database_key).unwrap();
        repository
            .store_issued(client_id, Uuid::new_v4(), request_id, &issue())
            .unwrap();
        let duplicate = repository
            .store_issued(client_id, Uuid::new_v4(), request_id, &issue())
            .unwrap_err();
        assert_eq!(duplicate.code(), 8080);
        drop(repository);
        fs::remove_file(path).unwrap();
    }
}

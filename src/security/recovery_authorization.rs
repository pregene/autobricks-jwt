use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

use crate::service_error::ServiceError;

const RECOVERY_KEY_BYTES: usize = 32;
const VERIFIER_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryKeyVerifier([u8; VERIFIER_BYTES]);

#[derive(Debug)]
pub struct GeneratedRecoveryKey {
    plaintext_hex: String,
    verifier: RecoveryKeyVerifier,
}

impl GeneratedRecoveryKey {
    pub fn generate() -> Result<Self, ServiceError> {
        let mut key = [0_u8; RECOVERY_KEY_BYTES];
        getrandom::fill(&mut key)
            .map_err(|_| ServiceError::internal("recovery authorization key generation failed"))?;
        let plaintext_hex = encode_hex(&key);
        let verifier = RecoveryKeyVerifier::from_key_bytes(&key);
        key.fill(0);
        Ok(Self {
            plaintext_hex,
            verifier,
        })
    }

    pub fn expose_once(self) -> (String, RecoveryKeyVerifier) {
        (self.plaintext_hex, self.verifier)
    }
}

impl RecoveryKeyVerifier {
    fn from_key_bytes(key: &[u8; RECOVERY_KEY_BYTES]) -> Self {
        let value = digest(&SHA256, key);
        match <&[u8; VERIFIER_BYTES]>::try_from(value.as_ref()) {
            Ok(bytes) => Self(*bytes),
            Err(_) => Self([0_u8; VERIFIER_BYTES]),
        }
    }

    pub fn from_bytes(bytes: [u8; VERIFIER_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; VERIFIER_BYTES] {
        &self.0
    }

    pub fn verify(&self, submitted_hex: &str) -> Result<(), ServiceError> {
        let submitted = decode_hex_key(submitted_hex).ok_or_else(authorization_failed)?;
        let candidate = Self::from_key_bytes(&submitted);
        let mut difference = 0_u8;
        for (expected, actual) in self.0.iter().zip(candidate.0) {
            difference |= expected ^ actual;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(authorization_failed())
        }
    }
}

pub struct RecoveryAuthorizationRepository {
    connection: Connection,
}

impl RecoveryAuthorizationRepository {
    pub fn open(path: &Path, database_key: &[u8; 32]) -> Result<Self, ServiceError> {
        let connection = Connection::open(path).map_err(|_| storage_failure())?;
        let key = encode_hex(database_key);
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
            .map_err(|_| storage_failure())?;
        let version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_| storage_failure())?;
        if version.is_empty() {
            return Err(storage_failure());
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS recovery_authorization (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            verifier BLOB NOT NULL CHECK(length(verifier) = 32),
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_operation_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation TEXT NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAILURE')),
            error_code INTEGER,
            completed_at INTEGER NOT NULL
        );",
            )
            .map_err(|_| storage_failure())?;
        Ok(Self { connection })
    }

    pub fn initialize(&mut self, now: u64) -> Result<String, ServiceError> {
        if self.load()?.is_some() {
            return Err(ServiceError::invalid_request(
                "recovery authorization is already initialized",
            ));
        }
        let (plaintext, verifier) = GeneratedRecoveryKey::generate()?.expose_once();
        self.connection.execute(
            "INSERT INTO recovery_authorization(singleton, verifier, created_at) VALUES (1, ?1, ?2)",
            params![verifier.as_bytes().as_slice(), i64::try_from(now).map_err(|_| storage_failure())?],
        ).map_err(|_| storage_failure())?;
        Ok(plaintext)
    }

    pub fn require(&self) -> Result<RecoveryKeyVerifier, ServiceError> {
        self.load()?.ok_or_else(|| {
            ServiceError::configuration_invalid("recovery authorization is not initialized")
        })
    }

    pub fn clear_failed_initialization(&mut self) -> Result<(), ServiceError> {
        self.connection
            .execute("DELETE FROM recovery_authorization WHERE singleton = 1", [])
            .map(|_| ())
            .map_err(|_| storage_failure())
    }

    pub fn record_operation(
        &mut self,
        operation: &str,
        result: &str,
        error_code: Option<u16>,
        completed_at: u64,
    ) -> Result<(), ServiceError> {
        if operation.is_empty() || !matches!(result, "SUCCESS" | "FAILURE") {
            return Err(storage_failure());
        }
        self.connection.execute(
            "INSERT INTO recovery_operation_history(operation, result, error_code, completed_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                operation,
                result,
                error_code.map(i64::from),
                i64::try_from(completed_at).map_err(|_| storage_failure())?
            ],
        ).map(|_| ()).map_err(|_| storage_failure())
    }

    fn load(&self) -> Result<Option<RecoveryKeyVerifier>, ServiceError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT verifier FROM recovery_authorization WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| storage_failure())?;
        bytes
            .map(|value| {
                value
                    .try_into()
                    .map(RecoveryKeyVerifier::from_bytes)
                    .map_err(|_| storage_failure())
            })
            .transpose()
    }
}

fn storage_failure() -> ServiceError {
    ServiceError::assigned(8081, "recovery authorization storage failed")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_key(value: &str) -> Option<[u8; RECOVERY_KEY_BYTES]> {
    if value.len() != RECOVERY_KEY_BYTES * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut decoded = [0_u8; RECOVERY_KEY_BYTES];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn authorization_failed() -> ServiceError {
    ServiceError::invalid_request("recovery authorization failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_256_bit_key_and_retains_only_verifier() {
        let generated = GeneratedRecoveryKey::generate().unwrap();
        let (plaintext, verifier) = generated.expose_once();
        assert_eq!(plaintext.len(), 64);
        assert!(
            plaintext
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(verifier.as_bytes().len(), 32);
        verifier.verify(&plaintext).unwrap();
    }

    #[test]
    fn rejects_malformed_and_incorrect_keys_with_same_classification() {
        let (plaintext, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let malformed = verifier.verify("short").unwrap_err();
        let mut incorrect = plaintext;
        incorrect.replace_range(0..2, if &incorrect[0..2] == "00" { "01" } else { "00" });
        let mismatch = verifier.verify(&incorrect).unwrap_err();
        assert_eq!(malformed.code(), 8001);
        assert_eq!(mismatch.code(), 8001);
        assert_eq!(malformed.public_message(), mismatch.public_message());
    }

    #[test]
    fn independent_installations_receive_independent_keys() {
        let (first, _) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let (second, _) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        assert_ne!(first, second);
    }

    #[test]
    fn persists_only_one_recovery_verifier_in_sqlcipher() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-recovery-auth-{}.db", uuid::Uuid::new_v4()));
        let key = [0x91; 32];
        let plaintext = {
            let mut repository = RecoveryAuthorizationRepository::open(&path, &key).unwrap();
            let plaintext = repository.initialize(1_000).unwrap();
            assert_eq!(repository.initialize(1_001).unwrap_err().code(), 8001);
            plaintext
        };
        let repository = RecoveryAuthorizationRepository::open(&path, &key).unwrap();
        repository.require().unwrap().verify(&plaintext).unwrap();
        let database_bytes = std::fs::read(&path).unwrap();
        assert!(
            !database_bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext.as_bytes())
        );
        drop(repository);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn persists_redacted_success_and_failure_recovery_evidence() {
        let path = std::env::temp_dir().join(format!(
            "ab-jwt-recovery-history-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = [0x92; 32];
        let repository = RecoveryAuthorizationRepository::open(&path, &key).unwrap();
        drop(repository);
        let mut repository = RecoveryAuthorizationRepository::open(&path, &key).unwrap();
        repository
            .record_operation("DATABASE_RESTORE", "SUCCESS", None, 1_000)
            .unwrap();
        repository
            .record_operation("DATABASE_RESTORE", "FAILURE", Some(8081), 1_001)
            .unwrap();
        let rows: Vec<(String, String, Option<u16>, u64)> = {
            let mut statement = repository
                .connection
                .prepare(
                    "SELECT operation, result, error_code, completed_at
                 FROM recovery_operation_history ORDER BY history_id",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(
            rows,
            vec![
                ("DATABASE_RESTORE".into(), "SUCCESS".into(), None, 1_000),
                (
                    "DATABASE_RESTORE".into(),
                    "FAILURE".into(),
                    Some(8081),
                    1_001
                ),
            ]
        );
        drop(repository);
        std::fs::remove_file(path).unwrap();
    }
}

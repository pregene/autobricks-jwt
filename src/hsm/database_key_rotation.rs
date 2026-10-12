use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rusqlite::{Connection, backup::Backup, params};

use crate::{recovery_authorization::RecoveryKeyVerifier, service_error::ServiceError};

pub trait HsmDatabaseKeys {
    fn initialize_current(&self) -> Result<(), ServiceError> {
        self.current().map(|_| ())
    }
    fn current(&self) -> Result<[u8; 32], ServiceError>;
    fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError>;
    fn generate_next(&mut self) -> Result<[u8; 32], ServiceError>;
    fn commit(&mut self, previous: [u8; 32], current: [u8; 32]) -> Result<(), ServiceError>;
}

pub struct CommandHsmDatabaseKeys {
    helper: PathBuf,
    key_namespace: String,
}

impl CommandHsmDatabaseKeys {
    pub fn new(
        helper: impl Into<PathBuf>,
        key_namespace: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let helper = helper.into();
        let key_namespace = key_namespace.into();
        if !helper.is_absolute() || key_namespace.trim().is_empty() {
            return Err(configuration(
                "HSM helper path and key namespace are required",
            ));
        }
        Ok(Self {
            helper,
            key_namespace,
        })
    }

    fn call(&self, request: serde_json::Value) -> Result<serde_json::Value, ServiceError> {
        let mut child = Command::new(&self.helper)
            .arg("--hsm-helper")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| hsm_failure("HSM helper cannot be started"))?;
        let input = child
            .stdin
            .as_mut()
            .ok_or_else(|| hsm_failure("HSM helper input is unavailable"))?;
        serde_json::to_writer(&mut *input, &request)
            .map_err(|_| hsm_failure("HSM request cannot be encoded"))?;
        input
            .write_all(b"\n")
            .map_err(|_| hsm_failure("HSM request cannot be written"))?;
        drop(child.stdin.take());
        let output = child
            .wait_with_output()
            .map_err(|_| hsm_failure("HSM helper did not complete"))?;
        if !output.status.success() {
            return Err(hsm_failure("HSM operation failed"));
        }
        serde_json::from_slice(&output.stdout).map_err(|_| hsm_failure("HSM response is invalid"))
    }

    fn read_key(&self, slot: &str) -> Result<Option<[u8; 32]>, ServiceError> {
        let response = self.call(serde_json::json!({
            "operation": "READ",
            "namespace": self.key_namespace,
            "slot": slot
        }))?;
        match response.get("key_hex").and_then(|value| value.as_str()) {
            None if response.get("present") == Some(&serde_json::Value::Bool(false)) => Ok(None),
            Some(value) => decode_key(value).map(Some),
            _ => Err(hsm_failure("HSM key response is incomplete")),
        }
    }
}

impl HsmDatabaseKeys for CommandHsmDatabaseKeys {
    fn initialize_current(&self) -> Result<(), ServiceError> {
        let response = self.call(serde_json::json!({
            "operation": "INITIALIZE",
            "namespace": self.key_namespace
        }))?;
        if response
            .get("initialized")
            .and_then(|value| value.as_bool())
            .is_some()
        {
            Ok(())
        } else {
            Err(hsm_failure("HSM initialization response is incomplete"))
        }
    }
    fn current(&self) -> Result<[u8; 32], ServiceError> {
        self.read_key("CURRENT")?
            .ok_or_else(|| hsm_failure("HSM CURRENT key is unavailable"))
    }

    fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
        self.read_key("PREVIOUS")
    }

    fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
        let response = self.call(serde_json::json!({
            "operation": "GENERATE",
            "namespace": self.key_namespace,
            "bits": 256
        }))?;
        decode_key(
            response
                .get("key_hex")
                .and_then(|value| value.as_str())
                .ok_or_else(|| hsm_failure("generated HSM key is unavailable"))?,
        )
    }

    fn commit(&mut self, previous: [u8; 32], current: [u8; 32]) -> Result<(), ServiceError> {
        let response = self.call(serde_json::json!({
            "operation": "COMMIT_TWO_SLOTS",
            "namespace": self.key_namespace,
            "previous_key_hex": encode_key(&previous),
            "current_key_hex": encode_key(&current)
        }))?;
        if response.get("committed") == Some(&serde_json::Value::Bool(true)) {
            Ok(())
        } else {
            Err(hsm_failure("HSM two-slot commit was rejected"))
        }
    }
}

fn encode_key(key: &[u8; 32]) -> String {
    key.iter().map(|value| format!("{value:02x}")).collect()
}

fn decode_key(value: &str) -> Result<[u8; 32], ServiceError> {
    if value.len() != 64 || !value.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(hsm_failure("HSM key has an invalid encoding"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| hsm_failure("HSM key has an invalid encoding"))?;
    }
    Ok(output)
}

#[derive(Clone, Debug)]
pub struct BackupResult {
    pub generation: u64,
    pub backup_file: PathBuf,
    pub completed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupValidationState {
    Available,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPoint {
    pub generation: u64,
    pub backup_file: PathBuf,
    pub completed_at: u64,
    pub validation: BackupValidationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPreflight {
    pub target_generation: u64,
    pub chain_length: u64,
    pub sqlcipher_integrity_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreResult {
    pub target_generation: u64,
    pub invalidated_sessions: usize,
    pub preserved_database: PathBuf,
}

pub struct DatabaseProtectionManager<H> {
    database_path: PathBuf,
    backup_directory: PathBuf,
    hsm: H,
    recovery: RecoveryKeyVerifier,
}

impl<H: HsmDatabaseKeys> DatabaseProtectionManager<H> {
    pub fn new(
        database_path: impl Into<PathBuf>,
        backup_directory: impl Into<PathBuf>,
        hsm: H,
        recovery: RecoveryKeyVerifier,
    ) -> Result<Self, ServiceError> {
        let database_path = database_path.into();
        let backup_directory = backup_directory.into();
        if !database_path.is_absolute() || !backup_directory.is_absolute() {
            return Err(configuration("database and backup paths must be absolute"));
        }
        fs::create_dir_all(&backup_directory)
            .map_err(|_| database_failure("backup directory cannot be created"))?;
        Ok(Self {
            database_path,
            backup_directory,
            hsm,
            recovery,
        })
    }

    pub fn initialize_schema(&mut self) -> Result<(), ServiceError> {
        let key = self.hsm.current()?;
        let connection = open_sqlcipher(&self.database_path, &key)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS database_key_chain (
                generation INTEGER PRIMARY KEY,
                backup_file TEXT NOT NULL UNIQUE,
                preceding_key BLOB,
                preceding_generation INTEGER,
                created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS backup_history (
                generation INTEGER PRIMARY KEY,
                backup_file TEXT NOT NULL UNIQUE,
                completed_at INTEGER NOT NULL
             );",
            )
            .map_err(|_| database_failure("key-chain schema could not be created"))?;
        Ok(())
    }

    pub fn force_backup_and_rotate(
        &mut self,
        submitted_recovery_key: &str,
        now: u64,
    ) -> Result<BackupResult, ServiceError> {
        self.recovery.verify(submitted_recovery_key)?;
        self.backup_and_rotate(now)
    }

    pub fn scheduled_backup_and_rotate(&mut self, now: u64) -> Result<BackupResult, ServiceError> {
        self.backup_and_rotate(now)
    }

    fn backup_and_rotate(&mut self, now: u64) -> Result<BackupResult, ServiceError> {
        let current = self.hsm.current()?;
        let connection = open_sqlcipher(&self.database_path, &current)?;
        let generation = current_generation(&connection)?.saturating_add(1);
        let backup_file = self
            .backup_directory
            .join(format!("autobricks-jwt-{generation:020}.db"));
        if backup_file.exists() {
            return Err(database_failure("backup generation already exists"));
        }
        create_encrypted_backup(&connection, &backup_file, &current)?;
        validate_database(&backup_file, &current)?;

        let next = self.hsm.generate_next()?;
        rekey(&connection, &next)?;
        let inserted = connection
            .execute(
                "INSERT INTO database_key_chain (
                generation, backup_file, preceding_key, preceding_generation, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    generation,
                    backup_file.to_string_lossy(),
                    current.as_slice(),
                    generation - 1,
                    now
                ],
            )
            .map_err(|_| key_failure("key-chain link could not be stored"));
        if let Err(error) = inserted {
            let _ = rekey(&connection, &current);
            let _ = fs::remove_file(&backup_file);
            return Err(error);
        }
        connection.execute(
            "INSERT INTO backup_history (generation, backup_file, completed_at) VALUES (?1, ?2, ?3)",
            params![generation, backup_file.to_string_lossy(), now],
        ).map_err(|_| database_failure("backup history could not be stored"))?;
        if let Err(error) = self.hsm.commit(current, next) {
            let _ = rekey(&connection, &current);
            let _ = fs::remove_file(&backup_file);
            return Err(error);
        }
        validate_database(&self.database_path, &next)?;
        Ok(BackupResult {
            generation,
            backup_file,
            completed_at: now,
        })
    }

    pub fn recovery_points(&self) -> Result<Vec<RecoveryPoint>, ServiceError> {
        let current = self.hsm.current()?;
        let connection = open_sqlcipher(&self.database_path, &current)?;
        let mut statement = connection
            .prepare(
                "SELECT generation, backup_file, completed_at
                   FROM backup_history ORDER BY generation DESC",
            )
            .map_err(|_| database_failure("recovery-point catalog cannot be read"))?;
        let records = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| database_failure("recovery-point catalog cannot be read"))?;
        records
            .map(|record| {
                let (generation, backup_file, completed_at) =
                    record.map_err(|_| database_failure("recovery-point record is invalid"))?;
                let generation = u64::try_from(generation)
                    .map_err(|_| database_failure("backup generation is invalid"))?;
                let completed_at = u64::try_from(completed_at)
                    .map_err(|_| database_failure("backup completion time is invalid"))?;
                let backup_file = PathBuf::from(backup_file);
                let validation = if backup_file.is_file() {
                    BackupValidationState::Available
                } else {
                    BackupValidationState::Missing
                };
                Ok(RecoveryPoint {
                    generation,
                    backup_file,
                    completed_at,
                    validation,
                })
            })
            .collect()
    }

    pub fn preflight_restore(
        &self,
        submitted_recovery_key: &str,
        target_generation: u64,
    ) -> Result<RecoveryPreflight, ServiceError> {
        self.recovery.verify(submitted_recovery_key)?;
        let current_key = self.hsm.current()?;
        let previous_key = self
            .hsm
            .previous()?
            .ok_or_else(|| hsm_failure("HSM PREVIOUS key is unavailable"))?;
        let (selected, key, head) =
            self.resolve_backup(target_generation, &current_key, previous_key)?;
        validate_database(&selected, &key)?;
        Ok(RecoveryPreflight {
            target_generation,
            chain_length: head - target_generation + 1,
            sqlcipher_integrity_verified: true,
        })
    }

    pub fn restore_generation(
        &mut self,
        submitted_recovery_key: &str,
        target_generation: u64,
    ) -> Result<RestoreResult, ServiceError> {
        self.restore_generation_with_validation(
            submitted_recovery_key,
            target_generation,
            validate_database,
        )
    }

    fn restore_generation_with_validation<F>(
        &mut self,
        submitted_recovery_key: &str,
        target_generation: u64,
        final_validation: F,
    ) -> Result<RestoreResult, ServiceError>
    where
        F: FnOnce(&Path, &[u8; 32]) -> Result<(), ServiceError>,
    {
        self.recovery.verify(submitted_recovery_key)?;
        let current_key = self.hsm.current()?;
        let previous_key = self
            .hsm
            .previous()?
            .ok_or_else(|| hsm_failure("HSM PREVIOUS key is unavailable"))?;
        let (selected, key, _) =
            self.resolve_backup(target_generation, &current_key, previous_key)?;
        let candidate = self.database_path.with_extension("restore-candidate");
        if candidate.exists() {
            fs::remove_file(&candidate)
                .map_err(|_| database_failure("stale recovery candidate cannot be removed"))?;
        }
        fs::copy(&selected, &candidate)
            .map_err(|_| database_failure("selected backup cannot be copied"))?;
        let restored = open_sqlcipher(&candidate, &key)?;
        rekey(&restored, &current_key)?;
        let invalidated_sessions = invalidate_restored_sessions(&restored)?;
        validate_database(&candidate, &current_key)?;
        let preserved = self.database_path.with_extension("pre-recovery");
        if preserved.exists() {
            fs::remove_file(&preserved)
                .map_err(|_| database_failure("previous recovery image cannot be removed"))?;
        }
        fs::rename(&self.database_path, &preserved)
            .map_err(|_| database_failure("active database cannot be preserved"))?;
        if fs::rename(&candidate, &self.database_path).is_err() {
            let _ = fs::rename(&preserved, &self.database_path);
            return Err(database_failure("restored database cannot be activated"));
        }
        if let Err(error) = final_validation(&self.database_path, &current_key) {
            let failed = self.database_path.with_extension("failed-recovery");
            let _ = fs::remove_file(&failed);
            let _ = fs::rename(&self.database_path, &failed);
            if fs::rename(&preserved, &self.database_path).is_err() {
                return Err(database_failure(
                    "recovery rollback could not restore active database",
                ));
            }
            return Err(error);
        }
        Ok(RestoreResult {
            target_generation,
            invalidated_sessions,
            preserved_database: preserved,
        })
    }

    pub fn into_hsm(self) -> H {
        self.hsm
    }

    fn backup_path(&self, generation: u64) -> PathBuf {
        self.backup_directory
            .join(format!("autobricks-jwt-{generation:020}.db"))
    }

    fn resolve_backup(
        &self,
        target_generation: u64,
        current_key: &[u8; 32],
        previous_key: [u8; 32],
    ) -> Result<(PathBuf, [u8; 32], u64), ServiceError> {
        if target_generation == 0 {
            return Err(ServiceError::invalid_request(
                "target generation is invalid",
            ));
        }
        let active = open_sqlcipher(&self.database_path, current_key)?;
        let head = current_generation(&active)?;
        if target_generation > head {
            return Err(ServiceError::invalid_request(
                "target generation is unavailable",
            ));
        }
        let mut generation = head;
        let mut key = previous_key;
        let mut selected = self.backup_path(generation);
        loop {
            validate_database(&selected, &key)?;
            if generation == target_generation {
                return Ok((selected, key, head));
            }
            let opened = open_sqlcipher(&selected, &key)?;
            let preceding: Vec<u8> = opened
                .query_row(
                    "SELECT preceding_key FROM database_key_chain WHERE generation = ?1",
                    [generation - 1],
                    |row| row.get(0),
                )
                .map_err(|_| key_failure("backup key chain is incomplete"))?;
            key = preceding
                .try_into()
                .map_err(|_| key_failure("preceding database key is invalid"))?;
            generation -= 1;
            selected = self.backup_path(generation);
        }
    }
}

fn invalidate_restored_sessions(connection: &Connection) -> Result<usize, ServiceError> {
    let token_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='token_versions')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| database_failure("restored session schema cannot be inspected"))?;
    if !token_table_exists {
        return Ok(0);
    }
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| database_failure("restored session invalidation cannot start"))?;
    let invalidated = transaction
        .execute(
            "UPDATE token_versions SET status='REVOKED' WHERE status='ACTIVE'",
            [],
        )
        .map_err(|_| database_failure("restored sessions cannot be invalidated"))?;
    transaction
        .execute(
            "UPDATE token_keys SET status='REVOKED' WHERE status='ACTIVE'",
            [],
        )
        .map_err(|_| database_failure("restored token keys cannot be invalidated"))?;
    transaction
        .execute("DELETE FROM cache_cleanup_queue", [])
        .map_err(|_| database_failure("restored Cache state cannot be cleared"))?;
    transaction
        .commit()
        .map_err(|_| database_failure("restored session invalidation cannot be committed"))?;
    Ok(invalidated)
}

fn open_sqlcipher(path: &Path, key: &[u8; 32]) -> Result<Connection, ServiceError> {
    let connection = Connection::open(path)
        .map_err(|_| database_failure("SQLCipher database cannot be opened"))?;
    let key_hex = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    connection
        .execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))
        .map_err(|_| database_failure("SQLCipher key cannot be applied"))?;
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| database_failure("SQLCipher database key is invalid"))?;
    Ok(connection)
}

fn create_encrypted_backup(
    source: &Connection,
    path: &Path,
    key: &[u8; 32],
) -> Result<(), ServiceError> {
    let mut destination = open_sqlcipher(path, key)?;
    let backup = Backup::new(source, &mut destination)
        .map_err(|_| database_failure("SQLCipher backup cannot start"))?;
    backup
        .run_to_completion(64, std::time::Duration::from_millis(1), None)
        .map_err(|_| database_failure("SQLCipher backup did not complete"))
}

fn validate_database(path: &Path, key: &[u8; 32]) -> Result<(), ServiceError> {
    let connection = open_sqlcipher(path, key)?;
    let result: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| database_failure("SQLCipher integrity check failed"))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(database_failure("SQLCipher integrity check failed"))
    }
}

fn rekey(connection: &Connection, key: &[u8; 32]) -> Result<(), ServiceError> {
    let key_hex = key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    connection
        .execute_batch(&format!("PRAGMA rekey = \"x'{key_hex}'\";"))
        .map_err(|_| key_failure("SQLCipher rekey failed"))
}

fn current_generation(connection: &Connection) -> Result<u64, ServiceError> {
    let value: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(generation), 0) FROM database_key_chain",
            [],
            |row| row.get(0),
        )
        .map_err(|_| database_failure("database generation cannot be read"))?;
    u64::try_from(value).map_err(|_| database_failure("database generation is invalid"))
}

fn configuration(message: &'static str) -> ServiceError {
    ServiceError::configuration_invalid(message)
}
fn database_failure(message: &'static str) -> ServiceError {
    ServiceError::assigned(8081, message)
}
fn key_failure(message: &'static str) -> ServiceError {
    ServiceError::assigned(8086, message)
}
fn hsm_failure(message: &'static str) -> ServiceError {
    ServiceError::assigned(8085, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_authorization::GeneratedRecoveryKey;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    struct MemoryHsm {
        current: [u8; 32],
        previous: Option<[u8; 32]>,
        next: u8,
    }
    impl HsmDatabaseKeys for MemoryHsm {
        fn current(&self) -> Result<[u8; 32], ServiceError> {
            Ok(self.current)
        }
        fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
            Ok(self.previous)
        }
        fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
            self.next += 1;
            Ok([self.next; 32])
        }
        fn commit(&mut self, previous: [u8; 32], current: [u8; 32]) -> Result<(), ServiceError> {
            self.previous = Some(previous);
            self.current = current;
            Ok(())
        }
    }

    #[test]
    fn forced_backups_rotate_two_hsm_slots_and_restore_older_generation_by_chain() {
        let root = std::env::temp_dir().join(format!("ab-jwt-backup-{}", Uuid::new_v4()));
        let backups = root.join("backups");
        fs::create_dir(&root).unwrap();
        let database = root.join("jwt.db");
        let (recovery_key, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let hsm = MemoryHsm {
            current: [1; 32],
            previous: None,
            next: 1,
        };
        let mut manager =
            DatabaseProtectionManager::new(&database, &backups, hsm, verifier).unwrap();
        manager.initialize_schema().unwrap();
        let connection = open_sqlcipher(&database, &[1; 32]).unwrap();
        connection.execute_batch("CREATE TABLE protected_data(value TEXT); INSERT INTO protected_data VALUES('generation-0');").unwrap();
        drop(connection);
        let first = manager
            .force_backup_and_rotate(&recovery_key, 1_000)
            .unwrap();
        let connection = open_sqlcipher(&database, &[2; 32]).unwrap();
        connection
            .execute("UPDATE protected_data SET value='generation-1'", [])
            .unwrap();
        drop(connection);
        let second = manager
            .force_backup_and_rotate(&recovery_key, 2_000)
            .unwrap();
        let connection = open_sqlcipher(&database, &[3; 32]).unwrap();
        connection
            .execute("UPDATE protected_data SET value='generation-2'", [])
            .unwrap();
        drop(connection);
        let third = manager
            .force_backup_and_rotate(&recovery_key, 3_000)
            .unwrap();
        assert_eq!(
            (first.generation, second.generation, third.generation),
            (1, 2, 3)
        );
        let hsm = &manager.hsm;
        assert_eq!(hsm.current, [4; 32]);
        assert_eq!(hsm.previous, Some([3; 32]));
        manager.restore_generation(&recovery_key, 1).unwrap();
        let restored = open_sqlcipher(&database, &[4; 32]).unwrap();
        let value: String = restored
            .query_row("SELECT value FROM protected_data", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "generation-0");
        drop(restored);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_authorization_fails_before_backup_or_rotation() {
        let root = std::env::temp_dir().join(format!("ab-jwt-backup-auth-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let database = root.join("jwt.db");
        let (_, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let hsm = MemoryHsm {
            current: [1; 32],
            previous: None,
            next: 1,
        };
        let mut manager =
            DatabaseProtectionManager::new(&database, root.join("backups"), hsm, verifier).unwrap();
        manager.initialize_schema().unwrap();
        assert_eq!(
            manager
                .force_backup_and_rotate(&"00".repeat(32), 1_000)
                .unwrap_err()
                .code(),
            8001
        );
        assert!(fs::read_dir(root.join("backups")).unwrap().next().is_none());
        let hsm = manager.into_hsm();
        assert_eq!(hsm.current, [1; 32]);
        assert!(hsm.previous.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalogs_completed_recovery_points_and_preflights_the_selected_chain() {
        let root = std::env::temp_dir().join(format!("ab-jwt-catalog-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let database = root.join("jwt.db");
        let (recovery_key, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let hsm = MemoryHsm {
            current: [1; 32],
            previous: None,
            next: 1,
        };
        let mut manager =
            DatabaseProtectionManager::new(&database, root.join("backups"), hsm, verifier).unwrap();
        manager.initialize_schema().unwrap();
        manager
            .force_backup_and_rotate(&recovery_key, 1_000)
            .unwrap();
        manager
            .force_backup_and_rotate(&recovery_key, 2_000)
            .unwrap();

        let points = manager.recovery_points().unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].generation, 2);
        assert_eq!(points[0].completed_at, 2_000);
        assert_eq!(points[0].validation, BackupValidationState::Available);
        let preflight = manager.preflight_restore(&recovery_key, 1).unwrap();
        assert_eq!(preflight.target_generation, 1);
        assert_eq!(preflight.chain_length, 2);
        assert!(preflight.sqlcipher_integrity_verified);
        println!("RECOVERY_POINT_CATALOG=PASS");
        println!("RECOVERY_PREFLIGHT=PASS");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restoration_invalidates_every_restored_active_session_before_activation() {
        let root = std::env::temp_dir().join(format!("ab-jwt-invalidate-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let database = root.join("jwt.db");
        let (recovery_key, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let hsm = MemoryHsm {
            current: [1; 32],
            previous: None,
            next: 1,
        };
        let mut manager =
            DatabaseProtectionManager::new(&database, root.join("backups"), hsm, verifier).unwrap();
        manager.initialize_schema().unwrap();
        let connection = open_sqlcipher(&database, &[1; 32]).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE token_versions(token_id TEXT, status TEXT);
             CREATE TABLE token_keys(token_id TEXT, status TEXT);
             CREATE TABLE cache_cleanup_queue(token_id TEXT);
             INSERT INTO token_versions VALUES('active-token', 'ACTIVE');
             INSERT INTO token_versions VALUES('revoked-token', 'REVOKED');
             INSERT INTO token_keys VALUES('active-token', 'ACTIVE');
             INSERT INTO cache_cleanup_queue VALUES('active-token');",
            )
            .unwrap();
        drop(connection);
        manager
            .force_backup_and_rotate(&recovery_key, 1_000)
            .unwrap();
        let result = manager.restore_generation(&recovery_key, 1).unwrap();
        assert_eq!(result.invalidated_sessions, 1);
        assert!(result.preserved_database.is_file());
        let restored = open_sqlcipher(&database, &[2; 32]).unwrap();
        let active_versions: i64 = restored
            .query_row(
                "SELECT COUNT(*) FROM token_versions WHERE status='ACTIVE'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let active_keys: i64 = restored
            .query_row(
                "SELECT COUNT(*) FROM token_keys WHERE status='ACTIVE'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let queued: i64 = restored
            .query_row("SELECT COUNT(*) FROM cache_cleanup_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((active_versions, active_keys, queued), (0, 0, 0));
        println!("RECOVERY_ATOMIC_ACTIVATION=PASS");
        println!("RECOVERY_SESSION_INVALIDATION=PASS");
        println!("RECOVERY_REACTIVATION_PREVENTION=PASS");
        drop(restored);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_final_recovery_validation_restores_original_database_and_hsm_slots() {
        let root = std::env::temp_dir().join(format!("ab-jwt-rollback-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let database = root.join("jwt.db");
        let (recovery_key, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let hsm = MemoryHsm {
            current: [1; 32],
            previous: None,
            next: 1,
        };
        let mut manager =
            DatabaseProtectionManager::new(&database, root.join("backups"), hsm, verifier).unwrap();
        manager.initialize_schema().unwrap();
        let connection = open_sqlcipher(&database, &[1; 32]).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE protected_data(value TEXT);
                 INSERT INTO protected_data VALUES('original-zero');",
            )
            .unwrap();
        drop(connection);
        manager
            .force_backup_and_rotate(&recovery_key, 1_000)
            .unwrap();
        let connection = open_sqlcipher(&database, &[2; 32]).unwrap();
        connection
            .execute("UPDATE protected_data SET value='original-one'", [])
            .unwrap();
        drop(connection);
        manager
            .force_backup_and_rotate(&recovery_key, 2_000)
            .unwrap();
        let current_before = manager.hsm.current;
        let previous_before = manager.hsm.previous;
        let error = manager
            .restore_generation_with_validation(&recovery_key, 1, |_, _| {
                Err(database_failure("injected final integrity failure"))
            })
            .unwrap_err();
        assert_eq!(error.code(), 8081);
        assert_eq!(manager.hsm.current, current_before);
        assert_eq!(manager.hsm.previous, previous_before);
        let original = open_sqlcipher(&database, &current_before).unwrap();
        let value: String = original
            .query_row("SELECT value FROM protected_data", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "original-one");
        drop(original);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_hsm_provider_uses_current_previous_generate_and_atomic_commit() {
        let root = std::env::temp_dir().join(format!("ab-jwt-hsm-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let helper = root.join("hsm-helper");
        fs::write(
            &helper,
            "#!/bin/sh\nread request\ncase \"$request\" in\n*'\"operation\":\"READ\"'*'\"slot\":\"CURRENT\"'*) printf '{\"key_hex\":\"%064d\"}\\n' 0;;\n*'\"operation\":\"READ\"'*'\"slot\":\"PREVIOUS\"'*) printf '{\"present\":false}\\n';;\n*'\"operation\":\"GENERATE\"'*) printf '{\"key_hex\":\"1111111111111111111111111111111111111111111111111111111111111111\"}\\n';;\n*'\"operation\":\"COMMIT_TWO_SLOTS\"'*) printf '{\"committed\":true}\\n';;\n*) exit 9;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();

        let mut hsm = CommandHsmDatabaseKeys::new(&helper, "autobricks-jwt/database").unwrap();
        assert_eq!(hsm.current().unwrap(), [0; 32]);
        assert_eq!(hsm.previous().unwrap(), None);
        let next = hsm.generate_next().unwrap();
        assert_eq!(next, [0x11; 32]);
        hsm.commit([0; 32], next).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

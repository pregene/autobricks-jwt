use std::{
    path::{Path, PathBuf},
    process::Command,
};

use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

type HandoverRow = (String, String, String, String, Vec<u8>, i64, Option<i64>);

use crate::{service_error::ServiceError, service_registry::OperationClass};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateMetadata {
    pub fingerprint: String,
    pub uri_sans: Vec<String>,
    pub ocsp_url: String,
    pub not_before: String,
    pub not_after: String,
    pub client_auth: bool,
}

pub struct CertificateTools {
    openssl: PathBuf,
    abpki_cli: PathBuf,
    ocsp_responder_override: Option<String>,
}

pub struct ServiceCertificateRepository {
    connection: Connection,
}

#[derive(Debug)]
pub struct CertificateHandover {
    pub pending_certificate_id: Uuid,
    pub registration_key: String,
    pub expires_at: u64,
}

impl CertificateTools {
    pub fn new(openssl: impl Into<PathBuf>, abpki_cli: impl Into<PathBuf>) -> Self {
        Self {
            openssl: openssl.into(),
            abpki_cli: abpki_cli.into(),
            ocsp_responder_override: None,
        }
    }

    pub fn with_ocsp_responder_override(mut self, url: impl Into<String>) -> Self {
        self.ocsp_responder_override = Some(url.into());
        self
    }

    pub fn inspect(&self, certificate: &Path) -> Result<CertificateMetadata, ServiceError> {
        let fingerprint = self.openssl(certificate, &["-fingerprint", "-sha256"])?;
        let fingerprint = fingerprint
            .split_once('=')
            .map(|(_, value)| value)
            .ok_or_else(|| classified(8011, "certificate fingerprint is invalid"))?
            .trim()
            .replace(':', "")
            .to_ascii_lowercase();
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err(classified(8011, "certificate fingerprint is invalid"));
        }
        let san = self.openssl(certificate, &["-ext", "subjectAltName"])?;
        let uri_sans = san
            .split(|character: char| character == ',' || character.is_whitespace())
            .filter_map(|part| part.strip_prefix("URI:").map(str::to_owned))
            .collect::<Vec<_>>();
        let ocsp_url = self.openssl(certificate, &["-ocsp_uri"])?;
        let ocsp_url = ocsp_url.trim().to_owned();
        if !(ocsp_url.starts_with("https://") || ocsp_url.starts_with("http://")) {
            return Err(classified(8014, "certificate AIA OCSP URL is missing"));
        }
        let dates = self.openssl(certificate, &["-dates"])?;
        let not_before = dates
            .lines()
            .find_map(|line| line.strip_prefix("notBefore="))
            .ok_or_else(|| classified(8012, "certificate notBefore is missing"))?
            .to_owned();
        let not_after = dates
            .lines()
            .find_map(|line| line.strip_prefix("notAfter="))
            .ok_or_else(|| classified(8012, "certificate notAfter is missing"))?
            .to_owned();
        let purpose = self.openssl(certificate, &["-purpose"])?;
        let client_auth = purpose
            .lines()
            .any(|line| line.trim() == "SSL client : Yes");
        if !client_auth {
            return Err(classified(
                8013,
                "certificate client-auth purpose is invalid",
            ));
        }
        let valid = Command::new(&self.openssl)
            .args(["x509", "-in"])
            .arg(certificate)
            .args(["-noout", "-checkend", "0"])
            .status()
            .map_err(|_| classified(8012, "certificate validity cannot be checked"))?;
        if !valid.success() {
            return Err(classified(8012, "certificate is outside its valid time"));
        }
        Ok(CertificateMetadata {
            fingerprint,
            uri_sans,
            ocsp_url,
            not_before,
            not_after,
            client_auth,
        })
    }

    pub fn require_ocsp_good(&self, fingerprint: &str) -> Result<(), ServiceError> {
        let output = Command::new(&self.abpki_cli)
            .arg("check")
            .arg(fingerprint)
            .output()
            .map_err(|_| classified(8015, "OCSP status cannot be obtained"))?;
        if !output.status.success() {
            return Err(classified(8015, "OCSP status cannot be obtained"));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let status = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| {
                value
                    .get("status")
                    .and_then(|status| status.as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| text.trim().to_owned())
            .to_ascii_uppercase();
        match status.as_str() {
            "GOOD" => Ok(()),
            "REVOKED" => Err(classified(8017, "certificate is revoked")),
            "UNKNOWN" => Err(classified(8018, "certificate status is unknown")),
            _ => Err(classified(8016, "OCSP response is invalid")),
        }
    }

    pub fn require_aia_ocsp_good(
        &self,
        certificate: &Path,
        issuer_chain: &Path,
        metadata: &CertificateMetadata,
    ) -> Result<(), ServiceError> {
        if metadata.ocsp_url.is_empty() {
            return Err(classified(8014, "certificate AIA OCSP URL is missing"));
        }
        let responder = self
            .ocsp_responder_override
            .as_deref()
            .unwrap_or(&metadata.ocsp_url);
        let mut command = Command::new(&self.openssl);
        command
            .arg("ocsp")
            .arg("-issuer")
            .arg(issuer_chain)
            .arg("-cert")
            .arg(certificate)
            .arg("-url")
            .arg(responder);
        if self.ocsp_responder_override.is_some()
            && let Some(host) = url_authority(&metadata.ocsp_url)
        {
            command.arg("-header").arg(format!("Host={host}"));
        }
        let output = command
            .arg("-CAfile")
            .arg(issuer_chain)
            .arg("-no_nonce")
            .output()
            .map_err(|_| classified(8015, "OCSP status cannot be obtained"))?;
        if !output.status.success() {
            return Err(classified(8015, "OCSP status cannot be obtained"));
        }
        let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        if stdout.contains(": good") {
            Ok(())
        } else if stdout.contains(": revoked") {
            Err(classified(8017, "certificate is revoked"))
        } else if stdout.contains(": unknown") {
            Err(classified(8018, "certificate status is unknown"))
        } else {
            Err(classified(8016, "OCSP response is invalid"))
        }
    }

    fn openssl(&self, certificate: &Path, arguments: &[&str]) -> Result<String, ServiceError> {
        let output = Command::new(&self.openssl)
            .args(["x509", "-in"])
            .arg(certificate)
            .arg("-noout")
            .args(arguments)
            .output()
            .map_err(|_| classified(8011, "certificate cannot be inspected"))?;
        if !output.status.success() {
            return Err(classified(8011, "certificate cannot be inspected"));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| classified(8011, "certificate output is invalid"))
    }
}

fn url_authority(url: &str) -> Option<&str> {
    url.split_once("://")?.1.split('/').next()
}

impl ServiceCertificateRepository {
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, ServiceError> {
        let connection = Connection::open(path).map_err(database_error)?;
        let key = key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        connection
            .execute_batch(&format!("PRAGMA key = \"x'{key}'\";"))
            .map_err(database_error)?;
        let version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(database_error)?;
        if version.is_empty() {
            return Err(classified(8084, "SQLCipher key store is unavailable"));
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS service_certificates (
                certificate_id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                operation_class TEXT NOT NULL CHECK(operation_class IN ('READ','WRITE')),
                uri_san TEXT NOT NULL,
                ocsp_url TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('ACTIVE','PENDING','RETIRED'))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_certificate_per_service
              ON service_certificates(service_id) WHERE status = 'ACTIVE';
            CREATE UNIQUE INDEX IF NOT EXISTS one_pending_certificate_per_service
              ON service_certificates(service_id) WHERE status = 'PENDING';
            CREATE TABLE IF NOT EXISTS certificate_handovers (
                request_id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                client_id TEXT NOT NULL,
                operation_class TEXT NOT NULL,
                active_fingerprint TEXT NOT NULL,
                pending_fingerprint TEXT NOT NULL UNIQUE,
                key_verifier BLOB NOT NULL CHECK(length(key_verifier) = 32),
                expires_at INTEGER NOT NULL,
                consumed_at INTEGER
            );",
            )
            .map_err(database_error)?;
        Ok(Self { connection })
    }

    pub fn register(
        &mut self,
        service_id: Uuid,
        client_id: Uuid,
        operation: OperationClass,
        metadata: &CertificateMetadata,
    ) -> Result<Uuid, ServiceError> {
        let expected = expected_uri(operation);
        if metadata.uri_sans.len() != 1 || metadata.uri_sans[0] != expected {
            return Err(classified(8021, "certificate URI SAN is invalid"));
        }
        if !metadata.client_auth {
            return Err(classified(8013, "certificate purpose is invalid"));
        }
        let certificate_id = Uuid::new_v4();
        self.connection
            .execute(
                "INSERT INTO service_certificates (
                certificate_id, service_id, client_id, fingerprint, operation_class,
                uri_san, ocsp_url, not_before, not_after, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'ACTIVE')",
                params![
                    certificate_id.to_string(),
                    service_id.to_string(),
                    client_id.to_string(),
                    metadata.fingerprint,
                    operation_name(operation),
                    expected,
                    metadata.ocsp_url,
                    metadata.not_before,
                    metadata.not_after
                ],
            )
            .map_err(database_error)?;
        Ok(certificate_id)
    }

    pub fn authorize(
        &self,
        service_id: Uuid,
        client_id: Uuid,
        operation: OperationClass,
        fingerprint: &str,
    ) -> Result<(), ServiceError> {
        let binding: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT service_id, client_id, operation_class FROM service_certificates
              WHERE fingerprint = ?1 AND status = 'ACTIVE'",
                [fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(database_error)?;
        match binding {
            Some((stored_service, stored_client, stored_operation))
                if stored_service == service_id.to_string()
                    && stored_client == client_id.to_string()
                    && stored_operation == operation_name(operation) =>
            {
                Ok(())
            }
            Some(_) => Err(classified(
                8028,
                "certificate service binding does not match",
            )),
            None => Err(classified(8019, "certificate is not registered")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_handover(
        &mut self,
        service_id: Uuid,
        client_id: Uuid,
        operation: OperationClass,
        active_fingerprint: &str,
        request_id: Uuid,
        replacement: &CertificateMetadata,
        now: u64,
        timeout_seconds: u64,
    ) -> Result<CertificateHandover, ServiceError> {
        if timeout_seconds == 0
            || replacement.uri_sans.as_slice() != [expected_uri(operation)]
            || !replacement.client_auth
        {
            return Err(classified(8027, "certificate handover request is invalid"));
        }
        self.authorize(service_id, client_id, operation, active_fingerprint)?;
        let expires_at = now
            .checked_add(timeout_seconds)
            .ok_or_else(|| classified(8027, "certificate handover expiration is invalid"))?;
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key)
            .map_err(|_| classified(8029, "certificate handover key generation failed"))?;
        let registration_key = key.iter().map(|byte| format!("{byte:02x}")).collect();
        let verifier = digest(&SHA256, &key);
        key.fill(0);
        let pending_certificate_id = Uuid::new_v4();
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO service_certificates (
                    certificate_id, service_id, client_id, fingerprint, operation_class,
                    uri_san, ocsp_url, not_before, not_after, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'PENDING')",
                params![
                    pending_certificate_id.to_string(),
                    service_id.to_string(),
                    client_id.to_string(),
                    replacement.fingerprint,
                    operation_name(operation),
                    expected_uri(operation),
                    replacement.ocsp_url,
                    replacement.not_before,
                    replacement.not_after,
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO certificate_handovers (
                    request_id, service_id, client_id, operation_class,
                    active_fingerprint, pending_fingerprint, key_verifier, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    request_id.to_string(),
                    service_id.to_string(),
                    client_id.to_string(),
                    operation_name(operation),
                    active_fingerprint,
                    replacement.fingerprint,
                    verifier.as_ref(),
                    i64::try_from(expires_at)
                        .map_err(|_| classified(8027, "handover expiration is invalid"))?,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(CertificateHandover {
            pending_certificate_id,
            registration_key,
            expires_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn activate_handover(
        &mut self,
        service_id: Uuid,
        client_id: Uuid,
        operation: OperationClass,
        request_id: Uuid,
        pending_fingerprint: &str,
        registration_key: &str,
        now: u64,
    ) -> Result<(), ServiceError> {
        let submitted = decode_key(registration_key)
            .ok_or_else(|| classified(8027, "certificate registration key is invalid"))?;
        let row: Option<HandoverRow> = self
            .connection
            .query_row(
                "SELECT service_id, client_id, operation_class, pending_fingerprint,
                        key_verifier, expires_at, consumed_at
                   FROM certificate_handovers WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((
            stored_service,
            stored_client,
            stored_operation,
            stored_pending,
            verifier,
            expires_at,
            consumed_at,
        )) = row
        else {
            return Err(classified(8027, "certificate registration key is invalid"));
        };
        let candidate = digest(&SHA256, &submitted);
        let key_matches = constant_time_equal(&verifier, candidate.as_ref());
        if stored_service != service_id.to_string()
            || stored_client != client_id.to_string()
            || stored_operation != operation_name(operation)
            || stored_pending != pending_fingerprint
            || consumed_at.is_some()
            || i64::try_from(now).unwrap_or(i64::MAX) >= expires_at
            || !key_matches
        {
            return Err(classified(8027, "certificate registration key is invalid"));
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        let retired = transaction
            .execute(
                "UPDATE service_certificates SET status = 'RETIRED'
                   WHERE service_id = ?1 AND status = 'ACTIVE'",
                [service_id.to_string()],
            )
            .map_err(database_error)?;
        let activated = transaction
            .execute(
                "UPDATE service_certificates SET status = 'ACTIVE'
                   WHERE service_id = ?1 AND fingerprint = ?2 AND status = 'PENDING'",
                params![service_id.to_string(), pending_fingerprint],
            )
            .map_err(database_error)?;
        let consumed = transaction
            .execute(
                "UPDATE certificate_handovers SET consumed_at = ?2
                   WHERE request_id = ?1 AND consumed_at IS NULL",
                params![
                    request_id.to_string(),
                    i64::try_from(now).unwrap_or(i64::MAX)
                ],
            )
            .map_err(database_error)?;
        if (retired, activated, consumed) != (1, 1, 1) {
            return Err(classified(8029, "certificate handover failed"));
        }
        transaction.commit().map_err(database_error)
    }
}

fn decode_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn constant_time_equal(expected: &[u8], actual: &[u8]) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn expected_uri(operation: OperationClass) -> &'static str {
    match operation {
        OperationClass::Read => "urn:autobricks:jwt:read",
        OperationClass::Write => "urn:autobricks:jwt:write",
    }
}
fn operation_name(operation: OperationClass) -> &'static str {
    match operation {
        OperationClass::Read => "READ",
        OperationClass::Write => "WRITE",
    }
}
fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}
fn database_error(_: impl std::fmt::Display) -> ServiceError {
    classified(8081, "certificate database operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn metadata(uri: &str) -> CertificateMetadata {
        CertificateMetadata {
            fingerprint: "a".repeat(64),
            uri_sans: vec![uri.into()],
            ocsp_url: "https://pki.example/ocsp".into(),
            not_before: "before".into(),
            not_after: "after".into(),
            client_auth: true,
        }
    }

    fn replacement(uri: &str) -> CertificateMetadata {
        CertificateMetadata {
            fingerprint: "b".repeat(64),
            uri_sans: vec![uri.into()],
            ocsp_url: "https://pki.example/ocsp".into(),
            not_before: "replacement-before".into(),
            not_after: "replacement-after".into(),
            client_auth: true,
        }
    }

    #[test]
    fn persists_and_enforces_fingerprint_service_and_uri_binding() {
        let path = std::env::temp_dir().join(format!("ab-jwt-cert-{}.db", Uuid::new_v4()));
        let mut repository = ServiceCertificateRepository::open(&path, &[0xe1; 32]).unwrap();
        let service_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        repository
            .register(
                service_id,
                client_id,
                OperationClass::Write,
                &metadata("urn:autobricks:jwt:write"),
            )
            .unwrap();
        repository
            .authorize(
                service_id,
                client_id,
                OperationClass::Write,
                &"a".repeat(64),
            )
            .unwrap();
        assert_eq!(
            repository
                .authorize(
                    Uuid::new_v4(),
                    client_id,
                    OperationClass::Write,
                    &"a".repeat(64)
                )
                .unwrap_err()
                .code(),
            8028
        );
        assert_eq!(
            repository
                .authorize(
                    service_id,
                    client_id,
                    OperationClass::Write,
                    &"b".repeat(64)
                )
                .unwrap_err()
                .code(),
            8019
        );
        assert_eq!(
            repository
                .register(
                    service_id,
                    client_id,
                    OperationClass::Read,
                    &metadata("urn:autobricks:jwt:write")
                )
                .unwrap_err()
                .code(),
            8021
        );
        drop(repository);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn atomically_hands_over_one_service_fingerprint_with_single_use_key() {
        let path = std::env::temp_dir().join(format!("ab-jwt-cert-handover-{}.db", Uuid::new_v4()));
        let mut repository = ServiceCertificateRepository::open(&path, &[0xe2; 32]).unwrap();
        let service_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let current = metadata("urn:autobricks:jwt:write");
        repository
            .register(service_id, client_id, OperationClass::Write, &current)
            .unwrap();
        let request_id = Uuid::new_v4();
        let next = replacement("urn:autobricks:jwt:write");
        let handover = repository
            .begin_handover(
                service_id,
                client_id,
                OperationClass::Write,
                &current.fingerprint,
                request_id,
                &next,
                1_000,
                300,
            )
            .unwrap();
        repository
            .authorize(
                service_id,
                client_id,
                OperationClass::Write,
                &current.fingerprint,
            )
            .unwrap();
        assert_eq!(
            repository
                .authorize(
                    service_id,
                    client_id,
                    OperationClass::Write,
                    &next.fingerprint,
                )
                .unwrap_err()
                .code(),
            8019
        );
        repository
            .activate_handover(
                service_id,
                client_id,
                OperationClass::Write,
                request_id,
                &next.fingerprint,
                &handover.registration_key,
                1_100,
            )
            .unwrap();
        repository
            .authorize(
                service_id,
                client_id,
                OperationClass::Write,
                &next.fingerprint,
            )
            .unwrap();
        assert_eq!(
            repository
                .authorize(
                    service_id,
                    client_id,
                    OperationClass::Write,
                    &current.fingerprint,
                )
                .unwrap_err()
                .code(),
            8019
        );
        assert_eq!(
            repository
                .activate_handover(
                    service_id,
                    client_id,
                    OperationClass::Write,
                    request_id,
                    &next.fingerprint,
                    &handover.registration_key,
                    1_101,
                )
                .unwrap_err()
                .code(),
            8027
        );
        drop(repository);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_wrong_expired_or_mismatched_handover_proof_without_retiring_active() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-cert-handover-fail-{}.db", Uuid::new_v4()));
        let mut repository = ServiceCertificateRepository::open(&path, &[0xe3; 32]).unwrap();
        let service_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let current = metadata("urn:autobricks:jwt:read");
        repository
            .register(service_id, client_id, OperationClass::Read, &current)
            .unwrap();
        let request_id = Uuid::new_v4();
        let next = replacement("urn:autobricks:jwt:read");
        let handover = repository
            .begin_handover(
                service_id,
                client_id,
                OperationClass::Read,
                &current.fingerprint,
                request_id,
                &next,
                1_000,
                10,
            )
            .unwrap();
        for (key, now) in [("00".repeat(32), 1_005), (handover.registration_key, 1_010)] {
            assert_eq!(
                repository
                    .activate_handover(
                        service_id,
                        client_id,
                        OperationClass::Read,
                        request_id,
                        &next.fingerprint,
                        &key,
                        now,
                    )
                    .unwrap_err()
                    .code(),
                8027
            );
        }
        repository
            .authorize(
                service_id,
                client_id,
                OperationClass::Read,
                &current.fingerprint,
            )
            .unwrap();
        drop(repository);
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "requires installed OpenSSL, abpki-cli, and enrolled test certificate"]
    fn inspects_enrolled_certificate_and_requires_live_ocsp_good() {
        let certificate =
            PathBuf::from(std::env::var("AUTOBRICKS_JWT_TEST_CLIENT_CERTIFICATE").unwrap());
        let issuer_chain = PathBuf::from(std::env::var("AUTOBRICKS_JWT_TEST_TRUST_CHAIN").unwrap());
        let openssl =
            std::env::var("AUTOBRICKS_JWT_TEST_OPENSSL").unwrap_or_else(|_| "openssl".to_string());
        let abpki_cli = std::env::var("AUTOBRICKS_JWT_TEST_ABPKI_CLI")
            .unwrap_or_else(|_| "abpki-cli".to_string());
        let ocsp_responder = std::env::var("AUTOBRICKS_JWT_TEST_OCSP_RESPONDER_OVERRIDE").unwrap();
        let tools =
            CertificateTools::new(openssl, abpki_cli).with_ocsp_responder_override(ocsp_responder);
        let metadata = tools.inspect(&certificate).unwrap();
        assert_eq!(metadata.uri_sans, ["urn:autobricks:jwt:write"]);
        tools
            .require_aia_ocsp_good(&certificate, &issuer_chain, &metadata)
            .unwrap();
        println!("Certificate fingerprint registration: verified");
        println!("Certificate URI SAN: WRITE");
        println!("Certificate client-auth purpose and current validity: verified");
        println!("Certificate AIA OCSP status: GOOD");
    }
}

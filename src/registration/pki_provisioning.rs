use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::service_certificate::{CertificateMetadata, CertificateTools};
use crate::{service_error::ServiceError, service_registry::OperationClass};

const MAX_CERTIFICATE_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct PkiCreateRequest<'a> {
    issuer: &'a str,
    profile: PkiClientProfile<'a>,
}

#[derive(Debug, Serialize)]
struct PkiClientProfile<'a> {
    kind: &'static str,
    common_name: &'a str,
    uri_sans: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct PkiCreateResponse {
    certificate: PkiCertificate,
}

#[derive(Debug, Deserialize)]
struct PkiCertificate {
    fingerprint: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct ProvisionedCertificate {
    pub fingerprint: String,
    pub uri_san: String,
    pub download_file: PathBuf,
}

#[derive(Debug)]
pub struct VerifiedCertificatePackage {
    pub fingerprint: String,
    pub uri_san: String,
    pub metadata: CertificateMetadata,
    pub archive_name: String,
    pub archive: Vec<u8>,
}

pub struct PkiProvisioner {
    executable: PathBuf,
    issuer: String,
}

impl PkiProvisioner {
    pub fn new(executable: impl Into<PathBuf>, issuer: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            issuer: issuer.into(),
        }
    }

    pub fn provision_client(
        &self,
        common_name: &str,
        operation: OperationClass,
        invocation_directory: &Path,
    ) -> Result<ProvisionedCertificate, ServiceError> {
        validate_name(common_name)?;
        if !invocation_directory.is_absolute() || !invocation_directory.is_dir() {
            return Err(ServiceError::configuration_invalid(
                "certificate download directory is invalid",
            ));
        }
        let mode = fs::metadata(invocation_directory)
            .map_err(|_| provisioning_failed())?
            .mode();
        if mode & 0o077 != 0 {
            return Err(ServiceError::configuration_invalid(
                "certificate staging directory permits unauthorized access",
            ));
        }
        let uri_san = match operation {
            OperationClass::Read => "urn:autobricks:jwt:read",
            OperationClass::Write => "urn:autobricks:jwt:write",
        };
        let request = serde_json::to_vec(&PkiCreateRequest {
            issuer: &self.issuer,
            profile: PkiClientProfile {
                kind: "client",
                common_name,
                uri_sans: vec![uri_san],
            },
        })
        .map_err(|_| provisioning_failed())?;
        let mut child = Command::new(&self.executable)
            .arg("create")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| provisioning_failed())?;
        child
            .stdin
            .take()
            .ok_or_else(provisioning_failed)?
            .write_all(&request)
            .map_err(|_| provisioning_failed())?;
        let output = child
            .wait_with_output()
            .map_err(|_| provisioning_failed())?;
        if !output.status.success() {
            return Err(provisioning_failed());
        }
        let response: PkiCreateResponse =
            serde_json::from_slice(&output.stdout).map_err(|_| provisioning_failed())?;
        if !valid_fingerprint(&response.certificate.fingerprint) {
            return Err(provisioning_failed());
        }
        let target = invocation_directory.join(common_name);
        let status = Command::new(&self.executable)
            .arg("download")
            .arg(&response.certificate.fingerprint)
            .arg(&target)
            .current_dir(invocation_directory)
            .status()
            .map_err(|_| provisioning_failed())?;
        let download_file = target.with_extension("tar.gz");
        if !status.success() || !download_file.is_file() {
            return Err(provisioning_failed());
        }
        Ok(ProvisionedCertificate {
            fingerprint: response.certificate.fingerprint,
            uri_san: uri_san.into(),
            download_file,
        })
    }

    pub fn provision_and_verify_client(
        &self,
        common_name: &str,
        operation: OperationClass,
        staging_directory: &Path,
        tools: &CertificateTools,
    ) -> Result<VerifiedCertificatePackage, ServiceError> {
        let provisioned = self.provision_client(common_name, operation, staging_directory)?;
        let result = verify_downloaded_package(&provisioned, staging_directory, tools);
        let _ = fs::remove_file(&provisioned.download_file);
        result
    }
}

fn verify_downloaded_package(
    provisioned: &ProvisionedCertificate,
    staging_directory: &Path,
    tools: &CertificateTools,
) -> Result<VerifiedCertificatePackage, ServiceError> {
    let archive = fs::read(&provisioned.download_file).map_err(|_| provisioning_failed())?;
    if archive.is_empty() || archive.len() > MAX_CERTIFICATE_ARCHIVE_BYTES {
        return Err(provisioning_failed());
    }
    let members = read_safe_tar_gz(&archive)?;
    let certificate_bytes = members
        .get("certificate.pem")
        .ok_or_else(provisioning_failed)?;
    let private_key_bytes = members
        .get("private-key.pem")
        .ok_or_else(provisioning_failed)?;
    let trust_chain_bytes = members.get("trust-chain").ok_or_else(provisioning_failed)?;

    let certificate =
        openssl::x509::X509::from_pem(certificate_bytes).map_err(|_| provisioning_failed())?;
    let private_key = openssl::pkey::PKey::private_key_from_pem(private_key_bytes)
        .map_err(|_| provisioning_failed())?;
    let public_key = certificate
        .public_key()
        .map_err(|_| provisioning_failed())?;
    if !public_key.public_eq(&private_key) {
        return Err(provisioning_failed());
    }

    let extraction = staging_directory.join(format!("verify-{}", uuid::Uuid::new_v4()));
    let mut builder = fs::DirBuilder::new();
    builder
        .mode(0o700)
        .create(&extraction)
        .map_err(|_| provisioning_failed())?;
    let verification = (|| {
        let certificate_path = extraction.join("certificate.pem");
        let private_key_path = extraction.join("private-key.pem");
        let trust_chain_path = extraction.join("trust-chain");
        write_secret(&certificate_path, certificate_bytes)?;
        write_secret(&private_key_path, private_key_bytes)?;
        write_secret(&trust_chain_path, trust_chain_bytes)?;
        tools.require_trusted_chain(&certificate_path, &trust_chain_path)?;
        let metadata = tools.inspect(&certificate_path)?;
        if metadata.fingerprint != provisioned.fingerprint
            || metadata.uri_sans.as_slice() != [provisioned.uri_san.as_str()]
        {
            return Err(provisioning_failed());
        }
        tools.require_aia_ocsp_good(&certificate_path, &trust_chain_path, &metadata)?;
        Ok(metadata)
    })();
    let _ = fs::remove_dir_all(&extraction);
    let metadata = verification?;
    Ok(VerifiedCertificatePackage {
        fingerprint: provisioned.fingerprint.clone(),
        uri_san: provisioned.uri_san.clone(),
        metadata,
        archive_name: provisioned
            .download_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(provisioning_failed)?
            .to_owned(),
        archive,
    })
}

fn write_secret(path: &Path, value: &[u8]) -> Result<(), ServiceError> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| provisioning_failed())?;
    file.write_all(value).map_err(|_| provisioning_failed())
}

fn read_safe_tar_gz(value: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ServiceError> {
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(value)
        .take((MAX_CERTIFICATE_ARCHIVE_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| provisioning_failed())?;
    if decoded.len() > MAX_CERTIFICATE_ARCHIVE_BYTES {
        return Err(provisioning_failed());
    }
    let mut offset = 0usize;
    let mut members = BTreeMap::new();
    while offset + 512 <= decoded.len() {
        let header = &decoded[offset..offset + 512];
        offset += 512;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let expected_checksum = usize::from_str_radix(field(&header[148..156])?.trim(), 8)
            .map_err(|_| provisioning_failed())?;
        let actual_checksum = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    b' ' as usize
                } else {
                    *byte as usize
                }
            })
            .sum::<usize>();
        if expected_checksum != actual_checksum {
            return Err(provisioning_failed());
        }
        let name = field(&header[0..100])?;
        let name = name.strip_prefix("./").unwrap_or(&name);
        if !matches!(name, "certificate.pem" | "private-key.pem" | "trust-chain")
            || header[156] != b'0' && header[156] != 0
        {
            return Err(provisioning_failed());
        }
        let size_text = field(&header[124..136])?;
        let size = usize::from_str_radix(size_text.trim(), 8).map_err(|_| provisioning_failed())?;
        let end = offset.checked_add(size).ok_or_else(provisioning_failed)?;
        if end > decoded.len()
            || members
                .insert(name.to_owned(), decoded[offset..end].to_vec())
                .is_some()
        {
            return Err(provisioning_failed());
        }
        offset = end
            .checked_add((512 - size % 512) % 512)
            .ok_or_else(provisioning_failed)?;
    }
    if members.len() != 3 {
        return Err(provisioning_failed());
    }
    Ok(members)
}

fn field(value: &[u8]) -> Result<String, ServiceError> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..end])
        .map(str::to_owned)
        .map_err(|_| provisioning_failed())
}

fn validate_name(value: &str) -> Result<(), ServiceError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ServiceError::invalid_request(
            "certificate common name is invalid",
        ));
    }
    Ok(())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn provisioning_failed() -> ServiceError {
    ServiceError::assigned(8044, "service certificate provisioning failed")
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use uuid::Uuid;

    use super::*;

    #[test]
    fn issues_exact_operation_uri_and_downloads_to_invocation_directory() {
        let root = std::env::temp_dir().join(format!("ab-jwt-pki-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = root.join("fake-abpki-cli");
        fs::write(
            &executable,
            "#!/bin/sh\nif [ \"$1\" = create ]; then input=$(cat); printf '%s' \"$input\" > \"$ABPKI_CAPTURE\"; printf '{\"certificate\":{\"fingerprint\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}'; exit 0; fi\nif [ \"$1\" = download ]; then : > \"$3.tar.gz\"; exit 0; fi\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let capture = root.join("request.json");
        unsafe { std::env::set_var("ABPKI_CAPTURE", &capture) };
        let result = PkiProvisioner::new(&executable, "configured-issuer")
            .provision_client("web_service_write", OperationClass::Write, &root)
            .unwrap();
        assert_eq!(result.uri_san, "urn:autobricks:jwt:write");
        assert_eq!(result.download_file, root.join("web_service_write.tar.gz"));
        let request: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&capture).unwrap()).unwrap();
        assert_eq!(request["profile"]["kind"], "client");
        assert_eq!(
            request["profile"]["uri_sans"],
            serde_json::json!(["urn:autobricks:jwt:write"])
        );
        assert!(!request.to_string().contains("urn:autobricks:jwt:read"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_target_and_failed_or_malformed_pki_output() {
        let root = std::env::temp_dir().join(format!("ab-jwt-pki-fail-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = root.join("false-cli");
        fs::write(&executable, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let provisioner = PkiProvisioner::new(&executable, "configured-issuer");
        assert_eq!(
            provisioner
                .provision_client("../escape", OperationClass::Read, &root)
                .unwrap_err()
                .code(),
            8001
        );
        assert_eq!(
            provisioner
                .provision_client("safe-name", OperationClass::Read, &root)
                .unwrap_err()
                .code(),
            8044
        );
        fs::remove_dir_all(root).unwrap();
    }
}

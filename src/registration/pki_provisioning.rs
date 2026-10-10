use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::{service_error::ServiceError, service_registry::OperationClass};

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

#[derive(Debug, Deserialize)]
struct PkiRenewResponse {
    renewed: bool,
    fingerprint: String,
    previous_fingerprint: Option<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct ProvisionedCertificate {
    pub fingerprint: String,
    pub uri_san: String,
    pub download_file: PathBuf,
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

    pub fn renew_and_download(
        &self,
        current_fingerprint: &str,
        target_name: &str,
        invocation_directory: &Path,
    ) -> Result<Option<ProvisionedCertificate>, ServiceError> {
        if !valid_fingerprint(current_fingerprint) {
            return Err(ServiceError::invalid_request(
                "current certificate fingerprint is invalid",
            ));
        }
        validate_name(target_name)?;
        let output = Command::new(&self.executable)
            .arg("renew")
            .arg(current_fingerprint)
            .output()
            .map_err(|_| provisioning_failed())?;
        if !output.status.success() {
            return Err(provisioning_failed());
        }
        let response: PkiRenewResponse =
            serde_json::from_slice(&output.stdout).map_err(|_| provisioning_failed())?;
        if !response.renewed {
            if response.fingerprint != current_fingerprint {
                return Err(provisioning_failed());
            }
            return Ok(None);
        }
        if response.previous_fingerprint.as_deref() != Some(current_fingerprint)
            || !valid_fingerprint(&response.fingerprint)
            || response.fingerprint == current_fingerprint
        {
            return Err(provisioning_failed());
        }
        let target = invocation_directory.join(target_name);
        let status = Command::new(&self.executable)
            .arg("download")
            .arg(&response.fingerprint)
            .arg(&target)
            .current_dir(invocation_directory)
            .status()
            .map_err(|_| provisioning_failed())?;
        let download_file = target.with_extension("tar.gz");
        if !status.success() || !download_file.is_file() {
            return Err(provisioning_failed());
        }
        Ok(Some(ProvisionedCertificate {
            fingerprint: response.fingerprint,
            uri_san: String::new(),
            download_file,
        }))
    }
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
    ServiceError::classified(8044, "service certificate provisioning failed")
        .expect("8044 must be assigned")
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

    #[test]
    fn renewal_downloads_only_a_valid_replacement_generation() {
        let root = std::env::temp_dir().join(format!("ab-jwt-pki-renew-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let executable = root.join("fake-abpki-cli");
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nif [ \"$1\" = renew ]; then printf '{{\"renewed\":true,\"fingerprint\":\"{new}\",\"previous_fingerprint\":\"{old}\"}}'; exit 0; fi\nif [ \"$1\" = download ]; then : > \"$3.tar.gz\"; exit 0; fi\nexit 1\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let renewed = PkiProvisioner::new(&executable, "configured-issuer")
            .renew_and_download(&old, "renewed-service", &root)
            .unwrap()
            .unwrap();
        assert_eq!(renewed.fingerprint, new);
        assert_eq!(renewed.download_file, root.join("renewed-service.tar.gz"));
        fs::remove_dir_all(root).unwrap();
    }
}

use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::{
    pki_provisioning::{PkiProvisioner, VerifiedServerCertificatePackage},
    production_scheduler::ScheduledCertificateRenewal,
    runtime_supervisor::RuntimeSupervisor,
    server_configuration::ServerConfiguration,
    service_certificate::CertificateTools,
    service_error::ServiceError,
};

pub struct ProductionServerCertificateRenewal {
    configuration: ServerConfiguration,
    supervisor: Arc<RuntimeSupervisor>,
}

impl ProductionServerCertificateRenewal {
    pub fn new(configuration: ServerConfiguration, supervisor: Arc<RuntimeSupervisor>) -> Self {
        Self {
            configuration,
            supervisor,
        }
    }
}

impl ScheduledCertificateRenewal for ProductionServerCertificateRenewal {
    fn run(&self, _: u64) -> Result<(), ServiceError> {
        let client = self
            .configuration
            .pki_client
            .as_ref()
            .ok_or_else(provisioning_failed)?;
        let issuer = self
            .configuration
            .pki_issuer
            .as_deref()
            .ok_or_else(provisioning_failed)?;
        let staging = self
            .configuration
            .pki_staging_directory
            .as_deref()
            .ok_or_else(provisioning_failed)?;
        let certificate = required(&self.configuration.server_certificate)?;
        let private_key = required(&self.configuration.server_private_key)?;
        let trust_chain = required(&self.configuration.server_trust_chain)?;
        let tools = CertificateTools::new(&self.configuration.openssl, client);
        let tools = self
            .configuration
            .ocsp_responder_override
            .as_ref()
            .map_or(tools.clone(), |url| tools.with_ocsp_responder_override(url));
        let current = tools.inspect_server(certificate)?;
        let target = format!("server-renewal-{}", uuid::Uuid::new_v4().simple());
        let provisioner = PkiProvisioner::new(client, issuer);
        let Some(package) = provisioner.renew_and_verify_server(
            &current.fingerprint,
            &target,
            staging,
            &tools,
            &current.subject_alt_names,
        )?
        else {
            return Ok(());
        };
        let swap = Arc::new(Mutex::new(CredentialSwap::prepare(
            certificate,
            private_key,
            trust_chain,
            package,
        )?));
        let install = Arc::clone(&swap);
        let rollback = Arc::clone(&swap);
        let commit = Arc::clone(&swap);
        self.supervisor.replace_secure_listener_credentials(
            move || {
                install
                    .lock()
                    .map_err(|_| provisioning_failed())?
                    .install()?;
                Ok(true)
            },
            move || {
                rollback
                    .lock()
                    .map_err(|_| provisioning_failed())?
                    .rollback()
            },
            move || commit.lock().map_err(|_| provisioning_failed())?.commit(),
        )?;
        Ok(())
    }
}

struct CredentialFile {
    active: PathBuf,
    staged: PathBuf,
    previous: PathBuf,
}
struct CredentialSwap {
    files: Vec<CredentialFile>,
    installed: bool,
}

impl CredentialSwap {
    fn prepare(
        certificate: &Path,
        private_key: &Path,
        trust_chain: &Path,
        package: VerifiedServerCertificatePackage,
    ) -> Result<Self, ServiceError> {
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let mut files = Vec::new();
        for (active, bytes) in [
            (certificate, package.certificate),
            (private_key, package.private_key),
            (trust_chain, package.trust_chain),
        ] {
            let metadata = fs::symlink_metadata(active).map_err(|_| provisioning_failed())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(provisioning_failed());
            }
            let parent = active.parent().ok_or_else(provisioning_failed)?;
            let name = active
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(provisioning_failed)?;
            let staged = parent.join(format!(".{name}.{marker}.new"));
            let previous = parent.join(format!(".{name}.{marker}.previous"));
            write_secret(&staged, &bytes)?;
            files.push(CredentialFile {
                active: active.to_path_buf(),
                staged,
                previous,
            });
        }
        Ok(Self {
            files,
            installed: false,
        })
    }

    fn install(&mut self) -> Result<(), ServiceError> {
        for index in 0..self.files.len() {
            let file = &self.files[index];
            if fs::rename(&file.active, &file.previous).is_err()
                || fs::rename(&file.staged, &file.active).is_err()
            {
                for installed in self.files[..=index].iter().rev() {
                    if installed.previous.exists() {
                        let _ = fs::remove_file(&installed.active);
                        let _ = fs::rename(&installed.previous, &installed.active);
                    }
                }
                return Err(provisioning_failed());
            }
        }
        self.installed = true;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), ServiceError> {
        if self.installed {
            for file in self.files.iter().rev() {
                fs::remove_file(&file.active).map_err(|_| provisioning_failed())?;
                fs::rename(&file.previous, &file.active).map_err(|_| provisioning_failed())?;
            }
            self.installed = false;
        }
        self.remove_staged()
    }

    fn commit(&mut self) -> Result<(), ServiceError> {
        for file in &self.files {
            if file.previous.exists() {
                fs::remove_file(&file.previous).map_err(|_| provisioning_failed())?;
            }
        }
        self.installed = false;
        self.remove_staged()
    }

    fn remove_staged(&self) -> Result<(), ServiceError> {
        for file in &self.files {
            if file.staged.exists() {
                fs::remove_file(&file.staged).map_err(|_| provisioning_failed())?;
            }
        }
        Ok(())
    }
}

impl Drop for CredentialSwap {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = fs::remove_file(&file.staged);
        }
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| provisioning_failed())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| provisioning_failed())
}

fn required(value: &Option<PathBuf>) -> Result<&Path, ServiceError> {
    value.as_deref().ok_or_else(provisioning_failed)
}

fn provisioning_failed() -> ServiceError {
    ServiceError::assigned(8044, "server certificate renewal failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_swap_supports_atomic_commit_and_rollback() {
        let root =
            std::env::temp_dir().join(format!("ab-jwt-credential-swap-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let certificate = root.join("certificate.pem");
        let private_key = root.join("private-key.pem");
        let trust_chain = root.join("trust-chain");
        fs::write(&certificate, b"old-certificate").unwrap();
        fs::write(&private_key, b"old-key").unwrap();
        fs::write(&trust_chain, b"old-chain").unwrap();
        let package = || VerifiedServerCertificatePackage {
            fingerprint: "ab".repeat(32),
            certificate: b"new-certificate".to_vec(),
            private_key: b"new-key".to_vec(),
            trust_chain: b"new-chain".to_vec(),
        };
        let mut rollback =
            CredentialSwap::prepare(&certificate, &private_key, &trust_chain, package()).unwrap();
        rollback.install().unwrap();
        assert_eq!(fs::read(&certificate).unwrap(), b"new-certificate");
        rollback.rollback().unwrap();
        assert_eq!(fs::read(&certificate).unwrap(), b"old-certificate");
        let mut commit =
            CredentialSwap::prepare(&certificate, &private_key, &trust_chain, package()).unwrap();
        commit.install().unwrap();
        commit.commit().unwrap();
        assert_eq!(fs::read(&certificate).unwrap(), b"new-certificate");
        assert_eq!(fs::read(&private_key).unwrap(), b"new-key");
        assert_eq!(fs::read(&trust_chain).unwrap(), b"new-chain");
        fs::remove_dir_all(root).unwrap();
    }
}

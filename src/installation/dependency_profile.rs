#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportCapability {
    Unix,
    Tcp,
    Tls,
    MutualTls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyProfile {
    transports: Vec<TransportCapability>,
    pub pki_client_available: bool,
    pub truelog_client_available: bool,
}

impl DependencyProfile {
    pub fn detect(pki_client_available: bool, truelog_client_available: bool) -> Self {
        let mut transports = vec![TransportCapability::Unix, TransportCapability::Tcp];
        if pki_client_available {
            transports.extend([TransportCapability::Tls, TransportCapability::MutualTls]);
        }
        Self {
            transports,
            pki_client_available,
            truelog_client_available,
        }
    }

    pub fn transports(&self) -> &[TransportCapability] {
        &self.transports
    }

    pub fn audit_evidence_available(&self) -> bool {
        self.truelog_client_available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disables_certificate_transports_without_pki_client() {
        let profile = DependencyProfile::detect(false, false);
        assert_eq!(
            profile.transports(),
            [TransportCapability::Unix, TransportCapability::Tcp]
        );
        assert!(!profile.audit_evidence_available());
    }

    #[test]
    fn enables_tls_mtls_and_audit_when_dependencies_exist() {
        let profile = DependencyProfile::detect(true, true);
        assert_eq!(
            profile.transports(),
            [
                TransportCapability::Unix,
                TransportCapability::Tcp,
                TransportCapability::Tls,
                TransportCapability::MutualTls,
            ]
        );
        assert!(profile.audit_evidence_available());
    }
}

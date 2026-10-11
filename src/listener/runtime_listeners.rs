use std::sync::Arc;

use rustls::ServerConfig;

use crate::{
    mtls_listener,
    server_configuration::{RuntimeTransport, ServerConfiguration},
    service_error::ServiceError,
    tcp_listener::TcpListenerEndpoint,
    tls_listener,
    unix_socket::UnixSocketEndpoint,
};

pub struct RuntimeListenerSet {
    _unix: Option<UnixSocketEndpoint>,
    _tcp: Option<TcpListenerEndpoint>,
    _tls: Option<(TcpListenerEndpoint, Arc<ServerConfig>)>,
    _mtls: Option<(TcpListenerEndpoint, Arc<ServerConfig>)>,
    enabled: Vec<RuntimeTransport>,
}

impl RuntimeListenerSet {
    pub fn bind(configuration: &ServerConfiguration) -> Result<Self, ServiceError> {
        let mut listeners = Self {
            _unix: None,
            _tcp: None,
            _tls: None,
            _mtls: None,
            enabled: configuration.runtime_transports.clone(),
        };
        for transport in &configuration.runtime_transports {
            match transport {
                RuntimeTransport::Unix => {
                    listeners._unix =
                        Some(UnixSocketEndpoint::bind(&configuration.service_socket)?);
                }
                RuntimeTransport::Tcp => {
                    listeners._tcp = Some(TcpListenerEndpoint::bind(&configuration.tcp_address)?);
                }
                RuntimeTransport::Tls => {
                    let identity = tls_listener::server_configuration(
                        required(&configuration.server_certificate)?,
                        required(&configuration.server_private_key)?,
                    )?;
                    listeners._tls = Some((
                        TcpListenerEndpoint::bind(&configuration.tls_address)?,
                        identity,
                    ));
                }
                RuntimeTransport::MutualTls => {
                    let identity = mtls_listener::server_configuration(
                        required(&configuration.server_certificate)?,
                        required(&configuration.server_private_key)?,
                        required(&configuration.client_trust_chain)?,
                    )?;
                    listeners._mtls = Some((
                        TcpListenerEndpoint::bind(&configuration.mtls_address)?,
                        identity,
                    ));
                }
            }
        }
        Ok(listeners)
    }

    pub fn enabled(&self) -> &[RuntimeTransport] {
        &self.enabled
    }
}

fn required(value: &Option<std::path::PathBuf>) -> Result<&std::path::Path, ServiceError> {
    value
        .as_deref()
        .ok_or_else(|| ServiceError::configuration_invalid("secure listener credential is missing"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use uuid::Uuid;

    use crate::server_configuration::{RuntimeTransport, ServerConfiguration};

    use super::RuntimeListenerSet;

    #[test]
    #[ignore = "requires local Autobricks PKI certificates and listener sockets"]
    fn binds_exactly_the_four_configured_runtime_transports() {
        let short_id = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from(format!("/tmp/abjwt-{}", &short_id[..12]));
        let socket = root.join("service.sock");
        let certificate = required_path("AUTOBRICKS_JWT_TEST_SERVER_CERTIFICATE");
        let private_key = required_path("AUTOBRICKS_JWT_TEST_SERVER_PRIVATE_KEY");
        let trust_chain = required_path("AUTOBRICKS_JWT_TEST_TRUST_CHAIN");
        let configuration = ServerConfiguration::parse(&format!(
            "timeout: 3600\nbackup_directory: /tmp/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\ndatabase_path: /tmp/jwt.db\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test/runtime\nruntime_transports: UNIX,TCP,TLS,MTLS\nservice_socket: {}\ntcp_address: 127.0.0.1:0\ntls_address: 127.0.0.1:0\nmtls_address: 127.0.0.1:0\nserver_certificate: {}\nserver_private_key: {}\nclient_trust_chain: {}\n",
            socket.display(), certificate.display(), private_key.display(), trust_chain.display()
        )).unwrap();
        let listeners = RuntimeListenerSet::bind(&configuration).unwrap();
        assert_eq!(
            listeners.enabled(),
            [
                RuntimeTransport::Unix,
                RuntimeTransport::Tcp,
                RuntimeTransport::Tls,
                RuntimeTransport::MutualTls
            ]
        );
        drop(listeners);
        assert!(!socket.exists());
        assert!(!root.exists());
    }

    fn required_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
    }
}

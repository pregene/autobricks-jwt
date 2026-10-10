use std::{path::Path, sync::Arc};

use rustls::{ClientConfig, RootCertStore, ServerConfig, server::WebPkiClientVerifier};

use crate::{
    service_error::ServiceError,
    tls_listener::{load_certificates, load_private_key, load_roots},
};

pub fn server_configuration(
    certificate_path: &Path,
    private_key_path: &Path,
    client_trust_chain_path: &Path,
) -> Result<Arc<ServerConfig>, ServiceError> {
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let roots = Arc::new(load_roots(client_trust_chain_path)?);
    let verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|_| ServiceError::configuration_invalid("mTLS client trust is invalid"))?;
    let configuration = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .map_err(|_| ServiceError::configuration_invalid("mTLS server certificate is invalid"))?;
    Ok(Arc::new(configuration))
}

pub fn client_configuration(
    server_trust_chain_path: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Arc<ClientConfig>, ServiceError> {
    let roots: RootCertStore = load_roots(server_trust_chain_path)?;
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let configuration = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|_| ServiceError::configuration_invalid("mTLS client certificate is invalid"))?;
    Ok(Arc::new(configuration))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::Arc,
        thread,
    };

    use rustls::{ClientConnection, ServerConnection, StreamOwned, pki_types::ServerName};

    use crate::tls_listener;

    use super::{client_configuration, server_configuration};

    #[test]
    #[ignore = "requires local Autobricks PKI test certificates"]
    fn accepts_registered_client_certificate_and_rejects_missing_certificate() {
        let server_certificate = required_path("AUTOBRICKS_JWT_TEST_SERVER_CERTIFICATE");
        let server_private_key = required_path("AUTOBRICKS_JWT_TEST_SERVER_PRIVATE_KEY");
        let client_certificate = required_path("AUTOBRICKS_JWT_TEST_CLIENT_CERTIFICATE");
        let client_private_key = required_path("AUTOBRICKS_JWT_TEST_CLIENT_PRIVATE_KEY");
        let trust_chain = required_path("AUTOBRICKS_JWT_TEST_TRUST_CHAIN");
        let server_name = std::env::var("AUTOBRICKS_JWT_TEST_SERVER_NAME").unwrap();

        let server_config =
            server_configuration(&server_certificate, &server_private_key, &trust_chain).unwrap();
        let client_config =
            client_configuration(&trust_chain, &client_certificate, &client_private_key).unwrap();
        exchange(server_config, client_config, &server_name).unwrap();

        let server_config =
            server_configuration(&server_certificate, &server_private_key, &trust_chain).unwrap();
        let client_without_certificate = tls_listener::client_configuration(&trust_chain).unwrap();
        assert!(exchange(server_config, client_without_certificate, &server_name).is_err());

        println!("mTLS listener: bound on loopback");
        println!("mTLS server certificate: Autobricks PKI certificate loaded");
        println!("mTLS client certificate: trusted certificate accepted");
        println!("mTLS encrypted data exchange: PING/PONG verified");
        println!("mTLS missing client certificate: rejected");
    }

    fn exchange(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<(), String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let server = thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let connection =
                ServerConnection::new(server_config).map_err(|error| error.to_string())?;
            let mut stream = StreamOwned::new(connection, stream);
            let mut request = [0_u8; 4];
            stream
                .read_exact(&mut request)
                .map_err(|error| error.to_string())?;
            if &request != b"PING" {
                return Err("unexpected mTLS request".to_owned());
            }
            stream
                .write_all(b"PONG")
                .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
            Ok(())
        });

        let tcp = TcpStream::connect(address).map_err(|error| error.to_string())?;
        let name =
            ServerName::try_from(server_name.to_owned()).map_err(|error| error.to_string())?;
        let connection =
            ClientConnection::new(client_config, name).map_err(|error| error.to_string())?;
        let mut stream = StreamOwned::new(connection, tcp);
        stream
            .write_all(b"PING")
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
        let mut response = [0_u8; 4];
        let client_result = stream
            .read_exact(&mut response)
            .map_err(|error| error.to_string())
            .and_then(|_| {
                if &response == b"PONG" {
                    Ok(())
                } else {
                    Err("unexpected mTLS response".to_owned())
                }
            });
        let server_result = server
            .join()
            .map_err(|_| "mTLS server thread failed".to_owned())?;
        client_result.and(server_result)
    }

    fn required_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
    }
}

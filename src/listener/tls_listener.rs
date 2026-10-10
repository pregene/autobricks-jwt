use std::{fs::File, io::BufReader, path::Path, sync::Arc};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use crate::service_error::ServiceError;

pub fn server_configuration(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Arc<ServerConfig>, ServiceError> {
    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let configuration = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| ServiceError::configuration_invalid("TLS server certificate is invalid"))?;
    Ok(Arc::new(configuration))
}

pub fn client_configuration(trust_chain_path: &Path) -> Result<Arc<ClientConfig>, ServiceError> {
    let roots = load_roots(trust_chain_path)?;
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

pub(crate) fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServiceError> {
    let file = File::open(path)
        .map_err(|_| ServiceError::configuration_invalid("certificate file cannot be read"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServiceError::configuration_invalid("certificate PEM is invalid"))
}

pub(crate) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ServiceError> {
    let file = File::open(path)
        .map_err(|_| ServiceError::configuration_invalid("private-key file cannot be read"))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|_| ServiceError::configuration_invalid("private-key PEM is invalid"))?
        .ok_or_else(|| ServiceError::configuration_invalid("private key is missing"))
}

pub(crate) fn load_roots(path: &Path) -> Result<RootCertStore, ServiceError> {
    let certificates = load_certificates(path)?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certificates);
    if added == 0 {
        return Err(ServiceError::configuration_invalid(
            "trust chain contains no usable certificate",
        ));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        thread,
    };

    use rustls::{ClientConnection, ServerConnection, StreamOwned, pki_types::ServerName};

    use super::{client_configuration, server_configuration};

    #[test]
    #[ignore = "requires local Autobricks PKI test certificates"]
    fn completes_tls_handshake_with_pki_certificate() {
        let server_certificate = required_path("AUTOBRICKS_JWT_TEST_SERVER_CERTIFICATE");
        let server_private_key = required_path("AUTOBRICKS_JWT_TEST_SERVER_PRIVATE_KEY");
        let trust_chain = required_path("AUTOBRICKS_JWT_TEST_TRUST_CHAIN");
        let server_name = std::env::var("AUTOBRICKS_JWT_TEST_SERVER_NAME").unwrap();

        let server_config = server_configuration(&server_certificate, &server_private_key).unwrap();
        let client_config = client_configuration(&trust_chain).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(server_config).unwrap();
            let mut stream = StreamOwned::new(connection, stream);
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
            stream.flush().unwrap();
        });

        let tcp = TcpStream::connect(address).unwrap();
        let name = ServerName::try_from(server_name).unwrap();
        let connection = ClientConnection::new(client_config, name).unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        stream.write_all(b"PING").unwrap();
        stream.flush().unwrap();
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"PONG");
        server.join().unwrap();

        println!("TLS listener bound: {address}");
        println!("TLS server certificate: Autobricks PKI certificate loaded");
        println!("TLS trust chain: verified");
        println!("TLS handshake: accepted");
        println!("TLS encrypted data exchange: PING/PONG verified");
    }

    fn required_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
    }
}

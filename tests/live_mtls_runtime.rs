use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde_json::{Value, json};

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

#[test]
#[ignore = "requires a running JWT service and protected local credentials"]
fn completes_the_jwt_lifecycle_over_mtls() {
    let input_path = std::env::var_os("AUTOBRICKS_JWT_MTLS_E2E_INPUT")
        .map(PathBuf::from)
        .expect("AUTOBRICKS_JWT_MTLS_E2E_INPUT must be configured");
    let input: Value = serde_json::from_slice(
        &fs::read(&input_path).expect("protected mTLS input must be readable"),
    )
    .expect("protected mTLS input must be valid JSON");

    let mut write = connect(&input, "write");
    activate(&mut write, &input, "write", "WRITE");
    let mut read = connect(&input, "read");
    activate(&mut read, &input, "read", "READ");

    let request_id = uuid::Uuid::new_v4();
    let created = success(
        &mut write,
        "JWT_CREATE",
        json!({
            "client_id": text(&input, "write", "client_id"),
            "apikey": text(&input, "write", "apikey"),
            "request_id": request_id,
            "data": {"user_id": "mtls-user", "role": "member"}
        }),
    );
    let token_id = created["token_id"]
        .as_str()
        .expect("token_id must be returned");
    let created_token = created["token"].as_str().expect("token must be returned");

    let updated = success(
        &mut write,
        "JWT_UPDATE",
        json!({
            "client_id": text(&input, "write", "client_id"),
            "apikey": text(&input, "write", "apikey"),
            "request_id": uuid::Uuid::new_v4(),
            "token_id": token_id,
            "token": created_token,
            "updates": {"role": "administrator"}
        }),
    );
    assert_eq!(updated["version"], 2);
    let updated_token = updated["token"]
        .as_str()
        .expect("updated token must be returned");

    let status = success(
        &mut read,
        "JWT_STATUS",
        json!({
            "client_id": text(&input, "read", "client_id"),
            "apikey": text(&input, "read", "apikey"),
            "request_id": uuid::Uuid::new_v4(),
            "token_id": token_id,
            "token": updated_token,
            "fields": null
        }),
    );
    assert_eq!(status["status"], "ACTIVE");

    let queried = success(
        &mut read,
        "JWT_QUERY",
        json!({
            "client_id": text(&input, "read", "client_id"),
            "apikey": text(&input, "read", "apikey"),
            "request_id": uuid::Uuid::new_v4(),
            "token_id": token_id,
            "token": updated_token,
            "fields": ["user_id", "role"]
        }),
    );
    assert_eq!(
        queried["fields"],
        json!({"user_id": "mtls-user", "role": "administrator"})
    );

    let revoked = success(
        &mut write,
        "JWT_REVOKE",
        json!({
            "client_id": text(&input, "write", "client_id"),
            "apikey": text(&input, "write", "apikey"),
            "request_id": uuid::Uuid::new_v4(),
            "token_id": token_id,
            "token": updated_token
        }),
    );
    assert_eq!(revoked["status"], "REVOKED");

    let rejected = framed(
        &mut read,
        "JWT_QUERY",
        json!({
            "client_id": text(&input, "read", "client_id"),
            "apikey": text(&input, "read", "apikey"),
            "request_id": uuid::Uuid::new_v4(),
            "token_id": token_id,
            "token": updated_token,
            "fields": ["user_id"]
        }),
    );
    assert_eq!(rejected["error"]["code"], 8060);

    println!("mTLS certificate activation: ACTIVE");
    println!("mTLS JWT lifecycle: create, update, status, query, revoke verified");
    println!("mTLS persistent connections: WRITE and READ streams reused");
    println!("mTLS revoked session: error 8060 verified");
}

fn connect(input: &Value, operation: &str) -> TlsStream {
    let address = input["address"].as_str().expect("address is required");
    let server_name = input["server_name"]
        .as_str()
        .expect("server_name is required")
        .to_owned();
    let material = &input[operation];
    let configuration = client_configuration(
        Path::new(
            input["server_trust"]
                .as_str()
                .expect("server_trust is required"),
        ),
        Path::new(
            material["certificate"]
                .as_str()
                .expect("certificate is required"),
        ),
        Path::new(
            material["private_key"]
                .as_str()
                .expect("private_key is required"),
        ),
    )
    .expect("mTLS client configuration must be valid");
    tls_stream(address, &server_name, configuration)
}

fn client_configuration(
    trust: &Path,
    certificate: &Path,
    private_key: &Path,
) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(load_certificates(trust)?);
    if added == 0 {
        return Err("server trust contains no certificate".into());
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certificates(certificate)?,
            load_private_key(private_key)?,
        )
        .map(Arc::new)
        .map_err(|_| "mTLS client identity is invalid".into())
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = fs::File::open(path).map_err(|_| "certificate cannot be read")?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "certificate PEM is invalid".into())
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = fs::File::open(path).map_err(|_| "private key cannot be read")?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(file))
        .map_err(|_| "private key PEM is invalid")?
        .ok_or_else(|| "private key is missing".into())
}

fn tls_stream(address: &str, server_name: &str, configuration: Arc<ClientConfig>) -> TlsStream {
    let tcp = TcpStream::connect(address).expect("mTLS endpoint must accept connections");
    tcp.set_nodelay(true)
        .expect("TCP_NODELAY must be configurable");
    let name = ServerName::try_from(server_name.to_owned()).expect("server_name must be valid");
    let connection =
        ClientConnection::new(configuration, name).expect("mTLS client must initialize");
    StreamOwned::new(connection, tcp)
}

fn activate(stream: &mut TlsStream, input: &Value, operation: &str, class: &str) {
    let material = &input[operation];
    let result = success(
        stream,
        "CERTIFICATE_ACTIVATE",
        json!({
            "client_id": text(input, operation, "client_id"),
            "apikey": text(input, operation, "apikey"),
            "request_id": material["request_id"].as_str().expect("request_id is required"),
            "operation_class": class,
            "temporary_registration_key": material["temporary_registration_key"]
                .as_str()
                .expect("temporary_registration_key is required")
        }),
    );
    assert_eq!(result["certificate_status"], "ACTIVE");
}

fn text<'a>(input: &'a Value, operation: &str, name: &str) -> &'a str {
    input[operation][name]
        .as_str()
        .unwrap_or_else(|| panic!("{operation}.{name} is required"))
}

fn success(stream: &mut TlsStream, operation: &str, request: Value) -> Value {
    let response = framed(stream, operation, request);
    assert_eq!(
        response["status"], "SUCCESS",
        "{operation} failed: {response}"
    );
    assert_eq!(response["operation"], operation);
    response["result"].clone()
}

fn framed(stream: &mut TlsStream, operation: &str, request: Value) -> Value {
    let payload = serde_json::to_vec(&json!({"operation": operation, "request": request}))
        .expect("runtime request must serialize");
    let length = u32::try_from(payload.len()).expect("runtime frame must fit in u32");
    stream
        .write_all(&length.to_be_bytes())
        .expect("frame length must be written");
    stream
        .write_all(&payload)
        .expect("frame payload must be written");
    stream.flush().expect("runtime request must flush");

    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .expect("response length must be read");
    let mut payload = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream
        .read_exact(&mut payload)
        .expect("response payload must be read");
    serde_json::from_slice(&payload).expect("runtime response must be valid JSON")
}

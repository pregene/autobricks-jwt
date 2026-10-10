use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::{
    management_protocol::{ManagementError, ManagementRequest, ManagementResponse},
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    unix_socket::UnixSocketEndpoint,
};
use serde_json::json;

const MAX_MANAGEMENT_FRAME: usize = 64 * 1024;

pub fn serve_server(
    socket_path: &Path,
    request_count: usize,
    registry: Arc<Mutex<ServiceRegistry>>,
) -> Result<(), ServiceError> {
    serve(
        socket_path,
        request_count,
        effective_user_id(),
        move |request| process_server_request(&registry, request),
    )
}

pub fn serve_broker(
    client_socket_path: &Path,
    server_socket_path: &Path,
    request_count: usize,
) -> Result<(), ServiceError> {
    let server_socket_path = server_socket_path.to_path_buf();
    serve(
        client_socket_path,
        request_count,
        effective_user_id(),
        move |request| forward_request(&server_socket_path, request),
    )
}

pub fn request(
    socket_path: &Path,
    request: &ManagementRequest,
) -> Result<ManagementResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("management socket connection failed: {error}"))?;
    let mut payload = serde_json::to_vec(request)
        .map_err(|error| format!("management request serialization failed: {error}"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|error| format!("management request write failed: {error}"))?;

    let response = read_frame(&mut stream)?;
    serde_json::from_slice(&response)
        .map_err(|error| format!("management response is invalid: {error}"))
}

fn serve<F>(
    socket_path: &Path,
    request_count: usize,
    expected_peer_uid: u32,
    handler: F,
) -> Result<(), ServiceError>
where
    F: Fn(ManagementRequest) -> ManagementResponse,
{
    let endpoint = UnixSocketEndpoint::bind(socket_path)?;
    for stream in endpoint.listener().incoming().take(request_count) {
        let mut stream = stream.map_err(|_| {
            ServiceError::service_unavailable("management connection cannot be accepted")
        })?;
        if peer_uid(&stream) != Some(expected_peer_uid) {
            write_response(
                &mut stream,
                &error_response(
                    ServiceError::classified(8030, "management peer is not authorized")
                        .expect("8030 must be assigned"),
                ),
            )?;
            continue;
        }
        let response = match read_frame(&mut stream)
            .and_then(|frame| serde_json::from_slice(&frame).map_err(|error| error.to_string()))
        {
            Ok(request) => handler(request),
            Err(_) => error_response(ServiceError::invalid_request(
                "management request is invalid",
            )),
        };
        write_response(&mut stream, &response)?;
    }
    Ok(())
}

fn process_server_request(
    registry: &Arc<Mutex<ServiceRegistry>>,
    request: ManagementRequest,
) -> ManagementResponse {
    let operation = request.operation_name().to_owned();
    let result = (|| {
        let mut registry = registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        match request {
            ManagementRequest::RegisterClient {
                client_name,
                operation_class,
                allowed_source_cidr,
                transports,
                keep_alive_timeout,
                peer_uid,
                peer_gid,
            } => {
                let client_id = registry.register_client_with_configuration(
                    &client_name,
                    operation_class,
                    &allowed_source_cidr,
                    transports,
                    keep_alive_timeout,
                    peer_uid,
                    peer_gid,
                )?;
                Ok(json!(
                    registry
                        .clients()
                        .into_iter()
                        .find(|client| client.client_id == client_id)
                        .expect("registered client must exist")
                ))
            }
            ManagementRequest::ListClients => Ok(json!(registry.clients())),
            ManagementRequest::ModifyClient { client_id, update } => {
                Ok(json!(registry.update_client(client_id, update)?))
            }
            ManagementRequest::SetClientActive { client_id, active } => {
                registry.set_client_active(client_id, active)?;
                Ok(json!({
                    "client_id": client_id,
                    "status": if active { "ACTIVE" } else { "INACTIVE" }
                }))
            }
            ManagementRequest::RegisterService {
                client_id,
                service_name,
                subject_type,
                allowed_jwt_query_fields,
                source_type,
                encryption_profile,
            } => Ok(json!(registry.register_service_with_configuration(
                client_id,
                &service_name,
                &subject_type,
                allowed_jwt_query_fields,
                source_type,
                encryption_profile,
            )?)),
            ManagementRequest::ListServices { client_id } => {
                Ok(json!(registry.services(client_id)))
            }
            ManagementRequest::DeleteService {
                client_id,
                service_id,
            } => {
                registry.delete_service(client_id, service_id)?;
                Ok(json!({
                    "client_id": client_id,
                    "service_id": service_id,
                    "status": "DELETED"
                }))
            }
            ManagementRequest::DeleteClient { client_id } => {
                let deleted = registry.delete_client(client_id)?;
                Ok(json!({
                    "client_id": deleted.client_id,
                    "status": "DELETED",
                    "deleted_service_count": deleted.deleted_service_count,
                    "revoked_apikey_count": deleted.revoked_apikey_count
                }))
            }
        }
    })();

    match result {
        Ok(result) => ManagementResponse {
            status: "SUCCESS".into(),
            operation: Some(operation),
            result: Some(result),
            error: None,
        },
        Err(error) => error_response(error),
    }
}

fn forward_request(server_socket_path: &Path, request: ManagementRequest) -> ManagementResponse {
    match self::request(server_socket_path, &request) {
        Ok(response) => response,
        Err(_) => error_response(ServiceError::service_unavailable(
            "server management service is unavailable",
        )),
    }
}

fn error_response(error: ServiceError) -> ManagementResponse {
    ManagementResponse {
        status: "ERROR".into(),
        operation: None,
        result: None,
        error: Some(ManagementError {
            code: error.code(),
            name: error.name().into(),
            message: error.public_message().into(),
        }),
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut reader = BufReader::new(stream);
    let mut frame = Vec::new();
    reader
        .by_ref()
        .take((MAX_MANAGEMENT_FRAME + 1) as u64)
        .read_until(b'\n', &mut frame)
        .map_err(|error| format!("management frame read failed: {error}"))?;
    if frame.is_empty() || frame.len() > MAX_MANAGEMENT_FRAME || frame.last() != Some(&b'\n') {
        return Err("management frame is empty, incomplete, or too large".into());
    }
    frame.pop();
    Ok(frame)
}

fn write_response(
    stream: &mut UnixStream,
    response: &ManagementResponse,
) -> Result<(), ServiceError> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|_| ServiceError::internal("management response serialization failed"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|_| ServiceError::service_unavailable("management response write failed"))
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    peer_uid_for_fd(stream.as_raw_fd())
}

fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no arguments and only reads the process credential.
    unsafe { libc::geteuid() }
}

use std::os::fd::AsRawFd;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_uid_for_fd(file_descriptor: std::os::fd::RawFd) -> Option<u32> {
    let mut user_id: libc::uid_t = 0;
    let mut group_id: libc::gid_t = 0;
    // SAFETY: Both pointers reference initialized writable values for the duration of the call.
    let status = unsafe { libc::getpeereid(file_descriptor, &mut user_id, &mut group_id) };
    (status == 0).then_some(user_id)
}

#[cfg(target_os = "linux")]
fn peer_uid_for_fd(file_descriptor: std::os::fd::RawFd) -> Option<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: The credential buffer and length pointer are valid for this getsockopt call.
    let status = unsafe {
        libc::getsockopt(
            file_descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    (status == 0).then_some(credentials.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt},
        path::PathBuf,
        thread,
        time::Duration,
    };

    use crate::{management_protocol::ManagementRequest, service_registry::OperationClass};
    use uuid::Uuid;

    #[test]
    #[ignore = "creates the two local management Unix sockets"]
    fn complete_cli_management_flow_uses_broker_and_server_sockets() {
        let root = PathBuf::from(format!("/tmp/autobricks-jwt-cli-test-{}", Uuid::new_v4()));
        let server_socket = root.join("server/ab-jwtd.sock");
        let client_socket = root.join("client/ab-jwt-cli.sock");
        let registry = Arc::new(Mutex::new(ServiceRegistry::default()));
        let mut root_builder = fs::DirBuilder::new();
        root_builder.mode(0o750).create(&root).unwrap();

        let server_registry = Arc::clone(&registry);
        let server_path = server_socket.clone();
        let server = thread::spawn(move || serve_server(&server_path, 10, server_registry));
        wait_for_socket(&server_socket);

        let broker_client_path = client_socket.clone();
        let broker_server_path = server_socket.clone();
        let broker =
            thread::spawn(move || serve_broker(&broker_client_path, &broker_server_path, 10));
        wait_for_socket(&client_socket);

        assert_socket_permissions(&server_socket);
        assert_socket_permissions(&client_socket);
        println!("CLI server management socket: mode 0660 parent 0750");
        println!("CLI broker management socket: mode 0660 parent 0750");

        let write_client = successful(request(
            &client_socket,
            &ManagementRequest::RegisterClient {
                client_name: "web-server-write".into(),
                operation_class: OperationClass::Write,
                allowed_source_cidr: "192.0.2.0/24".into(),
                transports: vec!["UNIX".into(), "MTLS".into()],
                keep_alive_timeout: 3600,
                peer_uid: Some(unsafe { libc::geteuid() }),
                peer_gid: Some(unsafe { libc::getegid() }),
            },
        ));
        let write_client_id = value_uuid(&write_client, "client_id");
        println!("CLI WRITE client registered: {write_client_id}");

        let read_client = successful(request(
            &client_socket,
            &ManagementRequest::RegisterClient {
                client_name: "policy-read".into(),
                operation_class: OperationClass::Read,
                allowed_source_cidr: "192.0.2.0/24".into(),
                transports: vec!["MTLS".into()],
                keep_alive_timeout: 900,
                peer_uid: None,
                peer_gid: None,
            },
        ));
        let read_client_id = value_uuid(&read_client, "client_id");
        println!("CLI READ client registered: {read_client_id}");

        let clients = successful(request(&client_socket, &ManagementRequest::ListClients));
        assert_eq!(clients.as_array().unwrap().len(), 2);
        println!("CLI client list: 2 active registrations");

        let write_service = successful(request(
            &client_socket,
            &ManagementRequest::RegisterService {
                client_id: write_client_id,
                service_name: "login-issuer".into(),
                subject_type: "USER".into(),
                allowed_jwt_query_fields: Vec::new(),
                source_type: Some("DATABASE".into()),
                encryption_profile: Some("JWE_DIR_A256GCM".into()),
            },
        ));
        let write_service_id = value_uuid(&write_service, "service_id");
        assert!(
            write_service["apikey"]
                .as_str()
                .is_some_and(|key| !key.is_empty())
        );
        println!("CLI WRITE service registered: {write_service_id} APIKEY issued");

        let read_service = successful(request(
            &client_socket,
            &ManagementRequest::RegisterService {
                client_id: read_client_id,
                service_name: "policy-query".into(),
                subject_type: "USER".into(),
                allowed_jwt_query_fields: vec!["user_id".into(), "role".into()],
                source_type: None,
                encryption_profile: None,
            },
        ));
        let read_service_id = value_uuid(&read_service, "service_id");
        assert_eq!(
            read_service["allowed_jwt_query_fields"],
            json!(["user_id", "role"])
        );
        println!("CLI READ service registered: {read_service_id} field allowlist preserved");

        let write_services = successful(request(
            &client_socket,
            &ManagementRequest::ListServices {
                client_id: write_client_id,
            },
        ));
        assert_eq!(write_services.as_array().unwrap().len(), 1);
        println!("CLI service list: selected client contains 1 service");

        let deleted_service = successful(request(
            &client_socket,
            &ManagementRequest::DeleteService {
                client_id: write_client_id,
                service_id: write_service_id,
            },
        ));
        assert_eq!(deleted_service["status"], "DELETED");
        println!("CLI service deleted: {write_service_id}");

        let missing_services = successful(request(
            &client_socket,
            &ManagementRequest::ListServices {
                client_id: write_client_id,
            },
        ));
        assert!(missing_services.as_array().unwrap().is_empty());
        println!("CLI service deletion verified: selected list is empty");

        let deleted_read_client = successful(request(
            &client_socket,
            &ManagementRequest::DeleteClient {
                client_id: read_client_id,
            },
        ));
        assert_eq!(deleted_read_client["deleted_service_count"], 1);
        assert_eq!(deleted_read_client["revoked_apikey_count"], 1);
        println!("CLI client cascade deletion: 1 service and 1 APIKEY removed");

        let deleted_write_client = successful(request(
            &client_socket,
            &ManagementRequest::DeleteClient {
                client_id: write_client_id,
            },
        ));
        assert_eq!(deleted_write_client["deleted_service_count"], 0);
        println!("CLI final client deleted: no active registration remains");

        broker.join().unwrap().unwrap();
        server.join().unwrap().unwrap();
        fs::remove_dir_all(&root).unwrap();
        println!("CLI management socket cleanup: removed");
    }

    fn successful(result: Result<ManagementResponse, String>) -> serde_json::Value {
        let response = result.expect("management request must complete");
        assert_eq!(
            response.status, "SUCCESS",
            "response error: {:?}",
            response.error
        );
        response
            .result
            .expect("successful response must have a result")
    }

    fn value_uuid(value: &serde_json::Value, field: &str) -> Uuid {
        Uuid::parse_str(value[field].as_str().expect("UUID field must be a string")).unwrap()
    }

    fn wait_for_socket(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("socket did not appear: {}", path.display());
    }

    fn assert_socket_permissions(path: &Path) {
        let socket = fs::symlink_metadata(path).unwrap();
        let parent = fs::metadata(path.parent().unwrap()).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.mode() & 0o777, 0o660);
        assert_eq!(parent.mode() & 0o777, 0o750);
    }
}

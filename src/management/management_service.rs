use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crate::{
    management_protocol::{
        ManagementAttachment, ManagementError, ManagementRequest, ManagementResponse,
    },
    service_error::ServiceError,
    service_registry::ServiceRegistry,
    unix_socket::UnixSocketEndpoint,
};
use serde_json::json;

const MAX_MANAGEMENT_FRAME: usize = 64 * 1024;
const MAX_MANAGEMENT_ATTACHMENT: usize = 16 * 1024 * 1024;

pub struct ReceivedAttachment {
    pub file_name: String,
    pub bytes: Vec<u8>,
}

struct WireResponse {
    response: ManagementResponse,
    attachment: Option<Vec<u8>>,
}

impl From<ManagementResponse> for WireResponse {
    fn from(response: ManagementResponse) -> Self {
        Self {
            response,
            attachment: None,
        }
    }
}

impl WireResponse {
    fn with_attachment(
        mut response: ManagementResponse,
        file_name: String,
        bytes: Vec<u8>,
    ) -> Result<Self, ServiceError> {
        if bytes.is_empty()
            || bytes.len() > MAX_MANAGEMENT_ATTACHMENT
            || !safe_file_name(&file_name)
        {
            return Err(
                ServiceError::classified(8044, "certificate package delivery is invalid")
                    .expect("assigned error"),
            );
        }
        let sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        response.attachment = Some(ManagementAttachment {
            file_name,
            size: bytes.len() as u64,
            sha256,
        });
        Ok(Self {
            response,
            attachment: Some(bytes),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ManagementCapabilities {
    pub transports: Vec<String>,
    pub encryption_profiles: Vec<String>,
    pub pki_available: bool,
}

pub trait RecoveryManagement: Send + Sync {
    fn process(
        &self,
        request: &ManagementRequest,
    ) -> Option<Result<serde_json::Value, ServiceError>>;
}

pub struct ManagementOperationResult {
    pub value: serde_json::Value,
    pub attachment_name: Option<String>,
    pub attachment: Option<Vec<u8>>,
}

pub trait CertificateManagement: Send + Sync {
    fn process(
        &self,
        registry: &Arc<Mutex<ServiceRegistry>>,
        request: &ManagementRequest,
    ) -> Option<Result<ManagementOperationResult, ServiceError>>;
}

impl Default for ManagementCapabilities {
    fn default() -> Self {
        Self {
            transports: vec!["UNIX".into(), "TCP".into(), "TLS".into(), "MTLS".into()],
            encryption_profiles: vec![
                "JWE_DIR_A128GCM".into(),
                "JWE_DIR_A192GCM".into(),
                "JWE_DIR_A256GCM".into(),
            ],
            pki_available: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    allowed_uids: BTreeSet<u32>,
    allowed_gids: BTreeSet<u32>,
    allowed_operations: BTreeSet<String>,
}

impl BrokerPolicy {
    pub fn new(
        allowed_uids: impl IntoIterator<Item = u32>,
        allowed_gids: impl IntoIterator<Item = u32>,
        allowed_operations: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ServiceError> {
        let policy = Self {
            allowed_uids: allowed_uids.into_iter().collect(),
            allowed_gids: allowed_gids.into_iter().collect(),
            allowed_operations: allowed_operations.into_iter().map(Into::into).collect(),
        };
        if (policy.allowed_uids.is_empty() && policy.allowed_gids.is_empty())
            || policy.allowed_operations.is_empty()
        {
            return Err(ServiceError::configuration_invalid(
                "management broker policy requires a peer identity and operation allowlist",
            ));
        }
        Ok(policy)
    }

    fn authorize(
        &self,
        peer_uid: u32,
        peer_gid: u32,
        request: &ManagementRequest,
    ) -> Result<(), ServiceError> {
        if !self.allowed_uids.contains(&peer_uid) && !self.allowed_gids.contains(&peer_gid) {
            return Err(
                ServiceError::classified(8030, "management peer is not authorized")
                    .expect("8030 must be assigned"),
            );
        }
        if !self.allowed_operations.contains(request.operation_name()) {
            return Err(
                ServiceError::classified(8031, "management operation is not authorized")
                    .expect("8031 must be assigned"),
            );
        }
        Ok(())
    }
}

pub fn serve_server(
    socket_path: &Path,
    request_count: usize,
    registry: Arc<Mutex<ServiceRegistry>>,
) -> Result<(), ServiceError> {
    serve_server_with_capabilities(
        socket_path,
        request_count,
        registry,
        ManagementCapabilities::default(),
    )
}

pub fn serve_server_with_capabilities(
    socket_path: &Path,
    request_count: usize,
    registry: Arc<Mutex<ServiceRegistry>>,
    capabilities: ManagementCapabilities,
) -> Result<(), ServiceError> {
    serve(
        socket_path,
        request_count,
        effective_user_id(),
        move |request| process_server_request(&registry, &capabilities, request).into(),
    )
}

pub fn serve_runtime_server(
    socket_path: &Path,
    request_count: usize,
    runtime: Arc<crate::runtime_context::RuntimeContextHandle>,
    capabilities: ManagementCapabilities,
    recovery: Arc<dyn RecoveryManagement>,
    certificates: Arc<dyn CertificateManagement>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), ServiceError> {
    serve_until(
        socket_path,
        request_count,
        effective_user_id(),
        Some(shutdown),
        move |request| {
            let certificate_result =
                if matches!(&request, ManagementRequest::RegisterService { .. }) {
                    match runtime.current() {
                        Ok(context) => certificates.process(&context.registry(), &request),
                        Err(error) => return error_response(error).into(),
                    }
                } else {
                    None
                };
            if let Some(result) = certificate_result {
                return match result {
                    Ok(result) => {
                        let response = ManagementResponse {
                            status: "SUCCESS".into(),
                            operation: Some(request.operation_name().into()),
                            result: Some(result.value),
                            error: None,
                            attachment: None,
                        };
                        match (result.attachment_name, result.attachment) {
                            (Some(name), Some(bytes)) => {
                                WireResponse::with_attachment(response, name, bytes)
                                    .unwrap_or_else(|error| error_response(error).into())
                            }
                            (None, None) => response.into(),
                            _ => error_response(
                                ServiceError::classified(
                                    8044,
                                    "certificate package delivery is invalid",
                                )
                                .expect("assigned error"),
                            )
                            .into(),
                        }
                    }
                    Err(error) => error_response(error).into(),
                };
            }
            if let Some(result) = recovery.process(&request) {
                return match result {
                    Ok(result) => ManagementResponse {
                        status: "SUCCESS".into(),
                        operation: Some(request.operation_name().into()),
                        result: Some(result),
                        error: None,
                        attachment: None,
                    }
                    .into(),
                    Err(error) => error_response(error).into(),
                };
            }
            match runtime.current() {
                Ok(context) => {
                    process_server_request(&context.registry(), &capabilities, request).into()
                }
                Err(error) => error_response(error).into(),
            }
        },
    )
}

pub fn serve_broker(
    client_socket_path: &Path,
    server_socket_path: &Path,
    request_count: usize,
) -> Result<(), ServiceError> {
    let identity = effective_peer_identity();
    let allowed_uid = std::env::var("AUTOBRICKS_JWT_BROKER_ALLOWED_UID")
        .ok()
        .map(|value| parse_broker_allowed_uid(&value))
        .transpose()?
        .unwrap_or(identity.0);
    let policy = BrokerPolicy::new(
        [allowed_uid],
        std::iter::empty(),
        [
            "GET_CAPABILITIES",
            "REGISTER_CLIENT",
            "LIST_CLIENTS",
            "MODIFY_CLIENT",
            "SET_CLIENT_ACTIVE",
            "REGISTER_SERVICE",
            "LIST_SERVICES",
            "DELETE_SERVICE",
            "DELETE_CLIENT",
            "LIST_RECOVERY_POINTS",
            "FORCE_BACKUP_AND_ROTATE",
            "RESTORE_DATABASE",
        ],
    )?;
    serve_broker_with_policy(
        client_socket_path,
        server_socket_path,
        request_count,
        policy,
    )
}

fn parse_broker_allowed_uid(value: &str) -> Result<u32, ServiceError> {
    value.parse::<u32>().map_err(|_| {
        ServiceError::configuration_invalid("management broker allowed UID is invalid")
    })
}

pub fn serve_broker_with_policy(
    client_socket_path: &Path,
    server_socket_path: &Path,
    request_count: usize,
    policy: BrokerPolicy,
) -> Result<(), ServiceError> {
    let endpoint = UnixSocketEndpoint::bind(client_socket_path)?;
    for stream in endpoint.listener().incoming().take(request_count) {
        let mut stream = stream.map_err(|_| {
            ServiceError::service_unavailable("management connection cannot be accepted")
        })?;
        let response = match peer_identity(&stream) {
            Some((uid, gid)) => match read_frame(&mut stream)
                .and_then(|frame| serde_json::from_slice(&frame).map_err(|error| error.to_string()))
            {
                Ok(request) => match policy.authorize(uid, gid, &request) {
                    Ok(()) => forward_request(server_socket_path, request),
                    Err(error) => error_response(error).into(),
                },
                Err(_) => error_response(ServiceError::invalid_request(
                    "management request is invalid",
                ))
                .into(),
            },
            None => error_response(
                ServiceError::classified(8030, "management peer is not authorized")
                    .expect("8030 must be assigned"),
            )
            .into(),
        };
        write_response(&mut stream, &response)?;
    }
    Ok(())
}

pub fn request(
    socket_path: &Path,
    request: &ManagementRequest,
) -> Result<ManagementResponse, String> {
    let (response, attachment) = request_with_attachment(socket_path, request)?;
    if attachment.is_some() {
        return Err("management response contains an unexpected attachment".into());
    }
    Ok(response)
}

pub fn request_with_attachment(
    socket_path: &Path,
    request: &ManagementRequest,
) -> Result<(ManagementResponse, Option<ReceivedAttachment>), String> {
    let wire = request_wire(socket_path, request)?;
    let attachment = wire.attachment.map(|bytes| ReceivedAttachment {
        file_name: wire
            .response
            .attachment
            .as_ref()
            .expect("validated attachment metadata")
            .file_name
            .clone(),
        bytes,
    });
    Ok((wire.response, attachment))
}

fn request_wire(socket_path: &Path, request: &ManagementRequest) -> Result<WireResponse, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("management socket connection failed: {error}"))?;
    let mut payload = serde_json::to_vec(request)
        .map_err(|error| format!("management request serialization failed: {error}"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|error| format!("management request write failed: {error}"))?;

    read_wire_response(&mut stream)
}

fn serve<F>(
    socket_path: &Path,
    request_count: usize,
    expected_peer_uid: u32,
    handler: F,
) -> Result<(), ServiceError>
where
    F: Fn(ManagementRequest) -> WireResponse,
{
    serve_until(socket_path, request_count, expected_peer_uid, None, handler)
}

fn serve_until<F>(
    socket_path: &Path,
    request_count: usize,
    expected_peer_uid: u32,
    shutdown: Option<Arc<AtomicBool>>,
    handler: F,
) -> Result<(), ServiceError>
where
    F: Fn(ManagementRequest) -> WireResponse,
{
    let endpoint = UnixSocketEndpoint::bind(socket_path)?;
    if shutdown.is_some() {
        endpoint.listener().set_nonblocking(true).map_err(|_| {
            ServiceError::service_unavailable("management listener cannot enter runtime mode")
        })?;
    }
    let mut accepted = 0;
    while accepted < request_count
        && shutdown
            .as_ref()
            .is_none_or(|flag| !flag.load(Ordering::Acquire))
    {
        let mut stream = match endpoint.listener().accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(_) => {
                return Err(ServiceError::service_unavailable(
                    "management connection cannot be accepted",
                ));
            }
        };
        accepted += 1;
        if peer_uid(&stream) != Some(expected_peer_uid) {
            write_response(
                &mut stream,
                &error_response(
                    ServiceError::classified(8030, "management peer is not authorized")
                        .expect("8030 must be assigned"),
                )
                .into(),
            )?;
            continue;
        }
        let response = match read_frame(&mut stream)
            .and_then(|frame| serde_json::from_slice(&frame).map_err(|error| error.to_string()))
        {
            Ok(request) => handler(request),
            Err(_) => error_response(ServiceError::invalid_request(
                "management request is invalid",
            ))
            .into(),
        };
        write_response(&mut stream, &response)?;
    }
    Ok(())
}

fn process_server_request(
    registry: &Arc<Mutex<ServiceRegistry>>,
    capabilities: &ManagementCapabilities,
    request: ManagementRequest,
) -> ManagementResponse {
    let operation = request.operation_name().to_owned();
    let result = (|| {
        let mut registry = registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        match request {
            ManagementRequest::GetCapabilities => Ok(json!(capabilities)),
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
                allowed_issuer_service_ids,
                source_type,
                encryption_profile,
                client_json_schema,
                database_source,
            } => {
                if let Some(database_source) = database_source {
                    if source_type.as_deref() != Some("DATABASE")
                        || !allowed_jwt_query_fields.is_empty()
                        || !allowed_issuer_service_ids.is_empty()
                        || client_json_schema.is_some()
                    {
                        return Err(ServiceError::invalid_request(
                            "DATABASE service registration fields conflict",
                        ));
                    }
                    Ok(json!(
                        registry
                            .register_database_service(
                                client_id,
                                &service_name,
                                &subject_type,
                                encryption_profile.as_deref().unwrap_or_default(),
                                database_source,
                            )?
                            .0
                    ))
                } else {
                    Ok(json!(
                        registry.register_service_with_source_schema_and_issuers(
                            client_id,
                            &service_name,
                            &subject_type,
                            allowed_jwt_query_fields,
                            source_type,
                            encryption_profile,
                            client_json_schema,
                            allowed_issuer_service_ids,
                        )?
                    ))
                }
            }
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
            ManagementRequest::ListRecoveryPoints
            | ManagementRequest::ForceBackupAndRotate { .. }
            | ManagementRequest::RestoreDatabase { .. } => Err(ServiceError::invalid_request(
                "recovery management is unavailable",
            )),
        }
    })();

    match result {
        Ok(result) => ManagementResponse {
            status: "SUCCESS".into(),
            operation: Some(operation),
            result: Some(result),
            error: None,
            attachment: None,
        },
        Err(error) => error_response(error),
    }
}

fn forward_request(server_socket_path: &Path, request: ManagementRequest) -> WireResponse {
    match request_wire(server_socket_path, &request) {
        Ok(response) => response,
        Err(_) => error_response(ServiceError::service_unavailable(
            "server management service is unavailable",
        ))
        .into(),
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
        attachment: None,
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

fn write_response(stream: &mut UnixStream, response: &WireResponse) -> Result<(), ServiceError> {
    let mut payload = serde_json::to_vec(&response.response)
        .map_err(|_| ServiceError::internal("management response serialization failed"))?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .and_then(|_| {
            response
                .attachment
                .as_ref()
                .map_or(Ok(()), |bytes| stream.write_all(bytes))
        })
        .map_err(|_| ServiceError::service_unavailable("management response write failed"))
}

fn read_wire_response(stream: &mut UnixStream) -> Result<WireResponse, String> {
    let mut reader = BufReader::new(stream);
    let mut frame = Vec::new();
    reader
        .by_ref()
        .take((MAX_MANAGEMENT_FRAME + 1) as u64)
        .read_until(b'\n', &mut frame)
        .map_err(|error| format!("management response read failed: {error}"))?;
    if frame.is_empty() || frame.len() > MAX_MANAGEMENT_FRAME || frame.pop() != Some(b'\n') {
        return Err("management response frame is invalid".into());
    }
    let response: ManagementResponse = serde_json::from_slice(&frame)
        .map_err(|error| format!("management response is invalid: {error}"))?;
    let attachment = if let Some(metadata) = response.attachment.as_ref() {
        let size =
            usize::try_from(metadata.size).map_err(|_| "management attachment size is invalid")?;
        if size == 0 || size > MAX_MANAGEMENT_ATTACHMENT || !safe_file_name(&metadata.file_name) {
            return Err("management attachment metadata is invalid".into());
        }
        let mut bytes = vec![0u8; size];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| "management attachment is incomplete")?;
        let checksum = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if checksum != metadata.sha256 {
            return Err("management attachment checksum is invalid".into());
        }
        Some(bytes)
    } else {
        None
    };
    Ok(WireResponse {
        response,
        attachment,
    })
}

fn safe_file_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains('/')
        && !value.contains('\\')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    peer_identity_for_fd(stream.as_raw_fd()).map(|identity| identity.0)
}

fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no arguments and only reads the process credential.
    unsafe { libc::geteuid() }
}

fn effective_peer_identity() -> (u32, u32) {
    // SAFETY: geteuid and getegid have no arguments and only read process credentials.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

fn peer_identity(stream: &UnixStream) -> Option<(u32, u32)> {
    peer_identity_for_fd(stream.as_raw_fd())
}

use std::os::fd::AsRawFd;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_identity_for_fd(file_descriptor: std::os::fd::RawFd) -> Option<(u32, u32)> {
    let mut user_id: libc::uid_t = 0;
    let mut group_id: libc::gid_t = 0;
    // SAFETY: Both pointers reference initialized writable values for the duration of the call.
    let status = unsafe { libc::getpeereid(file_descriptor, &mut user_id, &mut group_id) };
    (status == 0).then_some((user_id, group_id))
}

#[cfg(target_os = "linux")]
fn peer_identity_for_fd(file_descriptor: std::os::fd::RawFd) -> Option<(u32, u32)> {
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
    (status == 0).then_some((credentials.uid, credentials.gid))
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
    fn parses_the_installed_macos_operator_uid_for_broker_authorization() {
        assert_eq!(parse_broker_allowed_uid("501").unwrap(), 501);
        assert_eq!(
            parse_broker_allowed_uid("operator").unwrap_err().code(),
            8090
        );
    }

    #[test]
    fn relays_verified_binary_attachment_separately_from_json() {
        let bytes = b"protected-certificate-package".to_vec();
        let response = ManagementResponse {
            status: "SUCCESS".into(),
            operation: Some("REGISTER_SERVICE".into()),
            result: Some(serde_json::json!({"service_id": Uuid::nil()})),
            error: None,
            attachment: None,
        };
        let wire = WireResponse::with_attachment(response, "service.tar.gz".into(), bytes.clone())
            .unwrap();
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || write_response(&mut writer, &wire).unwrap());
        let received = read_wire_response(&mut reader).unwrap();
        sender.join().unwrap();
        assert_eq!(received.attachment.unwrap(), bytes);
        let metadata = received.response.attachment.unwrap();
        assert_eq!(metadata.file_name, "service.tar.gz");
        assert_eq!(metadata.size, 29);
        assert_eq!(metadata.sha256.len(), 64);
        assert!(
            !serde_json::to_string(&received.response.result)
                .unwrap()
                .contains("protected-certificate-package")
        );
    }

    #[test]
    fn runtime_management_listener_honors_shutdown_before_accepting() {
        let identifier = uuid::Uuid::new_v4().simple().to_string();
        let root = std::path::PathBuf::from(format!("/tmp/ajm-{}", &identifier[..12]));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(
            &root,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let socket = root.join("management.sock");
        let shutdown = Arc::new(AtomicBool::new(true));
        serve_until(
            &socket,
            usize::MAX,
            effective_user_id(),
            Some(shutdown),
            |_| panic!("a stopped listener must not accept a request"),
        )
        .unwrap();
        assert!(!socket.exists());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn broker_policy_requires_peer_identity_and_filters_each_operation() {
        let uid = effective_user_id();
        let gid = effective_peer_identity().1;
        let policy = BrokerPolicy::new([uid], [gid], ["LIST_CLIENTS"]).unwrap();
        assert!(
            policy
                .authorize(uid, u32::MAX, &ManagementRequest::ListClients)
                .is_ok()
        );
        assert!(
            policy
                .authorize(u32::MAX, gid, &ManagementRequest::ListClients)
                .is_ok()
        );
        let denied_operation = policy
            .authorize(
                uid,
                gid,
                &ManagementRequest::DeleteClient {
                    client_id: Uuid::new_v4(),
                },
            )
            .unwrap_err();
        assert_eq!(denied_operation.code(), 8031);
        let denied_peer = policy
            .authorize(u32::MAX, u32::MAX, &ManagementRequest::ListClients)
            .unwrap_err();
        assert_eq!(denied_peer.code(), 8030);
    }

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
                allowed_issuer_service_ids: Vec::new(),
                source_type: Some("DATABASE".into()),
                encryption_profile: Some("JWE_DIR_A256GCM".into()),
                client_json_schema: None,
                database_source: None,
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
                allowed_issuer_service_ids: vec![write_service_id],
                source_type: None,
                encryption_profile: None,
                client_json_schema: None,
                database_source: None,
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

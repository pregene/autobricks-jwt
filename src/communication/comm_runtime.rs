use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char, c_void},
    net::IpAddr,
    path::PathBuf,
    ptr, slice,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use libloading::Library;

use crate::{
    runtime_connection::{ConnectionIdentity, RuntimeSession, client_error_payload},
    runtime_context::RuntimeContextHandle,
    runtime_protocol::RuntimeRequest,
    server_configuration::{RuntimeTransport, ServerConfiguration},
    service_certificate::CertificateTools,
    service_error::ServiceError,
};

const COMM_ABI_VERSION: u32 = 1;
const COMM_APPLICATION_API_VERSION: u32 = 1;
const IPC_SESSION_API_VERSION: u32 = 2;
const TRANSPORT_SESSION_API_VERSION: u32 = 2;

type CommInitialize = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type CommUninitialize = unsafe extern "C" fn(*mut c_void);
type CommBind = unsafe extern "C" fn(*const CommApplicationApi, *mut c_void) -> *mut c_void;
type CommUnbind = unsafe extern "C" fn(*mut c_void);
type CommStart = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type CommControl = unsafe extern "C" fn(*const c_void) -> i32;
type CommStop = unsafe extern "C" fn(*mut c_void) -> i32;

#[repr(C)]
struct CommApplicationApi {
    struct_size: usize,
    api_version: u32,
    ipc: *const c_void,
    http: *const c_void,
    structured: *const c_void,
}

#[repr(C)]
struct IpcSessionApi {
    struct_size: usize,
    api_version: u32,
    request: Option<unsafe extern "C" fn(*const c_char, *mut c_void, *mut bool) -> *mut c_char>,
    response_free: unsafe extern "C" fn(*mut c_char),
    request_v2:
        Option<unsafe extern "C" fn(*const IpcRequest, *mut c_void, *mut bool) -> *mut c_char>,
}

#[repr(C)]
struct IpcRequest {
    struct_size: usize,
    connection_id: u64,
    payload: *const c_char,
    has_peer_credentials: bool,
    peer_uid: u32,
    peer_gid: u32,
}

#[repr(C)]
struct Bytes {
    data: *const u8,
    length: usize,
}

#[repr(C)]
struct TransportRequest {
    struct_size: usize,
    sid: *const c_char,
    client_ip: *const c_char,
    transport: *const c_char,
    cert: Bytes,
    metadata: Bytes,
    payload: Bytes,
}

#[repr(C)]
struct TransportResponse {
    struct_size: usize,
    metadata: Bytes,
    payload: Bytes,
    close: bool,
    idle_timeout_ms: u64,
    absolute_deadline_unix_ms: u64,
}

#[repr(C)]
struct TransportSessionApi {
    struct_size: usize,
    api_version: u32,
    request: Option<
        unsafe extern "C" fn(*const TransportRequest, *mut TransportResponse, *mut c_void) -> i32,
    >,
    response_free: Option<unsafe extern "C" fn(*mut TransportResponse, *mut c_void)>,
    session_closed: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
}

struct CommSymbols {
    uninitialize: CommUninitialize,
    unbind: CommUnbind,
    pause: CommControl,
    resume: CommControl,
    stop: CommStop,
}

pub struct CommRuntime {
    runtime: *mut c_void,
    application_binding: *mut c_void,
    definition: *mut c_void,
    application: Box<CommApplication>,
    symbols: CommSymbols,
    _library: Library,
}

unsafe impl Send for CommRuntime {}

struct CommApplication {
    context: Arc<RuntimeContextHandle>,
    maximum_lifetime: u64,
    sessions: Mutex<HashMap<String, RuntimeSession>>,
    certificate_tools: Option<CertificateTools>,
    client_trust: Option<PathBuf>,
}

impl CommRuntime {
    pub fn start(
        configuration: &ServerConfiguration,
        context: Arc<RuntimeContextHandle>,
    ) -> Result<Self, ServiceError> {
        let library_path =
            configuration
                .comm_library_directory
                .join(if cfg!(target_os = "macos") {
                    "libautobricks_comm.dylib"
                } else {
                    "libautobricks_comm.so"
                });
        let library = unsafe { Library::new(library_path) }
            .map_err(|_| unavailable("COMM library cannot be loaded"))?;
        let abi: unsafe extern "C" fn() -> u32 =
            unsafe { load(&library, b"ab_comm_abi_version\0")? };
        if unsafe { abi() } != COMM_ABI_VERSION {
            return Err(unavailable("COMM ABI is incompatible"));
        }
        let initialize: CommInitialize = unsafe { load(&library, b"ab_comm_initialize\0")? };
        let uninitialize: CommUninitialize = unsafe { load(&library, b"ab_comm_uninitialize\0")? };
        let bind: CommBind = unsafe { load(&library, b"ab_comm_bind_application\0")? };
        let unbind: CommUnbind = unsafe { load(&library, b"ab_comm_unbind_application\0")? };
        let start: CommStart = unsafe { load(&library, b"ab_comm_start\0")? };
        let pause: CommControl = unsafe { load(&library, b"ab_comm_pause\0")? };
        let resume: CommControl = unsafe { load(&library, b"ab_comm_resume\0")? };
        let stop: CommStop = unsafe { load(&library, b"ab_comm_stop\0")? };
        let config = CString::new(comm_configuration(configuration)?.to_string())
            .map_err(|_| unavailable("COMM configuration contains an invalid string"))?;
        let definition = unsafe { initialize(config.as_ptr()) };
        if definition.is_null() {
            return Err(unavailable("COMM initialization failed"));
        }
        let tools = configuration.pki_client.as_ref().map(|client| {
            let tools = CertificateTools::new(&configuration.openssl, client);
            configuration
                .ocsp_responder_override
                .as_ref()
                .map_or(tools.clone(), |url| tools.with_ocsp_responder_override(url))
        });
        let mut application = Box::new(CommApplication {
            context,
            maximum_lifetime: configuration.maximum_connection_lifetime_seconds,
            sessions: Mutex::new(HashMap::new()),
            certificate_tools: tools,
            client_trust: configuration.client_trust_chain.clone(),
        });
        let ipc_api = IpcSessionApi {
            struct_size: std::mem::size_of::<IpcSessionApi>(),
            api_version: IPC_SESSION_API_VERSION,
            request: None,
            response_free: ipc_response_free,
            request_v2: Some(ipc_request),
        };
        let transport_api = TransportSessionApi {
            struct_size: std::mem::size_of::<TransportSessionApi>(),
            api_version: TRANSPORT_SESSION_API_VERSION,
            request: Some(transport_request),
            response_free: Some(transport_response_free),
            session_closed: Some(transport_session_closed),
        };
        let api = CommApplicationApi {
            struct_size: std::mem::size_of::<CommApplicationApi>(),
            api_version: COMM_APPLICATION_API_VERSION,
            ipc: if configuration
                .runtime_transports
                .contains(&RuntimeTransport::Unix)
            {
                (&raw const ipc_api).cast()
            } else {
                ptr::null()
            },
            http: ptr::null(),
            structured: if configuration
                .runtime_transports
                .iter()
                .any(|value| !matches!(value, RuntimeTransport::Unix))
            {
                (&raw const transport_api).cast()
            } else {
                ptr::null()
            },
        };
        let context_pointer = (&raw mut *application).cast();
        let application_binding = unsafe { bind(&raw const api, context_pointer) };
        if application_binding.is_null() {
            unsafe { uninitialize(definition) };
            return Err(unavailable("COMM application binding failed"));
        }
        let runtime = unsafe { start(definition, application_binding) };
        if runtime.is_null() {
            unsafe {
                unbind(application_binding);
                uninitialize(definition);
            }
            return Err(unavailable("COMM listener start failed"));
        }
        Ok(Self {
            runtime,
            application_binding,
            definition,
            application,
            symbols: CommSymbols {
                uninitialize,
                unbind,
                pause,
                resume,
                stop,
            },
            _library: library,
        })
    }

    pub fn pause(&self) -> Result<(), ServiceError> {
        (unsafe { (self.symbols.pause)(self.runtime) } == 0)
            .then_some(())
            .ok_or_else(|| unavailable("COMM admission cannot pause"))
    }

    pub fn resume(&self) -> Result<(), ServiceError> {
        (unsafe { (self.symbols.resume)(self.runtime) } == 0)
            .then_some(())
            .ok_or_else(|| unavailable("COMM admission cannot resume"))
    }

    pub fn shutdown(mut self) -> Result<(), ServiceError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), ServiceError> {
        if self.runtime.is_null() {
            return Ok(());
        }
        let status = unsafe { (self.symbols.stop)(self.runtime) };
        self.runtime = ptr::null_mut();
        unsafe {
            (self.symbols.unbind)(self.application_binding);
            (self.symbols.uninitialize)(self.definition);
        }
        self.application_binding = ptr::null_mut();
        self.definition = ptr::null_mut();
        self.application
            .sessions
            .lock()
            .map_err(|_| unavailable("COMM session registry is unavailable"))?
            .clear();
        (status == 0)
            .then_some(())
            .ok_or_else(|| unavailable("COMM shutdown failed"))
    }
}

impl Drop for CommRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

unsafe fn load<T: Copy>(library: &Library, name: &[u8]) -> Result<T, ServiceError> {
    unsafe { library.get::<T>(name) }
        .map(|value| *value)
        .map_err(|_| unavailable("COMM symbol is unavailable"))
}

unsafe extern "C" fn ipc_request(
    request: *const IpcRequest,
    context: *mut c_void,
    stop: *mut bool,
) -> *mut c_char {
    if request.is_null() || context.is_null() || stop.is_null() {
        return ptr::null_mut();
    }
    unsafe { *stop = false };
    let request = unsafe { &*request };
    let payload = match c_text(request.payload) {
        Ok(value) => value.as_bytes(),
        Err(_) => return ptr::null_mut(),
    };
    let application = unsafe { &*context.cast::<CommApplication>() };
    let identity = ConnectionIdentity {
        transport: "UNIX",
        source: None,
        peer: request
            .has_peer_credentials
            .then_some((request.peer_uid, request.peer_gid)),
        certificate: None,
    };
    let mut session = RuntimeSession::new(identity, unix_time(), application.maximum_lifetime);
    let response = process(&mut session, application, payload);
    CString::new(response).map_or(ptr::null_mut(), CString::into_raw)
}

unsafe extern "C" fn ipc_response_free(response: *mut c_char) {
    if !response.is_null() {
        drop(unsafe { CString::from_raw(response) });
    }
}

unsafe extern "C" fn transport_request(
    request: *const TransportRequest,
    response: *mut TransportResponse,
    context: *mut c_void,
) -> i32 {
    if request.is_null() || response.is_null() || context.is_null() {
        return -1;
    }
    let request = unsafe { &*request };
    let (Ok(sid), Ok(client_ip), Ok(transport), Ok(payload), Ok(cert)) = (
        c_text(request.sid),
        c_text(request.client_ip),
        c_text(request.transport),
        bytes(&request.payload),
        bytes(&request.cert),
    ) else {
        return -1;
    };
    let transport = transport.to_ascii_uppercase();
    let Ok(source) = client_ip.parse::<IpAddr>() else {
        return -1;
    };
    let application = unsafe { &*context.cast::<CommApplication>() };
    let certificate = if transport == "MTLS" {
        let (Some(tools), Some(chain)) =
            (&application.certificate_tools, &application.client_trust)
        else {
            return -1;
        };
        match tools.prepare_runtime_validation(cert, chain, unix_time()) {
            Ok(validation) => Some(validation.identity()),
            Err(_) => return -1,
        }
    } else {
        None
    };
    let Ok(mut sessions) = application.sessions.lock() else {
        return -1;
    };
    let session = sessions.entry(sid.to_owned()).or_insert_with(|| {
        RuntimeSession::new(
            ConnectionIdentity {
                transport: match transport.as_str() {
                    "TCP" => "TCP",
                    "TLS" => "TLS",
                    "MTLS" => "MTLS",
                    _ => "INVALID",
                },
                source: Some(source),
                peer: None,
                certificate,
            },
            unix_time(),
            application.maximum_lifetime,
        )
    });
    let result = session.process_frame(&application.context, payload, unix_time());
    let (payload, close, idle_timeout_ms, absolute_deadline_unix_ms) = match result {
        Ok(value) => (
            value.payload,
            value.close,
            value.idle_timeout_ms,
            value.absolute_deadline_unix_ms,
        ),
        Err(error) => {
            let operation = serde_json::from_slice::<RuntimeRequest>(payload)
                .map_or("UNKNOWN", |request| request.operation_name());
            match client_error_payload(operation, error) {
                Ok(payload) => (payload, true, 0, 0),
                Err(_) => return -1,
            }
        }
    };
    if close {
        sessions.remove(sid);
    }
    drop(sessions);
    let payload = payload.into_boxed_slice();
    let length = payload.len();
    let data = Box::into_raw(payload).cast::<u8>();
    unsafe {
        (*response).metadata = Bytes {
            data: ptr::null(),
            length: 0,
        };
        (*response).payload = Bytes { data, length };
        (*response).close = close;
        (*response).idle_timeout_ms = idle_timeout_ms;
        (*response).absolute_deadline_unix_ms = absolute_deadline_unix_ms;
    }
    0
}

unsafe extern "C" fn transport_response_free(
    response: *mut TransportResponse,
    _context: *mut c_void,
) {
    if response.is_null() {
        return;
    }
    let response = unsafe { &mut *response };
    if !response.payload.data.is_null() {
        let raw = ptr::slice_from_raw_parts_mut(
            response.payload.data.cast_mut(),
            response.payload.length,
        );
        drop(unsafe { Box::from_raw(raw) });
        response.payload.data = ptr::null();
        response.payload.length = 0;
    }
}

unsafe extern "C" fn transport_session_closed(sid: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let Ok(sid) = c_text(sid) else {
        return;
    };
    let application = unsafe { &*context.cast::<CommApplication>() };
    if let Ok(mut sessions) = application.sessions.lock() {
        sessions.remove(sid);
    }
}

fn process(session: &mut RuntimeSession, application: &CommApplication, payload: &[u8]) -> Vec<u8> {
    match session.process_frame(&application.context, payload, unix_time()) {
        Ok(response) => response.payload,
        Err(error) => {
            let operation = serde_json::from_slice::<RuntimeRequest>(payload)
                .map_or("UNKNOWN", |request| request.operation_name());
            client_error_payload(operation, error).unwrap_or_default()
        }
    }
}

fn bytes(value: &Bytes) -> Result<&[u8], ()> {
    if value.length == 0 {
        return Ok(&[]);
    }
    if value.data.is_null() {
        return Err(());
    }
    Ok(unsafe { slice::from_raw_parts(value.data, value.length) })
}

fn c_text<'a>(value: *const c_char) -> Result<&'a str, ()> {
    if value.is_null() {
        return Err(());
    }
    unsafe { CStr::from_ptr(value) }.to_str().map_err(|_| ())
}

fn comm_configuration(
    configuration: &ServerConfiguration,
) -> Result<serde_json::Value, ServiceError> {
    let mut structured = Vec::new();
    for transport in &configuration.runtime_transports {
        let (bind, mode) = match transport {
            RuntimeTransport::Unix => continue,
            RuntimeTransport::Tcp => (
                &configuration.tcp_address,
                serde_json::json!({"protocol":"tcp"}),
            ),
            RuntimeTransport::Tls => (
                &configuration.tls_address,
                serde_json::json!({
                    "protocol":"tls",
                    "cert": required(&configuration.server_certificate)?,
                    "key": required(&configuration.server_private_key)?,
                    "chain": required(&configuration.server_trust_chain)?
                }),
            ),
            RuntimeTransport::MutualTls => (
                &configuration.mtls_address,
                serde_json::json!({
                    "protocol":"mtls",
                    "cert": required(&configuration.server_certificate)?,
                    "key": required(&configuration.server_private_key)?,
                    "chain": required(&configuration.server_trust_chain)?,
                    "ca": required(&configuration.client_trust_chain)?
                }),
            ),
        };
        structured.push(serde_json::json!({
            "enabled":true,
            "bind":bind,
            "mode":mode,
            "worker_count":100,
            "waiting_count":200,
            "read_timeout_ms":1000,
            "write_timeout_ms":5000,
            "idle_timeout_ms":configuration.timeout_seconds.saturating_mul(1000),
            "max_metadata_bytes":16384,
            "max_payload_bytes":16 * 1024 * 1024,
            "frame":"length32"
        }));
    }
    let ipc = configuration
        .runtime_transports
        .contains(&RuntimeTransport::Unix)
        .then(|| {
            serde_json::json!({
                "enabled":true,
                "version":1,
                "socket_path":configuration.service_socket,
                "auth_code":false,
                "session_count":100,
                "waiting_count":200,
                "read_timeout_ms":35000,
                "write_timeout_ms":5000
            })
        });
    let certificate = if structured.iter().any(|value| {
        value
            .pointer("/mode/protocol")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| matches!(value, "tls" | "mtls"))
    }) {
        configuration.pki_client.as_ref().map(|client| {
            serde_json::json!({
                "enabled":true,
                "renewal_time":configuration.certificate_renewal_time.to_string(),
                "pki_client":client,
                "openssl":configuration.openssl,
                "ocsp_responder_override":configuration.ocsp_responder_override,
                "staging_directory":configuration.pki_staging_directory,
                "cert":configuration.server_certificate,
                "key":configuration.server_private_key,
                "trust":configuration.server_trust_chain
            })
        })
    } else {
        None
    };
    Ok(serde_json::json!({
        "library_directory":configuration.comm_library_directory,
        "ipc":ipc,
        "structured":structured,
        "certificate":certificate
    }))
}

fn required(value: &Option<PathBuf>) -> Result<&PathBuf, ServiceError> {
    value
        .as_ref()
        .ok_or_else(|| unavailable("COMM TLS path is missing"))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn unavailable(message: &'static str) -> ServiceError {
    ServiceError::service_unavailable(message)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::Arc,
        time::Duration,
    };

    use uuid::Uuid;

    use super::CommRuntime;
    use crate::{
        database_key_rotation::HsmDatabaseKeys,
        runtime_context::{RuntimeContextHandle, RuntimeServiceContext},
        server_configuration::ServerConfiguration,
        service_error::ServiceError,
        service_registry::{OperationClass, ServiceRegistry},
    };

    struct TestHsm([u8; 32]);

    impl HsmDatabaseKeys for TestHsm {
        fn current(&self) -> Result<[u8; 32], ServiceError> {
            Ok(self.0)
        }
        fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
            Ok(None)
        }
        fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
            Err(ServiceError::internal("unused test HSM operation"))
        }
        fn commit(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<(), ServiceError> {
            Err(ServiceError::internal("unused test HSM operation"))
        }
    }

    #[test]
    #[ignore = "requires the four locally built COMM dynamic libraries"]
    fn tcp_jwt_create_reaches_application_through_comm() {
        let library_directory = std::env::var("AUTOBRICKS_JWT_COMM_TEST_LIB_DIR")
            .expect("AUTOBRICKS_JWT_COMM_TEST_LIB_DIR must be configured");
        let probe = TcpListener::bind("127.0.0.1:0").expect("port probe");
        let address = probe.local_addr().expect("probe address");
        drop(probe);
        let root = std::env::temp_dir().join(format!("ab-jwt-comm-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("test directory");
        let database = root.join("jwt.db");
        let key = [0x91; 32];
        let (client_id, apikey) = {
            let mut registry =
                ServiceRegistry::open_sqlcipher(&database, &key).expect("test registry");
            let client_id = registry
                .register_client_with_configuration(
                    "comm-tcp-client",
                    OperationClass::Write,
                    "127.0.0.1/32",
                    vec!["TCP".into()],
                    30,
                    None,
                    None,
                )
                .expect("TCP client");
            let service = registry
                .register_service(client_id, "comm-tcp-service")
                .expect("TCP service");
            (client_id, service.apikey)
        };
        let context =
            RuntimeServiceContext::open(&database, &TestHsm(key), Duration::from_secs(300), true)
                .expect("runtime context");
        let configuration = ServerConfiguration::parse(&format!(
            "timeout: 30\nbackup_directory: {}\nlog_request: false\nlog_query: false\nlog_issuance: false\nlog_audit: false\ndatabase_path: {}\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test\nruntime_transports: TCP\ntcp_address: {}\ncomm_library_directory: {}\n",
            root.join("backup").display(),
            database.display(),
            address,
            library_directory
        ))
        .expect("test configuration");
        let runtime =
            CommRuntime::start(&configuration, Arc::new(RuntimeContextHandle::new(context)))
                .expect("COMM runtime");
        let mut client = TcpStream::connect(address).expect("COMM TCP listener");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let request = serde_json::to_vec(&serde_json::json!({
            "operation":"JWT_CREATE",
            "request":{
                "client_id":client_id,
                "apikey":apikey,
                "request_id":Uuid::new_v4(),
                "data":{"user_id":"comm-test"}
            }
        }))
        .expect("request JSON");
        client
            .write_all(&(request.len() as u32).to_be_bytes())
            .expect("frame length");
        client.write_all(&request).expect("request frame");
        let mut length = [0_u8; 4];
        client.read_exact(&mut length).expect("response length");
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        client.read_exact(&mut response).expect("response body");
        let response: serde_json::Value = serde_json::from_slice(&response).expect("JSON response");
        assert_eq!(response["status"], "SUCCESS");
        assert_eq!(response["operation"], "JWT_CREATE");
        runtime.shutdown().expect("COMM shutdown");
        fs::remove_dir_all(root).expect("test cleanup");
    }
}

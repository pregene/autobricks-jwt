use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    service_error::ServiceError, sqlcipher_token_repository::SqlCipherTokenRepository,
    truelog_audit::AuditRecorder, unix_socket::UnixSocketEndpoint,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInspectionResult {
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub service_id: Uuid,
    pub payload: Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInspectionRequest {
    pub request_id: Uuid,
    pub token_id: Uuid,
    pub event_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInspectionResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TokenInspectionResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u16>,
}

pub struct TokenInspectionService<'a> {
    tokens: &'a SqlCipherTokenRepository,
}

pub fn serve_inspection_socket<A: AuditRecorder>(
    socket_path: &Path,
    expected_peer_uid: u32,
    administrator_uid: u32,
    request_count: usize,
    tokens: &SqlCipherTokenRepository,
    audit: &mut A,
) -> Result<(), ServiceError> {
    let endpoint = UnixSocketEndpoint::bind(socket_path)?;
    for stream in endpoint.listener().incoming().take(request_count) {
        let mut stream = stream.map_err(|_| {
            ServiceError::service_unavailable("inspection connection cannot be accepted")
        })?;
        let response = if peer_uid(&stream) != Some(expected_peer_uid) {
            TokenInspectionResponse {
                status: "ERROR".into(),
                result: None,
                error_code: Some(8031),
            }
        } else {
            let request = read_request(&mut stream)?;
            match TokenInspectionService::new(tokens).inspect(
                administrator_uid,
                request.request_id,
                request.token_id,
                &request.event_at,
                audit,
            ) {
                Ok(result) => TokenInspectionResponse {
                    status: "SUCCESS".into(),
                    result: Some(result),
                    error_code: None,
                },
                Err(error) => TokenInspectionResponse {
                    status: "ERROR".into(),
                    result: None,
                    error_code: Some(error.code()),
                },
            }
        };
        let mut bytes = serde_json::to_vec(&response)
            .map_err(|_| ServiceError::internal("inspection response serialization failed"))?;
        bytes.push(b'\n');
        stream.write_all(&bytes).map_err(|_| {
            ServiceError::service_unavailable("inspection response cannot be written")
        })?;
    }
    Ok(())
}

pub fn request_inspection(
    socket_path: &Path,
    request: &TokenInspectionRequest,
) -> Result<TokenInspectionResponse, ServiceError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|_| ServiceError::service_unavailable("inspection socket cannot be connected"))?;
    let mut bytes = serde_json::to_vec(request)
        .map_err(|_| ServiceError::invalid_request("inspection request is invalid"))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(|_| ServiceError::service_unavailable("inspection request cannot be written"))?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|_| ServiceError::service_unavailable("inspection response cannot be read"))?;
    serde_json::from_str(&response)
        .map_err(|_| ServiceError::service_unavailable("inspection response is invalid"))
}

fn read_request(stream: &mut UnixStream) -> Result<TokenInspectionRequest, ServiceError> {
    let mut frame = String::new();
    BufReader::new(stream)
        .read_line(&mut frame)
        .map_err(|_| ServiceError::invalid_request("inspection request cannot be read"))?;
    if frame.len() > 4096 || !frame.ends_with('\n') {
        return Err(ServiceError::invalid_request(
            "inspection request frame is invalid",
        ));
    }
    serde_json::from_str(&frame)
        .map_err(|_| ServiceError::invalid_request("inspection request is invalid"))
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    peer_uid_for_fd(stream.as_raw_fd())
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_uid_for_fd(file_descriptor: std::os::fd::RawFd) -> Option<u32> {
    let mut user_id: libc::uid_t = 0;
    let mut group_id: libc::gid_t = 0;
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

impl<'a> TokenInspectionService<'a> {
    pub fn new(tokens: &'a SqlCipherTokenRepository) -> Self {
        Self { tokens }
    }

    pub fn inspect<A: AuditRecorder>(
        &self,
        peer_uid: u32,
        request_id: Uuid,
        token_id: Uuid,
        event_at: &str,
        audit: &mut A,
    ) -> Result<TokenInspectionResult, ServiceError> {
        if peer_uid != 0 {
            return Err(ServiceError::classified(
                8031,
                "privileged token inspection requires root",
            )
            .expect("8031 must be assigned"));
        }
        let record = self
            .tokens
            .load_by_correlation(request_id, token_id)?
            .ok_or_else(|| {
                ServiceError::classified(8060, "session is not found or expired")
                    .expect("8060 must be assigned")
            })?;
        let payload = record.token.inspect_payload()?;
        audit.privileged_inspection(record.service_id, request_id, token_id, peer_uid, event_at)?;
        Ok(TokenInspectionResult {
            request_id,
            token_id,
            service_id: record.service_id,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::mpsc, thread, time::Duration,
    };

    use serde_json::{Map, Value};

    use crate::{
        issuance_service::{IssuanceService, JwtCreateRequest},
        service_registry::{OperationClass, ServiceRegistry},
    };

    use super::*;

    #[derive(Default)]
    struct InspectionAudit {
        events: Vec<(Uuid, Uuid, Uuid, u32)>,
    }

    impl AuditRecorder for InspectionAudit {
        fn issued(
            &mut self,
            _service_id: Uuid,
            _subject_type: &str,
            _request_id: Uuid,
            _token_id: Uuid,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }

        fn invalid_session(
            &mut self,
            _service_id: Uuid,
            _request_id: Uuid,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            unreachable!()
        }

        fn privileged_inspection(
            &mut self,
            service_id: Uuid,
            request_id: Uuid,
            token_id: Uuid,
            administrator_uid: u32,
            _event_at: &str,
        ) -> Result<(), ServiceError> {
            self.events
                .push((service_id, request_id, token_id, administrator_uid));
            Ok(())
        }
    }

    #[test]
    fn root_inspects_historical_payload_by_both_correlations_and_records_audit() {
        let path = std::env::temp_dir().join(format!("ab-jwt-inspection-{}.db", Uuid::new_v4()));
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xb1; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("inspection-writer", OperationClass::Write)
            .unwrap();
        let credential = registry
            .register_service(client_id, "inspection-service")
            .unwrap();
        let request_id = Uuid::new_v4();
        let response = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id,
                    apikey: credential.apikey,
                    request_id,
                    data: Map::from_iter([
                        ("user_id".into(), Value::String("user-inspect".into())),
                        ("role".into(), Value::String("administrator".into())),
                    ]),
                },
                1_000,
            )
            .unwrap();
        tokens.revoke_active(response.token_id).unwrap();
        let mut audit = InspectionAudit::default();
        let result = TokenInspectionService::new(&tokens)
            .inspect(
                0,
                request_id,
                response.token_id,
                "2026-10-11T02:00:00Z",
                &mut audit,
            )
            .unwrap();
        assert_eq!(result.payload["sub"], "user-inspect");
        assert_eq!(result.payload["claims"]["role"], "administrator");
        assert_eq!(audit.events.len(), 1);
        assert_eq!(audit.events[0].1, request_id);
        assert_eq!(audit.events[0].2, response.token_id);
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn non_root_and_mismatched_correlation_cannot_inspect() {
        let path =
            std::env::temp_dir().join(format!("ab-jwt-inspection-deny-{}.db", Uuid::new_v4()));
        let tokens = SqlCipherTokenRepository::open(&path, &[0xb2; 32]).unwrap();
        let mut audit = InspectionAudit::default();
        let service = TokenInspectionService::new(&tokens);
        assert_eq!(
            service
                .inspect(
                    501,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    "2026-10-11T02:00:00Z",
                    &mut audit,
                )
                .unwrap_err()
                .code(),
            8031
        );
        assert_eq!(
            service
                .inspect(
                    0,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    "2026-10-11T02:00:00Z",
                    &mut audit,
                )
                .unwrap_err()
                .code(),
            8060
        );
        assert!(audit.events.is_empty());
        drop(tokens);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn privileged_inspection_round_trips_only_over_local_unix_socket() {
        let root = PathBuf::from(format!("/tmp/ab-jwt-inspect-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let socket = root.join("inspect.sock");
        let path = root.join("tokens.db");
        let mut tokens = SqlCipherTokenRepository::open(&path, &[0xb3; 32]).unwrap();
        let mut registry = ServiceRegistry::default();
        let client_id = registry
            .register_client("socket-inspection-writer", OperationClass::Write)
            .unwrap();
        let credential = registry
            .register_service(client_id, "socket-inspection-service")
            .unwrap();
        let request_id = Uuid::new_v4();
        let response = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
            .unwrap()
            .create(
                JwtCreateRequest {
                    client_id,
                    apikey: credential.apikey,
                    request_id,
                    data: Map::from_iter([(
                        "user_id".into(),
                        Value::String("user-socket-inspect".into()),
                    )]),
                },
                1_000,
            )
            .unwrap();
        let peer_uid = unsafe { libc::geteuid() };
        let (ready_tx, ready_rx) = mpsc::channel();
        let socket_for_server = socket.clone();
        let server = thread::spawn(move || {
            let mut audit = InspectionAudit::default();
            ready_tx.send(()).unwrap();
            serve_inspection_socket(&socket_for_server, peer_uid, 0, 1, &tokens, &mut audit)
                .unwrap();
            audit
        });
        ready_rx.recv().unwrap();
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let inspected = request_inspection(
            &socket,
            &TokenInspectionRequest {
                request_id,
                token_id: response.token_id,
                event_at: "2026-10-11T02:01:00Z".into(),
            },
        )
        .unwrap();
        assert_eq!(inspected.status, "SUCCESS");
        assert_eq!(
            inspected.result.unwrap().payload["sub"],
            "user-socket-inspect"
        );
        assert_eq!(server.join().unwrap().events.len(), 1);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

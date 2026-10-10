use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    audit_log_repository::{AuditLogFilter, AuditLogRecord, AuditLogRepository},
    service_error::ServiceError,
    unix_socket::UnixSocketEndpoint,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditQueryResponse {
    pub status: String,
    pub records: Vec<AuditLogRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<u16>,
}

pub fn serve_audit_query_socket(
    socket_path: &Path,
    expected_peer_uid: u32,
    request_count: usize,
    repository: &AuditLogRepository,
) -> Result<(), ServiceError> {
    let endpoint = UnixSocketEndpoint::bind(socket_path)?;
    for stream in endpoint.listener().incoming().take(request_count) {
        let mut stream = stream.map_err(|_| {
            ServiceError::service_unavailable("audit query connection cannot be accepted")
        })?;
        let response = if peer_uid(&stream) != Some(expected_peer_uid) {
            AuditQueryResponse {
                status: "ERROR".into(),
                records: vec![],
                error_code: Some(8031),
            }
        } else {
            match read_filter(&mut stream).and_then(|filter| {
                repository
                    .query(&filter)
                    .map_err(|_| ServiceError::invalid_request("audit query filter is invalid"))
            }) {
                Ok(records) => AuditQueryResponse {
                    status: "SUCCESS".into(),
                    records,
                    error_code: None,
                },
                Err(error) => AuditQueryResponse {
                    status: "ERROR".into(),
                    records: vec![],
                    error_code: Some(error.code()),
                },
            }
        };
        let mut output = serde_json::to_vec(&response)
            .map_err(|_| ServiceError::internal("audit query response serialization failed"))?;
        output.push(b'\n');
        stream.write_all(&output).map_err(|_| {
            ServiceError::service_unavailable("audit query response cannot be written")
        })?;
    }
    Ok(())
}

pub fn request_audit_query(
    socket_path: &Path,
    filter: &AuditLogFilter,
) -> Result<AuditQueryResponse, ServiceError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|_| ServiceError::service_unavailable("audit query socket cannot be connected"))?;
    let mut input = serde_json::to_vec(filter)
        .map_err(|_| ServiceError::invalid_request("audit query filter is invalid"))?;
    input.push(b'\n');
    stream
        .write_all(&input)
        .map_err(|_| ServiceError::service_unavailable("audit query request cannot be written"))?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|_| ServiceError::service_unavailable("audit query response cannot be read"))?;
    serde_json::from_str(&response)
        .map_err(|_| ServiceError::service_unavailable("audit query response is invalid"))
}

fn read_filter(stream: &mut UnixStream) -> Result<AuditLogFilter, ServiceError> {
    let mut frame = String::new();
    BufReader::new(stream)
        .read_line(&mut frame)
        .map_err(|_| ServiceError::invalid_request("audit query request cannot be read"))?;
    if frame.len() > 8192 || !frame.ends_with('\n') {
        return Err(ServiceError::invalid_request(
            "audit query request frame is invalid",
        ));
    }
    serde_json::from_str(&frame)
        .map_err(|_| ServiceError::invalid_request("audit query filter is invalid"))
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, thread, time::Duration};

    use uuid::Uuid;

    use crate::audit_log_repository::AuditLogRecord;

    use super::*;

    #[test]
    fn filters_local_records_over_protected_unix_socket() {
        let root = PathBuf::from(format!("/tmp/ab-jwt-audit-query-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let database = root.join("audit.db");
        let socket = root.join("audit.sock");
        let mut repository = AuditLogRepository::open(&database, &[0xc1; 32]).unwrap();
        for (event, state, code) in [
            ("JWT_ISSUED", "PENDING", None),
            ("JWT_SESSION_INVALID", "PENDING", Some(8060)),
        ] {
            repository
                .store_pending(&AuditLogRecord {
                    audit_id: Uuid::new_v4(),
                    event: event.into(),
                    event_at: "2026-10-11T03:00:00Z".into(),
                    service_id: "service-1".into(),
                    subject_type: None,
                    result: if code.is_some() { "ERROR" } else { "SUCCESS" }.into(),
                    error_code: code,
                    error: None,
                    request_id: None,
                    token_id: None,
                    administrator_uid: None,
                    receipt_state: state.into(),
                    receipt: None,
                })
                .unwrap();
        }
        let peer_uid = unsafe { libc::geteuid() };
        let socket_for_server = socket.clone();
        let server = thread::spawn(move || {
            serve_audit_query_socket(&socket_for_server, peer_uid, 1, &repository).unwrap()
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let response = request_audit_query(
            &socket,
            &AuditLogFilter {
                event: Some("JWT_SESSION_INVALID".into()),
                receipt_state: Some("PENDING".into()),
                from_event_at: Some("2026-10-11T00:00:00Z".into()),
                to_event_at: Some("2026-10-11T23:59:59Z".into()),
                service_id: Some("service-1".into()),
                result: Some("ERROR".into()),
                error_code: Some(8060),
                limit: 100,
            },
        )
        .unwrap();
        assert_eq!(response.status, "SUCCESS");
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.records[0].event, "JWT_SESSION_INVALID");
        server.join().unwrap();
        fs::remove_file(database).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_invalid_state_and_unbounded_limit() {
        let path = std::env::temp_dir().join(format!("ab-jwt-audit-filter-{}.db", Uuid::new_v4()));
        let repository = AuditLogRepository::open(&path, &[0xc2; 32]).unwrap();
        for filter in [
            AuditLogFilter {
                receipt_state: Some("UNKNOWN".into()),
                limit: 10,
                ..Default::default()
            },
            AuditLogFilter {
                limit: 0,
                ..Default::default()
            },
        ] {
            assert!(repository.query(&filter).is_err());
        }
        drop(repository);
        fs::remove_file(path).unwrap();
    }
}

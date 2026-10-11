use std::{
    io::{ErrorKind, Read, Write},
    net::IpAddr,
    sync::Arc,
};

use serde_json::json;
use uuid::Uuid;

use crate::{
    connection_policy::{ConnectionLease, ConnectionPolicy},
    framed_connection::MAX_SERVICE_FRAME,
    operational_logger::{OperationalLogger, SyslogSink},
    runtime_context::{PresentedCertificateIdentity, RuntimeContextHandle},
    runtime_protocol::RuntimeRequest,
    service_error::{ClientDisposition, ServiceError},
};

#[derive(Clone, Debug)]
pub struct ConnectionIdentity {
    pub transport: &'static str,
    pub source: Option<IpAddr>,
    pub peer: Option<(u32, u32)>,
    pub certificate: Option<PresentedCertificateIdentity>,
}

pub fn process_runtime_connection<S, C, V, K>(
    stream: &mut S,
    context: &Arc<RuntimeContextHandle>,
    identity: &ConnectionIdentity,
    maximum_lifetime: u64,
    mut clock: C,
    mut revalidate: V,
    mut keep_running: K,
) -> Result<usize, ServiceError>
where
    S: Read + Write,
    C: FnMut() -> u64,
    V: FnMut() -> Result<(), ServiceError>,
    K: FnMut() -> bool,
{
    log_connection(identity, true, None);
    let opened_at = clock();
    let mut lease: Option<ConnectionLease> = None;
    let mut bound_client: Option<Uuid> = None;
    let mut processed = 0;
    loop {
        let mut length = [0_u8; 4];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(processed),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                let now = clock();
                if !keep_running() {
                    return Ok(processed);
                }
                if let Some(lease) = lease.as_ref() {
                    lease.ensure_open(now)?;
                } else if now.saturating_sub(opened_at) >= maximum_lifetime {
                    return Err(classified(8025, "connection lifetime exceeded"));
                }
                continue;
            }
            Err(_) => return Err(classified(8005, "service frame header is malformed")),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_SERVICE_FRAME {
            return Err(classified(
                if length == 0 { 8005 } else { 8004 },
                "service frame length is invalid",
            ));
        }
        let mut frame = vec![0_u8; length];
        stream
            .read_exact(&mut frame)
            .map_err(|_| classified(8005, "service frame body is malformed"))?;
        let request: RuntimeRequest = serde_json::from_slice(&frame)
            .map_err(|_| classified(8005, "service frame request is malformed"))?;
        let _permit = context.begin_request()?;
        revalidate()?;
        let active_context = context.current()?;
        if let RuntimeRequest::CertificateActivate(activation) = &request {
            let now = clock();
            let authorization = match active_context.activate_initial_certificate(
                activation,
                identity.transport,
                identity.source,
                identity.certificate.as_ref(),
                now,
            ) {
                Ok(value) => value,
                Err(error) => {
                    log_connection(identity, false, None);
                    log_error(&error);
                    write_client_error(stream, request.operation_name(), error)?;
                    return Ok(processed);
                }
            };
            bind_connection(
                &mut lease,
                &mut bound_client,
                identity,
                authorization,
                opened_at,
                maximum_lifetime,
            )?;
            lease.as_mut().expect("lease created").begin_request(now)?;
            let response = serde_json::to_vec(&json!({
                "status": "SUCCESS",
                "operation": "CERTIFICATE_ACTIVATE",
                "result": { "certificate_status": "ACTIVE" }
            }))
            .map_err(|_| {
                ServiceError::internal("certificate activation response cannot be encoded")
            })?;
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .and_then(|_| stream.write_all(&response))
                .and_then(|_| stream.flush())
                .map_err(|_| ServiceError::service_unavailable("service response write failed"))?;
            processed += 1;
            continue;
        }
        let authorization = match active_context.authorize_runtime_request(
            &request,
            identity.transport,
            identity.source,
            identity.peer,
            identity.certificate.as_ref(),
        ) {
            Ok(value) => value,
            Err(error) => {
                log_connection(identity, false, None);
                log_error(&error);
                write_client_error(stream, request.operation_name(), error)?;
                return Ok(processed);
            }
        };
        bind_connection(
            &mut lease,
            &mut bound_client,
            identity,
            authorization,
            opened_at,
            maximum_lifetime,
        )?;
        let now = clock();
        lease.as_mut().expect("lease created").begin_request(now)?;
        let response = active_context.dispatch_frame(&frame, now)?;
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .and_then(|_| stream.flush())
            .map_err(|_| ServiceError::service_unavailable("service response write failed"))?;
        processed += 1;
    }
}

fn log_connection(identity: &ConnectionIdentity, accepted: bool, client_id: Option<Uuid>) {
    let source = identity
        .source
        .map(|value| value.to_string())
        .or_else(|| {
            identity
                .peer
                .map(|(uid, gid)| format!("uid={uid},gid={gid}"))
        })
        .unwrap_or_else(|| "unavailable".into());
    OperationalLogger::new(SyslogSink).connection_access(
        accepted,
        identity.transport,
        &source,
        client_id,
        &event_time(),
    );
}

fn log_error(error: &ServiceError) {
    OperationalLogger::new(SyslogSink).classified_error(error, &event_time());
}

fn event_time() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let raw = seconds as libc::time_t;
    let mut value = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::gmtime_r(&raw, &mut value) }.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
    )
}

fn bind_connection(
    lease: &mut Option<ConnectionLease>,
    bound_client: &mut Option<Uuid>,
    identity: &ConnectionIdentity,
    authorization: crate::runtime_context::RuntimeAuthorization,
    opened_at: u64,
    maximum_lifetime: u64,
) -> Result<(), ServiceError> {
    if bound_client.is_some_and(|client_id| client_id != authorization.client_id) {
        return Err(classified(8023, "connection client identity changed"));
    }
    if lease.is_none() {
        let source = identity
            .source
            .unwrap_or_else(|| "127.0.0.1".parse().expect("loopback"));
        let cidr = if source.is_ipv4() {
            format!("{source}/32")
        } else {
            format!("{source}/128")
        };
        *lease =
            Some(
                ConnectionPolicy::new(&cidr, authorization.idle_timeout, maximum_lifetime)?
                    .accept(source, opened_at, authorization.certificate_not_after)?,
            );
        *bound_client = Some(authorization.client_id);
    }
    Ok(())
}

fn write_client_error<S: Write>(
    stream: &mut S,
    operation: &str,
    error: ServiceError,
) -> Result<(), ServiceError> {
    let ClientDisposition::Respond(error) = error.client_disposition() else {
        return Err(error);
    };
    let response = serde_json::to_vec(&json!({
        "status": "ERROR",
        "operation": operation,
        "error": {
            "code": error.code(),
            "name": error.name(),
            "message": error.public_message()
        }
    }))
    .map_err(|_| ServiceError::internal("runtime error response cannot be encoded"))?;
    stream
        .write_all(&(response.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&response))
        .and_then(|_| stream.flush())
        .map_err(|_| ServiceError::service_unavailable("service error response write failed"))
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("assigned runtime error")
}

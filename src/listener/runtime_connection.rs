use std::{net::IpAddr, sync::Arc};

use serde_json::json;
use uuid::Uuid;

use crate::{
    connection_policy::{ConnectionLease, ConnectionPolicy},
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

pub struct RuntimeSession {
    identity: ConnectionIdentity,
    opened_at: u64,
    maximum_lifetime: u64,
    lease: Option<ConnectionLease>,
    bound_client: Option<Uuid>,
}

pub struct RuntimeFrameResponse {
    pub payload: Vec<u8>,
    pub close: bool,
    pub idle_timeout_ms: u64,
    pub absolute_deadline_unix_ms: u64,
}

impl RuntimeSession {
    pub fn new(identity: ConnectionIdentity, opened_at: u64, maximum_lifetime: u64) -> Self {
        log_connection(&identity, true, None);
        Self {
            identity,
            opened_at,
            maximum_lifetime,
            lease: None,
            bound_client: None,
        }
    }

    pub fn process_frame(
        &mut self,
        context: &Arc<RuntimeContextHandle>,
        frame: &[u8],
        now: u64,
    ) -> Result<RuntimeFrameResponse, ServiceError> {
        let request: RuntimeRequest = serde_json::from_slice(frame)
            .map_err(|_| classified(8005, "service frame request is malformed"))?;
        let _permit = context.begin_request()?;
        let active_context = context.current()?;
        let response = if let RuntimeRequest::CertificateActivate(activation) = &request {
            let authorization = active_context
                .activate_initial_certificate(
                    activation,
                    self.identity.transport,
                    self.identity.source,
                    self.identity.certificate.as_ref(),
                    now,
                )
                .map_err(|error| self.rejected(error))?;
            bind_connection(
                &mut self.lease,
                &mut self.bound_client,
                &self.identity,
                authorization,
                self.opened_at,
                self.maximum_lifetime,
            )?;
            self.lease
                .as_mut()
                .ok_or_else(|| ServiceError::internal("connection lease is unavailable"))?
                .begin_request(now)?;
            serde_json::to_vec(&json!({
                "status": "SUCCESS",
                "operation": "CERTIFICATE_ACTIVATE",
                "result": { "certificate_status": "ACTIVE" }
            }))
            .map_err(|_| {
                ServiceError::internal("certificate activation response cannot be encoded")
            })?
        } else {
            let authorization = active_context
                .authorize_runtime_request(
                    &request,
                    self.identity.transport,
                    self.identity.source,
                    self.identity.peer,
                    self.identity.certificate.as_ref(),
                )
                .map_err(|error| self.rejected(error))?;
            bind_connection(
                &mut self.lease,
                &mut self.bound_client,
                &self.identity,
                authorization,
                self.opened_at,
                self.maximum_lifetime,
            )?;
            self.lease
                .as_mut()
                .ok_or_else(|| ServiceError::internal("connection lease is unavailable"))?
                .begin_request(now)?;
            active_context.dispatch_frame(frame, now)?
        };
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| ServiceError::internal("connection lease is unavailable"))?;
        Ok(RuntimeFrameResponse {
            payload: response,
            close: false,
            idle_timeout_ms: lease
                .idle_deadline()
                .saturating_sub(now)
                .saturating_mul(1_000),
            absolute_deadline_unix_ms: lease.connection_deadline().saturating_mul(1_000),
        })
    }

    fn rejected(&self, error: ServiceError) -> ServiceError {
        log_connection(&self.identity, false, None);
        OperationalLogger::new(SyslogSink).classified_error(&error, &event_time());
        error
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
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
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

pub fn client_error_payload(operation: &str, error: ServiceError) -> Result<Vec<u8>, ServiceError> {
    let ClientDisposition::Respond(error) = error.client_disposition() else {
        return Err(error);
    };
    serde_json::to_vec(&json!({
        "status": "ERROR",
        "operation": operation,
        "error": {
            "code": error.code(),
            "name": error.name(),
            "message": error.public_message()
        }
    }))
    .map_err(|_| ServiceError::internal("runtime error response cannot be encoded"))
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::assigned(code, message)
}

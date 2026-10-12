use std::{
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::{
    mtls_listener,
    operational_logger::{OperationalLogger, SyslogSink},
    runtime_connection::{ConnectionIdentity, process_runtime_connection},
    runtime_context::RuntimeContextHandle,
    server_configuration::{RuntimeTransport, ServerConfiguration},
    service_certificate::CertificateTools,
    service_error::ServiceError,
    tcp_listener::TcpListenerEndpoint,
    tls_listener,
    unix_socket::UnixSocketEndpoint,
};

pub struct RuntimeListenerSet {
    _unix: Option<UnixSocketEndpoint>,
    _tcp: Option<TcpListenerEndpoint>,
    _tls: Option<(TcpListenerEndpoint, Arc<ServerConfig>)>,
    _mtls: Option<(TcpListenerEndpoint, Arc<ServerConfig>)>,
    enabled: Vec<RuntimeTransport>,
}

pub struct RuntimeListenerRuntime {
    accepting: Arc<AtomicBool>,
    accept_threads: Vec<JoinHandle<()>>,
    connection_threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl RuntimeListenerSet {
    pub fn bind(configuration: &ServerConfiguration) -> Result<Self, ServiceError> {
        let mut listeners = Self {
            _unix: None,
            _tcp: None,
            _tls: None,
            _mtls: None,
            enabled: configuration.runtime_transports.clone(),
        };
        for transport in &configuration.runtime_transports {
            match transport {
                RuntimeTransport::Unix => {
                    listeners._unix =
                        Some(UnixSocketEndpoint::bind(&configuration.service_socket)?);
                }
                RuntimeTransport::Tcp => {
                    listeners._tcp = Some(TcpListenerEndpoint::bind(&configuration.tcp_address)?);
                }
                RuntimeTransport::Tls => {
                    let identity = tls_listener::server_configuration(
                        required(&configuration.server_certificate)?,
                        required(&configuration.server_private_key)?,
                        required(&configuration.server_trust_chain)?,
                    )?;
                    listeners._tls = Some((
                        TcpListenerEndpoint::bind(&configuration.tls_address)?,
                        identity,
                    ));
                }
                RuntimeTransport::MutualTls => {
                    let identity = mtls_listener::server_configuration(
                        required(&configuration.server_certificate)?,
                        required(&configuration.server_private_key)?,
                        required(&configuration.server_trust_chain)?,
                        required(&configuration.client_trust_chain)?,
                    )?;
                    listeners._mtls = Some((
                        TcpListenerEndpoint::bind(&configuration.mtls_address)?,
                        identity,
                    ));
                }
            }
        }
        Ok(listeners)
    }

    pub fn enabled(&self) -> &[RuntimeTransport] {
        &self.enabled
    }

    pub fn start(
        mut self,
        context: Arc<RuntimeContextHandle>,
        maximum_lifetime: u64,
        certificate_tools: Option<CertificateTools>,
        client_trust_chain: Option<std::path::PathBuf>,
    ) -> Result<RuntimeListenerRuntime, ServiceError> {
        let accepting = Arc::new(AtomicBool::new(true));
        let connection_threads = Arc::new(Mutex::new(Vec::new()));
        let mut accept_threads = Vec::new();
        if let Some(endpoint) = self._unix.take() {
            endpoint.listener().set_nonblocking(true).map_err(|_| {
                ServiceError::service_unavailable("Unix listener cannot enter runtime mode")
            })?;
            let flag = Arc::clone(&accepting);
            let context = Arc::clone(&context);
            let workers = Arc::clone(&connection_threads);
            accept_threads.push(thread::spawn(move || {
                while flag.load(Ordering::Acquire) {
                    match endpoint.listener().accept() {
                        Ok((stream, _)) => {
                            let peer = UnixSocketEndpoint::peer_credentials(&stream).ok();
                            let identity = ConnectionIdentity {
                                transport: "UNIX",
                                source: None,
                                peer,
                                certificate: None,
                            };
                            let context = Arc::clone(&context);
                            let worker_flag = Arc::clone(&flag);
                            let worker = thread::spawn(move || {
                                let mut stream = stream;
                                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                                let _ = process_runtime_connection(
                                    &mut stream,
                                    &context,
                                    &identity,
                                    maximum_lifetime,
                                    unix_time,
                                    || Ok(()),
                                    || worker_flag.load(Ordering::Acquire),
                                );
                            });
                            retain_and_push(&workers, worker);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            }));
        }
        if let Some(endpoint) = self._tcp.take() {
            accept_threads.push(start_tcp(
                endpoint,
                None,
                "TCP",
                Arc::clone(&context),
                Arc::clone(&accepting),
                maximum_lifetime,
                Arc::clone(&connection_threads),
            )?);
        }
        if let Some((endpoint, tls)) = self._tls.take() {
            accept_threads.push(start_tcp(
                endpoint,
                Some(tls),
                "TLS",
                Arc::clone(&context),
                Arc::clone(&accepting),
                maximum_lifetime,
                Arc::clone(&connection_threads),
            )?);
        }
        if let Some((endpoint, tls)) = self._mtls.take() {
            let tools = certificate_tools.ok_or_else(|| {
                ServiceError::configuration_invalid("mTLS runtime requires a configured PKI client")
            })?;
            let chain = client_trust_chain.ok_or_else(|| {
                ServiceError::configuration_invalid("mTLS runtime requires a client trust chain")
            })?;
            endpoint.listener().set_nonblocking(true).map_err(|_| {
                ServiceError::service_unavailable("mTLS listener cannot enter runtime mode")
            })?;
            let flag = Arc::clone(&accepting);
            let context = Arc::clone(&context);
            let workers = Arc::clone(&connection_threads);
            accept_threads.push(thread::spawn(move || {
                while flag.load(Ordering::Acquire) {
                    match endpoint.listener().accept() {
                        Ok((tcp, peer)) => {
                            let context = Arc::clone(&context);
                            let tls = Arc::clone(&tls);
                            let tools = tools.clone();
                            let chain = chain.clone();
                            let worker_flag = Arc::clone(&flag);
                            let worker = thread::spawn(move || {
                                let mut tcp = tcp;
                                if tcp.set_nonblocking(false).is_err() {
                                    log_listener_error(&classified(
                                        8009,
                                        "mTLS connection cannot enter handshake mode",
                                    ));
                                    return;
                                }
                                let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
                                let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
                                let mut connection = match ServerConnection::new(tls) {
                                    Ok(connection) => connection,
                                    Err(_) => {
                                        log_listener_error(&classified(
                                            8009,
                                            "mTLS server state cannot be created",
                                        ));
                                        return;
                                    }
                                };
                                while connection.is_handshaking() {
                                    if let Err(error) = connection.complete_io(&mut tcp) {
                                        if !connection.is_handshaking() {
                                            break;
                                        }
                                        let code = if matches!(
                                            error.kind(),
                                            std::io::ErrorKind::TimedOut
                                                | std::io::ErrorKind::WouldBlock
                                        ) {
                                            8006
                                        } else {
                                            8011
                                        };
                                        log_listener_error(&classified(
                                            code,
                                            "mTLS handshake failed",
                                        ));
                                        return;
                                    }
                                }
                                let Some(der) = connection
                                    .peer_certificates()
                                    .and_then(|certificates| certificates.first())
                                else {
                                    log_listener_error(&classified(
                                        8010,
                                        "mTLS client certificate is required",
                                    ));
                                    return;
                                };
                                let validation = match tools.prepare_runtime_validation(
                                    der.as_ref(),
                                    &chain,
                                    unix_time(),
                                ) {
                                    Ok(validation) => validation,
                                    Err(error) => {
                                        log_listener_error(&error);
                                        return;
                                    }
                                };
                                let identity = ConnectionIdentity {
                                    transport: "MTLS",
                                    source: Some(peer.ip()),
                                    peer: None,
                                    certificate: Some(validation.identity()),
                                };
                                let _ = tcp.set_read_timeout(Some(Duration::from_secs(1)));
                                let mut stream = StreamOwned::new(connection, tcp);
                                let _ = process_runtime_connection(
                                    &mut stream,
                                    &context,
                                    &identity,
                                    maximum_lifetime,
                                    unix_time,
                                    || validation.revalidate(),
                                    || worker_flag.load(Ordering::Acquire),
                                );
                            });
                            retain_and_push(&workers, worker);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            }));
        }
        Ok(RuntimeListenerRuntime {
            accepting,
            accept_threads,
            connection_threads,
        })
    }
}

impl RuntimeListenerRuntime {
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::Release);
    }

    pub fn shutdown(mut self) -> Result<(), ServiceError> {
        self.stop_accepting();
        for thread in self.accept_threads.drain(..) {
            thread.join().map_err(|_| {
                ServiceError::service_unavailable("runtime listener did not stop cleanly")
            })?;
        }
        let workers = std::mem::take(&mut *self.connection_threads.lock().map_err(|_| {
            ServiceError::service_unavailable("runtime connection registry is unavailable")
        })?);
        for worker in workers {
            worker.join().map_err(|_| {
                ServiceError::service_unavailable("runtime connection did not stop cleanly")
            })?;
        }
        Ok(())
    }
}

impl Drop for RuntimeListenerRuntime {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
    }
}

fn start_tcp(
    endpoint: TcpListenerEndpoint,
    tls: Option<Arc<ServerConfig>>,
    transport: &'static str,
    context: Arc<RuntimeContextHandle>,
    accepting: Arc<AtomicBool>,
    maximum_lifetime: u64,
    connection_threads: Arc<Mutex<Vec<JoinHandle<()>>>>,
) -> Result<JoinHandle<()>, ServiceError> {
    endpoint
        .listener()
        .set_nonblocking(true)
        .map_err(|_| ServiceError::service_unavailable("TCP listener cannot enter runtime mode"))?;
    Ok(thread::spawn(move || {
        while accepting.load(Ordering::Acquire) {
            match endpoint.listener().accept() {
                Ok((stream, peer)) => {
                    let identity = ConnectionIdentity {
                        transport,
                        source: Some(peer.ip()),
                        peer: None,
                        certificate: None,
                    };
                    let context = Arc::clone(&context);
                    let configuration = tls.clone();
                    let worker_flag = Arc::clone(&accepting);
                    let worker = thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                        if let Some(configuration) = configuration {
                            if let Ok(connection) = ServerConnection::new(configuration) {
                                let mut stream = StreamOwned::new(connection, stream);
                                let _ = process_runtime_connection(
                                    &mut stream,
                                    &context,
                                    &identity,
                                    maximum_lifetime,
                                    unix_time,
                                    || Ok(()),
                                    || worker_flag.load(Ordering::Acquire),
                                );
                            }
                        } else {
                            serve_tcp(stream, &context, &identity, maximum_lifetime, &worker_flag);
                        }
                    });
                    retain_and_push(&connection_threads, worker);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    }))
}

fn retain_and_push(threads: &Arc<Mutex<Vec<JoinHandle<()>>>>, worker: JoinHandle<()>) {
    if let Ok(mut threads) = threads.lock() {
        let mut index = 0;
        while index < threads.len() {
            if threads[index].is_finished() {
                let finished = threads.swap_remove(index);
                let _ = finished.join();
            } else {
                index += 1;
            }
        }
        threads.push(worker);
    }
}

fn serve_tcp(
    mut stream: TcpStream,
    context: &Arc<RuntimeContextHandle>,
    identity: &ConnectionIdentity,
    maximum_lifetime: u64,
    accepting: &Arc<AtomicBool>,
) {
    let _ = process_runtime_connection(
        &mut stream,
        context,
        identity,
        maximum_lifetime,
        unix_time,
        || Ok(()),
        || accepting.load(Ordering::Acquire),
    );
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn log_listener_error(error: &ServiceError) {
    OperationalLogger::new(SyslogSink).classified_error(error, &event_time());
}

fn event_time() -> String {
    let raw = unix_time() as libc::time_t;
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

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::assigned(code, message)
}

fn required(value: &Option<std::path::PathBuf>) -> Result<&std::path::Path, ServiceError> {
    value
        .as_deref()
        .ok_or_else(|| ServiceError::configuration_invalid("secure listener credential is missing"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use uuid::Uuid;

    use crate::server_configuration::{RuntimeTransport, ServerConfiguration};

    use super::RuntimeListenerSet;

    #[test]
    #[ignore = "requires local Autobricks PKI certificates and listener sockets"]
    fn binds_exactly_the_four_configured_runtime_transports() {
        let short_id = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from(format!("/tmp/abjwt-{}", &short_id[..12]));
        let socket = root.join("service.sock");
        let certificate = required_path("AUTOBRICKS_JWT_TEST_SERVER_CERTIFICATE");
        let private_key = required_path("AUTOBRICKS_JWT_TEST_SERVER_PRIVATE_KEY");
        let trust_chain = required_path("AUTOBRICKS_JWT_TEST_TRUST_CHAIN");
        let configuration = ServerConfiguration::parse(&format!(
            "timeout: 3600\nbackup_directory: /tmp/backup\nlog_request: true\nlog_query: true\nlog_issuance: true\nlog_audit: true\ndatabase_path: /tmp/jwt.db\nhsm_helper: /usr/bin/false\nhsm_key_namespace: test/runtime\nruntime_transports: UNIX,TCP,TLS,MTLS\nservice_socket: {}\ntcp_address: 127.0.0.1:0\ntls_address: 127.0.0.1:0\nmtls_address: 127.0.0.1:0\nserver_certificate: {}\nserver_private_key: {}\nserver_trust_chain: {}\nclient_trust_chain: {}\n",
            socket.display(), certificate.display(), private_key.display(), trust_chain.display(), trust_chain.display()
        )).unwrap();
        let listeners = RuntimeListenerSet::bind(&configuration).unwrap();
        assert_eq!(
            listeners.enabled(),
            [
                RuntimeTransport::Unix,
                RuntimeTransport::Tcp,
                RuntimeTransport::Tls,
                RuntimeTransport::MutualTls
            ]
        );
        drop(listeners);
        assert!(!socket.exists());
        assert!(!root.exists());
    }

    #[test]
    fn transport_adapters_contain_no_jwt_lifecycle_implementation() {
        let adapters = [
            ("UNIX", include_str!("unix_socket.rs")),
            ("TCP", include_str!("tcp_listener.rs")),
            ("TLS", include_str!("tls_listener.rs")),
            ("MTLS", include_str!("mtls_listener.rs")),
        ];
        let forbidden = [
            "JWT_CREATE",
            "JWT_STATUS",
            "JWT_QUERY",
            "JWT_UPDATE",
            "JWT_REVOKE",
            "JwtCreateRequest",
            "JwtQueryRequest",
            "JwtUpdateRequest",
            "JwtRevokeRequest",
            "IssuanceService",
            "SessionService",
        ];
        for (transport, source) in adapters {
            for symbol in forbidden {
                assert!(
                    !source.contains(symbol),
                    "{transport} adapter must not implement lifecycle symbol {symbol}"
                );
            }
        }
        let composition = include_str!("runtime_listeners.rs");
        let production = composition.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("process_runtime_connection"));
        assert!(!production.contains("IssuanceService"));
        assert!(!production.contains("SessionService"));
    }

    #[test]
    fn secure_listener_reports_handshake_and_certificate_validation_failures() {
        let source = include_str!("runtime_listeners.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("mTLS handshake failed"));
        assert!(production.contains("mTLS client certificate is required"));
        assert!(production.contains("log_listener_error(&error)"));
        assert!(!production.contains("let Ok(validation)"));
    }

    #[test]
    fn mtls_listener_completes_handshake_before_reading_peer_certificate() {
        let source = include_str!("runtime_listeners.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let handshake = production
            .find("while connection.is_handshaking()")
            .unwrap();
        let peer_certificate = production.find(".peer_certificates()").unwrap();
        assert!(handshake < peer_certificate);
    }

    #[test]
    fn mtls_listener_preserves_a_completed_handshake_after_io_timeout() {
        let source = include_str!("runtime_listeners.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("if !connection.is_handshaking()"));
        assert!(production.contains("break;"));
    }

    #[test]
    fn mtls_listener_separates_handshake_and_keep_alive_polling_timeouts() {
        let source = include_str!("runtime_listeners.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let mtls = production
            .split("if let Some((endpoint, tls)) = self._mtls.take()")
            .nth(1)
            .unwrap();
        let handshake_timeout = mtls.find("Duration::from_secs(10)").unwrap();
        let handshake = mtls.find("while connection.is_handshaking()").unwrap();
        let polling_timeout = mtls.rfind("Duration::from_secs(1)").unwrap();
        assert!(handshake_timeout < handshake);
        assert!(handshake < polling_timeout);
    }

    #[test]
    fn mtls_listener_normalizes_accepted_socket_before_handshake() {
        let source = include_str!("runtime_listeners.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let mtls = production
            .split("if let Some((endpoint, tls)) = self._mtls.take()")
            .nth(1)
            .unwrap();
        let blocking = mtls.find("set_nonblocking(false)").unwrap();
        let handshake = mtls.find("while connection.is_handshaking()").unwrap();
        assert!(blocking < handshake);
    }

    fn required_path(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} must be configured")))
    }
}

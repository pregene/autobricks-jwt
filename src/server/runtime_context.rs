use std::{
    path::Path,
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct RuntimeContextHandle {
    current: RwLock<Option<Arc<RuntimeServiceContext>>>,
    accepting: AtomicBool,
    in_flight: Mutex<usize>,
    drained: Condvar,
}

pub struct RuntimeRequestPermit<'a> {
    handle: &'a RuntimeContextHandle,
}

impl RuntimeContextHandle {
    pub fn new(context: RuntimeServiceContext) -> Self {
        Self {
            current: RwLock::new(Some(Arc::new(context))),
            accepting: AtomicBool::new(true),
            in_flight: Mutex::new(0),
            drained: Condvar::new(),
        }
    }

    pub fn current(&self) -> Result<Arc<RuntimeServiceContext>, ServiceError> {
        self.current
            .read()
            .map_err(|_| ServiceError::internal("runtime context lock failed"))?
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| ServiceError::assigned(8092, "runtime is not accepting requests"))
    }

    pub fn replace(
        &self,
        context: RuntimeServiceContext,
    ) -> Result<Option<Arc<RuntimeServiceContext>>, ServiceError> {
        let mut current = self
            .current
            .write()
            .map_err(|_| ServiceError::internal("runtime context lock failed"))?;
        Ok(current.replace(Arc::new(context)))
    }

    pub fn take(&self) -> Result<Option<Arc<RuntimeServiceContext>>, ServiceError> {
        self.current
            .write()
            .map_err(|_| ServiceError::internal("runtime context lock failed"))
            .map(|mut context| context.take())
    }

    pub fn begin_request(&self) -> Result<RuntimeRequestPermit<'_>, ServiceError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ServiceError::assigned(
                8092,
                "runtime is not accepting requests",
            ));
        }
        let mut count = self
            .in_flight
            .lock()
            .map_err(|_| ServiceError::internal("runtime admission lock failed"))?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ServiceError::assigned(
                8092,
                "runtime is not accepting requests",
            ));
        }
        *count += 1;
        Ok(RuntimeRequestPermit { handle: self })
    }

    pub fn stop_and_drain(&self) -> Result<(), ServiceError> {
        self.accepting.store(false, Ordering::Release);
        let mut count = self
            .in_flight
            .lock()
            .map_err(|_| ServiceError::internal("runtime admission lock failed"))?;
        while *count != 0 {
            count = self
                .drained
                .wait(count)
                .map_err(|_| ServiceError::internal("runtime admission lock failed"))?;
        }
        Ok(())
    }

    pub fn resume(&self) {
        self.accepting.store(true, Ordering::Release);
    }
}

impl Drop for RuntimeRequestPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut count) = self.handle.in_flight.lock() {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.handle.drained.notify_all();
            }
        }
    }
}

use crate::{
    database_key_rotation::HsmDatabaseKeys, runtime_protocol::RuntimeDispatcher,
    service_error::ServiceError, service_registry::ServiceRegistry,
    sqlcipher_token_repository::SqlCipherTokenRepository, worker_process::CacheWorkerSet,
};
use crate::{
    operational_logger::SyslogSink, production_audit::ProductionAuditRecorder,
    session_worker::SessionCacheWorker, truelog_audit::CommandTrueLogWriter,
};
use crate::{service_certificate::ServiceCertificateRepository, service_registry::OperationClass};

#[derive(Clone, Debug)]
pub struct PresentedCertificateIdentity {
    pub fingerprint: String,
    pub uri_san: String,
    pub not_after: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorization {
    pub client_id: uuid::Uuid,
    pub idle_timeout: u64,
    pub certificate_not_after: Option<u64>,
}

pub struct RuntimeServiceContext {
    registry: Arc<Mutex<ServiceRegistry>>,
    tokens: Mutex<SqlCipherTokenRepository>,
    token_lifetime: Duration,
    require_complete_token: bool,
    database_caches: Option<CacheWorkerSet>,
    audit: Mutex<ProductionAuditRecorder<SyslogSink, CommandTrueLogWriter>>,
    certificates: Mutex<ServiceCertificateRepository>,
    session_cache: Mutex<Option<SessionCacheWorker>>,
}

impl RuntimeServiceContext {
    pub fn open<H: HsmDatabaseKeys>(
        database_path: &Path,
        hsm: &H,
        token_lifetime: Duration,
        require_complete_token: bool,
    ) -> Result<Self, ServiceError> {
        if token_lifetime.is_zero() {
            return Err(ServiceError::configuration_invalid(
                "token lifetime must be greater than zero",
            ));
        }
        let database_key = hsm.current()?;
        let registry = ServiceRegistry::open_sqlcipher(database_path, &database_key)?;
        let tokens = SqlCipherTokenRepository::open(database_path, &database_key)?;
        let audit = ProductionAuditRecorder::open(database_path, &database_key, false, None)?;
        let certificates = ServiceCertificateRepository::open(database_path, &database_key)?;
        Ok(Self {
            registry: Arc::new(Mutex::new(registry)),
            tokens: Mutex::new(tokens),
            token_lifetime,
            require_complete_token,
            database_caches: None,
            audit: Mutex::new(audit),
            certificates: Mutex::new(certificates),
            session_cache: Mutex::new(None),
        })
    }

    pub fn open_with_cache<H: HsmDatabaseKeys>(
        database_path: &Path,
        hsm: &H,
        token_lifetime: Duration,
        require_complete_token: bool,
        executable: &Path,
        cache_library: &Path,
    ) -> Result<Self, ServiceError> {
        let mut context = Self::open(database_path, hsm, token_lifetime, require_complete_token)?;
        let registry = context
            .registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        let caches = CacheWorkerSet::start_registered(executable, cache_library, &registry)?;
        drop(registry);
        context.database_caches = Some(caches);
        Ok(context)
    }

    pub fn registry(&self) -> Arc<Mutex<ServiceRegistry>> {
        Arc::clone(&self.registry)
    }

    pub fn configure_audit(
        &mut self,
        database_key: &[u8; 32],
        enabled: bool,
        truelog_client: Option<&Path>,
    ) -> Result<(), ServiceError> {
        self.audit = Mutex::new(ProductionAuditRecorder::open(
            &self.database_path()?,
            database_key,
            enabled,
            truelog_client,
        )?);
        Ok(())
    }

    fn database_path(&self) -> Result<std::path::PathBuf, ServiceError> {
        self.tokens
            .lock()
            .map_err(|_| ServiceError::internal("token repository lock failed"))
            .map(|repository| repository.database_path())
    }

    pub fn authorize_certificate(
        &self,
        service_id: uuid::Uuid,
        client_id: uuid::Uuid,
        operation: OperationClass,
        fingerprint: &str,
    ) -> Result<(), ServiceError> {
        self.certificates
            .lock()
            .map_err(|_| ServiceError::internal("certificate repository lock failed"))?
            .authorize(service_id, client_id, operation, fingerprint)
    }

    pub fn authorize_runtime_request(
        &self,
        request: &crate::runtime_protocol::RuntimeRequest,
        transport: &str,
        source: Option<std::net::IpAddr>,
        peer: Option<(u32, u32)>,
        certificate: Option<&PresentedCertificateIdentity>,
    ) -> Result<RuntimeAuthorization, ServiceError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        let client = registry
            .clients()
            .into_iter()
            .find(|client| client.client_id == request.client_id())
            .ok_or_else(|| {
                ServiceError::client_registration_inactive("client registration is not active")
            })?;
        if !client.transports.iter().any(|value| value == transport) {
            return Err(ServiceError::assigned(
                8023,
                "connection transport is not authorized",
            ));
        }
        if transport == "UNIX" {
            let (uid, gid) = peer
                .ok_or_else(|| ServiceError::assigned(8023, "Unix peer identity is unavailable"))?;
            if client.peer_uid.is_some_and(|expected| expected != uid)
                || client.peer_gid.is_some_and(|expected| expected != gid)
                || (client.peer_uid.is_none() && client.peer_gid.is_none())
            {
                return Err(ServiceError::assigned(
                    8023,
                    "Unix peer identity is not authorized",
                ));
            }
        } else {
            let source = source
                .ok_or_else(|| ServiceError::assigned(8023, "connection source is unavailable"))?;
            let source_policy = crate::connection_policy::ConnectionPolicy::new(
                &client.allowed_source_cidr,
                client.keep_alive_timeout,
                client.keep_alive_timeout,
            )?;
            if !source_policy.permits(source) {
                return Err(ServiceError::assigned(
                    8023,
                    "connection source is not authorized",
                ));
            }
        }
        let service = registry.authorize_service_by_apikey(
            request.client_id(),
            request.apikey(),
            request.operation_class(),
        )?;
        let certificate_not_after = if transport == "MTLS" {
            let certificate = certificate
                .ok_or_else(|| ServiceError::assigned(8010, "client certificate is required"))?;
            let expected_uri = match request.operation_class() {
                OperationClass::Read => "urn:autobricks:jwt:read",
                OperationClass::Write => "urn:autobricks:jwt:write",
            };
            if certificate.uri_san != expected_uri {
                return Err(ServiceError::assigned(
                    8021,
                    "certificate operation URI is invalid",
                ));
            }
            self.certificates
                .lock()
                .map_err(|_| ServiceError::internal("certificate repository lock failed"))?
                .authorize(
                    service.service_id,
                    request.client_id(),
                    request.operation_class(),
                    &certificate.fingerprint,
                )?;
            Some(certificate.not_after)
        } else {
            if certificate.is_some() {
                return Err(ServiceError::assigned(8023, "connection identity changed"));
            }
            None
        };
        Ok(RuntimeAuthorization {
            client_id: client.client_id,
            idle_timeout: client.keep_alive_timeout,
            certificate_not_after,
        })
    }

    pub fn activate_initial_certificate(
        &self,
        request: &crate::runtime_protocol::CertificateActivationRequest,
        transport: &str,
        source: Option<std::net::IpAddr>,
        certificate: Option<&PresentedCertificateIdentity>,
        now: u64,
    ) -> Result<RuntimeAuthorization, ServiceError> {
        if transport != "MTLS" {
            return Err(ServiceError::assigned(
                8010,
                "mTLS client certificate is required",
            ));
        }
        let certificate = certificate
            .ok_or_else(|| ServiceError::assigned(8010, "mTLS client certificate is required"))?;
        let registry = self
            .registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        let client = registry
            .clients()
            .into_iter()
            .find(|client| client.client_id == request.client_id)
            .ok_or_else(|| {
                ServiceError::client_registration_inactive("client registration is not active")
            })?;
        if !client.transports.iter().any(|value| value == "MTLS")
            || client.operation_class != request.operation_class
        {
            return Err(ServiceError::assigned(
                8028,
                "certificate client binding does not match",
            ));
        }
        let source = source
            .ok_or_else(|| ServiceError::assigned(8023, "connection source is unavailable"))?;
        let policy = crate::connection_policy::ConnectionPolicy::new(
            &client.allowed_source_cidr,
            client.keep_alive_timeout,
            client.keep_alive_timeout,
        )?;
        if !policy.permits(source) {
            return Err(ServiceError::assigned(
                8023,
                "connection source is not authorized",
            ));
        }
        let expected_uri = match request.operation_class {
            OperationClass::Read => "urn:autobricks:jwt:read",
            OperationClass::Write => "urn:autobricks:jwt:write",
        };
        if certificate.uri_san != expected_uri {
            return Err(ServiceError::assigned(
                8021,
                "certificate operation URI is invalid",
            ));
        }
        let service = registry.authorize_service_by_apikey(
            request.client_id,
            &request.apikey,
            request.operation_class,
        )?;
        self.certificates
            .lock()
            .map_err(|_| ServiceError::internal("certificate repository lock failed"))?
            .activate_initial_registration(
                service.service_id,
                request.client_id,
                request.operation_class,
                request.request_id,
                &certificate.fingerprint,
                &request.temporary_registration_key,
                now,
            )?;
        Ok(RuntimeAuthorization {
            client_id: client.client_id,
            idle_timeout: client.keep_alive_timeout,
            certificate_not_after: Some(certificate.not_after),
        })
    }

    pub fn enable_session_cache(
        &self,
        executable: &Path,
        cache_library: &Path,
        database_key: &[u8; 32],
        now: u64,
    ) -> Result<(), ServiceError> {
        let records = self
            .tokens
            .lock()
            .map_err(|_| ServiceError::internal("token repository lock failed"))?
            .cache_rebuild_records(now)?;
        let worker = SessionCacheWorker::start_rebuilt(
            executable,
            cache_library,
            &self.database_path()?,
            database_key,
            &records,
        )?;
        *self
            .session_cache
            .lock()
            .map_err(|_| ServiceError::internal("session Cache lock failed"))? = Some(worker);
        Ok(())
    }

    pub fn dispatch_frame(&self, frame: &[u8], now: u64) -> Result<Vec<u8>, ServiceError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| ServiceError::internal("service registry lock failed"))?;
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| ServiceError::internal("token repository lock failed"))?;
        let mut audit = self
            .audit
            .lock()
            .map_err(|_| ServiceError::internal("audit recorder lock failed"))?;
        let mut session_cache = self
            .session_cache
            .lock()
            .map_err(|_| ServiceError::internal("session Cache lock failed"))?;
        let mut dispatcher = RuntimeDispatcher::new(
            &registry,
            &mut tokens,
            self.token_lifetime,
            self.require_complete_token,
        )?;
        if let Some(caches) = &self.database_caches {
            dispatcher = dispatcher.with_database_caches(caches);
        }
        dispatcher = dispatcher.with_audit(&mut *audit);
        if let Some(cache) = session_cache.as_mut() {
            dispatcher = dispatcher.with_session_cache(cache);
        }
        Ok(dispatcher.dispatch_json(frame, now))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        sync::Arc,
        thread,
        time::Duration,
    };

    use serde_json::{Map, Value, json};
    use uuid::Uuid;

    use crate::{
        audit_log_repository::{AuditLogRecord, AuditLogRepository},
        connection_policy::ConnectionPolicy,
        database_key_rotation::HsmDatabaseKeys,
        issuance_service::{IssuanceService, JwtCreateRequest},
        service_certificate::{CertificateMetadata, ServiceCertificateRepository},
        service_error::ServiceError,
        service_registry::{OperationClass, ServiceRegistry},
        sqlcipher_token_repository::SqlCipherTokenRepository,
        tcp_listener::TcpListenerEndpoint,
    };

    use super::{RuntimeContextHandle, RuntimeServiceContext};

    struct StartupHsm([u8; 32]);

    impl HsmDatabaseKeys for StartupHsm {
        fn current(&self) -> Result<[u8; 32], ServiceError> {
            Ok(self.0)
        }

        fn previous(&self) -> Result<Option<[u8; 32]>, ServiceError> {
            Ok(None)
        }

        fn generate_next(&mut self) -> Result<[u8; 32], ServiceError> {
            unreachable!()
        }

        fn commit(&mut self, _: [u8; 32], _: [u8; 32]) -> Result<(), ServiceError> {
            unreachable!()
        }
    }

    fn seeded_context() -> (Arc<RuntimeServiceContext>, Uuid, String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ab-jwt-context-{}.db", Uuid::new_v4()));
        let key = [0x81; 32];
        let (client_id, apikey) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
            let client_id = registry
                .register_client("runtime-context-writer", OperationClass::Write)
                .unwrap();
            let service = registry
                .register_service(client_id, "runtime-context-service")
                .unwrap();
            (client_id, service.apikey)
        };
        let context =
            RuntimeServiceContext::open(&path, &StartupHsm(key), Duration::from_secs(300), true)
                .unwrap();
        (Arc::new(context), client_id, apikey, path)
    }

    fn create_frame(client_id: Uuid, apikey: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "operation": "JWT_CREATE",
            "request": {
                "client_id": client_id,
                "apikey": apikey,
                "request_id": Uuid::new_v4(),
                "data": Map::from_iter([(
                    "user_id".to_owned(),
                    Value::String("runtime-user".to_owned())
                )])
            }
        }))
        .unwrap()
    }

    #[test]
    fn runtime_admission_drains_inflight_work_and_resumes_after_context_replacement() {
        let (context, _, _, path) = seeded_context();
        let context = Arc::try_unwrap(context)
            .ok()
            .expect("exclusive test context");
        let handle = Arc::new(RuntimeContextHandle::new(context));
        let permit = handle.begin_request().unwrap();
        let draining = Arc::clone(&handle);
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            draining.stop_and_drain().unwrap();
            completed_tx.send(()).unwrap();
        });
        thread::sleep(Duration::from_millis(20));
        assert!(completed_rx.try_recv().is_err());
        let rejected = match handle.begin_request() {
            Ok(_) => panic!("draining runtime accepted a request"),
            Err(error) => error,
        };
        assert_eq!(rejected.code(), 8092);
        drop(permit);
        completed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        handle.resume();
        drop(handle.begin_request().unwrap());
        drop(handle);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn composes_registry_token_repository_and_dispatcher_from_one_database() {
        let (context, client_id, apikey, path) = seeded_context();
        let response = context
            .dispatch_frame(&create_frame(client_id, &apikey), 1_000)
            .unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["status"], "SUCCESS");
        assert_eq!(response["operation"], "JWT_CREATE");
        drop(context);
        fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "creates a local TCP listener"]
    fn tcp_listener_frames_reach_the_runtime_dispatcher() {
        let (context, client_id, apikey, path) = seeded_context();
        let endpoint = TcpListenerEndpoint::bind("127.0.0.1:0").unwrap();
        let address = endpoint.local_addr().unwrap();
        let policy = ConnectionPolicy::new("127.0.0.1/32", 30, 300).unwrap();
        let server_context = Arc::clone(&context);
        let server = thread::spawn(move || {
            endpoint
                .serve_one(&policy, |frame| server_context.dispatch_frame(frame, 1_000))
                .unwrap()
        });

        let request = create_frame(client_id, &apikey);
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&request).unwrap();
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).unwrap();
        drop(stream);
        assert_eq!(server.join().unwrap(), 1);
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["status"], "SUCCESS");
        drop(context);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reduced_capability_runtime_starts_without_pki_truelog_or_cache_library_access() {
        let path = std::env::temp_dir().join(format!("ab-jwt-reduced-{}.db", Uuid::new_v4()));
        let key = [0x82; 32];
        let (client_id, apikey) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
            let client_id = registry
                .register_client("reduced-writer", OperationClass::Write)
                .unwrap();
            let service = registry
                .register_service(client_id, "reduced-json-service")
                .unwrap();
            (client_id, service.apikey)
        };
        let missing_library =
            std::env::temp_dir().join(format!("missing-autobricks-cache-{}", Uuid::new_v4()));
        let mut context = RuntimeServiceContext::open_with_cache(
            &path,
            &StartupHsm(key),
            Duration::from_secs(300),
            true,
            std::env::current_exe().unwrap().as_path(),
            &missing_library,
        )
        .unwrap();
        context.configure_audit(&key, true, None).unwrap();
        let response = context
            .dispatch_frame(&create_frame(client_id, &apikey), 1_000)
            .unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["status"], "SUCCESS");
        assert!(!missing_library.exists());
        drop(context);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn restart_restores_registration_apikey_certificate_token_and_audit_state() {
        let path = std::env::temp_dir().join(format!("ab-jwt-restart-{}.db", Uuid::new_v4()));
        let key = [0x83; 32];
        let fingerprint = "ab".repeat(32);
        let audit_id = Uuid::new_v4();
        let (writer_id, writer_service_id, reader_id, reader_apikey, token_id) = {
            let mut registry = ServiceRegistry::open_sqlcipher(&path, &key).unwrap();
            let writer_id = registry
                .register_client("restart-writer", OperationClass::Write)
                .unwrap();
            let writer = registry
                .register_service(writer_id, "restart-issuer")
                .unwrap();
            let reader_id = registry
                .register_client("restart-reader", OperationClass::Read)
                .unwrap();
            let reader = registry
                .register_service_with_issuers(
                    reader_id,
                    "restart-query",
                    "USER",
                    vec!["user_id".into()],
                    None,
                    None,
                    vec![writer.service_id],
                )
                .unwrap();
            let mut tokens = SqlCipherTokenRepository::open(&path, &key).unwrap();
            let issued = IssuanceService::new(&registry, &mut tokens, Duration::from_secs(300))
                .unwrap()
                .create(
                    JwtCreateRequest {
                        client_id: writer_id,
                        apikey: writer.apikey,
                        request_id: Uuid::new_v4(),
                        data: Map::from_iter([(
                            "user_id".into(),
                            Value::String("restart-user".into()),
                        )]),
                    },
                    1_000,
                )
                .unwrap();
            let mut certificates = ServiceCertificateRepository::open(&path, &key).unwrap();
            certificates
                .register(
                    writer.service_id,
                    writer_id,
                    OperationClass::Write,
                    &CertificateMetadata {
                        fingerprint: fingerprint.clone(),
                        uri_sans: vec!["urn:autobricks:jwt:write".into()],
                        ocsp_url: "https://ocsp.invalid/status".into(),
                        not_before: "Oct 11 00:00:00 2026 GMT".into(),
                        not_after: "Oct 11 00:00:00 2027 GMT".into(),
                        client_auth: true,
                    },
                )
                .unwrap();
            let mut audit = AuditLogRepository::open(&path, &key).unwrap();
            audit
                .store_pending(&AuditLogRecord {
                    audit_id,
                    event: "JWT_ISSUED".into(),
                    event_at: "2026-10-11T00:00:00Z".into(),
                    service_id: writer.service_id.to_string(),
                    subject_type: Some("USER".into()),
                    result: "SUCCESS".into(),
                    error_code: None,
                    error: None,
                    request_id: Some(Uuid::new_v4()),
                    token_id: Some(issued.token_id),
                    administrator_uid: None,
                    receipt_state: "PENDING".into(),
                    receipt: None,
                })
                .unwrap();
            (
                writer_id,
                writer.service_id,
                reader_id,
                reader.apikey,
                issued.token_id,
            )
        };

        let context =
            RuntimeServiceContext::open(&path, &StartupHsm(key), Duration::from_secs(300), false)
                .unwrap();
        context
            .authorize_certificate(
                writer_service_id,
                writer_id,
                OperationClass::Write,
                &fingerprint,
            )
            .unwrap();
        let response = context
            .dispatch_frame(
                &serde_json::to_vec(&json!({
                    "operation": "JWT_QUERY",
                    "request": {
                        "client_id": reader_id,
                        "apikey": reader_apikey,
                        "request_id": Uuid::new_v4(),
                        "token_id": token_id,
                        "fields": ["user_id"]
                    }
                }))
                .unwrap(),
                1_001,
            )
            .unwrap();
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["result"]["fields"]["user_id"], "restart-user");
        let audit = AuditLogRepository::open(&path, &key).unwrap();
        assert_eq!(
            audit.find(audit_id).unwrap().unwrap().receipt_state,
            "PENDING"
        );
        drop(context);
        drop(audit);
        fs::remove_file(path).unwrap();
    }
}

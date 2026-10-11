use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    autobricks_cache::AutobricksCache, database_source::DatabaseSourceCache,
    service_error::ServiceError, service_registry::ServiceRegistry,
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct WorkerInitialization {
    library_path: String,
    connection: Value,
    caches: Vec<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE")]
enum WorkerRequest {
    Query { cache_id: String, input: Value },
    Insert { cache_id: String, input: Value },
    Update { cache_id: String, input: Value },
    Delete { cache_id: String, input: Value },
    Shutdown,
}

#[derive(Serialize, Deserialize)]
struct WorkerResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

struct WorkerIo {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

pub struct CacheWorkerProcess {
    io: Mutex<WorkerIo>,
}

pub struct CacheWorkerSet {
    workers: BTreeMap<Uuid, CacheWorkerProcess>,
}

impl CacheWorkerSet {
    pub fn start_registered(
        executable: &Path,
        library_path: &Path,
        registry: &ServiceRegistry,
    ) -> Result<Self, ServiceError> {
        let mut workers = BTreeMap::new();
        for service in registry.all_services() {
            if service.source_type.as_deref() != Some("DATABASE") {
                continue;
            }
            let plan = service.database_source.ok_or_else(|| {
                ServiceError::configuration_invalid(
                    "registered DATABASE service has no Cache source plan",
                )
            })?;
            let runtime_definition = plan.cache_runtime_definition();
            let worker = CacheWorkerProcess::start(
                executable,
                library_path,
                plan.connection_json,
                vec![runtime_definition],
            )?;
            workers.insert(service.service_id, worker);
        }
        Ok(Self { workers })
    }

    pub fn cache_for(&self, service_id: Uuid) -> Result<&CacheWorkerProcess, ServiceError> {
        self.workers.get(&service_id).ok_or_else(|| {
            ServiceError::classified(8052, "DATABASE Cache worker is unavailable")
                .expect("8052 must be assigned")
        })
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub fn shutdown(&self) -> Result<(), ServiceError> {
        for worker in self.workers.values() {
            worker.shutdown()?;
        }
        Ok(())
    }
}

impl CacheWorkerProcess {
    pub fn start(
        executable: &Path,
        library_path: &Path,
        connection: Value,
        caches: Vec<Value>,
    ) -> Result<Self, ServiceError> {
        if !executable.is_absolute() || !library_path.is_absolute() || caches.is_empty() {
            return Err(ServiceError::configuration_invalid(
                "Cache worker executable, library, and definitions are required",
            ));
        }
        let mut child = Command::new(executable)
            .arg("--cache-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| ServiceError::service_unavailable("Cache worker cannot be started"))?;
        let input = child.stdin.take().ok_or_else(|| {
            ServiceError::service_unavailable("Cache worker input is unavailable")
        })?;
        let output = child.stdout.take().ok_or_else(|| {
            ServiceError::service_unavailable("Cache worker output is unavailable")
        })?;
        let worker = Self {
            io: Mutex::new(WorkerIo {
                child,
                input,
                output: BufReader::new(output),
            }),
        };
        worker.exchange(&WorkerInitialization {
            library_path: library_path.to_string_lossy().into_owned(),
            connection,
            caches,
        })?;
        Ok(worker)
    }

    fn exchange<T: Serialize>(&self, request: &T) -> Result<WorkerResponse, ServiceError> {
        let mut io = self
            .io
            .lock()
            .map_err(|_| ServiceError::service_unavailable("Cache worker lock failed"))?;
        serde_json::to_writer(&mut io.input, request).map_err(|_| {
            ServiceError::source_data_unavailable("Cache worker request is invalid")
        })?;
        io.input
            .write_all(b"\n")
            .and_then(|_| io.input.flush())
            .map_err(|_| ServiceError::service_unavailable("Cache worker request failed"))?;
        let mut line = String::new();
        io.output
            .read_line(&mut line)
            .map_err(|_| ServiceError::service_unavailable("Cache worker response failed"))?;
        let response: WorkerResponse = serde_json::from_str(&line).map_err(|_| {
            ServiceError::source_data_unavailable("Cache worker response is invalid")
        })?;
        if response.status == "SUCCESS" {
            Ok(response)
        } else {
            Err(ServiceError::source_data_unavailable(
                response
                    .message
                    .unwrap_or_else(|| "Cache worker operation failed".into()),
            ))
        }
    }

    pub fn shutdown(&self) -> Result<(), ServiceError> {
        self.exchange(&WorkerRequest::Shutdown)?;
        let mut io = self
            .io
            .lock()
            .map_err(|_| ServiceError::service_unavailable("Cache worker lock failed"))?;
        let status = io
            .child
            .wait()
            .map_err(|_| ServiceError::service_unavailable("Cache worker did not stop"))?;
        if status.success() {
            Ok(())
        } else {
            Err(ServiceError::service_unavailable(
                "Cache worker stopped unsuccessfully",
            ))
        }
    }
}

impl DatabaseSourceCache for CacheWorkerProcess {
    fn query(&self, cache_id: &str, input: &Value) -> Result<Vec<Value>, ServiceError> {
        self.exchange(&WorkerRequest::Query {
            cache_id: cache_id.into(),
            input: input.clone(),
        })?
        .records
        .ok_or_else(|| ServiceError::source_data_unavailable("Cache worker records are missing"))
    }

    fn update(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.exchange(&WorkerRequest::Update {
            cache_id: cache_id.into(),
            input: input.clone(),
        })?;
        Ok(())
    }
}

impl CacheWorkerProcess {
    pub fn insert_record(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.exchange(&WorkerRequest::Insert {
            cache_id: cache_id.into(),
            input: input.clone(),
        })?;
        Ok(())
    }

    pub fn delete_record(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.exchange(&WorkerRequest::Delete {
            cache_id: cache_id.into(),
            input: input.clone(),
        })?;
        Ok(())
    }
}

impl Drop for CacheWorkerProcess {
    fn drop(&mut self) {
        let _ = self.exchange(&WorkerRequest::Shutdown);
        if let Ok(mut io) = self.io.lock() {
            let _ = io.child.wait();
        }
    }
}

pub fn run_worker() -> Result<(), ServiceError> {
    let standard_input = std::io::stdin();
    let mut lines = standard_input.lock().lines();
    let initialization: WorkerInitialization = serde_json::from_str(
        &lines
            .next()
            .ok_or_else(|| ServiceError::configuration_invalid("Cache worker input is missing"))?
            .map_err(|_| {
                ServiceError::configuration_invalid("Cache worker input cannot be read")
            })?,
    )
    .map_err(|_| ServiceError::configuration_invalid("Cache worker initialization is invalid"))?;
    let cache = AutobricksCache::initialize(
        Path::new(&initialization.library_path),
        &initialization.connection.to_string(),
        &Value::Array(initialization.caches).to_string(),
    )?;
    write_response(WorkerResponse {
        status: "SUCCESS".into(),
        records: None,
        message: None,
    })?;
    for line in lines {
        let request: WorkerRequest = serde_json::from_str(
            &line.map_err(|_| ServiceError::service_unavailable("Cache worker input failed"))?,
        )
        .map_err(|_| ServiceError::invalid_request("Cache worker request is invalid"))?;
        let response = match request {
            WorkerRequest::Query { cache_id, input } => {
                cache
                    .query(&cache_id, &input)
                    .map(|records| WorkerResponse {
                        status: "SUCCESS".into(),
                        records: Some(records),
                        message: None,
                    })
            }
            WorkerRequest::Insert { cache_id, input } => {
                cache.insert(&cache_id, &input).map(|()| WorkerResponse {
                    status: "SUCCESS".into(),
                    records: None,
                    message: None,
                })
            }
            WorkerRequest::Update { cache_id, input } => {
                cache.update(&cache_id, &input).map(|()| WorkerResponse {
                    status: "SUCCESS".into(),
                    records: None,
                    message: None,
                })
            }
            WorkerRequest::Delete { cache_id, input } => {
                cache.delete(&cache_id, &input).map(|()| WorkerResponse {
                    status: "SUCCESS".into(),
                    records: None,
                    message: None,
                })
            }
            WorkerRequest::Shutdown => {
                cache.uninitialize()?;
                write_response(WorkerResponse {
                    status: "SUCCESS".into(),
                    records: None,
                    message: None,
                })?;
                return Ok(());
            }
        };
        match response {
            Ok(response) => write_response(response)?,
            Err(error) => write_response(WorkerResponse {
                status: "ERROR".into(),
                records: None,
                message: Some(error.public_message().into()),
            })?,
        }
    }
    cache.uninitialize()
}

fn write_response(response: WorkerResponse) -> Result<(), ServiceError> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response).map_err(|_| {
        ServiceError::service_unavailable("Cache worker response cannot be encoded")
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|_| ServiceError::service_unavailable("Cache worker response cannot be written"))
}

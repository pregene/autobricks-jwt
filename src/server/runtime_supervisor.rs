use std::sync::{Arc, Mutex};

use crate::{
    comm_runtime::CommRuntime,
    runtime_context::{RuntimeContextHandle, RuntimeServiceContext},
    server_configuration::ServerConfiguration,
    service_error::ServiceError,
};

pub struct RuntimeSupervisor {
    context: Arc<RuntimeContextHandle>,
    communication: Mutex<Option<CommRuntime>>,
    lifecycle: Mutex<()>,
}

impl RuntimeSupervisor {
    pub fn start(
        configuration: ServerConfiguration,
        context: RuntimeServiceContext,
    ) -> Result<Self, ServiceError> {
        let context = Arc::new(RuntimeContextHandle::new(context));
        let communication = CommRuntime::start(&configuration, Arc::clone(&context))?;
        Ok(Self {
            context,
            communication: Mutex::new(Some(communication)),
            lifecycle: Mutex::new(()),
        })
    }

    pub fn context(&self) -> Arc<RuntimeContextHandle> {
        Arc::clone(&self.context)
    }

    pub fn maintenance<T, O, R>(&self, operation: O, reopen: R) -> Result<T, ServiceError>
    where
        O: FnOnce() -> Result<T, ServiceError>,
        R: FnOnce() -> Result<RuntimeServiceContext, ServiceError>,
    {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| ServiceError::internal("runtime lifecycle lock failed"))?;
        let communication = self
            .communication
            .lock()
            .map_err(|_| ServiceError::internal("COMM runtime lock failed"))?;
        let runtime = communication
            .as_ref()
            .ok_or_else(|| ServiceError::service_unavailable("COMM runtime is stopped"))?;
        runtime.pause()?;
        self.context.stop_and_drain()?;
        drop(self.context.take()?);
        let operation_result = operation();
        match reopen() {
            Ok(context) => {
                self.context.replace(context)?;
                self.context.resume();
                runtime.resume()?;
                operation_result
            }
            Err(error) => Err(error),
        }
    }

    pub fn shutdown(&self) -> Result<(), ServiceError> {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| ServiceError::internal("runtime lifecycle lock failed"))?;
        let communication = self
            .communication
            .lock()
            .map_err(|_| ServiceError::internal("COMM runtime lock failed"))?
            .take();
        if let Some(runtime) = communication {
            runtime.pause()?;
            self.context.stop_and_drain()?;
            runtime.shutdown()?;
        }
        drop(self.context.take()?);
        Ok(())
    }
}

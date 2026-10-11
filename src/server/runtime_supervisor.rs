use std::sync::{Arc, Mutex};

use crate::{
    runtime_context::{RuntimeContextHandle, RuntimeServiceContext},
    runtime_listeners::{RuntimeListenerRuntime, RuntimeListenerSet},
    server_configuration::{RuntimeTransport, ServerConfiguration},
    service_certificate::CertificateTools,
    service_error::ServiceError,
};

pub struct RuntimeSupervisor {
    configuration: ServerConfiguration,
    context: Arc<RuntimeContextHandle>,
    listeners: Mutex<ListenerRuntimes>,
    lifecycle: Mutex<()>,
}

#[derive(Default)]
struct ListenerRuntimes {
    insecure: Option<RuntimeListenerRuntime>,
    secure: Option<RuntimeListenerRuntime>,
}

impl RuntimeSupervisor {
    pub fn start(
        configuration: ServerConfiguration,
        context: RuntimeServiceContext,
    ) -> Result<Self, ServiceError> {
        let context = Arc::new(RuntimeContextHandle::new(context));
        let listeners = start_listeners(&configuration, Arc::clone(&context))?;
        Ok(Self {
            configuration,
            context,
            listeners: Mutex::new(listeners),
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
        let listeners = std::mem::take(
            &mut *self
                .listeners
                .lock()
                .map_err(|_| ServiceError::internal("runtime listener lock failed"))?,
        );
        stop_accepting(&listeners);
        self.context.stop_and_drain()?;
        shutdown_listeners(listeners)?;
        drop(self.context.take()?);
        let operation_result = operation();
        let reopen_result = reopen();
        match reopen_result {
            Ok(context) => {
                self.context.replace(context)?;
                let listeners = start_listeners(&self.configuration, Arc::clone(&self.context))?;
                *self
                    .listeners
                    .lock()
                    .map_err(|_| ServiceError::internal("runtime listener lock failed"))? =
                    listeners;
                self.context.resume();
                operation_result
            }
            Err(error) => Err(error),
        }
    }

    pub fn replace_secure_listener_credentials<O, R, C>(
        &self,
        install: O,
        rollback: R,
        commit: C,
    ) -> Result<bool, ServiceError>
    where
        O: FnOnce() -> Result<bool, ServiceError>,
        R: FnOnce() -> Result<(), ServiceError>,
        C: FnOnce() -> Result<(), ServiceError>,
    {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| ServiceError::internal("runtime lifecycle lock failed"))?;
        let secure = self
            .listeners
            .lock()
            .map_err(|_| ServiceError::internal("runtime listener lock failed"))?
            .secure
            .take();
        if let Some(runtime) = secure {
            runtime.stop_accepting();
            runtime.shutdown()?;
        }
        let installed = match install() {
            Ok(value) => value,
            Err(error) => {
                let secure =
                    start_listener_group(&self.configuration, Arc::clone(&self.context), true)?;
                self.listeners
                    .lock()
                    .map_err(|_| ServiceError::internal("runtime listener lock failed"))?
                    .secure = secure;
                return Err(error);
            }
        };
        match start_listener_group(&self.configuration, Arc::clone(&self.context), true) {
            Ok(secure) => {
                self.listeners
                    .lock()
                    .map_err(|_| ServiceError::internal("runtime listener lock failed"))?
                    .secure = secure;
                commit()?;
                Ok(installed)
            }
            Err(error) => {
                rollback()?;
                let secure =
                    start_listener_group(&self.configuration, Arc::clone(&self.context), true)?;
                self.listeners
                    .lock()
                    .map_err(|_| ServiceError::internal("runtime listener lock failed"))?
                    .secure = secure;
                Err(error)
            }
        }
    }

    pub fn shutdown(&self) -> Result<(), ServiceError> {
        let _lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| ServiceError::internal("runtime lifecycle lock failed"))?;
        let listeners = std::mem::take(
            &mut *self
                .listeners
                .lock()
                .map_err(|_| ServiceError::internal("runtime listener lock failed"))?,
        );
        stop_accepting(&listeners);
        self.context.stop_and_drain()?;
        shutdown_listeners(listeners)?;
        drop(self.context.take()?);
        Ok(())
    }
}

fn start_listeners(
    configuration: &ServerConfiguration,
    context: Arc<RuntimeContextHandle>,
) -> Result<ListenerRuntimes, ServiceError> {
    Ok(ListenerRuntimes {
        insecure: start_listener_group(configuration, Arc::clone(&context), false)?,
        secure: start_listener_group(configuration, context, true)?,
    })
}

fn start_listener_group(
    configuration: &ServerConfiguration,
    context: Arc<RuntimeContextHandle>,
    secure: bool,
) -> Result<Option<RuntimeListenerRuntime>, ServiceError> {
    let mut selected = configuration.clone();
    selected.runtime_transports.retain(|transport| {
        matches!(
            transport,
            RuntimeTransport::Tls | RuntimeTransport::MutualTls
        ) == secure
    });
    if selected.runtime_transports.is_empty() {
        return Ok(None);
    }
    let tools = configuration.pki_client.as_ref().map(|client| {
        let tools = CertificateTools::new(&configuration.openssl, client);
        configuration
            .ocsp_responder_override
            .as_ref()
            .map_or(tools.clone(), |url| tools.with_ocsp_responder_override(url))
    });
    RuntimeListenerSet::bind(&selected)?
        .start(
            context,
            configuration.maximum_connection_lifetime_seconds,
            tools,
            configuration.client_trust_chain.clone(),
        )
        .map(Some)
}

fn stop_accepting(listeners: &ListenerRuntimes) {
    if let Some(runtime) = &listeners.insecure {
        runtime.stop_accepting();
    }
    if let Some(runtime) = &listeners.secure {
        runtime.stop_accepting();
    }
}

fn shutdown_listeners(listeners: ListenerRuntimes) -> Result<(), ServiceError> {
    if let Some(runtime) = listeners.insecure {
        runtime.shutdown()?;
    }
    if let Some(runtime) = listeners.secure {
        runtime.shutdown()?;
    }
    Ok(())
}

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    recovery_management::ProductionRecoveryManagement, server_configuration::ServerConfiguration,
    service_error::ServiceError,
};

const DAY_SECONDS: u64 = 86_400;

pub struct ProductionSchedulerRuntime {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ProductionSchedulerRuntime {
    pub fn start(
        configuration: &ServerConfiguration,
        recovery: Arc<ProductionRecoveryManagement>,
    ) -> Result<Self, ServiceError> {
        let now = unix_time()?;
        let interval = u64::from(configuration.backup_interval_days) * DAY_SECONDS;
        let latest = recovery.latest_backup_completed_at()?.unwrap_or(now);
        let mut next_backup = latest.saturating_add(interval);
        let mut next_drain = now;
        let running = Arc::new(AtomicBool::new(true));
        let signal = Arc::clone(&running);
        let thread = thread::spawn(move || {
            while signal.load(Ordering::Acquire) {
                let now = unix_time().unwrap_or(0);
                if now >= next_drain && recovery.drain_internal_logs(now).is_ok() {
                    next_drain = now.saturating_add(DAY_SECONDS);
                }
                if now >= next_backup && recovery.scheduled_backup_and_rotate(now).is_ok() {
                    next_backup = now.saturating_add(interval);
                }
                for _ in 0..30 {
                    if !signal.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });
        Ok(Self {
            running,
            thread: Some(thread),
        })
    }

    pub fn shutdown(mut self) -> Result<(), ServiceError> {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| {
                ServiceError::service_unavailable("production scheduler did not stop")
            })?;
        }
        Ok(())
    }
}

impl Drop for ProductionSchedulerRuntime {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::internal("system time is before the Unix epoch"))
}

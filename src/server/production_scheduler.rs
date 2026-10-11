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

pub trait ScheduledCertificateRenewal: Send + Sync {
    fn run(&self, now: u64) -> Result<(), ServiceError>;
}

pub struct ProductionSchedulerRuntime {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ProductionSchedulerRuntime {
    pub fn start(
        configuration: &ServerConfiguration,
        recovery: Arc<ProductionRecoveryManagement>,
        certificates: Option<Arc<dyn ScheduledCertificateRenewal>>,
    ) -> Result<Self, ServiceError> {
        let now = unix_time()?;
        let interval = u64::from(configuration.backup_interval_days) * DAY_SECONDS;
        let latest = recovery.latest_backup_completed_at()?.unwrap_or(now);
        let mut next_backup = latest.saturating_add(interval);
        let mut next_drain = now;
        let mut next_certificate = next_local_daily_run(
            now,
            configuration
                .certificate_renewal_time
                .seconds_since_midnight(),
        )?;
        let running = Arc::new(AtomicBool::new(true));
        let signal = Arc::clone(&running);
        let thread = thread::spawn(move || {
            while signal.load(Ordering::Acquire) {
                let now = unix_time().unwrap_or(0);
                if now >= next_drain {
                    if recovery.drain_internal_logs(now).is_ok() {
                        next_drain = now.saturating_add(DAY_SECONDS);
                    }
                }
                if now >= next_backup {
                    if recovery.scheduled_backup_and_rotate(now).is_ok() {
                        next_backup = now.saturating_add(interval);
                    }
                }
                if now >= next_certificate {
                    if certificates
                        .as_ref()
                        .is_none_or(|renewal| renewal.run(now).is_ok())
                    {
                        next_certificate = next_local_daily_run(
                            now.saturating_add(1),
                            local_seconds_from_midnight(next_certificate).unwrap_or(0),
                        )
                        .unwrap_or(now.saturating_add(DAY_SECONDS));
                    }
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

fn next_local_daily_run(now: u64, seconds_since_midnight: u32) -> Result<u64, ServiceError> {
    let raw = now as libc::time_t;
    let mut local = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::localtime_r(&raw, &mut local) }.is_null() {
        return Err(ServiceError::internal(
            "local scheduler time is unavailable",
        ));
    }
    local.tm_hour = (seconds_since_midnight / 3600) as i32;
    local.tm_min = ((seconds_since_midnight % 3600) / 60) as i32;
    local.tm_sec = 0;
    let scheduled = unsafe { libc::mktime(&mut local) };
    if scheduled < 0 {
        return Err(ServiceError::internal("local scheduler time is invalid"));
    }
    let scheduled = scheduled as u64;
    Ok(if scheduled > now {
        scheduled
    } else {
        local.tm_mday += 1;
        let next = unsafe { libc::mktime(&mut local) };
        if next < 0 {
            return Err(ServiceError::internal("local scheduler time is invalid"));
        }
        next as u64
    })
}

fn local_seconds_from_midnight(value: u64) -> Result<u32, ServiceError> {
    let raw = value as libc::time_t;
    let mut local = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::localtime_r(&raw, &mut local) }.is_null() {
        return Err(ServiceError::internal(
            "local scheduler time is unavailable",
        ));
    }
    Ok((local.tm_hour as u32) * 3600 + (local.tm_min as u32) * 60)
}

fn unix_time() -> Result<u64, ServiceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServiceError::internal("system time is before the Unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_exact_next_local_daily_schedule() {
        let now = unix_time().unwrap();
        let next = next_local_daily_run(now, 4 * 3600).unwrap();
        assert!(next > now);
        assert!(next - now <= DAY_SECONDS + 3600);
        assert_eq!(local_seconds_from_midnight(next).unwrap(), 4 * 3600);
    }
}

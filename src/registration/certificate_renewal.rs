use std::path::PathBuf;

use crate::{pki_provisioning::PkiProvisioner, service_error::ServiceError};

const DAY_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplacementPackage {
    pub fingerprint: String,
    pub archive: PathBuf,
}

pub trait CertificateRenewalPoller {
    fn poll(&mut self) -> Result<Option<ReplacementPackage>, ServiceError>;
}

pub trait SecureListenerRestarter {
    fn install_and_restart(&mut self, replacement: &ReplacementPackage)
    -> Result<(), ServiceError>;
}

#[derive(Debug)]
pub struct DailyCertificateRenewal {
    next_run_at: u64,
}

pub struct PkiRenewalPoller<'a> {
    provisioner: &'a PkiProvisioner,
    current_fingerprint: String,
    target_name: String,
    staging_directory: PathBuf,
}

impl<'a> PkiRenewalPoller<'a> {
    pub fn new(
        provisioner: &'a PkiProvisioner,
        current_fingerprint: impl Into<String>,
        target_name: impl Into<String>,
        staging_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            provisioner,
            current_fingerprint: current_fingerprint.into(),
            target_name: target_name.into(),
            staging_directory: staging_directory.into(),
        }
    }

    pub fn current_fingerprint(&self) -> &str {
        &self.current_fingerprint
    }
}

impl CertificateRenewalPoller for PkiRenewalPoller<'_> {
    fn poll(&mut self) -> Result<Option<ReplacementPackage>, ServiceError> {
        let replacement = self.provisioner.renew_and_download(
            &self.current_fingerprint,
            &self.target_name,
            &self.staging_directory,
        )?;
        Ok(replacement.map(|replacement| {
            self.current_fingerprint = replacement.fingerprint.clone();
            ReplacementPackage {
                fingerprint: replacement.fingerprint,
                archive: replacement.download_file,
            }
        }))
    }
}

impl DailyCertificateRenewal {
    pub fn new(day_start: u64, seconds_since_midnight: u32, now: u64) -> Self {
        let scheduled = day_start.saturating_add(u64::from(seconds_since_midnight));
        let next_run_at = if scheduled > now {
            scheduled
        } else {
            scheduled.saturating_add(DAY_SECONDS)
        };
        Self { next_run_at }
    }

    pub fn next_run_at(&self) -> u64 {
        self.next_run_at
    }

    pub fn run_if_due<P: CertificateRenewalPoller, R: SecureListenerRestarter>(
        &mut self,
        now: u64,
        poller: &mut P,
        restarter: &mut R,
    ) -> Result<bool, ServiceError> {
        if now < self.next_run_at {
            return Ok(false);
        }
        while self.next_run_at <= now {
            self.next_run_at = self.next_run_at.saturating_add(DAY_SECONDS);
        }
        if let Some(replacement) = poller.poll()? {
            restarter.install_and_restart(&replacement)?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Poller {
        calls: usize,
        replacement: bool,
    }

    impl CertificateRenewalPoller for Poller {
        fn poll(&mut self) -> Result<Option<ReplacementPackage>, ServiceError> {
            self.calls += 1;
            Ok(self.replacement.then(|| ReplacementPackage {
                fingerprint: "a".repeat(64),
                archive: PathBuf::from("/protected/replacement.tar.gz"),
            }))
        }
    }

    #[derive(Default)]
    struct Restarter {
        replacements: Vec<String>,
    }

    impl SecureListenerRestarter for Restarter {
        fn install_and_restart(
            &mut self,
            replacement: &ReplacementPackage,
        ) -> Result<(), ServiceError> {
            self.replacements.push(replacement.fingerprint.clone());
            Ok(())
        }
    }

    #[test]
    fn runs_once_daily_at_injected_time_and_restarts_only_for_replacement() {
        let day_start = 1_000_000;
        let four_am = 4 * 3600;
        let due = day_start + four_am;
        let mut schedule = DailyCertificateRenewal::new(day_start, four_am as u32, due - 10);
        let mut no_change = Poller {
            calls: 0,
            replacement: false,
        };
        let mut restarter = Restarter::default();
        assert!(
            !schedule
                .run_if_due(due - 1, &mut no_change, &mut restarter)
                .unwrap()
        );
        assert!(
            schedule
                .run_if_due(due, &mut no_change, &mut restarter)
                .unwrap()
        );
        assert_eq!(no_change.calls, 1);
        assert!(restarter.replacements.is_empty());
        assert!(
            !schedule
                .run_if_due(due + 60, &mut no_change, &mut restarter)
                .unwrap()
        );

        let next_due = due + DAY_SECONDS;
        let mut replacement = Poller {
            calls: 0,
            replacement: true,
        };
        assert!(
            schedule
                .run_if_due(next_due, &mut replacement, &mut restarter)
                .unwrap()
        );
        assert_eq!(replacement.calls, 1);
        assert_eq!(restarter.replacements, vec!["a".repeat(64)]);
        assert_eq!(schedule.next_run_at(), next_due + DAY_SECONDS);
    }

    #[test]
    fn delayed_run_skips_missed_slots_without_repeating_in_one_day() {
        let mut schedule = DailyCertificateRenewal::new(0, 100, 0);
        let mut poller = Poller {
            calls: 0,
            replacement: false,
        };
        let mut restarter = Restarter::default();
        let delayed = 100 + DAY_SECONDS * 3 + 5;
        assert!(
            schedule
                .run_if_due(delayed, &mut poller, &mut restarter)
                .unwrap()
        );
        assert_eq!(poller.calls, 1);
        assert!(schedule.next_run_at() > delayed);
    }
}

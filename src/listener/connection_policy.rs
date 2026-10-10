use std::net::IpAddr;

use crate::service_error::ServiceError;

#[derive(Clone, Debug)]
pub struct ConnectionPolicy {
    network: IpAddr,
    prefix: u8,
    idle_timeout: u64,
    maximum_lifetime: u64,
}

#[derive(Clone, Debug)]
pub struct ConnectionLease {
    policy: ConnectionPolicy,
    opened_at: u64,
    last_activity_at: u64,
    certificate_not_after: Option<u64>,
}

impl ConnectionPolicy {
    pub fn new(
        allowed_source_cidr: &str,
        idle_timeout: u64,
        maximum_lifetime: u64,
    ) -> Result<Self, ServiceError> {
        let (address, prefix) = allowed_source_cidr
            .split_once('/')
            .ok_or_else(|| ServiceError::configuration_invalid("source CIDR is invalid"))?;
        let network: IpAddr = address
            .parse()
            .map_err(|_| ServiceError::configuration_invalid("source CIDR is invalid"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ServiceError::configuration_invalid("source CIDR is invalid"))?;
        let bits = if network.is_ipv4() { 32 } else { 128 };
        if prefix > bits || idle_timeout == 0 || maximum_lifetime == 0 {
            return Err(ServiceError::configuration_invalid(
                "connection policy value is invalid",
            ));
        }
        Ok(Self {
            network,
            prefix,
            idle_timeout,
            maximum_lifetime,
        })
    }

    pub fn permits(&self, source: IpAddr) -> bool {
        match (self.network, source) {
            (IpAddr::V4(network), IpAddr::V4(source)) => {
                let mask = prefix_mask(self.prefix, 32) as u32;
                u32::from(network) & mask == u32::from(source) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(source)) => {
                let mask = prefix_mask(self.prefix, 128);
                u128::from(network) & mask == u128::from(source) & mask
            }
            _ => false,
        }
    }

    pub fn accept(
        &self,
        source: IpAddr,
        now: u64,
        certificate_not_after: Option<u64>,
    ) -> Result<ConnectionLease, ServiceError> {
        if !self.permits(source) {
            return Err(classified(8023, "connection source is not authorized"));
        }
        if certificate_not_after.is_some_and(|deadline| now >= deadline) {
            return Err(classified(8012, "certificate is outside its valid time"));
        }
        Ok(ConnectionLease {
            policy: self.clone(),
            opened_at: now,
            last_activity_at: now,
            certificate_not_after,
        })
    }
}

impl ConnectionLease {
    pub fn begin_request(&mut self, now: u64) -> Result<(), ServiceError> {
        if now.saturating_sub(self.last_activity_at) >= self.policy.idle_timeout {
            return Err(classified(8024, "connection idle timeout expired"));
        }
        if now.saturating_sub(self.opened_at) >= self.policy.maximum_lifetime {
            return Err(classified(8025, "connection lifetime exceeded"));
        }
        if self
            .certificate_not_after
            .is_some_and(|deadline| now >= deadline)
        {
            return Err(classified(8026, "certificate connection deadline reached"));
        }
        self.last_activity_at = now;
        Ok(())
    }

    pub fn idle_deadline(&self) -> u64 {
        self.last_activity_at
            .saturating_add(self.policy.idle_timeout)
    }

    pub fn connection_deadline(&self) -> u64 {
        let lifetime = self.opened_at.saturating_add(self.policy.maximum_lifetime);
        self.certificate_not_after
            .map_or(lifetime, |certificate| lifetime.min(certificate))
    }
}

fn prefix_mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (bits - prefix) & (u128::MAX >> (128 - bits))
    }
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_ipv4_and_ipv6_source_cidr() {
        let ipv4 = ConnectionPolicy::new("192.0.2.0/24", 3600, 7200).unwrap();
        assert!(ipv4.permits("192.0.2.200".parse().unwrap()));
        assert!(!ipv4.permits("10.10.253.200".parse().unwrap()));
        let ipv6 = ConnectionPolicy::new("2001:db8:abcd::/48", 3600, 7200).unwrap();
        assert!(ipv6.permits("2001:db8:abcd::99".parse().unwrap()));
        assert!(!ipv6.permits("2001:db8:abce::99".parse().unwrap()));
    }

    #[test]
    fn refreshes_sliding_idle_deadline_only_on_work() {
        let policy = ConnectionPolicy::new("127.0.0.1/32", 3600, 20_000).unwrap();
        let mut lease = policy
            .accept("127.0.0.1".parse().unwrap(), 1_000, None)
            .unwrap();
        assert_eq!(lease.idle_deadline(), 4_600);
        lease.begin_request(4_599).unwrap();
        assert_eq!(lease.idle_deadline(), 8_199);
        assert_eq!(lease.begin_request(8_199).unwrap_err().code(), 8024);
    }

    #[test]
    fn closes_at_earliest_lifetime_or_certificate_deadline() {
        let policy = ConnectionPolicy::new("127.0.0.1/32", 10_000, 7_200).unwrap();
        let mut certificate_first = policy
            .accept("127.0.0.1".parse().unwrap(), 1_000, Some(5_000))
            .unwrap();
        assert_eq!(certificate_first.connection_deadline(), 5_000);
        assert_eq!(
            certificate_first.begin_request(5_000).unwrap_err().code(),
            8026
        );
        let mut lifetime_first = policy
            .accept("127.0.0.1".parse().unwrap(), 1_000, Some(20_000))
            .unwrap();
        assert_eq!(lifetime_first.connection_deadline(), 8_200);
        assert_eq!(
            lifetime_first.begin_request(8_200).unwrap_err().code(),
            8025
        );
    }
}

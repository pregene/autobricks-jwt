use crate::service_error::ServiceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwningBoundary {
    Protocol,
    Certificate,
    Authorization,
    Registration,
    Issuance,
    Session,
    Audit,
    Storage,
    Runtime,
}

impl OwningBoundary {
    pub fn for_code(code: u16) -> Option<Self> {
        match code {
            8000..=8009 => Some(Self::Protocol),
            8010..=8029 => Some(Self::Certificate),
            8030..=8032 => Some(Self::Authorization),
            8040..=8044 => Some(Self::Registration),
            8050..=8056 => Some(Self::Issuance),
            8060..=8066 => Some(Self::Session),
            8070..=8073 => Some(Self::Audit),
            8080..=8086 => Some(Self::Storage),
            8090..=8093 => Some(Self::Runtime),
            _ => None,
        }
    }

    pub fn failure(
        self,
        code: u16,
        safe_diagnostic: &'static str,
    ) -> Result<ServiceError, ServiceError> {
        if Self::for_code(code) != Some(self) {
            return Err(ServiceError::configuration_invalid(
                "error code does not belong to this boundary",
            ));
        }
        ServiceError::classified(code, safe_diagnostic)
            .map_err(|_| ServiceError::configuration_invalid("error code is not assigned"))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProtocolAdmission {
    pub supported_version: u16,
    pub maximum_frame_bytes: usize,
    pub rate_remaining: u32,
    pub in_flight: u32,
    pub maximum_in_flight: u32,
    pub accepting: bool,
    pub remaining_capacity: u32,
}

impl ProtocolAdmission {
    pub fn validate(&self, version: u16, frame_bytes: usize) -> Result<(), ServiceError> {
        if !self.accepting {
            return Err(OwningBoundary::Runtime
                .failure(8092, "service is shutting down")
                .expect("owned code"));
        }
        if self.remaining_capacity == 0 {
            return Err(OwningBoundary::Runtime
                .failure(8093, "runtime capacity is exhausted")
                .expect("owned code"));
        }
        if version != self.supported_version {
            return Err(OwningBoundary::Protocol
                .failure(8003, "protocol version is unsupported")
                .expect("owned code"));
        }
        if frame_bytes > self.maximum_frame_bytes {
            return Err(OwningBoundary::Protocol
                .failure(8004, "request frame is too large")
                .expect("owned code"));
        }
        if self.rate_remaining == 0 {
            return Err(OwningBoundary::Protocol
                .failure(8007, "request rate is exceeded")
                .expect("owned code"));
        }
        if self.in_flight >= self.maximum_in_flight {
            return Err(OwningBoundary::Protocol
                .failure(8008, "in-flight request limit is exceeded")
                .expect("owned code"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_registry::ERROR_REGISTRY;

    #[test]
    fn every_assigned_error_is_triggered_only_by_its_owning_boundary() {
        let mut triggered = Vec::new();
        for definition in ERROR_REGISTRY {
            let boundary =
                OwningBoundary::for_code(definition.code).expect("assigned code needs an owner");
            let error = boundary
                .failure(definition.code, "boundary condition triggered")
                .unwrap();
            assert_eq!(
                (error.code(), error.name()),
                (definition.code, definition.name)
            );
            let wrong = if boundary == OwningBoundary::Protocol {
                OwningBoundary::Storage
            } else {
                OwningBoundary::Protocol
            };
            assert_eq!(
                wrong
                    .failure(definition.code, "wrong boundary")
                    .unwrap_err()
                    .code(),
                8090
            );
            triggered.push(error.code());
        }
        assert_eq!(triggered.len(), 67);
    }

    #[test]
    fn runtime_admission_triggers_version_size_rate_inflight_shutdown_and_capacity_errors() {
        let base = ProtocolAdmission {
            supported_version: 1,
            maximum_frame_bytes: 10,
            rate_remaining: 1,
            in_flight: 0,
            maximum_in_flight: 1,
            accepting: true,
            remaining_capacity: 1,
        };
        assert_eq!(base.validate(2, 1).unwrap_err().code(), 8003);
        assert_eq!(base.validate(1, 11).unwrap_err().code(), 8004);
        assert_eq!(
            ProtocolAdmission {
                rate_remaining: 0,
                ..base
            }
            .validate(1, 1)
            .unwrap_err()
            .code(),
            8007
        );
        let base = ProtocolAdmission {
            supported_version: 1,
            maximum_frame_bytes: 10,
            rate_remaining: 1,
            in_flight: 1,
            maximum_in_flight: 1,
            accepting: true,
            remaining_capacity: 1,
        };
        assert_eq!(base.validate(1, 1).unwrap_err().code(), 8008);
        let base = ProtocolAdmission {
            accepting: false,
            ..base
        };
        assert_eq!(base.validate(1, 1).unwrap_err().code(), 8092);
        let base = ProtocolAdmission {
            accepting: true,
            remaining_capacity: 0,
            ..base
        };
        assert_eq!(base.validate(1, 1).unwrap_err().code(), 8093);
    }
}

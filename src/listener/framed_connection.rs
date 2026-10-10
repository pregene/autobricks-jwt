use std::io::{ErrorKind, Read, Write};

use crate::{connection_policy::ConnectionLease, service_error::ServiceError};

pub const MAX_SERVICE_FRAME: usize = 1024 * 1024;

pub fn process_frames<S, C, H>(
    stream: &mut S,
    lease: &mut ConnectionLease,
    clock: C,
    handler: H,
) -> Result<usize, ServiceError>
where
    S: Read + Write,
    C: FnMut() -> u64,
    H: FnMut(&[u8]) -> Result<Vec<u8>, ServiceError>,
{
    process_frames_with_revalidation(stream, lease, clock, || Ok(()), handler)
}

pub fn process_frames_with_revalidation<S, C, V, H>(
    stream: &mut S,
    lease: &mut ConnectionLease,
    mut clock: C,
    mut revalidate_certificate: V,
    mut handler: H,
) -> Result<usize, ServiceError>
where
    S: Read + Write,
    C: FnMut() -> u64,
    V: FnMut() -> Result<(), ServiceError>,
    H: FnMut(&[u8]) -> Result<Vec<u8>, ServiceError>,
{
    let mut processed = 0;
    loop {
        let mut length = [0_u8; 4];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(processed),
            Err(_) => return Err(classified(8005, "service frame header is malformed")),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 {
            return Err(classified(8005, "service frame is empty"));
        }
        if length > MAX_SERVICE_FRAME {
            return Err(classified(
                8004,
                "service frame exceeds the configured limit",
            ));
        }
        let mut frame = vec![0_u8; length];
        stream
            .read_exact(&mut frame)
            .map_err(|_| classified(8005, "service frame body is malformed"))?;
        lease.begin_request(clock())?;
        revalidate_certificate()?;
        let response = handler(&frame)?;
        if response.len() > MAX_SERVICE_FRAME {
            return Err(ServiceError::internal(
                "service response exceeds the frame limit",
            ));
        }
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .and_then(|_| stream.flush())
            .map_err(|_| ServiceError::service_unavailable("service response write failed"))?;
        processed += 1;
    }
}

fn classified(code: u16, message: &'static str) -> ServiceError {
    ServiceError::classified(code, message).expect("ERROR.md code must be assigned")
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::*;
    use crate::connection_policy::ConnectionPolicy;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn processes_multiple_frames_and_refreshes_activity() {
        let mut bytes = Vec::new();
        for request in [b"one".as_slice(), b"two".as_slice()] {
            bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
            bytes.extend_from_slice(request);
        }
        let mut stream = Duplex {
            input: Cursor::new(bytes),
            output: Vec::new(),
        };
        let policy = ConnectionPolicy::new("127.0.0.1/32", 100, 1000).unwrap();
        let mut lease = policy
            .accept("127.0.0.1".parse().unwrap(), 10, None)
            .unwrap();
        let mut times = [20_u64, 90].into_iter();
        let processed = process_frames(
            &mut stream,
            &mut lease,
            || times.next().unwrap(),
            |frame| Ok(frame.to_ascii_uppercase()),
        )
        .unwrap();
        assert_eq!(processed, 2);
        assert_eq!(lease.idle_deadline(), 190);
        assert_eq!(stream.output, b"\0\0\0\x03ONE\0\0\0\x03TWO");
    }

    #[test]
    fn rejects_oversized_frame_before_allocation() {
        let mut stream = Duplex {
            input: Cursor::new(((MAX_SERVICE_FRAME as u32) + 1).to_be_bytes().to_vec()),
            output: Vec::new(),
        };
        let policy = ConnectionPolicy::new("127.0.0.1/32", 100, 1000).unwrap();
        let mut lease = policy
            .accept("127.0.0.1".parse().unwrap(), 10, None)
            .unwrap();
        let error = process_frames(&mut stream, &mut lease, || 20, |_| Ok(vec![])).unwrap_err();
        assert_eq!(error.code(), 8004);
    }

    #[test]
    fn revalidates_certificate_before_every_persistent_request() {
        let mut bytes = Vec::new();
        for request in [b"one".as_slice(), b"two".as_slice()] {
            bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
            bytes.extend_from_slice(request);
        }
        let mut stream = Duplex {
            input: Cursor::new(bytes),
            output: Vec::new(),
        };
        let policy = ConnectionPolicy::new("127.0.0.1/32", 100, 1000).unwrap();
        let mut lease = policy
            .accept("127.0.0.1".parse().unwrap(), 10, Some(900))
            .unwrap();
        let mut checks = 0;
        let error = process_frames_with_revalidation(
            &mut stream,
            &mut lease,
            || 20,
            || {
                checks += 1;
                if checks == 1 {
                    Ok(())
                } else {
                    Err(ServiceError::classified(8017, "certificate is revoked").unwrap())
                }
            },
            |frame| Ok(frame.to_vec()),
        )
        .unwrap_err();
        assert_eq!(checks, 2);
        assert_eq!(error.code(), 8017);
        assert_eq!(stream.output, b"\0\0\0\x03one");
    }
}

use std::{
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    connection_policy::ConnectionPolicy, framed_connection::process_frames,
    service_error::ServiceError,
};

pub struct TcpListenerEndpoint {
    listener: TcpListener,
}

impl TcpListenerEndpoint {
    pub fn bind(address: impl ToSocketAddrs) -> Result<Self, ServiceError> {
        let listener = TcpListener::bind(address)
            .map_err(|_| ServiceError::service_unavailable("TCP listener cannot be created"))?;
        Ok(Self { listener })
    }

    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ServiceError> {
        self.listener.local_addr().map_err(|_| {
            ServiceError::service_unavailable("TCP listener address cannot be inspected")
        })
    }

    pub fn serve_one<H>(&self, policy: &ConnectionPolicy, handler: H) -> Result<usize, ServiceError>
    where
        H: FnMut(&[u8]) -> Result<Vec<u8>, ServiceError>,
    {
        let (mut stream, peer) = self
            .listener
            .accept()
            .map_err(|_| ServiceError::service_unavailable("TCP connection cannot be accepted"))?;
        let now = unix_time();
        let mut lease = policy.accept(peer.ip(), now, None)?;
        process_frames(&mut stream, &mut lease, unix_time, handler)
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        thread,
    };

    use super::TcpListenerEndpoint;

    #[test]
    #[ignore = "creates a local TCP listener"]
    fn accepts_tcp_connection_and_exchanges_data() {
        let endpoint = TcpListenerEndpoint::bind("127.0.0.1:0").unwrap();
        let address = endpoint.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = endpoint.listener().accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"PING");
            stream.write_all(b"PONG").unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"PING").unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"PONG");
        server.join().unwrap();

        println!("TCP listener bound: {address}");
        println!("TCP connection: accepted");
        println!("TCP data exchange: PING/PONG verified");
    }
}

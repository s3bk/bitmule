//! A minimal STUN server (RFC 5389): it answers Binding requests with the
//! address the request came from, so clients behind a NAT can learn the
//! public address of a UDP socket. Nothing else is implemented.

use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;
use tracing::{debug, warn};

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Answer Binding requests on `socket` until the task is dropped.
pub async fn serve(socket: UdpSocket) {
    let mut buf = [0u8; 1500];
    loop {
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("stun recv: {e}");
                continue;
            }
        };
        if let Some(response) = respond(&buf[..n], source) {
            if let Err(e) = socket.send_to(&response, source).await {
                debug!("stun send to {source}: {e}");
            }
        }
    }
}

/// The response to `request` from `source`, if it is a Binding request.
pub fn respond(request: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }
    let kind = u16::from_be_bytes([request[0], request[1]]);
    let magic = u32::from_be_bytes(request[4..8].try_into().unwrap());
    if kind != BINDING_REQUEST || magic != MAGIC {
        return None;
    }
    let transaction = &request[8..20];

    let mut value = vec![0u8, 0];
    value.extend_from_slice(&(source.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
    match source.ip() {
        IpAddr::V4(ip) => {
            value[1] = 0x01;
            value.extend_from_slice(&(u32::from(ip) ^ MAGIC).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value[1] = 0x02;
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
            mask[4..].copy_from_slice(transaction);
            let mut octets = ip.octets();
            octets.iter_mut().zip(mask).for_each(|(o, m)| *o ^= m);
            value.extend_from_slice(&octets);
        }
    }

    let mut out = Vec::with_capacity(20 + 4 + value.len());
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(transaction);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_a_binding_request_with_the_source_address() {
        let mut request = vec![0, 1, 0, 0];
        request.extend_from_slice(&MAGIC.to_be_bytes());
        request.extend_from_slice(&[7u8; 12]);
        let source: SocketAddr = "203.0.113.9:54321".parse().unwrap();

        let response = respond(&request, source).unwrap();
        assert_eq!(response[..2], [0x01, 0x01]);
        assert_eq!(response[8..20], [7u8; 12]);
        let value = &response[24..32];
        assert_eq!(u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC >> 16) as u16, 54321);
        assert_eq!(u32::from_be_bytes(value[4..8].try_into().unwrap()) ^ MAGIC, u32::from(std::net::Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn ignores_other_packets() {
        assert!(respond(&[0u8; 20], "127.0.0.1:1".parse().unwrap()).is_none());
        assert!(respond(b"short", "127.0.0.1:1".parse().unwrap()).is_none());
    }
}

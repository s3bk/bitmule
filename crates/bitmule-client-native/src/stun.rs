//! Learn the public address of a UDP socket from a STUN server (RFC 5389
//! Binding request). The answer is the address a NAT mapped the socket to,
//! which the peer can send to: a server reflexive ICE candidate.

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};

use anyhow::{Result, bail};
use rand_core::RngCore;
use tokio::net::UdpSocket;

const MAGIC: u32 = 0x2112_A442;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;
const ATTEMPTS: u32 = 3;
const WAIT: Duration = Duration::from_millis(400);

/// The public address of `socket` as `server` sees it. Retries a few times,
/// as UDP loses packets.
pub async fn public_addr(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    let mut transaction = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut transaction);
    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&0x0001u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&MAGIC.to_be_bytes());
    request.extend_from_slice(&transaction);

    let mut buf = [0u8; 1500];
    for _ in 0..ATTEMPTS {
        socket.send_to(&request, server).await?;
        let deadline = tokio::time::Instant::now() + WAIT;
        // other packets may arrive first; only the answer to this request counts
        while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            let (n, from) = received?;
            if from == server {
                if let Some(addr) = parse(&buf[..n], &transaction) {
                    return Ok(addr);
                }
            }
        }
    }
    bail!("no STUN answer from {server}")
}

fn parse(response: &[u8], transaction: &[u8; 12]) -> Option<SocketAddr> {
    if response.len() < 20 || response[0..2] != [0x01, 0x01] || response[8..20] != transaction[..] {
        return None;
    }
    let mut attributes = &response[20..];
    let mut mapped = None;
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let len = u16::from_be_bytes([attributes[2], attributes[3]]) as usize;
        let value = attributes.get(4..4 + len)?;
        match kind {
            XOR_MAPPED_ADDRESS => return address(value, true, transaction),
            MAPPED_ADDRESS => mapped = address(value, false, transaction),
            _ => {}
        }
        attributes = attributes.get(4 + len.next_multiple_of(4)..).unwrap_or(&[]);
    }
    mapped
}

fn address(value: &[u8], xored: bool, transaction: &[u8; 12]) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let mut port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    if xored {
        port ^= (MAGIC >> 16) as u16;
    }
    let ip = match family {
        0x01 => {
            let mut raw = u32::from_be_bytes(value.get(4..8)?.try_into().ok()?);
            if xored {
                raw ^= MAGIC;
            }
            IpAddr::V4(Ipv4Addr::from(raw))
        }
        0x02 => {
            let mut raw: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            if xored {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC.to_be_bytes());
                mask[4..].copy_from_slice(transaction);
                raw.iter_mut().zip(mask).for_each(|(o, m)| *o ^= m);
            }
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client against a responder written separately (the server crate's
    /// is not a dependency): a fixed answer with a known mapped address.
    #[tokio::test]
    async fn learns_the_mapped_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 100];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let mut out = vec![0x01, 0x01, 0, 12];
            out.extend_from_slice(&MAGIC.to_be_bytes());
            out.extend_from_slice(&buf[8..20]);
            out.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
            out.extend_from_slice(&(from.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
            let IpAddr::V4(ip) = from.ip() else { unreachable!() };
            out.extend_from_slice(&(u32::from(ip) ^ MAGIC).to_be_bytes());
            server.send_to(&out, from).await.unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mapped = public_addr(&client, server_addr).await.unwrap();
        assert_eq!(mapped, client.local_addr().unwrap());
    }
}

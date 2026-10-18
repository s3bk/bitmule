//! Limit the client to one network interface (`--nic`).
//!
//! The choice is process-wide: set once at startup, then every socket the
//! client opens (WebRTC UDP, the websocket, relay HTTP) goes through the
//! helpers here. With no interface set they behave like the plain calls.

use std::{
    ffi::CStr,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
};

use anyhow::{Result, bail};
use tokio::net::{TcpStream, UdpSocket};

static NIC: OnceLock<String> = OnceLock::new();

/// Restrict the client to `name`. Fails if the interface does not exist or has no address.
pub fn set(name: &str) -> Result<()> {
    let ips = ips(name)?;
    if ips.is_empty() {
        bail!("interface {name} has no usable address");
    }
    NIC.set(name.to_string()).map_err(|_| anyhow::anyhow!("interface already set"))
}

pub fn get() -> Option<&'static str> {
    NIC.get().map(String::as_str)
}

/// Addresses of interface `name` (link-local IPv6 left out: it needs a scope id).
pub fn ips(name: &str) -> Result<Vec<IpAddr>> {
    let (found, names) = interfaces()?;
    if !names.iter().any(|n| n == name) {
        bail!("no interface named {name} (have: {})", names.join(", "));
    }
    Ok(found.into_iter().filter(|(n, _)| n == name).map(|(_, ip)| ip).collect())
}

#[cfg(unix)]
fn interfaces() -> Result<(Vec<(String, IpAddr)>, Vec<String>)> {
    let mut found = Vec::new();
    let mut names: Vec<String> = Vec::new();
    // SAFETY: the list from getifaddrs is only read until freeifaddrs.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            if !names.contains(&name) {
                names.push(name.clone());
            }
            if ifa.ifa_addr.is_null() {
                continue;
            }
            match (*ifa.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    found.push((name, IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)))));
                }
                libc::AF_INET6 => {
                    let a = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
                    if !ip.is_unicast_link_local() {
                        found.push((name, IpAddr::V6(ip)));
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(head);
    }
    Ok((found, names))
}

#[cfg(not(unix))]
fn interfaces() -> Result<(Vec<(String, IpAddr)>, Vec<String>)> {
    bail!("--nic is only supported on unix")
}

#[cfg(target_os = "linux")]
fn pin(socket: &socket2::Socket, name: &str) -> std::io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn pin(_socket: &socket2::Socket, _name: &str) -> std::io::Result<()> {
    Ok(()) // bound by address only
}

/// A UDP socket at `addr`, pinned to the interface if one is set.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if let Some(name) = get() {
        pin(&socket, name)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// A TCP connection to `host:port`, over the interface if one is set.
pub async fn connect_tcp(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let Some(name) = get() else {
        return TcpStream::connect((host, port)).await;
    };
    let mut last = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        let attempt = async {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            pin(&socket, name)?;
            socket.set_nonblocking(true)?;
            let socket = tokio::net::TcpSocket::from_std_stream(socket.into());
            socket.connect(addr).await
        };
        match attempt.await {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other(format!("no address for {host}"))))
}

/// An HTTP client that uses the interface if one is set.
pub fn http_client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(name) = get() {
        builder = builder.interface(name);
    }
    builder.build().expect("http client")
}

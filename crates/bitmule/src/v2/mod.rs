//! The v2 client: sending and receiving files through a bitmule server.
//!
//! Everything is a worker (a tokio task) that talks to the others through
//! channels, and each knows only its neighbours:
//!
//! ```text
//!  server <-ws-> session --routes--> peer worker <-decrypted messages-> demux
//!  (session.rs)                      (peer.rs)                             |
//!                                          signaling (SDP) ----> WebRTC worker (rtc.rs)
//!                                          app messages  ----> transfer worker (send.rs / recv.rs)
//! ```
//!
//! - `session`: the websocket to the server: proof of work, create or join,
//!   and handing each peer's messages to its peer worker.
//! - `peer`: the key exchange with one peer, then sealing and opening. Past
//!   this point there are no websockets and no ciphertext.
//! - `bitmule_client_native::rtc`: a WebRTC data channel. It exchanges only
//!   `Peer2Peer` SDP messages through the peer worker.
//! - `send` / `recv`: the transfer itself, over the relay (fountain coded),
//!   the data channel, or both; the receiver takes whichever finishes first.
//! - `dcproto`: what goes over the data channel.

mod dcproto;
mod peer;
mod recv;
mod send;
mod session;

use anyhow::Result;
use bitmule_client_common::transfer::Transfer;
use bitmule_client_native::{TransportMode, crypto::ShareLink};
use bitmule_core::protocol::websocket::{PeerCaps, TransferManifest};

/// A bitmule server, as reached by this client.
#[derive(Clone, Debug)]
pub struct Server {
    /// `host[:port]`
    pub host: String,
    pub tls: bool,
    /// `host:port` of the STUN server, if any.
    pub stun: Option<String>,
}

impl Server {
    /// Accepts `http://host`, `https://host`, or a bare `host` (TLS).
    pub fn parse(s: &str) -> Self {
        let s = s.trim().trim_end_matches('/');
        if let Some(host) = s.strip_prefix("http://") {
            Server::with_stun(host.into(), false)
        } else {
            Server::with_stun(s.strip_prefix("https://").unwrap_or(s).into(), true)
        }
    }

    /// The STUN server is expected next to the relay, on UDP port 3478.
    fn with_stun(host: String, tls: bool) -> Self {
        let name = host.rsplit_once(':').map_or(host.as_str(), |(name, _)| name);
        let stun = Some(format!("{name}:3478"));
        Server { host, tls, stun }
    }

    /// The address of the STUN server, if one is set and resolves.
    pub async fn stun_addr(&self) -> Option<std::net::SocketAddr> {
        let found = tokio::net::lookup_host(self.stun.as_deref()?).await.ok()?;
        found.filter(|a| a.is_ipv4()).next()
    }

    pub fn http(&self, path: &str) -> String {
        format!("{}://{}{path}", if self.tls { "https" } else { "http" }, self.host)
    }

    pub fn ws(&self, path: &str) -> String {
        format!("{}://{}{path}", if self.tls { "wss" } else { "ws" }, self.host)
    }

    /// The URL to hand to a receiver.
    pub fn share_url(&self, link: &ShareLink) -> String {
        format!("{}/#{}", self.http(""), link.to_b64_url())
    }
}

/// Which transports to use.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub webrtc: bool,
    pub relay: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { webrtc: true, relay: true }
    }
}

impl Options {
    pub fn from_mode(mode: TransportMode) -> Self {
        match mode {
            TransportMode::Auto => Options { webrtc: true, relay: true },
            TransportMode::Webrtc => Options { webrtc: true, relay: false },
            TransportMode::Relay => Options { webrtc: false, relay: true },
        }
    }

    fn caps(self) -> PeerCaps {
        let mut caps = PeerCaps::empty();
        caps.set(PeerCaps::RELAY, self.relay);
        caps.set(PeerCaps::WEBRTC, self.webrtc);
        caps
    }
}

/// How the data arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Relay,
    WebRtc,
}

pub struct Report {
    pub manifest: TransferManifest,
    pub transport: Transport,
    /// Bytes that came over the relay and over the data channel. A transfer
    /// that starts on the relay and moves to the data channel has both.
    pub relay_bytes: u64,
    pub data_channel_bytes: u64,
}

/// Send `transfer` to every receiver that joins; returns once the receivers
/// that connected have all finished. `on_link` is called with the share link
/// as soon as the session exists.
pub async fn run_send(
    server: &Server,
    manifest: TransferManifest,
    transfer: Transfer,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
) -> Result<()> {
    session::send(server, manifest, transfer, options, on_link).await
}

/// Receive the transfer behind `link` into `out` (which must be readable and
/// writable). Returns once the data has been written and checked against the
/// link's signature.
pub async fn run_recv(
    server: &Server,
    link: &ShareLink,
    out: std::fs::File,
    options: Options,
) -> Result<Report> {
    session::receive(server, link, out, options).await
}

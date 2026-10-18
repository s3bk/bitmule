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
use bitmule_client_native::{TransportMode, crypto::{ShareKey, ShareLink}};
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

    /// The link a receiver hands to a sender to ask for a transfer.
    pub fn request_url(&self, key: &ShareKey) -> String {
        format!("{}/send#{}", self.http(""), key.to_hex())
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

/// When the first and the last piece (data channel) or symbol (relay) of a
/// transfer went by: the time the bytes were in flight, without the
/// connection set-up before and the verification after.
#[derive(Clone, Copy, Default, Debug)]
pub struct Span {
    first: Option<std::time::Instant>,
    last: Option<std::time::Instant>,
}

impl Span {
    pub fn mark(&mut self) {
        let now = std::time::Instant::now();
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    /// Cover what `other` covers too.
    pub fn merge(&mut self, other: Span) {
        self.first = self.first.into_iter().chain(other.first).min();
        self.last = self.last.into_iter().chain(other.last).max();
    }

    /// First mark to last mark; `None` if nothing was marked.
    pub fn elapsed(&self) -> Option<std::time::Duration> {
        Some(self.last?.duration_since(self.first?))
    }

    /// "256.0 MiB in 3.42 s (74.8 MiB/s)", or `None` if nothing went by.
    pub fn describe(&self, bytes: u64) -> Option<String> {
        let time = self.elapsed()?.as_secs_f64();
        let mib = bytes as f64 / (1024.0 * 1024.0);
        Some(format!("{mib:.1} MiB in {time:.2} s ({:.1} MiB/s)", mib / time.max(1e-9)))
    }
}

pub struct Report {
    pub manifest: TransferManifest,
    pub transport: Transport,
    /// Bytes that came over the relay and over the data channel. A transfer
    /// that starts on the relay and moves to the data channel has both.
    pub relay_bytes: u64,
    pub data_channel_bytes: u64,
    /// First to last relay symbol / data channel piece received.
    pub relay_time: Span,
    pub data_channel_time: Span,
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

/// Receiver-initiated transfers: `on_request` gets the key to put in the link
/// for the sender (see `Server::request_url`); returns the share link the
/// sender made, to be received with `run_recv`.
pub async fn run_request(
    server: &Server,
    options: Options,
    on_request: impl FnOnce(&ShareKey),
) -> Result<ShareLink> {
    session::request(server, options, on_request).await
}

/// Send `transfer` to the receiver that made the request link with `request`.
pub async fn run_send_to(
    server: &Server,
    request: &ShareKey,
    manifest: TransferManifest,
    transfer: Transfer,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
) -> Result<()> {
    session::send_to_request(server, request, manifest, transfer, options, on_link).await
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
    run_recv_with(server, link, move |_| Ok(out), options).await
}

/// Like `run_recv`, with the output file made once the sender's manifest is
/// known, so it can be named after what the sender calls the file
/// (`TransferManifest::file_name`).
pub async fn run_recv_with(
    server: &Server,
    link: &ShareLink,
    open: impl FnOnce(&TransferManifest) -> std::io::Result<std::fs::File> + Send + 'static,
    options: Options,
) -> Result<Report> {
    session::receive(server, link, Box::new(open), None, options).await
}

/// Like `run_recv_with`, calling `progress(received, total)` as data arrives.
pub async fn run_recv_progress(
    server: &Server,
    link: &ShareLink,
    open: impl FnOnce(&TransferManifest) -> std::io::Result<std::fs::File> + Send + 'static,
    progress: impl Fn(u64, u64) + Send + Sync + 'static,
    options: Options,
) -> Result<Report> {
    session::receive(server, link, Box::new(open), Some(std::sync::Arc::new(progress)), options).await
}

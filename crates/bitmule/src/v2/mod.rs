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
mod need;
mod peer;
mod recv;
mod send;
pub use send::{Reader, StreamInfo, StreamSource};
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

    /// Like [`Server::parse`], but a server without TLS (`http://`) is an
    /// error unless `allow_insecure`: the transfer stays encrypted end to
    /// end either way, but over plain `ws`/`http` anybody on the path sees
    /// who talks to whom and can drop or delay anything.
    pub fn parse_checked(s: &str, allow_insecure: bool) -> anyhow::Result<Self> {
        let s = s.trim();
        let Some((scheme, rest)) = s.split_once("://") else {
            return Ok(Server::parse(s)); // a bare host: TLS
        };
        match scheme.to_ascii_lowercase().as_str() {
            "https" => Ok(Server::parse(&format!("https://{rest}"))),
            "http" if allow_insecure => Ok(Server::parse(&format!("http://{rest}"))),
            "http" => anyhow::bail!("{s} is not https: the connection to the server would be unencrypted (--unsafe allows it)"),
            other => anyhow::bail!("{s}: the server's scheme must be https, not {other}"),
        }
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

#[cfg(test)]
mod tests {
    use super::Server;

    #[test]
    fn plain_http_needs_permission() {
        assert!(Server::parse_checked("https://bitmule.example", false).unwrap().tls);
        assert!(Server::parse_checked("bitmule.example:8443", false).unwrap().tls);
        assert!(Server::parse_checked("HTTPS://bitmule.example", false).unwrap().tls);
        assert!(Server::parse_checked("http://127.0.0.1:8443", false).is_err());
        assert!(Server::parse_checked("HTTP://127.0.0.1:8443", false).is_err());
        assert!(Server::parse_checked("ws://127.0.0.1:8443", true).is_err());
        let plain = Server::parse_checked("HTTP://127.0.0.1:8443", true).unwrap();
        assert!(!plain.tls && plain.host == "127.0.0.1:8443");
    }
}

/// Which transports to use.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub webrtc: bool,
    pub relay: bool,
    /// Raw fountain symbols over UDP, straight between native peers. Tried
    /// first when both sides allow it; the other transports take over if no
    /// path is found.
    pub udp: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { webrtc: true, relay: true, udp: false }
    }
}

impl Options {
    pub fn from_mode(mode: TransportMode) -> Self {
        match mode {
            TransportMode::Auto => Options { webrtc: true, relay: true, udp: false },
            TransportMode::Webrtc => Options { webrtc: true, relay: false, udp: false },
            TransportMode::Relay => Options { webrtc: false, relay: true, udp: false },
        }
    }

    /// These options with UDP on. `only`: nothing else (no fallback).
    pub fn with_udp(mut self, only: bool) -> Self {
        self.udp = true;
        if only {
            self.relay = false;
            self.webrtc = false;
        }
        self
    }

    fn caps(self) -> PeerCaps {
        let mut caps = PeerCaps::empty();
        caps.set(PeerCaps::RELAY, self.relay);
        caps.set(PeerCaps::WEBRTC, self.webrtc);
        caps.set(PeerCaps::UDP, self.udp);
        caps
    }
}

/// How the data arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Relay,
    WebRtc,
    Udp,
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

/// The received data does not match its checksum (the share link's signature,
/// or the one a streaming sender sent after the data). The file that was
/// written is not what was sent.
#[derive(Debug)]
pub struct VerifyFailed(pub &'static str);

impl std::fmt::Display for VerifyFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for VerifyFailed {}

pub struct Report {
    pub manifest: TransferManifest,
    pub transport: Transport,
    /// Bytes that came over the relay and over the data channel. A transfer
    /// that starts on the relay and moves to the data channel has both.
    pub relay_bytes: u64,
    pub data_channel_bytes: u64,
    /// Bytes that came over UDP (the whole transfer when `transport` is `Udp`).
    pub udp_bytes: u64,
    /// First to last relay symbol / data channel piece / UDP symbol received.
    pub relay_time: Span,
    pub data_channel_time: Span,
    pub udp_time: Span,
}

/// What a sender learns about its receivers. `receiver` is a short id, the
/// same for all events of one receiver.
#[derive(Clone, Debug)]
pub enum SendEvent {
    /// A receiver joined the session.
    Connected { receiver: String },
    /// The receiver has this many of `total` bytes (what it reports itself,
    /// so it counts the relay and the data channel alike).
    Progress { receiver: String, bytes: u64, total: u64 },
    /// The receiver has the whole file.
    Done { receiver: String },
}

/// Called for every [`SendEvent`], from the sender's worker tasks.
pub type OnSendEvent = std::sync::Arc<dyn Fn(SendEvent) + Send + Sync>;

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
    run_send_events(server, manifest, transfer, options, on_link, std::sync::Arc::new(|_| {})).await
}

/// Send data as it is read, when its size and hash are not known until all of
/// it has been: `info` says what it is, `source` where it comes from (see
/// [`StreamSource`]: it is read once per pass, which is why it has to be
/// restartable, or is kept in a temporary file). The share link comes with
/// no signature (an all-zero one) because the checksum can only follow the
/// data. Receivers must be streaming-aware, see `recv.rs`: a streaming
/// transfer goes over the relay only.
pub async fn run_send_stream(
    server: &Server,
    info: StreamInfo,
    source: StreamSource,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
    on_event: OnSendEvent,
) -> Result<()> {
    session::send_stream(server, info, source, options, on_link, on_event).await
}

/// `run_send`, and `on_event` hears about the receivers: who connected, how
/// far each one is, who finished.
pub async fn run_send_events(
    server: &Server,
    manifest: TransferManifest,
    transfer: Transfer,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
    on_event: OnSendEvent,
) -> Result<()> {
    session::send(server, manifest, transfer, options, on_link, on_event).await
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

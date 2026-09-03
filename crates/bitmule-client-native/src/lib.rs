//! bitmule-client-native — CLI-side counterpart to the browser SPA.
//!
//! Same wire protocol as `web/main.js`: a WebSocket to
//! `bitmule-server`'s `/ws/<hex>` carries JSON signaling frames
//! (`hello`, `peer_hello`, `sdp`, `ice`); a WebRTC peer connection
//! then opens a data channel labelled `bitmule` for the actual chunk
//! stream.
//!
//! Two entry points:
//!
//! - [`send_connect`] opens as `role=sender`. Generates a fresh session
//!   id, waits for the receiver's `peer_hello`, sends an SDP offer,
//!   trickles ICE. Resolves once the data channel is open.
//! - [`recv_connect`] opens as `role=receiver`. Sends the receiver
//!   hello + `peer_hello`, waits for an SDP offer, answers, trickles
//!   ICE. Resolves once the data channel is open.
//!
//! Both entry points return a `LiveSession` that owns the peer + WS
//! and holds them open until dropped. The chunk-transfer layer will
//! attach on top of the data channel in a follow-up.

pub mod str0m_client;
pub mod crypto;
pub mod pipeline;
pub use str0m_client::{LiveSession, recv_file, send_file};

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::SessionId;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use tokio::{io::AsyncReadExt, sync::{mpsc, Mutex}};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, warn};

/// 16 KiB is the SCTP-safe universal message size (Firefox cap). Matches
/// the browser side (`web/main.js` CONFIG.chunkBytes) so a native sender
/// and a browser receiver see identical framing over the WebRTC data
/// channel.
pub const CHUNK_BYTES: usize = 16 * 1024;

/// 1 MiB chunks for the server-relay path. HTTP PUT per chunk carries
/// real overhead, so relay pays for larger chunks. The receiver adapts
/// to whatever the sender declares in the meta_relay frame's
/// `chunkBytes` field, so this only needs to match on the sender side.
pub const RELAY_CHUNK_BYTES: usize = 1024 * 1024;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct MetaFrame {
    #[serde(rename = "type")]
    pub ty: String,
    pub name: String,
    pub size: u64,
    #[serde(rename = "chunkBytes")]
    pub chunk_bytes: u32,
    #[serde(rename = "totalChunks")]
    pub total_chunks: u64,
}

/// Reject any name that would escape `out_dir` or is otherwise unsafe on
/// the local filesystem. Keeps only the file-name component. Returns a
/// safe fallback if the sender's `name` degenerates to nothing.
pub(crate) fn sanitize_filename(name: &str) -> String {
    let stripped = std::path::Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if stripped.is_empty() || stripped == "." || stripped == ".." {
        return "received.bin".to_string();
    }
    stripped.to_string()
}

// ---- server-relay path (fallback for when WebRTC doesn't come up) -------
//
// These primitives mirror the browser sendFileOverRelay / makeRelayReceiver
// in web/main.js. They take String-based mpsc channels so the caller can
// decide how to plumb them into whatever WebSocket transport the caller
// already has (drive_ws in this crate, a raw websocket in a test, etc).

/// Snapshot of what the sender has already emitted over the relay path,
/// so a fresh receiver joining mid-upload can be caught up by re-emitting
/// meta + all sent chunk_relay frames + relay_done if applicable. Match
/// for `sendSession.relayProgress` on the browser side.
#[derive(Debug, Default)]
pub struct RelaySendProgress {
    pub meta_frame: Option<String>,
    pub sent_idxs: Vec<u32>,
    pub done: bool,
}

/// Send a file via the server relay. HTTP PUT each chunk to
/// `/session/:sess/chunk/:idx`, and for every successful PUT push a
/// `chunk_relay` JSON frame into `out_json_tx` so the peer can `GET` it.
///
/// Frames pushed on `out_json_tx`:
///   {"type":"meta_relay", name, size, chunkBytes, totalChunks}
///   {"type":"chunk_relay", "idx": N}   (per chunk after PUT ok)
///   {"type":"relay_done"}
pub async fn send_file_over_relay(
    server_url_http: &str,
    session_id: &SessionId,
    file_path: &Path,
    out_json_tx: mpsc::UnboundedSender<String>,
    progress: Arc<Mutex<RelaySendProgress>>,
    mut on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let http_base = server_url_http.trim_end_matches('/').to_string();
    let session_hex = session_id.as_hex();

    let meta_fs = tokio::fs::metadata(file_path).await
        .with_context(|| format!("stat {}", file_path.display()))?;
    if !meta_fs.is_file() {
        bail!("{} is not a regular file", file_path.display());
    }
    let size = meta_fs.len();
    let name = file_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let total_chunks = if size == 0 { 0 } else { (size + RELAY_CHUNK_BYTES as u64 - 1) / RELAY_CHUNK_BYTES as u64 };

    let meta_json = serde_json::json!({
        "type": "meta_relay",
        "name": name,
        "size": size,
        "chunkBytes": RELAY_CHUNK_BYTES,
        "totalChunks": total_chunks,
    }).to_string();

    {
        let mut p = progress.lock().await;
        p.meta_frame = Some(meta_json.clone());
        p.sent_idxs.clear();
        p.done = false;
    }
    let _ = out_json_tx.send(meta_json);

    let client = reqwest::Client::new();
    let mut f = tokio::fs::File::open(file_path).await?;
    let mut buf = vec![0u8; RELAY_CHUNK_BYTES];
    let mut idx: u32 = 0;
    let mut sent: u64 = 0;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        let url = format!("{http_base}/session/{session_hex}/chunk/{idx}");
        let body = Bytes::copy_from_slice(&buf[..n]);
        let resp = client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, n)
            .body(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            bail!("relay PUT {idx} → {status} {body_text}");
        }

        let chunk_frame = serde_json::json!({"type":"chunk_relay","idx": idx}).to_string();
        let _ = out_json_tx.send(chunk_frame);
        {
            let mut p = progress.lock().await;
            p.sent_idxs.push(idx);
        }
        sent += n as u64;
        on_progress(sent, size);
        idx += 1;
    }

    let done_frame = r#"{"type":"relay_done"}"#.to_string();
    let _ = out_json_tx.send(done_frame);
    {
        let mut p = progress.lock().await;
        p.done = true;
    }
    Ok(())
}

/// Given a snapshot of RelaySendProgress (typically stored in the
/// sender's session), re-emit meta + all sent chunk_relay + relay_done
/// (if done) into the outbound channel. Call this when the server
/// notifies the sender that a new receiver joined mid-upload.
pub async fn resend_relay_progress(
    out_json_tx: &mpsc::UnboundedSender<String>,
    progress: Arc<Mutex<RelaySendProgress>>,
) {
    let p = progress.lock().await;
    if let Some(meta) = &p.meta_frame {
        let _ = out_json_tx.send(meta.clone());
    }
    for idx in &p.sent_idxs {
        let _ = out_json_tx.send(
            serde_json::json!({"type":"chunk_relay","idx": idx}).to_string(),
        );
    }
    if p.done {
        let _ = out_json_tx.send(r#"{"type":"relay_done"}"#.to_string());
    }
}

/// Receive a file via the server relay. Consumes JSON frames from
/// `in_json_rx`, filters to the relay-mode ones, and for each
/// `chunk_relay` frame does HTTP GET `/session/:sess/chunk/:idx`.
/// On `relay_done`, fetches any still-missing chunks, assembles the
/// file into `out_dir/<sanitized-name>`, and returns the final path.
///
/// Frames on the WS other than meta_relay/chunk_relay/relay_done are
/// ignored — the caller can share the same channel between this and
/// e.g. the WebRTC-signaling path.
pub async fn recv_file_over_relay(
    server_url_http: &str,
    session_id: &SessionId,
    out_dir: &Path,
    mut in_json_rx: mpsc::UnboundedReceiver<String>,
    mut on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<std::path::PathBuf> {
    let http_base = server_url_http.trim_end_matches('/').to_string();
    let session_hex = session_id.as_hex();
    tokio::fs::create_dir_all(out_dir).await?;

    let client = reqwest::Client::new();
    let mut meta_opt: Option<MetaRelayFrame> = None;
    // chunks[idx] = Some(bytes) or None. Allocated once meta arrives.
    let mut chunks: Vec<Option<Bytes>> = Vec::new();
    let mut filled: u64 = 0;
    let mut received_bytes: u64 = 0;

    async fn fetch_chunk(
        client: &reqwest::Client,
        http_base: &str,
        session_hex: &str,
        idx: u32,
    ) -> Result<Bytes> {
        let url = format!("{http_base}/session/{session_hex}/chunk/{idx}");
        let resp = client.get(&url).send().await
            .with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            bail!("relay GET {idx} → {}", resp.status());
        }
        Ok(resp.bytes().await?)
    }

    while let Some(text) = in_json_rx.recv().await {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let Some(ty) = value.get("type").and_then(|x| x.as_str()) else { continue };
        match ty {
            "meta_relay" => {
                let m: MetaRelayFrame = match serde_json::from_value(value) {
                    Ok(v) => v,
                    Err(e) => { warn!("meta_relay decode: {e}"); continue }
                };
                if chunks.is_empty() {
                    chunks = vec![None; m.total_chunks as usize];
                    on_progress(0, m.size, &m.name);
                }
                meta_opt = Some(m);
            }
            "chunk_relay" => {
                let Some(idx) = value.get("idx").and_then(|x| x.as_u64()) else { continue };
                let idx_u32 = idx as u32;
                if (idx_u32 as usize) >= chunks.len() { continue }
                if chunks[idx_u32 as usize].is_some() { continue }
                let bytes = fetch_chunk(&client, &http_base, &session_hex, idx_u32).await?;
                received_bytes += bytes.len() as u64;
                chunks[idx_u32 as usize] = Some(bytes);
                filled += 1;
                if let Some(m) = meta_opt.as_ref() {
                    on_progress(received_bytes, m.size, &m.name);
                }
            }
            "relay_done" => {
                let Some(m) = meta_opt.clone() else { continue };
                // Backfill any missing chunks by direct GET before we
                // finalize. Sender may have raced ahead of notifications.
                for i in 0..(m.total_chunks as usize) {
                    if chunks[i].is_none() {
                        let b = fetch_chunk(&client, &http_base, &session_hex, i as u32).await?;
                        received_bytes += b.len() as u64;
                        chunks[i] = Some(b);
                        filled += 1;
                    }
                }
                if filled != m.total_chunks {
                    bail!("relay_done but {} of {} chunks still missing", m.total_chunks - filled, m.total_chunks);
                }
                let name = sanitize_filename(&m.name);
                let path = out_dir.join(&name);
                let mut f = tokio::fs::File::create(&path).await?;
                use tokio::io::AsyncWriteExt;
                for chunk in chunks.iter() {
                    if let Some(b) = chunk {
                        f.write_all(b).await?;
                    }
                }
                f.flush().await?;
                f.sync_all().await?;
                on_progress(received_bytes, m.size, &m.name);
                return Ok(path);
            }
            _ => {}
        }
    }
    bail!("json input channel closed before relay_done");
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MetaRelayFrame {
    #[serde(rename = "type")]
    ty: String,
    name: String,
    size: u64,
    #[serde(rename = "chunkBytes")]
    chunk_bytes: u32,
    #[serde(rename = "totalChunks")]
    total_chunks: u64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Sender => "sender",
            Role::Receiver => "receiver",
        }
    }
}

/// Wire-protocol version this client speaks. Bumped whenever the on-wire
/// format changes in a way that would fail silently. Both sides advertise
/// this in `SignalFrame::Hello.wire_version` and refuse the session if
/// they don't match. `None` on the incoming side means "peer is an older
/// client that didn't send a version" — treated as a mismatch too, so the
/// error message tells the user to update.
///
/// History:
///   1 — pre-crypto plaintext meta + chunks (deprecated)
///   2 — AEAD meta (`meta_enc`) + AEAD-per-chunk (idx-derived nonce);
///       KEX+KeyWrap over WS; ShareLink URL fragment
pub const WIRE_VERSION: u32 = 2;

/// Wire frames on the signaling WebSocket. Mirrors what `web/main.js` sends.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum SignalFrame {
    Hello {
        role: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        receiver_id: Option<String>,
        /// Wire-protocol version. See [`WIRE_VERSION`]. Absent when
        /// deserializing a Hello from a pre-v2 client — the receiver
        /// rejects the session with "please update your client".
        #[serde(skip_serializing_if = "Option::is_none", default)]
        wire_version: Option<u32>,
    },
    PeerHello {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        receiver_id: Option<String>,
        /// Server-injected role of the peer being announced ("sender" or
        /// "receiver"). Present when server relays a peer_hello notification,
        /// absent on the receiver-sent PeerHello that kicks the SDP handshake.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        role: Option<String>,
        /// Wire-protocol version of the OTHER side, as observed by the
        /// signaling server when it paired us. Server copies from the
        /// peer's `Hello.wire_version` into this field. Client bails when
        /// version mismatches ours.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        wire_version: Option<u32>,
    },
    Sdp {
        kind: String, // "offer" | "answer"
        sdp: String,
    },
    Ice {
        candidate: Option<serde_json::Value>,
    },
    /// Crypto handshake: this side's ephemeral X25519 public key, plus
    /// the MAC-under-A that proves the sender knows the URL secret.
    /// Sent by both sides as soon as they're paired, concurrent with SDP.
    KexPub {
        pub_hex: String,
        mac_hex: String,
    },
    /// Bulk key wrap: sender-of-file generates B, AEAD-wraps under
    /// wrap_key (HKDF-of-S), sends over WS. Receiver unwraps to
    /// recover B for the chunk stream.
    KeyWrap {
        enc_b_hex: String,
        nonce_hex: String,
    },
    /// Encrypted meta frame: AEAD-encrypted under meta_key with
    /// session_id bound as AAD. Optional Ed25519 signature over
    /// SHA256(session_id || nonce || ct) if the sender has a
    /// bitmule identity keypair.
    MetaEnc {
        nonce_hex: String,
        ct_hex: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        sig_hex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        signer_pub_hex: Option<String>,
    },
}

pub(crate) type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) async fn open_ws(server_url: &str, session_hex: &str) -> Result<Ws> {
    let ws_url = format!("{}/ws/{}", derive_ws_url(&server_url.trim_end_matches('/')), session_hex);
    let (ws, _resp) = connect_async(&ws_url)
        .await
        .with_context(|| format!("connect {ws_url}"))?;
    Ok(ws)
}

///   candidate:<foundation> <component> <transport> <priority> <addr> <port> typ <type> [...]
/// We only need to look at the 5th token (addr).
/// Run both resolvers concurrently, log which won by elapsed time, and
/// return the winning IP. If both fail/time out, return None.
async fn race_mdns_resolvers(hostname: &str, timeout: std::time::Duration) -> Option<std::net::IpAddr> {
    use tracing::info;
    let start = tokio::time::Instant::now();
    let mdns_fut = resolve_mdns_hostname(hostname, timeout);
    let sys_fut = resolve_via_system(hostname, timeout);
    tokio::pin!(mdns_fut);
    tokio::pin!(sys_fut);
    tokio::select! {
        m = &mut mdns_fut => {
            match m {
                Some(ip) => {
                    info!("mdns crate WON for {hostname} in {:?} -> {ip}", start.elapsed());
                    Some(ip)
                }
                None => {
                    // mdns crate failed; wait on the system resolver.
                    let sys = sys_fut.await;
                    if let Some(ip) = sys {
                        info!("mdns crate failed, system resolver got {hostname} in {:?} -> {ip}", start.elapsed());
                    }
                    sys
                }
            }
        }
        s = &mut sys_fut => {
            match s {
                Some(ip) => {
                    info!("system resolver WON for {hostname} in {:?} -> {ip}", start.elapsed());
                    Some(ip)
                }
                None => {
                    let m = mdns_fut.await;
                    if let Some(ip) = m {
                        info!("system resolver failed, mdns crate got {hostname} in {:?} -> {ip}", start.elapsed());
                    }
                    m
                }
            }
        }
    }
}

/// Fallback / comparison resolver: whatever the system libc gives us
/// through tokio::net::lookup_host (needs libnss-mdns wired in for
/// `.local` to work).
async fn resolve_via_system(hostname: &str, timeout: std::time::Duration) -> Option<std::net::IpAddr> {
    let lookup = format!("{hostname}:0");
    match tokio::time::timeout(timeout, tokio::net::lookup_host(lookup)).await {
        Ok(Ok(mut iter)) => iter.next().map(|s| s.ip()),
        _ => None,
    }
}

/// Ask the local multicast DNS responders for the A record behind
/// `hostname` (a `.local` name). Returns the first IP that comes back,
/// or None on timeout.
async fn resolve_mdns_hostname(hostname: &str, timeout: std::time::Duration) -> Option<std::net::IpAddr> {
    use futures_util::{pin_mut, stream::StreamExt};
    // The mdns crate's discover API is oriented at DNS-SD (service
    // browsing), but the underlying multicast query works for plain
    // A-record lookups when we pass the hostname as the "service" and
    // filter response records for A/AAAA on the matching hostname.
    let stream = match mdns::discover::all(hostname, timeout).ok()?.listen() {
        s => s,
    };
    pin_mut!(stream);
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(response))) => {
                for record in response.records() {
                    if !record.name.eq_ignore_ascii_case(hostname) { continue; }
                    match record.kind {
                        mdns::RecordKind::A(v4) => return Some(std::net::IpAddr::V4(v4)),
                        mdns::RecordKind::AAAA(v6) => return Some(std::net::IpAddr::V6(v6)),
                        _ => {}
                    }
                }
            }
            Ok(Some(Err(_))) => continue,
            Ok(None) => return None,
            Err(_) => return None,
        }
    }
    None
}

pub(crate) async fn maybe_resolve_mdns_candidate(candidate_line: &str) -> Option<String> {
    // Some browsers send an empty end-of-candidates as candidate:"" — skip.
    if candidate_line.is_empty() { return None; }
    let parts: Vec<&str> = candidate_line.split_whitespace().collect();
    // Need at least: candidate:<f> <comp> <transport> <prio> <addr> <port>
    if parts.len() < 6 { return None; }
    let addr = parts[4];
    if !addr.ends_with(".local") { return None; }

    // Race two resolvers per Seb 2026-09-02: the in-process `mdns` crate
    // (portable, no avahi dep) AND tokio's system lookup_host (which
    // uses whatever the OS resolver has wired for .local, typically
    // libnss-mdns + avahi if installed). Whichever returns first wins;
    // print which one it was so we can retire the loser if one is
    // consistently faster.
    let ip_str = match race_mdns_resolvers(addr, std::time::Duration::from_secs(5)).await {
        Some(ip) => ip.to_string(),
        None => {
            debug!("mdns resolve of {addr} failed / timed out (both resolvers)");
            return None;
        }
    };
    debug!("resolved mdns {addr} -> {ip_str}");

    // Substitute the address token and reassemble. Preserve everything
    // else verbatim.
    let mut out_parts = parts.clone();
    out_parts[4] = &ip_str;
    Some(out_parts.join(" "))
}

// ---- top-level file transfer with WebRTC / relay auto-fallback ----------
//
// send_file / recv_file are the CLI-facing entry points that unify the DC
// and relay paths. Default (mode=Auto) is WebRTC-first with a 3s fallback
// timer to the relay path; --webrtc and --relay force a single mode.

/// How the caller wants file transfer to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Try WebRTC first; if the data channel hasn't opened after
    /// [`WEBRTC_FALLBACK_MS`], fall back to relay. Default for CLI.
    Auto,
    /// Only WebRTC. Errors if the DC never opens.
    Webrtc,
    /// Skip WebRTC entirely; use server relay from the start.
    Relay,
}

/// How long the auto mode waits for the DC to open before falling back.
pub const WEBRTC_FALLBACK_MS: u64 = 3000;


fn derive_ws_url(server_url_http: &str) -> String {
    let base = server_url_http.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("http://") { format!("ws://{rest}") }
    else if let Some(rest) = base.strip_prefix("https://") { format!("wss://{rest}") }
    else { base.to_string() }
}

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
pub mod multipeer;
pub mod container;
pub mod session;
pub use str0m_client::{LiveSession, recv_file, send_file_multi, send_file_relay};
pub use multipeer::ServeMode;

/// Return value from [`recv_file`] — the on-disk path plus the wire's
/// `container` flag so the caller can post-process (e.g. unzip a
/// `Some("zip-store")` bundle) without re-parsing the meta frame.
#[derive(Debug, Clone)]
pub struct RecvComplete {
    pub path: std::path::PathBuf,
    pub container: Option<String>,
}

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::{ReceiverId, SessionId};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
use tokio::{io::AsyncReadExt, sync::{mpsc, Mutex}};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
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
    /// Container-type flag. `Some("zip-store")` means the sender bundled
    /// N files or a directory into an on-the-fly zip (store mode, no
    /// compression) — the receiver should unpack it. `None` = single
    /// user-selected file, receiver keeps it as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
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
    container: Option<&str>,
    out_json_tx: mpsc::UnboundedSender<String>,
    progress: Arc<Mutex<RelaySendProgress>>,
    bulk_key: &crate::crypto::BulkKey,
    meta_key: &crate::crypto::MetaKey,
    session_id_bytes: &[u8; 32],
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

    // Inner plaintext meta (encrypted under meta_key before hitting the wire).
    let mut meta_plain_val = serde_json::json!({
        "type": "meta_relay",
        "name": name,
        "size": size,
        "chunkBytes": RELAY_CHUNK_BYTES,
        "totalChunks": total_chunks,
    });
    if let Some(c) = container {
        meta_plain_val["container"] = serde_json::Value::String(c.to_string());
    }
    let meta_plain = meta_plain_val.to_string();
    let (meta_nonce, meta_ct) = meta_key.encrypt_meta(session_id_bytes, meta_plain.as_bytes())?;
    let meta_enc_frame = serde_json::json!({
        "type": "meta_relay_enc",
        "nonce_hex": hex_bytes(&meta_nonce),
        "ct_hex": hex_bytes(&meta_ct),
    }).to_string();

    {
        let mut p = progress.lock().await;
        p.meta_frame = Some(meta_enc_frame.clone());
        p.sent_idxs.clear();
        p.done = false;
    }
    let _ = out_json_tx.send(meta_enc_frame);

    let client = reqwest::Client::new();
    let mut f = tokio::fs::File::open(file_path).await?;
    let mut buf = vec![0u8; RELAY_CHUNK_BYTES];
    let mut idx: u32 = 0;
    let mut sent: u64 = 0;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        // AEAD-encrypt with idx-derived nonce. Server stores ciphertext.
        let ct = bulk_key.encrypt_chunk(idx as u64, &buf[..n])?;
        let ct_len = ct.len();
        let url = format!("{http_base}/session/{session_hex}/chunk/{idx}");
        let body = Bytes::from(ct);
        let resp = client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, ct_len)
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
        // Progress in PLAINTEXT bytes so ratio matches meta.size on both sides.
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

/// Local hex helper (no anyhow ceremony; used in this module only).
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_bytes_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 { bail!("odd-length hex string"); }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
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
    bulk_key: &crate::crypto::BulkKey,
    meta_key: &crate::crypto::MetaKey,
    session_id_bytes: &[u8; 32],
    mut on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<crate::RecvComplete> {
    let http_base = server_url_http.trim_end_matches('/').to_string();
    let session_hex = session_id.as_hex();
    tokio::fs::create_dir_all(out_dir).await?;

    let client = reqwest::Client::new();
    let mut meta_opt: Option<MetaRelayFrame> = None;
    // chunks[idx] = Some(PLAINTEXT bytes) or None. Ciphertext is decrypted
    // as it arrives so the final assembly step is a straight write.
    let mut chunks: Vec<Option<Bytes>> = Vec::new();
    let mut filled: u64 = 0;
    let mut received_plain_bytes: u64 = 0;

    async fn fetch_chunk_ct(
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
            "meta_relay_enc" => {
                let nonce_hex = value.get("nonce_hex").and_then(|x| x.as_str()).unwrap_or("");
                let ct_hex = value.get("ct_hex").and_then(|x| x.as_str()).unwrap_or("");
                let nonce = match hex_bytes_decode(nonce_hex) {
                    Ok(v) => v,
                    Err(e) => { warn!("meta_relay_enc nonce hex: {e}"); continue }
                };
                let ct = match hex_bytes_decode(ct_hex) {
                    Ok(v) => v,
                    Err(e) => { warn!("meta_relay_enc ct hex: {e}"); continue }
                };
                let plain = match meta_key.decrypt_meta(session_id_bytes, &nonce, &ct) {
                    Ok(p) => p,
                    Err(e) => { warn!("meta_relay_enc decrypt: {e}"); continue }
                };
                let m: MetaRelayFrame = match serde_json::from_slice(&plain) {
                    Ok(v) => v,
                    Err(e) => { warn!("meta_relay decode after decrypt: {e}"); continue }
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
                let ct = fetch_chunk_ct(&client, &http_base, &session_hex, idx_u32).await?;
                let plain = bulk_key.decrypt_chunk(idx as u64, &ct)
                    .with_context(|| format!("decrypt relay chunk {idx_u32}"))?;
                received_plain_bytes += plain.len() as u64;
                chunks[idx_u32 as usize] = Some(Bytes::from(plain));
                filled += 1;
                if let Some(m) = meta_opt.as_ref() {
                    on_progress(received_plain_bytes, m.size, &m.name);
                }
            }
            "relay_done" => {
                let Some(m) = meta_opt.clone() else { continue };
                // Backfill any missing chunks by direct GET before we
                // finalize. Sender may have raced ahead of notifications.
                for i in 0..(m.total_chunks as usize) {
                    if chunks[i].is_none() {
                        let ct = fetch_chunk_ct(&client, &http_base, &session_hex, i as u32).await?;
                        let plain = bulk_key.decrypt_chunk(i as u64, &ct)
                            .with_context(|| format!("decrypt relay backfill chunk {i}"))?;
                        received_plain_bytes += plain.len() as u64;
                        chunks[i] = Some(Bytes::from(plain));
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
                on_progress(received_plain_bytes, m.size, &m.name);
                return Ok(crate::RecvComplete { path, container: m.container.clone() });
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
    /// See [`MetaFrame::container`]. Same semantics on the relay path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    container: Option<String>,
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
/// `Clone` for the M2b router's dual-delivery path — a frame may need
/// to land on both `pending[from_receiver_id]` (for a not-yet-registered
/// peer) and `unrouted_rx` (for the legacy single-peer send_connect).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum SignalFrame {
    /// Sender-only: create a new session slot on the server. Only frame
    /// permitted on a fresh ws before the peer has joined. Replaces the
    /// old `Hello { role: "sender" }` shape.
    SessionCreate {
        /// Wire-protocol version. See [`WIRE_VERSION`]. Absent when
        /// deserializing from a pre-v3 client — the receiver rejects
        /// the session with "please update your client".
        #[serde(skip_serializing_if = "Option::is_none", default)]
        wire_version: Option<u32>,
        /// Chunk-transports this side is willing to speak. In
        /// preference order (element 0 = preferred). Values from the
        /// closed set `{"webrtc","relay"}`. Empty = old client, treat
        /// as `["webrtc","relay"]` for backward-compat. Server includes
        /// this in the counterpart's PeerJoined so the counterpart can
        /// pick the highest-preference intersection at KEX-completion.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        transports: Option<Vec<String>>,
    },
    /// Receiver-only: join an existing session slot. Carries the
    /// receiver's `receiver_id` for multipeer routing. Replaces the
    /// old `Hello { role: "receiver" } + PeerHello` pair (they were
    /// redundant — server only ever routed off Hello, receiver-sent
    /// PeerHello was silently dropped by wait_for_peer).
    SessionJoin {
        receiver_id: ReceiverId,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        wire_version: Option<u32>,
        /// Same shape and semantics as SessionCreate.transports.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        transports: Option<Vec<String>>,
    },
    /// Server → client pairing notification. Emitted by the server to
    /// both sides once a Sender + Receiver are both registered on the
    /// same session_hex. Carries the OTHER side's role + wire_version
    /// so each side can fail-fast on version mismatch. Distinct from
    /// SessionCreate/SessionJoin (which are client → server) — this is
    /// the only frame the server originates in this family.
    PeerJoined {
        /// Counterpart's role: "sender" or "receiver".
        role: String,
        /// Counterpart's wire_version, copied from their SessionCreate
        /// or SessionJoin. `None` = pre-v3 peer, this side bails.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        wire_version: Option<u32>,
        /// Receiver's `receiver_id` when the pairing notification lands
        /// on the sender side (multipeer routing key). Absent on the
        /// notification the receiver gets.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        receiver_id: Option<ReceiverId>,
        /// Counterpart's advertised transports (in preference order).
        /// `None` = pre-v3 peer that didn't advertise (backward-compat:
        /// treat as `["webrtc","relay"]`, matches legacy Auto).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        transports: Option<Vec<String>>,
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
    /// Receiver-to-sender request: "I've given up on WebRTC. Please
    /// switch to relay transport for this session and re-emit your
    /// progress so I can start pulling chunks." Sender-side handler
    /// should cancel the WebRTC attempt cleanly and start
    /// `send_file_over_relay` on the same session_hex, then call
    /// `resend_relay_progress` to catch the receiver up on which
    /// chunks are already on the server. Server broadcasts within
    /// the session, so a single request lands on any active sender
    /// WS regardless of which peer sent it.
    ///
    /// Wire pair with the receiver's independent 10s fallback timer:
    /// if the sender's listener catches this frame, both sides switch
    /// synchronously and skip the timeout window; if the sender is
    /// legacy code that doesn't handle it, the receiver still falls
    /// back on its own timer and the sender times out independently.
    RequestRelay {},
    /// Client → server timing beacon. Fired by either side the moment
    /// the WebRTC data channel opens successfully, with the elapsed
    /// time from the WS-hello send to DC-open. Server-side action:
    /// log the pair `{session_hex, role, elapsed_ms}` so we can build
    /// a distribution of "how long does WebRTC take to come up on real
    /// networks" and tune the fallback timer per client type.
    ///
    /// Server-side handler is a follow-up on the server crate. Client
    /// emits regardless of whether the server knows what to do with
    /// it — the frame is opaque to peers on the session; the server
    /// silently swallows it (or logs it once wired).
    WebrtcReady {
        elapsed_ms: u64,
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
/// Resolve a `.local` hostname via the mdns crate. Per Seb: the mdns
/// crate always wins the race against the system resolver, and pumping
/// a doomed system-resolver future in parallel just adds latency and
/// log noise. If we ever see mdns lose (e.g. libnss-mdns configured
/// on the host and firing sub-ms), reinstate the race.
///
/// Process-wide 60s TTL cache so repeat lookups of the same hostname
/// (Firefox emits both `typ host udp` and `typ host tcp` for the
/// same mDNS name; without the cache the TCP candidate re-hits the
/// 5s discovery timeout after the responder has stopped announcing).
/// Negative results are cached with a shorter TTL (5s) so a
/// transiently-unresolvable hostname doesn't wedge for a full minute.
async fn race_mdns_resolvers(hostname: &str, timeout: std::time::Duration) -> Option<std::net::IpAddr> {
    use tracing::info;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static CACHE: std::sync::OnceLock<Mutex<HashMap<String, (Instant, Option<std::net::IpAddr>)>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    const POSITIVE_TTL: Duration = Duration::from_secs(60);
    const NEGATIVE_TTL: Duration = Duration::from_secs(5);

    let key = hostname.to_ascii_lowercase();
    if let Ok(g) = cache.lock() {
        if let Some((cached_at, cached_ip)) = g.get(&key) {
            let ttl = if cached_ip.is_some() { POSITIVE_TTL } else { NEGATIVE_TTL };
            if cached_at.elapsed() < ttl {
                if let Some(ip) = cached_ip {
                    info!("mdns cache hit {hostname} -> {ip}");
                }
                return *cached_ip;
            }
        }
    }

    let start = tokio::time::Instant::now();
    let ip = resolve_mdns_hostname(hostname, timeout).await;
    if let Some(v) = ip {
        info!("mdns resolved {hostname} in {:?} -> {v}", start.elapsed());
    }
    if let Ok(mut g) = cache.lock() {
        g.insert(key, (Instant::now(), ip));
    }
    ip
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
            debug!("mdns resolve of {addr} failed / timed out");
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

// ---- top-level file transfer entry points -------------------------------
//
// Send: `send_file_multi` (WebRTC multipeer, default) or `send_file_relay`
//       (server-relay legacy).
// Recv: `recv_file` (dispatches WebRTC or Relay per `TransportMode`).
//
// The pre-multipeer `send_file` public API was deleted 2026-09-04 per Seb:
// no callers remained. Same day: `TransportMode::Auto` deleted — the
// WebRTC-first-with-3s-relay-fallback flow lived only inside the removed
// send_file / recv_file Auto branches, and the SPA now handles fallback
// on its own layer (peer-present + ICE-failed trigger, not a wall clock).

/// How the caller wants file transfer to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Try WebRTC first with a bounded budget (see `AUTO_WEBRTC_BUDGET`);
    /// if the DC hasn't opened by then, tear it down and reconnect via
    /// the server-relay path. Both `send_file_*` and `recv_file` handle
    /// this internally so callers only pick a mode.
    /// Kenna 2026-09-13: reinstated after the CLI matrix showed that a
    /// hardcoded auto = Webrtc leaves any receiver that can't reach
    /// STUN completely dead.
    Auto,
    /// Only WebRTC. Errors if the DC never opens.
    Webrtc,
    /// Skip WebRTC entirely; use server relay from the start.
    Relay,
}

impl TransportMode {
    /// Advertised chunk-transports for this mode, in preference order
    /// (element 0 = preferred). Consumed at SessionCreate/SessionJoin
    /// time and copied by the server into the counterpart's PeerJoined
    /// notification. The peer's TransportNegotiator picks the highest-
    /// preference mutual entry from the intersection.
    pub fn advertised_transports(self) -> Vec<String> {
        match self {
            TransportMode::Webrtc => vec!["webrtc".to_string()],
            TransportMode::Relay => vec!["relay".to_string()],
            TransportMode::Auto => vec!["webrtc".to_string(), "relay".to_string()],
        }
    }
}

/// Pick the highest-preference mutual transport from local + peer
/// advertisements. Returns `None` if the intersection is empty — the
/// caller prints "no compatible transport, peer speaks {peer}, we
/// speak {local}" and exits non-zero (Seb-set 2026-09-13: pure-webrtc
/// paired with pure-relay is unrecoverable and should be a clean
/// error not a hang).
pub fn negotiate_transport(local: &[String], peer: &[String]) -> Option<String> {
    for t in local {
        if peer.iter().any(|p| p == t) {
            return Some(t.clone());
        }
    }
    None
}

/// Wall-clock budget the Auto sender/receiver gives WebRTC before
/// tearing it down and reconnecting via the relay path. Only used
/// when transport-negotiation lands on webrtc but the DC never opens
/// — the negotiated-relay path skips this entirely.
pub const AUTO_WEBRTC_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);


fn derive_ws_url(server_url_http: &str) -> String {
    let base = server_url_http.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("http://") { format!("ws://{rest}") }
    else if let Some(rest) = base.strip_prefix("https://") { format!("wss://{rest}") }
    else { base.to_string() }
}

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

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::SessionId;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, Mutex},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};
use webrtc::{
    api::{
        interceptor_registry::register_default_interceptors, media_engine::MediaEngine, APIBuilder,
    },
    data_channel::{data_channel_message::DataChannelMessage, RTCDataChannel},
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    interceptor::registry::Registry,
    peer_connection::{
        configuration::RTCConfiguration, sdp::session_description::RTCSessionDescription,
        RTCPeerConnection,
    },
};

/// 16 KiB is the SCTP-safe universal message size (Firefox cap). Matches
/// the browser side (`web/main.js` CONFIG.chunkBytes) so a native sender
/// and a browser receiver see identical framing.
pub const CHUNK_BYTES: usize = 16 * 1024;
const BUFFERED_HIGH_WATER: usize = 4 * 1024 * 1024;
const BUFFERED_LOW_WATER: usize = 1 * 1024 * 1024;
const BACKPRESSURE_POLL: Duration = Duration::from_millis(10);

/// Send a file over an opened WebRTC data channel using the same wire
/// framing as the browser sender:
///
/// - text frame: `{"type":"meta", name, size, chunkBytes, totalChunks}`
/// - binary frames: raw `CHUNK_BYTES`-sized (or smaller for the tail) payloads
/// - text frame: `{"type":"done"}`
///
/// Backpressure: waits for `dc.buffered_amount()` to fall below
/// `BUFFERED_HIGH_WATER` before sending the next chunk. Simple polling
/// rather than the callback-based `on_buffered_amount_low` pattern —
/// bounded latency (10ms poll) and no shared-state plumbing between the
/// callback and this async loop.
pub async fn send_file_over_dc(
    dc: Arc<RTCDataChannel>,
    file_path: &Path,
    mut on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let meta_file = tokio::fs::metadata(file_path)
        .await
        .with_context(|| format!("stat {}", file_path.display()))?;
    if !meta_file.is_file() {
        bail!("{} is not a regular file", file_path.display());
    }
    let size = meta_file.len();
    let name = file_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let total_chunks = if size == 0 { 0 } else { (size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };

    let meta = serde_json::json!({
        "type": "meta",
        "name": name,
        "size": size,
        "chunkBytes": CHUNK_BYTES,
        "totalChunks": total_chunks,
    });
    dc.send_text(meta.to_string())
        .await
        .map_err(|e| anyhow!("dc send meta: {e}"))?;

    dc.set_buffered_amount_low_threshold(BUFFERED_LOW_WATER)
        .await;

    let mut f = tokio::fs::File::open(file_path)
        .await
        .with_context(|| format!("open {}", file_path.display()))?;
    let mut sent: u64 = 0;
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        // Backpressure: pause sending while the SCTP send queue is above
        // the high-water mark. Poll at BACKPRESSURE_POLL granularity;
        // bounded to a small tail wait so the file finish is prompt.
        while dc.buffered_amount().await > BUFFERED_HIGH_WATER {
            tokio::time::sleep(BACKPRESSURE_POLL).await;
        }
        let payload = Bytes::copy_from_slice(&buf[..n]);
        dc.send(&payload)
            .await
            .map_err(|e| anyhow!("dc send chunk: {e}"))?;
        sent += n as u64;
        on_progress(sent, size);
    }

    dc.send_text(r#"{"type":"done"}"#.to_string())
        .await
        .map_err(|e| anyhow!("dc send done: {e}"))?;

    // Ensure the SCTP queue drains before the caller closes the DC.
    while dc.buffered_amount().await > 0usize {
        tokio::time::sleep(BACKPRESSURE_POLL).await;
    }
    Ok(())
}

/// Receive a single file over an opened WebRTC data channel using the
/// browser-parity wire framing (see [`send_file_over_dc`]). Writes the
/// file into `out_dir/<sanitized-name>` and returns the final path.
///
/// Blocks until the sender emits `{"type":"done"}` OR the DC dies. If the
/// DC closes before `done`, returns an error and the partial file stays
/// on disk (caller can decide whether to unlink or resume).
pub async fn recv_file_over_dc(
    dc: Arc<RTCDataChannel>,
    out_dir: &Path,
    mut on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<std::path::PathBuf> {
    #[derive(Debug)]
    enum RxEvent {
        Meta(MetaFrame),
        Chunk(Bytes),
        Done,
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<RxEvent>();
    let close_notify = Arc::new(tokio::sync::Notify::new());

    tokio::fs::create_dir_all(out_dir)
        .await
        .with_context(|| format!("mkdir -p {}", out_dir.display()))?;

    // on_message pushes events into the channel; the main task below
    // drains them and writes to disk. Errors in the callback are logged
    // rather than surfaced — the caller sees them via the closed channel.
    let tx_msg = tx.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = tx_msg.clone();
        Box::pin(async move {
            if msg.is_string {
                let text = match std::str::from_utf8(&msg.data) {
                    Ok(s) => s.to_string(),
                    Err(_) => return,
                };
                let value: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                match value.get("type").and_then(|x| x.as_str()) {
                    Some("meta") => {
                        if let Ok(m) = serde_json::from_value::<MetaFrame>(value) {
                            let _ = tx.send(RxEvent::Meta(m));
                        } else {
                            warn!("dc meta decode failed");
                        }
                    }
                    Some("done") => {
                        let _ = tx.send(RxEvent::Done);
                    }
                    _ => {}
                }
            } else {
                let _ = tx.send(RxEvent::Chunk(msg.data));
            }
        })
    }));

    let close_notify2 = close_notify.clone();
    dc.on_close(Box::new(move || {
        let n = close_notify2.clone();
        Box::pin(async move {
            n.notify_waiters();
        })
    }));

    let mut meta_opt: Option<MetaFrame> = None;
    let mut file_opt: Option<tokio::fs::File> = None;
    let mut path_opt: Option<std::path::PathBuf> = None;
    let mut received: u64 = 0;
    let mut done = false;

    loop {
        tokio::select! {
            biased;
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    RxEvent::Meta(m) => {
                        let name = sanitize_filename(&m.name);
                        let path = out_dir.join(&name);
                        let file = tokio::fs::File::create(&path)
                            .await
                            .with_context(|| format!("create {}", path.display()))?;
                        on_progress(0, m.size, &m.name);
                        file_opt = Some(file);
                        path_opt = Some(path);
                        meta_opt = Some(m);
                    }
                    RxEvent::Chunk(bytes) => {
                        if let Some(f) = file_opt.as_mut() {
                            use tokio::io::AsyncWriteExt;
                            f.write_all(&bytes).await?;
                            received += bytes.len() as u64;
                            if let Some(m) = meta_opt.as_ref() {
                                on_progress(received, m.size, &m.name);
                            }
                        }
                    }
                    RxEvent::Done => {
                        if let Some(mut f) = file_opt.take() {
                            use tokio::io::AsyncWriteExt;
                            f.flush().await?;
                            f.sync_all().await?;
                        }
                        done = true;
                        break;
                    }
                }
            }
            _ = close_notify.notified() => {
                bail!("data channel closed before done (received {received}/{} bytes)",
                    meta_opt.as_ref().map(|m| m.size).unwrap_or(0));
            }
        }
    }

    if !done {
        bail!("data channel event stream ended without a done frame");
    }
    path_opt.ok_or_else(|| anyhow!("no meta received before done"))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MetaFrame {
    #[serde(rename = "type")]
    ty: String,
    name: String,
    size: u64,
    #[serde(rename = "chunkBytes")]
    chunk_bytes: u32,
    #[serde(rename = "totalChunks")]
    total_chunks: u64,
}

/// Reject any name that would escape `out_dir` or is otherwise unsafe on
/// the local filesystem. Keeps only the file-name component. Returns a
/// safe fallback if the sender's `name` degenerates to nothing.
fn sanitize_filename(name: &str) -> String {
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
    let total_chunks = if size == 0 { 0 } else { (size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };

    let meta_json = serde_json::json!({
        "type": "meta_relay",
        "name": name,
        "size": size,
        "chunkBytes": CHUNK_BYTES,
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
    let mut buf = vec![0u8; CHUNK_BYTES];
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

/// A running, connected session: WS held open + peer connection + data channel.
pub struct LiveSession {
    pub session_id: SessionId,
    pub role: Role,
    pub pc: Arc<RTCPeerConnection>,
    pub dc: Arc<RTCDataChannel>,
    _ws_task: tokio::task::JoinHandle<()>,
}

impl LiveSession {
    /// Close the peer connection (drops the WS task with it).
    pub async fn close(&self) -> Result<()> {
        self.pc.close().await.map_err(|e| anyhow!("pc close: {e}"))
    }
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

/// Wire frames on the signaling WebSocket. Mirrors what `web/main.js` sends.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SignalFrame {
    Hello {
        role: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        receiver_id: Option<String>,
    },
    PeerHello {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        receiver_id: Option<String>,
    },
    Sdp {
        kind: String, // "offer" | "answer"
        sdp: String,
    },
    Ice {
        candidate: Option<serde_json::Value>,
    },
}

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn open_ws(server_url: &str, session_hex: &str) -> Result<Ws> {
    let ws_url = format!("{}/ws/{}", server_url.trim_end_matches('/'), session_hex);
    let (ws, _resp) = connect_async(&ws_url)
        .await
        .with_context(|| format!("connect {ws_url}"))?;
    Ok(ws)
}

async fn build_peer_connection() -> Result<Arc<RTCPeerConnection>> {
    let mut me = MediaEngine::default();
    me.register_default_codecs().map_err(|e| anyhow!("register codecs: {e}"))?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut me)
        .map_err(|e| anyhow!("register interceptors: {e}"))?;
    let api = APIBuilder::new()
        .with_media_engine(me)
        .with_interceptor_registry(registry)
        .build();
    let cfg = RTCConfiguration {
        ice_servers: vec![
            RTCIceServer {
                urls: vec![
                    "stun:stun.l.google.com:19302".to_owned(),
                    "stun:stun1.l.google.com:19302".to_owned(),
                ],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let pc = api
        .new_peer_connection(cfg)
        .await
        .map_err(|e| anyhow!("new_peer_connection: {e}"))?;
    Ok(Arc::new(pc))
}

/// Handles returned from [`drive_ws`]. Typed channels for the four
/// SignalFrame variants (Hello/PeerHello/Sdp/Ice); raw JSON channels
/// for anything else — relay-mode framing (meta_relay / chunk_relay /
/// relay_done) and server-side peer_joined notifications ride the raw
/// channel. Callers that only need the typed side can ignore raw.
struct WsHandles {
    typed_out: mpsc::UnboundedSender<SignalFrame>,
    typed_in: mpsc::UnboundedReceiver<SignalFrame>,
    raw_out: mpsc::UnboundedSender<String>,
    raw_in: mpsc::UnboundedReceiver<String>,
    task: tokio::task::JoinHandle<()>,
}

fn drive_ws(
    ws: Ws,
    pc: Arc<RTCPeerConnection>,
    dc_ready: Arc<tokio::sync::Notify>,
) -> WsHandles {
    let (typed_out, mut typed_out_rx) = mpsc::unbounded_channel::<SignalFrame>();
    let (typed_in_tx, typed_in) = mpsc::unbounded_channel::<SignalFrame>();
    let (raw_out, mut raw_out_rx) = mpsc::unbounded_channel::<String>();
    let (raw_in_tx, raw_in) = mpsc::unbounded_channel::<String>();

    let (sink, mut stream) = ws.split();
    let sink = Arc::new(Mutex::new(sink));

    // Outbound pump — typed frames.
    let sink_typed = sink.clone();
    tokio::spawn(async move {
        while let Some(frame) = typed_out_rx.recv().await {
            let text = match serde_json::to_string(&frame) {
                Ok(t) => t,
                Err(e) => { warn!("frame encode: {e}"); continue; }
            };
            let mut s = sink_typed.lock().await;
            if let Err(e) = s.send(Message::Text(text.into())).await {
                warn!("ws send typed: {e}");
                break;
            }
        }
    });

    // Outbound pump — raw strings (relay-mode framing, etc).
    let sink_raw = sink.clone();
    tokio::spawn(async move {
        while let Some(text) = raw_out_rx.recv().await {
            let mut s = sink_raw.lock().await;
            if let Err(e) = s.send(Message::Text(text.into())).await {
                warn!("ws send raw: {e}");
                break;
            }
        }
    });

    // Inbound pump: parse + route + always mirror raw text into raw_in.
    let pc_in = pc.clone();
    let typed_in_clone = typed_in_tx.clone();
    let raw_in_clone = raw_in_tx.clone();
    let handle = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => { warn!("ws recv: {e}"); break; }
            };
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };
            // Every text frame flows out on raw regardless of parse.
            let _ = raw_in_clone.send(text.clone());

            let frame: SignalFrame = match serde_json::from_str(&text) {
                Ok(f) => f,
                Err(_) => continue,
            };
            match &frame {
                SignalFrame::Sdp { kind, sdp } => {
                    let desc = if kind == "offer" {
                        RTCSessionDescription::offer(sdp.clone())
                    } else {
                        RTCSessionDescription::answer(sdp.clone())
                    };
                    match desc {
                        Ok(d) => {
                            if let Err(e) = pc_in.set_remote_description(d).await {
                                warn!("set_remote_description: {e}");
                            }
                        }
                        Err(e) => warn!("build sdp: {e}"),
                    }
                    let _ = typed_in_clone.send(frame);
                }
                SignalFrame::Ice { candidate } => {
                    if let Some(c) = candidate {
                        let init: RTCIceCandidateInit = match serde_json::from_value(c.clone()) {
                            Ok(v) => v,
                            Err(e) => { warn!("ice decode: {e}"); continue; }
                        };
                        if let Err(e) = pc_in.add_ice_candidate(init).await {
                            warn!("add_ice_candidate: {e}");
                        }
                    }
                    let _ = typed_in_clone.send(frame);
                }
                _ => {
                    let _ = typed_in_clone.send(frame);
                }
            }
        }
        // Wake anything still waiting on the DC in case the WS dies.
        dc_ready.notify_waiters();
    });

    WsHandles { typed_out, typed_in, raw_out, raw_in, task: handle }
}

/// Wire the peer's `on_ice_candidate` handler to forward every candidate to
/// the WS as an `ice` frame.
fn wire_ice_forwarding(
    pc: &Arc<RTCPeerConnection>,
    out_tx: mpsc::UnboundedSender<SignalFrame>,
) {
    pc.on_ice_candidate(Box::new(move |cand| {
        let out_tx = out_tx.clone();
        Box::pin(async move {
            let candidate = match cand {
                Some(c) => match c.to_json() {
                    Ok(init) => Some(serde_json::to_value(init).ok()).flatten(),
                    Err(e) => { warn!("ice to_json: {e}"); None }
                },
                None => None,
            };
            let _ = out_tx.send(SignalFrame::Ice { candidate });
        })
    }));
}

/// Sender flow. Caller supplies the SessionId so it can be printed to
/// the user before the (blocking) wait for the receiver's peer_hello.
pub async fn send_connect(server_url: &str, session_id: SessionId) -> Result<LiveSession> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening sender WS");
    let ws = open_ws(server_url, &session_hex).await?;

    let pc = build_peer_connection().await?;

    // Data channel MUST be created BEFORE the offer so its m-line is in the SDP.
    let dc = pc
        .create_data_channel("bitmule", None)
        .await
        .map_err(|e| anyhow!("create_data_channel: {e}"))?;

    let dc_ready = Arc::new(tokio::sync::Notify::new());
    let dc_ready_signal = dc_ready.clone();
    dc.on_open(Box::new(move || {
        let n = dc_ready_signal.clone();
        Box::pin(async move { n.notify_waiters(); })
    }));

    let WsHandles { typed_out: out_tx, typed_in: mut in_rx, task: ws_task, .. } =
        drive_ws(ws, pc.clone(), dc_ready.clone());
    wire_ice_forwarding(&pc, out_tx.clone());

    // Send initial hello.
    out_tx.send(SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
    })?;

    // Wait for the receiver's peer_hello — that's the go-signal to offer.
    info!("waiting for receiver peer_hello");
    loop {
        let frame = in_rx.recv().await.ok_or_else(|| anyhow!("ws closed before peer_hello"))?;
        if matches!(frame, SignalFrame::PeerHello { .. }) {
            break;
        }
    }

    // Offer.
    let offer = pc
        .create_offer(None)
        .await
        .map_err(|e| anyhow!("create_offer: {e}"))?;
    pc.set_local_description(offer.clone())
        .await
        .map_err(|e| anyhow!("set_local_description: {e}"))?;
    out_tx.send(SignalFrame::Sdp {
        kind: "offer".to_owned(),
        sdp: offer.sdp,
    })?;
    debug!("offer sent");

    // Wait for DC open (or WS death).
    dc_ready.notified().await;
    if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
        bail!("data channel not open after signal ({:?})", dc.ready_state());
    }
    info!("sender data channel open");

    Ok(LiveSession {
        session_id,
        role: Role::Sender,
        pc,
        dc,
        _ws_task: ws_task,
    })
}

/// Receiver flow.
pub async fn recv_connect(server_url: &str, session_id: SessionId) -> Result<LiveSession> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening receiver WS");
    let ws = open_ws(server_url, &session_hex).await?;

    let pc = build_peer_connection().await?;

    let dc_ready = Arc::new(tokio::sync::Notify::new());
    let dc_slot: Arc<Mutex<Option<Arc<RTCDataChannel>>>> = Arc::new(Mutex::new(None));
    let dc_ready_signal = dc_ready.clone();
    let dc_slot_signal = dc_slot.clone();
    pc.on_data_channel(Box::new(move |channel| {
        let slot = dc_slot_signal.clone();
        let ready = dc_ready_signal.clone();
        Box::pin(async move {
            let ch_for_open = channel.clone();
            let ready_open = ready.clone();
            ch_for_open.on_open(Box::new(move || {
                let n = ready_open.clone();
                Box::pin(async move { n.notify_waiters(); })
            }));
            *slot.lock().await = Some(channel);
        })
    }));

    let WsHandles { typed_out: out_tx, typed_in: mut in_rx, task: ws_task, .. } =
        drive_ws(ws, pc.clone(), dc_ready.clone());
    wire_ice_forwarding(&pc, out_tx.clone());

    let receiver_id = SessionId::random().as_hex();
    out_tx.send(SignalFrame::Hello {
        role: Role::Receiver.as_str().to_owned(),
        receiver_id: Some(receiver_id.clone()),
    })?;
    out_tx.send(SignalFrame::PeerHello {
        receiver_id: Some(receiver_id),
    })?;

    // Wait for the offer (set_remote_description was already called by drive_ws),
    // then answer.
    info!("waiting for sender SDP offer");
    loop {
        let frame = in_rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("ws closed before offer"))?;
        if let SignalFrame::Sdp { kind, .. } = &frame {
            if kind == "offer" {
                break;
            }
        }
    }

    let answer = pc
        .create_answer(None)
        .await
        .map_err(|e| anyhow!("create_answer: {e}"))?;
    pc.set_local_description(answer.clone())
        .await
        .map_err(|e| anyhow!("set_local_description: {e}"))?;
    out_tx.send(SignalFrame::Sdp {
        kind: "answer".to_owned(),
        sdp: answer.sdp,
    })?;
    debug!("answer sent");

    dc_ready.notified().await;
    let dc = dc_slot
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow!("no data channel arrived"))?;
    if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
        bail!("data channel not open after signal ({:?})", dc.ready_state());
    }
    info!("receiver data channel open");

    Ok(LiveSession {
        session_id,
        role: Role::Receiver,
        pc,
        dc,
        _ws_task: ws_task,
    })
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

async fn build_pc_and_dc()
    -> Result<(Arc<RTCPeerConnection>, Arc<RTCDataChannel>, Arc<tokio::sync::Notify>)>
{
    let pc = build_peer_connection().await?;
    let dc = pc
        .create_data_channel("bitmule", None)
        .await
        .map_err(|e| anyhow!("create_data_channel: {e}"))?;
    let dc_ready = Arc::new(tokio::sync::Notify::new());
    let n = dc_ready.clone();
    dc.on_open(Box::new(move || {
        let n = n.clone();
        Box::pin(async move { n.notify_waiters(); })
    }));
    Ok((pc, dc, dc_ready))
}

/// Send `file_path` over a fresh session. Auto mode tries WebRTC first
/// and falls back to server relay after WEBRTC_FALLBACK_MS if the DC
/// hasn't opened. `--webrtc` / `--relay` on the CLI force one path.
pub async fn send_file(
    server_url_http: &str,
    session_id: SessionId,
    file_path: std::path::PathBuf,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64, &str) + Send + 'static,
) -> Result<()> {
    let session_hex = session_id.as_hex();
    let ws = open_ws(&derive_ws_url(server_url_http), &session_hex).await?;
    let (pc, dc, dc_ready) = build_pc_and_dc().await?;
    let WsHandles {
        typed_out, mut typed_in, raw_out, mut raw_in, task: _ws_task
    } = drive_ws(ws, pc.clone(), dc_ready.clone());
    wire_ice_forwarding(&pc, typed_out.clone());

    typed_out.send(SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
    })?;

    // Relay progress state — shared between the send loop and the raw-in
    // task that resends on peer_joined.
    let relay_progress = Arc::new(Mutex::new(RelaySendProgress::default()));
    let file_name = file_path.file_name().map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let file_size = tokio::fs::metadata(&file_path).await?.len();

    // Watch raw_in for peer_joined:receiver notifications; if the relay
    // path is running, re-emit the progress so the newcomer catches up.
    let raw_out_for_task = raw_out.clone();
    let relay_progress_for_task = relay_progress.clone();
    let peer_joined_task = tokio::spawn(async move {
        while let Some(text) = raw_in.recv().await {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            let ty = v.get("type").and_then(|x| x.as_str());
            let role = v.get("role").and_then(|x| x.as_str());
            if ty == Some("peer_joined") && role == Some("receiver") {
                resend_relay_progress(&raw_out_for_task, relay_progress_for_task.clone()).await;
            }
        }
    });

    match mode {
        TransportMode::Relay => {
            // No WebRTC — just upload.
            let fname = file_name.clone();
            let sess = session_id.clone();
            let file_path_cloned = file_path.clone();
            let mut prog_cb = on_progress;
            send_file_over_relay(
                server_url_http, &sess, &file_path_cloned,
                raw_out.clone(), relay_progress.clone(),
                move |s, t| prog_cb(s, t, &fname),
            ).await?;
            peer_joined_task.abort();
            return Ok(());
        }
        TransportMode::Webrtc => {
            // Wait for the receiver's peer_hello, offer, wait for DC open.
            loop {
                let frame = typed_in.recv().await.ok_or_else(|| anyhow!("ws closed before peer_hello"))?;
                if matches!(frame, SignalFrame::PeerHello { .. }) { break; }
            }
            let offer = pc.create_offer(None).await.map_err(|e| anyhow!("offer: {e}"))?;
            pc.set_local_description(offer.clone()).await.map_err(|e| anyhow!("set_local: {e}"))?;
            typed_out.send(SignalFrame::Sdp { kind: "offer".into(), sdp: offer.sdp })?;
            dc_ready.notified().await;
            if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
                bail!("data channel didn't open");
            }
            let fname = file_name.clone();
            let mut prog_cb = on_progress;
            send_file_over_dc(dc.clone(), &file_path, move |s, t| prog_cb(s, t, &fname)).await?;
            peer_joined_task.abort();
            return Ok(());
        }
        TransportMode::Auto => {}
    }

    // Auto: race WebRTC negotiation vs 3s timer. Whichever fires first
    // decides the transport. The other is cancelled cleanly.

    // Handle peer_hello → offer in a task so it runs alongside the timer.
    let typed_out_offer = typed_out.clone();
    let pc_offer = pc.clone();
    let offer_task = tokio::spawn(async move {
        loop {
            let frame = match typed_in.recv().await {
                Some(f) => f, None => return,
            };
            if matches!(frame, SignalFrame::PeerHello { .. }) {
                match pc_offer.create_offer(None).await {
                    Ok(offer) => {
                        if let Err(e) = pc_offer.set_local_description(offer.clone()).await {
                            warn!("set_local: {e}"); return;
                        }
                        let _ = typed_out_offer.send(SignalFrame::Sdp { kind: "offer".into(), sdp: offer.sdp });
                    }
                    Err(e) => { warn!("create_offer: {e}"); return; }
                }
                return;
            }
        }
    });

    let dc_ready_clone = dc_ready.clone();
    let timer = tokio::time::sleep(Duration::from_millis(WEBRTC_FALLBACK_MS));
    let dc_wait = async move { dc_ready_clone.notified().await; };
    tokio::pin!(timer);
    tokio::pin!(dc_wait);

    let mut prog_cb = on_progress;
    let fname = file_name.clone();
    tokio::select! {
        _ = &mut dc_wait => {
            if dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
                let _ = offer_task;
                info!("auto: DC open, using WebRTC");
                send_file_over_dc(dc.clone(), &file_path, move |s, t| prog_cb(s, t, &fname)).await?;
                peer_joined_task.abort();
                return Ok(());
            }
        }
        _ = &mut timer => {
            info!("auto: {WEBRTC_FALLBACK_MS}ms elapsed without DC; falling back to relay");
        }
    }
    // Fallback: relay upload. offer_task keeps running (if peer_hello
    // arrives later, DC may still open; the receiver dedups by index).
    let fname2 = file_name.clone();
    let sess = session_id.clone();
    send_file_over_relay(
        server_url_http, &sess, &file_path,
        raw_out.clone(), relay_progress.clone(),
        move |s, t| prog_cb(s, t, &fname2),
    ).await?;
    peer_joined_task.abort();
    let _ = file_size;
    Ok(())
}

/// Receive one file from `session_id`. Auto mode watches both DC and
/// relay paths in parallel; whichever completes first wins.
pub async fn recv_file(
    server_url_http: &str,
    session_id: SessionId,
    out_dir: std::path::PathBuf,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64, &str) + Send + 'static,
) -> Result<std::path::PathBuf> {
    let session_hex = session_id.as_hex();
    let ws = open_ws(&derive_ws_url(server_url_http), &session_hex).await?;
    let pc = build_peer_connection().await?;
    let dc_ready = Arc::new(tokio::sync::Notify::new());
    let dc_slot: Arc<Mutex<Option<Arc<RTCDataChannel>>>> = Arc::new(Mutex::new(None));
    let dc_ready_signal = dc_ready.clone();
    let dc_slot_signal = dc_slot.clone();
    pc.on_data_channel(Box::new(move |channel| {
        let slot = dc_slot_signal.clone();
        let ready = dc_ready_signal.clone();
        Box::pin(async move {
            let ready_open = ready.clone();
            let ch = channel.clone();
            ch.on_open(Box::new(move || {
                let n = ready_open.clone();
                Box::pin(async move { n.notify_waiters(); })
            }));
            *slot.lock().await = Some(channel);
        })
    }));
    let WsHandles {
        typed_out, mut typed_in, raw_out: _, raw_in, task: _ws_task
    } = drive_ws(ws, pc.clone(), dc_ready.clone());
    wire_ice_forwarding(&pc, typed_out.clone());

    let receiver_id = SessionId::random().as_hex();
    typed_out.send(SignalFrame::Hello {
        role: Role::Receiver.as_str().to_owned(),
        receiver_id: Some(receiver_id.clone()),
    })?;
    typed_out.send(SignalFrame::PeerHello { receiver_id: Some(receiver_id) })?;

    // Wrap the callback in Arc<Mutex> so both the DC path and the relay
    // path can call it as chunks land.
    let on_progress = Arc::new(Mutex::new(on_progress));

    // Watch typed_in for the SDP offer; once seen, answer.
    let typed_out_ans = typed_out.clone();
    let pc_ans = pc.clone();
    let answer_task = tokio::spawn(async move {
        while let Some(f) = typed_in.recv().await {
            if let SignalFrame::Sdp { kind, .. } = &f {
                if kind == "offer" {
                    match pc_ans.create_answer(None).await {
                        Ok(a) => {
                            if let Err(e) = pc_ans.set_local_description(a.clone()).await {
                                warn!("recv set_local: {e}"); return;
                            }
                            let _ = typed_out_ans.send(SignalFrame::Sdp { kind: "answer".into(), sdp: a.sdp });
                        }
                        Err(e) => { warn!("recv create_answer: {e}"); return; }
                    }
                    return;
                }
            }
        }
    });

    match mode {
        TransportMode::Relay => {
            let progress_cb = on_progress.clone();
            let cb = move |a, b, c: &str| {
                if let Ok(mut g) = progress_cb.try_lock() { (*g)(a, b, c); }
            };
            let path = recv_file_over_relay(
                server_url_http, &session_id, &out_dir, raw_in, cb,
            ).await?;
            answer_task.abort();
            return Ok(path);
        }
        TransportMode::Webrtc => {
            dc_ready.notified().await;
            let dc = dc_slot.lock().await.clone().ok_or_else(|| anyhow!("no dc arrived"))?;
            if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
                bail!("dc not open");
            }
            let progress_cb = on_progress.clone();
            let cb = move |a, b, c: &str| {
                if let Ok(mut g) = progress_cb.try_lock() { (*g)(a, b, c); }
            };
            let path = recv_file_over_dc(dc, &out_dir, cb).await?;
            answer_task.abort();
            return Ok(path);
        }
        TransportMode::Auto => {}
    }

    // Auto: run both paths in parallel; whichever completes first wins,
    // cancel the other. The relay-mode consumer takes ownership of
    // raw_in so we can't share it — that means auto mode uses raw for
    // relay, DC for direct, no crossover.
    let out_dir_dc = out_dir.clone();
    let dc_slot_clone = dc_slot.clone();
    let dc_ready_clone = dc_ready.clone();
    let progress_dc = on_progress.clone();
    let dc_task = tokio::spawn(async move {
        dc_ready_clone.notified().await;
        let dc = dc_slot_clone.lock().await.clone().ok_or_else(|| anyhow!("no dc"))?;
        if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
            bail!("dc not open");
        }
        let cb = move |a, b, c: &str| {
            if let Ok(mut g) = progress_dc.try_lock() { (*g)(a, b, c); }
        };
        recv_file_over_dc(dc, &out_dir_dc, cb).await
    });

    let server_url_owned = server_url_http.to_string();
    let session_id_clone = session_id.clone();
    let out_dir_relay = out_dir.clone();
    let progress_relay = on_progress.clone();
    let relay_task = tokio::spawn(async move {
        let cb = move |a, b, c: &str| {
            if let Ok(mut g) = progress_relay.try_lock() { (*g)(a, b, c); }
        };
        recv_file_over_relay(&server_url_owned, &session_id_clone, &out_dir_relay, raw_in, cb).await
    });

    let dc_abort = dc_task.abort_handle();
    let relay_abort = relay_task.abort_handle();
    tokio::pin!(dc_task);
    tokio::pin!(relay_task);
    tokio::select! {
        r = &mut dc_task => {
            relay_abort.abort();
            answer_task.abort();
            match r {
                Ok(Ok(p)) => Ok(p),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow!("dc task join: {e}")),
            }
        }
        r = &mut relay_task => {
            dc_abort.abort();
            answer_task.abort();
            match r {
                Ok(Ok(p)) => Ok(p),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(anyhow!("relay task join: {e}")),
            }
        }
    }
}

fn derive_ws_url(server_url_http: &str) -> String {
    let base = server_url_http.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("http://") { format!("ws://{rest}") }
    else if let Some(rest) = base.strip_prefix("https://") { format!("wss://{rest}") }
    else { base.to_string() }
}

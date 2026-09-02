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

/// Splits the WS into a send-side (an mpsc that pushes JSON frames into the
/// socket) and a receive-side (JoinHandle that pumps incoming frames into
/// the peer's ICE + SDP paths). The join handle is kept alive by returning
/// it to the caller as part of the LiveSession.
fn drive_ws(
    ws: Ws,
    pc: Arc<RTCPeerConnection>,
    dc_ready: Arc<tokio::sync::Notify>,
) -> (mpsc::UnboundedSender<SignalFrame>, mpsc::UnboundedReceiver<SignalFrame>, tokio::task::JoinHandle<()>) {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SignalFrame>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<SignalFrame>();

    let (sink, mut stream) = ws.split();
    let sink = Arc::new(Mutex::new(sink));

    // Outbound pump: JSON-encode + send.
    let sink_out = sink.clone();
    tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let text = match serde_json::to_string(&frame) {
                Ok(t) => t,
                Err(e) => { warn!("frame encode: {e}"); continue; }
            };
            let mut s = sink_out.lock().await;
            if let Err(e) = s.send(Message::Text(text.into())).await {
                warn!("ws send: {e}");
                break;
            }
        }
    });

    // Inbound pump: parse + route.
    let pc_in = pc.clone();
    let in_tx_clone = in_tx.clone();
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
                    let _ = in_tx_clone.send(frame);
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
                    let _ = in_tx_clone.send(frame);
                }
                _ => {
                    let _ = in_tx_clone.send(frame);
                }
            }
        }
        // Wake anything still waiting on the DC in case the WS dies.
        dc_ready.notify_waiters();
    });

    (out_tx, in_rx, handle)
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

    let (out_tx, mut in_rx, ws_task) = drive_ws(ws, pc.clone(), dc_ready.clone());
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

    let (out_tx, mut in_rx, ws_task) = drive_ws(ws, pc.clone(), dc_ready.clone());
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

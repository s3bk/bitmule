//! Multi-peer sender orchestration (Phase M2 scaffolding).
//!
//! Spec: `docs/multipeer.md`. This module holds the type definitions
//! for the per-peer serving model; wiring lands in follow-up slices.
//! - M2b-1: type scaffold (ServeMode / DcControlFrame / ChunkRange / PeerHandle / CoveredNote).
//! - M2b-2: shared-WS router + writer scaffolding. Parent task
//!   owns single WS split into stream+sink; router dispatches inbound
//!   frames by `from_receiver_id` to per-peer mpsc inboxes; writer drains
//!   an outbox mpsc onto the sink.
//! - M2b-3 (this slice): send_connect swapped over to router+writer shape,
//!   still single-peer. Router+writer support shutdown-and-return-halves so
//!   the caller can reunite the WS before it lands in LiveSession —
//!   downstream file-transfer code keeps its `session.ws.next()` shape
//!   untouched until N-Rtc dispatch (M2b-4) needs the split-in-flight.
//! - M2b-4: N-Rtc dispatch loop over shared SocketPool via Rtc::accepts().
//! - M2b-5: PeerSession struct + per-peer task spawn on peer_hello.
//! - M2b-6: block-serve loop with request_ranges wire.
//! - M2b-7: receiver-side request_ranges + persistence for reconnect.
//! - M2b-8: unify --complete / --multi behind ServeMode; relay-path adapt.

use crate::crypto::BulkKey;
use crate::str0m_client::parse_ws_frame_with_from_id;
use crate::{SignalFrame, Ws};
use anyhow::{anyhow, Result};
use bitmule_core::ReceiverId;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_tungstenite::tungstenite::Message;

/// Serving mode selected by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ServeMode {
    /// Sender exits when at least one peer has fully received the file
    /// (covered set = 0..total_chunks). Peers may disconnect + reconnect
    /// during the transfer; sender rides that out.
    Complete,
    /// Sender never exits until process termination.
    Multi,
}

/// New wire frames on the data channel (chunks side, not signaling side).
///
/// Text control frames on the DC use JSON with `type` tag. See
/// `docs/multipeer.md` for semantics.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum DcControlFrame {
    /// Receiver → sender: ranges of chunks I want, half-open [start, end).
    RequestRanges { ranges: Vec<ChunkRange> },
    /// Receiver → sender: I have all chunks assembled locally.
    RecvDone,
    /// Sender → receiver: acknowledged; you can close the DC.
    DoneAck,
}

/// Half-open chunk index range, `[start, end)`. Wire form:
/// `{"start": u32, "end": u32}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ChunkRange {
    pub start: u32,
    pub end: u32,
}

/// Shared handle to a spawned per-peer serving task. Owned by the
/// sender-parent's peers map.
#[allow(dead_code)]
pub struct PeerHandle {
    pub receiver_id: ReceiverId,
    /// Covered set for THIS peer. Shared Arc<Mutex<...>> with the task
    /// so the parent can compute per-peer progress + check --complete
    /// exit predicate without cross-task channels.
    pub covered: Arc<Mutex<HashSet<u64>>>,
    /// Parent signals shutdown by dropping (or `send(true)` on) this.
    /// Per-peer task watches for the signal in its select! loop.
    pub shutdown_rx: watch::Receiver<bool>,
    /// Retained on parent to keep the channel alive for the peer task.
    pub _shutdown_tx: watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Cross-task notes from per-peer tasks to parent. Not used yet in the
/// scaffold (parent reads `covered` directly via the shared Arc), but
/// reserved for future signals (peer explicit recv_done ack, error
/// escalation, etc).
#[derive(Debug)]
#[allow(dead_code)]
pub enum CoveredNote {
    /// Peer emitted recv_done on the DC — they have the full file
    /// assembled locally. Parent can exit --complete on this.
    RecvDone { receiver_id: ReceiverId },
    /// Per-peer task terminated with an error. Parent logs + continues
    /// (other peers may still be serving).
    TaskError { receiver_id: ReceiverId, error: String },
}

// -------------------------------------------------------------------
// M2b-2: shared-WS router + writer.
//
// Parent task owns the single WS split into stream + sink halves.
// The router task reads from the stream, extracts each frame's
// `from_receiver_id` tag, and dispatches: known peer → that peer's
// inbox mpsc; unknown / untagged → parent's unrouted mpsc (peer_hello
// notifications and any sender-side control land there).
//
// The writer task drains an outbox mpsc<Message> to the sink. Per-peer
// tasks call `send_targeted(&outbox_tx, frame, Some(receiver_id))` which
// serializes + injects `to_receiver_id` + queues onto the outbox.
//
// Types + spawn helpers only in this slice. Not integrated into
// `send_connect` yet — that's M2b-3.
// -------------------------------------------------------------------

/// Control message to the router: register a per-peer inbox mpsc so
/// subsequent frames tagged with `from_receiver_id == this` route to it.
/// Sent by the parent when a peer_hello arrives + a per-peer task is
/// about to be spawned. Un-registration on peer-task exit is implicit
/// (the receiver half of the mpsc dropping causes send failures which
/// the router silently discards).
#[allow(dead_code)]
pub(crate) struct PeerRegistration {
    pub receiver_id: String,
    pub inbox_tx: mpsc::UnboundedSender<SignalFrame>,
}

/// Handle to the running WS router task. Task returns the reclaimed
/// stream half on graceful shutdown so the caller can reunite the WS.
#[allow(dead_code)]
pub(crate) struct WsRouterHandle {
    /// Send `PeerRegistration` here to add a per-peer route. Router
    /// updates its internal HashMap on next iteration.
    pub register_tx: mpsc::UnboundedSender<PeerRegistration>,
    /// Frames whose `from_receiver_id` is absent or matches no
    /// registered peer land here. Peer_hello notifications from the
    /// server are the primary content.
    pub unrouted_rx: mpsc::UnboundedReceiver<SignalFrame>,
    /// Set to `true` to ask the router to exit its select! loop after
    /// draining the current iteration. Router then returns the stream
    /// half back through `task`.
    pub shutdown_tx: watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<Result<SplitStream<Ws>>>,
}

/// Handle to the running WS writer task. Task returns the reclaimed
/// sink half on graceful shutdown (all `outbox_tx` clones dropped).
#[allow(dead_code)]
pub(crate) struct WsWriterHandle {
    /// All outbound WS payloads route through this mpsc. Per-peer tasks
    /// keep a clone of the sender; parent uses `.send()` to enqueue.
    /// Drop every clone to trigger writer shutdown.
    pub outbox_tx: mpsc::UnboundedSender<Message>,
    pub task: tokio::task::JoinHandle<Result<SplitSink<Ws, Message>>>,
}

/// Spawn the router task. Owns the read half of the WS; runs until
/// `shutdown_tx.send(true)` is called or the stream closes. Returns a
/// handle with the registration channel + unrouted mpsc receiver;
/// awaiting `task` after shutdown yields the stream half back.
#[allow(dead_code)]
pub(crate) fn spawn_ws_router(mut stream: SplitStream<Ws>) -> WsRouterHandle {
    let (register_tx, mut register_rx) = mpsc::unbounded_channel::<PeerRegistration>();
    let (unrouted_tx, unrouted_rx) = mpsc::unbounded_channel::<SignalFrame>();
    let (shutdown_tx, mut shutdown_rx) = watch::channel::<bool>(false);

    let task = tokio::spawn(async move {
        let mut peers: HashMap<String, mpsc::UnboundedSender<SignalFrame>> = HashMap::new();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(reg) = register_rx.recv() => {
                    peers.insert(reg.receiver_id, reg.inbox_tx);
                }
                maybe_msg = stream.next() => {
                    let parsed = match parse_ws_frame_with_from_id(maybe_msg) {
                        Ok(Some(pair)) => pair,
                        Ok(None) => continue,
                        Err(e) => return Err(e),
                    };
                    let (frame, from) = parsed;
                    match from.as_deref().and_then(|rid| peers.get(rid)) {
                        Some(inbox) => {
                            // Silent-drop if peer inbox already dropped.
                            let _ = inbox.send(frame);
                        }
                        None => {
                            let _ = unrouted_tx.send(frame);
                        }
                    }
                }
                else => break,
            }
        }
        Ok(stream)
    });

    WsRouterHandle { register_tx, unrouted_rx, shutdown_tx, task }
}

/// Spawn the writer task. Owns the write half of the WS; drains the
/// outbox mpsc until every `outbox_tx` clone is dropped, then returns
/// the sink half.
#[allow(dead_code)]
pub(crate) fn spawn_ws_writer(mut sink: SplitSink<Ws, Message>) -> WsWriterHandle {
    use futures_util::SinkExt;
    let (outbox_tx, mut outbox_rx) = mpsc::unbounded_channel::<Message>();
    let task = tokio::spawn(async move {
        while let Some(msg) = outbox_rx.recv().await {
            sink.send(msg)
                .await
                .map_err(|e| anyhow!("ws writer send: {e}"))?;
        }
        Ok(sink)
    });
    WsWriterHandle { outbox_tx, task }
}

/// Helper: serialize + optionally inject `to_receiver_id` + enqueue on
/// the writer's outbox. Per-peer tasks call this instead of touching
/// the sink directly. Mirror of `str0m_client::ws_send_targeted` but
/// routing to a mpsc instead of awaiting the sink.
#[allow(dead_code)]
pub(crate) fn ws_enqueue_targeted(
    outbox_tx: &mpsc::UnboundedSender<Message>,
    frame: &SignalFrame,
    to_receiver_id: Option<&str>,
) -> Result<()> {
    let mut v = serde_json::to_value(frame).map_err(|e| anyhow!("frame encode: {e}"))?;
    if let (Some(rid), Some(obj)) = (to_receiver_id, v.as_object_mut()) {
        obj.insert("to_receiver_id".to_string(), serde_json::Value::String(rid.to_string()));
    }
    let text = serde_json::to_string(&v).map_err(|e| anyhow!("frame reencode: {e}"))?;
    outbox_tx.send(Message::Text(text.into())).map_err(|e| anyhow!("outbox closed: {e}"))?;
    Ok(())
}


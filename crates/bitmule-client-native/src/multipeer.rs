//! Multi-peer sender orchestration (Phase M2 scaffolding).
//!
//! Spec: `docs/multipeer.md`. This module holds the type definitions
//! for the per-peer serving model; wiring lands in follow-up slices.
//! - M2b-1: type scaffold (ServeMode / DcControlFrame / ChunkRange / PeerHandle / CoveredNote).
//! - M2b-2: shared-WS router + writer scaffolding. Parent task
//!   owns single WS split into stream+sink; router dispatches inbound
//!   frames by `from_receiver_id` to per-peer mpsc inboxes; writer drains
//!   an outbox mpsc onto the sink.
//! - M2b-3: send_connect swapped over to router+writer shape, still
//!   single-peer. Router+writer support shutdown-and-return-halves so
//!   the caller can reunite the WS before it lands in LiveSession —
//!   downstream file-transfer code keeps its `session.ws.next()` shape
//!   untouched until N-Rtc dispatch requires the split-in-flight.
//! - M2b-4 (this slice): shared SocketPool + N-Rtc dispatch scaffolding.
//!   `build_rtc()` split into `build_socket_pool` + `build_rtc_with_pool_candidates`
//!   so multiple Rtcs can share one pool. `dispatch_pool_recv_to_rtcs`
//!   routes inbound packets via `Rtc::accepts()`. send_connect uses the
//!   new shape with N=1 today; M2b-5 spawns per-peer Rtcs into the same
//!   dispatch path with no changes to the routing itself.
//! - M2b-5: PeerSession struct + per-peer task spawn on peer_hello.
//! - M2b-6: block-serve loop with request_ranges wire.
//! - M2b-7: receiver-side request_ranges + persistence for reconnect.
//! - M2b-8: unify --complete / --multi behind ServeMode; relay-path adapt.

use crate::crypto::{BulkKey, MetaKey, ShareKey, WrapKey};
use crate::str0m_client::parse_ws_frame_with_from_id;
use crate::{SignalFrame, Ws};
use anyhow::{anyhow, Result};
use bitmule_core::ReceiverId;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use str0m::{channel::ChannelId, Rtc};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
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
///
/// `ack` fires once the router has inserted this peer into its
/// dispatch map. Callers await it before letting the peer task
/// proceed — closes the µs-scale race between mpsc-register and the
/// router's next iteration where a fast receiver's first frame could
/// otherwise land on `unrouted_rx` and get dropped. `spawn_peer_task`
/// is allowed to be a little slow — trade the two-µs oneshot roundtrip
/// for handshake correctness under a hot signaling server.
#[allow(dead_code)]
pub(crate) struct PeerRegistration {
    pub receiver_id: String,
    pub inbox_tx: mpsc::UnboundedSender<SignalFrame>,
    pub ack: oneshot::Sender<()>,
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
    /// server are the primary content. Payload is `(frame, from)`
    /// where `from` is the envelope-level `from_receiver_id` (server
    /// injects it when relaying notifications) — the orchestrator
    /// uses it to identify the peer since `PeerHello.receiver_id`
    /// in the frame body is optional and often not set by the server.
    pub unrouted_rx: mpsc::UnboundedReceiver<(SignalFrame, Option<String>)>,
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
    let (unrouted_tx, unrouted_rx) = mpsc::unbounded_channel::<(SignalFrame, Option<String>)>();
    let (shutdown_tx, mut shutdown_rx) = watch::channel::<bool>(false);

    let task = tokio::spawn(async move {
        let mut peers: HashMap<String, mpsc::UnboundedSender<SignalFrame>> = HashMap::new();
        // Pending: WS frames whose envelope `from_receiver_id` names a
        // peer that hasn't registered yet. Common when the receiver
        // ships peer_hello + KexPub + SDP answer back-to-back and the
        // KexPub reaches the router BEFORE the orchestrator has
        // finished spawn_peer_task's registration handshake. Small cap
        // to bound worst-case memory if a bogus from_receiver_id keeps
        // arriving for a peer that never registers.
        let mut pending: HashMap<String, Vec<SignalFrame>> = HashMap::new();
        const PENDING_CAP_PER_PEER: usize = 32;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(reg) = register_rx.recv() => {
                    // Drain any pending frames for this peer's id into
                    // the freshly-registered inbox BEFORE the ack fires,
                    // so `spawn_peer_task`'s caller sees a consistent
                    // "registration is live and any queued frames are
                    // already delivered" post-condition.
                    if let Some(queued) = pending.remove(&reg.receiver_id) {
                        for f in queued {
                            let _ = reg.inbox_tx.send(f);
                        }
                    }
                    peers.insert(reg.receiver_id, reg.inbox_tx);
                    let _ = reg.ack.send(());
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
                            // Dual-delivery: forward every frame with an
                            // unknown from_receiver_id to unrouted_rx
                            // AND buffer a clone by receiver_id for a
                            // future peer registration.
                            //
                            // - unrouted_rx keeps the legacy single-peer
                            //   `send_connect` path working (it never
                            //   registers peers, so it reads everything
                            //   from unrouted_rx and just ignores the
                            //   from_receiver_id envelope).
                            // - pending[from] wins the race where a
                            //   receiver ships KexPub/SDP-answer BEFORE
                            //   the multipeer orchestrator finishes
                            //   spawn_peer_task. On registration, the
                            //   buffered frames drain into the peer's
                            //   inbox so the peer_session_run's KEX
                            //   completes without a lost frame.
                            //
                            // The multipeer orchestrator drops the
                            // unrouted copy at debug level (non-PeerHello
                            // unrouted frames are expected chatter under
                            // this dual-delivery scheme).
                            if let Some(rid) = from.as_deref() {
                                let entry = pending.entry(rid.to_string()).or_default();
                                if entry.len() < PENDING_CAP_PER_PEER {
                                    entry.push(frame.clone());
                                }
                                // Silent-cap: if a bogus from_receiver_id
                                // spams us past the cap, we stop buffering
                                // but still forward to unrouted so
                                // send_connect / diagnostics see it.
                            }
                            let _ = unrouted_tx.send((frame, from));
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

// -------------------------------------------------------------------
// M2b-5: sender-side shared state + per-peer task spawn on peer_hello.
//
// Scope of this slice (per docs/multipeer.md line 21):
//   - Type definitions: SenderShared, PeerSession.
//   - Per-peer task-spawn entry: `spawn_peer_task` (in str0m_client.rs
//     where the private handshake helpers live).
//   - Long-lived orchestrator entry: `send_serve` (in str0m_client.rs).
//
// Explicitly NOT in this slice:
//   - Block-serve loop / request_ranges wire (M2b-6).
//   - Receiver-side request_ranges + persistence (M2b-7).
//   - cmd_send wiring to send_serve; --multi CLI flag (M2b-8).
//
// The single-peer `send_connect` path stays untouched — send_serve runs
// alongside as a parallel entry so we don't destabilize the working
// wire-transport while multipeer scaffolds up.
// -------------------------------------------------------------------

/// Sender-side state that every per-peer task needs read-only access to.
/// Cheap-cloned into each PeerSession as `Arc<SenderShared>`.
///
/// `bulk_key` is the SAME B for every peer — URL commitment binds one B
/// per file. `share_key` stays live so per-peer KEX MAC verification
/// can call `share_key.mac_ephemeral_pub`. `session_id_bytes` is derived
/// once from the session hex and reused for HKDF salting.
///
/// M2b-6: file identity (path/size/total_chunks) + serve mode so per-peer
/// tasks can send the meta_enc frame + serve chunk ranges + eventually
/// exit under --complete when a peer covers 0..total_chunks.
#[allow(dead_code)]
pub struct SenderShared {
    pub share_key: ShareKey,
    pub bulk_key: BulkKey,
    pub session_id_bytes: [u8; 32],
    pub wire_version: u32,
    pub file_path: PathBuf,
    pub file_size: u64,
    pub total_chunks: u64,
    pub mode: ServeMode,
    /// See MetaFrame::container semantics. `Some("zip-store")` = receiver
    /// should unpack; `None` = single file, keep as-is.
    pub container: Option<String>,
}

/// Per-peer serving state. Owned by the per-peer task's async block —
/// constructed inside `spawn_peer_task` and filled in as the handshake
/// progresses (wrap_key + meta_key land after KEX; the block-serve loop
/// in M2b-6 will consume the whole struct).
///
/// M2b-5 uses these fields inline in the task body; the struct exists
/// now so M2b-6's block-serve refactor doesn't need to touch types.
#[allow(dead_code)]
pub struct PeerSession {
    pub receiver_id: ReceiverId,
    pub rtc: Rtc,
    pub channel_id: ChannelId,
    /// Filled after KEX completes; None before the peer's KexPub lands.
    pub wrap_key: Option<WrapKey>,
    pub meta_key: Option<MetaKey>,
    pub covered: Arc<Mutex<HashSet<u64>>>,
    pub shared: Arc<SenderShared>,
}

/// Handle returned by `send_serve` — long-lived orchestrator over the
/// sender-side multipeer stack. Holds the shared WS router+writer, the
/// per-peer task map, and the shared SocketPool alive for the run.
///
/// M2b-8 grows `note_rx` for peer-task → orchestrator notifications
/// (RecvDone, TaskError) so `await_complete` can drive the mode-aware
/// exit predicate.
#[allow(dead_code)]
pub struct SenderOrchestrator {
    pub shared: Arc<SenderShared>,
    pub peers: Arc<Mutex<HashMap<String, PeerHandle>>>,
    /// Held so the WS reader half stays owned by the router task.
    /// `pub(crate)` — WsRouterHandle is internal plumbing.
    pub(crate) router: WsRouterHandle,
    /// Held so per-peer tasks can enqueue outbound frames.
    pub(crate) writer: WsWriterHandle,
    /// Orchestrator loop task — reads unrouted (peer_hello) frames and
    /// spawns per-peer tasks. Exits on WS close.
    pub loop_task: tokio::task::JoinHandle<Result<()>>,
    /// M2b-8: per-peer notifications back to the orchestrator. Peer
    /// tasks send `RecvDone` after the sender→receiver DoneAck exchange
    /// completes cleanly, and `TaskError` on abnormal exit. `await_complete`
    /// consumes this to drive mode-aware exit (Complete: shut down all
    /// peers when the first one finishes; Multi: log + continue).
    pub(crate) note_rx: mpsc::UnboundedReceiver<CoveredNote>,
}

impl SenderOrchestrator {
    /// Drive the orchestrator to its mode-dependent end state.
    ///
    /// - `ServeMode::Complete`: return `Ok(())` the moment the first
    ///   peer's DoneAck exchange completes. Signals every other peer
    ///   task to shut down cleanly + drains the WS router+writer.
    ///   Semantic match to docs/multipeer.md §"--complete early exit
    ///   predicate": get the file to A destination, not exit after N
    ///   minutes.
    /// - `ServeMode::Multi`: never returns Ok. Runs until either the
    ///   WS closes (orchestrator loop exits, propagated as Err) or
    ///   `stop_and_shutdown` is called on the handle. `TaskError`
    ///   notes are logged but don't terminate the sender.
    pub async fn await_complete(&mut self) -> Result<()> {
        use tracing::{info, warn};
        let mode = self.shared.mode;
        loop {
            let note = match self.note_rx.recv().await {
                Some(n) => n,
                None => {
                    // Every peer-task sender clone dropped without note.
                    // Happens if the orchestrator loop dies before any
                    // peer connects (WS close) — propagate as error.
                    return Err(anyhow!("all peer-note senders dropped without RecvDone"));
                }
            };
            match note {
                CoveredNote::RecvDone { receiver_id } => {
                    let rid_hex = receiver_id.as_hex();
                    match mode {
                        ServeMode::Complete => {
                            info!(peer = %rid_hex, "peer completed — shutting down orchestrator (Complete mode)");
                            self.shutdown_all_peers().await;
                            return Ok(());
                        }
                        ServeMode::Multi => {
                            info!(peer = %rid_hex, "peer completed — continuing to serve (Multi mode)");
                        }
                    }
                }
                CoveredNote::TaskError { receiver_id, error } => {
                    warn!(peer = %receiver_id.as_hex(), "peer task errored: {error} — other peers keep serving");
                }
            }
        }
    }

    /// Signal every currently-registered peer task to shut down cleanly,
    /// then await their exits. Used by `await_complete` on Complete-mode
    /// success and by callers who want to stop a Multi-mode server.
    pub async fn shutdown_all_peers(&self) {
        use tracing::{debug, warn};
        // Take ownership of the peer handles (empties the map) so we can
        // move each `task` into an await without holding the mutex.
        let handles: Vec<PeerHandle> = {
            let mut peers = self.peers.lock().await;
            peers.drain().map(|(_k, v)| v).collect()
        };
        for handle in handles {
            let rid = handle.receiver_id.as_hex();
            let _ = handle._shutdown_tx.send(true);
            match handle.task.await {
                Ok(Ok(())) => debug!(peer = %rid, "peer task joined clean"),
                Ok(Err(e)) => warn!(peer = %rid, "peer task exited with err: {e}"),
                Err(je) => warn!(peer = %rid, "peer task join panic: {je}"),
            }
        }
    }
}


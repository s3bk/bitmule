//! Multi-peer sender orchestration (Phase M2 scaffolding).
//!
//! Spec: `docs/multipeer.md`. This module holds the type definitions
//! for the per-peer serving model; wiring lands in follow-up slices.
//! - M2b-1 (this file): types only, no runtime behavior.
//! - M2b-2: parent WS reader/writer + per-peer task spawn on peer_hello.
//! - M2b-3: block-serve loop with request_ranges wire.
//! - M2b-4: receiver-side request_ranges + persistence for reconnect.
//! - M2b-5: unify --complete / --multi behind ServeMode.
//! - M2b-6: relay-path adaptation (single-KEX-shared-across-peers).

use crate::crypto::BulkKey;
use bitmule_core::ReceiverId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

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

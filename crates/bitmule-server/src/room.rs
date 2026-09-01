//! In-memory per-session signaling room.
//!
//! A [`Room`] holds one sender slot and any number of receiver slots. Each
//! slot is an `mpsc::UnboundedSender` that dispatches WebSocket text frames
//! back to that connected peer. Frames from the sender fan out to all
//! receivers; frames from any receiver route only to the sender.
//!
//! Rooms are ephemeral — dropped from [`crate::AppState`] the moment their
//! last peer disconnects. State that must survive restart (chunks, delivery
//! ledger, quota) lives in the [`bitmule_core::traits::ChunkStore`].

use bitmule_core::ReceiverId;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// One-way channel to a peer's WebSocket sink. Text frames only — binary
/// signaling is JSON-over-text.
pub type PeerSink = mpsc::UnboundedSender<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// One session's live signaling state.
#[derive(Default)]
pub struct Room {
    pub sender: Option<PeerSink>,
    pub receivers: HashMap<ReceiverId, PeerSink>,
}

impl Room {
    pub fn is_empty(&self) -> bool {
        self.sender.is_none() && self.receivers.is_empty()
    }

    /// Fan a sender-originated frame out to all receivers currently in the room.
    /// Silently drops sinks whose receive half has been closed.
    pub fn fan_to_receivers(&mut self, frame: &str) {
        self.receivers
            .retain(|_, sink| sink.send(frame.to_string()).is_ok());
    }

    /// Route a receiver-originated frame to the sender if present.
    pub fn route_to_sender(&self, frame: &str) {
        if let Some(sink) = &self.sender {
            let _ = sink.send(frame.to_string());
        }
    }
}

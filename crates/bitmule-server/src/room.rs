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

use bitmule_core::{ReceiverId, crypto::{PublicKey, SessionMac}, protocol::websocket::{PeerCaps, ServerToClient}};
use bytes::Bytes;
use std::collections::HashMap;
use tokio::sync::mpsc::{self, error::TrySendError};

pub type PeerSink = mpsc::Sender<ServerToClient>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// A registered peer: sink for outbound frames + the wire-protocol version
/// they advertised in their Hello (used to send `peer_hello` notifications
/// with the counterpart's version so mismatched clients can bail cleanly).
#[derive(Clone)]
pub struct PeerEntry {
    pub sink: PeerSink,
    pub caps: PeerCaps,
    pub pub_key: PublicKey,
    pub mac: SessionMac,
}

/// One session's live signaling state.
pub struct Room {
    pub owner: ReceiverId,
    pub receivers: HashMap<ReceiverId, PeerEntry>,
}

impl Room {
    pub fn is_empty(&self) -> bool {
        self.receivers.is_empty()
    }

    pub fn get_sink(&self, dest: ReceiverId) -> Option<PeerSink> {
        self.receivers.get(&dest).map(|peer| peer.sink.clone())
    }
    pub fn send_to(&self, dest: ReceiverId, msg: ServerToClient) -> Result<(), SendError> {
        if let Some(recv) = self.receivers.get(&dest) {
            match recv.sink.try_send(msg) {
                Ok(()) => Ok(()),
                Err(TrySendError::Closed(_)) => Err(SendError::Disconnected),
                Err(TrySendError::Full(_)) => Err(SendError::Full)
            }
        } else {
            Err(SendError::Disconnected)
        }
    }
}
pub enum SendError {
    Disconnected,
    Full
}

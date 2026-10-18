//! Shared app state passed to axum handlers.

use crate::{Difficulty, Magic, decode_difficulty_and_magic, encode_difficulty_and_magic, relay2::MulticastSession, room::{PeerEntry, Room}};
use bitmule_core::{ReceiverId, SessionId, Token, protocol::websocket::ServerToClient};
use std::{collections::HashMap, sync::{Arc, Weak, atomic::{AtomicU64, Ordering}}};
use tokio::sync::Mutex;

pub struct SessionState {
    multicast: MulticastSession,
    room: Mutex<Room>,
    /// What a joiner's proof has to hash to (`bitmule_core::crypto::join_check_of`).
    join_check: [u8; 32],
}
impl SessionState {
    pub fn new(owner: ReceiverId, peer: PeerEntry, join_check: [u8; 32]) -> Self {
        let mut room = Room {
            owner,
            receivers: Default::default()
        };
        room.receivers.insert(owner, peer);
        SessionState {
            multicast: MulticastSession::default(),
            room: Mutex::new(room),
            join_check,
        }
    }

    /// Does `proof` let somebody into this session?
    pub fn allows_join(&self, proof: &[u8; 32]) -> bool {
        bitmule_core::crypto::join_proof_matches(proof, &self.join_check)
    }
    pub fn multicast(&self) -> &MulticastSession {
        &self.multicast
    }
    pub fn room(&self) -> &Mutex<Room> {
        &self.room
    }
    /// Register a joining peer and notify the owner. Returns the owner's id
    /// and entry (for `SessionJoined`). Ids already in the room, the
    /// owner's included, are rejected.
    pub async fn add_peer(&self, id: ReceiverId, peer: PeerEntry) -> Result<(ReceiverId, PeerEntry), JoinError> {
        let msg = ServerToClient::PeerJoined { id, pub_key: peer.pub_key, mac: peer.mac, caps: peer.caps };

        let (owner_id, owner) = {
            let mut room = self.room.lock().await;
            if room.receivers.contains_key(&id) {
                return Err(JoinError::IdInUse);
            }
            room.receivers.insert(id, peer);
            let owner_id = room.owner;
            (owner_id, room.receivers[&owner_id].clone())
        };
        // an absent owner learns about this peer when it reconnects
        let _ = owner.sink.send(msg).await;
        Ok((owner_id, owner))
    }

    /// Owner reconnect: must present the reconnect token issued at creation
    /// and the same id and identity key. The old connection's sink is
    /// dropped, which closes it. Returns the entry (tokens unchanged) and
    /// the receivers currently in the room.
    pub async fn reconnect_owner(&self, id: ReceiverId, token: Token, new: PeerEntry, join_check: [u8; 32]) -> Result<(PeerEntry, Vec<(ReceiverId, PeerEntry)>), CreateError> {
        let mut room = self.room.lock().await;
        if id != room.owner {
            return Err(CreateError::BadToken);
        }
        let old = &room.receivers[&id];
        if old.reconnect_token != token {
            return Err(CreateError::BadToken);
        }
        if old.pub_key.0 != new.pub_key.0 || join_check != self.join_check {
            return Err(CreateError::IdentityChanged);
        }
        let entry = PeerEntry { reconnect_token: old.reconnect_token, relay_token: old.relay_token, ..new };
        room.receivers.insert(id, entry.clone());
        let peers = room.receivers.iter()
            .filter(|(pid, _)| **pid != id)
            .map(|(pid, p)| (*pid, p.clone()))
            .collect();
        Ok((entry, peers))
    }

    /// Remove a disconnected receiver and tell the owner. The owner's entry
    /// is kept so it can reconnect.
    pub async fn remove_peer(&self, id: ReceiverId) {
        let owner_sink = {
            let mut room = self.room.lock().await;
            if id == room.owner || room.receivers.remove(&id).is_none() {
                return;
            }
            room.get_sink(room.owner)
        };
        if let Some(sink) = owner_sink {
            let _ = sink.send(ServerToClient::PeerDisconnected { id }).await;
        }
    }

    /// Check a relay token. POST (`owner_only`) must come from the owner;
    /// GET from any peer in the room, with its own token.
    pub async fn authorize_relay(&self, id: ReceiverId, token: &Token, owner_only: bool) -> bool {
        let room = self.room.lock().await;
        if owner_only && id != room.owner {
            return false;
        }
        room.receivers.get(&id).is_some_and(|p| p.relay_token == *token)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("receiver id already in use")]
    IdInUse,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("session exists; reconnect token missing or invalid")]
    BadToken,
    #[error("no live session to reconnect to; create it with a PoW instead")]
    NoSession,
    #[error("identity key differs from the original owner")]
    IdentityChanged,
}

pub struct Created {
    pub session: Arc<SessionState>,
    /// The owner's entry as stored, with the tokens to report to it.
    pub entry: PeerEntry,
    /// Receivers already present (non-empty only on reconnect).
    pub peers: Vec<(ReceiverId, PeerEntry)>,
}

pub struct AppState {
    pub rooms: Mutex<HashMap<SessionId, Weak<SessionState>>>,
    difficulty_and_magic: AtomicU64,
    /// How often a websocket that asked for it (`enablePing`) is pinged.
    pub ping_interval: std::time::Duration,
}

impl AppState {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let difficulty_and_magic = AtomicU64::new(encode_difficulty_and_magic(
            Difficulty(22),
            Magic::random(&mut rng),
            Magic::random(&mut rng)
        ));
        Self {
            rooms: Mutex::new(HashMap::new()),
            difficulty_and_magic,
            ping_interval: std::time::Duration::from_secs(20),
        }
    }

    pub fn with_ping_interval(mut self, interval: std::time::Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    pub fn rotate_magic(&self) {
        let magic1 = Magic::random(&mut rand::thread_rng());
        self.difficulty_and_magic.update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            let (difficulty, magic2, _) = decode_difficulty_and_magic(n);
            encode_difficulty_and_magic(difficulty, magic1, magic2)
        });
    }
    pub fn difficulty_and_magic(&self) -> (Difficulty, Magic, Magic) {
        let n = self.difficulty_and_magic.load(Ordering::Relaxed);
        decode_difficulty_and_magic(n)
    }

    /// Create the room for a session. If a live room exists, this is an
    /// owner reconnect and needs the reconnect token.
    pub async fn create_session(&self, id: SessionId, owner: ReceiverId, peer: PeerEntry, join_check: [u8; 32], token: Option<Token>) -> Result<Created, CreateError> {
        let mut map = self.rooms.lock().await;
        if let Some(session) = map.get(&id).and_then(Weak::upgrade) {
            let token = token.ok_or(CreateError::BadToken)?;
            let (entry, peers) = session.reconnect_owner(owner, token, peer, join_check).await?;
            return Ok(Created { session, entry, peers });
        }
        if token.is_some() {
            // a token skips the PoW, so it can't be used to create a session
            return Err(CreateError::NoSession);
        }
        let entry = peer.clone();
        let session = Arc::new(SessionState::new(owner, peer, join_check));
        map.insert(id, Arc::downgrade(&session));
        Ok(Created { session, entry, peers: vec![] })
    }

    /// Get or create the [`Room`] for a session. Two-level mutex: the outer
    /// map lock is held only long enough to insert the room slot; the inner
    /// per-room lock is what handlers actually contend on during a session.
    pub async fn get_session(&self, id: SessionId) -> Option<Arc<SessionState>> {
        let map = self.rooms.lock().await;
        map.get(&id).and_then(|w| w.upgrade())
    }

    /// Drop the room slot when the last peer has disconnected. Callers
    /// should check `is_empty()` on the room they're leaving and then call
    /// this to reclaim the map entry.
    pub async fn maybe_drop_room(&self, session: SessionId) {
        let mut map = self.rooms.lock().await;
        match map.entry(session) {
            std::collections::hash_map::Entry::Occupied(e) => {
                if e.get().strong_count() == 0 {
                    e.remove();
                }
            }
            _ => {}
        }
    }
}

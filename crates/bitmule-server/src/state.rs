//! Shared app state passed to axum handlers.

use crate::{Difficulty, Magic, decode_difficulty_and_magic, encode_difficulty_and_magic, relay2::MulticastSession, room::{PeerEntry, Room}};
use bitmule_core::{ReceiverId, SessionId, protocol::websocket::ServerToClient};
use rand::Rng;
use std::{collections::HashMap, sync::{Arc, Weak, atomic::{AtomicU8, AtomicU64, Ordering}}};
use tokio::sync::Mutex;

pub struct SessionState {
    multicast: MulticastSession,
    room: Mutex<Room>,
}
impl SessionState {
    pub fn new(owner: ReceiverId, peer: PeerEntry) -> Self {
        let mut room = Room {
            owner,
            receivers: Default::default()
        };
        room.receivers.insert(owner, peer);
        SessionState {
            multicast: MulticastSession::default(),
            room: Mutex::new(room)
        }
    }
    pub fn multicast(&self) -> &MulticastSession {
        &self.multicast
    }
    pub fn room(&self) -> &Mutex<Room> {
        &self.room
    }
    /// tries to send a message to the owner of the room (and blocks for that)
    /// does nothing if the owner isn't reachable
    pub async fn add_peer(&self, id: ReceiverId, peer: PeerEntry) {
        let msg = ServerToClient::PeerJoined { id, pub_key: peer.pub_key.clone(), mac: peer.mac };

        let sink = {
            let mut room = self.room.lock().await;
            room.receivers.insert(id, peer);
            room.receivers.get(&room.owner).map(|peer| peer.sink.clone())
        };
        if let Some(sink) = sink {
            let _ = sink.send(msg).await;
        }
    }
}

pub struct AppState {
    pub rooms: Mutex<HashMap<SessionId, Weak<SessionState>>>,
    difficulty_and_magic: AtomicU64,
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
            difficulty_and_magic
        }
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

    /// Get or create the [`Room`] for a session. Two-level mutex: the outer
    /// map lock is held only long enough to insert the room slot; the inner
    /// per-room lock is what handlers actually contend on during a session.
    pub async fn create_session(&self, id: SessionId, owner: ReceiverId, peer: PeerEntry) -> Arc<SessionState> {
        let mut map = self.rooms.lock().await;
        if let Some(session) = map.entry(id)
            .or_default()
            .upgrade()
        {
            return session;
        }
        let session = Arc::new(SessionState::new(owner, peer));
        map.insert(id, Arc::downgrade(&session));
        session
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

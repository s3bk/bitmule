//! Shared app state passed to axum handlers.

use crate::{relay2::MulticastSession, room::Room};
use bitmule_core::{SessionId};
use std::{collections::HashMap, sync::{Arc, Weak}};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct SessionState {
    multicast: MulticastSession,
    room: Mutex<Room>,
}
impl SessionState {
    pub fn multicast(&self) -> &MulticastSession {
        &self.multicast
    }
    pub fn room(&self) -> &Mutex<Room> {
        &self.room
    }
}

#[derive(Clone)]
pub struct AppState {
    pub rooms: Arc<Mutex<HashMap<SessionId, Weak<SessionState>>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create the [`Room`] for a session. Two-level mutex: the outer
    /// map lock is held only long enough to insert the room slot; the inner
    /// per-room lock is what handlers actually contend on during a session.
    pub async fn create_session(&self, id: SessionId) -> Arc<SessionState> {
        let mut map = self.rooms.lock().await;
        if let Some(session) = map.entry(id)
            .or_default()
            .upgrade()
        {
            return session;
        }
        let session = Arc::new(SessionState::default());
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

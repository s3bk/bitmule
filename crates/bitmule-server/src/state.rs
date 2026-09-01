//! Shared app state passed to axum handlers.

use crate::room::Room;
use bitmule_core::{traits::ChunkStore, SessionId};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn ChunkStore>,
    pub rooms: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Room>>>>>,
}

impl AppState {
    pub fn new(store: Arc<dyn ChunkStore>) -> Self {
        Self {
            store,
            rooms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create the [`Room`] for a session. Two-level mutex: the outer
    /// map lock is held only long enough to insert the room slot; the inner
    /// per-room lock is what handlers actually contend on during a session.
    pub async fn room(&self, session: SessionId) -> Arc<Mutex<Room>> {
        let mut map = self.rooms.lock().await;
        map.entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(Room::default())))
            .clone()
    }

    /// Drop the room slot when the last peer has disconnected. Callers
    /// should check `is_empty()` on the room they're leaving and then call
    /// this to reclaim the map entry.
    pub async fn maybe_drop_room(&self, session: &SessionId) {
        let mut map = self.rooms.lock().await;
        if let Some(room) = map.get(session) {
            if room.lock().await.is_empty() {
                map.remove(session);
            }
        }
    }
}

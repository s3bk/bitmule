use crate::{ChunkBitmap, ReceiverId, Result, SessionId};
use async_trait::async_trait;
use std::time::Duration;

/// Signaling transport for WebRTC SDP + session key exchange between peers.
///
/// Default impl: WebSocket via `bitmule-server-signal-ws`. Swap out for gRPC,
/// libp2p, or a custom transport by implementing this trait.
#[async_trait]
pub trait SignalTransport: Send + Sync {
    async fn connect(&mut self, session: &SessionId) -> Result<()>;
    async fn send(&mut self, msg: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
    async fn close(&mut self) -> Result<()>;
}

/// Storage for server-side buffered chunks (relay fallback for when WebRTC
/// direct fails or one peer is offline). Ciphertext-only — the server never
/// sees plaintext.
///
/// Default impl: filesystem via `bitmule-server-store-fs`. Swap for S3/R2 in
/// SaaS deployments.
#[async_trait]
pub trait ChunkStore: Send + Sync {
    /// Store an encrypted chunk (ciphertext under K_session).
    async fn put(&self, session: &SessionId, chunk_idx: u32, ciphertext: &[u8]) -> Result<()>;

    /// Retrieve a stored chunk.
    async fn get(&self, session: &SessionId, chunk_idx: u32) -> Result<Option<Vec<u8>>>;

    /// Which chunks does the server currently have for this session?
    async fn have(&self, session: &SessionId) -> Result<ChunkBitmap>;

    /// Remaining bytes of capacity in this session's quota (backpressure signal).
    async fn capacity_available(&self, session: &SessionId) -> Result<u64>;

    /// Mark a chunk as delivered to a specific receiver. When all configured
    /// receivers have received, `gc_delivered` can reclaim the chunk.
    async fn mark_delivered(
        &self,
        session: &SessionId,
        chunk_idx: u32,
        receiver: &ReceiverId,
    ) -> Result<()>;

    /// Reclaim storage for chunks fully delivered to all receivers.
    async fn gc_delivered(&self) -> Result<u64>;

    /// Evict undelivered chunks older than the retention threshold.
    async fn evict_older_than(&self, threshold: Duration) -> Result<u64>;

    /// Total bytes of stored chunk data across all sessions.
    async fn total_bytes_stored(&self) -> Result<u64>;

    /// Evict oldest chunks first until total stored bytes falls at or below
    /// `target_bytes`. Returns the number of bytes freed. If already at or
    /// below `target_bytes`, returns 0 without touching anything.
    async fn evict_to_bytes(&self, target_bytes: u64) -> Result<u64>;
}

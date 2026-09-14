//! bitmule-core: chunking, crypto, manifest, protocol state.
//!
//! Designed to compile to both native (server, CLI) and wasm (browser).
//! No I/O, no filesystem, no networking — those live in the caller.

pub mod manifest;
pub mod chunk;
pub mod crypto;
pub mod protocol;
pub mod traits;

pub use manifest::{Manifest, FileEntry, ChunkSize};
pub use chunk::{ChunkId, ChunkHeader, ChunkPayload};
pub use crypto::{SessionKey, ContentKey, WrappedContentKey, KeyExchange};
pub use protocol::{SessionId, ReceiverId, ChunkBitmap};
pub use traits::{ChunkStore, SignalTransport};
use xxhash_rust::xxh3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("io: {0}")]
    Io(String),
    #[error("bad chunk: {0}")]
    BadChunk(String),
    #[error("bad manifest: {0}")]
    BadManifest(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ChunkHasher {
    inner: xxh3::Xxh3
}
impl ChunkHasher {
    pub fn new(chunk_idx: u32) -> Self {
        const V1_PRIME: u64 = 1537228672809129329;
        const BUILDER: xxh3::Xxh3Builder = xxh3::Xxh3Builder::new()
            .with_secret(*b"bitmule-chunk-hash-v1-yi5raeXaep9MeeNgoo0shup9eeyeefe9aeyeaw6Bi9shuh7diequee7ohyee8oodaWe8Baish6googh9ahquuok6waoXoh8wa8Phpea9shahw1aih1bohkaeg3oShaiXeejiM8ahfohfie7RiepaNee2ieTee8Ahngagoh3ani");

        let seed = (chunk_idx as u64).wrapping_mul(V1_PRIME);
        ChunkHasher {
            inner: BUILDER.with_seed(seed).build()
        }
    }
    pub fn add_frame(&mut self, frame: &[u8]) {
        self.inner.update(frame);
    }
    pub fn digest(&self) -> u64 {
        self.inner.digest()
    }
}

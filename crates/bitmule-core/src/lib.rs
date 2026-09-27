//! bitmule-core: chunking, crypto, manifest, protocol state.
//!
//! Designed to compile to both native (server, CLI) and wasm (browser).
//! No I/O, no filesystem, no networking — those live in the caller.

pub mod manifest;
pub mod chunk;
pub mod crypto;
pub mod protocol;
pub mod pow;
pub mod inner;

use std::ops;

pub use manifest::{Manifest, FileEntry, ChunkSize};
pub use chunk::{ChunkId, ChunkHeader, ChunkPayload};
pub use crypto::{SessionKey, ContentKey, WrappedContentKey, KeyExchange};
pub use protocol::{SessionId, ReceiverId, ChunkBitmap};
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

#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkIdx(u64);
impl ChunkIdx {
    pub fn from_le_bytes(bytes: [u8; 6]) -> Self {
        let [b0,b1,b2,b3,b4,b5] = bytes;
        ChunkIdx(u64::from_le_bytes([b0,b1,b2,b3,b4,b5,0,0]))
    }
    pub fn to_le_bytes(self) -> [u8; 6] {
        let [b0,b1,b2,b3,b4,b5,_,_] = self.0.to_le_bytes();
        [b0,b1,b2,b3,b4,b5]
    }
}
impl ops::Deref for ChunkIdx {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

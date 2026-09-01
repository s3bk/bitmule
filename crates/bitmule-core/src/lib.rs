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

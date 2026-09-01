use serde::{Deserialize, Serialize};

/// Chunk identity within a session: (file_idx, chunk_idx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId {
    pub file_idx: u32,
    pub chunk_idx: u32,
}

/// Header prepended to each encrypted chunk on wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHeader {
    pub id: ChunkId,
    /// Total chunks in this file (for progress).
    pub total_in_file: u32,
    /// Nonce for AEAD (per-chunk).
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 12],
}

/// Encrypted chunk payload as bytes-on-the-wire.
#[derive(Debug, Clone)]
pub struct ChunkPayload {
    pub header: ChunkHeader,
    pub ciphertext: Vec<u8>,
}

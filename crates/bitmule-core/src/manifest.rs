use serde::{Deserialize, Serialize};

/// Chunk size in bytes. Adaptive at manifest-creation time based on total size.
///
/// - `< 100MB`  → 256 KiB
/// - `< 10GB`   → 1 MiB
/// - `>= 10GB`  → 4 MiB
///
/// When both peers negotiate a LAN-direct ICE candidate pair, chunk size can
/// be bumped further (see protocol renegotiation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChunkSize {
    // chunk size = 1 << power
    power: u8,
}

impl ChunkSize {
    pub fn from_total(total_bytes: u64) -> Self {
        const MIN: u32 = 10; // 1kB chunks
        const MAX: u32 = 20; // 1MB chunks

        let size_power = 63 - total_bytes.leading_zeros().min(63);
        let chunk_power = size_power.saturating_sub(5);
        ChunkSize { power: chunk_power.clamp(MIN, MAX) as u8 }
    }
    pub fn size(&self) -> u64 {
        1u64 << self.power
    }
    pub fn num_chunks(&self, bytes: u64) -> u32 {
        ((bytes + self.size() - 1) >> self.power) as u32
    }
}

/// A file within a transfer, identified by its ordinal index in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub file_idx: u32,
    /// Path relative to the transfer root (folders preserved).
    pub path: String,
    /// Total size in bytes.
    pub size: u64,
    /// Blake3 hash of the full file (streamed during transfer, verified post).
    #[serde(with = "serde_bytes")]
    pub blake3: [u8; 32],
}

/// Transfer-level manifest. Sent first, then chunks stream in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub session_id: String,
    pub chunk_size: ChunkSize,
    pub files: Vec<FileEntry>,
    pub total_bytes: u64,
    /// Base64 of the wrapped K_content, if the sender password-protected payload.
    pub wrapped_content_key: Option<String>,
}

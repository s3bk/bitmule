//! fountain-demo-v2 — RaptorQ block-fountain over UDP with disk-backed
//! receiver state and reverse-channel progress reporting.
//!
//! Two-binary split: `fountain-send` and `fountain-recv`. Wire is UDP unicast
//! so both PIDs run real network code and can be profiled independently.
//!
//! Receiver persists per-block symbol logs (append-only) plus a small header
//! per block. On restart the receiver replays each in-progress block's
//! symbols into a fresh decoder and resumes. Sender persists a tiny map of
//! per-block cursors so restarts pick up where the last progress packet left.
//!
//! All disk I/O uses `tokio::fs` so the shape stays io_uring-ready — no
//! mmap. RAM peak = one block on both sides.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Fixed symbol size for the demo. RFC 6330 supports up to 65 535 bytes; 8 kB
/// is the sweet spot for K ≈ 1 000 – 4 000 per fountain.md's guidance.
pub const DEFAULT_SYMBOL_SIZE: u16 = 8 * 1024;

/// Overhead factor applied on top of K when the sender decides how many
/// repair symbols to emit per block before waiting for progress feedback.
/// RaptorQ decodes with ~2 % overhead in practice, so 2×K is generous.
pub const DEFAULT_OVERHEAD_FACTOR: u32 = 2;

/// Progress packets go out at this cadence from the receiver when no
/// completion event fires. On block-decoded we also emit immediately.
pub const DEFAULT_PROGRESS_TICK_MS: u64 = 100;

/// Wire frame types on the byte 0 of every UDP packet.
pub const PROTO_DATA: u8 = 0x01;
pub const PROTO_PROGRESS: u8 = 0x02;
pub const PROTO_HELLO: u8 = 0x03;

/// Block-size table from docs/fountain.md — chosen to keep K in the range
/// where the RaptorQ solver overhead is lowest and most predictable.
///
/// | File size          | Block size |
/// |--------------------|------------|
/// | <  100 MB          |    4 MB    |
/// | 100 MB – 10 GB     |   16 MB    |
/// | > 10 GB            |   32 MB    |
///
/// Symbol size fixed at 8 kB, so K = block_size / symbol_size.
pub fn block_size_for(file_len: u64) -> u32 {
    if file_len < 100 * 1024 * 1024 {
        4 * 1024 * 1024
    } else if file_len < 10 * 1024 * 1024 * 1024 {
        16 * 1024 * 1024
    } else {
        32 * 1024 * 1024
    }
}

/// Global transfer manifest — written by the sender at startup, mirrored to
/// the receiver during the HELLO handshake and stored under
/// `<state>/manifest.json` on both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub file_len: u64,
    pub block_size: u32,
    pub symbol_size: u16,
    pub num_blocks: u32,
    /// Expected sha256 of the whole input file — receiver verifies its output.
    pub sha256_expected: [u8; 32],
}

impl Manifest {
    pub fn from_file_len(file_len: u64, block_size: u32, symbol_size: u16, sha256_expected: [u8; 32]) -> Self {
        let bs = block_size as u64;
        let num_blocks = ((file_len + bs - 1) / bs) as u32;
        Self { file_len, block_size, symbol_size, num_blocks, sha256_expected }
    }

    pub fn this_block_size(&self, block_idx: u32) -> usize {
        let block_start = block_idx as u64 * self.block_size as u64;
        let remaining = self.file_len.saturating_sub(block_start);
        remaining.min(self.block_size as u64) as usize
    }

    pub async fn save_to(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        tokio::fs::write(path, bytes).await?;
        Ok(())
    }

    pub async fn load_from(path: &Path) -> Result<Self> {
        let bytes = tokio::fs::read(path).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Wire framing for the forward channel (sender → receiver).
///
/// `[proto:u8=DATA][block_idx:u32le][coded_id:u32le][payload_len:u16le][payload...]`
///
/// The receiver forwards the payload verbatim into `RaptorQDecoder::add_coded_vector`.
pub fn encode_data_frame(buf: &mut Vec<u8>, block_idx: u32, coded_id: u32, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize { bail!("payload too big for u16 len") }
    buf.clear();
    buf.push(PROTO_DATA);
    buf.extend_from_slice(&block_idx.to_le_bytes());
    buf.extend_from_slice(&coded_id.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

/// Parse a forward DATA frame. Returns (block_idx, coded_id, &payload).
pub fn decode_data_frame(frame: &[u8]) -> Result<(u32, u32, &[u8])> {
    if frame.len() < 1 + 4 + 4 + 2 { bail!("data frame too short") }
    if frame[0] != PROTO_DATA { bail!("wrong proto byte") }
    let block_idx = u32::from_le_bytes(frame[1..5].try_into().unwrap());
    let coded_id = u32::from_le_bytes(frame[5..9].try_into().unwrap());
    let plen = u16::from_le_bytes(frame[9..11].try_into().unwrap()) as usize;
    if frame.len() < 11 + plen { bail!("truncated payload") }
    Ok((block_idx, coded_id, &frame[11..11 + plen]))
}

/// Wire framing for the reverse channel (receiver → sender).
///
/// `[proto:u8=PROGRESS][num_blocks:u32le][per block: (block_idx:u32le, symbols_received:u32le, decoded:u8)]`
///
/// Emitted on a fixed tick and on every block-decoded event. Sender uses this
/// to stop emitting for decoded blocks and bias the tail.
#[derive(Debug, Clone, Copy)]
pub struct BlockProgress {
    pub block_idx: u32,
    pub symbols_received: u32,
    pub decoded: bool,
}

pub fn encode_progress_frame(buf: &mut Vec<u8>, blocks: &[BlockProgress]) {
    buf.clear();
    buf.push(PROTO_PROGRESS);
    buf.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for b in blocks {
        buf.extend_from_slice(&b.block_idx.to_le_bytes());
        buf.extend_from_slice(&b.symbols_received.to_le_bytes());
        buf.push(if b.decoded { 1 } else { 0 });
    }
}

pub fn decode_progress_frame(frame: &[u8]) -> Result<Vec<BlockProgress>> {
    if frame.len() < 1 + 4 { bail!("progress frame too short") }
    if frame[0] != PROTO_PROGRESS { bail!("wrong proto byte") }
    let n = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
    let per_block = 4 + 4 + 1;
    if frame.len() < 5 + n * per_block { bail!("truncated progress body") }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let base = 5 + i * per_block;
        out.push(BlockProgress {
            block_idx: u32::from_le_bytes(frame[base..base+4].try_into().unwrap()),
            symbols_received: u32::from_le_bytes(frame[base+4..base+8].try_into().unwrap()),
            decoded: frame[base+8] != 0,
        });
    }
    Ok(out)
}

/// HELLO packet sender → receiver on session bootstrap so the receiver can
/// initialise its state layout without needing an out-of-band manifest.
///
/// `[proto:u8=HELLO][manifest_len:u32le][manifest_json bytes]`
pub fn encode_hello_frame(buf: &mut Vec<u8>, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    buf.clear();
    buf.push(PROTO_HELLO);
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&bytes);
    Ok(())
}

pub fn decode_hello_frame(frame: &[u8]) -> Result<Manifest> {
    if frame.len() < 1 + 4 { bail!("hello too short") }
    if frame[0] != PROTO_HELLO { bail!("wrong proto byte") }
    let n = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
    if frame.len() < 5 + n { bail!("truncated hello body") }
    Ok(serde_json::from_slice(&frame[5..5+n])?)
}

/// Small utility — sha256 a file by streaming it through 64 kB buffers via
/// async I/O. Used for both the sender's initial expected-hash and the
/// receiver's final integrity check.
pub async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

// -------- Per-side state persistence --------

/// Sender-side per-block cursor. Small — one row per block.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SenderBlockState {
    /// Next encoding symbol id (ESI) to emit for this block on the next
    /// round-robin visit. RaptorQ coded_ids are unbounded — we can keep
    /// generating repair symbols indefinitely if the receiver keeps asking.
    pub next_esi: u32,
    /// Set true when the receiver reports the block decoded. Sender stops
    /// emitting for it after the next progress-round.
    pub decoded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderState {
    pub manifest: Manifest,
    pub dest_addr: String,
    /// Vec index = block_idx. Length = manifest.num_blocks.
    pub blocks: Vec<SenderBlockState>,
}

impl SenderState {
    pub fn new_from(manifest: Manifest, dest_addr: String) -> Self {
        let blocks = vec![SenderBlockState::default(); manifest.num_blocks as usize];
        Self { manifest, dest_addr, blocks }
    }

    /// Atomic write: temp file + rename, so a crash mid-write cannot corrupt.
    pub async fn save_atomic(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(&tmp, path).await?;
        Ok(())
    }

    pub async fn load(path: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&tokio::fs::read(path).await?)?)
    }
}

/// Receiver-side per-block header. Companion to the append-only symbols.log
/// under `<state>/block-<idx>/`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverBlockHeader {
    pub block_idx: u32,
    /// K, i.e. number of source symbols this block requires to decode. This
    /// is derived from `manifest.this_block_size` / symbol_size but stored
    /// explicitly so recovery doesn't have to re-derive.
    pub k_source: u32,
    /// Number of symbols in symbols.log — recomputed on restart by scanning.
    pub num_received: u32,
    pub decoded: bool,
}

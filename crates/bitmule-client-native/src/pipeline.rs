//! Send + receive data pipelines per Seb 2026-09-03: zstd in one
//! dedicated thread, AEAD in another. Reader/writer stay async in
//! their own tokio tasks and feed the pipelines via tokio mpsc.
//!
//! ## Send pipeline (compress → encrypt)
//!
//! ```text
//!   caller.push(idx, raw_bytes)
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   ┌─ compress thread ─┐
//!   │ zstd::encode(raw) │  (skipped if !use_compression)
//!   └───────┬───────────┘
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   ┌─ encrypt thread ──────────────────────────────────┐
//!   │ frame  = [u32 len][compressed_bytes][zero pad]    │
//!   │ ct     = AES-256-GCM(B, nonce_from_idx, frame)    │
//!   └───────┬───────────────────────────────────────────┘
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   caller.next() → Result<(idx, ciphertext)>
//! ```
//!
//! ## Receive pipeline (decrypt → decompress)
//!
//! ```text
//!   caller.push(idx, ciphertext)
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   ┌─ decrypt thread ─────────────────────────────────┐
//!   │ frame       = AES-256-GCM-open(B, nonce, ct)     │
//!   │ len         = u32 prefix                          │
//!   │ compressed  = frame[4 .. 4+len]                   │
//!   └───────┬──────────────────────────────────────────┘
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   ┌─ decompress thread ─┐
//!   │ zstd::decode(comp)  │  (skipped if !use_compression)
//!   └───────┬─────────────┘
//!         │
//!         ▼    (tokio::sync::mpsc, bounded)
//!   caller.next() → Result<(idx, plaintext)>
//! ```
//!
//! Both pipelines maintain per-stage backpressure via bounded channels
//! (capacity chosen to keep threads fed without unbounded memory growth).
//! Threads exit cleanly when the input channel closes.

use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex};

use crate::crypto::BulkKey;

const STAGE_QUEUE: usize = 4;
/// How many buffers a pool pre-allocates. Chosen so all in-flight
/// buffers across the pipeline (reader queue + 2 stage queues + caller
/// downstream) can be served without falling back to on-the-fly
/// allocation. STAGE_QUEUE (4) × 3 hops + slack.
pub const POOL_DEFAULT_COUNT: usize = 16;

/// Shared bounded buffer pool. Callers rent a Vec<u8> to write into,
/// return it after consumption so it circulates. Backpressure is
/// natural: if the pool is drained, `rent`/`rent_blocking` waits
/// until a buffer is returned.
///
/// Bytes are cleared on rent (not on return) so returned buffers
/// don't linger with sensitive plaintext / ciphertext in memory
/// longer than needed. Capacity is preserved across rent-cycles so
/// no re-allocation happens.
///
/// Sharing shape: `Arc<BufferPool>`. Both async tasks and std::thread
/// workers use it — async uses `rent`/`return_buf`, threads use
/// `rent_blocking`/`return_buf_blocking`. `tokio::sync::Mutex::blocking_lock`
/// works from plain threads (does NOT work from inside a spawned tokio
/// task, so async callers stick to the async path).
pub struct BufferPool {
    rent_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    ret_tx: mpsc::Sender<Vec<u8>>,
    capacity: usize,
}

impl BufferPool {
    /// Pre-allocate `count` buffers of `capacity` each. All buffers
    /// start in the pool ready to rent.
    pub fn new(count: usize, capacity: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(count);
        for _ in 0..count {
            let _ = tx.try_send(Vec::with_capacity(capacity));
        }
        Arc::new(Self { rent_rx: Mutex::new(rx), ret_tx: tx, capacity })
    }

    pub fn capacity(&self) -> usize { self.capacity }

    /// Async rent — waits until a buffer is available.
    pub async fn rent(&self) -> Vec<u8> {
        let mut guard = self.rent_rx.lock().await;
        let mut buf = guard.recv().await.unwrap_or_else(|| Vec::with_capacity(self.capacity));
        buf.clear();
        buf
    }

    /// Blocking rent for use from std::thread workers. Never call from
    /// inside a tokio task.
    pub fn rent_blocking(&self) -> Vec<u8> {
        let mut guard = self.rent_rx.blocking_lock();
        let mut buf = guard.blocking_recv().unwrap_or_else(|| Vec::with_capacity(self.capacity));
        buf.clear();
        buf
    }

    /// Return a buffer to the pool. Non-blocking; if the pool is full
    /// (shouldn't happen — count is bounded and matches rents), the
    /// buffer is silently dropped.
    pub fn return_buf(&self, buf: Vec<u8>) {
        let _ = self.ret_tx.try_send(buf);
    }
}

// ------------------------------------------------------------------ send

/// Send-side pipeline: raw file chunks in → ciphertext chunks out.
/// Zstd and AEAD each get their own thread; both are CPU-bound so
/// running them concurrently on separate cores overlaps compress-of-N+1
/// with encrypt-of-N.
pub struct SendPipeline {
    raw_tx: Option<mpsc::Sender<(u64, Vec<u8>)>>,
    ct_rx: mpsc::Receiver<Result<(u64, Vec<u8>)>>,
    _compress: JoinHandle<()>,
    _encrypt: JoinHandle<()>,
}

impl SendPipeline {
    /// Kick off the two worker threads. `chunk_wire_bytes` is the fixed
    /// padded frame size (16 KiB DC, 1 MiB relay) — every emitted
    /// ciphertext will be `chunk_wire_bytes + AEAD_TAG` (16) bytes.
    pub fn start(file_key: Arc<BulkKey>, chunk_wire_bytes: usize, use_compression: bool) -> Self {
        let (raw_tx, mut raw_rx) = mpsc::channel::<(u64, Vec<u8>)>(STAGE_QUEUE);
        let (comp_tx, mut comp_rx) = mpsc::channel::<(u64, Vec<u8>)>(STAGE_QUEUE);
        let (ct_tx, ct_rx) = mpsc::channel::<Result<(u64, Vec<u8>)>>(STAGE_QUEUE);

        let compress = std::thread::spawn(move || {
            while let Some((idx, raw)) = raw_rx.blocking_recv() {
                let out = if use_compression {
                    match zstd::stream::encode_all(&raw[..], 3) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = comp_tx.blocking_send((idx, raw));
                            tracing::warn!("zstd chunk {idx} failed ({e}) — passing raw through");
                            continue;
                        }
                    }
                } else {
                    raw
                };
                if comp_tx.blocking_send((idx, out)).is_err() { break; }
            }
        });

        let encrypt = std::thread::spawn(move || {
            let key = file_key;
            let frame_bytes = chunk_wire_bytes;
            while let Some((idx, compressed)) = comp_rx.blocking_recv() {
                if compressed.len() + 4 > frame_bytes {
                    let _ = ct_tx.blocking_send(Err(anyhow!(
                        "chunk {idx} compressed to {} bytes, exceeds frame budget {} (4-byte len prefix + payload)",
                        compressed.len(), frame_bytes - 4
                    )));
                    break;
                }
                let mut frame = vec![0u8; frame_bytes];
                let len = compressed.len() as u32;
                frame[..4].copy_from_slice(&len.to_le_bytes());
                frame[4..4 + compressed.len()].copy_from_slice(&compressed);
                match key.encrypt_chunk(idx, &frame) {
                    Ok(ct) => {
                        if ct_tx.blocking_send(Ok((idx, ct))).is_err() { break; }
                    }
                    Err(e) => {
                        let _ = ct_tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
        });

        Self { raw_tx: Some(raw_tx), ct_rx, _compress: compress, _encrypt: encrypt }
    }

    /// Feed the next raw chunk into the pipeline. Applies backpressure
    /// via the bounded input channel.
    pub async fn push(&self, idx: u64, raw: Vec<u8>) -> Result<()> {
        let tx = self.raw_tx.as_ref()
            .ok_or_else(|| anyhow!("send pipeline input closed"))?;
        tx.send((idx, raw)).await
            .map_err(|_| anyhow!("compress thread exited"))
    }

    /// Signal that no more raw chunks will be pushed. Downstream stages
    /// drain their queues, encrypt the tail, then exit.
    pub fn close_input(&mut self) { self.raw_tx.take(); }

    /// Pull the next ciphertext chunk from the pipeline. Returns None
    /// after `close_input()` and both worker threads have drained.
    pub async fn next(&mut self) -> Option<Result<(u64, Vec<u8>)>> {
        self.ct_rx.recv().await
    }
}

// ---------------------------------------------------------------- recv

/// Receive-side pipeline: ciphertext chunks in → plaintext chunks out.
pub struct RecvPipeline {
    ct_tx: Option<mpsc::Sender<(u64, Vec<u8>)>>,
    pt_rx: mpsc::Receiver<Result<(u64, Vec<u8>)>>,
    _decrypt: JoinHandle<()>,
    _decompress: JoinHandle<()>,
}

impl RecvPipeline {
    pub fn start(file_key: Arc<BulkKey>, chunk_wire_bytes: usize, use_compression: bool) -> Self {
        let (ct_tx, mut ct_rx) = mpsc::channel::<(u64, Vec<u8>)>(STAGE_QUEUE);
        let (comp_tx, mut comp_rx) = mpsc::channel::<Result<(u64, Vec<u8>)>>(STAGE_QUEUE);
        let (pt_tx, pt_rx) = mpsc::channel::<Result<(u64, Vec<u8>)>>(STAGE_QUEUE);

        let decrypt = std::thread::spawn(move || {
            let key = file_key;
            let frame_bytes = chunk_wire_bytes;
            while let Some((idx, ct)) = ct_rx.blocking_recv() {
                let frame = match key.decrypt_chunk(idx, &ct) {
                    Ok(pt) => pt,
                    Err(e) => {
                        let _ = comp_tx.blocking_send(Err(e));
                        break;
                    }
                };
                if frame.len() != frame_bytes {
                    let _ = comp_tx.blocking_send(Err(anyhow!(
                        "chunk {idx} decrypted to {} bytes, expected padded frame of {}",
                        frame.len(), frame_bytes
                    )));
                    break;
                }
                let mut lenb = [0u8; 4];
                lenb.copy_from_slice(&frame[..4]);
                let len = u32::from_le_bytes(lenb) as usize;
                if len + 4 > frame.len() {
                    let _ = comp_tx.blocking_send(Err(anyhow!(
                        "chunk {idx} length prefix {} exceeds frame ({} bytes)",
                        len, frame.len()
                    )));
                    break;
                }
                let compressed = frame[4..4 + len].to_vec();
                if comp_tx.blocking_send(Ok((idx, compressed))).is_err() { break; }
            }
        });

        let decompress = std::thread::spawn(move || {
            while let Some(msg) = comp_rx.blocking_recv() {
                let (idx, compressed) = match msg {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = pt_tx.blocking_send(Err(e));
                        break;
                    }
                };
                let out = if use_compression {
                    match zstd::stream::decode_all(&compressed[..]) {
                        Ok(d) => d,
                        Err(e) => {
                            let _ = pt_tx.blocking_send(Err(anyhow!("zstd decode chunk {idx}: {e}")));
                            break;
                        }
                    }
                } else {
                    compressed
                };
                if pt_tx.blocking_send(Ok((idx, out))).is_err() { break; }
            }
        });

        Self { ct_tx: Some(ct_tx), pt_rx, _decrypt: decrypt, _decompress: decompress }
    }

    pub async fn push(&self, idx: u64, ct: Vec<u8>) -> Result<()> {
        let tx = self.ct_tx.as_ref()
            .ok_or_else(|| anyhow!("recv pipeline input closed"))?;
        tx.send((idx, ct)).await
            .map_err(|_| anyhow!("decrypt thread exited"))
    }

    pub fn close_input(&mut self) { self.ct_tx.take(); }

    pub async fn next(&mut self) -> Option<Result<(u64, Vec<u8>)>> {
        self.pt_rx.recv().await
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip_one(compression: bool) {
        let key = Arc::new(BulkKey::random());
        let frame = 4096usize;
        let mut send = SendPipeline::start(key.clone(), frame, compression);
        let mut recv = RecvPipeline::start(key.clone(), frame, compression);

        let payload_0 = vec![0xABu8; 200];
        let payload_1 = vec![0x5Au8; 3500];
        send.push(0, payload_0.clone()).await.unwrap();
        send.push(1, payload_1.clone()).await.unwrap();
        send.close_input();

        let mut cts = Vec::new();
        while let Some(item) = send.next().await { cts.push(item.unwrap()); }
        assert_eq!(cts.len(), 2);

        for (idx, ct) in cts { recv.push(idx, ct).await.unwrap(); }
        recv.close_input();

        let mut pts = Vec::new();
        while let Some(item) = recv.next().await { pts.push(item.unwrap()); }
        pts.sort_by_key(|(i, _)| *i);
        assert_eq!(pts[0].1, payload_0);
        assert_eq!(pts[1].1, payload_1);
    }

    #[tokio::test]
    async fn roundtrip_compressed() { roundtrip_one(true).await; }

    #[tokio::test]
    async fn roundtrip_uncompressed() { roundtrip_one(false).await; }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let key = Arc::new(BulkKey::random());
        let frame = 4096usize;
        let mut send = SendPipeline::start(key.clone(), frame, false);
        let mut recv = RecvPipeline::start(key.clone(), frame, false);

        send.push(0, vec![1u8; 200]).await.unwrap();
        send.close_input();
        let (idx, mut ct) = send.next().await.unwrap().unwrap();
        assert!(send.next().await.is_none());

        // Flip one byte
        ct[0] ^= 0x80;
        recv.push(idx, ct).await.unwrap();
        recv.close_input();
        assert!(recv.next().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn buffer_pool_rent_return_cycles() {
        let pool = BufferPool::new(2, 1024);
        let a = pool.rent().await;
        let b = pool.rent().await;
        assert_eq!(a.capacity(), 1024);
        assert_eq!(a.len(), 0);
        pool.return_buf(a);
        let c = pool.rent().await;
        assert_eq!(c.capacity(), 1024);
        pool.return_buf(b);
        pool.return_buf(c);
    }

    #[test]
    fn buffer_pool_rent_blocking_from_std_thread() {
        let pool = BufferPool::new(2, 512);
        let pool_c = pool.clone();
        let t = std::thread::spawn(move || {
            let buf = pool_c.rent_blocking();
            assert_eq!(buf.capacity(), 512);
            pool_c.return_buf(buf);
        });
        t.join().unwrap();
    }

    #[tokio::test]
    async fn oversized_chunk_errors() {
        let key = Arc::new(BulkKey::random());
        let frame = 512usize;
        let mut send = SendPipeline::start(key, frame, false);
        // 600 bytes of raw + 4 byte len prefix = 604 > 512 frame budget
        send.push(0, vec![0xFFu8; 600]).await.unwrap();
        send.close_input();
        assert!(send.next().await.unwrap().is_err());
    }
}

// -- silence Send warning on BulkKey Arc share ----
// Arc<BulkKey> requires BulkKey: Send + Sync. BulkKey is [u8; 32] +
// ZeroizeOnDrop-shape — auto-Send + auto-Sync. Compiler infers.
fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<Arc<BulkKey>>();
    is_send_sync::<SendPipeline>();
    is_send_sync::<RecvPipeline>();
}

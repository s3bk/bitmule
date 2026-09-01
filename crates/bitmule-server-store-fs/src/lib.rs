//! Filesystem-backed ChunkStore impl for bitmule-server.
//!
//! Layout under root:
//!
//! ```text
//! <root>/
//!   <session_id>/
//!     config.json                # quota, receivers, created_at
//!     chunks/
//!       <chunk_idx>.chunk        # encrypted chunk bytes (K_session)
//!     delivered.jsonl            # append-only ledger of (chunk_idx, receiver_id)
//! ```
//!
//! - `put` writes atomically via .tmp + rename.
//! - `have` scans chunks/ directory names.
//! - `capacity_available` subtracts current total-bytes from the session quota.
//! - `mark_delivered` appends a line to delivered.jsonl.
//! - `gc_delivered` deletes chunks whose delivered-set covers ALL configured receivers.
//! - `evict_older_than` deletes chunks whose mtime is older than the threshold.

use bitmule_core::{traits::ChunkStore, ChunkBitmap, Error, ReceiverId, Result, SessionId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::Mutex,
};

/// Default per-session quota if not specified in config.json.
pub const DEFAULT_SESSION_QUOTA_BYTES: u64 = 100 * 1024 * 1024 * 1024; // 100 GB

fn io_err(e: io::Error) -> Error {
    Error::Io(e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub quota_bytes: u64,
    pub receivers: Vec<ReceiverId>,
    pub created_unix: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            quota_bytes: DEFAULT_SESSION_QUOTA_BYTES,
            receivers: Vec::new(),
            created_unix: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// Filesystem-backed ChunkStore.
pub struct FsChunkStore {
    root: PathBuf,
    /// Per-session delivery-ledger write mutex to serialize appenders.
    /// Keyed on the raw 32-byte id so we never round-trip through untrusted strings.
    session_locks: Mutex<HashMap<[u8; 32], std::sync::Arc<Mutex<()>>>>,
}

impl FsChunkStore {
    pub fn new<P: Into<PathBuf>>(root: P) -> Self {
        Self {
            root: root.into(),
            session_locks: Mutex::new(HashMap::new()),
        }
    }

    async fn session_dir(&self, session: &SessionId) -> PathBuf {
        // Hex encoding of a fixed 32-byte id: no `..`, no `/`, no NUL, no
        // unicode surprises. The type system makes path traversal
        // unrepresentable at this boundary.
        self.root.join(session.as_hex())
    }

    async fn chunks_dir(&self, session: &SessionId) -> PathBuf {
        self.session_dir(session).await.join("chunks")
    }

    async fn config_path(&self, session: &SessionId) -> PathBuf {
        self.session_dir(session).await.join("config.json")
    }

    async fn delivered_path(&self, session: &SessionId) -> PathBuf {
        self.session_dir(session).await.join("delivered.jsonl")
    }

    async fn ensure_session_dirs(&self, session: &SessionId) -> Result<()> {
        let cdir = self.chunks_dir(session).await;
        fs::create_dir_all(&cdir).await.map_err(io_err)?;
        let cfg_path = self.config_path(session).await;
        if fs::metadata(&cfg_path).await.is_err() {
            let cfg = SessionConfig::default();
            let bytes = serde_json::to_vec_pretty(&cfg)
                .map_err(|e| Error::Io(e.to_string()))?;
            fs::write(&cfg_path, bytes).await.map_err(io_err)?;
        }
        Ok(())
    }

    async fn read_config(&self, session: &SessionId) -> Result<SessionConfig> {
        let p = self.config_path(session).await;
        match fs::read(&p).await {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| Error::Io(e.to_string())),
            Err(_) => Ok(SessionConfig::default()),
        }
    }

    /// Get or create the per-session write lock.
    async fn lock_for(&self, session: &SessionId) -> std::sync::Arc<Mutex<()>> {
        let mut map = self.session_locks.lock().await;
        map.entry(session.0)
            .or_insert_with(|| std::sync::Arc::new(Mutex::new(())))
            .clone()
    }

    fn chunk_path(&self, chunks_dir: &Path, chunk_idx: u32) -> PathBuf {
        chunks_dir.join(format!("{}.chunk", chunk_idx))
    }

    /// Sum on-disk chunk bytes for this session.
    async fn total_bytes_used(&self, session: &SessionId) -> Result<u64> {
        let cdir = self.chunks_dir(session).await;
        if fs::metadata(&cdir).await.is_err() {
            return Ok(0);
        }
        let mut total = 0u64;
        let mut rd = fs::read_dir(&cdir).await.map_err(io_err)?;
        while let Some(entry) = rd.next_entry().await.map_err(io_err)? {
            if let Ok(md) = entry.metadata().await {
                if md.is_file() {
                    total += md.len();
                }
            }
        }
        Ok(total)
    }
}

#[async_trait]
impl ChunkStore for FsChunkStore {
    async fn put(&self, session: &SessionId, chunk_idx: u32, ciphertext: &[u8]) -> Result<()> {
        self.ensure_session_dirs(session).await?;
        let cdir = self.chunks_dir(session).await;
        let final_path = self.chunk_path(&cdir, chunk_idx);
        let tmp_path = final_path.with_extension("chunk.tmp");
        {
            let mut f = fs::File::create(&tmp_path).await.map_err(io_err)?;
            f.write_all(ciphertext).await.map_err(io_err)?;
            f.sync_all().await.map_err(io_err)?;
        }
        fs::rename(&tmp_path, &final_path).await.map_err(io_err)?;
        Ok(())
    }

    async fn get(&self, session: &SessionId, chunk_idx: u32) -> Result<Option<Vec<u8>>> {
        let cdir = self.chunks_dir(session).await;
        let path = self.chunk_path(&cdir, chunk_idx);
        match fs::read(&path).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    async fn have(&self, session: &SessionId) -> Result<ChunkBitmap> {
        let mut bitmap = ChunkBitmap::new();
        let cdir = self.chunks_dir(session).await;
        if fs::metadata(&cdir).await.is_err() {
            return Ok(bitmap);
        }
        let mut rd = fs::read_dir(&cdir).await.map_err(io_err)?;
        while let Some(entry) = rd.next_entry().await.map_err(io_err)? {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if let Some(stem) = s.strip_suffix(".chunk") {
                if let Ok(idx) = stem.parse::<u32>() {
                    bitmap.set(idx);
                }
            }
        }
        Ok(bitmap)
    }

    async fn capacity_available(&self, session: &SessionId) -> Result<u64> {
        let cfg = self.read_config(session).await?;
        let used = self.total_bytes_used(session).await?;
        Ok(cfg.quota_bytes.saturating_sub(used))
    }

    async fn mark_delivered(
        &self,
        session: &SessionId,
        chunk_idx: u32,
        receiver: &ReceiverId,
    ) -> Result<()> {
        self.ensure_session_dirs(session).await?;
        let lock = self.lock_for(session).await;
        let _guard = lock.lock().await;
        let path = self.delivered_path(session).await;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(io_err)?;
        let line = format!("{}\t{}\n", chunk_idx, receiver.as_hex());
        f.write_all(line.as_bytes()).await.map_err(io_err)?;
        f.sync_all().await.map_err(io_err)?;
        Ok(())
    }

    async fn gc_delivered(&self) -> Result<u64> {
        let mut freed = 0u64;
        let mut rd = match fs::read_dir(&self.root).await {
            Ok(r) => r,
            Err(_) => return Ok(0),
        };
        while let Some(sess_entry) = rd.next_entry().await.map_err(io_err)? {
            if !sess_entry
                .metadata()
                .await
                .map_err(io_err)?
                .is_dir()
            {
                continue;
            }
            // Directory names must be valid hex session ids. Anything else is
            // either stray fs debris or an active traversal attempt; either
            // way, silently skip it.
            let dir_name = sess_entry.file_name();
            let name_str = match dir_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let session_id = match SessionId::from_hex(name_str) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let cfg = self.read_config(&session_id).await?;
            if cfg.receivers.is_empty() {
                continue;
            }
            let all_recv: HashSet<[u8; 32]> = cfg.receivers.iter().map(|r| r.0).collect();
            // Read delivered.jsonl and group by chunk_idx
            let delivered_path = self.delivered_path(&session_id).await;
            let mut per_chunk: HashMap<u32, HashSet<[u8; 32]>> = HashMap::new();
            if let Ok(f) = fs::File::open(&delivered_path).await {
                let mut lines = BufReader::new(f).lines();
                while let Some(line) = lines.next_line().await.map_err(io_err)? {
                    let mut it = line.splitn(2, '\t');
                    let idx: u32 = match it.next().and_then(|s| s.parse().ok()) {
                        Some(v) => v,
                        None => continue,
                    };
                    let rid = match it.next().and_then(|s| ReceiverId::from_hex(s).ok()) {
                        Some(r) => r.0,
                        None => continue,
                    };
                    per_chunk.entry(idx).or_default().insert(rid);
                }
            }
            let cdir = self.chunks_dir(&session_id).await;
            for (chunk_idx, delivered_set) in per_chunk {
                if delivered_set.is_superset(&all_recv) {
                    let cp = self.chunk_path(&cdir, chunk_idx);
                    if let Ok(md) = fs::metadata(&cp).await {
                        let sz = md.len();
                        if fs::remove_file(&cp).await.is_ok() {
                            freed += sz;
                        }
                    }
                }
            }
        }
        Ok(freed)
    }

    async fn evict_older_than(&self, threshold: Duration) -> Result<u64> {
        let mut evicted = 0u64;
        let cutoff = SystemTime::now()
            .checked_sub(threshold)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut rd = match fs::read_dir(&self.root).await {
            Ok(r) => r,
            Err(_) => return Ok(0),
        };
        while let Some(sess_entry) = rd.next_entry().await.map_err(io_err)? {
            let sess_path = sess_entry.path();
            let cdir = sess_path.join("chunks");
            if fs::metadata(&cdir).await.is_err() {
                continue;
            }
            let mut chunk_rd = fs::read_dir(&cdir).await.map_err(io_err)?;
            while let Some(entry) = chunk_rd.next_entry().await.map_err(io_err)? {
                let md = entry.metadata().await.map_err(io_err)?;
                if !md.is_file() {
                    continue;
                }
                if let Ok(mtime) = md.modified() {
                    if mtime < cutoff {
                        let sz = md.len();
                        if fs::remove_file(entry.path()).await.is_ok() {
                            evicted += sz;
                        }
                    }
                }
            }
        }
        Ok(evicted)
    }
}

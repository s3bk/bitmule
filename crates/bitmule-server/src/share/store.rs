//! Durable storage for shares and invites.
//!
//! Layout under the store root:
//!
//! ```text
//! shares/<sid>/meta.json       the share's file rows and counters
//! shares/<sid>/<uid>.bin       one file's ciphertext, exactly as uploaded
//! invites/<iid>/meta.json      the invite's caps and the items received
//! invites/<iid>/uploads/<uid>.bin
//! invites/by_granter/<hex>     one invite id per line: the granter's inbox index
//! usage.tsv                    egress, appended by the meter's hourly flush
//! ```
//!
//! Everything is streamed. An upload is copied body -> `<uid>.part` through
//! one fixed 256 KiB buffer and renamed into place only once the last byte is
//! on the platter, so a partial upload never looks like a finished one. The
//! part file has a name that does not change between requests, which is what
//! makes an upload resumable: the bytes that did arrive stay exactly where the
//! next request expects to append, and the offset to advertise is the part
//! file's length — no side table, no journal. A download is file -> body
//! through the same size of buffer, so serving a 4 GiB file costs the server
//! 256 KiB and no more.
//!
//! An upload is in exactly one of three states at any moment: nothing yet,
//! `<uid>.part` (in progress), or `<uid>.bin` (done). Restarting a finished
//! file therefore deletes it before the new part appears, so "in progress" and
//! "done" are never both true and no request has to guess which is authoritative.
//!
//! Metadata is written with write-to-temp + rename (`save_meta`), so a reader
//! never sees half a JSON document. Reads of one share are serialized by a
//! sharded lock: the shard is held across the read-modify-write of the
//! metadata, never across the payload copy.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use futures_util::StreamExt;
use tokio::io::{AsyncWriteExt, BufWriter};

/// The buffer an upload or download passes through. 256 KiB is large enough
/// that the syscall and stream overhead per byte is negligible and small
/// enough that a thousand concurrent transfers still fit in a few hundred MB.
pub const IO_BUFFER: usize = 256 * 1024;

pub const DEFAULT_SHARE_TTL: u64 = 7 * 86_400;
pub const DEFAULT_INVITE_TTL: u64 = 7 * 86_400;
pub const DEFAULT_INVITE_BYTES: u64 = 2 << 30;
pub const DEFAULT_INVITE_FILES: u64 = 32;

/// How long a download session minted by `POST …/session` is good for.
pub const SESSION_TTL: u64 = 900;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareState {
    #[default]
    Uploading,
    Live,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRow {
    pub uid: String,
    #[serde(default)]
    pub size: u64,
    /// What the uploader said the file would weigh, when it said anything.
    /// Only a hint for resuming — `size` is the number of bytes that arrived.
    #[serde(default)]
    pub declared: u64,
    #[serde(default)]
    pub name_enc: String,
    #[serde(default)]
    pub name_iv: String,
    #[serde(default)]
    pub wrapped_kf: String,
    #[serde(default)]
    pub kf_iv: String,
    #[serde(default)]
    pub ct_iv: String,
    #[serde(default)]
    pub uploaded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Share {
    pub sid: String,
    pub created: u64,
    pub expires: u64,
    /// hex sha256 of the auth key that a link's key derives. The key itself is
    /// never here, and never leaves the client.
    pub auth: String,
    #[serde(default)]
    pub state: ShareState,
    #[serde(default)]
    pub max_downloads: u64,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub files: Vec<FileRow>,
}

impl Share {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
    pub fn file(&self, uid: &str) -> Option<&FileRow> {
        self.files.iter().find(|f| f.uid == uid)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub uid: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub name_enc: String,
    #[serde(default)]
    pub name_iv: String,
    #[serde(default)]
    pub kf_enc: String,
    #[serde(default)]
    pub kf_iv: String,
    #[serde(default)]
    pub ct_iv: String,
    #[serde(default)]
    pub epk: String,
    pub created: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub iid: String,
    pub created: u64,
    pub expires: u64,
    pub auth: String,
    /// hex sha256 of the granter token, handed out once at creation.
    pub gt: String,
    #[serde(default)]
    pub pubkey: String,
    #[serde(default)]
    pub label: String,
    pub max_bytes: u64,
    pub max_files: u64,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub used_files: u64,
    #[serde(default)]
    pub one_time: bool,
    #[serde(default)]
    pub closed: bool,
    #[serde(default)]
    pub items: Vec<Item>,
}

impl Invite {
    pub fn remaining_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.used_bytes)
    }
}

/// What went wrong while receiving a body. `TooLarge` carries the cap that was
/// hit so the handler can say how much room was left; `Offset` carries the
/// offset the store actually holds, so the handler can tell the client where to
/// resume instead of making it start over.
#[derive(Debug)]
pub enum ReceiveError {
    TooLarge(u64),
    Offset { stored: u64 },
    Io(io::Error),
    Body(String),
}

impl From<io::Error> for ReceiveError {
    fn from(e: io::Error) -> Self {
        ReceiveError::Io(e)
    }
}

/// How far an upload got. `stored` is durable on disk; when `complete` is true
/// the bytes are also renamed into their final name and are servable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    pub stored: u64,
    pub complete: bool,
}

pub struct Store {
    root: PathBuf,
    /// Read-modify-write locks for metadata. Sharded rather than one per id: a
    /// map keyed by id would grow with every share ever made, and two shares
    /// hashing to the same shard only serialize their metadata writes, which
    /// take microseconds.
    locks: Box<[tokio::sync::Mutex<()>]>,
    /// Locks held for the length of an upload body, keyed by (share, file).
    /// Separate from `locks` and much finer, because a 4 GiB upload would
    /// otherwise own a 64th of all metadata traffic for minutes. An upload
    /// takes this lock and then, once the body is done, the metadata lock — one
    /// after the other, never both, so the two sets cannot deadlock.
    upload_locks: Box<[tokio::sync::Mutex<()>]>,
    tmp_seq: AtomicU64,
}

const LOCK_SHARDS: usize = 64;
const UPLOAD_SHARDS: usize = 1024;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store {
            root: root.into(),
            locks: (0..LOCK_SHARDS)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
            upload_locks: (0..UPLOAD_SHARDS)
                .map(|_| tokio::sync::Mutex::new(()))
                .collect(),
            tmp_seq: AtomicU64::new(0),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Serialize the metadata half of a request. Callers take it, load, mutate
    /// and save; payload bytes move outside the guard.
    pub async fn lock(&self, id: &str) -> tokio::sync::MutexGuard<'_, ()> {
        let idx = (fnv1a(id.as_bytes()) % LOCK_SHARDS as u64) as usize;
        self.locks[idx].lock().await
    }

    /// Serialize the whole of one file's upload, body included. Without this
    /// two requests could append to the same part at the same time and the
    /// second one's offset would be a lie.
    pub async fn lock_upload(&self, sid: &str, uid: &str) -> tokio::sync::MutexGuard<'_, ()> {
        // Hash the pair as one string, so two ids that differ only in where
        // the separator falls do not end up in the same shard.
        let mut key = String::with_capacity(sid.len() + uid.len() + 1);
        key.push_str(sid);
        key.push('/');
        key.push_str(uid);
        let idx = (fnv1a(key.as_bytes()) % UPLOAD_SHARDS as u64) as usize;
        self.upload_locks[idx].lock().await
    }

    pub fn share_dir(&self, sid: &str) -> PathBuf {
        self.root.join("shares").join(sid)
    }

    pub fn share_file(&self, sid: &str, uid: &str) -> PathBuf {
        self.share_dir(sid).join(format!("{uid}.bin"))
    }

    pub fn invite_dir(&self, iid: &str) -> PathBuf {
        self.root.join("invites").join(iid)
    }

    pub fn invite_file(&self, iid: &str, uid: &str) -> PathBuf {
        self.invite_dir(iid)
            .join("uploads")
            .join(format!("{uid}.bin"))
    }

    fn granter_index(&self, gt_hash: &str) -> PathBuf {
        self.root.join("invites").join("by_granter").join(gt_hash)
    }

    pub async fn load_share(&self, sid: &str) -> io::Result<Option<Share>> {
        Self::load_meta(&self.share_dir(sid).join("meta.json")).await
    }

    pub async fn save_share(&self, s: &Share) -> io::Result<()> {
        let dir = self.share_dir(&s.sid);
        tokio::fs::create_dir_all(&dir).await?;
        Self::save_meta(&dir.join("meta.json"), s, &self.tmp_seq).await
    }

    pub async fn remove_share(&self, sid: &str) -> io::Result<()> {
        match tokio::fs::remove_dir_all(self.share_dir(sid)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn load_invite(&self, iid: &str) -> io::Result<Option<Invite>> {
        Self::load_meta(&self.invite_dir(iid).join("meta.json")).await
    }

    pub async fn save_invite(&self, inv: &Invite) -> io::Result<()> {
        let dir = self.invite_dir(&inv.iid);
        tokio::fs::create_dir_all(&dir).await?;
        Self::save_meta(&dir.join("meta.json"), inv, &self.tmp_seq).await
    }

    /// Record that `iid` belongs to the holder of this granter token, so the
    /// inbox is a file read and not a scan over every invite ever made.
    pub async fn index_granter(&self, gt_hash: &str, iid: &str) -> io::Result<()> {
        let path = self.granter_index(gt_hash);
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let mut line = String::with_capacity(iid.len() + 1);
        line.push_str(iid);
        line.push('\n');
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        f.write_all(line.as_bytes()).await?;
        f.flush().await
    }

    /// The invite ids whose granter token hashes to `gt_hash`.
    pub async fn granted_invites(&self, gt_hash: &str) -> io::Result<Vec<String>> {
        match tokio::fs::read_to_string(self.granter_index(gt_hash)).await {
            Ok(text) => Ok(text
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    async fn load_meta<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn save_meta<T: Serialize>(path: &Path, value: &T, seq: &AtomicU64) -> io::Result<()> {
        let bytes =
            serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let n = seq.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
        tokio::fs::write(&tmp, &bytes).await?;
        if let Err(e) = tokio::fs::rename(&tmp, path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        Ok(())
    }

    /// Where an upload stands: bytes durable on disk and whether it is done.
    ///
    /// This is a stat of one path, not a metadata read, so a client polling for
    /// the offset costs the server no more than an `ls`.
    pub async fn upload_progress(&self, dst: &Path) -> io::Result<Received> {
        if let Ok(meta) = tokio::fs::metadata(dst).await {
            return Ok(Received {
                stored: meta.len(),
                complete: true,
            });
        }
        match tokio::fs::metadata(part_path(dst)).await {
            Ok(meta) => Ok(Received {
                stored: meta.len(),
                complete: false,
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Received {
                stored: 0,
                complete: false,
            }),
            Err(e) => Err(e),
        }
    }

    /// Copy a request body into `dst`, starting where `offset` says the client
    /// left off, and enforcing `cap` (and the client's own `declared` total)
    /// while it streams.
    ///
    /// Resumption is the same code path as a first upload: the part file is
    /// opened for append, its length is compared with the client's offset, and
    /// the body is written after it. A connection that dies mid-body leaves the
    /// bytes that arrived on disk — and nothing else — so the next request
    /// continues from them instead of resending the file. When the last byte is
    /// in, the part is synced and renamed: a file is complete or it is not, and
    /// the rename is the only thing that says so.
    pub async fn receive_from(
        &self,
        body: Body,
        dst: &Path,
        offset: u64,
        declared: Option<u64>,
        cap: u64,
    ) -> Result<Received, ReceiveError> {
        if let Some(dir) = dst.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let part = part_path(dst);

        // A finished file answers for itself. One of three states, always:
        // offset 0 means "start over" and drops the finished file first;
        // anything else is a retry against bytes that are already all there, so
        // the answer is the same and costs nothing.
        if let Ok(meta) = tokio::fs::metadata(dst).await {
            let size = meta.len();
            if offset == 0 {
                tokio::fs::remove_file(dst).await?;
            } else {
                return Ok(Received {
                    stored: size,
                    complete: true,
                });
            }
        }

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&part)
            .await?;
        let stored = file.metadata().await?.len();
        if stored != offset {
            return Err(ReceiveError::Offset { stored });
        }
        // Refuse on what the client already said, before touching the disk: an
        // upload that cannot fit should cost nothing at all.
        if let Some(total) = declared
            && total > cap
        {
            return Err(ReceiveError::TooLarge(cap));
        }

        let mut w = BufWriter::with_capacity(IO_BUFFER, file);
        let mut total = stored;
        let mut over: Option<u64> = None;
        let mut interrupted: Option<ReceiveError> = None;
        let limit = declared.unwrap_or(cap).min(cap);
        let mut stream = body.into_data_stream();
        loop {
            match stream.next().await {
                None => break,
                Some(Err(e)) => {
                    interrupted = Some(ReceiveError::Body(e.to_string()));
                    break;
                }
                Some(Ok(chunk)) => {
                    total += chunk.len() as u64;
                    if total > limit {
                        over = Some(limit);
                        break;
                    }
                    if let Err(e) = w.write_all(&chunk).await {
                        interrupted = Some(ReceiveError::Io(e));
                        break;
                    }
                }
            }
        }

        if let Some(limit) = over {
            // Too large is not a partial upload: drop it, so a refused file
            // does not squat on the disk waiting for a cap that will never come.
            drop(w);
            let _ = tokio::fs::remove_file(&part).await;
            return Err(ReceiveError::TooLarge(limit));
        }
        if let Some(e) = interrupted {
            // Keep what arrived, and make it durable before the next request
            // reads its length to decide where to resume. The offset is only
            // ever taken from the file itself, so a shorter part after a crash
            // is a correct answer, not a loss of sync.
            let _ = w.flush().await;
            let _ = w.get_ref().sync_data().await;
            drop(w);
            return Err(e);
        }

        w.flush().await?;
        w.get_ref().sync_data().await?;
        drop(w);

        // Complete when the client's total is reached, or — for a plain single
        // PUT that declares nothing — when the whole body started at zero.
        let complete = declared.map_or(offset == 0, |t| t == total);
        if !complete {
            return Ok(Received {
                stored: total,
                complete: false,
            });
        }
        if let Err(e) = tokio::fs::rename(&part, dst).await {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(ReceiveError::Io(e));
        }
        Ok(Received {
            stored: total,
            complete: true,
        })
    }

    /// One request, one file, no resumption: the shape a plain `PUT` has.
    pub async fn receive(
        &self,
        body: Body,
        dst: &Path,
        cap: Option<u64>,
    ) -> Result<u64, ReceiveError> {
        let cap = cap.unwrap_or(u64::MAX);
        self.receive_from(body, dst, 0, None, cap)
            .await
            .map(|r| r.stored)
    }
}

/// The part file's name, derived from the finished name and constant across
/// requests — that constancy is the whole mechanism of resuming.
fn part_path(dst: &Path) -> PathBuf {
    dst.with_extension("part")
}

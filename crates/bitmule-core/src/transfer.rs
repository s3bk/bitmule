use std::path::PathBuf;

use bitmule_crypto::{BulkKey, CommitmentHasher};
use bytes::Bytes;

use crate::protocol::websocket::{TransferManifest, TransferType};

pub struct TransferBuilder {
    files: Vec<FileEntry>,
    /// Force MultiFileZip framing even for a single file. Off by default —
    /// single-file transfers ship the raw bytes to avoid an unnecessary
    /// zip container.
    force_zip: bool,
}

impl TransferBuilder {
    pub fn new() -> Self {
        Self { files: Vec::new(), force_zip: false }
    }

    pub fn add_file(&mut self, storage: impl Into<Storage>, name: Option<PathBuf>) {
        self.files.push(FileEntry { name, storage: storage.into() });
    }

    /// Force MultiFileZip transfer_typ even if only one file was added.
    /// Useful when the receiver needs the zip envelope regardless (e.g.
    /// consistent extract path in the UI).
    pub fn force_multi_file_zip(&mut self) {
        self.force_zip = true;
    }

    pub async fn commit_async(self) -> anyhow::Result<(TransferManifest, Transfer)> {
        let bulk_key = BulkKey::random();
        let use_zip = self.force_zip || self.files.len() != 1;

        let (transfer_typ, transfer_size, commitment) = if use_zip {
            let (zip_size, zip_commit) = zip_and_commit(&self.files, &bulk_key).await?;
            (
                TransferType::MultiFileZip { outer_compression: None },
                zip_size,
                zip_commit,
            )
        } else {
            let entry = &self.files[0];
            let (size, commit) = single_file_commit(&entry.storage, &bulk_key).await?;
            (
                TransferType::SingleFile { compression: None },
                size,
                commit,
            )
        };

        let manifest = TransferManifest {
            transfer_typ,
            block_size: 1024 * 1024, // 1 MiB relay chunks — matches BulkKey chunk-nonce assumption
            transfer_size,
            bulk_key: bulk_key.clone(),
        };
        let transfer = Transfer {
            files: self.files,
            bulk_key,
            commitment,
        };
        Ok((manifest, transfer))
    }
}

impl Default for TransferBuilder {
    fn default() -> Self { Self::new() }
}

pub struct Transfer {
    files: Vec<FileEntry>,
    bulk_key: BulkKey,
    commitment: [u8; 32],
}

pub struct FileEntry {
    name: Option<PathBuf>,
    storage: Storage,
}

pub struct TransferEntry {
    name: Option<PathBuf>,
    storage: Storage,
    hash: [u8; 32],
}

pub enum Storage {
    File(PathBuf),
    Bytes(Bytes),
}
impl From<PathBuf> for Storage {
    fn from(path: PathBuf) -> Self { Self::File(path) }
}
impl From<Bytes> for Storage {
    fn from(bytes: Bytes) -> Self { Storage::Bytes(bytes) }
}

// ─── Native impl ──────────────────────────────────────────────────────────
// tempfile + tokio::fs. Not compiled on wasm32 targets.

#[cfg(not(target_arch = "wasm32"))]
async fn single_file_commit(storage: &Storage, bulk_key: &BulkKey) -> anyhow::Result<(u64, [u8; 32])> {
    use bitmule_crypto::commit_reader;
    match storage {
        Storage::File(path) => {
            let f = tokio::fs::File::open(path).await?;
            let size = f.metadata().await?.len();
            let mut r = f;
            let commit = commit_reader(&mut r, bulk_key).await?;
            Ok((size, commit))
        }
        Storage::Bytes(b) => {
            let size = b.len() as u64;
            let mut hasher = CommitmentHasher::new();
            hasher.update(b);
            Ok((size, hasher.finalize(bulk_key)))
        }
    }
}

/// Native zip staging: write via async_zip → tempfile, then rehash the file.
#[cfg(not(target_arch = "wasm32"))]
async fn zip_and_commit(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> anyhow::Result<(u64, [u8; 32])> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use bitmule_crypto::commit_reader;
    use futures_lite::io::AsyncWriteExt as _;
    use tokio::io::AsyncReadExt;
    use tokio_util::compat::TokioAsyncWriteCompatExt;

    let tmp = tempfile::NamedTempFile::new()?;
    let tmp_path = tmp.path().to_path_buf();
    let out = tokio::fs::File::create(&tmp_path).await?;
    let mut writer = ZipFileWriter::new(out.compat_write());

    for (idx, entry) in files.iter().enumerate() {
        let name = zip_entry_name(entry, idx);
        // Compression = Zstd: zip's per-entry offset structure survives
        // 1 MiB AEAD chunking downstream, so a receiver can fetch the
        // central-directory trailer, enumerate entries, then range-request
        // only the entries they want (compressed, small). Zstd over Deflate:
        // similar decode speed, materially better ratio. Seb 2026-09-20.
        let builder = ZipEntryBuilder::new(name.into(), Compression::Zstd);
        match &entry.storage {
            Storage::File(path) => {
                let mut src = tokio::fs::File::open(path).await?;
                let mut stream = writer.write_entry_stream(builder).await?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = src.read(&mut buf).await?;
                    if n == 0 { break; }
                    stream.write_all(&buf[..n]).await?;
                }
                stream.close().await?;
            }
            Storage::Bytes(b) => {
                writer.write_entry_whole(builder, b).await?;
            }
        }
    }
    writer.close().await?;

    let zip_size = tokio::fs::metadata(&tmp_path).await?.len();
    let mut f = tokio::fs::File::open(tmp.path()).await?;
    let commit = commit_reader(&mut f, bulk_key).await?;
    drop(tmp);

    Ok((zip_size, commit))
}

// ─── Wasm impls ───────────────────────────────────────────────────────────
// Two paths, both against OPFS via web-sys:
//   - `zip_and_commit` (default, fully async, main-thread safe) uses
//     FileSystemFileHandle → createWritable → FileSystemWritableFileStream.
//   - `zip_and_commit_sync_worker` (worker-scope only) uses
//     FileSystemSyncAccessHandle for blake3-style sync consumption.
//
// Kept scaffold-only right now: hashing recipe + entry naming + BulkKey
// finalize match native exactly; the OPFS byte-io is behind todo!() so any
// downstream trait/type mismatch surfaces at cargo-check time, per Seb
// 2026-09-20. Wiring the real web-sys promises comes when the wasm build
// target is first driven end-to-end.

#[cfg(target_arch = "wasm32")]
async fn single_file_commit(storage: &Storage, bulk_key: &BulkKey) -> anyhow::Result<(u64, [u8; 32])> {
    match storage {
        Storage::File(_path) => {
            // In-browser Storage::File semantics aren't defined yet — the
            // browser side generally hands us Bytes from a File API blob.
            // Left as todo! so the missing-piece surfaces if a wasm caller
            // ever routes a filesystem path through here.
            todo!("wasm: Storage::File is not defined in the browser; expect Storage::Bytes")
        }
        Storage::Bytes(b) => {
            let size = b.len() as u64;
            let mut hasher = CommitmentHasher::new();
            hasher.update(b);
            Ok((size, hasher.finalize(bulk_key)))
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn zip_and_commit(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> anyhow::Result<(u64, [u8; 32])> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures_lite::io::AsyncWriteExt as _;

    // Stage in an OPFS file via createWritable — fully async, no worker.
    let stage = opfs::OpfsAsyncStage::create("bitmule_stage.zip").await?;
    let mut writer = ZipFileWriter::new(stage.writer());

    for (idx, entry) in files.iter().enumerate() {
        let name = zip_entry_name(entry, idx);
        // Compression = Zstd: zip's per-entry offset structure survives
        // 1 MiB AEAD chunking downstream, so a receiver can fetch the
        // central-directory trailer, enumerate entries, then range-request
        // only the entries they want (compressed, small). Zstd over Deflate:
        // similar decode speed, materially better ratio. Seb 2026-09-20.
        let builder = ZipEntryBuilder::new(name.into(), Compression::Zstd);
        match &entry.storage {
            Storage::File(_path) => {
                todo!("wasm: Storage::File is not defined in the browser; expect Storage::Bytes")
            }
            Storage::Bytes(b) => {
                writer.write_entry_whole(builder, b).await?;
            }
        }
    }
    writer.close().await?;

    let zip_size = stage.size().await?;
    let commit = stage.hash_into_commitment(bulk_key).await?;
    stage.remove().await?;
    Ok((zip_size, commit))
}

/// Worker-scope only. Uses FileSystemSyncAccessHandle for blocking-style
/// I/O against OPFS. Same shape as the async variant; picked when the
/// caller is already inside a Worker context and wants to avoid the
/// promise round-trip per chunk.
#[cfg(target_arch = "wasm32")]
pub async fn zip_and_commit_sync_worker(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> anyhow::Result<(u64, [u8; 32])> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures_lite::io::AsyncWriteExt as _;

    let stage = opfs::OpfsSyncStage::create("bitmule_stage_sync.zip").await?;
    let mut writer = ZipFileWriter::new(stage.writer());

    for (idx, entry) in files.iter().enumerate() {
        let name = zip_entry_name(entry, idx);
        // Compression = Zstd: zip's per-entry offset structure survives
        // 1 MiB AEAD chunking downstream, so a receiver can fetch the
        // central-directory trailer, enumerate entries, then range-request
        // only the entries they want (compressed, small). Zstd over Deflate:
        // similar decode speed, materially better ratio. Seb 2026-09-20.
        let builder = ZipEntryBuilder::new(name.into(), Compression::Zstd);
        match &entry.storage {
            Storage::File(_path) => {
                todo!("wasm: Storage::File is not defined in the browser; expect Storage::Bytes")
            }
            Storage::Bytes(b) => {
                writer.write_entry_whole(builder, b).await?;
            }
        }
    }
    writer.close().await?;

    let zip_size = stage.size()?;
    let commit = stage.hash_into_commitment(bulk_key).await?;
    stage.remove()?;
    Ok((zip_size, commit))
}

fn zip_entry_name(entry: &FileEntry, idx: usize) -> String {
    entry
        .name
        .as_ref()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| format!("file_{idx}"))
}

// ─── Wasm OPFS helpers ────────────────────────────────────────────────────
// Thin wrappers around StorageManager.getDirectory() + FileSystemFileHandle.
// Async variant hits createWritable() (Promise chain, main-thread safe).
// Sync variant hits createSyncAccessHandle() — Worker-scope ONLY per MDN.
//
// Both surface async fns that return AsyncWrite-capable staging handles
// so async_zip's writer can consume them without special-casing. Bodies
// are todo!() so the type shapes and web-sys feature flags surface any
// mismatches at cargo-check time; real bytes get wired when the wasm
// build first runs end-to-end.

#[cfg(target_arch = "wasm32")]
mod opfs {
    use bitmule_crypto::BulkKey;
    use futures_lite::io::AsyncWrite;

    pub(super) struct OpfsAsyncStage {
        // future fields: FileSystemFileHandle, WritableFileStream
    }

    impl OpfsAsyncStage {
        pub(super) async fn create(_name: &str) -> anyhow::Result<Self> {
            todo!("web-sys StorageManager.getDirectory() → getFileHandle({{create:true}}) → createWritable()")
        }
        pub(super) fn writer(&self) -> impl AsyncWrite + Unpin + '_ {
            #[allow(unreachable_code)]
            futures_lite::io::sink()
        }
        pub(super) async fn size(&self) -> anyhow::Result<u64> {
            todo!("FileSystemFileHandle.getFile().size")
        }
        pub(super) async fn hash_into_commitment(&self, _bulk_key: &BulkKey) -> anyhow::Result<[u8; 32]> {
            todo!("stream File.stream() through CommitmentHasher.finalize(bulk_key)")
        }
        pub(super) async fn remove(&self) -> anyhow::Result<()> {
            todo!("parent DirectoryHandle.removeEntry(name)")
        }
    }

    pub(super) struct OpfsSyncStage {
        // future fields: FileSystemSyncAccessHandle
    }

    impl OpfsSyncStage {
        pub(super) async fn create(_name: &str) -> anyhow::Result<Self> {
            todo!("Worker-scope only: getFileHandle → createSyncAccessHandle()")
        }
        pub(super) fn writer(&self) -> impl AsyncWrite + Unpin + '_ {
            #[allow(unreachable_code)]
            futures_lite::io::sink()
        }
        pub(super) fn size(&self) -> anyhow::Result<u64> {
            todo!("FileSystemSyncAccessHandle.getSize()")
        }
        pub(super) async fn hash_into_commitment(&self, _bulk_key: &BulkKey) -> anyhow::Result<[u8; 32]> {
            todo!("SyncAccessHandle.read() loop → CommitmentHasher.finalize(bulk_key)")
        }
        pub(super) fn remove(&self) -> anyhow::Result<()> {
            todo!("close() + parent DirectoryHandle.removeEntry(name) via saved handle")
        }
    }
}

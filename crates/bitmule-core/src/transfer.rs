use std::{path::PathBuf, pin::Pin};

use anyhow::Error;
use async_trait::async_trait;
use bitmule_crypto::{BulkKey, CommitmentHasher};
use bytes::Bytes;
use tempfile::NamedTempFile;
use tokio::{fs::File, io::AsyncWrite};

#[cfg(target_arch = "wasm32")]
use js_sys::{wasm_bindgen::JsCast, Uint8Array};

#[cfg(target_arch = "wasm32")]
use web_sys::{FileSystemDirectoryHandle, FileSystemGetDirectoryOptions, Navigator, window};


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
    #[cfg(target_arch = "wasm32")]
    ArrayBuffer(Uint8Array),
}
impl From<PathBuf> for Storage {
    fn from(path: PathBuf) -> Self { Self::File(path) }
}
impl From<Bytes> for Storage {
    fn from(bytes: Bytes) -> Self { Storage::Bytes(bytes) }
}

#[async_trait]
pub trait FsImpl: Sized {
    type TempFile: AsyncWrite;
    async fn create_tmp_file(&self) -> Self::TempFile;
    async fn drop_tmp_file(&self, file: Self::TempFile);
}
struct NativeImpl;

#[async_trait]
impl FsImpl for NativeImpl {
    type TempFile = NativeTempFile;
    async fn create_tmp_file(&self) -> Result<Self::TempFile, Error> {
        let tmp = tempfile::NamedTempFile::new()?;
        let tmp_path = tmp.path().to_path_buf();
        let file = tokio::fs::File::create(&tmp_path).await?;
        Ok(NativeTempFile { tmp, file })
    }
    async fn drop_tmp_file(&self, file: Self::TempFile);
}
impl NativeTempFile {
    fn file(self: Pin<&mut Self>) -> Pin<&mut File> {
        // This is okay because `field` is pinned when `self` is.
        unsafe { self.map_unchecked_mut(|s| &mut s.file) }
    }
}

struct NativeTempFile {
    tmp: NamedTempFile,
    file: File,
}
impl AsyncWrite for NativeTempFile {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        self.file().poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.file().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.file().poll_shutdown(cx)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>>
    {
        self.file().poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.file.is_write_vectored()
    }
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
            // Path in OPFS
            todo!("wasm: Storage::File is not defined in the browser; expect Storage::Bytes")
        }
        Storage::Bytes(b) => {
            let size = b.len() as u64;
            let mut hasher = CommitmentHasher::new();
            hasher.update(b);
            Ok((size, hasher.finalize(bulk_key)))
        }
        Storage::ArrayBuffer(data) => {
            // read buffer in 1MB chunks and hash it
            let chunk_size: u32 = 1024 * 1024;
            let mut hasher = CommitmentHasher::new();
            let mut buffer = vec![0u8; chunk_size as usize];
            let size = data.length();
            for off in (0..size).step_by(chunk_size as usize) {
                let end = (off + chunk_size).min(size);

                let slice = &mut buffer[.. (end - off) as usize];
                data.slice(off, end).copy_to(slice);

                hasher.update(&slice);
            }
            Ok((size as u64, hasher.finalize(bulk_key)))
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
            Storage::ArrayBuffer(data) => {
                todo!()
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
            Storage::ArrayBuffer(data) => {
                todo!()
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

    struct Opfs {
        root: FileSystemDirectoryHandle,
        tmp: FileSystemDirectoryHandle,
    }
    struct OpfsTempFile {
        file: FileSystemFileHandle,
        writable: FileSystemWritableFileStream,
    }
    impl Opfs {
        pub async fn new_window() -> Result<Self> {
            let root = window().ok_or(anyhow!("no window"))?.navigator().storage().get_directory().await?
                .dyn_into::<FileSystemDirectoryHandle>()?;

            let options = FileSystemGetDirectoryOptions::new();
            options.set_create(true);
            let tmp = self.root.get_file_handle_with_options("tmp", &options).await?
                .dyn_into::<FileSystemDirectoryHandle>()?;

            Ok(Opfs {
                root, tmp
            })
        }
    }

    #[async_trait]
    impl FsImpl for Opfs {
        type TempFile = OpfsTempFile;
        async fn create_tmp_file(&self) -> Result<Self::TempFile, Error> {
            let name = uuid::Uuid::new_v4();
            let options = &FileSystemGetFileOptions::new();
            options.set_create(true);
            let file = self.tmp.get_file_handle_with_options(&name.to_string(), &options).await?.dyn_into::<FileSystemFileHandle>()?;
            let writable = file.create_writable.await?().dyn_into::<FileSystemFileHandle>()?;

            Ok(OpfsTempFile {
                file,
                writable,
            })
        }
        async fn drop_tmp_file(&self, file: Self::TempFile);
    }
}

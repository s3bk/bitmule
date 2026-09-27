use std::{future::Future, path::PathBuf, pin::Pin};

use anyhow::{anyhow, Result};
use bitmule_crypto::{BulkKey, CommitmentHasher};
use bytes::Bytes;

use futures_lite::AsyncReadExt;
#[cfg(not(target_arch = "wasm32"))]
use tempfile::NamedTempFile;

#[cfg(not(target_arch = "wasm32"))]
use tokio::{fs::File, io::AsyncWrite};

#[cfg(target_arch = "wasm32")]
use js_sys::{wasm_bindgen::JsCast, Uint8Array};

#[cfg(target_arch = "wasm32")]
use web_sys::{FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions, Navigator, window};

use crate::Error;
#[cfg(target_arch = "wasm32")]
use crate::{opfs::{self, open_write}, web::open_read};

use bitmule_core::protocol::websocket::{TransferManifest, TransferType};

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

    pub async fn commit_async(self) -> Result<(TransferManifest, Transfer)> {
        let bulk_key = BulkKey::random();
        let use_zip = self.force_zip || self.files.len() != 1;

        let (transfer_typ, transfer_size, commitment, storage) = if use_zip {
            let (zip_size, zip_commit, zip_file) = zip_and_commit(&self.files, &bulk_key).await?;
            (
                TransferType::MultiFileZip { outer_compression: None },
                zip_size,
                zip_commit,
                zip_file
            )
        } else {
            let entry = self.files.remove(0);
            let (size, commit) = single_file_commit(&entry.storage, &bulk_key).await?;
            let file = storage_to_file(&entry.storage).await?;
            (
                TransferType::SingleFile { compression: None },
                size,
                commit,
                PreparedFile(file),
            )
        };

        let manifest = TransferManifest {
            transfer_typ,
            block_size: 1024 * 1024, // 1 MiB relay chunks — matches BulkKey chunk-nonce assumption
            transfer_size,
            bulk_key: bulk_key.clone(),
        };
        let transfer = Transfer {
            data: storage,
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
    data: PreparedFile,
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
    #[cfg(not(target_arch = "wasm32"))]
    File(PathBuf),
    #[cfg(target_arch = "wasm32")]
    File(web_sys::FileSystemFileHandle),

    Bytes(Bytes),

    #[cfg(target_arch = "wasm32")]
    ArrayBuffer(Uint8Array),
}
#[cfg(not(target_arch = "wasm32"))]
impl From<PathBuf> for Storage {
    fn from(path: PathBuf) -> Self { Self::File(path) }
}
#[cfg(target_arch = "wasm32")]
impl From<web_sys::FileSystemFileHandle> for Storage {
    fn from(file: web_sys::FileSystemFileHandle) -> Self { Self::File(file) }
}
impl From<Bytes> for Storage {
    fn from(bytes: Bytes) -> Self { Storage::Bytes(bytes) }
}

async fn storage_to_file(storage: &Storage) -> Result<PreparedFile, Error> {
    // @Kenna fill this
    todo!()
}

struct PreparedFile {
    #[cfg(not(target_arch = "wasm32"))]
    tmp_file: NativeTempFile,

    #[cfg(target_arch = "wasm32")]
    handle: FileSystemFileHandle
}

async fn zip_and_commit(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> Result<(u64, [u8; 32], PreparedFile), Error> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use bitmule_crypto::commit_reader;
    use futures_lite::io::AsyncWriteExt as _;
    use tokio::io::AsyncReadExt;
    //use tokio_util::compat::TokioAsyncWriteCompatExt;

    let tmp;
    #[cfg(target_arch = "wasm32")]
    {
        use opfs::*;

        use crate::fs::FsImpl;
        let opfs = Opfs::new_window().await?;
        tmp = opfs.create_tmp_file().await?;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // tokio impl here

    }
    #[cfg(target_arch = "wasm32")]
    let mut writer = open_write(&tmp).await?;


    let mut zip_writer = ZipFileWriter::new(writer);

    for (idx, entry) in files.iter().enumerate() {
        let name = zip_entry_name(entry, idx);
        // Compression = Zstd: zip's per-entry offset structure survives
        // 1 MiB AEAD chunking downstream, so a receiver can fetch the
        // central-directory trailer, enumerate entries, then range-request
        // only the entries they want (compressed, small). Zstd over Deflate:
        // similar decode speed, materially better ratio. Seb 2026-09-20.
        let builder = ZipEntryBuilder::new(name.into(), Compression::Zstd);
        match &entry.storage {
            Storage::File(handle) => {

                #[cfg(target_arch = "wasm32")]
                let mut src = open_read(handle).await?;

                #[cfg(not(target_arch = "wasm32"))]
                let mut src = tokio::fs::File::open(path).await?;

                let mut stream = zip_writer.write_entry_stream(builder).await?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = src.read(&mut buf).await?;
                    if n == 0 { break; }
                    stream.write_all(&buf[..n]).await?;
                }
                stream.close().await?;
            }
            Storage::Bytes(b) => {
                zip_writer.write_entry_whole(builder, b).await?;
            }
            #[cfg(target_arch = "wasm32")]
            Storage::ArrayBuffer(data) => {
                let mut stream = zip_writer.write_entry_stream(builder).await?;
                let stream = array_buffer_chunks_async::<_, _, Error>(&data, stream, |stream, chunk| async move {
                    stream.write_all(chunk).await?;
                    Ok(stream)
                }).await?;
                stream.close().await?;
            }
        }
    }
    zip_writer.close().await?;

    #[cfg(not(target_arch = "wasm32"))]
    let zip_size = tokio::fs::metadata(&tmp_path).await?.len();

    #[cfg(not(target_arch = "wasm32"))]
    let mut reader = tokio::fs::File::open(tmp.path()).await?;

    #[cfg(target_arch = "wasm32")]
    let mut reader = open_read(&tmp).await?;

    let (zip_size, commit) = commit_reader(&mut reader, bulk_key).await?;

    #[cfg(not(target_arch = "wasm32"))]
    let file = PreparedFile {

    };
    #[cfg(target_arch = "wasm32")]
    let file = PreparedFile {
        handle: tmp,
    };

    Ok((zip_size, commit, file))
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

async fn single_file_commit(storage: &Storage, bulk_key: &BulkKey) -> anyhow::Result<(u64, [u8; 32])> {
    match storage {
        #[cfg(target_arch = "wasm32")]
        Storage::File(handle) => {
            use crate::web::read_file_in_chunks;
            let size = handle.len() as u64;
            let mut hasher = CommitmentHasher::new();
            read_file_in_chunks(&handle, 1024 * 1024, |slice| {
                hasher.update(&slice);
            });
            Ok((size as u64, hasher.finalize(bulk_key)))
        }
        #[cfg(not(target_arch = "wasm32"))]
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
        Storage::ArrayBuffer(data) => {
            let size = data.len() as u64;
            let mut hasher = CommitmentHasher::new();
            array_buffer_chunks(data, |slice| {
                hasher.update(&slice);
            });
            Ok((size as u64, hasher.finalize(bulk_key)))
        }
    }
}

async fn array_buffer_chunks(data: &Uint8Array, mut cb: impl FnMut(&[u8])) {
    // read buffer in 1MB chunks and hash it
    let chunk_size: u32 = 1024 * 1024;
    let mut buffer = vec![0u8; chunk_size as usize];
    let size = data.length();
    for off in (0..size).step_by(chunk_size as usize) {
        let end = (off + chunk_size).min(size);

        let slice = &mut buffer[.. (end - off) as usize];
        data.slice(off, end).copy_to(slice);

        cb(&slice);
    }
}

async fn array_buffer_chunks_async<I, F, E>(data: &Uint8Array, mut init: I, cb: impl Fn(I, &[u8]) -> F) -> Result<I, E>
    where F: Future<Output = Result<I, E>>
{
    // read buffer in 1MB chunks and hash it
    let chunk_size: u32 = 1024 * 1024;
    let mut buffer = vec![0u8; chunk_size as usize];
    let size = data.length();
    for off in (0..size).step_by(chunk_size as usize) {
        let end = (off + chunk_size).min(size);

        let slice = &mut buffer[.. (end - off) as usize];
        data.slice(off, end).copy_to(slice);

        init = cb(init, &slice).await?;
    }
    Ok(init)
}

#[cfg(target_arch = "wasm32")]
async fn zip_and_commit_wasm(
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

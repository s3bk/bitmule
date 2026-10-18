use std::path::PathBuf;

use anyhow::{anyhow, Result};
use bitmule_crypto::{BulkKey, CommitmentHasher};
use bytes::Bytes;

#[cfg(target_arch = "wasm32")]
use futures_lite::AsyncReadExt;
#[cfg(not(target_arch = "wasm32"))]
use tempfile::NamedTempFile;

#[cfg(not(target_arch = "wasm32"))]
use tokio::fs::File;

#[cfg(target_arch = "wasm32")]
use js_sys::{wasm_bindgen::JsCast, Uint8Array};

#[cfg(target_arch = "wasm32")]
use web_sys::{FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions, Navigator, window};

use crate::Error;
#[cfg(target_arch = "wasm32")]
use crate::{opfs::{self, open_write}, web::open_read};

use bitmule_core::protocol::websocket::{TransferManifest, TransferType};
use bitmule_crypto::commit_reader;

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

    pub async fn commit_async(mut self) -> Result<(TransferManifest, Transfer)> {
        let bulk_key = BulkKey::random();
        let use_zip = self.force_zip || self.files.len() != 1;

        // what the receiver saves it as: the file's name, or a name for the zip
        let name = if use_zip {
            "bitmule-files.zip".to_string()
        } else {
            self.files[0].name.as_ref().and_then(|n| n.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "bitmule-download".to_string())
        };
        let (transfer_typ, transfer_size, commitment, storage) = if use_zip {
            let (zip_size, zip_commit, unpacked_size, zip_file) = zip_and_commit(&self.files, &bulk_key).await?;
            (
                TransferType::MultiFileZip { outer_compression: None, unpacked_size },
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
                file,
            )
        };

        // the hashes of what is actually staged for sending
        #[cfg(not(target_arch = "wasm32"))]
        let block_hashes = {
            let path = storage.tmp_file.path().to_path_buf();
            let key = bulk_key.clone();
            tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Vec<u64>>> {
                crate::fountain::block_hashes(&std::fs::File::open(path)?, transfer_size, &key)
            }).await.map_err(|e| Error::from(anyhow!("hashing the blocks: {e}")))??.unwrap_or_default()
        };
        #[cfg(target_arch = "wasm32")]
        let block_hashes = Vec::new();

        let manifest = TransferManifest {
            transfer_typ,
            block_size: crate::fountain::BLOCK_PLAIN as u32,
            transfer_size,
            bulk_key: bulk_key.clone(),
            block_hashes,
            name: Some(name),
        };
        let transfer = Transfer {
            data: storage,
            bulk_key,
            commitment,
        };
        Ok((manifest, transfer))
    }
    pub async fn commit_stream(self) -> Result<()> {
        todo!("streaming commit");
    }
}

impl Default for TransferBuilder {
    fn default() -> Self { Self::new() }
}

#[allow(dead_code)]
pub struct Transfer {
    data: PreparedFile,
    bulk_key: BulkKey,
    commitment: [u8; 32],
}

impl Transfer {
    /// Where the data to send is staged.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn path(&self) -> &std::path::Path {
        self.data.tmp_file.path()
    }

    /// `SHA256(data || bulk_key)`; the signature half of the share link.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Read up to `len` bytes at `start` (fewer at end of file).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn read_at(&self, start: u64, len: usize) -> Result<Bytes> {
        use std::io::SeekFrom;
        use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
        // a fresh handle per call, so concurrent peers don't share a cursor
        let mut file = File::open(self.data.tmp_file.path()).await?;
        file.seek(SeekFrom::Start(start)).await?;
        let mut buf = Vec::with_capacity(len);
        file.take(len as u64).read_to_end(&mut buf).await?;
        Ok(buf.into())
    }

    /// Fill `buf` from `start`; errors if the data ends first.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn read_exact_at(&self, start: u64, buf: &mut [u8]) -> Result<()> {
        use std::io::SeekFrom;
        use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
        let mut file = File::open(self.data.tmp_file.path()).await?;
        file.seek(SeekFrom::Start(start)).await?;
        file.read_exact(buf).await?;
        Ok(())
    }
}

#[allow(dead_code)]
pub struct FileEntry {
    name: Option<PathBuf>,
    storage: Storage,
}

#[allow(dead_code)]
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
    // Native: materialize the Storage into a NamedTempFile so downstream
    // relay chunking has a single, uniform file-backed reader path. Bytes
    // get written into a fresh temp file; existing filesystem paths get
    // copied so the temp file owns the lifecycle (caller-side deletion
    // semantics stay consistent, and the source file can move / be deleted
    // without breaking an in-flight transfer).
    //
    // Wasm: the OPFS write path isn't wired yet (see zip_and_commit_wasm's
    // stage-and-hash comment); todo!() surfaces the trait/type mismatch at
    // cargo-check time on wasm, same discipline as the rest of this file.
    #[cfg(not(target_arch = "wasm32"))]
    {
        let tmp = NamedTempFile::new()
            .map_err(|e| Error::from(anyhow!("storage_to_file: NamedTempFile::new: {e}")))?;
        match storage {
            Storage::File(path) => {
                let dst_path = tmp.path().to_path_buf();
                tokio::fs::copy(path, &dst_path).await.map_err(|e| {
                    Error::from(anyhow!("storage_to_file: copy {} -> {}: {e}",
                        path.display(), dst_path.display()))
                })?;
            }
            Storage::Bytes(b) => {
                tokio::fs::write(tmp.path(), b).await.map_err(|e| {
                    Error::from(anyhow!("storage_to_file: write bytes to {}: {e}",
                        tmp.path().display()))
                })?;
            }
        }
        Ok(PreparedFile { tmp_file: tmp })
    }
    #[cfg(target_arch = "wasm32")]
    {
        use web_sys::FileSystemWritableFileStream;
        use crate::{fs::FsImpl, opfs::Opfs};

        match storage {
            Storage::ArrayBuffer(buffer) => {
                let opfs = Opfs::new_window().await?;
                let handle = opfs.create_tmp_file().await?;
                let writable = handle.create_writable().await?.dyn_into::<FileSystemWritableFileStream>()?;

                writable.write_with_buffer_source(buffer)?.await?;
                Ok(PreparedFile { handle })
            }
            Storage::Bytes(data) => {
                let opfs = Opfs::new_window().await?;
                let handle = opfs.create_tmp_file().await?;
                let writable = handle.create_writable().await?.dyn_into::<FileSystemWritableFileStream>()?;

                writable.write_with_u8_array(&data)?.await?;
                Ok(PreparedFile { handle })
            }
            Storage::File(handle) => Ok(PreparedFile { handle: handle.clone() })
        }
    }
}

struct PreparedFile {
    #[cfg(not(target_arch = "wasm32"))]
    tmp_file: NamedTempFile,

    #[cfg(target_arch = "wasm32")]
    handle: FileSystemFileHandle
}

async fn zip_and_commit(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> Result<(u64, [u8; 32], Option<u64>, PreparedFile), Error> {
    #[cfg(target_arch = "wasm32")]
    {
        zip_and_commit_wasm_impl(files, bulk_key).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        zip_and_commit_native_impl(files, bulk_key).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn zip_and_commit_native_impl(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> Result<(u64, [u8; 32], Option<u64>, PreparedFile), Error> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures_lite::io::AsyncWriteExt as _;
    use tokio::io::AsyncReadExt as _;
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

    // Stage the zip into a NamedTempFile so the resulting PreparedFile
    // owns the file lifecycle (matches the wasm side's opfs tmp-handle
    // pattern). The temp file survives past this function's return as
    // part of PreparedFile { tmp_file: tmp }.
    let tmp = NamedTempFile::new()
        .map_err(|e| Error::from(anyhow!("zip_and_commit: NamedTempFile::new: {e}")))?;
    let write_path = tmp.path().to_path_buf();
    // what the files add up to, for the receiver to hold the zip to
    let mut unpacked = 0u64;

    // Write phase: open a tokio File, wrap in tokio_util's compat so
    // async_zip's futures_lite AsyncWrite bound is satisfied.
    {
        let write_file = tokio::fs::File::create(&write_path).await?;
        let mut zip_writer = ZipFileWriter::new(write_file.compat_write());

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
                    let mut stream = zip_writer.write_entry_stream(builder).await?;
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = src.read(&mut buf).await?;
                        if n == 0 { break; }
                        unpacked += n as u64;
                        stream.write_all(&buf[..n]).await?;
                    }
                    stream.close().await?;
                }
                Storage::Bytes(b) => {
                    unpacked += b.len() as u64;
                    zip_writer.write_entry_whole(builder, b).await?;
                }
            }
        }
        zip_writer.close().await?;
    }

    // Commit phase: reopen for read, run commit_reader via tokio_util's
    // compat so the futures_io::AsyncRead + Unpin bound is satisfied.
    let read_file = tokio::fs::File::open(&write_path).await?;
    let mut reader = read_file.compat();
    let (zip_size, commit) = commit_reader(&mut reader, bulk_key).await?;

    Ok((zip_size, commit, Some(unpacked), PreparedFile { tmp_file: tmp }))
}

/// Wasm-side impl, kept close to the original scaffold. Uses OPFS via
/// `open_write` / `open_read` and finalizes the commit against the same
/// streamed file.
#[cfg(target_arch = "wasm32")]
async fn zip_and_commit_wasm_impl(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> Result<(u64, [u8; 32], Option<u64>, PreparedFile), Error> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures_lite::io::AsyncWriteExt as _;

    use opfs::*;
    use crate::fs::FsImpl;

    let opfs = Opfs::new_window().await?;
    let tmp = opfs.create_tmp_file().await?;
    let writer = open_write(&tmp).await?;
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
                let mut src = open_read(handle).await?;
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
            Storage::ArrayBuffer(data) => {
                let mut stream = zip_writer.write_entry_stream(builder).await?;
                // Inlined 1MB-chunk read to sidestep the borrow-checker
                // headache of an FnMut closure returning a Future that
                // captures a &[u8] slice, which array_buffer_chunks_async
                // would otherwise require to name a lifetime.
                let chunk_size: u32 = 1024 * 1024;
                let mut buffer = vec![0u8; chunk_size as usize];
                let size = data.length();
                for off in (0..size).step_by(chunk_size as usize) {
                    let end = (off + chunk_size).min(size);
                    let slice = &mut buffer[.. (end - off) as usize];
                    data.slice(off, end).copy_to(slice);
                    stream.write_all(slice).await?;
                }
                stream.close().await?;
            }
        }
    }
    zip_writer.close().await?;

    let (zip_size, commit) = {
        let mut reader = open_read(&tmp).await?;
        commit_reader(&mut reader, bulk_key).await?
    }; // reader dropped here so `tmp` is no longer borrowed
    let file = PreparedFile { handle: tmp };
    Ok((zip_size, commit, None, file))
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
            use js_sys::wasm_bindgen::JsCast;
            use wasm_bindgen_futures::JsFuture;
            // FileSystemFileHandle has no direct .len(); go through
            // getFile() → Blob.size() to obtain the byte length. JsValue
            // errors are routed through the crate Error (impls std::error::Error)
            // so `?` into anyhow works.
            let file_val = JsFuture::from(handle.get_file()).await
                .map_err(Error::from)?;
            let file: web_sys::File = file_val.dyn_into::<web_sys::File>()
                .map_err(Error::from)?;
            let size = file.size() as u64;
            let mut hasher = CommitmentHasher::new();
            read_file_in_chunks(handle, 1024 * 1024, |slice| {
                hasher.update(slice);
            }).await.map_err(Error::from)?;
            Ok((size, hasher.finalize(bulk_key)))
        }
        #[cfg(not(target_arch = "wasm32"))]
        Storage::File(path) => {
            // Read + hash via tokio's AsyncReadExt directly. Avoids pulling in a
            // tokio<->futures_lite compat wrapper just to satisfy commit_reader's
            // `futures_io::AsyncRead + Unpin` bound; the hashing recipe is the
            // same either way (see bitmule_crypto::commit_reader body).
            use tokio::io::AsyncReadExt as _;
            let mut f = tokio::fs::File::open(path).await?;
            let size = f.metadata().await?.len();
            let mut hasher = CommitmentHasher::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = f.read(&mut buf).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
            }
            Ok((size, hasher.finalize(bulk_key)))
        }
        Storage::Bytes(b) => {
            let size = b.len() as u64;
            let mut hasher = CommitmentHasher::new();
            hasher.update(b);
            Ok((size, hasher.finalize(bulk_key)))
        }
        #[cfg(target_arch = "wasm32")]
        Storage::ArrayBuffer(data) => {
            // Uint8Array uses .length() (JS-style), not .len().
            let size = data.length() as u64;
            let mut hasher = CommitmentHasher::new();
            array_buffer_chunks(data, |slice| {
                hasher.update(slice);
            }).await;
            Ok((size, hasher.finalize(bulk_key)))
        }
    }
}

#[cfg(target_arch = "wasm32")]
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

/// The entry's name inside the zip: the file's name as given, with its
/// directories (`album/sub/a.txt`) so a folder keeps its layout. Only plain
/// path components are kept, so a name can't point outside the folder it is
/// unpacked into.
fn zip_entry_name(entry: &FileEntry, idx: usize) -> String {
    let parts: Vec<String> = entry
        .name
        .iter()
        .flat_map(|p| p.components())
        .filter_map(|c| match c {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if parts.is_empty() { format!("file_{idx}") } else { parts.join("/") }
}

#[cfg(test)]
mod zip_name_tests {
    use super::*;

    fn entry(name: Option<&str>) -> FileEntry {
        FileEntry { name: name.map(PathBuf::from), storage: Storage::Bytes(Default::default()) }
    }

    #[test]
    fn keeps_directories_and_drops_anything_that_escapes() {
        assert_eq!(zip_entry_name(&entry(Some("a.txt")), 0), "a.txt");
        assert_eq!(zip_entry_name(&entry(Some("album/sub/a.txt")), 0), "album/sub/a.txt");
        assert_eq!(zip_entry_name(&entry(Some("../../etc/passwd")), 0), "etc/passwd");
        assert_eq!(zip_entry_name(&entry(Some("/abs/path.txt")), 0), "abs/path.txt");
        assert_eq!(zip_entry_name(&entry(None), 3), "file_3");
        assert_eq!(zip_entry_name(&entry(Some("..")), 7), "file_7");
    }
}

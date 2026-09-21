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

    // ─── AsyncWrite adapter for FileSystemWritableFileStream ──────────────
    // Wraps an FSWFS in the async_zip-compatible AsyncWrite surface (the
    // `futures_lite::io::AsyncWrite` variant, matching what the zip writer
    // consumes on both native and wasm sides).
    //
    // Design:
    //   - Every poll_write copies `buf` into a fresh Uint8Array and hands
    //     it to `stream.write_with_u8_array(...)`. The returned Promise is
    //     stored as a JsFuture in `in_flight` and the byte count is
    //     latched in `in_flight_bytes` so a later poll can return the
    //     right Ready(n).
    //   - Subsequent poll_write / poll_flush / poll_close first drain the
    //     in-flight promise (if any) before issuing a new one. Serialised
    //     one-in-flight; matches FSWFS's own contract (writes queue on the
    //     stream anyway, so overlapping poll_writes would just serialise
    //     underneath us with no throughput gain).
    //   - poll_close issues stream.close() as the final promise and holds
    //     `closed = true` so re-polling after Ready(Ok(())) is a no-op.
    //
    // Not concurrency-safe (single-owner future by design). Errors from JS
    // map to std::io::Error{Other, format!("{:?}", e)} — good enough for
    // async_zip's error surface; refine if we start seeing specific JS
    // exception shapes we want to disambiguate.
    //
    // Kenna 2026-09-21, per Seb's ask.
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use js_sys::{wasm_bindgen::JsCast, Uint8Array};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::FileSystemWritableFileStream;

    pub struct OpfsWritable {
        stream: FileSystemWritableFileStream,
        in_flight: Option<JsFuture>,
        in_flight_bytes: usize,
        closed: bool,
    }

    impl OpfsWritable {
        pub fn new(stream: FileSystemWritableFileStream) -> Self {
            Self {
                stream,
                in_flight: None,
                in_flight_bytes: 0,
                closed: false,
            }
        }

        // Poll the currently-in-flight JsFuture. On Ready, clear it and
        // return the pre-latched byte count (or Ok(()) if the caller
        // doesn't need the byte count, per the `wants_bytes` flag).
        fn poll_inflight(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            wants_bytes: bool,
        ) -> Poll<io::Result<usize>> {
            // Safety: we only project `in_flight`; the struct is not
            // structurally pinned (JsFuture is Unpin).
            let this = unsafe { self.get_unchecked_mut() };
            match this.in_flight.as_mut() {
                None => Poll::Ready(Ok(0)),
                Some(fut) => match Pin::new(fut).poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(_)) => {
                        let n = if wants_bytes { this.in_flight_bytes } else { 0 };
                        this.in_flight = None;
                        this.in_flight_bytes = 0;
                        Poll::Ready(Ok(n))
                    }
                    Poll::Ready(Err(e)) => {
                        this.in_flight = None;
                        this.in_flight_bytes = 0;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("opfs write: {e:?}"),
                        )))
                    }
                },
            }
        }
    }

    impl AsyncWrite for OpfsWritable {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // Drain any prior write first (returns the earlier buf's byte
            // count via the wants_bytes=true path).
            if self.in_flight.is_some() {
                match self.as_mut().poll_inflight(cx, true) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                }
            }
            if self.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "opfs write on closed stream",
                )));
            }

            // Start a new write. Copy `buf` into a Uint8Array so JS owns
            // the bytes independent of our stack.
            let arr = Uint8Array::new_with_length(buf.len() as u32);
            arr.copy_from(buf);
            let promise = match self
                .stream
                .write_with_u8_array(&mut arr.to_vec()[..])
            {
                Ok(p) => p,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("opfs write init: {e:?}"),
                    )));
                }
            };
            // Latch byte count + stash the JsFuture, then Pending. The
            // executor re-polls; next poll drains the future and returns
            // Ready(Ok(n)).
            let this = unsafe { self.get_unchecked_mut() };
            this.in_flight_bytes = buf.len();
            this.in_flight = Some(JsFuture::from(promise));
            // Wake immediately so the executor calls us back without
            // waiting for the promise resolution to fire the waker (which
            // it will do too; belt-and-suspenders).
            cx.waker().wake_by_ref();
            Poll::Pending
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            // Drain any in-flight write; no new-op needed since FSWFS
            // serialises writes on its own queue.
            match self.as_mut().poll_inflight(cx, false) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            }
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            // Two phases:
            //   1. Drain any pending write.
            //   2. Issue stream.close() and await its promise.
            // We use the `closed` flag to route between phases: false =
            // still in phase 1 (may start close after drain); true = close
            // promise already in flight.
            if !self.closed {
                if self.in_flight.is_some() {
                    match self.as_mut().poll_inflight(cx, false) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(_)) => { /* fall through to issue close */ }
                    }
                }
                // Nothing else in flight; fire close().
                let promise = self.stream.close();
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                this.closed = true;
                this.in_flight = Some(JsFuture::from(promise));
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            // closed == true: drain the close-promise.
            match self.as_mut().poll_inflight(cx, false) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            }
        }
    }

    // ─── Sync-worker AsyncWrite adapter for FileSystemSyncAccessHandle ────
    // FSSAH is a synchronous, worker-scope-only OPFS I/O primitive. Every
    // method (write, flush, close, get_size, truncate) returns immediately
    // with no Promise plumbing. Wrapping it in the futures_lite AsyncWrite
    // surface is trivial: every poll_* call resolves to Ready.
    //
    // The wrapper exists so async_zip's ZipFileWriter can consume both the
    // async-createWritable and the sync-access-handle paths without
    // special-casing at the call site. Structural cost of the AsyncWrite
    // trait is zero here — no state to hold beyond the handle itself.
    //
    // web-sys method names hedged: adjust `write_with_u8_array` and
    // friends if the target web-sys crate version renames them (0.3.68+
    // used the names below). `close()` return type varied between
    // web-sys versions (some `()`, some `Result<(), JsValue>`); the
    // match here assumes Result and treats a bare `()` as a compile-time
    // hint to drop the `?`.
    //
    // Kenna 2026-09-21, per Seb ask.
    use web_sys::FileSystemSyncAccessHandle;

    pub struct OpfsSyncWritable {
        handle: FileSystemSyncAccessHandle,
        offset: f64,
    }

    impl OpfsSyncWritable {
        pub fn new(handle: FileSystemSyncAccessHandle) -> Self {
            Self { handle, offset: 0.0 }
        }
    }

    impl AsyncWrite for OpfsSyncWritable {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // FSSAH.write is synchronous and returns the byte count written
            // as f64 (JS Number). Positional writes use FileSystemReadWriteOptions
            // with an `at` offset; without options FSSAH writes at its current
            // internal file cursor. We track offset explicitly here so callers
            // that reuse the handle don't have to trust the browser's internal
            // cursor semantics between chunks.
            let this = unsafe { self.get_unchecked_mut() };
            let options = web_sys::FileSystemReadWriteOptions::new();
            options.set_at(this.offset);
            // web-sys write_with_u8_array_and_options takes a mut slice.
            // Copy to a local mut vec so we don't need the caller's buf mut.
            let mut chunk = buf.to_vec();
            let written = match this
                .handle
                .write_with_u8_array_and_options(&mut chunk, &options)
            {
                Ok(n) => n as usize,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("opfs-sync write: {e:?}"),
                    )));
                }
            };
            this.offset += written as f64;
            Poll::Ready(Ok(written))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            match self.handle.flush() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("opfs-sync flush: {e:?}"),
                ))),
            }
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            // FSSAH.close() has varied between web-sys versions between
            // `-> ()` and `-> Result<(), JsValue>`. If your version returns
            // bare `()`, drop the `.map_err` block and just call `self.handle.close()`.
            self.handle.close();
            Poll::Ready(Ok(()))
        }
    }

    // ─── Stage wrappers for lines 304 (async) + 348 (sync) ────────────────
    // Structural shims so async_zip's ZipFileWriter can consume the OPFS
    // write backends at the two call sites without special-casing. Both
    // stages own the file handle + the write handle; `.writer()` returns
    // the correct AsyncWrite wrapper for the branch.
    //
    // The `create`, `size`, `hash_into_commitment`, `remove` methods stay
    // as todo!() stubs — those wire the actual OPFS lifecycle (creating
    // the temp file in the OPFS root, hashing back through it for the
    // commitment, deleting on cleanup) and Seb owns those. The type
    // shapes below let the call sites at 304 + 348 compile cleanly so any
    // downstream trait/type mismatch surfaces at cargo-check.

    pub struct OpfsAsyncStage {
        file: FileSystemFileHandle,
        writable: FileSystemWritableFileStream,
    }

    impl OpfsAsyncStage {
        pub async fn create(_name: &str) -> Result<Self, anyhow::Error> {
            todo!("wire OPFS root → tmp/ → getFileHandle → createWritable")
        }
        pub fn writer(&self) -> OpfsWritable {
            OpfsWritable::new(self.writable.clone())
        }
        pub async fn size(&self) -> Result<u64, anyhow::Error> {
            todo!("query FSFileHandle.getFile().size()")
        }
        pub async fn hash_into_commitment(
            &self,
            _bulk_key: &BulkKey,
        ) -> Result<[u8; 32], anyhow::Error> {
            todo!("re-open the staged file, stream through CommitmentHasher, finalize with bulk_key")
        }
        pub async fn remove(&self) -> Result<(), anyhow::Error> {
            todo!("removeEntry on the parent directory handle")
        }
    }

    pub struct OpfsSyncStage {
        file: FileSystemFileHandle,
        handle: FileSystemSyncAccessHandle,
    }

    impl OpfsSyncStage {
        pub async fn create(_name: &str) -> Result<Self, anyhow::Error> {
            todo!("wire OPFS root → tmp/ → getFileHandle → createSyncAccessHandle (worker-scope only)")
        }
        pub fn writer(&self) -> OpfsSyncWritable {
            OpfsSyncWritable::new(self.handle.clone())
        }
        pub fn size(&self) -> Result<u64, anyhow::Error> {
            todo!("self.handle.getSize() as u64")
        }
        pub async fn hash_into_commitment(
            &self,
            _bulk_key: &BulkKey,
        ) -> Result<[u8; 32], anyhow::Error> {
            todo!("read chunks off the sync handle synchronously, feed into CommitmentHasher, finalize with bulk_key")
        }
        pub fn remove(&self) -> Result<(), anyhow::Error> {
            todo!("removeEntry on the parent directory handle (sync-scope from a Worker context)")
        }
    }
}

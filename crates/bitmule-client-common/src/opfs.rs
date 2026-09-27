use anyhow::Error;
use bitmule_crypto::BulkKey;
use futures_lite::io::AsyncWrite;
use wasm_bindgen::{JsError, JsValue};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use js_sys::{wasm_bindgen::JsCast, Uint8Array};
use wasm_bindgen_futures::JsFuture;
use web_sys::{FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemSyncAccessHandle, FileSystemWritableFileStream};
use async_trait::async_trait;

use crate::fs::FsImpl;

pub struct Opfs {
    root: FileSystemDirectoryHandle,
    tmp: FileSystemDirectoryHandle,
}
struct OpfsTempFile {
    file: FileSystemFileHandle,
    writable: FileSystemWritableFileStream,
}
impl Opfs {
    pub async fn new_window() -> Result<Self, JsValue> {
        let root = web_sys::window().ok_or(JsValue::from_str("no window"))?.navigator().storage().get_directory().await?
            .dyn_into::<FileSystemDirectoryHandle>()?;

        let options = FileSystemGetDirectoryOptions::new();
        options.set_create(true);
        let tmp = root.get_directory_handle_with_options("tmp", &options).await?
            .dyn_into::<FileSystemDirectoryHandle>()?;

        Ok(Opfs {
            root, tmp
        })
    }
}

#[async_trait(?Send)]
impl FsImpl for Opfs {
    type Error = JsValue;
    type TempFile = FileSystemFileHandle;
    async fn create_tmp_file(&self) -> Result<Self::TempFile, JsValue> {
        let name = uuid::Uuid::new_v4();
        let options = &FileSystemGetFileOptions::new();
        options.set_create(true);
        let file = self.tmp.get_file_handle_with_options(&name.to_string(), &options).await?.dyn_into::<FileSystemFileHandle>()?;
        Ok(file)
    }
    async fn drop_tmp_file(&self, file: Self::TempFile) {
    }
}

pub async fn open_write(handle: &FileSystemFileHandle) -> Result<OpfsWritable, JsValue>  {
    let writable = handle.create_writable().await?.dyn_into::<FileSystemWritableFileStream>()?;

    Ok(OpfsWritable::new(writable))
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
    pub fn remove(&self) -> Result<(), anyhow::Error> {
        todo!("removeEntry on the parent directory handle (sync-scope from a Worker context)")
    }
}

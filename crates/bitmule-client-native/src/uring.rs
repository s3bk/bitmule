//! Helpers for running socket I/O on io_uring (Linux).
//!
//! A worker runs on its own thread with a `tokio_uring` runtime. It talks to
//! the rest of the program through channels only, so everything outside
//! stays on tokio.

use std::{future::Future, io, sync::OnceLock};

use bitmule_buf::Buf;
use bytes::Bytes;
use tokio::sync::oneshot;
use tokio_uring::buf::{IoBuf, IoBufMut};

/// Submission queue entries asked for: sockets keep thousands of operations outstanding.
const RING_ENTRIES: u32 = 4096;

/// A runtime with a long queue, or with the default one if the kernel will not give that.
fn runtime() -> io::Result<tokio_uring::Runtime> {
    tokio_uring::Runtime::new(&tokio_uring::builder().entries(RING_ENTRIES))
        .or_else(|_| tokio_uring::Runtime::new(&tokio_uring::builder()))
}

/// Is there an io_uring to use? False when the kernel has none, or
/// `BITMULE_NO_IO_URING` is set (the same switch as for file I/O).
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        if std::env::var_os("BITMULE_NO_IO_URING").is_some() {
            return false;
        }
        // on a thread of its own: a runtime must not be built or dropped inside tokio's
        std::thread::spawn(|| runtime().is_ok())
            .join()
            .unwrap_or(false)
    })
}

/// A running io_uring worker. Dropping it stops the worker.
pub struct Stop(#[allow(dead_code)] oneshot::Sender<()>);

/// Run the future `f` makes on a new thread with an io_uring runtime, until
/// it finishes or the returned `Stop` is dropped. In-flight operations are
/// cancelled then.
pub async fn spawn<F, Fut>(name: &str, f: F) -> io::Result<Stop>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let (ready_tx, ready_rx) = oneshot::channel::<io::Result<()>>();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let runtime = match runtime() {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        runtime.block_on(async move {
            let work = f();
            tokio::select! {
                _ = work => {}
                _ = stop_rx => {}
            }
        });
    })?;
    ready_rx.await.map_err(|_| io::Error::other("io_uring thread ended before it started"))??;
    Ok(Stop(stop_tx))
}

/// A pooled buffer as an io_uring buffer. Reads fill it and set its length.
pub struct UBuf<const N: usize>(pub Buf<N>);

// The array is on the heap and does not move while the kernel uses it.
unsafe impl<const N: usize> IoBuf for UBuf<N> {
    fn stable_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.0.len()
    }
    fn bytes_total(&self) -> usize {
        N
    }
}

unsafe impl<const N: usize> IoBufMut for UBuf<N> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.0.array_mut().as_mut_ptr()
    }
    unsafe fn set_init(&mut self, pos: usize) {
        if pos > self.0.len() {
            self.0.set_len(pos);
        }
    }
}

/// Bytes as an io_uring buffer, sent from as they are.
pub struct UBytes(pub Bytes);

// `Bytes` keeps its memory in place until dropped.
unsafe impl IoBuf for UBytes {
    fn stable_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    fn bytes_init(&self) -> usize {
        self.0.len()
    }
    fn bytes_total(&self) -> usize {
        self.0.len()
    }
}

// ---- slab ---------------------------------------------------------------------

/// One allocation cut into equal slots, for the buffers of a socket's send or
/// receive side. It is mapped and touched up front (no page faults while the
/// socket runs) and locked in memory when the process's limit allows, so the
/// kernel's pinned pages never move.
pub struct Slab {
    base: *mut u8,
    len: usize,
    slot: usize,
    locked: bool,
}

// The memory is plain bytes owned by the slab; slots are handed out one at a time.
unsafe impl Send for Slab {}
unsafe impl Sync for Slab {}

impl Slab {
    pub fn new(slot: usize, count: usize) -> io::Result<std::sync::Arc<Slab>> {
        let len = slot * count;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let locked = unsafe { libc::mlock(base, len) } == 0;
        if !locked {
            tracing::debug!("mlock of {len} bytes failed ({}), the buffers are not locked", io::Error::last_os_error());
        }
        Ok(std::sync::Arc::new(Slab { base: base as *mut u8, len, slot, locked }))
    }

    pub fn locked(&self) -> bool {
        self.locked
    }
}

impl Drop for Slab {
    fn drop(&mut self) {
        unsafe {
            if self.locked {
                libc::munlock(self.base as *mut _, self.len);
            }
            libc::munmap(self.base as *mut _, self.len);
        }
    }
}

/// One slot of a slab as an io_uring buffer. The memory stays where it is
/// for as long as the slot (it holds the slab).
pub struct Slot {
    slab: std::sync::Arc<Slab>,
    index: usize,
}

impl Slot {
    fn ptr(&self) -> *mut u8 {
        unsafe { self.slab.base.add(self.index * self.slab.slot) }
    }
}

unsafe impl IoBuf for Slot {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr()
    }
    // the slab is initialized (zeroed pages), so the whole slot counts
    fn bytes_init(&self) -> usize {
        self.slab.slot
    }
    fn bytes_total(&self) -> usize {
        self.slab.slot
    }
}

unsafe impl IoBufMut for Slot {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr()
    }
    unsafe fn set_init(&mut self, _pos: usize) {}
}

/// Most buffers the kernel takes in one registration on older kernels.
const REGISTER_MAX: usize = 1024;

/// The buffers of one direction of a socket: a slab, registered with the ring
/// (the kernel maps the pages once, not for every operation).
pub struct Buffers {
    pool: tokio_uring::buf::fixed::FixedBufPool<Slot>,
    slot: usize,
    registered: bool,
    locked: bool,
}

impl Buffers {
    /// `count` buffers of at least `size` bytes. Must be called inside the
    /// io_uring runtime. If the ring will not register them (old kernel, memory
    /// limit) they are used as ordinary buffers.
    pub fn new(size: usize, count: usize) -> io::Result<Buffers> {
        let slot = size.next_multiple_of(64);
        let slab = Slab::new(slot, count)?;
        let locked = slab.locked();
        let pool = tokio_uring::buf::fixed::FixedBufPool::new((0..count).map(|index| Slot { slab: slab.clone(), index }));
        let registered = match pool.register() {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!("registering {count} buffers: {e} — using them unregistered (the limit on old kernels is {REGISTER_MAX})");
                false
            }
        };
        Ok(Buffers { pool, slot, registered, locked })
    }

    pub fn registered(&self) -> bool {
        self.registered
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    /// A free buffer; waits until one is.
    pub async fn next(&self) -> tokio_uring::buf::fixed::FixedBuf {
        self.pool.next(self.slot).await
    }

    /// Read one datagram from a connected socket into `buf`.
    pub async fn read(
        &self,
        socket: &tokio_uring::net::UdpSocket,
        buf: tokio_uring::buf::fixed::FixedBuf,
    ) -> (io::Result<usize>, tokio_uring::buf::fixed::FixedBuf) {
        if self.registered { socket.read_fixed(buf).await } else { socket.read(buf).await }
    }

    /// Send the first `len` bytes of `buf` on a connected socket.
    pub async fn write(&self, socket: &tokio_uring::net::UdpSocket, buf: tokio_uring::buf::fixed::FixedBuf, len: usize) -> io::Result<usize> {
        use tokio_uring::buf::BoundedBuf;
        let slice = buf.slice(..len);
        if self.registered { socket.write_fixed(slice).await.0 } else { socket.write(slice).submit().await.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slab_buffers_register_and_hold_data() {
        if !available() {
            println!("io_uring not available, skipped");
            return;
        }
        let runtime = runtime().unwrap();
        runtime.block_on(async {
            let buffers = Buffers::new(1187, 4096).unwrap();
            println!("registered: {}, locked: {}", buffers.registered(), buffers.locked());
            let mut a = buffers.next().await;
            let mut b = buffers.next().await;
            assert!(a.len() >= 1187 && a.len() % 64 == 0);
            a[..4].copy_from_slice(&[1, 2, 3, 4]);
            b[..4].copy_from_slice(&[5, 6, 7, 8]);
            assert_eq!(&a[..4], &[1, 2, 3, 4]);
            assert_eq!(&b[..4], &[5, 6, 7, 8]);
        });
    }
}

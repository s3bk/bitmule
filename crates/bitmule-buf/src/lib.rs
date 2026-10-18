//! A pool of fixed size buffers: an array of `N` bytes and the length of what
//! is in it.
//!
//! A `Buf` is meant to be filled once where the data is made and then passed
//! on as it is, through channels and queues, until the last place that needs
//! it (a socket send, say) drops it. Dropping gives the array back to its
//! pool, so steady state allocates nothing. `Buf::into_bytes` hands the same
//! memory to code that wants `bytes::Bytes`, still without a copy: the array
//! goes back to the pool when the last `Bytes` made from it is dropped.

use std::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::Arc,
};

use bytes::Bytes;
use crossbeam_queue::ArrayQueue;

/// A bounded stock of `N` byte arrays. Taking from an empty pool allocates;
/// returning to a full pool frees. Arrays keep whatever they last held.
pub struct Pool<const N: usize> {
    queue: ArrayQueue<Array<N>>,
    /// The memory of a slab pool, which owns all its slots.
    slab: Option<Arc<Region>>,
}

/// An array of a pool: on the heap, or a slot of a slab.
enum Array<const N: usize> {
    Heap(Box<[u8; N]>),
    Slot(NonNull<[u8; N]>, #[allow(dead_code)] Arc<Region>),
}

// A slot is an array nobody else touches while the `Array` exists; the region
// outlives it.
unsafe impl<const N: usize> Send for Array<N> {}
unsafe impl<const N: usize> Sync for Array<N> {}

impl<const N: usize> Array<N> {
    fn get(&self) -> &[u8; N] {
        match self {
            Array::Heap(b) => b,
            Array::Slot(p, _) => unsafe { p.as_ref() },
        }
    }

    fn get_mut(&mut self) -> &mut [u8; N] {
        match self {
            Array::Heap(b) => b,
            Array::Slot(p, _) => unsafe { p.as_mut() },
        }
    }
}

/// Touch the pages at mmap time where the OS can (Linux); elsewhere they fault in on first use.
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAP_POPULATE: libc::c_int = libc::MAP_POPULATE;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const MAP_POPULATE: libc::c_int = 0;

/// One allocation for a slab pool's arrays.
struct Region {
    base: *mut u8,
    len: usize,
    locked: bool,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    /// `len` zeroed bytes, all touched now, and locked in memory if the limits allow.
    #[cfg(unix)]
    fn new(len: usize) -> Region {
        unsafe {
            let base = libc::mmap(
                std::ptr::null_mut(),
                len.max(1),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_POPULATE,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                std::alloc::handle_alloc_error(std::alloc::Layout::from_size_align(len.max(1), 64).unwrap());
            }
            let locked = libc::mlock(base, len) == 0;
            Region { base: base as *mut u8, len, locked }
        }
    }

    #[cfg(not(unix))]
    fn new(len: usize) -> Region {
        let layout = std::alloc::Layout::from_size_align(len.max(1), 64).unwrap();
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        if base.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Region { base, len, locked: false }
    }
}

impl Drop for Region {
    #[cfg(unix)]
    fn drop(&mut self) {
        unsafe {
            if self.locked {
                libc::munlock(self.base as *mut _, self.len);
            }
            libc::munmap(self.base as *mut _, self.len.max(1));
        }
    }

    #[cfg(not(unix))]
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.base, std::alloc::Layout::from_size_align(self.len.max(1), 64).unwrap()) }
    }
}

impl<const N: usize> Pool<N> {
    /// A pool that keeps up to `capacity` arrays, `prefill` of them allocated now.
    pub fn new(capacity: usize, prefill: usize) -> Arc<Self> {
        let pool = Arc::new(Pool { queue: ArrayQueue::new(capacity), slab: None });
        for _ in 0..prefill.min(capacity) {
            let _ = pool.queue.push(Array::Heap(zeroed()));
        }
        pool
    }

    /// A pool of `capacity` arrays in one allocation, made and touched now and
    /// locked in memory when the process's limit allows (see `locked`): no
    /// allocation or page fault later, and the pages stay where they are for
    /// code that registers them with the kernel. Taking from it when all are
    /// out allocates a loose array, which is freed when returned.
    pub fn slab(capacity: usize) -> Arc<Self> {
        let region = Arc::new(Region::new(capacity * N));
        let pool = Pool { queue: ArrayQueue::new(capacity.max(1)), slab: Some(region.clone()) };
        for i in 0..capacity {
            let ptr = unsafe { NonNull::new_unchecked(region.base.add(i * N) as *mut [u8; N]) };
            let _ = pool.queue.push(Array::Slot(ptr, region.clone()));
        }
        Arc::new(pool)
    }

    /// Is a slab pool's memory locked? False for other pools.
    pub fn locked(&self) -> bool {
        self.slab.as_ref().is_some_and(|region| region.locked)
    }

    /// An empty buffer (length 0).
    pub fn get(self: &Arc<Self>) -> Buf<N> {
        let array = self.queue.pop().unwrap_or_else(|| Array::Heap(zeroed()));
        Buf { array: Some(array), len: 0, pool: self.clone() }
    }

    /// A buffer holding a copy of `data` (which must fit).
    pub fn get_from(self: &Arc<Self>, data: &[u8]) -> Buf<N> {
        let mut buf = self.get();
        buf.extend_from_slice(data);
        buf
    }

    /// Arrays at rest in the pool.
    pub fn idle(&self) -> usize {
        self.queue.len()
    }
}

fn zeroed<const N: usize>() -> Box<[u8; N]> {
    // straight from the allocator; no stack temporary for big arrays
    unsafe { Box::new_zeroed().assume_init() }
}

/// An array on loan from a `Pool`, and how much of it is in use. Dereferences
/// to the used part. Gives the array back when dropped.
pub struct Buf<const N: usize> {
    array: Option<Array<N>>,
    len: usize,
    pool: Arc<Pool<N>>,
}

impl<const N: usize> Buf<N> {
    pub const CAPACITY: usize = N;

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Room left after the used part.
    pub fn remaining(&self) -> usize {
        N - self.len
    }

    /// Append `data`. Panics if it does not fit.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        assert!(data.len() <= self.remaining(), "Buf: {} bytes do not fit in {} left", data.len(), self.remaining());
        let at = self.len;
        self.array_mut()[at..at + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    /// The whole array, for filling in place (a read into it, say). Follow
    /// with `set_len`.
    pub fn array_mut(&mut self) -> &mut [u8; N] {
        self.array.as_mut().unwrap().get_mut()
    }

    /// Declare the first `len` bytes to be in use. Panics if `len > N`.
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= N, "Buf: length {len} over capacity {N}");
        self.len = len;
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The same memory as `Bytes`, without a copy. The array returns to the
    /// pool when the last clone or slice of the `Bytes` is dropped.
    pub fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

impl<const N: usize> Drop for Buf<N> {
    fn drop(&mut self) {
        match self.array.take() {
            // a slab pool has room for each of its slots; loose arrays are not kept
            Some(array @ Array::Slot(..)) => {
                let _ = self.pool.queue.push(array);
            }
            Some(array @ Array::Heap(_)) if self.pool.slab.is_none() => {
                let _ = self.pool.queue.push(array);
            }
            _ => {}
        }
    }
}

impl<const N: usize> Deref for Buf<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.array.as_ref().unwrap().get()[..self.len]
    }
}

impl<const N: usize> DerefMut for Buf<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.array.as_mut().unwrap().get_mut()[..len]
    }
}

impl<const N: usize> AsRef<[u8]> for Buf<N> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<const N: usize> std::fmt::Debug for Buf<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Buf<{N}>(len {})", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_dereferences_to_the_used_part() {
        let pool = Pool::<16>::new(2, 0);
        let mut buf = pool.get();
        assert!(buf.is_empty());
        buf.extend_from_slice(b"abc");
        buf.push(b'd');
        assert_eq!(&*buf, b"abcd");
        assert_eq!(buf.remaining(), 12);
    }

    #[test]
    #[should_panic]
    fn overfilling_panics() {
        let pool = Pool::<4>::new(1, 0);
        pool.get_from(b"12345");
    }

    #[test]
    fn arrays_are_recycled() {
        let pool = Pool::<16>::new(2, 0);
        let first = pool.get();
        let ptr = first.array.as_ref().unwrap().get().as_ptr();
        drop(first);
        assert_eq!(pool.idle(), 1);
        assert_eq!(pool.get().array.as_ref().unwrap().get().as_ptr(), ptr);
    }

    #[test]
    fn a_full_pool_frees_the_extra() {
        let pool = Pool::<8>::new(1, 0);
        let (a, b) = (pool.get(), pool.get());
        drop(a);
        drop(b);
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn bytes_keep_the_array_until_the_last_slice_is_gone() {
        let pool = Pool::<16>::new(2, 0);
        let bytes = pool.get_from(b"hello world").into_bytes();
        let tail = bytes.slice(6..);
        drop(bytes);
        assert_eq!(pool.idle(), 0);
        assert_eq!(&tail[..], b"world");
        drop(tail);
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn fill_in_place_with_set_len() {
        let pool = Pool::<8>::new(1, 1);
        let mut buf = pool.get();
        buf.array_mut()[..3].copy_from_slice(b"xyz");
        buf.set_len(3);
        assert_eq!(&*buf, b"xyz");
    }

    #[test]
    fn a_slab_is_one_block_and_overflow_is_loose() {
        let pool = Pool::<64>::slab(4);
        let mut bufs: Vec<_> = (0..4).map(|_| pool.get()).collect();
        let mut starts: Vec<usize> = bufs.iter_mut().map(|b| b.array_mut().as_ptr() as usize).collect();
        starts.sort();
        // slots follow each other in one block
        assert!(starts.windows(2).all(|w| w[1] - w[0] == 64));
        assert_eq!(pool.idle(), 0);

        // a fifth is loose, and is not kept
        let mut extra = pool.get();
        let extra_start = extra.array_mut().as_ptr() as usize;
        assert!(!starts.contains(&extra_start));
        drop(extra);
        assert_eq!(pool.idle(), 0);

        drop(bufs);
        assert_eq!(pool.idle(), 4);
        println!("locked: {}", pool.locked());
    }

    #[test]
    fn slab_bytes_return_their_slot() {
        let pool = Pool::<32>::slab(2);
        let bytes = pool.get_from(b"slab bytes").into_bytes();
        assert_eq!(&bytes[..], b"slab bytes");
        assert_eq!(pool.idle(), 1);
        drop(bytes);
        assert_eq!(pool.idle(), 2);
    }

    #[test]
    fn a_slab_pool_outlives_its_handle_while_buffers_are_out() {
        let pool = Pool::<16>::slab(1);
        let buf = pool.get_from(b"still here");
        drop(pool);
        assert_eq!(&*buf, b"still here");
    }
}

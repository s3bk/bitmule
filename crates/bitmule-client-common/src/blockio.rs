//! File I/O for the fountain pipeline, off the async runtime.
//!
//! As in `raptor-demo`, reading and writing blocks each run on a thread of
//! their own, connected to the rest by bounded channels. On Linux the threads
//! drive io_uring (many writes in flight at once); where io_uring is not
//! available, or on other systems, they fall back to blocking positional I/O.

use std::{fs::File, io, path::PathBuf, sync::Arc, thread::JoinHandle};

use tokio::sync::mpsc;

use crate::fountain::{BLOCK_SIZE, Block, DecodedBlock, Pool, Pooled, SYMBOL_SIZE, SpillSink, Symbol, block_span, num_blocks, read_exact_at, write_all_at};

/// An io_uring runtime, unless there is none or `BITMULE_NO_IO_URING` is set
/// (to run on the blocking fallback).
#[cfg(target_os = "linux")]
fn uring_runtime() -> Option<tokio_uring::Runtime> {
    if std::env::var_os("BITMULE_NO_IO_URING").is_some() {
        return None;
    }
    tokio_uring::Runtime::new(&tokio_uring::builder()).ok()
}

/// Writes in flight at once.
const WRITES_IN_FLIGHT: usize = 16;
/// Blocks read ahead of the encoder.
const READ_AHEAD: usize = 4;
/// Blocks queued for writing.
const WRITE_QUEUE: usize = 16;

pub struct ReadBlock {
    /// Which pass over the file this block belongs to.
    pub pass: u32,
    pub block_nr: u32,
    /// The plaintext is in the first `len` bytes.
    pub buf: Block,
    pub len: usize,
}

/// Read the file block by block, pass after pass, forever: a sender keeps
/// producing fresh symbols until it is told to stop. Stops when the
/// receiver is dropped.
pub fn read_blocks(
    path: PathBuf,
    size: u64,
    pool: Arc<Pool<BLOCK_SIZE>>,
) -> mpsc::Receiver<io::Result<ReadBlock>> {
    let (tx, rx) = mpsc::channel(READ_AHEAD);
    std::thread::Builder::new().name("bitmule-read".into()).spawn(move || {
        #[cfg(target_os = "linux")]
        if let Some(runtime) = uring_runtime() {
            return runtime.block_on(uring::read_blocks(path, size, pool, tx));
        }
        read_blocks_blocking(path, size, pool, tx)
    }).expect("spawning the reader thread");
    rx
}

fn read_blocks_blocking(
    path: PathBuf,
    size: u64,
    pool: Arc<Pool<BLOCK_SIZE>>,
    tx: mpsc::Sender<io::Result<ReadBlock>>,
) {
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) => {
            let _ = tx.blocking_send(Err(e));
            return;
        }
    };
    if num_blocks(size) == 0 {
        return;
    }
    for pass in 0u32.. {
        for block_nr in 0..num_blocks(size) {
            let (offset, len) = block_span(size, block_nr);
            let mut buf = pool.get();
            let result = read_exact_at(&file, &mut buf[..len], offset)
                .map(|()| ReadBlock { pass, block_nr, buf, len });
            let failed = result.is_err();
            if tx.blocking_send(result).is_err() || failed {
                return;
            }
        }
    }
}

enum WriteJob {
    Block(DecodedBlock),
    Bytes { offset: u64, data: bytes::Bytes },
}

impl WriteJob {
    fn offset(&self) -> u64 {
        match self {
            WriteJob::Block(block) => block.offset(),
            WriteJob::Bytes { offset, .. } => *offset,
        }
    }
    fn data(&self) -> &[u8] {
        match self {
            WriteJob::Block(block) => block.data(),
            WriteJob::Bytes { data, .. } => data,
        }
    }
}

/// Writes decoded blocks and byte ranges to their place in the output file.
pub struct BlockWriter {
    tx: mpsc::Sender<WriteJob>,
    thread: JoinHandle<io::Result<()>>,
}

impl BlockWriter {
    pub fn spawn(file: Arc<File>) -> Self {
        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        let thread = std::thread::Builder::new().name("bitmule-write".into()).spawn(move || {
            #[cfg(target_os = "linux")]
            if let Some(runtime) = uring_runtime() {
                return runtime.block_on(uring::write_blocks(file, rx));
            }
            write_blocks_blocking(file, rx)
        }).expect("spawning the writer thread");
        BlockWriter { tx, thread }
    }

    /// Queue a block; blocks while the queue is full. Call from a thread
    /// that may block. Errors if the writer has stopped (see `finish`).
    pub fn write(&self, block: DecodedBlock) -> io::Result<()> {
        self.tx.blocking_send(WriteJob::Block(block))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "block writer stopped"))
    }

    /// Queue bytes for `offset`; waits while the queue is full. For async callers.
    pub async fn write_bytes(&self, offset: u64, data: bytes::Bytes) -> io::Result<()> {
        self.tx.send(WriteJob::Bytes { offset, data }).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "block writer stopped"))
    }

    /// Wait until everything queued is written.
    pub fn finish(self) -> io::Result<()> {
        drop(self.tx);
        self.thread.join().unwrap_or_else(|_| Err(io::Error::other("block writer panicked")))
    }
}

fn write_blocks_blocking(file: Arc<File>, mut rx: mpsc::Receiver<WriteJob>) -> io::Result<()> {
    while let Some(job) = rx.blocking_recv() {
        write_all_at(&file, job.data(), job.offset())?;
    }
    Ok(())
}


// ---- spilling incomplete blocks ----------------------------------------------

/// Spilled symbols that were asked for have been read back.
pub struct Loaded {
    pub block_nr: u32,
    pub symbols: io::Result<Vec<(u32, Symbol)>>,
}

/// Spilled stores allowed in flight; the decoder waits beyond that.
const STORES_IN_FLIGHT: usize = 4;
/// Requests queued for the spill thread.
const SPILL_QUEUE: usize = 8;

enum Request {
    Store { block_nr: u32, symbols: Vec<(u32, Symbol)> },
    Load { block_nr: u32 },
}

#[derive(Clone, Copy)]
enum Place {
    /// In the output file, in the block's own gap.
    Gap(u64),
    /// In the overflow file.
    Overflow(u64),
}

/// Who has which symbol where. Only the dispatcher touches it.
struct SpillIndex {
    transfer_size: u64,
    overflow_len: u64,
    blocks: std::collections::HashMap<u32, Vec<(u32, Place)>>,
}

impl SpillIndex {
    /// Give each symbol a place: first the gap of the block, then the overflow.
    fn place_store(&mut self, block_nr: u32, symbols: Vec<(u32, Symbol)>) -> Vec<(Place, Symbol)> {
        let (gap, len) = block_span(self.transfer_size, block_nr);
        let slots = len / SYMBOL_SIZE;
        let mut entries = Vec::with_capacity(symbols.len());
        let mut placed = Vec::with_capacity(symbols.len());
        for (i, (esi, symbol)) in symbols.into_iter().enumerate() {
            let place = if i < slots {
                Place::Gap(gap + (i * SYMBOL_SIZE) as u64)
            } else {
                let at = self.overflow_len;
                self.overflow_len += SYMBOL_SIZE as u64;
                Place::Overflow(at)
            };
            entries.push((esi, place));
            placed.push((place, symbol));
        }
        self.blocks.insert(block_nr, entries);
        placed
    }

    fn take(&mut self, block_nr: u32) -> Vec<(u32, Place)> {
        self.blocks.remove(&block_nr).unwrap_or_default()
    }
}

enum Job {
    Store(Vec<(Place, Symbol)>),
    Load { block_nr: u32, places: Vec<(u32, Place)> },
}

/// What the workers of the spill thread share.
struct SpillShared {
    out: Arc<File>,
    overflow: Arc<File>,
    symbols: Arc<Pool<SYMBOL_SIZE>>,
    loaded: mpsc::UnboundedSender<Loaded>,
}

/// Spills incomplete blocks into the output file, in the gap where the
/// finished block will end up (the block rewrites it when it completes).
/// What does not fit in the gap goes to an extra file.
///
/// All of it happens on threads of its own: the decoder only queues requests
/// (`Decoder::push` never waits for the disk), and answers arrive on the
/// `loaded` channel. Each block with something to do gets a worker of its
/// own, so reading one block back holds up only that block; the others keep
/// being stored and loaded meanwhile. Requests for one block run in order.
pub struct FileSpill {
    tx: mpsc::Sender<Request>,
}

impl FileSpill {
    pub fn spawn(
        out: Arc<File>,
        transfer_size: u64,
        symbols: Arc<Pool<SYMBOL_SIZE>>,
        loaded: mpsc::UnboundedSender<Loaded>,
    ) -> io::Result<Self> {
        let shared = SpillShared { out, overflow: Arc::new(tempfile::tempfile()?), symbols, loaded };
        let index = SpillIndex { transfer_size, overflow_len: 0, blocks: Default::default() };
        let (tx, rx) = mpsc::channel(SPILL_QUEUE);
        std::thread::Builder::new().name("bitmule-spill".into()).spawn(move || {
            #[cfg(target_os = "linux")]
            if let Some(runtime) = uring_runtime() {
                return runtime.block_on(uring::spill(shared, index, rx));
            }
            spill_blocking(shared, index, rx)
        })?;
        Ok(FileSpill { tx })
    }
}

impl SpillSink for FileSpill {
    fn store(&mut self, block_nr: u32, symbols: Vec<(u32, Symbol)>) -> io::Result<()> {
        self.tx.blocking_send(Request::Store { block_nr, symbols }).map_err(|_| spill_stopped())
    }
    fn load(&mut self, block_nr: u32) -> io::Result<Option<Vec<(u32, Symbol)>>> {
        self.tx.blocking_send(Request::Load { block_nr }).map_err(|_| spill_stopped())?;
        Ok(None)
    }
}

fn spill_stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "spill thread stopped")
}

fn file_for<'a>(shared: &'a SpillShared, place: Place) -> (&'a File, u64) {
    match place {
        Place::Gap(at) => (&shared.out, at),
        Place::Overflow(at) => (&shared.overflow, at),
    }
}

/// The fallback: a thread per block with work, blocking I/O.
fn spill_blocking(shared: SpillShared, mut index: SpillIndex, mut rx: mpsc::Receiver<Request>) {
    use std::sync::{Mutex, mpsc as std_mpsc};

    let shared = Arc::new(shared);
    // a token per store in flight
    let (token_tx, token_rx) = std_mpsc::sync_channel::<()>(STORES_IN_FLIGHT);
    let token_rx = Arc::new(Mutex::new(token_rx));
    let mut workers: std::collections::HashMap<u32, std_mpsc::Sender<Job>> = Default::default();

    let spawn_worker = |shared: Arc<SpillShared>, token_rx: Arc<Mutex<std_mpsc::Receiver<()>>>| {
        let (tx, rx) = std_mpsc::channel::<Job>();
        std::thread::spawn(move || {
            let mut failed: Option<(io::ErrorKind, String)> = None;
            while let Ok(job) = rx.recv() {
                match job {
                    Job::Store(places) => {
                        for (place, symbol) in &places {
                            let (file, at) = file_for(&shared, *place);
                            if let Err(e) = write_all_at(file, &symbol[..], at) {
                                failed.get_or_insert((e.kind(), e.to_string()));
                            }
                        }
                        drop(places);
                        let _ = token_rx.lock().unwrap().recv();
                    }
                    Job::Load { block_nr, places } => {
                        let symbols = match &failed {
                            Some((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
                            None => places.iter().map(|&(esi, place)| {
                                let (file, at) = file_for(&shared, place);
                                let mut symbol = shared.symbols.get();
                                read_exact_at(file, &mut symbol[..], at).map(|()| (esi, symbol))
                            }).collect(),
                        };
                        let _ = shared.loaded.send(Loaded { block_nr, symbols });
                        break; // the block is back in memory
                    }
                }
            }
        });
        tx
    };

    while let Some(request) = rx.blocking_recv() {
        match request {
            Request::Store { block_nr, symbols } => {
                let placed = index.place_store(block_nr, symbols);
                if token_tx.send(()).is_err() {
                    return;
                }
                let worker = workers.entry(block_nr)
                    .or_insert_with(|| spawn_worker(shared.clone(), token_rx.clone()));
                let _ = worker.send(Job::Store(placed));
            }
            Request::Load { block_nr } => {
                let places = index.take(block_nr);
                let worker = workers.remove(&block_nr)
                    .unwrap_or_else(|| spawn_worker(shared.clone(), token_rx.clone()));
                let _ = worker.send(Job::Load { block_nr, places });
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod uring {
    use super::*;
    use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
    use tokio_uring::buf::{BoundedBuf, IoBuf, IoBufMut};

    /// A pooled buffer as an io_uring buffer.
    struct UringBuf<const N: usize>(Pooled<N>);

    // The buffer lives on the heap and does not move while the kernel uses it.
    unsafe impl<const N: usize> IoBuf for UringBuf<N> {
        fn stable_ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
        fn bytes_init(&self) -> usize {
            N
        }
        fn bytes_total(&self) -> usize {
            N
        }
    }
    unsafe impl<const N: usize> IoBufMut for UringBuf<N> {
        fn stable_mut_ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        unsafe fn set_init(&mut self, _pos: usize) {
            // pooled buffers are always initialized
        }
    }

    /// Bytes as an io_uring buffer, written from as they are.
    struct UringBytes(bytes::Bytes);

    // `Bytes` keeps its memory in place until dropped.
    unsafe impl IoBuf for UringBytes {
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

    pub async fn read_blocks(
        path: PathBuf,
        size: u64,
        pool: Arc<Pool<BLOCK_SIZE>>,
        tx: mpsc::Sender<io::Result<ReadBlock>>,
    ) {
        let file = match tokio_uring::fs::File::open(&path).await {
            Ok(file) => file,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        if num_blocks(size) == 0 {
            return;
        }
        for pass in 0u32.. {
            for block_nr in 0..num_blocks(size) {
                let (offset, len) = block_span(size, block_nr);
                let (result, slice) = file.read_exact_at(UringBuf(pool.get()).slice(..len), offset).await;
                let result = result.map(|()| ReadBlock { pass, block_nr, buf: slice.into_inner().0, len });
                let failed = result.is_err();
                if tx.send(result).await.is_err() || failed {
                    return;
                }
            }
        }
    }

    pub async fn spill(shared: SpillShared, mut index: SpillIndex, mut rx: mpsc::Receiver<Request>) {
        use std::{collections::HashMap, rc::Rc};
        use tokio::sync::{Semaphore, mpsc::unbounded_channel};

        let open = |file: &File| file.try_clone().map(tokio_uring::fs::File::from_std);
        let (out, overflow) = match (open(&shared.out), open(&shared.overflow)) {
            (Ok(out), Ok(overflow)) => (Rc::new(out), Rc::new(overflow)),
            (Err(e), _) | (_, Err(e)) => {
                // answer every load with the error
                while let Some(request) = rx.recv().await {
                    if let Request::Load { block_nr } = request {
                        let _ = shared.loaded.send(Loaded { block_nr, symbols: Err(io::Error::new(e.kind(), e.to_string())) });
                    }
                }
                return;
            }
        };
        let (symbols, loaded) = (shared.symbols.clone(), shared.loaded.clone());
        let stores = Arc::new(Semaphore::new(STORES_IN_FLIGHT));

        // one task per block with work, fed through a channel
        let spawn_worker = || {
            let (tx, mut rx) = unbounded_channel::<(Job, Option<tokio::sync::OwnedSemaphorePermit>)>();
            let (out, overflow) = (out.clone(), overflow.clone());
            let (symbols, loaded) = (symbols.clone(), loaded.clone());
            tokio_uring::spawn(async move {
                let file_for = |place: Place| match place {
                    Place::Gap(at) => (out.clone(), at),
                    Place::Overflow(at) => (overflow.clone(), at),
                };
                let mut failed: Option<(io::ErrorKind, String)> = None;
                while let Some((job, permit)) = rx.recv().await {
                    match job {
                        Job::Store(places) => {
                            let mut writes = FuturesUnordered::new();
                            for (place, symbol) in places {
                                let (file, at) = file_for(place);
                                writes.push(async move { file.write_all_at(UringBuf(symbol), at).await.0 });
                            }
                            while let Some(result) = writes.next().await {
                                if let Err(e) = result {
                                    failed.get_or_insert((e.kind(), e.to_string()));
                                }
                            }
                            drop(permit);
                        }
                        Job::Load { block_nr, places } => {
                            let symbols = match &failed {
                                Some((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
                                None => {
                                    let mut reads = FuturesUnordered::new();
                                    for (esi, place) in places {
                                        let (file, at) = file_for(place);
                                        let buf = UringBuf(symbols.get());
                                        reads.push(async move {
                                            let (result, buf) = file.read_exact_at(buf, at).await;
                                            result.map(|()| (esi, buf.0))
                                        });
                                    }
                                    let mut all = vec![];
                                    let mut error = None;
                                    while let Some(result) = reads.next().await {
                                        match result {
                                            Ok(entry) => all.push(entry),
                                            Err(e) => { error.get_or_insert(e); }
                                        }
                                    }
                                    match error { Some(e) => Err(e), None => Ok(all) }
                                }
                            };
                            let _ = loaded.send(Loaded { block_nr, symbols });
                            break; // the block is back in memory
                        }
                    }
                }
            });
            tx
        };

        let mut workers: HashMap<u32, _> = HashMap::new();
        while let Some(request) = rx.recv().await {
            match request {
                Request::Store { block_nr, symbols } => {
                    let placed = index.place_store(block_nr, symbols);
                    let Ok(permit) = stores.clone().acquire_owned().await else { return };
                    let worker = workers.entry(block_nr).or_insert_with(&spawn_worker);
                    let _ = worker.send((Job::Store(placed), Some(permit)));
                }
                Request::Load { block_nr } => {
                    let places = index.take(block_nr);
                    let worker = workers.remove(&block_nr).unwrap_or_else(&spawn_worker);
                    let _ = worker.send((Job::Load { block_nr, places }, None));
                }
            }
        }
    }

    pub async fn write_blocks(file: Arc<File>, mut rx: mpsc::Receiver<WriteJob>) -> io::Result<()> {
        let file = match file.try_clone() {
            Ok(file) => tokio_uring::fs::File::from_std(file),
            Err(e) => return Err(e),
        };
        let mut first_error = None;
        let mut note = |result: io::Result<()>| {
            if let Err(e) = result {
                first_error.get_or_insert(e);
            }
        };

        let mut pending = FuturesUnordered::new();
        let mut open = true;
        loop {
            tokio::select! {
                block = rx.recv(), if open => match block {
                    Some(job) => {
                        let offset = job.offset();
                        match job {
                            WriteJob::Block(block) => {
                                let (buf, len) = block.into_parts();
                                pending.push(file.write_all_at(UringBuf(buf).slice(..len), offset).map(|(result, _buf)| result).boxed_local());
                            }
                            WriteJob::Bytes { data, .. } => {
                                pending.push(file.write_all_at(UringBytes(data), offset).map(|(result, _buf)| result).boxed_local());
                            }
                        }
                        // as in the demo: keep a bounded number in flight
                        while pending.len() >= WRITES_IN_FLIGHT {
                            note(pending.next().await.unwrap());
                        }
                    }
                    None => open = false,
                },
                Some(result) = pending.next(), if !pending.is_empty() => note(result),
                else => break,
            }
        }
        // `rx` is dropped here, which makes `BlockWriter::write` fail after an error
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fountain::{BLOCK_PLAIN, Decoder, Encoder, MemSpill, symbol_pool};
    use bitmule_crypto::BulkKey;
    use std::io::Write;

    fn data(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| i.wrapping_mul(2654435761) as u8).collect()
    }

    /// Not a failure when the machine has no io_uring (the blocking fallback
    /// runs then), but say which one the other tests exercised.
    #[cfg(target_os = "linux")]
    #[test]
    fn reports_whether_io_uring_is_available() {
        match uring_runtime() {
            Some(_) => println!("io_uring: in use"),
            None => println!("io_uring: not in use (unavailable or BITMULE_NO_IO_URING set), the blocking fallback runs"),
        }
    }

    #[tokio::test]
    async fn reads_blocks_pass_after_pass() {
        let size = BLOCK_PLAIN + 100;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&data(size)).unwrap();

        let pool = Pool::new(8, 2);
        let mut rx = read_blocks(file.path().to_path_buf(), size as u64, pool);
        let plain = data(size);
        for (pass, block_nr) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
            let block = rx.recv().await.unwrap().unwrap();
            assert_eq!((block.pass, block.block_nr), (pass, block_nr));
            let (start, len) = block_span(size as u64, block_nr);
            assert_eq!(block.len, len);
            assert_eq!(&block.buf[..len], &plain[start as usize..start as usize + len]);
        }
    }

    #[tokio::test]
    async fn writes_blocks_where_they_belong() {
        let key = BulkKey::random();
        let size = BLOCK_PLAIN * 2 + 4321;
        let plain = data(size);

        // encode all blocks, decode them back, in reverse order
        let encoder = Encoder::new();
        let mut decoded = vec![];
        let mut decoder = Decoder::new(key.clone(), size as u64, Box::new(MemSpill::default()), symbol_pool());
        for block_nr in (0..num_blocks(size as u64)).rev() {
            let (start, len) = block_span(size as u64, block_nr);
            let mut buf = encoder.block_buffer();
            buf[..len].copy_from_slice(&plain[start as usize..start as usize + len]);
            for frame in encoder.encode_block(&key, block_nr, buf, len).unwrap().frames(0) {
                if let Some(block) = decoder.push(&frame[3..]).unwrap() {
                    decoded.push(block);
                }
            }
        }
        assert_eq!(decoded.len(), 3);

        let out = Arc::new(tempfile::tempfile().unwrap());
        let writer = BlockWriter::spawn(out.clone());
        tokio::task::spawn_blocking(move || {
            for block in decoded {
                writer.write(block).unwrap();
            }
            writer.finish().unwrap();
        }).await.unwrap();

        let mut got = vec![0u8; size];
        read_exact_at(&out, &mut got, 0).unwrap();
        assert_eq!(got, plain);
    }

    fn marked_symbols(pool: &Arc<Pool<SYMBOL_SIZE>>, n: u32) -> Vec<(u32, Symbol)> {
        (0..n).map(|i| {
            let mut symbol = pool.get();
            symbol.fill(i as u8 ^ 0x5a);
            (i * 2, symbol)
        }).collect()
    }

    #[tokio::test]
    async fn spill_fills_the_gap_then_overflows() {
        let size = BLOCK_PLAIN * 2;
        let out = Arc::new(tempfile::tempfile().unwrap());
        let pool = crate::fountain::symbol_pool();
        let (loaded_tx, mut loaded_rx) = mpsc::unbounded_channel();
        let spill = FileSpill::spawn(out.clone(), size as u64, pool.clone(), loaded_tx).unwrap();

        let slots = (BLOCK_PLAIN / SYMBOL_SIZE) as u32;
        let n = slots + 5;
        let (loaded, gap) = tokio::task::spawn_blocking(move || {
            let mut spill = spill;
            spill.store(1, marked_symbols(&pool, n)).unwrap();
            assert!(spill.load(1).unwrap().is_none()); // arrives on the channel
            (loaded_rx.blocking_recv().unwrap(), out)
        }).await.unwrap();

        let mut symbols = loaded.symbols.unwrap();
        assert_eq!(loaded.block_nr, 1);
        symbols.sort_by_key(|(esi, _)| *esi);
        assert_eq!(symbols.len() as u32, n);
        for (i, (esi, symbol)) in symbols.iter().enumerate() {
            assert_eq!(*esi, i as u32 * 2);
            assert!(symbol.iter().all(|&b| b == (i as u8 ^ 0x5a)));
        }
        // the first symbol sits at the start of block 1's gap
        let mut first = vec![0u8; SYMBOL_SIZE];
        read_exact_at(&gap, &mut first, BLOCK_PLAIN as u64).unwrap();
        assert!(first.iter().all(|&b| b == 0x5a));
    }

    /// Loading one block back does not hold up another block's decoding.
    #[tokio::test]
    async fn decoding_goes_on_while_a_block_is_read_back() {
        let key = BulkKey::random();
        let size = BLOCK_PLAIN * 3;
        let plain = data(size);
        let encoder = Encoder::new();
        let frames_of = |block_nr: u32, pass: u32| {
            let (start, len) = block_span(size as u64, block_nr);
            let mut buf = encoder.block_buffer();
            buf[..len].copy_from_slice(&plain[start as usize..start as usize + len]);
            encoder.encode_block(&key, block_nr, buf, len).unwrap().frames(pass)
        };
        let b0 = frames_of(0, 0);
        let b1 = frames_of(1, 0);
        let b2 = frames_of(2, 0);

        let out = Arc::new(tempfile::tempfile().unwrap());
        let pool = crate::fountain::symbol_pool();
        let (loaded_tx, mut loaded_rx) = mpsc::unbounded_channel();
        let spill = FileSpill::spawn(out, size as u64, pool.clone(), loaded_tx).unwrap();
        let mut decoder = Decoder::new(key.clone(), size as u64, Box::new(spill), pool).with_blocks_in_memory(1);

        tokio::task::spawn_blocking(move || {
            let payload = |f: &bytes::Bytes| f[3..].to_vec();
            // half of block 0, then block 1 starts, which spills block 0
            for f in &b0[..100] { assert!(decoder.push(&payload(f)).unwrap().is_none()); }
            for f in &b1[..10] { assert!(decoder.push(&payload(f)).unwrap().is_none()); }
            // the rest of block 0 triggers its read-back; block 2 completes meanwhile
            for f in &b0[100..] {
                decoder.push(&payload(f)).unwrap();
            }
            let mut done = vec![];
            for f in &b2 {
                if let Some(block) = decoder.push(&payload(f)).unwrap() { done.push(block.block_nr); }
            }
            assert_eq!(done, vec![2]);
            // block 1 completes too; then block 0, once its symbols are back
            for f in &b1[10..] {
                if let Some(block) = decoder.push(&payload(f)).unwrap() { done.push(block.block_nr); }
            }
            // blocks 0 and 1 were spilled; they finish as their symbols come back
            while !decoder.is_complete() {
                let loaded = loaded_rx.blocking_recv().unwrap();
                if let Some(block) = decoder.loaded(loaded.block_nr, loaded.symbols.unwrap()).unwrap() {
                    let (start, len) = block_span(size as u64, block.block_nr);
                    assert_eq!(block.data(), &plain[start as usize..start as usize + len]);
                    done.push(block.block_nr);
                }
            }
            done.sort();
            assert_eq!(done, vec![0, 1, 2]);
        }).await.unwrap();
    }
}

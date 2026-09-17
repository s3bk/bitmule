

const KB: usize = 1024;
const MB: usize = 1024 * 1024;
const BLOCK_SIZE: usize = 2 * MB;
const SYMBOL_SIZE: usize = 8 * KB;
const N_SYMBOLS: usize = BLOCK_SIZE / SYMBOL_SIZE;

use std::{collections::HashSet, io, iter::once, mem::replace, ops::Deref, path::{Path, PathBuf}, sync::Arc};

use crossbeam::queue::ArrayQueue;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use raptor_demo::tracked_await;
use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation, SourceBlockDecoder, SourceBlockEncoder, SourceBlockEncodingPlan, SourceBlockStorage, Symbol, ZeroInit};
use serde::{Deserialize, Serialize};
use tokio::{select, spawn, sync::{Semaphore, mpsc}, time::Instant};
use tokio_uring::{buf::{BoundedBuf, BoundedBufMut, IoBuf, IoBufMut}, fs::{File, OpenOptions}};
use anyhow::{Context, Error, anyhow, bail};
use clap::Parser;
use xxhash_rust::xxh3::xxh3_64;
use serde_with::serde_as;

#[derive(Parser, Debug)]
#[command(about = "RaptorQ block-fountain demo (encode -> lossy channel -> decode -> verify)")]
struct Cli {
    /// Input file to transmit
    #[arg(long)]
    input: PathBuf,

    /// Path to write the reconstructed file to
    #[arg(long)]
    output: PathBuf,

    #[arg(long)]
    partial: PathBuf,

    /// Independent random drop probability per encoded packet [0.0, 1.0)
    #[arg(long, default_value_t = 0.10)]
    loss: f64,

    /// How many extra packets (beyond K per block) the encoder is allowed to emit
    /// before giving up on that block. In practice RaptorQ decodes with ~2%
    /// overhead so a small multiple of K is plenty.
    #[arg(long, default_value_t = 4)]
    overhead_factor: u32,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
struct SymbolBuffer {
    #[serde_as(as = "Box<[_; SYMBOL_SIZE]>")]
    inner: Box<[u8; SYMBOL_SIZE]>
}
impl SymbolBuffer {
    fn new() -> Self {
        SymbolBuffer { inner: make_buffer() }
    }
}
impl Drop for SymbolBuffer {
    fn drop(&mut self) {
        panic!();
    }
}
impl AsRef<[u8]> for SymbolBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &*self.inner
    }
}
impl AsMut<[u8]> for SymbolBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut *self.inner
    }
}
impl ZeroInit for SymbolBuffer {
    #[inline]
    fn zero_init(_size: usize) -> Self {
        SymbolBuffer { inner: make_buffer() }
    }
}
struct BlockBuffer {
    inner: Box<[u8; BLOCK_SIZE]>,
}
impl AsMut<[u8]> for BlockBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut *self.inner
    }
}
struct BufferSlice {
    buffer: Box<[u8; BLOCK_SIZE]>,
    len: usize
}
unsafe impl IoBuf for BufferSlice {
    #[inline]
    fn stable_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }
    #[inline]
    fn bytes_init(&self) -> usize {
        self.len
    }
    #[inline]
    fn bytes_total(&self) -> usize {
        BLOCK_SIZE
    }
}
unsafe impl IoBufMut for BufferSlice {
    #[inline]
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr()
    }

    #[inline]
    unsafe fn set_init(&mut self, pos: usize) {
        self.len = pos;
    }
}
impl BlockBuffer {
    fn new() -> Self {
        BlockBuffer { inner: make_buffer() }
    }
    #[inline]
    fn slice(self, len: usize) -> BufferSlice {
        let BlockBuffer { inner } = self;
        BufferSlice { buffer: inner, len }
    }
}
impl BufferSlice {
    #[inline]
    fn into_inner(self) -> (BlockBuffer, usize) {
        let BufferSlice { buffer, len } = self;
        (BlockBuffer { inner: buffer }, len)
    }
    #[inline]
    pub fn padded(self) -> BlockBuffer {
        let BufferSlice { mut buffer, len } = self;
        if len < BLOCK_SIZE {
            buffer[len..].fill(0);
        }
        BlockBuffer { inner: buffer }
    }
}
impl Deref for BlockBuffer {
    type Target = [u8; BLOCK_SIZE];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

struct InputBlock {
    block_nr: u64,
    data: BlockBuffer,
    hash: u64,
}

async fn read_loop(input: PathBuf, input_size: u64, tx: mpsc::Sender<InputBlock>, pool: BlockPool) -> Result<(), Error> {
    let file = File::open(&input).await?;
    let n_blocks = div_ceil(input_size, BLOCK_SIZE as u64);

    // TODO: fetch a few in parallel using FututesOrdered
    for n in 0 .. n_blocks {
        let buffer = pool.pop().ok_or(anyhow!("Out of buffers"))?;
        let offset = BLOCK_SIZE as u64 * n;
        let size = (input_size - offset).min(BLOCK_SIZE as u64) as usize;
        let slice = buffer.slice(size);
        let (res, slice) = tracked_await!(file.read_at(slice, offset), "read block from disk");
        match res {
            Ok(n) if n == size => {}
            _ => bail!("failed to read buffer {n}")
        }
        let data = slice.padded();

        let hash = block_hash(&*data);
        tracked_await!(tx.send(InputBlock { block_nr: n, data, hash }), "send block")?;
    }
    Ok(())
}

async fn encode_loop(mut rx: mpsc::Receiver<InputBlock>, tx: mpsc::Sender<Packet>, block_pool: BlockPool, overhead: u32, symbol_pool: SymbolPool) -> Result<(), Error> {
    let plan = SourceBlockEncodingPlan::generate(N_SYMBOLS as u16);
    let config = ObjectTransmissionInformation::new(0, SYMBOL_SIZE as u16, 0, 1, 1);

    while let Some(InputBlock { block_nr, data, hash }) = tracked_await!(rx.recv(), "receive block") {
        let encoder = SourceBlockEncoder::with_encoding_plan(1, &config, &*data, &plan);
        block_pool.push(data).map_err(|_| anyhow!("BlockPool full"))?;

        let packets = encoder.repair_packets_with(0, N_SYMBOLS as u32 + overhead, |_| symbol_pool.pop().unwrap());

        for data in packets {
            tx.send(Packet { block_nr, data, hash  }).await?;
        }
    }

    Ok(())
}

fn reset_storage(storage: &mut SourceBlockStorage<SymbolBuffer>, symbol_pool: &SymbolPool) {
    let dispose = |buf| {
        let _ = symbol_pool.push(buf);
    };
    for s in storage.source_symbols.iter_mut() {
        if let Some(s) = s.take() {
            dispose(s.into_inner());
        }
    }
    for s in storage.repair_packets.drain(..) {
        dispose(s.split().1);
    }
}

async fn decode_loop(mut rx: mpsc::Receiver<Packet>, partial_tx: mpsc::Sender<PartialBlock>, complete_tx: mpsc::Sender<CompleteBlock>, num_blocks: usize, symbol_pool: SymbolPool, block_pool: BlockPool) -> Result<(), Error> {
    let config = ObjectTransmissionInformation::new(0, SYMBOL_SIZE as u16, 0, 1, 1);

    const ELEMENTS: u64 = N_SYMBOLS as u64 * SYMBOL_SIZE as u64;
    let mut decoder = SourceBlockDecoder::new(1, &config, ELEMENTS);
    let mut storage = SourceBlockStorage::<SymbolBuffer>::new(&config, ELEMENTS);
    let mut last_block = 0;
    let mut block_complete = false;
    let mut complete = HashSet::with_capacity(num_blocks);
    let dispose_symbol = |buf| {
        let _ = symbol_pool.push(buf);
    };
    let alloc_block = |_| block_pool.pop().unwrap();

    while let Some(Packet { block_nr, data, hash }) = tracked_await!(rx.recv(), "recv packet") {
        //println!("{block_nr}:{}", data.payload_id().encoding_symbol_id());
        if complete.contains(&block_nr) {
            continue;
        }
        if block_nr != last_block {
            if block_complete {
                decoder = SourceBlockDecoder::new(1, &config, ELEMENTS);
                reset_storage(&mut storage, &symbol_pool);
                block_complete = false;
            } else {
                let partial = replace(&mut storage,  SourceBlockStorage::<SymbolBuffer>::new(&config, ELEMENTS));
                partial_tx.send(PartialBlock { block_nr, storage: partial }).await?;
            }
        }
        last_block = block_nr;
        if let Some(data) = decoder.decode_with(&mut storage, once(data), dispose_symbol, alloc_block) {
            tracked_await!(complete_tx.send(CompleteBlock { block_nr, data, hash }), "send output block").context("complete_tx.send")?;
            block_complete = true;
            complete.insert(block_nr);
            if complete.len() == num_blocks {
                break;
            }
        }
    }
    reset_storage(&mut storage, &symbol_pool);

    if complete.len() != num_blocks {
        bail!("transfer incomplete {}/{}", complete.len(), num_blocks);
    }

    Ok(())
}

struct PartialBlock {
    block_nr: u64,
    storage: SourceBlockStorage<SymbolBuffer>,
}
struct CompleteBlock {
    block_nr: u64,
    data: BlockBuffer,
    hash: u64,
}
fn block_hash(data: &[u8; BLOCK_SIZE]) -> u64 {
    xxh3_64(data)
}

async fn save_output(mut rx: mpsc::Receiver<CompleteBlock>, output_file: PathBuf, file_size: u64, block_pool: BlockPool) -> Result<(), Error> {
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&output_file)?;
    file.set_len(file_size)?;
    let file = File::from_std(file);

    let process_result = |(block_nr, r, buf): (u64, Result<(), io::Error>, BufferSlice)| {
        match r {
            Err(e) => println!("save output {block_nr}: {e:?}"),
            Ok(()) => {}
        }
        let (buf, len) = buf.into_inner();
        let _ = block_pool.push(buf);
    };

    let mut pending = FuturesUnordered::new();
    loop {
        select!{
            Some(CompleteBlock { block_nr, data, hash }) = rx.recv(), if !rx.is_closed() => {
                if block_hash(&data) != hash {
                    bail!("incorrect block {block_nr}");
                }
                let pos = block_nr * BLOCK_SIZE as u64;
                let remaining = file_size - pos;
                let slice = data.slice(remaining.min(BLOCK_SIZE as u64) as usize);

                pending.push(file.write_all_at(slice, pos).map(move |(r, buf)| (block_nr, r, buf)));

                if pending.len() > 16 {
                    process_result(pending.next().await.unwrap());
                }
            }
            Some(r) = pending.next(), if !pending.is_empty() => {
                process_result(r);
            }
            else => {
                break
            }
        }
    }

    println!("save_output exit");

    Ok(())
}

async fn save_decoder(mut rx: mpsc::Receiver<PartialBlock>, dir: &Path, symbol_pool: SymbolPool) -> Result<(), Error> {
    // this needs to be implemented much differently
    let mut pending = FuturesUnordered::new();

    loop {
        select!{
            Some(PartialBlock { block_nr, mut storage }) = rx.recv(), if !rx.is_closed() => {
                let data = postcard::to_stdvec(&storage).unwrap();
                let f_name = dir.join(format!("decoder_{block_nr}.data"));
                pending.push(async move {
                    let file = match File::create(f_name).await {
                        Ok(file) => file,
                        Err(err) => return (block_nr, Err(err.into())),
                    };
                    let (r, buf) = file.write_all_at(data, 0).await;
                    (block_nr, r)
                });
                reset_storage(&mut storage, &symbol_pool);
            }
            Some((block_nr, r)) = pending.next(), if !pending.is_empty() => {
                match r {
                    Err(e) => println!("save decoder {block_nr}: {e:?}"),
                    Ok(()) => {}
                }
            }
            else => {
                break
            }
        }
    }
    Ok(())
}

struct Packet {
    block_nr: u64,
    data: raptorq::EncodingPacket<SymbolBuffer>,
    hash: u64,
}

type BlockPool = Arc<ArrayQueue<BlockBuffer>>;
type SymbolPool = Arc<ArrayQueue<SymbolBuffer>>;

fn make_pool<T>(n: usize, init: impl Fn() -> T) -> Arc<ArrayQueue<T>> {
    let pool = Arc::new(ArrayQueue::new(n));
    for _ in 0..n {
        pool.push(init()).ok();
    }
    pool
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let args = Cli::parse();
    std::fs::create_dir_all(&args.partial)?;
    let block_pool = make_pool(10 + 16, BlockBuffer::new);

    let packet_ch_cap = 4 * 1024;
    let partial_ch_cap = 16;
    let n_symbol_allocs = packet_ch_cap + (N_SYMBOLS + args.overhead_factor as usize) * (partial_ch_cap + 4);
    let symbol_pool = make_pool(n_symbol_allocs, SymbolBuffer::new);

    let input_size = std::fs::metadata(&args.input)?.len();
    let num_blocks = div_ceil(input_size, BLOCK_SIZE as u64);

    let (input_tx, input_rx) = mpsc::channel(4);
    let (packet_tx, packet_rx) = mpsc::channel(packet_ch_cap);
    let (partial_tx, partial_rx) = mpsc::channel(16);
    let (complete_tx, complete_rx) = mpsc::channel(16);

    let block_pool2 = block_pool.clone();
    let block_pool3 = block_pool.clone();
    let block_pool4 = block_pool.clone();
    let symbol_pool2 = symbol_pool.clone();
    let symbol_pool3 = symbol_pool.clone();
    let symbol_pool4 = symbol_pool.clone();
    let symbol_pool5 = symbol_pool.clone();

    let start = Instant::now();
    let t_read = std::thread::spawn(move || {
        tokio_uring::start(read_loop(args.input, input_size, input_tx, block_pool))
    });

    let t_encode = spawn(encode_loop(input_rx, packet_tx, block_pool2, args.overhead_factor, symbol_pool2));
    let t_decode = spawn(decode_loop(packet_rx, partial_tx, complete_tx, num_blocks as usize, symbol_pool3, block_pool4));
    let t_partial = std::thread::spawn(move || {
        tokio_uring::start(save_decoder(partial_rx, &args.partial, symbol_pool4))
    });
    let t_complete = std::thread::spawn(move || {
        tokio_uring::start(save_output(complete_rx, args.output, input_size, block_pool3))
    });

    let mut ok = true;
    ok &= print_err(t_decode.await?, "decode_loop");
    ok &= print_err(t_partial.join().unwrap(), "save_decoder");
    ok &= print_err(t_complete.join().unwrap(), "save_output");
    ok &= print_err(t_encode.await?, "encode_loop");
    ok &= print_err(t_read.join().unwrap(), "read_loop");

    let elapsed = start.elapsed().as_secs_f64();
    if ok {
        println!("{elapsed:.2}s,  {:.2} MB/s", input_size as f64 / (MB as f64 * elapsed));
    }

    std::mem::forget(symbol_pool5);

    raptor_demo::await_tracker::print_report();
    Ok(())
}
fn print_err(r: Result<(), Error>, label: &str) -> bool {
    match r {
        Err(e) => {
            println!("ERROR {label}: {e}");
            false
        }
        Ok(()) => true
    }
}
fn div_ceil<T: Copy + From<u8> + std::ops::Add<Output = T> + std::ops::Sub<Output = T> + std::ops::Div<Output = T>>(a: T, b: T) -> T {
    (a + (b - 1u8.into())) / b
}

struct BufferPool<const N: usize> {
    buffers: Vec<Box<[u8; N]>>
}
impl<const N: usize> BufferPool<N> {
    pub fn new(capacity: usize) -> Self {
        BufferPool {
            buffers: Vec::with_capacity(capacity)
        }
    }
    pub fn get(&mut self) -> Box<[u8; N]> {
        self.buffers.pop().unwrap_or_else(make_buffer)
    }
}

fn make_buffer<const N: usize>() -> Box<[u8; N]> {
    unsafe {
        Box::new_zeroed().assume_init()
    }
}

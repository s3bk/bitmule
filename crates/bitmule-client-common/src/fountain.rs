//! Fountain coding (RaptorQ) of a transfer for the relay path.
//!
//! The data is cut into blocks of `BLOCK_PLAIN` bytes. Each block is
//! encrypted with the bulk key (AES-GCM, nonce from the block number), which
//! makes it exactly `BLOCK_SIZE` bytes, and then RaptorQ coded into
//! `N_SYMBOLS` source symbols plus any number of repair symbols. Any
//! `N_SYMBOLS` (plus a little) distinct symbols of a block rebuild it, so a
//! receiver does not care which frames it misses.
//!
//! Parameters match `raptor-demo`: 2 MiB blocks, 8 KiB symbols. As there,
//! the hot path works on pooled buffers (`Pool`): blocks, symbols and frames
//! are recycled instead of allocated, and a frame goes from the encoder to
//! the network without being copied.
//!
//! Sending order: block by block. Pass 0 sends every source symbol and
//! `FIRST_PASS_REPAIR` repair symbols per block; each later pass sends
//! `LATER_PASS_REPAIR` fresh repair symbols per block. Block by block keeps a
//! receiver's partial state small.
//!
//! Frame (this is also what the relay carries):
//! `len: u16 LE | type | block_nr: u32 LE | block hash: u64 LE | payload id (4) | symbol`.
//!
//! The block hash is the first 8 bytes of the BLAKE3 hash of the block as
//! coded (the ciphertext). Every frame of a block carries it, as in
//! `raptor-demo`: a receiver checks a decoded block against it before
//! decrypting, so a corrupt symbol or a decoder problem is caught at the
//! block, with the cause in the error. The sender also lists the hashes of
//! all blocks in the manifest (`Decoder::with_block_hashes`): then a frame
//! that announces anything else is refused, so whoever carries the frames
//! cannot make the receiver misjudge a block by being first with a false hash.

use std::{collections::{HashMap, HashSet}, ops::{Deref, DerefMut}, sync::Arc};

use anyhow::{Result, bail, ensure};
use bitmule_core::protocol::relay_frame::{F_DATA, FRAME_SIZE_BYTES};
use bitmule_crypto::BulkKey;
use bytes::{Buf, Bytes, BytesMut};
use crossbeam_queue::ArrayQueue;
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder, SourceBlockEncodingPlan, SourceBlockStorage,
};

pub const KB: usize = 1024;
pub const SYMBOL_SIZE: usize = 8 * KB;
pub const BLOCK_SIZE: usize = 2 * 1024 * KB;
pub const N_SYMBOLS: usize = BLOCK_SIZE / SYMBOL_SIZE;
const TAG_SIZE: usize = 16;
/// Plaintext bytes per block (the AEAD tag takes the rest).
pub const BLOCK_PLAIN: usize = BLOCK_SIZE - TAG_SIZE;

pub const FIRST_PASS_REPAIR: u32 = 16;
pub const LATER_PASS_REPAIR: u32 = 32;

/// All blocks use this RaptorQ source block number; the block number of the
/// transfer travels in our own frame header.
const SBN: u8 = 1;
/// `len | type`
const RELAY_HEADER: usize = FRAME_SIZE_BYTES + 1;
const HASH_OFFSET: usize = RELAY_HEADER + 4;
const ID_OFFSET: usize = HASH_OFFSET + 8;
const SYMBOL_OFFSET: usize = ID_OFFSET + 4;
/// What the relay frame's length field covers: the header and the symbol.
pub const PAYLOAD_SIZE: usize = SYMBOL_HEADER + SYMBOL_SIZE;
/// A payload starts with `block_nr: u32 | block hash: u64 | payload id (4)`.
pub const SYMBOL_HEADER: usize = 4 + 8 + 4;

/// A symbol payload split into its header and its symbol, as
/// `Decoder::push_symbol` takes it.
pub struct SymbolPacket {
    pub header: [u8; SYMBOL_HEADER],
    pub symbol: Symbol,
}

fn block_hash(coded_block: &[u8]) -> u64 {
    let hash = blake3::hash(coded_block);
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
}

/// The most block hashes a manifest carries: 8 bytes each, which with a
/// 2 MiB block is 8 MiB of manifest for a 2 TiB transfer. A larger transfer
/// goes without (the server's message limit is what bounds this).
pub const MAX_MANIFEST_HASHES: usize = 1 << 20;

/// The hashes of all blocks of the transfer in `file` (`size` bytes) as they
/// are sent under `key`, for the manifest. `None` if the transfer has more
/// blocks than a manifest carries.
#[cfg(not(target_arch = "wasm32"))]
pub fn block_hashes(file: &std::fs::File, size: u64, key: &BulkKey) -> Result<Option<Vec<u64>>> {
    let blocks = num_blocks(size) as usize;
    if blocks > MAX_MANIFEST_HASHES {
        return Ok(None);
    }
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut hashes = Vec::with_capacity(blocks);
    for block_nr in 0..blocks as u32 {
        let (start, len) = block_span(size, block_nr);
        read_exact_at(file, &mut buf[..len], start)?;
        buf[len..BLOCK_PLAIN].fill(0);
        let (data, tag) = buf.split_at_mut(BLOCK_PLAIN);
        tag.copy_from_slice(&key.encrypt_chunk_in_place(block_nr as u64, data)?);
        hashes.push(block_hash(&buf));
    }
    Ok(Some(hashes))
}
pub const FRAME_SIZE: usize = RELAY_HEADER + PAYLOAD_SIZE;

fn config() -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::new(0, SYMBOL_SIZE as u16, 0, 1, 1)
}

/// The symbol payload of a relay frame (what `Decoder::push` takes), without
/// the frame's length and type bytes. No copy.
pub fn frame_payload(frame: &Bytes) -> Bytes {
    frame.slice(RELAY_HEADER..)
}

pub fn num_blocks(transfer_size: u64) -> u32 {
    transfer_size.div_ceil(BLOCK_PLAIN as u64) as u32
}

/// Offset and length of block `block_nr` in the plaintext.
pub fn block_span(transfer_size: u64, block_nr: u32) -> (u64, usize) {
    let start = block_nr as u64 * BLOCK_PLAIN as u64;
    (start, (transfer_size - start).min(BLOCK_PLAIN as u64) as usize)
}

// ---- buffer pools ----------------------------------------------------------

/// A bounded stock of `N` byte buffers. Taking from an empty pool allocates;
/// returning to a full pool frees. Buffers keep whatever they last held.
pub struct Pool<const N: usize> {
    queue: ArrayQueue<Box<[u8; N]>>,
}

impl<const N: usize> Pool<N> {
    /// A pool that keeps up to `capacity` buffers, `prefill` of them allocated now.
    pub fn new(capacity: usize, prefill: usize) -> Arc<Self> {
        let pool = Arc::new(Pool { queue: ArrayQueue::new(capacity) });
        for _ in 0..prefill.min(capacity) {
            let _ = pool.queue.push(zeroed());
        }
        pool
    }

    pub fn get(self: &Arc<Self>) -> Pooled<N> {
        let buf = self.queue.pop().unwrap_or_else(zeroed);
        Pooled { buf: Some(buf), pool: self.clone() }
    }
}

fn zeroed<const N: usize>() -> Box<[u8; N]> {
    // straight from the allocator; no stack temporary for big buffers
    unsafe { Box::new_zeroed().assume_init() }
}

/// A buffer on loan from a `Pool`; returns itself when dropped.
pub struct Pooled<const N: usize> {
    buf: Option<Box<[u8; N]>>,
    pool: Arc<Pool<N>>,
}

impl<const N: usize> Drop for Pooled<N> {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            let _ = self.pool.queue.push(buf);
        }
    }
}
impl<const N: usize> Deref for Pooled<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] { self.buf.as_ref().unwrap() }
}
impl<const N: usize> DerefMut for Pooled<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] { self.buf.as_mut().unwrap() }
}
impl<const N: usize> AsRef<[u8]> for Pooled<N> {
    fn as_ref(&self) -> &[u8] { &**self }
}
impl<const N: usize> AsMut<[u8]> for Pooled<N> {
    fn as_mut(&mut self) -> &mut [u8] { &mut **self }
}
impl<const N: usize> Clone for Pooled<N> {
    fn clone(&self) -> Self {
        let mut copy = self.pool.get();
        copy.copy_from_slice(&**self);
        copy
    }
}

pub type Block = Pooled<BLOCK_SIZE>;
pub type Symbol = Pooled<SYMBOL_SIZE>;
type FrameBuf = Pooled<FRAME_SIZE>;

// ---- encoding --------------------------------------------------------------

pub struct Encoder {
    plan: SourceBlockEncodingPlan,
    config: ObjectTransmissionInformation,
    blocks: Arc<Pool<BLOCK_SIZE>>,
    frames: Arc<Pool<FRAME_SIZE>>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            plan: SourceBlockEncodingPlan::generate(N_SYMBOLS as u16),
            config: config(),
            blocks: Pool::new(16, 4),
            // the frames in flight between the encoder and the network
            frames: Pool::new(2048, 512),
        }
    }

    /// A buffer to read a block's plaintext into (the first `BLOCK_PLAIN`
    /// bytes are used), then hand to `encode_block`.
    pub fn block_buffer(&self) -> Block {
        self.blocks.get()
    }

    /// The pool `block_buffer` draws from, for a reader running elsewhere.
    pub fn block_pool(&self) -> Arc<Pool<BLOCK_SIZE>> {
        self.blocks.clone()
    }

    /// Encrypt and code a block. `buf[..plain_len]` holds the plaintext; a
    /// short (last) block is zero padded.
    pub fn encode_block(&self, key: &BulkKey, block_nr: u32, mut buf: Block, plain_len: usize) -> Result<EncodedBlock> {
        ensure!(plain_len <= BLOCK_PLAIN, "block too large");
        buf[plain_len..BLOCK_PLAIN].fill(0);
        let (data, tag) = buf.split_at_mut(BLOCK_PLAIN);
        tag.copy_from_slice(&key.encrypt_chunk_in_place(block_nr as u64, data)?);

        let hash = block_hash(&buf[..]);
        // the encoder copies the symbols it needs
        let encoder = SourceBlockEncoder::with_encoding_plan(SBN, &self.config, &buf[..], &self.plan);
        Ok(EncodedBlock { block_nr, hash, encoder, ciphertext: buf, frames: self.frames.clone() })
    }
}

impl Default for Encoder {
    fn default() -> Self { Self::new() }
}

pub struct EncodedBlock {
    block_nr: u32,
    hash: u64,
    encoder: SourceBlockEncoder,
    ciphertext: Block,
    frames: Arc<Pool<FRAME_SIZE>>,
}

/// A frame buffer seen as just its symbol, as the encoder wants it.
struct SymbolSlot(FrameBuf);
impl AsRef<[u8]> for SymbolSlot {
    fn as_ref(&self) -> &[u8] { &self.0[SYMBOL_OFFSET..] }
}
impl AsMut<[u8]> for SymbolSlot {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.0[SYMBOL_OFFSET..] }
}

/// A finished frame, seen whole; goes into `Bytes` without a copy.
struct WholeFrame(FrameBuf);
impl AsRef<[u8]> for WholeFrame {
    fn as_ref(&self) -> &[u8] { &self.0[..] }
}

fn finish_frame(mut frame: FrameBuf, block_nr: u32, hash: u64, id: PayloadId) -> Bytes {
    frame[..FRAME_SIZE_BYTES].copy_from_slice(&(PAYLOAD_SIZE as u16).to_le_bytes());
    frame[FRAME_SIZE_BYTES] = F_DATA;
    frame[RELAY_HEADER..HASH_OFFSET].copy_from_slice(&block_nr.to_le_bytes());
    frame[HASH_OFFSET..ID_OFFSET].copy_from_slice(&hash.to_le_bytes());
    frame[ID_OFFSET..SYMBOL_OFFSET].copy_from_slice(&id.serialize());
    Bytes::from_owner(WholeFrame(frame))
}

impl EncodedBlock {
    /// The hash of the block as coded, which every frame of it announces.
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// The relay frames of `pass`. Passes never repeat a symbol.
    pub fn frames(self, pass: u32) -> Vec<Bytes> {
        self.frames_with(pass, FIRST_PASS_REPAIR, LATER_PASS_REPAIR)
    }

    /// Like `frames`, with the number of repair symbols of the first pass
    /// (after the source symbols) and of each later pass given. A sender that
    /// knows the loss to expect sizes these to cover it: with `first_repair`
    /// = 15% of `N_SYMBOLS`, the receiver rebuilds the block from the first
    /// pass alone as long as under about 13% of the symbols are lost.
    pub fn frames_with(self, pass: u32, first_repair: u32, later_repair: u32) -> Vec<Bytes> {
        let EncodedBlock { block_nr, hash, encoder, ciphertext, frames } = self;
        let mut out = Vec::with_capacity(N_SYMBOLS + first_repair as usize);

        let (start, count) = if pass == 0 {
            // source symbols are the ciphertext itself
            for (i, symbol) in ciphertext.chunks_exact(SYMBOL_SIZE).enumerate() {
                let mut frame = frames.get();
                frame[SYMBOL_OFFSET..].copy_from_slice(symbol);
                out.push(finish_frame(frame, block_nr, hash, PayloadId::new(SBN, i as u32)));
            }
            (0, first_repair)
        } else {
            (first_repair + (pass - 1) * later_repair, later_repair)
        };
        drop(ciphertext);

        let repair = encoder.repair_packets_with(start, count, |_| SymbolSlot(frames.get()));
        for packet in repair {
            let (id, SymbolSlot(frame)) = packet.split();
            out.push(finish_frame(frame, block_nr, hash, id));
        }
        out
    }
}

// ---- decoding --------------------------------------------------------------

/// Where the symbols of partially decoded blocks go when too many blocks are
/// in memory. Must not block the decoder for long: `store` only queues the
/// write, and `load` may deliver its result later.
pub trait SpillSink: Send {
    /// Take the symbols (`esi`, symbol) of `block_nr` to write out.
    fn store(&mut self, block_nr: u32, symbols: Vec<(u32, Symbol)>) -> std::io::Result<()>;
    /// Ask for the symbols of `block_nr` back. `Some` if they are at hand,
    /// `None` if they will arrive later; pass them to `Decoder::loaded`.
    fn load(&mut self, block_nr: u32) -> std::io::Result<Option<Vec<(u32, Symbol)>>>;
}

/// Keeps spilled symbols in memory. For tests.
#[derive(Default)]
pub struct MemSpill(HashMap<u32, Vec<(u32, Symbol)>>);

impl SpillSink for MemSpill {
    fn store(&mut self, block_nr: u32, symbols: Vec<(u32, Symbol)>) -> std::io::Result<()> {
        self.0.insert(block_nr, symbols);
        Ok(())
    }
    fn load(&mut self, block_nr: u32) -> std::io::Result<Option<Vec<(u32, Symbol)>>> {
        Ok(Some(self.0.remove(&block_nr).unwrap_or_default()))
    }
}

pub fn symbol_pool() -> Arc<Pool<SYMBOL_SIZE>> {
    Pool::new((PARTIAL_BLOCKS_IN_MEMORY + 1) * (N_SYMBOLS + 64), 2 * N_SYMBOLS)
}

#[cfg(not(target_arch = "wasm32"))]
pub use native_io::{read_exact_at, write_all_at};

#[cfg(not(target_arch = "wasm32"))]
mod native_io {
    use std::{fs::File, io};

    /// Write at an offset without touching the file's cursor.
    pub fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            return file.write_all_at(buf, offset);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            while !buf.is_empty() {
                let n = file.seek_write(buf, offset)?;
                buf = &buf[n..];
                offset += n as u64;
            }
            return Ok(());
        }
    }

    /// Read exactly `buf.len()` bytes at an offset.
    pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            return file.read_exact_at(buf, offset);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            while !buf.is_empty() {
                let n = file.seek_read(buf, offset)?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                buf = &mut buf[n..];
                offset += n as u64;
            }
            return Ok(());
        }
    }
}

/// How many partially decoded blocks stay in memory (about 2 MiB each).
pub const PARTIAL_BLOCKS_IN_MEMORY: usize = 4;

struct Partial {
    decoder: SourceBlockDecoder,
    storage: SourceBlockStorage<Symbol>,
    /// Last time this block saw a symbol; the oldest is spilled first.
    touched: u64,
}

impl Partial {
    fn new() -> Self {
        let config = config();
        Partial {
            decoder: SourceBlockDecoder::new(SBN, &config, BLOCK_SIZE as u64),
            storage: SourceBlockStorage::new(&config, BLOCK_SIZE as u64),
            touched: 0,
        }
    }

    /// Forget everything, keeping the allocations (as `raptor-demo` does).
    fn reset(&mut self) {
        self.decoder = SourceBlockDecoder::new(SBN, &config(), BLOCK_SIZE as u64);
        // the symbols go back to their pool
        self.storage.source_symbols.iter_mut().for_each(|s| *s = None);
        self.storage.repair_packets.clear();
    }

    /// Take every received symbol out, leaving the partial reset.
    fn drain(&mut self) -> Vec<(u32, Symbol)> {
        let mut out = Vec::with_capacity(N_SYMBOLS + 32);
        for (esi, symbol) in self.storage.source_symbols.iter_mut().enumerate() {
            if let Some(symbol) = symbol.take() {
                out.push((esi as u32, symbol.into_inner()));
            }
        }
        for packet in self.storage.repair_packets.drain(..) {
            let (id, symbol) = packet.split();
            out.push((id.encoding_symbol_id(), symbol));
        }
        self.reset();
        out
    }
}

/// A decoded block, in a pooled buffer.
pub struct DecodedBlock {
    pub block_nr: u32,
    buf: Block,
    len: usize,
}

impl DecodedBlock {
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Where this block belongs in the plaintext.
    pub fn offset(&self) -> u64 {
        self.block_nr as u64 * BLOCK_PLAIN as u64
    }
    /// The pooled buffer (plaintext in its first `len` bytes) and `len`, to
    /// hand to an I/O layer that wants to own the buffer.
    pub fn into_parts(self) -> (Block, usize) {
        (self.buf, self.len)
    }
}

/// Blocks come out in the order they complete, which is not the block
/// order. Blocks that are still short of symbols when memory runs out are
/// handed to the `SpillSink`; the decoder does not wait for the disk. If more
/// symbols arrive for a spilled block meanwhile, they are held back until the
/// spilled ones are loaded.
pub struct Decoder {
    key: BulkKey,
    transfer_size: u64,
    partial: HashMap<u32, Partial>,
    /// Reset partials, ready for the next block.
    free: Vec<Partial>,
    spilled: HashSet<u32>,
    /// Blocks being loaded back, with the symbols that arrived meanwhile.
    loading: HashMap<u32, Vec<(u32, Symbol)>>,
    /// The block hash announced for every block in progress.
    announced: HashMap<u32, u64>,
    /// The hashes the manifest lists, if it does.
    expected: Option<Vec<u64>>,
    spill: Box<dyn SpillSink>,
    in_memory: usize,
    tick: u64,
    done: HashSet<u32>,
    blocks: Arc<Pool<BLOCK_SIZE>>,
    symbols: Arc<Pool<SYMBOL_SIZE>>,
}

impl Decoder {
    /// `symbols` is where the decoder takes its symbol buffers from; a
    /// `SpillSink` that loads symbols back should draw from the same pool.
    pub fn new(key: BulkKey, transfer_size: u64, spill: Box<dyn SpillSink>, symbols: Arc<Pool<SYMBOL_SIZE>>) -> Self {
        Decoder {
            key,
            transfer_size,
            partial: HashMap::new(),
            free: Vec::new(),
            spilled: HashSet::new(),
            loading: HashMap::new(),
            announced: HashMap::new(),
            expected: None,
            spill,
            in_memory: PARTIAL_BLOCKS_IN_MEMORY,
            tick: 0,
            done: HashSet::new(),
            blocks: Pool::new(16, 4),
            symbols,
        }
    }

    /// The hash of every block, from the manifest. Frames that announce a
    /// different hash for their block are refused. Panics unless there is one
    /// hash per block of the transfer: check `block_hashes.len()` first.
    pub fn with_block_hashes(mut self, block_hashes: Vec<u64>) -> Self {
        assert_eq!(block_hashes.len(), num_blocks(self.transfer_size) as usize, "one hash per block");
        self.expected = Some(block_hashes);
        self
    }

    pub fn with_blocks_in_memory(mut self, n: usize) -> Self {
        self.in_memory = n.max(1);
        self
    }

    /// The blocks decoded so far, in order.
    pub fn done_blocks(&self) -> Vec<u32> {
        let mut done: Vec<u32> = self.done.iter().copied().collect();
        done.sort_unstable();
        done
    }

    pub fn is_complete(&self) -> bool {
        self.done.len() == num_blocks(self.transfer_size) as usize
    }

    fn feed(&self, partial: &mut Partial, esi: u32, symbol: Symbol) -> Option<Block> {
        let packet = EncodingPacket::new(PayloadId::new(SBN, esi), symbol);
        // dropped symbols go back to their pool by themselves
        partial.decoder.decode_with(&mut partial.storage, [packet], drop, |_| self.blocks.get())
    }

    /// Feed one frame payload (without the relay header). Returns a block
    /// once it is complete. Symbols of finished blocks are ignored.
    pub fn push(&mut self, payload: &[u8]) -> Result<Option<DecodedBlock>> {
        ensure!(payload.len() == PAYLOAD_SIZE, "bad symbol frame length {}", payload.len());
        let mut symbol = self.symbols.get();
        symbol.copy_from_slice(&payload[SYMBOL_HEADER..]);
        self.push_symbol(payload[..SYMBOL_HEADER].try_into().unwrap(), symbol)
    }

    /// Like `push`, with the payload already split: its header and its symbol,
    /// which the decoder takes over as it is (no copy). A receiver that
    /// reassembles symbols from datagrams can write them into a `Symbol` of
    /// its own to begin with.
    pub fn push_symbol(&mut self, header: &[u8; SYMBOL_HEADER], symbol: Symbol) -> Result<Option<DecodedBlock>> {
        let block_nr = u32::from_le_bytes(header[..4].try_into().unwrap());
        ensure!(block_nr < num_blocks(self.transfer_size), "block {block_nr} out of range");
        if self.done.contains(&block_nr) {
            return Ok(None);
        }
        let hash = u64::from_le_bytes(header[4..12].try_into().unwrap());
        if let Some(expected) = &self.expected {
            ensure!(hash == expected[block_nr as usize], "block {block_nr}: symbol announces a hash that is not the manifest's");
        }
        let id = PayloadId::deserialize(header[12..16].try_into().unwrap());
        ensure!(id.source_block_number() == SBN, "unexpected source block number");
        match self.announced.entry(block_nr) {
            std::collections::hash_map::Entry::Vacant(e) => { e.insert(hash); }
            std::collections::hash_map::Entry::Occupied(e) => {
                ensure!(*e.get() == hash, "block {block_nr}: symbol announces another block hash");
            }
        }

        self.tick += 1;
        let esi = id.encoding_symbol_id();

        if let Some(waiting) = self.loading.get_mut(&block_nr) {
            if waiting.len() < 2 * N_SYMBOLS {
                waiting.push((esi, symbol));
            }
            return Ok(None);
        }
        if self.spilled.remove(&block_nr) {
            return match self.spill.load(block_nr)? {
                Some(stored) => self.resume(block_nr, stored, vec![(esi, symbol)]),
                None => {
                    self.loading.insert(block_nr, vec![(esi, symbol)]);
                    Ok(None)
                }
            };
        }

        let mut partial = match self.partial.remove(&block_nr) {
            Some(partial) => partial,
            None => self.free.pop().unwrap_or_else(Partial::new),
        };
        partial.touched = self.tick;
        let finished = self.feed(&mut partial, esi, symbol);
        self.after_feed(block_nr, partial, finished)
    }

    /// The symbols a `SpillSink` was asked to `load` have arrived.
    pub fn loaded(&mut self, block_nr: u32, stored: Vec<(u32, Symbol)>) -> Result<Option<DecodedBlock>> {
        let waiting = self.loading.remove(&block_nr).unwrap_or_default();
        self.resume(block_nr, stored, waiting)
    }

    /// Continue a block from its spilled symbols plus those that came since.
    fn resume(&mut self, block_nr: u32, stored: Vec<(u32, Symbol)>, extra: Vec<(u32, Symbol)>) -> Result<Option<DecodedBlock>> {
        let mut partial = self.free.pop().unwrap_or_else(Partial::new);
        partial.touched = self.tick;
        let mut finished = None;
        for (esi, symbol) in stored.into_iter().chain(extra) {
            if finished.is_none() {
                finished = self.feed(&mut partial, esi, symbol);
            }
        }
        self.after_feed(block_nr, partial, finished)
    }

    fn after_feed(&mut self, block_nr: u32, mut partial: Partial, finished: Option<Block>) -> Result<Option<DecodedBlock>> {
        let Some(mut buf) = finished else {
            self.partial.insert(block_nr, partial);
            self.spill_excess()?;
            return Ok(None);
        };
        partial.reset();
        self.free.push(partial);
        let hash = self.announced.remove(&block_nr).expect("a block in progress has an announced hash");

        let found = block_hash(&buf[..]);
        if found != hash {
            // the symbols are gone; later symbols start the block afresh
            bail!("block {block_nr}: decoded to hash {found:016x}, expected {hash:016x} (corrupt symbol or decoder fault)");
        }

        let (data, tag) = buf.split_at_mut(BLOCK_PLAIN);
        self.key.decrypt_chunk_in_place(block_nr as u64, data, (&*tag).try_into().unwrap())?;
        self.done.insert(block_nr);
        Ok(Some(DecodedBlock { block_nr, buf, len: block_span(self.transfer_size, block_nr).1 }))
    }

    /// Spill the least recently used partial blocks until few enough remain.
    fn spill_excess(&mut self) -> Result<()> {
        while self.partial.len() > self.in_memory {
            let (&victim, _) = self.partial.iter().min_by_key(|(_, p)| p.touched).unwrap();
            let mut partial = self.partial.remove(&victim).unwrap();
            let symbols = partial.drain();
            self.free.push(partial);
            self.spill.store(victim, symbols)?;
            self.spilled.insert(victim);
        }
        Ok(())
    }
}

/// Wrap a payload in the relay's frame header (`len: u16 LE`, type, payload).
pub fn relay_frame(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(FRAME_SIZE_BYTES + 1 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(&[F_DATA]);
    frame.extend_from_slice(payload);
    frame.freeze()
}

/// Cuts the relay's byte stream back into frame payloads.
#[derive(Default)]
pub struct FrameSplitter {
    buf: BytesMut,
}

impl FrameSplitter {
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>> {
        self.buf.extend_from_slice(bytes);
        let mut payloads = vec![];
        while self.buf.len() >= FRAME_SIZE_BYTES + 1 {
            let len = u16::from_le_bytes(self.buf[..FRAME_SIZE_BYTES].try_into().unwrap()) as usize;
            if self.buf.len() < FRAME_SIZE_BYTES + 1 + len {
                break;
            }
            let frame_type = self.buf[FRAME_SIZE_BYTES];
            if frame_type != F_DATA {
                bail!("unexpected relay frame type {frame_type}");
            }
            self.buf.advance(FRAME_SIZE_BYTES + 1);
            payloads.push(self.buf.split_to(len).freeze());
        }
        Ok(payloads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| i.wrapping_mul(2654435761) as u8).collect()
    }

    fn encode(encoder: &Encoder, key: &BulkKey, plain: &[u8], size: usize, block_nr: u32, pass: u32) -> Vec<Bytes> {
        let (start, len) = block_span(size as u64, block_nr);
        let mut buf = encoder.block_buffer();
        buf[..len].copy_from_slice(&plain[start as usize..start as usize + len]);
        encoder.encode_block(key, block_nr, buf, len).unwrap().frames(pass)
    }

    /// Feed passes of every block, dropping every `drop_every`th frame, until
    /// the decoder is done. Returns the reassembled data and passes needed.
    fn run(size: usize, drop_every: usize, in_memory: usize, key: &BulkKey, dec_key: BulkKey) -> (Vec<u8>, u32) {
        run_with(size, drop_every, in_memory, key, dec_key, Box::new(MemSpill::default()))
    }

    fn run_with(size: usize, drop_every: usize, in_memory: usize, key: &BulkKey, dec_key: BulkKey, spill: Box<dyn SpillSink>) -> (Vec<u8>, u32) {
        let plain = data(size);
        let encoder = Encoder::new();
        let mut decoder = Decoder::new(dec_key, size as u64, spill, symbol_pool()).with_blocks_in_memory(in_memory);
        let mut out = vec![0u8; size];
        let mut n = 0usize;
        for pass in 0..10 {
            for b in 0..num_blocks(size as u64) {
                for frame in encode(&encoder, key, &plain, size, b, pass) {
                    n += 1;
                    if drop_every != 0 && n % drop_every == 0 {
                        continue;
                    }
                    if let Some(block) = decoder.push(&frame[RELAY_HEADER..]).unwrap() {
                        let (start, len) = block_span(size as u64, block.block_nr);
                        assert_eq!(block.data().len(), len);
                        out[start as usize..start as usize + len].copy_from_slice(block.data());
                    }
                }
            }
            if decoder.is_complete() {
                return (out, pass + 1);
            }
        }
        panic!("did not complete");
    }

    #[test]
    fn lossless_one_pass_with_short_last_block() {
        let key = BulkKey::random();
        let size = BLOCK_PLAIN * 2 + 12345;
        let (out, passes) = run(size, 0, 4, &key, key.clone());
        assert_eq!(out, data(size));
        assert_eq!(passes, 1);
    }

    #[test]
    fn heavy_loss_needs_more_passes() {
        let key = BulkKey::random();
        let size = BLOCK_PLAIN + 1000;
        let (out, passes) = run(size, 4, 4, &key, key.clone()); // 25% loss
        assert_eq!(out, data(size));
        assert!(passes > 1);
    }

    /// More incomplete blocks than fit in memory: they go through the spill store.
    #[test]
    fn incomplete_blocks_are_spilled_and_resumed() {
        let key = BulkKey::random();
        let size = BLOCK_PLAIN * 3 - 5;
        // 25% loss leaves every block short after pass 0; one block fits in memory
        let (out, passes) = run(size, 4, 1, &key, key.clone());
        assert_eq!(out, data(size));
        assert!(passes > 1);
    }

    /// A corrupt symbol is caught by the block hash, and the block can be
    /// decoded again afterwards.
    #[test]
    fn corrupt_symbol_is_caught_by_the_block_hash() {
        let key = BulkKey::random();
        let encoder = Encoder::new();
        let plain = data(3000);
        let frames = encode(&encoder, &key, &plain, 3000, 0, 0);
        let mut decoder = Decoder::new(key.clone(), 3000, Box::new(MemSpill::default()), symbol_pool());

        let mut error = None;
        for frame in &frames {
            let mut payload = frame[RELAY_HEADER..].to_vec();
            if payload[16..].len() == SYMBOL_SIZE && frame.as_ptr() == frames[7].as_ptr() {
                payload[100] ^= 0xff;
            }
            match decoder.push(&payload) {
                Err(e) => { error = Some(e.to_string()); break; }
                Ok(Some(_)) => panic!("a corrupt block was accepted"),
                Ok(None) => {}
            }
        }
        assert!(error.unwrap().contains("hash"));

        let mut block = None;
        for frame in &frames {
            if let Some(b) = decoder.push(&frame[RELAY_HEADER..]).unwrap() {
                block = Some(b);
                break;
            }
        }
        assert_eq!(block.unwrap().data(), &plain[..]);
    }

    #[test]
    fn manifest_hashes_match_the_frames_and_refuse_a_false_announcement() {
        use std::io::Write;
        let key = BulkKey::random();
        let size = BLOCK_PLAIN + 1000; // two blocks, the last one short
        let plain = data(size);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&plain).unwrap();

        let hashes = block_hashes(&file, size as u64, &key).unwrap().unwrap();
        assert_eq!(hashes.len(), 2);
        let encoder = Encoder::new();
        for block_nr in 0..2 {
            let frames = encode(&encoder, &key, &plain, size, block_nr, 0);
            let announced = u64::from_le_bytes(frames[0][HASH_OFFSET..ID_OFFSET].try_into().unwrap());
            assert_eq!(announced, hashes[block_nr as usize]);
        }

        // a frame in front of the genuine ones announcing another hash is refused
        let mut decoder = Decoder::new(key.clone(), size as u64, Box::new(MemSpill::default()), symbol_pool())
            .with_block_hashes(hashes);
        let mut forged = encode(&encoder, &key, &plain, size, 0, 0).remove(0);
        let mut raw = forged.to_vec();
        raw[HASH_OFFSET] ^= 1;
        forged = Bytes::from(raw);
        assert!(decoder.push(&forged[RELAY_HEADER..]).is_err());
        // and the block still decodes from the genuine frames
        let mut done = 0;
        for block_nr in 0..2 {
            for frame in encode(&encoder, &key, &plain, size, block_nr, 0) {
                if decoder.push(&frame[RELAY_HEADER..]).unwrap().is_some() {
                    done += 1;
                }
            }
        }
        assert_eq!(done, 2);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = BulkKey::random();
        let encoder = Encoder::new();
        let plain = data(5000);
        let mut decoder = Decoder::new(BulkKey::random(), 5000, Box::new(MemSpill::default()), symbol_pool());
        let mut failed = false;
        for frame in encode(&encoder, &key, &plain, 5000, 0, 0) {
            match decoder.push(&frame[RELAY_HEADER..]) {
                Err(_) => { failed = true; break; }
                Ok(Some(_)) => panic!("decrypted with the wrong key"),
                Ok(None) => {}
            }
        }
        assert!(failed);
    }

    #[test]
    fn frames_have_the_relay_header() {
        let key = BulkKey::random();
        let frames = encode(&Encoder::new(), &key, &data(10), 10, 0, 0);
        assert_eq!(frames.len(), N_SYMBOLS + FIRST_PASS_REPAIR as usize);
        let mut splitter = FrameSplitter::default();
        let payloads = splitter.push(&frames[0]).unwrap();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].len(), PAYLOAD_SIZE);
    }

    #[test]
    fn pooled_buffers_are_recycled() {
        let pool = Pool::<16>::new(2, 0);
        let first = pool.get();
        let ptr = first.as_ptr();
        drop(first);
        assert_eq!(pool.get().as_ptr(), ptr);
    }

    #[test]
    fn splitter_reassembles_frames_across_reads() {
        let a = relay_frame(&[1; 100]);
        let b = relay_frame(&[2; 7]);
        let stream: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
        let mut splitter = FrameSplitter::default();
        let mut got = vec![];
        for chunk in stream.chunks(13) {
            got.extend(splitter.push(chunk).unwrap());
        }
        assert_eq!(got, vec![Bytes::from(vec![1; 100]), Bytes::from(vec![2; 7])]);
    }
}

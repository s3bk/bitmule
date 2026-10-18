//! Raw fountain symbols over UDP, straight between two native peers.
//!
//! The data path of this module is the relay's, minus the relay: the sender
//! hands over symbol payloads (what `fountain::Decoder::push` takes), they
//! cross the network as datagrams, and the receiver hands the payloads on.
//! Nothing here knows about files, blocks or encryption of the data; the
//! codec above already makes a lost symbol harmless as long as enough others
//! arrive, so there are no retransmissions at all.
//!
//! Like `rtc`, this is a worker that knows nothing about the signaling
//! server: it is given the peer channel (`Peer2Peer` messages, sealed and
//! carried by someone else) for exchanging addresses, and a key both peers
//! hold (the bulk key) to prove they are the right ones.
//!
//! # Getting a path
//!
//! Each side binds sockets as the WebRTC code does (one per local address,
//! asking STUN for the public one) and tells the other where it can be
//! reached (`UdpHello`). Then both send a sealed `HELLO` carrying a random
//! challenge from every socket to every address of the other, every 100 ms.
//! Whoever receives a valid `HELLO` answers it with an `ACK` echoing the
//! challenge. Packets from both sides going out punch holes in the NATs. The
//! sender takes a path only when it gets an `ACK` for its own challenge, so
//! it never streams to an address that has not shown it holds the key (a
//! replayed or spoofed packet cannot make it send to a victim). The receiver
//! sends only small feedback, so a valid `HELLO` from the sender is enough.
//!
//! # Datagrams (little endian)
//!
//! - `HELLO` / `ACK` / `FEEDBACK`: `kind | nonce: u64 | AEAD(kind | data) | tag`.
//!   The nonce has its top bit set, which the codec's block nonces never do.
//! - `DATA`: `kind | seq: u32 | index: u8 | count: u8 | bytes`. A symbol
//!   payload (8 KiB) is cut into `count` fragments of at most `FRAGMENT`
//!   bytes, so no datagram is bigger than 1200 bytes and the network never has
//!   to fragment. A symbol is lost if one of its fragments is. Data is not
//!   sealed per datagram: a forged symbol fails the block's hash and AEAD tag
//!   above, which costs a block, not integrity.
//!
//! # Pacing
//!
//! The sender sends at a rate it adapts to the receiver's `FEEDBACK` (every
//! 50 ms: how many symbols it has seen, the highest sequence number, and
//! which blocks are complete). Under 2% symbol loss the rate grows by a
//! quarter per report; over 10% it drops by 30%. Reported blocks are not
//! sent again: `DoneBlocks`.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, bail};
use bitmule_buf::{Buf, Pool};
use bitmule_core::protocol::websocket::{Peer2Peer, UdpHello};
use bytes::Bytes;
use rand_core::{OsRng, RngCore};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, interval, sleep_until, timeout_at},
};
use tracing::{debug, warn};

use crate::{
    Role,
    crypto::BulkKey,
    str0m_client::{PoolRecv, SocketPool, build_socket_pool_with},
};

#[cfg(target_os = "linux")]
#[path = "udp_uring.rs"]
mod uring;

/// Symbol bytes in one datagram. 7 bytes of header make it 1187, under the
/// 1200 that passes any IPv6 path.
pub const FRAGMENT: usize = 1180;
/// The most `UdpConfig::fragment` may be: a whole 8 KiB symbol in one datagram
/// (which needs jumbo frames or loopback, else IP fragments it).
pub const FRAGMENT_MAX: usize = 9000;
const DATA_HEADER: usize = 7;
const DATAGRAM_MAX: usize = DATA_HEADER + FRAGMENT_MAX;
/// The longest symbol payload taken in (a relay frame's is 8208 bytes).
const PAYLOAD_MAX: usize = 9 * 1024;

const KIND_HELLO: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_DATA: u8 = 3;
const KIND_FEEDBACK: u8 = 4;
/// Set in the nonce of every sealed packet. Block nonces are small numbers.
const SEAL_DOMAIN: u64 = 1 << 63;

/// Blocks reported per feedback packet, from the first not yet done.
const FEEDBACK_WINDOW: usize = 256;
const FEEDBACK_EVERY: Duration = Duration::from_millis(50);
/// Incomplete symbols kept while waiting for their other fragments.
const REASSEMBLY_WINDOW: usize = 512;
const HELLO_EVERY: Duration = Duration::from_millis(100);
/// The sender never goes below this (bytes per second).
const MIN_RATE: f64 = 1_000_000.0;
/// How much the sender may send in a burst without waiting.
const BURST: Duration = Duration::from_millis(2);

#[derive(Clone, Copy, Debug)]
pub struct UdpConfig {
    /// Where the sender starts, bytes per second.
    pub start_rate: u64,
    /// The most it ever sends, bytes per second.
    pub max_rate: u64,
    /// How long to try to find a path before giving up.
    pub connect_timeout: Duration,
    /// For tests: the share of incoming data datagrams to drop (0.0 to 1.0).
    pub drop: f32,
    /// Symbol bytes per datagram, up to `FRAGMENT_MAX`. Both peers must use the
    /// same. Above ~2000 only works on the io_uring path (the tokio one reads
    /// into 2 KiB buffers), and over a real network only where the MTU allows it.
    pub fragment: usize,
    /// Run the data phase on io_uring when the machine has it (Linux).
    pub io_uring: bool,
}

impl Default for UdpConfig {
    fn default() -> Self {
        UdpConfig {
            start_rate: 6_250_000,  // 50 Mbit/s
            max_rate: 125_000_000,  // 1 Gbit/s
            connect_timeout: Duration::from_secs(4),
            drop: 0.0,
            io_uring: true,
            fragment: FRAGMENT,
        }
    }
}

/// Blocks the receiver has reported complete; the sender need not send those.
#[derive(Default)]
pub struct DoneBlocks {
    /// Every block below this is done.
    below: AtomicU32,
    above: Mutex<HashSet<u32>>,
}

impl DoneBlocks {
    pub fn contains(&self, block: u32) -> bool {
        block < self.below.load(Ordering::Relaxed) || self.above.lock().unwrap().contains(&block)
    }

    /// Are all of the first `total` blocks done?
    pub fn all(&self, total: u32) -> bool {
        self.below.load(Ordering::Relaxed) >= total
    }

    fn apply(&self, base: u32, bitmap: &[u8]) {
        self.below.fetch_max(base, Ordering::Relaxed);
        let below = self.below.load(Ordering::Relaxed);
        let mut above = self.above.lock().unwrap();
        for bit in 0..bitmap.len() * 8 {
            if bitmap[bit / 8] & (1 << (bit % 8)) != 0 {
                above.insert(base + bit as u32);
            }
        }
        above.retain(|&b| b >= below);
    }
}

/// A UDP path to the peer and the worker that runs it. Dropping it stops the worker.
pub struct UdpLink<T> {
    /// Sender: symbol payloads to send, in the order they should go.
    pub payloads_out: mpsc::Sender<Bytes>,
    /// Receiver: symbol payloads that arrived whole.
    pub payloads_in: mpsc::Receiver<T>,
    /// Receiver: tell the sender a block is complete.
    pub block_done: mpsc::UnboundedSender<u32>,
    /// Sender: what the receiver has told us is complete.
    pub done: Arc<DoneBlocks>,
    worker: Worker,
}

/// What runs the data phase.
enum Worker {
    Task(JoinHandle<()>),
    #[cfg(target_os = "linux")]
    Uring(#[allow(dead_code)] crate::uring::Stop),
}

impl<T> Drop for UdpLink<T> {
    fn drop(&mut self) {
        if let Worker::Task(task) = &self.worker {
            task.abort();
        }
    }
}

/// Find a path to the peer and start the worker. `signal_tx` / `signal_rx`
/// are the peer channel: only `UdpHello` is used. Fails if no path is found
/// within `cfg.connect_timeout`. `assembler` puts the receiver's fragments
/// together (the sender does not use it).
pub async fn connect<A: Assembler>(
    role: Role,
    key: BulkKey,
    stun: Option<SocketAddr>,
    signal_tx: mpsc::Sender<Peer2Peer>,
    mut signal_rx: mpsc::Receiver<Peer2Peer>,
    cfg: UdpConfig,
    assembler: A,
) -> Result<UdpLink<A::Item>> {
    let mut cfg = cfg;
    cfg.fragment = cfg.fragment.clamp(64, FRAGMENT_MAX);
    #[cfg(target_os = "linux")]
    let uring = cfg.io_uring && crate::uring::available();
    #[cfg(not(target_os = "linux"))]
    let uring = false;
    if !uring && cfg.fragment > 2000 {
        warn!("udp: fragment {} needs io_uring, using 2000", cfg.fragment);
        cfg.fragment = 2000;
    }
    let deadline = Instant::now() + cfg.connect_timeout;
    let pool = build_socket_pool_with(stun).await?;
    let ours: Vec<String> = pool.candidate_addrs().iter().map(SocketAddr::to_string).collect();
    signal_tx.send(Peer2Peer::UdpHello(UdpHello { addrs: ours })).await?;

    let theirs: Vec<SocketAddr> = loop {
        match timeout_at(deadline, signal_rx.recv()).await {
            Ok(Some(Peer2Peer::UdpHello(hello))) => {
                break hello.addrs.iter().take(16).filter_map(|a| a.parse().ok()).collect();
            }
            Ok(Some(_)) => {}
            Ok(None) => bail!("peer channel closed before the UDP addresses arrived"),
            Err(_) => bail!("the peer did not answer with UDP addresses"),
        }
    };

    let mut challenge = [0u8; 16];
    OsRng.fill_bytes(&mut challenge);
    let mut hello_data = vec![role_byte(role)];
    hello_data.extend_from_slice(&challenge);
    let hello = seal(&key, KIND_HELLO, &hello_data)?;

    let locals = pool.bound_addrs();
    let mut tick = interval(HELLO_EVERY);
    let (local, remote) = loop {
        tokio::select! {
            _ = tick.tick() => {
                if Instant::now() >= deadline {
                    bail!("no UDP path to the peer (tried {} addresses)", theirs.len());
                }
                for local in &locals {
                    for remote in theirs.iter().filter(|r| r.is_ipv4() == local.is_ipv4()) {
                        let _ = pool.send_from(*local, *remote, &hello).await;
                    }
                }
            }
            packet = pool.recv() => {
                let Some(packet) = packet else { bail!("UDP sockets closed") };
                match open(&key, &packet.bytes) {
                    Some((KIND_HELLO, data)) if data.len() == 17 && data[0] != role_byte(role) => {
                        let ack = seal(&key, KIND_ACK, &data[1..])?;
                        let _ = pool.send_from(packet.destination, packet.source, &ack).await;
                        if role == Role::Receiver {
                            break (packet.destination, packet.source);
                        }
                    }
                    Some((KIND_ACK, data)) if data == challenge => break (packet.destination, packet.source),
                    _ => {}
                }
            }
        }
    };
    debug!("udp path {local} <-> {remote}");

    let (payloads_out, out_rx) = mpsc::channel(256);
    let (in_tx, payloads_in) = mpsc::channel(2048);
    let (block_done, done_rx) = mpsc::unbounded_channel();
    let done = Arc::new(DoneBlocks::default());
    let path = Path { local, remote };

    #[cfg(target_os = "linux")]
    if uring {
        // the same sockets, duplicated; the pool's readers must stop so they do not take datagrams
        let socket = pool.dup_socket(local.ip())?;
        let stop = match role {
            Role::Sender => uring::start_sender(socket, key, remote, cfg, out_rx, done.clone()).await,
            Role::Receiver => uring::start_receiver(socket, key, remote, cfg, assembler, in_tx, done_rx).await,
        }?;
        pool.stop_receiving();
        debug!("udp data phase on io_uring");
        return Ok(UdpLink { payloads_out, payloads_in, block_done, done, worker: Worker::Uring(stop) });
    }

    let task = match role {
        Role::Sender => tokio::spawn(sender(pool, key, path, cfg, out_rx, done.clone())),
        Role::Receiver => tokio::spawn(receiver(pool, key, path, cfg, assembler, in_tx, done_rx)),
    };
    Ok(UdpLink { payloads_out, payloads_in, block_done, done, worker: Worker::Task(task) })
}

struct Path {
    local: SocketAddr,
    remote: SocketAddr,
}

fn role_byte(role: Role) -> u8 {
    match role {
        Role::Sender => 0,
        Role::Receiver => 1,
    }
}

// ---- sealed packets -----------------------------------------------------------

fn seal(key: &BulkKey, kind: u8, data: &[u8]) -> Result<Bytes> {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let nonce = u64::from_le_bytes(random) | SEAL_DOMAIN;
    // the kind is inside what is sealed, so it cannot be changed on the way
    let mut body = Vec::with_capacity(1 + data.len());
    body.push(kind);
    body.extend_from_slice(data);
    let tag = key.encrypt_chunk_in_place(nonce, &mut body)?;
    let mut out = Vec::with_capacity(9 + body.len() + 16);
    out.push(kind);
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    Ok(out.into())
}

/// The kind and data of a sealed packet, if it is one and is genuine.
fn open(key: &BulkKey, packet: &[u8]) -> Option<(u8, Vec<u8>)> {
    if packet.len() < 9 + 1 + 16 || !matches!(packet[0], KIND_HELLO | KIND_ACK | KIND_FEEDBACK) {
        return None;
    }
    let nonce = u64::from_le_bytes(packet[1..9].try_into().ok()?);
    if nonce & SEAL_DOMAIN == 0 {
        return None;
    }
    let (body, tag) = packet[9..].split_at(packet.len() - 9 - 16);
    let mut plain = body.to_vec();
    key.decrypt_chunk_in_place(nonce, &mut plain, tag.try_into().ok()?).ok()?;
    let kind = plain.remove(0);
    (kind == packet[0]).then_some((kind, plain))
}

// ---- the sender ---------------------------------------------------------------

/// The sending rate, adapted to the receiver's feedback.
struct RateControl {
    /// Bytes per second.
    rate: f64,
    max: f64,
    /// The last feedback's counters (symbols seen, symbols received), to see
    /// the loss in between.
    last: Option<(u32, u32)>,
    /// Doubling per report until the first loss shows where the limit is.
    slow_start: bool,
    /// Has the receiver reported yet? It is listening then; data sent before would be lost.
    ready: bool,
}

impl RateControl {
    fn new(cfg: &UdpConfig) -> Self {
        RateControl { rate: cfg.start_rate as f64, max: cfg.max_rate as f64, last: None, slow_start: true, ready: false }
    }

    /// Take in the data of a `FEEDBACK` packet.
    fn feedback(&mut self, data: &[u8], done: &DoneBlocks) {
        let base = u32::from_le_bytes(data[..4].try_into().unwrap());
        self.ready = true;
        done.apply(base, &data[4..4 + FEEDBACK_WINDOW / 8]);
        let seen = u32::from_le_bytes(data[4 + FEEDBACK_WINDOW / 8..][..4].try_into().unwrap());
        let received = u32::from_le_bytes(data[4 + FEEDBACK_WINDOW / 8 + 4..][..4].try_into().unwrap());
        let Some((last_seen, last_received)) = self.last else {
            self.last = Some((seen, received));
            return;
        };
        let expected = seen.wrapping_sub(last_seen);
        if expected >= 20 {
            let got = received.wrapping_sub(last_received).min(expected);
            let loss = 1.0 - got as f64 / expected as f64;
            if self.slow_start && loss < 0.02 {
                self.rate = (self.rate * 2.0).min(self.max);
            } else {
                self.slow_start = false;
                self.rate = adapt(self.rate, loss, self.max);
            }
            self.last = Some((seen, received));
        }
    }
}

/// What a packet that reached the sender asks for.
fn sender_packet(key: &BulkKey, remote: SocketAddr, rate: &mut RateControl, done: &DoneBlocks, source: SocketAddr, bytes: &[u8]) -> Option<Bytes> {
    match open(key, bytes)? {
        (KIND_FEEDBACK, data) if data.len() == 4 + FEEDBACK_WINDOW / 8 + 8 && source == remote => {
            rate.feedback(&data, done);
            None
        }
        // the receiver is still looking for us
        (KIND_HELLO, data) if data.len() == 17 && data[0] != role_byte(Role::Sender) => seal(key, KIND_ACK, &data[1..]).ok(),
        _ => None,
    }
}

/// Decides when the next datagrams may go out for a rate.
struct Pacer {
    next: Instant,
}

impl Pacer {
    fn new() -> Self {
        Pacer { next: Instant::now() }
    }

    /// Count `bytes` as sent at `rate` bytes per second. Returns when to wait
    /// until before sending them, if the sender is more than a burst ahead of
    /// its rate (timers tick in milliseconds, so waiting for every datagram
    /// would cap the speed at one per tick).
    fn reserve(&mut self, bytes: usize, rate: f64) -> Option<Instant> {
        let now = Instant::now();
        // idle time is saved up for no more than a burst
        let start = self.next.max(now.checked_sub(BURST).unwrap_or(now));
        self.next = start + Duration::from_secs_f64(bytes as f64 / rate);
        (start > now + BURST).then(|| start - BURST)
    }
}

/// The `DATA` header for fragment `index` of `count` of payload number `seq`.
fn data_header(seq: u32, index: usize, count: usize) -> [u8; DATA_HEADER] {
    let s = seq.to_le_bytes();
    [KIND_DATA, s[0], s[1], s[2], s[3], index as u8, count as u8]
}

async fn sender(
    pool: SocketPool,
    key: BulkKey,
    path: Path,
    cfg: UdpConfig,
    mut payloads: mpsc::Receiver<Bytes>,
    done: Arc<DoneBlocks>,
) {
    let datagrams = Pool::<DATAGRAM_MAX>::new(1024, 256);
    let mut seq = 0u32;
    let mut rate = RateControl::new(&cfg);
    let mut pacer = Pacer::new();

    loop {
        tokio::select! {
            packet = pool.recv() => {
                let Some(packet) = packet else { return };
                if let Some(ack) = sender_packet(&key, path.remote, &mut rate, &done, packet.source, &packet.bytes) {
                    let _ = pool.send_from(packet.destination, packet.source, &ack).await;
                }
            }
            payload = payloads.recv(), if rate.ready => {
                let Some(payload) = payload else { return };
                let count = payload.len().div_ceil(cfg.fragment);
                if count == 0 || count > u8::MAX as usize {
                    warn!("udp: dropping a payload of {} bytes", payload.len());
                    continue;
                }
                let fragments: Vec<Bytes> = payload.chunks(cfg.fragment).enumerate().map(|(index, chunk)| {
                    let mut datagram = datagrams.get();
                    datagram.extend_from_slice(&data_header(seq, index, count));
                    datagram.extend_from_slice(chunk);
                    datagram.into_bytes()
                }).collect();
                seq = seq.wrapping_add(1);

                let bytes: usize = fragments.iter().map(Bytes::len).sum();
                if let Some(at) = pacer.reserve(bytes, rate.rate) {
                    sleep_until(at).await;
                }

                let batch: Vec<_> = fragments.iter().map(|f| (path.local, path.remote, &f[..])).collect();
                if let Err(e) = pool.send_batch(&batch).await {
                    warn!("udp send: {e:#}");
                    return;
                }
            }
        }
    }
}

/// The sending rate after a report with `loss` (0.0 to 1.0).
fn adapt(rate: f64, loss: f64, max: f64) -> f64 {
    if loss < 0.02 {
        (rate * 1.25).min(max)
    } else if loss > 0.10 {
        (rate * 0.7).max(MIN_RATE)
    } else {
        rate
    }
}

// ---- the receiver -------------------------------------------------------------

/// A symbol payload being put together from its fragments.
struct Partial {
    buf: Buf<PAYLOAD_MAX>,
    count: u8,
    have: [u64; 4],
    len: usize,
}

/// Which blocks are done, as the feedback reports them.
#[derive(Default)]
struct DoneTracker {
    /// Every block below this is done.
    base: u32,
    above: BTreeSet<u32>,
}

impl DoneTracker {
    fn add(&mut self, block: u32) {
        if block >= self.base {
            self.above.insert(block);
        }
        while self.above.first() == Some(&self.base) {
            self.above.pop_first();
            self.base += 1;
        }
    }

    fn bitmap(&self) -> [u8; FEEDBACK_WINDOW / 8] {
        let mut bitmap = [0u8; FEEDBACK_WINDOW / 8];
        for &block in self.above.range(self.base..self.base.saturating_add(FEEDBACK_WINDOW as u32)) {
            let bit = (block - self.base) as usize;
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
        bitmap
    }
}

/// Puts the fragments of a symbol payload together where the caller wants
/// them, so that the one copy on the receive path (from the datagram buffer)
/// lands in its final place: a fountain symbol of the decoder, say.
pub trait Assembler: Send + 'static {
    /// What a whole payload becomes.
    type Item: Send + 'static;

    /// Fragment `index` of `count` of payload number `seq` arrived (`index <
    /// count`, at most `FRAGMENT` bytes, fragments of a payload are all
    /// `FRAGMENT` long except the last). Copy it into place; the item if that
    /// completed the payload. Duplicates, fragments that disagree about
    /// `count`, and payloads that never complete (keep a bounded window of
    /// those) are the assembler's to deal with.
    fn fragment(&mut self, seq: u32, index: u8, count: u8, bytes: &[u8]) -> Option<Self::Item>;
}

/// The fragments of a `DATA` datagram: sequence number, index, count, bytes.
fn parse_data(datagram: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    if datagram.len() <= DATA_HEADER || datagram.len() > DATAGRAM_MAX {
        return None;
    }
    let seq = u32::from_le_bytes(datagram[1..5].try_into().unwrap());
    let (index, count) = (datagram[5], datagram[6]);
    (count != 0 && index < count).then(|| (seq, index, count, &datagram[DATA_HEADER..]))
}

/// Payloads as `Bytes` in pooled buffers.
pub struct BytesAssembler {
    buffers: Arc<Pool<PAYLOAD_MAX>>,
    partials: BTreeMap<u32, Partial>,
    fragment: usize,
}

impl BytesAssembler {
    pub fn new() -> Self {
        Self::with_fragment(FRAGMENT)
    }

    /// For peers using `UdpConfig::fragment = fragment`.
    pub fn with_fragment(fragment: usize) -> Self {
        BytesAssembler { buffers: Pool::new(REASSEMBLY_WINDOW + 64, 64), partials: BTreeMap::new(), fragment }
    }
}

impl Default for BytesAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler for BytesAssembler {
    type Item = Bytes;

    fn fragment(&mut self, seq: u32, index: u8, count: u8, fragment: &[u8]) -> Option<Bytes> {
        let index = index as usize;
        let at = index * self.fragment;
        if fragment.len() > self.fragment || at + fragment.len() > PAYLOAD_MAX || count as usize > PAYLOAD_MAX.div_ceil(self.fragment).max(1) {
            return None;
        }
        let buffers = &self.buffers;
        let partial = self.partials.entry(seq).or_insert_with(|| Partial { buf: buffers.get(), count, have: [0; 4], len: 0 });
        if partial.count != count || partial.have[index / 64] & (1 << (index % 64)) != 0 {
            return None; // inconsistent, or a duplicate
        }
        partial.buf.array_mut()[at..][..fragment.len()].copy_from_slice(fragment);
        partial.have[index / 64] |= 1 << (index % 64);
        partial.len = partial.len.max(at + fragment.len());
        let have: u32 = partial.have.iter().map(|w| w.count_ones()).sum();

        if have == count as u32 {
            let Partial { mut buf, len, .. } = self.partials.remove(&seq).unwrap();
            buf.set_len(len);
            return Some(buf.into_bytes());
        }
        while self.partials.len() > REASSEMBLY_WINDOW {
            self.partials.pop_first();
        }
        None
    }
}

/// What a packet that reached the receiver led to.
enum Incoming<T> {
    Nothing,
    /// A symbol payload that is now whole.
    Payload(T),
    /// The sender is still looking for us: send this back to where it came from.
    Ack(Bytes),
}

/// Everything the receiver keeps between packets.
struct ReceiveState<A> {
    assembler: A,
    tracker: DoneTracker,
    /// Symbols seen (highest sequence number + 1), and delivered whole.
    seen: u32,
    received: u32,
    dropper: Dropper,
}

impl<A: Assembler> ReceiveState<A> {
    fn new(cfg: &UdpConfig, assembler: A) -> Self {
        ReceiveState { assembler, tracker: DoneTracker::default(), seen: 0, received: 0, dropper: Dropper::new(cfg.drop) }
    }

    fn packet(&mut self, key: &BulkKey, remote: SocketAddr, source: SocketAddr, bytes: &[u8]) -> Incoming<A::Item> {
        match bytes.first() {
            Some(&KIND_DATA) if source == remote => {
                if self.dropper.drop() {
                    return Incoming::Nothing;
                }
                let Some((seq, index, count, fragment)) = parse_data(bytes) else { return Incoming::Nothing };
                self.seen = self.seen.max(seq.wrapping_add(1));
                match self.assembler.fragment(seq, index, count, fragment) {
                    Some(payload) => {
                        self.received = self.received.wrapping_add(1);
                        Incoming::Payload(payload)
                    }
                    None => Incoming::Nothing,
                }
            }
            Some(&KIND_HELLO) => match open(key, bytes) {
                Some((KIND_HELLO, data)) if data.len() == 17 && data[0] != role_byte(Role::Receiver) => {
                    seal(key, KIND_ACK, &data[1..]).map_or(Incoming::Nothing, Incoming::Ack)
                }
                _ => Incoming::Nothing,
            },
            _ => Incoming::Nothing,
        }
    }

    /// The sealed `FEEDBACK` packet for now.
    fn feedback(&self, key: &BulkKey) -> Result<Bytes> {
        let mut data = Vec::with_capacity(4 + FEEDBACK_WINDOW / 8 + 8);
        data.extend_from_slice(&self.tracker.base.to_le_bytes());
        data.extend_from_slice(&self.tracker.bitmap());
        data.extend_from_slice(&self.seen.to_le_bytes());
        data.extend_from_slice(&self.received.to_le_bytes());
        seal(key, KIND_FEEDBACK, &data)
    }
}

async fn receiver<A: Assembler>(
    pool: SocketPool,
    key: BulkKey,
    path: Path,
    cfg: UdpConfig,
    assembler: A,
    payloads: mpsc::Sender<A::Item>,
    mut block_done: mpsc::UnboundedReceiver<u32>,
) {
    let mut state = ReceiveState::new(&cfg, assembler);
    let mut tick = interval(FEEDBACK_EVERY);

    loop {
        tokio::select! {
            packet = pool.recv() => {
                let Some(packet) = packet else { return };
                let PoolRecv { bytes, source, destination } = packet;
                match state.packet(&key, path.remote, source, &bytes) {
                    Incoming::Payload(payload) => {
                        if payloads.send(payload).await.is_err() {
                            return;
                        }
                    }
                    Incoming::Ack(ack) => {
                        let _ = pool.send_from(destination, source, &ack).await;
                    }
                    Incoming::Nothing => {}
                }
            }
            Some(block) = block_done.recv() => state.tracker.add(block),
            _ = tick.tick() => {
                if let Ok(feedback) = state.feedback(&key) {
                    let _ = pool.send_from(path.local, path.remote, &feedback).await;
                }
            }
        }
    }
}

/// For tests: decides which datagrams to drop.
struct Dropper {
    share: f32,
    state: u64,
}

impl Dropper {
    fn new(share: f32) -> Self {
        let mut seed = [0u8; 8];
        OsRng.fill_bytes(&mut seed);
        Dropper { share, state: u64::from_le_bytes(seed) | 1 }
    }

    fn drop(&mut self) -> bool {
        if self.share <= 0.0 {
            return false;
        }
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        ((self.state >> 40) as f32 / (1u64 << 24) as f32) < self.share
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> BulkKey {
        BulkKey::random()
    }

    #[test]
    fn sealed_packets_open_only_with_the_key_and_unchanged() {
        let key = key();
        let packet = seal(&key, KIND_HELLO, b"hello").unwrap();
        assert_eq!(open(&key, &packet), Some((KIND_HELLO, b"hello".to_vec())));
        assert_eq!(open(&BulkKey::random(), &packet), None);

        let mut changed = packet.to_vec();
        changed[12] ^= 1;
        assert_eq!(open(&key, &changed), None);
        // the kind byte is authenticated too
        let mut other_kind = packet.to_vec();
        other_kind[0] = KIND_ACK;
        assert_eq!(open(&key, &other_kind), None);
        // and a block-style nonce is no sealed packet
        let mut plain_nonce = packet.to_vec();
        plain_nonce[1..9].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(open(&key, &plain_nonce), None);
    }

    /// A datagram through the parser into the assembler.
    fn feed(assembler: &mut BytesAssembler, datagram: &[u8]) -> Option<Bytes> {
        let (seq, index, count, bytes) = parse_data(datagram)?;
        assembler.fragment(seq, index, count, bytes)
    }

    fn fragments(seq: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        let count = payload.len().div_ceil(FRAGMENT);
        payload.chunks(FRAGMENT).enumerate().map(|(index, chunk)| {
            let mut d = vec![KIND_DATA];
            d.extend_from_slice(&seq.to_le_bytes());
            d.push(index as u8);
            d.push(count as u8);
            d.extend_from_slice(chunk);
            d
        }).collect()
    }

    #[test]
    fn fragments_reassemble_in_any_order_and_ignore_duplicates() {
        let mut assembler = BytesAssembler::new();
        let payload: Vec<u8> = (0..8208u32).map(|i| (i * 7) as u8).collect();
        let mut parts = fragments(9, &payload);
        assert_eq!(parts.len(), 7);
        parts.reverse();
        let last = parts.len() - 1;
        for (i, part) in parts.iter().enumerate().take(last) {
            assert!(feed(&mut assembler, part).is_none());
            // the same fragment again changes nothing
            assert!(feed(&mut assembler, part).is_none(), "duplicate {i}");
        }
        let result = feed(&mut assembler, &parts[last]).expect("complete");
        assert_eq!(&result[..], &payload[..]);
        assert!(assembler.partials.is_empty());
    }

    #[test]
    fn a_missing_fragment_means_no_payload_and_old_partials_are_dropped() {
        let mut assembler = BytesAssembler::new();
        let payload = vec![1u8; 3000];
        for part in fragments(0, &payload).iter().take(2) {
            assert!(feed(&mut assembler, part).is_none());
        }
        assert_eq!(assembler.partials.len(), 1);
        for seq in 1..=REASSEMBLY_WINDOW as u32 + 5 {
            feed(&mut assembler, &fragments(seq, &payload)[0]);
        }
        assert!(assembler.partials.len() <= REASSEMBLY_WINDOW);
        assert!(!assembler.partials.contains_key(&0));
    }

    #[test]
    fn malformed_data_datagrams_are_ignored() {
        let mut assembler = BytesAssembler::new();
        for bad in [vec![KIND_DATA; 3], vec![KIND_DATA, 0, 0, 0, 0, 5, 3, 1], vec![KIND_DATA, 0, 0, 0, 0, 0, 0, 1], vec![KIND_DATA; 2000]] {
            assert!(feed(&mut assembler, &bad).is_none());
        }
        assert!(assembler.partials.is_empty());
    }

    #[test]
    fn done_tracking_survives_gaps_and_reports_a_window() {
        let tracker = &mut DoneTracker::default();
        for b in [2, 0, 5, 1] {
            tracker.add(b);
        }
        assert_eq!(tracker.base, 3);
        let bitmap = tracker.bitmap();
        // block 5 is bit 2 from base 3
        assert_eq!(bitmap[0], 0b100);

        let done = DoneBlocks::default();
        done.apply(tracker.base, &bitmap);
        assert!(done.contains(0) && done.contains(2) && done.contains(5));
        assert!(!done.contains(3) && !done.contains(4));
        assert!(!done.all(6));
        tracker.add(3);
        tracker.add(4);
        done.apply(tracker.base, &tracker.bitmap());
        assert!(done.all(6));
    }

    #[test]
    fn rate_goes_up_without_loss_and_down_with_much() {
        assert_eq!(adapt(10e6, 0.0, 100e6), 12.5e6);
        assert_eq!(adapt(90e6, 0.0, 100e6), 100e6);
        assert_eq!(adapt(10e6, 0.05, 100e6), 10e6);
        assert!((adapt(10e6, 0.2, 100e6) - 7e6).abs() < 1.0);
        assert_eq!(adapt(MIN_RATE, 0.5, 100e6), MIN_RATE);
    }

    #[test]
    fn the_dropper_drops_about_its_share() {
        let mut dropper = Dropper::new(0.1);
        let dropped = (0..100_000).filter(|_| dropper.drop()).count();
        assert!((8_000..12_000).contains(&dropped), "{dropped}");
        let mut never = Dropper::new(0.0);
        assert!(!(0..1000).any(|_| never.drop()));
    }

    /// Both peers, joined by in-memory signalling, and `count` payloads sent through.
    async fn roundtrip(io_uring: bool, loss: f32, count: usize) -> usize {
        let key = BulkKey::random();
        let (a_tx, a_rx) = mpsc::channel(8);
        let (b_tx, b_rx) = mpsc::channel(8);
        let cfg = |loss| UdpConfig { io_uring, drop: loss, start_rate: 50_000_000, ..UdpConfig::default() };
        // the sender's signalling output is the receiver's input and the other way round
        let (sender, receiver) = tokio::join!(
            connect(Role::Sender, key.clone(), None, a_tx, b_rx, cfg(0.0), BytesAssembler::new()),
            connect(Role::Receiver, key.clone(), None, b_tx, a_rx, cfg(loss), BytesAssembler::new()),
        );
        let (sender, mut receiver) = (sender.unwrap(), receiver.unwrap());
        let payload = |n: usize| Bytes::from((0..8208usize).map(|i| (i + n) as u8).collect::<Vec<_>>());
        let send = tokio::spawn(async move {
            for n in 0..count {
                if sender.payloads_out.send(payload(n)).await.is_err() {
                    break;
                }
            }
            sleep_until(Instant::now() + Duration::from_secs(1)).await;
            drop(sender);
        });
        let mut got = 0;
        while let Ok(Some(p)) = tokio::time::timeout(Duration::from_millis(700), receiver.payloads_in.recv()).await {
            // every payload that arrives is one that was sent, whole
            let n = (p[0] as usize).wrapping_sub(0);
            assert_eq!(p.len(), 8208);
            assert!((0..count).any(|k| (k as u8) as usize == n), "unknown payload");
            assert_eq!(p[1], p[0].wrapping_add(1));
            got += 1;
        }
        send.abort();
        got
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tokio_path_delivers_on_loopback() {
        let got = roundtrip(false, 0.0, 200).await;
        assert!(got >= 190, "{got} of 200");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn uring_path_delivers_on_loopback() {
        if !crate::uring::available() {
            println!("io_uring not available, skipped");
            return;
        }
        let got = roundtrip(true, 0.0, 200).await;
        assert!(got >= 190, "{got} of 200");
        let lossy = roundtrip(true, 0.05, 200).await;
        assert!((90..=185).contains(&lossy), "with 5% datagram loss (about 70% of symbols whole): {lossy} of 200");
    }

    /// Throughput on loopback: `cargo test -p bitmule-client-native --release --lib udp_speed -- --ignored --nocapture`
    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    async fn udp_speed() {
        for io_uring in std::env::var("UDP_SPEED_URING").map_or(vec![true, false], |v| vec![v == "1"]) {
            let key = BulkKey::random();
            let (a_tx, a_rx) = mpsc::channel(8);
            let (b_tx, b_rx) = mpsc::channel(8);
            let fragment = std::env::var("UDP_SPEED_FRAGMENT").ok().and_then(|v| v.parse().ok()).unwrap_or(FRAGMENT);
            let cfg = UdpConfig { io_uring, max_rate: 2_000_000_000, fragment, ..UdpConfig::default() };
            let (sender, receiver) = tokio::join!(
                connect(Role::Sender, key.clone(), None, a_tx, b_rx, cfg, BytesAssembler::with_fragment(fragment)),
                connect(Role::Receiver, key.clone(), None, b_tx, a_rx, cfg, BytesAssembler::with_fragment(fragment)),
            );
            let (sender, mut receiver) = (sender.unwrap(), receiver.unwrap());
            let count: usize = std::env::var("UDP_SPEED_COUNT").ok().and_then(|v| v.parse().ok()).unwrap_or(60_000); // 8208 bytes each
            let payload = Bytes::from(vec![7u8; 8208]);
            let start = Instant::now();
            tokio::spawn(async move {
                for _ in 0..count {
                    if sender.payloads_out.send(payload.clone()).await.is_err() {
                        break;
                    }
                }
                sleep_until(Instant::now() + Duration::from_secs(3)).await;
                drop(sender);
            });
            let mut got = 0usize;
            while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(500), receiver.payloads_in.recv()).await {
                got += 1;
                if got == 1 { println!("first after {:?}", start.elapsed()); }
            }
            let secs = start.elapsed().as_secs_f64() - 0.5;
            println!("io_uring={io_uring}: {got}/{count} payloads, {:.0} MiB/s", got as f64 * 8208.0 / 1048576.0 / secs);
        }
    }
}

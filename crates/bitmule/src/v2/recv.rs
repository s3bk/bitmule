//! The receiving side of a transfer.
//!
//! The transfer worker (`receive`) asks for the whole file and then
//! coordinates the transports, each a worker of its own:
//! - the relay download: a fountain coded stream, decoded on its own threads,
//!   written to its place in the file block by block as blocks complete;
//! - the WebRTC data channel (`rtc`), if the peers agree on it.
//!
//! When the data channel opens it takes over and the relay download is
//! stopped; if the data channel dies, the relay download starts again. The
//! transfer is finished when either has delivered everything. The result is
//! checked against the signature in the share link in any case.

use std::{collections::{HashSet, VecDeque}, sync::Arc};

use anyhow::{Result, bail, ensure};
use bitmule_client_common::{
    blockio::{BlockWriter, FileSpill, Loaded},
    fountain,
};
use bitmule_client_native::{
    crypto::{BulkKey, CommitmentHasher, ShareLink},
    rtc::{self, ChannelEvent},
    udp::{self, BytesAssembler, UdpConfig},
};
use bitmule_core::{
    ReceiverId, SessionId, Token,
    protocol::websocket::{Peer2Peer, PeerCaps, TransferManifest},
};
use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{sync::{mpsc, oneshot}, task::JoinHandle};
use tracing::warn;

use super::{Options, Report, Server, Span, Transport, VerifyFailed, dcproto, peer::PeerLink, send::AbortOnDrop};

/// No symbol over UDP for this long: the path did not work out, or died.
const UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

/// Symbols queued for the decoder thread.
const DECODE_QUEUE: usize = 4096;

pub struct Context {
    server: Server,
    session_id: SessionId,
    our_id: ReceiverId,
    relay_token: Token,
    link: ShareLink,
    /// Makes the output file once the manifest is known (its name is in there).
    open: Option<OpenOutput>,
    progress: Option<Progress>,
    options: Options,
}

/// Called with (bytes received so far, total) as data comes in.
pub type Progress = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Makes the file the transfer is written to (read and write) from the manifest.
pub type OpenOutput = Box<dyn FnOnce(&TransferManifest) -> std::io::Result<std::fs::File> + Send>;

impl Context {
    pub fn new(
        server: Server,
        session_id: SessionId,
        our_id: ReceiverId,
        relay_token: Token,
        link: ShareLink,
        open: OpenOutput,
        progress: Option<Progress>,
        options: Options,
    ) -> Self {
        Context { server, session_id, our_id, relay_token, link, open: Some(open), progress, options }
    }

    fn relay_url(&self) -> String {
        self.server.http(&format!(
            "/session/{}/{}?token={}",
            self.session_id.as_hex(), self.our_id.as_hex(), self.relay_token.as_hex(),
        ))
    }
}

/// What a data channel message carries: one piece, or the pieces it arrived in
/// (written out one after the other, never joined).
enum Payload {
    One(Bytes),
    Parts(Vec<Bytes>),
}

impl Payload {
    fn len(&self) -> u64 {
        match self {
            Payload::One(bytes) => bytes.len() as u64,
            Payload::Parts(parts) => parts.iter().map(|p| p.len() as u64).sum(),
        }
    }

    fn copy_to(&self, out: &mut [u8]) {
        let parts = match self {
            Payload::One(bytes) => std::slice::from_ref(bytes),
            Payload::Parts(parts) => &parts[..],
        };
        let mut at = 0;
        for part in parts {
            out[at..][..part.len()].copy_from_slice(part);
            at += part.len();
        }
    }

    async fn write(self, writer: &BlockWriter, offset: u64) -> std::io::Result<()> {
        match self {
            Payload::One(bytes) => writer.write_bytes(offset, bytes).await,
            Payload::Parts(parts) => writer.write_parts(offset, parts).await,
        }
    }
}

/// How a relay download ended.
enum RelayEnd {
    /// Every block is in the file.
    Complete(Span),
    /// Stopped on request; these blocks are in the file.
    Stopped(Vec<u32>, Span),
}

/// Counts `n` more bytes as received and reports.
type Bump = Arc<dyn Fn(u64) + Send + Sync>;

/// How often the sender is told how far we are.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

fn bump_for(progress: Option<Progress>, size: u64, sender: mpsc::Sender<Peer2Peer>) -> Bump {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    let done = Arc::new(AtomicU64::new(0));
    let started = std::time::Instant::now();
    let last_report = Arc::new(AtomicU64::new(0)); // ms since `started`, +1
    Arc::new(move |n| {
        let total = (done.fetch_add(n, Relaxed) + n).min(size);
        if let Some(progress) = &progress {
            progress(total, size);
        }
        // the sender shows this to its user; a full queue just skips one report
        let now = started.elapsed().as_millis() as u64 + 1;
        let last = last_report.load(Relaxed);
        if (last == 0 || now - last >= REPORT_EVERY.as_millis() as u64)
            && last_report.compare_exchange(last, now, Relaxed, Relaxed).is_ok()
        {
            let _ = sender.try_send(Peer2Peer::Progress(total));
        }
    })
}

/// A running relay download.
struct Relay {
    task: JoinHandle<Result<RelayEnd>>,
    /// Asks the download to stop after writing what it has decoded.
    stop: Option<oneshot::Sender<()>>,
}

impl Relay {
    fn start(url: String, manifest: TransferManifest, out: Arc<std::fs::File>, bump: Bump) -> Self {
        let (stop, stop_rx) = oneshot::channel();
        Relay { task: tokio::spawn(relay_download(url, manifest, out, stop_rx, bump)), stop: Some(stop) }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Byte ranges of the blocks not in `have`, adjacent blocks merged.
fn missing_ranges(size: u64, have: &HashSet<u32>) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for block in (0..fountain::num_blocks(size)).filter(|b| !have.contains(b)) {
        let (start, len) = fountain::block_span(size, block);
        match ranges.last_mut() {
            Some(last) if last.1 == start => last.1 = start + len as u64,
            _ => ranges.push((start, start + len as u64)),
        }
    }
    ranges
}

/// The ranges asked of the data channel, one at a time: the next is asked
/// for when the current one has arrived.
#[derive(Default)]
struct DcRequests {
    current: Option<(u64, u64)>,
    got: u64,
    queue: VecDeque<(u64, u64)>,
}

impl DcRequests {
    fn new(ranges: Vec<(u64, u64)>) -> Self {
        let mut queue: VecDeque<_> = ranges.into();
        DcRequests { current: queue.pop_front(), got: 0, queue }
    }

    /// Is a piece of `len` bytes at `offset` the next one of the current range?
    fn accepts(&self, offset: u64, len: u64) -> bool {
        self.current.is_some_and(|(start, end)| offset == start + self.got && offset + len <= end)
    }

    /// Account for an accepted piece. `Some(next)` once the current range is
    /// complete: the range to ask for next, or `None` inside when all is in.
    fn received(&mut self, len: u64) -> Option<Option<(u64, u64)>> {
        let (start, end) = self.current?;
        self.got += len;
        if start + self.got < end {
            return None;
        }
        self.got = 0;
        self.current = self.queue.pop_front();
        Some(self.current)
    }
}

pub async fn receive(mut ctx: Context, sender_caps: PeerCaps, app: PeerLink, signaling: PeerLink, udp: PeerLink) -> Result<Report> {
    let PeerLink { tx, mut rx } = app;

    let manifest = loop {
        match rx.recv().await {
            Some(Peer2Peer::Manifest(manifest)) => break manifest,
            // data first, the manifest at the end: a streaming transfer
            Some(Peer2Peer::JoinRelay) => return receive_stream(ctx, sender_caps, tx, rx).await,
            Some(Peer2Peer::Progress(_)) => {}
            Some(_) => bail!("expected Manifest"),
            None => bail!("sender went away"),
        }
    };
    ensure!(manifest.block_size as usize == fountain::BLOCK_PLAIN, "sender uses an unsupported block size");
    let size = manifest.transfer_size;
    let out = Arc::new((ctx.open.take().expect("the output is opened once"))(&manifest)?);
    let bump = bump_for(ctx.progress.take(), size, tx.clone());

    let use_relay = ctx.options.relay && sender_caps.contains(PeerCaps::RELAY);
    let use_webrtc = ctx.options.webrtc && sender_caps.contains(PeerCaps::WEBRTC);
    let udp_possible = ctx.options.udp && sender_caps.contains(PeerCaps::UDP);
    let use_udp = udp_possible && size > 0;
    ensure!(use_relay || use_webrtc || udp_possible, "sender and receiver have no transport in common");

    tx.send(Peer2Peer::Get { start: 0, end: size }).await?;

    // TEMP-INSTR: BITMULE_MEMOUT=1 puts the data channel's output in memory, not the file
    let mut mem: Option<Vec<u8>> = std::env::var_os("BITMULE_MEMOUT").map(|_| vec![0u8; size as usize]);
    let mut transport = Transport::Relay;
    let mut relay_time = Span::default();
    let mut data_channel_time = Span::default();
    let mut dc_bytes = 0u64;
    let mut relay_bytes = size;
    let mut udp_bytes = 0u64;
    let mut udp_time = Span::default();
    if size > 0 {
        // UDP is tried first; if it fails the sender starts the other transports (`JoinRelay`, an offer)
        let mut udp_task = use_udp.then(|| {
            let (manifest, out, bump, server) = (manifest.clone(), out.clone(), bump.clone(), ctx.server.clone());
            AbortOnDrop(tokio::spawn(async move { udp_download(server.stun_addr().await, udp, manifest, out, bump).await }))
        });
        // the offer arrives on the signaling channel whenever the sender is ready
        let mut channel = if use_webrtc {
            Some(rtc::spawn(rtc::Role::Answerer, ctx.server.stun_addr().await, signaling.tx, signaling.rx).await?)
        } else {
            None
        };
        let mut relay_offered = false;
        let mut relay_failed = false;
        let mut relay: Option<Relay> = None;
        // blocks the relay download finished before it was stopped
        let mut have: HashSet<u32> = HashSet::new();
        let mut data_channel_active = false;
        let mut dc_start_due = false;
        let mut dc = DcRequests::default();
        let mut dc_writer: Option<BlockWriter> = None;

        loop {
            tokio::select! {
                message = rx.recv() => match message {
                    // the sender gave up on UDP (or never used it): the relay is how it goes on
                    Some(Peer2Peer::JoinRelay) if use_relay => {
                        udp_task = None;
                        relay_offered = true;
                    }
                    Some(Peer2Peer::JoinRelay) | Some(Peer2Peer::Progress(_)) => {}
                    Some(_) => bail!("unexpected message during transfer"),
                    None => bail!("sender went away"),
                },
                result = async { (&mut udp_task.as_mut().unwrap().0).await }, if udp_task.is_some() => {
                    udp_task = None;
                    match result? {
                        Ok(RelayEnd::Complete(span)) => {
                            udp_time = span;
                            udp_bytes = size;
                            relay_bytes = 0;
                            transport = Transport::Udp;
                            break;
                        }
                        Ok(RelayEnd::Stopped(..)) => bail!("the udp download was stopped"),
                        // the sender notices as well and starts the other transports
                        Err(e) if use_relay || use_webrtc => warn!("udp download: {e:#}"),
                        Err(e) => return Err(e),
                    }
                }
                result = async { (&mut relay.as_mut().unwrap().task).await }, if relay.is_some() => {
                    relay = None;
                    match result? {
                        Ok(RelayEnd::Complete(span)) => { relay_time.merge(span); break }
                        // handed over to the data channel, which takes the rest
                        Ok(RelayEnd::Stopped(done, span)) => { relay_time.merge(span); have.extend(done) }
                        Err(e) if channel.is_some() || data_channel_active => {
                            warn!("relay download: {e}");
                            relay_failed = true;
                        }
                        Err(e) => return Err(e),
                    }
                }
                event = async { channel.as_mut().unwrap().events.recv().await }, if channel.is_some() => match event {
                    Some(ChannelEvent::Open) => {
                        // the data channel takes over: the relay finishes the blocks it
                        // holds, and the data channel asks for the rest
                        data_channel_active = true;
                        dc_start_due = true;
                        dc_writer.get_or_insert_with(|| BlockWriter::spawn(out.clone()));
                        if let Some(stop) = relay.as_mut().and_then(|r| r.stop.take()) {
                            let _ = stop.send(());
                        }
                    }
                    Some(event @ (ChannelEvent::Message(_) | ChannelEvent::Segments(_))) => {
                        let (offset, payload) = match event {
                            ChannelEvent::Message(message) => match dcproto::Message::decode(message)? {
                                dcproto::Message::Data { offset, bytes } => (offset, Payload::One(bytes)),
                                _ => bail!("unexpected data channel message"),
                            },
                            ChannelEvent::Segments(parts) => {
                                let (offset, parts) = dcproto::data_parts(parts)?;
                                (offset, Payload::Parts(parts))
                            }
                            _ => unreachable!(),
                        };
                        if data_channel_active && dc.current.is_some() {
                            let len = payload.len();
                            ensure!(dc.accepts(offset, len), "sender sent data that was not asked for");
                            data_channel_time.mark();
                            if let Some(mem) = mem.as_mut() { payload.copy_to(&mut mem[offset as usize..]); } else { payload.write(dc_writer.as_ref().unwrap(), offset).await?; } // TEMP-INSTR
                            dc_bytes += len;
                            bump(len);
                            match dc.received(len) {
                                Some(Some((start, end))) => {
                                    channel.as_ref().unwrap().send.send(dcproto::Message::Get { start, end }.encode()).await?;
                                }
                                Some(None) => {
                                    transport = Transport::WebRtc;
                                    relay_bytes = size - dc_bytes;
                                    break;
                                }
                                None => {}
                            }
                        }
                        else {
                            bail!("unexpected data channel message")
                        }
                    }
                    Some(ChannelEvent::Closed) | None => {
                        channel = None;
                        if data_channel_active {
                            // go back to the relay
                            ensure!(use_relay && relay_offered, "data channel lost and no relay to fall back on");
                            data_channel_active = false;
                            dc_start_due = false;
                            dc = DcRequests::default();
                            relay_failed = false;
                        } else if !use_relay {
                            bail!("the data channel failed and the relay is not in use");
                        }
                    }
                },
            }

            // the data channel starts once the relay has stopped, with what is still missing
            if dc_start_due && relay.is_none() {
                dc_start_due = false;
                dc = DcRequests::new(missing_ranges(size, &have));
                match dc.current {
                    Some((start, end)) => {
                        channel.as_ref().unwrap().send.send(dcproto::Message::Get { start, end }.encode()).await?;
                    }
                    None => break, // the relay had delivered everything
                }
            }
            if use_relay && relay_offered && !relay_failed && !data_channel_active && relay.is_none() {
                relay = Some(Relay::start(ctx.relay_url(), manifest.clone(), out.clone(), bump.clone()));
            }
        }
        // whatever the data channel wrote has to be on disk before it is read back
        if let Some(writer) = dc_writer {
            tokio::task::spawn_blocking(move || writer.finish()).await??;
        }
    }

    if let Some(mem) = &mem { // TEMP-INSTR: the data channel wrote into memory; check it there
        let mut hasher = CommitmentHasher::new();
        hasher.update(mem);
        if hasher.finalize(&manifest.bulk_key) != ctx.link.signature {
            return Err(VerifyFailed("data does not match the share link's signature").into());
        }
        tx.send(Peer2Peer::Complete).await?;
        return Ok(Report { manifest, transport, relay_bytes, data_channel_bytes: dc_bytes, udp_bytes, relay_time, data_channel_time, udp_time });
    }
    if commitment_of(out.clone(), size, manifest.bulk_key.clone()).await? != ctx.link.signature {
        return Err(VerifyFailed("data does not match the share link's signature").into());
    }
    tx.send(Peer2Peer::Complete).await?;
    Ok(Report { manifest, transport, relay_bytes, data_channel_bytes: dc_bytes, udp_bytes, relay_time, data_channel_time, udp_time })
}

/// A streaming transfer (the sender's first message was `JoinRelay`, not
/// `Manifest`): the data comes first over the relay, encrypted with a key we
/// do not have yet, so it is kept as it arrives. The manifest (key, size,
/// name) and the checksum come when the sender has read all its data. Then
/// the kept data and what still arrives are decoded into the output file,
/// which is opened only now, and checked against the checksum.
async fn receive_stream(mut ctx: Context, sender_caps: PeerCaps, tx: mpsc::Sender<Peer2Peer>, mut rx: mpsc::Receiver<Peer2Peer>) -> Result<Report> {
    ensure!(
        ctx.options.relay && sender_caps.contains(PeerCaps::RELAY),
        "this is a streaming transfer, which goes over the relay, and one side does not use it"
    );
    let progress = ctx.progress.take();
    let (start_tx, start_rx) = oneshot::channel::<(TransferManifest, Arc<std::fs::File>, Bump)>();
    let mut start_tx = Some(start_tx);
    let spool = tempfile::tempfile()?;
    let mut download = Relay {
        task: tokio::spawn(relay_download_stream(ctx.relay_url(), spool, start_rx, progress.clone())),
        stop: None,
    };

    let mut started: Option<(TransferManifest, Arc<std::fs::File>)> = None;
    let mut checksum: Option<[u8; 32]> = None;
    let mut relay_time = Span::default();
    let mut downloaded = false;
    while !(downloaded && checksum.is_some()) {
        tokio::select! {
            message = rx.recv() => match message {
                Some(Peer2Peer::Manifest(manifest)) if started.is_none() => {
                    ensure!(manifest.block_size as usize == fountain::BLOCK_PLAIN, "sender uses an unsupported block size");
                    let out = Arc::new((ctx.open.take().expect("the output is opened once"))(&manifest)?);
                    let bump = bump_for(progress.clone(), manifest.transfer_size, tx.clone());
                    started = Some((manifest.clone(), out.clone()));
                    let _ = start_tx.take().expect("started once").send((manifest, out, bump));
                }
                Some(Peer2Peer::Checksum(sum)) => checksum = Some(sum),
                Some(Peer2Peer::JoinRelay) | Some(Peer2Peer::Progress(_)) => {}
                Some(_) => bail!("unexpected message during a streaming transfer"),
                None => bail!("sender went away"),
            },
            result = async { (&mut download.task).await }, if !downloaded => {
                downloaded = true;
                match result?? {
                    RelayEnd::Complete(span) => relay_time = span,
                    RelayEnd::Stopped(..) => bail!("the download was stopped"),
                }
            }
        }
    }

    // the download only completes once it has the manifest
    let (manifest, out) = started.expect("a complete download has its manifest");
    let (size, key) = (manifest.transfer_size, manifest.bulk_key.clone());
    let actual = commitment_of(out, size, key).await?;
    if Some(actual) != checksum {
        return Err(VerifyFailed("data does not match the sender's checksum").into());
    }
    // a link that does carry a signature has to agree as well
    if ctx.link.signature != [0u8; 32] && actual != ctx.link.signature {
        return Err(VerifyFailed("data does not match the share link's signature").into());
    }
    tx.send(Peer2Peer::Complete).await?;
    Ok(Report { manifest, transport: Transport::Relay, relay_bytes: size, data_channel_bytes: 0, udp_bytes: 0, relay_time, data_channel_time: Span::default(), udp_time: Span::default() })
}

/// The relay download of a streaming transfer: until the manifest arrives
/// (`start`) the stream is only written to `spool`, as it is, since there is
/// no key to decode it with. Then the spool is decoded, followed by the rest
/// of the stream, as in `relay_download`.
async fn relay_download_stream(
    url: String,
    spool: std::fs::File,
    mut start: oneshot::Receiver<(TransferManifest, Arc<std::fs::File>, Bump)>,
    progress: Option<Progress>,
) -> Result<RelayEnd> {
    use tokio::io::AsyncWriteExt;
    let response = bitmule_client_native::nic::http_client().get(url).send().await?.error_for_status()?;
    let mut stream: ByteStream = Box::pin(response.bytes_stream());
    let mut spool = tokio::fs::File::from_std(spool);
    let mut spooled = 0u64;
    let mut stream_over = false;
    let (manifest, out, bump) = loop {
        tokio::select! {
            started = &mut start => {
                break started.map_err(|_| anyhow::anyhow!("the transfer ended before its manifest arrived"))?;
            }
            chunk = stream.next(), if !stream_over => match chunk {
                Some(chunk) => {
                    let chunk = chunk?;
                    spool.write_all(&chunk).await?;
                    spooled += chunk.len() as u64;
                    // the size is not known yet: bytes so far, no total
                    if let Some(progress) = &progress {
                        progress(spooled, 0);
                    }
                }
                None => stream_over = true,
            }
        }
    };
    spool.flush().await?;
    let spool = spool.into_std().await;
    let (_keep, stop) = oneshot::channel();
    decode_download(stream, Some((spool, spooled)), manifest, out, stop, bump).await
}

/// `SHA256(file || bulk_key)`, read back from the finished file.
async fn commitment_of(file: Arc<std::fs::File>, size: u64, key: BulkKey) -> Result<[u8; 32]> {
    Ok(tokio::task::spawn_blocking(move || -> Result<[u8; 32]> {
        let mut hasher = CommitmentHasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut pos = 0u64;
        while pos < size {
            let n = buf.len().min((size - pos) as usize);
            fountain::read_exact_at(&file, &mut buf[..n], pos)?;
            hasher.update(&buf[..n]);
            pos += n as u64;
        }
        Ok(hasher.finalize(&key))
    }).await??)
}

/// The decoder thread: payloads in, blocks written to `out`. `block_done` is
/// told of every block once it is queued for writing. The thread ends when the
/// sender half is dropped (after it has decoded what was queued) or when
/// every block is in; its result is the blocks that are.
fn spawn_decoder(
    manifest: &TransferManifest,
    out: Arc<std::fs::File>,
    bump: Bump,
    block_done: Option<mpsc::UnboundedSender<u32>>,
) -> Result<(mpsc::Sender<Bytes>, JoinHandle<Result<Vec<u32>>>)> {
    let (tx, mut frames) = mpsc::channel::<Bytes>(DECODE_QUEUE);
    let (key, size) = (manifest.bulk_key.clone(), manifest.transfer_size);
    let block_hashes = manifest.block_hashes.clone();
    if !block_hashes.is_empty() {
        ensure!(
            block_hashes.len() == fountain::num_blocks(size) as usize,
            "the manifest lists {} block hashes for {} blocks", block_hashes.len(), fountain::num_blocks(size)
        );
    }
    let runtime = tokio::runtime::Handle::current();
    let decode = tokio::task::spawn_blocking(move || -> Result<Vec<u32>> {
        use tokio::sync::mpsc::error::TryRecvError;

        let symbols = fountain::symbol_pool();
        // spilling and reading back happens on threads of its own; what is
        // read back arrives here, and only the block concerned waits for it
        let (loaded_tx, mut loaded) = mpsc::unbounded_channel();
        let spill = FileSpill::spawn(out.clone(), size, symbols.clone(), loaded_tx)?;
        let mut decoder = fountain::Decoder::new(key, size, Box::new(spill), symbols);
        if !block_hashes.is_empty() {
            decoder = decoder.with_block_hashes(block_hashes);
        }
        let writer = BlockWriter::spawn(out);

        let decoded = (|| -> Result<()> {
            enum Event { Frame(Bytes), Loaded(Loaded), End }
            while !decoder.is_complete() {
                // busy: take what is there; idle: wait for a frame or a read-back
                let event = match (loaded.try_recv(), frames.try_recv()) {
                    (Ok(l), _) => Event::Loaded(l),
                    (_, Ok(f)) => Event::Frame(f),
                    (_, Err(TryRecvError::Disconnected)) => Event::End,
                    _ => runtime.block_on(async {
                        tokio::select! {
                            l = loaded.recv() => l.map_or(Event::End, Event::Loaded),
                            f = frames.recv() => f.map_or(Event::End, Event::Frame),
                        }
                    }),
                };
                let block = match event {
                    Event::Frame(payload) => match decoder.push(&payload) {
                        Ok(block) => block,
                        Err(e) => { warn!("dropping bad symbol: {e}"); None }
                    },
                    Event::Loaded(l) => decoder.loaded(l.block_nr, l.symbols?)?,
                    Event::End => return Ok(()),
                };
                if let Some(block) = block {
                    bump(block.data().len() as u64);
                    let block_nr = block.block_nr;
                    writer.write(block)?;
                    if let Some(done) = &block_done {
                        let _ = done.send(block_nr);
                    }
                }
            }
            Ok(())
        })();
        let written = writer.finish();
        decoded?;
        written?;
        Ok(decoder.done_blocks())
    });

    Ok((tx, decode))
}

/// Download and decode the fountain coded stream at `url` into `out`.
///
/// Blocks are written where they belong in the order they complete. Decoding
/// runs on a thread of its own, the writer (io_uring on Linux) on another;
/// blocks still short of symbols when memory runs out are spilled into their
/// gap in `out`. Dropping the future stops it all; `stop` ends it gracefully:
/// the frames already taken are decoded, the blocks written, and the blocks
/// that are in `out` are reported.
async fn relay_download(url: String, manifest: TransferManifest, out: Arc<std::fs::File>, stop: oneshot::Receiver<()>, bump: Bump) -> Result<RelayEnd> {
    let response = bitmule_client_native::nic::http_client().get(url).send().await?.error_for_status()?;
    decode_download(Box::pin(response.bytes_stream()), None, manifest, out, stop, bump).await
}

type ByteStream = std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send>>;

/// `relay_download` on a stream that is already open. `prefix`, with its length,
/// is the start of the stream as it was kept: decoded first.
async fn decode_download(
    mut stream: ByteStream,
    prefix: Option<(std::fs::File, u64)>,
    manifest: TransferManifest,
    out: Arc<std::fs::File>,
    stop: oneshot::Receiver<()>,
    bump: Bump,
) -> Result<RelayEnd> {
    let mut splitter = fountain::FrameSplitter::default();
    let (tx, mut decode) = spawn_decoder(&manifest, out, bump, None)?;
    let size = manifest.transfer_size;

    let mut tx = Some(tx);
    let mut stop = Some(stop);
    let mut stopped = false;
    let mut span = Span::default();
    if let Some((file, len)) = prefix {
        // what was kept before the key was known; a frame cut at the end of it
        // is completed by the stream that follows (same splitter)
        let file = Arc::new(file);
        let mut pos = 0u64;
        'replay: while pos < len {
            let n = (len - pos).min(1 << 20) as usize;
            let chunk = {
                let file = file.clone();
                tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                    let mut buf = vec![0u8; n];
                    fountain::read_exact_at(&file, &mut buf, pos)?;
                    Ok(buf)
                }).await??
            };
            pos += n as u64;
            for payload in splitter.push(&chunk)? {
                span.mark();
                // a closed queue means the decoder is done, or has failed: its result says which
                if tx.as_ref().unwrap().send(payload).await.is_err() {
                    tx = None;
                    break 'replay;
                }
            }
        }
    }
    loop {
        tokio::select! {
            asked = async { stop.as_mut().unwrap().await }, if stop.is_some() => {
                stop = None;
                if asked.is_ok() {
                    stopped = true;
                    tx = None; // the decoder finishes what is queued, then ends
                }
            }
            chunk = stream.next(), if tx.is_some() => {
                match chunk {
                    Some(chunk) => {
                        let chunk = chunk?;
                        for payload in splitter.push(&chunk)? {
                            span.mark();
                            // a full queue holds the download back; the relay then drops
                            // frames for us and the sender covers them with fresh symbols
                            if tx.as_ref().unwrap().send(payload).await.is_err() {
                                tx = None;
                                break;
                            }
                        }
                    }
                    None => tx = None,
                }
            }
            result = &mut decode => {
                let done = result??;
                return if done.len() == fountain::num_blocks(size) as usize {
                    Ok(RelayEnd::Complete(span))
                } else if stopped {
                    Ok(RelayEnd::Stopped(done, span))
                } else {
                    bail!("relay stream ended before the transfer was complete")
                };
            }
        }
    }
}

/// Receive the transfer over UDP: find a path to the sender, decode the
/// symbols as they come and write the blocks, telling the sender which blocks
/// are in so that it stops coding them. Fails if no path is found, or when no
/// symbol arrives for `UDP_IDLE`.
async fn udp_download(
    stun: Option<std::net::SocketAddr>,
    link: PeerLink,
    manifest: TransferManifest,
    out: Arc<std::fs::File>,
    bump: Bump,
) -> Result<RelayEnd> {
    let PeerLink { tx: signal_tx, rx: signal_rx } = link;
    let mut udp = udp::connect(
        bitmule_client_native::Role::Receiver, manifest.bulk_key.clone(), stun, signal_tx, signal_rx,
        UdpConfig {
            // Test aid: BITMULE_UDP_DROP=0.05 drops 5% of incoming data datagrams.
            drop: std::env::var("BITMULE_UDP_DROP").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0),
            ..UdpConfig::default()
        }, BytesAssembler::new(),
    ).await?;
    let size = manifest.transfer_size;
    let (tx, mut decode) = spawn_decoder(&manifest, out, bump, Some(udp.block_done.clone()))?;
    let mut tx = Some(tx);
    let mut span = Span::default();
    loop {
        tokio::select! {
            payload = tokio::time::timeout(UDP_IDLE, udp.payloads_in.recv()), if tx.is_some() => match payload {
                Ok(Some(payload)) => {
                    span.mark();
                    // a full queue holds the reader back; the datagrams then queue up in the socket
                    if tx.as_ref().unwrap().send(payload).await.is_err() {
                        tx = None; // the decoder is done, or has failed: its result says which
                    }
                }
                Ok(None) => bail!("the udp link closed"),
                Err(_) => bail!("no symbol over udp for {} s", UDP_IDLE.as_secs()),
            },
            result = &mut decode => {
                let done = result??;
                ensure!(done.len() == fountain::num_blocks(size) as usize, "the udp transfer ended before it was complete");
                // the sender learns of the last blocks from the worker; give it the time to send them
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                return Ok(RelayEnd::Complete(span));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u64 = fountain::BLOCK_PLAIN as u64;

    #[test]
    fn missing_ranges_merge_neighbours_and_keep_the_short_last_block() {
        let size = B * 4 + 100; // five blocks
        let have: HashSet<u32> = [1].into();
        assert_eq!(missing_ranges(size, &have), vec![(0, B), (2 * B, size)]);
        assert_eq!(missing_ranges(size, &(0..5).collect()), vec![]);
        assert_eq!(missing_ranges(size, &HashSet::new()), vec![(0, size)]);
    }

    #[test]
    fn requests_go_one_range_at_a_time() {
        let mut dc = DcRequests::new(vec![(0, 100), (300, 350)]);
        assert_eq!(dc.current, Some((0, 100)));
        assert!(dc.accepts(0, 60));
        assert!(!dc.accepts(10, 60), "pieces arrive in order");
        assert_eq!(dc.received(60), None);
        assert!(dc.accepts(60, 40));
        assert!(!dc.accepts(60, 50), "not past the range");
        assert_eq!(dc.received(40), Some(Some((300, 350))));
        assert_eq!(dc.received(50), Some(None));
    }
}

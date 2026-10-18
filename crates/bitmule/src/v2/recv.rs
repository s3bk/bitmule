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
};
use bitmule_core::{
    ReceiverId, SessionId, Token,
    protocol::websocket::{Peer2Peer, PeerCaps, TransferManifest},
};
use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{sync::{mpsc, oneshot}, task::JoinHandle};
use tracing::warn;

use super::{Options, Report, Server, Span, Transport, dcproto, peer::PeerLink};

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
        if now - last >= REPORT_EVERY.as_millis() as u64
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

pub async fn receive(mut ctx: Context, sender_caps: PeerCaps, app: PeerLink, signaling: PeerLink) -> Result<Report> {
    let PeerLink { tx, mut rx } = app;

    let manifest = loop {
        match rx.recv().await {
            Some(Peer2Peer::Manifest(manifest)) => break manifest,
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
    ensure!(use_relay || use_webrtc, "sender and receiver have no transport in common");

    tx.send(Peer2Peer::Get { start: 0, end: size }).await?;

    // TEMP-INSTR: BITMULE_MEMOUT=1 puts the data channel's output in memory, not the file
    let mut mem: Option<Vec<u8>> = std::env::var_os("BITMULE_MEMOUT").map(|_| vec![0u8; size as usize]);
    let mut transport = Transport::Relay;
    let mut relay_time = Span::default();
    let mut data_channel_time = Span::default();
    let mut dc_bytes = 0u64;
    let mut relay_bytes = size;
    if size > 0 {
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
                    Some(Peer2Peer::JoinRelay) if use_relay => relay_offered = true,
                    Some(Peer2Peer::JoinRelay) | Some(Peer2Peer::Progress(_)) => {}
                    Some(_) => bail!("unexpected message during transfer"),
                    None => bail!("sender went away"),
                },
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
                    Some(ChannelEvent::Message(message)) => match dcproto::Message::decode(message)? {
                        dcproto::Message::Data { offset, bytes } if data_channel_active && dc.current.is_some() => {
                            let len = bytes.len() as u64;
                            ensure!(dc.accepts(offset, len), "sender sent data that was not asked for");
                            data_channel_time.mark();
                            if let Some(mem) = mem.as_mut() { mem[offset as usize..][..bytes.len()].copy_from_slice(&bytes); } else { dc_writer.as_ref().unwrap().write_bytes(offset, bytes).await?; } // TEMP-INSTR
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
                        _ => bail!("unexpected data channel message"),
                    },
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
        ensure!(hasher.finalize(&manifest.bulk_key) == ctx.link.signature, "data does not match the share link's signature");
        tx.send(Peer2Peer::Complete).await?;
        return Ok(Report { manifest, transport, relay_bytes, data_channel_bytes: dc_bytes, relay_time, data_channel_time });
    }
    if commitment_of(out.clone(), size, manifest.bulk_key.clone()).await? != ctx.link.signature {
        bail!("data does not match the share link's signature");
    }
    tx.send(Peer2Peer::Complete).await?;
    Ok(Report { manifest, transport, relay_bytes, data_channel_bytes: dc_bytes, relay_time, data_channel_time })
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
    let mut stream = response.bytes_stream();
    let mut splitter = fountain::FrameSplitter::default();

    let (tx, mut frames) = mpsc::channel::<Bytes>(DECODE_QUEUE);
    let (key, size) = (manifest.bulk_key.clone(), manifest.transfer_size);
    let runtime = tokio::runtime::Handle::current();
    let mut decode = tokio::task::spawn_blocking(move || -> Result<Vec<u32>> {
        use tokio::sync::mpsc::error::TryRecvError;

        let symbols = fountain::symbol_pool();
        // spilling and reading back happens on threads of its own; what is
        // read back arrives here, and only the block concerned waits for it
        let (loaded_tx, mut loaded) = mpsc::unbounded_channel();
        let spill = FileSpill::spawn(out.clone(), size, symbols.clone(), loaded_tx)?;
        let mut decoder = fountain::Decoder::new(key, size, Box::new(spill), symbols);
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
                    writer.write(block)?;
                }
            }
            Ok(())
        })();
        let written = writer.finish();
        decoded?;
        written?;
        Ok(decoder.done_blocks())
    });

    let mut tx = Some(tx);
    let mut stop = Some(stop);
    let mut stopped = false;
    let mut span = Span::default();
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

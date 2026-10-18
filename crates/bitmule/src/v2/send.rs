//! The sending side of a transfer, for one receiver.
//!
//! A transfer worker per receiver (`serve_peer`) answers what the receiver
//! asks for. For the whole file it offers the transports: the relay (one
//! upload worker for all receivers, fountain coded) and a WebRTC data channel
//! (a worker of its own per receiver, plus one that reads ranges for it).

use std::{future::Future, pin::Pin, sync::{Arc, Mutex}};

use anyhow::{Result, bail, ensure};
use bitmule_client_common::{blockio::{RangeData, read_blocks, read_ranges}, fountain, transfer::Transfer};
use bitmule_client_native::crypto::{BulkKey, CommitmentHasher};
use bitmule_client_native::udp::{self, BytesAssembler, UdpConfig};
use bitmule_core::{
    ReceiverId, SessionId, Token,
    protocol::websocket::{Peer2Peer, PeerCaps, TransferManifest, TransferType},
};
use bytes::Bytes;
use futures_util::stream::FuturesOrdered;
use futures_util::StreamExt;
use tokio::{io::{AsyncRead, AsyncReadExt}, sync::{mpsc, watch}, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use bitmule_client_native::rtc::{self, ChannelEvent, DataChannel};

use super::{OnSendEvent, Options, SendEvent, Server, Span, dcproto, peer::PeerLink};

/// Size of one `InlineData` piece. Stays well below the server's
/// WebSocket message limit.
const INLINE_PIECE: usize = 64 * 1024;
/// Frames queued between the encoder and the upload (the demo's packet queue).
const UPLOAD_QUEUE: usize = 1024;

/// What every receiver's worker needs.
pub struct Context {
    server: Server,
    our_id: ReceiverId,
    session_id: SessionId,
    relay_token: Token,
    manifest: TransferManifest,
    transfer: Arc<Transfer>,
    options: Options,
    relay: RelayTask,
    events: OnSendEvent,
}

impl Context {
    pub fn new(
        server: Server,
        our_id: ReceiverId,
        session_id: SessionId,
        relay_token: Token,
        manifest: TransferManifest,
        transfer: Transfer,
        options: Options,
        events: OnSendEvent,
    ) -> Self {
        Context {
            server, our_id, session_id, relay_token, manifest,
            transfer: Arc::new(transfer),
            options,
            relay: RelayTask::default(),
            events,
        }
    }
}

/// The one upload to the relay, shared by all receivers. Aborted on drop.
#[derive(Default)]
struct RelayTask(std::sync::Mutex<Option<JoinHandle<()>>>);

impl RelayTask {
    fn start_once(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut handle = self.0.lock().unwrap();
        if handle.is_none() {
            *handle = Some(tokio::spawn(task));
        }
    }
}
impl Drop for RelayTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.lock().unwrap().take() {
            handle.abort();
        }
    }
}

/// A data channel to one receiver and the worker that serves its requests.
struct Webrtc {
    channel: DataChannel,
    /// Ranges the receiver asked for, for the worker that reads them.
    requests: mpsc::Sender<(u64, u64)>,
}

/// Serve one receiver until it says it is done.
pub async fn serve_peer(ctx: Arc<Context>, id: ReceiverId, peer_caps: PeerCaps, app: PeerLink, signaling: PeerLink, udp: PeerLink) -> Result<()> {
    let PeerLink { tx, mut rx } = app;
    let receiver = id.as_hex().chars().take(8).collect::<String>();
    (ctx.events)(SendEvent::Connected { receiver: receiver.clone() });
    let size = ctx.manifest.transfer_size;
    let mut signaling = Some(signaling);
    let mut udp = Some(udp);
    let mut webrtc: Option<Webrtc> = None;
    let relay_offered = ctx.options.relay && peer_caps.contains(PeerCaps::RELAY);
    let udp_offered = ctx.options.udp && peer_caps.contains(PeerCaps::UDP);
    // UDP goes first; relay and WebRTC are started when it does not work out
    let mut udp_task: Option<AbortOnDrop<Result<()>>> = None;
    let mut fallback_due = false;

    tx.send(Peer2Peer::Manifest(ctx.manifest.clone())).await?;
    loop {
        tokio::select! {
            message = rx.recv() => {
                let Some(message) = message else { bail!("receiver went away") };
                match message {
                    Peer2Peer::Get { start, end } if start == 0 && end == size && size > 0 => {
                        match udp.take() {
                            Some(link) if udp_offered => {
                                let ctx = ctx.clone();
                                udp_task = Some(AbortOnDrop(tokio::spawn(async move { udp_upload(&ctx, link).await })));
                            }
                            _ => fallback_due = true,
                        }
                    }
                    Peer2Peer::Get { start, end } => {
                        ensure!(start <= end && end <= size, "get range outside the transfer");
                        let mut pos = start;
                        while pos < end {
                            let len = INLINE_PIECE.min((end - pos) as usize);
                            let data = ctx.transfer.read_at(pos, len).await?;
                            ensure!(!data.is_empty(), "get range past the end of the data");
                            tx.send(Peer2Peer::InlineData { start: pos, data: data.clone() }).await?;
                            pos += data.len() as u64;
                        }
                    }
                    Peer2Peer::Complete => {
                        (ctx.events)(SendEvent::Done { receiver });
                        return Ok(());
                    }
                    // an early UDP hello that arrived on the app side: not ours to handle
                    Peer2Peer::UdpHello(_) => {}
                    Peer2Peer::Progress(bytes) => {
                        (ctx.events)(SendEvent::Progress { receiver: receiver.clone(), bytes: bytes.min(size), total: size });
                    }
                    _ => bail!("unexpected message from receiver"),
                }
            }
            result = async { (&mut udp_task.as_mut().unwrap().0).await }, if udp_task.is_some() => {
                udp_task = None;
                match result {
                    // the receiver has every block; it says so itself in a moment
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!("udp: {e:#}");
                        fallback_due = true;
                    }
                    Err(e) => {
                        warn!("udp worker: {e}");
                        fallback_due = true;
                    }
                }
            }
            event = async { webrtc.as_mut().unwrap().channel.events.recv().await }, if webrtc.is_some() => {
                match event {
                    Some(ChannelEvent::Message(message)) => match dcproto::Message::decode(message)? {
                        dcproto::Message::Get { start, end } => {
                            ensure!(start <= end && end <= size, "get range outside the transfer");
                            let _ = webrtc.as_ref().unwrap().requests.send((start, end)).await;
                        }
                        dcproto::Message::Data { .. } => bail!("receiver sent data"),
                    },
                    Some(ChannelEvent::Segments(_)) => bail!("receiver sent a message in pieces"),
                    Some(ChannelEvent::Open) => {}
                    Some(ChannelEvent::Closed) | None => {
                        // the relay, if this receiver uses it, carries on without the channel
                        ensure!(relay_offered, "data channel closed and there is no relay to fall back on");
                        webrtc = None;
                    }
                }
            }
        }

        if fallback_due {
            fallback_due = false;
            if relay_offered {
                tx.send(Peer2Peer::JoinRelay).await?;
                let relay = ctx.clone();
                ctx.relay.start_once(async move {
                    if let Err(e) = relay_upload(&relay).await {
                        warn!("relay upload: {e}");
                    }
                });
            }
            if ctx.options.webrtc && peer_caps.contains(PeerCaps::WEBRTC) {
                if let Some(signaling) = signaling.take() {
                    let channel = rtc::spawn(rtc::Role::Offerer, ctx.server.stun_addr().await, signaling.tx, signaling.rx).await?;
                    let (requests, ranges) = mpsc::channel(8);
                    tokio::spawn(serve_ranges(ctx.transfer.path().to_path_buf(), size, ranges, channel.send.clone()));
                    webrtc = Some(Webrtc { channel, requests });
                }
            }
            ensure!(relay_offered || webrtc.is_some() || udp_task.is_some(), "no transport in common with the receiver");
        }
    }
}

/// A task that is aborted when this goes away.
pub(super) struct AbortOnDrop<T>(pub(super) JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send the fountain coded transfer to one receiver over UDP, pass after
/// pass, until the receiver has reported every block. Fails if no path is
/// found or the link dies; then the other transports take over.
///
/// The same pipeline as `relay_upload` (a reader, a few encoders), but the
/// symbols go to the UDP worker, which paces them to the receiver's reports,
/// and a block the receiver has finished is not coded again.
async fn udp_upload(ctx: &Context, link: PeerLink) -> Result<()> {
    let size = ctx.manifest.transfer_size;
    let total = fountain::num_blocks(size);
    let PeerLink { tx: signal_tx, rx: signal_rx } = link;
    let stun = ctx.server.stun_addr().await;
    let udp = udp::connect(
        bitmule_client_native::Role::Sender, ctx.manifest.bulk_key.clone(), stun, signal_tx, signal_rx,
        UdpConfig::default(), BytesAssembler::new(),
    ).await?;
    info!("udp path found, datagrams carry {} bytes of symbol", udp.fragment);

    let mut stats = SendStats::new("udp");
    let encoder = Arc::new(fountain::Encoder::new());
    let mut blocks = read_blocks(ctx.transfer.path().to_path_buf(), size, encoder.block_pool());
    let parallel = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(1, 4);
    let promised = Arc::new(ctx.manifest.block_hashes.clone());
    let mut encoding = FuturesOrdered::new();
    let mut reading = true;
    loop {
        if udp.done.all(total) {
            return Ok(());
        }
        while reading && encoding.len() < parallel {
            match blocks.recv().await {
                Some(block) => {
                    let block = block?;
                    let (encoder, key, promised, done) = (encoder.clone(), ctx.manifest.bulk_key.clone(), promised.clone(), udp.done.clone());
                    encoding.push_back(tokio::task::spawn_blocking(move || -> Result<Vec<Bytes>> {
                        // the receiver has this one
                        if done.contains(block.block_nr) {
                            return Ok(Vec::new());
                        }
                        let encoded = encoder.encode_block(&key, block.block_nr, block.buf, block.len)?;
                        if let Some(&promised) = promised.get(block.block_nr as usize) {
                            ensure!(encoded.hash() == promised, "block {} is not what the manifest promised: the data changed", block.block_nr);
                        }
                        Ok(encoded.frames(block.pass))
                    }));
                }
                None => reading = false,
            }
        }
        let Some(frames) = encoding.next().await else { return Ok(()) };
        for frame in frames?? {
            let payload = fountain::frame_payload(&frame);
            let len = payload.len() as u64;
            if udp.payloads_out.send(payload).await.is_err() {
                bail!("the udp worker stopped");
            }
            stats.sent(len);
        }
    }
}

/// Reads the ranges the receiver asks for over the data channel, a block at
/// a time (`read_ranges`), and sends them as pieces. Ends when either side is
/// dropped.
async fn serve_ranges(path: std::path::PathBuf, size: u64, requests: mpsc::Receiver<(u64, u64)>, send: mpsc::Sender<Bytes>) {
    let mut ranges = read_ranges(path, size, requests);
    let mut stats = SendStats::new("data channel");
    let messages = dcproto::message_pool();
    while let Some(Ok(RangeData { offset, data })) = ranges.recv().await {
        let mut pos = 0;
        while pos < data.len() {
            let end = (pos + dcproto::PIECE).min(data.len());
            let message = dcproto::data_message(&messages, offset + pos as u64, &data[pos..end]);
            if send.send(message).await.is_err() {
                return;
            }
            stats.sent((end - pos) as u64);
            pos = end;
        }
    }
}

/// What a sending task handed on, first to last piece. Logs the figures
/// when the task ends.
struct SendStats {
    what: &'static str,
    span: Span,
    bytes: u64,
}

impl SendStats {
    fn new(what: &'static str) -> Self {
        SendStats { what, span: Span::default(), bytes: 0 }
    }

    fn sent(&mut self, bytes: u64) {
        self.span.mark();
        self.bytes += bytes;
    }
}

impl Drop for SendStats {
    fn drop(&mut self) {
        if let Some(line) = self.span.describe(self.bytes) {
            info!("sent over the {}: {line}", self.what);
        }
    }
}

/// A POST to the relay whose body is whatever is sent into the channel.
fn open_upload(url: String) -> (mpsc::Sender<Result<Bytes, std::io::Error>>, JoinHandle<reqwest::Result<reqwest::Response>>) {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(UPLOAD_QUEUE);
    let post = tokio::spawn(
        bitmule_client_native::nic::http_client().post(url).body(reqwest::Body::wrap_stream(ReceiverStream::new(rx))).send()
    );
    (tx, post)
}

/// Upload the fountain coded transfer, pass after pass, until aborted. The
/// relay holds the upload back while no receiver is connected.
///
/// A pipeline, as in `raptor-demo`: a reader thread (io_uring on Linux)
/// reads blocks ahead into pooled buffers, a few encoders work on them in
/// parallel on blocking threads (their output stays in order), and the
/// frames, which are pooled buffers too, go to the relay as they are.
async fn relay_upload(ctx: &Context) -> Result<()> {
    let size = ctx.manifest.transfer_size;
    let url = ctx.server.http(&format!(
        "/session/{}/{}?token={}",
        ctx.session_id.as_hex(), ctx.our_id.as_hex(), ctx.relay_token.as_hex(),
    ));

    let (tx, post) = open_upload(url);

    // the frames count, repair symbols included, so this is wire bytes
    let mut stats = SendStats::new("relay");
    let encoder = Arc::new(fountain::Encoder::new());
    let mut blocks = read_blocks(ctx.transfer.path().to_path_buf(), size, encoder.block_pool());
    let parallel = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(1, 4);

    let mut encoding = FuturesOrdered::new();
    let mut reading = true;
    // what the manifest promised each block would be: the staged copy must not change
    let promised = Arc::new(ctx.manifest.block_hashes.clone());
    loop {
        // keep the encoders busy, then send what is ready
        while reading && encoding.len() < parallel {
            match blocks.recv().await {
                Some(block) => {
                    let block = block?;
                    let (encoder, key, promised) = (encoder.clone(), ctx.manifest.bulk_key.clone(), promised.clone());
                    encoding.push_back(tokio::task::spawn_blocking(move || -> Result<Vec<Bytes>> {
                        let encoded = encoder.encode_block(&key, block.block_nr, block.buf, block.len)?;
                        if let Some(&promised) = promised.get(block.block_nr as usize) {
                            ensure!(encoded.hash() == promised, "block {} is not what the manifest promised: the data changed", block.block_nr);
                        }
                        Ok(encoded.frames(block.pass))
                    }));
                }
                None => reading = false,
            }
        }
        let Some(frames) = encoding.next().await else { return Ok(()) };
        for frame in frames?? {
            let len = frame.len() as u64;
            if tx.send(Ok(frame)).await.is_err() {
                // the upload ended; see why
                bail!("relay closed the upload: {:?}", post.await?.map(|r| r.status()));
            }
            stats.sent(len);
        }
    }
}

/// Pass 0 notes the hash of block `nr`; later passes must find the same.
fn record_or_check_hash(hashes: &mut Vec<u64>, pass: u32, nr: u32, hash: u64) -> Result<()> {
    if pass == 0 {
        // the blocks of a pass are coded in parallel, so they can finish out of order
        if hashes.len() <= nr as usize {
            hashes.resize(nr as usize + 1, 0);
        }
        hashes[nr as usize] = hash;
        return Ok(());
    }
    match hashes.get(nr as usize) {
        Some(&first) if first == hash => Ok(()),
        Some(_) => bail!("block {nr} changed between pass 0 and pass {pass}: the source did not give the same bytes twice"),
        None => bail!("block {nr} did not exist on the first pass"),
    }
}

// ---- streaming transfers ---------------------------------------------------
//
// For data whose size and hash are not known until it has all been read. The
// bulk key exists from the start, so the fountain code sends the data as it is
// read; only what needs the whole data comes after it: the size, the hash, and
// with them the manifest. A receiver recognizes a streaming sender by `JoinRelay`
// arriving before any `Manifest`; the sender then ends the transfer with
// `Manifest` and `Checksum`. Normal transfers are not touched by any of this.
//
// A repair pass needs the data again, so the source must be restartable: it
// is opened once per pass.

pub type Reader = Box<dyn AsyncRead + Send + Unpin>;
type OpenFuture = Pin<Box<dyn Future<Output = std::io::Result<Reader>> + Send>>;

/// Where a streaming transfer's data comes from.
pub enum StreamSource {
    /// Opened again for every pass: a file that is still growing, an archive
    /// generated on demand. Every pass has to produce the same bytes.
    Restartable(Box<dyn Fn() -> OpenFuture + Send + Sync>),
    /// Can be read once (a pipe). What is read is kept in a temporary file,
    /// which then serves the later passes.
    OneShot(Mutex<Option<Reader>>),
}

impl StreamSource {
    pub fn restartable<F, Fut>(open: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<Reader>> + Send + 'static,
    {
        StreamSource::Restartable(Box::new(move || Box::pin(open())))
    }

    pub fn one_shot(reader: impl AsyncRead + Send + Unpin + 'static) -> Self {
        StreamSource::OneShot(Mutex::new(Some(Box::new(reader))))
    }
}

/// What the sender knows about a streaming transfer before it starts.
pub struct StreamInfo {
    pub typ: TransferType,
    /// What the receiver saves it as.
    pub name: Option<String>,
    /// The size, if the caller has an idea: only for the progress totals
    /// until the real one is known. The transfer does not depend on it.
    pub size_hint: Option<u64>,
}

impl StreamInfo {
    /// One file (or any single stream) called `name`.
    pub fn file(name: impl Into<String>) -> Self {
        StreamInfo { typ: TransferType::SingleFile { compression: None }, name: Some(name.into()), size_hint: None }
    }
}

/// What the end of the data adds: the manifest, now with the size, and the checksum.
pub struct Finished {
    manifest: TransferManifest,
    checksum: [u8; 32],
}

pub struct StreamContext {
    server: Server,
    our_id: ReceiverId,
    session_id: SessionId,
    relay_token: Token,
    options: Options,
    events: OnSendEvent,
    key: BulkKey,
    info: StreamInfo,
    source: StreamSource,
    /// Backs a one-shot source (kept while the transfer runs).
    spool: Option<tempfile::NamedTempFile>,
    finished: watch::Sender<Option<Arc<Finished>>>,
    /// Set when the upload failed (say, the source changed between passes).
    failed: watch::Sender<Option<String>>,
    /// The upload to the relay, one for all receivers.
    producer: RelayTask,
}

impl StreamContext {
    pub fn new(
        server: Server,
        our_id: ReceiverId,
        session_id: SessionId,
        relay_token: Token,
        info: StreamInfo,
        source: StreamSource,
        options: Options,
        events: OnSendEvent,
    ) -> Result<Self> {
        let spool = match &source {
            StreamSource::OneShot(_) => Some(tempfile::NamedTempFile::new()?),
            StreamSource::Restartable(_) => None,
        };
        Ok(StreamContext {
            server, our_id, session_id, relay_token, options, events, info, source, spool,
            key: BulkKey::random(),
            finished: watch::channel(None).0,
            failed: watch::channel(None).0,
            producer: RelayTask::default(),
        })
    }

    /// The size once it is known, else the caller's idea of it, else 0.
    fn total(&self) -> u64 {
        match &*self.finished.borrow() {
            Some(done) => done.manifest.transfer_size,
            None => self.info.size_hint.unwrap_or(0),
        }
    }

    async fn open(&self, pass: u32) -> std::io::Result<Reader> {
        match &self.source {
            StreamSource::Restartable(open) => open().await,
            StreamSource::OneShot(reader) if pass == 0 => reader
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| std::io::Error::other("a one-shot source can only be read once")),
            StreamSource::OneShot(_) => Ok(Box::new(tokio::fs::File::open(self.spool.as_ref().expect("one-shot sources have a spool").path()).await?)),
        }
    }
}

/// Fill `buf` from `reader`; fewer bytes than `buf` holds only at the end of the data.
async fn read_full(reader: &mut Reader, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let m = reader.read(&mut buf[n..]).await?;
        if m == 0 {
            break;
        }
        n += m;
    }
    Ok(n)
}

/// The upload of a streaming transfer failed for good; the whole send ends.
#[derive(Debug)]
pub struct UploadFailed(pub String);

impl std::fmt::Display for UploadFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the upload failed: {}", self.0)
    }
}
impl std::error::Error for UploadFailed {}

/// Serve one receiver of a streaming transfer: tell it to take the data from
/// the relay at once, and hand it the manifest and checksum when they exist.
pub async fn serve_stream_peer(ctx: Arc<StreamContext>, id: ReceiverId, peer_caps: PeerCaps, app: PeerLink) -> Result<()> {
    let PeerLink { tx, mut rx } = app;
    let receiver = id.as_hex().chars().take(8).collect::<String>();
    (ctx.events)(SendEvent::Connected { receiver: receiver.clone() });
    ensure!(
        ctx.options.relay && peer_caps.contains(PeerCaps::RELAY),
        "a streaming transfer goes over the relay, and one side does not use it"
    );

    tx.send(Peer2Peer::JoinRelay).await?;
    let upload = ctx.clone();
    ctx.producer.start_once(async move {
        if let Err(e) = stream_upload(&upload).await {
            warn!("streaming upload: {e:#}");
            upload.failed.send_replace(Some(format!("{e:#}")));
        }
    });

    let mut finished = ctx.finished.subscribe();
    let mut failed = ctx.failed.subscribe();
    let mut told = false;
    loop {
        if !told {
            let done = finished.borrow_and_update().clone();
            if let Some(done) = done {
                tx.send(Peer2Peer::Manifest(done.manifest.clone())).await?;
                tx.send(Peer2Peer::Checksum(done.checksum)).await?;
                told = true;
            }
        }
        tokio::select! {
            changed = finished.changed(), if !told => {
                ensure!(changed.is_ok(), "the transfer ended");
            }
            _ = failed.changed() => {
                let why = failed.borrow().clone().unwrap_or_default();
                return Err(UploadFailed(why).into());
            }
            message = rx.recv() => match message {
                None => bail!("receiver went away"),
                Some(Peer2Peer::Complete) => {
                    (ctx.events)(SendEvent::Done { receiver });
                    return Ok(());
                }
                Some(Peer2Peer::Progress(bytes)) => {
                    let total = ctx.total();
                    (ctx.events)(SendEvent::Progress { receiver: receiver.clone(), bytes: if total > 0 { bytes.min(total) } else { bytes }, total });
                }
                // signaling and the like: there is no data channel in a streaming transfer
                Some(_) => {}
            }
        }
    }
}

/// Read the source, code it and upload it as it comes, then go on with repair
/// passes until aborted. The first pass also computes the hash and finds the
/// size; once it is through, `finished` is set.
async fn stream_upload(ctx: &StreamContext) -> Result<()> {
    let url = ctx.server.http(&format!(
        "/session/{}/{}?token={}",
        ctx.session_id.as_hex(), ctx.our_id.as_hex(), ctx.relay_token.as_hex(),
    ));
    let (tx, post) = open_upload(url);
    let mut stats = SendStats::new("relay");
    let encoder = Arc::new(fountain::Encoder::new());
    let parallel = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(1, 4);
    let spool = match &ctx.spool {
        Some(file) => Some(Arc::new(file.as_file().try_clone()?)),
        None => None,
    };

    let mut hasher = Some(CommitmentHasher::new());
    let mut size = 0u64;
    // The hash of every block as coded, noted on the first pass and held to on
    // the others. A repair symbol of a pass is made from the block read again
    // and encrypted under the same key and nonce as before: if the source gave
    // other bytes this time, the two encryptions would give away the XOR of
    // the two plaintexts (and the authentication key). So any change is fatal.
    let hashes: Arc<Mutex<Vec<u64>>> = Arc::default();
    for pass in 0u32.. {
        let mut reader = ctx.open(pass).await?;
        let mut encoding = FuturesOrdered::new();
        let (mut block_nr, mut offset) = (0u32, 0u64);
        let mut ended = false;
        loop {
            // keep the encoders busy, then send what is ready
            while !ended && encoding.len() < parallel {
                let mut buf = encoder.block_buffer();
                let len = read_full(&mut reader, &mut buf[..fountain::BLOCK_PLAIN]).await?;
                if len == 0 {
                    ended = true;
                    break;
                }
                ended = len < fountain::BLOCK_PLAIN;
                if let Some(hasher) = hasher.as_mut() {
                    hasher.update(&buf[..len]);
                }
                let (encoder, key) = (encoder.clone(), ctx.key.clone());
                let (nr, at) = (block_nr, offset);
                // the first pass of a one-shot source is what the later passes read back
                let keep = if pass == 0 { spool.clone() } else { None };
                let hashes = hashes.clone();
                encoding.push_back(tokio::task::spawn_blocking(move || -> Result<Vec<Bytes>> {
                    if let Some(file) = keep {
                        fountain::write_all_at(&file, &buf[..len], at)?;
                    }
                    let encoded = encoder.encode_block(&key, nr, buf, len)?;
                    record_or_check_hash(&mut hashes.lock().unwrap(), pass, nr, encoded.hash())?;
                    Ok(encoded.frames(pass))
                }));
                block_nr += 1;
                offset += len as u64;
            }
            let Some(frames) = encoding.next().await else { break };
            for frame in frames?? {
                let len = frame.len() as u64;
                if tx.send(Ok(frame)).await.is_err() {
                    bail!("relay closed the upload: {:?}", post.await?.map(|r| r.status()));
                }
                stats.sent(len);
            }
        }

        if pass == 0 {
            size = offset;
            let checksum = hasher.take().expect("hashed on the first pass").finalize(&ctx.key);
            let block_hashes = std::mem::take(&mut *hashes.lock().unwrap());
            // the same list is what later passes are held to
            let manifest = TransferManifest {
                transfer_typ: ctx.info.typ.clone(),
                block_size: fountain::BLOCK_PLAIN as u32,
                transfer_size: size,
                bulk_key: ctx.key.clone(),
                block_hashes: if block_hashes.len() <= fountain::MAX_MANIFEST_HASHES { block_hashes.clone() } else { Vec::new() },
                name: ctx.info.name.clone(),
            };
            *hashes.lock().unwrap() = block_hashes;
            ctx.finished.send_replace(Some(Arc::new(Finished { manifest, checksum })));
            if size == 0 {
                return Ok(()); // no blocks, nothing to repair
            }
        } else {
            ensure!(offset == size, "the source gave {offset} bytes on pass {pass}, {size} on the first");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::record_or_check_hash;

    #[test]
    fn later_passes_must_find_the_blocks_of_the_first() {
        let mut hashes = Vec::new();
        // blocks of the first pass finish in any order
        for (nr, hash) in [(1u32, 11u64), (0, 10), (2, 12)] {
            record_or_check_hash(&mut hashes, 0, nr, hash).unwrap();
        }
        assert_eq!(hashes, [10, 11, 12]);

        for pass in 1..4 {
            for (nr, hash) in [(0u32, 10u64), (1, 11), (2, 12)] {
                record_or_check_hash(&mut hashes, pass, nr, hash).unwrap();
            }
        }
        // a source that gave other bytes this time
        let err = record_or_check_hash(&mut hashes, 4, 1, 99).unwrap_err().to_string();
        assert!(err.contains("block 1 changed"), "{err}");
        // or more of them
        assert!(record_or_check_hash(&mut hashes, 4, 3, 13).is_err());
    }
}

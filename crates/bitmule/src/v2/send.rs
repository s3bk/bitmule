//! The sending side of a transfer, for one receiver.
//!
//! A transfer worker per receiver (`serve_peer`) answers what the receiver
//! asks for. For the whole file it offers the transports: the relay (one
//! upload worker for all receivers, fountain coded) and a WebRTC data channel
//! (a worker of its own per receiver, plus one that reads ranges for it).

use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use bitmule_client_common::{blockio::read_blocks, fountain, transfer::Transfer};
use bitmule_core::{
    ReceiverId, SessionId, Token,
    protocol::websocket::{Peer2Peer, PeerCaps, TransferManifest},
};
use bytes::Bytes;
use futures_util::stream::FuturesOrdered;
use futures_util::StreamExt;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

use bitmule_client_native::rtc::{self, ChannelEvent, DataChannel};

use super::{Options, Server, dcproto, peer::PeerLink};

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
    ) -> Self {
        Context {
            server, our_id, session_id, relay_token, manifest,
            transfer: Arc::new(transfer),
            options,
            relay: RelayTask::default(),
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
pub async fn serve_peer(ctx: Arc<Context>, peer_caps: PeerCaps, app: PeerLink, signaling: PeerLink) -> Result<()> {
    let PeerLink { tx, mut rx } = app;
    let size = ctx.manifest.transfer_size;
    let mut signaling = Some(signaling);
    let mut webrtc: Option<Webrtc> = None;

    tx.send(Peer2Peer::Manifest(ctx.manifest.clone())).await?;
    loop {
        tokio::select! {
            message = rx.recv() => {
                let Some(message) = message else { bail!("receiver went away") };
                match message {
                    Peer2Peer::Get { start, end } if start == 0 && end == size && size > 0 => {
                        if ctx.options.relay && peer_caps.contains(PeerCaps::RELAY) {
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
                                tokio::spawn(serve_ranges(ctx.transfer.clone(), ranges, channel.send.clone()));
                                webrtc = Some(Webrtc { channel, requests });
                            }
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
                    Peer2Peer::Complete => return Ok(()),
                    Peer2Peer::Progress(_) => {}
                    _ => bail!("unexpected message from receiver"),
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
                    Some(ChannelEvent::Open) => {}
                    // the relay (if any) carries on without it
                    Some(ChannelEvent::Closed) | None => webrtc = None,
                }
            }
        }
    }
}

/// Reads the ranges the receiver asks for over the data channel and sends
/// them as pieces. Ends when either side is dropped.
async fn serve_ranges(transfer: Arc<Transfer>, mut requests: mpsc::Receiver<(u64, u64)>, send: mpsc::Sender<Bytes>) {
    while let Some((start, end)) = requests.recv().await {
        let mut pos = start;
        while pos < end {
            let len = dcproto::PIECE.min((end - pos) as usize);
            let bytes = match transfer.read_at(pos, len).await {
                Ok(bytes) if !bytes.is_empty() => bytes,
                _ => return,
            };
            let offset = pos;
            pos += bytes.len() as u64;
            if send.send(dcproto::Message::Data { offset, bytes }.encode()).await.is_err() {
                return;
            }
        }
    }
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

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(UPLOAD_QUEUE);
    let post = tokio::spawn(
        bitmule_client_native::nic::http_client().post(url).body(reqwest::Body::wrap_stream(ReceiverStream::new(rx))).send()
    );

    let encoder = Arc::new(fountain::Encoder::new());
    let mut blocks = read_blocks(ctx.transfer.path().to_path_buf(), size, encoder.block_pool());
    let parallel = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(1, 4);

    let mut encoding = FuturesOrdered::new();
    let mut reading = true;
    loop {
        // keep the encoders busy, then send what is ready
        while reading && encoding.len() < parallel {
            match blocks.recv().await {
                Some(block) => {
                    let block = block?;
                    let (encoder, key) = (encoder.clone(), ctx.manifest.bulk_key.clone());
                    encoding.push_back(tokio::task::spawn_blocking(move || -> Result<Vec<Bytes>> {
                        Ok(encoder.encode_block(&key, block.block_nr, block.buf, block.len)?.frames(block.pass))
                    }));
                }
                None => reading = false,
            }
        }
        let Some(frames) = encoding.next().await else { return Ok(()) };
        for frame in frames?? {
            if tx.send(Ok(frame)).await.is_err() {
                // the upload ended; see why
                bail!("relay closed the upload: {:?}", post.await?.map(|r| r.status()));
            }
        }
    }
}

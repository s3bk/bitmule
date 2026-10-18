//! The data phase of `udp` on io_uring: many datagrams in flight at once on
//! one thread, with the same logic as the tokio workers.
//!
//! The socket is connected to the peer (after the handshake only the peer's
//! datagrams are wanted), which lets both directions use buffers registered
//! with the ring. Each direction has one slab, allocated up front and locked in
//! memory (`uring::Buffers`), so the kernel maps and pins its pages once.
//!
//! Receive: `RECV_INFLIGHT` reads are always outstanding, each into a slot of
//! the receive slab; a datagram is parsed in place and its fragment copied once
//! into the payload being put together. Send: header and payload slice are
//! copied into a slot of the send slab (one copy, from the producer's memory)
//! and sent from there.

use std::{cell::RefCell, net::SocketAddr, rc::Rc};

use bytes::Bytes;
use futures_util::future::join_all;
use tokio::{sync::mpsc, time::{interval, sleep, sleep_until}};
use tokio_uring::net::UdpSocket;
use tracing::{debug, warn};

use super::*;
use crate::uring::{Buffers, Stop, UBytes, spawn};

/// Reads outstanding on the receiver's socket (and slots of its slab).
const RECV_INFLIGHT: usize = 2048;
/// Operations outstanding for the sender's feedback.
const FEEDBACK_INFLIGHT: usize = 4;
/// Slots of the sender's slab: datagrams handed to the kernel and not yet seen complete.
const SEND_INFLIGHT: usize = 2048;

/// Fix the socket to the peer's address; from now on the kernel drops what comes from elsewhere.
fn connect_to(socket: &std::net::UdpSocket, remote: SocketAddr) -> std::io::Result<()> {
    socket2::SockRef::from(socket).connect(&remote.into())
}

pub(super) async fn start_sender(
    socket: std::net::UdpSocket,
    key: BulkKey,
    remote: SocketAddr,
    cfg: UdpConfig,
    payloads: mpsc::Receiver<Bytes>,
    done: Arc<DoneBlocks>,
) -> std::io::Result<Stop> {
    connect_to(&socket, remote)?;
    spawn("udp-uring-send", move || sender(socket, key, remote, cfg, payloads, done)).await
}

pub(super) async fn start_receiver<A: Assembler>(
    socket: std::net::UdpSocket,
    key: BulkKey,
    remote: SocketAddr,
    cfg: UdpConfig,
    assembler: A,
    payloads: mpsc::Sender<A::Item>,
    block_done: mpsc::UnboundedReceiver<u32>,
) -> std::io::Result<Stop> {
    connect_to(&socket, remote)?;
    spawn("udp-uring-recv", move || receiver(socket, key, remote, cfg, assembler, payloads, block_done)).await
}

async fn sender(
    socket: std::net::UdpSocket,
    key: BulkKey,
    remote: SocketAddr,
    cfg: UdpConfig,
    mut payloads: mpsc::Receiver<Bytes>,
    done: Arc<DoneBlocks>,
) {
    let socket = Rc::new(UdpSocket::from_std(socket));
    let key = Rc::new(key);
    let rate = Rc::new(RefCell::new(RateControl::new(&cfg)));
    for _ in 0..FEEDBACK_INFLIGHT {
        tokio_uring::spawn(read_feedback(socket.clone(), key.clone(), remote, rate.clone(), done.clone()));
    }

    let buffers = match Buffers::new(DATA_HEADER + cfg.fragment, SEND_INFLIGHT) {
        Ok(buffers) => Rc::new(buffers),
        Err(e) => {
            warn!("udp send buffers: {e}");
            return;
        }
    };
    debug!("udp send slab: {SEND_INFLIGHT} x {} bytes, registered: {}, locked: {}", DATA_HEADER + cfg.fragment, buffers.registered(), buffers.locked());

    // the receiver's first report says it is listening
    while !rate.borrow().ready {
        sleep(Duration::from_millis(1)).await;
    }

    let mut pacer = Pacer::new();
    let mut seq = 0u32;
    while let Some(payload) = payloads.recv().await {
        let count = payload.len().div_ceil(cfg.fragment);
        if count == 0 || count > u8::MAX as usize {
            warn!("udp: dropping a payload of {} bytes", payload.len());
            continue;
        }
        let bytes = payload.len() + count * DATA_HEADER;
        let current = rate.borrow().rate;
        if let Some(at) = pacer.reserve(bytes, current) {
            sleep_until(at).await;
        }

        // the one copy: header and payload slice into slots (waits if all are with the kernel)
        let mut datagrams = Vec::with_capacity(count);
        for (index, chunk) in payload.chunks(cfg.fragment).enumerate() {
            let mut buf = buffers.next().await;
            let len = DATA_HEADER + chunk.len();
            buf[..DATA_HEADER].copy_from_slice(&data_header(seq, index, count));
            buf[DATA_HEADER..len].copy_from_slice(chunk);
            datagrams.push((buf, len));
        }
        seq = seq.wrapping_add(1);

        let (socket, buffers) = (socket.clone(), buffers.clone());
        tokio_uring::spawn(async move {
            // all submitted before any completion is waited for
            let results = join_all(datagrams.into_iter().map(|(buf, len)| buffers.write(&socket, buf, len))).await;
            if let Some(Err(e)) = results.into_iter().find(Result::is_err) {
                debug!("udp send: {e}");
            }
        });
    }
}

/// Feedback (and a receiver's late `HELLO`s) arriving at the sender.
async fn read_feedback(socket: Rc<UdpSocket>, key: Rc<BulkKey>, remote: SocketAddr, rate: Rc<RefCell<RateControl>>, done: Arc<DoneBlocks>) {
    let mut buf = Vec::with_capacity(2048);
    loop {
        let (result, back) = socket.recv_from(buf).await;
        buf = back;
        match result {
            Ok((n, source)) => {
                let ack = sender_packet(&key, remote, &mut rate.borrow_mut(), &done, source, &buf[..n]);
                if let Some(ack) = ack {
                    let _ = socket.send_to(UBytes(ack), source).await;
                }
            }
            Err(e) => {
                debug!("udp recv: {e}");
                sleep(Duration::from_millis(10)).await;
            }
        }
        buf.clear();
    }
}

async fn receiver<A: Assembler>(
    socket: std::net::UdpSocket,
    key: BulkKey,
    remote: SocketAddr,
    cfg: UdpConfig,
    assembler: A,
    payloads: mpsc::Sender<A::Item>,
    mut block_done: mpsc::UnboundedReceiver<u32>,
) {
    let socket = Rc::new(UdpSocket::from_std(socket));
    let key = Rc::new(key);
    let state = Rc::new(RefCell::new(ReceiveState::new(&cfg, assembler)));
    let buffers = match Buffers::new(DATA_HEADER + cfg.fragment, RECV_INFLIGHT) {
        Ok(buffers) => Rc::new(buffers),
        Err(e) => {
            warn!("udp receive buffers: {e}");
            return;
        }
    };
    debug!("udp receive slab: {RECV_INFLIGHT} x {} bytes, registered: {}, locked: {}", DATA_HEADER + cfg.fragment, buffers.registered(), buffers.locked());
    for _ in 0..RECV_INFLIGHT {
        tokio_uring::spawn(read_data(socket.clone(), key.clone(), remote, state.clone(), buffers.clone(), payloads.clone()));
    }

    let mut tick = interval(FEEDBACK_EVERY);
    loop {
        tokio::select! {
            Some(block) = block_done.recv() => state.borrow_mut().tracker.add(block),
            _ = tick.tick() => {
                let feedback = state.borrow().feedback(&key);
                if let Ok(feedback) = feedback {
                    let _ = socket.send_to(UBytes(feedback), remote).await;
                }
            }
        }
    }
}

/// One of the receiver's outstanding reads, over and over.
async fn read_data<A: Assembler>(
    socket: Rc<UdpSocket>,
    key: Rc<BulkKey>,
    remote: SocketAddr,
    state: Rc<RefCell<ReceiveState<A>>>,
    buffers: Rc<Buffers>,
    payloads: mpsc::Sender<A::Item>,
) {
    loop {
        let (result, buf) = buffers.read(&socket, buffers.next().await).await;
        let n = match result {
            Ok(n) => n,
            Err(e) => {
                debug!("udp recv: {e}");
                drop(buf);
                sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // a connected socket: everything is from the peer
        let incoming = state.borrow_mut().packet(&key, remote, remote, &buf[..n]);
        drop(buf);
        match incoming {
            Incoming::Payload(payload) => {
                if payloads.send(payload).await.is_err() {
                    return;
                }
            }
            Incoming::Ack(ack) => {
                let _ = socket.send_to(UBytes(ack), remote).await;
            }
            Incoming::Nothing => {}
        }
    }
}

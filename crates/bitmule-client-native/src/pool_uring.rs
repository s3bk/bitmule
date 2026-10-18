//! The socket pool's I/O on io_uring: one thread reads from and sends on all
//! the pool's sockets (duplicates of them), with many operations outstanding
//! on each. Packets go on to the same peer queues as with tokio sockets.
//!
//! Receive: `RECV_INFLIGHT` reads per socket into pooled buffers, which then
//! travel on as `Bytes` without a copy. Send: batches (as str0m produced them
//! in one go) come in over a channel, one copy into a pooled buffer, and go to
//! the kernel together.

use std::{collections::HashMap, io, net::{IpAddr, SocketAddr}, rc::Rc, sync::{Arc, OnceLock}};

use bitmule_buf::Pool;
use futures_util::future::join_all;
use tokio::{sync::{Semaphore, mpsc}, time::sleep};
use tokio_uring::net::UdpSocket;
use tracing::debug;

use crate::{
    str0m_client::{DATAGRAM_MAX, Peers, PoolRecv, route_packet},
    uring::{Stop, UBuf, spawn},
};

/// Reads outstanding per socket.
const RECV_INFLIGHT: usize = 1024;
/// Datagrams the thread may have handed to the kernel and not yet seen complete.
const SEND_INFLIGHT: usize = 2048;
/// Batches waiting for the thread.
const BATCHES_QUEUED: usize = 1024;

pub(crate) struct Outgoing {
    /// The local address (its IP picks the socket).
    pub socket: IpAddr,
    pub dest: SocketAddr,
    pub data: bitmule_buf::Buf<DATAGRAM_MAX>,
}

/// The buffers outgoing datagrams are copied into: one slab, made on first use.
pub(crate) fn buffers() -> &'static Arc<Pool<DATAGRAM_MAX>> {
    static POOL: OnceLock<Arc<Pool<DATAGRAM_MAX>>> = OnceLock::new();
    POOL.get_or_init(|| Pool::slab(SEND_INFLIGHT * 2))
}

pub(crate) struct Started {
    pub tx: mpsc::Sender<Vec<Outgoing>>,
    _stop: Stop,
}

/// Start the thread. `sockets`: IP, a duplicate of the socket, and the
/// address packets arriving on it are reported as destined to.
pub(crate) async fn start(
    sockets: Vec<(IpAddr, std::net::UdpSocket, SocketAddr)>,
    peers: Peers,
    unclaimed: mpsc::Sender<PoolRecv>,
) -> io::Result<Started> {
    let (tx, rx) = mpsc::channel(BATCHES_QUEUED);
    let stop = spawn("pool-uring", move || run(sockets, peers, unclaimed, rx)).await?;
    Ok(Started { tx, _stop: stop })
}

async fn run(
    sockets: Vec<(IpAddr, std::net::UdpSocket, SocketAddr)>,
    peers: Peers,
    unclaimed: mpsc::Sender<PoolRecv>,
    mut outgoing: mpsc::Receiver<Vec<Outgoing>>,
) {
    // the reads in flight, and what waits in the peers' queues
    let received = Pool::<DATAGRAM_MAX>::slab(sockets.len() * RECV_INFLIGHT + 2048);
    let mut by_ip = HashMap::new();
    for (ip, socket, local) in sockets {
        let socket = Rc::new(UdpSocket::from_std(socket));
        for _ in 0..RECV_INFLIGHT {
            tokio_uring::spawn(read(socket.clone(), local, received.clone(), peers.clone(), unclaimed.clone()));
        }
        by_ip.insert(ip, socket);
    }

    let permits = Arc::new(Semaphore::new(SEND_INFLIGHT));
    while let Some(batch) = outgoing.recv().await {
        // a batch larger than the whole allowance still goes (alone)
        let wanted = batch.len().clamp(1, SEND_INFLIGHT) as u32;
        let Ok(permit) = permits.clone().acquire_many_owned(wanted).await else { return };
        let sends: Vec<_> = batch.into_iter().filter_map(|out| {
            let socket = by_ip.get(&out.socket)?.clone();
            Some(async move {
                let (result, _) = socket.send_to(UBuf(out.data), out.dest).await;
                if let Err(e) = result {
                    // the ICE state machine tries other pairs
                    debug!("send to {}: {e}", out.dest);
                }
            })
        }).collect();
        tokio_uring::spawn(async move {
            // all submitted before any completion is waited for
            join_all(sends).await;
            drop(permit);
        });
    }
}

/// One of a socket's outstanding reads, over and over.
async fn read(socket: Rc<UdpSocket>, local: SocketAddr, buffers: Arc<Pool<DATAGRAM_MAX>>, peers: Peers, unclaimed: mpsc::Sender<PoolRecv>) {
    loop {
        let (result, buf) = socket.recv_from(UBuf(buffers.get())).await;
        match result {
            Ok((_, source)) => {
                let packet = PoolRecv { bytes: buf.0.into_bytes(), source, destination: local };
                if !route_packet(&peers, &unclaimed, packet).await {
                    return;
                }
            }
            Err(e) => {
                debug!("recv on {local}: {e}");
                sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

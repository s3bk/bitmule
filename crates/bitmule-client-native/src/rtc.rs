//! A WebRTC data channel between two bitmule peers.
//!
//! This worker knows nothing about the signaling server or about
//! encryption. It is given a pair of channels to "the peer channel" and
//! exchanges `Peer2Peer` messages over them: its `SdpOffer` / `SdpAnswer`
//! go out through `signal_tx`, and the other side's come in on `signal_rx`.
//! Whatever carries those (in v2 the end-to-end encrypted peer worker) is
//! not its business. What it gives back is the data channel: messages in,
//! messages out, and when it is open or gone.
//!
//! The SDP has to arrive authenticated, because DTLS authenticates the peer
//! only by the fingerprint in it. That is why it travels in the encrypted
//! peer messages.
//!
//! One worker is one str0m `Rtc` with one reliable, ordered data channel and a
//! socket pool of its own, so several workers on a sender (one per receiver)
//! never have to share or sort packets. The pool binds each local interface
//! address, so a machine on ethernet and wifi offers both. All local
//! candidates travel inside the SDP; there is no trickle ICE.

use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use bitmule_core::protocol::websocket::{Peer2Peer, SdpAnswer as AnswerMsg, SdpOffer as OfferMsg};
use bytes::Bytes;
use str0m::{
    Event, IceConnectionState, Input, Output, Rtc,
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::ChannelId,
    net::{Protocol, Receive},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, warn};

use crate::str0m_client::{SocketPool, build_rtc_with_pool_candidates, build_socket_pool_with};

#[derive(Debug)]
pub enum ChannelEvent {
    /// The data channel is open; messages can be sent.
    Open,
    /// A message from the other peer.
    Message(Bytes),
    /// The link is over (failed or closed). Nothing follows.
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Makes the offer and the data channel.
    Offerer,
    /// Answers an offer.
    Answerer,
}

/// Messages queued towards the peer before `send` waits.
const SEND_QUEUE: usize = 64;
/// Events queued towards the caller before the worker waits.
const EVENT_QUEUE: usize = 256;
/// Below this much buffered data the channel takes more.
const BUFFER_LOW: usize = 256 * 1024;

/// The data channel, as seen from outside the worker. Dropping it stops the worker.
pub struct DataChannel {
    /// Messages for the other peer; they wait here until the channel is open.
    pub send: mpsc::Sender<Bytes>,
    pub events: mpsc::Receiver<ChannelEvent>,
    task: JoinHandle<()>,
}

impl Drop for DataChannel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Start the worker. `signal_tx` / `signal_rx` are the peer channel: the
/// `Peer2Peer` messages the worker sends and receives. Messages that are
/// not SDP are ignored. With a `stun` server the offer also carries the
/// public addresses of the sockets, so a peer behind another NAT can reach them.
pub async fn spawn(
    role: Role,
    stun: Option<std::net::SocketAddr>,
    signal_tx: mpsc::Sender<Peer2Peer>,
    signal_rx: mpsc::Receiver<Peer2Peer>,
) -> Result<DataChannel> {
    let pool = build_socket_pool_with(stun).await?;
    let rtc = build_rtc_with_pool_candidates(&pool);
    let (send, send_rx) = mpsc::channel(SEND_QUEUE);
    let (events_tx, events) = mpsc::channel(EVENT_QUEUE);
    let task = tokio::spawn(async move {
        if let Err(e) = run(role, rtc, pool, signal_tx, signal_rx, send_rx, &events_tx).await {
            warn!("webrtc worker ended: {e:#}");
        }
        let _ = events_tx.send(ChannelEvent::Closed).await;
    });
    Ok(DataChannel { send, events, task })
}

struct Driver {
    rtc: Rtc,
    pool: SocketPool,
    channel: Option<ChannelId>,
    open: bool,
}

async fn run(
    role: Role,
    rtc: Rtc,
    pool: SocketPool,
    signal_tx: mpsc::Sender<Peer2Peer>,
    mut signal_rx: mpsc::Receiver<Peer2Peer>,
    mut send_rx: mpsc::Receiver<Bytes>,
    events: &mpsc::Sender<ChannelEvent>,
) -> Result<()> {
    let mut d = Driver { rtc, pool, channel: None, open: false };
    let mut pending_offer: Option<SdpPendingOffer> = None;

    if role == Role::Offerer {
        let mut change = d.rtc.sdp_api();
        d.channel = Some(change.add_channel("bitmule".into()));
        let (offer, pending) = change.apply().ok_or_else(|| anyhow!("no offer to make"))?;
        pending_offer = Some(pending);
        signal_tx.send(Peer2Peer::SdpOffer(OfferMsg { sdp: offer.to_sdp_string() })).await?;
    }

    // a message taken from the queue that the channel did not accept yet
    let mut unsent: Option<Bytes> = None;
    loop {
        let timeout = d.drain(events).await?;

        if let (Some(buf), true) = (&unsent, d.open) {
            let id = d.channel.expect("open implies a channel");
            let accepted = d.rtc.channel(id).ok_or_else(|| anyhow!("channel gone"))?
                .write(true, buf).map_err(|e| anyhow!("channel write: {e}"))?;
            if accepted {
                unsent = None;
                continue; // drain after every mutation
            }
        }

        let wait = timeout.saturating_duration_since(Instant::now());
        tokio::select! {
            packet = d.pool.recv() => {
                let packet = packet.ok_or_else(|| anyhow!("sockets closed"))?;
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: packet.source,
                    destination: packet.destination,
                    contents: (&*packet.bytes).try_into().map_err(|_| anyhow!("oversized packet"))?,
                });
                if d.rtc.accepts(&input) {
                    d.rtc.handle_input(input).map_err(|e| anyhow!("handle_input: {e}"))?;
                }
            }
            message = signal_rx.recv() => {
                let Some(message) = message else { return Ok(()) };
                match (message, role) {
                    (Peer2Peer::SdpOffer(OfferMsg { sdp }), Role::Answerer) => {
                        let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| anyhow!("parse offer: {e}"))?;
                        let answer = d.rtc.sdp_api().accept_offer(offer).map_err(|e| anyhow!("accept offer: {e}"))?;
                        signal_tx.send(Peer2Peer::SdpAnswer(AnswerMsg { sdp: answer.to_sdp_string() })).await?;
                    }
                    (Peer2Peer::SdpAnswer(AnswerMsg { sdp }), Role::Offerer) => {
                        let answer = SdpAnswer::from_sdp_string(&sdp).map_err(|e| anyhow!("parse answer: {e}"))?;
                        let pending = pending_offer.take().ok_or_else(|| anyhow!("unexpected answer"))?;
                        d.rtc.sdp_api().accept_answer(pending, answer).map_err(|e| anyhow!("accept answer: {e}"))?;
                    }
                    (Peer2Peer::SdpOffer(_) | Peer2Peer::SdpAnswer(_), role) => bail!("SDP does not fit the {role:?} role"),
                    _ => {} // not for us
                }
            }
            message = send_rx.recv(), if d.open && unsent.is_none() => {
                match message {
                    Some(message) => unsent = Some(message),
                    None => return Ok(()), // the owner dropped its sender: done
                }
            }
            _ = tokio::time::sleep(wait) => {
                d.rtc.handle_input(Input::Timeout(Instant::now())).map_err(|e| anyhow!("timeout: {e}"))?;
            }
        }
    }
}

impl Driver {
    /// Run str0m until it has nothing more to say; the rule is that this
    /// happens after every change. Returns when it wants to be woken next.
    async fn drain(&mut self, events: &mpsc::Sender<ChannelEvent>) -> Result<Instant> {
        loop {
            match self.rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
                Output::Timeout(at) => return Ok(at),
                Output::Transmit(t) => {
                    self.pool.send_from(t.source, t.destination, &t.contents).await
                        .with_context(|| format!("send to {}", t.destination))?;
                }
                Output::Event(Event::ChannelOpen(id, _label)) => {
                    self.channel = Some(id);
                    self.open = true;
                    if let Some(mut channel) = self.rtc.channel(id) {
                        channel.set_buffered_amount_low_threshold(BUFFER_LOW);
                    }
                    events.send(ChannelEvent::Open).await?;
                }
                Output::Event(Event::ChannelData(data)) if Some(data.id) == self.channel => {
                    events.send(ChannelEvent::Message(Bytes::from(data.data))).await?;
                }
                Output::Event(Event::ChannelClose(id)) if Some(id) == self.channel => {
                    bail!("data channel closed");
                }
                Output::Event(Event::IceConnectionStateChange(IceConnectionState::Disconnected)) => {
                    bail!("ICE disconnected");
                }
                Output::Event(event) => debug!("str0m: {event:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn next(channel: &mut DataChannel) -> ChannelEvent {
        tokio::time::timeout(std::time::Duration::from_secs(10), channel.events.recv()).await
            .expect("no event in time").expect("worker gone")
    }

    /// Two workers in this process, the peer channels wired to each other
    /// the way the encrypted peer workers wire them in v2.
    async fn connected_pair() -> (DataChannel, DataChannel) {
        let (to_answerer, answerer_in) = mpsc::channel(8);
        let (to_offerer, offerer_in) = mpsc::channel(8);
        let mut offerer = spawn(Role::Offerer, None, to_answerer, offerer_in).await.unwrap();
        let mut answerer = spawn(Role::Answerer, None, to_offerer, answerer_in).await.unwrap();

        for channel in [&mut offerer, &mut answerer] {
            loop {
                match next(channel).await {
                    ChannelEvent::Open => break,
                    ChannelEvent::Closed => panic!("closed before opening"),
                    ChannelEvent::Message(_) => panic!("message before open"),
                }
            }
        }
        (offerer, answerer)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn messages_flow_both_ways() {
        let (mut offerer, mut answerer) = connected_pair().await;

        offerer.send.send(Bytes::from_static(b"hello")).await.unwrap();
        let ChannelEvent::Message(m) = next(&mut answerer).await else { panic!() };
        assert_eq!(&m[..], b"hello");

        answerer.send.send(Bytes::from_static(b"and back")).await.unwrap();
        let ChannelEvent::Message(m) = next(&mut offerer).await else { panic!() };
        assert_eq!(&m[..], b"and back");
    }

    /// More than the channel's buffer holds, in order, so the sender has to wait.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lot_of_data_arrives_in_order() {
        let (offerer, mut answerer) = connected_pair().await;
        let (n, size) = (2000u32, 16 * 1024);

        let send = offerer.send.clone();
        let sender = tokio::spawn(async move {
            for i in 0..n {
                let mut m = vec![i as u8; size];
                m[..4].copy_from_slice(&i.to_le_bytes());
                send.send(m.into()).await.unwrap();
            }
        });
        for i in 0..n {
            let ChannelEvent::Message(m) = next(&mut answerer).await else { panic!("expected message {i}") };
            assert_eq!(m.len(), size);
            assert_eq!(u32::from_le_bytes(m[..4].try_into().unwrap()), i);
        }
        sender.await.unwrap();
        drop(offerer);
    }
}

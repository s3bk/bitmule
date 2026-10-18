//! The peer channel: an authenticated, encrypted message pipe to one peer.
//!
//! Servers and sockets stop here. A peer worker turns the signaling server's
//! routed messages into plain `Peer2Peer` messages and back: it runs the key
//! exchange, then seals what goes out and opens what comes in. Everything
//! above it (transfer logic, WebRTC) sees only `PeerLink`, two channels of
//! decrypted messages, and never a websocket.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use bitmule_core::{
    ReceiverId, SessionId,
    crypto::PublicKey,
    inner::{Envelope, EnvelopeCounter, EphemeralKeypair, IdentityKeypair, InnerKeyKind, OuterKeyKind, derive_session_key},
    protocol::websocket::{ClientToServer, ECDH, Peer2Peer, ServerToClient},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// What the workers of one session share.
pub struct Wire {
    pub identity: IdentityKeypair,
    pub session_id: SessionId,
    /// Towards the server; the websocket worker sits behind this.
    pub to_server: mpsc::Sender<ClientToServer>,
}

/// Decrypted messages to and from one peer. `rx` ends when the peer is gone.
pub struct PeerLink {
    pub tx: mpsc::Sender<Peer2Peer>,
    pub rx: mpsc::Receiver<Peer2Peer>,
}

const QUEUE: usize = 64;

/// Start the worker for one peer. `from_server` carries what the server
/// routed from this peer.
pub fn spawn(
    wire: Arc<Wire>,
    peer_id: ReceiverId,
    peer_pub: PublicKey,
    from_server: mpsc::Receiver<ServerToClient>,
) -> PeerLink {
    let (tx, outgoing) = mpsc::channel(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    tokio::spawn(async move {
        if let Err(e) = run(wire, peer_id, peer_pub, from_server, outgoing, incoming).await {
            warn!("peer {peer_id:?}: {e}");
        }
    });
    PeerLink { tx, rx }
}

async fn run(
    wire: Arc<Wire>,
    peer_id: ReceiverId,
    peer_pub: PublicKey,
    mut from_server: mpsc::Receiver<ServerToClient>,
    mut outgoing: mpsc::Receiver<Peer2Peer>,
    incoming: mpsc::Sender<Peer2Peer>,
) -> Result<()> {
    let peer_pub = x25519_dalek::PublicKey::from(peer_pub.0);
    // the server could hand us our own identity key as the peer's
    if peer_pub.as_bytes() == wire.identity.public.as_bytes() {
        bail!("the peer's identity key is ours");
    }
    let outer = wire.identity.outer_key_for(&peer_pub, &wire.session_id);
    let ephemeral = EphemeralKeypair::generate();
    let (mut tx_counter, mut rx_counter) = EnvelopeCounter::pair(wire.identity.public.as_bytes(), peer_pub.as_bytes());

    // Both sides send their ephemeral key at once and read the other's.
    let hello = ECDH { ephemeral_pub: ephemeral.public_key() };
    let envelope = Envelope::<OuterKeyKind, ECDH>::seal(&hello, &outer, &mut tx_counter, &wire.session_id)
        .map_err(|e| anyhow!("sealing key exchange: {e:?}"))?;
    wire.to_server.send(ClientToServer::SendTo1 { dest_id: peer_id, msg: envelope }).await?;

    let session_key = loop {
        match from_server.recv().await {
            Some(ServerToClient::PeerMessage1 { data, .. }) => {
                let theirs = data.open(&outer, &wire.session_id, &mut rx_counter)
                    .map_err(|e| anyhow!("opening key exchange: {e:?}"))?;
                break derive_session_key(&wire.identity, &ephemeral, &peer_pub, &theirs.ephemeral_pub.into(), &wire.session_id);
            }
            Some(ServerToClient::Text(_)) => {}
            Some(ServerToClient::PeerDisconnected { .. }) | None => bail!("peer left during the handshake"),
            Some(_) => bail!("unexpected message during the handshake"),
        }
    };
    debug!("peer {peer_id:?}: secure channel up");

    loop {
        tokio::select! {
            message = from_server.recv() => match message {
                Some(ServerToClient::PeerMessage2 { data, .. }) => {
                    let message = data.open(&session_key, &wire.session_id, &mut rx_counter)
                        .map_err(|e| anyhow!("opening message: {e:?}"))?;
                    if incoming.send(message).await.is_err() {
                        return Ok(()); // nobody is listening any more
                    }
                }
                Some(ServerToClient::Text(_)) => {}
                Some(ServerToClient::PeerDisconnected { .. }) | None => return Ok(()),
                Some(_) => bail!("unexpected message from the server"),
            },
            message = outgoing.recv() => {
                let Some(message) = message else { return Ok(()) };
                let envelope = Envelope::<InnerKeyKind, Peer2Peer>::seal(&message, &session_key, &mut tx_counter, &wire.session_id)
                    .map_err(|e| anyhow!("sealing message: {e:?}"))?;
                wire.to_server.send(ClientToServer::SendTo2 { dest_id: peer_id, msg: envelope }).await?;
            }
        }
    }
}

/// A peer channel split in three by kind: WebRTC signaling goes one way,
/// the UDP path-finding (`UdpHello`) another, everything else the third. All
/// share the way out.
pub struct Demuxed {
    pub app: PeerLink,
    pub signaling: PeerLink,
    pub udp: PeerLink,
}

pub fn demux(link: PeerLink) -> Demuxed {
    let PeerLink { tx, mut rx } = link;
    let (app_tx, app_rx) = mpsc::channel(QUEUE);
    let (signaling_tx, signaling_rx) = mpsc::channel(QUEUE);
    let (udp_tx, udp_rx) = mpsc::channel(QUEUE);
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            match message {
                Peer2Peer::SdpOffer(_) | Peer2Peer::SdpAnswer(_) | Peer2Peer::IceCandidate(_) => {
                    // nobody may be listening for signaling; never let that stall the rest
                    let _ = signaling_tx.try_send(message);
                }
                Peer2Peer::UdpHello(_) => {
                    let _ = udp_tx.try_send(message);
                }
                message => {
                    if app_tx.send(message).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    Demuxed {
        app: PeerLink { tx: tx.clone(), rx: app_rx },
        signaling: PeerLink { tx: tx.clone(), rx: signaling_rx },
        udp: PeerLink { tx, rx: udp_rx },
    }
}

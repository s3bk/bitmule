use std::{collections::HashMap, sync::Arc};

use anyhow::bail;
use bitmule_client_common::transfer::Transfer;
use bitmule_client_native::{crypto::ShareKey, websocket::connect_ws};
use bitmule_core::{KeyExchange, Manifest, ReceiverId, SessionId, crypto::{PublicKey, SessionMac}, inner::{Envelope, EnvelopeCounter, EphemeralKeypair, IdentityKeypair, InnerKeyKind, OuterKeyKind, SessionKey, derive_session_key}, pow, protocol::{Encoded, websocket::{ClientToServer, ECDH, Peer2Peer, PeerCaps, ServerToClient::{self, PeerMessage1}, TransferManifest}}};
use serde::Deserialize;
use tokio::{select, spawn, sync::mpsc, task::JoinHandle};
use tracing::warn;


pub async fn run_send(manifest: TransferManifest, transfer: Transfer) -> Result<(), anyhow::Error> {
    let server = "bitmule.net";
    let our_id = ReceiverId::random();
    let our_caps = PeerCaps::RELAY | PeerCaps::WEBRTC;
    let identity = IdentityKeypair::generate();
    let share_key = ShareKey::random();

    let session_id = SessionId(share_key.session_id());
    let session_id_hex = session_id.as_hex();

    let pow_challenge: PowChallenge = reqwest::get(format!("https://{server}/pow")).await?.json().await?;
    let reconnect_token = random_token();
    let pow_solution = solve_pow(&pow_challenge, &session_id);
    let magic = pow_challenge.magic;

    let (ws_tx, mut ws_rx) = connect_ws(&format!("wss://{server}/create?sid={session_id_hex}&magic={magic}&pow={pow_solution}&token={reconnect_token}")).await?;

    ws_tx.send(ClientToServer::CreateSession {
        id: our_id,
        capabilities: our_caps,
        pub_key: identity.public_key(),
        mac: SessionMac(share_key.mac_ephemeral_pub(&identity.public_key().0))
    }).await?;

    match ws_rx.recv().await {
        Some(ServerToClient::SessionCreated) => (),
        _ => bail!("expected SessionCreated")
    }

    let mut peer_tasks = HashMap::new();

    // a channel for the peer-tasks to send messages to the relay
    let (send_tx, send_rx) = mpsc::channel(16);
    let state = Arc::new(State {
        identity,
        session_id,
        send_tx
    });

    while let Some(msg) = ws_rx.recv().await {
        match msg {
            ServerToClient::PeerJoined { id, pub_key, mac } => {
                if share_key.mac_ephemeral_pub(&pub_key) != mac {
                    warn!("Bad MAC from {id:?}");
                    continue;
                }

                let (recv_tx, recv_rx) = mpsc::channel(16);
                peer_tasks.insert(id, PeerTask {
                    recv_tx,
                    handle: spawn(peer_task_send(state.clone(), id, pub_key, recv_rx, manifest.clone()))
                });
            }
            ServerToClient::Text(msg) => {
                println!("SERVER: {msg:?}");
            }
            m @ ServerToClient::PeerMessage1 { from, .. } | m @ ServerToClient::PeerMessage2 { from, .. } => {
                use std::collections::hash_map::Entry;
                match peer_tasks.entry(from) {
                    Entry::Occupied(e) => {
                        if let Err(_) = e.get().recv_tx.send(m).await {
                            e.remove();
                        }
                    }
                    _ => {}
                }
            }
            ServerToClient::SessionJoined { .. } => {
                bail!("unexpected SessionJoined");
            }
            ServerToClient::SessionCreated => {
                bail!("unexpected SessionCreated");
            }
            ServerToClient::PeerDisconnected { id } => {
                if let Some(task) = peer_tasks.remove(&id) {
                    task.handle.abort();
                }
            }
            ServerToClient::PeerFull { id } => {
                warn!("peer full")
            }
        }
    }
    Ok(())
}

struct PeerTask {
    recv_tx: mpsc::Sender<ServerToClient>,
    handle: JoinHandle<Result<(), anyhow::Error>>,
}

struct State {
    identity: IdentityKeypair,
    session_id: SessionId,
    send_tx: mpsc::Sender<ClientToServer>,
}
async fn peer_task_send(state: Arc<State>, peer_id: ReceiverId, peer_pub: PublicKey, rx: mpsc::Receiver<ServerToClient>, manifest: TransferManifest) -> Result<(), anyhow::Error> {
    let mut conn = peer_connection(state, peer_id, peer_pub, rx).await?;

    conn.send(Peer2Peer::Manifest(manifest));
    Ok(())
}

/// common handshake function for sender and reciever
async fn peer_connection(state: Arc<State>, peer_id: ReceiverId, peer_pub: PublicKey, mut rx: mpsc::Receiver<ServerToClient>) -> Result<PeerConnection, Error> {
    let peer_pub = x25519_dalek::PublicKey::from(peer_pub.0);
    let outer = state.identity.outer_key_for(&peer_pub, &state.session_id);
    let ephermal = EphemeralKeypair::generate();

    let mut tx_counter = EnvelopeCounter::default();
    let mut rx_counter = EnvelopeCounter::default();

    let data = ECDH { ephemeral_pub: ephermal.public_key() };
    let envelope = Envelope::<OuterKeyKind, ECDH>::seal(&data, &outer, &mut tx_counter, &state.session_id).unwrap();

    state.send_tx.send(ClientToServer::SendTo1 { dest_id: peer_id, msg: envelope }).await.map_err(|_| Error::ChannelClosed)?;

    let inner = match rx.recv().await {
        Some(ServerToClient::PeerMessage1 { from, data }) => {
            let ecdh = data.open(&outer, &state.session_id, &mut rx_counter).map_err(Error::Envelope)?;
            derive_session_key(&state.identity, &ephermal, &peer_pub, &ecdh.ephemeral_pub.into(), &state.session_id)
        }
        _ => return Err(Error::WrongMessage),
    };

    Ok(PeerConnection { state, peer_id, inner, rx, rx_counter, tx_counter })
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("data opening envelope")]
    Envelope(bitmule_core::inner::Error),

    #[error("wrong message recieved")]
    WrongMessage,

    #[error("websocket channel closed")]
    ChannelClosed
}

struct PeerConnection {
    state: Arc<State>,
    peer_id: ReceiverId,
    inner: SessionKey,
    rx: mpsc::Receiver<ServerToClient>,
    rx_counter: EnvelopeCounter,
    tx_counter: EnvelopeCounter
}
impl PeerConnection {
    pub async fn recv(&mut self) -> Result<Peer2Peer, Error> {
        match self.rx.recv().await {
            Some(ServerToClient::PeerMessage2 { from, data }) => {
                let data = data.open(&self.inner, &self.state.session_id, &mut self.rx_counter).map_err(Error::Envelope)?;
                Ok(data)
            }
            _ => Err(Error::WrongMessage)
        }
    }
    pub async fn send(&mut self, msg: Peer2Peer) -> Result<(), anyhow::Error> {
        let envelope = Envelope::<InnerKeyKind, Peer2Peer>::seal(&msg, &self.inner, &mut self.tx_counter, &self.state.session_id).unwrap();
        self.state.send_tx.send(ClientToServer::SendTo2 { dest_id: self.peer_id, msg: envelope }).await?;
        Ok(())
    }
}

fn random_token() -> String {
    todo!("random token string")
}
#[derive(Deserialize)]
struct PowChallenge {
    difficulty: u8,
    magic: u32,
}
fn solve_pow(challenge: &PowChallenge, session_id: &SessionId) -> u64 {
    pow::solve_c(&session_id.0, challenge.magic, challenge.difficulty)
}

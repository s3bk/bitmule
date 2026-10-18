//! The session worker: the one place that talks to the signaling server.
//!
//! It does the proof of work, creates or joins the session, and hands each
//! peer's messages to that peer's worker (`peer.rs`). Past that, it only
//! starts the transfer workers (`send.rs` / `recv.rs`) and waits for them.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, bail, ensure};
use bitmule_client_common::transfer::Transfer;
use bitmule_client_native::{
    crypto::{ShareKey, ShareLink},
    websocket::connect_ws,
};
use bitmule_core::{
    ReceiverId, SessionId,
    inner::IdentityKeypair,
    pow,
    protocol::websocket::{ClientToServer, Peer2Peer, ServerToClient, TransferManifest},
};
use serde::Deserialize;
use tokio::{select, sync::mpsc, task::JoinSet};
use tracing::warn;

use super::{Options, Report, Server, peer, recv, send};

#[derive(Deserialize)]
struct PowChallenge {
    difficulty: u8,
    magic: u32,
}

pub async fn send(
    server: &Server,
    manifest: TransferManifest,
    transfer: Transfer,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
    on_event: super::OnSendEvent,
) -> Result<()> {
    let share_key = ShareKey::random();
    let link = ShareLink::new(share_key.clone(), transfer.commitment());
    let Created { our_id, identity, session_id, to_server, mut from_server, relay_token, .. } =
        create(server, &share_key, options).await?;
    on_link(&link);

    let wire = Arc::new(peer::Wire { identity, session_id, to_server });
    let ctx = Arc::new(send::Context::new(server.clone(), our_id, session_id, relay_token, manifest, transfer, options, on_event));

    // routes what the server says about a peer to that peer's worker
    let mut peers: HashMap<ReceiverId, mpsc::Sender<ServerToClient>> = HashMap::new();
    let mut workers = JoinSet::new();
    let mut completed = 0usize;

    loop {
        select! {
            message = from_server.recv() => {
                let Some(message) = message else { bail!("connection to the server closed") };
                match message {
                    ServerToClient::PeerJoined { id, pub_key, mac, caps } => {
                        if share_key.mac_ephemeral_pub(&pub_key) != mac {
                            warn!("Bad MAC from {id:?}");
                            continue;
                        }
                        let (to_peer, peer_from_server) = mpsc::channel(64);
                        peers.insert(id, to_peer);
                        let link = peer::spawn(wire.clone(), id, pub_key, peer_from_server);
                        let peer::Demuxed { app, signaling } = peer::demux(link);
                        let ctx = ctx.clone();
                        workers.spawn(async move { (id, send::serve_peer(ctx, id, caps, app, signaling).await) });
                    }
                    ServerToClient::Text(text) => println!("SERVER: {text:?}"),
                    ServerToClient::PeerMessage1 { from, .. } | ServerToClient::PeerMessage2 { from, .. } => {
                        if let Some(to_peer) = peers.get(&from) {
                            if to_peer.send(message).await.is_err() {
                                peers.remove(&from);
                            }
                        }
                    }
                    ServerToClient::PeerDisconnected { id } => {
                        // dropping the sender ends the peer's worker
                        peers.remove(&id);
                    }
                    ServerToClient::PeerFull { id } => warn!("peer {id:?} is not keeping up"),
                    ServerToClient::SessionJoined { .. } => bail!("unexpected SessionJoined"),
                    ServerToClient::SessionCreated { .. } => bail!("unexpected SessionCreated"),
                }
            }
            Some(done) = workers.join_next() => {
                let (id, result) = done?;
                peers.remove(&id);
                match result {
                    Ok(()) => completed += 1,
                    Err(e) => warn!("receiver {id:?}: {e}"),
                }
                if peers.is_empty() && completed > 0 {
                    return Ok(());
                }
            }
        }
    }
}

pub async fn receive(server: &Server, link: &ShareLink, open: recv::OpenOutput, progress: Option<recv::Progress>, options: Options) -> Result<Report> {
    let Joined { our_id, identity, session_id, to_server, from_server, ws_worker, sender_id, sender_pub, sender_caps, relay_token } =
        join(server, &link.share_key, options).await?;

    // the only peer is the sender, so everything the server says goes to its worker
    let wire = Arc::new(peer::Wire { identity, session_id, to_server });
    let peer::Demuxed { app, signaling } = peer::demux(peer::spawn(wire, sender_id, sender_pub, from_server));

    let ctx = recv::Context::new(server.clone(), session_id, our_id, relay_token, link.clone(), open, progress, options);
    let report = recv::receive(ctx, sender_caps, app, signaling).await;

    // The last thing we say (that we are done) is still on its way through
    // the workers: the peer worker seals it, the websocket worker writes it.
    // Both stop once nothing can send any more, so wait for that.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ws_worker).await;
    report
}

/// A session we created and own.
struct Created {
    our_id: ReceiverId,
    identity: IdentityKeypair,
    session_id: SessionId,
    to_server: mpsc::Sender<ClientToServer>,
    from_server: mpsc::Receiver<ServerToClient>,
    /// pass as `&token=` to /ws/create to regain our id (not used yet)
    #[allow(dead_code)]
    reconnect_token: bitmule_core::Token,
    /// authorizes the relay POST
    relay_token: bitmule_core::Token,
}

/// Create the session of `share_key`: proof of work, websocket, registration.
async fn create(server: &Server, share_key: &ShareKey, options: Options) -> Result<Created> {
    let our_id = ReceiverId::random();
    let identity = IdentityKeypair::generate();
    let session_id = SessionId(share_key.session_id());

    let challenge: PowChallenge = bitmule_client_native::nic::http_client().get(server.http("/pow")).send().await?.json().await?;
    let nonce = pow::solve_c(&session_id.0, challenge.magic, challenge.difficulty);
    let url = server.ws(&format!("/ws/create?sid={}&magic={}&pow={nonce}", session_id.as_hex(), challenge.magic));
    let (to_server, mut from_server, _ws_worker) = connect_ws(&url).await?;

    to_server.send(ClientToServer::CreateSession {
        id: our_id,
        capabilities: options.caps(),
        pub_key: identity.public_key(),
        mac: share_key.mac_ephemeral_pub(&identity.public_key()),
    }).await?;

    let (reconnect_token, relay_token) = match from_server.recv().await {
        Some(ServerToClient::SessionCreated { reconnect_token, relay_token }) => (reconnect_token, relay_token),
        Some(ServerToClient::Text(reason)) => bail!("server refused session: {reason}"),
        _ => bail!("expected SessionCreated"),
    };
    Ok(Created { our_id, identity, session_id, to_server, from_server, reconnect_token, relay_token })
}

/// A session we joined, with its owner.
struct Joined {
    our_id: ReceiverId,
    identity: IdentityKeypair,
    session_id: SessionId,
    to_server: mpsc::Sender<ClientToServer>,
    from_server: mpsc::Receiver<ServerToClient>,
    ws_worker: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    sender_id: ReceiverId,
    sender_pub: bitmule_core::crypto::PublicKey,
    sender_caps: bitmule_core::protocol::websocket::PeerCaps,
    relay_token: bitmule_core::Token,
}

/// Join the session of `share_key`; the owner has to know the key too.
async fn join(server: &Server, share_key: &ShareKey, options: Options) -> Result<Joined> {
    let our_id = ReceiverId::random();
    let identity = IdentityKeypair::generate();
    let session_id = SessionId(share_key.session_id());

    let (to_server, mut from_server, ws_worker) = connect_ws(&server.ws(&format!("/ws/join?sid={}", session_id.as_hex()))).await?;
    to_server.send(ClientToServer::JoinSession {
        id: our_id,
        capabilities: options.caps(),
        pub_key: identity.public_key(),
        mac: share_key.mac_ephemeral_pub(&identity.public_key()),
    }).await?;

    let (sender_id, sender_pub, sender_caps, relay_token) = match from_server.recv().await {
        Some(ServerToClient::SessionJoined { sender_id, sender_pub_key, sender_mac, sender_caps, relay_token }) => {
            ensure!(share_key.mac_ephemeral_pub(&sender_pub_key) == sender_mac, "sender does not know the share key");
            (sender_id, sender_pub_key, sender_caps, relay_token)
        }
        Some(ServerToClient::Text(reason)) => bail!("server refused join: {reason}"),
        _ => bail!("expected SessionJoined"),
    };
    Ok(Joined { our_id, identity, session_id, to_server, from_server, ws_worker, sender_id, sender_pub, sender_caps, relay_token })
}

/// Receiver-initiated transfers, receiver side. Creates a rendezvous
/// session under a fresh key, hands the key to `on_request` (it goes into the
/// link for the sender) and waits for a sender to join and send back the
/// share link of the transfer it created. That link is then received as any
/// other (`receive`), signature included.
pub async fn request(server: &Server, options: Options, on_request: impl FnOnce(&ShareKey)) -> Result<ShareLink> {
    let share_key = ShareKey::random();
    let Created { identity, session_id, to_server, mut from_server, .. } = create(server, &share_key, options).await?;
    on_request(&share_key);

    let wire = Arc::new(peer::Wire { identity, session_id, to_server });
    let mut peers: HashMap<ReceiverId, mpsc::Sender<ServerToClient>> = HashMap::new();
    let (found_tx, mut found) = mpsc::channel::<String>(4);
    loop {
        select! {
            message = from_server.recv() => {
                let Some(message) = message else { bail!("connection to the server closed") };
                match message {
                    ServerToClient::PeerJoined { id, pub_key, mac, .. } => {
                        if share_key.mac_ephemeral_pub(&pub_key) != mac {
                            warn!("Bad MAC from {id:?}");
                            continue;
                        }
                        let (to_peer, peer_from_server) = mpsc::channel(64);
                        peers.insert(id, to_peer);
                        let peer::PeerLink { tx, mut rx } = peer::spawn(wire.clone(), id, pub_key, peer_from_server);
                        let found_tx = found_tx.clone();
                        tokio::spawn(async move {
                            let _tx = tx; // the peer worker ends when this is dropped
                            while let Some(message) = rx.recv().await {
                                if let Peer2Peer::ShareLink(link) = message {
                                    let _ = found_tx.send(link).await;
                                    return;
                                }
                            }
                        });
                    }
                    ServerToClient::PeerMessage1 { from, .. } | ServerToClient::PeerMessage2 { from, .. } => {
                        if let Some(to_peer) = peers.get(&from) {
                            if to_peer.send(message).await.is_err() {
                                peers.remove(&from);
                            }
                        }
                    }
                    ServerToClient::PeerDisconnected { id } => {
                        peers.remove(&id);
                    }
                    _ => {}
                }
            }
            Some(text) = found.recv() => match ShareLink::from_b64_url(&text) {
                Ok(link) => return Ok(link),
                Err(e) => warn!("sender sent a bad share link: {e}"),
            },
        }
    }
}

/// Receiver-initiated transfers, sender side. Joins the rendezvous session of
/// `request`, creates the transfer's own session as `send` does, and sends its
/// share link to the requester through the encrypted peer channel.
pub async fn send_to_request(
    server: &Server,
    request: &ShareKey,
    manifest: TransferManifest,
    transfer: Transfer,
    options: Options,
    on_link: impl FnOnce(&ShareLink),
) -> Result<()> {
    let Joined { identity, session_id, to_server, from_server, ws_worker, sender_id, sender_pub, .. } =
        join(server, request, options).await?;
    let wire = Arc::new(peer::Wire { identity, session_id, to_server });
    let peer::PeerLink { tx, rx } = peer::spawn(wire, sender_id, sender_pub, from_server);

    let (link_tx, link_rx) = tokio::sync::oneshot::channel::<ShareLink>();
    tokio::spawn(async move {
        let _rx = rx;
        let Ok(link) = link_rx.await else { return };
        if tx.send(Peer2Peer::ShareLink(link.to_b64_url())).await.is_err() {
            return;
        }
        // let the link get through the workers before the connection goes
        drop(tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ws_worker).await;
    });

    send(server, manifest, transfer, options, |link| {
        let _ = link_tx.send(link.clone());
        on_link(link);
    }, Arc::new(|_| {})).await
}

//! WebSocket signaling handler.
//!
//! Protocol (all JSON-over-text):
//!
//! Client → server, first frame after upgrade — one of:
//!   `{"type":"session_create","wire_version":<u32>?}`         (sender)
//!   `{"type":"session_join","receiver_id":"<hex>","wire_version":<u32>?}` (receiver)
//!
//! Server → client pairing notification:
//!   `{"type":"peer_joined","role":"sender"|"receiver","wire_version":<u32>?,"receiver_id":"<hex>"?}`
//!
//! After the pairing notification the socket is a bidirectional relay:
//!   - Sender frames fan out to all receivers currently in the room.
//!   - Receiver frames route only to the sender.
//!
//! The server does not inspect frame payloads. SDP, ICE, and key-exchange
//! all ride the same relay.

use std::sync::Arc;

use crate::{
    Difficulty, Magic, room::{PeerEntry, SendError}, state::{AppState, SessionState},
};
use anyhow::bail;
use axum::{
    extract::{
        Query, State, ws::{Message, WebSocket, WebSocketUpgrade},
    }, Json, http::StatusCode, response::IntoResponse,
};
use bitmule_core::{ReceiverId, SessionId, Token, pow, protocol::websocket::{ClientToServer, ServerToClient}};
use serde::{Deserialize, Serialize};
use tokio::{select, sync::mpsc};
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct CreateSessionArgs {
    sid: String,
    /// PoW magic and solution (the nonce found by `pow::solve_c`).
    /// Not needed when reconnecting with `token`.
    magic: Option<Magic>,
    pow: Option<u64>,
    /// Reconnect token from `SessionCreated`. Required if the session is
    /// live, and skips the PoW. Only valid for a live session.
    token: Option<String>,
    /// Ping the client now and then. Browsers cannot send websocket pings, and
    /// a proxy in front of us may drop a connection that stays quiet.
    #[serde(rename = "enablePing")]
    enable_ping: Option<String>,
}

#[derive(Deserialize)]
pub struct JoinSessionArgs {
    sid: String,
    #[serde(rename = "enablePing")]
    enable_ping: Option<String>,
}

/// Is `enablePing` present and not switched off (`?enablePing`, `=1`, `=true`)?
fn ping_requested(arg: &Option<String>) -> bool {
    arg.as_deref().is_some_and(|v| !matches!(v, "0" | "false"))
}

/// Largest accepted signaling message. The biggest is a manifest, which
/// lists 8 bytes per 2 MiB block of the transfer (`MAX_MANIFEST_HASHES`:
/// 8 MiB for a 2 TiB transfer), sealed in an envelope.
const MAX_MESSAGE_SIZE: usize = 9 * 1024 * 1024;

/// What a first message (`CreateSession`, `JoinSession`) may weigh: a few
/// hundred bytes. Anybody can connect, so nobody gets to send more than that
/// before they are registered.
const MAX_HELLO_SIZE: usize = 4 * 1024;

#[derive(Serialize)]
pub struct PowChallenge {
    difficulty: Difficulty,
    magic: Magic,
}

/// `GET /pow`: hand out the current PoW difficulty and magic.
pub async fn pow_challenge(State(state): State<Arc<AppState>>) -> Json<PowChallenge> {
    let (difficulty, magic, _) = state.difficulty_and_magic();
    Json(PowChallenge { difficulty, magic })
}

pub async fn ws_join_session(
    ws: WebSocketUpgrade,
    Query(args): Query<JoinSessionArgs>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let session_id = match SessionId::from_hex(&args.sid) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid session id").into_response(),
    };
    if state.get_session(session_id).await.is_none() {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    }

    let ping = ping_requested(&args.enable_ping);
    ws.max_message_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_socket(socket, state, session_id, None, ping))
        .into_response()
}

pub async fn ws_create_session(
    ws: WebSocketUpgrade,
    Query(args): Query<CreateSessionArgs>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let session_id = match SessionId::from_hex(&args.sid) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid session id").into_response(),
    };
    let reconnect = match args.token.as_deref().map(Token::from_hex).transpose() {
        Ok(t) => t,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid token").into_response(),
    };
    // The token itself is checked against the live session after the upgrade.
    if reconnect.is_none() {
        let (Some(magic), Some(nonce)) = (args.magic, args.pow) else {
            return (StatusCode::BAD_REQUEST, "pow required").into_response();
        };
        let (difficulty, magic1, magic2) = state.difficulty_and_magic();
        if !(magic == magic1 || magic == magic2) {
            return (StatusCode::BAD_REQUEST, "bad magic").into_response();
        }
        if !pow::verify_c(&session_id, magic.0, nonce, difficulty.0) {
            return (StatusCode::BAD_REQUEST, "bad pow").into_response();
        }
    }
    let ping = ping_requested(&args.enable_ping);
    ws.max_message_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_socket(socket, state, session_id, Some(reconnect), ping))
        .into_response()
}

/// `reconnect`: `None` for a receiver joining, `Some(token)` for the owner
/// (inner `None` on the first connect).
async fn handle_socket(socket: WebSocket, state: Arc<AppState>, session_id: SessionId, owner: Option<Option<Token>>, ping: bool) {
    if let Err(e) = handle_socket_inner(socket, state, session_id, owner, ping).await {
        error!("during handle_socket_inner: {e:?}");
    }
}

async fn reject(socket: &mut WebSocket, reason: impl ToString) -> Result<(), anyhow::Error> {
    let reason = reason.to_string();
    send_msg(socket, ServerToClient::Text(reason.clone())).await?;
    bail!(reason)
}

async fn handle_socket_inner(mut socket: WebSocket, state: Arc<AppState>, session_id: SessionId, owner: Option<Option<Token>>, ping: bool) -> Result<(), anyhow::Error> {
    let ping_interval = ping.then_some(state.ping_interval);
    let (dispatch_tx, mut dispatch_rx) = mpsc::channel(16);
    let is_owner = owner.is_some();

    // Registration: first message must be CreateSession (owner) or
    // JoinSession (receiver). `hello` is what we answer with.
    let session;
    let our_id;
    let mut hello = vec![];
    loop {
        match socket.recv().await {
            None => return Ok(()),
            Some(Ok(Message::Binary(data))) if data.len() > MAX_HELLO_SIZE => {
                return reject(&mut socket, "hello message too large").await;
            }
            Some(Ok(Message::Binary(data))) => match postcard::from_bytes(&data) {
                Ok(ClientToServer::CreateSession { id, capabilities, pub_key, mac, join_check }) if is_owner => {
                    let peer = PeerEntry {
                        sink: dispatch_tx,
                        caps: capabilities,
                        mac,
                        pub_key,
                        reconnect_token: Token::random(),
                        relay_token: Token::random(),
                    };
                    match state.create_session(session_id, id, peer, join_check, owner.flatten()).await {
                        Ok(created) => {
                            hello.push(ServerToClient::SessionCreated {
                                reconnect_token: created.entry.reconnect_token,
                                relay_token: created.entry.relay_token,
                            });
                            // on reconnect, replay the receivers that joined meanwhile
                            hello.extend(created.peers.into_iter().map(|(id, p)| {
                                ServerToClient::PeerJoined { id, pub_key: p.pub_key, mac: p.mac, caps: p.caps }
                            }));
                            session = created.session;
                            our_id = id;
                            break;
                        }
                        Err(e) => return reject(&mut socket, e).await,
                    }
                }
                Ok(ClientToServer::JoinSession { id, capabilities, pub_key, mac, join_proof }) if !is_owner => {
                    let Some(s) = state.get_session(session_id).await else {
                        return reject(&mut socket, "No such session").await;
                    };
                    // Nobody who only knows the session id (it is in URLs and
                    // logs) gets the owner's identity, a relay token, or a
                    // place in the room.
                    if !s.allows_join(&join_proof) {
                        return reject(&mut socket, "join proof does not match").await;
                    }
                    let relay_token = Token::random();
                    let peer = PeerEntry {
                        sink: dispatch_tx,
                        caps: capabilities,
                        mac,
                        pub_key,
                        reconnect_token: Token::random(),
                        relay_token,
                    };
                    match s.add_peer(id, peer).await {
                        Ok((owner_id, owner)) => {
                            hello.push(ServerToClient::SessionJoined {
                                relay_token,
                                sender_id: owner_id,
                                sender_pub_key: owner.pub_key,
                                sender_mac: owner.mac,
                                sender_caps: owner.caps,
                            });
                            session = s;
                            our_id = id;
                            break;
                        }
                        Err(e) => return reject(&mut socket, e).await,
                    }
                }
                Ok(_) => return reject(&mut socket, "wrong message").await,
                Err(e) => {
                    warn!("invalid data: {e:?}");
                    return reject(&mut socket, format!("invalid data: {e}")).await;
                }
            }
            Some(Ok(Message::Ping(data))) => {
                socket.send(Message::Pong(data)).await?;
            }
            Some(Ok(Message::Close(_))) => return Ok(()),
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                warn!("client error: {e:?}");
                return Ok(());
            }
        }
    }

    let result = relay_loop(&mut socket, &session, our_id, hello, &mut dispatch_rx, ping_interval).await;
    if !is_owner {
        session.remove_peer(our_id).await;
    }
    result
}

async fn relay_loop(
    socket: &mut WebSocket,
    session: &SessionState,
    our_id: ReceiverId,
    hello: Vec<ServerToClient>,
    dispatch_rx: &mut mpsc::Receiver<ServerToClient>,
    ping_interval: Option<std::time::Duration>,
) -> Result<(), anyhow::Error> {
    for msg in hello {
        send_msg(socket, msg).await?;
    }
    let mut ping = ping_interval.map(|every| {
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    });
    loop {
        select! {
            _ = async { ping.as_mut().unwrap().tick().await }, if ping.is_some() => {
                socket.send(Message::Ping(Default::default())).await?;
            }
            ev = socket.recv() => match ev {
                None | Some(Ok(Message::Close(_))) => return Ok(()),
                Some(Ok(Message::Binary(data))) => match postcard::from_bytes(&data) {
                    Ok(ClientToServer::SendTo1 { dest_id, msg: data }) => {
                        let msg = ServerToClient::PeerMessage1 { from: our_id, data };
                        checked_send(session, dest_id, msg, socket).await?;
                    }
                    Ok(ClientToServer::SendTo2 { dest_id, msg: data }) => {
                        let msg = ServerToClient::PeerMessage2 { from: our_id, data };
                        checked_send(session, dest_id, msg, socket).await?;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("invalid data: {e:?}");
                        return reject(socket, format!("invalid data: {e}")).await;
                    }
                },
                Some(Ok(Message::Ping(data))) => {
                    socket.send(Message::Pong(data)).await?;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    warn!("client error: {e:?}");
                    return Ok(());
                }
            },
            msg = dispatch_rx.recv() => match msg {
                Some(msg) => send_msg(socket, msg).await?,
                // our entry was replaced (owner reconnected elsewhere)
                None => return Ok(()),
            },
        }
    }
}
async fn checked_send(session: &SessionState, dest: ReceiverId, msg: ServerToClient, socket: &mut WebSocket) -> Result<(), anyhow::Error> {
    match session.room().lock().await.send_to(dest, msg) {
        Ok(()) => Ok(()),
        Err(SendError::Disconnected) => {
            send_msg(socket, ServerToClient::PeerDisconnected { id: dest }).await
        }
        Err(SendError::Full) => {
            send_msg(socket, ServerToClient::PeerFull { id: dest }).await
        }
    }
}
async fn send_msg(socket: &mut WebSocket, msg: ServerToClient) -> Result<(), anyhow::Error> {
    let bytes = postcard::to_stdvec(&msg).unwrap();
    socket.send(Message::Binary(bytes.into())).await?;
    Ok(())
}

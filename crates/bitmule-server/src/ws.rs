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
    Magic, room::{PeerEntry, PeerSink, Role, SendError}, state::{AppState, SessionState},
};
use anyhow::bail;
use axum::{
    extract::{
        Path, Query, State, ws::{Message, WebSocket, WebSocketUpgrade},
    }, http::StatusCode, response::IntoResponse,
};
use bitmule_core::{ReceiverId, SessionId, pow, protocol::websocket::{ClientToServer, ServerToClient}};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use tokio::{select, sync::mpsc};
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct CreateSessionArgs {
    sid: String,
    magic: Magic,
    nonce: u64,
}

#[derive(Deserialize)]
pub struct JoinSessionArgs {
    sid: String,
}


pub async fn ws_join_session(
    ws: WebSocketUpgrade,
    Query(args): Query<JoinSessionArgs>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let session_id = match SessionId::from_hex(&args.sid) {
        Ok(id) => id,
        Err(_) => {
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(axum::body::Body::from("invalid session id"))
                .unwrap();
        }
    };
    let Some(session_state) = state.get_session(session_id).await else {
        return (StatusCode::NOT_FOUND, "session not found").into_response();
    };

    ws.on_upgrade(move |socket| handle_socket(socket, state, session_id, false))
        .into_response()
}

pub async fn ws_create_session(
    ws: WebSocketUpgrade,
    Query(args): Query<CreateSessionArgs>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let session_id = match SessionId::from_hex(&args.sid) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid session id").into_response();
        }
    };
    let (difficulty, magic1, magic2) = state.difficulty_and_magic();
    if !(args.magic == magic1 || args.magic == magic2) {
        return (StatusCode::BAD_REQUEST, "bad magic").into_response();
    }
    if !pow::verify_c(&session_id, args.magic.0, args.nonce, difficulty.0) {
        return (StatusCode::BAD_REQUEST, "bad nounce").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state, session_id, true))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, session_id: SessionId, is_owner: bool) {
    match handle_socket_inner(socket, state, session_id, is_owner).await {
        Err(e) => {
            error!("during handle_socket_inner: {e:?}");
        }
        Ok(()) => {}
    }
}

async fn handle_socket_inner(mut socket: WebSocket, state: Arc<AppState>, session_id: SessionId, is_owner: bool) -> Result<(), anyhow::Error> {
    let (dispatch_tx, mut dispatch_rx) = mpsc::channel(16);

    let session;
    let our_id;
    loop {
        match socket.recv().await {
            None => return Ok(()),
            Some(Ok(Message::Binary(data))) => match postcard::from_bytes(&data) {
                Ok(ClientToServer::CreateSession { id, capabilities, pub_key, mac }) if is_owner => {
                    let peer = PeerEntry {
                        sink: dispatch_tx,
                        caps: capabilities,
                        mac,
                        pub_key
                    };
                    session = state.create_session(session_id, id, peer).await;
                    our_id = id;
                    break;
                }
                Ok(ClientToServer::JoinSession { id, capabilities, pub_key, mac }) if !is_owner => {
                    let peer = PeerEntry {
                        sink: dispatch_tx,
                        caps: capabilities,
                        mac,
                        pub_key
                    };
                    match state.get_session(session_id).await {
                        Some(s) => {
                            s.add_peer(id, peer).await;
                            session = s;
                            our_id = id;
                            break;
                        }
                        None => {
                            socket.send(Message::Text("No such session".into())).await?;
                            bail!("invalid session id")
                        }
                    }
                }
                Ok(_) => {
                    warn!("client did not send the correct message");
                    bail!("wrong message");
                }
                Err(e) => {
                    warn!("invalid data: {e:?}");
                    socket.send(Message::Text(e.to_string())).await?;
                    bail!("invalid data");
                }
            }
            Some(Ok(Message::Ping(data))) => {
                socket.send(Message::Pong(data)).await?;
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                warn!("client error: {e:?}");
            }
        }
    }

    loop {
        select! {
            Some(ev) = socket.recv() => {
                match ev {
                    Ok(Message::Binary(data)) => match postcard::from_bytes(&data) {
                        Ok(ClientToServer::SendTo1 { dest_id, msg: data }) => {
                            let msg = ServerToClient::PeerMessage1 { from: our_id, data };
                            checked_send(&session, dest_id, msg, &mut socket).await?;
                        }
                        Ok(ClientToServer::SendTo2 { dest_id, msg: data }) => {
                            let msg = ServerToClient::PeerMessage2 { from: our_id, data };
                            checked_send(&session, dest_id, msg, &mut socket).await?;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("invalid data: {e:?}");
                            socket.send(Message::Text(e.to_string())).await;
                            bail!("invalid data");
                        }
                    }
                    Ok(Message::Ping(data)) => {
                        socket.send(Message::Pong(data)).await?;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("client error: {e:?}");
                    }
                }
            }
            Some(msg) = dispatch_rx.recv() => {
                send_msg(&mut socket, msg).await?;
            }
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

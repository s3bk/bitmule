//! WebSocket signaling handler.
//!
//! Protocol (all JSON-over-text):
//!
//! Client → server, first frame after upgrade:
//!   `{"type":"hello","role":"sender"|"receiver","receiver_id":"<hex>"?}`
//!
//! After a valid hello, the socket becomes a bidirectional relay:
//!   - Sender frames fan out to all receivers currently in the room.
//!   - Receiver frames route only to the sender.
//!
//! The server does not inspect frame payloads. SDP, ICE, and key-exchange
//! all ride the same relay.

use crate::{
    room::{PeerSink, Role},
    state::AppState,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
};
use bitmule_core::{ReceiverId, SessionId};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelloFrame {
    Hello {
        role: String,
        #[serde(default)]
        receiver_id: Option<ReceiverId>,
    },
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(session_hex): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let session = match SessionId::from_hex(&session_hex) {
        Ok(id) => id,
        Err(_) => {
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(axum::body::Body::from("invalid session id"))
                .unwrap();
        }
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, session))
        .into_response()
}

async fn handle_socket(mut socket: WebSocket, state: AppState, session: SessionId) {
    // Wait for the initial hello frame.
    let (role, receiver_id) = match read_hello(&mut socket).await {
        Some(v) => v,
        None => {
            let _ = socket.close().await;
            return;
        }
    };

    let room = state.room(session).await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Register into the room. After registering, notify the OTHER role
    // that a new peer joined — the incumbent uses this to re-emit its
    // peer_hello (or otherwise re-kick handshake) so a peer_hello that
    // was sent before the counterpart existed isn't lost forever.
    let notify_frame: Option<(Role, String)>;
    {
        let mut r = room.lock().await;
        match role {
            Role::Sender => {
                if r.sender.is_some() {
                    let _ = socket.close().await;
                    return;
                }
                r.sender = Some(tx.clone());
                notify_frame = if r.receivers.is_empty() {
                    None
                } else {
                    Some((
                        Role::Receiver,
                        r#"{"type":"peer_joined","role":"sender"}"#.to_string(),
                    ))
                };
            }
            Role::Receiver => {
                let rid = match receiver_id {
                    Some(id) => id,
                    None => {
                        let _ = socket.close().await;
                        return;
                    }
                };
                r.receivers.insert(rid, tx.clone());
                notify_frame = if r.sender.is_some() {
                    Some((
                        Role::Sender,
                        r#"{"type":"peer_joined","role":"receiver"}"#.to_string(),
                    ))
                } else {
                    None
                };
            }
        }
    }
    if let Some((target, frame)) = notify_frame {
        let r = room.lock().await;
        match target {
            Role::Sender => r.route_to_sender(&frame),
            Role::Receiver => {
                // fan_to_receivers is &mut; take a fresh mut lock
                drop(r);
                let mut r2 = room.lock().await;
                r2.fan_to_receivers(&frame);
            }
        }
    }

    let (mut sink, mut stream) = socket.split();

    // Pump outbound frames from the room into this socket.
    let out = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if sink.send(Message::Text(frame.into())).await.is_err() {
                break;
            }
        }
    });

    // Read inbound frames and relay to the other side of the room.
    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { break };
        match msg {
            Message::Text(t) => {
                let s = t.to_string();
                let mut r = room.lock().await;
                match role {
                    Role::Sender => r.fan_to_receivers(&s),
                    Role::Receiver => r.route_to_sender(&s),
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Unregister and drop the room if it's now empty.
    {
        let mut r = room.lock().await;
        match role {
            Role::Sender => {
                r.sender = None;
            }
            Role::Receiver => {
                if let Some(rid) = receiver_id {
                    r.receivers.remove(&rid);
                }
            }
        }
    }
    state.maybe_drop_room(&session).await;
    out.abort();
}

async fn read_hello(socket: &mut WebSocket) -> Option<(Role, Option<ReceiverId>)> {
    while let Some(msg) = socket.next().await {
        match msg.ok()? {
            Message::Text(t) => {
                let parsed: HelloFrame = serde_json::from_str(&t).ok()?;
                let HelloFrame::Hello { role, receiver_id } = parsed;
                let role = match role.as_str() {
                    "sender" => Role::Sender,
                    "receiver" => Role::Receiver,
                    _ => return None,
                };
                return Some((role, receiver_id));
            }
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

// Tag-along: PeerSink is re-exported for cross-module type reference in
// case a follow-up wants to construct sinks outside this file.
#[allow(dead_code)]
type _PeerSinkAlias = PeerSink;

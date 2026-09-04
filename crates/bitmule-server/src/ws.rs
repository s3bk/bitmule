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
    room::{PeerEntry, PeerSink, Role},
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
        /// Client wire-protocol version. Server stores per peer and includes
        /// in `peer_hello` notifications so the counterpart can detect
        /// version mismatch and prompt an update.
        #[serde(default)]
        wire_version: Option<u32>,
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
    let (role, receiver_id, wire_version) = match read_hello(&mut socket).await {
        Some(v) => v,
        None => {
            let _ = socket.close().await;
            return;
        }
    };

    let room = state.room(session).await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Register into the room. After registering, notify each side of the
    // OTHER'S wire_version via `peer_hello` frames so a client can bail
    // cleanly on version mismatch. `to_incumbent` tells the already-present
    // peer about the newcomer; `to_newcomer` tells the newcomer about the
    // incumbent (needed on our side because the newcomer's own registration
    // ran after the incumbent's already-sent frames drained).
    let self_entry = PeerEntry { sink: tx.clone(), wire_version };
    let (to_incumbent, to_newcomer_frames): (Option<(Role, String)>, Vec<String>);
    {
        let mut r = room.lock().await;
        match role {
            Role::Sender => {
                if r.sender.is_some() {
                    let _ = socket.close().await;
                    return;
                }
                // Newcomer is sender; incumbents are all receivers.
                // Each notification carries the incumbent receiver's id
                // so the sender's per-peer router can pre-register.
                let incumbent_frames: Vec<String> = r.receivers.iter()
                    .map(|(rid, entry)| build_peer_hello("receiver", entry.wire_version, Some(rid)))
                    .collect();
                r.sender = Some(self_entry.clone());
                to_incumbent = if r.receivers.is_empty() {
                    None
                } else {
                    Some((
                        Role::Receiver,
                        // Sender→receiver notification: sender has no
                        // receiver_id (unique-per-receiver-only concept).
                        build_peer_hello("sender", wire_version, None),
                    ))
                };
                to_newcomer_frames = incumbent_frames;
            }
            Role::Receiver => {
                let rid = match receiver_id {
                    Some(id) => id,
                    None => {
                        let _ = socket.close().await;
                        return;
                    }
                };
                // Newcomer is receiver; incumbent is at most one sender.
                let incumbent_frames: Vec<String> = r.sender.as_ref()
                    .map(|entry| vec![build_peer_hello("sender", entry.wire_version, None)])
                    .unwrap_or_default();
                r.receivers.insert(rid, self_entry.clone());
                to_incumbent = if r.sender.is_some() {
                    Some((
                        Role::Sender,
                        // Notification to the sender about the newcomer
                        // receiver — INCLUDE the newcomer's id so the
                        // sender-side router can register the per-peer
                        // dispatch route.
                        build_peer_hello("receiver", wire_version, Some(&rid)),
                    ))
                } else {
                    None
                };
                to_newcomer_frames = incumbent_frames;
            }
        }
    }
    // Fire notifications AFTER releasing the room lock so we don't hold it
    // across the send-half sink calls.
    if let Some((target, frame)) = to_incumbent {
        let r = room.lock().await;
        match target {
            Role::Sender => r.route_to_sender(&frame),
            Role::Receiver => {
                drop(r);
                let mut r2 = room.lock().await;
                r2.fan_to_receivers(&frame);
            }
        }
    }
    for frame in to_newcomer_frames {
        let _ = tx.send(frame);
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
                    Role::Sender => {
                        // Multi-peer routing (M1): a sender-originated frame
                        // may carry a top-level `to_receiver_id` string. If
                        // present, route to that receiver only. If absent,
                        // fan to all receivers (backward-compat with the
                        // single-receiver stack).
                        let target = serde_json::from_str::<serde_json::Value>(&s)
                            .ok()
                            .and_then(|v| v.get("to_receiver_id")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string()));
                        match target.as_deref().and_then(|s| ReceiverId::from_hex(s).ok()) {
                            Some(rid) => r.route_to_receiver(&rid, &s),
                            None => r.fan_to_receivers(&s),
                        }
                    }
                    Role::Receiver => {
                        // Anti-spoof: if the receiver populated
                        // `from_receiver_id`, it must match the id they
                        // registered with. Prevents receiver A from
                        // impersonating receiver B on the sender's
                        // per-peer dispatch. Absent field = backward-compat
                        // (single-receiver stack, sender doesn't
                        // disambiguate).
                        let claimed = serde_json::from_str::<serde_json::Value>(&s)
                            .ok()
                            .and_then(|v| v.get("from_receiver_id")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string()));
                        if let Some(claim) = claimed.as_deref() {
                            let actual = receiver_id.as_ref().map(|r| r.as_hex());
                            match actual.as_deref() {
                                Some(a) if a == claim => { /* verified */ }
                                Some(a) => {
                                    tracing::warn!(
                                        "dropping receiver frame: claimed from_receiver_id={} != actual={}",
                                        claim, a
                                    );
                                    continue;
                                }
                                None => {
                                    tracing::warn!(
                                        "dropping receiver frame with from_receiver_id={} — receiver has no registered id",
                                        claim
                                    );
                                    continue;
                                }
                            }
                        }
                        // Inject from_receiver_id if the receiver didn't set
                        // it — the sender-side multipeer WS router uses this
                        // to dispatch SDP answers, Ice, KexPub etc. to the
                        // right per-peer inbox. Anti-spoof check above still
                        // stands for the case where the receiver DID claim
                        // an id (must match its registered id).
                        let outgoing = if claimed.is_none() {
                            if let Some(rid) = receiver_id.as_ref() {
                                match serde_json::from_str::<serde_json::Value>(&s) {
                                    Ok(mut v) => {
                                        if let Some(obj) = v.as_object_mut() {
                                            obj.insert(
                                                "from_receiver_id".to_string(),
                                                serde_json::Value::String(rid.as_hex()),
                                            );
                                            v.to_string()
                                        } else {
                                            s.clone()
                                        }
                                    }
                                    Err(_) => s.clone(),
                                }
                            } else {
                                s.clone()
                            }
                        } else {
                            s.clone()
                        };
                        r.route_to_sender(&outgoing);
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Unregister and notify the other side.
    //
    // `peer_left` frames let the counterparty prune stale UI + tear
    // down orphaned peer state without waiting on ICE timeouts. Frame
    // shape mirrors `peer_hello`: {"type":"peer_left","role":<role>,
    // "receiver_id"?:<hex>,"from_receiver_id"?:<hex>}. A departing
    // receiver's frame lists its receiver_id so the sender can look
    // up the right per-peer entry to close.
    {
        let mut r = room.lock().await;
        match role {
            Role::Sender => {
                r.sender = None;
                // Fan a sender-departed notice to every receiver.
                r.fan_to_receivers(r#"{"type":"peer_left","role":"sender"}"#);
            }
            Role::Receiver => {
                if let Some(rid) = receiver_id {
                    r.receivers.remove(&rid);
                    // Notify the sender that THIS receiver went away.
                    let hex = rid.as_hex();
                    let frame = format!(
                        r#"{{"type":"peer_left","role":"receiver","receiver_id":"{hex}","from_receiver_id":"{hex}"}}"#
                    );
                    r.route_to_sender(&frame);
                }
            }
        }
    }
    state.maybe_drop_room(&session).await;
    out.abort();
}

async fn read_hello(socket: &mut WebSocket) -> Option<(Role, Option<ReceiverId>, Option<u32>)> {
    while let Some(msg) = socket.next().await {
        match msg.ok()? {
            Message::Text(t) => {
                let parsed: HelloFrame = serde_json::from_str(&t).ok()?;
                let HelloFrame::Hello { role, receiver_id, wire_version } = parsed;
                let role = match role.as_str() {
                    "sender" => Role::Sender,
                    "receiver" => Role::Receiver,
                    _ => return None,
                };
                return Some((role, receiver_id, wire_version));
            }
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Build a peer_hello notification frame. Wraps counterpart's role +
/// wire_version so the recipient can bail on version mismatch. When
/// `peer_receiver_id` is `Some` (server notifying the sender about a
/// receiver), also injects `from_receiver_id` at the envelope level so
/// the sender-side WS router can dispatch subsequent per-peer frames
/// (KexPub, SDP answer, Ice) to the right peer task.
///
/// Kept as a helper so the two call sites (incumbent-notified,
/// newcomer-notified) stay in sync.
fn build_peer_hello(
    peer_role: &str,
    wire_version: Option<u32>,
    peer_receiver_id: Option<&ReceiverId>,
) -> String {
    let mut v = serde_json::json!({
        "type": "peer_hello",
        "role": peer_role,
    });
    if let Some(ver) = wire_version {
        v["wire_version"] = serde_json::Value::from(ver);
    }
    if let Some(rid) = peer_receiver_id {
        let hex = rid.as_hex();
        // Include BOTH:
        //   - `receiver_id` in the body (matches the receiver-emitted
        //     PeerHello shape; some clients may still look here).
        //   - `from_receiver_id` at the envelope level (the sender-side
        //     WS router keys per-peer inbox dispatch off this field).
        v["receiver_id"] = serde_json::Value::from(hex.clone());
        v["from_receiver_id"] = serde_json::Value::from(hex);
    }
    v.to_string()
}

// Tag-along: PeerSink is re-exported for cross-module type reference in
// case a follow-up wants to construct sinks outside this file.
#[allow(dead_code)]
type _PeerSinkAlias = PeerSink;

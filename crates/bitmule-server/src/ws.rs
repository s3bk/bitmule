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
enum JoinFrame {
    /// Sender opens a new session slot on this ws.
    SessionCreate {
        /// Client wire-protocol version. Server stores per peer and
        /// includes in `peer_joined` notifications so the counterpart
        /// can detect version mismatch and prompt an update.
        #[serde(default)]
        wire_version: Option<u32>,
        /// Chunk-transports this side is willing to speak (preference
        /// order). Values from `{"webrtc","relay"}`. Server copies into
        /// the counterpart's PeerJoined so each side picks the
        /// intersection at KEX time. `None` = pre-v3 client, treated
        /// as `["webrtc","relay"]` by the peer for backward-compat.
        #[serde(default)]
        transports: Option<Vec<String>>,
    },
    /// Receiver joins an existing session slot on this ws.
    SessionJoin {
        receiver_id: ReceiverId,
        #[serde(default)]
        wire_version: Option<u32>,
        #[serde(default)]
        transports: Option<Vec<String>>,
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
    // Wait for the initial SessionCreate or SessionJoin frame.
    let (role, receiver_id, wire_version, transports) = match read_join(&mut socket).await {
        Some(v) => v,
        None => {
            let _ = socket.close().await;
            return;
        }
    };

    let room = state.room(session).await;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Register into the room. After registering, notify each side of the
    // OTHER'S wire_version + transports via `peer_joined` frames so a
    // client can bail cleanly on version mismatch OR pick the negotiated
    // chunk transport from the intersection. `to_incumbent` tells the
    // already-present peer about the newcomer; `to_newcomer` tells the
    // newcomer about the incumbent (needed on our side because the
    // newcomer's own registration ran after the incumbent's already-sent
    // frames drained).
    let self_entry = PeerEntry { sink: tx.clone(), wire_version, transports: transports.clone() };
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
                    .map(|(rid, entry)| build_peer_joined("receiver", entry.wire_version, Some(rid), entry.transports.as_deref()))
                    .collect();
                r.sender = Some(self_entry.clone());
                to_incumbent = if r.receivers.is_empty() {
                    None
                } else {
                    Some((
                        Role::Receiver,
                        // Sender→receiver notification: sender has no
                        // receiver_id (unique-per-receiver-only concept).
                        build_peer_joined("sender", wire_version, None, transports.as_deref()),
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
                    .map(|entry| vec![build_peer_joined("sender", entry.wire_version, None, entry.transports.as_deref())])
                    .unwrap_or_default();
                r.receivers.insert(rid, self_entry.clone());
                to_incumbent = if r.sender.is_some() {
                    Some((
                        Role::Sender,
                        // Notification to the sender about the newcomer
                        // receiver — INCLUDE the newcomer's id so the
                        // sender-side router can register the per-peer
                        // dispatch route.
                        build_peer_joined("receiver", wire_version, Some(&rid), transports.as_deref()),
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

async fn read_join(socket: &mut WebSocket) -> Option<(Role, Option<ReceiverId>, Option<u32>, Option<Vec<String>>)> {
    while let Some(msg) = socket.next().await {
        let raw = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("read_join: ws error before join frame: {e}");
                return None;
            }
        };
        match raw {
            Message::Text(t) => {
                let text = t.to_string();
                match serde_json::from_str::<JoinFrame>(&text) {
                    Ok(parsed) => {
                        return Some(match parsed {
                            JoinFrame::SessionCreate { wire_version, transports } => {
                                (Role::Sender, None, wire_version, transports)
                            }
                            JoinFrame::SessionJoin { receiver_id, wire_version, transports } => {
                                (Role::Receiver, Some(receiver_id), wire_version, transports)
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("read_join: reject frame ({e}) body={text}");
                        return None;
                    }
                }
            }
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Build a `peer_joined` notification frame. Wraps counterpart's role +
/// wire_version so the recipient can bail on version mismatch. When
/// `peer_receiver_id` is `Some` (server notifying the sender about a
/// receiver), also injects `from_receiver_id` at the envelope level so
/// the sender-side WS router can dispatch subsequent per-peer frames
/// (KexPub, SDP answer, Ice) to the right peer task.
///
/// Kept as a helper so the two call sites (incumbent-notified,
/// newcomer-notified) stay in sync.
fn build_peer_joined(
    peer_role: &str,
    wire_version: Option<u32>,
    peer_receiver_id: Option<&ReceiverId>,
    peer_transports: Option<&[String]>,
) -> String {
    let mut v = serde_json::json!({
        "type": "peer_joined",
        "role": peer_role,
    });
    if let Some(ver) = wire_version {
        v["wire_version"] = serde_json::Value::from(ver);
    }
    if let Some(ts) = peer_transports {
        v["transports"] = serde_json::Value::from(
            ts.iter().map(|s| serde_json::Value::from(s.clone())).collect::<Vec<_>>()
        );
    }
    if let Some(rid) = peer_receiver_id {
        let hex = rid.as_hex();
        // Include BOTH:
        //   - `receiver_id` in the body (matches the SignalFrame::PeerJoined
        //     variant on the client side; the receiver_id field is where
        //     the sender reads the paired receiver's id from).
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

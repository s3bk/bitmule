//! WebSocket-based SignalTransport impl for bitmule-server.
//!
//! Wire protocol:
//!
//! Client → server first frame after WS upgrade:
//!   {"type":"hello","session_id":"...","role":"sender"|"receiver","receiver_id":"..."}
//!
//! Server → client:
//!   {"type":"peer_hello","peer_public":"<base64 x25519 public key>"}
//!   {"type":"peer_left"}
//!   {"type":"ice","payload":"<sdp/candidate blob>"}
//!
//! Client → server (relayed to the other peer):
//!   {"type":"ice","payload":"<sdp/candidate blob>"}
//!   {"type":"peer_public","payload":"<base64>"}
//!
//! All frames are JSON on binary WS. The signaling channel carries only
//! SDP/ICE + key-exchange handshake — never chunk data. Chunk data goes over
//! either the WebRTC data channel (direct) or the ChunkStore relay (fallback).

use bitmule_core::{traits::SignalTransport, Error, ReceiverId, Result, SessionId};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{protocol::Message, ClientRequestBuilder},
    MaybeTlsStream, WebSocketStream,
};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WebSocket signaling client. Constructed with the signaling URL.
///
/// Not connected until `connect()` is called.
pub struct WsSignalTransport {
    url: String,
    role: Role,
    receiver_id: Option<ReceiverId>,
    ws: Option<WsStream>,
}

/// Which side of the transfer this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Sender => "sender",
            Role::Receiver => "receiver",
        }
    }
}

impl WsSignalTransport {
    /// Sender side: no receiver_id needed (server assigns one to the incoming receiver).
    pub fn sender<S: Into<String>>(url: S) -> Self {
        Self {
            url: url.into(),
            role: Role::Sender,
            receiver_id: None,
            ws: None,
        }
    }

    /// Receiver side: caller supplies its own [`ReceiverId`].
    pub fn receiver<S: Into<String>>(url: S, receiver_id: ReceiverId) -> Self {
        Self {
            url: url.into(),
            role: Role::Receiver,
            receiver_id: Some(receiver_id),
            ws: None,
        }
    }
}

fn err(msg: impl std::fmt::Display) -> Error {
    Error::Protocol(msg.to_string())
}

#[async_trait]
impl SignalTransport for WsSignalTransport {
    async fn connect(&mut self, session: &SessionId) -> Result<()> {
        let req = ClientRequestBuilder::new(
            self.url.parse().map_err(err)?,
        );
        let (mut ws, _resp) = connect_async(req).await.map_err(err)?;

        // Initial hello frame with session id + role. Both ids serialize
        // as hex strings on the wire.
        let hello = serde_json::json!({
            "type": "hello",
            "session_id": session,
            "role": self.role.as_str(),
            "receiver_id": self.receiver_id,
        });
        ws.send(Message::Text(hello.to_string().into()))
            .await
            .map_err(err)?;

        self.ws = Some(ws);
        tracing::debug!(session = %session.as_hex(), role = ?self.role, "ws signaling connected");
        Ok(())
    }

    async fn send(&mut self, msg: &[u8]) -> Result<()> {
        let ws = self.ws.as_mut().ok_or_else(|| err("not connected"))?;
        ws.send(Message::Binary(msg.to_vec().into()))
            .await
            .map_err(err)?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        let ws = self.ws.as_mut().ok_or_else(|| err("not connected"))?;
        loop {
            let frame = ws
                .next()
                .await
                .ok_or_else(|| err("ws closed"))?
                .map_err(err)?;
            match frame {
                Message::Binary(b) => return Ok(b.to_vec()),
                Message::Text(s) => return Ok(s.as_bytes().to_vec()),
                Message::Ping(p) => {
                    ws.send(Message::Pong(p)).await.map_err(err)?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err(err("ws closed by peer")),
                Message::Frame(_) => {}
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut ws) = self.ws.take() {
            let _ = ws.close(None).await;
        }
        Ok(())
    }
}

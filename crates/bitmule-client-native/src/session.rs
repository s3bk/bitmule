//! Session-single-ws primitive. One `Session` owns the ws + KEX-derived
//! keys for a whole transfer, regardless of which chunk-transport the
//! caller picks. Solves the "auto retries → new ws → server slams the
//! door" race by keeping the same ws + peer-state across a mode switch.
//!
//! Kenna 2026-09-13. Introduced as step 1 of the session-single-ws
//! refactor that also enables AutoParallel (webrtc + relay chunks
//! concurrent).
//!
//! Right now this module ONLY handles the shared open + Hello +
//! wait_for_peer + KEX flow that send_file_relay and recv_file_relay
//! both duplicated. Later commits will:
//!   - Add `Session::try_webrtc_send/recv` reusing the same ws for
//!     SDP+ICE signaling.
//!   - Add `Session::serve_over_relay_http` for the current relay
//!     path (extracts the pump-spawn + send_file_over_relay wire-up).
//!   - Add `Session::serve_auto_parallel` combining both.

use crate::{
    open_ws,
    crypto::{BulkKey, MetaKey, ShareKey},
    str0m_client::{handshake_bulk_key_over_ws, wait_for_peer, ws_send, SignalFrame, Role, Ws},
    WIRE_VERSION,
};
use crate::str0m_client::hex_decode_fixed;
use crate::multipeer::SessionId;
use anyhow::{anyhow, Result};

/// A live, KEX-completed session over a single ws.
///
/// After `Session::open_sender` / `open_receiver` returns, the ws is
/// past Hello + KEX and holds the derived keys. The ws is still owned
/// by this struct; callers hand it over to whatever chunk-transport
/// they pick (relay pump, webrtc SDP signalling, or both concurrently).
pub struct Session {
    pub server_url_http: String,
    pub session_id: SessionId,
    pub session_id_bytes: [u8; 32],
    pub role: Role,
    pub bulk_key: BulkKey,
    pub meta_key: MetaKey,
    /// The signalling ws. Ownership moves out when the caller spawns
    /// its chunk-transport (e.g. `pump_relay_ws`), which typically
    /// takes the ws by value.
    pub ws: Option<Ws>,
}

impl Session {
    /// Sender bootstrap: open ws, Hello{sender}, wait for
    /// peer_hello(receiver), then KEX(sender) with the pre-generated
    /// `bulk_key`.
    pub async fn open_sender(
        server_url_http: &str,
        share_key: &ShareKey,
        bulk_key: BulkKey,
    ) -> Result<Self> {
        let session_hex = share_key.session_id_hex();
        let session_id = SessionId::from_hex(&session_hex)
            .map_err(|e| anyhow!("session_id from hex: {e}"))?;
        let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

        let mut ws = open_ws(server_url_http, &session_hex).await?;
        ws_send(&mut ws, &SignalFrame::Hello {
            role: Role::Sender.as_str().to_owned(),
            receiver_id: None,
            wire_version: Some(WIRE_VERSION),
        }).await?;
        // Don't blast KexPub into an empty room — wait for the server
        // to announce a receiver has joined.
        wait_for_peer(&mut ws, "receiver").await?;
        let (bulk, meta) = handshake_bulk_key_over_ws(
            &mut ws, Role::Sender, share_key, &session_id_bytes, Some(bulk_key),
        ).await?;

        Ok(Self {
            server_url_http: server_url_http.to_string(),
            session_id,
            session_id_bytes,
            role: Role::Sender,
            bulk_key: bulk,
            meta_key: meta,
            ws: Some(ws),
        })
    }

    /// Receiver bootstrap: open ws, Hello{receiver, rid} + PeerHello,
    /// then KEX(receiver). Sender-side of the KEX unwraps its bulk_key
    /// into ours via KeyWrap.
    pub async fn open_receiver(
        server_url_http: &str,
        share_key: &ShareKey,
    ) -> Result<Self> {
        let session_hex = share_key.session_id_hex();
        let session_id = SessionId::from_hex(&session_hex)
            .map_err(|e| anyhow!("session_id from hex: {e}"))?;
        let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

        let mut ws = open_ws(server_url_http, &session_hex).await?;
        let receiver_id = SessionId::random().as_hex();
        ws_send(&mut ws, &SignalFrame::Hello {
            role: Role::Receiver.as_str().to_owned(),
            receiver_id: Some(receiver_id.clone()),
            wire_version: Some(WIRE_VERSION),
        }).await?;
        ws_send(&mut ws, &SignalFrame::PeerHello {
            receiver_id: Some(receiver_id),
            role: None,
            wire_version: Some(WIRE_VERSION),
        }).await?;
        let (bulk, meta) = handshake_bulk_key_over_ws(
            &mut ws, Role::Receiver, share_key, &session_id_bytes, None,
        ).await?;

        Ok(Self {
            server_url_http: server_url_http.to_string(),
            session_id,
            session_id_bytes,
            role: Role::Receiver,
            bulk_key: bulk,
            meta_key: meta,
            ws: Some(ws),
        })
    }

    /// Take the ws out of the session. Panics if already taken.
    /// Callers that need the ws to hand to `pump_relay_ws` or a
    /// str0m signal channel use this.
    pub fn take_ws(&mut self) -> Ws {
        self.ws
            .take()
            .expect("session ws already taken")
    }
}

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
    str0m_client::{handshake_bulk_key_over_ws, wait_for_peer, ws_send, hex_decode_fixed},
    Role, SignalFrame, TransportMode, Ws,
    WIRE_VERSION,
};
use bitmule_core::SessionId;
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
    /// Counterpart's advertised transports (preference order), as
    /// received in PeerJoined. `None` = pre-v3 peer that didn't
    /// advertise. Callers pick the negotiated chunk-transport via
    /// [`crate::negotiate_transport`] on `mode.advertised_transports()`
    /// intersect `peer_transports`.
    pub peer_transports: Option<Vec<String>>,
}

impl Session {
    /// Sender bootstrap: open ws, SessionCreate (advertising `mode`'s
    /// transports), wait for PeerJoined (server-emitted pairing
    /// notification announcing the receiver + its transports), then
    /// KEX(sender) with the pre-generated `bulk_key`.
    pub async fn open_sender(
        server_url_http: &str,
        share_key: &ShareKey,
        bulk_key: BulkKey,
        mode: TransportMode,
    ) -> Result<Self> {
        let session_hex = share_key.session_id_hex();
        let session_id = SessionId::from_hex(&session_hex)
            .map_err(|e| anyhow!("session_id from hex: {e}"))?;
        let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

        let mut ws = open_ws(server_url_http, &session_hex).await?;
        ws_send(&mut ws, &SignalFrame::SessionCreate {
            wire_version: Some(WIRE_VERSION),
            transports: Some(mode.advertised_transports()),
        }).await?;
        // Don't blast KexPub into an empty room — wait for the server
        // to announce a receiver has joined.
        let peer_transports = wait_for_peer(&mut ws, "receiver").await?;
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
            peer_transports,
        })
    }

    /// Receiver bootstrap: open ws, single SessionJoin{rid}, then
    /// KEX(receiver). Sender-side of the KEX unwraps its bulk_key
    /// into ours via KeyWrap. (Was previously Hello+PeerHello — the
    /// server only ever routed off the first frame and the second was
    /// silently dropped by wait_for_peer.)
    pub async fn open_receiver(
        server_url_http: &str,
        share_key: &ShareKey,
        mode: TransportMode,
    ) -> Result<Self> {
        let session_hex = share_key.session_id_hex();
        let session_id = SessionId::from_hex(&session_hex)
            .map_err(|e| anyhow!("session_id from hex: {e}"))?;
        let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

        let mut ws = open_ws(server_url_http, &session_hex).await?;
        let receiver_id = SessionId::random().as_hex();
        ws_send(&mut ws, &SignalFrame::SessionJoin {
            receiver_id,
            wire_version: Some(WIRE_VERSION),
            transports: Some(mode.advertised_transports()),
        }).await?;
        // Receiver's ws is now paired-registered. The PeerJoined
        // notification (carrying sender's transports) arrives BEFORE
        // the sender's KexPub — handshake_bulk_key_over_ws consumes
        // both. To surface peer_transports on the receiver Session,
        // the KEX helper reads and returns it (see
        // `handshake_bulk_key_over_ws` — its return tuple grows a
        // third element on the receiver path).
        // For now, receiver reads it via a peek before KEX:
        let peer_transports = wait_for_peer(&mut ws, "sender").await?;
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
            peer_transports,
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

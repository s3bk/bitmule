//! bitmule-server: the signaling + relay server.
//!
//! Two responsibilities:
//!
//! 1. **Signaling.** A `/ws/:session_id` WebSocket endpoint pairs a sender
//!    with one or more receivers inside a session room and relays SDP/ICE
//!    and key-exchange handshake frames between them. The server sees only
//!    handshake bytes, never chunk plaintext.
//!
//! 2. **Chunk relay.** A REST surface for uploading and downloading
//!    ciphertext chunks, used when direct WebRTC fails or one peer is
//!    offline. Chunk bytes are ciphertext under K_session; the server never
//!    holds a decryption key.
//!
//! Storage is any `ChunkStore` impl. The default binary wires
//! [`bitmule_server_store_fs::FsChunkStore`].
//!
//! Auth is out of scope for this initial cut — the identity-key layer
//! (contacts, pubkey-based routing) attaches in a follow-up commit. Every
//! endpoint currently accepts any hex session id.

pub mod room;
pub mod state;
pub mod ws;
pub mod relay2;
pub mod stun;

/// The link surfaces: shares, invites, the granter's inbox, egress metering
/// (merged from the `bitmule-proto` prototype; see the module docs).
pub mod share;
/// The links-only host: the viewer at `/`, and nothing to browse.
pub mod hosts;

use rand::Rng;
pub use room::{Role, Room};
use serde::{Deserialize, Serialize};
pub use state::AppState;

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct Difficulty(u8);
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct Magic(u32);
impl Magic {
    pub fn new(n: u32) -> Option<Self> {
        if n < (1<<28) {
            Some(Magic(n))
        } else {
            None
        }
    }
    pub fn random(rng: &mut impl Rng) -> Self {
        Magic(rng.r#gen::<u32>() & ((1 << 28) - 1))
    }
}
fn encode_difficulty_and_magic(diffficulty: Difficulty, magic1: Magic, magic2: Magic) -> u64 {
    (diffficulty.0 as u64) << 56 | (magic1.0 as u64) << 28 | magic2.0 as u64
}
fn decode_difficulty_and_magic(n: u64) -> (Difficulty, Magic, Magic) {
    (
        Difficulty((n >> 56) as u8),
        Magic(((n >> 28) & ((1 << 28) - 1)) as u32),
        Magic((n & ((1 << 28) - 1)) as u32)
    )
}

/// All HTTP/WS routes, without the static-file fallback.
pub fn router(state: std::sync::Arc<AppState>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/pow", get(ws::pow_challenge))
        .route("/ws/join", get(ws::ws_join_session))
        .route("/ws/create", get(ws::ws_create_session))
        .route("/session/:sess/:receiver_id", post(relay2::post).get(relay2::get))
        .with_state(state)
}

/// The headers every response carries. The page that handles share links
/// (`/#<key>`) holds the secret of the transfer, so it gets a policy that
/// leaves a script no way to run from anywhere but this origin, nor to send
/// data anywhere but back to it.
///
/// Two hosts are allowed, and only for the marketing page's typefaces: it may
/// fetch a stylesheet from `fonts.googleapis.com` and the font files it names
/// from `fonts.gstatic.com`. Neither can run, and `connect-src 'self'` keeps a
/// page from sending anything anywhere. Every page carries the same policy.
/// The marketing page used to be exempt, under a name of its own, because its
/// CSS and its theme chooser were inline; they are `bitmule.css` and
/// `bitmule.js` now, so it is served as `/` (index.html under a static root)
/// and styled instead of stripped bare by a policy that blocks inline styles.
pub fn security_headers(app: axum::Router) -> axum::Router {
    use axum::{extract::Request, http::{HeaderValue, header}, middleware::{self, Next}, response::Response};

    const CSP: &str = "default-src 'none'; \
        script-src 'self' 'wasm-unsafe-eval'; \
        style-src 'self' https://fonts.googleapis.com; \
        img-src 'self' data: blob:; \
        font-src 'self' https://fonts.gstatic.com; \
        connect-src 'self'; \
        worker-src 'self' blob:; \
        object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    async fn add(request: Request, next: Next) -> Response {
        let mut response = next.run(request).await;
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
        headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
        headers.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
        response
    }
    app.layer(middleware::from_fn(add))
}

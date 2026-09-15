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

pub use room::{Role, Room};
pub use state::AppState;

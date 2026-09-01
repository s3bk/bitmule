//! Browser-side bitmule client. Compiled to wasm and loaded by the
//! landing-page SPA under `web/`.
//!
//! This cut exposes the minimum needed to prove the module loads: a
//! `version()` function and a `SessionId::random_hex()` helper the SPA
//! calls before opening a signaling socket. The chunk-stream and
//! key-exchange surface lands in follow-up commits, mirroring what
//! `bitmule-core` already provides for the CLI.

use bitmule_core::SessionId;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Fresh 32-byte session id, hex-encoded. The SPA uses this to open a
/// signaling socket at `/ws/<hex>` on the server.
#[wasm_bindgen]
pub fn random_session_id_hex() -> String {
    SessionId::random().as_hex()
}

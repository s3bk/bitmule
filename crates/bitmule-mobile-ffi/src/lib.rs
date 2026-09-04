//! bitmule mobile FFI — UniFFI-exported surface for Android + iOS shells.
//!
//! Everything the Kotlin / Swift shell needs to run a full receive
//! (URL parse → session negotiate → chunk decrypt → signature verify)
//! lives behind the UDL-defined interface. The mobile shells never
//! touch bitmule-client-native or bitmule-crypto directly — that
//! boundary is deliberate so a breaking change in the native crate
//! doesn't ripple into the two mobile UI trees at once.
//!
//! Threading contract: `recv_file` runs its own tokio runtime
//! internally (via `tokio::runtime::Builder::new_multi_thread`) so
//! the mobile shell can just `await`/`suspend` the call from any
//! coroutine or dispatch queue.

use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

uniffi::include_scaffolding!("bitmule_mobile_ffi");

pub fn ffi_version() -> String {
    // Semver of the FFI SURFACE (not the crate as a whole). Bump on
    // any UDL change so the shell can fail fast on binary/binding
    // mismatch after an OTA update.
    "0.1.0".to_string()
}

#[derive(Debug, Error)]
pub enum BitmuleError {
    #[error("invalid url: {reason}")]
    InvalidUrl { reason: String },
    #[error("invalid fragment: {reason}")]
    InvalidFragment { reason: String },
    #[error("network: {reason}")]
    Network { reason: String },
    #[error("transport: {reason}")]
    Transport { reason: String },
    #[error("verify: {reason}")]
    Verify { reason: String },
    #[error("io: {reason}")]
    Io { reason: String },
    #[error("unknown: {reason}")]
    Unknown { reason: String },
}

impl From<anyhow::Error> for BitmuleError {
    fn from(e: anyhow::Error) -> Self {
        // Broad initial classifier — refine as specific error types
        // land in bitmule-client-native. Keeping the mapping in one
        // place so the shell can pattern-match without churn.
        let s = format!("{e:#}");
        let lower = s.to_lowercase();
        if lower.contains("decrypt") || lower.contains("verify") || lower.contains("aead") {
            BitmuleError::Verify { reason: s }
        } else if lower.contains("network") || lower.contains("ws") || lower.contains("http") {
            BitmuleError::Network { reason: s }
        } else if lower.contains("io") || lower.contains("fs") || lower.contains("write") {
            BitmuleError::Io { reason: s }
        } else if lower.contains("dtls") || lower.contains("ice") || lower.contains("sctp") || lower.contains("rtc") {
            BitmuleError::Transport { reason: s }
        } else {
            BitmuleError::Unknown { reason: s }
        }
    }
}

pub struct ParsedShareUrl {
    pub server: String,
    pub fragment: String,
}

pub struct RecvOutcome {
    pub path: String,
    pub size: u64,
    pub name: String,
}

// UniFFI callback interface — the mobile shell implements this. Every
// call MAY arrive from a tokio worker thread; the shell is responsible
// for marshaling to the UI thread before touching Compose/SwiftUI state.
pub trait ProgressListener: Send + Sync {
    fn on_progress(&self, received: u64, total: u64, name: String);
}

pub fn parse_share_url(url: String) -> Result<ParsedShareUrl, BitmuleError> {
    let hash = url.find('#').ok_or_else(|| BitmuleError::InvalidUrl {
        reason: "missing '#' fragment separator".into(),
    })?;
    let (before, after) = url.split_at(hash);
    let server = before.trim_end_matches('/').to_string();
    let fragment = after.trim_start_matches('#').to_string();
    if server.is_empty() {
        return Err(BitmuleError::InvalidUrl { reason: "empty server".into() });
    }
    if fragment.is_empty() {
        return Err(BitmuleError::InvalidFragment { reason: "empty fragment".into() });
    }
    Ok(ParsedShareUrl { server, fragment })
}

pub async fn recv_file(
    url: String,
    out_dir: String,
    on_progress: Arc<dyn ProgressListener>,
) -> Result<RecvOutcome, BitmuleError> {
    let parsed = parse_share_url(url)?;
    let link = bitmule_crypto::ShareLink::from_b64_url(&parsed.fragment).map_err(|e| {
        BitmuleError::InvalidFragment { reason: format!("{e:#}") }
    })?;
    let out_dir_path = PathBuf::from(&out_dir);
    let listener = on_progress.clone();
    let final_path = bitmule_client_native::recv_file(
        &parsed.server,
        link.share_key,
        Some(link.signature),
        &out_dir_path,
        bitmule_client_native::TransportMode::Webrtc,
        move |received, total, name| {
            listener.on_progress(received, total, name.to_string());
        },
    )
    .await
    .map_err(BitmuleError::from)?;
    let size = std::fs::metadata(&final_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(RecvOutcome {
        path: final_path.to_string_lossy().into_owned(),
        size,
        name,
    })
}

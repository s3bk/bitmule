//! bitmule mobile FFI — UniFFI-exported surface for Android + iOS shells.
//!
//! Everything the Kotlin / Swift shell needs to run a full receive OR
//! send (URL parse → session negotiate → chunk decrypt/encrypt →
//! signature verify) lives behind the UDL-defined interface. The
//! mobile shells never touch bitmule-client-native or bitmule-crypto
//! directly — that boundary is deliberate so a breaking change in
//! the native crate doesn't ripple into the two mobile UI trees at
//! once.
//!
//! Threading contract: async entry points suspend from any coroutine
//! or dispatch queue. Progress/URL callbacks fire from tokio worker
//! threads — the shell is responsible for marshaling to the UI
//! thread before touching Compose/SwiftUI state.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::fmt::Debug;
use thiserror::Error;
use tokio::io::AsyncReadExt;

use bitmule_client_native::{recv_file as native_recv, send_file_multi, TransportMode};
use bitmule_client_native::multipeer::ServeMode;
use bitmule_crypto::{BulkKey, CommitmentHasher, ShareKey, ShareLink};

uniffi::include_scaffolding!("bitmule_mobile_ffi");

pub fn ffi_version() -> String {
    // Semver of the FFI SURFACE (not the crate as a whole). Bump on
    // any UDL change so the shell can fail fast on binary/binding
    // mismatch after an OTA update.
    "0.2.0".to_string()
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

pub struct SendOutcome {
    pub share_url: String,
    pub session_hex: String,
    pub peers_served: u64,
}

#[uniffi::trait_interface]
pub trait ProgressListener: Send + Sync + Debug {
    fn on_progress(&self, received: u64, total: u64, name: String);
}

#[uniffi::trait_interface]
pub trait UrlListener: Send + Sync + Debug {
    fn on_url(&self, url: String, session_hex: String, file_name: String, file_size: u64);
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
    let link = ShareLink::from_b64_url(&parsed.fragment)
        .map_err(|e| BitmuleError::InvalidFragment { reason: format!("{e:#}") })?;
    let out_dir_path = PathBuf::from(&out_dir);
    let listener = on_progress.clone();
    let final_path = native_recv(
        &parsed.server,
        link.share_key,
        Some(link.signature),
        &out_dir_path,
        TransportMode::Webrtc,
        move |received, total, name| {
            listener.on_progress(received, total, name.to_string());
        },
    )
    .await
    .map_err(BitmuleError::from)?;
    let size = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(RecvOutcome { path: final_path.to_string_lossy().into_owned(), size, name })
}

pub async fn send_file(
    server: String,
    file_path: String,
    multi: bool,
    on_url: Arc<dyn UrlListener>,
) -> Result<SendOutcome, BitmuleError> {
    let path = PathBuf::from(&file_path);
    let meta = tokio::fs::metadata(&path).await.map_err(|e| BitmuleError::Io {
        reason: format!("stat {}: {e}", path.display()),
    })?;
    if !meta.is_file() {
        return Err(BitmuleError::Io {
            reason: format!("{} must be a regular file", path.display()),
        });
    }
    let file_size = meta.len();
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());

    // Mint share_key + bulk_key up front. Hash the file with the
    // bulk_key to produce the URL signature commitment. Share URL
    // fragment = base64url(share_key || signature). Mirrors the
    // desktop-CLI `prepare_and_spawn_send` in crates/bitmule/src/main.rs.
    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let session_hex = share_key.session_id_hex();
    let signature = commit_file(&path, &bulk_key).await?;
    let link = ShareLink::new(share_key.clone(), signature);
    let share_url = format!(
        "{}/#{}",
        server.trim_end_matches('/'),
        link.to_b64_url(),
    );

    // Fire the URL callback BEFORE spawning the transfer so the shell
    // can put the URL / QR on screen immediately. Then block on the
    // transfer's completion.
    on_url.on_url(share_url.clone(), session_hex.clone(), file_name, file_size);

    let mode = if multi { ServeMode::Multi } else { ServeMode::Complete };
    // FFI send only accepts a single file path today — multi-file/dir
    // bundling belongs in the Kotlin/Swift caller (F4 Android + iOS
    // pickers zip on their side). None here = single-file wire path.
    send_file_multi(
        server.trim_end_matches('/'),
        share_key,
        bulk_key,
        path,
        None,
        mode,
    )
    .await
    .map_err(BitmuleError::from)?;

    Ok(SendOutcome {
        share_url,
        session_hex,
        // Complete mode returns after first-peer; Multi runs until
        // cancel so this value is really "at least 1" — refine when
        // send_serve exposes a per-peer completion counter.
        peers_served: 1,
    })
}

pub fn qr_png_bytes(text: String, pixel_scale: u32) -> Result<Vec<u8>, BitmuleError> {
    let scale = pixel_scale.max(1).min(32);
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| BitmuleError::Unknown { reason: format!("qr encode: {e}") })?;
    let image = code
        .render::<image::Luma<u8>>()
        .module_dimensions(scale, scale)
        .quiet_zone(true)
        .build();
    let mut out = Vec::with_capacity(image.width() as usize * image.height() as usize);
    image
        .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| BitmuleError::Io { reason: format!("png encode: {e}") })?;
    Ok(out)
}

async fn commit_file(path: &Path, bulk_key: &BulkKey) -> Result<[u8; 32], BitmuleError> {
    let mut f = tokio::fs::File::open(path).await.map_err(|e| BitmuleError::Io {
        reason: format!("open {}: {e}", path.display()),
    })?;
    let mut hasher = CommitmentHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(|e| BitmuleError::Io {
            reason: format!("read {}: {e}", path.display()),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize(bulk_key))
}

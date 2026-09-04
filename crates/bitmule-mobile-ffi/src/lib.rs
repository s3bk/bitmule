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
use std::sync::{Arc, LazyLock};
use std::fmt::Debug;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::runtime::Runtime;

use bitmule_client_native::{recv_file as native_recv, send_file_multi, send_file_relay, TransportMode};
use bitmule_client_native::multipeer::ServeMode;
use bitmule_crypto::{BulkKey, CommitmentHasher, ShareKey, ShareLink};

uniffi::include_scaffolding!("bitmule_mobile_ffi");

// Global multi-threaded tokio runtime for the FFI. Every `async fn`
// exported over UniFFI wraps its body in `TOKIO_RT.spawn(...).await`,
// so the actual work always runs inside a tokio context regardless of
// the executor that polls the outer Future. Without this, calls
// against `tokio::fs`, `tokio::spawn`, `str0m`'s inner tokio primitives,
// etc. fail at runtime with "there is no reactor running" the moment
// the Kotlin coroutine dispatch picks up the outer Future on a
// non-tokio thread.
//
// One process-wide runtime is deliberate: multiple runtimes on Android
// would compete for threadpool workers + double the wake-up cost, and
// nothing in our surface wants isolated schedulers.
static TOKIO_RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bitmule-ffi-tokio")
        .build()
        .expect("failed to build bitmule-ffi tokio runtime")
});

/// Wrap an async body in a tokio spawn so it runs on TOKIO_RT and its
/// inner tokio primitives are all in a valid reactor context.
async fn run_on_tokio<F, T>(fut: F) -> Result<T, BitmuleError>
where
    F: std::future::Future<Output = Result<T, BitmuleError>> + Send + 'static,
    T: Send + 'static,
{
    match TOKIO_RT.spawn(fut).await {
        Ok(inner) => inner,
        Err(join_err) => Err(BitmuleError::Unknown {
            reason: format!("tokio join: {join_err}"),
        }),
    }
}

pub fn ffi_version() -> String {
    // Semver of the FFI SURFACE (not the crate as a whole). Bump on
    // any UDL change so the shell can fail fast on binary/binding
    // mismatch after an OTA update.
    // 0.3.0 (F4): send_file takes `sequence<string>` file_paths + auto
    // bundles; RecvOutcome gains `is_bundle` and auto-unpacks
    // container="zip-store" transfers into a directory before return.
    "0.3.0".to_string()
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
    /// `true` when the transfer was a `container="zip-store"` bundle
    /// and the FFI has already extracted it into a directory at
    /// `path`. `false` for single-file transfers (also the fallback
    /// when unpack fails — `path` then points at the raw zip so the
    /// caller can still hand the bytes off).
    pub is_bundle: bool,
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
    // Enter the FFI tokio runtime for the whole body so every tokio
    // primitive downstream (native_recv, container::unpack_zip_store,
    // str0m internals) has a live reactor.
    run_on_tokio(recv_file_inner(url, out_dir, on_progress)).await
}

async fn recv_file_inner(
    url: String,
    out_dir: String,
    on_progress: Arc<dyn ProgressListener>,
) -> Result<RecvOutcome, BitmuleError> {
    let parsed = parse_share_url(url)?;
    let link = ShareLink::from_b64_url(&parsed.fragment)
        .map_err(|e| BitmuleError::InvalidFragment { reason: format!("{e:#}") })?;
    let out_dir_path = PathBuf::from(&out_dir);

    // WebRTC-first with relay fallback. WEBRTC_DEADLINE bounds the
    // WebRTC attempt so a broken NAT / ICE-failure doesn't hang the
    // caller forever — the web SPA has the same pattern via
    // armFallbackTimer. On any WebRTC-side error OR the deadline
    // firing without a DC-open, we re-open on the relay transport
    // and re-run recv with the same share_key + signature. The relay
    // path negotiates fresh crypto over the same WS/session_hex.
    const WEBRTC_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
    let listener_wr = on_progress.clone();
    let webrtc_attempt = tokio::time::timeout(
        WEBRTC_DEADLINE,
        native_recv(
            &parsed.server,
            link.share_key.clone(),
            Some(link.signature),
            &out_dir_path,
            TransportMode::Webrtc,
            move |received, total, name| {
                listener_wr.on_progress(received, total, name.to_string());
            },
        ),
    )
    .await;
    let outcome = match webrtc_attempt {
        Ok(Ok(o)) => o,
        Ok(Err(webrtc_err)) => {
            tracing::warn!("recv webrtc failed ({webrtc_err:#}); falling back to relay");
            let listener_relay = on_progress.clone();
            native_recv(
                &parsed.server,
                link.share_key,
                Some(link.signature),
                &out_dir_path,
                TransportMode::Relay,
                move |received, total, name| {
                    listener_relay.on_progress(received, total, name.to_string());
                },
            )
            .await
            .map_err(BitmuleError::from)?
        }
        Err(_) => {
            tracing::warn!("recv webrtc DC did not open within {WEBRTC_DEADLINE:?}; falling back to relay");
            let listener_relay = on_progress.clone();
            native_recv(
                &parsed.server,
                link.share_key,
                Some(link.signature),
                &out_dir_path,
                TransportMode::Relay,
                move |received, total, name| {
                    listener_relay.on_progress(received, total, name.to_string());
                },
            )
            .await
            .map_err(BitmuleError::from)?
        }
    };

    // If the sender flagged `container="zip-store"`, unpack it here
    // and hand the caller the directory. Extraction failure isn't
    // fatal — we fall back to returning the raw zip so the shell
    // can still show / share the bytes.
    if outcome.container.as_deref() == Some("zip-store") {
        let unpack_dir = bitmule_client_native::container::unpack_dir_for(&outcome.path);
        match bitmule_client_native::container::unpack_zip_store(&outcome.path, &unpack_dir).await {
            Ok(entries) => {
                let _ = std::fs::remove_file(&outcome.path);
                let size = dir_size_recursive(&unpack_dir);
                let stem = unpack_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "bundle".to_string());
                let name = format!(
                    "{stem} ({entries} file{})",
                    if entries == 1 { "" } else { "s" }
                );
                return Ok(RecvOutcome {
                    path: unpack_dir.to_string_lossy().into_owned(),
                    size,
                    name,
                    is_bundle: true,
                });
            }
            Err(_e) => {
                // fall through to the single-file shape below
            }
        }
    }

    let final_path = outcome.path;
    let size = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(RecvOutcome {
        path: final_path.to_string_lossy().into_owned(),
        size,
        name,
        is_bundle: false,
    })
}

/// Sum of regular-file byte lengths under `dir`, best-effort — walk
/// errors are ignored so the size stays a report, not a failure mode.
fn dir_size_recursive(dir: &Path) -> u64 {
    let mut total: u64 = 0;
    for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
        if entry.file_type().is_file() {
            if let Ok(md) = entry.metadata() {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
}

pub async fn send_file(
    server: String,
    file_paths: Vec<String>,
    multi: bool,
    on_url: Arc<dyn UrlListener>,
) -> Result<SendOutcome, BitmuleError> {
    run_on_tokio(send_file_inner(server, file_paths, multi, on_url)).await
}

async fn send_file_inner(
    server: String,
    file_paths: Vec<String>,
    multi: bool,
    on_url: Arc<dyn UrlListener>,
) -> Result<SendOutcome, BitmuleError> {
    if file_paths.is_empty() {
        return Err(BitmuleError::Io {
            reason: "no file paths given".into(),
        });
    }
    let paths: Vec<PathBuf> = file_paths.iter().map(PathBuf::from).collect();
    for p in &paths {
        let md = tokio::fs::metadata(p).await.map_err(|e| BitmuleError::Io {
            reason: format!("stat {}: {e}", p.display()),
        })?;
        if !md.is_file() {
            return Err(BitmuleError::Io {
                reason: format!("{} must be a regular file (dir picking not yet supported on FFI)", p.display()),
            });
        }
    }

    // Bundling decision mirrors the CLI/Qt6: 1 path = stream as-is,
    // N>=2 = build a store-mode zip on the fly and flag the meta so
    // the receiver auto-unpacks. Zip guard is held in scope until
    // send_file_multi returns (single task, no spawn — FFI's send
    // fn returns to the caller when the transfer completes).
    let (send_path, _zip_guard, container, file_name) = if paths.len() == 1 {
        let p = paths[0].clone();
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file.bin".to_string());
        (p, None, None, name)
    } else {
        let (tmp, disp) = bitmule_client_native::container::build_zip_bundle(&paths)
            .await
            .map_err(BitmuleError::from)?;
        (tmp.path().to_path_buf(), Some(tmp), Some("zip-store".to_string()), disp)
    };
    let file_size = tokio::fs::metadata(&send_path).await
        .map(|m| m.len())
        .unwrap_or(0);

    // Mint share_key + bulk_key up front. Hash the send file (raw
    // single file OR the just-built bundle) with the bulk_key to
    // produce the URL signature commitment. Share URL fragment =
    // base64url(share_key || signature). Mirrors the desktop-CLI
    // `prepare_and_spawn_send` in crates/bitmule/src/main.rs.
    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let session_hex = share_key.session_id_hex();
    let signature = commit_file(&send_path, &bulk_key).await?;
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
    let server_trimmed = server.trim_end_matches('/').to_string();

    // WebRTC-first with relay fallback in Complete mode. If WebRTC
    // never completes (no peer connects, ICE fails, etc.) inside the
    // deadline, republish the same session via the relay path — the
    // share_key + bulk_key + signature are already committed on the
    // URL the receiver holds, so re-sending as relay lands cleanly on
    // whichever transport the receiver is currently attempting.
    //
    // Multi mode = server-keeps-URL-live-indefinitely, no deadline
    // makes sense; we call send_file_multi directly and any failure
    // surfaces to the caller. Live-URL sessions that need relay
    // should be started explicitly by the caller with a --relay-mode
    // FFI arg (not yet exposed; add when needed).
    const WEBRTC_SEND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
    if multi {
        send_file_multi(
            &server_trimmed,
            share_key,
            bulk_key,
            send_path,
            container,
            mode,
        )
        .await
        .map_err(BitmuleError::from)?;
    } else {
        let share_key_wr = share_key.clone();
        let bulk_key_wr = bulk_key.clone();
        let send_path_wr = send_path.clone();
        let container_wr = container.clone();
        let server_wr = server_trimmed.clone();
        let webrtc_attempt = tokio::time::timeout(
            WEBRTC_SEND_DEADLINE,
            send_file_multi(&server_wr, share_key_wr, bulk_key_wr, send_path_wr, container_wr, mode),
        )
        .await;
        match webrtc_attempt {
            Ok(Ok(())) => { /* WebRTC succeeded */ }
            Ok(Err(webrtc_err)) => {
                tracing::warn!("send webrtc failed ({webrtc_err:#}); falling back to relay");
                send_file_relay(
                    &server_trimmed,
                    share_key,
                    bulk_key,
                    &send_path,
                    container.as_deref(),
                    |_sent, _total| {},
                )
                .await
                .map_err(BitmuleError::from)?;
            }
            Err(_) => {
                tracing::warn!("send webrtc did not complete within {WEBRTC_SEND_DEADLINE:?}; falling back to relay");
                send_file_relay(
                    &server_trimmed,
                    share_key,
                    bulk_key,
                    &send_path,
                    container.as_deref(),
                    |_sent, _total| {},
                )
                .await
                .map_err(BitmuleError::from)?;
            }
        }
    }

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

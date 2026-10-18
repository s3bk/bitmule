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
use std::sync::{Arc, LazyLock, Mutex};
use std::fmt::Debug;
use thiserror::Error;
use tokio::runtime::Runtime;

use bitmule::v2::{self, Options, Server};
use bitmule_client_common::transfer::{Storage, TransferBuilder};
use bitmule_client_native::crypto::ShareLink;
use bitmule_core::protocol::websocket::TransferType;

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
    // 0.4.0: runs on the v2 protocol (same interface; `multi` is ignored,
    // a send ends once the receivers that connected have finished; the
    // received file is named by the sender).
    // 0.5.0: adds decode_qr for the camera scanner.
    "0.5.0".to_string()
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
    // primitive downstream (the v2 workers, str0m internals) has a live reactor.
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
    // a share link can name any server: not one without TLS
    let server = Server::parse_checked(&parsed.server, false).map_err(|e| BitmuleError::InvalidUrl { reason: format!("{e:#}") })?;
    let out_dir_path = PathBuf::from(&out_dir);
    std::fs::create_dir_all(&out_dir_path).map_err(|e| BitmuleError::Io { reason: format!("create {out_dir}: {e}") })?;

    // The file is made once the sender's manifest is in, named after what the
    // sender calls it. Progress reports use that name.
    let chosen: Arc<Mutex<Option<PathBuf>>> = Arc::default();
    let open = {
        let chosen = chosen.clone();
        move |manifest: &bitmule_core::protocol::websocket::TransferManifest| {
            let name = manifest.file_name().unwrap_or_else(|| "bitmule-download".to_string());
            // a taken name is kept; the new file gets `name (1)`, …
            let (path, file) = bitmule::output::open_new(&out_dir_path.join(name), bitmule::OnConflict::Rename, |_| unreachable!())?;
            *chosen.lock().unwrap() = Some(path);
            Ok(file)
        }
    };
    let progress = {
        let chosen = chosen.clone();
        move |received: u64, total: u64| {
            let name = chosen.lock().unwrap().as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            on_progress.on_progress(received, total, name);
        }
    };
    let report = match v2::run_recv_progress(&server, &link, open, progress, Options::default()).await {
        Ok(report) => report,
        Err(e) => {
            // the file is not what was sent
            if e.is::<v2::VerifyFailed>() {
                if let Some(path) = chosen.lock().unwrap().take() {
                    let _ = std::fs::remove_file(path);
                }
                return Err(BitmuleError::Verify { reason: format!("{e:#}") });
            }
            return Err(BitmuleError::from(e));
        }
    };
    let path = chosen.lock().unwrap().clone().ok_or_else(|| BitmuleError::Unknown { reason: "no file was written".into() })?;

    // Several files arrive as one zip: unpack it here and hand the caller the
    // directory. Extraction failure isn't fatal — fall back to the raw zip so
    // the shell can still show / share the bytes.
    if matches!(report.manifest.transfer_typ, TransferType::MultiFileZip { .. }) {
        let zip_path = path.clone();
        let limit = bitmule::unzip::unpack_limit(&report.manifest);
        let unpacked = tokio::task::spawn_blocking(move || unpack_zip(&zip_path, limit)).await;
        if let Ok(Ok((dir, entries))) = unpacked {
            let _ = std::fs::remove_file(&path);
            let stem = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "bundle".to_string());
            return Ok(RecvOutcome {
                size: dir_size_recursive(&dir),
                name: format!("{stem} ({entries} file{})", if entries == 1 { "" } else { "s" }),
                path: dir.to_string_lossy().into_owned(),
                is_bundle: true,
            });
        }
    }

    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(RecvOutcome { path: path.to_string_lossy().into_owned(), size, name, is_bundle: false })
}

/// Unpack `zip_path` (stored, deflated or zstd entries, holding at most
/// `limit` bytes) into a new directory next to it. Returns the directory and
/// the number of files.
fn unpack_zip(zip_path: &Path, limit: u64) -> anyhow::Result<(PathBuf, usize)> {
    let parent = zip_path.parent().ok_or_else(|| anyhow::anyhow!("zip has no directory"))?;
    let dir = bitmule::unzip::unpack_zip(zip_path, parent, limit)?;
    let files = walkdir::WalkDir::new(&dir).into_iter().flatten().filter(|e| e.file_type().is_file()).count();
    Ok((dir, files))
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
    _multi: bool, // v2 ends a send once the receivers that connected are done
    on_url: Arc<dyn UrlListener>,
) -> Result<SendOutcome, BitmuleError> {
    if file_paths.is_empty() {
        return Err(BitmuleError::Io { reason: "no file paths given".into() });
    }
    // 1 path = streams as it is; several are zipped on the fly by the builder.
    let mut builder = TransferBuilder::new();
    for path in file_paths.iter().map(PathBuf::from) {
        let md = tokio::fs::metadata(&path).await.map_err(|e| BitmuleError::Io {
            reason: format!("stat {}: {e}", path.display()),
        })?;
        if !md.is_file() {
            return Err(BitmuleError::Io {
                reason: format!("{} must be a regular file (dir picking not yet supported on FFI)", path.display()),
            });
        }
        let name = path.file_name().map(PathBuf::from);
        builder.add_file(Storage::File(path), name);
    }
    // hashes the data for the link's signature
    let (manifest, transfer) = builder.commit_async().await.map_err(BitmuleError::from)?;
    let file_name = manifest.file_name().unwrap_or_default();
    let file_size = manifest.transfer_size;

    let server = Server::parse_checked(&server, false).map_err(|e| BitmuleError::InvalidUrl { reason: format!("{e:#}") })?;
    let minted: Arc<Mutex<Option<(String, String)>>> = Arc::default();
    let listener_state = minted.clone();
    let server_for_url = server.clone();
    v2::run_send(&server, manifest, transfer, Options::default(), move |link| {
        // fires before the transfer starts, so the shell can show the URL / QR at once
        let url = server_for_url.share_url(link);
        let session_hex = link.share_key.session_id_hex();
        *listener_state.lock().unwrap() = Some((url.clone(), session_hex.clone()));
        on_url.on_url(url, session_hex, file_name, file_size);
    })
    .await
    .map_err(BitmuleError::from)?;

    let (share_url, session_hex) = minted.lock().unwrap().take().unwrap_or_default();
    Ok(SendOutcome { share_url, session_hex, peers_served: 1 })
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

/// Looks for QR codes in one camera frame. Returns the text of the first one
/// that decodes; frames without a readable code are the normal case while
/// the user is still aiming, so that is `None`, not an error.
pub fn decode_qr(gray: Vec<u8>, width: u32, height: u32, row_stride: u32) -> Option<String> {
    let (w, h, stride) = (width as usize, height as usize, row_stride as usize);
    if w == 0 || h == 0 || stride < w || gray.len() < stride * (h - 1) + w {
        return None;
    }
    // the decoder wants the rows back to back
    let packed: Vec<u8> = if stride == w {
        gray
    } else {
        gray.chunks(stride).take(h).flat_map(|row| &row[..w]).copied().collect()
    };
    // quirc needs a few pixels per module and a sharp edge: a code that is
    // small or soft in the frame is often found only after enlarging it
    // (measured on degraded copies of a share-link code: plain 15 of 22, with
    // these passes 21 of 22). Cheapest pass first.
    let frame = image::GrayImage::from_raw(width, height, packed)?;
    if let Some(text) = decode_plain(&frame) {
        return Some(text);
    }
    let up2 = enlarge(&frame, 2);
    if let Some(text) = decode_plain(&up2) {
        return Some(text);
    }
    let up3 = enlarge(&frame, 3);
    decode_plain(&up3).or_else(|| decode_plain(&image::imageops::unsharpen(&up3, 4.0, 10)))
}

fn decode_plain(frame: &image::GrayImage) -> Option<String> {
    let mut decoder = quircs::Quirc::default();
    decoder
        .identify(frame.width() as usize, frame.height() as usize, frame.as_raw())
        .filter_map(|code| code.ok()?.decode().ok())
        .find_map(|data| String::from_utf8(data.payload).ok())
}

fn enlarge(frame: &image::GrayImage, factor: u32) -> image::GrayImage {
    image::imageops::resize(frame, frame.width() * factor, frame.height() * factor, image::imageops::FilterType::CatmullRom)
}

#[cfg(test)]
mod qr_tests {
    use super::*;

    fn frame(text: &str, scale: u32) -> (Vec<u8>, u32, u32) {
        let image = qrcode::QrCode::new(text.as_bytes())
            .unwrap()
            .render::<image::Luma<u8>>()
            .module_dimensions(scale, scale)
            .quiet_zone(true)
            .build();
        (image.as_raw().clone(), image.width(), image.height())
    }

    #[test]
    fn decodes_a_share_link() {
        let url = "https://bitmule.qdat.net/#TMUe-v7W5eT6PQATGAtCQ7sV4K8stFmiRg8pBWV_BE21YNHenSlXHRnsx_HVMi6ccZnIubqU4KjsQbM5ThEJnQ";
        let (gray, w, h) = frame(url, 4);
        assert_eq!(decode_qr(gray, w, h, w).as_deref(), Some(url));
    }

    #[test]
    fn honours_the_row_stride() {
        let url = "https://bitmule.qdat.net/#abc";
        let (gray, w, h) = frame(url, 6);
        // camera rows are often padded
        let stride = w + 24;
        let padded: Vec<u8> = gray.chunks(w as usize).flat_map(|row| row.iter().copied().chain([0u8; 24])).collect();
        assert_eq!(decode_qr(padded, w, h, stride).as_deref(), Some(url));
    }

    #[test]
    fn a_small_soft_code_is_found_after_enlarging() {
        let url = "https://bitmule.qdat.net/#TMUe-v7W5eT6PQATGAtCQ7sV4K8stFmiRg8pBWV_BE21YNHenSlXHRnsx_HVMi6ccZnIubqU4KjsQbM5ThEJnQ";
        let (gray, w, h) = frame(url, 3);
        let soft = image::imageops::blur(&image::GrayImage::from_raw(w, h, gray).unwrap(), 1.5);
        assert_eq!(decode_plain(&soft), None, "the test frame should need the extra passes");
        assert_eq!(decode_qr(soft.into_raw(), w, h, w).as_deref(), Some(url));
    }

    #[test]
    fn a_frame_without_a_code_is_none() {
        assert_eq!(decode_qr(vec![128; 64 * 64], 64, 64, 64), None);
        assert_eq!(decode_qr(vec![0; 10], 64, 64, 64), None);
    }
}

//! Bitmule — resumable, E2E-encrypted, WebRTC-first file transfer.
//!
//! Library surface of the `bitmule` crate. The same crate also ships a
//! CLI in `src/main.rs`; `cargo add bitmule` gets the types below,
//! `cargo install bitmule` gets the binary.
//!
//! # Design
//!
//! One [`Client`] carries the signaling/relay server URL and any
//! long-lived state (identity, HTTP client reuse). A send is a fluent
//! builder — chain `.send(path)` for each file, override the display
//! name with `.send_with_name(path, name)`, tune `.mode()` /
//! `.on_progress()`, then `.start().await` to mint the share URL and
//! spawn the transport. Recv is symmetric: `client.recv(url)`,
//! `.dest(dir)`, `.on_progress(...)`, `.start().await` — the returned
//! [`RecvOutcome`] iterates each received file via `.files()` with
//! per-file `read()` / `read_all().await`.
//!
//! # Send
//!
//! ```no_run
//! # #[tokio::main] async fn main() -> bitmule::Result<()> {
//! use bitmule::{Client, TransportMode};
//!
//! let client = Client::new("https://bitmule.qdat.net");
//! let handle = client
//!     .send("./photo.png")
//!     .send("./another_photo.png")
//!     .send_with_name("/tmp/folder", "secret")
//!     .mode(TransportMode::Auto)
//!     .on_progress(|sent, total| eprintln!("{sent}/{total}"))
//!     .start()
//!     .await?;
//! println!("share {}", handle.share_url());
//! handle.wait().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Recv
//!
//! ```no_run
//! # #[tokio::main] async fn main() -> bitmule::Result<()> {
//! use bitmule::Client;
//!
//! let client = Client::new("https://bitmule.qdat.net");
//! let outcome = client
//!     .recv("https://bitmule.qdat.net/#…")
//!     .dest("./downloads")
//!     .on_progress(|sent, total, name| eprintln!("{name}: {sent}/{total}"))
//!     .start()
//!     .await?;
//! for f in outcome.files() {
//!     println!("{} {}b", f.name(), f.size());
//!     let bytes = f.read_all().await?;
//!     drop(bytes);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Progress
//!
//! Callbacks fire from the transport task on chunk boundaries — cheap
//! and non-blocking. Progress is in plaintext bytes; sender and
//! receiver see the same denominator.
//!
//! # What isn't here yet
//!
//! - Identity / contacts API (currently `src/identity.rs`, CLI-only).
//! - Streaming send from an `AsyncRead` — the transport wants a `Path`
//!   today. Needed for the synthline-agent handoff where an
//!   attachment lives in a SQLite BLOB.
//! - Structured error variants — [`Error::Transport`] wraps
//!   `anyhow::Error` verbatim.

use bitmule_client_native::{self as native, commit_reader};
use bitmule_client_native::crypto::{BulkKey, ShareKey, ShareLink};
use bitmule_client_native::{recv_file, send_file_multi, send_file_relay, ServeMode};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncRead;

pub use native::TransportMode;
pub mod v2;

// -----------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    EmptySend,
    BadShareUrl(String),
    NotAFileOrDir(PathBuf),
    Transport(anyhow::Error),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EmptySend => write!(f, "no paths given to send"),
            Error::BadShareUrl(s) => write!(f, "invalid share url: {s}"),
            Error::NotAFileOrDir(p) => write!(f, "{} is not a file or directory", p.display()),
            Error::Transport(e) => write!(f, "transport: {e}"),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport(e) => Some(e.as_ref()),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Transport(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// -----------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------

#[derive(Clone)]
pub struct Client {
    server: Arc<String>,
}

impl Client {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: Arc::new(server.into()),
        }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder { server: None }
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    /// Start a fluent send with one file. Chain `.send(...)` /
    /// `.send_with_name(...)` for more.
    pub fn send(&self, path: impl Into<PathBuf>) -> SendBuilder {
        SendBuilder::new(self.clone()).send(path)
    }

    /// Fluent recv from a share URL. Defaults `dest` to the current
    /// working directory until [`RecvBuilder::dest`] overrides.
    pub fn recv(&self, share_url: impl Into<String>) -> RecvBuilder {
        RecvBuilder {
            client: self.clone(),
            share_url: share_url.into(),
            dest: PathBuf::from("."),
            mode: TransportMode::Webrtc,
            progress: None,
        }
    }
}

pub struct ClientBuilder {
    server: Option<String>,
}

impl ClientBuilder {
    pub fn server(mut self, s: impl Into<String>) -> Self {
        self.server = Some(s.into());
        self
    }

    pub fn build(self) -> Client {
        Client::new(
            self.server
                .unwrap_or_else(|| "https://bitmule.qdat.net".to_string()),
        )
    }
}

// -----------------------------------------------------------------------
// Send
// -----------------------------------------------------------------------

/// One entry queued for the next send. `display_name` is `None` when
/// the sender wants the receiver to see the original basename, `Some`
/// when `.send_with_name(...)` overrode it.
struct SendEntry {
    path: PathBuf,
    display_name: Option<String>,
}

/// Fluent send configuration. Own the builder, chain `.send(...)` calls
/// to append files, then `.start()`.
pub struct SendBuilder {
    client: Client,
    entries: Vec<SendEntry>,
    mode: TransportMode,
    multi: bool,
    progress: Option<Box<dyn FnMut(u64, u64) + Send>>,
}

impl SendBuilder {
    fn new(client: Client) -> Self {
        Self {
            client,
            entries: Vec::new(),
            mode: TransportMode::Webrtc,
            multi: false,
            progress: None,
        }
    }

    /// Append a file or directory to the send. Multiple `.send(...)`
    /// calls accumulate. Directories are auto-bundled into a
    /// store-mode zip on the fly (the receiver unpacks).
    pub fn send(mut self, path: impl Into<PathBuf>) -> Self {
        self.entries.push(SendEntry {
            path: path.into(),
            display_name: None,
        });
        self
    }

    /// Append a path with an explicit display name (what the receiver
    /// sees in the meta frame / on disk). Same accumulator as
    /// [`SendBuilder::send`].
    pub fn send_with_name(mut self, path: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        self.entries.push(SendEntry {
            path: path.into(),
            display_name: Some(name.into()),
        });
        self
    }

    /// Force a specific transport. Defaults to WebRTC.
    pub fn mode(mut self, m: TransportMode) -> Self {
        self.mode = m;
        self
    }

    /// Keep the sender live and hand the same URL to any number of
    /// receivers. Combines with [`SendBuilder::mode`].
    pub fn multi(mut self, on: bool) -> Self {
        self.multi = on;
        self
    }

    /// Progress callback: `(bytes_sent, total_bytes)`. Fires from the
    /// transport task on chunk boundaries; keep it cheap.
    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Mint the session, hash the file(s), spawn the transport task,
    /// and return a [`SendHandle`] carrying the share URL.
    pub async fn start(self) -> Result<SendHandle> {
        if self.entries.is_empty() {
            return Err(Error::EmptySend);
        }

        // Bundle decision: single existing file → send as-is. Directory
        // or multi-path → build a store-mode zip bundle on the fly,
        // meta-flag it so the receiver unpacks. `send_with_name`
        // overrides the top-level display name; only the FIRST entry's
        // display_name is honored for bundles (later ones become
        // entries inside the zip and use their own basenames).
        let entry_paths: Vec<PathBuf> = self.entries.iter().map(|e| e.path.clone()).collect();
        let first_display_override = self
            .entries
            .first()
            .and_then(|e| e.display_name.clone());

        let (send_path, zip_guard, container, display_name) = if entry_paths.len() == 1 {
            let p = &entry_paths[0];
            let meta = tokio::fs::metadata(p)
                .await
                .map_err(|e| Error::Transport(anyhow::anyhow!("stat {}: {e}", p.display())))?;
            if meta.is_file() {
                let basename = p
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file.bin".to_string());
                let name = first_display_override.unwrap_or(basename);
                (p.clone(), None, None, name)
            } else if meta.is_dir() {
                let (zip_file, disp) =
                    bitmule_client_native::container::build_zip_bundle(&entry_paths)
                        .await
                        .map_err(Error::Transport)?;
                let path = zip_file.path().to_path_buf();
                let name = first_display_override.unwrap_or(disp);
                (path, Some(zip_file), Some("zip-store".to_string()), name)
            } else {
                return Err(Error::NotAFileOrDir(p.clone()));
            }
        } else {
            let (zip_file, disp) =
                bitmule_client_native::container::build_zip_bundle(&entry_paths)
                    .await
                    .map_err(Error::Transport)?;
            let path = zip_file.path().to_path_buf();
            let name = first_display_override.unwrap_or(disp);
            (path, Some(zip_file), Some("zip-store".to_string()), name)
        };

        let total_bytes = tokio::fs::metadata(&send_path)
            .await
            .map_err(|e| Error::Transport(anyhow::anyhow!("stat {}: {e}", send_path.display())))?
            .len();

        // Mint keys + compute URL commitment (SHA-256 folded with bulk key).
        let share_key = ShareKey::random();
        let bulk_key = BulkKey::random();
        let session_hex = share_key.session_id_hex();
        let signature = commit_file(&send_path, &bulk_key).await.map_err(Error::Transport)?;
        let link = ShareLink::new(share_key.clone(), signature);
        let server = (*self.client.server).clone();
        let share_url = format!("{}/#{}", server.trim_end_matches('/'), link.to_b64_url());

        let mode = self.mode;
        let multi = self.multi;
        let on_progress = self.progress.unwrap_or_else(|| Box::new(|_, _| {}));
        // Progress boxes need FnMut+Send. tokio::spawn takes an owned future,
        // capture the box directly.
        let server_owned = server;
        let container_owned = container.clone();
        let handle = tokio::spawn(async move {
            let _zip_guard = zip_guard; // hold NamedTempFile alive for the transfer
            let container_ref = container_owned.as_deref();
            match (multi, mode) {
                (_, TransportMode::Relay) => {
                    send_file_relay(
                        &server_owned,
                        share_key,
                        bulk_key,
                        &send_path,
                        container_ref,
                        on_progress,
                    )
                    .await
                }
                (false, TransportMode::Webrtc) => {
                    send_file_multi(
                        &server_owned,
                        share_key,
                        bulk_key,
                        send_path,
                        container_owned,
                        ServeMode::Complete,
                    )
                    .await
                }
                (true, TransportMode::Webrtc) => {
                    send_file_multi(
                        &server_owned,
                        share_key,
                        bulk_key,
                        send_path,
                        container_owned,
                        ServeMode::Multi,
                    )
                    .await
                }
                (_, TransportMode::Auto) => {
                    // Try WebRTC with a bounded budget; on timeout or
                    // error, reconnect via relay. Same shape as the
                    // main.rs Auto arm — the lib API is used by the
                    // Qt6 / GTK4 UIs which need identical semantics.
                    // Kenna 2026-09-13.
                    let serve = if multi { ServeMode::Multi } else { ServeMode::Complete };
                    let sk_relay = share_key.clone();
                    let bulk_relay = bulk_key.clone();
                    let webrtc_attempt = tokio::time::timeout(
                        bitmule_client_native::AUTO_WEBRTC_BUDGET,
                        send_file_multi(&server_owned, share_key, bulk_key, send_path.clone(), container_owned.clone(), serve),
                    ).await;
                    match webrtc_attempt {
                        Ok(Ok(())) => Ok(()),
                        _ => {
                            eprintln!(
                                "auto send: WebRTC leg didn't complete within {}s, falling back to relay",
                                bitmule_client_native::AUTO_WEBRTC_BUDGET.as_secs()
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            send_file_relay(&server_owned, sk_relay, bulk_relay, &send_path, container_ref, on_progress).await
                        }
                    }
                }
            }
        });

        Ok(SendHandle {
            share_url,
            session_hex,
            display_name,
            total_bytes,
            task: handle,
        })
    }
}


/// Stream `path` through SHA-256 folding the bulk key in, produce the
/// 32-byte URL commitment. Reads in 64 KiB chunks — the file is not
/// held in memory. Mirrors the `commit_file` helper in `main.rs`.
async fn commit_file(path: &Path, bulk_key: &BulkKey) -> anyhow::Result<[u8; 32]> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;

    commit_reader(&mut f, bulk_key).await
}

/// In-flight (or completed) send. Share URL is available immediately;
/// `wait` resolves when the receiver finishes (or, in multi mode, when
/// the caller drops the future).
pub struct SendHandle {
    share_url: String,
    session_hex: String,
    display_name: String,
    total_bytes: u64,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl SendHandle {
    pub fn share_url(&self) -> &str {
        &self.share_url
    }
    pub fn session_hex(&self) -> &str {
        &self.session_hex
    }
    /// What the receiver will see as the top-level filename (single
    /// file's basename, `send_with_name` override, or bundle display
    /// name for multi/directory sends).
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Plaintext byte count. Progress callbacks use the same unit.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    pub async fn wait(self) -> Result<()> {
        self.task
            .await
            .map_err(|e| Error::Transport(anyhow::anyhow!("send task panicked: {e}")))?
            .map_err(Error::Transport)
    }
}

// -----------------------------------------------------------------------
// Recv
// -----------------------------------------------------------------------

pub struct RecvBuilder {
    client: Client,
    share_url: String,
    dest: PathBuf,
    mode: TransportMode,
    progress: Option<Box<dyn FnMut(u64, u64, &str) + Send>>,
}

impl RecvBuilder {
    /// Override the destination directory. Defaults to the current
    /// working directory.
    pub fn dest(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dest = dir.into();
        self
    }

    pub fn mode(mut self, m: TransportMode) -> Self {
        self.mode = m;
        self
    }

    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64, &str) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Connect, receive, verify signature, and land the file(s) under
    /// `dest`. Returns a [`RecvOutcome`] that enumerates each landed
    /// file.
    pub async fn start(self) -> Result<RecvOutcome> {
        // Parse the share URL. Two accepted forms:
        //   1. Full ShareLink b64 (86 chars in the fragment) — real
        //      URL commitment, signature will be verified post-transfer.
        //   2. Legacy 64-char hex share_key — receiver-initiated flow,
        //      no signature.
        let frag = extract_link_fragment(&self.share_url)
            .ok_or_else(|| Error::BadShareUrl(self.share_url.clone()))?;
        let (share_key, expected_signature) = if let Ok(link) = ShareLink::from_b64_url(&frag) {
            (link.share_key, Some(link.signature))
        } else if frag.len() == 64 && frag.chars().all(|c| c.is_ascii_hexdigit()) {
            let key = ShareKey::from_hex(&frag)
                .map_err(|e| Error::Transport(anyhow::anyhow!("bad share_key hex: {e}")))?;
            (key, None)
        } else {
            return Err(Error::BadShareUrl(format!(
                "fragment {frag:?} is neither an 86-char ShareLink nor a 64-char share_key"
            )));
        };

        // Prefer the server explicitly baked into the share URL (so
        // the receiver doesn't need to match `.server()` at
        // construction) — but fall back to the client's own if the
        // URL is fragment-only.
        let inferred_server = extract_server_from_url(&self.share_url);
        let server = inferred_server.unwrap_or_else(|| (*self.client.server).clone());

        let mode = self.mode;
        let dest = self.dest.clone();
        // recv_file expects `FnMut(u64, u64, &str)`. Default no-op if
        // the caller didn't set one.
        let on_progress = self.progress.unwrap_or_else(|| Box::new(|_, _, _| {}));
        let outcome = recv_file(&server, share_key, expected_signature, &dest, mode, on_progress)
            .await
            .map_err(Error::Transport)?;

        // Container-aware landing. `zip-store` → unpack into a
        // sibling dir and enumerate; anything else (or none) → the
        // single downloaded path is the ReceivedFile.
        let mut files = Vec::new();
        match outcome.container.as_deref() {
            Some("zip-store") => {
                let unpack_dir = bitmule_client_native::container::unpack_dir_for(&outcome.path);
                match bitmule_client_native::container::unpack_zip_store(
                    &outcome.path,
                    &unpack_dir,
                )
                .await
                {
                    Ok(_) => {
                        // Zip served its purpose; delete best-effort.
                        let _ = tokio::fs::remove_file(&outcome.path).await;
                        collect_files_recursive(&unpack_dir, &mut files)
                            .await
                            .map_err(Error::Io)?;
                    }
                    Err(e) => {
                        // Fall back to shipping the raw zip as one file.
                        eprintln!(
                            "warning: zip-store unpack failed: {e:#} — leaving as one file"
                        );
                        let size = tokio::fs::metadata(&outcome.path).await.map(|m| m.len()).unwrap_or(0);
                        let name = outcome
                            .path
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "file.bin".to_string());
                        files.push(ReceivedFile { name, path: outcome.path.clone(), size });
                    }
                }
            }
            Some(other) => {
                // Unknown container; emit a warn but ship the raw file.
                eprintln!(
                    "warning: sender flagged container={other:?} — leaving file as-is"
                );
                let size = tokio::fs::metadata(&outcome.path).await.map(|m| m.len()).unwrap_or(0);
                let name = outcome
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file.bin".to_string());
                files.push(ReceivedFile { name, path: outcome.path.clone(), size });
            }
            None => {
                let size = tokio::fs::metadata(&outcome.path).await.map(|m| m.len()).unwrap_or(0);
                let name = outcome
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file.bin".to_string());
                files.push(ReceivedFile { name, path: outcome.path.clone(), size });
            }
        }

        Ok(RecvOutcome { files, dest })
    }
}

/// Extract the URL fragment from a share URL, or accept a bare
/// fragment directly. Mirrors main.rs::extract_link_fragment.
fn extract_link_fragment(input: &str) -> Option<String> {
    let s = input.trim();
    let candidate = if s.starts_with("http://") || s.starts_with("https://") {
        s.rsplit('#').next().unwrap_or(s).to_string()
    } else {
        s.to_string()
    };
    let trimmed = candidate.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract `scheme://host[:port]` origin from a share URL, if the
/// input is a full URL. Returns None on bare fragments.
fn extract_server_from_url(input: &str) -> Option<String> {
    let s = input.trim();
    let (scheme, rest) = if let Some(r) = s.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = s.strip_prefix("https://") {
        ("https", r)
    } else {
        return None;
    };
    let end = rest.find(|c: char| c == '/' || c == '#').unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        None
    } else {
        Some(format!("{scheme}://{authority}"))
    }
}

/// Walk `dir` recursively, appending every regular file as a
/// [`ReceivedFile`] to `out`. Preserves the on-disk layout the
/// unzip step produced.
fn collect_files_recursive<'a>(
    dir: &'a Path,
    out: &'a mut Vec<ReceivedFile>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut rd = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let path = entry.path();
            let meta = entry.metadata().await?;
            if meta.is_dir() {
                collect_files_recursive(&path, out).await?;
            } else if meta.is_file() {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file.bin".to_string());
                out.push(ReceivedFile { name, path, size: meta.len() });
            }
        }
        Ok(())
    })
}

/// One received file's on-disk landing. `.read()` / `.read_all().await`
/// stream the bytes from disk lazily — the transport has already
/// written the file, this is just the reader convenience.
pub struct ReceivedFile {
    name: String,
    path: PathBuf,
    size: u64,
}

impl ReceivedFile {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    /// Absolute on-disk path — useful when the caller wants to hand
    /// the file to another tool without re-reading through this
    /// library.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open the file for streaming. Returns a boxed async reader so
    /// callers don't have to name the concrete `tokio::fs::File`.
    pub async fn read(&self) -> Result<Box<dyn AsyncRead + Send + Unpin>> {
        let f = tokio::fs::File::open(&self.path).await?;
        Ok(Box::new(f))
    }

    /// Slurp the whole file. Convenience for callers that don't want
    /// to write the streaming loop themselves.
    pub async fn read_all(&self) -> Result<Vec<u8>> {
        Ok(tokio::fs::read(&self.path).await?)
    }
}

/// What a completed recv landed on disk. Iterate via [`RecvOutcome::files`].
pub struct RecvOutcome {
    files: Vec<ReceivedFile>,
    dest: PathBuf,
}

impl RecvOutcome {
    /// Iterate the received files in the order the sender bundled
    /// them. Borrowed so callers can call `.read()` / `.read_all()`
    /// per file without moving the outcome.
    pub fn files(&self) -> impl Iterator<Item = &ReceivedFile> {
        self.files.iter()
    }

    /// The directory the receiver wrote into.
    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// Total files landed. Handy when the caller just wants a count
    /// without walking the iterator.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

// -----------------------------------------------------------------------
// Escape hatch
// -----------------------------------------------------------------------

/// Advanced: direct access to the underlying transport crate. Import
/// from here for `LiveSession`, hand-rolled crypto keys, or the
/// commitment hasher. Anything under [`internals`] may move.
pub mod internals {
    pub use bitmule_client_native as native;
}

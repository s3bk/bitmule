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

use bitmule_client_native as native;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncRead;

pub use native::TransportMode;

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
        // TODO(kenna 2026-09-11): plumb `prepare_and_spawn_send` (in
        // `bitmule/src/main.rs`) up into this crate's lib module and
        // delegate here. The zip bundle already handles multi-file /
        // directory sends; `send_with_name`'s display_name lands in
        // the meta frame's `name` field. The interim error keeps the
        // API shape reviewable before we do the surgery.
        let _ = (self.client, self.entries, self.mode, self.multi, self.progress);
        Err(Error::Transport(anyhow::anyhow!(
            "SendBuilder::start not yet wired to bitmule-client-native (draft)"
        )))
    }
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
        // TODO(kenna 2026-09-11): parse the share URL into a
        // `ShareKey` + expected commitment (see `main.rs::cmd_recv`
        // for the fragment shape), then delegate to
        // `native::recv_file(server, share_key, Some(sig), &dest, mode, on_progress)`.
        // For zip-store bundles unpack in place and enumerate the
        // extracted entries; for single files emit one ReceivedFile.
        let _ = (self.client, self.share_url, self.dest, self.mode, self.progress);
        Err(Error::Transport(anyhow::anyhow!(
            "RecvBuilder::start not yet wired to bitmule-client-native (draft)"
        )))
    }
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

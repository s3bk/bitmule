//! Bitmule — resumable, E2E-encrypted, WebRTC-first file transfer.
//!
//! Library surface of the `bitmule` crate (crate also ships a CLI in
//! `src/main.rs`; both compile from this same `bitmule` package so
//! `cargo add bitmule` gives embedders the types below and
//! `cargo install bitmule` still gets the CLI).
//!
//! # Design
//!
//! One [`Client`] carries the signaling/relay server URL and any
//! long-lived state (identity, HTTP client reuse). Per-transfer options
//! come off fluent builders returned from [`Client::send`] and
//! [`Client::recv`]. A send returns a [`SendHandle`] up front — the
//! caller can hand out `handle.share_url()` before the receiver ever
//! connects; `handle.wait().await` blocks until the transfer completes.
//!
//! Under the hood, the library wraps `bitmule-client-native`'s
//! [`send_file_multi`] / [`send_file_relay`] / [`recv_file`] one-shots
//! plus commitment hashing so the receiver can verify the URL
//! signature. Nothing here touches CLI concerns (stdout, QR rendering,
//! `--server` flag parsing) — that stays in `main.rs`.
//!
//! # Quick send
//!
//! ```no_run
//! # use std::path::Path;
//! # async fn demo() -> bitmule::Result<()> {
//! let client = bitmule::Client::new("https://bitmule.qdat.net");
//! let handle = client
//!     .send(Path::new("./photo.png"))
//!     .start()
//!     .await?;
//! println!("share this URL: {}", handle.share_url());
//! handle.wait().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Quick recv
//!
//! ```no_run
//! # async fn demo() -> bitmule::Result<()> {
//! let client = bitmule::Client::new("https://bitmule.qdat.net");
//! let outcome = client
//!     .recv("https://bitmule.qdat.net/#abcdef...", "./downloads/")
//!     .start()
//!     .await?;
//! println!("wrote {} ({} bytes)", outcome.path.display(), outcome.size);
//! # Ok(())
//! # }
//! ```
//!
//! # Progress
//!
//! Both builders accept an `on_progress` callback. Called from the
//! transport task on chunk-completion boundaries; must be cheap and
//! non-blocking (spawn a task from inside if you need to do real work).
//! Progress bytes are plaintext — same denominator on both sides.
//!
//! # What isn't here yet
//!
//! - Identity/contacts API (currently `src/identity.rs`, CLI-only).
//!   Migrate `Identity`, `Contact`, and the share-link/QR helpers up
//!   to `pub use` here once the shape settles.
//! - Streaming send from an `AsyncRead` (today the transport wants a
//!   `Path`). Needed for the synthline-agent hand-off where the file
//!   lives in a SQLite BLOB, not on disk.
//! - Structured error variants — right now the transport crate returns
//!   `anyhow::Error`; [`Error::Transport`] wraps it verbatim.

use bitmule_client_native as native;
use std::fmt;
use std::path::{Path, PathBuf};

pub use native::{RecvComplete, TransportMode};

// -----------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------

pub type Result<T> = std::result::Result<T, Error>;

/// Client-facing error. Grows structured variants as internal errors
/// stabilize; today most transport failures land in `Transport`.
#[derive(Debug)]
pub enum Error {
    /// No paths given to `send`.
    EmptySend,
    /// The URL passed to `recv` couldn't be parsed as a bitmule share
    /// link (`https://host/#<hex>` or a bare fragment).
    BadShareUrl(String),
    /// A source path is neither a regular file nor a directory.
    NotAFileOrDir(PathBuf),
    /// Wrapping the underlying transport / crypto crate's errors.
    Transport(anyhow::Error),
    /// Filesystem I/O.
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

/// Long-lived handle to a bitmule server. Cheap to clone; internal
/// state is `Arc`d as it grows (currently just the server URL string).
#[derive(Clone)]
pub struct Client {
    server: String,
}

impl Client {
    /// Shorthand for [`Client::builder`]`.server(url).build()`.
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
        }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder { server: None }
    }

    /// Signaling+relay server URL this client was built with.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Send a single file. Chain builder methods and call
    /// [`SendBuilder::start`] to kick it off.
    pub fn send(&self, path: impl Into<PathBuf>) -> SendBuilder<'_> {
        SendBuilder::new(self, vec![path.into()])
    }

    /// Send multiple files or a directory — the sender bundles them
    /// into a store-mode zip on the fly and flags the meta so the
    /// receiver unpacks. A single-file `paths` behaves like
    /// [`Client::send`].
    pub fn send_paths(&self, paths: Vec<PathBuf>) -> SendBuilder<'_> {
        SendBuilder::new(self, paths)
    }

    /// Receive a file/bundle from `share_url` into `out_dir`. Accepts
    /// full `https://host/#<hex>` share URLs or a bare fragment
    /// (`<hex>` — the caller has already stripped the origin).
    pub fn recv(&self, share_url: impl Into<String>, out_dir: impl Into<PathBuf>) -> RecvBuilder<'_> {
        RecvBuilder {
            client: self,
            share_url: share_url.into(),
            out_dir: out_dir.into(),
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
        Client {
            server: self
                .server
                .unwrap_or_else(|| "https://bitmule.qdat.net".to_string()),
        }
    }
}

// -----------------------------------------------------------------------
// Send
// -----------------------------------------------------------------------

/// Fluent send configuration. Consumed by [`SendBuilder::start`].
pub struct SendBuilder<'a> {
    client: &'a Client,
    paths: Vec<PathBuf>,
    mode: TransportMode,
    multi: bool,
    container: Option<String>,
    progress: Option<Box<dyn FnMut(u64, u64) + Send>>,
}

impl<'a> SendBuilder<'a> {
    fn new(client: &'a Client, paths: Vec<PathBuf>) -> Self {
        Self {
            client,
            paths,
            mode: TransportMode::Webrtc,
            multi: false,
            container: None,
            progress: None,
        }
    }

    /// Force a specific transport. Defaults to WebRTC.
    pub fn mode(mut self, m: TransportMode) -> Self {
        self.mode = m;
        self
    }

    /// Keep the sender live and hand the same URL to any number of
    /// receivers over time. Combines with [`SendBuilder::mode`].
    pub fn multi(mut self, on: bool) -> Self {
        self.multi = on;
        self
    }

    /// Advisory MIME/container hint that flows through the meta frame
    /// (e.g. `"zip-store"` for auto-bundled directories). Callers
    /// almost never need to set this — the bundler picks it.
    pub fn container(mut self, name: impl Into<String>) -> Self {
        self.container = Some(name.into());
        self
    }

    /// Progress callback: `(bytes_sent, total_bytes)`. Fired from the
    /// transport task on chunk boundaries; keep it cheap.
    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Prepare the session (mint keys, hash the file, spawn the
    /// transport task) and return a [`SendHandle`]. `handle.share_url()`
    /// is immediately valid; the transfer runs in the background until
    /// `handle.wait().await`.
    pub async fn start(self) -> Result<SendHandle> {
        // TODO(kenna 2026-09-11): plumb `prepare_and_spawn_send` out of
        // `main.rs` into this crate's lib.rs and delegate here. The
        // existing function already returns everything a `SendHandle`
        // needs (`session_hex`, `share_url`, `file_name`, `file_size`,
        // `handle`); it just lives on the binary side today.
        //
        // Interim: this shape compiles and documents the intended API.
        let _ = (self.client, self.paths, self.mode, self.multi, self.container, self.progress);
        Err(Error::Transport(anyhow::anyhow!(
            "SendBuilder::start not yet wired to bitmule-client-native (draft)"
        )))
    }
}

/// In-flight (or completed) send. The share URL is available before
/// the receiver connects; `wait` resolves when the transfer's over.
pub struct SendHandle {
    share_url: String,
    session_hex: String,
    file_name: String,
    file_size: u64,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl SendHandle {
    /// Full share URL (`<server>/#<fragment>`). Safe to log or QR-encode.
    pub fn share_url(&self) -> &str {
        &self.share_url
    }

    /// 64-char hex session id — useful for logs and matching against
    /// the signaling server's session table.
    pub fn session_hex(&self) -> &str {
        &self.session_hex
    }

    /// The name the receiver will see. For directories/multi-file
    /// sends this is the zip bundle's display name.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Plaintext size in bytes. Progress callbacks are in the same
    /// unit — this is the denominator.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Await transfer completion. Single-peer transports resolve after
    /// the first receiver finishes; multi mode resolves when the
    /// caller cancels the returned future (via drop or an outer
    /// `select!`).
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

pub struct RecvBuilder<'a> {
    client: &'a Client,
    share_url: String,
    out_dir: PathBuf,
    mode: TransportMode,
    progress: Option<Box<dyn FnMut(u64, u64, &str) + Send>>,
}

impl<'a> RecvBuilder<'a> {
    pub fn mode(mut self, m: TransportMode) -> Self {
        self.mode = m;
        self
    }

    /// Progress callback: `(bytes_received, total_bytes, filename)`.
    /// `filename` is the sender-declared name; for zip-store bundles
    /// it's the bundle display name, not the individual entry.
    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64, &str) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Connect, receive, and write into `out_dir`. Resolves when the
    /// file (or bundle) is fully on disk and the URL signature has
    /// been verified. Returns the concrete on-disk path + plaintext
    /// size.
    pub async fn start(self) -> Result<RecvComplete> {
        // TODO(kenna 2026-09-11): parse `share_url` into a `ShareKey`
        // + expected signature (see `bitmule/src/main.rs::cmd_recv`
        // for the URL/fragment parsing shape), then delegate to
        // `native::recv_file(server, share_key, Some(sig), &out_dir, mode, on_progress)`.
        let _ = (self.client, self.share_url, self.out_dir, self.mode, self.progress);
        Err(Error::Transport(anyhow::anyhow!(
            "RecvBuilder::start not yet wired to bitmule-client-native (draft)"
        )))
    }
}

// -----------------------------------------------------------------------
// Convenience free functions
// -----------------------------------------------------------------------

/// One-liner send for callers who don't want to hold on to a
/// [`Client`]. Equivalent to
/// `Client::new(server).send(path).mode(mode).start().await`.
pub async fn send(
    server: impl Into<String>,
    path: impl Into<PathBuf>,
    mode: TransportMode,
) -> Result<SendHandle> {
    Client::new(server).send(path).mode(mode).start().await
}

/// One-liner receive for callers who don't want to hold on to a
/// [`Client`]. Equivalent to
/// `Client::new(server).recv(url, out_dir).mode(mode).start().await`.
pub async fn recv(
    server: impl Into<String>,
    share_url: impl Into<String>,
    out_dir: impl Into<PathBuf>,
    mode: TransportMode,
) -> Result<RecvComplete> {
    Client::new(server)
        .recv(share_url, out_dir)
        .mode(mode)
        .start()
        .await
}

// -----------------------------------------------------------------------
// Re-exports for advanced users
// -----------------------------------------------------------------------

/// Escape hatch: the underlying transport crate. Import from here if
/// you need `LiveSession`, hand-rolled crypto keys, or the pre-flight
/// commitment hasher. The `bitmule` crate's stable surface is the
/// types above; anything under [`native`] may move.
pub mod internals {
    pub use bitmule_client_native as native;
}

// -----------------------------------------------------------------------
// Path helpers — small enough to keep here rather than adding a util
// module for two functions.
// -----------------------------------------------------------------------

/// Best-effort file-name display string from a path. Used by
/// [`SendHandle::file_name`] when the send is a single file.
fn _display_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string())
}

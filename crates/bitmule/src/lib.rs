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
//! # Send a stream
//!
//! Data that is made while it is sent (a pipe, a database BLOB, a
//! generator) has no size or hash up front. [`Client::send_reader`] and
//! [`Client::send_stream`] upload it as it is read and send the manifest and
//! checksum after the data; the receiver checks it then. This goes over the
//! relay, and the share link carries no signature.
//!
//! ```no_run
//! # #[tokio::main] async fn main() -> bitmule::Result<()> {
//! use bitmule::{Client, StreamSource};
//!
//! let client = Client::new("https://bitmule.qdat.net");
//! // can only be read once: kept in a temporary file for the repair passes
//! let handle = client.send_reader("log.txt", tokio::io::stdin()).start().await?;
//! // or something that can be opened again, which needs no copy
//! let _ = client.send_stream("big.bin", StreamSource::restartable(|| async {
//!     Ok(Box::new(tokio::fs::File::open("big.bin").await?) as bitmule::StreamReader)
//! }));
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
//! - Structured error variants — [`Error::Transport`] wraps
//!   `anyhow::Error` verbatim.

use bitmule_client_common::transfer::{Storage, TransferBuilder};
use bitmule_client_native::crypto::ShareLink;
use bitmule_client_native::{self as native};
use bitmule_core::protocol::websocket::TransferType;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncRead;
use v2::{Options, SendEvent, Server, StreamInfo};

pub use native::TransportMode;
pub use v2::{Reader as StreamReader, StreamSource};
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

    /// Like [`Client::send`], saved by the receiver under `name`.
    pub fn send_with_name(&self, path: impl Into<PathBuf>, name: impl Into<String>) -> SendBuilder {
        SendBuilder::new(self.clone()).send_with_name(path, name)
    }

    /// Send data that is produced while it is sent (a pipe, a growing
    /// file, a generator), so its size and hash are not known up front.
    /// The receiver gets it under `name`, and the transfer goes over the
    /// relay. `source` must be [`StreamSource::restartable`] (it is opened
    /// again for each repair pass), or [`StreamSource::one_shot`], which is
    /// kept in a temporary file for them. The share link has no signature:
    /// the checksum follows the data, and the receiver checks against it.
    pub fn send_stream(&self, name: impl Into<String>, source: StreamSource) -> StreamSendBuilder {
        StreamSendBuilder { client: self.clone(), name: name.into(), source, size_hint: None, progress: None }
    }

    /// [`Client::send_stream`] for a reader that can only be read once.
    pub fn send_reader(&self, name: impl Into<String>, reader: impl AsyncRead + Send + Unpin + 'static) -> StreamSendBuilder {
        self.send_stream(name, StreamSource::one_shot(reader))
    }

    /// Fluent recv from a share URL. Defaults `dest` to the current
    /// working directory until [`RecvBuilder::dest`] overrides.
    pub fn recv(&self, share_url: impl Into<String>) -> RecvBuilder {
        RecvBuilder {
            client: self.clone(),
            share_url: share_url.into(),
            dest: PathBuf::from("."),
            mode: TransportMode::Auto,
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
    progress: Option<Box<dyn FnMut(u64, u64) + Send>>,
}

impl SendBuilder {
    fn new(client: Client) -> Self {
        Self {
            client,
            entries: Vec::new(),
            mode: TransportMode::Auto,
            progress: None,
        }
    }

    /// Append a file or directory to the send. Multiple `.send(...)`
    /// calls accumulate. A single file is sent as it is; several
    /// paths, or a directory, go as one zip the receiver unpacks.
    pub fn send(mut self, path: impl Into<PathBuf>) -> Self {
        self.entries.push(SendEntry {
            path: path.into(),
            display_name: None,
        });
        self
    }

    /// Append a path under another name: what the receiver saves a file
    /// as, or the top-level folder of a directory inside the zip. Same
    /// accumulator as [`SendBuilder::send`].
    pub fn send_with_name(mut self, path: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        self.entries.push(SendEntry {
            path: path.into(),
            display_name: Some(name.into()),
        });
        self
    }

    /// Which transports to use. Defaults to [`TransportMode::Auto`]: a
    /// WebRTC data channel when one can be made, the relay otherwise (and
    /// both at once at the start, so a slow handshake costs no time).
    pub fn mode(mut self, m: TransportMode) -> Self {
        self.mode = m;
        self
    }

    /// Kept for compatibility, does nothing: a v2 send serves every
    /// receiver that joins and ends once the receivers that connected are
    /// done.
    pub fn multi(self, _on: bool) -> Self {
        self
    }

    /// Progress callback: `(bytes_received, total_bytes)`, as the
    /// receiver reports it (relay and data channel counted together).
    /// With several receivers it is whichever reported last.
    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Hash the file(s), open the session, spawn the transport task, and
    /// return a [`SendHandle`] carrying the share URL.
    pub async fn start(self) -> Result<SendHandle> {
        if self.entries.is_empty() {
            return Err(Error::EmptySend);
        }

        let mut builder = TransferBuilder::new();
        let mut files = 0usize;
        let mut zip = self.entries.len() > 1;
        for entry in &self.entries {
            let meta = tokio::fs::metadata(&entry.path)
                .await
                .map_err(|e| Error::Transport(anyhow::anyhow!("stat {}: {e}", entry.path.display())))?;
            if meta.is_file() {
                let name = entry.display_name.clone().map(PathBuf::from).or_else(|| entry.path.file_name().map(PathBuf::from));
                builder.add_file(Storage::File(entry.path.clone()), name);
                files += 1;
            } else if meta.is_dir() {
                // the directory's name is the first component of every entry
                zip = true;
                let top = entry
                    .display_name
                    .clone()
                    .or_else(|| entry.path.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .unwrap_or_else(|| "files".to_string());
                let mut inside = Vec::new();
                collect_paths(&entry.path, Path::new(""), &mut inside).await?;
                for (path, relative) in inside {
                    builder.add_file(Storage::File(path), Some(Path::new(&top).join(relative)));
                    files += 1;
                }
            } else {
                return Err(Error::NotAFileOrDir(entry.path.clone()));
            }
        }
        if files == 0 {
            return Err(Error::Transport(anyhow::anyhow!("nothing to send: no files in the given paths")));
        }
        if zip {
            builder.force_multi_file_zip();
        }
        // hashes the data for the link's signature
        let (manifest, transfer) = builder.commit_async().await.map_err(Error::Transport)?;
        let display_name = manifest.file_name().unwrap_or_default();
        let total_bytes = manifest.transfer_size;

        let server = Server::parse(&self.client.server);
        let options = Options::from_mode(self.mode);
        let progress = Mutex::new(self.progress);
        let on_event: v2::OnSendEvent = Arc::new(move |event| {
            if let SendEvent::Progress { bytes, total, .. } = event {
                if let Some(callback) = progress.lock().unwrap().as_mut() {
                    callback(bytes, total);
                }
            }
        });

        let (link_tx, link_rx) = tokio::sync::oneshot::channel::<(String, String)>();
        let mut task = tokio::spawn(async move {
            let mut link_tx = Some(link_tx);
            let for_url = server.clone();
            v2::run_send_events(&server, manifest, transfer, options, move |link| {
                if let Some(tx) = link_tx.take() {
                    let _ = tx.send((for_url.share_url(link), link.share_key.session_id_hex()));
                }
            }, on_event).await
        });
        let (share_url, session_hex) = wait_for_link(link_rx, &mut task).await?;

        Ok(SendHandle {
            share_url,
            session_hex,
            display_name,
            total_bytes,
            task,
        })
    }
}

/// The share URL and session id of a send task, or why it ended before there was one.
async fn wait_for_link(
    link_rx: tokio::sync::oneshot::Receiver<(String, String)>,
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) -> Result<(String, String)> {
    match link_rx.await {
        Ok(v) => Ok(v),
        // the task ended before there was a link: its error is the reason
        Err(_) => Err(match task.await {
            Ok(Err(e)) => Error::Transport(e),
            Ok(Ok(())) => Error::Transport(anyhow::anyhow!("send ended before a share link was made")),
            Err(e) => Error::Transport(anyhow::anyhow!("send task panicked: {e}")),
        }),
    }
}

/// Fluent configuration of a send whose data is read as it goes, see
/// [`Client::send_stream`].
pub struct StreamSendBuilder {
    client: Client,
    name: String,
    source: StreamSource,
    size_hint: Option<u64>,
    progress: Option<Box<dyn FnMut(u64, u64) + Send>>,
}

impl StreamSendBuilder {
    /// The size, if known: only so progress has a total to show. The
    /// transfer does not depend on it.
    pub fn size_hint(mut self, bytes: u64) -> Self {
        self.size_hint = Some(bytes);
        self
    }

    /// Progress callback: `(bytes_received, total_bytes)`. The total is 0
    /// until the data has been read to its end, unless there is a
    /// [`size_hint`](Self::size_hint).
    pub fn on_progress<F>(mut self, f: F) -> Self
    where
        F: FnMut(u64, u64) + Send + 'static,
    {
        self.progress = Some(Box::new(f));
        self
    }

    /// Open the session and start uploading as soon as a receiver joins.
    /// The returned handle's `total_bytes` is the hint, or 0.
    pub async fn start(self) -> Result<SendHandle> {
        let server = Server::parse(&self.client.server);
        // the data is not known up front, so there is nothing for a peer
        // connection to ask for: it goes over the relay
        let options = Options { webrtc: false, relay: true };
        let progress = Mutex::new(self.progress);
        let on_event: v2::OnSendEvent = Arc::new(move |event| {
            if let SendEvent::Progress { bytes, total, .. } = event {
                if let Some(callback) = progress.lock().unwrap().as_mut() {
                    callback(bytes, total);
                }
            }
        });
        let mut info = StreamInfo::file(self.name.clone());
        info.size_hint = self.size_hint;
        let source = self.source;

        let (link_tx, link_rx) = tokio::sync::oneshot::channel::<(String, String)>();
        let mut task = tokio::spawn(async move {
            let mut link_tx = Some(link_tx);
            let for_url = server.clone();
            v2::run_send_stream(&server, info, source, options, move |link| {
                if let Some(tx) = link_tx.take() {
                    let _ = tx.send((for_url.share_url(link), link.share_key.session_id_hex()));
                }
            }, on_event).await
        });
        let (share_url, session_hex) = wait_for_link(link_rx, &mut task).await?;
        Ok(SendHandle {
            share_url,
            session_hex,
            display_name: self.name,
            total_bytes: self.size_hint.unwrap_or(0),
            task,
        })
    }
}

/// Every regular file under `dir`, with its path relative to the starting
/// directory (`relative` is the prefix so far), in a stable order.
fn collect_paths<'a>(
    dir: &'a Path,
    relative: &'a Path,
    out: &'a mut Vec<(PathBuf, PathBuf)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = Vec::new();
        let mut rd = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            entries.push((entry.file_name(), entry.path(), entry.metadata().await?));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, path, meta) in entries {
            let relative = relative.join(&name);
            if meta.is_dir() {
                collect_paths(&path, &relative, out).await?;
            } else if meta.is_file() {
                out.push((path, relative));
            }
        }
        Ok(())
    })
}

/// In-flight (or completed) send. Share URL is available immediately;
/// `wait` resolves once the receivers that connected have finished.
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
    /// file's name, `send_with_name` override, or the zip's name for
    /// multi/directory sends).
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Plaintext byte count (of the zip, for a bundle). Progress
    /// callbacks use the same unit.
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

    /// Connect, receive, verify the signature, and land the file(s) under
    /// `dest`, named as the sender named them (a zip is unpacked into a
    /// folder). Returns a [`RecvOutcome`] that enumerates each landed
    /// file.
    pub async fn start(self) -> Result<RecvOutcome> {
        let frag = extract_link_fragment(&self.share_url)
            .ok_or_else(|| Error::BadShareUrl(self.share_url.clone()))?;
        let link = ShareLink::from_b64_url(&frag)
            .map_err(|_| Error::BadShareUrl(format!("fragment {frag:?} is not a share link")))?;

        // Prefer the server explicitly baked into the share URL (so
        // the receiver doesn't need to match `.server()` at
        // construction) — but fall back to the client's own if the
        // URL is fragment-only.
        let server = Server::parse(&extract_server_from_url(&self.share_url).unwrap_or_else(|| (*self.client.server).clone()));
        let options = Options::from_mode(self.mode);
        let dest = self.dest.clone();
        std::fs::create_dir_all(&dest)?;

        // the file is made once the sender's manifest is in
        let chosen: Arc<Mutex<Option<PathBuf>>> = Arc::default();
        let open = {
            let chosen = chosen.clone();
            let dest = dest.clone();
            move |manifest: &bitmule_core::protocol::websocket::TransferManifest| {
                let name = manifest.file_name().unwrap_or_else(|| "bitmule-download".to_string());
                let path = free_name(&dest, &name);
                let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
                *chosen.lock().unwrap() = Some(path);
                Ok(file)
            }
        };
        let progress = {
            let chosen = chosen.clone();
            let callback = Mutex::new(self.progress);
            move |received: u64, total: u64| {
                if let Some(callback) = callback.lock().unwrap().as_mut() {
                    let name = chosen.lock().unwrap().as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    callback(received, total, &name);
                }
            }
        };
        let report = v2::run_recv_progress(&server, &link, open, progress, options)
            .await
            .map_err(Error::Transport)?;
        let path = chosen
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::Transport(anyhow::anyhow!("no file was written")))?;

        let mut files = Vec::new();
        let mut unpacked = false;
        if matches!(report.manifest.transfer_typ, TransferType::MultiFileZip { .. }) {
            let zip_path = path.clone();
            let into = dest.clone();
            match tokio::task::spawn_blocking(move || unpack_zip(&zip_path, &into)).await {
                Ok(Ok(dir)) => {
                    // the zip served its purpose
                    let _ = tokio::fs::remove_file(&path).await;
                    collect_files_recursive(&dir, &mut files).await.map_err(Error::Io)?;
                    unpacked = true;
                }
                // fall back to handing over the raw zip as one file
                Ok(Err(e)) => eprintln!("warning: unpacking the zip failed: {e:#} — leaving it as one file"),
                Err(e) => eprintln!("warning: unpacking the zip failed: {e} — leaving it as one file"),
            }
        }
        if !unpacked {
            let size = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "file.bin".to_string());
            files.push(ReceivedFile { name, path, size });
        }

        Ok(RecvOutcome { files, dest })
    }
}

/// A file name in `dir` that is not taken yet: `name`, `name (1)`, …
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name, String::new()),
    };
    (1..).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists()).unwrap()
}

/// Unpack `zip_path` (stored, deflated or zstd entries) into a new directory
/// in `into`, named after the zip. Returns that directory.
fn unpack_zip(zip_path: &Path, into: &Path) -> anyhow::Result<PathBuf> {
    let stem = zip_path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "bundle".into());
    let dir = free_name(into, &stem);
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip_path)?)?;
    std::fs::create_dir_all(&dir)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // `enclosed_name` refuses paths that would leave `dir`
        let Some(relative) = entry.enclosed_name() else { continue };
        let target = dir.join(relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(up) = target.parent() {
            std::fs::create_dir_all(up)?;
        }
        std::io::copy(&mut entry, &mut std::fs::File::create(&target)?)?;
    }
    Ok(dir)
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

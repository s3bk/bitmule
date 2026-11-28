use c_str_macro::c_str;
use bitmule_client_common::video;
use qmetaobject::*;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

mod account;
mod keyring;

/// The origins a share link can name: the short host a sender is handed
/// (`https://mul.li#<code>`, no path) and the long host the app itself is
/// served from. Matching ignores case, because a symbol draws the link
/// upper-case (`HTTPS://MUL.LI#…`).
/// It is the *host* that decides, not the spelling: a link pasted from an
/// older build carries a slash before the `#` (`https://mul.li/#<code>`) and
/// is the same link.
fn is_bitmule_link(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    let Some((_, rest)) = lower.split_once("://") else { return false };
    let host = rest.split(['/', '#', '?']).next().unwrap_or("");
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host == "mul.li" || host == "bitmule.net" || host.ends_with(".bitmule.net") {
        return true;
    }
    // The port is not part of a host's name: a link may carry one
    // (`http://127.0.0.1:8080/#…`), and so may the list below.
    let name = host_port(host).0;
    // A share link may name a server of its own, and the e2e suite keeps one on
    // loopback: `BITMULE_QT_HOSTS` lists the extra hosts something else has
    // vouched for. Unset in the app, so a URL the clipboard happens to carry is
    // still judged by its host alone.
    extra_hosts().iter().any(|h| h == name || h == host)
}

/// `host:port` → (`host`, Some(port)); a bare host keeps its name. Only a
/// numeric suffix counts as a port, so an IPv6 literal is left alone.
fn host_port(host: &str) -> (&str, Option<&str>) {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (name, Some(port))
        }
        _ => (host, None),
    }
}

/// The hosts named in `BITMULE_QT_HOSTS`, lower-case, read once. Empty unless
/// a test (or an operator pointing the app elsewhere) says otherwise.
fn extra_hosts() -> &'static [String] {
    static HOSTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    HOSTS.get_or_init(|| {
        std::env::var("BITMULE_QT_HOSTS")
            .map(|v| {
                v.split(',')
                    .map(|h| h.trim().trim_start_matches("www.").to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// The server a share is made through. `https://bitmule.net` is what the web
/// app is served from and the host that answers `/pow` and `/ws/create`; the
/// CLI has always taken `--server`, and the app reads the same choice from
/// `BITMULE_SERVER` — a build no longer decides for the user, and the e2e
/// suite can point it at a server of its own.
fn share_server() -> String {
    std::env::var("BITMULE_SERVER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://bitmule.net".to_string())
}

/// Whether a plain-`http` server may be used: the CLI's `--unsafe`, by
/// environment. The bytes are encrypted end to end either way, but over plain
/// `http`/`ws` anyone on the path sees who talks to whom; it exists for a
/// server on loopback (`BITMULE_INSECURE=1`), never for a deployment.
fn allow_insecure() -> bool {
    std::env::var_os("BITMULE_INSECURE").is_some()
}

const OPTIONS_FILE_NAME: &str = "bitmule-qt6-options.json";

/// What one send tells the window while it runs. Every field is optional:
/// an update changes only what it carries.
#[derive(Clone, Default)]
struct SendUpdate {
    /// "preparing" | "live" | "done" | "error" | "stopped"
    status: Option<&'static str>,
    phase: Option<String>,
    progress: Option<f64>,
    size: Option<u64>,
    peers: Option<usize>,
    url: Option<String>,
    error: Option<String>,
}

impl SendUpdate {
    fn status(status: &'static str, phase: impl Into<String>) -> Self {
        SendUpdate { status: Some(status), phase: Some(phase.into()), ..Default::default() }
    }
    fn phase(phase: impl Into<String>) -> Self {
        SendUpdate { phase: Some(phase.into()), ..Default::default() }
    }
    fn progress(fraction: f64) -> Self {
        SendUpdate { progress: Some(fraction), ..Default::default() }
    }
    fn peers(n: usize) -> Self {
        SendUpdate { peers: Some(n), ..Default::default() }
    }
    fn link(url: impl Into<String>) -> Self {
        SendUpdate { status: Some("live"), url: Some(url.into()), ..Default::default() }
    }
    fn failed(error: impl Into<String>) -> Self {
        let error = error.into();
        SendUpdate { status: Some("error"), phase: Some(error.clone()), error: Some(error), ..Default::default() }
    }
}

/// How a send reports: from tokio worker threads, and for the length of the
/// transfer.
type SendReport = std::sync::Arc<dyn Fn(SendUpdate) + Send + Sync>;

/// Prepare a bitmule share from `files` and spawn the send task in the
/// background. Returns the share URL as soon as the session exists (the data
/// is hashed for the link's signature first); the transfer keeps running in
/// a detached tokio task until the receivers that connected are done.
///
/// One file is sent as it is; several files, or a directory, go as a zip the
/// builder makes. v2 has no "keep the link live for more receivers" mode, so
/// the old multi-send option no longer does anything.
///
/// Several shares can run at once: nothing here is shared between calls but
/// the host, so a second one gets its own session and its own link.
///
/// Every stage says so on stderr and through `report`: the window used to
/// show only "Preparing…", and a phase that takes minutes (hashing a big
/// file, zipping a directory, the server's proof of work) has to be
/// distinguishable from a hang.
async fn share(
    files: Vec<PathBuf>,
    report: SendReport,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> Result<Url, String> {
    use bitmule::v2::{self, Options, Server, StreamInfo, StreamSource};
    use bitmule_client_common::transfer::{Storage, Transfer, TransferBuilder};
    use bitmule_core::protocol::websocket::TransferManifest;

    // The host the app shares through: bitmule.net unless `BITMULE_SERVER`
    // says otherwise (see `share_server`).
    let server_url = share_server();

    if files.is_empty() {
        return Err("no file selected".into());
    }

    log(format!("share: {} path(s) selected", files.len()));
    let mut builder = TransferBuilder::new();
    let mut total_bytes = 0u64;
    for path in &files {
        match tokio::fs::metadata(path).await {
            Ok(md) if md.is_file() => {
                log(format!("  file {} ({} bytes)", path.display(), md.len()));
                total_bytes += md.len();
                builder.add_file(Storage::File(path.clone()), path.file_name().map(PathBuf::from));
            }
            Ok(md) if md.is_dir() => {
                // the directory's name stays the first component of every entry
                let base = path.parent().unwrap_or(Path::new("")).to_path_buf();
                let (mut entries, mut bytes) = (0u64, 0u64);
                for entry in walkdir::WalkDir::new(path).sort_by_file_name().into_iter().flatten() {
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    if let Ok(md) = entry.metadata() {
                        entries += 1;
                        bytes += md.len();
                    }
                    let name = entry.path().strip_prefix(&base).unwrap_or(entry.path()).to_path_buf();
                    builder.add_file(Storage::File(entry.path().to_path_buf()), Some(name));
                }
                log(format!("  dir {} ({entries} files, {bytes} bytes)", path.display()));
                total_bytes += bytes;
            }
            Ok(_) => return Err("not a regular file or directory".into()),
            Err(e) => return Err(format!("stat {}: {e}", path.display())),
        }
    }
    // a lone directory still goes as a zip, even with a single file inside
    let zipped = files.len() > 1 || files.iter().any(|p| p.is_dir());
    if zipped {
        builder.force_multi_file_zip();
    }
    log(format!(
        "share: {} bytes{}",
        total_bytes,
        if zipped { " as a zip" } else { "" }
    ));

    // Two ways to send, and the size decides which. A single big file is
    // streamed: the link is made before a byte is read, the data goes as it is
    // read, and the checksum follows it (validation is after the transfer, so
    // nothing has to be known in advance). That is the difference between a
    // link in a second and a link after three passes over the file — the old
    // path copied it to a temporary file, then hashed it twice for the same
    // answer the receiver computes at the end anyway.
    //
    // Everything else is prepared as before: below a few megabytes the wait is
    // not worth streaming's extra repair passes, and a zip has to be built
    // before any of it can be sent.
    //
    // Streaming is what a big file takes: the link exists before any of the
    // data is hashed, and the receiver checks what arrived against a checksum
    // that follows it. It needs a streaming-aware receiver (the browser viewer
    // and this build's `recv` are), which is why it is chosen only above a few
    // megabytes: below that the prepared path costs nothing and works with
    // every older client.
    const STREAM_ABOVE: u64 = 4 << 20;
    // A big file is streamed, always: the link comes before the data has been
    // read, and nobody waits for a hash they did not ask for. (It was switched
    // off for a while because a stream from this app did not arrive; that was
    // a bug in the streaming path here, and turning the feature off is not a
    // fix. `BITMULE_STREAM=0` remains as a way to force the prepared path.)
    let may_stream = std::env::var_os("BITMULE_STREAM").is_none_or(|v| v != "0");

    enum Job {
        Known(TransferManifest, Transfer),
        Stream(StreamInfo, StreamSource),
    }

    let phase = Phase::start("preparing the data");
    let job = if may_stream && !zipped && total_bytes > STREAM_ABOVE {
        let path = files[0].clone();
        let shown = path.display().to_string();
        log(format!("share: streaming {shown} as it is read, no pre-hash"));
        report(SendUpdate { size: Some(total_bytes), ..SendUpdate::phase("streaming the file as it is read") });
        let info = StreamInfo {
            typ: bitmule_core::protocol::websocket::TransferType::SingleFile { compression: None },
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()),
            size_hint: Some(total_bytes),
        };
        // Opened again for every pass (a repair pass reads the file anew), so
        // a file that changes under the transfer is caught by the block hashes
        // instead of being sent as two different files.
        let source = StreamSource::restartable(move || {
            let path = path.clone();
            Box::pin(async move {
                tokio::fs::File::open(&path).await.map(|f| Box::new(f) as v2::Reader)
            })
        });
        Job::Stream(info, source)
    } else {
        // hashes the data for the link's signature (and builds the zip, if any)
        report(SendUpdate { size: Some(total_bytes), ..SendUpdate::phase("hashing the data for the link signature") });
        phase.set("hashing the data for the link signature");
        match builder.commit_async().await {
            Ok((manifest, transfer)) => {
                log("share: hashed, the data is ready to send");
                Job::Known(manifest, transfer)
            }
            Err(e) => return Err(format!("prepare: {e:#}")),
        }
    };

    let server = Server::parse(&server_url);
    let (link_tx, link_rx) = tokio::sync::oneshot::channel::<String>();
    phase.set(&format!("waiting for {server_url} (proof of work, then the session)"));
    report(SendUpdate::phase(format!("waiting for {server_url} (proof of work, then the session)")));
    tokio::spawn(async move {
        let server_for_url = server.clone();
        let mut link_tx = Some(link_tx);

        // What the receivers say. `peers` counts the ones connected now, and
        // the progress shown is the furthest of them: one sender can be
        // feeding two tabs, and the slower one must not make the bar go back.
        let peers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let per_receiver = std::sync::Arc::new(Mutex::new(std::collections::HashMap::<String, u64>::new()));
        let on_event: v2::OnSendEvent = {
            let report = report.clone();
            let peers = peers.clone();
            let per_receiver = per_receiver.clone();
            std::sync::Arc::new(move |event: v2::SendEvent| match event {
                v2::SendEvent::Connected { .. } => {
                    let n = peers.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    log(format!("share: a receiver is connected ({n} now)"));
                    report(SendUpdate::peers(n));
                }
                v2::SendEvent::Progress { receiver, bytes, total } => {
                    if total == 0 {
                        return;
                    }
                    let best = {
                        let mut m = per_receiver.lock().unwrap();
                        let seen = m.entry(receiver).or_insert(0);
                        if *seen >= bytes {
                            return;
                        }
                        *seen = bytes;
                        m.values().copied().max().unwrap_or(0)
                    };
                    report(SendUpdate::progress((best.min(total)) as f64 / total as f64));
                }
                v2::SendEvent::Done { .. } => {}
            })
        };

        let on_link = {
            let report = report.clone();
            let server_for_url = server_for_url.clone();
            move |link: &bitmule_client_native::crypto::ShareLink| {
                let url = server_for_url.link_url(link);
                report(SendUpdate::link(url.clone()));
                if let Some(tx) = link_tx.take() {
                    let _ = tx.send(url);
                }
            }
        };

        // A share is a link that keeps answering: after a receiver finishes,
        // the session stays up (`keep_open`) instead of closing with it, and
        // the next person to open the link gets the same files — the app's
        // transfer ends on Stop, or by turning the share into a hosted one.
        let options = Options { keep_open: true, ..Options::default() };
        let running = async move {
            match job {
                Job::Known(manifest, transfer) => {
                    v2::run_send_events(&server, manifest, transfer, options, on_link, on_event).await
                }
                Job::Stream(info, source) => {
                    v2::run_send_stream(&server, info, source, options, on_link, on_event).await
                }
            }
        };
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => match result {
                Ok(()) => {
                    report(SendUpdate::status("done", "every receiver has the file"));
                    log("share: send finished, the link stays valid while peers use it");
                }
                Err(e) => {
                    report(SendUpdate::failed(format!("{e:#}")));
                    log(format!("share: send failed: {e:#}"));
                }
            },
            _ = &mut stop => {
                // Dropping `running` closes the session: the link stops
                // answering, and nothing is left in the background.
                report(SendUpdate::status("stopped", "stopped"));
                log("share: stopped");
            }
        }
    });

    // Making the session is the server's answer, before any data moves, so a
    // minute here is generous — and better than the tab waiting forever.
    let outcome = match tokio::time::timeout(Duration::from_secs(60), link_rx).await {
        Ok(Ok(url)) => Url::parse(&url).map_err(|e| format!("bad share URL from the server: {e}")),
        Ok(Err(_)) => Err(format!("couldn't reach {server_url}")),
        Err(_) => Err(format!("{server_url} didn't answer within 60 s")),
    };
    drop(phase);
    match &outcome {
        Ok(url) => log(format!("share: link {url}")),
        Err(e) => log(format!("share: failed: {e}")),
    }
    outcome
}



#[derive(QObject, Default)]
struct UploaderApi {
    base: qt_base_class!(trait QObject),

    // State properties
    is_busy: qt_property!(bool; NOTIFY is_busy_changed),
    share_url: qt_property!(QString; NOTIFY share_url_changed),
    /// Why the last share attempt did not produce a link — empty when it did,
    /// or when nobody has tried yet. QML shows it under the Share button.
    share_error: qt_property!(QString; NOTIFY share_error_changed),
    /// `data:image/svg+xml;base64,...` — bind directly on an Image
    /// source in QML to display the share URL as a scannable QR code.
    /// Empty string when no URL is set.
    qr_data_url: qt_property!(QString; NOTIFY qr_data_url_changed),
    file_list: qt_property!(QStringList; NOTIFY file_list_changed),
    /// A video the next share would convert, as JSON: `{name, size, codec,
    /// duration, seconds, profiles: [{key, label}]}`, or empty. While it is
    /// set, QML shows the conversion dialog and `decide_video` answers it.
    video_offer: qt_property!(QString; NOTIFY video_offer_changed),
    /// What is being converted right now ("converting Shrek.mkv (balanced)…"),
    /// empty when nothing is. The share starts by itself when it is over.
    converting: qt_property!(QString; NOTIFY converting_changed),
    /// Fraction of the conversion, 0..1, from ffmpeg's own progress.
    convert_progress: qt_property!(f64; NOTIFY convert_progress_changed),

    // F00 options (persisted to `<config>/bitmule-qt6-options.json`)
    opt_multi_send: qt_property!(bool; NOTIFY opt_multi_send_changed),
    opt_upnp: qt_property!(bool; NOTIFY opt_upnp_changed),
    opt_clipboard_watch: qt_property!(bool; NOTIFY opt_clipboard_watch_changed),
    opt_auto_download: qt_property!(bool; NOTIFY opt_auto_download_changed),
    /// `"auto"` | `"light"` | `"dark"`. The QML side reads it once on
    /// load and owns the colour table; Rust only persists the choice.
    /// Empty (an options file from before this field existed) reads as
    /// `"auto"`.
    opt_theme: qt_property!(QString; NOTIFY opt_theme_changed),

    // F02 fetch queue: bitmule URLs the clipboard watcher has detected
    // that are NOT this app's own shares. Bind on ListView / repeater.
    fetch_queue: qt_property!(QStringList; NOTIFY fetch_queue_changed),

    // Signals
    is_busy_changed: qt_signal!(),
    share_url_changed: qt_signal!(),
    share_error_changed: qt_signal!(),
    qr_data_url_changed: qt_signal!(),
    file_list_changed: qt_signal!(),
    video_offer_changed: qt_signal!(),
    converting_changed: qt_signal!(),
    convert_progress_changed: qt_signal!(),
    opt_multi_send_changed: qt_signal!(),
    opt_upnp_changed: qt_signal!(),
    opt_clipboard_watch_changed: qt_signal!(),
    opt_auto_download_changed: qt_signal!(),
    opt_theme_changed: qt_signal!(),
    fetch_queue_changed: qt_signal!(),

    // Shared paths state
    paths: Rc<RefCell<Vec<PathBuf>>>,
    /// Snapshot of currently-live share URLs so the clipboard watcher
    /// can suppress own-uploads (avoid queueing a URL we just minted).
    active_share_urls: Arc<Mutex<Vec<String>>>,
    /// Queue of clipboard-detected bitmule URLs.
    fetch_queue_urls: Arc<Mutex<Vec<String>>>,
    /// Internal store for recv transfers. Rendered to `recv_transfers`
    /// as JSON strings on every mutation.
    recv_state: Arc<Mutex<Vec<RecvTransferState>>>,
    /// Every send this window has started, oldest first — the Active tab.
    /// Starting another one does not touch the ones already running: each
    /// is its own relay session with its own link.
    send_state: Arc<Mutex<Vec<SendEntry>>>,
    /// The next id to hand a send. Ids are what QML uses to stop or forget
    /// one; they are not the link (a send has no link yet while it is
    /// preparing).
    send_next_id: Arc<Mutex<u64>>,
    /// One channel per running send: dropping the sender (or sending on it)
    /// is what stops the transfer.
    send_stops: Arc<Mutex<std::collections::HashMap<u64, tokio::sync::oneshot::Sender<()>>>>,
    /// Set while a video conversion should stop: the encoder is killed, the
    /// half-written output removed, and the share starts from the original
    /// bytes. The person asked for it now instead.
    convert_cancel: Arc<AtomicBool>,

    // Invokable methods from QML
    add_files: qt_method!(fn(&mut self, urls: QVariantList)),
    /// Forget one entry of the share list, by its position in it.
    remove_file: qt_method!(fn(&mut self, index: i32)),
    /// Empty the share list.
    clear_files: qt_method!(fn(&mut self)),
    trigger_share: qt_method!(fn(&mut self)),
    /// Answer the video question: `"as-is"` or a profile key (`fast`,
    /// `balanced`, `quality`). Converting and then sharing happen on their own.
    decide_video: qt_method!(fn(&mut self, mode: QString)),
    /// Give up on the conversion and send the file as it is, now: the encoder
    /// is killed and the share starts from the original bytes.
    cancel_conversion: qt_method!(fn(&mut self)),
    /// Copy the current share_url to the system clipboard. QML calls
    /// this from a Copy button; it also fires automatically inside
    /// trigger_share the moment the URL is produced.
    copy_share_url: qt_method!(fn(&mut self) -> bool),
    /// Persist all four opt_* fields to disk. QML calls this from any
    /// onCheckedChanged handler in the options panel.
    save_options: qt_method!(fn(&mut self)),
    /// Open a queued URL in the system browser. First-cut fetch action;
    /// full in-app receiver arrives when the qt6 recv panel lands.
    open_fetch_url: qt_method!(fn(&mut self, url: QString) -> bool),
    /// Remove a URL from the fetch queue after user actions on it.
    drop_fetch_url: qt_method!(fn(&mut self, url: QString)),
    /// Load persisted options + start the clipboard watcher if enabled.
    /// QML should call this from Component.onCompleted so the UI shows
    /// the saved option state on launch.
    init_from_qml: qt_method!(fn(&mut self)),

    // ---- receive side ----
    /// JSON-string list, one per active or completed receive. Each entry:
    /// `{ "url": String, "name": String, "progress": 0..1, "status":
    /// "connecting"|"receiving"|"complete"|"error", "path": String|null,
    /// "error": String|null }`. QML delegate `JSON.parse(modelData)`.
    recv_transfers: qt_property!(QStringList; NOTIFY recv_transfers_changed),
    recv_transfers_changed: qt_signal!(),
    /// Add a bitmule share URL to the receive queue. Kicks off a
    /// background download; per-transfer state lands on `recv_transfers`.
    add_recv_url: qt_method!(fn(&mut self, url: QString)),
    /// Remove a transfer entry from the list (does not delete the file).
    drop_recv_transfer: qt_method!(fn(&mut self, url: QString)),
    /// Open the receiver's out dir in the system file manager.
    open_recv_dir: qt_method!(fn(&mut self)),

    // ---- the Active tab: every send this window has started ----
    /// JSON-string list, one per send, oldest first. Each entry:
    /// `{ "id": u64, "name": String, "size": u64, "progress": 0..1,
    /// "status": "preparing"|"live"|"done"|"error", "phase": String,
    /// "url": String, "peers": usize, "error": String }`. QML delegate
    /// `JSON.parse(modelData)` — the same shape the receive list uses.
    sends: qt_property!(QStringList; NOTIFY sends_changed),
    sends_changed: qt_signal!(),
    /// Stop one send by id: the relay session closes and the link stops
    /// answering. The entry stays in the list, marked stopped.
    stop_send: qt_method!(fn(&mut self, id: QString)),
    /// Forget one entry by id (a send that has finished, failed or been
    /// stopped). A running send is stopped first.
    drop_send: qt_method!(fn(&mut self, id: QString)),
    /// Copy any text (a link out of the Active list) to the clipboard.
    copy_text: qt_method!(fn(&mut self, text: QString) -> bool),
}

impl UploaderApi {
    fn add_files(&mut self, urls: QVariantList) {
        let mut paths = self.paths.borrow_mut();
        let mut list = self.file_list.clone();

        for url_var in urls.into_iter() {
            let url_str = url_var.to_qstring().to_string();
            // Qt hands a drop over as QUrl, whose text form percent-encodes
            // everything that is not plain ASCII: a name with a space, a
            // bracket or an accent arrives as `Shrek%202%20(2004)` and the
            // path is then a file that does not exist.
            let clean_path = file_url_to_path(&url_str);
            let path = PathBuf::from(&clean_path);

            paths.push(path);
            list.push(QString::from(clean_path.as_str()));
        }

        self.file_list = QStringList::from(list);
        self.file_list_changed();
    }

    fn remove_file(&mut self, index: i32) {
        let i = index.max(0) as usize;
        {
            let mut paths = self.paths.borrow_mut();
            if i >= paths.len() { return; }
            paths.remove(i);
        }
        let mut list = self.file_list.clone();
        if i < list.len() {
            list.remove(i);
        }
        self.file_list = QStringList::from(list);
        self.file_list_changed();
    }

    fn clear_files(&mut self) {
        self.paths.borrow_mut().clear();
        self.file_list = QStringList::default();
        self.file_list_changed();
    }

    /// Share what is in the list — unless it is a video this client could
    /// convert: then the question comes first (`video_offer`), because a
    /// conversion that nobody wanted is minutes of the sender's life, and a
    /// conversion nobody was told about is a link that behaves oddly.
    fn trigger_share(&mut self) {
        let paths = self.paths.borrow().clone();
        if paths.is_empty() {
            self.share_error = QString::from("drop a file or a folder first");
            self.share_error_changed();
            return;
        }
        if let Some(offer) = video_offer_for(&paths) {
            log(format!("share: {offer}"));
            self.video_offer = QString::from(offer);
            self.video_offer_changed();
            return;
        }
        self.begin_share(paths);
    }

    /// The answer to the video question: `"as-is"`, or one of the profiles
    /// (`video::Profile::key`). A conversion happens first and the result is
    /// what goes out; a failure to convert does not swallow the share — the
    /// file is sent as it is, and the error says why nothing was converted.
    fn decide_video(&mut self, mode: QString) {
        let mode = mode.to_string();
        self.video_offer = QString::default();
        self.video_offer_changed();
        let paths = self.paths.borrow().clone();
        if paths.is_empty() {
            return;
        }
        let Some(profile) = video::Profile::parse(&mode) else {
            self.begin_share(paths); // "as-is", or a mode this build does not know
            return;
        };
        let Some(ffmpeg) = video::available() else {
            self.begin_share(paths);
            return;
        };
        let input = paths[0].clone();
        let name = input.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "video".into());
        let out = std::env::temp_dir().join(format!("{}-{}.av1.mp4", sanitized_stem(&name), profile.key()));
        log(format!("video: converting {name} ({}) to AV1", profile.label()));
        let label = format!("converting {name} ({})", profile.label());
        self.converting = QString::from(format!("{label}…"));
        self.converting_changed();
        self.convert_progress = 0.0;
        self.convert_progress_changed();
        self.convert_cancel.store(false, Ordering::Relaxed);
        let cancel = self.convert_cancel.clone();
        let started = Instant::now();

        let qpointer = QPointer::from(&*self);
        let progress_ui = {
            let qpointer = qpointer.clone();
            qmetaobject::queued_callback(move |f: f64| {
                if let Some(api) = qpointer.as_pinned() {
                    let mut a = api.borrow_mut();
                    a.convert_progress = f;
                    a.convert_progress_changed();
                    // How long the rest will take, from what this encode has
                    // managed so far: what a person deciding whether to wait
                    // needs to know, and the only honest number there is.
                    let text = if f >= 0.02 && f < 1.0 {
                        let elapsed = started.elapsed().as_secs_f64();
                        let left = (elapsed / f * (1.0 - f)).max(0.0);
                        let left = human_duration(left);
                        if left.is_empty() { format!("{label}…") } else { format!("{label}… about {left} left") }
                    } else {
                        format!("{label}…")
                    };
                    let text = QString::from(text);
                    if a.converting != text {
                        a.converting = text;
                        a.converting_changed();
                    }
                }
            })
        };
        qmetaobject::future::execute_async(async move {
            let out_path = out.clone();
            let done = async {
                let media = video::probe(&ffmpeg, &input)?;
                let encoders = video::encoders(&ffmpeg)?;
                let video::Plan::Convert { args, out: to } =
                    video::plan(&input, &media, profile, &encoders, out.clone())
                else {
                    anyhow::bail!("already AV1");
                };
                let progress = progress_ui.clone();
                video::convert_until(&ffmpeg, &args, media.duration, move |f| progress(f), &cancel).await?;
                anyhow::Ok(to)
            }
            .await;
            if let Some(api) = qpointer.as_pinned() {
                let mut a = api.borrow_mut();
                a.converting = QString::default();
                a.converting_changed();
                if cancel.load(Ordering::Relaxed) {
                    // The person chose to send it now instead; the card has
                    // already started that share (see `cancel_conversion`), so
                    // there is nothing to start here — only the stump to clear.
                    log("video: conversion cancelled, sending the original");
                    let _ = std::fs::remove_file(&out_path);
                } else {
                    match done {
                        Ok(to) => {
                            log(format!("video: converted to {}", to.display()));
                            // The list now holds the converted file: that is what
                            // the send is made from, and the original stays as it
                            // was, untouched, on disk.
                            a.paths.borrow_mut().clear();
                            a.paths.borrow_mut().push(to.clone());
                            a.file_list = QStringList::from(vec![QString::from(to.display().to_string())]);
                            a.file_list_changed();
                            a.begin_share(vec![to]);
                        }
                        Err(e) => {
                            log(format!("video: not converted: {e:#}"));
                            a.share_error = QString::from(format!("could not convert the video ({e:#}); sending it as it is"));
                            a.share_error_changed();
                            a.begin_share(vec![input]);
                        }
                    }
                }
            }
        });
    }

    /// Stop converting and send the file as it is, now. The encode is killed
    /// and the share starts from the original bytes — the same thing the
    /// "send as it is" answer does, only later, when the wait has turned out
    /// to be longer than the person wanted to give.
    fn cancel_conversion(&mut self) {
        if self.converting.is_empty() {
            return;
        }
        self.convert_cancel.store(true, Ordering::Relaxed);
        self.converting = QString::default();
        self.converting_changed();
        log("video: asked to send now; stopping the conversion");
        let paths = self.paths.borrow().clone();
        if paths.is_empty() {
            return;
        }
        self.begin_share(paths);
    }

    fn begin_share(&mut self, paths: Vec<PathBuf>) {
        log(format!("share: {} path(s) to send", paths.len()));
        if paths.len() == 1 {
            log(format!("share: {}", paths[0].display()));
        }

        // A send is a thing that stays: it gets an id of its own, a row in the
        // Active tab, and its own stop channel. Nothing about it overlaps with
        // the send before it, so another one can be started while it runs.
        let id = {
            let mut next = self.send_next_id.lock().unwrap();
            *next += 1;
            *next
        };
        let (name, size) = describe_selection(&paths);
        {
            let mut list = self.send_state.lock().unwrap();
            list.push(SendEntry {
                id,
                name,
                size,
                progress: 0.0,
                status: "preparing".into(),
                phase: "reading the selection".into(),
                url: String::new(),
                peers: 0,
                error: String::new(),
            });
        }
        self.refresh_sends();
        self.is_busy = true;
        self.is_busy_changed();
        // The picked files are the ones this send was made from: the list is
        // emptied so the next drop starts a new send, not a wider first one.
        self.paths.borrow_mut().clear();
        self.file_list = QStringList::default();
        self.file_list_changed();
        // The last link stays on the Send tab until a new one arrives; the
        // error under it is about the last attempt, so it goes now.
        self.share_error = QString::default();
        self.share_error_changed();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        if let Ok(mut stops) = self.send_stops.lock() {
            stops.insert(id, stop_tx);
        }

        let state = self.send_state.clone();
        let active_urls = self.active_share_urls.clone();
        let qpointer = QPointer::from(&*self);

        // Progress comes from tokio threads, many times a second: it is
        // marshalled onto the Qt thread, where the property may be touched.
        let state_ui = state.clone();
        let qpointer_ui = qpointer.clone();
        let report_ui = qmetaobject::queued_callback(move |update: SendUpdate| {
            let finished = matches!(update.status, Some("done" | "error" | "stopped"));
            update_send_state(&state_ui, id, |s| s.apply(update));
            refresh_sends_from_bg(&qpointer_ui, &state_ui);
            if finished {
                if let Some(api) = qpointer_ui.as_pinned() {
                    let mut a = api.borrow_mut();
                    // The session this stop channel belongs to has ended, so
                    // the channel can go. It must not go a moment earlier: the
                    // session lives in a task of its own and a dropped sender
                    // *is* a stop, which is why a share used to die the instant
                    // it printed its link.
                    a.send_stops.lock().ok().map(|mut s| s.remove(&id));
                    a.is_busy = a.send_state.lock().map(|g| g.iter().any(|s| s.status == "preparing")).unwrap_or(false);
                    a.is_busy_changed();
                }
            }
        });
        let report: SendReport = std::sync::Arc::new(report_ui);
        let report_bg = report.clone();

        // The window's own copy of the link: it arrives on a tokio thread, so
        // the property is set through the queue as well.
        let qpointer_link = qpointer.clone();
        let active_for_link = active_urls.clone();
        let link_ui = qmetaobject::queued_callback(move |url: String| {
            if is_bitmule_link(&url) {
                if let Ok(mut v) = active_for_link.lock() { v.push(url.clone()); }
            }
            copy_to_clipboard(&url);
            if let Some(api) = qpointer_link.as_pinned() {
                let mut a = api.borrow_mut();
                let qr = qr_data_url_for(&print_text_for(&url));
                a.share_url = QString::from(url);
                a.qr_data_url = QString::from(qr);
                a.share_url_changed();
                a.qr_data_url_changed();
            }
        });

        qmetaobject::future::execute_async(async move {
            // A preparing send keeps the Send tab's hint up until it has a
            // link; the check is on this send, not on the last one.
            let result = share(paths, report_bg, stop_rx).await;
            match result {
                Ok(url) => link_ui(url.to_string()),
                Err(e) => {
                    let failed = SendUpdate::failed(e.clone());
                    report(failed);
                    if let Some(api) = qpointer.as_pinned() {
                        let mut a = api.borrow_mut();
                        a.share_error = QString::from(e);
                        a.share_error_changed();
                    }
                }
            }
            if let Some(api) = qpointer.as_pinned() {
                let mut a = api.borrow_mut();
                // The stop channel is *not* dropped here: `share` returns as
                // soon as the link is made, and the session it started keeps
                // running in its own task. Dropping the sender would end that
                // session — the link would be dead the moment it appeared. It
                // goes when the send reports itself finished (see `report_ui`).
                a.is_busy = a.send_state.lock().map(|g| g.iter().any(|s| s.status == "preparing")).unwrap_or(false);
                a.is_busy_changed();
            } else {
                log("share: the window is gone, dropping the result");
            }
        });
    }

    fn stop_send(&mut self, id: QString) {
        let Ok(id) = id.to_string().parse::<u64>() else { return };
        if let Ok(mut stops) = self.send_stops.lock() {
            if let Some(tx) = stops.remove(&id) {
                let _ = tx.send(());
                log(format!("share: stop asked for #{id}"));
            }
        }
        update_send_state(&self.send_state, id, |s| {
            s.status = "stopped".into();
            s.phase = "stopped".into();
        });
        self.refresh_sends();
    }

    fn drop_send(&mut self, id: QString) {
        let Ok(id) = id.to_string().parse::<u64>() else { return };
        if let Ok(mut stops) = self.send_stops.lock() {
            if let Some(tx) = stops.remove(&id) {
                let _ = tx.send(());
            }
        }
        if let Ok(mut list) = self.send_state.lock() {
            list.retain(|s| s.id != id);
        }
        self.refresh_sends();
    }

    fn copy_text(&mut self, text: QString) -> bool {
        let text = text.to_string();
        if text.is_empty() { return false; }
        copy_to_clipboard(&text)
    }

    fn refresh_sends(&mut self) {
        let snap: Vec<QString> = match self.send_state.lock() {
            Ok(g) => g.iter().map(|s| QString::from(
                serde_json::to_string(s).unwrap_or_else(|_| "{}".into())
            )).collect(),
            Err(_) => Vec::new(),
        };
        self.sends = QStringList::from(snap);
        self.sends_changed();
    }


    fn copy_share_url(&mut self) -> bool {
        let url = self.share_url.to_string();
        if url.is_empty() { return false; }
        copy_to_clipboard(&url)
    }

    fn save_options(&mut self) {
        let opts = OptionsSnapshot {
            multi_send: self.opt_multi_send,
            upnp: self.opt_upnp,
            clipboard_watch: self.opt_clipboard_watch,
            auto_download: self.opt_auto_download,
            theme: self.opt_theme.to_string(),
        };
        if let Err(e) = write_options(&opts) {
            eprintln!("save_options: {e}");
        }
    }

    fn open_fetch_url(&mut self, url: QString) -> bool {
        let u = url.to_string();
        // Simple first-cut: open in the system browser. Full in-app
        // receiver flow (mirror of `share`'s send flow) is a follow-up.
        let opened = open::that(&u).is_ok();
        if opened { self.drop_fetch_url(url); }
        opened
    }

    fn drop_fetch_url(&mut self, url: QString) {
        let u = url.to_string();
        if let Ok(mut q) = self.fetch_queue_urls.lock() {
            q.retain(|x| x != &u);
            self.fetch_queue = QStringList::from(
                q.iter().map(|s| QString::from(s.as_str())).collect::<Vec<_>>()
            );
        }
        self.fetch_queue_changed();
    }

    fn init_from_qml(&mut self) {
        let opts = load_options();
        self.opt_multi_send = opts.multi_send;
        self.opt_upnp = opts.upnp;
        self.opt_clipboard_watch = opts.clipboard_watch;
        self.opt_auto_download = opts.auto_download;
        self.opt_theme = QString::from(opts.theme.as_str());
        self.opt_multi_send_changed();
        self.opt_upnp_changed();
        self.opt_clipboard_watch_changed();
        self.opt_auto_download_changed();
        self.opt_theme_changed();

        if opts.clipboard_watch {
            self.spawn_clipboard_watcher();
        }
        self.init_automation();
    }

    /// Test hooks, applied once the window is up. A test cannot click a button,
    /// so the two things a person does by hand — drop a file and press Share,
    /// paste a link — are named in the environment instead:
    /// `BITMULE_QT_SHARE=<path>` shares at startup, and `BITMULE_QT_RECV=<link>`
    /// receives at startup. Both unset in the app: the suite in
    /// `bitmule-e2e-tests/tests/qt_client.rs` is the only caller. It follows the
    /// window through the log lines below and kills it when the case is done,
    /// rather than asking the app to exit itself.
    fn init_automation(&mut self) {
        if let Ok(path) = std::env::var("BITMULE_QT_SHARE") {
            let path = PathBuf::from(file_url_to_path(path.trim()));
            log(format!("automation: sharing {} at startup", path.display()));
            self.paths.borrow_mut().push(path.clone());
            self.file_list = QStringList::from(vec![QString::from(path.to_string_lossy().into_owned())]);
            self.file_list_changed();
            self.trigger_share();
            // A headless run cannot press the video card's buttons, so the
            // answer comes from the environment: `as-is`, `fast`, `balanced`
            // or `quality`.
            if let Ok(mode) = std::env::var("BITMULE_QT_CONVERT") {
                let mode = mode.trim().to_string();
                log(format!("automation: answering the video question with {mode:?}"));
                self.decide_video(QString::from(mode));
            }
        }
        if let Ok(url) = std::env::var("BITMULE_QT_RECV") {
            let url = url.trim().to_string();
            log(format!("automation: receiving {url} at startup"));
            self.add_recv_url(QString::from(url));
        }
    }

    fn add_recv_url(&mut self, url: QString) {
        let u = url.to_string();
        let u_trim = u.trim().to_string();
        if !is_bitmule_link(&u_trim) {
            log(format!("recv: rejected {u_trim} — not a bitmule share link"));
            self.push_recv_transfer(RecvTransferState {
                url: u_trim,
                name: String::new(),
                progress: 0.0,
                status: "error".into(),
                path: None,
                error: Some("a share link starts with https://mul.li# or https://bitmule.net/#".into()),
            });
            return;
        }
        // Dedup: don't add the same URL twice if it's already in progress.
        if let Ok(g) = self.recv_state.lock() {
            if g.iter().any(|s| s.url == u_trim && s.status != "error") { return; }
        }
        self.push_recv_transfer(RecvTransferState {
            url: u_trim.clone(),
            name: String::new(),
            progress: 0.0,
            status: "connecting".into(),
            path: None,
            error: None,
        });
        self.spawn_recv_task(u_trim);
    }

    fn drop_recv_transfer(&mut self, url: QString) {
        let u = url.to_string();
        if let Ok(mut g) = self.recv_state.lock() {
            g.retain(|s| s.url != u);
        }
        self.refresh_recv_transfers();
    }

    fn open_recv_dir(&mut self) {
        let d = recv_out_dir();
        let _ = std::fs::create_dir_all(&d);
        let _ = open::that(&d);
    }

    fn push_recv_transfer(&mut self, s: RecvTransferState) {
        if let Ok(mut g) = self.recv_state.lock() {
            g.push(s);
        }
        self.refresh_recv_transfers();
    }

    fn refresh_recv_transfers(&mut self) {
        let snap: Vec<QString> = match self.recv_state.lock() {
            Ok(g) => g.iter().map(|s| QString::from(
                serde_json::to_string(s).unwrap_or_else(|_| "{}".into())
            )).collect(),
            Err(_) => Vec::new(),
        };
        self.recv_transfers = QStringList::from(snap);
        self.recv_transfers_changed();
    }

    fn spawn_recv_task(&mut self, url: String) {
        let qpointer = QPointer::from(&*self);
        let state = self.recv_state.clone();
        qmetaobject::future::execute_async(async move {
            let out_dir = recv_out_dir();
            let _ = std::fs::create_dir_all(&out_dir);
            // Stage the transfer inside a per-download subdir so a partial
            // file from a mid-stream failure (e.g. AEAD decrypt error) is
            // never visible in the user's Downloads folder. On success we
            // rename the finished file into out_dir; on any error we
            // clean up staging.
            let stage_dir = out_dir.join(format!(".staging-{}", short_stage_tag(&url)));
            let _ = std::fs::create_dir_all(&stage_dir);
            let (server, fragment) = match split_share_url(&url) {
                Some(v) => v,
                None => {
                    log(format!("recv: error — {url}: not a server and a code"));
                    update_recv_state(&state, &url, |s| {
                        s.status = "error".into();
                        s.error = Some("couldn't split URL into server + fragment".into());
                    });
                    refresh_from_bg(&qpointer, &state);
                    return;
                }
            };
            let link = match parse_fragment(&fragment) {
                Some(v) => v,
                None => {
                    log(format!("recv: error — {url}: the code does not decode"));
                    update_recv_state(&state, &url, |s| {
                        s.status = "error".into();
                        s.error = Some("couldn't parse URL fragment as ShareLink".into());
                    });
                    refresh_from_bg(&qpointer, &state);
                    return;
                }
            };
            update_recv_state(&state, &url, |s| { s.status = "receiving".into(); });
            refresh_from_bg(&qpointer, &state);
            // Callback runs on tokio worker threads and must be Send;
            // QPointer is !Send. queued_callback returns a
            // Send+Sync+Clone closure that marshals the call back onto
            // the qt event-loop thread, where it's safe to touch
            // QPointer + qmetaobject state.
            let state_ui = state.clone();
            let url_ui = url.clone();
            let qpointer_ui = qpointer.clone();
            let on_progress_ui = qmetaobject::queued_callback(move |(name_s, prog): (String, f64)| {
                update_recv_state(&state_ui, &url_ui, |s| {
                    s.name = name_s;
                    s.progress = prog;
                });
                refresh_from_bg(&qpointer_ui, &state_ui);
            });

            // The file is made inside the staging dir once the sender's
            // manifest is in, named after what the sender calls it.
            let staged: Arc<Mutex<Option<PathBuf>>> = Arc::default();
            let open = {
                let staged = staged.clone();
                let stage_dir = stage_dir.clone();
                move |manifest: &bitmule_core::protocol::websocket::TransferManifest| {
                    let name = manifest.file_name().unwrap_or_else(|| "bitmule-download".to_string());
                    let path = stage_dir.join(name);
                    let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
                    *staged.lock().unwrap() = Some(path);
                    Ok(file)
                }
            };
            let last_pct = Arc::new(Mutex::new(0u8));
            let progress = {
                let staged = staged.clone();
                move |received: u64, total: u64| {
                    let pct = if total > 0 {
                        ((received as f64 / total as f64) * 100.0).floor() as u8
                    } else { 0 };
                    // Coalesce progress writes at 1% granularity.
                    let mut lp = last_pct.lock().unwrap();
                    if pct == *lp { return; }
                    *lp = pct;
                    drop(lp);
                    let prog = if total > 0 { received as f64 / total as f64 } else { 0.0 };
                    let name = staged.lock().unwrap().as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    on_progress_ui((name, prog));
                }
            };
            // a share link can name any server: not one without TLS, unless
            // `BITMULE_INSECURE` says the server is on loopback
            let result = match bitmule::v2::Server::parse_checked(&server, allow_insecure()) {
                Ok(server) => bitmule::v2::run_recv_progress(&server, &link, open, progress, bitmule::v2::Options::default()).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(report) => {
                    // run_recv_progress returned Ok: the data was checked
                    // against the link's signature. Promote it out of staging;
                    // a zip is unpacked into a fresh directory, and kept
                    // as the raw zip if that fails.
                    let staged_path = staged.lock().unwrap().clone().unwrap_or_default();
                    let is_zip = matches!(report.manifest.transfer_typ, bitmule_core::protocol::websocket::TransferType::MultiFileZip { .. });
                    let unpacked = if is_zip {
                        let zip_path = staged_path.clone();
                        let into = out_dir.clone();
                        let limit = bitmule::unzip::unpack_limit(&report.manifest);
                        Some(tokio::task::spawn_blocking(move || unpack_zip(&zip_path, &into, limit)).await)
                    } else { None };
                    match unpacked {
                        Some(Ok(Ok((final_dir, entries)))) => {
                            let stem = final_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "bundle".into());
                            let _ = std::fs::remove_dir_all(&stage_dir);
                            update_recv_state(&state, &url, |s| {
                                s.status = "complete".into();
                                s.progress = 1.0;
                                s.name = format!("{} ({} file{})", stem, entries,
                                    if entries == 1 { "" } else { "s" });
                                s.path = Some(final_dir.to_string_lossy().into_owned());
                            });
                        }
                        other => {
                            let unpack_error = match other {
                                Some(Ok(Err(e))) => Some(format!("unpack zip: {e:#}")),
                                Some(Err(e)) => Some(format!("unpack zip: {e}")),
                                _ => None,
                            };
                            let name_s = staged_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                            let final_path = unique_dest_path(&out_dir, &name_s);
                            let moved = std::fs::rename(&staged_path, &final_path);
                            let _ = std::fs::remove_dir_all(&stage_dir);
                            update_recv_state(&state, &url, |s| match (moved, unpack_error) {
                                (Ok(()), None) => {
                                    s.status = "complete".into();
                                    s.progress = 1.0;
                                    s.name = final_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                    s.path = Some(final_path.to_string_lossy().into_owned());
                                }
                                (Ok(()), Some(msg)) => {
                                    s.status = "error".into();
                                    s.error = Some(format!("{msg} — zip kept at {}", final_path.display()));
                                    s.path = Some(final_path.to_string_lossy().into_owned());
                                }
                                (Err(e), _) => {
                                    s.status = "error".into();
                                    s.error = Some(format!("promote staged file: {e:#}"));
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    // A failed transfer leaves partial bytes in stage_dir;
                    // clean the whole staging tree.
                    let _ = std::fs::remove_dir_all(&stage_dir);
                    update_recv_state(&state, &url, |s| {
                        s.status = "error".into();
                        s.error = Some(format!("{e:#}"));
                    });
                }
            }
            refresh_from_bg(&qpointer, &state);
            // One line per finished download, in the words the window shows:
            // a GUI has no console, and a test (or the owner with a terminal)
            // needs to know how it ended and where the bytes went.
            let (status, name, detail) = match state.lock() {
                Ok(g) => match g.iter().find(|s| s.url == url) {
                    Some(s) => (
                        s.status.clone(),
                        s.name.clone(),
                        s.path.clone().or_else(|| s.error.clone()).unwrap_or_default(),
                    ),
                    None => (String::from("gone"), String::new(), String::new()),
                },
                Err(_) => (String::from("gone"), String::new(), String::new()),
            };
            log(format!("recv: {status} — {name} {detail}"));
        });
    }

    fn spawn_clipboard_watcher(&mut self) {
        let qpointer = QPointer::from(&*self);
        let active_urls = self.active_share_urls.clone();
        let queue_urls = self.fetch_queue_urls.clone();
        qmetaobject::future::execute_async(async move {
            let mut last = String::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                let (still_on, auto) = match qpointer.as_pinned() {
                    Some(api) => {
                        let a = api.borrow();
                        (a.opt_clipboard_watch, a.opt_auto_download)
                    }
                    None => return, // API gone (app closing)
                };
                if !still_on { return; }
                let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let trimmed = text.trim().to_string();
                if trimmed == last { continue; }
                last = trimmed.clone();
                if !is_bitmule_link(&trimmed) { continue; }
                // Own-upload guard.
                if active_urls.lock().map(|v| v.iter().any(|u| u == &trimmed)).unwrap_or(false) {
                    continue;
                }
                // Dedup within the queue.
                if queue_urls.lock().map(|v| v.iter().any(|u| u == &trimmed)).unwrap_or(false) {
                    continue;
                }
                if let Ok(mut q) = queue_urls.lock() { q.push(trimmed.clone()); }
                // Push into the QStringList property on the UI thread.
                if let Some(api) = qpointer.as_pinned() {
                    let snap: Vec<QString> = queue_urls.lock()
                        .map(|q| q.iter().map(|s| QString::from(s.as_str())).collect())
                        .unwrap_or_default();
                    api.borrow_mut().fetch_queue = QStringList::from(snap);
                    api.borrow_mut().fetch_queue_changed();
                }
                if auto {
                    let u_q = QString::from(trimmed.as_str());
                    if let Some(api) = qpointer.as_pinned() {
                        let _ = api.borrow_mut().open_fetch_url(u_q);
                    }
                }
            }
        });
    }
}

/// One entry of the Active tab: a send this window started, from the moment
/// its files were read until it is done, stopped or failed.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SendEntry {
    id: u64,
    /// What it sends: the file's name, or "3 items".
    name: String,
    /// Bytes of the selection, when known (0 while a folder is being counted).
    size: u64,
    /// 0.0..=1.0 — the receiver that has the most of it.
    progress: f64,
    /// "preparing" | "live" | "done" | "error" | "stopped"
    status: String,
    /// What it is doing right now, in the sender's words.
    phase: String,
    /// The link, once the session exists; empty while preparing.
    url: String,
    /// How many receivers have joined.
    peers: usize,
    /// Why it failed, when it did.
    error: String,
}

impl SendEntry {
    fn apply(&mut self, u: SendUpdate) {
        if let Some(status) = u.status { self.status = status.into(); }
        if let Some(phase) = u.phase { self.phase = phase; }
        if let Some(progress) = u.progress { self.progress = progress; }
        if let Some(size) = u.size { self.size = size; }
        if let Some(peers) = u.peers { self.peers = peers; }
        if let Some(url) = u.url { self.url = url; }
        if let Some(error) = u.error { self.error = error; }
    }
}

/// What a selection is called and how big it is, before it is hashed: a
/// directory is counted, which is the one place this touches the disk from
/// the Qt thread (a directory of a few thousand files takes a millisecond).
fn describe_selection(paths: &[PathBuf]) -> (String, u64) {
    let mut bytes = 0u64;
    for path in paths {
        match std::fs::metadata(path) {
            Ok(md) if md.is_file() => bytes += md.len(),
            Ok(md) if md.is_dir() => {
                for entry in walkdir::WalkDir::new(path).into_iter().flatten() {
                    if entry.file_type().is_file() {
                        if let Ok(md) = entry.metadata() { bytes += md.len(); }
                    }
                }
            }
            _ => {}
        }
    }
    let name = match paths {
        [one] => one.file_name().map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| one.display().to_string()),
        many => format!("{} items", many.len()),
    };
    (name, bytes)
}

/// Whether this selection is a video that would have to be converted, as the
/// JSON the dialog needs — `None` when there is nothing to ask: not a single
/// file, not a video by its name, no ffmpeg that can encode AV1, or already AV1
/// (then a conversion would only lose).
fn video_offer_for(paths: &[PathBuf]) -> Option<String> {
    /// The extensions worth asking ffmpeg about. A file with one of these that
    /// ffmpeg cannot open is sent as it is, quietly.
    const VIDEO: [&str; 17] = [
        "mp4", "m4v", "mkv", "mov", "avi", "webm", "mpg", "mpeg", "ts", "m2ts", "mts", "wmv",
        "flv", "3gp", "ogv", "vob", "mxf",
    ];
    let [path] = paths else { return None };
    if !path.is_file() {
        return None;
    }
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    if !VIDEO.contains(&ext.as_str()) {
        return None;
    }
    let ffmpeg = video_tool()?;
    // A probe that fails is not a reason to stop a share: the file goes as it is.
    let media = bitmule_client_common::video::probe(&ffmpeg, path).ok()?;
    if media.is_playable_av1() {
        return None;
    }
    let size = std::fs::metadata(path).map(|md| md.len()).unwrap_or(0);
    let profiles: Vec<String> = bitmule_client_common::video::Profile::ALL
        .iter()
        .map(|p| format!("{{\"key\":\"{}\",\"label\":\"{}\"}}", p.key(), p.label()))
        .collect();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Some(format!(
        "{{\"name\":{},\"size\":{},\"sizeText\":{},\"codec\":{},\"seconds\":{:.1},\"durationText\":{},\"profiles\":[{}]}}",
        json_string(&name),
        size,
        json_string(&human_size(size)),
        json_string(&media.video_codec),
        media.duration,
        json_string(&human_duration(media.duration)),
        profiles.join(","),
    ))
}

/// Bytes as a person reads them (binary units, one decimal above a kibibyte).
fn human_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10), ("B", 1)];
    for (unit, scale) in UNITS {
        if bytes >= scale || scale == 1 {
            return if scale == 1 { format!("{bytes} B") } else { format!("{:.1} {unit}", bytes as f64 / scale as f64) };
        }
    }
    format!("{bytes} B")
}

/// Seconds as "1 h 33 min" / "4 min 12 s" / "38 s".
fn human_duration(seconds: f64) -> String {
    let total = seconds.max(0.0).round() as u64;
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    if h > 0 {
        format!("{h} h {m} min")
    } else if m > 0 {
        format!("{m} min {s} s")
    } else if total > 0 {
        format!("{s} s")
    } else {
        String::new()
    }
}

/// The ffmpeg that can encode AV1, looked for once: the search touches the
/// disk and runs `ffmpeg -encoders`, and the answer does not change while the
/// window is open.
fn video_tool() -> Option<PathBuf> {
    static FOUND: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    FOUND.get_or_init(bitmule_client_common::video::available).clone()
}

/// A JSON string literal, with the characters JSON forbids escaped. A file name
/// is the only untrusted part of the dialog's payload.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A file name's stem, safe to put into a temporary file name.
fn sanitized_stem(name: &str) -> String {
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    let cleaned: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if cleaned.is_empty() { "video".into() } else { cleaned.chars().take(80).collect() }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RecvTransferState {    url: String,
    name: String,
    /// 0.0..=1.0
    progress: f64,
    /// "connecting" | "receiving" | "complete" | "error"
    status: String,
    /// Absolute filesystem path once complete; None while in-flight.
    path: Option<String>,
    /// Human-readable error when status == "error".
    error: Option<String>,
}

/// Where recv_file writes downloads. Follows the same
/// XDG_DOWNLOAD_DIR / $HOME/Downloads convention as most Linux apps.
/// A `file:` URL as a filesystem path. Qt's drop carries QUrl, whose text
/// form is percent-encoded — `/home/sebk/Videos/Shrek%202%20(2004)%20[1080p]/…`
/// — and trimming the scheme alone leaves a path that does not exist. A
/// string that did not come in as a URL is returned untouched, so a plain
/// path with a `%` in it is not decoded twice.
fn file_url_to_path(s: &str) -> String {
    let Some(rest) = s.strip_prefix("file:") else { return s.to_string() };
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let bytes = rest.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn short_stage_tag(url: &str) -> String {
    // 8 hex chars off a stable hash of the URL — enough to keep
    // concurrent staging dirs from colliding without leaking the
    // full URL onto disk paths.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut h);
    format!("{:08x}", (h.finish() & 0xffff_ffff) as u32)
}

fn unique_dest_path(dir: &Path, name: &str) -> PathBuf {
    let cand = dir.join(name);
    if !cand.exists() { return cand; }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1u32..1000 {
        let cand = dir.join(format!("{stem} ({n}){ext}"));
        if !cand.exists() { return cand; }
    }
    dir.join(name)
}

fn recv_out_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_DOWNLOAD_DIR") {
        return PathBuf::from(x).join("bitmule");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join("Downloads").join("bitmule")
}

fn split_share_url(url: &str) -> Option<(String, String)> {
    let hash_at = url.find('#')?;
    let (before, after) = url.split_at(hash_at);
    let named = before.trim_end_matches('/');
    let fragment = after.trim_start_matches('#').to_string();
    if named.is_empty() || fragment.is_empty() { return None; }
    // The link names where its pages live. A printed link names the short host
    // (`https://mul.li#<code>`), which serves pages and no rooms — a websocket
    // join there is a 404 — so the room is the server this window is set up
    // for. Any other origin is its own room (`bitmule::v2::room_for_link`).
    let configured = share_server();
    let room = bitmule::v2::room_for_link(Some(named), &configured);
    Some((room.to_string(), fragment))
}

fn parse_fragment(fragment: &str) -> Option<bitmule_client_native::crypto::ShareLink> {
    // Every spelling the tree has emitted: the 32-byte code (48 base-42
    // characters), its base64url text codes of 44 and 43, the base32 forms of
    // 2026-11-10 and the base64url links before them. `from_link` tells them
    // apart by length.
    bitmule_client_native::crypto::ShareLink::from_link(fragment).ok()
}

/// Unpack `zip_path` (stored, deflated or zstd entries, holding at most
/// `limit` bytes) into a new directory in `into`. Returns the directory and
/// the number of files.
fn unpack_zip(zip_path: &Path, into: &Path, limit: u64) -> anyhow::Result<(PathBuf, usize)> {
    fn count_files(dir: &Path) -> usize {
        std::fs::read_dir(dir).into_iter().flatten().flatten()
            .map(|e| if e.path().is_dir() { count_files(&e.path()) } else { 1 })
            .sum()
    }
    let dir = bitmule::unzip::unpack_zip(zip_path, into, limit)?;
    let files = count_files(&dir);
    Ok((dir, files))
}

fn update_recv_state<F: FnOnce(&mut RecvTransferState)>(
    state: &Arc<Mutex<Vec<RecvTransferState>>>,
    url: &str,
    f: F,
) {
    if let Ok(mut g) = state.lock() {
        for s in g.iter_mut() {
            if s.url == url { f(s); return; }
        }
    }
}

fn refresh_from_bg(
    qpointer: &QPointer<UploaderApi>,
    state: &Arc<Mutex<Vec<RecvTransferState>>>,
) {
    let snap: Vec<QString> = match state.lock() {
        Ok(g) => g.iter().map(|s| QString::from(
            serde_json::to_string(s).unwrap_or_else(|_| "{}".into())
        )).collect(),
        Err(_) => Vec::new(),
    };
    if let Some(mut api) = qpointer.as_pinned() {
        api.borrow_mut().recv_transfers = QStringList::from(snap);
        api.borrow_mut().recv_transfers_changed();
    }
}

fn update_send_state<F: FnOnce(&mut SendEntry)>(
    state: &Arc<Mutex<Vec<SendEntry>>>,
    id: u64,
    f: F,
) {
    if let Ok(mut g) = state.lock() {
        if let Some(s) = g.iter_mut().find(|s| s.id == id) { f(s); }
    }
}

fn refresh_sends_from_bg(
    qpointer: &QPointer<UploaderApi>,
    state: &Arc<Mutex<Vec<SendEntry>>>,
) {
    let snap: Vec<QString> = match state.lock() {
        Ok(g) => g.iter().map(|s| QString::from(
            serde_json::to_string(s).unwrap_or_else(|_| "{}".into())
        )).collect(),
        Err(_) => Vec::new(),
    };
    if let Some(mut api) = qpointer.as_pinned() {
        api.borrow_mut().sends = QStringList::from(snap);
        api.borrow_mut().sends_changed();
    }
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
struct OptionsSnapshot {
    #[serde(default = "default_true")]
    multi_send: bool,
    #[serde(default)]
    upnp: bool,
    #[serde(default)]
    clipboard_watch: bool,
    #[serde(default)]
    auto_download: bool,
    /// `"auto"` follows the desktop's colour scheme; `"light"` and
    /// `"dark"` pin one. Anything else is read as `"auto"` by the QML.
    #[serde(default = "default_theme")]
    theme: String,
}
fn default_true() -> bool { true }
fn default_theme() -> String { "auto".to_string() }

impl OptionsSnapshot {
    /// What a missing or unparsable options file reads as.
    fn first_run() -> Self {
        OptionsSnapshot {
            multi_send: true,
            upnp: false,
            clipboard_watch: false,
            auto_download: false,
            theme: default_theme(),
        }
    }
}

/// The app's mark: the loop from `web/site/icons/favicon.svg`, rendered at
/// 256 px. Qt's window icon (`ApplicationWindow.icon`) takes a file, not
/// bytes, so the binary carries the PNG and writes it to the user's cache
/// dir on first use — 20 KB, and only when what is there differs, so an
/// updated mark replaces the old one on the next start.
const ICON_PNG: &[u8] = include_bytes!("icon.png");

unsafe extern "C" {
    /// `src/winicon.cpp` (or its no-op stub): sets the application's window
    /// icon, which every `QWindow` without one of its own inherits.
    fn bm_set_window_icon(path: *const std::ffi::c_char);
}

fn app_icon_file() -> String {
    static PATH_ONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH_ONCE
        .get_or_init(|| {
            let base = std::env::var("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::var("HOME")
                        .map(|h| PathBuf::from(h).join(".cache"))
                        .unwrap_or_else(|_| std::env::temp_dir())
                });
            let dir = base.join("bitmule");
            let path = dir.join("icon.png");
            if std::fs::read(&path)
                .map(|have| have != ICON_PNG)
                .unwrap_or(true)
            {
                if std::fs::create_dir_all(&dir).is_ok() {
                    if let Err(e) = std::fs::write(&path, ICON_PNG) {
                        eprintln!("icon: couldn't write {}: {e}", path.display());
                    }
                }
            }
            path.to_string_lossy().into_owned()
        })
        .clone()
}

fn options_path() -> PathBuf {
    // Prefer XDG_CONFIG_HOME/bitmule/, fall back to $HOME/.config/bitmule/.
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")).unwrap_or_default()
        });
    base.join("bitmule").join(OPTIONS_FILE_NAME)
}

fn load_options() -> OptionsSnapshot {
    let path = options_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| OptionsSnapshot::first_run()),
        Err(_) => OptionsSnapshot::first_run(),
    }
}

fn write_options(opts: &OptionsSnapshot) -> std::io::Result<()> {
    let path = options_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(opts)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, s)
}

/// Cross-platform clipboard copy via `arboard`.
///
/// Linux caveat: X11/Wayland clipboards go dead the instant the
/// setting process drops its selection ownership. A synchronous
/// `Clipboard::new()?.set_text(t)?` returns in ~1 ms, so clipboard
/// managers (clipman, parcellite, gnome-shell clipboard-indicator)
/// often miss the paint — the content is gone before they poll.
///
/// Fix: spawn a detached thread that owns the Clipboard and calls
/// `SetExtLinux::wait()`. `wait()` blocks the thread until another
/// process claims the selection (typically seconds — user paste,
/// user selects other text, next app copy), keeping the content
/// alive for the clipboard-manager pickup window. Non-Linux: use
/// the plain set_text (macOS + Windows retain the clipboard past
/// process exit natively).
///
/// Non-blocking to the caller either way; returns true when the
/// thread spawn succeeds. Actual paste-success is best-effort.
fn copy_to_clipboard(text: &str) -> bool {
    let t = text.to_string();
    std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        {
            use arboard::SetExtLinux;
            match arboard::Clipboard::new() {
                Ok(mut c) => {
                    if let Err(e) = c.set().wait().text(t) {
                        eprintln!("clipboard set().wait() failed: {e}");
                    }
                }
                Err(e) => eprintln!("clipboard init failed: {e}"),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(t)) {
                Ok(()) => {}
                Err(e) => eprintln!("clipboard copy failed: {e}"),
            }
        }
    });
    true
}

/// What goes in the symbol: the code itself — 48 base-42 alphanumeric
/// characters, the same 48 a pasted link carries — inside an upper-case link,
/// `HTTPS://MUL.LI#…`, so a camera can still open it. The
/// three segments cost 391 of the 440 bits QR version 3 at ECC L carries
/// (`code::print_url_for` has the arithmetic and the 56-digit cap).
///
/// Falls back to the link itself if it is not a code this build can print.
fn print_text_for(url: &str) -> String {
    bitmule_client_native::crypto::code::print_url_for(url)
}

/// Render `text` as a QR bitmap and encode it as a
/// `data:image/png;base64,...` URL suitable for direct binding on a
/// QML `Image.source`. PNG over SVG: smaller wire (~1–3KB vs
/// ~7–20KB), single-pass decode in QML's image loader, no SVG parser
/// spinup, pixel-exact — QR is a fixed grid, we don't need scaling.
///
/// Returns empty string when the input is empty or QR generation
/// fails (payload too large for QR at any error-correction level).
fn qr_data_url_for(text: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use image::{codecs::png::PngEncoder, ExtendedColorType, ImageEncoder, Luma};

    if text.is_empty() { return String::new(); }
    // ECC L is the owner's default for the printed code (2026-11-24): 7%
    // recovery still scans a clean flat surface, and it is what lets the 63
    // character URL fit version 3 (29×29). The symbol is version 3 by
    // construction (owner, 2026-11-27): a link is `HTTPS://MUL.LI#` plus 48
    // alphanumeric digits — 63 characters, 391 of the 440 bits version 3
    // holds at ECC L. Anything longer says so and gets the smallest symbol
    // that holds it, rather than silently growing.
    // The segments are built by `bitmule_client_common::qr` — the `qrcode`
    // crate's own layout puts the whole 63 characters in byte mode because of
    // the `#` and lands on version 4.
    let code = match bitmule_client_common::qr::symbol(text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "qr: {} characters do not fit any version at ECC L ({e})",
                text.chars().count()
            );
            return String::new();
        }
    };
    if code.width() != 29 {
        eprintln!(
            "qr: {} characters do not fit version 3 at ECC L — the symbol grew to {} modules",
            text.chars().count(),
            code.width()
        );
    }
    // `render::<Luma<u8>>` produces a grayscale ImageBuffer at
    // one pixel per module + configurable quiet-zone/scale. 8 px
    // per module keeps the PNG small while still landing at ~240 px
    // for a typical URL. QML upscales pixel-exact via the Image
    // source binding.
    let img = code
        .render::<Luma<u8>>()
        .module_dimensions(8, 8)
        .build();
    let (w, h) = img.dimensions();
    let mut png_bytes: Vec<u8> = Vec::new();
    if let Err(e) = PngEncoder::new(&mut png_bytes).write_image(
        img.as_raw(),
        w,
        h,
        ExtendedColorType::L8,
    ) {
        eprintln!("qr png encode failed: {e}");
        return String::new();
    }
    format!("data:image/png;base64,{}", STANDARD.encode(&png_bytes))
}

#[tokio::main]
async fn main() {
    // One look on every desktop. The platform styles (Fusion, material,
    // whatever a desktop integration provides) paint controls from their own
    // palettes and only partly follow the window palette; the Basic style
    // draws every control from `palette.*` alone, so the colour table in
    // app.qml is what the user actually sees. An explicit choice in the
    // environment still wins, for experiments.
    if std::env::var_os("QT_QUICK_CONTROLS_STYLE").is_none() {
        // SAFETY: single-threaded, before any Qt object exists and before the
        // QML engine reads the variable.
        unsafe { std::env::set_var("QT_QUICK_CONTROLS_STYLE", "Basic") };
    }

    log("bitmule-qt6 starting");
    // The library talks through `tracing`, and a window with no subscriber
    // swallows all of it: a relay that closes an upload, a receiver that goes
    // away, a streaming pass that fails — none of it reached the terminal
    // before, so a transfer that did nothing looked like a transfer that did
    // nothing for no reason. `RUST_LOG=debug` shows the details.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "bitmule=info,bitmule_qt6=info".into());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    qml_register_type::<UploaderApi>(c_str!("Uploader"), 1, 0, c_str!("UploaderApi"));
    qml_register_type::<account::AccountApi>(c_str!("Uploader"), 1, 0, c_str!("AccountApi"));

    let mut engine = QmlEngine::new();
    // Qt Quick has no QML property for the window icon (`ApplicationWindow`
    // has no `icon`), so one C++ call sets it for every window the app
    // opens. The mark is the loop from `web/site/icons/favicon.svg`.
    if let Ok(path) = std::ffi::CString::new(app_icon_file()) {
        // SAFETY: a NUL-terminated path, read only for the length of the
        // call; Qt copies what it needs.
        unsafe { bm_set_window_icon(path.as_ptr()) };
    }
    engine.load_data(include_str!("app.qml").into());
    engine.exec();
}

/// Terminal log line, stamped with the time since the app started.
///
/// The GUI has no console of its own: the QML window only knows "busy" or
/// "not busy", so a slow phase looks exactly like a hung one. Everything
/// worth watching therefore goes to stderr, where a run from a terminal
/// shows it.
fn log(msg: impl AsRef<str>) {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    eprintln!("[{:>8.3}s] {}", start.elapsed().as_secs_f64(), msg.as_ref());
}

/// Names the phase a share is in and keeps saying so every few seconds.
///
/// Hashing a large file, zipping a directory and waiting on the server are
/// all silent; without this the terminal is silent too and the user cannot
/// tell work from a hang. Dropping the guard stops the ticker.
struct Phase {
    text: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    ticker: tokio::task::JoinHandle<()>,
}

impl Phase {
    fn start(what: &str) -> Self {
        let text = Arc::new(Mutex::new(what.to_string()));
        let stop = Arc::new(AtomicBool::new(false));
        let ticker = {
            let text = text.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let what = text.lock().unwrap().clone();
                    log(format!("still {what}…"));
                }
            })
        };
        log(what);
        Self { text, stop, ticker }
    }

    fn set(&self, what: &str) {
        *self.text.lock().unwrap() = what.to_string();
        log(what);
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.ticker.abort();
    }
}



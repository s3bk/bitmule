use c_str_macro::c_str;
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
    host == "mul.li" || host == "bitmule.net" || host.ends_with(".bitmule.net")
}

const OPTIONS_FILE_NAME: &str = "bitmule-qt6-options.json";

/// Prepare a bitmule share from `files` and spawn the send task in the
/// background. Returns the share URL as soon as the session exists (the data
/// is hashed for the link's signature first); the transfer keeps running in
/// a detached tokio task until the receivers that connected are done.
///
/// One file is sent as it is; several files, or a directory, go as a zip the
/// builder makes. v2 has no "keep the link live for more receivers" mode, so
/// the old multi-send option no longer does anything.
///
/// Every stage says so on stderr: the window only shows "Preparing…", and a
/// phase that takes minutes (hashing a big file, zipping a directory, the
/// server's proof of work) has to be distinguishable from a hang.
async fn share(files: Vec<PathBuf>) -> Result<Url, String> {
    use bitmule::v2::{self, Options, Server};
    use bitmule_client_common::transfer::{Storage, TransferBuilder};

    // The host the web app lives on, and the only one that answers /pow and
    // /ws/create: https://bitmule.qdat.net no longer terminates TLS, so no
    // session can be made there and the UI would wait for a link forever.
    const SERVER: &str = "https://bitmule.net";

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

    // hashes the data for the link's signature (and builds the zip, if any)
    let phase = Phase::start("hashing the data for the link signature");
    let (manifest, transfer) = match builder.commit_async().await {
        Ok(v) => v,
        Err(e) => return Err(format!("prepare: {e:#}")),
    };
    log("share: hashed, the data is ready to send");

    let server = Server::parse(SERVER);
    let (link_tx, link_rx) = tokio::sync::oneshot::channel::<String>();
    phase.set("waiting for bitmule.net (proof of work, then the session)");
    tokio::spawn(async move {
        let server_for_url = server.clone();
        let mut link_tx = Some(link_tx);
        let result = v2::run_send(&server, manifest, transfer, Options::default(), move |link| {
            if let Some(tx) = link_tx.take() {
                let _ = tx.send(server_for_url.link_url(link));
            }
        })
        .await;
        match result {
            Ok(()) => log("share: send finished, the link stays valid while peers use it"),
            Err(e) => log(format!("share: send failed: {e:#}")),
        }
    });

    // Making the session is the server's answer, before any data moves, so a
    // minute here is generous — and better than the tab waiting forever.
    let outcome = match tokio::time::timeout(Duration::from_secs(60), link_rx).await {
        Ok(Ok(url)) => Url::parse(&url).map_err(|e| format!("bad share URL from the server: {e}")),
        Ok(Err(_)) => Err(format!("couldn't reach {SERVER}")),
        Err(_) => Err(format!("{SERVER} didn't answer within 60 s")),
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

    // Invokable methods from QML
    add_files: qt_method!(fn(&mut self, urls: QVariantList)),
    trigger_share: qt_method!(fn(&mut self)),
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
}

impl UploaderApi {
    fn add_files(&mut self, urls: QVariantList) {
        let mut paths = self.paths.borrow_mut();
        let mut list = self.file_list.clone();

        for url_var in urls.into_iter() {
            let url_str = url_var.to_qstring().to_string();
            // Clean up file:// prefix from Qt URLs
            let clean_path = url_str.trim_start_matches("file://");
            let path = PathBuf::from(clean_path);

            paths.push(path.clone());
            list.push(QString::from(clean_path));
        }

        self.file_list = QStringList::from(list);
        self.file_list_changed();
    }

    fn trigger_share(&mut self) {
        log(format!("share: button pressed, {} path(s) in the list", self.paths.borrow().len()));
        self.is_busy = true;
        self.is_busy_changed();
        // a new attempt at once: the old link (and any old error) is stale
        self.share_url = QString::default();
        self.qr_data_url = QString::default();
        self.share_error = QString::default();
        self.share_url_changed();
        self.qr_data_url_changed();
        self.share_error_changed();

        let paths = self.paths.borrow().clone();
        let active_urls = self.active_share_urls.clone();
        let qpointer = QPointer::from(&*self);

        // Run async operation
        qmetaobject::future::execute_async(async move {
            let result = share(paths).await;

            // Everything that has to reach the UI, done on the main thread:
            // the clipboard copy can happen from here, the properties may not.
            let outcome = match result {
                Ok(url) => {
                    let url_str = url.to_string();
                    // The symbol carries the printed spelling of the same 32 bytes.
                    let qr = qr_data_url_for(&print_text_for(&url_str));
                    // Register the URL as own-upload so the clipboard watcher
                    // ignores it if the user copies it and it comes back
                    // through the poll.
                    if is_bitmule_link(&url_str) {
                        if let Ok(mut v) = active_urls.lock() { v.push(url_str.clone()); }
                    }
                    // Copy to clipboard before touching the UI so the user
                    // sees the URL appear and can already paste it. Failures
                    // (no display, missing xdg utilities) are non-fatal — a
                    // Copy button in the QML will let the user try again.
                    copy_to_clipboard(&url_str);
                    Ok((url_str, qr))
                }
                Err(e) => Err(e),
            };

            // Update UI safely on main thread
                if let Some(api) = qpointer.as_pinned() {
                    log("share: handing the result to the window");
                    {
                        let mut a = api.borrow_mut();
                        match outcome {
                            Ok((url_str, qr)) => {
                                a.share_url = QString::from(url_str);
                                a.qr_data_url = QString::from(qr);
                            }
                            Err(e) => a.share_error = QString::from(e),
                        }
                        a.is_busy = false;
                    }
                    api.borrow_mut().share_url_changed();
                    api.borrow_mut().qr_data_url_changed();
                    api.borrow_mut().share_error_changed();
                    api.borrow_mut().is_busy_changed();
                } else {
                    log("share: the window is gone, dropping the result");
                }
        });
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
    }

    fn add_recv_url(&mut self, url: QString) {
        let u = url.to_string();
        let u_trim = u.trim().to_string();
        if !is_bitmule_link(&u_trim) {
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
            // a share link can name any server: not one without TLS
            let result = match bitmule::v2::Server::parse_checked(&server, false) {
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RecvTransferState {
    url: String,
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
    let server = before.trim_end_matches('/').to_string();
    let fragment = after.trim_start_matches('#').to_string();
    if server.is_empty() || fragment.is_empty() { return None; }
    Some((server, fragment))
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
    qml_register_type::<UploaderApi>(c_str!("Uploader"), 1, 0, c_str!("UploaderApi"));
    qml_register_type::<account::AccountApi>(c_str!("Uploader"), 1, 0, c_str!("AccountApi"));

    let mut engine = QmlEngine::new();
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
    text: Arc<Mutex<&'static str>>,
    stop: Arc<AtomicBool>,
    ticker: tokio::task::JoinHandle<()>,
}

impl Phase {
    fn start(what: &'static str) -> Self {
        let text = Arc::new(Mutex::new(what));
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
                    let what = *text.lock().unwrap();
                    log(format!("still {what}…"));
                }
            })
        };
        log(what);
        Self { text, stop, ticker }
    }

    fn set(&self, what: &'static str) {
        *self.text.lock().unwrap() = what;
        log(what);
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.ticker.abort();
    }
}



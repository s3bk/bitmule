use c_str_macro::c_str;
use qmetaobject::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use url::Url;

const BITMULE_URL_PREFIX: &str = "https://bitmule.qdat.net/#";
const OPTIONS_FILE_NAME: &str = "bitmule-qt6-options.json";

/// Prepare a bitmule share for the first file in `files` and spawn the
/// send task in the background. Returns the share URL as soon as the
/// commitment hash finishes — the actual transfer keeps running in a
/// detached tokio task in `ServeMode::Multi` until the app exits.
///
/// Multiple files: only the first is sent for now; bitmule's wire is
/// one-file-per-session. Follow-up: iterate + return a list of URLs
/// or zip on the fly.
async fn share(files: Vec<PathBuf>, multi_send: bool) -> Url {
    use bitmule_client_native::{send_file_multi, ServeMode};
    use bitmule_crypto::{BulkKey, CommitmentHasher, ShareKey, ShareLink};
    use tokio::io::AsyncReadExt;

    const SERVER: &str = "https://bitmule.qdat.net";
    let err_url = |msg: &str| {
        Url::parse(&format!("about:blank#error={}", urlencoding_min(msg)))
            .unwrap_or_else(|_| Url::parse("about:blank").unwrap())
    };

    let path = match files.into_iter().next() {
        Some(p) => p,
        None => return err_url("no file selected"),
    };

    // Stat + commitment: stream-hash the file with a fresh bulk_key to
    // produce SHA256(data || bulk_key), the URL-committed signature.
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) if m.is_file() => m,
        Ok(_) => return err_url("not a regular file"),
        Err(e) => return err_url(&format!("stat: {e}")),
    };
    let _ = meta;

    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let signature = {
        let mut f = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) => return err_url(&format!("open: {e}")),
        };
        let mut hasher = CommitmentHasher::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match f.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) => return err_url(&format!("read: {e}")),
            }
        }
        hasher.finalize(&bulk_key)
    };

    let link = ShareLink::new(share_key.clone(), signature);
    let url_str = format!("{}/#{}", SERVER.trim_end_matches('/'), link.to_b64_url());

    // Fire-and-forget the send task. Mode: Multi if multi_send option
    // is on (URL stays live, unlimited receivers), Complete if off
    // (exits after first receiver's done_ack). Either way, any
    // receiver who opens the URL gets a fresh KEX + AEAD stream.
    let path_clone = path.clone();
    let mode = if multi_send { ServeMode::Multi } else { ServeMode::Complete };
    tokio::spawn(async move {
        if let Err(e) = send_file_multi(
            SERVER, share_key, bulk_key, path_clone, mode,
        ).await {
            eprintln!("bitmule send failed: {e:#}");
        }
    });

    Url::parse(&url_str).unwrap_or_else(|_| err_url("URL build"))
}

/// Minimal percent-encoding for stuffing an error message into a URL
/// fragment. Not RFC-3986-complete; only escapes what would break
/// `Url::parse` on the return path.
fn urlencoding_min(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

#[derive(QObject, Default)]
struct UploaderApi {
    base: qt_base_class!(trait QObject),

    // State properties
    is_busy: qt_property!(bool; NOTIFY is_busy_changed),
    share_url: qt_property!(QString; NOTIFY share_url_changed),
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

    // F02 fetch queue: bitmule URLs the clipboard watcher has detected
    // that are NOT this app's own shares. Bind on ListView / repeater.
    fetch_queue: qt_property!(QStringList; NOTIFY fetch_queue_changed),

    // Signals
    is_busy_changed: qt_signal!(),
    share_url_changed: qt_signal!(),
    qr_data_url_changed: qt_signal!(),
    file_list_changed: qt_signal!(),
    opt_multi_send_changed: qt_signal!(),
    opt_upnp_changed: qt_signal!(),
    opt_clipboard_watch_changed: qt_signal!(),
    opt_auto_download_changed: qt_signal!(),
    fetch_queue_changed: qt_signal!(),

    // Shared paths state
    paths: Rc<RefCell<Vec<PathBuf>>>,
    /// Snapshot of currently-live share URLs so the clipboard watcher
    /// can suppress own-uploads (avoid queueing a URL we just minted).
    active_share_urls: Arc<Mutex<Vec<String>>>,
    /// Queue of clipboard-detected bitmule URLs.
    fetch_queue_urls: Arc<Mutex<Vec<String>>>,

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
        self.is_busy = true;
        self.is_busy_changed();

        let paths = self.paths.borrow().clone();
        let multi_send = self.opt_multi_send;
        let active_urls = self.active_share_urls.clone();
        let qpointer = QPointer::from(&*self);

        // Run async operation
        qmetaobject::future::execute_async(async move {
            let url = share(paths, multi_send).await;
            let url_str = url.to_string();
            let qr = qr_data_url_for(&url_str);
            // Register the URL as own-upload so the clipboard watcher
            // ignores it if the user copies it and it comes back
            // through the poll.
            if url_str.starts_with(BITMULE_URL_PREFIX) {
                if let Ok(mut v) = active_urls.lock() { v.push(url_str.clone()); }
            }

            // Copy to clipboard before touching the UI so the user
            // sees the URL appear and can already paste it. Failures
            // (no display, missing xdg utilities) are non-fatal — a
            // Copy button in the QML will let the user try again.
            copy_to_clipboard(&url_str);

            // Update UI safely on main thread
            if let Some(api) = qpointer.as_pinned() {
                {
                    let mut a = api.borrow_mut();
                    a.share_url = QString::from(url_str);
                    a.qr_data_url = QString::from(qr);
                    a.is_busy = false;
                }
                api.borrow_mut().share_url_changed();
                api.borrow_mut().qr_data_url_changed();
                api.borrow_mut().is_busy_changed();
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
        self.opt_multi_send_changed();
        self.opt_upnp_changed();
        self.opt_clipboard_watch_changed();
        self.opt_auto_download_changed();

        if opts.clipboard_watch {
            self.spawn_clipboard_watcher();
        }
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
                if !trimmed.starts_with(BITMULE_URL_PREFIX)
                    || trimmed.len() <= BITMULE_URL_PREFIX.len() { continue; }
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
}
fn default_true() -> bool { true }

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
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| OptionsSnapshot {
            multi_send: true, upnp: false, clipboard_watch: false, auto_download: false,
        }),
        Err(_) => OptionsSnapshot {
            multi_send: true, upnp: false, clipboard_watch: false, auto_download: false,
        },
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

/// Cross-platform clipboard copy via `arboard`. Returns false and
/// logs on failure (no display, missing xsel/xclip/wl-clipboard on
/// Linux, permission denied on macOS/Windows). Non-fatal — the
/// user's next click on the Copy button retries.
fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("clipboard copy failed: {e}");
            false
        }
    }
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
    use qrcode::QrCode;

    if text.is_empty() { return String::new(); }
    let code = match QrCode::new(text.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("qr generation failed: {e}");
            return String::new();
        }
    };
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
    qml_register_type::<UploaderApi>(c_str!("Uploader"), 1, 0, c_str!("UploaderApi"));

    let mut engine = QmlEngine::new();
    engine.load_data(include_str!("app.qml").into());
    engine.exec();
}

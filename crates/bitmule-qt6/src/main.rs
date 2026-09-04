use c_str_macro::c_str;
use qmetaobject::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use url::Url;

/// Prepare a bitmule share for the first file in `files` and spawn the
/// send task in the background. Returns the share URL as soon as the
/// commitment hash finishes — the actual transfer keeps running in a
/// detached tokio task in `ServeMode::Multi` until the app exits.
///
/// Multiple files: only the first is sent for now; bitmule's wire is
/// one-file-per-session. Follow-up: iterate + return a list of URLs
/// or zip on the fly.
async fn share(files: Vec<PathBuf>) -> Url {
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

    // Fire-and-forget the send task. Multi mode = runs until app exit.
    // Any receiver who opens the URL gets a fresh KEX + AEAD stream.
    let path_clone = path.clone();
    tokio::spawn(async move {
        if let Err(e) = send_file_multi(
            SERVER, share_key, bulk_key, path_clone, ServeMode::Multi,
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
    file_list: qt_property!(QStringList; NOTIFY file_list_changed),

    // Signals
    is_busy_changed: qt_signal!(),
    share_url_changed: qt_signal!(),
    file_list_changed: qt_signal!(),

    // Shared paths state
    paths: Rc<RefCell<Vec<PathBuf>>>,

    // Invokable method from QML
    add_files: qt_method!(fn(&mut self, urls: QVariantList)),
    trigger_share: qt_method!(fn(&mut self)),
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
        let qpointer = QPointer::from(&*self);

        // Run async operation
        qmetaobject::future::execute_async(async move {
            let url = share(paths).await;

            // Update UI safely on main thread
            if let Some(mut api) = qpointer.as_pinned() {
                api.borrow_mut().share_url = QString::from(url.to_string());
                api.borrow_mut().share_url_changed();

                api.borrow_mut().is_busy = false;
                api.borrow_mut().is_busy_changed();
            }
        });
    }
}

#[tokio::main]
async fn main() {
    qml_register_type::<UploaderApi>(c_str!("Uploader"), 1, 0, c_str!("UploaderApi"));

    let mut engine = QmlEngine::new();
    engine.load_data(include_str!("app.qml").into());
    engine.exec();
}

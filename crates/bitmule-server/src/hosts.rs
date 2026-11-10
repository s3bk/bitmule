//! The links-only host.
//!
//! A share link carries its key in the fragment, so it needs no path:
//! `https://mul.li#<key>` is the whole address. That host therefore has no
//! front door, nothing to browse and nothing to create — it serves the viewer
//! at `/`, the viewer's own assets, and the key-addressed `/v1/pub/…` routes
//! the page calls same-origin. Everything else gets one page saying where the
//! browsable host is.
//!
//! Why a second listener and not a `Host` check: a TLS terminator in front
//! rewrites `Host` to the upstream it dialled, so the header cannot be trusted
//! to tell the two names apart. A port can, because the proxy's own config
//! chooses which one it dials.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio_util::io::ReaderStream;

use crate::share::store::IO_BUFFER;

/// Everything the link host will hand out besides the viewer document. One
/// list, so a new icon cannot be served on one host and 404 on the other.
const ASSETS: &[&str] = &[
    "style.css",
    "bm.js",
    "md.js",
    "preview.js",
    "index.js",
    "l.js",
    "d.js",
    "u.js",
    "new.js",
    "inbox.js",
    "selftest.js",
    "favicon.svg",
    "favicon-16.png",
    "favicon-32.png",
    "favicon.ico",
    "apple-touch-icon.png",
    "icon-192.png",
    "pv/cage.html",
    "pdf/pdf_web.wasm",
    "pdf/standard_fonts.br",
];

pub struct Site {
    /// The directory the viewer and its assets live in.
    pub web_dir: PathBuf,
    /// The host that does have a front door; the 404 page points at it.
    pub main_host: String,
}

impl Site {
    fn safe_host(&self) -> &str {
        // Operator-set, but never trust a string that ends up in markup.
        if self
            .main_host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        {
            &self.main_host
        } else {
            "bitmule.net"
        }
    }
}

/// The link host's router: the viewer, its assets, and `api` (the share and
/// invite routes) — nothing else.
pub fn link_router(api: Router, site: Site) -> Router {
    let site = Arc::new(site);
    let pages: Router = Router::new()
        .route("/", get(viewer))
        .route("/index.html", get(viewer))
        // `/d` and `/u` are the shape links printed before the pathless form
        // had; they open the same document, which tells the roles apart by key
        // length anyway.
        .route("/d", get(viewer))
        .route("/u", get(viewer))
        .route("/healthz", get(healthz))
        .fallback(asset_or_404)
        .with_state(site);
    pages.merge(api)
}

async fn viewer(State(site): State<Arc<Site>>) -> Response {
    serve(&site.web_dir, "l.html").await
}

async fn healthz() -> Response {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        format!("{{\"ok\":true,\"now\":{now}}}"),
    )
        .into_response()
}

async fn asset_or_404(State(site): State<Arc<Site>>, req: Request) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = req.uri().path().trim_start_matches('/');
    if ASSETS.contains(&path) {
        let mut response = serve(&site.web_dir, path).await;
        if path == "pdf/standard_fonts.br" {
            response
                .headers_mut()
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        }
        response
    } else {
        no_front_door(site.safe_host())
    }
}

/// Stream a file from the web directory. Never read whole: a 3.8 MB wasm
/// module costs a 256 KiB buffer per request, like every other body here.
async fn serve(web: &Path, rel: &str) -> Response {
    let path = web.join(rel);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let size = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let body = Body::from_stream(ReaderStream::with_capacity(file, IO_BUFFER));
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(rel)),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    response
}

fn content_type(rel: &str) -> &'static str {
    match rel.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn no_front_door(main_host: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>bitmule</title><style>body{{font:16px system-ui,sans-serif;margin:4rem auto;\
max-width:32rem;padding:0 1rem;line-height:1.5;color:#222}}\
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}}</style></head><body>\
<h1>This host serves links only</h1>\
<p>A bitmule link puts its key in the fragment, so it needs no path.</p>\
<p>To create a link or open your inbox, go to <a href=\"https://{main_host}/\">https://{main_host}/</a>.</p>\
</body></html>\n"
    );
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],
        html,
    )
        .into_response()
}

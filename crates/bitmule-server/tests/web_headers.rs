//! The web app holds a transfer's secret in the URL fragment, so what it may
//! load and where it may send data is pinned down here.

use std::sync::Arc;

use axum::{body::Body, http::Request};
use bitmule_server::{AppState, router, security_headers};
use tower::ServiceExt;

fn web_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web")
}

#[tokio::test]
async fn pages_carry_the_content_policy() {
    let app = security_headers(router(Arc::new(AppState::new())).fallback_service(
        tower_http::services::ServeDir::new(web_dir()).append_index_html_on_directories(true),
    ));

    let response = app.clone().oneshot(Request::get("/").body(Body::empty()).unwrap()).await.unwrap();
    let csp = response.headers()["content-security-policy"].to_str().unwrap().to_string();
    assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'") && csp.contains("connect-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'") && !csp.contains("unsafe-inline"));
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");

    // the API answers with the headers too
    let response = app.clone().oneshot(Request::get("/pow").body(Body::empty()).unwrap()).await.unwrap();
    assert!(response.headers().contains_key("content-security-policy"));

    // the marketing page is the one exception to the content policy
    let response = app.oneshot(Request::get("/bitmule.html").body(Body::empty()).unwrap()).await.unwrap();
    assert!(!response.headers().contains_key("content-security-policy"));
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
}

/// The app page loads scripts and styles from its own origin only, and has
/// no inline script. (The content policy enforces it in a browser; this
/// catches it before a release.)
#[test]
fn the_app_page_has_no_third_party_or_inline_scripts() {
    let html = std::fs::read_to_string(web_dir().join("index.html")).unwrap();
    let mut rest = html.as_str();
    let mut scripts = 0;
    while let Some(at) = rest.find("<script") {
        rest = &rest[at..];
        let end = rest.find('>').unwrap();
        let tag = &rest[..end];
        let src = tag.split("src=\"").nth(1).and_then(|s| s.split('"').next()).expect("inline script in index.html");
        assert!(src.starts_with("./") || src.starts_with('/'), "script from elsewhere: {src}");
        let body = &rest[end + 1..rest.find("</script>").unwrap()];
        assert!(body.trim().is_empty(), "inline script in index.html");
        scripts += 1;
        rest = &rest[end..];
    }
    assert!(scripts > 0);
    for tag in html.split("<link").skip(1) {
        let tag = tag.split('>').next().unwrap();
        assert!(!tag.contains("http://") && !tag.contains("https://"), "external resource: <link{tag}>");
    }
    assert!(!html.contains("style=\""), "inline style attributes need style-src 'unsafe-inline'");
}

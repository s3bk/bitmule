//! The web pages hold a transfer's secret in the URL fragment, so what they may
//! load and where they may send data is pinned down here.

use std::sync::Arc;

use axum::{body::Body, http::Request};
use bitmule_server::{AppState, router, security_headers};
use tower::ServiceExt;

fn web_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web")
}

/// The one third party any page may talk to: the marketing page's typefaces.
/// A stylesheet from the first, the font files it names from the second.
const FONT_STYLE_HOST: &str = "https://fonts.googleapis.com";
const FONT_FILE_HOST: &str = "https://fonts.gstatic.com";

#[tokio::test]
async fn pages_carry_the_content_policy() {
    let app = security_headers(bitmule_server::static_site(
        router(Arc::new(AppState::new())),
        &web_dir(),
    ));

    // every page, the marketing one included: it used to be the exception, and
    // a policy that blocks inline styles then left the deployed page unstyled
    for path in ["/", "/index.html", "/app"] {
        let response = app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        let csp = response.headers()["content-security-policy"].to_str().unwrap().to_string();
        assert!(csp.contains("script-src 'self' 'wasm-unsafe-eval'"), "{path}: {csp}");
        assert!(csp.contains("connect-src 'self'"), "{path}: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        assert!(!csp.contains("unsafe-inline"), "{path}: {csp}");
        assert!(csp.contains(FONT_STYLE_HOST) && csp.contains(FONT_FILE_HOST), "{path}: {csp}");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }

    // the stylesheet the marketing page now loads carries the headers too
    let response = app.clone().oneshot(Request::get("/bitmule.css").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("content-security-policy"));

    // the API answers with the headers too
    let response = app.oneshot(Request::get("/pow").body(Body::empty()).unwrap()).await.unwrap();
    assert!(response.headers().contains_key("content-security-policy"));
}

/// The app has one address, `/app`. `/app.html` is where it used to be and
/// redirects there, `/send` is the shape of every invite link already printed
/// and still lands on the app, and `/` is the marketing page and only that.
#[tokio::test]
async fn the_app_lives_at_app() {
    let app = security_headers(bitmule_server::static_site(
        router(Arc::new(AppState::new())),
        &web_dir(),
    ));

    let body_of = |app: axum::Router, path: &'static str| async move {
        let response = app.oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        (response.status(), axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap())
    };

    let (status, body) = body_of(app.clone(), "/app").await;
    assert_eq!(status, 200);
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("id=\"dropzone\""), "/app is not the app");

    let response = app.clone().oneshot(Request::get("/app.html").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), 308);
    assert_eq!(response.headers()["location"], "/app");

    let (status, body) = body_of(app.clone(), "/send").await;
    assert_eq!(status, 200);
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("id=\"dropzone\""), "/send does not land on the app");

    let (status, body) = body_of(app, "/").await;
    assert_eq!(status, 200);
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("hero-title"), "/ is not the marketing page");
}

/// Both pages load scripts and styles from their own origin only, and neither
/// has an inline `<script>`, an inline `<style>` or a `style=` attribute. The
/// content policy enforces it in a browser; this catches it before a release,
/// because the failure is a page that renders bare rather than one that errors.
///
/// `index.html` is the marketing page — the one place a third-party stylesheet
/// is allowed, and only for its typefaces — and `app.html` is the SPA.
#[test]
fn the_pages_carry_no_inline_script_or_style() {
    for name in ["index.html", "app.html"] {
        let html = std::fs::read_to_string(web_dir().join(name)).unwrap();
        let mut rest = html.as_str();
        let mut scripts = 0;
        while let Some(at) = rest.find("<script") {
            rest = &rest[at..];
            let end = rest.find('>').unwrap();
            let tag = &rest[..end];
            let src = tag
                .split("src=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or_else(|| panic!("inline script in {name}"));
            assert!(!src.contains("://") && !src.starts_with("//"), "{name}: script from elsewhere: {src}");
            let body = &rest[end + 1..rest.find("</script>").unwrap()];
            assert!(body.trim().is_empty(), "inline script in {name}");
            scripts += 1;
            rest = &rest[end..];
        }
        assert!(scripts > 0, "{name} loads no script at all");

        assert!(!html.contains("<style"), "{name} has an inline <style>, which the policy blocks");
        assert!(!html.contains("style=\""), "{name} has a style attribute, which the policy blocks");

        for tag in html.split("<link").skip(1) {
            let tag = tag.split('>').next().unwrap();
            let external = tag.contains("http://") || tag.contains("https://");
            if !external {
                continue;
            }
            let fonts = tag.contains(FONT_STYLE_HOST) || tag.contains(FONT_FILE_HOST) || tag.contains("//fonts.");
            assert!(name == "index.html" && fonts, "{name}: external resource <link{tag}>");
        }
    }
}

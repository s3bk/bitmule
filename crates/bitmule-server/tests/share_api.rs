//! The link surfaces, exercised the way the browser calls them: create a
//! share, upload, commit, read ranges back, and the invite -> inbox path.

use bitmule_server::share::{self, Api, Meter, Store};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

const SID: &str = "sh_AAAAAAAAAAAAAAAA";
const IID: &str = "inv_BBBBBBBBBBBBBBBB";
const AUTH: &str = "auth-key-for-the-tests";
const INVITE_KEY: &str = "invite-key-for-the-tests";

fn auth_hash(key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(key.as_bytes()))
}

struct Harness {
    app: Router,
    dir: tempfile::TempDir,
    meter: Arc<Meter>,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::new(dir.path()));
    let meter = Arc::new(Meter::new());
    let cfg = Arc::new(share::Config::default());
    let app = share::router(Api {
        store,
        meter: meter.clone(),
        cfg,
    });
    Harness { app, dir, meter }
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

fn request(method: &str, uri: &str, bearer: Option<&str>, body: impl Into<Body>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(body.into()).unwrap()
}

fn json_request(method: &str, uri: &str, bearer: Option<&str>, value: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::from(value.to_string())).unwrap()
}

async fn create_live_share(h: &Harness, content: &[u8]) {
    let create = json_request(
        "POST",
        "/v1/pub/shares",
        None,
        serde_json::json!({
            "sid": SID,
            "auth_hash": auth_hash(AUTH),
            "files": [{ "uid": "file00000001", "name_enc": "n", "name_iv": "i", "wrapped_kf": "w", "kf_iv": "k", "ct_iv": "c" }],
        }),
    );
    let (status, _, body) = call(&h.app, create).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));

    let upload = request(
        "PUT",
        &format!("/v1/pub/s/{SID}/files/file00000001"),
        Some(AUTH),
        content.to_vec(),
    );
    let (status, _, body) = call(&h.app, upload).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));

    let commit = request("POST", &format!("/v1/pub/s/{SID}/commit"), Some(AUTH), Body::empty());
    let (status, _, _) = call(&h.app, commit).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn share_round_trip_and_ranges() {
    let h = harness();
    let content = b"hello bitmule, this is ciphertext".to_vec();
    create_live_share(&h, &content).await;

    // meta
    let (status, _, body) = call(
        &h.app,
        request("GET", &format!("/v1/pub/s/{SID}/meta"), Some(AUTH), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let meta: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(meta["state"], "live");
    assert_eq!(meta["total_bytes"].as_u64().unwrap(), content.len() as u64);

    // the whole file
    let uri = format!("/v1/pub/s/{SID}/files/file00000001/content");
    let (status, headers, body) = call(&h.app, request("GET", &uri, Some(AUTH), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content);
    assert_eq!(headers[header::ACCEPT_RANGES], "bytes");
    assert_eq!(
        headers[header::CONTENT_LENGTH].to_str().unwrap(),
        content.len().to_string()
    );

    // a range
    let mut ranged = request("GET", &uri, Some(AUTH), Body::empty());
    ranged.headers_mut().insert(header::RANGE, "bytes=6-12".parse().unwrap());
    let (status, headers, body) = call(&h.app, ranged).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, b"bitmule");
    assert_eq!(
        headers[header::CONTENT_RANGE],
        format!("bytes 6-12/{}", content.len())
    );

    // a suffix range
    let mut tail = request("GET", &uri, Some(AUTH), Body::empty());
    tail.headers_mut().insert(header::RANGE, "bytes=-6".parse().unwrap());
    let (status, _, body) = call(&h.app, tail).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, b"ertext");

    // past the end
    let mut beyond = request("GET", &uri, Some(AUTH), Body::empty());
    beyond.headers_mut().insert(header::RANGE, "bytes=9999-".parse().unwrap());
    let (status, headers, _) = call(&h.app, beyond).await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(headers[header::CONTENT_RANGE], format!("bytes */{}", content.len()));

    // egress was billed to the share, for the bytes that left
    let n = h.meter.flush(&h.dir.path().join("usage.tsv")).await.unwrap();
    assert_eq!(n, 1, "one row for one share and one day");
    let usage = std::fs::read_to_string(h.dir.path().join("usage.tsv")).unwrap();
    let bytes: u64 = usage
        .lines()
        .next()
        .unwrap()
        .split('\t')
        .nth(3)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        bytes,
        content.len() as u64 + 7 + 6,
        "whole file + the two ranges, and nothing for the 416"
    );
    assert!(usage.contains(SID));
}

#[tokio::test]
async fn share_needs_the_key() {
    let h = harness();
    create_live_share(&h, b"secret").await;

    let uri = format!("/v1/pub/s/{SID}/meta");
    let (status, _, _) = call(&h.app, request("GET", &uri, None, Body::empty())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, _) = call(&h.app, request("GET", &uri, Some("wrong"), Body::empty())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // deleting with the key takes the bytes with it
    let (status, _, _) = call(
        &h.app,
        request("DELETE", &format!("/v1/pub/s/{SID}"), Some(AUTH), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = call(&h.app, request("GET", &uri, Some(AUTH), Body::empty())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invite_to_inbox() {
    let h = harness();
    let create = json_request(
        "POST",
        &format!("/v1/pub/i/{IID}"),
        None,
        serde_json::json!({
            "auth_hash": auth_hash(INVITE_KEY),
            "pubkey": "granter-public-key",
            "label": "from the tests",
            "max_bytes": 1024,
            "max_files": 2,
        }),
    );
    let (status, _, body) = call(&h.app, create).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let granter = created["granter_token"].as_str().unwrap().to_string();
    assert!(granter.starts_with("gt_"));

    // the uploader, holding the invite key, sends one file
    let mut upload = request(
        "PUT",
        &format!("/v1/pub/i/{IID}/uploads/item00000001"),
        Some(INVITE_KEY),
        b"for-the-granter".to_vec(),
    );
    upload.headers_mut().insert("x-bm-epk", "ephemeral".parse().unwrap());
    let (status, _, body) = call(&h.app, upload).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let uploaded: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        uploaded["used_bytes"].as_u64().unwrap(),
        "for-the-granter".len() as u64
    );

    let commit = request(
        "POST",
        &format!("/v1/pub/i/{IID}/uploads/item00000001/commit"),
        Some(INVITE_KEY),
        Body::empty(),
    );
    let (status, _, _) = call(&h.app, commit).await;
    assert_eq!(status, StatusCode::OK);

    // the invite is one-time by default: closed after the commit
    let (status, _, _) = call(
        &h.app,
        request("GET", &format!("/v1/pub/i/{IID}/status"), Some(INVITE_KEY), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);

    // the granter sees it in the inbox
    let (status, _, body) = call(&h.app, request("GET", "/v1/inbox", Some(&granter), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    let inbox: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["id"], "item00000001");
    assert_eq!(inbox["items"][0]["label"], "from the tests");
    assert_eq!(inbox["items"][0]["epk"], "ephemeral");

    // and can fetch the bytes
    let (status, _, body) = call(
        &h.app,
        request("GET", "/v1/inbox/item00000001/content", Some(&granter), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"for-the-granter");

    // somebody else's token sees nothing
    let (status, _, body) = call(&h.app, request("GET", "/v1/inbox", Some("gt_wrong"), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    let empty: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(empty["items"].as_array().unwrap().is_empty());

    // taking it back empties the item and frees the cap
    let (status, _, _) = call(
        &h.app,
        request("DELETE", "/v1/inbox/item00000001", Some(&granter), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, body) = call(&h.app, request("GET", "/v1/inbox", Some(&granter), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    let inbox: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(inbox["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn invite_caps_are_enforced_while_streaming() {
    let h = harness();
    let create = json_request(
        "POST",
        &format!("/v1/pub/i/{IID}"),
        None,
        serde_json::json!({
            "auth_hash": auth_hash(INVITE_KEY),
            "pubkey": "granter-public-key",
            "max_bytes": 4,
        }),
    );
    let (status, _, _) = call(&h.app, create).await;
    assert_eq!(status, StatusCode::CREATED);

    let upload = request(
        "PUT",
        &format!("/v1/pub/i/{IID}/uploads/toolong00001"),
        Some(INVITE_KEY),
        b"five!".to_vec(),
    );
    let (status, _, body) = call(&h.app, upload).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&body));
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "too_large");

    // the rejected bytes are not on the disk, not even as a part file
    let uploads = h.dir.path().join("invites").join(IID).join("uploads");
    let leftovers: Vec<_> = match std::fs::read_dir(&uploads) {
        Ok(rd) => rd.flatten().map(|e| e.file_name()).collect(),
        Err(_) => Vec::new(),
    };
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[tokio::test]
async fn gate_covers_creation_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::new(dir.path()));
    let meter = Arc::new(Meter::new());
    let cfg = Arc::new(share::Config {
        max_upload: share::DEFAULT_MAX_UPLOAD,        gate: Some("let-me-in".to_string()),
    });
    let app = share::router(Api { store, meter, cfg });

    // no password: refused before anything is stored
    let create = json_request(
        "POST",
        "/v1/pub/shares",
        None,
        serde_json::json!({ "sid": SID, "auth_hash": auth_hash(AUTH), "files": [] }),
    );
    let (status, _, _) = call(&app, create).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // with it, creation works
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode("bm:let-me-in");
    let mut create = json_request(
        "POST",
        "/v1/pub/shares",
        None,
        serde_json::json!({ "sid": SID, "auth_hash": auth_hash(AUTH), "files": [] }),
    );
    create
        .headers_mut()
        .insert(header::AUTHORIZATION, format!("Basic {basic}").parse().unwrap());
    let (status, _, body) = call(&app, create).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));

    // reading a link never asks for the password
    let (status, _, _) = call(
        &app,
        request("GET", &format!("/v1/pub/s/{SID}/meta"), Some(AUTH), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ------------------------------------------------------------ resuming

fn bytes_of(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn share_file_uri(uid: &str) -> String {
    format!("/v1/pub/s/{SID}/files/{uid}")
}

#[tokio::test]
async fn upload_resumes_after_a_cut() {
    let h = harness();
    let content = bytes_of(40_000);
    let half = content.len() / 2;

    let create = json_request(
        "POST",
        "/v1/pub/shares",
        None,
        serde_json::json!({
            "sid": SID,
            "auth_hash": auth_hash(AUTH),
            "files": [{ "uid": "file00000001", "size": content.len() }],
        }),
    );
    let (status, _, body) = call(&h.app, create).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));

    let uri = share_file_uri("file00000001");

    // nothing has arrived: the client is told the whole truth before it starts
    let (status, headers, body) = call(&h.app, request("GET", &uri, Some(AUTH), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-bm-offset"], "0");
    assert_eq!(headers["x-bm-total"], content.len().to_string());
    let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(state["uploaded"], false);

    // the connection dies halfway through the body
    let cut = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(bytes::Bytes::from(content[..half].to_vec())),
        Err(std::io::Error::other("connection cut")),
    ]);
    let mut interrupted = request("PUT", &uri, Some(AUTH), Body::from_stream(cut));
    interrupted.headers_mut().insert(
        "content-range",
        format!("bytes 0-{last}/{total}", last = half - 1, total = content.len())
            .parse()
            .unwrap(),
    );
    let (status, _, _) = call(&h.app, interrupted).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a cut body is a bad body");

    // what did arrive is still there, and the server says how much
    let (status, headers, body) = call(&h.app, request("GET", &uri, Some(AUTH), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-bm-offset"], half.to_string());
    let state: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(state["stored"].as_u64().unwrap(), half as u64);
    assert_eq!(state["uploaded"], false);

    // guessing wrong costs no bytes: the answer is the real offset
    let mut wrong = request("PUT", &uri, Some(AUTH), content[..8].to_vec());
    wrong
        .headers_mut()
        .insert("upload-offset", "7".parse().unwrap());
    let (status, headers, _) = call(&h.app, wrong).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(headers["x-bm-offset"], half.to_string());

    // resuming from the truth finishes the file — and it need not repeat the
    // total, because creation already declared what the file would weigh
    let mut resume = request("PUT", &uri, Some(AUTH), content[half..].to_vec());
    resume
        .headers_mut()
        .insert("upload-offset", half.to_string().parse().unwrap());
    let (status, headers, body) = call(&h.app, resume).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["x-bm-offset"], content.len().to_string());

    let commit = request("POST", &format!("/v1/pub/s/{SID}/commit"), Some(AUTH), Body::empty());
    let (status, _, body) = call(&h.app, commit).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    let (status, headers, body) = call(
        &h.app,
        request("GET", &format!("/v1/pub/s/{SID}/files/file00000001/content"), Some(AUTH), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content, "every resumed byte is the byte that was sent");
    assert!(headers.contains_key(header::ETAG));

    // the part file is gone: one file, one name
    let left: Vec<_> = std::fs::read_dir(h.dir.path().join("shares").join(SID))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!left.iter().any(|n| n.ends_with(".part")), "left behind: {left:?}");
}

#[tokio::test]
async fn finishing_twice_is_harmless() {
    let h = harness();
    let content = bytes_of(9_000);
    create_live_share(&h, &content).await;
    let uri = share_file_uri("file00000001");

    // the response to the last chunk was lost: the client asks again saying
    // "I have all of it", and gets the same answer without resending anything
    let mut retry = request("PUT", &uri, Some(AUTH), Body::empty());
    retry
        .headers_mut()
        .insert("upload-offset", content.len().to_string().parse().unwrap());
    let (status, headers, _) = call(&h.app, retry).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(headers["x-bm-offset"], content.len().to_string());

    let (status, _, body) = call(
        &h.app,
        request("GET", &format!("/v1/pub/s/{SID}/files/file00000001/content"), Some(AUTH), Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content);
}

#[tokio::test]
async fn download_resumes_with_if_range() {
    let h = harness();
    let content = bytes_of(30_000);
    create_live_share(&h, &content).await;
    let uri = format!("/v1/pub/s/{SID}/files/file00000001/content");

    let (status, headers, body) = call(&h.app, request("GET", &uri, Some(AUTH), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content);
    let etag = headers[header::ETAG].to_str().unwrap().to_string();
    assert!(etag.starts_with('"') && etag.ends_with('"'));

    // the first part of a download that will be cut
    let cut = content.len() / 3;
    let mut first = request("GET", &uri, Some(AUTH), Body::empty());
    first
        .headers_mut()
        .insert(header::RANGE, format!("bytes=0-{}", cut - 1).parse().unwrap());
    let (status, headers, body) = call(&h.app, first).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, &content[..cut]);
    assert_eq!(headers[header::ETAG], etag.as_str());

    // the rest, revalidated with the tag the first answer carried
    let mut rest = request("GET", &uri, Some(AUTH), Body::empty());
    rest.headers_mut()
        .insert(header::RANGE, format!("bytes={cut}-").parse().unwrap());
    rest.headers_mut()
        .insert(header::IF_RANGE, etag.parse().unwrap());
    let (status, headers, body) = call(&h.app, rest).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, &content[cut..]);
    assert_eq!(
        headers[header::CONTENT_RANGE],
        format!("bytes {cut}-{}/{}", content.len() - 1, content.len())
    );

    // a tag that no longer holds gets the whole file rather than a splice
    let mut stale = request("GET", &uri, Some(AUTH), Body::empty());
    stale
        .headers_mut()
        .insert(header::RANGE, format!("bytes={cut}-").parse().unwrap());
    stale
        .headers_mut()
        .insert(header::IF_RANGE, "\"some-older-tag\"".parse().unwrap());
    let (status, _, body) = call(&h.app, stale).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content);
}

#[tokio::test]
async fn invite_upload_resumes() {
    let h = harness();
    let content = bytes_of(600);
    let half = content.len() / 2;

    let create = json_request(
        "POST",
        &format!("/v1/pub/i/{IID}"),
        None,
        serde_json::json!({
            "auth_hash": auth_hash(INVITE_KEY),
            "pubkey": "granter-public-key",
            "max_bytes": 1024,
        }),
    );
    let (status, _, _) = call(&h.app, create).await;
    assert_eq!(status, StatusCode::CREATED);

    let uri = format!("/v1/pub/i/{IID}/uploads/item00000001");
    let mut first = request("PUT", &uri, Some(INVITE_KEY), content[..half].to_vec());
    first.headers_mut().insert(
        "content-range",
        format!("bytes 0-{last}/{total}", last = half - 1, total = content.len())
            .parse()
            .unwrap(),
    );
    let (status, headers, _) = call(&h.app, first).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers["x-bm-offset"], half.to_string());

    // the part is not billed yet: the invite still has room for the rest
    let (status, headers, _) = call(&h.app, request("GET", &uri, Some(INVITE_KEY), Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-bm-offset"], half.to_string());
    assert_eq!(headers["x-bm-remaining"], "1024");

    let mut resume = request("PUT", &uri, Some(INVITE_KEY), content[half..].to_vec());
    resume
        .headers_mut()
        .insert("upload-offset", half.to_string().parse().unwrap());
    resume
        .headers_mut()
        .insert("upload-length", content.len().to_string().parse().unwrap());
    let (status, _, body) = call(&h.app, resume).await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let uploaded: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(uploaded["used_bytes"].as_u64().unwrap(), content.len() as u64);
}

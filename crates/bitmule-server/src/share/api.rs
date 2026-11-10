//! The link surfaces: shares, invites and the granter's inbox.
//!
//! What this half of the server is: the smallest thing that ends a link. It
//! stores ciphertext it cannot read, hashes of bearers it cannot reverse, and
//! the caps of an invite. There are no accounts and no session cookie; a
//! credential is always a key that came in a link, or the granter token a
//! person was handed once when they made an invite.
//!
//! It sits beside the signaling and relay surfaces rather than replacing
//! them: `/v1/pub/…` is what a link is, `/ws/…` and `/session/…` are how the
//! bytes move when both peers are online.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use super::meter::{self, Kind, Meter, MeterSink};
use super::store::{
    now, Invite, Item, ReceiveError, Share, ShareState, Store, DEFAULT_INVITE_BYTES,
    DEFAULT_INVITE_FILES, DEFAULT_INVITE_TTL, DEFAULT_SHARE_TTL, IO_BUFFER, SESSION_TTL,
};

/// How much the process is willing to hold for one upload. Bodies are streamed,
/// so this is a disk policy, not a memory one.
pub const DEFAULT_MAX_UPLOAD: u64 = 8 << 30;

#[derive(Clone)]
pub struct Config {
    pub max_upload: u64,
    /// On a deployment that hosts other people's ciphertext, creation is the
    /// one unauthenticated way to put bytes on the disk, so it can be behind a
    /// password. Nothing else asks for it: a link must work for whoever holds
    /// it, or it is not a link.
    pub gate: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_upload: DEFAULT_MAX_UPLOAD,
            gate: None,
        }
    }
}

#[derive(Clone)]
pub struct Api {
    pub store: Arc<Store>,
    pub meter: Arc<Meter>,
    pub cfg: Arc<Config>,
}

pub fn router(api: Api) -> Router {
    Router::new()
        // shares
        .route("/v1/pub/shares", post(create_share))
        .route("/v1/pub/s/:sid", delete(delete_share))
        .route(
            "/v1/pub/s/:sid/files/:uid",
            get(share_file_status).put(upload_share_file),
        )
        .route("/v1/pub/s/:sid/commit", post(commit_share))
        .route("/v1/pub/s/:sid/meta", get(share_meta))
        .route("/v1/pub/s/:sid/session", post(share_session))
        .route("/v1/pub/s/:sid/files/:uid/content", get(share_content))
        // invites
        .route("/v1/pub/i/:iid", post(create_invite))
        .route("/v1/pub/i/:iid/status", get(invite_status))
        .route(
            "/v1/pub/i/:iid/uploads/:uid",
            get(invite_upload_status).put(upload_invite_file),
        )
        .route(
            "/v1/pub/i/:iid/uploads/:uid/commit",
            post(commit_invite_file),
        )
        // the granter's inbox
        .route("/v1/inbox", get(inbox_list))
        .route("/v1/inbox/:uid", delete(inbox_delete))
        .route("/v1/inbox/:uid/content", get(inbox_content))
        .with_state(api)
}

// ---------------------------------------------------------------- errors

pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    /// Headers the client needs to see even though the request failed — an
    /// offset to resume from, above all.
    headers: Vec<(&'static str, String)>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            headers: Vec::new(),
        }
    }
    fn bad(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }
    fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", message)
    }
    fn io(e: std::io::Error) -> Self {
        tracing::warn!(error = %e, "share store io error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "io", e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({ "error": self.code, "message": self.message })),
        )
            .into_response();
        for (name, value) in self.headers {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().insert(name, value);
            }
        }
        response
    }
}

// ---------------------------------------------------------------- helpers

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn hash_bearer(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Constant-time compare of two hex strings of the same length.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// `a:b` from a Basic header, the way a browser sends it.
fn basic_password(headers: &HeaderMap) -> Option<String> {
    use base64::Engine as _;
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    Some(text.split_once(':').map(|(_, p)| p.to_string()).unwrap_or(text))
}

fn sane_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn id_ok(prefix: &str, v: &str) -> bool {
    v.len() >= 12 && v.starts_with(prefix) && sane_id(v)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn token(prefix: &str, bytes: usize) -> String {
    use base64::Engine as _;
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
    )
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// What a `PUT` of a file body says about the file: where this body starts, how
/// long the file will be, and whether the bytes live in a part file already.
///
/// Three dialects mean the same thing and all are read: the TUS headers
/// (`Upload-Offset`, `Upload-Length`), a `Content-Range` (what a resumed
/// `fetch` sends), and this server's own `X-BM-*`. A request with none of them
/// is a plain whole-file `PUT`, which is what every non-resuming client sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct UploadSpec {
    offset: u64,
    total: Option<u64>,
}

fn header_u64(headers: &HeaderMap, name: &str) -> Result<Option<u64>, ApiError> {
    match headers.get(name).and_then(|v| v.to_str().ok()) {
        None | Some("") => Ok(None),
        Some(raw) => raw.trim().parse().map(Some).map_err(|_| {
            ApiError::bad("bad_upload_header", format!("{name} is not a number"))
        }),
    }
}

fn upload_spec(headers: &HeaderMap) -> Result<UploadSpec, ApiError> {
    let mut offset = match (
        header_u64(headers, "upload-offset")?,
        header_u64(headers, "x-bm-offset")?,
    ) {
        (Some(a), Some(b)) if a != b => {
            return Err(ApiError::bad(
                "bad_upload_header",
                "Upload-Offset and X-BM-Offset disagree",
            ));
        }
        (a, b) => a.or(b),
    };
    let mut total = match (
        header_u64(headers, "upload-length")?,
        header_u64(headers, "x-bm-total")?,
    ) {
        (Some(a), Some(b)) if a != b => {
            return Err(ApiError::bad(
                "bad_upload_header",
                "Upload-Length and X-BM-Total disagree",
            ));
        }
        (a, b) => a.or(b),
    };
    if let Some(raw) = headers.get(header::CONTENT_RANGE).and_then(|v| v.to_str().ok()) {
        let spec = raw.trim();
        let range = spec.strip_prefix("bytes ").ok_or_else(|| {
            ApiError::bad(
                "bad_content_range",
                "Content-Range must be bytes <first>-<last>/<total>",
            )
        })?;
        let (span, whole) = range.split_once('/').ok_or_else(|| {
            ApiError::bad(
                "bad_content_range",
                "Content-Range must be bytes <first>-<last>/<total>",
            )
        })?;
        let (first, last) = span.split_once('-').ok_or_else(|| {
            ApiError::bad(
                "bad_content_range",
                "Content-Range must be bytes <first>-<last>/<total>",
            )
        })?;
        let bad = || ApiError::bad("bad_content_range", "Content-Range is not a byte range");
        let first: u64 = first.trim().parse().map_err(|_| bad())?;
        let last: u64 = last.trim().parse().map_err(|_| bad())?;
        if last < first {
            return Err(bad());
        }
        if let Some(other) = offset
            && other != first
        {
            return Err(ApiError::bad(
                "bad_upload_header",
                "Content-Range and Upload-Offset disagree",
            ));
        }
        offset = Some(first);
        if whole.trim() != "*" {
            let whole: u64 = whole.trim().parse().map_err(|_| bad())?;
            if let Some(other) = total
                && other != whole
            {
                return Err(ApiError::bad(
                    "bad_upload_header",
                    "Content-Range and Upload-Length disagree",
                ));
            }
            total = Some(whole);
        }
    }
    Ok(UploadSpec {
        offset: offset.unwrap_or(0),
        total,
    })
}

/// The answer to a request that carried some of a file but not the end of it.
fn resume_response(stored: u64) -> Response {
    (
        StatusCode::NO_CONTENT,
        [("x-bm-offset", stored.to_string())],
    )
        .into_response()
}

/// The answer to a request whose offset is not where the bytes are.
fn offset_conflict(stored: u64) -> ApiError {
    let mut err = ApiError::new(
        StatusCode::CONFLICT,
        "offset_mismatch",
        format!("resume from offset {stored}"),
    );
    err.headers.push(("x-bm-offset", stored.to_string()));
    err
}

impl Api {
    fn gate(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let Some(want) = &self.cfg.gate else {
            return Ok(());
        };
        match basic_password(headers) {
            // Compare through a hash so the lengths always match and the loop
            // does not tell an attacker how long the password is.
            Some(got) if ct_eq(&sha256_hex(got.as_bytes()), &sha256_hex(want.as_bytes())) => Ok(()),
            Some(_) => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "bad_gate",
                "wrong test password",
            )),
            None => Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "gate",
                "this deployment asks for a password before it stores anything",
            )),
        }
    }

    async fn authed_share(&self, headers: &HeaderMap, sid: &str) -> Result<Share, ApiError> {
        let share = self
            .store
            .load_share(sid)
            .await
            .map_err(ApiError::io)?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no_share", "no such share"))?;
        let token = bearer(headers).ok_or_else(|| {
            ApiError::new(StatusCode::UNAUTHORIZED, "no_bearer", "auth_key required")
        })?;
        if !ct_eq(&hash_bearer(token), &share.auth) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "bad_key",
                "auth_key does not match",
            ));
        }
        if now() > share.expires {
            return Err(ApiError::new(
                StatusCode::GONE,
                "expired",
                "share expired",
            ));
        }
        Ok(share)
    }

    async fn authed_invite(&self, headers: &HeaderMap, iid: &str) -> Result<Invite, ApiError> {
        let invite = self
            .store
            .load_invite(iid)
            .await
            .map_err(ApiError::io)?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no_invite", "no such invite"))?;
        let token = bearer(headers).ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "no_bearer",
                "invite key required",
            )
        })?;
        if !ct_eq(&hash_bearer(token), &invite.auth) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "bad_key",
                "invite key does not match",
            ));
        }
        if now() > invite.expires {
            return Err(ApiError::new(
                StatusCode::GONE,
                "expired",
                "invite expired",
            ));
        }
        if invite.closed {
            return Err(ApiError::new(StatusCode::GONE, "closed", "invite closed"));
        }
        Ok(invite)
    }

    /// The granter token's invites, loaded. Only the ids the index names, so
    /// this does not walk every invite ever made.
    async fn granter_invites(&self, gt_hash: &str) -> Result<Vec<Invite>, ApiError> {
        let ids = self
            .store
            .granted_invites(gt_hash)
            .await
            .map_err(ApiError::io)?;
        let mut out = Vec::new();
        for iid in ids {
            if let Some(invite) = self.store.load_invite(&iid).await.map_err(ApiError::io)? {
                // The index says "you made this"; the stored hash is what
                // proves it. A stale or forged index line fails here.
                if ct_eq(&invite.gt, gt_hash) {
                    out.push(invite);
                }
            }
        }
        Ok(out)
    }

    async fn find_inbox_item(
        &self,
        gt_hash: &str,
        uid: &str,
    ) -> Result<Option<(Invite, Item)>, ApiError> {
        for invite in self.granter_invites(gt_hash).await? {
            if let Some(item) = invite.items.iter().find(|i| i.uid == uid).cloned() {
                return Ok(Some((invite, item)));
            }
        }
        Ok(None)
    }
}

fn receive_error(e: ReceiveError) -> ApiError {
    match e {
        ReceiveError::TooLarge(cap) => ApiError::too_large(format!("body over the {cap} byte cap")),
        ReceiveError::Offset { stored } => offset_conflict(stored),
        ReceiveError::Io(e) => ApiError::io(e),
        ReceiveError::Body(e) => ApiError::bad("bad_body", e),
    }
}

// ---------------------------------------------------------------- shares

#[derive(Deserialize)]
struct CreateShareBody {
    sid: String,
    auth_hash: String,
    #[serde(default)]
    files: Vec<NewFile>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    max_downloads: u64,
}

#[derive(Deserialize)]
struct NewFile {
    uid: String,
    /// What the client says the file weighs, if it knows. Recorded so that a
    /// resumed upload (and the metadata page) do not depend on the client
    /// remembering, and so an obviously oversized share is refused at creation
    /// instead of after the first gigabyte.
    #[serde(default)]
    size: u64,
    #[serde(default)]
    name_enc: String,
    #[serde(default)]
    name_iv: String,
    #[serde(default)]
    wrapped_kf: String,
    #[serde(default)]
    kf_iv: String,
    #[serde(default)]
    ct_iv: String,
}

async fn create_share(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(body): Json<CreateShareBody>,
) -> Result<Response, ApiError> {
    api.gate(&headers)?;
    if !id_ok("sh_", &body.sid) {
        return Err(ApiError::bad(
            "bad_sid",
            "sid must be sh_ followed by base64url",
        ));
    }
    if !is_hex64(&body.auth_hash) {
        return Err(ApiError::bad("bad_auth_hash", "auth_hash must be hex sha256"));
    }
    let mut files = Vec::with_capacity(body.files.len());
    let mut declared_total: u64 = 0;
    for f in body.files {
        if !sane_id(&f.uid) {
            return Err(ApiError::bad("bad_uid", "each file needs a uid"));
        }
        if f.size > api.cfg.max_upload {
            return Err(ApiError::too_large(format!(
                "each file must be under the {} byte cap",
                api.cfg.max_upload
            )));
        }
        declared_total = declared_total.saturating_add(f.size);
        files.push(super::store::FileRow {
            uid: f.uid,
            size: 0,
            declared: f.size,
            name_enc: f.name_enc,
            name_iv: f.name_iv,
            wrapped_kf: f.wrapped_kf,
            kf_iv: f.kf_iv,
            ct_iv: f.ct_iv,
            uploaded: false,
        });
    }

    let _guard = api.store.lock(&body.sid).await;
    if api
        .store
        .load_share(&body.sid)
        .await
        .map_err(ApiError::io)?
        .is_some()
    {
        return Err(ApiError::conflict("id_taken", "sid exists; regenerate km"));
    }
    let ttl = body
        .expires_in
        .unwrap_or(DEFAULT_SHARE_TTL)
        .clamp(60, 90 * 86_400);
    let share = Share {
        sid: body.sid.clone(),
        created: now(),
        expires: now() + ttl,
        auth: body.auth_hash.to_ascii_lowercase(),
        state: ShareState::Uploading,
        max_downloads: body.max_downloads,
        downloads: 0,
        files,
    };
    api.store.save_share(&share).await.map_err(ApiError::io)?;
    let upload_urls: Vec<String> = share
        .files
        .iter()
        .map(|f| format!("/v1/pub/s/{}/files/{}", share.sid, f.uid))
        .collect();
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "sid": share.sid,
            "expires": share.expires,
            "declared_bytes": declared_total,
            "upload_urls": upload_urls,
        })),
    )
        .into_response())
}

/// Where an upload of this file stands, so a client that lost a connection can
/// ask instead of guessing: `x-bm-offset` is how many bytes are durable.
async fn share_file_status(
    State(api): State<Api>,
    Path((sid, uid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let share = api.authed_share(&headers, &sid).await?;
    let row = share.file(&uid).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "no_file",
            "not a file of this share",
        )
    })?;
    let progress = api
        .store
        .upload_progress(&api.store.share_file(&sid, &uid))
        .await
        .map_err(ApiError::io)?;
    let total = if row.uploaded {
        row.size
    } else {
        row.declared
    };
    let mut response = Json(json!({
        "uid": uid,
        "stored": progress.stored,
        "total": total,
        "uploaded": progress.complete,
    }))
    .into_response();
    let h = response.headers_mut();
    h.insert("x-bm-offset", HeaderValue::from(progress.stored));
    if total > 0 {
        h.insert("x-bm-total", HeaderValue::from(total));
    }
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn upload_share_file(
    State(api): State<Api>,
    Path((sid, uid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let spec = upload_spec(&headers)?;
    let share = api.authed_share(&headers, &sid).await?;
    let row = share.file(&uid).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "no_file",
            "not a file of this share",
        )
    })?;
    let max = api.cfg.max_upload;
    if let Some(total) = spec.total
        && total > max
    {
        return Err(ApiError::too_large(format!(
            "file over the {max} byte cap"
        )));
    }
    if row.declared > max {
        return Err(ApiError::too_large(format!(
            "file over the {max} byte cap"
        )));
    }

    // One body per file at a time: two appends to the same part would make the
    // offset each of them reports a lie.
    let upload = api.store.lock_upload(&sid, &uid).await;
    // A resume need not repeat the total: creation already recorded what the
    // uploader said this file would weigh.
    let declared = spec
        .total
        .or_else(|| (row.declared > 0).then_some(row.declared));
    let dst = api.store.share_file(&sid, &uid);
    let received = api
        .store
        .receive_from(body, &dst, spec.offset, declared, max)
        .await;
    drop(upload);

    let received = match received {
        Ok(r) => r,
        Err(ReceiveError::Offset { stored }) => return Err(offset_conflict(stored)),
        Err(e) => return Err(receive_error(e)),
    };
    if !received.complete {
        return Ok(resume_response(received.stored));
    }

    let _guard = api.store.lock(&sid).await;
    let mut share = api.authed_share(&headers, &sid).await?;
    if let Some(row) = share.files.iter_mut().find(|f| f.uid == uid) {
        row.size = received.stored;
        row.declared = received.stored;
        row.uploaded = true;
    }
    api.store.save_share(&share).await.map_err(ApiError::io)?;
    Ok((
        StatusCode::CREATED,
        [("x-bm-offset", received.stored.to_string())],
        Json(json!({ "ok": true, "size": received.stored })),
    )
        .into_response())
}

async fn commit_share(
    State(api): State<Api>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _guard = api.store.lock(&sid).await;
    let mut share = api.authed_share(&headers, &sid).await?;
    let missing = share.files.iter().filter(|f| !f.uploaded).count();
    if missing > 0 {
        return Err(ApiError::conflict(
            "missing_files",
            format!("{missing} file(s) not uploaded"),
        ));
    }
    share.state = ShareState::Live;
    api.store.save_share(&share).await.map_err(ApiError::io)?;
    Ok(Json(json!({ "sid": sid, "state": "live" })).into_response())
}

async fn share_meta(
    State(api): State<Api>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let share = api.authed_share(&headers, &sid).await?;
    Ok(Json(json!({
        "sid": share.sid,
        "created": share.created,
        "expires": share.expires,
        "state": share.state,
        "max_downloads": share.max_downloads,
        "downloads": share.downloads,
        "total_bytes": share.total_bytes(),
        "files": share.files,
    }))
    .into_response())
}

/// Mint a download session. Today this is a bearer of the handshake rather
/// than a room: the peers still create their room with `/ws/create`, and this
/// is what a link-only reader is handed. The counter it bumps is the one
/// `max_downloads` caps.
async fn share_session(
    State(api): State<Api>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _guard = api.store.lock(&sid).await;
    let mut share = api.authed_share(&headers, &sid).await?;
    if share.state != ShareState::Live {
        return Err(ApiError::conflict(
            "not_live",
            "share is still uploading",
        ));
    }
    if share.max_downloads > 0 && share.downloads >= share.max_downloads {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "share_ended_count",
            "download count used up",
        ));
    }
    share.downloads += 1;
    api.store.save_share(&share).await.map_err(ApiError::io)?;
    Ok(Json(json!({
        "session_id": token("ses_", 16),
        "ttl": SESSION_TTL,
        "state": "live",
        "total_bytes": share.total_bytes(),
        "files": share.files,
    }))
    .into_response())
}

async fn delete_share(
    State(api): State<Api>,
    Path(sid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _guard = api.store.lock(&sid).await;
    api.authed_share(&headers, &sid).await?;
    api.store.remove_share(&sid).await.map_err(ApiError::io)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn share_content(
    State(api): State<Api>,
    Path((sid, uid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let share = api.authed_share(&headers, &sid).await?;
    let file = share.file(&uid).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "no_file",
            "not a file of this share",
        )
    })?;
    if !file.uploaded {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_uploaded",
            "file has no bytes",
        ));
    }
    // Egress is billed to the share the link names, not to the request and not
    // to the file: a thousand viewers of one document are one row a day.
    let sink = api.meter.sink(&sid, Kind::Download);
    file_response(api.store.share_file(&sid, &uid), &headers, Some(sink)).await
}

// ---------------------------------------------------------------- invites

#[derive(Deserialize)]
struct CreateInviteBody {
    auth_hash: String,
    pubkey: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    max_files: Option<u64>,
    #[serde(default = "yes")]
    one_time: bool,
}

fn yes() -> bool {
    true
}

async fn create_invite(
    State(api): State<Api>,
    Path(iid): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateInviteBody>,
) -> Result<Response, ApiError> {
    api.gate(&headers)?;
    if !id_ok("inv_", &iid) {
        return Err(ApiError::bad(
            "bad_invite_id",
            "invite_id must be inv_ + base64url",
        ));
    }
    if !is_hex64(&body.auth_hash) {
        return Err(ApiError::bad(
            "bad_auth_hash",
            "auth_hash must be hex sha256(invite_key)",
        ));
    }
    if body.pubkey.is_empty() {
        return Err(ApiError::bad(
            "no_pubkey",
            "pubkey is required: file keys wrap to it",
        ));
    }
    let granter_token = token("gt_", 24);
    let gt = hash_bearer(&granter_token);

    let _guard = api.store.lock(&iid).await;
    if api
        .store
        .load_invite(&iid)
        .await
        .map_err(ApiError::io)?
        .is_some()
    {
        return Err(ApiError::conflict(
            "id_taken",
            "invite exists; regenerate kt",
        ));
    }
    let ttl = body
        .expires_in
        .unwrap_or(DEFAULT_INVITE_TTL)
        .clamp(60, 90 * 86_400);
    let invite = Invite {
        iid: iid.clone(),
        created: now(),
        expires: now() + ttl,
        auth: body.auth_hash.to_ascii_lowercase(),
        gt: gt.clone(),
        pubkey: body.pubkey,
        label: body.label,
        max_bytes: body.max_bytes.unwrap_or(DEFAULT_INVITE_BYTES),
        max_files: body.max_files.unwrap_or(DEFAULT_INVITE_FILES),
        used_bytes: 0,
        used_files: 0,
        one_time: body.one_time,
        closed: false,
        items: Vec::new(),
    };
    api.store.save_invite(&invite).await.map_err(ApiError::io)?;
    api.store
        .index_granter(&gt, &iid)
        .await
        .map_err(ApiError::io)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "invite_id": invite.iid,
            "expires": invite.expires,
            "granter_token": granter_token,
            "max_bytes": invite.max_bytes,
            "max_files": invite.max_files,
        })),
    )
        .into_response())
}

async fn invite_status(
    State(api): State<Api>,
    Path(iid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let invite = api.authed_invite(&headers, &iid).await?;
    Ok(Json(json!({
        "invite_id": invite.iid,
        "label": invite.label,
        "pubkey": invite.pubkey,
        "max_bytes": invite.max_bytes,
        "max_files": invite.max_files,
        "used_bytes": invite.used_bytes,
        "used_files": invite.used_files,
        "remaining_bytes": invite.remaining_bytes(),
        "expires": invite.expires,
        "one_time": invite.one_time,
        "closed": invite.closed,
    }))
    .into_response())
}

/// The offset of an invite upload, for a client resuming one.
async fn invite_upload_status(
    State(api): State<Api>,
    Path((iid, uid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let invite = api.authed_invite(&headers, &iid).await?;
    let progress = api
        .store
        .upload_progress(&api.store.invite_file(&iid, &uid))
        .await
        .map_err(ApiError::io)?;
    let mut response = Json(json!({
        "uid": uid,
        "stored": progress.stored,
        "uploaded": progress.complete,
        "remaining_bytes": invite.remaining_bytes(),
    }))
    .into_response();
    let h = response.headers_mut();
    h.insert("x-bm-offset", HeaderValue::from(progress.stored));
    h.insert(
        "x-bm-remaining",
        HeaderValue::from(invite.remaining_bytes()),
    );
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn upload_invite_file(
    State(api): State<Api>,
    Path((iid, uid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    if !sane_id(&uid) {
        return Err(ApiError::bad("bad_uid", "bad uid"));
    }
    let spec = upload_spec(&headers)?;
    let invite = api.authed_invite(&headers, &iid).await?;
    let known = invite.items.iter().any(|i| i.uid == uid);
    if !known && invite.used_files >= invite.max_files {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "over_files",
            "file count cap reached",
        ));
    }

    let upload = api.store.lock_upload(&iid, &uid).await;
    let dst = api.store.invite_file(&iid, &uid);
    // Bytes already in the part are this upload's own room: they were not
    // charged to `used_bytes` yet, and a resume must not pay for them twice.
    let progress = api.store.upload_progress(&dst).await.map_err(ApiError::io)?;
    let room = invite.remaining_bytes().saturating_add(progress.stored);
    if let Some(total) = spec.total
        && total > room
    {
        return Err(ApiError::too_large(format!("{room} bytes remain")));
    }
    let received = api
        .store
        .receive_from(body, &dst, spec.offset, spec.total, room)
        .await;
    drop(upload);

    let received = match received {
        Ok(r) => r,
        Err(ReceiveError::Offset { stored }) => return Err(offset_conflict(stored)),
        Err(ReceiveError::TooLarge(_)) => {
            return Err(ApiError::too_large(format!(
                "{} bytes remain",
                invite.remaining_bytes()
            )));
        }
        Err(e) => return Err(receive_error(e)),
    };
    if !received.complete {
        return Ok(resume_response(received.stored));
    }
    let size = received.stored;

    // Re-check under the lock: two uploads can both stream while each thinks
    // the other's bytes are still free.
    let _guard = api.store.lock(&iid).await;
    let mut invite = api.authed_invite(&headers, &iid).await?;
    if size > invite.remaining_bytes() {
        let _ = tokio::fs::remove_file(&dst).await;
        return Err(ApiError::too_large(format!(
            "{} bytes remain",
            invite.remaining_bytes()
        )));
    }
    let item = Item {
        uid: uid.clone(),
        size,
        name_enc: header_str(&headers, "x-bm-name-enc").to_string(),
        name_iv: header_str(&headers, "x-bm-name-iv").to_string(),
        kf_enc: header_str(&headers, "x-bm-kf-enc").to_string(),
        kf_iv: header_str(&headers, "x-bm-kf-iv").to_string(),
        ct_iv: header_str(&headers, "x-bm-ct-iv").to_string(),
        epk: header_str(&headers, "x-bm-epk").to_string(),
        created: now(),
    };
    match invite.items.iter().position(|i| i.uid == uid) {
        Some(idx) => {
            invite.used_bytes = invite.used_bytes.saturating_sub(invite.items[idx].size);
            invite.items[idx] = item;
        }
        None => {
            invite.items.push(item);
            invite.used_files += 1;
        }
    }
    invite.used_bytes += size;
    api.store.save_invite(&invite).await.map_err(ApiError::io)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "size": size,
            "used_bytes": invite.used_bytes,
            "remaining_bytes": invite.remaining_bytes(),
        })),
    )
        .into_response())
}

async fn commit_invite_file(
    State(api): State<Api>,
    Path((iid, uid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _guard = api.store.lock(&iid).await;
    let mut invite = api.authed_invite(&headers, &iid).await?;
    if !invite.items.iter().any(|i| i.uid == uid) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "no_upload",
            "no such upload",
        ));
    }
    // §7: commit is where fan-out happens; one_time closes the door behind it.
    if invite.one_time {
        invite.closed = true;
    }
    api.store.save_invite(&invite).await.map_err(ApiError::io)?;
    Ok(Json(json!({
        "ok": true,
        "used_files": invite.used_files,
        "remaining_bytes": invite.remaining_bytes(),
        "closed": invite.closed,
    }))
    .into_response())
}

// ---------------------------------------------------------------- inbox

async fn inbox_list(
    State(api): State<Api>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let gt = bearer(&headers).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "no_bearer",
            "granter token required",
        )
    })?;
    let invites = api.granter_invites(&hash_bearer(gt)).await?;
    let mut items = Vec::new();
    for invite in &invites {
        for item in &invite.items {
            items.push(json!({
                "id": item.uid,
                "invite_id": invite.iid,
                "label": invite.label,
                "size": item.size,
                "created": item.created,
                "name_enc": item.name_enc,
                "name_iv": item.name_iv,
                "kf_enc": item.kf_enc,
                "kf_iv": item.kf_iv,
                "ct_iv": item.ct_iv,
                "epk": item.epk,
            }));
        }
    }
    Ok(Json(json!({ "items": items })).into_response())
}

async fn inbox_content(
    State(api): State<Api>,
    Path(uid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let gt = bearer(&headers).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "no_bearer",
            "granter token required",
        )
    })?;
    match api.find_inbox_item(&hash_bearer(gt), &uid).await? {
        // The granter taking back what somebody sent them. It is egress, but it
        // is not a share's egress: when invites get a rate of their own, this
        // passes a sink and nothing else changes.
        Some((invite, item)) => {
            file_response(
                api.store.invite_file(&invite.iid, &item.uid),
                &headers,
                None,
            )
            .await
        }
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "no_item",
            "no such item",
        )),
    }
}

async fn inbox_delete(
    State(api): State<Api>,
    Path(uid): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let gt = bearer(&headers).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "no_bearer",
            "granter token required",
        )
    })?;
    let gt_hash = hash_bearer(gt);
    let Some((mut invite, item)) = api.find_inbox_item(&gt_hash, &uid).await? else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "no_item",
            "no such item",
        ));
    };
    let _guard = api.store.lock(&invite.iid).await;
    let _ = tokio::fs::remove_file(api.store.invite_file(&invite.iid, &uid)).await;
    invite.items.retain(|i| i.uid != uid);
    invite.used_bytes = invite.used_bytes.saturating_sub(item.size);
    api.store.save_invite(&invite).await.map_err(ApiError::io)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------------------------------------------------------------- bytes

fn range_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::RANGE).and_then(|v| v.to_str().ok())
}

/// A byte range of a file: `(start, len)`.
#[derive(Debug, PartialEq, Eq)]
struct ByteRange {
    start: u64,
    len: u64,
}

/// One range, the whole file when there is no header, `Err` when the request
/// is unsatisfiable. Multi-range requests are answered with their first range:
/// the viewer asks for one at a time, and multipart/byteranges costs a second
/// pass over the file for no benefit here.
fn parse_range(header: Option<&str>, len: u64) -> Result<ByteRange, ()> {
    let Some(value) = header else {
        return Ok(ByteRange { start: 0, len });
    };
    let spec = value.strip_prefix("bytes=").ok_or(())?;
    let spec = spec.split(',').next().unwrap_or("");
    let (a, b) = spec.split_once('-').ok_or(())?;
    if a.is_empty() {
        // suffix range: the last N bytes
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        let n = n.min(len);
        return Ok(ByteRange {
            start: len - n,
            len: n,
        });
    }
    let start: u64 = a.parse().map_err(|_| ())?;
    let end: u64 = if b.is_empty() {
        len.saturating_sub(1)
    } else {
        b.parse().map_err(|_| ())?
    };
    if start >= len || end < start {
        return Err(());
    }
    let end = end.min(len - 1);
    Ok(ByteRange {
        start,
        len: end - start + 1,
    })
}

/// A validator for a stored file: its size and the time it was last written.
/// Both change if the bytes change, and neither costs a read — which is what
/// makes a resume safe: a client sends back the tag it was given with
/// `If-Range`, and a file that has been replaced since gets served whole
/// instead of spliced wrongly.
fn etag_for(size: u64, modified: Option<std::time::SystemTime>) -> String {
    let nanos = modified
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("\"{size:x}.{nanos:x}\"")
}

/// Does an `If-Range` value name this validator? A bare date never does: this
/// server hands out no `Last-Modified`, so a date cannot be one of ours.
fn if_range_matches(value: &str, etag: &str) -> bool {
    let value = value.trim();
    let value = value.strip_prefix("W/").unwrap_or(value);
    value == etag
}

/// Stream `path` to the client, honouring one Range, billing what goes out.
///
/// The file is never read whole: `ReaderStream` hands out 256 KiB chunks and
/// `Body::from_stream` applies backpressure, so a slow client slows the read
/// instead of growing a buffer. Resuming a download is the client's half of
/// this and needed nothing new from the server: `Accept-Ranges` and honest
/// 206s were already there, and `ETag` + `If-Range` make a continued range
/// safe when the file changed underneath it.
async fn file_response(
    path: std::path::PathBuf,
    headers: &HeaderMap,
    sink: Option<MeterSink>,
) -> Result<Response, ApiError> {
    let mut file = tokio::fs::File::open(&path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ApiError::new(StatusCode::NOT_FOUND, "no_bytes", "no bytes on disk")
        }
        _ => ApiError::io(e),
    })?;
    let meta = file.metadata().await.map_err(ApiError::io)?;
    let size = meta.len();
    let etag = etag_for(size, meta.modified().ok());

    // A range whose validator no longer holds is answered with the whole file:
    // better one restart than a splice of two different versions.
    let range = match range_header(headers) {
        Some(_) => match headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
            Some(validator) if !if_range_matches(validator, &etag) => None,
            _ => range_header(headers),
        },
        None => None,
    };

    let (status, part) = match parse_range(range, size) {
        Ok(part) => (
            if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            },
            part,
        ),
        Err(()) => {
            let mut response = ApiError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "range",
                "range outside the file",
            )
            .into_response();
            let h = response.headers_mut();
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}")).unwrap(),
            );
            if let Ok(tag) = HeaderValue::from_str(&etag) {
                h.insert(header::ETAG, tag);
            }
            return Ok(response);
        }
    };
    if part.start > 0 {
        file.seek(std::io::SeekFrom::Start(part.start))
            .await
            .map_err(ApiError::io)?;
    }
    let stream = ReaderStream::with_capacity(file.take(part.len), IO_BUFFER);
    let body = match sink {
        Some(sink) => Body::from_stream(meter::metered(stream, sink)),
        None => Body::from_stream(stream),
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, part.len)
        .header(header::ETAG, etag)
        // Ciphertext behind a bearer: keep it out of shared caches, and make a
        // client revalidate rather than resume against a stale copy.
        .header(header::CACHE_CONTROL, "private, max-age=0, must-revalidate");
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", part.start, part.start + part.len - 1, size),
        );
    }
    builder.body(body).map_err(|e| ApiError::io(std::io::Error::other(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 100).unwrap(), ByteRange { start: 0, len: 100 });
        assert_eq!(
            parse_range(Some("bytes=0-9"), 100).unwrap(),
            ByteRange { start: 0, len: 10 }
        );
        assert_eq!(
            parse_range(Some("bytes=-10"), 100).unwrap(),
            ByteRange { start: 90, len: 10 }
        );
        assert_eq!(
            parse_range(Some("bytes=90-"), 100).unwrap(),
            ByteRange { start: 90, len: 10 }
        );
        assert_eq!(
            parse_range(Some("bytes=90-200"), 100).unwrap(),
            ByteRange { start: 90, len: 10 }
        );
        assert_eq!(
            parse_range(Some("bytes=0-1,5-6"), 100).unwrap(),
            ByteRange { start: 0, len: 2 }
        );
        assert!(parse_range(Some("bytes=200-"), 100).is_err());
        assert!(parse_range(Some("bytes=-0"), 100).is_err());
        assert!(parse_range(Some("items=0-1"), 100).is_err());
    }

    #[test]
    fn ids() {
        assert!(id_ok("sh_", "sh_AAAAAAAAAAAAAAAA"));
        assert!(!id_ok("sh_", "sh_short"));
        assert!(!id_ok("sh_", "sh_../../etc/passwd"));
        assert!(sane_id("abc-def_1"));
        assert!(!sane_id("abc/def"));
    }
}

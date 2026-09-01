//! Ciphertext chunk-relay HTTP endpoints.
//!
//! All chunk bytes on the wire and at rest are ciphertext under K_session.
//! The server neither derives nor holds the session key.
//!
//! Routes:
//!   PUT  /session/:sess/chunk/:idx        — upload ciphertext
//!   GET  /session/:sess/chunk/:idx        — download ciphertext
//!   GET  /session/:sess/have              — serialized ChunkBitmap of stored chunks
//!   GET  /session/:sess/capacity          — remaining bytes of session quota
//!   POST /session/:sess/delivered/:idx    — receiver acks delivery (body: hex ReceiverId)
//!
//! Session id and receiver id are the hex forms of the underlying 32-byte
//! arrays. Any non-hex path segment gets a 400 immediately.

use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use bitmule_core::{ReceiverId, SessionId};
use serde::Serialize;

fn parse_session(hex: &str) -> Result<SessionId, StatusCode> {
    SessionId::from_hex(hex).map_err(|_| StatusCode::BAD_REQUEST)
}

fn parse_receiver(hex: &str) -> Result<ReceiverId, StatusCode> {
    ReceiverId::from_hex(hex).map_err(|_| StatusCode::BAD_REQUEST)
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub async fn put_chunk(
    Path((session_hex, idx)): Path<(String, u32)>,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    let session = parse_session(&session_hex).map_err(|s| (s, "bad session".into()))?;
    // Enforce quota before writing so a runaway sender can't blow past it.
    let cap = state
        .store
        .capacity_available(&session)
        .await
        .map_err(internal)?;
    if (body.len() as u64) > cap {
        return Err((StatusCode::INSUFFICIENT_STORAGE, "session quota".into()));
    }
    state
        .store
        .put(&session, idx, &body)
        .await
        .map_err(internal)?;
    Ok(StatusCode::CREATED)
}

pub async fn get_chunk(
    Path((session_hex, idx)): Path<(String, u32)>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session = parse_session(&session_hex).map_err(|s| (s, "bad session".into()))?;
    match state.store.get(&session, idx).await.map_err(internal)? {
        Some(bytes) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response()),
        None => Ok((StatusCode::NOT_FOUND, "no chunk").into_response()),
    }
}

pub async fn have(
    Path(session_hex): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let session = parse_session(&session_hex).map_err(|s| (s, "bad session".into()))?;
    let bitmap = state.store.have(&session).await.map_err(internal)?;
    Ok(Json(serde_json::to_value(&bitmap).map_err(internal)?))
}

#[derive(Serialize)]
pub struct CapacityResp {
    pub remaining_bytes: u64,
}

pub async fn capacity(
    Path(session_hex): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<CapacityResp>, (StatusCode, String)> {
    let session = parse_session(&session_hex).map_err(|s| (s, "bad session".into()))?;
    let remaining_bytes = state
        .store
        .capacity_available(&session)
        .await
        .map_err(internal)?;
    Ok(Json(CapacityResp { remaining_bytes }))
}

pub async fn mark_delivered(
    Path((session_hex, idx)): Path<(String, u32)>,
    State(state): State<AppState>,
    body: String,
) -> Result<StatusCode, (StatusCode, String)> {
    let session = parse_session(&session_hex).map_err(|s| (s, "bad session".into()))?;
    let receiver = parse_receiver(body.trim()).map_err(|s| (s, "bad receiver id".into()))?;
    state
        .store
        .mark_delivered(&session, idx, &receiver)
        .await
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

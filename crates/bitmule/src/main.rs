//! bitmule CLI — send or receive files/folders over WebRTC (or app-relay fallback).
//!
//! `cargo install bitmule` gets a user the CLI. Same wire protocol as the browser
//! SPA client (which is `bitmule-client-wasm` compiled from bitmule-core).
//!
//! **Current state:** the send/recv subcommands run a minimal smoke-test
//! path against `bitmule-server` — one file goes up as `chunk 0` under a
//! random SessionId, and comes back down by SessionId. No manifest,
//! chunking, encryption, or WebRTC yet — those layers land in follow-up
//! commits. This exists to prove the streaming HTTP relay end-to-end.

use anyhow::{anyhow, Context, Result};
use bitmule_core::SessionId;
use clap::{Parser, Subcommand};
use futures_util::TryStreamExt;
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;

#[derive(Parser)]
#[command(name = "bitmule", version, about, long_about = None)]
struct Cli {
    /// Signaling+relay server URL. HTTP(S) for smoke-test upload/download.
    #[arg(long, default_value = "http://localhost:8443")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Smoke test: upload a single file as chunk 0 of a fresh session,
    /// print the session id the receiver needs.
    Send {
        /// Path to the file to send.
        path: PathBuf,

        /// Optional password (not wired in smoke-test path).
        #[arg(long)]
        password: Option<String>,
    },
    /// Smoke test: download chunk 0 of the given session id and write it out.
    Recv {
        /// Session id (64 hex chars) printed by `bitmule send`.
        session: String,

        /// Where to write the received file.
        #[arg(long, default_value = "received.bin")]
        out: PathBuf,

        /// Password if the sender set one (not wired in smoke-test path).
        #[arg(long)]
        password: Option<String>,
    },
    /// Print version + build info.
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bitmule=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Send { path, password: _ } => send_smoke(&cli.server, path).await,
        Command::Recv {
            session,
            out,
            password: _,
        } => recv_smoke(&cli.server, session, out).await,
        Command::Version => {
            println!("bitmule {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn send_smoke(server: &str, path: PathBuf) -> Result<()> {
    let meta = fs::metadata(&path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        return Err(anyhow!(
            "smoke path {} must be a regular file",
            path.display()
        ));
    }
    let len = meta.len();

    let session = SessionId::random();
    let url = format!("{}/session/{}/chunk/0", server.trim_end_matches('/'), session.as_hex());

    let file = fs::File::open(&path).await?;
    let stream = ReaderStream::new(file);
    let body = reqwest::Body::wrap_stream(stream);

    let client = reqwest::Client::new();
    let resp = client
        .put(&url)
        .header(reqwest::header::CONTENT_LENGTH, len)
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .send()
        .await
        .with_context(|| format!("PUT {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("server rejected upload: {status} {text}"));
    }

    println!("session: {}", session.as_hex());
    println!(
        "recv with: bitmule --server {} recv {}",
        server,
        session.as_hex()
    );
    Ok(())
}

async fn recv_smoke(server: &str, session_hex: String, out: PathBuf) -> Result<()> {
    // Validate the session hex up front so a typo doesn't reach the server.
    let session = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("invalid session id {session_hex:?}: {e}"))?;
    let url = format!("{}/session/{}/chunk/0", server.trim_end_matches('/'), session.as_hex());

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow!("no chunk on server for session {}", session.as_hex()));
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("server error: {status} {text}"));
    }

    let mut f = fs::File::create(&out)
        .await
        .with_context(|| format!("create {}", out.display()))?;
    let mut stream = resp
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    while let Some(bytes) = futures_util::StreamExt::next(&mut stream).await {
        let bytes = bytes?;
        f.write_all(&bytes).await?;
    }
    f.sync_all().await?;

    println!("wrote {}", out.display());
    Ok(())
}

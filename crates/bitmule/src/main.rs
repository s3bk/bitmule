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
use qrcode::{render::unicode, QrCode};
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;

mod identity;

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
    /// Manage local identities (keypairs). Each identity is a
    /// (name, Ed25519 sign key, X25519 KEX key) triple stored under
    /// $XDG_CONFIG_HOME/bitmule/identities/<name>.json.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Add a peer to the local contacts store. Accepts either:
    ///   bitmule add <name> <pubkey_b64url>
    ///   bitmule add <https://…/c/<name>/<pubkey>>
    Add {
        /// A share URL (https://…/c/name/pubkey) OR a bare NAME. If NAME,
        /// PUBKEY must be given as the second positional arg.
        first: String,
        /// Public-key blob (64-byte concat, base64url no-pad). Required when
        /// FIRST is a name; ignored when FIRST is a share URL.
        pubkey: Option<String>,
    },
    /// WebRTC connect (sender). Opens a signaling WS to the server,
    /// waits for a receiver, exchanges SDP + ICE, opens a data channel,
    /// and holds it open. No transfer yet — this proves the CLI reaches
    /// the same "direct channel open" state the browser reaches. Prints
    /// the session id the receiver needs.
    WebrtcSend {
        /// Signaling server URL (ws:// or wss://). Defaults to derived
        /// from --server (http:// swapped to ws://).
        #[arg(long)]
        signal_url: Option<String>,
        /// Seconds to hold the DC open before exiting.
        #[arg(long, default_value_t = 30)]
        hold_seconds: u64,
    },
    /// WebRTC connect (receiver). Given a session hex printed by
    /// `webrtc-send`, opens a signaling WS, exchanges SDP + ICE against
    /// the sender, and holds the DC open.
    WebrtcRecv {
        /// Session id (64 hex chars).
        session: String,
        #[arg(long)]
        signal_url: Option<String>,
        #[arg(long, default_value_t = 30)]
        hold_seconds: u64,
    },
    /// Print version + build info.
    Version,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new keypair, store under NAME, print a share link + QR.
    Add {
        /// Identity name. Advertised to peers as your handle.
        name: String,
        /// Contact-URL host used in the printed share link. Users can point
        /// this at a self-hosted bitmule server that serves the `/c/*`
        /// landing page.
        #[arg(long, default_value = identity::DEFAULT_CONTACT_BASE)]
        contact_base: String,
    },
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
        Command::Identity { action } => match action {
            IdentityAction::Add { name, contact_base } => identity_add(name, contact_base).await,
        },
        Command::Add { first, pubkey } => contact_add(first, pubkey).await,
        Command::WebrtcSend {
            signal_url,
            hold_seconds,
        } => webrtc_send(&cli.server, signal_url, hold_seconds).await,
        Command::WebrtcRecv {
            session,
            signal_url,
            hold_seconds,
        } => webrtc_recv(&cli.server, signal_url, session, hold_seconds).await,
        Command::Version => {
            println!("bitmule {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

async fn identity_add(name: String, contact_base: String) -> Result<()> {
    let id = identity::create(&name).await?;
    let link = id.share_link(&contact_base)?;

    let qr = QrCode::new(link.as_bytes()).context("build qr")?;
    let rendered = qr
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();

    println!("identity: {}", id.name);
    println!(
        "stored:   {}",
        identity::identities_dir()?
            .join(format!("{}.json", id.name))
            .display()
    );
    println!();
    println!("share link:");
    println!("  {link}");
    println!();
    println!("{rendered}");
    Ok(())
}

async fn contact_add(first: String, pubkey: Option<String>) -> Result<()> {
    // Decide which form we're in: URL or (name, pubkey).
    let looks_like_url = first.starts_with("https://") || first.starts_with("http://");

    let (name, pk_b64, source) = if looks_like_url {
        if pubkey.is_some() {
            return Err(anyhow!(
                "when adding by URL, do not pass a second positional arg"
            ));
        }
        let (n, pk) = identity::parse_contact_url(&first)?;
        (n, pk, first.clone())
    } else {
        let pk = pubkey.ok_or_else(|| {
            anyhow!("adding by name requires a second arg: bitmule add <name> <pubkey>")
        })?;
        (first, pk, "raw".to_string())
    };

    let saved = identity::save_contact(&name, &pk_b64, &source).await?;
    let path = identity::contacts_dir()?.join(format!("{}.json", saved.name));
    println!("contact: {}", saved.name);
    println!("stored:  {}", path.display());
    println!("pubkey:  {}", saved.public_blob_b64);
    Ok(())
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

fn derive_signal_url(server: &str, override_url: Option<String>) -> String {
    if let Some(u) = override_url {
        return u.trim_end_matches('/').to_string();
    }
    let base = server.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        base.to_string()
    }
}

async fn webrtc_send(server: &str, signal_url: Option<String>, hold_seconds: u64) -> Result<()> {
    let signal = derive_signal_url(server, signal_url);
    // Print the session hex BEFORE the (blocking) wait for the receiver
    // so the operator can paste it into the receiver CLI right away.
    let session_id = SessionId::random();
    println!("session: {}", session_id.as_hex());
    println!(
        "receive with: bitmule --server {} webrtc-recv {}",
        server,
        session_id.as_hex()
    );
    println!("opening sender WebSocket at {signal} — waiting for receiver…");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let session = bitmule_client_native::send_connect(&signal, session_id).await?;
    println!("data channel open (label={:?}) — holding {}s", session.dc.label(), hold_seconds);
    tokio::time::sleep(std::time::Duration::from_secs(hold_seconds)).await;
    let _ = session.close().await;
    Ok(())
}

async fn webrtc_recv(
    server: &str,
    signal_url: Option<String>,
    session_hex: String,
    hold_seconds: u64,
) -> Result<()> {
    let signal = derive_signal_url(server, signal_url);
    let session_id = SessionId::from_hex(session_hex.trim())
        .map_err(|e| anyhow!("bad session id: {e}"))?;
    println!("opening receiver WebSocket at {signal}");
    let session = bitmule_client_native::recv_connect(&signal, session_id).await?;
    println!("connected to session {}", session.session_id.as_hex());
    println!("data channel open (label={:?}) — holding {}s", session.dc.label(), hold_seconds);
    tokio::time::sleep(std::time::Duration::from_secs(hold_seconds)).await;
    let _ = session.close().await;
    Ok(())
}

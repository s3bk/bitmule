//! bitmule CLI — send or receive files/folders over WebRTC (with server-relay fallback).
//!
//! `cargo install bitmule` gets a user the CLI. Same wire protocol as the browser
//! SPA client (which is `bitmule-client-wasm` compiled from bitmule-core).

use anyhow::{anyhow, Context, Result};
use bitmule_client_native::crypto::{BulkKey, CommitmentHasher, ShareKey, ShareLink};
use bitmule_client_native::{recv_file, send_file, TransportMode};
use clap::{Parser, Subcommand};
use qrcode::{render::unicode, QrCode};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

mod identity;

#[derive(Parser)]
#[command(name = "bitmule", version, about, long_about = None)]
struct Cli {
    /// Signaling+relay server URL.
    #[arg(long, default_value = "http://localhost:8443")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file. Auto mode: WebRTC first, falls back to server relay
    /// after 3s if the data channel hasn't opened. --webrtc / --relay
    /// force a single transport.
    Send {
        /// Path to the file to send.
        path: PathBuf,
        /// Force WebRTC only (no relay fallback).
        #[arg(long, conflicts_with = "relay")]
        webrtc: bool,
        /// Force server relay only (skip WebRTC).
        #[arg(long)]
        relay: bool,
    },
    /// Receive a file. With SESSION (a hex or a share URL), connects to
    /// an existing session initiated by a sender. Without SESSION,
    /// generates a fresh session id, prints a `<server>/send#<hex>`
    /// link the sender can open in their browser, and waits.
    Recv {
        /// Session hex (64 chars) OR a URL of shape `.../send#<hex>` or
        /// `.../#<hex>`. Omit to have the CLI generate a fresh session
        /// and print a share link.
        session: Option<String>,
        /// Where to write the received file(s).
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Force WebRTC only (no relay fallback).
        #[arg(long, conflicts_with = "relay")]
        webrtc: bool,
        /// Force server relay only (skip WebRTC).
        #[arg(long)]
        relay: bool,
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

fn resolve_mode(webrtc: bool, relay: bool) -> TransportMode {
    if webrtc { TransportMode::Webrtc }
    else if relay { TransportMode::Relay }
    else { TransportMode::Auto }
}

fn mode_label(m: TransportMode) -> &'static str {
    match m {
        TransportMode::Auto => "auto (WebRTC-first, 3s fallback to relay)",
        TransportMode::Webrtc => "WebRTC only",
        TransportMode::Relay => "relay only",
    }
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
        Command::Send { path, webrtc, relay } => {
            cmd_send(&cli.server, path, resolve_mode(webrtc, relay)).await
        }
        Command::Recv { session, out, webrtc, relay } => {
            cmd_recv(&cli.server, session, out, resolve_mode(webrtc, relay)).await
        }
        Command::Identity { action } => match action {
            IdentityAction::Add { name, contact_base } => identity_add(name, contact_base).await,
        },
        Command::Add { first, pubkey } => contact_add(first, pubkey).await,
        Command::Version => {
            println!("bitmule {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// Extract the URL fragment from a share URL or accept the fragment
/// directly. Returns None only when there's nothing after the `#` (or the
/// argument is not a URL and not itself a plausible fragment).
fn extract_link_fragment(input: &str) -> Option<String> {
    let s = input.trim();
    let candidate = if s.starts_with("http://") || s.starts_with("https://") {
        s.rsplit('#').next().unwrap_or(s).to_string()
    } else {
        s.to_string()
    };
    let trimmed = candidate.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

/// Stream `path` through SHA256 and fold in `bulk_key` to produce the
/// 32-byte URL commitment. Reads in 64 KiB chunks — the file is not held
/// in memory.
async fn commit_file(path: &Path, bulk_key: &BulkKey) -> Result<[u8; 32]> {
    let mut f = tokio::fs::File::open(path).await
        .with_context(|| format!("open {}", path.display()))?;
    let mut hasher = CommitmentHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize(bulk_key))
}

async fn cmd_send(server: &str, path: PathBuf, mode: TransportMode) -> Result<()> {
    let meta = tokio::fs::metadata(&path).await
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        return Err(anyhow!("{} must be a regular file", path.display()));
    }
    // Mint share_key (URL secret) + bulk_key (file-encryption key) up front.
    // Then hash the file with the bulk_key to produce the URL signature
    // commitment. The share URL fragment = base64url(share_key || signature).
    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let session_hex = share_key.session_id_hex();
    eprintln!("computing file commitment…");
    let signature = commit_file(&path, &bulk_key).await?;
    let link = ShareLink::new(share_key.clone(), signature);
    let share = format!(
        "{}/#{}",
        server.trim_end_matches('/'),
        link.to_b64_url()
    );
    println!("session: {}", session_hex);
    println!("share:   {share}");
    println!("mode:    {}", mode_label(mode));
    println!("sending {} ({} bytes)…", path.display(), meta.len());
    use std::io::Write;
    std::io::stdout().flush().ok();

    let name_for_progress = path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let mut last_pct = 0u64;
    send_file(server, share_key, bulk_key, &path, mode, move |sent, total| {
        if total == 0 { return }
        let pct = sent * 100 / total;
        if pct != last_pct {
            last_pct = pct;
            eprint!("\r{}: {}%    ", name_for_progress, pct);
            let _ = std::io::stderr().flush();
        }
    }).await?;
    eprintln!();
    println!("done.");
    Ok(())
}

async fn cmd_recv(
    server: &str,
    session_arg: Option<String>,
    out: PathBuf,
    mode: TransportMode,
) -> Result<()> {
    // Parsing precedence: (1) full ShareLink b64 URL fragment (86 chars) —
    // send-initiated flow with a real signature; (2) legacy 64-char hex —
    // temporary receiver-initiated flow, no signature to verify; (3) nothing
    // — mint a fresh share_key for receiver-initiated flow.
    let (share_key, expected_signature) = match session_arg.as_ref() {
        Some(raw) => {
            let frag = extract_link_fragment(raw)
                .ok_or_else(|| anyhow!("couldn't extract share fragment from {raw:?}"))?;
            if let Ok(link) = ShareLink::from_b64_url(&frag) {
                (link.share_key, Some(link.signature))
            } else if frag.len() == 64 && frag.chars().all(|c| c.is_ascii_hexdigit()) {
                (ShareKey::from_hex(&frag).map_err(|e| anyhow!("bad share key hex: {e}"))?, None)
            } else {
                return Err(anyhow!("share fragment {frag:?} is neither an 86-char b64 ShareLink nor a 64-char hex share_key"));
            }
        }
        None => (ShareKey::random(), None),
    };
    let session_hex = share_key.session_id_hex();

    if session_arg.is_none() {
        // Receiver-initiated flow — no file to commit to yet, so print the
        // legacy hex form. Sender-initiated flow will re-encode with real
        // signature on the send side.
        let share = format!(
            "{}/send#{}",
            server.trim_end_matches('/'),
            share_key.to_hex()
        );
        println!("share this link with the sender:");
        println!("  {share}");
        println!("(receiver-initiated: no URL signature commitment on this flow yet)");
        println!();
    }
    println!("session:   {}", session_hex);
    println!("mode:      {}", mode_label(mode));
    println!("signature: {}", if expected_signature.is_some() { "present (will verify post-transfer)" } else { "none (skipped)" });
    println!("waiting for transfer…");
    use std::io::Write;
    std::io::stdout().flush().ok();

    let mut last_pct = 0u64;
    let path = recv_file(server, share_key, expected_signature, &out, mode, move |received, total, name| {
        if total == 0 { return }
        let pct = received * 100 / total;
        if pct != last_pct {
            last_pct = pct;
            eprint!("\r{}: {}%    ", name, pct);
            let _ = std::io::stderr().flush();
        }
    }).await?;
    eprintln!();
    if expected_signature.is_some() {
        println!("received (signature verified): {}", path.display());
    } else {
        println!("received: {}", path.display());
    }
    Ok(())
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

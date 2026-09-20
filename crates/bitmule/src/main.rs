//! bitmule CLI — send or receive files/folders over WebRTC (with server-relay fallback).
//!
//! `cargo install bitmule` gets a user the CLI. Same wire protocol as the browser
//! SPA client (which is `bitmule-client-wasm` compiled from bitmule-core).

use anyhow::{anyhow, Context, Result};
use bitmule_client_native::crypto::{BulkKey, CommitmentHasher, ShareKey, ShareLink};
use bitmule_client_native::{recv_file, send_file_multi, send_file_relay, ServeMode, TransportMode};
use clap::{Parser, Subcommand};
use qrcode::{render::unicode, QrCode};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

mod identity;

#[derive(Parser)]
#[command(name = "bitmule", version, about, long_about = None)]
struct Cli {
    /// Signaling+relay server URL.
    #[arg(long, default_value = "https://bitmule.qdat.net")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send file(s) or a directory. Auto mode: WebRTC first, falls back
    /// to server relay after 3s if the data channel hasn't opened.
    /// --webrtc / --relay force a single transport.
    ///
    /// Multiple paths OR a directory path → the sender bundles them
    /// into a store-mode zip (no compression) on the fly and flags the
    /// meta so the receiver unpacks. A single file path streams as-is.
    Send {
        /// Path(s) to file(s) or a directory to send.
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,
        /// Force WebRTC only (no relay fallback).
        #[arg(long, conflicts_with = "relay")]
        webrtc: bool,
        /// Force server relay only (skip WebRTC).
        #[arg(long)]
        relay: bool,
        /// Multi-peer serving: keep the sender live and hand the same
        /// URL to any number of receivers over time (Ctrl-C to stop).
        /// Combines with --webrtc or --relay: --multi --webrtc runs
        /// the multipeer WebRTC stack (send_serve+Multi); --multi
        /// --relay falls back to the server-relay path (single-peer
        /// under the hood, but re-usable URL until process exit).
        /// Without --webrtc or --relay, defaults to WebRTC-multi.
        #[arg(long)]
        multi: bool,
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
    // Default (no flag) = Auto: try WebRTC first with a bounded budget
    // (bitmule_client_native::AUTO_WEBRTC_BUDGET), fall back to relay
    // if the DC doesn't open in time. --webrtc forces WebRTC only,
    // --relay forces relay only. clap's `conflicts_with` prevents both
    // being passed together. Kenna 2026-09-13 — reinstated after the
    // CLI transport matrix showed the earlier "auto = Webrtc" left
    // mixed-mode pairs broken.
    match (webrtc, relay) {
        (false, false) => TransportMode::Auto,
        (true,  false) => TransportMode::Webrtc,
        (false, true)  => TransportMode::Relay,
        (true,  true)  => unreachable!("clap conflicts_with prevents this"),
    }
}

fn mode_label(m: TransportMode) -> &'static str {
    match m {
        TransportMode::Webrtc => "WebRTC only",
        TransportMode::Relay => "relay only",
        TransportMode::Auto => "auto (WebRTC first, relay fallback)",
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
        Command::Send { paths, webrtc, relay, multi } => {
            cmd_send(&cli.server, paths, resolve_mode(webrtc, relay), multi).await
        }
        Command::Recv { session, out, webrtc, relay } => {
            // Infer the server from the share URL when possible so the
            // receiver doesn't need `--server` to match the sender's
            // published origin. Falls back to `--server` (default
            // http://localhost:8443) if the arg is a bare hex/b64
            // fragment with no scheme.
            let inferred = session
                .as_deref()
                .and_then(extract_server_from_url);
            let server = inferred.as_deref().unwrap_or(&cli.server);
            cmd_recv(server, session, out, resolve_mode(webrtc, relay)).await
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

/// If `input` is an `http(s)://host[:port]/path#fragment` URL, return
/// the `scheme://host[:port]` base — everything before the path/fragment.
/// Returns None when `input` is a bare hex/b64 fragment (no scheme).
///
/// Used by `bitmule recv` to infer the signaling server from the share
/// URL, so the receiver doesn't have to also pass `--server` matching.
fn extract_server_from_url(input: &str) -> Option<String> {
    let s = input.trim();
    let rest = if let Some(r) = s.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = s.strip_prefix("https://") {
        ("https", r)
    } else {
        return None;
    };
    let (scheme, tail) = rest;
    // authority = up to the first '/' or '#' or end-of-string
    let end = tail.find(|c: char| c == '/' || c == '#').unwrap_or(tail.len());
    let authority = &tail[..end];
    if authority.is_empty() { return None; }
    Some(format!("{scheme}://{authority}"))
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

/// Everything an in-process caller (tests, embedders) needs after
/// [`prepare_and_spawn_send`] returns: the share URL to hand to the
/// receiver + the JoinHandle to `await` for the transfer's final result.
///
/// Also carries `session_hex`, `file_name`, `file_size` so callers can
/// log or display the same info the CLI does without re-statting the
/// file or re-deriving the session id.
pub struct SendSpawn {
    pub session_hex: String,
    pub share_url: String,
    pub file_name: String,
    pub file_size: u64,
    pub handle: tokio::task::JoinHandle<Result<()>>,
}

/// Prepare a send session and spawn the transfer as a background task.
///
/// Splits out of `cmd_send` so an integration test (or any embedder)
/// can drive both sides of a transfer from the same process: call
/// this, hand `share_url` to a receiver, then `.await` `handle` for
/// the transfer's final result. No stdout/stderr side effects here —
/// callers do their own printing.
///
/// The transfer body picks `send_file_multi` when `multi` is true,
/// `send_file` otherwise. `on_progress(sent, total)` fires from the
/// legacy single-peer path only (multipeer has no equivalent hook
/// yet); pass a no-op closure when unused.
pub async fn prepare_and_spawn_send<F>(
    server: String,
    paths: Vec<PathBuf>,
    mode: TransportMode,
    multi: bool,
    on_progress: F,
) -> Result<SendSpawn>
where
    F: FnMut(u64, u64) + Send + 'static,
{
    if paths.is_empty() {
        return Err(anyhow!("no paths given"));
    }

    // Decide single-file vs bundle. Single existing file, one path → legacy
    // shape (container=None). Directory OR more than one path → build a
    // store-mode zip on the fly, container=Some("zip-store"), receiver
    // unpacks. The zip temp file is held alive by moving its guard into
    // the spawn closure so it survives the whole transfer and unlinks on
    // task exit.
    let (send_path, zip_guard, container, file_name) = if paths.len() == 1 {
        let p = &paths[0];
        let meta = tokio::fs::metadata(p).await
            .with_context(|| format!("stat {}", p.display()))?;
        if meta.is_file() {
            let name = p.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file.bin".to_string());
            (p.clone(), None, None, name)
        } else if meta.is_dir() {
            let (zip_file, disp) = bitmule_client_native::container::build_zip_bundle(&paths).await?;
            let path = zip_file.path().to_path_buf();
            (path, Some(zip_file), Some("zip-store".to_string()), disp)
        } else {
            return Err(anyhow!("{} is neither a regular file nor a directory", p.display()));
        }
    } else {
        let (zip_file, disp) = bitmule_client_native::container::build_zip_bundle(&paths).await?;
        let path = zip_file.path().to_path_buf();
        (path, Some(zip_file), Some("zip-store".to_string()), disp)
    };

    let file_size = tokio::fs::metadata(&send_path).await
        .with_context(|| format!("stat {}", send_path.display()))?
        .len();

    // Mint share_key (URL secret) + bulk_key (file-encryption key) up front.
    // Then hash the file with the bulk_key to produce the URL signature
    // commitment. The share URL fragment = base64url(share_key || signature).
    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let session_hex = share_key.session_id_hex();
    let signature = commit_file(&send_path, &bulk_key).await?;
    let link = ShareLink::new(share_key.clone(), signature);
    let share_url = format!(
        "{}/#{}",
        server.trim_end_matches('/'),
        link.to_b64_url()
    );

    // Dispatch matrix:
    //
    //  multi | mode    | path taken
    //  ------+---------+-----------------------------------------------
    //  false | Webrtc  | send_file_multi Complete (exits on 1st peer done)
    //  false | Relay   | send_file_relay (server-relay single-peer)
    //  true  | Webrtc  | send_file_multi Multi (WebRTC multipeer)
    //  true  | Relay   | send_file_relay — session URL stays valid until
    //                    process exit; late receivers fetch from retained
    //                    server chunks (natural multipeer-over-relay)
    let handle = tokio::spawn(async move {
        let _zip_guard = zip_guard; // hold NamedTempFile until send completes
        let container_ref = container.as_deref();
        match (multi, mode) {
            (_, TransportMode::Relay) => {
                send_file_relay(&server, share_key, bulk_key, &send_path, container_ref, on_progress).await
            }
            (false, TransportMode::Webrtc) => {
                send_file_multi(&server, share_key, bulk_key, send_path, container.clone(), ServeMode::Complete).await
            }
            (true, TransportMode::Webrtc) => {
                send_file_multi(&server, share_key, bulk_key, send_path, container.clone(), ServeMode::Multi).await
            }
            (_, TransportMode::Auto) => {
                // Try WebRTC with a bounded budget; on timeout or error,
                // reconnect via relay. Kenna 2026-09-13. Multi + Auto
                // behaves like Multi + Webrtc first, then Relay single-
                // peer as fallback — the multipeer-over-relay path isn't
                // exercised here.
                let serve = if multi { ServeMode::Multi } else { ServeMode::Complete };
                let sk_relay = share_key.clone();
                let bulk_relay = bulk_key.clone();
                let webrtc_attempt = tokio::time::timeout(
                    bitmule_client_native::AUTO_WEBRTC_BUDGET,
                    send_file_multi(&server, share_key, bulk_key, send_path.clone(), container.clone(), serve),
                ).await;
                match webrtc_attempt {
                    Ok(Ok(())) => Ok(()),
                    _ => {
                        eprintln!(
                            "auto send: WebRTC leg didn't complete within {}s, falling back to relay",
                            bitmule_client_native::AUTO_WEBRTC_BUDGET.as_secs()
                        );
                        // Server's ws_handler slams the door on a
                        // second sender-Hello for a session that
                        // already has one registered. When we time out
                        // above the ws-drop → TCP-FIN → server-side
                        // remove-from-room happens asynchronously; if
                        // we re-connect too fast the server still sees
                        // the old sender and closes our new ws
                        // immediately. Short sleep here lets the
                        // cleanup land before we retry. Kenna 2026-09-13.
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        send_file_relay(&server, sk_relay, bulk_relay, &send_path, container_ref, on_progress).await
                    }
                }
            }
        }
    });

    Ok(SendSpawn { session_hex, share_url, file_name, file_size, handle })
}

// build_zip_bundle moved to bitmule_client_native::container so Qt6 +
// mobile FFI can share the same on-the-fly bundling.

async fn cmd_send(server: &str, paths: Vec<PathBuf>, mode: TransportMode, multi: bool) -> Result<()> {
    // Bundling decision is duplicated with `prepare_and_spawn_send` for the
    // progress-line label only. The real send uses whatever
    // `prepare_and_spawn_send` decides.
    let will_bundle = paths.len() > 1 || (paths.len() == 1 && paths[0].is_dir());
    let name_for_progress = if will_bundle {
        "bundle.zip".to_string()
    } else {
        paths[0].file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file.bin".to_string())
    };
    let mut last_pct = 0u64;
    let on_progress = move |sent: u64, total: u64| {
        if total == 0 { return }
        let pct = sent * 100 / total;
        if pct != last_pct {
            last_pct = pct;
            eprint!("\r{}: {}%    ", name_for_progress, pct);
            use std::io::Write;
            let _ = std::io::stderr().flush();
        }
    };

    if will_bundle {
        eprintln!("bundling {} entr{} into store-mode zip…",
            paths.len(),
            if paths.len() == 1 { "y" } else { "ies" });
    }
    eprintln!("computing file commitment…");
    let SendSpawn { session_hex, share_url, file_name, file_size, handle } =
        prepare_and_spawn_send(server.to_string(), paths, mode, multi, on_progress).await?;

    println!("session: {}", session_hex);
    println!("share:   {share_url}");
    // Render the share URL as a terminal QR so a phone camera can
    // pick it up without pasting. Fits in a standard 80-col shell
    // for an 86-char b64 fragment at Dense1x2.
    match QrCode::new(share_url.as_bytes()) {
        Ok(qr) => {
            let rendered = qr
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            println!("{rendered}");
        }
        Err(e) => eprintln!("(qr render skipped: {e})"),
    }
    match (multi, mode) {
        (true, TransportMode::Relay) => {
            println!("mode:    relay-multi (server-relay, URL stays valid — Ctrl-C to stop)");
        }
        (false, TransportMode::Relay) => {
            println!("mode:    relay only (single-peer)");
        }
        (true, TransportMode::Webrtc) => {
            println!("mode:    multi-peer (WebRTC, never exits — Ctrl-C to stop)");
        }
        (false, TransportMode::Webrtc) => {
            println!("mode:    complete (WebRTC, exits after first receiver has the file)");
        }
        (_, TransportMode::Auto) => {
            println!("mode:    auto (WebRTC first, relay fallback after {}s)",
                bitmule_client_native::AUTO_WEBRTC_BUDGET.as_secs());
        }
    }
    println!("sending {} ({} bytes)…", file_name, file_size);
    use std::io::Write;
    std::io::stdout().flush().ok();

    match handle.await {
        Ok(Ok(())) => {
            eprintln!();
            if multi {
                println!("multi-peer server exited.");
            } else {
                println!("done.");
            }
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(je) => Err(anyhow!("send task join: {je}")),
    }
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
    let outcome = recv_file(server, share_key, expected_signature, &out, mode, move |received, total, name| {
        if total == 0 { return }
        let pct = received * 100 / total;
        if pct != last_pct {
            last_pct = pct;
            eprint!("\r{}: {}%    ", name, pct);
            let _ = std::io::stderr().flush();
        }
    }).await?;
    eprintln!();
    let path = outcome.path;
    if expected_signature.is_some() {
        println!("received (signature verified): {}", path.display());
    } else {
        println!("received: {}", path.display());
    }

    // F2: if the sender flagged a container, unpack it. Today the only
    // container is "zip-store"; unknown values are surfaced but not
    // touched so an older receiver on a newer container still lands the
    // bytes on disk for the user to open manually.
    if let Some(container) = outcome.container.as_deref() {
        match container {
            "zip-store" => {
                let unpack_dir = bitmule_client_native::container::unpack_dir_for(&path);
                match bitmule_client_native::container::unpack_zip_store(&path, &unpack_dir).await {
                    Ok(entries) => {
                        // Zip is redundant now — the caller wanted the files, not the archive.
                        // Best-effort delete; log but don't fail if it stays.
                        if let Err(e) = tokio::fs::remove_file(&path).await {
                            eprintln!("(kept received zip at {} — remove failed: {e})", path.display());
                        }
                        println!("unpacked {} entr{} into {}",
                            entries,
                            if entries == 1 { "y" } else { "ies" },
                            unpack_dir.display());
                    }
                    Err(e) => {
                        eprintln!("warning: container=zip-store but unpack failed: {e:#}");
                        eprintln!("(zip kept at {} for manual extraction)", path.display());
                    }
                }
            }
            other => {
                eprintln!("warning: sender flagged container={other:?} but this receiver only knows \"zip-store\" — leaving file as-is");
            }
        }
    }
    Ok(())
}

// unpack_dir_for + unpack_zip_store moved to bitmule_client_native::container.

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use bitmule_core::traits::ChunkStore;
    use bitmule_server::{state::AppState, ws::ws_join_session};
    use bitmule_server_store_fs::FsChunkStore;

    /// End-to-end round-trip: spawn an in-process bitmule-server on a
    /// random localhost port, call `prepare_and_spawn_send` on a random
    /// 32 KiB file, hand its share URL to `cmd_recv`, wait ≤10s for the
    /// receiver to finish, and confirm the received bytes match.
    ///
    /// Bounded by tokio::time::timeout so the test either passes cleanly
    /// or fails deterministically — no hangs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn prepare_and_spawn_send_roundtrip() -> Result<()> {
        // --- server bring-up (same axum::Router shape as bitmule-server main) ---
        let state = AppState::new();
        let app = axum::Router::new()
            .route("/ws/:session", axum::routing::get(ws_join_session))
            .route(
                "/session/:sess/chunk/:idx",
                axum::routing::put(relay::put_chunk).get(relay::get_chunk),
            )
            .route("/session/:sess/have", axum::routing::get(relay::have))
            .route("/session/:sess/capacity", axum::routing::get(relay::capacity))
            .route(
                "/session/:sess/delivered/:idx",
                axum::routing::post(relay::mark_delivered),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let bound = listener.local_addr()?;
        let server_url = format!("http://{bound}");
        let _server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // --- file under test: 32 KiB of deterministic-random bytes ---
        let src_dir = tempfile::tempdir()?;
        let src_path = src_dir.path().join("payload.bin");
        let want: Vec<u8> = (0..32 * 1024u32)
            .map(|i| ((i.wrapping_mul(2654435761)) & 0xff) as u8)
            .collect();
        tokio::fs::write(&src_path, &want).await?;

        // --- prepare + spawn the sender via the new entrypoint ---
        let SendSpawn { share_url, handle: send_handle, .. } = prepare_and_spawn_send(
            server_url.clone(),
            vec![src_path.clone()],
            TransportMode::Webrtc,
            /* multi */ false,
            /* on_progress */ |_sent, _total| {},
        )
        .await?;

        // --- hand the URL to cmd_recv, capped at 10s wall clock ---
        let dst_dir = tempfile::tempdir()?;
        let dst_out = dst_dir.path().to_path_buf();
        let server_url_recv = server_url.clone();
        let share_for_recv = share_url.clone();
        let recv_fut = async move {
            cmd_recv(
                &server_url_recv,
                Some(share_for_recv),
                dst_out,
                TransportMode::Webrtc,
            )
            .await
        };

        // Await sender + receiver together; whichever errors first fails
        // the test, and the outer timeout guarantees no hang.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (send_res, recv_res) = tokio::join!(
                async {
                    match send_handle.await {
                        Ok(inner) => inner,
                        Err(je) => Err(anyhow!("send join: {je}")),
                    }
                },
                recv_fut,
            );
            send_res.and(recv_res)
        })
        .await;

        match joined {
            Ok(Ok(())) => { /* both sides clean */ }
            Ok(Err(e)) => return Err(anyhow!("transfer failed: {e:#}")),
            Err(_) => return Err(anyhow!("transfer did not finish within 10s")),
        }

        // --- verify the received file matches ---
        let entries: Vec<_> = std::fs::read_dir(dst_dir.path())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        let got_path = entries
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no file landed in {}", dst_dir.path().display()))?;
        let got = tokio::fs::read(&got_path).await?;
        if got != want {
            return Err(anyhow!(
                "received bytes differ: got {} bytes, want {}",
                got.len(),
                want.len()
            ));
        }
        Ok(())
    }
}

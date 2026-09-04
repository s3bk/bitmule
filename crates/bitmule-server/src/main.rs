//! `bitmule-server` binary. Wires WebSocket signaling + REST chunk relay on
//! top of an [`FsChunkStore`].
//!
//! Usage:
//!   bitmule-server --bind 0.0.0.0:8443 --data-dir /var/lib/bitmule
//!
//! Runs a periodic GC loop that reclaims fully-delivered chunks every 60s
//! and evicts undelivered chunks older than the retention threshold every
//! 10 minutes.

use axum::{
    routing::{get, post, put},
    Router,
};
use bitmule_core::traits::ChunkStore;
use bitmule_server::{relay, state::AppState, ws::ws_handler};
use bitmule_server_store_fs::FsChunkStore;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "bitmule-server", about = "bitmule signaling + chunk relay")]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// Directory root for the FsChunkStore.
    #[arg(long, default_value = "/var/lib/bitmule")]
    data_dir: PathBuf,

    /// Retention for undelivered chunks. Older chunks are evicted.
    #[arg(long, default_value_t = 10)]
    retention_minutes: u64,

    /// Hard upper bound on total ciphertext bytes stored across all sessions.
    /// When exceeded, the maintenance loop evicts oldest chunks first until
    /// storage drops back at or below this value.
    ///
    /// Accepts SI (kB / MB / GB / TB, base 1000) and IEC (KiB / MiB / GiB /
    /// TiB, base 1024) byte suffixes; plain digits = raw bytes. Case-
    /// insensitive on the leading letter. Default 500GiB.
    #[arg(long, default_value = "500GiB", value_parser = parse_byte_size)]
    max_disk_bytes: u64,

    /// If set, serve static files from this directory on any GET that
    /// isn't matched by /ws/... or /session/... — typically points at
    /// the repo's web/ directory so the SPA is available on the same host
    /// as the signaling + relay endpoints.
    #[arg(long)]
    web_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bitmule_server=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();
    tokio::fs::create_dir_all(&args.data_dir).await?;

    let store: Arc<dyn ChunkStore> = Arc::new(FsChunkStore::new(&args.data_dir));
    let state = AppState::new(store.clone());

    // Periodic maintenance: gc every 60s, retention-eviction every 10 min,
    // disk-cap eviction opportunistically after each pass.
    tokio::spawn(maintenance_loop(
        store.clone(),
        args.retention_minutes,
        args.max_disk_bytes,
    ));

    let mut app = Router::new()
        .route("/ws/:session", get(ws_handler))
        .route(
            "/session/:sess/chunk/:idx",
            put(relay::put_chunk).get(relay::get_chunk),
        )
        .route("/session/:sess/have", get(relay::have))
        .route("/session/:sess/capacity", get(relay::capacity))
        .route(
            "/session/:sess/delivered/:idx",
            post(relay::mark_delivered),
        )
        .with_state(state);

    // If --web-dir is set, mount a static-file fallback for everything
    // else. ServeDir serves index.html for `/` automatically and 404s
    // for missing paths. Missing-path fallback then routes to
    // index.html so client-side routes like `/send` resolve to the SPA.
    if let Some(dir) = &args.web_dir {
        let index_path = dir.join("index.html");
        let index_fallback = ServeFile::new(&index_path);
        let serve = ServeDir::new(dir)
            .append_index_html_on_directories(true)
            .not_found_service(index_fallback);
        app = app.fallback_service(serve);
        info!(web_dir = %dir.display(), "serving static SPA from web-dir");
    }

    info!(bind = %args.bind, data_dir = %args.data_dir.display(), "bitmule-server up");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Parse a byte-size string with optional SI or IEC suffix. Examples:
///   "10"      -> 10
///   "10kB"    -> 10_000                (SI: 1000-power)
///   "10 KiB"  -> 10 * 1024              (IEC: 1024-power)
///   "500GiB"  -> 500 * 1024^3
///   "2.5MB"   -> 2_500_000              (decimal fractions on SI multipliers)
/// Case-insensitive on the leading letter. Whitespace between number
/// and suffix is optional. Missing suffix = raw bytes.
fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() { return Err("empty byte size".to_string()); }
    // Split into leading numeric part + trailing suffix.
    let split = s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len());
    let (num_str, suffix) = s.split_at(split);
    let num_str = num_str.trim();
    let suffix = suffix.trim().to_ascii_lowercase();
    let value: f64 = num_str
        .parse()
        .map_err(|e| format!("invalid number in {s:?}: {e}"))?;
    if value < 0.0 || !value.is_finite() {
        return Err(format!("byte size must be a finite non-negative number, got {value}"));
    }
    // IEC (1024-power) suffixes first — "kib"/"mib"/"gib"/"tib".
    // SI (1000-power) — "kb"/"mb"/"gb"/"tb". Bare "k"/"m"/"g"/"t"
    // and "b" also accepted; bare letter = SI to match `--help` output
    // in most CLIs (`dd bs=1M` is SI-decimal in coreutils).
    let mul: f64 = match suffix.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1_000.0,
        "m" | "mb" => 1_000_000.0,
        "g" | "gb" => 1_000_000_000.0,
        "t" | "tb" => 1_000_000_000_000.0,
        "kib" => 1024.0,
        "mib" => (1024u64 * 1024) as f64,
        "gib" => (1024u64 * 1024 * 1024) as f64,
        "tib" => (1024u64 * 1024 * 1024 * 1024) as f64,
        other => return Err(format!("unknown byte-size suffix {other:?}")),
    };
    let bytes = value * mul;
    if bytes > u64::MAX as f64 {
        return Err(format!("byte size {s:?} overflows u64"));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::parse_byte_size;

    #[test]
    fn plain_bytes() {
        assert_eq!(parse_byte_size("0").unwrap(), 0);
        assert_eq!(parse_byte_size("42").unwrap(), 42);
        assert_eq!(parse_byte_size("42B").unwrap(), 42);
    }

    #[test]
    fn si_suffixes_are_1000_power() {
        assert_eq!(parse_byte_size("10kB").unwrap(), 10_000);
        assert_eq!(parse_byte_size("10 kB").unwrap(), 10_000);
        assert_eq!(parse_byte_size("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_byte_size("10 GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_byte_size("1TB").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_byte_size("2.5MB").unwrap(), 2_500_000);
    }

    #[test]
    fn iec_suffixes_are_1024_power() {
        assert_eq!(parse_byte_size("10KiB").unwrap(), 10 * 1024);
        assert_eq!(parse_byte_size("10 MiB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_byte_size("500GiB").unwrap(), 500u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn case_insensitive_suffix() {
        assert_eq!(parse_byte_size("10gb").unwrap(), 10_000_000_000);
        assert_eq!(parse_byte_size("10GB").unwrap(), 10_000_000_000);
        assert_eq!(parse_byte_size("10gib").unwrap(), 10u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn empty_and_bad_suffix_error() {
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("10QQ").is_err());
        assert!(parse_byte_size("-5MB").is_err());
    }
}

async fn maintenance_loop(
    store: Arc<dyn ChunkStore>,
    retention_retention_minutes: u64,
    max_disk_bytes: u64,
) {
    let gc_period = Duration::from_secs(60);
    let evict_period = Duration::from_secs(600);
    let retention = Duration::from_secs(retention_retention_minutes * 60);
    let mut last_evict = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(gc_period).await;
        match store.gc_delivered().await {
            Ok(freed) if freed > 0 => info!(freed_bytes = freed, "gc_delivered"),
            Ok(_) => {}
            Err(e) => warn!(err = %e, "gc_delivered failed"),
        }
        if last_evict.elapsed() >= evict_period {
            match store.evict_older_than(retention).await {
                Ok(freed) if freed > 0 => info!(freed_bytes = freed, "evict_older_than"),
                Ok(_) => {}
                Err(e) => warn!(err = %e, "evict_older_than failed"),
            }
            last_evict = tokio::time::Instant::now();
        }
        // Global disk-cap enforcement every tick. Skips work when under cap.
        match store.evict_to_bytes(max_disk_bytes).await {
            Ok(freed) if freed > 0 => {
                info!(freed_bytes = freed, cap = max_disk_bytes, "evict_to_bytes")
            }
            Ok(_) => {}
            Err(e) => warn!(err = %e, "evict_to_bytes failed"),
        }
    }
}

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
    #[arg(long, default_value_t = 72)]
    retention_hours: u64,
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

    // Periodic maintenance: gc every 60s, eviction every 10 min.
    tokio::spawn(maintenance_loop(store.clone(), args.retention_hours));

    let app = Router::new()
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

    info!(bind = %args.bind, data_dir = %args.data_dir.display(), "bitmule-server up");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn maintenance_loop(store: Arc<dyn ChunkStore>, retention_hours: u64) {
    let gc_period = Duration::from_secs(60);
    let evict_period = Duration::from_secs(600);
    let retention = Duration::from_secs(retention_hours * 3600);
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
    }
}

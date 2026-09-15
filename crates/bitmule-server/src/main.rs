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
use bitmule_server::{relay2, state::AppState, ws::{ws_create_session, ws_join_session}};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info};

#[derive(Parser, Debug)]
#[command(name = "bitmule-server", about = "bitmule signaling + chunk relay")]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

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
    let state = AppState::new();

    let mut app = Router::new()
        .route("/ws/join/:session", get(ws_join_session))
        .route("/ws/create/:session/:nounce", get(ws_create_session))
        .route("/session/:sess/:receiver_id", post(relay2::post).get(relay2::get))
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

    info!(bind = %args.bind, "bitmule-server up");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

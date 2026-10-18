//! `bitmule-server` binary. Wires WebSocket signaling + REST chunk relay on
//! top of an [`FsChunkStore`].
//!
//! Usage:
//!   bitmule-server --bind 0.0.0.0:8443 --data-dir /var/lib/bitmule
//!
//! Runs a periodic GC loop that reclaims fully-delivered chunks every 60s
//! and evicts undelivered chunks older than the retention threshold every
//! 10 minutes.

use bitmule_server::state::AppState;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
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

    /// UDP address of the STUN server, which tells clients their public
    /// address for WebRTC.
    #[arg(long, default_value = "0.0.0.0:3478")]
    stun_bind: SocketAddr,

    /// Do not run the STUN server.
    #[arg(long)]
    no_stun: bool,
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
    let state = Arc::new(AppState::new());
    {
        // rotate the PoW magic; the previous one stays valid for one more period
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                state.rotate_magic();
            }
        });
    }

    if !args.no_stun {
        match tokio::net::UdpSocket::bind(args.stun_bind).await {
            Ok(socket) => {
                info!(bind = %args.stun_bind, "stun up");
                tokio::spawn(bitmule_server::stun::serve(socket));
            }
            Err(e) => tracing::warn!("stun disabled, cannot bind {}: {e}", args.stun_bind),
        }
    }

    let mut app = bitmule_server::router(state);

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

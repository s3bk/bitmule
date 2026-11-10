//! `bitmule-server` binary. Wires WebSocket signaling + the chunk relay, and
//! (since the prototype was merged in) the link surfaces — shares, invites, the
//! granter's inbox — on top of a filesystem store.
//!
//! Usage:
//!   bitmule-server --bind 0.0.0.0:8443 --data-dir /var/lib/bitmule \
//!                  --web-dir ../web --link-bind 127.0.0.1:8441
//!
//! `--link-bind` is the links-only host (`https://mul.li#<key>`): viewer at
//! `/`, the key-addressed API, nothing else. The proxy points the short host's
//! vhost at that port and the long host's at `--bind`.

use bitmule_server::share::{self, Meter, Store};
use bitmule_server::state::AppState;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "bitmule-server", about = "bitmule signaling, relay and links")]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// If set, serve static files from this directory on any GET that
    /// isn't matched by /ws/..., /session/... or /v1/... — typically points at
    /// the repo's web/ directory so the app is available on the same host as
    /// the signaling, relay and share endpoints.
    #[arg(long)]
    web_dir: Option<PathBuf>,

    /// Where shares, invites and the egress meter live.
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,

    /// Also serve the links-only surface here: the viewer at `/`, the viewer's
    /// assets, and the key-addressed `/v1/pub/…` routes. Everything else on
    /// this port gets a page pointing at `--main-host`.
    #[arg(long)]
    link_bind: Option<SocketAddr>,

    /// The host that has a front door; the links-only host's 404 names it.
    #[arg(long, default_value = "bitmule.net")]
    main_host: String,

    /// Largest single upload, in bytes.
    #[arg(long, default_value_t = share::api::DEFAULT_MAX_UPLOAD)]
    max_upload: u64,

    /// Basic-auth password the two creating endpoints require before they
    /// store anything. Reading a link, uploading through an invite and
    /// deleting with a key never ask for it.
    #[arg(long)]
    gate: Option<String>,

    /// How often the egress meter is written to `<data-dir>/usage.tsv`.
    #[arg(long, default_value_t = 3600)]
    meter_flush_secs: u64,

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
    // The gate can also come from the environment, so a unit file does not
    // have to carry a password in its command line (visible in `ps`).
    let gate = args
        .gate
        .clone()
        .or_else(|| std::env::var("BITMULE_GATE").ok().filter(|s| !s.is_empty()));
    let state = Arc::new(AppState::new());
    {
        // rotate the PoW magic; the previous one stays valid for one more period
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
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

    // The link surfaces. The meter is shared by both listeners: a byte served
    // on the short host is the same byte, billed to the same share.
    let store = Arc::new(Store::new(args.data_dir.clone()));
    let meter = Arc::new(Meter::new());
    meter.spawn_flush(
        args.data_dir.join("usage.tsv"),
        Duration::from_secs(args.meter_flush_secs.max(1)),
    );
    let share_cfg = Arc::new(share::Config {
        max_upload: args.max_upload,
        gate: gate.clone(),
    });
    let share_api = || {
        share::router(share::Api {
            store: store.clone(),
            meter: meter.clone(),
            cfg: share_cfg.clone(),
        })
    };
    info!(
        data_dir = %args.data_dir.display(),
        max_upload = args.max_upload,
        gated = gate.is_some(),
        "share store up"
    );

    let mut app = bitmule_server::router(state).merge(share_api());

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

    let app = bitmule_server::security_headers(app);

    // The links-only host, if a port was given for it. A second listener and
    // not a Host check: a TLS terminator in front rewrites Host to the
    // upstream it dialled, so only the port tells the two names apart.
    if let Some(addr) = args.link_bind {
        match &args.web_dir {
            Some(web_dir) => {
                let site = bitmule_server::hosts::Site {
                    web_dir: web_dir.clone(),
                    main_host: args.main_host.clone(),
                };
                let link_app = bitmule_server::security_headers(
                    bitmule_server::hosts::link_router(share_api(), site),
                );
                let main_host = args.main_host.clone();
                tokio::spawn(async move {
                    match tokio::net::TcpListener::bind(addr).await {
                        Ok(listener) => {
                            info!(bind = %addr, main_host = %main_host, "links-only surface up");
                            if let Err(e) = axum::serve(listener, link_app).await {
                                tracing::error!(error = %e, "links-only listener died");
                            }
                        }
                        Err(e) => {
                            tracing::error!(bind = %addr, error = %e, "cannot bind the links-only port")
                        }
                    }
                });
            }
            None => tracing::warn!("--link-bind needs --web-dir; serving one host only"),
        }
    }

    info!(bind = %args.bind, "bitmule-server up");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

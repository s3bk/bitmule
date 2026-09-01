//! bitmule CLI — send or receive files/folders over WebRTC (or app-relay fallback).
//!
//! `cargo install bitmule` gets a user the CLI. Same wire protocol as the browser
//! SPA client (which is `bitmule-client-wasm` compiled from bitmule-core).

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bitmule", version, about, long_about = None)]
struct Cli {
    /// Signaling+relay server URL (wss://... or configured default).
    #[arg(long, default_value = "wss://bitmule.net")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file or folder. Emits a link the receiver can paste into their browser or CLI.
    Send {
        /// Path to file or folder to send.
        path: std::path::PathBuf,

        /// Optional password. Receiver must supply this to decrypt the payload,
        /// even if they have the link. Wraps content-key with Argon2id-derived KEK.
        #[arg(long)]
        password: Option<String>,
    },
    /// Receive by pasting the link the sender gave you.
    Recv {
        /// The bitmule:// link (or https-shortened equivalent).
        link: String,

        /// Password if the sender set one.
        #[arg(long)]
        password: Option<String>,

        /// Where to write. Default: cwd.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
    },
    /// Print version + build info.
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Send { path, password } => {
            tracing::info!(?path, has_password = password.is_some(), server = cli.server, "send: TODO");
            unimplemented!("send flow: manifest, key-exchange, chunk-stream, resume");
        }
        Command::Recv { link, password, out } => {
            tracing::info!(link, has_password = password.is_some(), ?out, server = cli.server, "recv: TODO");
            unimplemented!("recv flow: parse link, key-exchange, request-missing, decrypt-verify");
        }
        Command::Version => {
            println!("bitmule {}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}

//! fountain-send — reads an input file, encodes each block with RaptorQ,
//! ships symbols to fountain-recv over UDP, listens to progress packets from
//! the receiver to know when to stop or which blocks to prioritise.
//!
//! State is a tiny per-block cursor persisted atomically to `<state>/sender.json`
//! so a Ctrl-C then relaunch picks up without re-emitting decoded blocks.
//!
//! v0 of the encoder path: uses `RaptorQEncoder::new_with_operator` seeded
//! with an in-memory `VecDataOperater` holding the block's source symbols,
//! then walks `encode_coded_vector(coded_id)` across the ESI space to emit
//! source + repair symbols out on the wire.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

use fountain_demo_v2::{
    block_size_for, decode_progress_frame, encode_data_frame, encode_hello_frame, sha256_file,
    Manifest, SenderState, DEFAULT_OVERHEAD_FACTOR, DEFAULT_SYMBOL_SIZE, PROTO_PROGRESS,
};
use fountain_raptor_q::raptor_q_main::raptor_q_main;
use fountain_utility::vec_data_operater::VecDataOperater;

#[derive(Parser, Debug)]
#[command(about = "RaptorQ block-fountain sender — UDP unicast to fountain-recv")]
struct Cli {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    dest: SocketAddr,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    block_size: Option<u32>,
    #[arg(long, default_value_t = DEFAULT_SYMBOL_SIZE)]
    symbol_size: u16,
    #[arg(long, default_value_t = DEFAULT_OVERHEAD_FACTOR)]
    overhead_factor: u32,
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    tokio::fs::create_dir_all(&cli.state_dir).await?;

    let state_path = cli.state_dir.join("sender.json");
    let sender_state = if state_path.exists() {
        let s = SenderState::load(&state_path).await?;
        tracing::info!(num_blocks = s.manifest.num_blocks, "resumed sender state");
        s
    } else {
        let file_len = tokio::fs::metadata(&cli.input).await?.len();
        let block_size = cli.block_size.unwrap_or_else(|| block_size_for(file_len));
        let sha = sha256_file(&cli.input).await?;
        let manifest = Manifest::from_file_len(file_len, block_size, cli.symbol_size, sha);
        tracing::info!(
            file_len,
            block_size,
            symbol_size = cli.symbol_size,
            num_blocks = manifest.num_blocks,
            sha256 = %hex::encode(sha),
            "new sender state",
        );
        let s = SenderState::new_from(manifest, cli.dest.to_string());
        s.save_atomic(&state_path).await?;
        s
    };
    let state = Arc::new(Mutex::new(sender_state));

    let sock = Arc::new(UdpSocket::bind(cli.bind).await?);
    sock.connect(cli.dest).await?;

    // Reverse-channel listener (Send-safe: only touches SenderState + sock).
    {
        let recv_state = state.clone();
        let recv_sock = sock.clone();
        let recv_path = state_path.clone();
        tokio::spawn(async move {
            if let Err(e) = progress_listener(recv_sock, recv_state, recv_path).await {
                tracing::error!(err = %e, "progress listener died");
            }
        });
    }

    // HELLO x3 (UDP loss cover) so receiver has manifest before data.
    let manifest = { state.lock().await.manifest.clone() };
    let mut buf = Vec::with_capacity(cli.symbol_size as usize + 32);
    encode_hello_frame(&mut buf, &manifest)?;
    for _ in 0..3 {
        sock.send(&buf).await?;
        sleep(Duration::from_millis(30)).await;
    }

    encode_loop(cli, state, sock, state_path).await
}

/// Main encoder loop. Runs on the main task's stack so the non-Send
/// `PaddedEncoder<raptor_q_main>` can be held across awaits.
async fn encode_loop(
    cli: Cli,
    state: Arc<Mutex<SenderState>>,
    sock: Arc<UdpSocket>,
    state_path: PathBuf,
) -> Result<()> {
    let mut buf = Vec::with_capacity(cli.symbol_size as usize + 32);
    let mut input = tokio::fs::File::open(&cli.input).await?;
    let mut block_bytes = vec![0u8; { state.lock().await.manifest.block_size } as usize];
    let mut last_save = Instant::now();

    loop {
        let (manifest, undone) = {
            let s = state.lock().await;
            let undone: Vec<u32> = (0..s.manifest.num_blocks)
                .filter(|i| !s.blocks[*i as usize].decoded)
                .collect();
            (s.manifest.clone(), undone)
        };
        if undone.is_empty() {
            tracing::info!("all blocks decoded on receiver side, exiting");
            return Ok(());
        }

        for block_idx in undone {
            let this_block_size = manifest.this_block_size(block_idx);
            block_bytes.resize(this_block_size, 0);
            input.seek(std::io::SeekFrom::Start(block_idx as u64 * manifest.block_size as u64)).await?;
            input.read_exact(&mut block_bytes[..this_block_size]).await
                .with_context(|| format!("reading block {block_idx}"))?;

            let symbol_size = manifest.symbol_size as usize;
            let k_source = ((this_block_size + symbol_size - 1) / symbol_size) as usize;

            // Seed a VecDataOperater with the k_source source symbols.
            // Short tail (last symbol under-full) is zero-padded to symbol_size.
            let mut operator = Box::new(VecDataOperater::new(symbol_size));
            for esi in 0..k_source {
                let sym_start = esi * symbol_size;
                let sym_end = (sym_start + symbol_size).min(this_block_size);
                let mut sym_buf = vec![0u8; symbol_size];
                sym_buf[..sym_end - sym_start].copy_from_slice(&block_bytes[sym_start..sym_end]);
                fountain_engine::traits::data_operator::DataOperator::insert_vector(
                    operator.as_mut(),
                    &sym_buf,
                    esi,
                );
            }

            let scheme = raptor_q_main::new_with_default_setting(k_source);
            let mut encoder = scheme.padded_encoder_with_operator(operator, symbol_size);

            let next_esi = { state.lock().await.blocks[block_idx as usize].next_esi };
            let total_to_emit = k_source * (1 + cli.overhead_factor as usize);
            let mut emitted = 0u32;

            for cursor in next_esi..(next_esi + total_to_emit as u32) {
                if let Some(data_id) = encoder.encode_coded_vector(cursor as usize) {
                    let payload = encoder.get_data_vector(data_id);
                    encode_data_frame(&mut buf, block_idx, cursor, payload)?;
                    if let Err(e) = sock.send(&buf).await {
                        tracing::warn!(err = %e, "udp send transient error");
                    }
                    emitted += 1;
                }
            }

            {
                let mut s = state.lock().await;
                s.blocks[block_idx as usize].next_esi = next_esi + total_to_emit as u32;
            }
            tracing::debug!(block_idx, emitted, "block batch emitted");

            if last_save.elapsed() > Duration::from_secs(1) {
                let s = state.lock().await;
                s.save_atomic(&state_path).await?;
                last_save = Instant::now();
            }

            tokio::task::yield_now().await;
        }

        sleep(Duration::from_millis(20)).await;
    }
}

async fn progress_listener(
    sock: Arc<UdpSocket>,
    state: Arc<Mutex<SenderState>>,
    state_path: PathBuf,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut save_counter = 0u32;
    loop {
        let n = sock.recv(&mut buf).await?;
        if n == 0 { continue; }
        if buf[0] != PROTO_PROGRESS {
            tracing::debug!(byte = buf[0], "ignoring non-progress frame");
            continue;
        }
        let blocks = decode_progress_frame(&buf[..n])?;
        {
            let mut s = state.lock().await;
            for bp in &blocks {
                let idx = bp.block_idx as usize;
                if idx < s.blocks.len() {
                    if bp.decoded && !s.blocks[idx].decoded {
                        tracing::info!(block_idx = bp.block_idx, "receiver reports decoded");
                    }
                    s.blocks[idx].decoded |= bp.decoded;
                }
            }
        }
        save_counter += 1;
        if save_counter % 10 == 0 {
            let s = state.lock().await;
            s.save_atomic(&state_path).await?;
        }
    }
}

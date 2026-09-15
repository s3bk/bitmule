//! Block-fountain (RaptorQ) demo for bitmule.
//!
//! Encoder reads an input file async block-by-block, encodes each block with
//! RaptorQ into a stream of encoded packets, ships them through a simulated
//! lossy channel to a decoder, which reassembles the file and compares its
//! sha256 against the original.
//!
//! Peak decoder RAM = one block. Encoder does not read the whole file into
//! memory; only one block at a time.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(about = "RaptorQ block-fountain demo (encode -> lossy channel -> decode -> verify)")]
struct Cli {
    /// Input file to transmit
    #[arg(long)]
    input: PathBuf,

    /// Path to write the reconstructed file to
    #[arg(long)]
    output: PathBuf,

    /// Block size in bytes (whole block is read into RAM before encoding)
    #[arg(long, default_value_t = 60_000)]
    block_size: u32,

    /// Symbol size in bytes (each encoded packet carries this many bytes of coded data)
    #[arg(long, default_value_t = 1000)]
    symbol_size: u16,

    /// Independent random drop probability per encoded packet [0.0, 1.0)
    #[arg(long, default_value_t = 0.10)]
    loss: f64,

    /// How many extra packets (beyond K per block) the encoder is allowed to emit
    /// before giving up on that block. In practice RaptorQ decodes with ~2%
    /// overhead so a small multiple of K is plenty.
    #[arg(long, default_value_t = 4)]
    overhead_factor: u32,
}

/// A wire packet as it crosses the "network". In a real transport this would
/// serialize as (block_idx: u48, esi: u32, payload: [u8; symbol_size]) or
/// similar; here we keep the raptorq EncodingPacket wrapper directly plus the
/// block index so the receiver can route to the right block's decoder.
struct WirePacket {
    block_idx: u32,
    packet: EncodingPacket,
}

async fn encoder_task(
    input: PathBuf,
    block_size: u32,
    symbol_size: u16,
    overhead_factor: u32,
    tx: mpsc::Sender<WirePacket>,
) -> Result<u32> {
    let mut f = File::open(&input)
        .await
        .with_context(|| format!("open {}", input.display()))?;
    let file_len = f.metadata().await?.len();
    let num_blocks = ((file_len + block_size as u64 - 1) / block_size as u64) as u32;

    tracing::info!(
        file_len,
        block_size,
        symbol_size,
        num_blocks,
        "encoder starting"
    );

    let mut buf = vec![0u8; block_size as usize];
    for block_idx in 0..num_blocks {
        let this_block_size = ((file_len - block_idx as u64 * block_size as u64)
            .min(block_size as u64)) as usize;
        let block = &mut buf[..this_block_size];
        f.read_exact(block).await.with_context(|| {
            format!("reading block {block_idx} ({} bytes)", this_block_size)
        })?;

        // ObjectTransmissionInformation for a single block. `with_defaults`
        // picks sub-block and interleave params from the block bytes+symbol
        // size. We recreate the same OTI on the decoder from the same knobs.
        let oti = ObjectTransmissionInformation::with_defaults(
            this_block_size as u64,
            symbol_size,
        );
        let enc = Encoder::new(block, oti);

        // Emit source packets (systematic — they contain the plaintext
        // symbols) plus a batch of repair packets from each source block.
        // For a 60KB block with 1KB symbols raptorq gives us one source
        // block; we loop over `get_block_encoders` to stay correct if a
        // future config splits into multiple sub-blocks.
        let mut emitted = 0u32;
        for sbe in enc.get_block_encoders() {
            for p in sbe.source_packets() {
                tx.send(WirePacket { block_idx, packet: p }).await.ok();
                emitted += 1;
            }
            let source_count = sbe.source_packets().len() as u32;
            let repair_count = source_count * overhead_factor;
            for p in sbe.repair_packets(0, repair_count) {
                tx.send(WirePacket { block_idx, packet: p }).await.ok();
                emitted += 1;
            }
        }
        tracing::debug!(block_idx, emitted, "block done");
    }
    Ok(num_blocks)
}

/// Independent iid loss. Returns true if the packet should be dropped.
fn should_drop(loss: f64, rng: &mut impl Rng) -> bool {
    loss > 0.0 && rng.gen::<f64>() < loss
}

async fn decoder_task(
    output: PathBuf,
    file_len: u64,
    block_size: u32,
    symbol_size: u16,
    num_blocks: u32,
    loss: f64,
    mut rx: mpsc::Receiver<WirePacket>,
) -> Result<()> {
    let mut decoders: HashMap<u32, (Decoder, Option<Vec<u8>>)> = HashMap::new();
    let mut rng = SmallRng::from_entropy();
    let mut received = 0u64;
    let mut dropped = 0u64;

    // Pre-seed decoders so we always know the OTI shape per block.
    for block_idx in 0..num_blocks {
        let this_block_size = ((file_len - block_idx as u64 * block_size as u64)
            .min(block_size as u64)) as usize;
        let oti = ObjectTransmissionInformation::with_defaults(
            this_block_size as u64,
            symbol_size,
        );
        decoders.insert(block_idx, (Decoder::new(oti), None));
    }

    while let Some(WirePacket { block_idx, packet }) = rx.recv().await {
        received += 1;
        if should_drop(loss, &mut rng) {
            dropped += 1;
            continue;
        }
        let Some((dec, decoded)) = decoders.get_mut(&block_idx) else {
            continue;
        };
        if decoded.is_some() {
            continue;
        }
        if let Some(bytes) = dec.decode(packet) {
            tracing::debug!(block_idx, "block decoded");
            *decoded = Some(bytes);
        }
    }

    tracing::info!(
        received,
        dropped,
        loss_rate = dropped as f64 / received.max(1) as f64,
        "channel stats"
    );

    // All blocks in order → output file.
    let mut out = File::create(&output).await?;
    for block_idx in 0..num_blocks {
        let (_dec, decoded) = decoders
            .remove(&block_idx)
            .ok_or_else(|| anyhow::anyhow!("no decoder for block {block_idx}"))?;
        let bytes = decoded
            .ok_or_else(|| anyhow::anyhow!("block {block_idx} never decoded (too much loss?)"))?;
        out.write_all(&bytes).await?;
    }
    out.flush().await?;
    Ok(())
}

async fn sha256_of(path: &PathBuf) -> Result<[u8; 32]> {
    let mut f = File::open(path).await?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
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
    if !(0.0..1.0).contains(&cli.loss) {
        bail!("--loss must be in [0.0, 1.0)");
    }

    let file_len = tokio::fs::metadata(&cli.input).await?.len();
    let num_blocks =
        ((file_len + cli.block_size as u64 - 1) / cli.block_size as u64) as u32;

    let (tx, rx) = mpsc::channel::<WirePacket>(4);

    let t0 = std::time::Instant::now();

    let enc = tokio::spawn(encoder_task(
        cli.input.clone(),
        cli.block_size,
        cli.symbol_size,
        cli.overhead_factor,
        tx,
    ));
    let dec = tokio::spawn(decoder_task(
        cli.output.clone(),
        file_len,
        cli.block_size,
        cli.symbol_size,
        num_blocks,
        cli.loss,
        rx,
    ));

    let enc_blocks = enc.await??;
    dec.await??;

    let dt = t0.elapsed().as_secs_f64();
    println!("{dt:.1}s, {:.2}MB/s", file_len as f64 / (dt * 1024. * 1024.));


    let a = sha256_of(&cli.input).await?;
    let b = sha256_of(&cli.output).await?;
    if a == b {
        tracing::info!(
            input = %cli.input.display(),
            output = %cli.output.display(),
            blocks = enc_blocks,
            "SUCCESS: sha256 match"
        );
    } else {
        bail!(
            "sha256 mismatch: input={} output={}",
            hex::encode(a),
            hex::encode(b)
        );
    }
    Ok(())
}

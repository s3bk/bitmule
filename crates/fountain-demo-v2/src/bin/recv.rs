//! fountain-recv — listens on UDP, decodes RaptorQ blocks, writes decoded
//! blocks + per-block symbol logs to disk under `<state>/`, reports progress
//! back to the sender at a fixed tick and on every block-decoded event.
//!
//! On startup, if `<state>/manifest.json` exists we resume: each block dir
//! that isn't marked decoded gets its symbols.log replayed into a fresh
//! `RaptorQDecoder` so we don't re-request bytes that already landed.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration as TokioDuration};

use fountain_demo_v2::{
    decode_data_frame, decode_hello_frame, encode_progress_frame, sha256_file,
    BlockProgress, Manifest, ReceiverBlockHeader, DEFAULT_PROGRESS_TICK_MS,
    PROTO_DATA, PROTO_HELLO,
};
use fountain_engine::types::DecodeStatus;
use fountain_raptor_q::raptor_q_main::raptor_q_main;
use fountain_raptor_q::RaptorQDecoder;
use fountain_utility::vec_data_operater::VecDataOperater;

#[derive(Parser, Debug)]
#[command(about = "RaptorQ block-fountain receiver — UDP unicast from fountain-send")]
struct Cli {
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long, default_value_t = DEFAULT_PROGRESS_TICK_MS)]
    tick_ms: u64,
    /// Optional expected sha256 of the input file (hex).
    #[arg(long)]
    verify_sha256: Option<String>,
}

/// Live per-block decoder state — RAM, main-task-only (not Send because
/// `PaddedDecoder<S>` holds `Box<dyn HDPC>` which isn't Send). Rebuilt on
/// restart by replaying the on-disk symbols.log.
struct BlockDecoder {
    header: ReceiverBlockHeader,
    decoded: Option<Vec<u8>>,
    decoder: Option<RaptorQDecoder>,
    log_file: Option<tokio::fs::File>,
    seen_ids: HashSet<u32>,
}

/// Send-safe shared slice — only fields the progress ticker needs.
/// Decoders live in the main task's stack, not here.
struct SharedRecvState {
    manifest: Option<Manifest>,
    /// Snapshot of header state per block for progress packets. Written by
    /// the main task whenever a block changes; read by the progress ticker.
    block_headers: HashMap<u32, ReceiverBlockHeader>,
    sender_addr: Option<SocketAddr>,
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

    let sock = Arc::new(UdpSocket::bind(cli.listen).await?);
    tracing::info!(listen = %cli.listen, state = %cli.state_dir.display(), "receiver listening");

    let shared = Arc::new(Mutex::new(SharedRecvState {
        manifest: None,
        block_headers: HashMap::new(),
        sender_addr: None,
    }));

    // Decoders live in the main task's stack — never cross the spawn line.
    let mut decoders: HashMap<u32, BlockDecoder> = HashMap::new();

    // Resume if we have prior state.
    let manifest_path = cli.state_dir.join("manifest.json");
    if manifest_path.exists() {
        let m = Manifest::load_from(&manifest_path).await?;
        tracing::info!(num_blocks = m.num_blocks, "resuming from prior state");
        for block_idx in 0..m.num_blocks {
            let dir = block_dir(&cli.state_dir, block_idx);
            if !dir.exists() { continue; }
            let hdr = load_or_init_header(&dir, block_idx, &m).await?;
            let mut bd = init_block_decoder(&dir, hdr, &m).await?;
            replay_symbols(&mut bd, &dir).await?;
            let mut sh = shared.lock().await;
            sh.block_headers.insert(block_idx, bd.header.clone());
            drop(sh);
            decoders.insert(block_idx, bd);
        }
        shared.lock().await.manifest = Some(m);
    }

    // Spawn progress ticker — reads shared, sends UDP.
    {
        let sock_c = sock.clone();
        let shared_c = shared.clone();
        let tick = cli.tick_ms;
        tokio::spawn(async move {
            let mut iv = interval(TokioDuration::from_millis(tick));
            loop {
                iv.tick().await;
                if let Err(e) = emit_progress(&sock_c, &shared_c).await {
                    tracing::debug!(err = %e, "progress emit transient");
                }
            }
        });
    }

    // Main recv loop.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if n == 0 { continue; }

        // Snapshot manifest + set sender_addr atomically.
        let manifest = {
            let mut sh = shared.lock().await;
            sh.sender_addr.get_or_insert(from);
            sh.manifest.clone()
        };

        match buf[0] {
            PROTO_HELLO => {
                let m = decode_hello_frame(&buf[..n])?;
                if manifest.is_none() {
                    tracing::info!(num_blocks = m.num_blocks, "manifest received");
                    m.save_to(&manifest_path).await?;
                    for block_idx in 0..m.num_blocks {
                        let dir = block_dir(&cli.state_dir, block_idx);
                        tokio::fs::create_dir_all(&dir).await?;
                        let hdr = load_or_init_header(&dir, block_idx, &m).await?;
                        let bd = init_block_decoder(&dir, hdr, &m).await?;
                        shared.lock().await.block_headers.insert(block_idx, bd.header.clone());
                        decoders.insert(block_idx, bd);
                    }
                    shared.lock().await.manifest = Some(m);
                }
            }
            PROTO_DATA => {
                let manifest = match manifest {
                    Some(m) => m,
                    None => { tracing::debug!("data before hello, ignoring"); continue; }
                };
                let (block_idx, coded_id, payload) = decode_data_frame(&buf[..n])?;
                let bd = match decoders.get_mut(&block_idx) { Some(b) => b, None => continue };
                if bd.header.decoded { continue; }
                if !bd.seen_ids.insert(coded_id) { continue; }

                if let Some(log_f) = bd.log_file.as_mut() {
                    let mut rec = Vec::with_capacity(4 + 2 + payload.len());
                    rec.extend_from_slice(&coded_id.to_le_bytes());
                    rec.extend_from_slice(&(payload.len() as u16).to_le_bytes());
                    rec.extend_from_slice(payload);
                    log_f.write_all(&rec).await?;
                }

                let mut newly_decoded = false;
                if let Some(dec) = bd.decoder.as_mut() {
                    let status = dec.add_coded_vector(coded_id as usize, payload);
                    bd.header.num_received = bd.header.num_received.saturating_add(1);
                    if status == DecodeStatus::Decoded {
                        let out = extract_decoded(dec, &manifest, block_idx);
                        write_decoded(&cli.state_dir, block_idx, &out).await?;
                        bd.header.decoded = true;
                        bd.decoded = Some(out);
                        save_header(&cli.state_dir, block_idx, &bd.header).await?;
                        newly_decoded = true;
                        tracing::info!(block_idx, "block decoded");
                    } else if bd.header.num_received % 32 == 0 {
                        save_header(&cli.state_dir, block_idx, &bd.header).await?;
                    }
                }

                // Mirror header into shared state so progress-ticker sees it.
                shared.lock().await.block_headers.insert(block_idx, bd.header.clone());
                if newly_decoded {
                    // Immediate progress packet on decode event.
                    let _ = emit_progress(&sock, &shared).await;
                }
            }
            other => { tracing::debug!(proto = other, "unknown proto"); }
        }

        // Termination check: all decoded → write output + verify.
        let all_done = {
            let sh = shared.lock().await;
            sh.manifest.as_ref().map_or(false, |m| {
                (0..m.num_blocks).all(|i| sh.block_headers.get(&i).map_or(false, |h| h.decoded))
            })
        };
        if all_done {
            let manifest = shared.lock().await.manifest.clone().unwrap();
            write_output_file(&cli.output, &cli.state_dir, &manifest).await?;
            let got = sha256_file(&cli.output).await?;
            if got != manifest.sha256_expected {
                bail!(
                    "sha256 mismatch after decode: got {} expected {}",
                    hex::encode(got), hex::encode(manifest.sha256_expected)
                );
            }
            if let Some(hex_expected) = &cli.verify_sha256 {
                let want: [u8; 32] = hex::decode(hex_expected)?
                    .try_into().map_err(|_| anyhow::anyhow!("bad --verify-sha256 length"))?;
                if got != want { bail!("output failed --verify-sha256 check") }
            }
            tracing::info!(sha256 = %hex::encode(got), "transfer complete + integrity verified");
            return Ok(());
        }
    }
}

fn block_dir(root: &Path, block_idx: u32) -> PathBuf {
    root.join(format!("block-{:06}", block_idx))
}

async fn load_or_init_header(dir: &Path, block_idx: u32, manifest: &Manifest) -> Result<ReceiverBlockHeader> {
    let p = dir.join("header.json");
    if p.exists() {
        let b = tokio::fs::read(&p).await?;
        Ok(serde_json::from_slice(&b)?)
    } else {
        let this_size = manifest.this_block_size(block_idx);
        let k = (this_size as u32 + manifest.symbol_size as u32 - 1) / manifest.symbol_size as u32;
        let h = ReceiverBlockHeader { block_idx, k_source: k, num_received: 0, decoded: false };
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::write(&p, serde_json::to_vec_pretty(&h)?).await?;
        Ok(h)
    }
}

async fn save_header(root: &Path, block_idx: u32, hdr: &ReceiverBlockHeader) -> Result<()> {
    let p = block_dir(root, block_idx).join("header.json");
    let tmp = p.with_extension("json.tmp");
    tokio::fs::write(&tmp, serde_json::to_vec_pretty(hdr)?).await?;
    tokio::fs::rename(&tmp, &p).await?;
    Ok(())
}

async fn init_block_decoder(dir: &Path, hdr: ReceiverBlockHeader, manifest: &Manifest) -> Result<BlockDecoder> {
    let log_path = dir.join("symbols.log");
    let log_file = if hdr.decoded {
        None
    } else {
        Some(tokio::fs::OpenOptions::new().create(true).append(true).open(&log_path).await?)
    };
    let decoder = if hdr.decoded {
        None
    } else {
        let scheme = raptor_q_main::new_with_default_setting(hdr.k_source as usize);
        let operator = Box::new(VecDataOperater::new(manifest.symbol_size as usize));
        Some(scheme.padded_decoder_with_operator(operator, manifest.symbol_size as usize))
    };
    let mut decoded = None;
    if hdr.decoded {
        let p = dir.join("decoded.bin");
        if p.exists() {
            decoded = Some(tokio::fs::read(&p).await?);
        }
    }
    Ok(BlockDecoder { header: hdr, decoded, decoder, log_file, seen_ids: Default::default() })
}

async fn replay_symbols(bd: &mut BlockDecoder, dir: &Path) -> Result<()> {
    if bd.decoder.is_none() { return Ok(()); }
    let log_path = dir.join("symbols.log");
    if !log_path.exists() { return Ok(()); }
    let mut f = tokio::fs::File::open(&log_path).await?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).await?;
    let mut cursor = 0;
    let mut replayed = 0u32;
    while cursor + 6 <= buf.len() {
        let coded_id = u32::from_le_bytes(buf[cursor..cursor+4].try_into().unwrap());
        let plen = u16::from_le_bytes(buf[cursor+4..cursor+6].try_into().unwrap()) as usize;
        cursor += 6;
        if cursor + plen > buf.len() { break; }
        let payload = &buf[cursor..cursor+plen];
        cursor += plen;
        if !bd.seen_ids.insert(coded_id) { continue; }
        if let Some(dec) = bd.decoder.as_mut() {
            let _ = dec.add_coded_vector(coded_id as usize, payload);
        }
        replayed += 1;
    }
    bd.header.num_received = replayed;
    tracing::info!(block_idx = bd.header.block_idx, replayed, "log replay complete");
    Ok(())
}

fn extract_decoded(dec: &RaptorQDecoder, manifest: &Manifest, block_idx: u32) -> Vec<u8> {
    let this_size = manifest.this_block_size(block_idx);
    let k = ((this_size as u32 + manifest.symbol_size as u32 - 1) / manifest.symbol_size as u32) as usize;
    let mut out = Vec::with_capacity(this_size);
    for data_id in 0..k {
        let v = dec.get_data_vector(data_id);
        let take = (this_size - out.len()).min(v.len());
        out.extend_from_slice(&v[..take]);
        if out.len() >= this_size { break; }
    }
    out
}

async fn write_decoded(root: &Path, block_idx: u32, bytes: &[u8]) -> Result<()> {
    let p = block_dir(root, block_idx).join("decoded.bin");
    let tmp = p.with_extension("bin.tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, &p).await?;
    Ok(())
}

async fn write_output_file(out_path: &Path, root: &Path, manifest: &Manifest) -> Result<()> {
    let mut f = tokio::fs::File::create(out_path).await?;
    for block_idx in 0..manifest.num_blocks {
        let p = block_dir(root, block_idx).join("decoded.bin");
        let bytes = tokio::fs::read(&p).await
            .with_context(|| format!("reading decoded block {block_idx}"))?;
        f.write_all(&bytes).await?;
    }
    f.flush().await?;
    Ok(())
}

async fn emit_progress(sock: &UdpSocket, shared: &Arc<Mutex<SharedRecvState>>) -> Result<()> {
    let (dest, blocks) = {
        let sh = shared.lock().await;
        let dest = match sh.sender_addr { Some(a) => a, None => return Ok(()) };
        let mut blocks: Vec<BlockProgress> = sh.block_headers.values().map(|h| BlockProgress {
            block_idx: h.block_idx,
            symbols_received: h.num_received,
            decoded: h.decoded,
        }).collect();
        blocks.sort_by_key(|b| b.block_idx);
        (dest, blocks)
    };
    let mut buf = Vec::with_capacity(1 + 4 + blocks.len() * 9);
    encode_progress_frame(&mut buf, &blocks);
    sock.send_to(&buf, dest).await?;
    Ok(())
}

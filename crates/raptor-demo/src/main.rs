

const KB: usize = 1024;
const MB: usize = 1024 * 1024;
const BLOCK_SIZE: usize = 2 * MB;
const SYMBOL_SIZE: usize = 8 * KB;
const N_SYMBOLS: usize = BLOCK_SIZE / SYMBOL_SIZE;

use std::{collections::HashSet, io, path::{Path, PathBuf}};

use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use raptorq::{Decoder, ObjectTransmissionInformation, SourceBlockDecoder, SourceBlockEncoder, SourceBlockEncodingPlan};
use tokio::{select, spawn, sync::mpsc};
use tokio_uring::fs::{File, OpenOptions};
use anyhow::{Error, anyhow};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "RaptorQ block-fountain demo (encode -> lossy channel -> decode -> verify)")]
struct Cli {
    /// Input file to transmit
    #[arg(long)]
    input: PathBuf,

    /// Path to write the reconstructed file to
    #[arg(long)]
    output: PathBuf,

    #[arg(long)]
    partial: PathBuf,

    /// Independent random drop probability per encoded packet [0.0, 1.0)
    #[arg(long, default_value_t = 0.10)]
    loss: f64,

    /// How many extra packets (beyond K per block) the encoder is allowed to emit
    /// before giving up on that block. In practice RaptorQ decodes with ~2%
    /// overhead so a small multiple of K is plenty.
    #[arg(long, default_value_t = 4)]
    overhead_factor: u32,
}

struct InputBlock {
    block_nr: u64,
    data: Vec<u8>
}

async fn read_loop(input: PathBuf, input_size: u64, tx: mpsc::Sender<InputBlock>) -> Result<(), Error> {
    let file = File::open(&input).await?;
    let n_blocks = div_ceil(input_size, BLOCK_SIZE as u64);

    for n in 0 .. n_blocks {
        let offset = BLOCK_SIZE as u64 * n;
        let size = (input_size - offset).min(BLOCK_SIZE as u64) as usize;
        let mut data = Vec::with_capacity(BLOCK_SIZE);
        data.resize(size, 0);
        let (res, mut data) = file.read_at(data, offset).await;
        data.resize(BLOCK_SIZE, 0);
        tx.send(InputBlock { block_nr: n, data }).await?;
    }
    Ok(())
}

async fn encode_loop(mut rx: mpsc::Receiver<InputBlock>, tx: mpsc::Sender<Packet>) -> Result<(), Error> {
    let symbol_count = div_ceil(BLOCK_SIZE, SYMBOL_SIZE);
    let plan = SourceBlockEncodingPlan::generate(symbol_count as u16);
    let config = ObjectTransmissionInformation::new(0, SYMBOL_SIZE as u16, 0, 1, 1);

    while let Some(input) = rx.recv().await {
        let encoder = SourceBlockEncoder::with_encoding_plan(1, &config, &input.data, &plan);
        let packets = encoder.repair_packets(0, 1);

        for data in packets {
            tx.send(Packet { block_nr: input.block_nr, data  }).await?;
        }
    }

    Ok(())
}

async fn decode_loop(mut rx: mpsc::Receiver<Packet>, partial_tx: mpsc::Sender<PartialBlock>, complet_tx: mpsc::Sender<CompleteBlock>, num_blocks: usize) -> Result<(), Error> {
    let config = ObjectTransmissionInformation::new(0, SYMBOL_SIZE as u16, 0, 1, 1);

    const ELEMENTS: u64 = N_SYMBOLS as u64 * SYMBOL_SIZE as u64;
    let mut decoder = SourceBlockDecoder::new(1, &config, ELEMENTS);
    let mut last_block = 0;
    let mut block_complete = false;
    let mut complete = HashSet::new();

    while let Some(Packet { block_nr, data }) = rx.recv().await {
        if complete.contains(&block_nr) {
            continue;
        }
        if block_nr != last_block {
            if !block_complete {
                partial_tx.send(PartialBlock { block_nr, decoder }).await?;
            }
            decoder = SourceBlockDecoder::new(1, &config, ELEMENTS);
        }
        last_block = block_nr;
        if let Some(data) = decoder.decode(std::iter::once(data)) {
            complet_tx.send(CompleteBlock { block_nr, data }).await?;
            block_complete = true;
            complete.insert(block_nr);
            if complete.len() == num_blocks {
                break;
            }
        }
    }
    Ok(())

}

struct PartialBlock {
    block_nr: u64,
    decoder: SourceBlockDecoder,
}
struct CompleteBlock {
    block_nr: u64,
    data: Vec<u8>,
}

async fn save_output(mut rx: mpsc::Receiver<CompleteBlock>, output_file: PathBuf, file_size: u64, ) -> Result<(), Error> {
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&output_file)?;
    file.set_len(file_size)?;
    let file = File::from_std(file);

    let mut pending = FuturesUnordered::new();
    loop {
        select!{
            Some(CompleteBlock { block_nr, data }) = rx.recv(), if !rx.is_closed() => {
                let pos = block_nr * BLOCK_SIZE as u64;
                pending.push(file.write_all_at(data, pos).map(move |r| (block_nr, r)));
            }
            Some((block_nr, (r, buf))) = pending.next(), if !pending.is_empty() => {
                match r {
                    Err(e) => println!("save output {block_nr}: {e:?}"),
                    Ok(()) => {}
                }
            }
            else => {
                break
            }
        }
    }
    Ok(())
}

async fn save_decoder(mut rx: mpsc::Receiver<PartialBlock>, dir: &Path) -> Result<(), Error> {
    // this needs to be implemented much differently
    let mut pending = FuturesUnordered::new();

    loop {
        select!{
            Some(PartialBlock { block_nr, decoder }) = rx.recv(), if !rx.is_closed() => {
                let data = postcard::to_stdvec(&decoder).unwrap();
                let f_name = dir.join(format!("decoder_{block_nr}.data"));
                pending.push(async move {
                    let file = match File::create(f_name).await {
                        Ok(file) => file,
                        Err(err) => return (block_nr, Err(err.into())),
                    };
                    let (r, buf) = file.write_all_at(data, 0).await;
                    (block_nr, r)
                });
            }
            Some((block_nr, r)) = pending.next(), if !pending.is_empty() => {
                match r {
                    Err(e) => println!("save decoder {block_nr}: {e:?}"),
                    Ok(()) => {}
                }
            }
            else => {
                break
            }
        }
    }
    Ok(())
}

struct Packet {
    block_nr: u64,
    data: raptorq::EncodingPacket,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let args = Cli::parse();
    std::fs::create_dir_all(&args.partial)?;

    let input_size = std::fs::metadata(&args.input)?.len();
    let num_blocks = div_ceil(input_size, BLOCK_SIZE as u64);

    let (input_tx, input_rx) = mpsc::channel(4);
    let (packet_tx, packet_rx) = mpsc::channel(1024);
    let (partial_tx, partial_rx) = mpsc::channel(16);
    let (complete_tx, complete_rx) = mpsc::channel(16);

    let t_read = std::thread::spawn(move || {
        tokio_uring::start(read_loop(args.input, input_size, input_tx))
    });

    let t_encode = spawn(encode_loop(input_rx, packet_tx));
    let t_decode = spawn(decode_loop(packet_rx, partial_tx, complete_tx, num_blocks as usize));
    let t_partial = std::thread::spawn(move || {
        tokio_uring::start(save_decoder(partial_rx, &args.partial))
    });
    let t_complete = std::thread::spawn(move || {
        tokio_uring::start(save_output(complete_rx, args.output, input_size))
    });

    t_decode.await??;
    t_partial.join().unwrap()?;
    t_complete.join().unwrap()?;
    t_encode.await??;
    t_read.join().unwrap()?;

    Ok(())
}
fn div_ceil<T: Copy + From<u8> + std::ops::Add<Output = T> + std::ops::Sub<Output = T> + std::ops::Div<Output = T>>(a: T, b: T) -> T {
    (a + (b - 1u8.into())) / b
}

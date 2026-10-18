# UDP: the receiver says what it needs (work in progress, 2026-10-18)

Why: over a lossy path the UDP sender sent passes of a fixed size (pass 0: 256 source + 16 repair symbols per block, each
later pass 32 repair per block, the whole file per pass) and slowed down on loss. At 20% extra loss (sudfa, 100 MB) it took
122 s (0.8 MiB/s) against 13.5 s clean, though the hash matched. A fountain code should make loss cost only the symbols
lost: the receiver tells the sender how many more symbols each block needs, the sender sends those.

## Design

- Feedback packet (sealed, every 50 ms) = fixed part (done base, bitmap of 256 blocks, symbols seen, symbols received) +
  an opaque application report of up to `REPORT_MAX` (800) bytes. The UDP layer only carries it.
- The report (`crates/bitmule/src/v2/need.rs`) is a list of `block_nr u32 LE | need u16 LE`, lowest blocks first, for blocks
  being worked on that need more than 0 symbols. `need = N_SYMBOLS + OVERHEAD(4) - symbols received of that block`.
- Sender (not done yet): per block keep the next unused repair number and when it last sent that block.
  - First visit: all source symbols + `max(16, ceil((N+8)/(1-p)) - N)` repairs, `p` = `udp.done.loss()` (the path's usual loss).
  - Later visits (the reader cycles passes over the file): skip blocks in `udp.done`; if the report names the block, send
    `ceil(need/(1-p)) + 2` repair symbols from the block's next repair number; if it does not (nothing arrived yet, or
    still in flight) send the default 32, but not within ~300 ms of the last send of that block (stops tiny files
    from being resent in a tight loop before the first report arrives).
  - Repair numbers never repeat for a block (`EncodedBlock::frames_range(with_source, start, count)`).
- Rate control stays as it is (loss above the lower quartile of the last 100 reports counts as congestion). Check afterwards
  whether the 0.8 MiB/s under combined loss was the rate control or the passes: if still slow, drive the rate from the
  receiver's delivered rate instead of loss.

## Done (uncommitted, compiles)

- `udp.rs` / `udp_uring.rs`: `Report` (= `Arc<Mutex<Bytes>>`), `REPORT_MAX`, `FEEDBACK_FIXED`; `UdpLink.report` (receiver writes it);
  the sender stores the latest in `DoneBlocks::report()`; `DoneBlocks::loss()` (the baseline loss from `RateControl`).
  `ReceiveState::new` and the receiver tasks take the report cell.
- `fountain.rs`: `EncodedBlock::frames_range`; `frames_with` uses it.
- `v2/need.rs`: encode/decode of the report (+2 unit tests, not run yet), module added in `v2/mod.rs`.
- `v2/recv.rs` `udp_download`: counts symbols per block from the payload header, drops a block from the counts when the
  decoder reports it finished (and forwards that to `udp.block_done`), writes the report every 50 ms.

## To do

1. Sender, `udp_upload` in `v2/send.rs`: the per-block logic above (needs `frames_range` instead of `block.pass`/`frames`).
2. Tests: `need.rs`; a library test through the bitmule crate with loss (needs `UdpConfig.drop` plumbing; today only the
   `BITMULE_UDP_DROP` env var in `recv.rs` and `BITMULE_UDP_MTU`).
3. Local check with `$SCRATCH/run.sh target/release DROP` (100 MB, `--udp-only`, local server on 127.0.0.1:18443): 0, 5, 20, 40, 60%.
   Before: 3.1, 3.3, 3.8, 4.0, 4.9 s.
4. sudfa: `scripts/deploy.sh sudfa-test [DROP]` (ssh to sudfa works; do not use `pkill -f` there, it kills its own ssh shell).
   Before: clean 13.5 s, 20% extra loss 122 s.
5. Update `docs/wire-protocol.md` (feedback packet now carries the report), `docs/v2-status.md`.

## Other things learned today (also in `docs/v2-status.md`)

- `tokio-uring` 0.5.0 use-after-free on runtime drop: fixed in `vendor/tokio-uring`.
- A big DF probe can make the kernel cache a bogus path MTU (552 seen on sudfa): probing and data use `IP_PMTUDISC_PROBE`.
- Still to do from before: the StackOverflow comparison report (SCTP receive window 1 MiB vs 4, UDP buffers capped by
  `rmem_max`, message size), WebRTC MTU discovery, redeploy of the relay on artisan, wasm bundle rebuild, removing TEMP-INSTR code.

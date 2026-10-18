# v2 status (written 2026-10-17, to reload a session)

Nothing from this work is committed. `git status` shows it all as modified or untracked.
`git rm` staged the deletion of `bitmule-client-native/src/send_loop.rs`, and a staged rename
`v2.rs -> v2/old.rs` is left over (`old.rs` itself is deleted; the new files are in `v2/`).

## Where it stands

Sender -> server -> receiver works end to end, over the relay (Raptor coded) and over a WebRTC data
channel, 1 sender to N receivers. Test suites that passed when last run:

- `cargo test -p bitmule --test v2_transfer` (9 tests: relay, WebRTC only, both, fallback when one
  side lacks WebRTC, 1->3 over each transport; about 150 s in debug)
- `cargo test -p bitmule-server` (handshake/auth/reconnect test, relay unit tests)
- `cargo test -p bitmule-client-common --lib` (fountain codec, spill, block I/O; also run with
  `BITMULE_NO_IO_URING=1` to exercise the blocking fallback)
- `cargo test -p bitmule-client-native --lib rtc::` (WebRTC worker alone)
- `cargo check --workspace --all-targets --exclude bitmule-server-signal-ws` is clean.
  `bitmule-server-signal-ws` is dead v1 code that no longer compiles; drop it from the workspace.

Smoke test with the real CLI against the relay on `artisan`, 20 MB, both processes on one machine:
hash matched over WebRTC (1.8 s) and over the relay (2.7 s).

## Relay on artisan

- PUBLIC relay: `~/bitmule-relay/start-prod.sh` runs `bitmule-server-prod` on 127.0.0.1:8443 (behind the
  TLS proxy for https://bitmule.qdat.net) and STUN on UDP 3478; upload as `bitmule-server.prod`;
  logs `prod.log`, pid `prod.pid`. It replaced the old server (old binary still in `~/bitmule/target/release`).
  `web/` there is still the old SPA. `--nic IFACE` limits a client to one interface.
- Test relay at `http://artisan:17843` (port picked because it was free). Files in `~/bitmule-relay/`:
  `bitmule-server`, `start.sh` (kills the pid in `relay.pid`, starts detached), `relay.pid`, `relay.log`.
- To update: build `cargo build --release -p bitmule-server`, `strip`, `scp` to
  `artisan:bitmule-relay/bitmule-server.new`, run `ssh artisan ~/bitmule-relay/start.sh`.
  Do not use `pkill -f` there (it matched its own ssh shell once).
- Another, unrelated `bitmule-server` runs on artisan (127.0.0.1:8443, from a `target/release`
  checkout). Do not touch it.
- No TLS, so clients use `--server http://artisan:17843`.
- The binary must be rebuilt and redeployed whenever `bitmule-core::protocol` changes (it did for
  `caps`).

Two-instance test the user planned (one on ethernet, one on wifi):
`bitmule --server http://artisan:17843 send [--webrtc|--relay] FILE` prints the share URL;
`bitmule --server ... recv [--webrtc|--relay] --out FILE URL` prints which transport carried it.
Release CLI: `target/release/bitmule`. Not yet run across two real NICs.

## Open items

1. **Receiver exit race (fixed, confirmed 2026-10-17: 5/5 clean exits in each of default, `--relay`,
   `--webrtc`, 20 MB, local relay, release build).** In relay mode the sender did not exit after the
   receiver finished: the receiver's `Complete` could be lost when its process exited. Fix: the
   receiver now waits for its websocket worker to flush (`connect_ws` returns a `JoinHandle`; see
   `v2/session.rs::receive`). A smoke-test loop to confirm it (sender exits by itself in default,
   `--relay`, `--webrtc` modes) was started in the background and not read. Re-run it.
2. Sender returns once all receivers it knows have finished; a late joiner after that is not served.
   A "wait for N receivers" option would make 1->N deterministic.
3. Throughput not measured. Debug builds only in tests; demo figure is 600 MB/s.
4. Receiver reconnect is not in the client (server side is done: `?token=` on `/ws/create` skips PoW).
5. wasm not built; the `raptorq` fork and tokio-uring are untested there. Windows untested.
6. Server: receivers can still message each other via `SendTo`; reconnect token is per-session owner
   only; `docs/wire-protocol.md` and parts of `docs/flow.md` describe the old protocol.
7. STUN works (2026-10-17): bitmule-server answers Binding requests on UDP 3478 (`--stun-bind`,
   `--no-stun`); clients ask it from each IPv4 socket and offer the result as a server reflexive
   candidate (`--stun HOST:PORT|none` overrides; default is the signaling host, port 3478). Verified
   across two separate LANs (WebRTC only, 50 MB). Still no ICE trickle and no TURN: symmetric NAT /
   CGNAT peers fall back to the relay. A forced `--webrtc` whose channel fails leaves the sender waiting.
8. WebRTC data path is plain `read_at` / `write_bytes` (16 KiB messages); not tuned.

## Architecture (user's rules: separate tokio tasks, talk only through channels, no spaghetti;
## the WebRTC code must not know about the websocket)

```
server <-ws-> websocket worker (client-native/websocket.rs: connect_ws)
          -> session worker (bitmule/src/v2/session.rs) routes by peer
          -> peer worker (v2/peer.rs): key exchange, seals/opens -> PeerLink of plain Peer2Peer
          -> demux (v2/peer.rs): SDP messages -> signaling link, the rest -> app link
signaling link -> WebRTC worker (client-native/src/rtc.rs): DataChannel {send, events}
app link       -> transfer worker (v2/send.rs per receiver; v2/recv.rs)
```
- `v2/mod.rs`: `Server`, `Options {webrtc, relay}` (`from_mode(TransportMode)`), `Transport`,
  `Report`, `run_send`, `run_recv(server, link, std::fs::File /*read+write*/, options)`.
- `v2/dcproto.rs`: data channel messages (`Get`, `Data`, 16 KiB pieces).
- Flow: Manifest -> receiver `Get{0,size}` -> sender `JoinRelay` + (if both have WEBRTC) SDP offer.
  Receiver starts the relay download; when the data channel opens the relay download is stopped
  gracefully (it decodes and writes what it already took and reports the finished blocks), and the
  data channel then asks, one range at a time, only for the byte ranges of the blocks still missing.
  Partial blocks of the relay are dropped. If the channel dies the relay restarts from scratch.
  `Report` has `relay_bytes` / `data_channel_bytes`; the CLI prints the split. Finished when either delivers
  everything; then SHA256(file || bulk_key) is checked against the share link signature and
  `Complete` is sent.
- Capabilities (`PeerCaps`) travel in `PeerJoined` / `SessionJoined` (`caps`, `sender_caps`).

## Relay / server (crates/bitmule-server)

- Routes: `GET /pow`, `/ws/create?sid&magic&pow[&token]`, `/ws/join?sid`,
  `/session/:sid/:receiver_id?token=` (POST = sender upload, GET = receiver download).
- `SessionCreated {reconnect_token, relay_token}`, `SessionJoined {relay_token, sender_*}`;
  tokens are `bitmule_core::Token` (16 bytes). Reconnect needs the token, the same id and the same
  identity key, and skips PoW; a token cannot create a session. Duplicate receiver ids rejected.
  Relay GET/POST need the peer's own relay token (POST: owner id only).
- Relay is broadcast, not routed: every frame goes to all connected receivers (queue 8 each); the
  sender waits only if no receiver can take it (blocks with no receivers). Newer POST replaces the
  older. Only frame type `F_DATA` exists.
- `bitmule_server::router(state)` is shared by `main.rs` and the tests.

## Fountain / I/O (crates/bitmule-client-common)

- `fountain.rs`: 2 MiB blocks, 8 KiB symbols, 256 symbols/block (same as `raptor-demo`, same
  `raptorq` git fork); AES-GCM per block (nonce = block number), xxh3 block hash in every frame,
  pooled buffers (`Pool`/`Pooled`), systematic first pass + 16 repair, later passes +32 repair.
  Frame: `len u16 | type | block_nr u32 | hash u64 | payload id 4 | symbol`.
- `Decoder`: out-of-order block completion, at most 4 partial blocks in memory, the rest spilled
  via `SpillSink`; symbols for a block being read back are held until it returns.
- `blockio.rs`: io_uring on Linux with automatic blocking fallback (`BITMULE_NO_IO_URING=1` forces
  the fallback): `read_blocks` (reader thread), `BlockWriter` (16 writes in flight; blocks and byte
  ranges), `FileSpill` (spill into the block's gap in the output file, overflow to a temp file; one
  worker per block, so a read-back only delays its own block).

## Other facts worth knowing

- str0m needs a crypto provider feature: set to `rust-crypto` in `bitmule-client-native/Cargo.toml`.
- Debug builds are slow (PoW at difficulty 22, Raptor); tests take minutes.
- `docs/flow.md` was updated for the new URLs; `docs/old-proto.md` is the user's untracked file.
- User preferences stated this session: everything async; no blocking of the decode path by spill I/O;
  per-block hash kept; io_uring for native Linux; demo-style buffer pools; keep components isolated.

# v2 status (updated 2026-10-18, to reload a session)

Committed as `24a1b61` ("v2 transfer protocol: relay + WebRTC, STUN, --nic"). NOT yet committed
(2026-10-18): the receiver-initiated request link (see below): `bitmule-core/src/protocol.rs`,
`bitmule/src/main.rs`, `bitmule/src/v2/{mod,session}.rs`, `bitmule/tests/v2_transfer.rs`, and this
file. Deliberately left
untracked: `perf.data*`, `flamegraph.svg` files, `bitmule-android/.../jniLibs`, `.../uniffi`,
`gradle-daemon-jvm.properties`, `icon256.webp`, `web/icons/NoteGPT_*.png`, and the user's
`docs/old-proto.md`. (A `.gitignore` entry for `perf.data*` / `flamegraph.svg` would help.)

## Where it stands

Sender -> server -> receiver works end to end, 1 sender to N receivers, over the relay (Raptor
coded), over a WebRTC data channel, or both: the transfer starts on the relay and moves to the data
channel when it opens (see Flow). Peers on separate LANs connect directly through STUN.

Tests that passed when last run (2026-10-17/18):

- `cargo test -p bitmule` (13 integration tests in `tests/v2_transfer.rs`: relay, WebRTC only, both,
  relay-to-data-channel hand-over, receiver-initiated over relay and WebRTC, wrong request key,
  fallback when one side lacks WebRTC, 1->3 over each transport,
  about 25 s in debug; plus unit tests for `dcproto` and the recv range bookkeeping). Every roundtrip
  checks `relay_bytes + data_channel_bytes == size` when WebRTC finished the transfer.
- `cargo test -p bitmule-server` (handshake/auth/reconnect, relay and STUN unit tests)
- `cargo test -p bitmule-client-common --lib` (fountain codec, spill, block I/O; also run with
  `BITMULE_NO_IO_URING=1` to exercise the blocking fallback; not re-run since the last change)
- `cargo test -p bitmule-client-native --lib` (WebRTC worker, STUN client)
- Tests clean up after themselves (all `tempfile`, `kill_on_drop`); checked by diffing /tmp, the repo,
  ~/.config and processes before/after a run.
- `cargo check --workspace --all-targets --exclude bitmule-server-signal-ws` was clean.
  `bitmule-server-signal-ws` is dead v1 code that no longer compiles; drop it from the workspace.
  `bitmule-e2e-tests` was not run.

Real-world checks with the release CLI:
- Exit race (receiver's `Complete` lost on exit): fixed, 5/5 clean exits in each of default,
  `--relay`, `--webrtc`.
- Two separate LANs (this machine on `enp1s0f0`, `sudfa.mywire.org` on `wlp61s0`, via
  https://bitmule.qdat.net): relay, auto and WebRTC-only all match. 400 MB over WebRTC in 42 s
  (about 9.5 MB/s, WAN-limited). Loopback, 1 GB through the data channel: 17-24 s.
- Hand-over on loopback (1 GB): 40 MB via relay, 958 MB via data channel, hash matched. Over the WAN
  the data channel opens (about 0.3 s) before the relay finishes a 2 MiB block, so nothing is
  handed over there.
- End-to-end encryption checked with a recording proxy in front of the server (30 MB marker file,
  relay and WebRTC): no plaintext, share key, commitment or URL fragment in what the server saw; relay
  body incompressible; a control on the plain file is detected. Key-swap protection (HMAC of the
  identity key with the share key, 3-DH session key) is from code reading, not an active attack test.
  The server still sees session id, IPs, timing and transfer size. Browser clients would trust the
  JS the server delivers.

## Receiver-initiated transfers (request link)

The old "receiver mints a URL for the sender" flow, redone for v2 without any server change:
- `bitmule recv [--out FILE]` with no link creates a rendezvous session under a fresh key and prints
  `<server>/send#<64 hex>` (plus QR). `bitmule send --to URL FILE` answers it.
- The sender joins the rendezvous session (it must know the key: same MAC check as everywhere), then
  creates its own ordinary v2 session (it is the owner there, so the relay POST rules are unchanged),
  and sends the new share link over the sealed peer channel as `Peer2Peer::ShareLink(String)`
  (b64url, appended at the end of the enum). The receiver gets the link and runs `run_recv` as
  usual, so the data signature (SHA256(file || bulk_key)) is still verified, which the old flow could
  not do. The rendezvous connection closes after the link is delivered.
- Library: `v2::run_request(server, options, on_request(&ShareKey)) -> ShareLink`,
  `v2::run_send_to(server, &request_key, manifest, transfer, options, on_link)`,
  `Server::request_url`. In `session.rs`: `create()` / `join()` are shared by all four flows.
- Verified: integration tests (relay, WebRTC, wrong key refused) and the release CLI across two LANs
  (receiver here, sender on sudfa, 100 MB, public relay): done over WebRTC, file matched. The server
  was not redeployed (it only routes the sealed message).
- Not done: anyone with the request link can be the sender and the first valid link wins (several
  senders to one request are not handled); the web SPA does not know `/send#` links yet.

## Relay on artisan

- PUBLIC relay (replaced the old server on 2026-10-17): `~/bitmule-relay/start-prod.sh` runs
  `bitmule-server-prod --bind 127.0.0.1:8443 --web-dir web/` (cwd `~/bitmule`) behind the TLS proxy
  for https://bitmule.qdat.net (certificate valid to 2026-12-02), plus STUN on UDP 3478 (reachable
  from outside). Logs `prod.log`, pid `prod.pid`. Old binary still at `~/bitmule/target/release`
  for rollback (old args: `--web-dir web/ --data-dir ../bitmule-data/ --max-disk-bytes 10GB`; the new
  server has neither data-dir nor disk limit). `web/` there is still the old SPA, which speaks the
  old protocol.
- To update: `cargo build --release -p bitmule-server`, `strip`, `scp` to
  `artisan:bitmule-relay/bitmule-server.prod`, `ssh artisan ~/bitmule-relay/start-prod.sh`.
  Do not use `pkill -f` there (it matched its own ssh shell once).
- Test relay at `http://artisan:17843` (still running, `start.sh`, `bitmule-server`, `relay.pid`);
  it has an older build without STUN. Stop it when no longer needed.
- Rebuild and redeploy whenever `bitmule-core::protocol` changes.
- `artisan` does not resolve from sudfa; use bitmule.qdat.net.

CLI options: `send --to URL`, `--server URL`, `--nic IFACE` (WebRTC sockets, websocket and relay HTTP stay on that
interface; Linux), `--stun HOST:PORT|none`. Server: `--bind`, `--web-dir`, `--stun-bind`, `--no-stun`.

## Open items

1. A forced `--webrtc` whose channel fails (ICE disconnected) leaves the sender waiting; it should
   give up with an error.
2. Sender returns once all receivers it knows have finished; a late joiner after that is not served.
   A "wait for N receivers" option would make 1->N deterministic.
3. Throughput: the data channel path is plain `read_at` / `write_bytes` with 16 KiB messages and is
   not tuned (about 45-60 MB/s on loopback); relay figure from the demo is 600 MB/s, not measured here.
4. Receiver reconnect is not in the client (server side is done: `?token=` on `/ws/create` skips PoW).
5. wasm not built; the `raptorq` fork and tokio-uring are untested there. Windows untested
   (`--nic` is Linux only).
6. Server: receivers can still message each other via `SendTo`; reconnect token is per-session owner
   only; `docs/wire-protocol.md` and parts of `docs/flow.md` describe the old protocol.
7. No ICE trickle and no TURN: peers behind symmetric NAT / CGNAT fall back to the relay. No IPv6 on
   the test hosts, so IPv6 candidates are untested.
8. Hand-over drops the relay's partial blocks, and if the data channel dies the relay restarts from
   scratch (blocks the data channel already delivered are fetched again).
9. Receiver-initiated: one sender per request link, first link wins; no timeout while waiting.
10. Web SPA on the public host is the old one; the browser client needs porting to v2.

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
- `client-native/src/nic.rs` holds the process-wide interface choice; `stun.rs` is the STUN client
  (asked per socket before the pool's receive tasks start); `bitmule-server/src/stun.rs` the responder.
- User preferences stated so far: everything async; no blocking of the decode path by spill I/O;
  per-block hash kept; io_uring for native Linux; demo-style buffer pools; keep components isolated.

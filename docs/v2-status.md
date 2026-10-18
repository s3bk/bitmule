# v2 status (updated 2026-10-18, security audit fixes)

## Security audit fixes (2026-10-18, committed)
Wire-incompatible with earlier builds: **redeploy `bitmule-server` and update all clients (including the wasm bundle).**
- Handshake: join proof (`CreateSession.join_check`, `JoinSession.join_proof`; the server refuses joins without it before
  sending the owner's key or a relay token); identity MAC binds role + session + id; envelope AAD binds direction
  (reflection does not open); own-key replay refused (`bitmule-crypto`, `bitmule-core/inner.rs`, `v2/session.rs`, wasm `session.rs`).
- Block hashes: truncated BLAKE3 per 2 MiB block in `TransferManifest.block_hashes`. The CLI sender records hashes on pass 0
  and aborts the upload (`UploadFailed`) if a later pass differs; relay upload and receivers check against the manifest.
  Capped at 1M blocks (then omitted). The web sender sends none.
- Receive policy: `--on-conflict ask|overwrite|reject|rename` (`output.rs`; library default rename, CLI default ask),
  zip unpack checked against `unpacked_size` (`unzip.rs`, fallback limit transfer*10+1 GiB), files failing the final check
  are deleted unless `--keep-failed` (`v2::VerifyFailed`). Overwrite truncates before verification.
- `--unsafe` is needed for non-https servers (`Server::parse_checked`, `Client::allow_insecure`; MCP via env
  `BITMULE_ALLOW_INSECURE=1`).
- Server sends CSP and other security headers (`security_headers`, test `tests/web_headers.rs`); `web/bitmule.html` is exempt.
  `web/README.md` no longer suggests an inline script.
- Dependencies unified (reqwest 0.12, url 2, tower 0.5, tower-http 0.6, thiserror 2, raptorq git fork). Remaining duplicates are
  transitive (RustCrypto 0.10 generation, tungstenite 0.24 via axum 0.7, zstd 0.13 via zip, rand 0.8/0.9/0.10).
- Docs: `docs/crypto.md` rewritten for v2 with the trust model (old text kept as `docs/crypto-v1.md`), over-claims removed from
  `docs/user-features.md` and `README.md`.
- Fixed the `v2_transfer` abort (it failed in about half the runs, also on the previous commit): `vendor/str0m`
  `Rtc::do_poll_output` called itself once per queued SCTP packet, so a busy data channel overflowed the 2 MiB tokio worker stack
  (lldb: hundreds of `do_poll_output` frames at `lib.rs:1734`). Now a loop (`repoll` flag). 0 failures in 14 runs. Not the buffer
  pools: `bitmule-buf` and `fountain::Pool` already allocate with `Box::new_zeroed`. Worth sending upstream to str0m.
- Not done / open: wasm bundle needs a rebuild (`wasm-pack`) and `web/test/browser_test.py` was not run; the web sender gives no
  block hashes; no SAS / revocation of the link; `bitmule-server-signal-ws` does not compile (stale v1 crate, untouched);
  axum 0.8 and rand 0.9 migrations would remove more duplicates.

## Zero-copy WebRTC data channel (2026-10-18, in progress)
Goal (user): send = one copy, done by the encryption step, from the dcproto message into the io_uring send buffer; receive = one
copy, into a slab-allocated `ChannelData` buffer. Today (traced in `vendor/`): send has about six copies per byte
(dcproto message, `ByteSlice::pop_chunk` `to_owned`, SCTP `marshal_to`, dimpl fragment buffer, dimpl queue_tx record, `poll_output`
into buf, `DatagramSend` `to_vec`, then the pooled `Buf` for io_uring); receive: pooled recv buf -> dimpl input buffer -> decrypt
in place -> `poll_output` copy -> SCTP parse -> reassembly `Vec` -> `ChannelData.data`.
- DONE (stage 1): `Channel::write_bytes(Bytes)` -> `Sctp::write_bytes` -> `Stream::write_owned_with_ppi` with `OwnedBytes`
  (slices, no `to_owned`); used by `rtc.rs`. One copy fewer; throughput unchanged (copies are not the bottleneck: 64 MB memcpy
  is a few ms against 1.5 s).
- DONE (receive experiment, `BITMULE_RX_MODE`): the decrypted packet is now a slab buffer (`vendor/str0m/src/rxbuf.rs`, polled straight
  into it, handed to SCTP as `Bytes`: no `to_vec`). `RtcConfig::set_channel_delivery(Delivery)`:
  `Vec` (old `Event::ChannelData`), `Merged` (the chunks copied into ONE slab buffer, `Event::ChannelMessage`, default in bitmule)
  and `Segments` (one part per SCTP chunk, slices of the decrypted packets; the receiver writes them with one `writev_at_all`,
  `BlockWriter::write_parts`). Compared interleaved, 6 runs each, 256 MiB over loopback, release: all three the same,
  42.0 / 43.1 / 42.6 MiB/s (vec / merged / segments) and receiver CPU 8.97 / 8.98 / 8.96 s. An earlier version of segments with one
  write per chunk cost about 15% more CPU (14 small writes per message). Conclusion: the copies are not what the receiver spends
  its CPU on. perf of the receiver (35 ms CPU per MiB): 54% kernel, threads: tokio worker 51%, pool-uring 41%, writer 2%.
  The remaining copies (dimpl input copy and `poll_output` copy) need the dimpl fork.
- NEXT stages all need forks: `dimpl` 0.7.3 (record creation straight into a caller buffer with headroom for header/nonce and
  room for the tag, encrypt in place; DTLS 1.2 and 1.3), `str0m-proto` (`DatagramSend` / `DatagramRecv` as owned `Bytes`), sctp-proto
  (marshal into that buffer; keep reassembled messages as `Bytes` segments), str0m glue (buffer allocator hook so the datagram
  buffer is a slab `Buf` of the socket pool).
- Receive cannot copy "at the decrypt step into ChannelData": the SCTP header that says where a chunk belongs is inside the
  ciphertext, and a message spans many datagrams. Plan: decrypt in place in the (slab) receive buffer, parse SCTP as `Bytes`
  slices of it, and make `ChannelData` a list of those slices (or one copy at reassembly into a slab buffer).

## Path MTU discovery for the UDP symbol path (2026-10-18)
- `udp.rs`: after HELLO/ACK, `discover_mtu`. The sender seals a `PROBE` of every size in `MTU_LADDER` (8972 jumbo, 1472, 1452,
  1432, 1400, 1280, 1232, 1194), the receiver echoes the size it saw (`PROBE_ACK`), the sender takes the largest answered
  (at least two rounds of 100 ms, so one lost probe does not cost the jumbo size), announces it (`MTU`, repeated until
  `MTU_ACK`), and both set `fragment = datagram - 7`. A symbol payload (8208 bytes) is one datagram when the path carries
  8972; otherwise the fewest fragments that fit. Nothing answered: the old 1187 bytes. All sealed, so the path cannot shrink it.
- `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (v4/v6) is set on the socket (`forbid_fragmentation`), else a big probe would pass in IP
  fragments. Not on Linux: only the 1194 rung is probed.
- With io_uring the probes use a socket of our own (dup of the pool's) with 64 KiB reads, since the pool reads 2 KiB; the
  pool is stopped first and the receiver keeps answering stray HELLOs meanwhile (its ACK could be cancelled with the pool).
  Without io_uring the ladder is capped at 2048 (what the pool reads): 1472 on loopback.
- `UdpConfig.discover_mtu` (default on; off = use `fragment` as given), `UdpConfig.max_datagram` (test: simulates a smaller path),
  `UdpLink.fragment`, `Assembler::set_fragment` (BytesAssembler implements it; the fountain assembler in the `bitmule`
  crate must too, when it is written).
- Loopback, 480 MB: io_uring 520-576 MiB/s (was 270 at 1187 bytes); tokio path about 100 MiB/s either way (the earlier 218 had
  the pool on io_uring too). Tests: sizes found on loopback / tokio / simulated 1500, 1450, 1300, 1000 paths; 26 lib tests pass.
- Not done: re-probing when the path changes (the DF flag stays set, sends then fail with EMSGSIZE), IPv6 untested.

## To investigate later: path MTU for WebRTC (2026-10-18)
- The UDP symbol path gets MTU discovery first (see below). The same probe could serve WebRTC between two native peers:
  sealed, padded, don't-fragment datagrams over the selected ICE pair through our socket pool, echoed by the receiver; the
  sender then raises its MTU. Each direction is independent (the sender's MTU only governs what it sends).
- Needs: a runtime `Rtc::set_mtu` in `vendor/str0m` (today `RtcConfig::set_mtu` is fixed at build; env `BITMULE_MTU` is
  TEMP-INSTR) and the same for sctp-proto's association MTU. Neither has path-MTU discovery.
- Browsers keep their own ~1200 byte size, so only native <-> native gains. "One symbol per packet" does not apply (SCTP cuts
  16 KiB messages into chunks); the gain is fewer, larger datagrams (~1450 on Ethernet, ~8-9 KB on jumbo/loopback).
- Related open finding: the default io_uring socket pool is slow on loopback (10-17 MiB/s, T3 timeouts) against 46-52 MiB/s
  with `BITMULE_NO_NET_URING=1`; also slow at `7d2716b`, so not caused by the audit changes.

## Earlier status (2026-10-18 night)

## Where things are right now (short)
- Everything below from this evening is UNCOMMITTED (about 30 modified files plus the new `bitmule-buf` crate, `udp.rs`,
  `udp_uring.rs`, `uring.rs`, `pool_uring.rs`, `vendor/`, `scripts/nic-loop.sh`). Tests last run green: `cargo test -p bitmule`
  (13 integration), `bitmule-client-native --lib` (22), `bitmule-buf` (9). NOT re-run since the last changes: `bitmule-server`,
  `bitmule-client-common` (also with `BITMULE_NO_IO_URING=1`).
- Done this evening: data channel loss fixes; UDP symbol transport with io_uring (pacer fix, slow start, queue depths 1024-4096,
  registered/locked slabs, `UdpConfig.fragment`, `Assembler` trait); WebRTC socket pool on io_uring with a slab-backed
  `bitmule_buf::Pool`; relay check to sudfa (100 Mbit link, so 10 MiB/s is the link, hash matched); `--nic` pinning verified by
  interface counters.
- Next: UDP is wired in (see "UDP in the bitmule crate" below); then cleanup (TEMP-INSTR, decide on the str0m fork),
  redeploy the server (protocol changed: `UdpHello`, `PeerCaps::UDP`), docs.
- Not possible from this session: anything needing root (no passwordless sudo; the `mcp__agent-invite__sudo_exec` tool was not
  connected). `scripts/nic-loop.sh` (wifi -> router -> cable loop on one machine with ipvlan/macvlan namespaces) was written but the
  user said it did not work and it is not important; it is untested and untracked.
- (Answered by the MTU discovery section above.) Datagram size. 1187 bytes is safe; `UdpConfig.fragment` up to 9000 works on loopback/jumbo frames
  (573-655 MiB/s vs 300-333). Idea: negotiate in HELLO / probe the path MTU, or UDP GSO via the `io-uring` crate.

## Web client ported to v2 (2026-10-18, uncommitted)
- `crates/bitmule-client-wasm`: rewritten (session state machine, sender transfer, relay decoder, verifier; 6 native unit
  tests). Needs `.cargo/config.toml` `getrandom_backend="wasm_js"` for wasm32 and the `getrandom` 0.4 `wasm_js` feature.
- `web/v2-worker.js` + `web/v2.js` + `web/main.js` (UI only); old JSON-protocol code removed. Relay upload is sequential
  POST batches (4 MiB), not a streaming body (no browser support everywhere).
- `web/test/browser_test.py` (selenium, 11 tests, all pass): cli<->chrome over relay and WebRTC (a direct data channel
  with the str0m peer works both ways), chrome<->chrome via request link, and the real page for receive / send /
  request / invited send.
- Not done: websocket keepalive (browsers cannot ping; a proxy idle timeout would drop an idle sender: have the server
  ping), no file name in the manifest, the zip extract dialog only reads store-mode zips (CLI zips are zstd), received
  files are not removed from OPFS until a day later, `wasm-opt` bundle size not checked, Firefox/Safari untested
  (workers with modules, OPFS sync handles), the page does not show per-receiver progress on the sender.

## Session of 2026-10-18 evening: data channel speed, UDP symbol path (NOTHING of this is committed)

### What was found (data channel, loopback, 64 MB, MTU 1400)
- The stalls ("clean time + whole seconds") were packet loss followed by SCTP's 1 s minimum
  retransmit timeout (T3, `RTO_MIN` 1000 ms), not the 200 ms delayed ACK and not str0m's 128 KiB cap.
- Two causes, both fixed: (1) the kernel dropped datagrams because the socket receive buffer was the
  208 KiB default (`/proc/net/snmp` `RcvbufErrors`); `nic::bind_udp` now asks for 8 MiB send/receive
  buffers (kernel caps at `net.core.[rw]mem_max`, 4 MiB here). (2) the socket pool's "unclaimed"
  channel held 64 packets and silently dropped the rest (`debug!` only), and a `sendmmsg` burst is 64;
  now 1024 and the reader waits instead of dropping (`POOL_UNCLAIMED_CAP`, `POOL_PEER_CHAN_CAP`).
- Result: 12 of 12 runs 1.20-1.27 s for 64 MB (about 53 MiB/s), 0 T3 timeouts, 0 lost; SACK delay
  200 ms vs 5 ms makes no difference then. Before: 0.85 s to 6.9 s, bimodal.
- A Unix socket instead of the data channel (same everything else) did 256 MB in 0.5 s, so the
  str0m path (SCTP + DTLS + UDP) is the limit, about 7-8x. The receiver (file vs memory vs discard)
  and the disk are not. Profile of the sender: `RandomState::hash_one<&u32>` (SipHash in sctp-proto's
  `PayloadQueue`) 15-20%, `gather_data_packets_to_retransmit` 6%, CRC32 6%, send syscalls now small.
- io_uring in str0m is not possible: str0m is sans-IO. The syscalls are in `SocketPool`
  (`str0m_client.rs`), which now batches with `sendmmsg` / `recvmmsg` (pooled buffers).

### Changed in the tree (all uncommitted)
- New crate `crates/bitmule-buf` (pool of fixed arrays + length, `Buf::into_bytes()` without a copy,
  6 tests). Used by `dcproto::data_message` (pooled data channel messages) and `SocketPool` receive.
- `blockio::read_ranges`: the data channel sender reads whole 2 MiB blocks (io_uring, pooled
  buffers, falls back to blocking reads) and cuts them into 16 KiB pieces. `serve_ranges` uses it.
- `v2::Span` (first to last mark) in `Report.relay_time` / `data_channel_time`; the CLI prints them;
  the sender logs `sent over the data channel/relay: ... MiB/s` at `info`.
- Open item 1 fixed: a closed data channel with no relay for that receiver ends `serve_peer` with an error.
- `fountain.rs`: `EncodedBlock::frames_with(pass, first_repair, later_repair)`, `frame_payload`,
  `Decoder::push_symbol(header, Symbol)` (takes a ready symbol, no copy), `SymbolPacket`,
  `SYMBOL_HEADER`. 13 client-common tests pass.
- Local forks in `vendor/` with `[patch.crates-io]` in the workspace `Cargo.toml`:
  `vendor/str0m` (data channel send buffer 1 MiB, was 128 KiB; made no difference once loss was fixed,
  can go back) and `vendor/sctp-proto` (Fx hashing in `PayloadQueue` and two per-SACK maps; SACK delay
  settable). The `fxhash` crate is not in the local registry; `rustc-hash` (same algorithm) already was.
- `bitmule-core::protocol`: `PeerCaps::UDP = 4`, `Peer2Peer::UdpHello(UdpHello { addrs })` (last
  variant). **The server must be rebuilt and redeployed** (see Relay on artisan) before UDP is used.
- Warnings cleaned in bitmule, core, client-common, client-native, server (`cargo fix`, dead v1
  stubs removed: `recv_loop.rs`). Unused-dependency notices in the manifests remain.
- `crates/bitmule-client-native/src/udp.rs` (new, compiles, 7 unit tests pass): raw fountain symbols
  over UDP between two native peers. Sealed HELLO/ACK challenge exchange (AEAD with the bulk key,
  nonce top bit set), hole punching from every socket to every address of the peer, DATA datagrams
  `kind | seq u32 | index u8 | count u8 | bytes` (<= 1200 bytes, symbol payload cut into 7 fragments),
  sender paced with loss-based rate control from sealed FEEDBACK (50 ms: highest seq, symbols
  received, done-block bitmap), reassembly with a 512 symbol window, test-only loss injection
  (`UdpConfig.drop`). Written for the tokio sockets of `SocketPool`; not yet wired into v2.

### Done later the same evening: io_uring for the UDP path and the WebRTC socket pool
- `client-native/src/uring.rs`: `available()` (probe; `BITMULE_NO_IO_URING` turns it off), `spawn()` (thread with a
  tokio_uring runtime, stopped by dropping `Stop`; the driver cancels in-flight ops), `UBuf` / `UBytes` buffer wrappers.
- `udp.rs`: shared logic factored out (`RateControl`, `Pacer`, `ReceiveState`, `sender_packet`); `udp_uring.rs` is the
  data phase on io_uring (128 `recv_from` in flight, `sendmsg` with header + payload slice, no payload copy).
  `UdpConfig.io_uring` (default on); `connect` dups the socket (`SocketPool::dup_socket`) and calls `stop_receiving`.
  Tests: tokio and uring loopback roundtrips (uring also with 5% injected loss). The generic `Assembler` is NOT done yet
  (output is still `Bytes`).
- `pool_uring.rs`: the WebRTC `SocketPool` reads (64 in flight per socket) and sends (batches, one copy into a pooled
  buffer) through one io_uring thread; falls back to the tokio/recvmmsg code when unavailable. `BITMULE_NO_NET_URING`
  forces the tokio sockets for comparisons (TEMP). Loopback, 64 MB, data channel: 42-43 MiB/s with uring vs 36-38 without
  (local server, release build, 5 runs each); `cargo test -p bitmule` 13/13 and client-native lib 21/21 pass.

- Later still: `Assembler` trait done (`udp::Assembler`, `BytesAssembler`; `connect` is generic and returns `UdpLink<A::Item>`;
  the fountain assembler for `Symbol`s still goes in the `bitmule` crate). Pacer fix: waiting for every datagram capped the
  sender at one per 1 ms timer tick (7 MiB/s); now it waits only when more than 2 ms ahead, plus slow start (rate x2 per
  report until the first loss) and the sender holds data until the receiver's first report. Loopback 480 MB: 270 MiB/s
  (io_uring) vs 218 (tokio path; note the pool's own sockets are on io_uring too unless `BITMULE_NO_NET_URING`).
  Queue depths: 2048 reads/sends in flight (UDP), 1024 reads per socket + 2048 sends (pool), ring of 4096 entries.
  strace -c of a 2 MB transfer (256 payloads, both peers): no sendto/recvfrom/sendmsg at all, 514 `io_uring_enter` for
  about 3600 datagrams; 4590 `mprotect` remain (malloc arena growth from the big buffer pools; could be cut by one slab).
  Datagram size is 1187 bytes; about 1400 is the safe limit on the internet (UDP GSO would cut per-packet cost instead).

- `UdpConfig.fragment` (symbol bytes per datagram, default 1180, max `FRAGMENT_MAX` 9000; both peers must match, pass
  `BytesAssembler::with_fragment`). Loopback 480 MB, io_uring: 1180 -> 300 MiB/s, 1400 -> 311, 8300 (a whole 8 KiB symbol
  in one datagram) -> 573 MiB/s with 9% of symbols lost at the 2 GB/s cap. Over a real network that needs jumbo frames
  (else IP fragments); sizes over 2000 only work on the io_uring path.

- Slabs: the UDP io_uring data phase now has one slab per direction (`uring::Slab` / `Buffers`: one anonymous mmap with
  MAP_POPULATE, `mlock`ed when RLIMIT_MEMLOCK allows, registered with the ring as fixed buffers through `FixedBufPool`;
  falls back to unregistered use if registration fails; the kernel took 4096 registered buffers here, older kernels cap at
  1024). The socket is `connect`ed to the peer after the handshake, which fixed buffers need (`read_fixed`/`write_fixed`).
  Send side: header + payload slice are copied into a slot (one copy). Loopback 480 MB: 1180 B datagrams 300 -> 333 MiB/s,
  8300 B 573 -> 655 MiB/s. The remaining ~3900 `mprotect` calls in strace come from the WebRTC `SocketPool` buffers
  (`pool_uring.rs`, boxed arrays allocated on its thread), not from the UDP path; they go on `Bytes` so they need a slab-backed
  `bitmule_buf::Pool` rather than registered buffers.
- Real network check (2026-10-18): `send --relay` of 100 MiB from here to sudfa.mywire.org through https://bitmule.qdat.net:
  hash matched, 9.9 s (10.1 MiB/s), 0 bytes via data channel. (Temporary binary on sudfa removed afterwards.)

- `bitmule_buf::Pool::slab(capacity)`: all arrays in one mmap (MAP_POPULATE, mlock when allowed, `locked()`); extras beyond
  the capacity are loose and freed on return. The WebRTC pool (`pool_uring.rs`) uses it for received and outgoing datagrams.
- `--nic` check (2026-10-18, this machine has enp1s0f0 192.168.100.50 and wlp2s0 192.168.100.5 on the same /24, default routes
  on both): interface byte counters show relay (`--nic enp1s0f0` upload, `--nic wlp2s0` download: 77 MB tx on eth, 79 MB rx on
  wifi, ~1 MB on the other directions) and WebRTC to sudfa (`--nic enp1s0f0`: 74 MB tx on eth, ~0.5 KB on wifi) stay on the pinned
  interface. What fails is eth <-> wifi of the SAME host (sender `--nic enp1s0f0`, receiver `--nic wlp2s0`): ICE never connects,
  because `ip neigh` shows `192.168.100.5 dev enp1s0f0 FAILED`: the ARP request for our own wifi address leaves on eth and is
  never answered (the router/AP does not hairpin it back to this host, and Linux ignores ARP/packets with a local source
  address, accept_local=0). Unpinned, the same traffic goes `local ... dev lo`, so it never touches either NIC.
  Test `--nic` against a second machine, not against another interface of the same one.

### TEMPORARY instrumentation (marked `TEMP-INSTR`, harmless when the variables are unset; remove when done)
- Env: `BITMULE_MTU` (str0m_client.rs), `BITMULE_SCTP_BUF` KiB (vendor/str0m), `BITMULE_ACK_MS` and
  `BITMULE_SCTP_TRACE` (vendor/sctp-proto: prints T3 timeouts), `BITMULE_MEMOUT` (recv.rs: data
  channel output into memory), `BITMULE_UDS` (rtc.rs: data over a Unix socket after the channel
  opens; path must be under 108 bytes), `PacketCounts` printed on drop of the rtc driver (rtc.rs).
- `Cargo.toml` of client-native has `net`, `io-util` added to tokio for the Unix socket test.

### UDP transfer path, with a 1-copy receive and io_uring (design; `udp.rs` + io_uring + Assembler are DONE, the wiring in the `bitmule` crate is not)
Decisions (user's rules: 1 copy in user space on receive; io_uring for native Linux; keep workers
isolated):
- Receive: the kernel writes datagrams into reusable buffers (many `recv_from` in flight on a
  tokio-uring socket); each is parsed in place and its fragment copied ONCE into the right slice of a
  pooled `Symbol` (header kept apart); the decoder takes it with `push_symbol`. Send: `sendmsg` with
  two buffers (7 byte header, slice of the encoded frame), no copy, many in flight.
- `udp.rs` becomes generic over an `Assembler` trait (`fragment(seq, index, count, bytes) ->
  Option<Item>`); a `BytesAssembler` for tests, a fountain one in the `bitmule` crate
  (`v2/symbols.rs`) that writes into `Symbol`s. The tokio implementation stays as the fallback (no
  io_uring, other OSes); the uring runtime thread follows `blockio.rs`. The sockets are handed over by
  `try_clone` (dup) after the handshake and the pool's receive tasks are stopped
  (`SocketPool::socket`, `stop_receiving`, to add). tokio-uring has no multishot / provided buffer
  rings, so the "large receive buffer" is N buffers in flight; the `io-uring` crate directly could do better.

### Next steps (in order)
1. DONE: `udp.rs` generic `Assembler`, uring sender/receiver with the tokio fallback, tests (see the section above).
   The fountain `Assembler` (writes fragments into `Symbol`s for `Decoder::push_symbol`) goes in `bitmule/src/v2/symbols.rs`.
2. `bitmule` crate: `Options.udp: Option<UdpOptions { overhead, max_rate_mbit, drop }>` (also update the
   `Options { .. }` literals in `tests/v2_transfer.rs`), `caps()` sets `UDP`, `Transport::Udp`,
   `Report.udp_*`, a third demux output (`UdpHello`) next to `signaling` and `app`, `session.rs` wiring.
3. `send.rs`: factor `relay_upload` into `encode_blocks(repair, skip, emit)` and add the UDP upload
   (repair count from the overhead factor, skip blocks the receiver reported done, stop when all done);
   `recv.rs`: factor the decoder thread out of `relay_download` (input = bytes or `SymbolPacket`, report
   finished blocks) and add `receive_udp`. UDP is tried first when both sides advertise it and falls
   back to relay/WebRTC if no path is found within 4 s.
4. CLI: `--udp` (UDP only) and the overhead / rate options; the default stays relay + WebRTC until it is tested on real networks.
5. Tests: loopback roundtrip, 5% and 20% injected loss, wrong key (no path), file larger than one block.
6. Then: rerun all suites (not run since these changes: `bitmule` integration tests, server, client-native
   lib, client-common with `BITMULE_NO_IO_URING=1`), remove the TEMP-INSTR code, decide whether to keep
   the str0m 1 MiB fork, update `docs/wire-protocol.md`, redeploy the server.

Known limits of the UDP design (v1): no congestion control beyond the loss-based rate; data datagrams
are not sealed per packet (a forged symbol costs a block, not integrity); a sender passes over blocks
the receiver has finished by reading them from disk anyway; several receivers per sender each get
their own stream.

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

## Streaming transfers (2026-10-18, uncommitted)

For data that is made while it is sent (a pipe, a BLOB, a generator): no size and no hash up front. Normal transfers are
unchanged on the wire.
- Order of messages. Normal: `Manifest` first, then the receiver's `Get`, then `JoinRelay`. Streaming: the sender's first message
  to a receiver is `JoinRelay`, and `Manifest` + the new last variant `Peer2Peer::Checksum([u8; 32])` follow once the source has
  been read to its end (real size, bulk key, name). `JoinRelay` before `Manifest` is what tells a receiver it is a stream.
- The bulk key is made at the start, so the fountain code can encode blocks as they are read. Pass 0 uploads blocks and hashes
  the data (`CommitmentHasher`: SHA256(data || bulk_key)); later passes re-read the source and send repair symbols until a
  receiver sends `Complete`. The source must therefore be restartable (`StreamSource::restartable`, the size must not change), or
  one-shot (`StreamSource::one_shot`: copied to a temp file during pass 0).
- The share link has an all-zero signature. The receiver checks the Checksum message (and a non-zero link signature if there is
  one). Relay only: `send_stream` / `run_send_stream` refuse options without `relay`.
- Receiver (`recv.rs::receive_stream`): spools the relay bytes to a temp file until the Manifest arrives, then opens the output
  (named from the manifest) and decodes the spool followed by the live stream (the same frame splitter, so a cut frame
  completes). Progress is `(bytes, 0)` until the size is known.
- API: `v2::run_send_stream(server, StreamInfo, StreamSource, options, on_link, on_event)`;
  `bitmule::Client::send_stream(name, source)` / `send_reader(name, reader)` -> `StreamSendBuilder` (`size_hint`, `on_progress`,
  `start()` -> `SendHandle`); CLI: `bitmule send - [--name N]` streams stdin (forces `--relay`).
- Web: the wasm `Session` has `setStreamingTransfer`, `transferUpdate`, `transferFinish`, `verifier(checksum)`, `newStream()`
  (a reconnect starts at a frame). `v2.js startSend({stream | blob | openStream, streaming: true, size?})`; a ReadableStream can
  be read once, so for repair passes the page gives an `openStream(pass)` function that returns a new one (or the stream is kept
  in an OPFS spool). The receiver spools in OPFS (`bitmule-recv-spool-*`), then replays it.
- Tests: `crates/bitmule/tests/v2_stream.rs` (6), `client_api.rs` (2 stream tests), `web/test/browser_test.py` (7 `stream:`
  tests, Chrome and Firefox). Not done: an MCP tool for streams, a receiver that resumes a stream after a restart.

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

1. (fixed, `send.rs`: a closed data channel with no relay for that receiver now ends `serve_peer` with an
   error; not covered by a test yet.)
2. Sender returns once all receivers it knows have finished; a late joiner after that is not served.
   A "wait for N receivers" option would make 1->N deterministic.
3. Throughput: the data channel does about 53 MiB/s on loopback (see the session section above for why);
   the relay path did 525 MiB/s on the same machine.
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
- Flow (streaming transfers differ, see "Streaming transfers"): Manifest -> receiver `Get{0,size}` -> sender `JoinRelay` + (if both have WEBRTC) SDP offer.
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

## UDP in the bitmule crate (2026-10-18)
- `Options.udp` (default off), `Options::with_udp(only)`, `PeerCaps::UDP`, `Transport::Udp`, `Report.udp_bytes/udp_time`.
  `Peer2Peer::UdpHello` goes to a third demux output. CLI: `--udp` (UDP first, relay/WebRTC behind it) and `--udp-only`.
- Sender (`udp_upload`): same read/encode pipeline as the relay upload, skips blocks the receiver reported done, stops
  when all are. If UDP errors or no path is found, the relay/WebRTC startup runs as the fallback. Receiver (`udp_download`)
  shares `spawn_decoder` with the relay path; the decoder reports finished blocks back to the UDP link.
- Tests in `tests/v2_transfer.rs`: `over_udp`, `a_small_file_over_udp`, `an_empty_file_with_udp_on`,
  `udp_with_the_relay_behind_it`, `udp_only_on_one_side_uses_the_relay`. All suites pass in release (debug builds are ~8x slower).
- Fixed: the receiver's first progress report waited 250 ms, so fast loopback transfers never reported to the sender
  (broke two `client_api` tests since the audit commit).
- Not done: tests with injected loss through the `bitmule` crate, the fountain `Assembler` writing straight into `Symbol`s,
  RaptorQ loss adaptation, wasm rebuild.

## UDP under loss (2026-10-18)

- Local check, `--udp-only`, 100 MB, `BITMULE_UDP_DROP` on the receiver (new test aid, `recv.rs`): 0% 3.1 s, 5% 3.3 s,
  20% 3.8 s, 40% 4.0 s, 60% 4.9 s, hash matched each time. Before: 20% never finished (rate fell to the 1 MiB/s floor).
- Rate control (`RateControl` in `udp.rs`): loss counts only above the lower quartile of the last 100 reports (5 s), so a path
  that always loses some (radio, policer) is not slowed, as the fountain code covers it. A rise on top of it still slows the sender.
- Heap corruption found on the way (about 1 run in 15, sender or receiver aborted at the end of the MTU phase,
  "tcache_thread_shutdown(): unaligned tcache chunk"): `tokio-uring` 0.5.0 `Driver::drop` replaced the `Lifecycle::Ignored(data)`
  of reads already dropped with `Ignored(())`, freeing the buffer, msghdr and address the kernel was still to write.
  Fixed in `vendor/tokio-uring` (patched in the workspace); 60/60 clean runs afterwards, 0/60 failed with io_uring off before.
- Not run: sudfa. The relay on artisan was not redeployed (ssh to it was refused in this session).

### UDP to sudfa (2026-10-18)
- First attempt: "no symbol over udp for 5 s". The sender's sends failed with EMSGSIZE: after the big (8972) DF probes the kernel had
  cached a path MTU of 552 for the receiver's address (`ip route get` showed `mtu lock 552`, probably from an ICMP of a router on
  the path), while the 1452 probe had passed before that ICMP arrived. Probing and sending now use `IP_PMTUDISC_PROBE` (DF set,
  cached path MTU ignored), so only the device MTU and what the probes prove count.
- After the fix, 100 MB sudfa -> here over `--udp-only` (path MTU 1500, 1445 bytes of symbol, six datagrams per symbol): 13.5 s
  (7.1 MiB/s, hash matched). With 20% extra loss injected at the receiver: hash matched but 122 s (0.8 MiB/s): the rate control
  recovers badly when real congestion loss is on top of steady loss. To look at.
- `BITMULE_UDP_MTU=N` (recv.rs) ignores datagrams above N, to test fragment reassembly locally (works at 1480: 92 MiB/s on loopback).
- `scripts/deploy.sh` (server deploy, sudfa test).

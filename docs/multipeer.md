# Multi-peer sender + range-request receiver (M2 + M3 design)

Working spec for the Phase M2 (per-peer sender orchestration) and Phase M3
(range-request wire) landings. Please tear apart before code lands.

## Goal in one line

Sender serves a file to N receivers (default N=1, `--multi` mode N=∞),
each getting their own per-session KEX + AEAD stream, all sharing the
same `bulk_key` so URL commitment holds. Receivers pull the ranges they
want instead of the sender streaming everything.

## Modes

- `--complete` (default): sender serves until exactly one receiver has
  covered `0..total_chunks`, then exits. This is the current one-shot
  UX preserved on top of the multi-peer stack.
- `--multi`: sender never exits. Serves any number of receivers over
  time. Explicit Ctrl-C or SIGTERM to stop.

Both modes run through the same code path. `--complete` is just an
early-exit predicate on top of the multi-peer server.

## Data model

### Sender-side global state (shared across peers)

```rust
struct SenderState {
    share_key: ShareKey,
    bulk_key: BulkKey,          // SAME B for every peer (URL commitment binds one B per file)
    file_path: PathBuf,
    file_size: u64,
    total_chunks: u64,
    mode: ServeMode,             // Complete | Multi
    ws: Ws,                      // single WS for all signaling
    peers: HashMap<ReceiverId, PeerHandle>,
    completed_covered: HashSet<u64>, // for --complete predicate: chunks any peer has requested
}
```

### Per-peer state (owned by that peer's task)

```rust
struct PeerHandle {
    receiver_id: ReceiverId,
    // Task handle; task itself owns Rtc + pool + wrap_key + meta_key
    // and its dedicated DC channel_id.
    task: JoinHandle<Result<()>>,
    // Cross-task command channel: parent tells task to shut down, task
    // reports covered-ranges back for --complete predicate.
    covered_tx: mpsc::UnboundedSender<CoveredNote>,
}

// Owned inside the per-peer task's scope:
struct PeerSession {
    receiver_id: ReceiverId,
    rtc: Rtc,
    pool: SocketPool,
    channel_id: ChannelId,
    wrap_key: WrapKey,   // per-peer, from own ephemeral X25519
    meta_key: MetaKey,   // per-peer
    // bulk_key shared from parent (Arc<BulkKey>)
}
```

### Receiver-side (no big change)

Receiver still has one LiveSession (it's a single-peer client). Difference
from today: after DC opens + KEX done, it emits `request_ranges` frames
with the ranges it wants, waits for the encrypted chunks, and repeats
until it has 0..total_chunks. Then closes the DC cleanly.

## Startup + peer lifecycle

### Sender

1. `cmd_send`: computes signature, prints URL, mints bulk_key, opens WS.
2. Sends `Hello{role: sender, wire_version}`. Loops on incoming WS.
3. On each `peer_hello{role: receiver, receiver_id, wire_version}`:
   a. Version check as today; bail on mismatch.
   b. Check `peers.contains_key(&receiver_id)` — if yes, ignore (dup notif).
   c. Spawn a per-peer task with `PeerSession::run(receiver_id, ws_out_tx, bulk_key_shared, file_path, mode)`.
4. Sender's parent loop also receives `CoveredNote { peer_id, chunks: Range<u64> }` from tasks. Under `--complete`, if any peer's covered set reaches `0..total_chunks`, sender signals all tasks to shut down and exits.

### Per-peer task

1. Build own `Rtc + SocketPool` (own DC creation as active-side).
2. Generate own ephemeral X25519; send `KexPub{pub, mac}` with `to_receiver_id = receiver_id`.
3. Emit SDP offer with `to_receiver_id`.
4. Runs select! on:
   - Own filtered slice of inbound WS (filtered by `from_receiver_id == receiver_id` — the shared parent WS reader dispatches).
   - Own `pool.recv()`.
   - Timeout.
5. On peer's `KexPub`: verify MAC, derive S, compute wrap_key + meta_key.
6. Wrap shared bulk_key under wrap_key, send `KeyWrap{...}` with `to_receiver_id`.
7. On peer's SDP answer: accept, wait for DC open.
8. Once DC open: send `meta_enc` on DC (meta of the file). Enter block-serve loop.
9. **Block-serve loop**:
   - Wait for `RequestRanges{ranges: Vec<Range<u32>>}` frame on DC.
   - For each range: file.seek(range.start * CHUNK_BYTES), read (range.end - range.start) * CHUNK_BYTES, split into chunks, AEAD-encrypt each with `bulk_key.encrypt_chunk(idx, plaintext)`, send as binary on DC. Report covered chunks to parent via `covered_tx`.
   - Repeat.
10. Task exits when:
    - Peer's DC closes (peer's decision).
    - Parent sends shutdown signal (--complete condition met by any peer, or process termination).

### Shared WS reader

Because sender has ONE WS but N per-peer tasks, we need a WS-demux layer:

```rust
struct WsRouter {
    per_peer_inbox: HashMap<ReceiverId, mpsc::UnboundedSender<SignalFrame>>,
    unrouted_tx: mpsc::UnboundedSender<SignalFrame>,  // peer_hello notifications for parent
}
```

Parent task owns the WS `stream` half and continuously reads:
```rust
loop {
    let frame = ws.next().await?;
    let (frame, from) = parse_ws_frame_with_from_id(...)?;
    match from {
        Some(rid) if per_peer_inbox.contains(&rid) => per_peer_inbox[&rid].send(frame),
        _ => unrouted_tx.send(frame),  // peer_hello, sender→sender frames if any
    }
}
```

And a separate write-mux task for outgoing frames:
```rust
struct WsWriter { outbox_rx: mpsc::UnboundedReceiver<String> }
// Per-peer tasks call ws_send_targeted(&mut outbox_tx.clone(), frame, receiver_id)
// which serializes + sends into the outbox mpsc.
// A single writer task pulls from outbox_rx and awaits sink.send(msg).
```

This keeps all WS I/O on one task and gives per-peer tasks async channels.

## Request-ranges wire

New frames on the DC (both directions between per-peer task and receiver):

```json
// Receiver → Sender (on DC, text control frame):
{"type":"request_ranges", "ranges":[{"start":0,"end":100},{"start":150,"end":200}]}

// Sender → Receiver: no new type — sender responds with the encrypted
// chunks (idx-derived nonces so receiver knows which chunk is which by
// order + count within the requested ranges).

// Receiver → Sender (once done):
{"type":"recv_done"}   // triggers sender to consider this peer done

// Sender → Receiver:
{"type":"done_ack"}    // sender confirms; peer task closes DC cleanly
```

Range semantics: half-open `[start, end)`, chunk indices (not byte
indices). Sender reads sequentially through each range.

Sender-side optimization Seb wanted: one `file.seek` + one contiguous
`file.read` per range instead of per-chunk seeks. Chunks within a range
are contiguous on disk, so a single 16 MiB read for a 1024-chunk range
is a lot cheaper than 1024 separate reads.

## `--complete` early exit predicate

Parent tracks `Vec<HashSet<u64>>` — one covered set per active peer.
When any peer's set reaches full coverage, parent:
1. Signals all peer tasks to shut down (via their command channels).
2. Awaits their exit.
3. Returns Ok(()) from cmd_send.

This means "one receiver got the whole file" = sender exits, matching
the current one-shot UX. Extra peers who joined mid-flight are dropped
without receiving completion — their responsibility to retry.

## `--multi` never-exit

Same code path, just no early-exit predicate. Sender lives until process
termination. Ctrl-C signals all peer tasks + shuts down WS.

## Deletions / refactors

- Existing `send_file_over_dc` (single-DC assumption, streams entire
  file) — replaced by the per-peer task's block-serve loop.
- Existing `send_connect` returning a single `LiveSession` for the
  sender — replaced by `send_serve` that returns nothing but stays alive
  serving peers.
- Existing recv-side stays MOSTLY the same, but `recv_file_over_dc`
  gains a `request_ranges` emitter after DC open and no longer waits
  passively for the sender to stream everything.

Client-side `cmd_send` signature stays the same (server URL, path, mode)
but the mode enum gets a `Multi` variant beside the existing transport
modes. Or `Multi` becomes a separate CLI flag orthogonal to transport.

## Open questions before I code

1. **Multi-peer + relay path?** The current relay design is one-sender-uploads-all-chunks-to-server, N-receivers-download. Doesn't map to per-peer sessions with per-peer wrap_keys. Two options: (a) relay path stays single-B-shared-KEX (this is already the case in C3a/B3), so `--multi` on relay = one KEX ceremony, all N receivers use the same wrap_key. Weaker than webrtc-per-peer but relay is server-mediated anyway. (b) drop relay path entirely for `--multi` mode (webrtc-only). Preference?

2. **Receiver-driven full-file fetch**: for `--complete` mode, the current single-shot receiver just wants everything. Does it emit `request_ranges: [{0, total_chunks}]` after meta_enc arrives, or is there an implicit "request-all" mode where the sender streams without waiting for an explicit request? I'd default to the explicit range request (one line on the receiver, keeps the wire uniform).

3. **Parent-task ↔ per-peer-task shutdown protocol**: mpsc oneshot per peer? Broadcast channel? Explicit `Command::Shutdown` enum on the covered_tx (bidirectional)? Cleanest is probably `tokio::sync::watch` for the shutdown signal (parent sets, peers watch).

4. **DC channel names**: currently str0m opens `"bitmule"`. Per-peer sessions all opening a channel named `"bitmule"` on their own Rtc — no collision since each Rtc is a separate PeerConnection. Ok.

5. **str0m + N Rtc instances share the same SocketPool?** Or does each peer's Rtc get its own port set? Sharing the pool means one incoming UDP packet has to be dispatched to the right Rtc by ICE state matching. str0m might not support that directly. Cleaner: per-peer Rtc + per-peer SocketPool (own port range). More expensive on socket count but simple. Worth checking str0m docs / examples before committing.

Once these are settled I can code M2b + M3 in a series of tight pushes.

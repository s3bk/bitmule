# bitmule end-to-end cryptography

Spec + implementation notes for the confidentiality layer riding on top
of the WebRTC data channel (or the server-relay HTTP path). Written up
alongside the initial crypto module 2026-09-02 per Seb.

## Threat model

- The server sees `session_id` (the WebSocket handle) and, on the relay
  path, ciphertext bytes for each chunk. Server never sees the URL
  fragment, never sees any key material.
- Passive network attackers see the same as the server on the wire.
- A URL leak (someone captures the share link after the transfer) must
  NOT let an attacker decrypt captured ciphertext from the finished
  session. This is the forward-secrecy requirement.

## Keys

| Symbol | Bytes | Lifetime         | Source           | Purpose                                                    |
|--------|-------|------------------|------------------|------------------------------------------------------------|
| `A`    | 32    | share URL        | initiator RNG    | URL-shared secret. In the `#` fragment; server never sees. |
| `E`    | 32    | one session      | each side RNG    | Ephemeral X25519 private key. Wiped after `S` is derived.  |
| `S`    | 32    | one session      | X25519 + HKDF    | Symmetric wrap key for `B`. Derived per session.           |
| `B`    | 32    | one file transfer| sender RNG       | Bulk stream key (ChaCha20-Poly1305).                       |

**Initiator generates `A`.** For `bitmule send`, that's the sender; for
`bitmule recv` (receiver invites a file), that's the receiver. Either way,
the initiator puts `A` in the URL fragment and shares it out-of-band
(clicking the link, scanning the QR).

**Sender-of-file generates `B`.** In the `send` flow that's the same
side as the initiator. In the `recv` flow (recipient invites the sender)
the initiator generates `A` but the OTHER party generates `B` when they
open the link and start streaming their file.

## Session identifier

```
session_id = SHA256(A)
```

64 hex characters, matches the existing session-hex format the server
already uses. Deterministic, so both sides compute the same one from the
same `A`. One-way — server sees `session_id`, cannot recover `A`.

## Per-session key exchange

Both sides generate a fresh ephemeral X25519 keypair `(E_priv, E_pub)`.
Each announces its `E_pub` over the signaling WebSocket (SignalFrame
variants defined in the next section). Each message includes a MAC
computed under `A`:

```
mac = HMAC-SHA256(A, E_pub)
```

Verification: on receiving the peer's `{ephemeral_pub, mac}` frame, the
local side recomputes `HMAC-SHA256(A, peer_pub)` and constant-time-
compares against the received MAC. Mismatch → abort the connection.

A passive listener without `A` cannot forge a MAC that verifies. This
authenticates the exchange without a full public-key infrastructure —
possession of `A` is the credential.

Both sides then derive the raw shared secret and, from it, a
purpose-specific wrap key:

```
S        = X25519(local_E_priv, peer_E_pub)          # 32 bytes, non-uniform
wrap_key = HKDF-SHA256(
             ikm  = S,
             salt = session_id,                       # = SHA256(A), public
             info = b"transfer-v1 wrap-key",
             length = 32,
           )
```

`session_id` is public, but binding the derivation to it guarantees
`wrap_key` is specific to THIS session AND this exact purpose. The
info string is versioned (`transfer-v1`) so a future protocol change
can bump it without colliding with fielded implementations.

The X25519 private halves are consumed by the derivation and dropped
immediately after `S` is computed. `S` itself sticks around only long
enough to derive `wrap_key`, then is dropped too. `A` stays as long
as the URL is live but is not sufficient alone to recover any of
this — the ephemerals are.

## Bulk key exchange

Sender generates `B` (32 random bytes) and wraps it under `wrap_key`:

```
nonce = 12 random bytes
enc_B = ChaCha20-Poly1305(wrap_key, nonce, plaintext=B, aad="")
```

Sends `{enc_B, nonce}` over the WebSocket as a new SignalFrame variant.
Receiver, holding `wrap_key`, unwraps:

```
B = ChaCha20-Poly1305-Decrypt(wrap_key, nonce, enc_B, aad="")
```

`wrap_key` (and `S`) are dropped (zeroized) as soon as `B` is in hand;
they aren't needed for the bulk stream.

## Chunk encryption

Each file chunk (whatever size the transport uses — 16 KiB for WebRTC
DC, 1 MiB for relay) is compressed then AEAD-encrypted under `B`:

```
compressed = zstd(-3, plaintext_chunk)          // per Seb's compression note
nonce      = chunk_index as u64 little-endian, right-padded to 12 bytes
ciphertext = ChaCha20-Poly1305(B, nonce, compressed, aad="")
```

The chunk index doubles as a nonce because `B` is fresh per transfer,
so nonce reuse is only a concern within one session and monotonic idx
guarantees uniqueness there. AEAD tag authenticates both the payload
and (implicitly, via nonce mismatch failing decrypt) the chunk position.

The receiver reverses:

```
compressed = ChaCha20-Poly1305-Decrypt(B, chunk_index_nonce, ciphertext)
plaintext  = zstd_decode(compressed)
```

Compression algorithm and level ride in the meta frame so the receiver
knows what to unpack. Sender picks: probe first ~64 KiB with zstd -3;
if ratio < 1.02 (near-incompressible content — video, jpg, already-
compressed archives), skip compression for the whole file and mark
`compression: "none"` in meta.

## Wire protocol additions

New SignalFrame variants (WebSocket JSON):

```
{"type":"kex_pub",  "pub":"<hex-64>",       "mac":"<hex-64>"}
{"type":"key_wrap", "enc_b":"<hex-var>",    "nonce":"<hex-24>"}
```

Meta frame gains a `compression` field:

```
{"type":"meta", "name":..., "size":..., "chunkBytes":..., "totalChunks":..., "compression":"zstd"|"none"}
```

Chunk frames on the DC / relay path carry ciphertext bytes directly,
no additional envelope needed — the receiver knows chunk index from
its position in the stream and derives the nonce from that.

## Optional identity signing (per Seb 2026-09-02)

If the initiating user has a stored bitmule identity keypair (Ed25519
sign key from `bitmule identity add`), the sender may additionally
compute:

```
file_hash = SHA256(entire plaintext file)
signature = Ed25519_sign(sender_identity_priv, file_hash)
```

And send `{file_hash_hex, signature_hex, signer_pubkey_hex}` as a
`sign` SignalFrame either before the meta or as a distinguished last
frame after `done`. The receiver, if it knows the sender's identity
from prior contact-add flow, verifies the signature and can display
"file authenticated as <sender>" alongside the completion notification.

Signing is optional — anonymous transfers still work end-to-end
without an identity. The authentication only adds a "who sent it" bit
on top of confidentiality.

## What this DOESN'T protect against

- Compromise of `A` DURING the session (before ephemerals are wiped):
  attacker with `A` can conduct their own KEX with either side and
  MITM. Same as with any share-link scheme.
- Endpoint compromise: if the sending or receiving box is owned, keys
  in memory leak. Standard.
- Traffic analysis: the relay server sees ciphertext sizes and timing.
  Chunk-size stability + zstd compression removes some info but not
  all.
- Sender identity denial-of-service: any URL-holder can send SOMETHING
  under the same session. The receiver has no way to tell without the
  optional identity signing above.

## Implementation

See `crates/bitmule-client-native/src/crypto.rs` for the Rust
primitives: `ShareKey`, `Ephemeral`, `SessionKey`, `BulkKey`. Each type
owns its key material and zeroizes on drop. Unit tests cover:
- HKDF roundtrip on shared-key derivation (both sides produce the same S)
- MAC binding — different `A` produces different MAC for the same pub
- Chunk encrypt/decrypt roundtrip at multiple indices
- Session-id determinism + hex format
- ShareKey hex roundtrip
- Wrong chunk index fails AEAD (authentication check)

Wiring into `str0m_client` (KEX over WS, encryption on chunk pipeline)
is in a follow-up push.

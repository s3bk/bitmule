# bitmule end-to-end cryptography

Confidentiality + authenticity for file transfers, riding on top of the
WebRTC data channel (or the server-relay HTTP path). Spec authored + iterated
2026-09-02 through 2026-09-03 with Seb driving; Kenna writing.

## Threat model

- **Signaling server** sees `session_id` (WebSocket handle) and, on the
  relay path, ciphertext bytes for each chunk. Server never sees the
  URL fragment, never sees any key material.
- **Passive network attacker** sees what the server sees on the wire.
- **Active network attacker without the URL secret** cannot inject
  valid signaling, cannot substitute keys, and cannot read ciphertext.
- **URL-secret holder** IS effectively an authorized party. Sharing the
  URL is the credential; anyone who has it is trusted. Same as any
  share-link scheme.
- **URL-secret leak AFTER the session** (recording captured, URL later
  reveals) must not decrypt the recording. This is the forward-secrecy
  requirement.

## Key hierarchy

| Symbol      | Bytes | Lifetime           | Source                                  | Purpose                                              |
|-------------|-------|--------------------|-----------------------------------------|------------------------------------------------------|
| `A`         | 32    | share URL          | initiator RNG                           | URL-shared secret. Lives in URL `#` fragment.        |
| `session_id`| 32    | ambient            | SHA256(A)                               | Public session identifier. Server sees it.           |
| `E_priv/pub`| 32/32 | one session        | each side RNG (fresh per session)       | Ephemeral X25519 keypair. Priv wiped after DH.       |
| `S`         | 32    | one session        | X25519(local_E_priv, peer_E_pub)        | Raw DH shared secret. Non-uniform.                   |
| `wrap_key`  | 32    | one session        | HKDF(S, salt=session_id, "wrap-key")    | Wraps B for wire transport.                          |
| `meta_key`  | 32    | one session        | HKDF(S, salt=session_id, "meta-key")    | Encrypts the meta frame.                             |
| `B`         | 32    | one file transfer  | sender-of-file RNG                      | Bulk stream key. AES-256-GCM.                  |

**Initiator generates `A`.** For `bitmule send`, that's the sender; for
`bitmule recv` (recipient invites file), that's the recipient. Either
way the initiator puts `A` in the URL fragment and shares out-of-band
(link, QR).

**Sender-of-file generates `B`.** In `send` flow that's the initiator;
in `recv` flow it's the OTHER party who opens the link and streams
their file.

**B is stable for the lifetime of the file being sent.** If the transfer
restarts, the same B is reused: since the file is immutable during
transfer, the same idx maps to the same plaintext, which produces the
same ciphertext deterministically. No nonce-reuse-with-different-plaintext
problem. A different file or a modified file requires a fresh B.

## Session identifier

```
session_id = SHA256(A)
```

64 hex characters, matches the existing session-hex format the server
uses. Deterministic (both sides derive it independently from A). One-way
— server holding session_id cannot recover A.

## Per-session key exchange

Both sides:

1. Generate a fresh ephemeral X25519 keypair `(E_priv, E_pub)`.
2. Announce their `E_pub` over the signaling WebSocket as a
   `KexPub { pub, mac }` SignalFrame, with `mac = HMAC-SHA256(A, E_pub)`.
   Sends immediately after being paired (concurrent with SDP exchange).
3. On receiving the peer's `KexPub`:
   - Recompute `HMAC-SHA256(A, peer_pub)` and constant-time-compare
     against the received MAC. Mismatch → abort.
   - Validate `peer_pub` against the RFC 7748 §7 list of low-order /
     small-subgroup X25519 points. Any match → abort.
4. Derive the raw DH shared secret:
   ```
   S = X25519(local_E_priv, peer_E_pub)
   ```
   Additionally verify S is not all zeros (catches any small-subgroup
   variant the pre-check missed; x25519-dalek returns zeros silently on
   this case rather than erroring). Zero → abort.
5. Derive purpose-specific keys:
   ```
   wrap_key = HKDF-SHA256(ikm=S, salt=session_id, info="transfer-v1 wrap-key", 32)
   meta_key = HKDF-SHA256(ikm=S, salt=session_id, info="transfer-v1 meta-key", 32)
   ```
   Different info strings guarantee wrap_key and meta_key are
   independent — a break of one does not propagate.
6. Wipe `E_priv` and `S` from memory as soon as `wrap_key` + `meta_key`
   are derived. Only `wrap_key` and `meta_key` live to be used.

Possession of `A` is the credential that authenticates the exchange —
a passive listener without A cannot forge a MAC that verifies. Forward
secrecy holds because the ephemeral privates are wiped after use;
someone acquiring A later cannot reconstruct S.

## Bulk key exchange

Sender-of-file generates `B` (32 random bytes) and wraps it under
`wrap_key`:

```
nonce = 12 random bytes
enc_B = AES-256-GCM(wrap_key, nonce, plaintext=B, aad="")
```

Sends `KeyWrap { enc_B, nonce }` over the WebSocket. Receiver, holding
`wrap_key`, unwraps:

```
B = AES-256-GCM-Decrypt(wrap_key, nonce, enc_B, aad="")
```

`wrap_key` and `S` are wiped after B is in hand.

## Meta frame encryption

Meta carries file metadata: name, size, chunkBytes, totalChunks,
compression choice. Attackers may plausibly know some of these fields
out-of-band (e.g. filename via context), so meta encryption is
constructed to guard S and B even if the meta plaintext is known:

```
meta_nonce = 12 random bytes
meta_ct    = AES-256-GCM(meta_key, meta_nonce, plaintext=meta_json, aad=session_id)
```

`meta_key` is DISTINCT from both `wrap_key` and `B` — HKDF with
different info strings. AAD binds the ciphertext to this specific
session so cross-session replay fails at decrypt time.

### Optional meta signing (identity)

If the sender has a bitmule Ed25519 identity keypair
(`bitmule identity add`), they may sign the meta:

```
sig_hash  = SHA256(session_id || meta_nonce || meta_ct)
signature = Ed25519_sign(sender_identity_priv, sig_hash)
```

The signature covers the exact session + exact ciphertext + exact
nonce, so a signature cannot be lifted onto a different meta or
replayed across sessions. Receiver, if they know the sender's Ed25519
public key out-of-band (prior contact-add flow), verifies the
signature before attempting decrypt. Displays "authenticated as
<sender>" on completion.

Anonymous transfers work without any signature — the field is
optional. The signature adds a "who sent it" bit on top of the always-
present confidentiality.

Wire frame:

```
{"type":"meta_enc", "nonce":"<hex-24>", "ct":"<hex-var>",
 "sig":"<hex-128>?", "signer_pub":"<hex-64>?"}
```

## Bulk data pipeline

For each file chunk:

1. **Frame the plaintext with a length prefix and pad to a fixed size**
   so ciphertext length is uniform regardless of content:
   ```
   payload = [u32 length_prefix][plaintext_bytes][zero_padding]
   ```
   where `length(payload) == CHUNK_BYTES` (16 KiB for the DC path,
   1 MiB for the relay path). The length prefix lets the receiver
   recover the original plaintext boundary after decrypt; padding
   prevents any per-chunk size-based inference by the observer. Total
   plaintext bytes across the transfer is redundantly recorded in the
   meta so the receiver validates end-of-stream.
2. **Compress** the framed payload if the file was flagged compressible
   in meta (see below). Compressed size is bounded by the padded frame
   so ciphertext stays uniform. If not compressible, skip the
   compression pass.
3. **AEAD-encrypt** under `B` with a deterministic nonce from the
   chunk index:
   ```
   nonce      = chunk_index (u64 LE) padded to 12 bytes
   ciphertext = AES-256-GCM(B, nonce, payload, aad="")
   ```
   `B` is fresh per file, so nonce reuse is only a concern within one
   session, and monotonic chunk_index guarantees uniqueness there.

### Compression choice

Sender probes the first ~64 KiB of the plaintext file with zstd -3.
If the ratio is meaningful (say < 0.98), the whole file is compressed
with zstd -3 and meta records `compression: "zstd"`. If not (already-
compressed formats: jpg, mp4, pre-zipped archives), skip and record
`compression: "none"`. Receiver reads meta to know whether to
decompress.

### Receiver pipeline

```
ciphertext → AEAD decrypt(B, chunk_nonce) → payload
payload → strip length prefix + trim padding → compressed_bytes (or raw)
compressed_bytes → zstd decode (if meta said so) → plaintext bytes
plaintext bytes → append to output file
```

### Chunk-count validation at close

Receiver tracks `set of received idx` during transfer. On the final
"done" signal, receiver checks: `received_set == {0..totalChunks}`.
If any idx is missing, the transfer is rejected — writes are
discarded (or the partial file is renamed with a `.partial` suffix
per operator preference), and the caller sees an error. Prevents an
attacker from silently deleting a mid-stream chunk and leaving the
receiver with a corrupted file.

## Design commitments

Encoded in code + enforced by tests, not just spec:

1. **No plaintext-fallback path.** Sender ALWAYS encrypts chunks
   under B. If KEX doesn't complete (peer never sends KexPub, or the
   MAC verify fails), the transfer errors out rather than downgrading
   to plaintext. A downgrade attack becomes a denial-of-service, not
   a decryption.
2. **Chunk padding.** Fixed padded chunk size (per transport)
   regardless of content compressibility.
3. **Dedicated SPA domain, zero third-party scripts.** The web SPA is
   served from a domain that runs no analytics, no fonts, no ads, no
   external JS at all. CI enforces this via a script-tag audit on the
   built bundle. This is the only mitigation available against the
   `#`-fragment-leak-via-page-JS class.
4. **B is immutable per file.** Sender does not rotate B mid-transfer.
   Restarts reuse the same B against the same immutable-file plaintext.

## Wire protocol additions

New SignalFrame variants over the signaling WebSocket:

```
{"type":"kex_pub",  "pub":"<hex-64>",       "mac":"<hex-64>"}
{"type":"key_wrap", "enc_b":"<hex-var>",    "nonce":"<hex-24>"}
{"type":"meta_enc", "nonce":"<hex-24>",     "ct":"<hex-var>",
                    "sig":"<hex-128>?",     "signer_pub":"<hex-64>?"}
```

Chunk frames on the DC or relay path carry ciphertext bytes directly
— receiver knows chunk index from its position in the stream and
derives the nonce from that.

## Adversarial review: attacks considered

Every credible attack we thought of + why the design closes it (or the
constraint that pushes it into "known + accepted"). Reviewed 2026-09-03.

| # | Attack                                       | Outcome | Why                                                                  |
|---|----------------------------------------------|---------|----------------------------------------------------------------------|
| 1 | Per-chunk bit-flip                           | Safe    | AEAD tag fails → decrypt errors → chunk rejected.                    |
| 2 | Chunk reorder (swap ct of idx 5 into idx 7)  | Safe    | Nonce = idx mismatch → tag fails.                                    |
| 3 | Chunk insertion by attacker without B        | Safe    | AEAD tag fails → dropped.                                            |
| 4 | Chunk deletion (silent drop)                 | Safe    | Chunk-count validation at close rejects if any idx is missing.       |
| 5 | Whole-file replay in later session           | Safe    | New ephemerals → new B → old ciphertext undecipherable.              |
| 6 | Low-order X25519 pub injection               | Safe    | Rejected pre-DH against the RFC 7748 §7 point list.                  |
| 7 | Small-subgroup variant not in point list     | Safe    | Post-DH zero-shared-secret check catches it.                         |
| 8 | Signaling-server MITM without A              | Safe    | KEX MAC under A fails; server can't forge a valid `kex_pub`.         |
| 9 | Signaling-server MITM to strip KEX (downgrade)| Safe    | No plaintext-fallback; sender encrypts unconditionally under B; receiver simply can't decrypt without KEX → transfer errors. |
| 10| Signaling-server MITM on SDP fingerprint     | Safe    | WebRTC DTLS-fingerprint check in the SDP layer prevents casual substitution below our layer. |
| 11| Attacker with A: MITM (KEX with each side)   | Accepted| A IS the credential. Anyone with A is authorized. Documented.        |
| 12| Meta ciphertext replay across sessions       | Safe    | session_id bound as AAD; replay fails decrypt.                       |
| 13| Meta ciphertext modification                 | Safe    | AEAD tag over ct.                                                    |
| 14| Meta signature lifted onto different meta    | Safe    | Sig hash covers session_id + nonce + ct.                             |
| 15| B leak via known-plaintext meta              | Safe    | meta_key is HKDF-distinct from wrap_key; break of one doesn't leak the other. |
| 16| CRIME-class compression side channel         | Safe    | Bitmule transfers a whole file; no attacker-controlled input mixed in. Compressed size + chunk padding leak only chunk count. |
| 17| B reuse on transfer restart                  | Safe    | File is immutable per B; same idx → same plaintext → deterministic ct. |
| 18| DoS via forged KEX MAC flooding              | Bounded | MAC verify is O(one HMAC-SHA256); server-layer WS rate limiting caps the flood. Not a decryption threat. |
| 19| Per-chunk size-based content inference       | Safe    | Chunks padded to fixed size before AEAD. Observer sees uniform-size ciphertext + chunk count only. |
| 20| `#`-fragment leak via SPA third-party script | Safe    | Dedicated bitmule domain, zero third-party scripts, CI-enforced. Only mitigation available at this layer.  |
| 21| URL leak DURING an active session            | Accepted| Any share-link scheme has this. Session in progress + URL leaks = MITM window until session ends. |
| 22| Endpoint compromise                          | N/A     | Out of scope. Keys in RAM leak if the host is owned. Standard.       |

## What this doesn't try to protect against

- **URL-secret compromise mid-session** — the attacker who obtains A
  during a live session can MITM. Design assumption: A is treated as
  sensitive credential material by the human sharing it.
- **Traffic analysis at the metadata layer** — server sees timing +
  aggregate ciphertext size + chunk count. Chunk padding + zstd
  compression before encryption remove some info but not all.
- **Sender identity denial-of-service** — any URL-holder can send
  SOMETHING under the same session. Receiver has no way to distinguish
  legitimate sender from URL-thief without the optional identity
  signing above.
- **Endpoint compromise** — if either sending or receiving box is
  owned, keys in memory leak. Standard.

## Browser (SubtleCrypto) compatibility

The bulk chunk cipher is AES-256-GCM specifically because SubtleCrypto
supports it natively in every current browser and gives us hardware-
accelerated AES-NI perf on the SPA side. Bulk decryption is the only
place where perf matters (many-chunk stream). Everything else runs
one-shot per session, so a WASM implementation in the SPA is fine.

| Primitive             | SubtleCrypto              | SPA fallback if unsupported            |
|-----------------------|---------------------------|----------------------------------------|
| AES-256-GCM (bulk)    | ✅ native everywhere      | required for bulk perf; no fallback    |
| SHA-256               | ✅ native everywhere      | —                                      |
| HMAC-SHA256           | ✅ native everywhere      | —                                      |
| HKDF-SHA256           | ✅ native everywhere      | —                                      |
| X25519 (ECDH)         | ⚠ Chrome 133+ / FF 132+ / Safari 18 | WASM `@noble/curves`         |
| Ed25519 (optional)    | ⚠ Chrome 137+ / FF 137+ / Safari 17 | WASM `@noble/curves` (only if signing enabled) |
| getRandomValues       | ✅ everywhere             | —                                      |

Native (Rust) uses `aes-gcm` for the same primitive, so the two sides
interop byte-for-byte on chunks + wraps + meta.

## Implementation

See `crates/bitmule-client-native/src/crypto.rs` for the Rust
primitives:

- `ShareKey` — A + session_id derivation + MAC over ephemeral pubs.
- `Ephemeral` — X25519 keypair, consumed on `derive_shared_secret`
  which rejects low-order pubs and zero shared secrets.
- `SessionKey` (S) — raw X25519 output. Non-uniform. `wrap_key(sid)`
  and `meta_key(sid)` derive purpose-specific AEAD keys.
- `WrapKey` — encrypts / decrypts B via AES-256-GCM.
- `MetaKey` — encrypts / decrypts meta with session_id bound as AAD.
  Provides `meta_signing_hash(sid, nonce, ct)` helper for the optional
  Ed25519 signature.
- `BulkKey` (B) — chunk encrypt / decrypt with idx-derived nonces.

Every key type Zeroizes on drop. All unit tests cover:
- HKDF derivations distinct across info strings
- Session-key equality across both sides of a full KEX
- MAC-A binding (different A → different MAC)
- Meta encrypt/decrypt roundtrip + session_id AAD binding (wrong
  session_id fails)
- Chunk encrypt/decrypt + wrong-idx nonce fails AEAD
- Low-order pub rejection
- Share-key hex roundtrip
- Session-id determinism

Wiring into `str0m_client` (KEX over WS, encryption on chunk pipeline,
chunk-count validation) is in a follow-up push.

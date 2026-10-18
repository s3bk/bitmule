# Cryptography and trust model (protocol v2)

## Secrets

| Name | Where it lives | Purpose |
|---|---|---|
| `A` (32 B) | link fragment (`#...`), never sent to the server | the only credential; authenticates peers |
| `session_id = SHA256(A)` | server sees it | names the session |
| identity key (X25519) | generated per run | long-term key for this run |
| bulk key `B` | inside the sealed manifest | encrypts relay blocks |

The link fragment is `A ‖ signature`, where `signature = SHA256(data ‖ B)` ties the link to one file.

## Handshake

1. The owner creates the session, sending `join_check = SHA256("bitmule-v2 join check" ‖ join_proof)`, where `join_proof = HMAC(A, "bitmule-v2 join proof")`. The server stores only the check.
2. A joiner must present `join_proof`. Knowing just `session_id` is not enough: the server refuses the join before handing out the owner's public key or a relay token.
3. Both sides publish their identity key with `HMAC(A, "bitmule-v2 identity" ‖ role ‖ session_id ‖ id ‖ pub)`. The role (owner/joiner) is bound in, so a peer cannot replay your own MAC back, and a peer presenting your own public key is refused.
4. The session key comes from three X25519 DH operations (X3DH style) hashed with HKDF.
5. All messages are AES-GCM envelopes. The AAD is `session_id ‖ direction ‖ counter`; direction is derived from the ordering of the two identity keys, so a reflected envelope does not open. Counters are checked for overflow.
6. The manifest (names, sizes, `B`, per-block hashes) travels sealed in this channel.

## Data paths

- **WebRTC:** the data channel is protected by DTLS. The SDP fingerprint is exchanged inside the sealed channel, so the server cannot swap it.
- **Relay:** 2 MiB blocks, AES-GCM under `B` (nonce = block number), RaptorQ-coded. The server stores ciphertext only.
- **Integrity:** the manifest carries a truncated BLAKE3 hash per block. The CLI sender records the hash of each block on the first pass and aborts if a later pass produces a different one; receivers reject frames whose announced hash differs from the manifest. After download the receiver checks the signature and checksum; on mismatch the file is deleted unless `--keep-failed`. Zip contents are checked against the sizes in the manifest (`unpacked_size`).
- The web sender does not provide block hashes or `unpacked_size`; receivers fall back to the signature check and a conservative unpack limit.

## What the server sees

Session ids, IP addresses, timing, transfer sizes, number of blocks, who is connected. Not names, contents or keys.

## Trust model and limits

- **`A` is the only credential.** Anyone holding the full link can join, and there is no limit on joiners, no revocation and no short-authentication-string. Share links over a channel you trust; treat a leaked link as a leaked file.
- **Browser E2E trusts whoever serves the JS/WASM.** A malicious or compromised host can ship code that exfiltrates the fragment. The server sets a strict CSP and related headers, and a test forbids inline scripts in `web/index.html`. `web/bitmule.html` is exempt (inline script, third-party fonts). For stronger guarantees use the CLI or a native app.
- **Transport:** the CLI refuses non-`https`/`wss` servers unless `--unsafe` is given. Everything is still end-to-end encrypted over plain http, but metadata and the traffic pattern are exposed, and the join proof is observable.
- **No padding, compression or metadata stripping.** File sizes are visible to the server; filenames and EXIF in your files are transferred as they are.
- The protocol is not compatible with v1 clients or earlier v2 builds.

## CLI receive options

- `--on-conflict ask|overwrite|reject|rename` (default `ask` on a terminal). Overwrite truncates the file before verification, so a failed check loses the original.
- `--keep-failed` keeps files that fail the final check.

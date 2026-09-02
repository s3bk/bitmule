# bitmule feature spec (running notes)

Source of truth for feature requirements before they land in code. Every entry names who requested it and when. Not a design doc — a queue of "here is what we agreed the tool needs to do."

## Transport

- **Default: link sharing.** `bitmule send <path>` prints a link that anyone with the link can fetch. (Seb 2026-09-01)
- **Bidirectional FTP-like remote mode.** Upload-to and download-from a bitmule endpoint from anywhere. (Pete 2026-09-01)
- **Serve mode.** `bitmule serve <dir>` publishes a directory persistently. Access is read-only or read-write per contact grant. (Seb 2026-09-01)
- **Direct-listener + UPnP.** `bitmule listen --port N --upnp` opens a fixed port and optionally auto-configures NAT via UPnP for a self-hosted receive endpoint. (Seb 2026-09-01)
- **Transport auto-optimization.** The tool picks the best transport (WebRTC, direct listener, relay, LAN, etc.) automatically. User-facing surface must stay simple: `bitmule send @peer path` — the tool decides how. (Pete 2026-09-01)

## Identity + contacts

- **Keypair per install.** Each install generates a private+public keypair on first run. (Seb 2026-09-01)
- **Public key sharing.** Public key exportable via link and QR code. (Seb 2026-09-01)
- **Contacts menu.** CLI subcommand to add/list/remove contacts. A contact is a `(name, public_key)` pair. (Seb 2026-09-01)
- **Server-side routing by pubkey.** On connect, CLI presents its public key to the server; server routes inbound requests for that pubkey to the connected client. (Seb 2026-09-01)
- **Named-peer send.** `bitmule send @pete some_folder` addresses a peer by contact name; resolves locally to their pubkey. (Seb 2026-09-01)
- **Identity keys are auth-only, not payload keys.** The long-term keypair authenticates the client to the server and the peer to the peer. Each transfer negotiates its own fresh session encryption independently, preserving forward secrecy per transfer. (Seb 2026-09-01)

## Daemon mode

- **Background receive.** Long-running process on the recipient host that accepts inbound sends from **authorized contacts** without per-transfer confirmation. (Seb 2026-09-01)
- **Delivered directly to disk.** Received files land in a configured directory. (Seb 2026-09-01)
- **Encryption required.** Payloads always encrypted; daemon-receive requires authenticated + encrypted transfer end-to-end. (Seb 2026-09-01)
- **Access grants per contact.** Serve-mode + daemon-receive both key off contact ACL: read-only, read-write, or receive-only per contact. (Seb 2026-09-01)

## Mobile

- **Mobile mount of a peer's server folder.** Phone with CLI installed + linked to a desktop install can mount the desktop's serve-mode folder for browse/read/write. (Seb 2026-09-01)

## Compression

- **zstd, per-file adaptive.** Skip on already-compressed formats. Pipeline order: plaintext → compress → encrypt → chunk. (Seb 2026-09-01 earlier)

## Server (built 2026-09-01)

`bitmule-server` binary wires WebSocket signaling + REST chunk relay on top of `FsChunkStore`:

- `GET /ws/:session_hex` — signaling room. First frame is a JSON hello with role (`sender`/`receiver`) and, for receivers, a receiver_id. Sender frames fan to all receivers in the room; receiver frames route to the sender. No inspection of payload — SDP, ICE, and key-exchange all ride the same relay.
- `PUT /session/:sess/chunk/:idx` — upload ciphertext chunk. Quota-checked before write.
- `GET /session/:sess/chunk/:idx` — download ciphertext chunk.
- `GET /session/:sess/have` — bitmap of stored chunks (roaring, serialized).
- `GET /session/:sess/capacity` — remaining bytes of session quota.
- `POST /session/:sess/delivered/:idx` — receiver acks delivery; body is the hex ReceiverId.
- Background loop: `gc_delivered` every 60s, `evict_older_than` every 10 min, `evict_to_bytes(max_disk_bytes)` every tick.
- `--max-disk-bytes` CLI flag (default 500 GiB) caps total stored ciphertext across all sessions. When exceeded, oldest chunks evict first until back at or below the cap. (Seb 2026-09-01)

Every path segment is hex-parsed via `SessionId::from_hex` / `ReceiverId::from_hex` — non-hex gets 400 immediately, so path traversal never reaches the store.

Auth is deferred to the identity-key layer (contacts, pubkey routing) — every session id is accepted for now.

## Smoke-test CLI (2026-09-01)

`bitmule send <path>` uploads the whole file as chunk 0 under a fresh random SessionId and prints:
```
session: <64-hex>
recv with: bitmule --server http://... recv <64-hex>
```
`bitmule recv <session_hex> --out <path>` downloads chunk 0 of that session and writes it.

Smoke path only — no manifest, no chunking, no encryption, no WebRTC yet. Exists to prove the streaming HTTP relay end-to-end. Uses reqwest for the client; upload body is `ReaderStream` from a `tokio::fs::File`, download body is a streamed `resp.bytes_stream()` piped to disk.

Verified 2026-09-01:
- 1 MiB roundtrip: sha256 match
- 100 MiB roundtrip: sha256 match, server RSS 1988 → 3448 KiB across the whole upload+download (no whole-body buffering)
- PUT without Content-Length → 411 Length Required
- Recv with malformed hex → client rejects locally
- Recv with unknown session → 404 → clean error
- PUT with non-hex session id in path → 400

## Naming concern (unresolved)

- Pete flagged 2026-09-01: an eMule spinoff already exists under the "bitmule" name. Rename gets cheaper the sooner it happens.

## downloads
- mark download as used only after completion
- allow generating unique 1-time download links, which can be revoked
- also allow revoking the whole download
- show download count / cap to the user

## uploads
- optional recovery passphrase (encrypt private key with passphrase, store on server or elsewhere). key loss -> data loss
- public key can be rotated, if signed by the old key

## exta features
- OS share-sheet integration — "share to [app]" from Photos, Files, other apps, instead of manually uploading through a browser tab
- Background sync / true P2P participation — a browser tab can't stay alive to sync files in the background the way a native client can (this is actually the core Syncthing-on-iOS problem Möbius Sync solves — iOS won't let any app run continuously in the background, which is exactly why paid native clients exist despite Syncthing itself being free)
- Camera roll / auto-backup hooks — direct access to photo/video libraries a web app can't get
- Notifications — push alerts when someone drops a file in your hosted inbox, without keeping a tab open
- Download limits / burn-after-reading — link self-destructs after N downloads. This is a heavily requested pattern (Firefox Send popularized it before shutting down) and it's fully compatible with E2EE since the limit-counter logic doesn't need to see file contents.
- Manual revocation — kill a link before it expires. Access control and revocation are consistently named as must-haves in secure file-sharing comparisons, and this is just server-side metadata (does the link still resolve), independent of the encryption layer.
- Custom expiry windows (hours vs. days vs. weeks) rather than a fixed TTL — flexible expiration is repeatedly called out as a differentiator.
- Inbox arrival push notifications on mobile (ties into your native-app value prop from earlier).
- Automatic EXIF/metadata stripping before encryption — this has to happen client-side anyway in a zero-knowledge system, so it's a natural fit and a real privacy plus most casual users don't think to ask for but appreciate.
- Run a script on sync/transfer completion — this is a persistent, unresolved request in the Syncthing ecosystem (people repeatedly ask for pre/post-sync hooks and have to hack around it with third-party watchers). Since your CLI is feature-complete, exposing --on-complete <cmd> or similar would be a genuine, low-cost differentiator for the technical crowd who'd otherwise reach for Syncthing.
- Battery-aware sync on laptops — "pause background sync on battery" is a recurring ask in Syncthing tray-app issue trackers that the core project hasn't addressed.

- Default expiry alongside single-use. An unused link sitting in an old email or chat log for years is a standing liability even if it's single-use — a sensible default TTL (e.g., 7–30 days, owner-configurable) closes that window.
- Bulk generation is a real, validated use case, not just a nice-to-have. Because you're CLI/API-first, you're naturally positioned for things like "generate 40 one-time upload links for a class roster" or "auto-generate a link per new vendor onboarded in our CRM." This is the same job as Dropbox File Requests / Kiteworks secure upload requests / JotForm-with-attachments, but scriptable — that's a genuine differentiator worth foregrounding in positioning, not just an implementation detail.
- Webhook/callback on upload completion. Since the owner may be offline, a webhook ("file arrived via link X") lets people build automation on top — triggering downstream processing, notifying a team channel, etc. This is a natural extension of your REST API story and something competitors' GUI-only file-request features don't offer.
- Metadata-only audit trail. Since the owner generated each link (presumably for a known purpose/recipient), you get free attribution — "link generated for Contractor X, used at time T, from IP Y" — without ever touching content. Worth surfacing this in the dashboard as a trust feature.

## Abuse mitigation
Hosted uploads & inbox
- Instant kill-switch at the account level. Since links resolve through your server, suspending an account can invalidate every active link instantly, regardless of whether you know what's in them.

### Downloads
- Download limits (rate, total)
- A report-abuse action on every download page, usable by the recipient without an account. Enough independent reports on one link/account triggers automatic link suspension or account throttling. This is the exact feature Send announced but never shipped before shutting down — you can ship it from day one since you already require identity for hosting.
  This needs a mechanism to prove that the downloaded file was uploaded by the given account without revealing the content in advace.
  (Abuse rport reveals the encryption key)

### Hosted Inbox
- one-time upload links for account-free submission
- Sender-side friction for anonymous submitters. A lightweight CAPTCHA or proof-of-work on inbox submission deters automated spam floods without requiring sender accounts.
- Per-sender-IP rate limiting on submission, platform-wide — an IP that gets reported or throttled on one inbox stays throttled elsewhere, even though you never know what they sent.


## Trial
The first month can be refunded if the user used less than 20% of the bandwidth AND their storage never exeeded 20% of the storage capacity

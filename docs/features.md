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
- Background loop: `gc_delivered` every 60s, `evict_older_than` every 10 min.

Every path segment is hex-parsed via `SessionId::from_hex` / `ReceiverId::from_hex` — non-hex gets 400 immediately, so path traversal never reaches the store.

Auth is deferred to the identity-key layer (contacts, pubkey routing) — every session id is accepted for now.

## Naming concern (unresolved)

- Pete flagged 2026-09-01: an eMule spinoff already exists under the "bitmule" name. Rename gets cheaper the sooner it happens.

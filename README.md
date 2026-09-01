# bitmule

Resumable, end-to-end-encrypted, WebRTC-first file transfer for browsers, mobile browsers, and CLI.

## Why

Nothing off-the-shelf hits all of:

- WebRTC direct with LAN-detected full-speed when peers are on the same network
- End-to-end encryption (server never sees plaintext)
- Server-buffered fallback when direct doesn't work — chunks persist for **days**, sender can go offline, receiver picks up when they reconnect
- Resumable across browser refresh, tab close, reboot, and multi-day interruption
- Optional password on top of the URL key (two-layer crypto: link decrypts transport, password decrypts payload)
- Folder support with per-file resume
- 10 MB → 1 TB file support (adaptive chunking)
- Browser (Chrome/Firefox, including Android) + Linux/macOS/Windows CLI, one wire protocol

Wormhole.app is closest — E2E and WebRTC but no resume, no folders, no server-buffered fallback.
Croc is CLI-only. LimeWire uploads to their servers first. LocalSend is LAN-only. WeTransfer is server-hosted plaintext.

## Install

```
cargo install bitmule
```

Or the browser client at https://bitmule.net (no install).

## Repo layout

```
crates/
  bitmule/                     # CLI binary — `cargo install bitmule` lands here
  bitmule-core/                # Rust library: chunking, crypto, manifest, protocol, traits.
                               # Compiles native (CLI/server) and wasm (browser).
  bitmule-client-wasm/         # wasm-bindgen wrapper of bitmule-core for the browser SPA
  bitmule-server/              # axum-based signaling + relay server
  bitmule-server-signal-ws/    # SignalTransport impl: WebSocket via tokio-tungstenite
  bitmule-server-store-fs/     # ChunkStore impl: filesystem-backed (S3 impl planned)
web/                           # SolidJS browser SPA (calls into bitmule-client-wasm)
```

## Architecture at a glance

- **Signaling**: WebSocket via `SignalTransport` trait, default impl in `bitmule-server-signal-ws`
- **Peer transport**: WebRTC DataChannel (browser) or equivalent (CLI-side lib TBD)
- **Fallback transport**: encrypted chunks buffered on the server via `ChunkStore` trait, default impl in `bitmule-server-store-fs`
- **Chunking**: adaptive size based on total transfer size and detected transport (LAN vs WAN)
- **Crypto**: two layers. K_session (X25519 → HKDF → XChaCha20-Poly1305) covers all wire traffic. Optional K_content (Argon2id from password) additionally wraps the payload so a compromised relay holding buffered ciphertext still can't decrypt.
- **Resume**: RoaringBitmap of received chunks, persisted client-side (IndexedDB + OPFS in browser, disk in CLI) and server-side (`ChunkStore::have`). Reconnection replays the delta.

## Status

Early scaffold. `bitmule-core` compiles; wire integration and server-side trait impls in flight.

## License

MIT.

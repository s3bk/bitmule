# bitmule web SPA

Zero-build landing page. Open `index.html` in any modern browser
(needs to be served over HTTP for the ES-module import to work — the
`file://` scheme blocks dynamic imports).

## Serve locally

```
cd web
python3 -m http.server 8080
# browse to http://localhost:8080
```

Or point any static file host at this directory.

## Server address

The SPA defaults to same-origin. Override at runtime by setting
`window.BITMULE_SERVER` before `main.js` runs, e.g. inject a
`<script>window.BITMULE_SERVER = "http://localhost:8443"</script>`
above the `main.js` include when serving the SPA from a different
host than `bitmule-server`.

If the SPA is opened via `file://`, it falls back to
`http://localhost:8443`.

## Building the wasm bundle

The SPA lazy-loads `./wasm/pkg/bitmule_client_wasm.js`. If that file
isn't present the UI still works; the status row just reads `wasm: not
built`.

To build it:

```
cargo install wasm-pack   # once
rustup target add wasm32-unknown-unknown

cd crates/bitmule-client-wasm
wasm-pack build --release --target web --out-dir ../../web/wasm/pkg
```

Refresh the SPA. Status row should read `wasm: v<version>`.

## How it works (v2)

The protocol runs in Rust compiled to wasm (`crates/bitmule-client-wasm`, the
same code as the CLI: postcard messages, sealed envelopes, key exchange,
fountain codes, proof of work). It runs in a dedicated web worker so the page
stays responsive; the page only does the UI and WebRTC.

- `v2-worker.js` — one job per worker (send / receive / request): the signaling
  websocket, relay upload and download, reading the file, assembling the
  received file in OPFS (memory if there is none).
- `v2.js` — starts a job, owns the `RTCPeerConnection`s, passes data channel
  messages to and from the worker.
- `main.js` — UI only.

Streaming send: `startSend({ streaming: true, ... })` sends data whose size is not known (a `ReadableStream`, or a
blob read as it goes). The data goes up first; the manifest and checksum follow, and the receiver checks it then. A
`ReadableStream` can be read once and repair passes need the data again, so pass `openStream: async (pass) => stream`
(opened anew for each pass), or just `stream` to have the worker keep a copy in OPFS. Streams go over the relay only.
The receiver needs no setup: it spools until the manifest arrives.

Limits: the transfer carries no file name (a receiver saves `bitmule-download`
or `bitmule-files.zip`); several files go as a store-mode zip; no UDP.

## Tests

```
pip install selenium
cargo build --release -p bitmule -p bitmule-server
python3 web/test/browser_test.py [name-filter]
```

Drives Chrome (headless, a matching chrome/chromedriver pair from
selenium-manager's cache, or `BITMULE_CHROME` / `BITMULE_CHROMEDRIVER`) against
the CLI and itself through a local server. Every wait is 10 s.

## Layout

- `index.html`     — single page that hosts both send-mode UI and receive-mode UI.
- `style.css`      — dark theme.
- `main.js`        — routes on `location.hash`: no hash → send mode, valid 64-hex hash → receive mode.
- `vendor/qrcode.js` — vendored QR generator (MIT, K. Arase).
- `bitmule.svg`    — logo + favicon.
- `wasm/pkg/*`     — populated by `wasm-pack build` (gitignored).

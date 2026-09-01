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
wasm-pack build --target web --out-dir ../../web/wasm/pkg
```

Refresh the SPA. Status row should read `wasm: v<version>`.

## Layout

- `index.html`     — single page that hosts both send-mode UI and receive-mode UI.
- `style.css`      — dark theme.
- `main.js`        — routes on `location.hash`: no hash → send mode, valid 64-hex hash → receive mode.
- `vendor/qrcode.js` — vendored QR generator (MIT, K. Arase).
- `bitmule.svg`    — logo + favicon.
- `wasm/pkg/*`     — populated by `wasm-pack build` (gitignored).

# exif-stripper

A tiny Rust → WASM library that strips EXIF metadata from JPEG (`APP1
Exif\0\0`) and PNG (`eXIf` chunk) files **as a true byte stream** — it
never loads the whole file into memory, in Rust or in JS.

## How it avoids "excessive allocations"

- **No whole-file buffer, ever.** The parser is a streaming state machine
  (`src/core.rs`). When it needs to drop an EXIF segment, it only tracks a
  `remaining: u32` byte counter — it never copies the segment's bytes
  anywhere, since they're being thrown away.
- **Passthrough is zero-copy.** Bytes that are kept are re-emitted as
  *borrowed slices* of the input chunk. Nothing is copied unless it has to
  cross the Rust/JS boundary.
- **State is a few bytes, independent of file size.** The only owned
  buffers in the whole state machine are fixed-size stack arrays: `[u8;6]`
  to peek the `Exif\0\0` signature, `[u8;8]` to peek a PNG chunk header,
  `[u8;8]` for format detection. A 5 KB JPEG and a 5 GB JPEG use the exact
  same amount of state.
- **Output chunk size == input chunk size**, not file size. The only heap
  allocations at runtime are the `Uint8Array`s handed to
  `controller.enqueue()`, each sized to what's actually being kept from
  one input chunk (typically bounded by `File.stream()`'s ~64 KiB reader
  chunks).
- **The stream stays a stream.** `File → File.stream() → pipeThrough(TransformStream) → ReadableStream`
  end to end. You can pipe the result straight into `fetch(url, {body})`,
  a `Response`, or another `pipeThrough` without ever materializing the
  full file.

## Supported formats

| Format | What's stripped |
|---|---|
| JPEG | `APP1` segments whose payload starts with `Exif\0\0` (the actual EXIF blob). Other `APP1` uses (e.g. XMP) and all other segments (JFIF `APP0`, ICC profiles, quantization tables, scan data, etc.) pass through byte-for-byte. |
| PNG | The `eXIf` chunk. All other chunks (`IHDR`, `IDAT`, `tEXt`, `pHYs`, `IEND`, ...) pass through byte-for-byte. |
| Anything else | Passed through completely untouched — the library only ever strips formats it explicitly understands, it never guesses. |

Extending it to other containers (e.g. WebP's `EXIF` RIFF chunk, HEIC's
`Exif` box) means adding another state machine variant to `core.rs`
following the same "track a byte counter, don't copy" pattern.

## Project layout

```
exif-stripper/
├── Cargo.toml
├── src/
│   ├── core.rs   # pure Rust, zero dependencies, unit + fuzz tested natively
│   └── lib.rs    # wasm-bindgen glue exposing it to a JS TransformStream
└── www/
    └── demo.html # drop-in browser example
```

`core.rs` has no wasm/browser dependencies at all, so its logic is
verified with plain `cargo test` (see the tests at the bottom of the
file) — including a check that every possible chunk-boundary split (1
byte at a time, up to the whole file in one call) produces identical,
correct output, plus a small deterministic fuzz test over random split
points.

## Building

You'll need a current Rust toolchain, the `wasm32-unknown-unknown`
target, and `wasm-pack`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack   # or: cargo binstall wasm-pack

wasm-pack build --target web --release
```

This produces a `pkg/` directory with `exif_stripper.js`,
`exif_stripper_bg.wasm`, and TypeScript types, ready to `import` from a
browser module.

(Run `cargo test` from the project root any time to re-check the core
parsing logic without needing wasm-pack at all.)

## Usage

```html
<script type="module">
  import init, { ExifStripTransformer } from "./pkg/exif_stripper.js";

  await init(); // loads and instantiates the .wasm once

  /**
   * @param {File} file
   * @returns {ReadableStream<Uint8Array>} the file's bytes, streamed,
   *   with EXIF metadata removed. Nothing is buffered in full at any point.
   */
  function stripExif(file) {
    const transformer = new ExifStripTransformer();

    const ts = new TransformStream({
      transform(chunk, controller) {
        // chunk is a Uint8Array from File.stream()
        transformer.transform(chunk, controller);
      },
      flush(controller) {
        transformer.flush(controller);
      },
    });

    return file.stream().pipeThrough(ts);
  }

  // --- example: upload a cleaned file without ever holding the whole
  // thing in memory ---
  document.querySelector("#file-input").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    const cleanStream = stripExif(file);

    await fetch("/upload", {
      method: "POST",
      headers: { "Content-Type": file.type },
      body: cleanStream,        // streamed straight to the network
      duplex: "half",           // required by fetch when body is a stream
    });
  });

  // --- example: turn it into a Blob if you need one (e.g. to preview it) ---
  async function stripExifToBlob(file) {
    const stream = stripExif(file);
    const response = new Response(stream);
    return response.blob();
  }
</script>
<input id="file-input" type="file" accept="image/jpeg,image/png" />
```

See `www/demo.html` for a complete, runnable page (pick a file, see
before/after size and a live preview, download the cleaned file).

### Notes on `fetch` + streaming request bodies

Streaming a `ReadableStream` as a `fetch` request body requires
`duplex: "half"` and, as of writing, works in Chrome/Edge; Firefox and
Safari have had partial/behind-a-flag support. If you need broad browser
support today, use `stripExifToBlob()` above instead — it still never
holds more than the source file rendered to a network `Response` +
whatever the browser's own streaming `Blob` construction needs
internally, which is far better than a naive "read whole file into a
`Uint8Array`, mutate it, re-encode it" approach — you just lose the
"streamed over the wire too" property.

## API

### `new ExifStripTransformer()`
Creates one transformer. Create a new one per file/stream — it holds
small internal parser state that assumes chunks arrive in order for a
single stream.

### `transformer.transform(chunk: Uint8Array, controller: TransformStreamDefaultController)`
Feed the next chunk. Call this from a `TransformStream`'s `transform`
callback, in order, exactly as shown above.

### `transformer.flush(controller: TransformStreamDefaultController)`
Call once after the source is exhausted, from `TransformStream`'s
`flush` callback. Only matters for truncated/malformed input; well-formed
JPEG/PNG streams are fully drained during `transform`.

## Testing

```bash
cargo test          # core parser: unit tests + boundary sweep + fuzz test
```

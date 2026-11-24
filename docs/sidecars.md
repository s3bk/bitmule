# The helper programs a client ships with

Two things can't live inside the Rust binary, so they travel beside it:

| binary | what it is | why not linked |
| --- | --- | --- |
| `ffmpeg` | LGPL build with `libsvtav1` | the video encoder (see [encoder profiles](#encoder-profiles)); LGPL code stays a separate program we exec |
| `bitmule-linearize` | the PDF linearizer (`pdf_render`, `web/src/bin/linearize.rs`) | it is written against pdf-rs in the pdf_render tree; shipping a binary keeps one implementation of the layout |

Everything else — encryption, fountain codes, the container — is ours and is
compiled in. A bundle without these two still shares files, just without video
conversion and without page-1-first PDFs.

## Where they are looked for

One locator decides, `bitmule_client_common::sidecar::Locator`, so the CLI, the
Qt client and the mobile FFI cannot disagree. First hit wins:

1. `$BITMULE_TOOLS` — a directory. Development and tests.
2. next to the executable: `tools/<name>`, then `<name>`.
3. macOS `.app`: `Contents/Resources/tools/<name>`, then `Contents/Resources/<name>`.
4. `$PATH`.

A bundled copy beats `$PATH` deliberately: a system ffmpeg without
`libsvtav1` would otherwise shadow ours and quietly encode nothing useful.
`bitmule version` prints what was found and, for each miss, what the helper is
for.

## Bundle layout

```
linux/  bitmule          tools/ffmpeg  tools/bitmule-linearize
        bitmule-qt6
windows/ bitmule.exe     tools/ffmpeg.exe  tools/bitmule-linearize.exe
macos/   Bitmule.app/Contents/MacOS/bitmule
                         Bitmule.app/Contents/Resources/{ffmpeg,bitmule-linearize}
android/ lib/*.so        assets/tools/<abi>/{ffmpeg,bitmule-linearize}   (see below)
```

The mobile FFI has no `current_exe`, so on Android and iOS the app passes the
directory it unpacked the tools into via `BITMULE_TOOLS` — the same knob as
during development, which keeps one code path.

## Staging

`scripts/sidecars.sh [--out DIR] [--ffmpeg PATH] [--pdf-render PATH]` fills
`dist/tools` (default) and refuses to stage a build that would break the video
path:

* ffmpeg configured `--enable-gpl` → refused. We ship inside an MIT project.
* ffmpeg without `libsvtav1` → refused. Every profile uses SVT-AV1 as the
  fallback and the default.
* the linearizer is built from the pdf_render workspace root, because
  `web/.cargo/config.toml` there targets wasm, and is then asked for its usage
  line so a binary for the wrong architecture fails at packaging time, not on
  a user's machine.

Nothing is downloaded by the script: build or unpack ffmpeg yourself, pass it
in.

## Encoder profiles

The three profiles from the video design, all `-pix_fmt yuv420p10le`:

| profile | encoder |
| --- | --- |
| small & fast (GPU) | `-c:v av1_nvenc -preset p5 -tune hq -rc vbr -cq 34 -b:v 0`; `av1_qsv -preset fast -global_quality 34`; `av1_amf` |
| balanced (default) | `-c:v libsvtav1 -preset 8 -crf 32 -svtav1-params tune=0:film-grain=8` |
| quality | `-c:v libsvtav1 -preset 5 -crf 30 -svtav1-params tune=0:film-grain=12` |

Hardware encoders are chosen only after probing the actual ffmpeg build;
macOS always uses `libsvtav1`; a probe failure falls back to Balanced, never to
hardware.

## Linearizing

The linearizer writes the file so that page 1, the objects page 1 reads and a
small xref for them come first, with the main xref at the end (`/Linearized 1`,
`/L /T /E /O /N`). A receiver can then render page 1 from the first few
kilobytes while the rest of the file is still arriving. `/H` hint streams are
omitted on purpose: a reader that wants page *n* walks the page tree, and a
wrong hint table is worse than none.

The sender linearizes *before* encrypting, on the same pass that computes the
range table, so the ranges it records point into the file the receiver gets.

## Licences

* The bundle ships the ffmpeg licence text and the source offer that LGPL
  requires, alongside `bitmule-linearize`'s own MIT text.
* Neither binary is modified; both are invoked with arguments only. If we ever
  patch ffmpeg we must publish that patch — cheaper to probe features instead.

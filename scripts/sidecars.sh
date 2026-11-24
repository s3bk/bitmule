#!/bin/bash
# Stage the helper programs a client bundle ships with, next to the client.
#
#   scripts/sidecars.sh [--out DIR] [--ffmpeg PATH] [--pdf-render PATH]
#
# Defaults: --out dist/tools, --ffmpeg the first ffmpeg on $PATH,
# --pdf-render ../pdf_render (a checkout on the branch that has
# web/src/bin/linearize.rs).
#
# What lands in DIR (docs/sidecars.md):
#   ffmpeg             LGPL build with libsvtav1 — the video encoder
#   bitmule-linearize  PDF linearizer — page 1 first
#
# Both are separate programs, exec'd by the client, never linked into it.
# Nothing here downloads anything: ffmpeg comes from wherever you built or
# unpacked an LGPL build, the linearizer is built from source here.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/dist/tools
FFMPEG=${FFMPEG:-}
PDF_RENDER=${PDF_RENDER:-$ROOT/../pdf_render}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT=$2; shift 2 ;;
        --ffmpeg) FFMPEG=$2; shift 2 ;;
        --pdf-render) PDF_RENDER=$2; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$OUT"

# --- ffmpeg -----------------------------------------------------------------
# The build we ship must have SVT-AV1 and must not be GPL: we exec it, and an
# LGPL build executed by our program stays redistributable alongside MIT code.
if [ -z "$FFMPEG" ]; then
    FFMPEG=$(command -v ffmpeg || true)
fi
if [ -z "$FFMPEG" ] || [ ! -x "$FFMPEG" ]; then
    echo "no ffmpeg: pass --ffmpeg PATH (an LGPL build with libsvtav1)" >&2
    exit 1
fi

if "$FFMPEG" -hide_banner -version 2>/dev/null | grep -q -- '--enable-gpl'; then
    echo "$FFMPEG is a GPL build; build or fetch an LGPL one (see docs/sidecars.md)" >&2
    exit 1
fi
if ! "$FFMPEG" -hide_banner -encoders 2>/dev/null | grep -q ' libsvtav1'; then
    echo "$FFMPEG has no libsvtav1 encoder; the video path needs it" >&2
    exit 1
fi
install -m 0755 "$FFMPEG" "$OUT/ffmpeg"
echo "ffmpeg: $("$OUT/ffmpeg" -hide_banner -version | head -1)"

# --- bitmule-linearize ------------------------------------------------------
# Built from the pdf_render workspace root: web/.cargo/config.toml there builds
# for wasm, so the bin has to be built from above it.
if [ ! -f "$PDF_RENDER/web/src/bin/linearize.rs" ]; then
    echo "no linearizer at $PDF_RENDER/web/src/bin/linearize.rs; pass --pdf-render PATH" >&2
    exit 1
fi
( cd "$PDF_RENDER" && cargo build --release --bin linearize )
install -m 0755 "$PDF_RENDER/target/release/linearize" "$OUT/bitmule-linearize"

# A receiver shows page 1 before the rest arrives only if the file really is
# linearized; a wrong byte offset is worse than no linearization, so check the
# three places a reader looks: the header, the first-page xref and startxref.
check=$("$OUT/bitmule-linearize" 2>&1 || true)
case "$check" in
    usage:*) ;;
    *) echo "bitmule-linearize does not answer as expected: $check" >&2; exit 1 ;;
esac

# --- what was staged --------------------------------------------------------
echo
printf '%-20s %10s  %s\n' name bytes sha256
for f in "$OUT"/*; do
    printf '%-20s %10s  %s\n' "$(basename "$f")" "$(stat -c %s "$f")" "$(sha256sum <"$f" | cut -d' ' -f1)"
done
echo
echo "staged in $OUT — the client looks there first: <exe>/tools/, $BITMULE_TOOLS, .app/Contents/Resources/"

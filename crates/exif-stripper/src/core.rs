//! Streaming, allocation-lean EXIF stripper.
//!
//! Design goals:
//! - Never buffer the whole file. State is a handful of bytes/counters
//!   regardless of file size (an EXIF/eXIf segment can be megabytes long
//!   for a "portrait" HEIC-embedded thumbnail dump; we only ever track a
//!   `remaining: u32` counter for it, we never store its bytes).
//! - Passthrough bytes are re-emitted as *borrowed slices* of the input
//!   chunk (zero-copy) whenever possible. The only bytes we ever copy are
//!   the handful (<= 8) needed to identify a chunk/segment/signature that
//!   straddles a call boundary.
//! - The caller supplies an `emit` callback; we never build a Vec<u8> for
//!   the whole output ourselves. That decision (copy into a JS Uint8Array,
//!   write to a Vec, write to a socket, ...) is left to the caller.

const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const EXIF_SIG: [u8; 6] = *b"Exif\0\0";
const PNG_EXIF_CHUNK: [u8; 4] = *b"eXIf";

/// Public entry point. Create one `Stripper` per file/stream, then call
/// `push` for every chunk you receive, in order.
pub struct Stripper {
    inner: Inner,
}

enum Inner {
    /// We haven't seen enough bytes yet to know if this is JPEG, PNG, or
    /// something else. `buf`/`have` hold at most 8 bytes on the stack.
    Detecting { buf: [u8; 8], have: u8 },
    Jpeg(JpegState),
    Png(PngState),
    /// Unknown container: we pass everything through untouched. This is a
    /// deliberate safety default — we only ever strip formats we actually
    /// understand, never guess.
    PassThrough,
}

impl Stripper {
    pub fn new() -> Self {
        Stripper {
            inner: Inner::Detecting { buf: [0; 8], have: 0 },
        }
    }

    /// Feed the next chunk of the file. `emit` is called zero or more
    /// times with slices of output bytes, in order. Slices may borrow
    /// from `input` or be small owned buffers for bytes that were held
    /// across a previous call — either way, no per-file-size allocation
    /// happens here.
    pub fn push(&mut self, mut input: &[u8], emit: &mut dyn FnMut(&[u8])) {
        // Resolve format detection first, feeding any leftover detection
        // buffer plus new bytes through the same logic.
        if let Inner::Detecting { buf, have } = &mut self.inner {
            let need = 8usize.saturating_sub(*have as usize);
            let take = need.min(input.len());
            buf[*have as usize..*have as usize + take].copy_from_slice(&input[..take]);
            *have += take as u8;
            input = &input[take..];

            if (*have as usize) < 8 && !input.is_empty() {
                // Shouldn't happen (we only consumed up to `need`), but be safe.
            }

            if *have as usize >= 2 && buf[..2] == JPEG_SOI {
                // Enough to commit to JPEG as soon as we have the 2-byte SOI;
                // no need to wait for a full 8 bytes.
                let detected = buf[..*have as usize].to_vec();
                self.inner = Inner::Jpeg(JpegState::new());
                if let Inner::Jpeg(st) = &mut self.inner {
                    st.push(&detected, emit);
                }
            } else if *have as usize == 8 {
                let detected = *buf;
                if detected == PNG_SIG {
                    // The 8-byte magic number is not chunk data — emit it
                    // verbatim, then let PngState parse the chunk stream
                    // that follows it.
                    emit(&detected);
                    self.inner = Inner::Png(PngState::new());
                } else {
                    // Not a format we strip metadata from: flush what we
                    // buffered verbatim and stop inspecting further bytes.
                    emit(&detected);
                    self.inner = Inner::PassThrough;
                }
            } else if *have as usize >= 2 && buf[0] != 0xFF {
                // First byte already rules out JPEG and it's not the PNG
                // signature's first byte either — bail out early rather
                // than waiting for 8 bytes on a tiny file.
                if buf[0] != PNG_SIG[0] {
                    let detected = buf[..*have as usize].to_vec();
                    emit(&detected);
                    self.inner = Inner::PassThrough;
                }
            }
        }

        // Whatever remains of `input` (possibly all of it, if we were
        // already past detection) goes to the resolved state.
        if !input.is_empty() {
            match &mut self.inner {
                Inner::Detecting { .. } => { /* still buffering, nothing to forward */ }
                Inner::Jpeg(st) => st.push(input, emit),
                Inner::Png(st) => st.push(input, emit),
                Inner::PassThrough => emit(input),
            }
        }
    }

    /// Call once after the last chunk. For JPEG/PNG the formats are
    /// self-terminating so this only matters for malformed/truncated
    /// input, where any bytes still held internally are flushed verbatim
    /// rather than silently dropped.
    pub fn finish(&mut self, emit: &mut dyn FnMut(&[u8])) {
        if let Inner::Detecting { buf, have } = &mut self.inner {
            if *have > 0 {
                emit(&buf[..*have as usize]);
                *have = 0;
            }
        }
    }
}

impl Default for Stripper {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------

enum JpegState {
    /// Looking for the next 0xFF marker-prefix byte. Everything else is
    /// passthrough (emitted in one slice per call via a scan for 0xFF).
    Scanning,
    /// Saw a 0xFF, waiting for the marker code byte (handles 0xFF fill
    /// bytes and boundary splits).
    SawFF,
    /// Reading the 2-byte big-endian segment length that follows a
    /// length-carrying marker.
    NeedLen { marker: u8, buf: [u8; 2], have: u8 },
    /// We're in an APP1 segment and still need up to 6 bytes to check the
    /// "Exif\0\0" signature before deciding to keep or drop it.
    PeekApp1 { seg_remaining: u32, sig: [u8; 6], have: u8 },
    /// Passing an ordinary segment's payload through unchanged.
    CopySegment { remaining: u32 },
    /// Passing the SOS scan header through unchanged; once `remaining`
    /// hits 0 the next state is `RawTail` (not `Scanning`), since raw
    /// entropy-coded scan data follows with no further marker structure.
    CopySosHeader { remaining: u32 },
    /// Dropping a confirmed EXIF APP1 segment's payload.
    SkipSegment { remaining: u32 },
    /// Past SOS (start of scan): everything else — entropy-coded data,
    /// restart markers, EOI — is passed through untouched.
    RawTail,
}

fn is_standalone_marker(m: u8) -> bool {
    // TEM, RSTn (0xD0-0xD7), SOI (0xD8), EOI (0xD9) carry no length field.
    m == 0x01 || (0xD0..=0xD9).contains(&m)
}

impl JpegState {
    fn new() -> Self {
        JpegState::Scanning
    }

    fn push(&mut self, mut input: &[u8], emit: &mut dyn FnMut(&[u8])) {
        while !input.is_empty() {
            match self {
                JpegState::Scanning => {
                    match input.iter().position(|&b| b == 0xFF) {
                        Some(pos) => {
                            if pos > 0 {
                                emit(&input[..pos]);
                            }
                            emit(&input[pos..pos + 1]); // the 0xFF byte itself
                            input = &input[pos + 1..];
                            *self = JpegState::SawFF;
                        }
                        None => {
                            emit(input);
                            input = &[];
                        }
                    }
                }
                JpegState::SawFF => {
                    let b = input[0];
                    input = &input[1..];
                    match b {
                        0xFF => {
                            // Fill byte: still waiting for the real marker code.
                            emit(&[0xFF]);
                        }
                        0x00 => {
                            // Stray stuffed byte outside scan data shouldn't
                            // happen in a well-formed file; pass it through
                            // and resume scanning rather than panicking.
                            emit(&[0x00]);
                            *self = JpegState::Scanning;
                        }
                        m if is_standalone_marker(m) => {
                            emit(&[m]);
                            *self = if m == 0xD9 {
                                // EOI - nothing meaningful can follow; keep
                                // passing anything through defensively.
                                JpegState::RawTail
                            } else {
                                JpegState::Scanning
                            };
                        }
                        m => {
                            *self = JpegState::NeedLen { marker: m, buf: [0; 2], have: 0 };
                        }
                    }
                }
                JpegState::NeedLen { marker, buf, have } => {
                    let need = 2 - *have as usize;
                    let take = need.min(input.len());
                    buf[*have as usize..*have as usize + take].copy_from_slice(&input[..take]);
                    *have += take as u8;
                    input = &input[take..];
                    if *have as usize == 2 {
                        let marker = *marker;
                        let len = u16::from_be_bytes(*buf) as u32;
                        // len includes the 2 length bytes themselves.
                        let payload_len = len.saturating_sub(2);
                        if marker == 0xDA {
                            // SOS: the "length" here covers only the scan
                            // header (component selectors etc); pass that
                            // header through, then everything else is raw
                            // entropy-coded data.
                            emit(&[marker]);
                            emit(&buf[..]);
                            *self = if payload_len == 0 {
                                JpegState::RawTail
                            } else {
                                JpegState::CopySosHeader { remaining: payload_len }
                            };
                        } else if marker == 0xE1 {
                            emit(&[marker]);
                            emit(&buf[..]);
                            *self = JpegState::PeekApp1 {
                                seg_remaining: payload_len,
                                sig: [0; 6],
                                have: 0,
                            };
                        } else {
                            emit(&[marker]);
                            emit(&buf[..]);
                            *self = JpegState::CopySegment { remaining: payload_len };
                        }
                    }
                }
                JpegState::PeekApp1 { seg_remaining, sig, have } => {
                    let need = (6usize.saturating_sub(*have as usize)).min(*seg_remaining as usize);
                    let take = need.min(input.len());
                    sig[*have as usize..*have as usize + take].copy_from_slice(&input[..take]);
                    *have += take as u8;
                    *seg_remaining -= take as u32;
                    input = &input[take..];

                    let sig_complete = *have as usize == 6;
                    let segment_too_short_for_sig = *seg_remaining == 0 && *have < 6;

                    if sig_complete || segment_too_short_for_sig {
                        if sig_complete && sig[..] == EXIF_SIG {
                            // Confirmed EXIF: drop what we peeked plus
                            // whatever payload remains.
                            *self = JpegState::SkipSegment { remaining: *seg_remaining };
                        } else {
                            // Not EXIF (e.g. XMP, or a short/odd APP1):
                            // flush the peeked bytes and copy the rest.
                            let peeked = sig[..*have as usize].to_vec();
                            emit(&peeked);
                            *self = JpegState::CopySegment { remaining: *seg_remaining };
                        }
                    }
                }
                JpegState::CopySegment { remaining } => {
                    let take = (*remaining as usize).min(input.len());
                    if take > 0 {
                        emit(&input[..take]);
                    }
                    *remaining -= take as u32;
                    input = &input[take..];
                    if *remaining == 0 {
                        *self = JpegState::Scanning;
                    }
                }
                JpegState::CopySosHeader { remaining } => {
                    let take = (*remaining as usize).min(input.len());
                    if take > 0 {
                        emit(&input[..take]);
                    }
                    *remaining -= take as u32;
                    input = &input[take..];
                    if *remaining == 0 {
                        *self = JpegState::RawTail;
                    }
                }
                JpegState::SkipSegment { remaining } => {
                    let take = (*remaining as usize).min(input.len());
                    *remaining -= take as u32;
                    input = &input[take..];
                    if *remaining == 0 {
                        *self = JpegState::Scanning;
                    }
                }
                JpegState::RawTail => {
                    emit(input);
                    input = &[];
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------

enum PngState {
    /// Reading the 8-byte chunk header (4-byte length + 4-byte type).
    NeedHeader { buf: [u8; 8], have: u8 },
    /// Copying a chunk (payload + 4-byte CRC) through unchanged.
    CopyChunk { remaining: u32 },
    /// Dropping an eXIf chunk (payload + 4-byte CRC).
    SkipChunk { remaining: u32 },
}

impl PngState {
    fn new() -> Self {
        PngState::NeedHeader { buf: [0; 8], have: 0 }
    }

    fn push(&mut self, mut input: &[u8], emit: &mut dyn FnMut(&[u8])) {
        while !input.is_empty() {
            match self {
                PngState::NeedHeader { buf, have } => {
                    let need = 8 - *have as usize;
                    let take = need.min(input.len());
                    buf[*have as usize..*have as usize + take].copy_from_slice(&input[..take]);
                    *have += take as u8;
                    input = &input[take..];
                    if *have as usize == 8 {
                        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                        let is_exif = buf[4..8] == PNG_EXIF_CHUNK;
                        let remaining = len.saturating_add(4); // payload + CRC
                        if is_exif {
                            *self = PngState::SkipChunk { remaining };
                        } else {
                            let header = *buf;
                            emit(&header);
                            *self = PngState::CopyChunk { remaining };
                        }
                    }
                }
                PngState::CopyChunk { remaining } => {
                    let take = (*remaining as usize).min(input.len());
                    if take > 0 {
                        emit(&input[..take]);
                    }
                    *remaining -= take as u32;
                    input = &input[take..];
                    if *remaining == 0 {
                        *self = PngState::NeedHeader { buf: [0; 8], have: 0 };
                    }
                }
                PngState::SkipChunk { remaining } => {
                    let take = (*remaining as usize).min(input.len());
                    *remaining -= take as u32;
                    input = &input[take..];
                    if *remaining == 0 {
                        *self = PngState::NeedHeader { buf: [0; 8], have: 0 };
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a whole input through the stripper split into chunks of size
    /// `chunk_size`, to make sure every internal boundary case (marker
    /// split across calls, signature split, length field split, etc.) is
    /// exercised, then return the concatenated output.
    fn strip_in_chunks(input: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut s = Stripper::new();
        let mut out = Vec::new();
        for chunk in input.chunks(chunk_size.max(1)) {
            s.push(chunk, &mut |b: &[u8]| out.extend_from_slice(b));
        }
        s.finish(&mut |b: &[u8]| out.extend_from_slice(b));
        out
    }

    fn app1_exif_segment(payload_extra: &[u8]) -> Vec<u8> {
        let mut seg = vec![0xFF, 0xE1];
        let len = 2 + EXIF_SIG.len() + payload_extra.len();
        seg.extend_from_slice(&(len as u16).to_be_bytes());
        seg.extend_from_slice(&EXIF_SIG);
        seg.extend_from_slice(payload_extra);
        seg
    }

    fn app0_jfif_segment() -> Vec<u8> {
        // Minimal, not realistic byte-for-byte, but structurally valid.
        let payload = [0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let mut seg = vec![0xFF, 0xE0];
        seg.extend_from_slice(&((2 + payload.len()) as u16).to_be_bytes());
        seg.extend_from_slice(&payload);
        seg
    }

    fn build_minimal_jpeg_with_exif() -> Vec<u8> {
        let mut buf = vec![0xFF, 0xD8]; // SOI
        buf.extend(app0_jfif_segment());
        buf.extend(app1_exif_segment(&vec![0xAB; 200])); // fake exif payload
        // SOS header (fake, short) + entropy data + EOI
        buf.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x03, 0x01, 0x00, 0x02, 0x11, 0x03]);
        buf.extend_from_slice(&[0x11, 0x22, 0xFF, 0x00, 0x33, 0x44]); // entropy data incl. a stuffed 0xFF00
        buf.extend_from_slice(&[0xFF, 0xD9]); // EOI
        buf
    }

    #[test]
    fn strips_exif_app1_leaves_rest_intact() {
        let input = build_minimal_jpeg_with_exif();
        for chunk_size in [1, 2, 3, 7, 16, 64, 4096, usize::MAX] {
            let out = strip_in_chunks(&input, chunk_size);
            assert!(!contains(&out, &EXIF_SIG), "chunk_size={chunk_size}: EXIF signature leaked into output");
            assert_eq!(&out[..2], &[0xFF, 0xD8], "chunk_size={chunk_size}: SOI missing");
            assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9], "chunk_size={chunk_size}: EOI missing");
            // JFIF APP0 segment must survive untouched.
            assert!(contains(&out, &[0x4A, 0x46, 0x49, 0x46, 0x00]), "chunk_size={chunk_size}: JFIF header lost");
            // Entropy data (including the 0xFF00 stuffed byte) must survive untouched.
            assert!(contains(&out, &[0x11, 0x22, 0xFF, 0x00, 0x33, 0x44]), "chunk_size={chunk_size}: scan data corrupted");
        }
    }

    #[test]
    fn non_exif_app1_passes_through() {
        // APP1 that is XMP, not EXIF - must NOT be dropped.
        let xmp_payload = b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>";
        let mut seg = vec![0xFF, 0xE1];
        seg.extend_from_slice(&((2 + xmp_payload.len()) as u16).to_be_bytes());
        seg.extend_from_slice(xmp_payload);

        let mut input = vec![0xFF, 0xD8];
        input.extend(seg.clone());
        input.extend_from_slice(&[0xFF, 0xD9]);

        let out = strip_in_chunks(&input, 5);
        assert!(contains(&out, b"xmpmeta"), "XMP APP1 must be preserved");
        assert_eq!(out, input, "non-EXIF APP1 must pass through byte-for-byte");
    }

    #[test]
    fn strips_png_exif_chunk() {
        fn chunk(ty: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut c = Vec::new();
            c.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            c.extend_from_slice(ty);
            c.extend_from_slice(payload);
            c.extend_from_slice(&[0, 0, 0, 0]); // fake CRC, we don't validate it
            c
        }
        let mut input = PNG_SIG.to_vec();
        input.extend(chunk(b"IHDR", &[0u8; 13]));
        input.extend(chunk(b"eXIf", &[0xAB; 500]));
        input.extend(chunk(b"IDAT", &[1, 2, 3, 4]));
        input.extend(chunk(b"IEND", &[]));

        for chunk_size in [1, 3, 9, 64, usize::MAX] {
            let out = strip_in_chunks(&input, chunk_size);
            assert!(!contains(&out, b"eXIf"), "chunk_size={chunk_size}: eXIf chunk leaked");
            assert!(contains(&out, b"IHDR"), "chunk_size={chunk_size}: IHDR lost");
            assert!(contains(&out, b"IDAT"), "chunk_size={chunk_size}: IDAT lost");
            assert!(contains(&out, b"IEND"), "chunk_size={chunk_size}: IEND lost");
        }
    }

    #[test]
    fn unknown_format_passes_through_untouched() {
        let input = b"not an image, just some bytes Exif\0\0 that happen to contain the word".to_vec();
        let out = strip_in_chunks(&input, 3);
        assert_eq!(out, input);
    }

    #[test]
    fn tiny_input_shorter_than_signature_passes_through() {
        for input in [&b""[..], &b"\xFF"[..], &b"\xFF\xD8"[..], &b"\x89PNG"[..]] {
            let out = strip_in_chunks(input, 1);
            // For a bare SOI with nothing after, JPEG state machine just
            // ends up idle - nothing lost, nothing corrupted.
            assert!(out.len() <= input.len() + 2);
        }
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len().max(1)).any(|w| w == needle)
    }

    /// Tiny xorshift PRNG so the fuzz test below is deterministic and
    /// dependency-free.
    fn xorshift(state: &mut u32) -> u32 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        *state
    }

    #[test]
    fn fuzzed_random_chunk_boundaries_never_panic_and_strip_correctly() {
        let jpeg = build_minimal_jpeg_with_exif();
        let mut seed = 0xC0FFEEu32;
        for _ in 0..200 {
            let mut out = Vec::new();
            let mut s = Stripper::new();
            let mut i = 0;
            while i < jpeg.len() {
                let take = 1 + (xorshift(&mut seed) as usize % 7);
                let end = (i + take).min(jpeg.len());
                s.push(&jpeg[i..end], &mut |b: &[u8]| out.extend_from_slice(b));
                i = end;
            }
            s.finish(&mut |b: &[u8]| out.extend_from_slice(b));
            assert!(!contains(&out, &EXIF_SIG));
            assert_eq!(&out[..2], &[0xFF, 0xD8]);
            assert_eq!(&out[out.len() - 2..], &[0xFF, 0xD9]);
        }
    }
}

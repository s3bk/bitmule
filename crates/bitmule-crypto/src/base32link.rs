//! The link format of 2026-11: uppercase base32 with the link's kind in the
//! two bits behind the key.
//!
//! This replaces the base64url `share_key || signature || checksum` link as
//! what the tree *emits*. The old base64url forms are still parsed (see
//! `ShareLink::from_b64_url`) so links already in the wild keep working; this
//! module only knows the new form.
//!
//! Same payload, three shapes, key size and signature length picked by the
//! character count:
//!
//! ```text
//! 26 chars = 130 bits: [          ][ 128-bit key ][ kind ]
//! 52 chars = 260 bits: [ 2 zero   ][ 256-bit key ][ kind ]
//! 78 chars = 390 bits: [ 4 zero   ][ 256-bit key ][ 128-bit sig ][ kind ]
//! 103 chars = 515 bits:[ 1 zero   ][ 256-bit key ][ 256-bit sig ][ kind ]
//! ```
//!
//! The spare bits are zero and the decoder insists on that, so every link has
//! exactly one spelling: a link with one character changed fails as "not
//! canonical" instead of quietly naming a different key. (That replaces the
//! 24-bit checksum the base64url form carried; five spare bits in every shape
//! are not a checksum, they are a shape test.)
//!
//! Why base32 at all: a QR code packs this alphabet in alphanumeric mode,
//! 5.5 bits a character against byte mode's 8, and its charset is uppercase
//! only — base64url's mixed case forces byte mode. The 90-character base64url
//! link was 484 bits; the 103-character committed form below is 404.

use anyhow::{bail, Result};

/// RFC 4648 base32, unpadded, uppercase.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// What a link opens. Zero is not a kind: a payload with zero type bits was
/// not produced by this format (there is no "ask the server what this is").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Both peers online, nothing stored: a peer-to-peer session.
    Live = 1,
    /// The server holds ciphertext under this key.
    Hosted = 2,
    /// An upload invite: a 128-bit key, and it grants upload.
    Invite = 3,
}

impl LinkKind {
    pub fn as_bits(self) -> u32 {
        self as u32
    }

    pub fn from_bits(bits: u32) -> Option<LinkKind> {
        match bits & 3 {
            1 => Some(LinkKind::Live),
            2 => Some(LinkKind::Hosted),
            3 => Some(LinkKind::Invite),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            LinkKind::Live => "live",
            LinkKind::Hosted => "hosted",
            LinkKind::Invite => "invite",
        }
    }
}

/// One payload length the format defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub kinds: &'static [LinkKind],
    pub key_bytes: usize,
    pub sig_bytes: usize,
    pub chars: usize,
}

const fn chars_for(bytes: usize) -> usize {
    // ceil((8·bytes + 2) / 5): the payload plus the two kind bits, in base32.
    (bytes * 8 + 2 + 4) / 5
}

const fn shape(kinds: &'static [LinkKind], key: usize, sig: usize) -> Shape {
    Shape { kinds, key_bytes: key, sig_bytes: sig, chars: chars_for(key + sig) }
}

const INVITE_ONLY: &[LinkKind] = &[LinkKind::Invite];
const SHARE_KINDS: &[LinkKind] = &[LinkKind::Live, LinkKind::Hosted];

pub const SHAPES: [Shape; 4] = [
    shape(INVITE_ONLY, 16, 0),
    shape(SHARE_KINDS, 32, 0),
    shape(SHARE_KINDS, 32, 16),
    shape(SHARE_KINDS, 32, 32),
];

/// What a decoded link carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub kind: LinkKind,
    /// 16 bytes for an invite, 32 otherwise.
    pub key: Vec<u8>,
    /// The data commitment, when the link carries one: 16 or 32 bytes.
    pub signature: Option<Vec<u8>>,
    /// Characters the link took, i.e. which of `SHAPES` it was.
    pub chars: usize,
}

fn shape_for_len(chars: usize) -> Option<Shape> {
    SHAPES.iter().copied().find(|s| s.chars == chars)
}

fn shape_for(kind: LinkKind, key: usize, sig: usize) -> Option<Shape> {
    SHAPES
        .iter()
        .copied()
        .find(|s| s.kinds.contains(&kind) && s.key_bytes == key && s.sig_bytes == sig)
}

/// Encode `key` (and `signature`, if the shape for this pair has one).
pub fn encode(kind: LinkKind, key: &[u8], signature: Option<&[u8]>) -> Result<String> {
    let sig_len = signature.map(|s| s.len()).unwrap_or(0);
    let shape = match shape_for(kind, key.len(), sig_len) {
        Some(shape) => shape,
        None => {
            let lens: Vec<usize> = SHAPES
                .iter()
                .filter(|s| s.kinds.contains(&kind))
                .map(|s| s.key_bytes)
                .collect();
            let sig = if sig_len == 0 { String::new() } else { format!(" with a {sig_len}-byte signature") };
            bail!("a {} link has key lengths {lens:?}, not {}{sig}", kind.name(), key.len());
        }
    };
    let payload = key.len() + sig_len;
    let pad = shape.chars * 5 - (payload * 8 + 2);
    let mut w = BitWriter::default();
    w.put(0, pad as u32);
    for b in key {
        w.put(*b as u32, 8);
    }
    if let Some(sig) = signature {
        for b in sig {
            w.put(*b as u32, 8);
        }
    }
    w.put(kind.as_bits(), 2);
    let out = w.finish();
    debug_assert_eq!(out.chars().count(), shape.chars);
    Ok(out)
}

/// Decode a fragment: the length picks the shape, the two kind bits say what
/// the link opens, and the two must agree. Case is folded and wrapping noise
/// ignored, so a link that was uppercased, lowercased or broken across lines
/// still opens.
pub fn decode(s: &str) -> Result<Link> {
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    let shape = match shape_for_len(n) {
        Some(shape) => shape,
        None => {
            let mut lens: Vec<usize> = SHAPES.iter().map(|s| s.chars).collect();
            lens.sort_unstable();
            bail!(
                "a link is {lens:?} characters, not {n} — it was probably cut short \
                 or has stray characters; copy the whole link"
            );
        }
    };
    let payload = shape.key_bytes + shape.sig_bytes;
    let mut r = BitReader::new(&cleaned)?;
    let pad = shape.chars * 5 - (payload * 8 + 2);
    if r.get(pad as u32) != 0 {
        bail!("the link has its spare bits set — it was not produced by this format");
    }
    let mut key = Vec::with_capacity(shape.key_bytes);
    for _ in 0..shape.key_bytes {
        key.push(r.get(8) as u8);
    }
    let mut signature = None;
    if shape.sig_bytes > 0 {
        let mut sig = Vec::with_capacity(shape.sig_bytes);
        for _ in 0..shape.sig_bytes {
            sig.push(r.get(8) as u8);
        }
        signature = Some(sig);
    }
    let kind = LinkKind::from_bits(r.get(2) as u32)
        .ok_or_else(|| anyhow::anyhow!("the link carries no kind — not produced by this format"))?;
    if !shape.kinds.contains(&kind) {
        let allowed: Vec<&str> = shape.kinds.iter().map(|k| k.name()).collect();
        bail!(
            "the kind bits say {}, but a {}-character link is {}",
            kind.name(),
            shape.chars,
            allowed.join(" or ")
        );
    }
    Ok(Link { kind, key, signature, chars: shape.chars })
}

/// Whitespace and zero-width characters, which chat clients, terminal wrapping
/// and copy buttons add, plus a leading `#` from a pasted fragment.
fn clean(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| {
            !c.is_whitespace()
                && !matches!(*c, '\u{200b}'..='\u{200d}' | '\u{feff}' | '\u{00ad}' | '\u{2060}')
        })
        .collect();
    t.trim_start_matches('#').to_string()
}

fn value_of(c: char) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    ALPHABET.iter().position(|a| *a as char == c).map(|p| p as u8)
}

#[derive(Default)]
struct BitWriter {
    acc: u32,
    have: u32,
    out: String,
}

impl BitWriter {
    fn put(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        self.acc = (self.acc << n) | (v & ((1u32 << n) - 1));
        self.have += n;
        while self.have >= 5 {
            self.have -= 5;
            self.out.push(ALPHABET[((self.acc >> self.have) & 31) as usize] as char);
        }
        self.acc &= (1u32 << self.have) - 1;
    }

    fn finish(mut self) -> String {
        if self.have > 0 {
            let n = 5 - self.have;
            self.put(0, n);
        }
        self.out
    }
}

struct BitReader<'a> {
    chars: &'a [u8],
    at: usize,
    acc: u64,
    have: u32,
}

impl<'a> BitReader<'a> {
    fn new(s: &'a str) -> Result<Self> {
        for c in s.chars() {
            if value_of(c).is_none() {
                bail!("{c:?} is not a link character; the alphabet is A-Z and 2-7");
            }
        }
        Ok(Self { chars: s.as_bytes(), at: 0, acc: 0, have: 0 })
    }

    fn get(&mut self, mut n: u32) -> u64 {
        let mut out = 0u64;
        while n > 0 {
            if self.have == 0 {
                let v = value_of(self.chars[self.at] as char).unwrap_or(0) as u64;
                self.at += 1;
                self.acc = v;
                self.have = 5;
            }
            let take = n.min(self.have);
            self.have -= take;
            out = (out << take) | ((self.acc >> self.have) & ((1u64 << take) - 1));
            n -= take;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn every_shape_roundtrips() {
        for shape in SHAPES {
            for kind in shape.kinds {
                let k = key(shape.key_bytes, 0x11);
                let sig = if shape.sig_bytes > 0 { Some(key(shape.sig_bytes, 0x80)) } else { None };
                let s = encode(*kind, &k, sig.as_deref()).unwrap();
                assert_eq!(s.chars().count(), shape.chars);
                let back = decode(&s).unwrap();
                assert_eq!(back.kind, *kind);
                assert_eq!(back.key, k);
                assert_eq!(back.signature, sig);
            }
        }
    }

    #[test]
    fn zero_kind_bits_are_refused() {
        // An all-A payload of share length: kind bits are zero.
        assert!(decode(&"A".repeat(52)).is_err());
    }

    #[test]
    fn kind_must_fit_the_length() {
        // 26 characters cannot be a live session.
        let inv = encode(LinkKind::Invite, &key(16, 1), None).unwrap();
        let mut bits = BitReader::new(&inv).unwrap();
        let _ = bits.get(128);
        let _ = bits.get(2);
        assert_eq!(inv.chars().count(), 26);
        assert!(matches!(decode(&inv).unwrap().kind, LinkKind::Invite));
        // Same payload, one kind step changed by hand, must not be a share.
        assert!(decode(&inv.to_lowercase()).is_ok());
    }

    #[test]
    fn agrees_with_the_mul_li_implementation() {
        // Vectors pinned by bitmule-proto's link.rs tests (the mul.li side):
        // all-zero payloads land on the last character, which is then the
        // whole kind. These pin byte order and bit packing across the two
        // implementations.
        assert_eq!(encode(LinkKind::Invite, &[0u8; 16], None).unwrap(), "A".repeat(25) + "D");
        assert_eq!(encode(LinkKind::Hosted, &[0u8; 32], None).unwrap(), "A".repeat(51) + "C");
        assert_eq!(
            encode(LinkKind::Hosted, &[0u8; 32], Some(&[0u8; 16])).unwrap(),
            "A".repeat(77) + "C"
        );
        assert_eq!(
            encode(LinkKind::Hosted, &[0u8; 32], Some(&[0u8; 32])).unwrap(),
            "A".repeat(102) + "C"
        );
    }

    #[test]
    fn short_and_noisy_links_are_diagnosed() {
        let s = encode(LinkKind::Hosted, &key(32, 7), Some(&key(16, 9))).unwrap();
        assert_eq!(s.chars().count(), 78);
        let cut = &s[..60];
        assert!(decode(cut).unwrap_err().to_string().contains("characters"));
        let noisy = format!("  #{}\n", s.to_lowercase());
        assert_eq!(decode(&noisy).unwrap().key, key(32, 7));
        assert!(!s.contains('8') && !s.contains('9')); // alphabet: A-Z, 2-7
    }

    #[test]
    fn one_changed_character_does_not_decode_to_the_same_key() {
        let s = encode(LinkKind::Live, &key(32, 3), None).unwrap();
        let mut chars: Vec<char> = s.chars().collect();
        chars[7] = if chars[7] == 'A' { 'B' } else { 'A' };
        let changed: String = chars.into_iter().collect();
        match decode(&changed) {
            Ok(link) => assert_ne!(link.key, key(32, 3)),
            Err(_) => {}
        }
    }
}

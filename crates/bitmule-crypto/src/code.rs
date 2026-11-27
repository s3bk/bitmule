//! The 32-byte code (owner, 2026-11-24): one size for every kind of link, and
//! since 2026-11-27 one spelling of it — 48 characters of base 42,
//! `MUL.LI#…`, on screen and on paper alike (owner: "43char MUL.li#code
//! everywhere").
//!
//! A link fragment is immutable the moment it is sent, so it can hold the
//! kind and the key material and nothing else — no version byte, no checksum,
//! no signature. The key is all 256 bits; the kind sits above the key instead
//! of taking bits from it (owner, 2026-11-24: "the key stays 256 bits"):
//!
//! ```text
//! value = kind · 2²⁵⁶ + key      258 bits at most, 48 base-42 digits
//! ```
//!
//! The alphabet is 42 of the 43 symbols QR packs in alphanumeric mode — the
//! uppercase alphanumeric charset minus `space` (does not survive a fragment
//! or an auto-link), minus `%` (opens a percent-encoded escape in every
//! RFC 3986 parser) and minus `+` (a form-urlencoded parser turns it into a
//! space). 42⁴⁸ = 2^258.83 against the 2^258 needed; 41⁴⁸ = 2^257.16 is short,
//! so 42 is the smallest alphabet that writes a code in 48 digits. That is the
//! point of it: the 0.83 bits left over are not payload. A decoder refuses a
//! value ≥ 2²⁵⁸, so a random 48-digit string is refused more often than not
//! instead of naming a code — and past that there is no margin at all.
//!
//! The code is uppercase *by construction* — QR's alphanumeric mode has no
//! lower case — and a decoder folds case before converting, so
//! `HTTPS://MUL.LI#…` scans to the URL it was drawn as. There is no base64
//! spelling any more: the base64url text forms are read, never written.
//!
//! What this module still reads, so links already pasted or printed keep
//! working:
//!
//! * 48 characters — the code. A value below 2²⁵⁶ is the printed code of
//!   2026-11-24, when the kind sat in the key's top three bits and the key was
//!   253 bits; at or above it, `kind · 2²⁵⁶ + key`.
//! * 44 characters — the base64url text code of 2026-11-24: 33 bytes, kind in
//!   the top three bits of byte 0, spare bits zero.
//! * 43 characters — the base64url text code of before it: 32 bytes, the same
//!   kind layout.
//!
//! Length picks the decoder and a value out of range is refused rather than
//! tried against another layout, so no spelling is ambiguous. Nothing in this
//! tree emits the base64url forms any more.
//!
//! Why the kind is in the code at all rather than in the path: a live session
//! and a hosted download carry the same key, so only the code can tell them
//! apart, and the owner's ruling (2026-11-10) is that the link encodes its
//! type. A code whose kind bits are 0 or 4–7 was not produced by this format
//! and is refused: there is no "ask the server what this is".

use anyhow::{bail, Result};

/// What a code opens. The values are the three kind bits in the code, so they
/// are part of the wire format and cannot be renumbered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Both peers online, nothing stored.
    Live = 1,
    /// The server holds ciphertext under this key.
    Hosted = 2,
    /// An upload invite: the key is a capability to create something.
    Invite = 3,
}

impl Kind {
    pub fn as_bits(self) -> u8 {
        self as u8
    }

    pub fn from_bits(bits: u8) -> Option<Kind> {
        match bits {
            1 => Some(Kind::Live),
            2 => Some(Kind::Hosted),
            3 => Some(Kind::Invite),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Live => "live",
            Kind::Hosted => "hosted",
            Kind::Invite => "invite",
        }
    }
}

/// A code: 48 characters of base 42, uppercase. One spelling, on screen and
/// on paper (owner, 2026-11-27).
pub const CODE_CHARS: usize = 48;
/// The printed code, which is the code: the same 48 characters.
pub const PRINT_CHARS: usize = CODE_CHARS;
/// The text code of 2026-11-24: 44 base64url characters, 33 bytes. Read,
/// never written.
pub const LEGACY_TEXT_CHARS: usize = 44;
/// The text code of before that: 43 base64url characters, 32 bytes, the kind
/// in the top three bits of byte 0. Read, never written.
pub const LEGACY_CODE_CHARS: usize = 43;
/// The base-42 alphabet: QR alphanumeric without space, `%` and `+`, in ASCII
/// order within each run so a human can find a digit or a letter.
pub const PRINT_ALPHABET: &[u8; 42] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*-./:";
/// The base the digits are written in: the size of [`PRINT_ALPHABET`]. 41 is
/// too few — 41⁴⁸ = 2^257.16 does not hold a 258-bit value in 48 digits.
pub const CODE_BASE: u64 = PRINT_ALPHABET.len() as u64;

/// A decoded code: what it opens, and the whole 256-bit key it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    pub kind: Kind,
    pub key: [u8; 32],
}

/// Encode a code — the base-42 spelling, [`encode_print`], because a code has
/// one spelling now: what is pasted is what is printed.
pub fn encode(kind: Kind, key: &[u8; 32]) -> Result<String> {
    encode_print(kind, key)
}

/// Read a base64url text code: 44 characters (33 bytes, kind in the top three
/// bits of byte 0), or the 43-character form of before 2026-11-24 (32 bytes,
/// the same layout). Nothing emits either any more.
pub fn decode_legacy_text(s: &str) -> Result<Code> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n == LEGACY_CODE_CHARS {
        return decode_text_legacy(&cleaned);
    }
    if n != LEGACY_TEXT_CHARS {
        bail!(
            "a code is {CODE_CHARS} characters; {n} is neither that nor one of the \
             base64url text codes of before 2026-11-27 ({LEGACY_TEXT_CHARS} or \
             {LEGACY_CODE_CHARS}) — it was probably cut short or has stray \
             characters; copy the whole code"
        );
    }
    if !cleaned.is_ascii() {
        bail!("a code is ASCII; it contains characters that are not");
    }
    let raw = URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|_| anyhow::anyhow!("code is not valid base64url; the alphabet is A-Z a-z 0-9 - _"))?;
    let bytes: [u8; 33] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("code decodes to {} bytes, expected 33", raw.len()))?;
    if bytes[0] & 0x1f != 0 {
        bail!("the code has its spare bits set — it was not produced by this format");
    }
    let bits = bytes[0] >> 5;
    let kind = Kind::from_bits(bits).ok_or_else(|| {
        anyhow::anyhow!(
            "the code's kind bits are {bits:#05b}, which no kind uses — it was not \
             produced by this format"
        )
    })?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[1..]);
    Ok(Code { kind, key })
}

/// The 43-character form: 32 bytes, kind in the top three bits of byte 0,
/// 253 bits of key behind it. Read only.
fn decode_text_legacy(cleaned: &str) -> Result<Code> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    if !cleaned.is_ascii() {
        bail!("a code is ASCII; it contains characters that are not");
    }
    let raw = URL_SAFE_NO_PAD.decode(cleaned.as_bytes()).map_err(|_| {
        anyhow::anyhow!(
            "{LEGACY_CODE_CHARS} characters is the text form of before 2026-11-24, \
             and this is not one of those — a cut code of {CODE_CHARS} characters \
             ends up this length; copy the whole code"
        )
    })?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("code decodes to {} bytes, expected 32", raw.len()))?;
    from_bytes(bytes)
}

/// The earlier layout: kind in the top three bits of byte 0, key masked to
/// 253 bits.
fn from_bytes(bytes: [u8; 32]) -> Result<Code> {
    let bits = bytes[0] >> 5;
    let kind = Kind::from_bits(bits).ok_or_else(|| {
        anyhow::anyhow!(
            "the code's kind bits are {bits:#05b}, which no kind uses — it was not \
             produced by this format"
        )
    })?;
    let mut key = bytes;
    key[0] &= 0x1f;
    Ok(Code { kind, key })
}

/// The code itself: 48 base-42 characters, `HTTPS://MUL.LI#…`-friendly and
/// therefore uppercase. What [`encode`] returns, and what a symbol carries.
///
/// The printed value is `kind · 2²⁵⁶ + key`, so the kind sits above the whole
/// key instead of in its top bits. 258 bits against the 2^258.83 of 48 digits:
/// the symbol's length does not change while the key keeps all 256 bits.
pub fn encode_print(kind: Kind, key: &[u8; 32]) -> Result<String> {
    let mut limbs = [0u64; 5];
    limbs[4] = kind.as_bits() as u64;
    limbs[..4].copy_from_slice(&to_limbs(key));
    let mut digits = [0u8; PRINT_CHARS];
    for i in (0..PRINT_CHARS).rev() {
        digits[i] = div_rem_small(&mut limbs, CODE_BASE) as u8;
    }
    debug_assert!(limbs == [0; 5], "258 bits must fit in 48 base-42 digits");
    Ok(digits.iter().map(|d| PRINT_ALPHABET[*d as usize] as char).collect())
}

/// Decode a code. Case is folded (the code is uppercase by construction), and
/// the value is checked against the range the format can produce, so exactly
/// one 48-digit spelling decodes to each code.
///
/// A value below 2²⁵⁶ is a code of the earlier layout (kind in the key's top
/// three bits); at or above it, `kind · 2²⁵⁶ + key`. The two ranges cannot
/// overlap, so an old sticker still reads without a flag.
pub fn decode_print(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n != PRINT_CHARS {
        bail!(
            "a code is {CODE_CHARS} characters, not {n} — it was probably cut short \
             or has stray characters; copy the whole code"
        );
    }
    let mut limbs = [0u64; 5];
    for c in cleaned.chars() {
        let up = c.to_ascii_uppercase();
        let digit = PRINT_ALPHABET
            .iter()
            .position(|a| *a as char == up)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{c:?} is not a code character; the alphabet is 0-9 A-Z and $*-./:"
                )
            })? as u8;
        // 42^48 < 2^259, so five limbs never overflow here.
        mul_add_small(&mut limbs, CODE_BASE, digit as u64);
    }
    if limbs[4] > 3 {
        bail!(
            "the code is worth 2^258 or more — it was not produced by this format"
        );
    }
    let low = [limbs[0], limbs[1], limbs[2], limbs[3]];
    if limbs[4] == 0 {
        // The earlier layout, which never reaches 2^256.
        return from_bytes(from_limbs(&low));
    }
    let bits = limbs[4] as u8;
    let kind = Kind::from_bits(bits).ok_or_else(|| {
        anyhow::anyhow!(
            "the code's kind bits are {bits:#05b}, which no kind uses — it was not \
             produced by this format"
        )
    })?;
    Ok(Code { kind, key: from_limbs(&low) })
}

/// Decode a code in any spelling this tree has emitted. Length picks it: 48 is
/// the code, 44 and 43 are the base64url text codes of before 2026-11-27.
pub fn decode(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    match cleaned.chars().count() {
        CODE_CHARS => decode_print(&cleaned),
        LEGACY_TEXT_CHARS | LEGACY_CODE_CHARS => decode_legacy_text(&cleaned),
        n => bail!(
            "a code is {CODE_CHARS} characters, not {n} — it was probably cut short \
             or has stray characters; copy the whole code"
        ),
    }
}

/// `https://host#<code>` — the same 48 characters a symbol carries.
pub fn url(host: &str, kind: Kind, key: &[u8; 32]) -> Result<String> {
    Ok(format!("https://{host}#{}", encode(kind, key)?))
}

/// `HTTPS://HOST#<code>` — what goes in a QR symbol. Scheme and host are
/// case-insensitive, the code is uppercase by construction, and the whole
/// thing is in QR's alphanumeric mode.
pub fn print_url(host: &str, kind: Kind, key: &[u8; 32]) -> Result<String> {
    Ok(format!(
        "HTTPS://{}#{}",
        host.to_ascii_uppercase(),
        encode_print(kind, key)?
    ))
}

/// What a client puts in the symbol for a link it already holds:
/// `https://host/#<code>` becomes `HTTPS://HOST#<code>`, the kind
/// carried over from the link.
///
/// This is the one place a surface turns a link into symbol content, so every
/// client draws the same symbol: 63 characters in three QR segments — host 14
/// alphanumeric, `#` one byte, code 48 alphanumeric — 391 of the 440 bits a
/// version 3 symbol at ECC L holds. A base64url spelling of the same key was
/// byte mode throughout (59 bytes, 484 bits) and needed a version 4 symbol.
///
/// Anything that is not a code comes back unchanged, so a caller can pass its
/// URL through without checking first. Already-printed input comes back as it
/// is (the printed form is canonical).
pub fn print_url_for(url: &str) -> String {
    let Some((head, frag)) = url.split_once('#') else { return url.to_string() };
    let (kind, key) = match decode(frag) {
        Ok(c) => (c.kind, c.key),
        // The spellings from before the code: a base32 or long base64url
        // link is a live share and prints as one.
        Err(_) => match crate::ShareLink::from_link(frag) {
            Ok(l) => (Kind::Live, l.share_key.0),
            Err(_) => return url.to_string(),
        },
    };
    let host = head
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("HTTPS://")
        .trim_start_matches("HTTP://")
        .trim_end_matches('/');
    print_url(host, kind, &key).unwrap_or_else(|_| url.to_string())
}

/// Whitespace and zero-width characters, which chat clients, terminal
/// wrapping and copy buttons add, plus a leading `#` from a pasted fragment.
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

fn to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[32 - 8 * (i + 1)..32 - 8 * i]);
        *limb = u64::from_be_bytes(word);
    }
    // `limbs` is little-endian: limbs[0] is the least significant word.
    limbs
}

fn from_limbs(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

/// `limbs /= d`, returning the remainder. Limbs are little-endian.
fn div_rem_small<const N: usize>(limbs: &mut [u64; N], d: u64) -> u64 {
    let mut rem: u128 = 0;
    for i in (0..N).rev() {
        let cur = (rem << 64) | limbs[i] as u128;
        limbs[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    rem as u64
}

/// `limbs = limbs * m + a`. Returns true on overflow past the top limb.
fn mul_add_small<const N: usize>(limbs: &mut [u64; N], m: u64, a: u64) -> bool {
    let mut carry: u128 = a as u128;
    for limb in limbs.iter_mut() {
        let cur = *limb as u128 * m as u128 + carry;
        *limb = cur as u64;
        carry = cur >> 64;
    }
    carry != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full-range key: the code carries all 256 bits, so nothing is masked.
    fn key(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        b
    }

    /// Base 42 and no `+`: the owner's ruling of 2026-11-27 (43 is what QR
    /// offers, 42 is the least that holds a code, and `+` is the one symbol a
    /// form-urlencoded parser rewrites to a space).
    #[test]
    fn the_alphabet_is_42_without_plus() {
        assert_eq!(PRINT_ALPHABET.len(), 42);
        assert!(!PRINT_ALPHABET.contains(&b'+'));
        assert_eq!(CODE_BASE, 42);
        // A digit string with `+` in it is not a code (the interim base-43
        // alphabet had one, and nothing outside this tree ever emitted it).
        let mut s: String = "0".repeat(23);
        s.push('+');
        s.push_str(&"0".repeat(24));
        assert_eq!(s.chars().count(), PRINT_CHARS);
        let err = decode_print(&s).expect_err("+ is not a code character");
        assert!(err.to_string().contains("not a code character"), "{err}");
    }

    /// One spelling since 2026-11-27: what is pasted is what is printed.
    #[test]
    fn the_code_is_48_chars_and_roundtrips() {
        for k in Kind::iter() {
            for seed in 0..8u8 {
                let k0 = key(seed);
                let s = encode(k, &k0).unwrap();
                assert_eq!(s.chars().count(), CODE_CHARS);
                assert_eq!(s, encode_print(k, &k0).unwrap(), "one spelling, not two");
                assert!(s.chars().all(|c| PRINT_ALPHABET.contains(&(c as u8))));
                let code = decode(&s).unwrap();
                assert_eq!(code, Code { kind: k, key: k0 });
                // A chat client lowercases a link; a phone reads the symbol.
                assert_eq!(decode(&s.to_lowercase()).unwrap(), Code { kind: k, key: k0 });
            }
        }
    }

    /// With a zero key the leading digit is the kind and nothing else:
    /// `kind · 2²⁵⁶ / 42⁴⁷` truncated is 5, 11 and 17. (It is not zero-padded
    /// away — only `decode_print`'s range check makes a code unique.)
    #[test]
    fn a_zero_key_still_shows_its_kind() {
        for (k, lead) in [(Kind::Live, '5'), (Kind::Hosted, 'B'), (Kind::Invite, 'H')] {
            let s = encode(k, &[0u8; 32]).unwrap();
            assert_eq!(s.chars().count(), CODE_CHARS);
            assert_eq!(s.chars().next(), Some(lead), "{s}");
            assert_eq!(decode(&s).unwrap(), Code { kind: k, key: [0u8; 32] });
        }
    }

    #[test]
    fn print_is_48_chars_and_roundtrips() {
        for k in Kind::iter() {
            for seed in 0..8u8 {
                let k0 = key(seed);
                let s = encode_print(k, &k0).unwrap();
                assert_eq!(s.chars().count(), PRINT_CHARS);
                assert!(s.chars().all(|c| PRINT_ALPHABET.contains(&(c as u8))));
                assert_eq!(decode_print(&s).unwrap(), Code { kind: k, key: k0 });
                // The printed form is read off paper by a phone: case folds.
                assert_eq!(decode_print(&s.to_lowercase()).unwrap(), Code { kind: k, key: k0 });
            }
        }
    }

    /// The second spelling until 2026-11-27: 44 base64url characters, 33
    /// bytes with the kind in byte 0's top three bits. Pasted ones still open;
    /// none is written any more.
    #[test]
    fn the_44_char_text_form_still_reads() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        for k in Kind::iter() {
            let k0 = key(11);
            let mut bytes = [0u8; 33];
            bytes[0] = k.as_bits() << 5;
            bytes[1..].copy_from_slice(&k0);
            let s = URL_SAFE_NO_PAD.encode(bytes);
            assert_eq!(s.chars().count(), LEGACY_TEXT_CHARS);
            assert_eq!(decode(&s).unwrap(), Code { kind: k, key: k0 });
        }
        let s = encode(Kind::Hosted, &key(9)).unwrap();
        assert_eq!(decode(&format!("#{s}\n")).unwrap().key, key(9));
    }

    /// The whole point of the 2026-11-24 change: a key with all 256 bits set
    /// is a code. Nothing in the key is reserved for the kind any more.
    #[test]
    fn a_full_range_key_is_a_code() {
        let k0 = [0xffu8; 32];
        for k in Kind::iter() {
            let text = encode(k, &k0).unwrap();
            assert_eq!(decode(&text).unwrap(), Code { kind: k, key: k0 });
            let print = encode_print(k, &k0).unwrap();
            assert_eq!(print.chars().count(), PRINT_CHARS);
            assert_eq!(decode_print(&print).unwrap(), Code { kind: k, key: k0 });
        }
        // Invite is the top of the range: 4·2^256 − 1.
        let print = encode_print(Kind::Invite, &k0).unwrap();
        assert!(decode_print(&print).unwrap().key.iter().all(|b| *b == 0xff));
    }

    #[test]
    fn a_value_above_2_258_is_refused() {
        // 48 digits of the largest base-42 digit is 42^48 − 1 = 2^258.83: not a code.
        let s = ":".repeat(PRINT_CHARS);
        let err = decode_print(&s).expect_err("2^260 is not a code");
        assert!(err.to_string().contains("2^258"), "{err}");
    }

    #[test]
    fn kind_zero_is_refused() {
        // All zeros is kind 000, which no code has.
        let err = decode(&"0".repeat(CODE_CHARS)).expect_err("kind 0 is not a kind");
        assert!(err.to_string().contains("kind bits"), "{err}");
        // And in the base64url text code of before 2026-11-27.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let s = URL_SAFE_NO_PAD.encode([0u8; 33]);
        assert_eq!(s.chars().count(), LEGACY_TEXT_CHARS);
        let err = decode(&s).expect_err("kind 0 is not a kind");
        assert!(err.to_string().contains("kind bits"), "{err}");
    }

    #[test]
    fn a_cut_code_is_named() {
        let s = encode(Kind::Live, &key(3)).unwrap();
        let err = decode(&s[..s.len() - 1]).expect_err("47 characters is not this code");
        assert!(err.to_string().contains("48"), "{err}");
    }

    #[test]
    fn spare_bits_in_the_kind_byte_are_refused() {
        // 33 bytes of base64url by hand: in the 44-char form, the kind byte's
        // low five bits were padding and had to be zero.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut buf = [0u8; 33];
        buf[0] = (Kind::Live.as_bits() << 5) | 1;
        let s = URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(s.chars().count(), LEGACY_TEXT_CHARS);
        let err = decode(&s).expect_err("padding bits set is not canonical");
        assert!(err.to_string().contains("spare bits"), "{err}");
    }

    /// The forms of before 2026-11-24: kind in the top three bits of byte 0,
    /// key masked to 253 bits. Old links and old stickers still read, and the
    /// key that comes back is the one that was printed — not a different one.
    #[test]
    fn the_earlier_forms_still_read() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut k0 = [0u8; 32];
        for (i, b) in k0.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        k0[0] &= 0x1f;
        for k in Kind::iter() {
            let mut bytes = k0;
            bytes[0] |= k.as_bits() << 5;

            let text = URL_SAFE_NO_PAD.encode(bytes);
            assert_eq!(text.chars().count(), LEGACY_CODE_CHARS);
            assert_eq!(decode(&text).unwrap(), Code { kind: k, key: k0 });

            // The same 32 bytes as 48 base-42 digits: a value below 2^256.
            let mut limbs = [0u64; 5];
            limbs[..4].copy_from_slice(&to_limbs(&bytes));
            let mut digits = [0u8; PRINT_CHARS];
            for i in (0..PRINT_CHARS).rev() {
                digits[i] = div_rem_small(&mut limbs, CODE_BASE) as u8;
            }
            let print: String = digits.iter().map(|d| PRINT_ALPHABET[*d as usize] as char).collect();
            assert_eq!(decode_print(&print).unwrap(), Code { kind: k, key: k0 });
        }
    }

    #[test]
    fn print_url_is_uppercase_and_scannable() {
        let u = print_url("mul.li", Kind::Hosted, &key(4)).unwrap();
        assert!(u.starts_with("HTTPS://MUL.LI#"));
        assert_eq!(u.chars().count(), "HTTPS://MUL.LI#".len() + PRINT_CHARS);
        assert!(!u.chars().any(|c| c.is_ascii_lowercase()));
    }

    /// The symbol is QR version 3 at ECC L: 55 data codewords, 440 bits. In
    /// alphanumeric mode a character costs 6 bits or 11 for a pair, on top of
    /// a 4-bit mode indicator and a 9-bit count (versions 1–9).
    fn alnum_bits(s: &str) -> usize {
        let n = s.chars().count();
        4 + 9 + 11 * (n / 2) + 6 * (n % 2)
    }

    /// One byte-mode character: 8 bits of data, and byte mode counts its
    /// characters in 8 bits rather than 9 at version 3.
    fn byte_bits(n: usize) -> usize {
        4 + 8 + 8 * n
    }

    /// `HTTPS://HOST#` and then the printed digits. `#` is not in the
    /// alphanumeric set, so it forces a segment break: the cost is three
    /// segments plus a terminator, not one segment over 63 characters.
    fn symbol_bits(host: &str, digits: &str) -> usize {
        let prefix = format!("HTTPS://{}", host.to_uppercase());
        alnum_bits(&prefix) + byte_bits(1) + alnum_bits(digits) + 4
    }

    #[test]
    fn print_url_fits_qr_v3_l() {
        let digits = encode_print(Kind::Hosted, &key(11)).unwrap();
        assert_eq!(digits.chars().count(), PRINT_CHARS);
        assert_eq!(print_url("mul.li", Kind::Hosted, &key(11)).unwrap(), format!("HTTPS://MUL.LI#{digits}"));
        // 14 characters are 7 pairs: 77 + 4+9. `#` in byte mode: 8 + 4+8.
        // 48 digits are 24 pairs: 264 + 4+9. Terminator: 4. Total 391.
        assert_eq!(alnum_bits("HTTPS://MUL.LI"), 90);
        assert_eq!(byte_bits(1), 20);
        assert_eq!(alnum_bits(&digits), 277);
        assert_eq!(symbol_bits("mul.li", &digits), 391);
        assert!(symbol_bits("mul.li", &digits) <= 440, "v3-L carries 440 bits");
        // 49 bits spare is 8 characters of headroom: the format holds 77.
        let ceiling: String = std::iter::repeat('A').take(77).collect();
        assert!(alnum_bits(&ceiling) <= 440);
        let too_many: String = std::iter::repeat('A').take(78).collect();
        assert!(alnum_bits(&too_many) > 440);
    }

    /// What every client draws: the printed form of the link it holds, with
    /// the kind carried over. Also pins the cap at version 3, ECC L, for the
    /// fragment form — `HTTPS://HOST` is 90 bits, `#` 20, the code's own
    /// header 13, the terminator 4, so 127 bits go before the first digit and
    /// 313 are left: 56 digits fit (308), 57 do not (314).
    #[test]
    fn a_link_prints_as_the_symbols_content() {
        let k = key(21);
        let text = format!("https://mul.li/#{}", encode(Kind::Live, &k).unwrap());
        let printed = print_url_for(&text);
        assert_eq!(printed, print_url("mul.li", Kind::Live, &k).unwrap());
        assert_eq!(crate::ShareLink::from_link(&printed).unwrap().share_key.0, k);
        assert_eq!(print_url_for(&printed), printed, "printing is idempotent");

        // The kind rides through: a hosted link prints as hosted.
        let hosted = format!("https://mul.li/#{}", encode(Kind::Hosted, &k).unwrap());
        let digits = print_url_for(&hosted);
        let digits = digits.strip_prefix("HTTPS://MUL.LI#").unwrap();
        assert_eq!(decode_print(digits).unwrap().kind, Kind::Hosted);

        // Host case and the trailing slash before `#` do not matter.
        let http = format!("HTTP://Mul.Li/#{}", encode(Kind::Live, &k).unwrap());
        assert_eq!(print_url_for(&http), printed);

        // 48 of the 56 digits the symbol has room for.
        let digits = printed.rsplit_once('#').unwrap().1;
        assert_eq!(symbol_bits("mul.li", digits), 391);
        let cap: String = std::iter::repeat('A').take(56).collect();
        assert!(symbol_bits("mul.li", &cap) <= 440, "56 digits still fit");
        let over: String = std::iter::repeat('A').take(57).collect();
        assert!(symbol_bits("mul.li", &over) > 440, "57 digits do not fit");

        // Junk passes through untouched, so a caller need not check first.
        assert_eq!(print_url_for("https://mul.li/#nope"), "https://mul.li/#nope");
        assert_eq!(print_url_for("https://mul.li/"), "https://mul.li/");
    }

    impl Kind {
        fn iter() -> [Kind; 3] {
            [Kind::Live, Kind::Hosted, Kind::Invite]
        }
    }
}

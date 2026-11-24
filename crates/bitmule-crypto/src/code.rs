//! The 32-byte code (owner, 2026-11-24): one size for every kind of link.
//!
//! A link fragment is immutable the moment it is sent, so it can hold the
//! kind and the key material and nothing else — no version byte, no checksum,
//! no signature. The key is all 256 bits; the kind rides in the surplus of
//! the printed alphabet instead of taking bits from the key (owner,
//! 2026-11-24: "the key stays 256 bits"):
//!
//! ```text
//! print:  value = kind · 2²⁵⁶ + key            259 bits, 48 base-43 digits
//! text:   [ kind : 3 | 00000 ][ key, 256 bits ]  33 bytes, 44 base64url
//! ```
//!
//! Two spellings of the same code, because a code is pasted *and* printed:
//!
//! * **text** — 44 characters of unpadded base64url, exactly 33 bytes with no
//!   spare bits. 43 characters hold 258 bits, one short of the 259 the kind
//!   and the key need, so the text form grew by one character when the key
//!   took back its top three bits.
//! * **print** — 48 alphanumeric characters, base 43, left-padded with `0`.
//!   43⁴⁸ = 2^260.46 against the 259 needed; 48 digits is the shortest length
//!   that holds them. The alphabet is QR's alphanumeric charset minus `space`
//!   (does not survive a fragment or an auto-link) and minus `%` (opens a
//!   percent-encoded escape in every RFC 3986 parser), leaving 43 symbols.
//!   The printed form did not change length: the kind fits in the slack.
//!
//! The print form is uppercase *by construction* — QR's alphanumeric mode
//! has no lower case — so a decoder folds case before converting. The text
//! form is base64url and stays case-sensitive: the two are told apart by
//! length (44 against 48), never by tries.
//!
//! What this module still reads, so links already printed or pasted keep
//! working: the earlier 43-character text code and the earlier printed code,
//! which put the kind in the top three bits of byte 0 and left the key 253
//! bits. Their values are disjoint from the current ones (< 2²⁵⁶ against
//! ≥ 2²⁵⁶ for print; 43 against 44 characters for text), so a decoder can
//! tell them apart without a flag. Nothing in this tree emits them any more.
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

/// Text form: 44 base64url characters, 33 bytes.
pub const CODE_CHARS: usize = 44;
/// The earlier text form: 43 characters, 32 bytes, kind in the top three bits
/// of byte 0. Read, never written.
pub const LEGACY_CODE_CHARS: usize = 43;
/// Print form: 48 base-43 characters.
pub const PRINT_CHARS: usize = 48;
/// The base-43 alphabet: QR alphanumeric without space and `%`, in ASCII
/// order within each run so a human can find a digit or a letter.
pub const PRINT_ALPHABET: &[u8; 43] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";

/// A decoded code: what it opens, and the whole 256-bit key it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    pub kind: Kind,
    pub key: [u8; 32],
}

/// Encode for a text surface: 44 unpadded base64url characters.
///
/// The payload is 33 bytes: one byte of kind, then the key. The kind byte's
/// low five bits are zero, so every code has exactly one spelling.
pub fn encode(kind: Kind, key: &[u8; 32]) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut buf = [0u8; 33];
    buf[0] = kind.as_bits() << 5;
    buf[1..].copy_from_slice(key);
    let s = URL_SAFE_NO_PAD.encode(buf);
    debug_assert_eq!(s.chars().count(), CODE_CHARS);
    Ok(s)
}

/// Decode the text form — 44 characters, or the 43-character form of before
/// 2026-11-24, which put the kind in the key's top three bits.
pub fn decode_text(s: &str) -> Result<Code> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n == LEGACY_CODE_CHARS {
        return decode_text_legacy(&cleaned);
    }
    if n != CODE_CHARS {
        bail!(
            "a code is {CODE_CHARS} characters (or {PRINT_CHARS} printed), not {n} — \
             it was probably cut short or has stray characters; copy the whole code"
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
             and this is not one of those — a cut {CODE_CHARS}-character code ends \
             up this length; copy the whole code"
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

/// Encode for paper: 48 base-43 characters, `HTTPS://MUL.LI#…`-friendly and
/// therefore uppercase.
///
/// The printed value is `kind · 2²⁵⁶ + key`, so the kind sits above the whole
/// key instead of in its top bits. 259 bits against the 2^260.46 of 48 digits:
/// the symbol's length does not change while the key keeps all 256 bits.
pub fn encode_print(kind: Kind, key: &[u8; 32]) -> Result<String> {
    let mut limbs = [0u64; 5];
    limbs[4] = kind.as_bits() as u64;
    limbs[..4].copy_from_slice(&to_limbs(key));
    let mut digits = [0u8; PRINT_CHARS];
    for i in (0..PRINT_CHARS).rev() {
        digits[i] = div_rem_small(&mut limbs, 43) as u8;
    }
    debug_assert!(limbs == [0; 5], "259 bits must fit in 48 base-43 digits");
    Ok(digits.iter().map(|d| PRINT_ALPHABET[*d as usize] as char).collect())
}

/// Decode the print form. Case is folded (the printed form is uppercase by
/// construction), and the value is checked against the range the format can
/// produce, so exactly one 48-digit spelling decodes to each code.
///
/// A value below 2²⁵⁶ is a code of the earlier layout (kind in the key's top
/// three bits); at or above it, `kind · 2²⁵⁶ + key`. The two ranges cannot
/// overlap, so an old sticker still reads without a flag.
pub fn decode_print(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n != PRINT_CHARS {
        bail!(
            "a printed code is {PRINT_CHARS} characters (or {CODE_CHARS} as text), not {n}"
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
                    "{c:?} is not a code character; the alphabet is 0-9 A-Z and $*+-./:"
                )
            })? as u8;
        // 43^48 < 2^261, so five limbs never overflow here.
        mul_add_small(&mut limbs, 43, digit as u64);
    }
    if limbs[4] > 3 {
        bail!(
            "the printed code is worth 2^258 or more — it was not produced by \
             this format"
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

/// Decode either spelling. Length picks it: 44 is text, 48 is print, 43 is the
/// text form of before 2026-11-24.
pub fn decode(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    match cleaned.chars().count() {
        CODE_CHARS | LEGACY_CODE_CHARS => decode_text(&cleaned),
        PRINT_CHARS => decode_print(&cleaned),
        n => bail!(
            "a code is {CODE_CHARS} characters as text or {PRINT_CHARS} printed, not {n}"
        ),
    }
}

/// `https://host#<text code>`.
pub fn url(host: &str, kind: Kind, key: &[u8; 32]) -> Result<String> {
    Ok(format!("https://{host}#{}", encode(kind, key)?))
}

/// `HTTPS://HOST#<printed code>` — what goes in a QR symbol. Scheme and host
/// are case-insensitive, the printed code is uppercase by construction, and
/// the whole thing is in QR's alphanumeric mode.
pub fn print_url(host: &str, kind: Kind, key: &[u8; 32]) -> Result<String> {
    Ok(format!(
        "HTTPS://{}#{}",
        host.to_ascii_uppercase(),
        encode_print(kind, key)?
    ))
}

/// What a client puts in the symbol for a link it already holds:
/// `https://host/#<text code>` becomes `HTTPS://HOST#<printed code>`, the kind
/// carried over from the link.
///
/// This is the one place a surface turns a link into symbol content, so every
/// client draws the same symbol: 63 characters in three QR segments — host 14
/// alphanumeric, `#` one byte, code 48 alphanumeric — 391 of the 440 bits a
/// version 3 symbol at ECC L holds. The text form would be byte mode
/// throughout (59 bytes, 484 bits) and need a version 4 symbol.
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

    #[test]
    fn text_is_44_chars_and_roundtrips() {
        for k in Kind::iter() {
            for seed in 0..8u8 {
                let k0 = key(seed);
                let s = encode(k, &k0).unwrap();
                assert_eq!(s.chars().count(), CODE_CHARS);
                let code = decode_text(&s).unwrap();
                assert_eq!(code, Code { kind: k, key: k0 });
            }
        }
    }

    /// A zero key shows only the kind: byte 0 is `kind << 5`, which is the
    /// base64url character at index 8, 16 or 24, then 33 zero bytes.
    #[test]
    fn zero_key_is_kind_then_a() {
        assert_eq!(encode(Kind::Live, &[0u8; 32]).unwrap(), format!("I{}", "A".repeat(43)));
        assert_eq!(encode(Kind::Hosted, &[0u8; 32]).unwrap(), format!("Q{}", "A".repeat(43)));
        assert_eq!(encode(Kind::Invite, &[0u8; 32]).unwrap(), format!("Y{}", "A".repeat(43)));
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

    #[test]
    fn both_spellings_are_the_same_code() {
        let k0 = key(9);
        let text = encode(Kind::Hosted, &k0).unwrap();
        let print = encode_print(Kind::Hosted, &k0).unwrap();
        assert_eq!(decode(&text).unwrap(), decode(&print).unwrap());
        assert_eq!(decode(&format!("#{text}\n")).unwrap().key, k0);
    }

    /// The whole point of the 2026-11-24 change: a key with all 256 bits set
    /// is a code. Nothing in the key is reserved for the kind any more.
    #[test]
    fn a_full_range_key_is_a_code() {
        let k0 = [0xffu8; 32];
        for k in Kind::iter() {
            let text = encode(k, &k0).unwrap();
            assert_eq!(decode_text(&text).unwrap(), Code { kind: k, key: k0 });
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
        // 48 digits of the largest base-43 digit is ~2^260.46: not a code.
        let s = ":".repeat(PRINT_CHARS);
        let err = decode_print(&s).expect_err("2^260 is not a code");
        assert!(err.to_string().contains("2^258"), "{err}");
    }

    #[test]
    fn kind_zero_is_refused() {
        // "A" repeated is all zero bits: kind 000, in either spelling.
        let err = decode_text(&"A".repeat(CODE_CHARS)).expect_err("kind 0 is not a kind");
        assert!(err.to_string().contains("kind bits"), "{err}");
        let err = decode_print(&"0".repeat(PRINT_CHARS)).expect_err("kind 0 is not a kind");
        assert!(err.to_string().contains("kind bits"), "{err}");
    }

    #[test]
    fn a_cut_code_is_named() {
        let s = encode(Kind::Live, &key(3)).unwrap();
        let err = decode(&s[..s.len() - 1]).expect_err("43 characters is not this code");
        assert!(err.to_string().contains("44"), "{err}");
    }

    #[test]
    fn spare_bits_in_the_kind_byte_are_refused() {
        // 33 bytes of base64url by hand: the kind byte's low bits are padding.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut buf = [0u8; 33];
        buf[0] = (Kind::Live.as_bits() << 5) | 1;
        let s = URL_SAFE_NO_PAD.encode(buf);
        assert_eq!(s.chars().count(), CODE_CHARS);
        let err = decode_text(&s).expect_err("padding bits set is not canonical");
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

            // The same 32 bytes as 48 base-43 digits: a value below 2^256.
            let mut limbs = [0u64; 5];
            limbs[..4].copy_from_slice(&to_limbs(&bytes));
            let mut digits = [0u8; PRINT_CHARS];
            for i in (0..PRINT_CHARS).rev() {
                digits[i] = div_rem_small(&mut limbs, 43) as u8;
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

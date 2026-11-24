//! The 32-byte code (owner, 2026-11-24): one size for every kind of link.
//!
//! A link fragment is immutable the moment it is sent, so it can hold the
//! kind and key material and nothing else — no version byte, no checksum,
//! no signature. The kind goes in the top three bits of the first byte, the
//! remaining 253 bits are the key:
//!
//! ```text
//! byte 0:  [ kind : 3 ][        key, 253 bits        ]
//! byte 1..31:                     key
//! ```
//!
//! Two spellings of the same 32 bytes, because a code is pasted *and*
//! printed:
//!
//! * **text** — 43 characters of unpadded base64url. 43 × 6 = 258 bits, so
//!   the last character carries four significant bits and two must be zero.
//! * **print** — 48 alphanumeric characters, base 43, left-padded with `0`.
//!   Read the 32 bytes as one 256-bit big-endian integer, convert to base
//!   43, pad to 48 digits. 43⁴⁸ = 2^260.5 against 256 needed; 47 digits are
//!   2^255.0 and just short, so 48 is the length. The alphabet is QR's
//!   alphanumeric charset minus `space` (does not survive a fragment or an
//!   auto-link) and minus `%` (opens a percent-encoded escape in every
//!   RFC 3986 parser), leaving 43 symbols.
//!
//! The print form is uppercase *by construction* — QR's alphanumeric mode
//! has no lower case — so a decoder folds case before converting. The text
//! form is base64url and stays case-sensitive: the two are told apart by
//! length (43 against 48), never by tries.
//!
//! Why the kind is in the bits rather than in the path: a live session and a
//! hosted download carry the same 256-bit key, so only the bits can tell them
//! apart, and the owner's ruling (2026-11-10) is that the link encodes its
//! type. A code whose kind bits are 0 or 4–7 was not produced by this format
//! and is refused: there is no "ask the server what this is".

use anyhow::{bail, Result};

/// What a code opens. The values are the three bits in the code, so they are
/// part of the wire format and cannot be renumbered.
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

/// Text form: 43 base64url characters.
pub const CODE_CHARS: usize = 43;
/// Print form: 48 base-43 characters.
pub const PRINT_CHARS: usize = 48;
/// The base-43 alphabet: QR alphanumeric without space and `%`, in ASCII
/// order within each run so a human can find a digit or a letter.
pub const PRINT_ALPHABET: &[u8; 43] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";

/// A decoded code: what it opens, and the 253-bit key it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    pub kind: Kind,
    pub key: [u8; 32],
}

/// Clear the three bits the kind will occupy, so a key can live in a code.
///
/// Every key this tree mints for a link goes through here: 253 bits, then the
/// kind bits are added at encode time. `random()` and the data commitment
/// both mask, so no link can be produced whose key does not fit its code.
pub fn key_for_code(mut key: [u8; 32]) -> [u8; 32] {
    key[0] &= 0x1f;
    key
}

/// Would `key` survive a round trip through a code, or would three bits be
/// lost? Keys minted before the 32-byte code existed can fail this.
pub fn fits(key: &[u8; 32]) -> bool {
    key[0] & 0xe0 == 0
}

fn with_kind(kind: Kind, key: &[u8; 32]) -> Result<[u8; 32]> {
    if !fits(key) {
        bail!(
            "key has its top three bits set (0x{:02x}) and cannot be squeezed into a \
             253-bit code without changing the key",
            key[0]
        );
    }
    let mut bytes = *key;
    bytes[0] |= kind.as_bits() << 5;
    Ok(bytes)
}

/// Encode for a text surface: 43 unpadded base64url characters.
pub fn encode(kind: Kind, key: &[u8; 32]) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = with_kind(kind, key)?;
    let s = URL_SAFE_NO_PAD.encode(bytes);
    debug_assert_eq!(s.chars().count(), CODE_CHARS);
    Ok(s)
}

/// Decode the text form. The two spare bits of the last character must be
/// zero, so every code has exactly one spelling and a one-character edit
/// fails instead of naming a different key.
pub fn decode_text(s: &str) -> Result<Code> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n != CODE_CHARS {
        bail!(
            "a code is {CODE_CHARS} characters (or {PRINT_CHARS} printed), not {n} — \
             it was probably cut short or has stray characters; copy the whole code"
        );
    }
    if !cleaned.is_ascii() {
        bail!("a code is ASCII; it contains characters that are not");
    }
    // 43 chars carry 258 bits, so the last character's low two bits are
    // padding and must be zero. Checked before the base64 engine, whose own
    // "invalid last symbol" would say nothing useful.
    let last = cleaned.chars().last().unwrap_or('A');
    let idx = URL_SAFE_CHARS
        .iter()
        .position(|c| *c as char == last)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{last:?} is not a code character; the alphabet is A-Z a-z 0-9 - _"
            )
        })? as u8;
    if idx & 0b11 != 0 {
        bail!("the code has its spare bits set — it was not produced by this format");
    }
    let raw = URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|_| anyhow::anyhow!("code is not valid base64url; the alphabet is A-Z a-z 0-9 - _"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("code decodes to {} bytes, expected 32", raw.len()))?;
    from_bytes(bytes)
}

/// base64url's alphabet, in value order.
const URL_SAFE_CHARS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
pub fn encode_print(kind: Kind, key: &[u8; 32]) -> Result<String> {
    let bytes = with_kind(kind, key)?;
    let mut limbs = to_limbs(&bytes);
    let mut digits = [0u8; PRINT_CHARS];
    // 43⁴⁸ > 2^256, so 32 bytes always fit in 48 digits.
    for i in (0..PRINT_CHARS).rev() {
        digits[i] = div_rem_small(&mut limbs, 43) as u8;
    }
    debug_assert!(limbs == [0; 4], "32 bytes must fit in 48 base-43 digits");
    Ok(digits.iter().map(|d| PRINT_ALPHABET[*d as usize] as char).collect())
}

/// Decode the print form. Case is folded (the printed form is uppercase by
/// construction), and a digit string whose value is ≥ 2²⁵⁶ is refused, so the
/// canonical 48-digit spelling is the only one that decodes.
pub fn decode_print(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    let n = cleaned.chars().count();
    if n != PRINT_CHARS {
        bail!(
            "a printed code is {PRINT_CHARS} characters (or {CODE_CHARS} as text), not {n}"
        );
    }
    let mut limbs = [0u64; 4];
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
        if mul_add_small(&mut limbs, 43, digit as u64) {
            bail!(
                "the printed code is worth more than 2^256 — it was not produced by \
                 this format"
            );
        }
    }
    let bytes = from_limbs(&limbs);
    let code = from_bytes(bytes)?;
    // Canonical: re-printing must give the same digits, which rejects a
    // string whose leading digits are not the shortest possible padding.
    if encode_print(code.kind, &code.key)? != cleaned.to_ascii_uppercase() {
        bail!("the printed code is not the canonical spelling of its value");
    }
    Ok(code)
}

/// Decode either spelling. Length picks it: 43 is text, 48 is print.
pub fn decode(s: &str) -> Result<Code> {
    let cleaned = clean(s);
    match cleaned.chars().count() {
        CODE_CHARS => decode_text(&cleaned),
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
fn div_rem_small(limbs: &mut [u64; 4], d: u64) -> u64 {
    let mut rem: u128 = 0;
    for i in (0..4).rev() {
        let cur = (rem << 64) | limbs[i] as u128;
        limbs[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    rem as u64
}

/// `limbs = limbs * m + a`. Returns true on overflow past 256 bits.
fn mul_add_small(limbs: &mut [u64; 4], m: u64, a: u64) -> bool {
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

    fn key(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = seed.wrapping_mul(31).wrapping_add(i as u8);
        }
        key_for_code(b)
    }

    #[test]
    fn text_is_43_chars_and_roundtrips() {
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
    /// base64url character at index 8, 16 or 24, then zeros.
    #[test]
    fn zero_key_is_kind_then_a() {
        assert_eq!(encode(Kind::Live, &[0u8; 32]).unwrap(), format!("I{}", "A".repeat(42)));
        assert_eq!(encode(Kind::Hosted, &[0u8; 32]).unwrap(), format!("Q{}", "A".repeat(42)));
        assert_eq!(encode(Kind::Invite, &[0u8; 32]).unwrap(), format!("Y{}", "A".repeat(42)));
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
    fn both_spellings_are_the_same_32_bytes() {
        let k0 = key(9);
        let text = encode(Kind::Hosted, &k0).unwrap();
        let print = encode_print(Kind::Hosted, &k0).unwrap();
        assert_eq!(decode(&text).unwrap(), decode(&print).unwrap());
        assert_eq!(decode(&format!("#{text}\n")).unwrap().key, k0);
    }

    #[test]
    fn all_ones_key_is_the_top_of_the_range() {
        // 0xff… with the kind bits in front of it: the largest code there is.
        let k0 = [0x1fu8; 32];
        let print = encode_print(Kind::Invite, &k0).unwrap();
        assert_eq!(print.chars().count(), PRINT_CHARS);
        assert_eq!(decode_print(&print).unwrap().key, k0);
        let text = encode(Kind::Invite, &k0).unwrap();
        assert_eq!(decode_text(&text).unwrap().key, k0);
    }

    #[test]
    fn a_value_above_2_256_is_refused() {
        // 48 digits of the largest base-43 digit is ~2^260: not a code.
        let s = ":".repeat(PRINT_CHARS);
        let err = decode_print(&s).expect_err("2^260 is not a code");
        assert!(err.to_string().contains("2^256"), "{err}");
    }

    #[test]
    fn a_key_that_does_not_fit_is_named() {
        let mut k0 = [0u8; 32];
        k0[0] = 0x80;
        assert!(!fits(&k0));
        let err = encode(Kind::Live, &k0).expect_err("256-bit key cannot carry a kind");
        assert!(err.to_string().contains("top three bits"), "{err}");
        assert_eq!(key_for_code(k0)[0], 0);
    }

    #[test]
    fn kind_zero_is_refused() {
        // "A" repeated is all zero bits: kind 000.
        let err = decode_text(&"A".repeat(CODE_CHARS)).expect_err("kind 0 is not a kind");
        assert!(err.to_string().contains("kind bits"), "{err}");
    }

    #[test]
    fn a_cut_code_is_named() {
        let s = encode(Kind::Live, &key(3)).unwrap();
        let err = decode(&s[..s.len() - 1]).expect_err("42 characters is not a code");
        assert!(err.to_string().contains("43"), "{err}");
    }

    #[test]
    fn non_canonical_text_is_refused() {
        // Flip the last character's spare bits: decodes, but is not canonical.
        let s = encode(Kind::Live, &key(3)).unwrap();
        let mut chars: Vec<char> = s.chars().collect();
        let last = *chars.last().unwrap();
        let idx = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .iter()
            .position(|c| *c as char == last)
            .unwrap() as u8;
        chars.pop();
        chars.push(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                [(idx | 1) as usize] as char,
        );
        let edited: String = chars.into_iter().collect();
        let err = decode_text(&edited).expect_err("spare bits set is not canonical");
        assert!(err.to_string().contains("spare bits"), "{err}");
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

    impl Kind {
        fn iter() -> [Kind; 3] {
            [Kind::Live, Kind::Hosted, Kind::Invite]
        }
    }
}

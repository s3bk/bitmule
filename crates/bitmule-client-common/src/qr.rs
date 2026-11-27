//! The printed symbol: one QR code, made the same way on every surface.
//!
//! A printed link is `HTTPS://MUL.LI#` plus 48 uppercase alphanumeric
//! characters — 63 characters. QR's alphanumeric mode carries letters, digits
//! and nine punctuation marks (`$%*+-./:`, plus space) but not `#`, and an
//! encoder that picks one mode for a string drops the whole payload into byte
//! mode the moment it sees one: the bundled `qrcode` 0.14 encoder lays this
//! out in 487 bits, and version 3 at ECC L holds 440, so it reports the link
//! as too long and grows the symbol to version 4 (33×33).
//!
//! Written as three segments — host alphanumeric, `#` one byte, code
//! alphanumeric — the same 63 characters take 387 bits and fit version 3
//! (29×29) with 53 bits to spare. So this module does the segmenting itself
//! and hands the bits to [`QrCode::with_bits`]. Text that still does not fit
//! is drawn at the next version up rather than refused.

use qrcode::bits::Bits;
use qrcode::types::QrError;
use qrcode::{EcLevel, QrCode, Version};

/// The version a link is drawn at: 3, 29×29 modules (owner, 2026-11-24 and
/// 2026-11-27). ECC L is 7% recovery, which still scans a clean flat surface.
pub const LINK_VERSION: i16 = 3;

/// Error correction for the printed symbol.
pub const ECC: EcLevel = EcLevel::L;

/// QR's alphanumeric mode: digits, uppercase letters, space and `$%*+-./:`.
/// Lowercase is *not* in it, which is why the printed form is uppercase.
fn is_alphanumeric(b: u8) -> bool {
    matches!(
        b,
        b'0'..=b'9' | b'A'..=b'Z' | b' ' | b'$' | b'%' | b'*' | b'+' | b'-' | b'.' | b'/' | b':'
    )
}

/// Push `text` as maximal runs of alphanumeric characters and of everything
/// else. A run never splits a UTF-8 character: every byte of a multi-byte
/// character is outside the alphanumeric set, so the whole character lands in
/// one byte-mode run.
fn push_segments(bits: &mut Bits, text: &str) -> Result<(), QrError> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let alnum = is_alphanumeric(bytes[i]);
        let start = i;
        while i < bytes.len() && is_alphanumeric(bytes[i]) == alnum {
            i += 1;
        }
        if alnum {
            bits.push_alphanumeric_data(&bytes[start..i])?;
        } else {
            bits.push_byte_data(&bytes[start..i])?;
        }
    }
    Ok(())
}

/// The symbol for `text`: version 3 at ECC L, or the smallest version above
/// it that holds the text, up to the largest QR code there is.
pub fn symbol(text: &str) -> Result<QrCode, QrError> {
    let mut version = LINK_VERSION;
    loop {
        if version > 40 {
            return Err(QrError::DataTooLong);
        }
        let mut bits = Bits::new(Version::Normal(version));
        let fitted = push_segments(&mut bits, text).and_then(|()| bits.push_terminator(ECC));
        match fitted {
            Ok(()) => match QrCode::with_bits(bits, ECC) {
                Ok(code) => return Ok(code),
                Err(QrError::DataTooLong) => {}
                Err(e) => return Err(e),
            },
            Err(QrError::DataTooLong) => {}
            Err(e) => return Err(e),
        }
        version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::Version as V;

    /// The link from the field (2026-11-27), 63 characters of printed form.
    const LINK: &str = "HTTPS://MUL.LI#8G8K00X/NVA1-7/M.*5*UJ3-TY8VW.5CO44ZG9E0AGMVQJMX";

    fn bits_for(text: &str, version: i16) -> Result<usize, QrError> {
        let mut bits = Bits::new(V::Normal(version));
        push_segments(&mut bits, text)?;
        Ok(bits.len())
    }

    #[test]
    fn a_printed_link_is_63_characters_and_fits_version_3() {
        assert_eq!(LINK.chars().count(), 63);
        // 14 alphanumeric + `#` one byte + 48 alphanumeric, plus a terminator,
        // inside the 440 bits version 3 at ECC L carries.
        assert_eq!(bits_for(LINK, 3).unwrap(), 387);
        let code = symbol(LINK).unwrap();
        assert_eq!(code.width(), 29, "version 3 is 29×29 modules");
    }

    #[test]
    fn a_lowercase_link_is_not_alphanumeric_but_still_draws() {
        let lower = LINK.to_ascii_lowercase();
        assert!(bits_for(&lower, 3).unwrap() > 440);
        let code = symbol(&lower).unwrap();
        assert!(code.width() > 29);
    }

    #[test]
    fn text_that_does_not_fit_grows_instead_of_failing() {
        let long = "A".repeat(400);
        let code = symbol(&long).unwrap();
        assert!(code.width() > 29);
        // And something no version holds is an error, not a panic.
        assert!(symbol(&"A".repeat(10_000)).is_err());
    }

    #[test]
    fn the_kind_moves_the_code_but_not_the_size() {
        // Both kinds print as 48 alphanumeric characters: the symbol is the
        // same shape, only the characters differ.
        let hosted = "HTTPS://MUL.LI#Z8G8K00X/NVA1-7/M.*5*UJ3-TY8VW.5CO44ZG9E0AGMVQJ";
        assert_eq!(symbol(hosted).unwrap().width(), 29);
    }
}

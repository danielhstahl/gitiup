//! Lower-case hex and RFC 4648 base64, with no dependencies.
//!
//! Both alphabets appear in the format, and getting the details wrong is a
//! compatibility bug, so the rules are stated once here instead of being
//! re-invented at every call site:
//!
//! * **hex** — lower case only, always the full length of the digest. Upper case
//!   is rejected on input ([ADR-0001 D2](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//! * **base64std** — the standard RFC 4648 §4 alphabet, `+` and `/`.
//!   Signatures use it *with* padding (like DSSE and minisign); SSH key material
//!   and SSH-style fingerprints use it *without* padding (like `ssh-keygen`).
//!   The two variants are separate functions so neither is guessed.

use crate::error::{Error, Result};

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lower-case hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode lower-case hex, rejecting upper case, odd lengths and stray whitespace.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(
            Error::invalid("hex", "odd number of digits").with_hint("digests are lower-case hex")
        );
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i])?;
        let lo = nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ if c.is_ascii_uppercase() => {
            Err(Error::invalid("hex", "upper-case digits are not canonical"))
        }
        _ => Err(Error::invalid("hex", "not a hex digit")),
    }
}

/// Standard-alphabet base64 with `=` padding (DSSE signatures).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let present = chunk.len();
        let mut buf = [0u8; 3];
        buf[..present].copy_from_slice(chunk);
        let bits = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
        // A short chunk emits `present + 1` characters and `=` for the rest.
        for (i, shift) in [18u32, 12, 6, 0].iter().enumerate() {
            if i < present + 1 {
                out.push(B64_ALPHABET[((bits >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard-alphabet base64 with the padding removed (SSH keys and fingerprints).
pub fn base64_encode_unpadded(bytes: &[u8]) -> String {
    let mut s = base64_encode(bytes);
    while s.ends_with('=') {
        s.pop();
    }
    s
}

/// Decode base64 (standard alphabet), accepting either padded or unpadded input.
///
/// Whitespace, the URL-safe alphabet and non-canonical trailing bits are all
/// rejected: a signature that decodes two ways is a signature that can be forged
/// into a different byte string.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let padding = bytes.iter().rev().take_while(|c| **c == b'=').count();
    if padding > 2 {
        return Err(Error::invalid("base64", "more than two padding characters"));
    }
    let body = &bytes[..bytes.len() - padding];
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if body.len() % 4 == 1 {
        return Err(Error::invalid(
            "base64",
            "length is 1 modulo 4, which cannot decode",
        ));
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(body.len() * 3 / 4 + 3);
    for &c in body {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'_' | b'-' => {
                return Err(Error::invalid(
                    "base64",
                    "the URL-safe alphabet is not used by this format",
                ));
            }
            _ => return Err(Error::invalid("base64", "not in the standard alphabet")),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Any bits left over must be zero, otherwise the same bytes encode two ways.
    if (acc & ((1 << bits) - 1)) != 0 {
        return Err(Error::invalid(
            "base64",
            "non-canonical trailing bits in the final group",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000fffa5");
        assert_eq!(hex_decode("000fffa5").unwrap(), bytes);
        assert!(hex_decode("000FA5").is_err());
        assert!(hex_decode("000").is_err());
        assert!(hex_decode("0g").is_err());
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 §10 example vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        for case in [
            b"".as_slice(),
            b"f".as_slice(),
            b"fo".as_slice(),
            b"foo".as_slice(),
            b"foob".as_slice(),
            b"fooba".as_slice(),
            b"foobar".as_slice(),
            &[0x00u8, 0x01, 0x02, 0xfe, 0xff][..],
        ] {
            assert_eq!(&base64_decode(&base64_encode(case)).unwrap(), case);
        }
    }

    #[test]
    fn base64_padding_is_optional_on_input_but_absent_for_ssh() {
        assert_eq!(base64_encode_unpadded(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode_unpadded(b"f"), "Zg");
        assert_eq!(base64_decode("Zg==").unwrap(), base64_decode("Zg").unwrap());
    }

    #[test]
    fn base64_rejects_ambiguity_and_wrong_alphabets() {
        assert!(base64_decode("Zg===").is_err());
        assert!(base64_decode("-").is_err());
        assert!(base64_decode("_ _").is_err());
        assert!(base64_decode("Z m").is_err());
        // "Zg==" and "Zh==" differ only in a bit that must be zero: the second is
        // a non-canonical encoding of the same single byte.
        assert_eq!(base64_decode("Zg==").unwrap(), vec![b'f']);
        assert!(base64_decode("Zh==").is_err());
    }
}

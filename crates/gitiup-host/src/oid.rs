//! Content/commit identifiers.
//!
//! [`Oid`] is a fixed-capacity identifier that holds git SHA-1 (20 bytes),
//! SHA-256 (32 bytes) and shorter CAS digests alike, so the same type can name
//! a commit, a blob or an attestation record. Hex is the canonical external
//! form (lower case, no `sha256:` prefix).

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::error::HostError;

/// Largest digest this type can hold (SHA-256).
pub const MAX_OID_BYTES: usize = 32;

/// Smallest accepted digest (guards against trivially ambiguous prefixes).
pub const MIN_OID_BYTES: usize = 2;

/// The flavour of an [`Oid`], derived from its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OidKind {
    /// 20 bytes — git SHA-1.
    Sha1,
    /// 32 bytes — git SHA-256 / our CAS digests.
    Sha256,
    /// Some other length (truncated ids, short hashes in refs).
    Other,
}

impl OidKind {
    /// The expected byte length, when there is one.
    pub fn byte_len(self) -> Option<usize> {
        match self {
            OidKind::Sha1 => Some(20),
            OidKind::Sha256 => Some(32),
            OidKind::Other => None,
        }
    }
}

/// An object/blob identifier: raw bytes with a canonical lower-case hex form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid {
    len: u8,
    bytes: [u8; MAX_OID_BYTES],
}

impl Oid {
    /// Build from raw bytes (`2..=32` bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HostError> {
        if bytes.len() < MIN_OID_BYTES || bytes.len() > MAX_OID_BYTES {
            return Err(HostError::invalid(
                "object id",
                format!(
                    "expected {}..={hex} bytes, got {}",
                    MIN_OID_BYTES,
                    bytes.len(),
                    hex = MAX_OID_BYTES
                ),
            ));
        }
        let mut buf = [0u8; MAX_OID_BYTES];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Oid {
            len: bytes.len() as u8,
            bytes: buf,
        })
    }

    /// Parse canonical lower- or upper-case hex (40 for SHA-1, 64 for SHA-256).
    pub fn from_hex(hex: &str) -> Result<Self, HostError> {
        let hex = hex.trim();
        if hex.is_empty() {
            return Err(HostError::invalid("object id", "empty object id"));
        }
        if !hex.len().is_multiple_of(2) {
            return Err(HostError::invalid(
                "object id",
                format!("'{hex}' is not a whole number of bytes of hex"),
            )
            .with_hint("object ids are 40 (sha1) or 64 (sha256) hex characters"));
        }
        if hex.len() / 2 > MAX_OID_BYTES {
            return Err(HostError::invalid(
                "object id",
                format!("'{hex}' is longer than {MAX_OID_BYTES} bytes"),
            ));
        }
        let mut buf = [0u8; MAX_OID_BYTES];
        let mut out = 0usize;
        for pair in hex.as_bytes().chunks(2) {
            let hi = nibble(pair[0]).ok_or_else(|| non_hex(hex))?;
            let lo = nibble(pair[1]).ok_or_else(|| non_hex(hex))?;
            buf[out] = (hi << 4) | lo;
            out += 1;
        }
        if out < MIN_OID_BYTES {
            return Err(HostError::invalid(
                "object id",
                format!("'{hex}' is shorter than {MIN_OID_BYTES} bytes"),
            ));
        }
        Ok(Oid {
            len: out as u8,
            bytes: buf,
        })
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Always false (an `Oid` is never empty) — present for clippy.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Length-derived flavour.
    pub fn kind(&self) -> OidKind {
        match self.len() {
            20 => OidKind::Sha1,
            32 => OidKind::Sha256,
            _ => OidKind::Other,
        }
    }

    /// Canonical lower-case hex form.
    pub fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(self.len() * 2);
        for b in self.as_bytes() {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Abbreviated hex, as shown in listings.
    pub fn short(&self, len: usize) -> String {
        let hex = self.hex();
        hex.chars().take(len).collect()
    }

    /// Default abbreviation (git-ish 12 chars for long ids).
    pub fn short_default(&self) -> String {
        self.short(if self.len() >= 12 { 12 } else { self.len() })
    }

    /// The all-zero id of `len` bytes (git's "unborn"/deleted marker).
    pub fn zero(len: usize) -> Result<Self, HostError> {
        Oid::from_bytes(&vec![0u8; len])
    }

    /// Whether this is the all-zero id.
    pub fn is_zero(&self) -> bool {
        self.bytes[..self.len as usize].iter().all(|b| *b == 0)
    }

    /// Whether the canonical hex starts with `prefix` (case-insensitive,
    /// tolerating an odd-length prefix).
    pub fn starts_with_hex(&self, prefix: &str) -> bool {
        let hex = self.hex();
        hex.starts_with(&prefix.to_ascii_lowercase())
    }

    /// SHA-256 digest of `content` — the digest used for CAS storage.
    pub fn hash_bytes(content: &[u8]) -> Oid {
        let digest = Sha256::digest(content);
        Oid {
            len: 32,
            bytes: digest.into(),
        }
    }
}

fn non_hex(hex: &str) -> HostError {
    HostError::invalid(
        "object id",
        format!("'{hex}' contains non-hexadecimal characters"),
    )
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.hex())
    }
}

impl FromStr for Oid {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Oid::from_hex(s)
    }
}

impl TryFrom<&[u8]> for Oid {
    type Error = HostError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Oid::from_bytes(value)
    }
}

impl Serialize for Oid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Oid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OidVisitor;
        impl Visitor<'_> for OidVisitor {
            type Value = Oid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hex object id string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Oid, E> {
                Oid::from_hex(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Oid, E> {
                Oid::from_bytes(v).map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_any(OidVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_is_canonical() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let oid = Oid::from_hex(hex).unwrap();
        assert_eq!(oid.hex(), hex);
        assert_eq!(oid.kind(), OidKind::Sha1);
        assert_eq!(oid.len(), 20);
        assert_eq!(oid.to_string(), hex);
        assert_eq!(oid.short(7), "0123456");
        assert_eq!(Oid::from_str(hex).unwrap(), oid);
    }

    #[test]
    fn upper_case_input_normalises_to_lower_case() {
        let oid = Oid::from_hex("AABBCCDDEEFF00112233445566778899AABBCCDD").unwrap();
        assert_eq!(oid.hex(), "aabbccddeeff00112233445566778899aabbccdd");
        assert!(oid.starts_with_hex("AA"));
    }

    #[test]
    fn rejects_malformed_hex() {
        for bad in ["", "z", "abc", "xyzw", "00", &"a".repeat(66)] {
            assert!(Oid::from_hex(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn sha256_digest_matches_known_vector() {
        // echo -n "abc" | sha256sum
        let oid = Oid::hash_bytes(b"abc");
        assert_eq!(
            oid.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(oid.kind(), OidKind::Sha256);
    }

    #[test]
    fn zero_id_is_zero() {
        assert!(Oid::zero(20).unwrap().is_zero());
        assert!(!Oid::from_hex("0001").unwrap().is_zero());
    }

    #[test]
    fn serde_uses_hex_form() {
        let oid = Oid::from_hex("aabb").unwrap();
        let json = serde_json::to_string(&oid).unwrap();
        assert_eq!(json, "\"aabb\"");
        let back: Oid = serde_json::from_str(&json).unwrap();
        assert_eq!(back, oid);
        let err = serde_json::from_str::<Oid>("\"nope!\"");
        assert!(err.is_err());
    }
}

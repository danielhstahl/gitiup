//! Algorithm-tagged digests: `sha256:<lower-case hex>`.
//!
//! Every digest in the format carries its algorithm
//! ([ADR-0001 D2](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//! That costs nine bytes and buys hash agility: admitting `blake3:` for large
//! artifact digests later is a policy change, not a format break, and a reader
//! that cannot check a digest must say so instead of silently comparing a byte
//! string it does not understand.

use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::encoding::{hex_decode, hex_encode};
use crate::error::{Error, ErrorKind, Result};

/// The digests one can name in this format version.
///
/// Adding a variant is a *policy* change (the string form already carries the
/// name), so it never invalidates an existing signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    /// SHA-256 — the only algorithm a v1 producer may emit.
    Sha256,
}

impl Algorithm {
    /// The name used in the `algo:hex` string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
        }
    }

    /// Digest length in bytes.
    pub fn byte_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 32,
        }
    }

    /// Every algorithm this build can actually compute.
    pub const ALL: [Algorithm; 1] = [Algorithm::Sha256];
}

/// A digest: an [`Algorithm`] plus its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest {
    algorithm: Algorithm,
    bytes: Vec<u8>,
}

impl Digest {
    /// SHA-256 of `bytes`.
    pub fn sha256(bytes: &[u8]) -> Digest {
        Digest {
            algorithm: Algorithm::Sha256,
            bytes: Sha256::digest(bytes).to_vec(),
        }
    }

    /// SHA-256 over a sequence of parts, each length-prefixed so that
    /// `digest(a, b)` cannot collide with `digest(ab)`.
    ///
    /// Producers use this when a digest covers more than one blob (for example an
    /// environment fingerprint built from several inventories).
    pub fn sha256_parts(parts: &[&[u8]]) -> Digest {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Digest {
            algorithm: Algorithm::Sha256,
            bytes: hasher.finalize().to_vec(),
        }
    }

    /// Build from an algorithm and raw bytes of the expected length.
    pub fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Digest> {
        if bytes.len() != algorithm.byte_len() {
            return Err(Error::invalid(
                "digest",
                format!(
                    "{} expects {} bytes, got {}",
                    algorithm.as_str(),
                    algorithm.byte_len(),
                    bytes.len()
                ),
            ));
        }
        Ok(Digest {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The raw digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lower-case hex of the digest, without the algorithm prefix.
    ///
    /// This is the form used as a storage key (`kv/attestation/<hex>`), where the
    /// namespace already says what was hashed.
    pub fn hex(&self) -> String {
        hex_encode(&self.bytes)
    }

    /// True if `algo` is in `allowed`.
    pub fn is_allowed(&self, allowed: &[Algorithm]) -> bool {
        allowed.contains(&self.algorithm)
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Digest> {
        let (algo, hex) = s.split_once(':').ok_or_else(|| {
            Error::invalid("digest", format!("'{s}' has no algorithm prefix"))
                .with_hint("write digests as sha256:<hex>")
        })?;
        let algorithm = match algo {
            "sha256" => Algorithm::Sha256,
            other => {
                return Err(Error::new(
                    ErrorKind::UnsupportedSchema,
                    "digest",
                    format!("unknown digest algorithm '{other}'"),
                )
                .with_hint(format!(
                    "this build understands: {}",
                    Algorithm::ALL
                        .iter()
                        .map(|a| a.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };
        let bytes = hex_decode(hex).map_err(|e| {
            Error::invalid("digest", format!("'{s}': {}", e.detail()))
                .with_hint("hex must be lower case")
        })?;
        Digest::new(algorithm, &bytes)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm.as_str(), self.hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Digest::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_form_round_trips() {
        let d = Digest::sha256(b"");
        assert_eq!(
            d.to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(Digest::from_str(&d.to_string()).unwrap(), d);
    }

    #[test]
    fn rejects_foreign_forms() {
        for bad in [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // no prefix
            "sha256:e3b0",                                                      // wrong length
            "blake3:00",                                                        // unknown algorithm
            "SHA256:00",       // case-sensitive algorithm
            "sha256:E3B0C442", // upper-case hex
        ] {
            assert!(Digest::from_str(bad).is_err(), "{bad} should not parse");
        }
        // An unknown algorithm is a version problem, not a malformed one.
        assert_eq!(
            Digest::from_str("blake3:00").unwrap_err().kind(),
            ErrorKind::UnsupportedSchema
        );
    }

    #[test]
    fn length_prefixing_prevents_part_ambiguity() {
        let ab = Digest::sha256_parts(&[b"ab", b"c"]);
        let abc = Digest::sha256_parts(&[b"a", b"bc"]);
        assert_ne!(ab, abc);
    }

    #[test]
    fn serializes_as_a_bare_string() {
        let d = Digest::sha256(b"x");
        assert!(serde_json::to_string(&d).unwrap().starts_with("\"sha256:"));
    }
}

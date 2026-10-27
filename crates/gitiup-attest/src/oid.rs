//! `GitOid` lives here too because it shares the `algo:hex` form with
//! [`crate::digest::Digest`] but a different purpose: a git object name is an *identifier* we
//! never recompute, while a digest is a *claim* we must be able to check.
//!
//! [ADR-0001 D2](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md).

use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{hex_decode, hex_encode};
use crate::error::{Error, ErrorKind, Result};

/// Algorithms a git object name can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OidAlgorithm {
    /// SHA-1 — git's default object format.
    Sha1,
    /// SHA-256 — git's `--object-format=sha256`, and the fallback used to name
    /// workflow sources that are not git blobs (content hash of the file).
    Sha256,
}

impl OidAlgorithm {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            OidAlgorithm::Sha1 => "sha1",
            OidAlgorithm::Sha256 => "sha256",
        }
    }

    /// Byte length of the digest.
    pub fn byte_len(self) -> usize {
        match self {
            OidAlgorithm::Sha1 => 20,
            OidAlgorithm::Sha256 => 32,
        }
    }
}

/// A git object id: `sha1:<40 hex>` or `sha256:<64 hex>`.
///
/// Attestations bind to a commit, so the binding has to survive git's own move
/// off SHA-1: naming the algorithm in the string is what lets a v1 attestation
/// bind a sha256-format repository without a format change. SHA-1 here is an
/// identity, not a collision resistance claim — the thing being trusted is the
/// signature over the manifest, not the hash git happens to use.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GitOid {
    algorithm: OidAlgorithm,
    bytes: Vec<u8>,
}

impl GitOid {
    /// From an algorithm and raw bytes.
    pub fn new(algorithm: OidAlgorithm, bytes: &[u8]) -> Result<GitOid> {
        if bytes.len() != algorithm.byte_len() {
            return Err(Error::invalid(
                "git object id",
                format!(
                    "{} expects {} bytes, got {}",
                    algorithm.as_str(),
                    algorithm.byte_len(),
                    bytes.len()
                ),
            ));
        }
        Ok(GitOid {
            algorithm,
            bytes: bytes.to_vec(),
        })
    }

    /// A SHA-1 commit id from hex (what `git rev-parse` prints).
    pub fn from_sha1_hex(hex: &str) -> Result<GitOid> {
        let bytes = hex_decode(hex)
            .map_err(|e| Error::invalid("git object id", format!("'{hex}': {}", e.detail())))?;
        GitOid::new(OidAlgorithm::Sha1, &bytes)
    }

    /// The algorithm.
    pub fn algorithm(&self) -> OidAlgorithm {
        self.algorithm
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lower-case hex without the algorithm prefix (the form a git ref file holds).
    pub fn hex(&self) -> String {
        hex_encode(&self.bytes)
    }
}

impl FromStr for GitOid {
    type Err = Error;

    fn from_str(s: &str) -> Result<GitOid> {
        let (algo, hex) = s.split_once(':').ok_or_else(|| {
            Error::invalid("git object id", format!("'{s}' has no algorithm prefix"))
                .with_hint("write commit ids as sha1:<hex> or sha256:<hex>")
        })?;
        let algorithm = match algo {
            "sha1" => OidAlgorithm::Sha1,
            "sha256" => OidAlgorithm::Sha256,
            other => {
                return Err(Error::new(
                    ErrorKind::UnsupportedSchema,
                    "git object id",
                    format!("unknown object format '{other}'"),
                ));
            }
        };
        let bytes = hex_decode(hex)
            .map_err(|e| Error::invalid("git object id", format!("'{s}': {}", e.detail())))?;
        GitOid::new(algorithm, &bytes)
    }
}

impl std::fmt::Display for GitOid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm.as_str(), self.hex())
    }
}

impl Serialize for GitOid {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GitOid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        GitOid::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_object_formats() {
        let sha1 = GitOid::from_str(&format!("sha1:{}", "a".repeat(40))).unwrap();
        assert_eq!(sha1.algorithm(), OidAlgorithm::Sha1);
        assert_eq!(sha1.hex(), "a".repeat(40));
        let sha256 = GitOid::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap();
        assert_eq!(sha256.algorithm(), OidAlgorithm::Sha256);
        assert!(GitOid::from_str("sha1:aa").is_err());
        assert!(GitOid::from_str("sha512:aa").is_err());
        assert!(GitOid::from_str(&"c".repeat(40)).is_err());
    }
}

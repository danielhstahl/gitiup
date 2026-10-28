//! The namespaced content-addressed blob store: change records, attestations,
//! rosters and job records.
//!
//! `put_cas(namespace, bytes)` returns the SHA-256 of the content and stores it
//! so that `get(oid)` returns exactly those bytes. Writes are idempotent and
//! content-addressed, so two contributors publishing the same attestation cannot
//! collide or overwrite each other, and `list_prefix` is the operation that
//! turns "all attestations" or "all open changes" into a single cheap listing.
//!
//! Hosts lay blobs out as `kv/<kind>/<hash>` (S3 key prefix, filesystem path,
//! git blob under `refs/gitiup/**`), which is exactly what [`Prefix`] describes.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{HostError, HostResult};
use crate::oid::Oid;
use crate::time::Timestamp;

/// Bucket for content-addressed records: `change`, `attestation`, `roster`,
/// `job`, ...
///
/// Lower-case `[a-z0-9][a-z0-9._-]{0,31}` so it can be used verbatim as an S3
/// key segment, a path segment and a ref component.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Namespace(Cow<'static, str>);

impl Namespace {
    /// Const constructor used for the well-known kinds below; a bad literal is a
    /// compile error.
    pub const fn const_new(name: &'static str) -> Namespace {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > 32 {
            panic!("namespace must be 1..=32 bytes");
        }
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')) {
                panic!("namespace must be lower-case [a-z0-9._-]");
            }
            i += 1;
        }
        if !bytes[0].is_ascii_alphanumeric() {
            panic!("namespace must start with an alphanumeric character");
        }
        Namespace(Cow::Borrowed(name))
    }

    /// Change records (the PR substitute).
    pub const CHANGE: Namespace = Namespace::const_new("change");
    /// Attestations (signed run digests and their manifests).
    pub const ATTESTATION: Namespace = Namespace::const_new("attestation");
    /// Verifier rosters.
    pub const ROSTER: Namespace = Namespace::const_new("roster");
    /// Job advertisements, claims and leases.
    pub const JOB: Namespace = Namespace::const_new("job");
    /// Quorum verdicts and policy documents.
    pub const POLICY: Namespace = Namespace::const_new("policy");
    /// Catch-all for anything else a host wants to keep.
    pub const RECORD: Namespace = Namespace::const_new("record");
    /// Wildcard used by [`Prefix::all`].
    pub const ANY: &str = "*";

    /// Validate and build a namespace at runtime.
    pub fn new(name: impl Into<String>) -> Result<Namespace, HostError> {
        let name = name.into();
        let bytes = name.as_bytes();
        let bad = |why: &str| {
            Err(
                HostError::invalid("blob namespace", format!("'{name}' {why}")).with_hint(
                    "namespaces are 1-32 characters of [a-z0-9._-], starting alphanumeric",
                ),
            )
        };
        if bytes.is_empty() || bytes.len() > 32 {
            return bad("must be 1-32 bytes");
        }
        if !bytes[0].is_ascii_alphanumeric() {
            return bad("must start with an alphanumeric character");
        }
        if !bytes.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        }) {
            return bad("must be lower-case [a-z0-9._-]");
        }
        Ok(Namespace(Cow::Owned(name)))
    }

    /// The namespace as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self.0)
    }
}

impl FromStr for Namespace {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Namespace::new(s)
    }
}

impl TryFrom<String> for Namespace {
    type Error = HostError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Namespace::new(value)
    }
}

impl From<Namespace> for String {
    fn from(value: Namespace) -> Self {
        value.0.into_owned()
    }
}

/// A parsed [`BlobStore::list_prefix`] pattern.
///
/// Accepted forms (kept unambiguous on purpose — a bare token is always a
/// namespace, never a hex prefix):
///
/// | pattern         | meaning                                   |
/// |-----------------|-------------------------------------------|
/// | `*`             | every blob in every namespace             |
/// | `attestation`   | every blob in namespace `attestation`     |
/// | `attestation/1a`| blobs in `attestation` whose digest starts with `1a` |
/// | `*/1a`          | blobs in *any* namespace whose digest starts with `1a` |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    /// Namespace filter, `None` for `*`.
    pub namespace: Option<Namespace>,
    /// Required digest hex prefix (may be empty).
    pub hex: String,
}

impl Prefix {
    /// Every blob, everywhere.
    pub fn all() -> Prefix {
        Prefix {
            namespace: None,
            hex: String::new(),
        }
    }

    /// Everything in one namespace.
    pub fn namespace(ns: &Namespace) -> Prefix {
        Prefix {
            namespace: Some(ns.clone()),
            hex: String::new(),
        }
    }

    /// Parse a pattern (see the table on [`Prefix`]).
    pub fn parse(pattern: &str) -> Result<Prefix, HostError> {
        let pattern = pattern.trim();
        let bad = |why: &str| {
            Err(
                HostError::invalid("blob list prefix", format!("'{pattern}' {why}")).with_hint(
                    "expected '*', '<namespace>', '<namespace>/<hex-prefix>' or '*/<hex-prefix>'",
                ),
            )
        };
        if pattern.is_empty() {
            return bad("is empty");
        }
        let (ns_part, hex_part) = match pattern.split_once('/') {
            Some((ns, hex)) => {
                if hex.contains('/') {
                    return bad("has more than one '/'");
                }
                (ns, hex)
            }
            None => (pattern, ""),
        };
        if !hex_part.is_empty() && !hex_part.bytes().all(|b| b.is_ascii_hexdigit() || b == b'*') {
            return bad("has a digest prefix that is not hexadecimal");
        }
        let namespace = if ns_part == Namespace::ANY {
            None
        } else {
            Some(Namespace::new(ns_part)?)
        };
        Ok(Prefix {
            namespace,
            hex: hex_part.to_ascii_lowercase(),
        })
    }

    /// Whether a stored blob passes the filter.
    pub fn matches(&self, namespace: &Namespace, oid: &Oid) -> bool {
        self.namespace.as_ref().is_none_or(|want| want == namespace)
            && (self.hex.is_empty() || self.hex == "*" || oid.starts_with_hex(&self.hex))
    }

    /// Canonical textual form.
    pub fn as_str(&self) -> String {
        let ns = self
            .namespace
            .as_ref()
            .map(|n| n.as_str().to_string())
            .unwrap_or_else(|| Namespace::ANY.to_string());
        if self.hex.is_empty() {
            ns
        } else {
            format!("{ns}/{}", self.hex)
        }
    }

    /// The S3-style key prefix for this filter under a store root, e.g.
    /// `gitiup/kv/attestation/1a`.
    pub fn key_prefix(&self, kv_root: &str) -> String {
        let root = kv_root.trim_matches('/');
        let ns = self
            .namespace
            .as_ref()
            .map(|n| n.as_str().to_string())
            .unwrap_or_else(|| Namespace::ANY.to_string());
        let mut key = format!("{root}/{ns}");
        if !self.hex.is_empty() {
            key.push('/');
            key.push_str(&self.hex);
        }
        key
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// A listing entry: what a host knows about a stored blob without fetching it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEntry {
    /// Namespace it was stored under.
    pub namespace: Namespace,
    /// Its content digest.
    pub oid: Oid,
    /// Size in bytes.
    pub size: u64,
    /// When it was stored, when the host records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
}

impl BlobEntry {
    /// Logical key: `<namespace>/<hex>` — the S3 key suffix under `kv/`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.oid.hex())
    }
}

/// The namespaced, content-addressed record store.
///
/// Contract every implementation honours:
///
/// * digests are SHA-256 over the exact bytes handed to `put_cas`;
/// * `put_cas` is idempotent — storing the same bytes twice is a no-op;
/// * blobs are immutable: there is no overwrite and no delete in this trait
///   (tombstoning/retention is a host policy, see giti-1rs.5);
/// * `list_prefix` never returns a blob the caller cannot `get`.
pub trait BlobStore: Send + Sync {
    /// Store `content` under `namespace`, returning its digest.
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid>;

    /// Store `value` as canonical JSON (see [`crate::config::canonical_json`]): the digest is over `serde_json`'s bytes, which are
    /// stable for a given type and field order.
    fn put_json(&self, namespace: &Namespace, value: &serde_json::Value) -> HostResult<Oid> {
        self.put_cas(namespace, &crate::config::canonical_json(value)?)
    }

    /// Fetch a blob. `Ok(None)` when absent.
    fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>>;

    /// Metadata for a blob without transferring it. Default implementation is a
    /// fetch; hosts should override when the listing is cheaper.
    fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        Ok(self.get(oid)?.map(|bytes| BlobEntry {
            namespace: Namespace::RECORD,
            oid: *oid,
            size: bytes.len() as u64,
            created_at: None,
        }))
    }

    /// Whether the blob exists.
    fn exists(&self, oid: &Oid) -> HostResult<bool> {
        Ok(self.head(oid)?.is_some())
    }

    /// List blobs matching a [`Prefix`] pattern (`*`, `attestation`,
    /// `attestation/1a`, `*/1a`), sorted by key.
    fn list_prefix(&self, prefix: &str) -> HostResult<Vec<BlobEntry>>;

    /// Everything in one namespace.
    fn list(&self, namespace: &Namespace) -> HostResult<Vec<BlobEntry>> {
        self.list_prefix(namespace.as_str())
    }

    /// Forget one blob, at the operator's instruction (retention and GC,
    /// giti-1rs.5).
    ///
    /// This is *not* part of the immutability promise and cannot be used to
    /// rewrite history: it is only ever called for an object a retention policy
    /// has already unpublished and nothing in the store still references, and the
    /// default says the host cannot do it at all — which is the truthful answer
    /// for a git object database (no single object can be removed) and for a
    /// versioned bucket (a delete is a marker, and the bytes stay reachable
    /// forever by design). Callers must treat a refusal as a normal outcome and
    /// report it, not as a failure of the run; see [`crate::attest`].
    ///
    /// `Ok(true)` means the bytes are gone, `Ok(false)` that they were not there.
    fn purge_cas(&self, oid: &Oid) -> HostResult<bool> {
        Err(HostError::unsupported(
            "purge-blob",
            format!(
                "this host cannot forget the object {}; it can unpublish it and say so",
                oid.short_default()
            ),
        )
        .with_hint(
            "the ref is retired and this store keeps history: a git object database cannot \
             drop a single object, and a versioned bucket keeps every version. Immutability \
             is what was promised here, so nothing was lost",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_validation() {
        assert!(Namespace::new("change").is_ok());
        assert!(Namespace::new("run-jobs.v2").is_ok());
        for bad in ["", "Change", "s p a c e", "-lead", &"x".repeat(33)] {
            assert!(Namespace::new(bad).is_err(), "should reject {bad:?}");
        }
        assert_eq!(Namespace::CHANGE.as_str(), "change");
        assert_eq!(
            serde_json::to_string(&Namespace::ATTESTATION).unwrap(),
            "\"attestation\""
        );
    }

    #[test]
    fn prefix_forms() {
        assert_eq!(Prefix::parse("*").unwrap(), Prefix::all());
        assert_eq!(
            Prefix::parse("attestation").unwrap(),
            Prefix::namespace(&Namespace::ATTESTATION)
        );
        let p = Prefix::parse("attestation/1Ab").unwrap();
        assert_eq!(p.hex, "1ab");
        let any = Prefix::parse("*/1a").unwrap();
        assert_eq!(any.namespace, None);
        assert_eq!(any.hex, "1a");
        for bad in ["", "**/x", "attestation/zz", "a/b/c", "Change/x"] {
            assert!(Prefix::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn prefix_matching_and_keys() {
        let ns = Namespace::JOB;
        let oid = Oid::from_hex("1a2b3c").unwrap();
        assert!(Prefix::parse("job").unwrap().matches(&ns, &oid));
        assert!(Prefix::parse("job/1a2").unwrap().matches(&ns, &oid));
        assert!(!Prefix::parse("job/1a3").unwrap().matches(&ns, &oid));
        assert!(!Prefix::parse("roster").unwrap().matches(&ns, &oid));
        assert!(Prefix::parse("*/1a2b").unwrap().matches(&ns, &oid));
        assert!(Prefix::all().matches(&ns, &oid));
        assert_eq!(
            Prefix::parse("job/1a")
                .unwrap()
                .key_prefix("repo/gitiup/kv"),
            "repo/gitiup/kv/job/1a"
        );
        assert_eq!(Prefix::all().key_prefix("/kv/"), "kv/*");
        assert_eq!(
            BlobEntry {
                namespace: ns.clone(),
                oid,
                size: 3,
                created_at: None
            }
            .key(),
            "job/1a2b3c"
        );
    }
}

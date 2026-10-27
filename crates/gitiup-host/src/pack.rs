//! Pack transport: what a host hands over when you ask for objects.
//!
//! Two formats, deliberately:
//!
//! * [`PackFormat::Raw`] — "gitiup pack": a simple, dependency-free container of
//!   `(namespace, bytes)` records, checksummed end to end. CAS-style hosts (the
//!   filesystem reference host, the S3 bucket host) store and serve this, and it
//!   is what tests build packs with.
//! * [`PackFormat::GitPackfile`] — an opaque git packfile, produced and consumed
//!   by git-backed hosts (giti-xdw.3) via `git fetch`/`git index-pack`. Hosts
//!   that cannot parse one answer
//!   [`HostError::UnsupportedCas`] rather than
//!   silently mangling it.
//!
//! A `Pack` is content-addressed by its own digest, which is how S3 lays packs
//! out (`packs/<oid>.pack`) and how a fetch can answer "you already have that
//! one, nothing to send".

use serde::{Deserialize, Serialize};

use crate::blob::Namespace;
use crate::error::HostError;
use crate::oid::Oid;

/// Magic bytes of a gitiup raw pack.
pub const RAW_MAGIC: &[u8; 4] = b"GPK1";

/// Version byte of the gitiup raw pack format.
pub const RAW_VERSION: u8 = 1;

/// Magic bytes of a git packfile ("PACK" in git's on-disk order).
pub const GIT_PACK_MAGIC: &[u8; 4] = b"PACK";

/// Refuse packs claiming more objects than this (abuse/memory guard).
pub const MAX_PACK_OBJECTS: u32 = 200_000;

/// Refuse single objects larger than this (64 MiB).
pub const MAX_PACK_OBJECT_BYTES: u32 = 64 * 1024 * 1024;

/// Refuse packs larger than this (512 MiB).
pub const MAX_PACK_BYTES: usize = 512 * 1024 * 1024;

/// Which wire format a [`Pack`] carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackFormat {
    /// gitiup's own record container (CAS-style hosts).
    #[default]
    Raw,
    /// A git packfile, handled by git-backed hosts only.
    GitPackfile,
}

impl PackFormat {
    /// Stable name for config and `--json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            PackFormat::Raw => "raw",
            PackFormat::GitPackfile => "git-packfile",
        }
    }

    /// Parse a format name (`raw`, `git`, `packfile`, `git-packfile`).
    pub fn parse(name: &str) -> Result<PackFormat, HostError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "raw" | "gitiup" => Ok(PackFormat::Raw),
            "git" | "packfile" | "git-packfile" => Ok(PackFormat::GitPackfile),
            other => Err(HostError::invalid(
                "pack format",
                format!("'{other}' is not a pack format"),
            )
            .with_hint(format!("expected 'raw' or 'git-packfile', got '{other}'"))),
        }
    }
}

/// A fetch request: "give me these `wants`, I already have these `haves`".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackRequest {
    /// Objects (or commit roots) the caller needs.
    pub wants: Vec<Oid>,
    /// Objects the caller already holds; the host may skip everything reachable
    /// from them.
    pub have: Vec<Oid>,
    /// Restrict traversal to these ref prefixes (e.g. `refs/changes`).
    pub ref_prefixes: Vec<String>,
    /// Desired wire format.
    pub format: PackFormat,
    /// Soft cap on the response size; hosts may answer
    /// [`HostError::UnsupportedCas`] when they
    /// cannot honour it.
    pub limit_bytes: Option<usize>,
}

impl PackRequest {
    /// Ask for `wants` in [`PackFormat::Raw`].
    pub fn new(wants: impl IntoIterator<Item = Oid>) -> PackRequest {
        PackRequest {
            wants: wants.into_iter().collect(),
            have: Vec::new(),
            ref_prefixes: Vec::new(),
            format: PackFormat::Raw,
            limit_bytes: None,
        }
    }

    /// Everything the host holds under `refs` (an unshallowed full fetch).
    pub fn all_refs(ref_prefix: impl Into<String>) -> PackRequest {
        PackRequest {
            wants: Vec::new(),
            have: Vec::new(),
            ref_prefixes: vec![ref_prefix.into()],
            format: PackFormat::Raw,
            limit_bytes: None,
        }
    }

    /// Record what the caller already has.
    pub fn with_have(mut self, have: impl IntoIterator<Item = Oid>) -> Self {
        self.have.extend(have);
        self
    }

    /// Request a specific wire format.
    pub fn with_format(mut self, format: PackFormat) -> Self {
        self.format = format;
        self
    }

    /// Cap the response size.
    pub fn with_limit_bytes(mut self, limit: usize) -> Self {
        self.limit_bytes = Some(limit);
        self
    }
}

/// A pack: opaque bytes plus the format they are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    /// Wire format.
    pub format: PackFormat,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Pack {
    /// An empty raw pack (zero records, still checksummed).
    pub fn empty() -> Pack {
        Pack {
            format: PackFormat::Raw,
            bytes: encode_raw(Vec::new()).expect("empty pack always encodes"),
        }
    }

    /// Wrap existing bytes, detecting a git packfile by magic.
    pub fn from_bytes(bytes: Vec<u8>) -> Pack {
        let format = if is_git_packfile(&bytes) {
            PackFormat::GitPackfile
        } else {
            PackFormat::Raw
        };
        Pack { format, bytes }
    }

    /// Build a raw pack from `(namespace, content)` records.
    pub fn from_raw_objects(
        items: impl IntoIterator<Item = (Namespace, Vec<u8>)>,
    ) -> Result<Pack, HostError> {
        let items: Vec<(Namespace, Vec<u8>)> = items.into_iter().collect();
        for (ns, content) in &items {
            if content.len() > MAX_PACK_OBJECT_BYTES as usize {
                return Err(HostError::invalid(
                    "pack",
                    format!(
                        "object in namespace {ns} is {} bytes, maximum is {MAX_PACK_OBJECT_BYTES}",
                        content.len()
                    ),
                ));
            }
        }
        let bytes = encode_raw(items)?;
        Ok(Pack {
            format: PackFormat::Raw,
            bytes,
        })
    }

    /// Wrap bytes that must be a git packfile.
    pub fn git_packfile(bytes: Vec<u8>) -> Result<Pack, HostError> {
        if !is_git_packfile(&bytes) {
            return Err(HostError::invalid(
                "pack",
                "bytes do not start with the git packfile magic",
            )
            .with_hint("pass raw gitiup packs with Pack::from_raw_objects"));
        }
        Ok(Pack {
            format: PackFormat::GitPackfile,
            bytes,
        })
    }

    /// Decompose a raw pack into `(namespace, content)` records, verifying its
    /// trailing digest.
    pub fn raw_objects(&self) -> Result<Vec<(Namespace, Vec<u8>)>, HostError> {
        decode_raw(&self.bytes)
    }

    /// Number of records in a raw pack.
    pub fn object_count(&self) -> Result<usize, HostError> {
        Ok(self.raw_objects()?.len())
    }

    /// The pack's own content digest — S3 stores packs at `packs/<oid>.pack`.
    pub fn oid(&self) -> Oid {
        Oid::hash_bytes(&self.bytes)
    }

    /// Byte length on the wire.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the pack carries nothing.
    pub fn is_empty(&self) -> bool {
        match self.format {
            PackFormat::Raw => self.object_count().map(|n| n == 0).unwrap_or(false),
            PackFormat::GitPackfile => self.bytes.is_empty(),
        }
    }

    /// Reject absurd sizes before we allocate for them.
    pub(crate) fn check_size(&self) -> Result<(), HostError> {
        if self.bytes.len() > MAX_PACK_BYTES {
            return Err(HostError::invalid(
                "pack",
                format!(
                    "pack is {} bytes, maximum is {MAX_PACK_BYTES}",
                    self.bytes.len()
                ),
            ));
        }
        Ok(())
    }
}

/// Whether `bytes` starts with the git packfile magic and version we know.
pub fn is_git_packfile(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[..4] == GIT_PACK_MAGIC && bytes[4..8] == [0, 0, 0, 2]
}

fn encode_raw(items: Vec<(Namespace, Vec<u8>)>) -> Result<Vec<u8>, HostError> {
    if items.len() as u32 > MAX_PACK_OBJECTS {
        return Err(HostError::invalid(
            "pack",
            format!("{} objects, maximum is {MAX_PACK_OBJECTS}", items.len()),
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(RAW_MAGIC);
    out.push(RAW_VERSION);
    out.push(0); // flags, reserved
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for (ns, content) in &items {
        let ns_bytes = ns.as_str().as_bytes();
        out.push(ns_bytes.len() as u8);
        out.extend_from_slice(ns_bytes);
        out.extend_from_slice(&(content.len() as u32).to_be_bytes());
        out.extend_from_slice(content);
    }
    let digest = Oid::hash_bytes(&out);
    out.extend_from_slice(digest.as_bytes());
    if out.len() > MAX_PACK_BYTES {
        return Err(HostError::invalid(
            "pack",
            format!("pack is {} bytes, maximum is {MAX_PACK_BYTES}", out.len()),
        ));
    }
    Ok(out)
}

fn decode_raw(bytes: &[u8]) -> Result<Vec<(Namespace, Vec<u8>)>, HostError> {
    let bad = |why: &str| HostError::invalid("pack", format!("malformed pack: {why}"));
    if bytes.len() < 4 || &bytes[..4] != RAW_MAGIC {
        if is_git_packfile(bytes) {
            return Err(HostError::unsupported(
                "pack-format:raw",
                "this pack is a git packfile, not a gitiup raw pack",
            )
            .with_hint("use a git-backed host (giti-xdw.3) to ingest packfiles"));
        }
        return Err(bad("bad magic"));
    }
    if bytes.len() < 8 + 32 {
        return Err(bad("truncated before the header"));
    }
    if bytes[4] != RAW_VERSION {
        return Err(bad(&format!("unsupported pack version {}", bytes[4])));
    }
    let count = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    if count > MAX_PACK_OBJECTS as usize {
        return Err(bad(&format!(
            "claims {count} objects, maximum is {MAX_PACK_OBJECTS}"
        )));
    }
    let (body, trailer) = bytes.split_at(bytes.len() - 32);
    let expected = Oid::from_bytes(&trailer[..32]).map_err(|_| bad("bad digest trailer"))?;
    if Oid::hash_bytes(body) != expected {
        return Err(bad("content digest does not match the trailer"));
    }

    let mut items = Vec::with_capacity(count.min(1024));
    let mut cur = 10usize;
    for idx in 0..count {
        let ns_len = *body
            .get(cur)
            .ok_or_else(|| bad("truncated namespace length"))? as usize;
        cur += 1;
        if cur + ns_len > body.len() {
            return Err(bad("truncated namespace"));
        }
        let ns = Namespace::new(String::from_utf8_lossy(&body[cur..cur + ns_len]).into_owned())
            .map_err(|_| bad(&format!("object {idx} has an invalid namespace")))?;
        cur += ns_len;
        let len_bytes: [u8; 4] = body
            .get(cur..cur + 4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| bad("truncated object length"))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        cur += 4;
        if len > MAX_PACK_OBJECT_BYTES as usize {
            return Err(bad(&format!(
                "object {idx} is {len} bytes, maximum is {MAX_PACK_OBJECT_BYTES}"
            )));
        }
        if cur + len > body.len() {
            return Err(bad("truncated object body"));
        }
        items.push((ns, body[cur..cur + len].to_vec()));
        cur += len;
    }
    if cur != body.len() {
        return Err(bad("trailing bytes after the last object"));
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<(Namespace, Vec<u8>)> {
        vec![
            (
                Namespace::ATTESTATION.clone(),
                b"{\"digest\":\"aa\"}".to_vec(),
            ),
            (Namespace::CHANGE.clone(), b"{\"id\":\"c1\"}".to_vec()),
            (Namespace::RECORD.clone(), vec![0u8, 1, 2, 255]),
        ]
    }

    #[test]
    fn raw_pack_roundtrip_is_byte_exact() {
        let pack = Pack::from_raw_objects(items()).unwrap();
        assert_eq!(pack.format, PackFormat::Raw);
        assert!(!pack.is_empty());
        assert_eq!(pack.object_count().unwrap(), 3);
        let back = pack.raw_objects().unwrap();
        assert_eq!(back, items());
        assert_eq!(pack.oid(), Oid::hash_bytes(&pack.bytes));
    }

    #[test]
    fn empty_pack_roundtrips() {
        let pack = Pack::empty();
        assert!(pack.is_empty());
        assert!(pack.raw_objects().unwrap().is_empty());
    }

    #[test]
    fn identical_inputs_give_identical_packs() {
        let a = Pack::from_raw_objects(items()).unwrap();
        let b = Pack::from_raw_objects(items()).unwrap();
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.oid(), b.oid());
    }

    #[test]
    fn tampering_is_detected() {
        let mut pack = Pack::from_raw_objects(items()).unwrap();
        let n = pack.bytes.len();
        let mid = n / 2;
        pack.bytes[mid] ^= 0xff;
        let err = pack.raw_objects().unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::Invalid);
        assert!(err.to_string().contains("digest"), "{err}");
    }

    #[test]
    fn git_packfiles_are_recognised_and_not_parsed_as_raw() {
        let mut fake = Vec::new();
        fake.extend_from_slice(GIT_PACK_MAGIC);
        fake.extend_from_slice(&[0, 0, 0, 2]);
        fake.extend_from_slice(&[0, 0, 0, 1]);
        fake.extend_from_slice(&[0u8; 20]);
        assert!(is_git_packfile(&fake));
        let pack = Pack::git_packfile(fake.clone()).unwrap();
        assert_eq!(pack.format, PackFormat::GitPackfile);
        assert_eq!(
            Pack::from_bytes(fake.clone()).format,
            PackFormat::GitPackfile
        );
        let err = pack.raw_objects().unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::UnsupportedCas);
        assert!(Pack::git_packfile(b"not a pack".to_vec()).is_err());
    }

    #[test]
    fn truncated_packs_are_rejected() {
        let pack = Pack::from_raw_objects(items()).unwrap();
        for len in [0usize, 4, 8, 40, pack.bytes.len() - 1] {
            let cut = Pack {
                format: PackFormat::Raw,
                bytes: pack.bytes[..len.min(pack.bytes.len())].to_vec(),
            };
            assert!(cut.raw_objects().is_err(), "should reject len {len}");
        }
    }

    #[test]
    fn format_names_parse() {
        assert_eq!(PackFormat::parse("raw").unwrap(), PackFormat::Raw);
        assert_eq!(
            PackFormat::parse("Git-Packfile").unwrap(),
            PackFormat::GitPackfile
        );
        assert!(PackFormat::parse("zstd").is_err());
        assert_eq!(PackFormat::Raw.as_str(), "raw");
    }
}

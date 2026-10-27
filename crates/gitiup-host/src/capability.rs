//! Capabilities, host identity and the [`Host`] trait that ties refs + blobs
//! together.
//!
//! Capability checks are how gitiup stays honest across transports: an S3 bucket
//! without conditional writes cannot gate a merge, so it reports
//! `cas = false` and every owner-side write that depends on CAS fails with
//! [`HostError::UnsupportedCas`] instead of
//! silently losing a ref (see giti-xdw.2).

use serde::{Deserialize, Serialize};

use crate::blob::BlobStore;
use crate::error::HostError;
use crate::refs::RefStore;

/// How a host authenticates writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthModel {
    /// No authentication at all (anonymous read; writes impossible or open).
    Anonymous,
    /// Local filesystem permissions (the `fs` host).
    Filesystem,
    /// A bearer/api token configured per remote.
    Token,
    /// An SSH key or ssh-signed identity (ssh remotes, signed ref updates).
    SshKey,
    /// Cloud credentials resolved from a provider chain (AWS env/profile/SSO/
    /// web-identity/IRSA).
    CloudRole,
    /// Credentials delegated to an external helper (an attestation or KMS
    /// signer, see giti-1rs.6).
    Helper,
}

impl AuthModel {
    /// Stable name for config and `--json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthModel::Anonymous => "anonymous",
            AuthModel::Filesystem => "filesystem",
            AuthModel::Token => "token",
            AuthModel::SshKey => "ssh-key",
            AuthModel::CloudRole => "cloud-role",
            AuthModel::Helper => "helper",
        }
    }

    /// Parse an `auth = "..."` config value.
    pub fn parse(name: &str) -> Result<AuthModel, HostError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "anonymous" => Ok(AuthModel::Anonymous),
            "fs" | "filesystem" => Ok(AuthModel::Filesystem),
            "token" | "tok" | "bearer" => Ok(AuthModel::Token),
            "ssh" | "ssh-key" | "sshkey" => Ok(AuthModel::SshKey),
            "cloud" | "cloud-role" | "aws" | "iam" => Ok(AuthModel::CloudRole),
            "helper" | "exec" => Ok(AuthModel::Helper),
            other => Err(HostError::invalid(
                "auth model",
                format!("'{other}' is not an auth model"),
            )
            .with_hint(
                "expected one of anonymous, filesystem, token, ssh-key, cloud-role, helper",
            )),
        }
    }

    /// Whether this model needs credentials resolved before a write.
    pub fn needs_credentials(self) -> bool {
        !matches!(self, AuthModel::Anonymous | AuthModel::Filesystem)
    }
}

/// A capability a caller may require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Ref updates are compare-and-swap (lost updates are impossible).
    Cas,
    /// Stored blobs can never be overwritten or deleted.
    Immutable,
    /// Several ref updates can be applied in one atomic transaction.
    AtomicMultiWrite,
}

impl Capability {
    /// Stable name (also the `capability` field of
    /// [`HostError::UnsupportedCas`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Cas => "cas",
            Capability::Immutable => "immutable",
            Capability::AtomicMultiWrite => "atomic-multi-write",
        }
    }
}

/// What a host can promise. Cheap to call; called before every risky operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Ref updates are compare-and-swap: `update_ref_cas` fails with
    /// [`HostError::Conflict`] rather than losing a
    /// concurrent write. A bucket without conditional writes reports `false`,
    /// and gitiup refuses owner-side merges there.
    pub cas: bool,
    /// Content-addressed blobs are immutable once written (no overwrite, no
    /// delete).
    pub immutable: bool,
    /// [`RefStore::update_refs_cas`] is all-or-nothing.
    pub atomic_multi_write: bool,
    /// How writes are authenticated here.
    pub auth: AuthModel,
}

impl Capabilities {
    /// Nothing is promised (the safe default for an unknown host).
    pub const fn none() -> Capabilities {
        Capabilities {
            cas: false,
            immutable: false,
            atomic_multi_write: false,
            auth: AuthModel::Anonymous,
        }
    }

    /// A full-featured host: CAS refs, immutable blobs, atomic multi-writes.
    pub const fn full(auth: AuthModel) -> Capabilities {
        Capabilities {
            cas: true,
            immutable: true,
            atomic_multi_write: true,
            auth,
        }
    }

    /// CAS + immutable blobs but no multi-ref transaction (the S3 shape).
    pub const fn cas_only(auth: AuthModel) -> Capabilities {
        Capabilities {
            cas: true,
            immutable: true,
            atomic_multi_write: false,
            auth,
        }
    }

    /// Whether `capability` holds.
    pub fn has(self, capability: Capability) -> bool {
        match capability {
            Capability::Cas => self.cas,
            Capability::Immutable => self.immutable,
            Capability::AtomicMultiWrite => self.atomic_multi_write,
        }
    }

    /// Require `capability`, or fail with
    /// [`HostError::UnsupportedCas`] naming it.
    pub fn require(self, capability: Capability) -> Result<(), HostError> {
        if self.has(capability) {
            return Ok(());
        }
        Err(unsupported(&self, capability))
    }

    /// The capabilities that are missing, as strings (used by
    /// `gitiup remote doctor`).
    pub fn missing(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for c in [
            Capability::Cas,
            Capability::Immutable,
            Capability::AtomicMultiWrite,
        ] {
            if !self.has(c) {
                out.push(c.as_str());
            }
        }
        out
    }
}

fn unsupported(caps: &Capabilities, capability: Capability) -> HostError {
    let hint = match capability {
        Capability::Cas => {
            "this host cannot guarantee compare-and-swap ref updates: \
                             for S3 enable conditional writes (If-Match/If-None-Match), \
                             or point the remote at a git host"
        }
        Capability::Immutable => {
            "content-addressed records may be overwritten here: \
                                  enable object versioning / Object Lock (S3) or use a \
                                  host that promises immutability"
        }
        Capability::AtomicMultiWrite => {
            "multi-ref updates will be applied one at a time \
                                         with best-effort rollback; a crash can leave a \
                                         partially applied change"
        }
    };
    HostError::unsupported(
        capability.as_str(),
        format!(
            "host does not support {} (capabilities: cas={}, immutable={}, atomic-multi-write={})",
            capability.as_str(),
            caps.cas,
            caps.immutable,
            caps.atomic_multi_write
        ),
    )
    .with_hint(hint)
}

/// What kind of host this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKind {
    /// A bare directory on a filesystem ([`FsHost`](crate::hosts::fs::FsHost)).
    Fs,
    /// An S3 (or MinIO) bucket used as the forge.
    S3,
    /// A plain git repository over ssh / smart-HTTP / dumb-HTTP.
    Git,
    /// GitHub, demoted to one adapter among several.
    Github,
    /// Something else entirely.
    Other,
}

impl HostKind {
    /// Stable name for config and `--json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            HostKind::Fs => "fs",
            HostKind::S3 => "s3",
            HostKind::Git => "git",
            HostKind::Github => "github",
            HostKind::Other => "other",
        }
    }
}

impl std::fmt::Display for HostKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Self-description of a host, for logs, `gitiup remote show` and the capability
/// matrix in `gitiup remote doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    /// Remote/host name as the user knows it (`origin`, `upstream`).
    pub name: String,
    /// Which implementation this is.
    pub kind: HostKind,
    /// Where it lives, redacted of any credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Prefix the store lives under inside the bucket/repo (e.g.
    /// `my-repo/gitiup`).
    pub store_prefix: String,
    /// What it promises.
    pub capabilities: Capabilities,
    /// Implementation and version, e.g. `gitiup-host 0.1.0 (fs)`.
    pub implemented_by: String,
    /// Schema version of the stored documents this host writes.
    pub schema_version: u32,
}

impl HostInfo {
    /// One-line rendering for humans.
    pub fn summary_line(&self) -> String {
        let missing = self.capabilities.missing();
        let promises = if missing.is_empty() {
            "full-cas".to_string()
        } else {
            format!("missing {}", missing.join(","))
        };
        format!(
            "{} ({}) at {} [{promises}]",
            self.name,
            self.kind,
            self.url.clone().unwrap_or_else(|| "-".to_string()),
        )
    }
}

/// A remote gitiup can talk to: refs, packs and content-addressed records, plus
/// the promises this host makes about them.
///
/// Implementations must be shareable (`Send + Sync`) so a verification run can
/// read from several hosts on threads. Trait upcasting means a `&dyn Host` can be
/// passed to code that only needs `&dyn RefStore` or `&dyn BlobStore`.
pub trait Host: RefStore + BlobStore {
    /// What this host promises. Must be cheap.
    fn capabilities(&self) -> Capabilities;

    /// Who this is. Must be cheap.
    fn describe(&self) -> HostInfo;

    /// Require a capability, so a code path can fail early and actionably
    /// instead of mid-write ([`HostError::UnsupportedCas`]).
    fn require(&self, capability: Capability) -> Result<(), HostError> {
        self.capabilities().require(capability)
    }

    /// The remote name (from [`describe`](Host::describe)).
    fn name(&self) -> String {
        self.describe().name
    }

    /// Which implementation this is.
    fn kind(&self) -> HostKind {
        self.describe().kind
    }
}

/// Standard `implemented_by` string for host implementations in this crate.
pub fn implemented_by(flavour: &str) -> String {
    format!("gitiup-host {} ({flavour})", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HostErrorExt as _;

    #[test]
    fn capability_checks_are_actionable() {
        let caps = Capabilities::cas_only(AuthModel::CloudRole);
        assert!(caps.require(Capability::Cas).is_ok());
        let err = caps.require(Capability::AtomicMultiWrite).unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::UnsupportedCas);
        assert!(err.to_string().contains("atomic-multi-write"), "{err}");
        assert!(err.hint().unwrap().contains("rollback"), "{err}");
        assert_eq!(caps.missing(), vec!["atomic-multi-write"]);
        assert!(err.is_unsupported());
    }

    #[test]
    fn auth_models_parse_and_report_credential_need() {
        assert_eq!(AuthModel::parse("ssh").unwrap(), AuthModel::SshKey);
        assert_eq!(AuthModel::parse("").unwrap(), AuthModel::Anonymous);
        assert!(AuthModel::parse("carrier-pigeon").is_err());
        assert!(!AuthModel::Filesystem.needs_credentials());
        assert!(AuthModel::Token.needs_credentials());
        assert_eq!(
            serde_json::to_string(&AuthModel::CloudRole).unwrap(),
            "\"cloud-role\""
        );
    }

    #[test]
    fn info_summary_mentions_gaps() {
        let info = HostInfo {
            name: "origin".into(),
            kind: HostKind::S3,
            url: Some("s3://bucket/repo".into()),
            store_prefix: "repo/gitiup".into(),
            capabilities: Capabilities::cas_only(AuthModel::CloudRole),
            implemented_by: implemented_by("s3"),
            schema_version: crate::HOST_SCHEMA_VERSION,
        };
        let line = info.summary_line();
        assert!(line.contains("origin"), "{line}");
        assert!(line.contains("missing atomic-multi-write"), "{line}");
        assert_eq!(info.kind.as_str(), "s3");
        assert!(implemented_by("fs").starts_with("gitiup-host "));
    }
}

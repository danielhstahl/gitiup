//! `gitiup-host` — the host abstraction gitiup codes against.
//!
//! gitiup wants to run CI, propose changes and store attestations *without* a
//! forge. To make that possible every interaction with "where the repo lives"
//! goes through a small set of capability traits instead of a GitHub client:
//!
//! * [`RefStore`] — list refs, fetch packs, and update refs with
//!   **compare-and-swap** semantics ([`RefUpdate`] / [`Expect`]).
//! * [`BlobStore`] — a namespaced, content-addressed KV store for change
//!   records, attestations, rosters and job records ([`Namespace`]).
//! * [`Host`] — the two above plus [`Capabilities`] and [`HostInfo`], so code
//!   can ask "may I do this here?" instead of guessing.
//!
//! The reference implementation is [`hosts::fs::FsHost`] (a bare directory with a
//! single `refs` file plus a content-addressed `cas/` tree). The second real host
//! is [`hosts::s3::S3Host`]: one S3/MinIO bucket as a complete remote, refs
//! updated with S3 conditional writes, packs by multipart upload, records
//! content addressed under `kv/`. Every test in the workspace uses them, and the
//! conformance suite (giti-xdw.5) runs the same tests against the plain-git host
//! and a live MinIO.
//!
//! The second half of the crate is configuration: [`Config`] parses
//! `gitiup.toml`, including [`RemoteConfig`] (name, url, store prefix,
//! credentials profile, per-remote timeout) with a schema-versioned file
//! format and [`RemoteScheme`] URI validation for `s3://`, `https://`,
//! `ssh://` and `file://`.
//!
//! # Error taxonomy
//!
//! Downstream tickets pattern-match on errors, so the taxonomy is part of the
//! public contract: [`HostError::Unreachable`], [`HostError::UnsupportedCas`],
//! [`HostError::Conflict`], [`HostError::PermissionDenied`] and
//! [`HostError::SchemeUnknown`] (plus [`HostError::NotFound`],
//! [`HostError::Invalid`] and [`HostError::Storage`] for plumbing). See
//! [`HostErrorKind`].
//!
//! # Store layout conventions
//!
//! Regardless of transport, a host root holds:
//!
//! ```text
//! refs/<ref name>          ref -> { oid, updated_by, updated_at, schema }
//! packs/<oid>.pack         pack files, content addressed
//! kv/<kind>/<hash>         change records, attestations, rosters, job records
//! ```
//!
//! Ref namespaces shared by all hosts (see [`refs::ns`]):
//!
//! ```text
//! refs/heads/**            real branches (owner writes)
//! refs/changes/<id>/head   proposed change head
//! refs/attestations/<subject>/<digest>  attestations for a commit, so `git fetch` carries proof
//! refs/gitiup/**           roster, job/lease records, quorum state
//! ```
//!
//! The attestation namespace is keyed by the *subject* first and holds one ref per
//! proof, and [`attest`] owns that layout plus the retention policy that prunes it.
//! Changes live under `refs/changes/<change_id>/{head,attempt/<n>,merged,abandoned}`,
//! and [`change`] owns that layout: a change is a signed record in the content-addressed
//! store, advertised by a ref, whose merge is a compare-and-swap a bucket can honour
//! ([ADR-0003](../../../docs/adr/0003-change-record-format-and-merge-semantics.md)).
//!
//! ```
//! use gitiup_host::{BlobStore, Host, RefStore, Namespace, RefName, RefUpdate, Expect};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join("gitiup-host-lib-example");
//! let _ = std::fs::remove_dir_all(&dir);
//! let host = gitiup_host::hosts::fs::FsHost::create(&dir)?;
//!
//! // blobs are content addressed and idempotent
//! let oid = host.put_cas(&Namespace::ATTESTATION, b"hello")?;
//! assert_eq!(host.get(&oid)?, Some(b"hello".to_vec()));
//! assert_eq!(oid, host.put_cas(&Namespace::ATTESTATION, b"hello")?);
//!
//! // refs are updated with compare-and-swap
//! let name = RefName::branch("main")?;
//! host.update_ref_cas(&RefUpdate::new(name.clone(), Expect::Absent, oid))?;
//! let again = host.update_ref_cas(&RefUpdate::new(name, Expect::Absent, oid));
//! assert!(matches!(again, Err(gitiup_host::HostError::Conflict(_))));
//!
//! assert!(host.capabilities().cas);
//! # let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```

pub mod attest;
pub mod blob;
pub mod capability;
/// The change record: its bytes, its refs, and publishing it over CAS (ADR-0003).
pub mod change;
pub mod config;
pub mod conformance;
pub mod error;
/// Federation: what a store may copy out of itself, and how (ADR-0005).
pub mod federation;
pub mod hosts;
pub mod oid;
pub mod pack;
pub mod refs;
/// The credential scope: which origin a credential may travel to, and the refusal when it
/// would not (giti-g5c.5).
pub mod scope;
pub mod time;

pub use blob::{BlobEntry, BlobStore, Namespace, Prefix};
pub use capability::{
    AuthModel, Capabilities, Capability, Host, HostInfo, HostKind, implemented_by,
};
pub use config::{
    Config, CredentialProfile, Credentials, RemoteConfig, RemoteScheme, RemoteUrl, canonical_json,
};
pub use error::{HostError, HostErrorExt, HostErrorKind, HostResult};
pub use federation::{CopyReport, Refusal, copy as federation_copy};
pub use hosts::fs::FsHost;
pub use hosts::s3::bucket::{
    Bucket, BucketError, BucketFacts, BucketInfo, MemoryBucket, MemoryBucketConfig, Object,
    ObjectMeta, PutCond, SharedBucket, VersioningState,
};
pub use hosts::s3::{
    ConditionalWrites, HostManifest as S3HostManifest, RefCacheStats, RefDocument as S3RefDocument,
    S3Host, S3Options,
};
pub use oid::{Oid, OidKind};
pub use pack::{Pack, PackFormat, PackRequest};
pub use refs::{Actor, Expect, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate};
pub use scope::{Breach, Origin, Scope};
pub use time::Timestamp;

/// Schema version of the host-facing on-disk formats written by this crate
/// (host manifest, refs file, ref JSON documents).
///
/// Readers must refuse anything newer than this; writers must only ever emit
/// this value.
pub const HOST_SCHEMA_VERSION: u32 = 1;

/// Highest ref/blob schema version this build can *read*.
pub const HOST_SCHEMA_VERSION_MAX: u32 = HOST_SCHEMA_VERSION;

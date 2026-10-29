//! Where a change lives in a store, and what it takes to publish one (giti-b2z.2).
//!
//! This module is the code half of
//! [ADR-0003](../../../docs/adr/0003-change-record-format-and-merge-semantics.md):
//! the record's bytes (D1–D4), the names it is filed under (D5), how a force-push is
//! recorded (D6), what the three states are made of (D7) and the order a reader checks
//! things in (D11). It is the same shape as [`crate::attest`] — canonical bytes in the
//! content-addressed store, advertised by a ref, every write a compare-and-swap — and
//! it keeps the same discipline about ordering: objects before bytes before refs, so a
//! ref never promises bytes the store cannot return.
//!
//! ```text
//! refs/changes/<change_id>/head              the current attempt (moves, under CAS)
//! refs/changes/<change_id>/attempt/<n>       attempt n: immutable, create-only
//! refs/changes/<change_id>/merged            the merge record, if merged (create-only)
//! refs/changes/<change_id>/abandoned         the abandon record, if abandoned (create-only)
//!
//! kv/change/<record_digest>                  a change record (one object per attempt)
//! kv/merge/<record_digest>                   a merge record
//! kv/abandon/<record_digest>                 an abandon record
//! ```
//!
//! # Two digests, because they answer different questions
//!
//! [`ChangeRecord::change_digest`] hashes the record **without its signatures** and is
//! the identity of the proposal: what a merge record cites, what an attempt's
//! `previous` names, what a verdict is about. It does not move when a signature is
//! added or re-encoded.
//!
//! [`ChangeRecord::digest`] hashes the **stored bytes** and is the CAS key: the object
//! at `kv/change/<hex>` must hash to `<hex>`, or this module's promise to "refuse
//! anything that does not re-hash to the name it is filed under" is a lie. Both are
//! `sha256:`-tagged lower-case hex, both come from the one canonicaliser
//! (`gitiup-canon`, which is also why `gitiup-attest` agrees with this module byte for
//! byte).
//!
//! # What a state is
//!
//! `open`, `merged` and `abandoned` are **derived from which refs exist** — there is no
//! `state` field to edit, because an edit is a new digest, and every attestation and
//! verdict that cited the old one would silently be about nothing. A transition is a
//! new signed record plus one create-only ref, which is why a change can be merged
//! exactly once and abandoned exactly once: the second attempt is a conflict, not a
//! surprise.
//!
//! # What a merge is
//!
//! A merge is a **compare-and-swap fast-forward of a branch**, and then a signed record of
//! it ([`plan_merge`] and [`merge`]): `refs/heads/<base>` moves from the base the author
//! signed to the attempt's head, and `kv/merge/<hex>` plus the create-only
//! `refs/changes/<id>/merged` say who did it, which attempt they merged and which proofs
//! they believed. A stale base is refused with both oids, because "pull first" is the only
//! useful advice; a non-fast-forward is refused, because a merge commit exists only after
//! the merge and no proof can cover it; and a refusal from the store itself — the
//! non-owner credential, the hook that says no — is passed through unedited, because the
//! store answered the question that was asked.
//!
//! The branch moves before the record does, so the one crash that can happen leaves a
//! detectable silence rather than a false statement: [`unrecorded_merge`] finds it and
//! [`record_merge`] closes it (and is also how a forge's own merge gets a record, with
//! `via: forge`).
//!
//! # Refusing, not counting twice
//!
//! Every write here is create-only or compare-and-swap. Publishing the same bytes
//! twice is idempotent success (`already: true`); publishing *different* bytes where a
//! ref already stands is a refusal that names both sides
//! ([`HostError::Conflict`], exit 6) — an attempt ref is never moved and `head` is only
//! ever moved from the value the writer just read. A store that cannot do CAS is
//! refused with [`HostError::UnsupportedCas`] rather than given an unconditional write
//! it would have to fake.
//!
//! # The exit codes (ADR-0003 D11)
//!
//! | code | when |
//! |------|------|
//! | 6 | refused: unknown `type`/field, over a limit, a bad ref binding, a stale base, an attempt that already exists, a conflict |
//! | 7 | a signature that does not verify, or a `key_id` that is not the fingerprint of the key offered |
//! | 8 | bytes that are not their own canonical form, a record that does not re-hash to its name, a `change_id` that does not re-derive |
//!
//! Everything else keeps the host taxonomy's code ([`HostError::exit_code`]): 3 for I/O
//! and store refusals this crate does not own.
//!
//! ```
//! use gitiup_host::change::{self, ChangeRecord};
//! use gitiup_host::{BlobStore, FsHost, Host, Oid};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join("gitiup-host-change-example");
//! let _ = std::fs::remove_dir_all(&dir);
//! let host = FsHost::create(&dir)?;
//! assert_eq!(gitiup_host::change::list_changes(&host)?.changes.len(), 0);
//!
//! // A record's own name is derived, so a reader can check it without asking the
//! // store anything:
//! let id = change::ChangeId::derive(
//!     "SHA256:kxdEn5B5O97An8LO4jzpCD5gVIqAyJxWVyqY7ILLiB0",
//!     "refs/heads/main",
//!     "sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
//! )?;
//! assert_eq!(id.as_str(), "chg-6a6a8eab778ba4d0");
//! assert_eq!(change::change_head_ref(&id).as_str(), format!("refs/changes/{id}/head"));
//! # let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```

use std::collections::BTreeMap;

use gitiup_canon::{Digest, SignatureEntry, Signer, canon, pae};
use serde::{Deserialize, Serialize};

use crate::Host;
use crate::blob::Namespace;
use crate::error::{HostError, HostResult};
use crate::oid::Oid;
use crate::refs::{Actor, Ref, RefName, RefParent, RefQuery, RefUpdate, ns};
use crate::time::Timestamp;

// --------------------------------------------------------------------------
// The format's constants (ADR-0003 D1-D3, D9, D11)
// --------------------------------------------------------------------------

/// Schema version written by this module; a reader refuses anything newer.
pub const SCHEMA_VERSION: u32 = 1;

/// `type` of a change record (D2).
pub const CHANGE_TYPE: &str = "gitiup-change-1";
/// `type` of a merge record (D7).
pub const MERGE_TYPE: &str = "gitiup-merge-1";
/// `type` of an abandon record (D7).
pub const ABANDON_TYPE: &str = "gitiup-abandon-1";

/// DSSE payload type of a change record (D1).
pub const CHANGE_PAYLOAD_TYPE: &str = "application/vnd.gitiup.change+json";
/// DSSE payload type of a merge record (D1, D8).
pub const MERGE_PAYLOAD_TYPE: &str = "application/vnd.gitiup.merge+json";
/// DSSE payload type of an abandon record (D1, D7).
pub const ABANDON_PAYLOAD_TYPE: &str = "application/vnd.gitiup.abandon+json";

/// The domain string inside every `change_id` (D3). Inside the hash means inside
/// the format: changing it changes every id in existence, which is a new record type
/// and not a quiet fix.
pub const ID_DOMAIN: &str = "gitiup-change-1";

/// Hex characters in a `change_id`'s body: eight bytes, enough to make an accidental
/// collision improbable and worthless to grind at (D3).
pub const ID_HEX_CHARS: usize = 16;

/// Largest record a reader will parse. A change is a kilobyte; a megabyte one is a
/// problem, not a change (D2).
pub const MAX_RECORD_BYTES: usize = 32 * 1024;
/// Largest title, in bytes (D2).
pub const MAX_TITLE_BYTES: usize = 512;
/// Largest `principal`, in bytes (D2).
pub const MAX_PRINCIPAL_BYTES: usize = 128;
/// Most jobs one record may name (D9).
pub const MAX_JOBS: usize = 64;
/// Largest job id, in bytes (D9).
pub const MAX_JOB_BYTES: usize = 128;
/// Most proof digests one merge record may cite (D8).
pub const MAX_PROOFS: usize = 64;
/// Most annotations one record may carry (D2).
pub const MAX_ANNOTATIONS: usize = 16;
/// Largest annotation value, in bytes (D2).
pub const MAX_ANNOTATION_BYTES: usize = 512;
/// Longest `previous` chain a reader will walk (D6).
pub const MAX_CHAIN: usize = 64;
/// Shortest unambiguous handle for a change (D3: "≥ 4 hex, like a short oid").
pub const MIN_ID_PREFIX: usize = 4;

/// The `kv/` namespace a change record is filed under.
pub const CHANGE_NAMESPACE: Namespace = Namespace::CHANGE;
/// The `kv/` namespace a merge record is filed under.
pub const MERGE_NAMESPACE: Namespace = Namespace::MERGE;
/// The `kv/` namespace an abandon record is filed under.
pub const ABANDON_NAMESPACE: Namespace = Namespace::ABANDON;

// --------------------------------------------------------------------------
// change_id
// --------------------------------------------------------------------------

/// A `change_id`: `chg-` plus sixteen lower-case hex characters (D3).
///
/// It is a *name*, not an integrity claim — the digest and the signature are the
/// integrity claim — but it is still a name every reader re-derives from the record
/// with [`ChangeId::derive`] and refuses to believe when the record disagrees.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangeId(String);

impl ChangeId {
    /// Validate the `chg-<16 lower hex>` grammar.
    pub fn new(text: &str) -> HostResult<ChangeId> {
        let hex = text.strip_prefix("chg-").ok_or_else(|| {
            HostError::invalid("change id", format!("'{text}' does not start with 'chg-'"))
        })?;
        if hex.len() != ID_HEX_CHARS || !lower_hex(hex) {
            return Err(HostError::invalid(
                "change id",
                format!(
                    "'{text}' is not 'chg-' followed by {ID_HEX_CHARS} lower-case hex characters"
                ),
            )
            .with_hint("a change id is derived, not typed: see ChangeId::derive (ADR-0003 D3)"));
        }
        Ok(ChangeId(text.to_string()))
    }

    /// Derive the id from the three fields that identify a proposal and survive every
    /// re-push: who signed it, toward which branch, and the head it started at (D3).
    ///
    /// Never the current `head` — a force-push would otherwise be "a new change" and
    /// every attestation of the previous attempt would be orphaned.
    pub fn derive(key_id: &str, base_ref: &str, anchor: &str) -> HostResult<ChangeId> {
        for (what, value) in [
            ("author.key_id", key_id),
            ("base.ref", base_ref),
            ("attempts.anchor", anchor),
        ] {
            if value.is_empty() {
                return Err(HostError::invalid("change id", format!("{what} is empty")));
            }
            if value.bytes().any(|b| b == 0) {
                return Err(HostError::invalid(
                    "change id",
                    format!("{what} contains a NUL, which is the derivation's separator"),
                ));
            }
        }
        let mut preimage =
            Vec::with_capacity(ID_DOMAIN.len() + key_id.len() + base_ref.len() + anchor.len() + 3);
        for (index, part) in [ID_DOMAIN, key_id, base_ref, anchor].iter().enumerate() {
            if index > 0 {
                preimage.push(0);
            }
            preimage.extend_from_slice(part.as_bytes());
        }
        let hex = Digest::sha256(&preimage).hex();
        Ok(ChangeId(format!(
            "chg-{}",
            hex.chars().take(ID_HEX_CHARS).collect::<String>()
        )))
    }

    /// The id as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex body, without the `chg-` prefix.
    pub fn hex(&self) -> &str {
        &self.0["chg-".len()..]
    }

    /// Whether `handle` names this change unambiguously: the whole id, or at least
    /// [`MIN_ID_PREFIX`] hex characters of its body (D3: a short handle, like a short
    /// oid).
    pub fn matches_handle(&self, handle: &str) -> bool {
        let handle = handle.trim();
        if handle.is_empty() {
            return false;
        }
        let body = handle
            .strip_prefix("chg-")
            .unwrap_or(handle)
            .to_ascii_lowercase();
        if body.len() < MIN_ID_PREFIX || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        self.hex().starts_with(&body)
    }
}

impl std::fmt::Display for ChangeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ChangeId {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ChangeId::new(s)
    }
}

impl Serialize for ChangeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ChangeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ChangeId::new(&String::deserialize(deserializer)?)
            .map_err(|e| serde::de::Error::custom(e.message()))
    }
}

// --------------------------------------------------------------------------
// ref and storage names (ADR-0003 D5)
// --------------------------------------------------------------------------

/// `refs/changes/<id>/head` — the ref that names a change's current attempt.
///
/// Its value is a **record digest**, not a git oid: on a git host the ref holds a
/// pointer commit carrying the record and the commits it proposes
/// ([`RefUpdate::with_parents`]).
pub fn change_head_ref(id: &ChangeId) -> RefName {
    // `chg-<hex>` is a legal ref component by construction and `head` is a constant.
    RefName::change(id.as_str(), "head").expect("a change id is a legal ref component")
}

/// `refs/changes/<id>/attempt/<n>` — one attempt, immutable and create-only (D6).
pub fn attempt_ref(id: &ChangeId, index: u32) -> RefName {
    RefName::change(id.as_str(), &format!("attempt/{index}"))
        .expect("a change id and a decimal index are legal ref components")
}

/// `refs/changes/<id>/merged` — the merge record, if the change was merged (D7).
pub fn merged_ref(id: &ChangeId) -> RefName {
    RefName::change(id.as_str(), "merged").expect("a change id is a legal ref component")
}

/// `refs/changes/<id>/abandoned` — the abandon record, if the change was abandoned.
pub fn abandoned_ref(id: &ChangeId) -> RefName {
    RefName::change(id.as_str(), "abandoned").expect("a change id is a legal ref component")
}

/// `refs/changes/<id>/` — everything one change owns, which is what a fetch of a
/// change asks for. The trailing separator matters: a listing is a string match.
pub fn change_prefix(id: &ChangeId) -> String {
    format!("{}/{}/", ns::CHANGES, id.as_str())
}

/// `kv/<namespace>/<hex>` — the storage key a record of `namespace` is filed under
/// (D5). This is the logical key: a host prefixes it with its own `kv` root.
pub fn kv_key(namespace: &Namespace, digest: &Oid) -> String {
    format!("kv/{namespace}/{}", digest.hex())
}

/// Which part of a change's ref namespace a name is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeRef {
    /// `refs/changes/<id>/head`.
    Head {
        /// The change.
        id: ChangeId,
    },
    /// `refs/changes/<id>/attempt/<n>`.
    Attempt {
        /// The change.
        id: ChangeId,
        /// The attempt index the leaf names.
        index: u32,
    },
    /// `refs/changes/<id>/merged`.
    Merged {
        /// The change.
        id: ChangeId,
    },
    /// `refs/changes/<id>/abandoned`.
    Abandoned {
        /// The change.
        id: ChangeId,
    },
}

impl ChangeRef {
    /// The change this ref belongs to.
    pub fn id(&self) -> &ChangeId {
        match self {
            ChangeRef::Head { id }
            | ChangeRef::Attempt { id, .. }
            | ChangeRef::Merged { id }
            | ChangeRef::Abandoned { id } => id,
        }
    }

    /// The ref this target names.
    pub fn ref_name(&self) -> RefName {
        match self {
            ChangeRef::Head { id } => change_head_ref(id),
            ChangeRef::Attempt { id, index } => attempt_ref(id, *index),
            ChangeRef::Merged { id } => merged_ref(id),
            ChangeRef::Abandoned { id } => abandoned_ref(id),
        }
    }
}

/// Read a `refs/changes/**` name back into what it addresses.
///
/// `None` means the name is not this layout — a deeper leaf, a malformed id, or a
/// leaf this format does not define. A listing reports those rather than guessing
/// (the same rule [`crate::attest`] applies to `unexpected_refs`): an invention under
/// `refs/changes/` is somebody's data that this build cannot name, which is worth
/// printing.
pub fn parse_ref(name: &RefName) -> Option<ChangeRef> {
    let rest = name.as_str().strip_prefix(ns::CHANGES)?.strip_prefix('/')?;
    let (id_text, leaf) = rest.split_once('/')?;
    let id = ChangeId::new(id_text).ok()?;
    match leaf {
        "head" => Some(ChangeRef::Head { id }),
        "merged" => Some(ChangeRef::Merged { id }),
        "abandoned" => Some(ChangeRef::Abandoned { id }),
        other => {
            let index = other
                .strip_prefix("attempt/")?
                .parse::<u32>()
                .ok()
                .filter(|n| *n <= 1_000_000)?;
            Some(ChangeRef::Attempt { id, index })
        }
    }
}

// --------------------------------------------------------------------------
// the records
// --------------------------------------------------------------------------

/// Who wrote a record: the key that signed it, and a display name nobody may use for
/// authorisation (D2, and ADR-0002 D9's rule that a key is the identity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    /// An SSH fingerprint (`SHA256:…`), which must equal `signatures[0].key_id`.
    pub key_id: String,
    /// Display only, 1…128 bytes.
    pub principal: String,
}

/// `base`: the branch a change is proposed against and the point it branched from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// A `refs/heads/<branch>`. Serde-renamed from `ref`, which Rust spells
    /// `r#ref`.
    #[serde(rename = "ref")]
    pub branch: String,
    /// The algorithm-tagged oid a merge must find there (D8's compare side).
    pub oid: String,
}

/// `attempts`: what makes a force-push a new attempt of the same change (D6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempts {
    /// Attempt 0's head: fixed for the life of the change, and the anchor of the id.
    pub anchor: String,
    /// 0-based attempt number.
    pub index: u32,
    /// The `change_digest` of attempt `index - 1`; omitted at 0, required above it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
}

/// Where a change came from (D10). A pull request is an *advertisement* of a record,
/// never its home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// `store` or `pull`.
    pub kind: OriginKind,
    /// The pull request number; present exactly when `kind` is `pull`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
}

/// Which kind of [`Origin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OriginKind {
    /// The store is the only place this change exists.
    Store,
    /// A pull request carries it, and the forge's merge button is the merge.
    Pull,
}

impl Origin {
    /// `{kind:"store"}`, carrying nothing else (D10).
    pub fn store() -> Origin {
        Origin {
            kind: OriginKind::Store,
            number: None,
        }
    }

    /// `{kind:"pull",number:n}`.
    pub fn pull(number: u64) -> Origin {
        Origin {
            kind: OriginKind::Pull,
            number: Some(number),
        }
    }
}

/// `workflow.jobs`: the jobs the author asks a verifier to re-run (D9).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    /// Sorted, deduplicated job ids; empty means "no re-run requested", which is not
    /// "run everything" and not "nothing is required".
    pub jobs: Vec<String>,
}

/// One signed change record (D1, D2).
///
/// Thirteen members, no `null`s, no unknown fields, and a `change_id` the record can
/// be checked against. Build one, sign it with [`ChangeRecord::sign`], publish it with
/// [`publish_change`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRecord {
    /// The only extension point, and deliberately weaker than a typed field (D2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// What attempt this is, and which one it replaces.
    pub attempts: Attempts,
    /// Who proposed it.
    pub author: Author,
    /// Which branch, from which oid.
    pub base: Base,
    /// `chg-` + 16 hex, re-derived by every reader (D3).
    pub change_id: ChangeId,
    /// Microseconds UTC, claimed by the author (D6 of ADR-0001).
    pub created_at_us: i64,
    /// The commit being proposed.
    pub head: String,
    /// Store or pull request (D10).
    pub origin: Origin,
    /// Must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Exactly one entry, by the author (D2).
    pub signatures: Vec<SignatureEntry>,
    /// One line, 1…512 bytes, no control characters.
    pub title: String,
    /// Must be [`CHANGE_TYPE`].
    #[serde(rename = "type")]
    pub record_type: String,
    /// The workflow hint (D9).
    pub workflow: Workflow,
}

/// One signed merge record (D7, D8): what a merge *is* — the attempt merged, the ref
/// move as the CAS that it was, and the proofs believed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeRecord {
    /// The attempt's `change_digest` — never the merge's own body digest (D4).
    pub change_digest: String,
    /// Which change.
    pub change_id: ChangeId,
    /// The attempt the record is about.
    pub attempt: u32,
    /// The ref move, spelled as a compare-and-swap.
    pub base: MergeBase,
    /// Microseconds UTC of the merge.
    pub merged_at_us: i64,
    /// `store` (gitiup moved the ref) or `forge` (a forge did, and this record was
    /// written afterwards).
    pub via: String,
    /// Attestation record digests, in the order believed. May be empty; empty says
    /// nothing rather than appearing to have believed everything (D8).
    pub proofs: Vec<String>,
    /// Reserved for Epic 2's published policy; absent means no policy was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    /// Whoever signed this record — the merger, not the change's author.
    pub author: Author,
    /// Must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`MERGE_TYPE`].
    #[serde(rename = "type")]
    pub record_type: String,
    /// Exactly one entry.
    pub signatures: Vec<SignatureEntry>,
    /// The only extension point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// `base` in a merge record: the ref move as `from → to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeBase {
    /// The branch moved.
    #[serde(rename = "ref")]
    pub branch: String,
    /// What the CAS expected.
    pub from: String,
    /// What the CAS wrote — the merged attempt's head.
    pub to: String,
}

/// One signed abandon record (D7): closing a change is a fact with a signature on it,
/// not a deleted ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbandonRecord {
    /// The attempt's `change_digest`.
    pub change_digest: String,
    /// Which change.
    pub change_id: ChangeId,
    /// The attempt the record is about.
    pub attempt: u32,
    /// Microseconds UTC.
    pub abandoned_at_us: i64,
    /// `superseded`, `withdrawn`, `rejected` or `stale` (D7).
    pub reason: String,
    /// Free text, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Whoever signed this record.
    pub author: Author,
    /// Must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`ABANDON_TYPE`].
    #[serde(rename = "type")]
    pub record_type: String,
    /// Exactly one entry.
    pub signatures: Vec<SignatureEntry>,
    /// The only extension point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

/// Any record this module reads, so a ref can be resolved without the caller knowing
/// which of the three kinds it is filed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredRecord {
    /// A change (one per attempt).
    Change(ChangeRecord),
    /// A merge.
    Merge(MergeRecord),
    /// An abandon.
    Abandon(AbandonRecord),
}

impl StoredRecord {
    /// The change this record is about.
    pub fn change_id(&self) -> &ChangeId {
        match self {
            StoredRecord::Change(r) => &r.change_id,
            StoredRecord::Merge(r) => &r.change_id,
            StoredRecord::Abandon(r) => &r.change_id,
        }
    }

    /// The record's `type` string.
    pub fn record_type(&self) -> &str {
        match self {
            StoredRecord::Change(_) => CHANGE_TYPE,
            StoredRecord::Merge(_) => MERGE_TYPE,
            StoredRecord::Abandon(_) => ABANDON_TYPE,
        }
    }

    /// Canonical bytes as stored.
    pub fn canonical_bytes(&self) -> HostResult<Vec<u8>> {
        match self {
            StoredRecord::Change(r) => r.canonical_bytes(),
            StoredRecord::Merge(r) => r.canonical_bytes(),
            StoredRecord::Abandon(r) => r.canonical_bytes(),
        }
    }

    /// The digest of the stored bytes: the `kv/` key (D4).
    pub fn digest(&self) -> HostResult<Oid> {
        record_digest(&self.canonical_bytes()?)
    }

    /// Re-hash, re-derive and re-verify (D11).
    pub fn verify(&self) -> HostResult<()> {
        match self {
            StoredRecord::Change(r) => r.verify(),
            StoredRecord::Merge(r) => r.verify(),
            StoredRecord::Abandon(r) => r.verify(),
        }
    }
}

// --------------------------------------------------------------------------
// canonical bytes, digests, verification
// --------------------------------------------------------------------------

/// Reject bytes over [`MAX_RECORD_BYTES`] before anything parses them (D2, D11: a
/// huge record is a `6`, not an out-of-memory).
fn check_size(bytes: &[u8], what: &str) -> HostResult<()> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(HostError::invalid(
            what,
            format!(
                "{} bytes exceeds the {MAX_RECORD_BYTES} byte limit for a change record",
                bytes.len()
            ),
        )
        .with_hint(
            "a change record is a kilobyte: a longer title is a description (put it in the \
             commit message), more jobs than this is a workflow file (point at one)",
        ));
    }
    Ok(())
}

/// Canonical bytes of any record: sorted keys, no whitespace, no `null`, no floats
/// (ADR-0001 D1 through the one canonicaliser).
fn canonical<T: Serialize>(record: &T) -> HostResult<Vec<u8>> {
    let value = serde_json::to_value(record)
        .map_err(|e| HostError::invalid("change record", format!("cannot encode: {e}")))?;
    let bytes = canon::to_value_bytes(&value).map_err(|e| {
        HostError::invalid("change record", format!("cannot canonicalise: {e}")).with_exit_code(8)
    })?;
    check_size(&bytes, "change record")?;
    Ok(bytes)
}

/// The signed body: the record with its `signatures` removed — the one rule
/// `gitiup-quorum`'s `record::body_bytes` applies to rosters and rounds, and the reason
/// adding a signature cannot move a `change_digest` (D1).
fn body<T: Serialize>(record: &T) -> HostResult<Vec<u8>> {
    let mut value = serde_json::to_value(record)
        .map_err(|e| HostError::invalid("change record", format!("cannot encode: {e}")))?;
    value
        .as_object_mut()
        .ok_or_else(|| HostError::invalid("change record", "a record must be an object"))?
        .remove("signatures");
    let bytes = canon::to_value_bytes(&value).map_err(|e| {
        HostError::invalid("change record", format!("cannot canonicalise: {e}")).with_exit_code(8)
    })?;
    check_size(&bytes, "change record")?;
    Ok(bytes)
}

/// Parse bytes that must already be canonical, refusing a newer schema or an unknown
/// record type before anything else (D11 step 1).
fn parse_canonical<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> HostResult<T> {
    check_size(bytes, what)?;
    canon::require_canonical(bytes).map_err(|e| {
        HostError::invalid(what, format!("bytes are not canonical: {e}")).with_exit_code(8)
    })?;
    serde_json::from_slice(bytes).map_err(|e| {
        HostError::invalid(what, format!("cannot be read: {e}")).with_hint(
            "unknown fields are refused rather than ignored: a field every reader must \
             understand is a new record type, not a new member (ADR-0003 D11)",
        )
    })
}

/// Parse a record of any of the three kinds from stored bytes.
///
/// The `type` member decides, and an unknown one is a refusal: reading a
/// `gitiup-change-2` as a `gitiup-change-1` is exactly the quiet misreading this
/// format refuses to allow.
pub fn record_from_bytes(bytes: &[u8]) -> HostResult<StoredRecord> {
    check_size(bytes, "change record")?;
    let value = serde_json::from_slice::<serde_json::Value>(bytes).map_err(|e| {
        HostError::invalid("change record", format!("cannot be read: {e}")).with_exit_code(8)
    })?;
    let seen = value
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or_default();
    match seen {
        CHANGE_TYPE => Ok(StoredRecord::Change(ChangeRecord::from_canonical_bytes(
            bytes,
        )?)),
        MERGE_TYPE => Ok(StoredRecord::Merge(MergeRecord::from_canonical_bytes(
            bytes,
        )?)),
        ABANDON_TYPE => Ok(StoredRecord::Abandon(AbandonRecord::from_canonical_bytes(
            bytes,
        )?)),
        other => Err(HostError::invalid(
            "change record",
            format!(
                "type '{other}' is not one this build speaks ({CHANGE_TYPE}, {MERGE_TYPE}, \
                 {ABANDON_TYPE})"
            ),
        )
        .with_hint("upgrade gitiup, or do not merge a record you cannot read")),
    }
}

/// `sha256:` + hex of the stored bytes — the `kv/` key (D4).
pub fn record_digest(bytes: &[u8]) -> HostResult<Oid> {
    Ok(Oid::hash_bytes(bytes))
}

/// The tagged digest string of some bytes (`sha256:<hex>`).
pub fn digest_string(bytes: &[u8]) -> String {
    Digest::sha256(bytes).to_string()
}

impl ChangeRecord {
    /// The exact bytes that are stored, signatures included (D1).
    pub fn canonical_bytes(&self) -> HostResult<Vec<u8>> {
        canonical(self)
    }

    /// The bytes the signature covers: the record without its `signatures` (D1).
    pub fn body_bytes(&self) -> HostResult<Vec<u8>> {
        body(self)
    }

    /// The digest of the stored bytes — the name the record is filed under,
    /// `kv/change/<hex>` (D4).
    ///
    /// [`ChangeRecord::change_digest`] is the other digest and the one everything
    /// *cites*; this one is the one the store is keyed by.
    pub fn digest(&self) -> HostResult<Oid> {
        record_digest(&self.canonical_bytes()?)
    }

    /// `sha256:` of [`ChangeRecord::body_bytes`] — the identity of the proposal, cited
    /// by `attempts.previous`, by merge and abandon records, and by quorum rounds (D4).
    pub fn change_digest(&self) -> HostResult<String> {
        Ok(digest_string(&self.body_bytes()?))
    }

    /// The bytes a signature is made over.
    pub fn signing_message(&self) -> HostResult<Vec<u8>> {
        Ok(pae(CHANGE_PAYLOAD_TYPE, &self.body_bytes()?))
    }

    /// Sign this record with `key`, returning the signed copy (D1).
    ///
    /// The signer must *be* the author: one signature, by the author, and a second
    /// signature is a new attempt with one author rather than a quiet co-authorship
    /// (D2).
    pub fn sign(&self, key: &dyn Signer) -> HostResult<ChangeRecord> {
        let mut signed = self.clone();
        signed.signatures = vec![
            SignatureEntry::new(key, &self.signing_message()?)
                .map_err(|e| HostError::invalid("signature", e.to_string()))?,
        ];
        if signed.author.key_id != key.key_id() {
            return Err(HostError::bad_signature(
                "change record",
                format!(
                    "the record is authored by {} but was signed by {}",
                    signed.author.key_id,
                    key.key_id()
                ),
            ));
        }
        signed.verify()?;
        Ok(signed)
    }

    /// Read stored bytes, refusing anything that is not this format (D11 step 1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> HostResult<ChangeRecord> {
        let record: ChangeRecord = parse_canonical(bytes, "change record")?;
        // Steps 1-5 of ADR-0003 D11 in one gate: shape and limits, the derived id, the
        // key id against the key offered, and the signature. A caller that wants to
        // read a record it does not intend to believe can `parse_canonical` is private
        // on purpose: refusing to verify is not a supported way to read a record.
        record.verify()?;
        Ok(record)
    }

    /// Everything a reader checks that does not involve the store (D11 steps 2–5):
    /// schema and type, limits and shapes, the derived `change_id`, the key id against
    /// the key offered, and the signature.
    ///
    /// Refusals are ordered, because the first thing wrong decides the exit code a
    /// script branches on.
    pub fn verify(&self) -> HostResult<()> {
        self.validate()?;
        self.check_derivation()?;
        check_one_signature(&self.signatures, &self.author, &self.signing_message()?)
    }

    /// The shape and limit checks (D2, D9), shared with [`ChangeRecord::verify`] and
    /// run first, before anything is derived or verified.
    pub fn validate(&self) -> HostResult<()> {
        check_schema(self.schema_version, &self.record_type, CHANGE_TYPE)?;
        check_author(&self.author)?;
        check_title(&self.title)?;
        check_oid(&self.head, "head")?;
        check_oid(&self.attempts.anchor, "attempts.anchor")?;
        check_branch(&self.base.branch, "base.ref")?;
        check_oid(&self.base.oid, "base.oid")?;
        check_annotations(self.annotations.as_ref())?;
        check_workflow(&self.workflow)?;
        check_origin(&self.origin)?;
        if self.change_id.as_str()
            != ChangeId::derive(
                &self.author.key_id,
                &self.base.branch,
                &self.attempts.anchor,
            )?
            .as_str()
        {
            return Err(HostError::digest_mismatch(
                "change id",
                format!(
                    "{} does not re-derive from this record's author, base branch and anchor",
                    self.change_id
                ),
            )
            .with_hint(
                "the id is a name the record must earn: it is SHA-256 over the author's key \
                 id, the base ref and attempt 0's head (ADR-0003 D3), so a record claiming \
                 someone else's name is refused here",
            ));
        }
        check_attempts(&self.attempts, &self.head)?;
        Ok(())
    }

    /// The derivation check on its own (D11 step 3), so a caller that already validated
    /// the shape can report the two failures apart.
    fn check_derivation(&self) -> HostResult<()> {
        let derived = ChangeId::derive(
            &self.author.key_id,
            &self.base.branch,
            &self.attempts.anchor,
        )?;
        if derived != self.change_id {
            return Err(HostError::digest_mismatch(
                "change id",
                format!("{} is not {derived}", self.change_id),
            ));
        }
        Ok(())
    }
}

impl MergeRecord {
    /// The exact stored bytes (D1).
    pub fn canonical_bytes(&self) -> HostResult<Vec<u8>> {
        canonical(self)
    }

    /// The bytes the merger's signature covers (D1).
    pub fn body_bytes(&self) -> HostResult<Vec<u8>> {
        body(self)
    }

    /// The digest of the stored bytes: `kv/merge/<hex>` (D4).
    pub fn digest(&self) -> HostResult<Oid> {
        record_digest(&self.canonical_bytes()?)
    }

    /// This merge record's own body digest.
    ///
    /// Distinct from its `change_digest` **field**, which names the *attempt* it
    /// merged: two values that would otherwise share a name (D4's naming note).
    pub fn body_digest(&self) -> HostResult<String> {
        Ok(digest_string(&self.body_bytes()?))
    }

    /// The bytes a signature is made over.
    pub fn signing_message(&self) -> HostResult<Vec<u8>> {
        Ok(pae(MERGE_PAYLOAD_TYPE, &self.body_bytes()?))
    }

    /// Sign with `key` (the merger's key), returning the signed copy.
    pub fn sign(&self, key: &dyn Signer) -> HostResult<MergeRecord> {
        let mut signed = self.clone();
        signed.signatures = vec![
            SignatureEntry::new(key, &self.signing_message()?)
                .map_err(|e| HostError::invalid("signature", e.to_string()))?,
        ];
        if signed.author.key_id != key.key_id() {
            return Err(HostError::bad_signature(
                "merge record",
                format!(
                    "the record is authored by {} but was signed by {}",
                    signed.author.key_id,
                    key.key_id()
                ),
            ));
        }
        signed.verify()?;
        Ok(signed)
    }

    /// Read stored bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> HostResult<MergeRecord> {
        let record: MergeRecord = parse_canonical(bytes, "merge record")?;
        // Steps 1-5 of ADR-0003 D11 in one gate: shape and limits, the derived id, the
        // key id against the key offered, and the signature. A caller that wants to
        // read a record it does not intend to believe can `parse_canonical` is private
        // on purpose: refusing to verify is not a supported way to read a record.
        record.verify()?;
        Ok(record)
    }

    /// Shape, derivation and signature (D11).
    pub fn verify(&self) -> HostResult<()> {
        self.validate()?;
        check_one_signature(&self.signatures, &self.author, &self.signing_message()?)
    }

    /// Shape and limit checks (D7).
    pub fn validate(&self) -> HostResult<()> {
        check_schema(self.schema_version, &self.record_type, MERGE_TYPE)?;
        check_author(&self.author)?;
        check_annotations(self.annotations.as_ref())?;
        check_digest(&self.change_digest, "change_digest")?;
        check_branch(&self.base.branch, "base.ref")?;
        check_oid(&self.base.from, "base.from")?;
        check_oid(&self.base.to, "base.to")?;
        if !matches!(self.via.as_str(), "store" | "forge") {
            return Err(HostError::invalid(
                "merge record",
                format!("via '{}' is neither 'store' nor 'forge'", self.via),
            ));
        }
        if self.proofs.len() > MAX_PROOFS {
            return Err(HostError::invalid(
                "merge record",
                format!(
                    "{} proofs exceeds the {MAX_PROOFS} proof limit",
                    self.proofs.len()
                ),
            ));
        }
        for proof in &self.proofs {
            check_digest(proof, "proofs")?;
        }
        if let Some(policy) = &self.policy_digest {
            check_digest(policy, "policy_digest")?;
        }
        Ok(())
    }
}

impl AbandonRecord {
    /// The exact stored bytes (D1).
    pub fn canonical_bytes(&self) -> HostResult<Vec<u8>> {
        canonical(self)
    }

    /// The bytes the abandoner's signature covers (D1).
    pub fn body_bytes(&self) -> HostResult<Vec<u8>> {
        body(self)
    }

    /// The digest of the stored bytes: `kv/abandon/<hex>` (D4).
    pub fn digest(&self) -> HostResult<Oid> {
        record_digest(&self.canonical_bytes()?)
    }

    /// This record's own body digest, as distinct from the `change_digest` field (D4).
    pub fn body_digest(&self) -> HostResult<String> {
        Ok(digest_string(&self.body_bytes()?))
    }

    /// The bytes a signature is made over.
    pub fn signing_message(&self) -> HostResult<Vec<u8>> {
        Ok(pae(ABANDON_PAYLOAD_TYPE, &self.body_bytes()?))
    }

    /// Sign with `key`, returning the signed copy.
    pub fn sign(&self, key: &dyn Signer) -> HostResult<AbandonRecord> {
        let mut signed = self.clone();
        signed.signatures = vec![
            SignatureEntry::new(key, &self.signing_message()?)
                .map_err(|e| HostError::invalid("signature", e.to_string()))?,
        ];
        if signed.author.key_id != key.key_id() {
            return Err(HostError::bad_signature(
                "abandon record",
                format!(
                    "the record is authored by {} but was signed by {}",
                    signed.author.key_id,
                    key.key_id()
                ),
            ));
        }
        signed.verify()?;
        Ok(signed)
    }

    /// Read stored bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> HostResult<AbandonRecord> {
        let record: AbandonRecord = parse_canonical(bytes, "abandon record")?;
        // Steps 1-5 of ADR-0003 D11 in one gate: shape and limits, the derived id, the
        // key id against the key offered, and the signature. A caller that wants to
        // read a record it does not intend to believe can `parse_canonical` is private
        // on purpose: refusing to verify is not a supported way to read a record.
        record.verify()?;
        Ok(record)
    }

    /// Shape, derivation and signature (D11).
    pub fn verify(&self) -> HostResult<()> {
        self.validate()?;
        check_one_signature(&self.signatures, &self.author, &self.signing_message()?)
    }

    /// Shape and limit checks (D7).
    pub fn validate(&self) -> HostResult<()> {
        check_schema(self.schema_version, &self.record_type, ABANDON_TYPE)?;
        check_author(&self.author)?;
        check_annotations(self.annotations.as_ref())?;
        check_digest(&self.change_digest, "change_digest")?;
        if !matches!(
            self.reason.as_str(),
            "superseded" | "withdrawn" | "rejected" | "stale"
        ) {
            return Err(HostError::invalid(
                "abandon record",
                format!(
                    "reason '{}' is not one of superseded, withdrawn, rejected, stale",
                    self.reason
                ),
            ));
        }
        if let Some(note) = &self.note
            && (note.is_empty()
                || note.len() > MAX_ANNOTATION_BYTES
                || note.chars().any(char::is_control))
        {
            return Err(HostError::invalid(
                "abandon record",
                "a note is 1…512 bytes of text with no control characters",
            ));
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------
// the shared checks (ADR-0003 D2, D11)
// --------------------------------------------------------------------------

fn check_schema(schema: u32, seen: &str, want: &str) -> HostResult<()> {
    if schema != SCHEMA_VERSION {
        return Err(HostError::invalid(
            "change record",
            format!("schema_version {schema} is not {SCHEMA_VERSION}"),
        )
        .with_hint("this build does not speak that version; upgrade gitiup"));
    }
    if seen != want {
        return Err(HostError::invalid(
            "change record",
            format!("type '{seen}' is not {want}"),
        ));
    }
    Ok(())
}

fn check_author(author: &Author) -> HostResult<()> {
    check_key_id(&author.key_id)?;
    if author.principal.is_empty() || author.principal.len() > MAX_PRINCIPAL_BYTES {
        return Err(HostError::invalid(
            "author",
            format!(
                "principal is {} bytes; the limit is 1…{MAX_PRINCIPAL_BYTES}",
                author.principal.len()
            ),
        ));
    }
    if author.principal.chars().any(char::is_control) {
        return Err(HostError::invalid(
            "author",
            "principal contains control characters",
        ));
    }
    Ok(())
}

/// A key id is an SSH fingerprint, and — more importantly for a ref name — it may not
/// contain the separator the derivations use.
fn check_key_id(key_id: &str) -> HostResult<()> {
    let Some(body) = key_id.strip_prefix("SHA256:") else {
        return Err(HostError::invalid(
            "author",
            format!("key_id '{key_id}' is not an SSH fingerprint (SHA256:…)"),
        ));
    };
    if body.is_empty()
        || body.len() > 128
        || body.chars().any(char::is_control)
        || key_id.bytes().any(|b| b == 0)
    {
        return Err(HostError::invalid(
            "author",
            "key_id is a SHA256: fingerprint with no control characters",
        ));
    }
    Ok(())
}

fn check_title(title: &str) -> HostResult<()> {
    if title.is_empty() || title.len() > MAX_TITLE_BYTES {
        return Err(HostError::invalid(
            "title",
            format!(
                "title is {} bytes; the limit is 1…{MAX_TITLE_BYTES}",
                title.len()
            ),
        ));
    }
    if title.chars().any(char::is_control) {
        return Err(HostError::invalid(
            "title",
            "a title is one line, in a table, in a terminal, forever: no control characters",
        ));
    }
    Ok(())
}

fn check_oid(text: &str, what: &str) -> HostResult<()> {
    let (algo, hex) = text.split_once(':').unwrap_or(("", text));
    let want = match algo {
        "sha1" => 40,
        "sha256" => 64,
        _ => {
            return Err(HostError::invalid(
                what,
                format!("'{text}' is not an algorithm-tagged oid (sha1:… or sha256:…)"),
            ));
        }
    };
    if hex.len() != want || !lower_hex(hex) {
        return Err(HostError::invalid(
            what,
            format!("'{text}' is not a lower-case hex {algo} oid"),
        ));
    }
    Ok(())
}

fn check_digest(text: &str, what: &str) -> HostResult<()> {
    let Some(hex) = text.strip_prefix("sha256:") else {
        return Err(HostError::invalid(
            what,
            format!("'{text}' is not a sha256:-tagged digest"),
        ));
    };
    if hex.len() != 64 || !lower_hex(hex) {
        return Err(HostError::invalid(
            what,
            format!("'{text}' is not a 64-character lower-case hex digest"),
        ));
    }
    Ok(())
}

fn check_branch(text: &str, what: &str) -> HostResult<()> {
    let name = RefName::new(text)
        .map_err(|e| HostError::invalid(what, format!("'{}' is not a legal ref: {e}", text)))?;
    if !name.is_branch() {
        return Err(
            HostError::invalid(what, format!("'{text}' is not a branch (refs/heads/…)")).with_hint(
                "a change is proposed against a branch, because a merge is a CAS move of \
                 that branch (ADR-0003 D8)",
            ),
        );
    }
    Ok(())
}

fn check_origin(origin: &Origin) -> HostResult<()> {
    match (origin.kind, origin.number) {
        (OriginKind::Store, None) => Ok(()),
        (OriginKind::Store, Some(_)) => Err(HostError::invalid(
            "origin",
            "a store origin carries a number, and a store origin has no forge to get one from",
        )),
        (OriginKind::Pull, Some(number)) if number >= 1 => Ok(()),
        (OriginKind::Pull, Some(_)) => Err(HostError::invalid(
            "origin",
            "a pull origin's number must be 1 or more",
        )),
        (OriginKind::Pull, None) => Err(HostError::invalid(
            "origin",
            "a pull origin must carry the pull request number",
        )),
    }
}

fn check_workflow(workflow: &Workflow) -> HostResult<()> {
    if workflow.jobs.len() > MAX_JOBS {
        return Err(HostError::invalid(
            "workflow",
            format!(
                "{} jobs exceeds the {MAX_JOBS} job limit",
                workflow.jobs.len()
            ),
        ));
    }
    let mut previous: Option<&str> = None;
    for job in &workflow.jobs {
        if job.is_empty()
            || job.len() > MAX_JOB_BYTES
            || !job.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(HostError::invalid(
                "workflow",
                format!("job id '{job}' is not 1…{MAX_JOB_BYTES} printable ASCII characters"),
            ));
        }
        if let Some(previous) = previous {
            match previous.cmp(job.as_str()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(HostError::invalid(
                        "workflow",
                        format!("job '{job}' is listed twice"),
                    )
                    .with_hint("the list is sorted and deduplicated, so two attempts diff"));
                }
                std::cmp::Ordering::Greater => {
                    return Err(HostError::invalid(
                        "workflow",
                        format!("jobs are not sorted: '{previous}' comes after '{job}'"),
                    )
                    .with_hint("sorted, so the same hint always encodes to the same bytes"));
                }
            }
        }
        previous = Some(job.as_str());
    }
    Ok(())
}

fn check_attempts(attempts: &Attempts, head: &str) -> HostResult<()> {
    if attempts.index == 0 {
        if attempts.previous.is_some() {
            return Err(HostError::invalid(
                "attempts",
                "attempt 0 cannot name a predecessor",
            ));
        }
        if attempts.anchor != head {
            return Err(HostError::invalid(
                "attempts",
                format!(
                    "attempt 0 must anchor its own head (anchor {}, head {})",
                    attempts.anchor, head
                ),
            )
            .with_hint(
                "the anchor is the head the change *started* at, and it is what the id \
                 derives from; attempt 0 is that head (ADR-0003 D3)",
            ));
        }
        return Ok(());
    }
    let previous = attempts.previous.as_deref().ok_or_else(|| {
        HostError::invalid(
            "attempts",
            format!(
                "attempt {} must name the attempt it replaces",
                attempts.index
            ),
        )
        .with_hint("attempts.previous is the change_digest of attempt <n-1> (ADR-0003 D6)")
    })?;
    check_digest(previous, "attempts.previous")
}

fn check_annotations(annotations: Option<&BTreeMap<String, String>>) -> HostResult<()> {
    let Some(annotations) = annotations else {
        return Ok(());
    };
    if annotations.len() > MAX_ANNOTATIONS {
        return Err(HostError::invalid(
            "annotations",
            format!(
                "{} annotations exceeds the {MAX_ANNOTATIONS} limit",
                annotations.len()
            ),
        ));
    }
    for (key, value) in annotations {
        if !annotation_key_ok(key) {
            return Err(HostError::invalid(
                "annotations",
                format!("key '{key}' is not x_<producer>_<name> in lower case"),
            ));
        }
        if value.is_empty()
            || value.len() > MAX_ANNOTATION_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(HostError::invalid(
                "annotations",
                format!("the value of '{key}' is 1…{MAX_ANNOTATION_BYTES} bytes of text"),
            ));
        }
    }
    Ok(())
}

/// Lower-case hex only: `sha256:`-tagged digests and `chg-` ids are written by one
/// implementation and a reader that accepts `AA` has two names for one object.
fn lower_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `x_<producer>_<name>`, lower-case, at least two segments after the `x`.
fn annotation_key_ok(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("x_") else {
        return false;
    };
    let mut parts = rest.split('_');
    let (Some(first), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    if first.is_empty() || second.is_empty() {
        return false;
    }
    for part in std::iter::once(first).chain(parts) {
        if part.is_empty()
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

/// Exactly one signature, by the author, over `message` (D2, D11 steps 3–4).
fn check_one_signature(
    signatures: &[SignatureEntry],
    author: &Author,
    message: &[u8],
) -> HostResult<()> {
    if signatures.len() != 1 {
        return Err(HostError::invalid(
            "signature",
            format!(
                "a record carries exactly one signature and this one carries {}",
                signatures.len()
            ),
        )
        .with_hint(
            "two people wanting credit is a new attempt with one author, or a follow-up \
             change — not a second signature on one document (ADR-0003 D2)",
        ));
    }
    let entry = &signatures[0];
    if entry.key_id != author.key_id {
        return Err(HostError::bad_signature(
            "signature",
            format!(
                "the record is authored by {} and signed by {}",
                author.key_id, entry.key_id
            ),
        ));
    }
    entry.verify(message).map_err(|e| {
        HostError::bad_signature("signature", e.to_string()).with_hint(
            "the key id is re-derived from the key offered, so this is either a spoofed \
             identity or bytes that are not the ones that were signed",
        )
    })
}

// --------------------------------------------------------------------------
// publishing (ADR-0003 D5, D6): bytes first, then the attempt ref, then head
// --------------------------------------------------------------------------

/// What [`publish_change`] (or one of the state-record publishers) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// Which change.
    pub change_id: ChangeId,
    /// `sha256(stored bytes)`: the `kv/` key the record was filed under (D4).
    pub record_digest: Oid,
    /// The attempt a change record was published as; `None` for a merge or abandon
    /// record, which are not attempts.
    pub attempt: Option<u32>,
    /// The create-only ref that advertises this record.
    pub reference: RefName,
    /// The `head` ref, for a change record.
    pub head_ref: RefName,
    /// Whether the store already held exactly this (a retry, not a change).
    pub already: bool,
    /// Bytes stored.
    pub size: u64,
}

/// Publish one attempt of a change (D5's write order, D6's CAS rules).
///
/// The order is the contract and must not be reordered: the record bytes, then the
/// create-only attempt ref, then `head` moved under the value this call just read. A
/// crash between any two of those leaves an *inert* store — an object nothing
/// advertises, or an attempt ref `head` has not moved to yet — and the next submit
/// finishes the job rather than tripping over it, because the next index is one past
/// the highest attempt present and not one past what `head` says (D6).
///
/// | step | if it conflicts |
///|------|-----------------|
///| `attempt/<n>` (`Expect::Absent`) | same digest: idempotent success (`already`); different digest: refusal, exit 6, "attempt *n* already exists with a different head" |
///| `head` (`Expect::Is(what we read)`) | [`HostError::Conflict`], exit 6, both digests in the message |
///
/// Nothing here force-pushes. A force-push of a change is a *new attempt*, which is
/// the whole point of the module.
pub fn publish_change(
    host: &dyn Host,
    record: &ChangeRecord,
    actor: impl Into<Actor>,
) -> HostResult<Published> {
    let actor = actor.into();
    // Refuse before touching the store: a record that cannot stand up to a reader
    // should never be half-published (D11).
    record.verify()?;
    let bytes = record.canonical_bytes()?;
    let digest = record.digest()?;
    let id = record.change_id.clone();
    require_cas(host, "publish a change")?;
    if let Some((state, reference)) = closing_ref(host, &id)? {
        return Err(HostError::invalid(
            "change",
            format!("change {id} is {state}; it does not take a new attempt"),
        )
        .with_hint(format!(
            "{reference} already exists. A closed change is closed for good: publish a new \
             change against the new base instead (ADR-0003 D7)"
        )));
    }
    put_record(host, &CHANGE_NAMESPACE, &bytes, &digest)?;

    let attempts = attempt_entries(host, &id)?;
    let index = record.attempts.index;
    let reference = attempt_ref(&id, index);
    let mut attempt_already = false;
    match attempts.iter().find(|(seen, _)| *seen == index) {
        Some((_, seen_digest)) if *seen_digest == digest => attempt_already = true,
        Some((_, seen_digest)) => {
            return Err(
                HostError::conflict(reference.clone(), None, Some(*seen_digest)).with_hint(
                    format!(
                        "attempt {index} of {id} already exists with a different head ({}); a \
                     force-push is attempt {} of its own, and the ref of an attempt that has \
                     attestations must never move (ADR-0003 D6)",
                        seen_digest.short_default(),
                        attempts
                            .iter()
                            .map(|(n, _)| *n)
                            .max()
                            .map(|max| (max + 1).to_string())
                            .unwrap_or_else(|| "0".to_string())
                    ),
                ),
            );
        }
        None => {
            check_chain_position(&attempts, index)?;
            check_previous(host, &attempts, record)?;
            host.update_ref_cas(
                &RefUpdate::create(reference.clone(), digest)
                    .with_actor(actor.clone())
                    .with_message(format!("change {id} attempt {index}"))
                    .with_parents(parents_for(record, &id, index)),
            )?;
        }
    }

    let head = change_head_ref(&id);
    let mut head_already = false;
    match host.get_ref(&head)? {
        Some(current) if current.oid == digest => head_already = true,
        Some(current) => {
            host.update_ref_cas(
                &RefUpdate::replace(head.clone(), current.oid, digest)
                    .with_actor(actor.clone())
                    .with_message(format!("change {id} -> attempt {index}"))
                    .with_parents(parents_for(record, &id, index)),
            )?;
        }
        None => {
            host.update_ref_cas(
                &RefUpdate::create(head.clone(), digest)
                    .with_actor(actor.clone())
                    .with_message(format!("change {id} opened, attempt {index}"))
                    .with_parents(parents_for(record, &id, index)),
            )?;
        }
    }

    Ok(Published {
        change_id: id,
        record_digest: digest,
        attempt: Some(index),
        reference,
        head_ref: head,
        already: attempt_already && head_already,
        size: bytes.len() as u64,
    })
}

/// File a merge record and advertise it with the create-only `merged` ref (D7, D8).
///
/// Create-only is the rule that makes a change mergeable exactly once: a second merge
/// is a conflict naming the first, not a re-merge. If the attempt the record names is
/// present in this store, the record must match it — a merge record that disagrees with
/// the attempt it cites is refused here rather than by a human later.
pub fn publish_merge(
    host: &dyn Host,
    record: &MergeRecord,
    actor: impl Into<Actor>,
) -> HostResult<Published> {
    let actor = actor.into();
    record.verify()?;
    let bytes = record.canonical_bytes()?;
    let digest = record.digest()?;
    require_cas(host, "publish a merge record")?;
    let reference = merged_ref(&record.change_id);
    check_state_absent(host, &reference, &record.change_id, "merged")?;
    put_record(host, &MERGE_NAMESPACE, &bytes, &digest)?;
    check_attempt_matches(
        host,
        record.change_id.as_str(),
        record.attempt,
        &record.change_digest,
    )?;
    host.update_ref_cas(
        &RefUpdate::create(reference.clone(), digest)
            .with_actor(actor)
            .with_message(format!("change {} merged", record.change_id)),
    )?;
    Ok(Published {
        change_id: record.change_id.clone(),
        record_digest: digest,
        attempt: Some(record.attempt),
        reference: reference.clone(),
        head_ref: change_head_ref(&record.change_id),
        already: false,
        size: bytes.len() as u64,
    })
}

/// File an abandon record and advertise it with the create-only `abandoned` ref (D7).
pub fn publish_abandon(
    host: &dyn Host,
    record: &AbandonRecord,
    actor: impl Into<Actor>,
) -> HostResult<Published> {
    let actor = actor.into();
    record.verify()?;
    let bytes = record.canonical_bytes()?;
    let digest = record.digest()?;
    require_cas(host, "publish an abandon record")?;
    let reference = abandoned_ref(&record.change_id);
    check_state_absent(host, &reference, &record.change_id, "abandoned")?;
    put_record(host, &ABANDON_NAMESPACE, &bytes, &digest)?;
    check_attempt_matches(
        host,
        record.change_id.as_str(),
        record.attempt,
        &record.change_digest,
    )?;
    host.update_ref_cas(
        &RefUpdate::create(reference.clone(), digest)
            .with_actor(actor)
            .with_message(format!("change {} abandoned", record.change_id)),
    )?;
    Ok(Published {
        change_id: record.change_id.clone(),
        record_digest: digest,
        attempt: Some(record.attempt),
        reference,
        head_ref: change_head_ref(&record.change_id),
        already: false,
        size: bytes.len() as u64,
    })
}

/// Store record bytes and insist the store filed them under *their own* digest.
///
/// A store that returns another digest is not storing these bytes verbatim, and every
/// signature over them becomes worthless — the same refusal [`crate::attest`] makes.
fn put_record(host: &dyn Host, namespace: &Namespace, bytes: &[u8], want: &Oid) -> HostResult<()> {
    let stored = host.put_cas(namespace, bytes)?;
    if &stored != want {
        return Err(HostError::digest_mismatch(
            "change store",
            format!(
                "the store filed {} bytes under {} instead of {}",
                bytes.len(),
                stored.short_default(),
                want.short_default()
            ),
        )
        .with_hint("this host is not storing blobs verbatim; nothing signed can be trusted here"));
    }
    Ok(())
}

fn require_cas(host: &dyn Host, what: &str) -> HostResult<()> {
    if host.capabilities().cas {
        return Ok(());
    }
    Err(HostError::unsupported(
        "cas",
        format!("this host cannot compare-and-swap a ref, so it cannot {what}"),
    )
    .with_hint(
        "a change is a ref, and a ref without compare-and-swap is a race: an S3 bucket \
         needs conditional writes, a git host needs `--force-with-lease` (ADR-0003 D8)",
    ))
}

/// The parents a git host should attach the pointer commit to (D5's first requirement):
/// the commit being proposed, and the previous attempt's pointer commit.
fn parents_for(record: &ChangeRecord, id: &ChangeId, index: u32) -> Vec<RefParent> {
    let mut parents = Vec::new();
    if let Some(oid) = commit_oid(&record.head) {
        parents.push(RefParent::Commit(oid));
    }
    if index > 0 {
        parents.push(RefParent::Ref(attempt_ref(id, index - 1)));
    }
    parents
}

/// The bare hex of an algorithm-tagged oid, for hosts that speak to git.
fn commit_oid(tagged: &str) -> Option<Oid> {
    let hex = tagged.split_once(':').map(|(_, hex)| hex).unwrap_or(tagged);
    Oid::from_hex(hex).ok()
}

/// `(index, record digest)` for every `refs/changes/<id>/attempt/<n>`, oldest first.
fn attempt_entries(host: &dyn Host, id: &ChangeId) -> HostResult<Vec<(u32, Oid)>> {
    let refs = host.list_refs(&RefQuery::prefix(change_prefix(id)))?;
    let mut out: Vec<(u32, Oid)> = refs
        .iter()
        .filter_map(|reference| match parse_ref(&reference.name) {
            Some(ChangeRef::Attempt { id: seen, index }) if seen == *id => {
                Some((index, reference.oid))
            }
            _ => None,
        })
        .collect();
    out.sort();
    Ok(out)
}

/// A create-only state ref that is already taken is a conflict, not a second state (D7).
fn check_state_absent(
    host: &dyn Host,
    reference: &RefName,
    id: &ChangeId,
    state: &str,
) -> HostResult<()> {
    if let Some(existing) = host.get_ref(reference)? {
        return Err(
            HostError::conflict(reference.clone(), None, Some(existing.oid)).with_hint(format!(
                "change {id} is already {state} ({}); a change is {state} exactly once, and \
             un-doing a merge is a new change, not an edit (ADR-0003 D7)",
                existing.oid.short_default()
            )),
        );
    }
    Ok(())
}

/// Which closing ref exists, if any (D7's precedence: merged, then abandoned).
fn closing_ref(host: &dyn Host, id: &ChangeId) -> HostResult<Option<(String, RefName)>> {
    if let Some(reference) = host.get_ref(&merged_ref(id))? {
        return Ok(Some((
            format!("merged ({})", reference.oid.short_default()),
            merged_ref(id),
        )));
    }
    if let Some(reference) = host.get_ref(&abandoned_ref(id))? {
        return Ok(Some((
            format!("abandoned ({})", reference.oid.short_default()),
            abandoned_ref(id),
        )));
    }
    Ok(None)
}

/// The new attempt must be one past the highest present (D6). Anything else means the
/// caller is racing, crashed mid-submit, or is lying about its history.
fn check_chain_position(attempts: &[(u32, Oid)], index: u32) -> HostResult<()> {
    let highest = attempts.iter().map(|(n, _)| *n).max();
    let Some(highest) = highest else {
        if index == 0 {
            return Ok(());
        }
        return Err(HostError::invalid(
            "change",
            format!("attempt {index} claims a predecessor, and this store has no attempts at all"),
        )
        .with_hint("publish attempt 0 first; the chain is what makes an attempt auditable"));
    };
    if index > highest + 1 {
        return Err(HostError::invalid(
            "change",
            format!(
                "attempt {index} leaves a gap: the highest attempt here is {highest}, so \
                 attempt {} is missing",
                highest + 1
            ),
        )
        .with_hint(
            "the next attempt is always one past the highest present, which is how a submit \
             that crashed mid-write is finished rather than repaired (ADR-0003 D6)",
        ));
    }
    Ok(())
}

/// If the attempt this record supersedes is in this store, it must be the one named.
fn check_previous(
    host: &dyn Host,
    attempts: &[(u32, Oid)],
    record: &ChangeRecord,
) -> HostResult<()> {
    if record.attempts.index == 0 {
        return Ok(());
    }
    let Some((_, previous_digest)) = attempts
        .iter()
        .find(|(n, _)| *n + 1 == record.attempts.index)
    else {
        // The gap check above already refused a missing link, so this only happens when
        // a mirror holds the head of a chain it did not fetch; not a lie, just unknown.
        return Ok(());
    };
    let previous = match read_stored(host, previous_digest)? {
        Some((StoredRecord::Change(previous), _)) => previous,
        Some((other, _)) => {
            return Err(HostError::digest_mismatch(
                "change",
                format!(
                    "attempt {} is filed where a {} record lives",
                    record.attempts.index - 1,
                    other.record_type()
                ),
            ));
        }
        // The ref is there and the bytes are not: a half-replicated mirror. The attempt
        // ref is the advertisement and it exists, so refuse only for a *known* mismatch.
        None => return Ok(()),
    };
    if previous.change_digest()? != record.attempts.previous.as_deref().unwrap_or_default() {
        return Err(HostError::digest_mismatch(
            "change",
            format!(
                "attempt {} names {}, but attempt {} is {}",
                record.attempts.index,
                record.attempts.previous.as_deref().unwrap_or("(nothing)"),
                record.attempts.index - 1,
                previous.change_digest()?
            ),
        )
        .with_hint("attempts.previous is the change_digest of the attempt it replaces"));
    }
    Ok(())
}

/// A merge or abandon record must agree with the attempt it names, when this store has it.
fn check_attempt_matches(
    host: &dyn Host,
    id: &str,
    attempt: u32,
    change_digest: &str,
) -> HostResult<()> {
    let id = ChangeId::new(id)?;
    let Some(current) = host.get_ref(&attempt_ref(&id, attempt))? else {
        return Ok(());
    };
    let Some((StoredRecord::Change(record), _)) = read_stored(host, &current.oid)? else {
        return Ok(());
    };
    if record.change_digest()? != change_digest {
        return Err(HostError::digest_mismatch(
            "change",
            format!(
                "the record cites change_digest {} for attempt {attempt}, which is {}",
                change_digest,
                record.change_digest()?
            ),
        )
        .with_hint("a merge or abandon record names an attempt, and must name the one it saw"));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// merging (ADR-0003 D8): a CAS move of the branch, then the record of it
// --------------------------------------------------------------------------

/// Who moved the branch (D7's `via`, D8's two ways to merge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// gitiup moved `refs/heads/<base>` with a compare-and-swap.
    Store,
    /// A forge moved it, and this record was written afterwards by whoever ran
    /// `change reconcile` (D10: a forge's merge button *is* the merge).
    Forge,
}

impl Via {
    /// The `via` string the record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Store => "store",
            Via::Forge => "forge",
        }
    }

    /// Read the `via` string back, refusing anything else: a merge record that says
    /// neither `store` nor `forge` is a record this build cannot explain (D7).
    pub fn parse(text: &str) -> HostResult<Via> {
        match text {
            "store" => Ok(Via::Store),
            "forge" => Ok(Via::Forge),
            other => Err(HostError::invalid(
                "via",
                format!("'{other}' is neither 'store' nor 'forge'"),
            )),
        }
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the caller can honestly say about `from` being an ancestor of `to` (D8 step 4).
///
/// The test is not computed *here*: answering it needs the commit objects, and a store
/// holds those as opaque bytes while the caller holds them in a repository. So the
/// caller — the only party that can look — says which of these three it knows, and
/// [`merge`] refuses `Unknown` rather than guessing. That is the whole of C4: the CAS
/// says nobody moved the branch, the ancestry test says nobody's work is dropped, and a
/// merge with neither is a force-push with good manners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ancestry {
    /// `from` is an ancestor of `to`, checked on objects the caller has.
    FastForward,
    /// `from` is not an ancestor of `to`: the branch has moved somewhere the change does
    /// not include.
    Diverged,
    /// The caller could not tell, and says why. Refused, not waved through.
    Unknown(String),
}

impl Ancestry {
    /// A stable word for `--json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Ancestry::FastForward => "fast-forward",
            Ancestry::Diverged => "diverged",
            Ancestry::Unknown(_) => "unknown",
        }
    }

    /// The caller's reason, when there is no verdict.
    pub fn why(&self) -> Option<&str> {
        match self {
            Ancestry::Unknown(why) => Some(why.as_str()),
            _ => None,
        }
    }
}

/// Everything [`merge`] needs that a store cannot decide for itself.
///
/// Built with [`MergeRequest::new`] plus a few `with_*` calls; the fields are public so a
/// caller can build one from its own arguments. (`Signer` is not `Debug`, so neither is
/// this: describe the request by its plan instead.)
#[derive(Clone)]
pub struct MergeRequest<'a> {
    /// The attempt being merged, already read and verified (D8 step 1).
    pub record: &'a ChangeRecord,
    /// The key that signs the merge record: whoever's credential moved the branch.
    pub signer: &'a dyn Signer,
    /// The `author` of the merge record — the merger, not the change's author (D7).
    pub merger: Author,
    /// The actor to record on the ref writes.
    pub actor: Actor,
    /// What the branch must hold, overriding the record's own `base.oid` (D8 step 3).
    pub expected: Option<Oid>,
    /// The caller's answer to "is this a fast-forward?" (D8 step 4).
    pub ancestry: Ancestry,
    /// Attestation record digests this merge believed, in the order believed (D8).
    pub proofs: Vec<String>,
    /// Reserved for Epic 2; `None` means no policy was applied, and the record says so.
    pub policy_digest: Option<String>,
    /// Store or forge (D7's `via`).
    pub via: Via,
    /// The claimed merge time in microseconds; `None` is now.
    pub at_us: Option<i64>,
    /// Where a forge's merge left the branch, when that is not the attempt's head
    /// ([`MergeRequest::with_landing`]).
    pub landed: Option<Oid>,
}

impl<'a> MergeRequest<'a> {
    /// The minimal request: this attempt, signed by this key. The ancestry starts
    /// `Unknown`, which is itself a refusal — every caller has to answer it with
    /// [`MergeRequest::with_ancestry`], because a merge that cannot say it is a
    /// fast-forward is not a merge.
    pub fn new(record: &'a ChangeRecord, signer: &'a dyn Signer, merger: Author) -> Self {
        let actor = Actor::from(short_key(&merger.key_id));
        MergeRequest {
            record,
            signer,
            merger,
            actor,
            expected: None,
            ancestry: Ancestry::Unknown("the caller did not say".to_string()),
            proofs: Vec::new(),
            policy_digest: None,
            via: Via::Store,
            at_us: None,
            landed: None,
        }
    }

    /// Expect the branch to hold `oid` rather than the record's `base.oid`.
    pub fn with_expected(mut self, oid: Oid) -> Self {
        self.expected = Some(oid);
        self
    }

    /// Say what the caller knows about the ancestry.
    pub fn with_ancestry(mut self, ancestry: Ancestry) -> Self {
        self.ancestry = ancestry;
        self
    }

    /// Cite one proof digest (D8: digests, never copies, in the order believed).
    pub fn with_proof(mut self, digest: impl Into<String>) -> Self {
        self.proofs.push(digest.into());
        self
    }

    /// The actor to record on the writes.
    pub fn with_actor(mut self, actor: impl Into<Actor>) -> Self {
        self.actor = actor.into();
        self
    }

    /// Claim a merge time (microseconds) instead of the clock.
    pub fn at(mut self, us: i64) -> Self {
        self.at_us = Some(us);
        self
    }

    /// This is a forge's merge being recorded, not a CAS write (D10).
    pub fn via_forge(mut self) -> Self {
        self.via = Via::Forge;
        self
    }

    /// The policy digest Epic 2 would have supplied, if there were one.
    pub fn with_policy(mut self, digest: impl Into<String>) -> Self {
        self.policy_digest = Some(digest.into());
        self
    }

    /// Say where a forge's merge left the branch, when that is not the attempt's head
    /// (a forge's merge commit, for instance).
    ///
    /// Only [`record_merge`] asks, and only it may answer: the branch already moved, so
    /// this is a report of where it landed, never a value to write (D10).
    pub fn with_landing(mut self, oid: Oid) -> Self {
        self.landed = Some(oid);
        self
    }
}

/// What a merge *would* do, computed before anything is written — which is what makes
/// `--dry-run` a plan and not a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergePlan {
    /// Which change.
    pub change_id: ChangeId,
    /// Which attempt of it.
    pub attempt: u32,
    /// The `change_digest` the merge record will cite (D4: the attempt's, never the
    /// merge's own body digest).
    pub change_digest: String,
    /// The branch the CAS moves.
    pub branch: RefName,
    /// What the CAS expects to find — the record's `base.oid`, or the caller's
    /// `--expected-oid`.
    pub from: Oid,
    /// What the CAS writes: the attempt's `head`.
    pub to: Oid,
    /// What the branch holds right now, which the comparison above just proved is `from`.
    pub store_oid: Oid,
    /// The `base.oid` the author signed, which is not `from` when the caller overrode
    /// it — a fact the output has to show rather than hide.
    pub signed_base: String,
    /// Whether `from` came from the caller and not from the record.
    pub base_overridden: bool,
    /// The create-only ref that will advertise the merge record.
    pub merged_ref: RefName,
    /// Where the record will be filed: `kv/merge/<hex>` once the bytes exist, and the
    /// namespace alone in a dry run, which has no bytes to hash yet.
    pub kv: String,
    /// The proof digests that will be cited.
    pub proofs: Vec<String>,
    /// Store or forge.
    pub via: Via,
    /// Anything the caller should say out loud alongside the plan.
    pub notes: Vec<String>,
    /// Whether a forge, not gitiup, made the merge.
    ///
    /// The two are not the same promise — a forge's merge is atomic and reviewed, a
    /// bucket's is a conditional write — so a machine reading this should not have to
    /// guess which one happened from the transport.
    pub via_forge: bool,
    /// Whether the branch was already where the change wanted (D8's failure window, or a
    /// forge's merge) rather than moved by this call.
    pub reconciled: bool,
}

impl MergePlan {
    /// The same facts as the words a person reads.
    pub fn summary(&self) -> String {
        format!(
            "move {} {} → {}, then file the merge record at {}",
            self.branch, self.from, self.to, self.kv
        )
    }
}

/// What [`merge`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    /// The plan that was executed.
    pub plan: MergePlan,
    /// Whether this call moved the branch. `false` means the branch already stood where
    /// the change wanted and only the record was missing ([`record_merge`]).
    pub moved: bool,
    /// The signed merge record.
    pub record: MergeRecord,
    /// `sha256(record bytes)` — the `kv/merge/<hex>` key.
    pub record_digest: Oid,
    /// The ref advertising it.
    pub reference: RefName,
    /// Bytes stored.
    pub size: u64,
    /// How many cited proofs retention must now keep ([`proof_pins`]).
    pub proofs_pinned: usize,
}

/// Every step of D8 up to and including the comparison, and nothing after it: the
/// read-only half of a merge, which is also what `--dry-run` prints.
///
/// Refusals, in the order they are checked — which is *most specific fact first* rather
/// than D8's step order, because the reader has to be told the true reason:
///
/// | check | refusal |
///|-------|---------|
///| the host cannot CAS | [`HostError::UnsupportedCas`], exit 6 |
///| the record is not what it claims | its own code (6/7/8) |
///| the branch does not exist | 6, naming the branch |
///| the change is already merged or abandoned | [`HostError::Conflict`], 6 |
///| the branch already is the change's head | 6, pointing at `change reconcile` |
///| the branch is not the expected oid | 6, naming **both** oids — "pull first" |
///
/// The last two are ordered that way because D8's failure window produces both conditions
/// at once: a branch sitting at the change's head has by definition left its base. Saying
/// "stale base, pull first" about a change that is already merged and merely missing its
/// record would send the reader to rebase work they have already done.
pub fn plan_merge(host: &dyn Host, request: &MergeRequest<'_>) -> HostResult<MergePlan> {
    let record = request.record;
    require_cas(host, "merge a change")?;
    // D11 before the store: a record that cannot stand up to a reader must not be
    // half-merged.
    record.verify()?;
    if request.proofs.len() > MAX_PROOFS {
        return Err(HostError::invalid(
            "merge",
            format!(
                "{} proofs is more than the {MAX_PROOFS} a merge record may cite",
                request.proofs.len()
            ),
        ));
    }
    for proof in &request.proofs {
        check_digest(proof, "proofs")?;
    }
    let branch = RefName::new(&record.base.branch)?;
    let signed_base = record.base.oid.clone();
    let base_oid = oid_of(&signed_base, "base.oid")?;
    let to = oid_of(&record.head, "head")?;
    let from = request.expected.unwrap_or(base_oid);

    // Step 2: the fresh read. This read *is* the lease — everything after it is a CAS
    // against exactly what was just seen.
    let store = host.get_ref(&branch)?.ok_or_else(|| {
        HostError::invalid(
            "branch",
            format!("the store has no {} to merge into", record.base.branch),
        )
        .with_hint(
            "a merge is a compare-and-swap of a branch the store has; publish the branch \
             first, which is the owner's act and is done with plain `git push`",
        )
    })?;
    // D7's state first, ahead of the base comparison: "this change is already merged" is
    // a truer and more useful sentence than "your base is stale" about the same store
    // state, because a merge whose record failed to land leaves the branch at the change's
    // head *and* the base looking stale. A change is closed exactly once (D7).
    let merged = merged_ref(&record.change_id);
    if let Some(existing) = host.get_ref(&merged)? {
        return Err(
            HostError::conflict(merged.clone(), None, Some(existing.oid)).with_hint(format!(
                "change {} is already merged ({}); un-doing a merge is a new change, not a \
                 second one (ADR-0003 D7)",
                record.change_id,
                existing.oid.short_default()
            )),
        );
    }
    if let Some(abandoned) = host.get_ref(&abandoned_ref(&record.change_id))? {
        return Err(HostError::conflict(
            abandoned_ref(&record.change_id),
            None,
            Some(abandoned.oid),
        )
        .with_hint(format!(
            "change {} was abandoned ({}); a change is closed for good, and the work \
                     it wanted is a new change against the new base",
            record.change_id,
            abandoned.oid.short_default()
        )));
    }
    if to == store.oid {
        return Err(HostError::invalid(
            "merge",
            format!(
                "{} already is {}, so there is nothing to merge",
                record.base.branch,
                spell(&store.oid, &signed_base)
            ),
        )
        .with_hint(format!(
            "if this change was merged and its record did not land, `gitiup change \
             reconcile {}` writes the record for the move the store already has (ADR-0003 \
             D8's failure window)",
            record.change_id
        )));
    }
    // Step 3, spelled with both oids because the only useful advice is "pull first" and
    // the person reading it has to know which of the two moved.
    if store.oid != from {
        return Err(HostError::invalid(
            "stale base",
            format!(
                "{} is {} in this record and {} in the store",
                record.base.branch,
                spell(&from, &signed_base),
                spell(&store.oid, &signed_base)
            ),
        )
        .with_hint(format!(
            "pull first: the branch moved, and merging this attempt would drop whatever \
             moved it. Rebase onto {} (or re-draft from it) and submit a new attempt, or \
             name the oid you are really standing on with --expected-oid (ADR-0003 D8 \
             step 3)",
            spell(&store.oid, &signed_base)
        )));
    }

    let mut notes = Vec::new();
    if from != base_oid {
        notes.push(format!(
            "the base was named by the caller: the author signed {} and the CAS expects {}",
            spell(&base_oid, &signed_base),
            spell(&from, &signed_base)
        ));
    }
    if record.origin.kind == OriginKind::Pull {
        notes.push(format!(
            "this change is carried by {}; on a forge the forge's own merge is the merge, \
             and the record says `via: forge`",
            record
                .origin
                .number
                .map(|number| format!("pull request {number}"))
                .unwrap_or_else(|| "a pull request".to_string())
        ));
    }
    Ok(MergePlan {
        change_id: record.change_id.clone(),
        attempt: record.attempts.index,
        change_digest: record.change_digest()?,
        branch,
        from,
        to,
        store_oid: store.oid,
        signed_base,
        base_overridden: from != base_oid,
        merged_ref: merged,
        // A dry run has no bytes to hash yet, so it names the namespace it will land in.
        kv: format!("kv/{}", MERGE_NAMESPACE.as_str()),
        proofs: request.proofs.clone(),
        via: request.via,
        notes,
        via_forge: request.via == Via::Forge,
        reconciled: false,
    })
}

/// Merge one attempt: a compare-and-swap fast-forward of the branch, then the signed
/// record of it (D8 steps 4–7, in that order and for the reason given there).
///
/// The branch moves first and the record second, deliberately. A crash in between leaves
/// a branch that moved without a record, which is a *detectable* silence (D7's
/// `unrecorded` flag, closed by [`record_merge`]); the reverse order would leave a signed
/// record claiming a merge that never happened — a false statement by an honest key, and
/// invisible from the store. So a failure at step 7 is reported with the exact retry
/// rather than papered over as "rolled back": there is no transaction to roll back with.
///
/// A refusal from the store itself — a non-owner credential, a hook that says no — is
/// passed through **unedited**: same kind, same message, same exit code. The store
/// answered the question that was asked, and rewriting "not allowed to update
/// refs/heads/main" into an I/O error loses the only useful sentence in the run.
pub fn merge(host: &dyn Host, request: &MergeRequest<'_>) -> HostResult<MergeOutcome> {
    let plan = plan_merge(host, request)?;
    // Step 4: the fast-forward, on the caller's objects.
    match &request.ancestry {
        Ancestry::FastForward => {}
        Ancestry::Diverged => {
            return Err(HostError::invalid(
                "not a fast-forward",
                format!(
                    "{} is not an ancestor of {}, so merging would drop commits",
                    plan.from, plan.to
                ),
            )
            .with_hint(
                "rebase the change onto the branch, or merge the branch into the change and \
                 re-submit it as a new attempt; gitiup merges by fast-forward only, because \
                 a merge commit exists only after the merge and no proof can cover it \
                 (ADR-0003 D8)",
            ));
        }
        Ancestry::Unknown(why) => {
            return Err(HostError::invalid(
                "ancestry",
                format!(
                    "nothing says whether {} is an ancestor of {}: {why}",
                    plan.from, plan.to
                ),
            )
            .with_hint(
                "refusing to guess a fast-forward is the point: fetch the change into a \
                 repository — `git fetch <remote> 'refs/changes/<id>/*'` carries the record \
                 and the commits in one packfile — and run the merge there",
            ));
        }
    }

    // Step 6: the fact. No wrapping: a refusal here is the store's own sentence.
    host.update_ref_cas(
        &RefUpdate::replace(plan.branch.clone(), plan.from, plan.to)
            .with_actor(request.actor.clone())
            .with_message(format!(
                "merge {} attempt {} ({} → {})",
                plan.change_id, plan.attempt, plan.from, plan.to
            )),
    )?;

    // Step 7: its record. A failure here is the named, incomplete state, not a rollback.
    let record = build_merge_record(host, request, &plan).map_err(|why| {
        HostError::invalid(
            "incomplete merge",
            format!(
                "{} moved {} → {}, and the merge record did not land: {why}",
                plan.branch, plan.from, plan.to
            ),
        )
        .with_exit_code(why.exit_code())
        .with_hint(format!(
            "the branch has the merge and the store does not have its record yet: `gitiup \
             change reconcile {}` writes the record for a move the store already has \
             (ADR-0003 D8)",
            plan.change_id
        ))
    })?;
    let size = record.canonical_bytes()?.len() as u64;
    let record_digest = record.digest()?;
    let reference = publish_merge_record(host, &record, &request.actor)?;
    let mut plan = plan;
    plan.kv = kv_key(&MERGE_NAMESPACE, &record_digest);
    Ok(MergeOutcome {
        proofs_pinned: record.proofs.len(),
        moved: true,
        size,
        plan,
        record_digest,
        reference,
        record,
    })
}

/// Write the record for a merge the store already has: `refs/heads/<base>` already stands
/// at the attempt's head and there is no `merged` ref (D7's `unrecorded`, D8's failure
/// window — and the shape a forge's merge is recorded with, `via: forge`).
///
/// Unlike [`merge`] this writes no branch: the fact already happened, and a record that
/// moved the branch it was only meant to describe would be a record about something that
/// did not happen the way it says.
pub fn record_merge(host: &dyn Host, request: &MergeRequest<'_>) -> HostResult<MergeOutcome> {
    let record = request.record;
    require_cas(host, "record a merge")?;
    record.verify()?;
    for proof in &request.proofs {
        check_digest(proof, "proofs")?;
    }
    let branch = RefName::new(&record.base.branch)?;
    let to = oid_of(&record.head, "head")?;
    let signed_base = record.base.oid.clone();
    let store = host.get_ref(&branch)?.ok_or_else(|| {
        HostError::invalid("branch", format!("the store has no {}", record.base.branch))
            .with_hint("there is no move to record without a branch that could have moved")
    })?;
    let from = request
        .expected
        .unwrap_or(oid_of(&signed_base, "base.oid")?);
    // A store merge moved the branch to the attempt's head, so that is what a record of
    // it has to find. A forge merge moved it to whatever the forge builds — its own
    // merge commit, usually — so the caller reports where it landed and the record says
    // that, because a merge record may only state what the store shows (D10).
    let to = match request.landed {
        Some(landed) if request.via == Via::Forge => {
            if store.oid != landed {
                return Err(HostError::invalid(
                    "nothing to reconcile",
                    format!(
                        "{} is {} in the store and the forge said it landed at {}",
                        record.base.branch,
                        spell(&store.oid, &signed_base),
                        spell(&landed, &signed_base)
                    ),
                )
                .with_hint(
                    "the forge's answer and the store's do not agree; record the merge \
                     from whichever one you can show (ADR-0003 D10)",
                ));
            }
            landed
        }
        _ => {
            if store.oid != to {
                return Err(HostError::invalid(
                    "nothing to reconcile",
                    format!(
                        "{} is {} in the store and attempt {} proposes {}",
                        record.base.branch,
                        spell(&store.oid, &signed_base),
                        record.attempts.index,
                        spell(&to, &signed_base)
                    ),
                )
                .with_hint(
                    "a merge record describes a move the store has. If the branch has not \
                     moved, that is `gitiup change merge`; if it moved to something else, \
                     that is a different change (ADR-0003 D8)",
                ));
            }
            to
        }
    };
    let plan = MergePlan {
        change_id: record.change_id.clone(),
        attempt: record.attempts.index,
        change_digest: record.change_digest()?,
        branch,
        from,
        to,
        store_oid: store.oid,
        signed_base,
        // The move is a fact; the "from" is the point the record was signed against,
        // which is what a reconcile can honestly claim.
        base_overridden: true,
        merged_ref: merged_ref(&record.change_id),
        kv: format!("kv/{}", MERGE_NAMESPACE.as_str()),
        proofs: request.proofs.clone(),
        via: request.via,
        notes: vec![
            "the branch had already moved; this record describes a merge that happened \
             without one"
                .to_string(),
        ],
        via_forge: request.via == Via::Forge,
        reconciled: true,
    };
    let record = build_merge_record(host, request, &plan)?;
    let size = record.canonical_bytes()?.len() as u64;
    let record_digest = record.digest()?;
    let reference = publish_merge_record(host, &record, &request.actor)?;
    let mut plan = plan;
    plan.kv = kv_key(&MERGE_NAMESPACE, &record_digest);
    Ok(MergeOutcome {
        proofs_pinned: record.proofs.len(),
        moved: false,
        size,
        plan,
        record_digest,
        reference,
        record,
    })
}

/// Build, sign and file the merge record D8 asks for, without advertising it.
///
/// The bytes go through the same gates [`publish_merge`] uses — the store must file them
/// under their own digest, and a merge record that disagrees with the attempt it names is
/// refused by `check_attempt_matches` — so a merge cannot cite an attempt it did not see.
fn build_merge_record(
    host: &dyn Host,
    request: &MergeRequest<'_>,
    plan: &MergePlan,
) -> HostResult<MergeRecord> {
    let record = request.record;
    let unsigned = MergeRecord {
        change_digest: plan.change_digest.clone(),
        change_id: record.change_id.clone(),
        attempt: record.attempts.index,
        base: MergeBase {
            branch: record.base.branch.clone(),
            from: spell(&plan.from, &plan.signed_base),
            to: spell(&plan.to, &plan.signed_base),
        },
        merged_at_us: request
            .at_us
            .unwrap_or_else(|| Timestamp::now().as_unix() as i64 * 1_000_000),
        via: request.via.as_str().to_string(),
        proofs: request.proofs.clone(),
        policy_digest: request.policy_digest.clone(),
        author: request.merger.clone(),
        schema_version: SCHEMA_VERSION,
        record_type: MERGE_TYPE.to_string(),
        signatures: Vec::new(),
        annotations: None,
    };
    let signed = unsigned.sign(request.signer)?;
    let bytes = signed.canonical_bytes()?;
    let digest = signed.digest()?;
    require_cas(host, "publish a merge record")?;
    check_state_absent(host, &plan.merged_ref, &record.change_id, "merged")?;
    put_record(host, &MERGE_NAMESPACE, &bytes, &digest)?;
    check_attempt_matches(
        host,
        record.change_id.as_str(),
        record.attempts.index,
        &plan.change_digest,
    )?;
    Ok(signed)
}

/// File the create-only `merged` ref that makes a merge record a state (D7).
fn publish_merge_record(
    host: &dyn Host,
    record: &MergeRecord,
    actor: &Actor,
) -> HostResult<RefName> {
    let digest = record.digest()?;
    let reference = merged_ref(&record.change_id);
    host.update_ref_cas(
        &RefUpdate::create(reference.clone(), digest)
            .with_actor(actor.clone())
            .with_message(format!("change {} merged", record.change_id)),
    )?;
    Ok(reference)
}

/// A change that is merged in fact and not in record (D7's `unrecorded` flag).
///
/// The fact happened and its record did not land: `refs/heads/<base>` stands at the head
/// of one of the change's attempts and there is no `merged` ref. This is the *detectable*
/// half of D8's failure window, and it is printed rather than quietly reconciled — a
/// merge record is a claim about who merged on what proof, and a tool cannot invent the
/// beliefs of whoever did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrecorded {
    /// Which attempt the branch now carries.
    pub attempt: u32,
    /// The branch that moved.
    pub branch: RefName,
    /// The commit it carries, which is the attempt's head.
    pub head: String,
    /// What the branch holds (the same commit, spelled as the store spells it).
    pub store_oid: Oid,
}

/// Whether a change's newest attempt is sitting on the base branch with no merge record.
///
/// Only the newest attempt is looked at: a merge is a move to the newest head, so an
/// *older* attempt on the branch tip is either a much older failure window (which
/// `change_history` still shows) or a coincidence of oids that is not this change's
/// business.
pub fn unrecorded_merge(
    host: &dyn Host,
    summary: &ChangeSummary,
) -> HostResult<Option<Unrecorded>> {
    if summary.merged.is_some() || summary.abandoned.is_some() {
        return Ok(None);
    }
    let Some(digest) = summary.newest_attempt_digest() else {
        return Ok(None);
    };
    let Some((StoredRecord::Change(record), _)) = read_stored(host, &digest)? else {
        return Ok(None);
    };
    let branch = RefName::new(&record.base.branch)?;
    let Some(store) = host.get_ref(&branch)? else {
        return Ok(None);
    };
    let Ok(head) = oid_of(&record.head, "head") else {
        return Ok(None);
    };
    if store.oid != head {
        return Ok(None);
    }
    Ok(Some(Unrecorded {
        attempt: record.attempts.index,
        branch,
        head: record.head.clone(),
        store_oid: store.oid,
    }))
}

/// Every proof digest cited by a merge record in this store, mapped to why it is pinned.
///
/// This is [`crate::attest::pin`] made automatic instead of left to the operator: a digest
/// inside a record is not a ref, so [`crate::attest::referenced`] cannot see it, and a
/// merge whose cited proof has since been pruned is a merge that cannot be audited. Anyone
/// running `attest gc` owes these digests a pin, and this is how they pay it without
/// knowing what a merge is.
pub fn proof_pins(host: &dyn Host) -> HostResult<BTreeMap<Oid, String>> {
    let mut pins = BTreeMap::new();
    for reference in host.list_refs(&RefQuery::prefix(ns::CHANGES))? {
        if !matches!(parse_ref(&reference.name), Some(ChangeRef::Merged { .. })) {
            continue;
        }
        let Some((StoredRecord::Merge(record), _)) = read_stored(host, &reference.oid)? else {
            continue;
        };
        for proof in &record.proofs {
            let Ok(oid) = Oid::from_hex(digest_hex(proof)) else {
                continue;
            };
            crate::attest::pin(
                &mut pins,
                oid,
                format!("merge record of {}", record.change_id),
            );
        }
    }
    Ok(pins)
}

/// The hex body of a `sha256:…` digest string.
fn digest_hex(digest: &str) -> &str {
    digest.split_once(':').map(|(_, hex)| hex).unwrap_or(digest)
}

/// An oid string from a record as an [`Oid`], in the algorithm the record names.
fn oid_of(tagged: &str, what: &str) -> HostResult<Oid> {
    commit_oid(tagged).ok_or_else(|| {
        HostError::invalid(
            what,
            format!("'{tagged}' is not an algorithm-tagged oid a store can compare"),
        )
    })
}

/// Spell an [`Oid`] the way the record it is being compared to spells its own, so the two
/// oids in a message read as the same kind of thing (ADR-0001 D2).
fn spell(oid: &Oid, like: &str) -> String {
    let algo = like.split_once(':').map(|(algo, _)| algo).unwrap_or("sha1");
    format!("{algo}:{}", oid.hex())
}

/// A short form of a key id, for the actor a ref write records.
fn short_key(key_id: &str) -> String {
    let tail = key_id.rsplit(':').next().unwrap_or(key_id);
    let count = tail.chars().count();
    if count > 12 {
        let keep: String = tail.chars().take(8).collect();
        let end: String = tail.chars().skip(count - 4).collect();
        format!("{keep}\u{2026}{end}")
    } else {
        tail.to_string()
    }
}

// --------------------------------------------------------------------------
// reading
// --------------------------------------------------------------------------

/// A record fetched through the ref that advertises it, with everything a caller needs
/// to report *why* it is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The ref it was read through.
    pub reference: RefName,
    /// What that ref addresses.
    pub target: ChangeRef,
    /// The ref's gitiup value: the record digest (D5 — a change ref holds a record
    /// digest, not a git oid).
    pub digest: Oid,
    /// The parsed record.
    pub record: StoredRecord,
    /// The exact bytes, so a caller can print or re-store them.
    pub bytes: Vec<u8>,
    /// Host metadata on the ref (actor, time).
    pub metadata: Ref,
}

/// Fetch and check the record one `refs/changes/**` ref advertises.
///
/// This is where D11's step-6 bindings live, because they are facts about a *store*
/// rather than about a document:
///
/// * the bytes must re-hash to the name the ref files them under — exit **8**;
/// * the record must name the change the ref is filed under — exit **6**;
/// * an `attempt/<n>` ref must hold a record that says it is attempt *n* — exit **6**;
/// * a `head` ref must point at the newest attempt: if it does not, the ref names a
///   different head than the change's own history does — exit **6**, with the retry
///   that finishes a half-finished submit.
pub fn change_at(host: &dyn Host, name: &RefName) -> HostResult<Fetched> {
    let metadata = host
        .get_ref(name)?
        .ok_or_else(|| HostError::not_found("ref", name.as_str()))?;
    change_at_ref(host, metadata)
}

/// [`change_at`] with the ref already in hand.
pub fn change_at_ref(host: &dyn Host, metadata: Ref) -> HostResult<Fetched> {
    let name = metadata.name.clone();
    let target = parse_ref(&name).ok_or_else(|| {
        HostError::invalid(
            "change ref",
            format!("{} is not a refs/changes/** name this format writes", name),
        )
    })?;
    let bytes = host.get(&metadata.oid)?.ok_or_else(|| {
        HostError::not_found("record", metadata.oid.hex()).with_hint(format!(
            "{name} advertises a record this store cannot return; re-publish it, or fetch \
             from a store that has it (a ref that promises bytes the store does not hold is \
             the failure D5's write order exists to prevent)"
        ))
    })?;
    let digest = Oid::hash_bytes(&bytes);
    if digest != metadata.oid {
        return Err(HostError::digest_mismatch(
            "change record",
            format!(
                "{name} points at {}, and the bytes there hash to {}",
                metadata.oid.short_default(),
                digest.short_default()
            ),
        )
        .with_hint("this store filed bytes under a name that is not their digest"));
    }
    // `record_from_bytes` already ran D11 steps 1-5 on these bytes; what is left is
    // what only the store can say (step 6).
    let record = record_from_bytes(&bytes)?;
    if record.change_id() != target.id() {
        return Err(HostError::invalid(
            "change record",
            format!(
                "{name} is filed under {}, and the record there is about {}",
                target.id(),
                record.change_id()
            ),
        )
        .with_hint(
            "a record's change_id is derived from its own contents, so one of the \
                    two is wrong and neither can be believed (ADR-0003 D3)",
        ));
    }
    let is_change = matches!(record, StoredRecord::Change(_));
    match &target {
        ChangeRef::Head { .. } if !is_change => {
            return Err(HostError::invalid(
                "change record",
                format!(
                    "{name} names a {} record, and a change's head is always a {CHANGE_TYPE}",
                    record.record_type()
                ),
            ));
        }
        ChangeRef::Attempt { index, .. } => {
            let StoredRecord::Change(record) = &record else {
                return Err(HostError::invalid(
                    "change record",
                    format!(
                        "{name} holds a {} record, not a change",
                        record.record_type()
                    ),
                ));
            };
            if record.attempts.index != *index {
                return Err(HostError::invalid(
                    "change record",
                    format!(
                        "{name} is attempt {index} and the record there claims attempt {}",
                        record.attempts.index
                    ),
                )
                .with_hint(
                    "an attempt ref never moves, so a ref and a record that disagree \
                            about the attempt number mean one of them was written by \
                            something that did not read this format",
                ));
            }
        }
        ChangeRef::Merged { .. } | ChangeRef::Abandoned { .. }
            if !matches!(
                (record.record_type(), &target),
                (MERGE_TYPE, ChangeRef::Merged { .. })
                    | (ABANDON_TYPE, ChangeRef::Abandoned { .. })
            ) =>
        {
            return Err(HostError::invalid(
                "change record",
                format!("{} holds a {} record", name, record.record_type()),
            ));
        }
        ChangeRef::Head { .. } => {
            // `head` names a different head than the change's own history: the record
            // is fine, the ref is behind it.
            let newest = attempt_entries(host, target.id())?
                .iter()
                .map(|(n, digest)| (*n, *digest))
                .max();
            if let Some((highest, newest_digest)) = newest
                && newest_digest != metadata.oid
                // A merge or abandon ref names an attempt, not a head: for those the
                // newest attempt is not what the ref promises.
                && let StoredRecord::Change(attempt) = &record
            {
                return Err(HostError::invalid(
                    "change record",
                    format!(
                        "{name} names {} (attempt {}), but attempt {highest} of this \
                         change is {}",
                        attempt.head,
                        attempt.attempts.index,
                        newest_digest.short_default()
                    ),
                )
                .with_hint(
                    "head always points at the newest attempt. This looks like a submit \
                     that created the attempt ref and died before moving head: re-run \
                     the same submit and it finishes the job (ADR-0003 D6)",
                ));
            }
        }
        _ => {}
    }
    Ok(Fetched {
        reference: name,
        target,
        digest,
        record,
        bytes,
        metadata,
    })
}

/// Fetch a record by its `kv/` digest and check it is self-consistent.
pub fn read_stored(host: &dyn Host, digest: &Oid) -> HostResult<Option<(StoredRecord, Vec<u8>)>> {
    let Some(bytes) = host.get(digest)? else {
        return Ok(None);
    };
    if &Oid::hash_bytes(&bytes) != digest {
        return Err(HostError::digest_mismatch(
            "change record",
            format!(
                "the bytes at {} hash to {}",
                digest.short_default(),
                Oid::hash_bytes(&bytes).short_default()
            ),
        )
        .with_hint("this store filed bytes under a name that is not their digest"));
    }
    let record = record_from_bytes(&bytes)?;
    Ok(Some((record, bytes)))
}

/// The three states of D7, derived from which refs exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Neither `merged` nor `abandoned` exists.
    Open,
    /// `refs/changes/<id>/merged` exists.
    Merged,
    /// `refs/changes/<id>/abandoned` exists.
    Abandoned,
}

impl State {
    /// The stable lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Merged => "merged",
            State::Abandoned => "abandoned",
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One change as the store's refs describe it — no record fetches, so this listing is
/// one `refs/changes/**` listing wide (D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSummary {
    /// Which change.
    pub change_id: ChangeId,
    /// `merged` > `abandoned` > `open`, in that precedence.
    pub state: State,
    /// The record digest `head` advertises, if there is a `head` ref at all.
    pub head: Option<Oid>,
    /// The merge record's digest, when merged.
    pub merged: Option<Oid>,
    /// The abandon record's digest, when abandoned.
    pub abandoned: Option<Oid>,
    /// The attempt indices present, oldest first.
    pub attempts: Vec<u32>,
    /// Their record digests, same order.
    pub attempt_digests: Vec<Oid>,
    /// Whether `head` names the newest attempt. `false` means the ref names a different
    /// head than the change's own history — usually a submit that died between the two
    /// writes, which is *reported* here and refused by [`change_at`] rather than hidden.
    pub head_tracks_newest: bool,
    /// Who moved `head` last, when the host records it.
    pub updated_by: Option<Actor>,
    /// When `head` moved, when the host records it.
    pub updated_at: Option<Timestamp>,
}

impl ChangeSummary {
    /// The newest attempt's record digest, if there is one.
    pub fn newest_attempt_digest(&self) -> Option<Oid> {
        self.attempt_digests.last().copied()
    }

    /// Whether `handle` (a full id or ≥4 hex of one) names this change (D3).
    pub fn matches(&self, handle: &str) -> bool {
        self.change_id.matches_handle(handle)
    }
}

/// What a listing found, plus what it refused to guess about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    /// One entry per change, sorted by id.
    pub changes: Vec<ChangeSummary>,
    /// `refs/changes/**` names that are not this layout. Reported, never skipped: a
    /// listing that drops a ref is how "there is no change named that" becomes a lie.
    pub unexpected: Vec<String>,
}

impl Catalog {
    /// Nothing at all.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.unexpected.is_empty()
    }

    /// The changes `handle` could mean: exact match first, then prefix matches (D3: a
    /// short handle is fine until it is ambiguous, and then the tool says so and lists
    /// the candidates rather than picking one).
    pub fn resolve(&self, handle: &str) -> Vec<&ChangeSummary> {
        let mut exact = Vec::new();
        let mut prefix = Vec::new();
        for change in &self.changes {
            if change.change_id.as_str() == handle {
                exact.push(change);
            } else if change.matches(handle) {
                prefix.push(change);
            }
        }
        if exact.is_empty() { prefix } else { exact }
    }

    /// Every open change.
    pub fn open(&self) -> Vec<&ChangeSummary> {
        self.changes
            .iter()
            .filter(|change| change.state == State::Open)
            .collect()
    }
}

/// Every change in the store, derived from `refs/changes/**` (D7).
pub fn list_changes(host: &dyn Host) -> HostResult<Catalog> {
    let refs = host.list_refs(&RefQuery::prefix(ns::CHANGES))?;
    let mut by_id: BTreeMap<String, Vec<Ref>> = BTreeMap::new();
    let mut catalog = Catalog::default();
    for reference in refs {
        match parse_ref(&reference.name) {
            Some(target) => by_id
                .entry(target.id().as_str().to_string())
                .or_default()
                .push(reference),
            None => catalog.unexpected.push(reference.name.as_str().to_string()),
        }
    }
    for (text, refs) in by_id {
        let change_id = ChangeId::new(&text)?;
        let mut attempts: Vec<(u32, Oid)> = Vec::new();
        let mut summary = ChangeSummary {
            change_id: change_id.clone(),
            state: State::Open,
            head: None,
            merged: None,
            abandoned: None,
            attempts: Vec::new(),
            attempt_digests: Vec::new(),
            head_tracks_newest: true,
            updated_by: None,
            updated_at: None,
        };
        for reference in refs {
            match parse_ref(&reference.name) {
                Some(ChangeRef::Head { .. }) => {
                    summary.head = Some(reference.oid);
                    summary.updated_by = reference.updated_by.clone();
                    summary.updated_at = reference.updated_at;
                }
                Some(ChangeRef::Merged { .. }) => summary.merged = Some(reference.oid),
                Some(ChangeRef::Abandoned { .. }) => summary.abandoned = Some(reference.oid),
                Some(ChangeRef::Attempt { index, .. }) => {
                    attempts.push((index, reference.oid));
                }
                None => {}
            }
        }
        // Sorted by attempt number, which is not the order a ref listing gives: a
        // listing sorts by name, and `attempt/10` sorts before `attempt/2`.
        attempts.sort_unstable_by_key(|(index, _)| *index);
        summary.attempts = attempts.iter().map(|(index, _)| *index).collect();
        summary.attempt_digests = attempts.iter().map(|(_, digest)| *digest).collect();
        if let Some((_, newest)) = attempts.last() {
            summary.head_tracks_newest = summary.head.is_none_or(|head| head == *newest);
        }
        // D7's precedence, spelled out rather than implied by a HashMap's order.
        summary.state = if summary.merged.is_some() {
            State::Merged
        } else if summary.abandoned.is_some() {
            State::Abandoned
        } else {
            State::Open
        };
        catalog.changes.push(summary);
    }
    Ok(catalog)
}

/// One attempt, as its own record describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptInfo {
    /// The ref advertising it.
    pub reference: RefName,
    /// The attempt number the ref's leaf names, which the record must agree with.
    pub index: u32,
    /// `sha256(stored bytes)` — the `kv/change/<hex>` key (D4).
    pub record_digest: Oid,
    /// What a merge record and `attempts.previous` cite (D4).
    pub change_digest: String,
    /// The commit this attempt proposes.
    pub head: String,
    /// The branch and the point it branched from.
    pub base: Base,
    /// Who signed it.
    pub author: Author,
    /// What they called it.
    pub title: String,
    /// When they wrote it (their claim, not the store's clock).
    pub created_at_us: i64,
    /// The attempt this one replaces, if any.
    pub previous: Option<String>,
    /// The workflow hint (D9).
    pub jobs: Vec<String>,
    /// Bytes stored.
    pub size: u64,
}

/// The attempt history of one change: `refs/changes/<id>/attempt/*`, each resolved to
/// its record, with the `previous` chain checked as it is read (D6).
///
/// On a git host this is the same history as `git log refs/changes/<id>/head`, because
/// the pointer commits are parented that way (D5). The chain is validated on the way
/// out, not on the way in: a gap means an attempt ref is gone, and "the history is
/// shorter than it claims" is exactly what a merge gate must not paper over.
pub fn change_history(host: &dyn Host, id: &ChangeId) -> HostResult<Vec<AttemptInfo>> {
    let entries = attempt_entries(host, id)?;
    if entries.len() > MAX_CHAIN {
        return Err(HostError::invalid(
            "change",
            format!(
                "{} attempts is more than the {MAX_CHAIN} link limit for a chain",
                entries.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(entries.len());
    let mut previous_digest: Option<String> = None;
    for (index, digest) in &entries {
        let Some(reference) = host.get_ref(&attempt_ref(id, *index))? else {
            continue;
        };
        let Some((StoredRecord::Change(record), bytes)) = read_stored(host, digest)? else {
            return Err(HostError::invalid(
                "change",
                format!(
                    "{} names {}, which is not a change record this store can read",
                    reference.name,
                    digest.short_default()
                ),
            ));
        };
        if record.attempts.index != *index {
            return Err(HostError::invalid(
                "change",
                format!(
                    "{} is attempt {index} and its record claims attempt {}",
                    reference.name, record.attempts.index
                ),
            ));
        }
        let change_digest = record.change_digest()?;
        if *index == 0 {
            if previous_digest.is_some() {
                return Err(HostError::invalid(
                    "change",
                    "attempt 0 is not the first ref in the chain",
                ));
            }
        } else if let Some(expected) = &previous_digest
            && record.attempts.previous.as_deref() != Some(expected.as_str())
        {
            return Err(HostError::digest_mismatch(
                "change",
                format!(
                    "attempt {index} names {:?}, but the attempt before it is {expected}",
                    record.attempts.previous
                ),
            )
            .with_hint(
                "the chain is walked when it is read: a gap or a mis-cited \
                 predecessor means an attempt ref is gone (ADR-0003 D6)",
            ));
        }
        previous_digest = Some(change_digest.clone());
        out.push(AttemptInfo {
            reference: reference.name,
            index: *index,
            record_digest: *digest,
            change_digest,
            head: record.head.clone(),
            base: record.base.clone(),
            author: record.author.clone(),
            title: record.title.clone(),
            created_at_us: record.created_at_us,
            previous: record.attempts.previous.clone(),
            jobs: record.workflow.jobs.clone(),
            size: bytes.len() as u64,
        });
    }
    if let Some(first) = out.first()
        && first.index != 0
    {
        return Err(HostError::invalid(
            "change",
            format!(
                "the chain starts at attempt {}, and attempt 0's ref is gone",
                first.index
            ),
        )
        .with_hint(format!(
            "the anchor of {} is attempt 0's head, so a reader cannot re-derive the \
             id without it (ADR-0003 D3, D6)",
            id
        )));
    }
    Ok(out)
}

/// The refspec a fetch of one change asks a git host for (D5, C1): one fetch carries
/// the change, every attempt and the commits they propose.
pub fn fetch_pattern(id: &ChangeId) -> String {
    format!("{}/{}/*", ns::CHANGES, id.as_str())
}

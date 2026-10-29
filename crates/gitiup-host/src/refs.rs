//! Refs: names, values, compare-and-swap updates and the [`RefStore`] trait.
//!
//! A ref is a name that points at an [`Oid`]. All hosts share one namespace
//! convention (see [`ns`]) so changes, attestations and quorum state travel
//! with plain `git fetch` where the host is git-backed, and are laid out
//! identically where it is not.
//!
//! Every write is a compare-and-swap: the caller states what it believes the ref
//! currently holds ([`Expect`]) and the host either applies the update or
//! reports [`HostError::Conflict`]. That is what
//! lets a plain S3 bucket (conditional writes) and a plain git repo
//! (`--force-with-lease`) stand in for a forge.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{HostError, HostResult};
use crate::oid::Oid;
use crate::pack::{Pack, PackRequest};
use crate::time::Timestamp;

/// Shared ref namespace conventions. Every host uses these, so later tickets can
/// speak about "the changes of repo X" without knowing the transport.
pub mod ns {
    /// Owner-written branches.
    pub const HEADS: &str = "refs/heads";
    /// Proposed changes: `refs/changes/<id>/head`.
    pub const CHANGES: &str = "refs/changes";
    /// Attestations for a commit: `refs/attestations/<oid>`.
    pub const ATTESTATIONS: &str = "refs/attestations";
    /// Roster, job/lease records and quorum state.
    pub const GITIUP: &str = "refs/gitiup";
    /// The `HEAD` symbolic ref name.
    pub const HEAD: &str = "HEAD";

    /// Number of leading path components a ref namespace has (`refs/changes/x`
    /// -> 2).
    pub const DEPTH: usize = 2;
}

/// Who performed a ref update, recorded for audit and for proposer-exclusion
/// rules later on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Actor(String);

impl Actor {
    /// Validate and build an actor from a display name.
    pub fn new(name: impl Into<String>) -> Result<Actor, HostError> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(HostError::invalid("actor", "actor name is empty"));
        }
        if trimmed.len() > 128 {
            return Err(HostError::invalid(
                "actor",
                format!("actor name is {} bytes, maximum is 128", trimmed.len()),
            ));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(HostError::invalid(
                "actor",
                "actor name contains control characters",
            ));
        }
        Ok(Actor(trimmed.to_string()))
    }

    /// Best-effort identity from the environment: `GITIUP_ACTOR`, then
    /// `GITIUP_USER`, then `USER`/`USERNAME`, else `unknown`.
    pub fn from_env() -> Actor {
        for key in ["GITIUP_ACTOR", "GITIUP_USER", "USER", "USERNAME"] {
            if let Ok(v) = std::env::var(key)
                && let Ok(actor) = Actor::new(v)
            {
                return actor;
            }
        }
        Actor::unknown()
    }

    /// The placeholder actor used when no identity is known.
    pub fn unknown() -> Actor {
        Actor("unknown".to_string())
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Actor {
    /// Lossy conversion used by builder-style APIs: trims, drops control
    /// characters and falls back to [`Actor::unknown`] when nothing is left. Use
    /// [`Actor::new`] when you need to reject bad input.
    fn from(name: &str) -> Actor {
        let cleaned: String = name
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(128)
            .collect();
        if cleaned.is_empty() {
            Actor::unknown()
        } else {
            Actor(cleaned)
        }
    }
}

impl From<String> for Actor {
    fn from(name: String) -> Actor {
        Actor::from(name.as_str())
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Actor {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Actor::new(s)
    }
}

/// A validated ref name, e.g. `refs/heads/main` or `refs/changes/a1b2/head`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RefName(String);

impl RefName {
    /// Validate `name` and build it.
    ///
    /// Rules follow git's: no whitespace or control characters, no `~ ^ : ? * [
    /// \`, no `..`, no `@{`, no empty/`.`/`..` components, no leading/trailing
    /// `/`, no `//`, no component ending in `.lock`, nothing after a trailing
    /// `.`.
    pub fn new(name: impl Into<String>) -> Result<RefName, HostError> {
        let name = name.into();
        Self::validate(&name)?;
        Ok(RefName(name))
    }

    /// `refs/heads/<name>`.
    pub fn branch(name: &str) -> Result<RefName, HostError> {
        RefName::new(format!("{}/{name}", ns::HEADS))
    }

    /// `refs/tags/<name>`.
    pub fn tag(name: &str) -> Result<RefName, HostError> {
        RefName::new(format!("refs/tags/{name}"))
    }

    /// `refs/changes/<id>/head`.
    pub fn change_head(id: &str) -> Result<RefName, HostError> {
        RefName::new(format!("{}/{id}/head", ns::CHANGES))
    }

    /// `refs/changes/<id>/<extra>`.
    pub fn change(id: &str, extra: &str) -> Result<RefName, HostError> {
        RefName::new(format!("{}/{id}/{extra}", ns::CHANGES))
    }

    /// `refs/attestations/<oid>`.
    pub fn attestation(oid: &Oid) -> RefName {
        // `ns` is a fixed, valid prefix and oid hex is always valid.
        RefName(format!("{}/{}", ns::ATTESTATIONS, oid.hex()))
    }

    /// `refs/gitiup/<rel>`.
    pub fn gitiup(rel: &str) -> Result<RefName, HostError> {
        RefName::new(format!("{}/{rel}", ns::GITIUP))
    }

    /// `HEAD`.
    pub fn head() -> RefName {
        RefName(ns::HEAD.to_string())
    }

    fn validate(name: &str) -> Result<(), HostError> {
        let bad = |why: &str| Err(HostError::invalid("ref name", format!("'{name}' {why}")));
        if name.is_empty() {
            return bad("is empty");
        }
        if name.len() > 1024 {
            return bad("is longer than 1024 bytes");
        }
        if name.starts_with('/') || name.ends_with('/') {
            return bad("must not start or end with '/'");
        }
        if name.contains("//") {
            return bad("contains an empty path component");
        }
        if name.contains("..") {
            return bad("contains '..'");
        }
        if name.contains("@{") {
            return bad("contains '@{'");
        }
        if name.ends_with(".lock") {
            return bad("must not end with '.lock'");
        }
        if name.ends_with('.') {
            return bad("must not end with '.'");
        }
        for c in name.chars() {
            if c.is_control() || c.is_whitespace() {
                return bad("contains whitespace or control characters");
            }
            if matches!(
                c,
                '~' | '^' | ':' | '?' | '*' | '[' | '\\' | '|' | '<' | '>'
            ) {
                return bad("contains an illegal character");
            }
        }
        for comp in name.split('/') {
            if comp.is_empty() {
                return bad("contains an empty path component");
            }
            if comp == "." || comp == ".." {
                return bad("contains a '.' path component");
            }
            if comp.starts_with('.') {
                return bad("has a path component starting with '.'");
            }
        }
        Ok(())
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path components.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Whether the name is under `prefix` (`refs/changes` matches
    /// `refs/changes/a1/head`, but not `refs/changesets/...`).
    pub fn starts_with(&self, prefix: &str) -> bool {
        let prefix = prefix.trim_end_matches('/');
        self.0 == prefix || self.0.starts_with(&format!("{prefix}/"))
    }

    /// Append a component.
    pub fn join(&self, component: &str) -> Result<RefName, HostError> {
        RefName::new(format!("{}/{}", self.0, component))
    }

    /// Drop the last component.
    pub fn parent(&self) -> Option<RefName> {
        match self.0.rfind('/') {
            Some(idx) if idx > 0 => Some(RefName(self.0[..idx].to_string())),
            _ => None,
        }
    }

    /// Whether this is a `refs/heads/**` ref.
    pub fn is_branch(&self) -> bool {
        self.starts_with(ns::HEADS)
    }

    /// Whether this is a `refs/changes/**` ref.
    pub fn is_change(&self) -> bool {
        self.starts_with(ns::CHANGES)
    }

    /// Whether this is a `refs/attestations/**` ref.
    pub fn is_attestation(&self) -> bool {
        self.starts_with(ns::ATTESTATIONS)
    }

    /// Whether this is a `refs/gitiup/**` ref.
    pub fn is_gitiup(&self) -> bool {
        self.starts_with(ns::GITIUP)
    }

    /// The `<id>` of a `refs/changes/<id>/...` ref.
    pub fn change_id(&self) -> Option<&str> {
        if !self.is_change() {
            return None;
        }
        self.0
            .strip_prefix(ns::CHANGES)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split('/').next())
    }

    /// The `<oid>` hex of a `refs/attestations/<oid>` ref.
    pub fn attestation_target(&self) -> Option<&str> {
        self.0
            .strip_prefix(ns::ATTESTATIONS)
            .and_then(|rest| rest.strip_prefix('/'))
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RefName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefName({})", self.0)
    }
}

impl FromStr for RefName {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RefName::new(s)
    }
}

impl TryFrom<String> for RefName {
    type Error = HostError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        RefName::new(value)
    }
}

impl From<RefName> for String {
    fn from(value: RefName) -> Self {
        value.0
    }
}

/// What a CAS write believes the ref currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The ref must not exist (create-only; `If-None-Match` in S3,
    /// `--create-only` in git).
    Absent,
    /// The ref must hold exactly this oid (`If-Match: <etag>`,
    /// `--force-with-lease=<ref>:<oid>`).
    Is(Oid),
    /// Whatever is there (an unconditional write; never used by gitiup code
    /// that gates a merge).
    Any,
}

impl Expect {
    /// Map the `Option` shape used by [`RefStore::cas_ref`]: `None` means "no
    /// opinion" ([`Expect::Any`]); use [`RefUpdate::create`] when the write must
    /// fail if the ref already exists.
    pub fn from_option(oid: Option<Oid>) -> Expect {
        match oid {
            Some(oid) => Expect::Is(oid),
            None => Expect::Any,
        }
    }

    /// Whether `actual` (as stored) satisfies this expectation.
    pub fn matches(self, actual: Option<Oid>) -> bool {
        match self {
            Expect::Absent => actual.is_none(),
            Expect::Is(oid) => actual == Some(oid),
            Expect::Any => true,
        }
    }

    /// Human-readable form for error messages.
    pub fn describe(self) -> String {
        match self {
            Expect::Absent => "absent".to_string(),
            Expect::Is(oid) => oid.hex(),
            Expect::Any => "any".to_string(),
        }
    }
}

/// Something a git-backed host must make a parent of the pointer commit it writes.
///
/// A gitiup ref whose value is a record digest is not a commit, so on a git host it
/// points at a small **pointer commit** carrying the record bytes
/// ([`crate::hosts::git`]). Which commits that commit should parent on is knowledge
/// the record has and the ref does not: a change ref must reach the commits it
/// proposes, or `git fetch refs/changes/<id>/head` delivers a record describing a
/// commit the fetch did not carry
/// ([ADR-0003 D5](../../../docs/adr/0003-change-record-format-and-merge-semantics.md)).
///
/// Hosts where a ref is a row rather than a commit (the `fs` host, a bucket) ignore
/// this: their reads do not go through a packfile, so there is nothing to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefParent {
    /// A commit, by its git object id.
    Commit(Oid),
    /// Whatever the named ref currently holds — used for a chain of pointer commits,
    /// where the parent is the previous attempt's pointer and only the host knows its
    /// git oid.
    Ref(RefName),
}

/// A compare-and-swap ref write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    /// Ref to write.
    pub name: RefName,
    /// Precondition on its current value.
    pub expect: Expect,
    /// New value.
    pub new: Oid,
    /// Who is writing (recorded when the host keeps metadata).
    pub actor: Option<Actor>,
    /// Free-form reason, for audit trails and reflog-ish messages.
    pub message: Option<String>,
    /// Extra parents for the pointer commit a git host writes (see [`RefParent`]);
    /// empty for every write that is not about a record chain.
    pub parents: Vec<RefParent>,
}

impl RefUpdate {
    /// Build an update with an explicit expectation.
    pub fn new(name: RefName, expect: Expect, new: Oid) -> RefUpdate {
        RefUpdate {
            name,
            expect,
            new,
            actor: None,
            message: None,
            parents: Vec::new(),
        }
    }

    /// `expect: Absent` — fail if the ref already exists.
    pub fn create(name: RefName, new: Oid) -> RefUpdate {
        RefUpdate::new(name, Expect::Absent, new)
    }

    /// `expect: Is(previous)` — fail if the ref moved.
    pub fn replace(name: RefName, previous: Oid, new: Oid) -> RefUpdate {
        RefUpdate::new(name, Expect::Is(previous), new)
    }

    /// `expect: Any` — unconditional.
    pub fn set(name: RefName, new: Oid) -> RefUpdate {
        RefUpdate::new(name, Expect::Any, new)
    }

    /// Record the actor.
    pub fn with_actor(mut self, actor: impl Into<Actor>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Record a message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Ask a git-backed host to parent the pointer commit it writes on these.
    ///
    /// Ignored by hosts where a ref is not a commit; a caller must never *need* the
    /// parent, only prefer it (the record still names what it carries).
    pub fn with_parents(mut self, parents: impl IntoIterator<Item = RefParent>) -> Self {
        self.parents = parents.into_iter().collect();
        self
    }
}

/// A compare-and-swap ref deletion (closing a change, withdrawing a roster...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefDeletion {
    /// Ref to remove.
    pub name: RefName,
    /// Precondition on its current value.
    pub expect: Expect,
    /// Who is deleting.
    pub actor: Option<Actor>,
}

impl RefDeletion {
    /// Build a deletion with an explicit expectation.
    pub fn new(name: RefName, expect: Expect) -> RefDeletion {
        RefDeletion {
            name,
            expect,
            actor: None,
        }
    }

    /// Record the actor.
    pub fn with_actor(mut self, actor: impl Into<Actor>) -> Self {
        self.actor = Some(actor.into());
        self
    }
}

/// A ref plus the metadata hosts keep alongside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ref {
    /// The name.
    pub name: RefName,
    /// The value.
    pub oid: Oid,
    /// Last writer, when the host records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Actor>,
    /// Last write time, when the host records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// Schema of the stored ref document (see [`crate::HOST_SCHEMA_VERSION`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<u32>,
}

impl Ref {
    /// A bare ref with no metadata.
    pub fn new(name: RefName, oid: Oid) -> Ref {
        Ref {
            name,
            oid,
            updated_by: None,
            updated_at: None,
            schema: None,
        }
    }

    /// Attach writer metadata.
    pub fn with_meta(mut self, actor: Option<Actor>, at: Option<Timestamp>) -> Self {
        self.updated_by = actor;
        self.updated_at = at;
        self.schema = Some(crate::HOST_SCHEMA_VERSION);
        self
    }
}

/// Filter for [`RefStore::list_refs`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefQuery {
    /// Only refs under this prefix (trimmed of trailing `/`).
    pub prefix: Option<String>,
    /// Stop after this many refs (hosts may apply it before sorting on).
    pub limit: Option<usize>,
}

impl RefQuery {
    /// Everything.
    pub fn all() -> RefQuery {
        RefQuery::default()
    }

    /// Only refs under `prefix`.
    pub fn prefix(prefix: impl Into<String>) -> RefQuery {
        RefQuery {
            prefix: Some(prefix.into()),
            limit: None,
        }
    }

    /// Limit the result size.
    pub fn with_limit(mut self, limit: usize) -> RefQuery {
        self.limit = Some(limit);
        self
    }

    /// Whether `name` passes this filter.
    pub fn matches(&self, name: &RefName) -> bool {
        match &self.prefix {
            None => true,
            Some(prefix) => name.starts_with(prefix),
        }
    }
}

/// The read/compare-and-swap side of a host: refs and pack transport.
///
/// Implementations must never silently overwrite: a write either satisfies its
/// [`Expect`] or returns [`HostError::Conflict`]
/// with both sides filled in, so callers can re-read and retry.
pub trait RefStore: Send + Sync {
    /// List refs matching `query`, sorted by name.
    fn list_refs(&self, query: &RefQuery) -> HostResult<Vec<Ref>>;

    /// Read one ref. `Ok(None)` when absent.
    ///
    /// The default implementation filters [`list_refs`](RefStore::list_refs);
    /// implementations should override it when a point lookup is cheaper.
    fn get_ref(&self, name: &RefName) -> HostResult<Option<Ref>> {
        let query = RefQuery::prefix(name.as_str());
        Ok(self
            .list_refs(&query)?
            .into_iter()
            .find(|r| &r.name == name))
    }

    /// Compare-and-swap a ref, recording actor and message when the host keeps
    /// that metadata. Returns the stored ref.
    fn update_ref_cas(&self, update: &RefUpdate) -> HostResult<Ref>;

    /// The shorthand form of [`RefStore::update_ref_cas`]: `expected` of `None`
    /// means "no opinion" ([`Expect::Any`]); use [`RefUpdate::create`] for
    /// create-only writes.
    fn cas_ref(&self, name: &RefName, expected: Option<Oid>, new: Oid) -> HostResult<Ref> {
        self.update_ref_cas(&RefUpdate::new(
            name.clone(),
            Expect::from_option(expected),
            new,
        ))
    }

    /// Apply several CAS updates, all-or-nothing.
    ///
    /// The default implementation applies them in order and rolls back the ones
    /// already applied if a later one fails; hosts that can write atomically
    /// ([`crate::Capabilities::atomic_multi_write`])
    /// should override it.
    fn update_refs_cas(&self, updates: &[RefUpdate]) -> HostResult<Vec<Ref>> {
        let mut applied: Vec<(RefName, Option<Oid>)> = Vec::with_capacity(updates.len());
        let mut written = Vec::with_capacity(updates.len());
        for update in updates {
            let before = self.get_ref(&update.name)?.map(|r| r.oid);
            match self.update_ref_cas(update) {
                Ok(reference) => {
                    written.push(reference);
                    applied.push((update.name.clone(), before));
                }
                Err(first) => {
                    // Best-effort rollback, newest first. Best effort means what
                    // it says: a host that refuses the undo (a transient bucket
                    // error, say) leaves a ref behind, and the caller has to be
                    // told rather than told "nothing happened".
                    let mut left_behind: Vec<String> = Vec::new();
                    for (name, before) in applied.into_iter().rev() {
                        let undone = match before {
                            Some(oid) => self
                                .update_ref_cas(&RefUpdate::set(name.clone(), oid))
                                .is_ok(),
                            None => self
                                .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Any))
                                .is_ok(),
                        };
                        if !undone {
                            left_behind.push(name.as_str().to_string());
                        }
                    }
                    if left_behind.is_empty() {
                        return Err(first);
                    }
                    let undone = format!(
                        "the batch was rolled back except for {}; re-run the submit or repair \
                         with `gitiup fsck`",
                        left_behind.join(", ")
                    );
                    let already = first.hint().map(str::to_string);
                    let hint = match already {
                        Some(already) => format!("{already} — {undone}"),
                        None => undone,
                    };
                    return Err(first.with_hint(hint));
                }
            }
        }
        Ok(written)
    }

    /// Compare-and-swap a deletion (`Ok(())`, or
    /// [`HostError::Conflict`] if the ref moved).
    fn delete_ref_cas(&self, deletion: &RefDeletion) -> HostResult<()>;

    /// Fetch the objects needed to satisfy `request`.
    ///
    /// Hosts that cannot satisfy a `want` answer
    /// [`HostError::NotFound`]; objects the caller
    /// already `have` are skipped.
    fn fetch_pack(&self, request: &PackRequest) -> HostResult<Pack>;

    /// Store a pack so later fetches can serve it, returning the pack's own
    /// content digest (S3 keeps it as `packs/<oid>.pack`).
    fn put_pack(&self, pack: &Pack) -> HostResult<Oid>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).unwrap()
    }

    #[test]
    fn ref_names_validate_like_git() {
        assert!(RefName::new("refs/heads/main").is_ok());
        assert!(RefName::branch("feature/x").is_ok());
        assert!(RefName::change_head("a1b2c3").is_ok());
        assert!(RefName::attestation(&oid("aabb")).as_str() == "refs/attestations/aabb");
        for bad in [
            "",
            "/lead",
            "trail/",
            "a//b",
            "a/../b",
            "refs/heads/x.lock",
            "refs/heads/x ",
            "refs/heads/x~1",
            "refs/heads/x^0",
            "refs/heads/x:y",
            "refs/heads/x*",
            "refs/heads/x[y",
            "refs/heads/x\\y",
            "refs/heads/x@{",
            ".",
        ] {
            assert!(RefName::new(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn ref_namespace_helpers() {
        let change = RefName::change_head("deadbeef").unwrap();
        assert!(change.is_change());
        assert!(!change.is_branch());
        assert_eq!(change.change_id(), Some("deadbeef"));
        assert_eq!(change.parent().unwrap().as_str(), "refs/changes/deadbeef");
        assert!(RefName::branch("main").unwrap().is_branch());
        assert!(RefName::gitiup("roster").unwrap().is_gitiup());
        assert_eq!(
            RefName::attestation(&oid("aabb")).attestation_target(),
            Some("aabb")
        );
        assert_eq!(RefName::new("refs/changesets/x").unwrap().change_id(), None);
    }

    #[test]
    fn query_prefixes_are_component_aware() {
        let changes = RefName::change_head("a1").unwrap();
        assert!(RefQuery::prefix(ns::CHANGES).matches(&changes));
        assert!(RefQuery::prefix("refs/changes/").matches(&changes));
        assert!(!RefQuery::prefix("refs/changes/a1/head/extra").matches(&changes));
        assert!(RefQuery::all().matches(&changes));
    }

    #[test]
    fn expect_semantics() {
        let a = oid("aabb");
        let b = oid("bbcc");
        assert!(Expect::Absent.matches(None));
        assert!(!Expect::Absent.matches(Some(a)));
        assert!(Expect::Is(a).matches(Some(a)));
        assert!(!Expect::Is(a).matches(Some(b)));
        assert!(Expect::Any.matches(None));
        assert_eq!(Expect::from_option(None), Expect::Any);
        assert_eq!(Expect::from_option(Some(a)), Expect::Is(a));
        assert_eq!(Expect::Is(a).describe(), "aabb");
    }

    #[test]
    fn actor_validation_and_serde() {
        assert_eq!(Actor::new("  ada  ").unwrap().as_str(), "ada");
        assert!(Actor::new("   ").is_err());
        assert!(Actor::new("ada\nrm -rf").is_err());
        let json = serde_json::to_string(&Actor::unknown()).unwrap();
        assert_eq!(json, "\"unknown\"");
    }

    #[test]
    fn ref_serde_shape() {
        let r = Ref::new(RefName::branch("main").unwrap(), oid("aabb")).with_meta(
            Some(Actor::unknown()),
            Some(Timestamp::from_unix(1_761_523_200)),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"name\":\"refs/heads/main\""), "{json}");
        let back: Ref = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

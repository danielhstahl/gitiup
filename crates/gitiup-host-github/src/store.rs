//! How a forge that stores git objects hosts gitiup's refs and records.
//!
//! Two mismatches have to be bridged, and this module is where both are bridged.
//!
//! **A ref can only hold a git object id; a gitiup ref often points at a record.**
//! A record is addressed by SHA-256 over its exact bytes (that is what a signature
//! covers), and a git ref cannot name such a thing. So a ref that points at a
//! record points at a small **pointer commit** instead: a commit whose tree holds
//! `gitiup-ref.json` — the digest gitiup promised, the actor, the time — and, when
//! this process has them, the record bytes as `record`. Reading the ref resolves
//! the pointer back to the promised digest, so nothing above this module knows any
//! of it happened. The plain-git host does the same thing, which is what makes
//! *`git fetch` carries proof* true here too: fetching `refs/attestations/<oid>`
//! brings the attestation in the same packfile, and
//! `git log refs/changes/c1/head` is the history of that change.
//!
//! **A forge with no key-value store is not a record store.** The records live in
//! one append-only commit chain at [`layout::kv_ref_name`], whose tree holds one
//! file per record at `<namespace>/<sha256hex>` — the same logical key every host
//! uses (`RemoteConfig::kv_key`), spelled as a git path. Appending is a tree update
//! on top of `base_tree` (the server merges, so an append does not rewrite the other
//! entries) followed by a ref move the forge will only accept as a fast-forward.
//! That is the compare-and-swap a record append needs, and it is why two
//! contributors publishing at once cannot lose a record.
//!
//! # What a ref write is, exactly
//!
//! | expectation | what goes on the wire | who enforces it |
//! |-------------|----------------------|-----------------|
//! | `Absent` | `POST /git/refs` | the forge: creating an existing ref is refused, atomically |
//! | `Is(oid)`, forward move | read · check · `PATCH … force=false` | the forge: a non-fast-forward move is refused |
//! | `Is(oid)`, rewind | read · check · `force=false` (refused) · re-read · `force=true` · verify | gitiup: checked before, verified after |
//! | `Any` | `PATCH … force=true` | nobody, which is what `Any` means |
//!
//! Every write ends by reading the ref back and comparing; a forge that answers 200
//! and stores something else is a `Conflict`, never a success. The case the forge
//! cannot make conditional is the rewind — no gitiup flow rewinds a ref (changes,
//! attestations and record chains all move forward) — and when one is genuinely
//! asked for, the window between the read and the forced write is *detected* by the
//! post-verification rather than *prevented*. That is a real difference from
//! `--force-with-lease` on the git host, and [`crate::GitHubHost::advice`] says so
//! out loud.

use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use gitiup_host::{
    Actor, BlobEntry, Expect, HostError, HostErrorExt, HostResult, Namespace, Oid, Prefix, Ref,
    RefName, Timestamp, config::canonical_json,
};
use serde::{Deserialize, Serialize};

use crate::api;
use crate::api::TreeEntryInput;
use crate::client::Client;
use crate::layout;

/// The path of the ref document inside a pointer commit.
pub const REF_DOCUMENT_PATH: &str = "gitiup-ref.json";

/// The path of the record bytes inside a pointer commit, when they were available.
pub const RECORD_PATH: &str = "record";

/// How many recently written records are kept so a pointer commit can carry them.
const RECENT_RECORDS: usize = 64;

/// The document inside a pointer commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefDocument {
    /// Schema of the stored document (see [`gitiup_host::HOST_SCHEMA_VERSION`]).
    pub schema: u32,
    /// The digest gitiup promised: SHA-256 of a record, or a git SHA-1 for a ref
    /// that points at ordinary git history.
    pub target: String,
    /// Who asked for the write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The free-form reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// When this process wrote it, seconds since the epoch.
    #[serde(default)]
    pub at: u64,
    /// Hex of the record bytes carried in this commit, when they were carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
}

impl RefDocument {
    /// The document for a promised digest.
    pub fn new(target: &Oid, actor: Option<&str>, message: Option<&str>) -> RefDocument {
        RefDocument {
            schema: gitiup_host::HOST_SCHEMA_VERSION,
            target: target.hex(),
            actor: actor.map(str::to_string).filter(|name| !name.is_empty()),
            message: message.map(str::to_string).filter(|text| !text.is_empty()),
            at: Timestamp::now().as_unix(),
            record: None,
        }
    }

    /// The promised digest, or an error when the stored document is nonsense.
    pub fn target_oid(&self) -> HostResult<Oid> {
        Oid::from_hex(&self.target).map_err(|_| {
            HostError::invalid(
                "stored ref document",
                format!("its `target` is '{}', which is not a digest", self.target),
            )
            .with_hint("that pointer commit was written by something that is not gitiup")
        })
    }

    /// The document as the bytes stored beside it.
    pub fn to_bytes(&self) -> HostResult<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|why| {
            HostError::invalid("ref document", format!("it cannot be serialised: {why}"))
        })?;
        canonical_json(&value)
    }
}

/// What a ref resolves to: ordinary git history, or a record behind a pointer
/// commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefTarget {
    /// The ref holds an ordinary git object (a branch, a tag, a fork's head).
    Plain {
        /// The git object id.
        sha: String,
    },
    /// The ref holds a pointer commit that promises a gitiup record.
    Record {
        /// The pointer commit.
        sha: String,
        /// What it promises.
        document: RefDocument,
    },
}

impl RefTarget {
    /// The git object the forge holds.
    pub fn sha(&self) -> &str {
        match self {
            RefTarget::Plain { sha } => sha,
            RefTarget::Record { sha, .. } => sha,
        }
    }

    /// The digest a gitiup caller sees as the ref's value.
    pub fn promised(&self) -> HostResult<Oid> {
        match self {
            RefTarget::Plain { sha } => Oid::from_hex(sha).map_err(|_| {
                HostError::invalid(
                    "ref value",
                    format!("the forge reports '{sha}', which is not an object id"),
                )
            }),
            RefTarget::Record { document, .. } => document.target_oid(),
        }
    }

    /// The stored document, when this ref is a gitiup pointer.
    pub fn document(&self) -> Option<&RefDocument> {
        match self {
            RefTarget::Record { document, .. } => Some(document),
            RefTarget::Plain { .. } => None,
        }
    }
}

/// The record/ref store behind a [`crate::GitHubHost`].
pub struct Store {
    client: Client,
    /// Immutable git objects keyed by id: whether a commit is a pointer commit, and
    /// what it promises, is forever, so this cache never expires.
    objects: Mutex<HashMap<String, Option<RefDocument>>>,
    /// The ref advertisement, trusted for `ref-cache-ttl`. This is a *listing*
    /// cache: no write ever reads its lease from here.
    refs: Mutex<HashMap<String, (Instant, Option<String>)>>,
    /// Records this process wrote, so a pointer commit can carry the bytes that
    /// make `git fetch` proof-carrying. An optimisation only: the chain is the
    /// authority.
    recent: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Whether this process has seen the repository answer something. The forge
    /// answers 404 for "no such ref" and "no such repository" identically, and the
    /// difference matters more than one call per process.
    repository_seen: std::sync::atomic::AtomicBool,
}

impl Store {
    /// Build a store over a client.
    pub fn new(client: Client) -> Store {
        Store {
            client,
            objects: Mutex::new(HashMap::new()),
            refs: Mutex::new(HashMap::new()),
            recent: Mutex::new(BTreeMap::new()),
            repository_seen: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The client this store drives.
    pub fn client(&self) -> &Client {
        &self.client
    }

    // -- refs ---------------------------------------------------------------

    /// List refs under `prefix`, resolved to what a gitiup caller means by them.
    ///
    /// Resolving is not free: a ref whose value might be a pointer commit costs one
    /// tree read (cached forever after, because git objects are immutable). A
    /// listing that shows raw git shas instead would be cheaper and would make
    /// `list_refs` disagree with `get_ref`, which is worse.
    pub fn list_refs(&self, query: &gitiup_host::RefQuery) -> HostResult<Vec<Ref>> {
        let prefix = query
            .prefix
            .as_deref()
            .map(|prefix| prefix.trim_matches('/').to_string())
            .unwrap_or_default();
        let asking_for_the_plumbing = prefix.starts_with(gitiup_host::refs::ns::GITIUP);
        let mut out: Vec<Ref> = Vec::new();
        for found in api::matching_refs(&self.client, &prefix)? {
            self.repository_seen
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let hidden = layout::is_internal_ref(&found.name);
            if hidden && !asking_for_the_plumbing {
                continue;
            }
            let name = match RefName::new(&found.name) {
                Ok(name) => name,
                Err(why) => {
                    // A ref the forge reports that gitiup cannot name is a line on
                    // stderr, not a failed command: the rest of the repository is
                    // still fine.
                    eprintln!("warning: ignoring ref {}: {why}", found.name);
                    continue;
                }
            };
            let target = self.resolve_object(&found.object.sha)?;
            out.push(ref_from_target(name.clone(), &target).ok_or_else(|| {
                HostError::invalid(
                    "ref value",
                    format!("{} does not resolve to a digest", found.name),
                )
            })?);
            if let Entry::Vacant(slot) = self.refs.lock().expect("ref cache").entry(found.name) {
                slot.insert((
                    Instant::now() + self.client.options().ref_cache_ttl,
                    Some(found.object.sha),
                ));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(limit) = query.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    /// Read one ref *as it is now*.
    ///
    /// Never served from cache: this is the read a lease is built from, and a lease
    /// taken from a cached advertisement is a guess.
    pub fn resolve(&self, name: &str) -> HostResult<Option<RefTarget>> {
        let Some(found) = api::get_ref(&self.client, name)? else {
            self.forget(name);
            return self.absent_ref(name);
        };
        let target = self.resolve_object(&found.object.sha)?;
        self.repository_seen
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.refs.lock().expect("ref cache").insert(
            name.to_string(),
            (
                Instant::now() + self.client.options().ref_cache_ttl,
                Some(found.object.sha),
            ),
        );
        Ok(Some(target))
    }

    /// A ref read that came back 404, which the forge uses identically for "no such
    /// ref" and "no such repository".
    ///
    /// Once this process has seen the repository answer anything, an absent ref is
    /// simply absent. Before that, one call finds out, because the alternative —
    /// `https://github.com/gitiup/giti-uyp` reporting a beautifully empty store
    /// forever — is the failure mode this adapter could not live with: `gitiup
    /// status` would say "nothing pending" about a repository it never reached.
    fn absent_ref(&self, name: &str) -> HostResult<Option<RefTarget>> {
        if self
            .repository_seen
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(None);
        }
        match api::repository(&self.client) {
            Ok(_) => {
                self.repository_seen
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(None)
            }
            Err(why)
                if why.kind() == gitiup_host::HostErrorKind::NotFound
                    || why.kind() == gitiup_host::HostErrorKind::PermissionDenied =>
            {
                Err(api::repository_missing(&self.client, name, &why))
            }
            Err(why) => Err(why),
        }
    }

    /// Decide whether a git object is a gitiup pointer commit, and read what it
    /// promises if it is.
    fn resolve_object(&self, sha: &str) -> HostResult<RefTarget> {
        if let Some(known) = self.objects.lock().expect("object cache").get(sha) {
            return Ok(match known {
                Some(document) => RefTarget::Record {
                    sha: sha.to_string(),
                    document: document.clone(),
                },
                None => RefTarget::Plain {
                    sha: sha.to_string(),
                },
            });
        }
        let document = match api::get_tree(&self.client, sha, false)? {
            None => None,
            Some(tree) => {
                let blob_sha = tree
                    .entries
                    .iter()
                    .find(|entry| entry.path == REF_DOCUMENT_PATH)
                    .and_then(|entry| entry.sha.clone());
                match blob_sha {
                    None => None,
                    Some(blob_sha) => {
                        let bytes = api::get_blob(&self.client, &blob_sha)?
                            .ok_or_else(|| not_found("ref document", sha))?;
                        let document: RefDocument =
                            serde_json::from_slice(&bytes).map_err(|why| {
                                HostError::invalid(
                                    "stored ref document",
                                    format!(
                                        "pointer commit {sha} holds JSON this build \
                                         cannot read: {why}"
                                    ),
                                )
                            })?;
                        if document.schema > gitiup_host::HOST_SCHEMA_VERSION_MAX {
                            return Err(HostError::invalid(
                                "stored ref document",
                                format!(
                                    "pointer commit {sha} is schema {}, and this build \
                                     reads at most {}",
                                    document.schema,
                                    gitiup_host::HOST_SCHEMA_VERSION_MAX
                                ),
                            )
                            .with_hint(
                                "upgrade gitiup: a newer ref document can mean \
                                             something this build would misread",
                            ));
                        }
                        Some(document)
                    }
                }
            }
        };
        self.objects
            .lock()
            .expect("object cache")
            .insert(sha.to_string(), document.clone());
        Ok(match document {
            Some(document) => RefTarget::Record {
                sha: sha.to_string(),
                document,
            },
            None => RefTarget::Plain {
                sha: sha.to_string(),
            },
        })
    }

    /// Compare-and-swap a ref, and return the stored ref.
    pub fn write(
        &self,
        name: &str,
        expect: Expect,
        new: &Oid,
        actor: Option<&str>,
        message: Option<&str>,
    ) -> HostResult<Ref> {
        self.require_writable("write a ref")?;
        let current = self.resolve(name)?;
        // Check the precondition before spending anything on it.
        self.check_expectation(name, expect, current.as_ref())?;

        let parents: Vec<String> = current
            .iter()
            .map(|target| target.sha().to_string())
            .collect();
        let built = self.build_value(name, new, &parents, actor, message)?;
        let created = current.is_none();
        let force = matches!(expect, Expect::Any);

        if let Err(why) = self.apply(name, &built.sha, created, force) {
            if !why.is_conflict() {
                return Err(why);
            }
            // A refused forward move means one of two things, and telling them apart
            // is the whole point of reading again.
            let moved = self.resolve(name)?;
            let same_as_before = moved.map(|target| target.sha().to_string())
                == current.map(|target| target.sha().to_string());
            if !same_as_before {
                return Err(HostError::conflict(
                    name.to_string(),
                    match expect {
                        Expect::Is(oid) => Some(oid),
                        _ => None,
                    },
                    self.resolve(name)?
                        .and_then(|target| target.promised().ok()),
                )
                .with_hint(
                    "the ref moved between the read and the write; rebuild the change on \
                     top of what is there now and retry",
                ));
            }
            // The ref did not move, so this is not a race: the forge refused the
            // move itself, because it is not a fast-forward. Forcing it is not this
            // adapter's decision to make silently — a rewound record ref is how an
            // immutable history becomes a suggestable one, and no gitiup flow needs
            // a rewind (an amend or an abandon appends a new record instead). The
            // caller who really wants a force-push types it themselves.
            let _ = force;
            return Err(crate::client::ref_moved(name, Some(&why.to_string())));
        }

        // Never trust the acknowledgement.
        let read_back = self.resolve(name)?.ok_or_else(|| {
            HostError::unreachable(format!(
                "the forge accepted a write to {name} and then reported it absent"
            ))
            .with_hint("the write cannot be verified, so it is reported as a failure")
        })?;
        if read_back.sha() != built.sha {
            return Err(HostError::conflict(
                name.to_string(),
                Some(*new),
                read_back.promised().ok(),
            )
            .with_hint(
                "the forge moved the ref somewhere else: a hook, a protection rule or \
                 a writer that does not lease is rewriting this repository",
            ));
        }
        self.forget(name);
        ref_from_target(RefName::new(name)?, &read_back).ok_or_else(|| not_found("ref", name))
    }

    /// Compare-and-swap a deletion.
    ///
    /// GitHub's delete is unconditional, so this is check-then-delete: an
    /// expectation that does not match is reported (`NotFound` for a ref that is not
    /// there, `Conflict` for one that moved), and a delete that races a write is not
    /// caught. Nothing that gates a merge deletes a ref, and `advice()` says so.
    pub fn delete(&self, name: &str, expect: Expect, _actor: Option<&str>) -> HostResult<()> {
        self.require_writable("delete a ref")?;
        let current = self.resolve(name)?;
        match expect {
            // An unguarded delete of a ref that is not there is idempotent, exactly as
            // on the other hosts.
            Expect::Any if current.is_none() => return Ok(()),
            Expect::Absent => {
                self.check_expectation(name, Expect::Absent, current.as_ref())?;
                if current.is_none() {
                    return Ok(());
                }
            }
            Expect::Is(oid) => {
                let Some(target) = current.as_ref() else {
                    return Err(not_found("ref", name));
                };
                let found = target.promised().ok();
                if found != Some(oid) {
                    return Err(HostError::conflict(name.to_string(), Some(oid), found)
                        .with_hint("the ref holds something else: re-read before deleting"));
                }
            }
            Expect::Any => {}
        }
        if !api::delete_ref(&self.client, name)? {
            return Err(not_found("ref", name));
        }
        self.forget(name);
        Ok(())
    }

    fn apply(&self, name: &str, sha: &str, created: bool, force: bool) -> HostResult<()> {
        if created {
            api::create_ref(&self.client, name, sha)
        } else {
            api::move_ref(&self.client, name, sha, force)
        }
    }

    fn check_expectation(
        &self,
        name: &str,
        expect: Expect,
        current: Option<&RefTarget>,
    ) -> HostResult<()> {
        let promised = current.and_then(|target| target.promised().ok());
        match expect {
            Expect::Absent if current.is_some() => Err(HostError::conflict(
                name.to_string(),
                None,
                promised,
            )
            .with_hint("create-only means create-only: read the ref and build on top of it")),
            Expect::Is(oid) if promised.as_ref() != Some(&oid) => {
                Err(
                    HostError::conflict(name.to_string(), Some(oid), promised).with_hint(
                        "the ref is not where the caller thought it was: re-read it and \
                     rebuild the change on top of what is actually there",
                    ),
                )
            }
            _ => Ok(()),
        }
    }

    /// Turn a promised digest into the git object the ref will hold.
    fn build_value(
        &self,
        name: &str,
        promised: &Oid,
        parents: &[String],
        actor: Option<&str>,
        message: Option<&str>,
    ) -> HostResult<Built> {
        if promised.len() == 20 {
            // A git SHA-1: the caller means that object itself. A branch written by
            // plain `git push` stays exactly what it looks like.
            return Ok(Built {
                sha: promised.hex(),
            });
        }
        let mut document = RefDocument::new(promised, actor, message);
        let mut entries = vec![TreeEntryInput::inline(
            REF_DOCUMENT_PATH,
            String::from_utf8_lossy(&document.to_bytes()?).into_owned(),
        )];
        let carried = self
            .recent
            .lock()
            .expect("recent lock")
            .get(&document.target)
            .cloned();
        if let Some(bytes) = carried {
            let entry = match std::str::from_utf8(&bytes) {
                Ok(text) => TreeEntryInput::inline(RECORD_PATH, text.to_string()),
                Err(_) => {
                    TreeEntryInput::blob(RECORD_PATH, api::create_blob(&self.client, &bytes)?)
                }
            };
            document.record = Some(Oid::hash_bytes(&bytes).hex());
            entries.push(entry);
            // The document names the record it carries, so rewrite it: the copy in
            // the tree has to describe the tree it sits in.
            entries[0] = TreeEntryInput::inline(
                REF_DOCUMENT_PATH,
                String::from_utf8_lossy(&document.to_bytes()?).into_owned(),
            );
        }
        let tree = api::create_tree(&self.client, None, &entries)?;
        let subject = format!(
            "gitiup: {} {name} -> {}",
            if parents.is_empty() { "create" } else { "move" },
            short(&document.target)
        );
        let sha = api::create_commit(&self.client, &subject, &tree, parents, &person(actor))?;
        Ok(Built { sha })
    }

    // -- records ------------------------------------------------------------

    /// The head of the record chain with its full tree.
    fn chain(&self) -> HostResult<Option<(String, api::Tree)>> {
        let name = layout::kv_ref_name();
        let Some(target) = self.resolve(name.as_str())? else {
            return Ok(None);
        };
        let sha = target.sha().to_string();
        let tree = api::get_tree(&self.client, &sha, true)?.ok_or_else(|| {
            HostError::invalid(
                "record chain",
                format!("{} points at {sha}, which has no tree", name),
            )
        })?;
        if tree.truncated {
            return Err(HostError::unsupported(
                "kv-tree-size",
                "this store's record tree is bigger than the forge will list at once",
            )
            .with_hint(
                "the chain needs splitting per namespace, or a store with a real key \
                 space (the S3 host); gitiup will not treat a truncated listing as \
                 the whole record set",
            ));
        }
        Ok(Some((sha, tree)))
    }

    /// Store a record, idempotently, retrying an append that lost its race.
    pub fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid> {
        self.require_writable("store a record")?;
        let oid = Oid::hash_bytes(content);
        let path = layout::record_path(namespace, &oid);
        let attempts = self.client.options().cas_attempts.max(1);
        for attempt in 0..attempts {
            let (head, base_tree) = match self.chain()? {
                None => (None, None),
                Some((sha, tree)) => {
                    if tree
                        .entries
                        .iter()
                        .any(|entry| entry.path == path && entry.obj_type == "blob")
                    {
                        // Already there — idempotence without a write at all.
                        self.remember(&oid, content);
                        return Ok(oid);
                    }
                    (Some(sha), tree.sha)
                }
            };
            match self.append(
                namespace,
                &oid,
                content,
                head.as_deref(),
                base_tree.as_deref(),
            ) {
                Ok(()) => {
                    self.remember(&oid, content);
                    return Ok(oid);
                }
                Err(why) if why.is_conflict() && attempt + 1 < attempts => {
                    // Someone else appended first: rebuild on their tip.
                    std::thread::sleep(self.client.options().cas_backoff * (attempt as u32 + 1));
                    continue;
                }
                Err(why) => return Err(why),
            }
        }
        Err(
            HostError::conflict(layout::kv_ref_name().to_string(), None, None).with_hint(
                "every append to the record chain lost its race; another writer is busy",
            ),
        )
    }

    fn append(
        &self,
        namespace: &Namespace,
        oid: &Oid,
        content: &[u8],
        head: Option<&str>,
        base_tree: Option<&str>,
    ) -> HostResult<()> {
        let path = layout::record_path(namespace, oid);
        let entry = match std::str::from_utf8(content) {
            Ok(text) => TreeEntryInput::inline(path.clone(), text.to_string()),
            Err(_) => TreeEntryInput::blob(path.clone(), api::create_blob(&self.client, content)?),
        };
        let tree = api::create_tree(&self.client, base_tree, &[entry])?;
        let message = format!("gitiup kv: add {path}");
        let parents: Vec<String> = head.into_iter().map(str::to_string).collect();
        let commit = api::create_commit(&self.client, &message, &tree, &parents, &person(None))?;
        let name = layout::kv_ref_name();
        match head {
            None => api::create_ref(&self.client, name.as_str(), &commit),
            Some(_) => {
                // The lease is the `force = false`: the forge accepts a descendant of
                // what is there now and refuses anything else, which is exactly what
                // an append means.
                api::move_ref(&self.client, name.as_str(), &commit, false)
            }
        }
    }

    /// Read a record's bytes, wherever in the store they live.
    pub fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        let Some(entry) = self.find(oid)? else {
            return Ok(None);
        };
        let sha = entry.sha.clone().unwrap_or_default();
        if sha.is_empty() {
            return Ok(None);
        }
        let bytes = api::get_blob(&self.client, &sha)?.ok_or_else(|| {
            not_found("record blob", &format!("{} (tree entry {sha})", oid.hex()))
        })?;
        if &Oid::hash_bytes(&bytes) != oid {
            return Err(HostError::invalid(
                "stored record",
                format!(
                    "the object stored as {} hashes to {}, so this store is lying about \
                     its content address",
                    oid.hex(),
                    Oid::hash_bytes(&bytes)
                ),
            )
            .with_hint(
                "verify nothing from this store until it is repaired: the bytes behind a \
                 name are not the bytes that name promises",
            ));
        }
        Ok(Some(bytes))
    }

    /// Metadata for a record, without transferring it.
    pub fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        let Some(entry) = self.find(oid)? else {
            return Ok(None);
        };
        let namespace = layout::namespace_of(&entry.path)
            .ok_or_else(|| HostError::invalid("record path", entry.path.clone()))?;
        Ok(Some(BlobEntry {
            namespace,
            oid: *oid,
            size: entry.size.unwrap_or(0),
            created_at: None,
        }))
    }

    /// Everything matching a [`Prefix`] pattern.
    pub fn list_prefix(&self, pattern: &str) -> HostResult<Vec<BlobEntry>> {
        let prefix = Prefix::parse(pattern)?;
        let Some((_, tree)) = self.chain()? else {
            return Ok(Vec::new());
        };
        let mut out: Vec<BlobEntry> = Vec::new();
        for entry in tree.entries.iter().filter(|entry| entry.obj_type == "blob") {
            let (Some(namespace), Some(oid)) = (
                layout::namespace_of(&entry.path),
                layout::oid_of(&entry.path),
            ) else {
                continue;
            };
            if !prefix.matches(&namespace, &oid) {
                continue;
            }
            out.push(BlobEntry {
                namespace,
                oid,
                size: entry.size.unwrap_or(0),
                created_at: None,
            });
        }
        out.sort_by_key(|a| a.key());
        Ok(out)
    }

    fn find(&self, oid: &Oid) -> HostResult<Option<api::TreeEntry>> {
        let Some((_, tree)) = self.chain()? else {
            return Ok(None);
        };
        let suffix = format!("/{}", oid.hex());
        Ok(tree
            .entries
            .iter()
            .find(|entry| {
                entry.obj_type == "blob"
                    && (entry.path == oid.hex() || entry.path.ends_with(&suffix))
            })
            .cloned())
    }

    /// The chain head commit, for `gitiup remote show`.
    pub fn chain_head(&self) -> HostResult<Option<String>> {
        Ok(self
            .resolve(layout::kv_ref_name().as_str())?
            .map(|target| target.sha().to_string()))
    }

    // -- bookkeeping --------------------------------------------------------

    fn require_writable(&self, action: &str) -> HostResult<()> {
        if self.client.options().read_only {
            return Err(HostError::unsupported(
                "read-only",
                format!("this remote is configured read-only, so gitiup will not {action}"),
            )
            .with_hint(
                "`read-only = \"true\"` was set (or the token cannot write and the remote \
                 says so); drop the option or use a credential that may push",
            ));
        }
        Ok(())
    }

    /// Forget a cached ref (after any write to it).
    fn forget(&self, name: &str) {
        self.refs.lock().expect("ref cache").remove(name);
    }

    /// Forget every cached ref.
    pub fn forget_all_refs(&self) {
        self.refs.lock().expect("ref cache").clear();
    }

    /// Remember what this process stored, so a pointer commit can carry it.
    fn remember(&self, oid: &Oid, bytes: &[u8]) {
        let mut recent = self.recent.lock().expect("recent lock");
        recent.insert(oid.hex(), bytes.to_vec());
        while recent.len() > RECENT_RECORDS {
            if let Some(oldest) = recent.keys().next().cloned() {
                recent.remove(&oldest);
            }
        }
    }
}

/// A value built for a ref write.
struct Built {
    /// The git object the forge will hold.
    sha: String,
}

fn person(actor: Option<&str>) -> api::Person {
    let name = actor
        .map(str::to_string)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| Actor::unknown().to_string());
    api::Person {
        name: name.clone(),
        // A machine identity, in a domain that cannot receive mail: the actor's
        // real address is not ours to invent, and a fake `@users.noreply` one would
        // silently attribute the commit to a stranger with that login.
        email: format!("{}@gitiup.invalid", sanitize_mailbox(&name)),
        date: Some(Timestamp::now().to_rfc3339()),
    }
}

/// Make a display name safe enough to sit in the local part of an email.
fn sanitize_mailbox(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "gitiup".to_string()
    } else {
        cleaned
    }
}

fn not_found(what: &str, key: &str) -> HostError {
    HostError::not_found(what, key.to_string())
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

/// The `Ref` a resolved target reports, with the metadata a forge cannot keep.
pub fn ref_from_target(name: RefName, target: &RefTarget) -> Option<Ref> {
    let oid = target.promised().ok()?;
    let (actor, at) = match target.document() {
        Some(document) => (
            document.actor.as_deref().map(Actor::from),
            Some(Timestamp::from_unix(document.at)),
        ),
        None => (None, None),
    };
    Some(Ref::new(name, oid).with_meta(actor, at))
}

/// How long a cached object answer stays valid — forever, spelled as a duration so
/// the type says why there is no timer.
pub const OBJECT_TTL: Duration = Duration::from_secs(u64::MAX / 4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_document_survives_its_round_trip() {
        let oid = Oid::hash_bytes(b"a change record");
        let document = RefDocument::new(&oid, Some("ada"), Some("open change c1"));
        let bytes = document.to_bytes().unwrap();
        let back: RefDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, document);
        assert_eq!(back.target_oid().unwrap(), oid);
        assert_eq!(back.schema, gitiup_host::HOST_SCHEMA_VERSION);
    }

    #[test]
    fn a_target_reports_both_halves_of_a_pointer_commit() {
        let oid = Oid::hash_bytes(b"attestation");
        let document = RefDocument::new(&oid, Some("ada"), None);
        let pointer = RefTarget::Record {
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
            document: document.clone(),
        };
        assert_eq!(pointer.promised().unwrap(), oid);
        assert_eq!(pointer.document().unwrap(), &document);
        let plain = RefTarget::Plain {
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
        };
        assert_eq!(plain.promised().unwrap().len(), 20);
        assert!(plain.document().is_none());
        let nonsense = RefTarget::Record {
            sha: "deadbeef".into(),
            document: RefDocument {
                schema: 1,
                target: "not a digest".into(),
                actor: None,
                message: None,
                at: 0,
                record: None,
            },
        };
        assert!(nonsense.promised().is_err());
    }

    #[test]
    fn a_ref_reported_by_the_forge_carries_the_actors_metadata() {
        let oid = Oid::hash_bytes(b"change");
        let pointer = RefTarget::Record {
            sha: "0123456789abcdef0123456789abcdef01234567".into(),
            document: RefDocument::new(&oid, Some("ada"), Some("reason")),
        };
        let reference = ref_from_target(RefName::change_head("c1").unwrap(), &pointer).unwrap();
        assert_eq!(reference.oid, oid);
        assert_eq!(reference.updated_by.unwrap().as_str(), "ada");
        assert_eq!(reference.schema, Some(gitiup_host::HOST_SCHEMA_VERSION));
    }

    #[test]
    fn a_mailbox_name_is_made_safe_without_inventing_a_person() {
        assert_eq!(sanitize_mailbox("Ada Lovelace"), "ada-lovelace");
        assert_eq!(sanitize_mailbox("  "), "gitiup");
        assert_eq!(sanitize_mailbox("ada@example.com"), "ada-example-com");
        let person = person(Some("Ada Lovelace"));
        assert_eq!(person.name, "Ada Lovelace");
        assert!(
            person.email.ends_with("@gitiup.invalid"),
            "{}",
            person.email
        );
    }
}

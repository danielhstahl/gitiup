//! The plain-git host seen through the traits: refs, records and packs.
//!
//! This is where gitiup's three verbs — move a ref with CAS, put a content
//! addressed record, move objects — become git commands. The layout decisions
//! (pointer commits, per-namespace record chains, leases) are documented on the
//! host itself in [`super`]; this module is the mechanics.

use std::collections::BTreeSet;

use super::{GitHost, KV_ROOT, Resolved, Target, ZERO_OID, plumb};
use crate::blob::{BlobEntry, BlobStore, Namespace, Prefix};
use crate::capability::{Capabilities, Host, HostInfo, HostKind, implemented_by};
use crate::error::{HostError, HostResult, NotFound};
use crate::oid::Oid;
use crate::pack::{Pack, PackFormat, PackRequest, is_git_packfile};
use crate::refs::{Actor, Expect, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate, ns};
use crate::time::Timestamp;

/// The namespace raw gitiup packs are stored in, so a `want` naming a pack's own
/// digest resolves the way it does on the bucket and `fs` hosts.
pub const PACK_NAMESPACE: Namespace = Namespace::const_new("pack");

/// Jitter source for [`GitHost::backoff`].
static RETRY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl GitHost {
    /// Which chain holds `oid`, and the tree entry that names it.
    ///
    /// A record's address is its own digest, so a lookup is "list the chains and
    /// find the file called `<hex>`". Known namespaces are tried first, because
    /// after the first fetch those are the only chains that exist in practice.
    pub(crate) fn find_record(&self, oid: &Oid) -> HostResult<Option<(Namespace, u64)>> {
        let hex = oid.hex();
        if hex.len() != 64 {
            // Only a full SHA-256 can name a record; a short or git-length id is
            // not one, and saying so beats a scan of every chain.
            return Ok(None);
        }
        let known: Vec<String> = {
            let state = self.lock();
            state.namespaces.clone().into_iter().collect()
        };
        let mut candidates: Vec<String> = known
            .iter()
            .filter(|name| (*name).starts_with(&hex[..2.min(hex.len())]))
            .cloned()
            .collect();
        if candidates.is_empty() || self.lock().fetched_at.is_none() {
            // Nothing in the known namespaces: re-fetch (once per lookup at worst)
            // and look at every chain the store has. A record somebody published a
            // moment ago must be findable, which is a different promise from the
            // ref advertisement's "what I saw a moment ago".
            self.sync(true)?;
            for line in plumb::local_refs(&self.inner.cli)? {
                if let Some(namespace) = line.name.strip_prefix(&format!("{KV_ROOT}/"))
                    && !namespace.is_empty()
                    && !candidates.contains(&namespace.to_string())
                {
                    candidates.push(namespace.to_string());
                }
            }
        }
        for namespace in candidates {
            let Ok(namespace_name) = Namespace::new(namespace.clone()) else {
                continue;
            };
            let Some(tip) = self.chain_tip(&namespace_name)? else {
                continue;
            };
            for entry in plumb::list_tree(&self.inner.cli, &tip)? {
                if entry.path == hex {
                    self.note_namespace(&namespace_name);
                    return Ok(Some((namespace_name, entry.size)));
                }
            }
        }
        Ok(None)
    }

    /// The tip commit of a namespace's record chain, in the mirror.
    pub(crate) fn chain_tip(&self, namespace: &Namespace) -> HostResult<Option<String>> {
        let name = Self::kv_ref(namespace);
        // The mirror is authoritative for reads here: it was fetched, and a chain
        // tip that moved since is a *write* problem (a lease), not a read one.
        Ok(plumb::local_refs(&self.inner.cli)?
            .into_iter()
            .find(|line| line.name == name.as_str())
            .map(|line| line.oid))
    }

    /// The bytes of a record, verified against its address.
    pub(crate) fn get_blob(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        let Some((_, _)) = self.find_record(oid)? else {
            return Ok(None);
        };
        let Some(bytes) = self.read_record(oid)? else {
            return Ok(None);
        };
        if &Oid::hash_bytes(&bytes) != oid {
            return Err(HostError::Storage(Box::new(crate::error::StorageError {
                what: "verify record".into(),
                key: oid.hex(),
                message: "stored content does not match its content address".into(),
                retryable: false,
                source: None,
            })));
        }
        Ok(Some(bytes))
    }

    /// Pause before retrying a record append that lost the race.
    ///
    /// Exponential, capped, and jittered with a process-wide counter so two
    /// writers that collided on attempt one do not collide on attempt two as well.
    fn backoff(&self, attempt: u32) {
        let base = self.inner.options.cas_backoff;
        if base.is_zero() {
            return;
        }
        let cap = self.inner.options.cas_backoff_cap.max(base);
        let grown = base.saturating_mul(1u32 << attempt.min(5)).min(cap);
        let jitter = {
            use std::sync::atomic::Ordering;
            let n = RETRY_COUNTER.fetch_add(1, Ordering::Relaxed);
            grown / 3 * ((n % 3) as u32)
        };
        std::thread::sleep(grown + jitter);
    }

    /// Read the file named `<hex>` out of whichever chain holds it.
    fn read_record(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        let hex = oid.hex();
        for line in plumb::local_refs(&self.inner.cli)? {
            let Some(namespace) = line.name.strip_prefix(&format!("{KV_ROOT}/")) else {
                continue;
            };
            if namespace.is_empty() {
                continue;
            }
            for entry in plumb::list_tree(&self.inner.cli, &line.oid)? {
                if entry.path == hex {
                    return plumb::cat_blob(&self.inner.cli, &entry.blob);
                }
            }
        }
        Ok(None)
    }

    /// Every chain, with the times its records were introduced.
    ///
    /// Forced: a record listing is "what is in the store", not an advertisement,
    /// and a verification run that lists attestations must not miss the one that
    /// landed a second ago.
    fn chains(&self) -> HostResult<Vec<(Namespace, String)>> {
        self.sync(true)?;
        let mut out = Vec::new();
        for line in plumb::local_refs(&self.inner.cli)? {
            let Some(name) = line.name.strip_prefix(&format!("{KV_ROOT}/")) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if let Ok(namespace) = Namespace::new(name) {
                out.push((namespace, line.oid.clone()));
            }
        }
        Ok(out)
    }
}

impl RefStore for GitHost {
    fn list_refs(&self, query: &RefQuery) -> HostResult<Vec<Ref>> {
        self.sync(false)?;
        let wanted = query.prefix.clone().unwrap_or_default();
        let mut out: Vec<Ref> = Vec::new();
        for line in plumb::local_refs(&self.inner.cli)? {
            if Self::is_internal(&line.name) {
                // The record chains and the manifest are layout, not refs the
                // caller asked about — unless the query names that prefix.
                let asked_for_layout = query
                    .prefix
                    .as_deref()
                    .is_some_and(|prefix| KV_ROOT.starts_with(prefix.trim_end_matches('/')));
                if !asked_for_layout {
                    continue;
                }
            }
            let Ok(name) = RefName::new(line.name.clone()) else {
                continue;
            };
            if !query.matches(&name) {
                continue;
            }
            if !wanted.is_empty() && !name.starts_with(&wanted) {
                continue;
            }
            let resolved = match self.resolve(&line.name, &line.oid) {
                Ok(resolved) => resolved,
                // A ref we cannot read is worse than a ref we did not mention:
                // say nothing quietly? No — report it, with the object we saw.
                Err(_) => Resolved {
                    git_oid: line.oid.clone(),
                    value: match Oid::from_hex(&line.oid) {
                        Ok(oid) => oid,
                        Err(_) => continue,
                    },
                    actor: None,
                    at: None,
                    pointer: false,
                },
            };
            out.push(self.ref_for(&name, &resolved));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(limit) = query.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    /// A point lookup is a fresh `ls-remote` of that one ref.
    ///
    /// Listings may be an advertisement from a moment ago; this may not. A caller
    /// asking "where is this ref *now*?" is about to decide something.
    fn get_ref(&self, name: &RefName) -> HostResult<Option<Ref>> {
        match self.probe(name)? {
            None => Ok(None),
            Some(resolved) => Ok(Some(self.ref_for(name, &resolved))),
        }
    }

    /// Compare-and-swap a ref, emulated the way git allows — see the [module
    /// docs](super#compare-and-swap-emulated-the-only-way-git-allows).
    fn update_ref_cas(&self, update: &RefUpdate) -> HostResult<Ref> {
        Self::reject_reserved(&update.name)?;
        self.require_write()?;
        let current = self.probe(&update.name)?;
        let found = current.as_ref().map(|resolved| resolved.value);
        if !update.expect.matches(found) {
            return Err(conflict(&update.name, update.expect, found));
        }
        let target = self.plan_target(update, current.as_ref())?;
        let lease = lease_for(update.expect, current.as_ref());
        let push = plumb::Push {
            src: Some(target.object().to_string()),
            dst: update.name.as_str().to_string(),
            lease,
        };
        self.push_refs(
            std::slice::from_ref(&push),
            push_style_for(update.expect, 1),
            &[(
                update.name.as_str().to_string(),
                Some(target.object().to_string()),
            )],
            &update.name,
        )?;
        Ok(Ref {
            name: update.name.clone(),
            oid: update.new,
            updated_by: update.actor.clone().or_else(|| Some(Actor::from_env())),
            updated_at: Some(Timestamp::now()),
            schema: Some(crate::HOST_SCHEMA_VERSION),
        })
    }

    /// A batch is one `git push --atomic`: the receiving side applies it as a
    /// transaction, which is why this host can promise
    /// `atomic_multi_write` rather than emulate it with rollback.
    fn update_refs_cas(&self, updates: &[RefUpdate]) -> HostResult<Vec<Ref>> {
        if updates.is_empty() {
            return Ok(Vec::new());
        }
        for update in updates {
            Self::reject_reserved(&update.name)?;
        }
        self.require_write()?;
        // One fresh advertisement for the whole batch: every expectation is
        // checked against the same snapshot of the remote before anything is sent.
        self.sync(true)?;
        let mut pushes = Vec::with_capacity(updates.len());
        let mut outcomes = Vec::with_capacity(updates.len());
        let mut written = Vec::with_capacity(updates.len());
        // Expectations may refer to a ref the same batch moves, so the working
        // copy is updated as we go, exactly like the trait's default does.
        let mut working: Vec<(String, Option<Resolved>)> = Vec::new();
        for update in updates {
            let current = match working
                .iter()
                .find(|(name, _)| name == update.name.as_str())
            {
                Some((_, resolved)) => resolved.clone(),
                None => self.probe(&update.name)?,
            };
            let found = current.as_ref().map(|resolved| resolved.value);
            if !update.expect.matches(found) {
                return Err(conflict(&update.name, update.expect, found));
            }
            let target = self.plan_target(update, current.as_ref())?;
            pushes.push(plumb::Push {
                src: Some(target.object().to_string()),
                dst: update.name.as_str().to_string(),
                lease: lease_for(update.expect, current.as_ref()),
            });
            outcomes.push((
                update.name.as_str().to_string(),
                Some(target.object().to_string()),
            ));
            written.push(Ref {
                name: update.name.clone(),
                oid: update.new,
                updated_by: update.actor.clone().or_else(|| Some(Actor::from_env())),
                updated_at: Some(Timestamp::now()),
                schema: Some(crate::HOST_SCHEMA_VERSION),
            });
            working.push((
                update.name.as_str().to_string(),
                Some(Resolved {
                    git_oid: target.object().to_string(),
                    value: update.new,
                    actor: update.actor.clone(),
                    at: Some(Timestamp::now()),
                    pointer: matches!(target, Target::Pointer { .. }),
                }),
            ));
        }
        self.push_refs(
            &pushes,
            push_style_for(Expect::Any, pushes.len()),
            &outcomes,
            &updates[0].name,
        )?;
        Ok(written)
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> HostResult<()> {
        Self::reject_reserved(&deletion.name)?;
        self.require_write()?;
        let current = self.probe(&deletion.name)?;
        let found = current.as_ref().map(|resolved| resolved.value);
        match (found, deletion.expect) {
            (None, Expect::Is(wanted)) => {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "ref".into(),
                    key: deletion.name.to_string(),
                    hint: Some(format!(
                        "it is not here, so the delete that expected {wanted} cannot be sure \
                         anything was removed; re-check the ref list",
                    )),
                })));
            }
            // Deleting what is not there is idempotent, exactly like the fs host.
            (None, Expect::Absent | Expect::Any) => return Ok(()),
            (Some(found), expect) if !expect.matches(Some(found)) => {
                return Err(conflict(&deletion.name, expect, Some(found)));
            }
            (Some(_), _) => {}
        }
        let lease = match deletion.expect {
            Expect::Any => None,
            // A deletion is leased on the git object we just read, so a concurrent
            // move loses the delete rather than deleting the wrong thing.
            _ => current.as_ref().map(|resolved| resolved.git_oid.clone()),
        };
        let push = plumb::Push {
            src: None,
            dst: deletion.name.as_str().to_string(),
            lease,
        };
        self.push_refs(
            std::slice::from_ref(&push),
            push_style_for(deletion.expect, 1),
            &[(deletion.name.as_str().to_string(), None)],
            &deletion.name,
        )
    }

    fn fetch_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        match request.format {
            PackFormat::Raw => self.fetch_raw_pack(request),
            PackFormat::GitPackfile => self.fetch_git_pack(request),
        }
    }

    fn put_pack(&self, pack: &Pack) -> HostResult<Oid> {
        pack.check_size()?;
        match pack.format {
            PackFormat::Raw => {
                let records = pack.raw_objects()?;
                let oid = pack.oid();
                // The pack body is itself a record, which is what lets a later
                // fetch answer "give me that pack" by digest, as the bucket host
                // does with `packs/<oid>.pack`.
                self.put_cas(&PACK_NAMESPACE, &pack.bytes)?;
                for (namespace, content) in &records {
                    self.put_cas(namespace, content)?;
                }
                Ok(oid)
            }
            PackFormat::GitPackfile => {
                if !is_git_packfile(&pack.bytes) {
                    return Err(HostError::invalid(
                        "pack",
                        "bytes do not look like a git packfile",
                    ));
                }
                // Objects land in the mirror; they travel to the remote with the
                // next ref update that makes them reachable, which is how git
                // works. The packfile is also stored as a record, so it survives
                // on the remote even if no ref is moved for a while.
                plumb::index_pack(&self.inner.cli, &pack.bytes)?;
                self.put_cas(&PACK_NAMESPACE, &pack.bytes)?;
                Ok(pack.oid())
            }
        }
    }
}

impl GitHost {
    /// Answer a raw gitiup pack request out of the record store.
    fn fetch_raw_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        let haves: BTreeSet<String> = request.have.iter().map(Oid::hex).collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut objects: Vec<(Namespace, Vec<u8>)> = Vec::new();
        let mut wanted_bytes = 0usize;
        let mut queue: Vec<Oid> = request.wants.clone();
        let mut budget = 100_000usize;
        while let Some(want) = queue.pop() {
            let hex = want.hex();
            if haves.contains(&hex) || !seen.insert(hex.clone()) {
                continue;
            }
            budget = budget.checked_sub(1).ok_or_else(|| {
                HostError::invalid(
                    "pack request",
                    "this fetch walks more than 100000 objects; narrow the wants",
                )
            })?;
            let Some(bytes) = self.get_blob(&want)? else {
                return Err(HostError::NotFound(Box::new(NotFound {
                    what: "blob".into(),
                    key: hex.clone(),
                    hint: Some(format!(
                        "'{}' is not in this store; push it first or check the digest",
                        &hex[..hex.len().min(12)]
                    )),
                })));
            };
            // A want that names a stored pack expands into that pack's records:
            // a fetch answers wants, it does not wrap a pack in a pack.
            if want.hex() != hex {
                continue;
            }
            // A stored pack is a container, so a `want` that names it expands into
            // the records inside it rather than being served as bytes.
            if let Ok(pack) = Pack::from_bytes(bytes.clone()).raw_objects()
                && (pack.iter().any(|(_, bytes)| !bytes.is_empty()) || pack.is_empty())
            {
                let mut expanded = false;
                for (_namespace, content) in pack {
                    expanded = true;
                    let digest = Oid::hash_bytes(&content);
                    if haves.contains(&digest.hex()) || seen.contains(&digest.hex()) {
                        continue;
                    }
                    queue.push(digest);
                }
                if expanded {
                    continue;
                }
            }
            let Some((namespace, _)) = self.find_record(&want)? else {
                continue;
            };
            wanted_bytes += bytes.len();
            if let Some(limit) = request.limit_bytes
                && wanted_bytes > limit
            {
                return Err(HostError::unsupported(
                    "pack-limit",
                    format!("the requested objects need more than the {limit} byte limit"),
                )
                .with_hint("raise limit_bytes, or narrow the wants and haves"));
            }
            objects.push((namespace, bytes));
        }
        Pack::from_raw_objects(objects)
    }

    /// Answer a git packfile request from the object database: exactly the
    /// `rev-list | pack-objects` a server does for `git fetch`.
    fn fetch_git_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        self.sync(false)?;
        let wants: Vec<String> = if request.wants.is_empty() {
            // No wants: everything under the requested ref prefixes (an
            // unshallowed fetch of, say, `refs/changes`).
            let prefixes = if request.ref_prefixes.is_empty() {
                vec![ns::HEADS.to_string()]
            } else {
                request.ref_prefixes.clone()
            };
            let mut out = Vec::new();
            for line in plumb::local_refs(&self.inner.cli)? {
                let Ok(name) = RefName::new(line.name.clone()) else {
                    continue;
                };
                if prefixes
                    .iter()
                    .any(|prefix| name.starts_with(prefix.as_str()))
                {
                    out.push(line.oid);
                }
            }
            out
        } else {
            request.wants.iter().map(|oid| oid.hex()).collect()
        };
        let haves: Vec<String> = request.have.iter().map(|oid| oid.hex()).collect();
        let bytes = plumb::pack_objects(&self.inner.cli, &wants, &haves)?;
        if bytes.is_empty() {
            return Ok(Pack {
                format: PackFormat::GitPackfile,
                bytes,
            });
        }
        if let Some(limit) = request.limit_bytes
            && bytes.len() > limit
        {
            return Err(HostError::unsupported(
                "pack-limit",
                format!(
                    "the packfile the remote would send is {} bytes, over the {limit} byte limit",
                    bytes.len()
                ),
            )
            .with_hint("raise limit_bytes, or fetch by ref with haves so less has to be sent"));
        }
        Pack::git_packfile(bytes)
    }
}

impl BlobStore for GitHost {
    /// Append a record to its namespace chain.
    ///
    /// The chain is one mutable ref, so two writers can race; the append is a
    /// leased push and a loser rebuilds on the new tip (`cas-attempts` times), so
    /// publishing two different attestations concurrently lands both instead of
    /// silently losing one. A record that is already there is a no-op: `put_cas`
    /// is idempotent on every host, and the digest is what proves it.
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid> {
        self.require_write()?;
        let oid = Oid::hash_bytes(content);
        let hex = oid.hex();
        let chain = Self::kv_ref(namespace);
        let mut last: Option<(Option<String>, Option<String>)> = None;
        for attempt in 0..=self.inner.options.cas_attempts {
            if self.find_record(&oid)?.is_some() {
                self.note_namespace(namespace);
                return Ok(oid);
            }
            let tip = plumb::ls_one(&self.inner.cli, &self.inner.url, chain.as_str())?;
            let existing = match &tip {
                Some(tip) => plumb::list_tree(&self.inner.cli, tip)?,
                None => Vec::new(),
            };
            if existing.iter().any(|entry| entry.path == hex) {
                self.note_namespace(namespace);
                return Ok(oid);
            }
            let blob = plumb::write_blob(&self.inner.cli, content)?;
            let mut entries: Vec<plumb::TreeSpec<'_>> = existing
                .iter()
                .map(|entry| plumb::TreeSpec {
                    mode: plumb::RECORD_MODE,
                    kind: "blob",
                    oid: &entry.blob,
                    path: &entry.path,
                })
                .collect();
            entries.push(plumb::TreeSpec {
                mode: plumb::RECORD_MODE,
                kind: "blob",
                oid: &blob,
                path: &hex,
            });
            let tree = plumb::make_tree(&self.inner.cli, &entries)?;
            let parents: Vec<String> = tip.clone().into_iter().collect();
            let commit = plumb::commit_tree(
                &self.inner.cli,
                &tree,
                &parents,
                &format!("gitiup: record {hex} in {namespace}"),
                Some(&Actor::from_env()),
                Timestamp::now(),
            )?;
            let push = plumb::Push {
                src: Some(commit),
                dst: chain.as_str().to_string(),
                lease: Some(tip.clone().unwrap_or_else(|| ZERO_OID.to_string())),
            };
            let _transport = self.lock_transport();
            match plumb::push(
                &self.inner.cli,
                &self.inner.url,
                &[push],
                plumb::PushStyle::default(),
            ) {
                Ok(()) => {
                    self.note_namespace(namespace);
                    self.note_write();
                    return Ok(oid);
                }
                Err(failure) if failure.is_stale_lease() => {
                    // Somebody else appended while we were building: rebuild on
                    // their tip rather than losing either record. The pause grows
                    // and is jittered, because six writers that retry instantly
                    // collide again on the very next attempt.
                    last = Some((tip, Some(failure.summary())));
                    self.flush_ref_cache();
                    self.backoff(attempt);
                    continue;
                }
                Err(failure) => return Err(failure.into()),
            }
        }
        let (tip, why) = last.unwrap_or((None, None));
        Err(HostError::conflict(
            chain.as_str(),
            tip.as_deref().and_then(|hex| Oid::from_hex(hex).ok()),
            plumb::ls_one(&self.inner.cli, &self.inner.url, chain.as_str())?
                .as_deref()
                .and_then(|hex| Oid::from_hex(hex).ok()),
        )
        .with_hint(format!(
            "the record chain for {namespace} moved {} times: another writer is publishing \
             records into it concurrently{} (raise cas-attempts if that is normal)",
            self.inner.options.cas_attempts,
            why.map(|why| format!(", last refusal: {why}"))
                .unwrap_or_default()
        )))
    }

    fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        self.get_blob(oid)
    }

    fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        match self.find_record(oid)? {
            None => Ok(None),
            Some((namespace, size)) => Ok(Some(BlobEntry {
                namespace,
                oid: *oid,
                size,
                created_at: self.record_created_at(oid)?,
            })),
        }
    }

    fn exists(&self, oid: &Oid) -> HostResult<bool> {
        Ok(self.find_record(oid)?.is_some())
    }

    fn list_prefix(&self, pattern: &str) -> HostResult<Vec<BlobEntry>> {
        let prefix = Prefix::parse(pattern)?;
        let mut out: Vec<BlobEntry> = Vec::new();
        for (namespace, tip) in self.chains()? {
            if let Some(want) = &prefix.namespace
                && want != &namespace
            {
                continue;
            }
            let entries = plumb::list_tree(&self.inner.cli, &tip)?;
            let times = plumb::introduced_at(&self.inner.cli, &tip).unwrap_or_default();
            for entry in entries {
                let Ok(oid) = Oid::from_hex(&entry.path) else {
                    continue;
                };
                if !prefix.matches(&namespace, &oid) {
                    continue;
                }
                out.push(BlobEntry {
                    namespace: namespace.clone(),
                    oid,
                    size: entry.size,
                    created_at: times.get(&entry.path).map(|at| Timestamp::from_unix(*at)),
                });
            }
        }
        out.sort_by_key(BlobEntry::key);
        Ok(out)
    }
}

impl GitHost {
    /// When a record landed: the commit that added it to its chain.
    fn record_created_at(&self, oid: &Oid) -> HostResult<Option<Timestamp>> {
        let Some((namespace, _)) = self.find_record(oid)? else {
            return Ok(None);
        };
        let Some(tip) = self.chain_tip(&namespace)? else {
            return Ok(None);
        };
        Ok(plumb::introduced_at(&self.inner.cli, &tip)?
            .get(&oid.hex())
            .map(|at| Timestamp::from_unix(*at)))
    }
}

impl Host for GitHost {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities
    }

    fn describe(&self) -> HostInfo {
        HostInfo {
            name: self.inner.remote.name.clone(),
            kind: HostKind::Git,
            url: Some(self.inner.remote.redacted_url()),
            store_prefix: self.inner.remote.store_prefix.clone(),
            capabilities: self.inner.capabilities,
            implemented_by: format!(
                "{} git {})",
                implemented_by("git").replace(" (git", ""),
                self.inner.cli.version()
            ),
            schema_version: crate::HOST_SCHEMA_VERSION,
        }
    }
}

impl fmt::Display for GitHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {}",
            self.inner.remote.name,
            self.inner.remote.redacted_url()
        )
    }
}

use std::fmt;

/// The conflict a failed expectation produces, naming both sides.
fn conflict(name: &RefName, expect: Expect, found: Option<Oid>) -> HostError {
    HostError::conflict(
        name.as_str(),
        match expect {
            Expect::Absent => None,
            Expect::Is(oid) => Some(oid),
            Expect::Any => found,
        },
        found,
    )
    .with_hint(
        "the ref moved under us: re-read it, rebuild the update and retry (a leased push never \
         clobbers a ref it did not read)",
    )
}

/// The lease for a write, in git's spelling.
///
/// `Expect::Absent` becomes the all-zero oid — "the ref must not exist" — which is
/// the only way git says create-only when pushing. `Expect::Any` has no lease, and
/// so needs `--force`; every other expectation leases on the git object that was
/// just read.
fn lease_for(expect: Expect, current: Option<&Resolved>) -> Option<String> {
    match expect {
        Expect::Any => None,
        Expect::Absent => Some(ZERO_OID.to_string()),
        Expect::Is(_) => current.map(|resolved| resolved.git_oid.clone()),
    }
}

/// Flags for a push: a leased write must not carry `--force` (git ignores the lease
/// when it does), an unconditional one must.
fn push_style_for(expect: Expect, count: usize) -> plumb::PushStyle {
    plumb::PushStyle {
        atomic: count > 1,
        dry_run: false,
        force: matches!(expect, Expect::Any),
    }
}

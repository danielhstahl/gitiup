//! The GitHub host: the same four traits, with a forge behind them.
//!
//! This is where the ticket's title lands — every GitHub-specific call the
//! workspace makes is reached from here and nowhere else, and everything above it
//! sees `RefStore` + `BlobStore` + `Host`. The capabilities are stated truthfully
//! (see the table in [`crate::store`]), and what the forge cannot promise is
//! reported by [`GitHubHost::advice`] rather than quietly worked around.

use std::sync::{Arc, Mutex};

use gitiup_host::{
    AuthModel, BlobEntry, BlobStore, Capabilities, Capability, CredentialProfile,
    HOST_SCHEMA_VERSION, Host, HostError, HostInfo, HostKind, HostResult, Namespace, Oid, Pack,
    PackFormat, PackRequest, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate,
    RemoteConfig,
};

use crate::api;
use crate::auth::Auth;
use crate::client::{Client, ClientOptions, RateBudget, RepoRef};
use crate::curl;
use crate::store::{RefTarget, Store, ref_from_target};
use crate::transport::Transport;

/// The namespace a stored raw pack is kept under, so a fetch by pack digest works.
pub const PACK_NAMESPACE: Namespace = Namespace::const_new("pack");

/// A remote whose store is a GitHub repository.
pub struct GitHubHost {
    store: Arc<Store>,
    remote: RemoteConfig,
    repo: RepoRef,
    /// `GET /repos/{owner}/{repo}`, read once and kept: it is what says whether the
    /// credential may write at all, and asking twice per command is rude.
    facts: Mutex<Option<api::Repository>>,
}

impl GitHubHost {
    /// Open a GitHub remote with this build's live transport.
    ///
    /// Nothing is fetched: `describe()` and `capabilities()` must be cheap, and a
    /// host that fails on construction cannot be *described* failing. Call
    /// [`GitHubHost::facts`] (or just use it) to find out whether the forge agrees.
    ///
    /// Without the `curl` feature this returns
    /// [`HostError::UnsupportedCas`] naming the feature: a build that cannot reach a
    /// forge should say so in those words rather than fail on a socket it has no
    /// code to open.
    pub fn open(remote: &RemoteConfig) -> HostResult<GitHubHost> {
        let transport = curl::default_transport(remote)?;
        GitHubHost::with_transport(remote, transport, None)
    }

    /// Open a GitHub remote over a given transport (the seam every test in this
    /// crate uses, and the one an embedder needing a different HTTP stack wants).
    pub fn with_transport(
        remote: &RemoteConfig,
        transport: Arc<dyn Transport>,
        profile: Option<&CredentialProfile>,
    ) -> HostResult<GitHubHost> {
        let repo = RepoRef::from_remote(remote)?;
        accept_forge_host(remote, &repo)?;
        let auth = Auth::resolve(remote, profile, &repo.api_host());
        let options = ClientOptions::from_remote(remote)?;
        let client = Client::new(repo.clone(), auth, transport, options);
        Ok(GitHubHost {
            store: Arc::new(Store::new(client)),
            remote: remote.clone(),
            repo,
            facts: Mutex::new(None),
        })
    }

    /// The store implementation (refs and records) this host drives.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The API client (rate budget, auth provenance, options).
    pub fn client(&self) -> &Client {
        self.store.client()
    }

    /// Where the store lives, as the forge names it.
    pub fn repo(&self) -> &RepoRef {
        &self.repo
    }

    /// The configured remote this host was opened from.
    pub fn remote(&self) -> &RemoteConfig {
        &self.remote
    }

    /// What the forge says about this repository, read once and remembered.
    pub fn facts(&self) -> HostResult<api::Repository> {
        if let Some(facts) = self.facts.lock().expect("facts lock").clone() {
            return Ok(facts);
        }
        let facts = api::repository(self.client())?;
        *self.facts.lock().expect("facts lock") = Some(facts.clone());
        Ok(facts)
    }

    /// What the forge last said about the credential's budget.
    pub fn rate_budget(&self) -> RateBudget {
        self.client().rate_budget()
    }

    /// Refuse, early and actionably, when the credential cannot do what is asked.
    pub fn require_write(&self) -> HostResult<()> {
        if self.client().options().read_only {
            return Err(
                HostError::unsupported("read-only", "this remote is configured read-only")
                    .with_hint("drop `read-only = \"true\"`, or use a credential that may push"),
            );
        }
        if !self.client().auth().has_token() {
            return Err(
                HostError::denied("write to a github remote without a token").with_hint(format!(
                    "anonymous reads are all this repository allows; see \
                     `gitiup remote show {}` for where a token would come from",
                    self.remote.name
                )),
            );
        }
        Ok(())
    }

    /// Everything a human should know about this host before trusting it, including
    /// the promises this forge makes *weaker* than the trait implies.
    ///
    /// `gitiup doctor` and `gitiup remote show` print this. An adapter that only
    /// reports its happy path is how a merge gate ends up believing a guarantee that
    /// a hook quietly voids.
    pub fn advice(&self) -> Vec<String> {
        let mut out = self.client().auth().advice();
        out.extend(self.client().options().advice());
        let caps = self.capabilities();
        if !caps.atomic_multi_write {
            out.push(
                "a multi-ref write is applied one ref at a time with best-effort \
                 rollback: the forge has no ref transaction, so a crash between two \
                 moves can leave a half-applied change (submit is idempotent, so \
                 re-running it repairs this)"
                    .to_string(),
            );
        }
        out.push(
            "a CAS write is checked before it is sent and verified after, and the forge \
             enforces create-only and forward moves; a *rewind* of a ref (which no \
             gitiup flow does) is the one case gitiup must force, where a concurrent \
             writer is caught by the verification rather than prevented"
                .to_string(),
        );
        out.push(
            "deleting a ref is check-then-delete: an expectation that does not match is \
             refused, but a write racing the delete is not caught — nothing that gates \
             a merge deletes a ref"
                .to_string(),
        );
        match self.facts() {
            Ok(facts) => {
                if let Some(permissions) = &facts.permissions
                    && !permissions.push
                {
                    out.push(format!(
                        "the credential cannot push to {} (the forge said so), so every \
                         write here will be refused — a read-only token is fine for \
                         verifying and useless for contributing",
                        facts.full_name
                    ));
                }
                if let Some(branch) = &facts.default_branch
                    && self
                        .store
                        .resolve(&format!("refs/heads/{branch}"))
                        .ok()
                        .flatten()
                        .is_none()
                {
                    out.push(format!(
                        "the forge calls `{branch}` the default branch and it has no ref \
                         yet, so a change based on it has nothing to land on"
                    ));
                }
            }
            Err(why) => out.push(format!(
                "the forge would not describe this repository ({why}); every call below \
                 this line will fail the same way"
            )),
        }
        out
    }

    /// The default branch as a gitiup ref (`refs/heads/<default>`).
    pub fn default_branch(&self) -> HostResult<Option<RefName>> {
        let facts = self.facts()?;
        match facts.default_branch {
            None => Ok(None),
            Some(branch) => Ok(Some(RefName::branch(&branch)?)),
        }
    }

    /// Where the default branch points now.
    pub fn default_branch_oid(&self) -> HostResult<Oid> {
        let Some(name) = self.default_branch()? else {
            return Err(HostError::invalid(
                "github remote",
                "the forge did not report a default branch",
            ));
        };
        let reference = self.get_ref(&name)?.ok_or_else(|| {
            HostError::not_found("ref", name.to_string())
                .with_hint("the default branch the forge named does not exist")
        })?;
        Ok(reference.oid)
    }

    /// Resolve a ref without going through the trait (used by the translation
    /// layer and by tests).
    pub fn resolve(&self, name: &RefName) -> HostResult<Option<RefTarget>> {
        self.store.resolve(name.as_str())
    }

    /// Forget cached ref advertisements (what `gitiup fetch` does after fetching).
    pub fn invalidate_ref_cache(&self) {
        self.store.forget_all_refs();
    }
}

/// Whether this adapter should serve this remote.
///
/// The endpoint API is GitHub-specific, and so is the assumption that a host is a
/// GitHub server — `https://gitlab.com/o/r` is a perfectly good remote that this
/// adapter must not silently try to serve. `github.com` is accepted; anything else
/// needs the operator to have said so, either by naming an `api-base` (which is
/// what a GitHub Enterprise Server needs anyway) or by `accept-host`.
fn accept_forge_host(remote: &RemoteConfig, repo: &RepoRef) -> HostResult<()> {
    let host = repo.forge_host.as_str();
    if host == "github.com" || host.ends_with(".github.com") {
        return Ok(());
    }
    let declared = remote.option("api-base").is_some()
        || remote.option("accept-host").is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });
    if declared {
        return Ok(());
    }
    Err(HostError::SchemeUnknown(Box::new(
        gitiup_host::error::SchemeUnknown {
            scheme: host.to_string(),
            supported: vec!["github.com".into()],
            hint: Some(format!(
                "gitiup's github adapter speaks the GitHub REST API. If {host} really is GitHub \
         Enterprise, say so: set `api-base` (usually https://{host}/api/v3) or \
         `accept-host = \"true\"` in [remote.options]. Otherwise point the remote at \
         its own host type (the plain-git host serves any git server)."
            )),
        },
    )))
}

impl Host for GitHubHost {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Enforced by the forge for creates and forward moves, and by
            // check-before/after for everything else: see the table in `crate::store`.
            cas: true,
            // Records are appended and re-hashed on read; the forge cannot rewrite a
            // git object in place. The residual risk — an admin force-pushing a
            // chain ref — is the same one the plain-git host carries.
            immutable: true,
            // No ref transaction on the wire, so no honest `true` here.
            atomic_multi_write: false,
            auth: self.client().auth().model(),
        }
    }

    fn describe(&self) -> HostInfo {
        HostInfo {
            name: self.remote.name.clone(),
            kind: HostKind::Github,
            url: Some(self.remote.redacted_url()),
            store_prefix: format!("{}/{}", self.repo.full_name(), self.remote.store_prefix),
            capabilities: self.capabilities(),
            // The shared contract asks `implemented_by` to start with
            // "gitiup-host "; the adapter is a host *implementation* of that
            // trait, and naming both crates is the honest way to say which code
            // answered.
            implemented_by: format!(
                "gitiup-host schema {HOST_SCHEMA_VERSION} via gitiup-host-github {} ({})",
                env!("CARGO_PKG_VERSION"),
                self.repo.forge_host
            ),
            schema_version: HOST_SCHEMA_VERSION,
        }
    }

    fn require(&self, capability: Capability) -> HostResult<()> {
        // The generic check, plus the one thing only a forge has: no credential.
        self.capabilities().require(capability)?;
        if self.capabilities().auth == AuthModel::Anonymous && capability != Capability::Immutable {
            return Err(HostError::denied(format!(
                "requiring {} from an anonymous github remote",
                capability.as_str()
            ))
            .with_hint("read-only is all an anonymous remote can offer"));
        }
        Ok(())
    }
}

impl RefStore for GitHubHost {
    fn list_refs(&self, query: &RefQuery) -> HostResult<Vec<Ref>> {
        self.store.list_refs(query)
    }

    fn get_ref(&self, name: &RefName) -> HostResult<Option<Ref>> {
        let Some(target) = self.store.resolve(name.as_str())? else {
            return Ok(None);
        };
        Ok(ref_from_target(name.clone(), &target))
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> HostResult<Ref> {
        self.require_write()?;
        self.store.write(
            update.name.as_str(),
            update.expect,
            &update.new,
            update.actor.as_ref().map(|actor| actor.as_str()),
            update.message.as_deref(),
        )
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> HostResult<()> {
        self.require_write()?;
        self.store.delete(
            deletion.name.as_str(),
            deletion.expect,
            deletion.actor.as_ref().map(|actor| actor.as_str()),
        )
    }

    fn fetch_pack(&self, request: &PackRequest) -> HostResult<Pack> {
        if request.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", request.format.as_str()),
                "the github host cannot serve a git packfile: there is no API to \
                 upload one, and `git push` is the way to move git history",
            )
            .with_hint(
                "use the plain-git host (or plain git) for git objects; this \
                         host's refs and records are ordinary git objects, so a \
                         `git fetch` of them works",
            ));
        }
        let mut objects: Vec<(Namespace, Vec<u8>)> = Vec::new();
        let mut seen: Vec<Oid> = Vec::new();
        for want in &request.wants {
            if request.have.contains(want) || seen.contains(want) {
                continue;
            }
            let entry = self
                .head(want)
                .ok()
                .flatten()
                .filter(|found| found.oid == *want);
            let bytes = self.get(want)?.ok_or_else(|| {
                HostError::not_found("blob", want.hex()).with_hint(format!(
                    "'{want}' is not in this host's store; push it first or check \
                     the digest"
                ))
            })?;
            match &entry {
                Some(found) if found.namespace == PACK_NAMESPACE => {
                    // The want names a stored pack: expand it into its records.
                    let pack = Pack::from_bytes(bytes);
                    for (namespace, content) in pack.raw_objects()? {
                        let oid = Oid::hash_bytes(&content);
                        if request.have.contains(&oid) || seen.contains(&oid) {
                            continue;
                        }
                        seen.push(oid);
                        objects.push((namespace, content));
                    }
                    seen.push(*want);
                }
                _ => {
                    let namespace = entry
                        .map(|found| found.namespace)
                        .unwrap_or(Namespace::RECORD);
                    seen.push(*want);
                    objects.push((namespace, bytes));
                }
            }
        }
        Pack::from_raw_objects(objects)
    }

    fn put_pack(&self, pack: &Pack) -> HostResult<Oid> {
        if pack.len() > gitiup_host::pack::MAX_PACK_BYTES {
            return Err(HostError::invalid(
                "pack size",
                format!("{} bytes is over the pack limit", pack.len()),
            ));
        }
        pack.object_count()?;
        if pack.format != PackFormat::Raw {
            return Err(HostError::unsupported(
                format!("pack-format:{}", pack.format.as_str()),
                "the github host stores gitiup raw packs; a git packfile has to be \
                 pushed with git",
            )
            .with_hint("use the plain-git host for git objects"));
        }
        let objects = pack.raw_objects()?;
        for (namespace, content) in &objects {
            self.put_cas(namespace, content)?;
        }
        // The pack itself is stored too, which is what makes "fetch me that pack" a
        // lookup rather than a re-encode.
        let oid = self.put_cas(&PACK_NAMESPACE, &pack.bytes)?;
        Ok(oid)
    }
}

impl BlobStore for GitHubHost {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> HostResult<Oid> {
        self.require_write()?;
        self.store.put_cas(namespace, content)
    }

    fn get(&self, oid: &Oid) -> HostResult<Option<Vec<u8>>> {
        self.store.get(oid)
    }

    fn head(&self, oid: &Oid) -> HostResult<Option<BlobEntry>> {
        self.store.head(oid)
    }

    fn list_prefix(&self, pattern: &str) -> HostResult<Vec<BlobEntry>> {
        self.store.list_prefix(pattern)
    }
}

/// A short rendering used by `gitiup remote show`.
impl std::fmt::Debug for GitHubHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubHost")
            .field("remote", &self.remote.name)
            .field("repo", &self.repo.full_name())
            .field("auth", &self.client().auth().source())
            .field("capabilities", &self.capabilities())
            .finish()
    }
}

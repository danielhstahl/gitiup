//! The plain-git host: a bare repository, driven with the `git` binary.
//!
//! This is the host for "the repo is just a git repo somewhere": a directory on a
//! box you ssh into, a repository an nginx serves over smart-HTTP
//! (`git-http-backend`), or a pile of files a static server exposes over
//! dumb-HTTP. There is no API and no server-side code to trust — only the four
//! namespaces every gitiup host shares, and the transport git already speaks.
//!
//! ```text
//! refs/heads/**            real branches (owner writes)
//! refs/changes/<id>/head   proposed change head
//! refs/attestations/<subject>/<digest>  attestations for a commit, so `git fetch` carries proof
//! refs/gitiup/**           roster, job/lease records, quorum state
//! ```
//!
//! On top of those, the host keeps its own bookkeeping in [`KV_ROOT`] and
//! [`HOST_REF`], and nothing else. A contributor with plain `git` and no gitiup at
//! all can `git fetch origin 'refs/changes/*:refs/remotes/origin/changes/*'` and
//! review the result, which is the point.
//!
//! # Compare-and-swap, emulated the only way git allows
//!
//! git has no conditional ref update, so a CAS write is a sequence (see
//! [`GitHost::update_ref_cas`]):
//!
//! 1. a **fresh `ls-remote`** of the one ref being moved — a lease built from a
//!    cached advertisement is a guess, not a lease;
//! 2. compare what it says with the caller's [`Expect`]; a mismatch is
//!    [`HostError::Conflict`] carrying both sides, and nothing has been sent yet;
//! 3. a **`--dry-run` probe** (`push-probe`), so a hook, a protected branch or a
//!    read-only endpoint refuses before anything can land;
//! 4. the real `git push --force-with-lease=<ref>:<what we just read>`, which is
//!    git's own "do not overwrite what I did not see" — including the all-zero
//!    expected value, which is how [`Expect::Absent`] (create-only) is spelled;
//! 5. a **post-write `ls-remote`**, because a server that answered "ok" and did
//!    something else is a conflict, not a success.
//!
//! `--force` is never passed together with a named lease: git silently ignores the
//! lease then, which would turn the safety net into a no-op. An
//! [`Expect::Any`] write has no lease, so it does use `--force` — and gitiup code
//! that gates a merge never uses `Expect::Any`.
//!
//! Batches go out as one `git push --atomic`, which the receiving side applies as
//! a transaction, so the `fs` host's `atomic_multi_write` promise is true here
//! too rather than emulated with rollback.
//!
//! # How a ref holds a SHA-256 record
//!
//! A git ref can only name a git object, but a gitiup ref often points at a
//! *record* — an attestation, a change — whose digest is SHA-256 over the record
//! bytes. So such a ref points at a small **pointer commit** holding
//! `gitiup-ref.json` (the digest gitiup promised, the actor, the time) and the
//! record bytes themselves. That is what makes `git fetch` carry proof: fetching
//! `refs/attestations/<subject>/<digest>` brings the attestation *in the same packfile* as the
//! ref, with no second protocol. Refs whose value is a git commit stay exactly
//! what they look like — plain git — so `refs/heads/**` and a change head that is
//! a real commit are untouched by any of this.
//!
//! Records themselves live in the record store: one append-only commit chain per
//! namespace at `refs/gitiup/kv/<namespace>`, whose tree holds one file per record
//! named by its SHA-256. Appending to a chain is itself a leased push, so two
//! contributors publishing records interleave honestly instead of losing one.
//!
//! # What this host never does
//!
//! * **does not rewrite.** Record chains and pointer commits are appended with
//!   leases; nothing here force-pushes a ref it did not read first.
//! * **does not read your git config for identity.** Pointer commits are
//!   authored as the actor that asked for them, not as whoever's `user.name` is
//!   configured on the runner.
//! * **does not pretend a static server is writable.** A dumb-HTTP endpoint
//!   answers reads; writes say so (`read-only = "true"` says so earlier, and
//!   cheaper).
//!
//! ```
//! use gitiup_host::{BlobStore, Host, RefStore, RefUpdate};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # if gitiup_host::hosts::git::git_program().is_none() { return Ok(()); }
//! let dir = std::env::temp_dir().join(format!("gitiup-git-host-doc-{}", std::process::id()));
//! let _ = std::fs::remove_dir_all(&dir);
//! gitiup_host::hosts::git::init_bare(&dir)?;
//! let remote = gitiup_host::RemoteConfig::new("origin", &format!("file://{}", dir.display()))?;
//! let host = gitiup_host::hosts::git::GitHost::open_or_init(&remote)?;
//! let oid = host.put_cas(&gitiup_host::Namespace::ATTESTATION, b"signed digest")?;
//! host.update_ref_cas(&RefUpdate::create(
//!     gitiup_host::RefName::attestation(&oid),
//!     oid,
//! ))?;
//! assert_eq!(host.list_refs(&gitiup_host::RefQuery::all())?.len(), 1);
//! assert_eq!(host.describe().kind, gitiup_host::HostKind::Git);
//! # let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::blob::Namespace;
use crate::capability::{AuthModel, Capabilities, HostKind};
use crate::config::{RemoteConfig, RemoteScheme};
use crate::error::{HostError, HostResult};
use crate::oid::Oid;
use crate::refs::{Actor, Ref, RefName, RefUpdate};
use crate::time::Timestamp;

pub mod plumb;
pub mod run;
mod store;

pub use plumb::{HostManifest, RefDocument};
pub use run::GitVersion;

/// Create a bare repository at `path`.
///
/// This is the whole of "hosting a repo gitiup can use" for the local case: make
/// a bare repo, point a `file://` remote at it, and
/// [`GitHost::open_or_init`] moves it from a git repository to a gitiup store.
/// Over ssh the same thing needs a shell on the other end, which is the
/// operator's job, not gitiup's.
///
/// From the command line a `file://` remote is a *directory* store unless the remote
/// says otherwise — the fs host keeps `refs` as a file where git keeps it as a
/// directory, and the two cannot share a path — so a `gitiup.toml` remote at a local
/// repository declares `host-type = "git"` in `[remote.options]` (see `Declared` in
/// `gitiup/src/remotes.rs`).
pub fn init_bare(path: &Path) -> HostResult<PathBuf> {
    let program = git_program().ok_or_else(|| {
        HostError::unsupported(
            "git-binary",
            "cannot create a repository because no git binary could be run",
        )
        .with_hint("install git, or set the git-binary option (or $GITIUP_GIT)")
    })?;
    run::init_bare_with(&program, path)
}

/// The all-zero object id: git's spelling of "this ref does not exist", which is
/// what makes `Expect::Absent` expressible as a lease.
pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The record store lives here: `refs/gitiup/kv/<namespace>`, one append-only
/// commit chain per namespace.
///
/// This is a **reserved** prefix: a ref named exactly `refs/gitiup/kv` (or below
/// it, other than the chains themselves) cannot exist in a repository this host
/// writes, because git would not be able to store both it and the chains.
pub const KV_ROOT: &str = "refs/gitiup/kv";

/// The store manifest ref: what this repository is as a gitiup store.
pub const HOST_REF: &str = "refs/gitiup/host";

/// How long the fetched advertisement is reused for listings.
pub const DEFAULT_REF_CACHE_TTL: Duration = Duration::from_secs(2);

/// Extra attempts a record append gets when another writer beat us to the chain
/// tip.
pub const DEFAULT_CAS_ATTEMPTS: u32 = 6;

/// First pause between those attempts.
pub const DEFAULT_CAS_BACKOFF: Duration = Duration::from_millis(10);

/// Ceiling for that pause, so a busy store cannot stall a command.
pub const DEFAULT_CAS_BACKOFF_CAP: Duration = Duration::from_millis(500);

/// Should every ref write start with a `--dry-run` probe?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Probe {
    /// Ask the remote to accept the ref line before sending it for real.
    #[default]
    On,
    /// Skip the probe: one round trip per write instead of two.
    Off,
}

impl Probe {
    /// Stable name for config and `--json` output.
    pub fn as_str(self) -> &'static str {
        match self {
            Probe::On => "on",
            Probe::Off => "off",
        }
    }

    /// Parse `push-probe`.
    pub fn parse(text: &str) -> Result<Probe, HostError> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "on" | "true" | "yes" | "1" | "always" => Ok(Probe::On),
            "off" | "false" | "no" | "0" | "never" => Ok(Probe::Off),
            other => Err(HostError::invalid(
                "push-probe",
                format!("'{other}' is not a probe setting"),
            )
            .with_hint("expected on (probe with --dry-run first) or off")),
        }
    }
}

/// Knobs for the plain-git host — every one of them a `[remote.options]` key in
/// `gitiup.toml` (or a query parameter on the remote URL).
///
/// The defaults describe a correctly configured writable repository; the explicit
/// values exist for static servers, odd ssh setups and CI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitOptions {
    /// `git-binary` — which git to run (default `git`, or `$GITIUP_GIT`).
    pub git_binary: String,
    /// `work-dir` — where the local mirror of the remote lives.
    pub work_dir: Option<PathBuf>,
    /// `ref-cache-ttl` — how long a fetched advertisement is reused for listings.
    pub ref_cache_ttl: Duration,
    /// `cas-attempts` — retries when another writer wins a record append.
    pub cas_attempts: u32,
    /// `cas-backoff` — first pause before retrying a lost record append.
    pub cas_backoff: Duration,
    /// `cas-backoff-cap` — ceiling for that pause.
    pub cas_backoff_cap: Duration,
    /// `push-probe` — dry-run before a write.
    pub push_probe: Probe,
    /// `read-only` — refuse writes up front (a dumb-HTTP or anonymous-fetch remote).
    pub read_only: bool,
    /// `ssh-command` — `GIT_SSH_COMMAND` for ssh remotes.
    pub ssh_command: Option<String>,
    /// `key-path` — a private key to use, from the credentials profile.
    pub key_path: Option<PathBuf>,
    /// `git-config.*` — `-c` overrides passed to every git command.
    pub git_config: Vec<(String, String)>,
    /// `pack-threads` — `-c pack.threads`, for cold mirrors of big repositories.
    pub pack_threads: Option<u32>,
}

impl Default for GitOptions {
    fn default() -> GitOptions {
        GitOptions {
            git_binary: git_program().unwrap_or_else(|| "git".to_string()),
            work_dir: None,
            ref_cache_ttl: DEFAULT_REF_CACHE_TTL,
            cas_attempts: DEFAULT_CAS_ATTEMPTS,
            cas_backoff: DEFAULT_CAS_BACKOFF,
            cas_backoff_cap: DEFAULT_CAS_BACKOFF_CAP,
            push_probe: Probe::default(),
            read_only: false,
            ssh_command: None,
            key_path: None,
            git_config: Vec::new(),
            pack_threads: None,
        }
    }
}

impl GitOptions {
    /// Read the knobs out of a remote's `[remote.options]` table (overlaid on the
    /// URL query string), plus the credentials profile for a key path.
    ///
    /// Unknown option keys are not an error — other hosts read the same table —
    /// but they come back as advice, so a typo surfaces in
    /// `gitiup remote doctor` instead of silently doing nothing.
    pub fn from_remote(
        remote: &RemoteConfig,
        profile: Option<&crate::config::CredentialProfile>,
    ) -> HostResult<(GitOptions, Vec<String>)> {
        let mut options = GitOptions::default();
        let mut advice = Vec::new();
        if let Some(profile) = profile {
            options.key_path = profile.key_path.clone();
        }
        for (key, value) in remote.effective_options() {
            let known = match key.as_str() {
                "git-binary" => {
                    options.git_binary = value.clone();
                    true
                }
                "work-dir" => {
                    options.work_dir = Some(PathBuf::from(value.clone()));
                    true
                }
                "ref-cache-ttl" => {
                    options.ref_cache_ttl = cache_timeout(&value)?;
                    true
                }
                "cas-attempts" => {
                    let count: u32 = value.trim().parse().map_err(|_| {
                        HostError::invalid("cas-attempts", format!("'{value}' is not a count"))
                            .with_hint("expected a small number of retries, e.g. 4")
                    })?;
                    options.cas_attempts = count.min(64);
                    true
                }
                "cas-backoff" => {
                    options.cas_backoff = crate::config::parse_timeout(&value)?;
                    true
                }
                "cas-backoff-cap" => {
                    options.cas_backoff_cap = crate::config::parse_timeout(&value)?;
                    true
                }
                "push-probe" => {
                    options.push_probe = Probe::parse(&value)?;
                    true
                }
                "read-only" => {
                    options.read_only = parse_bool(&key, &value)?;
                    true
                }
                "ssh-command" => {
                    options.ssh_command = Some(value.clone());
                    true
                }
                "key-path" => {
                    options.key_path = Some(PathBuf::from(value.clone()));
                    true
                }
                "pack-threads" => {
                    let threads: u32 = value.trim().parse().map_err(|_| {
                        HostError::invalid("pack-threads", format!("'{value}' is not a number"))
                    })?;
                    options.pack_threads = Some(threads);
                    true
                }
                _ => false,
            };
            if !known {
                if let Some(config) = key.strip_prefix("git-config.") {
                    options.git_config.push((config.to_string(), value));
                    continue;
                }
                advice.push(format!(
                    "remote '{}' sets option '{key}', which the plain-git host does not read",
                    remote.name
                ));
            }
        }
        if options.ref_cache_ttl == Duration::ZERO {
            advice.push(
                "ref-cache-ttl = 0s: every listing re-fetches the whole advertisement".to_string(),
            );
        }
        if options.cas_backoff > options.cas_backoff_cap {
            advice.push(format!(
                "cas-backoff ({}) is longer than cas-backoff-cap ({}): the cap wins, so the \
                 first pause is effectively the cap",
                crate::config::format_timeout(options.cas_backoff),
                crate::config::format_timeout(options.cas_backoff_cap)
            ));
        }
        if options.cas_attempts == 0 {
            advice.push(
                "cas-attempts = 0: a record append that loses a race fails instead of retrying"
                    .to_string(),
            );
        }
        Ok((options, advice))
    }
}

/// `ref-cache-ttl`, including the spellings that mean "do not cache at all".
fn cache_timeout(raw: &str) -> HostResult<Duration> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if matches!(trimmed.as_str(), "off" | "no" | "none" | "never") {
        return Ok(Duration::ZERO);
    }
    let digits = trimmed
        .trim_end_matches("ms")
        .trim_end_matches(['s', 'm', 'h'])
        .trim();
    if digits == "0" {
        return Ok(Duration::ZERO);
    }
    crate::config::parse_timeout(raw)
}

fn parse_bool(key: &str, value: &str) -> HostResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(
            HostError::invalid(key, format!("'{other}' is not a boolean"))
                .with_hint("expected true or false"),
        ),
    }
}

/// Find the git binary, honouring `$GITIUP_GIT`.
///
/// `None` means "there is no usable git here", which is a fact about the machine,
/// not a corrupt store: callers turn it into an actionable refusal (or, in tests,
/// a skip).
pub fn git_program() -> Option<String> {
    let program = std::env::var("GITIUP_GIT").unwrap_or_else(|_| "git".to_string());
    match std::process::Command::new(&program)
        .arg("--version")
        .output()
    {
        Ok(out) if out.status.success() => Some(program),
        _ => None,
    }
}

/// What a ref write is going to point the ref at.
#[derive(Debug, Clone)]
enum Target {
    /// A git object the mirror already holds (or just fetched): the ref keeps
    /// holding plain git, and `git log` on it is the branch history.
    GitObject(String),
    /// A pointer commit gitiup built: the ref's value is a record digest that git
    /// cannot spell, so the commit carries the promise and the record.
    Pointer {
        /// The commit to point the ref at.
        commit: String,
    },
}

impl Target {
    /// The object id the push sends.
    fn object(&self) -> &str {
        match self {
            Target::GitObject(oid) => oid,
            Target::Pointer { commit, .. } => commit,
        }
    }
}

/// A ref as the outside world sees it: the git object it holds plus the gitiup
/// value recovered from it.
#[derive(Debug, Clone)]
struct Resolved {
    /// The object the ref holds on the remote (40 hex in a sha1 repository).
    git_oid: String,
    /// What gitiup says the ref points at: the record digest inside a pointer
    /// commit, or the git object itself.
    value: Oid,
    /// Writer, when the host knows one.
    actor: Option<Actor>,
    /// When it was written.
    at: Option<Timestamp>,
    /// Whether this is a gitiup pointer rather than a plain git ref.
    pointer: bool,
}

/// A host backed by one bare repository, reached over `file://`, `ssh://`,
/// `https://` (smart HTTP) or a static HTTP server (read-only).
///
/// Cloning is cheap and the type is `Send + Sync`, so a verification run can hold
/// several remotes on threads. Build one with [`GitHost::open`],
/// [`GitHost::init`] or [`GitHost::from_remote`].
///
/// Every operation goes through a **mirror**: a local bare repository under
/// [`GitOptions::work_dir`] that `git fetch` keeps in step with the remote and
/// that `git push` pushes from. The mirror is not a cache of convenience — it is
/// what makes the object model work: records are written as git objects locally,
/// and the push that moves a ref is what uploads them, exactly as it would be for
/// a human contributor.
pub struct GitHost {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    remote: RemoteConfig,
    options: GitOptions,
    /// `git` pointed at the mirror.
    cli: run::GitCli,
    /// The URL git is given (never the config's query string, never a secret).
    url: String,
    mirror: PathBuf,
    capabilities: Capabilities,
    advice: Vec<String>,
    state: Mutex<State>,
    /// One mirror per process, so transport calls on the same handle are
    /// serialised: two threads fetching into one repository at once is how you
    /// get `unable to lock` failures that look like remote problems. Reads that
    /// need no transport (the object database, the mirror's refs) are not held up
    /// by it.
    transport: Mutex<()>,
}

/// Mutable, per-process state: the advertisement we last fetched and the
/// namespaces we have seen records in.
struct State {
    /// When the mirror was last fetched (for the listing TTL).
    fetched_at: Option<Instant>,
    /// Namespaces seen in `refs/gitiup/kv/**`, so a blob lookup does not have to
    /// list every chain in the repository.
    namespaces: BTreeSet<String>,
    /// The object format the remote turned out to use, if it has refs yet.
    sha256_repo: bool,
}

impl State {
    fn new() -> State {
        State {
            fetched_at: None,
            namespaces: BTreeSet::new(),
            sha256_repo: false,
        }
    }
}

impl fmt::Debug for GitHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHost")
            .field("remote", &self.inner.remote.name)
            .field("url", &self.git_url())
            .field("mirror", &self.inner.mirror)
            .field("capabilities", &self.inner.capabilities)
            .finish_non_exhaustive()
    }
}

impl GitHost {
    /// Open an initialised gitiup store: the remote must answer, and must hold the
    /// store manifest at [`HOST_REF`].
    pub fn open(remote: &RemoteConfig) -> HostResult<GitHost> {
        let host = Self::connect(remote, Purpose::Open)?;
        let manifest = host.manifest()?.ok_or_else(|| {
            HostError::not_found("store manifest", HOST_REF).with_hint(format!(
                "{} is not initialised as a gitiup store; initialise it with GitHost::init",
                host.git_url()
            ))
        })?;
        host.check_manifest(&manifest)?;
        Ok(host)
    }

    /// Create the store in a repository that has no gitiup refs yet.
    ///
    /// The manifest goes in with a create-only push, so two people initialising
    /// the same repository at once cannot clobber each other — one of them is
    /// told the store already exists, which is the truth.
    pub fn init(remote: &RemoteConfig) -> HostResult<GitHost> {
        let host = Self::connect(remote, Purpose::Init)?;
        if let Some(manifest) = host.manifest()? {
            return Err(
                HostError::invalid(HOST_REF, format!("{HOST_REF} already exists")).with_hint(
                    format!(
                        "the store was created {} ; open it with GitHost::open instead",
                        manifest
                            .created_at
                            .map(|at| at.to_string())
                            .unwrap_or_else(|| "earlier".to_string())
                    ),
                ),
            );
        }
        host.write_manifest()?;
        Ok(host)
    }

    /// Open the store, creating it when the repository holds no gitiup store yet.
    pub fn open_or_init(remote: &RemoteConfig) -> HostResult<GitHost> {
        let host = Self::connect(remote, Purpose::Open)?;
        match host.manifest()? {
            Some(manifest) => {
                host.check_manifest(&manifest)?;
                Ok(host)
            }
            None => {
                host.write_manifest()?;
                Ok(host)
            }
        }
    }

    /// A host that asks nothing of the store: no manifest, no schema check. For
    /// read-only inspection of a repository gitiup did not create — and for
    /// pointing a dumb-HTTP mirror at somebody else's project.
    pub fn detached(remote: &RemoteConfig) -> HostResult<GitHost> {
        Self::connect(remote, Purpose::Detached)
    }

    /// Open the `file://`, `ssh://` or `https://` remote named in a `gitiup.toml`.
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<GitHost> {
        GitHost::open(remote)
    }

    /// Open or initialise, whichever the repository needs (what
    /// `gitiup remote add --create` ends up doing).
    pub fn open_or_init_remote(remote: &RemoteConfig) -> HostResult<GitHost> {
        GitHost::open_or_init(remote)
    }

    /// The URL handed to git: the remote's, without the query string (options
    /// live there, and git would read it as part of a path).
    pub fn git_url(&self) -> String {
        self.inner.url.clone()
    }

    /// The remote this host was built from.
    pub fn remote(&self) -> &RemoteConfig {
        &self.inner.remote
    }

    /// Options this host is running with.
    pub fn options(&self) -> &GitOptions {
        &self.inner.options
    }

    /// The local mirror repository: every object this host holds, in a
    /// `git log`-able bare repo.
    pub fn mirror(&self) -> &Path {
        &self.inner.mirror
    }

    /// The git version driving this host.
    pub fn git_version(&self) -> GitVersion {
        self.inner.cli.version()
    }

    /// What `gitiup remote doctor` should say.
    pub fn advice(&self) -> &[String] {
        &self.inner.advice
    }

    /// The store manifest, as stored at [`HOST_REF`].
    pub fn manifest(&self) -> HostResult<Option<HostManifest>> {
        // The manifest is a commit, and reading it means having it: fetch first.
        self.sync(true)?;
        let Some(oid) = plumb::ls_one(&self.inner.cli, &self.inner.url, HOST_REF)? else {
            return Ok(None);
        };
        match self.read_pointer_file(&oid, "host.json")? {
            None => Ok(None),
            Some(bytes) => Ok(Some(HostManifest::decode(&bytes)?)),
        }
    }

    /// The ref a namespace's record chain lives on.
    pub fn kv_ref(namespace: &Namespace) -> RefName {
        // `kv/<ns>` is a valid ref tail by construction: namespaces are
        // [a-z0-9._-] and 1-32 bytes (see `Namespace`).
        RefName::new(format!("{KV_ROOT}/{}", namespace)).expect("namespace is a valid ref tail")
    }

    /// Every record chain the store holds, with its tip.
    pub fn store_refs(&self) -> HostResult<Vec<Ref>> {
        self.sync(true)?;
        let mut out = Vec::new();
        for line in plumb::local_refs(&self.inner.cli)? {
            if !Self::is_internal(&line.name) {
                continue;
            }
            let Ok(name) = RefName::new(line.name.clone()) else {
                continue;
            };
            out.push(match self.resolve(&line.name, &line.oid) {
                Ok(resolved) => self.ref_for(&name, &resolved),
                Err(_) => Ref {
                    name,
                    oid: Oid::from_hex(&line.oid)
                        .unwrap_or_else(|_| Oid::zero(20).expect("a 20-byte zero id")),
                    updated_by: None,
                    updated_at: None,
                    schema: None,
                },
            });
        }
        Ok(out)
    }

    /// Forget the fetched advertisement (what `gitiup fetch --refresh` does).
    pub fn flush_ref_cache(&self) {
        let mut state = self.lock();
        state.fetched_at = None;
    }

    /// Whether a ref name belongs to the host's own machinery rather than to a
    /// person: the record chains and the manifest.
    ///
    /// These are hidden from [`RefStore::list_refs`](crate::RefStore::list_refs)
    /// — they are the store's layout, the way `kv/` prefixes are layout on a
    /// bucket, not refs a reviewer asked about. Ask for the prefix explicitly, or
    /// use [`GitHost::store_refs`], to see them.
    pub fn is_internal(name: &str) -> bool {
        name == HOST_REF
            || name == KV_ROOT
            || name
                .strip_prefix(KV_ROOT)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }

    /// A ref name a person may not point a gitiup ref at, because git could not
    /// store both it and the record chains.
    fn reject_reserved(name: &RefName) -> HostResult<()> {
        if name.as_str() == KV_ROOT {
            return Err(HostError::invalid(
                "ref name",
                format!("'{name}' is reserved by the plain-git host"),
            )
            .with_hint(format!(
                "'{KV_ROOT}/**' holds the record store (one chain per namespace); use \
                 refs/gitiup/** for your own records"
            )));
        }
        if name.as_str() == HOST_REF {
            return Err(
                HostError::invalid("ref name", format!("'{name}' is the store manifest"))
                    .with_hint("write your own refs under refs/gitiup/** instead"),
            );
        }
        Ok(())
    }

    fn lock_transport(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner
            .transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn note_write(&self) {
        self.flush_ref_cache();
    }

    fn note_namespace(&self, namespace: &Namespace) {
        self.lock()
            .namespaces
            .insert(namespace.as_str().to_string());
    }

    /// Refuse a remote this host cannot serve, and explain the alternative.
    fn check_scheme(remote: &RemoteConfig) -> HostResult<()> {
        match remote.scheme() {
            RemoteScheme::File | RemoteScheme::Ssh | RemoteScheme::Https | RemoteScheme::Http => {
                Ok(())
            }
            other => Err(HostError::SchemeUnknown(Box::new(
                crate::error::SchemeUnknown {
                    scheme: other.as_str().to_string(),
                    supported: vec!["file", "ssh", "https", "http"]
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    hint: Some(format!(
                        "remote '{}' points at {}: the plain-git host serves a git URL, not a bucket \
                     prefix",
                        remote.name,
                        remote.redacted_url()
                    )),
                },
            ))),
        }
    }

    /// Refuse a `gitiup.toml` that asks the plain-git host to spend a token.
    ///
    /// The bucket host refuses a static token for the same reason
    /// ([`S3Host::check_credentials`](crate::S3Host::check_credentials)), and here the
    /// reason is stronger: gitiup does not carry a git transport's credential at all.
    /// `git` authenticates — an ssh key, an agent, a credential helper — and gitiup cannot
    /// scope what `git` then does with it across a redirect or a rewrite, which is exactly
    /// the promise [giti-g5c.5](../../../docs/federation.md) makes about every credential.
    /// So a `token-env` on a git remote means one of two bad things: the operator believes
    /// they are authenticated and are not, or a token would be handed to a transport that
    /// can spend it anywhere. Both are worth refusing before a byte moves — and the
    /// refusal is a capability answer (exit **6**), not the cross-origin refusal
    /// ([`crate::scope::refusal`], exit **3**), because nothing ever left for this host to
    /// be refused *about*.
    ///
    /// A profile that only says `auth = "token"` is advice, not a refusal: git's own
    /// credential helper may well be in use, and gitiup can see that it is not the one
    /// carrying the credential without forbidding it.
    pub fn check_credentials(
        remote: &RemoteConfig,
        profile: Option<&crate::config::CredentialProfile>,
    ) -> HostResult<()> {
        let Some(profile) = profile else {
            return Ok(());
        };
        if let Some(variable) = &profile.token_env {
            return Err(HostError::unsupported(
                "token-credentials",
                format!(
                    "the credentials profile for remote '{}' names token-env = \"{variable}\", \
                     and the plain-git host has no token to send: git authenticates for itself",
                    remote.name
                ),
            )
            .with_hint(
                "drop token-env from the profile. For a private repository over ssh use \
                 auth = \"ssh-key\" with key-path; over https let git use its own credential \
                 helper (gitiup never passes a token to git, because git would spend it on \
                 whatever host it ends up talking to), or put the store on a host gitiup \
                 authenticates to directly — a bucket, or a forge adapter",
            ));
        }
        Ok(())
    }

    /// The URL to hand git for this remote.
    fn git_url_for(remote: &RemoteConfig) -> String {
        match remote.scheme() {
            RemoteScheme::File => format!("file://{}", remote.url.file_path().display()),
            scheme => {
                let user = remote
                    .url
                    .user
                    .as_deref()
                    .map(|user| format!("{user}@"))
                    .unwrap_or_default();
                let port = remote
                    .url
                    .port
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default();
                format!(
                    "{}{}{}{}/{}",
                    scheme.with_separator(),
                    user,
                    remote.url.host,
                    port,
                    remote.url.path
                )
            }
        }
    }

    /// Where the mirror for this remote lives: `work-dir` (or a cache directory),
    /// then a name that cannot collide with another remote's mirror.
    fn mirror_path(options: &GitOptions, remote: &RemoteConfig) -> HostResult<PathBuf> {
        let root = match &options.work_dir {
            Some(dir) => dir.clone(),
            None => default_work_root(),
        };
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        remote.redacted_url().hash(&mut hasher);
        let slug: String = remote
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let dir = root.join(format!(
            "{}-{:016x}",
            slug.trim_matches('-'),
            hasher.finish()
        ));
        std::fs::create_dir_all(&dir)
            .map_err(|e| HostError::from_io("create mirror directory", &dir, e))?;
        Ok(dir)
    }

    /// Build the host: find git, prepare the mirror, and ask the remote what it
    /// has. `purpose` decides whether the answer has to look like a gitiup store.
    fn connect(remote: &RemoteConfig, purpose: Purpose) -> HostResult<GitHost> {
        Self::check_scheme(remote)?;
        let (mut options, mut advice) = GitOptions::from_remote(remote, None)?;
        if options.git_binary.trim().is_empty() {
            options.git_binary = "git".to_string();
        }
        let cli = run::GitCli::discover(&options.git_binary)?;
        let url = Self::git_url_for(remote);
        let mirror = Self::mirror_path(&options, remote)?;

        // Read-only is a fact about the transport that the operator is allowed to
        // declare: a dumb-HTTP endpoint refuses writes anyway, and saying so up
        // front turns a confusing push failure into a clear capability answer.
        if options.read_only {
            advice.push(
                "remote is read-only: gitiup will fetch and verify here, and refuse to move refs"
                    .to_string(),
            );
        }

        let mut cli = cli
            .with_git_dir(&mirror)
            .with_timeout(remote.timeout.max(run::DEFAULT_COMMAND_TIMEOUT));
        for (key, value) in &options.git_config {
            cli = cli.with_config(key.clone(), value.clone());
        }
        if let Some(threads) = options.pack_threads {
            cli = cli.with_config("pack.threads", threads.to_string());
        }
        if let Some(command) = ssh_command_for(remote, &options, ssh_command_from_env().as_deref())
        {
            cli = cli.with_env("GIT_SSH_COMMAND", command);
        }

        if !mirror.join("HEAD").is_file() {
            run::init_bare_with(&options.git_binary, &mirror)?;
        }

        let capabilities = capabilities_for(remote, options.read_only);
        let host = GitHost {
            inner: std::sync::Arc::new(Inner {
                remote: remote.clone(),
                options,
                cli,
                url,
                mirror,
                capabilities,
                advice,
                state: Mutex::new(State::new()),
                transport: Mutex::new(()),
            }),
        };

        // Ask the remote before promising anything: an unreachable URL is
        // `Unreachable`, a missing repository is `NotFound`, and a repository no
        // gitiup has ever touched is only a problem for `open`/`init`.
        let advertised = plumb::ls_remote(&host.inner.cli, &host.inner.url, &[])?;
        {
            let mut state = host.lock();
            state.fetched_at = Some(Instant::now());
            // A sha256 repository is the one thing that makes a 32-byte value
            // ambiguous, and gitiup's record digests are exactly that.
            state.sha256_repo = advertised.iter().any(|line| line.oid.len() > 40);
        }
        if host.lock().sha256_repo {
            return Err(HostError::unsupported(
                "object-format:sha256",
                format!(
                    "{} uses sha256 object ids; the plain-git host addresses records by SHA-256, \
                     which is ambiguous in such a repository",
                    host.git_url()
                ),
            )
            .with_hint("use a sha1 repository (git's default) until gitiup learns sha256 stores"));
        }
        let _ = purpose;
        let _ = advertised_count(&advertised);
        Ok(host)
    }

    fn check_manifest(&self, manifest: &HostManifest) -> HostResult<()> {
        if manifest.schema > crate::HOST_SCHEMA_VERSION_MAX {
            return Err(HostError::invalid(
                HOST_REF,
                format!("{HOST_REF} is schema {}", manifest.schema),
            )
            .with_hint(format!(
                "upgrade gitiup; this build understands schema {}",
                crate::HOST_SCHEMA_VERSION
            )));
        }
        if manifest.kind != HostKind::Git.as_str() {
            return Err(HostError::invalid(
                HOST_REF,
                format!(
                    "{HOST_REF} declares kind '{}', expected '{}'",
                    manifest.kind,
                    HostKind::Git.as_str()
                ),
            ));
        }
        Ok(())
    }

    /// Write the store manifest with a create-only push.
    fn write_manifest(&self) -> HostResult<()> {
        let manifest = HostManifest {
            schema: crate::HOST_SCHEMA_VERSION,
            kind: HostKind::Git.as_str().to_string(),
            url: self.inner.remote.redacted_url(),
            store_prefix: self.inner.remote.store_prefix.clone(),
            created_at: Some(Timestamp::now()),
            created_by: Some(Actor::from_env().to_string()),
            implemented_by: Some(crate::capability::implemented_by("git")),
        };
        let document = RefDocument::new(&manifest.url);
        let tree = plumb::make_tree(
            &self.inner.cli,
            &[
                plumb::TreeSpec {
                    mode: plumb::RECORD_MODE,
                    kind: "blob",
                    oid: &plumb::write_blob(&self.inner.cli, &manifest.encode()?)?,
                    path: "host.json",
                },
                plumb::TreeSpec {
                    mode: plumb::RECORD_MODE,
                    kind: "blob",
                    oid: &plumb::write_blob(&self.inner.cli, &document.encode()?)?,
                    path: plumb::REF_DOC_PATH,
                },
            ],
        )?;
        let commit = plumb::commit_tree(
            &self.inner.cli,
            &tree,
            &[],
            &format!("gitiup: initialise the store at {}", self.git_url()),
            Some(&Actor::from_env()),
            Timestamp::now(),
        )?;
        let push = plumb::Push {
            src: Some(commit),
            dst: HOST_REF.to_string(),
            lease: Some(ZERO_OID.to_string()),
        };
        let _transport = self.lock_transport();
        match plumb::push(
            &self.inner.cli,
            &self.inner.url,
            &[push],
            plumb::PushStyle::default(),
        ) {
            Ok(()) => Ok(()),
            Err(failure) if failure.is_stale_lease() => Err(HostError::invalid(
                HOST_REF,
                format!("{HOST_REF} already exists"),
            )
            .with_hint("somebody else initialised this repository first")),
            Err(failure) => Err(failure.into()),
        }
    }

    /// Re-sync the mirror if the cached advertisement has aged out.
    ///
    /// Listings may be served from the last fetch — they are an advertisement of
    /// what gitiup saw a moment ago, which is what a fetch loop wants. Writes
    /// never use this: they re-read the one ref they are about to move.
    fn sync(&self, force: bool) -> HostResult<()> {
        let fresh = {
            let state = self.lock();
            match state.fetched_at {
                Some(at) => !force && at.elapsed() < self.inner.options.ref_cache_ttl,
                None => false,
            }
        };
        if fresh {
            return Ok(());
        }
        let _transport = self.lock_transport();
        plumb::fetch_all(&self.inner.cli, &self.inner.url)?;
        let mut state = self.lock();
        state.fetched_at = Some(Instant::now());
        drop(state);
        // Note the namespaces the store actually uses, so a later blob lookup is
        // a couple of listings rather than a walk of every chain.
        for line in plumb::local_refs(&self.inner.cli)? {
            if let Some(namespace) = line.name.strip_prefix(&format!("{KV_ROOT}/"))
                && !namespace.is_empty()
            {
                self.lock().namespaces.insert(namespace.to_string());
            }
        }
        Ok(())
    }

    /// The file inside a pointer commit (`gitiup-ref.json`, `host.json`,
    /// `record`).
    fn read_pointer_file(&self, commit: &str, path: &str) -> HostResult<Option<Vec<u8>>> {
        plumb::cat_blob(&self.inner.cli, &format!("{commit}:{path}"))
    }

    /// Turn what a ref holds into what gitiup says it holds.
    ///
    /// Two shapes are possible: a pointer commit written by this host (so the
    /// value is the record digest inside it, with the actor and time that came
    /// with the update), or a plain git ref (so the value is the git object, and
    /// the best metadata available is the commit's own author and date).
    fn resolve(&self, name: &str, git_oid: &str) -> HostResult<Resolved> {
        // If the mirror cannot name the object, "no pointer document" would be a
        // lie: the honest answer is "I do not know yet", which is what makes
        // `probe` re-fetch instead of mistaking a pointer for a plain git ref.
        if !self.inner.cli.has_object(git_oid) {
            return Err(HostError::not_found("object", git_oid).with_hint(format!(
                "{name} points at an object this mirror does not have; fetch {url}",
                url = self.git_url()
            )));
        }
        if let Some(bytes) = self.read_pointer_file(git_oid, plumb::REF_DOC_PATH)? {
            let document = RefDocument::decode(&bytes)?;
            let value = Oid::from_hex(&document.oid).map_err(|_| {
                HostError::invalid(
                    plumb::REF_DOC_PATH,
                    format!(
                        "{name} carries a value that is not an object id: '{}'",
                        document.oid
                    ),
                )
            })?;
            return Ok(Resolved {
                git_oid: git_oid.to_string(),
                value,
                actor: document.updated_by,
                at: document.updated_at,
                pointer: true,
            });
        }
        let commit = plumb::read_commit(&self.inner.cli, git_oid)?;
        let value = Oid::from_hex(git_oid).map_err(|_| {
            HostError::invalid(
                "ref",
                format!(
                    "{name} points at '{git_oid}', which is not an object id this build can \
                         represent"
                ),
            )
        })?;
        Ok(match commit {
            Some(commit) => Resolved {
                git_oid: git_oid.to_string(),
                value,
                actor: (!commit.author.is_empty()).then(|| Actor::from(commit.author.as_str())),
                at: commit.commit_time.map(Timestamp::from_unix),
                pointer: false,
            },
            None => Resolved {
                git_oid: git_oid.to_string(),
                value,
                actor: None,
                at: None,
                pointer: false,
            },
        })
    }

    /// The `Ref` a resolved ref is reported as.
    fn ref_for(&self, name: &RefName, resolved: &Resolved) -> Ref {
        Ref {
            name: name.clone(),
            oid: resolved.value,
            updated_by: resolved.actor.clone(),
            updated_at: resolved.at,
            // Only gitiup's own writes carry a schema; a plain git ref is git's,
            // and pretending otherwise would claim a format this host did not write.
            schema: resolved.pointer.then_some(crate::HOST_SCHEMA_VERSION),
        }
    }

    /// Read the current state of one ref *as gitiup sees it*, straight from the
    /// remote rather than from the mirror.
    ///
    /// This is the probe half of the CAS protocol: it is what the lease is checked
    /// against, so it is never served from cache. If the object is newer than the
    /// mirror, the mirror is re-fetched and the read tried again — without that, a
    /// ref somebody else just moved would be misread as a plain git ref and the
    /// expectation would be compared against the wrong value.
    fn probe(&self, name: &RefName) -> HostResult<Option<Resolved>> {
        let Some(oid) = plumb::ls_one(&self.inner.cli, &self.inner.url, name.as_str())? else {
            return Ok(None);
        };
        match self.resolve(name.as_str(), &oid) {
            Ok(resolved) => Ok(Some(resolved)),
            Err(err) if self.object_may_be_missing(&err) => {
                self.sync(true)?;
                match self.resolve(name.as_str(), &oid) {
                    Ok(resolved) => Ok(Some(resolved)),
                    // Still unreadable: a git ref to the bones, and the git
                    // object itself is the only honest answer.
                    Err(_) => Ok(Some(Resolved {
                        value: Oid::from_hex(&oid)?,
                        git_oid: oid,
                        actor: None,
                        at: None,
                        pointer: false,
                    })),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Whether an error from `resolve` means "the mirror does not have that object
    /// yet" rather than "the stored bytes are nonsense".
    fn object_may_be_missing(&self, error: &HostError) -> bool {
        matches!(error.kind(), crate::HostErrorKind::NotFound)
    }

    /// Refuse a write on a host that cannot honour one, before anything is sent.
    fn require_write(&self) -> HostResult<()> {
        if self.inner.capabilities.cas {
            return Ok(());
        }
        Err(HostError::unsupported(
            "cas",
            format!(
                "remote '{}' is read-only here, so refs cannot be moved at all",
                self.inner.remote.name
            ),
        )
        .with_hint(
            "drop read-only = \"false\" from [remote.options] if the endpoint really does \
             accept pushes, or point the remote at the writable URL (git-http-backend, ssh://)",
        ))
    }

    /// The object a ref will be pointed at, built if the value needs a pointer.
    ///
    /// The rule is the object id's own shape: a value that is a git object id and
    /// that the mirror can actually name a commit for stays plain git; anything
    /// else is a record digest and gets wrapped.
    fn plan_target(&self, update: &RefUpdate, current: Option<&Resolved>) -> HostResult<Target> {
        let want = &update.new;
        if want.len() == 20 && self.has_git_object(&want.hex())? {
            return Ok(Target::GitObject(want.hex()));
        }
        if want.len() != 32 {
            // Not a record digest and not a commit: the only way it could still be
            // pushable is as an object the mirror has never seen.
            if self.has_git_object(&want.hex())? {
                return Ok(Target::GitObject(want.hex()));
            }
            return Err(
                HostError::not_found("object", want.hex()).with_hint(format!(
                    "'{want}' is neither a record in this store nor an object the mirror holds; \
                 fetch the commits first (git fetch {}), or publish the record with put_cas",
                    self.git_url()
                )),
            );
        }
        // A record digest: the ref gets a pointer commit carrying the promise and
        // the record itself, parented on whatever the ref held before so that
        // `git log refs/attestations/<oid>` is the audit trail of the ref.
        let record = self.get_blob(want)?.ok_or_else(|| {
            HostError::not_found("record", want.hex()).with_hint(format!(
                "publish the record into this store (put_cas) before pointing a ref at it: a \
                 ref whose bytes nobody has pushed would be an empty promise to anyone who \
                 fetches {name}",
                name = update.name
            ))
        })?;
        let mut document = RefDocument::new(&want.hex());
        document.updated_by = update.actor.clone().or_else(|| Some(Actor::from_env()));
        document.updated_at = Some(Timestamp::now());
        document.message = update.message.clone();
        let doc_blob = plumb::write_blob(&self.inner.cli, &document.encode()?)?;
        let record_blob = plumb::write_blob(&self.inner.cli, &record)?;
        let entries = vec![
            plumb::TreeSpec {
                mode: plumb::RECORD_MODE,
                kind: "blob",
                oid: &doc_blob,
                path: plumb::REF_DOC_PATH,
            },
            plumb::TreeSpec {
                mode: plumb::RECORD_MODE,
                kind: "blob",
                oid: &record_blob,
                path: plumb::RECORD_PATH,
            },
        ];
        let tree = plumb::make_tree(&self.inner.cli, &entries)?;
        // The ref's own previous value is the first parent, so `git log <ref>` is the
        // audit trail of that ref. Then whatever the caller named: a change ref names
        // the commit it proposes (so a fetch of the ref carries it) and the previous
        // attempt's pointer commit (so one fetch of `refs/changes/<id>/*` carries
        // every attempt) — ADR-0003 D5.
        let mut parents: Vec<String> = current
            .map(|resolved| vec![resolved.git_oid.clone()])
            .unwrap_or_default();
        for parent in &update.parents {
            let named = match parent {
                crate::refs::RefParent::Commit(oid) => Some(oid.hex()),
                crate::refs::RefParent::Ref(name) => {
                    self.probe(name)?.map(|resolved| resolved.git_oid)
                }
            };
            let Some(named) = named else { continue };
            if parents.contains(&named) {
                continue;
            }
            // A parent git cannot name would fail the whole write for a bit of history
            // nobody has yet: the record is the promise, the parents are the convenience.
            if !self.has_git_object(&named)? {
                continue;
            }
            parents.push(named);
        }
        // The commit message is the audit line a reviewer reads; the caller's own
        // message is inside the ref document, where it cannot be mangled by a
        // line-wrapping tool between here and the remote.
        let message = format!("gitiup: {} -> {want}", update.name);
        let commit = plumb::commit_tree(
            &self.inner.cli,
            &tree,
            &parents,
            &message,
            update.actor.as_ref(),
            Timestamp::now(),
        )?;
        Ok(Target::Pointer { commit })
    }

    /// Whether the mirror can name `oid` right now, fetching it from the remote if
    /// it cannot.
    fn has_git_object(&self, oid: &str) -> HostResult<bool> {
        if self.inner.cli.has_object(oid) {
            return Ok(true);
        }
        // One attempt at the server: it may refuse (git only hands out arbitrary
        // object ids when it is configured to), which is not an error yet.
        let _ = plumb::fetch_object(&self.inner.cli, &self.inner.url, oid);
        Ok(self.inner.cli.has_object(oid))
    }

    /// The push, with the probe in front of it and the verification after it.
    ///
    /// `expectations` pairs each push with the value the caller expects the ref to
    /// end up holding, so a server that answered "ok" and did something else is
    /// reported as the conflict it is instead of believed.
    fn push_refs(
        &self,
        pushes: &[plumb::Push],
        style: plumb::PushStyle,
        outcomes: &[(String, Option<String>)],
        context: &RefName,
    ) -> HostResult<()> {
        let _transport = self.lock_transport();
        // The dry-run first: a lease that will not hold is reported without a
        // packfile ever crossing the wire, and a batch that will be refused is
        // refused for the whole batch rather than ref by ref.
        if self.inner.options.push_probe == Probe::On
            && let Err(failure) = plumb::push(
                &self.inner.cli,
                &self.inner.url,
                pushes,
                plumb::PushStyle {
                    dry_run: true,
                    ..style
                },
            )
        {
            return Err(self.classify_ref_failure(&failure, context));
        }
        if let Err(failure) = plumb::push(&self.inner.cli, &self.inner.url, pushes, style) {
            return Err(self.classify_ref_failure(&failure, context));
        }
        self.note_write();
        // Trust, then verify: a receive-pack with a hook that rewrote the ref, or a
        // load balancer in front of a stale replica, must not be able to report a
        // move that did not happen.
        for (name, expected) in outcomes {
            let name = RefName::new(name.clone())?;
            let actual = plumb::ls_one(&self.inner.cli, &self.inner.url, name.as_str())?;
            let agreed = match (expected, &actual) {
                // A deletion we expected but that did not happen, or a move that
                // came back as a deletion, is a conflict just as much as a ref
                // left at somebody else's commit.
                (None, None) | (Some(_), Some(_)) if expected.is_none() == actual.is_none() => {
                    expected == &actual
                }
                _ => false,
            };
            if !agreed {
                return Err(HostError::conflict(
                    name.as_str(),
                    expected.as_deref().and_then(|hex| Oid::from_hex(hex).ok()),
                    actual.as_deref().and_then(|hex| Oid::from_hex(hex).ok()),
                )
                .with_hint(
                    "the push was accepted but the ref does not hold what we sent: something \
                     between us and the repository moved it (a hook, or a read replica); \
                     re-read the ref before retrying",
                ));
            }
        }
        Ok(())
    }

    /// A push failure, named as the ref write that hit it.
    fn classify_ref_failure(&self, failure: &run::GitFailure, context: &RefName) -> HostError {
        if failure.is_stale_lease() {
            return HostError::conflict(context.as_str(), None::<Oid>, None).with_hint(format!(
                "the ref moved between our read and our push: re-read {} and rebuild the update \
                 (git said: {})",
                context,
                failure.summary()
            ));
        }
        HostError::from(failure.clone())
    }
}

/// A capability promise is a claim about the transport, so it is derived from the
/// transport rather than configured.
fn capabilities_for(remote: &RemoteConfig, read_only: bool) -> Capabilities {
    // What gitiup *holds*, not what the transport might arrange behind its back. A
    // git remote over `http(s)://` is authenticated by git's own helper, an agent or an
    // anonymous read — never by a credential gitiup carries (see
    // [`GitHost::check_credentials`]) — so claiming `token` here would be a capability
    // lie, and a caller has a right to branch on this field.
    let auth = match remote.scheme() {
        RemoteScheme::File => AuthModel::Filesystem,
        RemoteScheme::Ssh => AuthModel::SshKey,
        RemoteScheme::Http | RemoteScheme::Https => AuthModel::Anonymous,
        RemoteScheme::S3 => AuthModel::Anonymous,
    };
    if read_only {
        // Nothing can be written, so nothing can be compare-and-swapped: saying
        // `cas = true` here would let a caller believe a merge could be gated.
        Capabilities {
            cas: false,
            immutable: true,
            atomic_multi_write: false,
            auth,
        }
    } else {
        Capabilities {
            cas: true,
            immutable: true,
            atomic_multi_write: true,
            auth,
        }
    }
}

/// Where mirrors live when the operator did not say: a cache directory if the
/// environment names one, the temp directory otherwise.
fn default_work_root() -> PathBuf {
    if let Some(cache) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(cache).join("gitiup").join("git-hosts");
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home)
            .join(".cache")
            .join("gitiup")
            .join("git-hosts");
        if candidate
            .parent()
            .is_some_and(|parent| parent.exists() || parent.parent().is_some())
        {
            return candidate;
        }
    }
    std::env::temp_dir().join("gitiup-git-hosts")
}

/// `GIT_SSH_COMMAND` gitiup should set for this remote, if any.
///
/// Three sources, in order of who gets their way: an explicit `ssh-command`
/// (because whoever wrote it knows something), a `key-path` from the remote or
/// the credential profile (`IdentitiesOnly`, so a loaded agent does not offer
/// some other key and get refused), and finally, for an ssh remote with nothing
/// set anywhere, `ssh -o BatchMode=yes` — a command-line tool must not hang on a
/// passphrase prompt it has no terminal to ask. Something the user already
/// exported outranks all of it.
fn ssh_command_for(
    remote: &RemoteConfig,
    options: &GitOptions,
    exported: Option<&std::ffi::OsStr>,
) -> Option<String> {
    if let Some(command) = &options.ssh_command {
        return Some(command.clone());
    }
    if let Some(key) = &options.key_path {
        return Some(format!("ssh -i {} -o IdentitiesOnly=yes", key.display()));
    }
    if exported.is_some() {
        return None;
    }
    matches!(remote.scheme(), RemoteScheme::Ssh).then(|| "ssh -o BatchMode=yes".to_string())
}

fn ssh_command_from_env() -> Option<std::ffi::OsString> {
    std::env::var_os("GIT_SSH_COMMAND")
}

/// Whether the advertisement was empty — an empty repository is still a perfectly
/// good remote, it just has nothing to say yet.
fn advertised_count(lines: &[plumb::RefLine]) -> usize {
    lines.len()
}

/// Why a host is being opened: it decides how loudly an empty or uninitialised
/// repository complains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// An existing store is expected.
    Open,
    /// A new store is being created.
    Init,
    /// Anything goes: read-only inspection of a repository gitiup did not create.
    Detached,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_at(url: &str) -> RemoteConfig {
        RemoteConfig::new("origin", url).expect("a valid remote url")
    }

    #[test]
    fn ssh_command_comes_from_the_operator_first_and_batchmode_last() {
        let ssh = remote_at("ssh://git@box/srv/git/repo.git");
        let local = remote_at("file:///srv/git/repo.git");
        let https = remote_at("https://host/repo.git");
        let none = GitOptions::default();

        // Nothing configured anywhere: an ssh remote gets BatchMode, so a command
        // line cannot stall on a passphrase prompt; a local or HTTP one gets
        // nothing, because there is no ssh to configure.
        assert_eq!(
            ssh_command_for(&ssh, &none, None).as_deref(),
            Some("ssh -o BatchMode=yes")
        );
        assert_eq!(ssh_command_for(&local, &none, None), None);
        assert_eq!(ssh_command_for(&https, &none, None), None);

        // A key from the remote or its credential profile is spelled for git, with
        // IdentitiesOnly so an agent full of other keys cannot get us refused.
        let with_key = GitOptions {
            key_path: Some(PathBuf::from("/home/ci/.ssh/deploy")),
            ..GitOptions::default()
        };
        assert_eq!(
            ssh_command_for(&ssh, &with_key, None).as_deref(),
            Some("ssh -i /home/ci/.ssh/deploy -o IdentitiesOnly=yes")
        );

        // An explicit command outranks the key, and whatever the user exported
        // outranks gitiup's defaults — it is their ssh, their rules.
        let explicit = GitOptions {
            ssh_command: Some("ssh -o ProxyJump=bastion".to_string()),
            key_path: Some(PathBuf::from("/home/ci/.ssh/deploy")),
            ..GitOptions::default()
        };
        assert_eq!(
            ssh_command_for(&ssh, &explicit, None).as_deref(),
            Some("ssh -o ProxyJump=bastion")
        );
        assert_eq!(
            ssh_command_for(&ssh, &none, Some("ProxyCommand=nc %h".as_ref())),
            None
        );
    }

    #[test]
    fn a_transport_that_cannot_lease_does_not_claim_it_can() {
        let writable = |url: &str| capabilities_for(&remote_at(url), false);
        for url in [
            "file:///srv/git/repo.git",
            "ssh://git@box/srv/git/repo.git",
            "https://host/repo.git",
            "http://127.0.0.1:8080/repo.git",
        ] {
            let caps = writable(url);
            assert!(caps.cas, "{url} can lease: {caps:?}");
            assert!(caps.atomic_multi_write, "{url}: {caps:?}");
            assert!(caps.immutable, "{url}: {caps:?}");
        }
        // Saying `cas = true` where nothing can be compare-and-swapped would let a
        // caller believe a merge could be gated here.
        let static_mirror = capabilities_for(&remote_at("http://127.0.0.1:8080/repo.git"), true);
        assert!(!static_mirror.cas);
        assert!(!static_mirror.atomic_multi_write);
        assert!(static_mirror.immutable);
        assert_eq!(static_mirror.missing(), vec!["cas", "atomic-multi-write"]);
    }

    #[test]
    fn the_record_store_owns_its_own_namespace() {
        assert!(GitHost::is_internal(HOST_REF));
        assert!(GitHost::is_internal(KV_ROOT));
        assert!(GitHost::is_internal("refs/gitiup/kv/attestation"));
        // A namespace that merely starts like the reserved one is somebody else's
        // ref, and hiding it would lose a real record.
        assert!(!GitHost::is_internal("refs/gitiup/kvroot"));
        assert!(!GitHost::is_internal("refs/gitiup/other"));
        assert!(!GitHost::is_internal("refs/heads/main"));

        assert_eq!(
            GitHost::kv_ref(&Namespace::ATTESTATION).as_str(),
            "refs/gitiup/kv/attestation"
        );
        // The prefix a chain lives under is a ref a person may not use for a
        // record, or the store and their ref would collide.
        assert!(GitHost::reject_reserved(&RefName::new(KV_ROOT).unwrap()).is_err());
        assert!(GitHost::reject_reserved(&RefName::change_head("c1").unwrap()).is_ok());
    }

    #[test]
    fn the_probe_setting_is_spelled_out() {
        assert_eq!(Probe::parse("on").unwrap(), Probe::On);
        assert_eq!(Probe::parse("").unwrap(), Probe::On);
        assert_eq!(Probe::parse("OFF").unwrap(), Probe::Off);
        assert_eq!(Probe::Off.as_str(), "off");
        let error = Probe::parse("sometimes").unwrap_err();
        assert_eq!(error.kind(), crate::HostErrorKind::Invalid);
        assert!(
            error.hint().is_some_and(|h| h.contains("--dry-run")),
            "{error}"
        );
    }

    #[test]
    fn options_that_would_stall_a_write_are_reported() {
        // A typo in a setting is advice, not silence: the same table is read by
        // other hosts, so an unknown key is not necessarily wrong.
        let remote = remote_at("file:///srv/git/repo.git").with_option("region", "eu-central-1");
        let (_, advice) = GitOptions::from_remote(&remote, None).unwrap();
        assert!(
            advice.iter().any(|line| line.contains("region")),
            "{advice:?}"
        );

        // A create-only CAS write that retries forever would be a hang, not a
        // retry policy, so 0 attempts means "say no once".
        let remote = remote_at("file:///srv/git/repo.git").with_option("cas-attempts", "0");
        let (options, advice) = GitOptions::from_remote(&remote, None).unwrap();
        assert_eq!(options.cas_attempts, 0);
        assert!(
            advice.iter().any(|line| line.contains("cas-attempts")),
            "{advice:?}"
        );
    }
}

//! Which host serves which remote — and what happens when nothing does.
//!
//! This is the composition root's job, and only this crate may do it: `gitiup-host`
//! defines the traits and ships the hosts it ships (`fs`, a bucket, plain git), and
//! forge adapters live in their own crates behind their own features. The CLI is
//! where those two meet, so the CLI is also where "this remote is a forge and you
//! built the binary without the forge adapter" has to be answered — in those words,
//! naming the flag to turn on, rather than as an unknown scheme or a silent fallback
//! to a host that can only read refs.
//!
//! Nothing here talks to a forge. The only thing this file knows about GitHub is the
//! name of the adapter that serves it, which is what makes the refusal possible in a
//! build that cannot reach one.

use gitiup_host::{
    Config, CredentialProfile, FsHost, Host, HostError, HostErrorKind, RemoteConfig, RemoteScheme,
};

use crate::CliError;

/// The cargo feature that puts a github adapter in the binary. Named in every
/// refusal, because "not supported" without a fix is a dead end.
pub const FORGE_FEATURE: &str = "hosts-github";

/// The forge hosts this build can *name*, used only to explain a missing adapter —
/// never to talk to one. An adapter added later is recognised by its `host-type`
/// option, which is why that option wins when both are present.
const FORGE_HOSTS: &[&str] = &["github.com"];

/// Usage for `gitiup doctor --remotes`.
pub const USAGE: &str = "\
gitiup doctor --remotes — say which host serves each configured remote.

USAGE:
    gitiup doctor --remotes [--json]

Reads `gitiup.toml` and, for every `[[remote]]`, reports the host that would serve
it and what that host says about itself. Nothing is written and nothing is pushed.
A forge remote is asked for its own account of the repository; a bucket or a plain
git remote is classified only, because probing those needs credentials and a
network and a doctor nobody runs is a doctor that tells you nothing.

Exit codes: 0 every remote has a host (warnings possible) · 6 a remote has no host
this build can serve · 2 usage.
";

/// A host that serves a remote, described.
#[derive(Debug, Clone)]
pub struct Served {
    /// Short kind: `github`, `s3`, `git`, `fs`.
    pub kind: String,
    /// Which code implements it, version included.
    pub implemented_by: String,
    /// One line the host offers to a human.
    pub summary: String,
}

/// What `gitiup doctor --remotes` found about one remote.
#[derive(Debug)]
pub struct RemoteReport {
    /// The remote's name as the user typed it.
    pub name: String,
    /// The URL with any credential removed.
    pub url: String,
    /// The host that serves it, or the refusal that says why nothing does.
    pub served: Result<Served, String>,
    /// What the serving host says the caller should know (its caveats).
    pub advice: Vec<String>,
}

impl RemoteReport {
    /// Whether this remote has a host at all.
    pub fn is_served(&self) -> bool {
        self.served.is_ok()
    }

    /// The report as a human-readable paragraph.
    pub fn text(&self) -> String {
        let mut out = match &self.served {
            Ok(served) => format!("{} [{}] — {}", self.name, served.kind, self.url),
            Err(why) => format!("{} — {} ({})", self.name, self.url, why),
        };
        for line in &self.advice {
            out.push_str(&format!("\n    · {line}"));
        }
        out
    }

    /// The report as JSON: the same facts, the same spelling.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "url": self.url,
            "served": match &self.served {
                Ok(served) => serde_json::json!({
                    "host": served.kind,
                    "by": served.implemented_by,
                    "summary": served.summary,
                }),
                Err(why) => serde_json::json!({"error": why}),
            },
            "advice": self.advice,
        })
    }
}

/// What an operator said a remote *is*, in `[remote.options] host-type`.
///
/// The URL says the transport; only the operator says the kind of store. A
/// `file://` path is a directory as far as gitiup knows, and a bare repository is a
/// store too — which is the difference between the fs host and the plain-git one,
/// and the difference a bucket of objects and a forge database do not let the URL
/// settle either. Saying it is one value in `gitiup.toml`; not being able to say it
/// is why a local bare repository used to be unreachable from the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declared {
    /// The forge adapter's (`hosts-github`).
    Github,
    /// A git repository — bare or not — reached over any transport.
    Git,
    /// A plain directory holding a gitiup store.
    Fs,
    /// A bucket.
    S3,
}

impl Declared {
    /// Every accepted spelling, in the order a refusal lists them.
    pub const ALL: &'static [&'static str] = &["github", "gh", "git", "fs", "s3"];

    /// The canonical kind name, the same spelling `classify` reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Declared::Github => "github",
            Declared::Git => "git",
            Declared::Fs => "fs",
            Declared::S3 => "s3",
        }
    }

    /// Read one spelling. `None` is not a refusal here: [`declared_host`] refuses,
    /// and [`wants_forge`] has to keep answering a yes/no question either way.
    fn parse(text: &str) -> Option<Declared> {
        match text.trim().to_ascii_lowercase().as_str() {
            "github" | "gh" => Some(Declared::Github),
            "git" => Some(Declared::Git),
            "fs" => Some(Declared::Fs),
            "s3" => Some(Declared::S3),
            _ => None,
        }
    }

    /// One line the host offers to a human, in the words `classify` reports.
    fn summary(self) -> &'static str {
        match self {
            Declared::Github => {
                "the forge's own API, with gitiup's refs and records stored in the \
                 repository itself"
            }
            Declared::Git => "a plain git remote: refs and packs, no change database",
            Declared::Fs => "a local directory",
            Declared::S3 => "one bucket as a complete remote",
        }
    }

    /// Does this kind fit a URL whose scheme is `scheme`?
    ///
    /// `fs` needs a path the process can open, so only `file://` can carry it; `s3`
    /// needs a bucket, so only `s3://` does. `git` is the one kind every transport
    /// can serve, which is why declaring it on an `https://` remote is a real answer
    /// and not a typo: it says "this is a git server, whatever its hostname says".
    fn fits(self, scheme: RemoteScheme) -> bool {
        match self {
            Declared::Github => true,
            // A repository is what git speaks over any of these transports; a bucket is
            // not, and pretending otherwise would send an `s3://` URL to `git fetch`.
            Declared::Git => !matches!(scheme, RemoteScheme::S3),
            Declared::Fs => matches!(scheme, RemoteScheme::File),
            Declared::S3 => matches!(scheme, RemoteScheme::S3),
        }
    }
}

/// The declared host kind for a remote, checked against its URL.
///
/// `host-type` is read once, here, so `classify` and `open` cannot drift about what
/// a remote is. A value from the list is honoured; a value off it is refused by name
/// with the list in the hint, because a declaration nobody recognises is exactly the
/// moment a write could land in the wrong kind of store.
pub fn declared_host(remote: &RemoteConfig) -> Result<Option<Declared>, HostError> {
    let Some(text) = remote.option("host-type") else {
        return Ok(None);
    };
    let Some(kind) = Declared::parse(text) else {
        return Err(HostError::invalid(
            "host-type",
            format!("\"{text}\" is not a host gitiup knows"),
        )
        .with_exit_code(2)
        .with_hint(format!(
            "say one of {} — `fs` is a directory store, `git` a repository (bare or not), \
             `s3` a bucket, `github` the forge adapter (`{FORGE_FEATURE}`)",
            Declared::ALL.join(", ")
        )));
    };
    if !kind.fits(remote.url.scheme) {
        return Err(HostError::invalid(
            "host-type",
            format!(
                "\"{}\" does not fit a {}:// URL",
                kind.as_str(),
                remote.url.scheme.as_str()
            ),
        )
        .with_exit_code(2)
        .with_hint(format!(
            "a {} store is reached with a {}:// URL; drop the declaration to let the URL \
             decide",
            kind.as_str(),
            kind.as_str()
        )));
    }
    Ok(Some(kind))
}

/// Is this path a git repository (bare, or a working copy)?
///
/// A cheap filesystem question, not a `git rev-parse`: the answer decides which of
/// two mutually incompatible store layouts gitiup is about to write into — the fs
/// host keeps `refs` as a *file*, git keeps it as a *directory* — so a wrong guess
/// is `Is a directory (os error 21)` from inside a storage call rather than a
/// sentence about what to change.
pub fn git_repository(path: &std::path::Path) -> bool {
    let bare = path.join("HEAD").is_file() && path.join("objects").is_dir();
    let worktree = path.join(".git").exists();
    bare || worktree
}

/// The refusal for a `file://` path that is a repository, not a directory store.
fn repository_not_directory(remote: &RemoteConfig) -> HostError {
    let path = remote.url.file_path().display().to_string();
    HostError::invalid(
        "store-kind",
        format!(
            "{path} is a git repository, and a file:// remote names a gitiup directory \
             store by default"
        ),
    )
    .with_hint(
        "say what it is: `host-type = \"git\"` in `[remote.options]` serves it with the \
         plain-git host — a bare repository is a complete gitiup store, refs and CAS \
         included — or point the remote at a plain directory instead",
    )
}

/// Is this remote one that needs a forge adapter rather than a plain host?
///
/// `host-type = "github"` in `[remote.options]` is the explicit spelling; the
/// hostname is the convenience, because `https://github.com/owner/repo` is what
/// everyone types. A GitHub Enterprise remote has no github.com in its URL, so it
/// needs `api-base` or `host-type` — and saying so is this function's job.
pub fn wants_forge(remote: &RemoteConfig) -> bool {
    if let Some(declared) = remote.option("host-type") {
        return Declared::parse(declared) == Some(Declared::Github);
    }
    let host = remote.url.host.to_ascii_lowercase();
    FORGE_HOSTS
        .iter()
        .any(|forge| host == *forge || host.ends_with(&format!(".{forge}")))
        || remote.option("api-base").is_some()
}

#[cfg_attr(
    feature = "hosts-github",
    allow(
        dead_code,
        reason = "the adapter answers, so nothing needs the refusal"
    )
)]

/// The error a forge remote gets in a build without the adapter.
///
/// A `SchemeUnknown` naming the flag, because to such a build that is exactly what
/// it is: nothing in this binary serves that remote. The alternative — falling back
/// to the plain-git host because `https://` happens to work for `git fetch` — would
/// let `gitiup submit` "succeed" against a remote whose change database it cannot
/// read, which is a worse failure than refusing.
pub fn forge_without_adapter(remote: &RemoteConfig) -> HostError {
    HostError::SchemeUnknown(Box::new(gitiup_host::error::SchemeUnknown {
        scheme: "github".to_string(),
        supported: vec![
            "s3".into(),
            "https".into(),
            "ssh".into(),
            "file".into(),
            #[cfg(feature = "hosts-github")]
            "github".into(),
        ],
        hint: Some(format!(
            "'{}' points at a forge repository ({}), and this gitiup was built without \
             the `{FORGE_FEATURE}` feature. Rebuild with `--features {FORGE_FEATURE}` \
             (it is on by default), or point the remote at a host this build does serve.",
            remote.name,
            remote.redacted_url()
        )),
    }))
}

/// What can be said about a remote without opening anything.
///
/// Cheap enough for a doctor run on a machine with no network, which is the machine
/// where the answer matters most.
pub fn classify(remote: &RemoteConfig) -> Result<Served, HostError> {
    if wants_forge(remote) {
        #[cfg(feature = "hosts-github")]
        return Ok(Served {
            kind: "github".to_string(),
            implemented_by: format!("gitiup-host-github {}", env!("CARGO_PKG_VERSION")),
            summary: "the forge's own API, with gitiup's refs and records stored in the \
                      repository itself"
                .to_string(),
        });
        #[cfg(not(feature = "hosts-github"))]
        return Err(forge_without_adapter(remote));
    }
    let kind = kind_for(remote)?;
    Ok(Served {
        kind: kind.as_str().to_string(),
        implemented_by: format!("gitiup-host {}", env!("CARGO_PKG_VERSION")),
        summary: kind.summary().to_string(),
    })
}

/// Which kind of host serves a remote: the declaration if there is one, the URL's
/// scheme otherwise.
///
/// One function because `classify` and `open` must never disagree: a remote the doctor
/// calls a directory and `submit` opens as a repository is the composition root failing
/// at its one job.
fn kind_for(remote: &RemoteConfig) -> Result<Declared, HostError> {
    if let Some(declared) = declared_host(remote)? {
        return Ok(declared);
    }
    Ok(match remote.url.scheme {
        RemoteScheme::S3 => Declared::S3,
        // A `file://` path is a directory store *by default*, not by nature: point one
        // at a bare repository and the fs host would fail inside a storage call with an
        // errno nobody can act on, so this is where that gets a sentence instead.
        RemoteScheme::File => {
            if git_repository(&remote.url.file_path()) {
                return Err(repository_not_directory(remote));
            }
            Declared::Fs
        }
        RemoteScheme::Https | RemoteScheme::Http | RemoteScheme::Ssh => Declared::Git,
    })
}

/// The host that serves a remote, opened for real.
///
/// The composition root's other half: [`classify`] says what *would* serve a remote
/// without touching it, and this opens it. Every command that reads or writes a store
/// goes through here, so no command gets to invent its own storage or reach a forge
/// behind the host traits. `profile` is the credential profile named by the remote, if
/// any — the caller resolves it from the config, because only the config knows whether
/// a missing profile is an error.
pub fn open(
    remote: &RemoteConfig,
    profile: Option<&CredentialProfile>,
) -> Result<Box<dyn Host>, HostError> {
    if wants_forge(remote) {
        #[cfg(feature = "hosts-github")]
        {
            let transport = gitiup_host_github::curl::default_transport(remote)?;
            return Ok(Box::new(gitiup_host_github::GitHubHost::with_transport(
                remote, transport, profile,
            )?));
        }
        #[cfg(not(feature = "hosts-github"))]
        {
            let _ = profile;
            return Err(forge_without_adapter(remote));
        }
    }
    // `classify` has already refused what has no host, and has already checked the
    // declaration against the scheme; this only has to agree with it.
    match kind_for(remote)? {
        Declared::Fs => Ok(Box::new(FsHost::open_or_create(remote.url.file_path())?)),
        Declared::S3 => Ok(Box::new(gitiup_host::S3Host::open_or_init_remote(remote)?)),
        // A `github` declaration is answered above, with the adapter or with the
        // refusal; reaching here with one means the URL is a plain git one and the
        // operator said so, which is what a declaration is for.
        Declared::Git | Declared::Github => Ok(Box::new(
            gitiup_host::hosts::git::GitHost::open_or_init_remote(remote)?,
        )),
    }
}

/// The report for one remote: what serves it, and what that host warns about.
///
/// A forge remote is *opened*, because the adapter is the only thing that can read
/// what the forge says about the repository (may this credential push? is the
/// default branch there?) and because opening it is what proves the adapter is in
/// the build. The other hosts are classified only — see [`USAGE`].
pub fn report(remote: &RemoteConfig, profile: Option<&CredentialProfile>) -> RemoteReport {
    let mut report = RemoteReport {
        name: remote.name.clone(),
        url: remote.redacted_url(),
        served: classify(remote).map_err(|why| plain(&why)),
        advice: Vec::new(),
    };
    if !wants_forge(remote) {
        return report;
    }
    match forge_host(remote, profile) {
        Ok(opened) => {
            report.served = Ok(Served {
                kind: opened.kind,
                implemented_by: opened.implemented_by,
                summary: opened.summary,
            });
            report.advice = opened.advice;
        }
        Err(why) => report.served = Err(plain(&why)),
    }
    report
}

/// A refused error as one line, for a report that has room for exactly one string
/// per remote. The taxonomy's own `Display` already renders the hint (it is part of
/// the answer, not a footnote), so appending it here would print it twice.
fn plain(error: &HostError) -> String {
    error.to_string()
}

/// The adapter's own account of itself: its caveats, and the capability it cannot
/// promise. Empty when there is no adapter to ask.
#[allow(unused_variables)]
fn forge_host(
    remote: &RemoteConfig,
    profile: Option<&CredentialProfile>,
) -> Result<Opened, HostError> {
    #[cfg(feature = "hosts-github")]
    {
        let transport = gitiup_host_github::curl::default_transport(remote)?;
        let host = gitiup_host_github::GitHubHost::with_transport(remote, transport, profile)?;
        let info = host.describe();
        let summary = info.summary_line();
        Ok(Opened {
            kind: format!("{:?}", info.kind).to_ascii_lowercase(),
            implemented_by: info.implemented_by,
            summary,
            advice: host.advice(),
        })
    }
    #[cfg(not(feature = "hosts-github"))]
    {
        let _ = profile;
        Err(forge_without_adapter(remote))
    }
}

/// Ask a forge to merge one of its own changes (ADR-0003 D10).
///
/// On a forge, the forge's merge *is* the merge: atomic, reviewed, and governed by the
/// forge's own protection rules, which is more than a conditional ref write can promise
/// and therefore not something gitiup should imitate. `expect` is the commit the caller
/// believes is being merged — the forge re-checks it, so this carries the same
/// compare-and-swap guarantee the store path gets from `Expect::Is`.
///
/// Returns the commit the forge put on the base branch, which is what the merge record
/// names as `to`: with a fast-forward that is the change's head, and with a merge commit
/// it is a commit no attestation can cover — which is why `ff` is the default and why the
/// record says `via: forge` rather than pretending.
#[cfg(feature = "hosts-github")]
pub fn forge_merge(
    remote: &RemoteConfig,
    profile: Option<&CredentialProfile>,
    number: u64,
    expect: &gitiup_host::Oid,
    method: &str,
) -> Result<gitiup_host::Oid, CliError> {
    let transport = gitiup_host_github::curl::default_transport(remote)
        .map_err(|e| CliError::io(format!("remote '{}': {e}", remote.name)))?;
    let host = gitiup_host_github::GitHubHost::with_transport(remote, transport, profile)
        .map_err(|e| CliError::io(format!("remote '{}': {e}", remote.name)))?;
    let merged = host
        .merge_change(number, expect, method)
        .map_err(|e| store_says(&e))?;
    if merged.state != gitiup_host_github::ChangeState::Merged {
        return Err(CliError::refused(
            format!("the forge closed pull {number} rather than merging it"),
            "the forge answered, and its answer was not a merge: its own checks, its \
             protection rules or a human said no. Nothing was merged, and gitiup will not \
             write a merge record for a change the forge refused (ADR-0003 D10)",
        ));
    }
    merged.landed.ok_or_else(|| {
        CliError::refused(
            format!("the forge merged pull {number} and did not say which commit landed"),
            "the merge record has to name the commit that moved onto the branch; check the \
             forge's own answer, or reconcile from a clone that can see the branch",
        )
    })
}

/// The same refusal on a build with no adapter in it. Reaching it at all means the remote
/// was accepted, which [`classify`] already refuses — so this is a belt, not the braces.
#[cfg(not(feature = "hosts-github"))]
pub fn forge_merge(
    remote: &RemoteConfig,
    _profile: Option<&CredentialProfile>,
    _number: u64,
    _expect: &gitiup_host::Oid,
    _method: &str,
) -> Result<gitiup_host::Oid, CliError> {
    let _ = remote;
    Err(CliError::refused(
        format!("this gitiup cannot reach a forge at all ({FORGE_FEATURE} is off)"),
        format!("rebuild with `--features {FORGE_FEATURE}`"),
    ))
}

/// A store's own words, kept: taxonomy label, message, hint, and the code its kind
/// implies. See `change::store_refusal`.
fn store_says(error: &gitiup_host::HostError) -> CliError {
    use gitiup_host::HostErrorExt as _;
    let message = if error.is_denied() {
        format!("{}: {}", error.kind(), error.message())
    } else {
        error.message()
    };
    CliError::scored(error.exit_code(), message, error.hint().map(str::to_string))
}

/// The parts of a host this command prints, held without a trait object so the
/// adapter-specific `advice()` call stays where it belongs.
struct Opened {
    kind: String,
    implemented_by: String,
    summary: String,
    advice: Vec<String>,
}

// ---------------------------------------------------------------------------
// the forge, as the change verbs need it
// ---------------------------------------------------------------------------

/// One change as a forge described it, in the command line's own words.
///
/// The adapter hands over a translated record; this is the same facts with the forge's
/// type name taken off, so `change.rs` can label a listing without importing anything
/// from a forge adapter — which is the rule `tests/no_forge_calls.rs` enforces, and the
/// reason this struct exists rather than a re-export.
#[derive(Debug, Clone)]
pub struct ForgeChange {
    /// The forge's own number, when it has one (`source: pull` or `both`).
    pub number: Option<u64>,
    /// How the forge names it (`gh-12`), or the change id when it came from a ref. Same
    /// key, same meaning as a store-backed row's `change`, so one script can read either.
    pub id: String,
    /// Its title.
    pub title: String,
    /// `open`, `merged` or `closed`.
    pub state: &'static str,
    /// Who opened it, as the forge spells the name.
    pub author: Option<String>,
    /// The branch it wants to land on.
    pub base: Option<String>,
    /// The commit it proposes, hex.
    pub head: Option<String>,
    /// Where a human can look at it.
    pub url: Option<String>,
    /// Labels, shown as read and never interpreted.
    pub labels: Vec<String>,
    /// When it last moved, seconds since the epoch.
    pub updated_at: Option<u64>,
    /// `ref` · `pull` · `both`: which database this came from, and so whether anything
    /// can vouch for it. A forge's `source`, spelled the same way in `--json`.
    pub source: &'static str,
    /// The forge could not hold the whole copy of this change.
    pub copy_truncated: bool,
    /// What the forge cannot promise about this change, in its own words.
    pub caveats: Vec<String>,
}

impl ForgeChange {
    /// The forge's number, if it has one.
    pub fn pull(&self) -> Option<u64> {
        self.number
    }

    /// The same facts as JSON, with the vocabulary the rest of `--json` uses.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "change": self.id,
            "pull": self.number,
            "title": self.title,
            "state": self.state,
            "author": self.author,
            "base": self.base,
            "head": self.head,
            "url": self.url,
            "labels": self.labels,
            "source": self.source,
            "copy_truncated": self.copy_truncated,
            "caveats": self.caveats,
        })
    }
}

/// A remote that has a merge button, opened.
///
/// The change verbs need exactly four things of a forge: what it carries, how to ask it
/// to carry one, which of its branches hold a commit, and how to ask it to merge. Those
/// four are answered here and nowhere else in the command line, so that a change verb can
/// be forge-agnostic in fact and not only in intention. Every method refuses, naming the
/// feature, in a build compiled without the adapter — the same answer [`classify`] gives
/// for the remote as a whole, at the same code.
pub struct Forge {
    remote: RemoteConfig,
    profile: Option<CredentialProfile>,
}

impl Forge {
    /// A forge handle for a remote that is one.
    pub fn new(remote: &RemoteConfig, profile: Option<&CredentialProfile>) -> Forge {
        Forge {
            remote: remote.clone(),
            profile: profile.cloned(),
        }
    }
}

#[cfg(feature = "hosts-github")]
impl Forge {
    fn host(&self) -> Result<gitiup_host_github::GitHubHost, CliError> {
        let transport = gitiup_host_github::curl::default_transport(&self.remote)
            .map_err(|e| CliError::io(format!("remote '{}': {e}", self.remote.name)))?;
        gitiup_host_github::GitHubHost::with_transport(
            &self.remote,
            transport,
            self.profile.as_ref(),
        )
        .map_err(|e| CliError::io(format!("remote '{}': {e}", self.remote.name)))
    }

    /// Every change the forge and the store together know about (`all` · `open` ·
    /// `closed`), each labelled with where it came from.
    pub fn changes(&self, state: &str) -> Result<Vec<ForgeChange>, CliError> {
        let host = self.host()?;
        Ok(host
            .changes(state)
            .map_err(|e| store_says(&e))?
            .into_iter()
            .map(describe)
            .collect())
    }

    /// Ask the forge to carry a change: open the pull request over `head_branch`.
    pub fn open_change(
        &self,
        title: &str,
        head_branch: &str,
        base_branch: &str,
        body: &str,
        draft: bool,
    ) -> Result<ForgeChange, CliError> {
        let host = self.host()?;
        host.open_change(title, head_branch, base_branch, body, draft)
            .map(describe)
            .map_err(|e| store_says(&e))
    }

    /// The forge's branches that point at `head` — the only refs it will accept as a
    /// pull request's head.
    pub fn branches_at(&self, head: &gitiup_host::Oid) -> Result<Vec<String>, CliError> {
        let host = self.host()?;
        host.branches_at(head).map_err(|e| store_says(&e))
    }

    /// The forge's open pulls that propose exactly `head`.
    pub fn open_pulls_at(&self, head: &gitiup_host::Oid) -> Result<Vec<ForgeChange>, CliError> {
        let host = self.host()?;
        Ok(host
            .open_pulls_at(head)
            .map_err(|e| store_says(&e))?
            .into_iter()
            .map(describe)
            .collect())
    }

    /// Ask the forge to merge its own change (ADR-0003 D10).
    pub fn merge(
        &self,
        number: u64,
        expect: &gitiup_host::Oid,
        method: &str,
    ) -> Result<gitiup_host::Oid, CliError> {
        forge_merge(&self.remote, self.profile.as_ref(), number, expect, method)
    }
}

#[cfg(not(feature = "hosts-github"))]
impl Forge {
    /// Every method answers this way in such a build: the flag to rebuild with, at the
    /// code the rest of the tool uses for "this build cannot".
    fn refused(&self) -> CliError {
        CliError::refused(
            format!(
                "remote '{}': {}",
                self.remote.name,
                plain(&forge_without_adapter(&self.remote))
            ),
            format!("rebuild with `--features {FORGE_FEATURE}`"),
        )
    }

    pub fn changes(&self, _state: &str) -> Result<Vec<ForgeChange>, CliError> {
        Err(self.refused())
    }

    pub fn open_change(
        &self,
        _title: &str,
        _head_branch: &str,
        _base_branch: &str,
        _body: &str,
        _draft: bool,
    ) -> Result<ForgeChange, CliError> {
        Err(self.refused())
    }

    pub fn branches_at(&self, _head: &gitiup_host::Oid) -> Result<Vec<String>, CliError> {
        Err(self.refused())
    }

    pub fn open_pulls_at(&self, _head: &gitiup_host::Oid) -> Result<Vec<ForgeChange>, CliError> {
        Err(self.refused())
    }

    pub fn merge(
        &self,
        number: u64,
        expect: &gitiup_host::Oid,
        method: &str,
    ) -> Result<gitiup_host::Oid, CliError> {
        forge_merge(&self.remote, self.profile.as_ref(), number, expect, method)
    }
}

/// The forge's caveats for a change it was asked about, in the adapter's own words.
///
/// The vocabulary is the adapter's (`CAVEAT_*`) so the words a human reads and the words
/// the forge admits are one set, not two that drift; the *decision* about which applies is
/// made here, because it is the command line that knows whether it also holds a record.
#[cfg(feature = "hosts-github")]
pub fn caveats(source: &str, copy_truncated: bool) -> Vec<String> {
    let mut out: Vec<String> = match source {
        "pull" => vec![gitiup_host_github::CAVEAT_COPY_ONLY.to_string()],
        "both" => vec![gitiup_host_github::CAVEAT_TWO_CALLS.to_string()],
        _ => vec![gitiup_host_github::CAVEAT_NO_PULL.to_string()],
    };
    if copy_truncated {
        out.push(gitiup_host_github::CAVEAT_TRUNCATED.to_string());
    }
    out.push(gitiup_host_github::CAVEAT_CAS.to_string());
    out
}

/// There is no forge to quote, so there is nothing for it to disclaim.
#[cfg(not(feature = "hosts-github"))]
pub fn caveats(_source: &str, _copy_truncated: bool) -> Vec<String> {
    Vec::new()
}

/// The adapter's record, with the adapter's type name taken off.
#[cfg(feature = "hosts-github")]
fn describe(change: gitiup_host_github::forge::ChangeRecord) -> ForgeChange {
    let caveats: Vec<String> = change.caveats().into_iter().map(str::to_string).collect();
    let labels = change.labels.clone();
    ForgeChange {
        number: match change.origin {
            gitiup_host_github::ChangeOrigin::Pull { number } => Some(number),
            gitiup_host_github::ChangeOrigin::Ref { .. } => None,
        },
        id: change.id.clone(),
        title: change.title,
        state: change.state.as_str(),
        author: change.author,
        base: change
            .base
            .map(|name| name.as_str().trim_start_matches("refs/heads/").to_string()),
        head: change.head.map(|oid| oid.hex()),
        url: change.url,
        labels,
        updated_at: change.updated_at,
        source: change.source.as_str(),
        copy_truncated: change.copy_truncated,
        caveats,
    }
}

/// `gitiup doctor --remotes`.
pub fn run(args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--remotes" => {}
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => {
                return Err(CliError::usage(format!(
                    "unknown doctor flag '{other}'; `gitiup doctor --help` lists what \
                     can be inspected"
                )));
            }
        }
    }
    let (path, config) = match Config::load_default() {
        Ok(Some(found)) => found,
        Ok(None) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"remotes": [], "note": "no gitiup.toml found"})
                );
            } else {
                println!(
                    "no gitiup.toml found, so no remotes are configured; the file lives \
                     at the top of the repository (or where `$GITIUP_CONFIG` points)"
                );
            }
            return Ok(());
        }
        Err(why) => {
            return Err(CliError::refused(
                format!("gitiup.toml could not be read: {}", plain(&why)),
                "fix the file; every remote must name a host this build can serve",
            ));
        }
    };
    let reports: Vec<RemoteReport> = config
        .remotes()
        .iter()
        .map(|remote| report(remote, config.credential_profile(remote)))
        .collect();
    let refused = reports.iter().any(|report| !report.is_served());
    if json {
        let body = serde_json::json!({
            "config": path.display().to_string(),
            "remotes": reports.iter().map(RemoteReport::json).collect::<Vec<_>>(),
            "warnings": config.warnings(),
        });
        println!("{body}");
    } else {
        println!("{} — {} remote(s)", path.display(), reports.len());
        for report in &reports {
            println!("{}", report.text());
        }
        for warning in config.warnings() {
            println!("warning: {warning}");
        }
        if refused {
            println!(
                "a remote above has no host this build can serve; the exit code is 6 so \
                 a script can branch on it"
            );
        }
    }
    if refused {
        return Err(CliError::refused(
            "a configured remote has no host in this build".to_string(),
            "each refusal above carries its own fix: a missing forge adapter names the \
             feature to build with (`{FORGE_FEATURE}`), a store-kind mismatch names the \
             `host-type` to declare",
        ));
    }
    Ok(())
}

/// Keeps the taxonomy import honest: a report that cannot say *why* nothing serves a
/// remote has not answered anything.
#[allow(dead_code)]
fn kind_name(kind: HostErrorKind) -> &'static str {
    kind.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(url: &str) -> RemoteConfig {
        RemoteConfig::new("origin", url).expect("a remote")
    }

    #[test]
    fn a_forge_remote_is_recognised_from_the_url_and_from_the_option() {
        assert!(wants_forge(&remote("https://github.com/gitiup/gitiup.git")));
        assert!(wants_forge(&remote("https://www.github.com/gitiup/gitiup")));
        let declared =
            remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "github");
        assert!(wants_forge(&declared));
        let enterprise = remote("https://git.example.com/gitiup/gitiup")
            .with_option("api-base", "https://git.example.com/api/v3");
        assert!(wants_forge(&enterprise));
        assert!(
            !wants_forge(&remote("https://git.example.com/gitiup/gitiup")),
            "an ordinary git server is not a forge just because it is https"
        );
        assert!(!wants_forge(&remote("s3://gitiup-forge/my-repo")));
        let not_a_forge =
            remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "git");
        assert!(!wants_forge(&not_a_forge));
    }

    #[test]
    fn every_ordinary_remote_classifies_itself() {
        assert_eq!(
            classify(&remote("s3://gitiup-forge/my-repo"))
                .expect("s3")
                .kind,
            "s3"
        );
        assert_eq!(
            classify(&remote("file:///srv/gitiup")).expect("fs").kind,
            "fs"
        );
        assert_eq!(
            classify(&remote("ssh://git@example.com/gitiup/gitiup.git"))
                .expect("git")
                .kind,
            "git"
        );
        let report = report(&remote("ssh://git@example.com/gitiup/gitiup.git"), None);
        assert!(report.is_served());
        assert!(report.text().contains("git"));
        assert_eq!(report.json()["served"]["host"], "git");
        assert!(
            report.json()["served"]["by"]
                .as_str()
                .unwrap()
                .starts_with("gitiup-host ")
        );
    }

    #[test]
    #[cfg(not(feature = "hosts-github"))]
    fn without_the_adapter_a_forge_remote_names_the_flag() {
        let github = remote("https://github.com/gitiup/gitiup");
        let error = forge_without_adapter(&github);
        assert_eq!(error.kind(), HostErrorKind::SchemeUnknown);
        let text = error.to_string();
        assert!(text.contains(FORGE_FEATURE), "{text}");
        assert!(text.contains("--features"), "and how to turn it on: {text}");
        let refused = classify(&github).expect_err("nothing serves it");
        assert!(refused.to_string().contains(FORGE_FEATURE));
        let report = report(&github, None);
        assert!(
            !report.is_served(),
            "and the doctor says so instead of pretending: {:?}",
            report.served
        );
    }

    #[test]
    #[cfg(feature = "hosts-github")]
    fn with_the_adapter_a_forge_remote_is_github() {
        let served = classify(&remote("https://github.com/gitiup/gitiup")).expect("github");
        assert_eq!(served.kind, "github");
        assert!(served.implemented_by.contains("gitiup-host-github"));
    }

    #[test]
    fn a_declared_host_kind_overrides_what_the_url_would_say() {
        let dir = tempfile::tempdir().expect("a plain directory");
        let url = format!("file://{}", dir.path().display());
        assert_eq!(
            classify(&remote(&url))
                .expect("a plain directory is a store")
                .kind,
            "fs"
        );
        // The declaration is the whole of what a bare repository needs to be reachable
        // from the command line: same URL, different kind of store.
        assert_eq!(
            classify(&remote(&url).with_option("host-type", "git"))
                .expect("the operator said it is a repository")
                .kind,
            "git"
        );
        assert_eq!(
            classify(&remote(&url).with_option("host-type", "fs"))
                .expect("and can say it is a directory")
                .kind,
            "fs"
        );
        // `git` on an https URL is an answer and not a typo: it is how a self-hosted
        // server that is *not* a forge says so without gitiup guessing from a hostname.
        let plain = remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "git");
        assert_eq!(classify(&plain).expect("plain git").kind, "git");
        assert!(!wants_forge(&plain));
    }

    #[test]
    fn a_host_type_off_the_list_is_refused_with_the_list() {
        let error = declared_host(
            &remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "gitea"),
        )
        .expect_err("not a host gitiup knows");
        assert_eq!(
            error.exit_code(),
            2,
            "a config typo is usage, not a store failure"
        );
        let text = error.to_string();
        assert!(text.contains("gitea"), "{text}");
        let hint = error.hint().expect("and the fix");
        for kind in Declared::ALL {
            assert!(hint.contains(kind), "the hint lists {kind}: {hint}");
        }
        assert!(
            classify(&remote("s3://bucket/x").with_option("host-type", "gitea")).is_err(),
            "and the refusal is reached through the same door every command opens"
        );
    }

    #[test]
    fn a_host_type_that_does_not_fit_the_url_is_refused() {
        // Each of these is a declaration the URL contradicts: a directory store needs a
        // path, a bucket is not reachable over https, and a bucket is not a repository.
        let wrong = [
            ("https://git.example.com/gitiup/gitiup", "fs"),
            ("s3://gitiup-forge/repo", "fs"),
            ("s3://gitiup-forge/repo", "git"),
            ("https://git.example.com/gitiup/gitiup", "s3"),
        ];
        for (url, kind) in wrong {
            let error = declared_host(&remote(url).with_option("host-type", kind))
                .expect_err("{url} cannot be a {kind} store");
            assert_eq!(error.exit_code(), 2, "{url} + {kind}: {error}");
        }
        // And the declarations that do fit are honoured, not merely tolerated.
        assert_eq!(
            classify(&remote("s3://gitiup-forge/repo").with_option("host-type", "s3"))
                .expect("a bucket declared as a bucket")
                .kind,
            "s3"
        );
    }

    #[test]
    fn a_file_remote_at_a_repository_names_the_declaration_instead_of_an_errno() {
        let scratch = tempfile::tempdir().expect("scratch");
        let repo = scratch.path().join("repo.git");
        if gitiup_host::hosts::git::git_program().is_none() {
            eprintln!("skipped: no git to make a repository with");
            return;
        }
        gitiup_host::hosts::git::init_bare(&repo).expect("a bare repository");
        let url = format!("file://{}", repo.display());
        assert!(git_repository(&repo), "and the check sees it");
        assert!(
            !git_repository(&scratch.path().join("plain")),
            "a directory that is not one is not one"
        );

        let error = classify(&remote(&url)).expect_err("the fs host cannot share a repository");
        assert_eq!(error.exit_code(), 6, "a refusal, not an errno: {error}");
        let text = format!("{error} {}", error.hint().unwrap_or_default());
        assert!(text.contains("git repository"), "{text}");
        assert!(text.contains("host-type"), "and names the fix: {text}");

        // Declaring it is the whole fix: the same URL now classifies as git.
        assert_eq!(
            classify(&remote(&url).with_option("host-type", "git"))
                .expect("a bare repository is a gitiup store")
                .kind,
            "git"
        );
    }

    #[test]
    fn an_unknown_doctor_flag_is_a_usage_error() {
        let error = run(&["--squids".to_string()]).expect_err("usage");
        assert_eq!(error.code, 2);
    }
}

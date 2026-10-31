//! `gitiup migrate repo` — leave a forge for a store, with the history and the proofs.
//!
//! ```text
//! gitiup migrate repo --from github:<owner>/<repo> --to s3://bucket/repo [--with-proofs]
//! ```
//!
//! One command, one direction, and the whole exit cost of a forge in it: branches and tags
//! become ordinary refs, every open and merged pull request becomes a change whose `origin`
//! says which pull it was, and a check run becomes an attestation only where the attestation
//! is honestly recoverable from it. The [ADR-0005](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! rules that govern a copy between two stores govern this too — same digest, bytes before
//! advertisement, create-only, `trust: none` — with the forge's two extra databases read
//! through the adapter that owns their translation ([`gitiup_host_github::migrate`]).
//!
//! # The four promises, and where each one is kept
//!
//! | promise | how it is kept |
//!|--------|----------------|
//!| idempotent | every write is create-only or a forward CAS move, so a re-run says `already` everywhere and moves nothing; a ref that stands at a *different* oid is `diverged` and fails the run rather than being overwritten |
//!| resumable | a journal of finished steps ([`journal`]), and a git mirror whose object database is itself the resume state of the clone ([`mirror`]) — a fetch that dies at 38 GB asks for the rest |
//!| rate-limit aware | the forge's quota is checked *before* each listing against `--rate-floor`, and a run that would run out stops at a checkpoint with `rate_budget_exhausted` instead of dying an hour into a sleep |
//!| faithful | every commit that arrived with a proof is re-hashed from the destination's own bytes and counted ([`objects::verify`]); a mismatch is exit 8, because a migration that cannot prove it was faithful is a copy with confidence, which is not the same thing |
//!
//! # What a run reports, and never hides
//!
//! A check-run log is an advertisement, not a signature. The only check run that becomes an
//! attestation is one whose copy re-hashes to the digest it claims; every other one is a
//! line in `dropped`, with a token and a sentence (`check_run_copy_truncated`,
//! `check_run_not_gitiup`, `pull_closed_unmerged`, …). A closed-without-merge pull is not
//! carried at all: an open change that no branch will ever take is a ref that lies.
//!
//! # Exit codes
//!
//! The same table as the rest of `gitiup`: 0 ok · 2 usage · 3 I/O or an unreachable
//! store · 6 refused (a diverged ref, a read-only destination, a spent rate budget, an
//! incomplete run) · 7 a signature that does not verify · 8 bytes that are not the bytes
//! their name promises, which is what a failed re-hash is.
//!
//! A per-record refusal — one untranscribable pull, one check run that cannot be rebuilt —
//! is a report line, not a failure, for the same reason `gitiup fetch` reports them: one bad
//! record must not end a migration of two thousand, and `--strict` is for the job that would
//! rather know.

pub mod journal;

// The whole verb is "leave a forge", so every part of it is bolted to the forge adapter:
// `changes` reads the pull database, `mirror` fetches the history the forge will not hand
// over an API for, and `objects` moves and re-hashes what that mirror took — and it imports
// `super::mirror` to do it. With `--no-default-features` there is no forge to leave and
// `repo` refuses, so none of this is reachable; leaving `objects` unbolted had it importing
// a `mirror` that was never compiled, which is a compile error in a build that is otherwise
// perfectly good (giti-17g).
#[cfg(feature = "hosts-github")]
mod changes;
#[cfg(feature = "hosts-github")]
mod mirror;
#[cfg(feature = "hosts-github")]
pub mod objects;

use std::path::PathBuf;

use crate::CliError;
use crate::keys::Args;

use journal::Dropping;

/// Help for the whole verb.
pub const MIGRATE_HELP: &str = "\
gitiup migrate repo — leave a forge for a store, with history and proofs

USAGE:
    gitiup migrate repo --from <src> --to <store> [OPTIONS]

BETWEEN WHICH STORES:
    --from <src>             the forge being left: `github:<owner>/<repo>`, a [[remote]] in
                                 gitiup.toml, or a forge URL
    --to <store>             the destination: `s3://bucket/prefix`, a directory, a bare
                                 repository, or a [[remote]] name
    --git-url <url>          where the *history* is fetched from. The forge's own clone URL
                                 is used when it names one; otherwise this is required, and
                                 `--no-history` is the alternative
    --cache <dir>            the bare mirror the history is fetched into (default
                                 .gitiup/migrate/<slug>.git). Kept between runs: an
                                 interrupted fetch asks for the rest

WHAT TO MOVE:
    --with-proofs            carry check-run evidence, turning each one that re-hashes to its
                                 own digest into an attestation (the rest are reported as
                                 dropped, with the reason)
    --no-branches            skip refs/heads/**
    --no-tags                skip refs/tags/**
    --no-pulls               skip the pull-request table
    --no-history             no git objects move. A ref whose commit this store cannot show it
                                 already holds is refused as `ref_without_history` rather than
                                 written into nowhere, and the verification says plainly which
                                 proofs it therefore cannot re-hash

HOW FAR TO GO:
    --dry-run                read everything, write nothing (not the journal either)
    --strict                 any refusal at all fails the command (exit 6)
    --restart                ignore the journal and do it all again (still idempotent)
    --journal <path>         where the resume state lives (default .gitiup/migrate/<slug>.json)
    --rate-floor <n>         stop before the forge's quota drops to n calls left (default 50)
    --key <name>             which keystore key signs the transcribed changes
    --actor <name>           who the ref writes are recorded as

REPORTING:
    --json                   the whole report as JSON

A RE-RUN IS NOT A RESTART. Every write is create-only or a forward move, so running the same
command again moves nothing and says `already`; a run that stopped — rate limit, bad link,
interrupted clone — picks up at the journal's last finished step. A ref that stands at a
different oid than the forge has is `diverged` and is a failure, never an overwrite.

NOTHING HERE MANUFACTURES TRUST (ADR-0005 D3). A check run is an advertisement: the copy in
it becomes an attestation only if it re-hashes to the digest the run claims, which makes it
the signed document itself and not a reconstruction. Everything else is reported as dropped
with a token, and there is no flag that says 'carry it anyway'. The transcribed change
records are signed by *this* machine's key and say `origin: pull <n>`, because no signature
at the forge covered them.

AT THE END: for every commit that arrived with a proof, its bytes are read back out of the
destination and re-hashed, and the report prints how many matched. Exit 8 means the copy is
not faithful; read the mismatched list before you turn the forge off.

Exit codes: 0 ok · 2 usage · 3 I/O or unreachable · 6 refused (diverged ref, spent rate
budget, incomplete run, any refusal under --strict) · 7 a signature that does not verify ·
8 a commit that did not re-hash to the name its proof gives.

Try:
    gitiup migrate repo --from github:gitiup/gitiup --to s3://gitiup-backup/gitiup --dry-run
    gitiup migrate repo --from github:gitiup/gitiup --to s3://gitiup-backup/gitiup \\
        --with-proofs --json
    gitiup migrate repo --from upstream --to ./store --restart   # the same run, checked
";

/// Valued flags. There is no trust flag, and there never will be one (ADR-0005 D3).
const VALUED: &[&str] = &[
    "--from",
    "--to",
    "--git-url",
    "--cache",
    "--journal",
    "--rate-floor",
    "--key",
    "--actor",
];

/// Switches.
const SWITCHES: &[&str] = &[
    "--with-proofs",
    "--no-branches",
    "--no-tags",
    "--no-pulls",
    "--no-history",
    "--dry-run",
    "--strict",
    "--restart",
    "--json",
];

/// Tokens this command can report that are not the adapter's.
pub const REF_DIVERGED: &str = "ref_diverged";
/// History was not asked for, so no objects moved.
pub const HISTORY_NOT_ASKED: &str = "history_not_asked";
/// Neither the forge nor the operator named a git endpoint to fetch from.
pub const HISTORY_NO_URL: &str = "history_no_endpoint";
/// The fetch itself failed; the mirror keeps what it got, and the journal the rest.
pub const HISTORY_FAILED: &str = "history_failed";
/// A store refused one record.
pub const CHANGE_REFUSED: &str = "change_refused";
/// A ref the destination cannot back with bytes of its own.
pub const REF_NO_HISTORY: &str = "ref_without_history";
/// The run stopped at a checkpoint and has more to do.
pub const INCOMPLETE: &str = "migration_incomplete";

/// `gitiup migrate …`
pub fn migrate(args: &[String]) -> Result<(), CliError> {
    match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") => {
            print!("{MIGRATE_HELP}");
            Ok(())
        }
        Some("repo") | Some("repository") => repo(&args[1..]),
        Some(other) => Err(CliError::usage(format!(
            "unknown `gitiup migrate` command '{other}' (there is one: `gitiup migrate repo`)"
        ))),
    }
}

/// What the operator asked for.
#[derive(Debug)]
struct Options {
    from: String,
    to: String,
    git_url: Option<String>,
    cache: Option<PathBuf>,
    journal: Option<PathBuf>,
    rate_floor: u32,
    actor: Option<String>,
    branches: bool,
    tags: bool,
    pulls: bool,
    with_proofs: bool,
    history: bool,
    dry_run: bool,
    strict: bool,
    restart: bool,
    json: bool,
}

impl Options {
    fn parse(args: &Args) -> Result<Options, CliError> {
        let need = |name: &str| -> Result<String, CliError> {
            args.get(name)
                .map(str::to_string)
                .ok_or_else(|| CliError::usage(format!("--{name} is required")))
        };
        let floor =
            match args.get("--rate-floor") {
                Some(text) => Some(text.trim().parse::<u32>().map_err(|_| {
                    CliError::usage(format!("--rate-floor '{text}' is not a count"))
                })?),
                None => None,
            };
        Ok(Options {
            from: need("--from")?,
            to: need("--to")?,
            git_url: args.get("--git-url").map(str::to_string),
            cache: args.get("--cache").map(PathBuf::from),
            journal: args.get("--journal").map(PathBuf::from),
            rate_floor: floor.unwrap_or(50),
            actor: args.get("--actor").map(str::to_string),
            branches: !args.on("--no-branches"),
            tags: !args.on("--no-tags"),
            pulls: !args.on("--no-pulls"),
            with_proofs: args.on("--with-proofs"),
            history: !args.on("--no-history"),
            dry_run: args.on("--dry-run"),
            strict: args.on("--strict"),
            restart: args.on("--restart"),
            json: args.json(),
        })
    }
}

/// `gitiup migrate repo …`
#[cfg(feature = "hosts-github")]
fn repo(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.help(MIGRATE_HELP).is_some() {
        return Ok(());
    }
    let options = Options::parse(&args)?;
    let mut run = Run::open(&options, &args)?;
    let code = run.run(&options)?;
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&run.json(&options)).unwrap_or_else(|_| "{}".into())
        );
    } else {
        for line in run.report(&options) {
            println!("{line}");
        }
    }
    if code != 0 {
        // The report is the verdict: printed on stdout, carried in the exit code, and not
        // repeated on stderr where a script would have to parse prose.
        return Err(CliError::verdict(code));
    }
    Ok(())
}

/// There is no forge adapter in this build, so there is nothing to leave.
#[cfg(not(feature = "hosts-github"))]
fn repo(_args: &[String]) -> Result<(), CliError> {
    Err(CliError::refused(
        "this gitiup was built without the `hosts-github` feature, so it cannot read a forge",
        "rebuild with `--features hosts-github` (it is on by default)",
    ))
}

/// Every fact about one run, in one place, so the report and the journal cannot disagree
/// about what happened.
#[cfg(feature = "hosts-github")]
struct Run {
    from: String,
    to_what: String,
    to: Box<dyn gitiup_host::Host>,
    github: gitiup_host_github::GitHubHost,
    key: gitiup_keys::signer::Key,
    key_id: String,
    principal: String,
    actor: gitiup_host::Actor,
    journal: journal::Journal,
    path: PathBuf,
    resumed: usize,
    halted: Option<String>,
    history: String,
    git_url: Option<String>,
    mirror: Option<mirror::Mirror>,
    refs_written: usize,
    refs_already: usize,
    branches: usize,
    tags: usize,
    refs_diverged: Vec<(String, String, String)>,
    changes: changes::Published,
    proofs: usize,
    proofs_already: usize,
    dropped: Vec<Dropping>,
    calls: usize,
    rate: String,
    verified: objects::Verified,
    object_form: &'static str,
    object_detail: Option<String>,
    objects_moved: usize,
    object_bytes: u64,
    manifest_ref: Option<String>,
    dry_run: bool,
}

#[cfg(feature = "hosts-github")]
impl Run {
    /// Open both ends, the identity, and the journal.
    fn open(options: &Options, args: &Args) -> Result<Run, CliError> {
        use gitiup_host::Config as HostConfig;

        let config =
            HostConfig::load_default().map_err(|e| CliError::io(format!("gitiup.toml: {e}")))?;
        let github = open_source(&options.from, &config)?;
        let from = describe_source(&github);
        let side = crate::fetch::open_destination(&options.to, &config)?;
        let keystore = crate::participant::keystore()?;
        let key = crate::participant::signing_key(args, &keystore).map_err(|e| {
            CliError::refused(
                e.message,
                "a transcribed change record is signed by whoever runs the migration: `gitiup \
                 key gen` makes a key and --key <name> chooses one; there is no unsigned \
                 record for a reader to refuse later",
            )
        })?;
        // Read the key's own account of itself in a block, so the borrow ends before the
        // key itself moves into the run.
        let (key_id, principal) = {
            let record = key.record();
            let principal = keystore
                .config
                .identity
                .handle
                .clone()
                .or_else(|| record.comment.clone())
                .unwrap_or_else(|| record.name.clone());
            (record.key_id.clone(), principal)
        };
        let principal: String = principal
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect();
        let slug = journal::slug(&from, &side.what);
        let path = options
            .journal
            .clone()
            .unwrap_or_else(|| journal::default_path(&slug));
        let existing = if options.restart {
            None
        } else {
            journal::Journal::load(&path).map_err(CliError::io)?
        };
        let resumed = existing.as_ref().map_or(0, |seen| seen.done.len());
        let mut journal = existing.unwrap_or_else(|| {
            journal::Journal::new(
                format!("{from} → {}", side.what),
                slug.clone(),
                from.clone(),
                side.what.clone(),
                gitiup_attest::TimeUs::now().as_us(),
            )
        });
        journal.path = Some(path.display().to_string());
        Ok(Run {
            from,
            to_what: side.what,
            to: side.host,
            github,
            key,
            key_id,
            principal,
            actor: gitiup_host::Actor::from_env(),
            journal,
            path,
            resumed,
            halted: None,
            history: "not asked for".to_string(),
            git_url: None,
            mirror: None,
            refs_written: 0,
            refs_already: 0,
            branches: 0,
            tags: 0,
            refs_diverged: Vec::new(),
            changes: changes::Published::default(),
            proofs: 0,
            proofs_already: 0,
            dropped: Vec::new(),
            calls: 0,
            rate: "no calls yet".to_string(),
            verified: objects::Verified::default(),
            object_form: "",
            object_detail: None,
            objects_moved: 0,
            object_bytes: 0,
            manifest_ref: None,
            dry_run: options.dry_run,
        })
    }

    /// The plan, in the order that makes an interruption harmless.
    ///
    /// Read the forge; move the metadata; move the objects; move the proofs; then check what
    /// the proofs are about. Bytes before advertisement holds inside every step too (objects
    /// before the ref that names them, a record before the ref advertising it), so any
    /// interruption leaves a store that advertises *less* than it holds, never more.
    fn run(&mut self, options: &Options) -> Result<u8, CliError> {
        let want = gitiup_host_github::migrate::Want {
            branches: options.branches,
            tags: options.tags,
            pulls: options.pulls,
            evidence: options.with_proofs,
        };
        let inventory =
            match gitiup_host_github::migrate::inventory(&self.github, &want, options.rate_floor) {
                Ok(found) => found,
                Err(why) if gitiup_host_github::migrate::is_rate_stop(&why) => {
                    self.halted = Some(gitiup_host_github::migrate::RATE_TOKEN.to_string());
                    return self.finish(options);
                }
                Err(why) => return Err(host_said(&why)),
            };
        self.calls += inventory.calls;
        self.rate = inventory.rate.summary();
        for dropped in &inventory.dropped {
            self.dropped.push(Dropping::of(
                dropped.token,
                dropped.class,
                &dropped.name,
                &dropped.detail,
            ));
        }

        // Which check runs can honestly become attestations, decided once, here. The set of
        // commits they are about is needed *before* the objects move, because those are the
        // commits the destination has to be able to name afterwards.
        let mut carried: Vec<(String, String, Vec<u8>)> = Vec::new();
        let mut proof_commits: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for evidence in &inventory.evidence {
            match evidence.reconstructed() {
                Ok(bytes) => {
                    proof_commits.insert(evidence.subject.hex().to_lowercase());
                    carried.push((
                        evidence.subject.hex().to_lowercase(),
                        evidence.name.clone(),
                        bytes.to_vec(),
                    ));
                }
                Err((token, detail)) => self.dropped.push(Dropping::of(
                    token,
                    "check-run",
                    format!("{} @ {}", evidence.name, evidence.subject.short_default()),
                    detail,
                )),
            }
        }

        self.history_step(options, &inventory)?;
        self.refs_step(options, &inventory, &proof_commits)?;
        self.changes_step(options, &inventory, &proof_commits)?;
        self.proofs_step(options, &carried)?;
        self.verify_step(options, &proof_commits)?;
        self.journal.finished = self.halted.is_none();
        self.finish(options)
    }

    /// Fetch the history into the mirror, or say why it was not fetched.
    fn history_step(
        &mut self,
        options: &Options,
        inventory: &gitiup_host_github::migrate::Inventory,
    ) -> Result<(), CliError> {
        use gitiup_host_github::migrate as fgm;

        if !options.history {
            self.history = format!(
                "{HISTORY_NOT_ASKED}: --no-history, so no git objects moved and a proof's \
                 commit cannot be re-hashed here"
            );
            return Ok(());
        }
        // Check the budget before a long clone: the clone is git's business, but the listings
        // after it are the forge's, and running out mid-history is the expensive place to
        // find it out.
        if let Err(why) = fgm::check_budget(&self.github, options.rate_floor) {
            if fgm::is_rate_stop(&why) {
                self.halted = Some(fgm::RATE_TOKEN.to_string());
                return Ok(());
            }
            return Err(host_said(&why));
        }
        let url = options
            .git_url
            .clone()
            .or_else(|| fgm::clone_url(&self.github));
        let Some(url) = url else {
            self.history = format!(
                "{HISTORY_NO_URL}: neither --git-url nor the forge named a git endpoint, so \
                 only refs, changes and proofs moved"
            );
            return Ok(());
        };
        self.git_url = Some(url.clone());
        self.journal.git_url = Some(url.clone());
        let cache = options.cache.clone().unwrap_or_else(|| {
            PathBuf::from(".gitiup")
                .join("migrate")
                .join(format!("{}.git", self.journal.slug))
        });
        if options.dry_run {
            self.history = format!(
                "planned: {url} → {} (dry run: nothing fetched)",
                cache.display()
            );
            return Ok(());
        }
        let opened = mirror::Mirror::open(&cache, &url)
            .map_err(|e| CliError::io(format!("mirror {}: {e}", cache.display())))?;
        match opened.fetch() {
            Ok(()) => {
                self.history = format!(
                    "{url} → {} ({} ref(s) mirrored)",
                    cache.display(),
                    opened.refs().map(|held| held.len()).unwrap_or(0)
                );
                self.mirror = Some(opened);
            }
            Err(why) => {
                // Not fatal, and said plainly: the mirror keeps what it got, the journal keeps
                // what finished, and the next run asks for the rest. Refs and proofs can still
                // move; only the re-hash of a proof's commit is then short of bytes.
                self.history = format!(
                    "{HISTORY_FAILED}: `git fetch {url}` said {why} — the mirror keeps \
                     what it did take and the next run asks for the remainder"
                );
                self.dropped.push(Dropping::of(
                    HISTORY_FAILED,
                    "history",
                    url,
                    why.to_string(),
                ));
                self.mirror = Some(opened);
            }
        }
        let _ = inventory;
        Ok(())
    }

    /// Move the refs, and the history each one names.
    fn refs_step(
        &mut self,
        options: &Options,
        inventory: &gitiup_host_github::migrate::Inventory,
        proof_commits: &std::collections::BTreeSet<String>,
    ) -> Result<(), CliError> {
        use gitiup_host::{Actor, RefName};

        let actor = match &options.actor {
            Some(name) => Actor::new(name).map_err(|e| CliError::usage(format!("--actor: {e}")))?,
            None => Actor::from_env(),
        };
        self.actor = actor.clone();
        for reference in inventory.refs() {
            let branch = reference.name.starts_with("refs/heads");
            if self
                .journal
                .done(&journal::Journal::ref_key(&reference.name))
            {
                self.refs_already += 1;
                continue;
            }
            let bare = reference
                .name
                .strip_prefix(if branch { "refs/heads/" } else { "refs/tags/" })
                .ok_or_else(|| {
                    CliError::io(format!("the forge named '{}' strangely", reference.name))
                })?;
            let name = if branch {
                RefName::branch(bare)
            } else {
                RefName::tag(bare)
            }
            .map_err(|e| CliError::io(format!("the forge named '{}': {e}", reference.name)))?;
            if options.dry_run {
                self.refs_written += 1;
                if branch {
                    self.branches += 1;
                } else {
                    self.tags += 1;
                }
                continue;
            }
            // Objects first, then the ref that names them: a store must never advertise a
            // commit it cannot back (ADR-0005 D8 rule 1), and on a git destination the push of
            // the ref is what carries the objects anyway.
            let tip = reference.oid.hex().to_lowercase();
            if options.history {
                self.objects_for(&tip, proof_commits)?;
            }
            if !self.store_holds(&tip)? {
                self.dropped.push(Dropping::of(
                    REF_NO_HISTORY,
                    "ref",
                    name.as_str().to_string(),
                    "this store cannot show it holds the commit the forge names, and a ref to \
                     a commit the store cannot back is a lie (ADR-0005 D8): drop --no-history \
                     to move the history with the ref",
                ));
                continue;
            }
            match write_ref(&*self.to, &name, &reference.oid, &actor, "migrated")? {
                RefMove::Written => {
                    self.refs_written += 1;
                    if branch {
                        self.branches += 1;
                    } else {
                        self.tags += 1;
                    }
                }
                RefMove::Already => {
                    self.refs_already += 1;
                    if branch {
                        self.branches += 1;
                    } else {
                        self.tags += 1;
                    }
                }
                RefMove::Diverged { found } => self.refs_diverged.push((
                    name.as_str().to_string(),
                    found.hex(),
                    reference.oid.hex(),
                )),
            }
            self.journal.note_ref(name.as_str(), &reference.oid.hex());
            self.journal
                .mark(&journal::Journal::ref_key(&reference.name));
            self.checkpoint();
        }
        Ok(())
    }

    /// Whether this store can produce this commit's bytes itself.
    ///
    /// Either this run (or an earlier one of the same migration) put them there, or the
    /// store is a git repository that will hand the object over when asked. A bucket that
    /// was filled by some other tool cannot be asked, so it answers no, and the honest
    /// outcome is a refused ref rather than a pointer into nowhere.
    fn store_holds(&self, tip: &str) -> Result<bool, CliError> {
        if self.journal.delivered.iter().any(|held| held == tip) {
            return Ok(true);
        }
        if let Some(mirror) = &self.mirror
            && mirror.holds(tip)
        {
            return Ok(true);
        }
        Ok(objects::holds(&*self.to, tip))
    }

    /// Hand one tip's objects to the destination, unless they went already.
    fn objects_for(
        &mut self,
        tip: &str,
        proof_commits: &std::collections::BTreeSet<String>,
    ) -> Result<(), CliError> {
        let Some(mirror) = &self.mirror else {
            return Ok(());
        };
        if self.journal.done(&journal::Journal::object_key(tip)) || !mirror.holds(tip) {
            return Ok(());
        }
        let delivered = self.journal.delivered.clone();
        let moved = objects::move_objects(
            mirror,
            &*self.to,
            tip,
            &delivered,
            proof_commits,
            &mut self.journal,
        )
        .map_err(|e| CliError::io(format!("moving the history of {tip}: {e}")))?;
        self.objects_moved += moved.objects;
        self.object_bytes += moved.bytes;
        self.journal.note_objects(tip, moved.objects, moved.bytes);
        // Several ref tips each move a unit of objects; the form is a fact about the run,
        // so the first unit that moved something is the one that describes it.
        if self.object_form.is_empty() || self.object_form == "nothing-new" {
            self.object_form = moved.form;
            self.object_detail = moved.detail;
        }
        self.journal.mark(&journal::Journal::object_key(tip));
        Ok(())
    }

    /// Transcribe every open and merged pull request into a change.
    fn changes_step(
        &mut self,
        options: &Options,
        inventory: &gitiup_host_github::migrate::Inventory,
        proof_commits: &std::collections::BTreeSet<String>,
    ) -> Result<(), CliError> {
        for pull in &inventory.pulls {
            let key = journal::Journal::pull_key(pull.number);
            if self.journal.done(&key) {
                self.changes.already += 1;
                continue;
            }
            if options.dry_run {
                self.changes.changes += 1;
                if pull.state == gitiup_host_github::ChangeState::Merged
                    && pull.merge_commit.is_some()
                {
                    self.changes.merges += 1;
                }
                continue;
            }
            self.objects_for(&pull.head.hex().to_lowercase(), proof_commits)?;
            if let Some(merge) = &pull.merge_commit {
                self.objects_for(&merge.hex().to_lowercase(), proof_commits)?;
            }
            match changes::publish(
                &*self.to,
                pull,
                &self.key,
                &self.key_id,
                &self.principal,
                &self.actor,
            ) {
                Ok((already, note)) => {
                    if already {
                        self.changes.already += 1;
                    } else {
                        self.changes.changes += 1;
                        if pull.state == gitiup_host_github::ChangeState::Merged && note.is_none() {
                            self.changes.merges += 1;
                        }
                    }
                    if let Some(note) = note {
                        self.dropped.push(note);
                    }
                    self.journal.mark(&key);
                    self.checkpoint();
                }
                Err(why) => self.changes.refused.push(Dropping::of(
                    CHANGE_REFUSED,
                    "pull",
                    format!("#{}", pull.number),
                    why.message,
                )),
            }
        }
        self.journal.counters.changes_published = self.changes.changes;
        self.journal.counters.merges_published = self.changes.merges;
        Ok(())
    }

    /// File the check-run evidence that could be rebuilt.
    fn proofs_step(
        &mut self,
        options: &Options,
        carried: &[(String, String, Vec<u8>)],
    ) -> Result<(), CliError> {
        use gitiup_host::{Oid, attest};

        for (subject, name, bytes) in carried {
            let digest = Oid::hash_bytes(bytes);
            let key = journal::Journal::proof_key(&digest.hex());
            if self.journal.done(&key) {
                self.proofs_already += 1;
                continue;
            }
            if options.dry_run {
                self.proofs += 1;
                continue;
            }
            let want = Oid::from_hex(subject)
                .map_err(|e| CliError::io(format!("the forge named '{subject}': {e}")))?;
            match attest::publish(&*self.to, &want, bytes, self.actor.clone()) {
                Ok(published) => {
                    if published.already {
                        self.proofs_already += 1;
                    } else {
                        self.proofs += 1;
                    }
                    self.journal
                        .note_proof(&digest.hex(), subject, published.already);
                    self.journal.mark(&key);
                    self.checkpoint();
                }
                Err(why) => self.dropped.push(Dropping::of(
                    "proof_refused",
                    "check-run",
                    format!("{name} @ {}", short(subject)),
                    format!(
                        "the copy is the document it claims (it re-hashed to its own digest), \
                         but the store refused to file it: {why}"
                    ),
                )),
            }
        }
        self.journal.counters.proofs_carried = self.proofs;
        self.journal.counters.proofs_already = self.proofs_already;
        Ok(())
    }

    /// Re-hash every proof-bearing commit out of the destination's own bytes.
    fn verify_step(
        &mut self,
        options: &Options,
        proof_commits: &std::collections::BTreeSet<String>,
    ) -> Result<(), CliError> {
        if options.dry_run {
            self.verified = objects::Verified {
                with_proof: proof_commits.len(),
                basis: "claimed_at_us",
                ..Default::default()
            };
            return Ok(());
        }
        let scratch = self.path.with_extension("verify");
        self.verified = objects::verify(&*self.to, &self.journal, proof_commits, &scratch)
            .map_err(|e| CliError::io(format!("verifying the copy: {e}")))?;
        if !self.verified.faithful() {
            self.journal.note_dropped(Dropping::of(
                "verify_mismatch",
                "commit",
                self.verified
                    .mismatched
                    .iter()
                    .map(|(want, got)| format!("{want} → {got}"))
                    .collect::<Vec<String>>()
                    .join(", "),
                "the bytes this store holds do not hash to the commit its proof is about",
            ));
        }
        Ok(())
    }

    /// Write the journal, file the manifest, and produce the report.
    fn finish(&mut self, options: &Options) -> Result<u8, CliError> {
        self.journal.dropped = self.dropped.clone();
        self.journal.counters.changes_published = self.changes.changes;
        self.journal.counters.merges_published = self.changes.merges;
        self.journal.counters.proofs_carried = self.proofs;
        self.journal.counters.proofs_already = self.proofs_already;
        self.journal.updated_us = gitiup_attest::TimeUs::now().as_us();
        if !options.dry_run {
            self.journal
                .save()
                .map_err(|e| CliError::io(format!("journal {}: {e}", self.path.display())))?;
            self.manifest_step()?;
        }
        Ok(self.code(options))
    }

    /// File the account of this run in the store it built, and advertise it.
    ///
    /// `refs/gitiup/migrate/<slug>` is provenance: the same class of fact as the
    /// `kv/import/<digest>` records `gitiup fetch` writes. It answers *how did this get here*
    /// from inside the store, without anybody having to keep the laptop that ran the command,
    /// and it is local by construction (ADR-0005 D2) and grants nothing.
    fn manifest_step(&mut self) -> Result<(), CliError> {
        use gitiup_host::{Namespace, RefName, RefUpdate};

        let manifest = self.journal.manifest();
        let namespace = Namespace::const_new("migrate");
        let digest = match self.to.put_cas(&namespace, manifest.as_bytes()) {
            Ok(digest) => digest,
            Err(why) => {
                self.dropped.push(Dropping::of(
                    "manifest_refused",
                    "record",
                    self.journal.slug.clone(),
                    format!("the store would not hold the account of this run: {why}"),
                ));
                return Ok(());
            }
        };
        let name = RefName::gitiup(&format!("migrate/{}", self.journal.slug))
            .map_err(|e| CliError::io(format!("manifest ref: {e}")))?;
        let update = RefUpdate::create(name.clone(), digest)
            .with_actor(self.actor.clone())
            .with_message(format!("migrated from {}", self.from));
        match self.to.update_ref_cas(&update) {
            Ok(_) => {
                self.manifest_ref = Some(format!("{} → {}", name.as_str(), digest.short_default()));
            }
            Err(why) => {
                if let Ok(Some(_)) = self.to.get_ref(&name) {
                    // Somebody (this run, an earlier one) already advertised it: the record
                    // is create-only, so the ref standing means the account is there.
                    self.manifest_ref =
                        Some(format!("{} → {}", name.as_str(), digest.short_default()));
                } else {
                    self.dropped.push(Dropping::of(
                        "manifest_refused",
                        "record",
                        name.as_str().to_string(),
                        format!(
                            "the account was filed at {} and the ref could not be written: \
                             {why}",
                            digest.short_default()
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Save the journal after each finished step, so an interruption loses at most the step
    /// that was in flight.
    fn checkpoint(&mut self) {
        if self.dry_run {
            return;
        }
        self.journal.updated_us = gitiup_attest::TimeUs::now().as_us();
        // A journal that will not save is worth less than a run that stops on it: the store is
        // still idempotent, and the journal is only ever a speed-up.
        let _ = self.journal.save();
    }

    /// The exit code this run deserves.
    fn code(&self, options: &Options) -> u8 {
        // Bytes that are not the bytes their name promises are the one outcome a migration
        // must never report as success.
        if !self.verified.faithful() {
            return 8;
        }
        if self.halted.is_some() || !self.refs_diverged.is_empty() {
            return 6;
        }
        if options.strict
            && (!self.dropped.is_empty()
                || !self.changes.refused.is_empty()
                || self.verified.rehashed < self.verified.with_proof)
        {
            return 6;
        }
        0
    }
}
/// The report, in the shape `gitiup fetch`'s is: one fact per line, machine-readable in
/// `--json`, and every refusal in it by name.
#[cfg(feature = "hosts-github")]
impl Run {
    /// The lines a human reads.
    fn report(&self, options: &Options) -> Vec<String> {
        let note = if options.dry_run {
            "  (dry run: nothing written)".to_string()
        } else if self.resumed > 0 {
            format!("  (resumed: {} step(s) already done)", self.resumed)
        } else {
            String::new()
        };
        let mut out = vec![format!(
            "migrate        {} → {}{}",
            self.from, self.to_what, note
        )];
        out.push(format!(
            "refs           {} written, {} already, {} diverged ({} branch(es), {} tag(s))",
            self.refs_written,
            self.refs_already,
            self.refs_diverged.len(),
            self.branches,
            self.tags
        ));
        out.push(format!(
            "changes        {} published, {} already · {} merge record(s){}",
            self.changes.changes,
            self.changes.already,
            self.changes.merges,
            if self.changes.refused.is_empty() {
                String::new()
            } else {
                format!(", {} refused", self.changes.refused.len())
            }
        ));
        out.push(format!("history        {}", self.history_lines()));
        out.push(format!(
            "proofs         {} carried, {} already, {} dropped",
            self.proofs,
            self.proofs_already,
            self.dropped.len()
        ));
        out.push(format!("verify         {}", self.verified.line()));
        for (name, dest, want) in &self.refs_diverged {
            out.push(format!(
                "  {REF_DIVERGED}  {name}  this store holds {}, the forge has {}",
                short(dest),
                short(want)
            ));
        }
        // The same refusals, tallied: the list is for reading one at a time, the tally is
        // for noticing that the same thing refused twelve times is one decision.
        let tally = self.journal.dropped_by();
        if !tally.is_empty() {
            out.push(format!(
                "refusals       {}",
                tally
                    .iter()
                    .map(|(token, count)| format!("{count}× {token}"))
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }
        for dropped in self.dropped.iter().take(20) {
            out.push(format!("  {}", dropped.line()));
        }
        if self.dropped.len() > 20 {
            out.push(format!(
                "  … and {} more (--json lists every one)",
                self.dropped.len() - 20
            ));
        }
        for refused in self.changes.refused.iter().take(10) {
            out.push(format!("  {}", refused.line()));
        }
        out.push(format!(
            "forge          {} call(s) · {}",
            self.calls, self.rate
        ));
        out.push(format!(
            "journal        {}{}",
            self.path.display(),
            if options.dry_run {
                " (not written: --dry-run)"
            } else {
                ""
            }
        ));
        if let Some(manifest) = &self.manifest_ref {
            out.push(format!("account        {manifest}"));
        }
        if let Some(token) = &self.halted {
            out.push(format!(
                "halted         {token} — re-run the same command to continue"
            ));
        }
        // Exit 6 is not a shrug: the run that did not finish has to name itself incomplete,
        // in the same token vocabulary every other refusal here uses.
        let code = self.code(options);
        out.push(format!(
            "code           {}{}",
            code,
            if code == 6 {
                format!(" ({INCOMPLETE})")
            } else {
                String::new()
            }
        ));
        out
    }

    /// What happened to the git objects, in one line, counted over the whole run and not
    /// over whichever ref tip moved last.
    fn history_lines(&self) -> String {
        if self.object_form.is_empty() {
            return self.history.clone();
        }
        let moved = objects::ObjectMove {
            objects: self.objects_moved,
            bytes: self.object_bytes,
            form: self.object_form,
            detail: self.object_detail.clone(),
        };
        format!("{} · {}", moved.phrase(), self.history)
    }

    /// The same report as data.
    fn json(&self, options: &Options) -> serde_json::Value {
        serde_json::json!({
            "verb": "migrate repo",
            "from": self.from,
            "to": self.to_what,
            "dry_run": options.dry_run,
            "resumed_steps": self.resumed,
            "scope": {
                "branches": self.branches,
                "tags": self.tags,
                "pulls": self.changes.changes + self.changes.already,
                "evidence": self.proofs + self.proofs_already,
            },
            "refs": {
                "written": self.refs_written,
                "already": self.refs_already,
                "diverged": self.refs_diverged,
                "branches": self.branches,
                "tags": self.tags,
            },
            "changes": {
                "published": self.changes.changes,
                "already": self.changes.already,
                "merges": self.changes.merges,
                "refused": dropped_json(&self.changes.refused),
            },
            "history": {
                "git_url": self.git_url,
                "detail": self.history,
                "objects": self.objects_moved,
                "bytes": self.object_bytes,
                "objects_total": self.journal.counters.objects,
                "form": self.object_form,
                "note": &self.object_detail,
            },
            "proofs": {
                "carried": self.proofs,
                "already": self.proofs_already,
            },
            // Everything that did not come, in one list: a script should not have to know
            // which step refused it.
            "dropped": dropped_json(&self.dropped),
            "verify": self.verified.json(),
            "journal": self.path.display().to_string(),
            "account": self.manifest_ref,
            "forge": { "calls": self.calls, "rate": self.rate },
            "halted": self.halted,
            "incomplete": (self.code(options) == 6).then_some(INCOMPLETE),
            "trust": "none",
            "code": self.code(options),
        })
    }
}

/// The refusals as data, in the shape a refusal has in every report: token, kind, name,
/// detail.
fn dropped_json(list: &[Dropping]) -> Vec<serde_json::Value> {
    list.iter()
        .map(Dropping::json)
        .collect::<Vec<serde_json::Value>>()
}

/// What a ref write did.
#[cfg(feature = "hosts-github")]
enum RefMove {
    Written,
    Already,
    Diverged { found: gitiup_host::Oid },
}

/// Write one ordinary ref, create-only, never over an oid this run did not put there.
///
/// A destination that already has `refs/heads/main` at a different commit is not a mistake to
/// paper over: two histories are claiming one name, and the operator has to choose. That is
/// why this is a report and a refusal, and why `--restart` is not the answer to it.
#[cfg(feature = "hosts-github")]
fn write_ref(
    to: &dyn gitiup_host::Host,
    name: &gitiup_host::RefName,
    oid: &gitiup_host::Oid,
    actor: &gitiup_host::Actor,
    message: &str,
) -> Result<RefMove, CliError> {
    use gitiup_host::{HostErrorKind, RefUpdate};

    if let Some(current) = to
        .get_ref(name)
        .map_err(|e| CliError::io(format!("reading {name}: {e}")))?
    {
        if current.oid == *oid {
            return Ok(RefMove::Already);
        }
        return Ok(RefMove::Diverged { found: current.oid });
    }
    match to.update_ref_cas(
        &RefUpdate::create(name.clone(), *oid)
            .with_actor(actor.clone())
            .with_message(message),
    ) {
        Ok(_) => Ok(RefMove::Written),
        Err(why) if why.kind() == HostErrorKind::Conflict => {
            let found = to
                .get_ref(name)
                .map_err(|e| CliError::io(format!("re-reading {name}: {e}")))?;
            Ok(match found {
                Some(found) if found.oid == *oid => RefMove::Already,
                Some(found) => RefMove::Diverged { found: found.oid },
                None => return Err(CliError::io(format!("{name}: {why}"))),
            })
        }
        Err(why) => Err(CliError::io(format!("writing {name}: {why}"))),
    }
}

/// A short oid for a report line.
#[cfg(feature = "hosts-github")]
fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

/// A store or forge refusal, at the code the library already decided for it.
#[cfg(feature = "hosts-github")]
fn host_said(error: &gitiup_host::HostError) -> CliError {
    CliError::scored(
        error.exit_code(),
        error.message().to_string(),
        error.hint().map(str::to_string),
    )
}

#[cfg(feature = "hosts-github")]
fn describe_source(github: &gitiup_host_github::GitHubHost) -> String {
    let repo = github.repo();
    format!("github:{}/{}", repo.owner, repo.repo)
}

/// Open the forge being left.
#[cfg(feature = "hosts-github")]
fn open_source(
    spelled: &str,
    config: &Option<(PathBuf, gitiup_host::Config)>,
) -> Result<gitiup_host_github::GitHubHost, CliError> {
    let remote = forge_remote(spelled, config)?;
    let transport = gitiup_host_github::curl::default_transport(&remote)
        .map_err(|e| CliError::io(format!("--from '{spelled}': {e}")))?;
    let profile = config
        .as_ref()
        .and_then(|(_path, config)| config.credential_profile(&remote));
    gitiup_host_github::GitHubHost::with_transport(&remote, transport, profile).map_err(|e| {
        CliError::refused(
            format!("--from '{spelled}': {e}"),
            "a forge source is `github:<owner>/<repo>`, a configured [[remote]] with \
             host-type = \"github\", or a forge URL",
        )
    })
}

/// Spell the source as a remote, in the three shapes a person has.
#[cfg(feature = "hosts-github")]
fn forge_remote(
    spelled: &str,
    config: &Option<(PathBuf, gitiup_host::Config)>,
) -> Result<gitiup_host::RemoteConfig, CliError> {
    let text = spelled.trim();
    if let Some(rest) = text.strip_prefix("github:") {
        let path = rest.trim_matches('/');
        if path.split('/').count() != 2 {
            return Err(CliError::usage(format!(
                "--from 'github:{path}' is not owner/repo"
            )));
        }
        let mut remote =
            gitiup_host::RemoteConfig::new("migrate-from", &format!("https://github.com/{path}"))
                .map_err(|e| CliError::usage(format!("--from: {e}")))?;
        remote
            .options
            .insert("host-type".to_string(), "github".to_string());
        return Ok(remote);
    }
    if text.contains("://") {
        let mut remote = gitiup_host::RemoteConfig::new("migrate-from", text)
            .map_err(|e| CliError::usage(format!("--from: {e}")))?;
        remote
            .options
            .insert("host-type".to_string(), "github".to_string());
        return Ok(remote);
    }
    let Some((_path, config)) = config else {
        return Err(CliError::refused(
            format!(
                "--from '{text}' is not a `github:<owner>/<repo>` or a URL, and there is no \
                 gitiup.toml to say it is a remote"
            ),
            "name it `github:owner/repo`, or write the [[remote]]",
        ));
    };
    config.remote(text).cloned().map_err(|e| {
        CliError::refused(
            format!("gitiup.toml: {e}"),
            "name a configured remote, or `github:<owner>/<repo>`",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                MIGRATE_HELP.contains(flag),
                "{flag} is accepted and undocumented"
            );
        }
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(MIGRATE_HELP.contains(code), "exit {code} undocumented");
        }
        assert!(MIGRATE_HELP.contains("gitiup migrate repo"));
    }

    #[test]
    fn no_flag_here_can_be_read_as_trust() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            let name = flag.to_ascii_lowercase();
            assert!(
                !name.contains("trust") && !name.contains("verify") && !name.contains("accept"),
                "`{flag}` reads like a trust decision, which ADR-0005 D3 forbids this command \
                 from having"
            );
        }
        assert!(
            MIGRATE_HELP.contains("MANUFACTURES TRUST"),
            "the help has to say what the flag list refuses"
        );
    }

    fn parse(args: &[&str]) -> Result<Options, CliError> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let parsed = Args::parse_with(&owned, VALUED, SWITCHES)?;
        Options::parse(&parsed)
    }

    #[test]
    fn both_ends_are_required_and_the_scope_flags_subtract() {
        assert!(parse(&[]).unwrap_err().message.contains("--from"));
        assert!(
            parse(&["--from", "github:a/b"])
                .unwrap_err()
                .message
                .contains("--to")
        );
        let options = parse(&[
            "--from",
            "github:a/b",
            "--to",
            "./store",
            "--no-tags",
            "--with-proofs",
            "--rate-floor",
            "200",
        ])
        .expect("parses");
        assert_eq!(options.from, "github:a/b");
        assert_eq!(options.to, "./store");
        assert!(!options.tags);
        assert!(options.branches && options.pulls && options.history);
        assert!(options.with_proofs);
        assert_eq!(options.rate_floor, 200);
        assert!(
            Options::parse(&Args::default())
                .unwrap_err()
                .message
                .contains("--from")
        );
    }

    #[test]
    fn a_rate_floor_is_a_count() {
        assert!(parse(&["--from", "a/b", "--to", "c", "--rate-floor", "plenty"]).is_err());
        assert_eq!(
            parse(&["--from", "a/b", "--to", "c"])
                .expect("defaults")
                .rate_floor,
            50
        );
    }
}

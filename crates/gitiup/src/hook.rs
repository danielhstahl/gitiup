//! `gitiup hook` — the gate that runs where the refs land.
//!
//! Everything else in this crate answers the question *before* a ref moves, from
//! wherever you happen to be standing: `gitiup verify change` asks about a change,
//! `gitiup policy check` asks about a commit and a ref. Neither of them can stop a
//! branch from moving. Only something running on the box that receives the push, after
//! the objects have arrived and before the refs are written, can say *no* in a way that
//! leaves the repository untouched — and git has exactly one such place: the
//! `pre-receive` hook.
//!
//! ```text
//! gitiup hook install pre-receive --repo /srv/git/repo.git
//! ```
//!
//! # What the gate refuses
//!
//! The hook reads `<old-oid> <new-oid> <ref>` lines from stdin, one per ref the push
//! would move, and refuses the whole push if any update to `refs/heads/**` names a new
//! head that the policy published in *that repository* does not accept. A refused push
//! prints the same report `gitiup policy check` and `gitiup verify change` print — the
//! same [`crate::policy_ask::Explanation`], one per refused ref, sent through the
//! transport to whoever pushed — and no ref moves, because git writes refs only after
//! every `pre-receive` hook has exited 0.
//!
//! # What it deliberately does not refuse
//!
//! `refs/changes/**`, `refs/attestations/**` and `refs/gitiup/**` are open to anyone the
//! git transport admits. That asymmetry is the design and not a gap in it: a proposal
//! and the proof offered for it cost nothing to make and are checked when read, so
//! filing them must never need permission; a branch is what everybody else builds on,
//! so it moves only on evidence. [ADR-0004 D5](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)
//! makes it a format rule rather than a local one — a policy whose `protects` reaches
//! outside `refs/heads/**` cannot be published at all — and the rule is stated in the
//! hook's own `--help` ([`PRE_RECEIVE_HELP`]) because a gate whose exceptions are
//! undocumented gets worked around instead of fixed.
//!
//! # No override, and why that is the point
//!
//! The hook resolves the store-published policy and nothing else: no `--policy`, no
//! `$GITIUP_POLICY`, no `gitiup-policy.json` from a checkout, no built-in default
//! ([ADR-0004 D4](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md),
//! encoded as [`Question::published`]). A stranger with a clone must be able to reach
//! the verdict the box that accepted their push reached; an override in a hook script on
//! one machine would make that impossible to know. The one thing a repository has to
//! state out loud is *whose* signature on a policy it believes, so `hook install` records
//! those key ids, `hook status` prints them, and what they select is a signed document —
//! never a rule someone typed into a flag.
//!
//! # The one escape, and where it is shouted about
//!
//! `gitiup hook install pre-receive --repo … --no-proof-required` records a
//! per-repository opt-out. It is per-repository (the record lives in the repository's own
//! `info/gitiup/`, which pushing does not write) and it is loud: the hook says on every
//! push that it is not requiring proof, `gitiup hook status` prints it, and
//! `gitiup doctor --hooks` exits 6 over it. An opt-out that only its author could find
//! is how a policy stops being enforced without anybody deciding to stop enforcing it.
//!
//! # Where the state lives, and who can write it
//!
//! The script is `hooks/pre-receive` in the repository's git directory (wherever
//! `core.hooksPath` sends it, which git answers, not us); its record is
//! `info/gitiup/pre-receive.json` beside it, and the plain-git host's mirror — the object
//! database the gate reads — defaults to `info/gitiup/mirror`. Nothing here is a ref,
//! which is deliberate: `refs/gitiup/**` is writable by anyone the transport admits, and
//! a gate whose opt-out switch could be flipped by a push is not a gate. Only someone
//! with a shell on the box can change what this hook does, which is exactly the trust
//! boundary a `pre-receive` hook sits on.
//!
//! # Failing closed
//!
//! No record, no policy, no trust root, no `gitiup` binary, unreachable store, a ref
//! deleted out from under a branch: every one of those is a refusal. 0 accepts; 6, 7 and
//! 8 refuse with a report (the same taxonomy every verdict in this crate uses); anything
//! else that goes wrong exits 3, which git also reads as "do not move the refs". A gate
//! that cannot answer is a gate that says no.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use gitiup_attest::{TimeUs, Trust};
use gitiup_host::RemoteConfig;
use gitiup_host::hosts::git::GitHost;
use gitiup_quorum::policy::{PolicyError, ResolvedPolicy};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::Opened;
use crate::policy as policy_cli;
use crate::policy_ask::Explanation;
use crate::verify::one_line;
use crate::verify_change::Question;

/// The only hook this build installs, and the default when none is named.
const PRE_RECEIVE: &str = "pre-receive";

/// The line that marks a script as ours. `gitiup hook uninstall` refuses to delete a
/// `hooks/pre-receive` that does not carry it, because that file belongs to somebody
/// else's workflow and silently replacing it would be our bug to keep.
const MARKER: &str = "gitiup:hook pre-receive v1";

/// What the record file is, in its own `record_type`, so a reader of
/// `info/gitiup/pre-receive.json` knows what it is holding.
const RECORD: &str = "gitiup-hook-1";

/// The refs the gate exists to guard.
const GUARDED: &str = "refs/heads/**";

/// The namespaces every contributor may write, listed so every report can name them.
const OPEN_REFS: &[&str] = &["refs/changes/**", "refs/attestations/**", "refs/gitiup/**"];

/// `gitiup hook help`.
pub const HOOK_HELP: &str = "\
gitiup hook — refuse an unproven ref update where the refs actually land

USAGE:
    gitiup hook install pre-receive --repo <path> [OPTIONS]
    gitiup hook uninstall pre-receive --repo <path> [OPTIONS]
    gitiup hook status    [pre-receive] [--repo <path>] [--json]
    gitiup hook run       [pre-receive] [--repo <path>] [--json]   (run by git)

A repository is where a ref either moves or does not, so that is where the rule has to
be enforced. `gitiup verify change` and `gitiup policy check` answer the same question
from wherever you stand; this command puts the answer in front of the ref.

INSTALL:
    --repo <path>              the repository to gate (bare or not; its git directory is
                               what gets the hook)
    --no-proof-required        install the gate switched OFF (see OPT OUT below)
    --trust <key|id>           whose signature on a policy this repository will believe;
                               repeatable. Default: this keystore's own keys, read now
    --program <path>           the `gitiup` the hook script runs (default: this binary)
    --mirror <dir>             where the plain-git host's object mirror lives
                               (default: <git-dir>/info/gitiup/mirror)
    --force                    replace a hooks/pre-receive gitiup did not write (the file
                               you are replacing is kept next to it, unchanged)
    --dry-run                  print exactly what would be written, write nothing
    --json                     the same report as data

UNINSTALL:
    Removes the script and the record — and refuses to remove a hook it did not write.

STATUS:
    Which policy is in force, which revision, cited by which digest, signed by which key,
    when it was read, what it gates, whose signature this box will believe, and whether
    proof is required at all. Exit 6 says a push that needs proof would be refused here
    *right now*, which is the question an operator actually asks.

OPT OUT:
    --no-proof-required keeps the hook installed and switches the gate off, so that the
    repository says out loud, on every push, that branches move here on trust alone. The
    same fact is printed by `gitiup hook status` and refused by `gitiup doctor --hooks`
    (exit 6). It is per-repository and it lives in the repository's own info/, which no
    push can write: flipping it takes a shell on the box, as it must.

THE GATE ITSELF — `gitiup hook run pre-receive --help` — states what it guards, what it
leaves open and why, and is the text the installed script carries.

Exit codes: install/uninstall/status: 0 ok · 2 usage · 3 I/O · 6 refused (a foreign hook
is in the way, nothing is installed, a gate that cannot gate). `hook run`: 0 accepts the
push · 6 refused · 7 a signature that does not verify · 8 bytes that are not what they
are named for · 3 the gate could not answer, which also refuses the push.

Try:
    gitiup hook install pre-receive --repo /srv/git/repo.git
    gitiup hook status --repo /srv/git/repo.git
    gitiup doctor --hooks --repo /srv/git/repo.git
    gitiup hook uninstall pre-receive --repo /srv/git/repo.git
";

/// The gate's own `--help`, installed as the script's header and printed by
/// `gitiup hook run pre-receive --help`.
///
/// The asymmetry is stated here on purpose: [ADR-0004 D5](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)
/// says a policy may only gate `refs/heads/**`, and a rule a reader can only find in an
/// ADR is a rule the next operator will work around.
pub const PRE_RECEIVE_HELP: &str = "\
gitiup hook run pre-receive — the gate git runs before any ref moves

This is what `gitiup hook install pre-receive --repo <path>` writes into
`hooks/pre-receive`, and what that script execs. git feeds it one line per ref the push
would move — `<old-oid> <new-oid> <ref>` — on stdin, with the objects already received
and no ref yet written. Exit 0 and the refs move; exit nonzero and the push is refused
whole, with everything printed here relayed to whoever pushed.

WHAT IT GUARDS

  refs/heads/**        GUARDED. The new head must have an attestation set in this
                       repository that satisfies the policy this repository *publishes*
                       at refs/gitiup/policy/current. A refusal prints the same report
                       `gitiup verify change` prints and the ref does not move.
                       Deleting a branch is refused too: a branch that vanishes is a
                       change to a guarded ref that nothing can prove.

WHAT IT LEAVES OPEN

  refs/changes/**        open — proposals
  refs/attestations/**   open — the proofs themselves, and filing one must never need
                         permission
  refs/gitiup/**         open — rosters, rounds, verdicts, published policies
  anything else          open — tags, notes, whatever else you keep

That asymmetry IS the design, not a hole in it, and it is worth the words because it
looks like a bug from outside. A proposal and its evidence cost nothing to offer and are
checked when read, so anyone the transport admits may write them: that is how a stranger
submits work to a repository they have no special rights in, and how a fork files the
proof that its own fix was verified. A branch is the opposite — it is what everyone else
builds on and merges — so it moves only when the owner's published policy is satisfied.
Gating `refs/changes/**` would lock out the very people this gate needs to receive work
from, which is why the format refuses to publish such a policy at all (ADR-0004 D5:
`protects` is only ever inside refs/heads/**). The gate guards what is TRUSTED and
nothing else.

WHAT THE GATE IS JUDGED BY

  refs/gitiup/policy/current, signed by a key this repository was told to believe,
  walked to the revision in force now. There is no --policy here, no $GITIUP_POLICY, no
  gitiup-policy.json from a checkout and no built-in default: an override in a hook
  script on one machine would destroy the only property a gate like this is worth
  anything for, which is that a stranger with a clone and this box reach the same
  verdict from the same bytes. Ask `gitiup hook status --repo <path>` for the policy in
  force, and `gitiup policy explain change <ID>` for the rules in words.

  If no policy can be resolved, every guarded push is REFUSED (exit 6,
  `no_policy_published`): a gate with nothing to go on does not wave things through.

ONE CAVEAT THAT BURNS PEOPLE

  A push that files the proof and moves the branch in the same transaction cannot be
  judged by that proof: refs move only after this hook returns, so the attestation ref
  is not there yet. Publish the proof first — `gitiup attest push --remote origin` — and
  push the branch after. This is not a limitation of the hook; it is what 'the proof had
  to be on record before the branch moved' means.

EVERY PROOF ON RECORD IS JUDGED

  If the store advertises two proofs for one head and the policy will not accept one of
  them, the push is refused even though the other would have carried it. That is the
  merge gate's own rule, applied here so this hook and `gitiup verify change` cannot give
  two answers about one set of bytes (ADR-0004 T15) — an untrusted signature on a commit
  is a fact about the commit, and it does not go away because a second key signed it too.
  The way to clear it is the open namespace again: `git push origin
  :refs/attestations/<subject>/<digest>` withdraws a proof exactly as filing one took an
  ordinary push.

OPT OUT

  `gitiup hook install pre-receive --repo <path> --no-proof-required` leaves this script
  installed with the gate off, and it says so on every push. `gitiup hook status` prints
  it and `gitiup doctor --hooks` exits 6 over it.

Exit codes: 0 accept · 6 refused (nothing proved it, no policy, no trust root, a deleted
branch) · 7 a signature that does not verify · 8 bytes that are not the bytes their name
promises · 3 the gate could not answer, which also refuses the push. Everything is
printed on stdout, because that is the stream git relays.

Try:
  ./hooks/pre-receive --help                       # the text you are reading
  printf '0000… <new> refs/heads/main\\n' | ./hooks/pre-receive
  gitiup policy check --commit <new> --ref refs/heads/main --store <repo.git>  # same answer
";

/// Valued flags for every `gitiup hook` subcommand.
const VALUED: &[&str] = &["--repo", "--program", "--mirror", "--trust"];

/// Switches for every `gitiup hook` subcommand.
const SWITCHES: &[&str] = &[
    "--json",
    "-j",
    "--quiet",
    "-q",
    "--no-proof-required",
    "--force",
    "--dry-run",
];

/// `gitiup hook …`
pub fn hook(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{HOOK_HELP}");
        return Ok(());
    };
    let rest = &args[1..];
    match sub {
        "help" | "--help" | "-h" => {
            print!("{HOOK_HELP}");
            Ok(())
        }
        "install" => install(&Args::parse_with(rest, VALUED, SWITCHES)?),
        "uninstall" => uninstall(&Args::parse_with(rest, VALUED, SWITCHES)?),
        "status" | "show" => status(&Args::parse_with(rest, VALUED, SWITCHES)?),
        "run" => {
            no_override(rest)?;
            run(&Args::parse_with(rest, VALUED, SWITCHES)?)
        }
        other => Err(CliError::usage(format!(
            "unknown `gitiup hook` command '{other}'; `gitiup hook help` lists install, \
             uninstall, status and run"
        ))),
    }
}

/// Which hook was named. There is one, and saying so beats guessing: `gitiup hook
/// install post-receive` would install nothing and promise something.
fn need_hook(args: &Args) -> Result<&'static str, CliError> {
    match args.positional.first().map(String::as_str) {
        None => Ok(PRE_RECEIVE),
        Some(text) if text == PRE_RECEIVE => Ok(PRE_RECEIVE),
        Some(other) => Err(CliError::usage(format!(
            "'{other}' is not a hook gitiup knows; it installs `{PRE_RECEIVE}`, the one place \
             a ref update can still be refused"
        ))),
    }
}

/// The flags the gate refuses to even parse.
///
/// [ADR-0004 D4](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)
/// is blunt about it: *the pre-receive hook takes no override* — not `--policy`, not
/// `$GITIUP_POLICY`, not a tree file, and not a `--trust` typed at push time either. It is
/// enforced here by refusing the flags rather than by ignoring them, because a flag that is
/// silently dropped is a flag somebody will later believe worked, and a gate whose rule
/// depends on a hook script on one machine is a gate a stranger cannot predict. The same
/// question with an operator's override is a different command, and the message says which.
fn no_override(args: &[String]) -> Result<(), CliError> {
    for flag in ["--policy", "--tree-file", "--trust"] {
        let given = args
            .iter()
            .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")));
        if given {
            return Err(CliError::usage(format!(
                "`gitiup hook run` takes no {flag}: the gate resolves the policy this \
                 repository publishes and nothing else, so that a stranger with a clone and \
                 the box that accepted the push reach the same verdict (ADR-0004 D4)"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the repository, and the store it is
// ---------------------------------------------------------------------------

/// Run `git` in `dir` and give back trimmed stdout.
///
/// The `GIT_*` scrub matters more here than it looks: a `pre-receive` hook runs with
/// `GIT_DIR` (often the relative `.`), `GIT_QUARANTINE_PATH` and friends set by
/// `git receive-pack`, and every git command the gate runs afterwards must be about the
/// repository *we were told about* rather than about whatever the transport had in its
/// environment. Same reason the installed script unsets them (see [`script_text`]).
fn git(dir: &Path, args: &[&str]) -> Result<String, CliError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_QUARANTINE_PATH")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = command
        .spawn()
        .map_err(|e| CliError::io(format!("running git {args:?}: {e}")))?
        .wait_with_output()
        .map_err(|e| CliError::io(format!("waiting for git {args:?}: {e}")))?;
    if !out.status.success() {
        return Err(CliError::refused(
            format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            "this command asks git where a repository's own directories are; the sentence \
             above is git's",
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The repository this command was pointed at, and the directories that follow from it.
///
/// The git directory is what gets the hook, and git itself is asked where that is
/// (`rev-parse --absolute-git-dir`), because discovering a repository has a dozen edge
/// cases — bare, work tree, `.git` file, submodule, linked work tree — and a second
/// implementation of the rules would be a hook installed next to a repository rather
/// than in it. The hooks directory comes from git too (`rev-parse --git-path hooks`), so
/// a host configured with `core.hooksPath` gets its gate where git will actually look.
struct Repo {
    /// What the operator named, in their words.
    named: PathBuf,
    /// The git directory: where `hooks/` and `info/` live.
    git_dir: PathBuf,
    /// Whether it is bare (the usual shape for a repository people push to).
    bare: bool,
    /// Where git will look for `pre-receive`, which `core.hooksPath` may move.
    hooks_dir: PathBuf,
    /// `core.hooksPath` itself, when it is set: said out loud, because it is how a
    /// perfectly good gate ends up never running.
    hooks_path: Option<String>,
}

impl Repo {
    /// The repository `--repo` names. Required: a gate has to be installed somewhere in
    /// particular, and guessing which repository a push is headed for is not a guess.
    fn need(args: &Args) -> Result<Repo, CliError> {
        let Some(text) = args.get("--repo") else {
            return Err(CliError::refused(
                "no repository was named",
                "say which repository to gate: --repo /srv/git/repo.git (a bare repository \
                 or any working clone of one)",
            ));
        };
        Repo::resolve(text)
    }

    /// The repository to report on: `--repo`, else `$GIT_DIR`, else wherever we already are.
    ///
    /// Reading is not writing: `hook status` and `doctor --hooks` may answer about the
    /// repository you are standing in, the way `policy show` may read a configured remote.
    /// The installed script always names its own `--repo`, so a repository that has been
    /// moved gets a refusal naming the stale path rather than a gate that quietly guards a
    /// different one — the gate fails closed, and the message says what to reinstall.
    fn locate(args: &Args) -> Result<Repo, CliError> {
        if let Some(text) = args.get("--repo") {
            return Repo::resolve(text);
        }
        if let Some(dir) = std::env::var_os("GIT_DIR") {
            let path = PathBuf::from(&dir);
            if path.exists() {
                return Repo::resolve(&path.display().to_string());
            }
        }
        Repo::resolve(".")
    }

    fn resolve(text: &str) -> Result<Repo, CliError> {
        let named = Path::new(text);
        if !named.exists() {
            return Err(CliError::io(format!(
                "'{text}' does not exist: a hook is installed in a repository that exists, \
                 not one that will"
            )));
        }
        let git_dir = match git(named, &["rev-parse", "--absolute-git-dir"]) {
            Ok(dir) => PathBuf::from(dir),
            // Not a work tree and not a discovery case git answers: hand back git's own
            // words rather than a guess about what the path was supposed to be.
            Err(error) => {
                return Err(CliError::refused(
                    format!("'{text}' is not a git repository: {}", error.message),
                    "point --repo at the repository that receives the push (a bare \
                     repository, or any clone of one)",
                ));
            }
        };
        let bare = git(&git_dir, &["rev-parse", "--is-bare-repository"])
            .map(|answer| answer == "true")
            .unwrap_or(false);
        let hooks_dir = match git(&git_dir, &["rev-parse", "--git-path", "hooks"]) {
            Ok(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir),
            Ok(dir) => git_dir.join(dir),
            Err(_) => git_dir.join("hooks"),
        };
        let hooks_path = git(&git_dir, &["config", "--path", "--get", "core.hooksPath"])
            .ok()
            .filter(|text| !text.trim().is_empty());
        Ok(Repo {
            named: named.to_path_buf(),
            git_dir,
            bare,
            hooks_dir,
            hooks_path,
        })
    }

    /// Where this command's own files live: `info/gitiup/`, which a push cannot write.
    fn info(&self) -> PathBuf {
        self.git_dir.join("info").join("gitiup")
    }

    /// The script's path: `<hooks dir>/pre-receive`, i.e. the file git will run.
    fn script(&self) -> PathBuf {
        self.hooks_dir.join(PRE_RECEIVE)
    }

    /// The record's path.
    fn record(&self) -> PathBuf {
        self.info().join(format!("{PRE_RECEIVE}.json"))
    }

    /// The default object mirror for the gate's reads: inside the repository, because
    /// the account git runs its hooks as is the one that is guaranteed to be able to
    /// write here — `$HOME` on a hosting box frequently is not.
    fn default_mirror(&self) -> PathBuf {
        self.info().join("mirror")
    }
}

/// Open the repository as a gitiup store, read-only as far as this command is concerned.
///
/// [`GitHost::detached`] rather than `open`: the gate must work against a repository that
/// no gitiup has ever initialised (its answer is then "no policy is published", which is
/// a refusal with a cause) and it must never write. Everything it reads — `refs/gitiup/**`
/// for the policy, `refs/attestations/**` and the record chains for the proofs — is
/// ordinary store reading.
fn open_store(repo: &Repo, mirror: &Path) -> Result<Opened, CliError> {
    let remote = RemoteConfig::new("repo", &format!("file://{}", repo.git_dir.display()))
        .map_err(|e| CliError::io(format!("{}: {e}", repo.git_dir.display())))?
        .with_option("work-dir", mirror.display().to_string())
        // One fetch per push rather than one per question: a push asks about a policy and
        // then about a proof per ref, and they are all the same advertisement.
        .with_option("ref-cache-ttl", "10s");
    let host = GitHost::detached(&remote)
        .map_err(|e| CliError::io(format!("open {}: {e}", repo.git_dir.display())))?;
    Ok(Opened {
        host: Box::new(host),
        what: format!("repository {}", repo.git_dir.display()),
    })
}

// ---------------------------------------------------------------------------
// the record: what was installed, and what it was told to believe
// ---------------------------------------------------------------------------

/// The published policy as the record remembers it: enough to notice a change, never
/// enough to decide anything. The gate re-reads the policy on every push; this is the
/// receipt, and `hook status` prints the difference between the two out loud.
#[derive(Debug)]
struct PolicyNote {
    source: String,
    revision: Option<u32>,
    body_digest: Option<String>,
    signed_by: Option<String>,
    protects: Vec<String>,
    gate_eligible: bool,
    read_at: TimeUs,
}

impl PolicyNote {
    fn of(resolved: &ResolvedPolicy, read_at: TimeUs) -> PolicyNote {
        PolicyNote {
            source: resolved
                .provenance
                .source
                .map(|source| source.as_str().to_string())
                .unwrap_or_else(|| "none".to_string()),
            revision: resolved.provenance.revision,
            body_digest: resolved.provenance.body_digest.clone(),
            signed_by: resolved.provenance.signed_by.clone(),
            protects: resolved
                .document
                .as_ref()
                .map(|document| document.protects().to_vec())
                .unwrap_or_default(),
            gate_eligible: resolved.gate_eligible(),
            read_at,
        }
    }

    fn json(&self) -> Value {
        json!({
            "source": self.source,
            "revision": self.revision,
            "body_digest": self.body_digest,
            "signed_by": self.signed_by,
            "protects": self.protects,
            "gate_eligible": self.gate_eligible,
            "read_at": self.read_at.to_rfc3339(),
            "read_at_us": self.read_at.0,
        })
    }

    /// The one line a report prints about a policy: what it is, whose it is, and whether
    /// a merge may rest on it.
    fn line(&self) -> String {
        let mut parts = vec![self.source.clone()];
        if let Some(revision) = self.revision {
            parts.push(format!("revision {revision}"));
        }
        if let Some(digest) = &self.body_digest {
            parts.push(format!("cited {digest}"));
        }
        if let Some(key) = &self.signed_by {
            parts.push(format!("signed by {key}"));
        }
        parts.push(if self.gate_eligible {
            "gate-eligible".to_string()
        } else {
            "NOT gate-eligible".to_string()
        });
        parts.join(" · ")
    }

    fn from(value: &Value) -> Option<PolicyNote> {
        Some(PolicyNote {
            source: value.get("source")?.as_str()?.to_string(),
            revision: value
                .get("revision")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
            body_digest: value
                .get("body_digest")
                .and_then(Value::as_str)
                .map(str::to_string),
            signed_by: value
                .get("signed_by")
                .and_then(Value::as_str)
                .map(str::to_string),
            protects: value
                .get("protects")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            gate_eligible: value
                .get("gate_eligible")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            read_at: TimeUs(
                value
                    .get("read_at_us")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
            ),
        })
    }
}

/// What was installed in a repository: the gate's own config, and the only place the
/// opt-out can be recorded.
///
/// A file under the git directory and not a ref, because `refs/gitiup/**` is writable by
/// anyone the transport admits — a gate whose settings a contributor could push over is
/// not a gate.
#[derive(Debug)]
struct Record {
    installed_at: TimeUs,
    /// Which build wrote this, so a stale hook is a fact and not a mystery.
    installed_by: String,
    /// The binary the script execs.
    program: PathBuf,
    /// The opt-out, in one boolean. `false` is what `--no-proof-required` writes.
    proof_required: bool,
    /// Which key ids' policy this repository will believe, resolved at install so the
    /// gate needs no keystore at push time.
    trust_key_ids: Vec<String>,
    /// How those were chosen — said back in every report, because "who do you trust to
    /// set the rules?" must have an answer printed next to the answer.
    trust_from: String,
    work_dir: PathBuf,
    script: PathBuf,
    hooks_path: Option<String>,
    policy: Option<PolicyNote>,
    notes: Vec<String>,
}

impl Record {
    fn json(&self) -> Value {
        json!({
            "record_type": RECORD,
            "hook": PRE_RECEIVE,
            "installed_at": self.installed_at.to_rfc3339(),
            "installed_at_us": self.installed_at.0,
            "installed_by": self.installed_by,
            "program": self.program.display().to_string(),
            "proof_required": self.proof_required,
            "trust_key_ids": self.trust_key_ids,
            "trust_from": self.trust_from,
            "mirror": self.work_dir.display().to_string(),
            "script": self.script.display().to_string(),
            "core_hooks_path": self.hooks_path,
            "policy": self.policy.as_ref().map(PolicyNote::json),
            "notes": self.notes,
        })
    }

    fn load(path: &Path) -> Result<Option<Record>, CliError> {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Ok(None);
        };
        let value: Value = serde_json::from_str(&text).map_err(|e| {
            CliError::io(format!(
                "{} is not readable as a {RECORD} record: {e}",
                path.display()
            ))
        })?;
        if value.get("record_type").and_then(Value::as_str) != Some(RECORD) {
            return Err(CliError::refused(
                format!("{} is not a {RECORD} record", path.display()),
                "it was not written by this command; it is being left alone",
            ));
        }
        Ok(Some(Record {
            installed_at: TimeUs(
                value
                    .get("installed_at_us")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
            ),
            installed_by: value
                .get("installed_by")
                .and_then(Value::as_str)
                .unwrap_or("gitiup, unknown build")
                .to_string(),
            program: PathBuf::from(
                value
                    .get("program")
                    .and_then(Value::as_str)
                    .unwrap_or("gitiup"),
            ),
            proof_required: value
                .get("proof_required")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            trust_key_ids: value
                .get("trust_key_ids")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            trust_from: value
                .get("trust_from")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            work_dir: PathBuf::from(
                value
                    .get("mirror")
                    .and_then(Value::as_str)
                    .unwrap_or("info/gitiup/mirror"),
            ),
            script: PathBuf::from(
                value
                    .get("script")
                    .and_then(Value::as_str)
                    .unwrap_or("hooks/pre-receive"),
            ),
            hooks_path: value
                .get("core_hooks_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            policy: value.get("policy").and_then(PolicyNote::from),
            notes: value
                .get("notes")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }))
    }

    fn save(&self, path: &Path) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::io(format!("create {}: {e}", parent.display())))?;
        }
        let text =
            serde_json::to_string_pretty(&self.json()).unwrap_or_else(|_| "{}\n".to_string());
        std::fs::write(path, text)
            .map_err(|e| CliError::io(format!("write {}: {e}", path.display())))
    }

    /// The trust roots, as a [`Trust`] the resolver takes. Empty means empty: the gate
    /// then resolves nothing and refuses, and says whose signature it was willing to
    /// believe in the refusal.
    fn roots(&self) -> Trust {
        Trust::KeyIds(self.trust_key_ids.iter().cloned().collect::<BTreeSet<_>>())
    }
}

/// Write `text` at `path`, marked executable, with the parent created.
fn write_executable(path: &Path, text: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::io(format!("create {}: {e}", parent.display())))?;
    }
    std::fs::write(path, text)
        .map_err(|e| CliError::io(format!("write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| CliError::io(format!("chmod +x {}: {e}", path.display())))?;
    }
    Ok(())
}

/// Is this `hooks/pre-receive` the one gitiup wrote?
///
/// A marker line, not a checksum: the script is text a human is allowed to read and is
/// expected to be able to find with `grep`, and the question anyone actually asks is
/// "did gitiup put this here", not "has it been modified byte for byte".
fn script_is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|text| text.contains(MARKER))
        .unwrap_or(false)
}

/// Shell-quote one path for the generated script.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The script that gets installed.
///
/// Three things it has to do that a `#!/bin/sh` + one `exec` line would not:
///
/// * **scrub the transport's environment.** `git receive-pack` runs hooks with `GIT_DIR`
///   (often the relative `.`), `GIT_QUARANTINE_PATH` and the object-directory variables
///   set; the gate reads the repository through `git` plumbing of its own, and those
///   variables are about *quarantined, uncommitted* objects. Unset here so the gate reads
///   the repository as every later reader will see it.
/// * **fail closed if `gitiup` is gone.** A script that cannot find its program must not
///   exit 0: 127 would do, and a sentence in the pusher's terminal is better than a bare
///   status code.
/// * **carry its own `--help`.** git never passes arguments to a `pre-receive` hook, so
///   `./hooks/pre-receive --help` on the box prints [`PRE_RECEIVE_HELP`] — the
///   asymmetry, the no-override rule and the one caveat, in the file itself.
fn script_text(repo: &Repo, program: &Path) -> String {
    let header = PRE_RECEIVE_HELP
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                "#".to_string()
            } else {
                format!("# {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "#!/bin/sh\n\
         # {MARKER} — installed by `gitiup hook install pre-receive --repo {repo}`\n\
         # into {script} by {by}.\n\
         #\n\
         # This is the gate. What it guards (refs/heads/**), what it leaves open\n\
         # ({open}), and why that asymmetry is the whole design, are written out in\n\
         # the text below: run `{script} --help` on this box.\n\
         #\n\
         # Edited by hand? `gitiup hook install pre-receive --repo {repo}` writes it\n\
         # again, and `gitiup hook status --repo {repo}` says what is in force here.\n\
         \n\
         {header}\n\
         \n\
         unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_QUARANTINE_PATH \\\n\
               GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_SUPER_PREFIX\n\
         \n\
         PROGRAM={program}\n\
         if [ ! -x \"$PROGRAM\" ]; then\n\
         \x20   echo \"gitiup: the pre-receive gate cannot run: $PROGRAM is not executable\"\n\
         \x20   echo \"gitiup: the push is refused. Reinstall with `gitiup hook install pre-receive --repo {repo}`\"\n\
         \x20   exit 1\n\
         fi\n\
         exec \"$PROGRAM\" hook run {hook} --repo {repo} \"$@\"\n",
        repo = repo.git_dir.display(),
        script = repo.script().display(),
        by = version(),
        open = OPEN_REFS.join(", "),
        header = header,
        program = quote(&program.display().to_string()),
        hook = PRE_RECEIVE,
    )
}

/// What to call this build in a record and a script header.
fn version() -> String {
    format!("gitiup {}", env!("CARGO_PKG_VERSION"))
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

/// The trust roots to record, and the words that say where they came from.
///
/// Resolved at install, once, so the gate needs no keystore at push time: the question
/// "whose policy does this repository believe?" is answered by a list of key ids written
/// by an operator with a shell here, and printed by `hook status`. That is the same rule
/// `gitiup policy show` and `gitiup verify change` apply (`--trust`, else this keystore's
/// own keys) — one question, one answer, said out loud in every report that used it.
fn install_trust(args: &Args) -> Result<(Trust, Vec<String>, String), CliError> {
    let explicit = !args.all("--trust").is_empty();
    let roots = policy_cli::show_trust(args)?;
    let Trust::KeyIds(ids) = &roots else {
        // `Trust::AnyKeyForTests` is a test fixture, never an operator's act, and it does
        // not belong in a hook that guards a real repository.
        return Err(CliError::refused(
            "this build's test trust rule cannot be installed into a hook",
            "name the keys with --trust <key|id>",
        ));
    };
    let ids: Vec<String> = ids.iter().cloned().collect();
    let from = if explicit {
        "--trust, given at install time".to_string()
    } else {
        "this keystore's own keys, read at install time".to_string()
    };
    Ok((roots, ids, from))
}

fn install(args: &Args) -> Result<(), CliError> {
    if args.help(HOOK_HELP).is_some() {
        return Ok(());
    }
    need_hook(args)?;
    let repo = Repo::need(args)?;
    let proof_required = !args.on("--no-proof-required");
    let program = match args.get("--program") {
        Some(text) => PathBuf::from(text),
        None => std::env::current_exe().map_err(|e| {
            CliError::io(format!(
                "cannot tell which gitiup binary to point the hook at: {e}"
            ))
        })?,
    };
    let work_dir = args
        .get("--mirror")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.default_mirror());
    let target = repo.script();
    let mut notes: Vec<String> = Vec::new();

    // Never silently eat somebody else's hook. A repository can already have a
    // `pre-receive` — a CI trigger, a deploy trigger, a policy of its own — and the
    // operator who runs `install` is not asking for it to be replaced.
    if target.exists() && !script_is_ours(&target) {
        if !args.force() {
            let first = std::fs::read_to_string(&target)
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| !line.starts_with("#!"))
                        .map(str::to_string)
                })
                .unwrap_or_default();
            return Err(CliError::refused(
                format!(
                    "{} already exists and was not written by gitiup, so it is being left \
                     alone ({})",
                    target.display(),
                    one_line(&first)
                ),
                "install alongside it by hand, or say `--force` to replace it — with \
                 --force the file you replace is kept next to it as `pre-receive.gitiup-replaced`",
            ));
        }
        let backup = repo
            .hooks_dir
            .join(format!("{PRE_RECEIVE}.gitiup-replaced"));
        std::fs::copy(&target, &backup)
            .map_err(|e| CliError::io(format!("keep {}: {e}", backup.display())))?;
        notes.push(format!(
            "a hook gitiup did not write was replaced and kept at {}",
            backup.display()
        ));
    }

    let (roots, trust_key_ids, trust_from) = install_trust(args)?;
    // Opening the store is the install-time proof that the gate can answer at all: git
    // runs here, the mirror directory is writable, and the repository is reachable over
    // `file://`. Failing here beats installing a gate that refuses every push.
    let store = open_store(&repo, &work_dir)?;
    let now = TimeUs::now();
    let question = Question::published(&store, roots, now);
    let policy = match question.resolve(now, "now") {
        Ok(resolved) => {
            let note = PolicyNote::of(&resolved, now);
            if !note.protects.is_empty() && !note.protects.iter().any(|glob| glob == GUARDED) {
                notes.push(format!(
                    "the policy in force gates [{}], so a refs/heads/** update outside those \
                     globs is accepted ungoverned (that is the owner's rule: ADR-0004 D1)",
                    note.protects.join(", ")
                ));
            }
            Some(note)
        }
        Err(error) => {
            notes.push(format!(
                "no gate-eligible policy can be resolved here right now ({}: {}), so every \
                 push to {GUARDED} will be REFUSED until one is published — `gitiup policy \
                 publish --repo …` or a [[remote]] for this repository publishes one",
                error.token(),
                one_line(&error.detail)
            ));
            None
        }
    };
    if trust_key_ids.is_empty() {
        notes.push(
            "no key id is trusted to sign a policy here, so no policy this gate reads will \
             ever be believed: reinstall with --trust <key|id> (a key id, or a name in this \
             keystore)"
                .to_string(),
        );
    }
    if !proof_required {
        notes.push(format!(
            "PROOF IS NOT REQUIRED IN THIS REPOSITORY: {GUARDED} will move on trust alone. \
             The gate is installed and says so on every push; `gitiup hook status` and \
             `gitiup doctor --hooks --repo {}` both refuse over it.",
            repo.git_dir.display()
        ));
    }
    if let Some(path) = &repo.hooks_path {
        notes.push(format!(
            "core.hooksPath is set to {path}: the gate was installed where git will look \
             for it ({}), not where a bare repository keeps its hooks by default",
            repo.hooks_dir.display()
        ));
    }
    if !repo.bare {
        notes.push(
            "this is a working clone, not a bare repository: this gate still runs for every \
             push to it, and git's own receive.denyCurrentBranch still refuses pushes that \
             move the checked-out branch — that refusal is git's, not this gate's"
                .to_string(),
        );
    }

    let record = Record {
        installed_at: now,
        installed_by: version(),
        program: program.clone(),
        proof_required,
        trust_key_ids,
        trust_from,
        work_dir: work_dir.clone(),
        script: target.clone(),
        hooks_path: repo.hooks_path.clone(),
        policy,
        notes,
    };

    let script = script_text(&repo, &program);
    if args.on("--dry-run") {
        report_install(&repo, &record, &script, true, args)?;
        return Ok(());
    }
    record.save(&repo.record())?;
    write_executable(&target, &script)?;
    report_install(&repo, &record, &script, false, args)
}

/// The install report: what was written where, what it will demand, and what it was told
/// to believe. Same text for `--dry-run`, which is the point of the flag — a preview that
/// describes a different run is not a preview.
fn report_install(
    repo: &Repo,
    record: &Record,
    script: &str,
    dry: bool,
    args: &Args,
) -> Result<(), CliError> {
    if args.json() {
        let mut out = record.json();
        out["repo"] = Value::String(repo.git_dir.display().to_string());
        out["bare"] = Value::Bool(repo.bare);
        out["dry_run"] = Value::Bool(dry);
        out["script_bytes"] = Value::from(script.len() as u64);
        println!("{}", out);
        return Ok(());
    }
    let row = |label: &str, value: String| format!("  {:<10}{}\n", label, value);
    let mut out = String::new();
    out.push_str(&format!(
        "gitiup hook {PRE_RECEIVE} — {}\n",
        if dry {
            format!("would install into {}", repo.git_dir.display())
        } else {
            format!("installed in {}", repo.git_dir.display())
        }
    ));
    out.push_str(&row(
        "script",
        format!("{} (0755, sh)", repo.script().display()),
    ));
    out.push_str(&row("record", repo.record().display().to_string()));
    out.push_str(&row(
        "runs",
        format!(
            "{} hook run {PRE_RECEIVE} --repo {}",
            record.program.display(),
            repo.git_dir.display()
        ),
    ));
    out.push_str(&row("mirror", record.work_dir.display().to_string()));
    out.push_str(&row(
        "proves",
        if record.proof_required {
            format!(
                "required — a {GUARDED} update needs an attestation set the published policy \
                 accepts"
            )
        } else {
            "NOT REQUIRED — this repository opted out: guarded refs move on trust alone".into()
        },
    ));
    match &record.policy {
        Some(policy) => {
            out.push_str(&row("policy", policy.line()));
            out.push_str(&row("gates", policy.protects.join(", ")));
        }
        None => out.push_str(&row(
            "policy",
            "none resolvable — guarded pushes will be refused (see notes)".to_string(),
        )),
    }
    out.push_str(&row(
        "trusts",
        if record.trust_key_ids.is_empty() {
            "nobody: no key id was recorded".to_string()
        } else {
            format!(
                "{} key(s) [{}] — {}",
                record.trust_key_ids.len(),
                record.trust_key_ids.join(", "),
                record.trust_from
            )
        },
    ));
    out.push_str(&row(
        "open",
        format!(
            "{} — writable by anyone the git transport admits",
            OPEN_REFS.join(", ")
        ),
    ));
    for note in &record.notes {
        out.push_str(&row("note", one_line(note)));
    }
    if !dry {
        out.push_str(&format!(
            "\n  read it:  {script} --help\n  test it:  printf '<old> <new> \
             refs/heads/main\\n' | {script}\n  undo it:  gitiup hook uninstall \
             {PRE_RECEIVE} --repo {repo}\n",
            script = repo.script().display(),
            repo = repo.git_dir.display()
        ));
    }
    print!("{out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

fn uninstall(args: &Args) -> Result<(), CliError> {
    if args.help(HOOK_HELP).is_some() {
        return Ok(());
    }
    need_hook(args)?;
    let repo = Repo::need(args)?;
    let script = repo.script();
    let record = repo.record();
    let state = Record::load(&record)?;
    if script.exists() && !script_is_ours(&script) {
        return Err(CliError::refused(
            format!(
                "{} is not a hook gitiup wrote, so it is not gitiup's to delete",
                script.display()
            ),
            "remove it yourself, once you have read it",
        ));
    }
    if !script.exists() && !record.exists() {
        if args.json() {
            println!(
                "{}",
                json!({ "record_type": RECORD, "hook": PRE_RECEIVE, "repo": repo.git_dir.display().to_string(), "installed": false })
            );
        } else {
            println!(
                "gitiup hook {PRE_RECEIVE} — nothing is installed in {}; nothing was removed.",
                repo.git_dir.display()
            );
        }
        return Ok(());
    }
    let dry = args.on("--dry-run");
    let mut removed: Vec<String> = Vec::new();
    if !dry {
        if script.exists() {
            std::fs::remove_file(&script)
                .map_err(|e| CliError::io(format!("remove {}: {e}", script.display())))?;
        }
        if record.exists() {
            std::fs::remove_file(&record)
                .map_err(|e| CliError::io(format!("remove {}: {e}", record.display())))?;
        }
    }
    if script.exists() {
        removed.push(script.display().to_string());
    }
    if record.exists() {
        removed.push(record.display().to_string());
    }
    if args.json() {
        println!(
            "{}",
            json!({
                "record_type": RECORD, "hook": PRE_RECEIVE,
                "repo": repo.git_dir.display().to_string(),
                "removed": removed, "dry_run": dry,
                "mirror": state.as_ref().map(|s| s.work_dir.display().to_string()),
            })
        );
        return Ok(());
    }
    println!(
        "gitiup hook {PRE_RECEIVE} — {} from {}",
        if dry { "would remove" } else { "removed" },
        repo.git_dir.display()
    );
    for path in &removed {
        println!("  {:<10}{path}", "file");
    }
    if let Some(state) = &state {
        println!(
            "  {:<10}{} — left in place: it is a cache of objects the gate read, and \
             deleting it is yours to decide",
            "mirror",
            state.work_dir.display()
        );
    }
    println!(
        "\n  this repository no longer refuses an unproven {GUARDED} update. If that was not \
         the plan: gitiup hook install {PRE_RECEIVE} --repo {}",
        repo.git_dir.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// the assessment behind `hook status` and `doctor --hooks`
// ---------------------------------------------------------------------------

/// One reason this repository would not gate an unproven push, and what to do about it.
struct Problem {
    sentence: String,
    hint: Option<String>,
}

/// What is installed, what is in force, and whether the two add up to a gate.
///
/// `gitiup hook status` and `gitiup doctor --hooks` print *this* — one assessment, two
/// renderings, in the same idiom as `policy check` and `policy explain`. Two commands
/// that each decide "is this repository honest about proofs?" is two answers.
struct Assessment {
    repo: Repo,
    record: Option<Record>,
    script: PathBuf,
    script_exists: bool,
    ours: bool,
    executable: bool,
    policy: Option<ResolvedPolicy>,
    policy_error: Option<PolicyError>,
    read_at: TimeUs,
    problems: Vec<Problem>,
    warnings: Vec<String>,
}

impl Assessment {
    fn code(&self) -> u8 {
        if self.problems.is_empty() { 0 } else { 6 }
    }

    fn verdict(&self) -> String {
        if self.problems.is_empty() {
            format!(
                "GATED — a {GUARDED} update whose new head has no policy-satisfying proof set \
                 is refused here"
            )
        } else {
            format!(
                "NOT GATED — {} · first reason: {}",
                self.problems.len(),
                one_line(&self.problems[0].sentence)
            )
        }
    }

    fn policy_line(&self) -> String {
        match (&self.policy, &self.policy_error) {
            (Some(resolved), _) => {
                let note = PolicyNote::of(resolved, self.read_at);
                note.line()
            }
            (None, Some(error)) => {
                format!("refused — {}: {}", error.token(), one_line(&error.detail))
            }
            (None, None) => "nothing was read".to_string(),
        }
    }

    fn json(&self) -> Value {
        let record = self.record.as_ref().map(Record::json);
        json!({
            "record_type": "gitiup-hook-status-1",
            "hook": PRE_RECEIVE,
            "repo": self.repo.git_dir.display().to_string(),
            "named": self.repo.named.display().to_string(),
            "bare": self.repo.bare,
            "hooks_dir": self.repo.hooks_dir.display().to_string(),
            "core_hooks_path": self.repo.hooks_path,
            "installed": self.script_exists && self.ours,
            "script": self.script.display().to_string(),
            "script_exists": self.script_exists,
            "script_is_ours": self.ours,
            "script_executable": self.executable,
            "record": record,
            "policy": self.policy.as_ref().map(|resolved| json!({
                "provenance": resolved.provenance.json(),
                "protects": resolved.document.as_ref().map(|document| document.protects().to_vec()),
                "min_signatures": resolved.policy.min_signatures,
                "allowed_tiers": resolved.policy.allowed_tiers.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
            })),
            "policy_refused": self.policy_error.as_ref().map(|error| json!({
                "token": error.token(), "detail": error.detail, "exit": error.exit_code(),
            })),
            "read_at": self.read_at.to_rfc3339(),
            "gates": self.policy.as_ref()
                .and_then(|resolved| resolved.document.as_ref())
                .map(|document| document.protects().to_vec())
                .unwrap_or_default(),
            "open_refs": OPEN_REFS,
            "verdict": if self.problems.is_empty() { "gated" } else { "not-gated" },
            "exit": self.code() as u64,
            "problems": self.problems.iter().map(|problem| json!({
                "detail": problem.sentence, "hint": problem.hint,
            })).collect::<Vec<Value>>(),
            "warnings": self.warnings,
        })
    }

    fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "gitiup hook {PRE_RECEIVE} — {}{}\n",
            self.repo.git_dir.display(),
            if self.repo.bare {
                ""
            } else {
                "  (a working clone)"
            }
        ));
        let row = |label: &str, value: String| format!("  {:<10}{}\n", label, value);
        out.push_str(&row(
            "status",
            match (self.script_exists, self.ours) {
                (true, true) => format!(
                    "installed, written by {} on {}",
                    self.record
                        .as_ref()
                        .map(|r| r.installed_by.clone())
                        .unwrap_or_else(|| "gitiup".to_string()),
                    self.record
                        .as_ref()
                        .map(|r| r.installed_at.to_rfc3339())
                        .unwrap_or_default()
                ),
                (true, false) => {
                    "a pre-receive hook is installed but gitiup did not write it".into()
                }
                (false, _) => "no hook script is installed".into(),
            },
        ));
        out.push_str(&row(
            "script",
            format!(
                "{}{}",
                self.script.display(),
                if self.script_exists {
                    if self.executable {
                        " (executable)"
                    } else {
                        " (NOT executable)"
                    }
                } else {
                    " (absent)"
                }
            ),
        ));
        out.push_str(&row("record", self.repo.record().display().to_string()));
        if let Some(record) = &self.record {
            out.push_str(&row(
                "runs",
                format!(
                    "{} hook run {PRE_RECEIVE} --repo {}",
                    record.program.display(),
                    self.repo.git_dir.display()
                ),
            ));
            out.push_str(&row("mirror", record.work_dir.display().to_string()));
            out.push_str(&row(
                "proves",
                if record.proof_required {
                    format!("required — a {GUARDED} update needs an attestation set the published policy accepts")
                } else {
                    "NOT REQUIRED — this repository opted out; guarded refs move on trust alone".into()
                },
            ));
            out.push_str(&row(
                "trusts",
                if record.trust_key_ids.is_empty() {
                    "nobody: no key id was recorded".into()
                } else {
                    format!(
                        "{} key(s) [{}] — {}",
                        record.trust_key_ids.len(),
                        record.trust_key_ids.join(", "),
                        record.trust_from
                    )
                },
            ));
            if let Some(note) = &record.policy {
                out.push_str(&row(
                    "before",
                    format!("{} (read {})", note.line(), note.read_at.to_rfc3339()),
                ));
            }
        }
        out.push_str(&row("policy", self.policy_line()));
        out.push_str(&row(
            "gates",
            self.policy
                .as_ref()
                .and_then(|resolved| resolved.document.as_ref())
                .map(|document| document.protects().join(", "))
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "nothing published: every guarded ref is refused".into()),
        ));
        out.push_str(&row(
            "read",
            format!("{} (this run)", self.read_at.to_rfc3339()),
        ));
        out.push_str(&row(
            "open",
            format!(
                "{} — writable by anyone the git transport admits",
                OPEN_REFS.join(", ")
            ),
        ));
        for warning in &self.warnings {
            out.push_str(&row("warning", one_line(warning)));
        }
        for problem in &self.problems {
            out.push_str(&row("problem", one_line(&problem.sentence)));
            if let Some(hint) = problem.hint.as_deref() {
                out.push_str(&row("hint", one_line(hint)));
            }
        }
        out.push_str(&format!("\n{}\n", self.verdict()));
        out
    }
}

/// Read everything and decide nothing twice.
fn assess(repo: Repo) -> Result<Assessment, CliError> {
    let read_at = TimeUs::now();
    let record = Record::load(&repo.record())?;
    let script = repo.script();
    let script_exists = script.is_file();
    let ours = script_exists && script_is_ours(&script);
    let executable = script_exists && is_executable(&script);
    let work_dir = record
        .as_ref()
        .map(|state| state.work_dir.clone())
        .unwrap_or_else(|| repo.default_mirror());
    let roots = match &record {
        Some(state) => state.roots(),
        None => policy_cli::show_trust(&Args::default())?,
    };
    let mut problems: Vec<Problem> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Install state first: a missing script and a missing policy are different facts, and
    // reporting the policy when the script is gone would send someone to the wrong file.
    match (script_exists, ours, record.as_ref()) {
        (false, _, None) => problems.push(Problem {
            sentence: format!(
                "no gitiup gate is installed here, so {GUARDED} moves on trust alone"
            ),
            hint: Some(format!(
                "gitiup hook install {PRE_RECEIVE} --repo {}",
                repo.git_dir.display()
            )),
        }),
        (false, _, Some(_)) => problems.push(Problem {
            sentence: format!(
                "{} is recorded as installed but is not on disk (deleted, or `core.hooksPath` \
                 moved the hooks directory)",
                script.display()
            ),
            hint: Some(format!(
                "run gitiup hook install {PRE_RECEIVE} --repo {} again",
                repo.git_dir.display()
            )),
        }),
        (true, false, _) => problems.push(Problem {
            sentence: format!(
                "{} exists but was not written by gitiup, so nothing about this repository's \
                 proofs is enforced by it",
                script.display()
            ),
            hint: Some("read it; install alongside it, or over it with --force".to_string()),
        }),
        (true, true, None) => problems.push(Problem {
            sentence: format!(
                "the gate script is installed but {} is not, so the gate has no policy signer \
                 to believe and will refuse every guarded push",
                repo.record().display()
            ),
            hint: Some(format!(
                "run gitiup hook install {PRE_RECEIVE} --repo {} again",
                repo.git_dir.display()
            )),
        }),
        (true, true, Some(state)) => {
            if !executable {
                problems.push(Problem {
                    sentence: format!(
                        "{} is not executable, so git will refuse to run it",
                        script.display()
                    ),
                    hint: Some(format!("chmod +x {}", script.display())),
                });
            }
            if state.script != script {
                problems.push(Problem {
                    sentence: format!(
                        "the gate was installed at {} but git now looks in {}, so the gate \
                         never runs",
                        state.script.display(),
                        script.display()
                    ),
                    hint: Some(format!(
                        "reinstall: gitiup hook install {PRE_RECEIVE} --repo {}",
                        repo.git_dir.display()
                    )),
                });
            }
            if !state.proof_required {
                problems.push(Problem {
                    sentence: format!(
                        "proof is NOT REQUIRED in this repository (opt-out recorded {}): a \
                         {GUARDED} update is accepted whatever it can prove — which is to say, \
                         with nothing",
                        state.installed_at.to_rfc3339()
                    ),
                    hint: Some(format!(
                        "put the gate back with gitiup hook install {PRE_RECEIVE} --repo {}",
                        repo.git_dir.display()
                    )),
                });
            }
            if state.trust_key_ids.is_empty() {
                problems.push(Problem {
                    sentence: "no key id is trusted here to sign a policy, so no policy this \
                               gate reads can be believed"
                        .to_string(),
                    hint: Some(format!(
                        "reinstall with --trust <key|id>: gitiup hook install {PRE_RECEIVE} \
                         --repo {}",
                        repo.git_dir.display()
                    )),
                });
            }
        }
    }

    // The policy, read now, through the gate's own roots. This is the same resolution the
    // hook performs mid-push, so `hook status` cannot promise a policy the next push will
    // not find.
    let mut policy = None;
    let mut policy_error = None;
    let store = match open_store(&repo, &work_dir) {
        Ok(store) => Some(store),
        Err(error) => {
            problems.push(Problem {
                sentence: format!(
                    "the repository could not be read as a store: {}",
                    error.message
                ),
                hint: error.hint,
            });
            None
        }
    };
    if let (Some(store), true) = (&store, script_exists && ours) {
        let question = Question::published(store, roots, read_at);
        match question.resolve(read_at, "now") {
            Ok(resolved) => {
                let protects: Vec<String> = resolved
                    .document
                    .as_ref()
                    .map(|document| document.protects().to_vec())
                    .unwrap_or_default();
                if !protects.is_empty() && !protects.iter().any(|glob| glob == GUARDED) {
                    warnings.push(format!(
                        "the policy in force gates [{}]: a refs/heads/** branch outside those \
                         globs moves with no proof asked of it — the owner's rule, not a \
                         defect (ADR-0004 D1)",
                        protects.join(", ")
                    ));
                }
                if let Some(note) = record.as_ref().and_then(|state| state.policy.as_ref())
                    && note.body_digest != resolved.provenance.body_digest
                {
                    warnings.push(format!(
                        "the policy changed since the gate was installed: {} then, {} now",
                        note.line(),
                        PolicyNote::of(&resolved, read_at).line()
                    ));
                }
                policy = Some(resolved);
            }
            Err(error) => {
                let stands = record
                    .as_ref()
                    .is_none_or(|state| state.proof_required && !state.trust_key_ids.is_empty());
                let reason = Problem {
                    sentence: format!(
                        "{}: {} — every push to {GUARDED} is refused until a policy can be \
                         resolved",
                        error.token(),
                        one_line(&error.detail)
                    ),
                    hint: error.hint.clone().or_else(|| {
                        Some(format!(
                            "publish one: gitiup policy publish --repo … (or a [[remote]] for \
                         this repository), then gitiup hook status --repo {}",
                            repo.git_dir.display()
                        ))
                    }),
                };
                // A repository that opted out of proof is already reported for that; a
                // missing policy on top of the opt-out is not a second reason to refuse.
                if stands {
                    problems.push(reason);
                } else {
                    warnings.push(reason.sentence);
                }
                policy_error = Some(error);
            }
        }
    }
    Ok(Assessment {
        repo,
        record,
        script,
        script_exists,
        ours,
        executable,
        policy,
        policy_error,
        read_at,
        problems,
        warnings,
    })
}

fn status(args: &Args) -> Result<(), CliError> {
    if args.help(HOOK_HELP).is_some() {
        return Ok(());
    }
    need_hook(args)?;
    let repo = Repo::locate(args)?;
    let out = assess(repo)?;
    if args.json() {
        println!("{}", out.json());
    } else {
        print!("{}", out.text());
    }
    if out.code() == 0 {
        return Ok(());
    }
    // A verdict, not a fault: everything worth saying went to stdout, and the number is
    // the answer — the same convention every other verdict in this crate keeps, and the
    // one a hook has to be able to rely on.
    Err(CliError::verdict(out.code()))
}

/// `gitiup doctor --hooks [--repo <path>]` — the same assessment, in doctor's voice.
pub fn doctor(args: &[String]) -> Result<(), CliError> {
    // `doctor` hands its own argument list over, so the flag that sent it here is still
    // in it. Accepting it (and `--hook`, its alias) is cheaper and less surprising than
    // a re-parse that drops a flag the caller plainly typed.
    let mut switches: Vec<&str> = SWITCHES.to_vec();
    switches.push("--hooks");
    switches.push("--hook");
    let args = Args::parse_with(args, VALUED, &switches)?;
    let repo = Repo::locate(&args)?;
    let out = assess(repo)?;
    if args.json() {
        println!("{}", out.json());
    } else {
        print!("gitiup doctor — the proof gate on ref updates\n\n");
        print!("{}", out.text());
    }
    if out.code() == 0 {
        return Ok(());
    }
    Err(CliError::verdict(out.code()))
}

// ---------------------------------------------------------------------------
// the gate: `gitiup hook run pre-receive`
// ---------------------------------------------------------------------------

/// One line of a `pre-receive` hook's stdin: the ref, where it is, and where the push
/// would move it.
struct Update {
    old: String,
    new: String,
    reference: String,
}

impl Update {
    /// git's spelling of "this ref will cease to exist".
    fn is_delete(&self) -> bool {
        self.new.chars().all(|c| c == '0')
    }

    /// Is this a ref the gate guards? Only `refs/heads/**` is, and that is the whole
    /// asymmetry in one line — see [`PRE_RECEIVE_HELP`] for why.
    fn guarded(&self) -> bool {
        self.reference
            .strip_prefix("refs/heads/")
            .is_some_and(|rest| !rest.is_empty())
    }

    /// Short form for a line of output: the first 8 hex characters, which is what a
    /// terminal has room for.
    fn short(&self) -> String {
        if self.new.chars().all(|c| c.is_ascii_hexdigit()) {
            self.new.chars().take(8).collect()
        } else {
            self.new.clone()
        }
    }
}

/// One ref update and the decision about it.
struct Decision {
    update: Update,
    /// `guarded` or `open`: which side of the asymmetry this ref is on.
    guard: &'static str,
    accepted: bool,
    exit: u8,
    /// The one line the pusher reads first about this ref.
    headline: String,
    /// The full report, when there was one worth printing (a refusal, always).
    report: Option<Explanation>,
}

fn run(args: &Args) -> Result<(), CliError> {
    if args.wants_help() {
        print!("{PRE_RECEIVE_HELP}");
        return Ok(());
    }
    need_hook(args)?;
    let repo = Repo::locate(args)?;
    let updates = read_updates()?;
    if updates.is_empty() {
        println!(
            "gitiup: {PRE_RECEIVE} — no ref update arrived on stdin, so there is nothing to decide"
        );
        return Ok(());
    }
    // The record is the gate's own instructions. Without it there is no set of trust
    // roots, no mirror and no answer — which is a refusal, not a shrug.
    let record = match Record::load(&repo.record())? {
        Some(record) => record,
        None => {
            println!(
                "gitiup: {PRE_RECEIVE} — {} is missing, so this hook has no trust roots and \
                 no policy to read",
                repo.record().display()
            );
            println!(
                "gitiup: the push is refused. Say it out loud rather than guess: `gitiup hook \
                 install {PRE_RECEIVE} --repo {}`",
                repo.git_dir.display()
            );
            return Err(CliError::verdict(6));
        }
    };
    let mut decisions: Vec<Decision> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    if !record.proof_required {
        // The opt-out, said on every push. The hook stays installed precisely so that this
        // line is in the pusher's terminal and in whoever is watching: a silent opt-out is
        // how a policy rots.
        notes.push(format!(
            "proof is NOT REQUIRED in this repository (--no-proof-required): {GUARDED} moves \
             on trust alone here"
        ));
        for update in updates {
            decisions.push(Decision {
                guard: if update.guarded() { "guarded" } else { "open" },
                accepted: true,
                exit: 0,
                headline: if update.guarded() {
                    "accepted without proof — proof is not required in this repository \
                     (opt-out recorded in the hook's record)"
                        .to_string()
                } else {
                    open_line(&update)
                },
                update,
                report: None,
            });
        }
        return finish(
            &repo,
            &record,
            decisions,
            notes,
            "not required — this repository opted out".to_string(),
            args,
        );
    }

    if record.trust_key_ids.is_empty() {
        println!(
            "gitiup: {PRE_RECEIVE} — this hook was told to believe nobody: no key id is \
             recorded as a policy signer in {}",
            repo.record().display()
        );
        println!(
            "gitiup: so no policy it reads can be believed, and every guarded push is \
             refused. Reinstall with --trust <key|id>."
        );
        return Err(CliError::verdict(6));
    }

    let store = open_store(&repo, &record.work_dir).map_err(|mut error| {
        // A gate that cannot read the store cannot answer, and "cannot answer" is a
        // refusal here, not a 3 to be argued about: say so on stdout, where git will
        // relay it.
        error.code = 6;
        error.message = format!("gitiup: {PRE_RECEIVE} — {}", error.message);
        error
    })?;
    let now = TimeUs::now();
    // Resolved once, here, for the whole push: it decides whether a ref is governed at all,
    // and a failure is one fact rather than one fact per ref.
    let question = Question::published(&store, record.roots(), now);
    let resolved = question.resolve(now, "now");
    for update in updates {
        if !update.guarded() {
            decisions.push(Decision {
                guard: "open",
                accepted: true,
                exit: 0,
                headline: open_line(&update),
                update,
                report: None,
            });
            continue;
        }
        if update.is_delete() {
            decisions.push(Decision {
                guard: "guarded",
                accepted: false,
                exit: 6,
                headline: "a branch that vanishes is a change to a guarded ref that nothing \
                           can prove; a guarded ref does not disappear on an unproved push"
                    .to_string(),
                update,
                report: None,
            });
            continue;
        }
        let commit = match crate::verify::commit_id(&update.new) {
            Ok(commit) => commit,
            Err(error) => {
                decisions.push(Decision {
                    guard: "guarded",
                    accepted: false,
                    exit: 6,
                    headline: format!("'{}' is not a commit: {}", update.new, error.message),
                    update,
                    report: None,
                });
                continue;
            }
        };
        // Does the published policy even govern this ref? `protects` is the owner's answer
        // to exactly that question, and a policy that does not mention a branch is not in
        // force for it (ADR-0004 D5) — so the push is accepted, and said to be accepted
        // ungoverned rather than accepted as proved.
        let governed = match &resolved {
            Ok(policy) => policy
                .document
                .as_ref()
                .map(|document| document.protects_ref(&update.reference))
                .unwrap_or(true),
            Err(_) => false,
        };
        let verdict = match crate::policy_ask::verdict_for_commit(
            &store,
            &commit,
            Some(&update.reference),
            &Question::published(&store, record.roots(), now),
            now,
        ) {
            Ok(verdict) => verdict,
            Err(error) => {
                // The store did not answer. That is not a verdict about the push, but it
                // is not a green light either: refuse, with the store's own sentence.
                decisions.push(Decision {
                    guard: "guarded",
                    accepted: false,
                    exit: if error.code == 7 || error.code == 8 {
                        error.code
                    } else {
                        6
                    },
                    headline: format!("the store could not be read: {}", error.message),
                    update,
                    report: None,
                });
                continue;
            }
        };
        if verdict.satisfied() {
            decisions.push(Decision {
                guard: "guarded",
                accepted: true,
                exit: 0,
                headline: verdict.accepted_line(),
                update,
                report: None,
            });
        } else if !governed && resolved.is_ok() {
            decisions.push(Decision {
                guard: "guarded",
                accepted: true,
                exit: 0,
                headline: format!(
                    "accepted UNGOVERNED — the published policy's `protects` does not name \
                     {}, so it asks nothing of this ref (ADR-0004 D1)",
                    update.reference
                ),
                update,
                report: None,
            });
        } else {
            decisions.push(Decision {
                guard: "guarded",
                accepted: false,
                exit: verdict.code(),
                headline: verdict.headline(),
                update,
                report: Some(verdict),
            });
        }
    }
    // One policy failure, said once: per-ref it would be the same sentence N times, and N
    // copies of one fact is how a report stops being readable.
    let policy = match &resolved {
        Ok(resolved) => PolicyNote::of(resolved, now).line(),
        Err(error) => {
            notes.push(format!(
                "no gate-eligible policy could be resolved from this repository ({}: {}), so \
                 nothing here says any guarded ref may move",
                error.token(),
                one_line(&error.detail)
            ));
            format!("none — {}: {}", error.token(), one_line(&error.detail))
        }
    };
    finish(&repo, &record, decisions, notes, policy, args)
}

/// What a ref that the gate does not guard says about itself.
fn open_line(update: &Update) -> String {
    format!(
        "accepted: {} is not a guarded ref — this gate guards {GUARDED} and leaves the \
         namespaces a proposal and its proof live in open",
        update.reference
    )
}

/// Print everything and leave with the verdict.
fn finish(
    repo: &Repo,
    record: &Record,
    decisions: Vec<Decision>,
    notes: Vec<String>,
    policy: String,
    args: &Args,
) -> Result<(), CliError> {
    let refused: Vec<&Decision> = decisions.iter().filter(|one| !one.accepted).collect();
    // 8 before 7 before 6: integrity outranks authority, which outranks policy — the same
    // precedence every verdict in this crate uses, so the number a pusher gets is the
    // number the report's first line names. The codes are already ordered for it.
    let code = refused.iter().map(|one| one.exit).max().unwrap_or(0);
    let quiet = args.on("--quiet") || args.on("-q");
    if args.json() {
        let refs: Vec<Value> = decisions
            .iter()
            .map(|one| {
                json!({
                    "ref": one.update.reference,
                    "old": one.update.old,
                    "new": one.update.new,
                    "guard": one.guard,
                    "outcome": if one.accepted { "accepted" } else { "refused" },
                    "exit": one.exit as u64,
                    "headline": one.headline,
                    "report": one.report.as_ref().map(Explanation::json),
                })
            })
            .collect();
        let out = json!({
            "record_type": "gitiup-hook-run-1",
            "hook": PRE_RECEIVE,
            "repo": repo.git_dir.display().to_string(),
            "proof_required": record.proof_required,
            "trusted_policy_signers": record.trust_key_ids,
            "policy": policy,
            "verdict": if refused.is_empty() { "accepted" } else { "refused" },
            "exit": code as u64,
            "refs": refs,
            "notes": notes,
            "open_refs": OPEN_REFS,
            "guarded_refs": [GUARDED],
        });
        println!("{out}");
    } else if quiet {
        for one in &decisions {
            println!(
                "gitiup: {:<8}{} {}",
                if one.accepted { "accepted" } else { "refused" },
                one.update.reference,
                one.update.short()
            );
        }
    } else {
        println!(
            "gitiup: {PRE_RECEIVE} — {} ref update(s) into {}",
            decisions.len(),
            repo.git_dir.display()
        );
        println!("gitiup: {:<9}{}", "policy", one_line(&policy));
        for note in &notes {
            println!("gitiup: {:<9}{}", "note", one_line(note));
        }
        for one in &decisions {
            println!(
                "gitiup: {:<9}{} {}  {}",
                if one.accepted { "accepted" } else { "REFUSED" },
                one.update.reference,
                one.update.short(),
                one_line(&one.headline)
            );
        }
        for one in &refused {
            if let Some(report) = &one.report {
                println!();
                print!("{}", report.text(false));
            }
        }
        if !refused.is_empty() {
            println!(
                "gitiup: the push is refused and no ref moved. Publish the proof first \
                 (`gitiup attest push --remote …`) and push the branch again — a push that \
                 files the proof and moves the branch in one transaction cannot be judged by \
                 that proof, because refs move only after this hook returns."
            );
        }
    }
    if refused.is_empty() {
        return Ok(());
    }
    Err(CliError::verdict(code))
}

/// The hook's stdin: `<old-oid> <new-oid> <ref>`, one line per ref.
fn read_updates() -> Result<Vec<Update>, CliError> {
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| CliError::io(format!("reading the ref updates on stdin: {e}")))?;
    Ok(parse_updates(&text))
}

/// The parser, split out so the edge cases are testable without a git transport: a ref
/// name with a space in it, blank lines, CRLF, and a line that is not three fields.
fn parse_updates(text: &str) -> Vec<Update> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let mut parts = line.splitn(3, ' ');
        let (Some(old), Some(new), Some(reference)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let reference = reference.trim();
        if old.is_empty() || new.is_empty() || reference.is_empty() {
            continue;
        }
        out.push(Update {
            old: old.to_string(),
            new: new.to_string(),
            reference: reference.to_string(),
        });
    }
    out
}

/// Is this file runnable? On unix the execute bit is the whole answer; everywhere else,
/// "it exists" is what git's own check amounts to.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hook's stdin format, including the cases a `printf` from a shell script hits:
    /// a trailing newline, a blank line, and a ref name with a space in it (legal, if
    /// inadvisable — and the third field is the rest of the line for exactly that reason).
    #[test]
    fn the_stdin_lines_are_read_as_git_writes_them() {
        let zero = "0000000000000000000000000000000000000000";
        let one = "9f2c8a1b2c3d4e5f60718293a4b5c6d7e8f90123";
        let updates = parse_updates(&format!(
            "{zero} {one} refs/heads/main\n\nnonsense\n{one} {zero} refs/heads/gone\n{one} {one} refs/heads/a ref with spaces\n"
        ));
        assert_eq!(
            updates.len(),
            3,
            "a blank line and a line with fewer than three fields are not ref updates"
        );
        assert_eq!(updates[0].reference, "refs/heads/main");
        assert!(updates[1].is_delete(), "an all-zero new oid is a delete");
        assert!(!updates[0].is_delete());
        assert_eq!(updates[2].reference, "refs/heads/a ref with spaces");
        assert_eq!(updates[0].short(), "9f2c8a1b");
    }

    /// Which side of the asymmetry a ref is on, in code: the guard is `refs/heads/` and
    /// nothing else, so the namespaces a proposal and its proof live in stay open.
    #[test]
    fn only_branches_are_guarded() {
        let update = |reference: &str| Update {
            old: String::new(),
            new: "9f2c8a1b2c3d4e5f60718293a4b5c6d7e8f90123".to_string(),
            reference: reference.to_string(),
        };
        assert!(update("refs/heads/main").guarded());
        assert!(update("refs/heads/feature/thing").guarded());
        assert!(
            !update("refs/heads/").guarded(),
            "an empty branch name is not a branch"
        );
        assert!(!update("refs/changes/chg-1/head").guarded());
        assert!(!update("refs/attestations/aa/bb").guarded());
        assert!(!update("refs/gitiup/policy/current").guarded());
        assert!(!update("refs/tags/v1").guarded());
        assert!(!update("HEAD").guarded());
    }

    #[test]
    fn a_path_with_a_quote_in_it_stays_one_argument() {
        assert_eq!(quote("/srv/git/it's.git"), r#"'/srv/git/it'\''s.git'"#);
    }

    /// The record is the gate's instructions, so what it round-trips is what the gate will
    /// do: the opt-out, the trust roots, and where it was installed.
    #[test]
    fn the_record_round_trips_what_the_gate_needs() {
        let record = Record {
            installed_at: TimeUs(1_760_000_000_000_000),
            installed_by: "gitiup test".to_string(),
            program: PathBuf::from("/usr/bin/gitiup"),
            proof_required: false,
            trust_key_ids: vec!["SHA256:aaa".to_string()],
            trust_from: "--trust, given at install time".to_string(),
            work_dir: PathBuf::from("/repo.git/info/gitiup/mirror"),
            script: PathBuf::from("/repo.git/hooks/pre-receive"),
            hooks_path: Some("/etc/git-hooks".to_string()),
            policy: Some(PolicyNote {
                source: "store".to_string(),
                revision: Some(2),
                body_digest: Some("sha256:bbb".to_string()),
                signed_by: Some("SHA256:aaa".to_string()),
                protects: vec!["refs/heads/**".to_string()],
                gate_eligible: true,
                read_at: TimeUs(1_760_000_000_000_000),
            }),
            notes: vec!["a note".to_string()],
        };
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("pre-receive.json");
        record.save(&path).expect("the record saves");
        let back = Record::load(&path)
            .expect("it loads")
            .expect("it was there");
        assert!(!back.proof_required, "the opt-out survives the round trip");
        assert_eq!(back.trust_key_ids, vec!["SHA256:aaa".to_string()]);
        assert_eq!(back.hooks_path.as_deref(), Some("/etc/git-hooks"));
        assert_eq!(
            back.policy.as_ref().expect("a policy note").revision,
            Some(2),
            "the policy the install saw is the policy the report compares against"
        );
        assert_eq!(
            back.roots(),
            Trust::KeyIds(["SHA256:aaa".to_string()].into())
        );
    }

    /// A file that is not this record is not touched — the same rule `uninstall` keeps.
    #[test]
    fn a_record_that_is_not_ours_is_refused_not_parsed() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("pre-receive.json");
        std::fs::write(&path, r#"{"record_type":"something-else"}"#).expect("write");
        let error = Record::load(&path).expect_err("a foreign record is not ours to read");
        assert_eq!(error.code, 6);
    }

    /// The marker is how a `hooks/pre-receive` is identified as ours, and the script that
    /// gets installed has to carry it or `uninstall` would refuse the file it wrote.
    #[test]
    fn the_installed_script_marks_itself_and_carries_the_help() {
        let repo = Repo {
            named: PathBuf::from("/srv/git/repo.git"),
            git_dir: PathBuf::from("/srv/git/repo.git"),
            bare: true,
            hooks_dir: PathBuf::from("/srv/git/repo.git/hooks"),
            hooks_path: None,
        };
        let script = script_text(&repo, &PathBuf::from("/usr/local/bin/gitiup"));
        assert!(script.starts_with("#!/bin/sh"), "git runs it as a script");
        assert!(script.contains(MARKER), "it says who wrote it");
        assert!(
            script.contains("unset GIT_DIR"),
            "the transport's environment is scrubbed before anything reads a repository"
        );
        assert!(
            script.contains(&quote("/usr/local/bin/gitiup")),
            "the program is quoted, not pasted"
        );
        assert!(script.contains("hook run pre-receive --repo /srv/git/repo.git"));
        assert!(
            script.contains("refs/changes/**"),
            "the asymmetry is written in the file itself, not only in `--help`"
        );
        assert!(!script_is_ours(Path::new("/nonexistent")));
    }
}

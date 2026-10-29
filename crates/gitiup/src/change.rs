//! `gitiup change …` — the contributor's side of a change, on any host (giti-b2z.3).
//!
//! Four commands, and they are the whole of the contributor's surface:
//!
//! ```text
//! gitiup change new      --base main           draft a record from local commits, write --out
//! gitiup change submit                         publish head ref + record to the resolved store
//! gitiup change list     [--state open] [--json]
//! gitiup change show     <id> [--json]
//! gitiup change checkout <id> [--for <job>]    fetch the change *and its proofs* into a clone
//! ```
//!
//! # `checkout`, which is the reviewer's whole command
//!
//! Everything else here is the author's side or the owner's side. `checkout` is the third
//! reader: someone with a clone of the repository and a change id, who wants the bytes and
//! the proof in one command and no argument to type twice. It fetches the change's own refs
//! and `refs/attestations/<head>/*` as *one* pack — the objects the change introduces and
//! nothing the clone already holds, with the attestations in the same packfile, which is the
//! property [host abstraction](../../../docs/host-abstraction.md) advertises and this is the
//! command that checks it held. It writes nothing to the store (a store that will only read
//! serves it), and it will not touch a dirty worktree: the paths are named and nothing moves.
//!
//! # Composition, exactly as `attest push` does it
//!
//! Every store is named, never described: `--store <dir>` or `--remote <name>`, and the
//! remote comes from `gitiup.toml` ([`crate::remotes`]). Nothing here chooses a URL
//! scheme, so a fs directory, a bare repository and a bucket are the same three commands
//! — which is the point of [ADR-0003](../../../docs/adr/0003-change-record-format-and-merge-semantics.md)
//! C7. A remote that wants a forge adapter this build was not compiled with is refused
//! *by name*, with the feature to enable in the hint, before anything is drafted: the
//! alternative is a `submit` that "succeeds" against a remote whose change database it
//! cannot read.
//!
//! # What a draft is, and what a submit is
//!
//! `new` reads a local repository with the plumbing (`rev-parse`, `merge-base`,
//! `rev-list`) and mints the record: the head it proposes, the base branch and the oid
//! that branch was at where this work forked, a one-line title, the jobs a verifier
//! should re-run. Then it signs. That is the whole content of the ticket's "who proposed
//! this is a signature and not a filename": `author.key_id` is the keystore key's
//! fingerprint, the signature is over the canonical body, and
//! [`ChangeId::derive`](gitiup_host::change::ChangeId::derive) re-derives the change's
//! name from those three facts, so a record cannot borrow an identity or a name.
//!
//! `submit` writes. The order is ADR-0003 D5's and is not negotiable: the objects the
//! change introduces, then the record bytes in the CAS, then the create-only attempt
//! ref, then `head` moved under the value just read. Nothing is force-pushed; a
//! force-push is a *new attempt*, which is what the next section is about.
//!
//! # A re-submit is an attempt, never an edit
//!
//! `change_id` is derived from the author, the base branch and the *anchor* — attempt 0's
//! head — so amending a commit and re-submitting cannot recompute its own name: a fresh
//! draft of amended work would open a second change and orphan the first one's
//! attestations. So the anchor is kept, not re-derived:
//!
//! * `change new` with no `--change` anchors at the current head: attempt 0 of a new
//!   change.
//! * `change new --change <handle>` (or `submit --change`) reads the store's attempt 0
//!   for its anchor and the highest attempt for `attempts.previous`, and drafts attempt
//!   *n + 1* of *that* change. If your key cannot produce that change's name — because
//!   the change was opened by someone else, or toward another branch — that is a refusal,
//!   not a new id.
//!
//! Either way `submit` re-reads the store before it writes, because the next index is
//! "one past the highest attempt present" and not "one past what `head` advertises"
//! (D6): that is what makes a submit that died between the two ref writes finishable
//! instead of needing an operator. Re-publishing bytes the store already holds is an
//! idempotent success (`already: true`); replacing bytes it already holds is a refusal
//! from [`publish_change`](gitiup_host::change::publish_change), never a force.
//!
//! # The base must be the base the store has
//!
//! `submit` reads `refs/heads/<base>` from the store and refuses, with exit **6** and
//! both oids in the message, when it is not the record's `base.oid`: an attempt whose
//! base has moved is an attempt that cannot merge, and finding that out at merge time is
//! how a rebase gets blamed on the reviewer. A store that has branch refs and not yours
//! is refused too, naming the branches it does have. A store with *no* branch refs at
//! all has not begun to describe itself — there is nothing to be stale against — so the
//! change is published with `base_check: "absent"` said out loud rather than a check
//! silently skipped.
//!
//! # Exit codes
//!
//! The same table as the rest of `gitiup` (ADR-0001 D7, ADR-0003 D11): 0 ok · 2 usage ·
//! 3 I/O or an unreachable store · 6 refused (no store named, unsigned record, stale
//! base, an attempt that already exists with a different head, a conflict; for
//! `checkout`: a dirty worktree, a bare repository, a store with no git object database,
//! a local ref that the change cannot fast-forward, no round for `--for`, or a live round
//! drawn against other bytes) · 7 a
//! signature that does not verify · 8 bytes that are not their own canonical form or a
//! digest that does not match — including a proof that arrived without its bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use gitiup_attest::{AttestationDoc, TimeUs};
use gitiup_host::change::{self, AttemptInfo, ChangeId, ChangeRecord, State, StoredRecord};
use gitiup_host::{
    Actor, Config, Host, HostKind, Namespace, Oid, PackFormat, PackRequest, RefName, RefQuery,
};
use gitiup_quorum::round::Round;
use gitiup_quorum::store as qstore;
use gitiup_quorum::verdict::VerdictRecord;
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::attest::{rfc3339, short};
use crate::keys::{self, Args};
use crate::participant::{self, Opened};
use crate::remotes;

/// Help for `gitiup change`.
pub const CHANGE_HELP: &str = "\
gitiup change — propose work to a store, with no forge

USAGE:
    gitiup change new       [OPTIONS]
    gitiup change submit    [OPTIONS]
    gitiup change list      [OPTIONS]
    gitiup change show      <ID> [OPTIONS]
    gitiup change checkout  <ID> [--for JOB] [--ref NAME]
    gitiup change merge     <ID> [--expected-oid OID] [--proof DIGEST] [--dry-run]
    gitiup change reconcile <ID> [--via store|forge] [--dry-run]

A change is one signed record in a content-addressed store, advertised by a ref
(ADR-0003). It is not a pull request: the record names the commit it proposes, the
branch it is proposed against and the oid that branch was at where this work forked,
and it is signed by the key that proposed it. `who proposed this` is a signature, so
a mirror, a bucket and a forge all say the same thing about it.

WHERE IT GOES (submit, list, show, checkout):
    --store <dir>            a directory as the store (the fs host)
    --remote <name>          a remote from gitiup.toml
                             `list` and `show` may read the configured default remote;
                             `submit` has to name its store, so a typo cannot publish a
                             change somewhere else. A remote that needs a forge adapter
                             this build was built without is refused by name, with the
                             feature to enable in the hint.

WHERE IT COMES FROM (new, submit):
    -C, --repository <path>  the repository to read (default: this one)
    --base <branch>          the branch the change is proposed against (required for new)
    --head <rev>             the commit to propose (default: HEAD)
    --change <ID>            continue that change: draft/publish the next attempt of it,
                             keeping its anchor instead of opening a second change

new — draft and sign a record from local commits:
    --title <text>           one line (default: the head commit's subject)
    --job <id>               ask a verifier to re-run this job (repeatable). With none
                             given, the job ids of the workflow file are asked for; an
                             empty list means \"no re-run requested\", which is not
                             \"run everything\" and not \"nothing is required\"
    --no-jobs                ask for nothing to be re-run
    -w, --workflow <path>    which workflow to take job ids from (default: the only file
                             in .github/workflows/)
    --key <selector>         which key signs (default: the current identity). A record is
                             always signed where it is drafted: an unsigned change is a
                             rumour, and a reader refuses one
    --out <path|->           where the record bytes go (default: stdout)

submit — publish one attempt:
    --record <path|->        the drafted record (default: draft it now, from the same
                             flags as `new`)
    --new-attempt            publish this even though the store already holds an attempt
                             with the same head (fixing a title or the job hint is a new
                             attempt; a re-run is not)
    --no-objects             do not push the commits this change introduces, because the
                             store already holds them
    --out <path|->           also write the exact bytes that were published

submit — on a forge remote (a github remote, with the hosts-github feature):
    --pull <number>          in new/submit: sign the record as carried by that pull request,
                             so the change's own bytes say the forge merges it. The number
                             is signed, so it has to be known before the record is; a change
                             submitted without it is matched to its pull by head commit
    --pull-branch <name>     which forge branch to open the pull request from. The forge will
                             open a pull from a branch and from nothing else, and
                             refs/changes/** is not one: with no branch over the change head
                             the forge is not asked, and that is printed
    --no-pull                file the change and do not ask the forge to carry it. The change
                             is then listed as one with no pull request (`source: ref`),
                             which is a state a forge can be in and not a failure
    --draft                  open the pull request as a draft

A forge is asked after the store has the change, and that is two calls rather than one
transaction: a change whose refs are filed and whose pull was not opened exists, is listed
as such, and is merged with the store's compare-and-swap because that is all there is. The
second call failing does not un-publish the first, does not exit non-zero for that reason,
and is printed as its own line (`pull not opened` plus the forge's reason) rather than left
for a reader to infer from a silence.

submit — the quorum rounds a published change needs:
    --no-quorum              publish without opening any round, even when the store's
                             published policy demands a quorum. The change then cannot
                             pass `gitiup verify change` until a selector opens one
                             (`gitiup select --change <id> … --publish`)
    --selector <key>         which keystore key derives and signs the round seeds
                             (default: --key). The seed is keyed on that key's Ed25519
                             seed (ADR-0002 D2), so an agent-held key cannot be a selector
    --seed-file <path|->     32 raw bytes (or 64 hex characters) as the selection secret,
                             for a delegated selector that holds no seed to derive from
    --trust <key|id>         whose policy signature counts here (repeatable; default: this
                             keystore). A policy this machine does not trust is reported
                             and never applied — a fork cannot set the rules (ADR-0004 D3)
    --explain                print each round's audit table: one row per roster entry with
                             its score, the first eligibility filter that rejected it, and
                             what the caps decided

A change whose published policy allows the `quorum` tier gets one round per job per matrix
arm, planned from the workflow files by the same planner `gitiup run` uses. The seat count,
the agreements required and the capability floor come from the policy's `quorum` block and
nowhere else — the tier a repository demands is data its owner signed, not a flag somebody
had to remember (ADR-0004 C4). The author's whole key family is excluded from every round,
and the exclusion is re-checked against the store's own bytes before the command says
success. A round that could not fill its `n` seats is published as `sufficient: false` with
the reasons its eligibility filters gave, is not advertised, and never lowers `n`.

list — every change the store advertises:
    --state <state>          open (default), merged, abandoned or all
    --json                   one line, sorted keys: per change its id, state, attempts,
                             head, base, whether the base is still what the store has,
                             author, title and both digests — and, against a forge remote,
                             `source` (ref · pull · both), `pull`, `url`, `copy_truncated`
                             and the forge's `caveats`

A forge answers `list` from two databases and says which one each row came from: a change
the store holds and the forge has no pull for is `source: ref`; a pull request with no
gitiup record behind it is `source: pull`, is listed and labelled (no signature covers it,
and nothing in it can be checked against the store), and is never skipped. Neither row is
the other's error.

show — one change, read back through the ref that advertises it:
    ID                       a change id or any unambiguous prefix of its hex (>= 4), or,
                             against a forge remote, `gh-<n>` for a pull request the store
                             holds no record of (shown as the forge's answer, labelled)
    --attempt <n>            show attempt n rather than the current one
    --bytes                  the exact stored bytes, and nothing else
    --json                   the record, its digests, its signature, the attempt chain,
                             the merge/abandon record if the change has one, and — on a
                             forge — the pull that carries it and what the forge cannot
                             promise about it

checkout — fetch one change, and its proofs, into a clone:
    ID                       the change to fetch (id, or 4+ hex of one)
    --repository, -C         the clone to fetch into (default: this one). It must have a
                             working tree: a bare repository has nothing to check out
    --ref <name>             the local branch to leave it on (default: the change id).
                             A name without refs/ goes under refs/heads/
    --attempt <n>            fetch attempt n rather than the current one
    --for <job>              also fetch that job's round, its seat submissions and its
                             verdict, and print them (build/matrix/linux-x86_64 is a job)
    --owner <key|id>         whose signature on a verdict counts (repeatable; default:
                             this machine's own keys, and the output says which)
    --detach                 look at it without a branch: detach HEAD at the change head
    --no-checkout            fetch and write the ref, and leave the worktree alone — the
                             one case a dirty worktree is allowed, because nothing in it
                             moves. --detach with --ref or with --no-checkout is refused
                             as usage: they contradict each other

checkout writes to the clone and never to the store: the pack is fetched, the store's refs
are not moved, and a store configured read-only serves it. It refuses a dirty worktree by
name (exit 6) rather than folding someone's uncommitted work into a review, and it refuses
to move a local branch that the change cannot fast-forward. The fetch is one pack carrying
refs/changes/<id>/* and refs/attestations/<head>/*, so the proof arrives with the bytes;
what the clone already held is not fetched twice, and the output counts the haves that made
that true. With --for the verdict is printed, not re-derived: `gitiup quorum verdict` is
the command whose exit code *is* the verdict.

merge — the owner's side: a compare-and-swap of the branch, then the record of it:
    ID                       the change to merge (id, or 4+ hex of one)
    --expected-oid <oid>     what the branch must hold. Default: the base.oid the author
                             signed, which is the honest default: it merges the attempt
                             the author could actually have merged. Naming another oid is
                             a decision of the owner's and is printed as one
    --proof <digest>         an attestation this merge believed (repeatable). Cited as a
                             digest in the merge record and pinned so retention cannot
                             retire it; the store must be able to return it, because a
                             digest nobody can fetch proves nothing
    --proof-required         refused on purpose: whether a merge is *allowed* is Epic 2's
                             policy engine, which does not exist yet, and \"no policy
                             found, merged anyway\" is not an answer. Verify the proofs
                             yourself and cite them with --proof
    --dry-run                print the plan and touch nothing, like `gitiup attest gc`
    --repository, -C, --key  where to prove the fast-forward, and who signs the record
    --json                   the plan or the outcome: both oids, the kv key, the ref, the
                             proofs, who signed and `via`

reconcile — write the record for a merge the store already has:
    ID                       the change whose branch already carries its head
    --via <store|forge>      who moved it (default: store)
    --landed <oid>           where a forge's merge left the branch, when that is not the
                             attempt's head (its own merge commit)
    --merge-method <how>     on a forge remote: ff (default) | merge | squash | rebase.
                             The default is gitiup's own rule — a merge commit exists
                             only after the merge, so no proof covers it

On a forge remote a change carried by a pull request is merged by the forge: its merge
is atomic and reviewed, and a ref write would only be an imitation of it. --json then
says \"via\": \"forge\" and what that promise is, because the two kinds of merge are not the
same guarantee and a script should not have to guess which one it got.

All: -j, --json on anything a script reads. Passphrases follow `gitiup key`:
--passphrase <text>, --passphrase-file <path|-> or GITIUP_KEY_PASSPHRASE, never a prompt a
script cannot answer.

A re-submit is never an overwrite. Amending the commits is attempt n+1 of the same
change (say which change with --change, because your amended head cannot recompute its
own name), and an attempt ref that exists is never moved: publishing different bytes
where an attempt already stands is refused with both digests.

A merge refuses, exit 6, with **both oids** when the branch is not what the record says
(\"pull first\" is the only useful advice) and when the change is not a fast-forward, and it
names the retry when the branch moved but its record did not land (`change reconcile`).
A refusal the store itself makes — a credential that may not write refs/heads/** — is
passed through in the store's own words and its own exit code, never retold as an I/O
error.

Exit codes: 0 ok · 2 usage · 3 I/O, store unreachable, a refusal the store owns (a denied
write) · 6 refused (no store, no key, unsigned record, stale base naming both oids,
attempt conflict, an id you cannot sign for, not a fast-forward, ancestry the tool cannot
check, --proof-required, a demanded quorum that cannot be opened: no roster, no
`quorum.requirements`, no derivable selector, no job, a round that seated its author; for
checkout: a dirty worktree — named, not guessed — a bare repository, a store with no git
object database, commits the store cannot return, a local ref the change would rewind, no
round for --for, a --for round drawn against other bytes) ·
7 a signature that does not verify · 8 bytes that are not the
record's own canonical form, or a digest that does not match its name — including a
change head or a proof that did not arrive with the pack.
";

/// Switches `gitiup change …` accepts.
const SWITCHES: &[&str] = &[
    "--no-jobs",
    "--no-objects",
    "--new-attempt",
    "--no-quorum",
    "--no-pull",
    "--draft",
    "--explain",
    "--bytes",
    "--dry-run",
    "--proof-required",
    "--detach",
    "--no-checkout",
];

/// Valued flags `gitiup change …` accepts.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--out",
    "--key",
    "--record",
    "--repository",
    "-C",
    "--base",
    "--head",
    "--change",
    "--title",
    "--job",
    "--workflow",
    "-w",
    "--state",
    "--attempt",
    "--passphrase",
    "--passphrase-file",
    "--expected-oid",
    "--proof",
    "--via",
    "--landed",
    "--merge-method",
    "--pull",
    "--pull-branch",
    "--selector",
    "--seed-file",
    "--trust",
    "--ref",
    "--for",
    "--owner",
];

/// `gitiup change …`
pub fn change(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{CHANGE_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{CHANGE_HELP}");
            Ok(())
        }
        "new" => new(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "submit" => submit(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "list" | "ls" => list(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "show" => show(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "checkout" => checkout(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "merge" => merge(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "reconcile" => reconcile(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        other => Err(CliError::usage(format!(
            "unknown `gitiup change` command '{other}'; `gitiup change help` lists new, \
             submit, list, show, checkout, merge and reconcile"
        ))),
    }
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

/// The store `--store`/`--remote` names, required: a change is published *somewhere*.
fn need_store(args: &Args) -> Result<Opened, CliError> {
    participant::need_store(args)
}

/// A store to read: the configured default remote is allowed here and not for a write.
pub(crate) fn read_store(args: &Args) -> Result<Opened, CliError> {
    participant::store_from(args)?.ok_or_else(|| {
        CliError::refused(
            "no store was named",
            "say where to look: --store <dir> or --remote <name> (see `gitiup doctor --remotes`)",
        )
    })
}

/// A host error keeps the code the library decided, so `gitiup change` and a merge gate
/// calling the same check cannot disagree about the same store.
pub(crate) fn host_error(what: &str, error: gitiup_host::HostError) -> CliError {
    CliError::scored(
        error.exit_code(),
        format!("{what}: {error}"),
        error.hint().map(str::to_string),
    )
}

/// The store's own branches, which is how "the store has no such branch" is told apart
/// from "the store has branches and none of them is yours".
fn store_branches(host: &dyn Host) -> Result<Vec<(String, Oid)>, CliError> {
    let refs = host
        .list_refs(&RefQuery::prefix("refs/heads"))
        .map_err(|e| host_error("list branches", e))?;
    Ok(refs
        .into_iter()
        .map(|reference| (reference.name.as_str().to_string(), reference.oid))
        .collect())
}

/// Where a change's base stands against the store.
#[derive(Debug, Clone)]
struct BaseCheck {
    /// `ok` · `absent` (the store has no branches at all) · `unknown` (not checked).
    state: &'static str,
    /// The oid the store has at the base ref, when it has one.
    store_oid: Option<String>,
}

/// ADR-0003 D8 step 3, done at submit time: an attempt whose base is not what the store
/// has is an attempt that cannot merge, so it is refused here rather than at the merge.
fn check_base(host: &dyn Host, record: &ChangeRecord) -> Result<BaseCheck, CliError> {
    let name = RefName::new(&record.base.branch).map_err(|e| {
        CliError::usage(format!(
            "the record's base '{}' is not a legal ref: {e}",
            record.base.branch
        ))
    })?;
    let want = Oid::from_hex(oid_hex(&record.base.oid)).map_err(|e| {
        CliError::refused(
            format!(
                "the record's base oid '{}' is not a store oid: {e}",
                record.base.oid
            ),
            "a base oid is algorithm-tagged lower-case hex, as `git rev-parse` prints it",
        )
    })?;
    match host
        .get_ref(&name)
        .map_err(|e| host_error("read the base ref", e))?
    {
        Some(found) if found.oid == want => Ok(BaseCheck {
            state: "ok",
            store_oid: Some(format_oid(&found.oid, &record.base.oid)),
        }),
        Some(found) => {
            // Both sides spelled the same way, because the whole point of the message is
            // the comparison: two oids that read differently invite a misread.
            let store_oid = format_oid(&found.oid, &record.base.oid);
            Err(CliError::refused(
                format!(
                    "{} is {} in this record and {} in the store",
                    record.base.branch, record.base.oid, store_oid
                ),
                format!(
                    "stale base: rebase onto {} (or re-draft from it) and submit again as a \
                     new attempt — a change whose base has moved is a change that cannot be \
                     merged (ADR-0003 D8 step 3)",
                    store_oid
                ),
            ))
        }
        None => {
            let branches = store_branches(host)?;
            if branches.is_empty() {
                return Ok(BaseCheck {
                    state: "absent",
                    store_oid: None,
                });
            }
            Err(CliError::refused(
                format!(
                    "the store has no {} — it has {}",
                    record.base.branch,
                    branches
                        .iter()
                        .map(|(name, _)| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                format!(
                    "a change is proposed against a branch the store has, because a merge is \
                     a compare-and-swap of that branch. Name the branch this work forks from \
                     with --base, or have the owner publish {}",
                    record.base.branch
                ),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// the local repository
// ---------------------------------------------------------------------------

/// A local repository, read with `git`'s plumbing and never written.
///
/// Only the *local* repository is touched here: everything that reaches the store goes
/// through the host traits, so `gitiup` never grows a second, worse `git push`.
struct Repo {
    dir: PathBuf,
}

impl Repo {
    /// The repository to read: `--repository`, else the current directory.
    fn discover(args: &Args) -> Result<Repo, CliError> {
        let dir = match args.get("--repository").or(args.get("-C")) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from("."),
        };
        let repo = Repo { dir };
        repo.text(&["rev-parse", "--is-bare-repository"])
            .map_err(|e| {
                CliError::refused(
                    format!(
                        "{} is not a git repository: {}",
                        repo.dir.display(),
                        e.message
                    ),
                    "run this in the repository the change comes from, or pass --repository <path>",
                )
            })?;
        Ok(repo)
    }

    /// Run `git -C <dir> <args>` and give back trimmed stdout.
    fn text(&self, args: &[&str]) -> Result<String, CliError> {
        let out = self.raw(args, None)?;
        Ok(String::from_utf8_lossy(&out).trim().to_string())
    }

    /// [`Repo::text`] where the byte output matters (a packfile).
    fn bytes(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, CliError> {
        self.raw(args, stdin)
    }

    fn raw(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, CliError> {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| CliError::io(format!("running git {args:?}: {e}")))?;
        if let Some(bytes) = stdin {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin is piped")
                .write_all(bytes)
                .map_err(|e| CliError::io(format!("feeding git {args:?}: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| CliError::io(format!("waiting for git {args:?}: {e}")))?;
        if !out.status.success() {
            return Err(CliError::refused(
                format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                "this command reads a repository with git's plumbing; the message above is git's",
            ));
        }
        Ok(out.stdout)
    }

    /// A revspec as an algorithm-tagged oid, refusing anything that looks like an option
    /// so a flag-shaped argument cannot become a flag.
    fn oid(&self, rev: &str, what: &str) -> Result<String, CliError> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err(CliError::usage(format!("'{rev}' is not a {what}")));
        }
        let hex = self.text(&["rev-parse", "--verify", "--quiet", rev])?;
        tag_oid(&hex).ok_or_else(|| {
            CliError::refused(
                format!(
                    "'{rev}' did not resolve to a commit in {}",
                    self.dir.display()
                ),
                format!("`git rev-parse --verify {rev}` had nothing to say about it"),
            )
        })
    }

    /// The branch a change is proposed against: the canonical `refs/heads/<branch>` the
    /// record will carry, and the commit it points at here.
    ///
    /// `main`, `refs/heads/main` and `origin/main` all name a branch to somebody; the
    /// record stores only the canonical form, because that is what a merge compares and
    /// what a mirror renames.
    fn branch(&self, name: &str) -> Result<(String, String), CliError> {
        let short = name
            .strip_prefix("refs/heads/")
            .unwrap_or(name)
            .trim_matches('/');
        if short.is_empty() || short.starts_with('-') || short.contains("..") {
            return Err(CliError::usage(format!(
                "'{name}' is not a branch name I can resolve"
            )));
        }
        let canonical = format!("refs/heads/{short}");
        let candidates = [
            canonical.clone(),
            format!("refs/remotes/{short}"),
            format!("refs/tags/{short}"),
            short.to_string(),
        ];
        let mut resolved = None;
        for candidate in &candidates {
            if let Ok(hex) = self.text(&["rev-parse", "--verify", "--quiet", candidate])
                && let Some(oid) = tag_oid(&hex)
            {
                resolved = Some(oid);
                break;
            }
        }
        match resolved {
            Some(oid) => Ok((canonical, oid)),
            None => Err(CliError::refused(
                format!("{} has no branch '{name}'", self.dir.display()),
                format!(
                    "`git -C {} branch -a` lists what it does have",
                    self.dir.display()
                ),
            )),
        }
    }

    /// The point where `head` forked from `base` — the oid a merge must find there.
    fn merge_base(&self, head: &str, base: &str) -> Result<Option<String>, CliError> {
        let out = self.raw(&["merge-base", oid_hex(head), oid_hex(base)], None);
        match out {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).trim().to_string();
                Ok(tag_oid(&text))
            }
            // `merge-base` exits 1 when the two histories are unrelated, which is an
            // answer and not a broken git.
            Err(_) => Ok(None),
        }
    }

    /// The head commit's subject line: a record's default title.
    fn subject(&self, head: &str) -> Result<String, CliError> {
        self.text(&["log", "-1", "--format=%s", oid_hex(head)])
    }

    /// How many commits the change introduces.
    fn commit_count(&self, base: &str, head: &str) -> Result<usize, CliError> {
        let text = self.text(&[
            "rev-list",
            "--count",
            &format!("{}..{}", oid_hex(base), oid_hex(head)),
        ])?;
        Ok(text.parse().unwrap_or(0))
    }

    /// The object ids the change introduces: everything reachable from `head` that is
    /// not reachable from `base`, which is exactly what the store cannot already have.
    fn introduced(&self, base: &str, head: &str) -> Result<Vec<String>, CliError> {
        let out = self.text(&[
            "rev-list",
            "--objects",
            oid_hex(head),
            "--not",
            oid_hex(base),
        ])?;
        let mut seen = BTreeSet::new();
        for line in out.lines() {
            if let Some(hex) = line.split_whitespace().next() {
                seen.insert(hex.to_string());
            }
        }
        Ok(seen.into_iter().collect())
    }

    /// Whether this repository holds the object at all.
    ///
    /// The fast-forward test needs both ends present; a repository that does not have one
    /// says so instead of guessing (ADR-0003 D8 step 4).
    fn holds(&self, hex: &str) -> bool {
        self.raw(&["cat-file", "-e", hex], None).is_ok()
    }

    /// A git packfile carrying `introduced(base, head)`.
    fn packfile(&self, objects: &[String]) -> Result<Vec<u8>, CliError> {
        let list = objects.join("\n");
        self.bytes(
            &["pack-objects", "--stdout", "--quiet", "--delta-base-offset"],
            Some(list.as_bytes()),
        )
    }

    /// The loose bytes of `objects`, for a host with no git object database (the raw
    /// pack gitiup speaks to an fs store or a bucket).
    fn loose(&self, objects: &[String]) -> Result<Vec<Vec<u8>>, CliError> {
        if objects.is_empty() {
            return Ok(Vec::new());
        }
        let list = objects.join("\n");
        let out = self.bytes(
            &["cat-file", "--batch"],
            Some(format!("{list}\n").as_bytes()),
        )?;
        parse_batch(&out)
    }

    /// Whether this repository has a working tree to check a change out into.
    ///
    /// Asked before anything is fetched, because "nothing moved" is the only honest
    /// answer a bare repository can give to `checkout`.
    fn bare(&self) -> Result<bool, CliError> {
        Ok(self.text(&["rev-parse", "--is-bare-repository"])? == "true")
    }

    /// The paths that differ from `HEAD` — staged, unstaged, added, deleted, conflicted.
    ///
    /// Untracked files are not dirt: they belong to whoever left them there, they survive
    /// a checkout, and git itself refuses a checkout that would overwrite one. Everything
    /// else is work someone has not committed, which is the thing a review must not
    /// silently land on top of.
    fn dirty_paths(&self) -> Result<Vec<String>, CliError> {
        let out = self.bytes(&["status", "--porcelain", "--untracked-files=no"], None)?;
        let text = String::from_utf8_lossy(&out);
        Ok(text
            .lines()
            // `XY <path>`: the two status columns and a space are not part of the name,
            // which is why this cannot go through [`Repo::text`] — the first column is
            // often a space, and trimming the output would eat it.
            .filter_map(|line| line.get(3..))
            .map(|path| {
                // A rename is `R  old -> new`; the new path is the one that exists.
                let path = path.rsplit(" -> ").next().unwrap_or(path);
                path.trim_end().to_string()
            })
            .filter(|path| !path.is_empty())
            .collect())
    }

    /// Every ref tip this repository holds, as bare hex.
    ///
    /// These are the haves a fetch is told about, so a change costs its own commits and
    /// not the history the clone already shares with the store.
    fn ref_tips(&self) -> Result<Vec<String>, CliError> {
        let out = self.text(&["for-each-ref", "--format=%(objectname)"])?;
        let mut out: Vec<String> = out
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        // A detached HEAD has no ref to be found by, and its commit is a legitimate have.
        if let Ok(head) = self.text(&["rev-parse", "--verify", "--quiet", "HEAD"])
            && !head.is_empty()
            && !out.contains(&head)
        {
            out.push(head);
        }
        Ok(out)
    }

    /// The oid a ref name holds here, bare hex, when it holds anything.
    fn ref_oid(&self, name: &str) -> Result<Option<String>, CliError> {
        match self.text(&["rev-parse", "--verify", "--quiet", name]) {
            Ok(hex) if !hex.is_empty() => Ok(Some(hex)),
            Ok(_) => Ok(None),
            // `--quiet` means "no such ref" is a non-zero exit and no output, and that
            // answer is not an error to report.
            Err(_) => Ok(None),
        }
    }

    /// The git oid `bytes` would have as a blob — without writing them anywhere.
    ///
    /// A git store carries an attestation as the blob of exactly its canonical bytes
    /// (the pointer commit's `record`), so this is how a checkout proves the proof
    /// arrived rather than that a ref mentioned it.
    fn blob_oid(&self, bytes: &[u8]) -> Result<String, CliError> {
        self.bytes(&["hash-object", "-t", "blob", "--stdin"], Some(bytes))
            .map(|out| String::from_utf8_lossy(&out).trim().to_string())
    }

    /// Take a packfile into this repository's object database.
    fn index_pack(&self, bytes: &[u8]) -> Result<(), CliError> {
        self.bytes(&["index-pack", "--stdin"], Some(bytes))?;
        Ok(())
    }

    /// Whether `from` is an ancestor of `to` (both hex oids this repository holds).
    fn is_ancestor(&self, from: &str, to: &str) -> bool {
        self.raw(&["merge-base", "--is-ancestor", from, to], None)
            .is_ok()
    }

    /// Run a git command that changes this repository, keeping git's own words on a
    /// refusal (a branch that is checked out elsewhere, a path in the way).
    fn change(&self, args: &[&str]) -> Result<(), CliError> {
        self.raw(args, None)?;
        Ok(())
    }
}

/// Parse `git cat-file --batch` output: `<oid> <type> <size>\n<content>\n` per object.
fn parse_batch(out: &[u8]) -> Result<Vec<Vec<u8>>, CliError> {
    let mut objects = Vec::new();
    let mut index = 0usize;
    while index < out.len() {
        let end = out[index..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|at| index + at)
            .ok_or_else(|| CliError::io("git cat-file --batch ended in the middle of a header"))?;
        let header = String::from_utf8_lossy(&out[index..end]).to_string();
        index = end + 1;
        let fields: Vec<&str> = header.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(CliError::io(format!(
                "git cat-file --batch said '{header}' where an object was expected"
            )));
        }
        let size: usize = fields[2]
            .parse()
            .map_err(|_| CliError::io(format!("git cat-file --batch said '{header}': no size")))?;
        if index + size > out.len() {
            return Err(CliError::io("git cat-file --batch was cut off mid-object"));
        }
        objects.push(out[index..index + size].to_vec());
        index += size + 1;
    }
    Ok(objects)
}

/// `sha1:`/`sha256:` in front of bare hex, which is how a record spells an oid
/// (ADR-0001 D2: an oid that does not name its algorithm is a guess).
fn tag_oid(hex: &str) -> Option<String> {
    let hex = hex.trim();
    let algo = match hex.len() {
        40 => "sha1",
        64 => "sha256",
        _ => return None,
    };
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{algo}:{hex}"))
}

/// The hex body of an algorithm-tagged oid.
fn oid_hex(tagged: &str) -> &str {
    tagged.split_once(':').map(|(_, hex)| hex).unwrap_or(tagged)
}

/// An oid as the store spelled it, when the record's spelling is the one a human typed:
/// both oids in a stale-base message have to read the same way.
fn format_oid(store: &Oid, like: &str) -> String {
    let algo = like.split_once(':').map(|(algo, _)| algo).unwrap_or("sha1");
    format!("{algo}:{}", store.hex())
}

// ---------------------------------------------------------------------------
// who is signing
// ---------------------------------------------------------------------------

/// The author of a record: this machine's key, and the display name that goes with it.
///
/// `principal` is display only and says so (D2); `key_id` is what everything downstream
/// believes, because it is re-derived from the public key the signature carries.
struct Identity {
    key: gitiup_keys::signer::Key,
    key_id: String,
    principal: String,
}

impl Identity {
    fn here(args: &Args) -> Result<Identity, CliError> {
        let keystore = participant::keystore()?;
        let key = participant::signing_key(args, &keystore)?;
        let record = key.record();
        let principal = keystore
            .config
            .identity
            .handle
            .clone()
            .or_else(|| record.comment.clone())
            .unwrap_or_else(|| record.name.clone());
        Ok(Identity {
            // The principal is a display string with a byte limit and no control
            // characters; neither is a reason to refuse a key, so it is cleaned rather
            // than enforced, and nobody may authorise on it anyway.
            principal: display(&principal),
            key_id: record.key_id.clone(),
            key,
        })
    }
}

/// A display string inside the format's limits: one line, at most
/// `MAX_PRINCIPAL_BYTES` bytes, cut on a character boundary.
fn display(text: &str) -> String {
    let one_line: String = text.chars().filter(|c| !c.is_control()).take(200).collect();
    let mut out = one_line.trim().to_string();
    while out.len() > gitiup_host::change::MAX_PRINCIPAL_BYTES {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// drafting
// ---------------------------------------------------------------------------

/// What the store says about the change being continued, if it says anything.
struct Continued {
    /// The handle the user gave, resolved.
    handle: String,
    /// The change's own id, as the store spells it.
    id: ChangeId,
    /// Attempt 0's head: the anchor, which is why continuing needs the store.
    anchor: String,
    /// The next attempt number, and the `change_digest` it replaces.
    index: u32,
    previous: Option<String>,
    /// The branch the change was opened against, so a mismatch is a refusal.
    base: String,
}

/// A drafted record, with the facts a human or a script wants alongside it.
struct Draft {
    record: ChangeRecord,
    bytes: Vec<u8>,
    /// How many commits the change introduces, when it was drafted from a repository.
    commits: Option<usize>,
    /// Where `workflow.jobs` came from: `--job`, `workflow`, `--no-jobs` or nothing.
    jobs_from: String,
    /// `new` for attempt 0, or the handle a later attempt was drafted against.
    continues: Option<String>,
}

/// Enough of a digest or an object id to compare by eye: the head and the tail of the
/// hex, with the algorithm kept. The whole value is always in `--json`, and `show` prints
/// it in full; this is the at-a-glance form, where a 40-hex sha1 is the width of a
/// paragraph and the middle of it is never what you were looking for.
fn short_id(value: &str) -> String {
    let (algo, hex) = match value.split_once(':') {
        Some((algo, hex)) => (format!("{algo}:"), hex),
        None => (String::new(), value),
    };
    if hex.len() > 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        format!("{algo}{}\u{2026}{}", &hex[..8], &hex[hex.len() - 4..])
    } else {
        value.to_string()
    }
}

/// The record's own digest, in the same `sha256:` shape as every other digest the CLI
/// prints and compares. The bare hex is a storage key (`kv/change/<hex>`); everything a
/// human or a script reads carries the algorithm, so a sha1 and a sha256 never look like
/// the same kind of thing.
fn record_digest(record: &ChangeRecord) -> String {
    record.digest().map(tagged).unwrap_or_default()
}

/// An `Oid` the way a record spells one. `Oid`'s own `Display` is the bare hex, which is
/// right for a storage key and wrong for anything a person or a script compares: an oid
/// that does not name its algorithm is a guess (ADR-0001 D2).
fn tagged(oid: Oid) -> String {
    tag_oid(&oid.hex()).unwrap_or_else(|| oid.hex())
}

impl Draft {
    fn summary(&self, extra: &[(&str, Value)]) -> Value {
        let record = &self.record;
        let mut value = json!({
            "change": record.change_id.as_str(),
            "attempt": record.attempts.index,
            "anchor": record.attempts.anchor,
            "previous": record.attempts.previous,
            "change_digest": record
                .change_digest()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
            "record_digest": record_digest(record),
            "base": { "ref": record.base.branch, "oid": record.base.oid },
            "head": record.head,
            "title": record.title,
            "jobs": record.workflow.jobs,
            "jobs_from": self.jobs_from,
            "author": { "key_id": record.author.key_id, "principal": record.author.principal },
            "signed": !record.signatures.is_empty(),
            "signers": record
                .signatures
                .iter()
                .map(|entry| entry.key_id.clone())
                .collect::<Vec<_>>(),
            "created_at": rfc3339(record.created_at_us),
            "created_at_us": record.created_at_us,
            "commits": self.commits,
            "continues": self.continues,
            "size": self.bytes.len(),
        });
        if let Some(map) = value.as_object_mut() {
            for (key, value) in extra {
                map.insert((*key).to_string(), value.clone());
            }
        }
        value
    }
}

/// The jobs the author asks a verifier to re-run (ADR-0003 D9).
///
/// Sorted and deduplicated because the format requires it and a hint that arrives in a
/// different order every attempt would look like a change of mind.
fn requested_jobs(args: &Args, repo: &Repo) -> Result<(Vec<String>, String), CliError> {
    let mut given = args.all("--job");
    if args.on("--no-jobs") && !given.is_empty() {
        return Err(CliError::usage("--job and --no-jobs contradict each other"));
    }
    if args.on("--no-jobs") {
        return Ok((Vec::new(), "--no-jobs".to_string()));
    }
    if given.is_empty() {
        let (path, text) = match workflow_file(args, repo) {
            Some(found) => found,
            None => {
                return Ok((
                    Vec::new(),
                    "none found (pass --job <id>, or --no-jobs to say so on purpose)".to_string(),
                ));
            }
        };
        let workflow = gitiup_run::Workflow::parse(&path, &text)?;
        let ids: Vec<String> = workflow.jobs.iter().map(|job| job.id.clone()).collect();
        if ids.is_empty() {
            return Err(CliError::refused(
                format!("{path} declares no jobs"),
                "the hint names job ids the way `gitiup run --job` spells them",
            ));
        }
        given = ids;
        let source = format!("workflow {path}");
        return Ok((sorted_dedup(given), source));
    }
    given.sort();
    given.dedup();
    let source = "--job".to_string();
    Ok((given, source))
}

/// The workflow to take job ids from: the one named, else the repository's only one.
/// Unlike `gitiup run`, an absent workflow is not a refusal here: an empty hint is a
/// legal answer, and a contributor with no workflow file has nothing to ask to be re-run.
fn workflow_file(args: &Args, repo: &Repo) -> Option<(String, String)> {
    if let Some(path) = args.get("--workflow").or(args.get("-w")) {
        let text = std::fs::read(path).ok()?;
        return Some((path.to_string(), String::from_utf8_lossy(&text).to_string()));
    }
    let dir = repo.dir.join(".github/workflows");
    let mut found: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yml") | Some("yaml")
            ) {
                found.push(path);
            }
        }
    }
    found.sort();
    let only = found.first()?;
    if found.len() != 1 {
        return None;
    }
    let text = std::fs::read(only).ok()?;
    // Named the way the repository knows it, because that is what a reader of the
    // record's `jobs` looks for next time they are standing in the repository.
    let shown = only
        .strip_prefix(&repo.dir)
        .unwrap_or(only.as_path())
        .display()
        .to_string();
    Some((shown, String::from_utf8_lossy(&text).to_string()))
}

fn sorted_dedup(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// One line, inside the format's title limit, with the record's own refusal kept honest
/// by leaving anything odd to `validate()` rather than second-guessing it here.
fn default_title(args: &Args, repo: &Repo, head: &str) -> Result<String, CliError> {
    if let Some(title) = args.get("--title") {
        return Ok(title.trim().to_string());
    }
    let subject = repo.subject(head)?;
    let mut title = subject.trim().to_string();
    while title.len() > gitiup_host::change::MAX_TITLE_BYTES {
        title.pop();
    }
    if title.is_empty() {
        return Err(CliError::refused(
            "the head commit has no subject line to take a title from",
            "give the change one: --title <one line>",
        ));
    }
    Ok(title)
}

/// What the store holds for one change: its attempts, oldest first.
fn attempts_in(host: &dyn Host, id: &ChangeId) -> Result<Vec<AttemptInfo>, CliError> {
    change::change_history(host, id).map_err(|e| host_error("read the change's attempts", e))
}

/// Resolve a handle the way D3 says to: exact, else an unambiguous prefix of the hex,
/// and when two changes could be meant, both are named and neither is picked.
pub(crate) fn resolve_handle(
    host: &dyn Host,
    handle: &str,
) -> Result<change::ChangeSummary, CliError> {
    let catalog = change::list_changes(host).map_err(|e| host_error("list changes", e))?;
    let matches = catalog.resolve(handle);
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(CliError::refused(
            format!("no change matching '{handle}' in this store"),
            "`gitiup change list --state all` shows what it holds",
        )),
        many => Err(CliError::refused(
            format!(
                "'{handle}' could be {} changes: {}",
                many.len(),
                many.iter()
                    .map(|change| change.change_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "give more of the id — a change id is 16 hex, and 4 is the shortest handle \
             this tool will guess from (ADR-0003 D3)",
        )),
    }
}

/// Read what continuing a change means: its anchor, its next attempt, its branch.
fn continue_change(host: &dyn Host, handle: &str) -> Result<Continued, CliError> {
    let found = resolve_handle(host, handle)?;
    let id = found.change_id.clone();
    let history = attempts_in(host, &id)?;
    let Some(first) = history.first() else {
        return Err(CliError::refused(
            format!("{id} has no attempt refs to take an anchor from"),
            "the anchor of a change is attempt 0's head; without it a reader cannot re-derive \
             the id, so a new attempt cannot be written either (ADR-0003 D3, D6)",
        ));
    };
    let last = history.last().expect("non-empty history");
    Ok(Continued {
        handle: handle.to_string(),
        base: last.base.branch.clone(),
        id,
        anchor: first.head.clone(),
        index: last.index + 1,
        previous: Some(last.change_digest.clone()),
    })
}

// ---------------------------------------------------------------------------
// new
// ---------------------------------------------------------------------------

/// Draft the record from local commits and this machine's identity (D2, D3, D9).
///
/// Nothing is written to any store here — the only store read is the one `--change`
/// names, and only to learn a change's anchor.
fn draft(args: &Args, store: Option<&Opened>) -> Result<Draft, CliError> {
    let repo = Repo::discover(args)?;
    let head = match args.get("--head") {
        Some(rev) => repo.oid(rev, "commit-ish")?,
        None => repo.oid("HEAD", "commit")?,
    };
    let continued = match args.get("--change") {
        Some(handle) => {
            let opened = store.ok_or_else(|| {
                CliError::refused(
                    "--change needs the store to read from",
                    "the anchor of a change is attempt 0's head, and only the store has it: \
                     name --store <dir> or --remote <name> with --change, or leave --change \
                     out to open a new change",
                )
            })?;
            Some(continue_change(&*opened.host, handle)?)
        }
        None => None,
    };
    let base_name = match (args.get("--base"), &continued) {
        (Some(name), _) => name.to_string(),
        (None, Some(found)) => found.base.clone(),
        (None, None) => {
            return Err(CliError::usage(
                "say what the change is proposed against: --base <branch> (as in `gitiup \
                 change new --base main`)",
            ));
        }
    };
    let (base_ref, base_tip) = repo.branch(&base_name)?;
    if let Some(found) = &continued
        && found.base != base_ref
    {
        return Err(CliError::refused(
            format!(
                "{} is proposed against {}, not {base_ref}",
                found.id, found.base
            ),
            "the base branch is part of what a change *is*: proposing the same work at \
                 another branch is another change (ADR-0003 D3)",
        ));
    }
    let base_oid = repo.merge_base(&head, &base_tip)?.ok_or_else(|| {
        CliError::refused(
            format!(
                "{head} and {base_ref} ({base_tip}) share no history, so there is no point \
                 for {base_ref} to be compared against"
            ),
            "rebase the work onto the branch, or name the branch it really forked from with \
             --base",
        )
    })?;
    let commits = repo.commit_count(&base_oid, &head)?;
    if commits == 0 {
        return Err(CliError::refused(
            format!("{head} proposes nothing on top of {base_ref} ({base_tip})"),
            "the head is already on the branch: there is nothing to publish as a change",
        ));
    }
    let who = Identity::here(args)?;
    let (anchor, index, previous, continues) = match &continued {
        Some(found) => (
            found.anchor.clone(),
            found.index,
            found.previous.clone(),
            Some(found.handle.clone()),
        ),
        None => (head.clone(), 0, None, None),
    };
    let change_id = ChangeId::derive(&who.key_id, &base_ref, &anchor)
        .map_err(|e| host_error("derive the change id", e))?;
    if let Some(found) = &continued
        && found.id != change_id
    {
        return Err(CliError::refused(
            format!(
                "{base_ref} anchored at {anchor}, signed by {}, is {change_id} — not {}",
                short(&who.key_id),
                found.id
            ),
            format!(
                "{} was opened by a different key, or from different commits. A change's name \
                 is derived from its author, its base branch and its anchor, so only the key \
                 that opened it can write its next attempt (ADR-0003 D3)",
                found.id
            ),
        ));
    }
    let (jobs, jobs_from) = requested_jobs(args, &repo)?;
    let title = default_title(args, &repo, &head)?;
    let record = ChangeRecord {
        annotations: None,
        attempts: change::Attempts {
            anchor,
            index,
            previous,
        },
        author: change::Author {
            key_id: who.key_id.clone(),
            principal: who.principal.clone(),
        },
        base: change::Base {
            branch: base_ref,
            oid: base_oid,
        },
        change_id,
        created_at_us: TimeUs::now().as_us(),
        head,
        origin: match args.get("--pull") {
            // A signed claim, not a lookup: the number has to be known before the record is
            // signed, because it is part of what the signature covers. A change opened
            // without it is matched to its pull by head commit instead, which is a fact
            // about oids and can change under nobody's feet.
            Some(text) => change::Origin::pull(
                text.trim()
                    .trim_start_matches("gh-")
                    .parse::<u64>()
                    .map_err(|_| {
                        CliError::usage(format!("--pull '{text}' is not a pull request number"))
                    })?,
            ),
            None => change::Origin::store(),
        },
        schema_version: change::SCHEMA_VERSION,
        signatures: Vec::new(),
        title,
        record_type: change::CHANGE_TYPE.to_string(),
        workflow: change::Workflow { jobs },
    };
    record.validate().map_err(|e| host_error("the record", e))?;
    // Always signed, always by the author: a change's identity *is* its signature, so
    // there is no useful draft that is not one (ADR-0003 D2).
    let record = record
        .sign(&who.key)
        .map_err(|e| host_error("sign the record", e))?;
    let bytes = record
        .canonical_bytes()
        .map_err(|e| host_error("canonicalise the record", e))?;
    Ok(Draft {
        record,
        bytes,
        commits: Some(commits),
        jobs_from,
        continues,
    })
}

fn new(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = participant::store_from(args)?;
    let draft = draft(args, store.as_ref())?;
    let written = match args.get("--out") {
        Some(path) => {
            participant::write_out(path, &draft.bytes)?;
            Some(path.to_string())
        }
        None if args.json() => None,
        None => {
            std::io::stdout()
                .write_all(&draft.bytes)
                .map_err(|e| CliError::io(format!("write stdout: {e}")))?;
            None
        }
    };
    if args.json() {
        print_json(draft.summary(&[("written", json!(written))]));
        return Ok(());
    }
    let record = &draft.record;
    let to = if written.is_some() || args.json() {
        Box::new(std::io::stdout()) as Box<dyn Write>
    } else {
        Box::new(std::io::stderr()) as Box<dyn Write>
    };
    let mut to = std::io::BufWriter::new(to);
    let _ = writeln!(
        to,
        "{} {}",
        if draft.continues.is_some() {
            "attempt"
        } else {
            "change"
        },
        record.change_id
    );
    let _ = writeln!(
        to,
        "  attempt  {} · anchor {}",
        record.attempts.index,
        short_id(&record.attempts.anchor)
    );
    let _ = writeln!(
        to,
        "  base     {} @ {} ({commits} commits)",
        record.base.branch,
        short_id(&record.base.oid),
        commits = draft.commits.unwrap_or(0)
    );
    let _ = writeln!(to, "  head     {}", short_id(&record.head));
    let _ = writeln!(to, "  title    {}", record.title);
    let _ = writeln!(
        to,
        "  jobs     {} ({})",
        if record.workflow.jobs.is_empty() {
            "(none requested)".to_string()
        } else {
            record.workflow.jobs.join(", ")
        },
        draft.jobs_from
    );
    let _ = writeln!(
        to,
        "  author   {} ({}) · {}",
        short(&record.author.key_id),
        record.author.principal,
        if record.signatures.is_empty() {
            "unsigned"
        } else {
            "signed"
        }
    );
    let _ = writeln!(
        to,
        "  digests  change {} · record {}",
        short_id(&record.change_digest().unwrap_or_default()),
        short_id(&record_digest(record))
    );
    match &written {
        Some(path) => {
            let _ = writeln!(to, "  written  {path}");
            let _ = writeln!(
                to,
                "  next     gitiup change submit --record {path} --store <dir>"
            );
        }
        None => {
            let _ = writeln!(
                to,
                "  note     these are the exact bytes that would be published; --out <path> \
                 writes them and --json prints the summary instead"
            );
        }
    }
    drop(to);
    Ok(())
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------

/// What happened to the commits a change introduces (D5's step 1).
struct ObjectReport {
    form: &'static str,
    objects: usize,
    bytes: usize,
    note: Option<String>,
}

impl ObjectReport {
    /// The form in the words a person reads; `--json` carries the machine name.
    fn phrase(&self) -> String {
        match self.form {
            "git-packfile" => "as a git packfile".to_string(),
            "raw" => "as gitiup raw objects".to_string(),
            "nothing-new" => "none, the base already has them".to_string(),
            _ => "none, --no-objects".to_string(),
        }
    }

    fn json(&self) -> Value {
        json!({
            "form": self.form,
            "objects": self.objects,
            "bytes": self.bytes,
            "note": self.note,
        })
    }
}

/// Push the commits the change introduces, before anything advertises them (D5).
///
/// "What the store does not have" is computed from the base oid, which is exactly the
/// oid the base check above just proved the store has — so the pack is the change's own
/// commits and nothing else, and a force-push costs a force-push rather than a re-upload
/// of history.
fn push_objects(
    host: &dyn Host,
    repo: &Repo,
    args: &Args,
    record: &ChangeRecord,
) -> Result<ObjectReport, CliError> {
    if args.on("--no-objects") {
        return Ok(ObjectReport {
            form: "skipped",
            objects: 0,
            bytes: 0,
            note: Some("--no-objects: the store was said to hold the commits already".into()),
        });
    }
    let objects = repo
        .introduced(oid_hex(&record.base.oid), oid_hex(&record.head))
        .map_err(|e| {
            CliError::refused(
                e.message,
                "the commits come from a local repository: run this there, pass \
                 --repository <path>, or say --no-objects if the store already holds them",
            )
        })?;
    if objects.is_empty() {
        return Ok(ObjectReport {
            form: "nothing-new",
            objects: 0,
            bytes: 0,
            note: Some("the store's base already contains every object this change needs".into()),
        });
    }
    match host.kind() {
        gitiup_host::HostKind::Git => {
            let bytes = repo.packfile(&objects)?;
            let len = bytes.len();
            let pack = gitiup_host::Pack::git_packfile(bytes)
                .map_err(|e| host_error("build the packfile", e))?;
            host.put_pack(&pack)
                .map_err(|e| host_error("push the commits", e))?;
            Ok(ObjectReport {
                form: "git-packfile",
                objects: objects.len(),
                bytes: len,
                note: None,
            })
        }
        kind => {
            // A store with no git object database keeps the objects as gitiup records:
            // the store can answer for their bytes, but a plain `git fetch` of the change
            // cannot carry them, and the difference is said out loud rather than hidden.
            let loose = repo.loose(&objects)?;
            let len: usize = loose.iter().map(Vec::len).sum();
            let pack = gitiup_host::Pack::from_raw_objects(
                loose
                    .into_iter()
                    .map(|bytes| (Namespace::const_new("git-object"), bytes)),
            )
            .map_err(|e| host_error("build the pack", e))?;
            host.put_pack(&pack)
                .map_err(|e| host_error("push the commits", e))?;
            Ok(ObjectReport {
                form: "raw",
                objects: objects.len(),
                bytes: len,
                note: Some(format!(
                    "a {} store has no git object database: the objects are filed as gitiup \
                     records, so `git fetch` of the change will not carry them",
                    kind.as_str()
                )),
            })
        }
    }
}

/// Line the attempt number up with what the store actually holds (D6).
///
/// The next index is one past the highest attempt *present*, never one past what `head`
/// advertises, so a submit that died between the two ref writes is finished by the next
/// one. Re-publishing the same bytes is left alone: `publish_change` calls it `already`.
fn fit_attempt(
    host: &dyn Host,
    args: &Args,
    record: &ChangeRecord,
) -> Result<(ChangeRecord, Option<String>), CliError> {
    let history = attempts_in(host, &record.change_id)?;
    let Some(last) = history.last() else {
        if record.attempts.index == 0 {
            return Ok((record.clone(), None));
        }
        return Err(CliError::refused(
            format!(
                "this record is attempt {} and the store holds no attempts of {}",
                record.attempts.index, record.change_id
            ),
            "attempt 0 comes first: the chain is what makes an attempt auditable (ADR-0003 D6)",
        ));
    };
    let mine = record.change_digest().unwrap_or_default();
    let same_head = last.head == record.head;
    let next = if last.head == record.head && last.change_digest == mine {
        last.index
    } else if same_head && !args.on("--new-attempt") {
        return Err(CliError::refused(
            format!(
                "attempt {} of {} already proposes {}",
                last.index, record.change_id, record.head
            ),
            format!(
                "there is nothing to publish: the store already holds this commit as attempt \
                 {}. Restating the record (a title, the job hint) is attempt {} and must be \
                 said out loud with --new-attempt, because the old attempt's attestations \
                 have to stay where they are (ADR-0003 D6)",
                last.index,
                last.index + 1
            ),
        ));
    } else {
        last.index + 1
    };
    if next == record.attempts.index {
        return Ok((record.clone(), None));
    }
    let anchor = history
        .first()
        .map(|attempt| attempt.head.clone())
        .unwrap_or_else(|| record.attempts.anchor.clone());
    if anchor != record.attempts.anchor {
        return Err(CliError::refused(
            format!(
                "{}'s anchor in this store is {anchor} and the record says {}",
                record.change_id, record.attempts.anchor
            ),
            "the anchor is attempt 0's head and never changes; a record that disagrees with \
             it belongs to a different change (ADR-0003 D3)",
        ));
    }
    let who = Identity::here(args)?;
    if record.author.key_id != who.key_id {
        return Err(CliError::refused(
            format!(
                "attempt {next} has to be signed by {} and this machine signs as {}",
                short(&record.author.key_id),
                short(&who.key_id)
            ),
            "renumbering an attempt changes the signed body, so it needs the author's key: \
             run this as the identity that opened the change, or with --key <name>",
        ));
    }
    let mut refitted = record.clone();
    refitted.attempts = change::Attempts {
        anchor,
        index: next,
        previous: Some(last.change_digest.clone()),
    };
    let refitted = refitted
        .sign(&who.key)
        .map_err(|e| host_error("re-sign the attempt", e))?;
    Ok((
        refitted,
        Some(format!(
            "the store's highest attempt is {}; this was published as attempt {next} so the \
             chain stays unbroken (ADR-0003 D6)",
            last.index
        )),
    ))
}

fn submit(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = need_store(args)?;
    let mut drafted: Option<Draft> = None;
    let record = match args.get("--record") {
        Some(path) => {
            let bytes = participant::read_maybe_stdin(path)?;
            // A record with no signature deserves a sentence of its own: the library's
            // reader refuses it among all the shape failures, and "carries exactly one
            // signature" is not the advice a person needs at 1am.
            if serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|value| value.get("signatures")?.as_array().cloned())
                .is_some_and(|signatures| signatures.is_empty())
            {
                return Err(CliError::refused(
                    "this record carries no signature",
                    "an unsigned change is a rumour, and a reader refuses it: sign it where \
                     the key is — `gitiup change new` signs with this machine's identity",
                ));
            }
            ChangeRecord::from_canonical_bytes(&bytes).map_err(|e| host_error("the record", e))?
        }
        None => {
            let made = draft(args, Some(&store))?;
            let record = made.record.clone();
            drafted = Some(made);
            record
        }
    };
    // D11's order: bytes, digests, derivations, signature — all of it before the store
    // is touched, because a record that cannot stand up to a reader should never be
    // half-published.
    record.verify().map_err(|e| host_error("the record", e))?;
    let (record, refitted) = fit_attempt(&*store.host, args, &record)?;
    let base = check_base(&*store.host, &record)?;
    // The quorum this change's published policy asks for, decided and derived before a
    // single byte is written (giti-zp1.2). A round that cannot stand up to a reader must not
    // be half-published any more than a record that cannot, and the author's exclusion is
    // checked here — while refusing still means nothing was written — rather than after.
    let mut quorum = crate::quorum::plan(args, &store, &record)?;
    let objects = if args.on("--no-objects") {
        ObjectReport {
            form: "skipped",
            objects: 0,
            bytes: 0,
            note: Some("--no-objects: the store was said to hold the commits already".into()),
        }
    } else {
        push_objects(&*store.host, &Repo::discover(args)?, args, &record)?
    };
    let actor = Actor::from(short(&record.author.key_id));
    let published = change::publish_change(&*store.host, &record, actor)
        .map_err(|e| host_error("publish the change", e))?;
    if let Some(path) = args.get("--out") {
        participant::write_out(
            path,
            &record
                .canonical_bytes()
                .map_err(|e| host_error("canonicalise", e))?,
        )?;
    }
    // The rounds pin the change, so they are written after it: an advertisement that points
    // at no round is an invitation to nothing, and a round nobody advertises is invisible to
    // the volunteers it needs (giti-zp1.1). Each one is read back and re-derived here before
    // this command is allowed to say it succeeded.
    quorum.publish(&store)?;
    // A forge is asked to carry the change *after* the store has it, and that is two calls
    // and not one transaction: the second can fail on its own terms without undoing the
    // first. So this reports what happened instead of pretending the pair is atomic — a
    // change with a ref and no pull is a state a forge can be in, and `change list`
    // labels it rather than hiding it.
    let carried = carry_on_forge(args, forge_remote(args)?.as_ref(), &record)?;
    let catalog = change::list_changes(&*store.host).map_err(|e| host_error("read it back", e))?;
    let state = catalog
        .changes
        .iter()
        .find(|change| change.change_id == record.change_id)
        .map(|change| change.state.as_str())
        .unwrap_or("open");
    // The trap D3 warns about, caught after the fact rather than before: a fresh change
    // by the same key against the same branch, when that key already has another open
    // change there, is usually an amended re-push that forgot `--change`.
    let siblings: Vec<String> = catalog
        .changes
        .iter()
        .filter(|change| {
            change.state == State::Open
                && change.change_id != record.change_id
                && published.attempt == Some(0)
        })
        .filter_map(|change| {
            let digest = change.head.or_else(|| change.newest_attempt_digest())?;
            let Some((StoredRecord::Change(other), _)) =
                change::read_stored(&*store.host, &digest).ok().flatten()
            else {
                return None;
            };
            (other.author.key_id == record.author.key_id && other.base.branch == record.base.branch)
                .then(|| format!("{}", change.change_id))
        })
        .collect();

    if args.json() {
        print_json(json!({
            "store": store.what,
            "change": record.change_id.as_str(),
            "attempt": published.attempt,
            "anchor": record.attempts.anchor,
            "previous": record.attempts.previous,
            "state": state,
            "already": published.already,
            "reference": published.reference.as_str(),
            "head_ref": published.head_ref.as_str(),
            "record_digest": tagged(published.record_digest),
            "change_digest": record.change_digest().unwrap_or_default(),
            "kv": change::kv_key(&change::CHANGE_NAMESPACE, &published.record_digest),
            "size": published.size,
            "base": {
                "ref": record.base.branch,
                "oid": record.base.oid,
                "store_oid": base.store_oid,
                "check": base.state,
            },
            "head": record.head,
            "title": record.title,
            "jobs": record.workflow.jobs,
            "author": { "key_id": record.author.key_id, "principal": record.author.principal },
            "objects": objects.json(),
            "quorum": quorum.json(),
            "note": refitted,
            "other_open_by_same_author": siblings,
            "pull": carried
                .as_ref()
                .map(Carried::json)
                .unwrap_or(Value::Null),
        }));
        return Ok(());
    }
    println!(
        "{} {} attempt {}",
        if published.already {
            "already filed:"
        } else {
            "submitted"
        },
        record.change_id,
        published.attempt.map(|n| n.to_string()).unwrap_or_default(),
    );
    println!("  store    {}", store.what);
    println!(
        "  base     {} @ {} [{}]",
        record.base.branch,
        short_id(&record.base.oid),
        match base.state {
            "ok" => "the store agrees".to_string(),
            "absent" => "the store has no branches at all, so this could not be checked; \
                         a merge will refuse until the branch exists"
                .to_string(),
            other => other.to_string(),
        }
    );
    println!(
        "  head     {} ({} objects, {} bytes, {})",
        short_id(&record.head),
        objects.objects,
        objects.bytes,
        objects.phrase()
    );
    if let Some(note) = &objects.note {
        println!("  objects  {note}");
    }
    println!("  title    {}", record.title);
    println!(
        "  jobs     {}",
        if record.workflow.jobs.is_empty() {
            "(none requested)".to_string()
        } else {
            record.workflow.jobs.join(", ")
        }
    );
    println!(
        "  author   {} ({})",
        short(&record.author.key_id),
        record.author.principal
    );
    println!("  ref      {}", published.reference);
    println!(
        "  head ref {} -> {}",
        published.head_ref,
        short_id(&tagged(published.record_digest))
    );
    println!(
        "  record   {} ({} bytes)",
        change::kv_key(&change::CHANGE_NAMESPACE, &published.record_digest),
        published.size
    );
    println!(
        "  digests  change {} · record {}",
        short_id(&record.change_digest().unwrap_or_default()),
        short_id(&tagged(published.record_digest))
    );
    if let Some(carried) = &carried {
        carried.text();
    }
    quorum.text();
    if let Some(note) = &refitted {
        eprintln!("note: {note}");
    }
    if !siblings.is_empty() {
        eprintln!(
            "note: this key has {} other open change(s) against {} ({}). If this was a \
             re-push of one of them, next time say `--change <id>` so it becomes an attempt \
             of that change instead of a second one.",
            siblings.len(),
            record.base.branch,
            siblings.join(", ")
        );
    }
    let _ = &drafted;
    Ok(())
}

// ---------------------------------------------------------------------------
// merge — the owner's side (ADR-0003 D8)
// ---------------------------------------------------------------------------

/// The refusal that keeps `--proof-required` honest.
///
/// There is no policy engine yet (it is Epic 2), so the honest answer is a refusal that
/// says who is missing and what to do instead. The alternative — "no policy found, merged
/// anyway" — is the one failure mode a merge gate must never have, and a `--dry-run` that
/// quietly agreed would be the same failure wearing a costume.
fn policy_engine_missing(flag: &str) -> CliError {
    CliError::refused(
        format!(
            "{flag} asks whether a merge is *allowed*, and there is no policy engine in \
             this build yet"
        ),
        "policy is Epic 2's, and deliberately not a field of the change record (ADR-0003 \
         D9): a contributor who could write \"no checks needed\" into the object being \
         merged has written their own gate. Until it lands, decide it yourself — `gitiup \
         verify attestation <file> --trust …` answers 0/6/7/8 for one proof — and cite \
         each proof you believed with --proof <digest>, so the merge record says what it \
         believed rather than saying nothing",
    )
}

/// A refusal the store owns, in the store's words.
///
/// `gitiup change merge` is the owner's credential against the owner's branch, and the
/// branch is the one ref the tool does not own. A refusal from the store — a hook, a
/// read-only token, a `pre-receive` that says no — keeps its taxonomy label, its message,
/// its hint and the exit code its kind implies. Rewriting it into "I/O error" throws away
/// the only useful sentence in the run.
fn store_refusal(error: gitiup_host::HostError) -> CliError {
    use gitiup_host::HostErrorExt as _;
    let message = if error.is_denied() {
        format!("{}: {}", error.kind(), error.message())
    } else {
        error.message()
    };
    CliError::scored(error.exit_code(), message, error.hint().map(str::to_string))
}

/// The `author` of a merge record: whoever signed it, which is the merger and not the
/// change's author (D7).
fn merger(who: &Identity) -> change::Author {
    change::Author {
        key_id: who.key_id.clone(),
        principal: who.principal.clone(),
    }
}

/// The proof digests this merge says it believed, each one checked against the store.
///
/// A merge record that cites a digest the store cannot return is evidence about an object
/// nobody can produce, which is the reason `proofs` holds digests in the first place (D8:
/// a copy can be edited; a digest you cannot fetch is no better). So a citation the store
/// cannot honour is a refusal, and a merge may cite nothing instead — which says nothing,
/// rather than appearing to have believed everything.
fn cited_proofs(store: &dyn Host, args: &Args) -> Result<Vec<String>, CliError> {
    let mut out = Vec::new();
    for text in args.all("--proof") {
        let hex = text.strip_prefix("sha256:").unwrap_or(&text).to_string();
        let oid = Oid::from_hex(&hex).map_err(|_| {
            CliError::usage(format!(
                "--proof '{text}' is not a digest: an attestation is named by sha256:, 64 \
                 lower hex"
            ))
        })?;
        if oid.hex().len() != 64 {
            return Err(CliError::usage(format!(
                "--proof '{text}' is not a sha256 digest ({} hex is a {})",
                oid.hex().len(),
                if oid.hex().len() == 40 {
                    "git oid, which is not what a proof is named by"
                } else {
                    "shortened digest, and a merge record cites the whole thing"
                }
            )));
        }
        if !proof_is_stored(store, &oid)? {
            return Err(CliError::refused(
                format!(
                    "this store cannot return sha256:{}, so this merge cannot cite it",
                    oid.hex()
                ),
                "file the proof first (`gitiup attest push`), or cite nothing: an empty \
                 `proofs` says the merge believed no attestation, which is honest, while a \
                 digest nobody can fetch is neither (ADR-0003 D8)",
            ));
        }
        out.push(format!("sha256:{}", oid.hex()));
    }
    Ok(out)
}

/// Whether the store can return the bytes behind a digest.
fn proof_is_stored(store: &dyn Host, digest: &Oid) -> Result<bool, CliError> {
    Ok(store
        .head(digest)
        .map_err(|e| host_error("read the proof", e))?
        .is_some())
}

/// What the local repository can honestly say about "is the branch an ancestor of the
/// change?" (D8 step 4).
///
/// The objects have to be *here*: a store keeps commits as opaque bytes and a ref as a
/// number, and the question is about parents. A repository that does not hold one of the
/// two commits produces `Unknown`, which [`merge`] refuses — guessing a fast-forward is
/// how other people's commits get dropped, and it is the reason this command will not
/// "just try it" without the objects.
fn fast_forward(args: &Args, from: &str, to: &str) -> change::Ancestry {
    let repo = match Repo::discover(args) {
        Ok(repo) => repo,
        Err(why) => return change::Ancestry::Unknown(why.message),
    };
    for oid in [from, to] {
        if !repo.holds(oid_hex(oid)) {
            return change::Ancestry::Unknown(format!("{oid} is not in {}", repo.dir.display()));
        }
    }
    match repo.merge_base(to, from) {
        Ok(Some(base)) if oid_hex(&base) == oid_hex(from) => change::Ancestry::FastForward,
        // Anything else — a merge base that is not the branch tip, two histories that
        // never meet, a git that could not answer — is a divergence. It is the caller's
        // job to say so rather than to hope.
        Ok(_) | Err(_) => change::Ancestry::Diverged,
    }
}

/// The request both `merge` and `reconcile` need, built the same way.
fn merge_request<'a>(
    record: &'a ChangeRecord,
    who: &'a Identity,
    proofs: &[String],
    expected: Option<Oid>,
    at_us: Option<i64>,
) -> change::MergeRequest<'a> {
    let mut request = change::MergeRequest::new(record, &who.key, merger(who))
        .with_ancestry(change::Ancestry::Unknown("not computed yet".to_string()));
    if let Some(oid) = expected {
        request = request.with_expected(oid);
    }
    if let Some(at) = at_us {
        request = request.at(at);
    }
    for proof in proofs {
        request = request.with_proof(proof.clone());
    }
    request
}

/// `--expected-oid`, in the shape the record uses.
fn expected_oid(text: &str, record: &ChangeRecord) -> Result<Oid, CliError> {
    let hex = match text.split_once(':') {
        Some((algo, hex)) if algo == "sha1" || algo == "sha256" => hex,
        _ => text,
    };
    Oid::from_hex(hex).map_err(|e| {
        CliError::usage(format!(
            "--expected-oid '{text}' is not an oid: {e}. Spell it the way {} spells its \
             base ({}), or give the bare hex",
            record.base.branch, record.base.oid
        ))
    })
}

/// What a merge would do, printed by everything it touched nothing.
fn print_plan(
    store: &Opened,
    record: &ChangeRecord,
    plan: &change::MergePlan,
    ancestry: &change::Ancestry,
    who: &Identity,
    json: bool,
    verb: &str,
) -> Result<(), CliError> {
    let ancestry_word = ancestry.as_str().to_string();
    let would_refuse = matches!(ancestry, change::Ancestry::Diverged);
    if json {
        print_json(json!({
            "store": store.what,
            "dry_run": true,
            "verb": verb,
            "would_write": !would_refuse,
            "refused": would_refuse,
            "reason": if would_refuse { "not a fast-forward" } else { "" },
            "change": plan.change_id.as_str(),
            "attempt": plan.attempt,
            "change_digest": plan.change_digest,
            "branch": plan.branch.as_str(),
            "from": spell_oid(&plan.from, record),
            "to": spell_oid(&plan.to, record),
            "store_oid": spell_oid(&plan.store_oid, record),
            "signed_base": plan.signed_base,
            "base_overridden": plan.base_overridden,
            "ancestry": ancestry_word,
            "ancestry_note": ancestry.why(),
            "merged_ref": plan.merged_ref.as_str(),
            "kv": plan.kv,
            "proofs": plan.proofs,
            "via": plan.via.as_str(),
            "merger": { "key_id": who.key_id, "principal": who.principal },
            "head": record.head,
            "title": record.title,
            "notes": plan.notes,
        }));
        return if would_refuse {
            Err(CliError::refused(
                format!(
                    "{} is not an ancestor of {}, so this merge would drop commits",
                    plan.from, plan.to
                ),
                "a dry run reports the refusal it would have hit rather than a plan it \
                 could not carry out (ADR-0003 D8 step 4)",
            ))
        } else {
            Ok(())
        };
    }
    println!("plan    {verb} · nothing written (--dry-run)");
    println!("  store   {}", store.what);
    println!(
        "  change  {} attempt {} · {}",
        plan.change_id, plan.attempt, record.title
    );
    println!(
        "  branch  {} {} → {}",
        plan.branch,
        short_id(&plan.from.to_string()),
        short_id(&plan.to.to_string())
    );
    println!(
        "  check   {} [{}] {}",
        short_id(&plan.from.to_string()),
        ancestry_word,
        match ancestry {
            change::Ancestry::FastForward => "a fast-forward: no commits would be dropped",
            change::Ancestry::Diverged =>
                "WOULD REFUSE — the branch has commits the change does not",
            change::Ancestry::Unknown(why) => why.as_str(),
        }
    );
    if plan.base_overridden {
        println!(
            "  base    the author signed {}; the CAS expects {}",
            short_id(&plan.signed_base),
            short_id(&plan.from.to_string())
        );
    }
    println!(
        "  record  {}/<digest of the signed record>, advertised by {}",
        plan.kv, plan.merged_ref
    );
    println!(
        "  proofs  {}",
        if plan.proofs.is_empty() {
            "none — the record will say the merge believed nothing".to_string()
        } else {
            format!("{} cited, and pinned against retention", plan.proofs.len())
        }
    );
    println!("  signed  {} ({})", short(&who.key_id), who.principal);
    for note in &plan.notes {
        eprintln!("note: {note}");
    }
    if would_refuse {
        return Err(CliError::refused(
            format!(
                "{} is not an ancestor of {}, so this merge would drop commits",
                plan.from, plan.to
            ),
            "the plan above is what a merge would do, and this is the step it would refuse \
             at (ADR-0003 D8 step 4)",
        ));
    }
    Ok(())
}

fn merge(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    // First, before a store is opened or a key is touched: a flag that asks for a policy
    // decision has to be refused while there is nothing to make it from.
    if args.on("--proof-required") {
        return Err(policy_engine_missing("--proof-required"));
    }
    let store = need_store(args)?;
    let handle = positional_handle(args, "merge")?;
    let found = resolve_handle(&*store.host, &handle)?;
    let id = found.change_id.clone();
    let record = head_record(&*store.host, &id)?;
    let who = Identity::here(args)?;
    let proofs = cited_proofs(&*store.host, args)?;
    let expected = match args.get("--expected-oid") {
        Some(text) => Some(expected_oid(text, &record)?),
        None => None,
    };
    let request = merge_request(&record, &who, &proofs, expected, None);
    // The plan is everything a merge can learn from the store without writing: this is
    // the fresh read that is the lease, and the same call a dry run stops at.
    let plan = change::plan_merge(&*store.host, &request).map_err(store_refusal)?;
    let ancestry = fast_forward(
        args,
        &spell_oid(&plan.from, &record),
        &spell_oid(&plan.to, &record),
    );
    // The one case where gitiup does not move the branch itself: a change a forge
    // carries is merged by the forge, whose merge is atomic and reviewed, and whose
    // ref write a bucket is only ever imitating (ADR-0003 D10). `--json` says which
    // kind of merge happened, because they are not the same promise.
    let forge = forge_remote(args)?;
    if let Some(number) = carrying_pull(forge.as_ref(), &record)? {
        let Some(handle) = forge.as_ref() else {
            return Err(CliError::refused(
                format!(
                    "{} is carried by pull request {number}, but no forge remote was named",
                    record.change_id
                ),
                "the forge's merge is the only merge a carried change has (--remote <name>)",
            ));
        };
        if args.on("--dry-run") {
            return print_forge_plan(&store, args, &record, &plan, number, &proofs);
        }
        let outcome = merge_on_forge(&store, args, &plan, request.via_forge(), number, handle)?;
        return print_outcome(&store, &record, &outcome, &who, args.json(), Some(number));
    }
    if args.on("--dry-run") {
        return print_plan(
            &store,
            &record,
            &plan,
            &ancestry,
            &who,
            args.json(),
            "merge",
        );
    }
    let outcome = change::merge(&*store.host, &request.with_ancestry(ancestry.clone()))
        .map_err(store_refusal)?;
    print_outcome(&store, &record, &outcome, &who, args.json(), None)
}

/// A forge and the credentials it asked for, kept together so the forge path reads as one
/// thing rather than two tuple elements passed side by side.
///
/// Only a `gitiup.toml` remote can be a forge — `--store` names a directory — and the
/// classification is the composition root's, so nothing in this file knows what a forge
/// *is*; it only knows that some remotes have a merge button, a pull-request database and
/// branches a pull can be opened from, and some do not.
fn forge_remote(args: &Args) -> Result<Option<remotes::Forge>, CliError> {
    let named = match args.get("--remote") {
        Some(name) => name.to_string(),
        None => return Ok(None),
    };
    let Some((_path, config)) =
        Config::load_default().map_err(|e| CliError::io(format!("gitiup.toml: {e}")))?
    else {
        return Ok(None);
    };
    let remote = config.remote_or_default(Some(&named)).map_err(|e| {
        CliError::refused(
            format!("gitiup.toml: {e}"),
            "name a remote that exists, or use --store <dir>",
        )
    })?;
    if !crate::remotes::wants_forge(remote) {
        return Ok(None);
    }
    Ok(Some(remotes::Forge::new(
        remote,
        config.credential_profile(remote),
    )))
}

/// What a merge did, in whichever form was asked for.
///
/// One printer for all three ways a merge happens — the CAS write, the reconcile of a move
/// that already happened, and a forge's merge — because the facts worth printing are the
/// same in each, and a third copy of the block is how `--json` and the text part ways.
fn print_outcome(
    store: &Opened,
    record: &ChangeRecord,
    outcome: &change::MergeOutcome,
    who: &Identity,
    json: bool,
    pull: Option<u64>,
) -> Result<(), CliError> {
    if json {
        let mut value = merge_json(store, record, outcome, who);
        if let Some(number) = pull {
            value["pull"] = json!(number);
        }
        print_json(value);
        return Ok(());
    }
    println!(
        "{}  {} attempt {}",
        if outcome.moved { "merged" } else { "recorded" },
        outcome.plan.change_id,
        outcome.plan.attempt
    );
    println!("  store    {}", store.what);
    println!(
        "  branch   {} {} → {}  [{}]",
        outcome.plan.branch,
        short_id(&spell_oid(&outcome.plan.from, record)),
        short_id(&spell_oid(&outcome.plan.to, record)),
        if outcome.moved {
            format!(
                "cas {}",
                short_id(&spell_oid(&outcome.plan.store_oid, record))
            )
        } else {
            "untouched by this call".to_string()
        },
    );
    println!(
        "  via      {}",
        match outcome.plan.via {
            change::Via::Store if outcome.moved => "store (gitiup moved the ref under CAS)",
            change::Via::Store => "store (the move had already happened; this is its record)",
            change::Via::Forge => "forge (the forge moved it; gitiup recorded where it landed)",
        }
    );
    if let Some(number) = pull {
        println!("  pull     {number}");
    }
    println!("  head     {} · {}", short_id(&record.head), record.title);
    println!(
        "  record   {} ({} bytes) · {}",
        outcome.plan.kv, outcome.size, outcome.reference
    );
    println!(
        "  digests  change {} · merge {}",
        short_id(&outcome.plan.change_digest),
        short_id(&tagged(outcome.record_digest))
    );
    println!(
        "  proofs   {}",
        if outcome.proofs_pinned == 0 {
            "none believed — the record says so".to_string()
        } else {
            format!(
                "{} believed, cited as digests and pinned so retention keeps them",
                outcome.proofs_pinned
            )
        }
    );
    println!("  signed   {} ({})", short(&who.key_id), who.principal);
    for note in &outcome.plan.notes {
        eprintln!("note: {note}");
    }
    Ok(())
}

/// `gitiup change reconcile` — the retry for D8's failure window, and the way a forge's
/// merge gets a record.
fn reconcile(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = need_store(args)?;
    let handle = positional_handle(args, "reconcile")?;
    let found = resolve_handle(&*store.host, &handle)?;
    let id = found.change_id.clone();
    let record = head_record(&*store.host, &id)?;
    let who = Identity::here(args)?;
    let proofs = cited_proofs(&*store.host, args)?;
    let expected = match args.get("--expected-oid") {
        Some(text) => Some(expected_oid(text, &record)?),
        None => None,
    };
    let via = match args.get("--via").unwrap_or("store") {
        "store" => change::Via::Store,
        "forge" => change::Via::Forge,
        other => {
            return Err(CliError::usage(format!(
                "--via '{other}' is not store or forge"
            )));
        }
    };
    let mut request = merge_request(&record, &who, &proofs, expected, None);
    if via == change::Via::Forge {
        request = request.via_forge();
    }
    if let Some(text) = args.get("--landed") {
        request = request.with_landing(expected_oid(text, &record)?);
    }
    if args.on("--dry-run") {
        println!("plan    reconcile · nothing written (--dry-run)");
        println!("  store   {}", store.what);
        println!(
            "  change  {} attempt {} · {}",
            id, record.attempts.index, record.title
        );
        println!(
            "  record  the branch already carries {}; write kv/merge/<digest> and advertise \
             it by {}",
            short_id(&record.head),
            change::merged_ref(&id)
        );
        println!("  via     {via}");
        return Ok(());
    }
    let outcome = change::record_merge(&*store.host, &request).map_err(store_refusal)?;
    print_outcome(&store, &record, &outcome, &who, args.json(), None)
}

/// The merge outcome as data: what moved, where the record is, and who says so.
fn merge_json(
    store: &Opened,
    record: &ChangeRecord,
    outcome: &change::MergeOutcome,
    who: &Identity,
) -> Value {
    json!({
        "store": store.what,
        "change": outcome.plan.change_id.as_str(),
        "attempt": outcome.plan.attempt,
        "change_digest": outcome.plan.change_digest,
        "branch": outcome.plan.branch.as_str(),
        "from": spell_oid(&outcome.plan.from, record),
        "to": spell_oid(&outcome.plan.to, record),
        "moved": outcome.moved,
        "via": outcome.plan.via.as_str(),
        "atomicity": match outcome.plan.via {
            change::Via::Store => "a conditional write: the CAS says nobody else moved the \
                                    branch, and the ancestry test says nothing was dropped",
            change::Via::Forge => "the forge's own merge: atomic and reviewed, which a \
                                   bucket's conditional write cannot promise",
        },
        "merged_ref": outcome.reference.as_str(),
        "record_digest": tagged(outcome.record_digest),
        "kv": outcome.plan.kv,
        "size": outcome.size,
        "proofs": outcome.record.proofs,
        "proofs_pinned": outcome.proofs_pinned,
        "policy_digest": outcome.record.policy_digest,
        "merged_at": rfc3339(outcome.record.merged_at_us),
        "merged_at_us": outcome.record.merged_at_us,
        "merger": { "key_id": who.key_id, "principal": who.principal },
        "head": record.head,
        "title": record.title,
        "notes": outcome.plan.notes,
    })
}

/// The change's current record, read through the ref that advertises it (D8 step 1), so
/// a record that lies about its digest or its head is refused before any branch is
/// touched — 8 for a digest, 7 for a signature, 6 for a store binding.
fn head_record(host: &dyn Host, id: &ChangeId) -> Result<ChangeRecord, CliError> {
    let fetched = change::change_at(host, &change::change_head_ref(id)).map_err(store_refusal)?;
    match fetched.record {
        StoredRecord::Change(record) => Ok(record),
        other => Err(CliError::refused(
            format!(
                "{} holds a {} record",
                fetched.reference,
                other.record_type()
            ),
            "a change's head holds a gitiup-change-1 record",
        )),
    }
}

/// The change the command line named.
fn positional_handle(args: &Args, verb: &str) -> Result<String, CliError> {
    args.positional
        .first()
        .cloned()
        .or_else(|| args.get("--change").map(str::to_string))
        .ok_or_else(|| {
            CliError::usage(format!(
                "say which change to {verb}: `gitiup change {verb} <ID>` (a change id, or \
                 4+ hex of one)"
            ))
        })
}

/// Spell an oid the way the record spells its own, so a message and a comparison read as
/// the same kind of thing (ADR-0001 D2).
fn spell_oid(oid: &Oid, record: &ChangeRecord) -> String {
    format_oid(oid, &record.base.oid)
}

// ---------------------------------------------------------------------------
// the forge's own merge, and its own change list (ADR-0003 D10)
// ---------------------------------------------------------------------------

/// Which pull request carries this change, which is what decides which merge runs.
///
/// There are two ways to know, and they are not equally good. The record can *say*: a
/// `origin: Pull { number }` is signed, so it outranks any lookup. Otherwise the forge is
/// asked which of its open pulls proposes this very commit, and exactly one answer is the
/// only one gitiup will act on — two pulls over one head is somebody's ambiguity to
/// resolve, not a coin this tool gets to flip.
fn carrying_pull(
    forge: Option<&remotes::Forge>,
    record: &ChangeRecord,
) -> Result<Option<u64>, CliError> {
    if record.origin.kind == change::OriginKind::Pull {
        // The signed claim stands whether or not a forge was named; the caller refuses the
        // second case, because there is nothing to ask.
        return Ok(record.origin.number);
    }
    let Some(forge) = forge else {
        return Ok(None);
    };
    let head = Oid::from_hex(oid_hex(&record.head)).map_err(|e| {
        CliError::refused(
            format!("{}'s head is not an oid: {e}", record.change_id),
            "a pull request is matched to a change by the commit it proposes",
        )
    })?;
    let found = forge.open_pulls_at(&head)?;
    match found.as_slice() {
        [] => Ok(None),
        [one] => Ok(one.pull()),
        many => Err(CliError::refused(
            format!(
                "{}'s head is proposed by {} open pulls: {}",
                record.change_id,
                many.len(),
                many.iter()
                    .filter_map(|change| change.pull())
                    .map(|number| number.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "gitiup will not guess which of them is the one that merges: say which change \
             you mean by drafting its record with --pull <number>, or close the other",
        )),
    }
}

/// Ask the forge to merge its own change, then write the record of what it did.
///
/// gitiup does not touch the branch here. The forge merged it — atomically, under its own
/// protection rules — and the record says `via: forge` and attests only what the forge
/// reports, which is the whole of ADR-0003 D10's budget for a pull request.
fn merge_on_forge(
    store: &Opened,
    args: &Args,
    plan: &change::MergePlan,
    mut request: change::MergeRequest<'_>,
    number: u64,
    forge: &remotes::Forge,
) -> Result<change::MergeOutcome, CliError> {
    let landing = forge.merge(number, &plan.to, &merge_method(args)?)?;
    // gitiup did not move the branch; the forge did, to a commit no attestation can cover
    // unless the forge fast-forwarded. So the record is a reconcile with `via: forge`, and
    // it names the commit the store now holds rather than the one a fast-forward would
    // have written (ADR-0003 D10).
    request = request.via_forge().with_landing(landing);
    change::record_merge(&*store.host, &request).map_err(store_refusal)
}

/// What a forge said when it was asked to carry a change.
///
/// Three answers are possible and all three are printed: it opened one, it already had
/// one, or it was not asked / could not / refused. The last is not a failed submit — the
/// change is in the store, which is the part that carries the signature — but it is not a
/// success either, and a silent line about a pull request that does not exist would be
/// both.
struct Carried {
    change: Option<remotes::ForgeChange>,
    note: Option<String>,
}

impl Carried {
    /// Nothing was opened, and the reason is said.
    fn without(note: impl Into<String>) -> Carried {
        Carried {
            change: None,
            note: Some(note.into()),
        }
    }

    fn json(&self) -> Value {
        match (&self.change, &self.note) {
            (Some(change), None) => change.json(),
            (Some(change), Some(note)) => {
                let mut value = change.json();
                if let Some(map) = value.as_object_mut() {
                    map.insert("note".to_string(), json!(note));
                }
                value
            }
            (None, Some(note)) => json!({ "opened": false, "note": note }),
            (None, None) => Value::Null,
        }
    }

    fn text(&self) {
        match (&self.change, &self.note) {
            (Some(change), None) => println!(
                "  pull     {} · {} · [source: {}]{}",
                change.id,
                change.state,
                change.source,
                change
                    .url
                    .as_deref()
                    .map(|url| format!(" · {url}"))
                    .unwrap_or_default()
            ),
            (Some(change), Some(note)) => {
                println!(
                    "  pull     {} · {} · [source: {}]",
                    change.id, change.state, change.source
                );
                eprintln!("note: {note}");
            }
            (None, Some(note)) => {
                println!("  pull     not opened");
                eprintln!("note: {note}");
            }
            (None, None) => {}
        }
    }
}

/// Ask a forge to carry a change the store already holds, and report what it answered.
///
/// This is the second of two calls, and the first is not undoable: the change is in the
/// store before the forge is asked, and nothing here takes that back. So every way this
/// can end without a pull request is reported as itself — not asked, could not tell which
/// branch, the forge refused — and the command still exits with the code for "the change
/// is published", because that is the truth of it. A change with a ref and no pull is a
/// state a forge can be in: `change list` labels it, and `change merge` merges it with the
/// store's CAS because that is all there is.
fn carry_on_forge(
    args: &Args,
    forge: Option<&remotes::Forge>,
    record: &ChangeRecord,
) -> Result<Option<Carried>, CliError> {
    let Some(forge) = forge else {
        return Ok(None);
    };
    if args.on("--no-pull") {
        return Ok(Some(Carried::without(
            "--no-pull: the change is filed and the forge was not asked to carry it, so it \
             will be listed as a change with no pull request",
        )));
    }
    let head = Oid::from_hex(oid_hex(&record.head)).map_err(|e| {
        CliError::refused(
            format!("{}'s head is not an oid: {e}", record.change_id),
            "a pull request is opened over a commit, so the head has to be one",
        )
    })?;
    if let change::OriginKind::Pull = record.origin.kind {
        // The claim outranks any lookup, because it is inside what the author signed, so
        // nothing is opened. But a claim about a pull the forge does not have is worth
        // saying while there is still time to fix it: the merge will otherwise chase a pull
        // that is not there, and "the record said so" is a poor thing to say then.
        let claimed = record.origin.number;
        let carried = claimed.is_some_and(|number| {
            forge
                .open_pulls_at(&head)
                .map(|found| found.iter().any(|change| change.pull() == Some(number)))
                .unwrap_or(false)
        });
        let claimed = claimed
            .map(|number| number.to_string())
            .unwrap_or_else(|| "(no number given)".to_string());
        return Ok(Some(Carried::without(if carried {
            format!(
                "the record says it is carried by pull request {claimed}, so the forge was \
                 not asked to open a second one: a new attempt moves that pull's branch, it \
                 does not open another pull"
            )
        } else {
            format!(
                "the record claims pull request {claimed}, and the forge has no open pull over \
                 this commit to carry it: the claim is in the signed record and stays there, \
                 but `change merge` will look for that pull and not find it"
            )
        })));
    }
    // A re-submit is not a new proposal. If the forge already has open pulls over this
    // commit, that is the answer, and opening another would be the tool making work for a
    // reviewer — one pull or three, the answer is the same, and with more than one the note
    // says so because which of them merges is still somebody's decision.
    let carrying = forge.open_pulls_at(&head)?;
    if let Some((first, rest)) = carrying.split_first() {
        let mut carried = first.clone();
        // The adapter saw pulls and no ref it could match to them; the command line knows
        // better, because it is holding the record whose head this is.
        carried.source = "both";
        let numbers = carrying
            .iter()
            .filter_map(|change| change.pull())
            .map(|number| number.to_string())
            .collect::<Vec<_>>();
        return Ok(Some(Carried {
            change: Some(carried),
            note: Some(if rest.is_empty() {
                "the forge already has an open pull over this commit, so no second one was \
                 opened"
                    .to_string()
            } else {
                format!(
                    "the forge already has {} open pulls over this commit ({}), so none was \
                     opened; which of them is the one that merges is not gitiup's to guess",
                    carrying.len(),
                    numbers.join(", ")
                )
            }),
        }));
    }
    let branch = match args.get("--pull-branch") {
        Some(named) => Some(named.to_string()),
        None => match forge.branches_at(&head)?.as_slice() {
            [only] => Some(only.clone()),
            [] => None,
            many => {
                return Ok(Some(Carried::without(format!(
                    "{} of the forge's branches point at this head ({}), so which one a pull \
                     request comes from is a decision and not a lookup — name it with  --pull-branch",
                    many.len(),
                    many.join(", ")
                ))));
            }
        },
    };
    let Some(branch) = branch else {
        return Ok(Some(Carried::without(format!(
            "the forge has no branch pointing at {} — a pull request has to be opened from a \
             branch, and `refs/changes/**` is not one. Push the commit (`git push <remote> {}:refs/heads/<branch>`), then re-run this submit: the attempt is already filed, so it will answer `already`, and the pull opens. Until then the change is listed as one with no pull request",
            short_id(&record.head),
            record.head
        ))));
    };
    let opened = forge.open_change(
        &record.title,
        &branch,
        &forge_branch(&record.base.branch),
        &pull_request_body(record),
        args.on("--draft"),
    );
    Ok(Some(match opened {
        Ok(change) => Carried {
            change: Some(change),
            note: None,
        },
        Err(why) => Carried::without(format!(
            "the change is filed; the forge would not open the pull request ({})",
            why.message
        )),
    }))
}

/// A change's base branch as the forge names it (`refs/heads/main` is `main` there).
fn forge_branch(name: &str) -> String {
    name.replace("refs/heads/", "").to_string()
}

/// The forge's copy of a change: enough to read, and the bytes a reviewer can hash.
///
/// The copy is a copy and says so. What a signature covers is the record in the store, and
/// this is what makes it acceptable for the forge to cut the copy short when it is over
/// the forge's own limit ([`remotes`]' adapter truncates it and reports
/// `copy_truncated`) — a truncated discussion loses the discussion, not the proof.
fn pull_request_body(record: &ChangeRecord) -> String {
    let bytes = record
        .canonical_bytes()
        .unwrap_or_else(|_| record.title.as_bytes().to_vec());
    format!(
        "Proposed with gitiup: change `{}`, attempt {}.\n\
         \n\
         head  {}\n\
         base  {} @ {}\n\
         jobs  {}\n\
         author {} ({})\n\
         \n\
         The signed bytes of record are in the store, advertised by the change's own ref;\n\
         the block below is a copy of them, so a reviewer can hash what they are reading.\n\
         `gitiup change show {}` prints the record as the store returns it, and\n\
         `gitiup change checkout {}` fetches it with its proofs.\n\
         \n\
         ```json\n\
         {}\n\
         ```\n",
        record.change_id,
        record.attempts.index,
        record.head,
        record.base.branch,
        record.base.oid,
        if record.workflow.jobs.is_empty() {
            "(none requested)".to_string()
        } else {
            record.workflow.jobs.join(", ")
        },
        record.author.key_id,
        record.author.principal,
        record.change_id,
        record.change_id,
        String::from_utf8_lossy(&bytes),
    )
}

/// `--merge-method`, in the words the forge uses.
///
/// The default is `ff`, because gitiup's whole merge story is a fast-forward: a merge
/// commit exists only after the merge, so no attestation can cover it. A forge whose
/// settings forbid one is told so by the forge, and the operator can say otherwise out
/// loud — at the cost, printed in the hint, of a merge no proof covers.
fn merge_method(args: &Args) -> Result<String, CliError> {
    let method = args.get("--merge-method").unwrap_or("ff").to_string();
    if matches!(method.as_str(), "ff" | "merge" | "squash" | "rebase") {
        return Ok(method);
    }
    Err(CliError::usage(format!(
        "--merge-method '{method}' is not ff, merge, squash or rebase"
    )))
}

/// The dry run of a forge-backed change: the plan is "ask the forge", and the CAS a store
/// merge would have made is named as what it is — an imitation of this.
fn print_forge_plan(
    store: &Opened,
    args: &Args,
    record: &ChangeRecord,
    plan: &change::MergePlan,
    number: u64,
    proofs: &[String],
) -> Result<(), CliError> {
    let atomicity = "the forge's own merge: atomic and reviewed, which a bucket's \
                     conditional write cannot promise";
    if args.json() {
        print_json(json!({
            "store": store.what,
            "dry_run": true,
            "verb": "merge",
            "would_write": true,
            "change": plan.change_id.as_str(),
            "attempt": plan.attempt,
            "pull": number,
            "via": "forge",
            "atomicity": atomicity,
            "branch": plan.branch.as_str(),
            "expect": spell_oid(&plan.to, record),
            "merged_ref": plan.merged_ref.as_str(),
            "kv": plan.kv,
            "proofs": proofs,
            "notes": plan.notes,
        }));
        return Ok(());
    }
    println!("plan    merge · nothing written (--dry-run)");
    println!("  store   {}", store.what);
    println!(
        "  change  {} attempt {} · {}",
        plan.change_id, plan.attempt, record.title
    );
    println!(
        "  pull    {number} — the forge's merge is the merge; gitiup will not touch {}",
        plan.branch
    );
    println!(
        "  expect  the forge refuses unless the head is still {}",
        short_id(&spell_oid(&plan.to, record))
    );
    println!(
        "  record  {}/<digest of the signed record>, advertised by {}",
        plan.kv, plan.merged_ref
    );
    for note in &plan.notes {
        eprintln!("note: {note}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// What a listing shows about one change, read out of the signed record and not out of
/// a ref: a store that mislabelled a change could not then steer a listing.
struct Parsed {
    attempt: u32,
    head: String,
    base: change::Base,
    base_check: &'static str,
    author: change::Author,
    title: String,
    jobs: Vec<String>,
    created_at_us: i64,
    change_digest: String,
    record_digest: String,
    size: u64,
    /// The pull request the record itself claims to be carried by, if it said so.
    pull: Option<u64>,
}

struct Row {
    summary: change::ChangeSummary,
    detail: Result<Parsed, CliError>,
}

/// Read one change's newest record, whichever ref names it.
///
/// `head` is preferred, but a submit that died after writing the attempt ref leaves a
/// `head` behind the history, and a listing that refused to print that would be hiding
/// the one thing an operator needs to see. The summary carries `head_tracks_newest` and
/// the listing prints it.
fn newest_record(
    host: &dyn Host,
    summary: &change::ChangeSummary,
) -> Result<Option<(ChangeRecord, Vec<u8>)>, CliError> {
    let digest = summary.head.or_else(|| summary.newest_attempt_digest());
    let Some(digest) = digest else {
        return Ok(None);
    };
    match change::read_stored(host, &digest).map_err(|e| host_error("read a record", e))? {
        Some((StoredRecord::Change(record), bytes)) => Ok(Some((record, bytes))),
        Some((other, _)) => Err(CliError::new(
            gitiup_attest::ErrorKind::DigestMismatch,
            format!(
                "{} is advertised by {} and is a {} record",
                digest.short_default(),
                summary.change_id,
                other.record_type()
            ),
            Some("a change's head and attempts hold gitiup-change-1 records"),
        )),
        None => Err(CliError::new(
            gitiup_attest::ErrorKind::DigestMismatch,
            format!(
                "{} is advertised as {}'s newest record and the store cannot return its bytes",
                digest.short_default(),
                summary.change_id
            ),
            Some("a ref that names a missing object is a broken store, not a missing change"),
        )),
    }
}

fn rows(store: &dyn Host, catalog: &change::Catalog) -> Result<Vec<Row>, CliError> {
    let mut out = Vec::with_capacity(catalog.changes.len());
    for summary in &catalog.changes {
        let detail = match newest_record(store, summary)? {
            Some((record, bytes)) => Ok(Parsed {
                attempt: record.attempts.index,
                base_check: base_status(store, &record)?,
                head: record.head.clone(),
                base: record.base.clone(),
                author: record.author.clone(),
                title: record.title.clone(),
                jobs: record.workflow.jobs.clone(),
                created_at_us: record.created_at_us,
                change_digest: record.change_digest().unwrap_or_default(),
                record_digest: record_digest(&record),
                size: bytes.len() as u64,
                pull: (record.origin.kind == change::OriginKind::Pull)
                    .then_some(record.origin.number)
                    .flatten(),
            }),
            None => Err(CliError::refused(
                format!("{} has no record to read", summary.change_id),
                "it has refs and nothing behind them: `gitiup change show` says which ref",
            )),
        };
        out.push(Row {
            summary: summary.clone(),
            detail,
        });
    }
    // Newest first, so "what is open right now" reads top-down; unreadable ones last,
    // because a corrupt record is somebody's problem and printing it first would make a
    // broken store invisible.
    out.sort_by(|a, b| match (&a.detail, &b.detail) {
        (Ok(newest), Ok(older)) => older.created_at_us.cmp(&newest.created_at_us).then(
            a.summary
                .change_id
                .as_str()
                .cmp(b.summary.change_id.as_str()),
        ),
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => a
            .summary
            .change_id
            .as_str()
            .cmp(b.summary.change_id.as_str()),
    });
    Ok(out)
}

/// Whether the store still has the base the record is based on (D7's `stale`).
fn base_status(host: &dyn Host, record: &ChangeRecord) -> Result<&'static str, CliError> {
    let Ok(name) = RefName::new(&record.base.branch) else {
        return Ok("absent");
    };
    let want = match Oid::from_hex(oid_hex(&record.base.oid)) {
        Ok(oid) => oid,
        Err(_) => return Ok("absent"),
    };
    match host
        .get_ref(&name)
        .map_err(|e| host_error("read the base ref", e))?
    {
        Some(found) if found.oid == want => Ok("ok"),
        Some(_) => Ok("stale"),
        None => Ok("absent"),
    }
}

fn list(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = read_store(args)?;
    let forge = forge_remote(args)?;
    let filter: Option<State> = match args.get("--state").unwrap_or("open") {
        "open" => Some(State::Open),
        "merged" => Some(State::Merged),
        "abandoned" => Some(State::Abandoned),
        "all" | "any" => None,
        other => {
            return Err(CliError::usage(format!(
                "--state '{other}' is not open, merged, abandoned or all"
            )));
        }
    };
    let catalog = change::list_changes(&*store.host).map_err(|e| host_error("list changes", e))?;
    let all = rows(&*store.host, &catalog)?;
    // What the forge carries, asked once. A bucket never gets asked, which is why every
    // forge field below is optional rather than empty: the question was not put.
    let carried: Vec<remotes::ForgeChange> = match &forge {
        Some(handle) => handle.changes("all")?,
        None => Vec::new(),
    };
    let mut shown: Vec<Listing> = all
        .iter()
        .map(|row| Listing::Stored(row, pairing(&carried, row)))
        .collect();
    // A pull the listing already paired with a store row is that row's `both`, not a second
    // row: the same change seen from two databases must read as one line, and the adapter
    // cannot make that call alone because only the store's record knows the commit under
    // the ref it advertises.
    let paired: BTreeSet<String> = shown
        .iter()
        .filter_map(|row| match row {
            Listing::Stored(_, Some(change)) => Some(change.id.clone()),
            Listing::Stored(_, None) | Listing::Unrecorded(_) => None,
        })
        .collect();
    shown.extend(
        carried
            .iter()
            .filter(|change| change.source == "pull" && !paired.contains(&change.id))
            .map(Listing::Unrecorded),
    );
    shown.sort_by(|a, b| b.stamp().cmp(&a.stamp()).then_with(|| a.id().cmp(&b.id())));
    let shown: Vec<&Listing> = shown.iter().filter(|row| row.shows(filter)).collect();

    if args.json() {
        let changes: Vec<Value> = shown.iter().map(|row| row.json()).collect();
        print_json(json!({
            "store": store.what,
            "state": args.get("--state").unwrap_or("open"),
            "count": changes.len(),
            "changes": changes,
            "unexpected_refs": catalog.unexpected,
            // Said out loud, because "the store has no changes" and "nobody asked the
            // forge" look identical otherwise.
            "forge": forge.as_ref().map(|_| json!({"asked": true, "rows": carried.len()})),
        }));
        return Ok(());
    }
    if shown.is_empty() {
        println!(
            "no {} changes in {}",
            filter.map(|state| state.as_str()).unwrap_or("any"),
            store.what
        );
    }
    for row in &shown {
        println!("{}", row.text());
        if let Listing::Stored(row, _) = row
            && !row.summary.head_tracks_newest
        {
            eprintln!(
                "note: {}'s head ref is behind its newest attempt — a submit died between \
                 the two writes; re-running that submit finishes it (ADR-0003 D6)",
                row.summary.change_id
            );
        }
    }
    if shown
        .iter()
        .any(|row| matches!(row, Listing::Unrecorded(_)))
    {
        eprintln!(
            "note: a row above is a pull request with no gitiup record behind it (`source: pull`): a title and a body the forge holds, signed by nobody. Nothing about it can be verified from the store, and `change merge` will not merge it"
        );
    }
    for name in &catalog.unexpected {
        eprintln!("note: {name} is in the change namespace but not this layout");
    }
    Ok(())
}

/// The forge's row that is the same change as this one, if a forge was asked at all.
///
/// Two tests, in order of how much they can be trusted: the record can name the pull it
/// was signed as (`origin: Pull`), which is a claim the signature covers; or the forge's
/// pull and the store's change can propose the same commit, which is a fact about oids and
/// nothing else. No third test is invented — a title match would be a guess dressed up as
/// a join.
fn pairing<'a>(carried: &'a [remotes::ForgeChange], row: &Row) -> Option<&'a remotes::ForgeChange> {
    let Ok(parsed) = row.detail.as_ref() else {
        return None;
    };
    carried.iter().find(|change| {
        parsed
            .pull
            .is_some_and(|number| change.pull() == Some(number))
            || change.head.as_deref() == Some(oid_hex(&parsed.head))
    })
}

fn row_json(row: &Row) -> Value {
    let summary = &row.summary;
    let base = json!({
        "change": summary.change_id.as_str(),
        "state": summary.state.as_str(),
        "recorded": true,
        "attempts": summary.attempts,
        "head_digest": summary.head.map(tagged),
        "head_tracks_newest": summary.head_tracks_newest,
        "merged_digest": summary.merged.map(tagged),
        "abandoned_digest": summary.abandoned.map(tagged),
        "updated_at": summary.updated_at.map(|at| rfc3339(at.as_unix() as i64 * 1_000_000)),
        "updated_by": summary.updated_by.as_ref().map(|actor| actor.as_str().to_string()),
    });
    let parsed = match &row.detail {
        Ok(parsed) => json!({
            "attempt": parsed.attempt,
            "head": parsed.head,
            "base": { "ref": parsed.base.branch, "oid": parsed.base.oid },
            "base_check": parsed.base_check,
            "stale": parsed.base_check == "stale",
            "author": { "key_id": parsed.author.key_id, "principal": parsed.author.principal },
            "title": parsed.title,
            "jobs": parsed.jobs,
            "created_at": rfc3339(parsed.created_at_us),
            "created_at_us": parsed.created_at_us,
            "change_digest": parsed.change_digest,
            "record_digest": parsed.record_digest,
            "size": parsed.size,
        }),
        Err(error) => json!({ "error": error.message }),
    };
    let mut out = match base.as_object() {
        Some(map) => map.clone(),
        None => Map::new(),
    };
    if let Some(map) = parsed.as_object() {
        for (key, value) in map {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

/// The same row, plus what a forge said about it (`None` when no forge was asked, which is
/// the bucket case and the reason the field is optional rather than empty).
fn row_json_carried(row: &Row, carried: Option<&remotes::ForgeChange>) -> Value {
    let mut value = row_json(row);
    forge_fields(&mut value, carried);
    value
}

/// Add the forge's fields to a row: which database it came from, whether a pull request
/// carries it, and what the forge cannot promise about it.
///
/// A store-backed row with no pull is `source: ref`, and that is stated rather than left
/// as an absence: on a forge the question was asked, and "no" is the answer.
fn forge_fields(value: &mut Value, carried: Option<&remotes::ForgeChange>) {
    let (source, pull, url, truncated) = match carried {
        Some(change) => (
            "both",
            json!(change.pull()),
            json!(change.url.clone()),
            json!(change.copy_truncated),
        ),
        None => ("ref", Value::Null, Value::Null, json!(false)),
    };
    if let Some(map) = value.as_object_mut() {
        map.insert("source".to_string(), json!(source));
        map.insert("pull".to_string(), pull);
        map.insert("url".to_string(), url);
        map.insert("copy_truncated".to_string(), truncated.clone());
        map.insert(
            "caveats".to_string(),
            json!(remotes::caveats(
                source,
                truncated.as_bool().unwrap_or(false)
            )),
        );
    }
}

/// The forge's own row as JSON, for a pull request with no gitiup record behind it.
fn unrecorded_json(change: &remotes::ForgeChange) -> Value {
    let mut value = change.json();
    if let Some(map) = value.as_object_mut() {
        map.insert("recorded".to_string(), json!(false));
        map.insert("attempts".to_string(), json!(Vec::<u32>::new()));
        map.insert(
            "error".to_string(),
            json!(
                "no gitiup record is behind this change: the forge's pull database is the \
                 only thing describing it, and nothing in it is signed"
            ),
        );
    }
    value
}

/// One line of `gitiup change list`.
enum Listing<'a> {
    /// A change the store's own refs advertise, and what the forge says about it when a
    /// forge was asked.
    Stored(&'a Row, Option<&'a remotes::ForgeChange>),
    /// A change only the forge knows about. Listed and labelled: silently skipping it is
    /// how "there is nothing here" becomes a lie.
    Unrecorded(&'a remotes::ForgeChange),
}

impl Listing<'_> {
    /// The change's name, whichever database it came from.
    fn id(&self) -> String {
        match self {
            Listing::Stored(row, _) => row.summary.change_id.as_str().to_string(),
            Listing::Unrecorded(change) => change.id.clone(),
        }
    }

    /// Its state, in the one vocabulary the listing uses.
    fn state(&self) -> &'static str {
        match self {
            Listing::Stored(row, _) => row.summary.state.as_str(),
            Listing::Unrecorded(change) => change.state,
        }
    }

    /// Whether `--state` keeps this row.
    fn shows(&self, filter: Option<State>) -> bool {
        let state = match self.state() {
            "merged" => State::Merged,
            "closed" | "abandoned" => State::Abandoned,
            _ => State::Open,
        };
        filter.is_none_or(|wanted| wanted == state)
    }

    /// What to sort by: newest first, and a row with no timestamp last.
    fn stamp(&self) -> i64 {
        match self {
            Listing::Stored(row, _) => match &row.detail {
                Ok(parsed) => parsed.created_at_us / 1_000_000,
                Err(_) => row
                    .summary
                    .updated_at
                    .map(|at| at.as_unix() as i64)
                    .unwrap_or(0),
            },
            Listing::Unrecorded(change) => change.updated_at.map(|at| at as i64).unwrap_or(0),
        }
    }

    fn json(&self) -> Value {
        match self {
            Listing::Stored(row, carried) => row_json_carried(row, *carried),
            Listing::Unrecorded(change) => unrecorded_json(change),
        }
    }

    fn text(&self) -> String {
        match self {
            Listing::Stored(row, carried) => {
                let summary = &row.summary;
                match &row.detail {
                    Ok(parsed) => format!(
                        "{}  {:<9} a{:<3} {:<20} {:<14} {}{}{}",
                        summary.change_id,
                        summary.state.as_str(),
                        summary.attempts.len(),
                        short_id(&parsed.head),
                        short(&parsed.author.key_id),
                        clip(&parsed.title, 48),
                        if parsed.base_check == "stale" {
                            "  [stale base]"
                        } else {
                            ""
                        },
                        carried_mark(*carried),
                    ),
                    Err(error) => format!(
                        "{}  {:<9} UNREADABLE  {}{}",
                        summary.change_id,
                        summary.state.as_str(),
                        error.message,
                        carried_mark(*carried)
                    ),
                }
            }
            Listing::Unrecorded(change) => format!(
                "{:<16}  {:<9} {:<5} {:<20} {:<14} {}  [{}{}]",
                change.id,
                change.state,
                "-",
                change
                    .head
                    .as_deref()
                    .map(short_id)
                    .unwrap_or_else(|| "-".to_string()),
                change.author.as_deref().unwrap_or("-"),
                clip(&change.title, 48),
                if change.copy_truncated {
                    "copy truncated, "
                } else {
                    ""
                },
                "no gitiup record"
            ),
        }
    }
}

/// The tag on a store-backed row that says what the forge does with it.
fn carried_mark(carried: Option<&remotes::ForgeChange>) -> &'static str {
    match carried {
        Some(change) if change.copy_truncated => "  [pull, copy truncated]",
        Some(_) => "  [pull]",
        None => "",
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

/// Show the forge's answer about a change the store has no record for.
///
/// This is a listing of what the forge holds, printed rather than refused: "no such
/// change" is the wrong answer about something plainly there, and printing it without the
/// label would be the other wrong answer. Nothing on this page can be checked against the
/// store, says so, and exits 0 like any other listing.
fn show_unrecorded(
    store: &Opened,
    change: &remotes::ForgeChange,
    json: bool,
) -> Result<(), CliError> {
    if json {
        print_json(unrecorded_json(change));
        return Ok(());
    }
    println!("change  {}  ·  {}", change.id, change.state);
    println!("  store     {}", store.what);
    println!(
        "  source    {} — the forge's pull database, and nothing else",
        change.source
    );
    if let Some(head) = &change.head {
        println!("  head      {head}");
    }
    if let Some(base) = &change.base {
        println!("  base      {base}");
    }
    println!(
        "  author    {}",
        change
            .author
            .as_deref()
            .unwrap_or("(the forge did not say)")
    );
    println!("  title     {}", change.title);
    if let Some(url) = &change.url {
        println!("  url       {url}");
    }
    if change.copy_truncated {
        println!("  copy      the forge could not hold the whole of it (`copy_truncated`)");
    }
    println!("  record    none — nothing here is signed, so nothing here can be verified");
    for caveat in &change.caveats {
        eprintln!("note: {caveat}");
    }
    Ok(())
}

/// The forge row that answers a handle the store cannot: `gh-7`, or a bare `7`.
fn forge_handle(
    forge: Option<&remotes::Forge>,
    handle: &str,
) -> Result<Option<remotes::ForgeChange>, CliError> {
    let Some(forge) = forge else {
        return Ok(None);
    };
    let bare = handle.trim().to_string();
    let numbered = bare
        .trim_start_matches("gh-")
        .parse::<u64>()
        .ok()
        .map(|number| format!("gh-{number}"));
    Ok(forge
        .changes("all")?
        .into_iter()
        .find(|change| change.id == bare || Some(change.id.clone()) == numbered))
}

fn show(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = read_store(args)?;
    let forge = forge_remote(args)?;
    let handle: Option<String> = args
        .positional
        .first()
        .cloned()
        .or_else(|| args.get("--change").map(str::to_string));
    let handle = match handle {
        Some(handle) => handle.clone(),
        None => {
            return Err(CliError::usage(
                "say which change: `gitiup change show <ID>` (a change id, or 4+ hex of one)",
            ));
        }
    };
    let found = match resolve_handle(&*store.host, &handle) {
        Ok(found) => found,
        Err(why) => {
            // The store does not hold it. A forge might, and "no such change" said about a
            // change the forge is holding is not an answer worth leaving — but it is the
            // forge's answer, labelled as one, and not a record.
            if let Some(change) = forge_handle(forge.as_ref(), &handle)? {
                return show_unrecorded(&store, &change, args.json());
            }
            return Err(why);
        }
    };
    let id = found.change_id.clone();
    let reference = match args.get("--attempt") {
        Some(text) => {
            let index = text
                .parse::<u32>()
                .map_err(|_| CliError::usage(format!("--attempt '{text}' is not a number")))?;
            change::attempt_ref(&id, index)
        }
        None => change::change_head_ref(&id),
    };
    // Reading through the ref is the point: this is where a record that disagrees with
    // the ref advertising it, or with the change's own history, is refused (D11 step 6).
    let fetched = change::change_at(&*store.host, &reference)
        .map_err(|e| host_error("read the change", e))?;
    let StoredRecord::Change(record) = fetched.record.clone() else {
        return Err(CliError::refused(
            format!("{} is not a change record", fetched.reference),
            "a change's head and attempts hold gitiup-change-1 records",
        ));
    };
    let history = change::change_history(&*store.host, &id)
        .map_err(|e| host_error("read the attempts", e))?;
    let base_check = base_status(&*store.host, &record)?;
    let state = found.state;
    let merge = match found.merged {
        Some(_) => state_record(&*store.host, &change::merged_ref(&id)).ok(),
        None => None,
    };
    let abandon = match found.abandoned {
        Some(_) => state_record(&*store.host, &change::abandoned_ref(&id)).ok(),
        None => None,
    };
    // What the forge says about this change, asked once. `show` reads through the store's
    // ref by default, and the forge's answer is an annotation on it — except when there is
    // no ref at all, which is the case above.
    let carried: Option<remotes::ForgeChange> = match &forge {
        Some(handle) => {
            let signed = (record.origin.kind == change::OriginKind::Pull)
                .then_some(record.origin.number)
                .flatten();
            handle.changes("all")?.into_iter().find(|change| {
                // Only a pull can be the answer here: the adapter also lists the store's
                // own refs, and matching one of those by absence (`None == None`) would
                // report a change as carried by the thing it already is.
                change.pull().is_some()
                    && (signed.is_some_and(|number| change.pull() == Some(number))
                        || change.head.as_deref() == Some(oid_hex(&record.head)))
            })
        }
        None => None,
    };

    if args.on("--bytes") {
        std::io::stdout()
            .write_all(&fetched.bytes)
            .map_err(|e| CliError::io(format!("write stdout: {e}")))?;
        return Ok(());
    }
    if args.json() {
        let document: Value = serde_json::from_slice(&fetched.bytes)
            .map_err(|e| CliError::io(format!("the stored bytes are not JSON: {e}")))?;
        let attempts: Vec<Value> = history.iter().map(attempt_json).collect();
        print_json(json!({
            "store": store.what,
            "change": id.as_str(),
            "state": state.as_str(),
            "reference": fetched.reference.as_str(),
            "record_digest": tagged(fetched.digest),
            "change_digest": record.change_digest().unwrap_or_default(),
            "size": fetched.bytes.len(),
            "canonical": true,
            "attempt": record.attempts.index,
            "anchor": record.attempts.anchor,
            "previous": record.attempts.previous,
            "head": record.head,
            "base": { "ref": record.base.branch, "oid": record.base.oid },
            "base_check": base_check,
            "stale": base_check == "stale",
            "title": record.title,
            "jobs": record.workflow.jobs,
            "origin": record.origin,
            "source": if carried.is_some() { "both" } else { "ref" },
            "pull": carried.as_ref().map(|change| change.json()),
            "copy_truncated": carried.as_ref().map(|change| change.copy_truncated).unwrap_or(false),
            "caveats": json!(remotes::caveats(
                if carried.is_some() { "both" } else { "ref" },
                carried.as_ref().map(|change| change.copy_truncated).unwrap_or(false),
            )),
            "author": { "key_id": record.author.key_id, "principal": record.author.principal },
            "signatures": record.signatures.iter().map(|entry| json!({
                "key_id": entry.key_id,
                "algorithm": entry.algorithm.as_str(),
            })).collect::<Vec<_>>(),
            "created_at": rfc3339(record.created_at_us),
            "created_at_us": record.created_at_us,
            "attempts": attempts,
            "head_tracks_newest": found.head_tracks_newest,
            "fetch": change::fetch_pattern(&id),
            "merged": merge.as_ref().map(state_json),
            "abandoned": abandon.as_ref().map(state_json),
            "kv": change::kv_key(&change::CHANGE_NAMESPACE, &fetched.digest),
            "document": document,
        }));
        return Ok(());
    }
    println!("change  {id}  ·  {state}");
    println!("  store     {}", store.what);
    println!("  ref       {}", fetched.reference);
    println!(
        "  record    {} ({} bytes)",
        tagged(fetched.digest),
        fetched.bytes.len()
    );
    println!(
        "  digests   change {} · record {}",
        record.change_digest().unwrap_or_default(),
        tagged(fetched.digest)
    );
    println!(
        "  attempt   {} of {} · anchor {}",
        record.attempts.index,
        history.len(),
        record.attempts.anchor
    );
    if let Some(previous) = &record.attempts.previous {
        println!("  previous  {previous}");
    }
    println!("  head      {}", record.head);
    println!(
        "  base      {} @ {} [{}]",
        record.base.branch,
        record.base.oid,
        match base_check {
            "ok" => "the store has this base".to_string(),
            "stale" =>
                "STALE — the store has moved; a new attempt rebased onto it is needed".to_string(),
            _ => "the store has no such branch yet".to_string(),
        }
    );
    println!("  title     {}", record.title);
    match &carried {
        Some(change) => println!(
            "  pull      {} · {} · [source: {}]{}",
            change.id,
            change.state,
            // The CLI's own answer, not the adapter's: the adapter cannot see that the
            // record behind this ref and this pull name one change, because the ref points
            // at a record and the pull at a commit. The command line can, and says `both`.
            if forge.is_some() { "both" } else { "ref" },
            change
                .url
                .as_deref()
                .map(|url| format!(" · {url}"))
                .unwrap_or_default()
        ),
        // Said rather than left out: on a forge the question was asked, and "no" is the
        // answer the caller needs.
        None if forge.is_some() => {
            println!("  pull      none — no pull request over this head [source: ref]")
        }
        None => {}
    }
    println!(
        "  jobs      {}",
        if record.workflow.jobs.is_empty() {
            "(none requested — which is not \"run everything\" and not \"nothing is required\")"
                .to_string()
        } else {
            record.workflow.jobs.join(", ")
        }
    );
    println!(
        "  author    {} ({})",
        record.author.key_id, record.author.principal
    );
    println!(
        "  signed    {}",
        record
            .signatures
            .iter()
            .map(|entry| format!("{} ({})", short(&entry.key_id), entry.algorithm.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  created   {} ({} µs)",
        rfc3339(record.created_at_us),
        record.created_at_us
    );
    println!("  attempts  {}", history.len());
    for attempt in &history {
        let marker = if attempt.index == record.attempts.index {
            "*"
        } else {
            " "
        };
        println!(
            "  {marker} a{:<3} {:<20} {}  {}",
            attempt.index,
            short(&attempt.head),
            short(&attempt.author.key_id),
            clip(&attempt.title, 40)
        );
    }
    if let Some(merge) = &merge {
        print!("  merged    ");
        let _ = writeln_line(&mut std::io::stdout(), merge);
    }
    if let Some(abandon) = &abandon {
        print!("  abandoned ");
        let _ = writeln_line(&mut std::io::stdout(), abandon);
    }
    println!(
        "  fetch     git fetch <remote> '{}'",
        change::fetch_pattern(&id)
    );
    Ok(())
}

/// The human line for a merge or abandon record, whichever the change carries.
fn writeln_line(out: &mut dyn Write, record: &StoredRecord) -> std::io::Result<()> {
    match record {
        StoredRecord::Merge(merge) => writeln!(
            out,
            "attempt {} · {} → {} · via {} · by {} · {} · proofs {}",
            merge.attempt,
            short(&merge.base.from),
            short(&merge.base.to),
            merge.via,
            short(&merge.author.key_id),
            rfc3339(merge.merged_at_us),
            merge.proofs.len()
        ),
        StoredRecord::Abandon(abandon) => writeln!(
            out,
            "attempt {} · {} · by {} · {}{}",
            abandon.attempt,
            abandon.reason,
            short(&abandon.author.key_id),
            rfc3339(abandon.abandoned_at_us),
            abandon
                .note
                .as_ref()
                .map(|note| format!(" · {note}"))
                .unwrap_or_default()
        ),
        StoredRecord::Change(_) => writeln!(out, "(a change record where a state record belongs)"),
    }
}

/// Read the record one state ref advertises (D7: a state is a ref plus a signed record).
fn state_record(host: &dyn Host, name: &RefName) -> Result<StoredRecord, CliError> {
    let fetched =
        change::change_at(host, name).map_err(|e| host_error("read the state record", e))?;
    Ok(fetched.record)
}

/// A merge or abandon record as data, so `--json` carries the state and not just the
/// word for it (D7: a state is a ref *and* a signed record).
fn state_json(record: &StoredRecord) -> Value {
    match record {
        StoredRecord::Merge(merge) => json!({
            "type": change::MERGE_TYPE,
            "attempt": merge.attempt,
            "change_digest": merge.change_digest,
            "base": {
                "ref": merge.base.branch,
                "from": merge.base.from,
                "to": merge.base.to,
            },
            "merged_at": rfc3339(merge.merged_at_us),
            "merged_at_us": merge.merged_at_us,
            "via": merge.via,
            "proofs": merge.proofs,
            "policy_digest": merge.policy_digest,
            "author": { "key_id": merge.author.key_id, "principal": merge.author.principal },
        }),
        StoredRecord::Abandon(abandon) => json!({
            "type": change::ABANDON_TYPE,
            "attempt": abandon.attempt,
            "change_digest": abandon.change_digest,
            "reason": abandon.reason,
            "note": abandon.note,
            "abandoned_at": rfc3339(abandon.abandoned_at_us),
            "abandoned_at_us": abandon.abandoned_at_us,
            "author": { "key_id": abandon.author.key_id, "principal": abandon.author.principal },
        }),
        StoredRecord::Change(record) => json!({
            "type": change::CHANGE_TYPE,
            "attempt": record.attempts.index,
            "change_digest": record.change_digest().unwrap_or_default(),
        }),
    }
}

fn attempt_json(attempt: &AttemptInfo) -> Value {
    json!({
        "index": attempt.index,
        "reference": attempt.reference.as_str(),
        "record_digest": tagged(attempt.record_digest),
        "change_digest": attempt.change_digest,
        "head": attempt.head,
        "base": { "ref": attempt.base.branch, "oid": attempt.base.oid },
        "author": { "key_id": attempt.author.key_id, "principal": attempt.author.principal },
        "title": attempt.title,
        "jobs": attempt.jobs,
        "previous": attempt.previous,
        "created_at": rfc3339(attempt.created_at_us),
        "created_at_us": attempt.created_at_us,
        "size": attempt.size,
    })
}

// ---------------------------------------------------------------------------
// checkout — the reviewer's one command (giti-b2z.5)
// ---------------------------------------------------------------------------

/// One proof the store advertises about the commit being checked out.
///
/// The listing is the store's (`refs/attestations/<subject>/`) and the bytes are read back
/// through it, so what gets printed is the signed document and not a ref's label — the
/// same rule `gitiup attest list` keeps.
struct Proof {
    digest: String,
    reference: String,
    tier: String,
    result: String,
    signers: Vec<String>,
    claimed_at_us: i64,
    size: usize,
    legacy: bool,
    /// The git blob these bytes are inside a git store's pointer commit, and whether the
    /// clone holds it after the fetch. That second half is the ticket's whole promise,
    /// checked rather than assumed.
    blob: String,
    arrived: bool,
}

/// One seat of a round, and what it handed in.
struct SeatReport {
    rank: u32,
    slot: String,
    key: String,
    identity: String,
    /// `None` is a silent seat, which is a fact about the round and not an error here.
    submission: Option<Submission>,
}

/// What a seat submitted, as far as a reader of a checkout needs: which result it signed,
/// at what tier, and who signed it. Re-verifying a submission is `gitiup quorum verdict`'s
/// job and it keeps the exit code that comes with the answer.
struct Submission {
    result: String,
    tier: String,
    signer: String,
    claimed_at_us: i64,
}

/// Everything `--for <job>` asks the store for beyond the change and its attestations.
struct ForJob {
    job: String,
    /// The ref the round was read through.
    reference: String,
    round: Round,
    /// Every attempt the store holds for this job, escalation included.
    attempts: Vec<u64>,
    seats: Vec<SeatReport>,
    /// The verdict, when the store files one *and* this machine trusts the key that signed
    /// it. A verdict is a claim by an owner and believing it is a trust decision.
    verdict: Option<VerdictRecord>,
    /// A verdict that is there and is not believed, in the words of the check that refused
    /// it. Reported, never quietly dropped.
    distrust: Option<String>,
    /// Which roots decided that, said out loud as every trust decision is.
    trusted_by: String,
    /// The round's head is the change's head, or the evidence is about other bytes.
    bound_to_head: bool,
}

/// The directory a ref name lives in, with the trailing separator a prefix match needs.
fn parent_of(name: &str) -> String {
    match name.rsplit_once('/') {
        Some((head, _)) => format!("{head}/"),
        None => format!("{name}/"),
    }
}

impl Proof {
    /// Every attestation filed under `refs/attestations/<subject>/`, plus the refs in that
    /// namespace the listing could not read at all.
    fn for_commit(
        host: &dyn Host,
        repo: &Repo,
        subject: &Oid,
    ) -> Result<(Vec<Proof>, Vec<String>), CliError> {
        let catalog = gitiup_host::attest::list_for(host, subject)
            .map_err(|e| host_error("list the proofs", e))?;
        let mut out = Vec::with_capacity(catalog.entries.len());
        for entry in catalog.entries {
            let bytes = gitiup_host::attest::fetch(host, &entry.digest)
                .map_err(|e| host_error("read a proof", e))?
                .ok_or_else(|| {
                    CliError::new(
                        gitiup_attest::ErrorKind::DigestMismatch,
                        format!(
                            "{} is advertised by {} and the store cannot return its bytes",
                            entry.digest.short_default(),
                            entry.reference
                        ),
                        Some(
                            "a ref that names a missing object is a broken store, not a \
                         missing proof",
                        ),
                    )
                })?;
            let doc = AttestationDoc::from_canonical_bytes(&bytes)?;
            out.push(Proof {
                digest: format!("sha256:{}", entry.digest.hex()),
                reference: entry.reference.as_str().to_string(),
                tier: doc.manifest.result.provenance.tier.as_str().to_string(),
                result: doc.result_digest()?.to_string(),
                signers: doc
                    .signatures
                    .iter()
                    .map(|entry| entry.key_id.clone())
                    .collect(),
                claimed_at_us: doc.manifest.claims.claimed_at_us,
                size: bytes.len(),
                legacy: entry.legacy,
                blob: repo.blob_oid(&bytes)?,
                arrived: false,
            });
        }
        // Newest claim first: the question a reviewer asks is what the proof about this
        // commit says *now*, and an older attempt's proof should not read as the answer.
        out.sort_by(|a, b| {
            b.claimed_at_us
                .cmp(&a.claimed_at_us)
                .then(a.digest.cmp(&b.digest))
        });
        Ok((out, catalog.unexpected))
    }

    fn json(&self) -> Value {
        json!({
            "digest": self.digest,
            "reference": self.reference,
            "shape": if self.legacy { "legacy" } else { "current" },
            "tier": self.tier,
            "result": self.result,
            "signers": self.signers,
            "claimed_at": rfc3339(self.claimed_at_us),
            "claimed_at_us": self.claimed_at_us,
            "size": self.size,
            "blob": format!("sha1:{}", self.blob),
            "arrived": self.arrived,
        })
    }
}

impl ForJob {
    /// Read the round, the seats and the verdict for one job of one change.
    ///
    /// Nothing here is derived: the round is the one the selector signed and published, the
    /// submissions are the ones the seats published, and the verdict is the one an owner
    /// signed. A checkout that recomputed any of it would disagree with the store for
    /// reasons nobody could explain.
    fn read(
        host: &dyn Host,
        id: &ChangeId,
        job: &str,
        record: &ChangeRecord,
        args: &Args,
    ) -> Result<ForJob, CliError> {
        let change = id.as_str();
        let rounds = qstore::rounds_for(host, change)?;
        let mut mine: Vec<&Round> = rounds
            .iter()
            .filter(|round| round.inputs.job_id == job)
            .collect();
        if mine.is_empty() {
            let known: Vec<&str> = rounds
                .iter()
                .map(|round| round.inputs.job_id.as_str())
                .collect();
            return Err(CliError::refused(
                format!("no round for job '{job}' was opened for {id} in this store"),
                if known.is_empty() {
                    format!(
                        "this change has no rounds at all; `gitiup change show {id} --json` \
                         prints the jobs its author asked to have re-run, and `gitiup select \
                         --change {id} --job <job> … --publish` opens one (ADR-0002)"
                    )
                } else {
                    format!(
                        "the store has rounds for {} of this change; a matrix arm is its own \
                         job id, spelled build/matrix/linux-x86_64",
                        known.join(", ")
                    )
                },
            ));
        }
        // The highest attempt is the live one: an escalation supersedes, it does not run
        // beside what it escalated from.
        mine.sort_by_key(|round| round.inputs.attempt);
        let attempts: Vec<u64> = mine.iter().map(|round| round.inputs.attempt).collect();
        let round = mine
            .last()
            .copied()
            .expect("non-empty after the refusal above");
        let reference = qstore::round_ref(change, job, round.inputs.attempt)?;
        if oid_hex(&round.inputs.head_oid.to_string()) != oid_hex(&record.head) {
            return Err(CliError::refused(
                format!(
                    "the round for '{job}' was drawn against {}, which is not {id}'s head {} \
                     in this store",
                    round.inputs.head_oid, record.head
                ),
                "the evidence is about other bytes, so printing it beside these would be \
                 worse than printing nothing: check the change out without --for, or open a \
                 round on this attempt (`gitiup select --change <id> --job <job> --head \
                 <oid> … --publish') (ADR-0002 D7)",
            ));
        }
        let docs = qstore::submissions(host, round)?;
        let by_key: BTreeMap<String, &AttestationDoc> = docs
            .iter()
            .filter_map(|doc| Some((doc.signatures.first()?.key_id.clone(), doc)))
            .collect();
        let mut seats = Vec::with_capacity(round.selected.len());
        for seat in &round.selected {
            let submission = match by_key.get(&seat.key_id) {
                Some(doc) => Some(Submission {
                    result: doc.result_digest()?.to_string(),
                    tier: doc.manifest.result.provenance.tier.as_str().to_string(),
                    signer: seat.key_id.clone(),
                    claimed_at_us: doc.manifest.claims.claimed_at_us,
                }),
                None => None,
            };
            seats.push(SeatReport {
                rank: seat.rank,
                slot: seat.slot.clone(),
                key: seat.key_id.clone(),
                identity: seat.identity.clone(),
                submission,
            });
        }
        // A verdict is read only when the store actually advertises one, so that a change
        // with no verdict costs this command no keystore and no trust decision.
        let name = qstore::verdict_ref(change, job)?;
        let (mut verdict, mut distrust, mut trusted_by) = (None, None, String::new());
        if host
            .get_ref(&name)
            .map_err(|e| host_error("read the verdict ref", e))?
            .is_some()
        {
            let (trust, by) = participant::owner_trust(args, &participant::keystore()?)?;
            trusted_by = by;
            match qstore::verdict_at(host, change, job, &trust) {
                Ok(Some(record)) => verdict = Some(record),
                Ok(None) => {
                    distrust = Some(format!("{name} names a record the store cannot return"))
                }
                Err(why) => distrust = Some(why.message()),
            }
        }
        Ok(ForJob {
            job: job.to_string(),
            reference: reference.as_str().to_string(),
            round: round.clone(),
            attempts,
            seats,
            verdict,
            distrust,
            trusted_by,
            bound_to_head: true,
        })
    }

    /// The refs `--for` adds to the fetch. On a git store these are ordinary refs, so the
    /// round, every seat's submission and the verdict arrive in the same packfile as the
    /// change and cost no second protocol.
    fn ref_prefixes(&self) -> Result<Vec<String>, CliError> {
        let change = &self.round.inputs.change_id;
        let job = &self.round.inputs.job_id;
        let round = qstore::round_ref(change, job, self.round.inputs.attempt)?;
        let mut out = vec![parent_of(round.as_str())];
        if let Some(seat) = self.round.selected.first() {
            let reveal = qstore::reveal_ref(change, job, &seat.slot)?;
            out.push(parent_of(reveal.as_str()));
        }
        out.push(qstore::verdict_ref(change, job)?.as_str().to_string());
        Ok(out)
    }

    fn submitted(&self) -> usize {
        self.seats
            .iter()
            .filter(|seat| seat.submission.is_some())
            .count()
    }

    fn json(&self) -> Value {
        let policy = &self.round.inputs.policy;
        json!({
            "job": self.job,
            "reference": self.reference,
            "attempt": self.round.inputs.attempt,
            "attempts": self.attempts,
            "round_digest": self.round.digest().map(|d| d.to_string()).unwrap_or_default(),
            "seed": self.round.seed.to_string(),
            "roster_epoch": self.round.inputs.roster_epoch,
            "roster_digest": self.round.inputs.roster_digest.to_string(),
            "policy_digest": self.round.policy_digest.to_string(),
            "seats": self.round.selected.len(),
            "required_agree": policy.required_agree,
            "sufficient": self.round.sufficient,
            "eligible": self.round.eligible,
            "bound_to_head": self.bound_to_head,
            "submitted": self.submitted(),
            "seat_report": self.seats.iter().map(|seat| json!({
                "rank": seat.rank,
                "slot": seat.slot,
                "key": seat.key,
                "identity": seat.identity,
                "submitted": seat.submission.as_ref().map(|done| json!({
                    "result": done.result,
                    "tier": done.tier,
                    "signed_by": done.signer,
                    "claimed_at": rfc3339(done.claimed_at_us),
                })),
            })).collect::<Vec<_>>(),
            "verdict": self.verdict.as_ref().map(|record| json!({
                "state": record.state.as_str(),
                "reason": record.reason.as_str(),
                "detail": record.detail,
                "attempt": record.attempt,
                "agreeing": record.agreeing,
                "required_agree": record.required_agree,
                "result": record.result_digest.as_ref().map(|d| d.to_string()),
                "counted": record.counted.iter().map(|v| v.key_id.clone()).collect::<Vec<_>>(),
                "missing": record.missing,
                "divergent": record.divergent.len(),
                "signed_by": record.signatures.iter().map(|s| s.key_id.clone()).collect::<Vec<_>>(),
                "digest": record.digest().map(|d| d.to_string()).unwrap_or_default(),
                "issued_at": rfc3339(record.issued_at_us),
                "trusted_by": self.trusted_by,
            })),
            "verdict_refused": self.distrust,
        })
    }

    /// The lines a person reads. The verdict is printed and not re-derived: `gitiup quorum
    /// verdict` is the command whose exit code *is* the answer.
    fn text(&self) {
        let policy = &self.round.inputs.policy;
        println!(
            "  round    {} attempt {} \u{b7} {} seat{} \u{b7} {} must agree \u{b7} {} eligible",
            self.job,
            self.round.inputs.attempt,
            self.round.selected.len(),
            if self.round.selected.len() == 1 {
                ""
            } else {
                "s"
            },
            policy.required_agree,
            self.round.eligible,
        );
        if self.attempts.len() > 1 {
            println!(
                "           attempts held: {} ({} is the live one)",
                self.attempts
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                self.round.inputs.attempt
            );
        }
        if !self.round.sufficient {
            println!(
                "           this round did not fill its seats: it can only ever be \
                 `insufficient' (ADR-0002 D3)"
            );
        }
        println!(
            "           {} \u{b7} roster epoch {} ({}) \u{b7} seed {}",
            short_id(
                self.round
                    .digest()
                    .map(|d| d.to_string())
                    .unwrap_or_default()
                    .as_str()
            ),
            self.round.inputs.roster_epoch,
            short_id(&self.round.inputs.roster_digest.to_string()),
            short_id(&self.round.seed.to_string()),
        );
        println!(
            "  seats    {} of {} submitted",
            self.submitted(),
            self.round.selected.len()
        );
        for seat in &self.seats {
            match &seat.submission {
                Some(done) => println!(
                    "    {:<3} {:<14} {:<9} {} \u{b7} {}",
                    format!("s{}", seat.rank),
                    short(&seat.key),
                    done.tier,
                    short_id(&done.result),
                    rfc3339(done.claimed_at_us),
                ),
                None => println!(
                    "    {:<3} {:<14} {:<9} silent",
                    format!("s{}", seat.rank),
                    short(&seat.key),
                    "-",
                ),
            }
        }
        match (&self.verdict, &self.distrust) {
            (Some(record), _) => {
                println!(
                    "  verdict  {} \u{b7} {} of {} identities agree on {}",
                    record.state,
                    record.agreeing,
                    record.required_agree,
                    record
                        .result_digest
                        .as_ref()
                        .map(|d| short_id(&d.to_string()))
                        .unwrap_or_else(|| "nothing".to_string()),
                );
                println!("           {}", one_line(&record.detail));
                println!(
                    "           signed by {} \u{b7} trusted via {} \u{b7} {}",
                    record
                        .signatures
                        .iter()
                        .map(|entry| short(&entry.key_id))
                        .collect::<Vec<_>>()
                        .join(", "),
                    self.trusted_by,
                    short_id(&record.digest().map(|d| d.to_string()).unwrap_or_default()),
                );
                if record.attempt != self.round.inputs.attempt {
                    println!(
                        "           note: it speaks about attempt {}, and the live round is \
                         attempt {}",
                        record.attempt, self.round.inputs.attempt
                    );
                }
            }
            (None, Some(why)) => {
                println!("  verdict  there is one, and this machine will not believe it: {why}")
            }
            (None, None) => println!(
                "  verdict  none filed for {} yet \u{b7} `gitiup quorum verdict <id> --job {} \
                 --publish' signs one",
                self.job, self.job
            ),
        }
    }
}

/// One round trip to the store: every object under `prefixes` that `haves` does not
/// already reach, in one git packfile.
struct Transport {
    /// `git-packfile`, or nothing at all when the clone already had it all.
    form: &'static str,
    objects: usize,
    bytes: usize,
    /// The packfile itself, for the clone to take into its object database.
    raw: Vec<u8>,
    /// How many of the clone's own ref tips the store agreed to treat as already held.
    haves: usize,
    /// True when the store could not honour the haves and had to send more, which is a
    /// fact about the size of the fetch and not a secret to keep.
    degraded: bool,
    prefixes: Vec<String>,
}

/// The haves a store will accept: this clone's ref tips that the store can also name.
///
/// One oid the store has never heard of would fail the whole fetch — git's `--not` has no
/// way to say "ignore that one" — so a local branch with local commits is left out rather
/// than guessed at, and the pack is a little bigger for it.
fn usable_haves(repo: &Repo, host: &dyn Host) -> Result<Vec<Oid>, CliError> {
    let advertised: BTreeSet<String> = host
        .list_refs(&RefQuery::all())
        .map_err(|e| host_error("read the store's refs", e))?
        .iter()
        .map(|reference| reference.oid.hex().to_lowercase())
        .collect();
    let mut out = Vec::new();
    for hex in repo.ref_tips()? {
        let hex = hex.to_lowercase();
        if advertised.contains(&hex)
            && let Ok(oid) = Oid::from_hex(&hex)
        {
            out.push(oid);
        }
    }
    Ok(out)
}

/// Ask the store for the pack, and say how much of it the clone did not need.
fn fetch_change(
    host: &dyn Host,
    prefixes: &[String],
    haves: &[Oid],
) -> Result<Transport, CliError> {
    let request = PackRequest {
        wants: Vec::new(),
        have: haves.to_vec(),
        ref_prefixes: prefixes.to_vec(),
        format: PackFormat::GitPackfile,
        limit_bytes: None,
    };
    let (pack, degraded) = match host.fetch_pack(&request) {
        Ok(pack) => (pack, false),
        Err(_) if !haves.is_empty() => {
            // Every have was checked against the store's own refs first, so this is a
            // surprise rather than a stale branch. Asking for more is the honest retry;
            // giving up, or retrying with the same request, is not.
            let wide = PackRequest {
                wants: Vec::new(),
                have: Vec::new(),
                ..request.clone()
            };
            (
                host.fetch_pack(&wide)
                    .map_err(|e| host_error("fetch the change", e))?,
                true,
            )
        }
        Err(error) => return Err(host_error("fetch the change", error)),
    };
    if pack.format != PackFormat::GitPackfile {
        return Err(CliError::new(
            gitiup_attest::ErrorKind::Invalid,
            format!(
                "this store answered a git packfile request with a {} pack",
                pack.format.as_str()
            ),
            Some(
                "a checkout needs git objects; the change's commits are not reachable as such here",
            ),
        ));
    }
    Ok(Transport {
        form: if pack.bytes.is_empty() {
            "nothing-new"
        } else {
            "git-packfile"
        },
        objects: pack_object_count(&pack.bytes),
        bytes: pack.len(),
        raw: pack.bytes,
        haves: if degraded { 0 } else { haves.len() },
        degraded,
        prefixes: prefixes.to_vec(),
    })
}

/// How many objects a git packfile carries, from its twelve-byte header.
fn pack_object_count(bytes: &[u8]) -> usize {
    if bytes.len() < 12 || &bytes[..4] != b"PACK" {
        return 0;
    }
    u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize
}

/// Where the change was left in the clone.
struct Landing {
    /// The ref written, if any; `--detach` writes none.
    reference: Option<String>,
    /// `created` · `fast-forwarded` · `unchanged` · `detached`, plus `written` when the
    /// worktree was deliberately left alone.
    action: &'static str,
    /// Whether the working tree now shows the change.
    worktree: &'static str,
}

fn checkout(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let handle = positional_handle(args, "checkout")?;
    if args.on("--detach") && args.get("--ref").is_some() {
        return Err(CliError::usage(
            "--detach and --ref contradict each other: detaching leaves no branch to name",
        ));
    }
    if args.on("--detach") && args.on("--no-checkout") {
        return Err(CliError::usage(
            "--detach and --no-checkout contradict each other: detaching is a working-tree \
             move, which is the one thing --no-checkout promises not to make",
        ));
    }
    let repo = Repo::discover(args)?;
    if repo.bare()? {
        return Err(CliError::refused(
            format!(
                "{} is a bare repository, so there is no working tree to check out into",
                repo.dir.display()
            ),
            "run this in a clone, or say --no-checkout to bring the objects and the ref and \
             leave the worktree alone",
        ));
    }
    // Before the store is opened, let alone fetched from: a refusal should cost nothing,
    // and the paths are the whole of what the person needs.
    let dirty = if args.on("--no-checkout") {
        Vec::new()
    } else {
        repo.dirty_paths()?
    };
    if !dirty.is_empty() {
        return Err(CliError::refused(
            format!(
                "{} has uncommitted changes: {}",
                repo.dir.display(),
                dirty.join(", ")
            ),
            "commit or stash them first: a checkout that folded your work into someone \
             else's change leaves you unable to tell the two apart, and `git status` is the \
             only thing that ever said which was which",
        ));
    }
    let store = read_store(args)?;
    if store.host.kind() != HostKind::Git {
        return Err(CliError::refused(
            format!(
                "{} cannot serve a git packfile — a {} store has no way to hand git \
                 objects over — so it cannot hand over the commits a checkout is",
                store.what,
                store.host.kind()
            ),
            "only a plain-git store speaks git objects (ADR-0003 D5): `gitiup change show` \
             reads the record and prints the refspec, `gitiup verify change` judges the \
             proofs, and a `git fetch` of the change refs does the rest — or name the \
             repository's git URL as the remote",
        ));
    }
    let found = resolve_handle(&*store.host, &handle)?;
    let id = found.change_id.clone();
    let reference = match args.get("--attempt") {
        Some(text) => {
            let index = text
                .parse::<u32>()
                .map_err(|_| CliError::usage(format!("--attempt '{text}' is not a number")))?;
            change::attempt_ref(&id, index)
        }
        None => change::change_head_ref(&id),
    };
    let fetched = change::change_at(&*store.host, &reference).map_err(store_refusal)?;
    let StoredRecord::Change(record) = fetched.record.clone() else {
        return Err(CliError::refused(
            format!(
                "{} holds a {} record",
                fetched.reference,
                fetched.record.record_type()
            ),
            "a change's head and attempts hold gitiup-change-1 records",
        ));
    };
    let head = oid_hex(&record.head).to_string();
    let subject = Oid::from_hex(&head).map_err(|e| {
        CliError::refused(
            format!("{}'s head '{}' is not an object id: {e}", id, record.head),
            "a change names a git commit, algorithm-tagged, as `git rev-parse` prints one",
        )
    })?;
    // Read everything the store has to say before a byte is written anywhere, so that a
    // refusal — no round for that job, a proof whose bytes the store cannot return —
    // leaves the clone exactly as it was.
    let (mut proofs, odd) = Proof::for_commit(&*store.host, &repo, &subject)?;
    let for_job = match args.get("--for") {
        Some(job) => Some(ForJob::read(&*store.host, &id, job, &record, args)?),
        None => None,
    };
    let base_here = repo.holds(oid_hex(&record.base.oid));
    let mut prefixes = vec![
        change::change_prefix(&id),
        gitiup_host::attest::prefix(&subject),
    ];
    if proofs.iter().any(|proof| proof.legacy) {
        prefixes.push(
            gitiup_host::attest::legacy_ref_name(&subject)
                .as_str()
                .to_string(),
        );
    }
    if let Some(job) = &for_job {
        prefixes.extend(job.ref_prefixes()?);
    }
    let haves = usable_haves(&repo, &*store.host)?;
    let pack = fetch_change(&*store.host, &prefixes, &haves)?;
    if pack.bytes > 0 {
        repo.index_pack(&pack.raw)?;
    }
    // The promise, checked instead of announced: the ref arrived, so the commit and every
    // proof filed under it must be in this object database now.
    if !repo.holds(&head) {
        return Err(CliError::refused(
            format!(
                "the store's refs for {id} do not carry {}, so nothing arrived to check out",
                record.head
            ),
            "the record was published and the commits were not — `submit --no-objects` says \
             \"the store already holds them\" out loud, and a store that was told that does \
             not hold them (ADR-0003 D5). Re-submit with the objects, or fetch the commits \
             from wherever they really are",
        ));
    }
    for proof in &mut proofs {
        proof.arrived = repo.holds(&proof.blob);
    }
    let lost: Vec<&Proof> = proofs.iter().filter(|proof| !proof.arrived).collect();
    if !lost.is_empty() {
        return Err(CliError::new(
            gitiup_attest::ErrorKind::DigestMismatch,
            format!(
                "the pack carried the change but not {} of its {} proof(s): {}",
                lost.len(),
                proofs.len(),
                lost.iter()
                    .map(|proof| short_id(&proof.digest))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Some(
                "a ref in refs/attestations/** that arrives without its bytes is a broken \
                 proof: the store advertised more than it moved",
            ),
        ));
    }
    let landing = land(args, &repo, &id, &head)?;
    if args.json() {
        print_json(json!({
            "store": store.what,
            "repository": repo.dir.display().to_string(),
            "change": id.as_str(),
            "state": found.state.as_str(),
            "attempt": record.attempts.index,
            "reference": fetched.reference.as_str(),
            "record_digest": tagged(fetched.digest),
            "change_digest": record.change_digest().unwrap_or_default(),
            "head": record.head,
            "title": record.title,
            "base": {
                "ref": record.base.branch,
                "oid": record.base.oid,
                "held_here": base_here,
            },
            "fetch": {
                "form": pack.form,
                "objects": pack.objects,
                "bytes": pack.bytes,
                "haves": pack.haves,
                "degraded": pack.degraded,
                "prefixes": pack.prefixes,
            },
            "proofs": proofs.iter().map(Proof::json).collect::<Vec<_>>(),
            "proof_count": proofs.len(),
            "unexpected_refs": odd,
            "quorum": for_job.as_ref().map(ForJob::json),
            "landed": {
                "ref": landing.reference,
                "action": landing.action,
                "worktree": landing.worktree,
                "at": record.head,
            },
        }));
        return Ok(());
    }
    println!(
        "checkout {} attempt {} \u{b7} {}",
        id, record.attempts.index, found.state
    );
    println!("  store    {}", store.what);
    println!(
        "  ref      {} -> record {}",
        fetched.reference,
        short_id(&tagged(fetched.digest))
    );
    println!(
        "  head     {} \u{b7} {}",
        short_id(&record.head),
        clip(&record.title, 48)
    );
    println!(
        "  base     {} @ {} [{}]",
        record.base.branch,
        short_id(&record.base.oid),
        if base_here {
            "held here"
        } else {
            "not in this clone: its objects came with the pack"
        }
    );
    println!(
        "  fetched  {}",
        if pack.bytes == 0 {
            "nothing \u{2014} this clone already holds the change and every proof of it".to_string()
        } else {
            format!(
                "{} objects, {} bytes as a git packfile \u{b7} {} of the clone's refs were \
                 already in the store and were not fetched twice{}",
                pack.objects,
                pack.bytes,
                pack.haves,
                if pack.degraded {
                    " (the store could not honour them, so this pack is larger than it was)"
                } else {
                    ""
                }
            )
        }
    );
    for prefix in &pack.prefixes {
        // A directory prefix is what the fetch wildcard means. An exact ref — a verdict,
        // one per change and job — is printed as itself, because `…/linux-x86_64*` would
        // advertise siblings the layout does not have.
        if prefix.ends_with('/') {
            println!("           {prefix}*");
        } else {
            println!("           {prefix}");
        }
    }
    if proofs.is_empty() {
        println!(
            "  proofs   none yet \u{b7} {} is what a run signs afterwards",
            gitiup_host::attest::prefix(&subject)
        );
    } else {
        println!(
            "  proofs   {} arrived with the pack, for {}",
            proofs.len(),
            short_id(&record.head)
        );
        for proof in &proofs {
            println!(
                "           {}  {:<9} {} \u{b7} {}{}",
                short_id(&proof.digest),
                proof.tier,
                proof
                    .signers
                    .iter()
                    .map(String::as_str)
                    .map(short)
                    .collect::<Vec<_>>()
                    .join(","),
                rfc3339(proof.claimed_at_us),
                if proof.legacy {
                    " \u{b7} legacy ref"
                } else {
                    ""
                }
            );
        }
    }
    for name in &odd {
        eprintln!("note: {name} is in the attestation namespace but not this layout");
    }
    if let Some(job) = &for_job {
        job.text();
    }
    println!(
        "  worktree {}",
        match (landing.reference.as_deref(), landing.action) {
            (_, "detached") => format!("detached at {}", short_id(&record.head)),
            (Some(full), "written") => format!(
                "left alone; {} now names {}",
                branch_of(full),
                short_id(&record.head)
            ),
            (Some(full), "created") => format!(
                "checked out on branch {} at {}",
                branch_of(full),
                short_id(&record.head)
            ),
            (Some(full), "unchanged") => format!(
                "already on {} at {}",
                branch_of(full),
                short_id(&record.head)
            ),
            (Some(full), _) => format!(
                "fast-forwarded {} to {}",
                branch_of(full),
                short_id(&record.head)
            ),
            (None, _) => "not moved".to_string(),
        }
    );
    let named = match (args.get("--remote"), args.get("--store")) {
        (Some(name), _) => format!("--remote {name}"),
        (None, Some(dir)) => format!("--store {dir}"),
        (None, None) => "--remote <name>".to_string(),
    };
    println!("  next     gitiup verify change {id} {named}");
    println!(
        "           the tally is `gitiup quorum verdict {id} --job {}`'s exit code, not \
         this one's",
        args.get("--for").unwrap_or("<job>")
    );
    Ok(())
}

/// Write the change into the clone: a branch that may move, or a detached HEAD.
///
/// The rule on a branch is the rule everywhere else in gitiup: a ref moves forward or it
/// does not move. `change merge` will not rewind a branch in the store and this will not
/// quietly rewind one in someone's clone either — the fast-forward test is the same test.
fn land(args: &Args, repo: &Repo, id: &ChangeId, head: &str) -> Result<Landing, CliError> {
    if args.on("--detach") {
        repo.change(&["checkout", "--detach", head])?;
        return Ok(Landing {
            reference: None,
            action: "detached",
            worktree: "detached",
        });
    }
    let name = match args.get("--ref") {
        Some(text) if text.starts_with("refs/") => text.to_string(),
        Some(text) if text.is_empty() || text.starts_with('-') => {
            return Err(CliError::usage(format!("'{text}' is not a ref name")));
        }
        Some(text) => format!("refs/heads/{text}"),
        // The change id is the default because it is derived, copyable from the store and
        // cannot collide with a branch the clone already had by accident.
        None => format!("refs/heads/{}", id.as_str()),
    };
    RefName::new(name.clone()).map_err(|e| {
        CliError::usage(format!(
            "'{name}' is not a ref this repository will accept: {e}"
        ))
    })?;
    let short = name
        .strip_prefix("refs/heads/")
        .unwrap_or(&name)
        .to_string();
    let action: &'static str = match repo.ref_oid(&name)? {
        Some(existing) if oid_hex(&existing) == head => "unchanged",
        Some(existing) if repo.is_ancestor(oid_hex(&existing), head) => "fast-forwarded",
        Some(existing) => {
            // Both oids, spelled the same way: the whole point of the message is the
            // comparison, and a refusal that says "would drop commits" without naming
            // which commits is advice nobody can act on.
            let here = tag_oid(&existing).unwrap_or_else(|| existing.clone());
            let there = tag_oid(head).unwrap_or_else(|| head.to_string());
            let free = format!("refs/heads/{}", id.as_str());
            return Err(CliError::refused(
                format!(
                    "{name} is {here} in this clone and {id}'s head is {there}, so moving \
                     it would drop commits"
                ),
                format!(
                    "a ref moves forward or it does not move: name somewhere else with \
                     --ref ({free} is free here), delete the branch if it really is spent, \
                     or look at the change without a branch using --detach"
                ),
            ));
        }
        None => "created",
    };
    if args.on("--no-checkout") {
        if action != "unchanged" {
            if action == "created" {
                repo.change(&["branch", &short, head])?;
            } else {
                repo.change(&["branch", "-f", &short, head])?;
            }
        }
        return Ok(Landing {
            reference: Some(name),
            action: "written",
            worktree: "left alone",
        });
    }
    repo.change(&["checkout", "-B", &short, head])?;
    let now = repo.oid("HEAD", "HEAD")?;
    if oid_hex(&now) != head {
        return Err(CliError::io(format!(
            "HEAD is {now} after a checkout of {head}"
        )));
    }
    Ok(Landing {
        reference: Some(name),
        action,
        worktree: "checked out",
    })
}

/// A branch ref the way `git branch` prints it. A ref outside `refs/heads/` keeps its
/// full name, because it has no short form that means only itself.
fn branch_of(name: &str) -> &str {
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// A sentence that stays one line, however the store wrote it.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" \u{2014} ")
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn print_json(value: Value) {
    keys::print_json(value);
}

/// A table cell that never wraps: the middle goes, the ends stay, because a title that
/// pushes a table out of shape hides the ids beside it.
fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('\u{2026}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_are_tagged_or_they_are_nothing() {
        assert_eq!(
            tag_oid("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678").as_deref(),
            Some("sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
        );
        assert!(
            tag_oid(&"ab".repeat(32)).unwrap().starts_with("sha256:"),
            "a 32-byte digest is a sha256"
        );
        assert!(tag_oid("abc").is_none());
        assert!(tag_oid(&"z".repeat(40)).is_none());
        assert_eq!(oid_hex("sha1:a1b2"), "a1b2");
        assert_eq!(oid_hex("a1b2"), "a1b2");
    }

    #[test]
    fn a_store_oid_is_spelled_the_way_the_record_spells_its_own() {
        let oid = Oid::from_hex("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678").unwrap();
        assert_eq!(
            format_oid(&oid, "sha1:5f3e0d0b1a6c4e8f9a7b3c2d1e0f4a6b8c9d0e1f"),
            format!("sha1:{}", oid.hex())
        );
    }

    #[test]
    fn a_principal_is_one_line_and_within_its_limit() {
        assert_eq!(display("  ada@example.org \n"), "ada@example.org");
        assert_eq!(display(""), "unknown");
        let long = "é".repeat(400);
        assert!(display(&long).len() <= gitiup_host::change::MAX_PRINCIPAL_BYTES);
        assert!(display("a\tb\u{7}c").chars().all(|c| !c.is_control()));
    }

    #[test]
    fn batch_output_is_split_into_objects() {
        let out = b"0000000000000000000000000000000000000001 commit 4\nhead\n0000000000000000000000000000000000000002 blob 2\nhi\n";
        let objects = parse_batch(out).expect("two objects");
        assert_eq!(objects, vec![b"head".to_vec(), b"hi".to_vec()]);
        assert!(parse_batch(b"deadbeef missing\n").is_err());
    }

    #[test]
    fn clipping_keeps_the_ends_and_adds_one_mark() {
        assert_eq!(clip("hello", 10), "hello");
        assert_eq!(clip("hello world", 6), "hello\u{2026}");
        assert_eq!(clip("", 3), "");
    }

    #[test]
    fn the_help_text_names_every_subcommand_and_the_exit_table() {
        for word in [
            "new",
            "submit",
            "list",
            "show",
            "--base",
            "--change",
            "--state",
            "--record",
            "--attempt",
            // The quorum half of `submit` (giti-zp1.2), which a person has to be able to
            // find without reading the source.
            "--no-quorum",
            "--selector",
            "--seed-file",
            "--trust",
            "--explain",
        ] {
            assert!(
                CHANGE_HELP.contains(word),
                "{word} is missing from the help"
            );
        }
        for code in ["0 ok", "2 usage", "3 I/O", "6 refused", "7", "8"] {
            assert!(CHANGE_HELP.contains(code), "{code} is missing");
        }
    }

    /// A flag in the help that the parser does not know is a lie, and a flag the parser knows
    /// that the help does not mention is a flag nobody will ever use. Both are the same
    /// mistake — two lists edited apart — so they are checked against each other.
    #[test]
    fn the_help_and_the_parser_agree_on_every_flag() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                CHANGE_HELP.contains(flag),
                "{flag} is accepted but not documented"
            );
        }
        let known = SWITCHES
            .iter()
            .chain(VALUED.iter())
            .copied()
            .collect::<BTreeSet<&str>>();
        // `--json` and `--help` are accepted by the parser everywhere and spelled in the
        // closing paragraph rather than in a flag list.
        let prose = ["--json", "--help"];
        for word in CHANGE_HELP
            .split_whitespace()
            .map(|word| word.split('=').next().unwrap_or(word))
            .filter(|word| word.starts_with("--") && word.len() > 2)
            .filter(|word| word.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        {
            assert!(
                known.contains(word) || prose.contains(&word),
                "`gitiup change help` documents {word}, which the parser does not accept"
            );
        }
    }
}

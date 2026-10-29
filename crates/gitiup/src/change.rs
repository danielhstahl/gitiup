//! `gitiup change …` — the contributor's side of a change, on any host (giti-b2z.3).
//!
//! Four commands, and they are the whole of the contributor's surface:
//!
//! ```text
//! gitiup change new   --base main              draft a record from local commits, write --out
//! gitiup change submit                         publish head ref + record to the resolved store
//! gitiup change list  [--state open] [--json]
//! gitiup change show  <id> [--json]
//! ```
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
//! base, an attempt that already exists with a different head, a conflict) · 7 a
//! signature that does not verify · 8 bytes that are not their own canonical form or a
//! digest that does not match.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use gitiup_attest::TimeUs;
use gitiup_host::change::{self, AttemptInfo, ChangeId, ChangeRecord, State, StoredRecord};
use gitiup_host::{Actor, Host, Namespace, Oid, RefName, RefQuery};
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::attest::{rfc3339, short};
use crate::keys::{self, Args};
use crate::participant::{self, Opened};

/// Help for `gitiup change`.
pub const CHANGE_HELP: &str = "\
gitiup change — propose work to a store, with no forge

USAGE:
    gitiup change new    [OPTIONS]
    gitiup change submit [OPTIONS]
    gitiup change list   [OPTIONS]
    gitiup change show   <ID> [OPTIONS]

A change is one signed record in a content-addressed store, advertised by a ref
(ADR-0003). It is not a pull request: the record names the commit it proposes, the
branch it is proposed against and the oid that branch was at where this work forked,
and it is signed by the key that proposed it. `who proposed this` is a signature, so
a mirror, a bucket and a forge all say the same thing about it.

WHERE IT GOES (submit, list, show):
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

list — every change the store advertises:
    --state <state>          open (default), merged, abandoned or all
    --json                   one line, sorted keys: per change its id, state, attempts,
                             head, base, whether the base is still what the store has,
                             author, title and both digests

show — one change, read back through the ref that advertises it:
    ID                       a change id or any unambiguous prefix of its hex (>= 4)
    --attempt <n>            show attempt n rather than the current one
    --bytes                  the exact stored bytes, and nothing else
    --json                   the record, its digests, its signature, the attempt chain,
                             and the merge/abandon record if the change has one

All: -j, --json on anything a script reads. Passphrases follow `gitiup key`:
--passphrase-file <path|-> or GITIUP_KEY_PASSPHRASE, never a prompt a script cannot
answer.

A re-submit is never an overwrite. Amending the commits is attempt n+1 of the same
change (say which change with --change, because your amended head cannot recompute its
own name), and an attempt ref that exists is never moved: publishing different bytes
where an attempt already stands is refused with both digests.

Exit codes: 0 ok · 2 usage · 3 I/O, store unreachable · 6 refused (no store, no key,
unsigned record, stale base naming both oids, attempt conflict, an id you cannot sign
for) · 7 a signature that does not verify · 8 bytes that are not the record's own
canonical form, or a digest that does not match its name.
";

/// Switches `gitiup change …` accepts.
const SWITCHES: &[&str] = &["--no-jobs", "--no-objects", "--new-attempt", "--bytes"];

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
        other => Err(CliError::usage(format!(
            "unknown `gitiup change` command '{other}'; `gitiup change help` lists new, \
             submit, list and show"
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
fn read_store(args: &Args) -> Result<Opened, CliError> {
    participant::store_from(args)?.ok_or_else(|| {
        CliError::refused(
            "no store was named",
            "say where to look: --store <dir> or --remote <name> (see `gitiup doctor --remotes`)",
        )
    })
}

/// A host error keeps the code the library decided, so `gitiup change` and a merge gate
/// calling the same check cannot disagree about the same store.
fn host_error(what: &str, error: gitiup_host::HostError) -> CliError {
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
fn resolve_handle(host: &dyn Host, handle: &str) -> Result<change::ChangeSummary, CliError> {
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
        origin: change::Origin::store(),
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
            "note": refitted,
            "other_open_by_same_author": siblings,
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
    let shown: Vec<&Row> = all
        .iter()
        .filter(|row| filter.is_none_or(|state| row.summary.state == state))
        .collect();

    if args.json() {
        let changes: Vec<Value> = shown.iter().map(|row| row_json(row)).collect();
        print_json(json!({
            "store": store.what,
            "state": args.get("--state").unwrap_or("open"),
            "count": changes.len(),
            "changes": changes,
            "unexpected_refs": catalog.unexpected,
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
        let summary = &row.summary;
        match &row.detail {
            Ok(parsed) => println!(
                "{}  {:<9} a{:<3} {:<20} {:<14} {}{}",
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
                }
            ),
            Err(error) => println!(
                "{}  {:<9} UNREADABLE  {}",
                summary.change_id,
                summary.state.as_str(),
                error.message
            ),
        }
        if !summary.head_tracks_newest {
            eprintln!(
                "note: {}'s head ref is behind its newest attempt — a submit died between \
                 the two writes; re-running that submit finishes it (ADR-0003 D6)",
                summary.change_id
            );
        }
    }
    for name in &catalog.unexpected {
        eprintln!("note: {name} is in the change namespace but not this layout");
    }
    Ok(())
}

fn row_json(row: &Row) -> Value {
    let summary = &row.summary;
    let base = json!({
        "change": summary.change_id.as_str(),
        "state": summary.state.as_str(),
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

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn show(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(CHANGE_HELP) {
        return Ok(());
    }
    let store = read_store(args)?;
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
}

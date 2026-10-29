//! `gitiup change merge` and `gitiup change reconcile`, run as the real binary
//! (giti-b2z.4).
//!
//! The ticket's acceptance criteria are command lines and exit codes, so they are tested
//! as command lines: a real repository (the fast-forward is a fact about parents, and only
//! `git` gets to say it), a real keystore (the merge record is signed by whoever merged),
//! and a real store per case. A dry run that touched nothing and a merge that wrote the
//! branch are two different claims, so both are read back from the store rather than from
//! the program's own stdout.
//!
//! One criterion is *not* tested here: "a refusal the store owns arrives in the store's own
//! words". The `fs` store never refuses on policy, and inventing a refusal would mean
//! wrapping a host — which is what `gitiup-host`'s `change_merge.rs` does, with a store
//! that denies `refs/heads/**` and a test that asserts the taxonomy label, the sentence and
//! the exit code all survive the trip. What this file can assert is the CLI's own taxonomy:
//! a stale base is 6 with both oids, a flag asking for a policy decision is 6, and a usage
//! mistake is 2.
//!
//! The forge path is in the same position: driving a forge needs a mock forge, and the mock
//! lives in `gitiup-host-github` as an in-process transport, not a URL this binary can be
//! pointed at. `tests/forge.rs` there merges a pull request and asserts the forge's refusal
//! stays a refusal; what the CLI has to add on top — `via: forge` in the record, and what the
//! forge landed rather than what the attempt proposed — is asserted here through
//! `change reconcile --via forge --landed`, which is the same record with the same fields.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{
    BlobStore, Expect, FsHost, Namespace, Oid, RefName, RefQuery, RefStore, RefUpdate,
};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";

/// A config home, a store, a repository, and the binary pointed at all three.
struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            dir: tempfile::tempdir().expect("a temp home"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn store(&self) -> String {
        self.path()
            .join("store")
            .to_str()
            .expect("utf-8")
            .to_string()
    }

    /// Run the binary with this home, from the temp directory.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .current_dir(self.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait")
    }

    fn key(&self, name: &str) -> String {
        let output = self.run(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
        let listed = self.run(&["key", "list", "--json"], None);
        assert!(listed.status.success(), "{}", stderr(&listed));
        let keys: Vec<Value> = serde_json::from_str(&stdout(&listed)).expect("key list json");
        keys.iter()
            .find(|record| record["name"].as_str() == Some(name))
            .expect("the key is listed")["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.store()).expect("open the fs store")
    }

    /// `refs/heads/<branch>` at `base`: the owner's act, done with the host API because
    /// nothing in gitiup publishes a branch (docs/host-abstraction.md).
    fn seed(&self, branch: &str, base: &str) {
        self.host()
            .update_ref_cas(&RefUpdate::new(
                RefName::branch(branch).expect("a branch name"),
                Expect::Absent,
                Oid::from_hex(base).expect("an oid"),
            ))
            .expect("publish the branch");
    }

    /// Move a branch, which is how a stale base — and D8's failure window — happens.
    fn move_branch(&self, branch: &str, from: &str, to: &str) {
        self.host()
            .update_ref_cas(&RefUpdate::replace(
                RefName::branch(branch).expect("a branch name"),
                Oid::from_hex(from).expect("an oid"),
                Oid::from_hex(to).expect("an oid"),
            ))
            .expect("move the branch");
    }

    /// Where a branch stands now, or `None`.
    fn branch(&self, branch: &str) -> Option<String> {
        self.host()
            .get_ref(&RefName::branch(branch).expect("a branch name"))
            .expect("read the branch")
            .map(|reference| reference.oid.hex().to_string())
    }

    /// Every change ref in the store, for the "a dry run touched nothing" assertions.
    fn change_refs(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .host()
            .list_refs(&RefQuery::all())
            .expect("list refs")
            .into_iter()
            .map(|reference| reference.name.as_str().to_string())
            .collect();
        names.sort();
        names
    }

    /// File bytes in the store's attestation namespace and name their digest, which is
    /// what a cited proof is.
    fn proof(&self, bytes: &[u8]) -> String {
        self.host()
            .put_cas(&Namespace::ATTESTATION, bytes)
            .expect("file the proof")
            .hex()
            .to_string()
    }

    /// A real signed attestation about `subject`, filed and advertised, and its digest —
    /// the difference between a citation retention can be shown a ref for and one it
    /// cannot, which is what the merge's pins are for.
    fn attestation(&self, subject: &str, fixture: &str) -> String {
        let report = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-attest/tests/fixtures/runs")
            .join(fixture)
            .join("run.json")
            .to_str()
            .expect("fixture path")
            .to_string();
        let output = self.run(
            &[
                "attest",
                "push",
                "--run-report",
                &report,
                "--subject",
                subject,
                "--sign",
                "--store",
                &self.store(),
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "`attest push {fixture}` failed: {}",
            stderr(&output)
        );
        json(&output)["digest"]
            .as_str()
            .expect("a digest")
            .to_string()
    }

    /// `attest gc` as a dry run over one commit, which is the only honest way to ask
    /// what retention would do to a store right now.
    fn gc(&self, subject: &str, max_age: &str) -> Value {
        let output = self.run(
            &[
                "attest",
                "gc",
                "--commit",
                subject,
                "--max-age",
                max_age,
                "--store",
                &self.store(),
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "`attest gc` failed: {}",
            stderr(&output)
        );
        json(&output)
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Both streams: a refusal may be split across them by whoever printed it.
fn said(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

fn ok(output: &Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} failed ({}): {}",
        code(output),
        said(output)
    );
    json(output)
}

fn refused(output: &Output, what: &str) -> Value {
    assert_eq!(
        code(output),
        6,
        "{what} should have been refused with 6, said: {}",
        said(output)
    );
    serde_json::from_str(&stdout(output))
        .ok()
        .unwrap_or(Value::Null)
}

/// The repository: `main` with two commits, then `feature` one ahead of the second, so
/// that `main`'s tip is a real fast-forward ancestor and its first commit is an ancestor
/// that is *not* the record's base — which is what `--expected-oid` is for.
struct Repo {
    dir: PathBuf,
    /// `main`'s first commit.
    root: String,
    /// `main`'s tip: the base a change forks from.
    base: String,
    /// `feature`'s commit: the head a change proposes.
    head: String,
}

impl Repo {
    fn new(harness: &Harness) -> Repo {
        let dir = harness.path().join("work");
        std::fs::create_dir_all(&dir).expect("work dir");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["config", "user.email", "ada@example.org"]);
        git(&dir, &["config", "user.name", "Ada"]);
        git(&dir, &["config", "commit.gpgsign", "false"]);
        std::fs::write(dir.join("Makefile"), "all:\n\t@echo one\n").expect("file");
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "Add the build"]);
        let root = git(&dir, &["rev-parse", "HEAD"]);
        std::fs::write(dir.join("README.md"), "two\n").expect("file");
        git(&dir, &["add", "README.md"]);
        git(&dir, &["commit", "-q", "-m", "Document the build"]);
        let base = git(&dir, &["rev-parse", "HEAD"]);
        git(&dir, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(dir.join("extra.txt"), "proposed\n").expect("file");
        git(&dir, &["add", "extra.txt"]);
        git(&dir, &["commit", "-q", "-m", "Propose the extra file"]);
        let head = git(&dir, &["rev-parse", "HEAD"]);
        Repo {
            dir,
            root,
            base,
            head,
        }
    }

    /// A second commit on `feature`: a fast-forward of two, so a merge is not doing one
    /// commit's work and a broken one is not subtle.
    fn commit_again(&self, message: &str) -> String {
        std::fs::write(self.dir.join("more.txt"), format!("{message}\n")).expect("file");
        git(&self.dir, &["add", "more.txt"]);
        git(&self.dir, &["commit", "-q", "-m", message]);
        git(&self.dir, &["rev-parse", "HEAD"])
    }

    fn path(&self) -> &str {
        self.dir.to_str().expect("utf-8")
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `sha1:<hex>`, the form a record spells an oid in.
fn tagged(hex: &str) -> String {
    format!("sha1:{hex}")
}

/// Draft and submit one attempt, and hand back its change id. The full loop belongs to
/// `change_cli.rs`; here it is the precondition every merge starts from.
fn submitted(harness: &Harness, repo: &Repo) -> String {
    let new = harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--out",
            "record.json",
        ],
        None,
    );
    assert!(new.status.success(), "{}", said(&new));
    let output = harness.run(
        &[
            "change",
            "submit",
            "--record",
            "record.json",
            "--repository",
            repo.path(),
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    ok(&output, "change submit")["change"]
        .as_str()
        .expect("a change id")
        .to_string()
}

/// Set up a store with one open change, and return its id.
fn setup() -> (Harness, Repo, String) {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    harness.seed("main", &repo.base);
    let id = submitted(&harness, &repo);
    (harness, repo, id)
}

fn merge(harness: &Harness, repo: &Repo, id: &str, extra: &[&str]) -> Output {
    let store = harness.store();
    let args = [
        "change",
        "merge",
        id,
        "--store",
        &store,
        "--repository",
        repo.path(),
    ]
    .iter()
    .chain(extra.iter())
    .copied()
    .collect::<Vec<&str>>();
    harness.run(&args, None)
}

fn show(harness: &Harness, id: &str) -> Value {
    ok(
        &harness.run(
            &["change", "show", id, "--store", &harness.store(), "--json"],
            None,
        ),
        "change show",
    )
}

// ---------------------------------------------------------------------------
// the merge that works
// ---------------------------------------------------------------------------

#[test]
fn a_merge_moves_the_branch_under_cas_and_writes_its_record() {
    let (harness, repo, id) = setup();
    let refs_before = harness.change_refs();
    let output = merge(&harness, &repo, &id, &["--json"]);
    let done = ok(&output, "change merge");
    assert_eq!(done["change"], id);
    assert_eq!(done["attempt"], 0);
    assert_eq!(done["branch"], "refs/heads/main");
    assert_eq!(
        done["from"],
        tagged(&repo.base),
        "the CAS expected the signed base"
    );
    assert_eq!(
        done["to"],
        tagged(&repo.head),
        "and wrote the attempt's head"
    );
    assert_eq!(done["moved"], true);
    assert_eq!(done["via"], "store");
    assert!(
        done["atomicity"]
            .as_str()
            .unwrap_or_default()
            .contains("conditional"),
        "the output has to say what kind of guarantee this was: {done}"
    );
    assert_eq!(
        done["proofs"].as_array().expect("a proofs array").len(),
        0,
        "nothing was believed, and the record says so rather than saying nothing"
    );
    assert!(done["merger"]["key_id"].is_string(), "who merged is data");
    assert!(
        done["kv"]
            .as_str()
            .unwrap_or_default()
            .starts_with("kv/merge/"),
        "the record landed under its own digest: {done}"
    );
    assert_eq!(
        done["merged_ref"],
        format!("refs/changes/{id}/merged"),
        "and is advertised by a ref, because that is what a state is here"
    );

    // The branch really moved, read back through the store rather than the program.
    assert_eq!(
        harness.branch("main").as_deref(),
        Some(repo.head.as_str()),
        "a merge that did not move the branch is not a merge"
    );
    let shown = show(&harness, &id);
    assert_eq!(shown["state"], "merged");
    let merged = &shown["merged"];
    assert_eq!(merged["type"], "gitiup-merge-1");
    assert_eq!(
        merged["change_digest"], shown["change_digest"],
        "the record names the attempt it merged, by the digest that never moves"
    );
    assert_eq!(merged["attempt"], 0);
    assert_eq!(merged["base"]["ref"], "refs/heads/main");
    assert_eq!(merged["base"]["from"], tagged(&repo.base));
    assert_eq!(merged["base"]["to"], tagged(&repo.head));
    assert_eq!(merged["via"], "store");
    assert!(
        merged["merged_at_us"].as_i64().unwrap_or_default() > 0,
        "the merge record carries ADR-0001 D6's trusted moment"
    );
    assert!(
        merged["author"]["key_id"].is_string(),
        "the merger signs the merge: {merged}"
    );
    assert_eq!(
        harness.change_refs().len(),
        refs_before.len() + 1,
        "one ref added — the merged advertisement — and nothing else"
    );
    // And `list` agrees, because state is derived from refs and not from memory.
    let listed = ok(
        &harness.run(
            &[
                "change",
                "list",
                "--state",
                "merged",
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change list",
    );
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["changes"][0]["change"], id);
}

#[test]
fn a_dry_run_prints_the_plan_and_touches_nothing() {
    let (harness, repo, id) = setup();
    let refs_before = harness.change_refs();
    let output = merge(&harness, &repo, &id, &["--dry-run", "--json"]);
    let plan = ok(&output, "a dry run");
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["would_write"], true);
    assert_eq!(plan["verb"], "merge");
    assert_eq!(plan["change"], id);
    assert_eq!(plan["from"], tagged(&repo.base));
    assert_eq!(plan["store_oid"], tagged(&repo.base));
    assert_eq!(plan["merged_ref"], format!("refs/changes/{id}/merged"));
    assert_eq!(plan["ancestry"], "fast-forward");
    assert_eq!(harness.branch("main").as_deref(), Some(repo.base.as_str()));
    assert_eq!(
        harness.change_refs(),
        refs_before,
        "the point of --dry-run, in the same spirit as `gitiup attest gc --dry-run`"
    );
    assert_eq!(show(&harness, &id)["state"], "open");

    // In the words a person reads, for the same nothing.
    let text = merge(&harness, &repo, &id, &["--dry-run"]);
    assert!(
        text.status.success(),
        "a dry run in words failed: {}",
        said(&text)
    );
    assert!(said(&text).contains("nothing written"), "{}", said(&text));
    assert_eq!(harness.change_refs(), refs_before);
    assert_eq!(harness.branch("main").as_deref(), Some(repo.base.as_str()));
}

#[test]
fn a_cited_proof_is_a_digest_the_store_can_return_and_is_pinned() {
    let (harness, repo, id) = setup();
    let digest = harness.proof(b"an attestation this merge believed".as_slice());
    let output = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--proof", &format!("sha256:{digest}")],
    );
    let done = ok(&output, "a merge that believed something");
    assert_eq!(
        done["proofs"],
        serde_json::json!([format!("sha256:{digest}")])
    );
    assert_eq!(done["proofs_pinned"], 1);
    assert_eq!(
        show(&harness, &id)["merged"]["proofs"],
        serde_json::json!([format!("sha256:{digest}")])
    );
}

#[test]
fn a_cited_proof_is_pinned_against_retention_and_an_uncited_one_is_not() {
    // The reason a merge cites digests rather than copies, tested at the far end: a
    // digest inside a record is not a ref, so retention would retire the evidence a
    // merge was made on unless the merge registered it. Same store, same policy; the
    // only difference is whether a merge believed the proof.
    let (harness, repo, id) = setup();
    let subject = repo.head.clone();
    let digest = harness.attestation(&subject, "hello");

    // Before the merge: the fixture claims a time old enough that any age limit expires
    // it, and nothing pins it. If this did not prune, the policy would be toothless and
    // the assertion after the merge would prove nothing.
    let before = harness.gc(&subject, "1s");
    assert_eq!(
        before["report"]["pruned"]
            .as_array()
            .expect("pruned list")
            .len(),
        1,
        "the policy has to bite before the merge: {before}"
    );
    assert_eq!(before["report"]["pinned"], 0);

    let output = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--proof", &format!("sha256:{digest}")],
    );
    let done = ok(&output, "a merge that believed the proof");
    assert_eq!(done["proofs_pinned"], 1);

    // After it: the same policy, the same store, and the cited proof is kept because a
    // merge said it believed it.
    let after = harness.gc(&subject, "1s");
    assert_eq!(
        after["report"]["pruned"]
            .as_array()
            .expect("pruned list")
            .len(),
        0,
        "a merge's proof is not what retention is for: {after}"
    );
    assert_eq!(after["report"]["pinned"], 1, "{after}");
    assert_eq!(
        show(&harness, &id)["merged"]["proofs"],
        serde_json::json!([format!("sha256:{digest}")])
    );
}

#[test]
fn a_proof_the_store_cannot_return_is_refused() {
    let (harness, repo, id) = setup();
    let ghost = "0".repeat(64);
    let output = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--proof", &format!("sha256:{ghost}")],
    );
    refused(&output, "a citation nobody can honour");
    let text = said(&output);
    assert!(
        text.contains("cannot return"),
        "the refusal has to say why the digest is not enough: {text}"
    );
    assert!(text.contains(&ghost), "and name the digest: {text}");
    assert_eq!(harness.branch("main").as_deref(), Some(repo.base.as_str()));
    // A git oid is not a proof digest. That is a malformed argument rather than a refusal,
    // so it is 2 — and the sentence says what the wrong thing was, which is the difference
    // between a user learning something and a user guessing.
    let wrong = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--proof", &format!("sha256:{}", repo.head)],
    );
    assert_eq!(code(&wrong), 2, "{}", said(&wrong));
    assert!(said(&wrong).contains("git oid"), "{}", said(&wrong));
}

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

#[test]
fn a_stale_base_is_refused_naming_both_oids() {
    let (harness, repo, id) = setup();
    // Whoever moved `main` first: this change is now stale.
    harness.move_branch("main", &repo.base, &repo.root);
    let output = merge(&harness, &repo, &id, &["--json"]);
    refused(&output, "a stale base");
    let text = said(&output);
    assert!(
        text.contains(&repo.base) && text.contains(&repo.root),
        "both oids, or the message is not actionable: {text}"
    );
    assert!(
        text.contains("in this record") && text.contains("in the store"),
        "the sentence has to say which oid was expected and which was there: {text}"
    );
    assert!(
        text.contains("pull first"),
        "and the one useful instruction: {text}"
    );
    assert_eq!(
        harness.branch("main").as_deref(),
        Some(repo.root.as_str()),
        "nothing moved"
    );
    assert_eq!(show(&harness, &id)["state"], "open");
}

#[test]
fn a_merge_refuses_when_it_cannot_check_the_fast_forward() {
    let (harness, repo, id) = setup();
    // The store holds commits as opaque bytes and refs as numbers: whether the branch is
    // an ancestor is a question about parents, answered by a repository that has them.
    // With none, gitiup refuses instead of guessing — which is the reason this command
    // will not "just try it" from a directory that is not a checkout.
    let elsewhere = harness.path().join("nowhere");
    std::fs::create_dir_all(&elsewhere).expect("a directory that is not a repository");
    let output = harness.run(
        &[
            "change",
            "merge",
            &id,
            "--store",
            &harness.store(),
            "--repository",
            elsewhere.to_str().expect("utf-8"),
            "--json",
        ],
        None,
    );
    refused(&output, "a merge with no objects to ask");
    let text = said(&output);
    assert!(
        text.contains("ancestor") || text.contains("fast-forward"),
        "the refusal should name what it could not establish: {text}"
    );
    assert_eq!(
        harness.branch("main").as_deref(),
        Some(repo.base.as_str()),
        "and it certainly did not force anything"
    );
    assert_eq!(show(&harness, &id)["state"], "open");
}

#[test]
fn a_diverged_history_is_refused_rather_than_merged() {
    let (harness, repo, id) = setup();
    // Move `main` to a commit the change does not contain: no fast-forward exists, and a
    // merge here would drop whoever made that commit.
    let other = harness.path().join("other");
    std::fs::create_dir_all(&other).expect("other dir");
    git(&other, &["init", "-q", "-b", "main"]);
    git(&other, &["config", "user.email", "bob@example.org"]);
    git(&other, &["config", "user.name", "Bob"]);
    git(&other, &["config", "commit.gpgsign", "false"]);
    std::fs::write(other.join("unrelated.txt"), "a different history\n").expect("file");
    git(&other, &["add", "unrelated.txt"]);
    git(&other, &["commit", "-q", "-m", "An unrelated line of work"]);
    let unrelated = git(&other, &["rev-parse", "HEAD"]);
    // The store's ref is moved to it; the objects are not in the contributor's repo, so
    // the ancestry check has to answer `Unknown` about a tip it cannot see.
    harness.move_branch("main", &repo.base, &unrelated);
    let output = merge(&harness, &repo, &id, &["--json"]);
    refused(&output, "a merge that would drop commits");
    assert!(
        said(&output).contains(&unrelated),
        "the message has to name the tip it found: {}",
        said(&output)
    );
    assert_eq!(harness.branch("main").as_deref(), Some(unrelated.as_str()));
}

#[test]
fn a_change_is_merged_exactly_once() {
    let (harness, repo, id) = setup();
    ok(&merge(&harness, &repo, &id, &["--json"]), "the first merge");
    let again = merge(&harness, &repo, &id, &["--json"]);
    refused(&again, "a second merge of the same change");
    let text = said(&again);
    assert!(text.contains("already merged"), "{text}");
    assert!(
        text.contains("un-doing a merge is a new change"),
        "and the advice has to be the true one: {text}"
    );
    assert_eq!(
        harness.branch("main").as_deref(),
        Some(repo.head.as_str()),
        "and the branch is where the first merge left it"
    );
}

#[test]
fn proof_required_is_refused_until_there_is_a_policy_engine() {
    let (harness, repo, id) = setup();
    let output = merge(&harness, &repo, &id, &["--proof-required", "--json"]);
    refused(&output, "--proof-required with no policy engine");
    let text = said(&output);
    assert!(text.contains("policy"), "{text}");
    assert!(
        text.contains("--proof"),
        "and it has to point at the thing that works instead: {text}"
    );
    assert_eq!(code(&harness.run(&["change", "merge", "--help"], None)), 0);
    assert_eq!(
        code(&harness.run(
            &[
                "change",
                "merge",
                &id,
                "--store",
                &harness.store(),
                "--bogus"
            ],
            None
        )),
        2,
        "an unknown flag is usage, not a refusal"
    );
}

// ---------------------------------------------------------------------------
// --expected-oid: the owner's own decision, printed as one
// ---------------------------------------------------------------------------

#[test]
fn an_expected_oid_override_merges_onto_what_the_branch_actually_holds() {
    let (harness, repo, id) = setup();
    // The branch is no longer where the record was signed. The default refuses; naming the
    // oid the owner is really standing on is allowed, because the CAS is against what is
    // in front of them — and the override has to be visible in the record afterwards.
    harness.move_branch("main", &repo.base, &repo.root);
    let output = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--expected-oid", &tagged(&repo.root)],
    );
    let done = ok(&output, "a merge onto a named base");
    assert_eq!(done["from"], tagged(&repo.root));
    assert_eq!(done["to"], tagged(&repo.head));
    assert_eq!(harness.branch("main").as_deref(), Some(repo.head.as_str()));
    let merged = &show(&harness, &id)["merged"];
    assert_eq!(
        merged["base"]["from"],
        tagged(&repo.root),
        "the record states the point the CAS really expected"
    );
    assert!(
        said(&output).contains("named by the caller")
            || harness
                .change_refs()
                .contains(&format!("refs/changes/{id}/merged")),
        "the override is said out loud, not assumed"
    );
    // And a nonsense oid is usage, because it cannot mean anything to the store.
    let nonsense = merge(
        &harness,
        &repo,
        &id,
        &["--json", "--expected-oid", "sha1:not-an-oid"],
    );
    assert_eq!(code(&nonsense), 2, "{}", said(&nonsense));
}

// ---------------------------------------------------------------------------
// D8's failure window
// ---------------------------------------------------------------------------

#[test]
fn a_move_whose_record_did_not_land_is_detected_and_reconciled() {
    let (harness, repo, id) = setup();
    // Step 6 landed and step 7 did not. From the outside that is a branch at the change's
    // head with no `merged` ref, which `show` still calls open — the silence this retry
    // exists to close.
    harness.move_branch("main", &repo.base, &repo.head);
    let blocked = merge(&harness, &repo, &id, &["--json"]);
    refused(&blocked, "a merge of a branch that already moved");
    assert!(
        said(&blocked).contains("reconcile"),
        "the refusal has to carry the retry: {}",
        said(&blocked)
    );

    let output = harness.run(
        &[
            "change",
            "reconcile",
            &id,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    let done = ok(&output, "change reconcile");
    assert_eq!(done["moved"], false, "a reconcile moves nothing");
    assert_eq!(done["via"], "store");
    assert_eq!(done["to"], tagged(&repo.head));
    assert_eq!(
        done["from"],
        tagged(&repo.base),
        "from stays the author's base"
    );
    assert_eq!(
        harness.branch("main").as_deref(),
        Some(repo.head.as_str()),
        "the branch is untouched by the command that only describes it"
    );
    let shown = show(&harness, &id);
    assert_eq!(shown["state"], "merged");
    assert_eq!(shown["merged"]["base"]["from"], tagged(&repo.base));
    assert_eq!(shown["merged"]["base"]["to"], tagged(&repo.head));

    // Reconciling again is the same refusal as merging again: one record per change.
    refused(
        &harness.run(
            &[
                "change",
                "reconcile",
                &id,
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "a second reconcile",
    );
}

#[test]
fn reconcile_refuses_when_the_branch_has_not_moved() {
    let (harness, _repo, id) = setup();
    let output = harness.run(
        &[
            "change",
            "reconcile",
            &id,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    refused(&output, "a reconcile with nothing to reconcile");
    assert!(
        said(&output).contains("change merge"),
        "and it sends the operator to the command that does move it: {}",
        said(&output)
    );
}

#[test]
fn a_forge_merge_is_recorded_where_the_forge_landed_it() {
    let (harness, repo, id) = setup();
    // The shape a forge leaves behind: the branch at a commit that is not the change's
    // head. `--via forge --landed` records what the store shows rather than what a
    // fast-forward would have written.
    let landing = repo.commit_again("A merge commit the forge would have made");
    harness.move_branch("main", &repo.base, &landing);
    let output = harness.run(
        &[
            "change",
            "reconcile",
            &id,
            "--store",
            &harness.store(),
            "--via",
            "forge",
            "--landed",
            &tagged(&landing),
            "--json",
        ],
        None,
    );
    let done = ok(&output, "recording a forge's merge");
    assert_eq!(done["via"], "forge");
    assert_eq!(done["to"], tagged(&landing));
    assert!(
        done["atomicity"]
            .as_str()
            .unwrap_or_default()
            .contains("forge"),
        "and the output says whose guarantee this is: {done}"
    );
    let merged = &show(&harness, &id)["merged"];
    assert_eq!(merged["via"], "forge");
    assert_eq!(merged["base"]["to"], tagged(&landing));
    // A `--via` that is neither word is usage.
    assert_eq!(
        code(&harness.run(
            &[
                "change",
                "reconcile",
                &id,
                "--store",
                &harness.store(),
                "--via",
                "maybe"
            ],
            None
        )),
        2
    );
}

// ---------------------------------------------------------------------------
// the help, which is the interface
// ---------------------------------------------------------------------------

#[test]
fn the_help_names_merge_reconcile_and_the_exit_codes_they_use() {
    let harness = Harness::new();
    for args in [
        vec!["change", "help"],
        vec!["change", "merge", "--help"],
        vec!["change", "reconcile", "--help"],
    ] {
        let output = harness.run(&args, None);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        for word in [
            "merge",
            "reconcile",
            "--expected-oid",
            "--dry-run",
            "--proof",
        ] {
            assert!(text.contains(word), "{args:?} does not document {word}");
        }
        assert!(
            text.contains("6 refused"),
            "the exit table is part of the help"
        );
    }
}

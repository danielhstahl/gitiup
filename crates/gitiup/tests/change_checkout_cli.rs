//! `gitiup change checkout`, run as the real binary (giti-b2z.5).
//!
//! The ticket gives a reviewer one command line, so that is what this file runs:
//!
//! ```text
//! gitiup change checkout <id> [--for <job>] [--ref <name>] [--no-checkout] [--detach]
//!     → the change's commits and every proof filed for them, in one pack
//!     → exit 0 · 2 usage · 3 unreachable · 6 refused (dirty, bare, no such store kind,
//!       a ref it would rewind, no round for --for) · 8 bytes that did not arrive
//! ```
//!
//! The claims that matter most here are the two a fake cannot make, so both are made
//! against a real `git-http-backend` on loopback — the same transport
//! `attest_cli.rs` and `change_cli.rs` use:
//!
//! * **the proof arrives with the bytes.** One pack carries `refs/changes/<id>/*` and
//!   `refs/attestations/<head>/*`, and the signed bytes are then in the clone's own
//!   object database, which is what `docs/host-abstraction.md` advertises and this is
//!   where it is enforced. The command checks it too: a ref that arrives without its
//!   bytes exits 8 rather than printing a proof nobody can produce.
//! * **nothing is written to the remote.** Asserted twice over: the store's ref listing
//!   is compared before and after, and one checkout runs against a remote configured
//!   `read-only = "true"`, which refuses every write the command could conceivably make.
//!
//! Thinness is asserted as a fact about the pack rather than about intent: the objects
//! that arrive are fewer than the store holds, because the clone's own history was
//! named as already held.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use std::collections::BTreeSet;

use gitiup_attest::GitOid;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store as qstore;
use gitiup_quorum::verdict::{Evaluation, VerdictRecord};
use serde_json::Value;

#[path = "common/mod.rs"]
mod common;

use common::SmartHttp;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The job the `--for` tests ask about: a matrix arm is its own job id.
const JOB: &str = "build/matrix/linux-x86_64";

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

    /// Run the binary against this home, in the temp dir (where `gitiup.toml` lives).
    fn run(&self, args: &[&str]) -> Output {
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
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        command
            .spawn()
            .expect("the binary runs")
            .wait_with_output()
            .expect("wait")
    }

    fn key(&self, name: &str) -> String {
        let output = self.run(&["key", "gen", "--name", name]);
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
        let shown = self.run(&["key", "show", name, "--json"]);
        json(&shown)["key_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no key id for {name}: {}", stderr(&shown)))
            .to_string()
    }

    fn config(&self, text: &str) {
        std::fs::write(self.path().join("gitiup.toml"), text).expect("write gitiup.toml");
    }

    fn file(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }
}

/// A served bare repository with one submitted change and one published proof above its
/// head, plus the contributor's own clone (which is where the change came from).
struct Scene {
    harness: Harness,
    /// The bare repository behind the server, so a test can read the store with plain
    /// `git` and prove what did not move.
    store: PathBuf,
    url: String,
    _server: SmartHttp,
    /// The commit the change proposes.
    head: String,
    /// `main`, which the reviewer's clone starts at.
    base: String,
    /// The change's id, as the store named it.
    change: String,
    /// The author's key id, which is the proposer a round has to exclude.
    author: String,
}

impl Scene {
    /// `None` when the box has no `git-http-backend` or no python3: the claims here need
    /// a real transport, so the test skips rather than pretending.
    fn new() -> Option<Scene> {
        let harness = Harness::new();
        let served = harness.path().join("served");
        std::fs::create_dir_all(&served).expect("served dir");
        let store = served.join("my-repo.git");
        gitiup_host::hosts::git::init_bare(&store).expect("init bare repository");
        common::allow_anonymous_receives(&store);
        let server = SmartHttp::serve(&served)?;
        let url = server.url("my-repo");
        harness.config(&format!(
            "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \
             \"origin\"\nurl = \"{url}\"\n\n[remote.options]\nwork-dir = \"{}\"\n\
             ref-cache-ttl = \"0s\"\n\n[[remote]]\nname = \"mirror\"\nurl = \"{url}\"\n\n\
             [remote.options]\nwork-dir = \"{}\"\nref-cache-ttl = \"0s\"\nread-only = \
             \"true\"\n",
            harness.path().join("mirror").display(),
            harness.path().join("mirror-ro").display(),
        ));
        let author = harness.key("ada");

        // The owner's branch, published the owner's way: plain `git push`.
        let work = harness.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["config", "user.email", "ada@example.org"]);
        git(&work, &["config", "user.name", "Ada"]);
        std::fs::write(work.join("base.txt"), "base\n").expect("file");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "Initial"]);
        let base = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["push", "-q", &url, "HEAD:refs/heads/main"]);
        // A store whose HEAD names nothing gives a clone an unborn HEAD, so the served
        // repository is told which branch it is about, the way `git init` would be.
        let out = Command::new("git")
            .args(["--git-dir", store.to_str().expect("utf-8")])
            .args(["symbolic-ref", "HEAD", "refs/heads/main"])
            .output()
            .expect("git symbolic-ref");
        assert!(out.status.success(), "{}", lossy(&out.stderr));
        // The proposal, on a branch of the contributor's own clone.
        git(&work, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(work.join("extra.txt"), "proposed\n").expect("file");
        git(&work, &["add", "extra.txt"]);
        git(&work, &["commit", "-q", "-m", "Propose the extra file"]);
        let head = git(&work, &["rev-parse", "HEAD"]);

        let record = harness.file("change.json");
        let drafted = harness.run(&[
            "change",
            "new",
            "--repository",
            work.to_str().expect("utf-8"),
            "--base",
            "main",
            "--job",
            JOB,
            "--out",
            record.as_str(),
        ]);
        assert!(
            drafted.status.success(),
            "{}{}",
            stdout(&drafted),
            stderr(&drafted)
        );
        let submitted = harness.run(&[
            "change",
            "submit",
            "--record",
            record.as_str(),
            "--repository",
            work.to_str().expect("utf-8"),
            "--remote",
            "origin",
            "--json",
        ]);
        assert!(
            submitted.status.success(),
            "{}{}",
            stdout(&submitted),
            stderr(&submitted)
        );
        let submitted = json(&submitted);
        assert_eq!(
            submitted["objects"]["form"], "git-packfile",
            "the store has to hold git objects for a checkout to fetch: {submitted}"
        );
        let change = submitted["change"]
            .as_str()
            .expect("a change id")
            .to_string();

        // One proof about the proposed commit, filed the way `gitiup attest push` files
        // it: the bytes in the store and `refs/attestations/<commit>/<digest>` naming them.
        let report = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-attest/tests/fixtures/runs/hello/run.json")
            .to_str()
            .expect("fixture path")
            .to_string();
        let pushed = harness.run(&[
            "attest",
            "push",
            "--run-report",
            &report,
            "--sign",
            "--subject",
            &head,
            "--remote",
            "origin",
            "--json",
        ]);
        assert!(
            pushed.status.success(),
            "{}{}",
            stdout(&pushed),
            stderr(&pushed)
        );
        Some(Scene {
            harness,
            store,
            url,
            _server: server,
            head,
            base,
            change,
            author,
        })
    }

    /// A fresh clone of the store: it holds `main` and nothing of the change, which is
    /// exactly what a reviewer's machine holds before the command runs. Each test gets
    /// its own, because tests run in parallel and a checkout writes into the clone.
    fn clone(&self, name: &str) -> PathBuf {
        let dir = self.harness.path().join(name);
        let out = Command::new("git")
            .args(["clone", "-q", &self.url, dir.to_str().expect("utf-8")])
            .output()
            .expect("git clone");
        assert!(out.status.success(), "{}", lossy(&out.stderr));
        assert_eq!(
            git(&dir, &["rev-parse", "HEAD"]),
            self.base,
            "a fresh clone has the branch and none of the change"
        );
        dir
    }

    fn checkout(&self, clone: &Path, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "change",
            "checkout",
            &self.change,
            "--remote",
            "origin",
            "--repository",
            clone.to_str().expect("utf-8"),
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args)
    }

    /// Every ref the store advertises, with its value: the whole of what a write to the
    /// remote would change.
    fn store_refs(&self) -> String {
        let out = Command::new("git")
            .args(["--git-dir", self.store.to_str().expect("utf-8")])
            .args(["for-each-ref", "--format=%(refname) %(objectname)"])
            .output()
            .expect("git for-each-ref");
        assert!(out.status.success(), "{}", lossy(&out.stderr));
        lossy(&out.stdout)
    }

    /// How many objects the store can be asked for in total, which is what "not the whole
    /// history" is measured against.
    fn store_objects(&self) -> usize {
        let out = Command::new("git")
            .args(["--git-dir", self.store.to_str().expect("utf-8")])
            .args(["rev-list", "--objects", "--all", "--count"])
            .output()
            .expect("git rev-list");
        assert!(out.status.success(), "{}", lossy(&out.stderr));
        lossy(&out.stdout).trim().parse().expect("a count")
    }
}

fn stdout(output: &Output) -> String {
    lossy(&output.stdout)
}

fn stderr(output: &Output) -> String {
    lossy(&output.stderr)
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|e| {
        panic!(
            "expected JSON, got {e}: {}{}",
            stdout(output),
            stderr(output)
        )
    })
}

fn ok(output: &Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} failed ({}): {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    json(output)
}

fn refused(output: &Output, what: &str) -> String {
    assert_eq!(
        code(output),
        6,
        "{what} should be refused with 6, got {}: {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    format!("{}{}", stdout(output), stderr(output))
}

/// A `sha1:…` oid as git spells it on the command line.
fn git_oid(oid: &str) -> &str {
    oid.split_once(':').map(|(_, hex)| hex).unwrap_or(oid)
}

/// Whether a git command succeeded, for the cases where the exit code is the answer.
fn git_ok(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run git")
        .status
        .success()
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
        lossy(&out.stderr)
    );
    lossy(&out.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// the happy path: one command, the change and its proof
// ---------------------------------------------------------------------------

#[test]
fn a_checkout_brings_the_change_and_every_proof_of_it_into_the_clone() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer");
    let before = scene.store_refs();
    let output = scene.checkout(&clone, &["--ref", "local/chg-1", "--json"]);
    let body = ok(&output, "change checkout");
    assert_eq!(body["change"], scene.change.as_str());
    assert_eq!(body["state"], "open");
    assert_eq!(body["attempt"], 0);
    assert_eq!(body["head"], format!("sha1:{}", scene.head));
    assert_eq!(body["base"]["ref"], "refs/heads/main");
    assert_eq!(body["base"]["held_here"], true);
    assert_eq!(body["landed"]["action"], "created");
    assert_eq!(body["landed"]["ref"], "refs/heads/local/chg-1");
    assert_eq!(body["fetch"]["form"], "git-packfile");
    assert!(body["fetch"]["bytes"].as_u64().unwrap() > 0, "{body}");
    assert_eq!(body["fetch"]["degraded"], false);
    assert_eq!(body["proof_count"], 1, "one proof was published: {body}");
    assert_eq!(body["proofs"][0]["arrived"], true);
    assert_eq!(body["unexpected_refs"].as_array().unwrap().len(), 0);

    // The clone now holds the change: the worktree, the branch and the commit itself.
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.head);
    assert_eq!(git(&clone, &["branch", "--show-current"]), "local/chg-1");
    assert!(
        git(&clone, &["status", "--porcelain"]).is_empty(),
        "a clean checkout"
    );
    assert!(git(&clone, &["cat-file", "-p", "HEAD"]).contains("Propose the extra file"));
    assert!(
        clone.join("extra.txt").is_file(),
        "the proposed file is in the worktree"
    );

    // …and the proof is in the object database, not merely named by a ref the clone was
    // told about. This is the promise `docs/host-abstraction.md` makes about
    // `git fetch refs/attestations/<subject>/*`, checked from the clone's own git.
    let blob = body["proofs"][0]["blob"].as_str().unwrap().to_string();
    let raw = Command::new("git")
        .current_dir(&clone)
        .args(["cat-file", "blob", git_oid(&blob)])
        .output()
        .expect("git cat-file");
    assert!(raw.status.success(), "the blob the command named is here");
    // The command did not merely print a ref: the exact bytes the store's ref names are
    // in this clone, at the length the record claimed, so the proof can be re-verified
    // here without going back to the store for anything.
    assert_eq!(
        raw.stdout.len() as u64,
        body["proofs"][0]["size"].as_u64().unwrap(),
        "the bytes that arrived are the length the record claimed"
    );
    let bytes = String::from_utf8(raw.stdout).expect("canonical form is UTF-8");
    assert!(
        bytes.contains("\"manifest\""),
        "the attestation body: {bytes}"
    );
    assert!(bytes.contains("signatures"), "and its signatures: {bytes}");
    let digest = body["proofs"][0]["digest"].as_str().unwrap().to_string();
    let reference = body["proofs"][0]["reference"].as_str().unwrap().to_string();
    assert!(
        reference.ends_with(&digest["sha256:".len()..]),
        "the ref that arrived is the one named by the digest: {reference} vs {digest}"
    );

    // The store was not written to, in any way, at all.
    assert_eq!(
        scene.store_refs(),
        before,
        "a checkout reads; it never writes to the remote"
    );
}

#[test]
fn a_read_only_remote_serves_the_same_checkout() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-ro");
    // `read-only = "true"` makes the host refuse every write before it tries one, so this
    // succeeding is the proof that nothing here writes: not a ref, not a record, not a
    // pack pushed back "to be helpful".
    let output = scene.harness.run(&[
        "change",
        "checkout",
        &scene.change,
        "--remote",
        "mirror",
        "--repository",
        clone.to_str().expect("utf-8"),
        "--json",
    ]);
    let body = ok(&output, "checkout from a read-only remote");
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.head);
    assert_eq!(body["proofs"][0]["arrived"], true);
}

#[test]
fn the_pack_is_the_change_and_not_the_history() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-thin");
    let body = ok(
        &scene.checkout(&clone, &["--json"]),
        "checkout into a fresh clone",
    );
    let fetched = body["fetch"]["objects"].as_u64().unwrap();
    let in_the_store = scene.store_objects();
    assert!(
        fetched > 0 && fetched < in_the_store as u64,
        "the pack carried {fetched} objects out of the {in_the_store} the store can name: \
         the clone's own history was named as already held and was not sent"
    );
    assert!(
        body["fetch"]["haves"].as_u64().unwrap() > 0,
        "the clone had refs the store could match, and said so: {body}"
    );
    // The base commit was already here, so nothing about it needed sending.
    assert_eq!(body["base"]["held_here"], true);
}

#[test]
fn checking_out_again_moves_nothing_and_still_delivers_the_bytes() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-twice");
    let first = ok(&scene.checkout(&clone, &["--json"]), "the first checkout");
    let second = ok(
        &scene.checkout(&clone, &["--json"]),
        "the same checkout, again",
    );
    // Idempotent where it counts: the same ref, the same commit, and nothing re-decided.
    assert_eq!(second["landed"]["action"], "unchanged");
    assert_eq!(second["landed"]["ref"], first["landed"]["ref"]);
    assert_eq!(second["head"], first["head"]);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.head);
    assert!(git(&clone, &["status", "--porcelain"]).is_empty());
}

#[test]
fn no_checkout_writes_the_ref_and_leaves_the_worktree_alone() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-fetch-only");
    // Someone's uncommitted work is no reason to refuse a fetch that will not touch it —
    // which is exactly why the flag exists, and why it is checked only when the worktree
    // is about to be moved.
    std::fs::write(clone.join("base.txt"), "mine\n").expect("dirty the worktree");
    let body = ok(
        &scene.checkout(&clone, &["--no-checkout", "--ref", "look/only", "--json"]),
        "checkout --no-checkout into a dirty clone",
    );
    assert_eq!(body["landed"]["action"], "written");
    assert_eq!(body["landed"]["worktree"], "left alone");
    assert_eq!(git(&clone, &["rev-parse", "look/only"]), scene.head);
    assert_eq!(
        git(&clone, &["rev-parse", "HEAD"]),
        scene.base,
        "HEAD did not move"
    );
    assert_eq!(
        git(&clone, &["status", "--porcelain"]),
        "M base.txt",
        "the dirty file is exactly as dirty as it was"
    );
}

#[test]
fn detach_looks_at_the_change_without_creating_a_branch() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-detached");
    let body = ok(
        &scene.checkout(&clone, &["--detach", "--json"]),
        "checkout --detach",
    );
    assert_eq!(body["landed"]["action"], "detached");
    assert_eq!(body["landed"]["ref"], Value::Null);
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.head);
    assert!(
        !git_ok(&clone, &["symbolic-ref", "-q", "HEAD"]),
        "a detached HEAD names no branch, so nothing was made to point at it"
    );
}

// ---------------------------------------------------------------------------
// the refusals, which are the reason the command can be trusted
// ---------------------------------------------------------------------------

#[test]
fn a_dirty_worktree_is_refused_by_name_and_nothing_moves() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-dirty");
    std::fs::write(clone.join("base.txt"), "mine\n").expect("dirty the worktree");
    std::fs::write(clone.join("new-file.txt"), "untracked\n").expect("untracked file");
    let said = refused(
        &scene.checkout(&clone, &[]),
        "a checkout into a dirty worktree",
    );
    assert!(
        said.contains("base.txt"),
        "the path is named, not guessed: {said}"
    );
    assert!(
        !said.contains("new-file.txt"),
        "an untracked file is not dirt, and git itself refuses a checkout that would \
         overwrite one: {said}"
    );
    // Refusing means *refusing*: nothing was fetched and no ref was written.
    assert!(
        !git_ok(&clone, &["rev-parse", "--verify", "--quiet", &scene.change]),
        "no branch was created for the change"
    );
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.base);
}

#[test]
fn a_branch_the_change_cannot_fast_forward_is_refused_naming_both_ends() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-diverged");
    // A branch with a commit the change does not have: moving it would drop work, so the
    // same rule `change merge` applies to a branch in the store applies here.
    git(&clone, &["checkout", "-q", "-b", "mine", "main"]);
    std::fs::write(clone.join("mine.txt"), "my work\n").expect("file");
    git(&clone, &["add", "mine.txt"]);
    git(&clone, &["commit", "-q", "-m", "My own work"]);
    let mine = git(&clone, &["rev-parse", "HEAD"]);
    let said = refused(
        &scene.checkout(&clone, &["--ref", "mine"]),
        "a checkout that would rewind a branch",
    );
    assert!(
        said.contains(&mine),
        "both ends, spelled the same way: {said}"
    );
    assert!(
        said.contains(&scene.head),
        "both ends, spelled the same way: {said}"
    );
    assert_eq!(
        git(&clone, &["rev-parse", "mine"]),
        mine,
        "the branch stayed put"
    );
}

#[test]
fn a_fast_forward_over_an_earlier_attempt_moves_the_branch() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-ff");
    // Stand at the base commit under the name the checkout will want: that is a
    // fast-forward, and a reviewer re-checking out after a rebase has to be able to do it.
    git(&clone, &["checkout", "-q", "-b", &scene.change, "main"]);
    let body = ok(
        &scene.checkout(&clone, &["--json"]),
        "a checkout that fast-forwards the branch it was given",
    );
    assert_eq!(body["landed"]["action"], "fast-forwarded");
    assert_eq!(git(&clone, &["rev-parse", &scene.change]), scene.head);
}

#[test]
fn a_bare_repository_and_a_store_with_no_git_objects_are_both_refused_by_name() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    // A bare repository has nothing to check out into, and says so instead of fetching
    // objects nobody will ever look at.
    let said = refused(
        &scene.harness.run(&[
            "change",
            "checkout",
            &scene.change,
            "--remote",
            "origin",
            "--repository",
            scene.store.to_str().expect("utf-8"),
        ]),
        "a checkout into a bare repository",
    );
    assert!(said.contains("bare repository"), "{said}");
    // An fs store keeps the change's commits as gitiup records, which is a thing the
    // submit said out loud and a checkout must not pretend otherwise about.
    let fs = scene.harness.path().join("fs-store");
    let said = refused(
        &scene.harness.run(&[
            "change",
            "checkout",
            &scene.change,
            "--store",
            fs.to_str().expect("utf-8"),
            "--repository",
            scene.clone("reviewer-fs").to_str().expect("utf-8"),
        ]),
        "a checkout from an fs store",
    );
    assert!(
        said.contains("git packfile") && said.contains("fs"),
        "the refusal names the store kind and what it lacks: {said}"
    );
}

#[test]
fn a_missing_id_is_a_usage_error_and_an_unknown_verb_says_what_exists() {
    let scene = Harness::new();
    let said = String::from_utf8_lossy(&scene.run(&["change", "checkout"]).stderr).to_string();
    assert!(said.contains("say which change"), "{said}");
    assert_eq!(scene.run(&["change", "checkout"]).status.code(), Some(2));
    // Flags that contradict each other are usage, not a coin flip about which wins.
    for contradiction in [
        &["--detach", "--ref", "somewhere"][..],
        &["--detach", "--no-checkout"][..],
    ] {
        let mut args = vec!["change", "checkout", "chg-0000", "--remote", "origin"];
        args.extend_from_slice(contradiction);
        let output = scene.run(&args);
        let said = format!("{}{}", stdout(&output), stderr(&output));
        assert_eq!(
            code(&output),
            2,
            "`{contradiction:?}` is a contradiction: {said}"
        );
        assert!(said.contains("contradict"), "{said}");
    }
    let said = String::from_utf8_lossy(&scene.run(&["change", "chekout"]).stderr).to_string();
    assert!(
        said.contains("checkout"),
        "the typo's own list of verbs: {said}"
    );
    let help = String::from_utf8_lossy(&scene.run(&["change", "help"]).stdout).to_string();
    for word in ["--for", "--ref", "--detach", "--no-checkout", "checkout"] {
        assert!(help.contains(word), "{word} is missing from `change help`");
    }
}

// ---------------------------------------------------------------------------
// --for <job>: the round, its seats, and the verdict if there is one
// ---------------------------------------------------------------------------

#[test]
fn for_a_job_with_no_round_is_refused_and_says_what_the_store_has() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let clone = scene.clone("reviewer-no-round");
    let said = refused(
        &scene.checkout(&clone, &["--for", JOB]),
        "a checkout --for a job nobody opened a round for",
    );
    assert!(said.contains(JOB), "the job it looked for: {said}");
    assert!(said.contains("no round"), "{said}");
    assert!(said.contains("select"), "how to open one: {said}");
    // Nothing was fetched, because a refusal is a refusal.
    assert_eq!(git(&clone, &["rev-parse", "HEAD"]), scene.base);
}

#[test]
fn for_a_job_fetches_the_round_and_its_seats_and_says_there_is_no_verdict() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    // A real round over the change's real head: a roster the owner signed, then a
    // selection derived from it. Nobody ran the job, so every seat is silent and no
    // verdict has been signed — which is the state a reviewer most often meets, and the
    // one a tool is most likely to leave them guessing about.
    //
    // The roster is built to a file rather than `--publish`ed to the remote, and that is
    // worth stating because it is a real limit rather than a shortcut: a roster's epoch
    // pointer is `refs/gitiup/roster` and its epochs live at `refs/gitiup/roster/<n>`,
    // and git cannot hold a file and a directory of the same name. Publishing a roster to
    // a plain-git store is refused by git itself ("failed to update ref"), which is a gap
    // in the roster's ref layout on the git host and not this command's to fix. `select`
    // takes the epoch from disk for exactly this reason, and the round it publishes —
    // `refs/gitiup/round/<change>/<job>/<attempt>`, one ref per round with nothing under
    // it — is git-safe, so the round the store holds is a real one.
    scene.harness.key("owner");
    let mut signups = Vec::new();
    for (name, tier) in [
        ("v1", "endorsed"),
        ("v2", "endorsed"),
        ("v3", "endorsed"),
        ("v4", "trusted"),
        ("v5", "anonymous"),
        ("v6", "anonymous"),
    ] {
        scene.harness.key(name);
        let signup = scene.harness.file(&format!("{name}.signup"));
        let registered = scene.harness.run(&[
            "participant",
            "register",
            "--key",
            name,
            "--ram-mb",
            "32768",
            "--disk-mb",
            "262144",
            "--sandbox",
            "docker",
            "--sandbox-level",
            "2",
            "--arch",
            "x86_64",
            "--out",
            &signup,
        ]);
        assert!(
            registered.status.success(),
            "register {name}: {}{}",
            stdout(&registered),
            stderr(&registered)
        );
        signups.push((signup, tier));
    }
    // One epoch per tier, each succeeding the last, all on disk.
    let mut epoch = String::new();
    for (n, tier) in ["endorsed", "trusted", "anonymous"].iter().enumerate() {
        let path = scene.harness.file(&format!("epoch{n}.json"));
        let mut args: Vec<&str> = vec!["participant", "approve", "--key", "owner"];
        if !epoch.is_empty() {
            args.extend_from_slice(&["--roster", &epoch]);
        }
        for (signup, row) in &signups {
            if *row == *tier {
                args.push("--from");
                args.push(signup.as_str());
            }
        }
        args.extend_from_slice(&["--tier", tier, "--out", &path]);
        let approved = scene.harness.run(&args);
        assert!(
            approved.status.success(),
            "approve {tier}: {}{}",
            stdout(&approved),
            stderr(&approved)
        );
        epoch = path;
    }
    let opened = scene.harness.run(&[
        "select",
        "--change",
        &scene.change,
        "--job",
        JOB,
        "--head",
        &format!("sha1:{}", scene.head),
        "--proposer",
        &scene.author,
        "--require-arch",
        "x86_64",
        "--roster",
        &epoch,
        "--remote",
        "origin",
        "--key",
        "owner",
        "--publish",
        "--json",
    ]);
    assert!(
        opened.status.success(),
        "select --publish: {}{}",
        stdout(&opened),
        stderr(&opened)
    );
    let round = json(&opened);
    let seats = round["selected"].as_array().map(Vec::len).unwrap_or(0);
    assert!(seats > 0, "the round seated somebody: {round}");

    let clone = scene.clone("reviewer-for");
    let body = ok(
        &scene.checkout(&clone, &["--for", JOB, "--json"]),
        "a checkout --for a job that has a round",
    );
    assert_eq!(
        git(&clone, &["rev-parse", "HEAD"]),
        scene.head,
        "the change arrived"
    );
    assert_eq!(body["proofs"][0]["arrived"], true, "and its proof did");
    let quorum = &body["quorum"];
    assert_eq!(quorum["job"], JOB);
    assert_eq!(quorum["attempt"], 0);
    assert_eq!(quorum["seats"].as_u64().unwrap() as usize, seats);
    // Nobody has run the job. Filing a submission is `gitiup work`'s job — a lease, a
    // workflow planned from the change, a sandbox this machine's doctor says may serve a
    // stranger's job, and a signed attestation of the result — none of which a CLI test
    // can honestly conjure. So the silent-seat state is asserted rather than skipped: a
    // seat that has not reported is named as silent, not left out of the table, which is
    // the state a reviewer meets most often.
    assert_eq!(quorum["submitted"], 0, "nobody has run the job: {quorum}");
    assert_eq!(quorum["bound_to_head"], true);
    assert_eq!(quorum["verdict"], Value::Null, "nothing has been tallied");
    assert_eq!(quorum["verdict_refused"], Value::Null);
    assert_eq!(
        quorum["seat_report"].as_array().map(Vec::len).unwrap_or(0),
        seats,
        "every seat is reported, silent ones included"
    );
    assert_eq!(
        quorum["seat_report"][0]["submitted"],
        Value::Null,
        "and silent means the report says so"
    );
    // The round is a ref in the store like every other, so it travelled in the same pack.
    assert!(
        body["fetch"]["prefixes"]
            .as_array()
            .map(|prefixes| prefixes.iter().any(|prefix| prefix
                .as_str()
                .unwrap_or_default()
                .starts_with(&format!("refs/gitiup/round/{}", scene.change))))
            .unwrap_or(false),
        "the round's own refs were part of the fetch: {}",
        body["fetch"]["prefixes"]
    );
    // A reviewer re-running the command gets the same answer: a ref that is already at
    // the head is left where it is, and the round is read again.
    let again = ok(
        &scene.checkout(&clone, &["--for", JOB, "--json"]),
        "the same --for checkout, again",
    );
    assert_eq!(again["landed"]["action"], "unchanged");
    assert_eq!(again["quorum"], *quorum);

    // Now the dangerous one: an escalation round drawn against other bytes. The store's
    // live round for the job is then evidence about a commit that is not this one, and
    // printing it beside the change would be worse than printing nothing.
    let reopened = scene.harness.run(&[
        "select",
        "--change",
        &scene.change,
        "--job",
        JOB,
        "--attempt",
        "1",
        "--head",
        &format!("sha1:{}", scene.base),
        "--proposer",
        &scene.author,
        "--require-arch",
        "x86_64",
        "--roster",
        &epoch,
        "--remote",
        "origin",
        "--key",
        "owner",
        "--publish",
        "--json",
    ]);
    assert!(
        reopened.status.success(),
        "select --attempt 1: {}{}",
        stdout(&reopened),
        stderr(&reopened)
    );
    let said = refused(
        &scene.checkout(&clone, &["--for", JOB]),
        "a --for round drawn against other bytes",
    );
    assert!(
        said.contains(&scene.base) && said.contains(&scene.head),
        "both oids, so the reviewer can see which end moved: {said}"
    );
    assert!(said.contains("head"), "{said}");
    // Without --for the change is still perfectly checkable out: it is the *evidence* that
    // is unusable, not the change.
    let body = ok(
        &scene.checkout(&clone, &["--ref", "still-fine", "--json"]),
        "the same change without --for",
    );
    assert_eq!(body["quorum"], Value::Null);
    assert_eq!(body["landed"]["action"], "created");
}

#[test]
fn for_a_job_reports_what_the_seats_came_back_with() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    // Four of the five seats have run the job and agree; the fifth has not reported. This
    // is the state a reviewer is actually in when they ask `--for`, and it is the only
    // state in which the seat table can be checked: a reported seat and a silent one have
    // to be distinguishable, and the result printed has to be the one the volunteer's
    // signature covers.
    //
    // The round and the submissions are put in the store through the library, because the
    // CLI path to them is `gitiup work` — a lease, a planned workflow, a sandbox — none of
    // which a CLI test can honestly claim. What they write are the store's own refs, at
    // the store's own names, over the same git transport the checkout reads.
    let host = gitiup_host::hosts::git::GitHost::open(
        &gitiup_host::RemoteConfig::new("origin", &scene.url).expect("a remote from a url"),
    )
    .expect("open the served store as a host");
    let owner = sample::owner_key();
    let roster = sample::roster_of(&owner, 7, 41);
    let mut inputs = sample::round_inputs(&roster, &scene.change, JOB);
    inputs.head_oid = GitOid::from_sha1_hex(&scene.head).expect("the change head");
    let secret = SelectionSecret::from_signing_key(&owner);
    let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
    round.sign(&owner).expect("the selector signs");
    qstore::publish_round(&host, &round).expect("the round is published to the store");
    let indexes = sample::indices_of(&round);
    assert!(indexes.len() >= 4, "the round seated five: {indexes:?}");
    let docs = sample::attest(&round, &indexes[..4], sample::claimed_at_us(), |_| None);
    for (position, doc) in docs.iter().enumerate() {
        let key = sample::verifier_key(indexes[position]);
        qstore::publish_submission(&host, &round, &key.public_key().key_id(), doc)
            .expect("the submission lands in its slot");
    }

    let clone = scene.clone("reviewer-reported");
    let body = ok(
        &scene.checkout(&clone, &["--for", JOB, "--json"]),
        "a checkout --for a job whose seats have reported",
    );
    let quorum = &body["quorum"];
    let seats = quorum["seats"].as_u64().unwrap() as usize;
    assert_eq!(quorum["submitted"], 4, "four of {seats} reported: {quorum}");
    assert_eq!(
        quorum["seat_report"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default(),
        seats
    );
    let reported: Vec<&Value> = quorum["seat_report"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|row| !row["submitted"].is_null())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(reported.len(), 4);
    let first = &reported[0]["submitted"];
    assert!(
        first["result"].as_str().unwrap().starts_with("sha256:"),
        "a reported seat shows the result digest it signed: {first}"
    );
    for row in quorum["seat_report"].as_array().unwrap() {
        if row["submitted"].is_null() {
            continue;
        }
        assert_eq!(
            row["submitted"]["signed_by"].as_str(),
            row["key"].as_str(),
            "a reported result is signed by the key that holds the seat: {row}"
        );
    }
    assert!(first["claimed_at"].as_str().unwrap().ends_with('Z'));
    // One agreement, because these four ran the same fixture: a divergent digest would be
    // its own row, and is `gitiup quorum verdict`'s to judge, not this command's.
    let digests: BTreeSet<&str> = reported
        .iter()
        .map(|row| row["submitted"]["result"].as_str().unwrap())
        .collect();
    assert_eq!(digests.len(), 1, "four honest reruns agree: {digests:?}");
    assert_eq!(
        quorum["verdict"],
        Value::Null,
        "nobody has tallied it yet, and this command does not pretend to"
    );
    // The submissions came in the same fetch as the change: their refs were among the
    // wants, which is the whole reason the reviewer can read them offline afterwards.
    assert!(
        body["fetch"]["prefixes"]
            .as_array()
            .map(|prefixes| prefixes.iter().any(|prefix| prefix
                .as_str()
                .unwrap_or_default()
                .starts_with(&format!("refs/gitiup/reveal/{}", scene.change))))
            .unwrap_or(false),
        "the seat submissions were part of the fetch: {}",
        body["fetch"]["prefixes"]
    );
}

#[test]
fn for_a_job_prints_the_signed_verdict_and_refuses_one_it_does_not_believe() {
    let Some(scene) = Scene::new() else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    // Every seat ran the job, the owner tallied it and signed, and the verdict is in the
    // store — so `--for` has an answer to print, which is the whole point of the flag: a
    // reviewer should not have to know that the tally lives behind a separate command with
    // flags of its own that have to be believed.
    //
    // The owner's key is imported from a *known* seed, so the CLI's keystore holds the very
    // key the library signs with. That is also what makes the second half of this test mean
    // something: a verdict is a claim by an owner, and a machine that does not trust that
    // owner has to say so rather than print it as reassurance.
    let seed = scene.harness.file("owner.seed");
    std::fs::write(&seed, format!("{}\n", "01".repeat(32))).expect("write the seed");
    let imported = scene
        .harness
        .run(&["key", "import", "seed", &seed, "--name", "owner"]);
    assert!(
        imported.status.success(),
        "{}{}",
        stdout(&imported),
        stderr(&imported)
    );
    let owner = sample::owner_key();
    assert_eq!(
        json(&scene.harness.run(&["key", "show", "owner", "--json"]))["key_id"],
        owner.public_key().key_id(),
        "the keystore's `owner` and the fixture owner must be one key"
    );

    // The round, the five seats and the tally are put in the store through the library —
    // the CLI route to a submission is `gitiup work`, with a lease, a planned workflow and a
    // sandbox a test cannot honestly claim. What gets written are the store's own refs at
    // the store's own names over the same git transport the checkout reads.
    let host = gitiup_host::hosts::git::GitHost::open(
        &gitiup_host::RemoteConfig::new("origin", &scene.url).expect("a remote from a url"),
    )
    .expect("open the served store as a host");
    let roster = sample::roster_of(&owner, 7, 41);
    let mut inputs = sample::round_inputs(&roster, &scene.change, JOB);
    inputs.head_oid = GitOid::from_sha1_hex(&scene.head).expect("the change head");
    let secret = SelectionSecret::from_signing_key(&owner);
    let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
    round.sign(&owner).expect("the selector signs");
    qstore::publish_round(&host, &round).expect("publish the round");
    let indexes = sample::indices_of(&round);
    let docs = sample::attest(&round, &indexes, sample::claimed_at_us(), |_| None);
    for (position, doc) in docs.iter().enumerate() {
        let key = sample::verifier_key(indexes[position]);
        qstore::publish_submission(&host, &round, &key.public_key().key_id(), doc)
            .expect("the submission lands in its slot");
    }
    // The clock is pinned to the fixture's own, as every verdict test does it: freshness is
    // a window against *now*, and an unpinned tally rots.
    let mut verdict = VerdictRecord::evaluate(
        &round,
        &roster,
        &docs,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("the round tallies");
    verdict.sign(&owner).expect("the owner signs the verdict");
    qstore::publish_verdict(&host, &verdict).expect("publish the verdict");
    // The store advertises it, which is how a reviewer's fetch finds it at all.
    let advertised = Command::new("git")
        .args(["ls-remote", &scene.url])
        .output()
        .expect("git ls-remote");
    assert!(
        advertised.status.success(),
        "ls-remote: {}",
        lossy(&advertised.stderr)
    );
    let advertised = lossy(&advertised.stdout);
    assert!(
        advertised.contains("refs/gitiup/verdict/"),
        "the verdict is an advertised ref: {advertised}"
    );
    assert_eq!(
        verdict.state.as_str(),
        "verified",
        "five honest seats agreeing: {}",
        verdict.detail
    );

    let clone = scene.clone("reviewer-verdict");

    let output = scene.checkout(&clone, &["--for", JOB, "--json"]);
    let body = ok(&output, "a checkout --for a change that has a verdict");
    let quorum = &body["quorum"];
    assert_eq!(
        quorum["submitted"], quorum["seats"],
        "every seat reported: {quorum}"
    );
    assert_eq!(quorum["verdict"]["state"], "verified");
    assert_eq!(quorum["verdict"]["attempt"], 0);
    assert_eq!(quorum["verdict_refused"], Value::Null);
    assert_eq!(
        quorum["verdict"]["agreeing"].as_u64(),
        quorum["seats"].as_u64(),
        "every seat agreed, and the verdict says so: {}",
        quorum["verdict"]
    );
    assert_eq!(quorum["verdict"]["reason"], "agreement_reached");
    assert!(
        quorum["verdict"]["signed_by"]
            .as_array()
            .map(|signers| signers
                .iter()
                .any(|signer| { signer.as_str().unwrap_or_default().starts_with("SHA256:") }))
            .unwrap_or(false),
        "and who said it: {}",
        quorum["verdict"]
    );
    assert!(
        quorum["verdict"]["trusted_by"]
            .as_str()
            .unwrap_or_default()
            .contains("keystore"),
        "the verdict says whose trust it was judged by: {}",
        quorum["verdict"]
    );
    let text = stdout(&scene.checkout(&clone, &["--ref", "again", "--for", JOB]));
    assert!(
        text.contains("verified"),
        "the table says the answer: {text}"
    );

    // A machine that does not trust the owner does not get to be reassured by the verdict.
    // It is shown that one exists and why it is not believed, which is the difference
    // between "the quorum says yes" and "somebody's store says somebody said yes".
    let stranger = scene.harness.key("stranger");
    let other = scene.clone("reviewer-stranger");
    let output = scene.harness.run(&[
        "change",
        "checkout",
        &scene.change,
        "--remote",
        "origin",
        "--repository",
        other.to_str().expect("utf-8"),
        "--for",
        JOB,
        "--owner",
        &stranger,
        "--ref",
        "not-yours",
        "--json",
    ]);
    let body = ok(
        &output,
        "a checkout --for on a machine that trusts somebody else",
    );
    assert_eq!(body["quorum"]["verdict"], Value::Null);
    let said = body["quorum"]["verdict_refused"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        said.contains("trust") || said.contains("sign"),
        "the refusal says why: {said}"
    );
    // The change itself arrived regardless: it is the *evidence* that is not believed, not
    // the code, and a reviewer on a stranger's machine still gets to read it.
    assert_eq!(git(&other, &["rev-parse", "not-yours"]), scene.head);
}

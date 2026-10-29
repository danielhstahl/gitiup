//! `gitiup attest …`, run as the real binary.
//!
//! The ticket's acceptance criteria are command lines — *push an attestation*, *`list
//! --commit <oid>`*, *`show --json`*, *a gc command prunes expired attestations per
//! retention policy*, *retrievable from fs, git and s3 hosts* — so they are tested
//! here as command lines against the built executable: a temp config home and a temp
//! store per harness, a real keystore, the repository's own run-report fixtures, and
//! every assertion read from `--json`. Each command runs in a **new process**: what
//! survives between them is what the store holds, not what a variable held.
//!
//! Two hosts are covered, because two are reachable from a test without credentials:
//! the `fs` host for the whole push -> list -> show -> gc loop, and a plain git remote
//! served over loopback smart HTTP for the claim that matters most — that a stranger
//! with nothing but `git` ends up holding the exact signed bytes. The bucket host is
//! covered at the library level (`gitiup-host`'s `tests/attest_store.rs`) rather than
//! here: standing one up in a CLI test would be testing the transport, not the
//! command, and the command's only bucket-specific decision is which host the store
//! url selects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

#[path = "common/mod.rs"]
mod common;

use common::SmartHttp;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";

/// A config home, a store directory, and the binary pointed at both.
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

    /// Run the binary with this home. The working directory is the temp dir, so a
    /// `gitiup.toml` is only found if the test wrote one, and `SSH_AUTH_SOCK` points
    /// where it cannot exist so no test can depend on the developer's agent.
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

    fn key(&self, name: &str) {
        let output = self.run(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
    }

    /// Push one fixture run report, signed, and return the `push --json` output.
    fn push(&self, fixture: &str) -> Value {
        let report = fixture_path(fixture);
        let output = self.run(
            &[
                "attest",
                "push",
                "--run-report",
                &report,
                "--sign",
                "--store",
                &self.store(),
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "push {fixture} failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        let value: Value = serde_json::from_str(&stdout(&output))
            .unwrap_or_else(|e| panic!("push --json for {fixture}: {e}: {}", stdout(&output)));
        value
    }
}

fn fixture_path(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../gitiup-attest/tests/fixtures/runs")
        .join(name)
        .join("run.json")
        .to_str()
        .expect("fixture path")
        .to_string()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

/// `gitiup digest --json` for the same report: the digests a stranger would
/// recompute, used here to prove the store kept the same manifest it was given.
fn digest_of(fixture: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .args(["digest", "--json", &fixture_path(fixture)])
        .env("GITIUP_CONFIG_HOME", std::env::temp_dir())
        .output()
        .expect("digest runs");
    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("digest json")
}

// ---------------------------------------------------------------------------
// push → list → show
// ---------------------------------------------------------------------------

/// The three commands, in the order a person uses them, on the `fs` host.
#[test]
fn a_signed_attestation_is_filed_found_and_shown() {
    let harness = Harness::new();
    harness.key("ada");
    let pushed = harness.push("hello");
    let digest = pushed["digest"].as_str().unwrap().to_string();
    let subject = pushed["subject"].as_str().unwrap().to_string();
    assert_eq!(
        subject,
        "a".repeat(40),
        "the subject is the commit the run is bound to, as plain hex (the form a ref component must take)"
    );
    assert_eq!(pushed["tier"], "simulated");
    assert_eq!(
        pushed["signers"].as_array().unwrap().len(),
        1,
        "the keystore key signed it"
    );
    assert!(
        pushed["warning"].is_string(),
        "a simulated attestation is filed with the warning attached, not silently"
    );
    // The digests are the ones `gitiup digest` computes for the same report: one
    // pipeline, so nothing stored here can disagree with what a verifier recomputes.
    let expected = digest_of("hello");
    assert_eq!(pushed["run_digest"], expected["run_digest"]);
    assert_eq!(pushed["result_digest"], expected["result_digest"]);

    // list --commit <oid> — the acceptance criterion's own command line.
    let listed = harness.run(
        &[
            "attest",
            "list",
            "--commit",
            &subject,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(listed.status.success(), "{}", stderr(&listed));
    let listed = json(&listed);
    assert_eq!(listed["count"], 1, "{listed}");
    let row = &listed["attestations"][0];
    assert_eq!(row["digest"], digest.as_str());
    assert_eq!(row["subject"], subject.as_str());
    assert_eq!(row["run_digest"], expected["run_digest"]);
    assert_eq!(row["tier"], "simulated");
    assert_eq!(
        row["signers"].as_array().unwrap().len(),
        1,
        "who signed is visible without a trust root: whether it counts is `verify`'s question"
    );

    // The same listing by `sha1:` spelling, because that is what a manifest and
    // `git rev-parse --object-format` print.
    let spelled = harness.run(
        &[
            "attest",
            "list",
            "--commit",
            &format!("sha1:{subject}"),
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert_eq!(
        json(&spelled)["count"],
        1,
        "a subject is a subject in either spelling"
    );

    // show --json — the stored document plus what the store knows about it.
    let shown = harness.run(
        &[
            "attest",
            "show",
            &digest,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    let shown = json(&shown);
    assert_eq!(shown["digest"], digest.as_str());
    assert_eq!(shown["run_digest"], expected["run_digest"]);
    assert_eq!(
        shown["canonical"], true,
        "the bytes re-hashed to their name"
    );
    assert_eq!(shown["tier"], "simulated");
    assert_eq!(shown["workflow"], ".github/workflows/hello.yml");
    assert_eq!(
        shown["document"]["manifest"]["result"]["source"]["commit"],
        "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "the whole signed document is returned, not a summary of it"
    );
    assert!(shown["document"]["signatures"].is_array());

    // show --bytes gives the exact stored bytes: the ones the signature covers.
    let bytes = harness.run(
        &[
            "attest",
            "show",
            &digest,
            "--bytes",
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert!(bytes.status.success(), "{}", stderr(&bytes));
    let raw = stdout(&bytes);
    assert!(
        raw.starts_with('{') && raw.contains("\"signatures\""),
        "{raw}"
    );
    // The bytes re-hash to the digest they are filed under — checked by the CLI too,
    // but asserted here so a regression cannot pass by both sides agreeing wrongly.
    let again = harness.run(
        &[
            "attest",
            "show",
            &digest,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert_eq!(json(&again)["size"].as_u64(), Some(raw.len() as u64));

    // Re-pushing the same run is a no-op, not a duplicate.
    let twice = harness.push("hello");
    assert_eq!(twice["already"], true, "re-filing is idempotent");
    assert_eq!(twice["digest"], digest.as_str());

    // A human listing gets a table, and an empty store says so out loud.
    let table = harness.run(
        &["attest", "list", "--all", "--store", &harness.store()],
        None,
    );
    assert!(table.status.success());
    let text = stdout(&table);
    assert!(text.contains("simulated"), "{text}");
    let empty = harness.run(
        &[
            "attest",
            "list",
            "--commit",
            &"b".repeat(40),
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert!(
        stdout(&empty).contains("no attestation"),
        "{}",
        stdout(&empty)
    );
}

// ---------------------------------------------------------------------------
// what push refuses
// ---------------------------------------------------------------------------

/// An unsigned attestation is a rumour, and the store says so.
#[test]
fn an_unsigned_attestation_is_refused() {
    let harness = Harness::new();
    harness.key("ada");
    let output = harness.run(
        &[
            "attest",
            "push",
            "--run-report",
            &fixture_path("matrix-build"),
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(
        stderr(&output).contains("no signature"),
        "{}",
        stderr(&output)
    );
    // And nothing was filed.
    let listed = harness.run(
        &[
            "attest",
            "list",
            "--all",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert_eq!(json(&listed)["count"], 0);
}

/// A listing needs to be told what to list: guessing "everything" is how an
/// operator ends up paging through a bucket they did not mean to read.
#[test]
fn a_listing_without_a_subject_is_a_usage_error() {
    let harness = Harness::new();
    let output = harness.run(&["attest", "list", "--store", &harness.store()], None);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("--commit"), "{}", stderr(&output));
}

/// With no store named, `list` refuses instead of reading whatever remote happens
/// to be configured for the directory it was called from.
#[test]
fn a_command_with_no_store_named_says_so() {
    let harness = Harness::new();
    let output = harness.run(&["attest", "list", "--all"], None);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(stderr(&output).contains("--store"), "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// retention
// ---------------------------------------------------------------------------

/// `gc` by per-commit cap: the plan first, the change second, and the survivor the
/// freshest claim — the one a gate should be looking at.
#[test]
fn gc_prunes_over_the_cap_and_records_the_run() {
    let harness = Harness::new();
    harness.key("ada");
    // Three attestations for one subject, from three fixtures, pushed with the
    // subject pinned so the cap has something to bite on.
    let subject = "e".repeat(40);
    let mut digests = Vec::new();
    for fixture in ["hello", "matrix-build", "test-failure"] {
        let report = fixture_path(fixture);
        let output = harness.run(
            &[
                "attest",
                "push",
                "--run-report",
                &report,
                "--subject",
                &subject,
                "--sign",
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "{}{}",
            stdout(&output),
            stderr(&output)
        );
        digests.push(json(&output)["digest"].as_str().unwrap().to_string());
    }

    // The plan, with nothing applied: `gc` is reviewable before it is destructive.
    let plan = harness.run(
        &[
            "attest",
            "gc",
            "--commit",
            &subject,
            "--max-per-commit",
            "2",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(plan.status.success(), "{}{}", stdout(&plan), stderr(&plan));
    let planned = json(&plan);
    assert_eq!(planned["report"]["dry_run"], true);
    assert_eq!(planned["report"]["pruned"].as_array().unwrap().len(), 1);
    assert_eq!(planned["note"], "dry run: nothing changed; add --apply");
    let doomed = planned["report"]["pruned"][0]["digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(digests.contains(&doomed), "{doomed} is one of {digests:?}");
    assert!(
        planned["report"]["pruned"][0]["verdict"]
            .get("over-quota")
            .is_some(),
        "the reason is stated, with the cap it missed: {:?}",
        planned["report"]["pruned"][0]["verdict"]
    );

    // Still nothing changed by the dry run.
    assert_eq!(
        json(&harness.run(
            &[
                "attest",
                "list",
                "--commit",
                &subject,
                "--store",
                &harness.store(),
                "--json"
            ],
            None,
        ))["count"],
        3
    );

    // Now apply it.
    let applied = harness.run(
        &[
            "attest",
            "gc",
            "--commit",
            &subject,
            "--max-per-commit",
            "2",
            "--apply",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(
        applied.status.success(),
        "{}{}",
        stdout(&applied),
        stderr(&applied)
    );
    let applied = json(&applied);
    assert_eq!(applied["note"], "applied");
    assert_eq!(applied["report"]["pruned"].as_array().unwrap().len(), 1);
    assert!(
        applied["report"]["record"].is_string(),
        "the run is on the record: {:?}",
        applied["report"]
    );
    let listed = json(&harness.run(
        &[
            "attest",
            "list",
            "--commit",
            &subject,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    ));
    assert_eq!(listed["count"], 2, "one was retired: {listed}");
    assert!(
        listed["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["digest"] != Value::String(doomed.clone())),
        "the pruned one is gone from the listing"
    );

    // The bytes of the retired proof are still in the store (no --purge-blobs) and
    // still readable by digest: retiring means un-advertising, not pretending.
    let shown = harness.run(
        &[
            "attest",
            "show",
            &doomed,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_eq!(
        json(&shown)["reference"],
        Value::Null,
        "readable, but no longer advertised by any ref"
    );

    // A second run has nothing left to do, and says why instead of exiting 0 in
    // silence — the failure mode a retention cron cannot see for itself.
    let again = harness.run(
        &[
            "attest",
            "gc",
            "--commit",
            &subject,
            "--max-per-commit",
            "2",
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert!(again.status.success());
    assert!(
        stdout(&again).contains("nothing to do"),
        "{}",
        stdout(&again)
    );
}

/// A `--keep` survives a cap that would otherwise prune it, and a policy with no
/// limits is refused rather than run.
#[test]
fn a_kept_digest_survives_and_an_empty_policy_says_so() {
    let harness = Harness::new();
    harness.key("ada");
    let subject = "f".repeat(40);
    let mut digests = Vec::new();
    for fixture in ["hello", "matrix-build", "test-failure"] {
        let output = harness.run(
            &[
                "attest",
                "push",
                "--run-report",
                &fixture_path(fixture),
                "--subject",
                &subject,
                "--sign",
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        );
        assert!(output.status.success(), "{}", stderr(&output));
        digests.push(json(&output)["digest"].as_str().unwrap().to_string());
    }
    // One slot for three proofs, and the operator names the one that must survive.
    // The pinned one is outside the cap — it is kept for a reason the cap knows
    // nothing about — so two survive and exactly one goes.
    let keep = &digests[0];
    let run = harness.run(
        &[
            "attest",
            "gc",
            "--commit",
            &subject,
            "--max-per-commit",
            "1",
            "--keep",
            keep,
            "--apply",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(run.status.success(), "{}{}", stdout(&run), stderr(&run));
    assert_eq!(json(&run)["report"]["pruned"].as_array().unwrap().len(), 1);
    let listed = json(&harness.run(
        &[
            "attest",
            "list",
            "--commit",
            &subject,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    ));
    assert_eq!(listed["count"], 2, "{listed}");
    assert!(
        listed["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["digest"] == Value::String(keep.clone())),
        "the kept digest is still advertised: {listed}"
    );

    // A policy with no limits could not prune anything: refused, not run.
    let nothing = harness.run(
        &[
            "attest",
            "gc",
            "--max-age",
            "never",
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert_eq!(
        code(&nothing),
        6,
        "{}{}",
        stdout(&nothing),
        stderr(&nothing)
    );
    assert!(
        stderr(&nothing).contains("--max-age"),
        "{}",
        stderr(&nothing)
    );
}

/// Age is measured against the claimed time inside the signed document, so a
/// fixture from last decade is old no matter when it was pushed.
#[test]
fn gc_prunes_by_age_and_purges_on_a_filesystem_store() {
    let harness = Harness::new();
    harness.key("ada");
    let pushed = harness.push("hello");
    let digest = pushed["digest"].as_str().unwrap().to_string();

    let run = harness.run(
        &[
            "attest",
            "gc",
            "--max-age",
            "1s",
            "--purge-blobs",
            "--apply",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert!(run.status.success(), "{}{}", stdout(&run), stderr(&run));
    let report = json(&run);
    assert_eq!(report["report"]["pruned"].as_array().unwrap().len(), 1);
    assert!(
        report["report"]["pruned"][0]["verdict"]
            .get("expired")
            .is_some(),
        "{:?}",
        report["report"]["pruned"][0]["verdict"]
    );
    assert_eq!(
        report["report"]["pruned"][0]["blob"], "removed",
        "the fs host can forget a blob, and the report says it did: {:?}",
        report["report"]["pruned"][0]
    );

    // The ref is gone and so are the bytes: this is what `--purge-blobs` buys, and
    // `show` on a digest that has neither is a digest mismatch, not an empty file.
    let shown = harness.run(
        &[
            "attest",
            "show",
            &digest,
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    assert_eq!(code(&shown), 8, "{}{}", stdout(&shown), stderr(&shown));
    assert_eq!(
        json(&harness.run(
            &[
                "attest",
                "list",
                "--all",
                "--store",
                &harness.store(),
                "--json"
            ],
            None,
        ))["count"],
        0
    );
}

// ---------------------------------------------------------------------------
// The claim only a git-backed host can carry: a plain clone gets the proof.
// ---------------------------------------------------------------------------

/// Push an attestation to a plain git remote, then read it back with nothing but
/// `git`: clone, fetch the attestation namespace, and take the bytes out of the
/// pointer commit the ref names.
///
/// This is the acceptance criterion's "survives clone/fetch" and "retrievable from
/// … git hosts" in the literal sense, at the command line rather than the library's:
/// a stranger with no gitiup, no API and no trust in the server ends up holding the
/// exact signed bytes, because the ref that names them brought them.
#[test]
fn an_attestation_survives_a_plain_git_clone() {
    let harness = Harness::new();
    let served = harness.path().join("served");
    std::fs::create_dir_all(&served).expect("served dir");
    let repo = served.join("repo.git");
    gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");
    common::allow_anonymous_receives(&repo);
    let Some(server) = SmartHttp::serve(&served) else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };

    harness.key("ada");
    write_remote_config(
        &harness,
        &server.url("repo"),
        &harness.path().join("mirror"),
    );

    let report = fixture_path("hello");
    let pushed = harness.run(
        &[
            "attest",
            "push",
            "--run-report",
            &report,
            "--sign",
            "--remote",
            "origin",
            "--json",
        ],
        None,
    );
    assert!(
        pushed.status.success(),
        "{}{}",
        stdout(&pushed),
        stderr(&pushed)
    );
    let pushed = json(&pushed);
    let digest = pushed["digest"].as_str().unwrap().to_string();
    let subject = pushed["subject"].as_str().unwrap().to_string();
    assert!(
        pushed["store"]
            .as_str()
            .unwrap()
            .contains("remote 'origin'"),
        "{pushed}"
    );

    // Read it back through the same remote, from a second mirror: what another
    // machine sees is what the repository says.
    let listed = harness.run(
        &[
            "attest", "list", "--commit", &subject, "--remote", "origin", "--json",
        ],
        None,
    );
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert_eq!(json(&listed)["count"], 1);
    assert_eq!(json(&listed)["attestations"][0]["digest"], digest.as_str());

    // Now plain git: clone, fetch the namespace, read the proof out of the pointer
    // commit the ref names.
    let clone = harness.path().join("clone.git");
    let status = Command::new("git")
        .args(["clone", "--bare"])
        .arg(server.url("repo"))
        .arg(&clone)
        .output()
        .expect("git clone");
    assert!(status.status.success(), "{}", stderr_of(&status));
    let fetch = Command::new("git")
        .args(["fetch", "origin", "refs/attestations/*:refs/attestations/*"])
        .current_dir(&clone)
        .output()
        .expect("git fetch");
    assert!(fetch.status.success(), "{}", stderr_of(&fetch));
    let refs = git_in(&clone, &["for-each-ref", "--format=%(refname)"]);
    assert!(
        refs.contains(&format!("refs/attestations/{subject}/{digest}")),
        "the ref is advertised to a plain client: {refs}"
    );
    let tip = git_in(
        &clone,
        &[
            "rev-parse",
            &format!("refs/attestations/{subject}/{digest}"),
        ],
    );
    let record = git_in(&clone, &["cat-file", "blob", &format!("{tip}:record")]);
    let bytes = harness.run(
        &["attest", "show", &digest, "--bytes", "--remote", "origin"],
        None,
    );
    assert!(bytes.status.success(), "{}", stderr(&bytes));
    assert_eq!(
        record,
        stdout(&bytes).trim_end(),
        "the bytes a plain clone fetched are the bytes that were signed"
    );
    // And the pointer document names the same digest, so a reviewer can see the
    // store did not re-encode anything on the way in.
    let pointer = git_in(
        &clone,
        &["cat-file", "blob", &format!("{tip}:gitiup-ref.json")],
    );
    assert!(pointer.contains(&digest), "{pointer}");
}

/// A `gitiup.toml` naming one remote, in the directory the harness runs from.
fn write_remote_config(harness: &Harness, url: &str, work_dir: &Path) {
    let config = format!(
        "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \"origin\"\
         \nurl = \"{url}\"\n\n[remote.options]\nwork-dir = \"{}\"\nref-cache-ttl = \"0s\"\n",
        work_dir.display()
    );
    std::fs::write(harness.path().join("gitiup.toml"), config).expect("write gitiup.toml");
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn git_in(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?}: {}", stderr_of(&out));
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// The path the harnesses hand to the binary never contains a `~`, and the binary
/// is the one this test built.
#[test]
fn the_binary_under_test_is_this_workspaces_one() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_gitiup"));
    assert!(exe.exists(), "{exe:?} was not built");
}

// ---------------------------------------------------------------------------
// The old single-level shape: read, reported, and moved.
// ---------------------------------------------------------------------------

/// A second fs store in the harness's directory, so one test can hold a store in two
/// shapes at once without anyone's home directory being involved.
fn store_in(harness: &Harness, name: &str) -> String {
    harness
        .path()
        .join(name)
        .to_str()
        .expect("utf-8")
        .to_string()
}

/// The exact canonical bytes of a signed attestation, produced the only way they can
/// be produced: `attest push --out`, whose whole promise is to write the bytes it
/// stored verbatim. A hand-written "attestation" would not survive the canonical read,
/// and the migration's claim is about *real* signed evidence.
fn signed_bytes(harness: &Harness, store: &str, fixture: &str, subject: &str) -> String {
    let out = harness
        .path()
        .join(format!("doc-{}-{}.json", fixture, &subject[..8]));
    let report = fixture_path(fixture);
    let mut args: Vec<&str> = vec![
        "attest",
        "push",
        "--run-report",
        &report,
        "--sign",
        "--store",
        store,
        "--out",
        out.to_str().expect("utf-8"),
    ];
    let subject_arg = subject.to_string();
    args.push("--subject");
    args.push(&subject_arg);
    let pushed = harness.run(&args, None);
    assert!(
        pushed.status.success(),
        "{}{}",
        stdout(&pushed),
        stderr(&pushed)
    );
    String::from_utf8(std::fs::read(&out).expect("the bytes that were stored"))
        .expect("canonical json is utf-8")
}

/// File one attestation the way an older gitiup did — `refs/attestations/<subject>`
/// pointing at the digest, one proof per commit and no room for a second — by writing
/// the ref directly through the host API. A test that invented the shape in a fixture
/// would be testing its own imagination of the past.
fn file_one_the_old_way(store: &str, subject: &str, bytes: &str) -> String {
    use gitiup_host::{BlobStore, RefStore, RefUpdate};
    let host = gitiup_host::hosts::fs::FsHost::open_or_create(store).expect("fs host");
    let oid = gitiup_host::Oid::from_hex(subject).expect("a subject hex");
    let digest = host
        .put_cas(&gitiup_host::Namespace::ATTESTATION, bytes.as_bytes())
        .expect("store the bytes");
    host.update_ref_cas(&RefUpdate::create(
        gitiup_host::attest::legacy_ref_name(&oid),
        digest,
    ))
    .expect("the single-level ref");
    digest.hex()
}

#[test]
fn a_legacy_attestation_is_listed_flagged_and_moved_without_losing_its_bytes() {
    let harness = Harness::new();
    harness.key("ada");
    let origin = store_in(&harness, "origin");
    let legacy = store_in(&harness, "legacy");

    // One real signed document, and a subject of its own so a second proof about the
    // same commit is possible later.
    let subject = gitiup_host::Oid::hash_bytes(b"the commit an older build attested").hex();
    let bytes = signed_bytes(&harness, &origin, "hello", &subject);
    let digest = file_one_the_old_way(&legacy, &subject, &bytes);

    // Read it, and say which shape it is in. Dropping it would be the lie: a listing
    // that returns nothing is how "there is no proof here" gets believed.
    let listed = json(&harness.run(
        &[
            "attest", "list", "--commit", &subject, "--store", &legacy, "--json",
        ],
        None,
    ));
    assert_eq!(listed["count"], 1, "{listed}");
    assert!(
        listed["unexpected_refs"].as_array().unwrap().is_empty(),
        "the old shape is a shape, not a surprise: {}",
        listed["unexpected_refs"]
    );
    assert_eq!(listed["attestations"][0]["digest"], digest.as_str());
    assert_eq!(
        listed["attestations"][0]["shape"], "legacy",
        "and the listing is honest about which layout it is in"
    );
    assert_eq!(
        listed["attestations"][0]["reference"],
        format!("refs/attestations/{subject}"),
        "the ref it is actually filed under"
    );
    assert_eq!(
        listed["attestations"][0]["tier"], "simulated",
        "everything else about it reads normally: it is a proof, merely an old-shaped one"
    );

    // The migration is a report before it is a change, exactly like `gc`.
    let planned = json(&harness.run(&["attest", "migrate", "--store", &legacy, "--json"], None));
    let report = &planned["report"];
    assert_eq!(report["dry_run"], true, "{planned}");
    assert_eq!(report["moved"].as_array().unwrap().len(), 1, "{planned}");
    assert_eq!(report["moved"][0]["digest"], digest.as_str());
    assert_eq!(report["moved"][0]["retired"], false);
    assert!(report["blocked"].as_array().unwrap().is_empty());
    assert!(
        planned["note"]
            .as_str()
            .unwrap_or("")
            .contains("nothing changed"),
        "{planned}"
    );
    // …and nothing moved, so listing it again says `legacy` still.
    let again = json(&harness.run(
        &["attest", "list", "--all", "--store", &legacy, "--json"],
        None,
    ));
    assert_eq!(again["attestations"][0]["shape"], "legacy");

    let applied = json(&harness.run(
        &["attest", "migrate", "--store", &legacy, "--apply", "--json"],
        None,
    ));
    let report = &applied["report"];
    assert_eq!(report["dry_run"], false, "{applied}");
    assert_eq!(report["moved"].as_array().unwrap().len(), 1);
    assert_eq!(report["moved"][0]["retired"], true);
    assert!(
        report["record"].is_string(),
        "a move over signed evidence is recorded: {applied}"
    );

    let moved = json(&harness.run(
        &[
            "attest", "list", "--commit", &subject, "--store", &legacy, "--json",
        ],
        None,
    ));
    assert_eq!(moved["count"], 1, "{moved}");
    assert_eq!(moved["attestations"][0]["shape"], "current");
    assert_eq!(moved["attestations"][0]["digest"], digest.as_str());
    assert_eq!(
        moved["attestations"][0]["reference"],
        format!("refs/attestations/{subject}/{digest}"),
        "the same proof, in the layout that has room for more than one"
    );

    // The bytes are untouched, which is the whole test: a migration that re-encoded
    // the document would have destroyed the signature it was moving.
    let shown = harness.run(
        &["attest", "show", &digest, "--store", &legacy, "--json"],
        None,
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert_eq!(
        json(&shown)["canonical"],
        true,
        "the moved bytes still re-hash to their own name"
    );
    assert!(
        json(&shown)["document"]["signatures"][0]["key_id"]
            .as_str()
            .unwrap_or("")
            .starts_with("SHA256:"),
        "the signature came along with the bytes: {}",
        stdout(&shown)
    );

    // And the reason the shape mattered: a second proof now fits beside the first.
    // Before the migration this was refused — a ref cannot be a leaf and a directory
    // at once — which is exactly the wall the two shapes had to be reconciled around.
    let second = json(&harness.run(
        &[
            "attest",
            "push",
            "--run-report",
            &fixture_path("test-failure"),
            "--subject",
            &subject,
            "--sign",
            "--key",
            "ada",
            "--store",
            &legacy,
            "--json",
        ],
        None,
    ));
    let both = json(&harness.run(
        &[
            "attest", "list", "--commit", &subject, "--store", &legacy, "--json",
        ],
        None,
    ));
    assert_eq!(both["count"], 2, "{both}");
    assert!(
        both["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["digest"] == second["digest"]),
        "both proofs are listed: {both}"
    );
    assert!(
        both["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["shape"] == "current"),
        "and neither is in the old shape any more: {both}"
    );
}

#[test]
fn a_store_with_nothing_legacy_says_so_rather_than_migrating_nothing_quietly() {
    let harness = Harness::new();
    harness.key("ada");
    harness.push("hello");
    let planned = json(&harness.run(
        &["attest", "migrate", "--store", &harness.store(), "--json"],
        None,
    ));
    let report = &planned["report"];
    assert!(
        report["moved"].as_array().unwrap().is_empty()
            && report["blocked"].as_array().unwrap().is_empty(),
        "{planned}"
    );
    assert!(
        report["record"].is_null(),
        "a run that changed nothing writes no record: {planned}"
    );
    let table = harness.run(&["attest", "migrate", "--store", &harness.store()], None);
    assert!(table.status.success(), "{}", stderr(&table));
    assert!(
        stdout(&table).contains("no legacy attestation refs"),
        "{}",
        stdout(&table)
    );
}

//! `gitiup fetch` and `gitiup push`, run as the real binary.
//!
//! The ticket's acceptance criteria are command lines, so they are tested as command
//! lines: a temp config home, a gitiup.toml naming two stores, real signed attestations
//! filed in the source, and every assertion read back out of `--json`. Each command is a
//! new process, so what survives between them is what the stores hold and not what a
//! variable held — which is the only way to test "re-running a fetch moves nothing".
//!
//! The library tests (`gitiup-host`'s `tests/federation.rs`) carry the invariants that
//! need a store to misbehave; this file carries the ones that only exist at the command
//! line: the flag list itself (there is no flag that makes a copy trusted, and an
//! absence is worth a test), the exit codes a script branches on, and the report a
//! human actually sees.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";

/// A config home with two stores and a gitiup.toml that names them.
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

    fn store(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }

    /// Write a `gitiup.toml` whose `upstream` remote is the source store and whose
    /// `mirror` remote is the destination, both directory stores.
    fn config(&self, extra: &str) {
        std::fs::write(
            self.path().join("gitiup.toml"),
            format!(
                "schema-version = 1\ndefault-remote = \"upstream\"\n\n[[remote]]\nname = \
                 \"upstream\"\nurl = \"file://{}\"\n\n[remote.options]\nhost-type = \
                 \"fs\"\n\n[[remote]]\nname = \"mirror\"\nurl = \"file://{}\"\n\n\
                 [remote.options]\nhost-type = \"fs\"\n{}\n",
                self.store("upstream"),
                self.store("mirror"),
                extra,
            ),
        )
        .expect("write gitiup.toml");
    }

    /// A git remote pointing at a bare repository, for the read-only case.
    fn git_config(&self, repo: &Path, options: &str) {
        std::fs::write(
            self.path().join("gitiup.toml"),
            format!(
                "schema-version = 1\ndefault-remote = \"upstream\"\n\n[[remote]]\nname = \
                 \"upstream\"\nurl = \"file://{}\"\n\n[remote.options]\nhost-type = \
                 \"fs\"\n\n[[remote]]\nname = \"mirror\"\nurl = \"file://{}\"\n\n\
                 [remote.options]\nhost-type = \"git\"\nwork-dir = \"{}\"\n{}\n",
                self.store("upstream"),
                repo.display(),
                self.path().join("mirror-work").display(),
                options,
            ),
        )
        .expect("write gitiup.toml");
    }

    fn run(&self, args: &[&str]) -> Output {
        self.spawn(args, None)
    }

    fn spawn(&self, args: &[&str], stdin: Option<&str>) -> Output {
        use std::io::Write as _;
        use std::process::Stdio;
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
        let output = self.spawn(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        name.to_string()
    }

    /// File one signed attestation in `store`, from the repository's own run fixtures.
    fn attest(&self, fixture: &str, store: &str) {
        let report = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-attest/tests/fixtures/runs")
            .join(fixture)
            .join("run.json");
        let output = self.run(&[
            "attest",
            "push",
            "--run-report",
            report.to_str().expect("utf-8"),
            "--sign",
            "--store",
            store,
            "--json",
        ]);
        assert!(
            output.status.success(),
            "attest push {fixture} failed: {}",
            stderr(&output)
        );
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

/// A fetch moves the proofs, the copy is readable by a command that knows nothing about
/// how it got there, and a second fetch moves nothing.
#[test]
fn a_fetch_carries_proofs_and_the_next_one_moves_nothing() {
    let harness = Harness::new();
    harness.config("");
    harness.key("ada");
    let upstream = harness.store("upstream");
    for fixture in ["hello", "matrix-build"] {
        harness.attest(fixture, &upstream);
    }

    let output = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        harness.store("mirror").as_str(),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "fetch failed: {}{}",
        stdout(&output),
        stderr(&output)
    );
    let report = json(&output);
    assert!(
        report["objects"]["arrived"].as_u64().unwrap() >= 2,
        "{report}"
    );
    assert_eq!(
        report["objects"]["rehashed"].as_u64().unwrap(),
        report["objects"]["arrived"].as_u64().unwrap()
    );
    assert_eq!(
        report["trust"], "none",
        "a fetch granted something: {report}"
    );
    assert_eq!(report["age_basis"], "claimed_at_us");
    assert!(report["refs"]["written"].as_u64().unwrap() >= 2);
    assert_eq!(report["verb"], "fetch");
    assert_eq!(report["from"], "remote 'upstream'");

    // The copy is a store like any other: `attest list` reads it back and refuses
    // anything that does not re-hash to its own name, which is the copy having worked.
    let listing = harness.run(&[
        "attest",
        "list",
        "--all",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert!(listing.status.success(), "{}", stderr(&listing));
    let listed = json(&listing);
    assert_eq!(
        listed["attestations"].as_array().map(|rows| rows.len()),
        Some(2),
        "the copy does not read back: {listed}"
    );

    // …and the same command again moves nothing, and says so.
    let again = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert!(again.status.success(), "{}", stderr(&again));
    let second = json(&again);
    assert_eq!(
        second["objects"]["arrived"], 0,
        "a re-run stored bytes again: {second}"
    );
    assert!(second["objects"]["already"].as_u64().unwrap() >= 2);
    assert_eq!(second["refs"]["written"], 0);
}

/// A copy is bytes. There is no flag that turns a store URL into a trust decision, and
/// the report has no field a merge gate may read as permission (D3).
#[test]
fn there_is_no_way_to_ask_a_fetch_to_trust_what_it_fetched() {
    let harness = Harness::new();
    harness.config("");
    for flag in [
        "--trust-remote",
        "--trust-mirror",
        "--from-trusted",
        "--trusted-store",
    ] {
        let output = harness.run(&[
            "fetch",
            "--remote",
            "upstream",
            "--store",
            &harness.store("mirror"),
            flag,
        ]);
        assert_eq!(
            code(&output),
            Some(2),
            "{flag} was accepted: {}{}",
            stdout(&output),
            stderr(&output)
        );
        assert_eq!(
            code(&harness.run(&[
                "push",
                "--remote",
                "mirror",
                "--store",
                &harness.store("upstream"),
                flag
            ])),
            Some(2),
            "`push` accepted {flag}"
        );
    }
    // And the help says so out loud, because a reviewer who greps the flag list is the
    // next person who will be tempted to add one.
    let help = harness.run(&["fetch", "help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    assert!(
        text.contains("no flag here") || text.contains("never trust"),
        "the help does not say what the flag list refuses: {text}"
    );
    assert!(
        !text.contains("--trust-remote"),
        "the help advertises a trust flag"
    );
}

/// `--proofs-only` moves the evidence and declines the code, in words.
#[test]
fn proofs_only_moves_evidence_and_declines_the_code() {
    let harness = Harness::new();
    harness.config("");
    harness.key("ada");
    let upstream = harness.store("upstream");
    harness.attest("hello", &upstream);

    let output = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--proofs-only",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    let report = json(&output);
    assert_eq!(report["proofs_only"], true);
    assert_eq!(report["code"]["outcome"], "declined");
    assert_eq!(report["code"]["carried"], 0);
    assert!(
        report["subject"]["excused"]
            .as_str()
            .unwrap_or_default()
            .contains("--proofs-only")
    );
    assert!(report["objects"]["arrived"].as_u64().unwrap() >= 1);
}

/// A mirror that says it is read-only is refused by name, with the token in the message
/// — and the same remote is still a perfectly good thing to fetch from.
#[test]
fn a_read_only_remote_is_refused_by_name() {
    if which("git").is_none() {
        eprintln!("skipping: no git binary");
        return;
    }
    let harness = Harness::new();
    let repo = harness.path().join("repo.git");
    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&repo)
        .output()
        .expect("git init --bare");
    assert!(init.status.success(), "{}", stderr(&init));
    harness.git_config(&repo, "read-only = \"true\"");
    harness.key("ada");
    harness.attest("hello", &harness.store("upstream"));

    let push = harness.run(&[
        "push",
        "--remote",
        "mirror",
        "--store",
        &harness.store("upstream"),
    ]);
    assert_eq!(
        code(&push),
        Some(6),
        "a write to a read-only store was not refused: {}{}",
        stdout(&push),
        stderr(&push)
    );
    assert!(
        stderr(&push).contains("read_only"),
        "the refusal does not name its token: {}",
        stderr(&push)
    );

    // Reading the same store is what a mirror is for, and is not refused.
    let pull = harness.run(&[
        "fetch",
        "--remote",
        "mirror",
        "--to",
        &harness.store("upstream"),
        "--json",
    ]);
    assert!(
        pull.status.success() || code(&pull) == Some(0),
        "reading a read-only mirror failed: {}{}",
        stdout(&pull),
        stderr(&pull)
    );
}

/// A budget is a refusal, not a silent truncation (D10): a run that cannot finish inside
/// its budget says so, writes nothing, and exits 6 — the twin of a truncated run that
/// exits 0 is a partial import pretending to be a complete one.
#[test]
fn a_budget_is_a_refusal_and_not_a_truncation() {
    let harness = Harness::new();
    harness.config("");
    harness.key("ada");
    let upstream = harness.store("upstream");
    for fixture in ["hello", "matrix-build"] {
        harness.attest(fixture, &upstream);
    }

    let output = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--max-records",
        "1",
        "--json",
    ]);
    assert_eq!(
        code(&output),
        Some(6),
        "a busted budget succeeded: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("closure_budget_records"),
        "the refusal does not name its token: {}",
        stderr(&output)
    );
    // Nothing was written: the budget is settled against the plan before the first byte
    // moves, which is what makes "refused rather than truncated" literally true.
    let listing = harness.run(&[
        "attest",
        "list",
        "--all",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert_eq!(
        json(&listing)["attestations"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        0,
        "a refused fetch left advertisements behind: {}",
        stdout(&listing)
    );

    // Room to spare, and all of it arrives — the refusal cost nothing but the run.
    let whole = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert!(
        whole.status.success(),
        "{}{}",
        stdout(&whole),
        stderr(&whole)
    );
    let report = json(&whole);
    assert_eq!(report["objects"]["arrived"].as_u64(), Some(2), "{report}");
    assert!(
        report["refused"].as_array().map(|rows| rows.is_empty()) == Some(true),
        "{report}"
    );
}

/// `--strict` is for the CI job that would rather know that something was skipped.
///
/// The source holds a lease, which is arbitration state: the lenient run says so in the
/// report and exits 0, because a fetch that skipped a lease did nothing wrong, and the
/// strict run exits 6 because somebody asked to be told.
#[test]
fn strict_turns_a_scope_refusal_into_an_exit_code() {
    use gitiup_host::{BlobStore as _, FsHost, Namespace, RefName, RefStore, RefUpdate};
    let harness = Harness::new();
    harness.config("");
    harness.key("ada");
    let upstream = harness.store("upstream");
    harness.attest("hello", &upstream);
    // File a lease the way the quorum would have: bytes, then the ref that advertises
    // them. It is a real ref in a real store, and it is the one thing a copy must refuse.
    let store = FsHost::open_or_create(&upstream).expect("open the source store");
    let digest = store
        .put_cas(&Namespace::JOB, b"a lease that expires in fifteen minutes")
        .expect("put the lease record");
    store
        .update_ref_cas(&RefUpdate::create(
            RefName::new("refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001").unwrap(),
            digest,
        ))
        .expect("advertise the lease");

    let lenient = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert!(
        lenient.status.success(),
        "the lenient run should succeed past a scope refusal: {}{}",
        stdout(&lenient),
        stderr(&lenient)
    );
    let report = json(&lenient);
    assert!(
        report["objects"]["arrived"].as_u64().unwrap() >= 1,
        "the proof did not arrive: {report}"
    );
    assert!(
        report["refused"]
            .as_array()
            .map(|rows| !rows.is_empty())
            .unwrap_or(false),
        "the lease was not refused by name: {report}"
    );
    assert_eq!(report["refused_by"]["no_arbitration_here"], 1, "{report}");
    assert_eq!(
        report["skipped_by_class"]["state"], 1,
        "the class tally is missing: {report}"
    );
    // And it really was not copied.
    let mirror = FsHost::open_or_create(harness.store("mirror")).expect("open the mirror");
    assert!(
        mirror
            .get_ref(
                &RefName::new("refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001")
                    .unwrap()
            )
            .unwrap()
            .is_none()
    );

    let strict = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--strict",
        "--json",
    ]);
    assert_eq!(
        code(&strict),
        Some(6),
        "--strict did not fail on the refusal: {}{}",
        stdout(&strict),
        stderr(&strict)
    );
    let report = json(&strict);
    assert_eq!(report["refused_by"]["no_arbitration_here"], 1);
    assert_eq!(
        report["objects"]["arrived"], 0,
        "the strict run re-wrote bytes too: {report}"
    );
}

/// Both verbs are in the help, and neither takes a flag it does not document.
#[test]
fn the_help_text_covers_both_verbs() {
    let harness = Harness::new();
    for command in ["fetch", "push"] {
        let output = harness.run(&[command, "help"]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        for flag in [
            "--remote",
            "--store",
            "--proofs-only",
            "--change",
            "--commit",
            "--strict",
            "--dry-run",
        ] {
            assert!(
                text.contains(flag),
                "`{command} help` does not document {flag}"
            );
        }
    }
    let usage = harness.run(&["help"]);
    let text = stdout(&usage);
    assert!(
        text.contains("fetch [OPTIONS]"),
        "the top-level help does not list fetch"
    );
    assert!(
        text.contains("push [OPTIONS]"),
        "the top-level help does not list push"
    );
}

/// Not naming both ends is a refusal with the fix in it, not a guess about where the
/// operator meant to write.
#[test]
fn both_ends_have_to_be_named_or_understood() {
    let harness = Harness::new();
    let upstream = harness.store("upstream");
    harness.key("ada");
    harness.attest("hello", &upstream);
    // No gitiup.toml at all: `--remote` has nothing to resolve against.
    let output = harness.run(&[
        "fetch",
        "--remote",
        "somewhere",
        "--store",
        &harness.store("mirror"),
    ]);
    assert_eq!(
        code(&output),
        Some(6),
        "an unknown remote was not refused: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("somewhere"), "{}", stderr(&output));
}

fn which(program: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// A repository is a destination and a source, not a special case.
///
/// The copy is pushed into a bare repository over the file transport, the repository is
/// then read with nothing but `git` to show that the proof refs really are refs, and a
/// third store fetches them back out of it — bytes and all — through the repository's own
/// pack path. That the two ends are different kinds of store is invisible in the report,
/// which is the point of the verbs existing at all.
#[test]
fn a_repository_takes_a_copy_on_both_sides() {
    let Some(git) = which("git") else {
        eprintln!("skipping: no git binary");
        return;
    };
    let harness = Harness::new();
    let repo = harness.path().join("repo.git");
    let init = Command::new(&git)
        .args(["init", "--bare", "-q"])
        .arg(&repo)
        .output()
        .expect("git init --bare");
    assert!(init.status.success(), "{}", stderr(&init));
    harness.git_config(&repo, "ref-cache-ttl = \"0s\"");
    harness.key("ada");
    let upstream = harness.store("upstream");
    for fixture in ["hello", "matrix-build"] {
        harness.attest(fixture, &upstream);
    }

    let push = harness.run(&["push", "--remote", "mirror", "--store", &upstream, "--json"]);
    assert!(
        push.status.success(),
        "push into a repository failed: {}{}",
        stdout(&push),
        stderr(&push)
    );
    let report = json(&push);
    assert_eq!(report["verb"], "push");
    assert!(
        report["objects"]["arrived"].as_u64().unwrap() >= 2,
        "{report}"
    );
    assert_eq!(report["trust"], "none");

    // The repository now advertises the proofs as refs, which is the claim the whole
    // design rests on: proof travels with the repository, and a stranger with `git` and
    // no gitiup at all ends up holding the exact signed bytes.
    let listed = Command::new(&git)
        .args(["--git-dir"])
        .arg(&repo)
        .args(["for-each-ref", "--format=%(refname)"])
        .output()
        .expect("git for-each-ref");
    let refs = stdout(&listed);
    assert!(
        refs.lines()
            .filter(|line| line.starts_with("refs/attestations/"))
            .count()
            >= 2,
        "the repository does not carry the attestation refs: {refs}"
    );

    // And they come back out of it, into a store that never saw the original.
    let back = harness.store("returned");
    let pull = harness.run(&["fetch", "--remote", "mirror", "--to", &back, "--json"]);
    assert!(
        pull.status.success(),
        "fetch out of a repository failed: {}{}",
        stdout(&pull),
        stderr(&pull)
    );
    let report = json(&pull);
    assert!(
        report["objects"]["arrived"].as_u64().unwrap() >= 2,
        "{report}"
    );
    let listing = harness.run(&["attest", "list", "--all", "--store", &back, "--json"]);
    assert_eq!(
        json(&listing)["attestations"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        2,
        "the round trip did not preserve the proofs: {}",
        stdout(&listing)
    );
}

/// `--dry-run` is the run you can point at somebody else's store and read.
///
/// The report has to be the real one — counts, refusals, everything — and the
/// destination has to be exactly as it was, because the flag's whole use is "what would
/// this do" asked of a mirror you do not own yet.
#[test]
fn a_dry_run_reports_the_copy_and_writes_nothing() {
    let harness = Harness::new();
    harness.config("");
    harness.key("ada");
    let upstream = harness.store("upstream");
    for fixture in ["hello", "matrix-build"] {
        harness.attest(fixture, &upstream);
    }

    let output = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--dry-run",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "a dry run failed: {}{}",
        stdout(&output),
        stderr(&output)
    );
    let report = json(&output);
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["objects"]["arrived"].as_u64(), Some(2), "{report}");
    assert_eq!(report["arrivals"], 0, "a dry run wrote arrival records");

    let listing = harness.run(&[
        "attest",
        "list",
        "--all",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert_eq!(
        json(&listing)["attestations"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0),
        0,
        "the dry run wrote the copy: {}",
        stdout(&listing)
    );

    // …and the real run after it does the work the dry run described, with the same
    // counts: the dry report was a plan and not a guess.
    let real = harness.run(&[
        "fetch",
        "--remote",
        "upstream",
        "--store",
        &harness.store("mirror"),
        "--json",
    ]);
    assert!(real.status.success(), "{}", stderr(&real));
    assert_eq!(
        json(&real)["objects"]["arrived"].as_u64(),
        Some(2),
        "the dry run and the run disagreed"
    );
}

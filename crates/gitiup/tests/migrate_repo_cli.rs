//! `gitiup migrate repo` against a forge on a socket (giti-g5c.4).
//!
//! The ticket's claim is that one command can leave a forge for a store and be trusted
//! afterwards, so every assertion here is made against a built binary and a store that
//! exists on disk afterwards — not against a mock of the command. The forge is the same
//! mock the change verbs use; the destination is a real bare git repository cloned from a
//! real working repository, because "the ref landed" has to mean something a `git` command
//! can check.
//!
//! The history is left at the door on purpose (`--no-history`): the mock forge is an HTTP
//! API and has no `git upload-pack` behind it, and a test that faked the clone would test
//! nothing about the copy. What that costs is exactly what the ADR says it should cost — a
//! ref whose commit the destination cannot produce is refused (ADR-0005 D8), and a proof
//! whose commit was never read back is reported as unverified rather than counted as a
//! match. Where the destination *can* produce the commit, the ref moves.
//!
//! What is asserted, and why each one is the thing that matters:
//!
//! * branches and tags arrive as ordinary refs, create-only, and a ref that already stands
//!   at the forge's own commit is `already` rather than rewritten;
//! * a pull request becomes a change record carrying `origin: pull <n>`, signed by the
//!   migrating machine, readable afterwards by `gitiup change show`;
//! * check-run evidence becomes an attestation only when the copy re-hashes to the digest
//!   the run claims, and the truncated one is refused by name;
//! * a ref the destination cannot back is refused, not written into nowhere;
//! * a ref that disagrees with the forge is a failed run, never an overwrite;
//! * a second run moves nothing, and the rate limit stops a run before it spends the quota.

#![cfg(feature = "hosts-github")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use gitiup_host::Oid;
use gitiup_host_github::testing::{ForgeServer, MockForge};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The token the mock accepts.
const TOKEN: &str = "gitiup-test-token";

/// A home, a working repository, a bare destination cloned from it, and a forge between
/// the two.
struct Scenario {
    harness: Harness,
    /// The real commits the forge advertises.
    base: String,
    head: String,
    forge: Arc<MockForge>,
    _server: ForgeServer,
    /// The destination: a bare clone, so it holds the same objects the forge names.
    dest: PathBuf,
}

impl Scenario {
    fn new() -> Scenario {
        let harness = Harness::new();
        harness.key();
        let work = harness.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["config", "user.email", "ada@example.org"]);
        git(&work, &["config", "user.name", "Ada"]);
        git(&work, &["config", "commit.gpgsign", "false"]);
        std::fs::write(work.join("Makefile"), "all:\n\t@echo one\n").expect("makefile");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "Add the build"]);
        let base = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(work.join("extra.txt"), "proposed\n").expect("file");
        git(&work, &["add", "extra.txt"]);
        git(&work, &["commit", "-q", "-m", "Propose the extra file"]);
        let head = git(&work, &["rev-parse", "HEAD"]);

        let forge = MockForge::new();
        let server = ForgeServer::start(forge.clone()).expect("a forge on a socket");
        harness.config(
            &server,
            &harness.path().join("dest.git").display().to_string(),
        );
        forge.set_ref("refs/heads/main", &base);
        forge.set_ref("refs/heads/feature", &head);
        // Two names the destination does not have yet, pointing at commits it does have:
        // this is what a migration actually does — a branch renamed on the forge, a tag
        // somebody made after the clone was taken.
        forge.set_ref("refs/heads/topic", &head);
        forge.set_ref("refs/tags/v1", &base);

        // The destination is a clone of the same history, so every commit the forge names is
        // one it can produce on request: the refs can move, and the objects do not have to.
        let dest = harness.path().join("dest.git");
        let clone = Command::new("git")
            .args(["clone", "--bare", "-q"])
            .arg(&work)
            .arg(&dest)
            .output()
            .expect("git clone");
        assert!(
            clone.status.success(),
            "{}",
            String::from_utf8_lossy(&clone.stderr)
        );

        Scenario {
            harness,
            base,
            head,
            forge,
            _server: server,
            dest,
        }
    }

    /// Run `gitiup migrate repo … --json` and parse the report.
    fn migrate(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "migrate",
            "repo",
            "--from",
            "origin",
            "--to",
            "dest",
            "--no-history",
            "--json",
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args)
    }

    fn migrate_ok(&self, extra: &[&str]) -> Value {
        let output = self.migrate(extra);
        ok(&output, &format!("`migrate repo {}`", extra.join(" ")))
    }

    /// What the destination's own git thinks a ref is.
    fn dest_ref(&self, name: &str) -> Option<String> {
        let out = Command::new("git")
            .current_dir(&self.dest)
            .args(["rev-parse", "--verify", name])
            .output()
            .expect("git rev-parse");
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            None
        }
    }

    /// A second branch in the working repository, pushed only to the destination: this is
    /// how a destination ends up disagreeing with the forge.
    fn push_a_different_main(&self) -> String {
        let work = self.harness.path().join("work");
        git(&work, &["checkout", "-q", "main"]);
        std::fs::write(work.join("later.txt"), "divergent\n").expect("file");
        git(&work, &["add", "."]);
        git(
            &work,
            &["commit", "-q", "-m", "A commit the forge never saw"],
        );
        let other = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &["push", "-q", self.dest.to_str().expect("utf-8"), "main"],
        );
        other
    }

    /// The journal file the run left behind.
    fn journal(&self) -> Option<Value> {
        let dir = self.harness.path().join(".gitiup").join("migrate");
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e == "json") {
                let text = std::fs::read_to_string(entry.path()).ok()?;
                return serde_json::from_str(&text).ok();
            }
        }
        None
    }
}

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

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("GITIUP_GITHUB_TOKEN", TOKEN)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .current_dir(self.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .spawn()
            .expect("the binary runs")
            .wait_with_output()
            .expect("wait")
    }

    fn key(&self) {
        let output = self.run(&["key", "gen", "--name", "ada"]);
        assert!(
            output.status.success(),
            "`key gen` failed: {}",
            stderr(&output)
        );
    }

    fn config(&self, server: &ForgeServer, dest: &str) {
        std::fs::write(
            self.path().join("gitiup.toml"),
            format!(
                "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \
                 \"origin\"\nurl = \"{url}\"\n\n[remote.options]\nhost-type = \
                 \"github\"\napi-base = \"{api}\"\nref-cache-ttl = \"100ms\"\n\n\
                 [[remote]]\nname = \"dest\"\nurl = \"file://{dest}\"\n\n\
                 [remote.options]\nhost-type = \"git\"\n",
                url = server.url,
                api = server.api_base,
                dest = dest,
            ),
        )
        .expect("write gitiup.toml");
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn ok(output: &Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} failed ({}): {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    serde_json::from_str(&stdout(output)).unwrap_or_else(|e| {
        panic!(
            "{what}: the --json output is not JSON ({e}): {}",
            stdout(output)
        )
    })
}

fn tokens(report: &Value, field: &str) -> Vec<String> {
    report[field]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| entry["type"].as_str().map(str::to_string))
        .collect()
}

/// Branches and tags become ordinary refs, create-only, and a ref already at the forge's
/// commit is left alone.
#[test]
fn branches_and_tags_arrive_as_ordinary_refs() {
    let scene = Scenario::new();
    let report = scene.migrate_ok(&["--no-pulls"]);
    // `main` was already where the forge has it; `feature` and `v1` had to be written.
    assert_eq!(report["refs"]["written"].as_u64(), Some(2), "{report}");
    assert_eq!(report["refs"]["already"].as_u64(), Some(2), "{report}");
    assert_eq!(report["refs"]["branches"].as_u64(), Some(3), "{report}");
    assert_eq!(report["refs"]["tags"].as_u64(), Some(1), "{report}");
    assert_eq!(report["refs"]["diverged"].as_array().unwrap().len(), 0);
    assert_eq!(
        scene.dest_ref("refs/heads/topic").as_deref(),
        Some(scene.head.as_str())
    );
    assert_eq!(
        scene.dest_ref("refs/tags/v1").as_deref(),
        Some(scene.base.as_str())
    );
    // The account of the run travels with the store it built, not only with the laptop.
    let account = report["account"].as_str().unwrap_or_default().to_string();
    assert!(account.starts_with("refs/gitiup/migrate/"), "{account}");
    let named = account.split_whitespace().next().expect("ref name");
    assert!(
        scene.dest_ref(named).is_some(),
        "{named} was advertised and is not there"
    );
    // A migration confers no trust, and says so where the trust would have been read.
    assert_eq!(report["trust"].as_str(), Some("none"));
}

/// A pull request becomes a change record, signed here, carrying the forge's number as its
/// origin — the fact `gitiup change merge` needs in order to know the forge is the merge.
#[test]
fn a_pull_request_becomes_a_change_carrying_its_forge_origin() {
    let scene = Scenario::new();
    scene.forge.open_pull(
        7,
        "Propose the extra file",
        &scene.head,
        "2026-01-01T00:00:00Z",
    );
    let report = scene.migrate_ok(&["--no-branches", "--no-tags"]);
    assert_eq!(report["changes"]["published"].as_u64(), Some(1), "{report}");
    assert_eq!(report["changes"]["refused"].as_array().unwrap().len(), 0);

    let listing = ok(
        &scene
            .harness
            .run(&["change", "list", "--remote", "dest", "--json"]),
        "`change list`",
    );
    let rows = listing["changes"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 1, "{listing}");
    let id = rows[0]["change"].as_str().expect("a change id").to_string();
    let shown = ok(
        &scene
            .harness
            .run(&["change", "show", "--remote", "dest", "--json", &id]),
        "`change show`",
    );
    assert_eq!(shown["origin"]["kind"].as_str(), Some("pull"), "{shown}");
    assert_eq!(shown["origin"]["number"].as_u64(), Some(7), "{shown}");
    assert_eq!(
        shown["head"].as_str(),
        Some(format!("sha1:{}", scene.head).as_str()),
        "{shown}"
    );
    // The forge's title is kept, and kept where it belongs: as an annotation a reader can
    // check, not as a field somebody signed.
    assert_eq!(
        shown["title"].as_str(),
        Some("Propose the extra file"),
        "{shown}"
    );
    // The forge's own fields came across as annotations, which is the only place they
    // belong: nobody at the forge signed them.
    let annotations = shown["document"]["annotations"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        annotations
            .get("x_gitiup_pull_number")
            .and_then(Value::as_str),
        Some("7"),
        "{shown}"
    );
}

/// Check-run evidence is only worth what its bytes are: the run that re-hashes to its own
/// digest is the document; everything else is an advertisement, and is reported as one.
#[test]
fn check_run_evidence_is_carried_only_when_it_is_the_bytes() {
    let scene = Scenario::new();
    let subject = Oid::from_hex(&scene.head).expect("a commit sha");
    let document = b"{\"type\":\"gitiup-attest-1\"}\n";
    scene
        .forge
        .publish_check_run_only(&subject, document, false);
    scene
        .forge
        .publish_check_run_only(&subject, b"the copy the forge cut short", true);
    // The tally of what came out of the forge, and of what could be rebuilt from it.
    let report = scene.migrate_ok(&["--no-pulls", "--no-branches", "--no-tags", "--with-proofs"]);
    assert_eq!(report["proofs"]["carried"].as_u64(), Some(1), "{report}");
    let dropped = tokens(&report, "dropped");
    assert!(
        dropped.contains(&"check_run_copy_truncated".to_string()),
        "the truncated copy has to be named: {report}"
    );
    // The commit the proof is about is one the destination can produce, so the run reads it
    // back out of the store and re-hashes it — and says which clock the proof's age is told
    // from, because that is the number ADR-0005 says is not a fact about the bytes.
    assert_eq!(report["verify"]["rehashed"].as_u64(), Some(1), "{report}");
    assert_eq!(report["verify"]["matched"].as_u64(), Some(1), "{report}");
    assert_eq!(report["verify"]["mismatched"].as_array().unwrap().len(), 0);
    assert_eq!(
        report["verify"]["age_basis"].as_str(),
        Some("claimed_at_us")
    );
    assert_eq!(report["code"].as_u64(), Some(0), "{report}");
    // …and under --strict that gap is a failure, because the operator asked for one.
    let strict = scene.migrate(&[
        "--no-pulls",
        "--no-branches",
        "--no-tags",
        "--with-proofs",
        "--strict",
    ]);
    assert_eq!(code(&strict), 6, "{}{}", stdout(&strict), stderr(&strict));
}

/// A ref to a commit the store cannot produce is a pointer into nowhere: it is refused, and
/// the run says which refs it refused.
#[test]
fn a_ref_the_store_cannot_back_is_refused() {
    let scene = Scenario::new();
    let bucket = scene.harness.path().join("bucket");
    std::fs::create_dir_all(&bucket).expect("bucket");
    let output = scene.harness.run(&[
        "migrate",
        "repo",
        "--from",
        "origin",
        "--to",
        bucket.to_str().expect("utf-8"),
        "--no-history",
        "--no-pulls",
        "--json",
    ]);
    let report = ok(&output, "`migrate repo` into an empty bucket");
    assert_eq!(report["refs"]["written"].as_u64(), Some(0), "{report}");
    let dropped = tokens(&report, "dropped");
    assert_eq!(
        dropped
            .iter()
            .filter(|token| *token == "ref_without_history")
            .count(),
        4,
        "all three refs are refused, by name: {report}"
    );
    assert_eq!(report["code"].as_u64(), Some(0));
    assert!(report["halted"].is_null(), "{report}");
}

/// Two histories claiming one name is the one thing a migration must not decide silently.
#[test]
fn a_ref_that_disagrees_with_the_forge_fails_the_run() {
    let scene = Scenario::new();
    let other = scene.push_a_different_main();
    let output = scene.migrate(&["--no-pulls"]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    let report: Value = serde_json::from_str(&stdout(&output)).expect("the report is JSON");
    let diverged = report["refs"]["diverged"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(diverged.len(), 1, "{report}");
    assert_eq!(diverged[0][0].as_str(), Some("refs/heads/main"));
    assert_eq!(
        diverged[0][1].as_str(),
        Some(other.as_str()),
        "the store's own oid"
    );
    assert_eq!(
        diverged[0][2].as_str(),
        Some(scene.base.as_str()),
        "the forge's oid"
    );
    // And the destination is exactly as it was: no overwrite, no partial repair.
    assert_eq!(
        scene.dest_ref("refs/heads/main").as_deref(),
        Some(other.as_str())
    );
}

/// The same command twice: the second run reads its journal, moves nothing, and says so.
#[test]
fn a_second_run_moves_nothing_and_says_already() {
    let scene = Scenario::new();
    scene.forge.open_pull(
        7,
        "Propose the extra file",
        &scene.head,
        "2026-01-01T00:00:00Z",
    );
    let first = scene.migrate_ok(&[]);
    assert!(first["refs"]["written"].as_u64().unwrap_or(0) > 0);
    let journal = scene.journal().expect("the run left a journal");
    assert!(journal["done"].as_array().unwrap().len() > 1, "{journal}");

    let second = scene.migrate_ok(&[]);
    assert_eq!(second["refs"]["written"].as_u64(), Some(0), "{second}");
    assert_eq!(second["changes"]["published"].as_u64(), Some(0), "{second}");
    assert!(
        second["changes"]["already"].as_u64().unwrap_or(0) >= 1,
        "{second}"
    );
    assert!(
        second["resumed_steps"].as_u64().unwrap_or(0) > 0,
        "{second}"
    );
    assert_eq!(second["code"].as_u64(), Some(0));
}

/// A rate limit stops the run before it spends the quota it does not have, and says which
/// step it stopped at rather than reporting an empty success.
#[test]
fn a_spent_rate_limit_stops_the_run_and_says_so() {
    let scene = Scenario::new();
    scene.forge.exhaust_rate_limit_from(1);
    let output = scene.migrate(&[]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    let report: Value = serde_json::from_str(&stdout(&output)).expect("the report is JSON");
    assert!(
        report["halted"]
            .as_str()
            .is_some_and(|token| token.contains("rate")),
        "{report}"
    );
    assert_eq!(report["refs"]["written"].as_u64(), Some(0), "{report}");
}

/// `--dry-run` reads everything and writes nothing, journal included.
#[test]
fn a_dry_run_leaves_the_destination_alone() {
    let scene = Scenario::new();
    scene.forge.open_pull(
        7,
        "Propose the extra file",
        &scene.head,
        "2026-01-01T00:00:00Z",
    );
    let report = scene.migrate_ok(&["--dry-run"]);
    assert!(report["dry_run"].as_bool().unwrap_or(false));
    assert!(
        report["refs"]["written"].as_u64().unwrap_or(0) > 0,
        "{report}"
    );
    assert_eq!(
        scene.dest_ref("refs/heads/topic"),
        None,
        "nothing was written"
    );
    assert!(
        scene.journal().is_none(),
        "a dry run leaves no journal either"
    );
    assert_eq!(scene.dest_ref("refs/tags/v1"), None);
}

/// The whole thing, the way the ticket asks for it: history, refs, a proof, into a store
/// with no git object database at all.
///
/// The history comes from `--git-url`, which is the honest shape of a real migration — the
/// forge's API is not where 40 GB of commits live, and a forge that rate-limits you names
/// the git endpoint to use instead. The destination is a plain directory, so the objects
/// have to travel as gitiup records, and the verification has to read them back out of the
/// store that received them.
#[test]
fn history_refs_and_a_proof_move_into_a_store_with_no_git_database() {
    let scene = Scenario::new();
    let subject = Oid::from_hex(&scene.head).expect("a commit sha");
    scene
        .forge
        .publish_check_run_only(&subject, b"the document itself\n", false);
    let bucket = scene.harness.path().join("bucket");
    std::fs::create_dir_all(&bucket).expect("bucket");
    let work = scene.harness.path().join("work");
    let run = |extra: &[&str]| -> Value {
        let mut args = vec![
            "migrate",
            "repo",
            "--from",
            "origin",
            "--to",
            bucket.to_str().expect("utf-8"),
            "--git-url",
            work.to_str().expect("utf-8"),
            "--with-proofs",
            "--json",
        ];
        args.extend_from_slice(extra);
        ok(&scene.harness.run(&args), "`migrate repo` with history")
    };

    let first = run(&[]);
    // Every ref the forge advertises lands, because its objects landed first.
    assert_eq!(first["refs"]["written"].as_u64(), Some(4), "{first}");
    assert_eq!(first["refs"]["diverged"].as_array().unwrap().len(), 0);
    assert!(
        first["history"]["objects"].as_u64().unwrap_or(0) > 0,
        "{first}"
    );
    assert_eq!(
        first["history"]["form"].as_str(),
        Some("records"),
        "{first}"
    );
    // The proof is about a commit whose bytes this store now holds, so the final step can
    // read them back out of the destination and re-hash them there.
    assert_eq!(first["proofs"]["carried"].as_u64(), Some(1), "{first}");
    assert_eq!(first["verify"]["rehashed"].as_u64(), Some(1), "{first}");
    assert_eq!(first["verify"]["matched"].as_u64(), Some(1), "{first}");
    assert_eq!(first["verify"]["mismatched"].as_array().unwrap().len(), 0);
    assert_eq!(first["code"].as_u64(), Some(0), "{first}");

    // The same command again: nothing new to move, nothing to write, and the second run
    // says which of those is which rather than printing zeroes and calling it a day.
    let second = run(&[]);
    assert_eq!(second["refs"]["written"].as_u64(), Some(0), "{second}");
    assert_eq!(second["refs"]["already"].as_u64(), Some(4), "{second}");
    assert_eq!(second["history"]["objects"].as_u64(), Some(0), "{second}");
    assert_eq!(second["proofs"]["already"].as_u64(), Some(1), "{second}");
    assert_eq!(second["code"].as_u64(), Some(0), "{second}");
    // `--strict` is the operator's question — *did anything at all fail to come?* — and a
    // migration that carried its one proof and re-hashed it has nothing to answer.
    let strict = scene.harness.run(&[
        "migrate",
        "repo",
        "--from",
        "origin",
        "--to",
        bucket.to_str().expect("utf-8"),
        "--git-url",
        work.to_str().expect("utf-8"),
        "--with-proofs",
        "--strict",
        "--json",
    ]);
    assert_eq!(code(&strict), 0, "{}{}", stdout(&strict), stderr(&strict));
    let strict: Value = serde_json::from_str(&stdout(&strict)).expect("JSON");
    assert_eq!(strict["verify"]["matched"].as_u64(), Some(1), "{strict}");
    assert!(strict["dropped"].as_array().unwrap().is_empty(), "{strict}");
}

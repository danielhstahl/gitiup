//! `gitiup change list|show|submit|merge` against a github remote (giti-b2z.7).
//!
//! The acceptance criterion is that the four verbs work *unchanged* against a forge, and
//! the only honest way to test that is to run the binary the way a person does, against a
//! forge at a URL. So: the mock forge from `gitiup-host-github`, on a loopback socket,
//! with a `gitiup.toml` whose `url` and `api-base` point at it, and the built `gitiup`
//! driven by the same harness the fs-store tests use. Nothing here is a unit test of the
//! adapter — the adapter has its own suite for that — and nothing here is a mock of the
//! CLI either: every claim below is read back from the forge or from the store after a
//! real process ran.
//!
//! What the four verbs have to answer, and what this file asserts:
//!
//! * `submit` files the change and asks the forge to carry it, and says which of the two
//!   it managed. The forge is asked *after* the store, so a change with refs and no pull
//!   is a real outcome and is printed as one rather than as a failure or a silence.
//! * `list` answers for both databases and labels each row: `both` when a ref and a pull
//!   describe one change, `ref` when the forge has no pull for it, `pull` when the store
//!   has no record for it. A pull with no record is listed, not skipped.
//! * `show` reads the store's record and annotates it with the forge's answer, and will
//!   show a pull that has no record at all — labelled as the forge's copy.
//! * `merge` uses the forge's merge for a change the forge carries, and records `via:
//!   forge` rather than pretending gitiup moved the branch (ADR-0003 D10).
//!
//! The forge-side limits are asserted where a caller can see them: `source`,
//! `copy_truncated` and the caveats a row carries.

#![cfg(feature = "hosts-github")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use gitiup_host_github::testing::{ForgeServer, MockForge};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The token the mock accepts, and the only thing that makes a write possible there.
const TOKEN: &str = "gitiup-test-token";

/// A home, a repository, a forge on a socket, and the binary pointed at all three.
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

    /// Run the binary against this home and this forge.
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

    /// Point the `origin` remote at the forge on its socket.
    fn config(&self, server: &ForgeServer) {
        std::fs::write(
            self.path().join("gitiup.toml"),
            format!(
                "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \
                 \"origin\"\nurl = \"{url}\"\n\n[remote.options]\nhost-type = \
                 \"github\"\napi-base = \"{api}\"\nref-cache-ttl = \"100ms\"\n",
                url = server.url,
                api = server.api_base
            ),
        )
        .expect("write gitiup.toml");
    }
}

/// The repository a change comes from: `main`, and `feature` one commit ahead.
struct Repo {
    dir: PathBuf,
    base: String,
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
        std::fs::write(dir.join("Makefile"), "all:\n\t@echo one\n").expect("makefile");
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "Add the build"]);
        let base = git(&dir, &["rev-parse", "HEAD"]);
        git(&dir, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(dir.join("extra.txt"), "proposed\n").expect("file");
        git(&dir, &["add", "extra.txt"]);
        git(&dir, &["commit", "-q", "-m", "Propose the extra file"]);
        let head = git(&dir, &["rev-parse", "HEAD"]);
        Repo { dir, base, head }
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

/// Everything a forge test needs standing up: the forge on a socket, the repository, and
/// a `gitiup.toml` that points one at the other.
///
/// The forge starts with `main` at the repository's own base commit and `feature` at its
/// head, because those are the two facts a real contributor's `git push` leaves behind:
/// the branch the change is proposed against, and the branch the pull request will be
/// opened from. A test that wants the second one absent takes it back off.
struct Scenario {
    harness: Harness,
    repo: Repo,
    forge: Arc<MockForge>,
    _server: ForgeServer,
}

impl Scenario {
    fn new() -> Scenario {
        let harness = Harness::new();
        harness.key();
        let repo = Repo::new(&harness);
        let forge = MockForge::new();
        let server = ForgeServer::start(forge.clone()).expect("a forge on a socket");
        harness.config(&server);
        // The forge answers the repository the remote names, so the mock has to be the
        // one repository the config points at.
        forge.set_ref("refs/heads/main", &repo.base);
        forge.set_ref("refs/heads/feature", &repo.head);
        // The commits are git's, not the API's: a forge that never saw them cannot say
        // whether moving a branch onto one is a fast-forward.
        forge.adopt_commit(&repo.head, &[&repo.base]);
        Scenario {
            harness,
            repo,
            forge,
            _server: server,
        }
    }

    /// `change submit --remote origin --json`, the way a contributor runs it.
    fn submit(&self, extra: &[&str]) -> Value {
        let mut args = vec![
            "change",
            "submit",
            "--remote",
            "origin",
            "--repository",
            self.repo.path(),
            "--base",
            "main",
            "--json",
        ];
        args.extend(extra.iter().copied());
        ok(&self.harness.run(&args), "`change submit`")
    }

    fn list(&self, extra: &[&str]) -> Value {
        let mut args = vec!["change", "list", "--remote", "origin", "--json"];
        args.extend(extra.iter().copied());
        ok(&self.harness.run(&args), "`change list`")
    }

    fn row<'a>(&'a self, listing: &'a Value, change: &str) -> &'a Value {
        listing["changes"]
            .as_array()
            .expect("a list")
            .iter()
            .find(|row| row["change"] == change)
            .unwrap_or_else(|| panic!("{change} is not in the listing: {listing}"))
    }
}

#[test]
fn submitting_a_change_asks_the_forge_to_carry_it() {
    let scene = Scenario::new();
    let published = scene.submit(&[]);
    let change = published["change"]
        .as_str()
        .expect("a change id")
        .to_string();

    // The pull was opened, and the answer is the forge's: a number, and the source that
    // says the change now exists in both databases.
    assert_eq!(
        published["pull"]["pull"].as_u64(),
        Some(1),
        "the forge opened the first pull: {published}"
    );
    assert_eq!(published["pull"]["source"], "both");
    assert_eq!(
        scene.forge.pulls().len(),
        1,
        "the forge really was asked, and once"
    );

    // …and the listing agrees, without being told twice.
    let listing = scene.list(&["--state", "all"]);
    let row = scene.row(&listing, &change);
    assert_eq!(row["source"], "both", "{row}");
    assert_eq!(row["pull"], 1);
    assert_eq!(row["recorded"], true);
    // The forge's own words about what it cannot promise travel with the row.
    let caveats = row["caveats"].as_array().expect("caveats");
    assert!(
        !caveats.is_empty(),
        "a forge row always says what a bucket did not have to: {row}"
    );

    // `show` annotates the record with the same fact.
    let shown = ok(
        &scene
            .harness
            .run(&["change", "show", &change, "--remote", "origin", "--json"]),
        "`change show`",
    );
    assert_eq!(shown["source"], "both");
    assert_eq!(shown["pull"]["pull"], 1);
}

#[test]
fn a_re_submit_does_not_open_a_second_pull() {
    let scene = Scenario::new();
    scene.submit(&[]);
    // Same head, restated: the forge already carries it, and a reviewer does not need a
    // second pull for a commit that already has one.
    let again = scene.submit(&["--new-attempt"]);
    assert_eq!(again["already"], false, "an attempt is a real write");
    assert!(
        again["pull"]["note"].is_string(),
        "and the reason no second pull appeared is said: {again}"
    );
    assert_eq!(scene.forge.pulls().len(), 1, "one pull, not two");
}

#[test]
fn a_change_the_forge_does_not_carry_is_labelled_not_skipped() {
    let scene = Scenario::new();
    // No branch over the head: the forge will not open a pull from `refs/changes/**`, and
    // saying so is the whole of the honest answer.
    scene.forge.set_ref("refs/heads/feature", &scene.repo.base);
    let published = scene.submit(&[]);
    assert_eq!(
        published["pull"]["opened"], false,
        "the forge was not asked, and says why: {published}"
    );
    assert!(
        published["pull"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("branch"),
        "the note names what is missing: {}",
        published["pull"]["note"]
    );

    let listing = scene.list(&["--state", "all"]);
    let change = published["change"].as_str().expect("an id").to_string();
    let row = scene.row(&listing, &change);
    assert_eq!(row["source"], "ref", "{row}");
    assert_eq!(row["pull"], Value::Null);
    assert_eq!(
        row["recorded"], true,
        "the store's own record is the record"
    );

    // `--no-pull` is the same outcome chosen on purpose.
    let scene = Scenario::new();
    let chosen = scene.submit(&["--no-pull"]);
    assert_eq!(chosen["pull"]["opened"], false);
    assert_eq!(
        scene.forge.pulls().len(),
        0,
        "the forge was not asked at all"
    );
    let listing = scene.list(&["--state", "all"]);
    let change = chosen["change"].as_str().expect("an id").to_string();
    assert_eq!(scene.row(&listing, &change)["source"], "ref");
}

#[test]
fn a_pull_with_no_record_is_listed_and_labelled() {
    let scene = Scenario::new();
    // Somebody opened a pull request the gitiup way knows nothing about: the forge has it,
    // the store has no refs and no record.
    scene.forge.open_pull(
        7,
        "Somebody else's work",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "2026-01-05T10:00:00Z",
    );

    let listing = scene.list(&["--state", "all"]);
    let rows = listing["changes"].as_array().expect("a list");
    let row = rows
        .iter()
        .find(|row| row["change"] == "gh-7")
        .unwrap_or_else(|| panic!("the pull is listed, not skipped: {listing}"));
    assert_eq!(row["source"], "pull");
    assert_eq!(row["recorded"], false);
    assert_eq!(row["state"], "open");
    assert!(
        row["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no gitiup record"),
        "and it says what is missing: {row}"
    );
    assert_eq!(
        row["url"].as_str().unwrap(),
        "https://github.com/gitiup/mock/pull/7"
    );

    // It is showable too, as the forge's answer rather than as a record.
    let shown = scene
        .harness
        .run(&["change", "show", "gh-7", "--remote", "origin", "--json"]);
    let shown = ok(&shown, "`change show gh-7`");
    assert_eq!(shown["recorded"], false);
    assert_eq!(shown["source"], "pull");
    assert_eq!(shown["title"], "Somebody else's work");

    // …and the human page says the thing that matters about it out loud.
    let text = scene
        .harness
        .run(&["change", "show", "gh-7", "--remote", "origin"]);
    assert!(text.status.success(), "{}", stderr(&text));
    assert!(
        stdout(&text).contains("nothing here is signed"),
        "{}",
        stdout(&text)
    );
}

#[test]
fn the_forge_merges_the_change_it_carries() {
    let scene = Scenario::new();
    let published = scene.submit(&[]);
    let change = published["change"].as_str().expect("an id").to_string();

    let merged = ok(
        &scene.harness.run(&[
            "change",
            "merge",
            &change,
            "--remote",
            "origin",
            "--repository",
            scene.repo.path(),
            "--json",
        ]),
        "`change merge`",
    );
    // D10: the forge merged, so the record says the forge merged.
    assert_eq!(merged["via"], "forge", "{merged}");
    assert_eq!(merged["pull"], 1);
    assert_eq!(
        merged["to"].as_str().expect("an oid").replace("sha1:", ""),
        scene.repo.head,
        "the branch moved to the change's own commit"
    );
    assert_eq!(
        scene.forge.refs()["refs/heads/main"],
        scene.repo.head,
        "and the forge is where it happened, not gitiup's own ref write"
    );
}

#[test]
fn a_merge_without_a_pull_falls_back_to_the_store() {
    let scene = Scenario::new();
    // Nothing for the forge to merge: no branch over the head, so no pull.
    scene.forge.set_ref("refs/heads/feature", &scene.repo.base);
    let published = scene.submit(&[]);
    let change = published["change"].as_str().expect("an id").to_string();
    assert_eq!(scene.forge.pulls().len(), 0);

    let merged = ok(
        &scene.harness.run(&[
            "change",
            "merge",
            &change,
            "--remote",
            "origin",
            "--repository",
            scene.repo.path(),
            "--json",
        ]),
        "`change merge`",
    );
    // The store's own compare-and-swap, which on this host is the forge's data API: the
    // same verb, the weaker promise, and `via` that says which one ran.
    assert_eq!(merged["via"], "store", "{merged}");
    assert_eq!(merged["pull"], Value::Null);
    assert_eq!(scene.forge.refs()["refs/heads/main"], scene.repo.head);
}

#[test]
fn a_forge_refused_as_a_store_is_still_classified_as_a_forge() {
    // The smallest check that the composition root is what routes these commands: the same
    // `gitiup.toml` answers `doctor` as a github remote and the verbs as a store.
    let scene = Scenario::new();
    let doctor = ok(
        &scene.harness.run(&["doctor", "--remotes", "--json"]),
        "`doctor --remotes`",
    );
    let remote = &doctor["remotes"].as_array().expect("remotes")[0];
    assert_eq!(remote["served"]["host"], "github", "{remote}");
    // And the verbs work against it, which is the ticket.
    let listing = scene.list(&["--state", "all"]);
    assert_eq!(listing["forge"]["asked"], true);
    assert_eq!(listing["count"].as_u64(), Some(0), "nothing filed yet");
}

#[test]
fn a_pull_somebody_else_opened_is_the_one_the_record_claims() {
    // The human path: a pull request exists because a person opened it on the forge, and
    // the change gitiup files says so in its own signed bytes (`origin: pull`) rather than
    // hoping a later lookup guesses right.
    let scene = Scenario::new();
    scene.forge.open_pull(
        12,
        "opened by hand, on the forge",
        &scene.repo.head,
        "2026-01-05T10:00:00Z",
    );

    let published = scene.submit(&["--pull", "12"]);
    assert_eq!(scene.forge.pulls().len(), 1, "no second pull was opened");
    assert!(
        published["pull"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("not asked to open a second one"),
        "and the answer says why: {}",
        published["pull"]
    );

    let shown = ok(
        &scene.harness.run(&[
            "change",
            "show",
            published["change"].as_str().expect("an id"),
            "--remote",
            "origin",
            "--json",
        ]),
        "`change show`",
    );
    assert_eq!(shown["source"], "both");
    assert_eq!(shown["pull"]["pull"], 12, "the claimed pull, not a guess");

    // …and a merge of that change is that pull's merge.
    let merged = ok(
        &scene.harness.run(&[
            "change",
            "merge",
            published["change"].as_str().expect("an id"),
            "--remote",
            "origin",
            "--repository",
            scene.repo.path(),
            "--json",
        ]),
        "`change merge`",
    );
    assert_eq!(merged["via"], "forge");
    assert_eq!(merged["pull"], 12);
}

#[test]
fn a_claimed_pull_the_forge_does_not_have_is_said_out_loud() {
    // The same flag, lied to: a number with no pull behind it. The record is still the
    // record — the claim is what the author signed, and taking the write back would be its
    // own untruth — but a merge would chase a pull that is not there, so the answer says so
    // while there is still time to fix it.
    let scene = Scenario::new();
    let published = scene.submit(&["--pull", "99"]);
    assert!(
        published["pull"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("no open pull"),
        "the note names the missing pull: {}",
        published["pull"]
    );
    assert_eq!(
        scene.forge.pulls().len(),
        0,
        "nothing was opened to fill the gap"
    );
}

#[test]
fn two_pulls_over_one_change_are_refused_rather_than_guessed() {
    // An ambiguity is somebody else's decision. gitiup naming one of two open pulls would
    // be a guess about which review counts, and a guessed merge is the worst place to guess.
    let scene = Scenario::new();
    scene
        .forge
        .open_pull(7, "first review", &scene.repo.head, "2026-01-05T10:00:00Z");
    scene
        .forge
        .open_pull(8, "second review", &scene.repo.head, "2026-01-05T11:00:00Z");
    let published = scene.submit(&[]);
    let change = published["change"].as_str().expect("an id").to_string();

    let refused = scene.harness.run(&[
        "change",
        "merge",
        &change,
        "--remote",
        "origin",
        "--repository",
        scene.repo.path(),
        "--json",
    ]);
    assert_eq!(
        code(&refused),
        6,
        "{}{}",
        stdout(&refused),
        stderr(&refused)
    );
    let said = format!("{}{}", stdout(&refused), stderr(&refused));
    assert!(
        said.contains("open pulls") && said.contains("7") && said.contains("8"),
        "the refusal names every pull it could not choose between: {said}"
    );
    assert_eq!(
        scene.forge.refs()["refs/heads/main"],
        scene.repo.base,
        "and nothing moved"
    );
}

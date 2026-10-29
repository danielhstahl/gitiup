//! `gitiup change new|submit|list|show`, run as the real binary (giti-b2z.3).
//!
//! The ticket's acceptance criteria are command lines, so they are tested as command
//! lines against the built executable: a real local repository (the record's facts come
//! from `git`'s plumbing, so a fixture would test the fixture), a real keystore (the
//! author is the signature, so the key has to be a real one), and a real store per case.
//!
//! Three stores are covered, because the criterion says the four verbs work against all
//! three and the composition through `gitiup.toml` is the thing being tested:
//!
//! * the `fs` host, for the whole new → submit → list → show loop and every refusal;
//! * a **plain git remote** over `file://`, where the claims that matter most live —
//!   that the proposed commits arrive, that `refs/changes/**` is advertised on the
//!   remote, and that a stranger's `git fetch` carries them;
//! * a **bucket**, gated like the rest of the live transport (`--ignored`, and it skips
//!   unless an endpoint is named), because standing one up in a CLI test would be testing
//!   the transport and not the command.
//!
//! The `fs` store's own `refs/heads/main` is seeded with the host API: a branch is the
//! owner's fact (docs/host-abstraction.md), and refusing to invent one is a decision this
//! file asserts on purpose.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{Expect, FsHost, Oid, RefName, RefStore, RefUpdate};
use serde_json::Value;

#[path = "common/mod.rs"]
mod common;

use common::SmartHttp;

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

    /// Write `gitiup.toml` in the working directory.
    fn config(&self, text: &str) {
        std::fs::write(self.path().join("gitiup.toml"), text).expect("write gitiup.toml");
    }

    /// The fs store, with `refs/heads/main` standing at `base` — the owner's act, done
    /// here with the host API because nothing in gitiup publishes a branch.
    fn seed(&self, branch: &str, base: &str) {
        let host = FsHost::open_or_create(self.store()).expect("open the fs store");
        let oid = Oid::from_hex(base).expect("an oid");
        let name = RefName::branch(branch).expect("a branch name");
        host.update_ref_cas(&RefUpdate::new(name, Expect::Absent, oid))
            .expect("publish the branch");
    }

    /// Move a branch in the fs store, which is how a stale base happens.
    fn move_branch(&self, branch: &str, from: &str, to: &str) {
        let host = FsHost::open_or_create(self.store()).expect("open the fs store");
        let name = RefName::branch(branch).expect("a branch name");
        host.update_ref_cas(&RefUpdate::replace(
            name,
            Oid::from_hex(from).expect("an oid"),
            Oid::from_hex(to).expect("an oid"),
        ))
        .expect("move the branch");
    }

    /// The record bytes `new` wrote.
    fn record(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path().join(name)).unwrap_or_else(|e| {
            panic!("reading {name}: {e}");
        })
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path().join(name);
        std::fs::write(&path, bytes).expect("write the file");
        path.display().to_string()
    }
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

/// The repository the change comes from: `main` at one commit, `feature` one ahead of it,
/// and a workflow whose job ids the hint should pick up.
struct Repo {
    dir: PathBuf,
    /// `main`'s commit: the base a change forks from.
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
        std::fs::create_dir_all(dir.join(".github/workflows")).expect("workflows dir");
        std::fs::write(
            dir.join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make test\n",
        )
        .expect("workflow");
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

    /// Another commit on `feature`, which is a force-push waiting to be an attempt.
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

/// Draft a record and return its parsed canonical bytes.
fn draft(harness: &Harness, repo: &Repo, extra: &[&str]) -> Value {
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--out",
            "record.json",
        ]
        .iter()
        .chain(extra.iter())
        .copied()
        .collect::<Vec<&str>>(),
        None,
    );
    assert!(
        output.status.success(),
        "change new failed: {}{}",
        stdout(&output),
        stderr(&output)
    );
    let bytes = harness.record("record.json");
    serde_json::from_slice(&bytes).expect("the record is JSON")
}

// ---------------------------------------------------------------------------
// new
// ---------------------------------------------------------------------------

#[test]
fn a_draft_names_the_commits_the_author_and_the_base_it_forked_from() {
    let harness = Harness::new();
    let key = harness.key("ada");
    let repo = Repo::new(&harness);
    let record = draft(&harness, &repo, &[]);
    assert_eq!(record["type"], "gitiup-change-1");
    assert_eq!(record["schema_version"], 1);
    assert_eq!(record["head"], tagged(&repo.head));
    assert_eq!(record["base"]["ref"], "refs/heads/main");
    assert_eq!(
        record["base"]["oid"],
        tagged(&repo.base),
        "the base oid is the point the work forked from, which is what a merge compares"
    );
    assert_eq!(record["attempts"]["index"], 0);
    assert_eq!(record["attempts"]["anchor"], tagged(&repo.head));
    assert!(
        record["attempts"].get("previous").is_none(),
        "attempt 0 names no predecessor"
    );
    assert_eq!(record["title"], "Propose the extra file");
    assert_eq!(
        record["workflow"]["jobs"],
        serde_json::json!(["build", "test"])
    );
    assert_eq!(record["author"]["key_id"], key);
    assert_eq!(record["origin"]["kind"], "store");
    assert_eq!(
        record["signatures"]
            .as_array()
            .expect("one signature array")
            .len(),
        1,
        "the record is signed where it is drafted, so who proposed it is a signature"
    );
    assert_eq!(record["signatures"][0]["key_id"], key);
    let change_id = record["change_id"].as_str().expect("a change id");
    assert!(
        change_id.starts_with("chg-") && change_id.len() == 20,
        "a change id is `chg-` plus 16 hex: {change_id}"
    );
}

#[test]
fn the_draft_says_what_it_drafted_in_json_and_writes_bytes_separately() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--json",
            "--out",
            "record.json",
        ],
        None,
    );
    let summary = ok(&output, "change new --json");
    assert_eq!(summary["attempt"], 0);
    assert_eq!(summary["commits"], 1);
    assert_eq!(summary["signed"], true);
    assert_eq!(summary["written"], "record.json");
    assert_eq!(
        summary["jobs_from"], "workflow .github/workflows/ci.yml",
        "the workflow is named the way the repository knows it"
    );
    assert!(
        summary["change_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "both digests are in the summary: the one that never moves and the one the store keys by"
    );
    assert_eq!(
        summary["record_digest"].as_str().unwrap().len(),
        71,
        "the summary carries the store's key for the record, tagged like every other digest"
    );
}

#[test]
fn a_change_with_nothing_to_propose_is_refused() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--head",
            &repo.base,
        ],
        None,
    );
    assert_eq!(code(&output), 6, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("proposes nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unknown_branch_and_an_unknown_base_are_both_refused() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "nope",
        ],
        None,
    );
    assert_eq!(code(&output), 6);
    assert!(stderr(&output).contains("no branch 'nope'"));
    let output = harness.run(&["change", "new", "--repository", repo.path()], None);
    assert_eq!(code(&output), 2, "no --base is a usage error");
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            harness.path().to_str().expect("utf-8"),
            "--base",
            "main",
        ],
        None,
    );
    assert_eq!(code(&output), 6, "the temp directory is not a repository");
}

// ---------------------------------------------------------------------------
// submit, list and show against an fs store
// ---------------------------------------------------------------------------

/// The ticket's four command lines, in order, on a store resolved from `--store`.
#[test]
fn a_change_is_drafted_published_listed_and_shown() {
    let harness = Harness::new();
    let key = harness.key("ada");
    let repo = Repo::new(&harness);
    harness.seed("main", &repo.base);
    draft(&harness, &repo, &[]);

    let submitted = ok(
        &harness.run(
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
        ),
        "change submit",
    );
    let change_id = submitted["change"].as_str().unwrap().to_string();
    assert_eq!(submitted["attempt"], 0);
    assert_eq!(submitted["already"], false);
    assert_eq!(submitted["state"], "open");
    assert_eq!(submitted["base"]["check"], "ok");
    assert_eq!(submitted["base"]["store_oid"], tagged(&repo.base));
    assert_eq!(
        submitted["reference"],
        format!("refs/changes/{change_id}/attempt/0")
    );
    assert_eq!(
        submitted["head_ref"],
        format!("refs/changes/{change_id}/head")
    );
    assert_eq!(
        submitted["kv"],
        format!(
            "kv/change/{}",
            submitted["record_digest"]
                .as_str()
                .unwrap()
                .trim_start_matches("sha256:")
        ),
        "the CAS key is the bare digest of the bytes it holds; the output names the algorithm"
    );
    assert_eq!(
        submitted["objects"]["form"].as_str().unwrap(),
        "raw",
        "an fs store has no git object database, and says so rather than pretending"
    );
    assert!(submitted["objects"]["objects"].as_u64().unwrap() >= 2);
    assert_eq!(submitted["author"]["key_id"], key);

    // list --state open: the change is there, read back out of the signed record and
    // not out of a ref label.
    let listed = ok(
        &harness.run(
            &[
                "change",
                "list",
                "--state",
                "open",
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change list",
    );
    assert_eq!(listed["count"], 1);
    let row = &listed["changes"][0];
    assert_eq!(row["change"], change_id.as_str());
    assert_eq!(row["state"], "open");
    assert_eq!(row["attempt"], 0);
    assert_eq!(row["head"], tagged(&repo.head));
    assert_eq!(row["author"]["key_id"], key);
    assert_eq!(row["title"], "Propose the extra file");
    assert_eq!(row["base_check"], "ok");
    assert_eq!(row["stale"], false);
    assert_eq!(row["attempts"].as_array().unwrap().len(), 1);

    // show <id>, and the same by a 4-hex handle (D3: a short handle is fine until it is
    // ambiguous).
    let shown = ok(
        &harness.run(
            &[
                "change",
                "show",
                &change_id,
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change show",
    );
    assert_eq!(shown["change"], change_id.as_str());
    assert_eq!(shown["state"], "open");
    assert_eq!(shown["head"], tagged(&repo.head));
    assert_eq!(shown["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(shown["signatures"][0]["key_id"], key);
    assert_eq!(shown["document"]["change_id"], change_id.as_str());
    assert_eq!(shown["fetch"], format!("refs/changes/{change_id}/*"));
    assert!(shown["merged"].is_null() && shown["abandoned"].is_null());
    let short = &change_id[4..8];
    let by_prefix = ok(
        &harness.run(
            &[
                "change",
                "show",
                short,
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change show by handle",
    );
    assert_eq!(by_prefix["change"], change_id.as_str());

    // --bytes is the exact stored record: the same bytes `new` wrote, because the
    // signature is over them.
    let bytes = harness.run(
        &[
            "change",
            "show",
            &change_id,
            "--store",
            &harness.store(),
            "--bytes",
        ],
        None,
    );
    assert!(bytes.status.success(), "{}", stderr(&bytes));
    assert_eq!(
        stdout(&bytes).into_bytes(),
        harness.record("record.json"),
        "the published bytes are the drafted bytes"
    );

    // A second submit of the same record is a retry, not a second attempt.
    let again = ok(
        &harness.run(
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
        ),
        "re-submit",
    );
    assert_eq!(again["already"], true);
    assert_eq!(again["attempt"], 0);
    let listed = ok(
        &harness.run(
            &["change", "list", "--store", &harness.store(), "--json"],
            None,
        ),
        "change list",
    );
    assert_eq!(listed["count"], 1);
    assert_eq!(
        listed["changes"][0]["attempts"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn a_re_submit_is_a_new_attempt_and_the_old_record_never_moves() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    harness.seed("main", &repo.base);
    let first = draft(&harness, &repo, &[]);
    let change_id = first["change_id"].as_str().unwrap().to_string();
    ok(
        &harness.run(
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
        ),
        "attempt 0",
    );
    let first_digest = first["signatures"][0]["sig"].as_str().unwrap().to_string();

    // A force-push: another commit, drafted as the next attempt of the same change.
    let head2 = repo.commit_again("Fix the extra file");
    let second = draft(
        &harness,
        &repo,
        &["--change", &change_id, "--store", &harness.store()],
    );
    assert_eq!(
        second["change_id"],
        serde_json::Value::String(change_id.clone()),
        "the anchor is kept, so a re-push is the same change and not a second one"
    );
    assert_eq!(second["attempts"]["index"], 1);
    assert_eq!(second["attempts"]["anchor"], tagged(&repo.head));
    assert!(
        second["attempts"]["previous"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "attempt 1 names attempt 0's change_digest"
    );
    let path = "record.json";
    let published = ok(
        &harness.run(
            &[
                "change",
                "submit",
                "--record",
                path,
                "--repository",
                repo.path(),
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "attempt 1",
    );
    assert_eq!(published["attempt"], 1);
    assert_eq!(published["anchor"], tagged(&repo.head));
    assert!(
        published["previous"].is_string(),
        "attempt 1 names attempt 0"
    );

    let shown = ok(
        &harness.run(
            &[
                "change",
                "show",
                &change_id,
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change show",
    );
    let attempts = shown["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0]["head"], tagged(&repo.head));
    assert_eq!(attempts[1]["head"], tagged(&head2));
    assert_eq!(attempts[1]["previous"], attempts[0]["change_digest"]);
    assert_eq!(shown["attempt"], 1, "head names the newest attempt");

    // Attempt 0's record is still exactly what it was: same bytes, same ref, same
    // signature. That is the immutability the merge gate and every attestation depend on.
    let attempt0 = harness.run(
        &[
            "change",
            "show",
            &change_id,
            "--attempt",
            "0",
            "--store",
            &harness.store(),
            "--json",
        ],
        None,
    );
    let attempt0 = ok(&attempt0, "show --attempt 0");
    assert_eq!(attempt0["attempt"], 0);
    assert_eq!(attempt0["document"]["signatures"][0]["sig"], first_digest);
    assert_eq!(
        attempt0["reference"],
        format!("refs/changes/{change_id}/attempt/0")
    );
}

#[test]
fn a_stale_base_is_refused_naming_both_oids() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    harness.seed("main", &repo.base);
    draft(&harness, &repo, &[]);
    // The owner moves the branch: every attempt drafted against the old tip is stale.
    let moved = harness.path().join("moved");
    std::fs::create_dir_all(&moved).expect("dir");
    let other = {
        let out = Command::new("git")
            .current_dir(&repo.dir)
            .args(["hash-object", "-w", "-t", "blob", "/dev/null"])
            .output()
            .expect("git");
        let _ = moved;
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    harness.move_branch("main", &repo.base, &other);
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
    assert_eq!(
        code(&output),
        6,
        "a stale base is a refusal: {}",
        stderr(&output)
    );
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains(&repo.base) && message.contains(&other),
        "both oids have to be in the message, and they are not: {message}"
    );
    assert!(message.contains("stale base"), "{message}");
    // Nothing was published: the refusal is before the write, not after it.
    let listed = ok(
        &harness.run(
            &[
                "change",
                "list",
                "--state",
                "all",
                "--store",
                &harness.store(),
                "--json",
            ],
            None,
        ),
        "change list",
    );
    assert_eq!(listed["count"], 0);
}

#[test]
fn a_store_with_branches_and_none_of_them_yours_is_refused_by_name() {
    let harness = Harness::new();
    let key = harness.key("ada");
    let repo = Repo::new(&harness);
    // The store is a store about another branch entirely.
    let other = {
        let out = Command::new("git")
            .current_dir(&repo.dir)
            .args(["hash-object", "-w", "-t", "blob", "/dev/null"])
            .output()
            .expect("git");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    harness.seed("stable", &other);
    draft(&harness, &repo, &[]);
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
        ],
        None,
    );
    assert_eq!(code(&output), 6);
    let message = stderr(&output);
    assert!(
        message.contains("refs/heads/main") && message.contains("refs/heads/stable"),
        "the refusal names the branch it wanted and the ones it has: {message}"
    );
    let _ = key;
}

#[test]
fn an_unsigned_record_a_missing_store_and_a_bad_handle_are_all_refused() {
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    harness.seed("main", &repo.base);

    // An unsigned record is not published: a signature is what makes a change someone's,
    // and a reader of the format refuses one too.
    let unsigned = harness.write("unsigned.json", b"{\"signatures\":[]}\n");
    let output = harness.run(
        &[
            "change",
            "submit",
            "--record",
            &unsigned,
            "--repository",
            repo.path(),
            "--store",
            &harness.store(),
        ],
        None,
    );
    assert_eq!(code(&output), 6);
    assert!(
        stderr(&output).contains("no signature"),
        "{}",
        stderr(&output)
    );

    // A write has to name its store, so a typo cannot publish somewhere else.
    let output = harness.run(
        &[
            "change",
            "submit",
            "--record",
            "record.json",
            "--repository",
            repo.path(),
        ],
        None,
    );
    assert_eq!(code(&output), 6, "no store named: {}", stderr(&output));

    // An unknown change, and a handle too short to guess from, both say what to do.
    let output = harness.run(
        &["change", "show", "chg-0000", "--store", &harness.store()],
        None,
    );
    assert_eq!(code(&output), 6);
    assert!(stderr(&output).contains("no change matching"));
    let output = harness.run(
        &["change", "show", "chg", "--store", &harness.store()],
        None,
    );
    assert_eq!(code(&output), 6, "a 3-hex handle: {}", stderr(&output));
    let output = harness.run(&["change", "nonsense"], None);
    assert_eq!(code(&output), 2);
}

#[test]
fn the_help_text_and_the_top_level_usage_agree_about_the_verbs() {
    let harness = Harness::new();
    for args in [
        vec!["change"],
        vec!["change", "help"],
        vec!["change", "new", "--help"],
    ] {
        let output = harness.run(&args, None);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        for verb in ["new", "submit", "list", "show"] {
            assert!(text.contains(verb), "{args:?} does not document {verb}");
        }
        assert!(
            text.contains("6 refused"),
            "the exit table is part of the help"
        );
    }
    let usage = harness.run(&["help"], None);
    assert!(stdout(&usage).contains("change submit"));
}

// ---------------------------------------------------------------------------
// a plain git remote, where the fetch promise lives
// ---------------------------------------------------------------------------

/// The remote, the contributor's repository, and the base and head oids.
struct GitRemote {
    /// Held so the server stays up for the length of the test: it is a child process, and
    /// dropping it would take the transport with it.
    _server: SmartHttp,
    repo: PathBuf,
    /// The contributor's repository, one commit ahead of `main`.
    work: PathBuf,
    base: String,
    head: String,
}

/// Serve a bare repository over loopback smart HTTP and set up a contributor's clone of
/// it, one commit ahead. Skips (rather than fails) when `git-http-backend` or python3 is
/// missing, exactly like the attestation suite: the claim being tested needs a real
/// transport, and no fake can make it.
fn git_remote(harness: &Harness) -> Option<GitRemote> {
    let served = harness.path().join("served");
    std::fs::create_dir_all(&served).expect("served dir");
    let repo = served.join("my-repo.git");
    gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");
    common::allow_anonymous_receives(&repo);
    let server = SmartHttp::serve(&served)?;
    let url = server.url("my-repo");

    let work = harness.path().join("work");
    std::fs::create_dir_all(&work).expect("work dir");
    git(&work, &["init", "-q", "-b", "main"]);
    git(&work, &["config", "user.email", "owner@example.org"]);
    git(&work, &["config", "user.name", "Owner"]);
    std::fs::write(work.join("base.txt"), "base\n").expect("file");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-q", "-m", "Initial"]);
    let base = git(&work, &["rev-parse", "HEAD"]);
    git(&work, &["push", "-q", &url, "HEAD:refs/heads/main"]);
    // The contributor's proposal, on a branch of their own clone of the same repository.
    git(&work, &["checkout", "-q", "-b", "feature"]);
    std::fs::create_dir_all(work.join(".github/workflows")).expect("workflows");
    std::fs::write(
        work.join(".github/workflows/ci.yml"),
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make\n",
    )
    .expect("workflow");
    std::fs::write(work.join("extra.txt"), "proposed\n").expect("file");
    git(&work, &["add", "extra.txt"]);
    git(&work, &["commit", "-q", "-m", "Propose the extra file"]);
    let head = git(&work, &["rev-parse", "HEAD"]);
    harness.config(&format!(
        "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \"origin\"\
         \nurl = \"{url}\"\n\n[remote.options]\nwork-dir = \"{}\"\nref-cache-ttl = \"0s\"\n",
        harness.path().join("mirror").display()
    ));
    Some(GitRemote {
        _server: server,
        repo,
        work,
        base,
        head,
    })
}

#[test]
fn a_change_reaches_a_plain_git_remote_and_a_stranger_fetches_it() {
    let harness = Harness::new();
    harness.key("ada");
    let Some(remote) = git_remote(&harness) else {
        eprintln!("skipped: python3 or git-http-backend is not available");
        return;
    };
    let work = remote.work.to_str().expect("utf-8");
    let output = harness.run(
        &[
            "change",
            "new",
            "--repository",
            work,
            "--base",
            "main",
            "--out",
            "r.json",
        ],
        None,
    );
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    let published = ok(
        &harness.run(
            &[
                "change",
                "submit",
                "--record",
                "r.json",
                "--repository",
                work,
                "--remote",
                "origin",
                "--json",
            ],
            None,
        ),
        "submit to a git remote",
    );
    let change_id = published["change"].as_str().unwrap().to_string();
    assert_eq!(published["base"]["check"], "ok", "{published}");
    assert_eq!(published["base"]["oid"], tagged(&remote.base));
    assert_eq!(
        published["objects"]["form"], "git-packfile",
        "a git store takes git objects, and the commits come over with them"
    );
    assert!(published["objects"]["bytes"].as_u64().unwrap() > 0);

    // The remote itself now advertises the change and holds the commits — which is the
    // promise a reviewer lives on: one `git fetch`, no gitiup, no second protocol.
    let refs = git(&remote.repo, &["for-each-ref", "--format=%(refname)"]);
    assert!(
        refs.contains(&format!("refs/changes/{change_id}/head"))
            && refs.contains(&format!("refs/changes/{change_id}/attempt/0")),
        "the change is advertised on the remote: {refs}"
    );
    assert!(
        refs.contains("refs/heads/main"),
        "the owner's branch is untouched: {refs}"
    );
    let pointer = git(
        &remote.repo,
        &["rev-parse", &format!("refs/changes/{change_id}/head")],
    );
    // The ref's gitiup value is a pointer commit carrying the record; its first parent is
    // the proposed commit, so fetching the ref brings the work too (ADR-0003 D5).
    let parent = git(&remote.repo, &["rev-parse", &format!("{pointer}^1")]);
    assert_eq!(
        parent, remote.head,
        "the pointer commit carries the proposal"
    );
    let carried = git(&remote.repo, &["cat-file", "-p", &remote.head]);
    assert!(carried.contains("Propose the extra file"), "{carried}");
    let pointer_body = git(
        &remote.repo,
        &["show", &format!("{pointer}:gitiup-ref.json")],
    );
    assert!(
        pointer_body.contains(
            published["record_digest"]
                .as_str()
                .unwrap()
                .trim_start_matches("sha256:")
        ),
        "the pointer names the record it carries: {pointer_body}"
    );

    // `list` and `show` read the same store back through the remote, with no --store.
    let listed = ok(
        &harness.run(&["change", "list", "--remote", "origin", "--json"], None),
        "list over a git remote",
    );
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["changes"][0]["change"], change_id.as_str());
    assert_eq!(listed["changes"][0]["head"], tagged(&remote.head));
    assert_eq!(listed["changes"][0]["base_check"], "ok");
    let shown = ok(
        &harness.run(
            &["change", "show", &change_id, "--remote", "origin", "--json"],
            None,
        ),
        "show over a git remote",
    );
    assert_eq!(shown["state"], "open");
    assert_eq!(shown["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(shown["head"], tagged(&remote.head));
}

// ---------------------------------------------------------------------------
// a bucket, when one is available
// ---------------------------------------------------------------------------

/// The same three verbs against a bucket resolved from `gitiup.toml`, gated exactly the
/// way the rest of the live transport is: hermetic by default, real when an endpoint and
/// credentials are named (`ci/host-conformance.sh` does that in CI).
#[test]
#[ignore = "needs a live bucket: GITIUP_S3_LIVE_ENDPOINT + AWS credentials"]
fn a_change_round_trips_a_live_bucket() {
    let endpoint = std::env::var("GITIUP_S3_LIVE_ENDPOINT").expect("an endpoint");
    let bucket =
        std::env::var("GITIUP_S3_LIVE_BUCKET").unwrap_or_else(|_| "gitiup-live-test".into());
    let harness = Harness::new();
    harness.key("ada");
    let repo = Repo::new(&harness);
    harness.config(&format!(
        "[[remote]]\nname = \"bucket\"\nurl = \"s3://{bucket}/change-cli\"\n\n[remote.options]\nendpoint = \"{endpoint}\"\nregion = \"us-east-1\"\nforce-path-style = true\n"
    ));
    draft(&harness, &repo, &[]);
    let published = ok(
        &harness.run(
            &[
                "change",
                "submit",
                "--record",
                "record.json",
                "--repository",
                repo.path(),
                "--remote",
                "bucket",
                "--json",
            ],
            None,
        ),
        "submit to a bucket",
    );
    let change_id = published["change"].as_str().unwrap().to_string();
    assert_eq!(
        published["base"]["check"], "absent",
        "a bucket nobody has pushed branches to has nothing to be stale against, and says so"
    );
    assert_eq!(
        published["objects"]["form"], "raw",
        "a bucket has no git object database, and the difference is in the output"
    );
    let listed = ok(
        &harness.run(&["change", "list", "--remote", "bucket", "--json"], None),
        "list over a bucket",
    );
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["changes"][0]["change"], change_id.as_str());
    assert_eq!(listed["changes"][0]["base_check"], "absent");
    let shown = ok(
        &harness.run(
            &["change", "show", &change_id, "--remote", "bucket", "--json"],
            None,
        ),
        "show over a bucket",
    );
    assert_eq!(shown["head"], tagged(&repo.head));
}

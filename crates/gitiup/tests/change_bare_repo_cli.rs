//! The epic's one sentence, run against a bare repository (giti-b2z).
//!
//! The acceptance criterion for *contribute without a forge — the change is a ref* is a
//! sequence, not a command: a stranger proposes, publishes and re-attempts a change
//! against a store with no forge database in it; a reviewer fetches the change *and its
//! proofs* in one command; the owner merges with a compare-and-swap ref update that
//! refuses a stale base. Every verb file in this crate measures one verb; this file runs
//! the sequence, and runs it twice — once against a directory store and once against a
//! **bare repository** — because the sentence is only worth anything if the two stores
//! answer with the same exit codes.
//!
//! The repository leg is the local one: a bare repo on disk, named by a `file://` remote
//! with `host-type = "git"` ([`remotes::Declared`]). That declaration is what makes a
//! repository addressable from the command line at all: without it a `file://` remote is
//! a directory store, and the fs host and git cannot share a path (gitiup's `refs` is a
//! *file* where git's is a *directory*). The same repository served over smart HTTP is
//! measured in `change_cli.rs`; this leg needs no server, which is why it runs everywhere.
//!
//! ```text
//! stranger  gitiup change new --base main          → draft, signed here
//!           gitiup change submit --remote origin   → pack, record, refs, all CAS
//!           gitiup change new --change <id>        → the next attempt of the same change
//! reviewer  gitiup change checkout <id>            → one fetch: refs/changes/* + refs/attestations/*
//! owner     gitiup change merge <id>               → the branch moves under CAS, then the record
//!           gitiup change merge <id>               → 6: already merged
//!           gitiup change merge <other>            → 6: the base moved, both oids named
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{FsHost, Oid, RefName, RefStore, RefUpdate};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";

/// A config home, a keystore in it, and the binary pointed at both.
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

    fn run<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Output {
        self.run_in(self.path(), args)
    }

    fn run_in<S: AsRef<std::ffi::OsStr>>(&self, dir: &Path, args: &[S]) -> Output {
        let child = Command::new(env!("CARGO_BIN_EXE_gitiup"))
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child.wait_with_output().expect("wait")
    }

    fn key(&self, name: &str) {
        let output = self.run(&["key", "gen", "--name", name]);
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.path().join("gitiup.toml"), text).expect("write gitiup.toml");
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Everything a command said, for an assertion message that has to be reproducible.
fn said(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

/// Assert the exit code, then hand back the parsed `--json` body.
fn ran(output: &Output, want: i32, what: &str) -> Value {
    assert_eq!(
        code(output),
        want,
        "{what} exited {} (want {want}):\n{}",
        code(output),
        said(output)
    );
    json(output)
}

/// The same assertion for a command whose stdout is not JSON (`--bytes`).
fn ran_code(output: &Output, want: i32, what: &str) {
    assert_eq!(code(output), want, "{what}:\n{}", said(output));
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

// ---------------------------------------------------------------------------
// the two stores the sentence has to mean the same thing on
// ---------------------------------------------------------------------------

/// A store the story runs against: a plain directory, or a bare repository.
///
/// The two differ in exactly one flag (`--store` versus `--remote`) and in one promise
/// (only the repository can hand a reviewer git objects). Everything else a command sees
/// is identical, which is what makes [`the_sequence_exits_the_same_way_on_both`] a real
/// comparison rather than a pair of stories.
enum Store {
    /// A directory the fs host fills in; `--store` names it.
    Fs,
    /// A bare repository, served by the plain-git host because the remote says so.
    BareRepo,
}

/// One leg: a store, the contributor's repository, and how to reach the store.
struct Setup {
    harness: Harness,
    /// The store's own path — a directory store's root, or the bare repository.
    store_dir: PathBuf,
    /// The flags every command passes to name the store.
    store_flags: Vec<String>,
    /// Where the changes come from.
    work: PathBuf,
    /// `main`'s commit: the branch point every change forks from.
    base: String,
    /// True for the repository leg: it answers git questions (the branch tip, the
    /// reviewer's fetch) that a directory store refuses.
    repository: bool,
}

impl Setup {
    /// Build the leg. The owner publishes `main` with plain `git push` — or, on a
    /// directory store, with the host API, because that is the only way a directory gets
    /// a branch (publishing branches is the owner's act, never gitiup's invention).
    fn new(kind: Store) -> Setup {
        let harness = Harness::new();
        harness.key("ada");
        let store_dir = harness.path().join(match kind {
            Store::Fs => "store",
            Store::BareRepo => "repo.git",
        });
        let work = harness.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["config", "user.email", "ada@example.org"]);
        git(&work, &["config", "user.name", "Ada"]);
        git(&work, &["config", "commit.gpgsign", "false"]);
        std::fs::create_dir_all(work.join(".github/workflows")).expect("workflows dir");
        std::fs::write(
            work.join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make test\n",
        )
        .expect("workflow");
        std::fs::write(work.join("Makefile"), "all:\n\t@echo one\n").expect("makefile");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "Add the build"]);
        let base = git(&work, &["rev-parse", "HEAD"]);

        let store_flags = match kind {
            Store::Fs => {
                std::fs::create_dir_all(&store_dir).expect("store dir");
                let host = fs_store(&store_dir);
                host.update_ref_cas(&RefUpdate::new(
                    RefName::branch("main").expect("a branch name"),
                    gitiup_host::Expect::Absent,
                    Oid::from_hex(&base).expect("the base"),
                ))
                .expect("publish the branch");
                vec!["--store".to_string(), store_dir.display().to_string()]
            }
            Store::BareRepo => {
                git(harness.path(), &["init", "-q", "--bare", "repo.git"]);
                git(
                    &work,
                    &[
                        "push",
                        "-q",
                        &store_dir.display().to_string(),
                        "main:refs/heads/main",
                    ],
                );
                // The declaration is the whole of what makes this repository a store.
                harness.write_config(&format!(
                    "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \
                     \"origin\"\nurl = \"file://{}\"\n\n[remote.options]\nhost-type = \
                     \"git\"\nref-cache-ttl = \"0s\"\n",
                    store_dir.display()
                ));
                vec!["--remote".to_string(), "origin".to_string()]
            }
        };
        Setup {
            repository: matches!(kind, Store::BareRepo),
            harness,
            store_dir,
            store_flags,
            work,
            base,
        }
    }

    fn is_repository(&self) -> bool {
        self.repository
    }

    fn config_path(&self) -> PathBuf {
        self.harness.path().join("gitiup.toml")
    }

    /// The store's `refs/heads/main`, read back through whatever the store answers to.
    fn main_of_store(&self) -> String {
        if self.is_repository() {
            git(&self.store_dir, &["rev-parse", "refs/heads/main"])
        } else {
            let host = fs_store(&self.store_dir);
            host.get_ref(&RefName::branch("main").expect("a branch"))
                .expect("read the ref")
                .expect("the branch is there")
                .oid
                .hex()
        }
    }
}

fn fs_store(dir: &Path) -> FsHost {
    FsHost::open_or_create(dir).expect("open the fs store")
}

/// A branch of the contributor's repository, one commit ahead of `main`.
fn feature(setup: &Setup, name: &str) -> String {
    git(&setup.work, &["checkout", "-q", "-b", name]);
    std::fs::write(setup.work.join(format!("{name}.txt")), "proposed\n").expect("file");
    git(&setup.work, &["add", "."]);
    git(&setup.work, &["commit", "-q", "-m", "Propose {name}"]);
    git(&setup.work, &["rev-parse", "HEAD"])
}

/// `gitiup change new`, drafting a record for what HEAD proposes against `main`.
///
/// The store is named even for the first draft: `--change` reads the anchor from the
/// store, and a draft that could not be told from a re-attempt would be a guess.
fn draft(setup: &Setup, out: &str, extra: &[&str]) -> Output {
    let args = ["change", "new", "--base", "main", "--out", out, "--json"]
        .iter()
        .chain(extra.iter())
        .copied()
        .collect::<Vec<&str>>();
    let mut all = with(&args, &["-C", setup.work_str()]);
    all.extend(setup.store_flags.iter().cloned());
    setup.harness.run_in(&setup.work, &all)
}

/// `gitiup change submit`, publishing the bytes `new` wrote (which are in the
/// contributor's repository, next to the work they came from).
fn submit(setup: &Setup, record: &str) -> Output {
    setup.harness.run_in(
        &setup.work,
        &with(
            &["change", "submit", "--record", record, "--json"],
            &[
                "-C",
                setup.work_str(),
                setup.store_flags[0].as_str(),
                setup.store_flags[1].as_str(),
            ],
        ),
    )
}

/// `gitiup change <verb> …` against this store.
fn verb(setup: &Setup, args: &[&str]) -> Output {
    let mut all: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    all.extend(setup.store_flags.iter().cloned());
    setup.harness.run(&all)
}

/// `gitiup change merge …`, proved from the contributor's repository, which is the
/// checkout that holds both ends of the fast-forward.
fn merge(setup: &Setup, id: &str, extra: &[&str]) -> Output {
    let mut args = with(
        &["change", "merge", id, "--json"],
        &["-C", setup.work_str()],
    );
    args.extend(setup.store_flags.iter().cloned());
    args.extend(extra.iter().map(|flag| flag.to_string()));
    setup.harness.run_in(&setup.work, &args)
}

impl Setup {
    fn work_str(&self) -> &str {
        self.work.to_str().expect("utf-8")
    }

    fn store_str(&self) -> &str {
        self.store_dir.to_str().expect("utf-8")
    }
}

/// `args` plus trailing flags, as one owned list.
fn with(args: &[&str], extra: &[&str]) -> Vec<String> {
    args.iter()
        .chain(extra.iter())
        .map(|arg| arg.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// the sequence
// ---------------------------------------------------------------------------

/// The whole path, one store at a time, with every exit code asserted.
///
/// This is the ticket's acceptance criterion transcribed: propose, publish, re-attempt,
/// merge, and have the second merge and the stale base refuse.
fn the_whole_path(setup: &Setup) {
    // ── a stranger proposes and publishes ────────────────────────────────────────
    let head = feature(setup, "feature");
    let drafted = ran(&draft(setup, "change.json", &[]), 0, "change new");
    assert_eq!(drafted["attempt"], 0);
    assert_eq!(drafted["head"], tagged(&head));

    let publish = submit(setup, "change.json");
    let published = ran(&publish, 0, "change submit");
    let id = published["change"]
        .as_str()
        .expect("a change id")
        .to_string();
    assert_eq!(
        published["base"]["check"],
        "ok",
        "the store has the branch, so the base check is a real check: {}",
        said(&publish)
    );

    let listed = ran(
        &verb(setup, &["change", "list", "--json"]),
        0,
        "change list",
    );
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["changes"][0]["change"], id.as_str());
    assert_eq!(listed["changes"][0]["base_check"], "ok");
    let shown = ran(
        &verb(setup, &["change", "show", &id, "--json"]),
        0,
        "change show",
    );
    assert_eq!(shown["state"], "open");
    assert_eq!(shown["head"], tagged(&head));

    // ── and re-attempts it: same change, new attempt, nothing overwritten ────────
    git(
        &setup.work,
        &["commit", "-q", "--amend", "-m", "Propose feature, amended"],
    );
    let amended = git(&setup.work, &["rev-parse", "HEAD"]);
    let bytes_of_a0 = std::fs::read(setup.work.join("change.json")).expect("attempt 0's bytes");
    ran(
        &draft(setup, "a1.json", &["--change", &id]),
        0,
        "change new --change (the next attempt)",
    );
    let again = submit(setup, "a1.json");
    let again = ran(&again, 0, "change submit (attempt 1)");
    assert_eq!(again["attempt"], 1);
    assert_eq!(
        again["change"].as_str().expect("the same change id"),
        id,
        "a re-attempt continues the change rather than opening a second one"
    );
    let attempts = ran(
        &verb(setup, &["change", "show", &id, "--json"]),
        0,
        "change show after the re-attempt",
    );
    assert_eq!(attempts["attempts"].as_array().expect("two").len(), 2);
    assert_eq!(attempts["attempt"], 1);
    assert_eq!(attempts["head"], tagged(&amended));
    let a0 = verb(setup, &["change", "show", &id, "--attempt", "0", "--bytes"]);
    ran_code(&a0, 0, "change show --attempt 0 --bytes");
    assert_eq!(
        a0.stdout, bytes_of_a0,
        "the first attempt's signed bytes are exactly what was published"
    );

    // ── a second change, open and current, for the stale base below ──────────────
    git(&setup.work, &["checkout", "-q", "main"]);
    feature(setup, "feature-two");
    ran(
        &draft(setup, "two.json", &[]),
        0,
        "change new for the second change",
    );
    let second = submit(setup, "two.json");
    let second_id = ran(&second, 0, "submit the second change")["change"]
        .as_str()
        .expect("a change id")
        .to_string();

    // ── the owner merges: the branch moves under CAS, then the record of it ──────
    let plan = merge(setup, &id, &["--dry-run"]);
    let planned = ran(&plan, 0, "change merge --dry-run");
    assert_eq!(planned["dry_run"], true);
    let merged = ran(&merge(setup, &id, &[]), 0, "change merge");
    assert_eq!(merged["to"], tagged(&amended));
    assert_eq!(merged["moved"], true);
    assert_eq!(merged["via"], "store");
    assert_eq!(
        setup.main_of_store(),
        amended,
        "the branch the record names is the branch the store holds"
    );

    // ── and merges exactly once ──────────────────────────────────────────────────
    let twice = merge(setup, &id, &[]);
    ran_code(&twice, 6, "merging a merged change");
    assert!(
        said(&twice).contains("already merged"),
        "and it says which fact it hit: {}",
        said(&twice)
    );
    let after = ran(
        &verb(setup, &["change", "show", &id, "--json"]),
        0,
        "change show after the merge",
    );
    assert_eq!(after["state"], "merged");

    // ── a stale base is a refusal, with both oids in it, and nothing written ─────
    // The staleness is the ordinary kind: the first change merged, so the second one's
    // base is no longer the branch tip.
    let stale = merge(setup, &second_id, &[]);
    ran_code(&stale, 6, "merging across a moved base");
    let text = said(&stale);
    assert!(
        text.contains(&tagged(&setup.base)) && text.contains(&tagged(&amended)),
        "both oids, spelled the same way, every time:\n{text}"
    );
    assert_eq!(
        setup.main_of_store(),
        amended,
        "and the refusal wrote nothing: the branch is where the merge left it"
    );
    let still_open = ran(
        &verb(setup, &["change", "show", &second_id, "--json"]),
        0,
        "the refused change is still open",
    );
    assert_eq!(still_open["state"], "open");
    assert_eq!(still_open["stale"], true);
}

#[test]
fn the_whole_path_against_a_bare_repository() {
    let setup = Setup::new(Store::BareRepo);
    assert!(setup.is_repository());
    the_whole_path(&setup);
}

#[test]
fn the_whole_path_against_a_directory_store() {
    let setup = Setup::new(Store::Fs);
    assert!(!setup.is_repository());
    the_whole_path(&setup);
}

#[test]
fn the_sequence_exits_the_same_way_on_both() {
    // The other half of the criterion: not "both stores work" but "both stores answer
    // alike", refusals included. One script, two stores, one exit code per line.
    let script: &[(&str, &[&str], i32)] = &[
        (
            "a handle that matches nothing",
            &["change", "show", "ab"],
            6,
        ),
        ("a verb that does not exist", &["change", "frobnicate"], 2),
        (
            "a change the store has never heard of",
            &["change", "show", "chg-deadbeefdeadbeef"],
            6,
        ),
        (
            "merging a change that is not there",
            &["change", "merge", "chg-deadbeefdeadbeef"],
            6,
        ),
        (
            "a state that is not one",
            &["change", "list", "--state", "wibble", "--json"],
            2,
        ),
    ];
    let fs = Setup::new(Store::Fs);
    let repo = Setup::new(Store::BareRepo);
    for (what, args, want) in script {
        let on_fs = code(&verb(&fs, args));
        let on_repo = code(&verb(&repo, args));
        assert_eq!(
            on_fs, on_repo,
            "{what}: the directory store said {on_fs}, the repository said {on_repo}"
        );
        assert_eq!(on_fs, *want, "{what}");
    }
    // And a write that names no store: with a default remote configured, that remote is
    // the store the operator chose, and `submit` publishes there and says so; with
    // nothing configured, there is no store and the refusal is by name.
    feature(&fs, "parity");
    feature(&repo, "parity");
    ran(
        &draft(&fs, "rec.json", &[]),
        0,
        "draft the record (directory store)",
    );
    let unnamed_fs = fs.harness.run_in(
        &fs.work,
        &[
            "change",
            "submit",
            "--record",
            "rec.json",
            "-C",
            fs.work_str(),
        ],
    );
    ran_code(
        &unnamed_fs,
        6,
        "submit with no store named and nothing configured",
    );
    assert!(
        said(&unnamed_fs).contains("no store was named"),
        "{}",
        said(&unnamed_fs)
    );
    ran(
        &draft(&repo, "rec.json", &[]),
        0,
        "draft the record (repository)",
    );
    let named = with(
        &["change", "submit", "--record", "rec.json", "--json"],
        &["-C", repo.work_str()],
    );
    let unnamed_repo = repo.harness.run_in(&repo.work, &named);
    let published_anyway = ran(&unnamed_repo, 0, "submit to the configured default remote");
    assert_eq!(
        published_anyway["store"], "remote 'origin' (the configured default)",
        "a default remote is a decision the operator made, and the output says so"
    );
}

#[test]
fn a_configured_default_remote_is_the_store_an_unnamed_submit_publishes_to() {
    // Stated as its own test because the help text used to promise the opposite, and a
    // script reading it would have branched the wrong way.
    let setup = Setup::new(Store::BareRepo);
    feature(&setup, "feature");
    ran(&draft(&setup, "change.json", &[]), 0, "change new");
    let output = setup.harness.run_in(
        &setup.work,
        &[
            "change",
            "submit",
            "--record",
            "change.json",
            "--json",
            "-C",
            setup.work_str(),
        ],
    );
    let body = ran(&output, 0, "submit with no --remote");
    assert!(
        body["store"]
            .as_str()
            .unwrap_or_default()
            .contains("the configured default"),
        "{}",
        said(&output)
    );
    let listed = ran(
        &verb(&setup, &["change", "list", "--json"]),
        0,
        "the change is in the default store",
    );
    assert_eq!(listed["count"], 1);
}

// ---------------------------------------------------------------------------
// the reviewer's one command, and the store that cannot answer it
// ---------------------------------------------------------------------------

/// A reviewer's clone of the store: what `checkout` needs, and what a stranger with a
/// clone of the repository actually is.
fn clone_of(setup: &Setup) -> PathBuf {
    git(
        setup.harness.path(),
        &["clone", "-q", setup.store_str(), "review"],
    );
    let clone = setup.harness.path().join("review");
    std::fs::copy(setup.config_path(), clone.join("gitiup.toml")).expect("the same remote");
    clone
}

#[test]
fn a_reviewer_fetches_the_change_and_its_proofs_in_one_command() {
    let setup = Setup::new(Store::BareRepo);
    feature(&setup, "feature");
    ran(&draft(&setup, "change.json", &[]), 0, "change new");
    let published = ran(&submit(&setup, "change.json"), 0, "change submit");
    let id = published["change"]
        .as_str()
        .expect("a change id")
        .to_string();
    let head = git(&setup.work, &["rev-parse", "HEAD"]);

    let clone = clone_of(&setup);
    let output = setup.harness.run_in(
        &clone,
        &["change", "checkout", &id, "--remote", "origin", "--json"],
    );
    let body = ran(&output, 0, "change checkout in a clone");
    assert_eq!(body["change"], id.as_str());
    assert_eq!(body["head"], tagged(&head));
    // One fetch, two prefixes: the change and the attestations about its head.
    let fetch = body["fetch"]["prefixes"]
        .as_array()
        .expect("which prefixes the one fetch covered")
        .iter()
        .map(|ref_| ref_.as_str().expect("a ref name").to_string())
        .collect::<Vec<String>>()
        .join(" ");
    assert!(
        fetch.contains(&format!("refs/changes/{id}/")),
        "the change came with the fetch: {fetch}"
    );
    assert!(
        fetch.contains(&format!("refs/attestations/{head}/")),
        "so did the prefix its proofs live under: {fetch}"
    );
    assert_eq!(
        git(&clone, &["rev-parse", &format!("refs/heads/{id}")]),
        head,
        "the reviewer's branch is the proposed commit"
    );
}

#[test]
fn a_directory_store_refuses_the_reviewers_command_by_name() {
    // The same command, on the store with no git object database: refused, and told
    // which verbs do answer. Asserted beside the success above so that the difference
    // stays a named limit rather than a surprise.
    let setup = Setup::new(Store::Fs);
    feature(&setup, "feature");
    ran(&draft(&setup, "change.json", &[]), 0, "change new");
    let published = ran(&submit(&setup, "change.json"), 0, "change submit");
    let id = published["change"]
        .as_str()
        .expect("a change id")
        .to_string();
    let output = setup.harness.run_in(
        &setup.work,
        &["change", "checkout", &id, "--store", setup.store_str()],
    );
    ran_code(&output, 6, "change checkout against a directory store");
    let text = said(&output);
    assert!(
        text.contains("change show") || text.contains("verify change"),
        "and it names the verbs that do work against this store:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// naming a repository where a directory store was meant
// ---------------------------------------------------------------------------

#[test]
fn a_repository_named_as_a_directory_store_is_refused_with_the_fix() {
    let setup = Setup::new(Store::BareRepo);
    let repo = setup.store_str();

    // `--store` names a directory store, and a repository is not one.
    let store = setup.harness.run(&["change", "list", "--store", repo]);
    ran_code(&store, 6, "--store at a repository");
    let text = said(&store);
    assert!(text.contains("git repository"), "{text}");
    assert!(
        text.contains("host-type") && text.contains("\"git\""),
        "the refusal has to carry the fix: {text}"
    );

    // The same repository named by a `file://` remote with nothing said about it.
    let config = setup.config_path();
    let declared = std::fs::read_to_string(&config).expect("the config");
    std::fs::write(&config, declared.replace("host-type = \"git\"\n", ""))
        .expect("drop the declaration");
    let remote = setup.harness.run(&["change", "list", "--remote", "origin"]);
    ran_code(&remote, 6, "a file:// remote at a repository, undeclared");
    let text = said(&remote);
    assert!(text.contains("git repository"), "{text}");
    assert!(
        text.contains("host-type"),
        "and it says what to declare: {text}"
    );

    // `gitiup doctor --remotes` says the same thing, because it asks the same question.
    let doctor = setup.harness.run(&["doctor", "--remotes"]);
    ran_code(&doctor, 6, "the doctor on the undeclared repository");
    assert!(
        said(&doctor).contains("host-type") && said(&doctor).contains("git repository"),
        "{}",
        said(&doctor)
    );

    // Put the declaration back and the same remote is a store.
    std::fs::write(&config, declared).expect("put the declaration back");
    let ok = setup.harness.run(&["doctor", "--remotes"]);
    ran_code(&ok, 0, "the doctor once the remote says what it is");
    assert!(said(&ok).contains("[git]"), "{}", said(&ok));
}

#[test]
fn a_host_type_off_the_list_is_refused_with_the_list() {
    let setup = Setup::new(Store::BareRepo);
    let config = setup.config_path();
    let text = std::fs::read_to_string(&config).expect("the config");
    std::fs::write(
        &config,
        text.replace("host-type = \"git\"", "host-type = \"gitea\""),
    )
    .expect("declare a host that does not exist");
    let output = setup.harness.run(&["change", "list", "--remote", "origin"]);
    ran_code(&output, 2, "a host-type that is not one of ours");
    let said = said(&output);
    assert!(said.contains("gitea"), "{said}");
    for kind in ["fs", "git", "s3", "github"] {
        assert!(said.contains(kind), "the refusal lists {kind}: {said}");
    }
}

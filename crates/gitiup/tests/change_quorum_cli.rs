//! `gitiup change submit` opening its quorum rounds, run as the real binary (giti-zp1.2).
//!
//! The ticket's acceptance criteria are command lines, so they are tested as command lines
//! against the built executable, in the shape every quorum test uses: a real keystore (the
//! author and every volunteer is a real key), a real `fs` store as the store, a real roster
//! the owner signed, and a real `gitiup-policy-1` published to it — because the whole point
//! of the ticket is that a round's numbers come from *that signed document* and not from a
//! flag.
//!
//! Four things are asserted on purpose, because each is a failure mode the ticket names:
//!
//! * one round per job per matrix arm, published and advertised — the automatic half of
//!   "five random users per PR";
//! * the author's *whole* key family out of every round, checked from the store's own bytes;
//! * `--no-quorum` opting out, and saying so;
//! * an unfilled `n` reported as `sufficient: false` with the filter reasons, `n` itself
//!   untouched, and the round published anyway rather than quietly shrunk.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{Expect, FsHost, Oid, RefName, RefQuery, RefStore, RefUpdate};
use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// What every volunteer in this file claims, and what every policy in this file asks for
/// unless a test says otherwise.
const ARCH: &str = "x86_64";

/// A config home, a store directory, a repository, and the binary pointed at all three.
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

    fn file(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }

    /// Run the binary with this home. The working directory is the temp dir, so a
    /// `gitiup.toml` is only found if a test wrote one, and `SSH_AUTH_SOCK` points where it
    /// cannot exist so no test can depend on the developer's agent.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_POLICY")
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

    fn new_key(&self, name: &str) -> String {
        let output = self.run(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
        name.to_string()
    }

    fn key_id(&self, name: &str) -> String {
        let output = self.run(&["key", "show", name, "--json"], None);
        json(&output)["key_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no key id for {name}: {}", stderr(&output)))
            .to_string()
    }

    /// A volunteer's honest claim, filed for the owner's eyes.
    fn register(&self, name: &str, arch: &str) -> String {
        self.register_extra(name, arch, &[])
    }

    fn register_extra(&self, name: &str, arch: &str, extra: &[&str]) -> String {
        self.new_key(name);
        let signup = self.file(&format!("{name}.signup"));
        let mut args = vec![
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
            arch,
            "--out",
            signup.as_str(),
        ];
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        assert!(
            output.status.success(),
            "participant register failed: {}",
            stderr(&output)
        );
        signup
    }

    /// Carry sign-ups into a new published epoch at one tier.
    fn approve(&self, store: &str, from: &[String], tier: &str) -> Value {
        let mut args: Vec<&str> =
            vec!["participant", "approve", "--key", "owner", "--store", store];
        for path in from {
            args.push("--from");
            args.push(path);
        }
        args.extend_from_slice(&["--tier", tier, "--publish", "--json"]);
        let output = self.run(&args, None);
        assert!(
            output.status.success(),
            "participant approve --tier {tier} failed: {}",
            stderr(&output)
        );
        json(&output)
    }

    /// Publish a policy into the store, signed by `owner`.
    ///
    /// `quorum` is `serde_json::Null` for a policy that asks for nothing but a `local` proof;
    /// otherwise it is the block verbatim, because that block is the ticket's whole
    /// "the numbers are data the owner signed" claim.
    fn publish_policy(&self, store: &str, quorum: Value) -> Value {
        let path = self.file("policy.json");
        let mut document = json!({
            "type": "gitiup-policy-1",
            "schema_version": 1,
            "owner": { "key_id": self.key_id("owner"), "principal": "Ada Hale" },
            "revision": 1,
            "previous_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "effective_from_us": 1,
            "protects": ["refs/heads/**"],
            "rules": {
                "allowed_tiers": ["quorum"],
                "trust_key_ids": [self.key_id("owner")],
            },
        });
        if quorum.is_null() {
            document["rules"]["allowed_tiers"] = json!(["local"]);
        } else {
            document["quorum"] = quorum;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(&document).expect("json")).expect("write");
        let output = self.run(
            &[
                "policy", "publish", &path, "--store", store, "--key", "owner", "--json",
            ],
            None,
        );
        ok(&output, "policy publish")
    }

    /// The store's own refs under a prefix, as sorted strings.
    fn refs(&self, store: &str, prefix: &str) -> Vec<String> {
        let host = FsHost::open_or_create(store).expect("open the store");
        let mut names: Vec<String> = host
            .list_refs(&RefQuery::prefix(prefix))
            .expect("list refs")
            .into_iter()
            .map(|named| named.name.as_str().to_string())
            .collect();
        names.sort();
        names
    }

    /// Seed `refs/heads/main` — the owner's act, and the only way a change's base can be
    /// what the store has.
    fn seed(&self, store: &str, branch: &str, base: &str) {
        let host = FsHost::open_or_create(store).expect("open the store");
        host.update_ref_cas(&RefUpdate::new(
            RefName::branch(branch).expect("a branch name"),
            Expect::Absent,
            Oid::from_hex(base).expect("an oid"),
        ))
        .expect("publish the branch");
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON on stdout, got {:?} ({e}); stderr: {}",
            stdout(output),
            stderr(output)
        )
    })
}

fn ok(output: &Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} should succeed ({}): {}{}",
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
        "{what} should be refused with exit 6, got {}: {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    format!("{}{}", stdout(output), stderr(output))
}

/// The repository the change comes from. `jobs` is the workflow's `jobs:` block, so a test
/// can say "a two-arm matrix" instead of describing one.
struct Repo {
    dir: PathBuf,
    base: String,
    head: String,
}

impl Repo {
    /// `None` writes no workflow file at all, which is how a test asks what a submit does
    /// when the only job hint is the record's.
    fn new(harness: &Harness, workflow: Option<&str>) -> Repo {
        let dir = harness.path().join("work");
        std::fs::create_dir_all(dir.join(".github/workflows")).expect("workflows dir");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["config", "user.email", "ada@example.org"]);
        git(&dir, &["config", "user.name", "Ada"]);
        git(&dir, &["config", "commit.gpgsign", "false"]);
        if let Some(workflow) = workflow {
            std::fs::write(dir.join(".github/workflows/ci.yml"), workflow).expect("workflow");
        }
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

/// Two jobs, one of them a two-arm matrix: three rounds, three seeds.
const MATRIX_WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        target: [linux-x86_64, linux-aarch64]
    steps:
      - run: make target=${{ matrix.target }}
  lint:
    runs-on: ubuntu-24.04
    steps:
      - run: make lint
";

/// One job, no matrix.
const PLAIN_WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - run: make
";

/// The `quorum` block of the fixture policies: 5 seats, 4 agreements, one per identity, and
/// the capabilities every volunteer in this file claims to have.
fn quorum_block() -> Value {
    json!({
        "default": {
            "max_per_identity": 1,
            "n": 5,
            "required_agree": 4,
            "reserves": 2,
            "tier_caps": { "anonymous": 1, "endorsed": 5, "trusted": 1 },
            "tier_floor": "anonymous"
        },
        "requirements": {
            "arch": ARCH,
            "ram_mb": 8192,
            "disk_mb": 51200,
            "sandboxes": ["docker"],
            "min_sandbox_level": 1
        }
    })
}

/// The one-owner scene: an `owner` key, an author with **two** boxes on the epoch (the case
/// ADR-0002 D4 is about), and five volunteers.
struct Scene {
    harness: Harness,
    store: String,
    /// The key the change is signed with.
    author: String,
    /// The author's second box, anchored on the author's principal.
    author_second: String,
    /// Every volunteer's key id.
    volunteer_ids: Vec<String>,
    /// Which keystore name the change is signed with (and so which key is the author).
    author_key: String,
}

impl Scene {
    fn new() -> Scene {
        Scene::with_arch(ARCH)
    }

    /// Every volunteer registers for `arch`, which is how a test makes a round that cannot
    /// fill its seats: a policy that asks for a machine nobody has.
    fn with_arch(arch: &str) -> Scene {
        let harness = Harness::new();
        harness.new_key("owner");
        let store = harness.store();
        let author_signup = harness.register("author", ARCH);
        let author_id = harness.key_id("author");
        let second_signup =
            harness.register_extra("author-laptop", ARCH, &["--identity", &author_id]);
        let volunteers = ["v1", "v2", "v3", "v4", "v5"];
        let signups: Vec<String> = volunteers
            .iter()
            .map(|name| harness.register(name, arch))
            .collect();
        harness.approve(&store, &[author_signup, second_signup], "endorsed");
        harness.approve(&store, &signups, "endorsed");
        Scene {
            volunteer_ids: volunteers.iter().map(|name| harness.key_id(name)).collect(),
            author_second: harness.key_id("author-laptop"),
            author: author_id,
            author_key: "author".to_string(),
            harness,
            store,
        }
    }

    /// Publish the fixture policy and submit the change, returning the `--json` report.
    fn submit(&self, repo: &Repo, extra: &[&str]) -> Value {
        ok(
            &self.harness.run(
                &self
                    .submit_args(repo, extra)
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
                None,
            ),
            "change submit",
        )
    }

    /// Same, without asserting success: the refusals are tests too.
    fn try_submit(&self, repo: &Repo, extra: &[&str]) -> Output {
        self.harness.run(
            &self
                .submit_args(repo, extra)
                .iter()
                .map(String::as_str)
                .collect::<Vec<&str>>(),
            None,
        )
    }

    fn submit_args(&self, repo: &Repo, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "change".to_string(),
            "submit".to_string(),
            "--repository".to_string(),
            repo.path().to_string(),
            "--base".to_string(),
            "main".to_string(),
            "--key".to_string(),
            self.author_key.clone(),
            "--store".to_string(),
            self.store.clone(),
            "--json".to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    }

    /// Publish the fixture policy into this scene's store.
    fn publish_policy(&self, quorum: Value) -> Value {
        self.harness.publish_policy(&self.store, quorum)
    }

    /// Every round ref the store holds.
    fn rounds(&self) -> Vec<String> {
        self.harness.refs(&self.store, "refs/gitiup/round")
    }

    /// Every job advertisement the store holds.
    fn advertisements(&self) -> Vec<String> {
        self.harness.refs(&self.store, "refs/gitiup/job")
    }

    /// Re-derive one published round the way an auditor does — no key, no opinion.
    fn audit(&self, change: &str, job: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "select".to_string(),
            "--change".to_string(),
            change.to_string(),
            "--job".to_string(),
            job.to_string(),
            "--store".to_string(),
            self.store.clone(),
            "--json".to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        self.harness.run(
            &args.iter().map(String::as_str).collect::<Vec<&str>>(),
            None,
        )
    }
}

/// A contributor's machine: the policy published, the repository ready, `main` seeded in the
/// store so a base check can pass.
fn staged(scene: &Scene, workflow: Option<&str>) -> Repo {
    scene.publish_policy(quorum_block());
    let repo = Repo::new(&scene.harness, workflow);
    scene.harness.seed(&scene.store, "main", &repo.base);
    repo
}

// ---------------------------------------------------------------------------
// one round per job, from the planner
// ---------------------------------------------------------------------------

/// The acceptance criterion, first half: a submit under a quorum policy publishes one round
/// per job, and a matrix is one round per arm — each with its own seed, because one seed for
/// two architectures would be one jury asked to judge machines one of them cannot run on.
#[test]
fn a_submit_opens_one_round_per_job_and_per_matrix_arm() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(MATRIX_WORKFLOW));
    let report = scene.submit(&repo, &[]);
    assert_eq!(report["quorum"]["state"], "opened");
    assert_eq!(report["quorum"]["demanded"], true);
    let rounds = report["quorum"]["rounds"].as_array().expect("rounds");
    let jobs: Vec<&str> = rounds
        .iter()
        .map(|round| round["job"].as_str().expect("a job id"))
        .collect();
    assert_eq!(
        jobs,
        vec![
            "build/matrix/linux-aarch64",
            "build/matrix/linux-x86_64",
            "lint"
        ],
        "the job set is the planner's, arms included, in id order"
    );
    assert_eq!(
        scene.rounds().len(),
        3,
        "one round per arm, all of them in the store"
    );
    let mut seeds: Vec<&str> = rounds
        .iter()
        .map(|round| round["seed"].as_str().expect("a published seed"))
        .collect();
    seeds.sort();
    seeds.dedup();
    assert_eq!(seeds.len(), 3, "three rounds, three seeds");
    for round in rounds {
        assert_eq!(round["n"], 5, "the seat count is the policy's");
        assert_eq!(round["required_agree"], 4);
        assert_eq!(round["attempt"], 0, "attempt 0 is the change's first");
        assert_eq!(round["inputs"]["head_oid"], format!("sha1:{}", repo.head));
        assert_eq!(round["sufficient"], true, "five volunteers, five seats");
        assert_eq!(round["seats"].as_array().expect("seats").len(), 5);
        assert!(
            round["advertised"].is_string(),
            "a filled round is advertised, or no volunteer will ever find it"
        );
        assert!(round["rechecked"] == Value::Bool(true));
    }
    // The rounds are the store's, not just the command's: an auditor with no key at all gets
    // the same seats back out of them.
    let audit = scene.audit(report["change"].as_str().unwrap(), "lint", &[]);
    let audited = ok(&audit, "select --audit");
    assert_eq!(audited["mode"], "audit");
    assert_eq!(audited["selected"].as_array().unwrap().len(), 5);
    assert_eq!(scene.advertisements().len(), 3);
}

/// A round id names the change and the attempt it belongs to, in the store's own ref layout.
#[test]
fn a_round_ref_names_the_change_the_job_and_the_attempt() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let report = scene.submit(&repo, &[]);
    let change = report["change"].as_str().unwrap();
    assert_eq!(
        scene.rounds(),
        vec![format!("refs/gitiup/round/{change}/build/0")]
    );
    assert_eq!(
        scene.advertisements(),
        vec![format!("refs/gitiup/job/{change}/build")]
    );
}

/// Re-publishing the same attempt's bytes does not open a second quorum for it: one job,
/// one round per attempt is the property the seed exists to make impossible, and a retried
/// command has to land on "already", not on a second jury.
#[test]
fn republishing_an_attempt_does_not_reopen_its_rounds() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let draft = scene.harness.run(
        &[
            "change",
            "new",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--key",
            scene.author_key.as_str(),
            "--out",
            "record.json",
        ],
        None,
    );
    assert!(draft.status.success(), "{}", stderr(&draft));
    let submit = |extra: &[&str]| {
        let mut args = vec![
            "change",
            "submit",
            "--record",
            "record.json",
            "--repository",
            repo.path(),
            "--key",
            scene.author_key.as_str(),
            "--store",
            &scene.store,
            "--json",
        ];
        args.extend_from_slice(extra);
        ok(&scene.harness.run(&args, None), "change submit --record")
    };
    let first = submit(&[]);
    let again = submit(&[]);
    assert_eq!(again["already"], true, "the attempt was already filed");
    let rounds = again["quorum"]["rounds"].as_array().expect("rounds");
    assert_eq!(rounds.len(), 1);
    assert_eq!(
        rounds[0]["already"], true,
        "the round was found published, not reopened"
    );
    assert_eq!(
        rounds[0]["round_digest"], first["quorum"]["rounds"][0]["round_digest"],
        "the same round, not a second one for the same attempt"
    );
    assert_eq!(scene.rounds().len(), 1, "and still one round in the store");
}

/// A new commit is a new attempt, and a new attempt gets its own rounds — with its own seed,
/// because the head oid is a seed input (ADR-0002 D2), which is what stops an author pushing
/// until they draw a friendly jury.
#[test]
fn a_new_attempt_gets_its_own_round_at_its_own_attempt() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let first = scene.submit(&repo, &[]);
    assert_eq!(first["attempt"], 0);
    std::fs::write(repo.dir.join("second.txt"), "again\n").expect("file");
    git(&repo.dir, &["add", "second.txt"]);
    git(&repo.dir, &["commit", "-q", "-m", "Amend the proposal"]);
    let second = scene.submit(&repo, &["--change", first["change"].as_str().unwrap()]);
    assert_eq!(second["attempt"], 1, "the amended head is attempt 1");
    let round = &second["quorum"]["rounds"][0];
    assert_eq!(round["attempt"], 1, "and so is its round");
    assert_eq!(
        round["inputs"]["head_oid"],
        format!("sha1:{}", git(&repo.dir, &["rev-parse", "HEAD"])),
        "the round pins the head it was opened for"
    );
    let change = first["change"].as_str().unwrap();
    assert_eq!(
        scene.rounds(),
        vec![
            format!("refs/gitiup/round/{change}/build/0"),
            format!("refs/gitiup/round/{change}/build/1")
        ],
        "attempt 0's round stays where it is, for the attestations it already has"
    );
}

// ---------------------------------------------------------------------------
// the author is out of the pool, and so is every box of theirs
// ---------------------------------------------------------------------------

/// The author's second box is the acceptance criterion: a roster entry that is eligible, is
/// anchored on the author's principal, and must not be seated anywhere — checked from the
/// store's own bytes, not from what this command meant to exclude.
#[test]
fn the_author_and_their_second_box_are_out_of_every_round() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(MATRIX_WORKFLOW));
    let report = scene.submit(&repo, &[]);
    for round in report["quorum"]["rounds"].as_array().expect("rounds") {
        let seats: Vec<&str> = round["seats"]
            .as_array()
            .expect("seats")
            .iter()
            .map(|seat| seat["key_id"].as_str().expect("a key id"))
            .collect();
        assert!(
            !seats.contains(&scene.author.as_str()),
            "the author may not referee their own change"
        );
        assert!(
            !seats.contains(&scene.author_second.as_str()),
            "naming one key has to reach the whole family: the author's other box was seated"
        );
        let family: Vec<&str> = round["author_family"]
            .as_array()
            .expect("a family")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(family.contains(&scene.author.as_str()));
        assert!(family.contains(&scene.author_second.as_str()));
        // The exclusion is in the signed inputs, so an auditor re-derives the same rule.
        for key in [&scene.author, &scene.author_second] {
            assert!(
                round["inputs"]["exclusions"]
                    .as_array()
                    .expect("exclusions")
                    .iter()
                    .any(|excluded| excluded == key),
                "{} is not excluded from the round that names it",
                short(key)
            );
        }
        // The exclusion is why five seats filled from six eligible entries: the author's two
        // boxes were on the roster and eligible until the rule took them out.
        assert_eq!(round["eligible"], 5);
        assert_eq!(round["rejected_by_filter"]["excluded"], 2);
    }
    // And `--proposer` against the published round is an exit 0: the same check, from the
    // outside.
    let change = report["change"].as_str().unwrap();
    let audit = scene.audit(change, "lint", &["--proposer", "author"]);
    ok(&audit, "select --proposer author");
}

/// Every volunteer's key id is on the roster as `endorsed`, so the seats are exactly them.
#[test]
fn the_seats_are_the_rosters_and_nobody_eligible_is_left_out() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let report = scene.submit(&repo, &[]);
    let round = &report["quorum"]["rounds"][0];
    let mut seated: Vec<&str> = round["seats"]
        .as_array()
        .expect("seats")
        .iter()
        .map(|seat| seat["key_id"].as_str().expect("a key id"))
        .collect();
    let mut expected: Vec<&str> = scene.volunteer_ids.iter().map(String::as_str).collect();
    seated.sort();
    expected.sort();
    assert_eq!(seated, expected, "five seats, five volunteers, one each");
}

// ---------------------------------------------------------------------------
// --no-quorum
// ---------------------------------------------------------------------------

/// Opting out is opt-in loud: the change publishes, no round exists, and the output says the
/// change is therefore unverifiable until somebody opens one.
#[test]
fn no_quorum_publishes_the_change_and_opens_nothing() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let report = scene.submit(&repo, &["--no-quorum"]);
    assert_eq!(report["quorum"]["state"], "declined");
    assert_eq!(
        report["quorum"]["demanded"], true,
        "the policy still demanded one — that is what the flag opted out of"
    );
    assert!(scene.rounds().is_empty(), "no round was published");
    assert!(scene.advertisements().is_empty());
    assert_eq!(report["state"], "open", "the change itself published");
    // And it is said out loud, not only in the machine output: a person who forgot the flag
    // (or remembered it when they should not have) has to be able to see what they did.
    let other = Scene::new();
    let other_repo = staged(&other, Some(PLAIN_WORKFLOW));
    let text = other.harness.run(
        &[
            "change",
            "submit",
            "--repository",
            other_repo.path(),
            "--base",
            "main",
            "--key",
            "author",
            "--store",
            &other.store,
            "--no-quorum",
        ],
        None,
    );
    let text = stdout(&text);
    assert!(
        text.contains("--no-quorum") && text.contains("verify change"),
        "the opt-out, and what it costs, are both printed: {text}"
    );
}

// ---------------------------------------------------------------------------
// a policy that does not ask, or cannot be applied
// ---------------------------------------------------------------------------

/// A `local`-only policy asks for nothing: the change publishes, no round is opened, and the
/// report says which policy decided that.
#[test]
fn a_policy_that_allows_no_quorum_opens_no_round() {
    let scene = Scene::new();
    scene.publish_policy(Value::Null);
    let repo = Repo::new(&scene.harness, Some(PLAIN_WORKFLOW));
    scene.harness.seed(&scene.store, "main", &repo.base);
    let report = scene.submit(&repo, &[]);
    assert_eq!(report["quorum"]["state"], "not-required");
    assert!(
        report["quorum"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("quorum"),
        "the reason names the tier that is missing"
    );
    assert!(scene.rounds().is_empty());
    assert_eq!(report["state"], "open");
}

/// A policy this machine does not trust is reported and never applied (ADR-0004 D3). The
/// store is the same; only the submitter's trust roots differ, which is the fork case: the
/// rules are upstream's signed rules, and this machine cannot vouch for them.
#[test]
fn an_untrusted_policy_is_reported_and_never_applied() {
    let scene = Scene::new();
    let repo = staged(&scene, Some(PLAIN_WORKFLOW));
    let stranger = Harness::new();
    stranger.new_key("stranger");
    let output = stranger.run(
        &[
            "change",
            "submit",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--key",
            "stranger",
            "--store",
            &scene.store,
            "--json",
        ],
        None,
    );
    // The record is signed by `stranger`, so the change id differs from the scene's author —
    // and the change publishes, because a change is not gated on a policy nobody trusts.
    let report = ok(&output, "a stranger's submit");
    assert_eq!(report["quorum"]["state"], "not-required");
    assert!(
        report["quorum"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("signer_untrusted"),
        "the report says whose policy it refused to apply: {:?}",
        report["quorum"]["reason"]
    );
    assert!(scene.rounds().is_empty(), "no round was opened on trust");
}

// ---------------------------------------------------------------------------
// a quorum that cannot be filled, and a quorum that cannot be opened
// ---------------------------------------------------------------------------

/// The ticket's third criterion: an `n` that cannot be filled is `sufficient: false` with
/// the reasons the eligibility filters gave, the round is published anyway, and `n` is not
/// quietly lowered to make the round look filled.
#[test]
fn a_round_that_cannot_fill_its_seats_reports_insufficient_and_names_the_filters() {
    // The roster signed up for x86_64; the policy asks for a machine nobody has.
    let scene = Scene::new();
    let mut block = quorum_block();
    block["requirements"]["arch"] = json!("aarch64");
    scene.publish_policy(block);
    let repo = Repo::new(&scene.harness, Some(PLAIN_WORKFLOW));
    scene.harness.seed(&scene.store, "main", &repo.base);
    let report = scene.submit(&repo, &[]);
    let round = &report["quorum"]["rounds"][0];
    assert_eq!(round["sufficient"], false);
    assert_eq!(
        round["n"], 5,
        "the round still asks for five: nobody lowered it to make the answer look better"
    );
    assert_eq!(
        round["inputs"]["policy"]["n"], 5,
        "and the signed inputs say the same"
    );
    assert_eq!(round["seats"].as_array().expect("seats").len(), 0);
    assert_eq!(
        round["rejected_by_filter"]["arch"], 5,
        "the filter that emptied the pool is named, with its count"
    );
    assert_eq!(round["rejected_by_filter"]["excluded"], 2);
    assert!(
        round["advertised"].is_null(),
        "an unfilled round is not advertised: recruiting for a quorum that cannot happen is \
         worse than escalating"
    );
    assert_eq!(scene.rounds().len(), 1, "and it is published all the same");
}

/// The same round in the words a person acts on, rather than in JSON: which filter emptied
/// the pool, and the fact that `n` was left alone.
#[test]
fn an_unfilled_round_says_which_filters_rejected_whom() {
    let scene = Scene::new();
    let mut block = quorum_block();
    block["requirements"]["arch"] = json!("aarch64");
    scene.publish_policy(block);
    let repo = Repo::new(&scene.harness, Some(PLAIN_WORKFLOW));
    scene.harness.seed(&scene.store, "main", &repo.base);
    let text = stdout(&scene.harness.run(
        &[
            "change",
            "submit",
            "--repository",
            repo.path(),
            "--base",
            "main",
            "--key",
            "author",
            "--store",
            &scene.store,
            "--explain",
        ],
        None,
    ));
    assert!(text.contains("`n` was not lowered"), "{text}");
    assert!(text.contains("arch ×5"), "the filters are named: {text}");
    assert!(
        text.contains("excluded ×2"),
        "and so is the author's family: {text}"
    );
    assert!(
        text.contains("NOT FILLED"),
        "the round is labelled, not buried: {text}"
    );
    assert!(
        text.contains("audit table"),
        "--explain prints the audit table: {text}"
    );
    assert!(
        text.contains("not advertised"),
        "and says there is nothing being advertised: {text}"
    );
}

/// A store whose policy demands a quorum and which publishes no roster cannot fill one, and
/// saying "submitted!" would be the silent failure this whole design exists to avoid. Nothing
/// is written, including the change.
#[test]
fn a_demanded_quorum_with_no_roster_is_refused_before_anything_is_written() {
    let harness = Harness::new();
    harness.new_key("owner");
    let store = harness.store();
    harness.publish_policy(&store, quorum_block());
    let scene = Scene {
        harness,
        store,
        author: String::new(),
        author_second: String::new(),
        volunteer_ids: Vec::new(),
        author_key: "owner".to_string(),
    };
    let repo = Repo::new(&scene.harness, Some(PLAIN_WORKFLOW));
    scene.harness.seed(&scene.store, "main", &repo.base);
    let output = scene.try_submit(&repo, &[]);
    let text = refused(&output, "a submit with no roster to select from");
    assert!(text.contains("no roster"), "{text}");
    assert!(
        scene.harness.refs(&scene.store, "refs/changes").is_empty(),
        "the refusal came before the change was written"
    );
    assert!(scene.rounds().is_empty());
}

/// The same rule for the numbers themselves: a policy that demands a quorum and names no
/// `quorum.requirements` cannot be seated, so it is refused where it is read.
#[test]
fn a_quorum_policy_with_no_requirements_is_refused() {
    let scene = Scene::new();
    let mut block = quorum_block();
    block
        .as_object_mut()
        .expect("an object")
        .remove("requirements");
    scene.publish_policy(block);
    let repo = Repo::new(&scene.harness, Some(PLAIN_WORKFLOW));
    scene.harness.seed(&scene.store, "main", &repo.base);
    let text = refused(
        &scene.try_submit(&repo, &[]),
        "a submit whose policy names no requirements",
    );
    assert!(text.contains("quorum.requirements"), "{text}");
    assert!(scene.harness.refs(&scene.store, "refs/changes").is_empty());
}

/// A matrix value that cannot be a ref component is refused with the workflow file named,
/// rather than half-published and then failing in the store.
#[test]
fn a_job_id_that_cannot_be_a_ref_component_is_refused() {
    let scene = Scene::new();
    scene.publish_policy(quorum_block());
    let repo = Repo::new(
        &scene.harness,
        Some(
            "name: CI\non: [push]\njobs:\n  build:\n    strategy:\n      matrix:\n        target: [\"..\"]\n    steps:\n      - run: make\n",
        ),
    );
    scene.harness.seed(&scene.store, "main", &repo.base);
    let text = refused(
        &scene.try_submit(&repo, &[]),
        "a submit whose matrix arm is not a ref",
    );
    assert!(text.contains("ci.yml"), "the file is named: {text}");
    assert!(scene.rounds().is_empty());
}

/// With no workflow file the record's own hint is the job set, and a record that asked for
/// nothing gets a refusal instead of a quorum guessed out of thin air.
#[test]
fn with_no_workflow_the_records_hint_is_the_job_set() {
    let scene = Scene::new();
    scene.publish_policy(quorum_block());
    let repo = Repo::new(&scene.harness, None);
    scene.harness.seed(&scene.store, "main", &repo.base);
    let report = scene.submit(&repo, &["--job", "package"]);
    let jobs: Vec<&str> = report["quorum"]["rounds"]
        .as_array()
        .expect("rounds")
        .iter()
        .map(|round| round["job"].as_str().expect("a job"))
        .collect();
    assert_eq!(
        jobs,
        vec!["package"],
        "--job is the record's hint, and the hint is what a round is opened for"
    );
}

/// A record that asked for nothing to be re-run cannot be verified by anybody, so a policy
/// that demands a quorum is refused rather than answered with an empty set of rounds.
#[test]
fn a_quorum_with_no_job_to_open_is_refused() {
    let scene = Scene::new();
    scene.publish_policy(quorum_block());
    let repo = Repo::new(&scene.harness, None);
    scene.harness.seed(&scene.store, "main", &repo.base);
    let text = refused(
        &scene.try_submit(&repo, &["--no-jobs"]),
        "a submit with no job to open a round for",
    );
    assert!(text.contains("no job"), "{text}");
    assert!(scene.rounds().is_empty());
    assert!(
        scene.harness.refs(&scene.store, "refs/changes").is_empty(),
        "and the change was not published in front of the refusal"
    );
}

/// A short key id for a message, because a fingerprint in an assertion failure is unreadable.
fn short(key_id: &str) -> String {
    let body = key_id.strip_prefix("SHA256:").unwrap_or(key_id);
    format!("SHA256:{}…", &body[..4])
}

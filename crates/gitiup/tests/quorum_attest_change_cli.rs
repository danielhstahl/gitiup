//! A `tier: quorum` attestation as merge evidence, end to end (giti-zp1.5).
//!
//! [`quorum_attest_cli.rs`](quorum_attest_cli) proves the two halves of the ticket
//! separately: a document is made only from a verdict, and it is believed only by
//! re-derivation. This file is where they meet — `gitiup verify change`, the question a
//! `pre-receive` hook actually asks:
//!
//! ```text
//! gitiup quorum verdict … --attest store        (the store now holds the round, the
//!                                                submissions, and the attestation that
//!                                                summarises them)
//! gitiup verify change <id> --policy …          → 0, accepted through the quorum tier
//! ```
//!
//! Three things are asserted here that no other test can assert in one piece.
//!
//! * **The attestation is about *this* head.** The round, the seats and the change record
//!   all name the same commit, and the document is advertised under it, so what the gate
//!   accepts is evidence about the thing it is being asked to merge.
//! * **The seats are what carry it.** `min_signatures` is a question about how many
//!   distinct identities certified the result, so the counted seats count — not the one
//!   key that filed the summary. A quorum attestation signed by a friendly key and no
//!   evidence is refused at the other end, and this end does not let it in sideways.
//! * **A policy that does not name the tier is not satisfied by it.** Same store, same
//!   document, different `allowed_tiers`: refused. The gate does not decide the owner's
//!   tier policy for them.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::GitOid;
use gitiup_host::{Expect, FsHost, Oid, RefName, RefStore, RefUpdate};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use serde_json::{Value, json};

const PASSPHRASE: &str = "four random words";
/// The job the change's workflow declares and the round is opened for.
const JOB: &str = "build";
/// The seed `sample::owner_key()` is derived from: the selector, the roster's issuer and
/// the key that asserts the attestation are all this one.
const OWNER_SEED: [u8; 32] = [1u8; 32];

struct Scene {
    dir: tempfile::TempDir,
    now: String,
    head: String,
    change: String,
}

impl Scene {
    /// A real change in a real store: a git repository with a proposed commit, the change
    /// record published, a roster the owner signed, and one round for the job whose every
    /// seat is filled and agreeing.
    fn new() -> Scene {
        let dir = tempfile::tempdir().expect("a temp home");
        let harness = Harness::new(&dir);
        harness.seed_key("owner", OWNER_SEED);
        let owner = sample::owner_key();

        // --- a repository with a base and one proposed commit --------------------
        let repo = dir.path().join("work");
        std::fs::create_dir_all(&repo).expect("work dir");
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["config", "user.email", "owner@example.org"]);
        git(&repo, &["config", "user.name", "Owner"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::create_dir_all(repo.join(".github/workflows")).expect("workflows");
        std::fs::write(
            repo.join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make\n",
        )
        .expect("workflow");
        std::fs::write(repo.join("Makefile"), "all:\n\t@echo one\n").expect("makefile");
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "Add the build"]);
        let base = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(repo.join("extra.txt"), "proposed\n").expect("file");
        git(&repo, &["add", "extra.txt"]);
        git(&repo, &["commit", "-q", "-m", "Propose the extra file"]);
        let hex = git(&repo, &["rev-parse", "HEAD"]);
        let head = format!("sha1:{hex}");
        seed_branch(&harness.store(), "main", &base);

        // --- the change, submitted ----------------------------------------------
        let record = harness.run(&[
            "change",
            "new",
            "--repository",
            repo.to_str().expect("utf-8"),
            "--base",
            "main",
            "--title",
            "Propose the extra file",
            "--key",
            "owner",
            "--out",
            "record.json",
        ]);
        assert!(
            record.status.success(),
            "`change new`: {}{}",
            stdout(&record),
            stderr(&record)
        );
        let submitted = harness.run(&[
            "change",
            "submit",
            "--record",
            "record.json",
            "--repository",
            repo.to_str().expect("utf-8"),
            "--store",
            &harness.store(),
            "--json",
        ]);
        assert!(
            submitted.status.success(),
            "`change submit`: {}{}",
            stdout(&submitted),
            stderr(&submitted)
        );
        let change = json(&submitted)["change"]
            .as_str()
            .expect("a change id")
            .to_string();

        // --- a round for *this* head, with every seat filled ---------------------
        let host = FsHost::open_or_create(harness.store()).expect("open the store");
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("publish the roster");
        let mut inputs = sample::round_inputs(&roster, &change, JOB);
        inputs.head_oid = head.parse::<GitOid>().expect("the head is an oid");
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
        round.sign(&owner).expect("the selector signs");
        store::publish_round(&host, &round).expect("publish the round");
        let round = store::round_at(&host, &change, JOB, 0)
            .expect("read the round")
            .expect("the round is open");
        let seats = sample::indices_of(&round);
        let docs = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(seats[position]).public_key().key_id();
            store::publish_submission(&host, &round, &key_id, doc).expect("the seat is filled");
        }

        Scene {
            dir,
            now: sample::clock().to_rfc3339(),
            head,
            change,
        }
    }

    fn harness(&self) -> Harness {
        Harness::new(&self.dir)
    }

    /// `gitiup quorum verdict … --attest store`: the only way a document like this exists.
    fn attest(&self) -> Output {
        let store = self.harness().store();
        let now = self.now.clone();
        self.harness().run(&[
            "quorum",
            "verdict",
            &self.change,
            "--job",
            JOB,
            "--store",
            &store,
            "--now",
            &now,
            "--attest",
            "store",
            "--key",
            "owner",
            "--json",
        ])
    }

    /// A policy file that accepts nothing but the quorum tier. The operator's own `--policy`
    /// is gate-eligible without a signature (ADR-0004 D4), which is what lets a test say
    /// "the policy in force" without publishing a whole revision history.
    fn policy(&self, tiers: &[&str]) -> String {
        let path = self.dir.path().join(if tiers.contains(&"quorum") {
            "quorum-policy.json"
        } else {
            "local-policy.json"
        });
        // The operator's own policy file, which is the flat attestation policy (the
        // signed `gitiup-policy-1` document is what an *owner* publishes; the file a
        // gate passes with `--policy` is the local reading of it, and ADR-0004 D4 makes
        // it gate-eligible on its own).
        let document = json!({
            "schema_version": 1,
            "allowed_tiers": tiers,
            "min_signatures": 1,
        });
        std::fs::write(&path, document.to_string()).expect("write the policy");
        path.to_str().expect("utf-8").to_string()
    }

    /// `gitiup verify change`, with the clock pinned to the moment the evidence claims.
    fn verify(&self, policy: &str) -> Output {
        let store = self.harness().store();
        let now = self.now.clone();
        self.harness().run(&[
            "verify",
            "change",
            &self.change,
            "--store",
            &store,
            "--trust",
            "owner",
            "--now",
            &now,
            "--policy",
            policy,
            "--json",
        ])
    }
}

struct Harness {
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(dir: &tempfile::TempDir) -> Harness {
        Harness {
            dir: dir.path().to_path_buf(),
        }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn store(&self) -> String {
        self.path()
            .join("store")
            .to_str()
            .expect("utf-8")
            .to_string()
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_POLICY")
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

    fn seed_key(&self, name: &str, seed: [u8; 32]) {
        let path = self.path().join(format!("{name}.seed"));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        let mut child = command
            .args([
                "key",
                "import",
                "seed",
                path.to_str().expect("utf-8"),
                "--name",
                name,
                "--passphrase-file",
                "-",
            ])
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .current_dir(self.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(format!("{PASSPHRASE}\n").as_bytes())
            .expect("write the passphrase");
        let output = child.wait_with_output().expect("wait");
        assert!(
            output.status.success(),
            "`key import seed {name}` failed: {}",
            stderr(&output)
        );
    }
}

/// A branch is the owner's fact, which nothing in gitiup publishes: the test writes it
/// with the host API, exactly as `change_cli.rs` does.
fn seed_branch(store: &str, branch: &str, hex: &str) {
    let host = FsHost::open_or_create(store).expect("open the fs store");
    host.update_ref_cas(&RefUpdate::new(
        RefName::branch(branch).expect("a branch name"),
        Expect::Absent,
        Oid::from_hex(hex).expect("an oid"),
    ))
    .expect("publish the branch");
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
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("the process was signalled: {}", stderr(output)))
}
fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the report is JSON on stdout")
}
fn clean(output: &Output) -> Value {
    assert_eq!(stderr(output).trim(), "", "a verdict goes to stdout only");
    json(output)
}
/// The outcome of one named change-level check.
fn check(value: &Value, wanted: &str) -> String {
    value["checks"]
        .as_array()
        .expect("every report prints its checks")
        .iter()
        .find(|row| row["code"] == wanted)
        .map(|row| row["outcome"].as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| panic!("no check named {wanted} in {value}"))
}

fn reasons(value: &Value) -> Vec<String> {
    value["reasons"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|reason| reason["code"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_quorum_attestation_carries_the_change_the_policy_asks_a_quorum_for() {
    let scene = Scene::new();
    let emitted = scene.attest();
    let emitted = clean(&emitted);
    assert_eq!(emitted["state"], "verified", "{emitted}");

    let policy = scene.policy(&["quorum"]);
    let output = scene.verify(&policy);
    let value = clean(&output);
    assert_eq!(code(&output), 0, "{value}");
    // `accepted` is the one word a hook branches on; the section that carried it is the
    // quorum attestation, judged by re-derivation and named by its own block.
    assert_eq!(value["accepted"], true, "{value}");
    assert_eq!(check(&value, "min_signatures"), "passed");
    let sections = value["attestations"].as_array().expect("sections");
    assert_eq!(sections.len(), 1, "{value}");
    let quorum = &sections[0];
    assert_eq!(quorum["verdict"], "pass", "{value}");
    assert_eq!(quorum["quorum"]["tier"], "quorum");
    assert_eq!(quorum["quorum"]["state"], "verified");
    assert_eq!(quorum["quorum"]["head"], scene.head);
    assert_eq!(quorum["quorum"]["job"], JOB);
    assert_eq!(quorum["quorum"]["agreeing"], 5);
    // The change's own `quorum` check is passed, and says where the answer came from: no
    // verdict *record* was filed for this change at all.
    assert_eq!(check(&value, "quorum"), "passed");
    assert_eq!(value["quorum"].as_array().map(Vec::len), Some(0));
}

#[test]
fn a_policy_that_does_not_name_the_tier_is_not_carried_by_it() {
    let scene = Scene::new();
    let emitted = scene.attest();
    assert_eq!(
        code(&emitted),
        0,
        "{}{}",
        stdout(&emitted),
        stderr(&emitted)
    );
    // The same store, the same document, and a policy that accepts only `local`: the
    // quorum tier is the owner's to ask for, and this one did not.
    let policy = scene.policy(&["local"]);
    let output = scene.verify(&policy);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert_eq!(value["accepted"], false, "{value}");
    assert!(reasons(&value).contains(&"tier".to_string()), "{value}");
}

#[test]
fn nothing_travels_to_the_next_head() {
    let scene = Scene::new();
    let emitted = scene.attest();
    assert_eq!(
        code(&emitted),
        0,
        "{}{}",
        stdout(&emitted),
        stderr(&emitted)
    );
    // A second proposal on the same branch, one commit on. The attestation is still in
    // the store, advertised under the head it was drawn against, where it stays somebody
    // else's proof: a verdict is bound to the head it was computed from.
    let repo = scene.dir.path().join("work");
    std::fs::write(repo.join("extra.txt"), "proposed again\n").expect("file");
    git(&repo, &["add", "extra.txt"]);
    git(&repo, &["commit", "-q", "-m", "Propose a second version"]);
    let record = scene.harness().run(&[
        "change",
        "new",
        "--repository",
        repo.to_str().expect("utf-8"),
        "--base",
        "main",
        "--title",
        "Propose the second version",
        "--key",
        "owner",
        "--out",
        "second.json",
    ]);
    assert!(
        record.status.success(),
        "{}{}",
        stdout(&record),
        stderr(&record)
    );
    let submitted = scene.harness().run(&[
        "change",
        "submit",
        "--record",
        "second.json",
        "--repository",
        repo.to_str().expect("utf-8"),
        "--store",
        &scene.harness().store(),
        "--json",
    ]);
    assert!(
        submitted.status.success(),
        "{}{}",
        stdout(&submitted),
        stderr(&submitted)
    );
    let second = json(&submitted)["change"]
        .as_str()
        .expect("a change id")
        .to_string();
    assert_ne!(second, scene.change);

    let policy = scene.policy(&["quorum"]);
    let store = scene.harness().store();
    let now = scene.now.clone();
    let output = scene.harness().run(&[
        "verify", "change", &second, "--store", &store, "--trust", "owner", "--now", &now,
        "--policy", &policy, "--json",
    ]);
    let value = clean(&output);
    assert_eq!(
        code(&output),
        6,
        "a new head has to earn its own quorum: {value}"
    );
    assert_eq!(value["accepted"], false);
    assert!(
        value["attestations"]
            .as_array()
            .is_none_or(|list| list.is_empty()),
        "nothing is advertised for a head nobody proved: {value}"
    );
}

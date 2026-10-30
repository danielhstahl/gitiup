//! `gitiup policy check` and `gitiup policy explain` (giti-91m.3).
//!
//! The ticket's promise is a command line, a rule list, and the same exit codes
//! `gitiup verify` already uses, so that is what is tested here: the real binary, a real
//! store, real signed documents, real git commits, and stdout/stderr asserted on every
//! run. Three things the tests are deliberately strict about:
//!
//! * **The clock is pinned** (`--now`), because freshness is a window against the reader
//!   and a test that let it run would pass today and fail next month.
//! * **The exit code is the contract** — 0 accepted, 6 refused, 7 bad signature, 8 digest
//!   mismatch — and it is asserted on stdout with an empty stderr every time, because a
//!   `pre-receive` hook pipes stdout into a log and shows stderr to a person.
//! * **The first failing rule must be the reason.** D7's order is only useful if a reader
//!   can rely on it, so one test asserts it directly on a refusal, and the digest- and
//!   signature-mismatch tests assert the integrity failure outranks the authority failure
//!   it causes rather than being reported beside it.
//!
//! The harness is the merge gate's own (`verify_change_cli.rs`), because the strongest
//! statement `policy explain change` can make is that it *is* that assessment: one test
//! runs both commands on the same store and asserts they cannot disagree.

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::{AttestationDoc, Digest, GitOid, SignatureEntry, SigningKey};
use gitiup_host::{Expect, FsHost, Oid, RefName, RefStore, RefUpdate};
use gitiup_quorum::store as quorum_store;
use gitiup_quorum::verdict::{CountedVote, QuorumState, ReasonCode, VerdictRecord};
use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// A moment inside every freshness window, after the fixtures' claimed time.
const NOW: &str = "2026-10-27T09:30:00Z";
/// Early enough to be in force for the fixtures' claimed time of 09:15:02Z.
const EFFECTIVE: &str = "2026-10-27T00:00:00Z";

/// A config home with keys, a store, and a change submitted to it.
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

    /// Run the binary with this home: cwd is the temp dir (so a stray `gitiup.toml` or
    /// `gitiup-policy.json` cannot leak in), and the agent is pointed where it cannot
    /// exist so no test can depend on the developer's ssh-agent.
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

    /// A generated keystore key, and its key id.
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
        self.key_id(name)
    }

    /// Import a *known* seed, so the test process and the CLI hold the same key. The
    /// quorum verdict is signed in-process (there is no CLI for it yet), which needs a
    /// key both sides can use.
    fn seed_key(&self, name: &str, seed: [u8; 32]) -> String {
        let path = self.path().join(format!("{name}.seed"));
        // The seed file is hex text (what `gitiup key gen --export-seed` would write),
        // not raw bytes.
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let output = self.run(
            &[
                "key",
                "import",
                "seed",
                &path.display().to_string(),
                "--name",
                name,
                "--passphrase-file",
                "-",
            ],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key import seed {name}` failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        self.key_id(name)
    }

    fn key_id(&self, name: &str) -> String {
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

    /// The owner's rule, published: `local` proofs from `ada`/`runner`/`co`.
    fn publish_policy(&self, extra: &[&str]) -> Value {
        let store = self.store();
        let mut args = vec![
            "policy",
            "publish",
            "--store",
            &store,
            "--key",
            "ada",
            "--principal",
            "Ada",
            "--allow-tier",
            "local",
            "--trust",
            "ada",
            "--trust",
            "runner",
            "--trust",
            "co",
            "--effective-from",
            EFFECTIVE,
            "--json",
        ];
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        assert!(
            output.status.success(),
            "policy publish failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)
    }

    /// Publish a policy document written by the test (the flag-built form cannot name a
    /// quorum block, and the quorum tests need one).
    fn publish_document(&self, name: &str, document: Value, extra: &[&str]) -> Value {
        let path = self.file(name);
        let store = self.store();
        std::fs::write(&path, document.to_string()).expect("write the policy document");
        let mut args = vec![
            "policy",
            "publish",
            &path,
            "--store",
            &store,
            "--key",
            "ada",
            "--principal",
            "Ada",
            "--trust",
            "ada",
            "--trust",
            "runner",
            "--effective-from",
            EFFECTIVE,
            "--json",
        ];
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        assert!(
            output.status.success(),
            "publishing {name} failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)
    }

    /// The owner's rules with a quorum block, which the flag form cannot build.
    fn quorum_policy(&self) -> Value {
        self.publish_document(
            "quorum-policy.json",
            json!({
                "type": "gitiup-policy-1",
                "schema_version": 1,
                "owner": { "key_id": "", "principal": "Ada" },
                "revision": 1,
                "previous_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "effective_from_us": 0,
                "protects": ["refs/heads/**"],
                "rules": {
                    "allowed_tiers": ["local", "quorum"],
                    "trust_key_ids": [self.key_id("runner")],
                    "min_signatures": 1,
                },
                "quorum": { "default": {
                    "n": 3, "reserves": 1, "required_agree": 2,
                    "tier_floor": "anonymous",
                    "tier_caps": { "trusted": 1, "endorsed": 1, "anonymous": 3 },
                    "max_per_identity": 1,
                } },
            }),
            &[],
        )
    }

    /// A run report naming `head` as its commit: the fixture's own facts, about the
    /// commit this change proposes.
    fn report(&self, fixture: &str, head: &str) -> String {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-attest/tests/fixtures/runs")
            .join(fixture)
            .join("run.json");
        let text = std::fs::read_to_string(&source).expect("the fixture run report");
        let mut report: Value = serde_json::from_str(&text).expect("the fixture is JSON");
        report["commit"] = format!("sha1:{head}").into();
        let path = self.file(&format!("{fixture}-{}.json", &head[..8]));
        std::fs::write(&path, report.to_string()).expect("write the run report");
        path
    }

    /// Sign one run report with `key` and file it in the store, as `gitiup attest push`
    /// does. Returns the push report, whose `digest` is the store's content address.
    fn push(&self, fixture: &str, key: &str, head: &str) -> Value {
        let report = self.report(fixture, head);
        let out = self.file(&format!("{fixture}-{key}.doc"));
        let output = self.run(
            &[
                "attest",
                "push",
                "--run-report",
                &report,
                "--sign",
                "--key",
                key,
                "--store",
                &self.store(),
                "--out",
                &out,
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "push {fixture} by {key} failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)
    }

    /// The bytes `push --out` wrote.
    fn document(&self, fixture: &str, key: &str) -> AttestationDoc {
        let bytes = std::fs::read(self.file(&format!("{fixture}-{key}.doc"))).expect("the doc");
        AttestationDoc::from_canonical_bytes(&bytes).expect("the pushed document is canonical")
    }

    /// File bytes the test already holds (a mutated document no CLI would produce) at
    /// their own digest, the way `attest push` does.
    fn file_document(&self, name: &str, doc: &AttestationDoc) -> Value {
        let path = self.file(name);
        std::fs::write(&path, doc.canonical_bytes().expect("canonical")).expect("write");
        let output = self.run(
            &["attest", "push", &path, "--store", &self.store(), "--json"],
            None,
        );
        assert!(
            output.status.success(),
            "push {name} failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)
    }

    /// `gitiup policy check`, with the same contract asserted: the verdict is on stdout
    /// (exit 0/6/7/8 all of them) and stderr stays empty, because a `pre-receive` hook
    /// pipes stdout into a log and shows stderr to a human.
    fn check(&self, extra: &[&str]) -> (u8, Value, String) {
        let store = self.store();
        let mut args = vec![
            "policy", "check", "--store", &store, "--trust", "ada", "--now", NOW,
        ];
        args.extend_from_slice(extra);
        self.verdict(&args)
    }

    /// `gitiup policy explain …`, same contract. `--trust ada` is added by the caller
    /// when the subject is a document, because a document may be judged with no store.
    fn explain(&self, extra: &[&str]) -> (u8, Value, String) {
        let args: Vec<&str> = std::iter::once("policy")
            .chain(std::iter::once("explain"))
            .chain(extra.iter().copied())
            .collect();
        self.verdict(&args)
    }

    /// `gitiup verify change`, for the test that asserts the two commands cannot part
    /// ways about the same store.
    fn verify(&self, change: &str, extra: &[&str]) -> (u8, Value, String) {
        let store = self.store();
        let mut args = vec![
            "verify", "change", change, "--store", &store, "--trust", "ada", "--now", NOW,
        ];
        args.extend_from_slice(extra);
        self.verdict(&args)
    }

    fn verdict(&self, args: &[&str]) -> (u8, Value, String) {
        let output = self.run(args, None);
        let code = code(&output);
        assert!(
            matches!(code, 0 | 6 | 7 | 8),
            "exit {code} is not a verdict on `{} …`: {}{}",
            args[..2].join(" "),
            stdout(&output),
            stderr(&output)
        );
        assert_eq!(
            stderr(&output),
            "",
            "a verdict leaves stderr empty (exit {code})"
        );
        let text = stdout(&output);
        let value: Value = if args.contains(&"--json") {
            serde_json::from_str(&text).expect("the --json output is JSON")
        } else {
            Value::Null
        };
        (code, value, text)
    }

    /// The store's `refs/heads/main`, which nothing in gitiup publishes: a branch is the
    /// owner's fact, so the test writes it with the host API (as `change_cli.rs` does).
    fn seed(&self, branch: &str, base: &str) {
        let host = FsHost::open_or_create(self.store()).expect("open the fs store");
        let oid = Oid::from_hex(base).expect("an oid");
        host.update_ref_cas(&RefUpdate::new(
            RefName::branch(branch).expect("a branch name"),
            Expect::Absent,
            oid,
        ))
        .expect("publish the branch");
    }
}

/// A change, submitted: `main` at one commit, `feature` one ahead, and the store holding
/// both.
struct Change {
    id: String,
    /// `sha1:<hex>` as the record spells it.
    head: String,
    /// The head without the prefix, for building run reports.
    hex: String,
}

fn change(h: &Harness) -> Change {
    let repo = h.path().join("work");
    std::fs::create_dir_all(&repo).expect("work dir");
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "user.email", "ada@example.org"]);
    git(&repo, &["config", "user.name", "Ada"]);
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
    let head = git(&repo, &["rev-parse", "HEAD"]);
    h.seed("main", &base);

    let new = h.run(
        &[
            "change",
            "new",
            "--repository",
            repo.to_str().expect("utf-8"),
            "--base",
            "main",
            "--title",
            "Propose the extra file",
            "--key",
            "ada",
            "--out",
            "record.json",
        ],
        None,
    );
    assert!(
        new.status.success(),
        "change new failed: {}{}",
        stdout(&new),
        stderr(&new)
    );
    let submitted = h.run(
        &[
            "change",
            "submit",
            "--record",
            "record.json",
            "--repository",
            repo.to_str().expect("utf-8"),
            "--store",
            &h.store(),
            "--json",
        ],
        None,
    );
    assert!(
        submitted.status.success(),
        "change submit failed: {}{}",
        stdout(&submitted),
        stderr(&submitted)
    );
    let submitted = json(&submitted);
    Change {
        id: submitted["change"]
            .as_str()
            .expect("a change id")
            .to_string(),
        head: format!("sha1:{head}"),
        hex: head,
    }
}

/// Publish a verified quorum verdict for this change, signed by `ada`'s seed.
///
/// There is no CLI for this yet (giti-zp1.4), which is the point: the gate reads what the
/// store carries, and how it got there is somebody else's business.
fn publish_verdict(
    h: &Harness,
    change: &Change,
    job: &str,
    seed: [u8; 32],
    build: impl FnOnce(&mut VerdictRecord),
) {
    let owner = SigningKey::from_seed(&seed);
    let mut verdict = VerdictRecord {
        schema_version: gitiup_quorum::verdict::VERDICT_SCHEMA_VERSION,
        verdict_type: gitiup_quorum::verdict::VERDICT_TYPE.to_string(),
        change_id: change.id.clone(),
        head_oid: change.head.parse::<GitOid>().expect("a head oid"),
        job_id: job.to_string(),
        attempt: 0,
        round_digest: Digest::sha256(b"round"),
        roster_digest: Digest::sha256(b"roster"),
        policy_digest: Digest::sha256(b"policy"),
        state: QuorumState::Verified,
        reason: ReasonCode::AgreementReached,
        detail: "4 of 5 agreeing".to_string(),
        result_digest: Some(Digest::sha256(b"result")),
        seats: 5,
        required_agree: 2,
        agreeing: 2,
        counted: vec![vote("ada"), vote("sofia")],
        divergent: Vec::new(),
        missing: Vec::new(),
        rejected: Vec::new(),
        issued_at_us: 1_793_092_502_500_000,
        signatures: Vec::new(),
    };
    build(&mut verdict);
    verdict.sign(&owner).expect("sign the verdict");
    let host = FsHost::open_or_create(h.store()).expect("open the store");
    quorum_store::publish_verdict(&host, &verdict).expect("publish the verdict");
}

fn vote(name: &str) -> CountedVote {
    CountedVote {
        key_id: format!("SHA256:{name}"),
        identity: name.to_string(),
        result_digest: Digest::sha256(b"result"),
        tier: gitiup_quorum::capability::RosterTier::Trusted,
    }
}

/// The seed the `ada` keystore key is imported from, so the in-process verdict signer and
/// the CLI's `--key ada` are the same key.
const ADA_SEED: [u8; 32] = [0x2au8; 32];
/// A key nothing in the store trusts.
const STRANGER_SEED: [u8; 32] = [0x9eu8; 32];

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> u8 {
    output.status.code().unwrap_or(0) as u8
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

/// The outcome of one change-level check.
fn check(value: &Value, code: &str) -> String {
    value["checks"]
        .as_array()
        .expect("a checks array")
        .iter()
        .find(|check| check["code"].as_str() == Some(code))
        .unwrap_or_else(|| panic!("{code} is not in the checks: {value}"))["outcome"]
        .as_str()
        .expect("an outcome")
        .to_string()
}

/// The reason codes, in the order the report printed them.
fn reason_codes(value: &Value) -> Vec<String> {
    value["reasons"]
        .as_array()
        .expect("a reasons array")
        .iter()
        .map(|reason| reason["code"].as_str().unwrap_or_default().to_string())
        .collect()
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

/// A home with the three identities every test needs.
fn harness() -> Harness {
    let harness = Harness::new();
    // `ada` is imported from a known seed so the test process can sign a quorum verdict
    // with it; `stranger` is imported from another seed no policy ever trusts.
    harness.seed_key("ada", ADA_SEED);
    harness.seed_key("stranger", STRANGER_SEED);
    harness.key("runner");
    harness.key("co");
    harness
}
/// The check codes `gitiup-attest` promises, in order, as a test-side constant so the
/// order is asserted rather than echoed from the implementation.
const CHECK_ORDER: &[&str] = &[
    "structure",
    "digest",
    "commit",
    "result",
    "challenge",
    "normalisation",
    "environment",
    "signature",
    "trust",
    "min_signatures",
    "tier",
    "sandbox",
    "freshness",
    "expiry",
];

/// The subject-level rule codes, in report order.
fn rule_codes(value: &Value) -> Vec<String> {
    value["rules"]
        .as_array()
        .expect("a rule list")
        .iter()
        .map(|rule| rule["rule"].as_str().expect("a rule code").to_string())
        .collect()
}

/// The outcome of one rule, in a subject's `rules` or a proof's `rules`.
fn rule(value: &Value, code: &str) -> String {
    value["rules"]
        .as_array()
        .expect("a rule list")
        .iter()
        .find(|rule| rule["rule"] == code)
        .unwrap_or_else(|| panic!("no rule `{code}` in {}", value["rules"]))["outcome"]
        .as_str()
        .expect("an outcome")
        .to_string()
}

/// The ladder's codes, in the order they were printed.
fn ladder_codes(proof: &Value) -> Vec<String> {
    proof["rules"]
        .as_array()
        .expect("a proof's rules")
        .iter()
        .map(|rule| rule["rule"].as_str().expect("a rule code").to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// `gitiup policy check --commit <oid>`
// ---------------------------------------------------------------------------

#[test]
fn a_commit_the_policy_can_see_is_satisfied_and_the_answer_names_the_combination() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);

    let (code, value, _) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(code, 0, "one trusted local proof: {value}");
    assert_eq!(value["record_type"], "policy-check");
    assert_eq!(value["verdict"], "pass");
    assert_eq!(value["exit"], 0);
    assert_eq!(value["satisfies"], true);
    assert_eq!(value["subject"]["commit"], c.head);

    // Every subject-level rule is there, in the order the module promises, and none of
    // them is missing: a `not_run` line is an honest answer where an absent one is silent.
    assert_eq!(
        rule_codes(&value),
        vec!["policy", "protects", "attestations", "min_signatures"]
    );
    assert_eq!(rule(&value, "policy"), "passed");
    assert_eq!(rule(&value, "protects"), "not_asked");
    assert_eq!(rule(&value, "attestations"), "passed");
    assert_eq!(rule(&value, "min_signatures"), "passed");

    // And the ladder underneath, from the proof's own point of view.
    let proof = &value["attestations"][0];
    assert_eq!(proof["accepted"], true);
    assert_eq!(proof["verdict"], "pass");
    assert_eq!(ladder_codes(proof), CHECK_ORDER, "every rung is printed");
    assert_eq!(rule(proof, "signature"), "passed");
    assert_eq!(rule(proof, "trust"), "passed");
    assert_eq!(rule(proof, "tier"), "passed");

    // The combination it accepted, because "satisfied" that does not say who signed is a
    // claim a reader cannot check.
    assert_eq!(value["accepts"]["via"], "attestations");
    assert_eq!(value["accepts"]["signers"].as_array().unwrap().len(), 1);
}

#[test]
fn quiet_is_one_word_and_the_human_report_says_the_same_thing_as_the_json() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);

    let (code, _, text) = h.check(&["--commit", &c.hex, "--quiet"]);
    assert_eq!(code, 0);
    assert_eq!(text.trim(), "satisfied");

    let (code, _, text) = h.check(&["--commit", &c.hex]);
    assert_eq!(code, 0);
    assert!(text.contains("min_signatures"), "{text}");
    assert!(
        text.contains("distinct trusted signer"),
        "the answer names what it counted: {text}"
    );
}

#[test]
fn nothing_proved_about_the_commit_is_a_refusal_that_names_the_head() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);

    let (code, value, text) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(code, 6, "no proof is a policy refusal: {value}");
    assert_eq!(value["satisfies"], false);
    assert_eq!(value["verdict"], "policy");
    assert_eq!(reason_codes(&value), vec!["attestations"]);
    assert_eq!(rule(&value, "attestations"), "failed");
    // Counting signatures was never possible, so the rule says it did not run rather than
    // pretending it counted zero.
    assert_eq!(rule(&value, "min_signatures"), "not_run");
    assert!(
        text.contains(&c.hex),
        "the refusal has to name what it looked for: {text}"
    );
}

#[test]
fn a_policy_that_gates_another_ref_refuses_before_it_counts_anything() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--protect", "refs/heads/main"]);
    h.push("matrix-build", "runner", &c.hex);

    let (code, value, _) = h.check(&["--commit", &c.hex, "--ref", "refs/heads/feature", "--json"]);
    assert_eq!(code, 6, "the policy does not govern this ref: {value}");
    assert_eq!(rule(&value, "protects"), "failed");
    // The proofs were still read and are still reported — a gate that refuses on `protects`
    // says what it saw on the way, rather than hiding it behind the refusal.
    assert_eq!(rule(&value, "attestations"), "passed");
    let (other, _, _) = h.check(&["--commit", &c.hex, "--ref", "refs/heads/main", "--json"]);
    assert_eq!(other, 0, "the same proof on a ref the policy does gate");
}

#[test]
fn nothing_published_anywhere_is_a_policy_rule_failure_and_nothing_else_ran() {
    let h = harness();
    let c = change(&h);

    let (code, value, _) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(code, 6, "a gate with no rules is a refusal: {value}");
    assert_eq!(value["policy"], Value::Null);
    assert_eq!(
        rule_codes(&value),
        vec!["policy", "protects", "attestations", "min_signatures"]
    );
    assert_eq!(rule(&value, "policy"), "failed");
    assert_eq!(rule(&value, "protects"), "not_run");
    assert_eq!(rule(&value, "attestations"), "not_run");
    assert_eq!(rule(&value, "min_signatures"), "not_run");
    assert_eq!(
        reason_codes(&value),
        vec!["policy"],
        "one reason, and it is the policy: {}",
        value["reasons"]
    );
}

#[test]
fn no_commit_named_is_usage_and_not_a_verdict() {
    let h = harness();
    let output = h.run(&["policy", "check", "--store", &h.store()], None);
    assert_eq!(code(&output), 2, "`check` has to be told what to check");
    assert_eq!(
        stdout(&output),
        "",
        "usage is an error, so it is stderr's business"
    );
    assert!(stderr(&output).contains("--commit"), "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// the exit codes, which are the same ladder `gitiup verify` uses
// ---------------------------------------------------------------------------

#[test]
fn a_proof_about_another_commit_is_exit_eight_and_the_first_failing_rule_is_commit() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    // Filed under this commit, certifying another one: canonical, genuinely signed, wrong
    // binding — which is what 8 means.
    let report = h.file("elsewhere.json");
    std::fs::write(
        &report,
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../gitiup-attest/tests/fixtures/runs/matrix-build/run.json"),
        )
        .expect("the fixture"),
    )
    .expect("write");
    h.run(
        &[
            "attest",
            "push",
            "--run-report",
            &report,
            "--subject",
            &c.hex,
            "--sign",
            "--key",
            "runner",
            "--store",
            &h.store(),
            "--json",
        ],
        None,
    );

    let (code, value, _) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(code, 8, "{value}");
    assert_eq!(value["exit"], 8);
    assert_eq!(reason_codes(&value), vec!["commit"]);
    // D7's ordering is the contract: the integrity failure outranks the authority question
    // it causes, so the first failure *is* the exit code and not one of its symptoms.
    assert_eq!(value["reasons"][0]["code"], "commit");
    let proof = &value["attestations"][0];
    assert_eq!(rule(proof, "commit"), "failed");
    // The ladder evaluates every rung rather than short-circuiting, which is what lets a
    // reader see that the signature is genuine and the *binding* is the problem. The
    // order is what makes the first failure the exit code, not a first-failure stop.
    assert_eq!(rule(proof, "signature"), "passed");
    assert_eq!(proof["exit"], 8);
}

#[test]
fn a_bad_signature_is_exit_seven_and_outranks_the_trust_it_breaks() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);
    let mut doc = h.document("matrix-build", "runner");
    let stranger = SigningKey::from_seed(&STRANGER_SEED);
    let mut entry =
        SignatureEntry::new(&stranger, &doc.signature_message().expect("message")).expect("sign");
    entry.key_id = h.key_id("runner");
    doc.signatures.clear();
    doc.signatures.push(entry);
    h.file_document("tampered.doc", &doc);

    let (code, value, _) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(
        code, 7,
        "a bad signature is a verdict, not a policy opinion: {value}"
    );
    assert_eq!(value["verdict"], "bad_signature");
    assert_eq!(reason_codes(&value)[0], "signature");
    // The good proof beside the forged one really did reach the policy's number, and the
    // rule says so; what the report withholds is `accepts`, because a store holding a
    // forged attestation is not one a merge may rest on. Same shape as `verify change`.
    assert_eq!(rule(&value, "min_signatures"), "passed");
    assert_eq!(value["accepts"], Value::Null);
}

#[test]
fn an_untrusted_signer_is_a_refusal_whose_first_failure_is_trust() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "stranger", &c.hex);

    let (code, value, text) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(code, 6, "{value}");
    assert_eq!(reason_codes(&value), vec!["trust", "min_signatures"]);
    let proof = &value["attestations"][0];
    assert_eq!(rule(proof, "signature"), "passed", "the signature is real");
    assert_eq!(
        rule(proof, "trust"),
        "failed",
        "just not by anyone in charge"
    );
    assert!(
        text.contains("none of them trusted here"),
        "the plain-language half: {text}"
    );
}

// ---------------------------------------------------------------------------
// `gitiup policy explain`
// ---------------------------------------------------------------------------

#[test]
fn explain_attestation_prints_every_rule_in_ladder_order_with_both_halves_of_the_evidence() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);
    let doc = h.file("matrix-build-runner.doc");

    let (code, value, text) = h.explain(&[
        "attestation",
        &doc,
        "--store",
        &h.store(),
        "--trust",
        "ada",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["record_type"], "policy-explanation");
    assert_eq!(value["subject"]["kind"], "attestation");
    assert_eq!(value["subject"]["commit"], c.head);
    assert_eq!(value["verdict"], "pass");
    let mut expected = vec!["policy"];
    expected.extend(CHECK_ORDER);
    assert_eq!(
        rule_codes(&value),
        expected,
        "the whole ladder, in the promised order, passing rules included"
    );
    // Every rule carries both halves: what the policy demanded, and what this proof
    // claims. That pairing is the whole point of `explain` over a check list.
    for rule in value["rules"].as_array().unwrap() {
        let code = rule["rule"].as_str().unwrap();
        assert!(
            rule["evidence"]["policy"].is_string(),
            "{code} says what the policy demands: {rule}"
        );
        assert!(
            rule["evidence"]["claim"].is_string(),
            "{code} says what this proof claims: {rule}"
        );
        assert!(
            rule["outcome"].is_string() && rule["rule"].is_string(),
            "every rule is addressable: {rule}"
        );
    }
    assert_eq!(rule(&value, "tier"), "passed");
    assert!(
        text.contains("runner"),
        "who signed it belongs in the human report: {text}"
    );
}

#[test]
fn explain_change_agrees_with_the_gate_it_explains() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);

    let store = h.store();
    let (verify_code, _, _) = h.verify(&c.id, &[]);
    let (code, value, text) = h.explain(&[
        "change", &c.id, "--store", &store, "--trust", "ada", "--now", NOW, "--json",
    ]);
    assert_eq!(
        code, verify_code,
        "one gate, so one answer: explain cannot disagree with `verify change`"
    );
    assert_eq!(value["subject"]["kind"], "change");
    assert_eq!(value["subject"]["change"], c.id);
    assert_eq!(
        rule_codes(&value),
        vec![
            "change",
            "policy",
            "protects",
            "attestations",
            "quorum",
            "min_signatures"
        ],
        "the change-level rules, in the order `verify change` checks them"
    );
    assert_eq!(
        rule(&value, "quorum"),
        "not_asked",
        "this policy asks for no verdict"
    );
    assert_eq!(ladder_codes(&value["attestations"][0]), CHECK_ORDER);
    assert!(text.contains(&c.hex), "the head it judged: {text}");
}

#[test]
fn explain_says_which_revision_it_walked_to_and_why_that_one() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);
    let doc = h.file("matrix-build-runner.doc");

    let (code, value, _) = h.explain(&[
        "attestation",
        &doc,
        "--store",
        &h.store(),
        "--trust",
        "ada",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(code, 0);
    // D6: the policy applied to a proof is the one that was in force when that proof was
    // made — so the report has to say the revision and where it came from.
    assert_eq!(value["policy"]["provenance"]["source"], "store");
    assert_eq!(value["policy"]["provenance"]["revision"], 1);
    assert!(value["policy"]["provenance"]["body_digest"].is_string());
    assert!(
        value["policy"]["rules"].is_object(),
        "the rules it applied, not just their names: {}",
        value["policy"]
    );
}

#[test]
fn explain_of_a_document_no_policy_will_claim_is_a_policy_refusal_with_no_invented_rules() {
    let h = harness();
    let c = change(&h);
    h.push("matrix-build", "runner", &c.hex);
    let doc = h.file("matrix-build-runner.doc");

    let (code, value, _) = h.explain(&[
        "attestation",
        &doc,
        "--store",
        &h.store(),
        "--trust",
        "ada",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(
        code, 6,
        "nothing published, and a file in a tree is not a rule: {value}"
    );
    assert_eq!(rule_codes(&value), vec!["policy"]);
    assert_eq!(rule(&value, "policy"), "failed");
    assert_eq!(reason_codes(&value), vec!["policy"]);
}

#[test]
fn the_first_failing_rule_is_the_reason_and_the_exit_code() {
    // The promise the whole command is built around, asserted on every verdict shape at
    // once: the rules are in D7 order, so the first failed one is the code the process
    // exits with — which is what lets a CI job post the rule list without re-deriving it.
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "stranger", &c.hex);
    let doc = h.file("matrix-build-stranger.doc");

    let (code, value, _) = h.explain(&[
        "attestation",
        &doc,
        "--store",
        &h.store(),
        "--trust",
        "ada",
        "--now",
        NOW,
        "--json",
    ]);
    let failures: Vec<String> = value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| matches!(rule["outcome"].as_str(), Some("failed") | Some("warned")))
        .map(|rule| rule["rule"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(failures.first().map(String::as_str), Some("trust"));
    assert_eq!(code, 6);
    assert_eq!(value["exit"], 6);
    assert_eq!(
        value["reasons"][0]["code"].as_str().unwrap(),
        failures.first().unwrap().as_str(),
        "the reason list and the rule list agree: {value}"
    );
}

#[test]
fn json_is_stable_enough_to_parse_twice_and_find_every_answer_without_guessing() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);

    let stamp = |mut value: Value| {
        // The clock is the one field that legitimately differs between two runs; the
        // shape around it may not.
        let object = value.as_object_mut().expect("an object");
        object.remove("clock");
        object.remove("clock_us");
        value
    };
    let (_, first, _) = h.check(&["--commit", &c.hex, "--json"]);
    let (_, second, _) = h.check(&["--commit", &c.hex, "--json"]);
    assert_eq!(
        stamp(first.clone()),
        stamp(second),
        "the same store says the same thing twice"
    );
    let value = first;
    for key in [
        "record_type",
        "verdict",
        "exit",
        "satisfies",
        "subject",
        "policy",
        "checks",
        "rules",
        "attestations",
        "accepts",
        "reasons",
        "clock",
        "clock_us",
    ] {
        assert!(value.get(key).is_some(), "`{key}` is missing: {value}");
    }
    // `checks` is the compact projection a hook reads; `rules` is the same list with its
    // evidence, and they must not disagree.
    let checks = value["checks"].as_array().unwrap();
    let rules = value["rules"].as_array().unwrap();
    assert_eq!(checks.len(), rules.len());
    for (check, rule) in checks.iter().zip(rules.iter()) {
        assert_eq!(check["code"], rule["rule"]);
        assert_eq!(check["outcome"], rule["outcome"]);
    }
}

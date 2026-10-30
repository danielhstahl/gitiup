//! `gitiup verify change`, run as the real binary (giti-91m.4).
//!
//! The ticket's acceptance criterion is a command line and a set of exit codes: *one
//! command resolves the change, gathers every attestation the store advertises for its
//! head plus any quorum verdict, evaluates against the policy in force at the run
//! timestamp, and exits 0/6/7/8; every failure is reported; the accepted combination of
//! attestations is named; stdout carries the report and stderr stays empty.* So it is
//! tested as command lines against the built executable, in a real store, with real
//! signed documents and real git commits.
//!
//! Four things are deliberately strict here:
//!
//! * **The clock is pinned.** The fixtures claim a fixed time and freshness is a window
//!   against *now*, so every run passes `--now`; a test that let the clock run would
//!   pass today and fail next month. One test pins `--at` as well, because the policy
//!   walk is the thing under test there.
//! * **The tampering is done through the library.** A mutated attestation has to stay
//!   canonical or the test proves only that whitespace matters (the same rule
//!   `verify_cli.rs` follows).
//! * **A verdict is stdout and an error is stderr** — asserted on every run, because the
//!   contract a `pre-receive` hook depends on is that the number is in the exit code and
//!   the document is on stdout, *including* for exit 6, 7 and 8.
//! * **The quorum verdict is published through the library**, because the CLI for it is
//!   giti-zp1.4 (not built yet) and the merge gate's job is to read whatever the store
//!   carries, however it got there.

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

    /// The verdict, with the stdout/stderr contract asserted: a verdict (0/6/7/8) prints
    /// its report on stdout and says nothing on stderr.
    fn verify(&self, change: &str, extra: &[&str]) -> (u8, Value, String) {
        let store = self.store();
        let mut args = vec![
            "verify", "change", change, "--store", &store, "--trust", "ada", "--now", NOW,
        ];
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        let code = code(&output);
        assert!(
            matches!(code, 0 | 6 | 7 | 8),
            "exit {code} is not a verdict: {}{}",
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

// ---------------------------------------------------------------------------
// the acceptance criterion: one command, one verdict, one exit code
// ---------------------------------------------------------------------------

#[test]
fn a_change_with_one_trusted_local_proof_may_merge_and_says_which_combination_it_accepted() {
    let h = harness();
    let c = change(&h);
    let policy = h.publish_policy(&[]);
    let pushed = h.push("matrix-build", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);

    assert_eq!(code, 0, "a trusted proof of the head should merge: {value}");
    assert_eq!(value["verdict"], "pass");
    assert_eq!(value["exit"], 0);
    assert_eq!(value["accepted"], true);
    assert_eq!(value["change"], c.id);
    assert_eq!(value["head"], c.head);
    assert_eq!(value["target"], "refs/heads/main");
    assert_eq!(value["state"], "open");
    assert!(value["reasons"].as_array().unwrap().is_empty(), "{value}");
    for code in [
        "change",
        "policy",
        "protects",
        "attestations",
        "min_signatures",
    ] {
        assert_eq!(check(&value, code), "passed", "{code}: {value}");
    }
    // No quorum was asked for, and the report says so instead of leaving it out.
    assert_eq!(check(&value, "quorum"), "not_asked");
    assert_eq!(check(&value, "attestations"), "passed");

    // "the accepted combination of attestations is named": which ones, whose, and what
    // single result they certify.
    let accepts = &value["accepts"];
    assert_eq!(accepts["via"], "attestations");
    assert_eq!(accepts["required"], 1);
    assert_eq!(accepts["signers"].as_array().unwrap().len(), 1);
    assert_eq!(accepts["signers"][0], h.key_id("runner"));
    assert_eq!(
        accepts["counted"].as_array().unwrap(),
        // Tagged, like every other digest in this report.
        &vec![format!(
            "sha256:{}",
            pushed["digest"].as_str().expect("a digest")
        )]
    );
    assert!(
        accepts["result_digest"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha256:"),
        "the combination names the result it certifies: {accepts}"
    );

    // The policy is cited, not assumed: the published revision, with its digest.
    assert_eq!(value["policy"]["provenance"]["source"], "store");
    assert_eq!(value["policy"]["provenance"]["revision"], 1);
    assert_eq!(value["policy"]["provenance"]["gate_eligible"], true);
    assert_eq!(
        value["policy"]["provenance"]["body_digest"], policy["body_digest"],
        "the report cites the policy it applied"
    );

    // And the attestation's own ladder is in the report, judged by the same policy.
    let attestations = value["attestations"].as_array().unwrap();
    assert_eq!(attestations.len(), 1);
    assert_eq!(attestations[0]["accepted"], true);
    assert_eq!(attestations[0]["verdict"], "pass");
    assert_eq!(
        attestations[0]["digest"],
        format!("sha256:{}", pushed["digest"].as_str().expect("a digest"))
    );
    assert_eq!(attestations[0]["ref"], pushed["reference"]);
    assert_eq!(attestations[0]["attestation"]["commit"], c.head);
    assert_eq!(attestations[0]["attestation"]["job"], "build");
    assert_eq!(attestations[0]["policy"]["provenance"]["revision"], 1);

    // The human form answers the same question in one line, and names the combination.
    let (code, _, text) = h.verify(&c.id, &[]);
    assert_eq!(code, 0);
    assert!(
        text.contains("verdict") && text.contains("MAY MERGE"),
        "{text}"
    );
    assert!(
        text.contains("accepted") && text.contains("attestations"),
        "{text}"
    );
    // The key is spelled in its shortened form, like every key id in prose output.
    let runner = h.key_id("runner");
    assert!(text.contains(&runner[..11]), "{text}");

    // The quiet form is the one a hook shells out for.
    let (code, _, quiet) = h.verify(&c.id, &["--quiet"]);
    assert_eq!(code, 0);
    assert_eq!(quiet.trim(), "ok");
}

#[test]
fn nothing_published_and_nothing_named_refuses_as_no_policy_published() {
    // No default is the answer, and the report has to say that it is (D4): a change with
    // no published rule is refused, not waved through by whatever the CLI would like.
    let h = harness();
    let c = change(&h);
    h.push("matrix-build", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6);
    assert_eq!(value["verdict"], "policy");
    assert_eq!(reason_codes(&value), vec!["policy"]);
    assert_eq!(check(&value, "policy"), "failed");
    assert_eq!(check(&value, "protects"), "not_run");
    let detail = value["reasons"][0]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("no policy") || detail.contains("no_policy_published"),
        "{detail}"
    );
    assert_eq!(value["accepts"], Value::Null);

    // A named file is an operator's act and is gate-eligible (D4), so the same change
    // merges once someone says which rule to apply — from a file the store never saw.
    let draft = h.file("draft.json");
    std::fs::write(
        &draft,
        json!({
            "allowed_tiers": ["local"],
            "trust_key_ids": [h.key_id("runner")],
        })
        .to_string(),
    )
    .expect("write the draft");
    let (code, value, _) = h.verify(&c.id, &["--json", "--policy", &draft]);
    assert_eq!(code, 0, "a named policy must apply: {value}");
    assert_eq!(value["policy"]["provenance"]["source"], "--policy");
}

#[test]
fn a_change_with_no_proof_at_all_refuses_and_names_the_head() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value), vec!["attestations"]);
    assert_eq!(check(&value, "attestations"), "failed");
    assert_eq!(check(&value, "quorum"), "not_asked");
    assert!(
        value["reasons"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains(&c.hex[..8]),
        "the refusal says which commit had nothing proved: {value}"
    );
    // The human form leads with the answer, and says which check decided it.
    let (code, _, text) = h.verify(&c.id, &[]);
    assert_eq!(code, 6);
    assert!(text.contains("REFUSED (exit 6)"), "{text}");
    assert!(text.contains("[attestations]"), "{text}");
}

#[test]
fn an_unresolvable_change_is_a_refusal_and_not_a_crash() {
    let h = harness();
    change(&h);
    let (code, value, _) = h.verify("chg-0000000000000000", &["--json"]);
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value), vec!["change"]);
    assert_eq!(check(&value, "change"), "failed");
    assert_eq!(check(&value, "policy"), "not_run");
}

// ---------------------------------------------------------------------------
// every failure is reported, and the first one decides the exit code
// ---------------------------------------------------------------------------

#[test]
fn an_untrusted_signer_is_reported_against_its_attestation_and_refuses() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    // A well-formed, correctly signed attestation from a key the policy never trusted.
    let pushed = h.push("matrix-build", "stranger", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);

    assert_eq!(code, 6, "an untrusted proof may not merge: {value}");
    assert_eq!(value["verdict"], "policy");
    // The attestation's own failure is in the report twice on purpose: once inside its
    // section, and once lifted to the top with its digest prefixed, so a reader of the
    // flat `reasons` list still learns *which* proof failed.
    assert_eq!(
        reason_codes(&value),
        vec!["trust", "min_signatures"],
        "the refusal and what it means for the count"
    );
    let detail = value["reasons"][0]["detail"].as_str().unwrap_or_default();
    let hex = pushed["digest"].as_str().expect("a digest");
    assert!(
        detail.starts_with(&format!(
            "attestation {}\u{2026}{}:",
            &hex[..8],
            &hex[hex.len() - 4..]
        )),
        "a lifted reason names which attestation it is about: {detail}"
    );
    let section = &value["attestations"][0];
    assert_eq!(section["accepted"], false);
    assert_eq!(section["reasons"][0]["code"], "trust");
    assert_eq!(check(section, "trust"), "failed");
    assert_eq!(check(section, "signature"), "passed");
    assert_eq!(
        check(&value, "attestations"),
        "passed",
        "the store advertised it"
    );
    assert_eq!(value["accepts"], Value::Null);
}

#[test]
fn a_proof_about_another_commit_is_a_digest_mismatch() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    // Filed under this change's head (that is what `--subject` is for) but certifying
    // some other commit: the bytes are canonical and the signature is real, so the only
    // thing wrong is the binding — which is exactly what exit 8 means.
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
    let output = h.run(
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
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );

    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 8, "the wrong commit is exit 8: {value}");
    assert_eq!(value["verdict"], "digest_mismatch");
    assert_eq!(value["exit"], 8);
    assert_eq!(reason_codes(&value), vec!["commit"]);
    assert_eq!(check(&value, "attestations"), "passed");
    let section = &value["attestations"][0];
    assert_eq!(check(section, "commit"), "failed");
    assert_eq!(
        section["attestation"]["commit"],
        "sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(value["accepts"], Value::Null);
}

#[test]
fn a_signature_that_does_not_verify_is_exit_seven_on_stdout() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    // Runner's key id carrying somebody else's signature: the ladder stops at `signature`,
    // which is a 7, and 7 outranks the policy refusal `trust` would otherwise have said.
    h.push("matrix-build", "runner", &c.hex);
    let mut doc = h.document("matrix-build", "runner");
    let stranger = SigningKey::from_seed(&STRANGER_SEED);
    let mut entry =
        SignatureEntry::new(&stranger, &doc.signature_message().expect("message")).expect("sign");
    entry.key_id = h.key_id("runner");
    doc.signatures.clear();
    doc.signatures.push(entry);
    let filed = h.file_document("tampered.doc", &doc);

    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 7, "a bad signature is a verdict: {value}");
    assert_eq!(value["verdict"], "bad_signature");
    assert_eq!(value["exit"], 7);
    assert_eq!(
        reason_codes(&value),
        vec!["signature", "min_signatures"],
        "the bad signature decides, and the count it implies is said too"
    );
    let sections = value["attestations"].as_array().unwrap();
    assert_eq!(sections.len(), 2);
    let forged = sections
        .iter()
        .find(|section| {
            section["digest"] == format!("sha256:{}", filed["digest"].as_str().expect("a digest"))
        })
        .expect("the forged attestation is in the report");
    assert_eq!(check(forged, "signature"), "failed");
    assert_eq!(
        check(forged, "min_signatures"),
        "failed",
        "a spoofed signature signs nothing the policy trusts: {forged}"
    );
    // The genuine proof beside it is still reported as good — and still does not carry
    // the merge, because a forged attestation in the store is not something a gate can
    // step over on the way to a pass.
    let genuine = sections
        .iter()
        .find(|section| {
            section["digest"] != format!("sha256:{}", filed["digest"].as_str().expect("a digest"))
        })
        .expect("the genuine attestation is in the report");
    assert_eq!(genuine["accepted"], true);
    assert_eq!(value["accepts"], Value::Null);
}

// ---------------------------------------------------------------------------
// what "add up to min_signatures" means
// ---------------------------------------------------------------------------

#[test]
fn two_trusted_keys_certifying_one_result_are_two_signatures() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--min-signatures", "2"]);
    // The same run, signed by two trusted keys: one result, two distinct signers — the
    // only combination that ever satisfies `min_signatures: 2`.
    let one = h.push("matrix-build", "runner", &c.hex);
    let two = h.push("matrix-build", "co", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 0, "two signers, one result: {value}");
    let accepts = &value["accepts"];
    assert_eq!(accepts["required"], 2);
    assert_eq!(accepts["via"], "attestations");
    let mut expected = vec![h.key_id("co"), h.key_id("runner")];
    expected.sort();
    assert_eq!(
        accepts["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap_or_default().to_string())
            .collect::<Vec<String>>(),
        expected,
        "the report names both keys it counted"
    );
    let mut counted = accepts["counted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_string())
        .collect::<Vec<String>>();
    counted.sort();
    let mut expected = ["digest", "digest"]
        .iter()
        .map(|_| String::new())
        .collect::<Vec<String>>();
    expected[0] = format!("sha256:{}", one["digest"].as_str().unwrap());
    expected[1] = format!("sha256:{}", two["digest"].as_str().unwrap());
    expected.sort();
    assert_eq!(counted, expected, "both attestations were counted");
    assert_eq!(check(&value, "min_signatures"), "passed");
    assert_eq!(check(&value, "attestations"), "passed");
}

#[test]
fn one_key_certifying_twice_is_one_signature() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--min-signatures", "2"]);
    // Two attestations, one key. `min_signatures` is about *who*, so this is a refusal,
    // and the reason has to say that the count was distinct signers rather than files.
    h.push("matrix-build", "runner", &c.hex);
    h.push("test-failure", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6, "two files from one key is one signature: {value}");
    assert_eq!(reason_codes(&value), vec!["min_signatures"]);
    assert_eq!(check(&value, "min_signatures"), "failed");
    assert_eq!(check(&value, "attestations"), "passed");
    assert!(
        value["reasons"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("distinct"),
        "{value}"
    );
}

#[test]
fn attestations_certifying_different_results_do_not_add_up() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--min-signatures", "2"]);
    // Two trusted keys, two different results: each proves a different claim, so neither
    // combination reaches 2. This is the quorum's own agreement rule, applied to a
    // repository's policy field — and the case a naive `count(accepted)` gets wrong.
    h.push("matrix-build", "runner", &c.hex);
    h.push("test-failure", "co", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6, "two claims do not make one agreement: {value}");
    assert_eq!(reason_codes(&value), vec!["min_signatures"]);
    assert_eq!(
        value["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|section| section["accepted"] == true)
            .count(),
        2,
        "each was accepted on its own, and neither combination adds up"
    );
    let detail = value["reasons"][0]["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("1") && detail.contains("2"), "{detail}");
    assert_eq!(value["accepts"], Value::Null);
}

// ---------------------------------------------------------------------------
// the policy is the revision in force at the run's timestamp (D6)
// ---------------------------------------------------------------------------

#[test]
fn the_merge_is_todays_revision_and_each_proof_is_the_one_in_force_when_it_ran() {
    let h = harness();
    let c = change(&h);
    // Rev 1: generous freshness, one signature. In force when the run happened.
    h.publish_policy(&["--max-age", "30d", "--min-signatures", "1"]);
    h.push("matrix-build", "runner", &c.hex);
    // Rev 2: three signatures, in force from the day after the run. Tomorrow's rule must
    // not refuse last week's run — and last week's rule must not decide today's merge.
    h.publish_policy(&[
        "--max-age",
        "30d",
        "--min-signatures",
        "3",
        "--effective-from",
        "2026-10-28T00:00:00Z",
    ]);

    // Judged today: rev 2 decides what a merge requires (3), rev 1 decides whether the
    // proof is good (it is). One accepted attestation, but not three.
    let (code, value, _) = h.verify(&c.id, &["--json", "--now", "2026-10-28T12:00:00Z"]);
    assert_eq!(code, 6, "today's rule asks for three: {value}");
    assert_eq!(value["policy"]["provenance"]["revision"], 2);
    assert_eq!(value["attestations"][0]["accepted"], true);
    assert_eq!(
        value["attestations"][0]["policy"]["provenance"]["revision"], 1,
        "the proof is judged by the rules that were in force when it was made"
    );
    assert_eq!(reason_codes(&value), vec!["min_signatures"]);

    // And the same question replayed as of yesterday: rev 1 throughout, and it merges.
    let (code, value, _) = h.verify(
        &c.id,
        &[
            "--json",
            "--now",
            "2026-10-28T12:00:00Z",
            "--at",
            "2026-10-27T12:00:00Z",
        ],
    );
    assert_eq!(code, 0, "as of yesterday one signature was enough: {value}");
    assert_eq!(value["policy"]["provenance"]["revision"], 1);
    assert_eq!(value["accepts"]["required"], 1);
}

#[test]
fn a_policy_that_does_not_gate_the_target_ref_refuses() {
    let h = harness();
    let c = change(&h);
    // The owner's rule gates a different branch. That is not "no rule, so go ahead":
    // approving ungated work is the failure mode D7 refuses to allow.
    h.publish_policy(&["--protect", "refs/heads/stable/**"]);
    h.push("matrix-build", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6, "an ungated target is a refusal: {value}");
    assert_eq!(reason_codes(&value), vec!["protects"]);
    assert_eq!(check(&value, "protects"), "failed");
    assert_eq!(check(&value, "policy"), "passed");
    assert_eq!(
        check(&value, "attestations"),
        "not_run",
        "nothing else was asked"
    );
}

// ---------------------------------------------------------------------------
// the quorum verdict, read from the store rather than inferred
// ---------------------------------------------------------------------------

#[test]
fn a_verified_quorum_verdict_carries_a_change_the_policy_demands_it_for() {
    let h = harness();
    let c = change(&h);
    // A policy whose accepted tiers include `quorum`, which is the only case where a
    // verdict may stand in for the individual proofs. The flag form cannot express a
    // quorum block, so the document is written out and published.
    h.quorum_policy();
    publish_verdict(&h, &c, "build", ADA_SEED, |_| {});

    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 0, "the owner's quorum should carry: {value}");
    assert_eq!(check(&value, "quorum"), "passed");
    assert_eq!(check(&value, "min_signatures"), "passed");
    let accepts = &value["accepts"];
    assert_eq!(accepts["via"], "quorum verdict");
    assert_eq!(accepts["required"], 1);
    assert!(
        accepts["ref"].as_str().unwrap_or_default().contains(&c.id),
        "the report names the verdict it rested on: {accepts}"
    );
    assert_eq!(
        accepts["result_digest"],
        Digest::sha256(b"result").to_string()
    );
    let verdicts = value["quorum"].as_array().unwrap();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0]["state"], "verified");
    assert_eq!(verdicts[0]["job"], "build");
    assert_eq!(verdicts[0]["head"], c.head);
    // Nothing was advertised as an individual proof, and the report says that plainly
    // instead of leaving an empty list for a reader to misread as a failure.
    assert_eq!(value["attestations"].as_array().unwrap().len(), 0);
    assert_eq!(check(&value, "attestations"), "not_asked");
    assert!(
        value["notes"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|note| note
                .as_str()
                .unwrap_or_default()
                .contains("quorum verdict is what carried it")),
        "{value}"
    );
}

#[test]
fn a_failed_quorum_verdict_refuses_even_though_a_proof_passes() {
    let h = harness();
    let c = change(&h);
    h.quorum_policy();
    h.push("matrix-build", "runner", &c.hex);
    publish_verdict(&h, &c, "build", ADA_SEED, |verdict| {
        verdict.state = QuorumState::Failed;
        verdict.reason = ReasonCode::IrreconcilableDigests;
        verdict.agreeing = 1;
        verdict.detail = "two results, neither at the threshold".to_string();
    });

    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(
        code, 6,
        "a quorum that disagreed cannot be ignored: {value}"
    );
    let codes = reason_codes(&value);
    assert!(
        !codes.is_empty() && codes.iter().all(|code| code == "quorum"),
        "{value}"
    );
    assert_eq!(check(&value, "quorum"), "failed");
    // The proof is still reported as good — the refusal is about the quorum, and a reader
    // is entitled to see both facts.
    assert_eq!(value["attestations"][0]["accepted"], true);
    assert_eq!(value["quorum"][0]["state"], "failed");
    assert_eq!(value["accepts"], Value::Null);
}

#[test]
fn a_verdict_about_another_head_is_a_digest_mismatch() {
    let h = harness();
    let c = change(&h);
    h.quorum_policy();
    publish_verdict(&h, &c, "build", ADA_SEED, |verdict| {
        verdict.head_oid = "sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse::<GitOid>()
            .expect("an oid");
    });
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(
        code, 8,
        "a verdict bound to another head is exit 8: {value}"
    );
    assert_eq!(value["verdict"], "digest_mismatch");
    let codes = reason_codes(&value);
    assert!(
        !codes.is_empty() && codes.iter().all(|code| code == "quorum"),
        "{value}"
    );
    assert_eq!(check(&value, "quorum"), "failed");
    assert!(
        value["reasons"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("bbbbbbbb"),
        "{value}"
    );
}

#[test]
fn a_verdict_the_owner_does_not_trust_is_refused_not_followed() {
    let h = harness();
    let c = change(&h);
    h.quorum_policy();
    // Perfectly well-formed, signed by a key the trust roots do not contain: the verdict
    // is a claim about the change, and whose claim it is remains the question.
    publish_verdict(&h, &c, "build", STRANGER_SEED, |_| {});
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(
        code, 6,
        "an unsigned-by-the-owner verdict is a refusal: {value}"
    );
    assert_eq!(check(&value, "quorum"), "failed");
    assert!(
        !value["quorum"][0]["refused"]["detail"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "the verdict section says why it was refused: {value}"
    );
    assert!(
        value["quorum"][0]["refused"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("trust")
    );
    assert_eq!(value["accepts"], Value::Null);
}

#[test]
fn a_policy_that_does_not_ask_for_a_quorum_is_not_refused_for_the_absence_of_one() {
    let h = harness();
    let c = change(&h);
    // `quorum` is in the accepted tiers, which means a verdict *may* count — not that a
    // round is mandatory. One good local proof still merges, and `quorum` reads not_asked.
    h.quorum_policy();
    h.push("matrix-build", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 0, "a verdict is not compulsory: {value}");
    assert_eq!(check(&value, "quorum"), "not_asked");
    assert_eq!(value["accepts"]["via"], "attestations");
}

#[test]
fn a_policy_that_asks_for_a_quorum_and_gets_no_verdict_refuses() {
    let h = harness();
    let c = change(&h);
    // Quorum-only rules with no proof that reaches that tier: the honest answer is that
    // nothing certifies this change at the tier the owner asked for.
    h.publish_document(
        "quorum-only.json",
        json!({
            "type": "gitiup-policy-1",
            "schema_version": 1,
            "owner": { "key_id": "", "principal": "Ada" },
            "revision": 1,
            "previous_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "effective_from_us": 0,
            "protects": ["refs/heads/**"],
            "rules": {
                "allowed_tiers": ["quorum"],
                "trust_key_ids": [h.key_id("runner")],
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
    );
    h.push("matrix-build", "runner", &c.hex);
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6, "a local proof is not the tier asked for: {value}");
    assert_eq!(check(&value, "quorum"), "failed");
    assert_eq!(value["accepts"], Value::Null);
    assert_eq!(
        value["attestations"][0]["accepted"], false,
        "the proof itself is refused at the tier: {value}"
    );
}

// ---------------------------------------------------------------------------
// the shapes a caller parses
// ---------------------------------------------------------------------------

#[test]
fn a_missing_id_is_usage_and_an_unreachable_store_is_not_a_verdict() {
    let h = harness();
    // Exit 2 and 3 are not verdicts: they go to stderr and print no report, and a hook
    // must be able to tell "the store did not answer" from "this change may not merge".
    let missing = h.run(&["verify", "change"], None);
    assert_eq!(code(&missing), 2);
    assert!(!stderr(&missing).is_empty());
    assert!(stdout(&missing).is_empty());

    let change = change(&h);
    // A store that cannot be opened — the path is a regular file. (A *missing* directory
    // is not that: the fs host creates one, so that answer is a refusal, correctly.)
    let away = h.file("not-a-store");
    std::fs::write(&away, "not a store").expect("write");
    let unreachable = h.run(
        &["verify", "change", &change.id, "--store", &away, "--json"],
        None,
    );
    assert_eq!(code(&unreachable), 3, "{}", stdout(&unreachable));
    assert!(stdout(&unreachable).is_empty(), "3 is not a verdict");
    assert!(!stderr(&unreachable).is_empty());
}

#[test]
fn the_json_is_one_object_with_every_answer_a_gate_needs() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&[]);
    h.push("matrix-build", "runner", &c.hex);
    let (_, value, _) = h.verify(&c.id, &["--json"]);
    for key in [
        "record_type",
        "verdict",
        "exit",
        "accepted",
        "store",
        "handle",
        "change",
        "state",
        "head",
        "target",
        "checks",
        "reasons",
        "policy",
        "attestations",
        "quorum",
        "accepts",
    ] {
        assert!(value.get(key).is_some(), "{key} is missing: {value}");
    }
    assert_eq!(value["record_type"], "change-verdict");
    // Every change-level check is listed, even the ones that had nothing to say: a reader
    // has to be able to see what was *not* established.
    let listed: Vec<String> = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["code"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        listed,
        vec![
            "change",
            "policy",
            "protects",
            "attestations",
            "quorum",
            "min_signatures"
        ]
    );
}

// ---------------------------------------------------------------------------
// provenance: what a copy of a proof is worth to a gate (ADR-0005 D5)
// ---------------------------------------------------------------------------

/// File an arrival record for a digest, in the shape `gitiup attest import` writes.
///
/// This is the *only* evidence a store has that it is a mirror — there is no `mirror`
/// flag anywhere, and there never will be — and it is what a policy's provenance demand is
/// judged against. Writing it here, rather than running an import, keeps the test about
/// the gate's decision instead of about two stores.
fn mark_as_copy(h: &Harness, digest: &str, reference: &str, from: &str) {
    let host = FsHost::open_or_create(h.store()).expect("open the store");
    let oid = Oid::from_hex(digest).expect("a digest");
    let arrival = gitiup_host::federation::Arrival::new(
        &oid,
        &RefName::new(reference).expect("a ref"),
        from,
        1_793_395_000_000_000,
    );
    gitiup_host::federation::record(&host, &arrival).expect("file the arrival record");
}

/// The `provenance` block is printed whatever the policy says, because a reader who is
/// not told a proof arrived by copy cannot ask whether that matters. The refusal is the
/// owner's: a policy that says "I will not gate a merge on a copy" is obeyed, and a
/// policy that says nothing is the default — federation on, a copy gates what an origin
/// gates.
#[test]
fn a_policy_that_will_only_gate_on_an_origin_proof_refuses_the_copy_of_one() {
    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--require-origin-provenance"]);
    let pushed = h.push("matrix-build", "runner", &c.hex);
    let digest = pushed["digest"].as_str().expect("a digest").to_string();

    // Made here, so the demand is satisfied and the block says which of the two this is.
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 0, "an origin proof satisfies the demand: {value}");
    let proof = &value["attestations"][0]["provenance"];
    assert_eq!(proof["store"], "origin");
    assert_eq!(proof["origin_seen"], true);
    assert_eq!(proof["age_basis"], "claimed_at_us");

    // The same bytes, arrived from elsewhere. Nothing about the document changed — it is
    // the same signature over the same manifest — and yet a gate that must not act on a
    // stale proof now refuses it, which is the whole of what a mirror can and cannot do.
    mark_as_copy(
        &h,
        &digest,
        pushed["reference"].as_str().unwrap(),
        "https://stranger.example.org/repo.git",
    );
    let (code, value, text) = h.verify(&c.id, &["--json"]);
    assert_eq!(
        code, 6,
        "a copy may not gate a merge under this policy: {value}"
    );
    let attestation = &value["attestations"][0];
    assert_eq!(attestation["accepted"], false, "{attestation}");
    assert_eq!(attestation["provenance"]["store"], "copy");
    assert_eq!(
        attestation["provenance"]["arrived_from"],
        "https://stranger.example.org/repo.git"
    );
    assert_eq!(attestation["provenance"]["origin_seen"], false);
    assert!(
        reason_codes(attestation).contains(&"origin_provenance_required".to_string()),
        "the refusal is named by its token: {attestation}"
    );
    // The gate's own question — does this add up to a merge? — is answered no. The
    // `attestations` check stays `passed` because it is the check that says the store's
    // proofs were read and parsed; the refusal is the ladder's and the combination's.
    assert_eq!(check(&value, "min_signatures"), "not_run", "{value}");
    assert!(
        value["notes"].as_array().unwrap().iter().any(|note| note
            .as_str()
            .unwrap_or_default()
            .contains("passed on its own")),
        "and the report says why nothing added up: {value}"
    );
    assert_eq!(value["accepted"], false);
    assert!(
        reason_codes(&value).contains(&"origin_provenance_required".to_string()),
        "and the reason reaches the change, not only the attestation: {value}"
    );

    // …and the human report says the same sentence.
    let (_, _, prose) = h.verify(&c.id, &[]);
    assert!(prose.contains("origin_provenance_required"), "{prose}");
    assert!(text.contains("origin_provenance_required"));
}

/// A policy may instead name the stores it keeps as fresh as itself. This is not a trust
/// list — keys do that, and a mirror has no key — and not an access-control list; it
/// states only which copies the owner is willing to treat as current.
#[test]
fn a_named_mirror_may_gate_a_merge_and_an_unnamed_one_may_not() {
    let mirror = "https://mirror.example.org/repo.git";

    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--mirror", mirror]);
    let pushed = h.push("matrix-build", "runner", &c.hex);
    mark_as_copy(
        &h,
        pushed["digest"].as_str().expect("a digest"),
        pushed["reference"].as_str().unwrap(),
        mirror,
    );
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 0, "the owner named this store: {value}");
    assert_eq!(value["attestations"][0]["provenance"]["store"], "copy");

    let h = harness();
    let c = change(&h);
    h.publish_policy(&["--mirror", mirror]);
    let pushed = h.push("matrix-build", "runner", &c.hex);
    mark_as_copy(
        &h,
        pushed["digest"].as_str().expect("a digest"),
        pushed["reference"].as_str().unwrap(),
        "https://somebody-elses.example.org/repo.git",
    );
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(code, 6, "nobody named this store: {value}");
    let attestation = &value["attestations"][0];
    assert!(
        reason_codes(attestation).contains(&"unlisted_mirror".to_string()),
        "the refusal names both the store and the list: {attestation}"
    );
    assert!(
        attestation["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("somebody-elses.example.org")),
        "and says which one it means: {attestation}"
    );
}

/// Absent the member — the shape of every policy signed before this existed — a copy is
/// an ordinary proof. Making provenance opt-in is what keeps "not tied to one bucket"
/// from quietly becoming "not mirrored at all".
#[test]
fn a_policy_that_says_nothing_about_copies_gates_on_them_like_anything_else() {
    let h = harness();
    let c = change(&h);
    let policy = h.publish_policy(&[]);
    let pushed = h.push("matrix-build", "runner", &c.hex);
    mark_as_copy(
        &h,
        pushed["digest"].as_str().expect("a digest"),
        pushed["reference"].as_str().unwrap(),
        "https://anybody.example.org/repo.git",
    );
    let (code, value, _) = h.verify(&c.id, &["--json"]);
    assert_eq!(
        code, 0,
        "a copy gates a merge unless the owner says otherwise: {value}"
    );
    assert_eq!(value["attestations"][0]["provenance"]["store"], "copy");
    assert!(
        policy["provenance"].is_null(),
        "the published policy says nothing about copies: {policy}"
    );
}

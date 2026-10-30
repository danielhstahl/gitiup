//! `gitiup verify attestation`, run as the real binary.
//!
//! The ticket's acceptance criteria are a command line, a set of exit codes and a
//! JSON shape — *checks signature, digest recomputation, env match, tier and
//! freshness; exit codes 0/6/7/8 for ok/policy-fail/bad-signature/digest-mismatch;
//! json output stable for tooling* — so they are tested here as command lines
//! against the built executable, each in a new process, with every assertion read
//! from `--json` (and from the exit code, which is what a hook actually branches
//! on).
//!
//! Three things the tests are strict about on purpose:
//!
//! * **The clock is pinned.** The committed fixtures claim a fixed time, and
//!   freshness is a window against *now*: a test that let `now` run would pass
//!   today and fail next week. `--now` exists for exactly this — replaying a
//!   decision the clock cannot move.
//! * **The tampering is done through the library, not with a text editor.** A
//!   mutated document has to stay canonical, or the test proves nothing except
//!   that whitespace is significant. `gitiup-attest` is a dependency of the crate
//!   under test, so the tests re-sign and re-canonicalise the same way production
//!   does.
//! * **A verdict is stdout, an error is stderr.** Exit codes 0/6/7/8 print a report
//!   on stdout and say nothing on stderr; 2 and 3 are the reverse. A CI job that
//!   merges the two streams is common enough that the difference has to be tested,
//!   not assumed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::{AttestationDoc, SignatureEntry, SigningKey, sample};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";

/// The instant the fixtures were signed at plus a few minutes: inside every
/// freshness window, so a passing test means the *checks* passed.
const NOW: &str = "2026-10-27T09:30:00Z";

/// A config home with two keys, a store, and the documents this machine pushed.
struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Harness {
        let harness = Harness {
            dir: tempfile::tempdir().expect("a temp home"),
        };
        harness.key("ada");
        harness.key("bob");
        harness
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
    /// `gitiup.toml` is only found if the test wrote one, and `SSH_AUTH_SOCK`
    /// points where it cannot exist so no test can depend on the developer's agent.
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

    /// Push one fixture run report, signed by `key`, and keep the exact stored
    /// bytes in a file named after the fixture. Returns `push --json`.
    fn push(&self, fixture: &str, key: &str) -> Value {
        let report = fixture_path(fixture);
        let out = self.file(&document(fixture));
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
            "push {fixture} failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        serde_json::from_str(&stdout(&output))
            .unwrap_or_else(|e| panic!("push --json for {fixture}: {e}: {}", stdout(&output)))
    }

    /// File bytes this process already holds (a mutated or unsigned document the
    /// CLI would never have produced itself) at its own digest.
    fn file_document(&self, name: &str, doc: &AttestationDoc) -> (String, Value) {
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
        (
            path,
            serde_json::from_str(&stdout(&output)).expect("push --json"),
        )
    }

    fn doc(&self, fixture: &str) -> AttestationDoc {
        let bytes = std::fs::read(self.file(&document(fixture))).expect("the pushed doc");
        AttestationDoc::from_canonical_bytes(&bytes).expect("the pushed document is canonical")
    }

    fn write_doc(&self, fixture: &str, doc: &AttestationDoc) {
        std::fs::write(
            self.file(&document(fixture)),
            doc.canonical_bytes().expect("canonical"),
        )
        .expect("write the document");
    }

    /// `gitiup verify attestation <doc> … --json`, as `(exit code, json)`.
    fn verify_json<S: AsRef<str>>(&self, fixture: &str, extra: &[S]) -> (i32, Value) {
        let output = self.verify(fixture, extra);
        let value = serde_json::from_str(&stdout(&output)).unwrap_or_else(|e| {
            panic!(
                "verify --json for {fixture}: {e}\nstdout: {}\nstderr: {}",
                stdout(&output),
                stderr(&output)
            )
        });
        (code(&output), value)
    }

    fn verify<S: AsRef<str>>(&self, fixture: &str, extra: &[S]) -> Output {
        let path = self.file(&document(fixture));
        let mut args: Vec<String> = vec!["verify".to_string(), "attestation".to_string(), path];
        args.extend(extra.iter().map(|arg| arg.as_ref().to_string()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&args, None)
    }

    /// The store path of a content-addressed attestation blob.
    fn blob(&self, digest: &str) -> PathBuf {
        let mut blob = PathBuf::from(self.store());
        blob.push("cas");
        blob.push("attestation");
        blob.push(&digest[..2]);
        blob.push(&digest[2..]);
        blob
    }
}

/// The file a pushed fixture's bytes ended up in.
fn document(fixture: &str) -> String {
    format!("{fixture}.attestation.json")
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

/// Trust this machine's `ada`, at the fixtures' own moment. Nearly every test.
fn pinned(extra: &[&str]) -> Vec<String> {
    let mut out = vec!["--trust".to_string(), "ada".to_string()];
    for arg in extra {
        out.push((*arg).to_string());
    }
    out.push("--now".to_string());
    out.push(NOW.to_string());
    out
}

/// Reason codes, in the order the verdict lists them.
fn reason_codes(value: &Value) -> Vec<String> {
    value["reasons"]
        .as_array()
        .expect("reasons is an array")
        .iter()
        .map(|reason| {
            reason["code"]
                .as_str()
                .expect("a reason is {code, detail}")
                .to_string()
        })
        .collect()
}

/// The keys of a JSON object, sorted (which is how the CLI writes them).
fn json_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

/// The outcome of one named check.
fn check(value: &Value, which: &str) -> String {
    value["checks"]
        .as_array()
        .expect("checks is an array")
        .iter()
        .find(|check| check["code"] == which)
        .unwrap_or_else(|| panic!("no check named {which} in {value}"))["outcome"]
        .as_str()
        .expect("an outcome")
        .to_string()
}

/// The key id `ada` signs as, as the store reported it.
fn signer(pushed: &Value) -> String {
    pushed["signers"][0].as_str().expect("a signer").to_string()
}

// ---------------------------------------------------------------------------
// the acceptance path: a real signed attestation, accepted
// ---------------------------------------------------------------------------

#[test]
fn a_signed_local_run_is_accepted() {
    let harness = Harness::new();
    let pushed = harness.push("test-failure", "ada");
    let (code, value) = harness.verify_json("test-failure", &pinned(&["--json"]));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["verdict"], "pass");
    assert_eq!(value["exit"], 0);
    assert_eq!(value["accepted"], true);
    assert_eq!(value["reasons"].as_array().unwrap().len(), 0);
    // The digests are the ones the runner computed and the store filed — recomputed
    // here, not copied out of the document, which is the whole claim.
    assert_eq!(value["attestation"]["run_digest"], pushed["run_digest"]);
    assert_eq!(
        value["attestation"]["result_digest"],
        pushed["result_digest"]
    );
    assert_eq!(value["attestation"]["tier"], "local");
    assert_eq!(
        value["attestation"]["signers"][0]["key_id"],
        signer(&pushed)
    );
    for which in [
        "structure",
        "digest",
        "signature",
        "trust",
        "min_signatures",
        "tier",
        "sandbox",
        "freshness",
    ] {
        assert_eq!(check(&value, which), "passed", "{which} in {value}");
    }
    // Checks nobody asked for are shown as not asked, never as passed.
    for which in ["commit", "result", "challenge", "environment", "expiry"] {
        assert_eq!(check(&value, which), "not_asked", "{which} in {value}");
    }
}

#[test]
fn a_document_can_be_piped_in() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let bytes = std::fs::read(harness.file(&document("test-failure"))).expect("the pushed doc");
    let output = harness.run(
        &[
            "verify",
            "attestation",
            "-",
            "--trust",
            "ada",
            "--now",
            NOW,
            "--json",
        ],
        Some(&String::from_utf8_lossy(&bytes)),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(value["verdict"], "pass");
    assert_eq!(value["source"], "stdin");
}

#[test]
fn a_document_named_on_the_command_line_is_the_document_verified() {
    // The merge-gate case, and the one a default remote could spoil: a working copy
    // has a `gitiup.toml`, so *some* store is always reachable, and the gate still
    // has to verify the file it was handed rather than whatever the remote happens
    // to hold. Getting this backwards verifies one commit and merges another.
    let harness = Harness::new();
    let pushed = harness.push("test-failure", "ada");
    std::fs::write(
        harness.path().join("gitiup.toml"),
        format!(
            "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \"origin\"\
             \nurl = \"file://{}\"\n",
            harness.store()
        ),
    )
    .expect("write gitiup.toml");

    let output = harness.verify("test-failure", &pinned(&["--json"]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(value["verdict"], "pass");
    assert!(
        value["source"].as_str().unwrap_or("").starts_with("file "),
        "the verdict names the document it judged, not a store it could have reached: \
         {}",
        value["source"]
    );
    assert_eq!(
        value["stored"],
        Value::Null,
        "nothing was fetched from a remote"
    );
    assert_eq!(
        value["attestation"]["run_digest"], pushed["run_digest"],
        "and it is the same proof either way, which is why the mistake is invisible"
    );

    // A store named out loud still wins, because the caller said where: the same
    // commit read out of the remote rather than off disk.
    let from_store = harness.run(
        &[
            "verify",
            "attestation",
            "--store",
            &harness.store(),
            "--commit",
            pushed["subject"].as_str().unwrap(),
            "--trust",
            "ada",
            "--now",
            NOW,
            "--json",
        ],
        None,
    );
    assert_eq!(code(&from_store), 0, "{}", stderr(&from_store));
    let value: Value = serde_json::from_str(&stdout(&from_store)).expect("json");
    assert_eq!(value["verdict"], "pass");
    assert!(
        value["source"].as_str().unwrap_or("").contains("fs store"),
        "{}",
        value["source"]
    );
}

#[test]
fn the_table_reports_the_verdict_on_stdout_and_nothing_on_stderr() {
    // A verdict is a result, not a fault. A CI job that pipes both streams into one
    // log must still be able to read the report, and one that reads stderr must not
    // see a "failure" for a proof that was accepted.
    let harness = Harness::new();
    harness.push("test-failure", "ada");

    let accepted = harness.verify("test-failure", &pinned(&[]));
    assert_eq!(code(&accepted), 0, "{}", stderr(&accepted));
    assert!(
        stdout(&accepted).contains("verdict       ACCEPTED (exit 0)"),
        "{}",
        stdout(&accepted)
    );
    assert_eq!(
        stderr(&accepted).trim(),
        "",
        "an accepted run says nothing on stderr"
    );

    let refused = harness.verify("test-failure", &pinned(&["--max-age", "1m"]));
    assert_eq!(code(&refused), 6);
    assert!(stdout(&refused).contains("verdict       POLICY (exit 6)"));
    assert!(stdout(&refused).contains("freshness       REFUSED"));
    assert_eq!(
        stderr(&refused).trim(),
        "",
        "a refused run prints its report, not a fault"
    );

    // `-q` is the one-word form for a shell that only tests the exit code.
    assert_eq!(
        stdout(&harness.verify("test-failure", &pinned(&["-q"]))).trim(),
        "ok"
    );
    assert_eq!(
        stdout(&harness.verify("test-failure", &pinned(&["--max-age", "1m", "--quiet"]))).trim(),
        "freshness"
    );
}

// ---------------------------------------------------------------------------
// the shape, pinned
// ---------------------------------------------------------------------------

#[test]
fn the_json_shape_is_stable_and_the_ladder_is_in_order() {
    // "Stable for tooling" has to mean pinned, or the next refactor moves it and
    // every hook that reads the verdict silently reads nothing.
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (_, pass) = harness.verify_json("test-failure", &pinned(&["--json"]));
    let keys = json_keys(&pass);
    assert_eq!(
        keys,
        vec![
            "accepted",
            "attestation",
            "checks",
            "exit",
            "policy",
            "provenance",
            "reasons",
            "source",
            "stored",
            "verdict"
        ],
        "the top-level keys a script reads, sorted"
    );
    let codes: Vec<&str> = pass["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|c| c["code"].as_str().expect("a code"))
        .collect();
    assert_eq!(
        codes,
        vec![
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
            "expiry"
        ],
        "the check ladder, in ADR-0001 D7 order"
    );
    // The policy block says what the verdict meant, and has the same shape whether
    // or not the document was accepted — a reader compares two verdicts.
    let (_, refused) =
        harness.verify_json("test-failure", &pinned(&["--tier", "simulated", "--json"]));
    assert_eq!(refused["exit"], 6);
    assert_eq!(
        json_keys(&pass["policy"]),
        json_keys(&refused["policy"]),
        "the policy block has the same shape for a pass and a refusal, so two verdicts \
         can be compared field by field"
    );
    assert_eq!(pass["policy"]["min_signatures"], 1);
    assert_eq!(pass["policy"]["now"], NOW);
    assert_eq!(pass["policy"]["tiers"], Value::Array(vec!["local".into()]));
    // Where the bytes came from is printed whatever the answer is, and the answer here is
    // `null`: a file on a command line did not come from a store, so there is nothing to
    // say about how it arrived (ADR-0005 D5 clause 2). The block itself is pinned by
    // [`mirror_reading_cli`], which reads the same documents out of two stores.
    assert_eq!(pass["provenance"], Value::Null, "{pass}");
    assert_eq!(refused["provenance"], Value::Null, "{refused}");
}

#[test]
fn every_reason_is_a_code_and_a_detail_and_all_of_them_are_reported() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (_, value) = harness.verify_json(
        "test-failure",
        &pinned(&["--tier", "simulated", "--require", "arch=amd64", "--json"]),
    );
    assert_eq!(value["exit"], 6);
    assert_eq!(value["verdict"], "policy");
    for reason in value["reasons"].as_array().unwrap() {
        assert!(
            reason["code"].is_string() && reason["detail"].is_string(),
            "a reason is {{code, detail}}: {reason}"
        );
        assert!(
            reason["exit"].is_number(),
            "a reason carries the exit code it alone would produce: {reason}"
        );
        assert_eq!(reason["exit"], 6);
    }
    // The first reason is the one the exit code came from — D7's order, observed.
    assert_eq!(reason_codes(&value)[0], "environment");
    assert!(
        reason_codes(&value).contains(&"tier".to_string()),
        "both complaints are reported, not only the first: {value}"
    );
}

// ---------------------------------------------------------------------------
// exit 6 — refused by policy
// ---------------------------------------------------------------------------

#[test]
fn an_untrusted_signer_is_policy_not_a_bad_signature() {
    // The distinction a reviewer cares about: this was signed correctly, by someone
    // this policy does not vouch for. That is exit 6, not 7.
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (code, value) = harness.verify_json(
        "test-failure",
        &[
            "--trust",
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--now",
            NOW,
            "--json",
        ],
    );
    assert_eq!(code, 6);
    assert_eq!(value["verdict"], "policy");
    assert_eq!(check(&value, "signature"), "passed");
    assert_eq!(check(&value, "trust"), "failed");
    assert_eq!(reason_codes(&value)[0], "trust");
    assert!(reason_codes(&value).contains(&"min_signatures".to_string()));
}

#[test]
fn a_simulated_plan_is_refused_until_someone_allows_it() {
    let harness = Harness::new();
    harness.push("hello", "ada");
    let (code, value) = harness.verify_json("hello", &pinned(&["--json"]));
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value)[0], "tier");
    assert!(
        value["reasons"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("simulated")
    );
    assert_eq!(check(&value, "tier"), "failed");
    assert_eq!(check(&value, "sandbox"), "not_run");

    // And it is a decision the operator can make on purpose.
    let (code, value) = harness.verify_json("hello", &pinned(&["--allow-simulated", "--json"]));
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["verdict"], "pass");
}

#[test]
fn a_stale_proof_is_refused() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (code, value) = harness.verify_json(
        "test-failure",
        &["--trust", "ada", "--now", "2026-12-01T00:00:00Z", "--json"],
    );
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value)[0], "freshness");
    assert_eq!(
        check(&value, "signature"),
        "passed",
        "the proof is fine, it is old"
    );
    assert!(
        value["reasons"][0]["hint"].is_string(),
        "a freshness refusal says what to do about it"
    );
    // The window is the operator's to widen, deliberately.
    let (code, _) = harness.verify_json(
        "test-failure",
        &[
            "--trust",
            "ada",
            "--now",
            "2026-12-01T00:00:00Z",
            "--max-age",
            "60d",
            "--json",
        ],
    );
    assert_eq!(code, 0);
}

#[test]
fn a_run_on_the_wrong_machine_is_refused_by_name() {
    // giti-1rs.4's promise, checked end to end: an aarch64 run offered for a change
    // that requires amd64 gets a sentence about architectures, not a mystery.
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (code, value) = harness.verify_json(
        "test-failure",
        &pinned(&["--require", "arch=amd64", "--json"]),
    );
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value)[0], "environment");
    let detail = value["reasons"][0]["detail"].as_str().unwrap();
    assert!(
        detail.contains("aarch64") && detail.contains("amd64"),
        "the refusal names both machines, so the reader knows which is which: {detail}"
    );
    assert_eq!(value["policy"]["require_env_match"], "strict");
    assert_eq!(value["policy"]["environment_requirement"], "arch=amd64");

    let (code, value) = harness.verify_json(
        "test-failure",
        &pinned(&["--require", "arch=arm64", "--json"]),
    );
    assert_eq!(code, 0, "{value}");
    assert_eq!(check(&value, "environment"), "passed");
}

#[test]
fn too_few_signatures_is_a_policy_refusal() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let (code, value) = harness.verify_json(
        "test-failure",
        &pinned(&["--min-signatures", "2", "--json"]),
    );
    assert_eq!(code, 6);
    assert_eq!(reason_codes(&value)[0], "min_signatures");

    // A second signature over the same manifest is a second vote, and two is enough.
    let co_signer = SigningKey::from_seed(&sample::TEST_SEED);
    let mut doc = harness.doc("test-failure");
    doc.sign(&co_signer).expect("co-sign the same manifest");
    harness.write_doc("test-failure", &doc);
    let (code, value) = harness.verify_json(
        "test-failure",
        &[
            "--trust",
            "ada",
            "--trust",
            &co_signer.public_key().key_id(),
            "--min-signatures",
            "2",
            "--now",
            NOW,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["attestation"]["signers"].as_array().unwrap().len(), 2);
    assert_eq!(check(&value, "min_signatures"), "passed");
}

#[test]
fn an_unsigned_document_proves_nothing() {
    let harness = Harness::new();
    let path = harness.file("unsigned.json");
    std::fs::write(
        &path,
        AttestationDoc::new(sample::local())
            .canonical_bytes()
            .expect("canonical"),
    )
    .expect("write");
    let output = harness.run(
        &[
            "verify",
            "attestation",
            &path,
            "--trust",
            "ada",
            "--now",
            NOW,
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 6, "{}", stdout(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(reason_codes(&value)[0], "min_signatures");
    assert_eq!(check(&value, "signature"), "not_asked", "nothing signed it");
}

#[test]
fn a_policy_file_is_the_policy_the_verdict_is_judged_by() {
    // The file a repo commits next to the change: trust, tiers, freshness and the
    // machine class, read identically by the gate and by the runner.
    let harness = Harness::new();
    let pushed = harness.push("test-failure", "ada");
    let policy = harness.file("gitiup-policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"schema_version":1,"trust_key_ids":["{}"],"allowed_tiers":["local"],"min_signatures":1,"max_age_us":3600000000,"require_arch":"arm64"}}"#,
            signer(&pushed)
        ),
    )
    .unwrap();
    let read = |now: &str| {
        harness.run(
            &[
                "verify",
                "attestation",
                &harness.file(&document("test-failure")),
                "--policy",
                &policy,
                "--now",
                now,
                "--json",
            ],
            None,
        )
    };
    let output = read(NOW);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(
        value["policy"]["trust"]
            .as_str()
            .unwrap()
            .contains("gitiup-policy.json"),
        "the verdict says whose list it used: {value}"
    );
    assert_eq!(value["policy"]["environment_requirement"], "arch=arm64");

    // …and the same file, one hour later, is too old. The file decides, not the tool.
    let output = read("2026-10-27T12:00:00Z");
    assert_eq!(code(&output), 6);
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(reason_codes(&value)[0], "freshness");
}

#[test]
fn a_policy_that_makes_every_key_trusted_says_so_in_the_output() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let output = harness.verify("test-failure", &["--trust-any-key", "--now", NOW]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("ANY key"));
    assert!(stdout(&output).contains("note"));

    // A signature that does not verify is still refused: `--trust-any-key` removes
    // the trust question, never the cryptography.
    let mut doc = harness.doc("test-failure");
    doc.manifest.claims.run_id = "deadbeefcafebabe".into();
    harness.write_doc("test-failure", &doc);
    let output = harness.verify("test-failure", &["--trust-any-key", "--now", NOW]);
    assert_eq!(code(&output), 7, "{}", stdout(&output));
}

#[test]
fn trust_falls_back_to_this_machines_keystore_and_says_so() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let output = harness.verify("test-failure", &["--now", NOW, "--json"]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(
        value["policy"]["trust"]
            .as_str()
            .unwrap()
            .contains("this machine's keystore"),
        "the output says where the trust came from: {value}"
    );
    assert_eq!(
        value["policy"]["trusted_key_ids"].as_array().unwrap().len(),
        2,
        "both of this machine's keys are trusted, and it is printed"
    );
}

#[test]
fn a_key_that_does_not_exist_here_is_refused_not_ignored() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let output = harness.verify("test-failure", &["--trust", "nobody", "--now", NOW]);
    assert_eq!(code(&output), 6, "{}", stderr(&output));
    assert!(stderr(&output).contains("no key 'nobody'"));
}

// ---------------------------------------------------------------------------
// exit 7 — a signature that does not verify
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_edited_after_signing_is_exit_7() {
    // The bytes stay canonical and the document parses; the signature is over
    // different bytes. This is the attack the format exists to catch, and the exit
    // code a gate must not confuse with "the signer is not on my list".
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let mut doc = harness.doc("test-failure");
    doc.manifest.result.steps[0].exit_code = 1;
    harness.write_doc("test-failure", &doc);

    let output = harness.verify("test-failure", &pinned(&["--json"]));
    assert_eq!(code(&output), 7, "{}", stdout(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["verdict"], "bad_signature");
    assert_eq!(reason_codes(&value)[0], "signature");
    assert_eq!(
        check(&value, "digest"),
        "passed",
        "the bytes are their own canonical form; they are just not what was signed"
    );
    assert_eq!(
        value["attestation"]["steps"], 3,
        "the tampered document is still shown"
    );
}

#[test]
fn a_key_id_that_is_not_its_key_is_exit_7() {
    // An entry claiming a famous fingerprint while carrying another key: the
    // identity is a lie, and it fails before the trust list is consulted at all.
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let mut doc = harness.doc("test-failure");
    let stranger = SigningKey::from_seed(&[9u8; 32]);
    let message = doc.signature_message().expect("the payload");
    let mut entry = SignatureEntry::new(&stranger, &message).expect("a signature");
    entry.key_id = sample::test_key_id();
    doc.add_signature(entry);
    harness.write_doc("test-failure", &doc);

    let output = harness.verify("test-failure", &pinned(&["--json"]));
    assert_eq!(code(&output), 7, "{}", stdout(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(reason_codes(&value)[0], "signature");
    assert!(
        value["reasons"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("spoofed")
    );
}

// ---------------------------------------------------------------------------
// exit 8 — digest mismatch
// ---------------------------------------------------------------------------

#[test]
fn bytes_that_are_not_canonical_are_exit_8() {
    // Re-serialising a document is not a cosmetic act: the signature is over these
    // exact bytes, so a transport that reformatted the file has broken the proof.
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let path = harness.file(&document("test-failure"));
    let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("JSON");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).expect("write");

    let output = harness.verify("test-failure", &pinned(&["--json"]));
    assert_eq!(code(&output), 8, "{}", stdout(&output));
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["verdict"], "digest_mismatch");
    assert_eq!(reason_codes(&report)[0], "structure");
    assert_eq!(
        check(&report, "signature"),
        "not_run",
        "nothing after an unreadable document was checked, and the report says so"
    );
    assert_eq!(report["attestation"], Value::Null);
}

#[test]
fn an_attestation_about_the_wrong_commit_is_exit_8() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let other = "a".repeat(40);
    let (code, value) =
        harness.verify_json("test-failure", &pinned(&["--commit", &other, "--json"]));
    assert_eq!(code, 8);
    assert_eq!(value["verdict"], "digest_mismatch");
    assert_eq!(reason_codes(&value)[0], "commit");
    assert!(
        value["policy"]["expected_commit"]
            .as_str()
            .unwrap()
            .starts_with("sha1:aaaa")
    );
}

#[test]
fn a_result_digest_that_is_not_the_one_expected_is_exit_8() {
    let harness = Harness::new();
    harness.push("test-failure", "ada");
    let zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let (code, value) = harness.verify_json(
        "test-failure",
        &pinned(&["--expect-result", zero, "--json"]),
    );
    assert_eq!(code, 8);
    assert_eq!(reason_codes(&value)[0], "result");

    // Named correctly, the same check is the quorum's comparison, and it passes.
    let (_, value) = harness.verify_json(
        "test-failure",
        &pinned(&[
            "--expect-result",
            harness
                .doc("test-failure")
                .result_digest()
                .unwrap()
                .to_string()
                .as_str(),
            "--json",
        ]),
    );
    assert_eq!(value["verdict"], "pass");
    assert_eq!(check(&value, "result"), "passed");
}

// ---------------------------------------------------------------------------
// the store as the source of the document
// ---------------------------------------------------------------------------

#[test]
fn verifying_from_the_store_is_the_merge_gates_own_command() {
    let harness = Harness::new();
    let pushed = harness.push("test-failure", "ada");
    let digest = pushed["digest"].as_str().unwrap().to_string();
    let commit = pushed["subject"].as_str().unwrap().to_string();
    let store = harness.store();
    let run = |extra: &[&str]| -> Output {
        let mut args = vec![
            "verify",
            "attestation",
            "--store",
            &store,
            "--commit",
            &commit,
            "--trust",
            "ada",
            "--now",
            NOW,
        ];
        args.extend(extra);
        harness.run(&args, None)
    };
    let output = run(&["--json"]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["verdict"], "pass");
    assert_eq!(value["stored"], digest);
    assert_eq!(
        value["policy"]["expected_commit"].as_str().unwrap(),
        format!("sha1:{commit}"),
        "asking for a commit's attestation also binds the verdict to that commit"
    );
    assert_eq!(
        value["source"],
        format!("fs store {} · kv/attestation/{digest}", harness.store())
    );

    // Two honest attestations for one commit is a real question, and the tool
    // refuses to answer it by coin toss.
    let mut second = harness.doc("test-failure");
    second.manifest.claims.run_id = "deadbeefdeadbeef".into();
    second.signatures.clear();
    second
        .sign(&SigningKey::from_seed(&sample::TEST_SEED))
        .expect("sign it");
    let (_path, filed) = harness.file_document("second.json", &second);
    assert_eq!(filed["subject"], Value::String(commit.clone()));
    assert_ne!(filed["digest"], Value::String(digest.clone()));

    let output = run(&[]);
    assert_eq!(code(&output), 6, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("name one"),
        "it lists what it could have chosen: {}",
        stderr(&output)
    );

    // Naming one is enough: `--digest` alongside `--commit` says which proof, and
    // the binding still applies.
    let output = harness.run(
        &[
            "verify",
            "attestation",
            "--store",
            &harness.store(),
            "--digest",
            &digest,
            "--commit",
            &commit,
            "--trust",
            "ada",
            "--now",
            NOW,
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_store_that_returns_the_wrong_bytes_is_exit_8() {
    // The ref and the CAS are both evidence. A store that hands back bytes which
    // are not the bytes their name promises has broken the chain from signature to
    // merge, and `verify` says so rather than checking a proof nobody filed.
    let harness = Harness::new();
    let pushed = harness.push("test-failure", "ada");
    let digest = pushed["digest"].as_str().unwrap().to_string();
    let blob = harness.blob(&digest);
    let mut bytes = std::fs::read(&blob).expect("the stored blob");
    bytes.push(b'x');
    std::fs::write(&blob, bytes).expect("corrupt the blob");

    let output = harness.run(
        &[
            "verify",
            "attestation",
            "--store",
            &harness.store(),
            "--digest",
            &digest,
            "--trust",
            "ada",
            "--now",
            NOW,
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 8, "{}", stdout(&output));
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["verdict"], "digest_mismatch");
    assert_eq!(reason_codes(&value)[0], "stored");
    assert_eq!(
        value["attestation"],
        Value::Null,
        "nothing downstream of the bytes is believed"
    );
}

#[test]
fn a_commit_with_no_attestation_is_a_refusal_not_a_crash() {
    let harness = Harness::new();
    let output = harness.run(
        &[
            "verify",
            "attestation",
            "--store",
            &harness.store(),
            "--commit",
            &"e".repeat(40),
            "--trust",
            "ada",
        ],
        None,
    );
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(
        stdout(&output).contains("no attestation"),
        "{}",
        stdout(&output)
    );
}

// ---------------------------------------------------------------------------
// the usage surface
// ---------------------------------------------------------------------------

#[test]
fn usage_and_io_are_not_verdicts() {
    // Exit 2 and 3 mean no decision was made, so they print on stderr and print no
    // report — the opposite contract to 0/6/7/8, and a hook must be able to tell.
    let harness = Harness::new();
    let unknown = harness.run(&["verify", "nonsense"], None);
    assert_eq!(code(&unknown), 2);
    assert_eq!(stdout(&unknown).trim(), "");

    let nothing = harness.run(&["verify", "attestation", "--trust", "ada"], None);
    assert_eq!(code(&nothing), 2);
    assert!(stdout(&nothing).trim().is_empty());

    let missing = harness.run(
        &[
            "verify",
            "attestation",
            "no-such-file.json",
            "--trust",
            "ada",
        ],
        None,
    );
    assert_eq!(code(&missing), 3);
    assert_eq!(stdout(&missing).trim(), "");

    // A policy file that argues with itself is refused before any document is read.
    harness.push("test-failure", "ada");
    let argued = harness.file("bad-policy.json");
    std::fs::write(
        &argued,
        r#"{"require_arch":"amd64","require_env_match":"off"}"#,
    )
    .unwrap();
    let output = harness.verify(
        "test-failure",
        &["--policy", &harness.file("bad-policy.json")],
    );
    assert_eq!(code(&output), 6);
    assert_eq!(
        stdout(&output).trim(),
        "",
        "a policy nobody can read is not a verdict on the document"
    );
}

#[test]
fn the_help_text_and_the_parser_agree() {
    let harness = Harness::new();
    let help = harness.run(&["verify", "--help"], None);
    assert_eq!(code(&help), 0);
    let text = stdout(&help);
    for flag in [
        "--policy",
        "--trust",
        "--tier",
        "--commit",
        "--digest",
        "--store",
        "--now",
        "--json",
        "--quiet",
        "--trust-any-key",
        "--max-age",
        "--expect-result",
        "--require",
    ] {
        assert!(text.contains(flag), "{flag} is missing from `verify help`");
    }
    for line in [
        "0 accepted",
        "2 usage",
        "3 I/O",
        "6 refused",
        "7 a signature",
        "8 digest mismatch",
    ] {
        assert!(
            text.contains(line),
            "`{line}` is missing from `verify help`"
        );
    }
    // And the top-level help points at the command at all.
    assert!(
        stdout(&harness.run(&["help"], None)).contains("verify attestation"),
        "the whole surface lists it"
    );
}

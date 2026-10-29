//! The whole epic, one command line at a time: a run becomes a digest, the digest
//! becomes a signed attestation, the attestation travels with `git fetch`, and a
//! stranger — a different machine, a different config home, no access to anything the
//! runner had — recomputes the digest and checks the signature.
//!
//! The children of giti-1rs each got their own tests (the format, the normaliser, the
//! fingerprint, the store, the keys, the tiers, the verdict). This file exists because
//! an epic's acceptance criterion is a sentence about the *composition*:
//!
//! > A run produces a `RunDigest` that any third party can independently recompute and
//! > whose signature verifies; attestations are stored with the repo and readable via an
//! > ordinary `git fetch`; provenance tier (simulated/local/quorum) is always explicit.
//!
//! Each clause is a section below, and every one is checked from the *third party's*
//! side of the boundary, because that is the only side whose agreement counts:
//!
//! * **independently recompute** — the stranger runs `gitiup digest` on the plain run
//!   report and gets the digests the attestation claims; `gitiup verify attestation`
//!   then re-derives them from the canonical bytes rather than trusting what the
//!   runner printed;
//! * **stored with the repo** — the attestation comes out of a clone made by `git`,
//!   with no gitiup involved in the transport;
//! * **tier always explicit** — the tier is in the signed document, in the listing and
//!   in the verdict, and a `simulated` proof is refused until somebody says otherwise.
//!
//! Key *distribution* is deliberately not here (that is the roster and identity work:
//! giti-msi.2, giti-1rs.6). Both machines import the same ed25519 seed, which is how a
//! test says "this machine holds the key that signed this" without inventing a
//! distribution channel. What is under test is that the bytes a stranger holds
//! re-derive to the digest they name, and check against the key it holds.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

#[path = "common/mod.rs"]
mod common;

/// The clock the fixtures were made against, pinned so freshness is a fact of the
/// test and never of the day it ran.
const NOW: &str = "2026-10-27T09:30:00Z";
/// The passphrase both machines use, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// One ed25519 seed, imported by both the runner and the stranger: the runner holds
/// the private half, the stranger holds "the key that signed this".
const SEED: [u8; 32] = [
    0x9d, 0x2f, 0x6b, 0x11, 0x84, 0xae, 0x37, 0x5c, 0xc0, 0x42, 0x0e, 0x77, 0xb9, 0x10, 0x63, 0x25,
    0xde, 0x08, 0x71, 0x9a, 0x3b, 0x4c, 0xe6, 0xf2, 0x15, 0x88, 0x04, 0x6d, 0xa7, 0x53, 0x90, 0x21,
];
/// A well-formed ResultDigest that is not any run's, for the "right proof, wrong
/// question" case.
const SOMEOTHER_RESULT: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// One machine: a config home, a keystore, its own `gitiup.toml`, and the binary
/// pointed at all three. Every command is a new process, so what survives between them
/// is what the stores hold — not what a variable held.
struct Machine {
    dir: tempfile::TempDir,
}

impl Machine {
    fn new() -> Machine {
        Machine {
            dir: tempfile::tempdir().expect("a temp home"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
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

    fn expect_ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "`gitiup {}` failed: {}{}",
            args.join(" "),
            stdout(&output),
            stderr(&output)
        );
        output
    }

    fn json(&self, args: &[&str]) -> Value {
        json(&self.expect_ok(args))
    }

    /// Run a command whose *verdict* is the output, whatever it exits with. A refusal
    /// is a result, not a crash: `verify` prints the same document and exits 6, 7 or 8
    /// on it, so this is how a test reads the answer it is interested in.
    fn verdict(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        let value = json(&output);
        assert_eq!(
            code_of(&value),
            output.status.code().unwrap_or(-1),
            "the verdict document and the process exit code must agree: {value}"
        );
        value
    }

    /// Import the shared seed as `owner`: for the runner that is "the key I sign
    /// with"; for the stranger it stands in for the owner's published key.
    fn import_key(&self) -> String {
        let seed = self.file("owner.seed");
        // `key import seed` reads hex, which is what a human would paste from another
        // tool; the bytes are the same either way.
        let hex: String = SEED.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&seed, format!("{hex}\n")).expect("write the seed");
        let output = self.expect_ok(&[
            "key",
            "import",
            "seed",
            &seed.display().to_string(),
            "--name",
            "owner",
            "--json",
        ]);
        json(&output)["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }

    /// A `gitiup.toml` naming one remote, in the directory commands run from.
    fn write_remote(&self, name: &str, url: &str) {
        let config = format!(
            "schema-version = 1\ndefault-remote = \"{name}\"\n\n[[remote]]\nname = \
             \"{name}\"\nurl = \"{url}\"\n\n[remote.options]\nwork-dir = \
             \"{}\"\nref-cache-ttl = \"0s\"\n",
            self.file("mirror").display()
        );
        std::fs::write(self.file("gitiup.toml"), config).expect("write gitiup.toml");
    }
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../gitiup-attest/tests/fixtures/runs")
        .join(name)
        .join("run.json")
        .to_str()
        .expect("utf-8")
        .to_string()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|e| {
        panic!(
            "expected json, got: {} ({e})",
            stdout(output).lines().next().unwrap_or("")
        )
    })
}

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

/// The exit code a verdict document reports (`verify` prints the number it exits with,
/// so a script can read either one and get the same answer).
fn code_of(value: &Value) -> i32 {
    value["exit"]
        .as_i64()
        .expect("a verdict carries its exit code") as i32
}

/// The outcome of one named check in a verdict.
fn check(value: &Value, which: &str) -> String {
    value["checks"]
        .as_array()
        .expect("checks is an array")
        .iter()
        .find(|check| check["code"] == which)
        .unwrap_or_else(|| panic!("no {which} check in {value}"))["outcome"]
        .as_str()
        .expect("an outcome")
        .to_string()
}

/// `git`, run in `repo`, failing the test with git's own words rather than returning
/// an error the reader has to interpret.
fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "`git {}` in {} failed: {}",
        args.join(" "),
        repo.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

/// The story up to "the proof is filed", as the things a stranger is allowed to know:
/// the repository's URL, the digests, and the key that signed.
struct Proving {
    /// The smart-HTTP server, kept alive for as long as the test reads from it.
    _server: common::SmartHttp,
    /// The URL every machine reaches the repository by — plain `git`, no forge.
    url: String,
    /// The commit the attestation is about, as a ref component spells it.
    subject: String,
    /// `sha256:` of the canonical document — the store's key.
    digest: String,
    run_digest: String,
    result_digest: String,
    /// The key that signed, as a key id.
    key_id: String,
    /// The machine that ran the workflow, kept alive so its keystore outlives the
    /// test (the stranger never reads from it, and that is the point).
    _runner: Machine,
}

/// Plan (or run) one fixture, sign it, and file it in a repository nothing else has
/// touched. The fixture's own provenance tier is whatever the report says — that is
/// the point of choosing the fixture per test.
///
/// `None` when this box cannot serve smart HTTP: the claim under test is precisely
/// that a `git fetch` carries the proof, so there is no in-process substitute to fall
/// back on. The caller says so out loud rather than reporting a pass.
fn prove(fixture_name: &str) -> Option<Proving> {
    let runner = Machine::new();
    let key_id = runner.import_key();
    let served = runner.file("served");
    std::fs::create_dir_all(&served).expect("served dir");
    let repo = served.join("repo.git");
    gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");
    // Anonymous receives, because that is what a stranger's `git push` and a runner's
    // `attest push` both need from an endpoint like this.
    common::allow_anonymous_receives(&repo);
    let server = common::SmartHttp::serve(&served)?;
    let url = server.url("repo");
    runner.write_remote("origin", &url);

    let pushed = runner.json(&[
        "attest",
        "push",
        "--run-report",
        &fixture(fixture_name),
        "--sign",
        "--key",
        "owner",
        "--remote",
        "origin",
        "--json",
    ]);
    assert!(
        pushed["store"]
            .as_str()
            .unwrap_or("")
            .contains("remote 'origin'"),
        "{pushed}"
    );
    Some(Proving {
        _server: server,
        url,
        subject: pushed["subject"].as_str().expect("a subject").to_string(),
        digest: pushed["digest"].as_str().expect("a digest").to_string(),
        run_digest: pushed["run_digest"]
            .as_str()
            .expect("a run digest")
            .to_string(),
        result_digest: pushed["result_digest"]
            .as_str()
            .expect("a result digest")
            .to_string(),
        key_id,
        _runner: runner,
    })
}

/// The line a test prints instead of pretending to have checked something.
const NEEDS_SMART_HTTP: &str = "skipped: this box has no python3 + git-http-backend, \
and the claim under test is that a real `git fetch` carries the proof";

/// A stranger: a fresh machine that knows the repository's URL and the owner's key and
/// nothing else. It clones with `git` — the transport claim, made by git rather than
/// asserted by gitiup — and reads through its own gitiup, which does its own fetch.
fn stranger(proving: &Proving) -> Machine {
    let stranger = Machine::new();
    stranger.import_key();
    stranger.write_remote("fork", &proving.url);
    stranger
}

/// The attestation's canonical bytes, as read from the stranger's own fetch.
fn stored_bytes(machine: &Machine, proving: &Proving) -> String {
    let output = machine.expect_ok(&[
        "attest",
        "show",
        &proving.digest,
        "--bytes",
        "--remote",
        "fork",
    ]);
    stdout(&output)
}

/// Clone the repository the way a stranger would: `git`, and nothing else.
fn plain_clone(machine: &Machine, proving: &Proving) -> PathBuf {
    let clone = machine.file("clone.git");
    git(
        Path::new("/"),
        &[
            "clone",
            "--mirror",
            &proving.url,
            &clone.display().to_string(),
        ],
    );
    clone
}

#[test]
fn a_stranger_recomputes_the_digest_from_a_plain_clone_and_checks_the_signature() {
    let Some(proving) = prove("test-failure") else {
        eprintln!("{NEEDS_SMART_HTTP}");
        return;
    };

    // ── clause 1, first half: independently recomputable ──────────────────────
    // The stranger is handed the run report — the same file the runner produced, and
    // nothing else — and computes both digests from it. Nobody has told it what the
    // answers are supposed to be.
    let bystander = stranger(&proving);
    let recomputed = bystander.json(&["digest", &fixture("test-failure"), "--json"]);
    assert_eq!(
        recomputed["run_digest"].as_str().unwrap(),
        proving.run_digest,
        "the RunDigest is re-derivable from the run, not remembered by the runner"
    );
    assert_eq!(
        recomputed["result_digest"].as_str().unwrap(),
        proving.result_digest,
        "and so is the ResultDigest independent reruns converge on"
    );

    // ── clause 2: stored with the repo, readable by `git fetch` ───────────────
    // Plain git, no gitiup: the namespace is advertised, and the commit the ref names
    // carries the signed bytes in the same packfile as the ref.
    let clone = plain_clone(&bystander, &proving);
    let ref_name = format!("refs/attestations/{}/{}", proving.subject, proving.digest);
    let refs = git(&clone, &["for-each-ref", "--format=%(refname)"]);
    assert!(
        refs.contains(&ref_name),
        "the proof is advertised to an ordinary git client: {refs}"
    );
    let tip = git(&clone, &["rev-parse", &ref_name]);
    let carried = git(&clone, &["cat-file", "blob", &format!("{tip}:record")]);
    let pointer = git(
        &clone,
        &["cat-file", "blob", &format!("{tip}:gitiup-ref.json")],
    );
    assert!(
        pointer.contains(&proving.digest),
        "the pointer commit names the digest it carries: {pointer}"
    );

    // ── ... and now the stranger, through gitiup, on its own fetch ────────────
    let machine = stranger(&proving);
    let listed = machine.json(&[
        "attest",
        "list",
        "--commit",
        &proving.subject,
        "--remote",
        "fork",
        "--json",
    ]);
    assert_eq!(listed["count"], 1, "{listed}");
    assert!(
        listed["unexpected_refs"].as_array().unwrap().is_empty(),
        "nothing in the attestation namespace went unaccounted for: {}",
        listed["unexpected_refs"]
    );
    let row = &listed["attestations"][0];
    assert_eq!(row["digest"], proving.digest.as_str());
    assert_eq!(
        row["shape"], "current",
        "filed in the layout that holds many"
    );
    assert_eq!(row["tier"], "local", "and the tier travels with it");
    assert_eq!(row["run_digest"], proving.run_digest.as_str());
    assert_eq!(row["result_digest"], proving.result_digest.as_str());

    // The exact bytes, as the stranger's fetch returns them — identical to what plain
    // `git cat-file` produced two commands ago, which is the store saying it did not
    // re-encode a signature on the way out.
    let canonical = stored_bytes(&machine, &proving);
    assert_eq!(
        canonical.trim_end(),
        carried,
        "the bytes gitiup reads back are the bytes git carried"
    );
    let doc = machine.file("proof.json");
    std::fs::write(&doc, canonical.as_bytes()).expect("write the document");

    // ── clause 1, second half: verify re-derives, it never trusts ─────────────
    // `--expect-result` is the stranger's own number, from the run report above: a
    // proof of a different result is refused, and bytes that do not hash to the digest
    // they name would be exit 8.
    let verdict = machine.verdict(&[
        "verify",
        "attestation",
        &doc.display().to_string(),
        "--trust",
        "owner",
        "--commit",
        &proving.subject,
        "--expect-result",
        &proving.result_digest,
        "--tier",
        "local",
        "--max-age",
        "24h",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(code_of(&verdict), 0, "{verdict}");
    assert_eq!(verdict["verdict"], "pass");
    assert_eq!(verdict["reasons"].as_array().unwrap().len(), 0);
    assert_eq!(
        verdict["attestation"]["run_digest"],
        proving.run_digest.as_str()
    );
    assert_eq!(
        verdict["attestation"]["result_digest"],
        proving.result_digest.as_str()
    );
    assert_eq!(verdict["attestation"]["tier"], "local");
    for which in [
        "structure",
        "digest",
        "signature",
        "trust",
        "min_signatures",
        "tier",
        "freshness",
    ] {
        assert_eq!(
            check(&verdict, which),
            "passed",
            "{which} should have been checked and passed"
        );
    }
    // The stranger trusted exactly one key id, and it is the runner's.
    assert_eq!(
        verdict["policy"]["trusted_key_ids"][0],
        proving.key_id.as_str(),
        "and the verdict says whose key it accepted"
    );
}

#[test]
fn a_proof_that_was_touched_after_signing_does_not_verify() {
    // "The signature verifies" is only worth saying if the ways it can fail are the
    // ways an attacker or a helpful proxy would try. All three below are the *same*
    // attestation, each damaged in exactly one way, each read back by a stranger.
    let Some(proving) = prove("test-failure") else {
        eprintln!("{NEEDS_SMART_HTTP}");
        return;
    };
    let machine = stranger(&proving);
    let canonical = stored_bytes(&machine, &proving);
    let parsed: Value = serde_json::from_str(&canonical).expect("the stored bytes are json");

    // (a) Re-serialised on the way through something that thinks JSON is whitespace.
    // Every value is still there; the signature is over the old bytes.
    let prettified = serde_json::to_string_pretty(&parsed).expect("pretty print");
    let reformatted = machine.file("reformatted.json");
    std::fs::write(&reformatted, prettified).expect("write");
    let verdict = machine.verdict(&[
        "verify",
        "attestation",
        &reformatted.display().to_string(),
        "--trust",
        "owner",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(
        code_of(&verdict),
        8,
        "non-canonical bytes are a digest fault: {verdict}"
    );
    assert_eq!(
        check(&verdict, "structure"),
        "failed",
        "and it is caught at the first check, before anything is trusted"
    );
    assert_eq!(
        verdict["reasons"][0]["class"], "digest_mismatch",
        "the reason says which class of fault, not just that something failed"
    );

    // (b) A signature swapped end to end: the manifest is untouched, so the digest
    // checks and the signature cannot. Two characters trade places inside the base64,
    // which stays valid base64 of the same length — the most surgical forgery there is.
    // `SignatureEntry::sig` is the field: `key_id`, `algorithm`, `public_key` and `sig`
    // are the whole of a signature entry, and the bytes of the signature are the part a
    // forger would have to touch.
    let signature = parsed["signatures"][0]["sig"]
        .as_str()
        .expect("a signature value");
    // Two characters trade places, and nothing else changes. The length has to stay put:
    // a base64 string of the same length decodes to the same 64 bytes, so this is a wrong
    // signature rather than a malformed one — the difference between exit 7 and exit 6.
    let mut chars: Vec<char> = signature.chars().collect();
    chars.swap(0, 1);
    let swapped: String = chars.into_iter().collect();
    assert_eq!(
        swapped.chars().count(),
        signature.chars().count(),
        "a swap, not an edit: the forgery has to stay 64 bytes when decoded"
    );
    assert_ne!(swapped, signature, "the swap has to change something");
    let forged = machine.file("forged.json");
    std::fs::write(&forged, canonical.replacen(signature, &swapped, 1)).expect("write");
    let verdict = machine.verdict(&[
        "verify",
        "attestation",
        &forged.display().to_string(),
        "--trust",
        "owner",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(
        code_of(&verdict),
        7,
        "a signature that does not check is exit 7: {verdict}"
    );
    assert!(reason_codes(&verdict).contains(&"signature".to_string()));

    // (c) The right proof about the wrong question: intact, correctly signed, and not
    // a result this stranger was waiting for.
    let intact = machine.file("intact.json");
    std::fs::write(&intact, canonical.as_bytes()).expect("write");
    let verdict = machine.verdict(&[
        "verify",
        "attestation",
        &intact.display().to_string(),
        "--trust",
        "owner",
        "--expect-result",
        SOMEOTHER_RESULT,
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(
        code_of(&verdict),
        8,
        "the wrong result is a digest fault: {verdict}"
    );
    assert!(reason_codes(&verdict).contains(&"result".to_string()));
}

#[test]
fn the_provenance_tier_is_part_of_the_proof_and_is_never_implicit() {
    // The same pipeline for a simulated run: nothing executed, so the attestation says
    // `simulated`, the default policy refuses it, and only somebody saying otherwise —
    // on the command line or in a policy file — changes the answer.
    let Some(proving) = prove("hello") else {
        eprintln!("{NEEDS_SMART_HTTP}");
        return;
    };
    let machine = stranger(&proving);
    let listed = machine.json(&[
        "attest",
        "list",
        "--commit",
        &proving.subject,
        "--remote",
        "fork",
        "--json",
    ]);
    let row = &listed["attestations"][0];
    assert_eq!(row["tier"], "simulated");
    let warning = row["warning"].as_str().unwrap_or("");
    assert!(
        warning.to_ascii_uppercase().contains("SIMULATED"),
        "a listing warns that a simulated proof is a plan, not a run: {row}"
    );

    let doc = machine.file("simulated.json");
    std::fs::write(&doc, stored_bytes(&machine, &proving)).expect("write");

    let refused = machine.verdict(&[
        "verify",
        "attestation",
        &doc.display().to_string(),
        "--trust",
        "owner",
        "--max-age",
        "24h",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(
        code_of(&refused),
        6,
        "a simulated proof is refused until someone allows it: {refused}"
    );
    assert!(reason_codes(&refused).contains(&"tier".to_string()));
    assert_eq!(refused["attestation"]["tier"], "simulated");

    let allowed = machine.verdict(&[
        "verify",
        "attestation",
        &doc.display().to_string(),
        "--trust",
        "owner",
        "--allow-simulated",
        "--max-age",
        "24h",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(code_of(&allowed), 0, "{allowed}");
    assert_eq!(allowed["attestation"]["tier"], "simulated");

    // And a tier no single run can earn is refused by name: a local proof does not
    // become `quorum` by being asked about, it is rejected for not being it.
    let Some(local) = prove("test-failure") else {
        eprintln!("{NEEDS_SMART_HTTP}");
        return;
    };
    let other = stranger(&local);
    let local_doc = other.file("local.json");
    std::fs::write(&local_doc, stored_bytes(&other, &local)).expect("write");
    let verdict = other.verdict(&[
        "verify",
        "attestation",
        &local_doc.display().to_string(),
        "--trust",
        "owner",
        "--tier",
        "quorum",
        "--now",
        NOW,
        "--json",
    ]);
    assert_eq!(code_of(&verdict), 6, "{verdict}");
    assert!(reason_codes(&verdict).contains(&"tier".to_string()));
}

//! A mirror's half of ADR-0005, run as the real binary (giti-g5c).
//!
//! The children of this epic built the transport (`fetch`/`push`, `attest import`); this
//! file tests what the *reading* and the *keeping* owe the same decision, in the two
//! places a mirror actually touches:
//!
//! * **What a copy is worth, printed where it is read** (D5 clauses 1–2). Every verify of
//!   a stored proof carries a `provenance` block — origin or copy, how old, from where —
//!   and the age is computed from the signed `claimed_at_us` and never from arrival, so a
//!   mirror cannot make a proof fresher. `age_basis` is printed because that is the rule a
//!   test can assert rather than admire.
//! * **Retention authority** (D8 rules 2–3). Age is an authority decision, so an age limit
//!   against a store whose proofs all arrived by copy is refused; a mirror evicts for
//!   *capacity*, and only among digests it can name a re-fetch source for; and a retention
//!   record somebody else wrote is evidence to a human, never an instruction to a machine.
//!
//! Everything here is a command line against the built binary in a real store, so the
//! assertions are about what the stores end up holding — not about what a function
//! returned.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{BlobStore, FsHost, Oid};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The run fixtures the rest of the suite attests from.
const FIXTURES: &str = "../gitiup-attest/tests/fixtures/runs";

/// A config home, two stores, and the binary pointed at both.
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

    fn store(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }

    fn file(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
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

    fn key(&self, name: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_gitiup"))
            .args(["key", "gen", "--name", name])
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .current_dir(self.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs")
            .write_stdin_passphrase();
        assert!(output.status.success(), "key gen {name}");
    }

    /// File two signed attestations in `store`, from the repository's own fixtures.
    fn attest_two(&self, store: &str) {
        for fixture in ["hello", "matrix-build"] {
            let report = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(FIXTURES)
                .join(fixture)
                .join("run.json");
            let output = self.run(&[
                "attest",
                "push",
                "--run-report",
                report.to_str().expect("fixture path"),
                "--sign",
                "--key",
                "ada",
                "--store",
                store,
                "--json",
            ]);
            assert!(
                output.status.success(),
                "push {fixture}: {}{}",
                stdout(&output),
                stderr(&output)
            );
        }
    }

    /// Copy the proofs into `to`, re-verifying them there the way `attest import` does.
    fn import(&self, from: &str, to: &str) {
        let output = self.run(&[
            "attest",
            "import",
            "--from",
            from,
            "--to",
            to,
            "--apply",
            "--proofs-only",
            "--trust",
            "ada",
            "--max-age",
            "never",
            "--allow-simulated",
            "--json",
        ]);
        assert!(
            output.status.success(),
            "import: {}{}",
            stdout(&output),
            stderr(&output)
        );
        let report = json(&output);
        assert!(
            !report["imported"].as_array().unwrap().is_empty(),
            "something had to arrive: {}",
            stdout(&output)
        );
    }

    /// The digests a store advertises, in its own order.
    fn digests(&self, store: &str) -> Vec<String> {
        let output = self.run(&["attest", "list", "--all", "--store", store, "--json"]);
        assert!(
            output.status.success(),
            "{}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["digest"].as_str().expect("a digest").to_string())
            .collect()
    }

    /// `gitiup verify attestation` for the first proof a store has.
    fn verify(&self, store: &str, digest: &str) -> (u8, Value) {
        let output = self.run(&[
            "verify",
            "attestation",
            "--store",
            store,
            "--digest",
            digest,
            "--trust",
            "ada",
            "--max-age",
            "never",
            "--allow-simulated",
            "--json",
        ]);
        (code(&output), json(&output))
    }
}

/// A tiny extension so `key gen`'s passphrase can be piped without a second helper.
trait WritePassphrase {
    fn write_stdin_passphrase(self) -> Output;
}

impl WritePassphrase for std::process::Child {
    fn write_stdin_passphrase(mut self) -> Output {
        use std::io::Write as _;
        self.stdin
            .take()
            .expect("stdin was piped")
            .write_all(format!("{PASSPHRASE}\n").as_bytes())
            .expect("write the passphrase");
        self.wait_with_output().expect("wait")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> u8 {
    output.status.code().unwrap_or(1) as u8
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the command printed JSON")
}

fn harness() -> Harness {
    let harness = Harness::new();
    harness.key("ada");
    harness.attest_two(&harness.store("origin"));
    harness
}

// ---------------------------------------------------------------------------
// D5 clauses 1–2: what a copy is worth, printed where it is read
// ---------------------------------------------------------------------------

/// A proof read where it was made says so, and a proof read out of a mirror says that —
/// with the age measured from the claim in both cases, which is the half that makes a
/// mirror harmless rather than merely convenient.
#[test]
fn an_imported_proof_is_marked_a_copy_in_the_reading_and_a_native_one_is_not() {
    let harness = harness();
    let origin = harness.store("origin");
    let mirror = harness.store("mirror");

    let digest = harness.digests(&origin)[0].clone();
    let (at, proof) = harness.verify(&origin, &digest);
    assert_eq!(at, 0, "the origin's own proof verifies: {proof}");
    let provenance = &proof["provenance"];
    assert_eq!(provenance["store"], "origin");
    assert_eq!(provenance["origin_seen"], true);
    assert_eq!(provenance["age_basis"], "claimed_at_us");
    assert_eq!(provenance["closure"], "not-imported");
    assert!(
        provenance["arrived_from"].is_null(),
        "nothing arrived: {provenance}"
    );
    assert!(
        provenance["store_url"].is_string(),
        "the report names where it read: {provenance}"
    );

    harness.import(&origin, &mirror);
    let copied = harness.digests(&mirror)[0].clone();
    let (at, proof) = harness.verify(&mirror, &copied);
    assert_eq!(at, 0, "the copy verifies on its own: {proof}");
    let provenance = &proof["provenance"];
    assert_eq!(provenance["store"], "copy");
    assert_eq!(provenance["origin_seen"], false);
    assert_eq!(
        provenance["age_basis"], "claimed_at_us",
        "D5 clause 1 is a printed field"
    );
    assert_eq!(
        provenance["closure"], "complete",
        "the import walked the closure and says so: {provenance}"
    );
    assert_eq!(provenance["arrived_from"], format!("fs store {origin}"));
    assert!(
        provenance["verified_by"].is_string() && provenance["verify_exit"] == 0,
        "the importing store recorded who checked it: {provenance}"
    );

    // The one number that must not be laundered. The bytes arrived a moment ago, so a
    // reader that measured age from arrival would call this proof brand new; measured
    // from the claim — the only basis that is signed — it is as old as it was at the
    // origin, and a mirror cannot change that without breaking the digest.
    let arrived = provenance["arrived_at_us"]
        .as_i64()
        .expect("an arrival stamp");
    let read_at = provenance["read_at_us"].as_i64().expect("the read's clock");
    let age = provenance["age_us"].as_i64().expect("an age");
    assert!(
        age > read_at - arrived,
        "age {age}µs was measured from the claim, not the arrival ({} since it arrived)",
        read_at - arrived
    );
    let (_, at_origin) = harness.verify(&origin, &digest);
    assert!(
        at_origin["provenance"]["age_us"].as_i64().unwrap() <= age + 60_000_000,
        "the copy is not younger than the proof it came from"
    );
}

/// The same facts, in the words a human reads: the line is there, and it names the
/// arrival rather than pretending the bytes grew here.
#[test]
fn the_human_report_says_where_the_proof_came_from() {
    let harness = harness();
    let origin = harness.store("origin");
    let mirror = harness.store("mirror");
    harness.import(&origin, &mirror);
    let digest = harness.digests(&mirror)[0].clone();
    let output = harness.run(&[
        "verify",
        "attestation",
        "--store",
        &mirror,
        "--digest",
        &digest,
        "--trust",
        "ada",
        "--max-age",
        "never",
        "--allow-simulated",
    ]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("provenance") && text.contains("store copy") && text.contains("arrived from"),
        "{text}"
    );
    assert!(
        text.contains("claimed_at_us"),
        "the age basis is printed, so a report that measured some other way is visibly wrong:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// D8 rule 2: retention authority follows write authority
// ---------------------------------------------------------------------------

/// `--max-age` is a statement about which proofs still matter, and only the store whose
/// policy gates merges on its own proofs may make it. A mirror's copies carry the same
/// `claimed_at_us` as the origin's, so its `--max-age` fires at the same instant
/// everywhere and buys nothing except an earlier deletion.
#[test]
fn an_origin_prunes_by_age_and_a_mirror_is_refused() {
    let harness = harness();
    let origin = harness.store("origin");
    let mirror = harness.store("mirror");
    harness.import(&origin, &mirror);

    let refused = harness.run(&["attest", "gc", "--store", &mirror, "--max-age", "1s"]);
    assert_eq!(
        code(&refused),
        6,
        "a mirror may not prune by age: {}",
        stdout(&refused)
    );
    let why = stderr(&refused);
    assert!(why.contains("mirror_may_not_prune_by_age"), "{why}");
    assert!(
        why.contains("kv/import/") && why.contains("--max-bytes"),
        "the refusal names the evidence it used and the limit the mirror may use: {why}"
    );
    assert_eq!(
        harness.digests(&mirror).len(),
        2,
        "and nothing was pruned on the way to saying so"
    );

    // The same policy, at the store that made the claims: an ordinary plan.
    let planned = harness.run(&[
        "attest",
        "gc",
        "--store",
        &origin,
        "--max-age",
        "1s",
        "--json",
    ]);
    assert_eq!(
        code(&planned),
        0,
        "{}{}",
        stdout(&planned),
        stderr(&planned)
    );
    let report = &json(&planned)["report"];
    assert_eq!(report["pruned"].as_array().unwrap().len(), 2, "{report}");
    assert_eq!(report["dry_run"], true, "a plan is still a plan");
}

/// A mirror *may* throw space back — that is what a cache is for — and it does it among
/// the copies it can name a source for, retiring the advertisement before the bytes.
#[test]
fn a_mirror_evicts_for_capacity_and_a_rerun_moves_nothing() {
    let harness = harness();
    let origin = harness.store("origin");
    let mirror = harness.store("mirror");
    harness.import(&origin, &mirror);

    let planned = harness.run(&[
        "attest",
        "gc",
        "--store",
        &mirror,
        "--max-bytes",
        "1",
        "--json",
    ]);
    assert_eq!(
        code(&planned),
        0,
        "{}{}",
        stdout(&planned),
        stderr(&planned)
    );
    let report = &json(&planned)["report"];
    let pruned = report["pruned"].as_array().unwrap();
    assert_eq!(pruned.len(), 2, "both copies are evictable: {report}");
    for item in pruned {
        assert!(
            item["verdict"].get("over-capacity").is_some(),
            "the reason is capacity, with the source named: {item}"
        );
        assert_eq!(
            item["verdict"]["over-capacity"]["source"],
            format!("fs store {origin}"),
            "and the report says where the bytes can be had again"
        );
    }

    let applied = harness.run(&[
        "attest",
        "gc",
        "--store",
        &mirror,
        "--max-bytes",
        "1",
        "--apply",
        "--json",
    ]);
    assert_eq!(
        code(&applied),
        0,
        "{}{}",
        stdout(&applied),
        stderr(&applied)
    );
    assert!(harness.digests(&mirror).is_empty(), "the copies are gone");
    assert!(
        json(&applied)["report"]["record"].is_string(),
        "the eviction is on the record, like any retention run"
    );

    // Idempotent: a second run has nothing left to say.
    let again = harness.run(&[
        "attest",
        "gc",
        "--store",
        &mirror,
        "--max-bytes",
        "1",
        "--apply",
    ]);
    assert_eq!(code(&again), 0, "{}{}", stdout(&again), stderr(&again));
}

/// A digest this store cannot name a re-fetch source for is not evictable, however
/// badly the limit is missed: forgetting it would make this store the only copy, and a
/// store that cannot say where a thing came from has not earned the right to call it
/// spare. `fetch --no-records` builds exactly that store on purpose.
#[test]
fn a_copy_with_no_named_source_is_reported_and_stays() {
    let harness = harness();
    let origin = harness.store("origin");
    let cold = harness.store("cold");
    let fetched = harness.run(&[
        "fetch",
        "--from",
        &origin,
        "--to",
        &cold,
        "--proofs-only",
        "--no-records",
        "--json",
    ]);
    assert!(
        fetched.status.success(),
        "{}{}",
        stdout(&fetched),
        stderr(&fetched)
    );
    assert_eq!(harness.digests(&cold).len(), 2, "the bytes arrived");
    assert_eq!(
        harness.digests(&cold).len(),
        2,
        "and the store has no idea where they came from"
    );

    let attempt = harness.run(&[
        "attest",
        "gc",
        "--store",
        &cold,
        "--max-bytes",
        "1",
        "--json",
    ]);
    assert_eq!(
        code(&attempt),
        6,
        "the limit was not met, and that is a refusal: {}",
        stdout(&attempt)
    );
    let report = &json(&attempt)["report"];
    assert!(
        report["pruned"].as_array().unwrap().is_empty(),
        "nothing was evicted: {report}"
    );
    let blocked = report["blocked"].as_array().unwrap();
    assert_eq!(blocked.len(), 2, "and every candidate is named: {report}");
    for item in blocked {
        assert_eq!(item["token"], "eviction_needs_source", "{item}");
    }
    assert!(
        stderr(&attempt).contains("eviction_needs_source"),
        "{}",
        stderr(&attempt)
    );
    assert_eq!(
        harness.digests(&cold).len(),
        2,
        "the proofs are still advertised, because nothing was deleted"
    );
}

// ---------------------------------------------------------------------------
// D8 rule 3: a gc record is evidence, never an instruction
// ---------------------------------------------------------------------------

/// A retention record from another store is worth reading — it is how you find out an
/// origin has been pruning — and worth nothing to a machine. The moment one store's
/// deletion could authorise another's, the most cautious mirror in the federation is the
/// one that deletes everything.
#[test]
fn another_stores_retention_record_is_read_and_refused() {
    let harness = harness();
    let origin = harness.store("origin");
    let mirror = harness.store("mirror");
    harness.import(&origin, &mirror);

    // The origin prunes, and leaves a record behind.
    let applied = harness.run(&[
        "attest",
        "gc",
        "--store",
        &origin,
        "--max-age",
        "1s",
        "--apply",
        "--json",
    ]);
    assert_eq!(
        code(&applied),
        0,
        "{}{}",
        stdout(&applied),
        stderr(&applied)
    );
    let record = json(&applied)["report"]["record"]
        .as_str()
        .expect("a kv/gc record")
        .to_string();
    assert_eq!(
        harness.digests(&origin).len(),
        0,
        "the origin pruned its own"
    );

    // Somebody carries that record to the mirror. It lives in the origin's CAS, so that
    // is where it is read from — the same way a human would `git cat-file` it out of a
    // store they were pointed at.
    let oid = Oid::from_hex(record.trim_start_matches("sha256:")).expect("a digest");
    let origin_host = FsHost::open_or_create(&origin).expect("open the origin");
    let bytes = origin_host
        .get(&oid)
        .expect("read the record")
        .expect("the record is in the store it was written to");
    let path = harness.file("their-retention-record.json");
    std::fs::write(&path, &bytes).expect("write the record somewhere the mirror can read");
    let evidence = harness.run(&[
        "attest",
        "gc",
        "--store",
        &mirror,
        "--evidence",
        &path,
        "--json",
    ]);
    assert_eq!(
        code(&evidence),
        6,
        "reading a stranger's deletion plan is a refusal to act on it: {}",
        stdout(&evidence)
    );
    let value = json(&evidence);
    assert_eq!(value["token"], "gc_record_not_instruction", "{value}");
    assert_eq!(value["acted"], false, "{value}");
    assert_eq!(
        value["record"]["pruned"].as_array().unwrap().len(),
        2,
        "and it was printed in full, because that is the useful half"
    );
    assert!(
        stderr(&evidence).contains("gc_record_not_instruction"),
        "{}",
        stderr(&evidence)
    );
    assert_eq!(
        harness.digests(&mirror).len(),
        2,
        "the mirror deleted nothing because a stranger did"
    );

    // The human form says the same thing in one line.
    let text = harness.run(&["attest", "gc", "--store", &mirror, "--evidence", &path]);
    assert_eq!(code(&text), 6);
    assert!(
        stdout(&text).contains("retired 2 attestation(s)"),
        "{}",
        stdout(&text)
    );
}

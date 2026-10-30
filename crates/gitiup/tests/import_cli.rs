//! `gitiup attest import`, run as the real binary (giti-g5c.3).
//!
//! The ticket's acceptance criteria are command lines, so they are tested as command
//! lines: two stores, real signed attestations in one, and every assertion read back out
//! of `--json` or out of the store the import wrote. Each command is a new process, so
//! what survives between them is what the stores hold — the only way to test "a plan
//! writes nothing" and "a re-import overwrites nothing".
//!
//! The library tests around it (`gitiup-host`'s `tests/federation.rs`) cover the write
//! path's invariants. What lives here is the *judgement*: that a proof is re-verified
//! before it is filed, that a failure is reported and skipped without stopping the rest,
//! that a `tier: quorum` document without its evidence is refused, and that the importing
//! store ends up able to say how each byte got there.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::federation::{self, Arrival};
use gitiup_host::{FsHost, RefQuery, RefStore};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The run fixtures the rest of the suite attests from.
const FIXTURES: &str = "../gitiup-attest/tests/fixtures/runs";

/// A config home with two directory stores and two keys.
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

    fn run(&self, args: &[&str]) -> Output {
        self.spawn(args, None)
    }

    fn spawn(&self, args: &[&str], stdin: Option<&str>) -> Output {
        use std::io::Write as _;
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
        let output = self.spawn(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}`: {}{}",
            stdout(&output),
            stderr(&output)
        );
        name.to_string()
    }

    /// Import a *known* seed, so the test process and the CLI hold the same key — which
    /// is how a roster's issuer and the keystore's `owner` are one identity.
    fn seed_key(&self, name: &str, seed: [u8; 32]) {
        let path = self.path().join(format!("{name}.seed"));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let mut child = Command::new(env!("CARGO_BIN_EXE_gitiup"))
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
            "`key import seed {name}`: {}",
            stderr(&output)
        );
    }

    /// File one signed attestation in `store`, from the repository's own run fixtures.
    fn attest(&self, fixture: &str, store: &str, key: &str) -> String {
        let report = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(fixture)
            .join("run.json");
        let output = self.run(&[
            "attest",
            "push",
            "--run-report",
            report.to_str().expect("utf-8"),
            "--sign",
            "--key",
            key,
            "--store",
            store,
            "--json",
        ]);
        assert!(
            output.status.success(),
            "`attest push {fixture}`: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)["digest"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// What a store advertises, as `attest list --all --json` reads it back.
    fn listed(&self, store: &str) -> Vec<String> {
        let output = self.run(&["attest", "list", "--all", "--store", store, "--json"]);
        assert!(
            output.status.success(),
            "{}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)["attestations"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row["digest"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `gitiup attest import --from … --to …`, with the two flags every test in this file
    /// needs and for the reasons it needs them: the subject excuse, because these fixtures
    /// attest commits no store here holds, and an unbounded freshness window, because
    /// freshness is what the freshness test is about and not what the others are.
    fn import(&self, from: &str, to: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "attest",
            "import",
            "--from",
            from,
            "--to",
            to,
            "--allow-missing-subject",
            "--max-age",
            "never",
        ];
        args.extend(extra);
        self.run(&args)
    }

    /// The microsecond a stored attestation claims, so a test can pin its clock to the
    /// document instead of to the day it happened to run on.
    fn claim_us(&self, store: &str, digest: &str) -> i64 {
        let output = self.run(&["attest", "list", "--all", "--store", store, "--json"]);
        let value = json(&output);
        value["attestations"]
            .as_array()
            .expect("the listing")
            .iter()
            .find(|row| row["digest"].as_str() == Some(digest.trim_start_matches("sha256:")))
            .expect("the attestation is listed")["claimed_at_us"]
            .as_i64()
            .expect("a claimed time")
    }

    /// The arrival records one store holds: its own answer to *how did this get here*.
    fn arrivals(&self, store: &str) -> Vec<Arrival> {
        let host = FsHost::open_or_create(store).expect("open the store");
        let mut out: Vec<Arrival> = federation::arrivals(&host)
            .expect("list arrivals")
            .into_values()
            .collect();
        out.sort_by(|a, b| a.digest.cmp(&b.digest));
        out
    }

    /// The refs a store advertises under one prefix.
    fn refs(&self, store: &str, prefix: &str) -> Vec<String> {
        let host = FsHost::open_or_create(store).expect("open the store");
        host.list_refs(&RefQuery::prefix(prefix))
            .expect("list refs")
            .into_iter()
            .map(|reference| reference.name.as_str().to_string())
            .collect()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

/// One check's outcome, out of a `--json` verify report.
fn check(value: &Value, wanted: &str) -> String {
    value["checks"]
        .as_array()
        .expect("every report prints its checks")
        .iter()
        .find(|row| row["code"] == wanted)
        .map(|row| row["outcome"].as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| panic!("no check named {wanted} in {value}"))
}

/// A clock for `--now`, from microseconds since the epoch.
fn clock(us: i64) -> String {
    gitiup_attest::TimeUs(us).to_rfc3339()
}

/// Tokens the report refused with, so a test can say *which* refusal, not just *some*.
fn tokens(value: &Value) -> Vec<String> {
    value["refused"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["token"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// the plan, the write, and the record of it
// ---------------------------------------------------------------------------

/// `--dry-run` — and a bare run, which plans too — reads and verifies and writes nothing;
/// `--apply` files the proof, and the importing store can then answer how it got there.
#[test]
fn a_plan_writes_nothing_and_apply_files_the_proof_and_records_it() {
    let harness = Harness::new();
    harness.key("ada");
    let upstream = harness.store("upstream");
    let down = harness.store("down");
    let digest = harness.attest("matrix-build", &upstream, "ada");

    let plan = harness.run(&[
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--allow-missing-subject",
        "--max-age",
        "never",
        "--json",
    ]);
    assert!(plan.status.success(), "{}{}", stdout(&plan), stderr(&plan));
    let planned = json(&plan);
    assert_eq!(planned["verb"], "import");
    assert_eq!(planned["plan_only"], true);
    assert_eq!(
        planned["imported"].as_array().map(|rows| rows.len()),
        Some(1),
        "the plan imported nothing: {planned}"
    );
    // A plan reports what it *would* take — the same counts the real run reports — and
    // writes none of it, which is what the store says below.
    assert_eq!(
        planned["dry_run"], true,
        "a plan does not say it is a plan: {planned}"
    );
    assert_eq!(
        planned["objects"]["arrived"], 1,
        "the plan took nothing to mean: {planned}"
    );
    assert_eq!(planned["records"], 0);
    // And the destination is untouched: not one ref, not one blob, no arrival record.
    assert!(
        harness.listed(&down).is_empty(),
        "a plan filed a proof: {:?}",
        harness.listed(&down)
    );
    assert!(harness.arrivals(&down).is_empty());

    let applied = harness.run(&[
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--allow-missing-subject",
        "--max-age",
        "never",
        "--apply",
        "--json",
    ]);
    assert!(
        applied.status.success(),
        "{}{}",
        stdout(&applied),
        stderr(&applied)
    );
    let report = json(&applied);
    assert_eq!(report["plan_only"], false);
    assert!(report["objects"]["arrived"].as_u64().unwrap() >= 1);
    assert!(report["refs"]["written"].as_u64().unwrap() >= 1);
    assert_eq!(report["trust"], "none", "an import granted trust: {report}");
    assert_eq!(
        harness.listed(&down),
        vec![digest.trim_start_matches("sha256:").to_string()],
        "the copy does not read back"
    );

    // The audit answer a mirror exists to make possible.
    let arrivals = harness.arrivals(&down);
    assert_eq!(arrivals.len(), 1, "{arrivals:?}");
    let arrival = &arrivals[0];
    assert_eq!(arrival.record_type, "gitiup-import-1");
    assert_eq!(arrival.digest, digest.trim_start_matches("sha256:"));
    assert_eq!(arrival.arrived_from, format!("fs store {}", upstream));
    assert_eq!(arrival.closure, "complete");
    assert_eq!(
        arrival.verify_exit,
        Some(0),
        "the record does not say what the check said: {arrival:?}"
    );
    assert!(
        arrival.verified_by.is_some(),
        "the record does not say who checked: {arrival:?}"
    );
    assert_eq!(
        arrival.subject_excused.as_deref(),
        Some("--allow-missing-subject"),
        "an excuse has to be recorded, not implied: {arrival:?}"
    );
    assert!(
        arrival
            .refs
            .iter()
            .any(|reference| reference.starts_with("refs/attestations/")),
        "{arrival:?}"
    );
}

/// Re-running an import writes nothing and overwrites nothing, and still re-verifies: a
/// blob that is already here was verified by whoever put it here, whose trust roots this
/// reader does not share (D4, "no waiver for duplicates").
#[test]
fn a_reimport_writes_nothing_and_overwrites_nothing() {
    let harness = Harness::new();
    harness.key("ada");
    let upstream = harness.store("upstream");
    let down = harness.store("down");
    harness.attest("matrix-build", &upstream, "ada");
    let args = [
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--allow-missing-subject",
        "--max-age",
        "never",
        "--apply",
        "--json",
    ];
    let first = json(&harness.run(&args));
    let second = json(&harness.run(&args));
    assert_eq!(first["objects"]["arrived"].as_u64().unwrap(), 1);
    assert_eq!(
        second["objects"]["arrived"], 0,
        "the second run stored bytes again: {second}"
    );
    assert!(second["objects"]["already"].as_u64().unwrap() >= 1);
    assert_eq!(
        second["refs"]["written"], 0,
        "the second re-wrote an advertisement: {second}"
    );
    assert!(second["objects"]["rehashed"].as_u64().unwrap() >= 1);
    assert_eq!(
        second["imported"].as_array().map(|rows| rows.len()),
        Some(1),
        "a duplicate was exempted from verification: {second}"
    );
    // …and one arrival record, because nothing arrived the second time.
    assert_eq!(harness.arrivals(&down).len(), 1);
}

/// A proof is judged against *this* clock and *this* trust list, not the origin's.
///
/// The clock is pinned around the document's own claim, so the test says what it means
/// whatever day it runs: the same bytes, in the same two stores, are acceptable an hour
/// after they were claimed and stale a year before that — because freshness is a window
/// against *here and now* and not a fact the origin got to settle (D5 clause 1).
#[test]
fn freshness_is_evaluated_here_and_not_as_the_origin_last_saw_it() {
    let harness = Harness::new();
    harness.key("ada");
    let upstream = harness.store("upstream");
    let down = harness.store("down");
    let digest = harness.attest("matrix-build", &upstream, "ada");
    let claimed = harness.claim_us(&upstream, &digest);

    // The control: judged an hour after it was claimed, it is fresh, and it arrives.
    let fresh = harness.import(
        &upstream,
        &down,
        &[
            "--now",
            &clock(claimed + 3_600_000_000),
            "--apply",
            "--json",
        ],
    );
    let report = json(&fresh);
    assert_eq!(code(&fresh), Some(0), "{report}");
    assert_eq!(
        report["imported"].as_array().map(|rows| rows.len()),
        Some(1)
    );

    // The same bytes, judged a year before they were claimed: future-dated, and refused
    // for it. Nothing about the document changed; only this machine's clock did.
    let stale = harness.import(
        &upstream,
        &down,
        &[
            "--now",
            &clock(claimed - 31_536_000_000_000),
            "--apply",
            "--json",
        ],
    );
    let report = json(&stale);
    assert_eq!(code(&stale), Some(0), "{report}");
    assert!(
        tokens(&report).contains(&"expired".to_string()),
        "a future-dated claim was not refused as stale: {report}"
    );
    assert!(
        harness.listed(&down).len() == 1,
        "the refusal filed something too"
    );

    // `--strict` is for the job that would rather know something was skipped.
    let strict = harness.import(
        &upstream,
        &down,
        &[
            "--now",
            &clock(claimed - 31_536_000_000_000),
            "--strict",
            "--apply",
        ],
    );
    assert_eq!(code(&strict), Some(6), "{}", stderr(&strict));
}

/// One unimportable proof does not end an import of two: the trusted one lands, the
/// signer this machine does not trust is reported and skipped, and the command succeeds
/// because a scope refusal is scope and not damage.
#[test]
fn a_refused_document_is_reported_and_skipped_and_the_rest_still_arrives() {
    let harness = Harness::new();
    harness.key("ada");
    harness.key("bob");
    let upstream = harness.store("upstream");
    let down = harness.store("down");
    let trusted = harness.attest("matrix-build", &upstream, "ada");
    let stranger = harness.attest("test-failure", &upstream, "bob");

    let output = harness.run(&[
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--allow-missing-subject",
        "--max-age",
        "never",
        "--trust",
        "ada",
        "--apply",
        "--json",
    ]);
    let report = json(&output);
    assert_eq!(
        code(&output),
        Some(0),
        "a per-record refusal failed the whole import: {report}"
    );
    assert_eq!(report["offered"], 2);
    assert_eq!(report["in_scope"], 2);
    assert_eq!(
        report["imported"].as_array().map(|rows| rows.len()),
        Some(1)
    );
    assert_eq!(report["refused"].as_array().map(|rows| rows.len()), Some(1));
    assert!(tokens(&report).contains(&"signer_untrusted".to_string()));
    assert_eq!(
        report["refused"][0]["exit"], 6,
        "a trust refusal is a 6: {report}"
    );
    assert_eq!(
        harness.listed(&down),
        vec![trusted.trim_start_matches("sha256:").to_string()],
        "{trusted} should have arrived and {stranger} should not have"
    );

    // And the refusal says which document it was about, in a form a log can use.
    let refused = &report["refused"][0];
    assert_eq!(
        refused["digest"].as_str().unwrap_or_default(),
        stranger.trim_start_matches("sha256:"),
        "the refusal does not name the document it refused: {report}"
    );
    assert!(
        refused["reference"]
            .as_str()
            .unwrap_or_default()
            .starts_with("refs/attestations/")
    );
    assert!(refused["detail"].as_str().unwrap_or_default().len() > 10);
}

/// Without the excuse, a proof about an object this store cannot name is refused — the
/// ticket's "never imports an attestation whose subject is not present", and the reason
/// `--proofs-only` exists and says what it means.
#[test]
fn a_subject_that_is_not_here_is_refused_unless_it_is_excused() {
    let harness = Harness::new();
    harness.key("ada");
    let upstream = harness.store("upstream");
    let down = harness.store("down");
    harness.attest("matrix-build", &upstream, "ada");

    let output = harness.run(&[
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--max-age",
        "never",
        "--apply",
        "--json",
    ]);
    let report = json(&output);
    assert!(
        tokens(&report).contains(&"subject_missing".to_string()),
        "the missing subject went unremarked: {report}"
    );
    assert!(harness.listed(&down).is_empty());

    // `--proofs-only` is the same excuse with the reason attached, and it says so in the
    // record, so "deliberately not here" and "lost" stay two sentences.
    let excused = harness.run(&[
        "attest",
        "import",
        "--from",
        &upstream,
        "--to",
        &down,
        "--max-age",
        "never",
        "--proofs-only",
        "--apply",
        "--json",
    ]);
    assert!(
        excused.status.success(),
        "{}{}",
        stdout(&excused),
        stderr(&excused)
    );
    let value = json(&excused);
    assert_eq!(value["imported"].as_array().map(|rows| rows.len()), Some(1));
    assert_eq!(
        value["subject"]["excused_by"],
        "--proofs-only implies --allow-missing-subject"
    );
    let arrival = &harness.arrivals(&down)[0];
    assert_eq!(
        arrival.subject_excused.as_deref(),
        Some("--proofs-only implies --allow-missing-subject")
    );
}

/// Two stores that are one store is not an import: the refusal is a usage-level "no" and
/// nothing is read or written.
#[test]
fn a_store_is_not_its_own_source() {
    let harness = Harness::new();
    harness.key("ada");
    let upstream = harness.store("upstream");
    let output = harness.run(&["attest", "import", "--from", &upstream, "--to", &upstream]);
    assert_eq!(code(&output), Some(6), "{}", stderr(&output));
}

/// `gitiup attest import help` says what the flag list refuses, and the exit codes it
/// uses, for the same reason every other verb's help does: an absent flag is easy for a
/// well-meaning reader to "fix".
#[test]
fn the_help_names_the_verb_and_refuses_a_trust_flag() {
    let harness = Harness::new();
    let help = harness.run(&["attest", "import", "help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    assert!(text.contains("attest import"), "{text}");
    assert!(
        text.contains("re-verify") || text.contains("re-verif"),
        "{text}"
    );
    for flag in [
        "--trust-remote",
        "--from-trusted",
        "--trusted-store",
        "--trust-source",
    ] {
        assert!(!text.contains(flag), "the help advertises {flag}: {text}");
        let output = harness.run(&["attest", "import", "--from", "./a", "--to", "./b", flag]);
        assert_eq!(
            code(&output),
            Some(2),
            "{flag} was accepted: {}",
            stderr(&output)
        );
    }
}

// ---------------------------------------------------------------------------
// the one document the copy exists to carry
// ---------------------------------------------------------------------------

const CHANGE: &str = "giti-a1b2c3";
const JOB: &str = "9f3a1c0d2e4b5a67";
/// The seed the quorum fixtures' roster issuer signs with, so the CLI's `owner` and the
/// roster's issuer are one identity.
const OWNER_SEED: [u8; 32] = [1u8; 32];

/// A store with a real quorum round in it: a roster, a round, enough sealed submissions
/// to meet the threshold, and the `tier: quorum` attestation the verdict earns — every
/// one of them made by the CLI, none of them by hand.
struct Scene {
    harness: Harness,
    now: String,
    head: String,
}

impl Scene {
    fn new() -> Scene {
        use gitiup_quorum::{derive::SelectionSecret, round::Round, sample, store};
        let harness = Harness::new();
        harness.seed_key("owner", OWNER_SEED);
        for index in 0..6 {
            harness.key(&format!("p{index}"));
        }
        let store = harness.store("upstream");
        let host = FsHost::open_or_create(&store).expect("open the source store");
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("publish the roster");
        let inputs = sample::round_inputs(&roster, CHANGE, JOB);
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
        round.sign(&owner).expect("the selector signs");
        store::publish_round(&host, &round).expect("publish the round");
        let round = store::round_at(&host, CHANGE, JOB, 0)
            .expect("read the round")
            .expect("the round is open");
        let seats = sample::indices_of(&round);
        let docs = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(seats[position]).public_key().key_id();
            store::publish_submission(&host, &round, &key_id, doc).expect("the seat is filled");
        }
        let head = round.inputs.head_oid.hex();
        Scene {
            harness,
            now: sample::clock().to_rfc3339(),
            head,
        }
    }

    fn harness(&self) -> &Harness {
        &self.harness
    }

    /// The digest the source store filed the quorum attestation under.
    fn attest_into_store(&self) -> String {
        let store = self.harness.store("upstream");
        let output = self.harness.run(&[
            "quorum",
            "verdict",
            CHANGE,
            "--job",
            JOB,
            "--store",
            &store,
            "--now",
            &self.now,
            "--attest",
            "store",
            "--key",
            "owner",
            "--publish",
            "--json",
        ]);
        assert!(
            output.status.success(),
            "`quorum verdict --attest store`: {}{}",
            stdout(&output),
            stderr(&output)
        );
        json(&output)["jobs"][0]["attestation"]["digest"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// `gitiup attest import` of the source store, asking for the quorum document.
    fn import(&self, to: &str, extra: &[&str]) -> Output {
        let upstream = self.harness.store("upstream");
        self.import_from(&upstream, to, extra)
    }

    /// The same, from whichever store the test wants read — which matters because the
    /// whole point of the verb is that the source decides what can be believed.
    fn import_from(&self, from: &str, to: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "attest",
            "import",
            "--from",
            from,
            "--to",
            to,
            "--tier",
            "quorum",
            "--trust",
            "owner",
            "--now",
            &self.now,
            "--proofs-only",
        ];
        args.extend(extra);
        self.harness.run(&args)
    }
}

/// The point of the whole document: one run's quorum attestation is worthless on its own,
/// and an import is what turns it into evidence a stranger can re-derive from — because
/// it walks the citations first and refuses the set that has no foot.
#[test]
fn a_quorum_attestation_arrives_with_the_evidence_it_points_at() {
    let scene = Scene::new();
    let digest = scene.attest_into_store();
    let down = scene.harness().store("down");

    let output = scene.import(&down, &["--apply", "--json"]);
    let report = json(&output);
    assert_eq!(code(&output), Some(0), "{report}");
    assert_eq!(report["refused"].as_array().map(|rows| rows.len()), Some(0));
    assert_eq!(
        report["imported"].as_array().map(|rows| rows.len()),
        Some(1)
    );
    // The closure is more than the document: the verdict, the round, the roster, the
    // reveals, and every digest they name.
    assert!(
        report["refs"]["written"].as_u64().unwrap() > 5,
        "the closure was not carried: {report}"
    );
    assert_eq!(report["imported"][0]["tier"], "quorum");
    // The verdict was advertised by the source, so it was copied — and the report says
    // which edges had nothing to copy and were closed by derivation instead.
    let derived = report["imported"][0]["derived"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| row.as_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        derived.iter().any(|edge| edge.starts_with("policy_digest")),
        "the selection policy inside the round is reported as derived: {derived:?}"
    );
    assert!(
        !derived
            .iter()
            .any(|edge| edge.starts_with("verdict_digest")),
        "a verdict the source advertised was not copied: {derived:?}"
    );

    // The store can name every ref the citations pointed at.
    let refs = scene.harness().refs(&down, "refs/");
    for prefix in [
        "refs/gitiup/verdict/",
        "refs/gitiup/round/",
        "refs/gitiup/roster/",
        "refs/gitiup/reveal/",
    ] {
        assert!(
            refs.iter().any(|name| name.starts_with(prefix)),
            "the copy has no {prefix}: {refs:?}"
        );
    }
    assert!(
        refs.iter()
            .any(|name| name.starts_with("refs/attestations/"))
    );

    // And the destination can now do the thing only a copy can do: re-derive the verdict
    // from the bytes it holds, with no reference to where they came from.
    let checked = scene.harness().run(&[
        "verify",
        "attestation",
        "--store",
        &down,
        "--digest",
        &digest,
        "--tier",
        "quorum",
        "--trust",
        "owner",
        "--now",
        &scene.now,
        "--json",
    ]);
    let checked = json(&checked);
    assert_eq!(
        checked["accepted"], true,
        "the imported closure does not verify on its own: {checked}"
    );
    for code in ["verdict", "roster", "round", "signature", "trust"] {
        assert_eq!(
            check(&checked, code),
            "passed",
            "the imported closure does not answer for itself: {checked}"
        );
    }
    assert_eq!(checked["quorum"]["state"], "verified");

    // The arrival record says so, and names the source it walked.
    let arrivals = scene.harness().arrivals(&down);
    let arrival = arrivals
        .iter()
        .find(|arrival| arrival.digest == digest.trim_start_matches("sha256:"))
        .expect("an arrival record for the quorum attestation");
    assert_eq!(arrival.closure, "complete");
    assert!(
        arrival
            .refs
            .iter()
            .any(|name| name.starts_with("refs/gitiup/verdict/")),
        "the record does not say the verdict came with it: {:?}",
        arrival.refs
    );
    // …and it is not portable: nothing written beside the copy could travel with it.
    assert!(
        scene
            .harness()
            .refs(&down, "kv/")
            .iter()
            .all(|name| !name.starts_with("refs/"))
    );
}

/// The same document in a store that never had its evidence is a rumour, and an import
/// says which citation has no foot instead of filing it. The store is built the way a
/// hand-rolled mirror builds one: take the ref that was advertised, and never ask what the
/// bytes point at.
#[test]
fn a_quorum_attestation_whose_evidence_is_not_offered_is_refused() {
    let scene = Scene::new();
    let digest = scene.attest_into_store();
    let upstream = scene.harness().store("upstream");
    let naive = scene.harness().store("naive");
    lone_copy(&upstream, &naive, &digest);

    let listed = scene.harness().listed(&naive);
    assert!(
        listed
            .iter()
            .any(|row| row == digest.trim_start_matches("sha256:")),
        "the mirror did not take the attestation: {listed:?}"
    );
    for prefix in [
        "refs/gitiup/verdict/",
        "refs/gitiup/round/",
        "refs/gitiup/reveal/",
    ] {
        assert!(
            scene.harness().refs(&naive, prefix).is_empty(),
            "the mirror has {prefix}, so this test proves nothing"
        );
    }
    // It took the one ref that was advertised, spelled exactly as the source spelled it —
    // which is the whole failure mode: a copy of a ref is not a copy of an argument.
    assert!(
        scene
            .harness()
            .refs(&naive, &format!("refs/attestations/{}/", scene.head))
            .iter()
            .any(|name| name.ends_with(digest.trim_start_matches("sha256:"))),
        "the mirror's copy is not filed under the head it speaks about"
    );

    let down = scene.harness().store("down");
    let output = scene.import_from(&naive, &down, &["--apply", "--json"]);
    let report = json(&output);
    assert!(
        tokens(&report).contains(&"closure_incomplete".to_string()),
        "a quorum attestation with no evidence in its source was filed: {report}"
    );
    assert_eq!(
        report["imported"].as_array().map(|rows| rows.len()),
        Some(0)
    );
    let detail = report["refused"][0]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("round_digest"),
        "the refusal does not say which citation has no foot: {report}"
    );
    assert!(
        scene.harness().listed(&down).is_empty(),
        "the rumour was filed"
    );
    assert!(scene.harness().arrivals(&down).is_empty());

    // …and for the operator who asked to be told, that refusal is the command's verdict.
    let strict = scene.import_from(&naive, &down, &["--apply", "--strict"]);
    assert_eq!(code(&strict), Some(6), "{}", stderr(&strict));
    assert!(scene.harness().listed(&down).is_empty());
}

/// Copy exactly one digest, with the same write path `gitiup fetch` uses, narrowed to the
/// one object a naive mirror would have taken.
fn lone_copy(from: &str, to: &str, digest: &str) {
    let source = FsHost::open_or_create(from).expect("open the source");
    let sink = FsHost::open_or_create(to).expect("open the destination");
    let mut only = std::collections::BTreeSet::new();
    only.insert(digest.trim_start_matches("sha256:").to_string());
    let mut options = federation::Options::new(
        federation::Verb::Fetch,
        format!("fs store {from}"),
        format!("fs store {to}"),
    );
    options.only = Some(only);
    options.proofs_only = true;
    options.record_arrivals = false;
    federation::copy(&source, &sink, &options).expect("the lone copy runs");
}

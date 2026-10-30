//! `gitiup quorum dispute`, run as the real binary (giti-zp1.7).
//!
//! The ticket's acceptance criteria are a report and its exit codes, so they are tested as
//! command lines against the built executable:
//!
//! ```text
//! gitiup quorum dispute <change> [--job …] [--logs <dir>] [--json]
//!     → the distinct ResultDigests and their counts
//!     → the seats involved, the sandbox rung each used, each machine's environment
//!       fingerprint
//!     → the losing logs: the raw diff and the same diff after gitiup-normalise, side by
//!       side, saying per hunk whether the difference is about the build or the machine
//!     → exit 0 nothing to dispute · 6 failed/insufficient · 7 bad signature ·
//!       8 a digest that is not what it names, including a --logs file that is not the
//!       run its seat signed
//! ```
//!
//! Three things are checked on every run, because they are the contract a human reads the
//! report under time pressure with:
//!
//! * **the exit code is the verdict's**. `dispute` re-decides nothing, so a scene tallied
//!   at 6 disputes at 6; a test that let the report disagree with the gate would let a
//!   friendly-looking report argue with a merge refusal.
//! * **stdout is the report and stderr stays empty**, including on the refusals.
//! * **an unverified log never becomes evidence.** The one test that hands over a log that
//!   does not hash to what its seat signed expects exit 8, not a report built out of it.

use std::path::Path;
use std::process::{Command, Output};

use gitiup_attest::SigningKey;
use gitiup_host::FsHost;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use serde_json::Value;

/// The passphrase every harness supplies the only way a script can.
const PASSPHRASE: &str = "four random words";
const CHANGE: &str = "chg-000000000000f00d";
const BUILD: &str = "build/matrix/linux-x86_64";
/// The seed `sample::owner_key()` is derived from, imported so the CLI's trust roots and
/// the fixture's are the same keys.
const OWNER_SEED: [u8; 32] = [1u8; 32];

/// The log the three agreeing seats ran, byte for byte.
///
/// Exactness matters twice over: the fixture hashes the text it is given with no
/// normalisation (`normalisation_version` 0), so a file that differs from the run by a
/// single newline is a different run; and the duration is there so that the slower
/// machine's log differs *only* in the one thing normalisation is defined to erase.
const AGREEING: &str = "test result: ok. 42 passed, 0 failed in 1.234s";
/// The same build on a slower machine: the raw text differs, the normalised text does not.
const SLOWER: &str = "test result: ok. 42 passed, 0 failed in 9.876s";
/// A build that did something else, in the same time.
const FAILED: &str = "test result: FAILED. 41 passed, 1 failed in 1.234s";

/// What seat `position` of the round ran, and so what its log file has to contain.
///
/// One function for both halves — what the fixture attests and what the test hands over —
/// because if they drifted the log check would be testing nothing.
fn text_for(position: usize) -> String {
    match position {
        3 => SLOWER.to_string(),
        4 => FAILED.to_string(),
        _ => AGREEING.to_string(),
    }
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

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

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, None)
    }

    /// Run the binary in this home. The cwd is the temp dir, so no stray `gitiup.toml` can
    /// leak in, and `SSH_AUTH_SOCK` points where no agent can exist.
    fn run_with(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_POLICY")
            .current_dir(self.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if stdin.is_some() {
            command.stdin(std::process::Stdio::piped());
        } else {
            command.stdin(std::process::Stdio::null());
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

    fn seed_key(&self, name: &str, seed: [u8; 32]) -> String {
        let path = self.path().join(format!("{name}.seed"));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let output = self.run_with(
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
        let listed = self.run(&["key", "list", "--json"]);
        let keys: Vec<Value> = serde_json::from_str(&stdout(&listed)).expect("key list json");
        keys.iter()
            .find(|record| record["name"].as_str() == Some(name))
            .expect("the key is listed")["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }
}

/// A store as the owner left it, with one round and whichever seats have voted.
struct Scene {
    harness: Harness,
    owner: SigningKey,
    roster: Roster,
    now: String,
}

impl Scene {
    fn new() -> Scene {
        let harness = Harness::new();
        harness.seed_key("owner", OWNER_SEED);
        let owner = sample::owner_key();
        let host = FsHost::open_or_create(harness.store()).expect("open the store");
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("publish the roster");
        let scene = Scene {
            harness,
            owner,
            roster,
            now: sample::clock().to_rfc3339(),
        };
        scene.open_round(BUILD, 0);
        scene
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.harness.store()).expect("open the store")
    }

    fn store(&self) -> String {
        self.harness.store()
    }

    fn open_round(&self, job: &str, attempt: u64) -> Round {
        let mut inputs = sample::round_inputs(&self.roster, CHANGE, job);
        inputs.attempt = attempt;
        let secret = gitiup_quorum::derive::SelectionSecret::from_signing_key(&self.owner);
        let mut round = Round::open(&inputs, &self.roster, &secret).expect("the round opens");
        round.sign(&self.owner).expect("the selector signs");
        store::publish_round(&self.host(), &round).expect("publish the round");
        self.round_at(job, attempt)
    }

    fn round(&self, job: &str) -> Round {
        self.round_at(job, 0)
    }

    fn round_at(&self, job: &str, attempt: u64) -> Round {
        store::round_at(&self.host(), CHANGE, job, attempt)
            .expect("read the round")
            .expect("the round is open")
    }

    fn seats(&self, job: &str) -> Vec<u8> {
        sample::indices_of(&self.round(job))
    }

    /// Every volunteer in `indexes` runs the job; `diverge` says which get different text.
    fn attest_diverging(
        &self,
        job: &str,
        indexes: &[u8],
        diverge: impl Fn(usize) -> Option<String>,
    ) {
        let round = self.round(job);
        let docs = sample::attest(&round, indexes, sample::claimed_at_us(), diverge);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(indexes[position])
                .public_key()
                .key_id();
            store::publish_submission(&self.host(), &round, &key_id, doc)
                .expect("the submission lands in its slot");
        }
    }

    /// File each seat's log text in `dir`, named by the slot the report looks them up by.
    ///
    /// Plain text on purpose: a single-stream run's log file *is* the stream the seat
    /// hashed, so a hand-written file can be checked against the attestation and a test can
    /// be sure the check is real and not a parse that always succeeds.
    fn write_logs(&self, job: &str, texts: impl Fn(usize) -> Option<String>) -> String {
        let dir = self.harness.path().join("logs");
        std::fs::create_dir_all(&dir).expect("make the logs dir");
        let round = self.round(job);
        for (position, seat) in round.selected.iter().enumerate() {
            let Some(text) = texts(position) else {
                continue;
            };
            std::fs::write(dir.join(&seat.slot), text).expect("write the log");
        }
        dir.to_str().expect("utf-8").to_string()
    }

    /// Run `gitiup quorum dispute` with the store and the pinned clock already there.
    fn dispute(&self, extra: &[&str]) -> Output {
        let store = self.store();
        let mut full: Vec<&str> = vec!["quorum", "dispute", CHANGE, "--store", &store];
        full.extend_from_slice(extra);
        if !full.contains(&"--now") {
            full.push("--now");
            full.push(&self.now);
        }
        self.harness.run(&full)
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// The exit code, a printed report, and an empty stderr — asserted in one place.
fn answer(output: &Output, expected: i32, what: &str) -> String {
    assert_eq!(
        code(output),
        expected,
        "{what}: expected exit {expected}, got {}\nstdout:\n{}\nstderr:\n{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    let text = stdout(output);
    assert!(!text.is_empty(), "{what}: a report is printed");
    assert_eq!(
        stderr(output).trim(),
        "",
        "{what}: the report is on stdout; stderr stays empty"
    );
    text
}

fn report(output: &Output, expected: i32, what: &str) -> Value {
    let text = answer(output, expected, what);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

fn job(body: &Value, which: &str) -> Value {
    body["jobs"]
        .as_array()
        .expect("a job per round")
        .iter()
        .find(|entry| entry["job"].as_str() == Some(which))
        .unwrap_or_else(|| panic!("no dispute for {which} in {body}"))
        .clone()
}

/// `[(count, winning)]` for one job's result groups, most-voted first.
fn groups(body: &Value, which: &str) -> Vec<(usize, bool)> {
    job(body, which)["results"]
        .as_array()
        .expect("results is a list")
        .iter()
        .map(|entry| {
            (
                entry["count"].as_u64().unwrap_or(0) as usize,
                entry["winning"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

/// Split three of five agreeing and two not: nobody reaches four, which is the disagreement
/// the report exists for.
fn disputed(scene: &Scene) -> Vec<u8> {
    let seats = scene.seats(BUILD);
    scene.attest_diverging(BUILD, &seats, |position| Some(text_for(position)));
    seats
}

// ---------------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------------

#[test]
fn a_split_round_is_reported_with_the_verdicts_own_exit_code() {
    let scene = Scene::new();
    disputed(&scene);

    let body = report(&scene.dispute(&["--json"]), 6, "a three-versus-two split");
    assert_eq!(body["kind"], "dispute");
    assert_eq!(body["change"], CHANGE);
    assert_eq!(body["exit"], 6, "the report's code is the gate's code");
    let entry = job(&body, BUILD);
    assert_eq!(
        groups(&body, BUILD),
        vec![(3, true), (1, false), (1, false)],
        "three digests, the agreeing one counted, most votes first"
    );
    let seats = entry["seats"].as_array().expect("a row per seat");
    assert_eq!(seats.len(), 5);
    assert_eq!(entry["verdict"]["agreeing"], 3);
    assert_eq!(entry["n"], 5);
    assert_eq!(entry["attempt"], 0);
    assert_eq!(
        entry["seats"]
            .as_array()
            .expect("a row per seat")
            .iter()
            .filter(|seat| seat["status"] == "diverging")
            .count(),
        2,
        "the two seats that disagreed are the two the tally counted as divergent"
    );

    // Every seat is reported with the sandbox that confined it, the rung that box is
    // registered at, and the machine it is — the ticket's "seats involved, sandbox rung
    // each used, each machine's environment fingerprint".
    for seat in seats {
        assert!(
            seat["sandbox"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "{seat}: a run that nothing confined must say so, not print nothing"
        );
        assert!(
            seat["environment_fingerprint"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:")),
            "{seat}: the fingerprint is how two machines get told apart"
        );
        assert!(seat["tier"].as_str().is_some());
        assert!(seat["slot"].as_str().is_some());
        assert!(seat["result_digest"].as_str().is_some());
    }
}

#[test]
fn the_text_report_names_the_digests_the_counts_and_the_rungs() {
    let scene = Scene::new();
    disputed(&scene);

    let text = answer(&scene.dispute(&[]), 6, "the human report");
    assert!(text.contains("dispute report"), "{text}");
    assert!(text.contains("results (3 distinct)"), "{text}");
    assert!(text.contains("seats:"), "{text}");
    assert!(
        text.contains("docker"),
        "{text}: the sandbox that confined the runs"
    );
    assert!(
        text.contains("env sha256:"),
        "{text}: and the machine it ran on"
    );
    assert!(text.contains("exit 6"), "{text}");
    assert!(
        text.contains("no logs were handed over"),
        "{text}: a dispute without logs has to say the log half is missing"
    );
}

#[test]
fn nothing_to_dispute_exits_zero() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    scene.attest_diverging(BUILD, &seats, |_| None);

    let body = report(&scene.dispute(&["--json"]), 0, "a round that agreed");
    assert_eq!(groups(&body, BUILD), vec![(5, true)]);
    assert_eq!(job(&body, BUILD)["logs"].as_array().expect("logs").len(), 0);
    assert_eq!(job(&body, BUILD)["verdict"]["state"], "verified");
}

// ---------------------------------------------------------------------------
// the logs
// ---------------------------------------------------------------------------

#[test]
fn a_losing_log_says_whether_the_difference_survives_normalisation() {
    let scene = Scene::new();
    disputed(&scene);
    // Every seat's log, including the agreeing side's, without which there is nothing to
    // compare a losing log against.
    let dir = scene.write_logs(BUILD, |position| Some(text_for(position)));

    let body = report(
        &scene.dispute(&["--logs", &dir, "--json"]),
        6,
        "a split round with every log handed over",
    );
    let logs = job(&body, BUILD)["logs"]
        .as_array()
        .expect("one comparison per losing seat with a log")
        .clone();
    assert_eq!(logs.len(), 2, "{logs:#?}");
    // The pairing is the report's whole claim: each losing seat is compared against the
    // side that reached the threshold, and not against itself or against another loser.
    let winning = job(&body, BUILD)["verdict"]["counted"]
        .as_array()
        .expect("the counted group")
        .iter()
        .map(|vote| vote["key_id"].as_str().expect("a key id").to_string())
        .collect::<Vec<_>>();
    for entry in &logs {
        assert_ne!(
            entry["key_id"].as_str(),
            entry["versus_key"].as_str(),
            "a seat is never its own yardstick: {entry}"
        );
        assert!(
            winning.contains(&entry["versus_key"].as_str().unwrap().to_string()),
            "the yardstick is a seat the verdict counted: {entry}"
        );
        assert_ne!(
            entry["slot"].as_str(),
            entry["versus_slot"].as_str(),
            "and the log files are two different files: {entry}"
        );
    }
    let mut compared: Vec<&str> = logs
        .iter()
        .map(|entry| entry["key_id"].as_str().unwrap())
        .collect();
    compared.sort();

    let entry = job(&body, BUILD);
    let mut losing: Vec<&str> = entry["verdict"]["divergent"]
        .as_array()
        .expect("the divergent groups")
        .iter()
        .flat_map(|group| {
            group["keys"]
                .as_array()
                .expect("keys")
                .iter()
                .map(|key| key.as_str().unwrap())
        })
        .collect();
    losing.sort();
    assert_eq!(compared, losing, "every losing seat with a log is compared");
    let noise = logs
        .iter()
        .find(|entry| entry["surviving"].as_u64() == Some(0))
        .expect("the slower machine's divergence is a fact about the machine");
    assert!(
        noise["verdict"]
            .as_str()
            .expect("a verdict per comparison")
            .contains("does not survive normalisation")
    );
    assert!(
        noise["verified"]
            .as_str()
            .expect("every log says it was checked")
            .contains("this seat signed")
    );
    // The one line the whole command exists to earn: the raw diff said two machines
    // disagreed, and the normalised diff says they did not — one equal row and nothing
    // else, which is what `TextDiff::surviving` is for.
    assert_eq!(
        noise["surviving"].as_u64(),
        Some(0),
        "a slower machine leaves nothing behind normalisation: {}",
        noise["normalised"]
    );
    let real = logs
        .iter()
        .find(|entry| entry["surviving"].as_u64().unwrap_or(0) > 0)
        .expect("a FAILED line is a fact about the build");
    assert!(
        real["verdict"]
            .as_str()
            .expect("a verdict per comparison")
            .contains("survives normalisation")
    );
    assert!(
        real["raw"]["rows"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "the raw side shows the disagreement: {real}"
    );
    assert!(
        real["normalised"]["rows"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "and so does the normalised one, which is the whole point: {real}"
    );
}

#[test]
fn the_side_by_side_diff_is_printed_for_a_human() {
    let scene = Scene::new();
    disputed(&scene);
    let dir = scene.write_logs(BUILD, |position| Some(text_for(position)));

    let text = answer(&scene.dispute(&["--logs", &dir]), 6, "the report with logs");
    assert!(text.contains("losing logs:"), "{text}");
    assert!(text.contains("side by side"), "{text}");
    assert!(
        text.contains("against slot"),
        "{text}: and which side is which"
    );
    assert!(text.contains("raw "), "{text}");
    assert!(text.contains("normalised "), "{text}");
    assert!(text.contains("survives normalisation"), "{text}");
    assert!(text.contains("does not survive normalisation"), "{text}");
    assert!(
        text.contains("FAILED"),
        "{text}: the build fact is in the diff"
    );
}

#[test]
fn a_missing_agreeing_log_is_said_rather_than_guessed() {
    let scene = Scene::new();
    disputed(&scene);
    // Only the losing seats: the agreeing side's text is what a losing log gets measured
    // against, and it is not here.
    let dir = scene.write_logs(BUILD, |position| match position {
        3 | 4 => Some(text_for(position)),
        _ => None,
    });

    let body = report(
        &scene.dispute(&["--logs", &dir, "--json"]),
        6,
        "logs for the losers only",
    );
    let entry = job(&body, BUILD);
    assert_eq!(
        entry["logs"].as_array().expect("nothing to compare").len(),
        0,
        "no agreeing log, so no comparison is claimed"
    );
    assert!(
        entry["notes"]
            .as_array()
            .expect("notes")
            .iter()
            .any(|note| note.as_str().unwrap_or_default().contains("agreeing side")),
        "{entry}: the report has to say what it could not do"
    );
}

#[test]
fn a_log_that_is_not_the_run_its_seat_signed_is_refused() {
    let scene = Scene::new();
    disputed(&scene);
    // The loser's text filed under an agreeing seat's slot: a plausible-looking report
    // built out of bytes nobody attested. That is exit 8, the same code an attestation
    // that is not the bytes it claims gets.
    let dir = scene.write_logs(BUILD, |position| {
        Some(match position {
            0 => FAILED.to_string(),
            other => text_for(other),
        })
    });

    let output = scene.dispute(&["--logs", &dir]);
    assert_eq!(
        code(&output),
        8,
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("not what this seat signed")
            || stderr(&output).contains("is not a run report"),
        "{}",
        stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// which rounds, and whose word
// ---------------------------------------------------------------------------

#[test]
fn a_job_and_an_attempt_can_be_named_and_a_missing_one_names_the_alternatives() {
    let scene = Scene::new();
    disputed(&scene);

    let body = report(
        &scene.dispute(&["--job", BUILD, "--attempt", "0", "--json"]),
        6,
        "one job, one attempt",
    );
    assert_eq!(body["jobs"].as_array().expect("one job").len(), 1);

    let output = scene.dispute(&["--job", "nope", "--json"]);
    assert_eq!(code(&output), 6);
    assert!(
        stdout(&output).is_empty(),
        "a refusal is an error, not a half report"
    );
}

#[test]
fn a_round_with_nothing_in_the_store_is_a_refusal_not_an_empty_report() {
    let scene = Scene::new();
    let output = scene.dispute(&["--job", "never-opened"]);
    assert_eq!(code(&output), 6, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("never-opened"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn help_and_usage_are_not_verdicts() {
    let scene = Scene::new();
    let output = scene.dispute(&["--help"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);
    for flag in ["--logs", "--log", "--width", "--context", "--rules"] {
        assert!(
            text.contains(flag),
            "{flag} is missing from the help:\n{text}"
        );
    }
    let store = scene.store();
    let output = scene.harness.run(&["quorum", "dispute", "--store", &store]);
    assert_eq!(code(&output), 2, "the change is not optional");
}

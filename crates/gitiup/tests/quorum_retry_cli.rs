//! `gitiup quorum retry`, run as the real binary (giti-zp1.7).
//!
//! The ticket's acceptance criteria are a command line, a new attempt and an exit code, so
//! they are tested as command lines against the built executable:
//!
//! ```text
//! gitiup quorum retry <change> [--job …] [--dry-run] [--json]
//!     → attempt + 1, with a fresh round id, a fresh seed and a fresh selection
//!     → the previous attempt's evidence kept, and cited by the new round
//!     → attempts configurable through the published policy, default 3
//!     → exit 0 opened · 6 nothing to escalate or refused · 9 the cap is exhausted
//! ```
//!
//! The assertions are the properties that make the escalation *bounded* and *auditable*,
//! rather than merely "a second round appeared":
//!
//! * the new round points at the old one, and the old one is untouched — an escalation that
//!   could not be traced back to the disagreement that caused it is a rerun;
//! * the seed changed, because the attempt number is a seed input and the same seed selects
//!   the same jury;
//! * the numbers widened (seats +2, threshold +1) and never lowered;
//! * the count comes from the store's own refs, so running the command twice cannot get
//!   past the cap, and the cap refuses at 9 instead of quietly looping.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::SigningKey;
use gitiup_host::FsHost;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use serde_json::{Value, json};

/// The passphrase every harness supplies the only way a script can.
const PASSPHRASE: &str = "four random words";
const CHANGE: &str = "chg-000000000000f00d";
const BUILD: &str = "build/matrix/linux-x86_64";
const TEST: &str = "test/unit";
const OWNER_SEED: [u8; 32] = [1u8; 32];
/// The default policy is five seats needing four to agree; `retry` widens that to seven
/// needing five, and the fixture roster is exactly big enough for the first widening.
const ROSTER: u8 = 7;
/// The attempt cap when the store's policy says nothing: the first round plus two retries.
const CAP: u64 = 3;

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

    /// Run the binary in this home, with the store and the clock pinned by the caller.
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

    fn seed_key(&self, name: &str, seed: [u8; 32]) -> String {
        let path = self.path().join(format!("{name}.seed"));
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
        let listed = self.run(&["key", "list", "--json"], None);
        let keys: Vec<Value> = serde_json::from_str(&stdout(&listed)).expect("key list json");
        keys.iter()
            .find(|record| record["name"].as_str() == Some(name))
            .expect("the key is listed")["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }
}

/// A store as the owner left it: a signed roster and one round per job at attempt 0.
struct Scene {
    harness: Harness,
    owner: SigningKey,
    owner_id: String,
    roster: Roster,
    now: String,
}

impl Scene {
    fn new() -> Scene {
        Scene::with(&[BUILD, TEST])
    }

    fn with(jobs: &[&str]) -> Scene {
        let harness = Harness::new();
        let owner_id = harness.seed_key("owner", OWNER_SEED);
        assert_eq!(
            owner_id,
            sample::owner_key().public_key().key_id(),
            "the keystore's `owner` and the fixture owner must be one key"
        );
        let owner = sample::owner_key();
        let host = FsHost::open_or_create(harness.store()).expect("open the store");
        let roster = sample::roster_of(&owner, ROSTER, 41);
        store::publish_roster(&host, &roster).expect("publish the roster");
        let scene = Scene {
            harness,
            owner,
            owner_id,
            roster,
            now: sample::clock().to_rfc3339(),
        };
        for job in jobs {
            scene.open_round(job, 0);
        }
        scene
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.harness.store()).expect("open the store")
    }

    fn open_round(&self, job: &str, attempt: u64) -> Round {
        let mut inputs = sample::round_inputs(&self.roster, CHANGE, job);
        inputs.attempt = attempt;
        let secret = SelectionSecret::from_signing_key(&self.owner);
        let mut round = Round::open(&inputs, &self.roster, &secret).expect("the round opens");
        round.sign(&self.owner).expect("the selector signs");
        store::publish_round(&self.host(), &round).expect("publish the round");
        self.round_at(job, attempt).expect("the round came back")
    }

    fn round_at(&self, job: &str, attempt: u64) -> Option<Round> {
        store::round_at(&self.host(), CHANGE, job, attempt).expect("read the store")
    }

    fn latest(&self, job: &str) -> Vec<u64> {
        store::rounds_for(&self.host(), CHANGE)
            .expect("list the rounds")
            .into_iter()
            .filter(|round| round.inputs.job_id == job)
            .map(|round| round.inputs.attempt)
            .collect()
    }

    fn seats(&self, job: &str) -> Vec<u8> {
        sample::indices_of(
            &self
                .round_at(job, 0)
                .unwrap_or_else(|| panic!("{job} has no attempt 0")),
        )
    }

    fn attest_diverging(
        &self,
        job: &str,
        indexes: &[u8],
        diverge: impl Fn(usize) -> Option<String>,
    ) {
        let round = self
            .round_at(job, 0)
            .unwrap_or_else(|| panic!("{job} has no attempt 0"));
        let docs = sample::attest(&round, indexes, sample::claimed_at_us(), diverge);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(indexes[position])
                .public_key()
                .key_id();
            store::publish_submission(&self.host(), &round, &key_id, doc)
                .expect("the submission lands in its slot");
        }
    }

    /// Three of five agree and two do not: `failed`, which is what an escalation is for.
    fn dispute_it(self: &Scene, job: &str) {
        let seats = self.seats(job);
        self.attest_diverging(job, &seats, |position| {
            (position >= 3).then(|| "test result: FAILED. 41 passed; 1 failed".to_string())
        });
    }

    /// Publish a policy whose `quorum` block caps the attempts, signed by the same owner
    /// key the roster and the rounds are signed by. This is the ticket's "attempts are
    /// policy-configurable": the number is data the owner signed, not a flag.
    fn publish_cap(&self, attempts: u64) {
        let path = self.harness.path().join("policy.json");
        let document = json!({
            "type": "gitiup-policy-1",
            "schema_version": 1,
            "owner": { "key_id": self.owner_id, "principal": "Ada Hale" },
            "revision": 1,
            "previous_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "effective_from_us": 1,
            "protects": ["refs/heads/**"],
            "rules": {
                // `quorum` numbers may only be published by a policy that allows the tier
                // they describe; the publish step refuses the contradiction.
                "allowed_tiers": ["quorum"],
                "trust_key_ids": [self.owner_id],
            },
            "quorum": {
                "default": {
                    "max_per_identity": 1,
                    "n": 5,
                    "required_agree": 4,
                    "reserves": 2,
                    "tier_caps": { "anonymous": 1, "endorsed": 5, "trusted": 1 },
                    "tier_floor": "anonymous"
                },
                "max_attempts": attempts,
            },
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&document).expect("json"))
            .expect("write the policy");
        let store = self.harness.store();
        let output = self.harness.run(
            &[
                "policy",
                "publish",
                &path.display().to_string(),
                "--store",
                &store,
                "--key",
                "owner",
                "--json",
            ],
            None,
        );
        assert!(
            output.status.success(),
            "`policy publish` failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
    }

    /// Run `gitiup quorum retry` with the store and the pinned clock already there.
    fn retry(&self, extra: &[&str]) -> Output {
        let store = self.harness.store();
        let mut full: Vec<&str> = vec![
            "quorum", "retry", CHANGE, "--store", &store, "--key", "owner", "--now", &self.now,
        ];
        full.extend_from_slice(extra);
        self.harness.run(&full, None)
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

/// The exit code, a printed answer, and an empty stderr.
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
    assert!(
        !text.is_empty(),
        "{what}: an escalation is a result, and a result is printed"
    );
    assert_eq!(
        stderr(output).trim(),
        "",
        "{what}: the answer is on stdout; stderr stays empty"
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
        .expect("a job per escalation")
        .iter()
        .find(|entry| entry["job"].as_str() == Some(which))
        .unwrap_or_else(|| panic!("no escalation for {which} in {body}"))
        .clone()
}

// ---------------------------------------------------------------------------
// the escalation
// ---------------------------------------------------------------------------

#[test]
fn a_disputed_job_opens_its_next_attempt_and_points_back() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    let before = scene
        .round_at(BUILD, 0)
        .expect("the first attempt is there to escalate");

    let body = report(&scene.retry(&["--json"]), 0, "escalate a failed job");
    assert_eq!(body["kind"], "escalation");
    assert_eq!(body["exit"], 0);
    assert_eq!(body["opened"], 1);
    let entry = job(&body, BUILD);
    assert_eq!(entry["state"], "escalated");
    assert_eq!(entry["attempt"], 1);
    assert_eq!(entry["from_attempt"], 0);
    assert_eq!(
        entry["from_round_digest"],
        body["jobs"][0]["from_round_digest"]
    );
    assert_eq!(
        entry["previous"]["state"], "failed",
        "the reason an attempt exists is the verdict it answers"
    );
    assert_eq!(entry["previous"]["divergent_seats"], 2);

    let after = scene
        .round_at(BUILD, 1)
        .expect("the escalation published attempt 1");
    assert_eq!(after.inputs.attempt, 1);
    assert_eq!(after.inputs.job_id, BUILD);
    assert_eq!(
        after.digest().expect("digest"),
        after.digest().expect("digest")
    );
    assert_eq!(
        after
            .escalated_from
            .as_ref()
            .expect("an escalation chain")
            .from_attempt,
        0
    );
    assert_eq!(
        after
            .escalated_from
            .as_ref()
            .expect("an escalation chain")
            .from_round_digest,
        before.digest().expect("a round digests"),
        "the new round names the round it replaces"
    );
    assert!(
        !after
            .escalated_from
            .as_ref()
            .expect("an escalation chain")
            .reason
            .is_empty()
    );
    assert_ne!(after.seed, before.seed, "a fresh seed selects a fresh jury");
    assert_eq!(
        after.signatures.first().map(|entry| entry.key_id.clone()),
        Some(scene.owner_id.clone()),
        "the escalation is signed by the selector the command was told to use"
    );
    assert_eq!(
        scene.latest(BUILD),
        vec![0, 1],
        "attempts are dense: one, then the next"
    );
}

#[test]
fn superseded_evidence_stays_where_it_was() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    let before = scene.round_at(BUILD, 0).expect("attempt 0");
    let canonical = before.canonical_bytes().expect("canonical bytes");

    answer(&scene.retry(&[]), 0, "escalate");

    let after = scene.round_at(BUILD, 0).expect("attempt 0 is still there");
    assert_eq!(
        after.canonical_bytes().expect("canonical bytes"),
        canonical,
        "an escalation supersedes; it does not edit"
    );
    // The seats that disagreed are still published, still checkable, and now they are
    // evidence for the new round rather than debris from the old one.
    assert_eq!(
        after.digest().expect("digest"),
        before.digest().expect("digest")
    );
    assert_eq!(
        store::submissions(&scene.host(), &before)
            .expect("the old submissions")
            .len(),
        5,
        "the losing attestations were not deleted to make the retry tidy"
    );
}

#[test]
fn the_escalation_widens_the_quorum_and_never_lowers_it() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);

    let body = report(&scene.retry(&["--json"]), 0, "escalate");
    let entry = job(&body, BUILD);
    let from = &entry["policy"]["from"];
    let to = &entry["policy"]["to"];
    assert_eq!(to["n"].as_u64(), from["n"].as_u64().map(|n| n + 2));
    assert_eq!(
        to["required_agree"].as_u64(),
        from["required_agree"].as_u64().map(|n| n + 1)
    );
    assert_eq!(entry["policy"]["widened"], true);
    assert!(
        entry["new_seats"].as_u64().unwrap_or(0) > 0,
        "a wider round over the same pool has to seat somebody new: {entry}"
    );

    let after = scene.round_at(BUILD, 1).expect("attempt 1");
    assert_eq!(
        after.inputs.policy.n as u64,
        from["n"].as_u64().unwrap() + 2
    );
    assert!(after.inputs.policy.required_agree > after.inputs.policy.n / 2);
}

#[test]
fn same_policy_re_runs_the_previous_numbers() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    let before = scene.round_at(BUILD, 0).expect("attempt 0");

    let body = report(
        &scene.retry(&["--same-policy", "--json"]),
        0,
        "escalate without widening",
    );
    assert_eq!(job(&body, BUILD)["policy"]["widened"], false);
    let after = scene.round_at(BUILD, 1).expect("attempt 1");
    assert_eq!(after.inputs.policy, before.inputs.policy);
    assert_ne!(
        after.seed, before.seed,
        "the same numbers, a different jury"
    );
}

/// An escalation nobody can see is an escalation nobody will run: the job advertisement
/// moves forward to the new attempt, which is how `gitiup work` volunteers find it.
fn advertise_attempt_zero(scene: &Scene) {
    // The fixture opens rounds without advertising them; advertise attempt 0 the way
    // `gitiup change submit` would, so "the advertisement moved forward" is a claim about
    // a ref that existed before.
    let first = scene.round_at(BUILD, 0).expect("attempt 0");
    store::advertise_round(
        &scene.host(),
        &first,
        &scene.owner,
        gitiup_attest::TimeUs::parse(&scene.now).expect("a clock"),
    )
    .expect("advertise attempt 0");
    let before = store::advertisement_at(&scene.host(), CHANGE, BUILD)
        .expect("read the advertisement")
        .expect("attempt 0 is advertised");
    assert_eq!(
        before.round_digest,
        first.digest().expect("a round digests")
    );
}

#[test]
fn the_escalation_moves_the_advertisement_volunteers_are_reading() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    advertise_attempt_zero(&scene);

    // `--same-policy` so the new round asks for the seats the fixture's roster can fill.
    answer(
        &scene.retry(&["--same-policy"]),
        0,
        "escalate within the roster",
    );

    let after = store::advertisement_at(&scene.host(), CHANGE, BUILD)
        .expect("read the advertisement")
        .expect("the new attempt is advertised");
    assert_eq!(after.attempt, 1);
    assert_eq!(
        after.round_digest,
        scene
            .round_at(BUILD, 1)
            .expect("attempt 1")
            .digest()
            .expect("a round digests"),
        "and it advertises the round it just opened, not the one it replaced"
    );
}

/// The widening can ask for more seats than the roster can fill. That round is published —
/// it is evidence, and the escalation chain has to be readable — and **not** advertised:
/// recruiting five strangers to a quorum that cannot happen is worse than escalating.
#[test]
fn an_escalation_whose_seats_cannot_be_filled_is_published_and_not_advertised() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    advertise_attempt_zero(&scene);

    let body = report(
        &scene.retry(&["--json"]),
        0,
        "escalate wider than the roster",
    );
    let entry = job(&body, BUILD);
    assert_eq!(entry["sufficient"], false, "{entry}");
    assert_eq!(entry["wrote"]["advertised"], false);
    assert!(
        entry["wrote"]["oid"].as_str().is_some(),
        "the round was written: {entry}"
    );

    let still = store::advertisement_at(&scene.host(), CHANGE, BUILD)
        .expect("read the advertisement")
        .expect("the old advertisement is where it was");
    assert_eq!(
        still.attempt, 0,
        "the job ref did not move: attempts only go forward, and an unfilled one has nothing          to recruit for"
    );
}

#[test]
fn a_clean_verified_job_is_not_escalated() {
    let scene = Scene::with(&[BUILD]);
    let seats = scene.seats(BUILD);
    scene.attest_diverging(BUILD, &seats, |_| None);

    let body = report(
        &scene.retry(&["--json"]),
        6,
        "a job with nothing to escalate",
    );
    assert_eq!(job(&body, BUILD)["state"], "nothing-to-escalate");
    assert_eq!(body["opened"], 0);
    assert_eq!(body["exit"], 6);
    assert_eq!(
        scene.latest(BUILD),
        vec![0],
        "a rerun is not a second opinion"
    );
}

#[test]
fn only_the_jobs_that_need_it_are_escalated() {
    let scene = Scene::new();
    let seats = scene.seats(TEST);
    scene.attest_diverging(TEST, &seats, |_| None);
    scene.dispute_it(BUILD);

    let body = report(&scene.retry(&["--json"]), 0, "one of two jobs");
    assert_eq!(body["opened"], 1);
    assert_eq!(job(&body, BUILD)["state"], "escalated");
    assert_eq!(job(&body, TEST)["state"], "nothing-to-escalate");
    assert_eq!(
        body["exit"], 0,
        "escalating one job of a change is a success"
    );
    assert!(scene.round_at(BUILD, 1).is_some());
    assert!(scene.round_at(TEST, 1).is_none());
}

// ---------------------------------------------------------------------------
// the cap
// ---------------------------------------------------------------------------

#[test]
fn the_cap_is_three_by_default_and_exhaustion_is_terminal() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);

    // Attempts 1 and 2, each escalated off the one before it: an unfilled round tallies
    // `insufficient`, which is still not clean, so it is still escalatable.
    for attempt in 1..CAP {
        assert_eq!(
            code(&scene.retry(&[])),
            0,
            "attempt {attempt} of {CAP} should open"
        );
    }
    assert_eq!(scene.latest(BUILD), vec![0, 1, 2]);

    let body = report(&scene.retry(&["--json"]), 9, "the fourth attempt");
    assert_eq!(body["exit"], 9);
    assert_eq!(job(&body, BUILD)["state"], "exhausted");
    assert_eq!(
        job(&body, BUILD)["exhausted"]["state"],
        "attempt_cap_exhausted",
        "the state has a name, so a caller can branch on it"
    );
    assert_eq!(job(&body, BUILD)["exhausted"]["max_attempts"], 3);
    assert_eq!(
        scene.latest(BUILD),
        vec![0, 1, 2],
        "asking again changes nothing"
    );

    let text = answer(&scene.retry(&[]), 9, "the exhausted report");
    assert!(text.contains("attempt_cap_exhausted"), "{text}");
    assert!(text.contains("terminal"), "{text}");
    assert!(
        text.contains("new attempt of the change"),
        "{text}: a terminal state has to say what to do instead"
    );
    assert!(
        text.contains("quorum.max_attempts"),
        "{text}: and where the number came from"
    );
}

#[test]
fn the_published_policy_sets_the_cap_and_the_report_cites_it() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    scene.publish_cap(2);

    // Attempt 1 opens; attempt 2 would be the third, and the policy said two.
    let body = report(&scene.retry(&["--json"]), 0, "the policy's second attempt");
    assert_eq!(job(&body, BUILD)["attempt"], 1);
    assert_eq!(body["cap"]["max_attempts"], 2);
    assert!(
        body["cap"]["source"]
            .as_str()
            .unwrap_or_default()
            .contains("quorum.max_attempts"),
        "the report says where the number came from: {}",
        body["cap"]["source"]
    );

    let exhausted = report(&scene.retry(&["--json"]), 9, "the policy's cap is the cap");
    assert_eq!(job(&exhausted, BUILD)["state"], "exhausted");
    assert_eq!(exhausted["cap"]["max_attempts"], 2);
    assert_eq!(scene.latest(BUILD), vec![0, 1]);
}

#[test]
fn a_flag_tightens_the_policys_cap_and_never_raises_it() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    scene.publish_cap(4);

    // Tighter: allowed, and the source says both numbers so a reader sees which one won.
    let body = report(
        &scene.retry(&["--max-attempts", "2", "--json"]),
        0,
        "a caller spending less than it was given",
    );
    assert_eq!(body["cap"]["max_attempts"], 2);
    assert!(
        body["cap"]["source"]
            .as_str()
            .unwrap_or_default()
            .contains("--max-attempts 2")
    );
    assert_eq!(code(&scene.retry(&["--max-attempts", "2"])), 9);

    // Looser: refused, because the roster's patience is the owner's to sign.
    let output = scene.retry(&["--max-attempts", "9"]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(
        stderr(&output).contains("raise"),
        "{}: the refusal has to say which number it would not raise",
        stderr(&output)
    );
    assert_eq!(
        scene.latest(BUILD),
        vec![0, 1],
        "and the refused attempt was not opened"
    );
}

#[test]
fn a_tighter_cap_is_honoured_and_named_as_the_callers() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);

    let body = report(
        &scene.retry(&["--max-attempts", "2", "--json"]),
        0,
        "a cap of two: attempt 1 is the last",
    );
    assert_eq!(job(&body, BUILD)["attempt"], 1);
    assert_eq!(job(&body, BUILD)["state"], "escalated");

    let output = scene.retry(&["--max-attempts", "2"]);
    assert_eq!(code(&output), 9, "{}{}", stdout(&output), stderr(&output));
    assert!(stderr(&output).is_empty() || stdout(&output).is_empty());
}

#[test]
fn a_cap_of_one_leaves_nothing_to_escalate() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    let body = report(
        &scene.retry(&["--max-attempts", "1", "--json"]),
        9,
        "one attempt was the whole allowance",
    );
    assert_eq!(job(&body, BUILD)["state"], "exhausted");
    assert_eq!(job(&body, BUILD)["exhausted"]["attempts_run"], 1);
    assert_eq!(scene.latest(BUILD), vec![0]);
}

#[test]
fn the_cap_is_counted_per_job_not_per_change() {
    let scene = Scene::new();
    scene.dispute_it(BUILD);
    scene.dispute_it(TEST);
    // One escalation each, then a cap so tight that only a fresh job could move: the
    // counts are per `(change, job)`, so `test` still has its second attempt.
    answer(
        &scene.retry(&["--job", BUILD, "--json"]),
        0,
        "build escalates",
    );
    let body = report(
        &scene.retry(&["--job", TEST, "--max-attempts", "2", "--json"]),
        0,
        "test still has one left",
    );
    assert_eq!(job(&body, TEST)["attempt"], 1);
    assert!(scene.round_at(TEST, 1).is_some());
    assert_eq!(
        scene.latest(BUILD),
        vec![0, 1],
        "and the other job's count is its own"
    );
}

// ---------------------------------------------------------------------------
// what is refused
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_derives_everything_and_writes_nothing() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);

    let body = report(&scene.retry(&["--dry-run", "--json"]), 0, "a rehearsal");
    let entry = job(&body, BUILD);
    assert_eq!(entry["attempt"], 1);
    assert_eq!(entry["wrote"]["oid"], Value::Null, "nothing was written");
    assert!(scene.round_at(BUILD, 1).is_none());
    let text = answer(&scene.retry(&["--dry-run"]), 0, "a rehearsal, printed");
    assert!(text.contains("--dry-run"), "{text}");
}

#[test]
fn the_reason_is_recorded_and_can_be_given() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    answer(
        &scene.retry(&["--reason", "flaky: test_mmap raced tmpfs"]),
        0,
        "escalate with a reason",
    );
    let after = scene.round_at(BUILD, 1).expect("attempt 1");
    assert_eq!(
        after
            .escalated_from
            .as_ref()
            .expect("an escalation chain")
            .reason,
        "flaky: test_mmap raced tmpfs"
    );
}

#[test]
fn the_new_round_is_recomputed_from_the_store_after_it_is_written() {
    let scene = Scene::with(&[BUILD]);
    scene.dispute_it(BUILD);
    let body = report(&scene.retry(&["--json"]), 0, "escalate");
    let roster = store::current_roster(&scene.host())
        .expect("the roster")
        .expect("a roster is published");
    let after = scene.round_at(BUILD, 1).expect("attempt 1");
    // Read back and re-derived: what a stranger recomputes from the published seed is what
    // the command claims it published.
    let selection = after
        .verify_selection(&roster)
        .expect("the selection re-derives");
    assert_eq!(
        selection.selected, after.selected,
        "the published seats are the derived ones"
    );
    assert_eq!(
        job(&body, BUILD)["wrote"]["rechecked"],
        true,
        "the command says it re-read what it wrote"
    );
    assert_eq!(
        job(&body, BUILD)["wrote"]["ref"].as_str(),
        Some(
            store::round_ref(CHANGE, BUILD, 1)
                .expect("a ref name")
                .as_str()
        ),
        "and the ref it names is the one a stranger would look in"
    );
}

#[test]
fn help_and_usage_are_not_escalations() {
    let scene = Scene::with(&[BUILD]);
    let output = scene.retry(&["--help"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);
    for flag in [
        "--max-attempts",
        "--same-policy",
        "--proposer",
        "--reason",
        "--dry-run",
    ] {
        assert!(
            text.contains(flag),
            "{flag} is missing from the help:\n{text}"
        );
    }
    let output = scene.harness.run(&["quorum", "retry"], None);
    assert_eq!(code(&output), 2, "the change is not optional");
}

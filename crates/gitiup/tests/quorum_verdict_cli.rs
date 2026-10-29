//! `gitiup quorum verdict`, run as the real binary (giti-zp1.4).
//!
//! The ticket's acceptance criteria are command lines and exit codes, so they are tested
//! as command lines against the built executable:
//!
//! ```text
//! gitiup quorum verdict <change> [--job …] [--publish] [--json]
//!     → verified / failed / insufficient, with the count, the threshold, the divergent
//!       digests and every rejection with its reason
//!     → exit 0 verified · 6 refused or not-yet · 7 bad signature · 8 digest mismatch
//!     → the report on stdout, stderr empty
//!     → --publish files the verdict and refuses to edit one that is already there
//! ```
//!
//! Three things are strict on purpose.
//!
//! * **The clock is pinned on every run.** Freshness is a window against *now*, and the
//!   fixtures claim a fixed time, so an unpinned test would pass today and rot next
//!   month. `--now` is also how a test says "three days later" without waiting.
//! * **The tampering goes through the library and stays canonical.** A mutated
//!   attestation is edited-then-re-signed or edited-after-signing on purpose; a test that
//!   merely corrupted the bytes would prove only that whitespace matters.
//! * **A verdict is stdout and stderr is empty** — asserted on every run that reaches a
//!   tally, including the 6s, the 7 and the 8, because the contract a hook depends on is
//!   that the answer is in the exit code and there is exactly one stream to read.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::{AttestationDoc, Digest, GitOid, SigningKey, Trust};
use gitiup_host::{FsHost, RefStore};
use gitiup_quorum::capability::RosterTier;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use gitiup_quorum::verdict::{CountedVote, QuorumState, ReasonCode, VerdictRecord};
use serde_json::Value;

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The change the rounds are opened for.
const CHANGE: &str = "chg-000000000000f00d";
/// Two jobs, because a matrix arm is its own round and a change's answer is about all
/// of them.
const BUILD: &str = "build/matrix/linux-x86_64";
const TEST: &str = "test/unit";
/// A change with no rounds anywhere.
const ABSENT: &str = "chg-0000000000000bad";
/// The seed `sample::owner_key()` is derived from, imported into the keystore so the
/// CLI can sign a verdict with the same key the roster and the rounds are signed by.
const OWNER_SEED: [u8; 32] = [1u8; 32];
/// A key nothing in the store trusts.
const STRANGER_SEED: [u8; 32] = [0x9eu8; 32];

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

    /// Run the binary with this home. The cwd is the temp dir, so no stray
    /// `gitiup.toml` or policy file can leak in, and `SSH_AUTH_SOCK` points where it
    /// cannot exist.
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

    /// Import a *known* seed, so the test process and the CLI hold the same key.
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
}

// ---------------------------------------------------------------------------
// the scene: a store with a roster, rounds and seats
// ---------------------------------------------------------------------------

/// A store as the owner left it: a signed roster, an open round per job, and — as each
/// test wants it — whichever seats have been filled by which volunteers.
struct Scene {
    harness: Harness,
    owner: SigningKey,
    owner_id: String,
    roster: Roster,
    /// The clock every run pins: a minute after the attestations claim to have happened.
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
        let roster = sample::roster_of(&owner, 7, 41);
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

    fn store(&self) -> String {
        self.harness.store()
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.store()).expect("open the store")
    }

    /// Open and publish a round for one job at one attempt, signed by the owner (who is
    /// also the selector: the seed is keyed on this key).
    fn open_round(&self, job: &str, attempt: u64) -> Round {
        let mut inputs = sample::round_inputs(&self.roster, CHANGE, job);
        inputs.attempt = attempt;
        let secret = SelectionSecret::from_signing_key(&self.owner);
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

    /// The fixture volunteer indices that hold a seat in a round.
    fn seats(&self, job: &str) -> Vec<u8> {
        sample::indices_of(&self.round(job))
    }

    /// Volunteer `index` runs the job and publishes into its own slot.
    fn attest(&self, job: &str, index: u8) {
        self.attest_diverging(job, &[index], |_| None);
    }

    /// Every volunteer in `indexes` runs the job; `diverge` says which ones get a
    /// different result (a different step output, which is what a disagreement is).
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

    /// One volunteer's run, mutated before it is filed — the only way a test can be sure
    /// the tally is judging a *document* and not a parse error.
    fn attest_tampered(
        &self,
        job: &str,
        index: u8,
        tamper: impl FnOnce(&mut AttestationDoc, &SigningKey),
    ) {
        let round = self.round(job);
        let key = sample::verifier_key(index);
        let mut doc = AttestationDoc::new(sample::manifest_for(
            &round,
            index,
            sample::claimed_at_us(),
            None,
        ));
        doc.sign(&key).expect("sign the attestation");
        tamper(&mut doc, &key);
        store::publish_submission(&self.host(), &round, &key.public_key().key_id(), &doc)
            .expect("the submission lands in its slot");
    }

    /// The owner revokes one volunteer's key *now*, for `compromised` — the reason that
    /// voids what it already signed, whatever the timing.
    fn revoke(&self, index: u8) {
        let key = sample::verifier_key(index);
        let mut revocation = Revocation::new(
            key.public_key().key_id(),
            RevocationReason::Compromised,
            self.roster.epoch,
            sample::claimed_at_us(),
        );
        revocation.issuer = self.owner.public_key().key_id();
        revocation
            .sign(&self.owner)
            .expect("the owner signs the revocation");
        store::publish_revocation(&self.host(), &revocation).expect("publish the revocation");
    }

    /// Run `gitiup quorum verdict` with the store and the pinned clock already there.
    ///
    /// `--later` is a test word, not a flag: it means "pin the clock three days on", so
    /// a run can be *late* — which is how a test asks what a stale quorum tallies to.
    fn verdict(&self, extra: &[&str]) -> Output {
        let store = self.store();
        let later = extra.contains(&"--later");
        let args: Vec<&str> = extra
            .iter()
            .copied()
            .filter(|arg| *arg != "--later")
            .collect();
        let three_days = (sample::clock().as_us() + 3 * 86_400_000_000i64).to_string();
        let mut full: Vec<&str> = vec!["quorum", "verdict", CHANGE, "--store", &store];
        full.extend_from_slice(&args);
        if !args.contains(&"--now") {
            full.push("--now");
            full.push(if later { &three_days } else { &self.now });
        }
        self.harness.run(&full, None)
    }

    /// Run any `gitiup` verb in this home.
    fn run(&self, args: &[&str]) -> Output {
        self.harness.run(args, None)
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

/// A verdict the command reached: the exit code it gave, its report on stdout and an
/// empty stderr — the contract, asserted in one place.
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
        "{what}: a verdict is a result, and a result is printed"
    );
    assert_eq!(
        stderr(output).trim(),
        "",
        "{what}: a verdict is printed on stdout; stderr stays empty for the hook"
    );
    text
}

/// The same assertion, with the `--json` report parsed.
fn report(output: &Output, expected: i32, what: &str) -> Value {
    let text = answer(output, expected, what);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

/// One job's entry in a `--json` report.
fn job(body: &Value, job: &str) -> Value {
    body["jobs"]
        .as_array()
        .expect("a job per round")
        .iter()
        .find(|entry| entry["job_id"].as_str() == Some(job))
        .unwrap_or_else(|| panic!("no tally for {job} in {body}"))
        .clone()
}

/// The rejection tokens a job's report carries.
fn rejected(body: &Value, which: &str) -> Vec<String> {
    job(body, which)["rejected"]
        .as_array()
        .expect("rejected is a list")
        .iter()
        .map(|entry| entry["code"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// `sha256:abcd…wxyz` — the shortening the report uses, so a test can look for a digest
/// in a terminal line.
fn short(digest: &str) -> String {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("sha256:{}\u{2026}{}", &body[..4], &body[body.len() - 4..])
}

/// File a verdict by hand (library-side), the way a store could have been filled before
/// this command existed — used to plant a verdict the command must then not edit.
fn file_verdict_by_hand(scene: &Scene, job: &str, state: QuorumState, seed: [u8; 32]) {
    let round = scene.round(job);
    let mut verdict = VerdictRecord {
        schema_version: gitiup_quorum::verdict::VERDICT_SCHEMA_VERSION,
        verdict_type: gitiup_quorum::verdict::VERDICT_TYPE.to_string(),
        change_id: CHANGE.to_string(),
        head_oid: round.inputs.head_oid.clone(),
        job_id: job.to_string(),
        attempt: 0,
        round_digest: round.digest().expect("a round digest"),
        roster_digest: scene.roster.digest().expect("a roster digest"),
        policy_digest: round.inputs.policy.digest().expect("a policy digest"),
        state,
        reason: match state {
            QuorumState::Verified => ReasonCode::AgreementReached,
            QuorumState::Failed => ReasonCode::IrreconcilableDigests,
            QuorumState::Insufficient => ReasonCode::NotEnoughAgreement,
        },
        detail: format!("{state}, filed by hand before the command got there"),
        result_digest: Some(Digest::sha256(b"by hand")),
        seats: round.selected.len(),
        required_agree: round.inputs.policy.required_agree,
        // A `verified` record may not claim an agreement it does not carry, so the
        // hand-built one says it reached exactly the threshold.
        agreeing: if state == QuorumState::Verified {
            round.inputs.policy.required_agree
        } else {
            1
        },
        counted: vec![CountedVote {
            key_id: "SHA256:by-hand".to_string(),
            identity: "SHA256:by-hand".to_string(),
            result_digest: Digest::sha256(b"by hand"),
            tier: RosterTier::Trusted,
        }],
        divergent: Vec::new(),
        missing: Vec::new(),
        rejected: Vec::new(),
        issued_at_us: 1_792_771_260_000_000,
        signatures: Vec::new(),
    };
    let key = SigningKey::from_seed(&seed);
    verdict.sign(&key).expect("sign the hand-built verdict");
    store::publish_verdict(&scene.host(), &verdict).expect("file the verdict");
}

// ---------------------------------------------------------------------------
// the three states, and the codes
// ---------------------------------------------------------------------------

#[test]
fn a_filled_round_is_verified_and_exits_zero() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    assert_eq!(seats.len(), 5, "the policy's n seats are open");
    for &index in &seats {
        scene.attest(BUILD, index);
    }

    let output = scene.verdict(&["--job", BUILD, "--json"]);
    let body = report(&output, 0, "five agreeing volunteers");
    let entry = job(&body, BUILD);
    assert_eq!(entry["state"], "verified");
    assert_eq!(entry["agreeing"], 5);
    assert_eq!(entry["required_agree"], 4);
    assert_eq!(entry["seats"], 5);
    assert_eq!(entry["reason"], "agreement_reached");
    assert_eq!(entry["counted"].as_array().expect("counted").len(), 5);
    assert!(entry["divergent"].as_array().expect("divergent").is_empty());
    assert!(entry["rejected"].as_array().expect("rejected").is_empty());
    // The verdict names the round, the roster and the policy it spoke about, so it
    // cannot be quietly re-used for another change.
    assert_eq!(entry["change_id"], CHANGE);
    assert!(entry["round_digest"].as_str().is_some());
    assert!(entry["policy_digest"].as_str().is_some());
    assert_eq!(body["exit"], 0);
    assert_eq!(body["state"], "verified");

    // The human report says the same numbers, on one screen.
    let text = answer(
        &scene.verdict(&["--job", BUILD]),
        0,
        "the same tally in words",
    );
    assert!(text.contains("verified"), "{text}");
    assert!(
        text.contains("5 of 4"),
        "the count and the threshold: {text}"
    );
    assert!(text.contains("threshold 4"), "{text}");
    assert!(text.contains("counted (5)"), "{text}");
}

#[test]
fn a_change_is_tallied_job_by_job_and_the_code_is_the_worst() {
    let scene = Scene::new();
    for &index in &scene.seats(BUILD) {
        scene.attest(BUILD, index);
    }
    // One volunteer turns up for the other job: that round cannot reach the threshold.
    scene.attest(TEST, scene.seats(TEST)[0]);

    let body = report(
        &scene.verdict(&["--json"]),
        6,
        "one job verified, one insufficient",
    );
    assert_eq!(job(&body, BUILD)["state"], "verified");
    assert_eq!(job(&body, TEST)["state"], "insufficient");
    assert_eq!(
        job(&body, TEST)["missing"]
            .as_array()
            .expect("missing")
            .len(),
        4
    );
    // The change's answer is the worst of its jobs, not the first one printed.
    assert_eq!(body["exit"], 6);
    assert_eq!(body["state"], "insufficient");

    let text = answer(&scene.verdict(&[]), 6, "both jobs in words");
    assert!(text.contains(BUILD) && text.contains(TEST), "{text}");
    assert!(text.contains("2 job(s)"), "{text}");
    assert!(text.contains("silent (4)"), "who never showed up: {text}");
}

#[test]
fn too_few_votes_are_insufficient_and_say_why() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats[..2] {
        scene.attest(BUILD, index);
    }
    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        6,
        "two of four required",
    );
    let entry = job(&body, BUILD);
    assert_eq!(entry["state"], "insufficient");
    assert_eq!(entry["reason"], "not_enough_agreement");
    assert_eq!(entry["agreeing"], 2);
    assert!(
        entry["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("need 4"),
        "{entry}"
    );
    assert_eq!(body["exit"], 6);
}

#[test]
fn disagreement_is_failed_and_names_every_divergent_digest() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    // Three agree, two do not: nobody reaches four, and that is a fact about the change
    // rather than a shortage of volunteers.
    scene.attest_diverging(BUILD, &seats, |position| {
        (position >= 3).then(|| "test result: FAILED. 41 passed; 1 failed".to_string())
    });

    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        6,
        "a three-versus-two split",
    );
    let entry = job(&body, BUILD);
    assert_eq!(entry["state"], "failed");
    assert_eq!(entry["reason"], "irreconcilable_digests");
    assert_eq!(entry["agreeing"], 3);
    let divergent = entry["divergent"].as_array().expect("divergent");
    assert_eq!(divergent.len(), 1, "one losing group: {entry}");
    assert_eq!(divergent[0]["keys"].as_array().expect("keys").len(), 2);
    let losing = divergent[0]["result_digest"]
        .as_str()
        .expect("the divergent digest is printed");
    assert!(losing.starts_with("sha256:"));
    assert_ne!(
        Some(losing),
        entry["result_digest"].as_str(),
        "the divergent digest is not the winning one"
    );

    let text = answer(&scene.verdict(&["--job", BUILD]), 6, "the split in words");
    assert!(text.contains("failed"), "{text}");
    assert!(text.contains("divergent results (1)"), "{text}");
    assert!(
        text.contains(&short(losing)),
        "the divergent digest is on the terminal too: {text}"
    );
}

#[test]
fn a_signature_that_does_not_verify_is_exit_7() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats[..4] {
        scene.attest(BUILD, index);
    }
    // The fifth signs honestly and is then edited: the bytes stay canonical, so the only
    // thing wrong is that the signature no longer matches what it was made over.
    scene.attest_tampered(BUILD, seats[4], |doc, _| {
        doc.manifest.claims.run_id = "deadbeef00000000".to_string();
    });

    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        7,
        "a tampered signature",
    );
    let entry = job(&body, BUILD);
    // The tally still says verified — four honest identities did agree — and the code
    // still says 7, because a broken thing in the evidence is not made whole by being
    // outvoted.
    assert_eq!(entry["state"], "verified");
    assert_eq!(body["exit"], 7);
    assert_eq!(rejected(&body, BUILD), vec!["bad_signature"]);
    assert_eq!(entry["rejected"][0]["exit_code"], 7);

    let text = answer(
        &scene.verdict(&["--job", BUILD]),
        7,
        "the tampering in words",
    );
    assert!(text.contains("bad_signature"), "{text}");
    assert!(text.contains("(exit 7)"), "{text}");
}

#[test]
fn a_submission_bound_to_another_commit_is_exit_8() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats[..4] {
        scene.attest(BUILD, index);
    }
    // Re-signed after the edit, so this is a *consistent* document about the wrong
    // commit — the case the binding checks exist for.
    scene.attest_tampered(BUILD, seats[4], |doc, key| {
        doc.manifest.result.source.commit = GitOid::from_sha1_hex(&"d".repeat(40)).expect("an oid");
        doc.signatures.clear();
        doc.sign(key).expect("re-sign the forgery");
    });

    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        8,
        "a submission about another commit",
    );
    assert_eq!(rejected(&body, BUILD), vec!["binding_mismatch"]);
    assert_eq!(job(&body, BUILD)["rejected"][0]["exit_code"], 8);
    assert_eq!(body["exit"], 8);
}

#[test]
fn a_capability_lie_is_refused_and_recorded() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats[..4] {
        scene.attest(BUILD, index);
    }
    // The seat was taken on a claim this run contradicts: it said x86_64 and its own
    // signed environment says otherwise (ADR-0002 D7's post-check).
    scene.attest_tampered(BUILD, seats[4], |doc, key| {
        doc.manifest.result.environment.arch = "sparc64".to_string();
        doc.manifest
            .result
            .environment
            .fix_fingerprint()
            .expect("a self-consistent lie");
        doc.signatures.clear();
        doc.sign(key).expect("re-sign");
    });

    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        0,
        "a quorum that survived one liar",
    );
    assert_eq!(job(&body, BUILD)["state"], "verified");
    assert_eq!(rejected(&body, BUILD), vec!["arch_mismatch"]);
    let text = answer(&scene.verdict(&["--job", BUILD]), 0, "the lie in words");
    assert!(text.contains("arch_mismatch"), "{text}");
    assert!(text.contains("sparc64"), "the reason is a sentence: {text}");
}

#[test]
fn a_key_revoked_now_voids_what_it_already_signed() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats {
        scene.attest(BUILD, index);
    }
    // Five agree. Then one key is burned *after* the fact: a `compromised` revocation
    // voids the claim whatever the timing, so five votes become four — still a quorum,
    // but the record says so with the revocation named rather than counting a dead key.
    scene.revoke(seats[4]);
    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        0,
        "five agreeing, one of them dead",
    );
    assert_eq!(rejected(&body, BUILD), vec!["revoked"]);
    assert_eq!(job(&body, BUILD)["agreeing"], 4);
    assert_eq!(job(&body, BUILD)["state"], "verified");

    // A second revocation takes it below the threshold, and the verdict follows it down.
    scene.revoke(seats[3]);
    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        6,
        "a quorum one vote short of itself",
    );
    let entry = job(&body, BUILD);
    assert_eq!(rejected(&body, BUILD), vec!["revoked", "revoked"]);
    assert_eq!(entry["agreeing"], 3);
    assert_eq!(entry["state"], "insufficient");
    assert!(
        entry["rejected"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("compromised"),
        "the revocation is quoted: {entry}"
    );
}

// ---------------------------------------------------------------------------
// --publish
// ---------------------------------------------------------------------------

#[test]
fn publish_files_the_verdict_and_refuses_to_edit_it() {
    let scene = Scene::new();
    let seats = scene.seats(BUILD);
    for &index in &seats[..4] {
        scene.attest(BUILD, index);
    }
    let verdict_ref = store::verdict_ref(CHANGE, BUILD).expect("a ref name");
    let host = scene.host();
    assert!(host.get_ref(&verdict_ref).expect("read the ref").is_none());

    let body = report(
        &scene.verdict(&["--job", BUILD, "--publish", "--key", "owner", "--json"]),
        0,
        "filing a verdict",
    );
    assert_eq!(job(&body, BUILD)["publish"]["state"], "filed");
    let first = host
        .get_ref(&verdict_ref)
        .expect("read the ref")
        .expect("the verdict ref exists");
    assert_eq!(
        job(&body, BUILD)["publish"]["oid"].as_str(),
        Some(first.oid.hex().as_str()),
        "the report names the blob it wrote"
    );
    // The filed record is the owner's, and reads back as one.
    let trust = Trust::KeyIds([scene.owner_id.clone()].into_iter().collect());
    let filed = store::verdict_at(&host, CHANGE, BUILD, &trust)
        .expect("read the verdict back")
        .expect("it is there");
    assert_eq!(filed.state, QuorumState::Verified);
    assert_eq!(filed.signatures[0].key_id, scene.owner_id);

    // Filing the same answer twice is a retry, not an edit.
    let again = report(
        &scene.verdict(&["--job", BUILD, "--publish", "--key", "owner", "--json"]),
        0,
        "re-filing the same verdict",
    );
    assert_eq!(job(&again, BUILD)["publish"]["state"], "unchanged");
    assert_eq!(
        host.get_ref(&verdict_ref)
            .expect("read the ref")
            .expect("still there")
            .oid
            .hex(),
        first.oid.hex(),
        "nothing moved"
    );

    // Three days later the attestations are stale, so a fresh tally is a different
    // answer about the same attempt — and the record refuses to be rewritten over.
    let body = report(
        &scene.verdict(&[
            "--job",
            BUILD,
            "--publish",
            "--key",
            "owner",
            "--json",
            "--later",
        ]),
        6,
        "an attempt to edit a filed verdict",
    );
    assert_eq!(job(&body, BUILD)["state"], "insufficient", "stale by then");
    assert_eq!(job(&body, BUILD)["publish"]["state"], "refused");
    assert!(
        job(&body, BUILD)["publish"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("superseded by a later attempt"),
        "{body}"
    );
    assert_eq!(
        host.get_ref(&verdict_ref)
            .expect("read the ref")
            .expect("untouched")
            .oid
            .hex(),
        first.oid.hex(),
        "the verdict on the record is still the one that was signed first"
    );
    // And the refusal is a verdict too: it is on stdout, not on stderr.
    let text = answer(
        &scene.verdict(&["--job", BUILD, "--publish", "--key", "owner", "--later"]),
        6,
        "the refusal in words",
    );
    assert!(text.contains("publish refused"), "{text}");
}

#[test]
fn publish_is_refused_when_the_record_is_not_the_store_s_own() {
    let scene = Scene::new();
    for &index in &scene.seats(BUILD)[..4] {
        scene.attest(BUILD, index);
    }
    // A verdict nobody here signed is filed at the ref. The command must not overwrite
    // it, and must not believe it either: it checks the incumbent's signature before it
    // compares anything.
    file_verdict_by_hand(&scene, BUILD, QuorumState::Failed, STRANGER_SEED);
    let output = scene.verdict(&["--job", BUILD, "--publish", "--key", "owner"]);
    assert_eq!(
        code(&output),
        6,
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        text.to_lowercase().contains("trust"),
        "the refusal names the trust failure: {text}"
    );
}

#[test]
fn out_dash_writes_the_signed_record_and_nothing_else() {
    let scene = Scene::new();
    for &index in &scene.seats(BUILD)[..4] {
        scene.attest(BUILD, index);
    }
    let output = scene.verdict(&["--job", BUILD, "--out", "-", "--key", "owner"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stderr(&output).trim(), "");
    let bytes = stdout(&output);
    assert!(bytes.trim_start().starts_with('{'), "{bytes}");
    let trust = Trust::KeyIds([scene.owner_id.clone()].into_iter().collect());
    let record = VerdictRecord::from_canonical_bytes(bytes.as_bytes(), &trust)
        .expect("the bytes are the signed verdict");
    assert_eq!(record.state, QuorumState::Verified);
    assert_eq!(record.job_id, BUILD);
    // A report beside those bytes would corrupt both, so it stayed off stdout: one
    // line, and none of the report's prose.
    assert_eq!(bytes.trim().lines().count(), 1, "{bytes}");
    assert!(!bytes.contains("read from"), "{bytes}");
    // And the two output modes cannot share a stream.
    assert_eq!(
        code(&scene.verdict(&["--job", BUILD, "--out", "-", "--json"])),
        2
    );
}

// ---------------------------------------------------------------------------
// the refusals that are not verdicts
// ---------------------------------------------------------------------------

#[test]
fn a_change_with_no_rounds_is_refused_with_the_way_to_open_one() {
    // A change nobody opened a round for, in a store that holds rounds for another one:
    // "no quorum" must not be answerable by guessing at the rounds that do exist.
    let scene = Scene::new();
    let store = scene.store();
    let output = scene.harness.run(
        &[
            "quorum", "verdict", ABSENT, "--store", &store, "--now", &scene.now,
        ],
        None,
    );
    assert_eq!(
        code(&output),
        6,
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(text.contains("no round"), "{text}");
    assert!(text.contains("select"), "how to open one: {text}");
}

#[test]
fn a_round_this_machine_does_not_trust_is_not_a_verdict() {
    let scene = Scene::new();
    for &index in &scene.seats(BUILD)[..4] {
        scene.attest(BUILD, index);
    }
    let stranger = scene.harness.seed_key("stranger", STRANGER_SEED);
    let output = scene.verdict(&["--job", BUILD, "--owner", &stranger]);
    assert_eq!(
        code(&output),
        6,
        "stdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        text.to_lowercase().contains("trust"),
        "the answer is about authority: {text}"
    );
}

#[test]
fn a_job_the_store_never_opened_names_the_ones_it_did() {
    let scene = Scene::new();
    let output = scene.verdict(&["--job", "nope/nope"]);
    assert_eq!(code(&output), 6);
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(text.contains(BUILD) && text.contains(TEST), "{text}");
}

#[test]
fn a_later_attempt_supersedes_the_filed_verdict() {
    let scene = Scene::new();
    for &index in &scene.seats(BUILD)[..4] {
        scene.attest(BUILD, index);
    }
    let verdict_ref = store::verdict_ref(CHANGE, BUILD).expect("a ref name");
    let host = scene.host();
    assert!(host.get_ref(&verdict_ref).expect("read the ref").is_none());
    report(
        &scene.verdict(&[
            "--job",
            BUILD,
            "--attempt",
            "0",
            "--publish",
            "--key",
            "owner",
            "--json",
        ]),
        0,
        "attempt 0 is verified",
    );
    let first = host
        .get_ref(&verdict_ref)
        .expect("read the ref")
        .expect("filed")
        .oid
        .hex();

    // Escalation: attempt 1, a fresh seed. The attempt-0 submissions are still sitting
    // in those slots — a reveal slot is per key, not per attempt — and they are *not*
    // this round's work: the challenge each one signed is derived from the old seed, so
    // every one is refused as a binding mismatch (ADR-0001 D7's exit 8) and the round
    // says insufficient until fresh votes arrive. Filing that still moves the ref: a
    // later attempt replaces the earlier answer, which is what "the old verdict is no
    // longer the answer" means while the new votes come in.
    scene.open_round(BUILD, 1);
    let body = report(
        &scene.verdict(&[
            "--job",
            BUILD,
            "--attempt",
            "1",
            "--publish",
            "--key",
            "owner",
            "--json",
        ]),
        8,
        "attempt 1 has only another attempt's evidence",
    );
    assert_eq!(job(&body, BUILD)["publish"]["state"], "superseded");
    assert_eq!(job(&body, BUILD)["publish"]["superseded_attempt"], 0);
    assert_eq!(job(&body, BUILD)["state"], "insufficient");
    assert_eq!(job(&body, BUILD)["reason"], "no_usable_attestations");
    assert_eq!(
        rejected(&body, BUILD),
        vec!["binding_mismatch", "binding_mismatch", "binding_mismatch"],
        "the stale submissions are named, not counted"
    );
    let second = host
        .get_ref(&verdict_ref)
        .expect("read the ref")
        .expect("superseded")
        .oid
        .hex();
    assert_ne!(second, first, "the record moved");

    // The default is the latest attempt, and it is no longer the verified one.
    let body = report(
        &scene.verdict(&["--job", BUILD, "--json"]),
        8,
        "the change now answers with attempt 1",
    );
    assert_eq!(job(&body, BUILD)["attempt"], 1);

    // And walking the record back to attempt 0 is refused: attempts only move forward.
    let body = report(
        &scene.verdict(&[
            "--job",
            BUILD,
            "--attempt",
            "0",
            "--publish",
            "--key",
            "owner",
            "--json",
        ]),
        6,
        "attempt 0 cannot overwrite attempt 1",
    );
    assert_eq!(job(&body, BUILD)["publish"]["state"], "refused");
    assert!(
        job(&body, BUILD)["publish"]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("later attempt"),
        "{body}"
    );
    let filed = store::verdict_at(&host, CHANGE, BUILD, &trust(&scene))
        .expect("read it")
        .expect("there");
    assert_eq!(filed.attempt, 1, "the record moved forward and only once");
}

fn trust(scene: &Scene) -> Trust {
    Trust::KeyIds([scene.owner_id.clone()].into_iter().collect())
}

#[test]
fn the_surface_is_helpful_and_strict() {
    let scene = Scene::new();
    assert_eq!(code(&scene.run(&["quorum"])), 0);
    assert_eq!(code(&scene.run(&["quorum", "help"])), 0);
    assert_eq!(code(&scene.run(&["quorum", "nonsense"])), 2);
    assert_eq!(code(&scene.run(&["quorum", "verdict", "--help"])), 0);
    // `help` where the change would go, the same spelling every other verb uses.
    let help = scene.run(&["quorum", "verdict", "help"]);
    assert_eq!(code(&help), 0);
    assert!(stdout(&help).contains("--publish"), "{}", stdout(&help));
    // A change is not optional, and neither is a store.
    assert_eq!(code(&scene.run(&["quorum", "verdict"])), 2);
    assert_eq!(code(&scene.run(&["quorum", "verdict", CHANGE])), 6);
    assert_eq!(
        code(&scene.run(&["quorum", "verdict", CHANGE, "--nonsense"])),
        2
    );
    // `gitiup help` knows the command exists.
    assert!(stdout(&scene.run(&["help"])).contains("quorum verdict"));
}

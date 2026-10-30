//! `gitiup participant quarantine|unquarantine|history`, run as the real binary (giti-zp1.8).
//!
//! The acceptance criteria are command lines and their consequences, so that is how they are
//! tested: a real store, a real keystore, a real verdict, and the binary doing what an owner
//! would type.
//!
//! ```text
//! gitiup participant quarantine <key> [--epochs 3] [--reason …] [--change … --job …]
//!     → the exclusion is written as a RoundInputs::excluding input, never as a roster edit
//!     → absence is scored (`history`) and refused as a ground (exit 6)
//!     → a quarantined key can read why, with no key of its own
//! gitiup participant unquarantine <key>   → the appeal, and it is a human act: no vote
//! gitiup participant history              → the trail, and the reputation table
//! ```
//!
//! Exit codes: 0 ok · 2 usage · 3 store unreachable · 6 refused (no reason, absence offered
//! as a reason, no evidence cited, nothing to lift) · 7 a signature that does not verify ·
//! 8 a digest that is not what it names.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::SigningKey;
use gitiup_host::{FsHost, RefQuery, RefStore as _};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use serde_json::Value;

const PASSPHRASE: &str = "four random words";
const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";
const HEAD: &str = "sha1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const EPOCH: u64 = 41;

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

    fn run_in(&self, home: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", home)
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", home.join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
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

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.path().join("cfg"), args)
    }

    fn seed_key(&self, name: &str, seed: [u8; 32]) -> String {
        let path = self.path().join(format!("{name}.seed"));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let mut child = Command::new(env!("CARGO_BIN_EXE_gitiup"))
            .args([
                "key",
                "import",
                "seed",
                &path.display().to_string(),
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
        {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(format!("{PASSPHRASE}\n").as_bytes())
                .expect("write passphrase");
        }
        let output = child.wait_with_output().expect("wait");
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn expect_ok<'a>(output: &'a Output, what: &str) -> &'a Output {
    assert!(
        output.status.success(),
        "{what} failed (exit {}): {}{}",
        output.status.code().unwrap_or(-1),
        stdout(output),
        stderr(output)
    );
    output
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).unwrap_or_else(|e| {
        panic!(
            "expected json on stdout: {e}\n{}{}",
            stdout(output),
            stderr(output)
        )
    })
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("an exit code")
}

fn ok(output: &Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed (exit {}): {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    stdout(output)
}

fn refused(output: &Output, what: &str) -> String {
    assert_eq!(
        code(output),
        6,
        "{what}: expected exit 6, got {}: {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    format!("{}{}", stdout(output), stderr(output))
}

// ---------------------------------------------------------------------------
// the scene: a store whose quorum produced a verdict with one divergence and one silence
// ---------------------------------------------------------------------------

struct Scene {
    harness: Harness,
    owner: SigningKey,
    owner_id: String,
    roster: Roster,
    now: String,
    /// Every seat's key id, in the round's own order.
    seats: Vec<String>,
}

impl Scene {
    fn new() -> Scene {
        let harness = Harness::new();
        let owner_id = harness.seed_key("owner", [1u8; 32]);
        assert_eq!(
            owner_id,
            sample::owner_key().public_key().key_id(),
            "the keystore's `owner` and the fixture owner must be one key"
        );
        let owner = sample::owner_key();
        let host = FsHost::open_or_create(harness.store()).expect("open the store");
        let roster = sample::roster_of(&owner, 7, EPOCH);
        store::publish_roster(&host, &roster).expect("publish the roster");

        // Three of five agreeing is the point: the verdict must *reach* a consensus while
        // still holding a divergence and a silent seat.
        let inputs = sample::round_inputs_with(
            &roster,
            CHANGE,
            JOB,
            SelectionPolicy {
                required_agree: 3,
                ..Default::default()
            },
        );
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
        round.sign(&owner).expect("the selector signs");
        store::publish_round(&host, &round).expect("publish the round");

        let indexes = sample::indices_of(&round);
        let silent = *indexes.last().expect("a seat");
        let diverging = indexes[indexes.len() - 2];
        let answering: Vec<u8> = indexes
            .iter()
            .copied()
            .filter(|index| *index != silent)
            .collect();
        let docs = sample::attest(&round, &answering, sample::claimed_at_us(), |position| {
            (answering[position] == diverging)
                .then(|| "test result: FAILED. 41 passed, 1 failed".to_string())
        });
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(answering[position])
                .public_key()
                .key_id();
            store::publish_submission(&host, &round, &key_id, doc)
                .expect("the submission lands in its slot");
        }
        let seats = indexes
            .iter()
            .map(|index| sample::verifier_key(*index).public_key().key_id())
            .collect();
        Scene {
            harness,
            owner,
            owner_id,
            roster,
            now: sample::clock().to_rfc3339(),
            seats,
        }
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.harness.store()).expect("open the store")
    }

    fn store(&self) -> String {
        self.harness.store()
    }

    /// The key that disagreed with the consensus, and the key that said nothing.
    fn diverging(&self) -> String {
        let verdict = self.verdict_record();
        verdict["divergent"][0]["keys"][0]
            .as_str()
            .expect("the verdict names its dissenters")
            .to_string()
    }

    fn silent(&self) -> String {
        let verdict = self.verdict_record();
        verdict["missing"][0]
            .as_str()
            .expect("the verdict names the seat that never answered")
            .to_string()
    }

    /// The owner's tally of the fixture round, as the command prints it. The clock is the
    /// fixture's, because an attestation that is 40 years old is `stale` and a stale tally
    /// has nothing to quarantine anybody for.
    fn verdict(&self) -> Value {
        json(&self.run(&[
            "quorum", "verdict", CHANGE, "--store", "@", "--now", &self.now, "--json",
        ]))
    }

    /// The one job block of that tally: the `VerdictRecord` itself.
    fn verdict_record(&self) -> Value {
        let whole = self.verdict();
        assert_eq!(
            whole["jobs"].as_array().map(|jobs| jobs.len()),
            Some(1),
            "the fixture change opens exactly one round: {whole}"
        );
        whole["jobs"][0].clone()
    }

    fn run(&self, args: &[&str]) -> Output {
        let store = self.store();
        let mut full: Vec<&str> = vec![];
        for arg in args {
            if *arg == "@" {
                full.push(&store);
            } else {
                full.push(arg);
            }
        }
        self.harness.run(&full)
    }

    /// File the owner's signed verdict, which is what a quarantine is allowed to cite.
    fn file_verdict(&self) -> String {
        let out = ok(
            &self.run(&[
                "quorum",
                "verdict",
                CHANGE,
                "--store",
                "@",
                "--publish",
                "--key",
                "owner",
                "--now",
                &self.now,
                "--json",
            ]),
            "`quorum verdict --publish`",
        );
        let record: Value = serde_json::from_str(&out).expect("verdict json");
        record["jobs"][0]["verdict_digest"]
            .as_str()
            .expect("a verdict digest")
            .to_string()
    }

    fn quarantine(&self, key: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "participant",
            "quarantine",
            key,
            "--store",
            "@",
            "--key",
            "owner",
            "--now",
            &self.now,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn unquarantine(&self, key: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "participant",
            "unquarantine",
            key,
            "--store",
            "@",
            "--key",
            "owner",
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    /// `participant history`, with the reputation half taken at the fixture's clock: the
    /// attestations were signed 55 years ago, and a tally that called them all `stale`
    /// would score a different round from the one the fixture ran.
    fn history(&self, extra: &[&str]) -> Output {
        let mut args: Vec<&str> =
            vec!["participant", "history", "--store", "@", "--now", &self.now];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    /// The current roster ref: the trust root a quarantine must never move.
    fn roster_ref(&self) -> String {
        let refs = self
            .host()
            .list_refs(&RefQuery::prefix("refs/gitiup/roster"))
            .expect("list refs");
        let mut names: Vec<(String, String)> = refs
            .iter()
            .map(|r| (r.name.as_str().to_string(), r.oid.hex()))
            .collect();
        names.sort();
        names
            .iter()
            .map(|(name, oid)| format!("{name}={oid}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Derive a fresh round for a new change: the seats are what quarantine must change.
    fn select(&self, change: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "select",
            "--change",
            change,
            "--job",
            JOB,
            "--head",
            HEAD,
            "--proposer",
            &self.owner_id,
            "--require-arch",
            "x86_64",
            "--store",
            "@",
            "--key",
            "owner",
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        // Keep the fixture's owner key alive for the process: nothing to do, but the field
        // documents that the scene owns the key the store trusts.
        let _ = &self.owner;
    }
}

// ---------------------------------------------------------------------------
// the criteria, as command lines
// ---------------------------------------------------------------------------

#[test]
fn a_divergence_is_quarantined_from_the_evidence_and_the_roster_does_not_move() {
    let scene = Scene::new();
    assert_eq!(
        scene.verdict()["state"].as_str(),
        Some("verified"),
        "the fixture's quorum reached a consensus"
    );
    let verdict_digest = scene.file_verdict();
    let diverging = scene.diverging();
    let before = scene.roster_ref();

    let output = scene.quarantine(
        &diverging,
        &[
            "--reason",
            "divergence",
            "--change",
            CHANGE,
            "--job",
            JOB,
            "--epochs",
            "3",
            "--publish",
            "--json",
        ],
    );
    let record = json(expect_ok(&output, "quarantining a diverging verifier"));
    assert_eq!(record["reason"].as_str(), Some("divergence"));
    assert_eq!(record["start_epoch"].as_u64(), Some(EPOCH));
    assert_eq!(record["epochs"].as_u64(), Some(3));
    assert_eq!(record["ends_epoch"].as_u64(), Some(EPOCH + 3));
    assert_eq!(
        record["evidence"][0]["verdict"].as_str(),
        Some(verdict_digest.as_str()),
        "the record cites the filed verdict, not a tally that lives in somebody's memory"
    );
    assert!(
        record["reaches"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "the exclusion closes over the key's identity family: {record}"
    );
    assert!(
        record["expires_at_us"].is_i64(),
        "a quarantine has a clock bound as well as an epoch window: {record}"
    );

    // The roster is the owner's signed trust list and a quarantine does not rewrite it.
    assert_eq!(
        scene.roster_ref(),
        before,
        "not one roster ref moved: quarantine is an exclusion input, never a roster edit"
    );

    // And the exclusion changes who is selected, through the round's own inputs.
    let selected = json(expect_ok(
        &scene.select("chg-quarantine-check", &["--json"]),
        "deriving a round after the quarantine",
    ));
    let seated: Vec<&str> = selected["selected"]
        .as_array()
        .expect("seats")
        .iter()
        .map(|seat| seat["key_id"].as_str().expect("a key id"))
        .collect();
    assert!(
        !seated.contains(&diverging.as_str()),
        "the quarantined key holds no seat: {seated:?}"
    );
    assert!(
        selected["inputs"]["exclusions"]
            .as_array()
            .expect("the round publishes its exclusions")
            .iter()
            .any(|name| name.as_str() == Some(diverging.as_str())),
        "the exclusion is inside the signed round inputs, where an auditor reads it"
    );
    let text = ok(
        &scene.quarantine(
            &scene.silent(),
            &[
                "--reason",
                "owner_decision",
                "--note",
                "their host was unreliable through the whole of last week",
            ],
        ),
        "an owner's judgement, written out loud",
    );
    assert!(
        text.contains("no vote") && text.contains("unquarantine"),
        "the appeal path is named as a human act: {text}"
    );
}

#[test]
fn silence_is_scored_and_refused_as_a_ground() {
    let scene = Scene::new();
    scene.file_verdict();
    let silent = scene.silent();

    // The reason vocabulary refuses the words for absence before it ever reaches a record.
    let text = refused(
        &scene.quarantine(&silent, &["--reason", "absence"]),
        "quarantining a key for not turning up",
    );
    assert!(
        text.contains("silence is insufficient"),
        "the refusal says why: {text}"
    );

    // …and so does the evidence, when an owner tries to cite a verdict that only shows the
    // key being absent.
    let text = refused(
        &scene.quarantine(
            &silent,
            &["--reason", "divergence", "--change", CHANGE, "--job", JOB],
        ),
        "calling a silent seat a divergence",
    );
    assert!(
        text.contains("silence is insufficient, not guilt"),
        "{text}"
    );

    // A counted vote is evidence *for* a key, not against it.
    let counted = scene.verdict_record()["counted"][0]["key_id"]
        .as_str()
        .expect("a counted vote")
        .to_string();
    let text = refused(
        &scene.quarantine(
            &counted,
            &["--reason", "divergence", "--change", CHANGE, "--job", JOB],
        ),
        "quarantining a verifier that agreed with the consensus",
    );
    assert!(text.contains("evidence for it"), "{text}");
}

#[test]
fn a_reason_has_to_stand_on_something() {
    let scene = Scene::new();
    scene.file_verdict();
    let diverging = scene.diverging();

    // A claimed fact with no citation is refused, and the refusal names the way to cite it.
    let text = refused(
        &scene.quarantine(&diverging, &["--reason", "divergence"]),
        "a divergence with no verdict cited",
    );
    assert!(text.contains("no verdict was cited"), "{text}");

    // A judgement with no sentence is refused too: an unnamed mood is not a policy.
    let text = refused(
        &scene.quarantine(&diverging, &["--reason", "owner_decision"]),
        "an owner decision with no note",
    );
    assert!(text.contains("--note"), "{text}");

    // The reason must be the one the evidence supports — the evidence names the reason, not
    // the other way round.
    let text = refused(
        &scene.quarantine(
            &diverging,
            &[
                "--reason",
                "capability_lie",
                "--change",
                CHANGE,
                "--job",
                JOB,
            ],
        ),
        "calling a divergence a capability lie",
    );
    assert!(text.contains("says `divergence`"), "{text}");

    // A quarantine past the bound is a roster edit with a different name.
    assert_eq!(
        code(&scene.quarantine(&diverging, &["--reason", "divergence", "--epochs", "99"])),
        2,
        "past the bound it is not a quarantine"
    );

    // And a verdict has to be filed before it can be cited: a punishment cites a document.
    let fresh = Scene::new();
    let text = refused(
        &fresh.quarantine(
            &fresh.diverging(),
            &["--reason", "divergence", "--change", CHANGE, "--job", JOB],
        ),
        "citing a verdict nobody filed",
    );
    assert!(text.contains("no filed verdict"), "{text}");
}

#[test]
fn history_is_the_trail_and_the_score_and_it_needs_no_key_of_its_own() {
    let scene = Scene::new();
    scene.file_verdict();
    let diverging = scene.diverging();
    let silent = scene.silent();
    ok(
        &scene.quarantine(
            &diverging,
            &[
                "--reason",
                "divergence",
                "--change",
                CHANGE,
                "--job",
                JOB,
                "--publish",
            ],
        ),
        "quarantining",
    );

    let report = json(expect_ok(
        &scene.history(&["--json"]),
        "`participant history`",
    ));
    assert_eq!(report["epoch"].as_u64(), Some(EPOCH));
    let quarantined = report["quarantines"].as_array().expect("one row");
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0]["key_id"].as_str(), Some(diverging.as_str()));
    assert_eq!(quarantined[0]["believed"].as_bool(), Some(true));
    assert!(
        quarantined[0]["standing"]
            .as_str()
            .expect("a standing")
            .contains("quarantined")
    );
    assert!(
        report["quarantined_now"]
            .as_array()
            .expect("the in-force list")
            .iter()
            .any(|name| name.as_str() == Some(diverging.as_str())),
        "and the report says it is in force at this epoch"
    );

    // The scored half: the silent seat is counted, and it authorises nothing.
    let reputation = &report["reputation"];
    let sheets = reputation["keys"].as_array().expect("a row per key");
    let row_of = |key: &str| -> Value {
        sheets
            .iter()
            .find(|sheet| sheet["key_id"].as_str() == Some(key))
            .cloned()
            .unwrap_or_else(|| panic!("{key} has no row in {sheets:?}"))
    };
    let diverging_row = row_of(&diverging);
    assert_eq!(diverging_row["divergent"].as_u64(), Some(1));
    assert!(
        diverging_row["grounds"]
            .as_array()
            .expect("grounds")
            .iter()
            .any(|ground| ground.as_str().is_some_and(|g| g.starts_with("divergence"))),
        "what a quarantine may cite, spelled out: {diverging_row}"
    );
    let silent_row = row_of(&silent);
    assert_eq!(
        silent_row["silent"].as_u64(),
        Some(1),
        "the silent seat is counted: {silent_row} / report {report}"
    );
    assert_eq!(
        silent_row["grounds"].as_array().expect("grounds").len(),
        0,
        "silence is scored, never a ground: {silent_row}"
    );
    assert!(
        reputation["capacity"]
            .as_str()
            .expect("the capacity note")
            .contains("went silent"),
        "the roster reads as capacity or as theatre, in its own numbers"
    );

    // The text report says the appeal is human, and says it where a reader will see it.
    let text = ok(&scene.history(&[]), "`participant history` as text");
    assert!(text.contains("appeal"), "{text}");
    assert!(text.contains("unquarantine"), "{text}");

    // The quarantined key reads its own reason, with no keys and no trust of its own.
    let stranger = Harness::new();
    let alone = stranger.path().join("empty-cfg");
    std::fs::create_dir_all(&alone).expect("make an empty home");
    let output = stranger.run_in(
        &alone,
        &["participant", "history", "--store", &scene.store()],
    );
    let text = ok(&output, "`participant history` with no keys at all");
    assert!(
        text.contains(&scene.harness.path().display().to_string()),
        "the trail names the store it read: {text}"
    );
    assert!(
        text.contains("not believed"),
        "and says what it could not believe: {text}"
    );
    assert!(
        text.contains("quarantined for"),
        "the reason and the evidence are public: {text}"
    );
    assert!(
        text.contains("reputation: not computed"),
        "and the scored half admits what it could not re-derive: {text}"
    );
}

#[test]
fn unquarantine_is_the_appeal_and_it_is_a_human_act() {
    let scene = Scene::new();
    scene.file_verdict();
    let diverging = scene.diverging();
    ok(
        &scene.quarantine(
            &diverging,
            &[
                "--reason",
                "divergence",
                "--change",
                CHANGE,
                "--job",
                JOB,
                "--publish",
            ],
        ),
        "quarantining",
    );
    assert!(
        json(expect_ok(&scene.history(&["--json"]), "history"))["quarantined_now"]
            .as_array()
            .expect("in force")
            .iter()
            .any(|name| name.as_str() == Some(diverging.as_str())),
        "it starts out excluded"
    );

    let lift = json(expect_ok(
        &scene.unquarantine(
            &diverging,
            &[
                "--note",
                "appeal granted: their host was rebuilt",
                "--publish",
                "--json",
            ],
        ),
        "unquarantining",
    ));
    assert_eq!(lift["type"].as_str(), Some("quarantine_lift"));
    assert_eq!(lift["effective_epoch"].as_u64(), Some(EPOCH));

    let report = json(expect_ok(
        &scene.history(&["--json"]),
        "history after the lift",
    ));
    assert!(
        report["quarantined_now"]
            .as_array()
            .expect("in force")
            .iter()
            .all(|name| name.as_str() != Some(diverging.as_str())),
        "the exclusion is over: {report}"
    );
    assert!(
        report["quarantines"][0]["standing"]
            .as_str()
            .expect("a standing")
            .contains("lifted"),
        "and the trail keeps both halves"
    );

    // Nothing is left to lift, and saying so is better than a no-op that looks like success.
    let text = refused(
        &scene.unquarantine(&diverging, &["--publish"]),
        "lifting a lifted quarantine",
    );
    assert!(text.contains("lifted"), "{text}");
    let text = refused(
        &scene.unquarantine(&scene.silent(), &["--publish"]),
        "lifting a quarantine that never existed",
    );
    assert!(text.contains("never quarantined"), "{text}");

    // There is no appeal command, no vote and no timer: the human act above is the path.
    let output = scene.run(&["participant", "appeal"]);
    assert_eq!(code(&output), 2, "no automated appeal exists");
    assert!(
        stderr(&output).contains("unquarantine"),
        "and the CLI says what the way out is instead"
    );
}

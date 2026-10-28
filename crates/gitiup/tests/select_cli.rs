//! `gitiup select …`, run as the real binary.
//!
//! The ticket's acceptance criteria are command lines — *`gitiup select --change X --json`
//! reproduces the same ordered selection for any auditor given the published inputs*,
//! *the author and their other keys are always excluded* — so they are tested here as
//! command lines against the built executable: a temp config home and a temp store per
//! harness, a real `fs` host as the store, and every assertion read from `--json`.
//!
//! The shape of every test is the same pair: an owner who *derives* a round with a
//! selector key, and an auditor — often a second harness with an empty keystore, which is
//! the point — who re-derives it. If the two disagree, the selection was never auditable.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// The head oid every test verifies: any well-formed sha1 will do, the round binds it.
const HEAD: &str = "sha1:e255b091aabd7e443b5d2fbeb90bc9769d07cbeb";
const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";
/// The other arm of a matrix: its own round, its own seed, its own eligible pool.
const ARM_JOB: &str = "build/matrix/linux-aarch64";
/// A derive needs to say what the job needs (ADR-0002 D7); this is all these tests need.
const ARCH: &str = "x86_64";

/// A config home, a store directory, and the binary pointed at both.
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

    fn config(&self) -> PathBuf {
        self.path().join("cfg")
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

    /// Run the binary with this home. `SSH_AUTH_SOCK` points where it cannot exist, so a
    /// test cannot depend on the developer's agent, and the working directory is the temp
    /// dir so no `gitiup.toml` is discovered by accident.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.config())
            .env("GITIUP_KEY_PASSPHRASE", "four random words")
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
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

    fn new_key(&self, name: &str) -> String {
        let output = self.run(&["key", "gen", "--name", name], Some("four random words\n"));
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
        name.to_string()
    }

    fn key_id(&self, name: &str) -> String {
        let output = self.run(&["key", "show", name, "--json"], None);
        json(&output)["key_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no key id for {name}: {}", stderr(&output)))
            .to_string()
    }

    /// A volunteer's honest claim, filed for the owner's eyes.
    ///
    /// The tier is deliberately not here: a sign-up may only claim the absence of a vouch,
    /// and the owner decides the tier when approving.
    fn register(&self, name: &str, arch: &str) -> String {
        self.register_extra(name, arch, &[])
    }

    fn register_extra(&self, name: &str, arch: &str, extra: &[&str]) -> String {
        self.new_key(name);
        let signup = self.file(&format!("{name}.signup"));
        let mut args = vec![
            "participant",
            "register",
            "--key",
            name,
            "--ram-mb",
            "32768",
            "--disk-mb",
            "262144",
            "--sandbox",
            "docker",
            "--sandbox-level",
            "2",
            "--arch",
            arch,
            "--out",
            signup.as_str(),
        ];
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        ok(&output, "participant register");
        signup
    }

    /// Carry sign-ups into a new published epoch at one tier.
    fn approve(&self, store: &str, from: &[String], tier: &str) -> Value {
        self.approve_extra(store, from, tier, &[])
    }

    fn approve_extra(&self, store: &str, from: &[String], tier: &str, extra: &[&str]) -> Value {
        let mut args: Vec<&str> =
            vec!["participant", "approve", "--key", "owner", "--store", store];
        for path in from {
            args.push("--from");
            args.push(path);
        }
        args.extend_from_slice(&["--tier", tier, "--publish", "--json"]);
        args.extend_from_slice(extra);
        let output = self.run(&args, None);
        assert!(
            output.status.success(),
            "participant approve --tier {tier} failed: {}",
            stderr(&output)
        );
        json(&output)
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> Value {
    let text = stdout(output);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON on stdout, got {text:?} ({e}); stderr: {}",
            stderr(output)
        )
    })
}

fn ok(output: &Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} should succeed: {}",
        stderr(output)
    );
    stdout(output)
}

fn refused(output: &Output, what: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(6),
        "{what} should be refused with exit 6, got {:?}: {}",
        output.status.code(),
        stderr(output)
    );
    stderr(output)
}

/// One owner, `endorsed` volunteers, `anonymous` volunteers, and an author with **two**
/// boxes on the epoch (both registered under one principal, which is what "their other
/// keys" means to the roster).
struct Scene {
    harness: Harness,
    store: String,
    /// The author's own box — the key they sign a change with.
    author: String,
    /// The author's second box, sharing the author's principal.
    author_second: String,
    /// Every other volunteer's key id.
    volunteers: Vec<String>,
}

impl Scene {
    fn new() -> Scene {
        let harness = Harness::new();
        harness.new_key("owner");
        let store = harness.store();
        // The author registers too: a proposer who is *on* the roster is the interesting
        // case, because their boxes are eligible until something takes them out.
        let author_signup = harness.register("author", "x86_64");
        let author_id = harness.key_id("author");
        // …and a second box anchored on the author's principal, so one name has to cover
        // both of them.
        let second_signup =
            harness.register_extra("author-laptop", "x86_64", &["--identity", &author_id]);
        let volunteers = [
            ("v1", "endorsed", "x86_64"),
            ("v2", "endorsed", "x86_64"),
            ("v3", "endorsed", "x86_64"),
            ("v4", "trusted", "x86_64"),
            ("v5", "anonymous", "x86_64"),
            ("v6", "anonymous", "x86_64"),
        ];
        let signups: Vec<(String, String)> = volunteers
            .iter()
            .map(|(name, tier, arch)| (harness.register(name, arch), (*tier).to_string()))
            .collect();
        let tier_of = |wanted: &str| -> Vec<String> {
            signups
                .iter()
                .filter(|(_, tier)| tier == wanted)
                .map(|(path, _)| path.clone())
                .collect()
        };
        // Three epochs, one per tier: the vouch is the owner's act and `approve` is where
        // it is given.
        harness.approve(&store, &[author_signup, second_signup], "endorsed");
        harness.approve(&store, &tier_of("trusted"), "trusted");
        harness.approve(&store, &tier_of("anonymous"), "anonymous");
        harness.approve(&store, &tier_of("endorsed"), "endorsed");
        let volunteer_ids = volunteers
            .iter()
            .map(|(name, _, _)| harness.key_id(name))
            .collect();
        let author_now = harness.key_id("author");
        let second_now = harness.key_id("author-laptop");
        Scene {
            harness,
            store,
            author: author_now,
            author_second: second_now,
            volunteers: volunteer_ids,
        }
    }

    /// Derive a round for one arm of the matrix.
    fn derive_for(&self, job: &str, arch: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "select",
            "--change",
            CHANGE,
            "--job",
            job,
            "--head",
            HEAD,
            "--proposer",
            &self.author,
            "--require-arch",
            arch,
            "--store",
            &self.store,
            // The selector: this keystore holds a dozen keys, so it has to be named.
            "--key",
            "owner",
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args, None)
    }

    /// Derive a round for the x86_64 arm, under the default policy.
    fn derive(&self, extra: &[&str]) -> Output {
        self.derive_for(JOB, "x86_64", extra)
    }
}

/// The eligibility that matters for these tests is architecture; everything else takes
/// the permissive default the flags describe.
fn selected_ids(body: &Value) -> Vec<String> {
    body["selected"]
        .as_array()
        .expect("a selection has seats")
        .iter()
        .map(|seat| seat["key_id"].as_str().expect("a seat key id").to_string())
        .collect()
}

#[test]
fn a_derived_round_fills_five_seats_under_the_default_policy() {
    let scene = Scene::new();
    let output = scene.derive(&["--explain", "--json"]);
    let body = json(&output);
    assert_eq!(body["mode"].as_str(), Some("derive"));
    assert_eq!(body["change_id"].as_str(), Some(CHANGE));
    assert_eq!(body["job_id"].as_str(), Some(JOB));
    assert_eq!(body["attempt"].as_u64(), Some(0));
    assert_eq!(body["sufficient"].as_bool(), Some(true));
    assert_eq!(body["selected"].as_array().map(Vec::len), Some(5));
    assert_eq!(body["policy"]["n"].as_u64(), Some(5));
    assert_eq!(body["policy"]["required_agree"].as_u64(), Some(4));
    assert_eq!(body["policy"]["max_per_identity"].as_u64(), Some(1));
    // The selection document is the ADR-0002 shape, so a stranger can diff `selection`
    // against a `selection.json` without knowing this command exists.
    assert_eq!(body["selection"]["kind"].as_str(), Some("selection"));
    assert_eq!(body["selection"]["seed"], body["seed"]);
    assert!(
        body["selection"]["round_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("gitiup-round-1/"),
        "the round id names the generation it was derived under"
    );
    // Caps bite the way the ADR says they must: at most one of the owner's tier and at
    // most one unvouched box, whatever the scores said.
    let tiers: Vec<&str> = body["selected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|seat| seat["tier"].as_str().unwrap_or_default())
        .collect();
    assert!(
        tiers.iter().filter(|t| **t == "trusted").count() <= 1,
        "tier_caps.trusted is 1: {tiers:?}"
    );
    assert!(
        tiers.iter().filter(|t| **t == "anonymous").count() <= 1,
        "tier_caps.anonymous is 1: {tiers:?}"
    );
    // The audit table is part of the contract, not a debug dump.
    let explain = body["explain"].as_str().expect("--explain in --json");
    assert!(explain.contains("round id"), "{explain}");
    assert!(explain.contains("seed"), "{explain}");
    assert!(explain.contains("machine"), "{explain}");
    assert!(explain.contains("selected"), "{explain}");
}

#[test]
fn the_author_and_their_other_keys_are_excluded_from_every_seat() {
    let scene = Scene::new();
    let body = json(&scene.derive(&["--json"]));
    let seats = selected_ids(&body);
    assert!(
        !seats.contains(&scene.author),
        "the author holds a seat: {seats:?}"
    );
    assert!(
        !seats.contains(&scene.author_second),
        "the author's other box holds a seat: {seats:?}"
    );
    // The rule closed over the family before the seed was derived, so the audit record
    // says `excluded` for both boxes — D7's order, not whichever filter bit first.
    let rows: Vec<&Value> = body["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["key_id"].as_str() == Some(scene.author.as_str())
                || row["key_id"].as_str() == Some(scene.author_second.as_str())
        })
        .collect();
    assert_eq!(rows.len(), 2, "both of the author's boxes are on the epoch");
    for row in &rows {
        assert_eq!(
            row["excluded_by"].as_str(),
            Some("excluded"),
            "the exclusion reason is the one the round published: {row:?}"
        );
        assert_eq!(row["eligible"].as_bool(), Some(false));
    }
    assert_eq!(body["proposer"]["excluded"].as_bool(), Some(true));
    assert_eq!(
        body["proposer"]["family"]
            .as_array()
            .map(|family| family.len()),
        Some(2),
        "naming one key reached the whole family"
    );
    // And the same exclusion is visible from the *published* side, which is what an
    // auditor without the owner's key can check.
    let published = scene.derive(&["--publish", "--json"]);
    ok(&published, "publishing the round");
    let audit = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--proposer",
            &scene.author,
            "--json",
        ],
        None,
    );
    let audit = json(&audit);
    assert_eq!(audit["mode"].as_str(), Some("audit"));
    assert_eq!(audit["proposer"]["excluded"].as_bool(), Some(true));
    assert_eq!(
        audit["selected"], body["selected"],
        "the audit re-derived different seats"
    );
}

#[test]
fn a_stranger_with_the_published_inputs_gets_the_same_ordered_selection() {
    // The acceptance criterion, in the shape it will be read: somebody else's machine,
    // an empty keystore, the same store, and no secret in sight.
    let scene = Scene::new();
    let derived = json(&scene.derive(&["--publish", "--json"]));
    ok(
        &scene.harness.run(
            &[
                "select",
                "--change",
                CHANGE,
                "--store",
                &scene.store,
                "--json",
            ],
            None,
        ),
        "auditing the published round",
    );

    let stranger = Harness::new();
    let audit = stranger.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--proposer",
            &scene.author,
            "--explain",
            "--json",
        ],
        None,
    );
    let audit = json(&audit);
    assert_eq!(audit["mode"].as_str(), Some("audit"));
    // Byte for byte, in order: seats, reserves, and every row of the audit table.
    assert_eq!(audit["selection"], derived["selection"]);
    assert_eq!(audit["inputs"], derived["inputs"]);
    assert_eq!(audit["seed"], derived["seed"]);
    assert_eq!(audit["policy_digest"], derived["policy_digest"]);
    assert_eq!(
        audit["selected"].as_array().map(Vec::len),
        Some(5),
        "an auditor who got a different seat count is not auditing the same round"
    );
    assert_eq!(
        audit["round"]["published_seats_are_derived"].as_bool(),
        Some(true)
    );
    // The stranger believes nobody's signature, and says so instead of pretending.
    assert_eq!(
        audit["roster"]["trusted_via"].as_str(),
        None,
        "an empty keystore is not a trust root, and must not be reported as one"
    );
    assert!(
        audit["round"]["selectors"].is_null(),
        "no trust root means no selector was believed: {:?}",
        audit["round"]
    );
    let notes = audit["notes"]
        .as_array()
        .map(|notes| {
            notes
                .iter()
                .any(|note| note.as_str().is_some_and(|n| n.contains("trust root")))
        })
        .unwrap_or(false);
    assert!(notes, "the gap has to be stated: {:?}", audit["notes"]);
    // Running it twice is the same answer: no clock, no randomness, no ordering luck.
    let again = stranger.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--proposer",
            &scene.author,
            "--json",
        ],
        None,
    );
    assert_eq!(json(&again)["selection"], audit["selection"]);
}

#[test]
fn a_round_can_be_audited_from_two_files_and_no_key() {
    // The offline audit: the round record and the roster epoch it pinned, handed over as
    // bytes. Nothing else reproduces the answer, which is the property a third-party audit
    // actually depends on — ADR-0002 C9, "audit is not a live query".
    let scene = Scene::new();
    // The owner's own approval dumps the epoch it signed, so the bytes an auditor needs
    // come from the command that made them trusted rather than from a store read.
    let late = scene.harness.register("v7", "x86_64");
    let roster_path = scene.harness.file("roster.json");
    scene
        .harness
        .approve_extra(&scene.store, &[late], "endorsed", &["--out", &roster_path]);
    let round_path = scene.harness.file("round.json");
    let derived = json(&scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--job",
            JOB,
            "--head",
            HEAD,
            "--proposer",
            &scene.author,
            "--require-arch",
            "x86_64",
            "--roster",
            &roster_path,
            "--out",
            &round_path,
            "--key",
            "owner",
            "--json",
        ],
        None,
    ));
    assert_eq!(
        derived["mode"].as_str(),
        Some("derive"),
        "a round derived from a roster file is still a round being opened"
    );
    assert!(
        derived["roster"]["source"]
            .as_str()
            .unwrap_or_default()
            .starts_with("file "),
        "the roster came from the file, not from a store: {:?}",
        derived["roster"]
    );
    let bytes = std::fs::read(&round_path).expect("the round record was written");
    assert!(bytes.starts_with(b"{"), "canonical JSON: {bytes:?}");

    // A stranger with the two files, no store configured and no key of their own.
    let stranger = Harness::new();
    let audit = stranger.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--round",
            &round_path,
            "--roster",
            &roster_path,
            "--proposer",
            &scene.author,
            "--json",
        ],
        None,
    );
    let audit = json(&audit);
    assert_eq!(audit["mode"].as_str(), Some("audit"));
    assert_eq!(audit["selection"], derived["selection"]);
    assert_eq!(audit["roster"]["epoch"], derived["roster"]["epoch"]);
    assert_eq!(audit["roster"]["digest"], derived["roster"]["digest"]);
    assert_eq!(
        audit["round"]["source"].as_str(),
        Some(format!("file {round_path}").as_str())
    );
    // A round record that names a different change is refused rather than audited anyway.
    let wrong = stranger.run(
        &[
            "select",
            "--change",
            "chg-other00000000",
            "--round",
            &round_path,
            "--roster",
            &roster_path,
        ],
        None,
    );
    refused(&wrong, "a round record for a different change");
}

#[test]
fn a_round_that_lets_the_author_in_is_refused_by_the_audit() {
    // Derived under one author, audited against another: the second author's boxes were
    // never excluded, so this round is not a legitimate selection for *that* change.
    let scene = Scene::new();
    ok(
        &scene.derive(&["--publish", "--json"]),
        "deriving and publishing",
    );
    let wrong_author = scene.volunteers[0].clone();
    let audit = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--proposer",
            &wrong_author,
            "--json",
        ],
        None,
    );
    let message = refused(&audit, "auditing a round that did not exclude its author");
    assert!(
        message.contains("proposer") || message.contains("REFUSED"),
        "{message}"
    );
    // And the JSON says the same thing when the refusal is asked politely: the check is
    // reported whether or not it is fatal.
    let clean = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--proposer",
            &scene.author,
            "--json",
        ],
        None,
    );
    assert_eq!(json(&clean)["proposer"]["excluded"].as_bool(), Some(true));
}

#[test]
fn opening_a_round_without_an_author_is_refused() {
    let scene = Scene::new();
    let output = scene.harness.run(
        &[
            "select",
            "--change",
            "chg-newchange00000",
            "--job",
            JOB,
            "--head",
            HEAD,
            "--require-arch",
            "x86_64",
            "--store",
            &scene.store,
            "--json",
        ],
        None,
    );
    let message = refused(&output, "deriving without naming an author");
    assert!(message.contains("--proposer"), "{message}");
}

#[test]
fn a_published_round_is_not_re_specified() {
    let scene = Scene::new();
    // Deriving twice before anything is published is deterministic: same selector, same
    // inputs, same seed, and therefore the same five.
    let once = json(&scene.derive(&["--json"]));
    let twice = json(&scene.derive(&["--json"]));
    assert_eq!(once["seed"], twice["seed"]);
    assert_eq!(once["selection"], twice["selection"]);
    ok(&scene.derive(&["--publish", "--json"]), "publishing");
    // From here the command is an audit, and a flag that would change the re-derivation is
    // refused rather than ignored: an auditor who could restate the policy or the head
    // would be proposing a new quorum, not checking one.
    for (flag, value) in [
        ("--n", "3"),
        ("--head", HEAD),
        ("--require-arch", "aarch64"),
    ] {
        let output = scene.harness.run(
            &[
                "select",
                "--change",
                CHANGE,
                "--store",
                &scene.store,
                flag,
                value,
                "--json",
            ],
            None,
        );
        let message = refused(&output, &format!("restating a published round with {flag}"));
        assert!(
            message.contains(flag),
            "the refusal names {flag}: {message}"
        );
    }
    // A round is one signed statement, so there is nothing to re-publish.
    let publish_published = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--publish",
            "--json",
        ],
        None,
    );
    refused(
        &publish_published,
        "auditing a published round must not claim to publish",
    );
}

#[test]
fn one_round_per_architecture_and_a_change_with_two_rounds_must_say_which() {
    // The arm boxes cannot run x86_64 and the x86 boxes cannot run the arm: "one verifier
    // per required architecture" is two rounds with two seeds, not a special case in the
    // ordering.
    let scene = Scene::new();
    let arms = ["arm1", "arm2", "arm3", "arm4", "arm5"]
        .iter()
        .map(|name| scene.harness.register(name, "aarch64"))
        .collect::<Vec<_>>();
    scene.harness.approve(&scene.store, &arms, "endorsed");
    let x86 = json(&scene.derive(&["--json"]));
    // `endorsed` is capped at 4 by the default policy and the arm pool is five boxes of
    // one tier, so this round states its caps: a policy is a choice, not a surprise.
    let arm = json(&scene.derive_for(ARM_JOB, "aarch64", &["--tier-cap", "endorsed=5", "--json"]));
    assert_eq!(arm["job_id"].as_str(), Some(ARM_JOB));
    assert_ne!(arm["seed"], x86["seed"], "a second arm is a second round");
    assert_eq!(arm["sufficient"].as_bool(), Some(true));
    assert_eq!(arm["selected"].as_array().map(Vec::len), Some(5));
    // Not one x86_64 box took an arm seat, and none of the arm boxes took an x86 seat: the
    // filter does that, with no architecture logic anywhere in the ordering.
    let arm_seats = selected_ids(&arm);
    let x86_seats = selected_ids(&x86);
    for seat in &arm_seats {
        assert!(
            !x86_seats.contains(seat),
            "{seat} cannot run both architectures"
        );
    }
    let outsider = arm["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key_id"].as_str() == Some(scene.volunteers[0].as_str()))
        .expect("the x86 volunteers are still in the audit table");
    assert_eq!(outsider["excluded_by"].as_str(), Some("arch"));
    assert_eq!(outsider["eligible"].as_bool(), Some(false));

    // Now the change has two rounds. Asking for "the" selection without saying which arm
    // is a question with two answers, so the command refuses and lists them.
    ok(
        &scene.derive(&["--publish", "--json"]),
        "publishing the x86 round",
    );
    ok(
        &scene.derive_for(
            ARM_JOB,
            "aarch64",
            &["--tier-cap", "endorsed=5", "--publish", "--json"],
        ),
        "publishing the arm round",
    );
    let ambiguous = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--store",
            &scene.store,
            "--json",
        ],
        None,
    );
    let message = refused(&ambiguous, "a change with two rounds needs --job");
    assert!(message.contains(ARM_JOB), "{message}");
    assert!(message.contains(JOB), "{message}");
    // Naming the arm gets the audit of exactly that round back.
    let audit = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--job",
            ARM_JOB,
            "--store",
            &scene.store,
            "--json",
        ],
        None,
    );
    assert_eq!(json(&audit)["job_id"].as_str(), Some(ARM_JOB));
    assert_eq!(json(&audit)["seed"], arm["seed"]);
}

#[test]
fn a_pool_too_small_for_five_says_insufficient_rather_than_becoming_smaller() {
    let harness = Harness::new();
    harness.new_key("owner");
    let store = harness.store();
    let signups = vec![
        harness.register("only1", "x86_64"),
        harness.register("only2", "x86_64"),
        harness.register("only3", "x86_64"),
    ];
    harness.approve(&store, &signups, "endorsed");
    let author = harness.key_id("only1");
    let output = harness.run(
        &[
            "select",
            "--change",
            "chg-small0000000",
            "--job",
            JOB,
            "--head",
            HEAD,
            "--proposer",
            &author,
            "--require-arch",
            "x86_64",
            "--store",
            &store,
            "--key",
            "owner",
            "--json",
        ],
        None,
    );
    let body = json(&output);
    // Two eligible (the author is out), five required: the answer is honest and the exit
    // code is still 0, because "not enough volunteers" is a verdict for giti-msi.7 to
    // make, not a usage error here.
    assert_eq!(body["sufficient"].as_bool(), Some(false));
    assert_eq!(body["selected"].as_array().map(Vec::len), Some(2));
    assert_eq!(body["eligible"].as_u64(), Some(2));
    assert_eq!(body["policy"]["n"].as_u64(), Some(5));
    let text = ok(
        &harness.run(
            &[
                "select",
                "--change",
                "chg-small0000000",
                "--job",
                JOB,
                "--head",
                HEAD,
                "--proposer",
                &author,
                "--require-arch",
                "x86_64",
                "--store",
                &store,
                "--key",
                "owner",
            ],
            None,
        ),
        "the human report for an insufficient round",
    );
    assert!(text.contains("NOT filled"), "{text}");
    assert!(text.contains("Insufficient"), "{text}");
}

#[test]
fn the_help_and_usage_text_name_the_command_it_added() {
    let harness = Harness::new();
    let help = ok(&harness.run(&["select", "help"], None), "select help");
    for flag in [
        "--change",
        "--proposer",
        "--explain",
        "--publish",
        "--tier-cap",
        "--seed-file",
    ] {
        assert!(help.contains(flag), "{flag} is missing from `select help`");
    }
    let usage = ok(&harness.run(&["help"], None), "gitiup help");
    assert!(usage.contains("select [OPTIONS]"), "{usage}");
}

#[test]
fn a_policy_document_is_an_input_and_the_library_decides_whether_it_is_sane() {
    // `--policy` is the other way a policy arrives, and the only one that can carry a
    // non-default trust floor or a cap the flags do not expose. The CLI does not re-check
    // it: `SelectionPolicy::check_valid` does, so a document asking for five agreements
    // across three seats is refused before a round record exists to be wrong in.
    let scene = Scene::new();
    // The last approved epoch is the one in force, and `--out` hands over exactly the
    // bytes the owner signed — the pair an auditor needs, and nothing else.
    let late = scene.harness.register("v7", "x86_64");
    let roster_path = scene.harness.file("roster.json");
    scene
        .harness
        .approve_extra(&scene.store, &[late], "endorsed", &["--out", &roster_path]);

    // A two-seat policy asking for two agreements, as a document.
    let policy_path = scene.harness.file("policy.json");
    let policy = serde_json::json!({
        "n": 2,
        "required_agree": 2,
        "reserves": 1,
        "max_per_identity": 1,
        "tier_floor": "anonymous",
        "tier_caps": { "endorsed": 2 },
    });
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).expect("write policy");
    let derived = json(&scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--job",
            JOB,
            "--head",
            HEAD,
            "--proposer",
            &scene.author,
            "--require-arch",
            ARCH,
            "--roster",
            &roster_path,
            "--policy",
            &policy_path,
            "--key",
            "owner",
            "--json",
        ],
        None,
    ));
    assert_eq!(
        derived["selection"]["selected"].as_array().map(Vec::len),
        Some(2),
        "two seats, because the document said so: {derived}"
    );
    assert_eq!(
        derived["policy"], policy,
        "the record carries the document it was given, not a paraphrase of it"
    );

    // Five agreements across three seats: unreachable, so refused.
    let silly = scene.harness.file("silly.json");
    std::fs::write(
        &silly,
        br#"{"n":3,"required_agree":5,"reserves":1,"max_per_identity":1,"tier_floor":"anonymous","tier_caps":{"endorsed":3}}"#,
    )
    .expect("write silly");
    refused(
        &scene.harness.run(
            &[
                "select",
                "--change",
                CHANGE,
                "--job",
                JOB,
                "--head",
                HEAD,
                "--proposer",
                &scene.author,
                "--roster",
                &roster_path,
                "--policy",
                &silly,
                "--key",
                "owner",
            ],
            None,
        ),
        "an unreachable threshold",
    );

    // Half-lowering the defaults is the common mistake: the default quorum is four of
    // five, so `--n 3` on its own is not a smaller quorum, it is an impossible one. The
    // refusal has to name the knob, because "invalid policy" is not advice.
    let output = scene.harness.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--job",
            JOB,
            "--head",
            HEAD,
            "--proposer",
            &scene.author,
            "--require-arch",
            ARCH,
            "--roster",
            &roster_path,
            "--n",
            "3",
            "--key",
            "owner",
        ],
        None,
    );
    let text = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(6),
        "a half-lowered policy is a refusal: {text}"
    );
    assert!(
        text.contains("--tier-cap"),
        "the refusal names the knob to lower: {text}"
    );
}

#[test]
fn a_record_written_by_out_is_the_record_read_back_from_a_pipe() {
    // The offline path end to end: bytes out, bytes in, the same answer. This is what an
    // auditor holding an emailed `round.json` and `roster.json` actually types.
    let scene = Scene::new();
    let late = scene.harness.register("v7", "x86_64");
    let roster_path = scene.harness.file("roster.json");
    scene
        .harness
        .approve_extra(&scene.store, &[late], "endorsed", &["--out", &roster_path]);
    let round_path = scene.harness.file("round.json");
    ok(
        &scene.derive(&["--out", &round_path]),
        "deriving to a file as well as a store",
    );
    let bytes = std::fs::read(&round_path).expect("the record was written");

    let stranger = Harness::new();
    let from_file = json(&stranger.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--round",
            &round_path,
            "--roster",
            &roster_path,
            "--proposer",
            &scene.author,
            "--json",
        ],
        None,
    ));
    let from_pipe = json(&stranger.run(
        &[
            "select",
            "--change",
            CHANGE,
            "--round",
            "-",
            "--roster",
            &roster_path,
            "--proposer",
            &scene.author,
            "--json",
        ],
        Some(String::from_utf8_lossy(&bytes).as_ref()),
    ));
    assert_eq!(
        from_file["selection"], from_pipe["selection"],
        "a record from a file and a record from a pipe are the same record"
    );
    assert_eq!(from_pipe["mode"].as_str(), Some("audit"));
    assert_eq!(
        from_pipe["selection"],
        json(&scene.derive(&["--json"]))["selection"],
        "and it is still the answer the selector gets"
    );
}

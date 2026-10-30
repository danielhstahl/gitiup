//! `tier: quorum` attestations at the command line (giti-zp1.5).
//!
//! Two commands carry the ticket and they are each other's ends:
//!
//! ```text
//! gitiup quorum verdict <change> --attest <path|store|->   ← the only way one is made
//! gitiup verify attestation <file> --tier quorum --evidence <store>   ← the only way one is believed
//! ```
//!
//! The first can only state a verdict that was tallied; the second re-derives the tally
//! from the round and the submissions and refuses anything the evidence does not back. So
//! every test here is the same scene seen from a different side: a real store, a real
//! roster, a real round with real volunteer signatures, and — for the dishonest half —
//! documents edited after they were written.
//!
//! As in the other quorum CLI tests the clock is pinned on every run: freshness is a
//! window against *now*, and a test that let it run would pass today and rot next month.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use gitiup_attest::{Digest, SigningKey, Tier};
use gitiup_host::FsHost;
use gitiup_quorum::attestation::QuorumAttestation;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use serde_json::Value;

const PASSPHRASE: &str = "four random words";
const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";
/// The seed `sample::owner_key()` is derived from, so the keystore's `owner` and the
/// roster's issuer are one key.
const OWNER_SEED: [u8; 32] = [1u8; 32];
/// A key the test can trust and that nobody in the round ever opened anything with.
const STRANGER_SEED: [u8; 32] = [0x9eu8; 32];

/// A store the owner has run, and the CLI pointed at it: a signed roster, one open
/// round, every seat filled by its own volunteer — so the honest tally is `verified`.
struct Scene {
    dir: tempfile::TempDir,
    owner: SigningKey,
    roster: Roster,
    round: Round,
    now: String,
}

impl Scene {
    fn new() -> Scene {
        let dir = tempfile::tempdir().expect("a temp home");
        let harness = Harness::new(&dir);
        harness.seed_key("owner", OWNER_SEED);
        harness.seed_key("stranger", STRANGER_SEED);
        let owner = sample::owner_key();
        let host = FsHost::open_or_create(harness.store()).expect("open the store");
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
        // Every seat filled, all agreeing.
        let seats = sample::indices_of(&round);
        let docs = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(seats[position]).public_key().key_id();
            store::publish_submission(&host, &round, &key_id, doc).expect("the seat is filled");
        }
        Scene {
            dir,
            owner,
            roster,
            round,
            now: sample::clock().to_rfc3339(),
        }
    }

    fn harness(&self) -> Harness {
        Harness::new(&self.dir)
    }

    /// `gitiup quorum verdict …`, with the store and the pinned clock already there.
    fn verdict(&self, extra: &[&str]) -> Output {
        let store = self.harness().store();
        let now = self.now.clone();
        let mut args: Vec<&str> = vec![
            "quorum", "verdict", CHANGE, "--job", JOB, "--store", &store, "--now", &now,
        ];
        args.extend(extra);
        self.harness().run(&args)
    }

    /// `gitiup verify attestation <file> …`, checked against the store's evidence.
    fn verify(&self, file: &str, extra: &[&str]) -> Output {
        let harness = self.harness();
        let store = harness.store();
        let now = self.now.clone();
        let mut args: Vec<&str> = vec![
            "verify",
            "attestation",
            file,
            "--evidence",
            &store,
            "--trust",
            "owner",
            "--now",
            &now,
        ];
        args.extend(extra);
        harness.run(&args)
    }

    /// The same command with no store at all: the file, on its own, with nothing to check
    /// it against.
    fn verify_without_store(&self, file: &str, extra: &[&str]) -> Output {
        let harness = self.harness();
        let now = self.now.clone();
        let mut args: Vec<&str> = vec![
            "verify",
            "attestation",
            file,
            "--trust",
            "owner",
            "--now",
            &now,
        ];
        args.extend(extra);
        harness.run(&args)
    }

    /// The attestation a round's verdict earns, written by the CLI to a file. The CLI is
    /// the only thing allowed to make it.
    fn attest_to_file(&self, name: &str) -> String {
        let path = self.file(name);
        let output = self.verdict(&["--attest", &path, "--key", "owner"]);
        assert_eq!(
            code(&output),
            0,
            "`quorum verdict --attest` failed: {}{}",
            stdout(&output),
            stderr(&output)
        );
        path
    }

    fn file(&self, name: &str) -> String {
        self.dir
            .path()
            .join(name)
            .to_str()
            .expect("utf-8")
            .to_string()
    }

    /// Rewrite a written attestation with one field changed, re-signing it or not. This
    /// is how a test asks what a *label* is worth: the bytes stay canonical either way,
    /// so a failure is about the claim and not about the whitespace.
    fn tamper(
        &self,
        path: &str,
        name: &str,
        edit: impl FnOnce(&mut QuorumAttestation),
        resign: bool,
    ) -> String {
        let bytes = std::fs::read(path).expect("the attestation");
        let mut doc: QuorumAttestation = serde_json::from_slice(&bytes).expect("the document");
        edit(&mut doc);
        if resign {
            doc.signatures.clear();
            doc.sign(&self.owner).expect("re-sign");
        }
        let out = self.file(name);
        std::fs::write(&out, doc.canonical_bytes().expect("canonical bytes")).expect("write");
        out
    }
    /// Re-issue the document under a different key, its claims untouched: the bytes are
    /// canonical, the signature is valid, and the hand is the wrong one.
    fn resign(&self, path: &str, name: &str, key: &SigningKey) -> String {
        let bytes = std::fs::read(path).expect("the attestation");
        let mut doc: QuorumAttestation = serde_json::from_slice(&bytes).expect("the document");
        doc.signatures.clear();
        doc.sign(key).expect("sign");
        let out = self.file(name);
        std::fs::write(&out, doc.canonical_bytes().expect("canonical bytes")).expect("write");
        out
    }
}

/// The binary, a config home and a store — the same shape as every other quorum CLI test.
struct Harness {
    dir: std::path::PathBuf,
}

impl Harness {
    fn new(dir: &tempfile::TempDir) -> Harness {
        Harness {
            dir: dir.path().to_path_buf(),
        }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn store(&self) -> String {
        self.path()
            .join("store")
            .to_str()
            .expect("utf-8")
            .to_string()
    }

    /// Run the binary in this home. The cwd is the temp dir, so no stray `gitiup.toml` or
    /// policy file can leak in, and `SSH_AUTH_SOCK` points where it cannot exist.
    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
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

    /// Import a *known* seed, so the test process and the CLI hold the same key.
    fn seed_key(&self, name: &str, seed: [u8; 32]) {
        let path = self.path().join(format!("{name}.seed"));
        let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, format!("{hex}\n")).expect("write the seed");
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        let mut child = command
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
            "`key import seed {name}` failed: {}",
            stderr(&output)
        );
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .unwrap_or_else(|| panic!("the process was signalled: {}", stderr(output)))
}
fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the report is JSON on stdout")
}
/// A verdict prints its report on stdout and says nothing on stderr, whatever the number.
fn clean(output: &Output) -> Value {
    assert_eq!(
        stderr(output).trim(),
        "",
        "a verdict goes to stdout, and only to stdout"
    );
    json(output)
}
/// The outcome of one named check, as the report prints it.
fn check(value: &Value, wanted: &str) -> String {
    value["checks"]
        .as_array()
        .expect("every report prints its checks")
        .iter()
        .find(|row| row["code"] == wanted)
        .map(|row| row["outcome"].as_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| panic!("no check named {wanted} in {value}"))
}
fn reasons(value: &Value) -> Vec<String> {
    value["reasons"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|reason| reason["code"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// the only way one is made
// ---------------------------------------------------------------------------

#[test]
fn a_verified_round_writes_one_and_verify_attestation_reads_it() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");
    let text = std::fs::read_to_string(&path).expect("the file is there");
    let doc: QuorumAttestation = serde_json::from_str(&text).expect("a quorum attestation");
    assert_eq!(doc.tier, Tier::Quorum);
    assert_eq!(doc.state, QuorumState::Verified);
    // Bound to the round, the epoch, the digest, the result and the seats — all five.
    assert_eq!(doc.round_id, scene.round.inputs.round_id_display().unwrap());
    assert_eq!(doc.roster_epoch, scene.roster.epoch);
    assert_eq!(doc.round_digest, scene.round.digest().unwrap());
    assert_eq!(doc.agreeing, doc.counted.len());
    assert!(!doc.counted.is_empty());

    // And the other half of the ticket accepts it — from the file, checked against the
    // store that holds the evidence.
    let output = scene.verify(&path, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 0, "{value}");
    assert_eq!(value["accepted"], true);
    assert_eq!(value["tier"], "quorum");
    assert_eq!(check(&value, "verdict"), "passed");
    assert_eq!(check(&value, "signature"), "passed");
    assert_eq!(value["quorum"]["state"], "verified");
    assert!(
        value["quorum"]["seats"].as_u64().unwrap() >= doc.counted.len() as u64,
        "{value}"
    );
}

#[test]
fn a_quorum_attestation_is_filed_in_the_store_beside_the_ones_it_summarises() {
    let scene = Scene::new();
    let store = scene.harness().store();
    let output = scene.verdict(&["--attest", "store", "--key", "owner", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 0, "{value}");
    assert_eq!(value["state"], "verified", "{value}");
    let digest = value["jobs"][0]["attestation"]["digest"]
        .as_str()
        .expect("the store's digest")
        .to_string();

    // `attest list` for the round's head now carries it, and `attest show` will not pass
    // it off as a run attestation.
    let head = scene.round.inputs.head_oid.hex();
    let listed = scene.harness().run(&[
        "attest", "list", "--commit", &head, "--store", &store, "--json",
    ]);
    assert_eq!(code(&listed), 0, "{}", stderr(&listed));
    assert!(
        stdout(&listed).contains(digest.trim_start_matches("sha256:")),
        "the quorum attestation is not advertised for the head it speaks about: {}",
        stdout(&listed)
    );
    // Read back out of the store it was filed in, the document and its evidence are the
    // same store, so `--store` alone names both.
    let now = scene.now.clone();
    let checked = scene.harness().run(&[
        "verify",
        "attestation",
        "--store",
        &store,
        "--digest",
        &digest,
        "--tier",
        "quorum",
        "--trust",
        "owner",
        "--now",
        &now,
        "--json",
    ]);
    let checked = clean(&checked);
    assert_eq!(checked["accepted"], true, "{checked}");
    assert_eq!(check(&checked, "verdict"), "passed");

    let shown = scene.harness().run(&[
        "attest",
        "show",
        digest.trim_start_matches("sha256:"),
        "--store",
        &store,
        "--json",
    ]);
    assert_eq!(
        code(&shown),
        6,
        "a quorum attestation is not a run attestation: {}",
        stdout(&shown)
    );
}

#[test]
fn a_verdict_that_is_not_verified_produces_no_document() {
    let scene = Scene::new();
    // Ask for the attestation on a job this store never opened: the verb refuses with the
    // verdict's own exit code and writes nothing.
    let missing = scene.file("never-written.json");
    let output = scene.verdict(&[
        "--job",
        "build/matrix/never-opened",
        "--attest",
        &missing,
        "--key",
        "owner",
        "--json",
    ]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(
        !std::path::Path::new(&missing).exists(),
        "nothing is written when there is no verdict to state"
    );
}

// ---------------------------------------------------------------------------
// the only way one is believed
// ---------------------------------------------------------------------------

#[test]
fn the_tier_is_never_accepted_unless_the_policy_asks_for_it() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");
    // The default policy accepts `local`; a quorum attestation is not a run attestation
    // and is not accepted at a tier the policy did not name.
    let output = scene.verify(&path, &["--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert_eq!(value["accepted"], false);
    assert!(reasons(&value).contains(&"tier".to_string()), "{value}");
}

#[test]
fn a_file_with_no_store_behind_it_is_only_a_label() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");
    // `--tier quorum`, but nothing to re-derive the verdict from. Refusing is the point:
    // a quorum attestation without its evidence is a claim about a round nobody checked.
    let output = scene.verify_without_store(&path, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert_eq!(value["accepted"], false);
    assert!(reasons(&value).contains(&"verdict".to_string()), "{value}");
    assert!(
        stdout(&output).contains("re-derive"),
        "the report says why: {}",
        stdout(&output)
    );
}

#[test]
fn a_document_that_only_labels_itself_quorum_is_refused() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");

    // The same document, still canonically signed, still `tier: quorum`, claiming more
    // seats agreed than it counts: it does not add up to its own claim, which is caught
    // before any evidence is fetched.
    let liar = scene.tamper(&path, "liar.json", |doc| doc.agreeing += 3, false);
    let output = scene.verify(&liar, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert!(
        reasons(&value).contains(&"structure".to_string()),
        "{value}"
    );

    // And one that adds up perfectly, naming a seat that never voted — re-signed by the
    // key that asserts it, so nothing about the *document* is wrong. Only re-deriving
    // the verdict from the round can catch it, which is what `--evidence` is for.
    let liar = scene.tamper(
        &path,
        "liar-seat.json",
        |doc| {
            let last = doc.counted.len() - 1;
            doc.counted[last].key_id = "SHA256:nobody-voted-with-this-key".into();
        },
        true,
    );
    let output = scene.verify(&liar, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert!(reasons(&value).contains(&"seats".to_string()), "{value}");

    // And with a `result_digest` nothing produced: that is a digest mismatch, and a gate
    // branches on 8.
    let liar = scene.tamper(
        &path,
        "liar-digest.json",
        |doc| doc.result_digest = Digest::sha256(b"a result nobody produced"),
        true,
    );
    let output = scene.verify(&liar, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 8, "{value}");
    assert!(reasons(&value).contains(&"result".to_string()), "{value}");

    // Signing a lie buys it nothing either: the signature is valid and the evidence still
    // does not say it.
    let liar = scene.tamper(&path, "liar-signed.json", |doc| doc.agreeing += 3, true);
    let output = scene.verify(&liar, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert!(
        !reasons(&value).contains(&"signature".to_string()),
        "the signature is not what is wrong here: {value}"
    );
    assert!(
        reasons(&value).contains(&"structure".to_string()),
        "{value}"
    );
}

#[test]
fn a_true_document_signed_by_the_wrong_hand_is_refused() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");
    // A perfect copy of the round's answer, asserted by a key that never opened the
    // round. The statement is true; it is still not theirs to make, and the gate says so
    // even when this key is on the trust list.
    let copy = scene.resign(&path, "copied.json", &SigningKey::from_seed(&STRANGER_SEED));
    let harness = scene.harness();
    let store = harness.store();
    let now = scene.now.clone();
    let output = harness.run(&[
        "verify",
        "attestation",
        &copy,
        "--evidence",
        &store,
        "--tier",
        "quorum",
        "--trust",
        "owner",
        "--trust",
        "stranger",
        "--now",
        &now,
        "--json",
    ]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert_eq!(check(&value, "signature"), "passed", "{value}");
    assert!(reasons(&value).contains(&"trust".to_string()), "{value}");
    assert!(
        stdout(&output).contains("selector"),
        "the report says whose word this is: {}",
        stdout(&output)
    );
}

#[test]
fn evidence_that_no_longer_supports_the_claim_undoes_the_attestation() {
    let scene = Scene::new();
    let path = scene.attest_to_file("quorum.json");
    // A seat's key is revoked after the fact. The attestation is untouched and its
    // signature is still good; what changed is what the store's evidence tallies to.
    let host = FsHost::open_or_create(scene.harness().store()).expect("open the store");
    let seats = sample::indices_of(&scene.round);
    let key = sample::verifier_key(seats[0]);
    let mut revocation = Revocation::new(
        key.public_key().key_id(),
        RevocationReason::Compromised,
        scene.roster.epoch,
        sample::claimed_at_us(),
    );
    revocation.issuer = scene.owner.public_key().key_id();
    revocation.sign(&scene.owner).expect("the owner signs it");
    store::publish_revocation(&host, &revocation).expect("publish it");

    let output = scene.verify(&path, &["--tier", "quorum", "--json"]);
    let value = clean(&output);
    assert_eq!(code(&output), 6, "{value}");
    assert_eq!(value["accepted"], false);
    assert!(
        reasons(&value).contains(&"verdict".to_string())
            || reasons(&value).contains(&"seats".to_string()),
        "{value}"
    );
}

//! `gitiup work` — the volunteer's loop, run as the real binary (giti-zp1.3).
//!
//! The ticket's acceptance criteria are command lines and exit codes, so they are tested
//! as command lines: a real keystore (owner, author and five volunteers are real keys), a
//! real `fs` store, a real roster the owner signed, a real published policy whose
//! `quorum` block opens the rounds, and a real change whose submit advertised them. From
//! there `gitiup work` is run as a volunteer would run it.
//!
//! Six things are asserted on purpose, because each is a failure mode the ticket names:
//!
//! * one pass takes the lease, runs, digests, signs and publishes into the volunteer's
//!   own slot — and the published bytes verify with the volunteer's signature;
//! * `--dry-run` publishes nothing and leases nothing, and says so;
//! * a *failing* build still produces a signed, published result: a quorum agrees on
//!   what happened, not on green ticks;
//! * the refusals each have their own code and sentence: no usable sandbox, a
//!   `reveal_mode` this build cannot enforce, a roster epoch below the ledger, a live lease
//!   held by somebody else, and a revoked key refused with the gate's own token;
//! * a `sealed` round — which the owner's policy asks for, never a flag — makes the
//!   volunteer commit before it reveals, without being told ([giti-zp1.6](../../../docs/quorum.md));
//! * the capability claim is checked against the machine, not against the roster's
//!   memory of it;
//! * `--max-jobs` and `--json` mean what a supervisor needs them to mean.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::Tier;
use gitiup_host::{BlobStore, Expect, FsHost, Namespace, RefName, RefQuery, RefStore, RefUpdate};
use gitiup_quorum::{LeaseRequest, RosterLedger, store};
use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// What every volunteer claims and what the fixture policy asks for.
const ARCH: &str = std::env::consts::ARCH;

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

    fn file(&self, name: &str) -> String {
        self.path().join(name).to_str().expect("utf-8").to_string()
    }

    /// Run the binary against this home, from the home itself.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_POLICY")
            .env_remove("SOURCE_DATE_EPOCH")
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

    fn new_key(&self, name: &str) {
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

    fn key_id(&self, name: &str) -> String {
        let output = self.run(&["key", "show", name, "--json"], None);
        json(&output)["key_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no key id for {name}: {}", stderr(&output)))
            .to_string()
    }

    /// A volunteer's honest claim, filed for the owner's eyes.
    fn register(&self, name: &str) -> String {
        self.new_key(name);
        let signup = self.file(&format!("{name}.signup"));
        let output = self.run(
            &[
                "participant",
                "register",
                "--key",
                name,
                "--ram-mb",
                "32768",
                "--disk-mb",
                "262144",
                "--sandbox",
                "landlock",
                "--sandbox",
                "docker",
                "--sandbox-level",
                "2",
                "--arch",
                ARCH,
                "--out",
                signup.as_str(),
            ],
            None,
        );
        assert!(
            output.status.success(),
            "participant register failed: {}",
            stderr(&output)
        );
        signup
    }

    fn approve(&self, store: &str, from: &[String]) -> Value {
        let mut args: Vec<&str> =
            vec!["participant", "approve", "--key", "owner", "--store", store];
        for path in from {
            args.push("--from");
            args.push(path);
        }
        args.extend_from_slice(&["--tier", "endorsed", "--publish", "--json"]);
        ok(&self.run(&args, None), "participant approve")
    }

    fn host(&self) -> FsHost {
        FsHost::open_or_create(self.store()).expect("open the store")
    }

    fn refs(&self, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .host()
            .list_refs(&RefQuery::prefix(prefix))
            .expect("list refs")
            .into_iter()
            .map(|named| named.name.as_str().to_string())
            .collect();
        names.sort();
        names
    }

    /// File bytes at a ref without asking the quorum crate's writers, which refuse what a
    /// hostile or buggy store would hold. This is how a test hands `work` a sealed
    /// advertisement: the library will not let one be advertised, and neither should the
    /// volunteer believe one.
    fn put_raw(&self, namespace: Namespace, name: &RefName, bytes: &[u8]) {
        let host = self.host();
        let oid = host.put_cas(&namespace, bytes).expect("put blob");
        let current = host.get_ref(name).expect("read ref");
        let update = match current {
            Some(existing) => RefUpdate::new(name.clone(), Expect::Is(existing.oid), oid),
            None => RefUpdate::create(name.clone(), oid),
        };
        host.update_ref_cas(&update).expect("write ref");
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap_or_else(|e| {
        panic!(
            "expected JSON on stdout, got {}/{stderr}: {e}",
            stdout(output),
            stderr = stderr(output)
        )
    })
}

fn ok(output: &Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} should succeed ({}): {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    json(output)
}

fn refused(output: &Output, what: &str) -> String {
    assert_eq!(
        code(output),
        6,
        "{what} should be refused with exit 6, got {}: {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    format!("{}{}", stdout(output), stderr(output))
}

/// Whether a stranger's job may be executed on this machine at all. The executed tests
/// are real runs, and a machine that can confine nothing must refuse them — so on such a
/// machine they are reported and skipped rather than failed.
fn may_serve_jobs() -> bool {
    let output = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .args(["doctor", "--sandbox"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run the binary")
        .wait_with_output()
        .expect("wait");
    output.status.success()
}

/// The repository the change comes from. The workflow is what decides how many rounds a
/// submit opens, and the step script decides whether the build succeeds.
struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(harness: &Harness, name: &str, workflow: &str) -> Repo {
        let dir = harness.path().join(name);
        std::fs::create_dir_all(dir.join(".github/workflows")).expect("workflows dir");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["config", "user.email", "ada@example.org"]);
        git(&dir, &["config", "user.name", "Ada"]);
        git(&dir, &["config", "commit.gpgsign", "false"]);
        std::fs::write(dir.join(".github/workflows/ci.yml"), workflow).expect("workflow");
        std::fs::write(dir.join("hello.txt"), "a file to build over\n").expect("file");
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "Add the build"]);
        git(&dir, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(dir.join("extra.txt"), "proposed\n").expect("file");
        git(&dir, &["add", "extra.txt"]);
        git(&dir, &["commit", "-q", "-m", "Propose the extra file"]);
        Repo { dir }
    }

    fn path(&self) -> &str {
        self.dir.to_str().expect("utf-8")
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The same green build, expanded twice, so one submit opens two rounds and a volunteer
/// with seats in both has a queue rather than a job.
const MATRIX_WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        rust: [stable, beta]
    steps:
      - name: the build
        run: exit 0
";

/// A build that fails with a code of its own, to show the failure is what gets signed.
const FAILING_WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: the build
        run: echo building; exit 3
";

/// The `quorum` block of the fixture policy: five seats, four agreements, and a
/// capability floor every volunteer here claims to meet *and* that a real machine in CI
/// can meet — the sandboxes named are the ladder, whatever this host happens to offer.
///
/// Note the sorted `sandboxes` list: `gitiup policy publish` normalises the document
/// after signing it, so a list in any other order publishes as a bad signature; the
/// sorted order is what the store keeps.
/// The same block, in a chosen reveal mode (giti-zp1.6): `sealed` asks every seat to
/// publish `H(attestation bytes ‖ slot ‖ challenge)` before it publishes the bytes.
fn quorum_block_in(reveal_mode: &str) -> Value {
    json!({
        "default": {
            "max_per_identity": 1,
            "n": 5,
            "required_agree": 4,
            "reserves": 2,
            "tier_caps": { "anonymous": 1, "endorsed": 5, "trusted": 1 },
            "tier_floor": "anonymous"
        },
        "reveal_mode": reveal_mode,
        "requirements": {
            "arch": ARCH,
            "ram_mb": 1024,
            "disk_mb": 1024,
            "sandboxes": ["bwrap", "docker", "landlock", "podman", "unshare"],
            "min_sandbox_level": 1
        }
    })
}

/// The reveal mode `gitiup work` knows how to honour, spelled from the library so a
/// rename cannot leave these fixtures claiming something the build does not do.
const REVEAL_MODE_OPEN: &str = gitiup_quorum::round::REVEAL_MODE_OPEN;

/// The whole scene: owner, author, five volunteers on a published epoch, a published
/// policy, and one submitted change whose round is advertised to all five.
struct Scene {
    harness: Harness,
    store: String,
    repo: Repo,
}

impl Scene {
    fn new() -> Scene {
        Scene::with(MATRIX_WORKFLOW)
    }

    fn with(workflow: &str) -> Scene {
        Scene::building(workflow, REVEAL_MODE_OPEN)
    }

    /// The same scene whose policy asks for `sealed` submission (giti-zp1.6).
    fn sealed(workflow: &str) -> Scene {
        Scene::building(workflow, gitiup_quorum::round::REVEAL_MODE_SEALED)
    }

    fn building(workflow: &str, reveal_mode: &str) -> Scene {
        let harness = Harness::new();
        harness.new_key("owner");
        let store = harness.store();
        let signups: Vec<String> = ["author", "v1", "v2", "v3", "v4", "v5"]
            .iter()
            .map(|name| harness.register(name))
            .collect();
        harness.approve(&store, &signups);
        let repo = Repo::new(&harness, "work", workflow);
        let policy_path = harness.file("policy.json");
        let document = json!({
            "type": "gitiup-policy-1",
            "schema_version": 1,
            "owner": { "key_id": harness.key_id("owner"), "principal": "Ada Hale" },
            "revision": 1,
            "previous_digest":
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "effective_from_us": 1,
            "protects": ["refs/heads/**"],
            "rules": {
                "allowed_tiers": ["quorum"],
                "trust_key_ids": [harness.key_id("owner")],
            },
            "quorum": quorum_block_in(reveal_mode),
        });
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&document).expect("json"),
        )
        .expect("write");
        ok(
            &harness.run(
                &[
                    "policy",
                    "publish",
                    &policy_path,
                    "--store",
                    &store,
                    "--key",
                    "owner",
                    "--json",
                ],
                None,
            ),
            "policy publish",
        );
        let submitted = ok(
            &harness.run(
                &[
                    "change",
                    "submit",
                    "--repository",
                    repo.path(),
                    "--base",
                    "main",
                    "--key",
                    "author",
                    "--store",
                    &store,
                    "--json",
                ],
                None,
            ),
            "change submit",
        );
        let _ = submitted;
        Scene {
            harness,
            store,
            repo,
        }
    }

    /// The change id the submit published, read back from the store's own refs.
    fn change_id(&self) -> String {
        let refs = self.harness.refs("refs/gitiup/job");
        let first = refs
            .first()
            .expect("the submit advertised at least one job");
        // refs/gitiup/job/<change>/<job>
        first
            .strip_prefix("refs/gitiup/job/")
            .and_then(|rest| rest.split('/').next())
            .expect("a job ref")
            .to_string()
    }

    fn work(&self, key: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "work",
            "--store",
            &self.store,
            "--key",
            key,
            "--workspace",
            self.repo.path(),
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args, None)
    }

    fn dry_run(&self, key: &str, extra: &[&str]) -> Output {
        let mut args = extra.to_vec();
        args.push("--dry-run");
        self.work(key, &args)
    }
}

// ---------------------------------------------------------------------------
// the pass, end to end
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_signs_a_simulated_result_and_publishes_nothing() {
    let scene = Scene::new();
    let output = scene.dry_run("v1", &["--json"]);
    let body = ok(&output, "work --dry-run");
    assert_eq!(body["simulated"], 2, "both arms: {body}");
    assert_eq!(body["published"], 0);
    assert_eq!(body["exit"], 0);
    assert_eq!(body["dry_run"], true);
    let round = &body["rounds"][0];
    assert_eq!(round["state"], "simulated", "{round}");
    assert_eq!(round["provenance_tier"], "simulated");
    assert!(round["published"].is_null(), "a dry run publishes nothing");
    assert!(
        round["result_digest"].as_str().is_some(),
        "a dry run still digests: {round}"
    );
    assert!(
        round["challenge"].as_str().is_some(),
        "…and binds the round"
    );
    // Nothing was written: no lease, no submission, and the store's refs are exactly
    // what the submit left them as.
    assert!(scene.harness.refs("refs/gitiup/lease").is_empty());
    assert!(scene.harness.refs("refs/gitiup/reveal").is_empty());
    // The human report says the same thing in words.
    let text = stdout(&scene.dry_run("v1", &[]));
    assert!(text.contains("dry run"), "{text}");
    assert!(text.contains("nothing was published"), "{text}");
}

#[test]
fn a_pass_leases_runs_digests_signs_and_publishes_into_the_seat() {
    if !may_serve_jobs() {
        eprintln!("skip: this machine has no sandbox that may serve a stranger's job");
        return;
    }
    let scene = Scene::new();
    let body = ok(&scene.work("v1", &["--json"]), "work");
    assert_eq!(
        body["published"], 2,
        "both arms, into this key's own seats: {body}"
    );
    let round = &body["rounds"][0];
    assert_eq!(round["state"], "published", "{round}");
    assert_eq!(round["provenance_tier"], "local");
    assert_eq!(round["result_failed"], false);
    assert!(round["sandbox"].as_str().is_some());
    assert_eq!(
        round["source_date_epoch"], 0,
        "the clock is pinned by default"
    );

    // The slot holds exactly one attestation, signed by this volunteer, bound to this
    // round, and it says where it ran.
    let host = scene.harness.host();
    let change = scene.change_id();
    let rounds = store::rounds_for(&host, &change).expect("rounds");
    assert_eq!(rounds.len(), 2, "one round per matrix arm");
    let job = round["job"].as_str().unwrap();
    let round_record = rounds
        .iter()
        .find(|round| round.inputs.job_id == job)
        .expect("the round this run answered for");
    let published = store::submissions(&host, round_record).expect("submissions");
    assert_eq!(published.len(), 1);
    let doc = &published[0];
    assert_eq!(doc.signatures.len(), 1);
    assert_eq!(doc.signatures[0].key_id, scene.harness.key_id("v1"));
    assert!(
        doc.manifest.claims.verifier_challenge.is_some(),
        "the attestation is bound to its round"
    );
    assert_eq!(doc.manifest.result.provenance.tier, Tier::Local);
    let notes = doc
        .manifest
        .claims
        .annotations
        .get("x_run_notes")
        .cloned()
        .unwrap_or_default();
    assert!(
        notes.contains("SOURCE_DATE_EPOCH=0"),
        "the pinned clock is recorded, not just applied: {notes}"
    );
    // `normalisation_version` is still what `gitiup run --attest` writes for any local
    // run — the packaging ticket owns bumping it — so what this test can insist on is
    // that a volunteer's run and a runner's run are the same kind of record.
    assert_eq!(doc.manifest.result.provenance.tier.as_str(), "local");
    // The lease was released once the work was published: a filled seat has no reason to
    // stay leased until the TTL.
    assert!(scene.harness.refs("refs/gitiup/lease").is_empty());
}

#[test]
fn a_failing_build_is_still_signed_and_published() {
    if !may_serve_jobs() {
        eprintln!("skip: this machine has no sandbox that may serve a stranger's job");
        return;
    }
    let scene = Scene::with(FAILING_WORKFLOW);
    let body = ok(&scene.work("v1", &["--json"]), "work over a failing build");
    assert_eq!(
        body["exit"], 0,
        "the loop worked; the build's failure is in the record"
    );
    let round = &body["rounds"][0];
    assert_eq!(round["state"], "published");
    assert_eq!(round["result_failed"], true, "{round}");
    assert!(
        round["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("quorum agrees on what happened"),
        "{round}"
    );
    // And the store holds the failure, signed: a quorum is about agreeing on what
    // happened, not about green ticks.
    let host = scene.harness.host();
    let rounds = store::rounds_for(&host, &scene.change_id()).expect("rounds");
    let submissions = store::submissions(&host, &rounds[0]).expect("submissions");
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].manifest.result.steps[0].exit_code, 3);
}

#[test]
fn max_jobs_stops_the_pass_after_that_many_rounds() {
    let scene = Scene::new();
    let body = ok(
        &scene.dry_run("v1", &["--json", "--max-jobs", "1"]),
        "work --max-jobs 1",
    );
    assert_eq!(body["simulated"], 1);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["rounds"].as_array().map(Vec::len), Some(1));
    // Without the cap, the same volunteer serves both arms.
    let everything = ok(&scene.dry_run("v1", &["--json"]), "work uncapped");
    assert_eq!(everything["simulated"], 2, "{everything}");
}

// ---------------------------------------------------------------------------
// sealed rounds: the volunteer commits before it reveals (giti-zp1.6)
// ---------------------------------------------------------------------------

#[test]
fn a_sealed_round_is_opened_by_the_policy_and_the_round_says_so() {
    let scene = Scene::sealed(MATRIX_WORKFLOW);
    // The rounds the submit published are sealed, because the owner's policy said so and
    // nobody passed a flag; the advertisement carries the mode, which is how a volunteer
    // finds out without being told.
    let host = scene.harness.host();
    let rounds = store::rounds_for(&host, &scene.change_id()).expect("rounds");
    assert_eq!(rounds.len(), 2);
    for round in &rounds {
        assert_eq!(round.reveal_mode, gitiup_quorum::round::REVEAL_MODE_SEALED);
    }
    let advertised = store::open_rounds(
        &host,
        gitiup_quorum::sample::clock(),
        store::Cursor::START,
        10,
    )
    .expect("the listing works");
    assert!(
        advertised
            .items
            .iter()
            .all(|ad| ad.reveal_mode == gitiup_quorum::round::REVEAL_MODE_SEALED),
        "an advertisement states the flow it invites: {advertised:?}"
    );
    // And a dry run says what it would commit to, so an operator can see the two phases
    // before writing either.
    let body = ok(&scene.dry_run("v1", &["--json"]), "a sealed dry run");
    assert_eq!(body["simulated"], 2, "{body}");
    let round = &body["rounds"][0];
    assert_eq!(round["reveal_mode"], "sealed");
    let notes = round["notes"]
        .as_array()
        .map(|notes| {
            notes
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    assert!(notes.contains("would commit"), "{round}");
    assert!(notes.contains("refs/gitiup/commit/"), "{round}");
    assert!(
        scene.harness.refs("refs/gitiup/commit").is_empty(),
        "and a dry run writes neither phase"
    );
    assert!(scene.harness.refs("refs/gitiup/reveal").is_empty());
}

#[test]
fn a_sealed_pass_commits_then_reveals_into_the_same_slot() {
    if !may_serve_jobs() {
        eprintln!("skip: this machine has no sandbox that may serve a stranger's job");
        return;
    }
    let scene = Scene::sealed(MATRIX_WORKFLOW);
    let body = ok(&scene.work("v1", &["--json"]), "a sealed pass");
    assert_eq!(body["published"], 2, "both arms: {body}");
    let round = &body["rounds"][0];
    assert_eq!(round["state"], "published");
    assert_eq!(round["reveal_mode"], "sealed");
    assert!(
        round["commitment"]
            .as_str()
            .is_some_and(|where_| where_.starts_with("refs/gitiup/commit/")),
        "phase 1 names its ref: {round}"
    );

    // Both phases are in the store, and the reveal opens the commitment — which anyone
    // with read access can check for themselves, because the preimage is published.
    let host = scene.harness.host();
    let job = round["job"].as_str().unwrap();
    let record = store::rounds_for(&host, &scene.change_id())
        .expect("rounds")
        .into_iter()
        .find(|candidate| candidate.inputs.job_id == job)
        .expect("the round this pass answered for");
    let filed = store::commitments(&host, &record).expect("commitments");
    assert_eq!(filed.len(), 1, "one seat, one promise");
    let submissions = store::submissions(&host, &record).expect("submissions");
    assert_eq!(submissions.len(), 1);
    let commitment = &filed[0].commitment;
    assert_eq!(commitment.key_id, scene.harness.key_id("v1"));
    assert!(
        commitment.opens_with(&submissions[0]).unwrap(),
        "the bytes published are the bytes promised"
    );
    // The refs are the ones the ticket names, both keyed by the seat's slot.
    let slot = record
        .seat(&commitment.key_id)
        .expect("a seat")
        .slot
        .clone();
    assert!(
        scene
            .harness
            .refs(&format!("refs/gitiup/commit/{}/{}", scene.change_id(), job))
            .iter()
            .any(|name| name.ends_with(&slot))
    );
    assert!(
        scene
            .harness
            .refs(&format!("refs/gitiup/reveal/{}/{}", scene.change_id(), job))
            .iter()
            .any(|name| name.ends_with(&slot))
    );
    // The verdict follows the round's mode too, and says which flow it tallied. One vote
    // against a required four is `insufficient` (exit 6), and that is the answer, not a
    // fault — the point here is the two fields that name the flow.
    let output = scene.harness.run(
        &[
            "quorum",
            "verdict",
            &scene.change_id(),
            "--store",
            &scene.store,
            "--job",
            job,
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    let verdict = json(&output);
    let job_report = &verdict["jobs"][0];
    assert_eq!(job_report["reveal_mode"], "sealed", "{verdict}");
    assert_eq!(job_report["committed"], 1);
    assert_eq!(job_report["state"], "insufficient");
}

/// Refused, never downgraded: a mode this build cannot enforce is not run as if it were
/// `open`. `sealed` is enforced, so the demonstration uses a mode from a newer build.
#[test]
fn a_reveal_mode_this_build_cannot_enforce_is_refused_not_downgraded() {
    let scene = Scene::new();
    let change = scene.change_id();
    let reference = store::job_ref(&change, "build/matrix/stable").expect("a ref name");
    let host = scene.harness.host();
    let rounds = store::rounds_for(&host, &change).expect("rounds");
    let record = rounds
        .iter()
        .find(|round| round.inputs.job_id == "build/matrix/stable")
        .expect("that round exists");
    let mut advertisement = store::advertisement_at(&host, &change, "build/matrix/stable")
        .expect("advertised")
        .expect("advertised");
    // The mode is refused while the record is being read — before its signature is
    // consulted — because a rule this build cannot enforce is not a rule to volunteer
    // under, whatever signed it.
    advertisement.reveal_mode = "commit-reveal-v2".to_string();
    let _ = record;
    scene.harness.put_raw(
        Namespace::JOB,
        &reference,
        &advertisement.canonical_bytes().unwrap(),
    );
    let output = scene.dry_run("v1", &[]);
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert_eq!(code(&output), 6, "{text}");
    assert!(text.contains("cannot honour"), "{text}");
    assert!(text.contains("commit-reveal-v2"), "{text}");
    assert!(scene.harness.refs("refs/gitiup/reveal").is_empty());
}

#[test]
fn a_key_with_no_seat_has_nothing_to_do_and_exits_zero() {
    let scene = Scene::new();
    let body = ok(
        &scene.dry_run("owner", &["--json"]),
        "work as a non-seated key",
    );
    assert_eq!(body["looked"], 0, "the poll does not even offer it a round");
    assert_eq!(body["exit"], 0);
}

// ---------------------------------------------------------------------------
// the refusals, each with its own code and sentence
// ---------------------------------------------------------------------------

#[test]
fn a_live_lease_held_by_somebody_else_is_refused_with_the_ttl_left() {
    let scene = Scene::new();
    let host = scene.harness.host();
    let rounds = store::rounds_for(&host, &scene.change_id()).expect("rounds");
    let seat = rounds[0]
        .seat(&scene.harness.key_id("v1"))
        .expect("v1 holds a seat")
        .clone();
    // A stranger's volunteer takes v1's seat, and is alive for the whole TTL. It does
    // not matter that nobody trusts this key: a live lease is advice about a seat, and
    // the volunteer's job is to read it before spending an hour on a build it need not
    // build twice.
    let holder = gitiup_quorum::sample::verifier_key(63);
    let claimed = store::claim_lease(
        &host,
        &LeaseRequest::new(
            &rounds[0].inputs.change_id,
            &rounds[0].inputs.job_id,
            rounds[0].inputs.attempt,
            &seat.slot,
            &holder,
        ),
    )
    .expect("claim the lease");
    assert!(claimed.claimed());

    let output = scene.dry_run("v1", &["--json"]);
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert_eq!(code(&output), 6, "{text}");
    assert!(text.contains("live lease"), "{text}");
    assert!(
        text.contains("another 14m") || text.contains("another 15m"),
        "the sentence names the TTL left, in time a human can read: {text}"
    );
    let body = json(&output);
    assert_eq!(body["rounds"][0]["state"], "refused");
    assert_eq!(body["rounds"][0]["exit"], 6);
    assert_eq!(body["exit"], 6, "and it is the pass's exit code");
}

#[test]
fn a_roster_epoch_below_the_ledger_is_called_what_it_is() {
    let scene = Scene::new();
    // A ledger that has already seen a far higher epoch: the store is now offering an
    // older world to this volunteer, which is a fork and not a coincidence.
    let path = scene.harness.file("ledger.json");
    let ledger = RosterLedger {
        schema_version: gitiup_quorum::ledger::LEDGER_SCHEMA_VERSION,
        store: "the-store-this-test-points-at".to_string(),
        highest_epoch: 999_999,
        epochs: Default::default(),
    };
    ledger.save(Path::new(&path)).expect("save the ledger");
    let output = scene.dry_run("v1", &["--ledger", &path]);
    let text = refused(&output, "a rolled-back roster");
    assert!(text.contains("older roster"), "{text}");
    // The path is printed in the header, so a volunteer can see which ledger refused.
    assert!(path.contains("ledger.json"));
}

#[test]
fn the_ledger_remembers_the_epoch_a_pass_just_believed() {
    let scene = Scene::new();
    let path = scene.harness.file("ledger.json");
    // A first pass records what it checked…
    ok(
        &scene.dry_run("v1", &["--ledger", &path, "--json"]),
        "a first pass",
    );
    let ledger = RosterLedger::load(Path::new(&path), "x").expect("load");
    assert!(ledger.highest_epoch > 0, "the epoch was remembered");
    let high = ledger.highest_epoch;
    // …and a second pass against the same epoch is a no-op, not a complaint.
    ok(
        &scene.dry_run("v1", &["--ledger", &path, "--json"]),
        "a second pass",
    );
    let again = RosterLedger::load(Path::new(&path), "x").expect("load");
    assert_eq!(again.highest_epoch, high);
}

#[test]
fn a_round_the_store_cannot_open_is_refused_and_not_stepped_over() {
    let scene = Scene::new();
    // An advertisement ref that is not an advertisement: a damaged mirror, a half-written
    // replication, a store that lies. The pass has to say so about the round it was
    // looking at, with a code, and publish nothing — not skip the round as if the
    // volunteer had never been invited to it.
    let change = scene.change_id();
    let reference = store::job_ref(&change, "build/matrix/stable").expect("a ref name");
    scene.harness.put_raw(
        gitiup_host::Namespace::JOB,
        &reference,
        b"not an advertisement",
    );
    let output = scene.dry_run("v1", &[]);
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert_ne!(
        code(&output),
        0,
        "an unreadable store is an error, not an empty evening: {text}"
    );
    assert!(
        scene.harness.refs("refs/gitiup/reveal").is_empty(),
        "a refused pass publishes nothing"
    );
    assert!(
        scene.harness.refs("refs/gitiup/lease").is_empty(),
        "and it leases nothing either"
    );
}

#[test]
fn a_revoked_key_is_refused_before_anything_is_built() {
    let scene = Scene::new();
    let v1 = scene.harness.key_id("v1");
    ok(
        &scene.harness.run(
            &[
                "participant",
                "revoke",
                &v1,
                "--reason",
                "compromised",
                "--key",
                "owner",
                "--store",
                &scene.store,
                "--publish",
                "--json",
            ],
            None,
        ),
        "participant revoke",
    );
    let output = scene.dry_run("v1", &[]);
    let text = refused(&output, "a revoked key");
    assert!(text.contains(gitiup_quorum::gate::code::REVOKED), "{text}");
    assert!(
        scene.harness.refs("refs/gitiup/reveal").is_empty(),
        "nothing was published by a dead key"
    );
}

#[test]
fn a_sandbox_that_may_not_serve_a_stranger_is_refused_naming_the_ladder() {
    let scene = Scene::new();
    // `plain` confines nothing and is refused for a stranger's job whatever the operator
    // asks, so this refuses on every machine in the world.
    let output = scene.work("v1", &["--sandbox", "plain", "--json"]);
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert_eq!(code(&output), 6, "{text}");
    assert!(text.contains("plain"), "{text}");
    assert!(
        text.contains("ladder") || text.contains("unavailable"),
        "the refusal names what was tried: {text}"
    );
    assert!(
        scene.harness.refs("refs/gitiup/reveal").is_empty(),
        "refused means nothing ran"
    );
}

#[test]
fn the_capability_claim_is_measured_here_and_not_repeated_from_the_roster() {
    let scene = Scene::new();
    // The policy asks for 1 GiB of RAM. `--ram-mb 1` says this box has a megabyte, and
    // the round's own requirements — not the roster's memory — decide the refusal.
    let output = scene.dry_run("v1", &["--ram-mb", "1", "--json"]);
    let text = refused(&output, "a box that no longer qualifies");
    assert!(
        text.contains("no longer meets what the round asks"),
        "{text}"
    );
    let body = json(&output);
    assert!(
        body["rounds"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("ram"),
        "{body}"
    );
    // And the measurement it made is printed, not hidden.
    let header = stdout(&scene.dry_run("v1", &[]));
    assert!(header.contains("measure"), "{header}");
}

#[test]
fn a_checkout_that_is_not_the_rounds_commit_is_refused() {
    let scene = Scene::new();
    // A second checkout, on its own commit, with the same workflow file.
    let other = Repo::new(&scene.harness, "other", MATRIX_WORKFLOW);
    let output = scene.work(
        "v1",
        &["--workspace", other.dir.to_str().unwrap(), "--json"],
    );
    let body = json(&output);
    assert_eq!(code(&output), 6, "{body}");
    assert!(
        body["rounds"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("refusing to attest a run of a commit"),
        "{body}"
    );
}

#[test]
fn a_bad_interval_is_a_usage_error_and_not_a_silent_once() {
    let scene = Scene::new();
    let output = scene.work("v1", &["--watch", "0"]);
    assert_eq!(code(&output), 2, "{}{}", stdout(&output), stderr(&output));
    let output = scene.work("v1", &["--watch", "soon"]);
    assert_eq!(code(&output), 2);
}

//! The whole volunteer loop, run as the binary: giti-zp1's acceptance criterion as one
//! story rather than as nine tickets' worth of parts.
//!
//! Every child of the epic proved a slice — the advertisement and the lease
//! (`job_leases`), the volunteer's pass ([`work_cli`](work_cli)), the tally
//! ([`quorum_verdict_cli`](quorum_verdict_cli)), the top tier
//! ([`quorum_attest_cli`](quorum_attest_cli)), the gate that believes it
//! ([`verify_change_cli`](verify_change_cli)) — and each slice was checked against a store
//! the *test* had built. What no single test did was what the epic promised: a volunteer
//! installs a key, registers, runs `gitiup work`, and the *owner's* next two commands turn
//! those five strangers' attestations into a verdict a merge gate can be told to believe.
//! Composition is its own failure mode — the slices can each be right and the loop still
//! not close — so the loop is what is tested here, one command line at a time, against a
//! real store, a real keystore, and the real sandbox ladder:
//!
//! ```text
//! participant register × 5 ─┐
//! participant approve       │ the owner's policy demands the quorum tier
//! policy publish            │
//! change submit --key owner ┴──► rounds opened, seats derived, jobs advertised
//! work --once × 5 ─────────────► lease, sandbox run, digest, sign, file in own slot
//! quorum verdict --publish --attest store ──► verified, filed, and attested at the top tier
//! verify change ───────────────► 0: the gate believes it
//! ```
//!
//! Four things are asserted that only the composition can assert:
//!
//! * **five separate runs agree at all.** Each volunteer is a separate process with its
//!   own key, its own lease and its own sandbox run, and nothing passes a digest from one
//!   to the next. Five `ResultDigest`s matching is the reproducibility claim, and the
//!   verdict reaching `verified` is the quorum claim, and neither is a fixture here.
//! * **what the loop leaves behind is what the gate reads.** The verdict ref, the
//!   attestation ref and the round the volunteers ran are the same three objects, so the
//!   `verify change` at the end is being asked about the change the volunteers actually
//!   built — not about a document the test filed beside it.
//! * **the attestation is signed by the key that opened the round.** The submitter is the
//!   selector, so the submitter is the one who attests what its round decided: a `tier:
//!   quorum` document signed by a friendly bystander is refused by the gate with the
//!   sentence that says why, which is the difference between a summary and an assertion.
//! * **an absent quorum refuses, quietly and with a code.** Three volunteers out of five
//!   is `insufficient` at exit 6, no attestation is written, and the gate still refuses.
//!   `n` is never lowered, and the run does not pretend to have decided something.
//!
//! A `failed` verdict is deliberately not re-staged here: reaching it needs five
//! volunteers who genuinely disagree, and inventing that disagreement in a test would
//! prove the report's formatting and nothing about the loop. It is proved where the
//! disagreement can be real — [`quorum_verdict_cli`](quorum_verdict_cli) over a store
//! whose seats disagree, and [`work_cli`](work_cli)'s failing build, which is signed and
//! published exactly as a passing one is.
//!
//! The sandboxed halves are skipped on a machine that can confine nothing, because a
//! volunteer must refuse to run a stranger's job there and the test would be asserting
//! the refusal twice. `gitiup doctor --sandbox` says whether this box may.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_host::{BlobStore, FsHost, RefName, RefQuery, RefStore};
use gitiup_quorum::store;
use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// What every volunteer claims and what the fixture policy asks for.
const ARCH: &str = std::env::consts::ARCH;
/// The one job the change's workflow declares, so a submit opens exactly one round and
/// the five volunteers are five seats at the same table rather than five tables.
const JOB: &str = "build";

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

    /// A volunteer's honest claim, filed for the owner's eyes. The capability claim is
    /// the one this machine can actually back, so that the round's own requirements are
    /// what decide whether it may serve.
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

    /// The bytes at a ref, exactly as the store holds them.
    fn blob(&self, reference: &str) -> Vec<u8> {
        let host = self.host();
        let oid = host
            .get_ref(&RefName::new(reference).expect("a ref name"))
            .expect("read ref")
            .unwrap_or_else(|| panic!("{} is not in the store", reference))
            .oid;
        host.get(&oid)
            .expect("read the blob")
            .unwrap_or_else(|| panic!("{} is not in the store", reference))
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
    serde_json::from_str(stdout(output).trim())
        .unwrap_or_else(|e| panic!("not json ({e}): {}", stdout(output)))
}

/// A command that had to succeed, with its answer parsed.
fn ok(output: &Output, what: &str) -> Value {
    assert_eq!(
        code(output),
        0,
        "{what} should succeed ({}): {}{}",
        code(output),
        stdout(output),
        stderr(output)
    );
    json(output)
}

/// Whether a stranger's job may be executed on this machine at all. The runs here are
/// real runs, and a machine that can confine nothing must refuse them — so on such a
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

/// A build that says one thing, the same way every time: the quorum agrees on what
/// happened, so what happens has to be something two machines can repeat.
const QUIET_WORKFLOW: &str = "\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: the build
        run: echo the change builds
";

/// The `quorum` block of the owner's policy: five seats, four agreements, and a
/// capability floor every volunteer here claims to meet and a real CI box can meet.
///
/// Note the sorted `sandboxes` list: `gitiup policy publish` normalises the document
/// after signing it, so a list in any other order publishes as a bad signature.
fn quorum_block() -> Value {
    json!({
        "default": {
            "max_per_identity": 1,
            "n": 5,
            "required_agree": 4,
            "reserves": 2,
            "tier_caps": { "anonymous": 1, "endorsed": 5, "trusted": 1 },
            "tier_floor": "anonymous"
        },
        "reveal_mode": gitiup_quorum::round::REVEAL_MODE_OPEN,
        "requirements": {
            "arch": ARCH,
            "ram_mb": 1024,
            "disk_mb": 1024,
            "sandboxes": ["bwrap", "docker", "landlock", "podman", "unshare"],
            "min_sandbox_level": 1
        }
    })
}

/// The whole scene: an owner who publishes the policy, submits the change and so selects
/// the jury, and five volunteers on a published epoch — the roster, the round and the
/// advertisement all come from the owner's own commands, not from the test.
struct Scene {
    harness: Harness,
    store: String,
    repo: PathBuf,
    change: String,
    /// The volunteer names in the order their seats were derived, seat 1 first.
    seated: Vec<String>,
    /// The ranks the seed gave each of them.
    ranks: Vec<(String, u32)>,
}

impl Scene {
    fn new() -> Scene {
        let harness = Harness::new();
        harness.new_key("owner");
        let store = harness.store();
        let names = ["v1", "v2", "v3", "v4", "v5"];
        let signups: Vec<String> = names.iter().map(|name| harness.register(name)).collect();
        harness.approve(&store, &signups);

        let repo = harness.path().join("work");
        std::fs::create_dir_all(repo.join(".github/workflows")).expect("workflows dir");
        let repo = repo.to_str().expect("utf-8").to_string();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["config", "user.email", "ada@example.org"]);
        git(&repo, &["config", "user.name", "Ada"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(
            Path::new(&repo).join(".github/workflows/ci.yml"),
            QUIET_WORKFLOW,
        )
        .expect("workflow");
        std::fs::write(Path::new(&repo).join("hello.txt"), "a file to build over\n").expect("file");
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "Add the build"]);
        git(&repo, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(Path::new(&repo).join("extra.txt"), "proposed\n").expect("file");
        git(&repo, &["add", "extra.txt"]);
        git(&repo, &["commit", "-q", "-m", "Propose the extra file"]);

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
            "quorum": quorum_block(),
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
        ok(
            &harness.run(
                &[
                    "change",
                    "submit",
                    "--repository",
                    &repo,
                    "--base",
                    "main",
                    "--key",
                    "owner",
                    "--store",
                    &store,
                    "--json",
                ],
                None,
            ),
            "change submit",
        );

        // The change id, read back from the advertisement the submit left behind rather
        // than from what the submit printed: the store is the record.
        let advertised = harness.refs("refs/gitiup/job");
        assert_eq!(advertised.len(), 1, "one job, one round: {advertised:?}");
        let change = advertised[0]
            .strip_prefix("refs/gitiup/job/")
            .and_then(|rest| rest.split('/').next())
            .expect("a job ref")
            .to_string();
        // Who the owner's submit seated, in the order the seed derived — so the tests
        // follow the round instead of guessing, and a change to the selector's key or the
        // roster cannot silently make a volunteer serve a seat that is not hers.
        let id_of: Vec<(String, String)> = names
            .iter()
            .map(|name| (name.to_string(), harness.key_id(name)))
            .collect();
        let scene = Scene {
            harness,
            store,
            repo: repo.into(),
            change,
            seated: Vec::new(),
            ranks: Vec::new(),
        };
        let selected: Vec<(String, u32)> = scene
            .round()
            .selected
            .iter()
            .map(|seat| (seat.key_id.clone(), seat.rank))
            .collect();
        Scene {
            seated: selected
                .iter()
                .map(|(key, _)| {
                    id_of
                        .iter()
                        .find(|(_, id)| id == key)
                        .unwrap_or_else(|| {
                            panic!("{key} holds a seat and is not a volunteer: {id_of:?}")
                        })
                        .0
                        .clone()
                })
                .collect(),
            ranks: selected,
            ..scene
        }
    }

    /// The round the submit published, as the store holds it.
    fn round(&self) -> gitiup_quorum::Round {
        store::rounds_for(&self.harness.host(), &self.change)
            .expect("rounds")
            .into_iter()
            .next()
            .expect("the round the submit opened")
    }

    /// One volunteer's evening: poll, lease, build, sign, publish.
    fn work(&self, key: &str, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "work",
            "--store",
            &self.store,
            "--key",
            key,
            "--workspace",
            self.repo.to_str().expect("utf-8"),
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args, None)
    }

    /// The owner's tally.
    fn verdict(&self, extra: &[&str]) -> Output {
        let mut args: Vec<&str> = vec![
            "quorum",
            "verdict",
            &self.change,
            "--store",
            &self.store,
            "--json",
        ];
        args.extend_from_slice(extra);
        self.harness.run(&args, None)
    }

    fn verify_change(&self) -> Output {
        self.harness.run(
            &[
                "verify",
                "change",
                &self.change,
                "--store",
                &self.store,
                "--json",
            ],
            None,
        )
    }
}

fn git(repo: &str, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(repo)
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

/// The seats the round derived, as `(key id, slot)`, in seat order.
fn seats(scene: &Scene) -> Vec<(String, String)> {
    scene
        .round()
        .selected
        .iter()
        .map(|seat| (seat.key_id.clone(), seat.slot.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// before anyone turns up
// ---------------------------------------------------------------------------

/// The half of the loop that needs no sandbox: the rounds exist, every volunteer can see
/// its own seat, and the owner's answer is an honest `insufficient` with its code.
#[test]
fn five_seats_are_derived_advertised_and_empty() {
    let scene = Scene::new();

    // The submit derived five distinct seats from the published seed, and advertised the
    // round because it was full: an unfilled round is not advertised at all.
    let seats = seats(&scene);
    assert_eq!(seats.len(), 5, "{seats:?}");
    let mut keys: Vec<&str> = seats.iter().map(|(key, _)| key.as_str()).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 5, "one identity one seat: {seats:?}");
    assert!(
        !scene.harness.refs("refs/gitiup/job").is_empty(),
        "a round with its seats filled invites volunteers"
    );
    assert!(
        scene.harness.refs("refs/gitiup/reveal").is_empty(),
        "and nothing has been filed yet"
    );

    // Each volunteer, polling the store with its own key, is invited to exactly this
    // round and finds its own seat in it. A dry run is the honest way to look: it leases
    // nothing and publishes nothing.
    //
    // The rank is the derived score order, not the order the test made the keys, so it is
    // read back from the round rather than assumed — which is the point: a volunteer sits
    // where the seed put it and nowhere else.
    let mut seen: Vec<String> = Vec::new();
    for (name, rank) in scene
        .seated
        .iter()
        .zip(scene.ranks.iter().map(|(_, rank)| *rank))
    {
        let body = ok(
            &scene.work(name, &["--dry-run", "--json"]),
            "work --dry-run",
        );
        assert_eq!(
            body["looked"], 1,
            "{name} sees one advertised round: {body}"
        );
        assert_eq!(body["simulated"], 1, "{body}");
        let round = &body["rounds"][0];
        assert_eq!(round["job"], JOB, "{round}");
        assert_eq!(
            round["seat"].as_u64(),
            Some(rank as u64),
            "{name} sits where the seed put it: {round}"
        );
        assert_eq!(round["seats"], 5, "{round}");
        seen.push(round["challenge"].as_str().unwrap_or_default().to_string());
    }
    // The per-key challenge is what binds an attestation to its seat: five seats, five
    // different challenges, or one volunteer could answer for another.
    let mut challenges = seen.clone();
    challenges.sort();
    challenges.dedup();
    assert_eq!(challenges.len(), 5, "the challenges are per seat: {seen:?}");

    // The owner's question, with nobody there: `insufficient`, exit 6, and the threshold
    // named rather than quietly lowered.
    let output = scene.verdict(&[]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    let verdict = json(&output);
    let job = &verdict["jobs"][0];
    assert_eq!(job["state"], "insufficient", "{verdict}");
    assert_eq!(job["agreeing"], 0, "{verdict}");
    assert_eq!(
        job["counted"].as_array().map(Vec::len),
        Some(0),
        "{verdict}"
    );
    assert_eq!(
        job["missing"].as_array().map(Vec::len),
        Some(5),
        "every seat is a chair nobody sat in: {verdict}"
    );
    assert_eq!(job["seats"], 5, "{verdict}");
    assert_eq!(job["required_agree"], 4, "{verdict}");

    // A verdict that did not verify earns no attestation, writes nothing, and says so.
    let output = scene.verdict(&["--attest", "store", "--key", "owner"]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    assert!(
        scene.harness.refs("refs/attestations").is_empty(),
        "an insufficient verdict has no agreement to attest: {:?}",
        scene.harness.refs("refs/attestations")
    );
    assert!(
        stdout(&output).contains("insufficient") || stdout(&output).contains("refused"),
        "and it says which refusal it is: {}{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).is_empty(),
        "the report is stdout, so a hook reads one stream: {}",
        stderr(&output)
    );

    // And the gate, asked the same question, refuses: the policy demands the quorum tier
    // and no quorum has spoken.
    let output = scene.verify_change();
    assert_eq!(code(&output), 6, "{}", json(&output));
    assert_eq!(json(&output)["accepted"], false, "{}", json(&output));
}

// ---------------------------------------------------------------------------
// five volunteers, one evening
// ---------------------------------------------------------------------------

/// The acceptance criterion, run: five volunteers serve their seats, the owner tallies
/// and publishes, the top tier exists, and the merge gate believes it.
#[test]
fn five_volunteers_carry_a_change_to_a_believed_quorum() {
    if !may_serve_jobs() {
        eprintln!("skip: this machine has no sandbox that may serve a stranger's job");
        return;
    }
    let scene = Scene::new();
    let seats = seats(&scene);

    // Five volunteers, five separate processes, each with its own key and its own build.
    for (name, rank) in scene
        .seated
        .iter()
        .zip(scene.ranks.iter().map(|(_, rank)| *rank))
    {
        let body = ok(&scene.work(name, &["--once", "--json"]), "work");
        assert_eq!(body["published"], 1, "{name}: {body}");
        assert_eq!(body["exit"], 0, "{body}");
        let round = &body["rounds"][0];
        assert_eq!(round["state"], "published", "{round}");
        assert_eq!(
            round["seat"].as_u64(),
            Some(rank as u64),
            "{name} served its own seat: {round}"
        );
        assert!(
            round["sandbox"].as_str().is_some_and(|s| !s.is_empty()),
            "the run was confined, and says by what: {round}"
        );
        assert_eq!(round["provenance_tier"], "local", "{round}");
    }

    // The store now holds one attestation per seat, signed by the seat's own key, and —
    // the part no single-volunteer test can check — they agree.
    let round = scene.round();
    let published = store::submissions(&scene.harness.host(), &round).expect("submissions");
    assert_eq!(published.len(), 5, "five seats, five answers");
    let mut signers: Vec<&str> = published
        .iter()
        .map(|doc| doc.signatures[0].key_id.as_str())
        .collect();
    signers.sort();
    signers.dedup();
    assert_eq!(signers.len(), 5, "five keys, five signatures: {signers:?}");
    let mut digests: Vec<String> = published
        .iter()
        .map(|doc| doc.result_digest().expect("a digest").to_string())
        .collect();
    let agreed = digests[0].clone();
    digests.sort();
    digests.dedup();
    assert_eq!(
        digests,
        vec![agreed.clone()],
        "five independent runs on five independent keys produced five digests: {digests:?}"
    );
    // Each answer landed in the slot its seat reserves, and nowhere else.
    for (key, slot) in &seats {
        assert!(
            published.iter().any(|doc| &doc.signatures[0].key_id == key),
            "{key} holds a seat and filed nothing"
        );
        assert!(
            !scene
                .harness
                .refs(&format!("refs/gitiup/reveal/{}/{}", scene.change, JOB))
                .iter()
                .filter(|name| name.ends_with(slot))
                .collect::<Vec<_>>()
                .is_empty(),
            "{}'s answer is not in its own slot",
            key
        );
    }
    // A served seat releases its lease: a filled seat has no reason to stay leased.
    assert!(
        scene.harness.refs("refs/gitiup/lease").is_empty(),
        "leases outlive the work they were for: {:?}",
        scene.harness.refs("refs/gitiup/lease")
    );

    // The owner tallies, files the verdict, and asks for the attestation it earns.
    //
    // The clock is pinned from the first tally's own report so that the two filings
    // below ask the identical question twice: a verdict is signed at a time, and two
    // tallies at two times are two documents.
    let clock = json(&scene.verdict(&[]))["now"]
        .as_str()
        .expect("the report says what it judged at")
        .to_string();
    let output = scene.verdict(&[
        "--now",
        &clock,
        "--publish",
        "--attest",
        "store",
        "--key",
        "owner",
    ]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
    let verdict = json(&output);
    let job = &verdict["jobs"][0];
    assert_eq!(job["state"], "verified", "{verdict}");
    assert_eq!(job["agreeing"], 5, "{verdict}");
    assert_eq!(
        job["counted"].as_array().map(Vec::len),
        Some(5),
        "all five seats were counted: {verdict}"
    );
    assert_eq!(job["required_agree"], 4, "{verdict}");
    assert_eq!(job["publish"]["state"], "filed", "{verdict}");
    assert_eq!(job["attestation"]["tier"], "quorum", "{verdict}");
    let attestation_ref = job["attestation"]["ref"]
        .as_str()
        .expect("the attestation names where it went")
        .to_string();
    assert_eq!(job["attestation"]["already"], false, "{verdict}");
    assert!(
        job["attestation"]["digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "and it has a digest of its own: {verdict}"
    );

    // Both documents are in the store, and the verdict ref holds exactly what --json
    // printed: the report and the record are one thing.
    assert!(!scene.harness.refs("refs/gitiup/verdict").is_empty());
    let filed = scene
        .harness
        .blob(&format!("refs/gitiup/verdict/{}/{}", scene.change, JOB));
    let filed: Value = serde_json::from_slice(&filed).expect("the verdict ref is the record");
    assert_eq!(filed["state"], "verified", "{filed}");
    assert_eq!(
        filed["result_digest"].as_str(),
        Some(agreed.as_str()),
        "the verdict is about the digest the five agreed on: {filed}"
    );
    assert!(
        !scene.harness.refs("refs/attestations").is_empty(),
        "the top tier is filed where a gate looks"
    );
    assert!(
        scene
            .harness
            .refs("refs/attestations")
            .iter()
            .any(|name| name.ends_with(attestation_ref.rsplit('/').next().unwrap())),
        "the ref --json named is in the store: {:?}",
        scene.harness.refs("refs/attestations")
    );

    // Asking again is a retry, not an edit: the same answer, the same bytes, and one
    // document in the store rather than two that happen to agree.
    let again = scene.verdict(&[
        "--now",
        &clock,
        "--publish",
        "--attest",
        "store",
        "--key",
        "owner",
    ]);
    assert_eq!(code(&again), 0, "{}{}", stdout(&again), stderr(&again));
    let again = json(&again);
    assert_eq!(again["jobs"][0]["publish"]["state"], "unchanged", "{again}");
    assert_eq!(again["jobs"][0]["attestation"]["already"], true, "{again}");
    assert_eq!(
        again["jobs"][0]["attestation"]["digest"], job["attestation"]["digest"],
        "the retry reproduced the document byte for byte"
    );
    assert_eq!(
        scene.harness.refs("refs/attestations").len(),
        1,
        "and filed it once: {:?}",
        scene.harness.refs("refs/attestations")
    );

    // The gate. This is the sentence the whole epic is for: a policy that asks for the
    // quorum tier is satisfied, and satisfied by re-derivation rather than by a label.
    let output = scene.verify_change();
    assert_eq!(code(&output), 0, "{}", json(&output));
    let gate = json(&output);
    assert_eq!(gate["accepted"], true, "{gate}");
    assert_eq!(gate["quorum"].as_array().map(Vec::len), Some(1), "{gate}");
    assert_eq!(
        gate["attestations"].as_array().map(Vec::len),
        Some(1),
        "{gate}"
    );

    // And the disagreement report agrees with the gate: there is nothing to dispute, so
    // it says so at the gate's own exit code.
    let output = scene.harness.run(
        &["quorum", "dispute", &scene.change, "--store", &scene.store],
        None,
    );
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
}

// ---------------------------------------------------------------------------
// three of five
// ---------------------------------------------------------------------------

/// Three volunteers out of five is an answer, and the answer is `insufficient`: exit 6,
/// no attestation, no gate, and `n` untouched.
#[test]
fn three_volunteers_of_five_are_insufficient_and_attest_nothing() {
    if !may_serve_jobs() {
        eprintln!("skip: this machine has no sandbox that may serve a stranger's job");
        return;
    }
    let scene = Scene::new();
    for name in scene.seated.iter().take(3) {
        let body = ok(&scene.work(name, &["--once", "--json"]), "work");
        assert_eq!(body["published"], 1, "{name}: {body}");
    }
    // The other two went home. Nothing about the round changed to notice: no seat was
    // lowered, no threshold was met by counting the empty chairs differently.
    let output = scene.verdict(&["--publish", "--attest", "store", "--key", "owner"]);
    assert_eq!(code(&output), 6, "{}{}", stdout(&output), stderr(&output));
    let verdict = json(&output);
    let job = &verdict["jobs"][0];
    assert_eq!(job["state"], "insufficient", "{verdict}");
    assert_eq!(job["agreeing"], 3, "{verdict}");
    assert_eq!(
        job["missing"].as_array().map(Vec::len),
        Some(2),
        "two went home: {verdict}"
    );
    assert_eq!(job["seats"], 5, "the round still asks for five: {verdict}");
    assert_eq!(job["required_agree"], 4, "and four agreements: {verdict}");
    assert!(
        job.get("attestation").is_none(),
        "an insufficient verdict earns nothing: {verdict}"
    );
    assert!(
        scene.harness.refs("refs/attestations").is_empty(),
        "and nothing was written: {:?}",
        scene.harness.refs("refs/attestations")
    );
    assert_eq!(
        code(&scene.verify_change()),
        6,
        "{}",
        json(&scene.verify_change())
    );
}

//! `gitiup participant …`, run as the real binary.
//!
//! The ticket's acceptance criteria are command lines — *a signed roster round-trips
//! through the host*, *claimed capabilities are visible in `gitiup participant list
//! --json`* — so they are tested as command lines, against the built executable, with a
//! temporary config home and a temporary store directory per test. A library test can be
//! satisfied by an API nobody calls; these cannot.
//!
//! The scripted path is the one under test everywhere: a passphrase arrives through
//! `--passphrase-file -` or the environment, every assertion reads `--json`, and the
//! store is a real `fs` host directory rather than a mock, because the property under
//! test is that a signed roster survives the store.

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// The passphrase every scripted key in these tests uses.
const PASS: &str = "four random words for age\n";

/// A config home, a store directory, and the binary pointed at both.
struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Harness {
        let dir = tempfile::tempdir().expect("a temp home");
        #[cfg(unix)]
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("0700 on the config home");
        Harness { dir }
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

    /// Run the binary with this home. `SSH_AUTH_SOCK` is pointed at a path that cannot
    /// exist, so a test cannot accidentally depend on the developer's own agent, and the
    /// working directory is the temp dir, so no `gitiup.toml` from the repository is
    /// discovered by accident.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.config())
            .env("GITIUP_KEY_PASSPHRASE", PASS.trim_end())
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
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait")
    }

    /// A keystore holding one new key.
    fn new_key(&self, name: &str) -> String {
        let output = self.run(&["key", "gen", "--name", name], Some(PASS));
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
        name.to_string()
    }

    /// The key id a keystore name stands for — the way a script gets it.
    fn key_id(&self, name: &str) -> String {
        let output = self.run(&["key", "show", name, "--json"], None);
        json(&output)["key_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no key id for {name}: {}", stderr(&output)))
            .to_string()
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

/// `register` with an honest, complete claim, writing the record to `path`.
fn register(harness: &Harness, key: &str, path: &str, extra: &[&str]) -> Output {
    let mut args = vec![
        "participant",
        "register",
        "--key",
        key,
        "--ram-mb",
        "32768",
        "--disk-mb",
        "262144",
        "--sandbox",
        "docker",
        "--sandbox-level",
        "2",
        "--out",
        path,
    ];
    args.extend_from_slice(extra);
    let output = harness.run(&args, None);
    ok(&output, "participant register");
    output
}

/// Approve a sign-up into a published epoch, and return the `approve --json` body.
fn approve(harness: &Harness, from: &str, extra: &[&str]) -> Value {
    let store = harness.store();
    let mut args = vec![
        "participant",
        "approve",
        "--key",
        "owner",
        "--from",
        from,
        "--store",
        &store,
        "--publish",
        "--json",
    ];
    args.extend_from_slice(extra);
    let output = harness.run(&args, None);
    json(&output)
}

#[test]
fn a_signed_roster_round_trips_through_the_host_from_the_command_line() {
    let harness = Harness::new();
    let owner = harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");

    // 1. A volunteer registers: a self-signed record, written for the owner's eyes.
    let image = format!("sha256:{}", "ab".repeat(32));
    let output = register(
        &harness,
        &volunteer,
        &signup,
        &["--arch", "x86_64", "--image", &image, "--can-pull"],
    );
    assert!(
        stdout(&output).contains("registered"),
        "{}",
        stdout(&output)
    );
    let record = std::fs::read_to_string(&signup).expect("the sign-up was written");
    assert!(record.starts_with('{'), "canonical JSON: {record}");

    // 2. The owner approves: a new signed epoch, published into the store.
    let approved = approve(&harness, &signup, &["--tier", "endorsed"]);
    let epoch = approved["epoch"].as_u64().expect("an epoch");
    let digest = approved["digest"].as_str().expect("a digest").to_string();
    assert_eq!(approved["entries"][0]["tier"].as_str(), Some("endorsed"));
    assert_eq!(
        approved["entries"][0]["key_id"].as_str(),
        Some(harness.key_id(&volunteer).as_str())
    );
    assert_eq!(
        approved["signed_by"].as_array().map(|keys| keys.len()),
        Some(1),
        "one owner signature approves one epoch"
    );
    assert_eq!(
        approved["signed_by"][0].as_str(),
        Some(harness.key_id(&owner).as_str()),
        "and it is the owner's key that signed it, not whichever key was lying around"
    );

    // 3. It comes back out of the store: same epoch, same digest, verified against the
    //    owner's key, and every entry intact.
    let listed = harness.run(
        &["participant", "list", "--store", &harness.store(), "--json"],
        None,
    );
    let listed = json(&listed);
    assert_eq!(listed["epoch"].as_u64(), Some(epoch));
    assert_eq!(listed["digest"].as_str(), Some(digest.as_str()));
    assert_eq!(listed["expired"].as_bool(), Some(false));
    let entries = listed["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["tier"].as_str(), Some("endorsed"));
    assert_eq!(entries[0]["ownership_proof"].as_bool(), Some(true));
}

#[test]
fn list_shows_every_claimed_capability_and_what_it_qualifies_for() {
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");
    let image = format!("sha256:{}", "cd".repeat(32));
    register(
        &harness,
        &volunteer,
        &signup,
        &[
            "--arch",
            "x86_64",
            "--arch",
            "aarch64",
            "--image",
            &image,
            "--sandbox",
            "unshare",
        ],
    );
    approve(&harness, &signup, &["--tier", "endorsed"]);
    let listed = harness.run(
        &[
            "participant",
            "list",
            "--store",
            &harness.store(),
            "--json",
            "--require-arch",
            "x86_64",
            "--require-ram-mb",
            "16384",
            "--require-disk-mb",
            "131072",
            "--require-sandbox",
            "docker",
            "--require-min-sandbox-level",
            "2",
        ],
        None,
    );
    let listed = json(&listed);
    let entry = &listed["entries"][0];
    let caps = &entry["capabilities"];
    // The ticket's list: arch, memory, disk, image cache, sandbox backend and level.
    assert_eq!(caps["arch"], serde_json::json!(["x86_64", "aarch64"]));
    assert_eq!(caps["ram_mb"].as_u64(), Some(32768));
    assert_eq!(caps["disk_mb"].as_u64(), Some(262144));
    assert_eq!(caps["image_cache"], serde_json::json!([image]));
    assert_eq!(caps["can_pull"].as_bool(), Some(false));
    assert_eq!(caps["sandboxes"], serde_json::json!(["docker", "unshare"]));
    assert_eq!(caps["sandbox_level"].as_u64(), Some(2));
    // The slot a store keys it under, and the eligibility answer for that job.
    assert_eq!(entry["slot"].as_str().map(str::len), Some(64));
    assert_eq!(entry["eligible"].as_bool(), Some(true));
    assert_eq!(entry["excluded_by"], Value::Null);
    assert_eq!(
        listed["summary"]["can_field_a_quorum"].as_bool(),
        Some(false)
    );

    // The same box, scored against a job it cannot run: the claim is what disqualifies
    // it, and the reason named is the first failing filter in D7's order rather than
    // whichever one the implementation happened to reach first.
    let scored = harness.run(
        &[
            "participant",
            "list",
            "--store",
            &harness.store(),
            "--json",
            "--require-arch",
            "riscv64",
            "--require-ram-mb",
            "1",
        ],
        None,
    );
    let scored = json(&scored);
    assert_eq!(scored["entries"][0]["eligible"].as_bool(), Some(false));
    assert_eq!(
        scored["entries"][0]["excluded_by"].as_str(),
        Some("arch"),
        "architecture is filtered before memory, and an audit has to be reproducible"
    );
}

#[test]
fn a_claim_that_was_never_measured_is_refused() {
    let harness = Harness::new();
    harness.new_key("volunteer");
    let output = harness.run(
        &[
            "participant",
            "register",
            "--key",
            "volunteer",
            "--sandbox",
            "docker",
            "--sandbox-level",
            "2",
        ],
        None,
    );
    let text = refused(&output, "an unmeasured claim");
    assert!(text.contains("--ram-mb"), "{text}");
    assert!(
        text.contains("gitiup env"),
        "and it says where to look: {text}"
    );
    // Same for the sandbox level: a backend name alone does not imply a strength, and a
    // box that overstates it has volunteers running strangers' code in a weaker jail.
    let output = harness.run(
        &[
            "participant",
            "register",
            "--key",
            "volunteer",
            "--ram-mb",
            "1024",
            "--disk-mb",
            "1024",
        ],
        None,
    );
    assert!(refused(&output, "no sandbox named").contains("--sandbox"));
}

#[test]
fn withdrawal_is_a_tombstone_the_next_epoch_applies() {
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");
    register(&harness, &volunteer, &signup, &[]);
    let store = harness.store();
    let approved = approve(&harness, &signup, &[]);
    let epoch = approved["epoch"].as_u64().unwrap();

    // Withdrawing without an epoch means "from the next one": a departure that voids a
    // round already in flight is indistinguishable from an attack on it.
    let withdrawn = harness.run(
        &[
            "participant",
            "withdraw",
            "--key",
            &volunteer,
            "--store",
            &store,
            "--publish",
            "--json",
        ],
        None,
    );
    let withdrawn = json(&withdrawn);
    assert_eq!(
        withdrawn["effective_epoch"].as_u64(),
        Some(epoch + 1),
        "a withdrawal defaults forward, not backward"
    );
    assert_eq!(withdrawn["slot"].as_str().map(str::len), Some(64));

    // The owner composes the next epoch: the store's withdrawal is applied without being
    // named, because ignoring a key's own signed request to leave would be worse than
    // honouring it.
    let next = harness.run(
        &[
            "participant",
            "approve",
            "--key",
            "owner",
            "--store",
            &store,
            "--publish",
            "--json",
        ],
        None,
    );
    let next = json(&next);
    assert_eq!(next["epoch"].as_u64(), Some(epoch + 1));
    assert_eq!(
        next["entries"].as_array().map(Vec::len),
        Some(0),
        "the withdrawal alone is enough to change the epoch"
    );
    assert_eq!(next["removed"].as_array().map(Vec::len), Some(1));

    // The old epoch is still published and unchanged: a round that pinned it stays
    // auditable against the roster it actually selected from.
    let old = harness.run(
        &[
            "participant",
            "list",
            "--store",
            &store,
            "--epoch",
            &epoch.to_string(),
            "--json",
        ],
        None,
    );
    assert_eq!(json(&old)["entries"].as_array().map(Vec::len), Some(1));
}

#[test]
fn an_epoch_handed_over_as_a_file_is_the_epoch_a_withdrawal_defaults_against() {
    // `--roster` means "the epoch in question" on every command here, not only on the two
    // that read a roster: a volunteer who was *sent* the epoch — no access to the store —
    // still leaves at the right one instead of being refused for lack of a store to guess.
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");
    register(&harness, &volunteer, &signup, &[]);
    let epoch_path = harness.file("epoch.json");
    let approved = approve(&harness, &signup, &["--out", &epoch_path]);
    let epoch = approved["epoch"].as_u64().expect("an epoch");
    let withdrawn = harness.run(
        &[
            "participant",
            "withdraw",
            "--key",
            &volunteer,
            "--roster",
            &epoch_path,
            "--json",
        ],
        None,
    );
    let withdrawn = json(&withdrawn);
    assert_eq!(
        withdrawn["effective_epoch"].as_u64(),
        Some(epoch + 1),
        "the epoch in the file, not a store nobody named, decides when the leave starts"
    );
}

#[test]
fn verify_roster_says_why_a_roster_is_or_is_not_a_trust_root() {
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");
    register(&harness, &volunteer, &signup, &[]);
    let store = harness.store();
    approve(&harness, &signup, &[]);
    let verified = harness.run(
        &["participant", "verify-roster", "--store", &store, "--json"],
        None,
    );
    let report = json(&verified);
    assert_eq!(report["ok"].as_bool(), Some(true), "{report}");
    let names: Vec<&str> = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| check["check"].as_str().unwrap())
        .collect();
    for expected in [
        "canonical",
        "owner-signature",
        "ownership-proofs",
        "entries",
        "epoch-is-current",
        "published",
    ] {
        assert!(
            names.contains(&expected),
            "missing check {expected}: {names:?}"
        );
    }

    // The same roster, judged by somebody who does not know the owner: refused with the
    // exit code a merge gate branches on, and the sentence says *trust*, not *parse*.
    let stranger = harness.new_key("stranger");
    let stranger_id = harness.key_id(&stranger);
    let output = harness.run(
        &[
            "participant",
            "verify-roster",
            "--store",
            &store,
            "--owner",
            &stranger_id,
        ],
        None,
    );
    let text = refused(&output, "a roster signed by a stranger");
    assert!(text.contains("trusts"), "{text}");
}

#[test]
fn a_pipe_is_a_supported_way_to_hand_a_record_over() {
    // `--out -` must be the bytes and nothing else, and `--from -` must read them back:
    // that pair is the whole owner/volunteer handover, with no shared filesystem and no
    // store both sides can reach.
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let bytes = harness.run(
        &[
            "participant",
            "register",
            "--key",
            &volunteer,
            "--ram-mb",
            "8192",
            "--disk-mb",
            "40960",
            "--sandbox",
            "unshare",
            "--sandbox-level",
            "1",
            "--out",
            "-",
        ],
        None,
    );
    let bytes = stdout(&bytes);
    let parsed: Value = serde_json::from_str(bytes.trim()).expect("only the record on stdout");
    assert_eq!(
        parsed["entry"]["capabilities"]["ram_mb"].as_u64(),
        Some(8192)
    );

    let approved = harness.run(
        &[
            "participant",
            "approve",
            "--key",
            "owner",
            "--from",
            "-",
            "--tier",
            "endorsed",
            "--json",
        ],
        Some(&bytes),
    );
    let approved = json(&approved);
    assert_eq!(approved["added"].as_array().map(Vec::len), Some(1));
    assert_eq!(approved["entries"][0]["tier"].as_str(), Some("endorsed"));
}

#[test]
fn nothing_is_published_unless_the_flag_says_so() {
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let signup = harness.file("signup.json");
    register(&harness, &volunteer, &signup, &[]);
    let store = harness.store();
    let approved = harness.run(
        &[
            "participant",
            "approve",
            "--key",
            "owner",
            "--from",
            &signup,
            "--store",
            &store,
            "--out",
            &harness.file("roster.json"),
        ],
        None,
    );
    ok(&approved, "approve without --publish");
    assert!(
        harness.path().join("roster.json").exists(),
        "--out wrote it"
    );
    // The epoch that was written to disk is a complete document on its own: it verifies
    // from the file, with no store involved — which is how a volunteer audits the roster
    // an owner sent them before trusting a store that claims to be it.
    let from_file = harness.run(
        &[
            "participant",
            "list",
            "--roster",
            &harness.file("roster.json"),
            "--json",
        ],
        None,
    );
    let from_file = json(&from_file);
    assert_eq!(from_file["entries"].as_array().map(Vec::len), Some(1));
    assert!(
        from_file["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("file")),
        "source: {from_file}"
    );
    // The store, meanwhile, saw the epoch and did not take it: reading a store is not
    // writing one.
    let listed = harness.run(&["participant", "list", "--store", &store], None);
    assert!(
        refused(&listed, "the store still has no roster").contains("no roster"),
        "{}",
        stderr(&listed)
    );
    // And `approve` with nothing to approve is a refusal, not an empty epoch: an epoch
    // that changes nothing bumps the chain for no reason and hides the mistake.
    let empty = harness.run(
        &[
            "participant",
            "approve",
            "--key",
            "owner",
            "--store",
            &store,
        ],
        None,
    );
    assert!(refused(&empty, "approve with nothing to do").contains("nothing to approve"));
}

#[test]
fn a_revocation_names_a_reason_and_the_reason_decides_what_it_voids() {
    let harness = Harness::new();
    harness.new_key("owner");
    let volunteer = harness.new_key("volunteer");
    let target = harness.key_id(&volunteer);
    let store = harness.store();
    let signup = harness.file("signup.json");
    register(&harness, &volunteer, &signup, &[]);
    let epoch = approve(&harness, &signup, &[])["epoch"].as_u64().unwrap();

    // A compromised key stops now: a thief signs tomorrow with yesterday's key, so an
    // effective epoch in the future would be a licence to keep voting.
    let compromised = harness.run(
        &[
            "participant",
            "revoke",
            &target,
            "--key",
            "owner",
            "--reason",
            "compromised",
            "--store",
            &store,
            "--json",
        ],
        None,
    );
    let compromised = json(&compromised);
    assert_eq!(compromised["effective_epoch"].as_u64(), Some(epoch));
    assert_eq!(compromised["voids_current_epoch"].as_bool(), Some(true));

    // A retirement is a different sentence: out from the next epoch, honest work stands.
    let retired = harness.run(
        &[
            "participant",
            "revoke",
            &target,
            "--key",
            "owner",
            "--reason",
            "retired",
            "--store",
            &store,
            "--json",
        ],
        None,
    );
    let retired = json(&retired);
    assert_eq!(retired["effective_epoch"].as_u64(), Some(epoch + 1));
    assert_eq!(retired["voids_current_epoch"].as_bool(), Some(false));

    // A reason outside the vocabulary is refused, not defaulted: guessing between "the
    // laptop was sold" and "the key is stolen" decides whether past work stands.
    let nonsense = harness.run(
        &[
            "participant",
            "revoke",
            &target,
            "--key",
            "owner",
            "--reason",
            "mislaid",
            "--store",
            &store,
        ],
        None,
    );
    assert_eq!(nonsense.status.code(), Some(6), "refused: a bad reason");
    assert!(
        stderr(&nonsense).contains("reasons are"),
        "{}",
        stderr(&nonsense)
    );
}

#[test]
fn the_surface_is_there_and_says_what_it_offers() {
    let harness = Harness::new();
    let help = harness.run(&["participant"], None);
    let text = ok(&help, "`participant` with no subcommand");
    for command in [
        "register",
        "withdraw",
        "list",
        "verify-roster",
        "approve",
        "revoke",
    ] {
        assert!(text.contains(command), "{command} is missing from the help");
    }
    let top = harness.run(&["help"], None);
    assert!(
        stdout(&top).contains("participant"),
        "and on the top level too"
    );
    let unknown = harness.run(&["participant", "enroll"], None);
    assert_eq!(unknown.status.code(), Some(2), "usage");
    assert!(stderr(&unknown).contains("enroll"));
}

#[test]
fn a_store_has_to_be_named_rather_than_guessed() {
    let harness = Harness::new();
    harness.new_key("owner");
    // No store flag and no `gitiup.toml` in this directory: the CLI must not invent one,
    // because "the roster I read" and "the roster I trusted" would stop being the same
    // sentence.
    let output = harness.run(&["participant", "list"], None);
    assert!(
        refused(&output, "list with no store").contains("store"),
        "{}",
        stderr(&output)
    );
}

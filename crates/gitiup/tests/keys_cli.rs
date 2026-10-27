//! `gitiup key` and `gitiup identity`, run as the real binary.
//!
//! The ticket's acceptance criteria are command lines — *"`keygen`, `import` and
//! `identity` can be driven from a script"* — so they are tested as command lines,
//! against the built executable, with a temporary `GITIUP_CONFIG_HOME` per test. A
//! library test could be satisfied by an API nobody calls; these cannot.
//!
//! The scripted path is the one under test everywhere: a passphrase arrives on stdin
//! through `--passphrase-file -`, and the assertions read `--json`. Nothing here has
//! a terminal, which is the property that makes the surface usable from CI.

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::encoding::base64_encode;
use gitiup_attest::key::SigningKey;

/// A configuration home, and the binary pointed at it.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        let dir = tempfile::tempdir().expect("a temp config home");
        #[cfg(unix)]
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("0700 on the config home");
        Home { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run the binary with this home as the config dir. `SSH_AUTH_SOCK` is pointed at
    /// a path that cannot exist so that a test cannot accidentally depend on the
    /// developer's own agent, and `GITIUP_PASSPHRASE` is cleared so the precedence
    /// rule under test is the flags', not the environment's.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path())
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
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

    fn code(&self, args: &[&str], stdin: Option<&str>) -> u8 {
        self.run(args, stdin).status.code().expect("an exit code") as u8
    }

    /// A passphrase long enough to pass the keystore's own policy, on stdin.
    const PASS: &'static str = "four random words for age\n";
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json_of(output: &Output) -> serde_json::Value {
    let text = out(output);
    let line = text
        .lines()
        .find(|line| line.starts_with('{') || line.starts_with('['))
        .unwrap_or_else(|| panic!("no JSON in: {text}"));
    serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON ({line}): {e}"))
}

/// Generate a key and return its `key_id`.
fn generate_key(home: &Home, name: &str, comment: &str) -> String {
    let output = home.run(
        &[
            "key",
            "gen",
            "--name",
            name,
            "--comment",
            comment,
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(output.status.success(), "key gen failed: {}", err(&output));
    json_of(&output)["key_id"]
        .as_str()
        .expect("key_id")
        .to_string()
}

/// Every file under a directory.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_generated_key_publishes_a_claim_and_the_whole_flow_is_scriptable() {
    let home = Home::new();
    let key_id = generate_key(&home, "ada-laptop", "ada@laptop");
    assert!(key_id.starts_with("SHA256:"), "{key_id}");

    // Publish, with no `--key`: one key in the keystore is unambiguous, and the first
    // thing a new user does is `key gen` then `identity publish`.
    let published = home.run(
        &[
            "identity",
            "publish",
            "ada",
            "--email",
            "ada@example.com",
            "--url",
            "https://ada.example",
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(published.status.success(), "{}", err(&published));
    let claim = json_of(&published);
    assert_eq!(claim["handle"], "ada");
    assert_eq!(claim["key_id"], key_id);
    assert_eq!(
        claim["became_current"], true,
        "the first identity published becomes the current one: {claim}"
    );
    assert_eq!(
        claim["claim"]["signatures"].as_array().map(Vec::len),
        Some(1),
        "a claim carries exactly its owner's self-signature"
    );

    // whoami, and `--check`: the signature test that proves the passphrase, the
    // container and the key all still agree.
    let whoami = home.run(
        &[
            "identity",
            "whoami",
            "--check",
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(whoami.status.success(), "{}", err(&whoami));
    let me = json_of(&whoami);
    assert_eq!(me["handle"], "ada");
    assert_eq!(me["key_id"], key_id);
    assert_eq!(me["check"], "signs and verifies");
    assert_eq!(me["backend"], "keystore");

    // verify: the claim's own signature checks out.
    let verify = home.run(&["identity", "verify", "ada", "--json"], None);
    assert!(verify.status.success(), "{}", err(&verify));
    assert_eq!(json_of(&verify)["self_signature"], "ok");

    // `key show --public-line` is the copy-paste-into-authorized_keys path.
    let line = out(&home.run(&["key", "show", "ada-laptop", "--public-line"], None));
    assert!(
        line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"),
        "{line}"
    );
    // And `identity show --canonical` prints the claim's own bytes, which must be
    // exactly the file on disk: that byte-for-byte equality is what lets a second
    // implementation diff its canonicalisation against ours.
    let canonical = home.run(&["identity", "show", "ada", "--canonical"], None);
    assert!(canonical.status.success(), "{}", err(&canonical));
    let stored = std::fs::read(home.path().join("identities/ada.identity.json")).unwrap();
    let printed = &out(&canonical).into_bytes()[..out(&canonical).len() - 1];
    assert_eq!(printed, stored.as_slice(), "the canonical form drifted");
}

#[test]
fn only_the_encrypted_container_is_written() {
    // The acceptance criterion, at the level a user can check: after a key is made
    // and used, the only thing on disk that mentions the key material is the age
    // container, and it is armour — not JSON, not a PEM.
    let home = Home::new();
    generate_key(&home, "ada-laptop", "ada@laptop");
    home.run(
        &["identity", "publish", "ada", "--passphrase-file", "-"],
        Some(Home::PASS),
    );

    let files = files_under(home.path());
    let names: Vec<String> = files
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.contains(&"ada-laptop.json".to_string()),
        "the public record should exist: {names:?}"
    );
    assert!(
        names.contains(&"ada-laptop.secret.age".to_string()),
        "the container should exist: {names:?}"
    );
    let leftovers: Vec<&String> = names
        .iter()
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "the atomic writer left {leftovers:?} behind"
    );
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(path).expect("read");
        if name.ends_with(".secret.age") {
            let text = String::from_utf8(bytes.clone()).expect("armour is ascii");
            assert!(
                text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
                "{name} is not age armour"
            );
            // Armour is base64 and newlines, so a quote can only mean plaintext.
            assert!(!text.contains('"'), "{name} holds plaintext");
        }
        // An unencrypted OpenSSH private key file, a PEM, or a plain seed must never
        // appear — including as a temp file the writer forgot to rename.
        let as_text = String::from_utf8_lossy(&bytes);
        assert!(
            !as_text.contains("BEGIN OPENSSH PRIVATE KEY"),
            "{name} is an unencrypted private key"
        );
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "{name} is group- or world-accessible: {mode:#o}"
            );
        }
    }
}

#[test]
fn an_imported_file_key_signs_the_same_as_the_seed_it_came_from() {
    // A real OpenSSH private key file, assembled from the wire format the parser
    // reads. The seed is a test fixture (public knowledge), so the assertion that
    // the imported key id equals the seed's own key id is a statement about the
    // import path, not about secrecy.
    let seed = [0xa1u8; 32];
    let signing = SigningKey::from_seed(&seed);
    let expected = signing.public_key().key_id();

    let home = Home::new();
    let key_path = home.path().join("id_ed25519");
    std::fs::write(&key_path, openssh_private_file(&seed, "ada@laptop")).expect("write key");

    let import = home.run(
        &[
            "key",
            "import",
            "file",
            &key_path.display().to_string(),
            "--name",
            "ada-import",
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(import.status.success(), "{}", err(&import));
    let record = json_of(&import);
    assert_eq!(record["key_id"], expected, "import changed the key");
    assert_eq!(record["backend"], "keystore");
    assert_eq!(
        record["secret_stored_in_keystore"], true,
        "a file import re-encrypts the seed: {record}"
    );

    // And it can sign a claim, which is the only thing the import was for.
    let published = home.run(
        &[
            "identity",
            "publish",
            "ada",
            "--key",
            "ada-import",
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(published.status.success(), "{}", err(&published));
    assert_eq!(json_of(&published)["key_id"], expected);
    assert!(
        home.run(&["identity", "verify", "ada"], None)
            .status
            .success(),
        "a claim signed with an imported key must verify"
    );

    // Importing the same name again is a refusal, not an overwrite: silently
    // replacing a key would destroy the only copy of the old one.
    let again = home.code(
        &[
            "key",
            "import",
            "file",
            &key_path.display().to_string(),
            "--name",
            "ada-import",
            "--passphrase-file",
            "-",
        ],
        Some(Home::PASS),
    );
    assert_eq!(again, 6, "a duplicate name should be refused (6)");
    let forced = home.code(
        &[
            "key",
            "import",
            "file",
            &key_path.display().to_string(),
            "--name",
            "ada-import",
            "--force",
            "--passphrase-file",
            "-",
        ],
        Some(Home::PASS),
    );
    assert_eq!(forced, 0, "`--force` replaces a record");
}

#[test]
fn an_agent_that_is_not_there_is_exit_three() {
    // Unreachable, not refused: ADR-0001 D7 gives I/O and "cannot reach" the same
    // code, and a script must be able to tell that apart from a key it declined to
    // use (6) without parsing prose.
    let home = Home::new();
    let socket = home.path().join("nope");
    let output = home.run(
        &[
            "key",
            "import",
            "ssh-agent",
            "--socket",
            &socket.display().to_string(),
        ],
        Some(Home::PASS),
    );
    assert_eq!(output.status.code().unwrap() as u8, 3, "{}", err(&output));
    assert!(
        err(&output).contains("ssh-agent"),
        "the message should name the thing that is missing: {}",
        err(&output)
    );
}

#[test]
fn a_tampered_claim_is_exit_seven_not_zero() {
    // The difference that matters: 6 is "I cannot read this", 7 is "this signature
    // is wrong". A merge gate branches on exactly that.
    let home = Home::new();
    generate_key(&home, "ada-laptop", "ada@laptop");
    assert!(
        home.run(
            &["identity", "publish", "ada", "--passphrase-file", "-"],
            Some(Home::PASS)
        )
        .status
        .success()
    );
    let path = home.path().join("identities/ada.identity.json");
    let text = std::fs::read_to_string(&path).expect("read claim");
    // Swap two characters inside the base64 of the self-signature: same length, still
    // canonical bytes, still valid base64 — so the only thing that fails is the
    // signature itself.
    let marker = "\"sig\":\"";
    let start = text.find(marker).expect("a signature") + marker.len();
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    bytes.swap(start + 5, start + 6);
    std::fs::write(&path, bytes).expect("write claim");

    let output = home.run(&["identity", "verify", "ada"], None);
    assert_eq!(
        output.status.code().unwrap() as u8,
        7,
        "a broken self-signature must be exit 7: {}",
        err(&output)
    );
    assert!(err(&output).contains("does not verify"), "{}", err(&output));
}

#[test]
fn a_claim_moves_between_two_machines_unchanged() {
    // Ada publishes on her laptop; Grace copies the file to her own machine, where
    // it must verify with nothing but the public key in it. That is the whole
    // interop claim: no shared database, no shared secret.
    let laptop = Home::new();
    generate_key(&laptop, "ada-laptop", "ada@laptop");
    laptop.run(
        &["identity", "publish", "ada", "--passphrase-file", "-"],
        Some(Home::PASS),
    );
    let claim = std::fs::read(laptop.path().join("identities/ada.identity.json")).unwrap();

    let other = Home::new();
    let file = other.path().join("ada.identity.json");
    std::fs::write(&file, &claim).unwrap();
    let imported = other.run(
        &["identity", "import", &file.display().to_string(), "--json"],
        None,
    );
    assert!(imported.status.success(), "{}", err(&imported));
    let summary = json_of(&imported);
    assert_eq!(summary["handle"], "ada");
    assert!(
        summary["trusted_endorsers"]
            .as_array()
            .is_some_and(|items| items.is_empty()),
        "Grace trusts nobody yet: {summary}"
    );
    // Reading it back from the other machine's store verifies, and the bytes are
    // unchanged: `import` did not re-encode the claim.
    assert!(
        other
            .run(&["identity", "verify", "ada"], None)
            .status
            .success()
    );
    assert_eq!(
        std::fs::read(other.path().join("identities/ada.identity.json")).unwrap(),
        claim,
        "import rewrote the claim"
    );

    // The same claim through a pipe, which is how a script would fetch it.
    let piped = other.run(
        &["identity", "import", "-", "--force"],
        Some(&String::from_utf8(claim).unwrap()),
    );
    assert!(piped.status.success(), "{}", err(&piped));
}

#[test]
fn help_and_usage_are_a_contract_too() {
    let home = Home::new();
    for (args, code) in [
        (vec!["key"], 0u8),
        (vec!["key", "help"], 0),
        (vec!["identity", "help"], 0),
        (vec!["key", "nonsense"], 2),
        (vec!["identity", "nonsense"], 2),
        (vec!["key", "show"], 2),
        (vec!["key", "gen", "--nope"], 2),
        (vec!["key", "gen", "--name"], 2),
    ] {
        let output = home.run(&args, None);
        assert_eq!(
            output.status.code().unwrap() as u8,
            code,
            "`gitiup {}` should exit {code}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let help = out(&home.run(&["key", "help"], None));
    for token in [
        "gitiup key gen",
        "import ssh-agent",
        "--passphrase-file",
        "Exit codes",
    ] {
        assert!(help.contains(token), "the key help should say {token}");
    }
    let help = out(&home.run(&["identity", "help"], None));
    for token in ["publish", "endorse", "whoami", "canonical"] {
        assert!(help.contains(token), "the identity help should say {token}");
    }
    let overview = out(&home.run(&["help"], None));
    assert!(
        overview.contains("key [COMMAND]"),
        "gitiup help should list `key`"
    );
    assert!(
        overview.contains("identity [COMMAND]"),
        "gitiup help should list `identity`"
    );
}

#[test]
fn two_identities_and_an_endorsement() {
    // One machine, two keys, two claims: Grace vouches for Ada. The endorsement must
    // survive being stored, and `verify` must say who is trusted *here* — which is a
    // laptop's opinion, not a repository's policy.
    let home = Home::new();
    generate_key(&home, "ada-key", "ada@laptop");
    generate_key(&home, "grace-key", "grace@lab");
    for (handle, key) in [("ada", "ada-key"), ("grace", "grace-key")] {
        let published = home.run(
            &[
                "identity",
                "publish",
                handle,
                "--key",
                key,
                "--passphrase-file",
                "-",
            ],
            Some(Home::PASS),
        );
        assert!(published.status.success(), "{}", err(&published));
    }
    // With two keys and no current identity for `ada`… there is one (the first
    // published), so naming `--key` is what selects the other.
    let endorsed = home.run(
        &[
            "identity",
            "endorse",
            "ada",
            "--key",
            "grace-key",
            "--statement",
            "we have worked together",
            "--passphrase-file",
            "-",
            "--json",
        ],
        Some(Home::PASS),
    );
    assert!(endorsed.status.success(), "{}", err(&endorsed));
    assert_eq!(json_of(&endorsed)["handle"], "ada");

    let verify = home.run(&["identity", "verify", "ada", "--json"], None);
    assert!(verify.status.success(), "{}", err(&verify));
    let report = json_of(&verify);
    assert_eq!(
        report["endorsers"].as_array().map(Vec::len),
        Some(1),
        "one endorsement: {report}"
    );
    assert_eq!(
        report["trusted_endorsers"].as_array().map(Vec::len),
        Some(1),
        "Grace's claim is in this machine's trust set: {report}"
    );

    // A key cannot endorse its own claim: that is what publish is for.
    let self_endorsement = home.code(
        &[
            "identity",
            "endorse",
            "ada",
            "--key",
            "ada-key",
            "--passphrase-file",
            "-",
        ],
        Some(Home::PASS),
    );
    assert_eq!(self_endorsement, 6, "self-endorsement is refused");

    // `identity use` switches who this machine signs as, and refuses a key that
    // cannot sign for the handle it was given.
    assert_eq!(home.code(&["identity", "use", "grace"], None), 0);
    let wrong_key = home.code(&["identity", "use", "grace", "--key", "ada-key"], None);
    assert_eq!(wrong_key, 6, "ada's key cannot sign for grace");
    let whoami = home.run(&["identity", "whoami", "--json"], None);
    assert_eq!(json_of(&whoami)["handle"], "grace");

    // The list shows both, and marks the current one.
    let list = json_of(&home.run(&["identity", "list", "--json"], None));
    assert_eq!(list.as_array().map(Vec::len), Some(2));
    let current: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|claim| claim["current"] == true)
        .map(|claim| claim["handle"].as_str().unwrap())
        .collect();
    assert_eq!(current, vec!["grace"]);
}

#[test]
fn a_wrong_passphrase_is_a_refusal_not_a_mystery() {
    let home = Home::new();
    generate_key(&home, "ada-laptop", "ada@laptop");
    let output = home.run(
        &[
            "key",
            "probe",
            "--name",
            "ada-laptop",
            "--passphrase-file",
            "-",
        ],
        Some("the wrong one entirely\n"),
    );
    assert_eq!(output.status.code().unwrap() as u8, 6, "{}", err(&output));
    assert!(
        err(&output).to_lowercase().contains("passphrase"),
        "the message should say what went wrong: {}",
        err(&output)
    );
}

/// Build an unencrypted OpenSSH private key file, the format `ssh-keygen -t ed25519
/// -N ''` writes. Written here rather than imported from `gitiup-keys`, where the
/// equivalent builder is `#[cfg(test)]` on purpose: nothing in the shipped library
/// may hand out plaintext key material, and a test that needs it should build it in
/// the test.
fn openssh_private_file(seed: &[u8; 32], comment: &str) -> Vec<u8> {
    let signing = SigningKey::from_seed(seed);
    let public = signing.public_key();
    let blob = {
        let mut blob = Vec::new();
        write_string(&mut blob, b"ssh-ed25519");
        write_string(&mut blob, public.as_bytes());
        blob
    };
    // OpenSSH's ed25519 private section is `string pubkey` then `string key` where
    // the key is the 64-byte expanded secret (seed || public), not one 96-byte blob —
    // getting this wrong is exactly the kind of thing a hand-written fixture catches.
    let mut sk = seed.to_vec();
    sk.extend_from_slice(public.as_bytes());

    let mut section = Vec::new();
    section.extend_from_slice(&0x5e11_2026u32.to_be_bytes());
    section.extend_from_slice(&0x5e11_2026u32.to_be_bytes());
    write_string(&mut section, public.as_bytes());
    write_string(&mut section, &sk);
    write_string(&mut section, comment.as_bytes());
    // OpenSSH pads the private section to a multiple of 8 with 1..n.
    let pad = 8 - (section.len() % 8);
    for byte in 1..=pad {
        section.push(byte as u8);
    }

    let mut wire = Vec::new();
    wire.extend_from_slice(b"openssh-key-v1\0");
    write_string(&mut wire, b"none");
    write_string(&mut wire, b"none");
    write_string(&mut wire, b"");
    wire.extend_from_slice(&1u32.to_be_bytes());
    write_string(&mut wire, &blob);
    write_string(&mut wire, &section);

    let encoded = base64_encode(&wire);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    out.into_bytes()
}

fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

//! The acceptance criterion, enforced instead of promised:
//!
//! > a test proves private key material is never written outside the encrypted
//! > keystore
//!
//! The proof is a search. Every operation a user can do is performed with a seed the
//! test knows in advance, then **every file in the tree is read and searched** for the
//! seed in each of the forms it could take — raw, hex, base64, and the OpenSSH
//! private-half concatenation. Not found anywhere, including inside the `.age`
//! container (where scrypt + ChaCha20-Poly1305 means it must not be findable, and
//! where finding it would mean the encryption is decoration).
//!
//! Two claims that are easy to lose in a later refactor are checked here too, because
//! both are the kind of thing a well-meaning "make it more flexible" change breaks:
//!
//! * the permissions on the tree (a `0644` secret file, a `0755` keystore);
//! * the one-way door on plaintext: the crate can read an OpenSSH private key and it
//!   can refuse a plaintext secret that someone hand-dropped, but nothing it exposes
//!   can *produce* a plaintext key — verified by grepping the sources for the only
//!   functions that know how to write one.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;

use gitiup_attest::encoding::{base64_encode, hex_encode};
use gitiup_attest::{SignatureEntry, Signer as _};
use gitiup_keys::identity::{IdentityClaim, IdentityStore, Profile};
use gitiup_keys::keystore::{AGE_HEADER, Generate, Import, Keystore};
use gitiup_keys::paths::Paths;
use gitiup_keys::{passphrase, signer};

/// The seed the tests use. Known in advance, and therefore findable if it leaks.
const SEED: [u8; 32] = [
    0x5e, 0xc0, 0xff, 0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
];
const PASSPHRASE: &str = "six honest random words";

/// Everything the seed can look like on disk.
fn seed_shapes() -> Vec<(&'static str, Vec<u8>)> {
    let signing = gitiup_attest::SigningKey::from_seed(&SEED);
    let public = signing.public_key();
    let mut openssh_half = Vec::new();
    openssh_half.extend_from_slice(&SEED);
    openssh_half.extend_from_slice(public.as_bytes());
    vec![
        ("raw", SEED.to_vec()),
        ("hex", hex_encode(&SEED).into_bytes()),
        ("HEX", hex_encode(&SEED).to_uppercase().into_bytes()),
        ("base64", base64_encode(&SEED).into_bytes()),
        ("openssh sk||pk", openssh_half),
        (
            "quoted-hex",
            format!("\"seed\": \"{}\"", hex_encode(&SEED)).into_bytes(),
        ),
    ]
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
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

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .map(|meta| {
            #[cfg(unix)]
            {
                std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777
            }
            #[cfg(not(unix))]
            {
                0
            }
        })
        .unwrap_or(0)
}

/// Assert none of `seed_shapes()` appears in any file under `root`, and report which
/// file and which shape if it does.
fn assert_no_seed_anywhere(root: &Path, context: &str) {
    let shapes = seed_shapes();
    let files = files_under(root);
    assert!(!files.is_empty(), "{context}: nothing to scan?");
    for file in &files {
        let bytes = std::fs::read(file).unwrap_or_default();
        for (name, shape) in &shapes {
            assert!(
                !contains_subsequence(&bytes, shape),
                "{context}: the private seed (as {name}) was found in {} — private key \
                 material must exist only inside an age container",
                file.display()
            );
        }
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn a_generated_key_leaves_the_seed_nowhere() {
    let world = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(world.path().join("config"));
    let store = Keystore::new(paths.clone());

    // Generate, list, find, unlock, sign, publish an identity: the ordinary session a
    // user has with a new key.
    let record = store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                comment: Some("ada@laptop".into()),
                seed: Some(SEED),
                force: false,
            },
            &secret(),
        )
        .expect("generate");
    let unlocked = store.unlock(&record, &secret()).expect("unlock");
    assert_eq!(unlocked.public_key().key_id(), record.key_id);
    let key = signer::open(&store, "laptop", &passphrase_source()).expect("open");
    key.probe().expect("probe");
    let entry = SignatureEntry::new(&key, b"pae").expect("sign");
    entry.verify(b"pae").expect("verify");
    assert_eq!(store.export_public("laptop").unwrap(), record.ssh_line());

    let claim = IdentityClaim::new(
        &key,
        &Profile {
            handle: "ada".into(),
            display_name: "Ada Lovelace".into(),
            email: None,
            url: None,
            annotations: Default::default(),
        },
        1_793_092_600_000_000,
    )
    .expect("claim");
    let store_of_identities = IdentityStore::new(paths.clone());
    store_of_identities.publish(&claim, false).expect("publish");

    assert_no_seed_anywhere(world.path(), "after generate + publish");

    // The container is there, it is armoured, and the tree is private.
    let secret = world.path().join("config/keys/laptop.secret.age");
    assert!(secret.exists(), "the container should exist");
    let text = std::fs::read_to_string(&secret).expect("the container is ASCII armour");
    assert!(
        text.starts_with(AGE_HEADER)
            && text
                .trim_end()
                .ends_with("-----END AGE ENCRYPTED FILE-----"),
        "the container is not a well-formed age armour:\n{text}"
    );
    // The first base64 line is the start of the binary header, and the binary header
    // starts with the format's own name: i.e. this really is age, and not base64 of
    // something else that happens to sit between armour lines.
    let first_body = text.lines().nth(1).expect("an armour body line");
    let decoded = gitiup_attest::encoding::base64_decode(first_body).expect("armour is base64");
    assert!(
        decoded.starts_with(b"age-encryption.org/v1"),
        "the container header does not name age: {decoded:?}"
    );
    // Armour is base64 and line breaks, so a quote character in the body can only
    // mean one thing: the plaintext got written instead of encrypted.
    assert!(!text.contains('"'), "the container holds plaintext");
    for path in [
        world.path().join("config"),
        world.path().join("config/keys"),
        world.path().join("config/identities"),
    ] {
        assert_eq!(
            mode_of(&path) & 0o077,
            0,
            "{} is group/world accessible",
            path.display()
        );
    }
    for file in files_under(&world.path().join("config")) {
        let mode = mode_of(&file);
        assert_eq!(mode & 0o077, 0, "{} is mode {mode:04o}", file.display());
    }
    // And no litter: the atomic writer renames its temp file, it does not leave it.
    let leftovers: Vec<String> = files_under(world.path())
        .into_iter()
        .filter(|file| {
            file.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".tmp"))
        })
        .map(|file| file.display().to_string())
        .collect();
    assert!(
        leftovers.is_empty(),
        "the atomic writer left a temp file behind: {leftovers:?}"
    );
}

#[test]
fn importing_an_ssh_key_reads_the_plaintext_and_writes_only_the_container() {
    let world = tempfile::tempdir().unwrap();
    let source = world.path().join("id_ed25519");
    // A real OpenSSH private key file, written by the test — this is the one place a
    // plaintext key exists here, and it is the input the user already has.
    let pem = openssh_private_file(&SEED, "ada@laptop");
    std::fs::write(&source, &pem).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();

    let paths = Paths::with_root(world.path().join("config"));
    let store = Keystore::new(paths.clone());
    let imported = store
        .import(
            &Import::Openssh {
                path: source.clone(),
            },
            Some("imported"),
            &secret(),
            false,
        )
        .expect("import");
    assert!(imported.moved);
    assert_eq!(imported.record.backend, gitiup_keys::Backend::Keystore);

    // Everything gitiup wrote is clean. The user's own input file is excluded on
    // purpose: it was plaintext before gitiup was run, and gitiup neither edited it
    // nor copied it — which the assertions below are about.
    let mut scanned = 0;
    for file in files_under(world.path()) {
        if file == source {
            continue;
        }
        scanned += 1;
        let bytes = std::fs::read(&file).unwrap_or_default();
        for (name, shape) in seed_shapes() {
            assert!(
                !contains_subsequence(&bytes, &shape),
                "the imported seed (as {name}) was found in {}",
                file.display()
            );
        }
    }
    assert!(
        scanned >= 2,
        "expected a record and a container, saw {scanned}"
    );
    assert_eq!(
        std::fs::read(&source).unwrap(),
        pem,
        "import must not modify the file it was given"
    );
    // The imported key signs with the *same* key it replaced, which is the only
    // reason importing rather than generating matters.
    let key = signer::open(&store, "imported", &passphrase_source()).unwrap();
    assert_eq!(
        key.key_id(),
        gitiup_attest::SigningKey::from_seed(&SEED)
            .public_key()
            .key_id()
    );
}

#[test]
fn an_agent_import_writes_no_secret_at_all() {
    // The other half of the claim: importing an ssh-agent or gpg key has no secret
    // to leak, and the keystore proves it by having no container.
    let public = gitiup_attest::SigningKey::from_seed(&SEED).public_key();
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path());
    let store = Keystore::new(paths.clone());
    let record = gitiup_keys::KeyRecord {
        version: gitiup_keys::keystore::RECORD_VERSION,
        name: "agent-key".into(),
        key_id: public.key_id(),
        public_key: public.to_openssh(),
        backend: gitiup_keys::Backend::SshAgent,
        created_at_us: 1_793_092_600_000_000,
        comment: None,
        secret: None,
        agent: Some(gitiup_keys::keystore::AgentRef {
            socket: "$SSH_AUTH_SOCK".into(),
            comment: None,
        }),
        gpg: None,
    };
    store
        .register(&record, false)
        .expect("record an agent-backed key");
    assert!(
        !files_under(&paths.keys_dir())
            .iter()
            .any(|file| file.to_string_lossy().ends_with(".secret.age")),
        "an agent-backed key must not get a secret container"
    );
    // And unlocking one says so instead of pretending.
    let error = store.unlock(&record, &secret()).unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(error.to_string().contains("agent"), "{error}");
}

#[test]
fn a_plaintext_secret_file_dropped_in_by_hand_is_refused() {
    // Someone who copies an unencrypted key into the keystore and edits the record to
    // point at it must be refused, not silently supported: support for plaintext
    // secrets is the thing this test exists to prevent, and a feature that "just
    // reads it anyway" would look exactly like this.
    let world = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(world.path().join("config"));
    let store = Keystore::new(paths.clone());
    let record = store
        .generate(
            &Generate {
                name: Some("real".into()),
                ..Default::default()
            },
            &secret(),
        )
        .unwrap();
    let container = paths.keys_dir().join("handy.secret.age");
    std::fs::write(
        &container,
        format!("{{\"seed\": \"{}\"}}", hex_encode(&SEED)),
    )
    .unwrap();
    let mut swapped = record.clone();
    swapped.secret = Some(gitiup_keys::keystore::SecretRef {
        file: "handy.secret.age".into(),
        format: "age-armor".into(),
        kdf: "scrypt".into(),
    });
    let error = store.unlock(&swapped, &secret()).unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(
        error.to_string().contains("not an age container"),
        "{error}"
    );
}

#[test]
fn nothing_in_the_crate_can_write_a_plaintext_key_file() {
    // The compile-time half of the guarantee: the two functions that know how to
    // serialise a plaintext OpenSSH key are test-only, and if a later change makes
    // one of them reachable from the library, this fails and the author has to
    // explain it here.
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for file in files_under(&sources) {
        let text = std::fs::read_to_string(&file).unwrap();
        for function in ["build_openssh_private", "armour("] {
            if file.file_name().is_some_and(|name| name == "ssh.rs") {
                continue;
            }
            if text.contains(function) {
                offenders.push(format!("{} mentions {function}", file.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "private-key-writing code leaked out of ssh.rs:\n{}",
        offenders.join("\n")
    );
}

fn secret() -> SecretString {
    SecretString::from(PASSPHRASE)
}

fn passphrase_source() -> passphrase::PassphraseSource {
    passphrase::PassphraseSource::given(PASSPHRASE)
}

/// Write a real, unencrypted OpenSSH private key file — written here rather than
/// borrowed from `src/ssh.rs` on purpose: the parser must be tested against the
/// format as somebody else writes it, not against this crate's own assumptions.
fn openssh_private_file(seed: &[u8; 32], comment: &str) -> Vec<u8> {
    let key = gitiup_attest::SigningKey::from_seed(seed);
    let public = key.public_key();
    let mut blob = Vec::new();
    write_string(&mut blob, b"ssh-ed25519");
    write_string(&mut blob, public.as_bytes());

    let mut sk = Vec::new();
    sk.extend_from_slice(seed);
    sk.extend_from_slice(public.as_bytes());
    let mut section = Vec::new();
    section.extend_from_slice(&0x1122_3344u32.to_be_bytes());
    section.extend_from_slice(&0x1122_3344u32.to_be_bytes());
    write_string(&mut section, public.as_bytes());
    write_string(&mut section, &sk);
    write_string(&mut section, comment.as_bytes());
    section.push(1);

    let mut wire = Vec::new();
    wire.extend_from_slice(b"openssh-key-v1\0");
    write_string(&mut wire, b"none");
    write_string(&mut wire, b"none");
    write_string(&mut wire, b"");
    wire.extend_from_slice(&1u32.to_be_bytes());
    write_string(&mut wire, &blob);
    write_string(&mut wire, &section);

    let encoded = gitiup_attest::encoding::base64_encode(&wire);
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

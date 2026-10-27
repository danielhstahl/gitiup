//! The keystore's life cycle: make a key, find it, replace it, delete it.
//!
//! `secret_hygiene.rs` asks "did any plaintext get out"; this file asks the other
//! question a keystore has to answer, which is whether the *bookkeeping* is honest.
//! A key is two files — a public record and an encrypted container — and every
//! operation that touches one has to touch the other in the same breath, or the
//! store ends up with a record that cannot sign or a secret nobody can name.
//!
//! `--force` is the interesting case, because it is the operation users reach for
//! when they are about to do something destructive and the one where a half-done
//! job is worst: half-replaced means a record pointing at a seed that is not its
//! key's.

use std::path::{Path, PathBuf};

use gitiup_attest::key::SigningKey;
use gitiup_keys::keystore::{
    AgentRef, Backend, Generate, Import, KeyRecord, Keystore, RECORD_VERSION, SECRET_SUFFIX,
};
use gitiup_keys::passphrase::{PassphraseSource, SecretString};
use gitiup_keys::paths::Paths;

fn passphrase() -> SecretString {
    SecretString::from("four random words, in order")
}

fn store_in(dir: &Path) -> Keystore {
    Keystore::new(Paths::with_root(dir))
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walk(dir) {
        out.push(entry.file_name().unwrap().to_string_lossy().into_owned());
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
    }
    out
}

#[test]
fn a_forced_replacement_replaces_both_files_or_neither() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let first = store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                comment: Some("ada@laptop".into()),
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();

    // Without `--force`, the name is taken and nothing changes — the check that
    // protects a key from a typo'd second `keygen`.
    let refused = store.generate(
        &Generate {
            name: Some("laptop".into()),
            ..Default::default()
        },
        &passphrase(),
    );
    assert_eq!(refused.unwrap_err().exit_code(), 6);
    assert_eq!(
        files(dir.path()),
        ["laptop.json".to_string(), "laptop.secret.age".to_string()]
    );

    // With it, the key is *replaced*: new key id, one record, one container, and the
    // old key id is gone from the store rather than shadowed.
    let second = store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                comment: Some("ada@laptop".into()),
                force: true,
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();
    assert_ne!(first.key_id, second.key_id, "a replacement is a new key");
    assert_eq!(
        files(dir.path()),
        ["laptop.json".to_string(), "laptop.secret.age".to_string()],
        "a replacement leaves exactly the two files it made"
    );
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(
        store.find(&first.key_id).is_err(),
        "the replaced key must not still be findable"
    );
    // …and the new one actually signs, because the container was rewritten and not
    // merely left behind from the old key.
    let unlocked = store.unlock(&second, &passphrase()).unwrap();
    assert_eq!(unlocked.public_key().key_id(), second.key_id);
    assert!(store.unlock(&first, &passphrase()).is_err());
}

#[test]
fn replacing_a_keystore_key_with_an_agent_record_leaves_no_secret_behind() {
    // The case `--force` makes possible and `clear_for_force` has to handle: an
    // ssh-agent record adopted over the top of a keystore key. The new record has no
    // container, so if the old container were left in place it would hold a seed
    // whose record is gone — a key that exists only in the file listing, and which
    // `list`, `find` and `delete` would never show or remove.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();
    let other = SigningKey::from_seed(&[3u8; 32]).public_key();
    let agent_record = KeyRecord {
        version: RECORD_VERSION,
        name: "laptop".to_string(),
        key_id: other.key_id(),
        public_key: other.to_openssh(),
        backend: Backend::SshAgent,
        created_at_us: 1_793_092_600_000_000,
        comment: Some("ada@laptop".into()),
        secret: None,
        agent: Some(AgentRef {
            socket: "$SSH_AUTH_SOCK".to_string(),
            comment: Some("ada@laptop".into()),
        }),
        gpg: None,
    };
    store.register(&agent_record, true).unwrap();

    let leftovers: Vec<String> = files(dir.path())
        .into_iter()
        .filter(|name| name.ends_with(SECRET_SUFFIX) || name.ends_with(".secret.age"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "an orphan secret container is exactly what a keystore must not accumulate: {leftovers:?}"
    );
    assert_eq!(store.list().unwrap()[0].backend, Backend::SshAgent);
}

#[test]
fn delete_takes_the_record_and_the_container_together() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();
    let removed = store.remove("laptop").unwrap();
    assert!(removed.secret_removed);
    assert!(store.list().unwrap().is_empty());
    assert!(
        files(dir.path())
            .iter()
            .all(|name| !name.starts_with("laptop.")),
        "both files should be gone: {:?}",
        files(dir.path())
    );
    // Deleting twice is a not-found (3), not a shrug: a script that meant to remove
    // a key needs to know whether it did.
    assert_eq!(store.remove("laptop").unwrap_err().exit_code(), 3);
}

#[test]
fn a_key_is_found_by_name_whole_fingerprint_or_a_long_enough_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let record = store
        .generate(
            &Generate {
                name: Some("laptop".into()),
                comment: Some("ada@laptop".into()),
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();
    for selector in [
        "laptop".to_string(),
        "LAPTOP".to_string(),
        record.key_id.clone(),
        record.key_id[..12].to_string(),
    ] {
        assert_eq!(
            store.find(&selector).unwrap().name,
            "laptop",
            "`{selector}` should find it"
        );
    }
    // A fragment too short to be an identity finds nothing (3), which is the honest
    // answer: it is not that two keys matched, it is that this is not a key id.
    assert_eq!(store.find("SHA256:12").unwrap_err().exit_code(), 3);
    // Two keys, one ambiguous prefix: the error names both so the user can choose.
    store
        .generate(
            &Generate {
                name: Some("desktop".into()),
                ..Default::default()
            },
            &passphrase(),
        )
        .unwrap();
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn an_unnamed_import_gets_a_name_that_does_not_collide() {
    // The name is a convenience, so it must not be a trap: the same comment twice
    // would otherwise produce two records with one name, and `--force` was never
    // asked for.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let seed = [9u8; 32];
    // The seed file is hex, which is the format a shell can produce (`xxd -p key.bin`)
    // and the one that survives being piped through text tools.
    let seed_path = dir.path().join("seed.hex");
    let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::write(&seed_path, format!("{hex}\n")).unwrap();
    let first = store
        .import(
            &Import::Seed {
                path: seed_path.clone(),
            },
            None,
            &passphrase(),
            false,
        )
        .unwrap();
    assert!(
        first.record.name.starts_with("key-"),
        "{:?}",
        first.record.name
    );
    // The same seed again is the same key: re-importing it under a new name would
    // silently duplicate a key, so the store says the key id is already here.
    let again = store.import(
        &Import::Seed { path: seed_path },
        None,
        &passphrase(),
        false,
    );
    assert_eq!(
        again.unwrap_err().exit_code(),
        6,
        "importing the same key twice should be a refusal, not two records"
    );
    assert_eq!(store.list().unwrap().len(), 1);
    // And a passphrase source that has nothing to read is a refusal with a hint, not
    // a hang: this is the scripted path.
    let empty = dir.path().join("empty.txt");
    std::fs::write(&empty, "").unwrap();
    let error = PassphraseSource::scripted()
        .file(&empty)
        .read()
        .unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(error.to_string().contains("empty"), "{error}");
}

//! Regenerate the committed golden fixtures (`tests/fixtures/v1/`).
//!
//! ```sh
//! GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_fixtures
//! ```
//!
//! The committed bytes are the contract ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)):
//! another implementation of gitiup — or a shell script checking a signature in a
//! pinch — must reproduce them. `tests/golden.rs` fails if what this program
//! writes no longer matches what is committed, which is the point: a format
//! change has to be a deliberate act, with an ADR.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gitiup_attest::{AttestationDoc, RunManifest, sample};

/// The cases that make up the vector set. New cases go here, and stay forever.
/* A named case: how it is called in `cases.json`, and how to build it. */
type Case = (&'static str, fn() -> RunManifest);

const CASES: [Case; 4] = [
    ("minimal", sample::minimal),
    ("simulated", sample::simulated),
    ("local", sample::local),
    ("quorum-member", sample::quorum_member),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    if std::env::var("GITIUP_UPDATE_FIXTURES").is_err() {
        eprintln!(
            "refusing to overwrite committed fixtures without GITIUP_UPDATE_FIXTURES=1\n\
             (tests/golden.rs checks them on every run)"
        );
        std::process::exit(2);
    }
    std::fs::create_dir_all(&root)?;

    let key = sample::test_key();
    let mut index = serde_json::Map::new();
    index.insert(
        "comment".into(),
        serde_json::Value::String(
            "Golden attestation vectors, v1. Generated with:\n  \
             GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_fixtures\n\
             manifest.json and doc.json are canonical bytes (no trailing newline); this index is \
             pretty-printed for humans and is not signed."
                .into(),
        ),
    );
    let mut key_info = serde_json::Map::new();
    key_info.insert(
        "public_key".into(),
        serde_json::Value::String(key.public_key().to_openssh()),
    );
    key_info.insert(
        "key_id".into(),
        serde_json::Value::String(key.public_key().key_id()),
    );
    key_info.insert(
        "comment".into(),
        serde_json::Value::String(
            "Derived from the public TEST_SEED in gitiup-attest::sample; no private key material \
             is committed, and no production trust policy may trust this key."
                .into(),
        ),
    );
    index.insert("signing_key".into(), serde_json::Value::Object(key_info));

    let mut cases = Vec::new();
    for (name, build) in CASES {
        let manifest = build();
        let mut doc = AttestationDoc::new(manifest.clone());
        doc.sign(&key).map_err(|e| e.to_string())?;

        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        write(&dir.join("manifest.json"), &doc.payload_bytes()?)?;
        write(&dir.join("doc.json"), &doc.canonical_bytes()?)?;

        let signatures: Vec<serde_json::Value> = doc
            .signatures
            .iter()
            .map(|entry| {
                let mut map = BTreeMap::new();
                map.insert("key_id".to_string(), entry.key_id.clone());
                map.insert("sig".to_string(), entry.sig.clone());
                serde_json::Value::Object(
                    map.into_iter()
                        .map(|(k, v)| (k, serde_json::Value::String(v)))
                        .collect(),
                )
            })
            .collect();
        let mut case = serde_json::Map::new();
        case.insert("name".into(), serde_json::Value::String(name.to_string()));
        case.insert(
            "run_digest".into(),
            serde_json::Value::String(doc.run_digest().map_err(|e| e.to_string())?.to_string()),
        );
        case.insert(
            "result_digest".into(),
            serde_json::Value::String(doc.result_digest().map_err(|e| e.to_string())?.to_string()),
        );
        case.insert(
            "record_digest".into(),
            serde_json::Value::String(doc.record_digest().map_err(|e| e.to_string())?.to_string()),
        );
        case.insert("signatures".into(), serde_json::Value::Array(signatures));
        cases.push(serde_json::Value::Object(case));
        println!(
            "wrote {name}: run {}",
            doc.run_digest()
                .map_err(|e| e.to_string())?
                .hex()
                .get(..12)
                .unwrap_or_default()
        );
    }

    index.insert("cases".into(), serde_json::Value::Array(cases));
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(index))? + "\n";
    write(&root.join("cases.json"), text.as_bytes())?;
    println!("wrote {}", root.join("cases.json").display());
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

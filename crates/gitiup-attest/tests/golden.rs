//! The golden fixtures: committed bytes that must never change by accident.
//!
//! This is the acceptance test for ADR-0001 in one file. For every case it
//! checks that the committed manifest bytes
//!
//! * are canonical (so the *encoding* is what is pinned, not just the model),
//! * parse and validate,
//! * hash to the digests recorded in `cases.json`,
//! * carry a signature that verifies against the recorded key id, and
//! * re-serialize to the identical bytes that were read.
//!
//! If you are changing the format on purpose, regenerate
//! (`GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_fixtures`)
//! and say why in the ADR.

use std::path::{Path, PathBuf};

use gitiup_attest::key::PublicKey;
use gitiup_attest::policy::Trust;
use gitiup_attest::{AttestationDoc, Policy, RunManifest};
use serde_json::Value;

/// Fixed verification clock: the fixtures claim a fixed instant.
const FIXED_NOW_SECS: i64 = 1_793_092_600;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn index() -> Value {
    let text = read(&fixtures_dir().join("cases.json"));
    serde_json::from_slice(&text).expect("cases.json must be valid JSON")
}

fn policy_for(key_id: &str) -> Policy {
    Policy {
        trust: Trust::KeyIds([key_id.to_string()].into_iter().collect()),
        allowed_tiers: vec![gitiup_attest::Tier::Simulated, gitiup_attest::Tier::Local],
        now: Some(gitiup_attest::TimeUs::from_secs(FIXED_NOW_SECS)),
        ..Policy::default()
    }
}

#[test]
fn every_case_matches_its_committed_bytes() {
    let dir = fixtures_dir();
    let mut checked = 0usize;
    for entry in index()["cases"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let manifest_bytes = read(&dir.join(name).join("manifest.json"));
        let doc_bytes = read(&dir.join(name).join("doc.json"));

        // Encoding is pinned: no whitespace, no re-ordering, no trailing newline.
        assert!(
            gitiup_attest::is_canonical(&manifest_bytes),
            "{name}: manifest.json is not canonical bytes"
        );
        assert!(
            gitiup_attest::is_canonical(&doc_bytes),
            "{name}: doc.json is not canonical bytes"
        );
        assert!(
            !manifest_bytes.ends_with(b"\n") && !doc_bytes.ends_with(b"\n"),
            "{name}: fixture bytes must be the payload exactly, no trailing newline"
        );

        let manifest = RunManifest::from_canonical_bytes(&manifest_bytes)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let doc = AttestationDoc::from_canonical_bytes(&doc_bytes)
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(doc.manifest, manifest, "{name}: doc and manifest diverged");
        assert_eq!(
            manifest.digest().unwrap().to_string(),
            entry["run_digest"].as_str().unwrap(),
            "{name}: RunDigest moved"
        );
        assert_eq!(
            manifest.result_digest().unwrap().to_string(),
            entry["result_digest"].as_str().unwrap(),
            "{name}: ResultDigest moved"
        );
        assert_eq!(
            doc.record_digest().unwrap().to_string(),
            entry["record_digest"].as_str().unwrap(),
            "{name}: storage key moved"
        );
        assert_eq!(
            doc.canonical_bytes().unwrap(),
            doc_bytes,
            "{name}: re-encoding differs from the committed bytes"
        );

        // Signatures: recorded form, and they actually verify.
        let expected = entry["signatures"].as_array().unwrap();
        assert_eq!(
            doc.signatures.len(),
            expected.len(),
            "{name}: signature count"
        );
        for (got, want) in doc.signatures.iter().zip(expected) {
            assert_eq!(got.key_id, want["key_id"].as_str().unwrap());
            assert_eq!(got.sig, want["sig"].as_str().unwrap());
        }
        let verdict = doc
            .verify(&policy_for(
                index()["signing_key"]["key_id"].as_str().unwrap(),
            ))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!verdict.signers.is_empty());
        checked += 1;
    }
    assert_eq!(checked, 4, "all four cases must be present");
}

#[test]
fn the_fixture_key_is_publicly_derivable_and_pinned() {
    // The index pins the key line and id; both must follow from the public seed.
    let key = gitiup_attest::sample::test_key();
    let index = index();
    assert_eq!(
        key.public_key().to_openssh(),
        index["signing_key"]["public_key"].as_str().unwrap()
    );
    assert_eq!(
        key.public_key().key_id(),
        index["signing_key"]["key_id"].as_str().unwrap()
    );
    // ...and the line parses back through the public API.
    assert_eq!(
        PublicKey::from_openssh(index["signing_key"]["public_key"].as_str().unwrap()).unwrap(),
        key.public_key()
    );
}

#[test]
fn a_byte_of_tampering_changes_the_digest_and_fails_the_signature() {
    // The property the whole design buys: digests and signatures react to any
    // edit, so "we noticed nothing" is not an option.
    let dir = fixtures_dir();
    let bytes = read(&dir.join("local").join("manifest.json"));
    let text = String::from_utf8(bytes.clone()).unwrap();
    let tampered = text.replacen("\"exit_code\":0", "\"exit_code\":1", 1);
    assert_ne!(tampered, text, "the fixture must contain an exit code");

    let manifest = RunManifest::from_canonical_bytes(tampered.as_bytes()).unwrap();
    let doc =
        AttestationDoc::from_canonical_bytes(&read(&dir.join("local").join("doc.json"))).unwrap();
    assert_ne!(
        manifest.digest().unwrap(),
        doc.run_digest().unwrap(),
        "the RunDigest must change"
    );
    assert_ne!(
        manifest.result_digest().unwrap(),
        doc.result_digest().unwrap(),
        "and so must the ResultDigest verifiers compare"
    );
    let mut forged = doc.clone();
    forged.manifest = manifest;
    let err = forged
        .verify(&policy_for(
            index()["signing_key"]["key_id"].as_str().unwrap(),
        ))
        .unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Signature);
    assert_eq!(err.exit_code(), 7);
}

#[test]
fn relabelling_a_run_as_simulated_is_refused_without_a_signature() {
    // The cheapest forgery to attempt is a *label* change, and giti-1rs.7 is the
    // ticket that made it fail: the tier has to agree with the sandbox and the
    // secrets around it, so flipping one word makes the manifest ill-formed. No
    // key, no clock and no policy needed to notice.
    let dir = fixtures_dir();
    let text = String::from_utf8(read(&dir.join("local").join("manifest.json"))).unwrap();
    let relabelled = text.replace("\"tier\":\"local\"", "\"tier\":\"simulated\"");
    assert_ne!(relabelled, text, "the fixture must contain the tier field");

    let err = RunManifest::from_canonical_bytes(relabelled.as_bytes()).unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert_eq!(err.exit_code(), 6);
    assert!(
        err.detail().contains("simulated run cannot claim sandbox"),
        "unexpected refusal: {}",
        err.detail()
    );

    // The other direction of the same lie: `local` with no sandbox named.
    let unconfined = text.replace("\"sandbox\":\"docker\",", "");
    assert_ne!(unconfined, text);
    let err = RunManifest::from_canonical_bytes(unconfined.as_bytes()).unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("must name the sandbox"));
}

#[test]
fn fixtures_survive_a_reparse_of_every_field() {
    // Round-tripping through the generic value model must not change anything:
    // it catches a field that serializes two ways (floats, nulls, map order).
    for entry in index()["cases"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let bytes = read(&fixtures_dir().join(name).join("manifest.json"));
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let again = gitiup_attest::canon::to_value_bytes(&value).unwrap();
        assert_eq!(again, bytes, "{name}: re-encode is not byte identical");
    }
}

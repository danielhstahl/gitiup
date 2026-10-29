//! The ADR-0003 change vectors, checked against *this* crate's primitives.
//!
//! [`docs/adr/fixtures/change-v1/`](../../../docs/adr/fixtures/change-v1/README.md)
//! is the byte-for-byte contract four tickets code against. The fixture generator is
//! Python, so checking the vectors against Python again would be checking them
//! against themselves; this file checks them against the canonicaliser, the SSH
//! key-id derivation and the signature verifier that the real code uses
//! ([`canon`], [`PublicKey::key_id`], [`SignatureEntry::verify`]).
//!
//! What is proven here is that the *bytes* are canonical, that both digests are the
//! ones the record's contents give, and that the signatures verify (and do not verify
//! when tampered). What `giti-b2z.2` adds on top, in
//! `crates/gitiup-host/tests/change_vectors.rs`, is the ref side: `change_id`
//! re-derivation, the `refs/changes/**` names in `cases.json`, and publish/fetch
//! through a real store.

use std::fs;
use std::path::{Path, PathBuf};

use gitiup_attest::{Digest, SignatureEntry, canon, pae};
use serde_json::Value;

/// The `kv/` namespace each record kind is filed under (ADR-0003 D5).
const NAMESPACES: &[(&str, &str)] = &[
    ("change", "kv/change"),
    ("merge", "kv/merge"),
    ("abandon", "kv/abandon"),
];

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/fixtures/change-v1")
        .to_path_buf()
}

fn index() -> Value {
    let path = fixtures_dir().join("cases.json");
    serde_json::from_slice(&fs::read(path).expect("cases.json readable"))
        .expect("cases.json parses")
}

fn read_record(case: &Value) -> Value {
    let path = fixtures_dir().join(case["file"].as_str().expect("file"));
    serde_json::from_slice(&fs::read(path).expect("record bytes readable")).expect("record parses")
}

fn cases() -> Vec<(String, Value, Vec<u8>)> {
    let index = index();
    let object = index["cases"].as_object().expect("cases is an object");
    assert!(!object.is_empty(), "no cases");
    object
        .iter()
        .map(|(name, case)| {
            let bytes = fs::read(fixtures_dir().join(case["file"].as_str().unwrap()))
                .expect("record bytes present");
            (name.clone(), case.clone(), bytes)
        })
        .collect()
}

/// The signed body: the record with its own signature lists removed
/// (ADR-0003 D1, the rule `gitiup_quorum::record::body_bytes` already applies).
fn body_bytes(record: &Value) -> Vec<u8> {
    let mut body = record.clone();
    body.as_object_mut()
        .expect("record is an object")
        .remove("signatures");
    canon::to_value_bytes(&body).expect("body canonicalises")
}

fn payload_type(kind: &str) -> String {
    format!("application/vnd.gitiup.{kind}+json")
}

#[test]
fn every_record_is_canonical_as_this_crate_writes_it() {
    for (name, _, bytes) in cases() {
        let value: Value = serde_json::from_slice(&bytes).expect("record parses");
        assert_eq!(
            canon::to_value_bytes(&value).unwrap(),
            bytes.as_slice(),
            "{name}: the committed bytes are not what this canonicaliser writes"
        );
        canon::require_canonical(&bytes).unwrap_or_else(|e| panic!("{name}: not canonical: {e}"));
    }
}

#[test]
fn both_digests_are_the_adrs_two() {
    for (name, case, bytes) in cases() {
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            format!("sha256:{}", Digest::sha256(&bytes).hex()),
            case["record_digest"].as_str().unwrap(),
            "{name}: record_digest is not sha256 of the stored bytes (ADR-0003 D4)"
        );
        assert_eq!(
            format!("sha256:{}", Digest::sha256(&body_bytes(&value)).hex()),
            case["body_digest"].as_str().unwrap(),
            "{name}: body_digest is not sha256 of the record without its signatures"
        );
        let kind = case["kind"].as_str().unwrap();
        let namespace = NAMESPACES
            .iter()
            .find(|(k, _)| *k == kind)
            .unwrap_or_else(|| panic!("{name}: unknown kind {kind}"))
            .1;
        let hex = case["record_digest"]
            .as_str()
            .unwrap()
            .trim_start_matches("sha256:");
        assert_eq!(
            case["refs"]["kv"].as_str().unwrap(),
            format!("{namespace}/{hex}"),
            "{name}: the storage key is not kv/<namespace>/<record digest hex>"
        );
    }
}

#[test]
fn signatures_verify_here_and_nowhere_else() {
    for (name, case, bytes) in cases() {
        let kind = case["kind"].as_str().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let signatures = value["signatures"].as_array().unwrap();
        assert_eq!(signatures.len(), 1, "{name}: exactly one signature (D2)");
        let entry: SignatureEntry =
            serde_json::from_value(signatures[0].clone()).expect("signature entry shape");
        assert_eq!(
            entry.key_id,
            case["author"].as_str().unwrap(),
            "{name}: the index and the record disagree about the author"
        );
        let message = pae(&payload_type(kind), &body_bytes(&value));
        entry
            .verify(&message)
            .unwrap_or_else(|e| panic!("{name}: {kind} signature must verify: {e}"));

        // The same signature must not survive a change to what it covers.
        let mut tampered = value.clone();
        let field = if kind == "change" { "title" } else { "note" };
        tampered[field] = Value::String("a different text entirely".into());
        assert!(
            entry
                .verify(&pae(&payload_type(kind), &body_bytes(&tampered)))
                .is_err(),
            "{name}: a tampered {kind} verified"
        );
        assert_eq!(
            entry
                .verify(&pae(&payload_type("abandon"), &body_bytes(&value)))
                .is_err(),
            kind != "abandon",
            "{name}: the payload type is not inside the signature"
        );
    }
}

#[test]
fn the_id_derivation_is_pinned_and_the_chain_is_real() {
    let index = index();
    let first = &index["cases"]["open-first"];
    let second = &index["cases"]["open-second"];
    assert_eq!(
        first["change_id"].as_str().unwrap(),
        second["change_id"].as_str().unwrap(),
        "a force-push must not change the change_id (ADR-0003 D3)"
    );
    assert_ne!(
        first["body_digest"].as_str().unwrap(),
        second["body_digest"].as_str().unwrap(),
        "two attempts are two records"
    );

    let first_record = read_record(first);
    let second_record = read_record(second);
    assert_eq!(
        second_record["attempts"]["previous"].as_str().unwrap(),
        first["body_digest"].as_str().unwrap(),
        "attempt 1's `previous` is attempt 0's change_digest (D6)"
    );
    assert_eq!(
        second_record["attempts"]["anchor"].as_str().unwrap(),
        first_record["head"].as_str().unwrap(),
        "the anchor is attempt 0's head, and it is what the id derives from (D3)"
    );

    // A merge names the *attempt* it merged: the cited field is that attempt's
    // digest, never the merge record's own body digest.
    let merged = &index["cases"]["merged"];
    let merged_record = read_record(merged);
    assert_eq!(
        merged_record["change_digest"].as_str().unwrap(),
        second["body_digest"].as_str().unwrap(),
        "the merge record must cite the attempt it merged (D8)"
    );
    assert_ne!(
        merged_record["change_digest"].as_str().unwrap(),
        merged["body_digest"].as_str().unwrap(),
        "a merge record citing itself would prove nothing"
    );
    assert_eq!(
        merged_record["base"]["to"].as_str().unwrap(),
        second_record["head"].as_str().unwrap(),
        "the merge's `to` must be the merged attempt's head (D8)"
    );
}

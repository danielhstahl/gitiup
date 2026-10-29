//! [ADR-0003's change vectors](../../../../docs/adr/fixtures/change-v1/README.md),
//! checked against the Rust reader that four downstream tickets code against.
//!
//! [`generate.py`](../../../../docs/adr/fixtures/change-v1/generate.py) is the
//! executable half of the spec and the only thing that proves the prose is a spec; this
//! file is the other half — the same bytes read by
//! [`gitiup_host::change`]. `crates/gitiup-attest/tests/change_vectors.rs` already
//! proves the *format* primitives agree (canonical bytes, digests, signatures); what is
//! proven here is the part only this crate owns: that a reader parses these records,
//! re-derives their `change_id`, and files them under the refs and `kv/` keys the index
//! says. A reader that disagrees is wrong about the format, however reasonable it looks.

use std::fs;
use std::path::{Path, PathBuf};

use gitiup_host::change::{
    self, ABANDON_TYPE, AbandonRecord, CHANGE_TYPE, ChangeId, ChangeRecord, MERGE_TYPE,
    MergeRecord, StoredRecord,
};
use serde_json::Value;

mod change_support;
use change_support::fixture_key;

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

fn case(name: &str) -> Value {
    index()["cases"][name].clone()
}

fn raw(name: &str) -> Vec<u8> {
    let entry = case(name);
    fs::read(fixtures_dir().join(entry["file"].as_str().unwrap())).expect("record bytes")
}

fn all_cases() -> Vec<(String, Value)> {
    index()["cases"]
        .as_object()
        .expect("cases is an object")
        .iter()
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect()
}

/// Parse stored bytes the way a store reader does: `type` decides, and nothing that
/// fails to re-derive or re-verify is returned.
fn read(bytes: &[u8]) -> gitiup_host::HostResult<StoredRecord> {
    change::record_from_bytes(bytes)
}

#[test]
fn the_committed_bytes_are_what_this_module_writes() {
    // Not "parses to the same value" — the *bytes* must round-trip, or a merge record
    // written here is not the one a foreign reader signed.
    for (name, entry) in all_cases() {
        let bytes = raw(&name);
        let record =
            read(&bytes).unwrap_or_else(|e| panic!("{name}: the committed record is refused: {e}"));
        assert_eq!(
            record.canonical_bytes().unwrap(),
            bytes.as_slice(),
            "{name}: re-encoding the parsed record does not reproduce the file"
        );
        assert_eq!(
            format!("sha256:{}", record.digest().unwrap().hex()),
            entry["record_digest"].as_str().unwrap(),
            "{name}: record_digest is not sha256 of the stored bytes (D4)"
        );
    }
}

#[test]
fn every_record_names_itself_the_way_the_index_says() {
    for (name, entry) in all_cases() {
        let bytes = raw(&name);
        let record = read(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        record
            .verify()
            .unwrap_or_else(|e| panic!("{name}: refused a valid record: {e}"));

        assert_eq!(
            record.change_id().as_str(),
            entry["change_id"].as_str().unwrap(),
            "{name}: change_id"
        );
        assert_eq!(
            record.change_id().as_str(),
            case(&name)["change_id"].as_str().unwrap()
        );

        // The body digest — `change_digest` for a change record (D4's naming note).
        let body = match &record {
            StoredRecord::Change(r) => r.change_digest().unwrap(),
            StoredRecord::Merge(r) => r.body_digest().unwrap(),
            StoredRecord::Abandon(r) => r.body_digest().unwrap(),
        };
        assert_eq!(
            body,
            entry["body_digest"].as_str().unwrap(),
            "{name}: the digest of the record without its signatures"
        );

        // And the names it is filed under (D5), derived here rather than transcribed.
        let hex = record.digest().unwrap().hex();
        let kind = entry["kind"].as_str().unwrap();
        let namespace = match kind {
            "change" => &change::CHANGE_NAMESPACE,
            "merge" => &change::MERGE_NAMESPACE,
            "abandon" => &change::ABANDON_NAMESPACE,
            other => panic!("{name}: unknown kind {other}"),
        };
        assert_eq!(
            entry["refs"]["kv"].as_str().unwrap(),
            change::kv_key(namespace, &record.digest().unwrap()),
            "{name}: the storage key is kv/<namespace>/<record digest>"
        );
        assert_eq!(hex.len(), 64, "{name}: a sha256 digest");

        let expected: Vec<String> = entry["refs"]["refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        let id = record.change_id();
        let written: Vec<String> = match &record {
            StoredRecord::Change(r) => vec![
                change::attempt_ref(id, r.attempts.index).to_string(),
                change::change_head_ref(id).to_string(),
            ],
            StoredRecord::Merge(_) => vec![change::merged_ref(id).to_string()],
            StoredRecord::Abandon(_) => vec![change::abandoned_ref(id).to_string()],
        };
        assert_eq!(
            expected, written,
            "{name}: refs differ from the index ({hex})"
        );
    }
}

#[test]
fn the_three_kinds_are_read_by_their_type_member() {
    for (name, entry) in all_cases() {
        let bytes = raw(&name);
        let want = match entry["kind"].as_str().unwrap() {
            "change" => CHANGE_TYPE,
            "merge" => MERGE_TYPE,
            "abandon" => ABANDON_TYPE,
            other => panic!("{name}: unknown kind {other}"),
        };
        assert_eq!(
            read(&bytes).unwrap().record_type(),
            want,
            "{name}: the type member must select the reader"
        );
        // And each typed reader accepts only its own kind.
        let typed = match want {
            CHANGE_TYPE => ChangeRecord::from_canonical_bytes(&bytes)
                .map(|_| ())
                .is_ok(),
            MERGE_TYPE => MergeRecord::from_canonical_bytes(&bytes)
                .map(|_| ())
                .is_ok(),
            _ => AbandonRecord::from_canonical_bytes(&bytes)
                .map(|_| ())
                .is_ok(),
        };
        assert!(typed, "{name}: its own typed reader refused it");
    }
    // A type this build does not speak is refused rather than read leniently.
    let bytes = raw("open-first");
    let foreign: serde_json::Value = {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["type"] = Value::String("gitiup-change-2".into());
        value
    };
    let err = read(&serde_json::to_vec(&foreign).unwrap()).unwrap_err();
    assert_eq!(err.exit_code(), 6, "an unknown type is a refusal: {err}");
}

#[test]
fn a_change_id_is_re_derivable_from_one_record_alone() {
    // D3's whole claim: no store query, no listing, no state.
    for (name, entry) in all_cases() {
        let bytes = raw(&name);
        let record = read(&bytes).unwrap();
        let id = record.change_id();
        assert_eq!(id.as_str(), entry["change_id"].as_str().unwrap(), "{name}");
        if let StoredRecord::Change(change) = &record {
            assert_eq!(
                ChangeId::derive(
                    &change.author.key_id,
                    &change.base.branch,
                    &change.attempts.anchor
                )
                .unwrap(),
                *id,
                "{name}: the id does not re-derive from its own fields"
            );
        }
        // ref-safe, bucket-safe, 20 characters (D3).
        assert!(id.as_str().starts_with("chg-"));
        assert_eq!(id.hex().len(), 16);
        assert_eq!(
            change::change_head_ref(id).as_str().len(),
            20 + "refs/changes/".len() + 5
        );
    }
}

#[test]
fn the_force_push_is_a_new_attempt_of_the_same_change() {
    let first = read(&raw("open-first")).unwrap();
    let second = read(&raw("open-second")).unwrap();
    let (StoredRecord::Change(first), StoredRecord::Change(second)) = (&first, &second) else {
        panic!("the open-* vectors are change records");
    };
    assert_eq!(
        first.change_id, second.change_id,
        "a force-push must not create a new change (D3)"
    );
    assert_ne!(first.head, second.head);
    assert_eq!(second.attempts.index, 1);
    assert_eq!(
        second.attempts.anchor, first.head,
        "the anchor is attempt 0's head"
    );
    assert_eq!(
        second.attempts.previous.as_deref(),
        Some(first.change_digest().unwrap().as_str()),
        "attempt 1 names attempt 0's change_digest (D6)"
    );
    assert_ne!(
        first.change_digest().unwrap(),
        second.change_digest().unwrap(),
        "two attempts are two records"
    );

    // A merge names the attempt it merged, not "the change" (D8).
    let merged = MergeRecord::from_canonical_bytes(&raw("merged")).unwrap();
    assert_eq!(
        merged.change_digest,
        second.change_digest().unwrap(),
        "the merge record must cite the attempt it merged"
    );
    assert_eq!(merged.attempt, 1);
    assert_eq!(
        merged.base.to, second.head,
        "the CAS wrote the attempt's head"
    );
    assert_eq!(
        merged.base.from, second.base.oid,
        "the CAS expected the base"
    );
    assert_eq!(merged.base.branch, second.base.branch);
    assert_eq!(merged.via, "store");
    assert_eq!(merged.proofs.len(), 2, "the proofs believed (D8)");
    assert_ne!(
        merged.change_digest,
        merged.body_digest().unwrap(),
        "a merge record citing itself would prove nothing"
    );

    // An abandon closes its change and cites its own attempt (D7).
    let abandoned = AbandonRecord::from_canonical_bytes(&raw("abandoned")).unwrap();
    let pull = ChangeRecord::from_canonical_bytes(&raw("pull-backed")).unwrap();
    assert_eq!(abandoned.change_digest, pull.change_digest().unwrap());
    assert_eq!(abandoned.attempt, 0);
    assert_eq!(abandoned.reason, "superseded");
    assert_eq!(
        abandoned.author.key_id, pull.author.key_id,
        "the author closed it"
    );
}

#[test]
fn tampering_is_refused_with_the_code_that_names_it() {
    // 8 for "these bytes are not what they were named", 7 for "this signature is not
    // this record's", 6 for "this record is refused" (D11).
    let bytes = raw("open-first");
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let mut later = tampered.clone();
    later["created_at_us"] = Value::from(1_764_674_043_000_001i64);
    let err = read(&gitiup_canon::canon::to_value_bytes(&later).unwrap()).unwrap_err();
    assert_eq!(err.exit_code(), 7, "a signed field was edited: {err}");

    tampered["title"] = Value::String("a different title entirely".into());
    let err = read(&gitiup_canon::canon::to_value_bytes(&tampered).unwrap()).unwrap_err();
    assert_eq!(
        err.exit_code(),
        7,
        "the title is inside the signature: {err}"
    );

    // A record claiming a name its own contents contradict.
    let mut squatter: serde_json::Value = serde_json::from_slice(&raw("wide")).unwrap();
    squatter["change_id"] = Value::String("chg-0000000000000000".into());
    let err = read(&gitiup_canon::canon::to_value_bytes(&squatter).unwrap()).unwrap_err();
    assert_eq!(err.exit_code(), 8, "the id must re-derive: {err}");

    // Bytes that are not their own canonical form.
    let mut spaced = raw("open-first");
    spaced.splice(1..1, b" ".to_vec());
    let err = read(&spaced).unwrap_err();
    assert_eq!(err.exit_code(), 8, "whitespace is a second encoding: {err}");

    // An unknown field, refused rather than ignored.
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["state"] = Value::String("merged".into());
    let err = read(&gitiup_canon::canon::to_value_bytes(&extra).unwrap()).unwrap_err();
    assert_eq!(
        err.exit_code(),
        6,
        "there is no `state` field and a reader does not ignore one: {err}"
    );

    // Someone else's signature on this record.
    let mut rekeyed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let lin = fixture_key("lin");
    rekeyed["signatures"][0]["public_key"] = Value::String(lin.public_key().to_openssh());
    rekeyed["signatures"][0]["key_id"] = Value::String(lin.public_key().key_id());
    let err = read(&gitiup_canon::canon::to_value_bytes(&rekeyed).unwrap()).unwrap_err();
    assert_eq!(
        err.exit_code(),
        7,
        "the signature is ada's and the author now claims lin: {err}"
    );
}

#[test]
fn the_fixture_keys_are_the_same_keys_everywhere() {
    // The key-id derivation is shared (gitiup-canon), so the fixture's key ids are this
    // build's key ids. If they ever differ, every stored record changes name.
    let index = index();
    let keys = index["keys"].as_object().unwrap();
    for (label, entry) in keys {
        assert_eq!(
            fixture_key(label).public_key().key_id(),
            entry["key_id"].as_str().unwrap(),
            "key id for {label}"
        );
        assert_eq!(
            fixture_key(label).public_key().to_openssh(),
            entry["public_key"].as_str().unwrap(),
            "public key for {label}"
        );
    }
}

#[test]
fn the_published_limits_are_the_fixtures_limits() {
    let limits = &index()["limits"];
    assert_eq!(
        limits["record_bytes"].as_u64().unwrap() as usize,
        change::MAX_RECORD_BYTES
    );
    assert_eq!(
        limits["title_bytes"].as_u64().unwrap() as usize,
        change::MAX_TITLE_BYTES
    );
    assert_eq!(
        limits["principal_bytes"].as_u64().unwrap() as usize,
        change::MAX_PRINCIPAL_BYTES
    );
    assert_eq!(limits["jobs"].as_u64().unwrap() as usize, change::MAX_JOBS);
    assert_eq!(
        limits["job_bytes"].as_u64().unwrap() as usize,
        change::MAX_JOB_BYTES
    );
    assert_eq!(
        limits["proofs"].as_u64().unwrap() as usize,
        change::MAX_PROOFS
    );
    assert_eq!(
        limits["annotations"].as_u64().unwrap() as usize,
        change::MAX_ANNOTATIONS
    );
    assert_eq!(
        limits["chain"].as_u64().unwrap() as usize,
        change::MAX_CHAIN
    );
    assert_eq!(
        index()["id"]["hex_chars"].as_u64().unwrap() as usize,
        change::ID_HEX_CHARS
    );
    assert_eq!(index()["id"]["domain"].as_str().unwrap(), change::ID_DOMAIN);
    assert_eq!(
        index()["payload_types"]["change"].as_str().unwrap(),
        change::CHANGE_PAYLOAD_TYPE
    );
    assert_eq!(
        index()["payload_types"]["merge"].as_str().unwrap(),
        change::MERGE_PAYLOAD_TYPE
    );
    assert_eq!(
        index()["payload_types"]["abandon"].as_str().unwrap(),
        change::ABANDON_PAYLOAD_TYPE
    );
}

#[test]
fn the_wide_record_stays_inside_the_limits_it_exists_to_test() {
    let record = ChangeRecord::from_canonical_bytes(&raw("wide")).unwrap();
    assert!(record.title.len() > 200, "the title is long on purpose");
    assert_eq!(record.workflow.jobs.len(), 8);
    assert!(record.title.contains('"') && record.title.contains('\\'));
    assert!(record.title.contains('é'), "canonical UTF-8 survives");
    assert!(record.title.len() <= change::MAX_TITLE_BYTES);
    let pull = ChangeRecord::from_canonical_bytes(&raw("pull-backed")).unwrap();
    assert_eq!(pull.origin, change::Origin::pull(428));
    assert_eq!(
        pull.annotations
            .as_ref()
            .unwrap()
            .get("x_gitiup_host_github_pr")
            .map(String::as_str),
        Some("428"),
        "the annotation hatch is the only place a foreign producer may write"
    );
}

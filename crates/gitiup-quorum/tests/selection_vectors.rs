//! The ADR-0002 golden vectors: roster.json + round.json in, `selection.json` out.
//!
//! This is the load-bearing test of the whole epic. The vectors were written by a
//! stdlib-only Python reference implementation
//! ([`docs/adr/fixtures/selection-v1/generate.py`](../../../docs/adr/fixtures/selection-v1/README.md)),
//! so comparing this crate's output against them is a cross-implementation check of
//! every number a quorum rests on: the seed, the score ordering, the filter order, the
//! caps, the handles and the promotion rule.
//!
//! The ADR says which side is wrong if this fails — the Rust, however reasonable it
//! looks — and that asymmetry is the reason the vectors were written before the code.

use std::path::PathBuf;

use gitiup_attest::Digest;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::roster::Roster;
use gitiup_quorum::select::{RoundInputs, Selection};
use serde_json::Value;

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../../docs/adr/fixtures/selection-v1",
        name,
    ]
    .iter()
    .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn json(name: &str) -> Value {
    let bytes = fixture(name);
    serde_json::from_slice(&bytes).expect("the fixture is valid JSON")
}

/// The roster parses, re-canonicalises to the same bytes, and hashes to the digest the
/// round pins.
#[test]
fn the_roster_vector_is_canonical_and_pinned() {
    let bytes = fixture("roster.json");
    let roster = Roster::from_canonical_bytes(&bytes).expect("the roster vector parses");
    assert!(
        gitiup_attest::is_canonical(&bytes),
        "roster.json is canonical"
    );
    // Re-encoding must be byte-identical, or the Rust and Python canonicalisers
    // disagree and every digest in the quorum is a coin flip.
    assert_eq!(
        roster.canonical_bytes().unwrap().as_slice(),
        bytes.as_slice(),
        "this build re-encodes the roster differently from the reference generator"
    );
    let round = json("round.json");
    let pinned: Digest = round["roster_digest"].as_str().unwrap().parse().unwrap();
    assert_eq!(roster.digest().unwrap(), pinned);
    assert_eq!(roster.entries.len(), 12);
    assert_eq!(
        roster.identities().len(),
        9,
        "twelve boxes, nine principals"
    );
    assert!(
        roster.signatures.is_empty(),
        "the selection vectors are unsigned by design; a real roster is not"
    );
}

/// The whole selection document, compared as parsed JSON so key order in the file is
/// not part of the contract but every value is.
#[test]
fn selection_reproduces_the_vector_exactly() {
    let roster = Roster::from_canonical_bytes(&fixture("roster.json")).unwrap();
    let inputs: RoundInputs = serde_json::from_slice(&fixture("round.json")).unwrap();
    let computed =
        Selection::select(&roster, &inputs, &SelectionSecret::test_vector()).expect("selects");
    let mut want = json("selection.json");
    // `promotion` is a second derivation over the same round, checked separately.
    let promotion = want
        .as_object_mut()
        .expect("selection.json is an object")
        .remove("promotion")
        .expect("the vector publishes promotion cases");

    let got = serde_json::to_value(&computed).expect("a selection serialises");
    assert_eq!(
        got, want,
        "selection differs from the ADR-0002 vector (the ADR says this implementation is wrong)"
    );

    // Promotion: re-run the same round with a longer exclusion list, same seed, same
    // epoch. Two cases in the vector: one that fills the seat, one where the caps leave
    // no substitute and the round legitimately comes up short.
    let cases = promotion["cases"].as_array().expect("promotion cases");
    assert_eq!(cases.len(), 2);
    for case in cases {
        let voided: std::collections::BTreeSet<String> = case["voided"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let after = Selection::promote(&roster, &inputs, computed.seed.clone(), &voided).unwrap();
        assert_eq!(after.seed, computed.seed, "promotion must not re-seed");
        assert_eq!(
            after.selected.len(),
            case["selected_after"].as_u64().unwrap() as usize,
            "seat count after promoting around {voided:?}"
        );
        assert_eq!(
            after.sufficient,
            case["sufficient"].as_bool().unwrap(),
            "sufficiency after promoting around {voided:?}"
        );
        // `promoted` is the seat that filled the void, or null when the caps leave no
        // substitute (the ADR's "the round legitimately comes up short" case).
        let want_promoted = &case["promoted"];
        if want_promoted.is_null() {
            assert!(
                after.selected.iter().all(|seat| computed
                    .selected
                    .iter()
                    .any(|was| was.key_id == seat.key_id)),
                "the vector says nothing could be promoted for {voided:?}, this build found a                  substitute — the caps or the identity rule changed"
            );
        } else {
            let added: Vec<&gitiup_quorum::select::Seat> = after
                .selected
                .iter()
                .filter(|seat| {
                    !computed
                        .selected
                        .iter()
                        .any(|was| was.key_id == seat.key_id)
                })
                .collect();
            assert_eq!(
                added.len(),
                1,
                "exactly one verifier is promoted for {voided:?}"
            );
            assert_eq!(
                serde_json::to_value(added[0]).unwrap(),
                *want_promoted,
                "the promoted seat must be the derived one, down to its handle"
            );
        }
    }
}

/// The seed, policy digest and round id the ADR quotes in prose.
#[test]
fn the_worked_example_numbers_are_the_adrs() {
    let roster = Roster::from_canonical_bytes(&fixture("roster.json")).unwrap();
    let inputs: RoundInputs = serde_json::from_slice(&fixture("round.json")).unwrap();
    let selection = Selection::select(&roster, &inputs, &SelectionSecret::test_vector()).unwrap();
    assert_eq!(
        selection.seed.to_string(),
        "sha256:f6bb5ca427209de28c8cc1d75d74c75f9d5b2f090be21c14f64be1557790c7eb"
    );
    assert_eq!(
        selection.policy_digest.to_string(),
        "sha256:97d8d4903559f88cf8fd6ec52f2ceb24abfccdb9c788122c2348d69dc7b8f572"
    );
    // The `/`-joined display form, with the note that the HMAC message uses NUL.
    assert_eq!(
        selection.round_id,
        "gitiup-round-1/41/e3c05974bea30ff0c2ad3b9b8d4219b1d41a0c45a5e1c948c8455fdc4c304a74/\
         chg-000000000000f00d/sha1:e255b091aabd7e443b5d2fbeb90bc9769d07cbeb/build/matrix/linux-x86_64/0"
    );
    // And the worked example quoted in `derive` is the same one, as data.
    assert_eq!(
        gitiup_quorum::derive::WORKED_EXAMPLE.roster_digest,
        inputs.roster_digest.to_string()
    );
}

/// The handles the ADR lists for the five selected verifiers.
#[test]
fn the_selected_handles_match_the_adr_table() {
    let roster = Roster::from_canonical_bytes(&fixture("roster.json")).unwrap();
    let inputs: RoundInputs = serde_json::from_slice(&fixture("round.json")).unwrap();
    let selection = Selection::select(&roster, &inputs, &SelectionSecret::test_vector()).unwrap();
    // The ADR quotes the handles truncated to 16 hex characters; this checks the ADR's
    // prose and this build agree, which the full-document test cannot do on its own.
    let adr_quoted = [
        "3efb23dee98c0bfc",
        "ac5b5fdf0701cbed",
        "9f5f4092fc03330c",
        "4e8d1bdfe52aae41",
        "0398b5a3b5d47b32",
    ];
    let quoted: Vec<&str> = selection
        .selected
        .iter()
        .map(|seat| &seat.handle[..16])
        .collect();
    assert_eq!(
        quoted, adr_quoted,
        "handles are quoted in the ADR, so a change here is a new round kind, not an edit"
    );
    assert!(selection.sufficient);
    assert_eq!(selection.selected.len(), 5);
}

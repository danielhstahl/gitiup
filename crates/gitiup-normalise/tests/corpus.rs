//! The acceptance criterion for giti-1rs.3, as data.
//!
//! One workflow, one commit, one machine architecture, run twice on two machines.
//! Their logs disagree about every incidental thing a log can disagree about —
//! clock, durations, hostnames, uids, build roots, progress churn, locale, line
//! endings, listing order — and after normalisation the two runs have **one
//! `ResultDigest`**. Without normalisation they do not, which is what makes the
//! first assertion worth making: the corpus is not two copies of one file.
//!
//! The digests are pinned in `expected.json`, so a rule change that quietly moves a
//! digest fails here rather than in someone else's pipeline
//! ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::path::PathBuf;

use gitiup_attest::RunManifest;
use gitiup_attest::run::{Material, RawText, RunReport};
use gitiup_normalise::{Comparison, PROFILE_VERSION, compare_runs, manifest_for};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus")
}

fn report(machine: &str) -> RunReport {
    let path = corpus().join(machine).join("run.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{machine}: {e}"))
}

fn expected() -> serde_json::Value {
    let path = corpus().join("expected.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("expected.json: {e}"))
}

#[test]
fn the_corpus_declares_the_profile_it_is_checked_with() {
    for machine in ["machine-a", "machine-b"] {
        let report = report(machine);
        report
            .validate()
            .unwrap_or_else(|e| panic!("{machine}: {e}"));
        assert_eq!(
            report.provenance.normalisation_version, PROFILE_VERSION,
            "{machine}: the corpus is a v{PROFILE_VERSION} sample"
        );
        // The logs are in the clear, not pre-hashed: the point of the corpus is to
        // watch the profile rewrite them.
        assert!(
            report
                .steps
                .iter()
                .any(|step| matches!(step.stdout, Material::Text(_))),
            "{machine}: logs must be handed over as text"
        );
    }
}

#[test]
fn two_machines_of_one_arch_converge_on_one_result_digest() {
    let a = manifest_for(&report("machine-a")).expect("machine-a normalises");
    let b = manifest_for(&report("machine-b")).expect("machine-b normalises");
    let digest_a = a.manifest.result_digest().unwrap();
    let digest_b = b.manifest.result_digest().unwrap();
    assert_eq!(
        digest_a, digest_b,
        "independent reruns must converge on one digest"
    );
    assert_eq!(
        digest_a.to_string(),
        expected()["result_digest"].as_str().unwrap(),
        "the converged digest moved: a normalisation rule changed its output"
    );
    for machine in ["machine-a", "machine-b"] {
        assert_eq!(
            expected()["result_digests"][machine].as_str().unwrap(),
            digest_a.to_string()
        );
    }
}

#[test]
fn the_same_reports_renormalise_to_the_same_digest_every_time() {
    // The literal acceptance words: "the same workflow run twice on one machine
    // yields an identical digest". Determinism of the pipeline is a precondition for
    // the interesting claim above.
    for machine in ["machine-a", "machine-b"] {
        let report = report(machine);
        let first = manifest_for(&report).unwrap();
        let second = manifest_for(&report).unwrap();
        assert_eq!(first.manifest, second.manifest);
        assert_eq!(
            first.manifest.digest().unwrap(),
            second.manifest.digest().unwrap()
        );
        assert_eq!(first.diffs, second.diffs);
    }
}

#[test]
fn without_normalisation_the_same_two_runs_disagree() {
    // The counterfactual, pinned: if this test ever fails to fail, the corpus has
    // stopped exercising nondeterminism and the test above proves nothing.
    let mut digests = Vec::new();
    for machine in ["machine-a", "machine-b"] {
        let mut raw = report(machine);
        raw.provenance.normalisation_version = 0;
        raw.claims.timings.clear();
        for step in raw.steps.iter_mut() {
            step.timing = None;
        }
        // `RawText`, the version-0 profile: hash exactly what the runner wrote.
        let manifest = RunManifest::from_run_with(&raw, &RawText).expect("raw digest");
        digests.push(manifest.result_digest().unwrap().to_string());
    }
    assert_ne!(
        digests[0], digests[1],
        "the two machines' raw logs must differ, or the corpus is not a corpus"
    );
    assert_eq!(
        digests,
        expected()["naive_result_digests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        "the un-normalised digests moved too"
    );
}

#[test]
fn the_claims_still_differ_and_that_is_correct() {
    // Two runs are not the same *event*: different run ids, clocks and durations.
    // They must differ in the RunDigest (which signs the claims) and agree in the
    // ResultDigest (which is what a verifier compares) — ADR-0001 D4.
    let a = manifest_for(&report("machine-a")).unwrap();
    let b = manifest_for(&report("machine-b")).unwrap();
    assert_ne!(a.manifest.digest().unwrap(), b.manifest.digest().unwrap());
    assert_eq!(
        a.manifest.result_digest().unwrap(),
        b.manifest.result_digest().unwrap()
    );
    assert_ne!(a.manifest.claims.run_id, b.manifest.claims.run_id);
    assert_ne!(a.manifest.claims.timing, b.manifest.claims.timing);
}

#[test]
fn every_rewrite_is_recorded_in_the_manifest() {
    let report = report("machine-a");
    let run = manifest_for(&report).unwrap();
    assert!(
        !run.diffs.is_empty(),
        "machine A's log is full of volatile text; rewriting nothing would mean the profile stopped matching"
    );
    // The manifest carries exactly the record returned — sorted the way the format
    // mandates (by step, then kind), which is not the order they were produced in.
    let mut carried = run.manifest.claims.normalisation_diffs.clone();
    let mut returned = run.diffs.clone();
    carried.sort_by(|a, b| (&a.step, &a.kind).cmp(&(&b.step, &b.kind)));
    returned.sort_by(|a, b| (&a.step, &a.kind).cmp(&(&b.step, &b.kind)));
    assert_eq!(
        carried, returned,
        "the manifest must carry exactly the record returned"
    );
    let expected_kinds: Vec<String> = expected()["kinds"]["machine-a"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    let mut kinds: Vec<String> = run.diffs.iter().map(|diff| diff.kind.clone()).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds, expected_kinds, "the rewrite kinds moved");
    run.manifest.validate().expect("still valid");
    // And the record says what it did in terms a human can check.
    let duration = run
        .diffs
        .iter()
        .find(|diff| diff.kind == "duration")
        .expect("a duration rewrite");
    assert_eq!(duration.step, "build");
    assert!(duration.after.contains("<dur>"), "{duration:?}");
    assert!(duration.before.contains('s'), "{duration:?}");
}

#[test]
fn the_two_machines_agree_through_the_comparison_api_too() {
    let comparison: Comparison = compare_runs(&report("machine-a"), &report("machine-b")).unwrap();
    assert!(
        comparison.converged,
        "divergences: {:#?}",
        comparison.divergences
    );
    assert!(comparison.divergences.is_empty());
    assert_eq!(comparison.result_a, comparison.result_b);
}

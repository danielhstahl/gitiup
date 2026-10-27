//! The golden run fixtures: five representative workflows whose digests are
//! pinned.
//!
//! Where `tests/golden.rs` pins the *format* (canonical bytes, signatures, the
//! envelope), this pins the *computation* (giti-1rs.2): for each case, the run
//! report in `run.json` must compute to the digests recorded in `cases.json` and
//! to exactly the bytes in `manifest.json`. Those are the numbers a third party
//! recomputes after re-running a change, so they are the numbers that must not
//! move by accident.
//!
//! Regenerate with
//! `GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_run_fixtures`,
//! which is only ever appropriate with an ADR saying why
//! ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use gitiup_attest::run::RunReport;
use gitiup_attest::{RunManifest, Tier};
use serde_json::Value;

const EXPECTED_CASES: usize = 5;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runs")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn index() -> Value {
    let text = read(&fixtures_dir().join("cases.json"));
    serde_json::from_slice(&text).expect("cases.json must be valid JSON")
}

/// The reports, parsed the way `gitiup digest` parses them: ordinary lenient
/// JSON, because a report is a transport and not a signed document.
fn report_for(name: &str) -> RunReport {
    let bytes = read(&fixtures_dir().join(name).join("run.json"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn every_case_computes_its_recorded_digests() {
    let mut checked = 0usize;
    let mut run_digests = BTreeSet::new();
    for entry in index()["cases"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let report = report_for(name);
        report.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        let manifest = RunManifest::from_run(&report).unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(
            manifest.digest().unwrap().to_string(),
            entry["run_digest"].as_str().unwrap(),
            "{name}: the RunDigest moved"
        );
        assert_eq!(
            manifest.result_digest().unwrap().to_string(),
            entry["result_digest"].as_str().unwrap(),
            "{name}: the ResultDigest moved"
        );
        assert_eq!(
            manifest.result.provenance.tier.as_str(),
            entry["tier"].as_str().unwrap(),
            "{name}: tier"
        );
        assert_eq!(
            manifest.result.steps.len(),
            entry["steps"].as_u64().unwrap() as usize,
            "{name}: step count"
        );
        assert_eq!(
            manifest.result.provenance.normalisation_version,
            entry["normalisation_version"].as_u64().unwrap() as u32,
            "{name}: normalisation version"
        );
        assert!(
            run_digests.insert(manifest.digest().unwrap().to_string()),
            "{name}: two cases hash alike"
        );
        checked += 1;
    }
    assert_eq!(
        checked, EXPECTED_CASES,
        "five representative workflows are the acceptance criterion"
    );
}

#[test]
fn every_case_computes_the_committed_manifest_bytes() {
    // The manifest bytes are what gets signed and stored, so pinning them pins
    // the encoding of a computed manifest, not just its hash: field order, no
    // nulls, no floats, no whitespace.
    let dir = fixtures_dir();
    for entry in index()["cases"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let bytes = read(&dir.join(name).join("manifest.json"));
        assert!(
            !bytes.ends_with(b"\n"),
            "{name}: manifest.json must be the payload exactly, no trailing newline"
        );
        assert!(
            gitiup_attest::is_canonical(&bytes),
            "{name}: manifest.json is not canonical bytes"
        );
        let computed = RunManifest::from_run(&report_for(name))
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            computed, bytes,
            "{name}: the manifest computed from run.json is not the committed bytes"
        );
        // And reading the stored bytes back proves the same digests.
        let read_back = RunManifest::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            read_back.digest().unwrap().to_string(),
            entry["run_digest"].as_str().unwrap()
        );
        assert_eq!(
            read_back.result_digest().unwrap().to_string(),
            entry["result_digest"].as_str().unwrap()
        );
    }
}

#[test]
fn the_five_cases_cover_the_digest_recipe() {
    // Each case earns its place by exercising a different part of the recipe. If
    // one of these stops being true the fixture has drifted into duplicating
    // another, and the fifth slot is being wasted.
    let by_name = |name: &str| RunManifest::from_run(&report_for(name)).unwrap();

    let hello = by_name("hello");
    assert_eq!(hello.result.provenance.tier, Tier::Simulated);
    assert!(hello.result.pins.is_empty() && hello.result.secret_names.is_empty());
    assert!(
        hello.result.source.workflow.oid.algorithm() == gitiup_attest::OidAlgorithm::Sha256,
        "a workflow handed over as text is named by a content hash"
    );

    let matrix = by_name("matrix-build");
    assert_eq!(matrix.result.source.matrix.len(), 2);
    assert_eq!(matrix.result.pins.len(), 2);
    assert_eq!(matrix.result.secret_names.len(), 2);
    assert_eq!(matrix.result.reusable_workflows.len(), 2);
    assert!(!matrix.result.inputs.is_empty());
    assert!(
        matrix.result.steps.iter().any(|s| s.artifacts.len() == 1),
        "one step uploads a file-set artifact"
    );
    assert!(matrix.result.environment.image.is_some());
    assert_eq!(matrix.result.environment.toolchain.len(), 3);
    assert!(
        !matrix.claims.timing.is_empty(),
        "timings are claims, not result"
    );

    let image = by_name("image-build-skipped");
    assert!(
        image
            .result
            .steps
            .iter()
            .any(|s| s.outcome == gitiup_attest::StepOutcome::Skipped),
        "one case must show a step that did not run"
    );
    assert_eq!(image.result.environment.arch, "aarch64");
    assert!(
        image
            .result
            .steps
            .iter()
            .flat_map(|s| s.artifacts.iter())
            .any(|a| a.size_bytes == 74_200_013),
        "a pre-hashed artifact keeps its declared size"
    );

    let failing = by_name("test-failure");
    assert!(
        failing
            .result
            .steps
            .iter()
            .any(|s| s.outcome == gitiup_attest::StepOutcome::Failure && s.exit_code != 0),
        "a failing run is attested too"
    );
    assert!(
        failing.result.steps.iter().any(|s| s.stdout != s.stderr),
        "stderr is part of the digest, separately"
    );

    let release = by_name("dispatch-release");
    assert_eq!(
        release.result.source.commit.algorithm(),
        gitiup_attest::OidAlgorithm::Sha256,
        "one case binds a sha256-format repository"
    );
    assert_eq!(release.result.inputs.len(), 3);
    assert!(release.claims.verifier_challenge.is_some());
    assert!(!release.claims.normalisation_diffs.is_empty());
    assert!(release.claims.not_before_us.is_some() && release.claims.not_after_us.is_some());
    assert_eq!(
        release.result.source.event.action.as_deref(),
        Some("workflow_dispatch")
    );
}

#[test]
fn a_fixture_report_that_claims_quorum_is_refused() {
    // The cases are all one run's claim about itself, so none of them may say
    // `quorum`; the check that enforces it belongs to the report, not to policy.
    for entry in index()["cases"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let report = report_for(name);
        assert_ne!(
            report.provenance.tier,
            gitiup_attest::Tier::Quorum,
            "{name}: a single run may not claim quorum"
        );
    }
}

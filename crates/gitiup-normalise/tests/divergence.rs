//! Divergence reporting: a disagreement must arrive as a structured
//! [`NormalisationDiff`](gitiup_attest::NormalisationDiff), never as a bare hash
//! mismatch.
//!
//! Normalisation converges honest reruns; this file is about the runs that do not
//! converge, which is where a digest mismatch stops being an answer. The comparison
//! must say *which step*, *which field*, and *both sides* — and it must say it in
//! the one record the format already carries, so a dispute report (giti-msi.8) and
//! an attestation use the same type.

use std::path::PathBuf;

use gitiup_attest::run::{Material, RunReport};
use gitiup_normalise::{compare_runs, manifest_for};

fn report(machine: &str) -> RunReport {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/corpus")
        .join(machine)
        .join("run.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{machine}: {e}"))
}

/// Distinct `(step, kind)` pairs a comparison produced.
fn kinds(comparison: &gitiup_normalise::Comparison) -> Vec<(String, String)> {
    comparison
        .divergences
        .iter()
        .map(|diff| (diff.step.clone(), diff.kind.clone()))
        .collect()
}

#[test]
fn a_run_never_diverges_from_itself() {
    let report = report("machine-a");
    let comparison = compare_runs(&report, &report).unwrap();
    assert!(comparison.converged);
    assert!(comparison.divergences.is_empty());
}

#[test]
fn a_real_failure_surfaces_as_a_named_divergence_not_a_hash() {
    let a = report("machine-a");
    let mut b = report("machine-b");
    b.steps[2].stdout = Material::text(
        "test result: FAILED. 117 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.001s\n\
         ok coverage: 1234567 lines covered in 1,5 seconds\n\
         -rw-r--r--  1 ci ci 1536 Oct 27 09:15 README.md\n\
         drwxr-xr-x  4 ci ci 4096 Oct 27 09:14 target\n",
    );
    b.steps[2].exit_code = 101;

    let comparison = compare_runs(&a, &b).unwrap();
    assert!(!comparison.converged);
    let found = kinds(&comparison);
    assert!(
        found.contains(&("test".into(), "exit-code".into())),
        "the exit code is the loudest difference: {found:?}"
    );
    assert!(
        found.contains(&("test".into(), "outcome".into())),
        "and how the runner classified it: {found:?}"
    );
    assert!(
        found.contains(&("test".into(), "stdout".into())),
        "and the log line that caused it: {found:?}"
    );
    let stdout = comparison
        .divergences
        .iter()
        .find(|diff| diff.step == "test" && diff.kind == "stdout")
        .unwrap();
    assert!(
        stdout.before.contains("118 passed") && stdout.after.contains("117 passed"),
        "both sides are quoted, not summarised: {stdout:?}"
    );
    // The line number is in the text, because "somewhere in 900 lines" is not a
    // diagnosis.
    assert!(stdout.before.contains("line 1:"), "{stdout:?}");
}

#[test]
fn divergences_fit_the_manifest_field_they_are_for() {
    // `claims.normalisation_diffs` is keyed by (step, kind) and `normalize()` keeps
    // one per key, so a report that emitted two `stdout` diffs for one step would
    // silently lose one. Aggregation is what prevents that.
    let a = report("machine-a");
    let mut b = report("machine-b");
    b.steps[2].stdout = Material::text("completely\n不同\nlines\n");
    b.steps[1].stdout = Material::text("also different\n");
    let comparison = compare_runs(&a, &b).unwrap();
    let mut pairs = kinds(&comparison);
    pairs.sort();
    let mut unique = pairs.clone();
    unique.dedup();
    assert_eq!(
        pairs, unique,
        "one diff per (step, kind) or a manifest drops it"
    );

    let mut carrier = comparison.manifests.0.clone();
    carrier.claims.normalisation_diffs = comparison.divergences.clone();
    carrier.normalize();
    carrier
        .validate()
        .expect("a divergence report fits in the manifest field it is for");
    assert_eq!(
        carrier.claims.normalisation_diffs, comparison.divergences,
        "normalize() must not drop anything the aggregator produced"
    );
}

#[test]
fn every_kind_of_result_difference_is_named() {
    let a = report("machine-a");
    let mut b = report("machine-a");
    b.matrix = std::collections::BTreeMap::from([("os".to_string(), "ubuntu-22.04".into())]);
    b.inputs
        .insert("extra".to_string(), gitiup_attest::InputValue::Int(9));
    b.steps[3]
        .outputs
        .insert("size".to_string(), "9999".to_string());
    b.steps[3].artifacts.clear();
    b.steps.remove(0);
    b.pins.clear();

    let comparison = compare_runs(&a, &b).unwrap();
    let found = kinds(&comparison);
    for expected in [
        (
            gitiup_normalise::RUN_STEP.to_string(),
            "source:matrix".to_string(),
        ),
        (
            gitiup_normalise::RUN_STEP.to_string(),
            "input:extra".to_string(),
        ),
        (
            gitiup_normalise::RUN_STEP.to_string(),
            "pin:actions/checkout@v4".to_string(),
        ),
        ("package".to_string(), "output:size".to_string()),
        ("package".to_string(), "artifact:coverage".to_string()),
        ("checkout".to_string(), "step".to_string()),
    ] {
        assert!(
            found.contains(&expected),
            "expected {expected:?} among {found:?}"
        );
    }
}

#[test]
fn a_prehashed_stream_reports_the_digests_it_has() {
    // When a log arrived as a digest there is no text to diff, and the honest answer
    // is the pair of digests — not a claim that the streams are equal.
    let mut a = report("machine-a");
    for step in a.steps.iter_mut() {
        step.stdout = Material::digest(gitiup_attest::Digest::sha256(b"a"));
        step.stderr = Material::digest(gitiup_attest::Digest::sha256(b"b"));
        step.timing = None;
    }
    a.provenance.normalisation_version = 1;
    let mut b = a.clone();
    b.steps[0].stdout = Material::digest(gitiup_attest::Digest::sha256(b"c"));
    b.claims.run_id = "1111111111111111".into();

    let comparison = compare_runs(&a, &b).unwrap();
    assert!(!comparison.converged);
    let stdout = comparison
        .divergences
        .iter()
        .find(|diff| diff.step == "checkout" && diff.kind == "stdout:digest")
        .unwrap_or_else(|| panic!("{:?}", comparison.divergences));
    assert!(stdout.before.starts_with("sha256:"), "{stdout:?}");
    assert_ne!(stdout.before, stdout.after);
}

#[test]
fn normalisation_reaches_logs_and_nothing_else() {
    // Artifacts, event payloads and workflow sources are products and inputs, not
    // logs: they hash as handed over, and the contract owns their ordering.
    let a = manifest_for(&report("machine-a")).unwrap();
    let b = manifest_for(&report("machine-b")).unwrap();
    assert_eq!(
        a.manifest.result.steps[3].artifacts, b.manifest.result.steps[3].artifacts,
        "artifact digests come from the bytes, not from the log rules"
    );
    assert_eq!(
        a.manifest.result.source.event.payload,
        b.manifest.result.source.event.payload
    );
    assert_eq!(
        a.manifest.result.source.workflow.oid, b.manifest.result.source.workflow.oid,
        "a source identity is never rewritten"
    );
}

#[test]
fn manifest_for_and_the_digest_pipeline_agree() {
    // The CLI, the library and a runner must not have three ideas of what a run
    // hashes to.
    let report = report("machine-a");
    let via_profile = manifest_for(&report).unwrap();
    let declared = {
        let mut report = report.clone();
        report.provenance.normalisation_version = gitiup_normalise::Profile::standard().version();
        report
    };
    let via_pipeline = gitiup_attest::RunManifest::from_run_with(
        &declared,
        &gitiup_normalise::Profile::standard(),
    )
    .unwrap();
    assert_eq!(
        via_profile.manifest.result_digest().unwrap(),
        via_pipeline.result_digest().unwrap(),
        "the runner path and the pipeline path must hash a run the same way"
    );
    assert_eq!(
        via_profile.manifest.result, via_pipeline.result,
        "…including every byte of the result"
    );
}

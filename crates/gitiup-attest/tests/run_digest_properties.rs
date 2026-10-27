//! Properties of the run-digest computation (giti-1rs.2).
//!
//! The golden fixtures say "these digests"; these tests say *why* they can be
//! stable at all:
//!
//! 1. **Order independence.** Maps and lists in a report that have no meaning in
//!    order may arrive in any order — different key order in the JSON text,
//!    secrets listed last-first, toolchain inventory in whatever order the probe
//!    found it — and the digest is unchanged. Step order is the exception, and
//!    there is a test that it matters.
//! 2. **Whitespace independence.** A report is not encoded, so reformatting it is
//!    not re-encoding a signed document: indentation and key spacing are text, not
//!    bytes that anybody hashes. (Whitespace *inside* a log line is content, and
//!    giti-1rs.3 normalises that; it is not this test's claim.)
//! 3. **Idempotence.** Producing a manifest twice, encoding it twice, and reading
//!    back what was written all give one answer; a manifest is a fixed point of
//!    its own production steps.
//! 4. **No silent drops.** Every field of a report reaches the digest — and every
//!    claims-side field reaches `RunDigest` without reaching `ResultDigest`, which
//!    is the quorum's whole premise ([ADR-0001 D4](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::path::PathBuf;

use gitiup_attest::run::{ArtifactReport, Material, RunReport, TimingReport, WorkflowSource};
use gitiup_attest::{
    Digest, GitOid, ImageRef, InputValue, NormalisationDiff, OidAlgorithm, RunManifest,
    StepOutcome, Tier, ToolchainEntry,
};
use serde_json::Value;

// ----------------------------------------------------------------- input ---

fn fixture_names() -> Vec<String> {
    // From the index, not a hardcoded list: a new golden case is covered by the
    // properties automatically, which is the difference between a property test
    // and a list of examples.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runs/cases.json");
    let bytes = std::fs::read(&path).expect("cases.json must exist (see make_run_fixtures)");
    let index: serde_json::Value = serde_json::from_slice(&bytes).expect("cases.json parses");
    index["cases"]
        .as_array()
        .expect("cases is a list")
        .iter()
        .map(|case| case["name"].as_str().expect("a named case").to_string())
        .collect()
}

fn report(name: &str) -> RunReport {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runs")
        .join(name)
        .join("run.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn manifest_of(report: &RunReport) -> RunManifest {
    RunManifest::from_run(report).expect("a fixture report must compute")
}

/// Write a [`Value`] back out with a chosen key order and indentation.
///
/// `serde_json`'s map is sorted internally, so reordering a *parsed* report is a
/// no-op; this re-emits the text so the test really is about the bytes a producer
/// might hand over.
fn emit(value: &Value, reverse_keys: bool, indent: usize) -> String {
    let mut out = String::new();
    write(&mut out, value, reverse_keys, indent, 0);
    out
}

fn write(out: &mut String, value: &Value, reverse_keys: bool, indent: usize, depth: usize) {
    let newline_before = |out: &mut String, depth: usize| {
        if indent > 0 {
            out.push('\n');
            out.push_str(&" ".repeat(indent * depth));
        }
    };
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = map.keys().collect();
            if reverse_keys {
                keys.reverse();
            }
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_before(out, depth + 1);
                out.push_str(&serde_json::to_string(key).unwrap());
                out.push(':');
                if indent > 0 {
                    out.push(' ');
                }
                write(out, &map[*key], reverse_keys, indent, depth + 1);
            }
            newline_before(out, depth);
            out.push('}');
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_before(out, depth + 1);
                write(out, item, reverse_keys, indent, depth + 1);
            }
            newline_before(out, depth);
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Reverse every list in a report that has no meaningful order, leaving the step
/// order (which does) alone.
fn reverse_orderless_lists(value: &Value) -> Value {
    const REVERSED: [&[&str]; 5] = [
        &["secret_names"],
        &["reusable_workflows"],
        &["environment", "toolchain"],
        &["claims", "timings"],
        &["claims", "normalisation_diffs"],
    ];
    let mut out = value.clone();
    for path in REVERSED {
        reverse_array_at(&mut out, path);
    }
    // Artifacts within a step are a set; the steps themselves are a sequence.
    if let Some(Value::Array(steps)) = out.get_mut("steps") {
        for step in steps.iter_mut() {
            if let Value::Object(step) = step
                && let Some(Value::Array(artifacts)) = step.get_mut("artifacts")
            {
                artifacts.reverse();
            }
        }
    }
    out
}

fn reverse_array_at(value: &mut Value, path: &[&str]) {
    let mut target = value;
    for key in path {
        // Absent means empty: a fixture that lists no secrets has nothing to
        // reorder, which is exactly the case the property is about.
        let Value::Object(map) = target else { return };
        let Some(next) = map.get_mut(*key) else {
            return;
        };
        target = next;
    }
    if let Value::Array(items) = target {
        items.reverse();
    }
}

// ------------------------------------------------------- order, whitespace ---

#[test]
fn reordering_report_text_cannot_move_the_digest() {
    for name in &fixture_names() {
        let baseline = report(name);
        let value = serde_json::to_value(&baseline).unwrap();
        let want = manifest_of(&baseline).digest().unwrap();

        let ascending = emit(&value, false, 0);
        let reversed = emit(&value, true, 4);
        assert_ne!(ascending, reversed, "the two renderings must differ");
        assert!(
            reversed.lines().count() > 3,
            "the indented rendering must actually be laid out"
        );
        // The first key of a reversed object is the last of an ascending one:
        // proof the reordering happened in the text and not just in our heads.
        assert_ne!(
            ascending.split('"').nth(1).unwrap(),
            reversed.split('"').nth(1).unwrap()
        );

        for (label, text) in [("ascending", ascending), ("reversed", reversed)] {
            let reparsed: RunReport =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} {label}: {e}"));
            assert_eq!(
                manifest_of(&reparsed).digest().unwrap(),
                want,
                "{name}: {label} key order or indentation moved the digest"
            );
        }
    }
}

#[test]
fn reordering_report_lists_cannot_move_the_digest() {
    for name in &fixture_names() {
        let baseline = report(name);
        let want = manifest_of(&baseline).digest().unwrap();
        let reversed: RunReport = serde_json::from_value(reverse_orderless_lists(
            &serde_json::to_value(&baseline).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            manifest_of(&reversed).digest().unwrap(),
            want,
            "{name}: an orderless list moved the digest when reversed"
        );
        assert_eq!(
            manifest_of(&reversed).result_digest().unwrap(),
            manifest_of(&baseline).result_digest().unwrap()
        );
    }
}

#[test]
fn step_order_is_the_one_order_that_means_something() {
    // The counterweight to the tests above: `steps` is execution order, and a
    // run that ran the same steps the other way round is a different run.
    for name in &fixture_names() {
        let baseline = report(name);
        if baseline.steps.len() < 2 {
            continue;
        }
        let mut shuffled = baseline.clone();
        shuffled.steps.reverse();
        // Keep the ids unique-or-absent rule honest by dropping ids.
        for step in &mut shuffled.steps {
            step.id = None;
            step.timing = None;
        }
        shuffled.claims.timings.clear();
        let reversed = manifest_of(&shuffled);
        let straight = manifest_of(&baseline);
        assert_ne!(
            reversed.result_digest(),
            straight.result_digest(),
            "{name}: reversing the steps changed nothing, so step order is being lost"
        );
    }
}

#[test]
fn whitespace_inside_a_log_is_content_not_formatting() {
    // Said plainly, because it is the boundary the next ticket has to respect:
    // trailing whitespace in a log line is *data* until giti-1rs.3 normalises it.
    let baseline = report("test-failure");
    let mut padded = baseline.clone();
    padded.steps[1].stdout = Material::text("running 3 tests \ntest slow_one ... FAILED\n");
    assert_ne!(
        manifest_of(&padded).result_digest(),
        manifest_of(&baseline).result_digest()
    );
    // … and a normalisation profile is what would rewrite it, with its version
    // recorded so the two digests are never compared as if they were the same.
    struct Trim;
    impl gitiup_attest::run::Normaliser for Trim {
        fn version(&self) -> u32 {
            9
        }
        fn normalise(&self, text: &str) -> String {
            text.lines()
                .map(str::trim_end)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        }
    }
    let mut trimmed = baseline.clone();
    trimmed.provenance.normalisation_version = 9;
    let manifest = RunManifest::from_run_with(&trimmed, &Trim).unwrap();
    assert_eq!(manifest.result.provenance.normalisation_version, 9);
    assert_ne!(
        manifest.result_digest().unwrap(),
        manifest_of(&baseline).result_digest().unwrap()
    );
}

// ------------------------------------------------------------- idempotence ---

#[test]
fn producing_encoding_and_reading_back_are_all_idempotent() {
    for name in &fixture_names() {
        let baseline = report(name);
        let once = manifest_of(&baseline);

        // twice from the same report
        assert_eq!(once, manifest_of(&baseline), "{name}: from_run twice");
        // twice from the same manifest
        assert_eq!(
            once.encode().unwrap(),
            once.encode().unwrap(),
            "{name}: encode twice"
        );
        assert_eq!(
            once.digest().unwrap(),
            manifest_of(&baseline).digest().unwrap(),
            "{name}: digest twice"
        );
        // the canonical bytes are a fixed point: read them back and they re-encode
        let bytes = once.encode().unwrap();
        let read_back = RunManifest::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read_back, once);
        assert_eq!(read_back.encode().unwrap(), bytes);
        assert_eq!(
            read_back.result_digest().unwrap(),
            once.result_digest().unwrap()
        );
        // re-running the production steps changes nothing
        let mut remade = once.clone();
        remade.normalize();
        remade.result.environment.fix_fingerprint().unwrap();
        remade.validate().unwrap();
        assert_eq!(remade, once, "{name}: normalize is not idempotent");
    }
}

#[test]
fn volatile_claims_never_reach_the_result_digest() {
    // The quorum's premise, per fixture rather than in prose.
    for name in &fixture_names() {
        let baseline = report(name);
        let mut other = baseline.clone();
        other.claims.run_id = other.claims.run_id.chars().rev().collect();
        other.claims.claimed_at_us += 12_345;
        other.claims.not_before_us = Some(other.claims.claimed_at_us);
        other.claims.not_after_us = Some(other.claims.claimed_at_us + 60_000_000);
        other.claims.timings.push(TimingReport {
            step: "a-step-that-may-not-exist".into(),
            started_us: Some(other.claims.claimed_at_us),
            duration_us: Some(1),
        });
        other.claims.annotations.insert(
            "x_probe".to_string(),
            format!("{}-rerun", other.claims.run_id),
        );
        other.claims.normalisation_diffs.push(NormalisationDiff {
            step: "probe".into(),
            kind: "x_probe".into(),
            before: "before".into(),
            after: "after".into(),
        });
        let (a, b) = (manifest_of(&baseline), manifest_of(&other));
        assert_eq!(
            a.result_digest().unwrap(),
            b.result_digest().unwrap(),
            "{name}: a claims-only change moved the ResultDigest"
        );
        assert_ne!(
            a.digest().unwrap(),
            b.digest().unwrap(),
            "{name}: a claims-only change left the RunDigest alone"
        );
    }
}

// ---------------------------------------------------------- no silent drops ---

/// Which half of the manifest a field is allowed to reach.
#[derive(Debug, PartialEq, Eq)]
enum Reach {
    /// Part of `result`: moves both digests.
    Result,
    /// Part of `claims`: moves the RunDigest only.
    Claims,
}

/// The result of a mutation: the mutated report, and which digest it must move.
type Mutation = (&'static str, fn(&mut RunReport), Reach);

fn probe_oid() -> GitOid {
    GitOid::new(OidAlgorithm::Sha1, &[0x11; 20]).unwrap()
}

fn mutations() -> Vec<Mutation> {
    vec![
        (
            "repo",
            |r| r.repo = Some("someone-else/fork".into()),
            Reach::Result,
        ),
        ("commit", |r| r.commit = probe_oid(), Reach::Result),
        (
            "workflow.path",
            |r| r.workflow.path = ".github/workflows/other.yml".into(),
            Reach::Result,
        ),
        (
            "workflow.text",
            |r| {
                r.workflow = WorkflowSource::from_text(r.workflow.path.clone(), "name: other\n");
            },
            Reach::Result,
        ),
        (
            "workflow.oid",
            |r| {
                r.workflow = WorkflowSource::committed(r.workflow.path.clone(), probe_oid());
            },
            Reach::Result,
        ),
        (
            "event.name",
            |r| r.event.name = "schedule".into(),
            Reach::Result,
        ),
        (
            "event.action",
            |r| r.event.action = Some("reopened".into()),
            Reach::Result,
        ),
        (
            "event.payload",
            |r| r.event.payload = Material::text("{\"probe\":true}"),
            Reach::Result,
        ),
        (
            "event.payload digest form",
            |r| r.event.payload = Material::digest(Digest::sha256(b"probe")),
            Reach::Result,
        ),
        ("job", |r| r.job = Some("other-job".into()), Reach::Result),
        (
            "matrix",
            |r| {
                r.matrix.insert("probe".to_string(), "on".into());
            },
            Reach::Result,
        ),
        (
            "inputs",
            |r| {
                r.inputs.insert("probe".to_string(), InputValue::Int(7));
            },
            Reach::Result,
        ),
        (
            "inputs bool",
            |r| {
                r.inputs.insert("probe".to_string(), InputValue::Bool(true));
            },
            Reach::Result,
        ),
        (
            "secret_names",
            |r| r.secret_names.push("PROBE_SECRET".into()),
            Reach::Result,
        ),
        (
            "pins",
            |r| {
                r.pins.insert(
                    "probe/action@v1".to_string(),
                    gitiup_attest::ActionPin {
                        repo: "probe/action".into(),
                        commit: probe_oid(),
                        reference: Some("v1".into()),
                    },
                );
            },
            Reach::Result,
        ),
        (
            "pins existing",
            |r| match r.pins.values_mut().next() {
                Some(pin) => pin.commit = probe_oid(),
                None => {
                    r.pins.insert(
                        "probe/action@v1".to_string(),
                        gitiup_attest::ActionPin {
                            repo: "probe/action".into(),
                            commit: probe_oid(),
                            reference: None,
                        },
                    );
                }
            },
            Reach::Result,
        ),
        (
            "reusable_workflows",
            |r| {
                r.reusable_workflows.push(WorkflowSource::committed(
                    ".github/workflows/probe.yml",
                    probe_oid(),
                ));
            },
            Reach::Result,
        ),
        (
            "environment.provider",
            |r| r.environment.provider = Some("containerd".into()),
            Reach::Result,
        ),
        (
            "environment.os",
            |r| r.environment.os = Some("freebsd".into()),
            Reach::Result,
        ),
        (
            "environment.arch",
            |r| r.environment.arch = "riscv64gc".into(),
            Reach::Result,
        ),
        (
            "environment.image",
            |r| {
                r.environment.image = Some(ImageRef {
                    reference: Some("example/img:tag".into()),
                    digest: Digest::sha256(b"probe"),
                });
            },
            Reach::Result,
        ),
        (
            "environment.toolchain",
            |r| {
                r.environment.toolchain.push(ToolchainEntry {
                    name: "probe".into(),
                    version: "0".into(),
                });
            },
            Reach::Result,
        ),
        (
            "steps[].id",
            |r| {
                let last = r.steps.len() - 1;
                let old = r.steps[last].key();
                r.steps[last].id = Some("probe-step".into());
                r.claims.timings.retain(|t| t.step != old);
                for step in &mut r.steps {
                    if step.key() == "probe-step" {
                        step.timing = None;
                    }
                }
            },
            Reach::Result,
        ),
        (
            "steps[].name",
            |r| r.steps[0].name = "Probe step".into(),
            Reach::Result,
        ),
        (
            "steps[].uses",
            |r| r.steps[0].uses = Some("probe/action@v1".into()),
            Reach::Result,
        ),
        (
            "steps[].exit_code",
            |r| {
                let last = r.steps.len() - 1;
                // Flip it, so the mutation is never a no-op on a fixture that
                // already reported the value we were about to write.
                r.steps[last].exit_code = if r.steps[last].exit_code == 0 { 1 } else { 0 };
            },
            Reach::Result,
        ),
        (
            "steps[].outcome",
            |r| {
                // The first step always ran in every fixture, so making it skipped
                // is always a change.
                r.steps[0].outcome = Some(StepOutcome::Skipped);
                r.steps[0].exit_code = 0;
            },
            Reach::Result,
        ),
        (
            "steps[].stdout",
            |r| r.steps[0].stdout = Material::text("probe\n"),
            Reach::Result,
        ),
        (
            "steps[].stdout parts",
            |r| r.steps[0].stdout = Material::parts(["probe", "probe"]),
            Reach::Result,
        ),
        (
            "steps[].stderr",
            |r| r.steps[0].stderr = Material::text("probe on stderr\n"),
            Reach::Result,
        ),
        (
            "steps[].outputs",
            |r| {
                r.steps[0].outputs.insert("probe".to_string(), "on".into());
            },
            Reach::Result,
        ),
        (
            "steps[].artifacts",
            |r| {
                r.steps[0].artifacts.push(ArtifactReport {
                    name: "probe-artifact".into(),
                    content: Material::files([("probe.txt", Material::text("probe"))]),
                    size_bytes: None,
                });
            },
            Reach::Result,
        ),
        (
            "steps[].artifacts prehashed",
            |r| {
                r.steps[0].artifacts.push(ArtifactReport {
                    name: "probe-artifact".into(),
                    content: Material::digest(Digest::sha256(b"probe")),
                    size_bytes: Some(5),
                });
            },
            Reach::Result,
        ),
        (
            "steps[].timing",
            |r| {
                let last = r.steps.len() - 1;
                r.steps[last].timing = Some(gitiup_attest::StepTiming {
                    started_us: Some(r.claims.claimed_at_us),
                    duration_us: Some(1),
                });
            },
            Reach::Claims,
        ),
        (
            "provenance.tier",
            |r| {
                r.provenance.tier = if r.provenance.tier == Tier::Simulated {
                    Tier::Local
                } else {
                    Tier::Simulated
                }
            },
            Reach::Result,
        ),
        (
            "provenance.runner",
            |r| r.provenance.runner = "other-runner 9.9".into(),
            Reach::Result,
        ),
        (
            "provenance.sandbox",
            |r| r.provenance.sandbox = Some("probe-sandbox".into()),
            Reach::Result,
        ),
        (
            "claims.run_id",
            |r| r.claims.run_id = "f".repeat(16),
            Reach::Claims,
        ),
        (
            "claims.claimed_at_us",
            |r| r.claims.claimed_at_us += 7,
            Reach::Claims,
        ),
        (
            "claims.not_before_us",
            |r| r.claims.not_before_us = Some(r.claims.claimed_at_us),
            Reach::Claims,
        ),
        (
            "claims.not_after_us",
            |r| r.claims.not_after_us = Some(r.claims.claimed_at_us + 60_000_000),
            Reach::Claims,
        ),
        (
            "claims.verifier_challenge",
            |r| r.claims.verifier_challenge = Some(Digest::sha256(b"probe")),
            Reach::Claims,
        ),
        (
            "claims.timings",
            |r| {
                r.claims.timings.push(TimingReport {
                    step: "probe-step-timing".into(),
                    started_us: Some(r.claims.claimed_at_us),
                    duration_us: Some(3),
                });
            },
            Reach::Claims,
        ),
        (
            "claims.normalisation_diffs",
            |r| {
                r.claims.normalisation_diffs.push(NormalisationDiff {
                    step: "probe".into(),
                    kind: "x_probe".into(),
                    before: "b".into(),
                    after: "a".into(),
                });
            },
            Reach::Claims,
        ),
        (
            "claims.annotations",
            |r| {
                r.claims
                    .annotations
                    .insert("x_probe".to_string(), "on".into());
            },
            Reach::Claims,
        ),
    ]
}

#[test]
fn every_report_field_reaches_a_digest() {
    for name in &fixture_names() {
        let baseline = report(name);
        let straight = manifest_of(&baseline);
        for (what, mutate, reach) in mutations() {
            let mut mutated = baseline.clone();
            mutate(&mut mutated);
            let manifest = match RunManifest::from_run(&mutated) {
                Ok(manifest) => manifest,
                // A mutation this fixture cannot carry (a step that may not be
                // skipped, a normalisation version that no longer matches) is not
                // a silent drop; note it and move on rather than pretend it passed.
                Err(_) => continue,
            };
            assert_ne!(
                manifest.digest().unwrap(),
                straight.digest().unwrap(),
                "{name}: changing {what} did not move the RunDigest"
            );
            match reach {
                Reach::Result => assert_ne!(
                    manifest.result_digest().unwrap(),
                    straight.result_digest().unwrap(),
                    "{name}: changing {what} is a change to the run's outcome, so it must move the ResultDigest"
                ),
                Reach::Claims => assert_eq!(
                    manifest.result_digest().unwrap(),
                    straight.result_digest().unwrap(),
                    "{name}: changing {what} is claims-side and must not move the ResultDigest"
                ),
            }
        }
    }
}

#[test]
fn the_properties_run_over_the_golden_cases() {
    // If the index were read wrongly, or the fixtures directory emptied, every
    // property below would pass vacuously.
    let names = fixture_names();
    assert_eq!(
        names.len(),
        5,
        "five representative workflows are the acceptance criterion: {names:?}"
    );
    assert!(names.contains(&"matrix-build".to_string()));
}

#[test]
fn every_mutation_is_meaningful_somewhere() {
    // Guards the guard: `every_report_field_reaches_a_digest` skips mutations a
    // fixture cannot carry, so a mutation that every fixture refuses has rotted
    // into a test that tests nothing.
    let mutations = mutations();
    let mut refused_completely = Vec::new();
    for (what, mutate, _) in &mutations {
        let mut accepted = 0usize;
        for name in &fixture_names() {
            let mut mutated = report(name);
            mutate(&mut mutated);
            if RunManifest::from_run(&mutated).is_ok() {
                accepted += 1;
            }
        }
        if accepted == 0 {
            refused_completely.push(*what);
        }
    }
    assert!(
        refused_completely.is_empty(),
        "these mutations are refused by every fixture and so prove nothing: {refused_completely:?}"
    );
}

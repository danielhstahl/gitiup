//! Two runs of one workflow, compared — and the disagreement written down.
//!
//! This is the other half of the ticket. Normalisation makes honest reruns
//! converge; when they still do not, the answer must not be "the hashes differ".
//! A digest mismatch tells a verifier *that* something happened and nothing about
//! *what*, which is useless in a dispute and miserable to debug. [`compare_runs`]
//! says which step, which field, and the two sides — as
//! [`NormalisationDiff`](gitiup_attest::NormalisationDiff), the same structured
//! record normalisation produces, so a dispute report and an attestation carry one
//! format rather than two.
//!
//! What is compared is the **result**, not the claims: two honest runs never agree
//! about clocks, run ids or step durations, and ADR-0001 D4/D5 put those in
//! `claims` for exactly that reason. Comparing claims would report a disagreement
//! on every pair of runs ever taken.

use gitiup_attest::run::{Material, RunReport, StepReport};
use gitiup_attest::{Digest, NormalisationDiff, Result, RunManifest};

use crate::manifest::{NormalisedRun, manifest_for_with};
use crate::profile::Profile;
use crate::rewrite::{Divergences, Stream};

/// The step name used for divergences that are not about a step.
pub const RUN_STEP: &str = "<run>";

/// The line-diff window LCS is run over.
///
/// Bigger than this and the quadratic table is not worth it for a diagnostic: the
/// comparison falls back to positional pairing after trimming the common prefix
/// and suffix, which is bounded and still names the first differences.
const DIFF_WINDOW: usize = 512;

/// The result of comparing two runs.
#[derive(Debug, Clone)]
pub struct Comparison {
    /// True when the two runs' `ResultDigest`s are equal — the acceptance question.
    pub converged: bool,
    /// Run A's `ResultDigest`.
    pub result_a: Digest,
    /// Run B's `ResultDigest`.
    pub result_b: Digest,
    /// The two manifests, so a caller can sign either or look further.
    pub manifests: (RunManifest, RunManifest),
    /// What differed, aggregated to one per (step, kind). Empty when converged.
    pub divergences: Vec<NormalisationDiff>,
}

impl Comparison {
    /// The divergences as `(step, kind, before, after)` tuples, for printing.
    pub fn lines(&self) -> Vec<String> {
        self.divergences
            .iter()
            .map(|diff| {
                format!(
                    "{:<16} {:<24} - {}\n{:<16} {:<24} + {}",
                    diff.step, diff.kind, diff.before, "", "", diff.after
                )
            })
            .collect()
    }
}

/// Compare two runs of the same workflow with the standard profile.
pub fn compare_runs(a: &RunReport, b: &RunReport) -> Result<Comparison> {
    compare_runs_with(a, b, &Profile::standard())
}

/// Compare two runs of the same workflow.
///
/// Both reports are normalised and turned into manifests first, so the comparison
/// is over *normalised* logs: a divergence here survived normalisation, which is
/// exactly what a dispute needs to know.
pub fn compare_runs_with(a: &RunReport, b: &RunReport, profile: &Profile) -> Result<Comparison> {
    let a_run = manifest_for_with(a, profile)?;
    let b_run = manifest_for_with(b, profile)?;
    let result_a = a_run.manifest.result_digest()?;
    let result_b = b_run.manifest.result_digest()?;

    let mut run_level = Divergences::default();
    let mut steps: Vec<(String, Divergences)> = Vec::new();

    compare_source(&a_run, &b_run, &mut run_level);
    compare_steps(a, b, &a_run, &b_run, profile, &mut steps);

    let mut divergences = run_level.aggregate(RUN_STEP, "");
    for (step, log) in steps {
        divergences.extend(log.aggregate(&step, ""));
    }
    divergences.sort_by(|x, y| (&x.step, &x.kind).cmp(&(&y.step, &y.kind)));

    if !a_run.manifest.result.eq(&b_run.manifest.result) && divergences.is_empty() {
        // Should be unreachable: a result difference is a field difference, and
        // every field is compared above. Saying so beats reporting convergence.
        divergences.push(NormalisationDiff {
            step: RUN_STEP.to_string(),
            kind: "unclassified".into(),
            before: format!("{result_a}"),
            after: format!("{result_b}"),
        });
    }

    Ok(Comparison {
        converged: result_a == result_b,
        result_a: result_a.0.clone(),
        result_b: result_b.0.clone(),
        manifests: (a_run.manifest, b_run.manifest),
        divergences,
    })
}

/// Render a manifest value for a `before`/`after` field.
fn shown<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "«unprintable»".to_string())
}

fn compare_source(a: &NormalisedRun, b: &NormalisedRun, out: &mut Divergences) {
    let (a, b) = (&a.manifest.result, &b.manifest.result);
    if a.source.commit != b.source.commit {
        out.push(
            "source:commit",
            shown(&a.source.commit),
            shown(&b.source.commit),
        );
    }
    if a.source.workflow != b.source.workflow {
        out.push(
            "source:workflow",
            shown(&a.source.workflow),
            shown(&b.source.workflow),
        );
    }
    if a.source.event != b.source.event {
        out.push(
            "source:event",
            shown(&a.source.event),
            shown(&b.source.event),
        );
    }
    if a.source.job != b.source.job {
        out.push("source:job", shown(&a.source.job), shown(&b.source.job));
    }
    if a.source.matrix != b.source.matrix {
        out.push(
            "source:matrix",
            shown(&a.source.matrix),
            shown(&b.source.matrix),
        );
    }
    for (key, value) in &a.inputs {
        match b.inputs.get(key) {
            Some(other) if other == value => {}
            Some(other) => out.push(format!("input:{key}"), shown(value), shown(other)),
            None => out.push(format!("input:{key}"), shown(value), "(absent)"),
        }
    }
    for (key, value) in &b.inputs {
        if !a.inputs.contains_key(key) {
            out.push(format!("input:{key}"), "(absent)", shown(value));
        }
    }
    if a.secret_names != b.secret_names {
        out.push("secrets", shown(&a.secret_names), shown(&b.secret_names));
    }
    for (key, pin) in &a.pins {
        match b.pins.get(key) {
            Some(other) if other == pin => {}
            Some(other) => out.push(format!("pin:{key}"), shown(pin), shown(other)),
            None => out.push(format!("pin:{key}"), shown(pin), "(absent)"),
        }
    }
    for (key, pin) in &b.pins {
        if !a.pins.contains_key(key) {
            out.push(format!("pin:{key}"), "(absent)", shown(pin));
        }
    }
    if a.reusable_workflows != b.reusable_workflows {
        out.push(
            "closure",
            shown(&a.reusable_workflows),
            shown(&b.reusable_workflows),
        );
    }
    if a.environment != b.environment {
        out.push("environment", shown(&a.environment), shown(&b.environment));
    }
    if a.provenance != b.provenance {
        out.push("provenance", shown(&a.provenance), shown(&b.provenance));
    }
    if a.steps.len() != b.steps.len() {
        out.push(
            "steps",
            format!("{} steps", a.steps.len()),
            format!("{} steps", b.steps.len()),
        );
    }
}

/// Compare the steps of two runs, matched by step key.
fn compare_steps(
    report_a: &RunReport,
    report_b: &RunReport,
    a_run: &NormalisedRun,
    b_run: &NormalisedRun,
    profile: &Profile,
    out: &mut Vec<(String, Divergences)>,
) {
    let keys: Vec<String> = a_run
        .manifest
        .result
        .steps
        .iter()
        .map(|step| step.id.clone().unwrap_or_else(|| step.name.clone()))
        .collect();
    let a_steps: std::collections::BTreeMap<String, &StepReport> = report_a
        .steps
        .iter()
        .map(|step| (step.key(), step))
        .collect();
    let b_steps: std::collections::BTreeMap<String, &StepReport> = report_b
        .steps
        .iter()
        .map(|step| (step.key(), step))
        .collect();
    let b_keys: Vec<String> = b_run
        .manifest
        .result
        .steps
        .iter()
        .map(|step| step.id.clone().unwrap_or_else(|| step.name.clone()))
        .collect();

    let mut all = keys.clone();
    all.extend(b_keys.iter().cloned());
    all.sort();
    all.dedup();

    for key in all {
        let Some(step_a) = a_steps.get(&key) else {
            let mut log = Divergences::default();
            log.push("step", "(absent)", key.clone());
            out.push((key, log));
            continue;
        };
        let Some(step_b) = b_steps.get(&key) else {
            let mut log = Divergences::default();
            log.push("step", key.clone(), "(absent)");
            out.push((key, log));
            continue;
        };
        let index_a = keys
            .iter()
            .position(|k| *k == key)
            .and_then(|i| a_run.manifest.result.steps.get(i));
        let index_b = b_keys
            .iter()
            .position(|k| *k == key)
            .and_then(|i| b_run.manifest.result.steps.get(i));
        let (Some(step_manifest_a), Some(step_manifest_b)) = (index_a, index_b) else {
            // One side reported the step and the other did not; recorded above.
            let mut log = Divergences::default();
            log.push("step", key.clone(), key.clone());
            out.push((key, log));
            continue;
        };
        let mut log = Divergences::default();
        if step_manifest_a.exit_code != step_manifest_b.exit_code {
            log.push(
                "exit-code",
                step_manifest_a.exit_code.to_string(),
                step_manifest_b.exit_code.to_string(),
            );
        }
        if step_manifest_a.outcome != step_manifest_b.outcome {
            log.push(
                "outcome",
                shown(&step_manifest_a.outcome),
                shown(&step_manifest_b.outcome),
            );
        }
        if step_manifest_a.uses != step_manifest_b.uses {
            log.push(
                "uses",
                shown(&step_manifest_a.uses),
                shown(&step_manifest_b.uses),
            );
        }
        for (name, value) in &step_manifest_a.outputs {
            match step_manifest_b.outputs.get(name) {
                Some(other) if other == value => {}
                Some(other) => log.push(format!("output:{name}"), value.clone(), other.clone()),
                None => log.push(format!("output:{name}"), value.clone(), "(absent)"),
            }
        }
        for (name, value) in &step_manifest_b.outputs {
            if !step_manifest_a.outputs.contains_key(name) {
                log.push(format!("output:{name}"), "(absent)", value.clone());
            }
        }
        for artifact_a in &step_manifest_a.artifacts {
            match step_manifest_b
                .artifacts
                .iter()
                .find(|artifact| artifact.name == artifact_a.name)
            {
                Some(artifact_b) if artifact_a == artifact_b => {}
                Some(artifact_b) => log.push(
                    format!("artifact:{}", artifact_a.name),
                    shown(artifact_a),
                    shown(artifact_b),
                ),
                None => log.push(
                    format!("artifact:{}", artifact_a.name),
                    shown(artifact_a),
                    "(absent)",
                ),
            }
        }
        for artifact_b in &step_manifest_b.artifacts {
            if !step_manifest_a
                .artifacts
                .iter()
                .any(|artifact| artifact.name == artifact_b.name)
            {
                log.push(
                    format!("artifact:{}", artifact_b.name),
                    "(absent)",
                    shown(artifact_b),
                );
            }
        }
        for (material_a, material_b, stream) in [
            (&step_a.stdout, &step_b.stdout, Stream::Stdout),
            (&step_a.stderr, &step_b.stderr, Stream::Stderr),
        ] {
            let digest_a = manifest_digest(step_manifest_a, stream);
            let digest_b = manifest_digest(step_manifest_b, stream);
            if digest_a != digest_b {
                log_stream(&mut log, material_a, material_b, profile, stream);
            }
        }
        out.push((key, log));
    }
}

/// The digest recorded in the manifest for one stream.
fn manifest_digest(step: &gitiup_attest::manifest::Step, stream: Stream) -> Digest {
    match stream {
        Stream::Stdout => &step.stdout,
        Stream::Stderr => &step.stderr,
    }
    .clone()
}

/// Report a log-stream divergence.
///
/// When both sides handed over text, the normalised text is diffed line by line,
/// because that is what a human can act on. When either side arrived pre-hashed,
/// the digests are all there is, and saying so is better than pretending otherwise.
fn log_stream(
    log: &mut Divergences,
    a: &Material,
    b: &Material,
    profile: &Profile,
    stream: Stream,
) {
    let kind = stream.name();
    let side_a = side(a, profile);
    let side_b = side(b, profile);
    let (Text(text_a), Text(text_b)) = (side_a.clone(), side_b.clone()) else {
        log.push(
            format!("{kind}:digest"),
            side_a.describe(),
            side_b.describe(),
        );
        return;
    };
    let lines_a: Vec<String> = text_a.lines().map(str::to_string).collect();
    let lines_b: Vec<String> = text_b.lines().map(str::to_string).collect();
    for (index_a, index_b) in line_diff(&lines_a, &lines_b) {
        let before = index_a
            .map(|i| format!("line {}: {}", i + 1, lines_a[i]))
            .unwrap_or_else(|| "(line absent)".to_string());
        let after = index_b
            .map(|i| format!("line {}: {}", i + 1, lines_b[i]))
            .unwrap_or_else(|| "(line absent)".to_string());
        log.push(kind, before, after);
    }
}

/// One side of a log stream: text that can be diffed, or a description of what was
/// handed over instead of text.
#[derive(Debug, Clone)]
enum Side {
    /// Normalised text, diffable line by line.
    Text(String),
    /// A digest (or a file set): describable, not diffable.
    Opaque(String),
}

use Side::{Opaque, Text};

impl Side {
    fn describe(&self) -> String {
        match self {
            Text(text) => format!("{} bytes of text", text.len()),
            Opaque(what) => what.clone(),
        }
    }
}

/// A stream as text, if it ever was text: normalising what was handed over in the
/// clear, and declining to guess at a digest.
fn side(material: &Material, profile: &Profile) -> Side {
    match material {
        Material::Text(text) => Text(profile.normalise(text)),
        Material::Parts(parts) => Text(
            parts
                .iter()
                .map(|part| profile.normalise(part))
                .collect::<Vec<_>>()
                .join(""),
        ),
        Material::Digest(digest) => Opaque(digest.to_string()),
        Material::Files(files) => Opaque(format!("{} files", files.len())),
    }
}

/// Pair up differing lines: `(Some(index in A), Some(index in B))`, with `None`
/// for an insertion or a deletion.
fn line_diff(a: &[String], b: &[String]) -> Vec<(Option<usize>, Option<usize>)> {
    let mut start = 0usize;
    while start < a.len() && start < b.len() && a[start] == b[start] {
        start += 1;
    }
    let mut end_a = a.len();
    let mut end_b = b.len();
    while end_a > start && end_b > start && a[end_a - 1] == b[end_b - 1] {
        end_a -= 1;
        end_b -= 1;
    }
    let window_a = &a[start..end_a];
    let window_b = &b[start..end_b];
    if window_a.is_empty() && window_b.is_empty() {
        return Vec::new();
    }
    if window_a.len() > DIFF_WINDOW || window_b.len() > DIFF_WINDOW {
        // Too big for the table: pair positionally and stop at the first handful.
        let pairs = window_a
            .iter()
            .enumerate()
            .map(|(i, _)| (Some(start + i), None))
            .chain(
                window_b
                    .iter()
                    .enumerate()
                    .map(|(i, _)| (None, Some(start + i))),
            )
            .take(64)
            .collect();
        return pairs;
    }
    lcs_pairs(window_a, window_b, start)
}

/// A longest-common-subsequence walk over a small window.
fn lcs_pairs(a: &[String], b: &[String], offset: usize) -> Vec<(Option<usize>, Option<usize>)> {
    let rows = a.len() + 1;
    let columns = b.len() + 1;
    let mut table = vec![0u32; rows * columns];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i * columns + j] = if a[i] == b[j] {
                table[(i + 1) * columns + j + 1] + 1
            } else {
                table[(i + 1) * columns + j].max(table[i * columns + j + 1])
            };
        }
    }
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if table[(i + 1) * columns + j] >= table[i * columns + j + 1] {
            pairs.push((Some(offset + i), None));
            i += 1;
        } else {
            pairs.push((None, Some(offset + j)));
            j += 1;
        }
    }
    pairs.extend((i..a.len()).map(|i| (Some(offset + i), None)));
    pairs.extend((j..b.len()).map(|j| (None, Some(offset + j))));
    pairs
}

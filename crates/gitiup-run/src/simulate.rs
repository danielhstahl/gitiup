//! The simulated run: an honest attestation of something that did not happen.
//!
//! This is the default path of `gitiup run`, and the reason the ticket exists. It
//! takes a [`Plan`], and produces a [`RunReport`] whose provenance is
//! `tier: simulated, sandbox: none` — a signed statement of *what a run would do*,
//! with nothing hidden about the fact that it did not do it.
//!
//! # What this module guarantees, and how that is checked
//!
//! * **No process is spawned.** Nothing here imports anything that can.
//! * **No secret is read.** `RunReport::secret_names` is empty and stays empty;
//!   there is no field to put a name in, so a caller cannot even ask.
//! * **Nothing is written.** The report is returned; writing it is the CLI's
//!   decision, made against a path the user named.
//! * **No clock reads beyond one.** `claimed_at_us` is the only volatile timestamp,
//!   and it is a claim in `claims`, never in the digest-bearing `result`.
//! * **It is reproducible.** Given the same workflow bytes, commit, matrix arm and
//!   inputs — and a pinned `--run-id` — the same plan hashes to the same digest on
//!   another machine. That is what makes a plan worth attesting to at all.
//!
//! `tests/no_side_effects.rs` turns the first three into a build failure if they
//! ever stop being true, and `tests/simulate.rs` checks the properties from the
//! producing side.
//!
//! # Why a plan is worth signing
//!
//! A simulated attestation answers "what would this change's CI do, and what would
//! it claim?" That is real information: it pins the workflow bytes, the commit, the
//! matrix, the action refs as written, and the input set — so a reviewer can see
//! that a change adds a step, changes a pin, or newly reaches for a secret *before*
//! anything executes. What it must never do is satisfy a gate that wants execution,
//! which is why the tier defaults to refusal in [`gitiup_attest::Policy`] and why
//! every consumer prints [`gitiup_attest::Tier::trust_warning`] when it is used.

use std::collections::BTreeMap;

use gitiup_attest::run::{
    ArtifactReport, ClaimReport, EnvironmentReport, EventReport, Material, StepReport,
    WorkflowSource,
};
use gitiup_attest::{
    Digest, Error, ErrorKind, GitOid, InputValue, NO_SANDBOX, Provenance, ResultDigest, RunReport,
    StepOutcome, Tier, TimeUs,
};

use crate::plan::{Plan, PlannedJob};

/// The `environment.provider` of a simulated run.
///
/// Named in the format's vocabulary of providers, so a verifier that filters on
/// provider sees the same word the tier says.
pub const SIMULATED_PROVIDER: &str = "simulated";

/// Everything a simulation needs that the plan does not already know.
///
/// Built by the CLI from flags; the fields are the ones an attestation binds, so
/// there is no way to leave a binding out by accident.
#[derive(Debug, Clone)]
pub struct Simulation<'a> {
    /// The commit the plan is bound to.
    pub commit: GitOid,
    /// The workflow file, as text or as a committed object id.
    pub workflow: WorkflowSource,
    /// The event being simulated (`push`, `pull_request`, …).
    pub event: String,
    /// Event action (`opened`, `synchronize`, …).
    pub event_action: Option<String>,
    /// Repository identity, trusted for nothing, recorded for humans.
    pub repo: Option<String>,
    /// Job inputs, by value.
    pub inputs: Vec<(String, InputValue)>,
    /// Event payload text; defaults to a small JSON object naming the event and
    /// the inputs, so the payload digest pins *something* real.
    pub payload: Option<String>,
    /// `claims.run_id`; derived from the plan when absent, so two runs of the same
    /// plan on the same clock agree, and `--run-id` pins it exactly.
    pub run_id: Option<String>,
    /// The clock. `None` means now.
    pub now_us: Option<i64>,
    /// Outputs replayed from an earlier run, if any.
    pub replay: Option<Replay>,
    /// Matrix vector of the arm being simulated (checked against the plan).
    pub matrix: BTreeMap<String, String>,
    /// Extra `claims.annotations` (`x_*` by convention).
    pub annotations: BTreeMap<String, String>,
    /// The runner string recorded in provenance, e.g. `gitiup 0.1.0`.
    pub runner: &'a str,
}

impl<'a> Simulation<'a> {
    /// The smallest honest simulation: `runner` on `commit`, running `workflow`.
    pub fn new(commit: GitOid, workflow: WorkflowSource, runner: &'a str) -> Simulation<'a> {
        Simulation {
            commit,
            workflow,
            event: "push".into(),
            event_action: None,
            repo: None,
            inputs: Vec::new(),
            payload: None,
            run_id: None,
            now_us: None,
            replay: None,
            matrix: BTreeMap::new(),
            annotations: BTreeMap::new(),
            runner,
        }
    }
}

/// Outputs replayed from an earlier run report.
///
/// The ticket's "describes/**replays**": a simulated run either describes what a
/// step would do, or replays what a *recorded* run said it did. Replaying is not
/// pretending: the source report is pinned by digest in the annotations, and the
/// tier still says `simulated`, so the digest changes and nothing about the
/// attestation claims more than it knows.
#[derive(Debug, Clone, Default)]
pub struct Replay {
    /// `sha256` of the report file the outputs came from.
    pub source: Option<Digest>,
    /// The source run's id, for the human reading the log.
    pub source_run_id: Option<String>,
    /// Per step key: the recorded step.
    steps: BTreeMap<String, RecordedStep>,
}

/// One recorded step, reduced to what a rerun may reuse.
#[derive(Debug, Clone)]
struct RecordedStep {
    stdout: Material,
    stderr: Material,
    exit_code: i64,
    outcome: StepOutcome,
    outputs: BTreeMap<String, String>,
    artifacts: Vec<ArtifactReport>,
}

impl Replay {
    /// An empty replay: every step falls back to describing itself.
    pub fn empty() -> Replay {
        Replay::default()
    }

    /// Take the step outputs of an earlier run report.
    ///
    /// Secrets are *not* carried over: names are not outputs, and the earlier run's
    /// environment is not this one's.
    pub fn from_report(report: &RunReport, source: Option<Digest>) -> Result<Replay, Error> {
        let mut replay = Replay {
            source,
            source_run_id: Some(report.claims.run_id.clone()),
            steps: BTreeMap::new(),
        };
        for step in &report.steps {
            replay.steps.insert(
                step.key(),
                RecordedStep {
                    stdout: step.stdout.clone(),
                    stderr: step.stderr.clone(),
                    exit_code: step.exit_code,
                    outcome: step.outcome.unwrap_or(if step.exit_code == 0 {
                        StepOutcome::Success
                    } else {
                        StepOutcome::Failure
                    }),
                    outputs: step.outputs.clone(),
                    artifacts: step.artifacts.clone(),
                },
            );
        }
        Ok(replay)
    }

    /// How many steps this replay can serve.
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

/// Build the run report of a simulated run: one planned job, one attestation.
///
/// `job` must come from `plan` (its identity is checked, not assumed): a report
/// that names a different job than the plan describes would be a plan for one run
/// attesting to another.
pub fn report(plan: &Plan, job: &PlannedJob, sim: &Simulation<'_>) -> Result<RunReport, Error> {
    if !plan
        .jobs
        .iter()
        .any(|planned| planned.id == job.id && planned.matrix == job.matrix)
    {
        return Err(Error::new(
            ErrorKind::Policy,
            "simulate",
            format!(
                "job `{}`{} is not part of this plan",
                job.id,
                if job.matrix.is_empty() {
                    String::new()
                } else {
                    format!(" arm {}", job.arm_text())
                }
            ),
        )
        .with_hint("take the job from the plan that is being simulated"));
    }

    let now_us = sim.now_us.unwrap_or_else(|| TimeUs::now().0);
    let run_id = match (&sim.run_id, sim.now_us) {
        (Some(id), _) => id.clone(),
        // Derived, not random: two simulations of one plan on one clock agree, and
        // `--run-id` pins it when byte-for-byte agreement across machines matters.
        (None, _) => derived_run_id(plan, job, sim, now_us),
    };

    let mut steps = Vec::with_capacity(job.steps.len());
    let mut replayed: Vec<String> = Vec::new();
    let mut assumptions: Vec<String> = job.assumptions.clone();
    for step in &job.steps {
        let key = step.key();
        let recorded = sim
            .replay
            .as_ref()
            .and_then(|replay| replay.steps.get(&key));
        let description = step.describe();
        match recorded {
            Some(recorded) => {
                replayed.push(key.clone());
                steps.push(StepReport {
                    id: step.id.clone(),
                    name: step.name.clone(),
                    uses: step.uses.clone(),
                    exit_code: recorded.exit_code,
                    outcome: Some(recorded.outcome),
                    stdout: recorded.stdout.clone(),
                    stderr: recorded.stderr.clone(),
                    outputs: recorded.outputs.clone(),
                    artifacts: recorded.artifacts.clone(),
                    timing: None,
                });
            }
            None => {
                steps.push(StepReport {
                    id: step.id.clone(),
                    name: step.name.clone(),
                    uses: step.uses.clone(),
                    exit_code: 0,
                    outcome: Some(StepOutcome::Success),
                    stdout: Material::text(description),
                    stderr: Material::text(String::new()),
                    outputs: BTreeMap::new(),
                    artifacts: Vec::new(),
                    timing: None,
                });
                assumptions.push(format!(
                    "step {} '{}' was assumed to succeed (exit 0)",
                    step.index, step.name
                ));
            }
        }
    }

    let mut annotations = sim.annotations.clone();
    annotations.insert("x_run_mode".into(), "simulated".into());
    if !assumptions.is_empty() {
        annotations.insert("x_assumptions".into(), assumptions.join("; "));
    }
    if let Some(replay) = &sim.replay {
        if let Some(source) = &replay.source {
            annotations.insert("x_replay_from".into(), source.to_string());
        }
        if !replayed.is_empty() {
            annotations.insert("x_replayed_steps".into(), replayed.join(","));
        }
    }
    for warning in &plan.warnings {
        // The plan's caveats travel with the attestation, not just with the
        // terminal they were printed on.
        annotations
            .entry("x_plan_notes".into())
            .and_modify(|existing| existing.push_str(" · "))
            .or_insert_with(|| warning.clone());
    }

    let payload = sim.payload.clone().unwrap_or_else(|| payload_text(sim));
    Ok(RunReport {
        repo: sim.repo.clone(),
        commit: sim.commit.clone(),
        workflow: sim.workflow.clone(),
        event: EventReport {
            name: sim.event.clone(),
            action: sim.event_action.clone(),
            payload: Material::text(payload),
        },
        job: Some(job.id.clone()),
        matrix: job.matrix.clone(),
        inputs: sim.inputs.iter().cloned().collect(),
        // No secrets, and not a name of one either: a plan touches none.
        secret_names: Vec::new(),
        pins: BTreeMap::new(),
        reusable_workflows: Vec::new(),
        environment: simulated_environment(job),
        steps,
        provenance: Provenance {
            tier: Tier::Simulated,
            runner: sim.runner.to_string(),
            // Raw text, rewritten by nothing: the description above is the text,
            // and it contains nothing machine-specific to rewrite.
            normalisation_version: 0,
            sandbox: Some(NO_SANDBOX.into()),
        },
        claims: ClaimReport {
            run_id,
            claimed_at_us: now_us,
            not_before_us: None,
            not_after_us: None,
            verifier_challenge: None,
            timings: Vec::new(),
            normalisation_diffs: Vec::new(),
            annotations,
        },
    })
}

/// The digest a report's `result` would carry, computed the one sanctioned way
/// ([`crate::manifest_for`]), so `gitiup run --json` prints exactly what a verifier
/// will later recompute.
pub fn result_digest(report: &RunReport) -> Result<ResultDigest, Error> {
    crate::manifest_for(report)?.result_digest()
}

/// The environment a plan claims: a machine *class*, and labelled as such.
///
/// A simulated run has not booted anything, so the environment is read off the
/// workflow's own `runs-on` (`ubuntu-24.04` ⇒ `linux`) with this host's
/// architecture, and `provider: simulated`. No image digest is claimed: resolving a
/// tag to a digest is a network operation, and a plan that faked one would be
/// inventing the most load-bearing field in the manifest.
fn simulated_environment(job: &PlannedJob) -> EnvironmentReport {
    EnvironmentReport {
        provider: Some(SIMULATED_PROVIDER.into()),
        os: os_from_runs_on(job.runs_on.as_deref()),
        os_version: None,
        arch: std::env::consts::ARCH.to_string(),
        image: None,
        toolchain: Vec::new(),
    }
}

/// The runner's own guess at the OS a `runs-on` label means.
///
/// Only the shapes GitHub's hosted runners use; anything else is left unsaid rather
/// than invented.
fn os_from_runs_on(label: Option<&str>) -> Option<String> {
    let label = label?.to_ascii_lowercase();
    for (needle, os) in [
        ("ubuntu", "linux"),
        ("debian", "linux"),
        ("macos", "macos"),
        ("macos-", "macos"),
        ("windows", "windows"),
    ] {
        if label.starts_with(needle) {
            return Some(os.into());
        }
    }
    None
}

/// A small, deterministic event payload: enough that the payload digest pins a real
/// event description instead of an empty object.
fn payload_text(sim: &Simulation<'_>) -> String {
    let inputs: Vec<String> = sim
        .inputs
        .iter()
        .map(|(name, value)| format!("\"{name}\":{}", json_value(value)))
        .collect();
    let mut fields = vec![format!("\"name\":\"{}\"", sim.event)];
    if let Some(action) = &sim.event_action {
        fields.push(format!("\"action\":\"{action}\""));
    }
    if !inputs.is_empty() {
        fields.push(format!("\"inputs\":{{{}}}", inputs.join(",")));
    }
    format!("{{{}}}", fields.join(","))
}

fn json_value(value: &InputValue) -> String {
    match value {
        InputValue::Text(text) => format!("\"{text}\""),
        InputValue::Int(number) => number.to_string(),
        InputValue::Bool(flag) => flag.to_string(),
    }
}

/// A run id that follows from the plan: same plan, same clock tick, same id.
fn derived_run_id(plan: &Plan, job: &PlannedJob, sim: &Simulation<'_>, now_us: i64) -> String {
    let mut parts: Vec<String> = vec![
        "simulated".into(),
        plan.workflow_path.clone(),
        sim.commit.to_string(),
        job.id.clone(),
        job.matrix
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",")
            .to_string(),
        now_us.to_string(),
    ];
    parts.extend(
        sim.inputs
            .iter()
            .map(|(name, value)| format!("{name}={value:?}")),
    );
    let bytes: Vec<&[u8]> = parts.iter().map(String::as_bytes).collect();
    let digest = Digest::sha256_parts(&bytes);
    digest.hex()[..16].to_string()
}

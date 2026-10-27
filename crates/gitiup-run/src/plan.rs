//! The plan: what a run *would* do, expanded and described.
//!
//! [`Plan`] sits between the workflow file ([`crate::Workflow`]) and the attestation
//! ([`crate::simulate`]) and holds the two things both sides need to agree on: the
//! matrix expansion (one attestation per arm, exactly as a runner would produce)
//! and the per-step description that is a simulated step's stdout.
//!
//! The description is written to be *read* and to be *stable*. It names the job,
//! the arm, the step, the action or script and the inputs, and nothing else: no
//! clock, no hostname, no temp path. Two people planning the same commit on
//! different machines therefore get byte-identical digests, which is the whole
//! point — a plan you cannot reproduce is a rumour.
//!
//! ```
//! use gitiup_run::{Plan, Selector, Workflow};
//!
//! let wf = Workflow::parse(
//!     "ci.yml",
//!     "on: push\njobs:\n  build:\n    steps:\n      - run: make\n",
//! )
//! .unwrap();
//! let plan = Plan::build(&wf, &Selector::default()).unwrap();
//! assert_eq!(plan.jobs.len(), 1);
//! let text = plan.describe();
//! assert!(text.contains("gitiup run plan"), "{text}");
//! assert!(text.contains("make"), "{text}");
//! ```

use std::collections::BTreeMap;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::workflow::{Job, Step, Workflow};

/// Largest number of matrix arms one job may expand to.
///
/// Real matrices are tens, not thousands; the cap turns a mistaken cartesian
/// product into an error instead of a plan that prints for an hour.
pub const MAX_MATRIX_ARMS: usize = 256;

/// What to include from the workflow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    /// Plan only this job. Required when the workflow has several, because an
    /// attestation is about one run of one job.
    pub job: Option<String>,
    /// Restrict a matrix axis (`os=ubuntu-24.04`).
    pub matrix: BTreeMap<String, String>,
}

/// One planned run: a job, one matrix arm of it, and its steps in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedJob {
    /// `jobs.<id>`.
    pub id: String,
    /// The job's `name:` if it has one.
    pub name: Option<String>,
    /// The `runs-on:` label, as written.
    pub runs_on: Option<String>,
    /// This arm's matrix vector; empty when the job has no matrix.
    pub matrix: BTreeMap<String, String>,
    /// Job-level `env:`, as written. Part of the plan text, because "what would the
    /// step have seen" is part of what the plan is claiming.
    pub env: Vec<(String, String)>,
    /// `services:` the job declares. The planner runs none of them: a plan says the
    /// database is assumed to be there, and `--execute` refuses rather than running a
    /// job alone.
    pub services: Vec<String>,
    /// The step conditions that were *not* evaluated, as `step: expr` notes. The
    /// plan assumes those steps run, and says so in the attestation.
    pub assumptions: Vec<String>,
    /// The steps, in execution order.
    pub steps: Vec<PlannedStep>,
}

/// One planned step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// 1-based position in the job.
    pub index: usize,
    /// `id:`.
    pub id: Option<String>,
    /// The name a human would read.
    pub name: String,
    /// `uses:` as written, unresolved.
    pub uses: Option<String>,
    /// `run:` body.
    pub run: Option<String>,
    /// `with:` inputs.
    pub inputs: Vec<(String, String)>,
    /// `if:`, unevaluated.
    pub condition: Option<String>,
    /// `shell:`, as written; `exec` runs `sh` scripts and refuses anything else.
    pub shell: Option<String>,
    /// Step-level `env:`, as written.
    pub env: Vec<(String, String)>,
}

impl Plan {
    /// Expand the workflow's jobs into the runs a runner would have created.
    pub fn build(workflow: &Workflow, selector: &Selector) -> Result<Plan> {
        let mut warnings = workflow.warnings.clone();
        let selected: Vec<&Job> = match &selector.job {
            Some(wanted) => {
                let found = workflow
                    .jobs
                    .iter()
                    .filter(|job| &job.id == wanted)
                    .collect::<Vec<_>>();
                if found.len() != 1 {
                    return Err(Error::new(
                        ErrorKind::Policy,
                        "plan",
                        format!(
                            "no job `{wanted}`; this workflow has {}",
                            workflow
                                .jobs
                                .iter()
                                .map(|job| job.id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                    .with_hint("name one job with --job"));
                }
                found
            }
            None if workflow.jobs.len() == 1 => workflow.jobs.iter().collect(),
            None => {
                return Err(Error::new(
                    ErrorKind::Policy,
                    "plan",
                    format!(
                        "this workflow has {} jobs, and an attestation is about one run: {}",
                        workflow.jobs.len(),
                        workflow
                            .jobs
                            .iter()
                            .map(|job| job.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
                .with_hint("choose with --job <id> (a run is one job on one matrix arm)"));
            }
        };

        let mut jobs = Vec::new();
        for job in selected {
            for matrix in expand(job, selector)? {
                jobs.push(PlannedJob::of(job, matrix, &mut warnings));
            }
        }
        let assumptions: usize = jobs.iter().map(|job| job.assumptions.len()).sum();
        if assumptions > 0 {
            warnings.push(format!(
                "{assumptions} conditional step(s) were assumed to run: expressions are not evaluated when planning"
            ));
        }
        if jobs.iter().any(|job| !job.steps.is_empty()) {
            warnings.push(
                "a simulated run executes nothing: exit codes below are assumed, never measured"
                    .to_string(),
            );
        }
        Ok(Plan {
            workflow_path: workflow.path.clone(),
            workflow_name: workflow.name.clone(),
            triggers: workflow.triggers.clone(),
            jobs,
            warnings,
        })
    }

    /// Human-readable plan text: what would run, in what order, and what was
    /// assumed about it.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str("gitiup run plan\n");
        out.push_str(&format!("  workflow   {}\n", self.workflow_path));
        if let Some(name) = &self.workflow_name {
            out.push_str(&format!("  name       {name}\n"));
        }
        out.push_str(&format!("  triggers   {}\n", self.triggers.join(", ")));
        out.push_str(&format!("  runs       {}\n", self.jobs.len()));
        for job in &self.jobs {
            out.push('\n');
            out.push_str(&format!("  job {}{}\n", job.id, job.arm_text()));
            if let Some(runs_on) = &job.runs_on {
                out.push_str(&format!("    runs-on    {runs_on}\n"));
            }
            for (key, value) in &job.matrix {
                out.push_str(&format!("    matrix     {key} = {value}\n"));
            }
            if !job.services.is_empty() {
                out.push_str(&format!(
                    "    services    {} (none of them started by a plan)\n",
                    job.services.join(", ")
                ));
            }
            for (key, value) in &job.env {
                out.push_str(&format!("    env         {key} = {value}\n"));
            }
            for assumption in &job.assumptions {
                out.push_str(&format!("    assumed     {assumption}\n"));
            }
            for step in &job.steps {
                out.push_str(&step.describe());
            }
        }
        if !self.warnings.is_empty() {
            out.push('\n');
            for warning in &self.warnings {
                out.push_str(&format!("  note       {warning}\n"));
            }
        }
        out
    }

    /// Total planned steps across every planned run.
    pub fn step_count(&self) -> usize {
        self.jobs.iter().map(|job| job.steps.len()).sum()
    }
}

/// A workflow expanded into the runs it would produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Where the workflow came from.
    pub workflow_path: String,
    /// `name:`.
    pub workflow_name: Option<String>,
    /// Trigger names.
    pub triggers: Vec<String>,
    /// The runs: one entry per job per matrix arm.
    pub jobs: Vec<PlannedJob>,
    /// What was assumed, in one line each. Printed, and put in the attestation's
    /// annotations, so a reader cannot miss it.
    pub warnings: Vec<String>,
}

impl PlannedJob {
    fn of(job: &Job, matrix: BTreeMap<String, String>, warnings: &mut Vec<String>) -> PlannedJob {
        let mut assumptions = Vec::new();
        if let Some(condition) = &job.condition {
            assumptions.push(format!("job `if: {condition}` was not evaluated"));
        }
        let steps = job
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| PlannedStep::of(index + 1, step, &mut assumptions))
            .collect();
        if !job.services.is_empty() {
            warnings.push(format!(
                "job `{}` declares service container(s) {}; nothing starts them — the plan assumes they are already listening, and --execute refuses to run this job",
                job.id,
                job.services.join(", ")
            ));
        }
        if job
            .container
            .as_deref()
            .is_some_and(|image| !image.contains('@'))
        {
            warnings.push(format!(
                "job `{}`: container image `{}` is not digest-pinned, so the plan cannot name the image it would run in",
                job.id,
                job.container.as_deref().unwrap_or_default()
            ));
        }
        PlannedJob {
            id: job.id.clone(),
            name: job.name.clone(),
            runs_on: job.runs_on.clone(),
            matrix,
            env: job.env.clone(),
            services: job.services.clone(),
            assumptions,
            steps,
        }
    }

    /// ` [os=ubuntu-24.04, profile=release]`, or nothing.
    pub fn arm_text(&self) -> String {
        if self.matrix.is_empty() {
            return String::new();
        }
        format!(
            " [{}]",
            self.matrix
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    /// The step key a report indexes by: the id when there is one, else the name —
    /// the same rule `gitiup-attest` uses for `claims.timing`.
    pub fn step_key(&self, step: &PlannedStep) -> String {
        step.id.clone().unwrap_or_else(|| step.name.clone())
    }

    /// The `steps[]` of the attestation: a description per step, prefixed so the
    /// log says which run it belongs to.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            out.push_str(&step.describe());
        }
        out
    }
}

impl PlannedStep {
    fn of(index: usize, step: &Step, assumptions: &mut Vec<String>) -> PlannedStep {
        let name = step.name.clone();
        if let Some(condition) = &step.condition {
            assumptions.push(format!(
                "step `{name}` was assumed to run (`if: {condition}`)"
            ));
        }
        PlannedStep {
            index,
            id: step.id.clone(),
            name,
            uses: step.uses.clone(),
            run: step.run.clone(),
            inputs: step.inputs.clone(),
            condition: step.condition.clone(),
            shell: step.shell.clone(),
            env: step.env.clone(),
        }
    }

    /// The step's identity in a report.
    pub fn key(&self) -> String {
        self.id.clone().unwrap_or_else(|| self.name.clone())
    }

    /// What this step would do, in the form a simulated run records as its stdout.
    ///
    /// Deliberately free of anything that varies between machines or between
    /// minutes: no timestamps, no paths, no hostnames, no random ids. This text is
    /// hashed.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "SIMULATED step {} '{}' — nothing executed\n",
            self.index, self.name
        ));
        match (&self.uses, &self.run) {
            (Some(uses), _) => out.push_str(&format!(
                "  action   {uses} (ref not resolved: a plan fetches nothing)\n"
            )),
            (None, Some(script)) => {
                let lines: Vec<&str> = script.trim_end().lines().collect();
                let shown = lines.len();
                for line in lines.iter().take(SCRIPT_LINES_SHOWN) {
                    out.push_str(&format!("  script   {line}\n"));
                }
                if shown > SCRIPT_LINES_SHOWN {
                    out.push_str(&format!(
                        "  script   … {} more line(s)\n",
                        shown - SCRIPT_LINES_SHOWN
                    ));
                }
            }
            (None, None) => out.push_str("  (no action and no script)\n"),
        }
        for (key, value) in &self.inputs {
            out.push_str(&format!("  with     {key} = {value}\n"));
        }
        for (key, value) in &self.env {
            out.push_str(&format!("  env      {key} = {value}\n"));
        }
        if let Some(condition) = &self.condition {
            out.push_str(&format!("  if       {condition} (not evaluated)\n"));
        }
        out.push_str("  outcome  assumed success (exit 0): assumed, not observed\n");
        out
    }
}

/// Script lines shown per step in a plan. Enough to recognise a step, short enough
/// to read.
const SCRIPT_LINES_SHOWN: usize = 6;

/// Expand `strategy.matrix` into arms, then apply the `--matrix` restriction.
fn expand(job: &Job, selector: &Selector) -> Result<Vec<BTreeMap<String, String>>> {
    if job.matrix.is_empty() {
        return Ok(vec![BTreeMap::new()]);
    }
    let mut arms: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    for (axis, values) in &job.matrix {
        let mut next = Vec::with_capacity(arms.len() * values.len());
        for arm in &arms {
            for value in values {
                let mut grown = arm.clone();
                grown.insert(axis.clone(), value.clone());
                next.push(grown);
            }
        }
        arms = next;
        if arms.len() > MAX_MATRIX_ARMS {
            return Err(Error::new(
                ErrorKind::Invalid,
                "plan",
                format!(
                    "job `{}` expands to more than {MAX_MATRIX_ARMS} matrix arms",
                    job.id
                ),
            )
            .with_hint("restrict the run with --matrix axis=value"));
        }
    }
    if selector.matrix.is_empty() {
        return Ok(arms);
    }
    let wanted = &selector.matrix;
    for (key, value) in wanted {
        if !arms.iter().any(|arm| arm.get(key) == Some(value)) {
            return Err(Error::new(
                ErrorKind::Policy,
                "plan",
                format!("job `{}` has no matrix arm with {key}={value}", job.id),
            )
            .with_hint(format!(
                "this run's arms are {}",
                arms.iter()
                    .map(|arm| arm
                        .get(key)
                        .cloned()
                        .unwrap_or_else(|| "(no such axis)".into()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    Ok(arms
        .into_iter()
        .filter(|arm| {
            wanted
                .iter()
                .all(|(key, value)| arm.get(key) == Some(value))
        })
        .collect())
}

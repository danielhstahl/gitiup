//! The workflow file, as far as a plan cares.
//!
//! A GitHub Actions workflow is bigger than this type, and deliberately so: the
//! planner needs *what runs, in what order, with what inputs*, and every field it
//! drops is dropped out loud (in [`Workflow::warnings`]) rather than silently.
//! Nothing here evaluates expressions — `if:`, `${{ … }}` and matrix includes are
//! recorded as written. A simulated run therefore *assumes* conditional steps run,
//! and says exactly that in its output, because guessing which branches a runner
//! would have taken is how a plan starts looking like evidence.
//!
//! ```
//! use gitiup_run::Workflow;
//!
//! let source = "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n      - run: cargo test\n";
//! let wf = Workflow::parse(".github/workflows/ci.yml", source).unwrap();
//! assert_eq!(wf.name.as_deref(), Some("CI"));
//! assert_eq!(wf.triggers, vec!["push".to_string()]);
//! assert_eq!(wf.jobs.len(), 1);
//! assert_eq!(wf.jobs[0].steps.len(), 2);
//! assert_eq!(wf.jobs[0].steps[0].uses.as_deref(), Some("actions/checkout@v4"));
//! assert_eq!(wf.jobs[0].steps[1].run.as_deref(), Some("cargo test"));
//! assert_eq!(wf.jobs[0].steps[0].name, "actions/checkout@v4");
//! ```

use gitiup_attest::{Error, ErrorKind, InputValue, Result};

use crate::yaml::{self, Mapping, Yaml};

/// A workflow file, parsed for planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workflow {
    /// Repository-relative path it was read from (`<stdin>` when it was not a
    /// file). Recorded in the attestation, so it is part of what a verifier checks.
    pub path: String,
    /// `name:`.
    pub name: Option<String>,
    /// Trigger names from `on:` (`push`, `pull_request`, `workflow_dispatch`, …).
    pub triggers: Vec<String>,
    /// The jobs, in document order.
    pub jobs: Vec<Job>,
    /// `workflow_dispatch` input defaults, as the file declares them.
    ///
    /// A dispatch run needs an input set and the file's own `default:` values are
    /// the only honest offline answer; an input with no default is left out and
    /// reported as a warning rather than invented.
    pub dispatch_inputs: Vec<(String, InputValue)>,
    /// Non-fatal advice: keys this reader does not model, assumptions it made.
    pub warnings: Vec<String>,
}

/// One job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// The key under `jobs:`.
    pub id: String,
    /// `name:`.
    pub name: Option<String>,
    /// `runs-on:` flattened to a label string (`ubuntu-24.04`).
    pub runs_on: Option<String>,
    /// `if:`, recorded as written and **not evaluated**.
    pub condition: Option<String>,
    /// `needs:`, so a plan can show the order the workflow declares.
    pub needs: Vec<String>,
    /// `uses:` for a reusable workflow, which this planner cannot see inside.
    pub uses: Option<String>,
    /// `strategy.matrix` axes, in document order, each with its values.
    pub matrix: Vec<(String, Vec<String>)>,
    /// `container.image`, if the job declares one.
    pub container: Option<String>,
    /// Job-level `env:`, as text. Workflow text, never secret values: a secret
    /// reaches a step as `${{ secrets.X }}`, which this planner never expands.
    pub env: Vec<(String, String)>,
    /// `services:` container names, if the job declares any. The planner starts
    /// none of them; recording them is what lets a plan say "this assumes a database
    /// is already listening" and `--execute` refuse instead of running alone.
    pub services: Vec<String>,
    /// The steps, in execution order.
    pub steps: Vec<Step>,
}

/// One step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// `id:`.
    pub id: Option<String>,
    /// `name:`, falling back to `uses:` then to `run` — GitHub's own rule, and the
    /// name a human reads in the log.
    pub name: String,
    /// `uses:` as written (`actions/checkout@v4`). Unresolved on purpose: a plan
    /// that resolved refs would be claiming a network fetch it did not do.
    pub uses: Option<String>,
    /// `run:` body.
    pub run: Option<String>,
    /// `with:` inputs, as text.
    pub inputs: Vec<(String, String)>,
    /// `env:` entries, as text — names *and* values, because these are workflow
    /// text, not secrets (a secret reaches a step as `${{ secrets.X }}`, which is
    /// never expanded here).
    pub env: Vec<(String, String)>,
    /// `if:`, recorded as written and **not evaluated**.
    pub condition: Option<String>,
    /// `shell:`, if the step names one.
    pub shell: Option<String>,
    /// `continue-on-error: true`.
    pub continue_on_error: bool,
}

impl Workflow {
    /// Parse a workflow file.
    ///
    /// Errors are [`ErrorKind::Invalid`] (exit 6) and name the line: a workflow that
    /// cannot be read is not a plan, and "I could not read step 4" is the whole
    /// point of refusing.
    pub fn parse(path: &str, text: &str) -> Result<Workflow> {
        let doc = yaml::parse(text)?;
        let root = doc.as_map().ok_or_else(|| {
            yaml::error(
                None,
                "a workflow must be a mapping",
                "start with `name:` or `on:`",
            )
        })?;

        let mut warnings: Vec<String> = Vec::new();
        for key in root.unknown_keys(TOP_LEVEL_KEYS) {
            warnings.push(format!(
                "`{key}` is not modelled by the planner; it is ignored"
            ));
        }

        let name = root.str_field("name").map(str::to_string);
        let triggers = triggers_of(root)?;
        let dispatch_inputs = dispatch_defaults(root, &mut warnings);

        let Some(jobs) = root.map_field("jobs") else {
            return Err(yaml::error(
                None,
                "no `jobs:` to plan",
                "a workflow declares `jobs:` with at least one job",
            ));
        };
        if jobs.entries.is_empty() {
            return Err(yaml::error(
                None,
                "`jobs:` is empty",
                "there is nothing to attest to otherwise",
            ));
        }
        let mut parsed_jobs = Vec::with_capacity(jobs.entries.len());
        for (id, value) in &jobs.entries {
            parsed_jobs.push(Job::from_yaml(id, value, &mut warnings)?);
        }

        Ok(Workflow {
            path: path.to_string(),
            name,
            triggers,
            jobs: parsed_jobs,
            dispatch_inputs,
            warnings,
        })
    }

    /// The name of the event this workflow would run for, given a requested event
    /// and its own trigger list: the first trigger that matches, or the first
    /// trigger it declares (a plan has to be about *something*).
    pub fn event_for(&self, requested: Option<&str>) -> Result<String> {
        if let Some(name) = requested {
            if self.triggers.iter().any(|trigger| trigger == name) {
                return Ok(name.to_string());
            }
            return Err(Error::new(
                ErrorKind::Policy,
                "workflow",
                format!(
                    "this workflow is not triggered by `{name}`; it declares {}",
                    self.triggers.join(", ")
                ),
            )
            .with_hint("pick one of the declared triggers"));
        }
        // Prefer an event with a payload the planner can describe over a schedule,
        // which has none.
        for preferred in ["workflow_dispatch", "pull_request", "push"] {
            if self.triggers.iter().any(|trigger| trigger == preferred) {
                return Ok(preferred.to_string());
            }
        }
        Ok(self.triggers[0].clone())
    }

    /// The declared `workflow_dispatch` inputs, so a caller can ask for values.
    pub fn dispatch_input_names(&self) -> Vec<String> {
        self.dispatch_inputs
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl Job {
    fn from_yaml(id: &str, value: &Yaml, warnings: &mut Vec<String>) -> Result<Job> {
        let map = value.as_map().ok_or_else(|| {
            yaml::error(
                None,
                format!("job `{id}` is not a mapping"),
                "`jobs: <id>: {…}`",
            )
        })?;
        for key in map.unknown_keys(JOB_KEYS) {
            warnings.push(format!(
                "job `{id}`: `{key}` is not modelled by the planner; it is ignored"
            ));
        }
        if let Some(called) = map.str_field("uses") {
            warnings.push(format!(
                "job `{id}` calls the reusable workflow `{called}`; the planner does not follow it, so the plan covers this job's own steps only"
            ));
        }
        let steps = match map.seq_field("steps") {
            Some(steps) => steps,
            None if map.str_field("uses").is_some() => &[][..],
            None => {
                return Err(yaml::error(
                    None,
                    format!("job `{id}` has neither `steps:` nor `uses:`"),
                    "a job runs steps, or calls a reusable workflow with `uses:`",
                ));
            }
        };
        let mut steps_out = Vec::with_capacity(steps.len());
        for (index, step) in steps.iter().enumerate() {
            steps_out.push(Step::from_yaml(id, index + 1, step, warnings)?);
        }
        if steps_out.is_empty() && map.str_field("uses").is_none() {
            return Err(yaml::error(
                None,
                format!("job `{id}` has an empty `steps:` list"),
                "a job that runs nothing proves nothing",
            ));
        }

        Ok(Job {
            id: id.to_string(),
            name: map.str_field("name").map(str::to_string),
            runs_on: map.get("runs-on").and_then(label_of),
            condition: map.str_field("if").map(str::to_string),
            needs: map
                .get("needs")
                .and_then(Yaml::as_str_list)
                .unwrap_or_default(),
            uses: map.str_field("uses").map(str::to_string),
            matrix: matrix_of(id, map, warnings)?,
            container: container_of(map),
            env: pairs_of(map, "env"),
            services: service_names(map),
            steps: steps_out,
        })
    }
}

impl Step {
    fn from_yaml(
        job: &str,
        number: usize,
        value: &Yaml,
        warnings: &mut Vec<String>,
    ) -> Result<Step> {
        let map = value.as_map().ok_or_else(|| {
            yaml::error(
                None,
                format!("job `{job}` step {number} is not a mapping"),
                "steps are `- name:`/`- uses:`/`- run:` mappings",
            )
        })?;
        for key in map.unknown_keys(STEP_KEYS) {
            warnings.push(format!(
                "job `{job}` step {number}: `{key}` is not modelled; it is ignored"
            ));
        }
        let uses = map.str_field("uses").map(str::to_string);
        let run = map.str_field("run").map(str::to_string);
        match (&uses, &run) {
            (Some(_), Some(_)) => {
                return Err(yaml::error(
                    None,
                    format!("job `{job}` step {number} has both `uses:` and `run:`"),
                    "a step is either an action or a script",
                ));
            }
            (None, None) => {
                return Err(yaml::error(
                    None,
                    format!("job `{job}` step {number} has neither `uses:` nor `run:`"),
                    "a step runs an action (`uses:`) or a script (`run:`)",
                ));
            }
            _ => {}
        }
        let name = map
            .str_field("name")
            .or(uses.as_deref())
            .unwrap_or("run")
            .to_string();
        let truthy = |key: &str| {
            matches!(
                map.str_field(key),
                Some("true") | Some("True") | Some("yes") | Some("on")
            )
        };
        Ok(Step {
            id: map.str_field("id").map(str::to_string),
            name,
            uses,
            run,
            inputs: pairs_of(map, "with"),
            env: pairs_of(map, "env"),
            condition: map.str_field("if").map(str::to_string),
            shell: map.str_field("shell").map(str::to_string),
            continue_on_error: truthy("continue-on-error"),
        })
    }

    /// Whether the workflow declares this step as conditional, which is enough for
    /// a plan to say "assumed to run".
    pub fn is_conditional(&self) -> bool {
        self.condition.is_some()
    }
}

/// Keys the reader models at the top level; anything else is a warning, not an
/// error, because workflow syntax grows.
const TOP_LEVEL_KEYS: &[&str] = &[
    "name",
    "on",
    "permissions",
    "env",
    "defaults",
    "concurrency",
    "jobs",
    "run-name",
    "initial-defaults",
    "secrets",
];

const JOB_KEYS: &[&str] = &[
    "name",
    "needs",
    "condition",
    "if",
    "runs-on",
    "environment",
    "defaults",
    "strategy",
    "matrix",
    "env",
    "services",
    // Deliberately not listed as understood: the planner runs no service containers,
    // and a workflow with `services:` must be told so rather than planned as if the
    // database were there.
    "container",
    "steps",
    "uses",
    "with",
    "secrets",
    "permissions",
    "timeout-minutes",
    "continue-on-error",
    "outputs",
    "concurrency",
];

const STEP_KEYS: &[&str] = &[
    "id",
    "name",
    "uses",
    "run",
    "with",
    "env",
    "if",
    "shell",
    "working-directory",
    "continue-on-error",
    "timeout-minutes",
    "timeout_minutes",
];

/// `on:` as trigger names, accepting `on: push`, `on: [push, pull_request]` and
/// the mapping form.
fn triggers_of(root: &Mapping) -> Result<Vec<String>> {
    let Some(on) = root.get("on") else {
        return Err(yaml::error(
            None,
            "no `on:` trigger",
            "a workflow declares when it runs",
        ));
    };
    let names = match on {
        Yaml::Map(map) => map.entries.iter().map(|(key, _)| key.clone()).collect(),
        other => other.as_str_list().ok_or_else(|| {
            yaml::error(
                None,
                "`on:` is neither a name, a list, nor a mapping",
                "on: push · on: [push, pull_request] · on:\\n  push: …",
            )
        })?,
    };
    if names.is_empty() {
        return Err(yaml::error(
            None,
            "`on:` names no triggers",
            "at least one trigger, e.g. `push`",
        ));
    }
    Ok(names)
}

/// `on.workflow_dispatch.inputs.<name>.default`, in declaration order.
fn dispatch_defaults(root: &Mapping, warnings: &mut Vec<String>) -> Vec<(String, InputValue)> {
    let Some(on) = root.get("on").and_then(Yaml::as_map) else {
        return Vec::new();
    };
    let Some(dispatch) = on.map_field("workflow_dispatch") else {
        return Vec::new();
    };
    let Some(inputs) = dispatch.map_field("inputs") else {
        return Vec::new();
    };
    inputs
        .entries
        .iter()
        .filter_map(|(name, value)| {
            let spec = value.as_map()?;
            match spec.get("default") {
                Some(default) => Some((name.clone(), scalar_input(default))),
                None => {
                    if spec.str_field("required") == Some("true") {
                        warnings.push(format!(
                            "workflow_dispatch input `{name}` is required and has no default; pass --input {name}=…"
                        ));
                    }
                    None
                }
            }
        })
        .collect()
}

/// A YAML scalar as a manifest input value: the runner hands actions scalars, so
/// integers and booleans keep their types and everything else is text.
pub fn scalar_input(value: &Yaml) -> InputValue {
    match value.as_str() {
        Some("true") | Some("True") => InputValue::Bool(true),
        Some("false") | Some("False") => InputValue::Bool(false),
        Some(text) => match text.parse::<i64>() {
            Ok(number) => InputValue::Int(number),
            Err(_) => InputValue::Text(text.to_string()),
        },
        None => InputValue::Text(display(value)),
    }
}

/// The matrix axes of a job's `strategy.matrix`.
fn matrix_of(
    job: &str,
    map: &Mapping,
    warnings: &mut Vec<String>,
) -> Result<Vec<(String, Vec<String>)>> {
    let strategy = match map.map_field("strategy") {
        Some(strategy) => strategy,
        None => return Ok(Vec::new()),
    };
    let Some(matrix) = strategy.map_field("matrix") else {
        return Ok(Vec::new());
    };
    let mut axes = Vec::new();
    for (key, value) in &matrix.entries {
        if key == "include" || key == "exclude" {
            // The honest answer is that these change the vector set in ways a
            // planner that has not expanded them cannot predict, so they are
            // reported rather than dropped.
            warnings.push(format!(
                "job `{job}`: `strategy.matrix.{key}` is not expanded by the planner; the plan lists the base axes only"
            ));
            continue;
        }
        let values = value.as_str_list().ok_or_else(|| {
            yaml::error(
                None,
                format!("job `{job}`: matrix axis `{key}` is not a list of scalars"),
                "matrix axes are lists, e.g. `os: [ubuntu-24.04, macos-14]`",
            )
        })?;
        axes.push((key.clone(), values));
    }
    Ok(axes)
}

/// The names under `services:` — a mapping of alias → service, in document order.
fn service_names(map: &Mapping) -> Vec<String> {
    map.map_field("services")
        .map(|services| {
            services
                .entries
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// `container: { image: x }` or `container: image: x` or `container: x`.
fn container_of(map: &Mapping) -> Option<String> {
    match map.get("container")? {
        Yaml::Scalar(text) => Some(text.clone()),
        Yaml::Map(inner) => inner.str_field("image").map(str::to_string),
        _ => None,
    }
}

/// `runs-on` as one label: a scalar, the first of a list, or a map's values.
fn label_of(value: &Yaml) -> Option<String> {
    match value {
        Yaml::Scalar(text) if !text.is_empty() => Some(text.clone()),
        Yaml::Seq(items) => items
            .iter()
            .filter_map(Yaml::as_str)
            .next()
            .map(str::to_string),
        Yaml::Map(map) => map
            .entries
            .first()
            .map(|(key, _)| key.clone())
            .or_else(|| map.str_field("label").map(str::to_string)),
        _ => None,
    }
}

/// A `with:` / `env:` block as text pairs.
fn pairs_of(map: &Mapping, key: &str) -> Vec<(String, String)> {
    let Some(inner) = map.map_field(key) else {
        return Vec::new();
    };
    inner
        .entries
        .iter()
        .map(|(name, value)| (name.clone(), display(value)))
        .collect()
}

/// Render a value as the text an action would receive.
///
/// Actions receive strings; a list or map input is rendered in flow form so a plan
/// shows *something* rather than nothing, and the shape stays visible.
fn display(value: &Yaml) -> String {
    match value {
        Yaml::Scalar(text) => text.clone(),
        Yaml::Seq(items) => format!(
            "[{}]",
            items.iter().map(display).collect::<Vec<_>>().join(", ")
        ),
        Yaml::Map(map) => format!(
            "{{{}}}",
            map.entries
                .iter()
                .map(|(key, value)| format!("{key}: {}", display(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

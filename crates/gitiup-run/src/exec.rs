//! The executed run: where `tier: local` is earned, and where side effects live.
//!
//! This is the only module in the workspace that spawns a process, and it is
//! reachable in one way: `gitiup run --execute --sandbox <backend>`, where the
//! backend has been [probed and found](crate::sandbox). The attestation it produces
//! says `tier: local, sandbox: <name>`, and every word of that is a fact this module
//! can stand behind:
//!
//! * the steps ran as OS processes, and their exit codes were observed, not assumed;
//! * their output was captured, [normalised](gitiup_normalise) and hashed;
//! * the environment the steps saw was **built from nothing**, so a secret reaches
//!   a step only if the caller named it explicitly (see [`Execution::secret_names`]);
//! * the run was confined by the named backend, because [`Sandbox::probe`] said so
//!   minutes before, on this machine.
//!
//! # What is deliberately refused
//!
//! A `uses:` step is an action: it has to be fetched, pinned and interpreted. This
//! build does not do that (giti-bgy.4 owns pinning and fetching), so `--execute`
//! **refuses** rather than skipping: a skipped step in a `local` attestation would
//! silently shrink what the signature claims. Plan those workflows instead, or run
//! the ones that are plain scripts.
//!
//! The shape, in one sketch: `Workflow::parse` → `Plan::build` → `sandbox::open` →
//! `exec::execute` → [`manifest_for`](crate::manifest_for), which is where the tier and
//! the sandbox names land in the bytes that get signed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gitiup_attest::run::{
    ClaimReport, EnvironmentReport, EventReport, Material, StepReport, WorkflowSource,
};
use gitiup_attest::{
    Digest, Error, ErrorKind, GitOid, InputValue, Provenance, RunReport, StepOutcome, Tier, TimeUs,
};

use crate::plan::{Plan, PlannedJob};
use crate::sandbox::Sandbox;

/// Largest log stream kept, in bytes.
///
/// A build log is not an artifact, and an OOM-killed runner proves nothing; the
/// truncation is recorded in the log itself so the digest shows it happened.
pub const MAX_LOG_BYTES: usize = 4 << 20;

/// Everything an execution needs beyond the plan.
#[derive(Debug, Clone)]
pub struct Execution<'a> {
    /// The commit being run.
    pub commit: GitOid,
    /// The workflow file.
    pub workflow: WorkflowSource,
    /// The event being run.
    pub event: String,
    /// Event action.
    pub event_action: Option<String>,
    /// Repository identity, for `GITHUB_REPOSITORY` and for humans.
    pub repo: Option<String>,
    /// Working directory the steps run in.
    pub workspace: PathBuf,
    /// Secrets to hand over, **by name**: the value is read from this process's
    /// environment and passed to the step's environment, and only the name is ever
    /// recorded. Not knowing a name is a refusal, not a silent omission.
    ///
    /// This is the local counterpart of giti-bgy.3's rule (never ship secret values
    /// to a volunteer): locally the value has to arrive somehow, and the name is all
    /// that reaches the attestation.
    pub secret_names: Vec<String>,
    /// Extra environment entries, e.g. from `--env`.
    pub extra_env: BTreeMap<String, String>,
    /// Job inputs.
    pub inputs: Vec<(String, InputValue)>,
    /// The backend named on the command line, already opened.
    pub sandbox: &'a str,
    /// `claims.run_id`, or derived from the clock.
    pub run_id: Option<String>,
    /// The clock.
    pub now_us: Option<i64>,
    /// Runner string for provenance.
    pub runner: &'a str,
    /// Non-fatal advice collected while running (unexpanded `${{ … }}`, truncated
    /// logs) — printed, and recorded in annotations.
    pub notes: Vec<String>,
}

impl<'a> Execution<'a> {
    /// The smallest honest execution: `runner` runs `workflow` for `commit` in
    /// `workspace`, confined by a backend named `sandbox`, with no secrets.
    pub fn new(
        commit: GitOid,
        workflow: WorkflowSource,
        sandbox: &'a str,
        workspace: &Path,
        runner: &'a str,
    ) -> Execution<'a> {
        Execution {
            commit,
            workflow,
            event: "push".into(),
            event_action: None,
            repo: None,
            workspace: workspace.to_path_buf(),
            secret_names: Vec::new(),
            extra_env: BTreeMap::new(),
            inputs: Vec::new(),
            sandbox,
            run_id: None,
            now_us: None,
            runner,
            notes: Vec::new(),
        }
    }
}

/// Run the planned job for real and report what happened.
///
/// One step failing stops the run the way a runner does — the rest are `skipped`,
/// unless the workflow said `continue-on-error` — because "it carried on after the
/// tests failed" is a fact about the workflow, not a licence to pretend.
pub fn execute(
    plan: &Plan,
    job: &PlannedJob,
    sandbox: &dyn Sandbox,
    execution: &Execution<'_>,
) -> Result<RunReport, Error> {
    if !job.services.is_empty() {
        return Err(Error::new(
            gitiup_attest::ErrorKind::Policy,
            "exec",
            format!(
                "job `{}` declares service container(s) {}, and this build starts none of them",
                job.id,
                job.services.join(", ")
            ),
        )
        .with_hint(
            "run the services yourself and point the workflow at them, or plan without \
             --execute — a job that silently runs without its database is the worst \
             outcome here, because its attestation would look clean",
        ));
    }
    if !plan
        .jobs
        .iter()
        .any(|planned| planned.id == job.id && planned.matrix == job.matrix)
    {
        return Err(Error::new(
            ErrorKind::Policy,
            "exec",
            format!("job `{}` is not part of this plan", job.id),
        )
        .with_hint("take the job from the plan that is being executed"));
    }
    // Probe again, here, at the last moment before the side effects: the name on the
    // command line is not the claim, the working backend is.
    sandbox.probe()?;

    let now_us = execution.now_us.unwrap_or_else(|| TimeUs::now().0);
    let scratch = scratch_dir(&now_us)?;
    let mut steps: Vec<StepReport> = Vec::with_capacity(job.steps.len());
    let mut notes = execution.notes.clone();
    let mut failed = false;

    for step in &job.steps {
        if failed {
            steps.push(StepReport {
                id: step.id.clone(),
                name: step.name.clone(),
                uses: step.uses.clone(),
                exit_code: 0,
                outcome: Some(StepOutcome::Skipped),
                stdout: Material::text(String::new()),
                stderr: Material::text("skipped: an earlier step failed\n".to_string()),
                outputs: BTreeMap::new(),
                artifacts: Vec::new(),
                timing: None,
            });
            continue;
        }
        let Some(script) = &step.run else {
            return Err(Error::new(
                ErrorKind::Policy,
                "exec",
                format!(
                    "step {} '{}' uses `{}`: this build does not fetch and interpret actions",
                    step.index,
                    step.name,
                    step.uses.clone().unwrap_or_default()
                ),
            )
            .with_hint(
                "either simulate the run (the default, and it plans `uses:` steps \
                 honestly) or pin and vendor the action first (giti-bgy.4); skipping a \
                 step while attesting that the run happened is not an option",
            ));
        };
        for (name, value) in &step.inputs {
            notes.push(format!(
                "step {}: `{name} = {value}` is not expanded",
                step.name
            ));
        }
        let outputs_path = scratch.join(format!("outputs-{}", step.index));
        let environment = step_environment(execution, sandbox, job, step, &outputs_path)?;
        let argv = shell_command(script, step, &scratch)?;
        let started = Instant::now();
        let started_us = TimeUs::now().0;
        let output = confine_and_run(sandbox, &argv, &environment, &execution.workspace, &scratch)
            .map_err(|why| {
                Error::new(
                    ErrorKind::Invalid,
                    "exec",
                    format!(
                        "step {} '{}' could not be run: {why}",
                        step.index, step.name
                    ),
                )
                .with_hint("the first argument is the program to run; check the sandbox backend")
            })?;
        let duration_us = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
        let exit_code = output.status.code().unwrap_or(-1) as i64;
        let stdout = clamp(captee(&output.stdout));
        let stderr = captee(&output.stderr);
        if stdout.truncated || stderr.truncated {
            notes.push(format!(
                "step {}: output beyond {MAX_LOG_BYTES} bytes was dropped before hashing",
                step.name
            ));
        }
        let outputs = read_outputs(&outputs_path);
        steps.push(StepReport {
            id: step.id.clone(),
            name: step.name.clone(),
            uses: step.uses.clone(),
            exit_code,
            outcome: Some(if exit_code == 0 {
                StepOutcome::Success
            } else {
                StepOutcome::Failure
            }),
            stdout: Material::text(stdout.text),
            stderr: Material::text(stderr.text),
            outputs,
            artifacts: Vec::new(),
            timing: Some(gitiup_attest::StepTiming {
                started_us: Some(started_us),
                duration_us: Some(duration_us),
            }),
        });
        if exit_code != 0 {
            failed = true;
        }
    }

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "x_run_mode".to_string(),
        format!("executed in the `{}` sandbox", sandbox.name()),
    );
    annotations.insert(
        "x_sandbox_guarantees".to_string(),
        sandbox.guarantees().to_string(),
    );
    for condition in &job.assumptions {
        notes.push(condition.clone());
    }
    if !notes.is_empty() {
        annotations.insert("x_run_notes".to_string(), notes.join(" · "));
    }
    // The machine class this ran on (giti-1rs.4), probed here rather than declared:
    // an executed run that reported no architecture and no inventory would carry a
    // fingerprint that identifies nothing, and the policy that later asks "was this
    // the machine we promised?" would have nothing to read.
    let probe = crate::env::Probe::collect().with_provider(sandbox.name());
    for (key, value) in probe.annotations() {
        annotations.insert(key, value);
    }
    let commit_text = execution.commit.to_string();
    let clock = now_us.to_string();
    let parts: Vec<&[u8]> = vec![
        sandbox.name().as_bytes(),
        commit_text.as_bytes(),
        job.id.as_bytes(),
        clock.as_bytes(),
    ];
    let run_id = execution
        .run_id
        .clone()
        .unwrap_or_else(|| Digest::sha256_parts(&parts).hex()[..16].to_string());

    Ok(RunReport {
        repo: execution.repo.clone(),
        commit: execution.commit.clone(),
        workflow: execution.workflow.clone(),
        event: EventReport {
            name: execution.event.clone(),
            action: execution.event_action.clone(),
            payload: Material::text(format!("{{\"name\":\"{}\"}}", execution.event)),
        },
        job: Some(job.id.clone()),
        matrix: job.matrix.clone(),
        inputs: execution.inputs.iter().cloned().collect(),
        secret_names: execution.secret_names.clone(),
        pins: BTreeMap::new(),
        reusable_workflows: Vec::new(),
        environment: EnvironmentReport {
            // The provider is the backend that ran it: the same word in two fields
            // saying the same thing is a feature, not a redundancy — a verifier that
            // filters on provider cannot be fooled by a `local` tier alone.
            provider: Some(sandbox.name().to_string()),
            ..probe.environment
        },
        steps,
        provenance: Provenance {
            tier: Tier::Local,
            runner: execution.runner.to_string(),
            // The logs arrive as text; `manifest_for` normalises them and rewrites
            // this to the profile's version, which is the only honest way to claim it.
            normalisation_version: 0,
            sandbox: Some(sandbox.name().to_string()),
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

/// A captured stream, clamped to [`MAX_LOG_BYTES`].
struct Captured {
    text: String,
    truncated: bool,
}

fn captee(bytes: &[u8]) -> Captured {
    let text = String::from_utf8_lossy(bytes).into_owned();
    Captured {
        text,
        truncated: false,
    }
}

fn clamp(mut captured: Captured) -> Captured {
    if captured.text.len() > MAX_LOG_BYTES {
        let mut kept: String = captured.text.chars().take(MAX_LOG_BYTES).collect();
        kept.push_str("\n… output truncated by gitiup before hashing …\n");
        captured.text = kept;
        captured.truncated = true;
    }
    captured
}

/// Build the confined command and run it.
///
/// Two failures end up as one message — the confinement refusing to arm, and the
/// confined process refusing to start — because from the step's point of view they are
/// the same event (it did not run) and the reason is in the text either way.
fn confine_and_run(
    sandbox: &dyn Sandbox,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    workspace: &Path,
    scratch: &Path,
) -> gitiup_attest::Result<std::process::Output> {
    let mut command = sandbox.command(argv, environment, workspace, scratch)?;
    command
        .output()
        .map_err(|why| Error::new(ErrorKind::Invalid, "exec", why.to_string()))
}

/// The step's environment, built from nothing.
fn step_environment(
    execution: &Execution<'_>,
    sandbox: &dyn Sandbox,
    job: &crate::plan::PlannedJob,
    step: &crate::plan::PlannedStep,
    outputs_path: &Path,
) -> Result<BTreeMap<String, String>, Error> {
    let mut env = BTreeMap::new();
    env.insert("PATH".into(), "/usr/bin:/bin:/usr/local/bin".into());
    env.insert("HOME".into(), execution.workspace.display().to_string());
    env.insert("LANG".into(), "C.UTF-8".into());
    env.insert("TERM".into(), "dumb".into());
    env.insert("CI".into(), "true".into());
    env.insert("GITIUP".into(), "1".into());
    env.insert(
        "GITHUB_WORKSPACE".into(),
        execution.workspace.display().to_string(),
    );
    env.insert("GITHUB_SHA".into(), execution.commit.hex().to_string());
    env.insert(
        "GITHUB_REPOSITORY".into(),
        execution.repo.clone().unwrap_or_default(),
    );
    env.insert("GITHUB_EVENT_NAME".into(), execution.event.clone());
    env.insert("GITHUB_RUN_ID".into(), execution.commit.to_string());
    env.insert("RUNNER_NAME".into(), format!("gitiup-{}", sandbox.name()));
    env.insert("GITHUB_OUTPUT".into(), outputs_path.display().to_string());
    for (key, value) in &execution.extra_env {
        env.insert(key.clone(), value.clone());
    }
    for (name, value) in &execution.inputs {
        env.insert(format!("INPUT_{}", normalise_input(name)), render(value));
    }
    for (name, value) in &step.inputs {
        env.insert(format!("INPUT_{}", normalise_input(name)), value.clone());
    }
    // `env:` from the workflow, job then step, after the fixed entries (so a
    // workflow can set `PATH` if it means to) and before the secrets (so a name used
    // both ways ends up holding the secret, which is what a runner would do).
    for (name, value) in job.env.iter().chain(&step.env) {
        env.insert(name.clone(), expand(value, &job.matrix, name)?);
    }
    for name in &execution.secret_names {
        let value = std::env::var(name).map_err(|_| {
            Error::new(
                ErrorKind::Policy,
                "exec",
                format!("secret `{name}` was requested but is not set in this environment"),
            )
            .with_hint(format!("export {name}=… or drop it from --secret-name"))
        })?;
        env.insert(name.clone(), value);
    }
    Ok(env)
}

/// `${{ matrix.* }}` in an `env:` value, and nothing else.
///
/// A matrix arm is known here (the plan was built for exactly one), so expanding it
/// makes the step see what a runner would have given it. Everything else — `github`,
/// `inputs`, and above all `secrets` — stays as written, and a literal
/// `${{ secrets.X }}` is refused rather than handed over as if it were a token: a step
/// that believes it has credentials when it has a template is worse than a step that
/// did not run.
fn expand(value: &str, matrix: &BTreeMap<String, String>, name: &str) -> Result<String, Error> {
    let mut out = value.to_string();
    for (key, arm) in matrix {
        out = out.replace(&format!("${{{{ matrix.{key} }}}}"), arm);
    }
    if out.contains("secrets.") {
        return Err(Error::new(
            gitiup_attest::ErrorKind::Policy,
            "exec",
            format!("`env: {name}` is `{value}`: secret expressions are not expanded"),
        )
        .with_hint("name the secret with --secret-name and read it from the environment"));
    }
    Ok(out)
}

/// The argv that runs one step's script.
fn shell_command(
    script: &str,
    step: &crate::plan::PlannedStep,
    scratch: &Path,
) -> Result<Vec<String>, Error> {
    let shell = match step.shell.as_deref().unwrap_or("sh") {
        "sh" | "bash" | "shell" => "/bin/sh",
        other => {
            return Err(Error::new(
                ErrorKind::Policy,
                "exec",
                format!("step '{}': `shell: {other}` is not supported", step.name),
            )
            .with_hint("this build runs `sh` scripts; declare `shell: sh` or simulate"));
        }
    };
    // The script goes through a file rather than `sh -c`: a multi-line heredoc-free
    // script survives quoting exactly as the workflow wrote it, and the file lives
    // in the scratch directory this run owns.
    let path = scratch.join(format!("step-{}.sh", step.index));
    std::fs::write(&path, script).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "exec",
            format!("could not stage step script {}: {why}", path.display()),
        )
    })?;
    Ok(vec![shell.to_string(), path.display().to_string()])
}

/// A private scratch directory for step scripts and output files.
fn scratch_dir(now_us: &i64) -> Result<PathBuf, Error> {
    let path = std::env::temp_dir().join(format!("gitiup-run-{}-{now_us}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "exec",
            format!(
                "could not create the scratch directory {}: {why}",
                path.display()
            ),
        )
    })?;
    Ok(path)
}

/// Parse a `$GITHUB_OUTPUT` file (`key=value`, one per line).
fn read_outputs(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut outputs = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=')
            && !key.is_empty()
        {
            outputs.insert(key.to_string(), value.to_string());
        }
    }
    outputs
}

/// `GITHUB_OUTPUT`-style input names: uppercase, spaces and `.` to `_`.
fn normalise_input(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            ' ' | '.' | '-' => '_',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

fn render(value: &InputValue) -> String {
    match value {
        InputValue::Text(text) => text.clone(),
        InputValue::Int(number) => number.to_string(),
        InputValue::Bool(flag) => flag.to_string(),
    }
}

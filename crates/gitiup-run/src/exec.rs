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
//!
//! # Reading a failure
//!
//! An attestation carries the *digest* of each step's output, never the text, so the
//! moment a step fails the text is in exactly one place: this process's memory. That is
//! why the reading helpers live here, next to the code that observed the exit code, and
//! not in the CLI: [`diagnose`] turns an exit code and the step's own words into a
//! sentence a person can act on ("`cargo` is not on this step's PATH", "killed by
//! SIGKILL", "the sandbox refused that write"), and [`excerpt`] cuts a stream to the
//! tail that is worth printing. A volunteer running a stranger's job — `gitiup work` —
//! has the same problem and gets the same answer.

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
            "run with --engine act, which starts the job's services in their own containers \
             (docs/act.md), run the services yourself and point the workflow at them, or \
             plan without --execute — a job that silently runs without its database is the \
             worst outcome here, because its attestation would look clean",
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
                "run with --engine act, which fetches and runs actions and understands the \
                 expression language (docs/act.md, and its attestation says `sandbox: act` \
                 because the containment was act's); or simulate the run (the default, and \
                 it plans `uses:` steps honestly); or pin and vendor the action first \
                 (giti-bgy.4). Skipping a step while attesting that the run happened is not \
                 an option",
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
        // A process killed by a signal reports no exit code at all, and the report can
        // only carry a number, so the number this run records (-1) says "no code" and
        // nothing more. The signal itself goes into the annotations: the difference
        // between SIGKILL from the OOM killer and SIGSEGV in the program is the whole
        // story of a crash, and it belongs with the evidence rather than only on a
        // terminal nobody was watching.
        if output.status.code().is_none() {
            notes.push(match signal_of(&output.status) {
                Some(signal) => format!(
                    "step {}: killed by signal {signal} ({}) rather than exiting",
                    step.name,
                    signal_name(signal)
                ),
                None => format!("step {}: the process could not be waited for", step.name),
            });
        }
        let stdout = clamp(captee(&output.stdout));
        let stderr = clamp(captee(&output.stderr));
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
///
/// Public because the confinement notes a run prints *before* it starts name this
/// directory — the scratch is one of the two writable mounts, so a caller that printed a
/// plan made from a different path would be printing a plan that is not the one the step
/// runs under. Deterministic for a given clock, and idempotent: calling it twice is the
/// same directory.
pub fn scratch_dir(now_us: &i64) -> Result<PathBuf, Error> {
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
// -------------------------------------------------------------- reading ---

/// The most of one step's stream worth putting in front of a human.
///
/// The digest covers everything up to [`MAX_LOG_BYTES`]; this limit is only about not
/// burying the reason for a failure under a megabyte of progress bars, so it is much
/// smaller than what is hashed — and it cuts from the front, because what killed a
/// build is at the end.
pub const MAX_DISPLAY_BYTES: usize = 64 << 10;

/// The same limit in lines, for a stream made of many short ones.
pub const MAX_DISPLAY_LINES: usize = 200;

/// Why a step failed, as far as its exit code and its own words can say.
///
/// Deliberately narrow: this is what a process's death rattle means, not a theory about
/// the caller's code. [`Diagnosis::hint`] is `None` whenever the honest answer is "the
/// log says", because a guess about somebody else's tests is noise that teaches people
/// to skip the line that actually mattered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// The exit code read as a sentence: "`cargo` was not found by the step's shell".
    pub cause: String,
    /// What to do about it, when there is something honest to do.
    pub hint: Option<String>,
}

impl std::fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cause)?;
        if let Some(hint) = &self.hint {
            write!(f, " — {hint}")?;
        }
        Ok(())
    }
}

/// The PATH a step really sees, so a hint can be checked against [`step_environment`]
/// instead of remembered.
const STEP_PATH: &str = "/usr/bin:/bin:/usr/local/bin";

/// The strings that mean "the container runtime, not the job, decided this".
///
/// Every one of them is a daemon's sentence about its own configuration, and none of
/// them is a verdict about the code under test. They are matched in the text rather
/// than by exit code because the daemon's message arrives whatever the code is, and
/// because the same refusal has exited 125 on one runtime and 1 on another.
const RUNTIME_REFUSALS: &[&str] = &[
    "mounts denied",
    "is not shared from the host",
    "duplicate mount point",
    "no such image",
    "error getting credentials",
    "error response from daemon",
    "oci runtime",
];

/// The strings that mean "the network was the problem", lower-cased.
const NETWORK_FAILURES: &[&str] = &[
    "network is unreachable",
    "connection refused",
    "connection timed out",
    "no route to host",
    "could not resolve host",
    "name or service not known",
    "temporary failure in name resolution",
    "couldn't connect to server",
    "failed to fetch",
];

/// Read one step's failure.
///
/// `exit_code` is the observed code ([`execute`] records `-1` when the process was
/// killed without reporting one) and `stderr` the step's own error stream, which is
/// where a shell says *why* it exited 127 rather than merely *that* it did.
///
/// `None` means "the exit code is the program's own verdict and nothing here can
/// improve on it" — the common case, and the case where the log text is the whole
/// answer.
pub fn diagnose(exit_code: i64, stderr: &str) -> Option<Diagnosis> {
    // Killed rather than exited. A shell reports 128 + signal, and reports nothing at
    // all when the signal took the reporting shell itself.
    if exit_code < 0 {
        return Some(Diagnosis {
            cause: "the step's process was killed rather than exiting, so it reported no \
                    exit code at all"
                .to_string(),
            hint: Some(
                "the run's annotations name the signal: SIGKILL is the machine's own \
                 out-of-memory killer or a `timeout -s KILL`, SIGSEGV is the program's own \
                 bug, and SIGXCPU is the sandbox's cpu limit. The sandbox bounds address \
                 space, cpu seconds, processes and file size — `gitiup doctor --sandbox` \
                 prints the limits in force here"
                    .to_string(),
            ),
        });
    }
    if exit_code > 128 {
        let signal = exit_code - 128;
        let hint = match signal {
            9 => Some(
                "SIGKILL is not a program deciding to stop: the usual sources are the \
                 machine's out-of-memory killer and a `timeout -s KILL`. The sandbox also \
                 bounds address space, cpu seconds, processes and file size — `gitiup \
                 doctor --sandbox` prints the limits in force here",
            ),
            11 => Some(
                "a segmentation fault: the step's own program, or a native library it \
                 loaded, walked off its memory",
            ),
            6 => Some("an abort: usually a failed assertion inside the program itself"),
            31 => Some(
                "SIGSYS is what a seccomp filter hands back. This ladder refuses ptrace, \
                 mount, unshare, setns, module loading and installing a filter of your \
                 own; a step that needs one of those has to run somewhere that allows it",
            ),
            24 => Some("the cpu-seconds limit was reached, which is a hang rather than a crash"),
            13 => Some(
                "SIGPIPE: the program was writing into a pipe that had already closed — \
                 look at whatever stood on the other end of it",
            ),
            _ => None,
        };
        return Some(Diagnosis {
            cause: format!(
                "killed by signal {signal} ({}) instead of exiting",
                signal_name(signal)
            ),
            hint: hint.map(str::to_string),
        });
    }

    // The runtime's own refusal, which is not the step's verdict at all. A container
    // runtime answers 125 when the container never started, and its sentence — a mount
    // it will not make, an image it does not have, a destination two grants wanted — is
    // the only account of what it refused. This is read before the sandbox denials below
    // because the two are easy to confuse and are opposite facts: "read-only file system"
    // from a daemon that mounted a directory over one the image owns, and "read-only file
    // system" from a sandbox refusing a write the job actually made.
    let lower = stderr.to_ascii_lowercase();
    if let Some(needle) = RUNTIME_REFUSALS
        .iter()
        .find(|needle| lower.contains(**needle))
    {
        // The daemon usually says the refusal in two lines: which refusal, then the
        // path or image it is about. One of them alone is the less useful half.
        let said = {
            let lines: Vec<&str> = stderr
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect();
            let index = lines
                .iter()
                .position(|line| line.to_ascii_lowercase().contains(needle))
                .unwrap_or(0);
            let raw = lines.get(index).copied().unwrap_or(needle);
            let head = raw.trim_end_matches(':').trim();
            match (head.len() < raw.trim().len(), lines.get(index + 1)) {
                (true, Some(more)) => format!("{head}: {more}"),
                _ => head.to_string(),
            }
        };
        return Some(Diagnosis {
            cause: format!("the container runtime refused the job rather than running it: {said}"),
            hint: Some(
                "nothing of the step ran, so nothing here is a verdict about the code: the \
                 refusal is about the container gitiup asked for. The two paths it always \
                 mounts are the checkout and the run's scratch directory, and the scratch \
                 follows `$TMPDIR` — on macOS, pointing TMPDIR at a directory the desktop \
                 app will share is the fix that needs no settings change. `gitiup run \
                 --execute` prints every mount it asked for before the first step; \
                 `gitiup doctor --sandbox` says what this machine's runtime will share, and \
                 whether the image is present — and gitiup never pulls one during a run, so \
                 an image the runtime has never seen is refused by name"
                    .to_string(),
            ),
        });
    }
    if exit_code == 125 {
        return Some(Diagnosis {
            cause: "the step exited 125, which is what a container runtime answers when the \
                    container never started: no step command ran"
                .to_string(),
            hint: Some(
                "the runtime's own words are in the output above, and they are the only \
                 account of what it refused. `gitiup run --execute` prints the mounts it \
                 asked for before the first step, and `gitiup doctor --sandbox` says what \
                 this machine's runtime will share. If this step did not run in a \
                 container, 125 is the program's own exit code and its output above is \
                 the answer"
                    .to_string(),
            ),
        });
    }

    // The shell's own two refusals: it could not find the program, or could not run it.
    if let Some(program) = missing_program(stderr) {
        if exit_code == 126 {
            return Some(Diagnosis {
                cause: format!("`{program}` was found but would not run (exit 126)"),
                hint: Some(
                    "exit 126 is the execute bit or a `#!` interpreter that is not there, \
                     not a missing file: check the mode bits, then the script's first line"
                        .to_string(),
                ),
            });
        }
        let hint = if program.contains('/') {
            "the step named a path that is not there; a step starts in the checkout \
             (`--workdir` moves it), so a script that lives somewhere else needs its path \
             to say so"
                .to_string()
        } else {
            format!(
                "a step's PATH is {STEP_PATH} and nothing else unless the workflow says \
                 otherwise with `env: PATH:` — install the tool, or name the directory it \
                 lives in on the job or the step"
            )
        };
        return Some(Diagnosis {
            cause: format!("`{program}` was not found by the step's shell (exit {exit_code})"),
            hint: Some(hint),
        });
    }

    // What the sandbox refused, as opposed to what the program decided. These are the
    // failures that read like a broken build and are really the confinement working.
    if lower.contains("read-only file system") {
        return Some(Diagnosis {
            cause: format!(
                "a write was refused because the filesystem is read-only here (exit {exit_code})"
            ),
            hint: Some(
                "a confined step may write to the checkout and to the run's scratch \
                 directory and nowhere else; write there, or move the checkout with \
                 --workdir — `gitiup doctor --sandbox` prints what the backend denies"
                    .to_string(),
            ),
        });
    }
    if lower.contains("operation not permitted") {
        return Some(Diagnosis {
            cause: format!("the step attempted something this sandbox refuses (exit {exit_code})"),
            hint: Some(
                "both Landlock and seccomp answer EPERM: writes outside the checkout and \
                 the scratch, ptrace, mount/unshare/setns and module loading are refused \
                 by design here. `gitiup doctor --sandbox` says which layer is active, and \
                 `--sandbox plain` — opt-in, for code you wrote — confines nothing"
                    .to_string(),
            ),
        });
    }
    if lower.contains("permission denied") || lower.contains("access is denied") {
        return Some(Diagnosis {
            cause: format!("a file could not be opened the way the step asked (exit {exit_code})"),
            hint: Some(
                "two things say this and they look identical: the step's own rights (it \
                 runs as this user, with this user's mode bits) and the sandbox's deny \
                 list, which allows writes to the checkout and to the run's scratch \
                 directory only. Check the path first, then the bits; `gitiup doctor \
                 --sandbox` names the layer that is active"
                    .to_string(),
            ),
        });
    }
    if NETWORK_FAILURES.iter().any(|needle| lower.contains(needle)) {
        return Some(Diagnosis {
            cause: format!("the step could not reach the network (exit {exit_code})"),
            hint: Some(
                "egress is deny-all in every backend this build offers and there is no \
                 allowlist flag yet: a step that fetches has to be handed its inputs some \
                 other way (docs/sandbox.md covers egress)"
                    .to_string(),
            ),
        });
    }
    if lower.contains("no space left on device") || lower.contains("disk quota exceeded") {
        return Some(Diagnosis {
            cause: format!("the disk filled up (exit {exit_code})"),
            hint: Some(
                "one step's log is capped at {MAX_LOG_BYTES} bytes before hashing, so a \
                 full disk is the build's own output rather than its transcript; the \
                 scratch directory this run wrote its scripts into lives in the temp \
                 directory"
                    .to_string(),
            ),
        });
    }
    if stderr.trim().is_empty() {
        return Some(Diagnosis {
            cause: format!("the step exited {exit_code} and wrote nothing to either stream"),
            hint: Some(
                "a program that dies without a word usually died in a start-up check of \
                 its own; run the step's script by hand to see what it prints when \
                 nothing is capturing it"
                    .to_string(),
            ),
        });
    }
    None
}

/// The program a shell complained about, if it complained about one.
///
/// `sh` says `sh: 1: cargo: not found`, `bash` says `bash: line 1: cargo: command not
/// found`, and both say `No such file or directory` about a path that is not there. In
/// all three the name is the field before the last `:`.
fn missing_program(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        let complaint = lower.ends_with(": not found")
            || lower.ends_with("command not found")
            || lower.ends_with("no such file or directory");
        if !complaint {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[fields.len() - 2].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// The name of a signal a shell's `128 + n` answer can produce, for the ones it does.
fn signal_name(signal: i64) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        31 => "SIGSYS",
        _ => "an unnamed signal",
    }
}

/// The tail of a captured stream, with the cut said out loud.
///
/// The digest covers the whole stream, so dropping the head here costs nobody anything
/// they could be asked to verify — but the printout has to say the drop happened, or a
/// reader assumes they saw the beginning.
pub fn excerpt(text: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut start = lines.len();
    let mut bytes = 0usize;
    while start > 0 {
        let line = lines[start - 1];
        let cost = line.chars().count() + 1;
        let kept = lines.len() - start;
        if kept > 0 && (bytes + cost > MAX_DISPLAY_BYTES || kept >= MAX_DISPLAY_LINES) {
            break;
        }
        bytes += cost;
        start -= 1;
    }
    let kept = lines[start..].join("\n");
    if start == 0 {
        return format!("{kept}\n");
    }
    let dropped_bytes: usize = lines[..start]
        .iter()
        .map(|line| line.chars().count() + 1)
        .sum();
    format!(
        "… {} earlier lines ({} bytes) are not printed here; the digest covers the whole \
         stream\n{kept}\n",
        start, dropped_bytes
    )
}

/// The signal a process was killed by, when a signal killed it.
///
/// Unix-only, which is the whole platform set of this crate: the same code path runs on
/// Linux and on macOS, where `wait(2)` reports the same fact.
fn signal_of(status: &std::process::ExitStatus) -> Option<i64> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|signal| signal as i64)
}

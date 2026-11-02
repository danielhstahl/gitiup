//! `gitiup run` — plan a workflow job, and only run it when told to.
//!
//! The shape of this command *is* the ticket's safety story, so it is worth stating
//! plainly before the code:
//!
//! * **the default simulates.** No process is spawned, no network is touched, no
//!   secret is read, nothing is written. What you get is the plan and the digest of
//!   the plan, and the attestation says `tier: simulated`.
//! * **`--execute` is the opt-in** to running for real, and it needs a sandbox this
//!   machine actually provides (`--sandbox <name>`; see `--sandboxes`, and
//!   `gitiup doctor --sandbox` when one of them does not work). That is what earns
//!   `tier: local`.
//! * **`quorum` is not a flag.** There is no spelling of this command that produces
//!   one, and the format refuses a single-run attestation that claims it
//!   ([`gitiup_attest::Provenance::check`]), so the flag cannot be added by accident
//!   later either.
//!
//! A simulated attestation is a plan with a fingerprint: good for "what would this
//! change do", useless for "this passed". The second reading is the dangerous one,
//! so keeping an attestation is the gated step — printing a plan exits 0 and warns,
//! while **`--out`** (writing one for someone else) and **`--policy`** (asking to be
//! gated) both run the policy, whose default allows `local` only.
//!
//! **A workflow may have several jobs, and an attestation is still one run.** That is
//! not a limitation of the format and not a limitation here: `--job <id>` (or the
//! bare positional job name) picks one job, repeating it picks several, and
//! `--all-jobs` takes every run the workflow would produce. What never happens is one
//! attestation about two runs, so a command that selects more than one run *prints or
//! writes more than one attestation* — one canonical manifest per run.
//!
//! # When a step fails
//!
//! An attestation carries the **digest** of each step's stdout and stderr and never the
//! text, so the instant a step fails its log exists in exactly one place: this
//! terminal. So `--execute` says what it saw, at the moment it saw it — the failing
//! step's streams by default (the `--logs` flag moves that line), a reading
//! of the exit code where one has a reading ([`gitiup_run::diagnose`]), and a
//! `checked / re-hashed / sandbox / logs` block saying what this command checked about
//! its own bookkeeping before it handed the bytes over.
//!
//! A failed step also ends the command with **exit 10**. That is not a `6`: nothing was
//! refused, the run happened, and the attestation says so honestly. It is not a `0`
//! either, because "the tests failed" and "the tests passed" must not be the same
//! number to the caller that decides what to do next.
//!
//! # Exit codes
//!
//! The same taxonomy as `gitiup digest` (ADR-0001 D7), so a merge gate branches on
//! one set of numbers: 0 ok · 2 usage · 3 I/O · 6 refused (tier, sandbox, or an
//! ambiguous selection) · 8 mismatch · 10 a step in the run failed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use gitiup_attest::run::{Material, RunReport, WorkflowSource};
use gitiup_attest::{
    Digest, EnvironmentRequirement, ErrorKind, GitOid, InputValue, POLICY_PATH_ENV, Policy,
    PolicyFile, RunManifest, StepOutcome, Tier, TimeUs,
};
use gitiup_run::act;
use gitiup_run::sandbox;
use gitiup_run::{
    Execution, MAX_MATRIX_ARMS, Plan, PlannedJob, Replay, Selector, Simulation, Workflow, diagnose,
    excerpt,
};

use crate::CliError;

const HELP: &str = "\
gitiup run — plan a workflow job; run it only with --execute

USAGE:
    gitiup run [OPTIONS] [JOB]
    gitiup run --job <id> [--job <id>]…
    gitiup run --all-jobs
    gitiup run --sandboxes

OPTIONS:
    -w, --workflow <path>   workflow to plan (default: the only file in
                            .github/workflows/)
        --job <id>          run this job (repeatable). The same thing as naming it
                            here — `gitiup run <job>` — and the spelling a change
                            record's job hint uses. Name two jobs and both run: each
                            one gets its own attestation, never one for the lot
        --all-jobs          every run the workflow would produce — every job, and
                            every arm of a matrix job — as one attestation each.
                            Each of them is byte-identical to running it on its own
        --matrix <k=v>      pin one matrix arm (repeatable). A job with a matrix
                            needs this: one attestation is one result
        --event <name>      which event to describe (default: the workflow's own
                            first trigger)
        --input <k=v>       workflow_dispatch input, name=value (repeatable)
        --commit <hex>      commit to attest (default: $GITIUP_COMMIT, then this
                            repository's HEAD)
        --run-id <hex>      pin the run id, so two runs of the same plan agree
        --secret <NAME>     name a secret for --execute (repeatable). A name, never
                            a value, and nothing reads it unless --execute does
        --replay-from <f>   reuse the step outputs of a prior run report (simulated
                            runs only)
        --execute           really run it, inside --sandbox, and attest as `local`
        --sandbox <name>    sandbox for --execute; if exactly one works here it is
                            used and named, otherwise this is required. `none` is
                            refused: an unconfined run earns no tier
        --sandboxes         list the sandboxes this build offers, then exit
        --engine <name>     with --execute: `gitiup` (the default — this build runs the
                            steps itself) or `act` (nektos/act runs the whole job in its
                            own container). `act` is the engine that understands `uses:`
                            steps, `services:` and the expression language; it is also a
                            containment gitiup does not own, so an attestation from it says
                            `sandbox: act` and a policy has to name `act` to accept one
                            (docs/act.md, ADR-0006)
        --act-image <l=img> with --engine act: the image for a `runs-on:` label
                            (repeatable: --act-image 'ubuntu-24.04=ghcr.io/img@sha256:…').
                            Required: without one act stops and asks a terminal which image
                            to pull, and a runner cannot answer
        --logs <when>       how much of a step's captured output to print (--execute
                            only): `failed` is the default and prints the streams of
                            the step that failed, `all` prints every step's, `none`
                            prints neither. The attestation stores the DIGEST of each
                            stream and not the text, so whatever this prints is the
                            only copy of that log that will ever exist — scrollback and
                            redirection are how you keep it
        --workdir <path>    directory to run in (default: the current one)
        --policy <path>     gate the attestation against a policy file (default:
                            $GITIUP_POLICY, then the built-in policy, which allows
                            `local` only)
        --json              print the canonical attestation manifest, not the plan
    -o, --out <path>        write the attestation manifest here (default: write
                            nothing at all; with more than one run, a directory to
                            write one manifest per run in). `gitiup attest push <file>
                            --sign` files it: the manifest is the attestation before
                            anybody has signed it
        --force             let --out overwrite an existing file
    -h, --help              this text

THE DEFAULT SIMULATES. Nothing is spawned, no network is touched, no secret is
read, nothing is written, and the attestation is `tier: simulated` — a plan, not
evidence. Running it for real, inside a sandbox that was probed first, is what
earns `tier: local`. There is no option that produces `quorum`: only a quorum of
independent verifiers may claim that, and the format rejects a single run that
tries.

Because a simulated attestation reads exactly like a real one, keeping one is the
gated step: with --out or --policy the policy runs, and the default policy refuses
a simulated attestation. Write `\"allow_simulated\": true` in a policy file to allow
one deliberately. The warning on stderr is printed either way.

More than one run is more than one attestation: with several runs selected, --json
prints one canonical manifest per line and --out must name a DIRECTORY, which gets
one manifest per run, named after the job and its matrix arm.

When a step fails, its stdout and stderr are printed here (the attestation carries
their digests, never their text) together with what the exit code means, and the
command exits 10 — the run happened and is attestable, but the step said no.

Exit codes: 0 ok · 2 usage · 3 I/O · 6 refused (tier, sandbox, ambiguous job) ·
8 mismatch · 10 a step in the run failed
";

/// Which thing runs the steps, decided once per command line (giti-ic0, ADR-0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Engine {
    /// This build: one process per step, inside a sandbox gitiup probed.
    #[default]
    Gitiup,
    /// nektos/act: the whole job, inside a container act starts.
    Act,
}

impl Engine {
    /// `gitiup` or `act`, in the words a refusal quotes back.
    fn parse(text: &str) -> Result<Engine, CliError> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" => Err(CliError::usage(
                "--engine needs a name: `gitiup` (the default) or `act`",
            )),
            "gitiup" | "giti" | "self" | "internal" => Ok(Engine::Gitiup),
            "act" => Ok(Engine::Act),
            other => Err(CliError::usage(format!(
                "--engine {other} is not an engine: `gitiup` runs the steps itself, `act` \
                 hands the job to nektos/act (https://nektosact.com)"
            ))),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Engine::Gitiup => "gitiup",
            Engine::Act => "act",
        }
    }
}

/// What the user asked for, once the flags are sorted out.
#[derive(Debug, Default)]
struct Options {
    workflow: Option<String>,
    /// The job named as a bare word: `gitiup run build`.
    job: Option<String>,
    /// The jobs named with `--job`, in the order given.
    jobs: Vec<String>,
    /// Every run the workflow would produce.
    all_jobs: bool,
    matrix: Vec<(String, String)>,
    event: Option<String>,
    inputs: Vec<(String, InputValue)>,
    commit: Option<String>,
    run_id: Option<String>,
    secrets: Vec<String>,
    replay_from: Option<String>,
    execute: bool,
    sandbox: Option<String>,
    list_sandboxes: bool,
    /// Which engine runs the steps; see [`Engine`].
    engine: Option<String>,
    /// `--act-image` mappings: `runs-on` label → image.
    act_images: Vec<(String, String)>,
    /// How much step output to print; see [`LogMode`].
    logs: Option<String>,
    workdir: Option<PathBuf>,
    policy: Option<String>,
    json: bool,
    out: Option<PathBuf>,
    force: bool,
    help: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, CliError> {
        let mut options = Options::default();
        let mut index = 0usize;
        while index < args.len() {
            let arg = args[index].clone();
            index += 1;
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) => (name.to_string(), Some(value.to_string())),
                None => (arg.clone(), None),
            };
            let mut value = || -> Result<String, CliError> {
                if let Some(value) = inline.clone() {
                    return Ok(value);
                }
                if index < args.len() {
                    let value = args[index].clone();
                    index += 1;
                    return Ok(value);
                }
                Err(CliError::usage(format!("{name} needs a value")))
            };
            match name.as_str() {
                "-h" | "--help" | "help" => options.help = true,
                "-w" | "--workflow" => options.workflow = Some(value()?),
                "--job" => options.jobs.push(value()?),
                "--all-jobs" => options.all_jobs = true,
                "--matrix" => {
                    let text = value()?;
                    let (key, arm) = pair("--matrix", &text)?;
                    // A matrix value is a label, and labels are text on a runner
                    // too: `--matrix os=22` means "22", not 22.
                    options.matrix.push((key, input_text_of(&arm)));
                }
                "--input" => {
                    let text = value()?;
                    options.inputs.push(pair("--input", &text)?);
                }
                "--event" => options.event = Some(value()?),
                "--commit" => options.commit = Some(value()?),
                "--run-id" => options.run_id = Some(value()?),
                "--secret" => options.secrets.push(value()?),
                "--replay-from" => options.replay_from = Some(value()?),
                "--execute" => options.execute = true,
                "--sandbox" => options.sandbox = Some(value()?),
                "--sandboxes" => options.list_sandboxes = true,
                "--engine" => options.engine = Some(value()?),
                "--act-image" => {
                    let text = value()?;
                    let (label, image) = text.split_once('=').ok_or_else(|| {
                        CliError::usage(format!(
                            "`--act-image {text}` is not label=image (e.g. \
                             --act-image 'ubuntu-24.04=ghcr.io/img@sha256:…')"
                        ))
                    })?;
                    if label.trim().is_empty() || image.trim().is_empty() {
                        return Err(CliError::usage(format!(
                            "`--act-image {text}` needs both a label and an image"
                        )));
                    }
                    options
                        .act_images
                        .push((label.trim().to_string(), image.trim().to_string()));
                }
                "--logs" => options.logs = Some(value()?),
                "--workdir" => options.workdir = Some(PathBuf::from(value()?)),
                "--policy" => options.policy = Some(value()?),
                "--json" => options.json = true,
                "-o" | "--out" => options.out = Some(PathBuf::from(value()?)),
                "--force" => options.force = true,
                _ if name.starts_with('-') => {
                    return Err(CliError::usage(format!(
                        "unknown option '{name}' (there is no `--tier`: a run is simulated \
                         unless --execute earns `local`, and `quorum` is never a single \
                         run's to claim)"
                    )));
                }
                _ => {
                    if let Some(previous) = &options.job {
                        return Err(CliError::usage(format!(
                            "two jobs given ('{previous}' and '{name}'); one attestation is \
                             one job (name the ones you want with --job)"
                        )));
                    }
                    options.job = Some(name);
                }
            }
        }
        Ok(options)
    }

    /// The jobs named on the command line, in the order they were given, without
    /// repeats.
    ///
    /// `--job build` and `gitiup run build` are the same request in two spellings — the
    /// first is the one the change record's job hint, the plan's own refusals and
    /// `gitiup help` all use — so they merge into one list, bare word first. Saying the
    /// same job twice is a stutter and is said once. There is no override here: a bare
    /// word and a `--job` that differ ask for both jobs, which is what both readings of
    /// the command line agree on.
    fn named_jobs(&self) -> Result<Vec<String>, CliError> {
        if self.all_jobs && (self.job.is_some() || !self.jobs.is_empty()) {
            return Err(CliError::usage(
                "--all-jobs and --job say different things: one is every job the workflow \
                 has, the other names particular ones",
            ));
        }
        let mut named: Vec<String> = Vec::new();
        for name in self.job.iter().chain(self.jobs.iter()) {
            let name = name.trim();
            if name.is_empty() {
                return Err(CliError::usage(
                    "--job needs a job id, and this one is empty",
                ));
            }
            if !named.iter().any(|seen| seen == name) {
                named.push(name.to_string());
            }
        }
        Ok(named)
    }

    /// The `--logs` answer, or a usage error naming the three things it accepts.
    fn log_mode(&self) -> Result<LogMode, CliError> {
        match self.logs.as_deref() {
            None => Ok(LogMode::default()),
            Some(text) => LogMode::parse(text),
        }
    }

    /// The engine the command line asked for, with the checks only the engine choice
    /// can make (giti-ic0, ADR-0006).
    ///
    /// An engine is not a sandbox and the flags must not pretend otherwise: `act`
    /// contains nothing gitiup probed, so there is no `--sandbox` to name, and it only
    /// exists as an *execution* engine, so `--execute` is not optional.
    fn engine(&self) -> Result<Engine, CliError> {
        let engine = match &self.engine {
            Some(text) => Engine::parse(text)?,
            None => Engine::default(),
        };
        if engine == Engine::Act {
            if !self.execute {
                return Err(CliError::refused(
                    "--engine act without --execute: act is an execution engine, and a plan \
                     needs no engine at all",
                    "drop --engine (the default plans on its own) or run with --execute --engine act",
                ));
            }
            if self.sandbox.is_some() {
                return Err(CliError::refused(
                    "--engine act does not take a --sandbox: what contains the job is a \
                     container act starts, and the attestation says `sandbox: act` rather \
                     than borrowing a gitiup backend's name",
                    "drop --sandbox; `gitiup run --sandboxes` says what the gitiup engine offers",
                ));
            }
        } else if !self.act_images.is_empty() {
            return Err(CliError::refused(
                "--act-image names an image for the act engine, which was not asked for",
                "pass --engine act, or drop --act-image",
            ));
        }
        Ok(engine)
    }
}

/// How much of a step's captured output this command puts in front of the user.
///
/// The default is `failed` rather than `all` for one reason: a green run has nothing to
/// read, and a wall of routine output is what makes people stop reading the output of a
/// command that failed. `all` is there for the step that only misbehaves in context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum LogMode {
    /// The streams of the step that failed, and nothing else.
    #[default]
    Failed,
    /// Every step's streams, in the order they ran.
    All,
    /// Nothing: the exit codes and the digests only.
    None,
}

impl LogMode {
    fn parse(text: &str) -> Result<LogMode, CliError> {
        match text.trim().to_ascii_lowercase().as_str() {
            "failed" | "fail" | "failures" => Ok(LogMode::Failed),
            "all" | "everything" | "every" => Ok(LogMode::All),
            "none" | "nothing" | "off" => Ok(LogMode::None),
            other => Err(CliError::usage(format!(
                "`--logs {other}` is not a thing this command can print: --logs takes \
                 `failed` (the default), `all` or `none`"
            ))),
        }
    }
}

/// `--input`/`--matrix` values: `name=value`, with the same plain-scalar sense a
/// workflow file uses, so `--input jobs=4` is the number 4 and not the string "4".
fn pair(flag: &str, text: &str) -> Result<(String, InputValue), CliError> {
    let (name, value) = match text.split_once('=') {
        Some((name, value)) => (name, value),
        None => {
            return Err(CliError::usage(format!(
                "`{flag} {text}` is not name=value"
            )));
        }
    };
    if name.trim().is_empty() {
        return Err(CliError::usage(format!(
            "`{flag} {text}` has no name before the `=`"
        )));
    }
    let value = value.trim();
    let parsed = if value == "true" {
        InputValue::Bool(true)
    } else if value == "false" {
        InputValue::Bool(false)
    } else if let Ok(number) = value.parse::<i64>() {
        InputValue::Int(number)
    } else {
        InputValue::Text(value.to_string())
    };
    Ok((name.trim().to_string(), parsed))
}

fn input_text_of(value: &InputValue) -> String {
    match value {
        InputValue::Text(text) => text.clone(),
        InputValue::Int(number) => number.to_string(),
        InputValue::Bool(flag) => flag.to_string(),
    }
}

/// What a run produced: the attestation, the report behind it, and how honest the
/// command has to be about it.
struct Outcome {
    plan: Plan,
    job: PlannedJob,
    manifest: RunManifest,
    /// The report behind the manifest: the step text the manifest only carries a digest
    /// of, and the timings the manifest does not carry at all. Kept because the terminal
    /// is the one and only copy of that text.
    report: RunReport,
    executed: bool,
    /// The two digests, computed once: `run` is the name of the attestation,
    /// `result` is what two verifiers compare.
    run_digest: String,
    result_digest: String,
}

impl Outcome {
    /// One run's attestation, digests and all: the report is folded into the manifest
    /// exactly the way it is when one job is run alone.
    fn new(run: &Requested, report: &RunReport, executed: bool) -> Result<Outcome, CliError> {
        let manifest = gitiup_run::manifest_for(report)?;
        let (run_digest, result_digest) = digests(&manifest)?;
        Ok(Outcome {
            plan: run.plan.clone(),
            job: run.job.clone(),
            manifest,
            report: report.clone(),
            executed,
            run_digest,
            result_digest,
        })
    }

    /// `build`, or `build [os=linux]` — the run, named the way the reader named it.
    fn label(&self) -> String {
        format!("{}{}", self.job.id, self.job.arm_text())
    }

    fn tier(&self) -> Tier {
        self.manifest.result.provenance.tier
    }

    /// The loud warning. Deliberately not subtle and not optional: the whole point
    /// of the tier is that a simulated attestation *looks* like a result.
    fn warnings(&self) -> Vec<String> {
        // The sentence itself comes from the format crate, so the warning a library
        // caller sees and the warning this command prints cannot drift apart.
        let Some(warning) = gitiup_run::warning_for(self.tier()) else {
            return Vec::new();
        };
        vec![
            format!("WARNING: {warning}"),
            "WARNING: do not merge, publish, or release on the strength of a simulated attestation.".to_string(),
            "WARNING: to run it for real: gitiup run --execute --sandbox <name>              (that is what attests as `local`; `quorum` is a verdict of independent              verifiers, never of one run). `--sandboxes` lists what this machine offers;              `gitiup doctor --sandbox` says why one of them does not work.".to_string(),
        ]
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        if self.executed {
            // An executed run leads with what happened, in order, with the exit codes
            // that were observed — the plan text would be the less interesting answer.
            let _ = writeln!(
                out,
                "ran job {}{} in {}",
                self.job.id,
                self.job.arm_text(),
                self.manifest
                    .result
                    .provenance
                    .sandbox
                    .as_deref()
                    .unwrap_or("?")
            );
            for (index, step) in self.manifest.result.steps.iter().enumerate() {
                // A skipped step must not read as a passing one: the report gives it
                // exit code 0 because it never ran, and "exit 0" on a line a reader
                // skims is a green tick that was never earned.
                let verdict = match step.outcome {
                    StepOutcome::Skipped => "skipped (an earlier step failed)".to_string(),
                    StepOutcome::Failure => format!("exit {} · FAILED", step.exit_code),
                    StepOutcome::Success => format!("exit {}", step.exit_code),
                };
                let _ = writeln!(out, "  {:>2}. {} — {verdict}", index + 1, step.name);
            }
            // The notes the run collected while it happened — an unexpanded `${{ … }}`, a
            // stream truncated before hashing, a step killed by a signal instead of
            // exiting. They are in the attestation's annotations; repeating them here is
            // the difference between a reader seeing them and not.
            if let Some(notes) = self.report.claims.annotations.get("x_run_notes") {
                for note in notes.split(" · ") {
                    out.push_str(&field("note", note));
                    out.push('\n');
                }
            }
        } else {
            out.push_str(&self.plan.describe());
        }
        let source = &self.manifest.result.source;
        let _ = writeln!(out, "commit         {}", source.commit);
        let _ = writeln!(
            out,
            "sandbox        {}",
            self.manifest
                .result
                .provenance
                .sandbox
                .as_deref()
                .unwrap_or("(none)")
        );
        let _ = writeln!(out, "run            {}", self.run_digest);
        let _ = writeln!(out, "result         {}", self.result_digest);
        let _ = writeln!(out, "tier           {}", self.tier());
        let _ = writeln!(
            out,
            "normalisation  v{}",
            self.manifest.result.provenance.normalisation_version
        );
        out
    }

    /// What this command checked about the run before handing the bytes over.
    ///
    /// This is *not* the verification a gate does — that is `gitiup verify attestation`,
    /// with keys, a trust list and a policy in it. These are the producer's own sums:
    /// that every step the plan named is in the report, that the bytes a stranger would
    /// read are canonical and re-hash to both numbers printed above, that the sandbox
    /// the attestation names is the backend that actually ran, and what was hashed in
    /// place of the log text they cannot see. Anything failing here is a bug in this
    /// build, and comes out as exit 8 rather than as a line nobody reads.
    fn verification(&self, backend: Option<&str>) -> Result<Vec<String>, CliError> {
        if !self.executed {
            return Ok(Vec::new());
        }
        let planned: Vec<&str> = self
            .job
            .steps
            .iter()
            .map(|step| step.name.as_str())
            .collect();
        let reported: Vec<&str> = self
            .manifest
            .result
            .steps
            .iter()
            .map(|step| step.name.as_str())
            .collect();
        if planned != reported {
            return Err(CliError::new(
                ErrorKind::DigestMismatch,
                format!(
                    "job `{}`: the plan named {} steps and the attestation reports {} ({:?} \
                     against {:?})",
                    self.label(),
                    planned.len(),
                    reported.len(),
                    planned,
                    reported
                ),
                Some(
                    "a step went missing between the plan and the attestation: this run \
                     proves less than it claims, so nothing here should be trusted",
                ),
            ));
        }
        let ran = self
            .manifest
            .result
            .steps
            .iter()
            .filter(|step| step.outcome != StepOutcome::Skipped)
            .count();
        let failed = self
            .manifest
            .result
            .steps
            .iter()
            .filter(|step| step.outcome == StepOutcome::Failure)
            .count();
        let skipped = reported.len() - ran;
        let mut lines = vec![format!(
            "checked      {} step{} planned, {} reported: {failed} failed, {skipped} \
             skipped, and every step the plan named is in the attestation",
            planned.len(),
            if planned.len() == 1 { "" } else { "s" },
            reported.len()
        )];
        // The check a stranger can repeat: canonical bytes, re-parsed, re-validated, and
        // both digests recomputed from what the parse produced rather than from what
        // this command still holds in memory.
        let bytes = self.manifest.canonical_bytes()?;
        let again = RunManifest::from_canonical_bytes(&bytes).map_err(|why| {
            CliError::new(
                ErrorKind::DigestMismatch,
                format!("the attestation this run just wrote does not re-parse: {why}"),
                Some(
                    "this build wrote bytes it itself refuses; that is a bug, and the \
                     attestation should not leave this machine",
                ),
            )
        })?;
        let run_digest = again.digest()?.to_string();
        let result_digest = again.result_digest()?.to_string();
        if run_digest != self.run_digest || result_digest != self.result_digest {
            return Err(CliError::new(
                ErrorKind::DigestMismatch,
                format!(
                    "the digests printed above are not what the manifest's own bytes give: \
                     {run_digest} / {result_digest}"
                ),
                Some(
                    "a bug in this build, not in the workflow: the numbers a stranger \
                     recomputes would not match the ones handed to them",
                ),
            ));
        }
        lines.push(
            "re-hashed    the manifest's own canonical bytes re-parse, pass the format's \
             checks, and give back both digests above"
                .to_string(),
        );
        if let Some(name) = backend {
            lines.push(format!(
                "sandbox      {name} was probed immediately before the first step and is the \
                 name the attestation carries"
            ));
        }
        lines.push(format!(
            "logs         hashed as normalised text (v{}): the attestation carries the \
             digest of each stream, so what was printed above is the only copy of it",
            self.manifest.result.provenance.normalisation_version
        ));
        Ok(lines)
    }

    /// Everything this run says about its own streams, printed as it finished.
    ///
    /// The attestation a stranger keeps will contain the *digest* of these bytes and
    /// never the bytes, so this printout is the only copy of the log that will ever
    /// exist; the last line says so, because a person who was hoping to `attest show`
    /// their way back to a failed step's stderr is going to be disappointed later.
    ///
    /// Failures are printed in `Failed` mode (the default) and in `All` mode; in `All`
    /// mode every step's streams come out, which is the only way to see the step that
    /// was fine but printed the warning three steps before the one that died.
    fn output_report(&self, mode: LogMode) -> Vec<String> {
        let mut lines = Vec::new();
        let failures = self
            .report
            .steps
            .iter()
            .filter(|step| step.outcome == Some(StepOutcome::Failure))
            .count();
        if mode == LogMode::None {
            if failures > 0 {
                let noun = if failures == 1 { "step" } else { "steps" };
                lines.push(field(
                    "note",
                    &format!(
                        "--logs none: the output of the {failures} failing {noun} was not \
                         printed, and the attestation stores only the digest of it. Drop \
                         --logs (or pass --logs failed) to read the reason."
                    ),
                ));
            }
            return lines;
        }
        for (index, step) in self.report.steps.iter().enumerate() {
            let number = index + 1;
            let failed = step.outcome == Some(StepOutcome::Failure);
            if !failed && mode == LogMode::Failed {
                continue;
            }
            let stderr = Outcome::stream_text(&step.stderr).unwrap_or_default();
            if failed {
                lines.push(field(
                    "FAILED",
                    &format!(
                        "job `{}` step {number} '{}' — exit {}",
                        self.label(),
                        step.name,
                        step.exit_code
                    ),
                ));
                if let Some(reading) = diagnose(step.exit_code, &stderr) {
                    lines.push(field("why", &reading.cause));
                    if let Some(hint) = reading.hint {
                        lines.push(field("hint", &hint));
                    }
                }
            }
            for (which, material) in [("stderr", &step.stderr), ("stdout", &step.stdout)] {
                let Some(text) = Outcome::stream_text(material) else {
                    continue;
                };
                if text.trim().is_empty() {
                    continue;
                }
                lines.push(format!(
                    "{:<width$}step {number} '{}' {which} — {} bytes, hashed into the \
                     attestation as a digest",
                    "log",
                    step.name,
                    text.chars().count(),
                    width = 13
                ));
                let body = excerpt(&text);
                for line in body.trim_end().lines() {
                    lines.push(format!("  | {line}"));
                }
            }
        }
        if failures > 0 {
            lines.push(field(
                "note",
                "the attestation carries the digest of every stream above and none of the \
                 text: what was just printed is the only copy of this log there will \
                 ever be, so redirect it, or keep --out so at least the digests survive",
            ));
        }
        lines
    }

    /// The stream a step captured, as text this command can print.
    ///
    /// `execute` hands over text, so the pre-hashed arms are only reachable through a
    /// report somebody else produced (`--replay-from`), where there is no text to give.
    fn stream_text(material: &Material) -> Option<String> {
        match material {
            Material::Text(text) => Some(text.clone()),
            Material::Parts(parts) => Some(parts.join("")),
            Material::Digest(_) | Material::Files(_) => None,
        }
    }
}

/// Print what a run captured, at the moment it stops existing anywhere else.
///
/// The attestation carries the digest of each stream and never the text, so whatever
/// this prints is the only copy of that log there will ever be; with `--json` stdout
/// belongs to the manifest, so the log goes to stderr instead. Both engines — gitiup's
/// own runner and act — are printed here, before the policy gate, so a run that a
/// policy then refuses still leaves its reason behind.
fn emit(outcome: &Outcome, mode: LogMode, json: bool) {
    for line in outcome.output_report(mode) {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

/// One `label      text` entry, wrapped under the label's column.
///
/// The report reads as a column of fields, and a hint long enough to wrap still has to
/// line up with them; the wrapped lines are what most people actually read.
fn field(label: &str, text: &str) -> String {
    const WIDTH: usize = 96;
    const COLUMN: usize = 13;
    let mut head = format!("{:width$}", label, width = COLUMN);
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let fits = line.is_empty()
            || head.chars().count() + line.chars().count() + 1 + word.chars().count() <= WIDTH;
        if !fits {
            out.push_str(&format!("{head}{line}\n"));
            head = " ".repeat(COLUMN);
            line = word.to_string();
            continue;
        }
        if line.is_empty() {
            line.push_str(word);
        } else {
            line.push(' ');
            line.push_str(word);
        }
    }
    out.push_str(&format!("{head}{line}\n"));
    out.trim_end_matches('\n').to_string()
}

/// Both digests, or the reason there are none.
fn digests(manifest: &RunManifest) -> Result<(String, String), CliError> {
    Ok((
        manifest.digest()?.to_string(),
        manifest.result_digest()?.to_string(),
    ))
}

/// One run this command was asked to produce: the plan it came from, and the run.
///
/// The plan travels with the run because the plan text is what a simulated run prints
/// and because the plan's caveats go into the attestation's annotations. Keeping them
/// together per run is what makes `gitiup run --all-jobs` produce byte-for-byte what
/// the same run produces when somebody pins it by hand.
struct Requested {
    plan: Plan,
    job: PlannedJob,
}

impl Requested {
    /// `build`, or `build [os=linux]`: how one run is referred to in every message.
    fn label(&self) -> String {
        format!("{}{}", self.job.id, self.job.arm_text())
    }
}

/// The runs this invocation asked for, in the order they were asked for, one per
/// attestation.
///
/// Three shapes of request, and only one of them is a guess refused:
///
/// * nothing named — the workflow's single job, or a refusal that lists the jobs and
///   says how to name one;
/// * `--job <id>` (repeatable, and the same as the positional spelling) — those jobs,
///   each still needing its matrix arm pinned, because widening one named job into six
///   runs is not what "run the build job" said;
/// * `--all-jobs` — every run the workflow would produce, every job and every arm,
///   each planned exactly as if it had been pinned by hand.
fn plan_runs(workflow: &Workflow, options: &Options) -> Result<Vec<Requested>, CliError> {
    let pin: BTreeMap<String, String> = options.matrix.iter().cloned().collect();
    let named = options.named_jobs()?;
    let mut runs: Vec<Requested> = Vec::new();
    if options.all_jobs {
        for job in &workflow.jobs {
            let wide = Plan::build(
                workflow,
                &Selector {
                    job: Some(job.id.clone()),
                    matrix: pin.clone(),
                },
            )?;
            let arms = wide
                .jobs
                .iter()
                .map(|planned| planned.matrix.clone())
                .collect::<Vec<_>>();
            for arm in arms {
                // One plan per arm, pinned: the annotations a hand-pinned run carries
                // are this run's, not the whole job's.
                let plan = Plan::build(
                    workflow,
                    &Selector {
                        job: Some(job.id.clone()),
                        matrix: arm,
                    },
                )?;
                let planned = select_job(&plan)?.clone();
                runs.push(Requested { plan, job: planned });
            }
        }
    } else if named.is_empty() {
        let plan = Plan::build(
            workflow,
            &Selector {
                job: None,
                matrix: pin.clone(),
            },
        )
        .map_err(|why| offer_all_jobs(workflow, CliError::from(why)))?;
        let job = select_job(&plan)?.clone();
        runs.push(Requested { plan, job });
    } else {
        for name in &named {
            let plan = Plan::build(
                workflow,
                &Selector {
                    job: Some(name.clone()),
                    matrix: pin.clone(),
                },
            )?;
            let job = select_job(&plan)?.clone();
            runs.push(Requested { plan, job });
        }
    }
    if runs.is_empty() {
        return Err(CliError::refused(
            "this workflow plans no job",
            "a workflow needs at least one job with steps",
        ));
    }
    if runs.len() > MAX_MATRIX_ARMS {
        return Err(CliError::refused(
            format!(
                "{} runs would be planned — more than {MAX_MATRIX_ARMS} attestations for \
                 one command line, which is a mistake about the matrix rather than a build",
                runs.len()
            ),
            "narrow it: --job <id> for the jobs you meant, --matrix k=v for one arm",
        ));
    }
    Ok(runs)
}

/// The sandbox `--execute` will confine the run with, decided once per command line.
///
/// The ticket says `--execute` requires an explicit sandbox. What that must mean is:
/// the attestation may never be vague about what confined it, and it may never silently
/// pick a confinement out of several on offer. So a named backend is used as given;
/// where exactly one backend works here it is used and *said*; where several do, the
/// choice is the user's to make.
fn choose_sandbox(options: &Options) -> Result<String, CliError> {
    if let Some(name) = options.sandbox.as_deref() {
        return Ok(name.to_string());
    }
    let available: Vec<String> = sandbox::detect()
        .into_iter()
        .filter(|backend| backend.available)
        .map(|backend| backend.name)
        .collect();
    match available.as_slice() {
        // The ticket's other half: with nothing holding, nothing runs. A default of
        // "just pick one anyway" would be the unconfined execution this command exists
        // to refuse.
        [] => Err(CliError::refused(
            "no sandbox on this machine holds, so there is nothing to run the step in",
            "run `gitiup doctor --sandbox` to see which rung failed and what to                              install or set; until then `gitiup run` plans and attests as                              `simulated`, which is the safe default",
        )),
        [only] => {
            println!(
                "sandbox        {only} (the only one this machine offers; name it with --sandbox to be explicit)"
            );
            Ok(only.clone())
        }
        many => Err(CliError::refused(
            format!(
                "{} sandboxes work here ({}), and --execute must say which one confined the run",
                many.len(),
                many.join(", ")
            ),
            "pass --sandbox <name> (see --sandboxes)",
        )),
    }
}

/// When a workflow has several jobs and nothing was named, the library's refusal names
/// `--job`; this command has one more answer than the library does, so it adds it.
fn offer_all_jobs(workflow: &Workflow, mut error: CliError) -> CliError {
    if workflow.jobs.len() > 1
        && let Some(hint) = error.hint.as_mut()
    {
        hint.push_str(" — or pass --all-jobs to run every one of them, one attestation each");
    }
    error
}

/// A failure from one run of several, saying *which* run it came from.
fn for_job(many: bool, label: &str, mut error: CliError) -> CliError {
    if many {
        error.message = format!("job `{label}`: {}", error.message);
    }
    error
}

/// The gate for one produced attestation: does the policy in force let it through?
fn gate(policy: &Policy, outcome: &Outcome, many: bool) -> Result<(), CliError> {
    policy
        .check_provenance(&outcome.manifest.result.provenance)
        .map_err(|why| for_job(many, &outcome.label(), CliError::from(why)))?;
    // The machine class the change requires (giti-1rs.4). A plan is held to less of
    // it, because a plan honestly claims no image digest and no toolchain inventory —
    // refusing a plan for the fields it refuses to invent would teach everyone to
    // stop reading the notes.
    let Some(requirement) = policy.environment_requirement() else {
        return Ok(());
    };
    let (asked, _) = if outcome.executed {
        (requirement.clone(), Vec::new())
    } else {
        plan_view(requirement)
    };
    if asked.is_empty() {
        return Ok(());
    }
    asked
        .check(
            &outcome.manifest.result.environment,
            &outcome.manifest.result.provenance,
            policy.require_env_match,
        )
        .map_err(|why| for_job(many, &outcome.label(), CliError::from(why)))
}

/// Several attestations, one file each, in the directory `--out` named.
///
/// One attestation is one result, so there is no such thing as "the file" when a
/// command produced three; `--out` names a directory instead and every run gets a
/// manifest named after itself. Nothing is overwritten without `--force`, same rule,
/// once per file.
fn write_attestations(dir: &Path, outcomes: &[Outcome], force: bool) -> Result<(), CliError> {
    if dir.exists() && !dir.is_dir() {
        return Err(CliError::refused(
            format!(
                "`{}` is a file, and {} attestations do not fit in one file",
                dir.display(),
                outcomes.len()
            ),
            "name a directory with --out, or run one job at a time with --job <id>",
        ));
    }
    std::fs::create_dir_all(dir)
        .map_err(|why| CliError::io(format!("cannot create `{}`: {why}", dir.display())))?;
    let mut taken: BTreeSet<String> = BTreeSet::new();
    for outcome in outcomes {
        let path = dir.join(manifest_file_name(&outcome.job, &mut taken));
        write_attestation(&path, &outcome.manifest, force)?;
        println!("wrote        {}", path.display());
    }
    Ok(())
}

/// The file one run's attestation gets: its job, its matrix arm, `.json`.
///
/// Predictable on purpose — a second run of the same command overwrites the same
/// names (with `--force`), which is what makes a directory of attestations a cache of
/// a workflow rather than a pile of temporary files.
fn manifest_file_name(job: &PlannedJob, taken: &mut BTreeSet<String>) -> String {
    let mut stem = file_safe(&job.id);
    for (axis, value) in &job.matrix {
        stem.push('+');
        stem.push_str(&file_safe(axis));
        stem.push('=');
        stem.push_str(&file_safe(value));
    }
    // Two job ids that clean up to the same name are the workflow's fault, but the
    // second attestation is not allowed to silently eat the first.
    let mut name = format!("{stem}.json");
    let mut fork = 1;
    while !taken.insert(name.clone()) {
        fork += 1;
        name = format!("{stem}#{fork}.json");
    }
    name
}

/// Keep a name a filesystem will accept and a shell can quote: no slashes, no spaces,
/// no control characters — nothing but the label characters a job id is made of.
fn file_safe(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '=' | '+') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "run".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), CliError> {
    let options = Options::parse(args)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    if options.list_sandboxes {
        list_sandboxes();
        return Ok(());
    }
    let log_mode = options.log_mode()?;
    let engine = options.engine()?;

    let (workflow_path, workflow_text) = read_workflow(options.workflow.as_deref())?;
    let workflow = Workflow::parse(&workflow_path, &workflow_text)?;
    // The warnings belong to the user, not to this command: a `services:` block the
    // planner cannot model has to be said out loud, or the plan reads as though it
    // covered the services too.
    for warning in &workflow.warnings {
        eprintln!("warning: {warning}");
    }

    let runs = plan_runs(&workflow, &options)?;
    // Said before anything runs: one attestation is one result, so a workflow with
    // several jobs yields several attestations, and a reader should not find that out
    // from a file they did not ask for.
    let many = runs.len() > 1;
    if many {
        eprintln!(
            "note    {} runs, so {} attestations: one per run — never one attestation \
             about two runs (--json prints one manifest per line; --out names a directory \
             to write them in)",
            runs.len(),
            runs.len()
        );
    }

    let event = workflow.event_for(options.event.as_deref())?;
    let commit = resolve_commit(options.commit.as_deref())?;
    let source = WorkflowSource::from_text(workflow_path.clone(), workflow_text);
    let runner = format!("gitiup {}", env!("CARGO_PKG_VERSION"));
    // One clock for the command line, so two runs of one workflow claim the same
    // instant and the only thing that differs between them is the job.
    let clock = now_us()?;

    let mut outcomes: Vec<Outcome> = Vec::with_capacity(runs.len());
    // Which backend confined the run, kept for the report: "the attestation names the
    // sandbox that ran it" is a check this command can make, and only if it knows the
    // name independently of the attestation.
    let mut backend: Option<String> = None;
    // For the act engine there is no gitiup sandbox to name, and the honest line about
    // who ran the job takes its place in the checks printed under the result.
    let mut engine_note: Option<String> = None;
    let workdir = match &options.workdir {
        Some(path) => path.clone(),
        None => std::env::current_dir()
            .map_err(|why| CliError::io(format!("cannot tell what directory I am in: {why}")))?,
    };
    if options.execute {
        if engine == Engine::Act {
            // act is discovered, not assumed: the version it reports is recorded in the
            // attestation, because a run of unknown version proves nothing a stranger
            // can repeat.
            let act_engine = act::Engine::discover(None)?;
            engine_note = Some(format!(
                "engine       {name} {version} ran the job in its own container ({container}); \
                 gitiup watched act's exit code and read its log, and probed none of the \
                 containment it used",
                name = engine.name(),
                version = act_engine.version,
                container = act_engine.container
            ));
            for line in &act_engine.notes {
                eprintln!("warning: engine: {line}");
            }
            for run in &runs {
                let mut request = act::Request::new(
                    commit.clone(),
                    source.clone(),
                    workflow_path.clone(),
                    &workdir,
                );
                request.event = event.clone();
                request.inputs = options.inputs.clone();
                request.secret_names = options.secrets.clone();
                request.run_id = options.run_id.clone();
                request.now_us = Some(clock);
                request.images = options.act_images.clone();
                request.repo = None;
                let report = act::run(&run.job, &act_engine, &request)
                    .map_err(|why| for_job(many, &run.label(), CliError::from(why)))?;
                let outcome = Outcome::new(run, &report, true)?;
                emit(&outcome, log_mode, options.json);
                outcomes.push(outcome);
            }
        } else {
            // Open and probe before anything is spawned: `none`, a backend this build did
            // not implement, and a backend this machine cannot do are three different
            // refusals, and none of them may run a step on the way to saying so.
            let sandbox_name = choose_sandbox(&options)?;
            let sandbox = sandbox::open(&sandbox_name)?;
            sandbox.probe()?;
            let backend_name = sandbox.name().to_string();
            backend = Some(backend_name);
            // What the confinement decided, said before the first step rather than
            // inferred from its failure: the mounts it will ask for, where the job's
            // `/usr` comes from, and — on a Mac — the file-sharing rule that decides
            // whether the checkout is inside the container at all. These are the
            // sentences `gitiup doctor --sandbox` prints, read off the plan these very
            // steps will run under; a step that cannot find its own checkout or its own
            // compiler is a different conversation once the mounts are on the table.
            // Stderr, because `--json` owns stdout.
            if let Ok(scratch) = gitiup_run::scratch_dir(&clock) {
                for note in sandbox.plan_notes(&workdir, &scratch) {
                    eprintln!("{}", field("note", &format!("sandbox: {note}")));
                }
            }
            for run in &runs {
                let mut execution = Execution::new(
                    commit.clone(),
                    source.clone(),
                    sandbox.name(),
                    &workdir,
                    &runner,
                );
                execution.event = event.clone();
                execution.inputs = options.inputs.clone();
                execution.secret_names = options.secrets.clone();
                execution.run_id = options.run_id.clone();
                execution.now_us = Some(clock);
                let report = gitiup_run::execute(&run.plan, &run.job, &*sandbox, &execution)
                    .map_err(|why| for_job(many, &run.label(), CliError::from(why)))?;
                let outcome = Outcome::new(run, &report, true)?;
                // Printed here, at the moment the streams stop existing anywhere else,
                // and before the policy gate: a run that fails and is then refused by a
                // policy has to leave both the refusal and the reason behind.
                emit(&outcome, log_mode, options.json);
                outcomes.push(outcome);
            }
        }
    } else {
        if !options.secrets.is_empty() {
            return Err(CliError::refused(
                format!(
                    "--secret has nothing to do in a simulated run: {} named, and a \
                     simulation reads no environment at all",
                    options.secrets.join(",")
                ),
                "run with --execute --sandbox <name> to pass secrets for real, or drop --secret",
            ));
        }
        if options.logs.is_some() {
            return Err(CliError::refused(
                "--logs has nothing to print in a simulated run: no step ran, so no stream \
                 was captured",
                "drop --logs (a plan prints its own text already), or run with --execute \
                 --sandbox <name> to capture output for real",
            ));
        }
        let replay = match &options.replay_from {
            Some(path) => {
                let bytes = read_file(path)?;
                let report: RunReport = serde_json::from_slice(&bytes).map_err(|why| {
                    CliError::new(
                        ErrorKind::Invalid,
                        format!("`{path}` is not a run report: {why}"),
                        Some("pass the runner's report JSON — the file `gitiup digest` reads"),
                    )
                })?;
                // The provenance of the replay is the file's own digest: not a
                // verification (the tier has not moved), just a citation a reader can
                // check against the file they still have.
                Some(Replay::from_report(&report, Some(Digest::sha256(&bytes)))?)
            }
            None => None,
        };
        for run in &runs {
            let mut simulation = Simulation::new(commit.clone(), source.clone(), &runner);
            simulation.event = event.clone();
            simulation.inputs = options.inputs.clone();
            simulation.run_id = options.run_id.clone();
            simulation.now_us = Some(clock);
            simulation.matrix = run.job.matrix.clone();
            simulation.replay = replay.clone();
            let report = gitiup_run::simulate_report(&run.plan, &run.job, &simulation)?;
            let outcome = Outcome::new(run, &report, false)?;
            // A replayed report can carry a failing exit code, and a reader who sees
            // `exit 1` in a plan will look for the output that explains it. There is
            // none, and saying so is the whole of the answer.
            let failed: Vec<&str> = outcome
                .report
                .steps
                .iter()
                .filter(|step| step.exit_code != 0)
                .map(|step| step.name.as_str())
                .collect();
            if !failed.is_empty() {
                let line = field(
                    "note",
                    &format!(
                        "{} ({}) exited non-zero in the report being replayed. Nothing ran \
                         here, so there is no output to show: the exit code is a copy of \
                         somebody else's observation, and `--execute` is how you make \
                         your own",
                        if failed.len() == 1 { "step" } else { "steps" },
                        failed.join(", ")
                    ),
                );
                if options.json {
                    eprintln!("{line}");
                } else {
                    println!("{line}");
                }
            }
            outcomes.push(outcome);
        }
    }

    // The warning is about the tier, and every run of one command line shares it.
    for warning in outcomes[0].warnings() {
        eprintln!("{warning}");
    }

    // The gate. Kept attestations and asked-for policies are checked, and the default
    // policy allows `local` only — so a simulated attestation is refused here rather
    // than being quietly filed next to the real ones. Every run is judged, because a
    // gate that only looked at the first one would be a hole with a heading on it.
    let gated = options.out.is_some()
        || options.policy.is_some()
        || std::env::var_os(POLICY_PATH_ENV).is_some();
    if gated {
        let policy = load_policy(options.policy.as_deref())?;
        if let Some(requirement) = policy.environment_requirement()
            && outcomes.iter().any(|outcome| !outcome.executed)
        {
            let (_, skipped) = plan_view(requirement);
            if !skipped.is_empty() {
                eprintln!(
                    "note    a plan claims no {}; those parts of the environment \
                         requirement were not checked",
                    skipped.join(", ")
                );
            }
        }
        for outcome in &outcomes {
            gate(&policy, outcome, many)?;
        }
        // An act run names a containment gitiup did not probe, so it is only kept by an
        // owner who has said so by name. The built-in policy allows `local` and names no
        // sandbox, which is exactly the policy that must not swallow one: "any backend the
        // format accepts" is a reasonable default about backends gitiup probed, and act is
        // not one of them (ADR-0006).
        if engine == Engine::Act
            && options.out.is_some()
            && !policy
                .allowed_sandboxes
                .iter()
                .any(|name| name.eq_ignore_ascii_case(act::ENGINE))
        {
            return Err(CliError::refused(
                format!(
                    "this run would attest as `sandbox: {}`, which no policy has accepted",
                    act::ENGINE
                ),
                "an act run is contained by act, not by a gitiup sandbox: keep it only where the \
                 policy names it — write `\"allowed_sandboxes\": [\"docker\", \"act\"]` in the \
                 policy file you gate with, or drop --out and treat the run as local \
                 experimentation",
            ));
        }
    } else if engine == Engine::Act {
        eprintln!(
            "note    this run says `sandbox: {}`: act contained it, gitiup only launched act and \
             read its log. Nothing is filed, and a policy that does not name `{}` will refuse it \
             if you try",
            act::ENGINE,
            act::ENGINE
        );
    }

    // The producer's own sums, computed for every run whether or not anybody asked to
    // read them: a check that only runs on the pretty path would be a check that the
    // `--json` caller — the one scripting this — never gets.
    let mut checks: Vec<Vec<String>> = Vec::with_capacity(outcomes.len());
    for outcome in &outcomes {
        let mut lines = outcome.verification(backend.as_deref())?;
        if let Some(note) = &engine_note {
            lines.push(note.clone());
        }
        checks.push(lines);
    }
    // The one line that says what to do with what was just made, worded for whether a
    // file now exists to do it with.
    let next = if options.execute {
        match &options.out {
            Some(path) => {
                let path = path.display();
                match &options.policy {
                    Some(policy) => field(
                        "next",
                        &format!(
                            "gitiup verify attestation {path} --policy {policy} asks whether \
                             these bytes may be acted on (0 accepted · 6 refused · 7 bad \
                             signature · 8 digest mismatch); nothing here signed them, so \
                             `gitiup attest push {path} --sign` is what makes them \
                             somebody's proof"
                        ),
                    ),
                    None => field(
                        "next",
                        &format!(
                            "gitiup verify attestation {path} asks whether these bytes may be \
                             acted on, against the built-in policy unless --policy or \
                             $GITIUP_POLICY names another (0 accepted · 6 refused · 7 bad \
                             signature · 8 digest mismatch); nothing here signed them, so \
                             `gitiup attest push {path} --sign` is what makes them \
                             somebody's proof"
                        ),
                    ),
                }
            }
            None => field(
                "next",
                "nothing was written (--out names a file), so there is no attestation to \
                 verify yet: the digests above are what a stored one would have to \
                 reproduce, and `gitiup attest push <file> --sign` is what files it",
            ),
        }
    } else {
        String::new()
    };
    // Same lines either way; `--json` owes its stdout to the machine, so the human
    // reading of the run goes to stderr there.
    let say = |line: &str| {
        if options.json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    if options.json {
        // The canonical bytes, verbatim: re-encoding them here would be a second
        // opinion about the encoding, which is exactly what ADR-0001 refuses. With
        // more than one run that is one manifest per line — each line still the exact
        // bytes whose digest is printed beside it.
        for outcome in &outcomes {
            let text = String::from_utf8(outcome.manifest.canonical_bytes()?).map_err(|_| {
                CliError::io("the canonical attestation is not utf-8 (it should be)")
            })?;
            print!("{text}");
            if many {
                println!();
            }
        }
        for checks in &checks {
            for line in checks {
                say(line);
            }
            if !next.is_empty() {
                say(&next);
            }
        }
    } else {
        for (index, outcome) in outcomes.iter().enumerate() {
            if many {
                if index > 0 {
                    println!();
                }
                println!(
                    "run {} of {} — {}",
                    index + 1,
                    outcomes.len(),
                    outcome.label()
                );
            }
            print!("{}", outcome.to_text());
            for line in &checks[index] {
                println!("{line}");
            }
            if !next.is_empty() {
                println!("{next}");
            }
            if !outcome.executed {
                // What the plan had to assume, repeated here rather than only in the
                // attestation's annotations.
                for assumption in &outcome.job.assumptions {
                    println!("assumed    {assumption}");
                }
            }
        }
    }

    if let Some(path) = &options.out {
        if many {
            write_attestations(path, &outcomes, options.force)?;
        } else {
            write_attestation(path, &outcomes[0].manifest, options.force)?;
            println!("wrote        {}", path.display());
        }
    }

    // The run's own verdict, and the reason this command does not exit 0 beside a FAILED
    // step: a caller that branches on the exit code must not have to read prose to learn
    // the tests failed. 10 and not 6 because nothing was refused — the run happened, the
    // attestation says so honestly, and the step is what said no.
    let mut failed: Vec<String> = Vec::new();
    for outcome in outcomes.iter().filter(|outcome| outcome.executed) {
        for (index, step) in outcome.manifest.result.steps.iter().enumerate() {
            if step.outcome == StepOutcome::Failure {
                failed.push(format!(
                    "job `{}` step {}: '{}' exited {}",
                    outcome.label(),
                    index + 1,
                    step.name,
                    step.exit_code
                ));
            }
        }
    }
    if let Some(first) = failed.first() {
        let message = if failed.len() == 1 {
            first.clone()
        } else {
            format!(
                "{first}, and {} more failing step{} in this command line",
                failed.len() - 1,
                if failed.len() == 2 { "" } else { "s" }
            )
        };
        return Err(CliError::step_failed(
            message,
            format!(
                "exit 10 is the step's own verdict, not a refusal by gitiup: every step \
                 ran, the run is attestable, and the failure is part of what it attests. \
                 The failing step's output was printed with this command{} — the \
                 attestation carries only its digest, so keep the log if you need it \
                 later",
                if options.json {
                    " on stderr (--json keeps stdout for the manifest)"
                } else {
                    ""
                }
            ),
        ));
    }
    Ok(())
}

/// Exactly one planned run per attestation, or an error that says what to pin.
fn select_job(plan: &Plan) -> Result<&PlannedJob, CliError> {
    match plan.jobs.len() {
        1 => Ok(&plan.jobs[0]),
        0 => Err(CliError::refused(
            "this workflow plans no job",
            "a workflow needs at least one job with steps",
        )),
        many => Err(CliError::refused(
            format!(
                "{many} runs would be planned, and one attestation is one result: {}",
                plan.jobs
                    .iter()
                    .map(|job| format!("{}{}", job.id, job.arm_text()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "name the job (`gitiup run --job <id>`, or `gitiup run <job>`) and pin one \
             matrix arm (`--matrix k=v`) — or ask for all of them with `--all-jobs`, \
             which writes one attestation per run",
        )),
    }
}

/// The policy the answer is judged by: named, else `$GITIUP_POLICY`, else the
/// built-in default (`local` only).
fn load_policy(explicit: Option<&str>) -> Result<Policy, CliError> {
    let path = match explicit {
        Some(path) => Some(path.to_string()),
        None => std::env::var(POLICY_PATH_ENV)
            .ok()
            .filter(|text| !text.is_empty()),
    };
    let Some(path) = path else {
        return Ok(Policy::default());
    };
    let bytes = read_file(&path)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| CliError::io(format!("`{path}` is not utf-8 text")))?;
    PolicyFile::from_json(&text)
        .and_then(|file| file.to_policy())
        .map_err(CliError::from)
}

/// The part of an environment requirement a *plan* can be judged against, and the
/// names of what had to be dropped to get there.
///
/// A simulated run executes nothing, so it claims no image digest and inventories no
/// toolchain (see `gitiup_run::simulate`). Holding a plan to those fields would
/// refuse every plan a policy with an image pin ever sees, which is not a gate but a
/// bug; what a plan *does* claim — architecture, OS, runner, provider, and the
/// fingerprint of exactly those — is still checked, and the dropped fields are said
/// out loud rather than quietly excused.
fn plan_view(requirement: &EnvironmentRequirement) -> (EnvironmentRequirement, Vec<String>) {
    let mut asked = requirement.clone();
    let mut skipped = Vec::new();
    if asked.image_digest.take().is_some() {
        skipped.push("image digest".to_string());
    }
    if asked.image_reference.take().is_some() {
        skipped.push("image reference".to_string());
    }
    if !asked.toolchain.is_empty() {
        asked.toolchain.clear();
        skipped.push("toolchain inventory".to_string());
    }
    (asked, skipped)
}

/// One file per attestation, and never by accident.
fn write_attestation(path: &Path, manifest: &RunManifest, force: bool) -> Result<(), CliError> {
    if path.exists() && !force {
        return Err(CliError::refused(
            format!("`{}` already exists", path.display()),
            "pass --force to overwrite it, or choose another path with --out",
        ));
    }
    let bytes = manifest.canonical_bytes()?;
    std::fs::write(path, &bytes)
        .map_err(|why| CliError::io(format!("cannot write `{}`: {why}", path.display())))
}

/// The workflow to plan: the one named, or the one file the repository has.
fn read_workflow(explicit: Option<&str>) -> Result<(String, String), CliError> {
    if let Some(path) = explicit {
        let text = String::from_utf8(read_file(path)?)
            .map_err(|_| CliError::io(format!("{path} is not utf-8 text")))?;
        return Ok((path.to_string(), text));
    }
    let dir = Path::new(".github/workflows");
    let mut found: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let extension = path.extension().and_then(|e| e.to_str());
            if extension == Some("yml") || extension == Some("yaml") {
                found.push(path);
            }
        }
    }
    found.sort();
    match found.as_slice() {
        [] => Err(CliError::refused(
            "no workflow found in .github/workflows/",
            "pass --workflow <path>",
        )),
        [only] => {
            let path = only.display().to_string();
            let text = String::from_utf8(read_file(&path)?)
                .map_err(|_| CliError::io(format!("{path} is not utf-8 text")))?;
            Ok((path, text))
        }
        many => Err(CliError::refused(
            format!(
                "{} workflows in .github/workflows/, and one attestation covers one job",
                many.len()
            ),
            format!(
                "pass --workflow <path>, e.g. --workflow {}",
                many[0].display()
            ),
        )),
    }
}

/// Read a file the way the rest of this command does: a missing file is I/O (3), and
/// the message names the path.
fn read_file(path: &str) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|why| CliError::io(format!("cannot read `{path}`: {why}")))
}

/// The commit the attestation will name.
///
/// Taken from the repository where possible, because a plan that names the wrong
/// commit is an attestation about nothing. `$GITIUP_COMMIT` and `$GITHUB_SHA` are
/// honoured for a runner that already knows.
fn resolve_commit(explicit: Option<&str>) -> Result<GitOid, CliError> {
    if let Some(text) = explicit {
        return Ok(text.parse()?);
    }
    for variable in ["GITIUP_COMMIT", "GITHUB_SHA"] {
        if let Ok(value) = std::env::var(variable) {
            let value = value.trim();
            if !value.is_empty() {
                return value.parse().map_err(|why| {
                    CliError::new(
                        ErrorKind::Invalid,
                        format!("${variable} is not a commit id: {why}"),
                        None,
                    )
                });
            }
        }
    }
    repository_head().ok_or_else(|| {
        CliError::refused(
            "cannot tell which commit this is: no .git/HEAD in this directory",
            "pass --commit <hex> (or set GITIUP_COMMIT) so the attestation names one",
        )
    })
}

/// `HEAD` straight out of `.git`, with no `git` subprocess: a `ref:` line, then the
/// loose ref, then `packed-refs`. Read-only, which is the point — the default path
/// stays read-only.
fn repository_head() -> Option<GitOid> {
    repository_head_in(Path::new("."))
}

/// The same, for a directory that is not the current one — `gitiup work` has to know
/// which commit a checkout it was not asked to create is on.
pub(crate) fn repository_head_in(dir: &Path) -> Option<GitOid> {
    let git = dir.join(".git");
    let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    let candidate = if let Some(reference) = head.strip_prefix("ref: ") {
        let loose = git.join(reference);
        std::fs::read_to_string(&loose).ok().or_else(|| {
            let packed = std::fs::read_to_string(git.join("packed-refs")).ok()?;
            packed.lines().find_map(|line| {
                let (oid, name) = line.split_once(' ')?;
                (name.trim() == reference).then(|| oid.to_string())
            })
        })?
    } else {
        head.to_string()
    };
    GitOid::from_sha1_hex(candidate.trim()).ok()
}

/// The clock the attestation will claim. `SOURCE_DATE_EPOCH` is honoured because it
/// is the one convention reproducible builds already agree on: pin it and two runs of
/// the same plan agree to the microsecond.
fn now_us() -> Result<i64, CliError> {
    if let Ok(text) = std::env::var("SOURCE_DATE_EPOCH") {
        let seconds: i64 = text.trim().parse().map_err(|why| {
            CliError::new(
                ErrorKind::Invalid,
                format!("SOURCE_DATE_EPOCH is not a second count: {why}"),
                None,
            )
        })?;
        return Ok(TimeUs::from_secs(seconds).0);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_micros() as i64)
        .map_err(|why| {
            CliError::new(
                ErrorKind::Invalid,
                format!("this machine's clock is before the epoch: {why}"),
                Some("set SOURCE_DATE_EPOCH to pin the claimed time"),
            )
        })
}

fn list_sandboxes() {
    println!("sandboxes this build offers:");
    for backend in sandbox::detect() {
        println!(
            "  {:<9} {:<11} {}",
            backend.name,
            if backend.available {
                "available"
            } else {
                "unavailable"
            },
            backend.note
        );
        // The reason a backend is out is worth one more line if it has a cure: an
        // unavailable docker on a Mac is usually a `docker pull` away from working, and
        // a person should not have to know that.
        if let Some(fix) = &backend.fix {
            println!("  {:<9} {:<11} fix: {fix}", "", "");
        }
    }
    println!(
        "  (with none available there is no --execute: a simulated plan is the only \
         tier on offer, and it says so)"
    );
    let (available, note) = act::status();
    println!("engines this build can hand a job to:");
    println!("  gitiup    available   one process per step, in the sandbox named above");
    println!(
        "  {:<9} {:<11} {}",
        act::ENGINE,
        if available {
            "available"
        } else {
            "unavailable"
        },
        note
    );
    println!(
        "  (act runs the `uses:` steps and services gitiup's own runner refuses to guess \
         at; it is contained by act, so an attestation from it says `sandbox: act` and a \
         policy has to name that — see docs/act.md)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_no_flag_for_the_tier() {
        // "quorum can never be set by a single plain run" is enforced here as well as
        // in the format: this surface has no knob for it, and says so when hunted for.
        for flag in ["--tier", "--attest-tier", "--quorum", "--simulated"] {
            let error = Options::parse(&[flag.into(), "quorum".into()]).unwrap_err();
            assert_eq!(error.code, 2, "{flag}");
            assert!(
                error.message.contains("quorum"),
                "the refusal should explain itself: {}",
                error.message
            );
        }
    }

    #[test]
    fn logs_takes_exactly_three_words_and_says_so() {
        for (text, mode) in [
            ("failed", LogMode::Failed),
            ("fail", LogMode::Failed),
            ("all", LogMode::All),
            ("none", LogMode::None),
            ("NONE", LogMode::None),
        ] {
            assert_eq!(LogMode::parse(text).unwrap(), mode, "{text}");
        }
        let error = LogMode::parse("sometimes").unwrap_err();
        assert_eq!(error.code, 2);
        for word in ["failed", "all", "none"] {
            assert!(error.message.contains(word), "{}", error.message);
        }
        // Not asking is the default, and the default is the one that shows a failure.
        assert_eq!(Options::default().log_mode().unwrap(), LogMode::Failed);
    }

    #[test]
    fn a_wrapped_report_line_keeps_its_column() {
        let wrapped = field(
            "hint",
            "a step's PATH is /usr/bin:/bin:/usr/local/bin and nothing else unless the \
             workflow says otherwise with env: PATH: — install the tool, or name the \
             directory it lives in on the job or the step",
        );
        let lines: Vec<&str> = wrapped.lines().collect();
        assert!(lines.len() > 1, "that hint is long enough to wrap");
        assert!(lines[0].starts_with("hint"), "{wrapped}");
        for line in &lines[1..] {
            assert!(line.starts_with(' '), "{line}");
            assert_eq!(&line[..13], "             ", "{line}");
        }
        assert!(wrapped.contains("the step"), "{wrapped}");
    }

    #[test]
    fn flags_take_values_either_way_and_repeat_where_that_means_something() {
        let options = Options::parse(&[
            "--workflow=ci.yml".into(),
            "build".into(),
            "--matrix".into(),
            "os=linux".into(),
            "--matrix=arch=x86_64".into(),
            "--secret".into(),
            "NPM_TOKEN".into(),
            "--input".into(),
            "jobs=4".into(),
            "--input=coverage=true".into(),
            "--input=name=gitiup".into(),
        ])
        .unwrap();
        assert_eq!(options.workflow.as_deref(), Some("ci.yml"));
        assert_eq!(options.job.as_deref(), Some("build"));
        assert_eq!(
            options.matrix,
            vec![
                ("os".to_string(), "linux".to_string()),
                ("arch".to_string(), "x86_64".to_string())
            ]
        );
        assert_eq!(options.secrets, vec!["NPM_TOKEN"]);
        assert_eq!(
            options.inputs,
            vec![
                ("jobs".to_string(), InputValue::Int(4)),
                ("coverage".to_string(), InputValue::Bool(true)),
                ("name".to_string(), InputValue::Text("gitiup".to_string())),
            ]
        );
    }

    #[test]
    fn two_jobs_is_a_usage_error_because_one_attestation_is_one_result() {
        let error = Options::parse(&["build".into(), "deploy".into()]).unwrap_err();
        assert_eq!(error.code, 2);
        assert!(
            error.message.contains("one attestation"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_job_can_be_named_with_the_flag_the_rest_of_the_tool_advertises() {
        // `--job <id>` is the spelling ADR-0003 D9, `gitiup change new --job`, and this
        // command's own refusals all use, so it has to be the one the parser takes.
        for args in [vec!["--job", "build"], vec!["--job=build"], vec!["build"]] {
            let options = Options::parse(&strings(&args)).unwrap();
            assert_eq!(
                options.named_jobs().unwrap(),
                vec!["build".to_string()],
                "{args:?}"
            );
        }

        // Saying the same job twice is a stutter, not two requests.
        let options = Options::parse(&strings(&["--job", "build", "--job", "build"])).unwrap();
        assert_eq!(options.named_jobs().unwrap(), vec!["build".to_string()]);
    }

    #[test]
    fn several_jobs_are_asked_for_by_name_and_keep_their_order() {
        let options = Options::parse(&strings(&["--job", "deploy", "--job", "build"])).unwrap();
        assert_eq!(
            options.named_jobs().unwrap(),
            vec!["deploy".to_string(), "build".to_string()]
        );
    }

    #[test]
    fn one_job_two_spellings_is_one_job_and_two_spellings_naming_two_is_two() {
        let options = Options::parse(&strings(&["build", "--job", "build"])).unwrap();
        assert_eq!(
            options.named_jobs().unwrap(),
            vec!["build".to_string()],
            "the same job said twice is one run"
        );

        // A bare word and a `--job` that differ ask for both, in the order they were
        // written: both readings of the command line say the same thing.
        let options = Options::parse(&strings(&["build", "--job", "deploy"])).unwrap();
        assert_eq!(
            options.named_jobs().unwrap(),
            vec!["build".to_string(), "deploy".to_string()]
        );
    }

    #[test]
    fn every_job_or_some_jobs_is_asked_for_and_not_both() {
        let error = Options::parse(&strings(&["--all-jobs", "--job", "build"]))
            .unwrap()
            .named_jobs()
            .unwrap_err();
        assert_eq!(error.code, 2, "{}", error.message);
        assert!(error.message.contains("--all-jobs"), "{}", error.message);

        let options = Options::parse(&strings(&["--all-jobs"])).unwrap();
        assert!(options.all_jobs);
        assert!(options.named_jobs().unwrap().is_empty());
    }

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts() {
        for flag in [
            "--workflow",
            "--job",
            "--all-jobs",
            "--matrix",
            "--event",
            "--input",
            "--commit",
            "--run-id",
            "--secret",
            "--replay-from",
            "--execute",
            "--sandbox",
            "--sandboxes",
            "--logs",
            "--workdir",
            "--policy",
            "--json",
            "--out",
            "--force",
        ] {
            assert!(HELP.contains(flag), "{flag} is accepted but not documented");
        }
        // And the thing that made this command worth writing: the default is the safe
        // one, and the help says so where a reader will hit it first.
        assert!(HELP.contains("THE DEFAULT SIMULATES"));
    }

    #[test]
    fn a_directory_of_attestations_names_each_file_after_its_run() {
        let workflow = Workflow::parse(
            "ci.yml",
            "on: push\njobs:\n  build:\n    strategy:\n      matrix:\n        os: [linux, macos]\n    steps:\n      - run: make\n",
        )
        .unwrap();
        let plan = Plan::build(&workflow, &Selector::default()).unwrap();
        let mut taken = BTreeSet::new();
        let names: Vec<String> = plan
            .jobs
            .iter()
            .map(|job| manifest_file_name(job, &mut taken))
            .collect();
        assert_eq!(
            names,
            vec![
                "build+os=linux.json".to_string(),
                "build+os=macos.json".to_string()
            ],
            "one file per run, named so a rerun lands on the same name"
        );
    }

    #[test]
    fn a_file_name_is_a_file_name_whatever_a_job_is_called() {
        assert_eq!(file_safe("build"), "build");
        assert_eq!(file_safe("a/b c"), "a-b-c");
        assert_eq!(file_safe("../../etc/passwd"), "..-..-etc-passwd");
        assert_eq!(file_safe("///"), "run");
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn a_flag_needs_a_value_and_says_which_flag() {
        for flag in ["--matrix", "--secret", "--workflow", "--policy", "--out"] {
            let error = Options::parse(&[flag.into()]).unwrap_err();
            assert_eq!(error.code, 2, "{flag}");
            assert!(error.message.contains(flag), "{flag}: {}", error.message);
        }
    }

    #[test]
    fn the_head_of_a_repository_is_read_without_running_git() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        std::fs::create_dir_all(git.join("refs/heads")).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            git.join("refs/heads/main"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let head = repository_head();
        std::env::set_current_dir(previous).unwrap();
        assert_eq!(
            head.map(|oid| oid.to_string()),
            Some("sha1:".to_string() + &"a".repeat(40))
        );
    }

    #[test]
    fn a_pinned_epoch_is_the_clock_of_the_attestation() {
        unsafe { std::env::set_var("SOURCE_DATE_EPOCH", "1793092502") };
        let pinned = now_us().unwrap();
        unsafe { std::env::remove_var("SOURCE_DATE_EPOCH") };
        assert_eq!(pinned, TimeUs::from_secs(1_793_092_502).0);

        unsafe { std::env::set_var("SOURCE_DATE_EPOCH", "not-a-number") };
        let error = now_us().unwrap_err();
        unsafe { std::env::remove_var("SOURCE_DATE_EPOCH") };
        assert_eq!(error.code, 6);
    }

    #[test]
    fn the_default_policy_is_the_one_the_ticket_asked_for() {
        // Worth restating at the surface: the gate that `--out` and `--policy` run is
        // the built-in one, and it has never heard of simulated being good enough.
        let policy = Policy::default();
        assert!(policy.allows_tier(Tier::Local));
        assert!(!policy.allows_tier(Tier::Simulated));
        assert!(!policy.allows_tier(Tier::Quorum));
    }
}

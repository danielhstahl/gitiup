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
//! # Exit codes
//!
//! The same taxonomy as `gitiup digest` (ADR-0001 D7), so a merge gate branches on
//! one set of numbers: 0 ok · 2 usage · 3 I/O · 6 refused (tier, sandbox, or an
//! ambiguous selection) · 8 mismatch.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use gitiup_attest::run::{RunReport, WorkflowSource};
use gitiup_attest::{
    Digest, ErrorKind, GitOid, InputValue, POLICY_PATH_ENV, Policy, PolicyFile, RunManifest, Tier,
    TimeUs,
};
use gitiup_run::sandbox;
use gitiup_run::{Execution, Plan, PlannedJob, Replay, Selector, Simulation, Workflow};

use crate::CliError;

const HELP: &str = "\
gitiup run — plan a workflow job; run it only with --execute

USAGE:
    gitiup run [OPTIONS] [JOB]
    gitiup run --sandboxes

OPTIONS:
    -w, --workflow <path>   workflow to plan (default: the only file in
                            .github/workflows/)
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
        --workdir <path>    directory to run in (default: the current one)
        --policy <path>     gate the attestation against a policy file (default:
                            $GITIUP_POLICY, then the built-in policy, which allows
                            `local` only)
        --json              print the canonical attestation manifest, not the plan
    -o, --out <path>        write the attestation manifest here (default: write
                            nothing at all)
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

Exit codes: 0 ok · 2 usage · 3 I/O · 6 refused (tier, sandbox, ambiguous job) ·
8 mismatch
";

/// What the user asked for, once the flags are sorted out.
#[derive(Debug, Default)]
struct Options {
    workflow: Option<String>,
    job: Option<String>,
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
                             one job"
                        )));
                    }
                    options.job = Some(name);
                }
            }
        }
        Ok(options)
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
    executed: bool,
    /// The two digests, computed once: `run` is the name of the attestation,
    /// `result` is what two verifiers compare.
    run_digest: String,
    result_digest: String,
}

impl Outcome {
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
                let _ = writeln!(
                    out,
                    "  {:>2}. {} — exit {}",
                    index + 1,
                    step.name,
                    step.exit_code
                );
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
}

/// Both digests, or the reason there are none.
fn digests(manifest: &RunManifest) -> Result<(String, String), CliError> {
    Ok((
        manifest.digest()?.to_string(),
        manifest.result_digest()?.to_string(),
    ))
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

    let (workflow_path, workflow_text) = read_workflow(options.workflow.as_deref())?;
    let workflow = Workflow::parse(&workflow_path, &workflow_text)?;
    // The warnings belong to the user, not to this command: a `services:` block the
    // planner cannot model has to be said out loud, or the plan reads as though it
    // covered the services too.
    for warning in &workflow.warnings {
        eprintln!("warning: {warning}");
    }
    let selector = Selector {
        job: options.job.clone(),
        matrix: options.matrix.iter().cloned().collect(),
    };
    let plan = Plan::build(&workflow, &selector)?;
    let job = select_job(&plan)?.clone();

    let event = workflow.event_for(options.event.as_deref())?;
    let commit = resolve_commit(options.commit.as_deref())?;
    let source = WorkflowSource::from_text(workflow_path.clone(), workflow_text);
    let runner = format!("gitiup {}", env!("CARGO_PKG_VERSION"));

    let outcome = if options.execute {
        // Open and probe before anything is spawned: `none`, a backend this build did
        // not implement, and a backend this machine cannot do are three different
        // refusals, and none of them may run a step on the way to saying so.
        // The ticket says `--execute` requires an explicit sandbox. What that must
        // mean is: the attestation may never be vague about what confined it, and it
        // may never silently pick a confinement out of several on offer. So a named
        // backend is used as given; where exactly one backend works here it is used
        // and *said*; where several do, the choice is the user's to make.
        let sandbox_name = match options.sandbox.as_deref() {
            Some(name) => name.to_string(),
            None => {
                let available: Vec<String> = sandbox::detect()
                    .into_iter()
                    .filter(|backend| backend.available)
                    .map(|backend| backend.name)
                    .collect();
                match available.as_slice() {
                    // The ticket's other half: with nothing holding, nothing runs. A
                    // default of "just pick one anyway" would be the unconfined
                    // execution this command exists to refuse.
                    [] => {
                        return Err(CliError::refused(
                            "no sandbox on this machine holds, so there is nothing to run the step in",
                            "run `gitiup doctor --sandbox` to see which rung failed and what to                              install or set; until then `gitiup run` plans and attests as                              `simulated`, which is the safe default",
                        ));
                    }
                    [only] => {
                        println!(
                            "sandbox        {only} (the only one this machine offers; name it with --sandbox to be explicit)"
                        );
                        only.clone()
                    }
                    many => {
                        return Err(CliError::refused(
                            format!(
                                "{} sandboxes work here ({}), and --execute must say which one confined the run",
                                many.len(),
                                many.join(", ")
                            ),
                            "pass --sandbox <name> (see --sandboxes)",
                        ));
                    }
                }
            }
        };
        let sandbox = sandbox::open(&sandbox_name)?;
        sandbox.probe()?;
        let workdir = match options.workdir {
            Some(path) => path,
            None => std::env::current_dir().map_err(|why| {
                CliError::io(format!("cannot tell what directory I am in: {why}"))
            })?,
        };
        let mut execution = Execution::new(commit, source, sandbox.name(), &workdir, &runner);
        execution.event = event.clone();
        execution.inputs = options.inputs.clone();
        execution.secret_names = options.secrets.clone();
        execution.run_id = options.run_id.clone();
        execution.now_us = Some(now_us()?);
        let report = gitiup_run::execute(&plan, &job, &*sandbox, &execution)?;
        let manifest = gitiup_run::manifest_for(&report)?;
        let (run_digest, result_digest) = digests(&manifest)?;
        Outcome {
            manifest,
            plan,
            job,
            executed: true,
            run_digest,
            result_digest,
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
        let mut simulation = Simulation::new(commit, source, &runner);
        simulation.event = event.clone();
        simulation.inputs = options.inputs.clone();
        simulation.run_id = options.run_id.clone();
        simulation.now_us = Some(now_us()?);
        simulation.matrix = job.matrix.clone();
        if let Some(path) = &options.replay_from {
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
            simulation.replay = Some(Replay::from_report(&report, Some(Digest::sha256(&bytes)))?);
        }
        let report = gitiup_run::simulate_report(&plan, &job, &simulation)?;
        let manifest = gitiup_run::manifest_for(&report)?;
        let (run_digest, result_digest) = digests(&manifest)?;
        Outcome {
            manifest,
            plan,
            job,
            executed: false,
            run_digest,
            result_digest,
        }
    };

    for warning in outcome.warnings() {
        eprintln!("{warning}");
    }

    // The gate. Kept attestations and asked-for policies are checked, and the default
    // policy allows `local` only — so a simulated attestation is refused here rather
    // than being quietly filed next to the real ones.
    if options.out.is_some()
        || options.policy.is_some()
        || std::env::var_os(POLICY_PATH_ENV).is_some()
    {
        let policy = load_policy(options.policy.as_deref())?;
        policy.check_provenance(&outcome.manifest.result.provenance)?;
    }

    if options.json {
        // The canonical bytes, verbatim: re-encoding them here would be a second
        // opinion about the encoding, which is exactly what ADR-0001 refuses.
        let text = String::from_utf8(outcome.manifest.canonical_bytes()?)
            .map_err(|_| CliError::io("the canonical attestation is not utf-8 (it should be)"))?;
        print!("{text}");
    } else {
        print!("{}", outcome.to_text());
        if !outcome.executed {
            // What the plan had to assume, repeated here rather than only in the
            // attestation's annotations.
            for assumption in &outcome.job.assumptions {
                println!("assumed    {assumption}");
            }
        }
    }

    if let Some(path) = &options.out {
        write_attestation(path, &outcome.manifest, options.force)?;
        println!("wrote        {}", path.display());
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
            "name the job (`gitiup run <job>`) and pin one matrix arm (`--matrix k=v`)",
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
    let head = std::fs::read_to_string(".git/HEAD").ok()?;
    let head = head.trim();
    let candidate = if let Some(reference) = head.strip_prefix("ref: ") {
        let loose = Path::new(".git").join(reference);
        std::fs::read_to_string(&loose).ok().or_else(|| {
            let packed = std::fs::read_to_string(".git/packed-refs").ok()?;
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
    }
    println!(
        "  (with none available there is no --execute: a simulated plan is the only \
         tier on offer, and it says so)"
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

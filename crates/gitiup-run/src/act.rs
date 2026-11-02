//! The `act` engine: run the job with [nektos/act](https://nektosact.com) and attest
//! only to what *that* can stand behind (giti-ic0, ADR-0006).
//!
//! # Why this module exists, and what it is not
//!
//! `act` is years of GitHub-Actions runtime: it fetches `uses:` actions, runs node and
//! docker actions, starts `services:` containers, evaluates the expression language
//! and knows the `GITHUB_*` environment better than anything written here.
//! Re-implementing that is the wheel this ticket pointed at, and [`crate::exec`] is
//! honest about not having it: it refuses every `uses:` step.
//!
//! This module therefore *delegates the running*. It does not delegate the *claim*. A
//! gitiup attestation is a promise about who observed what, and act cannot supply
//! several of the observations gitiup's own runner makes:
//!
//! | [`crate::exec`] (gitiup's runner)              | the `act` engine                          |
//!|--------------------------------------------------|-------------------------------------------|
//!| exit codes come from `waitpid`                  | step results are parsed out of act's log   |
//!| confinement is a backend probed on this machine | confinement is whatever act's flags say    |
//!| egress is refused unless an allowlist was given | act's job container has the **host** network |
//!| the step's environment is built from nothing    | act builds it, from act's defaults + our flags |
//!| the step writes in the checkout                 | act copies the checkout in, so writes stay inside the container |
//!
//! So the report says `sandbox: act` — a name that is **not** one of the ladder's, on
//! purpose. [`gitiup_sandbox::policy::allows`] refuses a name it cannot open when the
//! policy named no sandboxes, and
//! [`gitiup_sandbox::policy::narrow`] refuses a policy that *lists* `act`, so a policy
//! for stranger's jobs can never be satisfied by an act run. An owner who wants act
//! attestations writes `"act"` into `allowed_sandboxes`, which is the moment they
//! accepted act's containment instead of gitiup's. The engine produces nothing but
//! `tier: local`, and a quorum seat never runs it (`gitiup work` only ever opens a
//! ladder backend).
//!
//! # What is refused before anything spawns
//!
//! act ignores parts of the workflow description — its own
//! [unsupported list](https://nektosact.com/not_supported.html) is the source. Where an
//! ignored feature would change the *result* (job- or step-level `continue-on-error`,
//! a step `timeout-minutes`, a job `environment:` whose secret scoping act does not
//! implement) this engine refuses rather than attest a run that disagrees with what
//! GitHub would have produced. Where the ignored thing is decoration (`concurrency`,
//! `permissions`, step summaries, annotations, problem matchers) it runs and annotates.
//!
//! # What the engine will not widen
//!
//! The argv is built here and nowhere else: the docker socket is never mounted into the
//! job, a workflow's own container options are restricted, gitignored files are not
//! copied, secrets travel as *names* (`-s NAME`, value from the environment) and never
//! as argv, and `--trust-project-actrc` is not available — a checkout must not be able
//! to steer the runner that attests it, which is also why a `.actrc` inside the
//! workspace is a refusal. There is no "pass an extra flag to act" option: an option
//! somebody can forget to read is a hole with a name on it.
//!
//! ```
//! use gitiup_run::act;
//!
//! // act prints `act version 0.2.94` and nothing else. The version goes into the
//! // attestation, because a run performed by an unknown version proves nothing a
//! // stranger can repeat.
//! let version = act::parse_version("act version 0.2.94").expect("act's own format");
//! assert_eq!(version.to_string(), "0.2.94");
//!
//! // One line of `act --json`, as act writes it.
//! let line = r#"{"job":"ci.yml/build","jobID":"build","level":"info","matrix":{},"msg":"  ✅  Success - build","step":"Build","stepResult":"success","time":"2026-11-01T12:00:00Z"}"#;
//! let events = act::parse_log(&format!("not json, and ignored: act prints a banner too\n{line}\n"));
//! assert_eq!(events.len(), 1);
//! assert_eq!(events[0].step_result.as_deref(), Some("success"));
//! assert_eq!(events[0].step.as_deref(), Some("Build"));
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gitiup_attest::run::{ClaimReport, EventReport, Material, StepReport, WorkflowSource};
use gitiup_attest::{
    Digest, Error, ErrorKind, GitOid, InputValue, Provenance, Result, RunReport, StepOutcome,
    StepTiming, Tier, TimeUs,
};

use crate::exec::MAX_LOG_BYTES;
use crate::plan::{PlannedJob, PlannedStep};
use crate::yaml::Mapping;

/// The name that lands in `provenance.sandbox`, and the name a policy has to name.
pub const ENGINE: &str = "act";

/// What the engine promises in the signed bytes, and what it refuses to promise.
///
/// Same shape as every backend's `guarantees`: a sentence a reviewer can act on, never
/// "sandboxed".
pub const GUARANTEES: &str = "a container act started with the docker socket unmounted and the \
                             workflow's own container options restricted; the job has the host \
                             network, act's image and act's user, and the checkout was copied \
                             in rather than mounted — gitiup probed none of act's containment, \
                             only that the binary and a container endpoint are here";

/// The wall clock gitiup enforces when the workflow does not ask for one.
///
/// act ignores `timeout-minutes`, so a hung job would hang its caller forever; the
/// process parent is the only party that can stop it, so the parent does. 360 minutes
/// is GitHub's own default, which keeps the two answers the same when neither was asked.
pub const DEFAULT_TIMEOUT_MINUTES: u64 = 360;

/// The environment variable that names the `act` binary.
pub const BINARY_ENV: &str = "GITIUP_ACT";

/// The flags act is always given, and why each one is there.
///
/// This list *is* the engine's containment claim; [`REFUSED_ARGS`] is the other half.
pub const FIXED_ARGS: [&str; 6] = [
    // Machine-readable instead of a coloured terminal to parse.
    "--json",
    // A job container that can drive the host's docker is not a container.
    "--container-daemon-socket",
    "-",
    // `--run: docker run --privileged` inside a workflow must not be a way out.
    "--container-options-policy",
    "restrict",
    // gitignored files are where a working tree keeps its `.env`.
    "--use-gitignore",
];

/// Flags that would widen what the engine promises.
///
/// There is no way to pass any of them; the list exists so the refusal can say which one
/// was tried, and so the next person to want one finds the wall rather than a hole.
pub const REFUSED_ARGS: [&str; 10] = [
    "--privileged",
    "--userns",
    "--container-options",
    "--container-cap-add",
    "--container-cap-drop",
    "--insecure-secrets",
    "--trust-project-actrc",
    "--secret-file",
    "--env-file",
    "--reuse",
];

/// act's own lifecycle steps: not steps of the workflow, so never steps of the report.
const LIFECYCLE: [&str; 3] = ["Set up job", "Complete job", "Post job"];

/// Environment passed to act itself, and nothing more: what a *step* sees is act's
/// business, so what act sees is gitiup's, and it is built from nothing.
const ACT_ENV: [&str; 8] = [
    "PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "LANG",
    "TERM",
];

/// The version line act prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The three numbers act printed.
    pub parts: (u32, u32, u32),
    /// Anything after the numbers (`-dev`, `+Homebrew`), kept because it identifies the
    /// build that ran.
    pub suffix: String,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.parts;
        write!(f, "{major}.{minor}.{patch}{}", self.suffix)
    }
}

impl Version {
    /// Whether this is at least `major.minor`.
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        (self.parts.0, self.parts.1) >= (major, minor)
    }

    /// Whether this is at least `major.minor.patch`.
    pub fn at_least_patch(&self, major: u32, minor: u32, patch: u32) -> bool {
        self.parts >= (major, minor, patch)
    }
}

/// Parse `act version 0.2.94`, or a bare `0.2.94`.
pub fn parse_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let rest = text
        .strip_prefix("act version")
        .or_else(|| text.strip_prefix("act"))
        .unwrap_or(text)
        .trim_start();
    let bytes = rest.as_bytes();
    let mut index = 0usize;
    let mut numbers: Vec<u32> = Vec::with_capacity(3);
    while numbers.len() < 3 {
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == start {
            break;
        }
        numbers.push(rest[start..index].parse().ok()?);
        if numbers.len() < 3 {
            if bytes.get(index) == Some(&b'.') {
                index += 1;
            } else {
                break;
            }
        }
    }
    if numbers.len() < 3 {
        return None;
    }
    let mut suffix = rest[index..].trim().to_string();
    if !suffix.is_empty() && !suffix.starts_with(['-', '+']) {
        suffix.insert(0, '-');
    }
    Some(Version {
        parts: (numbers[0], numbers[1], numbers[2]),
        suffix,
    })
}

/// A discovered `act`.
#[derive(Debug, Clone)]
pub struct Engine {
    /// The binary that was run.
    pub path: PathBuf,
    /// The version it reported for `--version`.
    pub version: Version,
    /// The container endpoint act will reach (`DOCKER_HOST`, or the default socket).
    pub container: String,
    /// What the probe could not check, in the order it failed to check it.
    pub notes: Vec<String>,
}

impl Engine {
    /// Find `act` and ask it what it is.
    ///
    /// `explicit` is what the operator named (a path, or the value of `$GITIUP_ACT`);
    /// `None` looks for `act` on `PATH`. A missing binary is a refusal with a hint and
    /// never a fallback: silently running a workflow with a different engine than the
    /// one asked for is how an attestation ends up describing a run nobody chose.
    pub fn discover(explicit: Option<&Path>) -> Result<Engine> {
        let path = match explicit {
            Some(path) => PathBuf::from(path),
            None => std::env::var_os(BINARY_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("act")),
        };
        let output = Command::new(&path)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .map_err(|why| {
                Error::new(
                    ErrorKind::Policy,
                    "engine",
                    format!(
                        "the `act` engine was asked for and `{}` did not run: {why}",
                        path.display()
                    ),
                )
                .with_hint(format!(
                    "install act (https://nektosact.com/installation/) or name the binary with \
                     ${BINARY_ENV}; act needs a container runtime (docker, or podman over \
                     DOCKER_HOST), because the containers are act's and not gitiup's"
                ))
            })?;
        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Policy,
                "engine",
                format!(
                    "`{} --version` exited {}",
                    path.display(),
                    output.status.code().unwrap_or(-1)
                ),
            )
            .with_hint("that binary is not act, or is a broken install of it"));
        }
        let printed = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let version = parse_version(&printed).ok_or_else(|| {
            Error::new(
                ErrorKind::Invalid,
                "engine",
                format!(
                    "`{} --version` did not look like act: {printed}",
                    path.display()
                ),
            )
        })?;
        // The container runtime is act's to find, so all gitiup can honestly say is
        // which endpoint act was told about. Claiming "docker is available" here would
        // be a probe of something this engine does not own.
        let (container, mut notes) = match std::env::var("DOCKER_HOST") {
            Ok(host) => (host, Vec::new()),
            Err(_) => {
                let socket = Path::new("/var/run/docker.sock");
                if socket.exists() {
                    (socket.display().to_string(), Vec::new())
                } else {
                    (
                        "(default)".to_string(),
                        vec![
                            "no DOCKER_HOST and no /var/run/docker.sock: act will report its \
                             own container error when it tries to start the job"
                                .to_string(),
                        ],
                    )
                }
            }
        };
        if !version.at_least(0, 2) {
            notes.push(format!(
                "act {version} predates the 0.2 series this engine was written against"
            ));
        }
        if !version.at_least_patch(0, 2, 86) {
            // `act --version` is not a security statement, but a pinned engine is the
            // only one a reviewer can look up, and act has published CVEs against
            // releases older than this.
            notes.push(format!(
                "act {version} is older than the release act's own security notices point at; \
                 `x_engine_version` records what ran"
            ));
        }
        Ok(Engine {
            path,
            version,
            container,
            notes,
        })
    }

    /// `act 0.2.94 · container endpoint unix:///run/user/1000/podman/podman.sock`.
    pub fn describe(&self) -> String {
        format!(
            "act {} · container endpoint {}",
            self.version, self.container
        )
    }

    /// The binary, as argv would show it.
    pub fn program(&self) -> String {
        self.path.display().to_string()
    }
}

/// Is the engine here? `(available, what it said)`, reported by
/// `gitiup run --sandboxes`, which is where a typist looks for "what can this machine
/// run".
pub fn status() -> (bool, String) {
    match Engine::discover(None) {
        Ok(engine) => (true, engine.describe()),
        Err(why) => (
            false,
            format!(
                "no `act` found: install act (https://nektosact.com/installation/) or set \
                 ${BINARY_ENV} — {}",
                why.detail()
            ),
        ),
    }
}

/// Everything an act run needs beyond the plan.
#[derive(Debug, Clone)]
pub struct Request {
    /// The commit being run.
    pub commit: GitOid,
    /// The workflow file, as the attestation records it.
    pub workflow: WorkflowSource,
    /// Where that file is on disk: act is given `-W` and reads it itself.
    pub workflow_file: PathBuf,
    /// The checkout. act copies it into the container rather than mounting it, which
    /// is why an act run cannot write on the working tree.
    pub workspace: PathBuf,
    /// The event to run for.
    pub event: String,
    /// Event action.
    pub event_action: Option<String>,
    /// Repository identity.
    pub repo: Option<String>,
    /// Secrets, **by name**: act is given `-s NAME`, which makes it read its own
    /// environment, so a value never appears in an argv a stranger could `ps`.
    pub secret_names: Vec<String>,
    /// `workflow_dispatch` inputs.
    pub inputs: Vec<(String, InputValue)>,
    /// `runs-on` label → image, e.g. `("ubuntu-24.04", "cat-the-planet/base@sha256:…")`.
    ///
    /// Required for the label the job uses. act would otherwise stop and ask — on a
    /// TTY, mid-run — which default image to pull, and a runner that blocks on a prompt
    /// it cannot answer is worse than a refusal that names the flag to pass.
    pub images: Vec<(String, String)>,
    /// `claims.run_id`, or derived from the clock.
    pub run_id: Option<String>,
    /// The clock.
    pub now_us: Option<i64>,
    /// Wall-clock limit; see [`DEFAULT_TIMEOUT_MINUTES`].
    pub timeout_minutes: Option<u64>,
}

impl Request {
    /// The smallest honest request: `workflow_file`, in `workspace`, run for `commit`.
    pub fn new(
        commit: GitOid,
        workflow: WorkflowSource,
        workflow_file: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
    ) -> Request {
        Request {
            commit,
            workflow,
            workflow_file: workflow_file.into(),
            workspace: workspace.into(),
            event: "push".into(),
            event_action: None,
            repo: None,
            secret_names: Vec::new(),
            inputs: Vec::new(),
            images: Vec::new(),
            run_id: None,
            now_us: None,
            timeout_minutes: None,
        }
    }
}

/// One line of `act --json`, kept loose on purpose.
///
/// act's machine-readable surface is a log stream (logrus fields), not a result
/// schema: unknown fields are ignored and missing ones are `None` rather than an error,
/// so a new act release adds a field instead of breaking a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// `level`: `info`, `warning`, `error`, `debug`.
    pub level: String,
    /// `job`: `<workflow>/<job>` as act names it.
    pub job: Option<String>,
    /// `jobID`, accepted as `jobid` too: logrus lowercases some keys depending on the
    /// act release.
    pub job_id: Option<String>,
    /// `step`: the step's name, or its `run:` body when it has no name.
    pub step: Option<String>,
    /// `stepResult`, on the line that closes a step: `success` / `failure` / `skipped`.
    pub step_result: Option<String>,
    /// `jobResult`, on the line that closes the job.
    pub job_result: Option<String>,
    /// `msg`: the log text, which is where act puts everything else.
    pub msg: String,
    /// `executionTime`, as act printed it (`1.045s`), on the line that closes a step.
    pub execution_time: Option<String>,
    /// The image act started, parsed out of `Start image=…`.
    pub image: Option<String>,
}

/// Parse act's JSON log. A line that is not JSON (act's banner, a runtime's warning,
/// cobra's `Error:` line) is skipped rather than fatal: the engine's claim is about
/// step results, and a banner is not a step result.
pub fn parse_log(text: &str) -> Vec<Event> {
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !(line.starts_with('{') && line.ends_with('}')) {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // act has shipped both `jobID` and `jobid`; a missing field is `None`, never a
        // guess.
        let field = |key: &str| {
            value
                .get(key)
                .or_else(|| value.get(key.to_ascii_lowercase()))
                .and_then(|found| found.as_str())
                .map(str::to_string)
        };
        let msg = field("msg").unwrap_or_default();
        let image = msg
            .split_once("Start image=")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .filter(|found| !found.is_empty())
            .map(str::to_string);
        events.push(Event {
            level: field("level").unwrap_or_default(),
            job: field("job"),
            job_id: field("jobID"),
            step: field("step"),
            step_result: field("stepResult"),
            job_result: field("jobResult"),
            execution_time: field("executionTime"),
            image,
            msg,
        });
    }
    events
}

/// The image act said it started, if the log carried one.
pub fn image_used(events: &[Event]) -> Option<String> {
    events.iter().find_map(|event| event.image.clone())
}

/// One step's worth of act's log, in the order it appeared.
#[derive(Debug, Default)]
struct Observed {
    name: String,
    lines: Vec<String>,
    /// More than one entry means two steps shared a name, which act's log cannot
    /// separate — said out loud rather than averaged.
    results: Vec<(String, Option<i64>)>,
    duration_us: Option<i64>,
}

/// Group act's log by step, in order of appearance.
fn observe(events: &[Event]) -> Vec<Observed> {
    let mut groups: Vec<Observed> = Vec::new();
    for event in events {
        let Some(name) = event.step.as_deref() else {
            continue;
        };
        if groups.last().map(|group| group.name.as_str()) != Some(name) {
            groups.push(Observed {
                name: name.to_string(),
                ..Default::default()
            });
        }
        let group = groups.last_mut().expect("a group was just pushed");
        if !event.msg.is_empty() {
            group.lines.push(event.msg.clone());
        }
        if let Some(result) = &event.step_result {
            group
                .results
                .push((result.clone(), exit_code_in(&group.lines)));
        }
        if group.duration_us.is_none() {
            group.duration_us = parse_go_duration(event.execution_time.as_deref());
        }
    }
    groups
}

/// The last `exit status N` / `exit code N` in a step's own log.
///
/// act does not put a step's exit code in a field; the number is in the text it echoed
/// (`exit status 2`, `Process completed with exit code 1`). Taking the last one is the
/// best reading available, and when there is none the caller says so instead of
/// inventing a number.
fn exit_code_in(lines: &[String]) -> Option<i64> {
    for line in lines.iter().rev() {
        for marker in ["exit status ", "exit code ", "exited with code "] {
            if let Some((_, rest)) = line.rsplit_once(marker) {
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(number) = digits.parse::<i64>() {
                    return Some(number);
                }
            }
        }
    }
    None
}

/// Go's duration text (`1.045s`, `2m3.4s`, `1.05ms`) as microseconds.
fn parse_go_duration(text: Option<&str>) -> Option<i64> {
    let text = text?.trim();
    if text.is_empty() {
        return None;
    }
    let mut total: i64 = 0;
    let mut number = String::new();
    let mut unit = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            if !unit.is_empty() {
                // `1h2m3s`: the previous unit ended, so start the next number.
                total += to_micros(&number, &unit)?;
                number.clear();
                unit.clear();
            }
            number.push(ch);
        } else if ch.is_ascii_alphabetic() || ch == 'µ' {
            unit.push(ch);
        } else {
            return None;
        }
    }
    if number.is_empty() {
        return None;
    }
    total += to_micros(&number, &unit)?;
    Some(total)
}

/// One number-and-unit pair in microseconds. Floats are deliberate and contained: this
/// is a duration for a human, never a signed field (ADR-0001 D1 bans floats from the
/// payload, and none of this reaches it).
fn to_micros(number: &str, unit: &str) -> Option<i64> {
    let value: f64 = number.parse().ok()?;
    let micros = match unit {
        "ns" => value / 1_000.0,
        "us" | "µs" => value,
        "ms" => value * 1_000.0,
        "s" => value * 1_000_000.0,
        "m" => value * 60_000_000.0,
        "h" => value * 3_600_000_000.0,
        _ => return None,
    };
    Some(micros.round() as i64)
}

/// The names act would have logged for a planned step.
///
/// act titles a step its `name:`, else its `uses:` string, else its `run:` body, and
/// it interpolates `${{ … }}` first. Every spelling is tried, because a name that does
/// not line up must show up as "act reported no result for this step" rather than as a
/// silent mismatch.
fn candidates(step: &PlannedStep, matrix: &BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |candidate: String| {
        for spelling in [candidate.clone(), expand_matrix(&candidate, matrix)] {
            let spelling = spelling.trim();
            if !spelling.is_empty() && !out.contains(&spelling.to_string()) {
                out.push(spelling.to_string());
            }
        }
    };
    add(step.name.clone());
    if let Some(run) = &step.run {
        add(run.clone());
        add(run.lines().next().unwrap_or_default().trim().to_string());
    }
    if let Some(uses) = &step.uses {
        add(uses.clone());
    }
    out
}

fn expand_matrix(text: &str, matrix: &BTreeMap<String, String>) -> String {
    let mut out = text.to_string();
    for (key, arm) in matrix {
        out = out.replace(&format!("${{{{ matrix.{key} }}}}"), arm);
    }
    out
}

/// The features in the workflow that act ignores and gitiup will not attest blind.
///
/// `Ok(notes)` is "this may run, and these are the caveats"; `Err` is "this may not".
/// The scan is the workflow's own YAML, read with gitiup's reader, because the plan
/// drops the keys it does not model and an engine that delegates must know what it
/// delegated past.
pub fn check(job: &PlannedJob, workflow_text: &str) -> Result<Vec<String>> {
    let document = crate::yaml::parse(workflow_text)?;
    let root = document.as_map().ok_or_else(|| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            "the workflow is not a mapping, so nothing can be checked about it",
        )
    })?;
    let mut notes: Vec<String> = Vec::new();
    let refused = |what: &str, why: String, fix: &str| {
        Err(Error::new(
            ErrorKind::Policy,
            "engine",
            format!("act ignores {what}, and {why}"),
        )
        .with_hint(fix.to_string()))
    };
    if root.map_field("concurrency").is_some() {
        notes.push(
            "`concurrency:` is ignored: act runs this job whether or not another run of \
                    it is already in flight"
                .to_string(),
        );
    }
    if root.map_field("permissions").is_some() {
        notes.push(
            "workflow-level `permissions:` is act's to ignore: a token passed with \
                    --secret keeps whatever scope it has in real life, not the scope the \
                    workflow asked for"
                .to_string(),
        );
    }
    let Some(jobs) = root.map_field("jobs") else {
        return Ok(notes);
    };
    let Some(map) = jobs.get(&job.id).and_then(|value| value.as_map()) else {
        return Ok(notes);
    };
    if map.str_field("uses").is_some() {
        return Err(Error::new(
            ErrorKind::Policy,
            "engine",
            format!(
                "job `{}` calls a reusable workflow, whose steps gitiup cannot enumerate",
                job.id
            ),
        )
        .with_hint(
            "an attestation that names none of the steps that ran is not an attestation; \
             run the job that has the steps",
        ));
    }
    for key in ["permissions", "concurrency", "run-name"] {
        if map.get(key).is_some() {
            notes.push(format!("job `{}` `{key}:` is ignored by act", job.id));
        }
    }
    if let Some(minutes) = map.str_field("timeout-minutes") {
        notes.push(format!(
            "job `{}` asks for `timeout-minutes: {minutes}`, which act ignores; gitiup puts that \
             same number on the whole run itself and kills act when it runs out",
            job.id
        ));
    }
    if map.get("environment").is_some() {
        return refused(
            "`jobs.<id>.environment`",
            format!(
                "so a secret scoped to that environment would reach `{}` anyway",
                job.id
            ),
            "run it locally with the secrets it is allowed to have and no others: an \
             attestation from a job that received credentials GitHub would have withheld is \
             worse than no attestation",
        );
    }
    if truthy(map, "continue-on-error") {
        return refused(
            "`jobs.<id>.continue-on-error`",
            format!("so a job GitHub would call success act calls `{}`", job.id),
            "the local run would disagree with the CI run it stands in for: drop the setting \
             locally, or plan the job instead of attesting it",
        );
    }
    let steps: Vec<_> = map
        .seq_field("steps")
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    for (index, step) in steps.iter().enumerate() {
        let Some(step) = step.as_map() else {
            continue;
        };
        if truthy(step, "continue-on-error") {
            return refused(
                "step `continue-on-error`",
                format!(
                    "so step {} of `{}` failing is a green job on GitHub and a red one here",
                    index + 1,
                    job.id
                ),
                "remove it for the local run: a step that is allowed to fail cannot be \
                 attested by an engine that cannot tell anyone it was allowed to",
            );
        }
        if step.get("timeout-minutes").is_some() {
            return refused(
                "step `timeout-minutes`",
                format!(
                    "so GitHub would cut step {} of `{}` off and act lets it run to the end of \
                     the job",
                    index + 1,
                    job.id
                ),
                "gitiup can only bound the whole run; drop the step timeout locally or do not \
                 attest this job",
            );
        }
    }
    Ok(notes)
}

/// `true`, in every spelling YAML and GitHub accept.
fn truthy(map: &Mapping, key: &str) -> bool {
    matches!(
        map.str_field(key),
        Some("true") | Some("True") | Some("TRUE") | Some("yes") | Some("Yes") | Some("on")
    )
}

/// The job's own `timeout-minutes`, if it declares one.
///
/// act ignores the setting; the parent process is the only party that can honour it, so
/// the parent reads it and enforces it — the deadline is then gitiup's, which is a
/// sentence the attestation can stand behind.
pub fn job_timeout(workflow_text: &str, job_id: &str) -> Option<u64> {
    let document = crate::yaml::parse(workflow_text).ok()?;
    document
        .as_map()?
        .map_field("jobs")?
        .get(job_id)?
        .as_map()?
        .str_field("timeout-minutes")?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Whether a `uses:` ref is a commit SHA rather than a moving tag or branch.
///
/// `actions/checkout@v4` is what a real workflow says, so the engine does not refuse
/// it — but such a run is not reproducible by construction and says so, until a vendored,
/// content-hashed action set replaces the fetch (ADR-0006 D7 names act's
/// `--local-repository` as the seam, and `giti-bgy.4` owns the vendoring).
pub fn ref_is_pinned(uses: &str) -> bool {
    let Some((_, reference)) = uses.rsplit_once('@') else {
        return false;
    };
    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
}

/// The argv for one planned job, with the engine's flags and nothing else.
pub fn argv(engine: &Engine, job: &PlannedJob, request: &Request) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        engine.program(),
        request.event.clone(),
        "-C".into(),
        request.workspace.display().to_string(),
        "-W".into(),
        request.workflow_file.display().to_string(),
        "-j".into(),
        job.id.clone(),
    ];
    argv.extend(FIXED_ARGS.iter().map(|arg| arg.to_string()));
    for (label, image) in &request.images {
        argv.push("-P".into());
        argv.push(format!("{label}={image}"));
    }
    for name in &request.secret_names {
        // The name only: `-s NAME` makes act read its own environment, so the value is
        // never in an argv, and never in a `ps` a stranger ran.
        argv.push("-s".into());
        argv.push(name.clone());
    }
    for (name, value) in &request.inputs {
        argv.push("--input".into());
        argv.push(format!("{name}={}", render(value)));
    }
    for (axis, arm) in &job.matrix {
        // One attestation is one result, so the arm the plan chose is the arm act runs.
        argv.push("--matrix".into());
        argv.push(format!("{axis}:{arm}"));
    }
    argv
}

fn render(value: &InputValue) -> String {
    match value {
        InputValue::Text(text) => text.clone(),
        InputValue::Int(number) => number.to_string(),
        InputValue::Bool(flag) => flag.to_string(),
    }
}

/// Run one planned job with act and report what act said.
///
/// Refusals come before anything spawns; the log is read after act exits, into files,
/// so a chatty build cannot deadlock on a full pipe; the report carries one entry per
/// *planned* step in plan order, so the rule every other gitiup path holds — the
/// attestation names every step the plan named — holds here too.
pub fn run(job: &PlannedJob, engine: &Engine, request: &Request) -> Result<RunReport> {
    let text = request.workflow.text.clone().ok_or_else(|| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            "the act engine needs the workflow's own text to check what act will ignore",
        )
        .with_hint("put the file's contents in the WorkflowSource, not only its object id")
    })?;
    let mut notes = check(job, &text)?;

    for path in [&request.workspace, &request.workflow_file] {
        if !path.exists() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "engine",
                format!(
                    "{} does not exist, and act is told to run there",
                    path.display()
                ),
            ));
        }
    }
    if let Some(actrc) = actrc_in(&request.workspace) {
        return Err(Error::new(
            ErrorKind::Policy,
            "engine",
            format!(
                "{} is in the checkout, and act reads it: a file inside the tree under test \
                 would be deciding what the runner does",
                actrc.display()
            ),
        )
        .with_hint(
            "a repository must not be able to steer the runner that attests it; remove the \
             file, or run from a checkout without one",
        ));
    }
    let label = job
        .runs_on
        .clone()
        .unwrap_or_else(|| "ubuntu-latest".to_string());
    if label.split_whitespace().any(|word| word == "self-hosted") {
        return Err(Error::new(
            ErrorKind::Policy,
            "engine",
            "`runs-on: self-hosted` means the job runs on the host, which is nothing to attest",
        )
        .with_hint("point the local run at a container label; an unconfined run earns no tier"));
    }
    if !request.images.iter().any(|(name, _)| name == &label) {
        return Err(Error::new(
            ErrorKind::Policy,
            "engine",
            format!(
                "`runs-on: {label}` has no image, and act would stop and ask a terminal which \
                 one to pull"
            ),
        )
        .with_hint(format!(
            "pass `--act-image '{label}=<image>'` — and pin it (`{label}=<image>@sha256:…`), \
             because a tag is only the same image twice by luck"
        )));
    }
    for (name, image) in &request.images {
        if !image.contains("@sha256:") {
            notes.push(format!(
                "`{name}` runs `{image}`, a tag rather than a digest: the run is only \
                 repeatable against the image act happened to pull"
            ));
        }
    }
    for (name, value) in &job.env {
        if value.contains("secrets.") {
            return Err(Error::new(
                ErrorKind::Policy,
                "engine",
                format!("`env: {name}` is `{value}`: secret expressions are not expanded"),
            )
            .with_hint(
                "name the secret with --secret and let the job read it from the environment",
            ));
        }
    }
    // Secrets by name on the command line, by value in act's own environment — which is
    // built from nothing else, so a step reaches a secret only if it was named.
    let mut secrets: Vec<(String, String)> = Vec::new();
    for name in &request.secret_names {
        let value = std::env::var(name).map_err(|_| {
            Error::new(
                ErrorKind::Policy,
                "engine",
                format!("secret `{name}` was requested but is not set in this environment"),
            )
            .with_hint(format!("export {name}=… or drop it from --secret"))
        })?;
        secrets.push((name.clone(), value));
    }

    for step in &job.steps {
        if let Some(uses) = &step.uses
            && !ref_is_pinned(uses)
        {
            notes.push(format!(
                "step '{}' fetches `{uses}`, a moving ref: this run is only reproducible against \
                 whatever that ref pointed at today (pin it by commit SHA, or vendor and pin the \
                 action)",
                step.name
            ));
        }
    }

    let now_us = request.now_us.unwrap_or_else(|| TimeUs::now().0);
    let scratch = scratch_dir(&now_us)?;
    let argv = argv(engine, job, request);
    let minutes = request
        .timeout_minutes
        .or_else(|| job_timeout(&text, &job.id))
        .unwrap_or(DEFAULT_TIMEOUT_MINUTES);
    let deadline = Duration::from_secs(minutes.saturating_mul(60));
    let out_path = scratch.join("act.stdout");
    let err_path = scratch.join("act.stderr");
    let started = Instant::now();
    let started_us = TimeUs::now().0;
    let out_file = std::fs::File::create(&out_path).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            format!("could not open {}: {why}", out_path.display()),
        )
    })?;
    let err_file = std::fs::File::create(&err_path).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            format!("could not open {}: {why}", err_path.display()),
        )
    })?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(&request.workspace)
        .stdin(Stdio::null())
        .stdout(out_file)
        .stderr(err_file);
    command.env_clear();
    for key in ACT_ENV {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    command.env("CI", "true");
    command.env("GITIUP", "1");
    for (name, value) in secrets {
        command.env(name, value);
    }
    let mut child = command.spawn().map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            format!("could not start act: {why}"),
        )
    })?;
    let mut killed_after: Option<u64> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() > deadline {
                    killed_after = Some(minutes);
                    let _ = child.kill();
                    break child.wait().map_err(|why| {
                        Error::new(
                            ErrorKind::Invalid,
                            "engine",
                            format!(
                                "act was killed at its deadline and could not be waited for: {why}"
                            ),
                        )
                    })?;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(why) => {
                return Err(Error::new(
                    ErrorKind::Invalid,
                    "engine",
                    format!("could not wait for act: {why}"),
                ));
            }
        }
    };
    let duration_us = started.elapsed().as_micros().min(i64::MAX as u128) as i64;
    let log = [
        std::fs::read_to_string(&out_path).unwrap_or_default(),
        std::fs::read_to_string(&err_path).unwrap_or_default(),
    ]
    .join("\n");
    let events = parse_log(&log);
    let act_exit = status.code().unwrap_or(-1);
    if let Some(minutes) = killed_after {
        notes.push(format!(
            "act was killed after {minutes} minutes: the run did not finish, so nothing about \
             what it would have produced is claimed"
        ));
    }

    let observed = observe(&events);
    let job_failed = events
        .iter()
        .any(|event| event.job_result.as_deref() == Some("failure"));
    let mut lifecycle_failures: Vec<String> = Vec::new();
    let mut setup_log: Option<String> = None;
    for group in observed.iter().filter(|group| is_lifecycle(&group.name)) {
        if group.results.iter().any(|(result, _)| result == "failure") {
            lifecycle_failures.push(group.name.clone());
            if group.name == "Set up job" {
                setup_log = Some(group.lines.join("\n"));
            }
        }
    }
    if let Some(tail) = setup_log {
        // Nothing of the workflow ran, so there is nothing to attest: act could not pull
        // the image, could not start the container, could not reach its runtime.
        // Refusing is the honest answer, and act's own words are the useful part of it.
        return Err(Error::new(
            ErrorKind::Invalid,
            "engine",
            format!("act could not set the job up: {}", excerpt_tail(&tail, 600)),
        )
        .with_hint(
            "act talks to the container runtime itself, so its own error is the one to read; \
             `gitiup doctor --sandbox` names the runtime this machine has",
        ));
    }

    let mut steps: Vec<StepReport> = Vec::with_capacity(job.steps.len());
    let mut skipped: Vec<String> = Vec::new();
    let mut used: Vec<bool> = vec![false; observed.len()];
    let mut cursor = 0usize;
    for step in &job.steps {
        let names = candidates(step, &job.matrix);
        let found = observed
            .iter()
            .enumerate()
            .skip(cursor)
            .find(|(index, group)| {
                !is_lifecycle(&group.name)
                    && !used[*index]
                    && group.results.iter().any(|(result, _)| result != "skipped")
                    && names.iter().any(|name| name == &group.name)
            })
            .map(|(index, _)| index);
        let Some(index) = found else {
            skipped.push(step.name.clone());
            steps.push(StepReport {
                id: step.id.clone(),
                name: step.name.clone(),
                uses: step.uses.clone(),
                exit_code: 0,
                outcome: Some(StepOutcome::Skipped),
                stdout: Material::text(String::new()),
                stderr: Material::text(
                    "skipped: act's log carried no result for this step (an `if:` that was \
                     false, or a step act did not reach)\n",
                ),
                outputs: BTreeMap::new(),
                artifacts: Vec::new(),
                timing: None,
            });
            continue;
        };
        used[index] = true;
        cursor = index + 1;
        let group = &observed[index];
        let (result, exit) = group
            .results
            .last()
            .cloned()
            .unwrap_or_else(|| ("success".to_string(), Some(0)));
        let exit_code = match result.as_str() {
            "success" => 0,
            "failure" => exit.unwrap_or(1),
            _ => 0,
        };
        if result == "failure" && exit.is_none() {
            notes.push(format!(
                "step '{}': act called it failed and printed no exit code, so the report \
                 records 1 — that number is act's silence, not an observation",
                step.name
            ));
        }
        if group.results.len() > 1 {
            notes.push(format!(
                "step '{}': act's log carries {} results under one name, which is what two \
                 steps sharing a name looks like; the last one is recorded",
                step.name,
                group.results.len()
            ));
        }
        steps.push(StepReport {
            id: step.id.clone(),
            name: step.name.clone(),
            uses: step.uses.clone(),
            exit_code,
            outcome: Some(match result.as_str() {
                "success" => StepOutcome::Success,
                _ => StepOutcome::Failure,
            }),
            stdout: Material::text(clamp(group.lines.join("\n"))),
            stderr: Material::text(String::new()),
            outputs: BTreeMap::new(),
            artifacts: Vec::new(),
            timing: Some(StepTiming {
                started_us: Some(started_us),
                duration_us: group.duration_us,
            }),
        });
    }
    if !skipped.is_empty() {
        notes.push(format!(
            "act's log carried no result for: {} — recorded as skipped, which is either an \
             `if:` that was false (act logs those only at debug level) or a run that stopped at \
             a failing step",
            skipped.join(", ")
        ));
    }
    let unaccounted: Vec<&Observed> = observed
        .iter()
        .enumerate()
        .filter(|(index, group)| !used[*index] && !is_lifecycle(&group.name))
        .map(|(_, group)| group)
        .collect();
    if !unaccounted.is_empty() {
        notes.push(format!(
            "act reported {} step(s) the plan does not have: {} — the attestation covers the \
             steps the workflow declares, and these are not them",
            unaccounted.len(),
            unaccounted
                .iter()
                .map(|group| group.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !lifecycle_failures.is_empty() {
        notes.push(format!(
            "act's own lifecycle reported a failure ({}); the workflow's steps are recorded as \
             they were seen",
            lifecycle_failures.join(", ")
        ));
    }
    if (job_failed || act_exit != 0)
        && !steps
            .iter()
            .any(|step| step.outcome == Some(StepOutcome::Failure))
    {
        notes.push(format!(
            "act exited {act_exit}{} and no step of the workflow failed — the failure is act's, \
             and it is recorded here instead of being blamed on a step",
            if job_failed {
                " and called the job failed"
            } else {
                ""
            }
        ));
    }
    if !events.iter().any(|event| event.job_result.is_some()) {
        notes.push(
            "act's log carried no job result line; the outcome gitiup watched directly is the \
             exit code above"
                .to_string(),
        );
    }
    notes.push(
        "act discards step summaries and annotations and ignores problem matchers (its own \
         unsupported list)"
            .to_string(),
    );

    let probe = crate::env::Probe::collect().with_provider(ENGINE);
    let mut annotations: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in probe.annotations() {
        annotations.insert(key, value);
    }
    annotations.insert(
        "x_run_mode".to_string(),
        format!(
            "executed by act {} in the `{ENGINE}` engine: one job, one matrix arm",
            engine.version
        ),
    );
    annotations.insert("x_sandbox_guarantees".to_string(), GUARANTEES.to_string());
    annotations.insert("x_engine_command".to_string(), argv.join(" "));
    annotations.insert("x_engine_exit".to_string(), act_exit.to_string());
    annotations.insert(
        "x_engine_seconds".to_string(),
        (duration_us / 1_000_000).to_string(),
    );
    annotations.insert("x_engine_container".to_string(), engine.container.clone());
    annotations.insert("x_engine_version".to_string(), engine.version.to_string());
    if let Some(image) = image_used(&events) {
        annotations.insert("x_engine_image".to_string(), image);
    }
    if !engine.notes.is_empty() {
        annotations.insert("x_engine_probe".to_string(), engine.notes.join(" · "));
    }
    for condition in &job.assumptions {
        notes.push(condition.clone());
    }
    annotations.insert("x_run_notes".to_string(), notes.join(" · "));

    let clock = now_us.to_string();
    let run_id = request.run_id.clone().unwrap_or_else(|| {
        Digest::sha256_parts(&[
            ENGINE.as_bytes(),
            job.id.as_bytes(),
            request.commit.to_string().as_bytes(),
            clock.as_bytes(),
        ])
        .hex()[..16]
            .to_string()
    });

    Ok(RunReport {
        repo: request.repo.clone(),
        commit: request.commit.clone(),
        workflow: request.workflow.clone(),
        event: EventReport {
            name: request.event.clone(),
            action: request.event_action.clone(),
            payload: Material::text(format!("{{\"name\":\"{}\"}}", request.event)),
        },
        job: Some(job.id.clone()),
        matrix: job.matrix.clone(),
        inputs: request.inputs.iter().cloned().collect(),
        secret_names: request.secret_names.clone(),
        pins: BTreeMap::new(),
        reusable_workflows: Vec::new(),
        environment: probe.environment,
        steps,
        provenance: Provenance {
            tier: Tier::Local,
            // The runner field is the thing that ran the steps, which is not gitiup.
            runner: format!("act {}", engine.version),
            normalisation_version: 0,
            sandbox: Some(ENGINE.to_string()),
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

/// Whether a logged step is act's own rather than the workflow's.
pub fn is_lifecycle(name: &str) -> bool {
    LIFECYCLE.contains(&name) || name.starts_with("Post ")
}

/// A checkout's `.actrc`, if it has one.
pub fn actrc_in(workspace: &Path) -> Option<PathBuf> {
    let path = workspace.join(".actrc");
    path.exists().then_some(path)
}

/// A private scratch directory for the log capture.
fn scratch_dir(now_us: &i64) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("gitiup-act-{}-{now_us}", std::process::id()));
    std::fs::create_dir_all(&path).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "engine",
            format!(
                "could not create the log directory {}: {why}",
                path.display()
            ),
        )
    })?;
    Ok(path)
}

/// Clamp a captured log the way [`crate::exec`] does, so the digest covers a bounded
/// stream and the truncation shows up in the bytes that were hashed.
fn clamp(text: String) -> String {
    if text.len() <= MAX_LOG_BYTES {
        return text;
    }
    let mut kept: String = text.chars().take(MAX_LOG_BYTES).collect();
    kept.push_str("\n… act's log truncated by gitiup before hashing …");
    kept
}

/// The end of a log, which is where the reason is.
fn excerpt_tail(text: &str, bytes: usize) -> String {
    let text = text.trim();
    if text.len() <= bytes {
        return text.to_string();
    }
    let mut tail = String::new();
    for line in text.lines().rev() {
        if tail.len() + line.len() + 1 > bytes {
            break;
        }
        tail.insert_str(0, line);
        tail.insert(0, '\n');
    }
    tail.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn act_owns_its_own_version_line() {
        assert_eq!(
            parse_version("act version 0.2.94").unwrap().to_string(),
            "0.2.94"
        );
        assert_eq!(parse_version("0.2.70\n").unwrap().to_string(), "0.2.70");
        assert_eq!(
            parse_version("act version 0.2.94-dev+Homebrew")
                .unwrap()
                .to_string(),
            "0.2.94-dev+Homebrew"
        );
        assert!(parse_version("curl 8.5.0").is_none());
        assert!(parse_version("").is_none());
        let fresh = parse_version("act version 0.2.94").unwrap();
        assert!(fresh.at_least(0, 2) && !fresh.at_least(1, 0));
    }

    #[test]
    fn the_log_parser_reads_what_act_prints_and_ignores_the_rest() {
        // Captured from `act push -j lint --json` (act 0.2.94): a banner line that is
        // not JSON, a warning with no step, and the lines that close a step and a job.
        let log = "\
Error: something cobra printed
{\"level\":\"warning\",\"msg\":\"Couldn't get a valid docker connection\",\"time\":\"t\"}
{\"dryrun\":true,\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"🚀  Start image=cat-the-planet/base:latest\",\"step\":\"Set up job\",\"stepid\":[\"--setup-job\"],\"time\":\"t\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | exit status 2\",\"step\":\"Build\",\"stepid\":[\"\"],\"time\":\"t\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  ❌  Failure - Build\",\"step\":\"Build\",\"stepResult\":\"failure\",\"executionTime\":\"1.045s\",\"time\":\"t\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"failure\",\"level\":\"info\",\"matrix\":{},\"msg\":\"🏁  Job failed\",\"time\":\"t\"}
";
        let events = parse_log(log);
        assert_eq!(events.len(), 5, "only the cobra line is not JSON");
        assert!(
            !events.iter().any(|event| event.msg.contains("cobra")),
            "a line act did not print as JSON is not a step result"
        );
        assert_eq!(
            image_used(&events).as_deref(),
            Some("cat-the-planet/base:latest")
        );
        let groups = observe(&events);
        let build = groups.iter().find(|group| group.name == "Build").unwrap();
        assert_eq!(build.results, vec![("failure".to_string(), Some(2))]);
        assert_eq!(build.duration_us, Some(1_045_000));
        assert!(is_lifecycle("Set up job") && is_lifecycle("Post actions/checkout@v4"));
        assert!(!is_lifecycle("Build"));
    }

    #[test]
    fn exit_codes_come_from_the_last_line_that_has_one() {
        let lines = vec![
            "cargo build".to_string(),
            "error: could not compile `x`".to_string(),
            "exit status 101".to_string(),
        ];
        assert_eq!(exit_code_in(&lines), Some(101));
        assert_eq!(exit_code_in(&["all good".to_string()]), None);
        assert_eq!(
            exit_code_in(&["Process completed with exit code 3".to_string()]),
            Some(3)
        );
    }

    #[test]
    fn go_durations_become_microseconds() {
        assert_eq!(parse_go_duration(Some("1.5s")), Some(1_500_000));
        assert_eq!(parse_go_duration(Some("250ms")), Some(250_000));
        assert_eq!(parse_go_duration(Some("1m2s")), Some(62_000_000));
        assert_eq!(parse_go_duration(Some("0s")), Some(0));
        assert_eq!(parse_go_duration(None), None);
        assert_eq!(parse_go_duration(Some("nonsense")), None);
    }

    #[test]
    fn a_named_step_is_found_under_any_of_its_spellings() {
        let step = PlannedStep {
            index: 1,
            id: None,
            name: "run".to_string(),
            uses: None,
            run: Some("make test ${{ matrix.target }}\n".to_string()),
            inputs: Vec::new(),
            condition: None,
            shell: None,
            env: Vec::new(),
        };
        let matrix = BTreeMap::from([("target".to_string(), "x86".to_string())]);
        let names = candidates(&step, &matrix);
        assert!(names.contains(&"make test x86".to_string()), "{names:?}");
        assert!(names.contains(&"make test ${{ matrix.target }}".to_string()));
    }

    #[test]
    fn a_workflow_act_cannot_honour_is_refused_before_anything_spawns() {
        let job = PlannedJob {
            id: "build".into(),
            name: None,
            runs_on: Some("ubuntu-latest".into()),
            matrix: BTreeMap::new(),
            env: Vec::new(),
            services: Vec::new(),
            assumptions: Vec::new(),
            steps: Vec::new(),
        };
        let workflow = "\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: make test
        continue-on-error: true
";
        let err = check(&job, workflow).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(
            err.detail().contains("continue-on-error"),
            "{}",
            err.detail()
        );

        let scoped = "\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: make test
";
        let err = check(&job, scoped).unwrap_err();
        assert!(err.detail().contains("environment"), "{}", err.detail());

        // Decoration is annotated, not refused.
        let decorated = "\
on: push
concurrency:
  group: one
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: make test
";
        let notes = check(&job, decorated).unwrap();
        let joined = notes.join(" · ");
        assert!(joined.contains("concurrency"), "{joined}");
        assert!(joined.contains("permissions"), "{joined}");
        assert!(joined.contains("timeout-minutes"), "{joined}");
    }

    #[test]
    fn a_pin_is_a_commit_sha_and_a_tag_is_not() {
        assert!(ref_is_pinned(&format!(
            "actions/checkout@{}",
            "a".repeat(40)
        )));
        assert!(!ref_is_pinned("actions/checkout@v4"));
        assert!(!ref_is_pinned("actions/checkout@main"));
        assert!(!ref_is_pinned("actions/checkout"));
        // A 39-char or non-hex ref is not a pin either; the point is that it is only
        // the same bytes twice if it names a commit.
        assert!(!ref_is_pinned(&format!("a/{}", "b".repeat(40))));
    }

    #[test]
    fn a_jobs_own_timeout_is_read_from_the_file_act_ignores_it_in() {
        let workflow =
            "on: push\njobs:\n  build:\n    timeout-minutes: 7\n    steps:\n      - run: make\n";
        assert_eq!(job_timeout(workflow, "build"), Some(7));
        assert_eq!(job_timeout(workflow, "other"), None);
        assert_eq!(job_timeout("nonsense: [", "build"), None);
    }

    #[test]
    fn the_fixed_flags_are_the_containment_claim() {
        // If one of these changes, the `sandbox: act` sentence in GUARANTEES is wrong,
        // and a signed attestation is the thing that would have to be re-checked.
        assert!(FIXED_ARGS.contains(&"--container-daemon-socket"));
        assert!(FIXED_ARGS.contains(&"--json"));
        assert!(FIXED_ARGS.contains(&"--use-gitignore"));
        assert!(!REFUSED_ARGS.iter().any(|flag| FIXED_ARGS.contains(flag)));
    }
}

//! The backend contract, the preference order, and the gate every job passes through.
//!
//! A backend is a thing that can answer three questions honestly: *what do you deny*,
//! *did you check it on this machine*, and *how would you wrap this command*. That is
//! the whole [`Sandbox`] trait, plus two policy answers (`serves_quorum`,
//! `opt_in_only`) that keep the weakest rung from being used by accident.
//!
//! ```text
//!   open(name) ──► Sandbox ──► probe() ──► Probe{properties}     "is it real here"
//!                     │
//!                     └──────► plan(spec, env) ──► Launch        "how it wraps"
//!                                  │
//!                        command() ─► std::process::Command ─────► spawn
//! ```
//!
//! [`admit`] is the one call a job-serving daemon should make. It is where the ticket's
//! last acceptance criterion lives: when nothing isolates, the answer is *refuse the
//! job*, not *run it anyway and hope*.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use gitiup_attest::{Error, ErrorKind, Result};
use serde::Serialize;

use crate::backends;
use crate::probe::Probe;
use crate::spec::{Enforcement, Purpose, Spec};

/// The environment a job is given: explicit, sorted, and never inherited
/// (the runner's `exec` module builds it from nothing for the same reason).
pub type Env = BTreeMap<String, String>;

/// What kind of isolation a backend is, which is the shortest answer to "how much do
/// you have to believe me".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A container runtime does the isolating (docker, podman).
    Container,
    /// A namespace the kernel gives us does the isolating (bwrap, unshare).
    Namespace,
    /// Syscalls applied to the child before `execve` (Landlock + seccomp).
    InProcess,
    /// Nothing.
    Plain,
}

impl Kind {
    /// The stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Container => "container",
            Kind::Namespace => "namespace",
            Kind::InProcess => "in-process",
            Kind::Plain => "plain",
        }
    }
}

/// How to wrap one command, produced by
/// [`plan`](Sandbox::plan).
///
/// Kept separate from the trait so a plan can be printed and reviewed before a
/// process exists — and so `--json` can show a reviewer *exactly* what would be run,
/// which is the difference between "trust the sandbox code" and "read the command
/// line".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Launch {
    /// The argv that comes before the job's own command.
    pub prefix: Vec<String>,
    /// A separator between the wrapper's arguments and the command, if the wrapper
    /// takes one (`unshare` and `bwrap` do, `docker run` does not).
    pub separator: Option<String>,
    /// Environment the backend insists on (proxy endpoints, a fixed `PATH`). It wins
    /// over the caller's, because a job that could unset `HTTP_PROXY` could leave the
    /// audited egress path.
    pub env: Env,
    /// Set when the backend passes environment as *arguments* (`docker -e`), in which
    /// case the wrapper's own environment is deliberately empty.
    pub env_as_args: bool,
    /// The working directory inside the confinement, when it differs from the host
    /// path (`/workspace` in a container).
    pub cwd: Option<PathBuf>,
    /// A wall-clock deadline to enforce, when the backend can enforce one itself.
    pub wall_clock: Option<Duration>,
    /// What the plan decided, in sentences. Printed by `--json` and `doctor`.
    pub notes: Vec<String>,
}

impl Launch {
    /// Run the command as it is, with whatever tuning the backend does in the child.
    pub fn direct() -> Launch {
        Launch::default()
    }

    /// The full argv to spawn: wrapper, its `-e` style environment, the separator,
    /// then the job's own command.
    pub fn argv(&self, command: &[String], caller_env: &Env) -> Vec<String> {
        let mut argv = self.prefix.clone();
        if self.env_as_args {
            for (key, value) in caller_env.iter().chain(self.env.iter()) {
                argv.push("-e".to_string());
                argv.push(format!("{key}={value}"));
            }
        }
        argv.extend(self.separator.iter().cloned());
        argv.extend(command.iter().cloned());
        argv
    }

    /// The command line, as one quotable line.
    pub fn describe(&self, command: &[String], caller_env: &Env) -> String {
        self.argv(command, caller_env)
            .iter()
            .map(|argument| {
                if argument.contains(' ') || argument.is_empty() {
                    format!("'{}'", argument.replace('\'', "'\\''"))
                } else {
                    argument.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A sandbox backend.
///
/// Implementations must be cheap to construct and must not touch the machine until
/// [`probe`](Sandbox::probe) or [`plan`](Sandbox::plan) is called: `detect()` builds
/// every backend to print a status table, and a constructor that started a container
/// would make `gitiup doctor` a side effect.
pub trait Sandbox: std::fmt::Debug {
    /// The name recorded in `provenance.sandbox`. One word, lowercase, stable: it ends
    /// up inside signed digests.
    fn name(&self) -> &'static str;

    /// What kind of isolation this is.
    fn kind(&self) -> Kind;

    /// What it actually denies, in the sentence a reviewer needs. Never "sandboxed".
    fn guarantees(&self) -> &'static str;

    /// Ask the machine whether this works *right now*, and record what was seen.
    fn probe(&self) -> Result<Probe>;

    /// Build the wrapper for one job. Must not spawn anything.
    fn plan(&self, spec: &Spec, env: &Env) -> Result<Launch>;

    /// How egress denial is achieved for this egress policy: in the kernel, by the
    /// proxy, or not at all.
    fn enforcement(&self, egress: &crate::egress::Egress) -> Enforcement;

    /// Whether a job whose verdict others rely on may be run here at all.
    fn serves_quorum(&self) -> bool {
        true
    }

    /// Whether this backend exists only for an operator who has said they want it.
    fn opt_in_only(&self) -> bool {
        false
    }

    /// The in-process half of confinement: hooks that run in the child between `fork`
    /// and `execve`. Only the in-process backend needs them; container and namespace
    /// backends confine by argv.
    fn tune(&self, command: &mut Command, spec: &Spec) -> Result<()> {
        let _ = (command, spec);
        Ok(())
    }
}

/// One backend's status on this machine, as `--sandboxes` and `doctor` print it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Backend {
    /// Backend name.
    pub name: String,
    /// Whether a job would be confined by it here.
    pub available: bool,
    /// What kind of isolation it is.
    pub kind: Kind,
    /// How egress would be enforced if this backend were used with no allowlist.
    pub enforcement: Enforcement,
    /// Set when the backend is refused unless the operator opted in.
    pub opt_in: bool,
    /// Whether a stranger's job may be run here.
    pub serves_quorum: bool,
    /// What it guarantees (available) or why it is not (unavailable). Printed verbatim.
    pub note: String,
    /// The probe properties that were watched, when available.
    pub observed: Vec<String>,
    /// The probe properties that could not be watched, when available.
    pub unchecked: Vec<String>,
}

impl Backend {
    /// Probe one backend and describe the outcome.
    pub fn of(sandbox: &dyn Sandbox) -> Backend {
        let enforcement = sandbox.enforcement(&crate::egress::Egress::deny_all());
        let probe = sandbox.probe();
        match probe {
            Ok(probe) => Backend {
                name: sandbox.name().to_string(),
                available: true,
                kind: sandbox.kind(),
                enforcement,
                opt_in: sandbox.opt_in_only(),
                serves_quorum: sandbox.serves_quorum(),
                note: sandbox.guarantees().to_string(),
                observed: probe
                    .observed()
                    .iter()
                    .map(|name| name.to_string())
                    .collect(),
                unchecked: probe
                    .unverified()
                    .iter()
                    .map(|name| name.to_string())
                    .collect(),
            },
            Err(error) => Backend {
                name: sandbox.name().to_string(),
                available: false,
                kind: sandbox.kind(),
                enforcement,
                opt_in: sandbox.opt_in_only(),
                serves_quorum: sandbox.serves_quorum(),
                note: error.detail().to_string(),
                observed: Vec::new(),
                unchecked: Vec::new(),
            },
        }
    }

    /// `landlock: available (in-process, kernel-enforced) — …`
    pub fn describe(&self) -> String {
        format!(
            "{}: {} ({}, {}) — {}",
            self.name,
            self.status(),
            self.kind.as_str(),
            self.enforcement.label(),
            self.note
        )
    }

    /// `available` / `opt-in` / `unavailable`.
    pub fn status(&self) -> &'static str {
        if !self.available {
            return "unavailable";
        }
        if self.opt_in { "opt-in" } else { "available" }
    }
}

/// The backends, in the order they should be preferred: strongest isolation first, and
/// the one that isolates nothing last.
///
/// Containers lead because they are the only rung that also isolates *reads* and
/// gives the job a filesystem of its own. Landlock is the interesting one for a
/// machine with no container runtime: it needs no daemon, no root and no setup, and it
/// is enforced by the same kernel that runs the job.
pub fn backends() -> Vec<Box<dyn Sandbox>> {
    vec![
        Box::new(backends::container::Container::docker()),
        Box::new(backends::container::Container::podman()),
        Box::new(backends::bwrap::Bubblewrap),
        Box::new(backends::inprocess::Landlock),
        Box::new(backends::unshare::Unshare),
        Box::new(backends::plain::Plain),
    ]
}

/// The names of every backend this build can run, in preference order.
pub fn implemented() -> Vec<&'static str> {
    backends().iter().map(|backend| backend.name()).collect()
}

/// The name of the opt-in, no-isolation backend.
pub const PLAIN: &str = "plain";

/// The environment variable a volunteer sets to say "I really do want the backend that
/// isolates nothing". Named to be unpleasant to set by accident.
pub const UNSANDBOXED_ENV: &str = "GITIUP_UNSANDBOXED";

/// The banner. Deliberately long: a warning that scrolls past in one line is a
/// warning that has already been ignored.
pub const UNSANDBOXED_BANNER: &str = "\
******************************************************************
UNSANDOXED: the `plain` backend runs the job as this user, with
this user's files, this user's network and no confinement at all.
It is meant for a machine whose only other option is not running
the job. Never use it for a stranger's job: a quorum job is refused
outright, and always will be.
******************************************************************";

/// Whether the operator has opted into unsandboxed execution.
pub fn opted_in() -> bool {
    matches!(
        std::env::var(UNSANDBOXED_ENV).as_deref(),
        Ok("1") | Ok("yes") | Ok("true")
    )
}

/// Open a backend by name.
///
/// Unknown names are refused with the list of what *is* real, because the commonest
/// mistake here is typing the name of the sandbox that CI happens to use.
pub fn open(name: &str) -> Result<Box<dyn Sandbox>> {
    let name = name.trim().to_ascii_lowercase();
    if gitiup_attest::NO_SANDBOX_ALIASES.contains(&name.as_str()) {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            "`--sandbox none` asks for an unconfined execution",
        )
        .with_hint(
            "an unconfined run may not attest as `local`: pick a backend \
             (see `gitiup run --sandboxes`), or drop --execute and get a simulated \
             attestation instead",
        ));
    }
    // `shell` is the word the attestation format uses for "it really ran on the
    // host"; accept the synonym rather than making people remember which layer named
    // it what.
    let name = match name.as_str() {
        "shell" | "host" | "plain" => PLAIN.to_string(),
        "bubblewrap" | "bwrap" => "bwrap".to_string(),
        other => other.to_string(),
    };
    backends()
        .into_iter()
        .find(|backend| backend.name() == name)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Invalid,
                "sandbox",
                format!("`{name}` is not a sandbox backend"),
            )
            .with_hint(format!(
                "choose one of {} (see `gitiup run --sandboxes` for what this machine offers)",
                implemented().join(", ")
            ))
        })
}

/// Every backend, probed, in preference order.
///
/// This spawns processes (a probe is a real attempt), so it belongs to `doctor` and
/// `--sandboxes`, not to a per-step path.
pub fn detect() -> Vec<Backend> {
    backends()
        .iter()
        .map(|backend| Backend::of(backend.as_ref()))
        .collect()
}

/// The best backend this machine actually offers, excluding the opt-in one.
///
/// `None` is the answer that makes a daemon refuse a job: "no isolation backend is
/// available" is a fact about this host, and the only safe response to it is to not
/// run anything.
pub fn best() -> Option<Box<dyn Sandbox>> {
    backends()
        .into_iter()
        .filter(|backend| !backend.opt_in_only())
        .find(|backend| backend.probe().is_ok())
}

/// What [`admit`] decided, with everything the caller needs to run and record the job.
#[derive(Debug, Clone)]
pub struct Admitted {
    /// The backend that will confine the job.
    pub backend: String,
    /// How egress is enforced for the spec that was admitted.
    pub enforcement: Enforcement,
    /// What the probe watched.
    pub probe: Probe,
    /// The wrapper to build the command from.
    pub launch: Launch,
    /// Loud messages: the UNSANDBOXED banner, unverified properties.
    pub warnings: Vec<String>,
}

/// The gate. Everything that runs a job it did not invent goes through here.
///
/// It refuses, in this order, before anything is spawned:
///
/// 1. a spec that cannot mean what it says;
/// 2. a purpose that needs more than this backend can promise (a quorum job in a cage
///    the job could walk out of);
/// 3. an opt-in backend that has not been opted into — with the banner;
/// 4. a backend whose own probe does not hold up on this machine.
pub fn admit(backend: &dyn Sandbox, spec: &Spec) -> Result<Admitted> {
    spec.check()?;
    let enforcement = backend.enforcement(&spec.egress);
    if enforcement < spec.purpose.minimum_enforcement() {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            format!(
                "a {} job may not run in the `{}` backend: egress would be {} for a verdict \
                 other people are being asked to rely on",
                spec.purpose.as_str(),
                backend.name(),
                enforcement.label()
            ),
        )
        .with_hint(match spec.purpose {
            Purpose::Quorum => concat!(
                "serve quorum jobs from a backend that denies egress in the kernel (docker or ",
                "podman with --network=none, bwrap, unshare, or landlock on Landlock ABI 4+), ",
                "and keep the default-deny egress policy for quorum rounds",
            )
            .to_string(),
            Purpose::Local => "raise the isolation".to_string(),
        }));
    }
    if !backend.serves_quorum() && spec.purpose == Purpose::Quorum {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            format!(
                "the `{}` backend refuses quorum jobs whatever the egress policy says",
                backend.name()
            ),
        )
        .with_hint("a quorum verdict must not come from a backend that opted out of one"));
    }
    // Last, and only for a job this backend could legitimately serve: suggesting the
    // opt-in for a job that would still be refused would be bad advice.
    if backend.opt_in_only() && !opted_in() {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            format!(
                "the `{}` backend confines nothing and has not been opted into",
                backend.name()
            ),
        )
        .with_hint(format!(
            "{UNSANDBOXED_BANNER}\nto accept that anyway: {UNSANDBOXED_ENV}=1 gitiup … ; otherwise \
             install a real backend (see `gitiup doctor --sandbox`)"
        )));
    }
    let probe = backend.probe()?;
    let launch = backend.plan(spec, &Env::new())?;
    let mut warnings = probe.warnings.clone();
    if backend.opt_in_only() {
        warnings.push(UNSANDBOXED_BANNER.to_string());
    }
    if !probe.unverified().is_empty() {
        warnings.push(format!(
            "`{}` could not verify: {}",
            backend.name(),
            probe.unverified().join(", ")
        ));
    }
    Ok(Admitted {
        backend: backend.name().to_string(),
        enforcement,
        probe,
        launch,
        warnings,
    })
}

/// Build the [`Command`] a confined job runs as, with the environment the caller built
/// and the backend's own hooks installed.
///
/// The environment is *cleared* first, always. A confined job that inherits the
/// runner's environment inherits its tokens, and then the attestation describes a run
/// nobody else could repeat.
pub fn command(
    backend: &dyn Sandbox,
    spec: &Spec,
    launch: &Launch,
    argv: &[String],
    env: &Env,
    cwd: &Path,
) -> Result<Command> {
    if argv.is_empty() {
        return Err(Error::new(
            ErrorKind::Invalid,
            "sandbox",
            "there is no command to confine",
        ));
    }
    let full = launch.argv(argv, env);
    let mut command = Command::new(&full[0]);
    command.args(&full[1..]);
    command.env_clear();
    if !launch.env_as_args {
        for (key, value) in env.iter().chain(launch.env.iter()) {
            command.env(key, value);
        }
    }
    command.current_dir(launch.cwd.as_deref().unwrap_or(cwd));
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    backend.tune(&mut command, spec)?;
    Ok(command)
}

/// Everything a caller needs to run one command now: plan, build, spawn, collect.
///
/// Used by the escape suite and by `gitiup doctor`; the runner path in
/// `gitiup-run`'s `exec` goes through the same two functions so there is one confinement
/// path and not two.
pub fn run(
    backend: &dyn Sandbox,
    spec: &Spec,
    argv: &[String],
    env: &Env,
    cwd: &Path,
) -> Result<std::process::Output> {
    let admitted = admit(backend, spec)?;
    let mut command = command(backend, spec, &admitted.launch, argv, env, cwd)?;
    command.output().map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "sandbox",
            format!(
                "the confined command could not be spawned: {why}\
                 \n  (a failed confinement refuses the run: nothing outside the sandbox was touched)"
            ),
        )
        .with_hint("`gitiup doctor --sandbox` says what this machine is missing")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preference_order_is_containers_then_namespaces_then_syscalls_then_nothing() {
        let names = implemented();
        assert_eq!(
            names,
            vec!["docker", "podman", "bwrap", "landlock", "unshare", "plain"],
            "the order in the ticket is the order on the machine"
        );
        let backends = backends();
        assert_eq!(
            backends.last().unwrap().name(),
            PLAIN,
            "the backend that isolates nothing is always last"
        );
        assert!(backends.last().unwrap().opt_in_only());
        assert!(!backends.last().unwrap().serves_quorum());
    }

    #[test]
    fn none_is_refused_and_an_unknown_name_is_told_what_exists() {
        let err = open("none").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("unconfined"), "{err}");
        assert!(err.hint().unwrap().contains("--execute"), "{err}");

        let err = open("kvm").unwrap_err();
        assert!(err.detail().contains("kvm"), "{err}");
        for name in implemented() {
            assert!(err.hint().unwrap().contains(name), "{name} missing: {err}");
        }
        assert_eq!(open(" UNSHARE ").unwrap().name(), "unshare");
        assert_eq!(open("shell").unwrap().name(), PLAIN);
        assert_eq!(open("bubblewrap").unwrap().name(), "bwrap");
    }

    #[test]
    fn a_launch_puts_the_wrapper_before_the_command_and_the_separator_where_it_belts() {
        let launch = Launch {
            prefix: vec!["bwrap".into(), "--ro-bind".into(), "/".into(), "/".into()],
            separator: Some("--".to_string()),
            ..Launch::default()
        };
        let argv = launch.argv(&["/bin/sh".into(), "-c".into(), "true".into()], &Env::new());
        assert_eq!(argv[0], "bwrap");
        assert_eq!(argv.last().unwrap(), "true");
        assert!(
            argv.windows(2)
                .any(|pair| pair[0] == "--" && pair[1] == "/bin/sh")
        );

        // A container takes no separator, and carries the environment as arguments.
        let container = Launch {
            prefix: vec!["docker".into(), "run".into(), "--rm".into(), "img".into()],
            env_as_args: true,
            ..Launch::default()
        };
        let mut env = Env::new();
        env.insert("TOKEN".to_string(), "s3cret".to_string());
        let argv = container.argv(&["/bin/true".to_string()], &env);
        assert!(
            argv.windows(2)
                .any(|pair| pair[0] == "-e" && pair[1] == "TOKEN=s3cret")
        );
        assert_eq!(argv.last().unwrap(), "/bin/true");
        assert!(!argv.iter().any(|argument| argument == "--"));
    }

    #[test]
    fn an_empty_command_is_refused_before_anything_is_spawned() {
        let spec = Spec::new("/tmp/work", "/tmp/scratch");
        let backend = backends::plain::Plain;
        let err = command(
            &backend,
            &spec,
            &Launch::direct(),
            &[],
            &Env::new(),
            Path::new("/tmp"),
        )
        .unwrap_err();
        assert!(err.detail().contains("no command"), "{err}");
    }

    #[test]
    fn a_quorum_job_is_refused_by_a_backend_that_isolates_nothing() {
        let spec = Spec::new("/tmp/work", "/tmp/scratch").quorum();
        let err = admit(&backends::plain::Plain, &spec).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("quorum"), "{err}");
    }

    #[test]
    fn the_opt_in_backend_is_refused_until_it_is_asked_for() {
        // This test changes the environment, so it must not run concurrently with the
        // ones that read it; `--test-threads` is not something this crate depends on,
        // so the check is written to pass in both states.
        let spec = Spec::new("/tmp/work", "/tmp/scratch");
        let outcome = admit(&backends::plain::Plain, &spec);
        if opted_in() {
            assert!(outcome.is_ok());
        } else {
            let err = outcome.unwrap_err();
            assert!(err.hint().unwrap().contains(UNSANDBOXED_ENV), "{err}");
        }
    }
}

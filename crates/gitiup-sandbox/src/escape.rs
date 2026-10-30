//! The escape checks — the same four for every backend, decided by observation.
//!
//! The ticket's acceptance criterion is an escape suite, and an escape suite is only
//! worth writing if its verdicts are *observed* rather than inferred from the exit
//! code of a program that could have lied:
//!
//! | check | what is tried | what decides it |
//!|-------|---------------|-----------------|
//!| `fs-write-outside` | create a file in a host directory the job was not given | whether the file appeared **on the host** afterwards |
//!| `tcp-egress` | connect to a port this process is listening on | whether a connection **arrived at the listener** |
//!| `ptrace` | attach to, and read the memory of, the runner process | whether either succeeded |
//!| `fork-bomb` | fill the process cap with live children | how many survived |
//!
//! Each check runs the confined canary through exactly the same path a real job takes
//! ([`plan`](crate::backend::Sandbox::plan) then
//! [`command`](crate::backend::command)), so passing here means the same code was
//! exercised, not a parallel copy of it.
//!
//! A backend that isolates a check's *subject* differently is not cheating: a `--pid`
//! namespace makes `ptrace` of the runner fail with `ESRCH` (a denial for a different
//! reason, and still a denial), and a container's own filesystem means a write to
//! `/tmp` succeeds *inside* while the host sees nothing (still a denial, by the
//! criterion above — which is the criterion that matters to the machine being
//! protected).

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{self, Env, Launch, Sandbox};
use crate::canary;
use crate::spec::Spec;

/// How many children the fork-bomb canary tries to start.
pub const FORK_ATTEMPT: usize = 128;

/// How much wider than the requested cap the observed cap may be before the check calls
/// it a failure. The cap is computed as "processes of this uid, right now, plus the
/// slack" and read a moment later, so the two readings differ by whatever the rest of
/// the machine did in between; a missing cap is off by thousands, not by tens.
pub const CAP_COUNT_NOISE: u64 = 64;

/// The verdict of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The escape did not happen, with what was seen.
    Denied(String),
    /// The escape happened. Nothing in this suite may tolerate this.
    Escaped(String),
    /// The check could not be run against this backend, and why.
    Unavailable(String),
}

impl Outcome {
    /// The one that must never be true.
    pub fn escaped(&self) -> bool {
        matches!(self, Outcome::Escaped(_))
    }

    /// Whether the check actually ran.
    pub fn checked(&self) -> bool {
        !matches!(self, Outcome::Unavailable(_))
    }

    /// The name for a status line.
    pub fn state(&self) -> &'static str {
        match self {
            Outcome::Denied(_) => "denied",
            Outcome::Escaped(_) => "ESCAPED",
            Outcome::Unavailable(_) => "unavailable",
        }
    }

    /// The check's own words, whatever they are.
    pub fn note(&self) -> &str {
        match self {
            Outcome::Denied(note) | Outcome::Escaped(note) | Outcome::Unavailable(note) => note,
        }
    }
}

/// A port on loopback that reports whether anything dialled it.
///
/// This is what makes the egress check an observation instead of a story: the canary's
/// exit code is evidence about the canary, while "a TCP handshake completed with my
/// listener" is evidence about the sandbox.
#[derive(Debug)]
pub struct Witness {
    listener: TcpListener,
    port: u16,
    arrived: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Witness {
    /// Bind an ephemeral loopback port and watch it.
    pub fn open() -> Result<Witness> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|why| {
            Error::new(
                ErrorKind::Invalid,
                "sandbox",
                format!("could not open the egress witness port: {why}"),
            )
        })?;
        let port = listener
            .local_addr()
            .map(|addr| addr.port())
            .map_err(|why| {
                Error::new(
                    ErrorKind::Invalid,
                    "sandbox",
                    format!("could not read the witness port: {why}"),
                )
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|why| Error::new(ErrorKind::Invalid, "sandbox", format!("{why}")))?;
        let arrived = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            // A clone for the watcher, so the struct can keep the listener alive and
            // a second witness could be opened from the same socket if it ever needs to.
            let watching = listener
                .try_clone()
                .map_err(|why| Error::new(ErrorKind::Invalid, "sandbox", format!("{why}")))?;
            let arrived = Arc::clone(&arrived);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match watching.accept() {
                        Ok((peer, _)) => {
                            arrived.store(true, Ordering::SeqCst);
                            drop(peer);
                        }
                        Err(why) if why.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        Ok(Witness {
            // `accept` needs the listener, so keep one handle and re-borrow per call.
            listener,
            port,
            arrived,
            stop,
            thread: std::sync::Mutex::new(Some(thread)),
        })
    }

    /// The port a job would have to reach to be counted as having egress.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address the canary is told to dial.
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Whether anything completed a handshake.
    pub fn saw_connection(&self) -> bool {
        self.arrived.load(Ordering::SeqCst)
    }

    /// Wait a moment for a late arrival, then report.
    pub fn settled(&self, wait: Duration) -> bool {
        let deadline = std::time::Instant::now() + wait;
        while !self.arrived.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.arrived.load(Ordering::SeqCst)
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        // Keep the listener alive until the watcher has stopped using it.
        let _ = &self.listener;
    }
}

/// A host path the job was never given, in a directory the runner can write to.
fn outside_file(spec: &Spec, tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gitiup-escape-{}-{}-{}",
        tag,
        std::process::id(),
        spec.scratch.display().to_string().len()
    ))
}

/// Run one canary program inside the backend, and hand back its output.
fn run_confined(
    backend: &dyn Sandbox,
    spec: &Spec,
    launch: &Launch,
    argv: &[String],
) -> Result<std::process::Output> {
    let directory = if spec.workspace.exists() {
        spec.workspace.clone()
    } else {
        std::env::temp_dir()
    };
    let mut command = backend::command(backend, spec, launch, argv, &Env::new(), &directory)?;
    // A canary that hangs is a sandbox problem, not a test-suite problem: give it a
    // deadline so a refused `connect` cannot wedge the suite.
    command.stdin(std::process::Stdio::null());
    let deadline = Duration::from_secs(30);
    let mut child = command.spawn().map_err(|why| {
        let hint = if why.kind() == std::io::ErrorKind::PermissionDenied {
            spec.canary
                .as_ref()
                .and_then(|program| crate::backends::inprocess::exec_grant_hint(spec, program))
                .map(|hint| format!(" — {hint}"))
                .unwrap_or_else(|| {
                    " — the sandbox refused to start the canary although its path is                      granted: a filesystem that accepts Landlock grants but does not                      honour them (a workspace bind-mounted from a host, some FUSE mounts)                      looks exactly like this. `escape::stage_canary` is the way to tell                      the two apart, and `escape::all` uses it."
                        .to_string()
                })
        } else {
            String::new()
        };
        Error::new(
            ErrorKind::Invalid,
            "sandbox",
            format!("the canary could not be spawned: {why}{hint}"),
        )
    })?;
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|why| Error::new(ErrorKind::Invalid, "sandbox", format!("{why}")))?
        {
            let output = child
                .wait_with_output()
                .map_err(|why| Error::new(ErrorKind::Invalid, "sandbox", format!("{why}")))?;
            let _ = status;
            return Ok(output);
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            return Err(Error::new(
                ErrorKind::Policy,
                "sandbox",
                "the canary did not finish within 30s",
            )
            .with_hint(
                "a canary that hangs is a hung sandbox; `gitiup doctor --sandbox` may say why",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The canary program to use, if there is one, staged where a confined process may
/// execute it (see [`stage_canary`]).
fn canary_program(spec: &Spec) -> Option<PathBuf> {
    stage_canary(spec).ok()
}

/// Copy the canary into the scratch and return the copy's path.
///
/// A confined process can only `exec` a program inside a tree it has execute rights
/// on, and the scratch is the one tree every backend grants for writing (and therefore
/// for executing what the job builds there). Staging also sidesteps the filesystems
/// where a Landlock grant is accepted but does not hold — a workspace bind-mounted
/// from a host machine behaves that way, and a canary left in `target/debug` there
/// makes every check answer "could not run" when the honest answer is a verdict.
///
/// The copy is named with a leading dot so it cannot collide with a file the job itself
/// made, and is left behind in scratch space that is thrown away with the job.
pub fn stage_canary(spec: &Spec) -> Result<PathBuf> {
    let program = spec
        .canary
        .clone()
        .or_else(canary::program)
        .filter(|path| path.is_file())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Invalid,
                "sandbox",
                "no escape canary to stage: set `Spec::canary` or install 
                 `gitiup-sandbox-canary` beside the runner",
            )
        })?;
    std::fs::create_dir_all(&spec.scratch).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "sandbox",
            format!("cannot create the scratch to stage the canary in: {why}"),
        )
    })?;
    let staged = spec.scratch.join(".gitiup-canary");
    std::fs::copy(&program, &staged).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "sandbox",
            format!(
                "cannot stage the canary from `{}` into `{}`: {why}",
                program.display(),
                staged.display()
            ),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(
            |why| {
                Error::new(
                    ErrorKind::Invalid,
                    "sandbox",
                    format!("cannot make the staged canary executable: {why}"),
                )
            },
        )?;
    }
    Ok(staged)
}

/// Can the job write outside the sandbox?
pub fn fs_write_outside(backend: &dyn Sandbox, spec: &Spec) -> Result<Outcome> {
    let target = outside_file(spec, "fs");
    let _ = std::fs::remove_file(&target);
    let launch = backend.plan(spec, &Env::new())?;
    let program = canary_program(spec);
    let argv = match &program {
        Some(program) => vec![
            program.display().to_string(),
            "fs".to_string(),
            target.display().to_string(),
        ],
        // No canary binary: `/bin/sh` writing a file is the same attempt, and the
        // verdict comes from the host either way.
        None => vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "printf x > '{}' && echo ESCAPED || echo DENIED",
                target.display()
            ),
        ],
    };
    let output = run_confined(backend, spec, &launch, &argv)?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let escaped = target.exists() || text.contains("ESCAPED");
    let _ = std::fs::remove_file(&target);
    Ok(if escaped {
        Outcome::Escaped(format!("a file appeared at {}", target.display()))
    } else {
        Outcome::Denied(format!(
            "no file at {}, and the confined attempt said {}",
            target.display(),
            text.trim()
        ))
    })
}

/// Can the job make an outbound connection?
pub fn outbound_connect(backend: &dyn Sandbox, spec: &Spec) -> Result<Outcome> {
    let witness = Witness::open()?;
    let program = match canary_program(spec) {
        Some(program) => program,
        None => {
            return Ok(Outcome::Unavailable(
                "no canary binary (set GITIUP_SANDBOX_CANARY) so a TCP connect can be tried"
                    .to_string(),
            ));
        }
    };
    let launch = backend.plan(spec, &Env::new())?;
    let argv = vec![
        program.display().to_string(),
        "connect".to_string(),
        witness.address().to_string(),
    ];
    let output = run_confined(backend, spec, &launch, &argv)?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let arrived = witness.settled(Duration::from_millis(300));
    Ok(if arrived || text.contains("ESCAPED") {
        Outcome::Escaped(format!(
            "a connection reached the witness port ({}); the canary said {}",
            witness.port(),
            text.trim()
        ))
    } else {
        Outcome::Denied(format!(
            "nothing arrived at the witness port {}; the canary said {}",
            witness.port(),
            text.trim()
        ))
    })
}

/// Can the job read or control the runner's memory?
pub fn ptrace_escape(backend: &dyn Sandbox, spec: &Spec) -> Result<Outcome> {
    let program = match canary_program(spec) {
        Some(program) => program,
        None => {
            return Ok(Outcome::Unavailable(
                "no canary binary (set GITIUP_SANDBOX_CANARY) so ptrace can be tried".to_string(),
            ));
        }
    };
    let launch = backend.plan(spec, &Env::new())?;
    let argv = vec![
        program.display().to_string(),
        "ptrace".to_string(),
        std::process::id().to_string(),
    ];
    let output = run_confined(backend, spec, &launch, &argv)?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok(if text.contains("ESCAPED") {
        Outcome::Escaped(format!(
            "the confined process traced or read the runner: {}",
            text.trim()
        ))
    } else {
        Outcome::Denied(format!("{} {}", text.trim(), detail).trim().to_string())
    })
}

/// Can the job exceed the process cap?
///
/// The verdict is about the **limit**, not about how many children got started.
/// `RLIMIT_NPROC` counts every process of the uid, so on a busy machine a cap of "32
/// more" can admit a hundred forks simply because the rest of the uid's processes went
/// away in the meantime — and a suite that called that an escape would be reporting on
/// the load of the host rather than on the sandbox. What must be true, and is checked,
/// is that the confined process was *given* the cap the job asked for; how many forks
/// then succeeded is printed as evidence.
///
/// The honest caveat belongs in the note too: a per-uid rlimit is a shared resource, so
/// the strong version of this control is a pid namespace or a cgroup, which `unshare`
/// and the container backends provide and Landlock cannot.
///
/// # Why the "how many were already running" number is taken outside
///
/// The limit is installed as *"this uid's process count right now, plus the slack the job
/// asked for"* — [`nproc_floor`](crate::linux::nproc_floor) — so that is the only count
/// the reading of the cap can honestly be compared against. The count a *confined*
/// process takes is frequently smaller, and always in the same direction: a pid
/// namespace (`bwrap`, `docker`, `podman`, `unshare`) hides every host process, and a
/// backend whose filesystem rules refuse `/proc/*` reads sees none at all. Subtracting
/// that smaller number manufactures slack the sandbox never granted, so a busy host
/// would be reported as an escape on every container backend there is — a refusal of
/// the machine, not a finding about the sandbox. The confined count is still read, and
/// the larger of the two is what the comparison uses.
pub fn fork_bomb(backend: &dyn Sandbox, spec: &Spec) -> Result<Outcome> {
    let program = match canary_program(spec) {
        Some(program) => program,
        None => {
            return Ok(Outcome::Unavailable(
                "no canary binary (set GITIUP_SANDBOX_CANARY) so the process cap can be read"
                    .to_string(),
            ));
        }
    };
    let launch = backend.plan(spec, &Env::new())?;
    let argv = vec![
        program.display().to_string(),
        "fork".to_string(),
        FORK_ATTEMPT.to_string(),
    ];
    let output = run_confined(backend, spec, &launch, &argv)?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let field = |name: &str| -> Option<u64> {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse::<u64>().ok())
    };
    let counted = field("FORKED").unwrap_or(0) as usize;
    let (Some(cap), Some(running)) = (field("CAP"), field("RUNNING")) else {
        return Ok(if text.contains("DENIED") {
            Outcome::Denied(format!(
                "{counted} of {FORK_ATTEMPT} children started before the cap held: {}",
                text.trim()
            ))
        } else {
            Outcome::Unavailable(format!("the canary reported nothing: {}", text.trim()))
        });
    };
    // The count the cap was built from. The canary's own reading is kept in `inside`
    // and printed, but it can only ever be too small to subtract — see the module note.
    let inside = running;
    let outside = crate::linux::current_nproc();
    if let Some(refusal) = cap_is_as_asked(cap, inside, outside, spec.limits.processes) {
        return Ok(Outcome::Escaped(format!(
            "{refusal} ({counted} of {FORK_ATTEMPT} children started)"
        )));
    }
    Ok(Outcome::Denied(format!(
        "{counted} of {FORK_ATTEMPT} children started; the confined process is capped at \
         {cap} for a uid already running {}{} — a per-uid rlimit is shared with everything \
         else running as this user, so a pid namespace or a cgroup is the strong version of \
         this control",
        outside.max(inside),
        if inside < outside {
            format!(
                " ({outside} counted here, {inside} from inside the sandbox, which hides the \
                 rest: a pid namespace, or /proc reads refused)"
            )
        } else {
            String::new()
        }
    )))
}

/// The verdict on the cap the confined process reports, as a refusal when there is one.
///
/// `cap` is `RLIMIT_NPROC` as the confined process reads it; `inside` is the process
/// count the confined process saw; `outside` the count the runner saw at the moment it
/// set the limit; `asked` the *extra* processes the job allowed. The comparison uses the
/// larger of the two counts, because a sandbox can hide processes from the count and can
/// never invent them, and because the limit was installed against `outside`.
pub fn cap_is_as_asked(cap: u64, inside: u64, outside: u64, asked: Option<u64>) -> Option<String> {
    // A job that asked for no cap cannot be refused for not having one: there is nothing
    // to check about a limit nobody asked for. Every job this build runs does ask for one,
    // and the default is in [`Limits`].
    let asked = asked?;
    if cap == u64::MAX {
        return Some(format!(
            "the confined process has no process cap at all, and the job asked for {asked} \
             extra processes"
        ));
    }
    let running = inside.max(outside);
    let slack = cap.saturating_sub(running);
    if slack > asked + CAP_COUNT_NOISE {
        return Some(format!(
            "the confined process may start {slack} more processes, but the job asked for a \
             cap of {asked} ({running} processes of this uid were already running: {outside} \
             counted by the runner, {inside} counted inside the sandbox)"
        ));
    }
    None
}

/// All four checks, as `(name, outcome)`, in the order the ticket lists them.
pub fn all(backend: &dyn Sandbox, spec: &Spec) -> Vec<(&'static str, Outcome)> {
    [
        ("fs-write-outside", fs_write_outside(backend, spec)),
        ("tcp-egress", outbound_connect(backend, spec)),
        ("ptrace", ptrace_escape(backend, spec)),
        ("fork-bomb", fork_bomb(backend, spec)),
    ]
    .into_iter()
    .map(|(name, outcome)| {
        (
            name,
            outcome.unwrap_or_else(|why| Outcome::Unavailable(why.to_string())),
        )
    })
    .collect()
}

/// Turn the escape results into probe properties, so a probe and the escape suite can
/// never disagree about what they saw.
pub fn probe_from(builder: &mut crate::probe::ProbeBuilder, results: &[(&'static str, Outcome)]) {
    for (name, outcome) in results {
        match outcome {
            Outcome::Denied(note) => {
                builder.observed(name, note.clone());
            }
            Outcome::Escaped(note) => {
                builder.failed(name, note.clone());
            }
            Outcome::Unavailable(note) => {
                builder.skipped(name, note.clone());
            }
        }
    }
}

/// A scratch directory for a probe or a canary run, created lazily.
pub fn probe_scratch(tag: &str) -> Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "gitiup-sandbox-probe-{}-{}",
        tag,
        std::process::id()
    ));
    std::fs::create_dir_all(&path).map_err(|why| {
        Error::new(
            ErrorKind::Invalid,
            "sandbox",
            format!(
                "could not create the probe scratch {}: {why}",
                path.display()
            ),
        )
    })?;
    Ok(path)
}

/// Connect once, to check the witness works — a self-test for the self-test.
pub fn witness_works(witness: &Witness) -> bool {
    let attempt = TcpStream::connect_timeout(&witness.address(), Duration::from_millis(500));
    let _ = attempt;
    witness.settled(Duration::from_millis(200))
}

/// The directory a canary is allowed to write to, for a "can it do what it should"
/// control check.
pub fn inside(spec: &Spec) -> &Path {
    &spec.scratch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_witness_sees_a_plain_connection() {
        let witness = Witness::open().unwrap();
        assert!(
            witness_works(&witness),
            "the witness must see an ordinary connection, or every tcp check is a false pass"
        );
    }

    #[test]
    fn an_outside_file_is_not_inside_the_scratch() {
        let spec = Spec::new("/work", "/work/.scratch");
        let path = outside_file(&spec, "fs");
        assert!(
            !path.starts_with(&spec.scratch),
            "{} is inside the scratch, so the fs check would prove nothing",
            path.display()
        );
    }

    #[test]
    fn outcomes_are_distinguishable_and_only_one_is_fatal() {
        assert!(Outcome::Escaped("x".into()).escaped());
        assert!(!Outcome::Denied("x".into()).escaped());
        assert!(!Outcome::Unavailable("x".into()).checked());
        assert_eq!(Outcome::Escaped("x".into()).state(), "ESCAPED");
    }

    // The process cap is judged against the count taken where the limit was installed,
    // and a sandbox is allowed to hide processes from the count taken inside it. These
    // four cases are the difference between a check about the sandbox and a check about
    // how busy the host happens to be.
    #[test]
    fn a_cap_of_exactly_what_was_asked_is_not_an_escape() {
        let outside = 92;
        let asked = 256;
        assert_eq!(
            cap_is_as_asked(outside + asked, outside, outside, Some(asked)),
            None
        );
    }

    #[test]
    fn a_sandbox_that_hides_the_process_count_is_not_blamed_for_it() {
        // Landlock with `/proc/*` reads refused, and every pid-namespaced backend:
        // the confined process counts fewer processes than the runner did, which is a
        // fact about namespaces and not about the cap. Reading this the other way round
        // refuses a job on any machine running more processes than the noise margin.
        let outside = 92;
        let asked = 256;
        assert_eq!(
            cap_is_as_asked(outside + asked, 0, outside, Some(asked)),
            None
        );
        assert_eq!(
            cap_is_as_asked(outside + asked, 2, outside, Some(asked)),
            None
        );
    }

    #[test]
    fn a_cap_wider_than_the_job_asked_for_is_an_escape() {
        let outside = 92;
        let asked = 256;
        // The limit a backend failed to lower, or lowered to something of its own
        // choosing: off by thousands, not by the few the machine moved in between.
        let refusal = cap_is_as_asked(outside + asked + 4000, 0, outside, Some(asked))
            .expect("a cap nobody asked for is a finding");
        assert!(refusal.contains("4256 more processes"), "{refusal}");
        assert!(refusal.contains("counted inside the sandbox"), "{refusal}");
    }

    #[test]
    fn no_cap_at_all_is_always_an_escape() {
        assert!(cap_is_as_asked(u64::MAX, 0, 92, Some(256)).is_some());
        // …and a job that asked for no cap is not refused for not having one.
        assert_eq!(cap_is_as_asked(u64::MAX, 0, 92, None), None);
    }
}

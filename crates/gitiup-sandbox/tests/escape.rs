//! The escape suite: the acceptance criterion, executable.
//!
//! Every backend this machine can actually run is asked to confine a canary that tries
//! the four things the ticket names — write outside the sandbox, make an outbound
//! connection, `ptrace` the runner, exceed the process cap — and each check is decided
//! by what the *host* observed (see [`gitiup_sandbox::escape`]).
//!
//! Two things make this suite more than a list of `assert!(err.is_err())`:
//!
//! * the checks are run through the same [`plan`](gitiup_sandbox::backend::Sandbox::plan)
//!   and [`command`](gitiup_sandbox::backend::command) path a real job takes, so nothing
//!   is being tested that production does not use;
//! * a check that could not be attempted is reported as such and *counted*: on a machine
//!   with a real isolation backend, the in-process backend must have every one of the
//!   four observed. A suite that quietly checks nothing would pass forever, which is the
//!   failure mode this whole ticket is about.
//!
//! Run it verbosely when you want to read the verdicts:
//!
//! ```sh
//! cargo test -p gitiup-sandbox --test escape -- --nocapture
//! ```

use std::path::PathBuf;

use gitiup_sandbox::backend::{self, Sandbox};
use gitiup_sandbox::backends::inprocess::Landlock;
use gitiup_sandbox::escape::{self, Outcome};
use gitiup_sandbox::spec::{Limits, Spec};

/// The canary built by this package, so the suite does not depend on what is installed.
fn canary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitiup-sandbox-canary"))
}

/// A spec the canaries can be run under: a real workspace, a real scratch, a tight
/// process cap (so the fork check measures the cap and not the machine), and egress
/// denied — which is the policy every backend claims to enforce hardest.
fn spec() -> Spec {
    let home = tempfile::tempdir().expect("a temp dir to sandbox");
    let workspace = home.path().to_path_buf();
    let scratch = workspace.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    // Keep the tempdir alive by leaking it into the spec's paths: the suite is short,
    // and a scratch that vanishes mid-canary would be reported as a denial.
    std::mem::forget(home);
    Spec::new(&workspace, &scratch)
        .with_limits(Limits::tight())
        .with_canary(canary())
}

/// Every backend, with the checks it was actually able to attempt.
fn run(backend: &dyn Sandbox) -> Vec<(&'static str, Outcome)> {
    let spec = spec();
    escape::all(backend, &spec)
}

fn report(name: &str, results: &[(&'static str, Outcome)]) {
    for (check, outcome) in results {
        println!(
            "{name:<9} {check:<17} {:<12} {}",
            outcome.state(),
            outcome.note()
        );
    }
}

/// The backend the machine will use by default must deny all four, or the suite has
/// nothing to say.
#[test]
fn the_available_backends_deny_every_escape() {
    let mut escaped: Vec<String> = Vec::new();
    let mut backends_tried: Vec<String> = Vec::new();

    for candidate in backend::backends() {
        if candidate.opt_in_only() {
            // `plain` isolates nothing by design; testing it for escapes would be a
            // way to forget that. Its own guarantees are tested in `serves.rs`.
            println!(
                "{:<9} skipped: it is the backend that isolates nothing",
                candidate.name()
            );
            continue;
        }
        match candidate.probe() {
            Ok(probe) => {
                println!("{} is available: {}", candidate.name(), probe.summary());
            }
            Err(why) => {
                println!("{} unavailable: {}", candidate.name(), why.detail());
                continue;
            }
        }
        backends_tried.push(candidate.name().to_string());
        let results = run(candidate.as_ref());
        report(candidate.name(), &results);
        for (check, outcome) in &results {
            if outcome.escaped() {
                escaped.push(format!(
                    "{}: {check} — {}",
                    candidate.name(),
                    outcome.note()
                ));
            }
        }
    }

    assert!(
        escaped.is_empty(),
        "an escape succeeded, which is the one result this suite exists to catch:\n{}",
        escaped.join("\n")
    );

    if backends_tried.is_empty() {
        // A machine with no isolation backend at all — a locked-down container, a
        // kernel without Landlock. That is a real and expected state, and the
        // matching requirement is that gitiup then refuses to run jobs, which
        // `serves.rs` checks. Say which fact was *not* exercised, so nobody reads a
        // vacuous pass as a green escape suite.
        println!(
            "note: no isolation backend is available on this machine, so no escape was \
             attempted; the refusal path is covered by tests/serves.rs"
        );
    }
}

/// The in-process backend is the one every supported check must reach: it needs no
/// runtime, no image and no privileged helper, so where the kernel allows it there is no
/// excuse for an unobserved check.
#[test]
fn the_in_process_backend_observes_every_check_it_can() {
    let landlock = Landlock;
    if landlock.probe().is_err() {
        println!("landlock is not usable here; nothing to observe");
        return;
    }
    let results = run(&landlock);
    report("landlock", &results);
    let observed: Vec<&str> = results
        .iter()
        .filter(|(_, outcome)| outcome.checked() && !outcome.escaped())
        .map(|(check, _)| *check)
        .collect();
    for needed in ["fs-write-outside", "tcp-egress", "ptrace", "fork-bomb"] {
        assert!(
            observed.contains(&needed),
            "`{needed}` was not denied or was not attempted: {:?}",
            results
                .iter()
                .map(|(check, outcome)| (check, outcome.state()))
                .collect::<Vec<_>>()
        );
    }
}

/// A write to the workspace — which the job is *allowed* to read but not write — must
/// also fail. This is the check that distinguishes a real confinement from a scratch
/// directory someone called a sandbox.
#[test]
fn the_workspace_is_readable_but_not_writable() {
    let landlock = Landlock;
    if landlock.probe().is_err() {
        println!("landlock is not usable here; nothing to observe");
        return;
    }
    let spec = spec();
    // Run the canary from inside the scratch: a confined process can only execute a
    // program in a tree it may execute, and the scratch is that tree everywhere (see
    // `escape::stage_canary` for the filesystems this matters on).
    let program = escape::stage_canary(&spec).expect("the canary stages into the scratch");
    let launch = landlock.plan(&spec, &backend::Env::new()).unwrap();
    let run = |target: PathBuf| {
        let mut command = backend::command(
            &landlock,
            &spec,
            &launch,
            &[
                program.display().to_string(),
                "fs".to_string(),
                target.display().to_string(),
            ],
            &backend::Env::new(),
            &spec.workspace,
        )
        .expect("the confined command builds");
        command.output().expect("the confined canary runs")
    };

    let outside = spec.workspace.join("written-by-the-job");
    let output = run(outside.clone());
    assert!(
        !outside.exists(),
        "a confined job wrote to the workspace it was given read-only: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // And the same process *can* write to the scratch, or the sandbox is a refusal.
    let inside = spec.scratch.join("written-by-the-job");
    let output = run(inside.clone());
    assert!(
        inside.exists(),
        "the scratch must be writable, or nothing can build: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The canary itself, run *unconfined*, must report escapes. A canary that always says
/// `DENIED` would turn this whole file into a ceremony.
#[test]
fn the_canary_escapes_when_nothing_is_confining_it() {
    let home = tempfile::tempdir().unwrap();
    let program = canary();
    let target = home.path().join("outside");
    let output = std::process::Command::new(&program)
        .args(["fs", &target.display().to_string()])
        .output()
        .expect("the canary built");
    assert_eq!(
        output.status.code(),
        Some(gitiup_sandbox::canary::ESCAPED),
        "unconfined, writing a file is not an escape attempt worth reporting: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.exists());

    let output = std::process::Command::new(&program)
        .args(["fork", "8"])
        .output()
        .expect("the canary built");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(text.contains("FORKED 8"), "{text}");
    assert_eq!(output.status.code(), Some(gitiup_sandbox::canary::ESCAPED));
}

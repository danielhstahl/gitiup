//! The mount-point clash, end to end: giti-0xi.
//!
//! A container runtime keeps its mounts keyed by *destination* and refuses the whole
//! container when two want one address:
//!
//! ```text
//! Error response from daemon: Duplicate mount point: '/work'
//! ```
//!
//! The spec a workflow step runs under asks for exactly that: the checkout is on the
//! read list because every workspace is mounted read-only, and on the write list
//! because a build writes where it is checked out (see
//! `gitiup_run::sandbox::spec_for`). Two `-v` arguments, one destination, every
//! `--sandbox docker` run refused — and the message named neither grant, which is why
//! it reads as a mystery rather than as a spec bug.
//!
//! The runtime is faked, and the fake enforces the one rule that matters here: it walks
//! the `-v` and `--tmpfs` arguments it is given, and answers with the daemon's own
//! error if a destination appears twice. That makes this file a reproduction rather
//! than an assertion about a data structure — hand it the old code and it fails, hand
//! it the new code and it passes, on Linux or a Mac, with no daemon in sight.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use gitiup_sandbox::backend::Env;
use gitiup_sandbox::backend::Sandbox;
use gitiup_sandbox::backends::container::Container;
use gitiup_sandbox::spec::Spec;

/// These tests reorder `PATH`, which is process-wide; a probe that found the host's
/// real docker instead of the fake would be reporting on the host.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Where the fake runtime lives, and what it recorded.
struct Fake {
    dir: tempfile::TempDir,
}

/// The fake runtime. It answers `version` and `image inspect` like a working daemon,
/// liveness-probes like one, and for `run` it does what the daemon does before starting
/// anything: it collects every mount destination in the argument list and refuses a
/// duplicate.
const RUNTIME_SCRIPT: &str = r#"#!/bin/sh
# giti-0xi's fake runtime: a docker that only checks mount destinations.
case "$1" in
    version)
        echo fake-1.0
        exit 0
        ;;
    image)
        echo sha256:00000000
        exit 0
        ;;
    run)
        dests=""
        prev=""
        for a in "$@"; do
            case "$prev" in
                -v)
                    dests="$dests ${a#*:}"
                    ;;
                --tmpfs)
                    dests="$dests ${a%%:*}"
                    ;;
            esac
            prev="$a"
        done
        # One pass over the list, counted by hand: no bash, no sort, same answer.
        for d in $dests; do
            # The destination is everything after the first `:` of a `-v`, and the
            # mode follows the second, so trim it off.
            d="${d%:*}"
            n=0
            for e in $dests; do
                e="${e%:*}"
                [ "$e" = "$d" ] && n=$((n + 1))
            done
            if [ "$n" -gt 1 ]; then
                echo "Error response from daemon: Duplicate mount point: '$d'" >&2
                exit 125
            fi
        done
        # The liveness canary the probe asks for, then a plain yes.
        for a in "$@"; do
            case "$a" in
                *gitiup-alive*)
                    printf '%s' "$a"
                    exit 0
                    ;;
            esac
        done
        echo NO-DUPLICATES
        exit 0
        ;;
esac
exit 0
"#;

impl Fake {
    fn new() -> Fake {
        let dir = tempfile::tempdir().expect("a temp dir to put a fake runtime in");
        let binary = dir.path().join("docker");
        std::fs::write(&binary, RUNTIME_SCRIPT).expect("the fake runtime is written");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("the fake runtime is executable");
        Fake { dir }
    }

    /// Run `body` with the fake first on `PATH`.
    fn with(&self, body: impl FnOnce()) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut searched = vec![self.dir.path().to_path_buf()];
        searched.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let path = std::env::join_paths(searched).expect("PATH can be re-joined");
        let previous = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", &path) };
        body();
        unsafe {
            match previous {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }
}

/// A workspace and a scratch inside it, on disk, because a container mounts what exists.
fn checkout() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("a checkout to mount");
    let workspace = std::fs::canonicalize(dir.path()).expect("the checkout is reachable");
    let scratch = workspace.join(".scratch");
    std::fs::create_dir_all(&scratch).expect("the scratch exists");
    (dir, workspace, scratch)
}

/// The shape `gitiup run --execute` gives a step, built here rather than imported from
/// the runner (which depends on this crate, not the other way round). `gitiup-run`'s
/// `the_shape_the_sandbox_doctor_checks_is_the_shape_a_step_runs_in` pins the two
/// together.
fn step(workspace: &Path, scratch: &Path) -> Spec {
    Spec::new(workspace, scratch).with_writable(workspace)
}

/// The command the runtime is handed, with the fake answering.
fn spawn(backend: &Container, spec: &Spec) -> std::process::Output {
    let launch = backend
        .plan(spec, &Env::new())
        .expect("a step's spec plans");
    let argv = launch.argv(&["/bin/true".to_string()], &Env::new());
    Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(launch.wrapper_env.clone())
        .output()
        .expect("the fake runtime runs")
}

/// The ticket, end to end: the spec a step runs in is handed to a runtime that keeps one
/// mount per destination, and the runtime does not refuse it.
#[test]
fn a_step_mounts_its_checkout_once_where_the_daemon_would_refuse_twice() {
    let fake = Fake::new();
    let (_dir, workspace, scratch) = checkout();
    fake.with(|| {
        let backend = Container::docker();
        // The probe has to survive too: a runtime that will not take the job is not
        // worth handing the arguments to.
        backend
            .probe()
            .expect("a working runtime with an image probes clean");
        let spec = step(&workspace, &scratch);
        let planned = backend
            .plan(&spec, &Env::new())
            .expect("the shape every step uses must plan");
        // Read it as a reviewer would: one `-v` for the checkout, and it is the
        // writable one, because the step is allowed to write there.
        let volumes: Vec<String> = planned
            .prefix
            .windows(2)
            .filter(|pair| pair[0] == "-v")
            .map(|pair| pair[1].clone())
            .collect();
        let w = workspace.display().to_string();
        let for_checkout: Vec<&String> = volumes
            .iter()
            .filter(|volume| volume.starts_with(&format!("{w}:")))
            .collect();
        assert_eq!(
            for_checkout.len(),
            1,
            "one destination, one mount — two is `Duplicate mount point: '{w}'`: {volumes:?}"
        );
        assert!(
            for_checkout[0].ends_with(":rw"),
            "the writable grant is the one that survived: {:?}",
            for_checkout[0]
        );
        // And the plan says which list it ended up in, so the reviewer is not told the
        // checkout is read-only.
        assert!(
            planned
                .notes
                .iter()
                .any(|note| note.starts_with("writable mounts:") && note.contains(&w)),
            "{:?}",
            planned.notes
        );
        assert!(
            planned.notes.iter().any(|note| {
                note.starts_with("mount points:") && note.contains("read-only promise")
            }),
            "the widened grant is in the notes: {:?}",
            planned.notes
        );
        // Then ask the fake, which is the part that used to fail: it counts mount
        // destinations the way the daemon does and refuses a repeat.
        let out = spawn(&backend, &spec);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "the runtime refused the job: {stderr}"
        );
        assert!(!stderr.contains("Duplicate mount point"), "{stderr}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("NO-DUPLICATES"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    });
}

/// The collision gitiup cannot resolve is its own refusal, with the fix in it — not the
/// daemon's, which names neither of the two things that collided. The scratch *is*
/// `/tmp` here, and `/tmp` is where the scratch cap lives.
#[test]
fn a_clash_gitiup_cannot_resolve_is_gitiups_refusal_not_the_runtimes() {
    let fake = Fake::new();
    let (_dir, workspace, _) = checkout();
    fake.with(|| {
        let backend = Container::docker();
        let spec = Spec::new(&workspace, "/tmp");
        let err = backend
            .plan(&spec, &Env::new())
            .expect_err("a mount on /tmp collides with the scratch cap's tmpfs");
        assert_eq!(err.exit_code(), 6, "a refusal a supervisor can branch on");
        assert!(err.detail().contains("/tmp"), "{err}");
        assert!(err.detail().contains("Duplicate mount point"), "{err}");
        assert!(err.hint().unwrap().contains("/tmp/gitiup-scratch"), "{err}");
        // And the fake was never asked: the refusal is gitiup's, before the runtime is.
        let out = Command::new(fake.dir.path().join("docker"))
            .args(["run", "-v", "/tmp:/tmp:rw", "--tmpfs", "/tmp:size=1"])
            .env_clear()
            .output()
            .expect("the fake runtime runs");
        assert!(
            !out.status.success(),
            "the fake must still be able to see the clash, or the test above proves nothing"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("Duplicate mount point: '/tmp'"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

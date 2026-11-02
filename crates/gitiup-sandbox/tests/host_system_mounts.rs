//! The host's system directories never go into a container: giti-ej2.
//!
//! The report was from a Mac, and it was not a mystery about Docker:
//!
//! ```text
//! a write was refused because the filesystem is read-only here (exit 125)
//! ```
//!
//! It said "read-only" because the job was told to write into trees that had arrived
//! read-only, and it said `exit 125` — the runtime's "the container never started" —
//! because some of them are paths the desktop app does not share at all. Both halves
//! came from one line of code: the read list every backend needs *on the host* (`/usr`,
//! `/bin`, `/lib`, `/etc`, and on macOS `/Applications`, `/Library`, `/opt/local`) was
//! handed to `docker -v` along with the workspace, so the container got a read-only copy
//! of a *different* operating system's toolchain laid over the one its image was built
//! for. The same argv is broken on Linux for a different reason — an `alpine` job given
//! the host's glibc `/usr` — which is why the ticket guessed it was not Mac-only, and
//! why neither fake below is Mac-shaped.
//!
//! The runtime is faked twice, each fake enforcing one consequence of the bug:
//!
//! * [`Unshared`] is a runtime with a file-sharing boundary: it refuses a `-v` whose
//!   source is outside what it will show the VM, with the daemon's own `Mounts denied`
//!   and `exit 125`.
//! * [`OwnRoot`] is an image that knows its own directories: it refuses a `-v` whose
//!   *destination* is one of them, because masking the image's `/bin/sh`, `/etc/passwd`
//!   or `/usr` is the silent half of the same bug.
//!
//! Hand the old code to either fake and it fails; hand it the new code and it passes, on
//! Linux or a Mac, with no daemon in sight.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use gitiup_sandbox::backend::Env;
use gitiup_sandbox::backend::Sandbox;
use gitiup_sandbox::backends::container::Container;
use gitiup_sandbox::spec::Spec;

/// These tests reorder `PATH`, which is process-wide; a probe that found the host's real
/// docker instead of the fake would be reporting on the host.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// What a fake runtime refused, when it refuses.
struct Refusal {
    status: Option<i32>,
    stderr: String,
}

/// The shared skeleton of both fakes: answers `version` and `image inspect` like a
/// working daemon, prints the liveness marker the probe asks for, and hands `run`
/// arguments to a `check_mounts` hook written in POSIX shell (`$1` is the whole `-v`
/// volume list, `$2` the destination list). The hook prints to stderr and exits 125 to
/// refuse.
fn script(check_mounts: &str) -> String {
    format!(
        r#"#!/bin/sh
case "$1" in
    version) echo fake-1.0; exit 0 ;;
    image) echo sha256:00000000; exit 0 ;;
    run)
        vols=""
        dests=""
        prev=""
        for a in "$@"; do
            case "$prev" in
                -v) vols="$vols $a"; dests="$dests ${{a#*:}}" ;;
                --tmpfs) dests="$dests ${{a%%:*}}" ;;
            esac
            prev="$a"
        done
        for a in "$@"; do
            case "$a" in
                *gitiup-alive*) printf '%s' "$a"; exit 0 ;;
            esac
        done
{CHECK}
        echo MOUNTS-OK
        exit 0
        ;;
esac
exit 0
"#,
        CHECK = check_mounts
    )
}

/// A fake runtime, written to a private directory and put first on `PATH` for the
/// duration of `body`.
fn run_with(script: &str, body: impl FnOnce()) {
    let dir = tempfile::tempdir().expect("a temp dir to put a fake runtime in");
    let binary = dir.path().join("docker");
    std::fs::write(&binary, script).expect("the fake runtime is written");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("the fake runtime is executable");
    // `PATH` is process-wide, so these tests are serialised: a probe that found the
    // host's real docker instead of the fake would be reporting on the host.
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut searched = vec![dir.path().to_path_buf()];
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

/// The shared skeleton as a `Fake`-shaped helper.
/// A runtime that will not show the VM a directory it has not agreed to share — what a
/// Mac's desktop app is. `/Users`, `/tmp`, `/private` and anything under a `.scratch`
/// count as shared; the host's system directories are exactly the ones that are not.
const UNSHARED: &str = r#"
        # giti-ej2's first fake: a runtime with a sharing boundary.
        for v in $vols; do
            src="${v%%:*}"
            case "$src" in
                /Users/*|/tmp|/tmp/*|/private|/private/*) continue ;;
            esac
            case "$src" in
                */.scratch|*/.scratch/*) continue ;;
            esac
            echo "Mounts denied: " >&2
            echo "The path $src is not shared from the host and is not known to Docker." >&2
            echo "You can configure shared paths from Docker -> Preferences... -> File Sharing." >&2
            exit 125
        done
"#;

/// An image that knows which directories are its own. Masking them is the half of the bug
/// a runtime does *not* refuse — it just does it — so the fake refuses on the image's
/// behalf and says what the job would have found.
const OWN_ROOT: &str = r#"
        # giti-ej2's second fake: an image with a root filesystem of its own.
        for d in $dests; do
            d="${d%:*}"
            case "$d" in
                /bin|/sbin|/usr|/lib|/lib64|/etc|/dev|/Applications|/Library|/opt/local)
                    echo "Error response from daemon: failed to create task for container: $d is the image's own directory and the mount over it is read-only: a write there is refused (read-only file system)" >&2
                    exit 125
                    ;;
            esac
        done
"#;

/// A workspace and a scratch inside it, on disk, because a container mounts what exists.
fn checkout() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("a checkout to mount");
    let workspace = std::fs::canonicalize(dir.path()).expect("the checkout is reachable");
    let scratch = workspace.join(".scratch");
    std::fs::create_dir_all(&scratch).expect("the scratch exists");
    (dir, workspace, scratch)
}

/// The shape `gitiup run --execute` gives a step: the checkout writable as well as the
/// scratch (see `gitiup_run::sandbox::spec_for`).
fn step(workspace: &Path, scratch: &Path) -> Spec {
    Spec::new(workspace, scratch).with_writable(workspace)
}

/// Plan a step and hand the argv to the fake runtime that is currently on `PATH`.
fn spawn(spec: &Spec) -> Refusal {
    let backend = Container::docker();
    let launch = backend
        .plan(spec, &Env::new())
        .expect("a step's spec plans");
    let argv = launch.argv(
        &["/bin/sh".to_string(), "-c".to_string(), "make".to_string()],
        &Env::new(),
    );
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(launch.wrapper_env.clone())
        .output()
        .expect("the fake runtime runs");
    Refusal {
        status: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

impl Refusal {
    fn refused(&self) -> bool {
        self.status != Some(0)
    }
}

/// The ticket, end to end: the spec a step runs in is handed to a runtime that will not
/// share the host's system directories, and the runtime starts the container instead of
/// refusing it with the reporter's error.
#[test]
fn a_step_does_not_ask_the_runtime_to_share_the_hosts_system_directories() {
    run_with(&script(UNSHARED), || {
        let (_dir, workspace, scratch) = checkout();
        let spec = step(&workspace, &scratch);
        // The probe still has to survive: a runtime that will not take the job is not
        // worth handing the arguments to.
        Container::docker()
            .probe()
            .expect("a runtime with an image and a shareable temp dir probes clean");
        let refusal = spawn(&spec);
        assert!(
            !refusal.refused(),
            "the runtime refused the job — this is giti-ej2: {}",
            refusal.stderr
        );
        assert!(
            !refusal.stderr.contains("Mounts denied"),
            "a mount the sharing layer refuses is a job that never started: {}",
            refusal.stderr
        );
        // …and the plan says where the job's toolchain comes from, because that is the
        // question a reader of the short mount list has to be able to answer: the
        // absence of `-v /usr` is invisible until `git` is missing.
        let plan = Container::docker()
            .plan(&spec, &Env::new())
            .expect("a step's spec plans");
        assert!(
            plan.notes
                .iter()
                .any(|note| note.contains("the job's toolchain, not this machine's")),
            "{:?}",
            plan.notes
        );
    });
}

/// The other half, and the one that is not Mac-specific: the job's `/bin`, `/usr`,
/// `/etc` and `/dev` are the image's, and nothing binds over them.
#[test]
fn a_step_does_not_mount_the_host_over_the_images_own_directories() {
    run_with(&script(OWN_ROOT), || {
        let (_dir, workspace, scratch) = checkout();
        let spec = step(&workspace, &scratch);
        let refusal = spawn(&spec);
        assert!(
            !refusal.refused(),
            "something masked the image's own directories — this is giti-ej2: {}",
            refusal.stderr
        );
        assert!(
            !refusal.stderr.contains("read-only"),
            "the job was given a read-only copy of the host where the image keeps its \
             toolchain: {}",
            refusal.stderr
        );
    });
}

/// The point of both fakes, stated without a fake: the mount set is short — the job's own
/// trees, both writable, each at its own path — and a reader of the plan is told where
/// the job's toolchain comes from, because the absence of `-v /usr` is otherwise a thing
/// nobody notices until `git` is gone.
#[test]
fn the_mounts_are_the_jobs_trees_and_nothing_else() {
    let (_dir, workspace, scratch) = checkout();
    let backend = Container::docker();
    let plan = backend
        .mounts(&step(&workspace, &scratch))
        .expect("a step's mounts resolve");
    let w = workspace.display().to_string();
    let s = scratch.display().to_string();
    let volumes: Vec<String> = plan.mounts.iter().map(|mount| mount.volume_arg()).collect();
    assert_eq!(
        volumes,
        vec![format!("{w}:{w}:rw"), format!("{s}:{s}:rw")],
        "two trees, both writable, both at their own path: {volumes:?}"
    );
    assert!(
        plan.notes
            .iter()
            .any(|note| note.contains("system directories are not mounted")),
        "{:?}",
        plan.notes
    );
}

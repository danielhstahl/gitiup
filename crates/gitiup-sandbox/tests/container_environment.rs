//! The job's environment has to arrive **before** the image: a runtime stops reading
//! its own options there.
//!
//! Every executed step of every `--sandbox docker` run failed with this, on every OS, and
//! the message named nothing that would have explained it:
//!
//! ```text
//! exec: "-e": executable file not found in $PATH
//! ```
//!
//! The sandbox was fine. The probe had started containers, watched a write fail to land
//! and seen a connection refused; the plan named the mounts and the image. What was wrong
//! was the order of two parts of one command line: the step's environment is handed to
//! the runtime as `-e KEY=VALUE` arguments, and they were appended *after* the image —
//! and `docker run` does not parse options after the image, it hands everything from
//! there on to the container as its command. So the container started, as confined as
//! can be, with the argv `["-e", "PATH=…", "-e", "HOME=…", …, "/bin/sh", "step-1.sh"]`,
//! and the first thing it tried to exec was a program called `-e`.
//!
//! Why no test saw it: every existing fake-runtime test hands the plan an *empty*
//! environment, because it is testing mounts. A step's environment is never empty —
//! `/bin/sh`, a `PATH`, a `HOME`, the `GITHUB_*` set — so the `-e` block is always
//! present in a real run and absent in the suite.
//!
//! The fake below is therefore a runtime that knows its own grammar: it parses options up
//! to the image, refuses anything option-shaped after it the way the real one does, and
//! runs what is left in the environment it was given as `-e`. Give it the old argv and it
//! answers with the reporter's error; give it the new one and the step runs and prints
//! the environment it was handed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use gitiup_sandbox::backend::{Env, Sandbox};
use gitiup_sandbox::backends::container::Container;
use gitiup_sandbox::spec::Spec;

/// These tests reorder `PATH`, which is process-wide; a probe that found the host's real
/// docker instead of the fake would be reporting on the host.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A container runtime that parses its arguments the way `docker` and `podman` do.
///
/// * options until the first bare word, which is the image;
/// * everything after the image is the container's command, and a command that starts
///   with `-` is the daemon's `exec: "-e": executable file not found in $PATH` refusal
///   (exit 127) rather than an option;
/// * the command runs, in an environment made of nothing plus the `-e` arguments, in the
///   `-w` directory — which is the whole point: a job that cannot report the environment
///   it got has not been given one;
/// * the two escape canaries are answered the way a contained process answers them, so
///   the probe that precedes the run completes and the run is reached at all.
const RUNTIME: &str = r#"#!/bin/sh
# gitiup's container_environment test: a docker that knows where its options end.
LOG='@DIR@/log'
echo "ARGS $*" >> "$LOG" 2>/dev/null
case "$1" in
    version) echo fake-1.0; exit 0 ;;
    image)   echo sha256:00000000; exit 0 ;;
esac
[ "$1" = run ] || exit 0
shift
ENVS=''
WORKDIR=''
while [ $# -gt 0 ]; do
    case "$1" in
        -e) ENVS="$ENVS$2
"; shift 2 ;;
        -v|--tmpfs|-w|--user|--name|--pids-limit|--memory|--network|--cap-drop|--security-opt|--pull|--shm-size|--stop-timeout)
            [ "$1" = -w ] && WORKDIR="$2"
            shift 2 ;;
        -*) shift ;;
        *)  shift; break ;;   # the image: what follows it is the container's command
    esac
done
# From here on, "$@" is the container's command, not the runtime's options.
if [ $# -eq 0 ]; then exit 0; fi
case "$1" in
    -*)
        printf 'exec: "%s": executable file not found in $PATH\n' "$1" >&2
        exit 127 ;;
esac
# A contained process cannot write to an unmounted host path, and a --network=none
# container cannot reach a port on the host; the canaries ask about exactly that.
case "$*" in
    *gitiup-container-probe*|*dev/tcp*|*'nc -w'*) exit 0 ;;
esac
if [ -n "$WORKDIR" ]; then cd "$WORKDIR" 2>/dev/null || exit 125; fi
# The job's environment: nothing inherited, everything it was handed as `-e`.
ENVFILE='@DIR@/env'
printf '%s' "$ENVS" > "$ENVFILE"
if [ -n "$ENVS" ]; then
    OLDIFS=$IFS
    IFS='
'
    for kv in $ENVS; do
        case "$kv" in
            ?*=*) export "$kv" ;;
        esac
    done
    IFS=$OLDIFS
fi
"$@"
"#;

/// Put the fake runtime first on `PATH` for the duration of `body`, and say where the
/// fake left its recordings.
fn with_runtime(body: impl FnOnce(&Path)) {
    let dir = tempfile::tempdir().expect("a temp dir to put a fake runtime in");
    let binary = dir.path().join("docker");
    std::fs::write(
        &binary,
        RUNTIME.replace("@DIR@", &dir.path().display().to_string()),
    )
    .expect("the fake runtime is written");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
        .expect("the fake runtime is executable");
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
    body(dir.path());
    unsafe {
        match previous {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }
}

/// The workspace and scratch of a real step, on disk, because a container mounts what
/// exists and refuses what does not.
fn checkout() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("a checkout to mount");
    let workspace = std::fs::canonicalize(dir.path()).expect("the checkout is reachable");
    let scratch = workspace.join(".scratch");
    std::fs::create_dir_all(&scratch).expect("the scratch exists");
    (dir, workspace, scratch)
}

/// The environment `gitiup run --execute` gives a step: never empty, never inherited.
fn step_env(scratch: &Path) -> Env {
    Env::from([
        (
            "PATH".to_string(),
            "/usr/bin:/bin:/usr/local/bin".to_string(),
        ),
        ("HOME".to_string(), "/home/dev".to_string()),
        (
            "GITHUB_SHA".to_string(),
            "0000000000000000000000000000000000000000".to_string(),
        ),
        (
            "GITHUB_OUTPUT".to_string(),
            scratch.join("outputs-1").display().to_string(),
        ),
    ])
}

/// The environment the fake's container reported, as `-e` arguments delivered them.
fn delivered(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("env")).unwrap_or_default()
}

/// The whole point, end to end: a step's spec and a step's environment, planned and
/// handed to a runtime that enforces its own grammar, and the step runs.
#[test]
fn a_step_runs_in_a_runtime_that_stops_parsing_at_the_image() {
    with_runtime(|dir| {
        let (_keep, workspace, scratch) = checkout();
        let backend = Container::docker();
        backend
            .probe()
            .expect("a runtime with an image and a readable mount probes clean");
        let spec = Spec::new(&workspace, &scratch).with_writable(&workspace);
        let launch = backend
            .plan(&spec, &Env::new())
            .expect("a step's spec plans");
        let env = step_env(&scratch);
        let script = scratch.join("step-1.sh");
        std::fs::write(&script, "printf 'ran %s\\n' \"$GITHUB_SHA\"\n").expect("a step script");
        let argv = launch.argv(&["/bin/sh".to_string(), script.display().to_string()], &env);
        let output = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .envs(launch.wrapper_env.clone())
            .output()
            .expect("the runtime runs");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "the runtime refused the step — this is the bug: {stderr}"
        );
        assert!(
            !stderr.contains("executable file not found"),
            "a container told to exec a program called `-e` is an argv with the \
             environment after the image: {stderr}"
        );
        assert_eq!(
            stdout.trim(),
            "ran 0000000000000000000000000000000000000000",
            "the step ran, but not with the environment it was given"
        );
        // And what it was given is exactly what was asked for, in the runtime's own
        // arguments rather than in the CLI's inherited environment.
        let given = delivered(dir);
        for key in ["PATH", "HOME", "GITHUB_SHA", "GITHUB_OUTPUT"] {
            assert!(given.contains(&format!("{key}=")), "{key}: {given}");
        }
    });
}

/// The same claim read off the argv, which is the half a reviewer of `--json` sees.
#[test]
fn every_environment_argument_precedes_the_image() {
    with_runtime(|_dir| {
        let (_keep, workspace, scratch) = checkout();
        let backend = Container::docker();
        let spec = Spec::new(&workspace, &scratch).with_writable(&workspace);
        let launch = backend
            .plan(&spec, &Env::new())
            .expect("a step's spec plans");
        let argv = launch.argv(&["/bin/sh".to_string()], &step_env(&scratch));
        let image = argv
            .iter()
            .position(|arg| arg == &backend.image())
            .expect("the image is in the command line");
        let positions: Vec<usize> = argv
            .iter()
            .enumerate()
            .filter(|(_, arg)| *arg == "-e")
            .map(|(index, _)| index)
            .collect();
        assert!(
            !positions.is_empty(),
            "a step always has an environment: {argv:?}"
        );
        assert!(
            positions.iter().all(|index| *index < image),
            "everything after `{}` is the job's command, so an `-e` there is a program the \
             job is asked to exec, not an option (found at {:?}): {argv:?}",
            backend.image(),
            positions
                .iter()
                .filter(|index| **index > image)
                .copied()
                .collect::<Vec<_>>()
        );
        // The command follows the image immediately: nothing of the runtime's is left
        // for it to be confused with.
        assert_eq!(&argv[image + 1..], ["/bin/sh".to_string()]);
    });
}

/// The wrapper's own variables stay the wrapper's: the `-e` block is the job's whole
/// environment, and the CLI's `PATH`/`HOME`/`DOCKER_HOST` must not become the job's by
/// accident of ordering.
#[test]
fn the_runtimes_own_environment_is_not_passed_as_the_jobs() {
    with_runtime(|_dir| {
        let (_keep, workspace, scratch) = checkout();
        let backend = Container::docker();
        let spec = Spec::new(&workspace, &scratch).with_writable(&workspace);
        let launch = backend
            .plan(&spec, &Env::new())
            .expect("a step's spec plans");
        assert!(
            !launch.wrapper_env.is_empty(),
            "the CLI needs a PATH and a HOME of its own to find its daemon"
        );
        let mut env = step_env(&scratch);
        env.insert("GITIUP_TOKEN_SENTINEL".to_string(), "hunter2".to_string());
        let argv = launch.argv(&["/bin/sh".to_string()], &env);
        let image = argv
            .iter()
            .position(|arg| arg == &backend.image())
            .expect("the image is in the command line");
        let given: Vec<&str> = argv[..image]
            .windows(2)
            .filter(|pair| pair[0] == "-e")
            .map(|pair| pair[1].as_str())
            .collect();
        let wanted: Vec<String> = env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        assert_eq!(
            given, wanted,
            "the job is handed exactly what it was given, as arguments"
        );
        for key in launch.wrapper_env.keys() {
            assert!(
                !given
                    .iter()
                    .any(|pair| pair.starts_with(&format!("{key}=")))
                    || env.contains_key(key),
                "`{key}` belongs to the runtime's CLI, not to the job: {given:?}"
            );
        }
    });
}

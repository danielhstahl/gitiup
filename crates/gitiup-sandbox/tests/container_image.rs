//! The container rung's two most common failures, and what the tool says about each.
//!
//! Both came out of a Mac (giti-kbs): `docker` was installed, `alpine:3.20` was not, and
//! what a person got was
//!
//! ```text
//! Unable to find image 'alpine:3.20' locally
//! error getting credentials - err: exit status 1, out: ``
//! ```
//!
//! — a sentence about a keychain, when the fact was about an image, and neither of them
//! saying the one thing that would have helped: `docker pull alpine:3.20`. The fixes
//! under test here are that a `run` never pulls, that the refusal names the command,
//! that the runtime's CLI gets an environment it can work in, and that a container
//! which cannot boot is not reported as a sandbox that denies everything.
//!
//! The runtime is faked: a shell script named `docker`, on `PATH`, that records what it
//! was asked for and what it was given. That is the only way to test the answers a
//! macOS user sees on a Linux CI runner, and it keeps the suite honest about the
//! messages rather than about somebody's daemon.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use gitiup_sandbox::backend::{self, Sandbox};
use gitiup_sandbox::backends::container::Container;

/// These tests reorder `PATH` and set `GITIUP_SANDBOX_IMAGE`, both of which are
/// process-wide. Serialise them; a probe that found the host's real docker instead of
/// the fake would be testing the host.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Where the fake left its recording, and the toggles it reads.
struct Fake {
    dir: tempfile::TempDir,
}

/// The fake runtime. It records every call — the argv, and the environment it was
/// given — into `<dir>/log`, then answers like a runtime with the toggle files in
/// `@DIR@` saying which way.
const RUNTIME_SCRIPT: &str = r#"#!/bin/sh
# gitiup's container_image test: a docker that only remembers.
LOG='@DIR@/log'
{
    echo "ARGS $*"
    echo ENV
    env | sort
    echo END
} >> "$LOG" 2>/dev/null
case "$1" in
    version)
        echo fake-1.0
        exit 0
        ;;
    image)
        if [ -f '@DIR@/haveimage' ]; then
            echo sha256:00000000
            exit 0
        fi
        echo "Error response from daemon: No such image: $3" >&2
        exit 1
        ;;
    run)
        if [ -f '@DIR@/noboot' ]; then
            echo "Error response from daemon: no matching manifest for linux/arm64/v8 in the manifest list entries" >&2
            exit 125
        fi
        for a in "$@"; do
            case "$a" in
                *gitiup-alive*)
                    printf '%s' "$a"
                    exit 0
                    ;;
            esac
        done
        exit 0
        ;;
esac
exit 0
"#;

impl Fake {
    /// Write a `docker` that answers `version`, answers `image inspect` according to
    /// [`Self::has_image`], and starts containers according to [`Self::boots`].
    fn new() -> Fake {
        let dir = tempfile::tempdir().expect("a temp dir to put a fake runtime in");
        let script = RUNTIME_SCRIPT.replace("@DIR@", &dir.path().display().to_string());
        let binary = dir.path().join("docker");
        std::fs::write(&binary, script).expect("the fake runtime is written");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))
            .expect("the fake runtime is executable");
        Fake { dir }
    }

    /// Pretend the image is (or is not) in the local store.
    fn has_image(&self, present: bool) {
        let marker = self.dir.path().join("haveimage");
        if present {
            std::fs::write(&marker, "x").unwrap();
        } else {
            let _ = std::fs::remove_file(&marker);
        }
    }

    /// Pretend a container from the image cannot be started (wrong architecture, no
    /// `/bin/sh`, a profile that refuses the start).
    fn boots(&self, boots: bool) {
        let marker = self.dir.path().join("noboot");
        if boots {
            let _ = std::fs::remove_file(&marker);
        } else {
            std::fs::write(&marker, "x").unwrap();
        }
    }

    /// What the fake was asked for and given, one `ARGS … ENV … END` block per call.
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("log")).unwrap_or_default()
    }

    /// Run `body` with the fake first on `PATH` and a pinned image name.
    fn with(&self, body: impl FnOnce(&Fake)) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut searched = vec![self.dir.path().to_path_buf()];
        searched.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let path = std::env::join_paths(searched).expect("PATH can be re-joined");
        let previous = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", &path);
            std::env::set_var("GITIUP_SANDBOX_IMAGE", "gitiup-fake:latest");
            // Not on the runtime CLI's allowlist: if it ever reaches the fake, the
            // allowlist has become a copy of the environment, which is the bug that
            // made a missing image look like a credential fault.
            std::env::set_var("GITIUP_TOKEN_SENTINEL", "hunter2");
        }
        body(self);
        unsafe {
            std::env::remove_var("GITIUP_TOKEN_SENTINEL");
            // Put the machine back: a fake runtime left on PATH would be what the next
            // test in this binary found, and the one after that.
            match previous {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }
}

/// The ticket, end to end: a runtime that works and an image that is not there is a
/// refusal that says what to type, not an unchecked property.
#[test]
fn a_missing_image_is_refused_with_the_command_that_fixes_it() {
    let fake = Fake::new();
    fake.with(|fake| {
        fake.has_image(false);
        let backend = Container::docker();
        let err = backend
            .probe()
            .expect_err("a runtime with no image may not be offered as a sandbox");
        assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
        assert_eq!(err.exit_code(), 6, "a refusal a supervisor can branch on");
        assert!(
            err.detail().contains("gitiup-fake:latest"),
            "the refusal must name the image it wanted: {err}"
        );
        assert!(
            err.detail().contains("does not pull"),
            "and must say why it will not pull: {err}"
        );
        let fix = backend::fix_of(&err).expect("the refusal carries an action");
        assert!(
            fix.contains("docker pull gitiup-fake:latest"),
            "the action is the command to type: {fix}"
        );
        assert!(
            fix.contains("GITIUP_SANDBOX_IMAGE"),
            "and the alternative: {fix}"
        );

        // …and `gitiup doctor` shows the same action, because the ticket's ask was
        // that doctor say so before a run found out.
        let status = backend::Backend::of(&backend);
        assert!(!status.available);
        assert!(
            status
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("docker pull")),
            "doctor prints the fix: {status:?}"
        );
        assert!(
            status.unchecked.is_empty(),
            "a refused backend does not get to list properties it did not check: {status:?}"
        );
    });
}

/// The property nobody could check is not the same as the property that failed: a probe
/// that merely *skipped* `image` used to leave docker looking available, and the run
/// then died inside the runtime's own pull.
#[test]
fn a_missing_image_is_not_reported_as_an_unchecked_property() {
    let fake = Fake::new();
    fake.with(|fake| {
        fake.has_image(false);
        let probe = Container::docker().probe();
        let err = match probe {
            Ok(probe) => panic!(
                "docker was offered as a sandbox with no image to run a job in: {}",
                probe.summary()
            ),
            Err(why) => why,
        };
        assert!(
            err.detail().contains("image failed"),
            "the failing property is named: {err}"
        );
    });
}

/// An image the runtime cannot start looks exactly like a sandbox that denies
/// everything to a probe made of denials: nothing was written, nothing was reached.
/// So the probe proves a container ran before it believes either canary.
#[test]
fn an_image_that_cannot_boot_is_not_reported_as_a_sandbox() {
    let fake = Fake::new();
    fake.with(|fake| {
        fake.has_image(true);
        fake.boots(false);
        let err = Container::docker()
            .probe()
            .expect_err("a container that never started confines nothing");
        assert!(
            err.detail().contains("container-starts"),
            "the failing property is named: {err}"
        );
        assert!(
            !err.detail().contains("tcp-egress"),
            "a canary that never ran must not be claimed either way: {err}"
        );
        assert!(
            backend::fix_of(&err).is_some(),
            "and the refusal says what to try: {err}"
        );
    });
}

/// The positive control: with an image that is there and boots, the same probe says so
/// and gets on with the canaries.
#[test]
fn a_present_image_that_boots_is_observed() {
    let fake = Fake::new();
    fake.with(|fake| {
        fake.has_image(true);
        fake.boots(true);
        let probe = Container::docker()
            .probe()
            .expect("the fake runtime boots a container");
        assert!(probe.observed().contains(&"image"), "{}", probe.summary());
        assert!(
            probe.observed().contains(&"container-starts"),
            "{}",
            probe.summary()
        );
        // The fake cannot serve a bind mount, so the file-sharing advice is expected;
        // nothing about the image is.
        assert!(
            probe.fixes().iter().all(|fix| !fix.contains("pull")),
            "an image that is there must not be offered for pulling: {:?}",
            probe.fixes()
        );
        // And the advice that *was* recorded reaches the report `gitiup doctor` prints:
        // the fake cannot serve a bind mount, so the file-sharing advice is the one fix
        // this machine is being given.
        let status = backend::Backend::of(&Container::docker());
        assert!(status.available, "{}", status.note);
        assert!(
            status
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("File sharing")),
            "the advice is carried to doctor: {status:?}"
        );
    });
}

/// The other half of the Mac's message: the runtime's own CLI was run with an empty
/// environment, so it could not find its config or its credential helper and reported
/// a keychain fault in place of the truth. The job still gets nothing but what it was
/// given.
#[test]
fn the_runtime_cli_is_given_the_environment_it_needs_and_no_more() {
    let fake = Fake::new();
    fake.with(|fake| {
        fake.has_image(true);
        fake.boots(true);
        Container::docker()
            .probe()
            .expect("the fake runtime answers");
        let log = fake.log();
        assert!(!log.is_empty(), "the fake recorded nothing");
        assert!(
            log.contains("PATH="),
            "the CLI must find docker-credential-* on PATH:\n{log}"
        );
        assert!(log.contains("HOME="), "and ~/.docker/config.json: {log}");
        assert!(
            !log.contains("hunter2"),
            "but the caller's environment is not handed over wholesale:\n{log}"
        );
    });
}

/// Every `run` says `--pull never`, so "the image moved between the two runs" is not
/// something a report can contain, and a missing image stays gitiup's message rather
/// than the runtime's.
#[test]
fn a_container_run_never_pulls() {
    let fake = Fake::new();
    fake.with(|_| {
        let workspace = tempfile::tempdir().unwrap();
        let scratch = workspace.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let spec = gitiup_sandbox::spec::Spec::new(workspace.path(), &scratch);
        let launch = Container::docker()
            .plan(&spec, &gitiup_sandbox::backend::Env::new())
            .expect("a plan for a workspace that exists");
        let argv = launch.prefix.join(" ");
        assert!(argv.contains("--pull never"), "{argv}");
        assert!(
            argv.ends_with("gitiup-fake:latest"),
            "the image is the last argument, before the job's own command: {argv}"
        );
        assert!(
            launch.notes.iter().any(|note| note.contains("never pulls")),
            "the plan says the image is an input, not something to fetch: {:?}",
            launch.notes
        );
        // The wrapper's environment is the CLI's, and must never reach the job: the
        // job's environment is the `-e` arguments, and nothing else.
        assert!(
            launch.wrapper_env.contains_key("PATH"),
            "{:?}",
            launch.wrapper_env.keys().collect::<Vec<_>>()
        );
        assert!(
            !launch.wrapper_env.contains_key("GITIUP_TOKEN_SENTINEL"),
            "wrapper_env is an allowlist, not a copy: {:?}",
            launch.wrapper_env.keys().collect::<Vec<_>>()
        );
        let job = launch.argv(
            &["/bin/true".to_string()],
            &gitiup_sandbox::backend::Env::new(),
        );
        assert!(
            !job.iter().any(|argument| argument.contains("PATH=")),
            "the CLI's environment is not the job's: {job:?}"
        );
    });
}

/// The fake is only a fake if it is the `docker` that gets found.
#[test]
fn the_fake_is_what_the_probe_finds() {
    let fake = Fake::new();
    fake.with(|fake| {
        let found: PathBuf = fake.dir.path().join("docker");
        assert_eq!(
            gitiup_sandbox::platform::binary("docker").as_deref(),
            Some(found.as_path()),
            "PATH was not honoured, so nothing here tested anything"
        );
    });
}

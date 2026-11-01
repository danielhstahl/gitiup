//! `docker` and `podman`: the rungs that isolate the most, and need the most setup.
//!
//! A container is the only backend here that gives the job a filesystem of its own, so
//! a write that succeeds inside it is not a write to your disk at all. That is worth
//! preferring when it is available — and it comes with two debts this module pays out
//! loud rather than quiet:
//!
//! * **the image has to be there, and gitiup never pulls one for you.** A job's
//!   network is denied by default, a tag that moves between runs is not a reproducible
//!   input, and a pull in the middle of a run is the runtime making a decision the
//!   operator should have made — so every `run` carries `--pull never`, and a missing
//!   image is a refusal that names the command (`docker pull alpine:3.20`) rather than
//!   a surprise halfway through a build. `gitiup doctor --sandbox` says the same thing
//!   before you find out by running something.
//! * **what the job sees must be what it gets.** Workspace and scratch are bind-mounted
//!   at *their own absolute paths* so the paths in the job's environment stay true
//!   inside the container. A sandbox that silently relocated the workspace would
//!   produce logs that match nothing. That rule has a consequence the runtime makes
//!   unavoidable: mounts are keyed by destination, so a tree named twice (the checkout
//!   is on the read list because every workspace is, and on the write list because a
//!   build writes where it is checked out) is two mounts at one address, and the
//!   runtime refuses the container with `Duplicate mount point: '/work'`. The mounts
//!   are therefore worked out by [`crate::mounts`] before any argv exists, and a
//!   collision the tool cannot resolve is gitiup's own refusal, naming both grants.
//!
//! The runtime's *own* CLI is a separate matter from the job it starts. The job gets
//! an environment built from nothing; the CLI has to find its config, its credential
//! helper and (on macOS or rootless podman) a daemon that is only reachable at an
//! endpoint named by the environment. Clearing the environment for both is what turns
//! "that image is not here" into `error getting credentials - err: exit status 1`, a
//! message about a keychain when the fact was about an image, so [`Launch::wrapper_env`]
//! hands the CLI exactly the variables it needs and nothing else.
//!
//! Egress: `--network=none` whenever the job asks for nothing, which is
//! kernel-enforced. When the job names registries, the container gets the runtime's
//! normal network plus the proxy environment — [`Enforcement::Audited`], not
//! kernel-enforced, because a container on a bridge network *can* dial out directly if
//! its author ignores `HTTP_PROXY`. That is why a quorum job with an allowlist is
//! refused on this backend and accepted on `landlock`, where the kernel refuses every
//! port except the proxy's.
//!
//! # On macOS this rung is a different animal, and a better one
//!
//! There is no container runtime in Darwin; `docker` and `podman` on a Mac talk to a
//! Linux VM the desktop app manages. That makes the isolation **stronger** than the
//! same command on Linux — the job cannot touch this kernel at all, because it is a
//! different kernel — and it makes the mounts a contract of their own, because only the
//! directories the app has agreed to *share* exist inside the VM. A path outside that
//! list mounts as an empty directory, silently, and the job cannot find its own
//! checkout. That is why `probe` checks `mount_probe` (can a container read a file
//! the host just wrote?) before it believes anything about the write checks, and why
//! [`plan`](crate::backend::Sandbox::plan) puts the file-sharing warning in the notes.

use std::path::PathBuf;
use std::process::Command;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape::Witness;
use crate::kernel::Kernel;
use crate::mounts::{self, Plan};
use crate::platform::{OS, Platform};
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The image used when nothing says otherwise.
///
/// A floating tag, which giti-bgy.4 will refuse for a verification run: the default
/// exists so `gitiup doctor --sandbox` has something to try, not so a volunteer trusts
/// it. Set `GITIUP_SANDBOX_IMAGE` to a digest-pinned image for real work.
pub const DEFAULT_IMAGE: &str = "alpine:3.20";

/// The environment variable that names the job's image.
pub const IMAGE_ENV: &str = "GITIUP_SANDBOX_IMAGE";

/// The environment the runtime's **own CLI** needs, and nothing more.
///
/// Not the job's environment — that is built from nothing and passed as `-e` arguments
/// (see [`Launch::env_as_args`]). These are the variables the `docker`/`podman`
/// *program* cannot work without:
///
/// * `PATH`, `HOME`, `USER`, `LOGNAME` — where its credential helpers live
///   (`docker-credential-osxkeychain`, `docker-credential-desktop`) and where its
///   config is (`~/.docker/config.json`). Without them a pull of a public image fails
///   with `error getting credentials - err: exit status 1`, which reads like a keychain
///   fault and is really a stripped environment.
/// * `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, `TMPDIR` — rootless podman keeps its socket
///   and its store under these.
/// * `DOCKER_*`, `CONTAINER_*` — which daemon to talk to at all. On macOS the desktop
///   app's endpoint is sometimes only in `DOCKER_HOST`, and a rootless podman is
///   reachable only through `CONTAINER_HOST`.
pub const CLI_ENV: [&str; 14] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_API_VERSION",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
];

/// [`CLI_ENV`] as it actually is on this machine, missing entries omitted.
pub fn cli_env() -> Env {
    CLI_ENV
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| (key.to_string(), value))
        })
        .collect()
}

/// The `docker` or `podman` backend.
#[derive(Debug, Clone, Copy)]
pub struct Container {
    /// Which runtime this is: also the name recorded in provenance.
    runtime: &'static str,
}

impl Container {
    /// The `docker` backend.
    pub fn docker() -> Container {
        Container { runtime: "docker" }
    }

    /// The `podman` backend.
    pub fn podman() -> Container {
        Container { runtime: "podman" }
    }

    /// The runtime's binary, if it is installed.
    pub fn binary(&self) -> Option<PathBuf> {
        Kernel::binary(self.runtime)
    }

    /// The image this run would use.
    pub fn image(&self) -> String {
        std::env::var(IMAGE_ENV)
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| DEFAULT_IMAGE.to_string())
    }

    /// The command that would put the job's image where this runtime can see it.
    ///
    /// Spelled out rather than described because the person reading the refusal has
    /// two seconds of work to do, not a paragraph to parse.
    pub fn pull_command(&self) -> String {
        format!("{} pull {}", self.runtime, self.image())
    }

    /// Whether the image is already in the runtime's local store.
    ///
    /// `None` means "could not tell" (no binary, no daemon, an unexpected answer);
    /// callers must not turn that into "missing", because the fix for an unreachable
    /// daemon is not `pull`.
    pub fn image_present(&self) -> Option<bool> {
        self.exec(
            &[
                "image".to_string(),
                "inspect".to_string(),
                "--format".to_string(),
                "{{.Id}}".to_string(),
                self.image(),
            ],
            &[],
        )
        .ok()
        .map(|output| output.status.success())
    }

    /// The `run` arguments that implement the baseline policy for one job.
    ///
    /// `mounts` is [`Container::mounts`] for the same spec, resolved once by the caller.
    fn run_args(&self, spec: &Spec, mounts: &Plan) -> Vec<String> {
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            // The image is an input, not something to go and fetch: see the module
            // doc. `--pull never` also keeps a missing image from turning into the
            // runtime's own network error, which on macOS is the credential-helper
            // message rather than anything about the image.
            "--pull".to_string(),
            "never".to_string(),
            // Shows up in `docker ps`, which is where someone looks when a job does not
            // finish.
            "--name".to_string(),
            format!("gitiup-{}-{}", self.runtime, std::process::id()),
            // No capabilities, and no way to gain them.
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--pids-limit".to_string(),
            spec.limits
                .processes
                .map(|count| count.to_string())
                .unwrap_or_else(|| "256".to_string()),
        ];
        // `--memory` is the one resource cap that means the same thing here and in the
        // spec. CPU *seconds* and container CPU *shares* are different quantities, so
        // the wall-clock and CPU-time caps stay with the spawner (giti-bgy.2 owns the
        // policy for both).
        if let Some(bytes) = spec.limits.address_bytes {
            args.push("--memory".to_string());
            args.push(format!("{bytes}"));
        }
        args.extend(self.network_args(spec));
        // The job runs as the uid that started gitiup, so what it can read is what
        // *this* user can read — not root's, and not the daemon's.
        args.push("--user".to_string());
        args.push(format!("{}:{}", unsafe { libc::getuid() }, unsafe {
            libc::getgid()
        }));
        // Every mount, read-only first, at its own cleaned destination, and exactly one
        // per destination — see [`crate::mounts`]. A read-only mount whose host
        // directory is not there is skipped rather than fatal: a container asked for a
        // workspace that does not exist is a confusing mount error instead of a refusal
        // that says so, and `/lib64` on a merged-usr distro is nobody's emergency.
        for mount in &mounts.mounts {
            if !mount.writable && !mount.source.exists() {
                continue;
            }
            args.push("-v".to_string());
            args.push(mount.volume_arg());
        }
        // The one place the scratch cap is enforced exactly rather than by
        // `RLIMIT_FSIZE`: a sized tmpfs.
        args.push("--tmpfs".to_string());
        args.push(format!("/tmp:rw,noexec,nosuid,size={}", spec.scratch_bytes));
        args.push("-w".to_string());
        // The working directory is the workspace *as it is mounted*, which is its
        // cleaned destination — the string the job's own paths have to match.
        args.push(mounts::clean(&spec.workspace));
        args.push(self.image());
        args
    }

    /// The mounts this runtime will be asked to make for one spec, clashes already
    /// resolved or refused.
    ///
    /// The runtime keeps one mount per destination and refuses a container that puts
    /// two there — `Duplicate mount point: '/work'` — which is a thing a workflow step
    /// asks for by default, because its checkout is both readable and writable.
    /// [`crate::mounts`] is what makes that a decision gitiup makes and explains rather
    /// than a daemon's error message; `gitiup doctor --sandbox` says the same thing
    /// before a job finds it out.
    pub fn mounts(&self, spec: &Spec) -> Result<Plan> {
        mounts::plan(spec, &mounts::TMPFS_DESTINATIONS)
    }

    /// The baseline flags for a probe container: the same policy, no mounts.
    fn probe_args(&self) -> Vec<String> {
        vec![
            "run".to_string(),
            "--rm".to_string(),
            "--pull".to_string(),
            "never".to_string(),
            "--network".to_string(),
            "none".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--user".to_string(),
            format!("{}:{}", unsafe { libc::getuid() }, unsafe {
                libc::getgid()
            }),
            self.image(),
        ]
    }

    /// The network flag: `none` unless the job named something it needs.
    fn network_args(&self, spec: &Spec) -> Vec<String> {
        if spec.egress.is_denied() {
            return vec!["--network".to_string(), "none".to_string()];
        }
        // Saying `bridge` out loud is what makes the weaker enforcement visible in the
        // command line a reviewer reads.
        vec!["--network".to_string(), "bridge".to_string()]
    }

    /// Run one short command with the runtime, for probing.
    ///
    /// The environment is cleared and then refilled with [`cli_env`]: the probe must not
    /// learn anything about the caller's environment, but the CLI it is talking to
    /// still has to find its own daemon and credential helpers.
    fn exec(&self, extra: &[String], command: &[String]) -> std::io::Result<std::process::Output> {
        let binary = self
            .binary()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, self.runtime))?;
        let mut program = vec![binary.display().to_string()];
        program.extend(extra.iter().cloned());
        program.extend(command.iter().cloned());
        Command::new(&program[0])
            .args(&program[1..])
            .env_clear()
            .envs(cli_env())
            .stdin(std::process::Stdio::null())
            .output()
    }

    /// Whether a container from the job's image actually **runs**, and says so.
    ///
    /// Every canary below asks for a *non*-event — the write that did not land, the
    /// connection that did not arrive — and a container that never started produces the
    /// very same non-event. Without this check an image the runtime cannot boot (wrong
    /// architecture on Apple silicon, no `/bin/sh` in a `FROM scratch` image, a
    /// seccomp profile that refuses the start) would be reported as a sandbox that
    /// denies everything, which is the most expensive lie a probe can tell.
    fn start_probe(&self) -> std::result::Result<(), String> {
        let marker = format!("gitiup-alive-{}", std::process::id());
        let command = format!("printf '%s' '{marker}'");
        let output = self.exec(
            &self.probe_args(),
            &["/bin/sh".to_string(), "-c".to_string(), command],
        );
        match output {
            Ok(output) if String::from_utf8_lossy(&output.stdout).contains(marker.as_str()) => {
                Ok(())
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                Err(format!(
                    "a `{runtime} run` of `{image}` printed nothing, so no canary could be \
                     believed: {}",
                    if stderr.is_empty() {
                        format!(
                            "it exited {} with nothing on stderr",
                            output
                                .status
                                .code()
                                .map(|code| code.to_string())
                                .unwrap_or_else(|| "on a signal".to_string())
                        )
                    } else {
                        stderr
                    },
                    runtime = self.runtime,
                    image = self.image()
                ))
            }
            Err(why) => Err(format!(
                "`{runtime} run` of `{image}` could not be started: {why}",
                runtime = self.runtime,
                image = self.image()
            )),
        }
    }

    /// Whether a container can actually see a host directory it was given.
    ///
    /// This is the check that matters on macOS and is a formality on Linux. A
    /// container runtime on macOS runs inside a VM, and only the directories the
    /// desktop app has agreed to *share* exist in it: bind-mount a path that is not
    /// shared and the runtime does not complain — it mounts an empty directory, and the
    /// job quietly cannot find its own checkout. Worse, the write-outside check below
    /// becomes vacuous, because a write to a host path that the VM cannot see was never
    /// a write to the host at all. So this writes a file, mounts its directory
    /// read-only, and asks a container to read it back: an observation, not a config
    /// read.
    fn mount_probe(&self) -> Option<String> {
        let directory = std::env::temp_dir();
        let marker = directory.join(format!("gitiup-mount-probe-{}", std::process::id()));
        let secret = format!("gitiup-visible-{}", std::process::id());
        if std::fs::write(&marker, &secret).is_err() {
            return None;
        }
        // The mount goes before the image, which `probe_args` puts last.
        let mut args = self.probe_args();
        let image = args.pop();
        args.push("-v".to_string());
        args.push(format!(
            "{}:{}:ro",
            directory.display(),
            directory.display()
        ));
        if let Some(image) = image {
            args.push(image);
        }
        let command = format!("cat '{}' 2>/dev/null || true", marker.display());
        let read = self.exec(&args, &["/bin/sh".to_string(), "-c".to_string(), command]);
        let _ = std::fs::remove_file(&marker);
        match read {
            Ok(output) if String::from_utf8_lossy(&output.stdout).contains(&secret) => {
                Some(directory.display().to_string())
            }
            _ => None,
        }
    }

    /// The host path a probe container would have to escape to, and whether it managed
    /// to write there.
    fn fs_probe(&self) -> bool {
        // Nothing is mounted in the probe container, so any host path is outside it;
        // `/tmp` is chosen because it exists in every image and on every host.
        let target = std::env::temp_dir().join(format!(
            "gitiup-container-probe-{}-{}",
            self.runtime,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&target);
        let command = format!("printf x > '{}' 2>/dev/null || exit 7", target.display());
        let _ = self.exec(
            &self.probe_args(),
            &["/bin/sh".to_string(), "-c".to_string(), command],
        );
        let escaped = target.exists();
        let _ = std::fs::remove_file(&target);
        escaped
    }

    /// Whether a probe container could reach a port on the host.
    fn net_probe(&self, witness: &Witness) -> bool {
        let port = witness.port();
        // Any of these is a sincere attempt; the observation is on the host side, so a
        // minimal image without `nc` still cannot make a connection arrive.
        let command = format!(
            "nc -w 1 127.0.0.1 {p} </dev/null >/dev/null 2>&1 || \
             (exec 3<>/dev/tcp/127.0.0.1/{p}) 2>/dev/null || true",
            p = port
        );
        let _ = self.exec(
            &self.probe_args(),
            &["/bin/sh".to_string(), "-c".to_string(), command],
        );
        std::thread::sleep(std::time::Duration::from_millis(150));
        witness.saw_connection()
    }
}

impl Sandbox for Container {
    fn name(&self) -> &'static str {
        self.runtime
    }

    fn kind(&self) -> Kind {
        Kind::Container
    }

    fn guarantees(&self) -> &'static str {
        "the job runs in a container with no capabilities, no new privileges, its own \
         pid namespace and its own filesystem; the workspace is bind-mounted read-only \
         and only the scratch and a size-capped /tmp are writable; egress is \
         --network=none unless the job named registries, in which case the proxy policy \
         is audited rather than kernel-enforced"
    }

    fn probe(&self) -> Result<Probe> {
        let mut probe = Probe::builder(self.runtime);
        let Some(binary) = self.binary() else {
            probe.failed(
                "runtime",
                format!(
                    "no `{}` binary on PATH (install it, or use a backend that needs no \
                     runtime: landlock, unshare or bwrap)",
                    self.runtime
                ),
            );
            return probe.finish();
        };
        probe.observed("runtime", format!("`{}` is installed", binary.display()));

        match Command::new(&binary)
            .args(["version", "--format", "{{.Server.Version}}"])
            .env_clear()
            .envs(cli_env())
            .output()
        {
            Ok(output) if output.status.success() => probe.observed(
                "daemon",
                format!(
                    "the {} daemon answers: {}",
                    self.runtime,
                    String::from_utf8_lossy(&output.stdout).trim()
                ),
            ),
            Ok(output) => {
                probe.failed(
                    "daemon",
                    format!(
                        "`{} version` failed: {}",
                        self.runtime,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                );
                // Nothing below this line can be answered by a runtime whose daemon is
                // not answering, and asking it about the image would turn a daemon
                // fault into a `docker pull` suggestion.
                return probe.finish();
            }
            Err(why) => {
                probe.failed(
                    "daemon",
                    format!("`{}` could not be run: {why}", binary.display()),
                );
                return probe.finish();
            }
        }

        let image = self.image();
        // Asked of the runtime itself rather than inferred: "I have alpine:3.20" means
        // something different to this daemon, to a remote daemon, and to a machine with
        // two architectures of the same tag.
        match self.image_present() {
            Some(true) => probe.observed("image", format!("`{image}` is present locally")),
            Some(false) => {
                probe.fix(format!(
                    "put the image where the runtime can see it first: `{}` — gitiup will \
                     not pull it during a run; or set {IMAGE_ENV} to an image that is \
                     already here",
                    self.pull_command()
                ));
                probe.failed(
                    "image",
                    format!(
                        "`{image}` is not present locally in `{}`, and gitiup does not pull \
                         an image while running a job: the job's network is denied by \
                         default, and an image that can move between runs is not the \
                         reproducible input a report is supposed to describe",
                        self.runtime
                    ),
                );
                probe.skipped("fs-write-outside", "no local image to run the canary in");
                probe.skipped("tcp-egress", "no local image to run the canary in");
                probe.skipped("ptrace", "no local image to run the canary in");
                return probe.finish();
            }
            // The daemon answered `version` and not `image inspect`, which is odd. The
            // honest answer is "I could not ask", and a backend that cannot ask about
            // the one thing every canary runs in is not offered as a sandbox.
            None => {
                probe.failed(
                    "image",
                    format!(
                        "`{runtime} image inspect {image}` could not be run, so `{image}` \
                         is neither confirmed nor absent, and no canary could be run in it",
                        runtime = self.runtime
                    ),
                );
                return probe.finish();
            }
        }

        match self.start_probe() {
            Ok(()) => probe.observed(
                "container-starts",
                format!("a container from `{image}` ran and printed what it was asked to"),
            ),
            Err(why) => {
                probe.fix(format!(
                    "an image the runtime cannot boot confines nothing: see what \
                     `{runtime} run --rm --pull never {image} /bin/sh -c true` says — an \
                     amd64-only image will not start an arm64 job (pull it again on this \
                     machine's own architecture, or point {IMAGE_ENV} at one that can), and \
                     a `FROM scratch` image has no /bin/sh for the canary to use",
                    runtime = self.runtime
                ));
                probe.failed("container-starts", why);
                return probe.finish();
            }
        }

        // Can a container see what the host put in a directory? Everything the
        // write check below can claim depends on the answer, and on macOS it is not a
        // formality: an unshared path mounts as an empty directory, without a word of
        // complaint from the runtime.
        let visible = self.mount_probe();
        match &visible {
            Some(directory) => probe.observed(
                "mount-visibility",
                format!("a read-only mount of {directory} was readable inside the container"),
            ),
            None => {
                // Not a refusal — a container backend that cannot see a host directory
                // can still run a job that needs nothing — but it is the one failure on
                // a Mac with a two-minute fix, so it is printed as a warning with that
                // fix rather than buried in the list of unchecked properties.
                probe.fix(
                    "if a job needs files from this machine, add their directories to the \
                     runtime's file-sharing list (Docker Desktop: Settings → Resources → \
                     File sharing), or run gitiup inside the VM, where mounts are not \
                     involved at all (docs/macos.md)",
                );
                probe.skipped(
                    "mount-visibility",
                    "a container could not read a file the host just wrote into a directory it was \
                     given as `-v`: the job would not find its own checkout. On macOS this means \
                     the directory is not in the runtime's file-sharing list (Docker Desktop: \
                     Settings → Resources → File sharing); or run gitiup inside the VM, where \
                     mounts are not involved at all (docs/macos.md)",
                );
            }
        }

        if self.fs_probe() {
            probe.failed(
                "fs-write-outside",
                "a container wrote to a host path that was never mounted",
            );
        } else if visible.is_none() {
            // Not "denied": the write cannot land on a host the VM cannot see, so the
            // check observed nothing about isolation and says so.
            probe.skipped(
                "fs-write-outside",
                "the runtime could not see a host directory at all, so a write that did not \
                 arrive is a fact about file sharing and not about the sandbox",
            );
        } else {
            probe.observed(
                "fs-write-outside",
                "a write to a host path did not land on the host",
            );
        }
        match Witness::open() {
            Ok(witness) => {
                if self.net_probe(&witness) {
                    probe.failed(
                        "tcp-egress",
                        "a --network=none container reached a port on the host",
                    );
                } else {
                    probe.observed("tcp-egress", crate::backends::WITNESS_NOTE);
                }
            }
            Err(why) => probe.skipped("tcp-egress", format!("no witness port: {why}")),
        }
        probe.skipped(
            "ptrace",
            "the container has its own pid namespace and the image has no canary binary",
        );
        probe.skipped(
            "fork-bomb",
            "--pids-limit is set on every run; this probe does not spend the time to fill it",
        );
        probe.finish()
    }

    fn enforcement(&self, egress: &Egress) -> Enforcement {
        if egress.is_denied() {
            Enforcement::Kernel
        } else {
            Enforcement::Audited
        }
    }

    fn plan(&self, spec: &Spec, env: &Env) -> Result<Launch> {
        super::require_absolute("workspace", &spec.workspace)?;
        super::require_absolute("scratch", &spec.scratch)?;
        let binary = self.binary().ok_or_else(|| {
            Error::new(
                ErrorKind::Policy,
                "sandbox",
                format!("no `{}` binary on PATH", self.runtime),
            )
        })?;
        let mut prefix = vec![binary.display().to_string()];
        let mounts = self.mounts(spec)?;
        prefix.extend(self.run_args(spec, &mounts));
        let mut launch = Launch {
            prefix,
            env_as_args: true,
            wrapper_env: cli_env(),
            cwd: Some(spec.workspace.clone()),
            wall_clock: spec.limits.wall_clock,
            ..Launch::default()
        };
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!(
            "image {}: expected to be here already; gitiup never pulls during a run \
             (`{}` if it is not, `gitiup doctor --sandbox` checks)",
            self.image(),
            self.pull_command()
        ));
        launch.notes.push(if spec.egress.is_denied() {
            "network none: nothing can be reached".to_string()
        } else {
            format!(
                "network bridge, proxy only: {}",
                spec.egress
                    .proxy_url()
                    .map(|url| url.to_string())
                    .unwrap_or_else(|| "no proxy".to_string())
            )
        });
        // The mount notes are the *resolved* mounts, not the spec's wish list: a
        // reviewer who reads "read-only mounts: /work" about a checkout that is
        // mounted read-write has been told something false.
        launch
            .notes
            .push(format!("read-only mounts: {}", mounts.list(false)));
        launch
            .notes
            .push(format!("writable mounts: {}", mounts.list(true)));
        for note in &mounts.notes {
            launch.notes.push(format!("mount points: {note}"));
        }
        if Platform::survey().os == OS::MacOS {
            // The one thing about a container on macOS that has bitten everyone: the
            // job runs in the desktop app's Linux VM, and a path the app has not
            // agreed to share mounts as an empty directory with no warning at all.
            launch.notes.push(
                "this container runs in the runtime's Linux VM: every mounted path above must \
                 be in the desktop app's file-sharing list, or the job will find an empty \
                 directory where its checkout should be (docs/macos.md)"
                    .to_string(),
            );
        }
        let _ = env;
        Ok(launch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_gets_no_capabilities_and_no_network_by_default() {
        let backend = Container::docker();
        // Only paths that exist are mounted (a container for a workspace that is not
        // there would be a mount error instead of a refusal), so the test uses a real
        // directory.
        let workspace = tempfile::tempdir().unwrap();
        let scratch = workspace.path().join(".scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let args = args_for(&backend, &Spec::new(workspace.path(), &scratch));
        let text = args.join(" ");
        assert!(text.contains("--cap-drop ALL"), "{text}");
        assert!(text.contains("no-new-privileges"), "{text}");
        assert!(text.contains("--network none"), "{text}");
        assert!(text.contains("--pids-limit 256"), "{text}");
        let workspace_text = workspace.path().display().to_string();
        let scratch_text = scratch.display().to_string();
        assert!(
            text.contains(&format!("{workspace_text}:{workspace_text}:ro")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{scratch_text}:{scratch_text}:rw")),
            "{text}"
        );
        assert!(text.contains("size="), "{text}");
        // The last argument is the image; the command follows it, with no separator.
        assert_eq!(args.last().unwrap(), &backend.image());
    }

    #[test]
    fn naming_a_registry_moves_the_container_to_an_audited_network() {
        // The distinction this test protects: `--network=none` is a kernel denial,
        // `--network=bridge` plus a proxy is not, and a quorum job must know which it
        // got.
        let backend = Container::podman();
        let denied = Spec::new("/work", "/work/.scratch");
        assert!(
            args_for(&backend, &denied)
                .join(" ")
                .contains("--network none")
        );
        assert_eq!(
            backend.enforcement(&Egress::deny_all()),
            Enforcement::Kernel
        );
        let allowed =
            Spec::new("/work", "/work/.scratch").with_egress(Egress::allow_registries().unwrap());
        assert!(
            args_for(&backend, &allowed)
                .join(" ")
                .contains("--network bridge"),
            "{allowed:?}"
        );
        assert_eq!(backend.enforcement(&allowed.egress), Enforcement::Audited);
    }

    /// The shape `gitiup run --execute` gives every step: the checkout writable as well
    /// as the scratch (see `gitiup_run::sandbox::spec_for`).
    fn step(workspace: &str, scratch: &str) -> Spec {
        Spec::new(workspace, scratch).with_writable(workspace)
    }

    /// The `run` arguments a spec produces, with the mounts resolved the way `plan`
    /// resolves them — which is the whole point: the refusal and the argv come from the
    /// same one computation.
    fn args_for(backend: &Container, spec: &Spec) -> Vec<String> {
        let mounts = backend
            .mounts(spec)
            .expect("the mounts for this spec resolve");
        backend.run_args(spec, &mounts)
    }

    #[test]
    fn a_checkout_named_readable_and_writable_is_mounted_once() {
        // giti-0xi, and the reason this file does not build `-v` arguments from the two
        // grant lists any more. The checkout is on the read list because every workspace
        // is and on the write list because a build writes where it is checked out, so the
        // two loops each emitted a mount for `/work`, and the runtime answered
        // `Duplicate mount point: '/work'` — naming neither grant, on every OS.
        let args = args_for(&Container::docker(), &step("/work", "/work/.scratch")).join(" ");
        assert_eq!(args.matches("-v /work:").count(), 1, "{args}");
        assert!(args.contains("/work:/work:rw"), "{args}");
        assert!(
            !args.contains("/work:/work:ro"),
            "the writable grant won, so the read-only one must not still be there: {args}"
        );
        // The scratch inside the checkout is a nested mount, not a clash, and is still
        // there and still writable.
        assert!(args.contains("/work/.scratch:/work/.scratch:rw"), "{args}");
        // And the job's working directory is the mount the job can actually see.
        assert!(args.contains("-w /work "), "{args}");
    }

    #[test]
    fn a_scratch_that_is_tmp_itself_is_refused_before_the_runtime_sees_it() {
        // The other way to meet `Duplicate mount point`: the scratch is /tmp (TMPDIR is
        // /tmp in a great many containers) and gitiup also mounts a size-capped tmpfs
        // there. The cap is the point of the tmpfs, so the scratch moves, not the tmpfs.
        let err = Container::docker()
            .mounts(&Spec::new("/work", "/tmp"))
            .unwrap_err();
        assert!(err.detail().contains("/tmp"), "{err}");
        assert!(err.hint().unwrap().contains("/tmp/gitiup-scratch"), "{err}");
        // A scratch inside /tmp keeps its cap and its mount.
        let args = args_for(
            &Container::docker(),
            &Spec::new("/work", "/tmp/gitiup-scratch"),
        )
        .join(" ");
        assert!(
            args.contains("/tmp/gitiup-scratch:/tmp/gitiup-scratch:rw"),
            "{args}"
        );
        assert!(
            args.contains("--tmpfs /tmp:rw,noexec,nosuid,size="),
            "{args}"
        );
    }

    #[test]
    fn a_relative_workspace_is_refused_rather_than_mounted_somewhere_surprising() {
        let spec = Spec::new("relative/work", "/tmp/scratch");
        let err = Container::docker().plan(&spec, &Env::new()).unwrap_err();
        assert!(err.detail().contains("absolute"), "{err}");
        assert!(err.hint().unwrap().contains("--workdir"), "{err}");
    }

    #[test]
    fn an_absent_runtime_is_a_refusal_that_names_an_alternative() {
        let backend = Container::docker();
        if backend.binary().is_some() {
            // Docker is installed here, so absence has nothing to say.
            return;
        }
        let err = backend.probe().unwrap_err();
        assert!(err.detail().contains("docker"), "{err}");
        assert!(err.detail().contains("landlock"), "{err}");
    }

    #[test]
    fn the_default_image_is_named_and_pinning_is_the_callers_job() {
        assert!(
            DEFAULT_IMAGE.contains(':'),
            "an untagged image is a moving target"
        );
        unsafe { std::env::remove_var("GITIUP_SANDBOX_IMAGE") };
        assert_eq!(Container::docker().image(), DEFAULT_IMAGE.to_string());
        // The command a refusal prints has to be the command the runtime understands,
        // with the image the refusal named — a person copies it out of the message.
        assert_eq!(
            Container::docker().pull_command(),
            format!("docker pull {DEFAULT_IMAGE}")
        );
        assert_eq!(
            Container::podman().pull_command(),
            format!("podman pull {DEFAULT_IMAGE}")
        );
        unsafe { std::env::set_var("GITIUP_SANDBOX_IMAGE", "example.com/img@sha256:aaa") };
        assert!(Container::docker().image().contains('@'));
        assert_eq!(
            Container::docker().pull_command(),
            "docker pull example.com/img@sha256:aaa"
        );
        unsafe { std::env::remove_var("GITIUP_SANDBOX_IMAGE") };
    }

    #[test]
    fn neither_a_job_nor_a_probe_is_allowed_to_pull_on_the_way_past() {
        // `--pull never` is what makes "the image moved between the two runs" a thing
        // this tool cannot do, and what keeps a missing image a gitiup message rather
        // than the runtime's own network error.
        let backend = Container::docker();
        let workspace = tempfile::tempdir().unwrap();
        let scratch = workspace.path().join(".scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        assert!(
            args_for(&backend, &Spec::new(workspace.path(), &scratch))
                .join(" ")
                .contains("--pull never"),
            "a job never pulls"
        );
        assert!(
            backend.probe_args().join(" ").contains("--pull never"),
            "a probe never pulls either"
        );
    }

    #[test]
    fn the_cli_environment_is_an_allowlist_not_a_copy() {
        // The Mac's `error getting credentials` was a stripped environment, and the
        // obvious over-correction is to hand the runtime the whole thing — which hands
        // it the runner's tokens too.
        unsafe { std::env::set_var("GITIUP_TOKEN_SENTINEL", "hunter2") };
        let given = cli_env();
        unsafe { std::env::remove_var("GITIUP_TOKEN_SENTINEL") };
        if std::env::var_os("PATH").is_some() {
            assert!(given.contains_key("PATH"), "the CLI must find its helpers");
        }
        assert!(
            !given.contains_key("GITIUP_TOKEN_SENTINEL"),
            "{:?}",
            given.keys().collect::<Vec<_>>()
        );
        assert!(
            !given.contains_key(IMAGE_ENV),
            "the image goes on the command line, not in the CLI's environment"
        );
    }

    #[test]
    fn a_probe_never_depends_on_the_callers_workspace() {
        // The probe is what decides whether a spec is runnable, so it may not need one.
        let probe = Container::docker().probe();
        if let Ok(probe) = probe {
            assert!(!probe.properties.is_empty());
        }
    }
}

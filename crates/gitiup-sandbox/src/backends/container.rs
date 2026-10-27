//! `docker` and `podman`: the rungs that isolate the most, and need the most setup.
//!
//! A container is the only backend here that gives the job a filesystem of its own, so
//! a write that succeeds inside it is not a write to your disk at all. That is worth
//! preferring when it is available — and it comes with two debts this module pays out
//! loud rather than quiet:
//!
//! * **the image has to be there.** With egress denied (the default) the runtime cannot
//!   pull it, so a missing image is reported as an unverified property with
//!   instructions, not a surprise halfway through a build.
//! * **what the job sees must be what it gets.** Workspace and scratch are bind-mounted
//!   at *their own absolute paths* so the paths in the job's environment stay true
//!   inside the container. A sandbox that silently relocated the workspace would
//!   produce logs that match nothing.
//!
//! Egress: `--network=none` whenever the job asks for nothing, which is
//! kernel-enforced. When the job names registries, the container gets the runtime's
//! normal network plus the proxy environment — [`Enforcement::Audited`], not
//! kernel-enforced, because a container on a bridge network *can* dial out directly if
//! its author ignores `HTTP_PROXY`. That is why a quorum job with an allowlist is
//! refused on this backend and accepted on `landlock`, where the kernel refuses every
//! port except the proxy's.

use std::path::PathBuf;
use std::process::Command;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape::Witness;
use crate::kernel::Kernel;
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The image used when nothing says otherwise.
///
/// A floating tag, which giti-bgy.4 will refuse for a verification run: the default
/// exists so `gitiup doctor --sandbox` has something to try, not so a volunteer trusts
/// it. Set `GITIUP_SANDBOX_IMAGE` to a digest-pinned image for real work.
pub const DEFAULT_IMAGE: &str = "alpine:3.20";

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
        std::env::var("GITIUP_SANDBOX_IMAGE")
            .ok()
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| DEFAULT_IMAGE.to_string())
    }

    /// The `run` arguments that implement the baseline policy for one job.
    fn run_args(&self, spec: &Spec) -> Vec<String> {
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
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
        for path in spec.read_paths() {
            if path.exists() {
                args.push("-v".to_string());
                args.push(format!("{}:{}:ro", path.display(), path.display()));
            }
        }
        for path in spec.write_paths() {
            args.push("-v".to_string());
            args.push(format!("{}:{}:rw", path.display(), path.display()));
        }
        // The one place the scratch cap is enforced exactly rather than by
        // `RLIMIT_FSIZE`: a sized tmpfs.
        args.push("--tmpfs".to_string());
        args.push(format!("/tmp:rw,noexec,nosuid,size={}", spec.scratch_bytes));
        args.push("-w".to_string());
        args.push(spec.workspace.display().to_string());
        args.push(self.image());
        args
    }

    /// The baseline flags for a probe container: the same policy, no mounts.
    fn probe_args(&self) -> Vec<String> {
        vec![
            "run".to_string(),
            "--rm".to_string(),
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
            .stdin(std::process::Stdio::null())
            .output()
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
            Ok(output) => probe.failed(
                "daemon",
                format!(
                    "`{} version` failed: {}",
                    self.runtime,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ),
            Err(why) => probe.failed(
                "daemon",
                format!("`{}` could not be run: {why}", binary.display()),
            ),
        }

        let image = self.image();
        let present = self
            .exec(
                &["image".to_string(), "inspect".to_string(), image.clone()],
                &[],
            )
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !present {
            probe.skipped(
                "image",
                format!(
                    "`{image}` is not present locally, and with egress denied it cannot be \
                     pulled: load it, or set GITIUP_SANDBOX_IMAGE to an image you have",
                ),
            );
            probe.skipped("fs-write-outside", "no local image to run the canary in");
            probe.skipped("tcp-egress", "no local image to run the canary in");
            probe.skipped("ptrace", "no local image to run the canary in");
            return probe.finish();
        }
        probe.observed("image", format!("`{image}` is present locally"));

        if self.fs_probe() {
            probe.failed(
                "fs-write-outside",
                "a container wrote to a host path that was never mounted",
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
        prefix.extend(self.run_args(spec));
        let mut launch = Launch {
            prefix,
            env_as_args: true,
            cwd: Some(spec.workspace.clone()),
            wall_clock: spec.limits.wall_clock,
            ..Launch::default()
        };
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!("image {}", self.image()));
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
        launch.notes.push(format!(
            "read-only mounts: {}",
            path_list(&spec.read_paths())
        ));
        launch.notes.push(format!(
            "writable mounts: {}",
            path_list(&spec.write_paths())
        ));
        let _ = env;
        Ok(launch)
    }
}

fn path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "(none)".to_string();
    }
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
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
        let args = backend.run_args(&Spec::new(workspace.path(), &scratch));
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
            backend
                .run_args(&denied)
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
            backend
                .run_args(&allowed)
                .join(" ")
                .contains("--network bridge"),
            "{allowed:?}"
        );
        assert_eq!(backend.enforcement(&allowed.egress), Enforcement::Audited);
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
        unsafe { std::env::set_var("GITIUP_SANDBOX_IMAGE", "example.com/img@sha256:aaa") };
        assert!(Container::docker().image().contains('@'));
        unsafe { std::env::remove_var("GITIUP_SANDBOX_IMAGE") };
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

//! `bwrap`: bubblewrap, the unprivileged container-in-a-binary.
//!
//! The middle rung of the ladder, and for a volunteer's machine often the best one: it
//! gives the job its own mount, pid, net and ipc namespaces with no daemon and no root,
//! which means the filesystem really is rebuilt for the job — the workspace bind-mounted
//! read-only, the scratch writable, everything else present only if the plan put it
//! there.
//!
//! Two things it does not give: a process cap (that needs a cgroup, which is giti-bgy.2's
//! work) and network *with* a filter — you get either no network (`--unshare-all`, the
//! default) or the host's (`--share-net`), so an allowlist on this backend is
//! audited-only, exactly as it is for a container.

use std::process::Command;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape;
use crate::kernel::Kernel;
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The `bwrap` backend.
#[derive(Debug, Clone, Copy)]
pub struct Bubblewrap;

impl Bubblewrap {
    /// The binary, if it is installed.
    pub fn binary() -> Option<std::path::PathBuf> {
        Kernel::binary("bwrap")
    }

    /// The namespace and safety flags, plus the mounts one spec asks for.
    fn args(&self, spec: &Spec) -> Vec<String> {
        let mut args = vec![
            // A sandbox that outlives the process that made it is a leak.
            "--die-with-parent".to_string(),
            // No controlling terminal: a job cannot inject keystrokes into the runner's
            // tty (the TIOCSTI class of escape).
            "--new-session".to_string(),
            // user, ipc, net, pid, cgroup and mount. The network goes back only if the
            // job named egress it needs.
            "--unshare-all".to_string(),
            "--hostname".to_string(),
            "gitiup".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
        ];
        if !spec.egress.is_denied() {
            args.push("--share-net".to_string());
        }
        // The scratch cap, expressed the only way bubblewrap takes it: a sized tmpfs.
        let mib = (spec.scratch_bytes / (1 << 20)).max(1).to_string();
        args.push("--size".to_string());
        args.push(mib);
        args.push("--tmpfs".to_string());
        args.push("/tmp".to_string());
        for path in spec.read_paths() {
            // `-try` so a missing `/lib64` on a merged-usr distro is not a refusal.
            args.push("--ro-bind-try".to_string());
            args.push(path.display().to_string());
            args.push(path.display().to_string());
        }
        for path in spec.write_paths() {
            args.push("--bind".to_string());
            args.push(path.display().to_string());
            args.push(path.display().to_string());
        }
        args.push("--setenv".to_string());
        args.push("HOME".to_string());
        args.push(spec.scratch.display().to_string());
        args.push("--setenv".to_string());
        args.push("TMPDIR".to_string());
        args.push(spec.scratch.display().to_string());
        args.push("--setenv".to_string());
        args.push("PATH".to_string());
        args.push(crate::linux::default_path().to_string_lossy().into_owned());
        args
    }
}

impl Sandbox for Bubblewrap {
    fn name(&self) -> &'static str {
        "bwrap"
    }

    fn kind(&self) -> Kind {
        Kind::Namespace
    }

    fn guarantees(&self) -> &'static str {
        "the job gets its own mount, pid, net and ipc namespaces: the workspace is \
         bind-mounted read-only, only the scratch is writable, /tmp is a size-capped \
         tmpfs, /proc is its own, and there is no controlling terminal; egress is denied \
         by the namespace unless the job named registries, in which case the proxy policy \
         is audited rather than kernel-enforced; no process cap (that needs a cgroup)"
    }

    fn probe(&self) -> Result<Probe> {
        let mut probe = Probe::builder(self.name());
        let Some(binary) = Bubblewrap::binary() else {
            probe.failed(
                "bubblewrap",
                "no `bwrap` binary on PATH (install the `bubblewrap` package, or use \
                 --sandbox landlock which needs nothing)",
            );
            return probe.finish();
        };
        probe.observed("bubblewrap", format!("`{}` is installed", binary.display()));

        // Not a version check: build a real, minimal sandbox and run `/bin/true` in it.
        // This is what catches the distribution-specific failures a `--version` string
        // cannot — a setuid build with user namespaces refused, a seccomp profile in an
        // outer container, a `/proc` that cannot be mounted.
        let attempt = Command::new(&binary)
            .args([
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--unshare-all",
            ])
            .arg("--")
            .arg("/bin/true")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .output();
        match attempt {
            Ok(output) if output.status.success() => {
                probe.observed("sandbox", "a minimal bwrap sandbox ran /bin/true");
            }
            Ok(output) => {
                probe.failed(
                    "sandbox",
                    format!(
                        "a minimal bwrap sandbox failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                );
            }
            Err(why) => {
                probe.failed(
                    "sandbox",
                    format!("`{}` could not be run: {why}", binary.display()),
                );
            }
        }

        let scratch = escape::probe_scratch("bwrap")?;
        let spec = Spec::new(scratch.join("workspace"), scratch.join("scratch"));
        std::fs::create_dir_all(&spec.workspace).ok();
        std::fs::create_dir_all(&spec.scratch).ok();
        let results = escape::all(self, &spec);
        escape::probe_from(&mut probe, &results);
        probe.finish()
    }

    fn enforcement(&self, egress: &Egress) -> Enforcement {
        if egress.is_denied() {
            Enforcement::Kernel
        } else {
            Enforcement::Audited
        }
    }

    fn plan(&self, spec: &Spec, _env: &Env) -> Result<Launch> {
        let binary = Bubblewrap::binary().ok_or_else(|| {
            Error::new(
                ErrorKind::Policy,
                "sandbox",
                "no `bwrap` binary on PATH (install the `bubblewrap` package)",
            )
        })?;
        for path in spec.write_paths() {
            std::fs::create_dir_all(&path).map_err(|why| {
                Error::new(
                    ErrorKind::Invalid,
                    "sandbox",
                    format!(
                        "could not create the writable directory {}: {why}",
                        path.display()
                    ),
                )
            })?;
        }
        let mut prefix = vec![binary.display().to_string()];
        prefix.extend(self.args(spec));
        let mut launch = Launch {
            prefix,
            separator: Some("--".to_string()),
            ..Launch::default()
        };
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!(
            "read-only: {}",
            spec.read_paths()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        launch.notes.push(format!(
            "writable: {}",
            spec.write_paths()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        launch.notes.push(if spec.egress.is_denied() {
            "no network namespace shared with the host".to_string()
        } else {
            "--share-net: the job can see the host network; the proxy policy is audited".to_string()
        });
        Ok(launch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_namespace_flags_are_the_ones_that_matter() {
        let spec = Spec::new("/work", "/work/.scratch");
        let args = Bubblewrap.args(&spec);
        let text = args.join(" ");
        assert!(text.contains("--unshare-all"), "{text}");
        assert!(text.contains("--die-with-parent"), "{text}");
        assert!(text.contains("--new-session"), "{text}");
        assert!(
            !text.contains("--share-net"),
            "default-deny must not share the network"
        );
        assert!(text.contains("--ro-bind-try /work /work"), "{text}");
        assert!(
            text.contains("--bind /work/.scratch /work/.scratch"),
            "{text}"
        );
        assert!(text.contains("--proc /proc"), "{text}");
    }

    #[test]
    fn naming_a_registry_shares_the_network_and_changes_the_enforcement() {
        let backend = Bubblewrap;
        let allowed =
            Spec::new("/work", "/work/.scratch").with_egress(Egress::allow_registries().unwrap());
        assert!(backend.args(&allowed).join(" ").contains("--share-net"));
        assert_eq!(backend.enforcement(&allowed.egress), Enforcement::Audited);
        assert_eq!(
            backend.enforcement(&Egress::deny_all()),
            Enforcement::Kernel,
            "the namespace denial is the strong case, and it is the default"
        );
    }

    #[test]
    fn a_probe_needs_no_workspace() {
        if let Ok(probe) = Bubblewrap.probe() {
            assert!(!probe.properties.is_empty());
        }
    }
}

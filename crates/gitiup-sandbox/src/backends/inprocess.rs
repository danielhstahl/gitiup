//! `landlock`: the in-process backend — Landlock for the filesystem and TCP ports,
//! seccomp for the syscalls that must not exist, `setrlimit` for the cheap backstop.
//!
//! This is the interesting rung of the ladder, because it needs no daemon, no root, no
//! container runtime and no setup: Landlock is designed to be usable by an
//! unprivileged process that wants to restrict *itself*, and seccomp needs only
//! `no_new_privs`. On a kernel with Landlock ABI 4 or later it is the only backend that
//! can offer kernel-enforced *allowlist* egress: every TCP port except the proxy's is
//! refused by the kernel, so a job that ignores `HTTP_PROXY` has nowhere to go.
//!
//! What it does not do, stated because a reviewer must be able to see it:
//!
//! * **reads are not isolated.** Landlock grants rights per subtree; the rules give the
//!   job read and execute rights on the system directories it needs, and the
//!   workspace, and nothing removes read access to the rest. A secret inside the
//!   workspace is readable — which is exactly why the runner hands over secret *names*
//!   and not values (giti-bgy.3), and why the plain answer "the filesystem is isolated"
//!   is not made here.
//! * **no new namespaces.** There is no pid namespace, so `ps` shows the host's
//!   processes (harmless, but not hidden), and the `ptrace` refusal comes from seccomp
//!   rather than from a namespace.
//! * **UDP is not covered.** Landlock's network rights are TCP; the per-job resolver
//!   makes the rest of the name service consistent, but it is not enforcement.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape;
use crate::kernel::{Availability, Kernel};
use crate::linux::{self, SeccompFilter};
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The Landlock ABI from which TCP ports can be refused.
const NET_ABI: u32 = 4;

/// The in-process backend.
#[derive(Debug, Clone, Copy)]
pub struct Landlock;

impl Landlock {
    /// The ABI this kernel reports, if any.
    pub fn abi() -> Option<u32> {
        linux::landlock_abi()
    }

    /// The TCP ports a spec leaves reachable. Default-deny means the empty list, which
    /// is Landlock's "no TCP at all".
    fn ports(egress: &Egress) -> Vec<u16> {
        egress
            .proxy()
            .map(|proxy| vec![proxy.endpoint().port()])
            .unwrap_or_default()
    }

    /// Everything the child needs to apply its own cage, decided before the fork so
    /// that nothing in the child allocates.
    fn plan_hooks(&self, spec: &Spec) -> impl Fn() -> std::io::Result<()> + Send + Sync + 'static {
        let read_only = spec.read_paths();
        let read_write = spec.write_paths();
        let ports = Self::ports(&spec.egress);
        let limits = spec.limits.clone();
        let uid = spec.unprivileged_uid;
        let gid = spec.unprivileged_uid.map(|_| 65534);
        let scratch_bytes = spec.scratch_bytes;
        let filter = SeccompFilter::hardened();
        let debug = std::env::var_os("GITIUP_SANDBOX_DEBUG").is_some();
        move || {
            if debug {
                crate::debug_hook("hook entered");
            }
            // The order is not cosmetic: seccomp and Landlock both require
            // `no_new_privs`, and the privilege drop must happen before the filter
            // refuses the syscalls that would do it.
            if let Err(why) = linux::no_new_privs() {
                if debug {
                    crate::debug_hook(&format!("no_new_privs: {why}"));
                }
                return Err(std::io::Error::other(why.to_string()));
            }
            if let Err(why) = linux::drop_privileges(uid, gid) {
                if debug {
                    crate::debug_hook(&format!("drop_privileges: {why}"));
                }
                return Err(std::io::Error::other(why.to_string()));
            }
            linux::apply_limits(
                limits.cpu_seconds,
                limits.address_bytes,
                limits.processes,
                limits.file_bytes.or(Some(scratch_bytes)),
            );
            let outcome = match linux::landlock_restrict(&read_only, &read_write, &ports) {
                Ok(outcome) => outcome,
                Err(why) => {
                    if debug {
                        crate::debug_hook(&format!("landlock: {why}"));
                    }
                    return Err(std::io::Error::other(why.to_string()));
                }
            };
            if !outcome.skipped.is_empty() {
                // A grant we could not make is a hole, and a hole is a refusal. The
                // commonest cause is a directory that does not exist on this distro,
                // which `read_paths` deliberately includes (a missing `/lib64` is not
                // a security problem), so only a *writable* path being missing is
                // fatal.
                let fatal: Vec<PathBuf> = outcome
                    .skipped
                    .iter()
                    .filter(|path| read_write.iter().any(|granted| granted == *path))
                    .cloned()
                    .collect();
                if !fatal.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "could not grant write access to {}: the directory does not exist",
                        fatal
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
            // SAFETY: this is the forked child, one step before `execve`, and the
            // filter is irreversible by design.
            if let Err(why) = unsafe { filter.install() } {
                if debug {
                    crate::debug_hook(&format!("seccomp install: {why}"));
                }
                return Err(why);
            }
            Ok(())
        }
    }
}

/// Explain a confined child that will not start, when the reason is a grant that was
/// never made.
///
/// Landlock refuses `execve` of a program that no granted tree covers, and the parent
/// only sees `EPERM` — which looks exactly like a sandbox that is too tight, and sends
/// people off debugging seccomp. `Spec::tool_dirs` is the knob; point at it.
pub fn exec_grant_hint(spec: &Spec, program: &std::path::Path) -> Option<String> {
    let covered = |paths: Vec<PathBuf>| paths.iter().any(|root| program.starts_with(root));
    if covered(spec.read_paths()) || covered(spec.write_paths()) {
        return None;
    }
    Some(format!(
        "`{}` is under no path the sandbox grants: name its directory with 
         `Spec::with_read_path`, or put the tool in the scratch",
        program.display()
    ))
}

impl Sandbox for Landlock {
    fn name(&self) -> &'static str {
        "landlock"
    }

    fn kind(&self) -> Kind {
        Kind::InProcess
    }

    fn guarantees(&self) -> &'static str {
        "Landlock refuses writes outside the scratch and refuses every TCP port the job \
         was not given (ABI 4+); a seccomp filter refuses ptrace, process_vm_readv, \
         mount, unshare, setns, module loading, open_by_handle_at, the privilege \
         syscalls and seccomp itself; no new privileges; rlimits on cpu seconds, address \
         space, process count and file size; core dumps off. Reads are NOT isolated: \
         anything this user can read can still be read, so no secret is handed to a job \
         at all"
    }

    fn probe(&self) -> Result<Probe> {
        let survey = Kernel::survey();
        let mut probe = Probe::builder(self.name());
        let Some(abi) = survey.landlock_abi else {
            let lsm = if survey.lsm.is_empty() {
                "and /sys/kernel/security/lsm is not readable".to_string()
            } else {
                format!("and the loaded LSM list is `{}`", survey.lsm.join(","))
            };
            probe.failed(
                "landlock",
                format!(
                    "this kernel ({}) has no Landlock {lsm}; need Linux 5.13+ with `landlock` \
                     enabled, or use unshare/bwrap/docker instead",
                    survey.kernel
                ),
            );
            return probe.finish();
        };
        probe.observed(
            "landlock-abi",
            format!(
                "Landlock ABI {abi} (network rights {})",
                if abi >= NET_ABI {
                    "available"
                } else {
                    "need ABI 4"
                }
            ),
        );
        match &survey.seccomp_usable {
            Availability::Yes => {
                probe.observed(
                    "seccomp",
                    format!(
                        "a {}-syscall filter installed in a test child",
                        SeccompFilter::hardened().refused().len()
                    ),
                );
            }
            other => {
                probe.skipped(
                    "seccomp",
                    format!(
                        "no filter could be installed here ({}), so ptrace and the syscall \
                         denials are not in force",
                        other.reason().unwrap_or("unknown")
                    ),
                );
            }
        }
        if abi < NET_ABI {
            probe.skipped(
                "tcp-egress",
                format!(
                    "Landlock ABI {abi} cannot refuse TCP ports; the proxy policy is audited only"
                ),
            );
        }

        // Run the real escape checks through the real confinement path.
        let scratch = escape::probe_scratch("landlock")?;
        let spec = Spec::new(scratch.join("workspace"), scratch.join("scratch"))
            .with_scratch_cap(64 << 20);
        std::fs::create_dir_all(&spec.workspace).ok();
        std::fs::create_dir_all(&spec.scratch).ok();
        let results = escape::all(self, &spec);
        escape::probe_from(&mut probe, &results);
        probe.observed(
            "writable-root",
            format!("only {} may be written", spec.scratch.display()),
        );
        probe.finish()
    }

    fn enforcement(&self, egress: &Egress) -> Enforcement {
        match Self::abi() {
            Some(abi) if abi >= NET_ABI => Enforcement::Kernel,
            // Without Landlock's net rights the proxy is advice, and with no allowlist
            // at all there is nothing even advising.
            _ => {
                if egress.is_denied() {
                    Enforcement::None
                } else {
                    Enforcement::Audited
                }
            }
        }
    }

    fn plan(&self, spec: &Spec, _env: &Env) -> Result<Launch> {
        spec.check()?;
        // A rule needs a directory that exists; creating it here is the only side
        // effect a plan is allowed, and it is the one every runner wants anyway.
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
        let mut launch = Launch::direct();
        launch.env.insert(
            "PATH".to_string(),
            linux::default_path().to_string_lossy().into_owned(),
        );
        launch
            .env
            .insert("HOME".to_string(), spec.scratch.display().to_string());
        launch
            .env
            .insert("TMPDIR".to_string(), spec.scratch.display().to_string());
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!(
            "landlock abi {}",
            Self::abi()
                .map(|abi| abi.to_string())
                .unwrap_or_else(|| "absent".to_string())
        ));
        launch.notes.push(format!(
            "writable {} (cap {} bytes)",
            spec.scratch.display(),
            spec.scratch_bytes
        ));
        launch
            .notes
            .push(match Self::ports(&spec.egress).as_slice() {
                [] => "no TCP ports at all".to_string(),
                ports => format!(
                    "TCP port(s) {} only",
                    ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            });
        launch.notes.push(format!(
            "seccomp refuses {} syscalls",
            SeccompFilter::hardened().refused().len()
        ));
        Ok(launch)
    }

    fn tune(&self, command: &mut Command, spec: &Spec) -> Result<()> {
        // One hook, applied in one place: see [`crate::linux`].
        let hooks = self.plan_hooks(spec);
        unsafe {
            command.pre_exec(hooks);
        }
        Ok(())
    }
}

/// The syscalls the seccomp filter refuses, for `doctor` and for the guarantees text.
pub fn refused_syscalls() -> Vec<&'static str> {
    SeccompFilter::hardened().refused().to_vec()
}

/// A `PATH` inside the confinement, exported for the runner's own environment builder.
pub fn confined_path() -> BTreeMap<String, String> {
    let mut env = Env::new();
    env.insert(
        "PATH".to_string(),
        linux::default_path().to_string_lossy().into_owned(),
    );
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_with_no_allowlist_is_given_no_tcp_ports() {
        assert!(Landlock::ports(&Egress::deny_all()).is_empty());
        let egress = Egress::allow_registries().unwrap();
        assert_eq!(
            Landlock::ports(&egress),
            vec![egress.proxy().unwrap().endpoint().port()],
            "the only port left open is the proxy's own"
        );
    }

    #[test]
    fn a_missing_directory_is_said_loudly_by_plan() {
        // A writable path a user cannot create is a refusal at plan time, not a
        // confined process that cannot write anything.
        let spec = Spec::new(
            "/tmp/gitiup-landlock-test",
            "/proc/definitely-not-writable/scratch",
        );
        let err = Landlock.plan(&spec, &Env::new()).unwrap_err();
        assert!(err.detail().contains("could not create"), "{err}");
    }

    #[test]
    fn the_plan_pins_a_home_and_a_tmp_inside_the_scratch() {
        let directory = tempfile::tempdir().unwrap();
        let spec = Spec::new(directory.path(), directory.path().join("scratch"));
        let launch = Landlock.plan(&spec, &Env::new()).unwrap();
        assert_eq!(launch.env["HOME"], spec.scratch.display().to_string());
        assert_eq!(launch.env["TMPDIR"], spec.scratch.display().to_string());
        assert!(
            launch.env["PATH"].starts_with("/usr"),
            "a confined job still needs a PATH"
        );
        assert!(
            launch
                .notes
                .iter()
                .any(|note| note.contains("no TCP ports")),
            "{:?}",
            launch.notes
        );
    }

    #[test]
    fn the_probe_never_claims_more_than_the_kernel_has() {
        let probe = Landlock.probe();
        match (Landlock::abi(), probe) {
            (None, Err(why)) => assert!(why.detail().contains("Landlock"), "{why}"),
            (Some(_), Ok(probe)) => {
                assert!(probe.observed().contains(&"landlock-abi"));
            }
            (Some(_), Err(why)) => {
                // A refusal must name the check that failed, whatever it was.
                assert!(why.detail().contains("failed"), "{why}");
            }
            (None, Ok(_)) => panic!("a kernel with no Landlock must not pass the probe"),
        }
    }
}

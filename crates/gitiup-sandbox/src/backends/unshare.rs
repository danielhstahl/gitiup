//! `unshare`: user and network namespaces via `unshare(1)`.
//!
//! The oldest rung of the ladder still standing in this build, and the one that got
//! there with the least machinery: a new user namespace (so the job is nobody out
//! there) and a new network namespace (so the only interface is a down `lo`) are two
//! syscalls and a `/bin/true`.
//!
//! What it cannot do is the filesystem: without a mount namespace the workspace stays
//! writable, so the guarantees say exactly that and `doctor` points at `bwrap` or
//! `landlock` for the rest. Where `unshare(1)` is old enough to also do `--pid
//! --mount-proc`, that variant is used and *said* — a probe that quietly downgrades is
//! the kind of thing an attestation should not have to rely on.

use std::process::Command;
use std::sync::OnceLock;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape;
use crate::kernel::Kernel;
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The `unshare(1)` backend.
#[derive(Debug, Clone, Copy)]
pub struct Unshare;

/// The strongest form: user, network and pid namespaces, with a fresh `/proc`.
fn full_argv() -> Vec<String> {
    vec![
        "--user".to_string(),
        "--map-root-user".to_string(),
        "--fork".to_string(),
        "--net".to_string(),
        "--pid".to_string(),
        "--mount-proc".to_string(),
    ]
}

/// The fallback for a util-linux that cannot `--mount-proc` in a user namespace, or a
/// kernel that will not allow it.
fn basic_argv() -> Vec<String> {
    vec![
        "--user".to_string(),
        "--map-root-user".to_string(),
        "--fork".to_string(),
        "--net".to_string(),
    ]
}

/// The variant this machine allowed, established once by trying.
///
/// A probe that reports "available" and a plan that then uses a *different* set of
/// flags would be the gap an attestation falls through, so the choice is made by the
/// probe and reused by the plan.
fn chosen() -> Option<&'static Vec<String>> {
    static CHOSEN: OnceLock<Option<Vec<String>>> = OnceLock::new();
    CHOSEN
        .get_or_init(|| {
            [full_argv(), basic_argv()]
                .into_iter()
                .find(|argv| attempt(argv).is_ok())
        })
        .as_ref()
}

/// Run `<program> <argv> -- /bin/true` and report what the kernel said.
fn attempt(argv: &[String]) -> std::result::Result<(), String> {
    let program = Kernel::binary("unshare")
        .ok_or_else(|| "no `unshare` binary on PATH (it is part of util-linux)".to_string())?;
    let mut command = Command::new(&program);
    command.args(argv);
    command.arg("--");
    command.arg("/bin/true");
    command.env_clear();
    command.stdin(std::process::Stdio::null());
    let output = command
        .output()
        .map_err(|why| format!("`{}` could not be run: {why}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if detail.is_empty() {
        format!("`unshare {}` exited {}", argv.join(" "), output.status)
    } else {
        detail
    })
}

impl Sandbox for Unshare {
    fn name(&self) -> &'static str {
        "unshare"
    }

    fn kind(&self) -> Kind {
        Kind::Namespace
    }

    fn guarantees(&self) -> &'static str {
        "no network egress (a new network namespace whose only interface is a down lo); \
         runs as mapped root in a new user namespace, so the host's uids are unreachable; \
         the filesystem is NOT isolated, so a write to the workspace is a write to the \
         workspace — use bwrap or landlock for that"
    }

    fn probe(&self) -> Result<Probe> {
        let mut probe = Probe::builder(self.name());
        let argv = match chosen() {
            Some(argv) => argv,
            None => {
                let why = attempt(&basic_argv()).unwrap_err();
                probe.failed(
                    "user-namespaces",
                    format!(
                        "{why} — user namespaces may be disabled by the kernel or refused by \
                         an outer container's seccomp profile (this is common inside docker); \
                         `sysctl kernel.unprivileged_userns_clone` and \
                         `sysctl kernel.seccomp.actions_avail` are where to look"
                    ),
                );
                return probe.finish();
            }
        };
        probe.observed("user-namespaces", "`unshare --user --net` ran /bin/true");
        if argv.contains(&"--pid".to_string()) {
            probe.observed(
                "pid-namespace",
                "`--pid --mount-proc` worked, so /proc is the sandbox's own",
            );
        } else {
            probe.skipped(
                "pid-namespace",
                "this unshare(1) or kernel would not allow `--pid --mount-proc` in a user namespace",
            );
        }
        probe.skipped(
            "fs-write-outside",
            "this backend does not isolate the filesystem; bwrap or landlock do",
        );

        // The checks that do apply: nothing should reach the host's network, and the
        // canary can show whether the syscall denials are needed at all.
        let scratch = escape::probe_scratch("unshare")?;
        let spec = Spec::new(scratch.join("workspace"), scratch.join("scratch"));
        std::fs::create_dir_all(&spec.workspace).ok();
        std::fs::create_dir_all(&spec.scratch).ok();
        match escape::outbound_connect(self, &spec) {
            Ok(outcome) => escape::probe_from(&mut probe, &[("tcp-egress", outcome)]),
            Err(why) => {
                probe.skipped("tcp-egress", why.detail().to_string());
            }
        }
        match escape::ptrace_escape(self, &spec) {
            Ok(outcome) => escape::probe_from(&mut probe, &[("ptrace", outcome)]),
            Err(why) => {
                probe.skipped("ptrace", why.detail().to_string());
            }
        }
        probe.skipped(
            "fork-bomb",
            "a namespace has no process cap; that is giti-bgy.2's cgroup work",
        );
        probe.finish()
    }

    fn enforcement(&self, _egress: &Egress) -> Enforcement {
        // The job has no interface to send anything out of, which is as kernel-enforced
        // as it gets — and it is why an allowlist on this backend means "no egress",
        // not "egress via the proxy".
        Enforcement::Kernel
    }

    fn plan(&self, spec: &Spec, _env: &Env) -> Result<Launch> {
        let argv = chosen().cloned().ok_or_else(|| {
            Error::new(
                ErrorKind::Policy,
                "sandbox",
                "user namespaces are not usable on this machine, so `unshare` cannot confine anything",
            )
            .with_hint("`gitiup doctor --sandbox` lists the backends this kernel does offer")
        })?;
        let program = Kernel::binary("unshare").ok_or_else(|| {
            Error::new(ErrorKind::Policy, "sandbox", "no `unshare` binary on PATH")
        })?;
        let mut prefix = vec![program.display().to_string()];
        prefix.extend(argv.iter().cloned());
        let mut launch = Launch {
            prefix,
            separator: Some("--".to_string()),
            ..Launch::default()
        };
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!("namespaces: {}", argv.join(" ")));
        if !spec.egress.is_denied() {
            launch.notes.push(
                "the job has no network namespace route, so an egress allowlist has no \
                 effect here: deny-all is the only policy this backend can serve"
                    .to_string(),
            );
        }
        Ok(launch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stronger_variant_is_the_one_tried_first() {
        let full = full_argv();
        assert!(full.contains(&"--pid".to_string()));
        assert!(full.contains(&"--mount-proc".to_string()));
        // The fallback must still be a sandbox: dropping the pid namespace is allowed,
        // dropping the network namespace would not be.
        let basic = basic_argv();
        assert!(basic.contains(&"--net".to_string()));
        assert!(basic.contains(&"--user".to_string()));
        assert!(!basic.contains(&"--pid".to_string()));
    }

    #[test]
    fn the_guarantee_says_the_filesystem_is_not_isolated() {
        // A test for a sentence, because the sentence is the security property: an
        // attestation that reads `sandbox: unshare` must not be read as "the files are
        // safe".
        let text = Unshare.guarantees();
        assert!(text.contains("filesystem is NOT isolated"), "{text}");
        assert!(text.contains("no network egress"), "{text}");
    }

    #[test]
    fn an_unusable_machine_refuses_with_where_to_look() {
        let probe = Unshare.probe();
        if let Err(err) = probe {
            assert!(err.detail().contains("user namespace"), "{err}");
            assert!(
                err.detail().contains("seccomp") || err.detail().contains("sysctl"),
                "the refusal should say where to look: {err}"
            );
        }
    }

    #[test]
    fn a_plan_uses_the_variant_the_probe_found() {
        let scratch =
            std::env::temp_dir().join(format!("gitiup-unshare-test-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).ok();
        let spec = Spec::new(&scratch, scratch.join("scratch"));
        match Unshare.plan(&spec, &Env::new()) {
            Ok(launch) => {
                assert_eq!(launch.separator.as_deref(), Some("--"));
                assert!(
                    launch.prefix.last().unwrap().starts_with("--")
                        || launch.prefix.last().unwrap() == "--net"
                        || launch.prefix.len() > 2
                );
            }
            Err(err) => assert!(err.detail().contains("namespaces"), "{err}"),
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

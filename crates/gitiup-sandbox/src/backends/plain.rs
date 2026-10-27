//! `plain`: run it as this user, with nothing taken away.
//!
//! This backend exists for one reason: a machine with no Landlock, no container runtime
//! and no user namespaces still has a person who wants to run their *own* build. The
//! answer to "there is no isolation available" is, by the ticket's acceptance criterion,
//! **refuse to serve jobs** — and a volunteer's own laptop is exactly where refusing
//! everything would be the wrong answer, so the way out is a door you have to open on
//! purpose and that never stops creaking:
//!
//! * it is **opt-in only**: [`admit`](crate::backend::admit) refuses it unless
//!   `GITIUP_UNSANDBOXED=1` is in the environment, so it can never be what a daemon
//!   picked by default;
//! * it **warns every single time**: the UNSANDBOXED banner is carried by the probe, so
//!   whoever prints the probe prints the warning;
//! * it **refuses quorum jobs** whatever the policy says: a stranger's job whose verdict
//!   other people rely on never runs in a cage made of a comment.
//!
//! It is still not *nothing*: `setrlimit` is applied in the child, so the process and
//! file caps hold, and a core dump cannot be written. That is a fact about this backend,
//! not a claim about its isolation — it is reported as `nothing enforced`.

use std::os::unix::process::CommandExt;
use std::process::Command;

use gitiup_attest::Result;

use crate::backend::{Env, Kind, Launch, Sandbox, UNSANDBOXED_BANNER};
use crate::egress::Egress;
use crate::linux;
use crate::probe::Probe;
use crate::spec::Enforcement;
use crate::spec::Spec;

/// The plain-process backend.
#[derive(Debug, Clone, Copy)]
pub struct Plain;

impl Sandbox for Plain {
    fn name(&self) -> &'static str {
        crate::backend::PLAIN
    }

    fn kind(&self) -> Kind {
        Kind::Plain
    }

    fn guarantees(&self) -> &'static str {
        "NOTHING: UNSANDBOXED. The job runs as this user with this user's files, network \
         and credentials; only the resource rlimits and a core-dump ban are applied. It \
         is refused for any job whose result is offered to anyone else"
    }

    fn probe(&self) -> Result<Probe> {
        let mut probe = Probe::builder(self.name());
        probe.warn(UNSANDBOXED_BANNER);
        if !crate::backend::opted_in() {
            probe.failed(
                "opt-in",
                "the plain backend confines nothing and has not been opted into \
                 (set GITIUP_UNSANDBOXED=1 only for code you wrote yourself)",
            );
            return probe.finish();
        }
        for (name, note) in [
            (
                "filesystem",
                "no filesystem restriction of any kind is applied",
            ),
            ("network", "the job has this host's network, unfiltered"),
            ("ptrace", "no seccomp filter is applied"),
            ("pid-namespace", "the job sees this machine's process table"),
            ("uid", "the job runs as this uid"),
        ] {
            probe.skipped(name, note);
        }
        probe.observed(
            "rlimits",
            "process and file caps, and no core dumps, are still applied in the child",
        );
        probe.finish()
    }

    fn enforcement(&self, _egress: &Egress) -> Enforcement {
        Enforcement::None
    }

    fn serves_quorum(&self) -> bool {
        false
    }

    fn opt_in_only(&self) -> bool {
        true
    }

    fn plan(&self, spec: &Spec, _env: &Env) -> Result<Launch> {
        let mut launch = Launch::direct();
        launch.env.extend(spec.egress.proxy_env());
        launch
            .notes
            .push("UNSANDBOXED: nothing about the job's view of this machine changes".to_string());
        launch.notes.push(format!(
            "rlimits: {:?}; scratch cap {} bytes is advice here",
            spec.limits, spec.scratch_bytes
        ));
        Ok(launch)
    }

    fn tune(&self, command: &mut Command, spec: &Spec) -> Result<()> {
        let limits = spec.limits.clone();
        let scratch_bytes = spec.scratch_bytes;
        unsafe {
            command.pre_exec(move || {
                linux::apply_limits(
                    limits.cpu_seconds,
                    limits.address_bytes,
                    limits.processes,
                    limits.file_bytes.or(Some(scratch_bytes)),
                );
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{admit, open};
    use crate::spec::Purpose;

    #[test]
    fn the_backend_that_isolates_nothing_is_the_one_that_refuses_the_most() {
        assert!(!Plain.serves_quorum());
        assert!(Plain.opt_in_only());
        assert_eq!(Plain.enforcement(&Egress::deny_all()), Enforcement::None);
        assert_eq!(
            Purpose::Quorum.minimum_enforcement(),
            Enforcement::Kernel,
            "and `none` is below it, so a quorum job cannot be admitted here"
        );
    }

    #[test]
    fn a_probe_of_the_plain_backend_carries_the_banner() {
        // Whatever the opt-in state, the banner is in the result: a warning that only
        // appears when the operator already agreed to it is not a warning.
        let probe = Plain.probe();
        match probe {
            Ok(probe) => assert!(probe.warnings.iter().any(|w| w.contains("UNSANDOXED"))),
            Err(err) => assert!(err.detail().contains("opt-in"), "{err}"),
        }
    }

    #[test]
    fn the_name_has_a_synonym_the_attestation_format_uses() {
        assert_eq!(open("shell").unwrap().name(), Plain.name());
        assert_eq!(open("plain").unwrap().name(), "plain");
    }

    #[test]
    fn admitting_a_quorum_job_here_is_refused_even_after_opting_in() {
        // The refusal is about purpose, not about the opt-in, so it must be the error
        // that wins when both apply.
        let spec = Spec::new("/tmp/work", "/tmp/scratch").quorum();
        let err = admit(&Plain, &spec).unwrap_err();
        assert!(err.detail().contains("quorum"), "{err}");
    }
}

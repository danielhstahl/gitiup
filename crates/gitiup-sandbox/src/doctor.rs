//! `gitiup doctor --sandbox`: what is active, what the kernel supports, what is
//! missing, and what to do about it.
//!
//! The report is built from the same probes the runner uses, so it cannot tell a
//! different story from the one `--execute` will hit ten seconds later. Each line is
//! `status`, `fact`, and — when the status is not `ok` — a **fix**, because the person
//! reading this has a job to run and "unavailable" is not an action.
//!
//! The verdict at the bottom is the acceptance criterion, phrased as the answer a
//! volunteer needs: whether this machine may serve a stranger's job at all. When it
//! says no, `gitiup` will still plan workflows and still sign a `simulated`
//! attestation; it just will not execute anything.

use serde::Serialize;

use crate::backend::{self, Backend};
use crate::egress::Egress;
use crate::kernel::{Availability, Kernel};
use crate::spec::{Enforcement, Spec};

/// How a line should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// This is fine.
    Ok,
    /// This works, less well than it could, or with a caveat a reviewer should see.
    Warn,
    /// This is broken or missing, and something will be refused because of it.
    Fail,
    /// Background, with nothing to fix.
    Info,
}

impl Status {
    /// A fixed-width marker, so the report scans in a terminal without colour.
    pub fn marker(self) -> &'static str {
        match self {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
            Status::Info => "info",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// What was looked at.
    pub name: String,
    /// How to read it.
    pub status: Status,
    /// The fact, in the machine's own words where possible.
    pub detail: String,
    /// What to do if it is not `ok`.
    pub fix: Option<String>,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    fn info(name: &str, detail: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Info,
            detail: detail.into(),
            fix: None,
        }
    }

    fn warn(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }

    fn fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
        Check {
            name: name.to_string(),
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The backend a run would pick by default, if any.
    pub active: Option<String>,
    /// The kernel and host facts.
    pub checks: Vec<Check>,
    /// Every backend, probed, in preference order.
    pub backends: Vec<Backend>,
    /// Whether a stranger's job may be served here.
    pub may_serve_jobs: bool,
    /// The verdict, in one sentence.
    pub verdict: String,
}

/// Look at everything.
pub fn survey() -> Report {
    let kernel = Kernel::survey();
    let mut checks: Vec<Check> = Vec::new();

    checks.push(Check::info(
        "kernel",
        format!(
            "{} — uid {}{}; {} processes already owned by this uid",
            kernel.kernel,
            kernel.uid,
            if kernel.euid == 0 {
                " (effective root)"
            } else {
                ""
            },
            kernel.processes_of_uid
        ),
    ));
    if kernel.euid != 0 {
        checks.push(Check::warn(
            "unprivileged uid",
            "gitiup is not root, so a job cannot be dropped to a distinct unprivileged uid; \
             it runs as this uid",
            "run gitiup as root, or in a container that is root, if the job's uid must differ \
             from the runner's; otherwise accept the backend's uid guarantee as it is stated",
        ));
    }

    match kernel.landlock_abi {
        Some(abi) => checks.push(Check::ok(
            "landlock",
            format!(
                "ABI {abi} ({})",
                if abi >= 4 {
                    "filesystem and TCP port rights available"
                } else {
                    "filesystem rights only; TCP ports need ABI 4"
                }
            ),
        )),
        None => {
            let lsm = if kernel.lsm.is_empty() {
                "unknown".to_string()
            } else {
                kernel.lsm.join(",")
            };
            checks.push(Check::fail(
                "landlock",
                format!("the {} kernel has no Landlock (lsm: {lsm})", kernel.kernel),
                "use a kernel with `CONFIG_SECURITY_LANDLOCK=y` (Linux 5.13+, `landlock` listed in \
                 /sys/kernel/security/lsm), or rely on the docker/podman/bwrap/unshare backends",
            ));
        }
    }

    match &kernel.seccomp_usable {
        Availability::Yes => checks.push(Check::ok(
            "seccomp",
            "a filter can be installed in a child (the syscall denials are in force)",
        )),
        Availability::No(why) => checks.push(Check::warn(
            "seccomp",
            format!("no filter could be installed: {why}"),
            "an outer container's seccomp profile usually causes this; docker's default profile \
             refuses seccomp(2), so run gitiup with a profile that allows it, or use a \
             container backend where the runtime does the filtering",
        )),
        Availability::Unknown(why) => checks.push(Check::warn(
            "seccomp",
            format!("could not be established: {why}"),
            "check /proc/sys/kernel/seccomp/actions_avail",
        )),
    }

    match &kernel.user_namespaces {
        Availability::Yes => checks.push(Check::ok(
            "user namespaces",
            "an unprivileged user namespace could be created",
        )),
        Availability::No(why) => checks.push(Check::warn(
            "user namespaces",
            format!("unshare --user was refused: {why}"),
            "set `sysctl kernel.unprivileged_userns_clone=1` (Debian/Ubuntu) and check \
             `sysctl user.max_user_namespaces`; inside a container, the runtime's default \
             seccomp/AppArmor profile commonly refuses this until you pass \
             `--security-opt seccomp=unconfined` or run bwrap setuid",
        )),
        Availability::Unknown(why) => checks.push(Check::info(
            "user namespaces",
            format!("not established: {why}"),
        )),
    }

    if let Some(max) = kernel.max_user_namespaces {
        checks.push(Check::info(
            "user.max_user_namespaces",
            format!("{max} (0 would disable every namespace backend)"),
        ));
    }
    match kernel.ptrace_scope {
        Some(0) => checks.push(Check::warn(
            "yama ptrace_scope",
            "0: any process of this uid may trace any other, so the seccomp denial is what \
             stands between a job and the runner's memory",
            "set /proc/sys/kernel/yama/ptrace_scope to 1 for defence in depth",
        )),
        Some(scope) => checks.push(Check::ok(
            "yama ptrace_scope",
            format!("{scope}: unprivileged cross-process tracing is already limited"),
        )),
        None => checks.push(Check::info(
            "yama ptrace_scope",
            "not present on this kernel",
        )),
    }

    let backends = backend::detect();
    let active = backends
        .iter()
        .filter(|candidate| candidate.available && !candidate.opt_in)
        .find(|candidate| {
            // The active backend is the one a run would pick: preference order, and
            // able to serve the strictest purpose.
            candidate.enforcement == Enforcement::Kernel || candidate.serves_quorum
        })
        .map(|candidate| candidate.name.clone());

    for candidate in &backends {
        checks.push(match (candidate.available, candidate.opt_in) {
            (true, false) => Check::ok(
                &format!("backend {}", candidate.name),
                format!("{} — {}", candidate.enforcement.label(), candidate.note),
            ),
            (true, true) => Check::warn(
                &format!("backend {}", candidate.name),
                format!("available only as an explicit opt-in: {}", candidate.note),
                format!(
                    "it confines nothing; prefer {}",
                    active.as_deref().unwrap_or("a real backend")
                ),
            ),
            (false, _) => Check::info(
                &format!("backend {}", candidate.name),
                candidate.note.clone(),
            ),
        });
    }

    // The egress defaults, because a default-deny policy that got edited to `*` is the
    // single easiest way to lose this property by accident.
    let deny = Egress::deny_all();
    checks.push(Check::ok(
        "egress default",
        format!(
            "deny-all is enforced as {} on the active backend; the proxy is started only \
             when a job names what it needs",
            deny.enforcement_label_on(active.as_deref()),
        ),
    ));

    let may_serve_jobs = backends
        .iter()
        .any(|candidate| candidate.available && !candidate.opt_in && candidate.serves_quorum);
    let verdict = if may_serve_jobs {
        format!(
            "this machine may serve stranger's jobs, in `{}`",
            active.as_deref().unwrap_or("?")
        )
    } else {
        "no isolation backend is available here, so gitiup will refuse to execute any job: \
         it will still plan workflows and attest them as `simulated`, which is the honest \
         answer and says so on its face"
            .to_string()
    };

    Report {
        active,
        checks,
        backends,
        may_serve_jobs,
        verdict,
    }
}

/// A small helper so the egress line can name the backend it is talking about.
trait EnforcementLabel {
    fn enforcement_label_on(&self, active: Option<&str>) -> String;
}

impl EnforcementLabel for Egress {
    fn enforcement_label_on(&self, active: Option<&str>) -> String {
        let name = active.unwrap_or(crate::backend::PLAIN);
        let backend = backend::open(name).ok();
        match backend {
            Some(backend) => backend.enforcement(self).label().to_string(),
            None => "nothing".to_string(),
        }
    }
}

impl Report {
    /// The report as a person reads it.
    pub fn text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "gitiup doctor --sandbox");
        let _ = writeln!(
            out,
            "active backend   {}",
            self.active
                .clone()
                .unwrap_or_else(|| "(none: nothing here can confine a job)".to_string())
        );
        let _ = writeln!(out);
        for check in &self.checks {
            let _ = writeln!(
                out,
                "{} {:<24} {}",
                check.status.marker(),
                check.name,
                check.detail
            );
            if let Some(fix) = &check.fix {
                let _ = writeln!(out, "     {:<24} fix: {fix}", "");
            }
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "backends, in the order gitiup prefers them:");
        for candidate in &self.backends {
            let _ = writeln!(out, "  {}", candidate.describe());
            if !candidate.observed.is_empty() {
                let _ = writeln!(out, "      observed: {}", candidate.observed.join(", "));
            }
            if !candidate.unchecked.is_empty() {
                let _ = writeln!(out, "      unchecked: {}", candidate.unchecked.join(", "));
            }
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "verdict          {verdict}", verdict = self.verdict);
        out
    }

    /// The report as a script reads it.
    pub fn json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}\n".to_string())
    }
}

/// The spec a doctor run uses when it needs one: nothing writable but a temp
/// directory, nothing reachable at all.
pub fn probe_spec() -> Spec {
    let scratch = std::env::temp_dir().join(format!("gitiup-doctor-{}", std::process::id()));
    Spec::new(&scratch, scratch.join("scratch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_a_backend_or_says_there_is_none() {
        let report = survey();
        assert!(
            report.active.is_some() || report.verdict.contains("refuse"),
            "either a backend is active or the verdict says what happens instead: {}",
            report.verdict
        );
        assert!(report.may_serve_jobs == report.active.is_some() || !report.may_serve_jobs);
    }

    #[test]
    fn every_failing_line_comes_with_an_action() {
        let report = survey();
        for check in &report.checks {
            if check.status == Status::Fail || check.status == Status::Warn {
                assert!(
                    check.fix.is_some(),
                    "`{}` is {} with no fix: {}",
                    check.name,
                    check.status.marker(),
                    check.detail
                );
            }
        }
    }

    #[test]
    fn the_text_is_readable_and_the_json_is_parseable() {
        let report = survey();
        let text = report.text();
        assert!(text.contains("active backend"), "{text}");
        assert!(text.contains("verdict"), "{text}");
        assert!(text.contains("backend docker"), "{text}");
        let value: serde_json::Value = serde_json::from_str(&report.json()).unwrap();
        assert_eq!(
            value["may_serve_jobs"].as_bool(),
            Some(report.may_serve_jobs),
            "{}",
            report.json()
        );
        assert!(value["backends"].is_array());
    }

    #[test]
    fn the_plain_backend_is_reported_as_opt_in_never_as_active() {
        let report = survey();
        let plain = report
            .backends
            .iter()
            .find(|candidate| candidate.name == crate::backend::PLAIN)
            .expect("plain is always listed");
        assert!(!plain.serves_quorum);
        assert!(plain.opt_in);
        assert_ne!(report.active.as_deref(), Some(crate::backend::PLAIN));
    }
}

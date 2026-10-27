//! `gitiup-sandbox` — the security floor: what confines a stranger's code, and how we
//! know.
//!
//! A volunteer who runs `gitiup verify serve` (giti-msi.5) is agreeing to execute a
//! workflow written by someone who has never met them, over a network, on a machine
//! that has their SSH keys and their mail on it. Everything in this crate exists to
//! answer one question honestly: **what stopped it?**
//!
//! The prose version of this document is
//! [docs/sandbox.md](../../../docs/sandbox.md); the API tour is the
//! [crate README](../README.md).
//!
//! ```text
//!                     Spec{workspace, scratch, egress, limits, purpose}
//!                                        │
//!   open("docker") ──► Sandbox ──probe()─►│ Probe{ what was watched being denied }
//!                                        │
//!                            plan() ──► Launch ──► Command ──► spawn
//!                                        │
//!   admit(backend, spec) ◄───────────────┘  the gate: refuse before anything runs
//! ```
//!
//! # The ladder, and what each rung actually denies
//!
//! | backend | what does the work | filesystem | egress, default-deny | egress, allowlist | needs |
//!|---------|--------------------|------------|----------------------|-------------------|-------|
//!| `docker`, `podman` | a container runtime | its own; workspace bind-mounted read-only | `--network=none`: **kernel** | proxy, **audited** | runtime + local image |
//!| `bwrap` | mount/pid/net namespaces | rebuilt; workspace read-only | no route: **kernel** | proxy, **audited** | `bubblewrap` package |
//!| `landlock` | Landlock + seccomp in the child | writes refused outside the scratch | no TCP rights: **kernel** (ABI 4+) | only the proxy's port: **kernel** (ABI 4+) | Linux ≥ 5.13 with Landlock |
//!| `unshare` | user + net namespaces | *not isolated* | no route: **kernel** | no effect: deny-all only | `unshare(1)`, userns allowed |
//!| `plain` | nothing | not isolated | **nothing** | **nothing** | opt-in, and refuses quorum jobs |
//!
//! The order is the preference order ([`backend::backends`]), and the last rung is the
//! one the ticket insists exists: a plain process is better than nothing *for your own
//! build* and is never acceptable for someone else's, so it is opt-in only, it prints
//! [`UNSANDBOXED_BANNER`](backend::UNSANDBOXED_BANNER) with every probe, and
//! [`backend::admit`] refuses it for a [`Quorum`](spec::Purpose::Quorum) job.
//!
//! # The two rules the code is built around
//!
//! 1. **A confinement claim is observed, not assumed.** [`Sandbox::probe`] asks the
//!    kernel — by trying — and records which properties it saw. [`escape`] runs four
//!    checks (write outside the sandbox, connect out, `ptrace` the runner, exceed the
//!    process cap) and decides each by what the *host* observed, so a canary cannot
//!    report a success it did not have. A probe whose check failed is a refusal, and a
//!    check that could not run says so in `gitiup doctor` rather than going quiet.
//! 2. **When nothing isolates, nothing runs.** [`backend::best`] returning `None`, or
//!    [`admit`] returning `Policy`, is the answer a daemon must act on. The
//!    corresponding user-facing behaviour is in `gitiup run`: no sandbox means it
//!    simulates and says `tier: simulated`, which is a plan and not a claim.
//!
//! # Egress
//!
//! Default-deny means *no route, no rights*: not "a proxy you may ignore". When a job
//! names what it needs, it gets a [`Proxy`](egress::Proxy) that only speaks for hosts on
//! an [`egress::Allowlist`] (package registries and the repository store, by
//! default) and writes an [`audit`](egress::Decision) of every decision, plus a
//! per-job [`Resolver`](dns::Resolver) that answers `NXDOMAIN` for anything not
//! allowlisted — so a job's failure looks like "that host does not exist", which is
//! true from inside its cage. Whether the job *had* to use the proxy is the difference
//! [`spec::Enforcement`] records: a quorum job requires the kernel to have
//! refused, not the proxy to have asked.
//!
//! # What is deliberately not here
//!
//! * **no resource policy** — admission control, budgets and cache eviction are
//!   giti-bgy.2; this crate only applies the limits a [`spec::Spec`] names.
//! * **no secrets** — the runner passes secret *names* and never values (giti-bgy.3),
//!   which matters most on the in-process backends, where reads are not isolated.
//! * **no pinning** — a floating image tag or action ref is giti-bgy.4's refusal.
//! * **no serving** — the daemon that calls [`backend::admit`] is giti-msi.5.
//!
//! ```
//! use gitiup_sandbox::{backend, egress, spec};
//!
//! // The vocabulary is public and stable, because the names end up in signed digests.
//! assert_eq!(
//!     backend::implemented(),
//!     vec!["docker", "podman", "bwrap", "landlock", "unshare", "plain"]
//! );
//!
//! // Asking for "no sandbox" is a refusal with an alternative, not a silent downgrade.
//! let err = backend::open("none").unwrap_err();
//! assert!(err.detail().contains("unconfined"), "{err}");
//!
//! // A spec is a value: making one touches nothing.
//! let spec = spec::Spec::new("/work", "/work/.scratch");
//! assert!(spec.egress.is_denied(), "default-deny is the default");
//!
//! // The backend that isolates nothing is the one that refuses the most.
//! let plain = backend::open("plain").unwrap();
//! assert!(!plain.serves_quorum(), "a stranger's job never runs unconfined");
//! assert!(plain.opt_in_only());
//!
//! // An allowlist that tries to allow everything is refused rather than honoured.
//! assert!(egress::Allowlist::empty().push("*").is_err());
//! ```

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

pub mod backend;
pub mod backends;
pub mod canary;
pub mod dns;
pub mod doctor;
pub mod egress;
pub mod escape;
pub mod kernel;
pub mod linux;
pub mod policy;
pub mod probe;
pub mod spec;

/// The types a caller normally needs, in one import.
pub mod prelude {
    pub use crate::backend::{self, Admitted, Backend, Launch, Sandbox};
    pub use crate::egress::{Allowlist, Egress};
    pub use crate::probe::{Observed, Probe};
    pub use crate::spec::{Enforcement, Limits, Purpose, Spec};
}

pub use backend::{Backend, Kind, Sandbox, admit, best, command, detect, implemented, open};
pub use doctor::{Check, Report, Status};
pub use egress::{Allowlist, Decision, Egress};
pub use escape::Outcome;
pub use kernel::Kernel;
pub use probe::{Observed, Probe};
pub use spec::{Enforcement, Limits, Purpose, Spec};

/// The version of the sandbox policy vocabulary.
///
/// Recorded beside an attestation so a verifier can tell which set of guarantees the
/// word `landlock` referred to when the run happened. Bumped when a backend's
/// [`guarantees`](backend::Sandbox::guarantees) sentence or the enforcement matrix
/// changes — not when the code underneath it does, because what a reviewer is relying
/// on is the sentence.
pub const POLICY_VERSION: u32 = 1;

/// Scratch log for the child-side hook, which runs between `fork` and `execve` where
/// nothing may allocate and stderr may already be a pipe nobody reads. Only the escape
/// harness and the `--sandbox` probes ever reach it. The *caller* decides whether to
/// write: a confined child's environment is rebuilt from nothing, so the hook cannot
/// look up `GITIUP_SANDBOX_DEBUG` itself and find it missing.
#[doc(hidden)]
pub fn debug_hook(line: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("gitiup-sandbox-hook.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

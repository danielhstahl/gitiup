//! The sandbox seam: what confined a `local` attestation, in the attestation's own words.
//!
//! A run report says `tier: local, sandbox: <name>`. That name is a claim, and the
//! claim is only worth what the machine's reality behind it is: a report that said
//! `sandbox: docker` on a host with no docker, or that said `sandbox: unshare` after
//! running the step unconfined because the namespace was refused, would be a
//! self-consistent forgery — nothing downstream could tell it from a real one. So the
//! rules here are, in order:
//!
//! 1. a step runs only under a backend that was **probed on this machine**, in this
//!    process, a moment before the step;
//! 2. a probe that fails is a **refusal** (`exit 6`), not a warning, and nothing is
//!    spawned on the way to saying so;
//! 3. the name that lands in the signed bytes is the name of the backend that was
//!    probed, and [`Sandbox::guarantees`] — one sentence about what it actually
//!    denies — travels beside it.
//!
//! The ladder itself lives in [`gitiup_sandbox`]: container runtimes, then bubblewrap,
//! then Landlock plus seccomp in the child, then `unshare(1)`, then — opt-in, loudly —
//! nothing at all. Each rung is probed rather than assumed, and when none holds,
//! `gitiup` plans and simulates and does not execute. What lives *here* is the seam:
//! a name typed on a command line becomes a [`Command`] a step runs as, and a probe
//! failure becomes the refusal vocabulary the rest of gitiup uses.
//!
//! ```
//! use gitiup_run::sandbox;
//!
//! // Which rungs exist in this build, and whether this machine allows each one.
//! let _ = sandbox::detect();
//! // An unconfined run may not attest as `local`.
//! assert!(sandbox::open("none").is_err());
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use gitiup_attest::{Error, ErrorKind, NO_SANDBOX_ALIASES, Result};
use gitiup_sandbox::backend::{self, Sandbox as Ladder};
use gitiup_sandbox::spec::{Limits, Spec as SandboxSpec};

/// A sandbox backend the runner can put a step inside.
///
/// Deliberately small: the *decision* about isolation belongs to
/// [`gitiup_sandbox`], and this trait only asks the two questions a
/// step needs answered — may anything run here, and what does the resulting command
/// look like.
pub trait Sandbox: std::fmt::Debug {
    /// The name recorded in `provenance.sandbox`. One word, lowercase, stable: it
    /// ends up inside signed digests.
    fn name(&self) -> &'static str;

    /// What it actually denies, in the sentence a reviewer needs. Never "sandboxed".
    fn guarantees(&self) -> &'static str;

    /// Ask the machine whether this works *right now* — permission denied, no binary,
    /// disabled namespaces, seccomp in a container.
    fn probe(&self) -> Result<()>;

    /// The command a step runs as: `argv`, an environment built from nothing, and the
    /// backend's own confinement applied — argv prefix for a container or namespace,
    /// a hook in the child for Landlock.
    ///
    /// `scratch` is the directory the runner staged the step in (its script, its
    /// output files). It is part of the confinement, not an afterthought: a backend
    /// that grants only the checkout produces a step that cannot read its own script,
    /// which looks like a broken shell rather than a sandbox doing its job.
    ///
    /// The environment is cleared and rebuilt by the backend, always: a step that
    /// inherits the runner's environment inherits its tokens, and then the report
    /// describes a run nobody else could repeat.
    fn command(
        &self,
        argv: &[String],
        environment: &BTreeMap<String, String>,
        workspace: &Path,
        scratch: &Path,
    ) -> Result<Command>;
}

/// The spec a workflow step runs under.
///
/// **Two trees are writable: the checkout and the runner's scratch.** The checkout,
/// because a build writes where it is checked out and a runner that made it read-only
/// would be refused by every real workflow; the scratch, because that is where the
/// step's own script and output files were staged — a step that cannot read its own
/// script fails in a way that looks like a broken shell instead of a sandbox.
///
/// The promise the sandbox still makes, and the one the escape suite checks, is about
/// everything outside those two: no writes elsewhere, no egress, bounded processes, no
/// `ptrace` of the runner.
///
/// Egress is deny-all, which is what `unshare --net` gave before this ladder existed
/// and what every backend here can enforce in the kernel. A step that needs the
/// network will need an explicit allowlist (`--egress`, a later ticket) rather than a
/// relaxed default: a default that allows is a default nobody reviews.
pub fn spec_for(workspace: &Path, scratch: &Path) -> SandboxSpec {
    SandboxSpec::new(workspace, scratch)
        .with_writable(workspace)
        .with_limits(Limits::default())
}

/// One rung of the ladder, seen from the runner.
#[derive(Debug)]
struct Rung {
    inner: Box<dyn Ladder>,
}

impl Sandbox for Rung {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn guarantees(&self) -> &'static str {
        self.inner.guarantees()
    }

    fn probe(&self) -> Result<()> {
        // The library's own refusal, kept verbatim: it already names the failed
        // property and says what to install or set, and it is the same refusal
        // `gitiup doctor --sandbox` will print.
        self.inner.probe().map(|_| ())
    }

    fn command(
        &self,
        argv: &[String],
        environment: &BTreeMap<String, String>,
        workspace: &Path,
        scratch: &Path,
    ) -> Result<Command> {
        let spec = spec_for(workspace, scratch);
        let launch = self.inner.plan(&spec, &backend::Env::new())?;
        backend::command(
            self.inner.as_ref(),
            &spec,
            &launch,
            argv,
            environment,
            workspace,
        )
    }
}

/// Open a backend by name.
///
/// Unknown names and names this machine cannot do are both refusals with the ladder
/// quoted: the commonest mistake is typing `docker` because that is what CI uses, and
/// the answer has to say what to type instead rather than exit(1) silently.
pub fn open(name: &str) -> Result<Box<dyn Sandbox>> {
    let trimmed = name.trim().to_ascii_lowercase();
    if NO_SANDBOX_ALIASES.contains(&trimmed.as_str()) {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            "`--sandbox none` asks for an unconfined execution",
        )
        .with_hint(
            "an unconfined run may not attest as `local`: pick a backend \
             (see gitiup run --sandboxes), or drop --execute and get a simulated \
             attestation instead",
        ));
    }
    let inner = backend::open(&trimmed)?;
    Ok(Box::new(Rung { inner }))
}

/// The names this build offers, in preference order.
pub fn implemented() -> Vec<String> {
    backend::backends()
        .iter()
        .map(|backend| backend.name().to_string())
        .collect()
}

/// Every backend, with whether this machine allows it right now.
///
/// Reported by `gitiup run --sandboxes` and quoted in every refusal, because "no
/// sandbox" is a fact about *this* host, not a permanent property of the tool.
pub fn detect() -> Vec<Backend> {
    backend::backends()
        .iter()
        .map(|backend| Backend::of(backend.as_ref()))
        .collect()
}

/// The backend a run would get if nobody named one, if any.
///
/// This is the whole serving decision: `None` means this machine may not execute
/// anything, and the caller must refuse rather than run.
pub fn best() -> Option<Box<dyn Sandbox>> {
    backend::best().map(|inner| Box::new(Rung { inner }) as Box<dyn Sandbox>)
}

/// Refuse, in the runner's vocabulary, when nothing here can confine a step.
///
/// Called before a plan is executed for real, so the message is the one a volunteer
/// reads instead of a step that half-ran.
pub fn require_one() -> Result<Box<dyn Sandbox>> {
    best().ok_or_else(|| {
        Error::new(
            ErrorKind::Policy,
            "sandbox",
            "no sandbox on this machine holds, so nothing will be executed",
        )
        .with_hint(
            "run `gitiup doctor --sandbox` to see which rung failed and what to install \
             or set; until then `gitiup run` plans and attests as `simulated`, which is \
             the safe default",
        )
    })
}

/// One backend's status on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// Backend name.
    pub name: String,
    /// Whether a run would be confined here.
    pub available: bool,
    /// Why not, or what it guarantees. Printed verbatim.
    pub note: String,
    /// What the probe managed to check just now, empty when the backend is not
    /// available at all. A backend that guarantees a lot and checked nothing is a
    /// different sentence from one that checked everything, and the reader should be
    /// able to tell them apart.
    pub observed: String,
}

impl Backend {
    fn of(sandbox: &dyn Ladder) -> Backend {
        // One probe per backend: `detect` runs on `--sandboxes`, and a probe is a
        // process spawn.
        match sandbox.probe() {
            Ok(probe) => Backend {
                name: sandbox.name().to_string(),
                available: true,
                note: sandbox.guarantees().to_string(),
                // The probe's own summary goes with it: `guarantees` is the promise,
                // the summary is what this machine let us check just now.
                observed: probe.summary(),
            },
            Err(why) => Backend {
                name: sandbox.name().to_string(),
                available: false,
                note: why.detail().to_string(),
                observed: String::new(),
            },
        }
    }

    /// `landlock: available — no network egress …` for one-line printing.
    pub fn describe(&self) -> String {
        format!("{}: {} — {}", self.name, self.status(), self.note)
    }

    /// `available` / `unavailable`.
    pub fn status(&self) -> &'static str {
        if self.available {
            "available"
        } else {
            "unavailable"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    #[test]
    fn an_unconfined_run_is_refused_before_anything_else() {
        // The list is the format crate's, because that is the list a verifier reads a
        // report against: `--sandbox off` and `sandbox: "off"` have to mean the same
        // refusal here and there, or a producer can write one and pass the other.
        for name in gitiup_attest::NO_SANDBOX_ALIASES {
            let err = open(name).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Policy, "{name:?}");
            assert!(err.detail().contains("unconfined"), "{err}");
        }
    }

    #[test]
    fn an_unknown_backend_is_refused_with_the_ladder() {
        let err = open("kvm").unwrap_err();
        assert!(err.detail().contains("kvm"), "{err}");
        assert!(err.hint().unwrap().contains("landlock"), "{err}");
    }

    #[test]
    fn names_are_typable() {
        assert_eq!(open(" LANDLOCK ").unwrap().name(), "landlock");
    }

    #[test]
    fn every_offered_backend_says_something_about_itself() {
        for backend in detect() {
            assert!(!backend.note.is_empty(), "{backend:?}");
            // An unavailable backend has to explain itself: "unavailable" alone is the
            // answer that sends someone to read source code.
            if !backend.available {
                assert!(
                    backend.note.len() > 20,
                    "{backend:?} refuses without a reason"
                );
            }
        }
    }

    #[test]
    fn the_step_spec_writes_in_the_checkout_and_nowhere_else() {
        let spec = spec_for(Path::new("/work"), Path::new("/tmp/gitiup-run-1"));
        let writes = spec.write_paths();
        assert!(writes.contains(&PathBuf::from("/work")), "{writes:?}");
        assert!(
            writes.contains(&PathBuf::from("/tmp/gitiup-run-1")),
            "a step must be able to read the script it was staged with: {writes:?}"
        );
        assert!(
            !writes.contains(&PathBuf::from("/")),
            "the whole filesystem is never the writable set: {writes:?}"
        );
        assert!(
            spec.egress.is_denied(),
            "a step gets no network until someone asks for it"
        );
    }
}

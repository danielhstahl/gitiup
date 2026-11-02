//! The probe: what a backend watched this kernel say.
//!
//! This module exists because "sandbox: available" is not a claim worth much. Every
//! backend's [`probe`](crate::backend::Sandbox::probe) answers two different
//! questions, and a reviewer is entitled to tell them apart:
//!
//! * **is it usable here** — the binary exists, the daemon answers, the syscall is not
//!   refused, the feature is not disabled by sysctl or by an outer container profile;
//! * **what was actually seen being denied** — a write to a path outside the sandbox
//!   that failed, a `ptrace` that came back `EPERM`, a connect that never arrived, a
//!   fork that hit the cap.
//!
//! A property is therefore one of three things: [`Observed::Yes`] (watched it hold),
//! [`Observed::No`] (watched it fail — the probe refuses the backend), and
//! [`Observed::Skipped`] (could not check it, and why). `Skipped` never turns into a
//! refusal, because a backend that cannot check every property on a minimal container
//! image would refuse to run on a minimal container image — but it does turn into a
//! line in `gitiup doctor`, because an unverified property is exactly what a reviewer
//! should ask about.
//!
//! A refusal may carry a **fix**: the command or setting that would make the property
//! hold. "Not usable" is not an action, and a refusal that names one (`docker pull
//! alpine:3.20`) is the difference between a bug report and a two-second fix. Fixes
//! travel with the refusal — into the error hint, and into `gitiup doctor`'s `fix:`
//! line — because the probe is the only place that knows which of the two the machine
//! is short of.

use serde::Serialize;

/// Whether a property was checked, and what the check said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Observed {
    /// The check ran and the denial happened.
    Yes,
    /// The check ran and the denial did **not** happen. A probe never returns `Ok`
    /// with one of these.
    No,
    /// The check could not run here, with the reason in the note.
    Skipped,
}

/// One property of the isolation, and how it was established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Property {
    /// Short, stable, lowercase: `fs-write-outside`, `tcp-egress`, `ptrace`.
    pub name: String,
    /// Whether it was checked and what the check said.
    pub observed: Observed,
    /// One line: what was tried, or why it was not tried. Printed verbatim.
    pub note: String,
}

impl Property {
    /// `yes` / `no` / `skipped`, for a status line.
    pub fn state(&self) -> &'static str {
        match self.observed {
            Observed::Yes => "yes",
            Observed::No => "no",
            Observed::Skipped => "skipped",
        }
    }
}

/// The result of one backend's probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    /// Which backend produced it.
    pub backend: String,
    /// The properties, in the order they were checked.
    pub properties: Vec<Property>,
    /// Loud messages that belong with the result — the UNSANDBOXED banner lives here,
    /// so anything that prints a probe prints the warning too.
    pub warnings: Vec<String>,
    /// What to change to make this backend usable, one imperative sentence each.
    ///
    /// Usually empty: a backend that probes clean needed nothing. It is filled by the
    /// checks that refused — or would refuse — and it is what turns `unavailable` into
    /// an instruction.
    pub fixes: Vec<String>,
}

impl Probe {
    /// Start building a probe for `backend`.
    pub fn builder(backend: impl Into<String>) -> ProbeBuilder {
        ProbeBuilder {
            backend: backend.into(),
            properties: Vec::new(),
            warnings: Vec::new(),
            fixes: Vec::new(),
        }
    }

    /// The properties that were actually watched, by name.
    pub fn observed(&self) -> Vec<&str> {
        self.properties
            .iter()
            .filter(|property| property.observed == Observed::Yes)
            .map(|property| property.name.as_str())
            .collect()
    }

    /// What to change about this machine, if anything.
    pub fn fixes(&self) -> &[String] {
        &self.fixes
    }

    /// The properties nobody could check — the honest part of the report.
    pub fn unverified(&self) -> Vec<&str> {
        self.properties
            .iter()
            .filter(|property| property.observed == Observed::Skipped)
            .map(|property| property.name.as_str())
            .collect()
    }

    /// The one-line summary `--sandboxes` prints.
    pub fn summary(&self) -> String {
        let observed = self.observed();
        let unverified = self.unverified();
        if observed.is_empty() {
            return format!("nothing observed ({} unchecked)", unverified.len());
        }
        format!(
            "observed: {}{}",
            observed.join(", "),
            if unverified.is_empty() {
                String::new()
            } else {
                format!(" · unchecked: {}", unverified.join(", "))
            }
        )
    }
}

/// The hint a refusal carries when the probe could not name an action.
///
/// Named so `Backend::of` can tell "the probe said what to do" from "the probe said to
/// ask doctor", and only put a `fix:` in front of a human where one exists.
pub(crate) const GENERIC_FIX: &str = "until a sandbox holds up, gitiup run will only \
                                      simulate — which is the safe default, and gitiup \
                                      doctor --sandbox says what to change about this \
                                      machine";

/// Builds a probe, then refuses if a check said no.
#[derive(Debug)]
pub struct ProbeBuilder {
    backend: String,
    properties: Vec<Property>,
    warnings: Vec<String>,
    fixes: Vec<String>,
}

impl ProbeBuilder {
    /// A property that held.
    pub fn observed(&mut self, name: &str, note: impl Into<String>) {
        self.push(name, Observed::Yes, note);
    }

    /// A property that did **not** hold. `finish` refuses.
    pub fn failed(&mut self, name: &str, note: impl Into<String>) {
        self.push(name, Observed::No, note);
    }

    /// A property that could not be checked here.
    pub fn skipped(&mut self, name: &str, note: impl Into<String>) {
        self.push(name, Observed::Skipped, note);
    }

    /// A warning to carry with the result.
    pub fn warn(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// What the operator should do to make this backend usable: an imperative,
    /// normally a command to type. Recorded whether or not the probe goes on to
    /// refuse, because the reason a backend is not usable is exactly the reason a
    /// person needs.
    pub fn fix(&mut self, fix: impl Into<String>) {
        let fix = fix.into();
        if !fix.trim().is_empty() && !self.fixes.contains(&fix) {
            self.fixes.push(fix);
        }
    }

    fn push(&mut self, name: &str, observed: Observed, note: impl Into<String>) {
        self.properties.push(Property {
            name: name.to_string(),
            observed,
            note: note.into(),
        });
    }

    /// Finish, refusing if a property failed — which is the entire point: a backend
    /// whose own check did not hold is not offered as a sandbox.
    pub fn finish(&self) -> gitiup_attest::Result<Probe> {
        let failed: Vec<&Property> = self
            .properties
            .iter()
            .filter(|property| property.observed == Observed::No)
            .collect();
        if !failed.is_empty() {
            let names: Vec<&str> = failed
                .iter()
                .map(|property| property.name.as_str())
                .collect();
            let notes: Vec<&str> = failed
                .iter()
                .map(|property| property.note.as_str())
                .collect();
            let hint = if self.fixes.is_empty() {
                GENERIC_FIX.to_string()
            } else {
                // Joined verbatim: `Backend::of` shows this string as doctor's `fix:`,
                // so it has to read as an instruction in that mouth too, not as a
                // sentence about the command being run from somewhere else.
                self.fixes.join(" · ")
            };
            return Err(gitiup_attest::Error::new(
                gitiup_attest::ErrorKind::Policy,
                "sandbox",
                format!(
                    "the `{}` sandbox is not usable here: {} failed — {}",
                    self.backend,
                    names.join(", "),
                    notes.join("; ")
                ),
            )
            .with_hint(hint));
        }
        Ok(Probe {
            backend: self.backend.clone(),
            properties: self.properties.clone(),
            warnings: self.warnings.clone(),
            fixes: self.fixes.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_that_failed_refuses_the_backend_and_says_which_check() {
        let mut builder = Probe::builder("landlock");
        builder.observed("fs-write-outside", "the write failed with EACCES");
        builder.failed("tcp-egress", "a connection arrived at the witness port");
        let err = builder.finish().unwrap_err();
        assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
        assert!(err.detail().contains("tcp-egress"), "{err}");
        assert!(
            !err.detail().contains("fs-write-outside"),
            "a property that held must not be in the complaint: {err}"
        );
        assert!(err.hint().unwrap().contains("doctor"), "{err}");
    }

    #[test]
    fn a_check_that_could_not_run_is_said_not_hidden() {
        let mut builder = Probe::builder("docker");
        builder.observed("network", "--network=none");
        builder.skipped("ptrace", "the image has no canary to try it with");
        let probe = builder.finish().unwrap();
        assert_eq!(probe.observed(), vec!["network"]);
        assert_eq!(probe.unverified(), vec!["ptrace"]);
        assert!(
            probe.summary().contains("unchecked: ptrace"),
            "{}",
            probe.summary()
        );
    }

    #[test]
    fn a_probe_with_nothing_observed_says_so() {
        let mut builder = Probe::builder("plain");
        builder.skipped("anything", "the plain backend enforces nothing");
        let probe = builder.finish().unwrap();
        assert!(
            probe.summary().starts_with("nothing observed"),
            "{}",
            probe.summary()
        );
    }

    /// The whole point of a `fix`: a refusal has to be actionable on its own, in
    /// whatever command printed it.
    #[test]
    fn a_refusal_that_could_name_the_command_does() {
        let mut builder = Probe::builder("docker");
        builder.fix("put the image where the runtime can see it first: `docker pull alpine:3.20`");
        builder.failed("image", "`alpine:3.20` is not present locally");
        let err = builder.finish().unwrap_err();
        let hint = err.hint().unwrap();
        assert!(hint.contains("docker pull alpine:3.20"), "{hint}");
        assert_eq!(
            crate::backend::fix_of(&err),
            Some(hint),
            "the action survives into doctor's `fix:` line"
        );
    }

    /// …and a refusal that could not name one must not fake one: doctor keeps those
    /// lines plain, because "install the runtime" is already in the note.
    #[test]
    fn a_refusal_with_no_action_says_so_rather_than_inventing_one() {
        let mut builder = Probe::builder("bwrap");
        builder.failed("bubblewrap", "no `bwrap` binary on PATH");
        let err = builder.finish().unwrap_err();
        assert!(err.hint().unwrap().contains("doctor"), "{err}");
        assert_eq!(crate::backend::fix_of(&err), None);
    }
}

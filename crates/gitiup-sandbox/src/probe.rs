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
}

impl Probe {
    /// Start building a probe for `backend`.
    pub fn builder(backend: impl Into<String>) -> ProbeBuilder {
        ProbeBuilder {
            backend: backend.into(),
            properties: Vec::new(),
            warnings: Vec::new(),
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

/// Builds a probe, then refuses if a check said no.
#[derive(Debug)]
pub struct ProbeBuilder {
    backend: String,
    properties: Vec<Property>,
    warnings: Vec<String>,
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
            .with_hint(
                "until a sandbox holds up, gitiup run will only simulate — which is the safe \
                 default, and gitiup doctor --sandbox says what to change about this machine",
            ));
        }
        Ok(Probe {
            backend: self.backend.clone(),
            properties: self.properties.clone(),
            warnings: self.warnings.clone(),
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
}

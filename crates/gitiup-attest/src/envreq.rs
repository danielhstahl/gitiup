//! The environment fingerprint, and what it takes to *match* one (giti-1rs.4).
//!
//! Every manifest carries an `environment` — OS and version, architecture, the
//! container image it ran in (digest-pinned, or nothing at all, in which case the
//! local toolchain inventory is what describes the machine), plus the runner
//! version and the sandbox backend beside it — and `environment.fingerprint` is the
//! digest over all of that ([`Environment::compute_fingerprint`]). The digest is the
//! *identity* of a machine class; this module is the other half of the ticket:
//! deciding whether a given machine class is the one a change asked for.
//!
//! # Why a knob, and why three settings
//!
//! Without enforcement an environment difference arrives as a mystery: two
//! reviewers compute two digests and both blame the format. So a repo publishes an
//! [`EnvironmentRequirement`] next to the change it gates — "this needs `amd64`,
//! `rustc 1.99`, image `sha256:…`" — and verification compares it against the
//! attestation. The comparison is deliberately a *spectrum*, because the honest
//! answer to "must the environment match?" is "down to the level I actually
//! promised":
//!
//! | [`EnvMatch`] | rule | use it when |
//!|--------------|------|-------------|
//!| `strict` | every required field must be exactly as required | bit-for-bit reproducibility is the claim (a pinned toolchain, a pinned image) |
//!| `major` | version-bearing fields must agree as far as the requirement states them | "same major version as the change was verified on" is the promise, and a patch release of `rustc` is not a new machine |
//!| `off` | nothing is compared | the environment is recorded for debugging and gated by nothing |
//!
//! `major` needs one sentence of precision: it compares a version **as far as the
//! requirement states it**. A requirement of `rustc = 1` accepts `1.100.2`;
//! `rustc = 1.99` accepts `1.99.4`; `rustc = 1.99.1` is an exact pin and accepts
//! nothing else. That is what makes the setting readable in a policy file — the
//! coarseness lives in the requirement, and `major` means "do not punish a run for
//! knowing more than you promised".
//!
//! Fields that carry no version — architecture, image digest, image reference,
//! provider, fingerprint — are compared exactly under both settings. There is no
//! "major version" of a hash, and guessing which characters of `ubuntu:24.04` count
//! as a version is how a policy starts accepting `alpine:24.04`.
//!
//! # The failure is the feature
//!
//! A refusal here is [`ErrorKind::Policy`] (exit 6: "we refuse this", not "these
//! bytes are corrupt") and names both sides:
//!
//! ```
//! use gitiup_attest::{EnvMatch, EnvironmentRequirement, sample};
//!
//! let mut environment = sample::local().result.environment;
//! environment.arch = "aarch64".into();
//! environment.fix_fingerprint().unwrap();
//! let requirement = EnvironmentRequirement::parse("arch=amd64").unwrap();
//! let err = requirement
//!     .check(&environment, &sample::local().result.provenance, EnvMatch::Strict)
//!     .unwrap_err();
//! assert_eq!(err.exit_code(), 6);
//! assert!(err.detail().contains("aarch64") && err.detail().contains("amd64"));
//! # Ok::<(), gitiup_attest::Error>(())
//! ```
//!
//! which is a different sentence from the one a mismatched digest prints, and that
//! difference is the ticket: a reviewer should not have to diff two fingerprints to
//! learn that someone re-ran an arm64 job on an amd64 change.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::error::{Error, ErrorKind, Result};
use crate::manifest::{Environment, Provenance};

/// How strictly an [`EnvironmentRequirement`] is enforced at verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvMatch {
    /// Every required field must be exactly as required. The default: a published
    /// requirement is a promise, and the conservative reading of a promise is the
    /// whole of it.
    Strict,
    /// Version-bearing fields must agree as far as the requirement states them;
    /// everything else must still match exactly.
    Major,
    /// Do not compare anything. The fingerprint is still recorded, derived and
    /// validated — this turns off the *gate*, not the *evidence*.
    Off,
}

impl EnvMatch {
    /// Every setting, most demanding first.
    pub const ALL: [EnvMatch; 3] = [EnvMatch::Strict, EnvMatch::Major, EnvMatch::Off];

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            EnvMatch::Strict => "strict",
            EnvMatch::Major => "major",
            EnvMatch::Off => "off",
        }
    }

    /// Parse a setting, tolerating case and whitespace because these come from
    /// hand-written policy files and command lines.
    ///
    /// The error lists the vocabulary: a typo in a gate must not read as "the gate
    /// is looser than you wrote".
    pub fn parse(text: &str) -> Result<EnvMatch> {
        let trimmed = text.trim().to_ascii_lowercase();
        EnvMatch::ALL
            .iter()
            .find(|mode| mode.as_str() == trimmed)
            .copied()
            .ok_or_else(|| {
                Error::invalid(
                    "policy",
                    format!("require-env-match '{text}' is not a known setting"),
                )
                .with_hint(format!(
                    "require-env-match is {}",
                    EnvMatch::ALL
                        .iter()
                        .map(|m| m.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// Is anything compared at all?
    pub fn is_enforced(self) -> bool {
        self != EnvMatch::Off
    }
}

impl fmt::Display for EnvMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EnvMatch {
    type Err = Error;

    fn from_str(text: &str) -> Result<EnvMatch> {
        EnvMatch::parse(text)
    }
}

/// A CPU architecture name, with the aliases the ecosystems use folded onto the
/// name the manifest stores.
///
/// Rust says `x86_64`, Debian and Docker say `amd64`, Apple and Debian say
/// `aarch64`/`arm64 — and a policy that compared those strings byte-for-byte would
/// refuse a perfectly good amd64 attestation because a human wrote the Debian
/// spelling. Canonicalising is the one place that ambiguity gets resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arch(String);

/// Architecture aliases: every spelling here canonicalises to the name a manifest
/// carries, which is the spelling `std::env::consts::ARCH` produces.
pub const ARCH_ALIASES: [(&str, &str); 10] = [
    ("x86_64", "x86_64"),
    ("amd64", "x86_64"),
    ("x64", "x86_64"),
    ("i686", "x86"),
    ("i386", "x86"),
    ("x86", "x86"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
    ("armv7l", "arm"),
    ("arm", "arm"),
];

impl Arch {
    /// Canonicalise a spelling (`AMD64`, `" arm64 "`, `x86_64` all survive).
    ///
    /// An unrecognised spelling is kept as written, lower-cased: architectures are
    /// not a closed vocabulary (riscv64, powerpc, s390x all exist in the wild), and
    /// refusing one would stop a policy from ever naming it.
    pub fn new(text: &str) -> Arch {
        let lowered = text.trim().to_ascii_lowercase();
        Arch(
            ARCH_ALIASES
                .iter()
                .find(|(alias, _)| *alias == lowered)
                .map(|(_, canonical)| (*canonical).to_string())
                .unwrap_or(lowered),
        )
    }

    /// The canonical name.
    pub fn canonical(&self) -> &str {
        &self.0
    }

    /// Do two spellings name the same architecture?
    pub fn matches(&self, other: &str) -> bool {
        self.0 == Arch::new(other).0
    }

    /// The alias note a refusal adds when the requirement spelled it differently.
    fn note(&self, written: &str) -> String {
        if self.canonical() == written.trim().to_ascii_lowercase() {
            String::new()
        } else {
            format!(" (canonical {self})")
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Arch {
    type Err = Error;

    fn from_str(text: &str) -> Result<Arch> {
        if text.trim().is_empty() {
            return Err(Error::invalid(
                "environment",
                "an architecture name is empty",
            ));
        }
        Ok(Arch::new(text))
    }
}

/// What a change requires its runs to have in common: the *requirement* half of
/// giti-1rs.4, published in the repo policy and compared to a manifest's
/// [`Environment`] at verification time.
///
/// Every field is optional, and a field that is absent is not compared — which is
/// what makes a requirement composable: a repo that only cares about the CPU
/// publishes `arch` and nothing else, and a repo claiming bit-for-bit
/// reproducibility publishes the image digest and the whole toolchain.
///
/// ```
/// use gitiup_attest::{EnvMatch, EnvironmentRequirement, sample};
///
/// // "this change was verified on amd64" — the sentence the acceptance criteria name.
/// let manifest = sample::local();
/// let requirement = EnvironmentRequirement::parse("arch=amd64 toolchain:rustc=1.99").unwrap();
/// requirement
///     .check(&manifest.result.environment, &manifest.result.provenance, EnvMatch::Major)
///     .unwrap();
/// # Ok::<(), gitiup_attest::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRequirement {
    /// Required architecture, in any spelling ([`Arch`] canonicalises it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Required OS id, lower case (`linux`, `macos`, `windows`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Required OS version (`24.04`). Version-bearing, so `major` rounds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Required container image digest — the supply-chain pin of the machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<Digest>,
    /// Required image reference as written (`ubuntu:24.04`). Compared exactly: a
    /// reference is a name, not a version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_reference: Option<String>,
    /// Required runner backend (`docker`, `unshare`, `shell`, …) — the single-value
    /// form of [`crate::Policy::allowed_sandboxes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Required runner implementation and version (`gitiup 0.1.0`). Version-bearing,
    /// so `major` rounds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    /// Required toolchain entries: tool name → version. Version-bearing, so `major`
    /// rounds it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub toolchain: BTreeMap<String, String>,
    /// Required environment fingerprint, for the case where a repo has *one* blessed
    /// machine class and wants it pinned by digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Digest>,
}

/// The fields a requirement may name, for the error that lists them.
pub const REQUIREMENT_FIELDS: [&str; 9] = [
    "arch",
    "os",
    "os_version",
    "image_digest",
    "image_reference",
    "provider",
    "runner",
    "fingerprint",
    "toolchain:NAME",
];

impl EnvironmentRequirement {
    /// A requirement that requires nothing.
    pub fn empty() -> EnvironmentRequirement {
        EnvironmentRequirement::default()
    }

    /// Does this requirement constrain anything at all?
    pub fn is_empty(&self) -> bool {
        self.arch.is_none()
            && self.os.is_none()
            && self.os_version.is_none()
            && self.image_digest.is_none()
            && self.image_reference.is_none()
            && self.provider.is_none()
            && self.runner.is_none()
            && self.fingerprint.is_none()
            && self.toolchain.is_empty()
    }

    /// The names of the fields it constrains, sorted, for refusals and for
    /// `gitiup env`'s "what did this policy ask for" line.
    pub fn named(&self) -> Vec<String> {
        let mut names = Vec::new();
        for (name, present) in [
            ("arch", self.arch.is_some()),
            ("os", self.os.is_some()),
            ("os_version", self.os_version.is_some()),
            ("image_digest", self.image_digest.is_some()),
            ("image_reference", self.image_reference.is_some()),
            ("provider", self.provider.is_some()),
            ("runner", self.runner.is_some()),
            ("fingerprint", self.fingerprint.is_some()),
        ] {
            if present {
                names.push(name.to_string());
            }
        }
        names.extend(
            self.toolchain
                .keys()
                .map(|tool| format!("toolchain:{tool}")),
        );
        names.sort();
        names
    }

    /// Set one field, spelled `NAME` (the value comes separately) — the shape a
    /// policy file and a command line both end up handing it.
    ///
    /// Toolchain entries are named `toolchain:rustc` (also accepted:
    /// `toolchain.rustc`, `toolchain rustc`, and `-` where you would write `_`).
    pub fn set(&mut self, field: &str, value: &str) -> Result<()> {
        let key = field.trim().to_ascii_lowercase().replace('-', "_");
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::invalid(
                "environment",
                format!("requirement for '{field}' is empty"),
            ));
        }
        if let Some(tool) = key
            .strip_prefix("toolchain:")
            .or_else(|| key.strip_prefix("toolchain."))
            .or_else(|| key.strip_prefix("toolchain "))
        {
            let tool = tool.trim().to_ascii_lowercase();
            if tool.is_empty() {
                return Err(Error::invalid(
                    "environment",
                    "a toolchain requirement needs the tool's name: toolchain:rustc=1.99.1",
                ));
            }
            self.toolchain.insert(tool, value.to_string());
            return Ok(());
        }
        match key.as_str() {
            "arch" => self.arch = Some(value.to_string()),
            "os" => self.os = Some(value.to_string()),
            "os_version" => self.os_version = Some(value.to_string()),
            "image_digest" => self.image_digest = Some(value.parse()?),
            "image_reference" | "image_ref" => self.image_reference = Some(value.to_string()),
            "provider" | "sandbox" => self.provider = Some(value.to_string()),
            "runner" => self.runner = Some(value.to_string()),
            "fingerprint" | "env_fingerprint" => self.fingerprint = Some(value.parse()?),
            other => {
                return Err(Error::invalid(
                    "environment",
                    format!("unknown environment requirement '{other}'"),
                )
                .with_hint(format!(
                    "known fields are {}",
                    REQUIREMENT_FIELDS.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// Parse a whole requirement in the command-line shape: whitespace-separated
    /// `field=value` pairs, optionally quoted so a value may hold a space
    /// (`runner="gitiup 0.1"`).
    ///
    /// ```
    /// use gitiup_attest::EnvironmentRequirement;
    ///
    /// let requirement =
    ///     EnvironmentRequirement::parse("arch=amd64 toolchain:rustc=1.99").unwrap();
    /// assert_eq!(requirement.arch.as_deref(), Some("amd64"));
    /// assert_eq!(
    ///     requirement.toolchain.get("rustc").map(String::as_str),
    ///     Some("1.99")
    /// );
    /// let quoted = EnvironmentRequirement::parse(r#"runner="gitiup 0.1""#).unwrap();
    /// assert_eq!(quoted.runner.as_deref(), Some("gitiup 0.1"));
    /// ```
    pub fn parse(text: &str) -> Result<EnvironmentRequirement> {
        let mut requirement = EnvironmentRequirement::empty();
        for pair in split_pairs(text) {
            let Some((field, value)) = pair.split_once('=') else {
                return Err(Error::invalid(
                    "environment",
                    format!("requirement '{pair}' is not a NAME=VALUE pair"),
                )
                .with_hint("requirements look like arch=amd64 toolchain:rustc=1.99.1"));
            };
            requirement.set(field, value)?;
        }
        Ok(requirement)
    }

    /// Fold another requirement into this one, `other` winning field by field.
    ///
    /// This is how a policy file and a command line become one question: the file
    /// says what the repo requires, the command line adds or narrows one field for
    /// this invocation, and neither silently drops the other's fields.
    pub fn merge(&mut self, other: &EnvironmentRequirement) {
        let EnvironmentRequirement {
            arch,
            os,
            os_version,
            image_digest,
            image_reference,
            provider,
            runner,
            toolchain,
            fingerprint,
        } = other;
        if arch.is_some() {
            self.arch = arch.clone();
        }
        if os.is_some() {
            self.os = os.clone();
        }
        if os_version.is_some() {
            self.os_version = os_version.clone();
        }
        if image_digest.is_some() {
            self.image_digest = image_digest.clone();
        }
        if image_reference.is_some() {
            self.image_reference = image_reference.clone();
        }
        if provider.is_some() {
            self.provider = provider.clone();
        }
        if runner.is_some() {
            self.runner = runner.clone();
        }
        if fingerprint.is_some() {
            self.fingerprint = fingerprint.clone();
        }
        for (tool, version) in toolchain {
            self.toolchain.insert(tool.clone(), version.clone());
        }
    }

    /// The requirement as one line, for a refusal to quote back.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        for (name, value) in [
            ("arch", self.arch.as_deref()),
            ("os", self.os.as_deref()),
            ("os_version", self.os_version.as_deref()),
            (
                "image_digest",
                self.image_digest.as_ref().map(Digest::hex).as_deref(),
            ),
            ("image_reference", self.image_reference.as_deref()),
            ("provider", self.provider.as_deref()),
            ("runner", self.runner.as_deref()),
            (
                "fingerprint",
                self.fingerprint.as_ref().map(Digest::hex).as_deref(),
            ),
        ] {
            if let Some(value) = value {
                parts.push(format!("{name}={value}"));
            }
        }
        for (tool, version) in &self.toolchain {
            parts.push(format!("toolchain:{tool}={version}"));
        }
        if parts.is_empty() {
            return "nothing".to_string();
        }
        parts.join(" ")
    }

    /// Compare a manifest's environment — and the provenance beside it, because the
    /// runner version lives there — against this requirement.
    ///
    /// Fails at the first difference, naming both sides. `mode` decides how a
    /// version is read; everything version-free is compared exactly whatever the
    /// mode (see [`EnvMatch`]).
    pub fn check(
        &self,
        environment: &Environment,
        provenance: &Provenance,
        mode: EnvMatch,
    ) -> Result<()> {
        if !mode.is_enforced() || self.is_empty() {
            return Ok(());
        }

        if let Some(needed) = &self.arch {
            let wanted = Arch::new(needed);
            if !wanted.matches(&environment.arch) {
                return Err(mismatch(
                    "arch",
                    &environment.arch,
                    &format!("{needed}{}", wanted.note(needed)),
                ));
            }
        }

        if let Some(needed) = &self.os {
            let got = environment.os.as_deref().unwrap_or(UNREPORTED);
            if !same_str(got, needed) {
                return Err(mismatch("os", got, needed));
            }
        }

        if let Some(needed) = &self.os_version {
            let got = environment.os_version.as_deref().unwrap_or(UNREPORTED);
            if !version_matches(got, needed, mode) {
                return Err(mismatch("os_version", got, needed));
            }
        }

        if let Some(needed) = &self.image_digest {
            match &environment.image {
                None => {
                    return Err(mismatch(
                        "image_digest",
                        "no container image was reported",
                        &needed.to_string(),
                    )
                    .with_hint(
                        "the runner reads the image digest from $GITIUP_IMAGE_DIGEST, then \
                         /run/.containerenv; a run on a plain host has none, so either run it \
                         in the pinned image or set require-env-match = off",
                    ));
                }
                Some(image) if &image.digest != needed => {
                    return Err(mismatch(
                        "image_digest",
                        &image.digest.to_string(),
                        &needed.to_string(),
                    ));
                }
                Some(_) => {}
            }
        }

        if let Some(needed) = &self.image_reference {
            let got = environment
                .image
                .as_ref()
                .and_then(|image| image.reference.as_deref())
                .unwrap_or(UNREPORTED);
            // A reference is a name: `major` does not round it, because nothing says
            // which characters of `ubuntu:24.04` would be the version.
            if !same_str(got, needed) {
                return Err(mismatch("image_reference", got, needed));
            }
        }

        if let Some(needed) = &self.provider {
            let got = environment.provider.as_deref().unwrap_or(UNREPORTED);
            if !same_str(got, needed) {
                return Err(mismatch("provider", got, needed));
            }
        }

        if let Some(needed) = &self.runner
            && !version_matches(&provenance.runner, needed, mode)
        {
            return Err(mismatch("runner", &provenance.runner, needed));
        }

        for (tool, needed) in &self.toolchain {
            match environment.find_tool(tool) {
                None => {
                    return Err(mismatch(
                        &format!("toolchain:{tool}"),
                        "not reported by this run",
                        needed,
                    )
                    .with_hint(format!(
                        "this run reported {} toolchain entr{} ({}); a tool the runner never \
                         saw cannot be matched — name more of them with $GITIUP_TOOLCHAIN",
                        environment.toolchain.len(),
                        if environment.toolchain.len() == 1 {
                            "y"
                        } else {
                            "ies"
                        },
                        environment.describe_toolchain()
                    )));
                }
                Some(got) if !version_matches(got, needed, mode) => {
                    return Err(mismatch(&format!("toolchain:{tool}"), got, needed));
                }
                Some(_) => {}
            }
        }

        if let Some(needed) = &self.fingerprint
            && &environment.fingerprint != needed
        {
            return Err(mismatch(
                "fingerprint",
                &environment.fingerprint.to_string(),
                &needed.to_string(),
            )
            .with_hint(format!(
                "this run's environment is {} · {}",
                environment.describe(),
                environment.describe_toolchain()
            )));
        }
        Ok(())
    }
}

impl fmt::Display for EnvironmentRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

impl FromStr for EnvironmentRequirement {
    type Err = Error;

    fn from_str(text: &str) -> Result<EnvironmentRequirement> {
        EnvironmentRequirement::parse(text)
    }
}

/// Split a requirement spec into `field=value` tokens, honouring `"…"` and `'…'`
/// so one value may contain a space.
///
/// Runner and image references are the reason: `gitiup 0.1.0` is one value, and a
/// splitter that broke on whitespace would make the most human-readable field in
/// the requirement the one you could not write.
fn split_pairs(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                c => current.push(c),
            },
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// What a run said about a field it does not have.
const UNREPORTED: &str = "unreported";

/// Split a version-ish string into its numeric components (`1.99.1` → `["1","99","1"]`).
///
/// Anything that is not a digit is a separator, which is what lets `v22.3.0`,
/// `22.3.0` and `node v22.3.0` all satisfy a requirement of `22.3`. `None` means
/// there were no digits at all, so there is nothing to round.
pub fn version_components(text: &str) -> Option<Vec<&str>> {
    let mut parts: Vec<&str> = Vec::new();
    for run in text.split(|c: char| !c.is_ascii_digit()) {
        if !run.is_empty() {
            parts.push(run);
        }
    }
    if parts.is_empty() { None } else { Some(parts) }
}

/// Do two version strings agree the way `mode` asks?
///
/// * `strict` — the same string, ignoring case and surrounding space.
/// * `major` — they agree as far as `required` states: `1.99` is satisfied by
///   `1.99.4`, `1.99.1` is not satisfied by `1.99.4`. When either side has no
///   digits (a runner string like `gitiup dev`), this falls back to exact equality
///   rather than guessing.
pub fn version_matches(got: &str, required: &str, mode: EnvMatch) -> bool {
    if mode == EnvMatch::Strict {
        return same_str(got, required);
    }
    let (Some(got), Some(required)) = (version_components(got), version_components(required))
    else {
        return same_str(got, required);
    };
    let shared = got.len().min(required.len());
    got[..shared] == required[..shared]
}

/// Case- and space-insensitive equality, for fields that carry no version.
fn same_str(got: &str, required: &str) -> bool {
    got.trim().eq_ignore_ascii_case(required.trim())
}

/// The refusal every mismatch produces: both sides, the field, and the exit code a
/// gate branches on.
fn mismatch(field: &str, got: &str, required: &str) -> Error {
    Error::new(
        ErrorKind::Policy,
        "environment",
        format!(
            "this run's {field} is '{got}', which does not match what this change requires: {required}"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample;

    fn environment() -> Environment {
        sample::local().result.environment
    }

    fn provenance() -> Provenance {
        sample::local().result.provenance
    }

    #[test]
    fn arch_aliases_are_the_same_architecture() {
        assert!(Arch::new("amd64").matches("x86_64"));
        assert!(Arch::new("arm64").matches("aarch64"));
        assert!(Arch::new(" ARM64 ").matches("aarch64"));
        assert!(!Arch::new("amd64").matches("aarch64"));
        // An unknown name is kept, not refused: riscv64 exists.
        assert_eq!(Arch::new("riscv64").canonical(), "riscv64");
        assert!("".parse::<Arch>().is_err());
    }

    #[test]
    fn match_settings_parse_tolerantly_and_refuse_typos() {
        assert_eq!(EnvMatch::parse(" Strict ").unwrap(), EnvMatch::Strict);
        assert_eq!(EnvMatch::parse("off").unwrap(), EnvMatch::Off);
        assert!(!EnvMatch::Off.is_enforced());
        let err = EnvMatch::parse("strictish").unwrap_err();
        assert_eq!(err.exit_code(), 6);
        assert!(err.detail().contains("strictish"));
        assert!(err.hint().unwrap().contains("strict, major, off"));
    }

    #[test]
    fn version_matching_is_as_coarse_as_the_requirement() {
        assert!(version_matches("1.99.4", "1.99", EnvMatch::Major));
        assert!(!version_matches("1.99.4", "1.99", EnvMatch::Strict));
        assert!(!version_matches("1.99.4", "1.99.1", EnvMatch::Major));
        assert!(version_matches("1.99.1", "1.99.1", EnvMatch::Major));
        assert!(version_matches("v22.3.0", "22.3", EnvMatch::Major));
        assert!(version_matches("node v22.3.0", "22", EnvMatch::Major));
        assert!(!version_matches("2.0", "1", EnvMatch::Major));
        // Nothing to round: fall back to equality rather than guessing.
        assert!(!version_matches("gitiup dev", "gitiup 0", EnvMatch::Major));
        assert!(version_matches("gitiup dev", "gitiup dev", EnvMatch::Major));
        assert_eq!(version_components("no digits"), None);
    }

    #[test]
    fn a_requirement_parses_and_describes_itself() {
        let requirement =
            EnvironmentRequirement::parse("arch=amd64 toolchain:rustc=1.99 os=linux").unwrap();
        assert_eq!(requirement.arch.as_deref(), Some("amd64"));
        assert_eq!(requirement.toolchain.len(), 1);
        assert!(!requirement.is_empty());
        let described = requirement.describe();
        assert!(described.contains("arch=amd64"), "{described}");
        assert!(described.contains("toolchain:rustc=1.99"), "{described}");
        assert_eq!(EnvironmentRequirement::empty().describe(), "nothing");
        assert!(EnvironmentRequirement::parse("nonsense").is_err());
        assert!(
            EnvironmentRequirement::parse("nope=1")
                .unwrap_err()
                .hint()
                .is_some()
        );
        // Quoting is how a value with a space is written — a runner is `gitiup 0.1`.
        let quoted = EnvironmentRequirement::parse(r#"runner="gitiup 0.1" os=linux"#).unwrap();
        assert_eq!(quoted.runner.as_deref(), Some("gitiup 0.1"));
        assert_eq!(quoted.os.as_deref(), Some("linux"));
    }

    #[test]
    fn merging_keeps_every_field_either_side_named() {
        let mut requirement =
            EnvironmentRequirement::parse("arch=amd64 os=linux toolchain:rustc=1.99").unwrap();
        requirement.merge(&EnvironmentRequirement::parse("arch=arm64 toolchain:node=22").unwrap());
        // The later source wins the field it names, and nothing else.
        assert_eq!(requirement.arch.as_deref(), Some("arm64"));
        assert_eq!(requirement.os.as_deref(), Some("linux"));
        assert_eq!(requirement.toolchain.len(), 2);
    }

    #[test]
    fn matching_environment_passes_and_unlisted_fields_are_free() {
        let environment = environment();
        let requirement = EnvironmentRequirement::parse("arch=x86_64 os=linux").unwrap();
        requirement
            .check(&environment, &provenance(), EnvMatch::Strict)
            .unwrap();
        // A field the requirement does not name is never compared.
        let loose = EnvironmentRequirement::parse("arch=amd64").unwrap();
        loose
            .check(&environment, &provenance(), EnvMatch::Off)
            .unwrap();
    }

    #[test]
    fn a_toolchain_requirement_reads_both_ways() {
        let environment = environment(); // carries rustc 1.99.1
        EnvironmentRequirement::parse("toolchain:rustc=1.99.1")
            .unwrap()
            .check(&environment, &provenance(), EnvMatch::Strict)
            .unwrap();
        EnvironmentRequirement::parse("toolchain:rustc=1.99")
            .unwrap()
            .check(&environment, &provenance(), EnvMatch::Major)
            .unwrap();
        let err = EnvironmentRequirement::parse("toolchain:rustc=1.88")
            .unwrap()
            .check(&environment, &provenance(), EnvMatch::Major)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("toolchain:rustc"));

        let absent = EnvironmentRequirement::parse("toolchain:ghc=9")
            .unwrap()
            .check(&environment, &provenance(), EnvMatch::Strict)
            .unwrap_err();
        assert!(absent.detail().contains("not reported by this run"));
        assert!(absent.hint().unwrap().contains("GITIUP_TOOLCHAIN"));
    }

    #[test]
    fn an_unreported_field_never_matches() {
        let mut environment = environment();
        environment.image = None;
        environment.os_version = None;
        let requirement = EnvironmentRequirement {
            image_digest: Some(crate::Digest::sha256(b"pinned image")),
            ..EnvironmentRequirement::empty()
        };
        let err = requirement
            .check(&environment, &provenance(), EnvMatch::Strict)
            .unwrap_err();
        assert!(err.detail().contains("no container image was reported"));
        assert!(err.hint().unwrap().contains("GITIUP_IMAGE_DIGEST"));
        EnvironmentRequirement::parse("os_version=24.04")
            .unwrap()
            .check(&environment, &provenance(), EnvMatch::Major)
            .unwrap_err();
    }

    #[test]
    fn a_fingerprint_requirement_says_what_the_environment_actually_was() {
        let environment = environment();
        let requirement = EnvironmentRequirement {
            fingerprint: Some(crate::Digest::sha256(b"someone else's machine")),
            ..EnvironmentRequirement::empty()
        };
        let err = requirement
            .check(&environment, &provenance(), EnvMatch::Strict)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("fingerprint"));
        // The hint is the actionable part: a hash cannot say which field moved, so
        // the refusal prints the environment instead.
        assert!(err.hint().unwrap().contains("rustc"));
    }
}

//! Verification policy: what a verifier is willing to accept
//! ([ADR-0001 D6](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md),
//! [D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//!
//! The format decides what a manifest *means*; policy decides whether *this*
//! manifest is good enough for *this* decision. The split is what lets
//! `gitiup verify attestation` be one primitive with many uses: a pre-receive
//! hook wants "signed by an owner key, less than an hour old, tier local"; a
//! quorum coordinator wants "signed by a selected verifier, challenge matches";
//! a human poking around wants "just tell me what it says".
//!
//! # Provenance is policy, and its default is the safe one
//!
//! [`Policy::allowed_tiers`] defaults to `[local]`: a *simulated* attestation —
//! the kind `gitiup run` writes when you ask it for nothing — is refused until
//! someone says otherwise on purpose, and `quorum` is never satisfiable by a
//! single run because the format refuses that claim outright
//! ([`Provenance::check`]). [`Policy::allowed_sandboxes`] narrows *where* a
//! `local` run may have happened, so a host that only trusts container runs can
//! say so without accepting a bare `shell` run. [`PolicyFile`] is the JSON a repo
//! writes that down (`gitiup-policy.json`), including the one-line spelling
//! `"allow_simulated": false`.
//!
//! # The machine class is policy too
//!
//! [`Policy::require_environment`] plus [`Policy::require_env_match`] are the
//! environment gate of giti-1rs.4: the repo publishes the machine class its
//! attestation was made on — "amd64, `rustc 1.99`, this image digest" — and
//! verification refuses a run that does not match it, at the setting the repo
//! chose (`strict`, `major`, or `off`). See [`crate::envreq`] for what each setting
//! promises and why a refusal reads like a sentence rather than like two digests
//! that failed to agree.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::{Algorithm, Digest};
use crate::envreq::{EnvMatch, EnvironmentRequirement};
use crate::error::{Error, ErrorKind, Result};
use crate::manifest::{Environment, Provenance, ResultDigest, Tier};
use crate::oid::GitOid;
use crate::time::TimeUs;

/// Schema version [`PolicyFile`] writes, and the only one it reads.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// The file name `gitiup` looks for when no `--policy` was given.
pub const POLICY_FILE_NAME: &str = "gitiup-policy.json";

/// Environment variable that overrides discovery with an explicit path.
pub const POLICY_PATH_ENV: &str = "GITIUP_POLICY";

/// Default freshness window: 24 h.
///
/// Deliberately short. A claimed timestamp is only as good as the clock that
/// wrote it, and without a trusted timestamp the honest assumption is "fresh
/// enough that the key was believed intact when it signed"
/// ([ADR-0001 D6](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
pub const DEFAULT_MAX_AGE_US: i64 = 24 * 60 * 60 * 1_000_000;

/// Default clock-skew allowance: 5 min.
pub const DEFAULT_MAX_CLOCK_SKEW_US: i64 = 5 * 60 * 1_000_000;

/// Who the verifier trusts to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Trust nobody: everything is refused. The default, so a mis-wired policy
    /// fails closed rather than accepting the first signature it sees.
    None,
    /// Trust exactly these key ids (`SHA256:…`). This is what an owner writes in
    /// `gitiup.toml`, and what giti-1rs.6's identity records publish.
    KeyIds(BTreeSet<String>),
    /// Trust whatever key is offered, as long as the signature is valid.
    ///
    /// **Never for production.** It exists so tests and `gitiup doctor`'s
    /// "does this file parse and sign?" path can say something useful without a
    /// keyring.
    AnyKeyForTests,
}

impl Trust {
    /// Is `key_id` trusted?
    pub fn trusts(&self, key_id: &str) -> bool {
        match self {
            Trust::None => false,
            Trust::KeyIds(ids) => ids.contains(key_id),
            Trust::AnyKeyForTests => true,
        }
    }
}

/// Everything a caller must supply beyond the bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Accepted signers.
    pub trust: Trust,
    /// Accepted digest algorithms (v1 has one honest value: `sha256`).
    pub digest_algorithms: Vec<Algorithm>,
    /// How old an attestation may be.
    pub max_age_us: i64,
    /// How far a claimed time may run ahead of the verifier's clock.
    pub max_clock_skew_us: i64,
    /// Accepted provenance tiers. `simulated` is excluded by default: a plan is
    /// not an execution (giti-1rs.7).
    pub allowed_tiers: Vec<Tier>,
    /// Accepted sandbox backends for a `local` run, by name (`docker`, `unshare`,
    /// `landlock`, …). Empty means "any backend the format accepts", which is the
    /// right default for a verifier with no opinion about *where* a run happened
    /// and the wrong one for a volunteer's machine (giti-bgy.1 narrows this).
    ///
    /// A run that named no sandbox never gets here: `local` requires one and a
    /// plan may not claim one ([`Provenance::check`]).
    pub allowed_sandboxes: Vec<String>,
    /// Distinct trusted signatures required (one vote per identity, giti-msi.9).
    pub min_signatures: usize,
    /// Refuse an attestation bound to a different commit than this.
    pub expected_commit: Option<GitOid>,
    /// Refuse unless the result digest matches — the check that makes a quorum a
    /// comparison instead of a vote of confidence.
    pub expected_result_digest: Option<ResultDigest>,
    /// Refuse unless the verifier was handed this challenge (giti-msi.6).
    pub expected_challenge: Option<Digest>,
    /// Require the producer's normalisation rules to be exactly this version;
    /// two normalisations that differ cannot produce comparable digests.
    pub normalisation_version: Option<u32>,
    /// How strictly the run's environment must match [`Self::require_environment`]
    /// (giti-1rs.4). `Off` compares nothing.
    ///
    /// Defaults to [`EnvMatch::Strict`]: a requirement that is published is a
    /// promise, and reading a promise generously is how an arm64 attestation ends
    /// up satisfying an amd64 change.
    pub require_env_match: EnvMatch,
    /// What the run's environment must be: architecture, OS and version, image
    /// digest, toolchain, runner, backend. `None` requires nothing.
    pub require_environment: Option<EnvironmentRequirement>,
    /// The clock. `None` means "now"; tests and replayed runs pin it.
    pub now: Option<TimeUs>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            trust: Trust::None,
            digest_algorithms: Algorithm::ALL.to_vec(),
            max_age_us: DEFAULT_MAX_AGE_US,
            max_clock_skew_us: DEFAULT_MAX_CLOCK_SKEW_US,
            allowed_tiers: vec![Tier::Local],
            allowed_sandboxes: Vec::new(),
            min_signatures: 1,
            expected_commit: None,
            expected_result_digest: None,
            expected_challenge: None,
            normalisation_version: None,
            require_env_match: EnvMatch::Strict,
            require_environment: None,
            now: None,
        }
    }
}

impl Policy {
    /// A policy that checks the mechanics and nothing that needs a keyring.
    ///
    /// Test and diagnostic helper: it accepts any signature, so it answers "is
    /// this well-formed and self-consistent?" and never "should I trust it?".
    pub fn for_tests() -> Policy {
        Policy {
            trust: Trust::AnyKeyForTests,
            allowed_tiers: vec![Tier::Simulated, Tier::Local, Tier::Quorum],
            now: Some(TimeUs::from_secs(1_793_092_600)),
            ..Default::default()
        }
    }

    /// A policy trusting exactly these key ids.
    pub fn trusting<I, S>(key_ids: I) -> Policy
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Policy {
            trust: Trust::KeyIds(key_ids.into_iter().map(Into::into).collect()),
            ..Default::default()
        }
    }

    /// Is this tier acceptable at all under this policy?
    pub fn allows_tier(&self, tier: Tier) -> bool {
        self.allowed_tiers.contains(&tier)
    }

    /// Is this sandbox backend acceptable? An empty allow-list accepts every
    /// backend, including the absence of one.
    pub fn allows_sandbox(&self, sandbox: Option<&str>) -> bool {
        if self.allowed_sandboxes.is_empty() {
            return true;
        }
        match sandbox {
            Some(name) => self
                .allowed_sandboxes
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name)),
            None => false,
        }
    }

    /// Check a run's provenance against this policy: tier first, then sandbox.
    ///
    /// Split out of [`AttestationDoc::verify`](crate::AttestationDoc::verify) for
    /// the callers holding an *unsigned* manifest — `gitiup run` asking "would the
    /// owner's policy accept what I am about to produce?", a gate deciding before
    /// it fetches a key. Same rules, same error, same exit code.
    pub fn check_provenance(&self, provenance: &Provenance) -> Result<()> {
        let tier = provenance.tier;
        if !self.allows_tier(tier) {
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!("provenance tier '{tier}' is not accepted here"),
            )
            .with_hint(if tier == Tier::Simulated {
                "a simulated run plans but does not execute; run it for real \
                 (`gitiup run --execute --sandbox <backend>`) to satisfy this gate, \
                 or set `\"allow_simulated\": true` in the policy only if a plan is \
                 genuinely what you want to record"
                    .to_string()
            } else {
                format!(
                    "adjust the owner's allowed provenance tiers deliberately: allowed here are {}",
                    self.allowed_tiers
                        .iter()
                        .map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }));
        }
        // The sandbox question only exists for work that actually happened: a
        // plan has no sandbox to name, and `allowed_sandboxes` must not silently
        // become a second way to refuse `simulated` (that is what `allowed_tiers`
        // is for, and one answer per question is what makes a policy readable).
        let sandbox = provenance.confining_sandbox();
        if provenance.tier.is_executed() && !self.allows_sandbox(sandbox) {
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!(
                    "sandbox '{}' is not accepted here",
                    sandbox.unwrap_or(crate::manifest::NO_SANDBOX)
                ),
            )
            .with_hint(format!(
                "allowed sandboxes are {}",
                self.allowed_sandboxes.join(", ")
            )));
        }
        Ok(())
    }

    /// The environment question, answered: is a requirement enforced here?
    ///
    /// `None` when the knob is `off` or no requirement was published, so a caller
    /// printing "what does this policy demand of the machine?" can say "nothing" in
    /// one branch instead of two.
    pub fn environment_requirement(&self) -> Option<&EnvironmentRequirement> {
        if self.require_env_match.is_enforced() {
            self.require_environment.as_ref()
        } else {
            None
        }
    }

    /// Check a run's environment against this policy's requirement (giti-1rs.4).
    ///
    /// This is the check that turns "the digests differ and nobody knows why" into
    /// a sentence: an arm64 attestation offered for a change that requires amd64 is
    /// refused as a *policy* decision (exit 6) naming both architectures, not
    /// reported as a mystery digest difference.
    ///
    /// `provenance` comes along because the runner version — part of the machine
    /// class a fingerprint stands for — is recorded there.
    pub fn check_environment(
        &self,
        environment: &Environment,
        provenance: &Provenance,
    ) -> Result<()> {
        let Some(requirement) = self.environment_requirement() else {
            return Ok(());
        };
        requirement.check(environment, provenance, self.require_env_match)
    }

    /// The clock this policy verifies against.
    pub fn now(&self) -> TimeUs {
        self.now.unwrap_or_else(TimeUs::now)
    }

    /// Digest algorithms as a slice.
    pub fn digest_algorithms(&self) -> &[Algorithm] {
        &self.digest_algorithms
    }

    /// Reject a digest the verifier cannot check, instead of comparing bytes it
    /// does not understand.
    pub fn check_digest(&self, digest: &Digest) -> Result<()> {
        if digest.is_allowed(self.digest_algorithms()) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!(
                    "digest algorithm '{}' is not allowed by policy",
                    digest.algorithm().as_str()
                ),
            ))
        }
    }
}

/// The JSON a repo writes to say what it will accept (`gitiup-policy.json`).
///
/// One file, one schema version, and every field optional: an empty document is
/// the safe policy (`[local]`, no trusted keys, fails closed), not an error. The
/// point of a *file* is that the decision is written down next to the change it
/// gates, reviewed like code, and read identically by `gitiup run`, by a hook and
/// by a volunteer — instead of being re-decided by whoever wrote the shell script.
///
/// ```json
/// {
///   "schema_version": 1,
///   "allow_simulated": false,
///   "allowed_sandboxes": ["docker", "podman", "unshare"],
///   "require_env_match": "major",
///   "require_arch": "amd64",
///   "require_toolchain": {"rustc": "1.99"},
///   "trust_key_ids": ["SHA256:nlTU572wrqEfZGpFZmv3xmlgh82RqlvoDhNfxWFbS/w"],
///   "min_signatures": 1,
///   "max_age_us": 86400000000
/// }
/// ```
///
/// `allow_simulated` is the one-line spelling of the decision most repos make:
/// `false` (the default) refuses a plan, `true` accepts one and still requires
/// everything else. It may not contradict `allowed_tiers` — a policy that argues
/// with itself is refused, not resolved by a precedence nobody remembers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Format version; only [`POLICY_SCHEMA_VERSION`] is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// Accept a `simulated` attestation. Absent means `false`: a plan is not an
    /// execution, so refusing it is the default (giti-1rs.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_simulated: Option<bool>,
    /// Tier names, instead of the `allow_simulated` shorthand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tiers: Option<Vec<String>>,
    /// Sandbox backends a `local` run may name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_sandboxes: Option<Vec<String>>,
    /// Key ids (`SHA256:…`) allowed to sign. Empty trusts nobody.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_key_ids: Vec<String>,
    /// Distinct trusted signatures required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_signatures: Option<usize>,
    /// Freshness window in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_us: Option<i64>,
    /// Clock-skew allowance in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clock_skew_us: Option<i64>,
    /// Refuse an attestation bound to a different commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_commit: Option<String>,
    /// Refuse unless the result digest is exactly this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_result_digest: Option<String>,
    /// Require the producer's normalisation rules to be this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_normalisation_version: Option<u32>,
    /// How strictly the environment requirement is enforced: `strict`, `major` or
    /// `off` (giti-1rs.4). Also accepted spelled `require-env-match`, because that
    /// is how people type it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-env-match"
    )]
    pub require_env_match: Option<String>,
    /// Required architecture, any spelling (`amd64`, `x86_64`, `arm64`, …).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-arch"
    )]
    pub require_arch: Option<String>,
    /// Required OS id (`linux`).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "require-os")]
    pub require_os: Option<String>,
    /// Required OS version (`24.04`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-os-version"
    )]
    pub require_os_version: Option<String>,
    /// Required container image digest (`sha256:…`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-image-digest"
    )]
    pub require_image_digest: Option<String>,
    /// Required image reference as written (`ubuntu:24.04`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-image-reference"
    )]
    pub require_image_reference: Option<String>,
    /// Required runner backend (`docker`, `unshare`, …).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-provider"
    )]
    pub require_provider: Option<String>,
    /// Required runner implementation and version (`gitiup 0.1.0`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-runner"
    )]
    pub require_runner: Option<String>,
    /// Required toolchain entries: tool name → version.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-toolchain"
    )]
    pub require_toolchain: Option<BTreeMap<String, String>>,
    /// Required environment fingerprint, for a repo with exactly one blessed
    /// machine class.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-env-fingerprint"
    )]
    pub require_env_fingerprint: Option<String>,
}

impl PolicyFile {
    /// The keys a policy file may contain, for the error that lists them.
    const KEYS: &'static [&'static str] = &[
        "schema_version",
        "allow_simulated",
        "allowed_tiers",
        "allowed_sandboxes",
        "trust_key_ids",
        "min_signatures",
        "max_age_us",
        "max_clock_skew_us",
        "expected_commit",
        "expected_result_digest",
        "require_normalisation_version",
        "require_env_match",
        "require_arch",
        "require_os",
        "require_os_version",
        "require_image_digest",
        "require_image_reference",
        "require_provider",
        "require_runner",
        "require_toolchain",
        "require_env_fingerprint",
    ];

    /// Parse policy JSON. Unknown keys are refused: a typo in a gate is a gate
    /// that quietly stopped gating.
    pub fn from_json(text: &str) -> Result<PolicyFile> {
        let file: PolicyFile = serde_json::from_str(text).map_err(|e| {
            Error::invalid("policy", format!("{POLICY_FILE_NAME}: {e}"))
                .with_hint(format!("known keys are {}", Self::KEYS.join(", ")))
        })?;
        if let Some(version) = file.schema_version
            && version != POLICY_SCHEMA_VERSION
        {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "policy",
                format!("policy schema_version {version} is not understood"),
            )
            .with_hint(format!("this build writes {POLICY_SCHEMA_VERSION}")));
        }
        // Tier names are checked here rather than in `to_policy`, so a typo is
        // reported against the file that contains it.
        if let Some(tiers) = &file.allowed_tiers {
            let mut parsed = Vec::with_capacity(tiers.len());
            for tier in tiers {
                parsed.push(Tier::parse(tier)?);
            }
            let mentions = parsed.contains(&Tier::Simulated);
            if let Some(allow) = file.allow_simulated
                && allow != mentions
            {
                return Err(Error::new(
                    ErrorKind::Policy,
                    "policy",
                    format!(
                        "allow_simulated is {allow} but allowed_tiers {} simulated",
                        if allow { "omits" } else { "includes" }
                    ),
                )
                .with_hint("say it once: drop allow_simulated, or make the two agree"));
            }
        }
        if let Some(version) = &file.require_env_match {
            // Parsed at read time, like the tier names, so a typo is reported
            // against the file that contains it rather than as a mystery refusal.
            EnvMatch::parse(version)?;
        }
        Ok(file)
    }

    /// Resolve into a [`Policy`], starting from this build's defaults.
    ///
    /// Every field the file does not mention keeps the default — the conservative
    /// one — so a minimal file cannot accidentally widen a gate.
    pub fn to_policy(&self) -> Result<Policy> {
        let mut policy = Policy::default();
        if let Some(tiers) = &self.allowed_tiers {
            policy.allowed_tiers = tiers
                .iter()
                .map(|t| Tier::parse(t))
                .collect::<Result<Vec<_>>>()?;
        } else if self.allow_simulated.unwrap_or(false) {
            policy.allowed_tiers.push(Tier::Simulated);
        }
        if policy.allowed_tiers.is_empty() {
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                "allowed_tiers is empty: a policy that accepts no tier accepts no attestation",
            )
            .with_hint("name at least one tier, usually \"local\""));
        }
        if let Some(sandboxes) = &self.allowed_sandboxes {
            policy.allowed_sandboxes = sandboxes.clone();
        }
        if !self.trust_key_ids.is_empty() {
            policy.trust = Trust::KeyIds(self.trust_key_ids.iter().cloned().collect());
        }
        if let Some(min) = self.min_signatures {
            if min == 0 {
                return Err(Error::new(
                    ErrorKind::Policy,
                    "policy",
                    "min_signatures 0 would accept an unsigned attestation",
                )
                .with_hint("the smallest sane value is 1"));
            }
            policy.min_signatures = min;
        }
        if let Some(age) = self.max_age_us {
            policy.max_age_us = age;
        }
        if let Some(skew) = self.max_clock_skew_us {
            policy.max_clock_skew_us = skew;
        }
        if let Some(commit) = &self.expected_commit {
            policy.expected_commit = Some(commit.parse()?);
        }
        if let Some(digest) = &self.expected_result_digest {
            let digest: Digest = digest.parse()?;
            policy.expected_result_digest = Some(ResultDigest(digest));
        }
        if let Some(version) = self.require_normalisation_version {
            policy.normalisation_version = Some(version);
        }
        if let Some(mode) = &self.require_env_match {
            policy.require_env_match = EnvMatch::parse(mode)?;
        }
        policy.require_environment = self.environment_requirement()?;
        // A policy that publishes a requirement while switching the comparison off
        // has argued with itself: say so instead of quietly ignoring the half the
        // reader spent their review time on (same rule as `allow_simulated`).
        if let Some(published) = &policy.require_environment
            && !policy.require_env_match.is_enforced()
        {
            // A policy that publishes a requirement while switching the
            // comparison off has argued with itself: say so instead of quietly
            // ignoring the half the reader spent their review time on (same rule
            // as `allow_simulated`).
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!(
                    "require-env-match is 'off' but an environment requirement is published ({published})",
                ),
            )
            .with_hint(
                "say it once: set require-env-match to strict or major, or drop the \
                 require_* keys you no longer want enforced",
            ));
        }
        Ok(policy)
    }

    /// The environment requirement this file publishes, if it names any field.
    ///
    /// One place so `to_policy` and any later reader agree on what "the repo
    /// requires amd64" is spelled.
    pub fn environment_requirement(&self) -> Result<Option<EnvironmentRequirement>> {
        let mut requirement = EnvironmentRequirement::empty();
        for (field, value) in [
            ("arch", self.require_arch.clone()),
            ("os", self.require_os.clone()),
            ("os_version", self.require_os_version.clone()),
            ("image_digest", self.require_image_digest.clone()),
            ("image_reference", self.require_image_reference.clone()),
            ("provider", self.require_provider.clone()),
            ("runner", self.require_runner.clone()),
            ("fingerprint", self.require_env_fingerprint.clone()),
        ] {
            if let Some(value) = value {
                requirement.set(field, &value)?;
            }
        }
        for (tool, version) in self.require_toolchain.iter().flatten() {
            requirement.set(&format!("toolchain:{tool}"), version)?;
        }
        if requirement.is_empty() {
            Ok(None)
        } else {
            Ok(Some(requirement))
        }
    }

    /// The policy a document describes, in one step.
    pub fn policy_from_json(text: &str) -> Result<Policy> {
        PolicyFile::from_json(text)?.to_policy()
    }
}

/// How fresh the attestation looked to the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    /// Claimed creation time.
    pub claimed_at: TimeUs,
    /// The clock it was judged against.
    pub now: TimeUs,
    /// `now - claimed_at`, negative when the claim is in the future.
    pub age_us: i64,
    /// The window that was applied.
    pub max_age_us: i64,
}

/// Check the claimed time against the policy window.
pub fn check_freshness(claimed_at_us: i64, policy: &Policy) -> Result<Freshness> {
    let now = policy.now();
    let claimed = TimeUs(claimed_at_us);
    let age_us = now.0 - claimed.0;
    if age_us < -policy.max_clock_skew_us {
        return Err(Error::new(
            ErrorKind::Policy,
            "freshness",
            format!(
                "attestation claims to be created {} in the future (skew allowance {})",
                crate::time::human_duration_us(-age_us),
                crate::time::human_duration_us(policy.max_clock_skew_us)
            ),
        )
        .with_hint("fix the clock on the machine that ran the job"));
    }
    if age_us > policy.max_age_us {
        return Err(Error::new(
            ErrorKind::Policy,
            "freshness",
            format!(
                "attestation is {} old, which exceeds the {} window",
                crate::time::human_duration_us(age_us),
                crate::time::human_duration_us(policy.max_age_us)
            ),
        )
        .with_hint("re-run the job, or widen the owner's freshness policy deliberately"));
    }
    Ok(Freshness {
        claimed_at: claimed,
        now,
        age_us,
        max_age_us: policy.max_age_us,
    })
}

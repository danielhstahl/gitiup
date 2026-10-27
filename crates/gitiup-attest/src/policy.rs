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

use std::collections::BTreeSet;

use crate::digest::{Algorithm, Digest};
use crate::error::{Error, ErrorKind, Result};
use crate::manifest::{ResultDigest, Tier};
use crate::oid::GitOid;
use crate::time::TimeUs;

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
            min_signatures: 1,
            expected_commit: None,
            expected_result_digest: None,
            expected_challenge: None,
            normalisation_version: None,
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

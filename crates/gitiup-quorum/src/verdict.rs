//! The verdict: what the owner may believe, and why
//! ([ADR-0002 D5, D7, D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md),
//! the epic's acceptance criterion).
//!
//! One change, five volunteers, five signed `ResultDigest`s — and now a decision that
//! a reviewer can audit without trusting the person who ran the tool. Three states,
//! and the difference between the last two is the whole point:
//!
//! | state | meaning | what a merge gate does |
//!|-------|---------|------------------------|
//!| `verified` | `required_agree` distinct identities signed the same `ResultDigest`, and every one of them survived selection, freshness, revocation and the capability post-check | merge |
//!| `failed` | the verifiers *disagree*, and no digest reached the threshold | do not merge; escalate (giti-msi.8) |
//!| `insufficient` | not enough eligible votes exist to decide, whoever they are | do not merge; grow the pool or wait |
//!
//! Counting rules, each one here because an attack exists:
//!
//! * **Identities, not keys.** A principal with four boxes is one vote (D4). A verdict
//!   that counted keys would let the owner's own rack certify a change.
//! * **Seats, not submissions.** Only a key the round selected may vote; a reserve
//!   that ran the job anyway has volunteered information, not a vote.
//! * **Void at verdict time, never remembered.** A `compromised` revocation voids the
//!   key's claims whatever the timing (D9), so there is no window in which a stale
//!   verdict can be minted.
//! * **Post-check the capability claims.** Selection trusted a claim; the signed
//!   environment is the receipt, and a mismatch is refused rather than argued with
//!   (D7).
//! * **Freshness is bound to the change.** The commit and the round challenge are
//!   checked per submission, so a replay of last week's honest work cannot certify
//!   this week's change.

use std::collections::BTreeMap;

use gitiup_attest::{
    AttestationDoc, Digest, GitOid, MAX_SIGNATURES, SignatureEntry, Signer, Tier, TimeUs, Trust,
};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::record::{
    VERDICT_PAYLOAD_TYPE, body_bytes, canonical_bytes, check_signatures, from_canonical_bytes,
    require_same_bytes,
};
use crate::roster::{Revocation, Roster};
use crate::round::Round;

/// The `type` of a verdict record.
pub const VERDICT_TYPE: &str = "gitiup-verdict-1";
/// Schema version this crate writes.
pub const VERDICT_SCHEMA_VERSION: u32 = 1;

/// The three states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumState {
    /// Enough distinct identities agree, under a policy that was met.
    Verified,
    /// The verifiers produced irreconcilable results.
    Failed,
    /// Not enough eligible votes to reach the threshold, whatever their content.
    Insufficient,
}

impl QuorumState {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            QuorumState::Verified => "verified",
            QuorumState::Failed => "failed",
            QuorumState::Insufficient => "insufficient",
        }
    }

    /// May a merge gate merge on this?
    pub fn mergeable(self) -> bool {
        self == QuorumState::Verified
    }
}

impl std::fmt::Display for QuorumState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the state is what it is, as a stable token for scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// The threshold was met.
    AgreementReached,
    /// Two or more results, none of them at the threshold.
    IrreconcilableDigests,
    /// The round could not fill its seats (D3: `sufficient: false`).
    SeatsNotFilled,
    /// The round filled its seats but too few of them voted, or too few agreed.
    NotEnoughAgreement,
    /// Nothing usable arrived at all.
    NoUsableAttestations,
}

impl QuorumState {
    /// Every state, for `--help` and error messages.
    pub const ALL: [QuorumState; 3] = [
        QuorumState::Verified,
        QuorumState::Failed,
        QuorumState::Insufficient,
    ];
}

impl ReasonCode {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ReasonCode::AgreementReached => "agreement_reached",
            ReasonCode::IrreconcilableDigests => "irreconcilable_digests",
            ReasonCode::SeatsNotFilled => "seats_not_filled",
            ReasonCode::NotEnoughAgreement => "not_enough_agreement",
            ReasonCode::NoUsableAttestations => "no_usable_attestations",
        }
    }
}

/// What the evaluator needs beyond the round: a clock, a tier floor and freshness.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// The clock. Pinned in tests and replays, `TimeUs::now()` in production.
    pub now: TimeUs,
    /// Accepted provenance tiers. A quorum of `simulated` plans is a quorum of
    /// guesses, so the default is `local` only.
    pub allowed_tiers: Vec<Tier>,
    /// Accepted sandbox backends; empty accepts any the format allows.
    pub allowed_sandboxes: Vec<String>,
    /// How old an attestation may be (ADR-0001 D6).
    pub max_age_us: i64,
    /// Clock skew allowance.
    pub max_clock_skew_us: i64,
    /// Require this normalisation version, so five machines that normalise
    /// differently cannot "agree" by normalising nothing.
    pub normalisation_version: Option<u32>,
}

impl Default for Evaluation {
    fn default() -> Self {
        Evaluation {
            now: TimeUs::now(),
            allowed_tiers: vec![Tier::Local],
            allowed_sandboxes: Vec::new(),
            max_age_us: gitiup_attest::DEFAULT_MAX_AGE_US,
            max_clock_skew_us: gitiup_attest::DEFAULT_MAX_CLOCK_SKEW_US,
            normalisation_version: None,
        }
    }
}

impl Evaluation {
    /// A fixed-clock evaluation (tests, replays, and any caller that wants the verdict
    /// to be a function of its inputs alone).
    pub fn at(now: TimeUs) -> Evaluation {
        Evaluation {
            now,
            ..Default::default()
        }
    }

    /// The per-submission attestation policy: bound to this round, this head, this
    /// verifier's challenge.
    fn attestation_policy(&self, round: &Round, key_id: &str) -> Result<gitiup_attest::Policy> {
        Ok(gitiup_attest::Policy {
            trust: Trust::KeyIds(
                round
                    .selected
                    .iter()
                    .map(|s| s.key_id.clone())
                    .collect::<std::collections::BTreeSet<String>>(),
            ),
            allowed_tiers: self.allowed_tiers.clone(),
            allowed_sandboxes: self.allowed_sandboxes.clone(),
            max_age_us: self.max_age_us,
            max_clock_skew_us: self.max_clock_skew_us,
            min_signatures: 1,
            expected_commit: Some(round.inputs.head_oid.clone()),
            expected_result_digest: None,
            expected_challenge: Some(round.challenge_for(key_id)?),
            normalisation_version: self.normalisation_version,
            now: Some(self.now),
            ..Default::default()
        })
    }
}

/// One submission's disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    /// The key that submitted.
    pub key_id: String,
    /// The principal behind it, when the roster knows the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Stable token: `not_selected`, `wrong_commit`, `bad_signature`, `revoked`,
    /// `duplicate_identity`, `arch_mismatch`, `stale`, …
    pub code: String,
    /// The sentence a human reads.
    pub detail: String,
    /// The exit code class of the underlying failure (6, 7 or 8), when there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u8>,
}

/// A result digest that at least one usable verifier produced but that did not win.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivergentResult {
    /// The `ResultDigest` somebody signed.
    pub result_digest: Digest,
    /// Who signed it.
    pub keys: Vec<String>,
}

/// A counted vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountedVote {
    /// The verifier's key id.
    pub key_id: String,
    /// The principal whose single vote this consumed.
    pub identity: String,
    /// The result it signed.
    pub result_digest: Digest,
    /// Its roster tier, for the audit ("was this quorum all one owner's boxes?").
    pub tier: crate::capability::RosterTier,
}

/// The verdict over one round, and the record of it.
///
/// Signed and stored at `refs/gitiup/verdict/<change>/<job>`, this is what a merge
/// gate (giti-kd4.5) reads: it names the round digest, the roster digest and the
/// policy digest it was computed from, so a verdict cannot quietly be re-used for a
/// different change or a different policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictRecord {
    /// Must be [`VERDICT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`VERDICT_TYPE`].
    #[serde(rename = "type")]
    pub verdict_type: String,
    /// The change this verdict is about.
    pub change_id: String,
    /// The head it was drawn against: freshness bound to the change, not to a clock
    /// alone.
    pub head_oid: GitOid,
    /// The job.
    pub job_id: String,
    /// The attempt (`0` first, `≥1` escalation).
    pub attempt: u64,
    /// Digest of the round record this was computed from.
    pub round_digest: Digest,
    /// Digest of the roster the round pinned.
    pub roster_digest: Digest,
    /// Digest of the policy that decided the thresholds.
    pub policy_digest: Digest,
    /// The state.
    pub state: QuorumState,
    /// Why, as a token.
    pub reason: ReasonCode,
    /// The same sentence in English, for a human and a log line.
    pub detail: String,
    /// The digest that was agreed, if anything was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<Digest>,
    /// Seats the round filled, and the policy's seat count.
    pub seats: usize,
    /// Distinct identities needed.
    pub required_agree: usize,
    /// Distinct identities that agreed on `result_digest`.
    pub agreeing: usize,
    /// The counted votes (the winning group), oldest-signature order.
    pub counted: Vec<CountedVote>,
    /// Usable attestations that disagreed with the winner. Evidence for giti-msi.8,
    /// and the reason a `verified` verdict can still be `disputed`.
    pub divergent: Vec<DivergentResult>,
    /// Selected keys that submitted nothing at all.
    pub missing: Vec<String>,
    /// Submissions that were refused, with the reason each was refused.
    pub rejected: Vec<Rejection>,
    /// Claimed time of this verdict.
    pub issued_at_us: i64,
    /// The owner's signature over the verdict body.
    pub signatures: Vec<SignatureEntry>,
}

impl VerdictRecord {
    /// Evaluate a round's submissions.
    ///
    /// `attestations` may be in any order: the counting order is defined here (by key
    /// id) so that two honest owners reaching the same facts print the same verdict.
    pub fn evaluate(
        round: &Round,
        roster: &Roster,
        attestations: &[AttestationDoc],
        revocations: &[Revocation],
        evaluation: &Evaluation,
    ) -> Result<VerdictRecord> {
        let policy_digest = round.inputs.policy.digest()?;
        let mut counted: Vec<CountedVote> = Vec::new();
        let mut rejected: Vec<Rejection> = Vec::new();
        let mut identity_votes: std::collections::BTreeSet<String> = Default::default();

        // Deterministic order, so "which of two submissions from one identity won"
        // is a fact and not a race.
        let mut ordered: Vec<&AttestationDoc> = attestations.iter().collect();
        ordered.sort_by_key(|doc| {
            doc.signatures
                .first()
                .map(|s| s.key_id.clone())
                .unwrap_or_default()
        });

        let seats: usize = round.selected.len();
        let required_agree = round.inputs.policy.required_agree;

        for doc in ordered {
            let (key_id, identity) = match doc.signatures.len() {
                0 => {
                    rejected.push(Rejection {
                        key_id: "<unsigned>".to_string(),
                        identity: None,
                        code: "unsigned".to_string(),
                        detail: "an attestation with no signature is not a vote".to_string(),
                        exit_code: Some(7),
                    });
                    continue;
                }
                1 => {
                    let key_id = doc.signatures[0].key_id.clone();
                    (
                        key_id.clone(),
                        roster.entry(&key_id).map(|e| e.identity.clone()),
                    )
                }
                many => {
                    rejected.push(Rejection {
                        key_id: crate::record::short_key(&doc.signatures[0].key_id),
                        identity: None,
                        code: "many_signers".to_string(),
                        detail: format!(
                            "{many} signatures on one attestation: one verifier submits one \
                             result, and pooling votes into one document is how a quorum is \
                             inflated"
                        ),
                        exit_code: Some(6),
                    });
                    continue;
                }
            };
            let entry = roster.entry(&key_id);
            let mut reject = |code: &str, detail: String, exit_code: Option<u8>| {
                rejected.push(Rejection {
                    key_id: key_id.clone(),
                    identity: identity.clone(),
                    code: code.to_string(),
                    detail,
                    exit_code,
                });
            };

            // Seats, not submissions: a reserve that ran the job has volunteered
            // information, not a vote.
            if !round.is_selected(&key_id) {
                reject(
                    "not_selected",
                    format!(
                        "{} was not selected for this round, so its result cannot be counted \
                         (a reserve waits to be promoted; it does not vote early)",
                        crate::record::short_key(&key_id)
                    ),
                    Some(6),
                );
                continue;
            }
            let Some(entry) = entry else {
                reject(
                    "not_in_roster",
                    "this key is not in the roster the round pinned".to_string(),
                    Some(6),
                );
                continue;
            };
            // One identity, one vote — even when a principal holds two seats.
            if identity_votes.contains(&entry.identity) {
                reject(
                    "duplicate_identity",
                    format!(
                        "identity {} has already cast this round's vote; a second box is a \
                         second machine, not a second vote",
                        crate::record::short_key(&entry.identity)
                    ),
                    Some(6),
                );
                continue;
            }
            // Revocation is evaluated here, now, and not remembered (D9).
            if let Some(revoked) = revocations.iter().find(|r| {
                (r.key_id == key_id || r.key_id == entry.identity)
                    && r.voids(round.inputs.roster_epoch)
            }) {
                reject(
                    "revoked",
                    format!(
                        "key revoked ({}), effective epoch {}, so this claim cannot be counted",
                        revoked.reason, revoked.effective_epoch
                    ),
                    Some(6),
                );
                continue;
            }

            // Signature, bindings, tier and freshness, with the round's own bindings.
            let attestation_policy = evaluation.attestation_policy(round, &key_id)?;
            let verdict = match doc.verify(&attestation_policy) {
                Ok(verdict) => verdict,
                Err(error) => {
                    reject(
                        rejection_code(&error),
                        error.detail().to_string(),
                        Some(error.exit_code()),
                    );
                    continue;
                }
            };

            // The capability claim is checked against the signed environment now
            // (D7): selection trusted the claim, the attestation is the receipt.
            let environment = &doc.manifest.result.environment;
            if environment.arch != round.inputs.required_capabilities.arch {
                reject(
                    "arch_mismatch",
                    format!(
                        "this box reported arch '{}' but the job requires '{}', so the seat was \
                         taken on a claim this run contradicts",
                        environment.arch, round.inputs.required_capabilities.arch
                    ),
                    Some(6),
                );
                continue;
            }
            if let Some(sandbox) = doc.manifest.result.provenance.confining_sandbox() {
                let required = &round.inputs.required_capabilities.sandboxes;
                if !required.iter().any(|s| s == sandbox) {
                    reject(
                        "sandbox_mismatch",
                        format!(
                            "the run claims sandbox '{sandbox}', which the job's requirement \
                             ({}) does not list",
                            required.join("|")
                        ),
                        Some(6),
                    );
                    continue;
                }
            }

            identity_votes.insert(entry.identity.clone());
            counted.push(CountedVote {
                key_id: key_id.clone(),
                identity: entry.identity.clone(),
                result_digest: verdict.result_digest.inner().clone(),
                tier: entry.tier,
            });
        }

        // Group by result digest. `counted` is already one vote per identity, so a
        // group's size *is* its identity count. The key is the digest's string form
        // (a map over a digest needs an order, and the hex form has one); the group
        // carries the `Digest` itself, so nothing here re-parses a digest on the way
        // back out — a parse step in a verdict is a place for a bug to live.
        let mut groups: BTreeMap<String, Vec<&CountedVote>> = BTreeMap::new();
        for vote in &counted {
            groups
                .entry(vote.result_digest.to_string())
                .or_default()
                .push(vote);
        }
        // Largest group wins. Ties break on the digest string, which keeps the outcome
        // a function of the inputs; a tie is still reported as divergence.
        let winner = groups
            .iter()
            .max_by_key(|(digest, votes)| (votes.len(), (*digest).clone()));
        let agreed: Option<Digest> =
            winner.and_then(|(_, votes)| votes.first().map(|v| v.result_digest.clone()));
        let counted_winners: Vec<CountedVote> = winner
            .map(|(_, votes)| votes.iter().map(|v| (*v).clone()).collect())
            .unwrap_or_default();
        let missing: Vec<String> = round
            .selected
            .iter()
            .filter(|seat| {
                !counted.iter().any(|v| v.key_id == seat.key_id)
                    && !rejected.iter().any(|r| r.key_id == seat.key_id)
            })
            .map(|seat| seat.key_id.clone())
            .collect();

        let agreed_string = agreed.as_ref().map(|digest| digest.to_string());
        let divergent: Vec<DivergentResult> = groups
            .iter()
            .filter(|(digest, _)| Some((*digest).as_str()) != agreed_string.as_deref())
            .map(|(_, votes)| DivergentResult {
                result_digest: votes
                    .first()
                    .expect("a group always has a member")
                    .result_digest
                    .clone(),
                keys: votes.iter().map(|v| v.key_id.clone()).collect(),
            })
            .collect();

        let (state, reason, detail) = decide(&Tally {
            agreeing: counted_winners.len(),
            groups: groups.len(),
            required_agree,
            seats,
            policy_n: round.inputs.policy.n,
            round_sufficient: round.sufficient,
            missing: missing.len(),
            rejected: rejected.len(),
            divergent: divergent.iter().map(|d| d.keys.len()).sum(),
        });

        Ok(VerdictRecord {
            schema_version: VERDICT_SCHEMA_VERSION,
            verdict_type: VERDICT_TYPE.to_string(),
            change_id: round.inputs.change_id.clone(),
            head_oid: round.inputs.head_oid.clone(),
            job_id: round.inputs.job_id.clone(),
            attempt: round.inputs.attempt,
            round_digest: round.digest()?,
            roster_digest: roster.digest()?,
            policy_digest,
            state,
            reason,
            detail,
            result_digest: agreed,
            seats,
            required_agree,
            agreeing: counted_winners.len(),
            counted: counted_winners,
            divergent,
            missing,
            rejected,
            issued_at_us: evaluation.now.as_us(),
            signatures: Vec::new(),
        })
    }

    /// The bytes the owner signs.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes for storage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// The verdict digest (over its canonical bytes).
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Sign the verdict as the owner.
    pub fn sign(&mut self, owner: &dyn Signer) -> Result<SignatureEntry> {
        let entry = crate::record::sign(VERDICT_PAYLOAD_TYPE, &self.body_bytes()?, owner)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != VERDICT_SCHEMA_VERSION || self.verdict_type != VERDICT_TYPE {
            return Err(Error::unsupported(
                "verdict",
                format!("unknown verdict type '{}'", self.verdict_type),
            ));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid("verdict", "too many signatures"));
        }
        match self.state {
            QuorumState::Verified => {
                if self.agreeing < self.required_agree || self.result_digest.is_none() {
                    return Err(Error::invalid(
                        "verdict",
                        "a verdict cannot say `verified` without the agreement it claims",
                    ));
                }
            }
            QuorumState::Failed | QuorumState::Insufficient => {
                if self.detail.is_empty() {
                    return Err(Error::invalid("verdict", "a negative verdict must say why"));
                }
            }
        }
        Ok(())
    }

    /// Verify a stored verdict: canonical bytes, structural sanity, and a trusted
    /// owner signature.
    ///
    /// Note what this does *not* do: it does not re-derive the selection or re-check
    /// the attestations. A verdict is a signed statement about a round that was
    /// checked when it was made, and the merge gate re-runs
    /// [`VerdictRecord::evaluate`] if it wants a fresh opinion (D9 rule 3).
    pub fn verify(&self, owner_trust: &Trust) -> Result<Digest> {
        self.validate()?;
        check_signatures(
            &self.signatures,
            VERDICT_PAYLOAD_TYPE,
            &self.body_bytes()?,
            owner_trust,
            "verdict",
            MAX_SIGNATURES,
        )?;
        self.digest()
    }

    /// Read from storage and check.
    pub fn from_canonical_bytes(bytes: &[u8], owner_trust: &Trust) -> Result<VerdictRecord> {
        let verdict: VerdictRecord = from_canonical_bytes(bytes)?;
        verdict.verify(owner_trust)?;
        require_same_bytes(&verdict, bytes)?;
        Ok(verdict)
    }

    /// Does this verdict say the *same thing* as `other`?
    ///
    /// Every field that states a fact about the round is compared; the two that record
    /// the *act of writing* — `issued_at_us` and `signatures` — are not, because an owner
    /// who re-runs the tally an hour later and reaches the same answer has not edited
    /// history. [`crate::store::file_verdict`] uses this to tell a harmless retry from
    /// an edit, so a verdict that differs in any way a reviewer could cite must not slip
    /// through as "the same": if a field appears in a verdict a human would quote, it
    /// belongs in this comparison.
    pub fn same_answer(&self, other: &VerdictRecord) -> bool {
        self.schema_version == other.schema_version
            && self.verdict_type == other.verdict_type
            && self.change_id == other.change_id
            && self.head_oid == other.head_oid
            && self.job_id == other.job_id
            && self.attempt == other.attempt
            && self.round_digest == other.round_digest
            && self.roster_digest == other.roster_digest
            && self.policy_digest == other.policy_digest
            && self.state == other.state
            && self.reason == other.reason
            && self.detail == other.detail
            && self.result_digest == other.result_digest
            && self.seats == other.seats
            && self.required_agree == other.required_agree
            && self.agreeing == other.agreeing
            && self.counted == other.counted
            && self.divergent == other.divergent
            && self.missing == other.missing
            && self.rejected == other.rejected
    }

    /// Does this verdict speak about `round`'s change, job and head?
    pub fn is_about(&self, round: &Round) -> bool {
        self.change_id == round.inputs.change_id
            && self.job_id == round.inputs.job_id
            && self.head_oid == round.inputs.head_oid
            && self.attempt == round.inputs.attempt
    }
}

/// The numbers `decide` works from.
#[derive(Debug, Clone)]
pub struct Tally {
    /// Distinct identities behind the largest agreeing group.
    agreeing: usize,
    groups: usize,
    required_agree: usize,
    seats: usize,
    policy_n: usize,
    round_sufficient: bool,
    missing: usize,
    rejected: usize,
    divergent: usize,
}

/// The decision, split out so the precedence is readable and testable.
///
/// Order matters, and each step is a sentence:
///
/// 1. A round that could not fill its seats is `insufficient` whatever arrived —
///    silently lowering N is the failure mode that makes a quorum look satisfied
///    while it is one honest machine wide.
/// 2. Otherwise, if some digest reached `required_agree`, it is `verified`, and any
///    divergence is recorded rather than hidden (a `verified` verdict can still be
///    `disputed`, which is giti-msi.8's input).
/// 3. Otherwise, if the usable attestations *disagree*, it is `failed`: that is a
///    fact about the change, not a shortage of volunteers.
/// 4. Otherwise it is `insufficient`: everyone who voted agrees, and there were not
///    enough of them.
pub fn decide(tally: &Tally) -> (QuorumState, ReasonCode, String) {
    let agreeing = tally.agreeing;

    if !tally.round_sufficient || tally.seats < tally.policy_n {
        return (
            QuorumState::Insufficient,
            ReasonCode::SeatsNotFilled,
            format!(
                "the round filled {} of {} seats ({} usable vote(s), {} refused, {} silent). \
                 A quorum with a seat nobody holds is one honest machine wide, so the bar is \
                 not lowered",
                tally.seats, tally.policy_n, agreeing, tally.rejected, tally.missing
            ),
        );
    }
    if agreeing >= tally.required_agree {
        let mut detail = format!(
            "{agreeing} of {} required distinct identities signed the same result digest",
            tally.required_agree
        );
        if tally.divergent > 0 {
            detail.push_str(&format!(
                "; {} attestation(s) disagreed and are recorded as divergent for escalation",
                tally.divergent
            ));
        }
        if tally.missing > 0 {
            detail.push_str(&format!(
                "; {} selected verifier(s) submitted nothing",
                tally.missing
            ));
        }
        return (QuorumState::Verified, ReasonCode::AgreementReached, detail);
    }
    if tally.groups > 1 {
        return (
            QuorumState::Failed,
            ReasonCode::IrreconcilableDigests,
            format!(
                "the verifiers produced {} different results and none reached the required {} \
                 agreeing identities (best was {}): this is disagreement, not a shortage of \
                 volunteers",
                tally.groups, tally.required_agree, agreeing
            ),
        );
    }
    (
        QuorumState::Insufficient,
        if agreeing == 0 {
            ReasonCode::NoUsableAttestations
        } else {
            ReasonCode::NotEnoughAgreement
        },
        format!(
            "{agreeing} distinct identit{} signed the same result, need {} ({} refused, {} silent)",
            if agreeing == 1 { "y" } else { "ies" },
            tally.required_agree,
            tally.rejected,
            tally.missing
        ),
    )
}

/// Map an attestation failure onto a stable rejection token.
fn rejection_code(error: &gitiup_attest::Error) -> &'static str {
    use gitiup_attest::ErrorKind;
    match error.kind() {
        ErrorKind::Signature => "bad_signature",
        ErrorKind::DigestMismatch => "binding_mismatch",
        ErrorKind::UnsupportedSchema => "unsupported_schema",
        ErrorKind::Invalid => "malformed",
        ErrorKind::Policy => {
            // Freshness and tier both arrive as policy refusals, and a reviewer
            // scanning a verdict wants to see which one it was.
            let text = error.detail();
            if text.contains("old") || text.contains("future") || text.contains("expired") {
                "stale"
            } else if text.contains("tier") {
                "tier_refused"
            } else if text.contains("sandbox") {
                "sandbox_refused"
            } else {
                "policy_refused"
            }
        }
    }
}

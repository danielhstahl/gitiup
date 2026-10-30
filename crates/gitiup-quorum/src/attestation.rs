//! A `tier: quorum` attestation — the verdict, wearing an attestation's clothes
//! ([giti-zp1.5](../../../docs/provenance-tiers.md)).
//!
//! [ADR-0001 D4](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md) reserved
//! the highest provenance tier and [the tier table](../../../docs/provenance-tiers.md)
//! made a single run incapable of claiming it: [`Provenance::check`](gitiup_attest::Provenance)
//! refuses `tier: quorum` in a run manifest, before any signature is even looked at.
//! That left the top of the ladder a hole — a tier every policy can name and nothing in
//! the workspace can ever produce. This module closes it, and closes it in exactly one
//! direction: **the only thing that can produce a quorum-tier attestation is a
//! [`VerdictRecord`]**, and the only thing that can accept one is a reader who can
//! re-derive that verdict from the round and the submissions that produced it.
//!
//! ```text
//!  round + roster + submissions + revocations
//!                     │
//!          VerdictRecord::evaluate          ← the one tally implementation
//!                     │  verified, with an agreed ResultDigest
//!        QuorumAttestation::from_verdict    ← refuses every other state
//!                     │  signed by the key that asserts it
//!          refs/attestations/<head>/<digest>
//!                     │
//!          rederive(…) ──► VerdictRecord::evaluate again, and compare
//! ```
//!
//! # What it is, and what it is not
//!
//! It is a record **about** attestations, so it does not duplicate them. It names the
//! round (`round_id`, `round_digest`), the trust root the round pinned (`roster_epoch`,
//! `roster_digest`), the rules it was tallied under (`policy_digest`), the
//! `ResultDigest` the quorum agreed on, and the seats whose votes made it a quorum —
//! each by key id, principal and roster tier. It carries **no** attestation bodies, no
//! step logs, no manifests: a reader who wants the evidence goes and fetches it from
//! the seats the record names, which is the same property that makes a verdict
//! auditable rather than merely long.
//!
//! Nor is it a *fourth* record class pretending to be new: it is the verdict the owner
//! already filed, restated at the tier a policy can ask for. `verify change` reads
//! either and reaches the same answer, and both paths go through the same
//! [`VerdictRecord::evaluate`] — the CLI and the library cannot disagree about what a
//! quorum decided because there is one function that decides it.
//!
//! # Why accepting one costs a re-derivation
//!
//! A signature proves who said something, never that it is true. A document that
//! *labels* itself `tier: quorum` costs nothing to write, so it proves nothing: the
//! only question worth asking is "does this store still contain a round, a roster and
//! a set of seat submissions that tally to what this document claims?" — and the only
//! honest answer is one computed on the spot ([`rederive`]). That is
//! [`QuorumAttestation::differences`], and it is what makes the exit-6 refusal of a
//! merely labelled one a fact about the store rather than an opinion about the bytes.

use gitiup_attest::{Digest, GitOid, MAX_SIGNATURES, SignatureEntry, Signer, Tier, Trust};
use serde::{Deserialize, Serialize};

use crate::capability::RosterTier;
use crate::error::{Error, Result};
use crate::record::{
    QUORUM_ATTESTATION_PAYLOAD_TYPE, body_bytes, canonical_bytes, check_signatures,
    from_canonical_bytes, require_same_bytes, short_key,
};
use crate::round::Round;
use crate::verdict::{Evaluation, QuorumState, ReasonCode, VerdictRecord};

/// The `type` of a quorum-tier attestation.
pub const QUORUM_ATTESTATION_TYPE: &str = "gitiup-quorum-attestation-1";
/// Schema version this crate writes.
pub const QUORUM_ATTESTATION_SCHEMA_VERSION: u32 = 1;
/// What a quorum attestation's `provenance.tier` must say. There is no way to ask for
/// any other value, and a reader refuses a document that carries one.
pub const QUORUM_TIER: Tier = Tier::Quorum;

/// The runner name this crate writes into a document it produces.
pub fn runner() -> String {
    format!("gitiup {}", env!("CARGO_PKG_VERSION"))
}

/// One seat that counted: the record names the voters, and does not copy their work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumSeat {
    /// The verifier's key id — the seat the round selected.
    pub key_id: String,
    /// The principal whose single vote this consumed.
    pub identity: String,
    /// Its roster tier, for the audit ("was this quorum one owner's rack?").
    pub tier: RosterTier,
}

/// A `tier: quorum` attestation: a signed statement that a quorum agreed on one
/// `ResultDigest` for one job of one change, at one head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumAttestation {
    /// Must be [`QUORUM_ATTESTATION_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`QUORUM_ATTESTATION_TYPE`].
    #[serde(rename = "type")]
    pub attestation_type: String,
    /// Always [`QUORUM_TIER`].
    ///
    /// A field rather than a constant precisely because it is read: the whole point of
    /// the tier vocabulary is that a policy asks for a tier by name, and a document
    /// that cannot answer the question has to be refused rather than assumed.
    pub tier: Tier,
    /// What produced it. Always this crate's own version: nothing else can produce one.
    pub runner: String,
    /// The change this attests.
    pub change_id: String,
    /// The job (matrix arm) within it.
    pub job_id: String,
    /// The attempt (`0` first, `≥ 1` escalation).
    pub attempt: u64,
    /// The head the round was drawn against — the commit binding a merge gate checks.
    pub head_oid: GitOid,
    /// The round's readable id (`kind/epoch/digest/change/job/head/job/attempt`).
    pub round_id: String,
    /// Digest of the round record the verdict was computed from.
    pub round_digest: Digest,
    /// The roster epoch the round pinned.
    pub roster_epoch: u64,
    /// Digest of that roster: the trust root, not a pointer to whatever is current.
    pub roster_digest: Digest,
    /// Digest of the selection policy that set the thresholds.
    pub policy_digest: Digest,
    /// The `ResultDigest` the quorum agreed on — the thing a gate merges on.
    pub result_digest: Digest,
    /// The state the tally reached. Only `verified` can be attested.
    pub state: QuorumState,
    /// Why, as a token.
    pub reason: ReasonCode,
    /// The same sentence in English.
    pub detail: String,
    /// Seats the round filled.
    pub seats: usize,
    /// Distinct identities the round required.
    pub required_agree: usize,
    /// Distinct identities that agreed.
    pub agreeing: usize,
    /// The seats that produced the agreed result — named, not copied.
    pub counted: Vec<QuorumSeat>,
    /// Digest of the [`VerdictRecord`] this was made from: the record it restates.
    pub verdict_digest: Digest,
    /// Claimed time, microseconds since the epoch — the verdict's own issue time.
    pub claimed_at_us: i64,
    /// Who asserted this, in the document's own words.
    pub signatures: Vec<SignatureEntry>,
}

impl QuorumAttestation {
    /// Make the attestation a verdict earns.
    ///
    /// This is the only constructor, and it refuses:
    ///
    /// * a verdict that is not `verified` — there is no quorum to attest about a
    ///   `failed` or `insufficient` round, and inventing a result digest to fill the
    ///   field would be the laundered proof this whole type exists to prevent;
    /// * a verdict that is not about `round` (change, job, attempt, head, round digest,
    ///   roster digest, policy digest all compared) — a tallied answer about one round
    ///   cannot be certified about another;
    /// * a verdict whose own numbers do not add up (`agreeing` disagrees with the votes
    ///   it counted, or the votes do not all carry the agreed digest).
    pub fn from_verdict(round: &Round, verdict: &VerdictRecord) -> Result<QuorumAttestation> {
        verdict.validate()?;
        let round_digest = round.digest()?;
        if !verdict.is_about(round) {
            return Err(Error::policy(
                "quorum attestation",
                format!(
                    "this verdict is about {}/{}/attempt {} against {}, not the round it is \
                     being attested from ({}/{}/attempt {} against {})",
                    verdict.change_id,
                    verdict.job_id,
                    verdict.attempt,
                    verdict.head_oid,
                    round.inputs.change_id,
                    round.inputs.job_id,
                    round.inputs.attempt,
                    round.inputs.head_oid
                ),
            )
            .with_hint(
                "a quorum attestation certifies the round that produced it; tally the round \
                 this verdict came from, or do not attest it",
            ));
        }
        if verdict.round_digest != round_digest {
            return Err(Error::digest_mismatch(
                "quorum attestation",
                format!(
                    "the verdict cites round {}, which is not the round it was evaluated \
                     against ({})",
                    verdict.round_digest, round_digest
                ),
            ));
        }
        if verdict.roster_digest != round.inputs.roster_digest {
            return Err(Error::digest_mismatch(
                "quorum attestation",
                format!(
                    "the verdict cites roster {}, but the round pinned {}",
                    verdict.roster_digest, round.inputs.roster_digest
                ),
            ));
        }
        if verdict.policy_digest != round.inputs.policy.digest()? {
            return Err(Error::digest_mismatch(
                "quorum attestation",
                format!(
                    "the verdict cites policy {}, but the round published {}",
                    verdict.policy_digest,
                    round.inputs.policy.digest()?
                ),
            ));
        }
        if verdict.state != QuorumState::Verified {
            return Err(Error::policy(
                "quorum attestation",
                format!(
                    "a verdict that says `{}` attests nothing: there is no agreement here to \
                     carry to the quorum tier ({})",
                    verdict.state, verdict.detail
                ),
            )
            .with_hint(
                "only a `verified` round has a `ResultDigest` the quorum agreed on; escalate \
                 (attempt + 1) or grow the pool, and do not attest the shortage",
            ));
        }
        let result_digest = verdict.result_digest.clone().ok_or_else(|| {
            Error::invalid(
                "quorum attestation",
                "a `verified` verdict with no agreed ResultDigest is a broken record",
            )
        })?;
        if verdict.agreeing != verdict.counted.len() {
            return Err(Error::invalid(
                "quorum attestation",
                format!(
                    "the verdict counts {} agreeing identities but names {} vote(s)",
                    verdict.agreeing,
                    verdict.counted.len()
                ),
            ));
        }
        if verdict
            .counted
            .iter()
            .any(|vote| vote.result_digest != result_digest)
        {
            return Err(Error::digest_mismatch(
                "quorum attestation",
                "a counted vote in this verdict certifies a different result than the one \
                 the verdict says was agreed",
            ));
        }
        Ok(QuorumAttestation {
            schema_version: QUORUM_ATTESTATION_SCHEMA_VERSION,
            attestation_type: QUORUM_ATTESTATION_TYPE.to_string(),
            tier: QUORUM_TIER,
            runner: runner(),
            change_id: verdict.change_id.clone(),
            job_id: verdict.job_id.clone(),
            attempt: verdict.attempt,
            head_oid: verdict.head_oid.clone(),
            round_id: round.inputs.round_id_display()?,
            round_digest: verdict.round_digest.clone(),
            roster_epoch: round.inputs.roster_epoch,
            roster_digest: verdict.roster_digest.clone(),
            policy_digest: verdict.policy_digest.clone(),
            result_digest,
            state: verdict.state,
            reason: verdict.reason,
            detail: verdict.detail.clone(),
            seats: verdict.seats,
            required_agree: verdict.required_agree,
            agreeing: verdict.agreeing,
            counted: verdict
                .counted
                .iter()
                .map(|vote| QuorumSeat {
                    key_id: vote.key_id.clone(),
                    identity: vote.identity.clone(),
                    tier: vote.tier,
                })
                .collect(),
            verdict_digest: verdict.digest()?,
            claimed_at_us: verdict.issued_at_us,
            signatures: Vec::new(),
        })
    }

    /// The bytes the asserting key signs.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes for storage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// The document's own digest: `sha256(canonical bytes)`, which is also its CAS key.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Sign it with the key that asserts the verdict.
    pub fn sign(&mut self, signer: &dyn Signer) -> Result<SignatureEntry> {
        let entry =
            crate::record::sign(QUORUM_ATTESTATION_PAYLOAD_TYPE, &self.body_bytes()?, signer)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Structural checks — including the two that keep this type honest about its own
    /// tier and its own numbers.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != QUORUM_ATTESTATION_SCHEMA_VERSION
            || self.attestation_type != QUORUM_ATTESTATION_TYPE
        {
            return Err(Error::unsupported(
                "quorum attestation",
                format!(
                    "unknown quorum attestation type '{}'",
                    self.attestation_type
                ),
            ));
        }
        if self.tier != QUORUM_TIER {
            return Err(Error::policy(
                "quorum attestation",
                format!(
                    "a document of this type claims tier '{}', which is not what a quorum \
                     attestation means",
                    self.tier
                ),
            )
            .with_hint(format!(
                "only a verdict may carry `tier: {}`, and only through \
                 QuorumAttestation::from_verdict",
                QUORUM_TIER
            )));
        }
        if self.state != QuorumState::Verified {
            return Err(Error::policy(
                "quorum attestation",
                format!(
                    "a quorum attestation cannot state `{}`: nothing was agreed",
                    self.state
                ),
            ));
        }
        if self.agreeing < self.required_agree || self.agreeing != self.counted.len() {
            return Err(Error::invalid(
                "quorum attestation",
                format!(
                    "the document claims {} agreeing seat(s) against a required {} and {} \
                     counted vote(s): it does not add up to its own claim",
                    self.agreeing,
                    self.required_agree,
                    self.counted.len()
                ),
            ));
        }
        if self.counted.is_empty() {
            return Err(Error::invalid(
                "quorum attestation",
                "a quorum with no named seats names nothing",
            ));
        }
        let mut keys: Vec<&str> = self
            .counted
            .iter()
            .map(|seat| seat.key_id.as_str())
            .collect();
        keys.sort_unstable();
        let distinct = keys.len();
        keys.dedup();
        if keys.len() != distinct {
            return Err(Error::invalid(
                "quorum attestation",
                "the same seat is named twice: one identity casts one vote",
            ));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid("quorum attestation", "too many signatures"));
        }
        Ok(())
    }

    /// Verify the document itself: canonical sanity, structure, and a trusted signer.
    ///
    /// This never decides whether the claim is *true* — that is [`rederive`], which
    /// needs the round and the submissions. A caller that runs this and stops has
    /// established only that someone they trust signed a well-formed sentence.
    pub fn verify(&self, trust: &Trust) -> Result<Vec<String>> {
        self.validate()?;
        check_signatures(
            &self.signatures,
            QUORUM_ATTESTATION_PAYLOAD_TYPE,
            &self.body_bytes()?,
            trust,
            "quorum attestation",
            MAX_SIGNATURES,
        )
    }

    /// Read from storage and check it, as every other record type in this crate does.
    pub fn from_canonical_bytes(bytes: &[u8], trust: &Trust) -> Result<QuorumAttestation> {
        let attestation: QuorumAttestation = from_canonical_bytes(bytes)?;
        attestation.verify(trust)?;
        require_same_bytes(&attestation, bytes)?;
        Ok(attestation)
    }

    /// Is a document these bytes, rather than a run attestation?
    ///
    /// Cheap and syntax-only by design: it is the dispatcher a reader uses before it
    /// decides which of the two attestation shapes to parse, so it must not itself
    /// refuse a document for being wrong.
    pub fn looks_like(bytes: &[u8]) -> bool {
        let Ok(value) = gitiup_attest::require_canonical(bytes) else {
            return false;
        };
        value
            .get("type")
            .and_then(|value| value.as_str())
            .is_some_and(|kind| kind == QUORUM_ATTESTATION_TYPE)
    }

    /// Every way this document fails to match the verdict a round and its submissions
    /// produce *now*, as `(check code, error)` pairs.
    ///
    /// Everything is compared, not just the first thing wrong, because the reader of a
    /// refusal wants the whole distance between the claim and the evidence: a stale
    /// `agreeing` count and a different agreed digest are two facts and not one. The
    /// digest-shaped ones are digest mismatches (exit 8, the same class a wrong-commit
    /// attestation gets); the rest are refusals (exit 6): a verdict that came out
    /// `insufficient` today is not a broken byte string, it is a claim the store no
    /// longer supports.
    pub fn differences(
        &self,
        round: &Round,
        verdict: &VerdictRecord,
    ) -> Vec<(&'static str, Error)> {
        let mut differences: Vec<(&'static str, Error)> = Vec::new();

        if !verdict.is_about(round) {
            differences.push((
                "round",
                Error::policy(
                    "quorum attestation",
                    "the verdict this store computes is about a different change, job, \
                     attempt or head than the round it was just derived from",
                ),
            ));
            return differences;
        }
        if verdict.round_digest != self.round_digest {
            differences.push((
                "digest",
                Error::digest_mismatch(
                    "quorum attestation",
                    format!(
                        "the document cites the round {}, which is not what this store \
                         derives ({})",
                        self.round_digest, verdict.round_digest
                    ),
                ),
            ));
        }
        // Who asserts a verdict is not a free question. The shape the ticket names is the
        // verdict *signed by the selector*: the key that opened the round is the one whose
        // word the round is, and anybody else copying a true statement would be putting
        // their name to a conclusion they did not reach. `rederive` already checked the
        // round's own signature against the trust roots, so all this says is that the two
        // documents were signed by the same hand.
        if !self.signatures.is_empty()
            && !self.signatures.iter().any(|mine| {
                round
                    .signatures
                    .iter()
                    .any(|theirs| theirs.key_id == mine.key_id)
            })
        {
            differences.push((
                "trust",
                Error::policy(
                    "quorum attestation",
                    "the key that signed this document did not open the round it summarises: \
                     a `tier: quorum` attestation speaks for the selector",
                )
                .with_hint(
                    "`gitiup quorum verdict --attest … --key <name>` signs with the key that \
                     tallied the round; a copy made by somebody else is not the round's answer",
                ),
            ));
        }
        if verdict.roster_digest != self.roster_digest {
            differences.push((
                "roster",
                Error::digest_mismatch(
                    "quorum attestation",
                    format!(
                        "the document cites the roster {}, which is not what this store \
                         derives ({})",
                        self.roster_digest, verdict.roster_digest
                    ),
                ),
            ));
        }
        if verdict.policy_digest != self.policy_digest {
            differences.push((
                "digest",
                Error::digest_mismatch(
                    "quorum attestation",
                    format!(
                        "the document cites the policy {}, which is not what the round \
                         publishes ({})",
                        self.policy_digest, verdict.policy_digest
                    ),
                ),
            ));
        }
        match &verdict.result_digest {
            Some(derived) if *derived != self.result_digest => differences.push((
                "result",
                Error::digest_mismatch(
                    "quorum attestation",
                    format!(
                        "the quorum agreed {derived} when re-tallied, and the document says {}",
                        self.result_digest
                    ),
                ),
            )),
            None => differences.push((
                "verdict",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "re-tallying this round produced no agreed result at all: the store \
                         now says `{}` ({})",
                        verdict.state, verdict.detail
                    ),
                )
                .with_hint(
                    "a quorum attestation is only believed while the evidence still adds up; \
                     a revocation, a stale submission or a vanished seat is why",
                ),
            )),
            Some(_) => {}
        }
        if verdict.state != self.state {
            differences.push((
                "verdict",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "the document says `{}` and the store now says `{}` ({})",
                        self.state, verdict.state, verdict.detail
                    ),
                ),
            ));
        }
        if verdict.reason != self.reason {
            differences.push((
                "verdict",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "the document's reason is `{}` and the tally now gives `{}`",
                        self.reason.as_str(),
                        verdict.reason.as_str()
                    ),
                ),
            ));
        }
        if verdict.seats != self.seats || verdict.required_agree != self.required_agree {
            differences.push((
                "verdict",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "the document says {} seats with {} required and the round says {} \
                         with {}",
                        self.seats, self.required_agree, verdict.seats, verdict.required_agree
                    ),
                ),
            ));
        }
        if verdict.agreeing != self.agreeing {
            differences.push((
                "verdict",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "the document says {} identities agreed and re-tallying agrees {}",
                        self.agreeing, verdict.agreeing
                    ),
                ),
            ));
        }
        let derived: Vec<QuorumSeat> = verdict
            .counted
            .iter()
            .map(|vote| QuorumSeat {
                key_id: vote.key_id.clone(),
                identity: vote.identity.clone(),
                tier: vote.tier,
            })
            .collect();
        if derived != self.counted {
            differences.push((
                "seats",
                Error::policy(
                    "quorum attestation",
                    format!(
                        "the seats that carry this quorum are not the seats the tally counts: \
                         the document names {}, the tally counts {}",
                        names(&self.counted),
                        names(&derived)
                    ),
                )
                .with_hint(
                    "one vote that has since been revoked, gone stale or changed its result \
                     changes who is in the quorum, and a document naming them is a document \
                     about a vote that no longer exists",
                ),
            ));
        }
        differences
    }

    /// The one error this document has against a re-derived verdict, if it has any.
    pub fn matches(&self, round: &Round, verdict: &VerdictRecord) -> Result<()> {
        match self.differences(round, verdict).into_iter().next() {
            Some((_, error)) => Err(error),
            None => Ok(()),
        }
    }
}

/// `SHA256:aaa…,SHA256:bbb…`, for a refusal that has to name seats.
fn names(seats: &[QuorumSeat]) -> String {
    if seats.is_empty() {
        return "nobody".to_string();
    }
    seats
        .iter()
        .map(|seat| short_key(&seat.key_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a re-derivation established: the round, and the verdict the store supports.
#[derive(Debug, Clone)]
pub struct Rederived {
    /// The round the attestation names, fetched and verified.
    pub round: Round,
    /// The roster the round pinned, verified under the caller's trust roots.
    pub roster_digest: Digest,
    /// The verdict [`VerdictRecord::evaluate`] just produced from the store's evidence.
    pub verdict: VerdictRecord,
}

/// Re-derive the verdict a quorum attestation claims, from the store that holds its
/// evidence.
///
/// This is the function that makes `tier: quorum` mean something. Nothing in the
/// document is believed: the round is fetched and re-verified (seats must be the ones
/// its published seed derives, under a trusted selector signature and the epoch it
/// pinned), the roster epoch is fetched and verified, every seat's submission and every
/// revocation is fetched, and [`VerdictRecord::evaluate`] — *the same one*
/// `gitiup quorum verdict` runs — is called. Then the attestation is compared against
/// the answer ([`QuorumAttestation::differences`]).
///
/// A store that cannot answer is not a pass: no round, no roster epoch, or an
/// unreachable store is a refusal (or an I/O error, which is not a verdict).
pub fn rederive(
    host: &dyn gitiup_host::Host,
    attestation: &QuorumAttestation,
    selector_trust: &Trust,
    evaluation: &Evaluation,
) -> Result<Rederived> {
    attestation.validate()?;
    let round = crate::store::round_at(
        host,
        &attestation.change_id,
        &attestation.job_id,
        attestation.attempt,
    )?
    .ok_or_else(|| {
        Error::policy(
            "quorum attestation",
            format!(
                "{} holds no round {}/{}/attempt {}, so nothing can be checked about what \
                 this document claims",
                "the store", attestation.change_id, attestation.job_id, attestation.attempt
            ),
        )
        .with_hint(
            "a tier: quorum attestation is only believed where its evidence is: point at the \
             store that ran the round (`--store`, `--remote`), or do not ask this build to \
             take the tier on faith",
        )
    })?;
    let roster = crate::store::roster_at(host, round.inputs.roster_epoch)?.ok_or_else(|| {
        Error::policy(
            "quorum attestation",
            format!(
                "the store holds no roster epoch {} for this round",
                round.inputs.roster_epoch
            ),
        )
        .with_hint("the round is only meaningful against the epoch it pinned")
    })?;
    roster.verify(
        selector_trust,
        gitiup_attest::TimeUs(evaluation.now.as_us()),
    )?;
    let facts = round.verify(selector_trust, &roster)?;
    if facts.round_digest != attestation.round_digest {
        return Err(Error::digest_mismatch(
            "quorum attestation",
            format!(
                "the round at {}/{}/attempt {} is {}, not the {} the document names",
                attestation.change_id,
                attestation.job_id,
                attestation.attempt,
                facts.round_digest,
                attestation.round_digest
            ),
        )
        .with_hint(
            "the ref moved, or the document was written against another store: a round is \
             identified by its digest for exactly this reason",
        ));
    }
    // `store::tally` so a sealed round is tallied by the sealed rules: a quorum
    // attestation about a sealed round that skipped the commitment check would be a
    // summary of an answer nobody has to stand behind.
    let revocations = crate::store::list_revocations(host, selector_trust)?;
    let verdict = crate::store::tally(host, &round, &roster, &revocations, evaluation)?;
    Ok(Rederived {
        round,
        roster_digest: facts.roster_digest,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::SelectionSecret;
    use crate::prelude::*;
    use crate::sample;

    /// A verified verdict, built the way every honest producer builds one.
    fn fixture() -> (Round, Roster, VerdictRecord) {
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let now = sample::clock();
        let roster = sample::roster_of(&owner, 7, 41);
        roster
            .verify(&trust, now)
            .expect("the fixture roster is trusted");
        let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build");
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).unwrap();
        round.sign(&owner).unwrap();
        let seats = sample::indices_of(&round);
        let docs = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
        let verdict =
            VerdictRecord::evaluate(&round, &roster, &docs, &[], &Evaluation::at(now)).unwrap();
        assert_eq!(verdict.state, QuorumState::Verified);
        (round, roster, verdict)
    }

    #[test]
    fn a_verified_verdict_makes_an_attestation_that_names_its_evidence() {
        let (round, _roster, verdict) = fixture();
        let attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        assert_eq!(attestation.tier, Tier::Quorum);
        assert_eq!(attestation.state, QuorumState::Verified);
        assert_eq!(attestation.agreeing, verdict.agreeing);
        assert_eq!(attestation.seats, verdict.seats);
        assert_eq!(attestation.result_digest, verdict.result_digest.unwrap());
        assert_eq!(attestation.round_digest, verdict.round_digest);
        assert_eq!(attestation.roster_digest, verdict.roster_digest);
        assert_eq!(attestation.roster_epoch, round.inputs.roster_epoch);
        assert_eq!(attestation.counted.len(), verdict.counted.len());
        // It names the seats; it does not copy them.
        assert!(
            attestation
                .counted
                .iter()
                .all(|seat| !seat.key_id.is_empty())
        );
        let json = serde_json::to_string(&attestation).unwrap();
        for forbidden in ["\"stdout\"", "\"steps\"", "\"manifest\"", "\"log\""] {
            assert!(
                !json.contains(forbidden),
                "a record about attestations must not carry one: {forbidden}"
            );
        }
    }

    #[test]
    fn a_round_id_is_in_the_record_and_is_the_rounds() {
        let (round, _, verdict) = fixture();
        let attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        assert_eq!(
            attestation.round_id,
            round.inputs.round_id_display().unwrap()
        );
        assert!(attestation.round_id.contains("build"));
    }

    #[test]
    fn only_a_verified_verdict_can_be_attested() {
        let (round, roster, _) = fixture();
        // Nobody votes: the verdict is `insufficient`, and there is nothing to attest.
        let empty =
            VerdictRecord::evaluate(&round, &roster, &[], &[], &Evaluation::at(sample::clock()))
                .unwrap();
        assert_eq!(empty.state, QuorumState::Insufficient);
        let error = QuorumAttestation::from_verdict(&round, &empty).unwrap_err();
        assert_eq!(error.exit_code(), 6);
        assert!(error.message().contains("insufficient"), "{error}");
    }

    #[test]
    fn a_verdict_about_another_round_is_refused() {
        let (round, _roster, verdict) = fixture();
        let mut other = round.clone();
        other.inputs.job_id = "build/matrix/other".into();
        // The round digest moves with the job, so this is caught by the binding check.
        let error = QuorumAttestation::from_verdict(&other, &verdict).unwrap_err();
        assert_eq!(error.exit_code(), 6);
        assert!(error.message().contains("not the round"), "{error}");
    }

    #[test]
    fn a_signed_document_round_trips_and_names_its_signer() {
        let (round, _, verdict) = fixture();
        let mut attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        let owner = sample::owner_key();
        attestation.sign(&owner).unwrap();
        let bytes = attestation.canonical_bytes().unwrap();
        assert!(gitiup_attest::is_canonical(&bytes));
        assert!(QuorumAttestation::looks_like(&bytes));
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let read = QuorumAttestation::from_canonical_bytes(&bytes, &trust).unwrap();
        assert_eq!(read, attestation);
        assert!(
            read.verify(&trust)
                .unwrap()
                .contains(&read.signatures[0].key_id)
        );
        // A document trusted by nobody is refused, and with a refusal's code.
        assert_eq!(read.verify(&Trust::None).unwrap_err().exit_code(), 6);
    }

    #[test]
    fn a_document_that_only_labels_itself_quorum_is_not_a_document() {
        // Take a real document and edit the numbers: the tier is still said, and the
        // claim is now nothing but the saying. Written through the canonicaliser, so
        // what is refused is the claim and not the formatting.
        let (round, _roster, verdict) = fixture();
        let honest = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        let mut value = serde_json::to_value(&honest).unwrap();
        value["agreeing"] = serde_json::json!(99);
        value["detail"] = serde_json::json!("trust me");
        let text = gitiup_attest::canon::to_value_bytes(&value).unwrap();
        assert!(QuorumAttestation::looks_like(&text));
        let liar: QuorumAttestation = from_canonical_bytes(&text).expect("it is the right shape");
        // It does not add up: the refusal is a policy refusal (6), never a pass.
        assert_eq!(liar.validate().unwrap_err().exit_code(), 6);
        // And a well-formed, unsigned claim of the tier is refused too, with the same
        // code: nobody said it, so nobody is believed.
        assert_eq!(honest.verify(&Trust::None).unwrap_err().exit_code(), 6);
        assert_eq!(honest.digest().unwrap().hex().len(), 64);
    }

    #[test]
    fn the_tier_is_not_a_field_a_writer_can_change() {
        let (round, _, verdict) = fixture();
        let mut attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        attestation.tier = Tier::Local;
        assert_eq!(attestation.validate().unwrap_err().exit_code(), 6);
        attestation.tier = Tier::Quorum;
        attestation.state = QuorumState::Failed;
        assert_eq!(attestation.validate().unwrap_err().exit_code(), 6);
    }

    #[test]
    fn a_claim_the_tally_no_longer_supports_is_a_differing_verdict() {
        let (round, roster, verdict) = fixture();
        let attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        assert!(attestation.differences(&round, &verdict).is_empty());
        assert!(attestation.matches(&round, &verdict).is_ok());

        // The same document, judged against a tally that lost its quorum: every claim
        // the store can no longer support is said, not just the first.
        let emptied =
            VerdictRecord::evaluate(&round, &roster, &[], &[], &Evaluation::at(sample::clock()))
                .unwrap();
        let differences = attestation.differences(&round, &emptied);
        assert!(differences.iter().any(|(code, _)| *code == "verdict"));
        assert!(differences.iter().any(|(code, _)| *code == "seats"));
        assert!(
            differences.iter().all(|(_, error)| error.exit_code() == 6),
            "a tally that moved is a refusal (6), not a corrupted byte string"
        );

        // A document judged against a round it is not about: one refusal, and it names
        // the round rather than listing five ways the numbers disagree.
        let mut elsewhere = round.clone();
        elsewhere.inputs.job_id = "build/matrix/other".into();
        let differences = attestation.differences(&elsewhere, &verdict);
        assert_eq!(differences.len(), 1);
        assert_eq!(differences[0].0, "round");
        assert_eq!(differences[0].1.exit_code(), 6);
    }

    #[test]
    fn a_document_signed_by_somebody_other_than_the_selector_is_refused() {
        let (round, _roster, verdict) = fixture();
        // Perfectly good bytes, a perfectly good key, and a stranger to the round: the
        // statement is true and it is still not theirs to make.
        let mut attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        attestation.sign(&sample::verifier_key(0)).unwrap();
        let codes: Vec<&str> = attestation
            .differences(&round, &verdict)
            .iter()
            .map(|(code, _)| *code)
            .collect();
        assert_eq!(codes, vec!["trust"], "{codes:?}");
        assert_eq!(
            attestation
                .matches(&round, &verdict)
                .unwrap_err()
                .exit_code(),
            6
        );

        // The key that opened the round is the one whose word the round is.
        let mut honest = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        honest.sign(&sample::owner_key()).unwrap();
        assert!(honest.differences(&round, &verdict).is_empty());
    }

    #[test]
    fn the_clock_the_attestation_carries_is_the_verdicts() {
        let (round, _, verdict) = fixture();
        let attestation = QuorumAttestation::from_verdict(&round, &verdict).unwrap();
        assert_eq!(attestation.claimed_at_us, verdict.issued_at_us);
        assert_eq!(attestation.claimed_at_us, sample::clock().as_us());
    }
}

//! Quarantine: a verdict's history, written back as a selection input
//! ([giti-zp1.8](../../../README.md),
//! [ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! Selection already accepts an exclusion set ([`RoundInputs::exclusions`](crate::select::RoundInputs)),
//! and a verdict already names every seat that diverged, was refused, or never turned up.
//! What was missing was the middle: anybody *remembering* that a key diverged twice. This
//! module is that middle — one signed record, one ref per record, and a rule about what a
//! record is allowed to be written for.
//!
//! ```text
//!  verdict (diverging · rejected)  ──► Quarantine (owner-signed, N epochs)
//!                                             │  refs/gitiup/quarantine/<slot>/<digest>
//!                                             ▼
//!                      RoundInputs::excluding(roster, named)  ──► Round (seats without it)
//!                                             │
//!  QuarantineLift (owner-signed) ─────────────┘  refs/gitiup/quarantine-lift/<slot>/<digest>
//! ```
//!
//! # Exclusion, never a roster edit
//!
//! The roster is the owner's signed trust list, and a quarantine is not a change of mind
//! about who is trusted: it is a statement about what should be *selected next*. So a
//! quarantine never touches the roster — it is applied with
//! [`RoundInputs::excluding`], the same door the proposer's family leaves by
//! ([ADR-0002 D4](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)),
//! and it appears in the round record's own `exclusions` field, where every auditor sees
//! it. Two things follow, and both are the point:
//!
//! * a published roster is never rewritten, so a quarantine cannot silently demote someone
//!   or quietly remove a vouch the owner signed;
//! * a quarantine is **prospective only**. A round that is already open keeps its seats,
//!   because voiding seats retroactively is [`Revocation`](crate::roster::Revocation)'s job,
//!   with its own reason codes and its own voids matrix — and a document that did both
//!   would make "was it stolen" and "was it wrong" the same question.
//!
//! # Silence is insufficient, not guilt
//!
//! A seat that never turned up is `missing` in the verdict, and it is **never** grounds for
//! a quarantine here: [`Quarantine::from_verdict`] refuses it at exit 6. Absence has a
//! hundred innocent causes (a box rebooted, a lease expired, a volunteer that gave up) and
//! punishing it punishes the roster into silence — the volunteer that learns "not showing
//! up gets me in trouble" learns to show up with a copied answer, which is the behaviour
//! sealing was built to catch. Absence is *scored* instead ([`crate::reputation`]) so an
//! owner can see a roster that is more theatre than capacity, and it is up to the owner to
//! decide what a roster that never answers is worth.
//!
//! The reason vocabulary enforces this rather than describing it:
//! [`QuarantineReason::parse`] refuses `absence`, `silent`, `missing`, `no_show`, `late`
//! and `timeout` by name, with the sentence that says why.
//!
//! # What a quarantine is not
//!
//! * **not a weight.** [ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)
//!   is explicit that reputation may exclude or demote and must never multiply: a score in
//!   a scoring formula is a trust anchor nobody can audit. A quarantined key is not less
//!   likely to be picked; it is not in the pool.
//! * **not a verdict.** It cites one, and the citation is checked
//!   ([`Evidence::verdict_digest`]), but it decides nothing about a change and no merge gate
//!   reads it.
//! * **not a life sentence.** `epochs` is bounded ([`MAX_QUARANTINE_EPOCHS`]) and every
//!   record carries a clock bound ([`Quarantine::expires_at_us`]) so a roster that stops
//!   publishing epochs cannot turn "three epochs" into forever.
//! * **not appealable by protocol.** There is no `gitiup quarantine appeal`, no vote and no
//!   timer. The way out is a human with an owner key running
//!   [`gitiup participant unquarantine`](../../../gitiup), and the CLI says so instead of
//!   inventing a ballot that an owner would have to override anyway.

use std::collections::BTreeSet;

use gitiup_attest::{Digest, SignatureEntry, Signer, TimeUs, Trust};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::record::{
    QUARANTINE_LIFT_PAYLOAD_TYPE, QUARANTINE_PAYLOAD_TYPE, body_bytes, canonical_bytes,
    check_signatures, from_canonical_bytes, require_key_id_shape, require_same_bytes, short_key,
};
use crate::verdict::VerdictRecord;

/// The `type` of a quarantine record.
pub const QUARANTINE_TYPE: &str = "gitiup-quarantine-1";
/// Quarantine record schema version this crate writes.
pub const QUARANTINE_SCHEMA_VERSION: u32 = 1;
/// The `type` of a record ending a quarantine early.
pub const LIFT_TYPE: &str = "gitiup-quarantine-lift-1";
/// Lift record schema version this crate writes.
pub const LIFT_SCHEMA_VERSION: u32 = 1;

/// How long a quarantine lasts when nobody says: three roster epochs.
///
/// Long enough that a key cannot serve a round, go quiet, and be back for the next one;
/// short enough that a bored owner's reflex is not a permanent exile.
pub const DEFAULT_QUARANTINE_EPOCHS: u64 = 3;
/// The longest quarantine that can be written. Past this it is a roster edit with a
/// different name, and a roster edit is exactly what this must not become.
pub const MAX_QUARANTINE_EPOCHS: u64 = 52;
/// Signature-list bound (ADR-0001 D7's work bound, as every record in this crate uses).
pub const MAX_QUARANTINE_SIGNATURES: usize = 8;

/// Why a key is quarantined, as a closed vocabulary.
///
/// Closed on purpose: the reason is the difference between a decision and a mood, and a
/// free-text reason is how "they were wrong twice" and "I do not like their owner" end up
/// in the same field. Every reason except [`QuarantineReason::OwnerDecision`] names a
/// fact a verdict already recorded, so a record can be checked against the evidence it
/// cites ([`Quarantine::from_verdict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Its result differed from the consensus a `verified` verdict reached. The reason the
    /// ticket is named for, and the only one that needs a *consensus* to exist.
    Divergence,
    /// In a sealed round it revealed bytes that do not open its own commitment: a seat
    /// that changed its mind after promising (exit 8 evidence).
    CommitmentMismatch,
    /// The capability claim its seat was taken on is contradicted by its own signed
    /// environment (`arch_mismatch`, `sandbox_mismatch`).
    CapabilityLie,
    /// Its evidence belongs to another round or another seat: `no_commitment`,
    /// `foreign_commitment`, `stale_commitment`, `wrong_round`.
    EvidenceReplay,
    /// Its own claim does not verify: `bad_signature`, `unsigned`, `many_signers`.
    BadSignature,
    /// The owner's judgement, with no automated evidence behind it. The only reason that
    /// may be written with an empty `evidence` list, and the only one that cannot be
    /// derived from a verdict — which is why it has to be typed by a human.
    OwnerDecision,
}

impl QuarantineReason {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            QuarantineReason::Divergence => "divergence",
            QuarantineReason::CommitmentMismatch => "commitment_mismatch",
            QuarantineReason::CapabilityLie => "capability_lie",
            QuarantineReason::EvidenceReplay => "evidence_replay",
            QuarantineReason::BadSignature => "bad_signature",
            QuarantineReason::OwnerDecision => "owner_decision",
        }
    }

    /// Every writable reason, for `--help` and for parsing.
    pub const ALL: [QuarantineReason; 6] = [
        QuarantineReason::Divergence,
        QuarantineReason::CommitmentMismatch,
        QuarantineReason::CapabilityLie,
        QuarantineReason::EvidenceReplay,
        QuarantineReason::BadSignature,
        QuarantineReason::OwnerDecision,
    ];

    /// The words for *absence*, which are refused rather than parsed.
    ///
    /// They are listed so the refusal can name the word the operator actually typed
    /// instead of lecturing in the abstract.
    pub const ABSENCE_WORDS: [&'static str; 8] = [
        "absence", "absent", "silent", "silence", "missing", "no_show", "late", "timeout",
    ];

    /// Parse a reason, refusing the absence vocabulary with the reason it is refused.
    pub fn parse(text: &str) -> Result<QuarantineReason> {
        let trimmed = text.trim().to_ascii_lowercase();
        if QuarantineReason::ABSENCE_WORDS.contains(&trimmed.as_str()) {
            return Err(Error::policy(
                "quarantine reason",
                format!("'{text}' is not a quarantine ground: silence is insufficient, not guilt"),
            )
            .with_hint(
                "a seat that never turned up has a hundred innocent causes, and punishing it \
                 teaches a volunteer to turn up with a copied answer. Absence is scored, not \
                 punished: `gitiup participant history` prints a key's turn-up rate, and \
                 `divergence`, `commitment_mismatch`, `capability_lie`, `evidence_replay`, \
                 `bad_signature` or `owner_decision` is what a quarantine has to be written \
                 for",
            ));
        }
        QuarantineReason::ALL
            .iter()
            .find(|reason| reason.as_str() == trimmed)
            .copied()
            .ok_or_else(|| {
                Error::invalid(
                    "quarantine reason",
                    format!("'{text}' is not a quarantine reason"),
                )
                .with_hint(format!(
                    "reasons are {}",
                    QuarantineReason::ALL
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// Whether this reason must cite a verdict to be written.
    pub fn requires_evidence(self) -> bool {
        self != QuarantineReason::OwnerDecision
    }

    /// Whether this reason is about a *divergence* and therefore needs a verdict that
    /// reached a consensus at all.
    pub fn needs_consensus(self) -> bool {
        self == QuarantineReason::Divergence
    }
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verdict rejection codes that are grounds for a quarantine, and what each means.
///
/// The list is the argument: a code is grounds when it describes something **this
/// verifier did** — its own signature, its own claim, its own commitment — and not grounds
/// when it describes something that happened *around* a submission (`not_selected`,
/// `not_in_roster`, `revoked`, `expired`, `duplicate_identity`, `wrong_commit`: a stale
/// checkout, a late revocation, a routing mistake). Those are worth a conversation and are
/// not worth an exclusion, because excluding a key for a mistake the roster made teaches
/// the wrong lesson.
pub fn reason_for_rejection(code: &str) -> Option<QuarantineReason> {
    match code {
        "commitment_mismatch" => Some(QuarantineReason::CommitmentMismatch),
        "no_commitment" | "foreign_commitment" | "stale_commitment" | "wrong_round" => {
            Some(QuarantineReason::EvidenceReplay)
        }
        "arch_mismatch" | "sandbox_mismatch" => Some(QuarantineReason::CapabilityLie),
        "bad_signature" | "unsigned" | "many_signers" => Some(QuarantineReason::BadSignature),
        _ => None,
    }
}

/// One cited verdict, and what it said about this key.
///
/// The citation is checked, not believed: [`Quarantine::from_verdict`] copies the digests
/// out of a verdict the caller has already verified, and a reader that has the verdict can
/// confirm the citation is about the round it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// The change the cited verdict is about.
    pub change_id: String,
    /// The job (matrix vector) within it.
    pub job_id: String,
    /// Which attempt of that job.
    pub attempt: u64,
    /// Digest of the cited `VerdictRecord` — the citation itself.
    pub verdict_digest: Digest,
    /// The verdict's own token for what this key did: `divergence`, or the rejection code
    /// (`commitment_mismatch`, `arch_mismatch`, …). Never a code for absence.
    pub code: String,
    /// The consensus result digest when the reason is divergence, so a reader can see what
    /// the key disagreed *with*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus: Option<Digest>,
    /// What the key signed instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theirs: Option<Digest>,
}

impl Evidence {
    /// Cite a verdict for a key that disagreed with its consensus.
    pub fn divergence(verdict: &VerdictRecord, theirs: Digest) -> Result<Evidence> {
        Ok(Evidence {
            change_id: verdict.change_id.clone(),
            job_id: verdict.job_id.clone(),
            attempt: verdict.attempt,
            verdict_digest: verdict.digest()?,
            code: "divergence".to_string(),
            consensus: verdict.result_digest.clone(),
            theirs: Some(theirs),
        })
    }

    /// Cite a verdict that refused this key's submission under `code`.
    pub fn rejection(
        verdict: &VerdictRecord,
        code: &str,
        theirs: Option<Digest>,
    ) -> Result<Evidence> {
        Ok(Evidence {
            change_id: verdict.change_id.clone(),
            job_id: verdict.job_id.clone(),
            attempt: verdict.attempt,
            verdict_digest: verdict.digest()?,
            code: code.to_string(),
            consensus: verdict.result_digest.clone(),
            theirs,
        })
    }

    /// Check the citation's shape (ids that can be named, a code that is not an absence).
    pub fn validate(&self) -> Result<()> {
        crate::store::check_segment(&self.change_id, "change id")?;
        crate::store::check_segment(&self.job_id, "job id")?;
        if self.code.trim().is_empty() {
            return Err(Error::invalid(
                "quarantine evidence",
                "an evidence row has to name the code the verdict used",
            ));
        }
        if is_absence_code(&self.code) {
            return Err(Error::policy(
                "quarantine evidence",
                format!(
                    "code '{}' is an absence, and absence is not a quarantine ground",
                    self.code
                ),
            )
            .with_hint(
                "a seat that said nothing is scored in `gitiup participant history` and \
                     is never written into a quarantine",
            ));
        }
        Ok(())
    }
}

/// Whether a code names a seat that never answered rather than something a key did.
pub fn is_absence_code(code: &str) -> bool {
    matches!(
        code.trim().to_ascii_lowercase().as_str(),
        "missing" | "silent" | "absence" | "no_show" | "late" | "timeout" | "never_arrived"
    )
}

/// An owner's decision to keep a key out of the pool for N roster epochs.
///
/// Signed by an owner and by nobody else: a quarantine is the owner's act, and a key that
/// could quarantine itself would be a volunteer that chooses its own assignments. Stored at
/// `refs/gitiup/quarantine/<slot>/<digest>` with `Expect::Absent`, so a record is never
/// edited and never replaced — a second quarantine for the same key is a second record,
/// which is what makes the audit trail a trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// Must be [`QUARANTINE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`QUARANTINE_TYPE`].
    #[serde(rename = "type")]
    pub quarantine_type: String,
    /// The key kept out. One name reaches its whole identity family, exactly as
    /// [`RoundInputs::excluding`](crate::select::RoundInputs) works, because a principal's
    /// boxes are interchangeable *to that principal* — excluding one of two and being
    /// routed to the other is not a quarantine, it is an inconvenience.
    pub key_id: String,
    /// Why, from a closed vocabulary.
    pub reason: QuarantineReason,
    /// The sentence a human reads, and the one an appeal has to answer.
    pub detail: String,
    /// First roster epoch it applies to. Rounds pinned below this epoch are untouched.
    pub start_epoch: u64,
    /// How many epochs it runs: `start_epoch .. start_epoch + epochs`.
    pub epochs: u64,
    /// The clock bound: no later than this, whatever the roster has done with its epochs
    /// ([`MAX_QUARANTINE_EPOCHS`] and a stalled roster must not combine into forever).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_us: Option<i64>,
    /// When the owner signed it.
    pub issued_at_us: i64,
    /// The owner who signed it (always the signer, never asserted).
    pub issuer: String,
    /// The verdicts this rests on. Empty only for `owner_decision`.
    pub evidence: Vec<Evidence>,
    /// Free text for the record (who raised it, which incident). Never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Owner signatures.
    pub signatures: Vec<SignatureEntry>,
}

impl Quarantine {
    /// An unsigned quarantine over `evidence`.
    ///
    /// `expires_at_us` is left `None` here: the caller decides the clock bound, because
    /// only the caller knows the roster's published epoch interval
    /// ([`Quarantine::expires_after_epochs`] does the arithmetic a CLI wants).
    pub fn new(
        key_id: impl Into<String>,
        reason: QuarantineReason,
        detail: impl Into<String>,
        start_epoch: u64,
        epochs: u64,
        now: TimeUs,
        evidence: Vec<Evidence>,
    ) -> Quarantine {
        Quarantine {
            schema_version: QUARANTINE_SCHEMA_VERSION,
            quarantine_type: QUARANTINE_TYPE.to_string(),
            key_id: key_id.into(),
            reason,
            detail: detail.into(),
            start_epoch,
            epochs,
            expires_at_us: None,
            issued_at_us: now.as_us(),
            issuer: String::new(),
            evidence,
            note: None,
            signatures: Vec::new(),
        }
    }

    /// Build the quarantine a verdict supports, and refuse the ones it does not.
    ///
    /// Where the key appears in the verdict decides the reason:
    ///
    /// | where the key is | the verdict |
    ///|------------------|-------------|
    ///| a `rejected` row with a code that names what *it* did | that code's reason |
    ///| a `divergent` row of a `verified` verdict | `divergence` |
    ///| `missing` | refused — silence is insufficient, not guilt |
    ///| a counted vote, or not mentioned at all | refused |
    ///
    /// A `failed` verdict cannot support `divergence` either: when the quorum reached no
    /// consensus there is no "eventual consensus" to have diverged from, and calling the
    /// minority wrong because the majority was louder is exactly the reasoning a quorum
    /// exists to refuse. An owner who wants to act on a failed round says so themselves with
    /// `owner_decision`.
    pub fn from_verdict(
        verdict: &VerdictRecord,
        key_id: &str,
        start_epoch: u64,
        epochs: u64,
        now: TimeUs,
    ) -> Result<Quarantine> {
        if let Some(rejection) = verdict.rejected.iter().find(|row| row.key_id == key_id) {
            let reason = reason_for_rejection(&rejection.code).ok_or_else(|| {
                Error::policy(
                    "quarantine",
                    format!(
                        "the verdict refused {} with `{}`, which is not a quarantine ground",
                        short_key(key_id),
                        rejection.code
                    ),
                )
                .with_hint(
                    "that code names something that happened around the submission — a stale \
                     checkout, a late revocation, a routing mistake — not something this key \
                     did wrong. `gitiup participant history` shows the whole record",
                )
            })?;
            let evidence =
                Evidence::rejection(verdict, &rejection.code, result_of(verdict, key_id))?;
            return Ok(Quarantine::new(
                key_id,
                reason,
                format!("{}: {}", rejection.code, rejection.detail),
                start_epoch,
                epochs,
                now,
                vec![evidence],
            ));
        }
        if verdict.missing.iter().any(|missing| missing == key_id) {
            return Err(Error::policy(
                "quarantine",
                format!(
                    "{} is `missing` from this round, and silence is insufficient, not guilt",
                    short_key(key_id)
                ),
            )
            .with_hint(
                "absence is scored, never punished: `gitiup participant history --key {}` \
                 prints its turn-up rate, and a quarantine needs a divergence or a refusal \
                 to stand on"
                    .to_string(),
            ));
        }
        if let Some(diverged) = verdict
            .divergent
            .iter()
            .find(|group| group.keys.iter().any(|key| key == key_id))
        {
            if verdict.state != crate::verdict::QuorumState::Verified {
                return Err(Error::policy(
                    "quarantine",
                    format!(
                        "this verdict is `{}`, so there is no consensus for {} to have \
                         diverged from",
                        verdict.state,
                        short_key(key_id)
                    ),
                )
                .with_hint(
                    "a minority on a round that reached no agreement is not the minority: \
                     escalate the round (`gitiup quorum retry`) or, if you really mean it, \
                     say so yourself with `--reason owner_decision`, which is signed by you \
                     rather than derived from the evidence",
                ));
            }
            return Ok(Quarantine::new(
                key_id,
                QuarantineReason::Divergence,
                format!(
                    "signed {}, the consensus was {}",
                    diverged.result_digest,
                    verdict
                        .result_digest
                        .as_ref()
                        .map(|digest| digest.to_string())
                        .unwrap_or_else(|| "nothing".to_string())
                ),
                start_epoch,
                epochs,
                now,
                vec![Evidence::divergence(
                    verdict,
                    diverged.result_digest.clone(),
                )?],
            ));
        }
        if verdict.counted.iter().any(|vote| vote.key_id == key_id) {
            return Err(Error::policy(
                "quarantine",
                format!(
                    "{}'s vote was counted with the consensus in this verdict, so this verdict \
                     is evidence for it, not against it",
                    short_key(key_id)
                ),
            )
            .with_hint("if the record you want is a different round's, cite that one"));
        }
        Err(Error::policy(
            "quarantine",
            format!(
                "this verdict says nothing about {}: it holds no seat here that this round \
                 counted, refused or missed",
                short_key(key_id)
            ),
        )
        .with_hint(
            "a quarantine cites a verdict that names the key; check the change, job and \
                    attempt you cited",
        ))
    }

    /// The epoch a quarantine stops applying at (exclusive).
    pub fn ends_epoch(&self) -> u64 {
        self.start_epoch.saturating_add(self.epochs)
    }

    /// The clock bound a CLI should write: `epochs` epoch intervals from `now`, using the
    /// interval the roster publishes (so the bound is the owner's own epoch arithmetic,
    /// not a guess at a calendar).
    pub fn expires_after_epochs(now: TimeUs, epoch_interval_us: i64, epochs: u64) -> Option<i64> {
        if epoch_interval_us <= 0 {
            return None;
        }
        let span = i64::try_from(epochs).ok()?.checked_mul(epoch_interval_us)?;
        now.as_us().checked_add(span)
    }

    /// Does this record keep `key_id` out of a round pinned to `epoch` at `now`?
    pub fn covers(&self, key_id: &str, epoch: u64, now: TimeUs) -> bool {
        self.key_id == key_id && self.covers_epoch(epoch) && self.clock_live(now)
    }

    /// The epoch arithmetic alone: `start_epoch <= epoch < start_epoch + epochs`.
    pub fn covers_epoch(&self, epoch: u64) -> bool {
        epoch >= self.start_epoch && epoch < self.ends_epoch()
    }

    /// Whether the clock bound (if any) still runs.
    pub fn clock_live(&self, now: TimeUs) -> bool {
        match self.expires_at_us {
            Some(at) => now.as_us() < at,
            None => true,
        }
    }

    /// The epochs still to run at `epoch` (`0` when it has lapsed by epoch arithmetic).
    pub fn remaining_epochs(&self, epoch: u64) -> u64 {
        self.ends_epoch()
            .saturating_sub(epoch.max(self.start_epoch))
    }

    /// The structural checks, including the ones that make the record defensible: a reason
    /// that needs evidence has some, and the epochs are a real, bounded window.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != QUARANTINE_SCHEMA_VERSION
            || self.quarantine_type != QUARANTINE_TYPE
        {
            return Err(Error::unsupported(
                "quarantine",
                format!(
                    "unknown quarantine type '{}' (schema version {})",
                    self.quarantine_type, self.schema_version
                ),
            ));
        }
        require_key_id_shape(&self.key_id, "quarantine key")?;
        if self.epochs == 0 {
            return Err(Error::invalid(
                "quarantine",
                "a quarantine of zero epochs excludes nobody and says so",
            ));
        }
        if self.epochs > MAX_QUARANTINE_EPOCHS {
            return Err(Error::policy(
                "quarantine",
                format!(
                    "{} epochs is past the {MAX_QUARANTINE_EPOCHS} maximum",
                    self.epochs
                ),
            )
            .with_hint(
                "past this it is not a quarantine, it is a roster edit with a different name \
                 — and the roster is the owner's signed trust list, which this must not \
                 become. If a key must be out for good, drop it from the next epoch \
                 (`gitiup participant approve --drop <key>`), where the removal is visible \
                 as what it is",
            ));
        }
        if self.detail.trim().is_empty() {
            return Err(Error::invalid(
                "quarantine",
                "a quarantine has to say why in a sentence an appeal can answer",
            ));
        }
        if self.reason.requires_evidence() && self.evidence.is_empty() {
            return Err(Error::policy(
                "quarantine",
                format!(
                    "reason `{}` claims a fact a verdict recorded, and cites no verdict",
                    self.reason
                ),
            )
            .with_hint(
                "cite it with --change/--job (the verdict in the store is read and checked), \
                 or use `owner_decision`, which is your judgement and asks no evidence to \
                 launder itself as a measurement",
            ));
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        if let Some(at) = self.expires_at_us
            && at <= self.issued_at_us
        {
            return Err(Error::invalid(
                "quarantine",
                "expires_at_us is before the record was signed, which is a quarantine that \
                 has already been served",
            ));
        }
        if self.signatures.len() > MAX_QUARANTINE_SIGNATURES {
            return Err(Error::invalid(
                "quarantine",
                format!(
                    "{} signatures exceeds the {MAX_QUARANTINE_SIGNATURES} limit for one record",
                    self.signatures.len()
                ),
            ));
        }
        Ok(())
    }

    /// The bytes the owner's signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what the store holds at the record's own ref.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Digest of the record — the name its ref carries and the name a lift cites.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// The hex slot the record's refs live under (a key id is hostile in a ref name).
    pub fn slot(&self) -> String {
        crate::derive::key_slot(&self.key_id)
    }

    /// Read from storage: canonical bytes, structure, and bytes-that-re-encode.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Quarantine> {
        let record: Quarantine = from_canonical_bytes(bytes)?;
        record.validate()?;
        require_same_bytes(&record, bytes)?;
        Ok(record)
    }

    /// Sign as an owner.
    ///
    /// The issuer field is set *before* the signature is made, because it is inside the
    /// body the signature covers — the same ordering a revocation uses, and for the same
    /// reason: an issuer recorded after the fact is a signature over a different record.
    pub fn sign(&mut self, owner: &dyn Signer) -> Result<SignatureEntry> {
        self.issuer = owner.key_id();
        let entry = crate::record::sign(QUARANTINE_PAYLOAD_TYPE, &self.body_bytes()?, owner)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Every signature verifies, and at least one is an owner this caller trusts.
    ///
    /// There is no "the key itself may sign this" clause the way a revocation has one:
    /// a key quarantining itself is not a check on anything, and the whole value of the
    /// record is that it is the owner's act.
    pub fn verify(&self, owner_trust: &Trust) -> Result<()> {
        self.validate()?;
        check_signatures(
            &self.signatures,
            QUARANTINE_PAYLOAD_TYPE,
            &self.body_bytes()?,
            owner_trust,
            "quarantine",
            MAX_QUARANTINE_SIGNATURES,
        )?;
        Ok(())
    }

    /// Every signature verifies, with **no** trust list.
    ///
    /// For reading a public audit trail: a quarantined key is entitled to see that it was
    /// quarantined, by whom and why, and "who is trusted" is the reader's policy, not a
    /// condition of being told. What this does guarantee is that the statement really was
    /// made by the key it names as issuer, so the audit trail cannot be forged at the store.
    pub fn verify_signatures(&self) -> Result<()> {
        self.validate()?;
        if self.signatures.is_empty() {
            return Err(Error::policy(
                "quarantine",
                "an unsigned quarantine is a rumour about a key",
            ));
        }
        let body = self.body_bytes()?;
        for entry in &self.signatures {
            crate::record::verify_one(entry, QUARANTINE_PAYLOAD_TYPE, &body)?;
        }
        if !self.signatures.iter().any(|s| s.key_id == self.issuer) {
            return Err(Error::signature(
                "quarantine",
                format!(
                    "issuer {} did not sign this quarantine of {}",
                    short_key(&self.issuer),
                    short_key(&self.key_id)
                ),
            ));
        }
        Ok(())
    }
}

impl crate::record::Record for Quarantine {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        Quarantine::from_canonical_bytes(bytes)
    }
}

/// An owner ending a quarantine before its epochs ran out.
///
/// A lift **names the record it lifts** rather than "the current quarantine": with two
/// records for one key (a divergence in May, a capability lie in September) "unquarantine
/// this key" would be a guess, and a guess about who is excluded is the thing this whole
/// module refuses to guess about. Like the quarantine it ends, a lift is append-only, and
/// it cannot rewrite a past that already held: `effective_epoch` is never earlier than the
/// record's own `start_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineLift {
    /// Must be [`LIFT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`LIFT_TYPE`].
    #[serde(rename = "type")]
    pub lift_type: String,
    /// The key whose exclusion ends. Must match the record cited.
    pub key_id: String,
    /// Digest of the [`Quarantine`] this ends — the citation that makes the act precise.
    pub quarantine_digest: Digest,
    /// First epoch the key may be selected in again.
    pub effective_epoch: u64,
    /// When the owner signed it.
    pub lifted_at_us: i64,
    /// The owner who signed it.
    pub issuer: String,
    /// Free text: who appealed, what changed. Not trusted, and the honest place to put the
    /// fact that this was a human decision rather than a computed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Owner signatures.
    pub signatures: Vec<SignatureEntry>,
}

impl QuarantineLift {
    /// An unsigned lift of `quarantine`, effective from `effective_epoch`.
    pub fn new(
        quarantine: &Quarantine,
        effective_epoch: u64,
        now: TimeUs,
        note: Option<String>,
    ) -> Result<QuarantineLift> {
        let record = QuarantineLift {
            schema_version: LIFT_SCHEMA_VERSION,
            lift_type: LIFT_TYPE.to_string(),
            key_id: quarantine.key_id.clone(),
            quarantine_digest: quarantine.digest()?,
            effective_epoch,
            lifted_at_us: now.as_us(),
            issuer: String::new(),
            note,
            signatures: Vec::new(),
        };
        record.validate_against(quarantine)?;
        Ok(record)
    }

    /// Structural checks plus the two rules that keep a lift honest about a record.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != LIFT_SCHEMA_VERSION || self.lift_type != LIFT_TYPE {
            return Err(Error::unsupported(
                "quarantine lift",
                format!(
                    "unknown lift type '{}' (schema version {})",
                    self.lift_type, self.schema_version
                ),
            ));
        }
        require_key_id_shape(&self.key_id, "quarantine lift key")?;
        if self.signatures.len() > MAX_QUARANTINE_SIGNATURES {
            return Err(Error::invalid(
                "quarantine lift",
                "too many signatures on one lift",
            ));
        }
        Ok(())
    }

    /// Check against the record it claims to end.
    pub fn validate_against(&self, quarantine: &Quarantine) -> Result<()> {
        self.validate()?;
        if self.key_id != quarantine.key_id {
            return Err(Error::policy(
                "quarantine lift",
                format!(
                    "this lift names {}, but the record it cites is about {}",
                    short_key(&self.key_id),
                    short_key(&quarantine.key_id)
                ),
            ));
        }
        if self.quarantine_digest != quarantine.digest()? {
            return Err(Error::digest_mismatch(
                "quarantine lift",
                "the quarantine digest cited is not the record's own bytes",
            ));
        }
        if self.effective_epoch < quarantine.start_epoch {
            return Err(Error::policy(
                "quarantine lift",
                format!(
                    "effective epoch {} is before the quarantine started ({})",
                    self.effective_epoch, quarantine.start_epoch
                ),
            )
            .with_hint(
                "a lift ends an exclusion from now on; it does not un-happen the epochs that \
                 already ran, because those rounds were held without this key and that is a \
                 fact about them",
            ));
        }
        Ok(())
    }

    /// Does this end `quarantine` as of `epoch`?
    pub fn lifts(&self, filed: &Filed, epoch: u64) -> bool {
        self.quarantine_digest == filed.digest
            && self.key_id == filed.quarantine.key_id
            && epoch >= self.effective_epoch
    }

    /// The bytes the signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what the store holds.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Digest of the lift record — the name its ref carries.
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// The hex slot its ref lives under (the same slot as the quarantine it ends).
    pub fn slot(&self) -> String {
        crate::derive::key_slot(&self.key_id)
    }

    /// Read from storage.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<QuarantineLift> {
        let record: QuarantineLift = from_canonical_bytes(bytes)?;
        record.validate()?;
        require_same_bytes(&record, bytes)?;
        Ok(record)
    }

    /// Sign as an owner.
    pub fn sign(&mut self, owner: &dyn Signer) -> Result<SignatureEntry> {
        self.issuer = owner.key_id();
        let entry = crate::record::sign(QUARANTINE_LIFT_PAYLOAD_TYPE, &self.body_bytes()?, owner)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Signature-verified and trusted as an owner's act.
    pub fn verify(&self, owner_trust: &Trust) -> Result<()> {
        self.validate()?;
        check_signatures(
            &self.signatures,
            QUARANTINE_LIFT_PAYLOAD_TYPE,
            &self.body_bytes()?,
            owner_trust,
            "quarantine lift",
            MAX_QUARANTINE_SIGNATURES,
        )?;
        Ok(())
    }

    /// Signature-verified, with no trust list (the public audit trail).
    pub fn verify_signatures(&self) -> Result<()> {
        self.validate()?;
        if self.signatures.is_empty() {
            return Err(Error::policy(
                "quarantine lift",
                "an unsigned lift is a rumour about a quarantine",
            ));
        }
        let body = self.body_bytes()?;
        for entry in &self.signatures {
            crate::record::verify_one(entry, QUARANTINE_LIFT_PAYLOAD_TYPE, &body)?;
        }
        if !self.signatures.iter().any(|s| s.key_id == self.issuer) {
            return Err(Error::signature(
                "quarantine lift",
                "the issuer named did not sign this lift",
            ));
        }
        Ok(())
    }
}

impl crate::record::Record for QuarantineLift {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        QuarantineLift::from_canonical_bytes(bytes)
    }
}

/// A quarantine record and the digest its ref carries.
#[derive(Debug, Clone)]
pub struct Filed {
    /// The record.
    pub quarantine: Quarantine,
    /// Digest of its canonical bytes — the citation a lift names.
    pub digest: Digest,
}

impl Filed {
    /// Pair a record with its own digest (computed once, here, rather than at every use).
    pub fn new(quarantine: Quarantine) -> Result<Filed> {
        let digest = quarantine.digest()?;
        Ok(Filed { quarantine, digest })
    }
}

/// What a store says about one key at one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing<'a> {
    /// Excluded at `epoch`: how long it runs, and what it was written for.
    Active {
        /// The record doing the excluding.
        quarantine: &'a Quarantine,
        /// The digest it is cited by.
        digest: Digest,
        /// The first epoch it no longer applies.
        ends_epoch: u64,
        /// Epochs left at `epoch`.
        remaining: u64,
    },
    /// It was quarantined and an owner ended it (early or on time).
    Lifted {
        /// The record that was lifted.
        quarantine: &'a Quarantine,
        /// The record that ended it.
        lift: &'a QuarantineLift,
    },
    /// Its N epochs ran out. Nothing after that is a punishment.
    Expired {
        /// The record that ran out.
        quarantine: &'a Quarantine,
        /// The epoch it stopped applying at.
        ends_epoch: u64,
        /// Whether the *clock* bound ended it while its epochs still ran — worth saying,
        /// because it means the roster stopped publishing epochs.
        by_clock: bool,
    },
    /// Nothing has ever been written about this key.
    Clear,
}

impl<'a> Standing<'a> {
    /// Is this key out of the pool at this epoch?
    pub fn excluded(&self) -> bool {
        matches!(self, Standing::Active { .. })
    }

    /// The record behind the standing, if any.
    pub fn quarantine(&self) -> Option<&'a Quarantine> {
        match self {
            Standing::Active { quarantine, .. }
            | Standing::Lifted { quarantine, .. }
            | Standing::Expired { quarantine, .. } => Some(quarantine),
            Standing::Clear => None,
        }
    }

    /// One line of English, for a listing and for `--json`'s `standing` field.
    pub fn describe(&self) -> String {
        match self {
            Standing::Active {
                quarantine,
                ends_epoch,
                remaining,
                ..
            } => format!(
                "quarantined for {} more epoch(s) (until epoch {ends_epoch}): {}",
                remaining, quarantine.reason
            ),
            Standing::Lifted {
                quarantine, lift, ..
            } => format!(
                "quarantined for {} ({}), lifted by {} from epoch {}",
                quarantine.reason,
                quarantine.epochs,
                short_key(&lift.issuer),
                lift.effective_epoch
            ),
            Standing::Expired {
                quarantine,
                ends_epoch,
                by_clock,
            } => format!(
                "quarantine expired at epoch {ends_epoch} ({}){}",
                quarantine.reason,
                if *by_clock {
                    " — by its clock bound, because the roster has not published the epochs"
                } else {
                    ""
                }
            ),
            Standing::Clear => "never quarantined".to_string(),
        }
    }
}

/// Every quarantine and lift one store holds, read together.
///
/// The aggregate exists because the questions are aggregate: "who is out at this epoch",
/// "is this key out", "what did the owner ever write about this key". Each answer walks
/// the records rather than consulting a cache, because there is no cache — the store is an
/// index and these records are its memory.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// Every quarantine record, each with the digest its ref carries.
    pub quarantines: Vec<Filed>,
    /// Every lift record.
    pub lifts: Vec<QuarantineLift>,
}

impl Ledger {
    /// Empty: a store that has never quarantined anybody.
    pub fn empty() -> Ledger {
        Ledger::default()
    }

    /// Validate and pair each record with its digest.
    pub fn new(quarantines: Vec<Quarantine>, lifts: Vec<QuarantineLift>) -> Result<Ledger> {
        let mut filed = Vec::with_capacity(quarantines.len());
        for record in quarantines {
            filed.push(Filed::new(record)?);
        }
        // Newest-first by (start_epoch, issued_at, digest): the ordering a listing prints
        // and the order `standing` prefers when several records speak about one key.
        filed.sort_by(|a, b| {
            b.quarantine
                .start_epoch
                .cmp(&a.quarantine.start_epoch)
                .then(b.quarantine.issued_at_us.cmp(&a.quarantine.issued_at_us))
                .then(b.digest.hex().cmp(&a.digest.hex()))
        });
        let mut lifts = lifts;
        lifts.sort_by_key(|lift| std::cmp::Reverse(lift.lifted_at_us));
        Ok(Ledger {
            quarantines: filed,
            lifts,
        })
    }

    /// Every record naming `key_id`, newest first.
    pub fn for_key(&self, key_id: &str) -> Vec<&Filed> {
        self.quarantines
            .iter()
            .filter(|filed| filed.quarantine.key_id == key_id)
            .collect()
    }

    /// The lift on `filed` that has taken effect by `epoch`, if any.
    pub fn lift_of(&self, filed: &Filed, epoch: u64) -> Option<&QuarantineLift> {
        self.lifts.iter().find(|lift| {
            lift.quarantine_digest == filed.digest
                && lift.key_id == filed.quarantine.key_id
                && epoch >= lift.effective_epoch
        })
    }

    /// What the store says about `key_id` at roster epoch `epoch`.
    pub fn standing(&self, key_id: &str, epoch: u64, now: TimeUs) -> Standing<'_> {
        let mut lifted: Option<(&Quarantine, &QuarantineLift)> = None;
        let mut expired: Option<(&Quarantine, bool)> = None;
        for filed in self.for_key(key_id) {
            let record = &filed.quarantine;
            if record.covers(key_id, epoch, now) {
                if let Some(lift) = self.lift_of(filed, epoch) {
                    return Standing::Lifted {
                        quarantine: record,
                        lift,
                    };
                }
                return Standing::Active {
                    quarantine: record,
                    digest: filed.digest.clone(),
                    ends_epoch: record.ends_epoch(),
                    remaining: record.remaining_epochs(epoch),
                };
            }
            if let Some(lift) = self.lift_of(filed, epoch) {
                lifted.get_or_insert((record, lift));
            } else if record.covers_epoch(epoch) {
                // Its epoch window still ran; only the clock bound stopped it.
                expired.get_or_insert((record, !record.clock_live(now)));
            } else if record.ends_epoch() <= epoch {
                expired.get_or_insert((record, false));
            }
        }
        match (lifted, expired) {
            (Some((quarantine, lift)), _) => Standing::Lifted { quarantine, lift },
            (None, Some((quarantine, by_clock))) => Standing::Expired {
                quarantine,
                ends_epoch: quarantine.ends_epoch(),
                by_clock,
            },
            (None, None) => Standing::Clear,
        }
    }

    /// The keys a round pinned to `epoch` must not select, as names for
    /// [`RoundInputs::excluding`](crate::select::RoundInputs).
    ///
    /// These are *names*, not the closed family: `excluding` closes each over the roster's
    /// identity families, which is where the family rule belongs and is applied exactly
    /// once.
    pub fn exclusions(&self, epoch: u64, now: TimeUs) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for filed in &self.quarantines {
            let record = &filed.quarantine;
            if record.covers_epoch(epoch)
                && record.clock_live(now)
                && self.lift_of(filed, epoch).is_none()
            {
                out.insert(record.key_id.clone());
            }
        }
        out
    }

    /// Every record in force at `epoch` (a listing's rows).
    pub fn active_at(&self, epoch: u64, now: TimeUs) -> Vec<&Filed> {
        self.quarantines
            .iter()
            .filter(|filed| {
                filed.quarantine.covers_epoch(epoch)
                    && filed.quarantine.clock_live(now)
                    && self.lift_of(filed, epoch).is_none()
            })
            .collect()
    }
}

/// The result digest a verdict would have counted for `key_id`, when it produced one.
///
/// A refused submission still *has* a result digest, and it is useful evidence in a
/// record; but the verdict only carries digests it looked at, so this returns `None`
/// rather than inventing one.
fn result_of(verdict: &VerdictRecord, key_id: &str) -> Option<Digest> {
    verdict
        .counted
        .iter()
        .find(|vote| vote.key_id == key_id)
        .map(|vote| vote.result_digest.clone())
        .or_else(|| {
            verdict
                .divergent
                .iter()
                .find(|group| group.keys.iter().any(|key| key == key_id))
                .map(|group| group.result_digest.clone())
        })
}

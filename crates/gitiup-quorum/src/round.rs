//! The round record: what the selector decided, and the proof it could not have
//! chosen otherwise ([ADR-0002 D2, D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! A round is one signed statement: *for this change, this head, this job and this
//! attempt, against roster epoch E with digest D, under policy P, the seed is S and
//! the five verifiers are these*. That is the entire advertisement — there is no
//! protocol after it. A verifier reads it, re-derives the selection from the seed it
//! can now see, and either finds its own key id in the list or goes back to sleep.
//!
//! Why the seed is published: for a verifier to learn it was selected it must read
//! something public, and a public store cannot hide the answer from the people it is
//! addressed to (D11). The secrecy budget therefore goes where it buys something —
//! nobody can compute the seed *before* publication, so nobody can pre-bribe or
//! pre-DoS a jury for a change that has not been opened yet — and the residual window
//! is met with reserves and lease expiry, not with a private channel that would
//! reintroduce the broker this design refuses.

use std::collections::BTreeSet;

use gitiup_attest::{Digest, MAX_SIGNATURES, SignatureEntry, Signer, Trust};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::record::{
    ROUND_PAYLOAD_TYPE, body_bytes, canonical_bytes, check_signatures, from_canonical_bytes,
    require_same_bytes,
};
use crate::roster::Roster;
use crate::select::{Reserve, RoundInputs, Seat, Selection};

/// The `type` of a round record.
pub const ROUND_RECORD_TYPE: &str = "gitiup-round-record-1";
/// The schema version this crate writes.
pub const ROUND_SCHEMA_VERSION: u32 = 1;

/// The default reveal mode: the selection is public from advertisement onward, and a
/// seat publishes its attestation and nothing before it.
pub const REVEAL_MODE_OPEN: &str = "open";
/// Commit-reveal submission ([giti-zp1.6](../../../README.md)): every seat publishes
/// `H(attestation bytes ‖ slot ‖ challenge)` before it publishes the bytes, and a reveal
/// that does not open its commitment is refused and counted against the seat.
///
/// What the mode is *not* is worth saying here, because the name invites the wrong
/// guess: sealing buys **independence between the seats**, not secrecy from the store. The
/// round record publishes the seed and the selection, so the seats are public from
/// advertisement onward either way ([ADR-0002 D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)),
/// and everything a sealed round contains is readable by anyone who can read the store
/// once the round closes. See [`crate::commit`] and
/// [docs/quorum.md](../../../docs/quorum.md).
pub const REVEAL_MODE_SEALED: &str = "sealed";

/// Every reveal mode this build can enforce.
///
/// A mode outside this list is a refusal, never a downgrade to `open`: a rule you cannot
/// check is a rule that must not be voted under.
pub const REVEAL_MODES: [&str; 2] = [REVEAL_MODE_OPEN, REVEAL_MODE_SEALED];

/// A published round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round {
    /// Must be [`ROUND_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`ROUND_RECORD_TYPE`].
    #[serde(rename = "type")]
    pub round_type: String,
    /// The inputs: what was asked for, under which roster and policy.
    pub inputs: RoundInputs,
    /// The published seed. The selector did not choose it (D2), and now everybody can
    /// check that.
    pub seed: Digest,
    /// Digest of the policy, repeated for convenience: a reviewer should not have to
    /// re-canonicalise a nested object to see which rules produced a quorum.
    pub policy_digest: Digest,
    /// `"open"` in v1. An unknown value is a refusal: a mode this build cannot
    /// enforce is a mode it must not vote under.
    pub reveal_mode: String,
    /// How many roster entries were eligible (the audit's denominator).
    pub eligible: usize,
    /// Whether `n` seats were filled. `false` means the round is `Insufficient`
    /// before a single job runs (D3: Insufficient is a verdict, not a shrug).
    pub sufficient: bool,
    /// The selected verifiers, in score order.
    pub selected: Vec<Seat>,
    /// The reserve order, as advice (promotion is the re-run).
    pub reserves: Vec<Reserve>,
    /// The attempt this one escalates from, and the evidence it replaces (giti-zp1.7).
    ///
    /// `None` on a first attempt. The superseded round is never edited or deleted — it
    /// stays at its own ref with its reveals, commitments and verdict — and this field is
    /// what makes the chain readable from the records: an escalation that nobody can trace
    /// back to the disagreement that caused it is a rerun, and a rerun is what a flaky test
    /// eats a roster's afternoon for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_from: Option<Escalation>,
    /// The selector's signature over the record's body.
    pub signatures: Vec<SignatureEntry>,
}

/// One round's pointer at the attempt it replaces (giti-zp1.7).
///
/// A digest and a sentence, not a copy: the evidence it refers to is already in the store,
/// and duplicating it here would be a second copy of the thing for somebody to disagree
/// about. `reason` is the one word of prose, because a chain of rounds that does not say
/// *why* it grew is indistinguishable from a loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    /// The attempt number it replaces. Always exactly one less than this round's: attempts
    /// are dense, the way roster epochs are, so "attempt 4 exists" answers "were there
    /// three before it" without a search.
    pub from_attempt: u64,
    /// The round record it replaces, by digest.
    pub from_round_digest: Digest,
    /// The verdict that prompted it, when one was filed. Optional because a round can be
    /// escalated before anybody tallied it — an unfilled round is escalated on its own
    /// `sufficient: false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_verdict_digest: Option<Digest>,
    /// Why, in the selector's words: usually the tally's own sentence
    /// (`irreconcilable_digests: …`), and required, because "again" is not a reason.
    pub reason: String,
}

impl Escalation {
    /// A new escalation record naming what it replaces.
    pub fn new(
        from: &Round,
        from_verdict_digest: Option<Digest>,
        reason: impl Into<String>,
    ) -> Result<Escalation> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(Error::invalid(
                "escalation",
                "an escalation has to say why the last attempt was not enough",
            ));
        }
        Ok(Escalation {
            from_attempt: from.inputs.attempt,
            from_round_digest: from.digest()?,
            from_verdict_digest,
            reason,
        })
    }

    /// Is this a reason a person could read two months from now?
    fn validate(&self, attempt: u64) -> Result<()> {
        if self.reason.trim().is_empty() {
            return Err(Error::invalid(
                "escalation",
                "an escalation has to say why the last attempt was not enough",
            ));
        }
        if self.from_attempt.saturating_add(1) != attempt {
            return Err(Error::invalid(
                "escalation",
                format!(
                    "this round is attempt {attempt} and points at attempt {}; attempts are \
                     dense, so the only round one may escalate from is the one before it",
                    self.from_attempt
                ),
            )
            .with_hint(
                "escalate `gitiup quorum retry`, which opens attempt + 1 from the highest \
                 attempt the store holds; a gap would mean an attempt nobody has the evidence \
                 for",
            ));
        }
        Ok(())
    }
}

/// What a verified round established, for the caller that has to record it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundFacts {
    /// Digest over the canonical record bytes.
    pub round_digest: Digest,
    /// Digest of the roster this round pins.
    pub roster_digest: Digest,
    /// Which selector keys authorised it.
    pub selectors: Vec<String>,
    /// The recomputed selection (identical to the published one, by construction of
    /// [`Round::verify`]).
    pub selection: Selection,
}

impl Round {
    /// Open a round: derive the seed and the selection, unsigned.
    pub fn open(
        inputs: &RoundInputs,
        roster: &Roster,
        secret: &crate::derive::SelectionSecret,
    ) -> Result<Round> {
        let selection = Selection::select(roster, inputs, secret)?;
        Round::from_selection(inputs, &selection)
    }

    /// Open a round in [`REVEAL_MODE_SEALED`]: the same selection, and every seat must
    /// commit before it reveals ([`crate::commit`]).
    pub fn open_sealed(
        inputs: &RoundInputs,
        roster: &Roster,
        secret: &crate::derive::SelectionSecret,
    ) -> Result<Round> {
        let selection = Selection::select(roster, inputs, secret)?;
        Round::from_selection_in(inputs, &selection, REVEAL_MODE_SEALED)
    }

    /// Build the record around an already-derived selection (the selector's path when
    /// it wants the audit table first).
    pub fn from_selection(inputs: &RoundInputs, selection: &Selection) -> Result<Round> {
        Round::from_selection_in(inputs, selection, REVEAL_MODE_OPEN)
    }

    /// Build the record around an already-derived selection, in a chosen reveal mode.
    ///
    /// The mode goes in before the record is validated, so a mode this build cannot
    /// enforce is refused at the point the round is made rather than at the point
    /// somebody volunteers for it.
    pub fn from_selection_in(
        inputs: &RoundInputs,
        selection: &Selection,
        reveal_mode: &str,
    ) -> Result<Round> {
        selection.validate()?;
        if selection.policy_digest != inputs.policy.digest()? {
            return Err(Error::digest_mismatch(
                "round",
                "this selection was produced under a different policy digest",
            ));
        }
        let round = Round {
            schema_version: ROUND_SCHEMA_VERSION,
            round_type: ROUND_RECORD_TYPE.to_string(),
            inputs: inputs.clone(),
            seed: selection.seed.clone(),
            policy_digest: selection.policy_digest.clone(),
            reveal_mode: reveal_mode.to_string(),
            eligible: selection.eligible,
            sufficient: selection.sufficient,
            selected: selection.selected.clone(),
            reserves: selection.reserves.clone(),
            escalated_from: None,
            signatures: Vec::new(),
        };
        round.validate()?;
        Ok(round)
    }

    /// Point this round at the attempt it replaces, before anything signs it.
    ///
    /// Refused once the record is signed, exactly as [`Round::set_reveal_mode`] is: the
    /// reference is inside what the selector signs, so adding it afterwards would be editing
    /// a signed record — and a round that could gain a justification after the fact is a
    /// round whose escalation was never justified.
    pub fn set_escalation(&mut self, from: &Escalation) -> Result<()> {
        if !self.signatures.is_empty() {
            return Err(Error::invalid(
                "round",
                format!(
                    "this round is signed; its escalation is inside what {} signed, so \
                     pointing it at a different attempt means re-deriving and re-signing it",
                    crate::record::short_key(&self.signatures[0].key_id)
                ),
            ));
        }
        from.validate(self.inputs.attempt)?;
        self.escalated_from = Some(from.clone());
        self.validate()
    }

    /// Restate the reveal mode, before anything signs the record.
    ///
    /// Refused once the round is signed: the mode is inside the body a selector's
    /// signature covers, so editing it afterwards is editing a signed record.
    pub fn set_reveal_mode(&mut self, reveal_mode: &str) -> Result<()> {
        if !self.signatures.is_empty() {
            return Err(Error::invalid(
                "round",
                format!(
                    "this round is signed; its reveal mode is inside what {} signed, so \
                     changing it means re-deriving and re-signing the round, not editing it",
                    crate::record::short_key(&self.signatures[0].key_id)
                ),
            ));
        }
        self.reveal_mode = reveal_mode.to_string();
        self.validate()
    }

    /// Structural checks, including the ones that stop a v2 record being read as v1.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != ROUND_SCHEMA_VERSION {
            return Err(Error::unsupported(
                "round",
                format!(
                    "round schema_version {} is not understood",
                    self.schema_version
                ),
            ));
        }
        if self.round_type != ROUND_RECORD_TYPE {
            return Err(Error::unsupported(
                "round",
                format!("unknown round record type '{}'", self.round_type),
            ));
        }
        if !REVEAL_MODES.contains(&self.reveal_mode.as_str()) {
            return Err(Error::unsupported(
                "round",
                format!(
                    "reveal mode '{}' is not implemented by this build",
                    self.reveal_mode
                ),
            )
            .with_hint(format!(
                "this build implements \"{REVEAL_MODE_OPEN}\" and \"{REVEAL_MODE_SEALED}\"; a \
                 mode it cannot enforce is refused rather than quietly read as \"{REVEAL_MODE_OPEN}\", \
                 because a rule you cannot check is a rule you can be cheated under"
            )));
        }
        self.inputs.validate()?;
        if self.policy_digest != self.inputs.policy.digest()? {
            return Err(Error::digest_mismatch(
                "round",
                "the published policy digest is not the digest of the published policy",
            ));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid(
                "round",
                format!("{} signatures exceeds the limit", self.signatures.len()),
            ));
        }
        let ranks: Vec<u32> = self.selected.iter().map(|s| s.rank).collect();
        if ranks.iter().enumerate().any(|(i, r)| *r != (i + 1) as u32) {
            return Err(Error::invalid(
                "round",
                "seat ranks must be 1..=n with no gaps",
            ));
        }
        if let Some(escalation) = &self.escalated_from {
            escalation.validate(self.inputs.attempt)?;
        }
        Ok(())
    }

    /// The bytes a selector signature covers.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes(self)
    }

    /// Canonical bytes: what goes into `kv/round/<hex>` and what `round_digest` is.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// The record digest, recorded by verdicts so a verdict names the round it drew
    /// its conclusions from rather than "the current round".
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Read a round from storage and check its bytes are the canonical encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Round> {
        let round: Round = from_canonical_bytes(bytes)?;
        round.validate()?;
        require_same_bytes(&round, bytes)?;
        Ok(round)
    }

    /// Sign as the selector.
    pub fn sign(&mut self, selector: &dyn Signer) -> Result<SignatureEntry> {
        let entry = crate::record::sign(ROUND_PAYLOAD_TYPE, &self.body_bytes()?, selector)?;
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry.clone());
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(entry)
    }

    /// Re-derive the selection this round *must* contain, from the published seed.
    ///
    /// This is the auditor's path and the verifier's step 4 (D11): no secret needed,
    /// because the seed is in the record.
    pub fn selection(&self, roster: &Roster) -> Result<Selection> {
        Selection::with_seed(roster, &self.inputs, self.seed.clone())
    }

    /// Re-run this round with more exclusions — the only legitimate way to fill a
    /// voided seat (D3). The seed does not change, so the ordering does not either.
    pub fn promote(&self, roster: &Roster, voided: &BTreeSet<String>) -> Result<Selection> {
        Selection::promote(roster, &self.inputs, self.seed.clone(), voided)
    }

    /// Re-check a published round against its own inputs, without deciding who to trust.
    ///
    /// This is the half of [`Round::verify`] that needs no trust root: the record's
    /// structure, the roster pin, and the rule that *the seats it publishes are the
    /// seats its seed derives*. A stranger auditing a selection they were not invited to
    /// has the round, the roster and the seed and nobody's signature, and this is the
    /// check that makes their answer mean something.
    pub fn verify_selection(&self, roster: &Roster) -> Result<Selection> {
        self.validate()?;
        let selection = self.selection(roster)?;
        if let Err(diff) = published_matches(&self.selected, &selection.selected) {
            return Err(Error::digest_mismatch("round", diff).with_hint(
                "the published selection must be the derived one; a round whose seats were \
                 edited is not a selection, it is a wish",
            ));
        }
        if self.eligible != selection.eligible || self.sufficient != selection.sufficient {
            return Err(Error::digest_mismatch(
                "round",
                format!(
                    "the record says {} eligible and sufficient={}, recomputation says {} and {}",
                    self.eligible, self.sufficient, selection.eligible, selection.sufficient
                ),
            ));
        }
        Ok(selection)
    }

    /// Verify a round: structurally sound, signed by a trusted selector, and *the
    /// selection it publishes is the one its own inputs derive*.
    ///
    /// The last part is what makes the record evidence rather than an assertion: a
    /// selector that published a hand-picked five gets exit 8 here, and so does one
    /// whose roster quietly changed since.
    pub fn verify(&self, selector_trust: &Trust, roster: &Roster) -> Result<RoundFacts> {
        let selection = self.verify_selection(roster)?;
        let selectors = check_signatures(
            &self.signatures,
            ROUND_PAYLOAD_TYPE,
            &self.body_bytes()?,
            selector_trust,
            "round",
            MAX_SIGNATURES,
        )?;
        Ok(RoundFacts {
            round_digest: self.digest()?,
            roster_digest: roster.digest()?,
            selectors,
            selection,
        })
    }

    /// Must every seat commit before it reveals? (`reveal_mode = "sealed"`.)
    pub fn is_sealed(&self) -> bool {
        self.reveal_mode == REVEAL_MODE_SEALED
    }

    /// The seat occupied by `key_id`, if it has one.
    pub fn seat(&self, key_id: &str) -> Option<&Seat> {
        self.selected.iter().find(|s| s.key_id == key_id)
    }

    /// Was `key_id` selected for this round? (A reserve is *not* selected: it waits.)
    pub fn is_selected(&self, key_id: &str) -> bool {
        self.seat(key_id).is_some()
    }

    /// The challenge this key must sign into `claims.verifier_challenge`.
    ///
    /// Derived from the seed and the key, so it is unforgeable-by-luck, distinct per
    /// verifier and per round, and checkable by the owner without any state: an
    /// attestation from a key selected in *another* round fails this and cannot be
    /// replayed into this one.
    pub fn challenge_for(&self, key_id: &str) -> Result<Digest> {
        if !self.is_selected(key_id) {
            return Err(Error::policy(
                "round",
                format!(
                    "{} holds no seat in this round, so there is no challenge to hand out",
                    crate::record::short_key(key_id)
                ),
            ));
        }
        let seed = seed_bytes(&self.seed)?;
        Ok(crate::derive::challenge(&seed, key_id))
    }

    /// The selector keys listed as owners of a store: the default selector is the
    /// roster signer, so a caller usually passes the same trust to
    /// [`Roster::verify`](crate::roster::Roster::verify) and here.
    pub fn trust_from_ids<I, S>(ids: I) -> Trust
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Trust::KeyIds(ids.into_iter().map(Into::into).collect())
    }
}

/// Compare a published seat list with a recomputed one.
fn published_matches(published: &[Seat], derived: &[Seat]) -> std::result::Result<(), String> {
    if published.len() != derived.len() {
        return Err(format!(
            "the record publishes {} seats, recomputation derives {}",
            published.len(),
            derived.len()
        ));
    }
    for (mine, theirs) in published.iter().zip(derived.iter()) {
        if mine.key_id != theirs.key_id {
            return Err(format!(
                "seat {} is {} in the record but {} on recomputation",
                mine.rank,
                crate::record::short_key(&mine.key_id),
                crate::record::short_key(&theirs.key_id)
            ));
        }
        if mine.slot != theirs.slot || mine.handle != theirs.handle {
            return Err(format!(
                "seat {} ({}) carries a slot or handle that the seed does not derive",
                mine.rank,
                crate::record::short_key(&mine.key_id)
            ));
        }
    }
    Ok(())
}

/// The raw 32 seed bytes.
fn seed_bytes(seed: &Digest) -> Result<[u8; 32]> {
    seed.as_bytes()
        .try_into()
        .map_err(|_| Error::invalid("round", "a round seed is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capabilities, Requirements, RosterTier};
    use crate::roster::{EpochWindow, RosterEntry};
    use gitiup_attest::{GitOid, SigningKey, TimeUs};

    const T0: i64 = 1_792_771_200_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32])
    }

    fn entry(k: &SigningKey, tier: RosterTier) -> RosterEntry {
        RosterEntry {
            key_id: k.public_key().key_id(),
            public_key: k.public_key().to_openssh(),
            identity: k.public_key().key_id(),
            tier,
            capabilities: Capabilities {
                arch: vec!["x86_64".into()],
                ram_mb: 32768,
                disk_mb: 524288,
                image_cache: vec![],
                can_pull: true,
                sandboxes: vec!["docker".into()],
                sandbox_level: 2,
            },
            epochs_valid: EpochWindow::open_from(1),
            self_signature: None,
        }
    }

    fn signed_roster(owner: &SigningKey, count: usize) -> Roster {
        let entries: Vec<RosterEntry> = (0..count as u8)
            .map(|i| {
                let mut e = entry(&key(20 + i), RosterTier::Endorsed);
                e.sign(&key(20 + i)).unwrap();
                e
            })
            .collect();
        let mut roster =
            Roster::new(7, Digest::sha256(b"prev"), T0, 604_800_000_000, entries).unwrap();
        roster.sign(owner).unwrap();
        let _ = TimeUs(T0);
        roster
    }

    /// A policy whose caps are wide enough that the fixture's twelve identical
    /// `endorsed` boxes can actually fill five seats. The default caps are a policy
    /// statement, not a test fixture: this file is about rounds, not caps.
    fn permissive() -> crate::select::SelectionPolicy {
        crate::select::SelectionPolicy {
            tier_caps: [("endorsed", 5), ("trusted", 5), ("anonymous", 5)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            ..Default::default()
        }
    }

    fn inputs(roster: &Roster) -> RoundInputs {
        RoundInputs {
            schema_version: crate::select::SELECTION_SCHEMA_VERSION,
            kind: None,
            round_kind: crate::derive::ROUND_KIND.to_string(),
            roster_epoch: roster.epoch,
            roster_digest: roster.digest().unwrap(),
            change_id: "chg-1".into(),
            head_oid: GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
            job_id: "build/matrix/linux-x86_64".into(),
            attempt: 0,
            required_capabilities: Requirements {
                arch: "x86_64".into(),
                ram_mb: 8192,
                disk_mb: 51200,
                image_digests: vec![],
                sandboxes: vec!["docker".into()],
                min_sandbox_level: 1,
            },
            exclusions: Default::default(),
            policy: permissive(),
        }
    }

    #[test]
    fn a_round_round_trips_and_verifies_against_its_roster() {
        let owner = key(1);
        let roster = signed_roster(&owner, 6);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        round.sign(&owner).unwrap();
        let bytes = round.canonical_bytes().unwrap();
        assert!(gitiup_attest::is_canonical(&bytes));
        let read = Round::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read, round);
        let facts = read.verify(&trust, &roster).unwrap();
        assert_eq!(facts.selection.selected.len(), 5);
        assert!(facts.selection.sufficient);
        assert_eq!(facts.roster_digest, roster.digest().unwrap());
        assert_eq!(facts.selectors, vec![owner.public_key().key_id()]);
        // Every selected verifier can be handed a challenge, and a non-selected key
        // cannot be.
        for seat in &read.selected {
            assert_eq!(
                read.challenge_for(&seat.key_id).unwrap(),
                read.challenge_for(&seat.key_id).unwrap()
            );
        }
        let outsider = key(99).public_key().key_id();
        assert!(read.challenge_for(&outsider).is_err());
    }

    #[test]
    fn edited_seats_are_a_digest_mismatch() {
        let owner = key(2);
        let roster = signed_roster(&owner, 7);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        round.sign(&owner).unwrap();
        // Swap the last seat for somebody else: the signature still covers the body,
        // so the recomputation is what catches it.
        let outsider = roster.entries[6].key_id.clone();
        round.selected.last_mut().unwrap().key_id = outsider;
        let err = round.verify(&trust, &roster).unwrap_err();
        assert_eq!(err.exit_code(), 8);
        assert!(err.to_string().contains("recomputation"), "{err}");
    }

    #[test]
    fn an_untrusted_selector_is_refused() {
        let owner = key(3);
        let stranger = key(4);
        let roster = signed_roster(&owner, 6);
        let secret = crate::derive::SelectionSecret::from_signing_key(&stranger);
        let mut round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        round.sign(&stranger).unwrap();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let err = round.verify(&trust, &roster).unwrap_err();
        assert_eq!(err.exit_code(), 6);
    }

    #[test]
    fn a_round_pinned_to_another_roster_is_refused() {
        let owner = key(5);
        let roster = signed_roster(&owner, 6);
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        round.sign(&owner).unwrap();
        // The same epoch number with different content: the pin is a digest, so this
        // is a different roster and the round no longer describes it.
        let other = {
            let mut r = signed_roster(&owner, 7);
            r.epoch = roster.epoch;
            r
        };
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let err = round.verify(&trust, &other).unwrap_err();
        assert_eq!(err.exit_code(), 8, "{err}");
    }

    #[test]
    fn promotion_keeps_the_seed_and_only_changes_the_pool() {
        let owner = key(6);
        let roster = signed_roster(&owner, 6);
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        let voided = round.selected[0].key_id.clone();
        let after = round
            .promote(&roster, &[voided.clone()].into_iter().collect())
            .unwrap();
        assert_eq!(after.seed, round.seed);
        assert!(!after.selected.iter().any(|s| s.key_id == voided));
        assert_eq!(after.selected.len(), 5, "a reserve fills the voided seat");
    }

    #[test]
    fn an_unimplemented_reveal_mode_is_refused_rather_than_downgraded() {
        let owner = key(7);
        let roster = signed_roster(&owner, 6);
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        // `sealed` is implemented (giti-zp1.6), so the refusal is demonstrated with a
        // mode this build genuinely cannot enforce: the hazard is identical, and the
        // point of the check is that *nothing* outside `REVEAL_MODES` is read as `open`.
        round.reveal_mode = "commit-reveal-v2".into();
        let err = round.validate().unwrap_err();
        assert!(err.to_string().contains("commit-reveal-v2"), "{err}");
        assert_eq!(err.exit_code(), 6, "{err}");
    }

    #[test]
    fn a_sealed_round_is_the_same_round_with_a_different_promise() {
        let owner = key(8);
        let roster = signed_roster(&owner, 6);
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let secret = crate::derive::SelectionSecret::from_signing_key(&owner);
        let open = Round::open(&inputs(&roster), &roster, &secret).unwrap();
        let mut sealed = Round::open_sealed(&inputs(&roster), &roster, &secret).unwrap();
        // Same seed, same seats: sealing changes what a seat must do, not who is picked.
        assert_eq!(sealed.seed, open.seed);
        assert_eq!(sealed.selected, open.selected);
        assert!(sealed.is_sealed() && !open.is_sealed());
        assert_ne!(
            sealed.digest().unwrap(),
            open.digest().unwrap(),
            "and the mode is part of what the round digest identifies, so a sealed round is \
             not the same round as an open one"
        );
        sealed.sign(&owner).unwrap();
        sealed
            .verify(&trust, &roster)
            .expect("a sealed round verifies");
        // The mode is inside the signature: editing it after the fact is refused.
        assert!(sealed.set_reveal_mode(REVEAL_MODE_OPEN).is_err());
    }
}

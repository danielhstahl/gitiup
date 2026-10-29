//! `gitiup-quorum` — the optional quorum verification network
//! ([epic giti-msi](../../../README.md), decided in
//! [ADR-0002](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! For each change, N registered participants (five by default) are chosen, run the
//! workflows independently in their own sandboxes, and sign the resulting `RunDigest`.
//! The owner trusts the result if enough signed digests agree. **Both halves are
//! opt-in**: running a verifier is a volunteer's choice ([`participate`]), requiring a
//! quorum is an owner's choice ([`verdict`]), and neither changes what a plain local run
//! produces.
//!
//! ```text
//!  gitiup participant register ─┐
//!                               │ (owner's decision, once per epoch)
//!                               ▼
//!                        Roster (signed epoch) ─────────┐
//!                                                       │ pins epoch + digest
//!  gitiup change submit ──► RoundInputs ──► Round ──────┤
//!         (owner/selector: seed = HMAC(inputs))        │
//!                               │                       │
//!              selection = order ∘ caps (auditable)    │
//!                               ▼                       ▼
//!                     five volunteers ──► attestations (one per slot, CAS)
//!                               │
//!                               ▼
//!                    VerdictRecord: verified / failed / insufficient
//! ```
//!
//! # The risks this crate is built to design out, not document away
//!
//! | risk | the mechanism that closes it | here |
//!|------|---------------------------|------|
//!| targeted verifier / selection bias | the seed is a keyed hash of the round inputs, so the pick is derived, published and re-derivable by a stranger | [`derive`], [`select`], [`Round::verify`] |
//!| copycat verifiers | the round publishes slots per key and the attestation is bound to a per-key challenge, which is the piece commit-reveal (giti-msi.6) needs | [`Round::challenge_for`], [`store::publish_submission`] |
//!| sybils and ballot stuffing | membership costs an owner signature, one *identity* casts one vote, the proposer's family is excluded, and caps limit each tier | [`roster`], [`capability`], [`verdict`] |
//!| stale or replayed attestations | freshness is bound to the change's head oid, the round's challenge, and roster revocation evaluated at verdict time | [`Evaluation`], [`Revocation::voids`] |
//!| roster rollback | epochs are monotone and pinned per round, and a verifier remembers the highest epoch a store has offered | [`Roster::next_epoch`], [`RosterLedger`] |
//!
//! # What is *not* here
//!
//! * **no sandbox** — what a volunteer's run may reach is `giti-bgy.*`; [`serve_once`]
//!   takes a `produce` callback and cannot run anything itself;
//! * **no network client** — the store is a [`gitiup_host::Host`] trait object, so the
//!   fs host in a test and the bucket-as-forge in production take the same code path;
//! * **no coordinator** — there is no daemon, no queue and no broker in this crate; a
//!   round is a signed record, and a submission is a CAS write;
//! * **no key store** — keys are giti-1rs.6; everything here takes a
//!   [`gitiup_attest::Signer`].
//!
//! # The acceptance criterion, in one example
//!
//! Five volunteers, one change, one verdict:
//!
//! ```
//! use gitiup_quorum::prelude::*;
//! use gitiup_quorum::{sample, derive::SelectionSecret, round::Round,
//!                     verdict::{Evaluation, QuorumState, VerdictRecord}};
//!
//! // The owner's key signs the roster and is the selector by default.
//! let owner = sample::owner_key();
//! let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
//! let now = sample::clock();
//!
//! // A roster of seven volunteers; the policy asks for five seats and four agreements.
//! let roster = sample::roster_of(&owner, 7, 41);
//! roster.verify(&trust, now).expect("a signed, owner-approved roster verifies");
//!
//! // The owner opens a round for one job of one change, and publishes it.
//! let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux-x86_64");
//! let secret = SelectionSecret::from_signing_key(&owner);
//! let mut round = Round::open(&inputs, &roster, &secret).unwrap();
//! round.sign(&owner).unwrap();
//! round.verify(&trust, &roster).expect("the published seats are the derived ones");
//! assert_eq!(round.selected.len(), 5);
//!
//! // The five selected volunteers re-run the job independently and sign the digest.
//! let seats = sample::indices_of(&round);
//! let attestations = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
//!
//! // Five agreeing `ResultDigest`s from five distinct identities, past the threshold
//! // of four: `verified`.
//! let verdict =
//!     VerdictRecord::evaluate(&round, &roster, &attestations, &[], &Evaluation::at(now)).unwrap();
//! assert_eq!(verdict.state, QuorumState::Verified);
//! assert_eq!(verdict.agreeing, 5);
//! assert!(verdict.agreeing >= verdict.required_agree);
//! assert!(verdict.state.mergeable());
//! # Ok::<(), gitiup_quorum::Error>(())
//! ```

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

pub mod capability;
pub mod derive;
pub mod error;
pub mod gate;
pub mod ledger;
pub mod participate;
pub mod policy;
pub mod record;
pub mod roster;
pub mod round;
pub mod select;
pub mod store;
pub mod verdict;

pub mod sample;

pub use capability::{Capabilities, Exclusion, Requirements, RosterTier, exclusion_of};
pub use derive::{ROUND_KIND, SelectionSecret};
pub use error::{Error, Result};
pub use gate::{admit, approval};
pub use gitiup_attest::{Digest, GitOid};
pub use ledger::RosterLedger;
pub use participate::{Invitation, JobBrief, ServeOutcome, Served, check_invitation};
pub use policy::{
    PolicyDocument, PolicyError, PolicyProvenance, ResolvedPolicy, Source as PolicySource,
    resolve as resolve_policy,
};
pub use roster::{
    EpochWindow, Revocation, RevocationReason, Roster, RosterEntry, SignUp, Withdrawal,
};
pub use round::{Round, RoundFacts};
pub use select::{
    CandidateRow, Greedy, ProposerExclusion, Reserve, RoundInputs, Seat, Selection,
    SelectionPolicy, proposer_family, proposer_family_exclusions,
};
pub use verdict::{
    CountedVote, DivergentResult, Evaluation, QuorumState, ReasonCode, Rejection, VerdictRecord,
};

/// The things a caller uses constantly, in one import.
///
/// ```
/// use gitiup_quorum::prelude::*;
/// let _tier = RosterTier::Endorsed;
/// let state = QuorumState::Verified;
/// assert!(state.mergeable());
/// ```
pub mod prelude {
    pub use crate::capability::{Capabilities, Requirements, RosterTier};
    pub use crate::error::Error;
    pub use crate::roster::{
        EpochWindow, Revocation, RevocationReason, Roster, RosterEntry, SignUp, Withdrawal,
    };
    pub use crate::round::Round;
    pub use crate::select::{ProposerExclusion, RoundInputs, Seat, Selection, SelectionPolicy};
    pub use crate::verdict::{Evaluation, QuorumState, ReasonCode, VerdictRecord};
    pub use gitiup_attest::{SigningKey, TimeUs, Trust};
}

/// The defaults this crate writes when a caller has no opinion, exposed so a policy
/// file and a program agree on what "the default" means.
///
/// These are literals on purpose: a default that is computed from a struct's `Default`
/// cannot be quoted in a doc or a config template. `defaults_match_the_policy_default`
/// fails the build if the two ever disagree.
pub mod defaults {
    /// Volunteers chosen per job.
    pub const N: usize = 5;
    /// Distinct identities that must agree.
    pub const REQUIRED_AGREE: usize = 4;
    /// Reserves published in a round record.
    pub const RESERVES: usize = 2;
    /// Roster epoch interval, microseconds (7 days).
    pub const EPOCH_INTERVAL_US: i64 = crate::roster::DEFAULT_EPOCH_INTERVAL_US;
    /// How many epochs a roster stays valid.
    pub const ROSTER_VALID_EPOCHS: u64 = crate::roster::ROSTER_VALID_EPOCHS;
}

#[cfg(test)]
mod tests {
    use crate::select::SelectionPolicy;

    #[test]
    fn defaults_match_the_policy_default() {
        // The constants quoted in docs and config templates are the ones the code uses.
        let policy = SelectionPolicy::default();
        assert_eq!(policy.n, crate::defaults::N);
        assert_eq!(policy.required_agree, crate::defaults::REQUIRED_AGREE);
        assert_eq!(policy.reserves, crate::defaults::RESERVES);
    }

    #[test]
    fn the_derivation_domain_is_what_the_adr_quotes() {
        crate::derive::assert_vectors_match().unwrap();
    }
}

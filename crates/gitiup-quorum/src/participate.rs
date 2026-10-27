//! Voluntary participation: the fail-closed checklist a verifier runs before it
//! executes a stranger's job
//! ([ADR-0002 D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! This is the other half of the epic, and the half that gets forgotten: the owner
//! *asking* is easy, the volunteer *agreeing* is where the risk lands. Six checks, all
//! of them cheap, all of them local except two fetches, and a refusal at any one of them
//! means the job does not run:
//!
//! 1. fetch the roster at the epoch the round pins, check the owner signature, re-hash
//!    it and compare against the pin;
//! 2. the epoch is at least the highest this store has ever offered us, and the roster
//!    has not expired;
//! 3. the round is signed by an accepted selector and its inputs recompute to the round
//!    id it claims;
//! 4. re-derive the selection from the published seed: the list must match, and my key
//!    id must be in it (a reserve does nothing but wait);
//! 5. my submission slot is still free;
//! 6. the attestation I am about to sign is bound to this round (the challenge) and to
//!    its head oid.
//!
//! Running on a cached roster is how a revoked key ends up voting, so "offline" means
//! *queue it*, never *trust my last known world*. The sandbox question — what the job may
//! reach — belongs to `giti-bgy.*`; this module decides *whether to run at all*, and hands
//! the job on with the binding facts attached.

use gitiup_attest::{AttestationDoc, Digest, RunManifest, Signer, TimeUs, Trust};
use gitiup_host::Host;

use crate::capability::Requirements;
use crate::error::Result;
use crate::ledger::RosterLedger;
use crate::roster::Roster;
use crate::round::Round;
use crate::select::Seat;
use crate::store;

/// Who and what the checklist trusts, bundled because they always travel together and
/// because a checklist with eight positional arguments is a checklist you can wire wrong.
#[derive(Debug)]
pub struct Trusts<'a> {
    /// Whose signature authorises a roster.
    pub owner: &'a Trust,
    /// Whose signature authorises a round record. Usually the same key as `owner`,
    /// and a separate parameter because the day it is not is the day the delegation
    /// matters.
    pub selector: &'a Trust,
    /// The anti-rollback ledger. `None` means step 2's monotonicity guard is skipped,
    /// which is a weaker guarantee and should be a deliberate choice, not an accident.
    pub ledger: Option<&'a RosterLedger>,
    /// The clock.
    pub now: TimeUs,
}

impl<'a> Trusts<'a> {
    /// Trusts with no ledger: fresh-check only, no memory of previous epochs.
    pub fn without_ledger(owner: &'a Trust, selector: &'a Trust, now: TimeUs) -> Trusts<'a> {
        Trusts {
            owner,
            selector,
            ledger: None,
            now,
        }
    }
}

/// What a verifier needs to know about the job it has been selected for.
#[derive(Debug, Clone)]
pub struct JobBrief {
    /// The change under verification.
    pub change_id: String,
    /// The job (matrix vector) within it.
    pub job_id: String,
    /// The head the result must be bound to.
    pub head_oid: gitiup_attest::GitOid,
    /// Which attempt this is (`0` first).
    pub attempt: u64,
    /// The capability requirements the run must honestly meet.
    pub requirements: Requirements,
    /// Digest of the round record, for the log line and the audit trail.
    pub round_digest: Digest,
    /// The challenge to write into `claims.verifier_challenge` (step 6).
    pub challenge: Digest,
    /// The roster tier this verifier was selected under, as the owner sees it.
    pub tier: crate::capability::RosterTier,
}

/// The outcome of the checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invitation {
    /// Every check passed; here is the seat and the binding.
    Selected {
        /// The seat held by this key.
        seat: Seat,
        /// The round digest, for the audit trail.
        round_digest: Digest,
        /// The challenge to sign into the attestation's claims.
        challenge: Digest,
        /// Whether the submission slot is still free (step 5). `false` means somebody
        /// — this key on another run — already published.
        slot_free: bool,
    },
    /// Not selected: nothing to do, and nothing to complain about.
    NotSelected {
        /// Position in the reserve list, if on it. A reserve waits; it does not vote.
        reserve_rank: Option<u32>,
    },
    /// A check failed. The job does not run, and the reason is the point.
    Refused {
        /// The sentence to print.
        reason: String,
        /// The exit code of the underlying refusal.
        exit_code: u8,
    },
}

impl Invitation {
    /// The seat and binding, if there is one, refusing everything else.
    pub fn into_selected(self) -> Result<(Seat, Digest, Digest, bool)> {
        match self {
            Invitation::Selected {
                seat,
                round_digest,
                challenge,
                slot_free,
            } => Ok((seat, round_digest, challenge, slot_free)),
            Invitation::NotSelected { reserve_rank } => Err(crate::error::Error::policy(
                "participation",
                format!(
                    "not selected for this round{}",
                    reserve_rank
                        .map(|r| format!(" (reserve rank {r}: wait for promotion)"))
                        .unwrap_or_default()
                ),
            )),
            Invitation::Refused { reason, .. } => {
                Err(crate::error::Error::policy("participation", reason))
            }
        }
    }
}

/// Run the D11 checklist over an already-fetched roster and round.
///
/// `owner_trust` authorises rosters, `selector_trust` authorises round records; they are
/// usually the same key and deliberately separate parameters, because the day they are
/// not is the day the delegation matters.
///
/// `ledger` is optional: without it, step 2's anti-rollback guard is *not* run, which is
/// a weaker guarantee and is therefore reported as such in the refusal list rather than
/// silently skipped.
pub fn check_invitation(
    roster: &Roster,
    round: &Round,
    my_key_id: &str,
    trusts: &Trusts<'_>,
    slot_free: bool,
) -> Invitation {
    let refused = |error: crate::error::Error| Invitation::Refused {
        reason: error.to_string(),
        exit_code: error.exit_code(),
    };
    // 1 and 2: the roster, its signature, its expiry and its epoch.
    if let Err(error) = roster.verify(trusts.owner, trusts.now) {
        return refused(error);
    }
    if let Some(ledger) = trusts.ledger
        && let Err(error) = ledger.check(roster)
    {
        return refused(error);
    }
    // 3 and 4: the round's own validity, and that its published seats are the derived
    // ones. Both are digest failures if they fail, which is why they exit 8.
    let facts = match round.verify(trusts.selector, roster) {
        Ok(facts) => facts,
        Err(error) => return refused(error),
    };
    let Some(seat) = round.seat(my_key_id).cloned() else {
        let reserve_rank = facts
            .selection
            .reserves
            .iter()
            .find(|r| r.key_id == my_key_id)
            .map(|r| r.rank);
        return Invitation::NotSelected { reserve_rank };
    };
    // 6: the binding we will be asked to sign.
    let challenge = match round.challenge_for(my_key_id) {
        Ok(challenge) => challenge,
        Err(error) => return refused(error),
    };
    Invitation::Selected {
        seat,
        round_digest: facts.round_digest,
        challenge,
        slot_free,
    }
}

/// What one volunteer round produced.
#[derive(Debug, Clone)]
pub struct Served {
    /// The attestation as published (manifest plus this verifier's signature).
    pub attestation: AttestationDoc,
    /// Its `ResultDigest` — the number the owner will compare.
    pub result_digest: gitiup_attest::ResultDigest,
    /// Where the store put it.
    pub oid: gitiup_host::Oid,
    /// The seat it occupied.
    pub seat: Seat,
}

/// What `serve_once` decided.
#[derive(Debug, Clone)]
pub enum ServeOutcome {
    /// The job ran and the attestation is published. Boxed: the attestation is far
    /// larger than any other outcome, and an enum that pays for its biggest variant
    /// makes every `match` on it copy a kilobyte for the `Skipped` path.
    Ran(Box<Served>),
    /// Not selected: nothing ran, nothing was written.
    Skipped,
    /// A check refused the job; nothing ran.
    Refused(String),
    /// The slot was already taken, so this run published nothing (a replay of a crashed
    /// run is the ordinary cause).
    AlreadySubmitted,
}

/// The volunteer's one call: check, produce, bind, sign, publish.
///
/// `produce` is the only part gitiup-quorum does not own: it receives the job brief and
/// returns the unsigned manifest of a run it really performed (tier `local`, sandbox
/// named, environment honest). That boundary is the seam giti-bgy.1 fills with a
/// sandbox, and it is deliberately a callback: nothing here can run a stranger's code by
/// accident, because nothing here knows how to run anything.
///
/// The challenge is filled in *here*, not by the caller: a verifier that forgot to bind
/// its attestation to the round would have produced a signature that can be replayed
/// into another round, and a security property must not be a caller's homework.
pub fn serve_once(
    host: &dyn Host,
    roster: &Roster,
    round: &Round,
    signer: &dyn Signer,
    trusts: &Trusts<'_>,
    produce: &dyn Fn(&JobBrief) -> Result<RunManifest>,
) -> Result<ServeOutcome> {
    let my_key_id = signer.key_id();
    let slot_free = store::slot_is_free(host, round, &my_key_id)?;
    match check_invitation(roster, round, &my_key_id, trusts, slot_free) {
        Invitation::NotSelected { .. } => Ok(ServeOutcome::Skipped),
        Invitation::Refused { reason, .. } => Ok(ServeOutcome::Refused(reason)),
        Invitation::Selected {
            slot_free: false, ..
        } => Ok(ServeOutcome::AlreadySubmitted),
        Invitation::Selected {
            seat,
            round_digest,
            challenge,
            slot_free: true,
        } => {
            let brief = JobBrief {
                change_id: round.inputs.change_id.clone(),
                job_id: round.inputs.job_id.clone(),
                head_oid: round.inputs.head_oid.clone(),
                attempt: round.inputs.attempt,
                requirements: round.inputs.required_capabilities.clone(),
                round_digest,
                challenge: challenge.clone(),
                tier: seat.tier,
            };
            let mut manifest = produce(&brief)?;
            // Step 6, enforced rather than requested.
            manifest.claims.verifier_challenge = Some(challenge);
            manifest.normalize();
            let result_digest = manifest.result_digest()?;
            let mut doc = AttestationDoc::new(manifest);
            doc.sign(signer)?;
            let oid = store::publish_submission(host, round, &my_key_id, &doc)?;
            Ok(ServeOutcome::Ran(Box::new(Served {
                attestation: doc,
                result_digest,
                oid,
                seat,
            })))
        }
    }
}

//! Admission control at submission time: *this key*, *this round*, *this document*
//! ([ADR-0002 D4, D7, D8, D9](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! The roster says who the owner approved; the round says who was picked. Neither
//! question is answered by [`store::publish_submission`](crate::store::publish_submission)
//! on its own — it can check that a key holds a seat, but a seat is a slot, and a slot
//! does not notice an attestation signed by somebody else's key, or one submitted by a
//! key the owner has since let go of. This module is the check a store runs *before* it
//! takes a write, so that "unapproved keys cannot submit attestations" is a refusal at
//! the door rather than a subtraction at the tally.
//!
//! Why not leave all of it to [`VerdictRecord::evaluate`](crate::verdict::VerdictRecord)?
//! Because a refusal that happens after the write costs the store the byte, the
//! volunteer the work, and the owner an explanation nobody asked for; because the verdict
//! runs once per change while submissions arrive N times from machines this deployment
//! does not know; and because a refusal at the door is the only one the volunteer can
//! act on — re-register, rotate the key, fix the clock.
//!
//! # The order, and why it is a contract
//!
//! Every refusal carries its own token, and exactly one is produced per document, in
//! this fixed order — the same discipline as the capability filter in
//! [`exclusion_of`](crate::capability::exclusion_of):
//!
//! | # | code | exit | the sentence |
//!|---|------|------|--------------|
//!| 1 | `unsigned` | 7 | nobody signed it |
//!| 1 | `many_signers` | 6 | more than one verifier signed one document |
//!| 2 | `bad_signature` | 7 | the document was not signed by the key it claims |
//!| 3 | `roster_expired` | 6 | the approved epoch itself is past its expiry |
//!| 4 | `not_in_roster` | 6 | this key was never approved (or was removed) |
//!| 5 | `expired` | 6 | approved, but not for this epoch (withdrawn, rotated, aged out) |
//!| 6 | `revoked` | 6 | approved once, now dead (D9) |
//!| 7 | `not_selected` | 6 | eligible, but not picked for this round |
//!| 8 | `wrong_commit` | 8 | a result for a different head |
//!| 9 | `wrong_round` | 6 | a challenge from a different round |
//!
//! Two rows deserve a sentence each. `not_in_roster` and `expired` are different
//! operational signals — "the owner never said yes to you" versus "the owner said yes
//! for epochs that have passed" — and a volunteer that gets the second must not
//! re-register. And `bad_signature` is checked *before* any roster lookup: a document
//! claiming a key id it cannot sign for has to fail as a signature problem (exit 7)
//! even when the claimed id is a perfectly good roster entry, because that is exactly
//! the forgery this row exists for.

use gitiup_attest::{AttestationDoc, TimeUs};

use crate::record::short_key;
use crate::roster::{Revocation, Roster, RosterEntry};
use crate::round::Round;
use crate::verdict::Rejection;

/// The refusal tokens this module produces, spelled once.
///
/// These are the tokens a verdict uses for the same facts (the verdict is the second
/// reader of the same documents, and a reviewer comparing a refusal at the door with a
/// rejection in a verdict must be reading one vocabulary), so a store can hand the same
/// string to a volunteer and to a tally.
pub mod code {
    /// No signature at all.
    pub const UNSIGNED: &str = "unsigned";
    /// More than one signature on one verifier's result.
    pub const MANY_SIGNERS: &str = "many_signers";
    /// The signature does not verify against the key the document claims.
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// The roster epoch itself has expired.
    pub const ROSTER_EXPIRED: &str = "roster_expired";
    /// The key is not in the approved roster: the owner never said yes, or said no.
    pub const NOT_IN_ROSTER: &str = "not_in_roster";
    /// The key is in the roster but not valid for the round's epoch.
    pub const EXPIRED: &str = "expired";
    /// The key (or its principal) has been revoked in a way that voids this round.
    pub const REVOKED: &str = "revoked";
    /// The key is eligible but holds no seat in this round.
    pub const NOT_SELECTED: &str = "not_selected";
    /// The result is for a different head oid than the round is about.
    pub const WRONG_COMMIT: &str = "wrong_commit";
    /// The result carries another round's verifier challenge.
    pub const WRONG_ROUND: &str = "wrong_round";
}

/// A refusal, as the record the verdict would also have written.
fn deny(
    key_id: impl Into<String>,
    identity: Option<String>,
    code: &str,
    detail: impl Into<String>,
    exit_code: u8,
) -> Rejection {
    Rejection {
        key_id: key_id.into(),
        identity,
        code: code.to_string(),
        detail: detail.into(),
        exit_code: Some(exit_code),
    }
}

/// The one key that signed an attestation.
///
/// "One document, one signer" is a rule, not a limitation: an attestation carrying two
/// signatures would let one submission consume two identities' votes, and the only
/// honest way for two verifiers to agree is two attestations.
pub fn signer_of(attestation: &AttestationDoc) -> std::result::Result<String, Rejection> {
    match attestation.signatures.len() {
        0 => Err(deny(
            "<unsigned>",
            None,
            code::UNSIGNED,
            "an attestation with no signature is not a claim by anyone",
            7,
        )),
        1 => Ok(attestation.signatures[0].key_id.clone()),
        many => Err(deny(
            short_key(&attestation.signatures[0].key_id),
            None,
            code::MANY_SIGNERS,
            format!(
                "{many} signatures on one attestation: one verifier signs one result, and \
                 pooling them into one document buys a second vote with a first one's paper"
            ),
            6,
        )),
    }
}

/// Is `key_id` approved by `roster` for `epoch` — and is that epoch still alive?
///
/// The two refusals are deliberately different: `not_in_roster` means the owner has
/// never approved this key (it should publish a sign-up), `expired` means the owner
/// approved it for a window that does not include this epoch (withdrawal, rotation, or
/// an entry that simply aged out). A volunteer told `expired` must not re-register.
pub fn approval<'a>(
    roster: &'a Roster,
    key_id: &str,
    epoch: u64,
    now: TimeUs,
) -> std::result::Result<&'a RosterEntry, Rejection> {
    if now.as_us() > roster.valid_until_us {
        return Err(deny(
            key_id,
            None,
            code::ROSTER_EXPIRED,
            format!(
                "roster epoch {} expired at {}; a trust list the calendar has passed \
                 authorises no new work",
                roster.epoch,
                TimeUs(roster.valid_until_us).to_rfc3339()
            ),
            6,
        ));
    }
    let Some(entry) = roster.entry(key_id) else {
        return Err(deny(
            key_id,
            None,
            code::NOT_IN_ROSTER,
            "this key is not in the approved roster, so nothing it signs can be a vote here; \
             `gitiup participant register` is how a key asks to be considered",
            6,
        ));
    };
    if !entry.epochs_valid.contains(epoch) {
        return Err(deny(
            key_id,
            Some(entry.identity.clone()),
            code::EXPIRED,
            format!(
                "this entry is approved for epochs {}..={}, not epoch {epoch}; an expired \
                 entry is a departure, not a bug to re-register around",
                entry.epochs_valid.from, entry.epochs_valid.to
            ),
            6,
        ));
    }
    Ok(entry)
}

/// Admit or refuse one submission, returning the signer's key id when it is admitted.
///
/// Checks, in order: the document is signed by exactly one key and that signature
/// verifies; the roster epoch is current and approves that key for the round's epoch;
/// neither the key nor its principal has been revoked in a way that voids this round;
/// the key holds a seat in the round; and the document actually belongs to this round
/// (the head oid, and this key's challenge).
///
/// What it deliberately does *not* do is decide whether the *roster* is trusted — that
/// is [`Roster::verify`], run by whoever fetched the roster, and by the time a
/// submission reaches here the roster has been fixed as the one the round pinned. It
/// also does not re-run the attestation's whole policy (tier, age, sandbox): the verdict
/// does that, and must, because those facts can change between a submission and a merge.
pub fn admit(
    roster: &Roster,
    round: &Round,
    attestation: &AttestationDoc,
    revocations: &[Revocation],
    now: TimeUs,
) -> std::result::Result<String, Rejection> {
    let key_id = signer_of(attestation)?;
    // The signature is checked against the document before any lookup: a claim to *be*
    // an approved key must fail as a signature failure when it is not that key, or a
    // forged key id would be refused for a policy reason and read like a roster bug.
    let message = attestation.signature_message().map_err(|error| {
        deny(
            key_id.clone(),
            None,
            code::BAD_SIGNATURE,
            format!("the document cannot be re-encoded to check its signature: {error}"),
            7,
        )
    })?;
    attestation.signatures[0]
        .verify(&message)
        .map_err(|error| {
            deny(
                key_id.clone(),
                None,
                code::BAD_SIGNATURE,
                format!(
                    "this attestation was not signed by {} ({}): a key id is derived from the \
                     key that signs, so naming an approved key does not make this one",
                    short_key(&key_id),
                    error.detail()
                ),
                7,
            )
        })?;
    let entry = approval(roster, &key_id, round.inputs.roster_epoch, now)?;
    let identity = Some(entry.identity.clone());
    if let Some(revoked) = revocations.iter().find(|r| {
        (r.key_id == key_id || r.key_id == entry.identity) && r.voids(round.inputs.roster_epoch)
    }) {
        return Err(deny(
            key_id,
            identity,
            code::REVOKED,
            format!(
                "{} revoked this key ({}) effective epoch {}, which voids a round pinned to \
                 epoch {}",
                if revoked.issuer == revoked.key_id {
                    "the key itself"
                } else {
                    "the owner"
                },
                revoked.reason,
                revoked.effective_epoch,
                round.inputs.roster_epoch
            ),
            6,
        ));
    }
    if !round.is_selected(&key_id) {
        return Err(deny(
            key_id,
            identity,
            code::NOT_SELECTED,
            "approved, but holding no seat in this round: a reserve waits to be promoted, \
             it does not vote early",
            6,
        ));
    }
    // The two bindings that make a submission *this* round's work: the commit it is
    // about, and the challenge only this round's seed could have produced for this key.
    let manifest = &attestation.manifest;
    if manifest.result.source.commit != round.inputs.head_oid {
        return Err(deny(
            key_id,
            identity,
            code::WRONG_COMMIT,
            format!(
                "this result is for {}, and the round is about {}",
                manifest.result.source.commit, round.inputs.head_oid
            ),
            8,
        ));
    }
    let expected = round.challenge_for(&key_id).map_err(|error| {
        deny(
            key_id.clone(),
            identity.clone(),
            code::NOT_SELECTED,
            error.to_string(),
            error.exit_code(),
        )
    })?;
    match manifest.claims.verifier_challenge.as_ref() {
        Some(challenge) if *challenge == expected => Ok(key_id),
        Some(challenge) => Err(deny(
            key_id,
            identity,
            code::WRONG_ROUND,
            format!(
                "this attestation is bound to challenge {challenge}, not the one this round \
                 derived for this key; it is another round's work and is not evidence here"
            ),
            6,
        )),
        None => Err(deny(
            key_id,
            identity,
            code::WRONG_ROUND,
            format!(
                "this attestation carries no verifier challenge at all, so it cannot be shown \
                 to be this round's work rather than a replay of honest work from somewhere \
                 else (the challenge this round expects is {expected})"
            ),
            6,
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::roster::{Revocation, RevocationReason};
    use crate::{Roster, sample};

    use super::*;

    /// A round over the fixture roster, with its seats filled and published.
    fn fixture() -> (Roster, crate::round::Round) {
        use crate::derive::SelectionSecret;
        let owner = sample::owner_key();
        let roster = sample::roster_of(&owner, 7, 41);
        let inputs = sample::round_inputs(&roster, "chg-000000000000f00d", "build/matrix/linux");
        let mut round =
            crate::round::Round::open(&inputs, &roster, &SelectionSecret::from_signing_key(&owner))
                .expect("round opens");
        round.sign(&owner).expect("selector signs");
        (roster, round)
    }

    fn one_attestation(round: &crate::round::Round) -> AttestationDoc {
        let seats = sample::indices_of(round);
        sample::attest(round, &seats[..1], sample::claimed_at_us(), |_| None)
            .into_iter()
            .next()
            .expect("one attestation")
    }

    /// A volunteer's honest manifest for this round, with one claim edited *before* it
    /// is signed — the shape of a verifier that bound the wrong thing, rather than of a
    /// document somebody tampered with after the fact.
    fn reseal(
        round: &crate::round::Round,
        index: u8,
        edit: impl FnOnce(&mut gitiup_attest::RunManifest),
    ) -> AttestationDoc {
        let key = sample::verifier_key(index);
        let mut manifest = sample::manifest_for(round, index, sample::claimed_at_us(), None);
        edit(&mut manifest);
        let mut doc = AttestationDoc::new(manifest);
        doc.sign(&key).expect("reseals");
        doc
    }

    #[test]
    fn a_selected_key_with_a_bound_result_is_admitted() {
        let (roster, round) = fixture();
        let doc = one_attestation(&round);
        let key_id = admit(&roster, &round, &doc, &[], sample::clock()).expect("admitted");
        assert!(round.is_selected(&key_id));
    }

    #[test]
    fn a_key_the_owner_never_approved_is_refused_by_name() {
        let (roster, round) = fixture();
        let stranger = gitiup_attest::SigningKey::from_seed(&[251u8; 32]);
        let mut doc = one_attestation(&round);
        // Re-sign an honest manifest with a key that is in no roster.
        doc.signatures.clear();
        doc.sign(&stranger).expect("signs");
        let refusal = admit(&roster, &round, &doc, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::NOT_IN_ROSTER);
        assert_eq!(refusal.exit_code, Some(6));
    }

    #[test]
    fn a_signature_that_is_not_the_claimed_key_is_a_signature_failure() {
        let (roster, round) = fixture();
        let seats = sample::indices_of(&round);
        let honest = sample::attest(&round, &seats[..1], sample::claimed_at_us(), |_| None)
            .into_iter()
            .next()
            .unwrap();
        let claimed = honest.signatures[0].key_id.clone();
        // Swap in another key's bytes over the same signature field: the id is a
        // roster entry, the signature is not that key's.
        let mut forged = honest.clone();
        forged.signatures[0].sig = sample::verifier_key(63)
            .sign(&honest.signature_message().unwrap())
            .to_base64();
        assert_eq!(forged.signatures[0].key_id, claimed);
        let refusal = admit(&roster, &round, &forged, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::BAD_SIGNATURE);
        assert_eq!(refusal.exit_code, Some(7));
    }

    #[test]
    fn an_expired_entry_and_an_unapproved_key_are_different_refusals() {
        let (roster, round) = fixture();
        let seats = sample::indices_of(&round);
        let doc = sample::attest(&round, &seats[..1], sample::claimed_at_us(), |_| None)
            .into_iter()
            .next()
            .unwrap();
        let key_id = doc.signatures[0].key_id.clone();
        let mut aged = roster.clone();
        {
            let entry = aged
                .entry_mut(&key_id)
                .expect("the seat holder is in the roster");
            entry.epochs_valid = crate::roster::EpochWindow {
                from: 1,
                to: roster.epoch.saturating_sub(1),
            };
        }
        let refusal = admit(&aged, &round, &doc, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::EXPIRED, "{refusal:?}");
        // The same document against a roster with the entry removed is the other
        // sentence, and it must not be conflated with this one.
        let removed = roster
            .without(&[key_id.clone()].into_iter().collect())
            .expect("a roster without one entry is still a roster");
        let refusal = admit(&removed, &round, &doc, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::NOT_IN_ROSTER);
    }

    #[test]
    fn an_expired_roster_admits_nothing_at_all() {
        let (roster, round) = fixture();
        let doc = one_attestation(&round);
        let late = TimeUs(roster.valid_until_us + 1);
        let refusal = admit(&roster, &round, &doc, &[], late).unwrap_err();
        assert_eq!(refusal.code, code::ROSTER_EXPIRED);
    }

    #[test]
    fn a_revoked_key_is_refused_by_the_same_token_the_verdict_uses() {
        let (roster, round) = fixture();
        let seats = sample::indices_of(&round);
        let doc = sample::attest(&round, &seats[..1], sample::claimed_at_us(), |_| None)
            .into_iter()
            .next()
            .unwrap();
        let key_id = doc.signatures[0].key_id.clone();
        let mut rev = Revocation::new(
            key_id.clone(),
            RevocationReason::Compromised,
            roster.epoch,
            sample::T0,
        );
        rev.sign(&sample::owner_key())
            .expect("the owner may revoke");
        let refusal = admit(&roster, &round, &doc, &[rev], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::REVOKED);
        assert_eq!(
            refusal.identity.as_deref(),
            Some(roster.entry(&key_id).unwrap().identity.as_str())
        );
    }

    #[test]
    fn an_unbound_or_foreign_challenge_is_not_this_rounds_work() {
        let (roster, round) = fixture();
        let seats = sample::indices_of(&round);
        let seat = seats[0];
        // Re-signed, not tampered with: a document whose claims were edited after
        // signing fails as a *signature* problem, and the interesting case is an honest
        // verifier that bound the wrong round.
        let unbound = reseal(&round, seat, |manifest| {
            manifest.claims.verifier_challenge = None;
        });
        let refusal = admit(&roster, &round, &unbound, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::WRONG_ROUND, "{refusal:?}");
        let foreign = reseal(&round, seat, |manifest| {
            manifest.claims.verifier_challenge =
                Some(gitiup_attest::Digest::sha256(b"another round"));
        });
        let refusal = admit(&roster, &round, &foreign, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::WRONG_ROUND);
        // A different head oid is a different change, and says so.
        let elsewhere = reseal(&round, seat, |manifest| {
            manifest.result.source.commit =
                gitiup_attest::GitOid::from_sha1_hex(&"b".repeat(40)).expect("40 hex");
        });
        let refusal = admit(&roster, &round, &elsewhere, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::WRONG_COMMIT);
        assert_eq!(refusal.exit_code, Some(8));
    }

    #[test]
    fn two_signatures_on_one_document_buy_nothing() {
        let (roster, round) = fixture();
        let seats = sample::indices_of(&round);
        let mut docs = sample::attest(&round, &seats[..2], sample::claimed_at_us(), |_| None);
        let second = docs.pop().expect("two");
        let mut merged = docs.pop().expect("one");
        merged.add_signature(second.signatures[0].clone());
        let refusal = admit(&roster, &round, &merged, &[], sample::clock()).unwrap_err();
        assert_eq!(refusal.code, code::MANY_SIGNERS);
    }
}

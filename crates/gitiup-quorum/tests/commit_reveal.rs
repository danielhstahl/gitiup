//! Commit-reveal submission: `reveal_mode = sealed`, end to end
//! ([giti-zp1.6](../../../README.md)).
//!
//! [`commit.rs`](gitiup_quorum::commit) says what a commitment *is*; this file proves what
//! the ticket's acceptance criteria say the store and the tally do:
//!
//! * a sealed round is **advertised and polled** like any other, and the volunteer needs no
//!   flag to know it is in one;
//! * phase 1 lands at `refs/gitiup/commit/<change>/<job>/<slot>` **before** the reveal, and
//!   a reveal into a sealed round with nothing committed is refused by the store;
//! * a reveal that does not hash to its commitment is **refused and counted against the
//!   seat** — named in `rejected`, not silently `missing`;
//! * a commitment with no reveal lands in **`missing`**, and a reveal with no commitment is
//!   **rejected** by the tally even when a store let it in;
//! * `store::tally` follows the **round's** `reveal_mode`, so one caller serves both flows.
//!
//! Everything runs against a real `fs` host, because the property under test is a pair of
//! CAS writes and their bytes, not a data structure.

use gitiup_attest::{AttestationDoc, SigningKey, Trust};
use gitiup_host::{BlobStore, Expect, FsHost, Oid, RefDeletion, RefName, RefStore, RefUpdate};
use gitiup_quorum::commit::{Commitment, code as commitment, commitment_of};
use gitiup_quorum::participate::{ServeOutcome, Trusts, serve_once};
use gitiup_quorum::prelude::*;
use gitiup_quorum::store::ns;
use gitiup_quorum::{defaults, sample, store};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";

struct Scene {
    host: FsHost,
    _dir: tempfile::TempDir,
    owner: SigningKey,
    trust: Trust,
    roster: Roster,
    round: Round,
}

impl Scene {
    /// A published `sealed` round over a seven-volunteer roster (five seats, four agree).
    fn sealed() -> Scene {
        Scene::build(true)
    }

    fn open() -> Scene {
        Scene::build(false)
    }

    fn build(sealed: bool) -> Scene {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path()).expect("fs host");
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("roster publishes");
        let inputs = sample::round_inputs(&roster, CHANGE, JOB);
        let secret = gitiup_quorum::derive::SelectionSecret::from_signing_key(&owner);
        let mut round = if sealed {
            Round::open_sealed(&inputs, &roster, &secret).expect("a sealed round opens")
        } else {
            Round::open(&inputs, &roster, &secret).expect("a round opens")
        };
        round.sign(&owner).expect("the selector signs");
        store::publish_round(&host, &round).expect("the round publishes");
        let round = store::round_at(&host, CHANGE, JOB, 0)
            .expect("read back")
            .expect("it is there");
        assert_eq!(round.reveal_mode, if sealed { "sealed" } else { "open" });
        assert_eq!(round.selected.len(), defaults::N);
        Scene {
            host,
            _dir: dir,
            owner,
            trust,
            roster,
            round,
        }
    }

    fn seats(&self) -> Vec<u8> {
        sample::indices_of(&self.round)
    }

    fn key(&self, index: u8) -> SigningKey {
        sample::verifier_key(index)
    }

    fn seat_of(&self, index: u8) -> gitiup_quorum::Seat {
        self.round
            .seat(&self.key(index).public_key().key_id())
            .expect("a seat")
            .clone()
    }

    fn commit_ref_of(&self, index: u8) -> RefName {
        store::commit_ref(CHANGE, JOB, &self.seat_of(index).slot).expect("a ref name")
    }

    fn reveal_ref_of(&self, index: u8) -> RefName {
        store::reveal_ref(CHANGE, JOB, &self.seat_of(index).slot).expect("a ref name")
    }

    /// The fixture attestation for one seat, signed by its key, unpublished.
    fn attestation(&self, index: u8, diverge: Option<&str>) -> AttestationDoc {
        sample::attest(&self.round, &[index], sample::claimed_at_us(), |_| {
            diverge.map(str::to_string)
        })
        .into_iter()
        .next()
        .expect("one attestation")
    }

    /// The honest volunteer: commit, then reveal, in that order, through the library's own
    /// volunteer path.
    fn serve(&self, index: u8, diverge: Option<&str>) -> ServeOutcome {
        let key = self.key(index);
        let ledger = {
            let mut ledger = gitiup_quorum::ledger::RosterLedger::new("commit-reveal");
            ledger.record(&self.roster).expect("fresh epoch");
            ledger
        };
        let trusts = Trusts {
            owner: &self.trust,
            selector: &self.trust,
            ledger: Some(&ledger),
            now: sample::clock(),
        };
        let round = self.round.clone();
        serve_once(&self.host, &self.roster, &round, &key, &trusts, &|_brief| {
            Ok(sample::manifest_for(
                &round,
                index,
                sample::claimed_at_us(),
                diverge,
            ))
        })
        .expect("serving does not fail")
    }

    /// Publish a seat's commitment for the given attestation (phase 1 by hand).
    fn commit(&self, index: u8, doc: &AttestationDoc) {
        let mut commitment =
            Commitment::for_document(&self.round, doc, sample::clock()).expect("commits");
        commitment.sign(&self.key(index)).expect("the seat signs");
        store::publish_commitment(&self.host, &self.round, &commitment).expect("phase 1");
    }

    /// Move a commitment ref by force — what a stale or hostile store would do.
    fn overwrite_commitment(&self, index: u8, commitment: &Commitment) {
        let name = self.commit_ref_of(index);
        let oid = self
            .host
            .put_cas(&ns::COMMIT, &commitment.canonical_bytes().unwrap())
            .expect("put the bytes");
        let current = self.host.get_ref(&name).unwrap().expect("a ref is there");
        self.host
            .update_ref_cas(&RefUpdate::new(name, Expect::Is(current.oid), oid))
            .expect("move the ref");
    }

    fn tally(&self) -> VerdictRecord {
        store::tally(
            &self.host,
            &self.round,
            &self.roster,
            &[],
            &Evaluation::at(sample::clock()),
        )
        .expect("the tally runs")
    }
}

/// Every seat commits, then reveals, and the round is `verified` with both phases in the
/// store where the ticket says they are.
#[test]
fn a_sealed_round_runs_its_two_phases_and_verifies() {
    let scene = Scene::sealed();
    for &index in &scene.seats() {
        match scene.serve(index, None) {
            ServeOutcome::Ran(served) => {
                let promised = served.commitment.as_ref().expect("a sealed round commits");
                assert_eq!(
                    promised.commitment,
                    Commitment::for_document(&scene.round, &served.attestation, sample::clock())
                        .unwrap()
                        .commitment,
                    "the promise is about the bytes that were actually published"
                );
            }
            other => panic!("expected a run, got {other:?}"),
        }
    }
    assert_eq!(
        store::commitments(&scene.host, &scene.round)
            .expect("commitments read")
            .len(),
        defaults::N
    );
    for seat in &scene.round.selected {
        let name = store::commit_ref(CHANGE, JOB, &seat.slot).unwrap();
        assert!(
            scene.host.get_ref(&name).unwrap().is_some(),
            "{name} should hold a commitment"
        );
        let at = store::commitment_at(&scene.host, &scene.round, &seat.key_id)
            .unwrap()
            .expect("this seat committed");
        assert_eq!(at.key_id, seat.key_id);
        assert_eq!(at.slot, seat.slot);
    }
    let verdict = scene.tally();
    assert_eq!(verdict.state, QuorumState::Verified, "{}", verdict.detail);
    assert_eq!(verdict.agreeing, defaults::N);
    assert!(verdict.rejected.is_empty() && verdict.missing.is_empty());

    // A sealed round is advertised, or no volunteer would ever find it.
    store::advertise_round(&scene.host, &scene.round, &scene.owner, sample::clock())
        .expect("a sealed round advertises");
    let page = store::open_rounds(&scene.host, sample::clock(), store::Cursor::START, 10)
        .expect("the listing works");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].reveal_mode, "sealed");
}

/// Phase order is not etiquette: a reveal into a sealed round with nothing committed is
/// refused by the store, and the refusal says what to do instead.
#[test]
fn a_reveal_with_no_commitment_is_refused_at_the_door() {
    let scene = Scene::sealed();
    let index = scene.seats()[0];
    let key = scene.key(index);
    let doc = scene.attestation(index, None);
    let err =
        store::publish_submission(&scene.host, &scene.round, &key.public_key().key_id(), &doc)
            .unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(err.message().contains("commit"), "{err}");
    assert!(
        scene
            .host
            .get_ref(&scene.reveal_ref_of(index))
            .unwrap()
            .is_none(),
        "and nothing was half-written"
    );
}

/// The one behaviour sealing exists to catch: a seat that commits, then reveals something
/// else. The store keeps the evidence and the verdict names it — the seat is *refused*, not
/// counted as silent.
#[test]
fn a_reveal_that_does_not_open_its_commitment_is_refused_and_counted_against_the_seat() {
    let scene = Scene::sealed();
    let index = scene.seats()[0];
    let key = scene.key(index);
    scene.commit(index, &scene.attestation(index, None));

    // The copycat's second thought: a different answer from the same seat, signed by the
    // same key, published after the promise was made.
    let changed = scene.attestation(index, Some("test result: FAILED. 41 passed, 1 failed"));
    store::publish_submission(
        &scene.host,
        &scene.round,
        &key.public_key().key_id(),
        &changed,
    )
    .expect("the mismatch is *published*: it is the evidence");

    let verdict = scene.tally();
    assert_eq!(verdict.rejected.len(), 1, "{:?}", verdict.rejected);
    let refusal = &verdict.rejected[0];
    assert_eq!(refusal.code, commitment::COMMITMENT_MISMATCH);
    assert_eq!(refusal.key_id, key.public_key().key_id());
    assert_eq!(
        refusal.exit_code,
        Some(8),
        "a reveal that is not the bytes it promised is a digest that is not what it names"
    );
    assert!(refusal.detail.contains("committed"), "{refusal:?}");
    assert!(
        !verdict.missing.contains(&key.public_key().key_id()),
        "the seat spoke; it is refused, not silent: {:?}",
        verdict.missing
    );
    assert!(
        !verdict
            .counted
            .iter()
            .any(|vote| vote.key_id == key.public_key().key_id()),
        "and it certainly did not get a vote"
    );

    // The other four still agree, so the round is `verified` *with the mismatch on the
    // record*: whoever audits it sees both the quorum and the seat that changed its mind.
    for &other in &scene.seats()[1..] {
        scene.serve(other, None);
    }
    let verdict = scene.tally();
    assert_eq!(verdict.agreeing, defaults::N - 1);
    assert_eq!(verdict.state, QuorumState::Verified, "{}", verdict.detail);
    assert_eq!(verdict.rejected.len(), 1);
    assert_eq!(verdict.rejected[0].code, commitment::COMMITMENT_MISMATCH);
}

/// A commitment with nothing behind it is a silent seat: it belongs in `missing`, exactly
/// like a volunteer that never showed up, and it is not a rejection.
#[test]
fn a_commitment_with_no_reveal_lands_in_missing() {
    let scene = Scene::sealed();
    let seats = scene.seats();
    let quiet = seats[0];
    scene.commit(quiet, &scene.attestation(quiet, None));
    for &index in &seats[1..] {
        scene.serve(index, None);
    }
    let verdict = scene.tally();
    assert_eq!(
        verdict.missing,
        vec![scene.key(quiet).public_key().key_id()],
        "a promise is not a vote"
    );
    assert!(verdict.rejected.is_empty());
    assert_eq!(
        verdict.state,
        QuorumState::Verified,
        "four of the required four still agree: {} of {}",
        verdict.agreeing,
        verdict.required_agree
    );
}

/// A store that let an uncommitted reveal in — a mirror, an older frontend, a hostile
/// operator — still gets a verdict that refuses it. The tally does not trust the store
/// about what was promised.
#[test]
fn a_reveal_with_no_commitment_is_rejected_by_the_tally_too() {
    let scene = Scene::sealed();
    for &index in &scene.seats() {
        scene.serve(index, None);
    }
    // Tear one seat's commitment back out of the store, leaving the reveal behind.
    let current = scene
        .host
        .get_ref(&scene.commit_ref_of(scene.seats()[0]))
        .unwrap()
        .expect("committed");
    scene
        .host
        .delete_ref_cas(&RefDeletion::new(
            scene.commit_ref_of(scene.seats()[0]),
            Expect::Is(current.oid),
        ))
        .expect("the ref goes away");
    let verdict = scene.tally();
    let refusal = verdict
        .rejected
        .iter()
        .find(|rejection| rejection.code == commitment::NO_COMMITMENT)
        .expect("the uncommitted reveal is named");
    assert_eq!(
        refusal.key_id,
        scene.key(scene.seats()[0]).public_key().key_id()
    );
    assert_eq!(refusal.exit_code, Some(6));
    assert!(
        !verdict.missing.contains(&refusal.key_id),
        "it is a refusal, not a silence"
    );
}

/// A commitment that does not describe this round — an escalation's, or another change's —
/// opens nothing, and saying so by name beats reporting "nothing was committed" about a
/// seat that committed to something else.
#[test]
fn a_stale_commitment_is_refused_and_named() {
    let scene = Scene::sealed();
    let index = scene.seats()[0];
    let key = scene.key(index);
    // The seat does both phases honestly, and *then* something replaces its commitment
    // with one from another round — the shape a stale write, a partial escalation or a
    // lying mirror leaves behind, with the reveal still in place to be judged.
    scene.serve(index, None);
    let stale = store::commitment_at(&scene.host, &scene.round, &key.public_key().key_id())
        .unwrap()
        .expect("committed");
    // Rewrite it to speak about attempt 1 — what a later round's slot would hold.
    let mut lie = stale.clone();
    lie.attempt = stale.attempt + 1;
    lie.signatures.clear();
    lie.sign(&key).unwrap();
    scene.overwrite_commitment(index, &lie);

    // The volunteer's own phase-1 step will not treat a foreign commitment as its own.
    let err =
        store::commitment_at(&scene.host, &scene.round, &key.public_key().key_id()).unwrap_err();
    assert_eq!(err.exit_code(), 8, "{err}");

    // And the tally refuses the seat rather than quietly ignoring the row.
    let filed = store::commitments(&scene.host, &scene.round).expect("read the slots");
    let reveals = store::submissions(&scene.host, &scene.round).expect("the reveals are there");
    assert_eq!(reveals.len(), 1);
    let foreign = filed
        .iter()
        .find(|row| row.seat == key.public_key().key_id())
        .expect("the stale commitment is there to be refused");
    assert!(foreign.matches(&scene.round).is_err());
    let verdict = VerdictRecord::evaluate_sealed(
        &scene.round,
        &scene.roster,
        &reveals,
        &filed,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("the tally runs");
    let refusal = verdict
        .rejected
        .iter()
        .find(|rejection| rejection.code == commitment::FOREIGN_COMMITMENT)
        .unwrap_or_else(|| panic!("named, not dropped: {:?}", verdict.rejected));
    assert_eq!(refusal.key_id, key.public_key().key_id());
}

/// `store::tally` reads the round's mode rather than being told it, and neither tally
/// passes for the other.
#[test]
fn the_flow_follows_the_round_and_neither_tally_passes_for_the_other() {
    let open = Scene::open();
    let sealed = Scene::sealed();
    for &index in &sealed.seats() {
        sealed.serve(index, None);
    }
    for &index in &open.seats() {
        match open.serve(index, None) {
            ServeOutcome::Ran(served) => {
                assert!(served.commitment.is_none(), "an open round commits nothing");
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(open.tally().state, QuorumState::Verified);
    assert!(
        store::commitments(&open.host, &open.round)
            .expect("reading an open round's commitments")
            .is_empty()
    );
    // Crossing the two is a refusal in both directions: dropping the commitment rule and
    // inventing one are equally misreadings of the round.
    let err = VerdictRecord::evaluate_sealed(
        &open.round,
        &open.roster,
        &[],
        &[],
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap_err();
    assert!(err.message().contains("open"), "{err}");
    let err = VerdictRecord::evaluate(
        &sealed.round,
        &sealed.roster,
        &[],
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap_err();
    assert!(err.message().contains("sealed"), "{err}");
    // `store::tally` is the caller that never has to know.
    for scene in [&open, &sealed] {
        let verdict = store::tally(
            &scene.host,
            &scene.round,
            &scene.roster,
            &[],
            &Evaluation::at(sample::clock()),
        )
        .expect("the round chooses the flow");
        assert_eq!(verdict.state, QuorumState::Verified);
    }
}

/// A commitment is a key's claim about itself: it is signed by the seat, and a store that
/// invented one for a key that never made one is not believed.
#[test]
fn a_commitment_somebody_else_signed_is_not_believed() {
    let scene = Scene::sealed();
    let index = scene.seats()[0];
    let stranger = sample::verifier_key(63);
    let mut commitment = Commitment::for_document(
        &scene.round,
        &scene.attestation(index, None),
        sample::clock(),
    )
    .unwrap();
    commitment.sign(&stranger).unwrap();
    assert_eq!(commitment.verify().unwrap_err().exit_code(), 7);
    // A store that holds it anyway is still not believed: the ref is not the authority.
    let name = scene.commit_ref_of(index);
    let oid: Oid = scene
        .host
        .put_cas(&ns::COMMIT, &commitment.canonical_bytes().unwrap())
        .unwrap();
    scene
        .host
        .update_ref_cas(&RefUpdate::create(name, oid))
        .unwrap();
    let err = store::commitments(&scene.host, &scene.round).unwrap_err();
    assert_eq!(err.exit_code(), 7, "{err}");
}

/// The preimage is published in the open: anyone who can read the two refs can check a
/// reveal themselves, which is what makes a sealed round auditable without trusting whoever
/// tallied it.
#[test]
fn a_stranger_can_check_a_reveal_against_its_commitment() {
    let scene = Scene::sealed();
    scene.serve(scene.seats()[0], None);
    let seat = scene.round.selected[0].clone();
    let commitment = store::commitment_at(&scene.host, &scene.round, &seat.key_id)
        .unwrap()
        .expect("committed");
    let name = store::reveal_ref(CHANGE, JOB, &seat.slot).unwrap();
    let reference = scene.host.get_ref(&name).unwrap().expect("revealed");
    let bytes = scene.host.get(&reference.oid).unwrap().expect("the blob");
    let revealed = AttestationDoc::from_canonical_bytes(&bytes).unwrap();
    let recomputed = commitment_of(
        &revealed.canonical_bytes().unwrap(),
        &seat.slot,
        &scene.round.challenge_for(&seat.key_id).unwrap(),
    );
    assert_eq!(recomputed, commitment.commitment);
    assert!(commitment.opens_with(&revealed).unwrap());
    // And it is not any other seat's promise: the slot and the challenge are in the
    // preimage precisely so a commitment cannot be carried between seats.
    let other = &scene.round.selected[1];
    assert_ne!(
        recomputed,
        commitment_of(
            &revealed.canonical_bytes().unwrap(),
            &other.slot,
            &scene.round.challenge_for(&other.key_id).unwrap(),
        )
    );
}

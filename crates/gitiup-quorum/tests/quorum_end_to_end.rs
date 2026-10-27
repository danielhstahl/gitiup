//! The epic's acceptance path, end to end, through a real store.
//!
//! Five volunteers are derived, run the job on their own boxes, publish into the slots
//! their seats reserve, and the owner's verdict says `verified` — and then the same code
//! says `failed` when one disagrees and `insufficient` when too few turn up. Everything
//! goes through [`gitiup_host::Host`] CAS writes, because the guarantee under test is
//! that the store, not a coordinator, is what makes a submission un-forgeable.

use gitiup_attest::{AttestationDoc, Trust};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::ledger::RosterLedger;
use gitiup_quorum::participate::{ServeOutcome, Trusts, serve_once};
use gitiup_quorum::prelude::*;
use gitiup_quorum::store;
use gitiup_quorum::verdict::{Evaluation, QuorumState, ReasonCode, VerdictRecord};
use gitiup_quorum::{defaults, sample};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";

struct Setup {
    host: gitiup_host::hosts::fs::FsHost,
    _dir: tempfile::TempDir,
    owner: gitiup_attest::SigningKey,
    trust: Trust,
    roster: Roster,
    round: Round,
}

/// Owner's view: a signed roster, a signed round, both published, and the round read
/// back from the store and re-verified against the roster it pins.
fn setup() -> Setup {
    let dir = tempfile::tempdir().expect("temp dir");
    let host = gitiup_host::hosts::fs::FsHost::create(dir.path()).expect("fs host");
    let owner = sample::owner_key();
    let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
    let roster = sample::roster_of(&owner, 7, 41);
    store::publish_roster(&host, &roster).expect("roster publishes");
    assert_eq!(
        store::current_roster(&host)
            .unwrap()
            .unwrap()
            .digest()
            .unwrap(),
        roster.digest().unwrap(),
        "the store's current roster is the one that was published"
    );

    let inputs = sample::round_inputs(&roster, CHANGE, JOB);
    let secret = SelectionSecret::from_signing_key(&owner);
    let mut round = Round::open(&inputs, &roster, &secret).expect("round opens");
    round.sign(&owner).expect("selector signs");
    store::publish_round(&host, &round).expect("round publishes");

    let published = store::round_at(&host, CHANGE, JOB, 0)
        .unwrap()
        .expect("the round is readable");
    published
        .verify(&trust, &roster)
        .expect("the published seats are the derived ones");
    assert_eq!(published.selected.len(), defaults::N);

    Setup {
        host,
        _dir: dir,
        owner,
        trust,
        roster,
        round: published,
    }
}

/// The volunteer's side: poll, check the invitation, run, sign, publish.
fn volunteer_runs(setup: &Setup, index: u8, ledger: &RosterLedger) -> ServeOutcome {
    let key = sample::verifier_key(index);
    let trusts = Trusts {
        owner: &setup.trust,
        selector: &setup.trust,
        ledger: Some(ledger),
        now: sample::clock(),
    };
    let now_us = sample::claimed_at_us();
    serve_once(
        &setup.host,
        &setup.roster,
        &setup.round,
        &key,
        &trusts,
        &|brief| {
            // A real volunteer derives the manifest from its own sandboxed run; the
            // fixture supplies one shaped like it. The brief is what the *round* said
            // the job was, and a volunteer that ignored it would be signing a digest
            // of something nobody asked for.
            assert_eq!(brief.job_id, setup.round.inputs.job_id);
            assert_eq!(brief.head_oid, setup.round.inputs.head_oid);
            Ok(sample::manifest_for(&setup.round, index, now_us, None))
        },
    )
    .expect("serving once does not fail")
}

fn ledger(rost: &Roster) -> RosterLedger {
    let mut ledger = RosterLedger::new("quorum-end-to-end");
    ledger
        .record(rost)
        .expect("the roster is new to this ledger");
    ledger
}

#[test]
fn five_volunteers_carry_a_change_to_verified() {
    let setup = setup();
    let ledger = ledger(&setup.roster);
    let seats = sample::indices_of(&setup.round);
    assert_eq!(seats.len(), defaults::N);

    for &index in &seats {
        match volunteer_runs(&setup, index, &ledger) {
            ServeOutcome::Ran(served) => {
                assert_eq!(
                    served.attestation.signatures.len(),
                    1,
                    "one verifier, one signature"
                );
                assert!(
                    served
                        .attestation
                        .manifest
                        .claims
                        .verifier_challenge
                        .is_some(),
                    "the attestation is bound to this round's challenge, so it cannot be \
                     replayed into another round"
                );
            }
            other => panic!("expected a run, got {other:?}"),
        }
    }

    // A second poll finds the slot taken and does no work. This is the same guarantee a
    // crashed-and-restarted volunteer relies on.
    match volunteer_runs(&setup, seats[0], &ledger) {
        ServeOutcome::AlreadySubmitted => {}
        other => panic!("expected AlreadySubmitted, got {other:?}"),
    }

    let submissions = store::submissions(&setup.host, &setup.round).unwrap();
    assert_eq!(
        submissions.len(),
        defaults::N,
        "every slot held an attestation"
    );

    let mut verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &submissions,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("a verdict is computable");
    assert_eq!(verdict.state, QuorumState::Verified, "{}", verdict.detail);
    assert_eq!(verdict.agreeing, defaults::N);
    assert!(verdict.rejected.is_empty());
    assert!(verdict.missing.is_empty());
    assert!(verdict.state.mergeable());

    verdict
        .sign(&setup.owner)
        .expect("the owner signs the verdict");
    store::publish_verdict(&setup.host, &verdict).expect("the verdict publishes");
    let read_back = store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
        .unwrap()
        .expect("the verdict is readable");
    assert_eq!(read_back.digest().unwrap(), verdict.digest().unwrap());
    assert!(read_back.state.mergeable());
}

/// The tolerance the defaults buy: five seats, four agreements required, so one honest
/// outlier — a flaky test, a different CPU, a slow mirror — does not sink a change.
///
/// The dissent is not hidden: it is in `divergent`, which is what giti-msi.8's escalation
/// re-run and dispute report read. This is the boundary the acceptance criterion draws —
/// "the digests agree *and* policy is met" — and it is a policy choice, not a fact: the
/// next test turns the same evidence into `failed` by raising `required_agree`.
#[test]
fn one_dissent_is_verified_with_the_divergence_recorded() {
    let setup = setup();
    let seats = sample::indices_of(&setup.round);
    let attestations = sample::attest(&setup.round, &seats, sample::claimed_at_us(), |i| {
        (i == 0).then(|| "test result: FAILED. 1 failed".to_string())
    });
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(verdict.state, QuorumState::Verified, "{}", verdict.detail);
    assert_eq!(verdict.agreeing, defaults::N - 1);
    assert_eq!(
        verdict.divergent.len(),
        1,
        "the minority result is published, not swallowed: a verified-but-disputed quorum \
         has to be readable"
    );
    assert_eq!(verdict.reason, ReasonCode::AgreementReached);
}

/// The same five volunteers and one more dissenter, under a policy that demands
/// unanimity: the split cannot reach the threshold, so the answer is `failed`, and the
/// losing digests are published as evidence.
#[test]
fn a_split_that_cannot_reach_the_threshold_is_failed_and_names_both_results() {
    let mut setup = setup();
    // Re-open the round with `required_agree` at the seat count. A real owner sets this
    // in the round's policy; here it is the same field.
    setup.round.inputs.policy.required_agree = defaults::N;
    let seats = sample::indices_of(&setup.round);
    let attestations = sample::attest(&setup.round, &seats, sample::claimed_at_us(), |i| {
        (i < 2).then(|| "test result: FAILED. 2 failed".to_string())
    });
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(verdict.state, QuorumState::Failed, "{}", verdict.detail);
    assert_eq!(verdict.reason, ReasonCode::IrreconcilableDigests);
    assert_eq!(verdict.agreeing, defaults::N - 2);
    assert_eq!(verdict.divergent.len(), 1, "the minority group is recorded");
    assert!(!verdict.state.mergeable());
    assert!(
        verdict.result_digest.is_some(),
        "the winning digest is named even in a failure"
    );
}

#[test]
fn too_few_agreements_is_insufficient_not_verified() {
    // Four of the five turn up and all four agree. `required_agree` is 4, so this is
    // `verified` — the threshold is about agreements, not about attendance.
    let setup = setup();
    let seats = sample::indices_of(&setup.round);
    let four = &seats[..4];
    let attestations = sample::attest(&setup.round, four, sample::claimed_at_us(), |_| None);
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(verdict.state, QuorumState::Verified, "{}", verdict.detail);
    assert_eq!(
        verdict.missing.len(),
        1,
        "the silent seat is recorded, not ignored"
    );

    // Three is below the threshold: nobody disagreed, so the honest answer is
    // "not enough", and it must not be reported as a failure of the code under test.
    let three = &seats[..3];
    let attestations = sample::attest(&setup.round, three, sample::claimed_at_us(), |_| None);
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(
        verdict.state,
        QuorumState::Insufficient,
        "{}",
        verdict.detail
    );
    assert_eq!(verdict.reason, ReasonCode::NotEnoughAgreement);
    assert!(!verdict.state.mergeable());
}

#[test]
fn an_attestation_from_outside_the_round_is_not_a_vote() {
    let setup = setup();
    let seats = sample::indices_of(&setup.round);
    let mut attestations = sample::attest(&setup.round, &seats, sample::claimed_at_us(), |_| None);
    // A volunteer who was not selected signs an honest-looking manifest for the same
    // job. It cannot even be built against a seat it does not hold, so the strongest
    // version of this attack is a *stolen* seat signature: the store refuses the write.
    let outsider = sample::verifier_key(63);
    let error = store::publish_submission(
        &setup.host,
        &setup.round,
        &outsider.public_key().key_id(),
        &attestations[0],
    )
    .expect_err("a key with no seat has no slot");
    assert!(
        error.to_string().contains("no seat"),
        "the refusal should say why: {error}"
    );
    // And a stray document in the store never reaches the tally: `submissions` reads
    // seats, not whatever was written.
    attestations.push(attestations[0].clone());
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    // Two signatures from the same key are one vote, so the double-signed document does
    // not buy a second agreement either.
    assert_eq!(verdict.agreeing, defaults::N);
    assert_eq!(verdict.state, QuorumState::Verified);
}

#[test]
fn revoked_compromised_keys_lose_their_votes_mid_flight() {
    use gitiup_quorum::roster::{Revocation, RevocationReason};

    let setup = setup();
    let seats = sample::indices_of(&setup.round);
    let attestations = sample::attest(&setup.round, &seats, sample::claimed_at_us(), |_| None);
    let clean = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(clean.state, QuorumState::Verified);

    // The owner learns that two volunteers' keys were stolen and revokes them as
    // `compromised`, which voids what those keys already signed (ADR-0002 D9). Two is
    // the number that breaks the threshold: one would leave four agreeing, which is
    // still a quorum, and the verdict says so.
    let voided: Vec<Revocation> = setup.round.selected[..2]
        .iter()
        .map(|seat| {
            let mut revocation = Revocation::new(
                seat.key_id.clone(),
                RevocationReason::Compromised,
                setup.roster.epoch,
                sample::claimed_at_us(),
            );
            revocation
                .sign(&setup.owner)
                .expect("the owner may revoke a key they vouched for");
            revocation
        })
        .collect();
    let verdict = VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        &attestations,
        &voided,
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(
        verdict.state,
        QuorumState::Insufficient,
        "five votes minus two compromised ones is three, which is below the threshold"
    );
    assert_eq!(
        verdict.agreeing,
        defaults::N - 2,
        "the compromised keys' votes are voided; the rest still agree, and still are not \
         enough"
    );
    assert_eq!(
        verdict.rejected.len(),
        2,
        "voided votes are recorded, never dropped"
    );
}

#[test]
fn a_verifier_refuses_a_round_whose_roster_it_has_never_seen() {
    // The rollback guard: a volunteer that has already recorded epoch 41 will not serve a
    // round pinned to epoch 40, even though epoch 40 is a perfectly valid roster.
    let setup = setup();
    let key = sample::verifier_key(sample::indices_of(&setup.round)[0]);
    let mut old_round = setup.round.clone();
    old_round.inputs.roster_epoch = 40;
    let trusts = Trusts {
        owner: &setup.trust,
        selector: &setup.trust,
        ledger: Some(&ledger(&setup.roster)),
        now: sample::clock(),
    };
    let outcome = serve_once(
        &setup.host,
        &setup.roster,
        &old_round,
        &key,
        &trusts,
        &|_| unreachable!("a refused round must not run"),
    )
    .expect("the check itself does not fail");
    assert!(
        matches!(outcome, ServeOutcome::Refused(_)),
        "a stale epoch must be refused, got {outcome:?}"
    );
}

/// The same round, read by a stranger: the audit path, which needs no secret.
#[test]
fn a_stranger_can_audit_the_quorum_they_were_not_invited_to() {
    let setup = setup();
    let seats = sample::indices_of(&setup.round);
    let attestations = sample::attest(&setup.round, &seats, sample::claimed_at_us(), |_| None);
    store::publish_roster(&setup.host, &setup.roster).ok();

    // The stranger has: the roster, the round record, the attestations, and the public
    // policy. They re-derive the seats from the *published* seed and find them equal.
    let round = store::round_at(&setup.host, CHANGE, JOB, 0)
        .unwrap()
        .unwrap();
    let facts = round
        .verify(&setup.trust, &setup.roster)
        .expect("the record verifies against its pinned roster");
    assert_eq!(facts.selection.selected.len(), round.selected.len());
    assert!(
        round.seed.as_bytes().len() == 32,
        "the seed is published, which is what makes the audit possible"
    );

    let verdict = VerdictRecord::evaluate(
        &round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(verdict.state, QuorumState::Verified);
    // `explain` is the audit trail: every candidate, its score, and why it was in or out.
    let selection = round.selection(&setup.roster).unwrap();
    let explanation = selection.explain(&setup.roster);
    assert!(
        explanation.contains("score"),
        "the audit trail names scores"
    );
    let docs: Vec<&AttestationDoc> = attestations.iter().collect();
    assert_eq!(docs.len(), defaults::N);
}

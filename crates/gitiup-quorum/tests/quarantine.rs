//! Quarantine and reputation as selection inputs (giti-zp1.8).
//!
//! The rule under test is one sentence: **a verdict's history may only ever come back as a
//! `RoundInputs::excluding` input, and never as an edit to the roster.** Everything else in
//! the file is a corollary — that absence is scored but not punished, that the exclusions
//! are prospective, that the audit trail is readable by the key it is about, and that a
//! stranger's signature on a quarantine moves nothing.
//!
//! ```text
//!  verdict ──► Quarantine (owner-signed, N epochs) ──► RoundInputs::excluding ──► Round
//!      │                                                              │
//!      └─ missing seat: scored in reputation, refused as a ground ◄───┘
//! ```

use gitiup_attest::{SigningKey, TimeUs, Trust};
use gitiup_host::hosts::fs::FsHost;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::quarantine::{
    DEFAULT_QUARANTINE_EPOCHS, Ledger, MAX_QUARANTINE_EPOCHS, Quarantine, QuarantineLift,
    QuarantineReason, Standing, reason_for_rejection,
};
use gitiup_quorum::reputation::Report;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use gitiup_quorum::verdict::{Evaluation, QuorumState, VerdictRecord};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";
const EPOCH: u64 = 41;

struct Fixture {
    host: FsHost,
    _dir: tempfile::TempDir,
    owner: SigningKey,
    trust: Trust,
    roster: Roster,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let host = FsHost::create(dir.path()).expect("fs host");
    let owner = sample::owner_key();
    let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
    let roster = sample::roster_of(&owner, 7, EPOCH);
    store::publish_roster(&host, &roster).expect("the roster publishes");
    Fixture {
        host,
        _dir: dir,
        owner,
        trust,
        roster,
    }
}

/// Open and publish a round, then answer every seat but one, and make one of the answers
/// disagree: the verdict that comes out holds a counted majority, one divergence and one
/// `missing` — every row the quarantine rules care about.
fn round_with_history(fixture: &Fixture) -> (Round, VerdictRecord) {
    // Three of five agreeing is enough here on purpose: the verdict must reach a consensus
    // (`verified`) while still holding one divergence and one silent seat, and the
    // default 4-of-5 would make one diverging seat out of four a failed round instead.
    let inputs = sample::round_inputs_with(
        &fixture.roster,
        CHANGE,
        JOB,
        SelectionPolicy {
            required_agree: 3,
            ..Default::default()
        },
    );
    let secret = SelectionSecret::from_signing_key(&fixture.owner);
    let mut round = Round::open(&inputs, &fixture.roster, &secret).expect("the round opens");
    round.sign(&fixture.owner).expect("the selector signs");
    store::publish_round(&fixture.host, &round).expect("the round publishes");

    let seats = sample::indices_of(&round);
    let silent_index = seats[seats.len() - 1];
    let diverging_index = seats[seats.len() - 2];
    let answering: Vec<u8> = seats
        .iter()
        .copied()
        .filter(|index| *index != silent_index)
        .collect();
    let diverging_key = sample::verifier_key(diverging_index).public_key().key_id();
    let attestations = sample::attest(&round, &answering, sample::claimed_at_us(), |position| {
        let key = sample::verifier_key(answering[position])
            .public_key()
            .key_id();
        (key == diverging_key).then(|| "test result: FAILED. 41 passed, 1 failed".to_string())
    });
    let verdict = VerdictRecord::evaluate(
        &round,
        &fixture.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("the round tallies");
    (round, verdict)
}

/// Sign and publish a quarantine the way the CLI would: owner-signed, checked, filed.
fn publish(fixture: &Fixture, mut quarantine: Quarantine) -> Quarantine {
    quarantine.sign(&fixture.owner).expect("the owner signs");
    quarantine
        .verify(&fixture.trust)
        .expect("a trusted owner signed it");
    store::publish_quarantine(&fixture.host, &quarantine).expect("the record publishes");
    quarantine
}

#[test]
fn a_diverging_seat_is_a_ground_and_the_reason_is_divergence() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    assert_eq!(verdict.state, QuorumState::Verified);
    assert_eq!(verdict.divergent.len(), 1, "one seat disagreed");
    let diverging = verdict.divergent[0].keys[0].clone();

    let record = Quarantine::from_verdict(
        &verdict,
        &diverging,
        EPOCH,
        DEFAULT_QUARANTINE_EPOCHS,
        sample::clock(),
    )
    .expect("a divergence against a reached consensus is grounds");
    assert_eq!(record.reason, QuarantineReason::Divergence);
    assert_eq!(record.evidence.len(), 1);
    assert_eq!(record.evidence[0].code, "divergence");
    assert_eq!(
        record.evidence[0].verdict_digest,
        verdict.digest().expect("the verdict digests"),
        "the citation is the verdict the record was read out of"
    );
    assert_eq!(record.evidence[0].consensus, verdict.result_digest);
    assert!(record.detail.contains("consensus"));
}

#[test]
fn silence_is_scored_and_never_a_ground() {
    let fixture = fixture();
    let (round, verdict) = round_with_history(&fixture);
    assert_eq!(verdict.missing.len(), 1, "one seat never answered");
    let silent = verdict.missing[0].clone();

    let error = Quarantine::from_verdict(&verdict, &silent, EPOCH, 3, sample::clock())
        .expect_err("absence cannot buy a quarantine");
    assert!(
        error
            .to_string()
            .contains("silence is insufficient, not guilt")
    );

    // …and the scored half of the same fact, from the same verdict.
    let report = Report::from_verdicts(std::slice::from_ref(&verdict), Some(&fixture.roster));
    let sheet = report.sheet_for(&silent).expect("the silent seat is a row");
    assert_eq!(sheet.silent, 1);
    assert!(sheet.grounds().is_empty(), "and it is not a ground");
    assert!(sheet.silence_only());
    assert!(report.capacity_note().contains("went silent"));
    // Every seat the round filled is accounted for exactly once in the report.
    let seated: usize = report.sheets.iter().map(|sheet| sheet.seated).sum();
    assert_eq!(seated, round.selected.len());
}

#[test]
fn the_reason_vocabulary_refuses_the_words_for_absence() {
    for word in [
        "silent", "silence", "missing", "absence", "no_show", "late", "timeout",
    ] {
        let error = QuarantineReason::parse(word)
            .expect_err(&format!("{word} must be refused"))
            .to_string();
        assert!(error.contains("silence is insufficient"), "{word}: {error}");
    }
    for reason in QuarantineReason::ALL {
        assert_eq!(
            QuarantineReason::parse(reason.as_str()).expect("a real reason parses"),
            reason
        );
    }
    // And the codes a verdict writes are read the same way the reasons are.
    assert_eq!(
        reason_for_rejection("commitment_mismatch"),
        Some(QuarantineReason::CommitmentMismatch)
    );
    assert_eq!(
        reason_for_rejection("wrong_commit"),
        None,
        "a stale checkout is not the verifier's guilt"
    );
    assert_eq!(
        reason_for_rejection("revoked"),
        None,
        "that is revocation's job, with its own voids matrix"
    );
}

#[test]
fn a_reason_that_claims_a_fact_has_to_cite_it() {
    let fixture = fixture();
    let bare = Quarantine::new(
        fixture.roster.entries[0].key_id.clone(),
        QuarantineReason::Divergence,
        "they were wrong twice",
        EPOCH,
        3,
        sample::clock(),
        Vec::new(),
    );
    let error = bare
        .validate()
        .expect_err("no citation, no divergence claim");
    assert!(error.to_string().contains("cites no verdict"), "{error}");
    // `owner_decision` is the honest place for a judgement with no measurement behind it.
    let owned = Quarantine::new(
        fixture.roster.entries[0].key_id.clone(),
        QuarantineReason::OwnerDecision,
        "their owner asked to be kept out of this repository",
        EPOCH,
        3,
        sample::clock(),
        Vec::new(),
    );
    owned.validate().expect("a stated judgement is enough");
    assert!(!QuarantineReason::OwnerDecision.requires_evidence());
}

#[test]
fn a_quarantine_excludes_without_touching_the_roster() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let roster_before = fixture.roster.canonical_bytes().expect("roster bytes");
    let record = publish(
        &fixture,
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 3, sample::clock()).expect("grounds"),
    );

    // The exclusions the store hands a selector, applied the way every selector applies
    // them: as an input, through `excluding`.
    let applied =
        store::quarantine_exclusions(&fixture.host, &fixture.trust, EPOCH, sample::clock())
            .expect("the store answers");
    assert!(applied.named.contains(&diverging));
    assert!(applied.ignored.is_empty(), "nothing was quietly dropped");

    let inputs = sample::round_inputs(&fixture.roster, "chg-another", "build")
        .excluding(
            &fixture.roster,
            &applied.named.iter().cloned().collect::<Vec<_>>(),
        )
        .expect("the exclusion applies");
    let secret = SelectionSecret::from_signing_key(&fixture.owner);
    let selection = Selection::select(&fixture.roster, &inputs, &secret).expect("selection runs");
    assert!(
        !selection
            .selected
            .iter()
            .any(|seat| seat.key_id == diverging),
        "a quarantined key holds no seat"
    );
    assert!(
        inputs.exclusions.contains(&diverging),
        "and the round record says so: the exclusion is signed into the round, not applied \
         quietly downstream"
    );

    // The roster is byte for byte what it was: no epoch, no entry, no tier moved.
    assert_eq!(
        fixture.roster.canonical_bytes().expect("roster bytes"),
        roster_before,
        "quarantine is an exclusion input, never a roster edit"
    );
    assert!(
        store::roster_at(&fixture.host, EPOCH)
            .expect("the epoch reads back")
            .expect("it is published")
            .canonical_bytes()
            .expect("bytes")
            == roster_before
    );
    let read_back = store::list_quarantines(&fixture.host).expect("read the trail");
    assert_eq!(read_back.len(), 1);
    assert_eq!(read_back[0], record);
}

#[test]
fn exclusion_is_prospective_and_expires_by_the_epoch_it_names() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let record =
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 3, sample::clock()).expect("grounds");

    assert!(!record.covers(&diverging, EPOCH - 1, sample::clock()));
    assert!(record.covers(&diverging, EPOCH, sample::clock()));
    assert!(record.covers(&diverging, EPOCH + 2, sample::clock()));
    assert!(!record.covers(&diverging, EPOCH + 3, sample::clock()));
    assert_eq!(record.remaining_epochs(EPOCH), 3);
    assert_eq!(record.ends_epoch(), EPOCH + 3);

    let ledger = Ledger::new(vec![record.clone()], Vec::new()).expect("the ledger validates");
    assert!(matches!(
        ledger.standing(&diverging, EPOCH + 1, sample::clock()),
        Standing::Active { remaining: 2, .. }
    ));
    assert!(matches!(
        ledger.standing(&diverging, EPOCH + 9, sample::clock()),
        Standing::Expired { .. }
    ));
    // A round pinned before the quarantine is untouched by it: prospective only.
    assert!(
        !ledger
            .exclusions(EPOCH - 1, sample::clock())
            .contains(&diverging)
    );
    assert!(
        ledger
            .exclusions(EPOCH, sample::clock())
            .contains(&diverging)
    );
    assert!(
        !ledger
            .exclusions(EPOCH + 3, sample::clock())
            .contains(&diverging)
    );
}

#[test]
fn a_quarantine_is_bounded_and_a_lift_names_the_record_it_ends() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let record = publish(
        &fixture,
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 3, sample::clock()).expect("grounds"),
    );

    // A quarantine past the bound is a roster edit wearing a costume.
    let forever = Quarantine::from_verdict(
        &verdict,
        &diverging,
        EPOCH,
        MAX_QUARANTINE_EPOCHS + 1,
        sample::clock(),
    )
    .expect("the verdict still supports it");
    let error = forever.validate().expect_err("but the bound does not");
    assert!(error.to_string().contains("roster edit"), "{error}");

    // A lift that rewrites a past that already held is refused.
    let backdated = QuarantineLift::new(&record, EPOCH - 1, sample::clock(), None)
        .expect_err("a lift cannot un-happen an epoch");
    assert!(
        backdated.to_string().contains("before the quarantine"),
        "{backdated}"
    );

    let mut lift = QuarantineLift::new(
        &record,
        EPOCH + 1,
        sample::clock(),
        Some("appeal granted".into()),
    )
    .expect("a forward lift is fine");
    lift.sign(&fixture.owner).expect("the owner signs");
    lift.verify(&fixture.trust).expect("and is trusted");
    store::publish_lift(&fixture.host, &lift).expect("the lift publishes");

    let ledger = store::quarantine_ledger(&fixture.host).expect("the ledger reads");
    assert!(
        !ledger
            .exclusions(EPOCH + 1, sample::clock())
            .contains(&diverging),
        "lifted from epoch {}; the next round may seat it",
        lift.effective_epoch
    );
    assert!(
        ledger
            .exclusions(EPOCH, sample::clock())
            .contains(&diverging)
    );
    assert!(matches!(
        ledger.standing(&diverging, EPOCH + 1, sample::clock()),
        Standing::Lifted { .. }
    ));
    assert!(ledger.lifts.iter().all(|lift| lift.key_id == record.key_id
        && lift.quarantine_digest == record.digest().expect("digest")));
}

#[test]
fn a_strangers_quarantine_is_public_and_applies_to_nobody() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let stranger = sample::verifier_key(63);
    let stranger_trust = Trust::KeyIds([stranger.public_key().key_id()].into_iter().collect());

    let mut record =
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 3, sample::clock()).expect("grounds");
    record.sign(&stranger).expect("anyone may sign one");
    record
        .verify_signatures()
        .expect("and it is a real signature by the issuer it names");
    store::publish_quarantine(&fixture.host, &record).expect("and the store holds it publicly");

    // The excluded key can read why with no keys at all — the audit trail is public.
    assert!(!Trust::None.trusts(&stranger.public_key().key_id()));
    let trail = store::list_quarantines(&fixture.host).expect("the trail is public");
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].reason, QuarantineReason::Divergence);
    assert!(!trail[0].detail.is_empty());
    assert_eq!(trail[0].evidence[0].change_id, CHANGE);

    // …but it is not a selection input unless a trusted owner signed it.
    let applied =
        store::quarantine_exclusions(&fixture.host, &fixture.trust, EPOCH, sample::clock())
            .expect("the store answers");
    assert!(
        applied.named.is_empty(),
        "a stranger's signature excludes nobody"
    );
    assert_eq!(applied.ignored.len(), 1);
    assert!(
        applied.ignored[0].1.contains("trusts"),
        "{:?}",
        applied.ignored
    );
    record
        .verify(&stranger_trust)
        .expect("to its own author it is signed");
}

#[test]
fn two_quarantines_are_two_records_and_neither_overwrites_the_other() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let first = publish(
        &fixture,
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 1, sample::clock()).expect("grounds"),
    );
    let later = TimeUs(sample::clock().as_us() + 1_000_000);
    let second = publish(
        &fixture,
        Quarantine::from_verdict(&verdict, &diverging, EPOCH + 1, 2, later).expect("grounds"),
    );
    store::publish_quarantine(&fixture.host, &first).expect("a retry is idempotent");
    assert_eq!(
        store::list_quarantines(&fixture.host)
            .expect("both records stand")
            .len(),
        2,
        "the retry rewrote nothing, and two records about one key are a trail"
    );
    assert_ne!(
        first.digest().expect("digest"),
        second.digest().expect("digest")
    );
    assert_eq!(
        store::quarantine_exclusions(&fixture.host, &fixture.trust, EPOCH + 1, sample::clock())
            .expect("the store answers")
            .named
            .len(),
        1,
        "two records about one key exclude one key, not twice as hard"
    );
}

#[test]
fn a_failed_verdict_names_no_divergence_for_anybody() {
    let fixture = fixture();
    let inputs = sample::round_inputs(&fixture.roster, CHANGE, JOB);
    let secret = SelectionSecret::from_signing_key(&fixture.owner);
    let mut round = Round::open(&inputs, &fixture.roster, &secret).expect("opens");
    round.sign(&fixture.owner).expect("signed");
    let seats = sample::indices_of(&round);
    // Half the seats sign one answer and half another: no group reaches the threshold.
    let attestations = sample::attest(&round, &seats, sample::claimed_at_us(), |position| {
        (position % 2 == 0).then(|| "test result: FAILED. 0 passed".to_string())
    });
    let verdict = VerdictRecord::evaluate(
        &round,
        &fixture.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("tallies");
    assert_ne!(
        verdict.state,
        QuorumState::Verified,
        "no consensus was reached"
    );
    assert!(
        !verdict.divergent.is_empty(),
        "and somebody was in the minority"
    );
    let loser = verdict.divergent[0].keys[0].clone();
    let error = Quarantine::from_verdict(&verdict, &loser, EPOCH, 3, sample::clock())
        .expect_err("with no consensus, nobody diverged from it");
    assert!(error.to_string().contains("no consensus"), "{error}");
    // Reputation scores the same rows and does not call them divergence either.
    let report = Report::from_verdicts(&[verdict], Some(&fixture.roster));
    let sheet = report.sheet_for(&loser).expect("a row");
    assert_eq!(sheet.divergent, 0);
    assert!(sheet.contested > 0);
    assert!(sheet.grounds().is_empty());
}

#[test]
fn a_stalled_roster_cannot_make_a_quarantine_last_forever() {
    let fixture = fixture();
    let (_round, verdict) = round_with_history(&fixture);
    let diverging = verdict.divergent[0].keys[0].clone();
    let mut record =
        Quarantine::from_verdict(&verdict, &diverging, EPOCH, 3, sample::clock()).expect("grounds");
    // Three epochs at the roster's own published interval: what the CLI writes.
    record.expires_at_us =
        Quarantine::expires_after_epochs(sample::clock(), fixture.roster.epoch_interval_us, 3);
    assert!(record.expires_at_us.is_some());
    let much_later = TimeUs(record.expires_at_us.expect("bound") + 1);
    assert!(
        !record.covers(&diverging, EPOCH, much_later),
        "the clock bound bites even though epoch {EPOCH} is still the current one"
    );
    let ledger = Ledger::new(vec![record], Vec::new()).expect("the ledger validates");
    assert!(matches!(
        ledger.standing(&diverging, EPOCH, much_later),
        Standing::Expired { by_clock: true, .. }
    ));
    assert!(
        !ledger.exclusions(EPOCH, much_later).contains(&diverging),
        "and the store stops applying it, saying why rather than vanishing"
    );
}

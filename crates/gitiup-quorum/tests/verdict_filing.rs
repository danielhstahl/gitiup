//! A filed verdict is **superseded, never edited** (giti-zp1.4).
//!
//! `refs/gitiup/verdict/<change>/<job>` holds one signed statement, and the rule that
//! decides whether a write may move it is the difference between an audit trail and an
//! editable file. So the four outcomes of [`store::file_verdict`] are tested here, against
//! a real store, with real signed records:
//!
//! | the ref holds | the write | outcome |
//!|---------------|-----------|---------|
//!| nothing | any verdict | `filed` |
//!| this verdict | the same answer | `unchanged` — a retry is not an edit |
//!| attempt N's verdict | a different answer at attempt N | `refused` |
//!| attempt N's verdict | attempt N+1's verdict | `superseded` |
//!| attempt N+1's verdict | attempt N's verdict | `refused` — attempts only move forward |
//!
//! The tempting bug is in the second row: a verdict carries the time it was written, so
//! every re-run produces different bytes. Comparing canonical bytes would refuse every
//! honest retry; comparing "the answer" is what makes the third row mean something.

use gitiup_attest::{SigningKey, Trust};
use gitiup_host::hosts::fs::FsHost;
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use gitiup_quorum::verdict::{Evaluation, QuorumState, VerdictRecord};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";

struct Setup {
    host: FsHost,
    _dir: tempfile::TempDir,
    owner: SigningKey,
    trust: Trust,
    roster: Roster,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().expect("temp dir");
    let host = FsHost::create(dir.path()).expect("fs host");
    let owner = sample::owner_key();
    let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
    let roster = sample::roster_of(&owner, 7, 41);
    store::publish_roster(&host, &roster).expect("the roster publishes");
    Setup {
        host,
        _dir: dir,
        owner,
        trust,
        roster,
    }
}

/// Open a round at one attempt, publish it, and have every seat submit an agreeing
/// result, so the tally is `verified` and the tests can vary one thing at a time.
fn round(setup: &Setup, attempt: u64) -> Round {
    let mut inputs = sample::round_inputs(&setup.roster, CHANGE, JOB);
    inputs.attempt = attempt;
    let secret = SelectionSecret::from_signing_key(&setup.owner);
    let mut round = Round::open(&inputs, &setup.roster, &secret).expect("the round opens");
    round.sign(&setup.owner).expect("the selector signs");
    store::publish_round(&setup.host, &round).expect("the round publishes");
    store::round_at(&setup.host, CHANGE, JOB, attempt)
        .expect("read the round back")
        .expect("it is published")
}

/// The owner's tally of a round, signed.
fn tally(setup: &Setup, round: &Round) -> VerdictRecord {
    let seats = sample::indices_of(round);
    let attestations = sample::attest(round, &seats, sample::claimed_at_us(), |_| None);
    // The slots are shared between attempts (the reveal ref is per key, not per
    // attempt), so only the attempt this attestation was made for can be evaluated.
    if round.inputs.attempt != 0 {
        let mut verdict = VerdictRecord::evaluate(
            round,
            &setup.roster,
            &[],
            &[],
            &Evaluation::at(sample::clock()),
        )
        .expect("an empty round still has an answer");
        verdict.sign(&setup.owner).expect("the owner signs");
        return verdict;
    }
    let mut verdict = VerdictRecord::evaluate(
        round,
        &setup.roster,
        &attestations,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .expect("the round tallies");
    assert_eq!(verdict.state, QuorumState::Verified);
    verdict.sign(&setup.owner).expect("the owner signs");
    verdict
}

#[test]
fn a_first_verdict_is_filed_and_reads_back_as_the_owner_s() {
    let setup = setup();
    let round = round(&setup, 0);
    let verdict = tally(&setup, &round);

    let filing = store::file_verdict(&setup.host, &verdict, &setup.trust).expect("file it");
    assert_eq!(filing.token(), "filed");
    let read_back = store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
        .expect("read it")
        .expect("it is there");
    assert_eq!(
        read_back, verdict,
        "the store holds these bytes, not a paraphrase"
    );
}

#[test]
fn the_same_answer_written_twice_is_a_retry_and_not_an_edit() {
    let setup = setup();
    let round = round(&setup, 0);
    let filed = tally(&setup, &round);
    assert_eq!(
        store::file_verdict(&setup.host, &filed, &setup.trust)
            .expect("file it")
            .token(),
        "filed"
    );

    // The same conclusion reached an hour later, by a different owner key: different
    // bytes, same answer.
    let mut retry = filed.clone();
    retry.issued_at_us += 3_600_000_000;
    retry.signatures.clear();
    retry.sign(&setup.owner).expect("re-sign");
    assert_ne!(
        retry.canonical_bytes().unwrap(),
        filed.canonical_bytes().unwrap(),
        "the bytes *do* differ: it is the answer that is the same"
    );
    assert!(retry.same_answer(&filed), "same_answer is the comparison");
    let filing = store::file_verdict(&setup.host, &retry, &setup.trust).expect("file again");
    assert_eq!(filing.token(), "unchanged");
    assert_eq!(
        store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
            .expect("read it")
            .expect("still there")
            .issued_at_us,
        filed.issued_at_us,
        "the first signature is the record"
    );
}

#[test]
fn a_different_answer_at_the_same_attempt_is_refused() {
    let setup = setup();
    let round = round(&setup, 0);
    let filed = tally(&setup, &round);
    store::file_verdict(&setup.host, &filed, &setup.trust).expect("file it");

    // The awkward verifier "went home": the same attempt now tallies to a tidy answer.
    // That is precisely the edit the rule exists to refuse.
    let mut rewritten = filed.clone();
    rewritten.state = QuorumState::Failed;
    rewritten.reason = gitiup_quorum::verdict::ReasonCode::IrreconcilableDigests;
    rewritten.detail = "the verifiers disagreed".to_string();
    rewritten.signatures.clear();
    rewritten.sign(&setup.owner).expect("re-sign");

    let filing = store::file_verdict(&setup.host, &rewritten, &setup.trust).expect("try again");
    let reason = filing.refusal().expect("a refusal, with a reason");
    assert!(reason.contains("superseded by a later attempt"), "{reason}");
    assert_eq!(
        store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
            .expect("read it")
            .expect("still there")
            .state,
        QuorumState::Verified,
        "the record did not move"
    );
}

#[test]
fn a_later_attempt_supersedes_and_an_earlier_one_cannot() {
    let setup = setup();
    let first = round(&setup, 0);
    let filed = tally(&setup, &first);
    store::file_verdict(&setup.host, &filed, &setup.trust).expect("file attempt 0");

    // Escalation: attempt 1, a fresh seed, and whatever its own evidence says.
    let second = round(&setup, 1);
    let escalation = tally(&setup, &second);
    assert_eq!(escalation.attempt, 1);
    let filing =
        store::file_verdict(&setup.host, &escalation, &setup.trust).expect("file attempt 1");
    assert_eq!(filing.token(), "superseded");
    assert_eq!(
        store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
            .expect("read it")
            .expect("there")
            .attempt,
        1,
        "the later attempt owns the ref now"
    );

    // …and walking it back is refused: attempts only move forward.
    let filing =
        store::file_verdict(&setup.host, &filed, &setup.trust).expect("try attempt 0 again");
    let reason = filing.refusal().expect("a refusal");
    assert!(reason.contains("later attempt"), "{reason}");
    assert_eq!(
        store::verdict_at(&setup.host, CHANGE, JOB, &setup.trust)
            .expect("read it")
            .expect("there")
            .attempt,
        1
    );
}

#[test]
fn a_verdict_the_owner_did_not_sign_is_never_believed_enough_to_compare() {
    let setup = setup();
    let round = round(&setup, 0);
    let mut verdict = tally(&setup, &round);
    verdict.signatures.clear();
    verdict
        .sign(&sample::verifier_key(0))
        .expect("somebody signs it");
    store::publish_verdict(&setup.host, &verdict).expect("the store is not the trust root");

    let error = store::file_verdict(&setup.host, &tally(&setup, &round), &setup.trust)
        .expect_err("the incumbent cannot be read as the owner's");
    assert_eq!(
        error.exit_code(),
        6,
        "an untrusted record is a refusal: {error}"
    );
}

#[test]
fn same_answer_compares_every_fact_and_ignores_the_act_of_writing() {
    let setup = setup();
    let round = round(&setup, 0);
    let one = tally(&setup, &round);

    let mut other = one.clone();
    other.issued_at_us += 1;
    other.signatures.clear();
    other.sign(&setup.owner).expect("re-sign");
    assert!(
        one.same_answer(&other),
        "the clock and the signatures are not the answer"
    );

    for change in [
        "state",
        "detail",
        "agreeing",
        "required_agree",
        "result_digest",
        "divergent",
        "missing",
        "rejected",
        "round_digest",
        "policy_digest",
        "attempt",
    ] {
        let mut edited = one.clone();
        match change {
            "state" => edited.state = QuorumState::Insufficient,
            "detail" => edited.detail.push('.'),
            "agreeing" => edited.agreeing += 1,
            "required_agree" => edited.required_agree += 1,
            "result_digest" => edited.result_digest = Some(gitiup_attest::Digest::sha256(b"other")),
            "divergent" => edited.missing.push("SHA256:nobody".to_string()),
            "missing" => edited.missing.push("SHA256:nobody".to_string()),
            "rejected" => edited.rejected.push(gitiup_quorum::verdict::Rejection {
                key_id: "SHA256:nobody".to_string(),
                identity: None,
                code: "nope".to_string(),
                detail: "nope".to_string(),
                exit_code: Some(6),
            }),
            "round_digest" => edited.round_digest = gitiup_attest::Digest::sha256(b"other"),
            "policy_digest" => edited.policy_digest = gitiup_attest::Digest::sha256(b"other"),
            "attempt" => edited.attempt += 1,
            _ => unreachable!(),
        }
        assert!(
            !one.same_answer(&edited),
            "a verdict that differs in `{change}` is not the same answer"
        );
    }
}

//! A `tier: quorum` attestation, end to end (giti-zp1.5).
//!
//! The ticket's acceptance criterion has two halves and they are the same fact seen from
//! opposite ends: a quorum-tier document is *generated only from* a `VerdictRecord`, and
//! it is *accepted only by* re-deriving that verdict from the round record and the
//! published submissions. So this file does the honest thing twice and the dishonest thing
//! once:
//!
//! ```text
//! roster ─► round ─► five seats filled ─► VerdictRecord::evaluate ─► verified
//!                                                    │
//!                                  QuorumAttestation::from_verdict ─► signed, published
//!                                                    │
//!                     rederive(…): round + roster + submissions + revocations
//!                                    └─► VerdictRecord::evaluate again ─► it matches
//!
//! and then: a document whose evidence has moved — a revoked seat, a tampered digest, a
//! round that is not in this store — is refused, with the exit code a gate branches on.
//! ```

use gitiup_attest::{AttestationDoc, Digest, GitOid, SigningKey, Tier, Trust};
use gitiup_host::Actor;
use gitiup_host::attest::{self};
use gitiup_host::{FsHost, Oid};
use gitiup_quorum::attestation::{QuorumAttestation, rederive};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::prelude::*;
use gitiup_quorum::sample;
use gitiup_quorum::store;
use gitiup_quorum::verdict::{Evaluation, QuorumState, VerdictRecord};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";

struct Scene {
    _dir: tempfile::TempDir,
    host: FsHost,
    owner: SigningKey,
    trust: Trust,
    roster: Roster,
    round: Round,
    evaluation: Evaluation,
}

impl Scene {
    /// A store the owner has run: a published roster, a published round, and every seat
    /// filled by its own volunteer, so the honest tally is `verified`.
    fn honest() -> Scene {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path()).expect("fs host");
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("publish the roster");
        let inputs = sample::round_inputs(&roster, CHANGE, JOB);
        let secret = SelectionSecret::from_signing_key(&owner);
        let mut round = Round::open(&inputs, &roster, &secret).expect("the round opens");
        round.sign(&owner).expect("the selector signs");
        store::publish_round(&host, &round).expect("publish the round");
        let round = store::round_at(&host, CHANGE, JOB, 0)
            .expect("read the round")
            .expect("the round is there");
        let seats = sample::indices_of(&round);
        let docs = sample::attest(&round, &seats, sample::claimed_at_us(), |_| None);
        for (position, doc) in docs.iter().enumerate() {
            let key_id = sample::verifier_key(seats[position]).public_key().key_id();
            store::publish_submission(&host, &round, &key_id, doc).expect("the seat is filled");
        }
        Scene {
            _dir: dir,
            host,
            owner,
            trust,
            roster,
            round,
            evaluation: Evaluation::at(sample::clock()),
        }
    }

    fn host(&self) -> &FsHost {
        &self.host
    }

    /// The verdict this store's evidence supports.
    fn verdict(&self) -> VerdictRecord {
        let submissions = store::submissions(self.host(), &self.round).expect("submissions");
        VerdictRecord::evaluate(
            &self.round,
            &self.roster,
            &submissions,
            &store::list_revocations(self.host(), &self.trust).expect("revocations"),
            &self.evaluation,
        )
        .expect("the tally runs")
    }

    /// The attestation the honest verdict earns, signed by the key that asserts it.
    fn attestation(&self) -> QuorumAttestation {
        let mut attestation =
            QuorumAttestation::from_verdict(&self.round, &self.verdict()).expect("attestable");
        attestation.sign(&self.owner).expect("the owner asserts it");
        attestation
    }

    /// File it where attestations live, advertised for the head it speaks about.
    fn publish(&self, attestation: &QuorumAttestation) -> Oid {
        let subject = Oid::from_hex(&self.round.inputs.head_oid.hex()).expect("the head is an oid");
        let published = attest::publish(
            self.host(),
            &subject,
            &attestation.canonical_bytes().expect("canonical"),
            Actor::from("owner"),
        )
        .expect("publish the quorum attestation");
        published.digest
    }

    fn rederive(&self, attestation: &QuorumAttestation) -> gitiup_quorum::Result<()> {
        let rederived = rederive(self.host(), attestation, &self.trust, &self.evaluation)?;
        attestation.matches(&rederived.round, &rederived.verdict)
    }

    /// The owner revokes one volunteer for `compromised`, which voids what it signed.
    fn revoke(&self, index: u8) {
        let key = sample::verifier_key(index);
        let mut revocation = Revocation::new(
            key.public_key().key_id(),
            RevocationReason::Compromised,
            self.roster.epoch,
            sample::claimed_at_us(),
        );
        revocation.issuer = self.owner.public_key().key_id();
        revocation
            .sign(&self.owner)
            .expect("the owner signs the revocation");
        store::publish_revocation(self.host(), &revocation).expect("publish the revocation");
    }

    fn head(&self) -> GitOid {
        self.round.inputs.head_oid.clone()
    }
}

#[test]
fn a_verified_verdict_makes_a_document_the_store_can_vouch_for() {
    let scene = Scene::honest();
    let verdict = scene.verdict();
    assert_eq!(verdict.state, QuorumState::Verified);

    let attestation = scene.attestation();
    assert_eq!(attestation.tier, Tier::Quorum);
    assert_eq!(attestation.state, QuorumState::Verified);
    // The bindings the ticket names, each one the round's and none of them invented.
    assert_eq!(
        attestation.round_id,
        scene.round.inputs.round_id_display().unwrap()
    );
    assert_eq!(attestation.round_digest, scene.round.digest().unwrap());
    assert_eq!(attestation.roster_epoch, scene.roster.epoch);
    assert_eq!(attestation.roster_digest, scene.roster.digest().unwrap());
    assert_eq!(attestation.result_digest, verdict.result_digest.unwrap());
    assert_eq!(attestation.counted.len(), verdict.agreeing);
    assert_eq!(attestation.head_oid, scene.head());

    let digest = scene.publish(&attestation);
    let bytes = attest::fetch(scene.host(), &digest)
        .expect("fetch")
        .expect("it is in the store");
    let read = QuorumAttestation::from_canonical_bytes(&bytes, &scene.trust).expect("read back");
    assert_eq!(read, attestation);

    // And the store agrees with every word of it.
    scene
        .rederive(&attestation)
        .expect("the verdict re-derives exactly");
}

#[test]
fn the_document_names_the_seats_and_carries_no_attestation_of_its_own() {
    let scene = Scene::honest();
    let attestation = scene.attestation();
    let json = serde_json::to_string(&attestation).expect("serialisable");
    // It is a record *about* attestations: the seats are named, their work is not copied.
    for seat in &attestation.counted {
        assert!(json.contains(&seat.key_id));
        assert!(json.contains(&seat.identity));
    }
    for forbidden in [
        "\"stdout\"",
        "\"steps\"",
        "\"manifest\"",
        "\"payload_type\"",
        "\"script\"",
        "\"annotations\"",
    ] {
        assert!(
            !json.contains(forbidden),
            "a record about attestations must not duplicate one: {forbidden}"
        );
    }
    // The evidence it points at is still fetched from the seats it names.
    let submissions = store::submissions(scene.host(), &scene.round).unwrap();
    assert_eq!(submissions.len(), attestation.counted.len());
}

#[test]
fn a_document_that_only_labels_itself_quorum_is_refused_with_exit_6() {
    let scene = Scene::honest();
    let honest = scene.attestation();

    // Same shape, wrong claim: the digest it cites is not the one the quorum agreed.
    let mut liar = honest.clone();
    liar.result_digest = Digest::sha256(b"a result nobody produced");
    let error = scene.rederive(&liar).unwrap_err();
    assert_eq!(error.exit_code(), 8, "{error}");
    assert!(error.message().contains("agreed"), "{error}");

    // And one that inflates the agreement: the same number of words, a different fact.
    let mut liar = honest.clone();
    liar.agreeing = liar.counted.len() + 3;
    let error = scene.rederive(&liar).unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(error.message().contains("agree"), "{error}");

    // An unsigned one is refused too: nobody said it, so nobody is believed.
    let unsigned = QuorumAttestation::from_verdict(&scene.round, &scene.verdict()).unwrap();
    assert_eq!(unsigned.verify(&scene.trust).unwrap_err().exit_code(), 6);
}

#[test]
fn a_document_with_no_round_behind_it_is_refused() {
    let scene = Scene::honest();
    let mut attestation = scene.attestation();
    // The same words, about a job this store never opened.
    attestation.job_id = "build/matrix/never-opened".into();
    let error = rederive(
        scene.host(),
        &attestation,
        &scene.trust,
        &Evaluation::at(sample::clock()),
    )
    .unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(error.message().contains("holds no round"), "{error}");
    assert!(
        error.hint().unwrap_or_default().contains("faith"),
        "{error}"
    );
}

#[test]
fn a_seat_revoked_afterwards_undoes_the_attestation() {
    let scene = Scene::honest();
    let attestation = scene.attestation();
    scene.publish(&attestation);
    // The round is re-tallied *now*, with the revocation the owner filed afterwards: the
    // quorum is no longer the quorum the document names, and the document goes with it.
    let seats = sample::indices_of(&scene.round);
    scene.revoke(seats[0]);
    let after = scene.verdict();
    let differences = attestation.differences(&scene.round, &after);
    assert!(
        !differences.is_empty(),
        "the tally moved, so the claim must fail"
    );
    assert!(
        differences
            .iter()
            .any(|(code, _)| *code == "seats" || *code == "verdict"),
        "{differences:?}"
    );
    let error = scene.rederive(&attestation).unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
}

#[test]
fn a_document_that_cites_another_round_is_a_digest_mismatch() {
    let scene = Scene::honest();
    let attestation = scene.attestation();

    // Escalation: attempt 1, a fresh seed and so a different digest.
    let mut inputs = sample::round_inputs(&scene.roster, CHANGE, JOB);
    inputs.attempt = 1;
    let secret = SelectionSecret::from_signing_key(&scene.owner);
    let mut round = Round::open(&inputs, &scene.roster, &secret).expect("attempt 1 opens");
    round.sign(&scene.owner).expect("the selector signs");
    store::publish_round(scene.host(), &round).expect("publish attempt 1");
    let attempt_one = store::round_at(scene.host(), CHANGE, JOB, 1)
        .expect("read it")
        .expect("it is there");
    assert_ne!(attempt_one.digest().unwrap(), attestation.round_digest);

    // The document speaks about attempt 0, and attempt 0 still answers for it.
    scene.rederive(&attestation).expect("attempt 0 still holds");

    // Cite the other round, and the digest binding is what catches it: this is not a
    // policy disagreement about the quorum, it is a document that is not about the
    // evidence in front of it.
    let mut lying = attestation.clone();
    lying.round_digest = attempt_one.digest().unwrap();
    assert_eq!(scene.rederive(&lying).unwrap_err().exit_code(), 8);
}

#[test]
fn a_failed_verdict_produces_no_document_at_all() {
    // One volunteer disagrees: the tally is `failed`, and a disagreement has no
    // `ResultDigest` to carry to the quorum tier.
    let dir = tempfile::tempdir().expect("temp dir");
    let host = FsHost::create(dir.path()).expect("fs host");
    let owner = sample::owner_key();
    let roster = sample::roster_of(&owner, 7, 41);
    store::publish_roster(&host, &roster).unwrap();
    let inputs = sample::round_inputs(&roster, CHANGE, JOB);
    let secret = SelectionSecret::from_signing_key(&owner);
    let mut round = Round::open(&inputs, &roster, &secret).unwrap();
    round.sign(&owner).unwrap();
    let seats = sample::indices_of(&round);
    // Two of the five disagree with the other three, so no digest reaches the required
    // four: that is `failed`, not `insufficient`, and there is nothing to attest.
    let docs: Vec<AttestationDoc> = sample::attest(&round, &seats, sample::claimed_at_us(), |i| {
        (i < 2).then(|| format!("test result: FAILED. {} passed", 40 + i))
    });
    let verdict = VerdictRecord::evaluate(
        &round,
        &roster,
        &docs,
        &[],
        &Evaluation::at(sample::clock()),
    )
    .unwrap();
    assert_eq!(verdict.state, QuorumState::Failed);
    let error = QuorumAttestation::from_verdict(&round, &verdict).unwrap_err();
    assert_eq!(error.exit_code(), 6);
    assert!(error.message().contains("failed"), "{error}");
}

//! The roster and registration path, end to end, through a real store
//! (giti-msi.2's acceptance criteria, as code).
//!
//! Three things are under test here, and none of them is "the struct round-trips":
//!
//! 1. **a signed roster round-trips through the host** — published into the `roster`
//!    namespace, readable at `refs/gitiup/roster` *and* at its epoch ref, and byte-for-byte
//!    the document that was signed, because a round pins that digest;
//! 2. **an unapproved key cannot submit an attestation** — refused at the store, with a
//!    code that says which kind of "not approved" it is, rather than counted and then
//!    subtracted at the tally;
//! 3. **claimed capabilities survive the trip** — arch, RAM, disk, image cache, sandbox
//!    backend and level arrive in the epoch exactly as the key signed them, which is what
//!    makes them an eligibility input rather than a rumour.
//!
//! Everything goes through [`gitiup_host::Host`] so the fs host in this test and the
//! bucket-as-forge in production take the same code path.

use gitiup_attest::{Digest, SigningKey, Trust};
use gitiup_host::RefStore as _;
use gitiup_quorum::capability::{Capabilities, Requirements, RosterTier};
use gitiup_quorum::derive::SelectionSecret;
use gitiup_quorum::error::Error;
use gitiup_quorum::gate::code;
use gitiup_quorum::prelude::*;
use gitiup_quorum::roster::RevocationReason;
use gitiup_quorum::{sample, store};

const CHANGE: &str = "chg-000000000000f001";
const JOB: &str = "build/matrix/linux-x86_64";

/// The volunteer's half: a self-signed sign-up for a machine with named capabilities.
fn signup(key: &SigningKey, capabilities: Capabilities) -> SignUp {
    let entry = RosterEntry {
        key_id: key.public_key().key_id(),
        public_key: key.public_key().to_openssh(),
        identity: key.public_key().key_id(),
        // A sign-up may claim a key and a capability set, not a vouch.
        tier: RosterTier::Anonymous,
        capabilities,
        epochs_valid: EpochWindow::open_from(0),
        self_signature: None,
    };
    SignUp::new(entry, key).expect("a sign-up signs with the key it registers")
}

/// An honest, specific claim: x86_64, 32 GB, 256 GB, one pinned image, docker at level 2.
fn claimed() -> Capabilities {
    Capabilities {
        arch: vec!["x86_64".into(), "aarch64".into()],
        ram_mb: 32_768,
        disk_mb: 262_144,
        image_cache: vec![sample::image_digest()],
        can_pull: false,
        sandboxes: vec!["docker".into(), "unshare".into()],
        sandbox_level: 2,
    }
}

struct Owner {
    host: gitiup_host::hosts::fs::FsHost,
    _dir: tempfile::TempDir,
    key: SigningKey,
    trust: Trust,
}

fn owner() -> Owner {
    let dir = tempfile::tempdir().expect("temp dir");
    let host = gitiup_host::hosts::fs::FsHost::create(dir.path()).expect("fs host");
    let key = sample::owner_key();
    let trust = Trust::KeyIds([key.public_key().key_id()].into_iter().collect());
    Owner {
        host,
        _dir: dir,
        key,
        trust,
    }
}

/// The owner's act: admit these sign-ups into a new epoch, sign it, publish it.
fn approve(owner: &Owner, previous: Option<&Roster>, additions: Vec<RosterEntry>) -> Roster {
    let now = sample::clock().as_us();
    let interval = sample::EPOCH_INTERVAL_US;
    let base = match previous {
        Some(roster) => roster.clone(),
        None => Roster::new(
            Roster::next_epoch(0, now, interval).unwrap(),
            Digest::sha256(b"gitiup-roster-1 genesis"),
            now,
            interval,
            Vec::new(),
        )
        .expect("a genesis epoch is a roster"),
    };
    let mut roster = Roster::next_epoch_from(&base, now, additions, &Default::default())
        .expect("the next epoch composes");
    for entry in &mut roster.entries {
        if entry.tier == RosterTier::Anonymous {
            entry.tier = RosterTier::Endorsed;
        }
    }
    // Re-signing is the owner's act, and the only field an owner may set after the fact
    // is the tier — which the entry's own proof deliberately does not cover.
    roster.sign(&owner.key).expect("the owner signs the epoch");
    store::publish_roster(&owner.host, &roster).expect("the epoch publishes");
    roster
}

#[test]
fn a_signed_roster_round_trips_through_the_host() {
    let owner = owner();
    let volunteers: Vec<SigningKey> = (0..3).map(sample::verifier_key).collect();
    let signups: Vec<SignUp> = volunteers
        .iter()
        .map(|key| signup(key, claimed()))
        .collect();
    for signup in &signups {
        store::publish_signup(&owner.host, signup).expect("a sign-up publishes");
    }
    assert_eq!(
        store::list_signups(&owner.host)
            .expect("the queue reads")
            .len(),
        3,
        "three sign-ups are waiting for the owner"
    );

    let roster = approve(
        &owner,
        None,
        signups.iter().map(|s| s.entry.clone()).collect(),
    );

    // Readable both ways, and identical both ways: the current pointer and the epoch ref
    // a round would be audited against.
    let current = store::current_roster(&owner.host)
        .expect("the pointer reads")
        .expect("and points at something");
    let at_epoch = store::roster_at(&owner.host, roster.epoch)
        .expect("the epoch ref reads")
        .expect("and holds the epoch");
    for read_back in [&current, &at_epoch] {
        assert_eq!(
            *read_back, roster,
            "the store returned a different document"
        );
        assert_eq!(
            read_back.digest().unwrap(),
            roster.digest().unwrap(),
            "the digest a round pins is the digest of what came back"
        );
        // Trusted, unexpired, every key proved: a trust root, not a list.
        let trusted = read_back
            .verify(&owner.trust, sample::clock())
            .expect("the published epoch verifies");
        assert_eq!(trusted, vec![owner.key.public_key().key_id()]);
    }
    // The refs are the ones ADR-0002 D10 names: the pointer, and the epoch beside it so a
    // past selection stays checkable after the roster moves on.
    for name in [
        store::roster_ref(),
        store::roster_epoch_ref(roster.epoch).unwrap(),
    ] {
        assert!(
            owner.host.get_ref(&name).unwrap().is_some(),
            "{name} should exist"
        );
    }
    // And the epoch chain: the new epoch names its predecessor's digest, so a rewritten
    // past is a different digest rather than a quiet edit.
    // And the epoch chain: the new epoch names its predecessor's digest, so a rewritten
    // past is a different digest rather than a quiet edit.
    let genesis = Roster::new(
        Roster::next_epoch(0, sample::clock().as_us(), sample::EPOCH_INTERVAL_US).unwrap(),
        Digest::sha256(b"gitiup-roster-1 genesis"),
        sample::clock().as_us(),
        sample::EPOCH_INTERVAL_US,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(roster.prev_roster_digest, genesis.digest().unwrap());
}

#[test]
fn claimed_capabilities_arrive_exactly_as_signed_and_drive_eligibility() {
    let owner = owner();
    let key = sample::verifier_key(3);
    let signup = signup(&key, claimed());
    let bytes = signup.canonical_bytes().unwrap();
    let back = SignUp::from_canonical_bytes(&bytes).expect("the sign-up is canonical");
    assert_eq!(back, signup);

    let roster = approve(&owner, None, vec![back.entry.clone()]);
    let entry = roster
        .entry(&key.public_key().key_id())
        .expect("the volunteer is on the epoch");
    // Every field the ticket names, unchanged, and still covered by the key's proof.
    assert_eq!(
        entry.capabilities.arch,
        vec!["x86_64".to_string(), "aarch64".to_string()]
    );
    assert_eq!(entry.capabilities.ram_mb, 32_768);
    assert_eq!(entry.capabilities.disk_mb, 262_144);
    assert_eq!(entry.capabilities.image_cache, vec![sample::image_digest()]);
    assert!(!entry.capabilities.can_pull);
    assert_eq!(
        entry.capabilities.sandboxes,
        vec!["docker".to_string(), "unshare".to_string()]
    );
    assert_eq!(entry.capabilities.sandbox_level, 2);
    assert_eq!(
        entry.tier,
        RosterTier::Endorsed,
        "the owner's vouch, not the claim"
    );

    // The same claims are what the eligibility filter reads, and a claim that does not
    // meet the job is refused with the *first* reason in D7's order.
    let requirements = Requirements {
        arch: "aarch64".into(),
        ram_mb: 16_384,
        disk_mb: 65_536,
        image_digests: vec![sample::image_digest()],
        sandboxes: vec!["docker".into()],
        min_sandbox_level: 2,
    };
    assert_eq!(
        gitiup_quorum::exclusion_of(
            entry,
            roster.epoch,
            &requirements,
            &Default::default(),
            RosterTier::Anonymous
        ),
        None,
        "a box that meets every requirement is eligible"
    );
    let too_small = Requirements {
        ram_mb: 65_536,
        ..requirements.clone()
    };
    assert_eq!(
        gitiup_quorum::exclusion_of(
            entry,
            roster.epoch,
            &too_small,
            &Default::default(),
            RosterTier::Anonymous
        ),
        Some(gitiup_quorum::Exclusion::Ram)
    );
    let needs_a_pull = Requirements {
        image_digests: vec![format!(
            "sha256:{}",
            Digest::sha256(b"not in the cache").hex()
        )],
        ..requirements.clone()
    };
    assert_eq!(
        gitiup_quorum::exclusion_of(
            entry,
            roster.epoch,
            &needs_a_pull,
            &Default::default(),
            RosterTier::Anonymous
        ),
        Some(gitiup_quorum::Exclusion::Images),
        "a box that cannot pull and does not have the image is out, whatever else it can do"
    );
}

#[test]
fn an_owner_editing_a_signed_claim_is_refused() {
    // The proof covers the claim, so "the owner nudged the RAM figure up" is not a thing
    // an owner can do to a roster entry: they can decline to carry it, or ask for a new
    // sign-up, and both are visible.
    let key = sample::verifier_key(4);
    let signup = signup(&key, claimed());
    let mut edited = signup.entry.clone();
    edited.capabilities.ram_mb = 32_768 * 4;
    let err = gitiup_quorum::roster::Roster::next_epoch_from(
        &sample::roster_of(&sample::owner_key(), 1, 41),
        sample::clock().as_us(),
        vec![edited],
        &Default::default(),
    )
    .expect_err("an edited entry does not verify");
    assert!(err.to_string().contains("ownership proof"), "{err}");
    assert_eq!(err.exit_code(), 7);
}

#[test]
fn a_withdrawal_is_a_tombstone_applied_to_the_next_epoch() {
    let owner = owner();
    let staying = sample::verifier_key(5);
    let leaving = sample::verifier_key(6);
    let roster = approve(
        &owner,
        None,
        vec![
            signup(&staying, claimed()).entry,
            signup(&leaving, claimed()).entry,
        ],
    );
    assert_eq!(roster.entries.len(), 2);

    let mut withdrawal = Withdrawal::new(
        leaving.public_key().key_id(),
        roster.epoch + 1,
        sample::clock().as_us(),
    );
    withdrawal
        .sign(&leaving)
        .expect("a key may always withdraw itself");
    withdrawal
        .verify()
        .expect("the withdrawal is signed by its key");
    store::publish_withdrawal(&owner.host, &withdrawal).expect("and published");
    assert_eq!(store::list_withdrawals(&owner.host).unwrap().len(), 1);

    // The owner composes the next epoch from what the store holds: the withdrawal is in
    // force from its epoch, and the old epoch keeps the entry, because history is not
    // edited (D8).
    let removals: std::collections::BTreeSet<String> = store::list_withdrawals(&owner.host)
        .unwrap()
        .into_iter()
        .filter(|w| w.effective_epoch <= roster.epoch + 1)
        .map(|w| w.key_id)
        .collect();
    let next = Roster::next_epoch_from(&roster, sample::clock().as_us() + 1, vec![], &removals)
        .expect("the next epoch composes");
    let mut next = next;
    next.sign(&owner.key).unwrap();
    store::publish_roster(&owner.host, &next).unwrap();
    assert_eq!(next.entries.len(), 1);
    assert!(next.entry(&leaving.public_key().key_id()).is_none());
    assert!(next.entry(&staying.public_key().key_id()).is_some());
    assert_eq!(next.epoch, roster.epoch + 1);

    // Both epochs stay fetchable: the old one is what any round that pinned it will be
    // audited against, forever (C9).
    assert!(
        store::roster_at(&owner.host, roster.epoch)
            .unwrap()
            .unwrap()
            .entry(&leaving.public_key().key_id())
            .is_some()
    );
    assert!(
        store::roster_at(&owner.host, next.epoch)
            .unwrap()
            .unwrap()
            .entry(&leaving.public_key().key_id())
            .is_none()
    );
}

/// Owner's view, mid-round: roster and round published, seats filled with fixture work.
struct Round {
    owner: Owner,
    roster: Roster,
    round: gitiup_quorum::Round,
    /// The fixture indices holding seats, in seat order.
    seats: Vec<u8>,
}

fn round_with(volunteers: &[u8]) -> Round {
    let owner = owner();
    let entries: Vec<RosterEntry> = volunteers
        .iter()
        .map(|&index| signup(&sample::verifier_key(index), claimed()).entry)
        .collect();
    let roster = approve(&owner, None, entries);
    let inputs = sample::round_inputs(&roster, CHANGE, JOB);
    let secret = SelectionSecret::from_signing_key(&owner.key);
    let mut round = gitiup_quorum::Round::open(&inputs, &roster, &secret).expect("round opens");
    round.sign(&owner.key).expect("the selector signs");
    store::publish_round(&owner.host, &round).expect("the round publishes");
    let seats = sample::indices_of(&round);
    Round {
        owner,
        roster,
        round,
        seats,
    }
}

#[test]
fn a_selected_key_submits_through_the_store_and_a_stranger_does_not() {
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let seat = *setup.seats.first().expect("the round filled seats");
    let honest = sample::attest(&setup.round, &[seat], sample::claimed_at_us(), |_| None)
        .into_iter()
        .next()
        .unwrap();
    store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &[],
        sample::clock(),
    )
    .expect("a selected key with a bound result is admitted");
    assert_eq!(
        store::submissions(&setup.owner.host, &setup.round)
            .unwrap()
            .len(),
        1,
        "and it is in the slot the round derived for it"
    );

    // A key the owner never approved, submitting an honestly-signed document. It has no
    // slot, and the refusal says the reason: not "no slot", but *why* it has none.
    let outsider = sample::verifier_key(62);
    let forged_slot = sample::attest(&setup.round, &[seat], sample::claimed_at_us(), |_| None)
        .into_iter()
        .next()
        .map(|mut doc| {
            doc.signatures.clear();
            doc.sign(&outsider).expect("re-signs");
            doc
        })
        .unwrap();
    let error = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &forged_slot,
        &[],
        sample::clock(),
    )
    .expect_err("an unapproved key gets no slot");
    assert_eq!(error.exit_code(), 6, "{error}");
    let text = error.to_string();
    assert!(text.contains(code::NOT_IN_ROSTER), "{text}");
    assert!(
        store::submissions(&setup.owner.host, &setup.round)
            .unwrap()
            .len()
            == 1,
        "the refused submission left nothing behind"
    );
}

#[test]
fn a_key_the_owner_dropped_is_refused_with_its_own_code() {
    // The interesting case is not a stranger with no seat — the seat already refuses that.
    // It is a key that *was* selected and has since been taken off the roster: the round
    // still names it, and the store must read the roster, not the round, for who is
    // approved.
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let seat = *setup.seats.first().unwrap();
    let honest = sample::attest(&setup.round, &[seat], sample::claimed_at_us(), |_| None)
        .into_iter()
        .next()
        .unwrap();
    let dropped = setup.round.selected[0].key_id.clone();
    let dropped_roster = setup
        .roster
        .without(&[dropped.clone()].into_iter().collect())
        .expect("a roster with one entry removed is still a roster");
    let error = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &dropped_roster,
        &honest,
        &[],
        sample::clock(),
    )
    .expect_err("the roster is who is approved, not the round");
    assert!(error.to_string().contains(code::NOT_IN_ROSTER), "{error}");
}

#[test]
fn an_expired_entry_is_a_different_refusal_from_an_unapproved_one() {
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let seat = setup.round.selected[0].key_id.clone();
    let honest = sample::attest(
        &setup.round,
        &setup.seats[..1],
        sample::claimed_at_us(),
        |_| None,
    )
    .into_iter()
    .next()
    .unwrap();
    let mut aged = setup.roster.clone();
    aged.entry_mut(&seat)
        .expect("the seat holder is on the epoch")
        .epochs_valid = EpochWindow {
        from: 1,
        to: setup.roster.epoch.saturating_sub(1),
    };
    let error = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &aged,
        &honest,
        &[],
        sample::clock(),
    )
    .expect_err("an entry that has aged out may not submit");
    let text = error.to_string();
    assert!(text.contains(code::EXPIRED), "{text}");
    assert!(
        !text.contains(code::NOT_IN_ROSTER),
        "\"your approval lapsed\" and \"you were never approved\" are different advice: {text}"
    );
}

#[test]
fn a_revoked_key_is_refused_at_the_door_and_not_only_at_the_tally() {
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let honest = sample::attest(
        &setup.round,
        &setup.seats[..1],
        sample::claimed_at_us(),
        |_| None,
    )
    .into_iter()
    .next()
    .unwrap();
    let seat = setup.round.selected[0].key_id.clone();
    let mut revocation = Revocation::new(
        seat.clone(),
        RevocationReason::Compromised,
        setup.roster.epoch,
        sample::T0,
    );
    revocation
        .sign(&sample::owner_key())
        .expect("the owner may revoke");
    store::publish_revocation(&setup.owner.host, &revocation).expect("and publish it");
    let error = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &store::list_revocations(&setup.owner.host, &setup.owner.trust)
            .expect("the store's revocations read back"),
        sample::clock(),
    )
    .expect_err("a compromised key may not add to a round");
    assert!(error.to_string().contains(code::REVOKED), "{error}");
    // The same revocation, evaluated by the tally, gives the same verdict about the same
    // document — one vocabulary, two places it is spoken.
    let verdict = gitiup_quorum::verdict::VerdictRecord::evaluate(
        &setup.round,
        &setup.roster,
        std::slice::from_ref(&honest),
        &[revocation],
        &gitiup_quorum::verdict::Evaluation::at(sample::clock()),
    )
    .expect("a verdict can be computed over a refused submission");
    assert_eq!(verdict.rejected.len(), 1);
    assert_eq!(verdict.rejected[0].code, code::REVOKED);
}

#[test]
fn a_submission_must_be_the_key_s_own_claim() {
    // The slot is a seat, not a mailbox: a selected key cannot publish somebody else's
    // signature into its own slot, because that is vote laundering through a legitimate
    // seat and no downstream check could see it.
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let stranger = sample::verifier_key(63);
    let mut foreign = sample::attest(
        &setup.round,
        &setup.seats[..1],
        sample::claimed_at_us(),
        |_| None,
    )
    .into_iter()
    .next()
    .unwrap();
    foreign.signatures.clear();
    foreign.sign(&stranger).expect("signed by the stranger");
    let error = store::publish_submission(
        &setup.owner.host,
        &setup.round,
        &setup.round.selected[0].key_id,
        &foreign,
    )
    .expect_err("a slot holds its owner's claim");
    assert_eq!(error.exit_code(), 7, "{error}");
    assert!(error.to_string().contains("not by the seat key"), "{error}");
}

#[test]
fn a_roster_epoch_the_calendar_has_passed_admits_nothing() {
    // The round is pinned to one epoch by digest; the epoch is also a document with an
    // expiry. An owner who stops publishing does not freeze the pool — the old epoch
    // stops authorising work — and a submission that arrives after that point is refused
    // whatever its content, because "who is approved" is no longer knowable from this
    // document.
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let late = TimeUs(setup.roster.valid_until_us + 1);
    let honest = sample::attest(
        &setup.round,
        &setup.seats[..1],
        sample::claimed_at_us(),
        |_| None,
    )
    .into_iter()
    .next()
    .unwrap();
    let error = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &[],
        late,
    )
    .expect_err("an expired epoch approves nobody");
    assert!(error.to_string().contains(code::ROSTER_EXPIRED), "{error}");
    // And not because the key vanished: the same document, submitted while the epoch was
    // alive, is admitted. The expiry is the refusal, not the roster's contents.
    store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &[],
        sample::clock(),
    )
    .expect("the same submission is fine before the expiry");
}

#[test]
fn the_store_refuses_a_second_submission_from_one_seat() {
    let setup = round_with(&[0, 1, 2, 3, 4, 5]);
    let honest = sample::attest(
        &setup.round,
        &setup.seats[..1],
        sample::claimed_at_us(),
        |_| None,
    )
    .into_iter()
    .next()
    .unwrap();
    store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &[],
        sample::clock(),
    )
    .unwrap();
    let again = store::publish_attestation(
        &setup.owner.host,
        &setup.round,
        &setup.roster,
        &honest,
        &[],
        sample::clock(),
    );
    assert!(
        matches!(again, Err(Error::Store(_))),
        "a second submission is a store conflict, not a second vote: {again:?}"
    );
    assert_eq!(again.unwrap_err().exit_code(), 6);
    // One slot, one record, and the tally still sees one — and the round is nowhere near
    // decided: a refused submission bought no second vote and cost the honest one
    // nothing.
    assert_eq!(
        store::submissions(&setup.owner.host, &setup.round)
            .unwrap()
            .len(),
        1
    );
    assert!(
        setup.round.selected.len() > 1,
        "the round has seats left to fill, so one submission is not a verdict"
    );
}

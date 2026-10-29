//! Job advertisements and TTL leases, in a real store
//! ([giti-zp1.1](../../../README.md)).
//!
//! [`job.rs`](gitiup_quorum::job) decides what an advertisement and a lease *are*; this
//! file proves what the ticket's acceptance criteria say about the store:
//!
//! * the `open_rounds` listing is **paged and cheap** — one bounded ref query under
//!   `refs/gitiup/job` and one blob per row actually returned, never a walk over
//!   `refs/gitiup/**`;
//! * a **free slot claims by CAS** — two volunteers racing get one winner, and the loser
//!   is told so rather than overwriting;
//! * a **live lease is refused naming the holder and the TTL** it has left;
//! * an **expired lease is stealable and the steal is recorded**;
//! * **renewal and release are CAS** — neither clobbers a lease that moved, and neither
//!   is available to a key that does not hold it;
//! * and the rule the whole design hangs on: **a live lease does not displace an
//!   attestation**. A lease is advice about who is working a seat; the seat is the
//!   authority, and a slow holder that finishes first still counts.
//!
//! Everything runs on the `fs` host, because the guarantee is about CAS writes and not
//! about transports; the two hosts here that misbehave ([`Raced`], [`Counting`]) are how
//! a race and a cost get tested deterministically instead of by sleep.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use gitiup_attest::{SignatureEntry, SigningKey, TimeUs, Trust};
use gitiup_host::{
    BlobEntry, BlobStore, Capabilities, Expect, FsHost, Host, HostError, HostInfo, Namespace, Oid,
    Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate,
};
use gitiup_quorum::gate;
use gitiup_quorum::job::{
    Advertisement, DEFAULT_JOB_TTL_US, DEFAULT_LEASE_TTL_US, LeaseRequest, MAX_LEASE_HISTORY,
    MAX_LEASE_TTL_US,
};
use gitiup_quorum::prelude::*;
use gitiup_quorum::{sample, store};

const CHANGE: &str = "chg-000000000000f00d";
const JOB: &str = "build/matrix/linux-x86_64";
const OTHER_JOB: &str = "build/matrix/linux-aarch64";

struct Scene {
    host: FsHost,
    _dir: tempfile::TempDir,
    owner: SigningKey,
    trust: Trust,
    roster: Roster,
}

impl Scene {
    fn new() -> Scene {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path()).expect("fs host");
        let owner = sample::owner_key();
        let trust = Trust::KeyIds([owner.public_key().key_id()].into_iter().collect());
        let roster = sample::roster_of(&owner, 7, 41);
        store::publish_roster(&host, &roster).expect("roster publishes");
        Scene {
            host,
            _dir: dir,
            owner,
            trust,
            roster,
        }
    }

    /// Open, sign and publish a round — the owner's half of the story.
    fn open_round(&self, change: &str, job: &str, attempt: u64) -> Round {
        let mut inputs = sample::round_inputs(&self.roster, change, job);
        inputs.attempt = attempt;
        let secret = gitiup_quorum::derive::SelectionSecret::from_signing_key(&self.owner);
        let mut round = Round::open(&inputs, &self.roster, &secret).expect("round opens");
        round.sign(&self.owner).expect("selector signs");
        store::publish_round(&self.host, &round).expect("round publishes");
        round
    }

    /// ...and advertise it, which is the half that was missing before this ticket.
    fn advertise(&self, round: &Round) -> Oid {
        store::advertise_round(&self.host, round, &self.owner, sample::clock())
            .expect("round advertises")
    }

    fn now(&self) -> TimeUs {
        sample::clock()
    }
}

fn at(now: TimeUs, delta_us: i64) -> TimeUs {
    TimeUs(now.as_us() + delta_us)
}

const MINUTE: i64 = 60 * 1_000_000;

/// A volunteer's lease request for one seat of one round.
fn lease_for<'a>(
    round: &'a Round,
    seat: usize,
    holder: &'a SigningKey,
    now: TimeUs,
) -> LeaseRequest<'a> {
    LeaseRequest::new(
        &round.inputs.change_id,
        &round.inputs.job_id,
        round.inputs.attempt,
        &round.selected[seat].slot,
        holder,
    )
    .at(now)
}

// ---------------------------------------------------------------------------
// the advertisement: the round's inverse index
// ---------------------------------------------------------------------------

#[test]
fn an_advertisement_is_an_index_into_the_round_and_nothing_more() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let oid = scene.advertise(&round);

    let advertised = store::advertisement_at(&scene.host, CHANGE, JOB)
        .expect("readable")
        .expect("it is there");
    assert_eq!(
        store::job_ref(CHANGE, JOB).unwrap().as_str(),
        "refs/gitiup/job/chg-000000000000f00d/build/matrix/linux-x86_64"
    );
    assert_eq!(
        advertised.round_digest,
        round.digest().unwrap(),
        "the ad's whole authority is the round it names"
    );
    assert_eq!(advertised.seats, round.selected);
    assert_eq!(advertised.required_agree, 4);
    assert_eq!(advertised.reveal_mode, "open");
    assert_eq!(advertised.lease_ttl(), DEFAULT_LEASE_TTL_US);
    advertised
        .verify(&scene.trust)
        .expect("the selector's signature checks");
    advertised
        .matches(&round)
        .expect("and it still describes its round");
    assert_eq!(
        store::open_rounds(&scene.host, scene.now(), store::Cursor::START, 10)
            .unwrap()
            .items,
        vec![advertised.clone()],
        "one advertised job is one open round"
    );

    // Publishing it again is a retry, not a conflict: idempotence is what makes a
    // selector that crashed mid-publish safe to run again. A later clock changes the
    // advertisement's bytes and not its meaning.
    let refreshed =
        store::advertise_round(&scene.host, &round, &scene.owner, at(scene.now(), 1)).unwrap();
    assert_ne!(refreshed, oid, "the refresh is a new record");
    let open = store::open_rounds(&scene.host, scene.now(), store::Cursor::START, 10).unwrap();
    assert_eq!(open.len(), 1, "and still one open round");
    assert_eq!(open.items[0].round_digest, advertised.round_digest);
    // Identical bytes are the same answer twice.
    assert_eq!(
        store::advertise(&scene.host, &open.items[0]).unwrap(),
        refreshed
    );
}

#[test]
fn an_advertisement_is_signed_by_a_selector_of_its_round_or_it_is_noise() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let stranger = sample::verifier_key(63);
    let err = store::advertise_round(&scene.host, &round, &stranger, scene.now()).unwrap_err();
    assert_eq!(err.exit_code(), 7, "{err}");
    assert!(err.message().contains("did not sign the round"), "{err}");

    // Hand-built and unsigned: refused before a byte is written.
    let mut unsigned = Advertisement::new(
        &round,
        scene.now(),
        DEFAULT_LEASE_TTL_US,
        DEFAULT_JOB_TTL_US,
    )
    .unwrap();
    assert!(
        store::advertise(&scene.host, &unsigned)
            .unwrap_err()
            .message()
            .contains("unsigned")
    );
    // A foreign selector's signature checks against *its* trust and nobody else's.
    unsigned.sign(&stranger).unwrap();
    let oid = store::advertise(&scene.host, &unsigned).expect("stored; belief is the reader's");
    assert!(
        store::advertisement_at(&scene.host, CHANGE, JOB)
            .unwrap()
            .unwrap()
            .verify(&scene.trust)
            .is_err(),
        "a volunteer that only checked the signature would still have to trust this key: \
         {oid}"
    );
}

#[test]
fn a_round_that_cannot_reach_its_threshold_is_not_advertised() {
    let scene = Scene::new();
    // Two eligible volunteers, five seats: `insufficient` is a verdict, not a job.
    let thin = sample::roster_of(&scene.owner, 2, 41);
    store::publish_roster(&scene.host, &thin).expect("a later epoch publishes");
    let inputs = sample::round_inputs(&thin, CHANGE, JOB);
    let secret = gitiup_quorum::derive::SelectionSecret::from_signing_key(&scene.owner);
    let mut round = Round::open(&inputs, &thin, &secret).expect("round opens");
    round.sign(&scene.owner).unwrap();
    assert!(!round.sufficient);
    let err = store::advertise_round(&scene.host, &round, &scene.owner, scene.now()).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(
        store::open_rounds(&scene.host, scene.now(), store::Cursor::START, 10)
            .unwrap()
            .is_empty(),
        "and nothing was left half-written in the listing"
    );
}

#[test]
fn the_listing_pages_and_never_costs_more_than_it_says() {
    let scene = Scene::new();
    let jobs: Vec<String> = (0..7)
        .map(|index| format!("build/matrix/job-{index}"))
        .collect();
    for job in &jobs {
        let round = scene.open_round(CHANGE, job, 0);
        scene.advertise(&round);
    }
    // Noise that a poll must not touch: a round and a lease ref, outside the job prefix.
    let round = scene.open_round(CHANGE, &jobs[0], 0);
    store::claim_lease(
        &scene.host,
        &lease_for(&round, 0, &sample::verifier_key(0), scene.now()),
    )
    .expect("a lease exists");

    let mut seen: Vec<String> = Vec::new();
    let mut cursor = store::Cursor::START;
    let mut pages = 0;
    loop {
        let counter = Counting::new(&scene.host);
        let page = store::open_rounds(&counter, scene.now(), cursor, 3).expect("a page");
        pages += 1;
        assert!(
            page.len() <= 3,
            "a page of three never returns more than three"
        );
        assert_eq!(
            counter.gets(),
            page.len(),
            "one blob per row returned — not one per job in the store"
        );
        assert_eq!(counter.listed().len(), 1, "one ref query per page");
        for prefix in counter.listed().iter() {
            assert!(
                prefix.starts_with(store::ADVERTISED_PREFIX),
                "a poll lists {prefix}, and a stranger polling must not see \
                 refs/gitiup/** as if it were a branch"
            );
        }
        assert!(
            counter
                .limits()
                .iter()
                .all(|limit| limit.is_some_and(|limit| limit <= 3 + cursor.offset() + 1)),
            "the query is bounded: {:?}",
            counter.limits()
        );
        for advertisement in &page.items {
            assert!(
                !seen.contains(&advertisement.job_id),
                "paging must not repeat a job"
            );
            seen.push(advertisement.job_id.clone());
        }
        match page.next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    assert_eq!(pages, 3, "seven jobs in pages of three");
    assert_eq!(seen.len(), 7);
    for job in &jobs {
        assert!(seen.contains(job), "{job} never came up");
    }

    // The cheapest possible poll: refs only, no blobs at all.
    let counter = Counting::new(&scene.host);
    let refs = store::advertised_refs(&counter, store::Cursor::START, 4).expect("refs");
    assert_eq!(refs.len(), 4);
    assert!(refs.next.is_some());
    assert_eq!(counter.gets(), 0, "not one blob fetched");
}

#[test]
fn closing_and_expiry_take_a_job_out_of_the_listing() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let oid = scene.advertise(&round);
    let short_lived = scene.open_round(CHANGE, OTHER_JOB, 0);
    let mut ad =
        Advertisement::new(&short_lived, scene.now(), DEFAULT_LEASE_TTL_US, MINUTE).unwrap();
    ad.sign(&scene.owner).unwrap();
    store::advertise(&scene.host, &ad).unwrap();

    // Both open now.
    let now = scene.now();
    assert_eq!(
        store::open_rounds(&scene.host, now, store::Cursor::START, 10)
            .unwrap()
            .len(),
        2
    );
    // One expires. The ref is still there — the store does not delete history on a
    // poll's behalf — but the listing is not obliged to offer dead work.
    let later = at(now, 2 * MINUTE);
    let open = store::open_rounds(&scene.host, later, store::Cursor::START, 10).unwrap();
    assert_eq!(open.items.len(), 1);
    assert_eq!(open.items[0].job_id, JOB);
    assert!(
        store::advertisement_at(&scene.host, CHANGE, OTHER_JOB).is_ok_and(|found| found.is_some())
    );

    // Closing the other one is CAS: the wrong expectation is refused, and a job
    // somebody re-advertised is not yours to delete.
    assert!(
        store::close_job(
            &scene.host,
            CHANGE,
            JOB,
            Some(Oid::from_hex(&"b".repeat(40)).unwrap())
        )
        .is_err()
    );
    assert!(store::close_job(&scene.host, CHANGE, JOB, Some(oid)).expect("closed"));
    let open = store::open_rounds(&scene.host, now, store::Cursor::START, 10).unwrap();
    assert_eq!(
        open.items
            .iter()
            .map(|item| item.job_id.as_str())
            .collect::<Vec<_>>(),
        vec![OTHER_JOB],
        "the closed job is out of the listing; the expired one was never in it"
    );
    assert!(
        store::open_rounds(&scene.host, later, store::Cursor::START, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        !store::close_job(&scene.host, CHANGE, JOB, None).unwrap(),
        "closing a closed job reports that, rather than pretending to have done it"
    );
}

#[test]
fn an_escalation_moves_one_ref_forward_and_never_back() {
    let scene = Scene::new();
    let first = scene.open_round(CHANGE, JOB, 0);
    scene.advertise(&first);
    let second = scene.open_round(CHANGE, JOB, 1);
    scene.advertise(&second);

    let open = store::open_rounds(&scene.host, scene.now(), store::Cursor::START, 10).unwrap();
    assert_eq!(
        open.len(),
        1,
        "one job is one row, not one row per attempt somebody gave up on"
    );
    assert_eq!(open.items[0].attempt, 1);
    assert_eq!(
        store::advertisement_at(&scene.host, CHANGE, JOB)
            .unwrap()
            .unwrap()
            .attempt,
        1
    );

    // Backwards is a refusal: attempt 0's round is over, and pretending otherwise is
    // how a stale selector would re-open a settled job.
    let err =
        store::advertise_round(&scene.host, &first, &scene.owner, at(scene.now(), 5)).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(err.message().contains("forward"), "{err}");

    // Two *different* rounds for one attempt is the store's own contradiction.
    let other = {
        let mut inputs = sample::round_inputs(&scene.roster, CHANGE, JOB);
        inputs.attempt = 1;
        inputs
            .exclusions
            .insert(sample::verifier_key(0).public_key().key_id());
        let secret = gitiup_quorum::derive::SelectionSecret::from_signing_key(&scene.owner);
        let mut round = Round::open(&inputs, &scene.roster, &secret).expect("opens");
        round.sign(&scene.owner).unwrap();
        round
    };
    let err =
        store::advertise_round(&scene.host, &other, &scene.owner, at(scene.now(), 6)).unwrap_err();
    assert!(err.message().contains("conflict"), "{err}");
}

#[test]
fn a_volunteer_polls_only_the_rounds_that_invited_it() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    scene.advertise(&round);
    let outsider = sample::verifier_key(63).public_key().key_id();
    let seats = sample::indices_of(&round);

    let invited = store::open_rounds_for(
        &scene.host,
        &sample::verifier_key(seats[0]).public_key().key_id(),
        scene.now(),
        store::Cursor::START,
        10,
    )
    .unwrap();
    assert_eq!(invited.len(), 1, "a seat holder is invited");
    let counter = Counting::new(&scene.host);
    let invited = store::open_rounds_for(
        &counter,
        &sample::verifier_key(seats[0]).public_key().key_id(),
        scene.now(),
        store::Cursor::START,
        10,
    )
    .unwrap();
    assert_eq!(invited.len(), 1);
    assert_eq!(
        counter.gets(),
        1,
        "finding out you are invited costs the same listing: the seats are in the \
         advertisement"
    );
    let not_mine = store::open_rounds_for(
        &scene.host,
        &outsider,
        scene.now(),
        store::Cursor::START,
        10,
    )
    .unwrap();
    assert!(
        not_mine.is_empty(),
        "a key with no seat is not invited, and never fetched a round to learn it"
    );
    assert!(not_mine.next.is_none());
}

#[test]
fn a_record_filed_under_the_wrong_ref_is_believed_by_nobody() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let other = scene.open_round(CHANGE, OTHER_JOB, 0);
    scene.advertise(&other);
    // The lie: job A's ref, job B's advertisement.
    let mut ad = Advertisement::new(
        &other,
        scene.now(),
        DEFAULT_LEASE_TTL_US,
        DEFAULT_JOB_TTL_US,
    )
    .unwrap();
    ad.sign(&scene.owner).unwrap();
    let oid = scene
        .host
        .put_cas(&Namespace::JOB, &ad.canonical_bytes().unwrap())
        .unwrap();
    scene
        .host
        .update_ref_cas(&RefUpdate::create(
            store::job_ref(CHANGE, JOB).unwrap(),
            oid,
        ))
        .unwrap();
    let err = store::advertisement_at(&scene.host, CHANGE, JOB).unwrap_err();
    assert_eq!(err.exit_code(), 8, "{err}");
    assert!(err.message().contains("disagree"), "{err}");
    let err = store::open_rounds(&scene.host, scene.now(), store::Cursor::START, 10).unwrap_err();
    assert_eq!(err.exit_code(), 8, "the listing refuses to lie too");
    // The lie is confined to the ref it was written into: job B's own advertisement is
    // untouched, which is what per-ref addressing buys. And no honest path can produce
    // this, because an advertisement is copied from the round it names.
    let honest = store::advertisement_at(&scene.host, CHANGE, OTHER_JOB).unwrap();
    assert!(honest.is_some());
    assert_eq!(honest.unwrap().job_id, OTHER_JOB);
    let _ = round;
}

// ---------------------------------------------------------------------------
// leases: advice with a deadline
// ---------------------------------------------------------------------------

#[test]
fn a_free_seat_claims_by_cas_and_a_live_lease_is_refused_by_name() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let first = sample::verifier_key(sample::indices_of(&round)[0]);
    let second = sample::verifier_key(sample::indices_of(&round)[1]);

    let claim =
        store::claim_lease(&scene.host, &lease_for(&round, 0, &first, scene.now())).expect("claim");
    assert!(claim.claimed());
    assert!(claim.took().is_none());
    let held = store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
        .unwrap()
        .expect("the lease is in the store");
    assert_eq!(held.holder, first.public_key().key_id());
    assert_eq!(held.attempt, 0);
    assert_eq!(held.ttl_us, DEFAULT_LEASE_TTL_US);
    held.verify().expect("the holder signed its own claim");

    // The second volunteer's poll: refused, and told exactly who and for how long.
    let mid = at(scene.now(), 5 * MINUTE);
    let held_by_first = store::claim_lease(&scene.host, &lease_for(&round, 0, &second, mid))
        .expect("a live lease is an answer, not a failure");
    match &held_by_first {
        store::Claim::Held {
            holder,
            remaining_us,
            slot,
            expires_at_us,
        } => {
            assert_eq!(holder, &first.public_key().key_id());
            assert_eq!(slot, &round.selected[0].slot);
            assert_eq!(*remaining_us, DEFAULT_LEASE_TTL_US - 5 * MINUTE);
            assert_eq!(*expires_at_us, scene.now().as_us() + DEFAULT_LEASE_TTL_US);
        }
        other => panic!("expected a refusal that names the holder, got {other:?}"),
    }
    let text = held_by_first.text();
    assert!(text.contains("SHA256:"), "{text}");
    assert!(text.contains("10m"), "{text}");
    assert_eq!(held_by_first.holder(), &first.public_key().key_id());
    assert_eq!(
        held_by_first.remaining_us(),
        DEFAULT_LEASE_TTL_US - 5 * MINUTE
    );

    // Re-claiming your own live lease refreshes it rather than buying a second seat.
    let again = store::claim_lease(&scene.host, &lease_for(&round, 0, &first, mid)).unwrap();
    assert!(again.claimed());
    let now_holds = store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
        .unwrap()
        .unwrap();
    assert_eq!(now_holds.acquired_at_us, mid.as_us());
    assert_eq!(now_holds.ttl_us, DEFAULT_LEASE_TTL_US);

    // And the CAS is what decided it: a rival that writes between the read and the
    // write wins, and the loser comes back with the refusal instead of an overwrite.
    let raced = Raced::new(
        &scene.host,
        lease_update(&scene, &round, 2, &second, scene.now()),
    );
    let claim = store::claim_lease(
        &raced,
        &lease_for(&round, 2, &sample::verifier_key(63), scene.now()),
    )
    .expect("the race is answered, not failed");
    assert!(
        !claim.claimed(),
        "the racer must not believe it won: {:?}",
        claim.text()
    );
    assert_eq!(
        claim.holder(),
        &second.public_key().key_id(),
        "and it is told who did win"
    );
    assert!(
        store::lease_at(&scene.host, CHANGE, JOB, &round.selected[2].slot)
            .unwrap()
            .unwrap()
            .holder
            == second.public_key().key_id(),
        "nothing was overwritten in the store either"
    );
}

#[test]
fn an_expired_lease_is_stealable_and_the_steal_is_recorded() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let slow = sample::verifier_key(sample::indices_of(&round)[0]);
    let impatient = sample::verifier_key(sample::indices_of(&round)[1]);
    let slot = round.selected[0].slot.clone();

    store::claim_lease(&scene.host, &lease_for(&round, 0, &slow, scene.now())).unwrap();
    let dead = at(scene.now(), DEFAULT_LEASE_TTL_US);
    assert!(
        store::lease_at(&scene.host, CHANGE, JOB, &slot)
            .unwrap()
            .unwrap()
            .is_expired(dead)
    );

    let took = store::claim_lease(&scene.host, &lease_for(&round, 0, &impatient, dead)).unwrap();
    let taken = took.took().expect("the steal is recorded, not silent");
    assert_eq!(taken.holder, slow.public_key().key_id());
    assert_eq!(taken.attempt, 0);
    assert_eq!(
        taken.expired_at_us,
        scene.now().as_us() + DEFAULT_LEASE_TTL_US
    );
    assert_eq!(taken.taken_at_us, dead.as_us());
    assert!(took.text().contains("took over a dead lease"));

    let lease = store::lease_at(&scene.host, CHANGE, JOB, &slot)
        .unwrap()
        .unwrap();
    assert_eq!(lease.holder, impatient.public_key().key_id());
    assert_eq!(lease.taken.len(), 1);
    assert_eq!(
        lease.last_taken().unwrap().holder,
        slow.public_key().key_id()
    );
    lease
        .verify()
        .expect("still self-signed, by the new holder");

    // Two stealers, one winner: the same CAS as a free claim.
    let third = sample::verifier_key(sample::indices_of(&round)[2]);
    let later = at(dead, DEFAULT_LEASE_TTL_US);
    let raced = Raced::new(
        &scene.host,
        lease_update_at(&scene, &round, 0, &third, later),
    );
    let claim = store::claim_lease(&raced, &lease_for(&round, 0, &slow, later)).unwrap();
    assert!(!claim.claimed());
    assert_eq!(claim.holder(), &third.public_key().key_id());
    assert_eq!(
        store::lease_at(&scene.host, CHANGE, JOB, &slot)
            .unwrap()
            .unwrap()
            .holder,
        third.public_key().key_id()
    );

    // A contested seat forever is a bounded note, not a growing blob.
    let mut index = 1u8;
    let mut clock = later;
    for _ in 0..(MAX_LEASE_HISTORY * 2) {
        clock = at(clock, DEFAULT_LEASE_TTL_US + 1);
        index += 1;
        store::claim_lease(
            &scene.host,
            &lease_for(&round, 0, &sample::verifier_key(50 + index), clock),
        )
        .expect("an expired lease is always takeable");
    }
    let lease = store::lease_at(&scene.host, CHANGE, JOB, &slot)
        .unwrap()
        .unwrap();
    assert_eq!(lease.taken.len(), MAX_LEASE_HISTORY);
}

#[test]
fn a_lease_is_per_attempt_so_an_escalation_does_not_inherit_the_old_rounds_claims() {
    let scene = Scene::new();
    let first = scene.open_round(CHANGE, JOB, 0);
    let holder = sample::verifier_key(sample::indices_of(&first)[0]);
    store::claim_lease(&scene.host, &lease_for(&first, 0, &holder, scene.now())).unwrap();
    let slot = first.selected[0].slot.clone();

    let second = scene.open_round(CHANGE, JOB, 1);
    let next_key = sample::verifier_key(sample::indices_of(&second)[0]);
    // The same seat position, the new attempt: the old lease cannot black it out.
    let take =
        LeaseRequest::new(CHANGE, JOB, second.inputs.attempt, &slot, &next_key).at(scene.now());
    let claim = store::claim_lease(&scene.host, &take).unwrap();
    assert!(
        claim.claimed(),
        "attempt 1 is a new round: attempt 0's lease cannot black out its seat"
    );
    let took = claim.took().expect("and the take is recorded");
    assert_eq!(took.attempt, 0);
    assert_eq!(took.holder, holder.public_key().key_id());

    // A renewal never crosses attempts either: attempt 0's holder cannot use its old
    // lease as a heartbeat for the new round's seat.
    let stale_attempt = LeaseRequest::new(CHANGE, JOB, 0, &slot, &next_key).at(scene.now());
    let err = store::renew_lease(&scene.host, &stale_attempt).unwrap_err();
    assert!(err.message().contains("attempt"), "{err}");
}

#[test]
fn renewal_is_a_cas_and_only_the_holder_renews() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let holder = sample::verifier_key(sample::indices_of(&round)[0]);
    let other = sample::verifier_key(sample::indices_of(&round)[1]);

    // Nothing to renew yet.
    let err =
        store::renew_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(err.message().contains("no lease"), "{err}");

    store::claim_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap();
    let beat = at(scene.now(), 5 * MINUTE);
    let renewed = store::renew_lease(&scene.host, &lease_for(&round, 0, &holder, beat)).unwrap();
    assert_eq!(renewed.acquired_at_us, beat.as_us());
    assert_eq!(
        renewed.remaining_us(beat),
        DEFAULT_LEASE_TTL_US,
        "a heartbeat restarts the clock, it does not extend a fixed deadline"
    );
    renewed
        .verify()
        .expect("renewed, and still the holder's own claim");

    // Somebody else's heartbeat is a refusal naming the holder and the TTL left — and
    // the TTL left is the whole fresh one, because the holder's own beat restarted it.
    let err = store::renew_lease(&scene.host, &lease_for(&round, 0, &other, beat)).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(err.message().contains("15m"), "{err}");
    assert!(err.message().contains(&short(&holder)), "{err}");

    // An expired lease is nobody's to renew: renewing it would be a way to keep a lease
    // the store has already offered to the next volunteer.
    let late = at(scene.now(), DEFAULT_LEASE_TTL_US * 2);
    let err = store::renew_lease(&scene.host, &lease_for(&round, 0, &holder, late)).unwrap_err();
    assert!(err.message().contains("nobody's to renew"), "{err}");

    // The CAS: a rival takes the seat in the window between this build's read and its
    // write, and the renewal fails rather than rolling the steal back.
    let fresh = store::claim_lease(&scene.host, &lease_for(&round, 1, &other, beat)).unwrap();
    assert!(fresh.claimed());
    let raced = Raced::new(&scene.host, lease_update(&scene, &round, 1, &holder, beat));
    let err = store::renew_lease(&raced, &lease_for(&round, 1, &other, beat)).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(
        store::lease_at(&scene.host, CHANGE, JOB, &round.selected[1].slot)
            .unwrap()
            .unwrap()
            .holder
            == holder.public_key().key_id(),
        "the rival's lease survives the failed renewal"
    );
    assert_eq!(
        store::job_leases(&scene.host, CHANGE, JOB, None)
            .unwrap()
            .len(),
        2,
        "both seats' leases are there, in slot order"
    );
    assert_eq!(
        store::job_leases(&scene.host, CHANGE, JOB, Some(1))
            .unwrap()
            .len(),
        0,
        "and an attempt filter is a filter"
    );
}

#[test]
fn release_is_a_cas_and_only_the_holder_releases() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let holder = sample::verifier_key(sample::indices_of(&round)[0]);
    let other = sample::verifier_key(sample::indices_of(&round)[1]);

    // Releasing nothing reports nothing.
    assert!(
        !store::release_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap()
    );

    store::claim_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap();
    let err =
        store::release_lease(&scene.host, &lease_for(&round, 0, &other, scene.now())).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert!(err.message().contains(&short(&holder)), "{err}");
    assert!(
        store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
            .unwrap()
            .is_some(),
        "a refusal leaves the lease alone"
    );

    assert!(
        store::release_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap()
    );
    assert!(
        store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
            .unwrap()
            .is_none()
    );
    assert!(
        !store::release_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap(),
        "idempotent, because a volunteer that retries a release is normal"
    );

    // A release after the lease moved on is a refusal, not a deletion of the new holder.
    store::claim_lease(&scene.host, &lease_for(&round, 0, &holder, scene.now())).unwrap();
    let raced = Raced::new(
        &scene.host,
        lease_update(&scene, &round, 0, &other, scene.now()),
    );
    let err =
        store::release_lease(&raced, &lease_for(&round, 0, &holder, scene.now())).unwrap_err();
    assert_eq!(err.exit_code(), 6, "{err}");
    assert_eq!(
        store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
            .unwrap()
            .unwrap()
            .holder,
        other.public_key().key_id(),
        "the volunteer that took the seat over keeps it"
    );
}

#[test]
fn a_live_lease_does_not_displace_an_attestation() {
    // The rule the ticket calls the difference between a lease and a lock nobody can
    // release, tested from both ends.
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    scene.advertise(&round);
    let seats = sample::indices_of(&round);
    let slow = sample::verifier_key(seats[0]);
    let impatient = sample::verifier_key(seats[1]);
    let slot = round.selected[0].slot.clone();
    let docs = sample::attest(&round, &seats[..1], sample::claimed_at_us(), |_| None);
    let doc = docs[0].clone();

    // While its own lease is live, admission does not notice: the lease is advice about
    // who is working the seat, and the holder *is* the seat.
    store::claim_lease(&scene.host, &lease_for(&round, 0, &slow, scene.now())).unwrap();
    assert_eq!(
        gate::admit(&scene.roster, &round, &doc, &[], sample::clock())
            .expect("a live lease on your own seat is no reason to refuse your own answer"),
        slow.public_key().key_id()
    );

    // The volunteer leases its seat, then is slow: the TTL runs out and another volunteer
    // takes the seat over.
    let after = at(scene.now(), DEFAULT_LEASE_TTL_US + 1);
    store::claim_lease(&scene.host, &lease_for(&round, 0, &impatient, after)).unwrap();
    assert_eq!(
        store::lease_at(&scene.host, CHANGE, JOB, &slot)
            .unwrap()
            .unwrap()
            .holder,
        impatient.public_key().key_id()
    );

    // The slow holder finishes first. `gate::admit` has never heard of leases, so its
    // attestation is admitted — while the new lease is itself live — and its slot, which
    // the seat and not the lease reserves, takes it.
    let key_id = gate::admit(&scene.roster, &round, &doc, &[], sample::clock())
        .expect("a lease is advice; a seat is the authority");
    assert_eq!(key_id, slow.public_key().key_id());
    store::publish_attestation(
        &scene.host,
        &round,
        &scene.roster,
        &doc,
        &[],
        sample::clock(),
    )
    .expect("the slow holder's work counts");
    assert_eq!(
        store::submissions(&scene.host, &round).unwrap().len(),
        1,
        "filed, notwithstanding the lease somebody else holds"
    );

    // The other end: holding a lease grants nothing at all. A key with no seat takes the
    // lease of a seat it will never fill, and its attestation is refused for exactly the
    // reason it always would have been.
    let outsider = sample::verifier_key(63);
    store::claim_lease(
        &scene.host,
        &LeaseRequest::new(CHANGE, JOB, 0, &slot, &outsider).at(after),
    )
    .expect("anybody may hold advice");
    let mut stranger_claim = doc.clone();
    stranger_claim.signatures = vec![
        SignatureEntry::new(&outsider, &doc.signature_message().unwrap())
            .expect("re-signing an honest manifest with the outsider's key"),
    ];
    let refusal = gate::admit(&scene.roster, &round, &stranger_claim, &[], sample::clock())
        .expect_err("a lease is not membership");
    assert_eq!(refusal.code, gate::code::NOT_IN_ROSTER, "{refusal:?}");
}

#[test]
fn open_seats_reports_what_a_job_still_needs() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let oid = scene.advertise(&round);
    let ad = store::advertisement_at(&scene.host, CHANGE, JOB)
        .unwrap()
        .unwrap();
    let seats = sample::indices_of(&round);
    let now = scene.now();

    assert_eq!(store::open_seats(&scene.host, &ad, now).unwrap(), 5);
    let fill = store::job_fill(&scene.host, &ad).unwrap();
    assert_eq!(fill.len(), 5);
    assert!(fill.iter().all(|state| state.open(now)));

    // One seat answered, one seat leased and being worked.
    let docs = sample::attest(&round, &seats[..1], sample::claimed_at_us(), |_| None);
    store::publish_attestation(
        &scene.host,
        &round,
        &scene.roster,
        &docs[0],
        &[],
        sample::clock(),
    )
    .unwrap();
    store::claim_lease(
        &scene.host,
        &lease_for(&round, 1, &sample::verifier_key(seats[1]), now),
    )
    .unwrap();
    let fill = store::job_fill(&scene.host, &ad).unwrap();
    assert!(fill[0].submitted && !fill[0].open(now));
    assert_eq!(
        fill[1].holder(now),
        Some(
            sample::verifier_key(seats[1])
                .public_key()
                .key_id()
                .as_str()
        )
    );
    assert!(!fill[1].open(now));
    assert_eq!(store::open_seats(&scene.host, &ad, now).unwrap(), 3);

    // The lease dies; the seat is open again even though nothing was released.
    assert_eq!(
        store::open_seats(&scene.host, &ad, at(now, DEFAULT_LEASE_TTL_US)).unwrap(),
        4
    );
    // And the job is still advertised: closing is the verdict publisher's call.
    assert!(store::close_job(&scene.host, CHANGE, JOB, Some(oid)).unwrap());
}

#[test]
fn a_lease_that_does_not_match_its_own_ref_is_refused() {
    let scene = Scene::new();
    let round = scene.open_round(CHANGE, JOB, 0);
    let holder = sample::verifier_key(sample::indices_of(&round)[0]);
    let request = lease_for(&round, 0, &holder, scene.now());
    store::claim_lease(&scene.host, &request).unwrap();
    let lease = store::lease_at(&scene.host, CHANGE, JOB, &round.selected[0].slot)
        .unwrap()
        .unwrap();
    // Move it — the store, not the holder, changing what a claim says.
    let other_slot = round.selected[1].slot.clone();
    let bytes = lease.canonical_bytes().unwrap();
    let oid = scene.host.put_cas(&Namespace::JOB, &bytes).unwrap();
    scene
        .host
        .update_ref_cas(&RefUpdate::create(
            store::lease_ref(CHANGE, JOB, &other_slot).unwrap(),
            oid,
        ))
        .unwrap();
    let err = store::lease_at(&scene.host, CHANGE, JOB, &other_slot).unwrap_err();
    assert_eq!(err.exit_code(), 8, "{err}");
    assert!(err.message().contains("disagree"), "{err}");

    // A bad slot is refused before the store is asked, and a TTL over the maximum is too.
    assert!(store::lease_ref(CHANGE, JOB, "not-a-slot").is_err());
    assert!(
        LeaseRequest::new(CHANGE, JOB, 0, &round.selected[0].slot, &holder)
            .ttl(MAX_LEASE_TTL_US + 1)
            .validate()
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// two hosts that misbehave on purpose
// ---------------------------------------------------------------------------

fn short(key: &SigningKey) -> String {
    let id = key.public_key().key_id();
    let body = id.strip_prefix("SHA256:").unwrap_or(&id);
    format!("SHA256:{}", &body[..4])
}

/// The update that hands a seat to `holder` — what a rival's write looks like.
fn lease_update(
    scene: &Scene,
    round: &Round,
    seat: usize,
    holder: &SigningKey,
    now: TimeUs,
) -> RefUpdate {
    lease_update_at(scene, round, seat, holder, now)
}

fn lease_update_at(
    scene: &Scene,
    round: &Round,
    seat: usize,
    holder: &SigningKey,
    now: TimeUs,
) -> RefUpdate {
    let request = lease_for(round, seat, holder, now);
    let mut lease = gitiup_quorum::job::Lease::new(
        request.job(),
        request.attempt,
        request.slot,
        &request.holder_id(),
        now,
        request.ttl_us,
        Vec::new(),
    )
    .unwrap();
    lease.sign(holder).unwrap();
    let oid = scene
        .host
        .put_cas(&Namespace::JOB, &lease.canonical_bytes().unwrap())
        .unwrap();
    let name = store::lease_ref(request.change_id, request.job_id, request.slot).unwrap();
    // The rival plays by the same rules: a CAS against whatever the ref holds now, so
    // the winner is decided by the store and not by who got there first in this test.
    match scene.host.get_ref(&name).unwrap() {
        Some(current) => RefUpdate::new(name, Expect::Is(current.oid), oid),
        None => RefUpdate::create(name, oid),
    }
}

/// A store that lets a rival slip its write in between this build's read and its CAS
/// write, once. That is the race two volunteers actually have, made deterministic: no
/// sleeps, no flaky threads, and the CAS has to be what settles it.
struct Raced<'a> {
    inner: &'a dyn Host,
    rival: RefUpdate,
    fired: AtomicBool,
}

impl<'a> Raced<'a> {
    fn new(inner: &'a FsHost, rival: RefUpdate) -> Raced<'a> {
        Raced {
            inner,
            rival,
            fired: AtomicBool::new(false),
        }
    }
}

impl RefStore for Raced<'_> {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.inner.list_refs(query)
    }

    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.inner.get_ref(name)
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        if !self.fired.swap(true, Ordering::SeqCst)
            && update.name.as_str().starts_with("refs/gitiup/lease/")
        {
            self.inner.update_ref_cas(&self.rival)?;
        }
        self.inner.update_ref_cas(update)
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> Result<(), HostError> {
        if !self.fired.swap(true, Ordering::SeqCst)
            && deletion.name.as_str().starts_with("refs/gitiup/lease/")
        {
            self.inner.update_ref_cas(&self.rival)?;
        }
        self.inner.delete_ref_cas(deletion)
    }

    fn fetch_pack(
        &self,
        request: &gitiup_host::PackRequest,
    ) -> Result<gitiup_host::Pack, HostError> {
        self.inner.fetch_pack(request)
    }

    fn put_pack(&self, pack: &gitiup_host::Pack) -> Result<Oid, HostError> {
        self.inner.put_pack(pack)
    }
}

impl BlobStore for Raced<'_> {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        self.inner.put_cas(namespace, content)
    }

    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        self.inner.get(oid)
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        self.inner.list_prefix(prefix)
    }
}

impl Host for Raced<'_> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

/// A store that keeps a bill: how many blobs a call fetched, and which refs it listed.
/// "Cheap enough for a poll" is a cost claim, so it gets a cost measurement.
struct Counting<'a> {
    inner: &'a dyn Host,
    gets: AtomicUsize,
    listed: Mutex<Vec<String>>,
    limits: Mutex<Vec<Option<usize>>>,
}

impl<'a> Counting<'a> {
    fn new(inner: &'a FsHost) -> Counting<'a> {
        Counting {
            inner,
            gets: AtomicUsize::new(0),
            listed: Mutex::new(Vec::new()),
            limits: Mutex::new(Vec::new()),
        }
    }

    fn gets(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }

    fn listed(&self) -> Vec<String> {
        self.listed.lock().expect("lock").clone()
    }

    fn limits(&self) -> Vec<Option<usize>> {
        self.limits.lock().expect("lock").clone()
    }
}

impl RefStore for Counting<'_> {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.listed
            .lock()
            .expect("lock")
            .push(query.prefix.clone().unwrap_or_default());
        self.limits.lock().expect("lock").push(query.limit);
        self.inner.list_refs(query)
    }

    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.inner.get_ref(name)
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        self.inner.update_ref_cas(update)
    }

    fn delete_ref_cas(&self, deletion: &RefDeletion) -> Result<(), HostError> {
        self.inner.delete_ref_cas(deletion)
    }

    fn fetch_pack(
        &self,
        request: &gitiup_host::PackRequest,
    ) -> Result<gitiup_host::Pack, HostError> {
        self.inner.fetch_pack(request)
    }

    fn put_pack(&self, pack: &gitiup_host::Pack) -> Result<Oid, HostError> {
        self.inner.put_pack(pack)
    }
}

impl BlobStore for Counting<'_> {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        self.inner.put_cas(namespace, content)
    }

    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(oid)
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        self.inner.list_prefix(prefix)
    }
}

impl Host for Counting<'_> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

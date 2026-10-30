//! Federation, over the hosts that can be stood up in a test.
//!
//! [ADR-0005](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! decides what a copy may carry; [`gitiup_host::federation`] is the code that carries
//! it. The acceptance criteria this file is written against are the ticket's, one test
//! each:
//!
//! * the verbs work between any two hosts, over each host's own pack/CAS path;
//! * the report counts arrived, re-hashed and refused objects, and marks nothing trusted;
//! * re-running a fetch moves nothing;
//! * an interrupted fetch leaves no ref advertising a partial set;
//! * `--proofs-only` moves evidence without code.
//!
//! Two of those need a store that misbehaves — one that stops halfway through, one that
//! will not take a write at all — and no honest host does either, so both are made with
//! the wrappers at the bottom, in the tradition of `tests/change_store.rs`.

mod change_support;

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use change_support::*;
use gitiup_host::attest::{self, MICROS};
use gitiup_host::blob::{BlobEntry, BlobStore, Namespace, Prefix};
use gitiup_host::change::{self, ChangeId};
use gitiup_host::federation::{self, AGE_BASIS, Options, TRUST_NONE, Verb, classify, copy};
use gitiup_host::hosts::git::GitHost;
use gitiup_host::{
    Actor, Capabilities, FsHost, Host, HostError, HostInfo, MemoryBucket, Oid, Pack, PackRequest,
    Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate, RemoteConfig, S3Host, SharedBucket,
};

// ---------------------------------------------------------------------------
// the stores
// ---------------------------------------------------------------------------

/// A directory store in a temp dir that outlives each handle.
struct FsStore {
    root: PathBuf,
    created: Cell<bool>,
}

impl FsStore {
    fn new() -> FsStore {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("store");
        std::mem::forget(dir);
        FsStore {
            root,
            created: Cell::new(false),
        }
    }

    fn open(&self) -> Box<dyn Host> {
        if self.created.get() {
            Box::new(FsHost::open(&self.root).expect("reopen"))
        } else {
            self.created.set(true);
            Box::new(FsHost::create(&self.root).expect("create"))
        }
    }
}

/// A bucket store on the in-process bucket.
struct BucketStore {
    bucket: MemoryBucket,
    created: Cell<bool>,
}

impl BucketStore {
    fn new() -> BucketStore {
        BucketStore {
            bucket: MemoryBucket::forge("gitiup-mirror"),
            created: Cell::new(false),
        }
    }

    fn open(&self) -> Box<dyn Host> {
        let remote = RemoteConfig::new("mirror", "s3://gitiup-mirror/repo")
            .expect("s3 remote")
            .with_option("ref-cache-ttl", "0s");
        let shared: SharedBucket = Arc::new(self.bucket.clone());
        if self.created.get() {
            Box::new(S3Host::open(shared, &remote).expect("reopen bucket"))
        } else {
            self.created.set(true);
            Box::new(S3Host::init(shared, &remote).expect("init bucket"))
        }
    }
}

/// A bare repository driven by the git binary, with real commits so the code half of a
/// copy has something to talk about.
struct GitStore {
    dir: tempfile::TempDir,
    repo: PathBuf,
}

impl GitStore {
    fn new() -> GitStore {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = dir.path().join("repo.git");
        if gitiup_host::hosts::git::git_program().is_none() {
            eprintln!("skipping: no git binary");
        }
        gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");
        GitStore { dir, repo }
    }

    fn open(&self, name: &str) -> Box<dyn Host> {
        let remote = RemoteConfig::new(name, &format!("file://{}", self.repo.display()))
            .expect("file url")
            .with_option(
                "work-dir",
                self.dir
                    .path()
                    .join(format!("mirror-{name}"))
                    .display()
                    .to_string(),
            );
        Box::new(GitHost::open_or_init(&remote).expect("open git host"))
    }
}

/// A directory store behind a factory, so a pair can hand out a fresh handle.
fn fs_box() -> Box<dyn Fn() -> Box<dyn Host>> {
    let store = FsStore::new();
    Box::new(move || store.open())
}

/// A bucket store behind a factory.
fn bucket_box() -> Box<dyn Fn() -> Box<dyn Host>> {
    let store = BucketStore::new();
    Box::new(move || store.open())
}

/// Every host pair worth crossing, with a name for the test log.
///
/// A store per side, not a store per test: a pair that shared a store with another pair
/// would see the previous pair's copies arrive and report them as `already`.
/// One named pair: a source factory and a destination factory.
type Pair = (
    &'static str,
    Box<dyn Fn() -> Box<dyn Host>>,
    Box<dyn Fn() -> Box<dyn Host>>,
);

fn pairs() -> Vec<Pair> {
    vec![
        ("fs \u{2192} fs", fs_box(), fs_box()),
        ("fs \u{2192} bucket", fs_box(), bucket_box()),
        ("bucket \u{2192} fs", bucket_box(), fs_box()),
        ("bucket \u{2192} bucket", bucket_box(), bucket_box()),
    ]
}

// ---------------------------------------------------------------------------
// a store full of everything the table has an opinion about
// ---------------------------------------------------------------------------

/// What was put in a store, so a test can say what should and should not arrive.
struct Seeded {
    /// The change, and the attempt numbers published.
    change_id: String,
    /// Portable refs, by name.
    portable: Vec<String>,
    /// Refs that must never arrive, by name.
    refused: Vec<String>,
    /// The attestation digests that travelled.
    digests: Vec<Oid>,
}

/// File one record and advertise it, the way every publisher does: bytes then ref.
fn advertise(host: &dyn Host, namespace: &Namespace, name: &str, bytes: &[u8]) -> Oid {
    let digest = host.put_cas(namespace, bytes).expect("put_cas");
    host.update_ref_cas(&RefUpdate::create(
        RefName::new(name).expect("ref name"),
        digest,
    ))
    .expect("update_ref_cas");
    digest
}

/// Fill a store with one of everything: proofs, a change with two attempts and a moved
/// `head`, roster epochs, verdicts, rounds, and then the arbitration state that must
/// never travel — a lease, a job advertisement, a pending sign-up, the live pointers,
/// and a branch.
fn seed(host: &dyn Host) -> Seeded {
    let subject = Oid::from_hex(HEAD_ONE.split_once(':').unwrap().1).expect("subject oid");
    let mut portable = Vec::new();
    let mut refused = Vec::new();
    let mut digests = Vec::new();

    // Two proofs about one commit, in the current spelling, and one in the legacy
    // single-level shape that a copy re-spells rather than re-creates (D7).
    for (index, body) in ["proof-one", "proof-two"].iter().enumerate() {
        let published = attest::publish(host, &subject, body.as_bytes(), "ada").expect("publish");
        digests.push(published.digest);
        portable.push(published.reference.as_str().to_string());
        let _ = index;
    }
    let legacy_bytes = b"legacy-proof".to_vec();
    let legacy_digest = host
        .put_cas(&Namespace::ATTESTATION, &legacy_bytes)
        .expect("legacy blob");
    host.update_ref_cas(&RefUpdate::create(
        attest::legacy_ref_name(&subject),
        legacy_digest,
    ))
    .expect("legacy ref");
    refused.push(attest::legacy_ref_name(&subject).as_str().to_string());

    // A change: attempt 0, a re-submit as attempt 1, and a `head` moved to 1.
    let zero = signed_change("ada", "carry the proofs", HEAD_ONE, HEAD_ONE, 0, None);
    change::publish_change(host, &zero, Actor::new("ada").unwrap()).expect("attempt 0");
    let one = signed_change(
        "ada",
        "carry the proofs, again",
        HEAD_ONE,
        HEAD_TWO,
        1,
        Some(zero.change_digest().expect("change digest")),
    );
    change::publish_change(host, &one, Actor::new("ada").unwrap()).expect("attempt 1");
    let change_id = one.change_id.as_str().to_string();
    portable.push(format!("refs/changes/{change_id}/attempt/0"));
    portable.push(format!("refs/changes/{change_id}/attempt/1"));
    refused.push(format!("refs/changes/{change_id}/head"));

    // Quorum evidence that travels, and the live state that does not.
    let roster = Namespace::ROSTER;
    advertise(host, &roster, "refs/gitiup/roster/00000007", b"epoch seven");
    advertise(
        host,
        &roster,
        "refs/gitiup/roster",
        b"epoch seven, live now",
    );
    portable.push("refs/gitiup/roster/00000007".to_string());
    refused.push("refs/gitiup/roster".to_string());

    advertise(
        host,
        &Namespace::new("revocation").unwrap(),
        "refs/gitiup/revocation/0000000000000001",
        b"key revoked",
    );
    portable.push("refs/gitiup/revocation/0000000000000001".to_string());

    advertise(
        host,
        &Namespace::JOB,
        "refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0",
        b"round zero",
    );
    portable.push("refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0".to_string());

    advertise(
        host,
        &Namespace::POLICY,
        "refs/gitiup/verdict/chg-6a6a8eab778ba4d0/build",
        b"verdict: verified 4 of 5",
    );
    portable.push("refs/gitiup/verdict/chg-6a6a8eab778ba4d0/build".to_string());

    advertise(
        host,
        &Namespace::new("reveal").unwrap(),
        "refs/gitiup/reveal/chg-6a6a8eab778ba4d0/build/0000000000000001",
        b"reveal one",
    );
    portable.push("refs/gitiup/reveal/chg-6a6a8eab778ba4d0/build/0000000000000001".to_string());
    advertise(
        host,
        &Namespace::new("commit").unwrap(),
        "refs/gitiup/commit/chg-6a6a8eab778ba4d0/build/0000000000000001",
        b"commitment one",
    );
    portable.push("refs/gitiup/commit/chg-6a6a8eab778ba4d0/build/0000000000000001".to_string());

    advertise(
        host,
        &Namespace::POLICY,
        "refs/gitiup/policy/history/000001",
        b"policy revision one",
    );
    portable.push("refs/gitiup/policy/history/000001".to_string());
    advertise(
        host,
        &Namespace::POLICY,
        "refs/gitiup/policy/current",
        b"policy revision one, live now",
    );
    refused.push("refs/gitiup/policy/current".to_string());

    advertise(
        host,
        &Namespace::JOB,
        "refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001",
        b"lease: 15 minutes, from now",
    );
    refused.push("refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001".to_string());
    advertise(
        host,
        &Namespace::JOB,
        "refs/gitiup/job/chg-6a6a8eab778ba4d0/build",
        b"this round is open here",
    );
    refused.push("refs/gitiup/job/chg-6a6a8eab778ba4d0/build".to_string());
    advertise(
        host,
        &Namespace::new("signup").unwrap(),
        "refs/gitiup/signup/0000000000000002",
        b"a volunteer awaiting a human",
    );
    refused.push("refs/gitiup/signup/0000000000000002".to_string());

    Seeded {
        change_id,
        portable,
        refused,
        digests,
    }
}

/// Every ref a store advertises, by name.
fn refs(host: &dyn Host) -> Vec<String> {
    host.list_refs(&RefQuery::all())
        .expect("list_refs")
        .into_iter()
        .map(|reference| reference.name.as_str().to_string())
        .collect()
}

/// The portable refs of `seeded` that a store advertises.
fn present(host: &dyn Host, names: &[String]) -> Vec<String> {
    let have = refs(host);
    names
        .iter()
        .filter(|name| have.contains(name))
        .cloned()
        .collect()
}

fn options(verb: Verb, from: &str, to: &str) -> Options {
    Options {
        verb,
        from: from.to_string(),
        to: to.to_string(),
        actor: Actor::new("mirror-bot").unwrap(),
        now_us: 1_793_347_200 * MICROS,
        ..Options::new(verb, from, to)
    }
}

// ---------------------------------------------------------------------------
// the acceptance criteria
// ---------------------------------------------------------------------------

/// Every portable ref arrives, every refused one stays home, and the report says both.
///
/// Run over each host pair the hermetic hosts can form, because the ticket's first
/// acceptance criterion is "between any two hosts", and a claim like that is worth
/// nothing tested on one.
#[test]
fn a_copy_moves_what_may_travel_and_refuses_by_name_what_may_not() {
    for (label, source, destination) in pairs() {
        eprintln!("--- {label}");
        let from = source();
        let seeded = seed(&*from);
        let to = destination();
        let report = copy(&*from, &*to, &options(Verb::Fetch, "origin", "this store"))
            .unwrap_or_else(|error| panic!("{label}: copy failed: {error}"));

        // Everything portable is advertised here, at the same value.
        let arrived = present(&*to, &seeded.portable);
        assert_eq!(
            arrived.len(),
            seeded.portable.len(),
            "{label}: only {arrived:?} of {:?}",
            seeded.portable
        );
        // …and it is the same bytes under the same name.
        for reference in from
            .list_refs(&RefQuery::all())
            .unwrap()
            .into_iter()
            .filter(|reference| classify(&reference.name).portable)
            // A legacy single-level ref arrives under a *new* name on purpose.
            .filter(|reference| !classify(&reference.name).respell)
        {
            let here = to
                .get_ref(&reference.name)
                .unwrap()
                .unwrap_or_else(|| panic!("{label}: {} did not arrive", reference.name));
            assert_eq!(here.oid, reference.oid, "{label}: {} moved", reference.name);
            assert_eq!(
                to.get(&reference.oid).unwrap(),
                from.get(&reference.oid).unwrap(),
                "{label}: {} arrived as different bytes",
                reference.name
            );
        }

        // Nothing that was refused is here, and each refusal is named.
        let have = refs(&*to);
        for name in &seeded.refused {
            // A change's `head` is the one refused ref that gets written here anyway: it
            // is *re-derived* from the attempts this run took, not copied (D2).
            if name.ends_with("/head") {
                assert!(
                    have.contains(name),
                    "{label}: {name} should have been resolved and written: {have:?}"
                );
                continue;
            }
            assert!(
                !have.contains(name),
                "{label}: {name} is not portable and must not be advertised here"
            );
        }
        let tokens: Vec<&str> = report
            .refused
            .iter()
            .map(|refusal| refusal.token.as_str())
            .collect();
        assert!(
            tokens.contains(&"not_portable"),
            "{label}: a refusal went unreported: {:?}",
            report.refused
        );
        for refusal in &report.refused {
            assert!(
                federation::knows_token(&refusal.token),
                "{label}: {} is not a federation token",
                refusal.token
            );
        }

        // The counters add up, and the report says what it says.
        assert!(report.objects.arrived > 0, "{label}: nothing arrived");
        assert_eq!(
            report.objects.arrived + report.objects.already,
            report.objects.rehashed,
            "{label}: arrived + already should be everything re-hashed: {:?}",
            report.objects
        );
        assert_eq!(
            report.trust, TRUST_NONE,
            "{label}: a copy granted something"
        );
        assert_eq!(
            report.age_basis, AGE_BASIS,
            "{label}: age was measured from something else"
        );
        assert_eq!(
            report.refused_by.values().sum::<usize>(),
            report.refused.len(),
            "{label}: the tallies disagree"
        );
        // And the change's pointer was *resolved*, not copied: it names an attempt.
        let head = format!("refs/changes/{}/head", seeded.change_id);
        let resolved = report
            .pointers
            .iter()
            .find(|pointer| pointer.reference == head)
            .unwrap_or_else(|| {
                panic!(
                    "{label}: no pointer report for {head}: {:?}",
                    report.pointers
                )
            });
        assert!(
            resolved.resolved.contains("/attempt/"),
            "{label}: head resolved to {}",
            resolved.resolved
        );
        assert!(
            to.get_ref(&RefName::new(head.clone()).unwrap())
                .unwrap()
                .is_some(),
            "{label}: {head} was not written, so the change has no current attempt here"
        );
    }
}

/// A second run says `already` to all of it and writes nothing.
#[test]
fn re_running_a_copy_moves_nothing() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let first = copy(
        &*source,
        &*to.open(),
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("first copy");
    let destination = to.open();
    let before = refs(&*destination);
    let _ = &before;
    let second = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("second copy");
    assert_eq!(second.objects.arrived, 0, "a re-run stored bytes again");
    assert!(second.objects.already > 0, "a re-run found nothing to skip");
    assert_eq!(second.refs.written, 0, "a re-run wrote a ref again");
    let already_pointers = second
        .pointers
        .iter()
        .filter(|pointer| pointer.action == "already")
        .count();
    assert_eq!(
        second.refs.already + already_pointers,
        first.refs.written + first.refs.moved,
        "a re-run should find every advertisement already in place"
    );
    assert_eq!(refs(&*destination), before, "a re-run changed the store");
    assert_eq!(
        second.arrivals, 0,
        "a re-run wrote arrival records for bytes that did not arrive"
    );
}

/// The destination refuses mid-run: no ref may then advertise bytes that are not there,
/// and the next run finishes the job.
/// A dry run is a plan and nothing else — including, above all, no advertisement.
///
/// The bytes are read from the source and re-hashed (that is what the plan is worth), but
/// the destination is untouched. A `--dry-run` that left a ref naming bytes nobody can
/// return would be the exact failure D8 rule 1 forbids, planted by the one flag whose
/// whole purpose is not to touch anything.
#[test]
fn a_dry_run_plans_the_copy_and_touches_nothing() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let destination = to.open();

    let mut plan = options(Verb::Fetch, "origin", "this store");
    plan.dry_run = true;
    let report = copy(&*source, &*destination, &plan).expect("a dry run plans a copy");
    assert!(report.dry_run);
    assert!(
        report.objects.arrived > 0 && report.refs.written > 0,
        "the dry run reported nothing to do: {report:?}"
    );
    assert_eq!(report.objects.rehashed, report.objects.arrived);
    assert_eq!(report.arrivals, 0, "a dry run wrote arrival records");

    // Every count was a plan, and the store is the store it was.
    let after = to.open();
    let advertisements = after.list_refs(&RefQuery::all()).unwrap();
    assert!(
        advertisements.is_empty(),
        "a dry run wrote advertisements: {:?}",
        advertisements
            .iter()
            .map(|reference| reference.name.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        after
            .list_prefix(&Prefix::all().as_str())
            .unwrap()
            .is_empty(),
        "a dry run wrote bytes"
    );

    // …and the run after it does exactly what the plan said, which is the only reason a
    // dry report is worth reading.
    let real = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("the copy the plan described");
    assert_eq!(
        real.objects.arrived, report.objects.arrived,
        "the plan was a guess"
    );
    assert_eq!(real.refs.written, report.refs.written);
}

#[test]
fn an_interrupted_copy_leaves_no_advertisement_without_its_bytes() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    let seeded = seed(&*source);
    let destination = to.open();

    // Die partway through: enough to write some records and not the rest.
    let limit = 6;
    let interrupted = Interrupted::new(destination, limit);
    let outcome = copy(
        &*source,
        &interrupted,
        &options(Verb::Fetch, "origin", "this store"),
    );
    let stopped = match &outcome {
        Ok(report) => report.refs.written == 0,
        Err(_) => true,
    };
    assert!(
        stopped,
        "the run was supposed to be interrupted, and it was not: {:?}",
        outcome
            .as_ref()
            .ok()
            .map(|report| (report.objects.arrived, report.refs.written))
    );

    // The invariant, in both directions: every advertisement names bytes this store can
    // return, and no pointer names an attempt this store cannot show.
    let to = to.open();
    for reference in to.list_refs(&RefQuery::all()).unwrap() {
        assert!(
            to.get(&reference.oid).unwrap().is_some(),
            "{} is advertised at {} and this store cannot return those bytes",
            reference.name,
            reference.oid.short_default()
        );
    }
    if let Some(head) = to
        .get_ref(&RefName::new(format!("refs/changes/{}/head", seeded.change_id)).unwrap())
        .unwrap()
    {
        let named = to
            .list_refs(&RefQuery::prefix(format!(
                "refs/changes/{}/",
                seeded.change_id
            )))
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.oid == head.oid);
        assert!(
            named.is_some(),
            "the head pointer was moved to a record this store does not advertise"
        );
    }

    // Resume: the same copy, uninterrupted, and the store is complete.
    let finished = copy(
        &*source,
        &*to,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("the resumed copy");
    let arrived = present(&*to, &seeded.portable);
    assert_eq!(
        arrived.len(),
        seeded.portable.len(),
        "the resumed copy left records missing: {arrived:?}"
    );
    assert!(
        finished.objects.arrived > 0,
        "the resumed copy stored nothing new"
    );
}

/// A pointer is resolved on this side of the wire and never moved backwards (D2, D7).
#[test]
fn a_pointer_is_resolved_here_and_never_moves_backwards() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    let seeded = seed(&*source);
    let head = RefName::new(format!("refs/changes/{}/head", seeded.change_id)).unwrap();
    let destination = to.open();

    let report = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("copy");
    let pointer = report
        .pointers
        .iter()
        .find(|pointer| pointer.reference == head.as_str())
        .expect("a pointer report");
    assert_eq!(pointer.action, "written");
    assert!(
        pointer.resolved.ends_with("attempt/1"),
        "{}",
        pointer.resolved
    );

    // This store now has an attempt the origin does not: a copy may not talk it out of
    // its own newer attempt, because a store never advertises less than it did.
    let ahead = signed_change(
        "ada",
        "a third attempt, published here",
        HEAD_ONE,
        HEAD_THREE,
        2,
        Some({
            let attempts = source
                .list_refs(&RefQuery::prefix(format!(
                    "refs/changes/{}/",
                    seeded.change_id
                )))
                .unwrap();
            let two = attempts
                .iter()
                .find(|candidate| candidate.name.as_str().ends_with("attempt/1"))
                .expect("attempt 1");
            let bytes = source.get(&two.oid).unwrap().expect("attempt bytes");
            let record = match change::record_from_bytes(&bytes).unwrap() {
                change::StoredRecord::Change(record) => record,
                other => panic!("expected a change record, got {}", other.record_type()),
            };
            record.change_digest().unwrap()
        }),
    );
    change::publish_change(&*destination, &ahead, Actor::new("ada").unwrap()).expect("attempt 2");
    let report = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("copy again");
    let pointer = report
        .pointers
        .iter()
        .find(|pointer| pointer.reference == head.as_str())
        .expect("a pointer report");
    assert_eq!(
        pointer.action, "held",
        "a copy moved this store's head backwards: {pointer:?}"
    );
    assert_eq!(
        destination.get_ref(&head).unwrap().unwrap().oid,
        ahead.digest().unwrap(),
        "the head moved anyway"
    );
}

/// A name that already holds other bytes is kept, and the clash is reported (D7).
#[test]
fn a_name_that_already_holds_other_bytes_is_kept_and_reported() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let destination = to.open();
    // Somebody else's round record, under the name ours would arrive at.
    let clash = advertise(
        &*destination,
        &Namespace::JOB,
        "refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0",
        b"a different round entirely",
    );
    let report = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("copy");
    let refusal = report
        .refused
        .iter()
        .find(|refusal| {
            refusal.reference.as_deref() == Some("refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0")
        })
        .expect("the clash was not reported");
    assert_eq!(refusal.token, "digest_mismatch");
    assert_eq!(refusal.exit, 8);
    assert_eq!(
        destination
            .get_ref(&RefName::new("refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0").unwrap())
            .unwrap()
            .unwrap()
            .oid,
        clash,
        "the copy overwrote a record that was already here"
    );
    assert!(
        destination.get(&clash).unwrap().is_some(),
        "the bytes that were here were dropped"
    );
}

/// `--proofs-only` moves evidence and no code, and says which one it declined.
#[test]
fn proofs_only_moves_evidence_and_no_code() {
    let source = FsStore::new();
    let from = source.open();
    let seeded = seed(&*from);
    let mirror = FsStore::new();
    let to = mirror.open();

    let report = copy(
        &*from,
        &*to,
        &Options {
            proofs_only: true,
            ..options(Verb::Push, "origin", "mirror")
        },
    )
    .expect("proofs-only copy");
    assert_eq!(report.code.outcome, "declined");
    assert_eq!(report.code.carried, 0);
    assert!(
        report
            .subject
            .excused
            .as_deref()
            .unwrap_or_default()
            .contains("--proofs-only"),
        "the excuse was not printed: {:?}",
        report.subject
    );
    // The evidence is all here.
    assert_eq!(present(&*to, &seeded.portable).len(), seeded.portable.len());
    // And no code: no branch, and nothing that is not a gitiup record.
    assert!(
        !refs(&*to)
            .iter()
            .any(|name| name.starts_with("refs/heads/")),
        "a proofs-only mirror grew a branch: {:?}",
        refs(&*to)
    );
    // The same store without the flag asks for the code and is told, in the report, that
    // this host pair has no git object database to move it through.
    let another = FsStore::new();
    let with_code = another.open();
    let report =
        copy(&*from, &*with_code, &options(Verb::Fetch, "origin", "here")).expect("full copy");
    assert_ne!(report.code.outcome, "declined");
    assert!(report.code.asked > 0, "no code was ever asked for");
    assert!(
        matches!(
            report.code.outcome.as_str(),
            "unsupported" | "missing" | "carried" | "refused"
        ),
        "unexpected code outcome {:?}",
        report.code
    );
    assert!(
        report.subject.attestations >= 2,
        "the proofs were not counted"
    );
}

/// The report has no field a caller may branch on to decide a merge (D3 clause 4).
#[test]
fn the_report_marks_nothing_trusted() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let report = copy(
        &*source,
        &*to.open(),
        &options(Verb::Fetch, "origin", "this store"),
    )
    .expect("copy");
    let value = serde_json::to_value(&report).expect("the report serialises");
    let text = value.to_string();
    for forbidden in [
        "trusted",
        "\"trust\": \"full\"",
        "verified_by",
        "authoritative",
    ] {
        assert!(
            !text.contains(forbidden),
            "the report carries `{forbidden}`, which a caller could read as permission: {text}"
        );
    }
    assert_eq!(value["trust"], TRUST_NONE);
    assert_eq!(value["age_basis"], AGE_BASIS);
    // And nothing in `kv/import/**` claims to have verified what it recorded.
    let destination = to.open();
    let arrivals = federation::arrivals(&*destination).expect("arrivals");
    assert!(!arrivals.is_empty(), "no arrival record was written");
    for arrival in arrivals.values() {
        assert_eq!(arrival.arrived_from, "origin");
        assert_eq!(arrival.closure, "not-walked");
        assert!(arrival.arrived_at_us > 0);
    }
}

/// A store that cannot take a write is refused by name, before anything is listed or
/// copied (D6's `read_only`).
#[test]
fn a_store_that_cannot_be_written_is_refused_by_name() {
    let from = FsStore::new();
    let source = from.open();
    seed(&*source);
    // A store that already holds a copy and will not take another write: what a mirror
    // behind dumb HTTP says about itself.
    let mirror = FsStore::new();
    seed(&*mirror.open());
    let read_only = ReadOnly(mirror.open());
    let error = copy(
        &*source,
        &read_only,
        &options(Verb::Push, "origin", "the public mirror"),
    )
    .expect_err("a read-only destination must be refused");
    assert_eq!(error.exit_code(), 6);
    assert!(
        error.message().contains("read_only"),
        "the refusal does not name its token: {error}"
    );
    assert_eq!(federation::token_for(&error), "read_only");
    // …and the same store is a perfectly good place to read *from*: that is what a
    // public mirror is for.
    let fresh = FsStore::new();
    let report = copy(
        &read_only,
        &*fresh.open(),
        &options(Verb::Fetch, "the public mirror", "here"),
    )
    .expect("reading from a read-only store is what a mirror is for");
    assert!(report.objects.arrived > 0);
}

/// A budget is a refusal, never a truncation (D10).
#[test]
fn a_budget_busts_rather_than_truncates() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let error = copy(
        &*source,
        &*to.open(),
        &Options {
            budgets: federation::Budgets {
                records: 2,
                ..federation::Budgets::default()
            },
            ..options(Verb::Fetch, "origin", "here")
        },
    )
    .expect_err("two records is not enough for this store");
    assert_eq!(error.exit_code(), 6);
    assert_eq!(federation::token_for(&error), "closure_budget_records");
    assert!(
        to.open().list_refs(&RefQuery::all()).unwrap().is_empty(),
        "a refused copy wrote something"
    );
}

/// A `--change` fetch brings the change, the quorum records addressed to it, and the
/// proofs filed for the commit it proposes — and nothing else.
#[test]
fn selecting_one_change_brings_that_change_and_its_proofs() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    let seeded = seed(&*source);
    let destination = to.open();
    let report = copy(
        &*source,
        &*destination,
        &Options {
            change: Some(ChangeId::new(&seeded.change_id).expect("change id")),
            ..options(Verb::Fetch, "origin", "here")
        },
    )
    .expect("selective copy");
    let have = refs(&*destination);
    assert!(
        have.iter()
            .any(|name| name.starts_with(&format!("refs/changes/{}/", seeded.change_id))),
        "the change did not arrive: {have:?}"
    );
    assert!(
        have.iter()
            .any(|name| name.starts_with("refs/attestations/")),
        "the proofs filed for the change's commit did not arrive: {have:?}"
    );
    assert!(
        !have
            .iter()
            .any(|name| name.starts_with("refs/gitiup/roster")),
        "a change fetch pulled the roster namespace in: {have:?}"
    );
    assert!(
        !have.iter().any(|name| name.contains("policy")),
        "a change fetch pulled the policy namespace in: {have:?}"
    );
    assert!(report.budget.records < seeded.portable.len());
}

/// The same bytes, the same names, whichever pair of hosts you pick: this is the claim
/// that makes "not tied to GitHub" mean something.
#[test]
fn the_same_bytes_arrive_whichever_two_hosts_you_pick() {
    for (label, source, destination) in pairs() {
        let from = source();
        let seeded = seed(&*from);
        let to = destination();
        copy(&*from, &*to, &options(Verb::Fetch, "origin", "here")).expect(label);
        for digest in &seeded.digests {
            assert_eq!(
                to.get(digest).unwrap().as_deref(),
                from.get(digest).unwrap().as_deref(),
                "{label}: {digest} arrived as different bytes"
            );
        }
    }
}

/// A bucket's records pushed into a bare repository: the pair where the destination
/// turns every record into a pointer commit and a chain append, because that is what a
/// git host's own CAS path is. Then read back out again, which is the claim that a
/// mirror is not a dead end.
#[test]
fn records_from_a_bucket_land_in_a_bare_repository() {
    if gitiup_host::hosts::git::git_program().is_none() {
        eprintln!("skipping: no git binary");
        return;
    }
    let from = BucketStore::new();
    let source = from.open();
    let seeded = seed(&*source);
    let mirror = GitStore::new();
    let to = mirror.open("mirror");
    let report = copy(
        &*source,
        &*to,
        &options(Verb::Push, "the bucket", "the repository"),
    )
    .expect("push a copy into a repository");
    assert!(report.objects.arrived > 0);
    assert_eq!(
        present(&*to, &seeded.portable).len(),
        seeded.portable.len(),
        "a repository did not advertise what it was given: {:?}",
        refs(&*to)
    );
    for name in &seeded.refused {
        if name.ends_with("/head") {
            continue;
        }
        assert!(
            !refs(&*to).contains(name),
            "{name} was written into the repository"
        );
    }

    // …and the repository can serve them back to somebody else, unchanged.
    let reader = mirror.open("reader");
    let onward = FsStore::new();
    let back = copy(
        &*reader,
        &*onward.open(),
        &options(Verb::Fetch, "the repository", "here"),
    )
    .expect("fetch back out of the repository");
    let here = onward.open();
    assert_eq!(
        present(&*here, &seeded.portable).len(),
        seeded.portable.len(),
        "a copy of a copy lost records: {:?}",
        refs(&*here)
    );
    assert!(back.objects.arrived > 0);
}

/// The legacy single-level attestation ref is read, re-spelled, and never re-created
/// in the old shape (D7).
#[test]
fn a_legacy_ref_is_respelled_and_never_recreated() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    seed(&*source);
    let subject = attest::legacy_ref_name(
        &Oid::from_hex(HEAD_ONE.split_once(':').unwrap().1).expect("subject"),
    );
    assert!(refs(&*source).contains(&subject.as_str().to_string()));

    let destination = to.open();
    let report = copy(
        &*source,
        &*destination,
        &options(Verb::Fetch, "origin", "here"),
    )
    .expect("copy");
    assert_eq!(report.refs.respelled, 1, "{:?}", report.refs);
    let have = refs(&*destination);
    assert!(
        !have.contains(&subject.as_str().to_string()),
        "the legacy spelling was recreated: {have:?}"
    );
    let under = have
        .iter()
        .filter(|name| name.starts_with(&format!("{}/", subject.as_str())))
        .count();
    // Two proofs published in the current shape, plus the legacy one re-spelled into it.
    assert_eq!(under, 3, "the re-spelled ref is missing: {have:?}");
}

/// A source that advertises bytes it cannot return loses that record and the rest of the
/// run, and says which it lost (D8's failure, met rather than trusted).
#[test]
fn a_source_missing_its_own_advertised_bytes_loses_that_record_only() {
    let from = FsStore::new();
    let to = FsStore::new();
    let source = from.open();
    let seeded = seed(&*source);
    // Take one advertised blob out from under its ref: exactly the lazy-mirror failure
    // ADR-0005 D8 forecloses, produced on purpose.
    let victim = seeded
        .digests
        .first()
        .copied()
        .expect("a published attestation");
    let missing = MissingBlob {
        inner: source,
        gone: victim,
    };
    let destination = to.open();
    let report = copy(
        &missing,
        &*destination,
        &options(Verb::Fetch, "origin", "here"),
    )
    .expect("the run carries on past one broken record");
    assert!(
        report
            .refused
            .iter()
            .any(|refusal| refusal.token == "closure_incomplete"),
        "the missing bytes were not reported: {:?}",
        report.refused
    );
    assert!(
        report.objects.arrived > 0,
        "the whole run stopped for one bad ref"
    );
}

// ---------------------------------------------------------------------------
// stores that misbehave
// ---------------------------------------------------------------------------

/// A destination that stops taking writes after `limit` blobs: the interrupted run.
struct Interrupted {
    inner: Box<dyn Host>,
    left: AtomicUsize,
}

impl Interrupted {
    fn new(inner: Box<dyn Host>, limit: usize) -> Interrupted {
        Interrupted {
            inner,
            left: AtomicUsize::new(limit),
        }
    }
}

impl RefStore for Interrupted {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.inner.list_refs(query)
    }
    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.inner.get_ref(name)
    }
    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        if self.left.load(Ordering::SeqCst) == 0 {
            return Err(HostError::unreachable("the operator's laptop closed"));
        }
        self.inner.update_ref_cas(update)
    }
    fn delete_ref_cas(&self, deletion: &RefDeletion) -> Result<(), HostError> {
        self.inner.delete_ref_cas(deletion)
    }
    fn fetch_pack(&self, request: &PackRequest) -> Result<Pack, HostError> {
        self.inner.fetch_pack(request)
    }
    fn put_pack(&self, pack: &Pack) -> Result<Oid, HostError> {
        self.inner.put_pack(pack)
    }
}

impl BlobStore for Interrupted {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        let left = self.left.load(Ordering::SeqCst);
        if left == 0 {
            return Err(HostError::unreachable("the operator's laptop closed"));
        }
        self.left.store(left - 1, Ordering::SeqCst);
        self.inner.put_cas(namespace, content)
    }
    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        self.inner.get(oid)
    }
    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        self.inner.list_prefix(prefix)
    }
    fn head(&self, oid: &Oid) -> Result<Option<BlobEntry>, HostError> {
        self.inner.head(oid)
    }
}

impl Host for Interrupted {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

/// A store that will not be written to at all: what a dumb-HTTP mirror reports.
struct ReadOnly(Box<dyn Host>);

impl RefStore for ReadOnly {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.0.list_refs(query)
    }
    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.0.get_ref(name)
    }
    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        Err(HostError::unsupported(
            "cas",
            format!(
                "this host is read-only: {} would be the first write",
                update.name
            ),
        ))
    }
    fn delete_ref_cas(&self, deletion: &RefDeletion) -> Result<(), HostError> {
        Err(HostError::unsupported(
            "cas",
            format!("this host is read-only: {:?}", deletion.name),
        ))
    }
    fn fetch_pack(&self, request: &PackRequest) -> Result<Pack, HostError> {
        self.0.fetch_pack(request)
    }
    fn put_pack(&self, pack: &Pack) -> Result<Oid, HostError> {
        self.0.put_pack(pack)
    }
}

impl BlobStore for ReadOnly {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        self.0.put_cas(namespace, content)
    }
    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        self.0.get(oid)
    }
    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        self.0.list_prefix(prefix)
    }
}

impl Host for ReadOnly {
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.0.capabilities();
        capabilities.cas = false;
        capabilities
    }
    fn describe(&self) -> HostInfo {
        self.0.describe()
    }
}

/// A source that has lost the bytes one of its refs advertises.
struct MissingBlob {
    inner: Box<dyn Host>,
    gone: Oid,
}

impl RefStore for MissingBlob {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
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
    fn fetch_pack(&self, request: &PackRequest) -> Result<Pack, HostError> {
        self.inner.fetch_pack(request)
    }
    fn put_pack(&self, pack: &Pack) -> Result<Oid, HostError> {
        self.inner.put_pack(pack)
    }
}

impl BlobStore for MissingBlob {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        self.inner.put_cas(namespace, content)
    }
    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        if *oid == self.gone {
            return Ok(None);
        }
        self.inner.get(oid)
    }
    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        Ok(self
            .inner
            .list_prefix(prefix)?
            .into_iter()
            .filter(|entry| entry.oid != self.gone)
            .collect())
    }
}

impl Host for MissingBlob {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

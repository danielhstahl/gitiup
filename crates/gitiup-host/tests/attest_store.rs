//! The attestation store (giti-1rs.5), run against every host that is not a
//! network service: the `fs` host, and the bucket-as-forge host on its in-process
//! bucket — plus a freshly reopened handle in each case, because "the attestation
//! is retrievable" means retrievable *later, by someone else*, not "it is in this
//! process's memory".
//!
//! The bodies are host-neutral on purpose. The point of the host trait set is that
//! `gitiup attest list --commit <oid>` and `gitiup attest gc` mean one thing
//! wherever the repo lives, so each body is written once and run against each store
//! rather than re-derived per transport. The plain-git host is covered in
//! `tests/host_git.rs`, where the claim that needs git — that a plain clone fetches
//! the proof — can actually be tested.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use gitiup_host::attest::{self, AttestationItem, BlobAction, GcOptions, MICROS, Retention};
use gitiup_host::{
    Actor, BlobStore, Expect, FsHost, Host, HostErrorExt, MemoryBucket, Namespace, Oid,
    RefDeletion, RefName, RefStore, RefUpdate, RemoteConfig, S3Host, SharedBucket,
};

/// A commit oid to attest to. Any well-formed sha1 will do: the store never parses
/// what it holds.
const COMMIT: &str = "e255b091aabd7e443b5d2fbeb90bc9769d07cbeb";
/// A second commit, to prove a listing does not leak across subjects.
const OTHER: &str = "2222222222222222222222222222222222222222";

fn commit(hex: &str) -> Oid {
    Oid::from_hex(hex).expect("a hex oid")
}

/// A store reopened from a temp directory: `None` the first time (create it), the
/// same store every time after (open it).
struct Reopen {
    root: PathBuf,
    created: Cell<bool>,
}

impl Reopen {
    fn new() -> Reopen {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("store");
        // Leak the temp dir: the store has to outlive each individual handle, which
        // is the whole point — a handle that dies must not take the proofs with it.
        std::mem::forget(dir);
        Reopen {
            root,
            created: Cell::new(false),
        }
    }

    fn open(&self) -> Box<dyn Host> {
        if self.created.get() {
            Box::new(FsHost::open(&self.root).expect("reopen the fs store"))
        } else {
            self.created.set(true);
            Box::new(FsHost::create(&self.root).expect("create the fs store"))
        }
    }
}

/// The same shape for the bucket host: one in-process bucket, reopened per step.
struct BucketReopen {
    bucket: MemoryBucket,
    created: Cell<bool>,
}

impl BucketReopen {
    fn new() -> BucketReopen {
        BucketReopen {
            bucket: MemoryBucket::forge("gitiup-forge"),
            created: Cell::new(false),
        }
    }

    fn open(&self) -> Box<dyn Host> {
        // `ref-cache-ttl = 0` because a listing is an advertisement, and a test that
        // reads a listing it cached a moment ago would be testing the cache.
        let remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo")
            .expect("s3 remote")
            .with_option("ref-cache-ttl", "0s");
        let shared: SharedBucket = Arc::new(self.bucket.clone());
        if self.created.get() {
            Box::new(S3Host::open(shared, &remote).expect("reopen the bucket store"))
        } else {
            self.created.set(true);
            Box::new(S3Host::init(shared, &remote).expect("init the bucket store"))
        }
    }
}

// ---------------------------------------------------------------------------
// One body, every host.
// ---------------------------------------------------------------------------

/// Publish two proofs for one commit and look at what the store says afterwards —
/// through handles that never wrote anything.
fn proof_is_stored_and_findable(open: &dyn Fn() -> Box<dyn Host>) {
    let subject = commit(COMMIT);
    let other = commit(OTHER);
    let ada = b"{\"signed-by\":\"ada\"}".to_vec();
    let bruno = b"{\"signed-by\":\"bruno\"}".to_vec();

    let first = {
        let host = open();
        let published = attest::publish(&*host, &subject, &ada, "ada").expect("publish ada");
        assert_eq!(published.digest, Oid::hash_bytes(&ada));
        assert!(!published.already);
        assert!(
            published
                .reference
                .as_str()
                .starts_with(&format!("refs/attestations/{subject}/")),
            "the ref is keyed by the object attested, so 'proof about this commit' is a ref \
             lookup on every host: {}",
            published.reference
        );
        assert!(
            host.list(&Namespace::ATTESTATION)
                .expect("list blobs")
                .iter()
                .any(|entry| entry.oid == published.digest),
            "the bytes are filed under kv/attestation/<digest>, as ADR-0001 says"
        );
        published
    };

    let second = {
        // A fresh handle: this is "another machine, later", the only reading of
        // "survives a clone" that means anything.
        let host = open();
        attest::publish(&*host, &subject, &bruno, "bruno")
            .expect("a second proof gets its own ref; it does not overwrite the first")
    };

    let host = open();
    let catalog = attest::list_for(&*host, &subject).expect("list for commit");
    assert_eq!(catalog.entries.len(), 2, "both proofs: {catalog:?}");
    assert!(catalog.unexpected.is_empty(), "{catalog:?}");
    let digests: Vec<String> = catalog.entries.iter().map(|e| e.digest.hex()).collect();
    assert!(digests.contains(&first.digest.hex()) && digests.contains(&second.digest.hex()));

    // Another commit's listing is empty: a subject is a key, not a hint.
    assert!(
        attest::list_for(&*host, &other)
            .expect("empty listing")
            .entries
            .is_empty()
    );
    // And everything in the store, for `list --all`.
    assert_eq!(attest::list_all(&*host).expect("list all").entries.len(), 2);

    // Publishing the first one again is a no-op, not a second copy and not a conflict.
    let again = attest::publish(&*host, &subject, &ada, "ada").expect("re-publish");
    assert!(again.already);
    assert_eq!(
        attest::list_for(&*host, &subject)
            .expect("list")
            .entries
            .len(),
        2,
        "idempotence must not inflate the listing"
    );

    // The bytes come back exactly as signed, and `head` can say how big they are.
    assert_eq!(
        attest::fetch(&*host, &first.digest)
            .expect("fetch")
            .expect("present"),
        ada,
        "a signature is only ever over these exact bytes"
    );
    assert_eq!(
        attest::size(&*host, &first.digest).expect("size"),
        Some(ada.len() as u64)
    );
}

/// A proof that something else in the store still references is never pruned, and
/// the store can name what is keeping it alive.
fn pinned_proofs_survive_every_policy(open: &dyn Fn() -> Box<dyn Host>) {
    let subject = commit(COMMIT);
    let host = open();
    let doomed = attest::publish(
        &*host,
        &subject,
        b"{\"stale\":true}".to_vec().as_slice(),
        "ada",
    )
    .expect("publish");
    let seat = attest::publish(
        &*host,
        &subject,
        b"{\"seat\":true}".to_vec().as_slice(),
        "verifier",
    )
    .expect("publish");
    // What a quorum seat submission looks like from here: a ref outside the
    // attestation namespace pointing at the attestation blob.
    host.update_ref_cas(
        &RefUpdate::create(
            RefName::gitiup("reveal/chg-1/build/slot-a").expect("reveal ref"),
            seat.digest,
        )
        .with_actor("quorum"),
    )
    .expect("a seat ref points at the attestation");

    let pins = attest::referenced(&*host).expect("referenced");
    assert_eq!(
        pins.get(&seat.digest).map(String::as_str),
        Some("refs/gitiup/reveal/chg-1/build/slot-a"),
        "the store can name what is keeping a proof alive"
    );
    assert!(!pins.contains_key(&doomed.digest));

    let items = vec![
        item(&doomed.digest, &subject, 0),
        item(&seat.digest, &subject, 0),
    ];
    let policy = Retention {
        max_bytes: None,
        max_age_us: Some(MICROS),
        max_per_subject: Some(1),
    };
    let plan = attest::plan(&policy, 100 * MICROS, &items, &pins);
    assert_eq!(plan.pruned().len(), 1, "{plan:?}");
    assert_eq!(plan.pinned_count(), 1);

    let report = attest::apply(
        &*host,
        &plan,
        &pins,
        &GcOptions {
            dry_run: false,
            ..GcOptions::default()
        },
    )
    .expect("apply");
    assert_eq!(report.pruned.len(), 1, "{report:?}");
    assert_eq!(report.pruned[0].digest, doomed.digest);
    assert_eq!(report.pinned, 1);
    assert_eq!(report.explain_nothing_pruned(), None);

    let after = attest::list_for(&*host, &subject).expect("list after gc");
    assert_eq!(after.entries.len(), 1, "{after:?}");
    assert_eq!(after.entries[0].digest, seat.digest);

    // The bytes of the retired proof are still there — nothing asked to purge them —
    // and the run itself is on the record: what went, when, under what policy. A
    // store that forgets its own deletions is not auditable.
    assert_eq!(
        attest::fetch(&*host, &doomed.digest)
            .expect("fetch")
            .expect("still stored"),
        b"{\"stale\":true}"
    );
    let records = attest::records(&*host).expect("gc records");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].1["pruned"][0]["digest"].as_str(),
        Some(doomed.digest.hex().as_str())
    );
    assert_eq!(
        records[0].1["retention"]["max_per_subject"].as_u64(),
        Some(1),
        "the record says which policy ran"
    );
}

/// Applying a plan whose ref has already gone is not an error: the state asked for
/// already holds.
fn an_already_gone_ref_counts_as_retired(open: &dyn Fn() -> Box<dyn Host>) {
    let subject = commit(COMMIT);
    let host = open();
    let published = attest::publish(&*host, &subject, b"{\"one\":1}".to_vec().as_slice(), "ada")
        .expect("publish");
    let plan = attest::plan(
        &Retention {
            max_bytes: None,
            max_age_us: Some(1),
            max_per_subject: None,
        },
        10,
        &[item(&published.digest, &subject, 0)],
        &BTreeMap::new(),
    );
    host.delete_ref_cas(&RefDeletion::new(
        published.reference.clone(),
        Expect::Is(published.digest),
    ))
    .expect("somebody retired it first");
    let report = attest::apply(
        &*host,
        &plan,
        &BTreeMap::new(),
        &GcOptions {
            dry_run: false,
            record: false,
            ..GcOptions::default()
        },
    )
    .expect("applying over an already-gone ref is not a failure");
    assert_eq!(
        report.pruned.len(),
        1,
        "it was retired either way: {report:?}"
    );
}

fn item(digest: &Oid, subject: &Oid, claimed_at_us: i64) -> AttestationItem {
    AttestationItem {
        digest: *digest,
        subject: *subject,
        claimed_at_us,
        size: 64,
        label: None,
        reference: Some(attest::ref_name(subject, digest).as_str().to_string()),
    }
}

// ---------------------------------------------------------------------------
// The `fs` host.
// ---------------------------------------------------------------------------

#[test]
fn fs_stores_and_lists_proofs() {
    let store = Reopen::new();
    proof_is_stored_and_findable(&|| store.open());
}

#[test]
fn fs_keeps_pinned_proofs_and_records_the_run() {
    let store = Reopen::new();
    pinned_proofs_survive_every_policy(&|| store.open());
}

#[test]
fn fs_treats_an_already_gone_ref_as_retired() {
    let store = Reopen::new();
    an_already_gone_ref_counts_as_retired(&|| store.open());
}

#[test]
fn the_fs_host_can_actually_forget_a_blob() {
    // The one host in the workspace that can say yes to `--purge-blobs`, and so the
    // one that proves the report distinguishes "removed" from "refused".
    let store = Reopen::new();
    let host = store.open();
    let subject = commit(COMMIT);
    let published = attest::publish(
        &*host,
        &subject,
        b"{\"purge\":me}".to_vec().as_slice(),
        "ada",
    )
    .expect("publish");
    let plan = attest::plan(
        &Retention {
            max_bytes: None,
            max_age_us: Some(1),
            max_per_subject: None,
        },
        10,
        &[item(&published.digest, &subject, 0)],
        &BTreeMap::new(),
    );
    let report = attest::apply(
        &*host,
        &plan,
        &BTreeMap::new(),
        &GcOptions {
            dry_run: false,
            purge_blobs: true,
            ..GcOptions::default()
        },
    )
    .expect("apply");
    assert_eq!(report.pruned[0].blob, BlobAction::Removed);
    assert!(
        attest::fetch(&*host, &published.digest)
            .expect("fetch")
            .is_none(),
        "--purge-blobs on a filesystem store means the bytes are gone"
    );

    // And the purge reaches nothing else: a pinned digest published afterwards, with
    // every aggressive option still pointed at the store, keeps its bytes. Deleting a
    // proof something still references is the one thing a retention run may not do,
    // and "we asked for the bytes too" is not the answer to that.
    let kept = attest::publish(
        &*host,
        &subject,
        b"{\"pinned\":me}".to_vec().as_slice(),
        "ada",
    )
    .expect("publish a second proof");
    let seat = RefName::gitiup("reveal/chg-1/build/slot-b").expect("reveal ref");
    host.update_ref_cas(&RefUpdate::create(seat.clone(), kept.digest).with_actor("quorum"))
        .expect("a seat points at it");
    let later = attest::plan(
        &Retention {
            max_bytes: None,
            max_age_us: Some(1),
            max_per_subject: Some(0),
        },
        10,
        &[item(&kept.digest, &subject, 0)],
        &attest::referenced(&*host).expect("referenced"),
    );
    let report = attest::apply(
        &*host,
        &later,
        &attest::referenced(&*host).expect("referenced"),
        &GcOptions {
            dry_run: false,
            purge_blobs: true,
            ..GcOptions::default()
        },
    )
    .expect("apply");
    assert_eq!(report.pinned, 1, "{report:?}");
    assert!(report.pruned.is_empty(), "{report:?}");
    assert_eq!(
        attest::fetch(&*host, &kept.digest)
            .expect("fetch")
            .expect("still there"),
        b"{\"pinned\":me}",
        "a pinned proof's bytes survive even a purging gc"
    );
    assert!(host.get_ref(&seat).expect("seat ref reads back").is_some());
}

/// The single-level spelling of this namespace (`refs/attestations/<subject>`, one ref
/// per attestation) is what older gitiup and the forge adapter used to file. It is not
/// this layout, but it *is* a proof: a listing reads it and flags it, a publish that
/// would need that name as a directory says so instead of overwriting it, and
/// [`attest::migrate`] moves it when asked.
#[test]
fn a_legacy_ref_is_read_flagged_and_movable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = FsHost::open_or_create(dir.path().join("store")).expect("open");
    let subject = commit(COMMIT);
    let bytes = b"{\"from\":\"the forge adapter\"}";
    let digest = host
        .put_cas(&Namespace::ATTESTATION, bytes)
        .expect("store the attestation");
    host.update_ref_cas(
        &RefUpdate::create(RefName::attestation(&subject), digest).with_actor("github"),
    )
    .expect("a forge-style single-level ref");

    let catalog = attest::list_all(&host).expect("list");
    assert!(
        catalog.unexpected.is_empty(),
        "a single-level ref is a shape, not a surprise: {:?}",
        catalog.unexpected
    );
    assert_eq!(catalog.entries.len(), 1, "it is a proof, so it is listed");
    let entry = &catalog.entries[0];
    assert_eq!(
        entry.subject, subject,
        "the name of a legacy ref is the object it attests"
    );
    assert_eq!(
        entry.digest, digest,
        "and its value is the attestation itself"
    );
    assert!(entry.legacy, "and the listing says which shape it is in");
    assert_eq!(catalog.legacy().len(), 1);
    assert_eq!(
        attest::fetch(&host, &digest).expect("fetch").as_deref(),
        Some(&bytes[..]),
        "and the bytes it advertises are readable, verbatim"
    );

    // Publishing under that subject would need `refs/attestations/<subject>` to be a
    // directory. Git cannot have both, and neither can a listing that is a prefix
    // match, so the store names the ref in the way instead of losing either — and
    // names the way out.
    let error = attest::publish(
        &host,
        &subject,
        b"{\"mine\":true}".to_vec().as_slice(),
        "ada",
    )
    .expect_err("that name is a leaf already");
    assert!(
        error
            .to_string()
            .contains(RefName::attestation(&subject).as_str()),
        "{error}"
    );
    assert!(
        host.get_ref(&RefName::attestation(&subject))
            .expect("read it back")
            .is_some(),
        "the existing ref survived the refused publish"
    );

    // A dry run tells the story and changes nothing…
    let planned = attest::migrate(&host, &attest::MigrationOptions::default()).expect("plan");
    assert!(planned.dry_run);
    assert_eq!(planned.moved.len(), 1);
    assert!(!planned.moved[0].retired);
    assert!(attest::legacy_proofs(&host).expect("look").len() == 1);

    // …and applying it moves the proof, retires the old ref only once the new one
    // exists, and leaves the bytes exactly as they were — the whole point, since a
    // re-encoded document would no longer verify.
    let applied = attest::migrate(
        &host,
        &attest::MigrationOptions {
            actor: Actor::from("ada"),
            apply: true,
            record: true,
        },
    )
    .expect("migrate");
    assert_eq!(applied.moved.len(), 1);
    assert!(applied.moved[0].retired);
    assert!(applied.record.is_some(), "and the move is on the record");
    assert!(attest::legacy_proofs(&host).expect("look").is_empty());
    let moved = attest::list_for(&host, &subject).expect("list");
    assert_eq!(moved.entries.len(), 1);
    assert!(!moved.entries[0].legacy);
    assert_eq!(moved.entries[0].digest, digest);
    assert_eq!(
        attest::fetch(&host, &digest).expect("fetch").as_deref(),
        Some(&bytes[..]),
        "the signed bytes were never touched"
    );

    // Which is what the shape was in the way of: now a second proof fits.
    attest::publish(
        &host,
        &subject,
        b"{\"mine\":true}".to_vec().as_slice(),
        "ada",
    )
    .expect("a second proof about one commit");
    assert_eq!(
        attest::list_for(&host, &subject)
            .expect("list")
            .entries
            .len(),
        2
    );
}

// ---------------------------------------------------------------------------
// The bucket-as-forge host.
// ---------------------------------------------------------------------------

#[test]
fn bucket_stores_and_lists_proofs() {
    let store = BucketReopen::new();
    proof_is_stored_and_findable(&|| store.open());
}

#[test]
fn bucket_keeps_pinned_proofs_and_records_the_run() {
    let store = BucketReopen::new();
    pinned_proofs_survive_every_policy(&|| store.open());
}

#[test]
fn bucket_treats_an_already_gone_ref_as_retired() {
    let store = BucketReopen::new();
    an_already_gone_ref_counts_as_retired(&|| store.open());
}

#[test]
fn a_bucket_refuses_to_forget_and_says_so() {
    // The default `purge_cas` refusal, exercised through the retention path rather
    // than asserted against a trait default: what `gc --purge-blobs` prints is a
    // refusal with a reason — not a failure, and not a silent success.
    let store = BucketReopen::new();
    let host = store.open();
    let subject = commit(COMMIT);
    let published = attest::publish(&*host, &subject, b"{\"x\":1}".to_vec().as_slice(), "ada")
        .expect("publish");
    let plan = attest::plan(
        &Retention {
            max_bytes: None,
            max_age_us: Some(1),
            max_per_subject: None,
        },
        10,
        &[item(&published.digest, &subject, 0)],
        &BTreeMap::new(),
    );
    let report = attest::apply(
        &*host,
        &plan,
        &BTreeMap::new(),
        &GcOptions {
            dry_run: false,
            purge_blobs: true,
            ..GcOptions::default()
        },
    )
    .expect("apply");
    match &report.pruned[0].blob {
        BlobAction::Refused { why } => {
            assert!(why.contains("cannot forget"), "{why}");
        }
        other => panic!("a bucket cannot forget a blob, and must say so: {other:?}"),
    }
    assert!(
        host.purge_cas(&published.digest)
            .unwrap_err()
            .is_unsupported(),
        "the refusal is the taxonomy's `unsupported-cas`, so a caller can branch on it"
    );
}

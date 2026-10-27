//! Bucket-as-forge: the same conformance bodies as the `fs` host, run against
//! [`S3Host`], plus the promises only a bucket makes — conditional writes,
//! multipart packs, tombstones instead of deletes, a TTL ref cache, and
//! credentials that come from the AWS chain rather than from the config file.
//!
//! The bucket here is [`MemoryBucket`]: a second, in-process implementation of
//! the transport contract (etags, 412s, paged LISTs, staged multipart uploads),
//! so these tests exercise the production code path with no network, no
//! MinIO and no credentials. `tests/host_s3_minio.rs` runs the same host over
//! the real `aws-sdk-s3` transport when an endpoint is available.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use gitiup_host::{
    AuthModel, BlobStore, Bucket, Capability, Config, Expect, Host, HostErrorExt, HostErrorKind,
    HostKind, MemoryBucket, MemoryBucketConfig, Namespace, Oid, Pack, PackRequest, PutCond,
    RefDeletion, RefName, RefQuery, RefStore, RefUpdate, RemoteConfig, S3Host, SharedBucket,
    VersioningState,
};

mod support;
use support::conformance;

/// The remote every test uses: `s3://gitiup-forge/my-repo` with the default
/// `gitiup` store prefix, so the root is `my-repo/gitiup`.
fn remote() -> RemoteConfig {
    RemoteConfig::new("origin", "s3://gitiup-forge/my-repo").expect("s3 remote")
}

fn shared(bucket: &MemoryBucket) -> SharedBucket {
    Arc::new(bucket.clone())
}

/// A freshly initialised bucket-as-forge.
fn hosted(bucket: &MemoryBucket) -> S3Host {
    S3Host::init(shared(bucket), &remote()).expect("init the store")
}

fn hosted_with(bucket: &MemoryBucket, remote: &RemoteConfig) -> S3Host {
    S3Host::init(shared(bucket), remote).expect("init the store")
}

// ---------------------------------------------------------------------------
// The shared conformance bodies.
// ---------------------------------------------------------------------------

#[test]
fn s3_refs_round_trip() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    conformance::refs_round_trip(&hosted(&bucket));
}

#[test]
fn s3_blobs_round_trip() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    conformance::blobs_round_trip(&hosted(&bucket));
}

#[test]
fn s3_pack_round_trip_between_two_hosts() {
    let source = MemoryBucket::forge("source");
    let sink = MemoryBucket::forge("sink");
    conformance::pack_round_trip(&hosted(&source), &hosted(&sink));
}

#[test]
fn s3_cas_conflicts_are_reported() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    conformance::cas_conflicts_are_reported(&hosted(&bucket));
}

#[test]
fn s3_multi_ref_writes_are_all_or_nothing() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    conformance::multi_ref_writes_are_all_or_nothing(&hosted(&bucket));
}

#[test]
fn s3_describe_and_capabilities() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    assert_eq!(host.kind(), HostKind::S3);
    conformance::describe_and_capabilities(&host);
    let info = host.describe();
    assert_eq!(info.store_prefix, "gitiup");
    assert_eq!(info.url.as_deref(), Some("s3://gitiup-forge/my-repo"));
    assert!(info.implemented_by.contains("s3"), "{info:?}");
    // The shape the design promises for S3: CAS and immutable, no multi-write.
    let caps = host.capabilities();
    assert!(caps.cas, "conditional writes are on for this bucket");
    assert!(caps.immutable, "the bucket is versioned");
    assert!(
        !caps.atomic_multi_write,
        "S3 has no multi-object transaction"
    );
    assert_eq!(caps.auth, AuthModel::CloudRole);
    assert_eq!(host.facts().versioning, VersioningState::Enabled);
    assert!(
        host.advice()
            .iter()
            .any(|advice| advice.contains("Object Lock")),
        "Object Lock is recommended: {:?}",
        host.advice()
    );
}

#[test]
fn s3_batch_writes_are_not_atomic_and_say_so() {
    // The inherited `update_refs_cas` applies updates one at a time and rolls
    // back best effort, so the capability has to be reported false and a late
    // conflict still leaves nothing behind (the rollback is what we are checking).
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    assert_eq!(
        host.require(Capability::AtomicMultiWrite)
            .unwrap_err()
            .kind(),
        HostErrorKind::UnsupportedCas
    );
    let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
    let first = RefName::branch("first").unwrap();
    let second = RefName::branch("second").unwrap();
    let err = host
        .update_refs_cas(&[
            RefUpdate::create(first.clone(), a),
            RefUpdate::replace(second.clone(), b, a),
        ])
        .expect_err("the second update cannot match");
    assert!(err.is_conflict(), "{err}");
    assert!(
        host.get_ref(&first).unwrap().is_none(),
        "the rollback must undo the first write"
    );
}

#[test]
fn the_s3_host_is_object_safe_and_shareable() {
    // Verification hands hosts around as `Arc<dyn Host>` and reads refs through
    // the narrower traits.
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let boxed: Box<dyn Host> = Box::new(host.clone());
    let refs_only: &dyn RefStore = &*boxed;
    let blobs_only: &dyn BlobStore = &*boxed;
    let oid = blobs_only
        .put_cas(&Namespace::RECORD, b"upcast me")
        .expect("blob store through the upcast");
    let name = RefName::branch("upcast").unwrap();
    refs_only
        .update_ref_cas(&RefUpdate::create(name.clone(), oid))
        .expect("ref store through the upcast");
    assert_eq!(boxed.get_ref(&name).unwrap().unwrap().oid, oid);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let host = Arc::new(host.clone()) as Arc<dyn Host>;
            std::thread::spawn(move || host.list_refs(&RefQuery::all()).map(|refs| refs.len()))
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap().unwrap(), 1);
    }
}

// ---------------------------------------------------------------------------
// The layout the ticket fixes.
// ---------------------------------------------------------------------------

#[test]
fn the_bucket_layout_is_exactly_what_the_ticket_promises() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let oid = host
        .put_cas(&Namespace::JOB, b"{\"job\":\"build\"}")
        .expect("job record");
    let branch = RefName::branch("main").unwrap();
    host.update_ref_cas(
        &RefUpdate::create(branch.clone(), oid)
            .with_actor("ada")
            .with_message("first"),
    )
    .expect("publish the branch");
    let pack = Pack::from_raw_objects([(Namespace::JOB, b"{\"job\":\"build\"}".to_vec())]).unwrap();
    let pack_oid = host.put_pack(&pack).expect("put the pack");

    let keys: BTreeSet<String> = bucket.keys().into_iter().collect();
    for expected in [
        "my-repo/gitiup/host.json".to_string(),
        "my-repo/gitiup/refs/heads/main".to_string(),
        format!("my-repo/gitiup/kv/job/{}", oid.hex()),
        format!("my-repo/gitiup/packs/{}.pack", pack_oid.hex()),
    ] {
        assert!(keys.contains(&expected), "{expected} missing from {keys:?}");
    }
    // The key helpers and the actual keys agree, so `aws s3 ls` finds what
    // `gitiup` wrote.
    assert_eq!(host.ref_key(&branch), "my-repo/gitiup/refs/heads/main");
    assert_eq!(
        host.kv_key(&Namespace::JOB, &oid),
        format!("my-repo/gitiup/kv/job/{}", oid.hex())
    );
    assert_eq!(
        host.pack_key(&pack_oid),
        format!("my-repo/gitiup/packs/{}.pack", pack_oid.hex())
    );

    // The ref object is the small JSON document the design fixes.
    let body: serde_json::Value =
        serde_json::from_slice(&bucket.raw(&host.ref_key(&branch)).unwrap()).unwrap();
    assert_eq!(body["oid"], oid.hex());
    assert_eq!(body["updated_by"], "ada");
    assert!(body.get("updated_at").is_some(), "{body}");
    assert_eq!(body["schema"], gitiup_host::HOST_SCHEMA_VERSION);
    assert_eq!(body["message"], "first");

    // The manifest says what the store is.
    let manifest = host.manifest().unwrap().expect("manifest");
    assert_eq!(manifest.kind, "s3");
    assert_eq!(manifest.bucket, "gitiup-forge");
    assert_eq!(manifest.root, "my-repo/gitiup");
    assert_eq!(manifest.store_prefix, "gitiup");
    assert!(manifest.created_at.is_some());
}

#[test]
fn a_store_prefix_moves_the_whole_layout() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let remote = remote()
        .with_store_prefix("store")
        .expect("normalise the prefix");
    let host = hosted_with(&bucket, &remote);
    let oid = host
        .put_cas(&Namespace::ROSTER, b"{\"verifiers\":5}")
        .unwrap();
    assert!(
        bucket
            .keys()
            .contains(&"my-repo/store/refs/heads/none".to_string())
            || bucket
                .keys()
                .iter()
                .any(|key| key.starts_with("my-repo/store/"))
    );
    assert!(
        bucket
            .keys()
            .contains(&format!("my-repo/store/kv/roster/{}", oid.hex()))
    );
}

#[test]
fn a_bucket_root_with_no_path_prefix_stores_at_the_store_prefix() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let remote = RemoteConfig::new("origin", "s3://gitiup-forge").unwrap();
    let host = hosted_with(&bucket, &remote);
    assert_eq!(host.root(), "gitiup");
    let oid = host.put_cas(&Namespace::POLICY, b"{}").unwrap();
    assert!(
        bucket
            .keys()
            .contains(&format!("gitiup/kv/policy/{}", oid.hex()))
    );
}

#[test]
fn the_store_has_a_manifest_and_open_insists_on_it() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let bucket_ref = shared(&bucket);
    let err = match S3Host::open(bucket_ref.clone(), &remote()) {
        Ok(_) => panic!("an empty bucket is not a store"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::NotFound);
    assert!(err.hint().unwrap().contains("init"), "{err}");

    let host = S3Host::init(bucket_ref.clone(), &remote()).unwrap();
    assert!(host.manifest().unwrap().is_some());
    let second = S3Host::init(bucket_ref.clone(), &remote()).unwrap_err();
    assert!(second.to_string().contains("already exists"), "{second}");
    let reopened = S3Host::open(bucket_ref, &remote()).unwrap();
    assert_eq!(reopened.describe().kind, HostKind::S3);
    assert_eq!(reopened.root(), "my-repo/gitiup");
    // `open_or_init` is idempotent, which is what `gitiup remote add` wants.
    assert!(S3Host::open_or_init(shared(&bucket), &remote()).is_ok());
}

#[test]
fn a_ref_object_that_is_not_a_ref_is_reported_not_guessed() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let name = RefName::branch("junk").unwrap();
    bucket
        .put(
            &host.ref_key(&name),
            b"not json at all",
            PutCond::Unconditional,
        )
        .expect("seed a junk object");
    let err = match host.get_ref(&name) {
        Ok(reference) => panic!("expected an error, got {reference:?}"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    assert!(err.hint().unwrap().contains("oid"), "{err}");

    // A document from a newer gitiup is refused rather than half-read.
    let newer = br#"{"schema":99,"oid":"aabb"}"#;
    bucket
        .put(&host.ref_key(&name), newer, PutCond::Unconditional)
        .expect("seed a newer-schema object");
    let err = host.get_ref(&name).unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    assert!(err.to_string().contains("newer"), "{err}");
}

// ---------------------------------------------------------------------------
// Compare-and-swap over the wire.
// ---------------------------------------------------------------------------

#[test]
fn ref_writes_are_conditional_on_the_wire() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
    let name = RefName::branch("main").unwrap();

    bucket.reset_stats();
    host.update_ref_cas(&RefUpdate::create(name.clone(), a))
        .expect("create-only write");
    assert!(
        bucket.stats().conditional_puts >= 1,
        "creating a ref must use If-None-Match: {}",
        bucket.stats().summary()
    );

    bucket.reset_stats();
    host.update_ref_cas(&RefUpdate::replace(name.clone(), a, b))
        .expect("replace with the value we read");
    assert!(
        bucket.stats().conditional_puts >= 1,
        "moving a ref must use If-Match: {}",
        bucket.stats().summary()
    );

    bucket.reset_stats();
    host.cas_ref(&name, None, b)
        .expect("Expect::Any is a plain PUT");
    assert_eq!(
        bucket.stats().conditional_puts,
        0,
        "an unconditional write must not send a condition: {}",
        bucket.stats().summary()
    );

    // A stale expectation is refused and changes nothing.
    let err = host
        .update_ref_cas(&RefUpdate::replace(name.clone(), a, b))
        .expect_err("a is no longer what the ref holds");
    assert!(err.is_conflict(), "{err}");
    assert_eq!(
        host.get_ref(&name).unwrap().unwrap().oid,
        b,
        "the refused write changed nothing"
    );
}

#[test]
fn deleting_a_ref_tombstones_the_object_and_never_deletes_anything() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let oid = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"c1\"}")
        .expect("change record");
    let name = RefName::change_head("c1").unwrap();
    host.update_ref_cas(&RefUpdate::create(name.clone(), oid).with_actor("ada"))
        .unwrap();
    let objects_before = bucket.object_count();
    let blobs_before = host.list(&Namespace::CHANGE).unwrap().len();

    host.delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(oid)).with_actor("ada"))
        .expect("close the change");

    assert!(host.get_ref(&name).unwrap().is_none(), "the ref is gone");
    assert_eq!(
        bucket.object_count(),
        objects_before,
        "nothing in the bucket was deleted"
    );
    assert_eq!(
        host.list(&Namespace::CHANGE).unwrap().len(),
        blobs_before,
        "the record is still there"
    );
    let document = host
        .ref_document(&name)
        .unwrap()
        .expect("tombstone document");
    assert!(document.deleted, "the ref object records the deletion");
    assert_eq!(document.oid, oid, "and remembers what was there");
    assert!(document.deleted_at.is_some());
    assert_eq!(
        bucket.versions(&host.ref_key(&name)),
        2,
        "the ref object was overwritten, which only versioning makes safe"
    );

    // A tombstone is an occupied key, so re-creating the ref is still a CAS.
    let next = host
        .put_cas(
            &Namespace::CHANGE,
            b"{\"id\":\"c1\",\"state\":\"reopened\"}",
        )
        .unwrap();
    host.update_ref_cas(&RefUpdate::create(name.clone(), next))
        .expect("re-create over a tombstone, guarded by its etag");
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, next);
    assert!(
        host.update_ref_cas(&RefUpdate::create(name.clone(), oid))
            .is_err(),
        "create-only over a live ref still loses"
    );
}

#[test]
fn a_bucket_without_conditional_writes_degrades_to_cas_false_and_refuses_merges() {
    let bucket = MemoryBucket::without_conditional_writes("old-gateway");
    let host = hosted(&bucket);
    let caps = host.capabilities();
    assert!(!caps.cas, "the probe must see the bucket cannot CAS");
    assert_eq!(caps.auth, AuthModel::CloudRole);
    assert!(
        host.advice()
            .iter()
            .any(|advice| advice.contains("conditional")),
        "remote doctor must explain the gap: {:?}",
        host.advice()
    );
    assert_eq!(
        host.require(Capability::Cas).unwrap_err().kind(),
        HostErrorKind::UnsupportedCas
    );

    // Reading and content-addressed writes still work: they do not need CAS.
    let oid = host.put_cas(&Namespace::ATTESTATION, b"attested").unwrap();
    assert_eq!(host.get(&oid).unwrap().unwrap(), b"attested");
    let pack = Pack::from_raw_objects([(Namespace::RECORD, b"x".to_vec())]).unwrap();
    assert!(host.put_pack(&pack).is_ok());

    let name = RefName::branch("gated").unwrap();
    let err = host
        .update_ref_cas(&RefUpdate::create(name.clone(), oid))
        .expect_err("owner-side merges are refused here");
    assert!(err.is_unsupported(), "{err}");
    assert!(err.hint().unwrap().contains("conditional"), "{err}");
    assert!(
        host.get_ref(&name).unwrap().is_none(),
        "the refusal wrote nothing"
    );
    assert!(
        host.update_refs_cas(&[RefUpdate::create(name.clone(), oid)])
            .unwrap_err()
            .is_unsupported(),
        "a batch refuses too, before writing anything"
    );
    assert!(
        host.get_ref(&name).unwrap().is_none(),
        "and the batch wrote nothing either"
    );
    // A deletion that names the value it expects is CAS-dependent, so it is
    // refused too.
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(oid)))
        .unwrap_err();
    assert!(err.is_unsupported(), "{err}");

    // An unconditional write remains available on purpose: that is the operator's
    // decision to make, not the host's.
    host.update_ref_cas(&RefUpdate::set(name.clone(), oid))
        .expect("Expect::Any is allowed");
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, oid);
    assert_eq!(
        bucket.stats().conditional_puts,
        0,
        "no condition was even attempted against this bucket"
    );
}

#[test]
fn a_promise_of_conditional_writes_the_bucket_breaks_is_an_error() {
    let bucket = MemoryBucket::without_conditional_writes("liar");
    let promised = remote().with_option("conditional-writes", "on");
    let err = match S3Host::init(shared(&bucket), &promised) {
        Ok(_) => panic!("the bucket does not do what the option promised"),
        Err(err) => err,
    };
    assert!(err.is_unsupported(), "{err}");
    assert!(err.to_string().contains("promises"), "{err}");
    // Saying "off" is the way to accept it.
    let accepted = remote().with_option("conditional-writes", "off");
    let host = S3Host::init(shared(&bucket), &accepted).expect("accept a dumb bucket");
    assert!(!host.capabilities().cas);
}

#[test]
fn a_412_the_ref_did_not_move_is_retried_with_backoff() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let fast = remote()
        .with_option("cas-backoff", "1ms")
        .with_option("cas-backoff-cap", "2ms");
    let host = hosted_with(&bucket, &fast);
    let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
    let name = RefName::branch("flinch").unwrap();
    host.update_ref_cas(&RefUpdate::create(name.clone(), a))
        .unwrap();

    // Two refusals that a re-read cannot explain: the host must back off and land
    // the write rather than report a conflict.
    bucket.lose_next_races(2);
    bucket.reset_stats();
    host.update_ref_cas(&RefUpdate::replace(name.clone(), a, b))
        .expect("the retried write lands");
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, b);
    assert!(
        bucket.stats().precondition_failures >= 2,
        "both refusals happened: {}",
        bucket.stats().summary()
    );

    // And when the budget runs out the caller gets a conflict that says so.
    let stingy = remote()
        .with_option("cas-backoff", "1ms")
        .with_option("cas-attempts", "1");
    let second = S3Host::open(shared(&bucket), &stingy).unwrap();
    let c = second.put_cas(&Namespace::RECORD, b"c").unwrap();
    bucket.lose_next_races(9);
    let err = second
        .update_ref_cas(&RefUpdate::replace(name.clone(), b, c))
        .expect_err("one attempt is not enough");
    assert!(err.is_conflict(), "{err}");
    assert!(err.hint().unwrap().contains("gave up"), "{err}");
}

#[test]
fn concurrent_writers_to_one_bucket_converge_and_lose_nothing() {
    // Eight writers, one ref, create-only: exactly one may win, and every loser
    // sees a conflict rather than a silently overwritten ref.
    let bucket = MemoryBucket::forge("gitiup-forge");
    let store = shared(&bucket);
    let host = hosted(&bucket);
    let oid = host.put_cas(&Namespace::RECORD, b"contended").unwrap();
    let name = RefName::branch("contended").unwrap();
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|worker| {
            let store = store.clone();
            let remote = remote();
            let name = name.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                let host = S3Host::open(store, &remote).expect("open the store");
                start.wait();
                host.update_ref_cas(&RefUpdate::create(name, oid).with_actor(format!("w{worker}")))
                    .is_ok()
            })
        })
        .collect();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1, "exactly one create-only write may win");
    assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
}

#[test]
fn two_clones_pushing_at_once_converge_with_no_lost_refs() {
    // The acceptance criterion, stated the way a user hits it: two clones of one
    // bucket, each publishing a branch and trying to advance `main` at the same
    // time. Nothing may be lost, and the CAS retry budget must be what settles it.
    let bucket = MemoryBucket::forge("gitiup-forge");
    let store = shared(&bucket);
    let owner = hosted(&bucket);
    let base = owner.put_cas(&Namespace::RECORD, b"base").unwrap();
    let main = RefName::branch("main").unwrap();
    owner
        .update_ref_cas(&RefUpdate::create(main.clone(), base))
        .unwrap();

    // A barrier so the six really do arrive at `main` at the same moment.
    let start = std::sync::Arc::new(std::sync::Barrier::new(6));
    let handles: Vec<_> = (0..6)
        .map(|push| {
            let store = store.clone();
            let remote = remote();
            let main = main.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                // A clone is a fresh host over the same bucket: it has never seen
                // this store and must work it out from the objects alone.
                let clone = S3Host::open(store, &remote).expect("open the remote");
                let mine = clone
                    .put_cas(&Namespace::RECORD, format!("push-{push}").as_bytes())
                    .expect("store the commit record");
                let branch = RefName::branch(&format!("push-{push}")).unwrap();
                clone
                    .update_ref_cas(
                        &RefUpdate::create(branch, mine).with_actor(format!("pusher-{push}")),
                    )
                    .expect("publish the branch");
                for attempt in 0..24 {
                    let seen = clone
                        .get_ref(&main)
                        .expect("read main")
                        .expect("main exists")
                        .oid;
                    match clone.cas_ref(&main, Some(seen), mine) {
                        Ok(_) => return attempt,
                        Err(err) if err.is_conflict() => continue,
                        Err(err) => panic!("unexpected refusal: {err}"),
                    }
                }
                panic!("never advanced main");
            })
        })
        .collect();
    let attempts: Vec<u32> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    let heads = owner.list_refs(&RefQuery::prefix("refs/heads")).unwrap();
    assert_eq!(
        heads.len(),
        7,
        "six pushed branches plus main, none lost: {heads:?}"
    );
    let names: Vec<&str> = heads
        .iter()
        .map(|reference| reference.name.as_str())
        .collect();
    for expected in ["refs/heads/main", "refs/heads/push-0", "refs/heads/push-5"] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    let advanced = owner.get_ref(&main).unwrap().expect("main is there");
    assert_ne!(advanced.oid, base, "main moved");
    let content = owner.get(&advanced.oid).unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&content).starts_with("push-"),
        "main points at a record that was really pushed"
    );
    // Every pusher had at least two conditional writes (its own branch, then
    // `main`), and the CAS budget is what settled the order they landed in.
    assert!(
        bucket.stats().conditional_puts >= 12,
        "six branches plus main, all written conditionally: {}",
        bucket.stats().summary()
    );
    let _ = attempts;
}

// ---------------------------------------------------------------------------
// Packs, multipart included.
// ---------------------------------------------------------------------------

#[test]
fn big_packs_go_up_as_multipart_uploads() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);

    let small = Pack::from_raw_objects([(Namespace::RECORD, b"small".to_vec())]).unwrap();
    bucket.reset_stats();
    host.put_pack(&small).unwrap();
    assert_eq!(
        bucket.stats().multipart_uploads,
        0,
        "a pack below the threshold is one PUT"
    );

    let body: Vec<u8> = (0u8..=255).cycle().take(9 * 1024 * 1024).collect();
    let big = Pack::from_raw_objects([(Namespace::ATTESTATION, body.clone())]).unwrap();
    bucket.reset_stats();
    let pack_oid = host.put_pack(&big).expect("put a 9 MiB pack");
    let stats = bucket.stats();
    assert!(
        stats.multipart_uploads >= 1,
        "a pack above the threshold must use multipart: {}",
        stats.summary()
    );
    assert!(
        stats.puts < 4,
        "the big body must not be PUT in one piece: {}",
        stats.summary()
    );
    assert!(stats.parts >= 2, "multipart means several parts: {stats:?}");
    assert_eq!(bucket.open_uploads(), 0, "no upload was left staging parts");
    let meta = bucket
        .head(&host.pack_key(&pack_oid))
        .unwrap()
        .expect("the pack is stored");
    assert!(
        meta.etag.contains('-'),
        "multipart etags carry a part count: {}",
        meta.etag
    );

    // It comes back byte for byte, addressed by the pack digest and by the record.
    let by_pack = host
        .fetch_pack(&PackRequest::new([pack_oid]))
        .expect("fetch by pack digest");
    let records = by_pack.raw_objects().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, body);
    let record_oid = Oid::hash_bytes(&body);
    assert_eq!(host.get(&record_oid).unwrap().unwrap(), body);

    // Pushing the same pack again is a no-op, not a second upload.
    bucket.reset_stats();
    assert_eq!(host.put_pack(&big).unwrap(), pack_oid);
    assert_eq!(
        bucket.stats().multipart_uploads,
        0,
        "content addressing means we do not re-upload"
    );
}

#[test]
fn multipart_is_honoured_for_a_ref_cache_ttl_and_pack_threshold_too() {
    // The threshold is configurable; a small one must make ordinary records go
    // multipart, which is how a MinIO deployment tunes it.
    let bucket = MemoryBucket::forge("gitiup-forge");
    let remote = remote()
        .with_option("multipart-threshold-mib", "5")
        .with_option("part-size-mib", "5");
    let host = hosted_with(&bucket, &remote);
    assert_eq!(host.options().threshold_bytes(), 5 * 1024 * 1024);
    let body: Vec<u8> = vec![3u8; 6 * 1024 * 1024];
    bucket.reset_stats();
    let oid = host.put_cas(&Namespace::ATTESTATION, &body).unwrap();
    assert_eq!(bucket.stats().multipart_uploads, 1);
    assert_eq!(host.get(&oid).unwrap().unwrap(), body);
}

#[test]
fn a_part_size_below_the_s3_minimum_is_refused() {
    let remote = remote().with_option("part-size-mib", "1");
    let bucket = MemoryBucket::forge("gitiup-forge");
    let err = match S3Host::init(shared(&bucket), &remote) {
        Ok(_) => panic!("S3 refuses parts below 5 MiB"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    assert!(err.to_string().contains("5 MiB"), "{err}");
}

// ---------------------------------------------------------------------------
// The ref advertisement cache.
// ---------------------------------------------------------------------------

#[test]
fn the_ref_advertisement_is_cached_for_a_short_ttl() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let mut oids = Vec::new();
    for index in 0..3 {
        let oid = host
            .put_cas(&Namespace::RECORD, format!("record-{index}").as_bytes())
            .unwrap();
        host.update_ref_cas(&RefUpdate::create(
            RefName::branch(&format!("b{index}")).unwrap(),
            oid,
        ))
        .unwrap();
        oids.push(oid);
    }
    assert!(!oids.is_empty());

    bucket.reset_stats();
    let first = host.list_refs(&RefQuery::all()).unwrap();
    let lists_after_first = bucket.stats().lists;
    assert!(lists_after_first >= 1, "the first listing hits the bucket");
    assert!(
        bucket.stats().gets >= 3,
        "LIST gives keys, so the values are GETs: {}",
        bucket.stats().summary()
    );

    let again = host.list_refs(&RefQuery::all()).unwrap();
    assert_eq!(first, again);
    assert_eq!(
        bucket.stats().lists,
        lists_after_first,
        "the second listing must not go to the bucket: {}",
        bucket.stats().summary()
    );
    let stats = host.ref_cache_stats();
    assert!(stats.hits >= 1, "{stats:?}");
    assert!(stats.entries >= 1, "{stats:?}");

    // Our own writes are visible immediately: the cache is invalidated on write.
    let late = host.put_cas(&Namespace::RECORD, b"late").unwrap();
    host.cas_ref(&RefName::branch("late").unwrap(), None, late)
        .unwrap();
    bucket.reset_stats();
    let after = host.list_refs(&RefQuery::all()).unwrap();
    assert_eq!(after.len(), 4, "the new ref shows up without a flush");
    assert!(bucket.stats().lists >= 1);

    // ...and `flush_ref_cache` is the explicit version of that.
    let _ = host.list_refs(&RefQuery::all()).unwrap();
    bucket.reset_stats();
    host.flush_ref_cache();
    let _ = host.list_refs(&RefQuery::all()).unwrap();
    assert!(
        bucket.stats().lists >= 1,
        "a flushed cache goes back to the bucket"
    );
}

#[test]
fn the_cache_expiry_and_the_opt_out_both_work() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let short = remote().with_option("ref-cache-ttl", "20ms");
    let host = hosted_with(&bucket, &short);
    let oid = host.put_cas(&Namespace::RECORD, b"x").unwrap();
    host.cas_ref(&RefName::branch("a").unwrap(), None, oid)
        .unwrap();

    bucket.reset_stats();
    assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
    let first = bucket.stats().lists;
    assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
    assert_eq!(bucket.stats().lists, first, "still fresh");
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(host.list_refs(&RefQuery::all()).unwrap().len(), 1);
    assert!(
        bucket.stats().lists > first,
        "the advertisement expired and was re-read"
    );

    // `ref-cache-ttl = 0s` means every listing is a real one, which is what a
    // long-running verifier may want.
    let off = remote().with_option("ref-cache-ttl", "0s");
    let cold = S3Host::open(shared(&bucket), &off).unwrap();
    assert!(
        cold.advice()
            .iter()
            .any(|advice| advice.contains("ref-cache-ttl")),
        "{:?}",
        cold.advice()
    );
    bucket.reset_stats();
    let _ = cold.list_refs(&RefQuery::all()).unwrap();
    let one = bucket.stats().lists;
    assert!(one >= 1);
    let _ = cold.list_refs(&RefQuery::all()).unwrap();
    assert!(
        bucket.stats().lists > one,
        "no cache, so every listing lists"
    );
}

// ---------------------------------------------------------------------------
// Versioning, retention and credentials.
// ---------------------------------------------------------------------------

#[test]
fn object_versioning_is_required_and_advice_recommends_object_lock() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let locked = bucket.clone();
    let host = hosted(&locked);
    assert!(host.capabilities().immutable);
    assert!(
        host.advice()
            .iter()
            .any(|advice| advice.contains("Object Lock")),
        "{:?}",
        host.advice()
    );

    let with_lock = MemoryBucket::new(
        MemoryBucketConfig::default()
            .with_bucket("gitiup-forge")
            .with_object_lock(true),
    );
    let host = hosted(&with_lock);
    assert!(host.facts().object_lock);
    assert!(
        host.advice().is_empty(),
        "a versioned, locked, conditional-write bucket needs no advice: {:?}",
        host.advice()
    );
}

#[test]
fn an_unversioned_bucket_is_refused_unless_the_operator_accepts_the_loss() {
    let bucket = MemoryBucket::unversioned("gitiup-forge");
    let err = match S3Host::init(shared(&bucket), &remote()) {
        Ok(_) => panic!("gitiup must not gate merges on an unversioned bucket"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
    assert!(err.to_string().contains("not versioned"), "{err}");
    assert!(
        err.hint().unwrap().contains("put-bucket-versioning"),
        "the hint says how to fix it: {err}"
    );

    let accepting = remote().with_option("require-versioning", "false");
    let host = S3Host::init(shared(&bucket), &accepting).expect("the operator chose this");
    assert!(
        !host.capabilities().immutable,
        "an unversioned bucket cannot promise immutability"
    );
    assert_eq!(host.facts().versioning, VersioningState::Disabled);
    assert!(
        host.advice()
            .iter()
            .any(|advice| advice.contains("versioning")),
        "{:?}",
        host.advice()
    );
}

#[test]
fn credentials_come_from_the_aws_chain_never_from_the_config() {
    // A token in `gitiup.toml` for an s3 remote is a refusal, not a warning: it
    // would be useless here and is a leak waiting to happen.
    let with_token = Config::parse(
        r#"
schema-version = 1
default-remote = "origin"

[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"
credentials-profile = "owner"

[credentials.owner]
auth = "token"
token-env = "GITIUP_TEST_TOKEN_THAT_IS_NOT_SET"
"#,
        None,
    )
    .expect("parses");
    let remote = with_token.remote("origin").unwrap();
    let err = match S3Host::check_credentials(&with_token, remote) {
        Ok(_) => panic!("a token profile must be refused for an s3 remote"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
    assert!(err.to_string().contains("token"), "{err}");
    assert!(err.hint().unwrap().contains("cloud-role"), "{err}");

    // The shape that is meant to work: cloud-role, nothing in the file.
    let with_chain = Config::parse(
        r#"
schema-version = 1
default-remote = "origin"

[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"
credentials-profile = "owner"

[credentials.owner]
auth = "cloud-role"
"#,
        None,
    )
    .expect("parses");
    let remote = with_chain.remote("origin").unwrap();
    S3Host::check_credentials(&with_chain, remote).expect("cloud-role is the point");
    let credentials = with_chain.credentials_for(remote).unwrap();
    assert_eq!(credentials.auth, AuthModel::CloudRole);
    assert!(
        !credentials.has_token(),
        "no token is resolved for the bucket"
    );

    // A profile that stays quiet about `auth` still means the cloud chain for an
    // s3 URL, even if it carries an ssh key for another remote's sake.
    let quiet = Config::parse(
        r#"
[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"
credentials-profile = "owner"

[credentials.owner]
key-path = "~/.ssh/id_ed25519"
"#,
        None,
    )
    .unwrap();
    let remote = quiet.remote("origin").unwrap();
    assert_eq!(
        quiet.credentials_for(remote).unwrap().auth,
        AuthModel::CloudRole,
        "the scheme decides when the profile does not"
    );
    S3Host::check_credentials(&quiet, remote).expect("nothing to refuse");
}

#[test]
fn the_host_refuses_a_remote_that_is_not_a_bucket() {
    let mirror =
        RemoteConfig::new("mirror", "ssh://git@build.example.net/srv/git/repo.git").unwrap();
    let err = match S3Host::detached(shared(&MemoryBucket::forge("b")), &mirror) {
        Ok(_) => panic!("the S3 host must not take an ssh remote"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), HostErrorKind::SchemeUnknown);
    assert!(err.to_string().contains("supported: s3"), "{err}");
}

#[test]
fn advice_about_options_nobody_reads_is_reported_not_swallowed() {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let remote = remote().with_option("conditonal-writes", "off"); // a typo
    let host = hosted_with(&bucket, &remote);
    assert!(
        host.advice()
            .iter()
            .any(|advice| advice.contains("conditonal-writes")),
        "a typo in an option must be visible: {:?}",
        host.advice()
    );
    assert!(
        host.capabilities().cas,
        "the typo'd option did nothing, which is why we say so"
    );
}

#[test]
fn a_rollback_that_cannot_be_completed_names_what_was_left_behind() {
    // `update_refs_cas` is not atomic on a bucket, so it rolls back best effort.
    // When the rollback itself cannot be written, the caller must not be told
    // "nothing happened": a ref is sitting there, half-submitted.
    let bucket = MemoryBucket::forge("gitiup-forge");
    let host = hosted(&bucket);
    let a = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"c7\"}")
        .unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
    let first = RefName::branch("first").unwrap();
    let second = RefName::branch("second").unwrap();
    host.cas_ref(&second.clone(), None, b).unwrap();

    // The first update lands, the second conflicts, and the undo of the first is
    // the write that the bucket refuses.
    bucket.fail_writes_after(1);
    let err = host
        .update_refs_cas(&[
            RefUpdate::create(first.clone(), a),
            RefUpdate::replace(second.clone(), a, b),
        ])
        .expect_err("the second update cannot match");
    assert!(err.is_conflict(), "{err}");
    let hint = err.hint().unwrap();
    assert!(hint.contains("refs/heads/first"), "{hint}");
    assert!(hint.contains("fsck"), "{hint}");
}

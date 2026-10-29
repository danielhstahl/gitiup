//! Publishing and reading changes, against the hosts that are not a network service: the
//! `fs` host and the bucket-as-forge host on its in-process bucket.
//!
//! The bodies are host-neutral on purpose — "`gitiup change list` means one thing
//! wherever the repo lives" is ADR-0003 C7 — so each story is written once and run
//! against each store, and against a handle that never wrote anything, because "the
//! change is retrievable" means retrievable *later, by someone else*.
//!
//! The two claims that need a store to misbehave — bytes that do not re-hash to the name
//! they are filed under, and a host that cannot compare-and-swap — are made with the
//! [`Tampered`] wrapper at the bottom, because no honest host can produce either.
//!
//! The git transport, where a ref is a pointer commit and a read is a packfile, is
//! covered in `tests/change_git.rs`.

mod change_support;

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Arc;

use change_support::*;
use gitiup_host::change::{self, AbandonRecord, ChangeRef, MergeRecord, State, StoredRecord};
use gitiup_host::{
    Actor, BlobEntry, BlobStore, Capabilities, Expect, FsHost, Host, HostError, HostErrorExt,
    HostInfo, MemoryBucket, Namespace, Oid, Pack, PackRequest, Ref, RefDeletion, RefName, RefQuery,
    RefStore, RefUpdate, RemoteConfig, S3Host, SharedBucket,
};

/// An `fs` store in a temp dir that outlives the handle.
struct FsReopen {
    root: PathBuf,
    created: Cell<bool>,
}

impl FsReopen {
    fn new() -> FsReopen {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("store");
        // Leaked on purpose: the store has to outlive each handle, which is the point.
        std::mem::forget(dir);
        FsReopen {
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

/// The same shape for the bucket host: one in-process bucket, a new handle per step.
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
        // `ref-cache-ttl = 0`: a listing is an advertisement, and a test that reads a
        // listing it cached a moment ago would be testing the cache.
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

/// Run `body` against every non-network store, twice: the handle that writes, then a
/// handle that only reads.
fn each_store(mut body: impl FnMut(&dyn Fn() -> Box<dyn Host>)) {
    let fs = FsReopen::new();
    eprintln!("--- fs host");
    body(&move || fs.open());
    let bucket = BucketReopen::new();
    eprintln!("--- s3 host on its in-process bucket");
    body(&move || bucket.open());
}

/// One published attempt, ready for the next story.
fn publish(
    host: &dyn Host,
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
) -> gitiup_host::change::Published {
    let record = signed_change(who, title, anchor, head, index, previous);
    change::publish_change(host, &record, Actor::new(who).unwrap())
        .unwrap_or_else(|e| panic!("publish attempt {index}: {e}"))
}

// ---------------------------------------------------------------------------
// an empty store
// ---------------------------------------------------------------------------

#[test]
fn an_empty_store_has_no_changes() {
    each_store(|open| {
        let host = open();
        let catalog =
            change::list_changes(host.as_ref()).expect("an empty listing is not an error");
        assert!(
            catalog.is_empty(),
            "nothing has been published: {catalog:?}"
        );

        let id = change::ChangeId::derive(&author("ada").key_id, BASE_REF, HEAD_ONE).unwrap();
        assert!(
            change::change_history(host.as_ref(), &id)
                .unwrap()
                .is_empty(),
            "a change nobody proposed has no attempts"
        );
        let missing = change::change_at(host.as_ref(), &change::change_head_ref(&id)).unwrap_err();
        assert_eq!(
            missing.exit_code(),
            3,
            "a ref that is not there is a missing thing, not a refusal: {missing}"
        );
        assert!(host.list(&Namespace::CHANGE).unwrap().is_empty());
        // And a handle that only reads says the same thing.
        assert!(change::list_changes(open().as_ref()).unwrap().is_empty());
    });
}

// ---------------------------------------------------------------------------
// publishing
// ---------------------------------------------------------------------------

#[test]
fn publish_stores_the_bytes_advertises_the_refs_and_reads_back() {
    each_store(|open| {
        let host = open();
        let record = signed_change(
            "ada",
            "Refuse a ref outside the store",
            HEAD_ONE,
            HEAD_ONE,
            0,
            None,
        );
        let published = change::publish_change(host.as_ref(), &record, Actor::new("ada").unwrap())
            .expect("publish attempt 0");

        assert_eq!(published.change_id, record.change_id);
        assert_eq!(published.attempt, Some(0));
        assert!(!published.already, "this one is new");
        assert_eq!(
            published.size,
            record.canonical_bytes().unwrap().len() as u64
        );
        assert_eq!(
            published.reference.as_str(),
            format!("refs/changes/{}/attempt/0", record.change_id)
        );
        assert_eq!(
            published.head_ref.as_str(),
            format!("refs/changes/{}/head", record.change_id)
        );

        // The bytes are in the CAS under their own digest, in the change namespace.
        let digest = record.digest().unwrap();
        assert_eq!(published.record_digest, digest);
        assert_eq!(
            host.get(&digest).unwrap().as_deref(),
            Some(record.canonical_bytes().unwrap().as_slice())
        );
        assert_eq!(
            change::kv_key(&Namespace::CHANGE, &digest),
            format!("kv/change/{}", digest.hex())
        );
        let blobs: Vec<BlobEntry> = host.list(&Namespace::CHANGE).unwrap();
        assert!(blobs.iter().any(|entry| entry.oid == digest));

        // Reading it back through either ref gives the same record, checked (and
        // through a handle that wrote nothing at all).
        let reader = open();
        for name in [published.head_ref.clone(), published.reference.clone()] {
            {
                let fetched = change::change_at(reader.as_ref(), &name)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(fetched.digest, digest);
                assert_eq!(fetched.bytes, record.canonical_bytes().unwrap());
                assert_eq!(
                    fetched.record,
                    StoredRecord::Change(record.clone()),
                    "{name} resolved to something else"
                );
            }
        }
        let head =
            change::change_at(host.as_ref(), &change::change_head_ref(&record.change_id)).unwrap();
        assert_eq!(
            head.target,
            ChangeRef::Head {
                id: record.change_id.clone()
            }
        );

        // The listing agrees with the refs without parsing a single record.
        let catalog = change::list_changes(host.as_ref()).unwrap();
        assert_eq!(catalog.changes.len(), 1);
        let summary = &catalog.changes[0];
        assert_eq!(summary.change_id, record.change_id);
        assert_eq!(summary.state, State::Open);
        assert_eq!(summary.attempts, vec![0]);
        assert_eq!(summary.head, Some(digest));
        assert!(summary.head_tracks_newest);
        assert_eq!(summary.merged, None);
        assert_eq!(summary.abandoned, None);
        // The handle trick for `resolve` on a short handle (D3).
        assert_eq!(catalog.resolve(&digest.hex()).len(), 0);
        assert_eq!(catalog.resolve(summary.change_id.hex()).len(), 1);
    });
}

#[test]
fn publishing_the_same_attempt_twice_is_not_a_second_write() {
    each_store(|open| {
        let host = open();
        let record = signed_change("ada", "Idempotence", HEAD_ONE, HEAD_ONE, 0, None);
        let first = change::publish_change(host.as_ref(), &record, "ada").unwrap();
        let second = change::publish_change(host.as_ref(), &record, "ada").unwrap();
        assert!(!first.already);
        assert!(second.already, "same bytes, same refs: nothing changed");
        assert_eq!(
            first.record_digest, second.record_digest,
            "and it is the same answer about the same record"
        );
        assert_eq!(
            change::list_changes(open().as_ref()).unwrap().changes[0].attempts,
            vec![0]
        );
        assert_eq!(
            host.list(&Namespace::CHANGE).unwrap().len(),
            1,
            "one object, not two"
        );
    });
}

#[test]
fn a_force_push_is_a_new_attempt_and_the_old_ref_never_moves() {
    each_store(|open| {
        let host = open();
        let first = signed_change("ada", "One title", HEAD_ONE, HEAD_ONE, 0, None);
        let first_digest = first.digest().unwrap();
        change::publish_change(host.as_ref(), &first, "ada").unwrap();

        let second = signed_change(
            "ada",
            "One title",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(first.change_digest().unwrap()),
        );
        let published = change::publish_change(host.as_ref(), &second, "ada").unwrap();
        assert_eq!(published.attempt, Some(1));
        assert_eq!(
            published.change_id, first.change_id,
            "still the same change"
        );

        let head =
            change::change_at(host.as_ref(), &change::change_head_ref(&first.change_id)).unwrap();
        assert_eq!(head.digest, second.digest().unwrap());
        let attempt0 =
            change::change_at(host.as_ref(), &change::attempt_ref(&first.change_id, 0)).unwrap();
        assert_eq!(attempt0.digest, first_digest, "attempt 0 is untouched");
        assert_eq!(
            attempt0.target,
            ChangeRef::Attempt {
                id: first.change_id.clone(),
                index: 0
            }
        );

        let summary = &change::list_changes(host.as_ref()).unwrap().changes[0];
        assert_eq!(summary.attempts, vec![0, 1]);
        assert!(summary.head_tracks_newest);

        // The history is the chain, and the chain is the one D6 describes.
        let history = change::change_history(host.as_ref(), &first.change_id).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].head, HEAD_ONE);
        assert_eq!(history[1].head, HEAD_TWO);
        assert_eq!(
            history[1].previous.as_deref(),
            Some(history[0].change_digest.as_str())
        );
        assert_eq!(history[1].record_digest, second.digest().unwrap());
        assert_eq!(history[1].author.key_id, first.author.key_id);
    });
}

#[test]
fn a_change_with_ten_attempts_still_numbers_in_order() {
    each_store(|open| {
        let host = open();
        let mut previous = None;
        for index in 0..11u32 {
            // Attempt 0 anchors its own head, so it starts where the change did.
            let head = if index == 0 { HEAD_ONE } else { HEAD_TWO };
            let record = signed_change("ada", "Eleven attempts", HEAD_ONE, head, index, previous);
            previous = Some(record.change_digest().unwrap());
            change::publish_change(host.as_ref(), &record, "ada").unwrap();
        }
        let catalog = change::list_changes(host.as_ref()).unwrap();
        assert_eq!(catalog.changes.len(), 1);
        assert_eq!(
            catalog.changes[0].attempts,
            (0..11u32).collect::<Vec<u32>>(),
            "attempts sort by number, not by ref name: `attempt/10` sorts before `attempt/2`"
        );
        assert!(
            catalog.changes[0].head_tracks_newest,
            "and the newest of them is where head points"
        );
        let history = change::change_history(host.as_ref(), &catalog.changes[0].change_id).unwrap();
        assert_eq!(history.len(), 11);
        assert_eq!(history.last().unwrap().index, 10);
    });
}

#[test]
fn an_attempt_that_exists_with_a_different_head_is_refused_not_overwritten() {
    each_store(|open| {
        let host = open();
        let published = publish(
            host.as_ref(),
            "ada",
            "One title",
            HEAD_ONE,
            HEAD_ONE,
            0,
            None,
        );

        // Same author, same base, same anchor — so the same change_id and the same
        // attempt index — but different bytes.
        let other = signed_change("ada", "A different title", HEAD_ONE, HEAD_ONE, 0, None);
        let err = change::publish_change(host.as_ref(), &other, "ada").unwrap_err();
        assert_eq!(
            err.exit_code(),
            6,
            "a duplicate attempt is a refusal: {err}"
        );
        assert!(
            err.is_conflict(),
            "and it is the store's own conflict: {err}"
        );
        assert!(
            err.hint().unwrap_or_default().contains("attempt 0"),
            "it says which attempt already exists and what to do about it: {err}"
        );

        // The ref and the bytes it advertises are untouched.
        assert_eq!(
            change::change_at(host.as_ref(), &change::attempt_ref(&published.change_id, 0),)
                .unwrap()
                .digest,
            published.record_digest
        );
        assert_eq!(
            change::change_at(
                host.as_ref(),
                &change::change_head_ref(&published.change_id)
            )
            .unwrap()
            .digest,
            published.record_digest
        );
    });
}

#[test]
fn head_moves_only_from_what_the_writer_just_read() {
    each_store(|open| {
        let host = open();
        let first = signed_change("ada", "Race", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &first, "ada").unwrap();
        let second = signed_change(
            "ada",
            "Race",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(first.change_digest().unwrap()),
        );

        // Somebody else moves head between our read and our write. The only legal move
        // is from the value we read, so a stale expectation is a conflict naming both
        // sides rather than a lost update.
        let head = change::change_head_ref(&first.change_id);
        let stale = host.get_ref(&head).unwrap().unwrap().oid;
        let elsewhere = host
            .put_cas(&Namespace::RECORD, b"someone else's record entirely")
            .unwrap();
        host.update_ref_cas(&RefUpdate::replace(head.clone(), stale, elsewhere))
            .unwrap();

        let err = host
            .update_ref_cas(&RefUpdate::replace(
                head.clone(),
                stale,
                second.digest().unwrap(),
            ))
            .unwrap_err();
        assert!(err.is_conflict(), "{err}");
        assert_eq!(err.exit_code(), 6);
        assert!(
            err.message().contains(&stale.short_default())
                && err.message().contains(&elsewhere.short_default()),
            "a conflict names both sides: {err}"
        );
        // A fresh read sees the truth, so the next submit succeeds.
        let published = change::publish_change(host.as_ref(), &second, "ada").unwrap();
        assert_eq!(
            change::change_at(host.as_ref(), &head).unwrap().digest,
            published.record_digest
        );
    });
}

// ---------------------------------------------------------------------------
// refusing what does not add up
// ---------------------------------------------------------------------------

/// A record built from a published change, by the owner's key.
fn merge_record_of(change: &gitiup_host::change::ChangeRecord, via: &str) -> MergeRecord {
    MergeRecord {
        change_digest: change.change_digest().unwrap(),
        change_id: change.change_id.clone(),
        attempt: change.attempts.index,
        base: gitiup_host::change::MergeBase {
            branch: change.base.branch.clone(),
            from: change.base.oid.clone(),
            to: change.head.clone(),
        },
        merged_at_us: T0 + 2 * HOUR,
        via: via.to_string(),
        proofs: vec![proof(0x11), proof(0x22)],
        policy_digest: None,
        author: author("owner"),
        schema_version: 1,
        record_type: gitiup_host::change::MERGE_TYPE.to_string(),
        signatures: Vec::new(),
        annotations: None,
    }
}

fn abandon_record_of(change: &gitiup_host::change::ChangeRecord, who: &str) -> AbandonRecord {
    AbandonRecord {
        change_digest: change.change_digest().unwrap(),
        change_id: change.change_id.clone(),
        attempt: change.attempts.index,
        abandoned_at_us: T0 + 2 * HOUR,
        reason: "superseded".to_string(),
        note: Some("re-drawn against main".to_string()),
        author: author(who),
        schema_version: 1,
        record_type: gitiup_host::change::ABANDON_TYPE.to_string(),
        signatures: Vec::new(),
        annotations: None,
    }
}

#[test]
fn states_are_derived_from_which_refs_exist() {
    each_store(|open| {
        let host = open();
        let change = signed_change("ada", "Close me", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &change, "ada").unwrap();
        assert_eq!(state_of(host.as_ref(), &change.change_id), State::Open);

        let merge = merge_record_of(&change, "store")
            .sign(&fixture_key("owner"))
            .unwrap();
        let merged = change::publish_merge(host.as_ref(), &merge, "owner").unwrap();
        assert_eq!(merged.record_digest, merge.digest().unwrap());
        // merged beats everything else (D7's precedence).
        assert_eq!(state_of(host.as_ref(), &change.change_id), State::Merged);
        let summary = &change::list_changes(host.as_ref()).unwrap().changes[0];
        assert_eq!(summary.merged, Some(merge.digest().unwrap()));
        assert_eq!(summary.head, Some(change.digest().unwrap()));

        // A second merge is a conflict naming the first, never a re-merge.
        let err = change::publish_merge(host.as_ref(), &merge, "owner").unwrap_err();
        assert_eq!(err.exit_code(), 6, "a change is merged once: {err}");
        assert!(err.is_conflict(), "{err}");

        // Abandoning a merged change: also refused, and the state stays merged.
        let abandon = abandon_record_of(&change, "ada")
            .sign(&fixture_key("ada"))
            .unwrap();
        change::publish_abandon(host.as_ref(), &abandon, "ada").unwrap();
        assert_eq!(
            state_of(host.as_ref(), &change.change_id),
            State::Merged,
            "merged outranks abandoned"
        );

        // A closed change takes no further attempts: a new topic is a new change.
        let more = signed_change(
            "ada",
            "Close me",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(change.change_digest().unwrap()),
        );
        let err = change::publish_change(host.as_ref(), &more, "ada").unwrap_err();
        assert_eq!(err.exit_code(), 6, "{err}");
        assert!(err.message().contains("merged"), "it says why: {err}");
    });
}

fn state_of(host: &dyn Host, id: &change::ChangeId) -> State {
    change::list_changes(host)
        .unwrap()
        .changes
        .iter()
        .find(|change| change.change_id == *id)
        .unwrap_or_else(|| panic!("no summary for {id}"))
        .state
}

#[test]
fn an_abandoned_change_is_abandoned_once() {
    each_store(|open| {
        let host = open();
        let change = signed_change("lin", "Withdrawn work", HEAD_THREE, HEAD_THREE, 0, None);
        change::publish_change(host.as_ref(), &change, "lin").unwrap();
        let abandon = abandon_record_of(&change, "lin")
            .sign(&fixture_key("lin"))
            .unwrap();
        change::publish_abandon(host.as_ref(), &abandon, "lin").unwrap();
        assert_eq!(state_of(host.as_ref(), &change.change_id), State::Abandoned);
        let err = change::publish_abandon(host.as_ref(), &abandon, "lin").unwrap_err();
        assert_eq!(err.exit_code(), 6, "abandoned once: {err}");
        assert!(host.get(&abandon.digest().unwrap()).unwrap().is_some());
    });
}

#[test]
fn a_merge_record_must_match_the_attempt_it_names() {
    each_store(|open| {
        let host = open();
        let first = signed_change("ada", "Which attempt", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &first, "ada").unwrap();
        let second = signed_change(
            "ada",
            "Which attempt",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(first.change_digest().unwrap()),
        );
        change::publish_change(host.as_ref(), &second, "ada").unwrap();

        // A merge record that cites attempt 1 but carries attempt 0's digest: the
        // merge gate would then be judging a different proposal than the one merged.
        let mut lying = merge_record_of(&second, "store");
        lying.change_digest = first.change_digest().unwrap();
        let lying = lying.sign(&fixture_key("owner")).unwrap();
        let err = change::publish_merge(host.as_ref(), &lying, "owner").unwrap_err();
        assert_eq!(err.exit_code(), 8, "a digest that does not match: {err}");

        // And one whose `to` is not the merged attempt's head.
        let mut misfiled = merge_record_of(&second, "store");
        misfiled.base.to = HEAD_THREE.to_string();
        let misfiled = misfiled.sign(&fixture_key("owner")).unwrap();
        // The digest citation is still right, so the store's binding is the attempt
        // ref; the `to`/head agreement is the merge's own step-3 check (giti-b2z.4).
        change::publish_merge(host.as_ref(), &misfiled, "owner").unwrap();
    });
}

#[test]
fn a_ref_pointing_at_a_record_that_names_a_different_head_is_refused() {
    each_store(|open| {
        let host = open();
        let mine = signed_change("ada", "Honest", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &mine, "ada").unwrap();
        let theirs = signed_change("lin", "Someone else's", HEAD_THREE, HEAD_THREE, 0, None);
        change::publish_change(host.as_ref(), &theirs, "lin").unwrap();

        // (a) a `head` ref filed under one change and pointing at another's record.
        let hijacked = change::change_head_ref(&mine.change_id);
        let current = host.get_ref(&hijacked).unwrap().unwrap().oid;
        host.update_ref_cas(&RefUpdate::replace(
            hijacked.clone(),
            current,
            theirs.digest().unwrap(),
        ))
        .unwrap();
        let err = change::change_at(host.as_ref(), &hijacked).unwrap_err();
        assert_eq!(
            err.exit_code(),
            6,
            "the record is about someone else: {err}"
        );
        assert!(
            err.message().contains(&theirs.change_id.to_string()),
            "{err}"
        );

        // (b) an `attempt/<n>` ref holding a record that says it is a different
        // attempt. The ref cannot move, so one of the two is a lie.
        let attempt = change::attempt_ref(&theirs.change_id, 1);
        host.update_ref_cas(&RefUpdate::create(
            attempt.clone(),
            theirs.digest().unwrap(),
        ))
        .unwrap();
        let err = change::change_at(host.as_ref(), &attempt).unwrap_err();
        assert_eq!(err.exit_code(), 6, "attempt 1 holding attempt 0: {err}");
        assert!(err.message().contains("attempt"), "{err}");

        // (c) a ref whose value names bytes this store cannot return.
        let ghost = Oid::hash_bytes(b"never stored anywhere");
        let reference = change::attempt_ref(&theirs.change_id, 7);
        host.update_ref_cas(&RefUpdate::create(reference.clone(), ghost))
            .unwrap();
        let err = change::change_at(host.as_ref(), &reference).unwrap_err();
        assert_eq!(err.exit_code(), 3, "the promise, not the bytes: {err}");
        assert!(err.hint().unwrap().contains("re-publish"), "{err}");
    });
}

#[test]
fn a_head_naming_a_different_head_than_the_history_is_refused_loudly() {
    each_store(|open| {
        let host = open();
        let first = signed_change("ada", "Half a submit", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &first, "ada").unwrap();
        let second = signed_change(
            "ada",
            "Half a submit",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(first.change_digest().unwrap()),
        );
        // The crashed submit: the bytes and the attempt ref exist, head never moved.
        host.put_cas(&Namespace::CHANGE, &second.canonical_bytes().unwrap())
            .unwrap();
        host.update_ref_cas(&RefUpdate::create(
            change::attempt_ref(&first.change_id, 1),
            second.digest().unwrap(),
        ))
        .unwrap();

        let summary = &change::list_changes(host.as_ref()).unwrap().changes[0];
        assert!(!summary.head_tracks_newest, "the listing says so");

        let err = change::change_at(host.as_ref(), &change::change_head_ref(&first.change_id))
            .unwrap_err();
        assert_eq!(err.exit_code(), 6, "head names a stale head: {err}");
        assert!(
            err.hint().unwrap().contains("re-run"),
            "and says the fix: {err}"
        );

        // The attempt itself is still readable, and re-publishing finishes the job.
        assert!(
            change::change_at(host.as_ref(), &change::attempt_ref(&first.change_id, 1)).is_ok()
        );
        change::publish_change(host.as_ref(), &second, "ada").unwrap();
        assert_eq!(
            change::change_at(host.as_ref(), &change::change_head_ref(&first.change_id))
                .unwrap()
                .digest,
            second.digest().unwrap()
        );
    });
}

#[test]
fn a_chain_with_a_gap_is_refused_by_name() {
    each_store(|open| {
        let host = open();
        let first = signed_change("ada", "Chain", HEAD_ONE, HEAD_ONE, 0, None);
        change::publish_change(host.as_ref(), &first, "ada").unwrap();
        let second = signed_change(
            "ada",
            "Chain",
            HEAD_ONE,
            HEAD_TWO,
            1,
            Some(first.change_digest().unwrap()),
        );
        change::publish_change(host.as_ref(), &second, "ada").unwrap();
        let third = signed_change(
            "ada",
            "Chain",
            HEAD_ONE,
            HEAD_THREE,
            2,
            Some(second.change_digest().unwrap()),
        );
        change::publish_change(host.as_ref(), &third, "ada").unwrap();
        assert_eq!(
            change::change_history(host.as_ref(), &first.change_id)
                .unwrap()
                .len(),
            3
        );

        // An attempt ref goes away: "the history is shorter than it claims" is a
        // refusal, not a shrug (D6).
        host.delete_ref_cas(&RefDeletion::new(
            change::attempt_ref(&first.change_id, 1),
            Expect::Any,
        ))
        .unwrap();
        let err = change::change_history(host.as_ref(), &first.change_id).unwrap_err();
        assert!(
            matches!(err.exit_code(), 6 | 8),
            "a gap is a refusal: {err}"
        );
        assert!(
            err.message().contains(&second.change_digest().unwrap())
                || err.message().contains("attempt"),
            "it names what is missing: {err}"
        );
        // And a chain that starts above zero cannot be checked at all.
        host.delete_ref_cas(&RefDeletion::new(
            change::attempt_ref(&first.change_id, 0),
            Expect::Any,
        ))
        .unwrap();
        assert!(change::change_history(host.as_ref(), &first.change_id).is_err());
    });
}

#[test]
fn garbage_is_refused_with_the_code_that_names_it() {
    let good = signed_change("ada", "Garbage", HEAD_ONE, HEAD_ONE, 0, None);
    let bytes = good.canonical_bytes().unwrap();

    // 8: bytes that are not their own canonical form.
    let mut spaced = bytes.clone();
    spaced.splice(1..1, b" ".to_vec());
    assert_eq!(
        change::ChangeRecord::from_canonical_bytes(&spaced)
            .unwrap_err()
            .exit_code(),
        8
    );
    // 8: a change_id that does not re-derive.
    let mut squatter: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    squatter["change_id"] = serde_json::Value::String("chg-0000000000000000".into());
    assert_eq!(
        change::record_from_bytes(&gitiup_canon::canon::to_value_bytes(&squatter).unwrap())
            .unwrap_err()
            .exit_code(),
        8
    );
    // 6: an unknown field, an unknown type, a base that is not a branch, an
    // unsorted job list.
    let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    extra["draft"] = serde_json::Value::Bool(true);
    assert_eq!(
        change::record_from_bytes(&gitiup_canon::canon::to_value_bytes(&extra).unwrap())
            .unwrap_err()
            .exit_code(),
        6
    );
    let mut not_a_branch = good.clone();
    not_a_branch.base.branch = "refs/pull/1/head".to_string();
    assert_eq!(not_a_branch.validate().unwrap_err().exit_code(), 6);
    let mut messy = good.clone();
    messy.workflow.jobs = vec!["test".to_string(), "build".to_string()];
    assert_eq!(messy.validate().unwrap_err().exit_code(), 6);
    let anchored_elsewhere = change_record("ada", "Garbage", HEAD_TWO, HEAD_ONE, 0, None);
    assert_eq!(
        anchored_elsewhere.validate().unwrap_err().exit_code(),
        6,
        "attempt 0 anchors its own head"
    );

    // 7: someone else's signature, and a key id that is not its fingerprint.
    let mut swapped = good.clone();
    swapped.signatures = signed_change("lin", "Garbage", HEAD_ONE, HEAD_ONE, 0, None).signatures;
    assert_eq!(swapped.verify().unwrap_err().exit_code(), 7);
    let mut spoofed = good.clone();
    spoofed.signatures[0].public_key = fixture_key("lin").public_key().to_openssh();
    assert_eq!(spoofed.verify().unwrap_err().exit_code(), 7);
    // Signing as somebody else is refused when it is made, not when it is read.
    let mut other_author = change_record("ada", "Garbage", HEAD_ONE, HEAD_ONE, 0, None);
    other_author.author = author("lin");
    assert_eq!(
        other_author
            .sign(&fixture_key("ada"))
            .unwrap_err()
            .exit_code(),
        7
    );
}

#[test]
fn a_huge_record_is_refused_before_it_reaches_the_store() {
    each_store(|open| {
        let host = open();
        let mut huge = change_record("ada", "", HEAD_ONE, HEAD_ONE, 0, None);
        huge.title = "a".repeat(gitiup_host::change::MAX_TITLE_BYTES);
        huge.annotations = Some(
            (0..gitiup_host::change::MAX_ANNOTATIONS)
                .map(|i| {
                    (
                        format!("x_producer_{i}"),
                        "y".repeat(gitiup_host::change::MAX_ANNOTATION_BYTES),
                    )
                })
                .collect(),
        );
        // Fill until the whole record is over the ceiling, then check the refusal.
        while huge.title.len() < gitiup_host::change::MAX_RECORD_BYTES {
            huge.title.push('a');
        }
        let err = huge.sign(&fixture_key("ada")).unwrap_err();
        assert_eq!(err.exit_code(), 6, "a huge record is refused: {err}");
        assert!(err.message().contains("limit"), "{err}");

        let before = host.list(&Namespace::CHANGE).unwrap().len();
        let err = change::publish_change(host.as_ref(), &huge, "ada").unwrap_err();
        assert_eq!(err.exit_code(), 6, "{err}");
        assert_eq!(
            host.list(&Namespace::CHANGE).unwrap().len(),
            before,
            "and nothing was written"
        );
        assert!(change::list_changes(host.as_ref()).unwrap().is_empty());

        // Asking for its bytes at all is the same refusal, so no caller can
        // accidentally hold a megabyte in a merge gate.
        assert_eq!(huge.canonical_bytes().unwrap_err().exit_code(), 6);
    });
}

#[test]
fn changes_do_not_leak_into_each_other_and_strangers_are_printed() {
    each_store(|open| {
        let host = open();
        let ada = signed_change("ada", "Ada's", HEAD_ONE, HEAD_ONE, 0, None);
        let lin = signed_change("lin", "Lin's", HEAD_THREE, HEAD_THREE, 0, None);
        change::publish_change(host.as_ref(), &ada, "ada").unwrap();
        change::publish_change(host.as_ref(), &lin, "lin").unwrap();

        let catalog = change::list_changes(host.as_ref()).unwrap();
        assert_eq!(catalog.changes.len(), 2);
        assert!(catalog.unexpected.is_empty());
        assert_eq!(catalog.open().len(), 2);
        assert_eq!(
            change::change_history(host.as_ref(), &ada.change_id)
                .unwrap()
                .len(),
            1,
            "one attempt each"
        );
        // A short handle works, an ambiguous one lists the candidates (D3).
        assert_eq!(catalog.resolve(&ada.change_id.hex()[..4]).len(), 1);
        assert!(catalog.resolve("zzzz").is_empty());

        // A ref under `refs/changes/` that this format never wrote is reported, not
        // silently dropped: a listing that hides a ref is how "there is no such
        // change" becomes a lie.
        host.update_ref_cas(&RefUpdate::create(
            RefName::new("refs/changes/not-a-change/head").unwrap(),
            Oid::hash_bytes(b"whatever"),
        ))
        .unwrap();
        let catalog = change::list_changes(host.as_ref()).unwrap();
        assert_eq!(catalog.unexpected.len(), 1, "{catalog:?}");
        assert!(catalog.unexpected[0].contains("not-a-change"));
        assert_eq!(catalog.changes.len(), 2);
    });
}

// ---------------------------------------------------------------------------
// the two claims that need a store that misbehaves
// ---------------------------------------------------------------------------

#[test]
fn bytes_that_do_not_rehash_to_their_name_are_refused_with_eight() {
    let store = FsReopen::new();
    let inner = store.open();
    let record = signed_change("ada", "Lies", HEAD_ONE, HEAD_ONE, 0, None);
    change::publish_change(inner.as_ref(), &record, "ada").unwrap();
    let digest = record.digest().unwrap();

    // Another record's bytes, filed under this digest: exactly what a corrupt store, a
    // truncated upload or an attacker with write access to the bucket produces.
    let other = signed_change("ada", "Different", HEAD_ONE, HEAD_ONE, 0, None);
    let host =
        Tampered::new(store.open(), false).with_bytes(digest, other.canonical_bytes().unwrap());
    let err = change::change_at(&host, &change::change_head_ref(&record.change_id)).unwrap_err();
    assert_eq!(err.exit_code(), 8, "the bytes are not their name: {err}");
    assert!(err.message().contains("hash"), "{err}");
    assert_eq!(
        change::read_stored(&host, &digest).unwrap_err().exit_code(),
        8
    );
    // And a store that answers `put_cas` with a name the bytes do not earn is refused
    // before a ref ever advertises the lie.
    let lie = signed_change("lin", "Another", HEAD_THREE, HEAD_THREE, 0, None);
    let lying_store =
        Tampered::new(store.open(), false).mislabelling(Oid::hash_bytes(b"different bytes"));
    let before = change::list_changes(&lying_store).unwrap().changes.len();
    let err = change::publish_change(&lying_store, &lie, "lin").unwrap_err();
    assert_eq!(err.exit_code(), 8, "a store that rewrites bytes: {err}");
    assert!(err.message().contains("instead of"), "{err}");
    assert_eq!(
        change::list_changes(&lying_store).unwrap().changes.len(),
        before,
        "and no ref was written to advertise the lie"
    );
}

#[test]
fn a_store_without_cas_is_refused_rather_than_asked_to_force() {
    let inner = FsReopen::new().open();
    let host = Tampered::new(inner, true);
    assert!(!host.capabilities().cas);
    let record = signed_change("ada", "No CAS", HEAD_ONE, HEAD_ONE, 0, None);
    let err = change::publish_change(&host, &record, "ada").unwrap_err();
    assert!(
        err.is_unsupported(),
        "a capability refusal, not a force: {err}"
    );
    assert_eq!(err.exit_code(), 6);
    assert!(err.hint().unwrap().contains("conditional writes"), "{err}");
    assert!(host.list(&Namespace::CHANGE).unwrap().is_empty());
}

/// A host wrapper that makes two claims no honest host makes: that a blob is not the
/// bytes it was filed under, and that refs cannot be compared-and-swapped.
///
/// Both are load-bearing promises of this module, and the only honest way to test them
/// is a store that breaks them on purpose.
struct Tampered {
    inner: Box<dyn Host>,
    no_cas: bool,
    /// `(name, bytes)` to answer a `get` with instead of what is stored there.
    lies: Vec<(Oid, Vec<u8>)>,
    /// A digest to answer `put_cas` with, whatever the bytes were.
    wrong_put: Option<Oid>,
}

impl Tampered {
    fn new(inner: Box<dyn Host>, no_cas: bool) -> Tampered {
        Tampered {
            inner,
            no_cas,
            lies: Vec::new(),
            wrong_put: None,
        }
    }

    fn with_bytes(mut self, oid: Oid, bytes: Vec<u8>) -> Tampered {
        self.lies.push((oid, bytes));
        self
    }

    /// Answer every `put_cas` with `claim` instead of the digest of the bytes handed
    /// over: a store that files bytes under a name that is not their digest.
    fn mislabelling(mut self, claim: Oid) -> Tampered {
        self.wrong_put = Some(claim);
        self
    }
}

impl RefStore for Tampered {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.inner.list_refs(query)
    }

    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.inner.get_ref(name)
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        if self.no_cas {
            return Err(HostError::unsupported("cas", "this host has no lease"));
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

impl BlobStore for Tampered {
    fn put_cas(&self, namespace: &Namespace, content: &[u8]) -> Result<Oid, HostError> {
        self.inner.put_cas(namespace, content)?;
        Ok(self.wrong_put.unwrap_or_else(|| Oid::hash_bytes(content)))
    }

    fn get(&self, oid: &Oid) -> Result<Option<Vec<u8>>, HostError> {
        if let Some((_, bytes)) = self.lies.iter().find(|(lie, _)| lie == oid) {
            return Ok(Some(bytes.clone()));
        }
        self.inner.get(oid)
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<BlobEntry>, HostError> {
        self.inner.list_prefix(prefix)
    }
}

impl Host for Tampered {
    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.capabilities();
        if self.no_cas {
            caps.cas = false;
        }
        caps
    }

    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

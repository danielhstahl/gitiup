//! Merging a change: the owner's compare-and-swap, the record it writes, and the
//! refusals that make it safe to run against a stranger's store (giti-b2z.4).
//!
//! ADR-0003 D8 makes a merge eight steps, and this file walks them in order: the record
//! read through its ref, the base read fresh, the comparison that refuses with both oids,
//! the fast-forward the caller has to prove, the CAS write, and the signed record of the
//! whole thing. Everything from step 6 on is deliberately the part that can fail alone,
//! so the failure window is exercised here too, with the retry that closes it.
//!
//! The store has to misbehave for two of the criteria, so two wrappers do: [`Denied`]
//! refuses writes to `refs/heads/**` the way a store with a non-owner credential does
//! (and the test asserts the refusal arrives *unedited*), and [`NoCas`] reports no
//! compare-and-swap at all, which is a refusal rather than an unconditional write.
//!
//! Every story runs against the bucket host as well as the filesystem host: a merge is a
//! conditional write, and a bucket is the weakest host that has to be able to make one.

mod change_support;

use std::sync::Arc;

use change_support::*;
use gitiup_canon::SigningKey;
use gitiup_host::change::{
    self, AbandonRecord, Ancestry, ChangeId, ChangeRecord, MergeRecord, State, StoredRecord, Via,
};
use gitiup_host::{
    Actor, BlobEntry, BlobStore, Capabilities, Expect, FsHost, Host, HostError, HostErrorExt,
    HostErrorKind, HostInfo, MemoryBucket, Namespace, Oid, Pack, PackRequest, Ref, RefDeletion,
    RefName, RefQuery, RefStore, RefUpdate, RemoteConfig, S3Host, SharedBucket,
};

/// The commit refs of a record, as the store spells them.
fn oid(tagged: &str) -> Oid {
    Oid::from_hex(tagged.split_once(':').map(|(_, hex)| hex).unwrap_or(tagged))
        .unwrap_or_else(|_| panic!("'{tagged}' is not an oid"))
}

/// `sha1:…` → `…`, which is how the CLI spells an oid in a message.
fn bare(tagged: &str) -> &str {
    tagged.split_once(':').map(|(_, hex)| hex).unwrap_or(tagged)
}

/// Publish `refs/heads/main` at the record's base. That publish is the owner's act and
/// this test's act, never gitiup's: D8 step 2 says the branch must already be there.
fn publish_branch(host: &dyn Host) {
    host.update_ref_cas(&RefUpdate::new(
        RefName::branch("main").expect("a branch name"),
        Expect::Absent,
        oid(BASE_OID),
    ))
    .expect("publish the branch");
}

/// Run each story against every store that can do a CAS. The bucket host is in here
/// because it is the hard case: no filesystem lock, no ref locking, and a commit graph
/// the store cannot even see.
fn each_store(mut body: impl FnMut(&dyn Host)) {
    eprintln!("--- fs host");
    let dir = tempfile::tempdir().expect("temp dir");
    let fs = FsHost::create(dir.path().join("store")).expect("create the fs store");
    publish_branch(&fs);
    body(&fs);

    eprintln!("--- s3 host on its in-process bucket");
    let bucket: SharedBucket = Arc::new(MemoryBucket::forge("gitiup-forge"));
    let remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo")
        .expect("s3 remote")
        .with_option("ref-cache-ttl", "0s");
    let s3 = S3Host::init(bucket, &remote).expect("init the bucket store");
    publish_branch(&s3);
    body(&s3);
}

/// Publish one attempt and hand back the record **as the store holds it**, read back
/// through the ref that advertises it — a merge may not be built out of the copy the
/// author kept, and reading it back through the ref is what proves the ref is there.
fn publish(host: &dyn Host, who: &str, head: &str) -> ChangeRecord {
    // Attempt 0 anchors its own head (D3), so the anchor is the head being published.
    let signed = signed_change(who, "Teach the merge to refuse", head, head, 0, None);
    let published = change::publish_change(host, &signed, Actor::new(who).expect("an actor"))
        .unwrap_or_else(|e| panic!("publish: {e}"));
    let fetched = change::change_at(host, &change::attempt_ref(&published.change_id, 0))
        .expect("the attempt is readable and verified through its own ref");
    let record = match fetched.record {
        StoredRecord::Change(record) => record,
        other => panic!("{} holds a {}", fetched.reference, other.record_type()),
    };
    assert_eq!(
        record.digest().expect("a digest"),
        published.record_digest,
        "the copy read back is the copy that was written"
    );
    record
}

/// The owner, and the key its merges are signed with.
///
/// The two live together because a [`change::MergeRequest`] borrows its signer: a helper
/// that minted a key inside itself could not hand back the request it built, and every
/// merge in these tests is the owner's.
struct Owner {
    key: SigningKey,
}

impl Owner {
    fn new() -> Owner {
        Owner {
            key: fixture_key("owner"),
        }
    }

    /// The request a merge gate builds: this attempt, signed by the owner, with the
    /// fast-forward the caller proved.
    fn request<'a>(
        &'a self,
        record: &'a ChangeRecord,
        ancestry: Ancestry,
    ) -> change::MergeRequest<'a> {
        change::MergeRequest::new(record, &self.key, author("owner")).with_ancestry(ancestry)
    }
}

/// Read the merge record back through the ref that advertises it, the way `show` does.
fn merged_record(host: &dyn Host, id: &ChangeId) -> MergeRecord {
    let fetched = change::change_at(host, &change::merged_ref(id))
        .unwrap_or_else(|e| panic!("read the merged ref: {e}"));
    match fetched.record {
        StoredRecord::Merge(record) => record,
        other => panic!("{} holds a {}", fetched.reference, other.record_type()),
    }
}

/// The branch tip, or none.
fn branch(host: &dyn Host) -> Option<Oid> {
    host.get_ref(&RefName::branch("main").expect("branch"))
        .expect("read the branch")
        .map(|reference| reference.oid)
}

/// Move the branch as if someone else had merged something: this is the only way a test
/// can create D8's failure window, because the CAS write and the record are two writes.
fn move_branch(host: &dyn Host, from: &str, to: &str) {
    host.update_ref_cas(&RefUpdate::replace(
        RefName::branch("main").expect("branch"),
        oid(from),
        oid(to),
    ))
    .expect("move the branch");
}

/// Every ref and every `kv/` object in the store, for the "touched nothing" assertions.
fn fingerprint(host: &dyn Host) -> (Vec<(String, String)>, Vec<String>) {
    let mut refs: Vec<(String, String)> = host
        .list_refs(&RefQuery::all())
        .expect("list refs")
        .into_iter()
        .map(|reference| {
            (
                reference.name.as_str().to_string(),
                reference.oid.hex().to_string(),
            )
        })
        .collect();
    refs.sort();
    let mut keys: Vec<String> = host
        .list_prefix("kv/")
        .expect("list kv")
        .into_iter()
        .map(|entry| entry.key())
        .collect();
    keys.sort();
    (refs, keys)
}

/// The one summary this change has, looked up by id.
fn summary_of(host: &dyn Host, id: &ChangeId) -> gitiup_host::change::ChangeSummary {
    let catalog = change::list_changes(host).expect("list");
    catalog
        .changes
        .iter()
        .find(|change| change.change_id == *id)
        .expect("listed")
        .clone()
}

// ---------------------------------------------------------------------------
// the merge that works
// ---------------------------------------------------------------------------

#[test]
fn a_merge_is_a_cas_move_of_the_branch_and_then_its_own_record() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        let outcome = change::merge(host, &owner.request(&record, Ancestry::FastForward))
            .unwrap_or_else(|e| panic!("merge: {e}"));

        // Step 6 happened: the branch moved from the base the author signed to the head.
        assert_eq!(
            branch(host),
            Some(oid(HEAD_TWO)),
            "the merge is a move of the branch, and that is the fact it had to write"
        );
        assert_eq!(outcome.plan.from, oid(BASE_OID));
        assert_eq!(outcome.plan.to, oid(HEAD_TWO));
        assert!(!outcome.plan.via_forge, "gitiup made this move itself");
        assert!(outcome.moved, "this call is the one that moved it");

        // Step 7 happened too: a record of itself, so a later clone can answer "why is
        // this commit here".
        let merged = merged_record(host, &record.change_id);
        assert_eq!(
            merged.change_digest,
            record.change_digest().expect("a digest"),
            "a merge record names the attempt it merged, by the digest that never moves"
        );
        assert_eq!(merged.attempt, 0);
        assert_eq!(merged.change_id, record.change_id);
        assert_eq!(merged.base.branch, BASE_REF);
        assert_eq!(merged.base.from, BASE_OID);
        assert_eq!(merged.base.to, HEAD_TWO);
        assert_eq!(merged.via, "store");
        assert!(
            merged.proofs.is_empty(),
            "nothing was cited, and the record says so"
        );
        assert!(
            merged.merged_at_us > 0,
            "the merge record is ADR-0001 D6's trusted moment, so it needs a moment"
        );
        merged
            .verify()
            .expect("the record re-hashes, re-derives and re-verifies");
        assert_eq!(
            merged.author.key_id,
            author("owner").key_id,
            "the merger signs the merge: `author` means whoever signed this record"
        );
        assert_eq!(
            outcome.record_digest,
            merged.digest().expect("a digest"),
            "the kv key is the hash of what was stored"
        );
        assert!(outcome.plan.kv.starts_with("kv/merge/"));
        assert_eq!(
            host.get(&outcome.record_digest)
                .expect("read the record")
                .expect("the store has it")
                .len(),
            outcome.size as usize,
            "and the bytes it filed are the bytes it signed"
        );

        // And the state is derived, not remembered: merged is a ref.
        let summary = summary_of(host, &record.change_id);
        assert_eq!(summary.state, State::Merged);
        assert_eq!(summary.merged, Some(outcome.record_digest));
        assert!(
            change::unrecorded_merge(host, &summary)
                .expect("checked")
                .is_none(),
            "a merge with its record is not the failure window"
        );
    });
}

#[test]
fn a_merge_cites_proofs_as_digests_and_pins_them() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let proof = host
            .put_cas(
                &Namespace::ATTESTATION,
                b"an attestation this merge believed",
            )
            .expect("file the proof");
        let key = fixture_key("owner");
        let request = change::MergeRequest::new(&record, &key, author("owner"))
            .with_ancestry(Ancestry::FastForward)
            .with_proof(format!("sha256:{}", proof.hex()));
        let outcome = change::merge(host, &request).expect("merge with a proof");
        assert_eq!(outcome.proofs_pinned, 1);
        assert_eq!(
            merged_record(host, &record.change_id).proofs,
            vec![format!("sha256:{}", proof.hex())],
            "digests, in the order believed — never copies of the bytes"
        );

        // The gap ADR-0003 D8 names: a digest inside a record is not a ref, so retention
        // cannot see it unless the merge says so. `attest gc` reads exactly this map.
        let pins = change::proof_pins(host).expect("pins");
        assert!(
            pins.contains_key(&proof),
            "a cited proof must survive retention, or the merge cannot be audited later"
        );
        assert!(
            pins[&proof].contains(record.change_id.as_str()),
            "and a pin says who owes it: {:?}",
            pins[&proof]
        );
    });
}

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

#[test]
fn a_stale_base_is_refused_naming_both_oids() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        // Someone else merged a change first. This one is now stale.
        move_branch(host, BASE_OID, HEAD_THREE);

        let error = change::merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("a stale base is a refusal");
        assert_eq!(error.exit_code(), 6, "{error}");
        let text = error.message();
        assert!(
            text.contains(bare(BASE_OID)) && text.contains(bare(HEAD_THREE)),
            "both oids have to be in the message or it is not actionable: {text}"
        );
        assert!(
            text.contains(BASE_REF),
            "the sentence has to say which ref was compared: {text}"
        );
        assert!(
            error.hint().unwrap_or_default().contains("pull first"),
            "the only useful advice is the hint: {:?}",
            error.hint()
        );
        assert_eq!(
            branch(host),
            Some(oid(HEAD_THREE)),
            "and the branch is exactly where whoever moved it left it"
        );
        assert!(
            host.get_ref(&change::merged_ref(&record.change_id))
                .expect("read")
                .is_none(),
            "a refused merge writes no record either"
        );
    });
}

#[test]
fn an_ancestry_the_caller_cannot_prove_is_a_refusal_not_a_guess() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let before = fingerprint(host);
        let owner = Owner::new();
        for (ancestry, word) in [
            (Ancestry::Diverged, "fast-forward"),
            (
                Ancestry::Unknown("the objects are not here".to_string()),
                "ancestor",
            ),
        ] {
            let error = change::merge(host, &owner.request(&record, ancestry.clone()))
                .expect_err("a merge may not assume the history");
            assert_eq!(error.exit_code(), 6, "{error}");
            assert!(
                error.message().contains(word) || error.hint().unwrap_or_default().contains(word),
                "the refusal should name what was missing ({word}): {error}"
            );
        }
        assert_eq!(
            fingerprint(host),
            before,
            "a refusal writes nothing, in either direction"
        );
    });
}

#[test]
fn a_change_cannot_be_merged_twice() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        change::merge(host, &owner.request(&record, Ancestry::FastForward)).expect("first merge");
        let error = change::merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("a change is merged exactly once");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(error.is_conflict(), "{error}");
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("un-doing a merge is a new change"),
            "{error}"
        );
    });
}

#[test]
fn an_abandoned_change_is_not_merged_either() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        let abandon = AbandonRecord {
            change_digest: record.change_digest().expect("a digest"),
            change_id: record.change_id.clone(),
            attempt: 0,
            abandoned_at_us: 1_764_674_043_000_000,
            reason: "withdrawn".to_string(),
            note: None,
            author: author("ada"),
            schema_version: 1,
            record_type: gitiup_host::change::ABANDON_TYPE.to_string(),
            signatures: Vec::new(),
            annotations: None,
        }
        .sign(&fixture_key("ada"))
        .expect("a signed abandon record");
        change::publish_abandon(host, &abandon, Actor::from("ada")).expect("abandon");

        let error = change::merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("closed is closed");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("a new change against the new base"),
            "{error}"
        );
    });
}

#[test]
fn a_store_that_refuses_is_passed_through_unedited() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        // The owner's branch, and a credential that is not the owner's.
        let store = Denied { inner: host };
        let error = change::merge(&store, &owner.request(&record, Ancestry::FastForward))
            .expect_err("the store refuses");
        assert_eq!(
            error.kind(),
            HostErrorKind::PermissionDenied,
            "the store said no, and that is the answer: {error}"
        );
        assert!(error.is_denied());
        assert_eq!(
            error.exit_code(),
            3,
            "a store refusal keeps the store's own code, not a generic 6"
        );
        assert!(
            error.message().starts_with("not allowed to"),
            "the store's sentence, not a rewrite of it: {}",
            error.message()
        );
        assert!(
            error.message().contains("refs/heads/main"),
            "and it still names what was refused: {error}"
        );
        assert!(
            store
                .inner
                .get_ref(&change::merged_ref(&record.change_id))
                .expect("read")
                .is_none(),
            "a denied merge leaves no record behind either"
        );
    });
}

#[test]
fn a_store_without_cas_is_refused_rather_than_force_pushed() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        let store = NoCas { inner: host };
        let error = change::merge(&store, &owner.request(&record, Ancestry::FastForward))
            .expect_err("no lease, no merge");
        assert_eq!(error.kind(), HostErrorKind::UnsupportedCas, "{error}");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(error.to_string().contains("compare-and-swap"), "{error}");
        assert_eq!(
            branch(store.inner),
            Some(oid(BASE_OID)),
            "nothing moved: an unconditional write is exactly what this host must not do"
        );
    });
}

// ---------------------------------------------------------------------------
// the dry plan, which touches nothing
// ---------------------------------------------------------------------------

#[test]
fn a_plan_names_the_move_without_making_it() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        let before = fingerprint(host);
        let plan = change::plan_merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect("the plan");
        assert_eq!(plan.branch.as_str(), BASE_REF);
        assert_eq!(plan.from, oid(BASE_OID));
        assert_eq!(plan.to, oid(HEAD_TWO));
        assert_eq!(plan.store_oid, oid(BASE_OID), "the store was read fresh");
        assert_eq!(plan.attempt, 0);
        assert_eq!(plan.change_digest, record.change_digest().expect("digest"));
        assert!(
            !plan.base_overridden,
            "the CAS expects what the author signed"
        );
        assert!(!plan.via_forge && !plan.reconciled);
        assert_eq!(
            plan.kv, "kv/merge",
            "a dry run cannot know the key: it is the hash of bytes that do not exist yet"
        );
        assert!(plan.summary().contains("refs/heads/main"));
        assert_eq!(
            fingerprint(host),
            before,
            "a plan is a read: same refs, same objects, nothing filed"
        );

        // The comparison a real merge makes still happens in a plan: a dry run that
        // claims a merge is available when the base has moved is worse than none.
        move_branch(host, BASE_OID, HEAD_THREE);
        let stale = change::plan_merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("a stale base is stale in a dry run too");
        assert_eq!(stale.exit_code(), 6, "{stale}");
    });
}

#[test]
fn an_expected_oid_overrides_the_record_and_says_so() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        // The branch moved on, and the owner says so out loud: the CAS is against the oid
        // in front of them, and the record keeps the author's own fact visible.
        move_branch(host, BASE_OID, HEAD_THREE);
        let key = fixture_key("owner");
        let request = change::MergeRequest::new(&record, &key, author("owner"))
            .with_ancestry(Ancestry::FastForward)
            .with_expected(oid(HEAD_THREE));
        let plan = change::plan_merge(host, &request).expect("plan");
        assert!(plan.base_overridden);
        assert_eq!(plan.from, oid(HEAD_THREE));
        assert_eq!(plan.signed_base, BASE_OID);
        assert!(
            plan.notes
                .iter()
                .any(|note| note.contains("named by the caller")),
            "the override is said, not assumed: {:?}",
            plan.notes
        );
        let outcome = change::merge(host, &request).expect("merge onto what is there");
        assert_eq!(outcome.plan.from, oid(HEAD_THREE));
        assert_eq!(
            merged_record(host, &record.change_id).base.from,
            HEAD_THREE,
            "and the record says which point the CAS really expected"
        );
    });
}

// ---------------------------------------------------------------------------
// D8's failure window: the move happened and the record did not
// ---------------------------------------------------------------------------

#[test]
fn a_move_without_its_record_is_detected_and_reconcilable() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        // The crash: step 6 landed and step 7 did not. Spelled here as a plain branch
        // move, because that is exactly the state the store would be holding.
        move_branch(host, BASE_OID, HEAD_TWO);

        let summary = summary_of(host, &record.change_id);
        assert_eq!(summary.state, State::Open, "with no ref, it is not merged");
        let found = change::unrecorded_merge(host, &summary)
            .expect("checked")
            .expect("the silence is detectable");
        assert_eq!(found.attempt, 0);
        assert_eq!(found.head, HEAD_TWO);
        assert_eq!(found.store_oid, oid(HEAD_TWO));

        // Merging now is refused — there is nothing left to merge — and points at the retry.
        let error = change::merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("the branch already moved");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(
            error.hint().unwrap_or_default().contains("reconcile"),
            "the refusal carries the retry: {:?}",
            error.hint()
        );

        let before = fingerprint(host);
        let outcome = change::record_merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect("write the record for the move the store has");
        assert!(!outcome.moved, "this call moved nothing");
        assert!(outcome.plan.reconciled);
        assert_eq!(
            branch(host),
            Some(oid(HEAD_TWO)),
            "a reconcile leaves the branch alone"
        );
        let merged = merged_record(host, &record.change_id);
        assert_eq!(
            merged.base.from, BASE_OID,
            "from is still the author's base"
        );
        assert_eq!(merged.base.to, HEAD_TWO);
        assert_eq!(merged.via, "store");
        assert_eq!(
            host.list_refs(&RefQuery::all()).expect("refs").len(),
            before.0.len() + 1,
            "one ref added: the merged advertisement, nothing else"
        );
        let summary = summary_of(host, &record.change_id);
        assert_eq!(summary.state, State::Merged);
        assert!(
            change::unrecorded_merge(host, &summary)
                .expect("checked")
                .is_none(),
            "and the flag is gone once the record exists"
        );
    });
}

#[test]
fn reconcile_refuses_when_the_branch_has_not_moved() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        let error = change::record_merge(host, &owner.request(&record, Ancestry::FastForward))
            .expect_err("there is no fact to record");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(
            error.hint().unwrap_or_default().contains("change merge"),
            "{error}"
        );
        assert!(
            host.get_ref(&change::merged_ref(&record.change_id))
                .expect("read")
                .is_none()
        );
    });
}

#[test]
fn a_forge_move_is_recorded_where_the_forge_landed_it() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        // The forge merged with its own merge commit: the branch tip is a commit that is
        // not the change's head, and the record must name what the store really holds.
        move_branch(host, BASE_OID, HEAD_THREE);
        let key = fixture_key("owner");
        let request = change::MergeRequest::new(&record, &key, author("owner"))
            .via_forge()
            .with_landing(oid(HEAD_THREE));
        let outcome = change::record_merge(host, &request).expect("record the forge's merge");
        assert_eq!(outcome.plan.via, Via::Forge);
        assert!(outcome.plan.via_forge && outcome.plan.reconciled);
        let merged = merged_record(host, &record.change_id);
        assert_eq!(merged.via, "forge", "gitiup did not make this move");
        assert_eq!(
            merged.base.to, HEAD_THREE,
            "it names the commit that landed"
        );
        assert_eq!(merged.base.from, BASE_OID);
    });
}

#[test]
fn a_landing_the_store_does_not_confirm_is_refused() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        move_branch(host, BASE_OID, HEAD_THREE);
        let key = fixture_key("owner");
        // The forge claims a commit the store does not have there. Two sources disagree
        // and neither is the merge record's author: refuse.
        let request = change::MergeRequest::new(&record, &key, author("owner"))
            .via_forge()
            .with_landing(oid(HEAD_TWO));
        let error = change::record_merge(host, &request).expect_err("a lie about where it landed");
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(error.message().contains("the forge said"), "{error}");
    });
}

// ---------------------------------------------------------------------------
// what the derived state says
// ---------------------------------------------------------------------------

#[test]
fn a_merged_change_is_merged_for_every_reader_of_the_catalog() {
    each_store(|host| {
        let record = publish(host, "ada", HEAD_TWO);
        let owner = Owner::new();
        assert_eq!(summary_of(host, &record.change_id).state, State::Open);
        let outcome =
            change::merge(host, &owner.request(&record, Ancestry::FastForward)).expect("merge");
        let summary = summary_of(host, &record.change_id);
        assert_eq!(
            summary.merged,
            Some(outcome.record_digest),
            "the derived state carries the record it is made of"
        );
        assert_eq!(summary.state, State::Merged);
        assert!(
            summary.head_tracks_newest,
            "and nothing about its attempts went stale"
        );
    });
}

// ---------------------------------------------------------------------------
// the two stores that have to misbehave
// ---------------------------------------------------------------------------

/// A store that lets a contributor write `refs/changes/**` and refuses `refs/heads/**`:
/// what "you are not the owner" means on a host that enforces it.
struct Denied<'a> {
    inner: &'a dyn Host,
}

impl Denied<'_> {
    fn check(&self, update: &RefUpdate) -> Result<(), HostError> {
        if update.name.as_str().starts_with("refs/heads/") {
            return Err(HostError::denied(format!(
                "update {} (this credential may write refs/changes/** only)",
                update.name
            )));
        }
        Ok(())
    }
}

impl RefStore for Denied<'_> {
    fn list_refs(&self, query: &RefQuery) -> Result<Vec<Ref>, HostError> {
        self.inner.list_refs(query)
    }

    fn get_ref(&self, name: &RefName) -> Result<Option<Ref>, HostError> {
        self.inner.get_ref(name)
    }

    fn update_ref_cas(&self, update: &RefUpdate) -> Result<Ref, HostError> {
        self.check(update)?;
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

impl BlobStore for Denied<'_> {
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

impl Host for Denied<'_> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

/// A store with no lease at all: a bucket without conditional writes, a git host whose
/// `--force-with-lease` is unavailable. It must be refused, never force-pushed through.
struct NoCas<'a> {
    inner: &'a dyn Host,
}

impl RefStore for NoCas<'_> {
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

impl BlobStore for NoCas<'_> {
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

impl Host for NoCas<'_> {
    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.capabilities();
        caps.cas = false;
        caps
    }

    fn describe(&self) -> HostInfo {
        self.inner.describe()
    }
}

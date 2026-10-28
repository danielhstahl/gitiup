//! The conformance bodies: one registry, every host measured against it.
//!
//! Five of these are the transport-agnostic bodies that already live in
//! [`gitiup_host::conformance`] — they are *re-used*, not copied, so there is one
//! implementation of each and the host's own test file cannot drift from the
//! suite. The rest are the edges the shared suite was asked to cover explicitly:
//! an empty store, a deleted ref, a pack big enough to matter, a listing wide
//! enough to page, credentials that were refused, and a host that cannot do
//! compare-and-swap.
//!
//! A body asserts; it does not return `Result`. That is what makes them readable,
//! and it is why [`crate::runner`] runs each one in its own `#[test]` (so the
//! failure message and line are the assertion's own) and also offers a
//! catch-everything report for callers that want the whole list at once.

use std::collections::{BTreeMap, BTreeSet};

use gitiup_host::conformance;
use gitiup_host::{
    BlobEntry, Capability, Expect, Host, HostError, HostErrorExt, HostErrorKind, HostKind,
    Namespace, Oid, Pack, PackFormat, PackRequest, RefDeletion, RefName, RefQuery, RefUpdate,
};

use crate::registration::Denial;
use crate::registration::Knobs;

/// Which slot of a [`crate::Registration`] a body needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One fresh store.
    Single,
    /// Two independent fresh stores.
    Pair,
    /// The registration's `denied` variant.
    Denied,
    /// The registration's `degraded` variant.
    Degraded,
}

/// What a body is handed.
pub struct Ctx<'a> {
    /// A fresh store (every `Single` and `Pair` body gets its own). Absent only
    /// for the [`Shape::Denied`] body when the host refused to be built at all.
    pub host: Option<&'a dyn Host>,
    /// A second, independent store — for `Pair`.
    pub peer: Option<&'a dyn Host>,
    /// The refused-credentials variant — for `Denied`.
    pub denial: Option<&'a Denial>,
    /// The `cas = false` variant — for `Degraded`.
    pub degraded: Option<&'a dyn Host>,
    /// How heavy the size-shaped bodies should be.
    pub knobs: Knobs,
}

impl Ctx<'_> {
    /// The store under test, or a clear failure if the runner mis-wired shapes.
    pub fn host(&self) -> &dyn Host {
        self.host
            .expect("runner: body needs a host and none was built")
    }

    /// The second store, or a clear failure if the runner mis-wired the shapes.
    pub fn peer(&self) -> &dyn Host {
        self.peer.expect("runner: pair body without a second host")
    }

    /// The denial, or a clear failure.
    pub fn denial(&self) -> &Denial {
        self.denial.expect("runner: denied body without a denial")
    }

    /// The degraded host, or a clear failure.
    pub fn degraded(&self) -> &dyn Host {
        self.degraded
            .expect("runner: degraded body without a degraded host")
    }
}

/// One body of the suite.
pub struct Body {
    /// The name, which is also the `#[test]` name and the key in a registration's
    /// `skips` list.
    pub name: &'static str,
    /// What it needs.
    pub shape: Shape,
    /// Whether the assertions depend on compare-and-swap being available.
    ///
    /// A host that truthfully reports `cas = false` is not failing these bodies;
    /// the runner says so out loud instead of pretending they passed.
    pub requires_cas: bool,
    /// One line on what it proves, for the report and for `--nocapture` CI logs.
    pub note: &'static str,
    /// The assertion itself.
    pub run: fn(&Ctx<'_>),
}

// ---------------------------------------------------------------------------
// The bodies.
// ---------------------------------------------------------------------------

/// Blobs round-trip: one digest per byte string, listings work, bytes come back
/// exactly as written.
fn blobs_round_trip(ctx: &Ctx<'_>) {
    conformance::blobs_round_trip(ctx.host());
}

/// Refs round-trip: write with a promise, read back, list with a filter.
fn refs_round_trip(ctx: &Ctx<'_>) {
    conformance::refs_round_trip(ctx.host());
}

/// CAS conflicts carry both sides and move nothing.
fn cas_conflicts_are_reported(ctx: &Ctx<'_>) {
    conformance::cas_conflicts_are_reported(ctx.host());
}

/// A batch whose last update cannot match applies nothing at all.
fn multi_ref_writes_are_all_or_nothing(ctx: &Ctx<'_>) {
    conformance::multi_ref_writes_are_all_or_nothing(ctx.host());
}

/// A pack written here is readable there, byte for byte, by digest and by want.
fn pack_round_trip_between_two_hosts(ctx: &Ctx<'_>) {
    conformance::pack_round_trip(ctx.host(), ctx.peer());
}

/// The host describes itself and never promises what it cannot do.
fn describe_and_capabilities(ctx: &Ctx<'_>) {
    conformance::describe_and_capabilities(ctx.host());
}

/// An empty store is not an error, and the first write is not special.
///
/// This is the state a repository is in the first time gitiup sees it, and the
/// state where a host is most likely to invent a failure: a listing of nothing, a
/// read of nothing, and then the write that has to work.
fn a_fresh_store_is_empty_then_writable(ctx: &Ctx<'_>) {
    let host = ctx.host();

    assert!(
        host.list_refs(&RefQuery::all())
            .expect("listing an empty store is not an error")
            .is_empty(),
        "a fresh store must advertise no refs"
    );
    assert!(
        host.list_prefix(Namespace::ANY)
            .expect("listing an empty store is not an error")
            .is_empty(),
        "a fresh store must hold no blobs"
    );

    let ghost = Oid::hash_bytes(b"never written by anyone");
    assert!(
        host.get_ref(&RefName::branch("main").unwrap())
            .unwrap()
            .is_none()
    );
    assert!(
        host.get(&ghost).unwrap().is_none(),
        "a missing blob is None"
    );
    assert!(!host.exists(&ghost).unwrap(), "and does not exist");
    let err = host
        .fetch_pack(&PackRequest::new([ghost]))
        .expect_err("a want nobody stored is NotFound, not an empty pack");
    assert_eq!(err.kind(), HostErrorKind::NotFound, "{err}");

    // The first write is an ordinary write.
    let oid = host
        .put_cas(&Namespace::RECORD, b"{\"first\":true}")
        .expect("the first blob");
    let main = RefName::branch("main").unwrap();
    host.update_ref_cas(&RefUpdate::create(main.clone(), oid).with_message("first ref"))
        .expect("the first ref");
    assert_eq!(host.get_ref(&main).unwrap().unwrap().oid, oid);
    assert_eq!(
        host.list_refs(&RefQuery::all())
            .expect("list after the first write")
            .len(),
        1,
        "one ref written, one ref advertised"
    );
    assert_eq!(host.list(&Namespace::RECORD).unwrap().len(), 1);
    assert_eq!(host.get(&oid).unwrap().unwrap(), b"{\"first\":true}");
}

/// Deleting a ref is a compare-and-swap too, and the name becomes free again.
///
/// Deletion is where a lazy host cheats: "delete" that succeeds while the ref
/// stays, or a delete that no-ops on a stale expectation so a merge closes a
/// change somebody else just moved. And on a bucket a deleted ref still occupies
/// its key, so re-creating it is a race like any other create.
fn ref_deletion_is_conditional(ctx: &Ctx<'_>) {
    let host = ctx.host();
    let keep = host
        .put_cas(&Namespace::RECORD, b"{\"id\":\"keep\"}")
        .unwrap();
    let other = host
        .put_cas(&Namespace::RECORD, b"{\"id\":\"other\"}")
        .unwrap();
    let name = RefName::change_head("del-1").unwrap();
    host.update_ref_cas(&RefUpdate::create(name.clone(), keep))
        .expect("create the ref");

    // A delete that names the wrong value is a conflict, and it deletes nothing.
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(other)))
        .expect_err("the ref does not hold `other`");
    assert!(err.is_conflict(), "{err}");
    match &err {
        HostError::Conflict(conflict) => {
            assert_eq!(conflict.expected, Some(other));
            assert_eq!(conflict.found, Some(keep));
        }
        other => panic!("expected a conflict carrying both sides, got {other:?}"),
    }
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, keep);

    // "Must not exist" is also an expectation, and it is not met here.
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Absent))
        .expect_err("the ref exists, so Absent cannot hold");
    assert!(err.is_conflict(), "{err}");
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, keep);

    // The honest delete.
    host.delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(keep)))
        .expect("delete with the value that is really there");
    assert!(
        host.get_ref(&name).unwrap().is_none(),
        "a deleted ref must not be readable"
    );
    let listed = host.list_refs(&RefQuery::all()).expect("list after delete");
    assert!(
        listed.iter().all(|reference| reference.name != name),
        "a deleted ref must not be advertised: {listed:?}"
    );
    assert!(
        host.list_refs(&RefQuery::prefix("refs/changes"))
            .expect("prefix listing after delete")
            .is_empty(),
        "the namespace listing must catch up with the delete"
    );

    // Deleting it again, still naming a value, is NotFound: the thing you meant
    // to take away is not there.
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(keep)))
        .expect_err("a second conditional delete reports the absence");
    assert_eq!(err.kind(), HostErrorKind::NotFound, "{err}");
    // Unguarded, it is idempotent: there is nothing to take away.
    host.delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Any))
        .expect("an unguarded delete of an absent ref succeeds");

    // The name is free: two clones pushing the same branch after a delete is an
    // ordinary create-only race, and this is the create side of it.
    host.update_ref_cas(&RefUpdate::create(name.clone(), other))
        .expect("re-creating a deleted ref");
    assert_eq!(host.get_ref(&name).unwrap().unwrap().oid, other);
    host.delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Any))
        .expect("unguarded delete of a live ref");
    assert!(host.get_ref(&name).unwrap().is_none());
}

/// A pack big enough to matter survives whole.
///
/// Small packs hide truncation, partial uploads and buffering bugs: they fit in
/// one request and one page of memory. CI raises the size past a bucket's
/// multipart threshold, which is where the interesting failures live.
fn a_huge_pack_round_trips_intact(ctx: &Ctx<'_>) {
    let host = ctx.host();
    // Stay inside the format's own limits (64 MiB per object); the body is about
    // transport fidelity, not about re-testing the codec's ceilings.
    let total = ctx.knobs.pack_bytes.clamp(64 * 1024, 48 * 1024 * 1024);
    let thirds = [
        total / 2 + total % 2,
        total / 6,
        total - (total / 2 + total % 2) - total / 6,
    ];
    let namespaces = [
        Namespace::ATTESTATION.clone(),
        Namespace::RECORD.clone(),
        Namespace::CHANGE.clone(),
    ];
    let objects: Vec<(Namespace, Vec<u8>)> = thirds
        .iter()
        .enumerate()
        .map(|(idx, size)| (namespaces[idx].clone(), pseudo_bytes(*size, idx as u8 + 1)))
        .collect();
    let total_bytes: usize = objects.iter().map(|(_, body)| body.len()).sum();
    assert_eq!(total_bytes, total, "the sizes must add up");

    let pack = Pack::from_raw_objects(objects.clone()).expect("build the pack");
    let pack_oid = host.put_pack(&pack).expect("write a large pack");
    assert_eq!(
        pack_oid,
        pack.oid(),
        "a pack is addressed by its own digest"
    );

    // Back by the pack digest, and then by the digests of the objects inside it.
    // Both compare digests rather than positions: a host serves objects in whatever
    // order its storage finds them (a git host answers from its own object
    // database, which has no interesting order), and the contract is that every
    // object arrives with the namespace it was written under and the bytes its
    // digest names.
    let wants: Vec<Oid> = objects
        .iter()
        .map(|(_, body)| Oid::hash_bytes(body))
        .collect();
    let by_pack = host
        .fetch_pack(&PackRequest::new([pack_oid]))
        .expect("fetch the pack back");
    same_objects("fetched by pack digest", &objects, &by_pack);
    let by_want = host
        .fetch_pack(&PackRequest::new(wants.clone()))
        .expect("fetch the objects by digest");
    same_objects("fetched by object digest", &objects, &by_want);

    // The host that holds it still answers ordinary reads afterwards: a big write
    // must not have wedged anything.
    let small = host
        .put_cas(&Namespace::RECORD, b"after the big one")
        .expect("ordinary writes still work");
    assert_eq!(
        host.get(&small).unwrap().unwrap(),
        b"after the big one",
        "and read back"
    );
}

/// Listings are complete across pages, and a filter never lies about what it kept.
///
/// Every backend paginates somewhere: a bucket answers LIST a thousand keys at a
/// time, a directory walk has its own order, a git host rebuilds a listing from
/// commit chains. A host that returns the first page and calls it a day looks
/// exactly like a correct one until the store grows past one page — and a missing
/// record is a missing attestation.
fn listings_are_complete_across_pages(ctx: &Ctx<'_>) {
    let host = ctx.host();
    let count = ctx.knobs.list_count.max(2);
    let namespace = Namespace::RECORD;

    let mut written: BTreeSet<String> = BTreeSet::new();
    for index in 0..count {
        let body = format!("{{\"index\":{index}}}");
        let oid = host
            .put_cas(&namespace, body.as_bytes())
            .expect("put a record");
        assert!(written.insert(oid.hex().to_string()), "digests must differ");
    }

    let listed = host.list(&namespace).expect("list the namespace");
    let keys: BTreeSet<String> = listed
        .iter()
        .map(|entry| entry.oid.hex().to_string())
        .collect();
    assert_eq!(
        keys.len(),
        written.len(),
        "listing found {} of {} records it wrote ({} entries, so a page was dropped)",
        keys.len(),
        written.len(),
        listed.len()
    );
    assert_eq!(keys, written, "the listing is exactly what was written");
    assert!(
        listed
            .iter()
            .all(|entry| entry.key().starts_with("record/")),
        "keys are namespaced: {:?}",
        listed.first().map(BlobEntry::key)
    );
    assert!(
        listed.iter().all(|entry| entry.size > 0 && entry.size < 64),
        "a listing reports the size of each record: {:?}",
        listed.first()
    );

    // The same set through the pattern interface.
    let by_pattern = host
        .list_prefix(namespace.as_str())
        .expect("a bare namespace is a pattern");
    assert_eq!(
        by_pattern.len(),
        written.len(),
        "pattern listing paginates too"
    );
    assert_eq!(
        host.list_prefix(Namespace::ANY).unwrap().len(),
        written.len()
    );

    // Every one-digit hex bucket holds exactly its own records, and the buckets
    // add up to the whole store: a filter that drops a page is caught here, and
    // so is one that returns rows belonging to a neighbour.
    let mut bucketed = 0usize;
    for digit in "0123456789abcdef".chars() {
        let bucket = host
            .list_prefix(&format!("{namespace}/{digit}"))
            .expect("hex prefix listing");
        for entry in &bucket {
            assert!(
                entry.oid.hex().starts_with(digit),
                "{digit} bucket contains {}",
                entry.oid.hex()
            );
        }
        bucketed += bucket.len();
    }
    assert_eq!(
        bucketed,
        written.len(),
        "the hex buckets must cover the store exactly once"
    );

    // Namespaces do not leak into each other, and a longer prefix narrows.
    let attestation = host
        .put_cas(&Namespace::ATTESTATION, b"{\"attested\":true}")
        .expect("a record in another namespace");
    assert_eq!(host.list(&namespace).unwrap().len(), written.len());
    assert_eq!(host.list(&Namespace::ATTESTATION).unwrap().len(), 1);
    assert_eq!(host.list_prefix("attestation").unwrap()[0].oid, attestation);
    assert_eq!(
        host.list_prefix(&format!("attestation/{}", &attestation.hex()[..8]))
            .unwrap()
            .len(),
        1,
        "a long hex prefix still finds the record"
    );
    assert!(
        host.list_prefix(&format!("record/{}", "f".repeat(40)))
            .expect("a hex prefix that matches nothing is empty, not an error")
            .is_empty()
    );

    // Ref listings paginate the same way: a fetch must see every branch, not the
    // first page of them.
    let refs_written = ctx.knobs.ref_count.max(2);
    let target = written.iter().next().expect("at least one blob").clone();
    let target = Oid::from_hex(&target).expect("digest we just wrote");
    let mut names = Vec::new();
    for index in 0..refs_written {
        let name = RefName::branch(&format!("page{:04}", index)).expect("a valid branch name");
        host.update_ref_cas(&RefUpdate::create(name.clone(), target))
            .expect("publish a branch");
        names.push(name);
    }
    let advertised = host.list_refs(&RefQuery::all()).expect("list every ref");
    assert_eq!(
        advertised.len(),
        refs_written,
        "a paged ref listing came back short ({} of {})",
        advertised.len(),
        refs_written
    );
    let seen: BTreeSet<String> = advertised
        .iter()
        .map(|reference| reference.name.as_str().to_string())
        .collect();
    for name in &names {
        assert!(seen.contains(name.as_str()), "{name} was not advertised");
    }
    // A namespace prefix narrows to what is under it, and nothing else. Whether a
    // *complete* ref name is also its own prefix is the one thing hosts genuinely
    // differ on — a bucket stores a ref at a key and a prefix ends at a component
    // boundary, while a directory host matches names as strings — so the suite
    // pins the promise every caller can rely on instead of inventing a third
    // answer: the result is a subset of the namespace, and the namespace itself
    // is complete.
    let one_namespace = host
        .list_refs(&RefQuery::prefix("refs/heads"))
        .expect("a namespace prefix lists");
    assert_eq!(
        one_namespace.len(),
        refs_written,
        "a namespace prefix must list every ref under it ({} of {})",
        one_namespace.len(),
        refs_written
    );
    let narrow = host
        .list_refs(&RefQuery::prefix("refs/heads/page0001"))
        .expect("a narrower prefix is not an error");
    assert!(
        narrow.len() <= 1
            && narrow
                .iter()
                .all(|reference| reference.name.as_str() == "refs/heads/page0001"),
        "a prefix query returned refs outside the prefix: {narrow:?}"
    );
    assert!(
        host.list_refs(&RefQuery::prefix("refs/changes"))
            .expect("an empty namespace lists empty, not everything")
            .is_empty()
    );
}

/// Threads moving one ref at once never lose a change or corrupt the store.
fn concurrent_ref_writers_never_lose_one(ctx: &Ctx<'_>) {
    let host = ctx.host();
    let base = host.put_cas(&Namespace::RECORD, b"base").unwrap();
    let name = RefName::branch("contended").unwrap();
    host.cas_ref(&name, None, base).expect("create the ref");

    enum Outcome {
        Won(Oid),
        Retried(HostError),
        Other(HostError),
    }

    let writers = ctx.knobs.writers.max(2);
    let outcomes: Vec<Outcome> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..writers)
            .map(|index| {
                let name = name.clone();
                scope.spawn(move || {
                    let mine = host
                        .put_cas(&Namespace::RECORD, format!("worker-{index}").as_bytes())
                        .expect("store this writer's record");
                    let seen = host
                        .get_ref(&name)
                        .expect("read the ref")
                        .expect("the ref is there")
                        .oid;
                    match host.cas_ref(&name, Some(seen), mine) {
                        Ok(_) => Outcome::Won(mine),
                        // A conflict is the honest answer to losing a race; a
                        // transport flinch (a lock, a transient 5xx) is allowed
                        // too because it is retryable. What is not allowed is
                        // anything else.
                        Err(err) if err.is_conflict() || err.is_retryable() => {
                            Outcome::Retried(err)
                        }
                        Err(err) => Outcome::Other(err),
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("writer thread"))
            .collect()
    });

    let impossible: Vec<String> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Other(err) => Some(err.to_string()),
            _ => None,
        })
        .collect();
    let flinched: Vec<String> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Retried(err) => Some(err.to_string()),
            _ => None,
        })
        .collect();
    assert!(
        impossible.is_empty(),
        "a contended ref write failed for a reason nobody can act on: {impossible:?} \
         (retryable refusals, which were allowed: {flinched:?})"
    );
    let won: Vec<Oid> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Won(oid) => Some(*oid),
            _ => None,
        })
        .collect();
    assert!(
        !won.is_empty(),
        "every writer failed; at least one must land"
    );

    let final_ref = host
        .get_ref(&name)
        .unwrap()
        .expect("the ref survived the race");
    assert!(
        final_ref.oid == base || won.contains(&final_ref.oid),
        "the ref points at something no writer offered: {}",
        final_ref.oid
    );
    let content = host
        .get(&final_ref.oid)
        .unwrap()
        .unwrap_or_else(|| panic!("the ref points at {} which is not stored", final_ref.oid));
    assert!(
        String::from_utf8_lossy(&content).starts_with("worker-") || content == b"base".as_slice(),
        "the winning value must be a real record"
    );
    // Losing a race must not destroy the loser's content: every record written is
    // still readable, so a retry can rebuild from it.
    for oid in &won {
        assert!(host.exists(oid).unwrap(), "{} vanished", oid.hex());
    }
}

/// Operations this host cannot serve are refused by name, not mangled or ignored.
fn unsupported_operations_are_refused_by_name(ctx: &Ctx<'_>) {
    let host = ctx.host();

    // A malformed pattern is `Invalid`, with a hint; a pattern that simply
    // matches nothing is an empty listing.
    let err = host
        .list_prefix("")
        .expect_err("an empty pattern is not 'everything'");
    assert_eq!(err.kind(), HostErrorKind::Invalid, "{err}");
    assert!(
        err.hint().is_some(),
        "{err}: the refusal says what to write"
    );
    let err = host
        .list_prefix("record/not-hex")
        .expect_err("a digest prefix that is not hex cannot mean anything");
    assert_eq!(err.kind(), HostErrorKind::Invalid, "{err}");
    assert!(
        host.list_prefix("no-such-namespace")
            .expect("an unknown namespace lists empty")
            .is_empty()
    );

    // A pack format the host does not speak says so, and names the capability.
    // The plain-git host is the one that does speak git packfiles, so it is held
    // to the opposite promise: bad bytes are refused, not accepted.
    let bogus = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&[0, 0, 0, 2]);
        bytes.extend_from_slice(&[0, 0, 0, 1]);
        bytes.extend_from_slice(&[7u8; 20]);
        Pack::git_packfile(bytes).expect("bytes that claim to be a git packfile")
    };
    if host.kind() == HostKind::Git {
        let err = host
            .put_pack(&bogus)
            .expect_err("a corrupt git packfile must not be ingested");
        assert!(
            !err.is_unsupported(),
            "this host does serve git packfiles, so it must refuse the bytes and not \
             the format: {err}"
        );
        // Serving the format is the promise here, so the shape of the answer matters
        // more than its size: an empty want list may legitimately be answered with an
        // empty pack, but not with "this host does not do that".
        match host.fetch_pack(&PackRequest::new([]).with_format(PackFormat::GitPackfile)) {
            Ok(pack) => assert_eq!(
                pack.format,
                PackFormat::GitPackfile,
                "a host that serves git packfiles answers them as git packfiles"
            ),
            Err(err) => assert_ne!(
                err.kind(),
                HostErrorKind::UnsupportedCas,
                "this host does serve git packfiles: {err}"
            ),
        }
    } else {
        let err = host
            .put_pack(&bogus)
            .expect_err("no git object db here, so the format must be refused");
        assert!(err.is_unsupported(), "{err}");
        match &err {
            HostError::UnsupportedCas(why) => {
                assert!(
                    why.capability.contains("pack-format"),
                    "the refusal names what is missing: {}",
                    why.capability
                );
            }
            other => panic!("expected UnsupportedCas, got {other:?}"),
        }
        let err = host
            .fetch_pack(&PackRequest::new([]).with_format(PackFormat::GitPackfile))
            .expect_err("and it cannot serve that format either");
        assert!(err.is_unsupported(), "{err}");
    }

    // A ref write cannot be coaxed into something else by an odd request shape.
    let missing = Oid::hash_bytes(b"referenced but never stored");
    let name = RefName::branch("dangling").unwrap();
    let outcome = host.update_ref_cas(&RefUpdate::create(name.clone(), missing));
    match outcome {
        // Both answers are defensible: a host may check that the object exists,
        // or may take the ref on trust and let the reader discover the gap. What
        // it may not do is accept the write and pretend the object is there.
        Ok(_) => assert!(
            host.get(&missing).unwrap().is_none(),
            "the ref points at nothing, and the host must not have invented it"
        ),
        Err(err) => assert!(
            matches!(
                err.kind(),
                HostErrorKind::NotFound | HostErrorKind::Invalid | HostErrorKind::UnsupportedCas
            ),
            "an unwritable ref must be refused in the taxonomy: {err}"
        ),
    }
    let _ = host.delete_ref_cas(&RefDeletion::new(name, Expect::Any));

    // An empty batch is a no-op, not a panic and not an error nobody can act on.
    let _ = host.update_refs_cas(&[]);
}

/// Forgetting one object is answered, not dodged.
///
/// Retention has to be able to say what happened to the bytes, and there are only
/// two honest answers: they are gone, or this kind of store cannot forget a single
/// object and says so. The failure this body exists to catch is the third — a host
/// that returns `Ok` while the bytes stay, or deletes something and reports a
/// refusal — because a retention report that overstates what it deleted is how a
/// store ends up claiming it forgot signed evidence it still holds.
fn one_object_is_forgotten_or_the_refusal_says_why(ctx: &Ctx<'_>) {
    let host = ctx.host();
    let bytes = b"{\"forgotten\":true}";
    let digest = host
        .put_cas(&Namespace::ATTESTATION, bytes)
        .expect("store the object");
    assert!(host.exists(&digest).unwrap(), "and it is there to forget");

    match host.purge_cas(&digest) {
        Ok(true) => {
            assert!(
                host.get(&digest)
                    .expect("a read after a successful purge is not an error")
                    .is_none(),
                "the host said the bytes are gone, so they must not be readable"
            );
            assert!(!host.exists(&digest).unwrap(), "and must not exist");
            // Forgetting is not corruption: the name is free again, and the same
            // bytes re-store to the same digest.
            let again = host
                .put_cas(&Namespace::ATTESTATION, bytes)
                .expect("re-store after a purge");
            assert_eq!(again, digest, "a digest is not a slot number");
        }
        // "Nothing happened, and that was fine" is not a thing a purge can be: a
        // host that cannot forget answers in the taxonomy, so the caller's report
        // can say so.
        Ok(false) => panic!(
            "purge_cas reported success without removing the object; refuse with              UnsupportedCas instead, so the retention report says why"
        ),
        Err(err) => {
            assert!(
                err.is_unsupported(),
                "a purge that did not happen must be an unsupported refusal, not {err}"
            );
            assert!(
                host.get(&digest)
                    .expect("a read after a refusal is not an error")
                    .is_some(),
                "a refusal may not have deleted anything on the way to saying no"
            );
        }
    }
    // Purging what was never there is the same answer as purging it twice would be:
    // nothing to forget, said quietly.
    let absent = Oid::hash_bytes(b"nobody ever stored this");
    let _ = host.purge_cas(&absent);
}

/// Credentials that were refused come back as a refusal.
///
/// The dangerous failure mode of an expired or revoked credential is not the
/// error, it is the *shape* of the error: a host that reports `NotFound` for a
/// bucket it may not read tells the user their object is gone, and a host that
/// returns an empty listing tells them there is nothing to merge. Both are wrong
/// in the direction of a silent lie, so every entry point has to answer
/// `PermissionDenied`, and none of them may print the secret.
fn refused_credentials_are_denied_not_dropped(ctx: &Ctx<'_>) {
    let denial = ctx.denial();
    let secret = denial.secret.clone();
    let label = denial.label;

    let mut problems: Vec<String> = Vec::new();
    let mut check = |what: &str, outcome: Result<(), HostError>| match outcome {
        Ok(()) => problems.push(format!("{what} succeeded with refused credentials")),
        Err(err) => {
            denial.record(err.to_string());
            if !err.is_denied() {
                problems.push(format!(
                    "{what} answered {} ({err}) where a refusal was required",
                    err.kind().as_str()
                ));
            }
        }
    };

    match &denial.outcome {
        crate::registration::DenialOutcome::Refused { error } => {
            // Refusing at connect time is the best possible answer, as long as it
            // is a denial and not a shrug.
            assert!(
                error.is_denied(),
                "{label}: refusing to build a host is only right if it is a denial, \
                 not {} ({error})",
                error.kind().as_str()
            );
            assert!(
                error.hint().is_some(),
                "{label}: a credential refusal must say what to do about it: {error}"
            );
        }
        crate::registration::DenialOutcome::Built { session } => {
            let host: &dyn Host = session.host();
            let ghost = Oid::hash_bytes(b"irrelevant");
            check(
                "get_ref",
                host.get_ref(&RefName::branch("main").unwrap()).map(|_| ()),
            );
            check("list_refs", host.list_refs(&RefQuery::all()).map(|_| ()));
            check("get", host.get(&ghost).map(|_| ()));
            check("exists", host.exists(&ghost).map(|_| ()));
            check("list_prefix", host.list_prefix(Namespace::ANY).map(|_| ()));
            check("list", host.list(&Namespace::RECORD).map(|_| ()));
            check(
                "put_cas",
                host.put_cas(&Namespace::RECORD, b"refused").map(|_| ()),
            );
            check(
                "update_ref_cas",
                host.update_ref_cas(&RefUpdate::create(RefName::branch("nope").unwrap(), ghost))
                    .map(|_| ()),
            );
            check(
                "update_refs_cas",
                host.update_refs_cas(&[RefUpdate::create(RefName::branch("nope").unwrap(), ghost)])
                    .map(|_| ()),
            );
            check(
                "delete_ref_cas",
                host.delete_ref_cas(&RefDeletion::new(
                    RefName::branch("nope").unwrap(),
                    Expect::Any,
                ))
                .map(|_| ()),
            );
            check(
                "fetch_pack",
                host.fetch_pack(&PackRequest::new([ghost])).map(|_| ()),
            );
            check("put_pack", host.put_pack(&Pack::empty()).map(|_| ()));
            assert!(
                problems.is_empty(),
                "{label}: refused credentials must produce a refusal from every \
                 entry point:\n{}",
                problems.join("\n")
            );
        }
    }

    if let Some(secret) = secret.filter(|value| value.len() >= 4) {
        assert!(
            !denial.leaks(&secret),
            "{label}: a refusal or a description printed the credential value it was given"
        );
    }
}

/// A host that cannot do compare-and-swap says so from every direction.
///
/// This is the bucket whose endpoint ignores `If-Match`, and the static web
/// server that answers reads and nothing else: both are legitimate release
/// mirrors and neither may be allowed to look like a forge. Reads keep working,
/// every CAS-dependent write is refused by name, and nothing is half-written on
/// the way to the refusal.
fn a_host_without_cas_refuses_cas_writes(ctx: &Ctx<'_>) {
    let host = ctx.degraded();
    let caps = host.capabilities();
    assert!(
        !caps.cas,
        "the degraded variant must really report cas = false, or it is not testing \
         the degradation: {caps:?}"
    );

    let err = host
        .require(Capability::Cas)
        .expect_err("a host without CAS must refuse the capability");
    assert!(err.is_unsupported(), "{err}");
    assert!(
        err.to_string().contains(Capability::Cas.as_str()),
        "the refusal names the capability: {err}"
    );
    assert!(err.hint().is_some(), "and says what to do instead: {err}");

    // Reading is still a service: a dumb mirror is a mirror.
    assert!(host.list_refs(&RefQuery::all()).is_ok(), "refs still list");
    assert!(
        host.get_ref(&RefName::branch("nothing-here").unwrap())
            .is_ok(),
        "a ref read still answers"
    );
    let ghost = Oid::hash_bytes(b"not in a read-only store");
    assert!(host.get(&ghost).is_ok(), "a blob read still answers");
    assert!(!host.exists(&ghost).unwrap(), "and answers honestly");
    assert!(
        host.list_prefix(Namespace::ANY).is_ok(),
        "listings still work"
    );

    // Content-addressed writes need no CAS, so a host that refuses them is
    // refusing *writes*, which is its own honest refusal. Either way the answer
    // is `UnsupportedCas` and never a silent ok.
    match host.put_cas(&Namespace::RECORD, b"degraded") {
        Ok(oid) => assert_eq!(
            host.get(&oid).unwrap().unwrap(),
            b"degraded",
            "a content-addressed write that succeeded must be readable"
        ),
        Err(err) => assert!(
            err.is_unsupported(),
            "a store that refuses writes must say so: {err}"
        ),
    }

    let name = RefName::branch("gated").unwrap();
    let pretend = Oid::hash_bytes(b"a value this store has never held");
    let cas_writes = [
        ("create-only", RefUpdate::create(name.clone(), pretend)),
        (
            "compare-and-set",
            RefUpdate::replace(name.clone(), pretend, ghost),
        ),
    ];
    for (what, update) in cas_writes {
        let err = host
            .update_ref_cas(&update)
            .expect_err(&format!("{what} must be refused without CAS"));
        assert!(err.is_unsupported(), "{what}: {err}");
        assert!(
            host.get_ref(&name).unwrap().is_none(),
            "{what} wrote something on its way to refusing"
        );
    }
    let err = host
        .update_refs_cas(&[RefUpdate::create(name.clone(), pretend)])
        .expect_err("a batch is CAS-dependent too");
    assert!(err.is_unsupported(), "{err}");
    assert!(host.get_ref(&name).unwrap().is_none());
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(pretend)))
        .expect_err("a guarded delete is CAS-dependent too");
    assert!(err.is_unsupported(), "{err}");

    // `Expect::Any` is the operator's choice to make, not the host's: an
    // unconditional write is allowed here unless the whole store is read-only,
    // and even then the refusal is by name.
    match host.update_ref_cas(&RefUpdate::set(name.clone(), pretend)) {
        Ok(reference) => assert_eq!(reference.oid, pretend),
        Err(err) => assert!(
            err.is_unsupported(),
            "an unconditional write is either allowed or refused by name, not {err:?}"
        ),
    }
}

/// Assert that a fetched pack holds exactly the objects that were sent: the same
/// digests, each with the namespace and length it was written under.
///
/// Order is deliberately not part of this. A host may serve objects in whatever
/// order its storage finds them — a git host answers out of its own object
/// database, which has no interesting order — and pinning the order would measure
/// an implementation instead of the contract.
fn same_objects(what: &str, sent: &[(Namespace, Vec<u8>)], fetched: &Pack) {
    let read = fetched
        .raw_objects()
        .unwrap_or_else(|err| panic!("{what}: the bytes do not parse as a raw pack: {err}"));
    let indexed = |pairs: &[(Namespace, Vec<u8>)]| -> BTreeMap<String, (String, usize)> {
        pairs
            .iter()
            .map(|(namespace, body)| {
                (
                    Oid::hash_bytes(body).hex(),
                    (namespace.as_str().to_string(), body.len()),
                )
            })
            .collect()
    };
    let wanted = indexed(sent);
    let served = indexed(&read);
    assert_eq!(
        served, wanted,
        "{what}: what came back is not what went in ({served:?} against {wanted:?}); a \
         digest names exact bytes, so any difference here is a byte that changed on the way"
    );
}

/// Deterministic pseudo-random bytes: incompressible enough that a truncation
/// cannot hide behind a compressor, and reproducible so two runs compare.
fn pseudo_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

// ---------------------------------------------------------------------------
// The registry.
// ---------------------------------------------------------------------------

/// Every body, in the order a reader should meet them: reads, then writes, then
/// the sizes, then the promises.
pub fn bodies() -> &'static [Body] {
    &BODIES
}

static BODIES: [Body; 15] = [
    Body {
        name: "blobs_round_trip",
        shape: Shape::Single,
        requires_cas: false,
        note: "one digest per byte string; listings and reads agree with what was written",
        run: blobs_round_trip,
    },
    Body {
        name: "refs_round_trip",
        shape: Shape::Single,
        requires_cas: true,
        note: "a ref written under a promise reads back, and listings honour prefixes",
        run: refs_round_trip,
    },
    Body {
        name: "cas_conflicts_are_reported",
        shape: Shape::Single,
        requires_cas: true,
        note: "a stale write reports both sides and moves nothing",
        run: cas_conflicts_are_reported,
    },
    Body {
        name: "multi_ref_writes_are_all_or_nothing",
        shape: Shape::Single,
        requires_cas: true,
        note: "a change and its attestation are applied as a unit or not at all",
        run: multi_ref_writes_are_all_or_nothing,
    },
    Body {
        name: "pack_round_trip_between_two_hosts",
        shape: Shape::Pair,
        requires_cas: false,
        note: "what one host writes, a stranger reads by digest",
        run: pack_round_trip_between_two_hosts,
    },
    Body {
        name: "a_fresh_store_is_empty_then_writable",
        shape: Shape::Single,
        requires_cas: true,
        note: "an empty store is not an error, and the first write is ordinary",
        run: a_fresh_store_is_empty_then_writable,
    },
    Body {
        name: "ref_deletion_is_conditional",
        shape: Shape::Single,
        requires_cas: true,
        note: "deleting a ref is a compare-and-swap, and frees the name",
        run: ref_deletion_is_conditional,
    },
    Body {
        name: "a_huge_pack_round_trips_intact",
        shape: Shape::Single,
        requires_cas: false,
        note: "a pack big enough to take a multipart upload arrives whole",
        run: a_huge_pack_round_trips_intact,
    },
    Body {
        name: "listings_are_complete_across_pages",
        shape: Shape::Single,
        requires_cas: true,
        note: "paginated listings find every record, and filters do not lie",
        run: listings_are_complete_across_pages,
    },
    Body {
        name: "concurrent_ref_writers_never_lose_one",
        shape: Shape::Single,
        requires_cas: true,
        note: "threads racing on one ref conflict cleanly; nobody loses a change",
        run: concurrent_ref_writers_never_lose_one,
    },
    Body {
        name: "unsupported_operations_are_refused_by_name",
        shape: Shape::Single,
        requires_cas: false,
        note: "what a host cannot do is refused by name, not half-done",
        run: unsupported_operations_are_refused_by_name,
    },
    Body {
        name: "one_object_is_forgotten_or_the_refusal_says_why",
        shape: Shape::Single,
        requires_cas: true,
        note: "retention's delete question gets an honest answer: gone, or why not",
        run: one_object_is_forgotten_or_the_refusal_says_why,
    },
    Body {
        name: "describe_and_capabilities",
        shape: Shape::Single,
        requires_cas: false,
        note: "the host describes itself and never promises what it cannot do",
        run: describe_and_capabilities,
    },
    Body {
        name: "refused_credentials_are_denied_not_dropped",
        shape: Shape::Denied,
        requires_cas: false,
        note: "an expired or revoked credential is a refusal from every entry point",
        run: refused_credentials_are_denied_not_dropped,
    },
    Body {
        name: "a_host_without_cas_refuses_cas_writes",
        shape: Shape::Degraded,
        requires_cas: false,
        note: "a host that cannot CAS says so from every direction, and keeps serving reads",
        run: a_host_without_cas_refuses_cas_writes,
    },
];

/// Look up one body by name.
pub fn body(name: &str) -> Option<&'static Body> {
    bodies().iter().find(|body| body.name == name)
}

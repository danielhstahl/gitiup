//! The host conformance bodies, shared by every host in the workspace.
//!
//! These are the assertions a host must satisfy to be called a gitiup host. They
//! take `&dyn Host` on purpose: the same code runs against the `fs` reference
//! host (`tests/host_fs.rs`), the bucket-as-forge host (`tests/host_s3.rs`), and
//! — the point of factoring them out — whatever the shared conformance suite of
//! giti-xdw.5 grows into, including a live MinIO.
//!
//! Bodies are deliberately transport-agnostic: no filesystem paths, no bucket
//! keys, no git. Anything that is host-specific belongs in the host's own test
//! file.

use gitiup_host::{
    Actor, BlobEntry, Capabilities, Expect, Host, HostError, HostErrorExt, HostErrorKind,
    Namespace, Oid, Pack, PackFormat, PackRequest, RefDeletion, RefName, RefQuery, RefUpdate,
};

/// Refs round-trip: write, read back, reopen, list with a filter.
pub fn refs_round_trip(host: &dyn Host) {
    let blob = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"c1\"}")
        .expect("put change record");
    let head = RefName::change_head("c1").expect("change ref name");

    let written = host
        .update_ref_cas(
            &RefUpdate::create(head.clone(), blob)
                .with_actor(Actor::new("ada").unwrap())
                .with_message("open change c1"),
        )
        .expect("create ref");
    assert_eq!(written.oid, blob);
    assert_eq!(written.name, head);
    assert_eq!(written.updated_by.as_ref().unwrap().as_str(), "ada");

    let read_back = host
        .get_ref(&head)
        .expect("get ref")
        .expect("ref must exist");
    assert_eq!(read_back.oid, blob);
    assert_eq!(read_back.schema, Some(gitiup_host::HOST_SCHEMA_VERSION));

    let next = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"c1\",\"state\":\"merged\"}")
        .expect("put updated record");
    host.cas_ref(&head, Some(blob), next)
        .expect("CAS to the value we read");
    assert_eq!(host.get_ref(&head).unwrap().unwrap().oid, next);

    // Listings honour prefixes and stay sorted.
    let branch = RefName::branch("main").unwrap();
    host.cas_ref(&branch, None, next).expect("set branch");
    let all = host.list_refs(&RefQuery::all()).expect("list all");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].name.as_str(), "refs/changes/c1/head");
    let changes = host
        .list_refs(&RefQuery::prefix(gitiup_host::refs::ns::CHANGES))
        .expect("list changes");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].name, head);

    // Deleting a change's ref is itself a CAS.
    host.delete_ref_cas(&RefDeletion::new(branch.clone(), Expect::Is(next)))
        .expect("delete with matching expectation");
    assert!(host.get_ref(&branch).unwrap().is_none());
}

/// Blobs round-trip: identical bytes give one object, listings work, content is
/// exactly what went in.
pub fn blobs_round_trip(host: &dyn Host) {
    let roster = b"{\"verifiers\":5}".to_vec();
    let oid = host
        .put_cas(&Namespace::ROSTER, &roster)
        .expect("put roster");
    assert_eq!(oid, Oid::hash_bytes(&roster));
    assert_eq!(
        host.put_cas(&Namespace::ROSTER, &roster)
            .expect("idempotent"),
        oid,
        "storing the same bytes again must return the same digest"
    );
    assert_eq!(host.get(&oid).unwrap().as_deref(), Some(&roster[..]));
    assert!(host.exists(&oid).unwrap());

    // Binary, empty-ish and larger payloads survive byte for byte.
    let binary: Vec<u8> = (0u16..=255).map(|b| b as u8).cycle().take(4096).collect();
    let binary_oid = host
        .put_cas(&Namespace::ATTESTATION, &binary)
        .expect("put attestation");
    assert_eq!(host.get(&binary_oid).unwrap().unwrap(), binary);

    let missing = Oid::hash_bytes(b"never stored");
    assert!(host.get(&missing).unwrap().is_none());
    assert!(!host.exists(&missing).unwrap());

    let entries: Vec<BlobEntry> = host
        .list_prefix(gitiup_host::refs::ns::CHANGES)
        .unwrap_or_default();
    assert!(
        entries.iter().all(|e| e.namespace.as_str() != "roster"),
        "listing one namespace must not leak another"
    );

    let rosters = host.list(&Namespace::ROSTER).expect("list rosters");
    assert_eq!(rosters.len(), 1, "{rosters:?}");
    assert_eq!(rosters[0].oid, oid);
    assert_eq!(rosters[0].size, roster.len() as u64);
    assert_eq!(rosters[0].key(), format!("roster/{}", oid.hex()));

    // Hex prefixes narrow further, across namespaces.
    let by_hex = host
        .list_prefix(&format!("roster/{}", &oid.hex()[..4]))
        .expect("list by hex prefix");
    assert_eq!(by_hex.len(), 1);
    assert!(
        host.list_prefix(&format!("roster/{}", oid.hex()[..4].to_uppercase()))
            .expect("hex prefix is case-insensitive")
            .len()
            == 1
    );
    assert!(
        host.list_prefix(&format!("attestation/{}", &oid.hex()[..4]))
            .unwrap()
            .is_empty()
    );
    assert!(!host.list_prefix("*").expect("list all").is_empty());
    assert!(
        !host
            .list_prefix(&format!("*/{}", &oid.hex()[..6]))
            .expect("any-namespace hex prefix")
            .is_empty()
    );
    assert!(
        host.list_prefix("no-such-namespace")
            .expect("an unknown namespace lists empty, it is not an error")
            .is_empty()
    );
    assert!(
        host.list_prefix("").is_err(),
        "an empty pattern is an error"
    );
}

/// A pack written by one host is readable by another: that is the transport for
/// proposals and attestations.
pub fn pack_round_trip(source: &dyn Host, sink: &dyn Host) {
    let records: Vec<(Namespace, Vec<u8>)> = vec![
        (Namespace::CHANGE, b"{\"id\":\"c9\"}".to_vec()),
        (Namespace::ATTESTATION, b"digest=abc".to_vec()),
        (Namespace::ROSTER, vec![0, 1, 2, 3]),
    ];
    let pack = Pack::from_raw_objects(records.clone()).expect("build pack");
    assert_eq!(pack.format, PackFormat::Raw);
    let pack_oid = source.put_pack(&pack).expect("put pack");
    assert_eq!(pack_oid, pack.oid());

    let oids: Vec<Oid> = records
        .iter()
        .map(|(_, bytes)| Oid::hash_bytes(bytes))
        .collect();

    // Fetch back from the source, asking for the records by digest...
    let fetched = source
        .fetch_pack(&PackRequest::new(oids.clone()))
        .expect("fetch by digest");
    assert_eq!(fetched.raw_objects().expect("fetch parses").len(), 3);

    // ...or by the pack's own digest.
    let via_pack = source
        .fetch_pack(&PackRequest::new([pack_oid]))
        .expect("fetch the pack itself");
    assert_eq!(via_pack.raw_objects().unwrap().len(), 3);

    // Haves are skipped.
    let partial = source
        .fetch_pack(&PackRequest::new(oids.clone()).with_have([oids[0]]))
        .expect("fetch with haves");
    assert_eq!(partial.raw_objects().unwrap().len(), 2);

    // A missing want is NotFound, not an empty pack.
    let err = source
        .fetch_pack(&PackRequest::new([Oid::hash_bytes(b"absent")]))
        .expect_err("missing want must fail");
    assert_eq!(err.kind(), HostErrorKind::NotFound);

    // Copy the objects into the second host (what `gitiup change submit` does).
    let transferred = via_pack.raw_objects().unwrap();
    let oids_written: Vec<Oid> = transferred
        .iter()
        .map(|(ns, bytes)| {
            let oid = sink.put_cas(ns, bytes).expect("transfer blob");
            assert_eq!(oid, Oid::hash_bytes(bytes));
            oid
        })
        .collect();
    for oid in &oids_written {
        assert_eq!(
            sink.get(oid).unwrap().unwrap(),
            source
                .get(oid)
                .unwrap()
                .unwrap_or_else(|| panic!("{oid} missing from source")),
            "transferred content must be byte-identical"
        );
    }
    sink.put_pack(&pack)
        .expect("the same pack ingests into another host");
}

pub fn cas_conflicts_are_reported(host: &dyn Host) {
    let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();
    let name = RefName::branch("gated").unwrap();

    // Create-only must fail once the ref exists.
    host.update_ref_cas(&RefUpdate::create(name.clone(), a))
        .unwrap();
    let err = host
        .update_ref_cas(&RefUpdate::create(name.clone(), b))
        .expect_err("create-only must not clobber");
    assert_eq!(err.kind(), HostErrorKind::Conflict);
    match &err {
        HostError::Conflict(conflict) => {
            assert_eq!(conflict.name, name.as_str());
            assert_eq!(conflict.found, Some(a));
            assert_eq!(conflict.expected, None);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }

    // A stale expectation reports both sides.
    let stale = host
        .update_ref_cas(&RefUpdate::replace(name.clone(), b, a))
        .expect_err("stale expectation");
    match &stale {
        HostError::Conflict(conflict) => {
            assert_eq!(conflict.expected, Some(b));
            assert_eq!(conflict.found, Some(a));
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert!(stale.is_conflict());
    assert!(stale.is_retryable(), "a conflict is retried, not fatal");
    assert_eq!(
        host.get_ref(&name).unwrap().unwrap().oid,
        a,
        "nothing moved"
    );

    // Deleting a ref that is already gone is NotFound, not a silent ok.
    let gone = RefName::branch("never-existed").unwrap();
    let err = host
        .delete_ref_cas(&RefDeletion::new(gone.clone(), Expect::Is(a)))
        .expect_err("deleting an absent ref with an expectation fails");
    assert_eq!(err.kind(), HostErrorKind::NotFound);
    host.delete_ref_cas(&RefDeletion::new(gone, Expect::Any))
        .expect("unguarded delete of an absent ref is idempotent");
}

pub fn multi_ref_writes_are_all_or_nothing(host: &dyn Host) {
    let head = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"c1\"}")
        .unwrap();
    let attestation = host
        .put_cas(&Namespace::ATTESTATION, b"signed digest")
        .unwrap();
    let change_ref = RefName::change_head("c1").unwrap();
    let attestation_ref = RefName::attestation(&attestation);
    let branch = RefName::branch("main").unwrap();
    let other = host.put_cas(&Namespace::RECORD, b"other").unwrap();
    host.cas_ref(&branch, None, other).unwrap();

    // A batch where the last update's expectation is wrong must apply nothing:
    // submitting a change and its attestation is only valid as a unit.
    let batch = vec![
        RefUpdate::create(change_ref.clone(), head).with_actor("ada"),
        RefUpdate::create(attestation_ref.clone(), attestation).with_actor("ada"),
        RefUpdate::replace(branch.clone(), Oid::from_hex("beef").unwrap(), head),
    ];
    let err = host
        .update_refs_cas(&batch)
        .expect_err("the third update cannot match");
    assert!(err.is_conflict(), "{err}");
    assert!(
        host.get_ref(&change_ref).unwrap().is_none(),
        "the change ref must not be left behind"
    );
    assert!(
        host.get_ref(&attestation_ref).unwrap().is_none(),
        "the attestation ref must not be left behind"
    );
    assert_eq!(host.get_ref(&branch).unwrap().unwrap().oid, other);

    // The same batch with correct expectations applies fully.
    let ok = host.update_refs_cas(&[
        RefUpdate::create(change_ref.clone(), head),
        RefUpdate::create(attestation_ref.clone(), attestation),
    ]);
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(host.get_ref(&change_ref).unwrap().unwrap().oid, head);
    assert!(host.get_ref(&attestation_ref).unwrap().is_some());
}

pub fn describe_and_capabilities(host: &dyn Host) {
    let caps: Capabilities = host.capabilities();
    assert!(caps.cas, "a host that cannot CAS cannot gate a merge");
    let info = host.describe();
    assert_eq!(info.schema_version, gitiup_host::HOST_SCHEMA_VERSION);
    assert!(!info.store_prefix.is_empty());
    assert!(info.implemented_by.starts_with("gitiup-host "));
    assert!(
        !info.summary_line().is_empty(),
        "capability matrix lines are for remote doctor"
    );
    // The capability helpers speak the taxonomy later tickets expect.
    let before = caps.missing();
    for missing in before {
        let required = match missing {
            "immutable" => gitiup_host::Capability::Immutable,
            "atomic-multi-write" => gitiup_host::Capability::AtomicMultiWrite,
            _ => gitiup_host::Capability::Cas,
        };
        let err = host
            .require(required)
            .expect_err("missing capability must refuse");
        assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
        assert!(err.to_string().contains(required.as_str()));
    }
}

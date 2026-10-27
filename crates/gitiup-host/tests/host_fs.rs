//! End-to-end tests for the host trait set against the `fs` reference host.
//!
//! The transport-agnostic assertions live in `tests/support/conformance.rs` (they
//! take `&dyn Host` so every host runs the same code, including the S3 host in
//! `tests/host_s3.rs` and the shared conformance suite of giti-xdw.5). What is
//! left here is what only the `fs` host can promise: a real atomic multi-write, a
//! refs file you can read, and state that survives a reopen.

use std::sync::atomic::{AtomicUsize, Ordering};

use gitiup_host::hosts::fs::FsHost;
use gitiup_host::{
    BlobEntry, BlobStore, Host, HostError, HostErrorKind, HostKind, Namespace, Pack, PackFormat,
    PackRequest, Ref, RefName, RefStore, RefUpdate,
};

mod support;
use support::conformance;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A throwaway `fs` host; the returned guard deletes the directory on drop.
fn temp_host() -> (tempfile::TempDir, FsHost) {
    let dir = tempfile::Builder::new()
        .prefix(&format!(
            "gitiup-host-it-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .tempdir()
        .expect("scratch dir");
    let host = FsHost::create(dir.path()).expect("create host");
    (dir, host)
}

// ---------------------------------------------------------------------------
// The fs host, driven through the traits.
// ---------------------------------------------------------------------------

#[test]
fn fs_refs_round_trip() {
    let (_scratch, host) = temp_host();
    conformance::refs_round_trip(&host);
}

#[test]
fn fs_blobs_round_trip() {
    let (_scratch, host) = temp_host();
    conformance::blobs_round_trip(&host);
}

#[test]
fn fs_pack_round_trip_between_two_hosts() {
    let (_s1, source) = temp_host();
    let (_s2, sink) = temp_host();
    conformance::pack_round_trip(&source, &sink);
}

#[test]
fn fs_cas_conflicts_are_reported() {
    let (_scratch, host) = temp_host();
    conformance::cas_conflicts_are_reported(&host);
}

#[test]
fn fs_multi_ref_writes_are_all_or_nothing() {
    let (_scratch, host) = temp_host();
    conformance::multi_ref_writes_are_all_or_nothing(&host);
}

#[test]
fn fs_describe_and_capabilities() {
    let (_scratch, host) = temp_host();
    assert_eq!(host.kind(), HostKind::Fs);
    conformance::describe_and_capabilities(&host);
}

#[test]
fn fs_state_survives_reopen() {
    let (_scratch, host) = temp_host();
    let oid = host
        .put_cas(&Namespace::ATTESTATION, b"persist me")
        .unwrap();
    let name = RefName::attestation(&oid);
    host.update_ref_cas(&RefUpdate::create(name.clone(), oid))
        .unwrap();
    let reopened = FsHost::open(host.root()).expect("reopen");
    assert_eq!(reopened.get_ref(&name).unwrap().unwrap().oid, oid);
    assert_eq!(reopened.get(&oid).unwrap().unwrap(), b"persist me");
    assert_eq!(reopened.list(&Namespace::ATTESTATION).unwrap().len(), 1);
}

#[test]
fn fs_reports_real_capabilities() {
    let (_scratch, host) = temp_host();
    let caps = host.capabilities();
    assert!(caps.cas && caps.immutable && caps.atomic_multi_write);
    assert_eq!(caps.auth, gitiup_host::AuthModel::Filesystem);
    let info = host.describe();
    assert_eq!(info.kind, HostKind::Fs);
    assert_eq!(info.store_prefix, "gitiup");
    assert!(info.url.unwrap().starts_with("file://"));
}

#[test]
fn concurrent_cas_writers_converge_without_losing_refs() {
    let (_scratch, host) = temp_host();
    let base = host.put_cas(&Namespace::RECORD, b"base").unwrap();
    let name = RefName::branch("contended").unwrap();
    host.cas_ref(&name, None, base).unwrap();

    let mut handles = Vec::new();
    for i in 0..8 {
        let host = host.clone();
        let name = name.clone();
        handles.push(std::thread::spawn(move || {
            let mine = host
                .put_cas(&Namespace::RECORD, format!("worker-{i}").as_bytes())
                .unwrap();
            // Every worker reads, then tries to advance the ref from what it saw.
            let seen = host.get_ref(&name).unwrap().unwrap().oid;
            match host.cas_ref(&name, Some(seen), mine) {
                Ok(_) => Ok(mine),
                Err(err) => Err(err),
            }
        }));
    }
    let mut won = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.join().unwrap() {
            Ok(_) => won += 1,
            Err(err) => {
                assert_eq!(err.kind(), HostErrorKind::Conflict, "{err}");
                conflicts += 1;
            }
        }
    }
    assert_eq!(won + conflicts, 8);
    assert!(won >= 1, "at least one writer must succeed");
    let final_ref = host.get_ref(&name).unwrap().expect("ref survives");
    let content = host.get(&final_ref.oid).unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&content).starts_with("worker-"),
        "the winning ref must point at a real stored record"
    );
}

#[test]
fn refs_and_packs_land_where_the_layout_promises() {
    let (_scratch, host) = temp_host();
    let oid = host
        .put_cas(&Namespace::JOB, b"{\"job\":\"build\"}")
        .unwrap();
    assert!(host.root().join("cas/job").exists(), "cas/<ns>/...");
    assert!(host.root().join("refs").is_file(), "a single refs file");
    assert!(
        host.root().join("gitiup-host.toml").is_file(),
        "host manifest"
    );
    let pack = Pack::from_raw_objects([(Namespace::JOB, b"{\"job\":\"build\"}".to_vec())]).unwrap();
    let pack_oid = host.put_pack(&pack).unwrap();
    assert!(
        host.root()
            .join("packs")
            .join(format!("{}.pack", pack_oid.hex()))
            .is_file(),
        "packs/<oid>.pack"
    );
    let listed: Vec<BlobEntry> = host.list(&Namespace::JOB).unwrap();
    assert_eq!(listed[0].oid, oid);
}

#[test]
fn git_packfiles_are_refused_with_the_right_taxonomy() {
    let (_scratch, host) = temp_host();
    let mut fake = Vec::new();
    fake.extend_from_slice(b"PACK");
    fake.extend_from_slice(&[0, 0, 0, 2]);
    fake.extend_from_slice(&[0, 0, 0, 1]);
    fake.extend_from_slice(&[0u8; 20]);
    let pack = Pack::git_packfile(fake).unwrap();
    let err = host.put_pack(&pack).expect_err("fs has no git object db");
    assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
    match &err {
        HostError::UnsupportedCas(why) => {
            assert_eq!(why.capability, "pack-format:git-packfile");
            assert!(why.hint.is_some(), "the refusal says what to do instead");
        }
        other => panic!("expected UnsupportedCas, got {other:?}"),
    }
    let err = host
        .fetch_pack(&PackRequest::new([]).with_format(PackFormat::GitPackfile))
        .expect_err("git format is not servable here");
    assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
}

#[test]
fn boxed_dyn_host_works_for_shared_use() {
    // Later tickets hand hosts around as `Arc<dyn Host>`; the traits must stay
    // object-safe and upcastable.
    let (_scratch, host) = temp_host();
    let boxed: Box<dyn Host> = Box::new(host.clone());
    let refs_only: &dyn RefStore = &*boxed;
    let blobs_only: &dyn BlobStore = &*boxed;
    let oid = blobs_only
        .put_cas(&Namespace::RECORD, b"upcast me")
        .expect("blob store through upcast");
    let name = RefName::branch("upcast").unwrap();
    refs_only
        .update_ref_cas(&RefUpdate::create(name.clone(), oid))
        .expect("ref store through upcast");
    assert_eq!(boxed.get_ref(&name).unwrap().unwrap().oid, oid);
    let _: &dyn RefStore = &host;
    let _: &dyn BlobStore = &host;
    let stored = host.get_ref(&name).unwrap().unwrap();
    assert_eq!(stored.name, name);
    assert_eq!(stored.oid, oid);
    let _ = Ref::new(name, oid);
}

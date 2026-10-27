//! A tour of the bucket-as-forge host: refs, content-addressed records, packs
//! and compare-and-swap, against an in-process bucket.
//!
//! `MemoryBucket` is a real implementation of the transport contract (etags,
//! 412s, paged listings, multipart uploads), so this exercises the same code
//! path as a live S3 bucket — no credentials, no network, no MinIO. To point the
//! same host at a real bucket instead, build with `--features gitiup-host/s3`
//! and swap the first lines for:
//!
//! ```text
//! let remote = RemoteConfig::new("origin", "s3://my-bucket/my-repo")?;
//! let host = S3Host::open_or_init(gitiup_host::hosts::s3::transport::connect(&remote)?, &remote)?;
//! ```
//!
//! Run with `cargo run -p gitiup-host --example s3_tour`.

use std::sync::Arc;

use gitiup_host::{
    BlobStore, Expect, Host, HostErrorExt, MemoryBucket, Namespace, Pack, PackRequest, RefDeletion,
    RefName, RefQuery, RefStore, RefUpdate, RemoteConfig, S3Host,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bucket = MemoryBucket::forge("gitiup-forge");
    let remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo")?;
    let host = S3Host::init(Arc::new(bucket.clone()), &remote)?;
    println!(
        "opened {} (cas: {}, immutable: {})",
        host.describe().name,
        host.capabilities().cas,
        host.capabilities().immutable
    );
    for advice in host.advice() {
        println!("  advice: {advice}");
    }

    // A change record, content addressed: put it twice and you get the same
    // digest and one object.
    let record = br#"{"id":"c1","title":"carry changes in refs"}"#;
    let oid = host.put_cas(&Namespace::CHANGE, record)?;
    println!(
        "\nrecord {} at {}",
        oid.short(12),
        host.kv_key(&Namespace::CHANGE, &oid)
    );
    println!(
        "  put again: {}",
        host.put_cas(&Namespace::CHANGE, record)? == oid
    );
    println!("  read back: {} bytes", host.get(&oid)?.unwrap().len());

    // Publishing it is a create-only ref write — `If-None-Match: *` on the wire.
    let head = RefName::change_head("c1")?;
    host.update_ref_cas(&RefUpdate::create(head.clone(), oid).with_actor("ada"))?;
    println!("\npublished {} -> {}", head, oid.short(12));
    println!("  key: {}", host.ref_key(&head));
    println!(
        "  object: {}",
        String::from_utf8_lossy(&bucket.raw(&host.ref_key(&head)).unwrap())
    );

    // Somebody else cannot create the same ref.
    match host.update_ref_cas(&RefUpdate::create(head.clone(), oid)) {
        Ok(_) => println!("  second create: impossible, and it happened"),
        Err(err) => println!("  second create: {} ({})", err.kind(), err),
    }

    // Two clones of the same bucket, pushing at once: one ref, no lost updates.
    let clone_a = S3Host::open(Arc::new(bucket.clone()), &remote)?;
    let clone_b = S3Host::open(Arc::new(bucket.clone()), &remote)?;
    let mine = clone_a.put_cas(&Namespace::RECORD, b"my work")?;
    let theirs = clone_b.put_cas(&Namespace::RECORD, b"their work")?;
    let main = RefName::branch("main")?;
    clone_a.update_ref_cas(&RefUpdate::create(main.clone(), theirs))?;
    for attempt in 0.. {
        let Some(seen) = clone_b.get_ref(&main)? else {
            return Err("refs/heads/main disappeared".into());
        };
        match clone_b.cas_ref(&main, Some(seen.oid), mine) {
            Ok(_) => {
                println!("\nclone_b moved refs/heads/main on attempt {}", attempt + 1);
                break;
            }
            Err(err) if err.is_conflict() => {
                println!("  conflict, re-reading ({})", err.kind());
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }
    println!(
        "  main now: {}",
        clone_a.get_ref(&main)?.unwrap().oid.short(12)
    );

    // A pack crosses between stores, which is how a proposal arrives.
    let pack = Pack::from_raw_objects([
        (Namespace::CHANGE, record.to_vec()),
        (Namespace::ATTESTATION, b"quorum=signed".to_vec()),
    ])?;
    let pack_oid = host.put_pack(&pack)?;
    let back = host.fetch_pack(&PackRequest::new([pack_oid]))?;
    println!(
        "\npack {} carries {} records, fetched by its own digest",
        pack_oid.short(12),
        back.object_count()?
    );
    println!("  key: {}", host.pack_key(&pack_oid));

    // Closing a change tombstones the ref object; nothing is deleted.
    let objects = bucket.object_count();
    host.delete_ref_cas(&RefDeletion::new(head.clone(), Expect::Is(oid)))?;
    println!(
        "\nclosed {}: get_ref says {}, objects went {} -> {}",
        head,
        host.get_ref(&head)?.map(|_| "present").unwrap_or("gone"),
        objects,
        bucket.object_count()
    );

    println!("\nrefs now:");
    for reference in host.list_refs(&RefQuery::all())? {
        println!("  {} -> {}", reference.name, reference.oid.short(12));
    }
    println!(
        "\nref cache: {} hits, {} misses",
        host.ref_cache_stats().hits,
        host.ref_cache_stats().misses
    );
    Ok(())
}

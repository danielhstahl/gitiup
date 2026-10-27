//! A guided tour of the host traits against the `fs` host: publish a change and
//! its attestation, hit a CAS conflict, then move both to a second host with a
//! pack — the same calls `gitiup change submit` will make (giti-kd4.3).
//!
//! Run with `cargo run -p gitiup-host --example fs_tour`.

use gitiup_host::{
    BlobStore, Expect, Host, HostError, Namespace, Oid, PackRequest, RefName, RefQuery, RefStore,
    RefUpdate,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("gitiup-example-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let owner = gitiup_host::FsHost::create(&root)?;
    let contributor = gitiup_host::FsHost::create_with_prefix(
        std::env::temp_dir().join(format!("gitiup-example-{}-clone", std::process::id())),
        "gitiup",
    )?;
    println!("owner host:   {}", owner.describe().summary_line());
    println!("clone host:   {}\n", contributor.describe().summary_line());

    // A change record lives in the CAS; a ref points at it.
    let record = br#"{"id":"c1","base_ref":"refs/heads/main","head_oid":"deadbeef"}"#;
    let record_oid = contributor.put_cas(&Namespace::CHANGE, record)?;
    let change_ref = RefName::change_head("c1")?;
    println!("stored change record {record_oid}");

    // An attestation over the run digest, plus the ref that carries proof.
    let attestation = format!(
        "digest={} signer=contributor",
        Oid::hash_bytes(record).short(12)
    );
    let attestation_oid = contributor.put_cas(&Namespace::ATTESTATION, attestation.as_bytes())?;
    let attestation_ref = RefName::attestation(&Oid::hash_bytes(record));
    println!("stored attestation   {attestation_oid}");

    // Both refs move together or not at all — a change without its proof is not
    // publishable.
    contributor.update_refs_cas(&[
        RefUpdate::create(change_ref.clone(), record_oid).with_actor("contributor"),
        RefUpdate::create(attestation_ref.clone(), attestation_oid).with_actor("contributor"),
    ])?;
    println!("clone refs:\n{}", render(&contributor)?);

    // Ship the objects to the owner's store as a pack, then point the refs there.
    let pack = contributor.fetch_pack(&PackRequest::new([record_oid, attestation_oid]))?;
    println!(
        "\npack: {} bytes, {} objects, digest {}",
        pack.len(),
        pack.object_count()?,
        pack.oid().short(12)
    );
    for (namespace, content) in pack.raw_objects()? {
        owner.put_cas(&namespace, &content)?;
    }
    owner.put_pack(&pack)?;
    owner.update_refs_cas(&[
        RefUpdate::create(change_ref.clone(), record_oid).with_actor("contributor"),
        RefUpdate::create(attestation_ref.clone(), attestation_oid).with_actor("contributor"),
    ])?;
    println!("\nowner refs:\n{}", render(&owner)?);

    // Now someone else races us: a create-only write must fail, not clobber.
    match owner.update_ref_cas(&RefUpdate::new(
        change_ref.clone(),
        Expect::Absent,
        attestation_oid,
    )) {
        Ok(reference) => println!("unexpectedly wrote {reference:?}"),
        Err(HostError::Conflict(conflict)) => println!(
            "CAS refused: {} was {}, we expected {}",
            conflict.name,
            conflict.found.map(|o| o.short(12)).unwrap_or_default(),
            conflict
                .expected
                .map(|o| o.short(12))
                .unwrap_or("absent".to_string()),
        ),
        Err(other) => return Err(other.into()),
    }

    // Fetching with `have` set is how a client pulls only what is new.
    let rest = owner
        .fetch_pack(&PackRequest::new([record_oid, attestation_oid]).with_have([record_oid]))?;
    println!(
        "\nsecond fetch only had to send {} object(s)",
        rest.object_count()?
    );

    for host in [&owner, &contributor] {
        let _ = std::fs::remove_dir_all(host.root());
    }
    Ok(())
}

fn render(host: &dyn Host) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = String::new();
    for reference in host.list_refs(&RefQuery::all())? {
        out.push_str(&format!(
            "  {} {:>12}  by {}\n",
            reference.name,
            reference.oid.short(12),
            reference
                .updated_by
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));
    }
    Ok(out)
}

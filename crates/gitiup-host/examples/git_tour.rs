//! A guided tour of the plain-git host: a bare repository on the filesystem,
//! talked to with `git push` and `git fetch` and nothing else. This is the host
//! where a repo is "just a repo" — no forge, no object store, no daemon — and it
//! shows the three things that make that work: the shared ref namespaces, a CAS
//! built out of `--force-with-lease`, and the fact that a reviewer with plain
//! `git` sees everything gitiup does.
//!
//! Run with `cargo run -p gitiup-host --example git_tour`.

use gitiup_host::hosts::git::GitHost;
use gitiup_host::{
    BlobStore, Expect, Host, HostError, Namespace, RefName, RefQuery, RefStore, RefUpdate,
    RemoteConfig,
};
use std::path::Path;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("gitiup-git-tour-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;

    // The "server": a bare repository. Anywhere `git init --bare` can live, and
    // anywhere that can be named by `file://`, `ssh://` or an HTTP URL, is a
    // gitiup store. `init` writes the store's own manifest ref into it.
    let repo = root.join("project.git");
    gitiup_host::hosts::git::init_bare(&repo)?;
    let host = GitHost::open_or_init(&remote("origin", &repo, &root.join("mirror")))?;
    println!("store:     {}", host.describe().summary_line());
    println!("git url:   {}", host.git_url());
    println!("mirror:    {}\n", host.mirror().display());

    // A change, and the proof about it: two records in the CAS and two refs that
    // point at them, moved in one transaction.
    let record = br#"{"id":"c1","base_ref":"refs/heads/main","head_oid":"deadbeef"}"#;
    let record_oid = host.put_cas(&Namespace::CHANGE, record)?;
    let attestation = format!("digest={} verified-by=ci", record_oid.short(12));
    let attestation_oid = host.put_cas(&Namespace::ATTESTATION, attestation.as_bytes())?;
    let change = RefName::change_head("c1")?;
    let proof = RefName::attestation(&record_oid);
    host.update_refs_cas(&[
        RefUpdate::create(change.clone(), record_oid).with_actor("contributor"),
        RefUpdate::create(proof.clone(), attestation_oid).with_actor("ci-bot"),
    ])?;
    println!("published c1 and its attestation");
    println!("refs:\n{}", render(&host)?);

    // What a reviewer with nothing but `git` sees. The ref names are the shared
    // convention, and because a ref that names a gitiup record points at a small
    // commit carrying those bytes, the record arrives in the same packfile as the
    // ref — there is no second download.
    println!("plain `git ls-remote` sees:");
    for line in git(
        &repo,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
    )?
    .lines()
    {
        if !line.starts_with("refs/gitiup/") {
            println!("  {line}");
        }
    }
    let tip = git(&repo, &["rev-parse", change.as_str()])?;
    println!(
        "\nthe record's own bytes, straight out of the clone: {}",
        String::from_utf8_lossy(
            &Command::new("git")
                .arg("--git-dir")
                .arg(&repo)
                .args(["cat-file", "blob", &format!("{tip}:record")])
                .output()?
                .stdout
        )
    );

    // The CAS, in the shape a merge gate needs it: somebody else's create-only
    // write cannot clobber what is already here. Underneath, this is
    // `git push --force-with-lease=<ref>:<what we read>`, and nothing about it
    // needs a server-side API.
    match host.update_ref_cas(&RefUpdate::new(
        change.clone(),
        Expect::Absent,
        attestation_oid,
    )) {
        Ok(reference) => println!("unexpectedly moved {}", reference.name),
        Err(HostError::Conflict(conflict)) => println!(
            "\nCAS refused: {} is already {}, and we expected {}",
            conflict.name,
            conflict
                .found
                .map(|oid| oid.short(12))
                .unwrap_or_else(|| "absent".to_string()),
            conflict
                .expected
                .map(|oid| oid.short(12))
                .unwrap_or_else(|| "absent".to_string()),
        ),
        Err(other) => return Err(other.into()),
    }

    // A second machine, with its own mirror and its own fetch: the same refs, the
    // same values, because the repository is the store.
    let peer = GitHost::open(&remote("peer", &repo, &root.join("mirror-peer")))?;
    println!(
        "\nsecond clone reads {} = {}",
        change,
        peer.get_ref(&change)?
            .map(|r| r.oid.short(12))
            .unwrap_or_default()
    );
    println!(
        "and it read the attestation bytes across the fetch: {}",
        String::from_utf8_lossy(&peer.get(&attestation_oid)?.unwrap())
    );

    // gitiup's own bookkeeping — the store manifest and the record chains that
    // stand in for a content-addressed store — is in the repository too, in
    // `refs/gitiup/**`, and stays out of every listing.
    println!("\nlisting any host the same way:");
    for reference in host.list_refs(&RefQuery::all())? {
        println!(
            "  {} {:>12}  by {}",
            reference.name,
            reference.oid.short(12),
            reference
                .updated_by
                .map(|a| a.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }
    println!(
        "reserved refs the store keeps to itself: {}",
        peer.store_refs()?
            .iter()
            .map(|r| r.name.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    std::fs::remove_dir_all(&root)?;
    Ok(())
}

fn remote(name: &str, repo: &Path, mirror: &Path) -> RemoteConfig {
    RemoteConfig::new(name, &format!("file://{}", repo.display()))
        .expect("a file url is a bare repository")
        .with_option("work-dir", mirror.display().to_string())
}

fn git(repo: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(format!("git {args:?}: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
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

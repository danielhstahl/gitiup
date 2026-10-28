//! End-to-end tests for the plain-git host: a real bare repository, real
//! `git push`/`git fetch`, real leases.
//!
//! The transport-agnostic assertions come from `tests/support/conformance.rs`, so
//! the same code runs here, against the `fs` host and against the bucket host —
//! that is the point of the trait set. What is left here is what only a
//! git-backed host can be asked: that a change ref is a ref plain git can see and
//! fetch, that a record's bytes come along in the same packfile as the ref that
//! points at them, that a lease actually refuses a stale write, and that the
//! store's own machinery stays out of the ref listing.
//!
//! Every test gets its own repository *and* its own mirror (`work-dir`), because
//! tests run in parallel and a shared mirror would make one test's fetch another's
//! race.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use gitiup_host::hosts::git::{GitHost, GitOptions, KV_ROOT};
use gitiup_host::{
    BlobStore, Expect, Host, HostErrorExt, HostErrorKind, HostKind, Namespace, Oid, Pack,
    PackFormat, PackRequest, Ref, RefDeletion, RefName, RefQuery, RefStore, RefUpdate,
    RemoteConfig,
};

mod support;
use support::conformance;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Skip (not fail) when there is no git: the host is the git binary, so a box
/// without one cannot run this file at all.
fn require_git() {
    if gitiup_host::hosts::git::git_program().is_none() {
        eprintln!("skipped: no git binary on this box");
    }
}

/// A scratch repository with its own store and mirror.
struct Scratch {
    repo: PathBuf,
    mirror: PathBuf,
    _dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Scratch {
        let dir = tempfile::Builder::new()
            .prefix(&format!(
                "gitiup-host-git-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
            .tempdir()
            .expect("scratch dir");
        let repo = dir.path().join("repo.git");
        gitiup_host::hosts::git::init_bare(&repo).expect("init bare repository");
        Scratch {
            repo,
            mirror: dir.path().join("mirror"),
            _dir: dir,
        }
    }

    fn remote(&self) -> RemoteConfig {
        RemoteConfig::new("origin", &format!("file://{}", self.repo.display()))
            .expect("file url")
            .with_option("work-dir", self.mirror.display().to_string())
    }

    fn host(&self) -> GitHost {
        GitHost::open_or_init(&self.remote()).expect("open_or_init")
    }

    /// A second handle on the same repository, with its own mirror: what another
    /// contributor's machine is.
    fn peer(&self, name: &str) -> GitHost {
        GitHost::open(&self.peer_remote(name)).expect("open peer")
    }

    /// The remote for a second handle — its own mirror, because two handles
    /// sharing one mirror is one machine pretending to be two.
    fn peer_remote(&self, name: &str) -> RemoteConfig {
        RemoteConfig::new(name, &format!("file://{}", self.repo.display()))
            .expect("file url")
            .with_option(
                "work-dir",
                self.mirror.with_extension(name).display().to_string(),
            )
            .with_option("ref-cache-ttl", "0s")
    }
}

fn plain_git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// The conformance suite, over the git transport.
// ---------------------------------------------------------------------------

#[test]
fn git_refs_round_trip() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    conformance::refs_round_trip(&host);
}

#[test]
fn git_blobs_round_trip() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    conformance::blobs_round_trip(&host);
}

#[test]
fn git_pack_round_trip_between_two_hosts() {
    require_git();
    let source = Scratch::new();
    let sink = Scratch::new();
    conformance::pack_round_trip(&source.host(), &sink.host());
}

#[test]
fn git_cas_conflicts_are_reported() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    conformance::cas_conflicts_are_reported(&host);
}

#[test]
fn git_multi_ref_writes_are_all_or_nothing() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    conformance::multi_ref_writes_are_all_or_nothing(&host);
}

#[test]
fn git_describe_and_capabilities() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    conformance::describe_and_capabilities(&host);
    let info = host.describe();
    assert_eq!(info.kind, HostKind::Git);
    assert_eq!(info.kind.as_str(), "git");
    assert!(info.implemented_by.contains("git"), "{info:?}");
    let caps = host.capabilities();
    assert!(caps.cas, "a git remote can lease, so a merge can be gated");
    assert!(
        caps.atomic_multi_write,
        "`git push --atomic` is a transaction on the receiving side"
    );
}

// ---------------------------------------------------------------------------
// What only a git-backed host can be asked.
// ---------------------------------------------------------------------------

/// The whole point of the namespace conventions: plain `git`, with no gitiup
/// anywhere, can see a change, fetch it, and read the attestation that came in
/// the same packfile.
#[test]
fn a_reviewer_with_plain_git_sees_the_change_and_the_proof() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();

    let record = br#"{"id":"c7","base_ref":"refs/heads/main"}"#.to_vec();
    let record_oid = host.put_cas(&Namespace::CHANGE, &record).unwrap();
    let attestation = format!("digest={} signer=ada", record_oid.short(12));
    let attestation_oid = host
        .put_cas(&Namespace::ATTESTATION, attestation.as_bytes())
        .unwrap();
    let change = RefName::change_head("c7").unwrap();
    let proof = RefName::attestation(&record_oid);
    host.update_refs_cas(&[
        RefUpdate::create(change.clone(), record_oid).with_actor("contributor"),
        RefUpdate::create(proof.clone(), attestation_oid).with_actor("ada"),
    ])
    .expect("publish change and proof together");

    // What `git ls-remote` advertises — the namespaces are the API.
    let listing = plain_git(
        &scratch.repo,
        &["ls-remote", "--get", "refs/changes/c7/head", "."],
    );
    let advertised = plain_git(&scratch.repo, &["for-each-ref", "--format=%(refname)"]);
    assert!(advertised.contains("refs/changes/c7/head"), "{advertised}");
    assert!(
        advertised.contains(&format!("refs/attestations/{record_oid}")),
        "{advertised}"
    );
    let _ = listing;

    // A stranger clones with plain git and fetches the change namespace.
    let clone = scratch._dir.path().join("clone");
    let out = Command::new("git")
        .args(["clone", "--bare"])
        .arg(&scratch.repo)
        .arg(&clone)
        .output()
        .expect("git clone");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new("git")
        .args(["fetch", "origin", "refs/changes/*:refs/changes/*"])
        .current_dir(&clone)
        .output()
        .expect("git fetch");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tip = plain_git(&clone, &["rev-parse", "refs/changes/c7/head"]);

    // The pointer commit carries the record itself, so the attestation is in this
    // clone already: no second protocol, no download.
    let bytes = Command::new("git")
        .args(["cat-file", "blob", &format!("{tip}:record")])
        .current_dir(&clone)
        .output()
        .expect("git cat-file");
    assert_eq!(
        bytes.stdout, record,
        "the change record rode along with the ref"
    );
    let doc: serde_json::Value = serde_json::from_slice(
        &Command::new("git")
            .args(["cat-file", "blob", &format!("{tip}:gitiup-ref.json")])
            .current_dir(&clone)
            .output()
            .expect("git cat-file doc")
            .stdout,
    )
    .unwrap();
    assert_eq!(doc["oid"], record_oid.hex());
    assert_eq!(doc["updated_by"], "contributor");

    // And gitiup, pointed at the same repository, agrees with what git says.
    let peer = scratch.peer("reviewer");
    assert_eq!(peer.get_ref(&change).unwrap().unwrap().oid, record_oid);
    assert_eq!(peer.get_ref(&proof).unwrap().unwrap().oid, attestation_oid);
}

/// A ref whose value is a real commit stays exactly what it looks like: git.
#[test]
fn git_native_refs_stay_plain_git() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();

    // Somebody pushes a branch with plain git, the way an owner would.
    let work = scratch._dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(&work)
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&[
        "-c",
        "user.email=ada@example.com",
        "-c",
        "user.name=Ada",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "first",
    ]);
    let sha = git(&["rev-parse", "HEAD"]);
    git(&[
        "push",
        "-q",
        &scratch.repo.to_string_lossy(),
        &format!("{sha}:refs/heads/main"),
    ]);

    let main = RefName::branch("main").unwrap();
    let reference = host.get_ref(&main).unwrap().expect("the branch is there");
    assert_eq!(
        reference.oid.hex(),
        sha,
        "a plain commit is reported as the commit, not wrapped"
    );
    assert_eq!(reference.schema, None, "gitiup did not write this ref");
    assert_eq!(
        reference
            .updated_by
            .map(|actor| actor.to_string())
            .as_deref(),
        Some("Ada"),
        "git's own authorship is the metadata for a git-native ref"
    );

    // And it can be moved with a lease like any other ref.
    let next = host
        .update_ref_cas(&RefUpdate::replace(
            main.clone(),
            reference.oid,
            reference.oid,
        ))
        .unwrap();
    assert_eq!(next.oid, reference.oid);
    let err = host
        .update_ref_cas(&RefUpdate::replace(
            main.clone(),
            Oid::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap(),
            reference.oid,
        ))
        .expect_err("a stale expectation must not move the branch");
    assert_eq!(err.kind(), HostErrorKind::Conflict);
    match &err {
        gitiup_host::HostError::Conflict(conflict) => {
            assert_eq!(conflict.name, "refs/heads/main");
            assert_eq!(conflict.found, Some(reference.oid));
        }
        other => panic!("{other:?}"),
    }
}

/// The store's own refs are layout, not content: they stay out of `list_refs`
/// until someone asks for that prefix.
#[test]
fn store_refs_stay_out_of_the_listing() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let oid = host
        .put_cas(&Namespace::ROSTER, b"{\"verifiers\":3}")
        .unwrap();
    host.update_ref_cas(&RefUpdate::create(RefName::gitiup("roster").unwrap(), oid))
        .unwrap();

    let listed: Vec<String> = host
        .list_refs(&RefQuery::all())
        .unwrap()
        .into_iter()
        .map(|reference| reference.name.to_string())
        .collect();
    assert_eq!(listed, vec!["refs/gitiup/roster".to_string()], "{listed:?}");

    let store: Vec<String> = host
        .store_refs()
        .unwrap()
        .into_iter()
        .map(|reference| reference.name.to_string())
        .collect();
    assert!(store.contains(&format!("{KV_ROOT}/roster")), "{store:?}");
    assert!(store.contains(&"refs/gitiup/host".to_string()), "{store:?}");

    // Asking for the prefix explicitly gets the chains, and `git ls-remote` always
    // did.
    let kv: Vec<String> = host
        .list_refs(&RefQuery::prefix(KV_ROOT))
        .unwrap()
        .into_iter()
        .map(|reference| reference.name.to_string())
        .collect();
    assert!(kv.contains(&format!("{KV_ROOT}/roster")), "{kv:?}");
}

/// A ref name that would collide with the record store is refused with the reason,
/// rather than as a weird git error at push time.
#[test]
fn the_record_store_namespace_is_reserved() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let oid = host.put_cas(&Namespace::RECORD, b"x").unwrap();
    for reserved in [KV_ROOT, "refs/gitiup/host"] {
        let err = host
            .update_ref_cas(&RefUpdate::create(RefName::new(reserved).unwrap(), oid))
            .expect_err("reserved");
        assert_eq!(err.kind(), HostErrorKind::Invalid, "{reserved}: {err}");
        assert!(
            err.to_string().contains("reserved") || reserved == "refs/gitiup/host",
            "{err}"
        );
    }
    // The prefix below the root is the store's, and a person's ref may not be a
    // directory git cannot also be a file.
    let err = host
        .delete_ref_cas(&RefDeletion::new(
            RefName::new(KV_ROOT).unwrap(),
            Expect::Any,
        ))
        .expect_err("deleting the record store root is refused");
    assert_eq!(err.kind(), HostErrorKind::Invalid);
}

/// Two contributors publish records at once. Both land, because the append is a
/// leased push and the loser rebuilds on the winner's tip.
#[test]
fn concurrent_record_appends_both_land() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let handles: Vec<_> = (0..6)
        .map(|i| {
            let remote = scratch.peer_remote(&format!("writer{i}"));
            std::thread::spawn(move || {
                let host = GitHost::open(&remote).expect("open for writer");
                host.put_cas(
                    &Namespace::ATTESTATION,
                    format!("attestation {i}").as_bytes(),
                )
                .expect("put under contention")
            })
        })
        .collect();
    let oids: Vec<Oid> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let listed = host.list(&Namespace::ATTESTATION).unwrap();
    for oid in &oids {
        assert!(
            listed.iter().any(|entry| &entry.oid == oid),
            "{oid} was lost: {listed:?}"
        );
    }
    assert_eq!(listed.len(), 6, "one record per writer: {listed:?}");
}

/// A second handle reads what the first wrote — the mirror is not the store, and
/// a stale mirror is re-fetched rather than trusted.
#[test]
fn a_second_clone_sees_the_same_store() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let oid = host
        .put_cas(&Namespace::ATTESTATION, b"signed by someone else")
        .unwrap();
    host.update_ref_cas(&RefUpdate::create(RefName::attestation(&oid), oid))
        .unwrap();

    let peer = scratch.peer("peer");
    assert_eq!(peer.get(&oid).unwrap().unwrap(), b"signed by someone else");
    assert!(peer.get_ref(&RefName::attestation(&oid)).unwrap().is_some());
    let entries = peer.list(&Namespace::ATTESTATION).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].created_at.is_some(),
        "git knows when the record landed: {entries:?}"
    );
    // Cross-host pack transfer, the way `gitiup change submit` moves objects.
    let pack = host
        .fetch_pack(&PackRequest::new([oid]).with_format(PackFormat::Raw))
        .unwrap();
    assert_eq!(pack.object_count().unwrap(), 1);
    assert_eq!(peer.put_pack(&pack).unwrap(), pack.oid());
}

/// A git packfile round-trips: `put_pack` ingests it, and a later fetch can serve
/// the same objects back out.
#[test]
fn git_packfiles_are_ingested_and_served() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();

    // Build a real commit in a throwaway repo and pack it.
    let work = scratch._dir.path().join("packme");
    std::fs::create_dir_all(&work).unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(&work)
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    std::fs::write(work.join("hello"), b"pack me").unwrap();
    git(&["add", "hello"]);
    git(&[
        "-c",
        "user.email=a@b",
        "-c",
        "user.name=a",
        "commit",
        "-q",
        "-m",
        "packed",
    ]);
    let sha = git(&["rev-parse", "HEAD"]);
    // A real packfile: the commit *and* the trees and blobs it needs, which is
    // what `rev-list --objects | pack-objects` produces for a fetch.
    let pack_bytes = Command::new("git")
        .args(["rev-list", "--objects", &sha])
        .current_dir(&work)
        .stdout(std::process::Stdio::piped())
        .output()
        .expect("rev-list")
        .stdout;
    let pack_bytes = Command::new("git")
        .args([
            "-c",
            "pack.threads=1",
            "pack-objects",
            "--stdout",
            "--delta-base-offset",
        ])
        .current_dir(&work)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(&pack_bytes)?;
            child.wait_with_output()
        })
        .expect("pack-objects")
        .stdout;
    let pack = Pack::git_packfile(pack_bytes).expect("a real packfile");
    assert_eq!(pack.format, PackFormat::GitPackfile);

    let pack_oid = host.put_pack(&pack).unwrap();
    assert_eq!(pack_oid, pack.oid());
    // The objects are here now, and a fetch can rebuild a pack for them.
    let again = host
        .fetch_pack(
            &PackRequest::new([Oid::from_hex(&sha).unwrap()]).with_format(PackFormat::GitPackfile),
        )
        .expect("fetch a git packfile");
    assert_eq!(again.format, PackFormat::GitPackfile);
    assert!(!again.is_empty());
    // The packfile is also addressable as a record, so it survives on the remote
    // even before any ref points at it.
    assert_eq!(host.get(&pack_oid).unwrap().unwrap(), pack.bytes);
}

/// Deleting a ref that exists is a CAS too: a stale expectation is a conflict, and
/// a matching one removes it — checked with plain `git`.
#[test]
fn deleting_a_ref_is_a_leased_push() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let oid = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"gone\"}")
        .unwrap();
    let name = RefName::change_head("gone").unwrap();
    host.update_ref_cas(&RefUpdate::create(name.clone(), oid))
        .expect("create");
    let wrong = Oid::from_hex("1111111111111111111111111111111111111111").unwrap();
    let err = host
        .delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(wrong)))
        .expect_err("a delete must match what is there");
    assert!(err.is_conflict(), "{err}");
    host.delete_ref_cas(&RefDeletion::new(name.clone(), Expect::Is(oid)))
        .expect("delete with the right expectation");
    assert!(host.get_ref(&name).unwrap().is_none());
}

/// A read-only remote is a capability answer, not a failed push: `cas` goes false
/// and every write refuses with `UnsupportedCas` before anything is sent. This is
/// the dumb-HTTP shape.
#[test]
fn a_read_only_remote_refuses_before_it_tries() {
    require_git();
    let scratch = Scratch::new();
    let writable = scratch.host();
    let oid = writable
        .put_cas(&Namespace::ATTESTATION, b"proof for a static mirror")
        .unwrap();
    writable
        .update_ref_cas(&RefUpdate::create(RefName::attestation(&oid), oid))
        .unwrap();

    let remote = RemoteConfig::new("mirror", &format!("file://{}", scratch.repo.display()))
        .unwrap()
        .with_option(
            "work-dir",
            scratch
                .mirror
                .with_extension("readonly")
                .display()
                .to_string(),
        )
        .with_option("read-only", "true");
    let host = GitHost::open(&remote).expect("open read-only");
    let caps = host.capabilities();
    assert!(!caps.cas, "nothing can be written here");
    assert!(caps.immutable, "records still cannot be rewritten");
    assert_eq!(caps.missing(), vec!["cas", "atomic-multi-write"]);

    let err = host
        .update_ref_cas(&RefUpdate::create(RefName::branch("nope").unwrap(), oid))
        .expect_err("a read-only host refuses");
    assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
    assert!(err.hint().unwrap().contains("read-only"), "{err}");
    assert!(host.put_cas(&Namespace::RECORD, b"nope").is_err());
    // Reads work, which is the entire point of a static mirror.
    assert_eq!(
        host.get_ref(&RefName::attestation(&oid))
            .unwrap()
            .unwrap()
            .oid,
        oid
    );
    assert_eq!(
        host.get(&oid).unwrap().unwrap(),
        b"proof for a static mirror"
    );
}

/// Options are read, and an option this host does not read is advice rather than
/// silence (the same rule the bucket host follows).
#[test]
fn options_are_read_and_typos_become_advice() {
    let remote = RemoteConfig::new("origin", "ssh://git@colo.example/srv/git/repo.git")
        .unwrap()
        .with_option("work-dir", "/tmp/mirror")
        .with_option("ref-cache-ttl", "30s")
        .with_option("cas-attempts", "9")
        .with_option("cas-backoff", "5ms")
        .with_option("push-probe", "off")
        .with_option("read-only", "false")
        .with_option("ssh-command", "ssh -o ProxyJump=bastion")
        .with_option("key-path", "/home/ada/id_ed25519")
        .with_option("git-config.http.sslVerify", "false")
        .with_option("pack-threads", "2")
        .with_option("conditional-writes", "on");
    let (options, advice) = GitOptions::from_remote(&remote, None).unwrap();
    assert_eq!(options.ref_cache_ttl, std::time::Duration::from_secs(30));
    assert_eq!(options.cas_attempts, 9);
    assert_eq!(options.cas_backoff, std::time::Duration::from_millis(5));
    assert_eq!(options.push_probe, gitiup_host::hosts::git::Probe::Off);
    assert_eq!(
        options.ssh_command.as_deref(),
        Some("ssh -o ProxyJump=bastion")
    );
    assert_eq!(
        options.key_path,
        Some(PathBuf::from("/home/ada/id_ed25519"))
    );
    assert_eq!(options.pack_threads, Some(2));
    assert_eq!(
        options.git_config,
        // git config keys are case-insensitive, and `RemoteConfig` lower-cases
        // option keys on the way in, so what reaches `-c` is lower-cased too.
        vec![("http.sslverify".to_string(), "false".to_string())]
    );
    assert_eq!(advice.len(), 1, "{advice:?}");
    assert!(advice[0].contains("conditional-writes"), "{advice:?}");

    // A bad value is an error, not a shrug.
    let bad = RemoteConfig::new("origin", "file:///srv/git/repo.git")
        .unwrap()
        .with_option("push-probe", "maybe");
    let err = GitOptions::from_remote(&bad, None).unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid);
}

/// `open` distinguishes "not a gitiup store" from "not reachable", so the fix each
/// one suggests is the right one.
#[test]
fn open_reports_the_difference_between_empty_missing_and_unreachable() {
    require_git();
    let scratch = Scratch::new();
    // A bare repository nobody has initialised.
    let err = GitHost::open(&scratch.remote()).expect_err("no store yet");
    assert_eq!(err.kind(), HostErrorKind::NotFound);
    assert!(err.hint().unwrap().contains("GitHost::init"), "{err}");

    // Nothing at that path at all.
    let missing = RemoteConfig::new(
        "ghost",
        &format!(
            "file://{}",
            scratch._dir.path().join("does-not-exist.git").display()
        ),
    )
    .unwrap()
    .with_option(
        "work-dir",
        scratch.mirror.with_extension("ghost").display().to_string(),
    );
    let err = GitHost::open(&missing).expect_err("no repository");
    assert_eq!(err.kind(), HostErrorKind::NotFound, "{err}");
    assert!(err.to_string().contains("repository"), "{err}");

    // `init` twice is a conflict-shaped refusal with the reason, not a clobber.
    GitHost::init(&scratch.remote()).expect("init");
    let err = GitHost::init(&scratch.remote()).expect_err("init twice");
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    assert!(err.hint().unwrap().contains("GitHost::open"), "{err}");

    // A host that is not a git remote at all says so by scheme.
    let bucket = RemoteConfig::new("s3", "s3://bucket/prefix").unwrap();
    assert_eq!(
        GitHost::open(&bucket).err().unwrap().kind(),
        HostErrorKind::SchemeUnknown
    );
}

/// Round-tripping through the git host keeps records byte-exact, which is what
/// keeps an attestation signature valid.
#[test]
fn records_are_stored_verbatim() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).cycle().take(9_000).collect();
    let oid = host.put_cas(&Namespace::ATTESTATION, &bytes).unwrap();
    assert_eq!(host.get(&oid).unwrap().unwrap(), bytes);
    let entry = host.head(&oid).unwrap().unwrap();
    assert_eq!(entry.size, bytes.len() as u64);
    assert_eq!(entry.namespace, Namespace::ATTESTATION);
    // A short digest is not a record address, and says so by returning nothing
    // rather than scanning every chain.
    assert!(!host.exists(&Oid::from_hex("aabb").unwrap()).unwrap());
}

/// Concurrent create-only writes to the same ref: exactly one winner, as the `fs`
/// host promises and as the merge gate needs.
#[test]
fn concurrent_create_only_writes_have_one_winner() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let oid = host
        .put_cas(&Namespace::CHANGE, b"{\"id\":\"race\"}")
        .unwrap();
    let name = RefName::change_head("race").unwrap();
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let remote = scratch.peer_remote(&format!("racer{i}"));
            let name = name.clone();
            std::thread::spawn(move || {
                let host = GitHost::open(&remote).expect("open");
                host.update_ref_cas(&RefUpdate::create(name, oid).with_actor(format!("w{i}")))
                    .is_ok()
            })
        })
        .collect();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(winners, 1, "a create-only CAS write has exactly one winner");
    let refs: Vec<Ref> = host
        .list_refs(&RefQuery::prefix(gitiup_host::refs::ns::CHANGES))
        .unwrap();
    assert_eq!(refs.len(), 1);
}

/// An `ssh://` remote is a first-class transport here even though these tests
/// cannot run an sshd: the URL is accepted, and a remote that is not answering
/// comes back as `Unreachable` — the one taxonomy answer that tells a caller to
/// back off and try later rather than give up.
#[test]
fn an_ssh_remote_that_is_not_answering_is_unreachable() {
    require_git();
    // Port 1 on the loopback interface is refused immediately on any box with
    // sshd absent, which is the situation this test can create on purpose.
    let remote = RemoteConfig::new("origin", "ssh://git@127.0.0.1:1/srv/git/repo.git")
        .expect("ssh url")
        .with_option("work-dir", Scratch::new().mirror.display().to_string())
        .with_option("ssh-command", "ssh -o ConnectTimeout=2 -o BatchMode=yes");
    let error = GitHost::open(&remote).expect_err("nothing is listening");
    assert!(
        error.is_unreachable(),
        "a refused ssh connection is a transport answer, not a corrupt store: {error}"
    );
    assert!(error.hint().is_some(), "{error}");
}

// ---------------------------------------------------------------------------
// Attestation storage (giti-1rs.5) over the git transport.
// ---------------------------------------------------------------------------

/// The headline claim of the attestation ticket, tested with the literal tool it
/// names: a proof about a commit lives under `refs/attestations/**`, so a stranger
/// with plain `git` and no gitiup anywhere fetches the attestation *in the same
/// packfile as the ref that names it*. No second protocol, no API, no download
/// afterwards — which is the difference between "the store can serve the proof" and
/// "the store can tell you where it keeps the proof".
#[test]
fn a_plain_clone_fetches_a_commits_attestations() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    // A commit oid, in this case a real sha1: the attestation namespace is keyed by
    // the object attested, so the listing question is a ref lookup on every host.
    let commit = Oid::from_hex("e255b091aabd7e443b5d2fbeb90bc9769d07cbeb").unwrap();
    let ada = b"{signed-by:ada,tier:local}".to_vec();
    let bruno = b"{signed-by:bruno,tier:local}".to_vec();
    let first = gitiup_host::attest::publish(&host, &commit, &ada, "ada").expect("publish ada");
    let second =
        gitiup_host::attest::publish(&host, &commit, &bruno, "bruno").expect("publish bruno");

    // Two handles, two mirrors: what the reviewer's machine sees is what the
    // repository says, not what this process wrote.
    let reviewer = scratch.peer("reviewer");
    let catalog = gitiup_host::attest::list_for(&reviewer, &commit).expect("list");
    let digests: BTreeSet<String> = catalog
        .entries
        .iter()
        .map(|entry| entry.digest.hex())
        .collect();
    assert_eq!(
        digests,
        BTreeSet::from([first.digest.hex(), second.digest.hex()]),
        "both attestations for this commit are advertised, and the store can say who \
         published each: {:?}",
        catalog.entries
    );
    assert!(catalog.unexpected.is_empty(), "{catalog:?}");
    assert_eq!(
        gitiup_host::attest::fetch(&reviewer, &first.digest)
            .expect("fetch")
            .expect("present"),
        ada,
        "the bytes come back verbatim, which is what a signature is checked against"
    );

    // Now with nothing but git: clone, fetch the namespace, read the proof out of
    // the pointer commit the ref names.
    let clone = scratch._dir.path().join("clone.git");
    let out = Command::new("git")
        .args(["clone", "--bare"])
        .arg(&scratch.repo)
        .arg(&clone)
        .output()
        .expect("git clone");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new("git")
        .args(["fetch", "origin", "refs/attestations/*:refs/attestations/*"])
        .current_dir(&clone)
        .output()
        .expect("git fetch");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let advertised = plain_git(&clone, &["for-each-ref", "--format=%(refname)"]);
    for entry in &catalog.entries {
        assert!(
            advertised.contains(entry.reference.as_str()),
            "the attestation ref must be fetchable by a plain git client: {advertised}"
        );
        let tip = plain_git(&clone, &["rev-parse", entry.reference.as_str()]);
        let record = plain_git(&clone, &["cat-file", "blob", &format!("{tip}:record")]);
        let expected = if entry.digest == first.digest {
            &ada
        } else {
            &bruno
        };
        assert_eq!(
            record.as_bytes(),
            expected.as_slice(),
            "the attestation bytes arrived with the ref, in the same packfile"
        );
        // And the pointer document says what the ref promised, so a reviewer can
        // check the store did not quietly re-encode the signed bytes.
        let pointer = plain_git(
            &clone,
            &["cat-file", "blob", &format!("{tip}:gitiup-ref.json")],
        );
        assert!(
            pointer.contains(&entry.digest.hex()),
            "the pointer names the digest the ref is keyed by: {pointer}"
        );
    }
}

/// Retention on a git host is honest about what a git object database cannot do: it
/// withdraws the advertisement and reports that the bytes stay. Refusing and saying
/// so beats a report that implies space was reclaimed.
#[test]
fn retiring_an_attestation_unpublishes_it_and_says_the_bytes_stay() {
    require_git();
    let scratch = Scratch::new();
    let host = scratch.host();
    let commit = Oid::from_hex("1111111111111111111111111111111111111111").unwrap();
    let bytes = b"{expired-proof}".to_vec();
    let published = gitiup_host::attest::publish(&host, &commit, &bytes, "ada").expect("publish");
    let item = gitiup_host::attest::AttestationItem {
        digest: published.digest,
        subject: commit,
        claimed_at_us: 1,
        size: bytes.len() as u64,
        label: None,
        reference: Some(published.reference.as_str().to_string()),
    };
    let policy = gitiup_host::attest::Retention {
        max_age_us: Some(1_000),
        max_per_subject: None,
    };
    let plan = gitiup_host::attest::plan(&policy, 10_000_000, &[item], &BTreeMap::new());
    let report = gitiup_host::attest::apply(
        &host,
        &plan,
        &BTreeMap::new(),
        &gitiup_host::attest::GcOptions {
            dry_run: false,
            purge_blobs: true,
            ..Default::default()
        },
    )
    .expect("apply");
    assert_eq!(report.pruned.len(), 1, "{report:?}");
    assert!(
        matches!(
            report.pruned[0].blob,
            gitiup_host::attest::BlobAction::Refused { .. }
        ),
        "a git store cannot forget one object, and must say that rather than pretend: {:?}",
        report.pruned[0]
    );
    assert!(
        gitiup_host::attest::list_for(&host, &commit)
            .expect("list")
            .entries
            .is_empty(),
        "the attestation is no longer advertised, which is what retiring means"
    );
    // The record chain still holds it: `refs/gitiup/kv/attestation` is append-only
    // by design, so the audit trail outlives the advertisement.
    assert_eq!(
        gitiup_host::attest::fetch(&host, &published.digest)
            .expect("fetch")
            .expect("still there"),
        bytes
    );
}

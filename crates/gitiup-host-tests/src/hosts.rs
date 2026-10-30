//! Every host the suite covers, in one file, so "who is measured" is a question
//! with one answer.
//!
//! Each registration is a `const`: its name, how to build one, what it may decline
//! and why. [`all`] is the list CI's coverage test walks, and
//! [`test_host!`](crate::test_host!) turns any one of them into `#[test]`s.
//!
//! Three shapes recur:
//!
//! * the host itself, from [`Make`] once per body so every body starts from an
//!   empty store;
//! * a **refused-credentials** variant, because "expired" is a state a working
//!   endpoint cannot be asked to enter on command — so the git one is a server that
//!   only says no, the in-memory bucket one is a bucket that only says no, and the
//!   live bucket one is CI handing the run revoked credentials;
//! * a **`cas = false`** variant, because a host that cannot do compare-and-swap
//!   has to be measured refusing, not measured succeeding.
//!
//! The environment knobs the live ones read are documented on each registration.

use std::path::{Path, PathBuf};

use gitiup_host::hosts::git::GitHost;
use gitiup_host::{BlobStore, RefStore};
use gitiup_host::{FsHost, HostError, HostKind, HostResult, Namespace, RemoteConfig, S3Host};

use crate::fixtures::{
    BareRepo, DeniedBucket, GitServer, PublicBucket, Scratch, dumb_bucket, paged_bucket,
    refused_server, served_git_server, shared, static_server,
};
use crate::registration::{Knobs, Registration, Session};

/// A host is only worth measuring if `git` is here to measure it with.
fn have_git() -> bool {
    gitiup_host::hosts::git::git_program().is_some()
}

// ---------------------------------------------------------------------------
// fs — the reference host: a directory.
// ---------------------------------------------------------------------------

fn make_fs() -> HostResult<Session> {
    let scratch = Scratch::new("fs");
    let host = FsHost::create(scratch.path())?;
    Ok(Session::new(host).with(scratch))
}

/// The reference host: a bare directory with a refs file and a content-addressed
/// tree. Everything else in the workspace is measured against what this one does.
pub const FS: Registration = Registration {
    name: "fs",
    kind: HostKind::Fs,
    make: make_fs,
    available: || true,
    unavailable: "the fs host needs nothing but a writable temp directory",
    knobs: Knobs {
        pack_bytes: 4 * 1024 * 1024,
        list_count: 130,
        ref_count: 40,
        writers: 8,
    },
    skips: &[
        (
            "refused_credentials_are_denied_not_dropped",
            "the fs host has no credentials: its auth model is the filesystem, and a local \
             EACCES is a Storage error by design rather than a PermissionDenied",
        ),
        (
            "a_host_without_cas_refuses_cas_writes",
            "a directory with a lock file can always promise compare-and-swap, so there is no \
             degraded shape of this host to measure",
        ),
        (
            "a_public_store_reads_with_no_credential",
            "a directory's credential is the filesystem: there is no anonymous reader of a path \
             who is not also somebody the operating system already authorised",
        ),
        (
            "a_credential_never_arrives_at_the_redirect_target",
            "a path cannot redirect: the decoy run needs a transport with an origin, which the \
             smart-HTTP and forge registrations have",
        ),
    ],
    denied: None,
    denied_available: always,
    denied_unavailable: "",
    denied_secret: || None,
    degraded: None,
    degraded_available: always,
    degraded_unavailable: "",
    anonymous: None,
    anonymous_available: always,
    anonymous_unavailable: "",
    decoy: None,
    decoy_available: always,
    decoy_unavailable: "",
};

// ---------------------------------------------------------------------------
// git — a bare repository, three ways.
// ---------------------------------------------------------------------------

fn make_git_file() -> HostResult<Session> {
    let scratch = Scratch::new("git-file");
    let repo = BareRepo::create(scratch.path(), "repo")?;
    let remote = remote_at(
        &format!("file://{}", repo.path.display()),
        &scratch.join("mirror"),
    );
    let host = GitHost::open_or_init(&remote)?;
    Ok(Session::new(host).with(scratch))
}

/// A bare repository on a local path — the shape an owner sshes into, and the one
/// every other git test in the workspace uses.
pub const GIT_FILE: Registration = Registration {
    name: "git-file",
    kind: HostKind::Git,
    make: make_git_file,
    available: have_git,
    unavailable: "no git binary on this box: the plain-git host *is* the git binary",
    knobs: Knobs {
        // Every record append is a commit and a push, so the counts stay modest:
        // the body is about correctness, and the heavy counts run against the
        // bucket in CI.
        pack_bytes: 4 * 1024 * 1024,
        list_count: 40,
        ref_count: 20,
        writers: 4,
    },
    skips: &[
        (
            "refused_credentials_are_denied_not_dropped",
            "a repository reached over file:// is authorised by the filesystem, not by \
             credentials; the smart-HTTP registration covers a refused endpoint",
        ),
        (
            "a_host_without_cas_refuses_cas_writes",
            "a local bare repository has refs --force-with-lease, so it always has CAS; the \
             smart-HTTP registration covers the read-only mirror that does not",
        ),
        (
            "a_public_store_reads_with_no_credential",
            "a repository under a path is readable by whoever the filesystem allows; the \
             smart-HTTP registration covers the anonymous reader over a transport",
        ),
        (
            "a_credential_never_arrives_at_the_redirect_target",
            "file:// has no origin to redirect from; the decoy run needs a client that carries \
             its own token, which the forge registration has",
        ),
    ],
    denied: None,
    denied_available: always,
    denied_unavailable: "",
    denied_secret: || None,
    degraded: None,
    degraded_available: always,
    degraded_unavailable: "",
    anonymous: None,
    anonymous_available: always,
    anonymous_unavailable: "",
    decoy: None,
    decoy_available: always,
    decoy_unavailable: "",
};

fn make_git_http() -> HostResult<Session> {
    let server = served_git_server().ok_or_else(|| {
        HostError::invalid(
            "git-http-backend",
            "no smart-HTTP endpoint is available for this registration",
        )
    })?;
    let scratch = Scratch::new("git-http");
    let name = format!("repo-{}", crate::fixtures::next());
    let repo = BareRepo::create(&server.root(), &name)?;
    let remote = remote_at(
        &format!("{}/{name}.git", server.base()),
        &scratch.join("mirror"),
    );
    let host = GitHost::open_or_init(&remote)?;
    // The repository belongs to this body: drop it when the body finishes, or the
    // served root fills up with one repository per test.
    Ok(Session::new(host)
        .with(scratch)
        .with(Cleanup(repo.path.clone())))
}

/// A bare repository served over smart HTTP by `git-http-backend` — the shape
/// that needs a forge's *promise* (leases over a network) rather than a
/// filesystem lock, which is why it also carries the refused and degraded shapes.
///
/// Environment: `GITIUP_CONFORMANCE_GIT_HTTP_URL` and
/// `GITIUP_CONFORMANCE_GIT_ROOT` point at a server CI already runs; without them
/// the suite spawns the python CGI fixture itself.
pub const GIT_HTTP: Registration = Registration {
    name: "git-http",
    kind: HostKind::Git,
    make: make_git_http,
    available: || have_git() && GitServer::available(),
    unavailable: crate::fixtures::NO_SMART_HTTP,
    knobs: Knobs {
        pack_bytes: 4 * 1024 * 1024,
        list_count: 40,
        ref_count: 20,
        writers: 4,
    },
    skips: &[(
        "a_credential_never_arrives_at_the_redirect_target",
        "the plain-git host holds no credential to leak: `git` owns that transport, and a \
         profile that names a token for a git remote is refused as a contradiction before any \
         subprocess starts (`refused_credentials_are_denied_not_dropped`, and \
         `GitHost::check_credentials`). The decoy run needs a client that carries its own \
         token, which is the forge registration over the decoy endpoint",
    )],
    denied: Some(make_git_refused),
    denied_available: have_git,
    denied_unavailable: "the refusing endpoint needs the git binary",
    denied_secret: || None,
    degraded: Some(make_git_dumb_http),
    degraded_available: have_git,
    degraded_unavailable: "the static-file endpoint needs the git binary",
    anonymous: Some(make_git_http_anonymous),
    anonymous_available: || have_git() && GitServer::available(),
    anonymous_unavailable: crate::fixtures::NO_SMART_HTTP,
    decoy: None,
    decoy_available: always,
    decoy_unavailable: "",
};

/// Publish one change and one attestation, through the transport the *owner* has, so a
/// stranger has something to read.
///
/// Both registrations with an anonymous shape use it, over whatever handle can write: the
/// point is only that the store is not empty when the stranger arrives, because "public
/// but empty" and "not allowed" must be told apart and there has to be a *something* to
/// tell apart.
fn seed_public_store(host: &dyn gitiup_host::Host) -> HostResult<()> {
    let record = br#"{"id":"public-1","state":"open"}"#;
    let record_oid = host.put_cas(&Namespace::ATTESTATION, record)?;
    host.update_ref_cas(
        &gitiup_host::RefUpdate::create(gitiup_host::RefName::attestation(&record_oid), record_oid)
            .with_actor("owner"),
    )?;
    Ok(())
}

/// The same served repository, read by somebody with nothing.
///
/// No profile, no token, no `GIT_*` credential anywhere: this is the stranger a public
/// mirror exists for, and every assertion the body makes is made through this handle. The
/// publish half runs over `file://` — the owner's shell, not the stranger's transport —
/// which is exactly how a public mirror really gets its content.
fn make_git_http_anonymous() -> HostResult<Session> {
    let server = served_git_server().ok_or_else(|| {
        HostError::invalid(
            "git-http-backend",
            "no smart-HTTP endpoint is available for this registration",
        )
    })?;
    let scratch = Scratch::new("git-http-anonymous");
    let name = format!("public-{}", crate::fixtures::next());
    let repo = BareRepo::create(&server.root(), &name)?;
    let owner = remote_at(
        &format!("file://{}", repo.path.display()),
        &scratch.join("owner"),
    );
    let published = GitHost::open_or_init(&owner)?;
    seed_public_store(&published)?;
    drop(published);

    let stranger = remote_at(
        &format!("{}/{name}.git", server.base()),
        &scratch.join("mirror"),
    );
    let host = GitHost::open(&stranger)?;
    Ok(Session::new(host)
        .with(scratch)
        .with(Cleanup(repo.path.clone())))
}

/// A smart-HTTP endpoint that refuses every request: what an expired token or a
/// pulled key looks like to a client that still has the URL.
fn make_git_refused() -> HostResult<Session> {
    let server = refused_server().ok_or_else(|| {
        HostError::invalid("git-refused", "no refusing endpoint could be started")
    })?;
    let scratch = Scratch::new("git-refused");
    let remote = remote_at(
        &format!("{}/repo.git", server.base()),
        &scratch.join("mirror"),
    );
    // Refusing at connect time is the expected answer, and the body judges the
    // shape of the refusal either way, so `?` is all the plumbing needed.
    let host = GitHost::open_or_init(&remote)?;
    Ok(Session::new(host).with(scratch))
}

/// A repository published to a static file server: a legitimate release mirror,
/// and the case where `cas = false` is not a configuration mistake but the truth.
fn make_git_dumb_http() -> HostResult<Session> {
    let scratch = Scratch::new("git-static");
    let repo = BareRepo::create(scratch.path(), "repo")?;
    // Seed it through the path the server has no idea about: this is how a mirror
    // gets its content in the first place — someone with a shell runs the push.
    let seed_remote = remote_at(
        &format!("file://{}", repo.path.display()),
        &scratch.join("seed-mirror"),
    );
    let seed = GitHost::open_or_init(&seed_remote)?;
    let oid = seed.put_cas(&Namespace::ATTESTATION, b"{\"mirrored\":true}")?;
    let branch = gitiup_host::RefName::branch("mirror").expect("valid ref name");
    seed.update_ref_cas(&gitiup_host::RefUpdate::create(branch, oid))
        .expect("seed the mirrored store");
    repo.publish_for_static_server()?;

    let server = static_server(scratch.path()).ok_or_else(|| {
        HostError::invalid("git-static", "no static file server could be started")
    })?;
    let remote = remote_at(
        &format!("{}/repo.git", server.base()),
        &scratch.join("mirror"),
    )
    .with_option("read-only", "true");
    let host = GitHost::open(&remote)?;
    Ok(Session::new(host).with(scratch).with(server))
}

// ---------------------------------------------------------------------------
// s3 — a bucket as the forge, in memory and live.
// ---------------------------------------------------------------------------

fn memory_remote(name: &str) -> RemoteConfig {
    RemoteConfig::new("origin", &format!("s3://{name}/my-repo")).expect("a valid bucket url")
}

fn make_s3_memory() -> HostResult<Session> {
    // A small LIST page, so the pagination body paginates even with no network.
    let name = format!("gitiup-forge-{}", crate::fixtures::next());
    let bucket = paged_bucket(&name, 32);
    let host = S3Host::open_or_init(shared(&bucket), &memory_remote(&name))?;
    Ok(Session::new(host).with(bucket))
}

/// The bucket-as-forge host over the in-process bucket: real etags, real 412s,
/// paged listings and staged multipart uploads, no network.
pub const S3_MEMORY: Registration = Registration {
    name: "s3-memory",
    kind: HostKind::S3,
    make: make_s3_memory,
    available: || true,
    unavailable: "the in-memory bucket needs nothing",
    knobs: Knobs {
        // Above the fake's own multipart threshold is what CI cares about; here
        // the point is that the body runs against two independent buckets.
        pack_bytes: 6 * 1024 * 1024,
        list_count: 130,
        ref_count: 40,
        writers: 6,
    },
    skips: &[(
        "a_credential_never_arrives_at_the_redirect_target",
        "the in-process bucket has no HTTP origin to redirect from — there is no socket for a \
         `302` to travel on, and asking a live endpoint to redirect to a decoy would be asking \
         it to be misconfigured",
    )],
    denied: Some(make_s3_denied),
    denied_available: always,
    denied_unavailable: "",
    denied_secret: || None,
    degraded: Some(make_s3_dumb),
    degraded_available: always,
    degraded_unavailable: "",
    anonymous: Some(make_s3_public),
    anonymous_available: always,
    anonymous_unavailable: "",
    decoy: None,
    decoy_available: always,
    decoy_unavailable: "",
};

/// The same bucket as a stranger reads it: a public-read policy, so objects and listings
/// are served to anybody and no write is.
///
/// This is what a public mirror of a private repository actually is, and the shape an
/// operator most often gets wrong: the host has to open it read-only and say so, rather
/// than refuse it for failing the bucket-admin probes (versioning, conditional writes)
/// that an anonymous caller is not allowed to make.
fn make_s3_public() -> HostResult<Session> {
    let name = format!("gitiup-public-{}", crate::fixtures::next());
    let public = PublicBucket::named(&name);
    let remote = memory_remote(&name).with_option("anonymous", "true");
    // The owner, holding real credentials, publishes one attestation into the same
    // bucket; the handle with nothing is what the body then reads.
    let owner = public.owner();
    let published = S3Host::open_or_init(shared(&owner), &remote)?;
    seed_public_store(&published)?;
    drop(published);
    drop(owner);
    let host = S3Host::open(shared(&public), &remote)?;
    Ok(Session::new(host).with(public))
}

/// A bucket that answers every request the way a bucket answers a revoked key.
fn make_s3_denied() -> HostResult<Session> {
    let bucket = DeniedBucket::named("gitiup-revoked");
    let remote = memory_remote("gitiup-revoked");
    let host = S3Host::open_or_init(shared(&bucket), &remote)?;
    Ok(Session::new(host).with(bucket))
}

/// The same host against a bucket whose endpoint ignores conditional writes: the
/// degradation the design refuses to paper over.
fn make_s3_dumb() -> HostResult<Session> {
    let name = format!("gitiup-dumb-{}", crate::fixtures::next());
    let bucket = dumb_bucket(&name);
    let remote = memory_remote(&name).with_option("conditional-writes", "auto");
    let host = S3Host::open_or_init(shared(&bucket), &remote)?;
    Ok(Session::new(host).with(bucket))
}

// ---------------------------------------------------------------------------
// s3, live: a real MinIO or S3 endpoint.
// ---------------------------------------------------------------------------

#[cfg(feature = "s3")]
pub mod live;

/// The live bucket registration exists only when the S3 transport is compiled
/// in; without it there is no live bucket to measure, and `tests/s3_minio.rs`
/// compiles to nothing.
#[cfg(feature = "s3")]
pub use live::{S3_MINIO, minio_configured, minio_denial_configured};

// ---------------------------------------------------------------------------
// the github adapter (feature `github`)
// ---------------------------------------------------------------------------

#[cfg(feature = "github")]
pub mod gh;

#[cfg(feature = "github")]
pub use gh::GITHUB;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A remote for a URL, with the local mirror the plain-git host reads through.
fn remote_at(url: &str, work_dir: &Path) -> RemoteConfig {
    RemoteConfig::new("origin", url)
        .expect("a valid remote url")
        .with_option("work-dir", work_dir.display().to_string())
}

/// Remove a path when the guard drops; the served repositories are per-body.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn always() -> bool {
    true
}

/// The host pairs the cross-host body runs, as `(publisher, merger)`.
///
/// Ordered the way the workflow actually happens: the contributor publishes to the host
/// they have credentials for — a bucket, because that is the cheapest forge-shaped store
/// there is — and the owner merges on the host where their branch lives, which is a plain
/// git repository. The hermetic pair runs everywhere; the live one is the same body over
/// a real MinIO and a real `git-http-backend`, which is the shape CI demands.
pub fn cross_pairs() -> Vec<(&'static str, &'static Registration, &'static Registration)> {
    #[allow(unused_mut)]
    let mut pairs = vec![("s3-memory->git-file", &S3_MEMORY, &GIT_FILE)];
    #[cfg(feature = "s3")]
    pairs.push(("s3-minio->git-http", &S3_MINIO, &GIT_HTTP));
    pairs
}

/// Every registration the suite covers, in the order CI should report them.
///
/// `tests/coverage.rs` walks this and refuses a body that nobody runs, a host kind
/// that nobody covers, and a registration that changed what it claims without
/// saying why.
pub fn all() -> Vec<&'static Registration> {
    // The optional hosts are pushed rather than listed, so a build without either
    // feature does not have to pretend the `mut` was needed.
    #[cfg_attr(not(any(feature = "s3", feature = "github")), allow(unused_mut))]
    let mut hosts: Vec<&'static Registration> = vec![&FS, &GIT_FILE, &GIT_HTTP, &S3_MEMORY];
    #[cfg(feature = "s3")]
    hosts.push(&S3_MINIO);
    #[cfg(feature = "github")]
    hosts.push(&GITHUB);
    hosts
}

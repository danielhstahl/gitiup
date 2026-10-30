//! A copy to and from the forge adapter.
//!
//! [ADR-0005](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! decides what a copy may carry, and [`gitiup_host::federation`] carries it — the ticket's
//! acceptance criterion is that the verbs work "between any two hosts (fs, git, s3, forge
//! adapter), using each host's own pack/CAS path, not a local git subprocess for some and
//! an API for others". The three directory-shaped hosts are covered in `gitiup-host`'s own
//! `tests/federation.rs`; this file is the fourth one, because a forge is the host where
//! "its own CAS path" is a real translation rather than a directory:
//!
//! * a ref is a *pointer commit* over the forge's git object database, not a line in a file,
//!   and a compare-and-swap is check-before/after with the forge's own conflict answer;
//! * a content-addressed record is an object in that database, so `get(digest)` is a fetch
//!   of a blob the forge has never heard of being named by a `sha256:`;
//! * the listing is a paginated API call.
//!
//! So the question this file answers is not "does the copy engine work" (it is the same
//! code) but "does the adapter hold the contract well enough to be one of the ends". The
//! forge is [`MockForge`], the in-process implementation the conformance suite drives, so
//! there is no network and no token here.

use std::sync::Arc;

use gitiup_host::BlobStore as _;
use gitiup_host::attest;
use gitiup_host::blob::Namespace;
use gitiup_host::federation::{self, Options, Verb};
use gitiup_host::{FsHost, Host, Oid, RefName, RefQuery, RefStore, RefUpdate};
use gitiup_host_github::GitHubHost;
use gitiup_host_github::testing::MockForge;

/// The variable the tests put the token in — named so nothing else can pick it up.
const TOKEN_ENV: &str = "GITIUP_HOST_GITHUB_TEST_TOKEN";
const TOKEN: &str = "test-token-8f2b1c4d";

fn remote() -> gitiup_host::RemoteConfig {
    // SAFETY: this variable is named for this test binary and nothing else reads it;
    // every test here sets it to the same value before it reads.
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    let mut remote = gitiup_host::RemoteConfig::new("origin", "https://github.com/gitiup/mock")
        .expect("a github remote");
    remote.credentials_profile = Some("gh".into());
    remote
        .options
        .insert("token-env".to_string(), TOKEN_ENV.to_string());
    remote
}

fn forge_host(forge: &Arc<MockForge>) -> GitHubHost {
    GitHubHost::with_transport(&remote(), forge.transport(), None)
        .expect("the github host opens against the mock forge")
}

/// A directory store in a temp dir, created on first open.
struct FsStore {
    root: std::path::PathBuf,
    created: std::cell::Cell<bool>,
}

impl FsStore {
    fn new(name: &str) -> FsStore {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join(name);
        std::mem::forget(dir);
        FsStore {
            root,
            created: std::cell::Cell::new(false),
        }
    }

    fn open(&self) -> Box<dyn Host> {
        if self.created.get() {
            Box::new(FsHost::open(&self.root).expect("reopen"))
        } else {
            self.created.set(true);
            Box::new(FsHost::create(&self.root).expect("create"))
        }
    }
}

/// File the portable set, plus the arbitration state a copy must refuse.
fn seed(host: &dyn Host) -> Vec<Oid> {
    let subject = Oid::hash_bytes(b"the commit the proofs are about");
    let mut digests = Vec::new();
    for body in ["proof one", "proof two"] {
        let published = attest::publish(host, &subject, body.as_bytes(), "ada").expect("publish");
        digests.push(published.digest);
    }
    // A roster epoch (portable evidence) and a lease (the purest "as of now" record in
    // the system, and a refusal with a token of its own — ADR-0005 D2).
    for (namespace, name, bytes) in [
        (
            Namespace::ROSTER,
            "refs/gitiup/roster/00000007",
            &b"epoch seven"[..],
        ),
        (
            Namespace::JOB,
            "refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001",
            &b"a lease that expires"[..],
        ),
    ] {
        let digest = host.put_cas(&namespace, bytes).expect("put_cas");
        host.update_ref_cas(&RefUpdate::create(RefName::new(name).unwrap(), digest))
            .expect("advertise");
    }
    digests
}

fn options(verb: Verb, from: &str, to: &str) -> Options {
    let mut options = Options::new(verb, from, to);
    options.actor = gitiup_host::Actor::new("mirror").expect("actor");
    options
}

/// The forge is a destination and a source, and it is not a special case either way.
#[test]
fn a_copy_reaches_the_forge_and_comes_back_out_of_it() {
    let forge = MockForge::new();
    forge.seed_branch("main", b"# gitiup\n");
    let forge = Arc::new(forge);

    let origin = FsStore::new("origin");
    let source = origin.open();
    let digests = seed(&*source);

    // ── fs → forge ──────────────────────────────────────────────────────────────
    let mirror = forge_host(&forge);
    let report = federation::copy(
        &*source,
        &mirror,
        &options(Verb::Push, "the fs origin", "the forge"),
    )
    .expect("a copy into the forge");
    assert_eq!(report.trust, "none", "a push to a forge granted something");
    assert_eq!(report.age_basis, "claimed_at_us");
    assert_eq!(
        report.objects.arrived,
        digests.len() + 1,
        "not every record reached the forge: {report:?}"
    );
    assert_eq!(report.objects.rehashed, report.objects.arrived);
    assert_eq!(
        report.refused_by.get("no_arbitration_here").copied(),
        Some(1),
        "the lease was not refused by name: {:?}",
        report.refused
    );

    // The forge holds the bytes under the names its own refs advertise — which is the
    // adapter's `sha256:`-named-object translation being real, not just its listing.
    // Note what a *bare* listing does not show: `refs/gitiup/**` is plumbing a forge
    // hides from a stranger (C11), which is precisely why the copy asks for each
    // namespace by name instead of asking for everything.
    let listing = mirror.list_refs(&RefQuery::all()).expect("list");
    let advertised: Vec<String> = listing
        .iter()
        .map(|r| r.name.as_str().to_string())
        .collect();
    assert!(
        advertised
            .iter()
            .filter(|name| name.starts_with("refs/attestations/"))
            .count()
            == 2,
        "the forge does not advertise the proofs: {advertised:?}"
    );
    assert!(
        !advertised
            .iter()
            .any(|name| name.starts_with("refs/gitiup/lease/")),
        "a lease reached the forge: {advertised:?}"
    );
    let plumbing: Vec<String> = mirror
        .list_refs(&RefQuery::prefix("refs/gitiup"))
        .expect("list the plumbing")
        .iter()
        .map(|r| r.name.as_str().to_string())
        .collect();
    assert_eq!(
        plumbing,
        vec![
            "refs/gitiup/kv".to_string(),
            "refs/gitiup/roster/00000007".to_string()
        ],
        "the roster epoch did not arrive, or something that should not have did"
    );
    // `refs/gitiup/kv` is the *forge's own* commit chain, and the source — a directory
    // store — has no such ref to have given it. That is D7 in one line: the mirror
    // appends the records it took to its own chain instead of importing one store's
    // private topology as if it were a fact about the records. Which is also why the copy
    // out of this forge below refuses that ref: it is this store's, and travels to nobody.
    for reference in &listing {
        // Only what the copy wrote: the forge's own `refs/heads/main` names a *commit*,
        // and a commit is not a content-addressed record this API can hand back by name.
        let ours = reference.name.as_str().starts_with("refs/attestations/")
            || reference.name.as_str().starts_with("refs/gitiup/");
        if !ours {
            continue;
        }
        let bytes = mirror.get(&reference.oid).expect("get").unwrap_or_else(|| {
            panic!("{} advertises bytes the forge cannot serve", reference.name)
        });
        assert_eq!(Oid::hash_bytes(&bytes), reference.oid, "{reference:?}");
    }

    // ── forge → fs, out of the forge's own store ────────────────────────────────
    let sink = FsStore::new("sink");
    let destination = sink.open();
    let report = federation::copy(
        &mirror,
        &*destination,
        &options(Verb::Fetch, "the forge", "a second fs store"),
    )
    .expect("a copy out of the forge");
    assert_eq!(report.objects.arrived, digests.len() + 1, "{report:?}");
    assert_eq!(report.trust, "none");

    // …and the bytes are the bytes: one round trip through a forge, and the digest that
    // names them is unchanged, because a copy that re-encoded anything would have broken
    // the signature, the blob name and the ref leaf at once (ADR-0005 C4).
    for digest in &digests {
        let here = destination.get(digest).expect("get").expect("arrived");
        let there = source.get(digest).expect("get").expect("still there");
        assert_eq!(here, there, "{digest} is not what it was");
    }

    // A second copy moves nothing, on the forge's side too: a name that already stands
    // against the same digest is `already`, never a second write (D7).
    let again = federation::copy(
        &*source,
        &mirror,
        &options(Verb::Push, "the fs origin", "the forge"),
    )
    .expect("re-push");
    assert_eq!(again.objects.arrived, 0, "a re-push stored bytes again");
    assert_eq!(again.refs.written, 0);
    assert!(again.objects.already >= digests.len());
}

/// A forge that answers anonymously is a read-only mirror, and a copy must refuse to
/// write to it by name rather than halfway down a list.
#[test]
fn an_anonymous_forge_refuses_the_copy_at_the_boundary() {
    let forge = Arc::new(MockForge::new());
    let anonymous = {
        // SAFETY: see `remote()`; the same variable, the same value.
        let mut remote = remote();
        remote.credentials_profile = None;
        remote.options.remove("token-env");
        GitHubHost::with_transport(&remote, forge.transport(), None).expect("open anonymously")
    };
    // The bit says CAS — a forge can do compare-and-swap — and the credential says no,
    // which is exactly why the copy asks `require` rather than reading the bit.
    assert!(anonymous.capabilities().cas);
    assert_eq!(
        anonymous.capabilities().auth,
        gitiup_host::AuthModel::Anonymous,
        "this is supposed to be the anonymous case"
    );

    let origin = FsStore::new("origin-ro");
    let source = origin.open();
    seed(&*source);
    let error = federation::copy(
        &*source,
        &anonymous,
        &options(Verb::Push, "the fs origin", "an anonymous forge"),
    )
    .expect_err("a read-only destination must be refused");
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(
        error.message().contains("read_only"),
        "the refusal does not name its token: {error}"
    );
    assert_eq!(
        gitiup_host::federation::token_for(&error),
        "read_only",
        "the token registry and the refusal disagree"
    );
}

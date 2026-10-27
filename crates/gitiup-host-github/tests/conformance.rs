//! The shared host contract, run against the github adapter over the mock forge.
//!
//! This is the acceptance criterion "the adapter passes the shared conformance
//! suite": the bodies come from [`gitiup_host::conformance`] — the same code the
//! `fs` and `s3` hosts pass — and nothing here is allowed to be github-shaped.
//! Where the forge cannot do something the adapter has to actually do it instead
//! (pointer commits, check-before/after, pagination): see `src/store.rs`.
//!
//! The forge here is [`MockForge`], an in-process implementation of the REST
//! semantics the adapter drives, so these tests exercise the production code path
//! with no network and no credentials. `tests/fixtures.rs` runs the same host
//! against recorded HTTP instead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gitiup_host::{
    Actor, Capability, Host, HostErrorExt, HostErrorKind, Oid, RefName, RefQuery, RefStore,
    RefUpdate, RemoteConfig,
};
use gitiup_host_github::testing::MockForge;
use gitiup_host_github::transport::{Request, Response, TransportError};
use gitiup_host_github::{GitHubHost, Transport};

/// The variable the tests put the token in — named so nothing else can pick it up.
const TOKEN_ENV: &str = "GITIUP_HOST_GITHUB_TEST_TOKEN";
const TOKEN: &str = "test-token-8f2b1c4d";

fn forge() -> Arc<MockForge> {
    let forge = MockForge::new();
    forge.seed_branch("main", b"# gitiup\n");
    forge
}

/// A remote pointing at the mock, with a credential that resolves.
fn remote() -> RemoteConfig {
    // SAFETY: this variable is named for this test binary and nothing else reads
    // it; every test here sets it to the same value before it reads.
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    let mut remote =
        RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("a github remote");
    remote.credentials_profile = Some("gh".into());
    remote
        .options
        .insert("token-env".to_string(), TOKEN_ENV.to_string());
    remote
}

fn hosted(forge: &Arc<MockForge>) -> GitHubHost {
    GitHubHost::with_transport(&remote(), forge.transport(), None)
        .expect("the github host opens against the mock forge")
}

// ---------------------------------------------------------------------------
// The shared bodies.
// ---------------------------------------------------------------------------

#[test]
fn the_github_host_conforms_to_the_shared_host_contract() {
    let failures = gitiup_host::conformance::run_all_with(|| {
        let forge = forge();
        Box::new(hosted(&forge)) as Box<dyn Host>
    });
    assert!(
        failures.is_empty(),
        "the github adapter is not a gitiup host:\n{}",
        failures.join("\n")
    );
}

#[test]
fn a_stranger_reads_exactly_what_we_wrote() {
    // The most important body in the suite, and the one that needs two hosts: a
    // pack pushed through the forge must be readable by a second client that
    // knows nothing but the digest — including its deltas.
    let forge = forge();
    let source = hosted(&forge);
    let sink = hosted(&forge);
    gitiup_host::conformance::pack_round_trip(&source, &sink);
}

#[test]
fn every_shared_body_is_still_there() {
    // The run above iterates `bodies()`; if a body quietly disappears it stops
    // being covered and nothing fails. This fails instead.
    let names: Vec<&str> = gitiup_host::conformance::bodies()
        .iter()
        .map(|(name, _)| *name)
        .collect();
    for wanted in [
        "refs_round_trip",
        "blobs_round_trip",
        "cas_conflicts_are_reported",
        "multi_ref_writes_are_all_or_nothing",
        "describe_and_capabilities",
    ] {
        assert!(names.contains(&wanted), "the suite no longer runs {wanted}");
    }
}

// ---------------------------------------------------------------------------
// What a forge has to do differently, and does.
// ---------------------------------------------------------------------------

#[test]
fn a_ref_holds_a_pointer_commit_not_a_bare_digest() {
    // `git update-ref refs/changes/c1/head <sha256>` is the naive version of this
    // and it cannot work: a git ref names a commit, and a record is not a commit.
    // The pointer commit is also the only audit trail the forge itself shows a
    // reviewer, so it has to say who and why.
    let forge = forge();
    let host = hosted(&forge);
    let record = Oid::hash_bytes(b"{\"id\":\"c1\"}");
    let head = RefName::change_head("c1").expect("change ref");
    host.update_ref_cas(
        &RefUpdate::create(head.clone(), record)
            .with_actor(Actor::new("ada").expect("actor"))
            .with_message("open change c1"),
    )
    .expect("create the change ref");

    let written = forge
        .refs()
        .get(head.as_str())
        .expect("the forge holds the ref")
        .clone();
    assert_ne!(written, record.hex(), "the ref names a commit");
    let commit = forge
        .commits()
        .into_iter()
        .find(|commit| commit.sha == written)
        .expect("and that commit exists");
    assert!(
        commit.message.starts_with("gitiup: create "),
        "{}",
        commit.message
    );
    assert!(commit.message.contains(head.as_str()), "{}", commit.message);
    assert_eq!(commit.author, "ada", "who wrote it is in the object");

    // The ref reads back as the digest that was promised, which is the whole point.
    let read_back = host.get_ref(&head).expect("read").expect("there");
    assert_eq!(read_back.oid, record);
    assert_eq!(
        read_back.updated_by.as_ref().map(Actor::as_str),
        Some("ada")
    );
}

#[test]
fn a_stale_expectation_is_a_conflict_and_says_so_in_gitiup_words() {
    let forge = forge();
    let host = hosted(&forge);
    let record = Oid::hash_bytes(b"{\"id\":\"c2\"}");
    let head = RefName::change_head("c2").expect("change ref");
    host.update_ref_cas(&RefUpdate::create(head.clone(), record))
        .expect("create");
    let wrong = Oid::hash_bytes(b"someone else got here first");
    let error = host
        .cas_ref(
            &head,
            Some(wrong),
            Oid::hash_bytes(b"{\"id\":\"c2\",\"v\":2}"),
        )
        .expect_err("the ref is not where the caller thought");
    assert_eq!(error.kind(), HostErrorKind::Conflict);
    assert!(error.is_conflict());
    let text = error.to_string();
    assert!(
        text.contains("refs/changes/c2/head"),
        "it names the ref that moved: {text}"
    );
    assert!(
        text.contains("re-read") || text.contains("rebuild"),
        "and says what to do about it: {text}"
    );
    assert!(
        !text.contains("422") && !text.contains("412"),
        "the forge's status code is not the caller's problem: {text}"
    );
}

#[test]
fn a_rewind_needs_force_and_says_which_one_it_was() {
    // The forge refuses a non-fast-forward with the same 422 as a violated
    // create-only, and the adapter must tell them apart rather than report a
    // conflict that no re-read will fix.
    let forge = forge();
    let host = hosted(&forge);
    let first = forge.seed_branch("feature", b"one");
    let second = forge.commit_on(&first, b"two");
    let branch = RefName::branch("feature").expect("branch name");
    assert_eq!(
        host.get_ref(&branch).expect("read").expect("there").oid,
        git_oid(&first),
        "a plain branch reads as the commit it is"
    );
    host.cas_ref(&branch, Some(git_oid(&first)), git_oid(&second))
        .expect("a forward move is a fast-forward and goes through");
    // Moving it back to the parent is a rewind: the forge refuses it, and the
    // adapter must say what would be needed rather than "conflict, good luck".
    let error = host
        .cas_ref(&branch, Some(git_oid(&second)), git_oid(&first))
        .expect_err("a rewind without force is refused");
    assert_eq!(error.kind(), HostErrorKind::Conflict, "{error}");
    assert!(
        error.to_string().to_lowercase().contains("force"),
        "and the message says what would make it possible: {error}"
    );
}

#[test]
fn a_listing_pages_until_it_is_empty() {
    // GitHub answers at most `per_page` refs and puts the next page in a `Link`
    // header; a client that forgets to follow it returns a *short* listing that
    // looks like a short repository.
    let forge = forge();
    let host = hosted(&forge);
    for index in 0..7u32 {
        let name = RefName::new(format!("refs/gitiup/test/{index:02}")).expect("name");
        host.update_ref_cas(&RefUpdate::create(
            name,
            Oid::hash_bytes(format!("record {index}").as_bytes()),
        ))
        .expect("create");
    }
    let found = host
        .list_refs(&RefQuery::prefix("refs/gitiup/test/"))
        .expect("list");
    assert_eq!(
        found.len(),
        7,
        "three pages of three, two and two: {:?}, ",
        found.iter().map(|r| r.name.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(
        forge.config().per_page,
        3,
        "the mock pages, so this proves it"
    );
}

#[test]
fn the_credential_is_a_header_and_never_part_of_a_url() {
    #[derive(Default)]
    struct Spy {
        calls: Mutex<Vec<Request>>,
        responses: AtomicUsize,
    }
    impl Transport for Spy {
        fn send(&self, request: &Request) -> Result<Response, TransportError> {
            self.calls.lock().expect("spy").push(request.clone());
            // A bare 404 JSON answer is enough: this test is about what went out.
            let index = self.responses.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                Ok(Response::new(200, br#"[]"#.to_vec()))
            } else {
                Ok(Response::new(404, br#"{"message": "gone"}"#.to_vec()))
            }
        }
        fn describe(&self) -> String {
            "spy".to_string()
        }
    }

    let spy = Arc::new(Spy::default());
    let host = GitHubHost::with_transport(&remote(), spy.clone(), None).expect("host");
    let _ = host.list_refs(&RefQuery::all());
    let calls = spy.calls.lock().expect("spy").clone();
    assert!(!calls.is_empty(), "the adapter made calls");
    for call in &calls {
        assert!(
            !call.url.contains(TOKEN),
            "a token in a URL is a token in every proxy log and referrer between \
             here and the forge: {}",
            call.url
        );
        assert_eq!(
            call.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str()),
            "the credential goes as a header, on every call including pagination"
        );
        assert!(
            call.header("user-agent")
                .is_some_and(|agent| agent.starts_with("gitiup-host-github/")),
            "a server cannot rate-limit what it cannot identify: {:?}",
            call.headers
        );
    }
}

#[test]
fn a_spent_rate_limit_stops_rather_than_lies() {
    // A throttled forge is not an empty forge. The taxonomy has no "rate limited"
    // rung, so this is a retryable `Unreachable` that says when to come back —
    // never a successful listing with nothing in it, and never a permission error.
    let forge = forge();
    forge.exhaust_rate_limit_from(1);
    let host = hosted(&forge);
    let error = host
        .list_refs(&RefQuery::all())
        .expect_err("a spent quota is not an empty repository");
    assert_eq!(error.kind(), HostErrorKind::Unreachable, "{error}");
    assert!(error.is_unreachable());
    assert!(error.to_string().contains("rate limit"), "{error}");
    assert!(
        !error.to_string().contains("denied"),
        "a rate limit is not a permissions problem: {error}"
    );
}

#[test]
fn a_missing_repository_is_not_reported_as_a_missing_ref() {
    // Both are a 404. Only the caller knows which it asked for, and a typo'd
    // repository read as "no changes yet" is the worst possible failure.
    let forge = forge();
    let remote =
        RemoteConfig::new("origin", "https://github.com/gitiup/nope").expect("a valid remote URL");
    let host = GitHubHost::with_transport(&remote, forge.transport(), None).expect("host");
    let listing = host
        .list_refs(&RefQuery::all())
        .expect_err("the repository is not there");
    assert_eq!(listing.kind(), HostErrorKind::NotFound, "{listing}");
    assert!(
        listing.to_string().contains("gitiup/nope"),
        "it names the repository, so the typo is findable: {listing}"
    );
    // A ref read must not be quieter than the listing: the forge answers 404 for
    // both, and "no such ref" in a repository that does not exist is a lie.
    let single = host
        .get_ref(&RefName::change_head("c1").expect("name"))
        .expect_err("same answer for one ref");
    assert_eq!(single.kind(), HostErrorKind::NotFound, "{single}");
    assert!(single.to_string().contains("gitiup/nope"), "{single}");
}

#[test]
fn an_anonymous_remote_refuses_to_promise_writes() {
    let forge = forge();
    let mut remote = remote();
    remote.options.remove("token-env");
    // No profile passed, so nothing resolves: this is a clone URL and nothing more.
    let host = GitHubHost::with_transport(
        &{
            let mut open = remote.clone();
            open.credentials_profile = None;
            open
        },
        forge.transport(),
        None,
    )
    .expect("host");
    assert_eq!(
        host.capabilities().auth,
        gitiup_host::AuthModel::Anonymous,
        "{remote:?}"
    );
    let error = host
        .require(Capability::Cas)
        .expect_err("an anonymous remote cannot write");
    assert_eq!(error.kind(), HostErrorKind::PermissionDenied);
    assert!(host.require(Capability::Immutable).is_ok());
}

#[test]
fn the_host_says_what_a_forge_cannot_promise() {
    let forge = forge();
    let host = hosted(&forge);
    let advice = host.advice();
    let joined = advice.join("\n");
    assert!(
        joined.contains("one ref at a time"),
        "a forge cannot write two refs in one transaction, and saying so is the \
         point of advice(): {joined}"
    );
    assert!(
        joined.contains("rewind") || joined.contains("force"),
        "{joined}"
    );
    let caps = host.capabilities();
    assert!(caps.cas && caps.immutable);
    assert!(!caps.atomic_multi_write);
    assert!(caps.require(Capability::AtomicMultiWrite).is_err());
    let info = host.describe();
    assert_eq!(info.schema_version, gitiup_host::HOST_SCHEMA_VERSION);
    assert!(info.implemented_by.starts_with("gitiup-host "), "{info:?}");
    assert!(info.url.expect("url").contains("github.com"));
    assert!(
        !format!("{host:?}").contains(TOKEN),
        "Debug must never print the token"
    );
}

/// A git-shaped id from the mock forge, as an [`Oid`].
fn git_oid(hex: &str) -> Oid {
    Oid::from_hex(hex).expect("the mock mints git-shaped ids")
}

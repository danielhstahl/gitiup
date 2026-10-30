//! The github adapter, measured by the same bodies as everything else.
//!
//! The forge is [`MockForge`], the in-process implementation of the REST
//! semantics the adapter drives, so these bodies exercise the production path
//! with no network and no token — and any drift between "what the adapter thinks
//! the API does" and "what a host owes gitiup" shows up here rather than in a
//! production merge. `gitiup-host-github`'s own `tests/conformance.rs` runs the
//! smaller in-crate set against recorded HTTP; this is the whole suite.
//!
//! The adapter is also the host most likely to *claim* more than it can deliver,
//! so the shapes this suite insists on are the ones it answers here: a token the
//! forge refuses, and the promises `capabilities()` makes about a forge with no
//! ref transactions.

use std::sync::Arc;

use gitiup_host::{HostError, HostKind, HostResult, RemoteConfig};
use gitiup_host_github::CurlTransport;
use gitiup_host_github::GitHubHost;
use gitiup_host_github::testing::MockForge;
use gitiup_host_github::transport::{Request, Response, Transport, TransportError};

use crate::registration::{Decoy, DecoyOutcome, Knobs, Registration, Session};

/// The variable the token is read from — named for this crate's tests, so a
/// leaked value is obviously the suite's own.
const TOKEN_ENV: &str = "GITIUP_HOST_TESTS_TOKEN";
const TOKEN: &str = "conformance-token-4f0c19";

/// The variable the **decoy** run's token is read from.
///
/// A name of its own, on purpose: the other registrations in this binary run concurrently
/// and assert what `GITIUP_HOST_TESTS_TOKEN` resolves to, so the decoy run must not be
/// able to move it.
const DECOY_TOKEN_ENV: &str = "GITIUP_HOST_TESTS_DECOY_TOKEN";

fn remote() -> RemoteConfig {
    // SAFETY: this variable is named for this crate's tests, and every test in
    // this binary sets it to the same value before it reads it.
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    // The name the mock forge answers for (see `MockConfig`), not a name this
    // suite invented: a forge that 404s your repository teaches you nothing about
    // the host above it.
    let mut remote =
        RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("a github url");
    remote.credentials_profile = Some("gh".into());
    remote
        .options
        .insert("token-env".to_string(), TOKEN_ENV.to_string());
    remote
}

/// A brand-new repository: created, with a default branch configured, and nothing
/// gitiup has written to it yet. That is the state a host meets first, and the one
/// the suite's empty-store body is about.
fn fresh_forge() -> Arc<MockForge> {
    MockForge::new()
}

fn make_github() -> HostResult<Session> {
    let forge = fresh_forge();
    let host = GitHubHost::with_transport(&remote(), forge.transport(), None)?;
    Ok(Session::new(host).with(forge))
}

/// A transport that answers 401 to every call: a token that expired between the
/// last successful call and this one.
#[derive(Debug)]
struct ExpiredToken {
    /// The value the forge no longer accepts, so the leak check has something
    /// real to look for.
    secret: &'static str,
}

impl Transport for ExpiredToken {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        // A forge never echoes a token back. If a client ever put one in a URL and
        // echoed it into an error, this is where the body would notice.
        let _ = request;
        Ok(
            Response::new(401, br#"{"message":"Bad credentials"}"#.to_vec())
                .with_header("content-type", "application/json"),
        )
    }

    fn describe(&self) -> String {
        format!("an expired-token transport (token {})", self.secret)
    }
}

fn make_github_denied() -> HostResult<Session> {
    let transport = Arc::new(ExpiredToken { secret: TOKEN });
    let host = GitHubHost::with_transport(&remote(), transport.clone(), None)?;
    Ok(Session::new(host).with(transport))
}

/// The forge as a **public repository**: nothing configured, reads allowed, writes
/// refused.
///
/// The mock serves unauthenticated `GET`s exactly as a public repository does, so this is
/// the adapter's anonymous path rather than a stand-in for it — including the part that
/// matters, which is that a host with no credential must still describe itself honestly
/// instead of claiming a token it does not have.
fn make_github_anonymous() -> HostResult<Session> {
    let forge = fresh_forge();
    // The owner publishes first, through the forge with a token: this is the same body's
    // story everywhere — somebody made the store worth reading, and then a stranger with
    // nothing has to be able to read it.
    let owner = GitHubHost::with_transport(&remote(), forge.transport(), None)?;
    super::seed_public_store(&owner)?;
    drop(owner);
    // No `token-env`, no credentials profile: whatever the environment happens to hold,
    // nothing was configured for *this* remote.
    let stranger =
        RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("a github url");
    let host = GitHubHost::with_transport(&stranger, forge.transport(), None)?;
    Ok(Session::new(host).with(forge))
}

/// A token configured for the decoy pair's origin, driven over the **real** transport:
/// `curl`, a socket, and a `302` to a second origin that reports what it was sent.
///
/// Not the mock, deliberately. The mock is my own code, so a leak that only happens
/// through it is a leak I would have written twice; here the token really is resolved, the
/// request really leaves with it, and the answer really is a redirect — the only thing
/// under test is whether the second request is ever made.
fn make_github_decoy() -> HostResult<Decoy> {
    let pair = crate::fixtures::decoy_pair().ok_or_else(|| {
        HostError::invalid(
            "github-decoy",
            "no redirect-to-decoy endpoint could be started",
        )
    })?;
    // The repository name is the probe: it appears in the path of every arrival, which is
    // how a body ties an arrival to *this* run when the decoy is shared by the whole test
    // binary.
    let probe = format!("decoy-{}", crate::fixtures::next());
    let token = format!("gitiup-github-decoy-token-{probe}");
    // SAFETY: a uniquely named variable that nothing else reads (the remote below names
    // it in `token-env`), set once, before the host is built.
    unsafe { std::env::set_var(DECOY_TOKEN_ENV, &token) };
    let remote = RemoteConfig::new("origin", &format!("https://github.com/gitiup/{probe}"))
        .expect("a github url")
        // The redirecting endpoint stands in for a forge, and `api-base` is the option that
        // says so — the same one that names a GitHub Enterprise address, and the address the
        // requests actually go to.
        .with_option("api-base", pair.origin())
        .with_option("accept-host", "true")
        .with_option("token-env", DECOY_TOKEN_ENV);
    let outcome = match GitHubHost::open(&remote) {
        Ok(host) => DecoyOutcome::Built {
            session: Session::new(host),
        },
        Err(error) => DecoyOutcome::Refused { error },
    };
    Ok(Decoy {
        label: "github",
        outcome,
        token,
        configured: pair.origin().to_string(),
        target: pair.decoy().to_string(),
        probe,
    })
}

/// The github adapter: the forge demoted to one host among several, and measured
/// like one.
pub const GITHUB: Registration = Registration {
    name: "github",
    kind: HostKind::Github,
    make: make_github,
    available: || true,
    unavailable: "the mock forge needs nothing",
    knobs: Knobs {
        pack_bytes: 1024 * 1024,
        list_count: 60,
        ref_count: 30,
        writers: 4,
    },
    skips: &[(
        "a_host_without_cas_refuses_cas_writes",
        "the adapter reports cas = true, and the mock models a forge that cannot do a \
         conditional write by refusing it — which is the conflict path, not the degradation \
         path; a forge that quietly ignored a lease is not modelled by anyone",
    )],
    denied: Some(make_github_denied),
    denied_available: || true,
    denied_unavailable: "",
    denied_secret: || Some(TOKEN.to_string()),
    degraded: None,
    degraded_available: || false,
    degraded_unavailable: "this host declares no cas=false variant",
    anonymous: Some(make_github_anonymous),
    anonymous_available: || true,
    anonymous_unavailable: "",
    decoy: Some(make_github_decoy),
    decoy_available: || crate::fixtures::decoy_pair().is_some() && CurlTransport::new().is_ok(),
    decoy_unavailable: "the decoy endpoint is a python fixture, and this run drives the \
         credential over the curl binary the github transport uses",
};

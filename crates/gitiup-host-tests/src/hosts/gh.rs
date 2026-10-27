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

use gitiup_host::{HostKind, HostResult, RemoteConfig};
use gitiup_host_github::GitHubHost;
use gitiup_host_github::testing::MockForge;
use gitiup_host_github::transport::{Request, Response, Transport, TransportError};

use crate::registration::{Knobs, Registration, Session};

/// The variable the token is read from — named for this crate's tests, so a
/// leaked value is obviously the suite's own.
const TOKEN_ENV: &str = "GITIUP_HOST_TESTS_TOKEN";
const TOKEN: &str = "conformance-token-4f0c19";

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
};

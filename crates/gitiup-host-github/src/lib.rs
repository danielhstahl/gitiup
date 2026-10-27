//! `gitiup-host-github` — the forge, demoted to one host among several.
//!
//! gitiup's premise is that a repository does not need a forge: refs, packs and
//! content-addressed records are enough to propose a change, prove something ran,
//! and gate a merge. GitHub is then *a host* — the one that also has a review
//! database, a workflow engine and a merge button, which is why it is the one host
//! that gets a translation layer instead of a driver.
//!
//! This crate is the only place in the workspace allowed to know what a GitHub API
//! body looks like. [`gitiup_host`] stays free of forge clients (its own
//! `tests/no_forge_deps.rs` enforces that), and the command line reaches this crate
//! behind its `hosts-github` feature, so a build without that feature contains no
//! forge code at all and says so:
//!
//! ```text
//! gitiup: remote 'origin' is a github remote, and this gitiup was built without
//! the `hosts-github` feature
//! hint: rebuild with --features hosts-github, or point the remote at a host this
//! build has: an s3:// bucket or any plain git remote
//! ```
//!
//! # The four things a forge gives you, and where they went
//!
//! | what GitHub has | where it lives now | what a caller sees |
//! |-----------------|--------------------|--------------------|
//! | refs, branches, the object store | [`store`] — the git data API, with pointer commits so a ref can point at a record | [`RefStore`], unchanged |
//! | the pull request database | `GitHubHost::changes`, `GitHubHost::open_change` | a [`ChangeRecord`], same as a bucket's `refs/changes/**` |
//! | check runs and CI status | `GitHubHost::publish_attestation`, `GitHubHost::attestations_for` | an [`AttestationRecord`], same as `refs/attestations/<oid>` on any host |
//! | webhooks, and `github.event.*` | [`ChangeFeedCursor`] polling | "what is new since I looked", one conditional listing |
//! | token auth, pagination, rate limits | [`client`], [`auth`] | nothing: they are the adapter's job, and a caller above should not be able to get them wrong |
//!
//! # What this host promises, truthfully
//!
//! `capabilities.cas` is true, and the reasons are in [`store`]'s table: the forge
//! enforces create-only atomically (`POST /git/refs`), enforces forward moves
//! (`force = false` refuses a non-fast-forward), and every write ends with a read
//! back and a comparison. It is *not* true in one case — rewinding a ref, which no
//! gitiup flow does — and that case, and the check-then-delete of
//! [`gitiup_host::RefStore::delete_ref_cas`], are reported by
//! [`GitHubHost::advice`] rather than hidden. `atomic_multi_write` is false, because
//! there is no ref transaction on the wire, and claiming it would be the kind of lie
//! a merge gate is built on top of.
//!
//! # Testing, which is the other half of the ticket
//!
//! The `testing` feature brings in [`testing`]: an in-process forge with real
//! semantics (fast-forward refusal, `Link` pagination, rate-limit headers, 401 on a
//! write with no token), plus a recorder and a fixture replayer. `tests/` runs the
//! shared conformance suite ([`gitiup_host::conformance`]) against that forge *and*
//! against the recorded fixtures, so the adapter is covered with no network, no
//! token and no shared rate limit.
//!
//! [`RefStore`]: gitiup_host::RefStore

use gitiup_host::HostError;

pub mod api;
pub mod auth;
pub mod client;
pub mod codec;
pub mod curl;
pub mod forge;
pub mod host;
pub mod layout;
pub mod store;
pub mod transport;

#[cfg(feature = "testing")]
pub mod testing;

pub use auth::{Auth, Environment, FixedEnvironment, Secret, TokenSource};
pub use client::{ClientOptions, RateBudget, RepoRef};
pub use curl::CurlTransport;
pub use forge::{
    AttestationRecord, AttestationSource, ChangeFeedCursor, ChangeOrigin, ChangeRecord, ChangeState,
};
pub use host::GitHubHost;
pub use transport::{Method, Request, Response, Transport, TransportError};

/// The feature a caller checks for, and the string a refusal must name.
pub const FEATURE: &str = "hosts-github";

/// The error every caller shows when a remote is a forge remote and this build has
/// no forge adapter compiled in.
///
/// It lives here so the wording is decided once. The command line reaches it
/// through `cfg(not(feature = "hosts-github"))`, which is the point: the message
/// names the flag, because "unsupported" without a flag to pass is a dead end.
pub fn forge_without_adapter(remote: &gitiup_host::RemoteConfig) -> HostError {
    HostError::SchemeUnknown(Box::new(gitiup_host::error::SchemeUnknown {
        scheme: "github".to_string(),
        supported: vec!["s3".into(), "https".into(), "ssh".into(), "file".into()],
        hint: Some(format!(
            "'{}' points at a github repository ({}), and this gitiup was built without \
             the `{FEATURE}` feature. Rebuild with --features {FEATURE} (it is on by \
             default), or point the remote at a host this build does serve: an s3:// \
             bucket or any plain git remote (https://, ssh://, file://)",
            remote.name,
            remote.redacted_url()
        )),
    }))
}

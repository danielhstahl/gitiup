//! `gitiup-host-tests` — the shared host conformance suite (giti-xdw.5).
//!
//! gitiup can be hosted by a directory, a bare repository, a bucket, or a forge.
//! The moment there is more than one host there is a second question to answer:
//! *do they all mean the same thing?* Without a shared suite the answer arrives
//! as a lost merge or a signature that will not verify — the S3 host accepting a
//! write the git host would have refused, a bucket listing that came back one page
//! short, an expired credential reported as "no changes". This crate is where
//! that question gets answered before production does.
//!
//! # Using it from a host
//!
//! Implement the traits, register one [`Registration`] describing how to build
//! your host, and instantiate the suite:
//!
//! ```ignore
//! // tests/conformance.rs of your crate
//! gitiup_host_tests::test_host!(my_fs, gitiup_host_tests::hosts::FS);
//! ```
//!
//! That generates one `#[test]` per body of the suite, named
//! `my_fs::<body>`, each running against a *fresh* store, plus an accounting test
//! that fails if the registration neither runs a body nor explains why. A host
//! that cannot pass a body either fixes the host or records a reason that CI then
//! prints — the suite has no silent third option.
//!
//! # The bodies
//!
//! See [`bodies`]; the short version is that the nasty edges are named
//! explicitly, because "it works on my host" is what each of them once did:
//!
//! | edge | body |
//! |------|------|
//! | empty repository | `a_fresh_store_is_empty_then_writable` |
//! | ref CAS conflict | `cas_conflicts_are_reported`, `concurrent_ref_writers_never_lose_one` |
//! | ref deletion | `ref_deletion_is_conditional` |
//! | pack round-trip | `pack_round_trip_between_two_hosts`, `a_huge_pack_round_trips_intact` |
//! | blob listing, pagination | `listings_are_complete_across_pages` |
//! | expired / refused credentials | `refused_credentials_are_denied_not_dropped` |
//! | `cas = false` degradation | `a_host_without_cas_refuses_cas_writes` |
//! | unsupported operations | `unsupported_operations_are_refused_by_name` |
//!
//! # Running it
//!
//! ```text
//! cargo test -p gitiup-host-tests                         # hermetic hosts only
//! cargo test -p gitiup-host-tests --features s3,github    # + transport shapes
//! ```
//!
//! The live hosts opt in through the environment and are *skipped, not passed*,
//! when it is not there:
//!
//! * `s3-minio`: the AWS chain, plus `GITIUP_S3_LIVE_ENDPOINT` for a MinIO — see
//!   [`hosts::live`].
//! * `git-http`: CI's `git-http-backend`, or the python fixture this suite can
//!   start itself — see [`fixtures::GitServer`].
//!
//! `GITIUP_CONFORMANCE_REQUIRE_HOSTS=s3-minio,git-http` (which CI sets) turns
//! those skips into failures, so a service that did not start cannot be mistaken
//! for a pass. `ci/host-conformance.sh` runs the whole matrix locally.
//!
//! ([`hosts::live`] is only compiled with the `s3` feature.)

#![doc = include_str!("../README.md")]

pub mod bodies;
pub mod fixtures;
pub mod hosts;
mod macro_support;
pub mod registration;
pub mod runner;

pub use bodies::{Body, Ctx, Shape, bodies as conformance_bodies};
pub use registration::{Available, Denial, DenialOutcome, DeniedSecret, Knobs, Make, Registration};
pub use runner::{account, failures, report, summary};

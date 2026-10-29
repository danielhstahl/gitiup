//! The `test_host!` macro and the two lists it needs.
//!
//! A `macro_rules!` macro cannot iterate a `static` registry, so the list of body
//! names is written twice: once as the names ([`conformance_body_names!`]) and
//! once as the generated tests ([`each_conformance_body!`]). That is deliberate
//! duplication in exactly one file, and `tests/coverage.rs` refuses it the moment
//! either one stops matching [`crate::bodies::bodies`] — the same guard that makes
//! the rest of this crate worth its time. When you add a body: add it to the
//! registry in `bodies.rs`, then to both of these.

/// Every body name, as a const array. The coverage test compares this against the
/// registry.
#[macro_export]
macro_rules! conformance_body_names {
    () => {
        [
            "blobs_round_trip",
            "refs_round_trip",
            "cas_conflicts_are_reported",
            "multi_ref_writes_are_all_or_nothing",
            "pack_round_trip_between_two_hosts",
            "a_fresh_store_is_empty_then_writable",
            "ref_deletion_is_conditional",
            "a_huge_pack_round_trips_intact",
            "listings_are_complete_across_pages",
            "concurrent_ref_writers_never_lose_one",
            "unsupported_operations_are_refused_by_name",
            "one_object_is_forgotten_or_the_refusal_says_why",
            "attestations_about_one_subject_are_found_by_subject",
            "a_change_goes_from_proposal_to_merge_and_merges_once",
            "a_stale_base_merge_is_refused_the_same_way_everywhere",
            "describe_and_capabilities",
            "refused_credentials_are_denied_not_dropped",
            "a_host_without_cas_refuses_cas_writes",
        ]
    };
}

/// Generate one `#[test]` per body, each against a fresh store.
///
/// One test per body rather than one test that loops: a failing host should show
/// up as a named test in CI output and be rerunnable with `--exact`, and a body
/// that panics must not take the other eleven down with it.
#[macro_export]
macro_rules! each_conformance_body {
    ($registration:path) => {
        #[test]
        fn blobs_round_trip() {
            $crate::runner::require_body("blobs_round_trip", &$registration);
        }
        #[test]
        fn refs_round_trip() {
            $crate::runner::require_body("refs_round_trip", &$registration);
        }
        #[test]
        fn cas_conflicts_are_reported() {
            $crate::runner::require_body("cas_conflicts_are_reported", &$registration);
        }
        #[test]
        fn multi_ref_writes_are_all_or_nothing() {
            $crate::runner::require_body("multi_ref_writes_are_all_or_nothing", &$registration);
        }
        #[test]
        fn pack_round_trip_between_two_hosts() {
            $crate::runner::require_body("pack_round_trip_between_two_hosts", &$registration);
        }
        #[test]
        fn a_fresh_store_is_empty_then_writable() {
            $crate::runner::require_body("a_fresh_store_is_empty_then_writable", &$registration);
        }
        #[test]
        fn ref_deletion_is_conditional() {
            $crate::runner::require_body("ref_deletion_is_conditional", &$registration);
        }
        #[test]
        fn a_huge_pack_round_trips_intact() {
            $crate::runner::require_body("a_huge_pack_round_trips_intact", &$registration);
        }
        #[test]
        fn listings_are_complete_across_pages() {
            $crate::runner::require_body("listings_are_complete_across_pages", &$registration);
        }
        #[test]
        fn concurrent_ref_writers_never_lose_one() {
            $crate::runner::require_body("concurrent_ref_writers_never_lose_one", &$registration);
        }
        #[test]
        fn unsupported_operations_are_refused_by_name() {
            $crate::runner::require_body(
                "unsupported_operations_are_refused_by_name",
                &$registration,
            );
        }
        #[test]
        fn one_object_is_forgotten_or_the_refusal_says_why() {
            $crate::runner::require_body(
                "one_object_is_forgotten_or_the_refusal_says_why",
                &$registration,
            );
        }
        #[test]
        fn attestations_about_one_subject_are_found_by_subject() {
            $crate::runner::require_body(
                "attestations_about_one_subject_are_found_by_subject",
                &$registration,
            );
        }
        #[test]
        fn a_change_goes_from_proposal_to_merge_and_merges_once() {
            $crate::runner::require_body(
                "a_change_goes_from_proposal_to_merge_and_merges_once",
                &$registration,
            );
        }
        #[test]
        fn a_stale_base_merge_is_refused_the_same_way_everywhere() {
            $crate::runner::require_body(
                "a_stale_base_merge_is_refused_the_same_way_everywhere",
                &$registration,
            );
        }
        #[test]
        fn describe_and_capabilities() {
            $crate::runner::require_body("describe_and_capabilities", &$registration);
        }
        #[test]
        fn refused_credentials_are_denied_not_dropped() {
            $crate::runner::require_body(
                "refused_credentials_are_denied_not_dropped",
                &$registration,
            );
        }
        #[test]
        fn a_host_without_cas_refuses_cas_writes() {
            $crate::runner::require_body("a_host_without_cas_refuses_cas_writes", &$registration);
        }
    };
}

/// Instantiate the conformance suite for one host.
///
/// ```ignore
/// gitiup_host_tests::test_host!(fs, gitiup_host_tests::hosts::FS);
/// ```
///
/// expands to a module `fs` holding one `#[test]` per body of the suite plus two
/// guards of its own: that the registration accounts for every body (running it
/// or explaining it), and that the host is the kind of host it says it is. The
/// module name appears in the test path, so two hosts can be instantiated in one
/// file without colliding.
#[macro_export]
macro_rules! test_host {
    ($module:ident, $registration:path $(,)?) => {
        #[doc(hidden)]
        mod $module {
            use super::*;

            $crate::each_conformance_body!($registration);

            /// The drift guard: a body this host neither runs nor explains is a
            /// hole in the suite, and this is the test that notices.
            #[test]
            fn the_suite_accounts_for_every_body() {
                let problems = $crate::runner::account(&$registration);
                assert!(
                    problems.is_empty(),
                    "{} does not account for the suite:\n{}",
                    stringify!($registration),
                    problems.join("\n")
                );
            }

            /// The kind a host claims is what call sites branch on, so it is part
            /// of the claim being measured — a host registered as `git` that
            /// answers `Other` is lying somewhere.
            #[test]
            fn the_host_is_the_kind_it_claims() {
                let note = $registration.skip_note();
                if note.is_some() {
                    eprintln!(
                        "skip [{}]: {}",
                        $registration.name,
                        note.unwrap_or_default()
                    );
                    return;
                }
                let made = ($registration.make)();
                let session = match made {
                    Ok(session) => session,
                    Err(err) => panic!("{} could not make a store: {err}", $registration.name),
                };
                let described = session.host().describe();
                assert_eq!(
                    described.kind, $registration.kind,
                    "{} is registered as {} but describes itself as {}",
                    $registration.name, $registration.kind, described.kind
                );
                assert!(
                    !described.summary_line().is_empty(),
                    "{} has nothing to say about itself",
                    $registration.name
                );
            }

            /// What the host declines, and why, printed once for the CI log: a
            /// skip is allowed, an invisible skip is not.
            #[test]
            fn the_skips_are_explained_out_loud() {
                for (body, reason) in $registration.skips {
                    assert!(
                        $crate::bodies::body(body).is_some(),
                        "{} skips `{body}`, which is not a body of the suite",
                        $registration.name
                    );
                    assert!(
                        !reason.trim().is_empty(),
                        "{} skips `{body}` without saying why",
                        $registration.name
                    );
                    eprintln!("skip [{}] {body}: declared: {reason}", $registration.name);
                }
                if let Some(note) = $registration.skip_note() {
                    eprintln!("skip [{}]: not available here: {note}", $registration.name);
                }
                if let Some(note) = $registration.denial_skip_note() {
                    eprintln!(
                        "skip [{}] refused_credentials_are_denied_not_dropped: {note}",
                        $registration.name
                    );
                }
                if let Some(note) = $registration.degradation_skip_note() {
                    eprintln!(
                        "skip [{}] a_host_without_cas_refuses_cas_writes: {note}",
                        $registration.name
                    );
                }
            }
        }
    };
}

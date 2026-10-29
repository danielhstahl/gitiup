//! The suite's own guard: it measures the measurement.
//!
//! A conformance suite fails in two ways, not one. The obvious way is a host that
//! drifts from the contract. The other is the suite itself drifting — a body
//! deleted and nobody notices, a skip added without a reason, a new host kind
//! added to `gitiup-host` that nothing measures, an environment so thin that the
//! whole run consisted of skips and still reported green. Every test here is about
//! the second failure mode.

use gitiup_host::HostKind;
use gitiup_host_tests::bodies::{Shape, bodies};
use gitiup_host_tests::hosts;
use gitiup_host_tests::registration::Registration;

/// The edges the suite is required to cover, by name, each with the bodies that
/// can cover it.
///
/// This is the ticket, written down where a deletion cannot miss it: an edge may
/// change body, and a body may be renamed, but the suite may not stop testing
/// something on this list.
const REQUIRED_EDGES: &[(&str, &[&str])] = &[
    (
        "empty repository",
        &["a_fresh_store_is_empty_then_writable"],
    ),
    (
        "ref CAS conflict",
        &[
            "cas_conflicts_are_reported",
            "concurrent_ref_writers_never_lose_one",
        ],
    ),
    ("ref deletion", &["ref_deletion_is_conditional"]),
    (
        "pack round-trip",
        &[
            "pack_round_trip_between_two_hosts",
            "a_huge_pack_round_trips_intact",
        ],
    ),
    ("huge pack", &["a_huge_pack_round_trips_intact"]),
    (
        "blob listing",
        &["blobs_round_trip", "listings_are_complete_across_pages"],
    ),
    (
        "listing pagination",
        &["listings_are_complete_across_pages"],
    ),
    (
        "expired credentials / auth failure",
        &["refused_credentials_are_denied_not_dropped"],
    ),
    (
        "cas=false degradation",
        &["a_host_without_cas_refuses_cas_writes"],
    ),
    (
        "unsupported operations",
        &["unsupported_operations_are_refused_by_name"],
    ),
    (
        "multi-ref atomicity",
        &["multi_ref_writes_are_all_or_nothing"],
    ),
    ("capabilities honesty", &["describe_and_capabilities"]),
    (
        "attestations findable by subject",
        &["attestations_about_one_subject_are_found_by_subject"],
    ),
    (
        "the change workflow, propose to merge",
        &["a_change_goes_from_proposal_to_merge_and_merges_once"],
    ),
    (
        "a stale-base merge refused, identically",
        &["a_stale_base_merge_is_refused_the_same_way_everywhere"],
    ),
];

/// Every host kind a gitiup build can ship. A new one here means a new host, and a
/// new host that nothing measures is the drift this file is for.
const SHIPPED_KINDS: &[HostKind] = &[HostKind::Fs, HostKind::Git, HostKind::S3, HostKind::Github];

fn registrations() -> Vec<&'static Registration> {
    hosts::all()
}

#[test]
fn the_macro_and_the_registry_agree() {
    let macro_names: Vec<String> = gitiup_host_tests::conformance_body_names!()
        .iter()
        .map(|name| name.to_string())
        .collect();
    let registry: Vec<String> = bodies().iter().map(|body| body.name.to_string()).collect();
    assert_eq!(
        macro_names, registry,
        "the generated tests and the body registry disagree, so a body exists that no host \
         runs (or a test calls a body that is not registered)"
    );
    assert!(
        macro_names.len() >= REQUIRED_EDGES.len(),
        "the suite has fewer bodies than the edges it must cover"
    );
}

#[test]
fn every_required_edge_is_covered_by_a_body() {
    for (edge, names) in REQUIRED_EDGES {
        for name in *names {
            assert!(
                bodies().iter().any(|body| body.name == *name),
                "`{edge}` is required to be covered, and `{name}` is no longer a body of the \
                 suite"
            );
        }
    }
}

#[test]
fn every_required_edge_is_actually_run_by_some_host() {
    let hosts = registrations();
    let mut problems: Vec<String> = Vec::new();
    for (edge, names) in REQUIRED_EDGES {
        let covered = names.iter().any(|name| {
            hosts.iter().any(|host| {
                let Some(body) = bodies().iter().find(|body| body.name == *name) else {
                    return false;
                };
                let offered = match body.shape {
                    Shape::Single | Shape::Pair => true,
                    Shape::Denied => host.denied.is_some(),
                    Shape::Degraded => host.degraded.is_some(),
                };
                offered && host.skip_reason(name).is_none()
            })
        });
        if !covered {
            problems.push(format!(
                "`{edge}` is not run by any host: every body that could cover it \
                 ({names:?}) is skipped or unoffered everywhere"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_shipped_host_kind_is_measured() {
    let hosts = registrations();
    let mut problems = Vec::new();
    for kind in SHIPPED_KINDS {
        // The github adapter is optional in every sense: without the feature this
        // build contains no forge code at all, so there is nothing to measure.
        if *kind == HostKind::Github && cfg!(not(feature = "github")) {
            continue;
        }
        if !hosts.iter().any(|host| host.kind == *kind) {
            problems.push(format!(
                "no registration covers a `{kind}` host: add one to `hosts::all`, or say why \
                 the suite no longer measures it"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The cross-host claim: a change published on a bucket and merged through a plain-git
/// host, with the same digests from both.
///
/// It is not a body — a body is one host measured once — so it cannot be guarded by the
/// registry. What can be guarded is the promise being made: that the pair exists, that it
/// points a bucket at a git host (the direction a contributor without a forge actually
/// travels), and that some host in the matrix is a bucket and some is git, or the pair is
/// a pair of nothing.
#[test]
fn the_cross_host_claim_is_a_bucket_publishing_and_a_git_host_merging() {
    let pairs = hosts::cross_pairs();
    assert!(
        !pairs.is_empty(),
        "nothing measures a change crossing from one host to another: that is the claim \
         the whole change design rests on, and `hosts::cross_pairs` is where it is declared"
    );
    let all = registrations();
    for (name, publisher, merger) in &pairs {
        for registration in [*publisher, *merger] {
            assert!(
                all.iter().any(|host| host.name == registration.name),
                "`{name}` names {}, which is not in `hosts::all`, so nothing runs its \
                 bodies either",
                registration.name
            );
        }
        assert_eq!(
            publisher.kind,
            HostKind::S3,
            "`{name}` publishes on a {}, and the claim is that a *bucket* can be the forge \
             a change is proposed on",
            publisher.kind
        );
        assert_eq!(
            merger.kind,
            HostKind::Git,
            "`{name}` merges on a {}, and the claim is that the owner's plain-git host is \
             where the merge happens",
            merger.kind
        );
    }
}

#[test]
fn a_registration_never_declines_more_than_it_runs() {
    let limit = bodies().len() / 2;
    for host in registrations() {
        let problems = gitiup_host_tests::account(host);
        assert!(
            problems.is_empty(),
            "{} does not account for the suite:\n{}",
            host.name,
            problems.join("\n")
        );
        assert!(
            host.skips.len() <= limit,
            "{} skips {} of {} bodies: a host that declines half the suite is not being \
             conformance-tested, it is being excused",
            host.name,
            host.skips.len(),
            bodies().len()
        );
    }
}

#[test]
fn host_names_are_unique_and_match_their_registration() {
    let mut seen: Vec<&str> = Vec::new();
    for host in registrations() {
        assert!(
            !seen.contains(&host.name),
            "two registrations claim the name {}",
            host.name
        );
        seen.push(host.name);
        assert!(
            !host.name.is_empty() && host.name == host.name.trim(),
            "host name {:?} is not a usable identifier fragment",
            host.name
        );
    }
}

#[test]
fn the_suite_actually_ran_something_here() {
    // A run in which every host was unavailable would report green. That is the
    // worst outcome available to a conformance suite, so the environment has to
    // have been enough for at least one host.
    let hosts = registrations();
    let available: Vec<&str> = hosts
        .iter()
        .filter(|host| host.skip_note().is_none())
        .map(|host| host.name)
        .collect();
    assert!(
        !available.is_empty(),
        "no host in the suite could be started here; nothing was measured. Notes: {}",
        hosts
            .iter()
            .map(|host| format!("{}: {}", host.name, host.skip_note().unwrap_or("available")))
            .collect::<Vec<_>>()
            .join(" | ")
    );
}

#[test]
fn ci_asked_for_and_got_every_host_it_named() {
    // The inverse guard to `the_suite_actually_ran_something_here`: CI names the
    // hosts it believes it tested, and a service that died quietly must not be
    // counted as a pass.
    let demanded_text = std::env::var("GITIUP_CONFORMANCE_REQUIRE_HOSTS").unwrap_or_default();
    let demanded: Vec<&str> = demanded_text
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    let hosts = registrations();
    let mut problems = Vec::new();
    for name in &demanded {
        let Some(host) = hosts.iter().find(|host| host.name == *name) else {
            problems.push(format!(
                "{name} is demanded but is not a host of this suite ({:?})",
                hosts.iter().map(|host| host.name).collect::<Vec<_>>()
            ));
            continue;
        };
        if let Some(note) = host.skip_note() {
            problems.push(format!("{name} was demanded and is not available: {note}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The matrix CI prints: every host, what it offers, what it declines, and whether
/// it can run here. Run with `-- --nocapture` to read it.
#[test]
fn the_matrix_of_what_is_measured() {
    let mut lines = vec![format!(
        "{:<16} {:<7} {:>5} {:>8}",
        "HOST", "KIND", "OFFER", "SKIPS"
    )];
    for host in registrations() {
        lines.push(gitiup_host_tests::summary(host));
        for (body, reason) in host.skips {
            lines.push(format!("    skip {body}: {reason}"));
        }
    }
    let text = lines.join("\n");
    println!("{text}");
    assert!(text.contains("fs"), "the summary is not a summary: {text}");
}

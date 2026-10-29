//! A change published on one host, read and merged through another (giti-b2z.6).
//!
//! Every other test in this crate measures one host at a time. This file measures the
//! claim that makes the whole design worth having: a change is a ref, so *where* it lives
//! is not part of what it means. A contributor publishes to a bucket because that is the
//! host they have credentials for; the owner merges from a plain git repository because
//! that is where their branch lives; and if the two stores disagreed about one byte of the
//! record, the merge would cite a digest nobody else can reproduce and every attestation
//! that named it would quietly be about nothing.
//!
//! The pairs are declared in [`gitiup_host_tests::hosts::cross_pairs`] so the coverage
//! test can insist the bucket→git direction is covered, and so CI's live run asks the
//! same question of a real MinIO and a real `git-http-backend` that the hermetic run asks
//! of an in-process bucket and a scratch repository.

use gitiup_host::change;
use gitiup_host_tests::changes::across_hosts;
use gitiup_host_tests::hosts;
use gitiup_host_tests::registration::Registration;
use gitiup_host_tests::runner;

/// Which pairs have a named test here.
///
/// `tests/coverage.rs` fails if a pair is registered without a test, because an
/// untested cross-host claim is the quietest hole this crate can have: both hosts pass
/// every single-host body, and the merge still cites a digest only one of them can
/// produce.
const TESTED_PAIRS: &[&str] = &["s3-memory->git-file"];

/// The live pair, when the live transport is compiled in at all.
#[cfg(feature = "s3")]
const TESTED_LIVE_PAIRS: &[&str] = &["s3-minio->git-http"];

fn tested_pairs() -> Vec<&'static str> {
    let mut names = TESTED_PAIRS.to_vec();
    #[cfg(feature = "s3")]
    names.extend(TESTED_LIVE_PAIRS);
    names
}

/// Look one pair up by name.
fn pair(name: &str) -> (&'static Registration, &'static Registration) {
    let found = hosts::cross_pairs()
        .into_iter()
        .find(|(pair, _, _)| *pair == name)
        .unwrap_or_else(|| {
            panic!(
                "`{name}` is not a cross-host pair: `hosts::cross_pairs` offers {:?}",
                hosts::cross_pairs()
                    .iter()
                    .map(|(pair, _, _)| *pair)
                    .collect::<Vec<_>>()
            )
        });
    (found.1, found.2)
}

/// Run the cross-host body for one named pair.
fn run(name: &str) {
    let (publisher, merger) = pair(name);
    // The pair, or a printed skip: a host CI demanded is a failure, not a quiet pass.
    let Some((from, to)) = runner::pair(publisher, merger) else {
        return;
    };
    eprintln!(
        "cross-host: publish on {} ({}), read and merge through {} ({})",
        publisher.name, publisher.kind, merger.name, merger.kind
    );
    across_hosts(from.host(), to.host());
}

/// The bucket publishes; the bare repository on a local path reads and merges.
///
/// Runs everywhere, because both halves are hermetic.
#[test]
fn s3_memory_publishes_and_the_plain_git_host_merges() {
    run("s3-memory->git-file");
}

/// The same body over the real transports: a live MinIO bucket publishes, a repository
/// served by `git-http-backend` reads it and merges it.
///
/// This is the pair CI demands (`GITIUP_CONFORMANCE_REQUIRE_HOSTS=s3-minio,git-http`), so
/// here a service that failed to start is a failure rather than a skip — and the step in
/// `ci/host-conformance.sh` and the workflow names it, so the log says which transports
/// were actually crossed.
#[cfg(feature = "s3")]
#[test]
fn the_live_bucket_publishes_and_the_served_repository_merges() {
    run("s3-minio->git-http");
}

/// The drift guard for this file: every registered pair has a test, and every test names
/// a registered pair.
#[test]
fn every_cross_pair_has_a_test() {
    let pairs = hosts::cross_pairs();
    let tested = tested_pairs();
    let mut problems = Vec::new();
    for (name, publisher, merger) in &pairs {
        if !tested.contains(name) {
            problems.push(format!(
                "`{name}` is a cross-host pair with no test in this file: add one, or drop \
                 the pair"
            ));
        }
        // The direction is the claim, not a detail: publishing on a *bucket* and merging
        // on *git* is what a contributor without a forge actually does.
        if publisher.kind != gitiup_host::HostKind::S3 || merger.kind != gitiup_host::HostKind::Git
        {
            problems.push(format!(
                "`{name}` publishes on {} and merges on {}; the pair this suite promises is \
                 a bucket publishing and a git host merging",
                publisher.kind, merger.kind
            ));
        }
    }
    for name in &tested {
        if !pairs.iter().any(|(pair, _, _)| pair == name) {
            problems.push(format!("`{name}` has a test but is not a registered pair"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A cross-host change is *transferred*, and the transfer is part of the claim: objects
/// first, then refs, or the receiving store advertises a record it cannot return. This
/// checks the order by breaking it in the only way a caller can — reading the far side
/// before anything was carried.
#[test]
fn a_change_is_invisible_on_the_other_host_until_it_is_carried() {
    let (publisher, merger) = pair("s3-memory->git-file");
    let Some((from_store, to_store)) = runner::pair(publisher, merger) else {
        return;
    };
    let (from, to) = (from_store.host(), to_store.host());
    let commits = gitiup_host_tests::changes::commits(to).expect("commits the merger can name");
    gitiup_host_tests::changes::publish_branch(from, &commits).expect("publish the branch");
    let record = gitiup_host_tests::changes::signed(
        "ada",
        "Nothing has crossed yet",
        &commits.first,
        &commits.first,
        0,
        None,
        &commits.base,
    )
    .expect("a signed attempt 0");
    let published =
        gitiup_host_tests::changes::publish(from, &record, "ada").expect("publish the change");
    let id = published.change_id.clone();

    // Nothing crossed, so the far store is honest about knowing nothing: an empty
    // listing, and a ref that is simply not there. A host that answered *anything* else
    // here — an error, or worse, a record — would be the drift this file is about.
    assert!(
        change::list_changes(to)
            .expect("the other store lists nothing")
            .changes
            .is_empty()
    );
    let missing = change::change_at(to, &change::change_head_ref(&id))
        .expect_err("the change is not on the far host yet");
    assert_eq!(
        missing.kind(),
        gitiup_host::HostErrorKind::NotFound,
        "{missing}"
    );

    // And once it is carried, the ref resolves and the record re-hashes to its own name
    // on the other side: the bytes, not a description of them, crossed.
    let carried = gitiup_host_tests::changes::transfer(from, to, "").expect("carry it");
    assert!(carried.objects > 0 && !carried.refs.is_empty());
    let shown = change::change_at(to, &change::change_head_ref(&id)).expect("now it resolves");
    assert_eq!(shown.digest, published.record_digest);
    assert_eq!(
        shown.bytes,
        record.canonical_bytes().expect("canonical bytes"),
        "verbatim, on the other host"
    );
}

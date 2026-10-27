//! Live smoke test against the real forge, off by default.
//!
//! Every other test in this crate talks to [`MockForge`] or to recorded fixtures,
//! which is what makes them fast and what makes a failure mean something. That
//! isolation has one blind spot: the mock's shape is *my* belief about what the API
//! returns. A field I invented, an envelope I forgot (the check-run listing is
//! `{"check_runs": [...]}`, not a bare array — that bug is only visible against the
//! forge), a header the real service adds: none of those can be caught by a double
//! that agrees with the code under test.
//!
//! So this file asks the real thing, read-only, and only when told to:
//!
//! ```text
//! GITIUP_LIVE_GITHUB=1 GITIUP_LIVE_GITHUB_REPO=rust-lang/rust \
//!     cargo test -p gitiup-host-github --test live_forge -- --nocapture
//! ```
//!
//! It never writes. It runs with no credential by default, so what it can prove is
//! the anonymous read path; set `GITHUB_TOKEN` (or `GITIUP_GITHUB_TOKEN`) for the
//! authenticated version, which is also the only way to see rate-limit headers that
//! are not the anonymous quota. Private repositories need a token, and remember that
//! a private repository the token cannot read answers 404.
//!
//! This is also the file that proves the *feature gate* works from the other side:
//! a build without `hosts-github` does not compile it at all.

use gitiup_host::{Host, HostErrorExt, RefQuery, RefStore, RemoteConfig};
use gitiup_host_github::GitHubHost;

fn wanted() -> Option<(String, GitHubHost)> {
    if std::env::var("GITIUP_LIVE_GITHUB").is_err() {
        eprintln!(
            "skipping: set GITIUP_LIVE_GITHUB=1 (and GITIUP_LIVE_GITHUB_REPO=owner/repo, \
             default gitiup/gitiup) to run the live forge smoke test"
        );
        return None;
    }
    let repo =
        std::env::var("GITIUP_LIVE_GITHUB_REPO").unwrap_or_else(|_| "gitiup/gitiup".to_string());
    let remote =
        RemoteConfig::new("live", &format!("https://github.com/{repo}")).expect("a github remote");
    let host = GitHubHost::open(&remote).expect("the live host opens");
    Some((repo, host))
}

#[test]
#[ignore = "touches the network; see the module docs for how to ask for it"]
fn the_forge_answers_the_way_the_adapter_reads_it() {
    let Some((repo, host)) = wanted() else {
        return;
    };
    let facts = host.facts().expect("the repository document parses");
    assert_eq!(
        facts.full_name, repo,
        "the forge names the repository it answered for"
    );
    assert!(
        facts.default_branch.is_some(),
        "every repository has a default branch; if this fails, the field moved"
    );
    let info = host.describe();
    assert!(info.implemented_by.contains("gitiup-host-github"));

    // Refs: one page of a big listing is the pagination and the header parsing.
    let branches = host
        .list_refs(&RefQuery::prefix("refs/heads/"))
        .expect("branches list");
    assert!(
        !branches.is_empty(),
        "{repo} has branches, so an empty listing means the call or the parse is wrong"
    );
    for branch in branches.iter().take(3) {
        let read = host
            .get_ref(&branch.name)
            .expect("read one ref")
            .expect("it was just listed");
        assert_eq!(
            read.oid, branch.oid,
            "a ref reads back as what the listing said"
        );
    }

    // The change translation, against real pull requests: numbers, dates, refs and
    // authors must all survive the trip, and none of the JSON may ride along.
    let changes = host
        .changes("all")
        .expect("the pull request list translates");
    for change in changes.iter().take(5) {
        assert!(
            change.id.starts_with("gh-"),
            "a pull request becomes `gh-<number>`: {}",
            change.id
        );
        assert!(!change.title.is_empty(), "the title came through");
        let rendered = format!("{change:?}");
        for leaked in ["html_url", "\"login\"", "\"draft\":"] {
            assert!(
                !rendered.contains(leaked),
                "raw API shape leaked into the change record ({leaked}): {rendered}"
            );
        }
    }
    println!(
        "{}: {} branch(es), {} change(s), default branch {:?}, rate budget {}",
        facts.full_name,
        branches.len(),
        changes.len(),
        facts.default_branch,
        host.rate_budget().summary()
    );
}

#[test]
#[ignore = "touches the network; see the module docs for how to ask for it"]
fn a_missing_repository_says_so() {
    let Some(_) = wanted() else {
        return;
    };
    let remote = RemoteConfig::new(
        "missing",
        "https://github.com/gitiup/this-repository-does-not-exist-anywhere",
    )
    .expect("a remote");
    let host = GitHubHost::open(&remote).expect("opening does not touch the network");
    let error = host
        .list_refs(&RefQuery::all())
        .expect_err("there is nothing to list");
    assert!(
        !error.is_unreachable() || error.to_string().contains("repository"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("gitiup/this-repository-does-not-exist-anywhere"),
        "and it names the repository so the typo is findable: {error}"
    );
}

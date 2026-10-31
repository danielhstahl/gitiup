//! The reading order, and the two ways a hand-written order goes wrong: a page that
//! is not in it, and an entry for a page that no longer exists.
//!
//! The sidebar's order is a judgement about the reader, so it is written down in
//! `nav::GUIDES`; the cost of writing things down is that they can rot, so these
//! tests are what keep the list and `docs/` the same set of pages.

mod common;

use common::{Fixture, repo_root};
use gitiup_site::{Config, nav, render, tree};

#[test]
fn the_guide_list_is_exactly_the_pages_in_docs() {
    // Both directions, because both failures are silent: a guide missing from the
    // list is published in an arbitrary position, and a name in the list that no
    // longer has a file is a sidebar entry nobody can click.
    let sources = tree::discover(&repo_root()).expect("discover");
    let guides: Vec<String> = sources
        .iter()
        .filter(|s| s.kind == tree::Kind::Guide)
        .map(|s| gitiup_site::paths::stem(&s.rel))
        .collect();

    let missing: Vec<&String> = guides
        .iter()
        .filter(|stem| !nav::GUIDES.contains(&stem.as_str()))
        .collect();
    let stale: Vec<&&str> = nav::GUIDES
        .iter()
        .filter(|stem| !guides.iter().any(|guide| guide == *stem))
        .collect();
    let listed: Vec<&str> = nav::GUIDES.to_vec();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "docs/ has {guides:?}; nav::GUIDES has {listed:?} — missing {missing:?}, stale {stale:?}"
    );
}

#[test]
fn the_quickstart_is_what_the_sidebar_offers_first() {
    // Everything else assumes a reader who has run something once.
    assert_eq!(nav::GUIDES.first(), Some(&"quickstart"));
}

#[test]
fn every_page_is_reachable_from_the_sidebar() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    let site = render(&cfg).expect("render");
    for source in &site.sources {
        assert!(
            site.nav.lists(&source.out),
            "{} is built but not listed, so nothing links to it",
            source.rel
        );
    }
    assert!(site.problems().is_empty(), "{:?}", site.problems());
}

#[test]
fn the_guides_are_in_the_listed_order_not_the_filesystem_s() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    let site = render(&cfg).expect("render");
    let guides = site
        .nav
        .sections
        .iter()
        .find(|s| s.title == "Guides")
        .expect("a Guides section");
    let shown: Vec<String> = guides
        .entries
        .iter()
        .map(|e| gitiup_site::paths::stem(e.src.as_ref().expect("a guide has a source")))
        .collect();
    assert_eq!(
        shown,
        nav::GUIDES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
        "the sidebar shows them out of order"
    );
}

#[test]
fn the_decision_records_are_in_numeric_order_after_the_index() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    let site = render(&cfg).expect("render");
    let decisions = site
        .nav
        .sections
        .iter()
        .find(|s| s.title == "Decision records")
        .expect("a Decision records section");
    let outs: Vec<&str> = decisions.entries.iter().map(|e| e.out.as_str()).collect();
    assert_eq!(outs.first(), Some(&"docs/adr/index.html"));
    let adrs = &outs[1..];
    assert!(adrs.len() >= 5, "only {adrs:?}");
    assert!(
        adrs.windows(2).all(|pair| pair[0] <= pair[1]),
        "ADR numbers are the order they were accepted in: {outs:?}"
    );
}

#[test]
fn a_new_directory_under_docs_is_still_built_and_still_listed() {
    // A page under a new directory is not silently dropped: it gets a section of its
    // own in the sidebar, "Other pages", which is the difference between a page a
    // reader can reach and one that only exists on disk.
    let fixture = Fixture::new(&[
        ("docs/one.md", "# One\n"),
        ("docs/talks/slides.md", "# Slides\n"),
    ]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let other = site
        .nav
        .sections
        .iter()
        .find(|s| s.title == "Other pages")
        .expect("unsorted pages are still listed");
    assert!(
        other
            .entries
            .iter()
            .any(|e| e.out == "docs/talks/slides.html")
    );
    assert!(
        site.problems().is_empty(),
        "a page in a new directory is unordered, not wrong: {:?}",
        site.problems()
    );
}

#[test]
fn a_new_guide_is_reachable_before_anybody_has_thought_about_its_order() {
    // The graceful degradation of a hand-written order: an unranked page reads after
    // the ranked ones, and is still a page. `the_guide_list_is_exactly_the_pages_in_docs`
    // is the test that then makes the repository give it a place.
    let fixture = Fixture::new(&[
        ("docs/quickstart.md", "# Q\n"),
        ("docs/newthing.md", "# N\n"),
    ]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    assert!(site.nav.lists("docs/newthing.html"));
    let guides = site
        .nav
        .sections
        .iter()
        .find(|s| s.title == "Guides")
        .expect("a Guides section");
    let outs: Vec<&str> = guides.entries.iter().map(|e| e.out.as_str()).collect();
    assert_eq!(outs, vec!["docs/quickstart.html", "docs/newthing.html"]);
}

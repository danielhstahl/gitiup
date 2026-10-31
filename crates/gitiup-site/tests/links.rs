//! Where a link goes once the docs are a site — and what happens when it cannot go
//! anywhere.
//!
//! These run against a fixture checkout rather than the repository's own `docs/`,
//! because the interesting cases are the awkward ones (a directory link, a link out
//! of `docs/` into the source tree, an anchor that no heading has) and a test that
//! asserted facts about the real docs would break whenever somebody wrote a page.
//! The real docs get one test here, in `build_site.rs`: `check` is clean on them.

mod common;

use common::Fixture;
use gitiup_site::{Config, md::NoRewriting, render};

/// Render one page of a fixture checkout and return the built body plus the
/// problems `check` would report.
fn one_page(markdown: &str) -> (String, Vec<String>) {
    let fixture = Fixture::new(&[
        // The page under test gets a title of its own: a page without one is its own
        // finding, and these tests are about links.
        ("docs/one.md", &format!("# One\n\n{markdown}\n")),
        ("docs/two.md", "# Two\n\n## Section two\n"),
        ("docs/dir/README.md", "# A directory\n"),
        (
            "crates/gitiup-host/src/attest.rs",
            "// the implementation\n",
        ),
        ("crates/gitiup-host/README.md", "# gitiup-host\n"),
    ]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let page = site
        .pages
        .iter()
        .find(|p| p.src == "docs/one.md")
        .expect("the page under test was built");
    let problems = site
        .problems()
        .into_iter()
        .filter(|p| p.page == "docs/one.md")
        .map(|p| p.message)
        .collect();
    (page.body.clone(), problems)
}

fn href_of(markdown: &str) -> String {
    let (body, problems) = one_page(markdown);
    assert!(problems.is_empty(), "unexpected problems: {problems:?}");
    // The heading's own `#anchor` link is not the link under test.
    let hrefs: Vec<String> = common::hrefs(&body)
        .into_iter()
        .filter(|href| !href.starts_with('#'))
        .collect();
    assert_eq!(hrefs.len(), 1, "one link in {body}");
    hrefs[0].clone()
}

#[test]
fn a_link_to_another_page_becomes_the_built_page() {
    assert_eq!(href_of("[two](two.md)"), "two.html");
    assert_eq!(href_of("[two](./two.md)"), "two.html");
}

#[test]
fn an_anchor_travels_with_the_link() {
    assert_eq!(href_of("[two](two.md#section-two)"), "two.html#section-two");
}

#[test]
fn a_link_up_and_back_resolves_like_a_shell_would() {
    // From docs/one.md, the root README is ../README.md — and the built pages are
    // at the same relative depths, so the href is the same shape.
    let fixture = Fixture::new(&[
        ("README.md", "# The project\n"),
        ("docs/one.md", "# One\n\n[readme](../README.md)\n"),
    ]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let page = site.pages.iter().find(|p| p.src == "docs/one.md").unwrap();
    assert!(
        page.body.contains("href=\"../index.html\""),
        "{}",
        page.body
    );
    assert!(site.problems().is_empty(), "{:?}", site.problems());
}

#[test]
fn a_directory_link_lands_on_the_page_built_from_its_readme() {
    // `docs/adr/README.md` and the fixture-vector READMEs are linked this way, and
    // on GitHub a directory link works, so it has to here too.
    assert_eq!(href_of("[the directory](dir/)"), "dir/index.html");
    assert_eq!(href_of("[the directory](dir)"), "dir/index.html");
}

#[test]
fn a_link_out_of_the_docs_points_at_the_repository() {
    // A docs site that pretends the code is not there is a site where every
    // "see the implementation" is a dead link.
    assert_eq!(
        href_of("[attest.rs](../crates/gitiup-host/src/attest.rs)"),
        "https://example.test/project/repo/blob/main/crates/gitiup-host/src/attest.rs"
    );
    // A crate's README is not a page of this site either.
    assert_eq!(
        href_of("[gitiup-host](../crates/gitiup-host/README.md)"),
        "https://example.test/project/repo/blob/main/crates/gitiup-host/README.md"
    );
}

#[test]
fn a_link_into_a_fixture_directory_follows_the_same_rule() {
    let fixture = Fixture::new(&[
        ("docs/adr/0001-thing.md", "# One\n\n## Detail\n"),
        (
            "docs/adr/fixtures/v1/README.md",
            "# Vectors\n\n[the ADR](../../0001-thing.md#detail)\n",
        ),
    ]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let page = site
        .pages
        .iter()
        .find(|p| p.src == "docs/adr/fixtures/v1/README.md")
        .unwrap();
    assert!(
        page.body.contains("href=\"../../0001-thing.html#detail\""),
        "{}",
        page.body
    );
    assert!(site.problems().is_empty(), "{:?}", site.problems());
}

#[test]
fn an_unknown_target_is_reported_rather_than_left_quietly() {
    let (body, problems) = one_page("[nowhere](no-such-page.md)");
    // The href is left as written — a wrong guess is still a hint to a reader.
    assert!(body.contains("href=\"no-such-page.md\""), "{body}");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("no-such-page.md"), "{problems:?}");
    assert!(problems[0].contains("no page"), "{problems:?}");
}

#[test]
fn an_anchor_no_heading_has_is_reported() {
    let (_, problems) = one_page("[two](two.md#not-a-section)");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("docs/two.html` has no section `not-a-section"),
        "{problems:?}"
    );

    // A good anchor is not reported, which is what makes the first assertion mean
    // anything.
    let (_, clean) = one_page("[two](two.md#section-two)");
    assert!(clean.is_empty(), "{clean:?}");
}

#[test]
fn a_same_page_anchor_is_checked_against_this_page() {
    let (_, bad) = one_page("## Present\n\n[see](#absent)\n");
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(
        bad[0].contains("this page has no section `absent`"),
        "{bad:?}"
    );

    let (_, good) = one_page("## Present\n\n[see](#present)\n");
    assert!(good.is_empty(), "{good:?}");
}

#[test]
fn elsewhere_is_left_elsewhere() {
    assert_eq!(
        href_of("[elsewhere](https://example.test/a#b)"),
        "https://example.test/a#b"
    );
    assert_eq!(
        href_of("[post](mailto:who@example.test)"),
        "mailto:who@example.test"
    );
    assert_eq!(
        href_of("[a page](https://docs.example.test/x.md)"),
        "https://docs.example.test/x.md",
        "another site's markdown is not this site's business"
    );
}

#[test]
fn an_external_link_says_so_in_the_markup() {
    let (body, _) = one_page("[elsewhere](https://example.test/a)");
    assert!(body.contains("class=\"external\""), "{body}");
    let (internal, _) = one_page("[two](two.md)");
    assert!(!internal.contains("class=\"external\""), "{internal}");
}

#[test]
fn a_page_with_no_h1_is_reported_and_titled_by_its_file_name() {
    let fixture = Fixture::new(&[("docs/orphan.md", "## Just a section\n")]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let page = site
        .pages
        .iter()
        .find(|p| p.src == "docs/orphan.md")
        .unwrap();
    assert_eq!(page.title, "orphan", "the fallback is the file stem");
    let problems = site.problems();
    assert!(
        problems
            .iter()
            .any(|p| p.page == "docs/orphan.md" && p.message.contains("no `#` heading")),
        "{problems:?}"
    );
}

#[test]
fn reading_the_checkout_is_the_only_input() {
    // The rewriter is a pure function of the checkout: a config that names a
    // different source URL changes only the URLs in the output, and nothing else.
    let fixture = Fixture::new(&[
        ("docs/one.md", "[x](../crates/gitiup-host/README.md)\n"),
        ("crates/gitiup-host/README.md", "# host\n"),
    ]);
    let mut cfg = fixture.config();
    cfg.source_url = "https://git.example.org/fork/repo".to_string();
    cfg.source_ref = "trunk".to_string();
    let site = render(&cfg).expect("render");
    let page = site.pages.iter().find(|p| p.src == "docs/one.md").unwrap();
    assert!(
        page.body
            .contains("https://git.example.org/fork/repo/blob/trunk/crates/gitiup-host/README.md"),
        "{}",
        page.body
    );
}

#[test]
fn rendering_a_page_with_no_links_needs_no_rewriter() {
    // `md::render` is usable on its own, which is what the fixture tests above and
    // anything else embedding a fragment rely on.
    let rendered = gitiup_site::md::render("# Hi\n\nThere.\n", "x.md", &mut NoRewriting);
    assert_eq!(rendered.title(), Some("Hi"));
}

#[test]
fn a_config_without_a_docs_directory_says_so() {
    let empty = tempfile::tempdir().expect("tempdir");
    let cfg = Config::new(empty.path());
    let error = match render(&cfg) {
        Ok(_) => panic!("a checkout with no docs/ must not render"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("docs/"), "{message}");
    assert!(message.contains("--root"), "{message}");
}

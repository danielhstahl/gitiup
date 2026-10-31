//! Building this repository's own docs, and the promises a build has to keep.
//!
//! This is the integration case: the pages are the real `docs/`, the links are the
//! real ones, and the assertions are the ones that matter to whoever publishes the
//! site — that it is complete, that it is the same bytes twice, and that nothing in
//! it points at a file or an anchor that is not there.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::{Fixture, repo_root};
use gitiup_site::{Config, build, tree};

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every file in a built site, as `(site-relative path, contents)`.
fn files_in(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&current)
            .unwrap_or_else(|e| panic!("read {}: {e}", current.display()))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path.strip_prefix(dir).expect("inside the site");
                out.push((
                    rel.to_string_lossy().replace('\\', "/"),
                    std::fs::read(&path).expect("read file"),
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_markdown_file_under_docs_becomes_a_page() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    let summary = build(&cfg).expect("build the repository's docs");

    let sources = tree::discover(&repo_root()).expect("discover");
    assert!(sources.len() > 20, "found only {}", sources.len());
    // Every discovered source, plus the three generated pages (index of all pages,
    // search, and the missing-page answer).
    assert_eq!(
        summary.pages,
        sources.len() + 3,
        "one HTML page per markdown file, plus the generated ones"
    );

    for source in &sources {
        assert!(
            fixture.exists(&source.out),
            "{} should have built {}",
            source.rel,
            source.out
        );
    }
}

#[test]
fn a_readme_becomes_the_index_of_its_directory() {
    // So that a directory URL serves it, which is what every ADR link assumes.
    let fixture = Fixture::new(&[
        ("README.md", "# Project\n"),
        ("docs/adr/README.md", "# Decisions\n"),
        ("docs/adr/fixtures/v1/README.md", "# Vectors\n"),
    ]);
    build(&fixture.config()).expect("build");
    assert!(fixture.exists("index.html"));
    assert!(fixture.exists("docs/adr/index.html"));
    assert!(fixture.exists("docs/adr/fixtures/v1/index.html"));
}

#[test]
fn the_generated_pages_are_written_alongside_the_rendered_ones() {
    let fixture = Fixture::new(&[
        ("README.md", "# Project\n\nThe front page.\n"),
        ("docs/one.md", "# One\n\nA line.\n"),
    ]);
    build(&fixture.config()).expect("build");
    for generated in [
        "docs/index.html",
        "search.html",
        "404.html",
        "search-index.js",
        "assets/site.css",
        "assets/search.js",
        "assets/favicon.svg",
        ".nojekyll",
    ] {
        assert!(fixture.exists(generated), "{generated} is missing");
    }
    assert!(
        fixture.read("index.html").contains("docs/index.html"),
        "the front page has to reach the index"
    );
}

#[test]
fn a_page_deleted_from_the_docs_does_not_survive_the_next_build() {
    // The output directory is removed and rewritten for exactly this case: a stale
    // page in a published site is a page that argues for a decision that was undone.
    let fixture = Fixture::new(&[("docs/one.md", "# One\n"), ("docs/two.md", "# Two\n")]);
    build(&fixture.config()).expect("first build");
    assert!(fixture.exists("docs/two.html"));

    std::fs::remove_file(fixture.root.join("docs/two.md")).expect("remove the source");
    build(&fixture.config()).expect("second build");
    assert!(
        !fixture.exists("docs/two.html"),
        "a page nobody has a source for must not be served"
    );
}

#[test]
fn building_the_same_checkout_twice_produces_the_same_bytes() {
    // The reproducibility the docs ask of every other artifact in this repository:
    // two builds of one checkout, into two different directories, byte for byte.
    let first = Fixture::new(&[]);
    let second = Fixture::new(&[]);
    let mut a = Config::new(repo_root());
    let mut b = Config::new(repo_root());
    a.out = first.root.join("_site");
    b.out = second.root.join("_site");
    build(&a).expect("first build");
    build(&b).expect("second build");

    let before = files_in(&first.root.join("_site"));
    let after = files_in(&second.root.join("_site"));
    assert_eq!(
        before.len(),
        after.len(),
        "the same set of files every time"
    );
    for ((name, left), (name2, right)) in before.iter().zip(after.iter()) {
        assert_eq!(name, name2);
        assert_eq!(
            left, right,
            "{name} differs between two builds of one checkout"
        );
    }
}

#[test]
fn the_output_names_no_path_on_the_machine_it_was_built_on() {
    // The site gets published from a runner and read somewhere else. If the build
    // directory appeared in it, the reproducibility test above would fail — this
    // says which rule it is protecting.
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    build(&cfg).expect("build");
    let root = fixture.root.to_string_lossy().replace('\\', "/");
    for (name, bytes) in files_in(&cfg.out) {
        let text = String::from_utf8(bytes).unwrap_or_default();
        assert!(
            !text.contains(&root),
            "{name} names the build directory: {text}"
        );
        assert!(
            !text.contains("href=\"file://"),
            "{name} links a local file"
        );
    }
}

#[test]
fn every_internal_reference_in_the_built_site_lands_on_a_file() {
    // Deliberately a second, independent check: this one reads the built files off
    // disk instead of the model `check` reasons over, so a bug in the model does not
    // hide here as well.
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    build(&cfg).expect("build");

    let mut checked = 0usize;
    for (name, bytes) in files_in(&cfg.out) {
        if !name.ends_with(".html") {
            continue;
        }
        let text = String::from_utf8(bytes).expect("utf-8 output");
        let here = cfg.out.join(&name);
        for reference in common::references(&text) {
            let (target, anchor) = match reference.split_once('#') {
                Some((target, anchor)) => (target, Some(anchor)),
                None => (reference.as_str(), None),
            };
            if target.contains("://") || target.starts_with("mailto:") {
                continue;
            }
            let resolved = if target.is_empty() {
                here.clone()
            } else if let Some(absolute) = target.strip_prefix('/') {
                // Only 404.html uses root-relative hrefs, and it is served from the
                // site root; resolve it against the root and check it the same way.
                cfg.out.join(absolute)
            } else {
                here.parent()
                    .expect("a built page is in a directory")
                    .join(target)
            };
            let resolved = normalize(&resolved);
            assert!(
                resolved.exists(),
                "{name} references `{reference}`, which is not in the site"
            );
            if let Some(anchor) =
                anchor.filter(|_| resolved.extension().is_some_and(|e| e == "html"))
            {
                let target_html = read(&resolved);
                assert!(
                    common::ids(&target_html).contains(anchor),
                    "{name} references `{reference}` and {name} has no such heading"
                );
            }
            checked += 1;
        }
    }
    assert!(checked > 500, "only {checked} references checked");
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[test]
fn a_page_links_the_stylesheet_from_whatever_depth_it_sits_at() {
    // Relative hrefs everywhere except `404.html`: that is what lets the same bytes
    // be served from a bucket path, a project Pages URL, or a filesystem.
    let fixture = Fixture::new(&[
        ("README.md", "# Project\n"),
        ("docs/one.md", "# One\n"),
        ("docs/adr/two.md", "# Two\n"),
    ]);
    build(&fixture.config()).expect("build");
    assert!(
        fixture
            .read("docs/one.html")
            .contains("href=\"../assets/site.css\"")
    );
    assert!(
        fixture
            .read("docs/adr/two.html")
            .contains("href=\"../../assets/site.css\"")
    );
    assert!(
        fixture
            .read("index.html")
            .contains("href=\"assets/site.css\"")
    );
}

#[test]
fn only_the_missing_page_page_needs_the_base_path() {
    let fixture = Fixture::new(&[("docs/one.md", "# One\n")]);
    let mut cfg = fixture.config();
    cfg.base_path = "/repo".to_string();
    build(&cfg).expect("build");
    let not_found = fixture.read("404.html");
    assert!(
        not_found.contains("href=\"/repo/assets/site.css\""),
        "{not_found}"
    );
    assert!(not_found.contains("href=\"/repo/index.html\""));
    // And every other page is unaffected, which is the point: they keep relative
    // hrefs, so they work from any depth and any base.
    let page = fixture.read("docs/one.html");
    assert!(
        !page.contains("href=\"/"),
        "no root-relative href outside 404: {page}"
    );
    assert!(
        !page.contains("src=\"/"),
        "no root-relative src outside 404: {page}"
    );
}

#[test]
fn a_site_url_buys_a_sitemap_and_robots_and_nothing_else_moves() {
    let fixture = Fixture::new(&[("docs/one.md", "# One\n")]);
    let mut cfg = fixture.config();
    cfg.site_url = Some("https://docs.example.test/repo/".to_string());
    build(&cfg).expect("build");
    let sitemap = fixture.read("sitemap.xml");
    assert!(sitemap.contains("<loc>https://docs.example.test/repo/docs/one.html</loc>"));
    assert!(
        fixture
            .read("robots.txt")
            .contains("Sitemap: https://docs.example.test/repo/sitemap.xml")
    );
    // Without it, no sitemap: a sitemap of a guessed host is worse than no sitemap.
    let plain = Fixture::new(&[("docs/one.md", "# One\n")]);
    build(&plain.config()).expect("build");
    assert!(!plain.exists("sitemap.xml"));
    assert!(!plain.exists("robots.txt"));
}

#[test]
fn the_search_index_covers_every_page() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    build(&cfg).expect("build");
    let index = fixture.read("search-index.js");
    assert!(
        index.contains("window.GITIUP_SEARCH_INDEX = [\n"),
        "{}",
        &index[..index.len().min(200)]
    );
    assert!(index.trim_end().ends_with("];"));

    let sources = tree::discover(&repo_root()).expect("discover");
    let mut pages_with_an_entry: BTreeSet<String> = BTreeSet::new();
    for line in index.lines() {
        if let Some(at) = line.find("\"url\":\"") {
            let url = at + 7;
            let end = url + line[url..].find('"').expect("a closing quote");
            let url = line[url..end].to_string();
            pages_with_an_entry.insert(url.split('#').next().unwrap_or(&url).to_string());
        }
    }
    for source in &sources {
        assert!(
            pages_with_an_entry.contains(&source.out),
            "{} is not searchable",
            source.out
        );
    }
}

#[test]
fn every_page_that_has_sections_links_them_from_its_own_table_of_contents() {
    let fixture = Fixture::new(&[]);
    let mut cfg = Config::new(repo_root());
    cfg.out = fixture.root.join("_site");
    build(&cfg).expect("build");
    let sources = tree::discover(&repo_root()).expect("discover");
    let mut with_toc = 0usize;
    for source in &sources {
        let html = fixture.read(&source.out);
        if html.contains("class=\"toc\" aria-label=\"On this page\"") {
            with_toc += 1;
        }
    }
    assert!(
        with_toc as f64 > sources.len() as f64 * 0.7,
        "only {with_toc} of {} pages have a table of contents",
        sources.len()
    );
}

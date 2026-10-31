//! The search index: what an entry is, and what its text is made of.
//!
//! Search is the part of the site a reader touches most and looks at least, so the
//! assertions here are about what a hit would show: the heading without the anchor
//! glyph, the section's own prose, an anchor that the page really has, and JSON that
//! a browser will parse.

mod common;

use common::Fixture;
use gitiup_site::{render, search};

fn entries_for(markdown: &str) -> Vec<search::Entry> {
    let fixture = Fixture::new(&[("docs/page.md", markdown)]);
    let cfg = fixture.config();
    let site = render(&cfg).expect("render");
    let page = site.pages.first().expect("one page was built");
    search::entries_for(page)
}

#[test]
fn one_entry_per_section_and_the_url_carries_the_anchor() {
    let entries = entries_for(
        "# The page\n\nThe opening line.\n\n## First section\n\nWhat the first section says.\n\n## Second section\n\nWhat the second says.\n",
    );
    let urls: Vec<&str> = entries.iter().map(|e| e.url.as_str()).collect();
    assert_eq!(
        urls,
        vec![
            "docs/page.html#the-page",
            "docs/page.html#first-section",
            "docs/page.html#second-section",
        ],
        "a hit lands on the section, not the top of the page"
    );
    assert_eq!(entries[1].heading, "First section");
    assert_eq!(
        entries[1].text, "What the first section says.",
        "an entry carries its own section and not the page's"
    );
    assert_eq!(
        entries[1].page, "The page",
        "so the result line can name the page"
    );
}

#[test]
fn the_heading_text_is_the_heading_and_not_the_heading_plus_its_anchor_glyph() {
    // The renderer appends `<a class="anchor" href="#…">#</a>` to every heading; a
    // result that reads "Notes #" is a renderer detail leaking into the index.
    let entries = entries_for("# Notes\n\nBody.\n");
    assert_eq!(entries[0].heading, "Notes");
    assert!(!entries[0].heading.contains('#'));
}

#[test]
fn fenced_code_is_not_what_a_section_is_matched_on() {
    // Otherwise a search for `--store` finds every page that types it in an example
    // rather than the page that explains it.
    let entries = entries_for(
        "# Flags\n\nThe `--store` flag names a store.\n\n```console\n$ gitiup run --store ./store\n```\n",
    );
    assert!(entries[0].text.contains("The --store flag names a store."));
    assert!(
        !entries[0].text.contains("gitiup run --store"),
        "{}",
        entries[0].text
    );
}

#[test]
fn a_wrapped_paragraph_keeps_its_spaces() {
    // The docs are wrapped at 80 columns; a soft newline is a space in the text too,
    // or every index snippet is a wall of joined words.
    let entries = entries_for(
        "# Wrapped\n\nThis sentence is written across more than one source line so that the join is\nvisible in the index text.\n",
    );
    assert_eq!(
        entries[0].text,
        "This sentence is written across more than one source line so that the join is visible in the index text."
    );
}

#[test]
fn a_section_with_nothing_to_match_has_no_entry() {
    // A heading that only introduces a code fence contributes no prose, and an entry
    // with an empty snippet is noise in a result list. A table *is* prose: half the
    // content of an ADR is in its tables, and a search that could not find it would
    // be worse than one that shows a row's worth of text.
    let entries = entries_for(
        "# Page\n\n## Only a table\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n## Only code\n\n```sh\ntrue\n```\n",
    );
    let headings: Vec<&str> = entries.iter().map(|e| e.heading.as_str()).collect();
    assert_eq!(headings, vec!["Only a table"], "{entries:?}");
    assert_eq!(entries[0].text, "a b 1 2");
}

#[test]
fn snippets_are_capped_at_a_word_boundary() {
    let long = format!("# Long\n\n{} tail.\n", "word ".repeat(400));
    let entries = entries_for(&long);
    let text = &entries[0].text;
    assert!(
        text.chars().count() <= 902,
        "{} chars",
        text.chars().count()
    );
    assert!(text.ends_with('…'), "{text}");
    assert!(
        !text.ends_with("word …"),
        "the cut should land after a whole word: {text}"
    );
}

#[test]
fn the_json_escapes_what_json_needs() {
    assert_eq!(search::json_string("plain"), "\"plain\"");
    assert_eq!(search::json_string("say \"hi\""), "\"say \\\"hi\\\"\"");
    assert_eq!(search::json_string("back\\slash"), "\"back\\\\slash\"");
    assert_eq!(search::json_string("line\nbreak"), "\"line\\nbreak\"");
    assert_eq!(search::json_string("tab\there"), "\"tab\\there\"");
    // The docs write `refs/gitiup/quarantine/<slot>` and `&lt;` inside code spans;
    // those arrive as ordinary characters and must survive verbatim.
    assert_eq!(
        search::json_string("a < b & c"),
        "\"a < b & c\"",
        "JSON does not need HTML escaping, and doing it would show entities to the reader"
    );
}

#[test]
fn the_index_file_is_a_script_assigning_one_array() {
    // A page opened from a filesystem cannot fetch its neighbour, which is why the
    // index is `search-index.js` and not `search-index.json`.
    let fixture = Fixture::new(&[]);
    let mut cfg = gitiup_site::Config::new(common::repo_root());
    cfg.out = fixture.root.join("_site");
    gitiup_site::build(&cfg).expect("build");
    let index = fixture.read("search-index.js");
    let assigned = index
        .find("window.GITIUP_SEARCH_INDEX = ")
        .expect("one assignment");
    let body = index[assigned + "window.GITIUP_SEARCH_INDEX = ".len()..].trim_end();
    let body = body.strip_suffix(';').expect("terminated with a semicolon");
    assert!(body.starts_with("[\n") && body.ends_with("\n]"), "{body}");
    let entries = body.lines().filter(|line| line.starts_with('{')).count();
    assert!(entries > 100, "{entries} entries");
    for line in body.lines().filter(|line| line.starts_with('{')) {
        let line = line.trim_end_matches(',');
        assert!(line.starts_with("{\"page\":"), "{line}");
        assert!(line.ends_with('}'), "{line}");
        for key in ["\"page\":", "\"url\":", "\"heading\":", "\"text\":"] {
            assert!(line.contains(key), "{key} missing from {line}");
        }
    }
}

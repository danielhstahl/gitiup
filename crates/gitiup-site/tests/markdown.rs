//! Markdown, rendered: the rules this site builder promises, each one pinned here
//! rather than trusted.
//!
//! The set is chosen around what the repository's own docs depend on. The anchor
//! rule is the load-bearing one — `docs/` links between pages by anchor, written
//! against the ids GitHub gives headings, so if `slug_of` diverges from GitHub the
//! docs' own cross-links break quietly and only in the built site.

mod common;

use gitiup_site::md::{Heading, NoRewriting, Slugger, slug_of};

fn render(markdown: &str) -> gitiup_site::md::Rendered {
    gitiup_site::md::render(markdown, "docs/page.md", &mut NoRewriting)
}

#[test]
fn heading_ids_follow_githubs_rule() {
    // The cases the real docs use, each copied from a heading that exists in
    // `docs/` and an anchor that something else links to.
    let cases = [
        ("Simple heading", "simple-heading"),
        (
            "D2 — The document: `gitiup-policy-1`, canonical bytes",
            "d2--the-document-gitiup-policy-1-canonical-bytes",
        ),
        (
            "The quorum ladder (`tier: quorum`)",
            "the-quorum-ladder-tier-quorum",
        ),
        (
            "Attesting it: `gitiup quorum verdict --attest`",
            "attesting-it-gitiup-quorum-verdict---attest",
        ),
        (
            "The merge question: `gitiup verify change`",
            "the-merge-question-gitiup-verify-change",
        ),
        (
            "Refs, paths and `kv/` namespaces",
            "refs-paths-and-kv-namespaces",
        ),
        (
            "What `policy publish` says before it signs",
            "what-policy-publish-says-before-it-signs",
        ),
        ("100% of the flags", "100-of-the-flags"),
        ("snake_case and kebab-case", "snake_case-and-kebab-case"),
        ("  spaced out  ", "spaced-out"),
    ];
    for (heading, slug) in cases {
        assert_eq!(slug_of(heading), slug, "slug of {heading:?}");
    }
}

#[test]
fn a_heading_of_pure_punctuation_still_has_an_id() {
    // It has to be linkable to, and an empty `id=""` is not an id.
    assert_eq!(slug_of("…?!"), "section");
}

#[test]
fn unicode_headings_keep_their_letters() {
    // GitHub keeps non-ASCII word characters, and so does this: dropping them
    // would collide two translated headings onto the same anchor.
    assert_eq!(slug_of("Über die Sandbox"), "über-die-sandbox");
}

#[test]
fn duplicate_headings_get_suffixed_ids() {
    // Several ADRs have a `Consequences`, so this is not hypothetical.
    let rendered = render("## Consequences\n\nfirst\n\n## Consequences\n\nsecond\n");
    let slugs: Vec<&str> = rendered.headings.iter().map(|h| h.slug.as_str()).collect();
    assert_eq!(slugs, vec!["consequences", "consequences-1"]);
    assert!(rendered.html.contains("<h2 id=\"consequences\">"));
    assert!(rendered.html.contains("<h2 id=\"consequences-1\">"));
}

#[test]
fn every_heading_carries_its_own_anchor_link() {
    // Clicking a heading to copy its URL is what a reader expects; the anchor is
    // also what `check` proves a link to a section lands on.
    let rendered = render("## The ladder\n");
    assert!(
        rendered.html.contains(
            "<a class=\"anchor\" href=\"#the-ladder\" aria-label=\"Link to this section\">#</a>"
        ),
        "{}",
        rendered.html
    );
}

#[test]
fn inline_code_in_a_heading_reaches_the_title_and_the_slug() {
    let rendered = render("## Running `gitiup run` twice\n");
    assert_eq!(
        rendered.headings.first(),
        Some(&Heading {
            level: 2,
            text: "Running gitiup run twice".to_string(),
            slug: "running-gitiup-run-twice".to_string(),
        })
    );
    assert!(rendered.html.contains("<code>gitiup run</code>"));
}

#[test]
fn the_first_h1_is_the_page_title() {
    let rendered = render("# The title\n\n## A section\n");
    assert_eq!(rendered.title(), Some("The title"));

    let no_h1 = render("## Only a section\n");
    assert_eq!(
        no_h1.title(),
        None,
        "the caller falls back to the file name"
    );
}

#[test]
fn a_docs_pr_cannot_put_markup_in_the_site() {
    // Raw HTML is escaped, not passed through, and the attempt is counted so
    // `check` can say so out loud.
    let rendered = render("Before\n\n<script>alert(1)</script>\n\nAfter\n");
    assert!(!rendered.html.contains("<script>"), "{}", rendered.html);
    assert!(rendered.html.contains("&lt;script&gt;"));
    assert_eq!(rendered.raw_html, 1);

    let inline = render("Text with <b>inline markup</b> in it.\n");
    assert!(inline.html.contains("&lt;b&gt;"));
    assert_eq!(inline.raw_html, 2, "both tags, opening and closing");
}

#[test]
fn code_is_escaped_in_prose_and_in_fences() {
    let rendered = render(
        "Use `<img src=x onerror=alert(1)>` carefully.\n\n```sh\nif [ \"$a\" = \"<b>\" ]; then echo '</b>'; fi\n```\n",
    );
    assert!(!rendered.html.contains("<img"), "{}", rendered.html);
    assert!(rendered.html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(rendered.html.contains("&lt;/b&gt;"));
    assert_eq!(rendered.raw_html, 0, "code is not markup that was refused");
}

#[test]
fn a_fence_language_becomes_a_label_and_stays_in_the_attribute() {
    let rendered = render("```console\n$ gitiup version\n```\n");
    assert!(
        rendered
            .html
            .contains("<pre class=\"code\" data-lang=\"console\">")
    );

    // A fence's info string is not a safe attribute value until this says so: the
    // tag is kept, the rest of the string is dropped or filtered.
    let tagged = render("```rust,ignore\nlet x = 1;\n```\n");
    assert!(
        tagged.html.contains("data-lang=\"rust\""),
        "{}",
        tagged.html
    );
    let hyphenated = render("```sh+jinja\necho hi\n```\n");
    assert!(
        hyphenated.html.contains("data-lang=\"sh+jinja\""),
        "{}",
        hyphenated.html
    );

    let plain = render("```\nnothing named\n```\n");
    assert!(plain.html.contains("<pre class=\"code\"><code>"));
}

#[test]
fn a_pipe_escaped_in_a_table_cell_stays_in_the_cell() {
    // The docs write `gitiup quorum verdict\|dispute` inside table cells; a pipe
    // that split the cell would silently re-shape the table.
    let rendered = render(
        "| verb | what |\n|------|------|\n| `verdict\\|dispute` | tallies and explains |\n",
    );
    assert!(rendered.html.contains("<div class=\"table-wrap\"><table>"));
    assert!(
        rendered.html.contains("verdict|dispute"),
        "{}",
        rendered.html
    );
    assert_eq!(
        rendered.html.matches("<td>").count(),
        2,
        "two cells, not three: {}",
        rendered.html
    );
    assert!(rendered.html.contains("<thead>"));
}

#[test]
fn smart_punctuation_stays_off_because_flags_are_written_with_dashes() {
    // `--store` in a sentence must not become an en dash. This is the option this
    // renderer refuses, and a future change to the option list would be caught here.
    let rendered = render("Pass --store and don't be clever.\n");
    assert!(rendered.html.contains("--store"), "{}", rendered.html);
    assert!(rendered.html.contains("don&#39;t"), "{}", rendered.html);
    assert!(!rendered.html.contains('–'));
}

#[test]
fn the_description_is_the_first_paragraph_not_a_preamble_note() {
    // Every guide in `docs/` opens with an italic note in a block quote about how
    // the page is executed; that is not the one-liner the index wants.
    let rendered = render(
        "# The sandbox\n\n> *This page is executed, not eyeballed.*\n\nThe sandbox says what confined a run.\n\n## Later\n",
    );
    assert_eq!(
        rendered.description,
        "The sandbox says what confined a run."
    );
}

#[test]
fn the_plain_text_is_the_prose_and_not_the_code() {
    // Search matches on this: a search for `--store` should find the page that
    // explains the flag, not every page that types it in an example.
    let rendered = render(
        "The flag --store names a store.\n\n```console\n$ gitiup run --store ./store\n```\n",
    );
    assert!(rendered.text.contains("The flag --store names a store."));
    assert!(
        !rendered.text.contains("gitiup run --store ./store"),
        "fenced code is not prose: {}",
        rendered.text
    );
}

#[test]
fn lists_quotes_rules_and_task_markers_render() {
    let rendered = render(
        "- one\n- two\n  - nested\n\n1. first\n2. second\n\n> a quote\n\n---\n\n- [x] done\n- [ ] not\n",
    );
    for expected in [
        "<ul>",
        "<li>one</li>",
        "<li>two",
        "<ol>",
        "<li>first</li>",
        "<blockquote>",
        "<hr>",
        "<input type=\"checkbox\" disabled checked>",
        "<input type=\"checkbox\" disabled>",
    ] {
        assert!(
            rendered.html.contains(expected),
            "missing {expected}: {}",
            rendered.html
        );
    }
}

#[test]
fn a_footnote_links_from_its_reference_to_its_definition() {
    let rendered = render("A claim[^1].\n\n[^1]: The evidence behind the claim.\n");
    assert!(
        rendered
            .html
            .contains("<sup class=\"footnote-ref\"><a href=\"#fn-1\"")
    );
    assert!(rendered.html.contains("id=\"fn-1\""));
}

#[test]
fn the_slugger_suffixes_only_when_it_has_to() {
    let mut slugs = Slugger::default();
    assert_eq!(slugs.slug("Notes"), "notes");
    assert_eq!(slugs.slug("Other"), "other");
    assert_eq!(slugs.slug("Notes"), "notes-1");
    assert_eq!(slugs.slug("Notes"), "notes-2");
}

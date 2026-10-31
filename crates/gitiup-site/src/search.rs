//! The search index.
//!
//! Search on a static site is a JSON file and a script, and both are written here.
//! There is no search server to depend on, no index to rebuild in a second language,
//! and nothing to phone home to: the whole thing is `search-index.json` and
//! `assets/search.js`, which is also why search works from a filesystem as readily
//! as from Pages.
//!
//! The unit of the index is a **section**, not a page: an entry's url carries the
//! heading's anchor, so a hit for "quorum verdict exit codes" lands on the section
//! that discusses them instead of the top of a 100 KB page. The sections are cut out
//! of the rendered body, so an entry can only ever point at an anchor the page
//! really has — there is no second implementation of "what headings does this page
//! have" to fall out of step with the first.
//!
//! Fenced code is dropped from the text a section is matched on, for the reason in
//! `md.rs`: a search for a flag should find the page that explains it, not every
//! page that types it once.

use std::fmt::Write as _;

use crate::paths;

/// How much prose an entry carries: enough for a useful snippet, short enough that
/// the index of this repository's docs stays a small download.
const TEXT_CAP: usize = 900;

/// One index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The page's title, shown on the result line.
    pub page: String,
    /// `docs/quorum.html#verdict-semantics`, site-relative.
    pub url: String,
    /// The section's heading, or the page title for the opening section.
    pub heading: String,
    /// The section's prose, capped, markup gone.
    pub text: String,
}

/// The index for a set of built pages, as JSON text.
///
/// Deterministic: pages in the order given (which is the sidebar's reading order,
/// so the page a reader would have picked first wins a tie), sections in document
/// order, keys in a fixed order, no timestamps.
pub fn index(pages: &[&crate::Built]) -> String {
    let mut out = String::from("[\n");
    let mut first = true;
    for page in pages {
        for entry in entries_for(page) {
            if !first {
                out.push_str(",\n");
            }
            first = false;
            let _ = writeln!(
                out,
                "{{\"page\":{},\"url\":{},\"heading\":{},\"text\":{}}}",
                json_string(&entry.page),
                json_string(&entry.url),
                json_string(&entry.heading),
                json_string(&entry.text)
            );
        }
    }
    out.push_str("\n]\n");
    out
}

/// The entries one page contributes.
pub fn entries_for(page: &crate::Built) -> Vec<Entry> {
    let mut entries = Vec::new();
    for section in sections(page.body.as_str()) {
        let text = cap(&strip_tags_and_entities(section.html), TEXT_CAP);
        if text.is_empty() {
            continue;
        }
        entries.push(Entry {
            page: page.title.clone(),
            url: match &section.anchor {
                Some(anchor) => format!("{}#{anchor}", page.out),
                None => page.out.clone(),
            },
            heading: section.heading.unwrap_or_else(|| page.title.clone()),
            text,
        });
    }
    entries
}

/// One slice of a rendered page: the bits under one heading.
struct Section<'a> {
    /// The heading's `id`, or `None` for whatever precedes the first heading.
    anchor: Option<String>,
    /// The heading's visible text, if it has one.
    heading: Option<String>,
    /// The body between the heading tag and the next one.
    html: &'a str,
}

/// A heading tag found in the rendered body.
struct Mark {
    /// Where the `<hN` starts.
    start: usize,
    /// Where the body starts, just after `</hN>`.
    content: usize,
    /// The heading's `id`.
    anchor: String,
    /// The heading's visible text.
    heading: String,
}

/// Cut a rendered page at its own heading tags.
///
/// The renderer emits `<hN id="slug">text<a class="anchor" …>#</a></hN>`, so the
/// anchors and the heading texts are already in the body and cannot disagree with
/// the page.
fn sections(body: &str) -> Vec<Section<'_>> {
    let marks = heading_marks(body);
    let mut out = Vec::with_capacity(marks.len() + 1);
    let first_start = marks.first().map(|m| m.start).unwrap_or(body.len());
    if !body[..first_start].trim().is_empty() {
        out.push(Section {
            anchor: None,
            heading: None,
            html: &body[..first_start],
        });
    }
    for (i, mark) in marks.iter().enumerate() {
        let end = marks
            .get(i + 1)
            .map(|next| next.start)
            .unwrap_or(body.len());
        out.push(Section {
            anchor: Some(mark.anchor.clone()),
            heading: Some(mark.heading.clone()),
            html: &body[mark.content..end],
        });
    }
    out
}

/// Every `<hN id="…">` in the body, in order, with the heading's text.
fn heading_marks(body: &str) -> Vec<Mark> {
    let mut marks = Vec::new();
    for (i, _) in body.match_indices("<h") {
        let prefix = &body[i..];
        // `<h`, one digit, ` id="`, the anchor, `">`. Anything shaped differently
        // (a `<hr>`, a literal `<h` in a code block that got escaped) is not one.
        let Some(level) = prefix.as_bytes().get(2).copied() else {
            continue;
        };
        if !level.is_ascii_digit() {
            continue;
        }
        let Some(after_level) = prefix.get(3..).and_then(|s| s.strip_prefix(" id=\"")) else {
            continue;
        };
        let Some(quote) = after_level.find('"') else {
            continue;
        };
        let anchor = &after_level[..quote];
        let after_anchor = 3 + 5 + quote + 2; // `id="` + anchor + `">`
        let tail = match body.get(i + after_anchor..) {
            Some(tail) => tail,
            None => continue,
        };
        // The renderer puts a `<a class="anchor" …>#</a>` at the end of every
        // heading, and that `#` is chrome: the index entry for `## Notes` has to say
        // "Notes", not "Notes #". So the heading's own text stops where that link
        // begins, and the section's body starts after the closing `</hN>`.
        let heading_close = match tail.find("</h") {
            Some(at) => at,
            None => continue,
        };
        let text_end = match tail.find("<a class=\"anchor\"") {
            Some(at) => at.min(heading_close),
            None => heading_close,
        };
        let text = strip_tags_and_entities(&tail[..text_end]);
        let content = i + after_anchor + heading_close + "</hN>".len();
        if content > body.len() || anchor.is_empty() {
            continue;
        }
        marks.push(Mark {
            start: i,
            content,
            anchor: anchor.to_string(),
            heading: text,
        });
    }
    marks
}

/// Drop every tag — including a `<pre>`'s contents — and decode the entities the
/// renderer wrote.
fn strip_tags_and_entities(html: &str) -> String {
    let mut plain = String::with_capacity(html.len() / 2 + 1);
    let mut rest = html;
    let mut in_pre = false;
    while let Some(i) = rest.find('<') {
        if !in_pre {
            plain.push_str(&rest[..i]);
        }
        let after = &rest[i..];
        let Some(j) = after.find('>') else {
            // A `<` with no closing `>` is text that failed to be a tag.
            if !in_pre {
                plain.push_str(after);
            }
            rest = "";
            break;
        };
        let tag = &after[..=j];
        if tag.starts_with("<pre") {
            in_pre = true;
        } else if tag.starts_with("</pre") {
            in_pre = false;
        }
        // One space per tag: `good<a>x</a>bye` is two words, not `goodxbye`.
        plain.push(' ');
        rest = &after[j + 1..];
    }
    if !in_pre {
        plain.push_str(rest);
    }
    collapse(&decode_entities(&plain))
}

/// Decode the five entities the renderer emits. Full named-entity tables are a
/// dependency, and nothing in these docs needs `&mdash;` back out.
fn decode_entities(text: &str) -> String {
    const ENTITIES: [(&str, &str); 5] = [
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
    ];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        match ENTITIES
            .iter()
            .find(|(entity, _)| after.starts_with(entity))
        {
            Some((entity, replacement)) => {
                out.push_str(replacement);
                rest = &after[entity.len()..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shorten to `limit` characters, not mid-word: an index snippet that stops inside
/// `selection_policy` matches nothing a reader would type.
fn cap(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit).collect();
    // Keep whole words: a snippet that stops inside `selection_policy` matches
    // nothing a reader would type.
    if let Some(space) = out.rfind(' ').filter(|at| *at > limit / 2) {
        out.truncate(space);
    }
    out.push('…');
    out
}

/// One JSON string, escaped.
///
/// Hand-written rather than a dependency: this crate refuses to grow a serializer
/// for one file's worth of output, and the rules are five cases.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The body of `search.html`.
///
/// The header's form on every page submits here; the script reads `?q=` and fills
/// in the list. Without JavaScript the page says so and points at the index, rather
/// than looking broken.
pub fn search_body() -> String {
    String::from(
        "<h1 id=\"search\">Search</h1>\n\
         <form class=\"search search-page\" action=\"search.html\" method=\"get\" role=\"search\">\n\
         <input type=\"search\" name=\"q\" placeholder=\"Search the docs\" aria-label=\"Search the docs\">\n\
         <button type=\"submit\">Search</button>\n\
         </form>\n\
         <p class=\"search-status\" id=\"search-status\">Type to search the documentation.</p>\n\
         <ul class=\"results\" id=\"search-results\"></ul>\n\
         <noscript><p><strong>Search needs JavaScript.</strong> Everything else here works without \
         it, including the <a href=\"docs/index.html\">index of every page</a>.</p></noscript>\n",
    )
}

/// The body of `docs/index.html`: every page in reading order, with the first
/// paragraph of each under it.
pub fn docs_index(nav: &crate::nav::Nav) -> String {
    let mut body = String::from(
        "<h1 id=\"every-page\">Every page</h1>\n<p>Everything <code>gitiup-site</code> builds, in the order it is meant to be read.</p>\n",
    );
    for section in &nav.sections {
        if section.entries.is_empty() {
            continue;
        }
        let _ = writeln!(
            body,
            "<h2 id=\"{}\">{}</h2>\n<ul class=\"index-list\">",
            crate::md::slug_of(&section.title),
            crate::md::escape_html(&section.title)
        );
        for entry in &section.entries {
            let _ = writeln!(
                body,
                "<li><a href=\"{}\"><strong>{}</strong></a>",
                paths::relative(paths::dir_of(crate::DOCS_INDEX), &entry.out),
                crate::md::escape_html(&entry.title)
            );
            if let Some(description) = &entry.description {
                let _ = write!(body, " — {}", crate::md::escape_html(description));
            }
            body.push_str("</li>\n");
        }
        body.push_str("</ul>\n");
    }
    body
}

/// The `sitemap.xml` for a site published at an absolute URL, or empty when no
/// absolute URL was given — a sitemap of a guessed host is worse than none.
pub fn sitemap(cfg: &crate::Config, pages: &[&crate::Built]) -> String {
    let Some(site) = cfg.site_url() else {
        return String::new();
    };
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for page in pages {
        let _ = writeln!(out, "  <url><loc>{site}/{}</loc></url>", page.out);
    }
    out.push_str("</urlset>\n");
    out
}

/// The `robots.txt`, or empty when there is no absolute site URL to point at.
pub fn robots(cfg: &crate::Config) -> String {
    let Some(site) = cfg.site_url() else {
        return String::new();
    };
    format!("User-agent: *\nAllow: /\n\nSitemap: {site}/sitemap.xml\n")
}

//! Markdown in, HTML out — plus the two things a *site* needs that a plain
//! renderer does not: an `id` on every heading, and links rewritten from the
//! source tree to the built tree.
//!
//! The renderer walks `pulldown-cmark`'s events rather than calling
//! [`pulldown_cmark::push_html`] because both of those jobs are easier on the event
//! stream than on someone else's HTML: a heading's text has to be read before its
//! `id` can be chosen, and a link's destination has to be resolved against the file
//! it appears in.
//!
//! Two decisions in here are load-bearing for the docs this crate renders:
//!
//! * **The heading ids are GitHub's.** The docs already link to each other by
//!   anchor (`verification.md#the-quorum-ladder-tier-quorum`), and those anchors
//!   were written against the ids GitHub gives headings when it renders a `.md`.
//!   [`slug_of`] reproduces that rule — lowercase, punctuation dropped, every
//!   whitespace character becoming a `-`, duplicate headings suffixed `-1`, `-2` —
//!   so a link written for the GitHub view lands here too. `tests/markdown.rs`
//!   pins the rule and `gitiup-site check` proves every anchor in `docs/` resolves.
//! * **Raw HTML in a doc is escaped, not passed through.** A docs PR is not a
//!   trusted input: letting `<script>` through would mean any contributor can run
//!   script on the project's own site. No page in `docs/` uses raw HTML today, and
//!   `check` reports the count so that stays true out loud rather than by accident.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use pulldown_cmark::{
    Alignment, BlockQuoteKind, CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd,
};

/// The extensions these docs use: GFM tables (every ADR is full of them), struck
/// text, task-list checkboxes, and footnotes. Deliberately off: smart punctuation,
/// which would turn the `--flag` in a sentence into an en dash, and math.
fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES
}

/// A heading in a rendered page, with the `id` it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heading {
    /// 1 for `#`, 2 for `##`, and so on.
    pub level: u8,
    /// The heading's text with the markup gone — what `<title>`, the table of
    /// contents and the sidebar show.
    pub text: String,
    /// The `id` it was given, without the `#`.
    pub slug: String,
}

/// One page's worth of rendering.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The page body as HTML — a fragment. The `<html>` shell is `template`'s job.
    pub html: String,
    /// Every heading, in document order.
    pub headings: Vec<Heading>,
    /// The whole body as plain text, for the search index.
    pub text: String,
    /// The page's summary line: the first paragraph that is not inside a block quote
    /// and is not the italic note almost every page here opens with. The index pages
    /// show it under the title.
    pub description: String,
    /// How many raw-HTML spans were escaped: the number of places a doc tried to
    /// put markup into the site. `check` reports it.
    pub raw_html: usize,
}

impl Rendered {
    /// The page's title: its first `#` heading, or `None` if it has none. The
    /// caller decides what to fall back to (a filename), and `check` is what
    /// reports the file that forced the fallback.
    pub fn title(&self) -> Option<&str> {
        self.headings
            .iter()
            .find(|h| h.level == 1)
            .map(|h| h.text.as_str())
    }
}

/// The anchor for a heading, computed the way GitHub computes it.
///
/// Lowercase; every character that is not a letter, a digit, `-` or `_` dropped;
/// every whitespace character turned into a `-`. Runs are *not* collapsed, which is
/// what makes `## D2 — The thing` become `d2--the-thing` (two dashes: the em dash
/// is dropped, and each of the two spaces around it becomes one). The docs are
/// written against exactly this, so the double dash is a rule and not a typo.
pub fn slug_of(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.trim().chars() {
        if ch.is_whitespace() {
            out.push('-');
        } else if ch == '-' || ch == '_' || ch.is_alphanumeric() {
            // `is_alphanumeric` is Unicode-aware, as GitHub's is: a heading in
            // another script gets its own letters in the anchor instead of nothing.
            let _ = write!(out, "{}", ch.to_lowercase());
        }
    }
    if out.is_empty() {
        // A heading of pure punctuation still needs an id to be linkable to.
        return "section".to_string();
    }
    out
}

/// Hands out heading ids the way GitHub does: the first heading gets the plain
/// slug, the second identical one `-1`, the third `-2`.
///
/// The docs really do repeat headings — each ADR has a `Consequences`, several
/// guides have a `Notes` — so this is not a theoretical case.
#[derive(Default)]
pub struct Slugger {
    seen: BTreeMap<String, usize>,
}

impl Slugger {
    /// The `id` for `text`, suffixing duplicates.
    pub fn slug(&mut self, text: &str) -> String {
        let base = slug_of(text);
        let n = self.seen.entry(base.clone()).or_insert(0);
        *n += 1;
        if *n == 1 {
            base
        } else {
            format!("{base}-{}", *n - 1)
        }
    }
}

/// Rewrite one link destination.
///
/// Called with a destination exactly as written in the markdown (`../quorum.md`,
/// `#the-ladder`, `https://…`, `fixtures/policy-v1/`) and the site-relative path of
/// the page it appears on, and returns the destination the built page should use.
/// The implementation lives in [`crate::links`]; `render` only sees this trait,
/// which is what keeps the renderer free of the site's layout.
pub trait LinkRewriter {
    /// The href to write for `dest`, found on the page at `page`.
    ///
    /// `&mut self` so an implementation can keep a ledger of what it was asked for
    /// — that is how `check` knows which links to review.
    fn rewrite(&mut self, page: &str, dest: &str) -> String;
}

/// A [`LinkRewriter`] that changes nothing: tests, and any fragment that is not
/// part of a site.
pub struct NoRewriting;

impl LinkRewriter for NoRewriting {
    fn rewrite(&mut self, _page: &str, dest: &str) -> String {
        dest.to_string()
    }
}

/// Render one page's markdown.
///
/// `page` is the repo-relative path of the file being rendered (`docs/quorum.md`),
/// which is what relative links resolve against and what a finding is reported
/// against.
pub fn render(markdown: &str, page: &str, links: &mut dyn LinkRewriter) -> Rendered {
    let mut w = Writer::new(page);
    let mut slugs = Slugger::default();

    for event in Parser::new_ext(markdown, options()) {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => w.start_paragraph(),
                Tag::Heading { .. } => w.start_heading(),
                Tag::BlockQuote(kind) => w.block_quote(kind),
                Tag::CodeBlock(kind) => w.start_code_block(kind),
                Tag::HtmlBlock => {}
                Tag::List(start) => w.start_list(start),
                Tag::Item => w.emit("<li>"),
                Tag::FootnoteDefinition(label) => {
                    let id = slug_of(&label);
                    w.emit(format!("<div class=\"footnote\" id=\"fn-{id}\">"));
                    w.emit(format!("<span class=\"footnote-label\">[{label}]</span>"));
                }
                Tag::Table(alignments) => w.start_table(&alignments),
                Tag::TableHead => w.start_table_head(),
                Tag::TableRow => w.emit("<tr>"),
                Tag::TableCell => w.start_table_cell(),
                Tag::Emphasis => w.emit("<em>"),
                Tag::Strong => w.emit("<strong>"),
                Tag::Strikethrough => w.emit("<del>"),
                Tag::Superscript => w.emit("<sup>"),
                Tag::Subscript => w.emit("<sub>"),
                Tag::Link {
                    dest_url, title, ..
                } => w.link(links, &dest_url, &title),
                Tag::Image {
                    dest_url, title, ..
                } => w.image(links, &dest_url, &title),
                Tag::DefinitionList => w.emit("<dl>"),
                Tag::DefinitionListTitle => w.emit("<dt>"),
                Tag::DefinitionListDefinition => w.emit("<dd>"),
                Tag::MetadataBlock(_) => {}
            },
            Event::End(end) => match end {
                TagEnd::Paragraph => w.end_paragraph(),
                TagEnd::Heading(level) => w.end_heading(level, &mut slugs),
                TagEnd::BlockQuote(_) => w.end_block_quote(),
                TagEnd::CodeBlock => w.end_code_block(),
                TagEnd::HtmlBlock => {}
                TagEnd::List(ordered) => w.emit(if ordered { "</ol>\n" } else { "</ul>\n" }),
                TagEnd::Item => w.emit("</li>\n"),
                TagEnd::FootnoteDefinition => w.emit("</div>"),
                TagEnd::Table => w.end_table(),
                TagEnd::TableHead => w.end_table_head(),
                TagEnd::TableRow => w.emit("</tr>\n"),
                TagEnd::TableCell => w.end_table_cell(),
                TagEnd::Emphasis => w.emit("</em>"),
                TagEnd::Strong => w.emit("</strong>"),
                TagEnd::Strikethrough => w.emit("</del>"),
                TagEnd::Superscript => w.emit("</sup>"),
                TagEnd::Subscript => w.emit("</sub>"),
                TagEnd::Link => w.emit("</a>"),
                TagEnd::Image => w.emit("</span>"),
                TagEnd::DefinitionList => w.emit("</dl>"),
                TagEnd::DefinitionListTitle => w.emit("</dt>"),
                TagEnd::DefinitionListDefinition => w.emit("</dd>"),
                TagEnd::MetadataBlock(_) => {}
            },
            Event::Text(text) => w.text(&text),
            Event::Code(code) => w.code(&code),
            Event::Html(raw) | Event::InlineHtml(raw) => w.raw_html(&raw),
            Event::SoftBreak => {
                // The newline is a space in the HTML *and* in the plain text: the
                // docs wrap their paragraphs at 80 columns, and a text index or an
                // index listing that joins `run,\nby` into `run,by` is worse than no
                // index at all.
                w.emit(" ");
                w.prose(" ");
            }
            Event::HardBreak => w.emit("<br>\n"),
            Event::Rule => w.emit("<hr>\n"),
            Event::TaskListMarker(checked) => w.emit(format!(
                "<input type=\"checkbox\" disabled{}>",
                if checked { " checked" } else { "" }
            )),
            Event::FootnoteReference(label) => {
                let id = slug_of(&label);
                w.emit(format!(
                    "<sup class=\"footnote-ref\"><a href=\"#fn-{id}\" id=\"fnref-{id}\">[{label}]</a></sup>"
                ));
            }
            Event::InlineMath(text) | Event::DisplayMath(text) => {
                // Math is not enabled, so these docs cannot reach this arm. Printing
                // it escaped rather than panicking keeps a future option flip a
                // bad-looking page instead of a failed deploy.
                w.text(&text);
            }
        }
    }

    w.finish()
}

/// Where the next characters go.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Sink {
    #[default]
    Body,
    /// The heading being read — buffered, because its text decides its own id.
    Heading,
}

/// The event loop's output state.
struct Writer {
    page: String,
    html: String,
    /// The body of the heading being read.
    heading_html: String,
    /// The plain text of the heading being read.
    heading_text: String,
    text: String,
    description: String,
    /// The paragraph being read as a summary-line candidate. It is only promoted at
    /// the paragraph's end, once we know what shape it was.
    pending_description: String,
    headings: Vec<Heading>,
    sink: Sink,
    /// Inside the paragraph being considered as the summary line.
    in_description: bool,
    /// Where in `html` the candidate paragraph's body began, so its shape can be
    /// checked at the end: a paragraph that opens with `<em>` is the executed-docs
    /// note almost every page here starts with — a footnote about the page, not a
    /// summary of it.
    description_html_at: usize,
    /// Inside a table's header row, which decides `<th>` versus `<td>`.
    in_head: bool,
    /// Block quote nesting depth, so a page's preamble note is not its description.
    quote_depth: usize,
    /// Inside a fenced or indented code block, whose text is not prose.
    in_code: bool,
    raw_html: usize,
}

impl Writer {
    fn new(page: &str) -> Self {
        Writer {
            page: page.to_string(),
            ..Writer::empty()
        }
    }

    fn empty() -> Self {
        Writer {
            page: String::new(),
            html: String::new(),
            heading_html: String::new(),
            heading_text: String::new(),
            text: String::new(),
            description: String::new(),
            pending_description: String::new(),
            headings: Vec::new(),
            sink: Sink::default(),
            in_description: false,
            description_html_at: 0,
            in_head: false,
            quote_depth: 0,
            in_code: false,
            raw_html: 0,
        }
    }

    fn emit(&mut self, s: impl AsRef<str>) {
        match self.sink {
            Sink::Body => self.html.push_str(s.as_ref()),
            Sink::Heading => self.heading_html.push_str(s.as_ref()),
        }
    }

    /// Characters that are part of the prose, so they also reach the plain-text
    /// copy — and the description, if we are still in the first paragraph.
    fn prose(&mut self, s: &str) {
        // A command line inside a fence is machine-facing text. Keeping it out of
        // the prose means a search for `--store` finds the page that *explains* the
        // flag rather than every page that shows it once.
        if self.in_code {
            return;
        }
        match self.sink {
            Sink::Body => {
                self.text.push_str(s);
                if self.in_description {
                    self.pending_description.push_str(s);
                }
            }
            Sink::Heading => self.heading_text.push_str(s),
        }
    }

    /// Text, escaped for the current sink.
    fn text(&mut self, s: &str) {
        let escaped = escape_html(s);
        self.emit(escaped);
        self.prose(s);
    }

    fn code(&mut self, s: &str) {
        self.emit("<code>");
        let escaped = escape_html(s);
        self.emit(escaped);
        self.emit("</code>");
        self.prose(s);
    }

    fn raw_html(&mut self, s: &str) {
        self.raw_html += 1;
        // Escaped on purpose; see the module comment. Not added to the prose
        // either: it is markup that was refused, not something a reader should
        // find by searching for the tag name.
        let escaped = escape_html(s);
        self.emit(escaped);
    }

    fn start_paragraph(&mut self) {
        // The summary line is the first ordinary paragraph: not a heading, not a
        // block quote, and — the case every guide in `docs/` hits — not the italic
        // note about how the page is executed. The last of those can only be judged
        // once the paragraph is over, so the candidate is buffered until then.
        if self.sink == Sink::Body && self.description.is_empty() && self.quote_depth == 0 {
            self.in_description = true;
            self.pending_description.clear();
        }
        self.emit("<p>");
        self.description_html_at = self.html.len();
    }

    fn end_paragraph(&mut self) {
        if self.in_description {
            self.in_description = false;
            let body = &self.html[self.description_html_at..];
            let is_a_note = body.starts_with("<em>") || body.starts_with("<strong>");
            let candidate = collapse_spaces(&self.pending_description);
            self.pending_description.clear();
            if !candidate.is_empty() && !is_a_note {
                self.description = candidate;
            }
        }
        self.emit("</p>\n");
        if self.sink == Sink::Body {
            self.text.push('\n');
        }
    }

    fn start_heading(&mut self) {
        self.sink = Sink::Heading;
        self.heading_html.clear();
        self.heading_text.clear();
    }

    fn end_heading(&mut self, level: HeadingLevel, slugs: &mut Slugger) {
        let html = std::mem::take(&mut self.heading_html);
        let text = std::mem::take(&mut self.heading_text);
        let tag = level as u8;
        let slug = slugs.slug(&text);
        self.sink = Sink::Body;
        // The trailing anchor makes a heading linkable by clicking it, which is
        // what a reader expects from every documentation site on earth.
        self.html.push_str(&format!(
            "<h{tag} id=\"{slug}\">{html}<a class=\"anchor\" href=\"#{slug}\" aria-label=\"Link to this section\">#</a></h{tag}>\n"
        ));
        self.headings.push(Heading {
            level: tag,
            text: text.clone(),
            slug,
        });
        self.text.push_str(&text);
        self.text.push('\n');
    }

    fn block_quote(&mut self, kind: Option<BlockQuoteKind>) {
        self.quote_depth += 1;
        match kind {
            Some(kind) => self.emit(format!(
                "<blockquote class=\"alert alert-{}\">",
                quote_kind(kind)
            )),
            None => self.emit("<blockquote>"),
        }
    }

    fn end_block_quote(&mut self) {
        self.quote_depth = self.quote_depth.saturating_sub(1);
        self.emit("</blockquote>\n");
    }

    fn start_code_block(&mut self, kind: CodeBlockKind<'_>) {
        self.in_code = true;
        let lang = match kind {
            CodeBlockKind::Indented => String::new(),
            CodeBlockKind::Fenced(info) => language_of(&info),
        };
        if lang.is_empty() {
            self.emit("<pre class=\"code\"><code>");
        } else {
            self.emit(format!(
                "<pre class=\"code\" data-lang=\"{}\"><code>",
                escape_attr(&lang)
            ));
        }
    }

    fn end_code_block(&mut self) {
        self.emit("</code></pre>\n");
        self.in_code = false;
        self.text.push(' ');
    }

    fn start_list(&mut self, start: Option<u64>) {
        match start {
            None => self.emit("<ul>\n"),
            Some(1) => self.emit("<ol>\n"),
            // `Some(n)` with n != 1 is rare, but a list that starts at 3 in a doc
            // should still say so when built.
            Some(n) => self.emit(format!("<ol start=\"{n}\">\n")),
        }
    }

    fn start_table(&mut self, _alignments: &[Alignment]) {
        // The wrapper is for narrow screens: a nine-column ADR table has to scroll
        // sideways rather than crush every column into nothing.
        self.emit("<div class=\"table-wrap\"><table>\n");
    }

    fn end_table(&mut self) {
        self.emit("</table></div>\n");
    }

    fn start_table_head(&mut self) {
        self.in_head = true;
        self.emit("<thead>\n<tr>\n");
    }

    fn end_table_head(&mut self) {
        self.in_head = false;
        self.emit("</tr>\n</thead>\n");
    }

    fn start_table_cell(&mut self) {
        self.emit(if self.in_head { "<th>" } else { "<td>" });
    }

    fn end_table_cell(&mut self) {
        self.emit(if self.in_head { "</th>\n" } else { "</td>\n" });
    }

    fn link(&mut self, links: &mut dyn LinkRewriter, dest: &str, title: &str) {
        let href = links.rewrite(&self.page, dest);
        let mut out = format!("<a href=\"{}\"", escape_attr(&href));
        if !title.is_empty() {
            out.push_str(&format!(" title=\"{}\"", escape_attr(title)));
        }
        if is_external(&href) {
            out.push_str(" class=\"external\"");
        }
        out.push('>');
        self.emit(out);
        // The href is deliberately not added to the prose: a link's destination is
        // not the sentence a reader is searching for.
    }

    fn image(&mut self, links: &mut dyn LinkRewriter, dest: &str, title: &str) {
        let href = links.rewrite(&self.page, dest);
        self.emit("<span class=\"figure\">");
        self.emit(format!(
            "<img src=\"{}\" alt=\"{}\">",
            escape_attr(&href),
            escape_attr(title)
        ));
        if !title.is_empty() {
            self.emit(format!(
                "<span class=\"caption\">{}</span>",
                escape_html(title)
            ));
        }
    }

    fn finish(self) -> Rendered {
        Rendered {
            html: self.html.trim_end().to_string(),
            headings: self.headings,
            text: collapse_spaces(&self.text),
            description: collapse_spaces(&self.description),
            raw_html: self.raw_html,
        }
    }
}

/// HTML-escape text for an element body.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Escape for an attribute value. The same table as `escape_html` today, named
/// separately so a future divergence (URL-escaping a path, say) lands in one place.
fn escape_attr(s: &str) -> String {
    escape_html(s)
}

fn collapse_spaces(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A fence's info string is not a safe attribute value — `rust,ignore`, `sh+jinja`
/// and `` sh `note` `` all appear somewhere in the wild — so keep the leading word
/// and drop anything that is not a language-name character.
fn language_of(info: &str) -> String {
    let word = info
        .split([' ', ',', ':', '`'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    word.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '-' || *c == '_')
        .collect()
}

fn quote_kind(kind: BlockQuoteKind) -> &'static str {
    match kind {
        BlockQuoteKind::Note => "note",
        BlockQuoteKind::Tip => "tip",
        BlockQuoteKind::Important => "important",
        BlockQuoteKind::Warning => "warning",
        BlockQuoteKind::Caution => "caution",
    }
}

/// Does this href leave the site?
fn is_external(href: &str) -> bool {
    href.contains("://") || href.starts_with("mailto:")
}

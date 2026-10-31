//! The HTML shell every page is wrapped in: header with the search box, the
//! sidebar, the article, the "on this page" list, and the pager.
//!
//! One page template, driven by [`View`], and nothing else — no templating
//! dependency, no partials, no layout inheritance. A docs site has exactly one
//! layout, and a templating language for one layout is a second language to learn
//! before editing the docs' chrome.
//!
//! Two properties the template is written to keep:
//!
//! * **Relative hrefs everywhere except `404.html`.** A page in `docs/adr/` links
//!   the stylesheet as `../../assets/site.css`, which means the same build can be
//!   opened from a filesystem, served out of a bucket subdirectory, and published
//!   under a project path on Pages, with no rebuild and no base-URL flag to get
//!   wrong. `404.html` is the exception because the server may serve it for a URL
//!   of any depth; it is the only consumer of `--base-path`.
//! * **No JavaScript to read the docs.** The stylesheet and the anchor links do the
//!   work; `search.js` is loaded by `search.html` alone, and that page says out loud
//!   in a `<noscript>` that it needs it.

use std::fmt::Write as _;

use crate::config::Config;
use crate::md::Heading;
use crate::nav::{Entry, Nav};
use crate::paths;

/// What a page needs to be rendered, and nothing it does not.
#[derive(Debug)]
pub struct View<'a> {
    /// The build's configuration.
    pub cfg: &'a Config,
    /// The sidebar.
    pub nav: &'a Nav,
    /// This page's site-relative output path, which decides every relative href.
    pub out: &'a str,
    /// The `<h1>`-equivalent title, shown in `<title>` and the header.
    pub title: &'a str,
    /// The rendered body.
    pub body: &'a str,
    /// The page's headings, for the "on this page" list.
    pub headings: &'a [Heading],
    /// The markdown it was built from, for "edit this page". `None` for a generated
    /// page, which has no file to edit.
    pub src: Option<&'a str>,
    /// The previous page in the reading order.
    pub prev: Option<Entry>,
    /// The next page in the reading order.
    pub next: Option<Entry>,
    /// Whether to load `search.js` — only `search.html` does.
    pub search_script: bool,
}

impl View<'_> {
    fn up(&self) -> String {
        paths::up(paths::depth_of(self.out))
    }

    fn href_to(&self, out: &str) -> String {
        paths::relative(paths::dir_of(self.out), out)
    }
}

/// Render a whole document.
pub fn page(view: &View<'_>) -> String {
    let up = view.up();
    let mut out = String::with_capacity(view.body.len() + 8 * 1024);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    // The front page's title *is* the site's name; "gitiup · gitiup" in a browser
    // tab is the same word twice.
    let title = if view.title == view.cfg.title {
        crate::md::escape_html(view.title)
    } else {
        format!(
            "{} · {}",
            crate::md::escape_html(view.title),
            crate::md::escape_html(&view.cfg.title)
        )
    };
    let _ = writeln!(out, "<title>{title}</title>");
    let _ = writeln!(
        out,
        "<meta name=\"generator\" content=\"gitiup-site {}\">",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(site) = view.cfg.site_url() {
        let _ = writeln!(
            out,
            "<link rel=\"canonical\" href=\"{site}/{page}\">",
            site = site,
            page = view.out
        );
    }
    let _ = writeln!(
        out,
        "<link rel=\"stylesheet\" href=\"{up}assets/site.css\">\n<link rel=\"icon\" href=\"{up}assets/favicon.svg\" type=\"image/svg+xml\">"
    );
    if view.search_script {
        let _ = writeln!(out, "<script src=\"{up}assets/search.js\" defer></script>");
    }
    out.push_str("</head>\n<body>\n");

    header(&mut out, view, &up);
    out.push_str("<div class=\"layout\">\n");
    sidebar(&mut out, view);
    main(&mut out, view);
    toc(&mut out, view);
    out.push_str("</div>\n");
    footer(&mut out, view, &up);
    out.push_str("</body>\n</html>\n");
    out
}

fn header(out: &mut String, view: &View<'_>, up: &str) {
    out.push_str("<header class=\"topbar\">\n");
    let _ = writeln!(
        out,
        "<a class=\"brand\" href=\"{up}index.html\">{}</a>",
        crate::md::escape_html(&view.cfg.title)
    );
    let _ = writeln!(
        out,
        "<span class=\"tagline\">{}</span>",
        crate::md::escape_html(&view.cfg.tagline)
    );
    // `action` is relative to the page, which is the only way a search form works
    // at three different directory depths without a line of JavaScript.
    let _ = writeln!(
        out,
        "<form class=\"search\" action=\"{up}search.html\" method=\"get\" role=\"search\">\n\
         <input type=\"search\" name=\"q\" placeholder=\"Search the docs\" aria-label=\"Search the docs\">\n\
         <button type=\"submit\">Search</button>\n\
         </form>\n",
    );
    out.push_str("</header>\n");
}

fn sidebar(out: &mut String, view: &View<'_>) {
    out.push_str("<nav class=\"sidebar\" aria-label=\"Documentation\">\n");
    for section in &view.nav.sections {
        if section.entries.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "<h2 class=\"nav-title\">{}</h2>\n<ul class=\"nav-list\">",
            crate::md::escape_html(&section.title)
        );
        for item in &section.entries {
            let current = item.out == view.out;
            let _ = writeln!(
                out,
                "<li><a href=\"{href}\"{cls}>{title}</a></li>",
                href = view.href_to(&item.out),
                cls = if current {
                    " class=\"current\" aria-current=\"page\""
                } else {
                    ""
                },
                title = crate::md::escape_html(&item.title)
            );
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</nav>\n");
}

fn main(out: &mut String, view: &View<'_>) {
    out.push_str("<main>\n<article class=\"page\">\n");
    out.push_str(view.body);
    out.push_str("\n</article>\n");
    pager(out, view);
    out.push_str("</main>\n");
}

fn pager(out: &mut String, view: &View<'_>) {
    out.push_str(
        "<nav class=\"pager\" aria-label=\"Page navigation\">\n<div class=\"pager-links\">\n",
    );
    match &view.prev {
        Some(prev) => {
            let _ = writeln!(
                out,
                "<a class=\"pager-prev\" href=\"{href}\">&larr; {title}</a>",
                href = view.href_to(&prev.out),
                title = crate::md::escape_html(&prev.title)
            );
        }
        None => out.push_str("<span class=\"pager-prev empty\"></span>\n"),
    }
    match &view.next {
        Some(next) => {
            let _ = writeln!(
                out,
                "<a class=\"pager-next\" href=\"{href}\">{title} &rarr;</a>",
                href = view.href_to(&next.out),
                title = crate::md::escape_html(&next.title)
            );
        }
        None => out.push_str("<span class=\"pager-next empty\"></span>\n"),
    }
    out.push_str("</div>\n");
    if let Some(src) = view.src {
        let _ = writeln!(
            out,
            "<p class=\"source-link\"><a href=\"{url}\">Edit this page</a> — built from <code>{src}</code></p>",
            url = view.cfg.blob_url(src)
        );
    }
    out.push_str("</nav>\n");
}

/// The "on this page" column: level 2 and 3 headings, which is the depth a reader
/// actually jumps to. Going deeper puts a 90-line list in the margin, which is not
/// a table of contents but a wall of text with links.
fn toc(out: &mut String, view: &View<'_>) {
    let items: Vec<&Heading> = view
        .headings
        .iter()
        .filter(|h| matches!(h.level, 2 | 3))
        .collect();
    if items.len() < 2 {
        // A page with one section does not need a table of contents pointing at it.
        out.push_str("<aside class=\"toc\"></aside>\n");
        return;
    }
    out.push_str("<aside class=\"toc\" aria-label=\"On this page\">\n<h2 class=\"toc-title\">On this page</h2>\n<ul class=\"toc-list\">\n");
    for heading in items {
        let _ = writeln!(
            out,
            "<li class=\"toc-{level}\"><a href=\"#{slug}\">{text}</a></li>",
            level = heading.level,
            slug = crate::md::escape_html(&heading.slug),
            text = crate::md::escape_html(&heading.text)
        );
    }
    out.push_str("</ul>\n</aside>\n");
}

fn footer(out: &mut String, view: &View<'_>, up: &str) {
    let _ = writeln!(
        out,
        "<footer class=\"site-footer\">\n<p>Built from <a href=\"{repo}\">the repository</a> by <code>gitiup-site</code>: static files, no server, no JavaScript required to read a page.</p>\n<p><a href=\"{up}index.html\">{site}</a> · <a href=\"{up}search.html\">Search</a></p>\n</footer>",
        repo = view.cfg.source_url,
        up = up,
        site = crate::md::escape_html(&view.cfg.title)
    );
}

/// The `404.html` document.
///
/// The one page that cannot use relative links: the server answers it for a URL of
/// any depth, so `../` would land somewhere different for every miss. It is
/// therefore the only consumer of `base_path`, and it says so on itself.
pub fn not_found(cfg: &Config, nav: &Nav) -> String {
    let base = cfg.base_path();
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<meta name=\"robots\" content=\"noindex\">\n");
    let _ = writeln!(
        out,
        "<title>Not found · {}</title>",
        crate::md::escape_html(&cfg.title)
    );
    let _ = writeln!(
        out,
        "<link rel=\"stylesheet\" href=\"{base}assets/site.css\">\n<link rel=\"icon\" href=\"{base}assets/favicon.svg\" type=\"image/svg+xml\">"
    );
    out.push_str("</head>\n<body>\n<header class=\"topbar\">\n");
    let _ = writeln!(
        out,
        "<a class=\"brand\" href=\"{base}index.html\">{}</a>\n<span class=\"tagline\">{}</span>\n</header>\n<div class=\"layout\">\n<nav class=\"sidebar\"></nav>\n<main>",
        crate::md::escape_html(&cfg.title),
        crate::md::escape_html(&cfg.tagline)
    );
    out.push_str(
        "<article class=\"page\">\n<h1>Nothing at this address</h1>\n<p>The site is built from the repository's markdown, so a page here is a file there: if you followed a link to get here, it is a broken link and worth reporting.</p>\n<ul>\n",
    );
    for section in &nav.sections {
        for item in section.entries.iter().take(3) {
            let _ = writeln!(
                out,
                "<li><a href=\"{base}{href}\">{title}</a></li>",
                base = base,
                href = item.out,
                title = crate::md::escape_html(&item.title)
            );
        }
    }
    let _ = writeln!(
        out,
        "</ul>\n<p>Start at the <a href=\"{base}index.html\">front page</a> or <a href=\"{base}docs/index.html\">the index of every page</a>.</p>\n</article>\n</main>\n<aside class=\"toc\"></aside>\n</div>\n</body>\n</html>"
    );
    out
}

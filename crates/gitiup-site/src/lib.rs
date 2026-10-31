//! `gitiup-site` — the repository's markdown, built into a static site.
//!
//! The docs in `docs/` and `docs/adr/` are the project's contract: they are
//! executed by the test suite ([`docs/policy.md`](../../../docs/policy.md) is run
//! line by line by `crates/gitiup/tests/policy_doc_cli.rs`, the quickstart by
//! `quickstart_doc_cli.rs`), they cross-reference each other by anchor, and they are
//! read in a browser far more often than in an editor. This crate turns them into a
//! site for that reader — and nothing else. It runs no server, watches nothing, and
//! touches no network: `build` reads a checkout and writes a directory of files, so
//! the same command works in CI, on a laptop, and on a machine with no network at
//! all, which is the same reason the tool this repository builds refuses to depend on
//! a forge being up.
//!
//! The pipeline is four steps, and each is a module:
//!
//! 1. [`tree`] finds the markdown (every `*.md` under `docs/`, plus `README.md`);
//! 2. [`md`] renders it, gives every heading a GitHub-shaped `id`, and asks
//!    [`links`] where each href should go — page, repository, or elsewhere;
//! 3. [`nav`] puts the pages in the order a reader should meet them, and
//!    [`template`] wraps each one in the shell: header, sidebar, article, "on this
//!    page", pager;
//! 4. [`search`] writes the section index that `search.html` reads.
//!
//! Two properties the whole crate is written to hold, because the rest of this
//! repository would not ship without them:
//!
//! * **The build is reproducible.** Sorted discovery, fixed key order, no clock, no
//!   absolute paths in the output. Build the same checkout twice and `diff -r` is
//!   empty — see `tests/build_site.rs`, which does exactly that.
//! * **`check` is the part you run in CI.** `build` will happily write a site with a
//!   dead anchor in it; `check` renders everything into memory and refuses if any
//!   internal link goes nowhere, any heading is missing, or any new page has fallen
//!   out of the reading order. That is how `docs/`'s anchors stay honest as the docs
//!   grow — the drift it caught on its first run (`federation.md` linking a heading
//!   that lives in ADR-0005) was already in the tree.
//!
//! ```
//! let cfg = gitiup_site::Config::new(std::path::Path::new("."));
//! // A config is just data: nothing here touches the network, and nothing here
//! // writes to disk until `build` is called.
//! assert!(cfg.out.to_string_lossy().ends_with("_site"));
//! ```

mod assets;
pub mod cli;
pub mod config;
pub mod error;
pub mod links;
pub mod md;
pub mod nav;
pub mod paths;
pub mod search;
pub mod template;
pub mod tree;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub use config::Config;
pub use error::Error;

use links::SiteLinks;
use md::{Heading, Rendered};
use nav::Nav;
use tree::Source;

/// The generated index of every page.
pub const DOCS_INDEX: &str = "docs/index.html";
/// The search page.
pub const SEARCH_PAGE: &str = "search.html";
/// The missing-page page, and the only file that needs `--base-path`.
pub const NOT_FOUND_PAGE: &str = "404.html";
/// The index `search.html` loads. A `.js` and not a `.json` on purpose: a page
/// opened from a filesystem is not allowed to `fetch` its neighbour, and the site is
/// meant to be readable that way. See `assets/search.js`.
pub const SEARCH_INDEX: &str = "search-index.js";

/// One page, built and ready to write.
#[derive(Debug, Clone)]
pub struct Built {
    /// The markdown it came from, repo-relative: `docs/quorum.md`.
    pub src: String,
    /// Its output path, site-relative: `docs/quorum.html`.
    pub out: String,
    /// The page title: its `<h1>`, or the file name if it has none.
    pub title: String,
    /// Its first paragraph, used in the index listing.
    pub description: String,
    /// The rendered body.
    pub body: String,
    /// Every heading, with the `id` it was given.
    pub headings: Vec<Heading>,
    /// How many raw-HTML spans were escaped rather than passed through.
    pub raw_html: usize,
}

/// What a build produced.
#[derive(Debug, Clone)]
pub struct Summary {
    /// Where it was written.
    pub out: PathBuf,
    /// How many HTML pages were written, counting the generated ones.
    pub pages: usize,
    /// How many files were written in total.
    pub files: usize,
    /// Their total size.
    pub bytes: u64,
    /// What `check` would complain about — printed as warnings by the command line,
    /// because a build that publishes a dead anchor is a build that should have been
    /// a `check`.
    pub problems: Vec<Problem>,
}

/// Something `check` refuses, or `build` warns about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    /// The page to blame, or the crate file, when the problem is not a page's.
    pub page: String,
    /// What is wrong, as one line.
    pub message: String,
}

impl Problem {
    fn new(page: impl Into<String>, message: impl Into<String>) -> Self {
        Problem {
            page: page.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.page, self.message)
    }
}

/// The whole render, before anything is written.
pub struct Site<'a> {
    /// Every source that became a page, in discovery order.
    pub sources: Vec<Source>,
    /// The built pages, in discovery order.
    pub pages: Vec<Built>,
    /// The sidebar, in reading order.
    pub nav: Nav,
    /// Every link the renderer was asked about.
    pub links: Vec<links::Record>,
    /// How many heading anchors each built page has, keyed by output path — the
    /// thing a link's anchor is checked against.
    anchors: BTreeMap<String, BTreeSet<String>>,
    /// The rewriter, kept so `review` can run over its ledger against `anchors`.
    rewriter: SiteLinks<'a>,
}

impl Site<'_> {
    /// The pages in reading order — the order the index, the sitemap and the search
    /// index use, so that a tie in search favours the page a reader would have found
    /// first.
    pub fn in_reading_order(&self) -> Vec<&Built> {
        let mut out = Vec::with_capacity(self.pages.len());
        for entry in self.nav.flat() {
            if let Some(page) = self.pages.iter().find(|p| p.out == entry.out) {
                out.push(page);
            }
        }
        // Anything the sidebar did not list still gets indexed rather than becoming
        // invisible to search.
        for page in &self.pages {
            if !out.iter().any(|p| p.out == page.out) {
                out.push(page);
            }
        }
        out
    }

    /// Every internal link that goes nowhere, every page that has no `<h1>`, every
    /// page that tried to embed raw HTML.
    ///
    /// This is what `gitiup-site check` runs, and it is the reason the tool is worth
    /// a CI step: `build` will write a site whose links are broken, and a reader
    /// follows a broken link once and then stops trusting the site.
    ///
    /// Note what is *not* here: a complaint about a guide that is not in
    /// [`nav::GUIDES`]. That list is this repository's reading order, so a fork or a
    /// second project using this builder would be told to edit a source file it has
    /// no interest in. That rule is a property of this crate's own source, and it is
    /// tested as one — `tests/navigation.rs`,
    /// `the_guide_list_is_exactly_the_pages_in_docs`.
    pub fn problems(&self) -> Vec<Problem> {
        let mut problems: Vec<Problem> = Vec::new();

        for finding in self.rewriter.review(&self.anchors) {
            let message = finding.report();
            problems.push(Problem::new(finding.page, message));
        }
        for page in &self.pages {
            if page.title_is_fallback() {
                problems.push(Problem::new(
                    &page.src,
                    "no `#` heading, so the sidebar shows the file name",
                ));
            }
            if page.raw_html > 0 {
                problems.push(Problem::new(
                    &page.src,
                    format!(
                        "{} raw HTML span{} escaped — this site does not pass markup through",
                        page.raw_html,
                        if page.raw_html == 1 { "" } else { "s" }
                    ),
                ));
            }
        }
        problems.sort();
        problems.dedup();
        problems
    }
}

impl Built {
    /// True when the title came from the file name because the page has no `<h1>`.
    pub fn title_is_fallback(&self) -> bool {
        !self.headings.iter().any(|h| h.level == 1)
    }
}

/// Render every page. Nothing is written by this function.
pub fn render(cfg: &Config) -> Result<Site<'_>, Error> {
    cfg.validate()?;
    let sources = tree::discover(&cfg.root)?;
    let mut rewriter = SiteLinks::new(cfg, &sources);

    let mut pages: Vec<Built> = Vec::new();
    let mut anchors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for source in &sources {
        let text = std::fs::read_to_string(source.abs(&cfg.root))
            .map_err(|e| Error::io(source.abs(&cfg.root), e))?;
        let rendered: Rendered = md::render(&text, &source.rel, &mut rewriter);
        let title = rendered
            .title()
            .map(str::to_string)
            .unwrap_or_else(|| paths::stem(&source.rel));
        for heading in &rendered.headings {
            anchors
                .entry(source.out.clone())
                .or_default()
                .insert(heading.slug.clone());
        }
        pages.push(Built {
            src: source.rel.clone(),
            out: source.out.clone(),
            title,
            description: rendered.description.clone(),
            body: rendered.html.clone(),
            headings: rendered.headings.clone(),
            raw_html: rendered.raw_html,
        });
    }

    let meta: BTreeMap<String, nav::Meta> = pages
        .iter()
        .map(|p| {
            (
                p.src.clone(),
                nav::Meta {
                    title: p.title.clone(),
                    description: (!p.description.is_empty()).then(|| p.description.clone()),
                },
            )
        })
        .collect();

    let nav = Nav::build(&sources, &meta);
    let links = rewriter.records().to_vec();

    Ok(Site {
        sources,
        pages,
        nav,
        links,
        anchors,
        rewriter,
    })
}

/// Build the site into [`Config::out`] and report what was written.
///
/// The output directory is removed first: a page deleted from `docs/` must not
/// survive in the published site from an earlier build, and "delete the directory
/// and write it again" is the only way to be sure.
pub fn build(cfg: &Config) -> Result<Summary, Error> {
    let site = render(cfg)?;
    let out = &cfg.out;

    if out.exists() {
        std::fs::remove_dir_all(out).map_err(|e| Error::io(out, e))?;
    }
    std::fs::create_dir_all(out).map_err(|e| Error::io(out, e))?;

    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut pages = 0usize;

    let mut write = |path: PathBuf, contents: &str| -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        std::fs::write(&path, contents).map_err(|e| Error::io(&path, e))?;
        files += 1;
        bytes += contents.len() as u64;
        Ok(())
    };

    // One page per markdown file, in the sidebar's reading order so that prev/next
    // is the reading order and not the filesystem's.
    let planned: Vec<&Built> = site.in_reading_order();

    for (index, page) in planned.iter().enumerate() {
        let view = template::View {
            cfg,
            nav: &site.nav,
            out: &page.out,
            title: &page.title,
            body: &page.body,
            headings: &page.headings,
            src: Some(&page.src),
            prev: index
                .checked_sub(1)
                .and_then(|i| planned.get(i))
                .map(|p| nav_entry_of(&site.nav, p)),
            next: planned.get(index + 1).map(|p| nav_entry_of(&site.nav, p)),
            search_script: false,
        };
        let html = template::page(&view);
        write(out.join(&page.out), &html)?;
        pages += 1;
    }

    // The generated pages: the index of everything, search, and the missing-page
    // answer.
    let index_body = search::docs_index(&site.nav);
    let index_headings: Vec<Heading> = site
        .nav
        .sections
        .iter()
        .filter(|s| !s.entries.is_empty())
        .map(|s| Heading {
            level: 2,
            text: s.title.clone(),
            slug: md::slug_of(&s.title),
        })
        .collect();
    let index_view = template::View {
        cfg,
        nav: &site.nav,
        out: DOCS_INDEX,
        title: "Every page",
        body: &index_body,
        headings: &index_headings,
        src: None,
        prev: None,
        next: None,
        search_script: false,
    };
    write(out.join(DOCS_INDEX), &template::page(&index_view))?;
    pages += 1;

    let search_body = search::search_body();
    let search_view = template::View {
        cfg,
        nav: &site.nav,
        out: SEARCH_PAGE,
        title: "Search",
        body: &search_body,
        headings: &[],
        src: None,
        prev: None,
        next: None,
        search_script: true,
    };
    write(out.join(SEARCH_PAGE), &template::page(&search_view))?;
    pages += 1;

    write(
        out.join(NOT_FOUND_PAGE),
        &template::not_found(cfg, &site.nav),
    )?;
    pages += 1;

    // The support files. The index is ordered by reading order, so a search that
    // ties prefers the page the docs would have led the reader to first.
    let ordered = site.in_reading_order();
    let index_js = format!(
        "// Written by `gitiup-site build`. Section index of the site's pages;\n// read by `assets/search.js`.\nwindow.GITIUP_SEARCH_INDEX = {};\n",
        search::index(&ordered).trim_end()
    );
    write(out.join(SEARCH_INDEX), &index_js)?;

    for (path, contents) in assets::files() {
        write(out.join(path), contents)?;
    }

    let sitemap = search::sitemap(cfg, &ordered);
    if !sitemap.is_empty() {
        write(out.join("sitemap.xml"), &sitemap)?;
    }
    let robots = search::robots(cfg);
    if !robots.is_empty() {
        write(out.join("robots.txt"), &robots)?;
    }

    // GitHub Pages would otherwise run Jekyll over the output, which silently
    // drops anything whose name begins with an underscore and re-renders the HTML.
    write(out.join(".nojekyll"), "")?;

    Ok(Summary {
        out: out.clone(),
        pages,
        files,
        bytes,
        problems: site.problems(),
    })
}

/// The sidebar entry a page was built from, or a stand-in for a page the sidebar
/// does not list (which `problems` reports).
fn nav_entry_of(nav: &Nav, page: &Built) -> nav::Entry {
    for section in &nav.sections {
        for entry in &section.entries {
            if entry.out == page.out {
                return entry.clone();
            }
        }
    }
    nav::Entry {
        title: page.title.clone(),
        out: page.out.clone(),
        src: Some(page.src.clone()),
        description: None,
    }
}

/// The `check` entry point: render, report, write nothing.
///
/// Returns the problems found rather than failing on the first one — the whole list
/// in one run is what makes it possible to fix a docs tree in one pass.
pub fn check(cfg: &Config) -> Result<Vec<Problem>, Error> {
    Ok(render(cfg)?.problems())
}

/// The site-relative path of `to` as seen from the directory of `from`, both
/// site-relative. Re-exported for tests and for anything assembling hrefs.
pub fn href(from: &str, to: &str) -> String {
    paths::relative(paths::dir_of(from), to)
}

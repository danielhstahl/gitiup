//! Link rewriting, and the list of links that go nowhere.
//!
//! A markdown file in `docs/` links three kinds of thing, and each needs a
//! different answer once the docs become a site:
//!
//! * **another page** (`../quorum.md`, `fixtures/policy-v1/`) — becomes the
//!   relative href between the two built pages, `../quorum.html`;
//! * **something that is not a page** (`../../crates/gitiup-host/src/attest.rs`, a
//!   fixture's `cases.json`, a crate's `README.md`) — becomes a link into the
//!   repository at [`Config::source_url`], because a docs site that pretends the
//!   code is not there is a site where every "see the implementation" is a dead
//!   link;
//! * **somewhere else entirely** (`https://…`, `mailto:`) — left exactly as written.
//!
//! The second half of the job is the reason this is a type and not a closure: every
//! decision is *recorded*, so `check` can say "this page links an anchor that no
//! heading has" — the failure mode the docs' own anchor links have already drifted
//! into once. A builder that silently emits a dead anchor is a builder that ships
//! documentation nobody can follow.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::Config;
use crate::md::LinkRewriter;
use crate::paths;
use crate::tree::Source;

/// What the rewriter decided about one link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// Another page of this site, `target` being its site-relative output path.
    InSite {
        /// The built page it points at, e.g. `docs/quorum.html`.
        target: String,
        /// The anchor, without its `#`; empty if there was none.
        anchor: String,
    },
    /// An anchor on the page the link is written on.
    Anchor {
        /// The anchor, without its `#`.
        anchor: String,
    },
    /// Left alone: it already names somewhere else.
    External,
    /// A file in the checkout that is not a page — linked into the repository.
    Source {
        /// The URL it was rewritten to.
        url: String,
    },
    /// Nothing matched. The href is left as written and the finding is reported.
    Unresolved {
        /// The path the destination resolved to, for the report.
        resolved: String,
    },
}

/// One link as it was rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The page the link was written on (repo-relative source path).
    pub page: String,
    /// The destination as written in the markdown.
    pub dest: String,
    /// What the rewriter made of it.
    pub found: Found,
}

/// Something wrong with a link, as it should be printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The page to name at the start of the message.
    pub page: String,
    /// The destination as written.
    pub dest: String,
    /// What is wrong with it.
    pub why: String,
}

impl Finding {
    /// The destination and what is wrong with it, as the one line a report prints
    /// under the page's name.
    pub fn report(&self) -> String {
        format!("link `{}` — {}", self.dest, self.why)
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.page, self.report())
    }
}

/// The rewriter, plus the ledger of everything it was asked about.
pub struct SiteLinks<'a> {
    cfg: &'a Config,
    /// Every in-site markdown path, mapped to its output path.
    by_source: BTreeMap<String, String>,
    /// Every link in render order. Deterministic because pages render in sorted
    /// order and a page's links are walked in document order.
    records: Vec<Record>,
}

impl<'a> SiteLinks<'a> {
    /// A rewriter for the pages `sources`, under the paths `cfg` describes.
    pub fn new(cfg: &'a Config, sources: &[Source]) -> Self {
        SiteLinks {
            cfg,
            by_source: sources
                .iter()
                .map(|s| (s.rel.clone(), s.out.clone()))
                .collect(),
            records: Vec::new(),
        }
    }

    /// Every link the rewriter was asked about, in render order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Check the ledger against the headings the pages actually have.
    ///
    /// `anchors` maps a built page's output path to the set of heading ids it
    /// rendered. A link to a page that is not in there, or to an anchor that page
    /// does not have, is a finding.
    pub fn review(&self, anchors: &BTreeMap<String, BTreeSet<String>>) -> Vec<Finding> {
        let mut out = Vec::new();
        for record in &self.records {
            match &record.found {
                Found::Unresolved { resolved } => out.push(Finding {
                    page: record.page.clone(),
                    dest: record.dest.clone(),
                    why: format!("nothing at `{resolved}` — no page, and no file in the checkout"),
                }),
                Found::InSite { target, anchor } => {
                    let Some(slugs) = anchors.get(target) else {
                        out.push(Finding {
                            page: record.page.clone(),
                            dest: record.dest.clone(),
                            why: format!("`{target}` was not built"),
                        });
                        continue;
                    };
                    if !anchor.is_empty() && !slugs.contains(anchor) {
                        out.push(Finding {
                            page: record.page.clone(),
                            dest: record.dest.clone(),
                            why: format!("`{target}` has no section `{anchor}`"),
                        });
                    }
                }
                Found::Anchor { anchor } => {
                    let Some(here) = self.by_source.get(&record.page) else {
                        continue;
                    };
                    let Some(slugs) = anchors.get(here) else {
                        continue;
                    };
                    if !anchor.is_empty() && !slugs.contains(anchor) {
                        out.push(Finding {
                            page: record.page.clone(),
                            dest: record.dest.clone(),
                            why: format!("this page has no section `{anchor}`"),
                        });
                    }
                }
                // A repository link's anchor is GitHub's business, not ours.
                Found::Source { .. } | Found::External => {}
            }
        }
        out
    }

    fn decide(&self, page: &str, dest: &str) -> Found {
        let (target, anchor) = paths::split_anchor(dest);
        if !paths::is_internal(dest) {
            return Found::External;
        }
        if target.is_empty() {
            return Found::Anchor {
                anchor: anchor.to_string(),
            };
        }

        let resolved = paths::resolve(paths::dir_of(page), target);

        // A page of this site, named directly…
        if let Some(out) = self.by_source.get(&resolved) {
            return Found::InSite {
                target: out.clone(),
                anchor: anchor.to_string(),
            };
        }
        // …or named as a directory, which means its `README.md`.
        let index = format!("{resolved}/README.md");
        if let Some(out) = self.by_source.get(&index) {
            return Found::InSite {
                target: out.clone(),
                anchor: anchor.to_string(),
            };
        }

        // Not a page: is it a file in the checkout? Then it is a repository link.
        let exists = self.cfg.root.join(&resolved).exists();
        let looks_like_dir = resolved.ends_with('/') || !resolved.contains('.');
        if exists || looks_like_dir {
            return Found::Source {
                url: self.cfg.blob_url(&resolved),
            };
        }

        Found::Unresolved { resolved }
    }
}

impl LinkRewriter for SiteLinks<'_> {
    fn rewrite(&mut self, page: &str, dest: &str) -> String {
        let dest = dest.trim();
        let found = self.decide(page, dest);
        let href = match &found {
            Found::InSite { target, anchor } => {
                let here = self.by_source.get(page).map(String::as_str).unwrap_or(page);
                let mut href = paths::relative(paths::dir_of(here), target);
                if !anchor.is_empty() {
                    href.push('#');
                    href.push_str(anchor);
                }
                href
            }
            Found::Source { url } => {
                let (_, anchor) = paths::split_anchor(dest);
                if anchor.is_empty() {
                    url.clone()
                } else {
                    format!("{url}#{anchor}")
                }
            }
            // Left as written: an unknown scheme or an unknown path is the page's
            // own business, and the finding is where it gets raised.
            Found::External | Found::Anchor { .. } | Found::Unresolved { .. } => dest.to_string(),
        };
        self.records.push(Record {
            page: page.to_string(),
            dest: dest.to_string(),
            found,
        });
        href
    }
}

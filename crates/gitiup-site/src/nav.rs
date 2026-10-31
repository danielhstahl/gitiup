//! The sidebar, and the order the docs read best in.
//!
//! Which files exist is `tree`'s rule; which order they are *shown* in is this
//! list. A newcomer should meet the quickstart before the quorum, and the quorum
//! before the ADR that decides its selection algorithm — that ordering is a
//! judgement about the reader, not a property of a filename, so it is written down
//! rather than inferred from `ls`.
//!
//! The cost of a hand-written list is that it can rot, and a stale docs sidebar
//! rots quietly. So `tests/navigation.rs` compares [`GUIDES`] against the contents
//! of `docs/` in both directions: no guide missing from the list, no name in the
//! list that `docs/` no longer has. Adding a page means editing this file, which is
//! the intended price of the ordering being deliberate.

use std::collections::BTreeMap;

use crate::paths;
use crate::tree::{Kind, Source};

/// The guides, in the order a newcomer should read them.
///
/// Build it up from "what can this machine promise", through "run a job and prove
/// it", to "who do you have to trust for that to mean anything", and only then the
/// federation and quorum machinery, which is the part a reader skips on the way to
/// their first successful run.
pub const GUIDES: &[&str] = &[
    "quickstart",
    "sandbox",
    "environment",
    "run-report",
    "provable-output",
    "reproducibility",
    "provenance-tiers",
    "signing-keys",
    "verification",
    "policy",
    "changes",
    "quorum",
    "host-abstraction",
    "federation",
    "site",
];

/// One sidebar entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What the sidebar and the pager show.
    pub title: String,
    /// The built page's site-relative path.
    pub out: String,
    /// The markdown it came from, for "edit this page". `None` for generated pages.
    pub src: Option<String>,
    /// The page's first paragraph, for the index listing. `None` for generated
    /// pages and for a page that opens with something other than a paragraph.
    pub description: Option<String>,
}

/// One group of entries, under a heading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The heading, e.g. `Guides`.
    pub title: String,
    /// The entries, in reading order.
    pub entries: Vec<Entry>,
}

/// What a page contributes to the sidebar: its title, and the line under it.
#[derive(Debug, Clone)]
pub struct Meta {
    /// The page's `<h1>`, or its file name if it has none.
    pub title: String,
    /// Its first paragraph, if it has one.
    pub description: Option<String>,
}

/// The whole sidebar.
#[derive(Debug, Clone, Default)]
pub struct Nav {
    /// The groups, in order.
    pub sections: Vec<Section>,
}

impl Nav {
    /// Build the sidebar from the pages that were found, using `meta` (keyed by
    /// source path) for the words to show.
    pub fn build(sources: &[Source], meta: &BTreeMap<String, Meta>) -> Nav {
        let by_kind = |kind: Kind| {
            let mut matching: Vec<&Source> = sources.iter().filter(|s| s.kind == kind).collect();
            matching.sort_by(|a, b| a.rel.cmp(&b.rel));
            matching
        };

        let mut sections = Vec::new();
        let mut used: Vec<&str> = Vec::new();

        // The front page and the generated index are not files under `docs/`, so
        // they are written out here rather than discovered.
        let mut project = Vec::new();
        if let Some(readme) = sources.iter().find(|s| s.kind == Kind::Home) {
            project.push(Entry {
                title: "Overview".to_string(),
                out: readme.out.clone(),
                src: Some(readme.rel.clone()),
                description: meta.get(&readme.rel).and_then(|m| m.description.clone()),
            });
        }
        project.push(Entry {
            title: "All pages".to_string(),
            out: crate::DOCS_INDEX.to_string(),
            src: None,
            description: Some("Every page in the site, in reading order.".to_string()),
        });
        sections.push(Section {
            title: "Project".to_string(),
            entries: project,
        });

        let guides = by_kind(Kind::Guide);
        let mut entries = Vec::new();
        for stem in GUIDES {
            if let Some(source) = guides.iter().find(|s| paths::stem(&s.rel) == *stem) {
                entries.push(entry(source, meta));
                used.push(source.rel.as_str());
            }
        }
        // Anything in `docs/` that the list has not been told about: rendered and
        // reachable, and reported by `check` as unsorted.
        for source in &guides {
            if !used.contains(&source.rel.as_str()) {
                entries.push(entry(source, meta));
            }
        }
        sections.push(Section {
            title: "Guides".to_string(),
            entries,
        });

        let mut decisions = Vec::new();
        for source in sources.iter().filter(|s| s.kind == Kind::AdrIndex) {
            decisions.push(entry(source, meta));
        }
        let mut adrs = by_kind(Kind::Adr);
        adrs.sort_by(|a, b| paths::file_name(&a.rel).cmp(paths::file_name(&b.rel)));
        for source in adrs {
            decisions.push(entry(source, meta));
        }
        sections.push(Section {
            title: "Decision records".to_string(),
            entries: decisions,
        });

        let fixtures: Vec<Entry> = by_kind(Kind::Fixture)
            .into_iter()
            .map(|s| entry(s, meta))
            .collect();
        if !fixtures.is_empty() {
            sections.push(Section {
                title: "Fixture vectors".to_string(),
                entries: fixtures,
            });
        }

        let others: Vec<Entry> = by_kind(Kind::Other)
            .into_iter()
            .map(|s| entry(s, meta))
            .collect();
        if !others.is_empty() {
            sections.push(Section {
                title: "Other pages".to_string(),
                entries: others,
            });
        }

        Nav { sections }
    }

    /// Every entry in reading order — the sequence the pager walks.
    pub fn flat(&self) -> Vec<&Entry> {
        self.sections
            .iter()
            .flat_map(|s| s.entries.iter())
            .collect()
    }

    /// Where an output path sits in the reading order, for prev/next.
    pub fn position_of(&self, out: &str) -> Option<usize> {
        self.flat().iter().position(|e| e.out == out)
    }

    /// Is this output path listed in the sidebar at all? Generated pages other than
    /// the index (search, 404) are not, which is why `check` asks.
    pub fn lists(&self, out: &str) -> bool {
        self.sections.iter().any(|s| {
            s.entries
                .iter()
                .any(|e| e.out == out || format!("{}/", e.out) == out)
        })
    }
}

fn entry(source: &Source, meta: &BTreeMap<String, Meta>) -> Entry {
    let known = meta.get(&source.rel);
    Entry {
        title: known
            .map(|m| m.title.clone())
            .unwrap_or_else(|| paths::stem(&source.rel)),
        out: source.out.clone(),
        src: Some(source.rel.clone()),
        description: known.and_then(|m| m.description.clone()),
    }
}

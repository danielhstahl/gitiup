//! Which files become pages, and what each one is called in the built site.
//!
//! The rule is one sentence: **every `*.md` under `docs/`, plus the checkout's
//! `README.md`, is a page** — with `README.md` becoming `index.html` in its own
//! directory so that a directory URL works, and hidden and generated directories
//! (`__pycache__` under the fixture vectors) left out.
//!
//! That rule is deliberately too blunt to curate. The alternative — a manifest of
//! page names — is a file that rots the day somebody adds a guide, and a guide that
//! silently does not get published is worse than one that lands in an "Other pages"
//! section of the sidebar. What is curated instead is the *order* the guides read
//! best in ([`crate::nav`]), and a test in this crate pins that list against
//! `docs/` so it cannot drift.

use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::paths;

/// What a page is, which is how the sidebar knows where to put it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The checkout's `README.md`, rendered as the site's front page.
    Home,
    /// A page directly under `docs/`.
    Guide,
    /// `docs/adr/README.md`, the decision-record index.
    AdrIndex,
    /// `docs/adr/NNNN-slug.md`.
    Adr,
    /// A fixture vector set's `README.md` under `docs/adr/fixtures/`.
    Fixture,
    /// Anything else under `docs/`. Rendered, linked, and a nudge that `nav`'s
    /// curated ordering has not caught up with a new directory.
    Other,
}

/// One markdown file, where it came from and where it lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Repo-relative, `/`-separated: `docs/quorum.md`.
    pub rel: String,
    /// Site-relative output path: `docs/quorum.html`.
    pub out: String,
    /// What kind of page it is.
    pub kind: Kind,
}

impl Source {
    /// The file on disk.
    pub fn abs(&self, root: &Path) -> PathBuf {
        root.join(&self.rel)
    }
}

/// The output path for a repo-relative markdown path.
///
/// `README.md` is `index.html` so a directory URL serves it; everything else keeps
/// its name and swaps the extension.
pub fn out_of(rel: &str) -> String {
    let dir = paths::dir_of(rel);
    let name = paths::file_name(rel);
    let out_name = if name.eq_ignore_ascii_case("README.md") {
        "index.html".to_string()
    } else if let Some(stem) = name.strip_suffix(".md") {
        format!("{stem}.html")
    } else {
        name.to_string()
    };
    if dir.is_empty() {
        out_name
    } else {
        format!("{dir}/{out_name}")
    }
}

/// Every page the site is built from, sorted by source path.
///
/// Sorted, and only from a `BTreeMap`-ordered walk, because the build has to be
/// byte-for-byte reproducible: two runs over the same checkout produce the same
/// bytes, so `diff` between two builds is a real signal and not inode order.
pub fn discover(root: &Path) -> Result<Vec<Source>, Error> {
    let mut found = std::collections::BTreeSet::new();

    if root.join("README.md").is_file() {
        found.insert("README.md".to_string());
    }

    let docs = root.join("docs");
    if docs.is_dir() {
        walk(root, &docs, &mut found)?;
    }

    let mut sources = Vec::new();
    for rel in found {
        sources.push(Source {
            out: out_of(&rel),
            kind: classify(&rel),
            rel,
        });
    }
    Ok(sources)
}

fn walk(
    root: &Path,
    dir: &Path,
    found: &mut std::collections::BTreeSet<String>,
) -> Result<(), Error> {
    let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
    let mut children: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    children.sort();
    for path in children {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.starts_with('.') || name == "__pycache__" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, found)?;
        } else if name.ends_with(".md") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            found.insert(rel);
        }
    }
    Ok(())
}

fn classify(rel: &str) -> Kind {
    if rel.eq_ignore_ascii_case("README.md") {
        return Kind::Home;
    }
    let Some(rest) = rel.strip_prefix("docs/") else {
        return Kind::Other;
    };
    if !rest.contains('/') {
        return Kind::Guide;
    }
    let Some(adr) = rest.strip_prefix("adr/") else {
        // `docs/adr/fixtures/x/README.md` is handled below; any other subdirectory
        // is a new part of the docs tree that `nav` has not been told about.
        return Kind::Other;
    };
    if adr.eq_ignore_ascii_case("README.md") {
        return Kind::AdrIndex;
    }
    if adr.starts_with("fixtures/") {
        return Kind::Fixture;
    }
    let name = paths::file_name(adr);
    let number = name.get(..4).unwrap_or("");
    if number.bytes().all(|b| b.is_ascii_digit()) && name.get(4..5) == Some("-") {
        return Kind::Adr;
    }
    Kind::Other
}

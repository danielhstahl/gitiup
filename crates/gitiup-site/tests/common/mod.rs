//! Shared helpers for `gitiup-site`'s tests: where the checkout is, and a throwaway
//! checkout for the cases that must not depend on the repository's own docs.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The repository this crate lives in.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("crates/gitiup-site sits two levels below the workspace root")
        .to_path_buf()
}

/// A checkout with a handful of markdown files in it, in a temporary directory.
///
/// The site's own behaviour has to be tested against a tree that is small enough to
/// reason about — the repository's real `docs/` is the integration case, not the
/// unit case, and a test that asserts a specific link count in it breaks the day
/// somebody adds a page.
pub struct Fixture {
    /// The temporary directory; dropping it removes the checkout.
    pub root: PathBuf,
    dir: tempfile::TempDir,
}

impl Fixture {
    /// Write `files` (repo-relative path → contents) into a fresh checkout with a
    /// `Cargo.toml` and a `docs/` directory.
    pub fn new(files: &[(&str, &str)]) -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\nrepository = \"https://example.test/project/repo\"\n",
        )
        .expect("manifest");
        for (path, contents) in files {
            let target = root.join(path);
            std::fs::create_dir_all(target.parent().expect("parent"))
                .expect("create parent directory");
            std::fs::write(target, contents).expect("write file");
        }
        Fixture { root, dir }
    }

    /// A config pointing at the fixture, with output inside the fixture so one
    /// test cannot read another's leftovers.
    pub fn config(&self) -> gitiup_site::Config {
        let mut cfg = gitiup_site::Config::new(self.root.clone());
        cfg.out = self.root.join("_site");
        cfg
    }

    /// Read a built file back out of the site.
    pub fn read(&self, site_relative: &str) -> String {
        std::fs::read_to_string(self.root.join("_site").join(site_relative))
            .unwrap_or_else(|e| panic!("read {}: {e}", site_relative))
    }

    /// Is anything at this site-relative path?
    pub fn exists(&self, site_relative: &str) -> bool {
        self.root.join("_site").join(site_relative).is_file()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // tempfile removes the directory; this only says out loud that the build
        // output is expected to live inside it and goes with it.
        let _ = &self.dir;
    }
}

/// The hrefs in a built page, in document order.
pub fn hrefs(html: &str) -> Vec<String> {
    in_attributes(html, ["href=\""].into_iter())
}

/// Every `href` and `src` in a built page, in document order.
pub fn references(html: &str) -> Vec<String> {
    in_attributes(html, ["href=\"", "src=\""].into_iter())
}

fn in_attributes<'a>(html: &str, attributes: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out = Vec::new();
    for attribute in attributes {
        let mut rest = html;
        while let Some(at) = rest.find(attribute) {
            rest = &rest[at + attribute.len()..];
            let Some(end) = rest.find('"') else { break };
            out.push(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    out
}

/// Every `id="…"` in a built page.
pub fn ids(html: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = html;
    while let Some(at) = rest.find("id=\"") {
        rest = &rest[at + 4..];
        let Some(end) = rest.find('"') else { break };
        out.insert(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

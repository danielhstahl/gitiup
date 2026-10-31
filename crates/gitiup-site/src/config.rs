//! What a build is told: where the checkout is, where the site goes, and what the
//! site is allowed to assume about where it will be served from.

use std::path::{Path, PathBuf};

use crate::error::Error;

/// Where the project says its own source lives, if `Cargo.toml` does not say.
pub const DEFAULT_SOURCE_URL: &str = "https://github.com/gitiup/gitiup";

/// The front-page one-liner, if `README.md` does not supply one.
pub const DEFAULT_TAGLINE: &str = "Run GitHub Actions locally, and contribute without a forge.";

/// A build's inputs.
///
/// Everything in here has a default that is right for this repository, so the
/// ordinary invocation is `gitiup-site build` with no flags at all.
#[derive(Debug, Clone)]
pub struct Config {
    /// The checkout: the directory holding `docs/`.
    pub root: PathBuf,
    /// Where to write the site. Removed and recreated on every build, so a page
    /// deleted from `docs/` cannot survive in the output from an earlier run.
    pub out: PathBuf,
    /// The site's name, in the header and in every `<title>`.
    pub title: String,
    /// One line under the site name. Defaults to `README.md`'s first paragraph.
    pub tagline: String,
    /// The repository to link to for anything that is not a page in the site — a
    /// source file, a fixture's `cases.json`, a crate's `README.md`.
    pub source_url: String,
    /// The ref those source links name. `main` is right for a site published from
    /// the default branch, which is the only thing that gets published.
    pub source_ref: String,
    /// The URL path the site is served from, `/` or `/gitiup/`. Only `404.html`
    /// needs it: a server can answer a missing page at a depth the builder cannot
    /// know, so that one page cannot use relative links.
    pub base_path: String,
    /// The absolute site URL. When set, `sitemap.xml` and `robots.txt` are written;
    /// when unset they are not, because a sitemap of guessed hosts is worse than no
    /// sitemap.
    pub site_url: Option<String>,
}

impl Config {
    /// The defaults for a checkout rooted at `root`.
    ///
    /// `source_url` is read out of the workspace `Cargo.toml`'s `repository` field
    /// when it is present, so a fork that edits its manifest gets links to its own
    /// repository and nobody has to pass a flag to get that.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let source_url =
            repository_from_manifest(&root).unwrap_or_else(|| DEFAULT_SOURCE_URL.to_string());
        Config {
            out: root.join("_site"),
            title: "gitiup".to_string(),
            tagline: DEFAULT_TAGLINE.to_string(),
            source_url,
            source_ref: "main".to_string(),
            base_path: "/".to_string(),
            site_url: None,
            root,
        }
    }

    /// Walk up from `cwd` to find the checkout: the first ancestor holding both a
    /// `Cargo.toml` and a `docs/`.
    ///
    /// This is what makes `cargo run -p gitiup-site -- build` work from anywhere
    /// inside the repository, which matters because the point of the tool is that
    /// anybody builds it locally before pushing.
    pub fn discover(cwd: &Path) -> Result<Self, Error> {
        let cwd = if cwd.is_absolute() {
            cwd.to_path_buf()
        } else {
            std::env::current_dir()?.join(cwd)
        };
        let mut dir: Option<&Path> = Some(cwd.as_path());
        while let Some(current) = dir {
            if current.join("Cargo.toml").is_file() && current.join("docs").is_dir() {
                return Ok(Self::new(current));
            }
            dir = current.parent();
        }
        // Fall back to the cwd itself: `check` will say what it could not find, and
        // saying it from `build` would be a second, less specific message.
        Ok(Self::new(cwd))
    }

    /// Fail early rather than mysteriously: no `docs/`, nothing to build.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.root.join("docs").is_dir() {
            return Err(Error::Config(format!(
                "no docs/ directory under {} — pass --root <checkout>",
                self.root.display()
            )));
        }
        Ok(())
    }

    /// `base_path`, normalized to start and end with `/`.
    pub fn base_path(&self) -> String {
        let trimmed = self.base_path.trim_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            format!("/{trimmed}/")
        }
    }

    /// `site_url` with any trailing `/` removed, so joins do not double it.
    pub fn site_url(&self) -> Option<String> {
        self.site_url
            .as_ref()
            .map(|u| u.trim_end_matches('/').to_string())
    }

    /// The `blob` URL for a repo-relative path, or `None` if the path is not inside
    /// the checkout (a `..` that escaped it, say).
    pub fn blob_url(&self, repo_relative: &str) -> String {
        format!(
            "{}/blob/{}/{}",
            self.source_url.trim_end_matches('/'),
            self.source_ref,
            repo_relative
        )
    }
}

/// The `repository` field of the workspace manifest, if it can be found.
///
/// Deliberately a line scan and not a TOML parse: one key, read once, in a tool
/// that has no reason to grow a TOML dependency (see `crates/gitiup-site/Cargo.toml`
/// for what a dependency has to do to earn its place here).
fn repository_from_manifest(root: &Path) -> Option<String> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    let repository = "repository";
    for line in manifest.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix(repository) else {
            continue;
        };
        let Some(rest) = rest.trim().strip_prefix('=') else {
            continue;
        };
        let value = rest.trim().trim_matches(',').trim_matches('"');
        if value.starts_with("http") {
            return Some(value.to_string());
        }
    }
    None
}

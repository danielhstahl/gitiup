//! Paths inside the built site.
//!
//! Every path in this crate is a site-relative, `/`-separated string — `docs/adr`,
//! `index.html`, `docs/quorum.html#the-ladder` — and never a `std::path::Path`, for
//! two reasons: the site is the same on Windows and Linux, and a path that is a
//! string compares, sorts and prints identically everywhere, which is what makes the
//! build byte-for-byte reproducible (the property `docs/reproducibility.md` asks of
//! every other artifact here).
//!
//! Only `tree` and the writer touch the filesystem, and they convert at the edge.

/// The directory part of a site path: `docs/adr/x.md` → `docs/adr`, `x.md` → ``.
pub fn dir_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

/// The last segment of a site path.
pub fn file_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// The file name without its last extension: `docs/quorum.md` → `quorum`.
pub fn stem(path: &str) -> String {
    let name = file_name(path);
    match name.strip_suffix(".md") {
        Some(s) => s.to_string(),
        None => name
            .rsplit_once('.')
            .map(|(s, _)| s.to_string())
            .unwrap_or_else(|| name.to_string()),
    }
}

/// Resolve `rel` against the directory `base`, normalizing `.` and `..` away.
///
/// This is the whole of markdown's relative-link resolution: `[x](../quorum.md)`
/// found in `docs/adr/index.md` resolves to `docs/quorum.md`. A `..` that would
/// walk above the repository root is dropped — the link then resolves to a path
/// that is not in the site, and `check` reports it as broken rather than silently
/// reaching outside the checkout.
pub fn resolve(base: &str, rel: &str) -> String {
    let rel = rel.trim();
    let mut segments: Vec<&str> = Vec::new();
    if rel.starts_with('/') {
        // Repo-root-relative, which is what a Pages site under a project path needs
        // and what a plain `/` cannot mean in a markdown file.
        segments.extend(rel.trim_matches('/').split('/').filter(|s| !s.is_empty()));
        return join_segments(&segments);
    }
    let start = if base.is_empty() {
        Vec::new()
    } else {
        split(base)
    };
    segments.extend(start.iter().copied());
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segments.last().is_some() {
                    segments.pop();
                }
            }
            other => segments.push(other),
        }
    }
    join_segments(&segments)
}

fn split(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

fn join_segments(segments: &[&str]) -> String {
    segments.join("/")
}

/// The href to use when standing in `from_dir` and linking to `to`.
///
/// Always relative, because a site that is built with relative links can be opened
/// from a filesystem, served from a bucket subdirectory, and published under a
/// project path on Pages — all from the same bytes. That is why there is no
/// `--base-path` for the pages themselves, only for `404.html`, which the server
/// can serve from a depth the builder cannot know.
pub fn relative(from_dir: &str, to: &str) -> String {
    let from = split(from_dir);
    let to_segs = split(to);
    let mut common = 0;
    while common < from.len() && common < to_segs.len() && from[common] == to_segs[common] {
        common += 1;
    }
    let ups = from.len() - common;
    let mut out = String::new();
    for _ in 0..ups {
        out.push_str("../");
    }
    out.push_str(&to_segs[common..].join("/"));
    out
}

/// How many directories below the site root a path is: `index.html` → 0,
/// `docs/adr/x.html` → 2.
pub fn depth_of(path: &str) -> usize {
    split(path).len().saturating_sub(1)
}

/// The href prefix that gets from a page at `depth` back to the site root: ``, `../`,
/// `../../`.
pub fn up(depth: usize) -> String {
    let mut out = String::new();
    for _ in 0..depth {
        out.push_str("../");
    }
    out
}

/// Split an href into `(target, anchor)` — the anchor without its `#`, or `""`.
pub fn split_anchor(dest: &str) -> (&str, &str) {
    match dest.find('#') {
        Some(i) => (&dest[..i], &dest[i + 1..]),
        None => (dest, ""),
    }
}

/// Does this destination name a place inside the site rather than elsewhere on the
/// network?
pub fn is_internal(dest: &str) -> bool {
    if dest.is_empty() {
        return true;
    }
    if let Some((head, _)) = dest.split_once(':') {
        // A scheme (`https:`, `mailto:`) is six or more ASCII letters before the
        // colon; a lone `C:` in a Windows path is one. Anything else with a colon
        // is treated as external, which is the safe reading.
        if !head.is_empty()
            && head.len() > 1
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return false;
        }
    }
    !dest.starts_with("//")
}

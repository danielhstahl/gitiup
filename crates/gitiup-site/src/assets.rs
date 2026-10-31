//! The files copied verbatim into every build.
//!
//! `include_str!` rather than a directory copy for three reasons: the binary has no
//! path it has to be run next to, so `cargo install` and a CI job on a runner with a
//! different working directory both work; the list is in the source, so there is no
//! "did the copy step run" question; and the build cannot emit a site missing its
//! stylesheet, because the stylesheet is part of the program.

/// The stylesheet: one file, no framework, no preprocessing.
pub const STYLESHEET: &str = include_str!("../assets/site.css");

/// The search script, loaded by `search.html` and by nothing else.
pub const SEARCH_SCRIPT: &str = include_str!("../assets/search.js");

/// The icon.
pub const FAVICON: &str = include_str!("../assets/favicon.svg");

/// `(site path, contents)` for everything that is copied rather than rendered.
pub fn files() -> [(&'static str, &'static str); 3] {
    [
        ("assets/site.css", STYLESHEET),
        ("assets/search.js", SEARCH_SCRIPT),
        ("assets/favicon.svg", FAVICON),
    ]
}

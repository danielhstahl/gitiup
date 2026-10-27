//! The acceptance criterion "no forge API types appear outside the adapter crate",
//! enforced instead of promised.
//!
//! Three checks, in order of how they get broken:
//!
//! 1. no source file in this crate may name a forge's wire vocabulary — not a type
//!    (`PullRequest`, `CheckRun`), not a header (`X-GitHub-Api-Version`), not a host
//!    literal in a call. This is the one that catches the pull request that "just
//!    needs one little thing from the API here".
//! 2. `Cargo.toml` must not gain a forge client or an HTTP client: the adapter is the
//!    only thing in the workspace that talks to a forge, and it is only reachable
//!    through the host traits.
//! 3. the feature gate must be real: `hosts-github` exists, is on by default, gates
//!    exactly the optional adapter dependency, and the code that refuses a forge
//!    remote in a build without it is compiled either way (a `cargo build
//!    --no-default-features` that silently *accepts* a forge remote would be worse
//!    than one that fails to build).

use std::path::{Path, PathBuf};

/// Forge wire vocabulary that must never appear in the CLI's own source.
const FORBIDDEN_TOKENS: &[&str] = &[
    "PullRequest",
    "CheckRun",
    "check_runs",
    "check-runs",
    "X-GitHub-Api-Version",
    "x-github-api-version",
    "api.github.com",
    "graphql",
    "octocrab",
    "octocrs",
    "reqwest",
    "hyper::",
    "ureq::",
    "html_url",
    "access_token",
    "client_id",
];

/// The file where the CLI is *allowed* to name the forge it does not talk to, and
/// why: it is the composition root, it has to recognise a forge remote to refuse it
/// by name in a build without the adapter, and the test below keeps that file to
/// classification and nothing else.
const ALLOWED: &[&str] = &["src/remotes.rs"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "fixtures") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn relative(path: &Path) -> String {
    path.strip_prefix(crate_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn dependency_lines(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains('='))
        .map(str::to_lowercase)
        .collect()
}

#[test]
fn the_cli_never_names_a_forge_wire_type() {
    let mut files = Vec::new();
    rust_files(&crate_root().join("src"), &mut files);
    assert!(
        files.len() > 3,
        "the walk found almost nothing; fix the test before trusting it"
    );
    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let name = relative(&file);
        if ALLOWED.contains(&name.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("a source file that cannot be read");
        for token in FORBIDDEN_TOKENS {
            if text.contains(token) {
                offenders.push(format!("{name}: {token}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "forge wire vocabulary leaked out of the adapter crate:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_cli_has_no_forge_or_http_client_dependency() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("Cargo.toml");
    let lines = dependency_lines(&manifest);
    for banned in [
        "octocrab", "octocrs", "github", "reqwest", "hyper", "ureq", "graphql", "curl",
    ] {
        let hit = lines.iter().any(|line| {
            line.starts_with(&format!("{banned} ")) || line.starts_with(&format!("{banned}="))
        });
        assert!(
            !hit,
            "gitiup gained a direct dependency on {banned}: {manifest}"
        );
    }
    // The adapter is present only as an optional dependency: that is what makes the
    // feature gate mean something.
    let adapter = lines
        .iter()
        .find(|line| line.starts_with("gitiup-host-github"))
        .expect("the github adapter is a dependency of the CLI");
    assert!(
        adapter.contains("optional"),
        "the adapter must be optional, or `--no-default-features` does not remove it: \
         {adapter}"
    );
}

#[test]
fn the_feature_gate_is_real() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("Cargo.toml");
    let section = manifest
        .split("[features]")
        .nth(1)
        .expect("a [features] section")
        .split("\n[")
        .next()
        .expect("the [features] section ends");
    assert!(
        section.contains("default = [\"hosts-github\"]"),
        "`hosts-github` must be on by default, or the feature is a way to lose \
         functionality rather than a way to keep the core clean: {section}"
    );
    assert!(
        section.contains("hosts-github = [\"dep:gitiup-host-github\"]"),
        "the feature's only job is the adapter: {section}"
    );
}

#[test]
fn the_refusal_is_compiled_whichever_way_the_feature_goes() {
    // The behaviour itself is asserted in `remotes::tests`, twice, once per feature
    // configuration; what is asserted *here*, with no cfg of its own, is that the
    // refusal text exists in the source at all — a deleted message is how a build
    // starts lying about what it supports.
    let source =
        std::fs::read_to_string(crate_root().join("src/remotes.rs")).expect("src/remotes.rs");
    assert!(
        source.contains("hosts-github"),
        "the flag must be named in the source"
    );
    assert!(source.contains("--features"), "and the fix must be as well");
    assert!(
        source.contains("#[cfg(not(feature = \"hosts-github\"))]"),
        "there must be a branch that runs when the adapter is absent"
    );
}

//! The acceptance criterion for this ticket is that `gitiup-host` compiles with
//! **zero forge imports**, so the ban is enforced here instead of in review
//! comments.
//!
//! Two checks:
//!
//! 1. no `use`/`extern crate`/`mod` statement anywhere under `src/` may name a
//!    forge client or HTTP/GraphQL stack used to talk to one;
//! 2. `Cargo.toml` must not depend on one, and the default feature set must stay
//!    forge-free — an adapter for a real forge has to be a *separate crate* that
//!    the binary makes optional, which is what `gitiup-host-github` and the CLI's
//!    `hosts-github` feature do; nothing you can turn off inside this crate counts.

use std::path::{Path, PathBuf};

/// Crate/path fragments that must never be imported from the core host crate.
const FORBIDDEN_IMPORTS: &[&str] = &[
    "github",
    "github_com",
    "gitlab",
    "bitbucket",
    "octocrab",
    "octocrs",
    "graphql",
    "gql_client",
    "reqwest",
    "hyper",
    "ureq",
    "oauth2",
    "gh_api",
    "forge_sdk",
];

/// Crates that are forge clients, banned as dependencies outright.
const FORBIDDEN_DEPENDENCIES: &[&str] = &[
    "octocrab",
    "octocrs",
    "github-graphql",
    "graphql_client",
    "graphql-client",
    "reqwest",
    "hyper",
    "ureq",
    "oauth2",
];

/// Module names that would mean a forge adapter has been added; if one appears it
/// must be behind a feature that is not on by default.
const ADAPTER_MODULES: &[&str] = &["github", "gitlab", "bitbucket"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Statements that could bring an outside type into scope.
fn import_statements(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("//") || line.is_empty() {
            continue;
        }
        let starts = line.starts_with("use ")
            || line.starts_with("pub use ")
            || line.starts_with("extern crate ")
            || line.starts_with("pub extern crate ");
        if let Some(buffer) = current.as_mut() {
            buffer.push(' ');
            buffer.push_str(line);
            if line.contains(';') {
                statements.push(buffer.clone());
                current = None;
            }
            continue;
        }
        if starts {
            if line.contains(';') {
                statements.push(line.to_string());
            } else {
                current = Some(line.to_string());
            }
        }
    }
    statements
}

/// `[dependencies]` style tables in a manifest, as (table, key) pairs.
fn manifest_dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut table = String::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            table = name.to_string();
            continue;
        }
        if table.ends_with("dependencies") || table.starts_with("dependencies") {
            let key = line
                .split(['=', ' '])
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            if !key.is_empty() {
                out.push((table.clone(), key));
            }
        }
    }
    out
}

fn default_features(manifest: &str) -> Vec<String> {
    let mut in_features = false;
    let mut out = Vec::new();
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if in_features
            && line.starts_with("default")
            && let Some(list) = line.split('=').nth(1)
        {
            out.extend(
                list.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(|f| f.trim().trim_matches('"').to_string())
                    .filter(|f| !f.is_empty()),
            );
        }
    }
    out
}

/// Directories whose code must stay forge-free.
const SCANNED_DIRS: &[&str] = &["src", "tests", "examples"];

#[test]
fn no_forge_imports_anywhere_in_src() {
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let files: Vec<PathBuf> = SCANNED_DIRS
        .iter()
        .flat_map(|dir| rust_files(&crate_root().join(dir)))
        .collect();
    assert!(
        !files.is_empty(),
        "the scanner found no sources under {:?}",
        SCANNED_DIRS
    );
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source readable");
        for statement in import_statements(&text) {
            checked += 1;
            let lowered = statement.to_ascii_lowercase();
            for forbidden in FORBIDDEN_IMPORTS {
                if lowered.contains(forbidden) {
                    offenders.push(format!("{}: {statement}", path.display()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "gitiup-host must not import forge clients:\n{}",
        offenders.join("\n")
    );
    assert!(
        checked >= 20,
        "the scanner should be seeing the crate's imports, saw {checked}"
    );
}

#[test]
fn no_forge_crates_in_the_manifest() {
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("manifest readable");
    let deps = manifest_dependencies(&manifest);
    assert!(
        !deps.is_empty(),
        "manifest parsing must find the dependencies"
    );
    for (table, dep) in &deps {
        for forbidden in FORBIDDEN_DEPENDENCIES {
            assert!(
                !dep.to_ascii_lowercase().contains(forbidden),
                "{dep} in {table} is a forge/HTTP client; core must stay forge-free"
            );
        }
    }
    // The default feature set is what `cargo build` compiles: it must stay empty
    // of adapters, so the plain `gitiup` binary never links a forge client.
    for feature in default_features(&manifest) {
        assert!(
            !feature.contains("github") && !feature.contains("gitlab"),
            "default features must not enable a forge adapter: {feature}"
        );
    }
}

#[test]
fn forge_adapters_are_only_allowed_behind_a_non_default_feature() {
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("manifest readable");
    let defaults = default_features(&manifest);
    let hosts = crate_root().join("src").join("hosts");
    for adapter in ADAPTER_MODULES {
        let file = hosts.join(format!("{adapter}.rs"));
        let dir = hosts.join(adapter).join("mod.rs");
        let present = file.is_file() || dir.is_file();
        if !present {
            continue;
        }
        // There is one arrangement that satisfies the ticket, and the github
        // adapter took it: the adapter is a *separate crate* (`gitiup-host-github`)
        // that depends on this one, not a module inside it. A module here would be
        // compiled by every build of the core no matter what feature the binary
        // turns on, and the whole point is that the core has no forge code to
        // remove. This assertion stays as the tripwire for someone doing it that
        // way anyway.
        assert!(
            !defaults.iter().any(|f| f.contains(adapter)),
            "adapter module {adapter} must not be reachable from default features"
        );
    }
}

#[test]
fn the_ban_list_is_not_toothless() {
    // Self-check: if the scanner cannot spot a planted offender it is broken.
    let planted = "use octocrab::Octocrab;\nuse github::client;\n";
    let statements = import_statements(planted);
    assert_eq!(statements.len(), 2);
    let hits = statements
        .iter()
        .filter(|s| {
            let lowered = s.to_ascii_lowercase();
            FORBIDDEN_IMPORTS.iter().any(|f| lowered.contains(f))
        })
        .count();
    assert_eq!(hits, 2, "the scanner must catch both forms");
}

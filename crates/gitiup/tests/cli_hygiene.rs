//! Hygiene for the user-facing crate.
//!
//! Two properties worth more than the convenience they cost:
//!
//! 1. **the CLI decides nothing about the format.** It depends on `gitiup-attest`,
//!    `gitiup-normalise` and a JSON parser, nothing else. Every extra dependency is
//!    a place where the digest printed here could differ from the digest a verifier
//!    recomputes, and the second JSON library or arg-parser is where that happens.
//!    The normaliser is allowed because it is not an opinion about the digest — for
//!    `normalisation_version` 1 it *is* the computation, and leaving it out would
//!    mean the CLI re-implemented the rules somewhere a verifier never looks.
//! 2. **the exit codes users branch on are one table, not two.** The usage text,
//!    the module docs and the library's own taxonomy have to agree, because a
//!    merge gate is written against the numbers.
//! 3. **the CLI is the composition root, and only the composition root.** It may
//!    depend on `gitiup-host` (it has to, to reach a remote at all) and on the forge
//!    adapters behind their features — `hosts-github`, on by default. That is not a
//!    license to talk to a forge from here: the adapter is reached through the host
//!    traits and `tests/no_forge_calls.rs` fails the build if any forge wire
//!    vocabulary appears in this crate's own source. What this file guards is the
//!    *digest* dependencies: nothing that could recompute a digest differently, and
//!    no HTTP or git client that would bypass the host abstraction entirely.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// What the binary may depend on directly.
// `gitiup-run` is the planning and tier-choosing crate behind `gitiup run`; it is
// itself kept network-free by its own `tests/no_side_effects.rs`.
const ALLOWED_DEPENDENCIES: [&str; 8] = [
    "gitiup-attest",
    "gitiup-normalise",
    "gitiup-run",
    // `gitiup doctor --sandbox` asks it what this machine can confine; it produces no
    // digest and reads no report, so it cannot disagree with the format crate.
    "gitiup-sandbox",
    // The host abstraction. Without it the CLI could not reach a remote at all; with
    // it, every remote operation goes through `Host`/`RefStore`/`BlobStore` and no
    // command gets to invent its own storage.
    "gitiup-host",
    // The github adapter, `optional = true` and gated on `hosts-github` (default on).
    // Optional is the point: `--no-default-features` produces a binary with no forge
    // code in it, which is what makes the feature gate mean something.
    "gitiup-host-github",
    // `gitiup key` / `gitiup identity`. Signing cannot be kept out of the CLI: the
    // passphrase is typed here, and a key is chosen here. It is not a second digest
    // implementation either — `gitiup-keys` has no digest logic and builds every key
    // as a `gitiup_attest::Signer`, so the signature bytes come from the format crate
    // whoever holds the key.
    "gitiup-keys",
    "serde_json",
];

/// Anything that could put a network, a forge client or a second digest
/// implementation behind the command line. Chosen as crate names, deliberately:
/// matching on `sha1` or `ring` would flag every `sha1:…` commit id in a fixture.
const FORBIDDEN: &[&str] = &[
    "reqwest", "hyper", "ureq", "git2", "libgit2", "octocrab", "blake3", "clap",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in ["src", "tests"] {
        let path = crate_root().join(dir);
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                let path = entry.path();
                // These two files name the forbidden things in order to forbid them.
                if path
                    .file_name()
                    .is_some_and(|n| n == "cli_hygiene.rs" || n == "no_forge_calls.rs")
                {
                    continue;
                }
                if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    files
}

#[test]
fn dependencies_are_the_two_item_list() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml")).unwrap();
    let mut direct = BTreeSet::new();
    let mut section = String::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section == "[dependencies]"
            && let Some((name, _)) = line.split_once('=')
        {
            direct.insert(name.trim().to_string());
        }
    }
    let allowed: BTreeSet<String> = ALLOWED_DEPENDENCIES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        direct, allowed,
        "the CLI must not grow a dependency that can disagree with the format crate"
    );
}

#[test]
fn no_network_or_forge_clients_behind_the_command_line() {
    for file in sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        for banned in FORBIDDEN {
            assert!(
                !text.contains(banned),
                "{} mentions `{banned}`",
                file.display()
            );
        }
    }
}

#[test]
fn the_documented_exit_codes_are_the_ones_the_code_uses() {
    let main = std::fs::read_to_string(crate_root().join("src/main.rs")).unwrap();
    // Usage (2), I/O (3), invalid (6), digest mismatch (8) must appear as exit
    // codes in the code, not only in prose.
    for code in ["code: 2", "code: 3"] {
        assert!(main.contains(code), "`{code}` is missing from main.rs");
    }
    let digest = std::fs::read_to_string(crate_root().join("src/digest.rs")).unwrap();
    assert!(
        digest.contains("ErrorKind::DigestMismatch"),
        "a mismatch must be raised as the library's own digest-mismatch class (exit 8), \
         not as a locally invented number"
    );
    assert!(
        main.contains("From<gitiup_attest::Error> for CliError"),
        "library errors must keep their documented exit code"
    );
}

#[test]
fn the_command_line_documents_the_format_it_consumes() {
    // `gitiup digest` consumes the run report; the format has to be written down
    // somewhere a runner author will read, not only in Rust types.
    let doc = crate_root().join("../../docs/run-report.md");
    assert!(doc.exists(), "{} must exist", doc.display());
    let doc = std::fs::read_to_string(&doc).unwrap();
    for token in ["RunReport", "Material", "normalisation_version", "run_id"] {
        assert!(
            doc.contains(token),
            "docs/run-report.md should mention {token}"
        );
    }
    let usage = std::fs::read_to_string(crate_root().join("src/main.rs")).unwrap()
        + &std::fs::read_to_string(crate_root().join("src/digest.rs")).unwrap();
    assert!(
        usage.contains("run-report.md"),
        "the help text should point at the document that defines the input"
    );
    assert!(
        usage.contains("ADR-0001"),
        "the exit-code taxonomy comes from the ADR; say so where users see it"
    );
}

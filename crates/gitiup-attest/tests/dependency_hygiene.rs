//! The crate that decides the trust format must stay auditable.
//!
//! Three properties are worth more than the features they cost, so they are
//! enforced here instead of in review comments:
//!
//! 1. **no I/O at all.** Verification runs in a pre-receive hook, in a volunteer's
//!    sandbox and in a test; it may not touch the network, the filesystem, a
//!    subprocess or the environment. Storage is `gitiup-host`'s job, keys are
//!    giti-1rs.6's job, and log anchoring is a *record* you hand to the verifier
//!    (ADR-0001 D7), never a fetch it performs.
//! 2. **no floating point.** ADR-0001 D1 bans floats from the signed payload; the
//!    ban is easier to keep if nothing in the crate can even mention `f32`/`f64`.
//! 3. **no C toolchain.** The dependency list is short and pure Rust, so `gitiup`
//!    cross-compiles and fits in a static image.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Everything this crate may depend on directly. Adding to this list is a
/// deliberate act: say why in the PR.
///
/// `gitiup-canon` is the half of ADR-0001 that may have exactly one implementation
/// (the canonicaliser, the digest and SSH key-id primitives, the exit-code
/// taxonomy), re-exported here unchanged so that `gitiup-host` — which may not
/// depend on *this* crate — can re-hash and signature-check a change record with the
/// same code. See ADR-0003 D11.
const ALLOWED_DEPENDENCIES: [&str; 5] = [
    "ed25519-dalek",
    "gitiup-canon",
    "serde",
    "serde_json",
    "sha2",
];

/// Tokens that must never appear in library code.
const FORBIDDEN_IN_LIBRARY: &[&str] = &[
    "std::net",
    "std::fs",
    "std::env",
    "std::process",
    "std::os::",
    "TcpStream",
    "UdpSocket",
    "Command::",
    "reqwest",
    "hyper",
    "ureq",
    "surf",
    "russh",
    "git2",
    "libgit2",
    "octocrab",
    "blake3", // not banned by ADR-0001 D2, just not admitted yet: it would be a format decision
];

/// The clock may only be read in `time.rs`, so "when is this fresh?" has exactly
/// one answer site (ADR-0001 D6).
const CLOCK_TOKENS: &[&str] = &["SystemTime", "UNIX_EPOCH", "Instant::"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Rust files under `src`, excluding the test-only tail of each file.
///
/// Tests are allowed to poke the clock and build floats: what matters is that the
/// shipped code cannot.
fn library_lines(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("readable source file");
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        out.push(line.to_string());
    }
    out
}

fn source_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let src = crate_root().join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src exists") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn dependencies_are_the_short_pure_rust_list() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml")).unwrap();
    let mut found = BTreeSet::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if in_dependencies && let Some((name, _)) = line.split_once('=') {
            found.insert(name.trim().to_string());
        }
    }
    let allowed: BTreeSet<String> = ALLOWED_DEPENDENCIES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        found, allowed,
        "the dependency list of the format crate is part of its audit story"
    );
    assert!(
        !manifest.contains("[dev-dependencies]") || !manifest.contains("reqwest"),
        "even a dev-dependency on an HTTP client invites a network call"
    );
}

#[test]
fn library_code_touches_no_io() {
    for file in source_files() {
        for (i, line) in library_lines(&file).into_iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for banned in FORBIDDEN_IN_LIBRARY {
                assert!(
                    !code.contains(banned),
                    "{}:{}: `{banned}` — this crate must not do I/O ({})",
                    file.display(),
                    i + 1,
                    code.trim()
                );
            }
            if file.file_name().is_some_and(|n| n != "time.rs") {
                for token in CLOCK_TOKENS {
                    assert!(
                        !code.contains(token),
                        "{}:{}: `{token}` — read the clock through Policy::now / TimeUs only",
                        file.display(),
                        i + 1
                    );
                }
            }
        }
    }
}

#[test]
fn no_floats_anywhere_in_the_library() {
    // ADR-0001 D1: integers only. The canonicaliser refuses floats on the way in
    // (`canon::tests::rejects_floats`); this keeps them out of the code as well, so
    // nobody can accumulate a duration or a coverage percentage in an `f64` and
    // hash the result.
    let mut offenders = Vec::new();
    for file in source_files() {
        for (i, line) in library_lines(&file).into_iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for token in ["f32", "f64"] {
                if code.contains(token) {
                    offenders.push(format!("{}:{}: {}", file.display(), i + 1, code.trim()));
                }
            }
            if has_float_literal(&strip_strings(code)) {
                offenders.push(format!("{}:{}: {}", file.display(), i + 1, code.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "floats in the format crate:\n{offenders:#?}"
    );
}

/// Remove `"…"` and `char` literals so a version string like `"1.99.1"` is not
/// mistaken for a float literal.
fn strip_strings(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            let quote = c;
            while let Some(inner) = chars.next() {
                if inner == '\\' {
                    chars.next();
                    continue;
                }
                if inner == quote {
                    break;
                }
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn has_float_literal(code: &str) -> bool {
    let bytes = code.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != b'.' {
            continue;
        }
        let before = i > 0 && bytes[i - 1].is_ascii_digit();
        let after = bytes.get(i + 1).is_some_and(|b| b.is_ascii_digit());
        if before && after {
            return true;
        }
    }
    false
}

#[test]
fn the_format_documents_the_adr() {
    // "code docs reference the ADR" is an acceptance criterion, so make it a
    // checkable claim rather than a hope.
    let adr = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/0001-attestation-encoding-hash-and-signature.md");
    assert!(adr.exists(), "ADR-0001 must exist at {}", adr.display());
    let mut mentioning = 0usize;
    for file in source_files() {
        let text = std::fs::read_to_string(&file).unwrap();
        if text.contains("ADR-0001") {
            mentioning += 1;
        }
    }
    assert!(
        mentioning >= 6,
        "the ADR should be referenced across the crate, not in one corner (found {mentioning} files)"
    );
}

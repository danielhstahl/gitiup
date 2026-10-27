//! The documentation examples are runnable.
//!
//! A format document that has drifted from the code is worse than none: it is a
//! specification people trust and then contradict. So the report in
//! `docs/run-report.md` is parsed and digested here, exactly as `gitiup digest`
//! would, and its digest is pinned.

use std::path::PathBuf;

use gitiup_attest::run::RunReport;
use gitiup_attest::{RunManifest, ToolchainEntry};

/// The first `jsonc` block in the run-report document, with `//` comments
/// removed (outside strings — a value is allowed to contain `//`).
fn documented_report_text() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/run-report.md");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let start = text
        .find("```jsonc")
        .expect("the run-report document must contain an example report");
    let body = &text[start + "```jsonc".len()..];
    let end = body.find("```").expect("an unterminated code fence");
    strip_line_comments(&body[..end])
}

fn documented_report() -> RunReport {
    serde_json::from_str(&documented_report_text())
        .expect("the report in docs/run-report.md must be a valid RunReport")
}

fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut cut = None;
        let bytes = line.as_bytes();
        let mut index = 0usize;
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                escaped = false;
            } else if byte == b'\\' && in_string {
                escaped = true;
            } else if byte == b'"' {
                in_string = !in_string;
            } else if !in_string && byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                cut = Some(index);
                break;
            }
            index += 1;
        }
        out.push_str(match cut {
            Some(cut) => line[..cut].trim_end(),
            None => line,
        });
        out.push('\n');
    }
    out
}

#[test]
fn the_documented_report_computes() {
    let report = documented_report();
    report.validate().expect("and a sane one");
    let manifest = RunManifest::from_run(&report).expect("and it must compute a manifest");
    assert_eq!(manifest.result.steps.len(), 2);
    assert_eq!(manifest.result.secret_names, vec!["NPM_TOKEN"]);
    assert_eq!(manifest.result.pins.len(), 1);
    assert_eq!(manifest.result.reusable_workflows.len(), 1);
    assert_eq!(manifest.result.environment.toolchain.len(), 1);
    // The example mixes a raw log with a pre-hashed one, and declares version 0:
    // the pass-through profile, which is the only honest match for raw text.
    assert_eq!(manifest.result.provenance.normalisation_version, 0);
    assert_eq!(
        manifest.result.steps[1].stdout.to_string(),
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "the second step's stdout arrived as a digest, and was taken as given"
    );
}

#[test]
fn the_documented_digest_is_pinned() {
    // Pinning the digest of a *documented* example is the cheapest way to make
    // "the document matches the code" checkable rather than aspirational.
    let manifest = RunManifest::from_run(&documented_report()).unwrap();
    assert_eq!(
        manifest.digest().unwrap().to_string(),
        "sha256:1d55a714fe1921de4ee011929292ac6bfdab3c5304138c3328e245df8b100694"
    );
    assert_eq!(
        manifest.result_digest().unwrap().to_string(),
        "sha256:b39a9e1b3669832f50e03b4df8a12ad7da76f5abf7e9c79165609e636f7e9d9c"
    );
}

#[test]
fn the_documented_notes_about_order_are_true() {
    // The document claims reordering does not move a digest, and that claims-side
    // changes stay out of the result digest. Prove both on the documented example,
    // where a reader would try it.
    let report = documented_report();
    let straight = RunManifest::from_run(&report).unwrap();

    let with_git = |reverse: bool| {
        let mut other = report.clone();
        other.environment.toolchain.push(ToolchainEntry {
            name: "git".into(),
            version: "2.47.0".into(),
        });
        if reverse {
            other.environment.toolchain.reverse();
        }
        RunManifest::from_run(&other).unwrap()
    };
    assert_eq!(
        with_git(false).digest().unwrap(),
        with_git(true).digest().unwrap(),
        "the inventory is a set: discovery order must not reach the digest"
    );
    assert_ne!(
        straight.digest().unwrap(),
        with_git(false).digest().unwrap(),
        "adding a tool must move the digest, or the field is being dropped"
    );

    let mut rerun = report.clone();
    rerun.claims.run_id = "fedcba9876543210".into();
    rerun.claims.claimed_at_us += 1;
    let rerun = RunManifest::from_run(&rerun).unwrap();
    assert_eq!(
        rerun.result_digest().unwrap(),
        straight.result_digest().unwrap(),
        "a rerun of the same outcome must agree on the ResultDigest"
    );
    assert_ne!(
        rerun.digest().unwrap(),
        straight.digest().unwrap(),
        "and still be a different attestation, so a replay is visible"
    );
}

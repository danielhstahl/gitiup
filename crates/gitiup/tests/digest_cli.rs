//! End-to-end tests for the `gitiup` binary.
//!
//! These run the real executable, because the acceptance criterion is a command
//! line: *`gitiup digest` prints the digest for a local run*. A library test could
//! be satisfied by a function nobody calls; these cannot.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Run the built binary with `args`, feeding `stdin` if given.
fn gitiup(args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
    command.args(args);
    // Explicitly piped: `spawn` + `wait_with_output` captures nothing unless the
    // pipes are asked for, and an inherited stdout makes these asserts vacuous.
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn().expect("the binary builds and runs");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("output is utf-8")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("output is utf-8")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

/// A minimal run report, in the shape a runner writes.
fn report() -> String {
    r#"{
        "repo": "gitiup/gitiup",
        "commit": "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "workflow": {"path": ".github/workflows/ci.yml", "text": "name: CI\non: push\n"},
        "event": {"name": "push", "payload": {"text": "{\"ref\":\"refs/heads/main\"}"}},
        "job": "build",
        "matrix": {"os": "ubuntu-24.04"},
        "inputs": {"jobs": 4, "coverage": true, "toolchain": "1.99.1"},
        "secret_names": ["NPM_TOKEN"],
        "environment": {"arch": "x86_64", "os": "linux", "provider": "docker",
                        "toolchain": [{"name": "rustc", "version": "1.99.1"}]},
        "steps": [
            {"id": "checkout", "name": "Checkout", "uses": "actions/checkout@v4",
             "exit_code": 0, "stdout": {"text": "Checked out\n"}},
            {"id": "test", "name": "cargo test", "exit_code": 0,
             "stdout": {"text": "test result: ok. 42 passed\n"},
             "outputs": {"coverage": "91"},
             "artifacts": [{"name": "cov", "content": {"text": "TN:\n"}, "size_bytes": 3}]}
        ],
        "provenance": {"tier": "local", "runner": "gitiup 0.1.0", "normalisation_version": 0,
                       "sandbox": "docker"},
        "claims": {"run_id": "0123456789abcdef", "claimed_at_us": 1793092502500000}
    }"#
    .to_string()
}

/// The digest the library computes for the same bytes: the CLI must not be a
/// second implementation of anything.
fn library_digest(bytes: &[u8]) -> (String, String) {
    use gitiup_attest::RunManifest;
    use gitiup_attest::run::RunReport;
    let report: RunReport = serde_json::from_slice(bytes).expect("test report parses");
    let manifest = RunManifest::from_run(&report).expect("test report computes");
    (
        manifest.digest().unwrap().to_string(),
        manifest.result_digest().unwrap().to_string(),
    )
}

fn write_report(dir: &Path, text: &str) -> PathBuf {
    let path = dir.join("run.json");
    std::fs::write(&path, text).expect("write report");
    path
}

#[test]
fn digest_prints_both_digests_for_a_local_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_report(dir.path(), &report());
    let (run, result) = library_digest(report().as_bytes());

    let output = gitiup(&["digest", path.to_str().unwrap()], None);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.contains(&format!("run            {run}")), "{text}");
    assert!(text.contains(&format!("result         {result}")), "{text}");
    // And enough context to know which run it was, without a second tool.
    assert!(text.contains("tier           local"), "{text}");
    assert!(
        text.contains("cargo test") || text.contains("steps          2"),
        "{text}"
    );
}

#[test]
fn digest_reads_a_report_from_stdin_two_ways() {
    let (run, _) = library_digest(report().as_bytes());
    for args in [vec!["digest"], vec!["digest", "-"]] {
        let output = gitiup(&args, Some(&report()));
        assert_eq!(code(&output), 0, "{}", stderr_of(&output));
        assert!(
            stdout_of(&output).contains(&run),
            "{args:?}: {}",
            stdout_of(&output)
        );
    }
}

#[test]
fn json_output_agrees_with_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_report(dir.path(), &report());
    let (run, result) = library_digest(report().as_bytes());

    let output = gitiup(&["digest", "--json", path.to_str().unwrap()], None);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout_of(&output)).unwrap();
    assert_eq!(parsed["run_digest"], run);
    assert_eq!(parsed["result_digest"], result);
    assert_eq!(parsed["tier"], "local");
    assert_eq!(parsed["steps"], 2);
    assert_eq!(parsed["workflow"], ".github/workflows/ci.yml");
}

#[test]
fn quiet_prints_the_run_digest_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_report(dir.path(), &report());
    let (run, result) = library_digest(report().as_bytes());
    let output = gitiup(&["digest", "--quiet", path.to_str().unwrap()], None);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    assert_eq!(stdout_of(&output).trim(), run);
    assert!(!stdout_of(&output).contains(&result));
}

#[test]
fn expect_is_the_reproducibility_check_and_exit_8_is_a_disagreement() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_report(dir.path(), &report());
    let (run, result) = library_digest(report().as_bytes());

    let ok = gitiup(&["digest", "--expect", &run, path.to_str().unwrap()], None);
    assert_eq!(code(&ok), 0, "{}", stderr_of(&ok));

    let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let bad = gitiup(&["digest", "--expect", wrong, path.to_str().unwrap()], None);
    assert_eq!(code(&bad), 8, "a rerun that disagrees is a digest mismatch");
    assert!(
        stderr_of(&bad).contains("expected RunDigest"),
        "{}",
        stderr_of(&bad)
    );

    assert_eq!(
        code(&gitiup(
            &["digest", "--expect-result", &result, path.to_str().unwrap()],
            None
        )),
        0
    );
    assert_eq!(
        code(&gitiup(
            &["digest", "--expect-result", wrong, path.to_str().unwrap()],
            None
        )),
        8
    );
}

#[test]
fn failures_use_the_documented_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.json");
    assert_eq!(
        code(&gitiup(&["digest", missing.to_str().unwrap()], None)),
        3,
        "I/O is 3"
    );

    let broken = write_report(dir.path(), "{\"commit\":\"sha1:00\"}");
    let output = gitiup(&["digest", broken.to_str().unwrap()], None);
    assert_eq!(code(&output), 6, "an invalid report is 6");
    assert!(
        stderr_of(&output).starts_with("gitiup:"),
        "{}",
        stderr_of(&output)
    );

    // An empty stdin is a usage mistake, not an invalid document.
    assert_eq!(code(&gitiup(&["digest"], Some("   \n"))), 2);

    assert_eq!(code(&gitiup(&["digest", "--not-a-flag"], Some("{}"))), 2);
    assert_eq!(code(&gitiup(&["fly"], None)), 2);
}

#[test]
fn help_and_version_are_exit_zero() {
    for args in [
        vec![],
        vec!["help"],
        vec!["--help"],
        vec!["digest", "--help"],
        vec!["version"],
    ] {
        let output = gitiup(&args, None);
        assert_eq!(code(&output), 0, "{args:?}");
        assert!(!output.stdout.is_empty(), "{args:?} printed nothing");
    }
    let version = stdout_of(&gitiup(&["version"], None));
    assert!(version.contains(env!("CARGO_PKG_VERSION")), "{version}");
}

#[test]
fn the_cli_prints_the_digest_of_the_committed_fixture() {
    // The golden vectors are the contract; this says the *command* prints them,
    // not only the library function behind it.
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../gitiup-attest/tests/fixtures/runs");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("cases.json")).unwrap()).unwrap();
    for case in index["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let report = fixtures.join(name).join("run.json");
        let output = gitiup(&["digest", "--json", report.to_str().unwrap()], None);
        assert_eq!(code(&output), 0, "{name}: {}", stderr_of(&output));
        let parsed: serde_json::Value = serde_json::from_str(&stdout_of(&output)).unwrap();
        assert_eq!(
            parsed["run_digest"],
            case["run_digest"].as_str().unwrap(),
            "{name}: gitiup digest disagrees with the golden RunDigest"
        );
        assert_eq!(
            parsed["result_digest"],
            case["result_digest"].as_str().unwrap(),
            "{name}: gitiup digest disagrees with the golden ResultDigest"
        );
    }
}

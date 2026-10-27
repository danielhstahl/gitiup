//! End-to-end tests for `gitiup normalise` — the acceptance surface of giti-1rs.3.
//!
//! The library tests in `gitiup-normalise` prove the rules; these prove the
//! *command* answers the two questions a reproducibility failure actually poses:
//! what was rewritten, and whether two runs converged. Exit codes follow the same
//! table as `gitiup digest`, because a merge gate must only branch once.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::run::RunReport;
use gitiup_normalise::manifest_for;

fn gitiup(args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
    command.args(args);
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

fn corpus(machine: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../gitiup-normalise/tests/fixtures/corpus")
        .join(machine)
        .join("run.json")
}

fn expected() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../gitiup-normalise/tests/fixtures/corpus/expected.json");
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn report_at(path: &Path) -> RunReport {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn one_run_reports_what_was_rewritten() {
    let output = gitiup(&["normalise", corpus("machine-a").to_str().unwrap()], None);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.contains("profile        repro v1"), "{text}");
    assert!(
        text.contains(&format!(
            "result         {}",
            expected()["result_digest"].as_str().unwrap()
        )),
        "the command must print the converged digest: {text}"
    );
    assert!(text.contains("identity     line 1"), "{text}");
    assert!(text.contains("+ <user>@<host>:~$"), "{text}");
    assert!(text.contains("<dur>"), "{text}");
}

#[test]
fn json_output_is_sorted_and_agrees_with_the_library() {
    let path = corpus("machine-b");
    let output = gitiup(&["normalise", "--json", path.to_str().unwrap()], None);
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(
        text.starts_with(r#"{"diffs":"#),
        "keys are sorted so a script can diff the output: {text}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    let library = manifest_for(&report_at(&path)).unwrap();
    assert_eq!(
        parsed["result_digest"].as_str().unwrap(),
        library.manifest.result_digest().unwrap().to_string(),
        "the command and the library must not have two ideas of the digest"
    );
    assert_eq!(parsed["profile"].as_str().unwrap(), "repro");
    assert_eq!(parsed["normalisation_version"].as_u64().unwrap(), 1);
    let rewrites = parsed["rewrites"].as_array().unwrap();
    let expected_count: usize = library
        .records
        .iter()
        .map(|(_, _, record)| record.items().len())
        .sum();
    assert_eq!(rewrites.len(), expected_count);
    let first = &rewrites[0];
    for key in ["step", "stream", "kind", "line", "before", "after"] {
        assert!(first.get(key).is_some(), "{first}");
    }
    assert_eq!(
        parsed["diffs"].as_array().unwrap().len(),
        library.diffs.len(),
        "the aggregated record is the one the manifest carries"
    );
}

#[test]
fn two_machines_converge_and_the_command_says_so() {
    let output = gitiup(
        &[
            "normalise",
            corpus("machine-a").to_str().unwrap(),
            "--compare",
            corpus("machine-b").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(text.starts_with("converged      yes"), "{text}");
    assert!(
        text.contains(&expected()["result_digest"].as_str().unwrap().to_string()),
        "{text}"
    );
}

#[test]
fn a_real_divergence_is_exit_8_and_names_step_field_and_both_sides() {
    let dir = tempfile::tempdir().unwrap();
    let mut broken: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus("machine-b")).unwrap()).unwrap();
    let step = &mut broken["steps"][2];
    step["exit_code"] = serde_json::Value::from(101);
    let text = step["stdout"]["text"].as_str().unwrap().to_string();
    step["stdout"]["text"] = serde_json::Value::String(text.replace("118 passed", "117 passed"));
    let path = dir.path().join("broken.json");
    std::fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();

    let output = gitiup(
        &[
            "normalise",
            path.to_str().unwrap(),
            "--compare",
            corpus("machine-a").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        code(&output),
        8,
        "divergence is ADR-0001 D7's mismatch code"
    );
    let stdout = stdout_of(&output);
    assert!(stdout.starts_with("converged      no"), "{stdout}");
    assert!(stdout.contains("test             exit-code"), "{stdout}");
    assert!(
        stdout.contains("- 101") && stdout.contains("+ 0"),
        "{stdout}"
    );
    assert!(
        stdout.contains("line 1: test result: ok. 117 passed"),
        "the log line is quoted with its number: {stdout}"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.starts_with("gitiup: normalise: test exit-code"),
        "{stderr}"
    );
    assert!(stderr.contains("hint:"), "{stderr}");

    // The machine-readable form carries the same divergences.
    let output = gitiup(
        &[
            "normalise",
            "--json",
            path.to_str().unwrap(),
            "--compare",
            corpus("machine-a").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&output), 8);
    let parsed: serde_json::Value = serde_json::from_str(&stdout_of(&output)).unwrap();
    assert_eq!(parsed["converged"], serde_json::Value::Bool(false));
    assert!(
        parsed["divergences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diff| diff["kind"] == "exit-code" && diff["step"] == "test"),
        "{parsed}"
    );
}

#[test]
fn rules_are_selectable_and_a_typo_is_a_usage_error() {
    let full = gitiup(&["normalise", corpus("machine-a").to_str().unwrap()], None);
    let one_rule = gitiup(
        &[
            "normalise",
            "--rules",
            "timestamp",
            corpus("machine-a").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&one_rule), 0, "{}", stderr_of(&one_rule));
    let text = stdout_of(&one_rule);
    assert!(
        text.contains("restricted rule set: not a standard normalisation"),
        "a non-standard rule set must not look like the profile: {text}"
    );
    assert!(!text.contains("<dur>"), "the duration rule is off: {text}");
    assert!(
        text.len() < stdout_of(&full).len(),
        "one rule cannot rewrite more than all of them"
    );

    let bad = gitiup(
        &[
            "normalise",
            "--rules",
            "timestamps",
            corpus("machine-a").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&bad), 2);
    assert!(
        stderr_of(&bad).contains("line-ending, ansi, progress"),
        "a refused rule name must say what the names are: {}",
        stderr_of(&bad)
    );
}

#[test]
fn text_prints_the_normalised_stream() {
    let output = gitiup(
        &[
            "normalise",
            "--text",
            "--rules",
            "timestamp",
            corpus("machine-a").to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&output), 0, "{}", stderr_of(&output));
    let text = stdout_of(&output);
    assert!(
        text.contains("--- checkout stdout (normalised) ---"),
        "{text}"
    );
    assert!(text.contains("[<ts>] Syncing"), "{text}");
    assert!(
        !text.contains("2026-10-27T09:11:12.481392Z\n"),
        "the timestamp is gone from the text that gets hashed: {text}"
    );
}

#[test]
fn expect_result_is_a_check_on_one_run() {
    let digest = expected()["result_digest"].as_str().unwrap().to_string();
    let path = corpus("machine-b");
    assert_eq!(
        code(&gitiup(
            &[
                "normalise",
                "--expect-result",
                &digest,
                path.to_str().unwrap()
            ],
            None
        )),
        0
    );
    let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let output = gitiup(
        &[
            "normalise",
            "--expect-result",
            wrong,
            path.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&output), 8, "{}", stdout_of(&output));
    assert!(stderr_of(&output).contains("expected ResultDigest"));
}

#[test]
fn exit_codes_follow_the_table() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        code(&gitiup(
            &["normalise", dir.path().join("nope.json").to_str().unwrap()],
            None
        )),
        3,
        "I/O is 3"
    );
    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, "{\"commit\":\"sha1:00\"}").unwrap();
    assert_eq!(
        code(&gitiup(&["normalise", broken.to_str().unwrap()], None)),
        6,
        "an invalid report is 6"
    );
    assert_eq!(code(&gitiup(&["normalise", "--not-a-flag"], Some("{}"))), 2);
    // Two positional reports are almost always someone meaning --compare.
    let two = gitiup(&["normalise", "a.json", "b.json"], None);
    assert_eq!(code(&two), 2);
    assert!(stderr_of(&two).contains("--compare"), "{}", stderr_of(&two));
    assert_eq!(code(&gitiup(&["normalise"], Some("   \n"))), 2);
    assert_eq!(code(&gitiup(&["normalise", "--help"], None)), 0);
    assert!(stdout_of(&gitiup(&["normalise", "--help"], None)).contains("RULES:"));
    // A report from stdin works like every other command.
    let report = std::fs::read_to_string(corpus("machine-a")).unwrap();
    assert_eq!(code(&gitiup(&["normalise", "-"], Some(&report))), 0);
}

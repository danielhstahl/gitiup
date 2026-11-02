//! `gitiup run --engine act` (giti-ic0, ADR-0006).
//!
//! The engine is act's; the *contract* is gitiup's, and this file tests the contract
//! against the real binary with a stub act: the same `--version` line, the same
//! `--json` log, the same exit code. What is being checked is what a stranger would
//! rely on —
//!
//! * the engine is chosen by name and never guessed, and every mistake on the way to
//!   choosing it is a refusal that says what to type instead;
//! * a run that happened says `sandbox: act`, and the checks printed under it say who
//!   actually observed what;
//! * a step act called failed exits this command 10, with act's own output printed;
//! * **keeping** the attestation (`--out`) needs a policy that has named `act`, because
//!   the containment was act's and the built-in policy has never heard of it;
//! * secrets never reach argv, and a missing one is a refusal before anything spawns.

use std::path::Path;
use std::process::{Command, Output};

/// The workflow these tests run: a `uses:` step, which the gitiup engine refuses and
/// act exists to run.
const CI: &str = "\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Test
        run: make test
";

/// The step lines of a passing act run, in act 0.2.94's own JSON shape.
const LOG_OK: &str = "\
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | Checking out the repository\",\"step\":\"Checkout\",\"stepid\":[\"co\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Checkout\",\"step\":\"Checkout\",\"stepResult\":\"success\",\"executionTime\":\"1.2s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | make test\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Test\",\"step\":\"Test\",\"stepResult\":\"success\",\"executionTime\":\"2s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"success\",\"level\":\"info\",\"matrix\":{},\"msg\":\"Job succeeded\"}
";

/// The same job with `Test` failing: act echoes `exit status N` in the step's own
/// stream and closes it with `stepResult: failure`.
const LOG_FAIL: &str = "\
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Checkout\",\"step\":\"Checkout\",\"stepResult\":\"success\",\"executionTime\":\"1.2s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"error\",\"matrix\":{},\"msg\":\"  | the compiler said no\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"error\",\"matrix\":{},\"msg\":\"  | exit status 7\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u274c  Failure - Test\",\"step\":\"Test\",\"stepResult\":\"failure\",\"executionTime\":\"2s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"failure\",\"level\":\"info\",\"matrix\":{},\"msg\":\"Job failed\"}
";

/// A workspace with the workflow, a git HEAD, and a stub `act` that replays `log`.
fn workspace(log: &str, exit: i32) -> (tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workflows = dir.path().join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(workflows.join("ci.yml"), CI).unwrap();
    std::fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
    std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        dir.path().join(".git/refs/heads/main"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();
    let bin = tempfile::tempdir().expect("tempdir for the stub binary");
    let transcript = bin.path().join("transcript.json");
    std::fs::write(&transcript, log).unwrap();
    let act = bin.path().join("act");
    // Every argv the stub is called with is recorded here, so a test can check what
    // gitiup actually put on a command line rather than trusting a comment about it.
    let trace = dir.path().join("argv.txt");
    std::fs::write(
        &act,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\nif [ \"$1\" = \"--version\" ]; then echo 'act version 0.2.94'; exit 0; fi\ncat '{}'\nexit {exit}\n",
            trace.display(),
            transcript.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&act, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, bin)
}

/// Run the built binary in `dir`; the same cleared, pinned environment `run_cli.rs`
/// uses, plus the stub engine.
fn gitiup(dir: &Path, args: &[&str], extra: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
    command
        .current_dir(dir)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("SOURCE_DATE_EPOCH", "1793092502")
        .env(
            "GITIUP_COMMIT",
            "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    for (key, value) in extra {
        if value.is_empty() {
            command.env_remove(key);
        } else {
            command.env(key, value);
        }
    }
    command
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the binary builds and runs")
}

fn out_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn err_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn all(output: &Output) -> String {
    format!("{}{}", out_text(output), err_text(output))
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

/// The engine flag every act test needs, plus the pinned image that stops act asking.
fn engine_args() -> Vec<&'static str> {
    vec![
        "--execute",
        "--engine",
        "act",
        "--act-image",
        "ubuntu-latest=cat-the-planet/base@sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]
}

#[test]
fn an_engine_is_named_and_never_guessed() {
    let (dir, _bin) = workspace(LOG_OK, 0);
    let stub = dir.path().join("nowhere");
    let cases: Vec<(Vec<&str>, i32, &str)> = vec![
        (
            vec!["run", "--engine", "act"],
            6,
            "act is an execution engine",
        ),
        (vec!["run", "--engine", "docker"], 2, "is not an engine"),
        (
            vec!["run", "--engine", "act", "--execute", "--sandbox", "docker"],
            6,
            "does not take a --sandbox",
        ),
        (
            vec!["run", "--act-image", "ubuntu-latest=x"],
            6,
            "was not asked for",
        ),
        (vec!["run", "--act-image", "nolabel"], 2, "not label=image"),
        (
            vec!["run", "--act-image", "ubuntu-latest="],
            2,
            "needs both a label and an image",
        ),
    ];
    for (args, want, needle) in cases {
        let output = gitiup(
            dir.path(),
            &args,
            &[("GITIUP_ACT", &stub.to_string_lossy())],
        );
        assert_eq!(code(&output), want, "{args:?}: {}", all(&output));
        assert!(
            all(&output).contains(needle),
            "{args:?} should say `{needle}`: {}",
            all(&output)
        );
    }
}

#[test]
fn an_absent_act_is_a_refusal_that_says_where_it_comes_from() {
    let (dir, _bin) = workspace(LOG_OK, 0);
    let missing = dir.path().join("no-act-here");
    let mut args = vec!["run"];
    args.extend(engine_args());
    let output = gitiup(
        dir.path(),
        &args,
        &[("GITIUP_ACT", &missing.to_string_lossy())],
    );
    assert_eq!(code(&output), 6, "{}", all(&output));
    let text = all(&output);
    assert!(text.contains("act"), "{text}");
    assert!(
        text.contains("nektosact.com"),
        "the refusal names the engine's home: {text}"
    );
    assert!(
        text.contains("GITIUP_ACT"),
        "and how to point at one: {text}"
    );
}

#[test]
fn an_act_run_is_local_and_says_act_ran_it() {
    let (dir, bin) = workspace(LOG_OK, 0);
    let act = bin.path().join("act");
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    let output = gitiup(
        dir.path(),
        &args,
        &[
            ("GITIUP_ACT", &act.to_string_lossy()),
            ("GITIUP_ENV_PROBE", "off"),
        ],
    );
    let text = all(&output);
    assert_eq!(code(&output), 0, "{text}");
    assert!(text.contains("ran job build in act"), "{text}");
    assert!(text.contains("sandbox        act"), "{text}");
    assert!(text.contains("tier           local"), "{text}");
    assert!(text.contains("1. Checkout"), "{text}");
    assert!(text.contains("2. Test"), "{text}");
    // The producer's own sums name the engine, and say what gitiup did *not* probe.
    assert!(text.contains("engine       act 0.2.94"), "{text}");
    assert!(text.contains("probed none"), "{text}");
    // And the note about the policy it would have to satisfy, because nothing was filed.
    assert!(text.contains("sandbox: act"), "{text}");
}

#[test]
fn a_failing_step_exits_ten_and_prints_what_act_saw() {
    let (dir, bin) = workspace(LOG_FAIL, 1);
    let act = bin.path().join("act");
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    let output = gitiup(
        dir.path(),
        &args,
        &[
            ("GITIUP_ACT", &act.to_string_lossy()),
            ("GITIUP_ENV_PROBE", "off"),
        ],
    );
    let text = all(&output);
    assert_eq!(code(&output), 10, "{text}");
    assert!(text.contains("FAILED"), "{text}");
    assert!(
        text.contains("exit 7"),
        "act's number, not a made-up one: {text}"
    );
    assert!(
        text.contains("the compiler said no"),
        "act's own log is the only copy of this output: {text}"
    );
}

#[test]
fn keeping_an_act_attestation_needs_a_policy_that_named_act() {
    let (dir, bin) = workspace(LOG_OK, 0);
    let act = bin.path().join("act");
    let act_path = act.to_string_lossy().to_string();
    let env = [
        ("GITIUP_ACT", act_path.as_str()),
        ("GITIUP_ENV_PROBE", "off"),
    ];

    // The default policy allows `local` and names no sandbox — which is precisely the
    // policy that must not swallow an act run.
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    args.extend(["-o", "attestation.json"]);
    let output = gitiup(dir.path(), &args, &env);
    let text = all(&output);
    assert_eq!(code(&output), 6, "{text}");
    assert!(text.contains("sandbox: act"), "{text}");
    assert!(
        text.contains("allowed_sandboxes"),
        "the refusal has to say what to write: {text}"
    );
    assert!(
        !dir.path().join("attestation.json").exists(),
        "a refused attestation was written anyway"
    );

    // A policy that names it is the owner deciding to accept act's containment.
    std::fs::write(
        dir.path().join("policy.json"),
        "{\n  \"allowed_tiers\": [\"local\"],\n  \"allowed_sandboxes\": [\"act\"]\n}\n",
    )
    .unwrap();
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    args.extend(["-o", "attestation.json", "--policy", "policy.json"]);
    let output = gitiup(dir.path(), &args, &env);
    let text = all(&output);
    assert_eq!(code(&output), 0, "{text}");
    let written = std::fs::read_to_string(dir.path().join("attestation.json")).unwrap();
    assert!(
        written.contains("\"sandbox\":\"act\"") || written.contains("\"sandbox\": \"act\""),
        "{written}"
    );
    assert!(written.contains("x_engine_version"), "{written}");
    assert!(
        written.contains("\"runner\":\"act 0.2.94\"")
            || written.contains("\"runner\": \"act 0.2.94\""),
        "{written}"
    );
}

#[test]
fn a_secret_is_a_name_in_argv_and_a_value_only_in_the_environment() {
    let (dir, bin) = workspace(LOG_OK, 0);
    let act = bin.path().join("act");
    let trace = dir.path().join("argv.txt");
    // The stub records the argv it was given, so the claim under test — that a secret
    // reaches act as a *name* — is checked against the bytes, not against a comment.
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    args.extend(["--secret", "MY_TOKEN"]);
    let output = gitiup(
        dir.path(),
        &args,
        &[
            ("GITIUP_ACT", &act.to_string_lossy()),
            ("GITIUP_ENV_PROBE", "off"),
            ("MY_TOKEN", "a-value-nobody-must-see-in-argv"),
        ],
    );
    let text = all(&output);
    assert_eq!(code(&output), 0, "{text}");
    let argv = std::fs::read_to_string(&trace).expect("the stub recorded its argv");
    assert!(argv.contains("-s\nMY_TOKEN\n"), "{argv}");
    assert!(
        !argv.contains("a-value-nobody-must-see-in-argv"),
        "a secret value reached act's argv: {argv}"
    );
    // And a named secret that is not in the environment is a refusal, not a step that
    // ran without it.
    let mut args = vec!["run", "--job", "build"];
    args.extend(engine_args());
    args.extend(["--secret", "MY_ABSENT_TOKEN"]);
    let output = gitiup(
        dir.path(),
        &args,
        &[
            ("GITIUP_ACT", &act.to_string_lossy()),
            ("GITIUP_ENV_PROBE", "off"),
            ("MY_ABSENT_TOKEN", ""),
        ],
    );
    assert_eq!(code(&output), 6, "{}", all(&output));
    assert!(
        all(&output).contains("MY_ABSENT_TOKEN"),
        "the refusal names the secret that was missing: {}",
        all(&output)
    );
}

#[test]
fn the_engine_is_listed_where_a_typist_looks() {
    let output = gitiup(Path::new("."), &["run", "--sandboxes"], &[]);
    assert_eq!(code(&output), 0);
    let text = out_text(&output);
    assert!(
        text.contains("engines this build can hand a job to:"),
        "{text}"
    );
    assert!(text.contains("gitiup"), "{text}");
    assert!(text.contains("act"), "{text}");
    assert!(text.contains("docs/act.md"), "{text}");
}

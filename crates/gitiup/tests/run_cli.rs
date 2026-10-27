//! End-to-end tests for `gitiup run` — the command line the ticket is written in.
//!
//! The acceptance criteria are behavioural, so they are tested behaviourally against
//! the real binary:
//!
//! * a plain run **plans** and touches nothing: no file is created, the attestation
//!   says `simulated`, and the warning is loud;
//! * the same plan hashes the same twice, and differently when the plan changes;
//! * `--execute` is refused unless a real sandbox is available, and `--sandbox none`
//!   is refused outright;
//! * keeping an attestation (`--out`) or asking for a gate (`--policy`) runs the
//!   policy, and the default policy refuses a simulated attestation;
//! * ambiguity is refused rather than guessed, and the refusal names the options.
//!
//! Everything runs in a temporary directory with a pinned clock and run id, so a
//! failure here is about behaviour and not about the weather.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Run the built binary in `dir`, with a clean, pinned environment.
fn gitiup(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
    command
        .current_dir(dir)
        .args(args)
        // Cleared, then set: the assertions below are about this run's flags, not
        // about whatever the CI machine happened to export.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("SOURCE_DATE_EPOCH", "1793092502")
        .env(
            "GITIUP_COMMIT",
            "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    for (key, value) in env {
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

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

const CI: &str = "\
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: Build
        run: cargo build --release
";

const MATRIX_CI: &str = "\
on:
  push:
jobs:
  build:
    strategy:
      matrix:
        os: [linux, macos]
    steps:
      - name: Test
        run: cargo test --target ${{ matrix.os }}
";

const TWO_JOBS: &str = "\
on: push
jobs:
  build:
    steps:
      - run: cargo build
  deploy:
    steps:
      - run: ./deploy.sh
";

/// A workspace with one workflow file and a `.git` that knows its HEAD.
fn workspace(workflow: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    std::fs::write(dir.path().join(".github/workflows/ci.yml"), workflow).unwrap();
    std::fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
    std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        dir.path().join(".git/refs/heads/main"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();
    dir
}

/// Every path under `root`, to prove nothing was written.
fn listing(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                paths.push(path.clone());
                stack.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

/// The value of a `key            value` line from the text output.
fn field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find(|line| line.starts_with(key))
        .map(|line| line[key.len()..].trim().to_string())
}

#[test]
fn a_plain_run_plans_and_writes_nothing_at_all() {
    let dir = workspace(CI);
    let before = listing(dir.path());
    let output = gitiup(dir.path(), &["run"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let stdout = out_text(&output);
    let stderr = err_text(&output);

    // The plan itself: which job, which steps, in order.
    assert!(stdout.contains("Build"), "{stdout}");
    assert!(stdout.contains("cargo build --release"), "{stdout}");
    assert_eq!(field(&stdout, "tier").as_deref(), Some("simulated"));
    assert!(
        stdout.contains("result         sha256:"),
        "a plan is attestable: {stdout}"
    );
    // The loud warning, on stderr so `--json` stays machine-readable.
    assert!(stderr.contains("WARNING"), "{stderr}");
    assert!(stderr.contains("SIMULATED"), "{stderr}");
    assert!(
        stderr.contains("--execute"),
        "and it says what to do instead: {stderr}"
    );

    // The whole point: the default run leaves no trace.
    assert_eq!(before, listing(dir.path()), "a plain run wrote something");
}

#[test]
fn the_json_is_a_canonical_manifest_and_says_simulated_with_no_sandbox() {
    let dir = workspace(CI);
    let output = gitiup(dir.path(), &["run", "--json"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let manifest: serde_json::Value =
        serde_json::from_str(&out_text(&output)).expect("--json prints a manifest that parses");
    let provenance = &manifest["result"]["provenance"];
    assert_eq!(provenance["tier"], "simulated");
    assert_eq!(provenance["sandbox"], "none");
    assert_eq!(manifest["result"]["environment"]["provider"], "simulated");
    assert_eq!(manifest["result"]["source"]["job"], "build");
    assert_eq!(
        manifest["result"]["source"]["commit"],
        "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    // The secret fields are absent, not empty: there is nothing to put in them.
    assert!(
        manifest["result"].get("secret_names").is_none(),
        "{manifest}"
    );
    // And the text output's digests are this document's, not a different rendering.
    let text = gitiup(dir.path(), &["run"], &[]);
    let manifest_digest = gitiup_attest::Digest::sha256(out_text(&output).as_bytes()).to_string();
    assert_eq!(
        field(&out_text(&text), "run").as_deref(),
        Some(manifest_digest.as_str()),
        "`run` must be sha256 of exactly these bytes"
    );
}

#[test]
fn the_same_plan_hashes_the_same_and_a_different_plan_does_not() {
    let dir = workspace(CI);
    let first = gitiup(dir.path(), &["run", "--json"], &[]);
    let second = gitiup(dir.path(), &["run", "--json"], &[]);
    assert_eq!(
        out_text(&first),
        out_text(&second),
        "two runs of the same plan must agree, or the digest proves nothing"
    );

    std::fs::write(
        dir.path().join(".github/workflows/ci.yml"),
        CI.replace("cargo build --release", "cargo build"),
    )
    .unwrap();
    let changed = gitiup(dir.path(), &["run", "--json"], &[]);
    assert_ne!(
        out_text(&first),
        out_text(&changed),
        "the plan changed and the digest did not: the tier text is decorative"
    );
}

#[test]
fn the_digest_of_a_pinned_plan_is_a_known_answer() {
    // The plan in `CI`, pinned to this commit, this clock and this run id. If this
    // moves, every plan attested before the change stops reproducing, which is a
    // bigger deal than whatever caused it.
    let dir = workspace(CI);
    let output = gitiup(
        dir.path(),
        &["run", "--run-id", "0123456789abcdef", "--json"],
        &[],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let manifest: serde_json::Value = serde_json::from_str(&out_text(&output)).unwrap();
    let digest = gitiup_attest::Digest::sha256(out_text(&output).as_bytes());
    let _ = manifest;
    assert_eq!(
        digest.to_string(),
        "sha256:46a9e4d3edd54774d028046eb6c6252048d95dd586f184f7561bf8deceb15499",
        "the RunDigest of this exact plan"
    );
}

#[test]
fn execute_needs_a_sandbox_that_exists_and_refuses_the_absence_of_one() {
    let dir = workspace(CI);
    let before = listing(dir.path());

    // The most important refusal in the command: "no sandbox" is not a tier.
    let output = gitiup(dir.path(), &["run", "--execute", "--sandbox", "none"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("unconfined"),
        "{}",
        err_text(&output)
    );

    // A backend the ecosystem has and this build does not is named, not faked.
    let output = gitiup(
        dir.path(),
        &["run", "--execute", "--sandbox", "docker"],
        &[],
    );
    assert_eq!(code(&output), 6);
    assert!(
        err_text(&output).contains("not built into this build"),
        "{}",
        err_text(&output)
    );

    // A backend nobody heard of, ditto.
    let output = gitiup(dir.path(), &["run", "--execute", "--sandbox", "kvm"], &[]);
    assert_eq!(code(&output), 6);
    assert!(err_text(&output).contains("kvm"), "{}", err_text(&output));

    // The one real backend: either this machine can do it — and then the run is
    // `local` — or it says so and offers the plan instead. Both are correct answers;
    // silently claiming `local` without running anything is the only wrong one.
    let output = gitiup(dir.path(), &["run", "--execute"], &[]);
    match code(&output) {
        0 => {
            assert!(
                out_text(&output).contains("ran job build"),
                "{}",
                out_text(&output)
            );
            assert_eq!(field(&out_text(&output), "tier").as_deref(), Some("local"));
        }
        6 => {
            let stderr = err_text(&output);
            assert!(stderr.contains("sandbox"), "{stderr}");
            assert!(
                stderr.contains("simulate") || stderr.contains("simulat"),
                "{stderr}"
            );
        }
        other => panic!("unexpected exit code {other}: {}", err_text(&output)),
    }
    // Whichever way that went, nothing was written: execution writes only when asked.
    assert_eq!(listing(dir.path()), before, "{:?}", listing(dir.path()));
}

#[test]
fn a_matrix_job_is_pinned_or_refused_with_the_choices() {
    let dir = workspace(MATRIX_CI);
    let output = gitiup(dir.path(), &["run"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    let stderr = err_text(&output);
    assert!(
        stderr.contains("linux") && stderr.contains("macos"),
        "{stderr}"
    );

    let output = gitiup(dir.path(), &["run", "--matrix", "os=linux"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(
        out_text(&output).contains("os=linux"),
        "{}",
        out_text(&output)
    );

    let output = gitiup(dir.path(), &["run", "--matrix", "os=plan9"], &[]);
    assert_eq!(code(&output), 6);
    assert!(
        err_text(&output).contains("plan9"),
        "the refusal should repeat what was asked: {}",
        err_text(&output)
    );
}

#[test]
fn one_attestation_is_one_job_so_two_jobs_need_naming() {
    let dir = workspace(TWO_JOBS);
    let output = gitiup(dir.path(), &["run"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("build") && err_text(&output).contains("deploy"),
        "{}",
        err_text(&output)
    );

    let output = gitiup(dir.path(), &["run", "deploy"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(
        out_text(&output).contains("deploy.sh"),
        "{}",
        out_text(&output)
    );
    assert!(
        !out_text(&output).contains("cargo build"),
        "{}",
        out_text(&output)
    );

    let output = gitiup(dir.path(), &["run", "nonsense"], &[]);
    assert_eq!(code(&output), 6);
}

#[test]
fn a_kept_attestation_is_gated_by_policy_and_the_default_refuses_a_plan() {
    let dir = workspace(CI);
    std::fs::write(
        dir.path().join("local-only.json"),
        "{\"allowed_tiers\":[\"local\"]}",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("plans-allowed.json"),
        "{\"allow_simulated\":true}",
    )
    .unwrap();

    // --out alone runs the gate, and the default policy has never heard of simulated
    // being good enough. Nothing is written, so there is nothing to mistake.
    let output = gitiup(dir.path(), &["run", "--out", "attestation.json"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("simulated"),
        "{}",
        err_text(&output)
    );
    assert!(!dir.path().join("attestation.json").exists());

    // An explicit local-only policy: same answer, said as a policy refusal.
    let output = gitiup(
        dir.path(),
        &[
            "run",
            "--policy",
            "local-only.json",
            "--out",
            "attestation.json",
        ],
        &[],
    );
    assert_eq!(code(&output), 6);
    assert!(!dir.path().join("attestation.json").exists());

    // A policy that deliberately accepts plans: written, and still warned about.
    let output = gitiup(
        dir.path(),
        &[
            "run",
            "--policy",
            "plans-allowed.json",
            "--out",
            "attestation.json",
        ],
        &[],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(dir.path().join("attestation.json").exists());
    assert!(
        err_text(&output).contains("WARNING"),
        "{}",
        err_text(&output)
    );

    // One attestation per file, and never by accident.
    let output = gitiup(
        dir.path(),
        &[
            "run",
            "--policy",
            "plans-allowed.json",
            "--out",
            "attestation.json",
        ],
        &[],
    );
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("--force"),
        "{}",
        err_text(&output)
    );
    let output = gitiup(
        dir.path(),
        &[
            "run",
            "--policy",
            "plans-allowed.json",
            "--out",
            "attestation.json",
            "--force",
        ],
        &[],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
}

#[test]
fn a_policy_can_be_named_by_environment_too() {
    let dir = workspace(CI);
    std::fs::write(dir.path().join("p.json"), "{\"allow_simulated\":true}").unwrap();
    let output = gitiup(
        dir.path(),
        &["run", "--out", "attestation.json"],
        &[("GITIUP_POLICY", "p.json")],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(dir.path().join("attestation.json").exists());
}

#[test]
fn quorum_is_not_something_this_command_can_offer() {
    let dir = workspace(CI);
    // No flag for it, and the refusal says why.
    let output = gitiup(dir.path(), &["run", "--tier", "quorum"], &[]);
    assert_eq!(code(&output), 2);
    assert!(err_text(&output).contains("quorum") || out_text(&output).contains("quorum"));

    // A policy that demands quorum is a legitimate policy — and a single run can
    // never satisfy it, which is the point.
    std::fs::write(
        dir.path().join("quorum.json"),
        "{\"allowed_tiers\":[\"quorum\"]}",
    )
    .unwrap();
    let output = gitiup(dir.path(), &["run", "--policy", "quorum.json"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
}

#[test]
fn a_secret_named_without_execute_is_refused_not_ignored() {
    let dir = workspace(CI);
    let output = gitiup(dir.path(), &["run", "--secret", "NPM_TOKEN"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("NPM_TOKEN"),
        "{}",
        err_text(&output)
    );
    assert!(
        err_text(&output).contains("--execute"),
        "{}",
        err_text(&output)
    );
}

#[test]
fn what_the_planner_cannot_model_is_said_out_loud() {
    let dir = workspace(
        "on: push\njobs:\n  build:\n    services:\n      postgres: {image: postgres}\n    steps:\n      - run: psql --version\n",
    );
    let output = gitiup(dir.path(), &["run"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    // Either on stdout or stderr, but never silently dropped.
    let both = format!("{}{}", out_text(&output), err_text(&output));
    assert!(both.contains("services"), "{both}");
}

#[test]
fn the_sandboxes_on_offer_are_reported_with_why() {
    let dir = workspace(CI);
    let output = gitiup(dir.path(), &["run", "--sandboxes"], &[]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let stdout = out_text(&output);
    assert!(stdout.contains("unshare"), "{stdout}");
    assert!(
        stdout.contains("available") || stdout.contains("unavailable"),
        "{stdout}"
    );
}

#[test]
fn a_run_needs_to_know_which_commit_it_describes() {
    let dir = workspace(CI);
    std::fs::remove_dir_all(dir.path().join(".git")).unwrap();
    // No .git, and the environment says nothing either.
    let output = gitiup(
        dir.path(),
        &["run"],
        &[("GITIUP_COMMIT", ""), ("GITHUB_SHA", "")],
    );
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("commit"),
        "{}",
        err_text(&output)
    );

    // Saying it explicitly works, and the attestation names it.
    let output = gitiup(
        dir.path(),
        &["run", "--commit", &format!("sha1:{}", "b".repeat(40))],
        &[("GITIUP_COMMIT", "")],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(
        out_text(&output).contains(&"b".repeat(40)),
        "{}",
        out_text(&output)
    );
}

#[test]
fn a_missing_workflow_is_io_and_an_ambiguous_one_is_a_refusal() {
    let dir = workspace(CI);
    let output = gitiup(dir.path(), &["run", "--workflow", "nope.yml"], &[]);
    assert_eq!(code(&output), 3, "{}", err_text(&output));

    std::fs::write(
        dir.path().join(".github/workflows/other.yml"),
        "on: push\njobs: {}\n",
    )
    .unwrap();
    let output = gitiup(dir.path(), &["run"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("--workflow"),
        "{}",
        err_text(&output)
    );
}

#[test]
fn usage_errors_are_exit_two_and_say_what_is_wrong() {
    let dir = workspace(CI);
    for args in [
        vec!["run", "--nonsense"],
        vec!["run", "--matrix", "no-equals-sign"],
        vec!["run", "one", "two"],
        vec!["run", "--out"],
    ] {
        let output = gitiup(dir.path(), &args, &[]);
        assert_eq!(code(&output), 2, "{args:?}: {}", err_text(&output));
        assert!(err_text(&output).starts_with("gitiup:"), "{args:?}");
    }
    let output = gitiup(dir.path(), &["run", "--help"], &[]);
    assert_eq!(code(&output), 0);
    assert!(out_text(&output).contains("THE DEFAULT SIMULATES"));
}

#[test]
fn a_replayed_plan_says_which_steps_came_from_a_recorded_run() {
    let dir = workspace(CI);
    // A recorded report from a real run: the step name matches the plan's.
    std::fs::write(
        dir.path().join("prior.json"),
        serde_json::json!({
            "commit": format!("sha1:{}", "a".repeat(40)),
            "workflow": {"path": ".github/workflows/ci.yml", "text": CI},
            "event": {"name": "pull_request", "payload": {"text": "{}"}},
            "job": "build",
            "environment": {"arch": "x86_64", "provider": "docker", "os": "linux"},
            "steps": [
                {"name": "Build", "exit_code": 0,
                 "stdout": {"text": "    Finished release profile\n"}}
            ],
            "provenance": {"tier": "local", "runner": "gitiup 0.1.0",
                           "normalisation_version": 0, "sandbox": "docker"},
            "claims": {"run_id": "0123456789abcdef", "claimed_at_us": 1793092502500000i64}
        })
        .to_string(),
    )
    .unwrap();

    let output = gitiup(
        dir.path(),
        &["run", "--replay-from", "prior.json", "--json"],
        &[],
    );
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let manifest: serde_json::Value = serde_json::from_str(&out_text(&output)).unwrap();
    // The tier did not move: reusing logs from a real run is still not running.
    assert_eq!(manifest["result"]["provenance"]["tier"], "simulated");
    let annotations = &manifest["claims"]["annotations"];
    assert_eq!(annotations["x_replayed_steps"], "Build", "{annotations}");
    assert!(annotations.get("x_replay_from").is_some(), "{annotations}");

    // A file that is not a run report is refused by name.
    std::fs::write(dir.path().join("junk.json"), "not json").unwrap();
    let output = gitiup(dir.path(), &["run", "--replay-from", "junk.json"], &[]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("junk.json"),
        "{}",
        err_text(&output)
    );
}

#[test]
fn a_job_needing_a_service_container_is_not_run_and_says_why() {
    let dir = workspace(
        "on: push\njobs:\n  db:\n    services:\n      postgres:\n        image: postgres:16\n    steps:\n      - name: Migrate\n        run: psql -f migrate.sql\n",
    );
    let output = gitiup(dir.path(), &["run"], &[]);
    // Planning it is fine — the plan says the service is assumed, and that this build
    // starts none of them.
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let both = format!("{}{}", out_text(&output), err_text(&output));
    assert!(both.contains("postgres"), "{both}");
    assert!(
        both.contains("--execute"),
        "the plan should say it will be refused: {both}"
    );

    // Executing it is refused whichever way the sandbox went: either the refusal for
    // services arrives first (exit 6), or this machine cannot sandbox at all (also 6).
    let output = gitiup(
        dir.path(),
        &["run", "--execute", "--sandbox", "unshare"],
        &[],
    );
    assert_eq!(code(&output), 6, "{}", out_text(&output));
}

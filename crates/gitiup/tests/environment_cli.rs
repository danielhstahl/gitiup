//! The environment fingerprint on the command line (giti-1rs.4).
//!
//! Three surfaces, one rule behind them:
//!
//! * `gitiup env` — what would a run here attest as, and does a published
//!   requirement accept it;
//! * `gitiup digest --require` / `--policy` — is *this run* the machine the change
//!   asked for, checked with exit 6 rather than with a digest nobody can diff;
//! * `gitiup run --policy` — the same gate applied to what the runner is about to
//!   produce, so a wrong machine is caught before anything is filed.
//!
//! The knob (`strict` / `major` / `off`) is exercised at this level too, because the
//! acceptance criterion is that the knob *works* — which means from a policy file,
//! through the binary, to an exit code.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Run the built binary in `dir`.
fn gitiup(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .current_dir(dir)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1793092502")
        .env(
            "GITIUP_COMMIT",
            "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        // The probe reads these; a caller's container or declared inventory would
        // otherwise decide what this machine claims.
        .env_remove("GITIUP_TOOLCHAIN")
        .env_remove("GITIUP_IMAGE_DIGEST")
        .stdin(Stdio::null())
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

/// A run report with a full environment: amd64, an image digest, a toolchain.
fn report(arch: &str, rustc: &str) -> String {
    format!(
        r#"{{
        "commit": "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "workflow": {{"path": ".github/workflows/ci.yml", "text": "on: push\n"}},
        "event": {{"name": "push", "payload": {{"text": "{{}}"}}}},
        "environment": {{"arch": "{arch}", "os": "linux", "os_version": "24.04",
                        "provider": "docker",
                        "image": {{"reference": "ghcr.io/gitiup/ci:ubuntu-24.04",
                                    "digest": "sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54"}},
                        "toolchain": [{{"name": "rustc", "version": "{rustc}"}}]}},
        "steps": [
            {{"id": "test", "name": "cargo test", "exit_code": 0,
              "stdout": {{"text": "test result: ok. 42 passed\n"}}}}
        ],
        "provenance": {{"tier": "local", "runner": "gitiup 0.1.0", "normalisation_version": 0,
                       "sandbox": "docker"}},
        "claims": {{"run_id": "0123456789abcdef", "claimed_at_us": 1793092502500000}}
    }}"#
    )
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write");
    path
}

// ------------------------------------------------------------- gitiup env ---

#[test]
fn env_prints_the_machine_class_a_run_would_attest() {
    let dir = tempfile::tempdir().unwrap();
    let output = gitiup(dir.path(), &["env"]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let text = out_text(&output);
    for field in [
        "os ",
        &format!("arch           {}", std::env::consts::ARCH),
        "image          ",
        "toolchain      ",
        "runner         gitiup ",
        "fingerprint    sha256:",
        "requirement    none published",
    ] {
        assert!(text.contains(field), "{field} missing from:\n{text}");
    }
}

#[test]
fn env_json_is_machine_readable_and_agrees_with_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let output = gitiup(dir.path(), &["env", "--json"]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let parsed: serde_json::Value = serde_json::from_str(&out_text(&output)).unwrap();
    assert_eq!(parsed["arch"], std::env::consts::ARCH);
    let fingerprint = parsed["fingerprint"].as_str().unwrap();
    assert!(fingerprint.starts_with("sha256:") && fingerprint.len() == 71);
    assert!(parsed["toolchain"].is_array());
    assert!(parsed["requirement"].is_null(), "nothing was required");

    // The quiet form is the same fingerprint, for `$(gitiup env -q)`.
    let quiet = gitiup(dir.path(), &["env", "--quiet"]);
    assert_eq!(code(&quiet), 0, "{}", err_text(&quiet));
    assert_eq!(out_text(&quiet).trim(), fingerprint);
}

#[test]
fn env_checks_this_machine_against_a_requirement() {
    let dir = tempfile::tempdir().unwrap();
    let here = std::env::consts::ARCH;

    let ok = gitiup(dir.path(), &["env", "--require", &format!("arch={here}")]);
    assert_eq!(code(&ok), 0, "{}", err_text(&ok));
    assert!(
        out_text(&ok).contains("— matched"),
        "the match should be said: {}",
        out_text(&ok)
    );

    // The other architecture is refused, exit 6, and says both sides.
    let wanted = if here == "x86_64" { "aarch64" } else { "amd64" };
    let bad = gitiup(dir.path(), &["env", "--require", &format!("arch={wanted}")]);
    assert_eq!(code(&bad), 6, "{}", out_text(&bad));
    let both = format!("{}{}", out_text(&bad), err_text(&bad));
    assert!(both.contains(wanted) && both.contains(here), "{both}");
}

#[test]
fn env_reads_the_requirement_from_a_policy_file_and_refuses_an_oxymoron() {
    let dir = tempfile::tempdir().unwrap();
    let policy = write(
        dir.path(),
        "gitiup-policy.json",
        r#"{"require_arch": "sparc64", "require_env_match": "strict"}"#,
    );
    let output = gitiup(dir.path(), &["env", "--policy", policy.to_str().unwrap()]);
    assert_eq!(code(&output), 6, "{}", out_text(&output));
    assert!(
        err_text(&output).contains("sparc64"),
        "{}",
        err_text(&output)
    );

    // A requirement published while matching is off is a policy that argued with
    // itself, and both the file reader and the command line refuse it.
    let contradiction = write(
        dir.path(),
        "off.json",
        r#"{"require_arch": "amd64", "require_env_match": "off"}"#,
    );
    let output = gitiup(
        dir.path(),
        &["env", "--policy", contradiction.to_str().unwrap()],
    );
    assert_eq!(code(&output), 6, "{}", out_text(&output));

    // The knob on the command line, and an unknown one, are usage-shaped refusals.
    assert_eq!(
        code(&gitiup(
            dir.path(),
            &[
                "env",
                "--require",
                "arch=amd64",
                "--require-env-match",
                "strictish"
            ]
        )),
        6
    );
    assert_eq!(code(&gitiup(dir.path(), &["env", "--nope"])), 2);
    assert_eq!(code(&gitiup(dir.path(), &["env", "--help"])), 0);
}

#[test]
fn env_can_be_told_the_inventory_and_the_image_instead_of_guessing() {
    let dir = tempfile::tempdir().unwrap();
    // GITIUP_TOOLCHAIN replaces discovery: a hermetic build system that knows what
    // its steps saw says so, and the fingerprint becomes reproducible.
    let output = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .current_dir(dir.path())
        .args(["env", "--json"])
        .env("GITIUP_TOOLCHAIN", "rustc=1.99.1,make=4.3")
        .env(
            "GITIUP_IMAGE_DIGEST",
            "sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54",
        )
        .env("GITIUP_IMAGE_REFERENCE", "ghcr.io/gitiup/ci:ubuntu-24.04")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let parsed: serde_json::Value = serde_json::from_str(&out_text(&output)).unwrap();
    assert_eq!(parsed["toolchain"].as_array().unwrap().len(), 2, "{parsed}");
    assert_eq!(
        parsed["image_digest"],
        "sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54"
    );

    // And a requirement can be satisfied from that declaration alone.
    let ok = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .current_dir(dir.path())
        .args([
            "env",
            "--require",
            "toolchain:rustc=1.99",
            "--require-env-match",
            "major",
        ])
        .env("GITIUP_TOOLCHAIN", "rustc=1.99.1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&ok), 0, "{}", err_text(&ok));
}

// ----------------------------------------------------------- gitiup digest ---

#[test]
fn digest_refuses_the_wrong_architecture_as_policy_not_as_mystery() {
    let dir = tempfile::tempdir().unwrap();
    let amd = write(dir.path(), "amd.json", &report("x86_64", "1.99.1"));
    let arm = write(dir.path(), "arm.json", &report("aarch64", "1.99.1"));

    let ok = gitiup(
        dir.path(),
        &["digest", "--require", "arch=amd64", amd.to_str().unwrap()],
    );
    assert_eq!(code(&ok), 0, "{}", err_text(&ok));
    assert!(out_text(&ok).contains("requirement    arch=amd64 (strict)"));

    let bad = gitiup(
        dir.path(),
        &["digest", "--require", "arch=amd64", arm.to_str().unwrap()],
    );
    assert_eq!(code(&bad), 6, "a wrong machine is refused, not mismatched");
    let both = format!("{}{}", out_text(&bad), err_text(&bad));
    assert!(both.contains("aarch64") && both.contains("amd64"), "{both}");

    // `--require-env-match=off` with a requirement is the same oxymoron as in a file.
    assert_eq!(
        code(&gitiup(
            dir.path(),
            &[
                "digest",
                "--require",
                "arch=amd64",
                "--require-env-match",
                "off",
                amd.to_str().unwrap()
            ]
        )),
        6
    );
}

#[test]
fn digest_major_and_strict_disagree_about_a_patch_version() {
    let dir = tempfile::tempdir().unwrap();
    let report_path = write(dir.path(), "run.json", &report("x86_64", "1.99.1"));
    let policy = write(
        dir.path(),
        "gitiup-policy.json",
        r#"{"require_env_match": "major", "require_arch": "amd64", "require_toolchain": {"rustc": "1.99"}}"#,
    );
    let strict = write(
        dir.path(),
        "strict.json",
        r#"{"require_env_match": "strict", "require_toolchain": {"rustc": "1.99"}}"#,
    );
    let report = report_path.to_str().unwrap();

    assert_eq!(
        code(&gitiup(
            dir.path(),
            &["digest", "--policy", policy.to_str().unwrap(), report]
        )),
        0,
        "major accepts a run whose rustc states more than the requirement does"
    );
    let bad = gitiup(
        dir.path(),
        &["digest", "--policy", strict.to_str().unwrap(), report],
    );
    assert_eq!(code(&bad), 6, "{}", out_text(&bad));
    assert!(
        err_text(&bad).contains("toolchain:rustc"),
        "{}",
        err_text(&bad)
    );
}

#[test]
fn digest_still_prints_the_environment_and_its_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "run.json", &report("x86_64", "1.99.1"));
    let output = gitiup(dir.path(), &["digest", path.to_str().unwrap()]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    let text = out_text(&output);
    assert!(
        text.contains("environment    x86_64 · fingerprint sha256:"),
        "{text}"
    );
    assert!(text.contains("image          sha256:3cafcfa8"), "{text}");
    assert!(text.contains("toolchain      rustc 1.99.1"), "{text}");

    let parsed: serde_json::Value = serde_json::from_str(&out_text(&gitiup(
        dir.path(),
        &["digest", "--json", path.to_str().unwrap()],
    )))
    .unwrap();
    assert_eq!(parsed["toolchain"], "rustc 1.99.1");
    assert!(
        parsed["image"]
            .as_str()
            .unwrap()
            .starts_with("sha256:3cafcfa8")
    );
}

// -------------------------------------------------------------- gitiup run ---

#[test]
fn a_plan_is_gated_by_the_machine_requirement_it_can_answer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    std::fs::write(
        dir.path().join(".github/workflows/ci.yml"),
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
    std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    std::fs::write(
        dir.path().join(".git/refs/heads/main"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    .unwrap();

    // A plan on the wrong architecture is refused before anything is kept, and the
    // fields a plan cannot honestly claim are named as skipped rather than passed.
    let wanted = if std::env::consts::ARCH == "x86_64" {
        "aarch64"
    } else {
        "amd64"
    };
    let policy = write(
        dir.path(),
        "gitiup-policy.json",
        &format!(
            "{{\"allow_simulated\": true, \"require_arch\": \"{wanted}\", \"require_toolchain\": {{\"rustc\": \"1.99\"}}}}"
        ),
    );
    let output = gitiup(dir.path(), &["run", "--policy", policy.to_str().unwrap()]);
    let both = format!("{}{}", out_text(&output), err_text(&output));
    assert!(both.contains("toolchain inventory"), "{both}");
    assert_eq!(code(&output), 6, "{both}");
    assert!(both.contains(wanted), "{both}");

    // Right architecture, toolchain requirement: the note says what was not checked,
    // and the plan is allowed.
    let here = std::env::consts::ARCH;
    let policy = write(
        dir.path(),
        "ok.json",
        &format!(
            "{{\"allow_simulated\": true, \"require_arch\": \"{here}\", \"require_toolchain\": {{\"rustc\": \"1.99\"}}}}"
        ),
    );
    let output = gitiup(dir.path(), &["run", "--policy", policy.to_str().unwrap()]);
    assert_eq!(code(&output), 0, "{}", err_text(&output));
    assert!(
        err_text(&output).contains("toolchain inventory"),
        "the skipped part must be said: {}",
        err_text(&output)
    );
}

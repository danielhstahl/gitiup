//! The command line: what each exit code means, and that `check` actually refuses.
//!
//! The exit codes are the interface here as everywhere else in this workspace — a CI
//! job reads the number, not the prose — so the numbers are asserted directly, and
//! both `0` and non-`0` cases are run through the real repository and a broken
//! fixture rather than a mocked filesystem.

mod common;

use common::{Fixture, repo_root};
use gitiup_site::cli::{EXIT_IO, EXIT_OK, EXIT_PROBLEM, EXIT_USAGE, run};

fn invoke(args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).to_string(),
        String::from_utf8_lossy(&err).to_string(),
    )
}

#[test]
fn help_and_version_are_free() {
    let (code, out, err) = invoke(&["help"]);
    assert_eq!(code, EXIT_OK);
    assert!(out.contains("USAGE"), "{out}");
    assert!(out.contains("--source-url"), "{out}");
    assert!(out.contains("EXIT CODES"), "{out}");
    assert!(err.is_empty(), "{err}");

    // No arguments at all is a request for help, not an error: the tool is a
    // one-liner and the flags are the thing worth seeing first.
    let (code, out, _) = invoke(&[]);
    assert_eq!(code, EXIT_OK);
    assert!(out.contains("gitiup-site <COMMAND>"));

    let (code, out, _) = invoke(&["version"]);
    assert_eq!(code, EXIT_OK);
    assert!(out.contains("gitiup-site 0."), "{out}");
}

#[test]
fn a_flag_that_does_not_exist_is_a_usage_error() {
    let (code, _, err) = invoke(&["build", "--themes", "midnight"]);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("unknown flag --themes"), "{err}");

    let (code, _, err) = invoke(&["build", "--out"]);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("--out needs a value"), "{err}");

    let (code, _, err) = invoke(&["build", "--quiet=1"]);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("takes no value"), "{err}");
}

#[test]
fn a_command_that_does_not_exist_is_a_usage_error() {
    let (code, _, err) = invoke(&["serve"]);
    assert_eq!(code, EXIT_USAGE);
    assert!(err.contains("unknown command `serve`"), "{err}");
    assert!(err.contains("run `gitiup-site help`"), "{err}");
}

#[test]
fn a_root_with_no_docs_is_a_usage_error_not_an_io_error() {
    let empty = tempfile::tempdir().expect("tempdir");
    let (code, _, err) = invoke(&["build", "--root", empty.path().to_str().expect("utf-8")]);
    assert_eq!(code, EXIT_USAGE, "{err}");
    assert!(err.contains("docs/"), "{err}");
}

#[test]
fn check_is_clean_on_this_repository() {
    // The whole reason this belongs in CI: every internal link in `docs/` lands on a
    // page and a heading that exist, every guide has a place in the reading order,
    // and no page has lost its title. If this test fails, the docs are wrong, not
    // the builder.
    let root = repo_root();
    let out = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = invoke(&[
        "check",
        "--root",
        root.to_str().expect("utf-8"),
        "--out",
        out.path().to_str().expect("utf-8"),
    ]);
    assert_eq!(code, EXIT_OK, "problems:\n{stdout}\n{stderr}");
    assert!(stdout.contains("no problems"), "{stdout}");
}

#[test]
fn check_refuses_a_broken_link_and_names_the_page() {
    let fixture = Fixture::new(&[
        (
            "docs/one.md",
            "# One\n\n[two](two.md#not-there)\n\n[gone](gone.md)\n",
        ),
        ("docs/two.md", "# Two\n\n## Really\n"),
    ]);
    let (code, stdout, stderr) =
        invoke(&["check", "--root", fixture.root.to_str().expect("utf-8")]);
    assert_eq!(code, EXIT_PROBLEM);
    assert!(stdout.contains("docs/one.md"), "{stdout}");
    assert!(stdout.contains("not-there"), "{stdout}");
    assert!(stdout.contains("gone.md"), "{stdout}");
    assert!(stderr.contains("2 problems"), "{stderr}");
}

#[test]
fn check_writes_nothing() {
    // `check` decides; `build` writes. A CI job that runs `check` must not be able to
    // publish anything by accident.
    let fixture = Fixture::new(&[("docs/one.md", "# One\n")]);
    let (code, _, _) = invoke(&["check", "--root", fixture.root.to_str().expect("utf-8")]);
    assert_eq!(code, EXIT_OK);
    assert!(
        !fixture.root.join("_site").exists(),
        "`check` created a site directory"
    );
}

#[test]
fn build_writes_where_it_is_told_and_says_how_much() {
    let fixture = Fixture::new(&[("docs/one.md", "# One\n\nA line of prose.\n")]);
    let root = fixture.root.to_str().expect("utf-8");
    let out = tempfile::tempdir().expect("tempdir");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, stdout, stderr) = invoke(&["build", "--root", root, "--out", out_dir]);
    assert_eq!(code, EXIT_OK, "{stderr}");
    assert!(stdout.contains("built "), "{stdout}");
    assert!(stdout.contains("pages"), "{stdout}");
    assert!(out.path().join("docs/one.html").is_file());
    assert!(out.path().join("assets/site.css").is_file());

    // `--quiet` is for the CI job that reads the exit code and nothing else.
    let (code, stdout, _) = invoke(&["build", "--root", root, "--out", out_dir, "--quiet"]);
    assert_eq!(code, EXIT_OK);
    assert!(!stdout.contains("built "), "{stdout}");

    // `--out=x` is the same flag spelled the other way.
    let other = tempfile::tempdir().expect("tempdir");
    let flag = format!("--out={}", other.path().display());
    let (code, _, _) = invoke(&["build", "--root", root, &flag]);
    assert_eq!(code, EXIT_OK);
    assert!(
        other.path().join("index.html").exists() || other.path().join("docs/one.html").exists()
    );
}

#[test]
fn a_build_that_found_problems_still_writes_and_says_so_on_stderr() {
    // The site is more useful published with one dead link than not published, so
    // `build` warns and succeeds; `check` is the command that refuses.
    let fixture = Fixture::new(&[("docs/one.md", "# One\n\n[gone](gone.md)\n")]);
    let root = fixture.root.to_str().expect("utf-8");
    let (code, _, stderr) = invoke(&["build", "--root", root]);
    assert_eq!(code, EXIT_OK);
    assert!(stderr.contains("warning:"), "{stderr}");
    assert!(stderr.contains("gone.md"), "{stderr}");
    assert!(fixture.root.join("_site/docs/one.html").is_file());
}

#[test]
fn writing_to_a_directory_that_cannot_be_written_is_an_io_error() {
    let fixture = Fixture::new(&[("docs/one.md", "# One\n")]);
    let root = fixture.root.to_str().expect("utf-8");
    // `docs/one.md` is a file, so the output directory cannot be created inside it.
    let blocked = fixture.root.join("docs/one.md/out");
    let blocked = blocked.to_str().expect("utf-8");
    let (code, _, stderr) = invoke(&["build", "--root", root, "--out", blocked]);
    assert_eq!(code, EXIT_IO, "{stderr}");
    assert!(stderr.contains("error:"), "{stderr}");
}

#[test]
fn flags_reach_the_site_they_describe() {
    let fixture = Fixture::new(&[("docs/one.md", "# One\n")]);
    let root = fixture.root.to_str().expect("utf-8");
    let (code, _, _) = invoke(&[
        "build",
        "--root",
        root,
        "--title",
        "Other name",
        "--tagline",
        "a different line",
        "--base-path",
        "/other/",
        "--source-url",
        "https://example.test/fork/repo/",
        "--source-ref",
        "trunk",
    ]);
    assert_eq!(code, EXIT_OK);
    let page = fixture.read("docs/one.html");
    assert!(page.contains("<title>One · Other name</title>"), "{page}");
    assert!(page.contains("a different line"));
    assert!(
        page.contains("https://example.test/fork/repo/blob/trunk/docs/one.md"),
        "the edit link follows --source-url and --source-ref: {page}"
    );
    assert!(fixture.read("404.html").contains("/other/index.html"));
}

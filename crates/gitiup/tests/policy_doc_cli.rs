//! `docs/policy.md` is executed, not eyeballed (giti-91m.6).
//!
//! The ticket's own words are the reason this file exists: *a doc example that has never
//! run is a guess*. So the page is parsed, and every line the page shows a reader typing
//! is typed here, in order, against the same empty home and the same empty stores, and
//! everything the page prints is compared with what the binary actually printed.
//!
//! Four guarantees, in this file:
//!
//! * **every documented command line runs, and exits where the page says it exits** —
//!   including the refusals, which are the lines most likely to have quietly changed;
//! * **every line of output the page shows was really printed**, in that order, by that
//!   command (a `…` line on the page means "output elided here", and nothing more);
//! * **the digests quoted in the prose are the vectors' own digests**, so a rewrite of
//!   the fixture set cannot leave the prose quoting a digest that no longer exists;
//! * **`examples/gitiup-policy.json` is a policy file the ladder accepts**, and is the
//!   same rules as the signed policy the page publishes.
//!
//! The state is deliberately shared between the blocks, in document order: example 3
//! forks the store example 2 built, and that is the claim the page is making. A fresh
//! temp home per document, and a real keystore with the three fixture identities derived
//! from their public labels, is what makes each run of this test the same run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::PolicyFile;
use gitiup_quorum::policy::normalise_rules;
use serde_json::Value;

/// The passphrase the page's keystore is unlocked with (supplied by the environment,
/// which is the only way a non-interactive run can supply it — `docs/signing-keys.md`).
const PASSPHRASE: &str = "four random words";
/// The fixture identity derivation, from
/// [`change-v1/generate.py`](../../../docs/adr/fixtures/change-v1/generate.py): the
/// seeds come from public labels, so no private key is committed anywhere and still
/// every digest on the page is reproducible.
const SEED_LABEL: &[u8] = b"gitiup ADR-0003 change-v1 fixture key: ";
/// The three identities the page introduces.
const IDENTITIES: &[&str] = &["ada", "sofia", "ci-runner"];
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn doc_text() -> String {
    let path = repo_root().join("docs/policy.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// the page, as steps
// ---------------------------------------------------------------------------

/// One documented command line, plus what the page says it prints and exits with.
struct Step {
    /// Where in the page it is, for a failure a reader can act on.
    line: usize,
    /// The text after the `$ ` prompt, exactly as written.
    command: String,
    /// The exit code the page claims. Default 0; a `# exit N` line sets it.
    exit: i32,
    /// The output lines the page shows, in order. `…` means "elided here".
    printed: Vec<String>,
}

/// Parse every ```console block in the page into the steps it tells a reader to run.
///
/// The parse is small and strict on purpose: `$` starts a command, `# exit N` sets the
/// expected exit code of the command above it, `…` is an elision, and anything else is
/// output that has to appear. A block that parses as nothing is a block nobody wrote —
/// and `the_page_documents_commands` below is what keeps that from being quiet.
fn steps() -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    let mut in_block = false;
    for (index, raw) in doc_text().lines().enumerate() {
        let line = index + 1;
        if raw.trim_start().starts_with("```console") {
            in_block = true;
            continue;
        }
        if in_block && raw.trim_start().starts_with("```") {
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        let text = raw.trim_end();
        if let Some(command) = text.strip_prefix("$ ") {
            let (command, exit) = split_exit(command.trim());
            assert!(
                !command.is_empty(),
                "docs/policy.md:{line}: a `$` line with no command on it"
            );
            steps.push(Step {
                line,
                command,
                exit,
                printed: Vec::new(),
            });
            continue;
        }
        if text.trim().is_empty() {
            continue;
        }
        if let Some(marker) = text.strip_prefix("# exit ") {
            let exit = marker.trim().parse::<i32>().unwrap_or_else(|_| {
                panic!("docs/policy.md:{line}: `# exit {marker}` is not a number")
            });
            let last = steps
                .last_mut()
                .expect("an `# exit` with no command above it");
            last.exit = exit;
            continue;
        }
        let step = steps
            .last_mut()
            .unwrap_or_else(|| panic!("docs/policy.md:{line}: output before any `$` line"));
        step.printed.push(text.to_string());
    }
    steps
}

/// A trailing `# exit N` on a command line, if it has one.
fn split_exit(command: &str) -> (String, i32) {
    if let Some((command, code)) = command.rsplit_once("  # exit ")
        && let Ok(code) = code.trim().parse::<i32>()
    {
        return (command.to_string(), code);
    }
    (command.to_string(), 0)
}

// ---------------------------------------------------------------------------
// the stage the page runs on
// ---------------------------------------------------------------------------

/// The directory the page runs in: paths on the page are relative to the repository
/// root, so the ones it opens are staged here, and the stores it creates are its own.
struct Stage {
    dir: tempfile::TempDir,
}

impl Stage {
    fn new() -> Stage {
        let stage = Stage {
            dir: tempfile::tempdir().expect("a temp home"),
        };
        for (source, target) in [
            (
                "docs/adr/fixtures/policy-v1/policies",
                "docs/adr/fixtures/policy-v1/policies",
            ),
            ("examples/gitiup-policy.json", "examples/gitiup-policy.json"),
            (
                "crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json",
                "crates/gitiup-attest/tests/fixtures/runs/matrix-build/run.json",
            ),
        ] {
            let from = repo_root().join(source);
            let to = stage.path().join(target);
            if from.is_dir() {
                copy_dir(&from, &to);
            } else {
                std::fs::create_dir_all(to.parent().expect("a parent")).expect("the parent");
                std::fs::copy(&from, &to)
                    .unwrap_or_else(|e| panic!("{} → {}: {e}", from.display(), to.display()));
            }
        }
        stage
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run one documented line, verbatim, in a shell, with `gitiup` the binary under
    /// test and nothing from the developer's machine able to reach in: a private
    /// config home, no ssh-agent, no inherited `$GITIUP_POLICY`.
    fn run(&self, command: &str) -> Output {
        let binary = env!("CARGO_BIN_EXE_gitiup");
        let child = Command::new("bash")
            .arg("-c")
            .arg(command)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dirname(binary),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .env_remove("GITIUP_POLICY")
            .env_remove("GITIUP_REMOTE")
            .current_dir(self.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bash runs");
        child.wait_with_output().expect("the command finishes")
    }
}

fn dirname(path: &str) -> &str {
    Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .expect("the binary has a parent directory")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the target directory");
    for entry in std::fs::read_dir(from).expect("a readable directory") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("a readable file");
        }
    }
}

/// The fixture seeds are written by the page itself (it documents the derivation), and
/// `IDENTITIES` is what the page imports; this asserts they are the three it names.
#[test]
fn the_page_imports_the_three_fixture_identities_it_derives() {
    let doc = doc_text();
    let cases: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("docs/adr/fixtures/policy-v1/cases.json"))
            .expect("the policy vectors"),
    )
    .expect("the policy vectors are JSON");
    for name in IDENTITIES {
        assert!(
            doc.contains(&format!("gitiup key import seed {name}.seed --name {name}")),
            "docs/policy.md should import `{name}`, the identity the examples are told in"
        );
        // And the fingerprint it prints is the vectors' fingerprint for that label —
        // otherwise the page is showing one repository and quoting another's digests.
        let key_id = cases["keys"][name]
            .as_str()
            .unwrap_or_else(|| panic!("the vectors have no key for `{name}`"));
        assert!(
            doc.contains(key_id),
            "docs/policy.md should show `{name}` as {key_id}, the fingerprint the vectors \
             derive from that label"
        );
    }
    assert!(
        doc.contains(std::str::from_utf8(SEED_LABEL).expect("an ascii label")),
        "docs/policy.md must state the seed derivation it depends on, or a reader cannot \
         reproduce a single digest on the page"
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ---------------------------------------------------------------------------
// 1. the page runs
// ---------------------------------------------------------------------------

#[test]
fn every_documented_command_line_runs_and_prints_what_the_page_says() {
    // The page documents its own dependency for the fixture identities; say which one
    // is missing rather than failing inside `bash`.
    if Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        panic!(
            "docs/policy.md re-derives its fixture identities with python3 (as the ADR \
             fixtures do throughout this repository), and python3 is not on PATH"
        );
    }
    let stage = Stage::new();
    let steps = steps();
    assert!(
        steps.len() >= 20,
        "docs/policy.md should document more commands than {} — a page with no commands \
         to run is a page this test proves nothing about",
        steps.len()
    );
    for step in &steps {
        let output = stage.run(&step.command);
        let code = output.status.code().unwrap_or(-1);
        assert_eq!(
            code,
            step.exit,
            "docs/policy.md:{}: `{}` exited {code}, the page says {}\n--- stdout\n{}--- stderr\n{}",
            step.line,
            step.command,
            step.exit,
            stdout(&output),
            stderr(&output)
        );
        // A verdict belongs on stdout and a fault on stderr; the page shows both
        // wherever they landed, and so checks both — but nothing more.
        let haystack: Vec<String> = stdout(&output)
            .lines()
            .chain(stderr(&output).lines())
            .map(|line| line.trim_end().to_string())
            .collect();
        let mut cursor = 0usize;
        for printed in &step.printed {
            if printed.trim() == "…" {
                cursor = 0;
                continue;
            }
            let found = haystack[cursor..]
                .iter()
                .position(|line| line == printed)
                .unwrap_or_else(|| {
                    panic!(
                        "docs/policy.md:{} claims `{}` prints:\n    {printed}\n\
                         and it printed:\n{}\n\
                         ({} lines searched from {cursor})",
                        step.line,
                        step.command,
                        haystack
                            .iter()
                            .map(|line| format!("    {line}"))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        haystack.len()
                    )
                });
            cursor += found + 1;
        }
    }
    // The page ends having built stores; say which ones, so a failure above is not the
    // only thing this run ever tells a reader.
    for store in ["store", "project", "fork", "sofia"] {
        assert!(
            stage.path().join(store).is_dir(),
            "the page should have created ./{store} by now"
        );
    }
}

#[test]
fn the_page_teaches_the_three_worked_examples_the_ticket_asked_for() {
    let doc = doc_text();
    for heading in [
        "## Example 1 — a personal repository that accepts one local run",
        "## Example 2 — a project that requires four of five",
        "## Example 3 — a fork: what it inherits, and where the divergence shows",
    ] {
        assert!(doc.contains(heading), "docs/policy.md lost `{heading}`");
    }
    // …and the claims that make them worked rather than illustrative: the five seats,
    // the four that must agree, the refusal of a fork's own signature, and the chain walk.
    for claim in [
        "4 of 5 seats must agree",
        "5 of 7 seats must agree",
        "signer_untrusted",
        "policy_history_missing",
        "the chain was walked 2 links to revision 1",
    ] {
        assert!(
            doc.contains(claim),
            "docs/policy.md no longer says `{claim}`"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. the digests the prose quotes
// ---------------------------------------------------------------------------

/// Every `sha256:…` the page's prose quotes, with the `…` forms expanded to a query.
///
/// Output inside a fenced block is already pinned by the run above, so this is about
/// the *prose*: the sentence that says "same `body_digest` (`sha256:c1406ed5…`)". A
/// digest there is a claim about bytes, and the only honest place to check it is the
/// vector set.
#[test]
fn the_digests_the_prose_quotes_are_real_ones() {
    let mut prose = String::new();
    let mut in_fence = false;
    for line in doc_text().lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            prose.push_str(line);
            prose.push('\n');
        }
    }
    let cases: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("docs/adr/fixtures/policy-v1/cases.json"))
            .expect("the policy vectors"),
    )
    .expect("the policy vectors are JSON");
    let mut known: Vec<String> = vec![
        cases["genesis_previous"]
            .as_str()
            .expect("a genesis previous digest")
            .to_string(),
    ];
    for (_, policy) in cases["policies"].as_object().expect("policies") {
        for key in ["body_digest", "record_digest"] {
            if let Some(digest) = policy[key].as_str() {
                known.push(digest.to_string());
            }
        }
    }
    // Anything the page itself prints is also real by construction.
    for step in steps() {
        for printed in step.printed {
            for candidate in digests_in(&printed) {
                known.push(candidate);
            }
        }
    }
    let mut quoted = 0usize;
    for candidate in digests_in(&prose) {
        quoted += 1;
        assert!(
            known.iter().any(|digest| digest.starts_with(&candidate)),
            "docs/policy.md quotes `{candidate}` in its prose, and no published policy, \
             printed line, or vector digest starts with it: the prose has drifted from \
             the vectors"
        );
    }
    assert!(
        quoted > 0,
        "the page quotes no digest at all in its prose, which is not the point of this check"
    );
}

/// `sha256:`-prefixed lowercase-hex runs in `text`, truncated or full.
fn digests_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while let Some(offset) = text[index..].find("sha256:").map(|at| index + at) {
        index = offset + "sha256:".len();
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        let hex = &text[start..index];
        if hex.len() >= 8 {
            found.push(format!("sha256:{hex}"));
        }
    }
    found
}

// ---------------------------------------------------------------------------
// 3. the example policy file
// ---------------------------------------------------------------------------

#[test]
fn the_example_policy_is_a_policy_file_the_ladder_accepts() {
    let path = repo_root().join("examples/gitiup-policy.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // The same call `policy show --policy` makes.
    let draft = PolicyFile::from_json(&text)
        .unwrap_or_else(|e| panic!("{}: {e}: {}", path.display(), e.detail()));
    let policy = draft
        .to_policy()
        .expect("and it turns into the rules a check applies");
    assert!(
        !policy.allowed_sandboxes.is_empty(),
        "the example should say which sandboxes count as confinement, or it teaches half \
         of what a policy decides"
    );
    // It is a *tree file*, not a document: the ADR chose JSON precisely so the two
    // shapes share one vocabulary, and the page shows publish refusing the confusion.
    let value: Value = serde_json::from_str(&text).expect("the example file is JSON");
    assert!(
        value.get("rules").is_none() && value.get("signatures").is_none(),
        "`examples/gitiup-policy.json` is the draft form (PolicyFile); the signed form \
         wraps it in `rules` and adds a signature, and the page says so"
    );
}

#[test]
fn the_example_policy_is_the_same_rules_the_page_publishes() {
    // The page says the example file is example 1's rules, byte-equal after
    // normalisation. `personal` is signed and published, so this is the sentence made
    // checkable against a signature rather than against another draft.
    let draft = PolicyFile::from_json(
        &std::fs::read_to_string(repo_root().join("examples/gitiup-policy.json"))
            .expect("the example policy"),
    )
    .expect("the example policy parses");
    let signed: Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo_root().join("docs/adr/fixtures/policy-v1/policies/personal.json"),
        )
        .expect("the personal vector"),
    )
    .expect("the personal vector is JSON");
    let signed: PolicyFile = serde_json::from_value(signed["rules"].clone())
        .expect("the personal vector's rules are a policy file");
    assert_eq!(
        normalise_rules(&draft),
        normalise_rules(&signed),
        "`examples/gitiup-policy.json` and the signed `personal` policy must be the same \
         rules written two ways — that is what the page claims, and the only reason a \
         reader should believe the example is representative"
    );
}

// ---------------------------------------------------------------------------
// 4. the page's own cross-references
// ---------------------------------------------------------------------------

/// Links rot silently, and a documentation ticket is exactly where they get made. Every
/// relative link on the page — to a document, a crate, a fixture, the example file — has
/// to point at something that exists.
#[test]
fn every_link_on_the_page_points_at_a_real_file() {
    let docs = repo_root().join("docs");
    let mut checked = 0usize;
    for (index, line) in doc_text().lines().enumerate() {
        let mut rest = line;
        while let Some(start) = rest.find("](") {
            let target = &rest[start + 2..];
            let end = target.find(')').unwrap_or_else(|| {
                panic!(
                    "docs/policy.md:{}: a link with no closing bracket",
                    index + 1
                )
            });
            let link = target[..end]
                .split('#')
                .next()
                .unwrap_or_default()
                .to_string();
            rest = &target[end..];
            if link.is_empty()
                || link.starts_with("http://")
                || link.starts_with("https://")
                || link.starts_with("mailto:")
            {
                continue;
            }
            let path = docs.join(&link);
            assert!(
                path.exists(),
                "docs/policy.md:{} links to `{link}`, which does not exist as {}",
                index + 1,
                path.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "only {checked} relative links found on the page — the check would be very quiet \
         if the links were gone"
    );
}

/// The page's `# anchor` links, same file or another, must land on a heading. A reader
/// following "the quorum ladder" should arrive at it.
#[test]
fn the_page_anchors_land_on_headings() {
    let mut checked = 0usize;
    for (index, line) in doc_text().lines().enumerate() {
        let mut rest = line;
        while let Some(start) = rest.find("](") {
            let target = &rest[start + 2..];
            let end = target.find(')').unwrap_or(0);
            let link = &target[..end];
            rest = &target[end..];
            let Some((file, anchor)) = link.split_once('#') else {
                continue;
            };
            if file.starts_with("http://") || file.starts_with("https://") {
                continue;
            }
            let path = if file.is_empty() {
                repo_root().join("docs/policy.md")
            } else {
                repo_root().join("docs").join(file)
            };
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("docs/policy.md:{}: {}: {e}", index + 1, path.display())
            });
            let wanted = slug(anchor);
            let slugs: Vec<String> = text
                .lines()
                .filter(|line| line.starts_with('#'))
                .map(|line| slug(line.trim_start_matches('#').trim()))
                .collect();
            assert!(
                slugs.contains(&wanted),
                "docs/policy.md:{} anchors to `#{anchor}` in {}, and that file has no \
                 heading that slugs to it (it has {} headings)",
                index + 1,
                path.display(),
                slugs.len()
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no anchored links found on the page — nothing was checked"
    );
}

/// GitHub's heading slugs: lowercase, spaces to hyphens, punctuation dropped.
fn slug(heading: &str) -> String {
    let mut out = String::new();
    for c in heading.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
        } else if c == ' ' || c == '-' || c == '_' {
            out.push('-');
        }
        // Everything else — ``, `(``, `:``, `—` — is dropped, which is how two
        // adjacent spaces become `--` and a colon vanishes without a trace.
    }
    out
}

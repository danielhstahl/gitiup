//! `docs/quickstart.md` is executed, not eyeballed (giti-vfv).
//!
//! The ticket asked for a quickstart "for people who are not familiar with how to use
//! the tool", and the only quickstart worth trusting is one that ran. So the page is
//! parsed and every line it shows a reader typing is typed here, in order, in one
//! temporary directory, by one binary, against an empty keystore and a store the page
//! creates itself — and everything the page prints has to have really been printed.
//!
//! Four guarantees, in this file:
//!
//! * **every documented command line runs, and exits where the page says it exits** —
//!   including the refusals, which are the lines a newcomer hits first and the ones most
//!   likely to have quietly changed;
//! * **every line of output the page shows was really printed**, in that order, by that
//!   command, in the *merged* stream — so a page that shows a warning above a report is
//!   checking that the warning really came out first;
//! * **the page finishes the story it promises**: a change was merged into a branch of a
//!   store with no forge, because a signed proof said so, and the `pre-receive` gate is
//!   still standing at the end;
//! * **the page teaches the words and the exit-code table the rest of the docs assume**,
//!   names no verb the binary does not answer, and every document it links to exists.
//!
//! The state is deliberately shared between the blocks, in document order: the store
//! section 4 creates is the one section 11 merges into. That is what makes this one
//! walkthrough rather than a pile of unrelated examples.
//!
//! Parsing rules for a `console` block, all of them the way a shell reads:
//!
//! * `$ <command>` — a line the reader types; a trailing `  # exit N` sets its exit code.
//! * a command ending in `<<WORD` or `<<'WORD'` — the lines below it, up to the
//!   terminator, are its heredoc body and are not output.
//! * `cd <dir>` — moves the page's working directory, which is what it does to a
//!   reader's.
//! * `…` on a line of its own — output elided here; resets the match cursor, because an
//!   elision is a hole in what the page claims, not a claim.
//! * anything else — output the page claims, and that has to appear.
//!
//! To debug a failing line by hand, run the test with `QS_KEEP_STAGE=<dir>`: the page runs
//! in that directory instead of a temporary one, and is left there afterwards.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The passphrase the page's keystore is unlocked with — supplied by the environment,
/// which is the only way a non-interactive run can supply it (`docs/signing-keys.md`).
const PASSPHRASE: &str = "four random words";
/// The sandbox the page runs its jobs in. Landlock is the one that needs no runtime, so
/// it is the one a page can name; where it is not available the walkthrough is skipped
/// rather than quietly narrowed to a backend the reader was never shown.
const SANDBOX: &str = "landlock";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn doc_text() -> String {
    let path = repo_root().join("docs/quickstart.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// the page, as steps
// ---------------------------------------------------------------------------

/// One documented command line, plus what the page says it prints and exits with.
struct Step {
    /// Where in the page it is, for a failure a reader can act on.
    line: usize,
    /// The text after the `$ ` prompt, exactly as written (plus its heredoc body).
    command: String,
    /// The exit code the page claims. Default 0; a trailing `# exit N` sets it.
    exit: i32,
    /// The output lines the page shows, in order. `…` means "elided here".
    printed: Vec<String>,
}

/// Parse every `console` block in the page into the steps it tells a reader to run.
fn steps() -> Vec<Step> {
    let lines: Vec<String> = doc_text().lines().map(str::to_string).collect();
    let mut steps: Vec<Step> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim_start().starts_with("```console") {
            index = fill_block(&mut steps, &lines, index + 1);
        }
        index += 1;
    }
    for step in &steps {
        check_one_process(step);
    }
    steps
}

/// The one way this page could tell a reader to do something this harness cannot run the
/// same way as a terminal would — change directory in the middle of a compound command —
/// caught here so the failure names the line rather than showing up as a store in the
/// wrong place three sections later.
fn check_one_process(step: &Step) {
    assert!(
        !step.command.contains("cd ") || step.command.starts_with("cd "),
        "docs/quickstart.md:{}: `{}` moves directories in the middle of a command; each \n         command here is one process, so the page has to `cd` on a line of its own — then \n         the reader and this harness stand in the same place",
        step.line,
        step.command
    );
}

/// Read one console block from just after its opening fence; returns the index of the
/// line holding the closing fence.
fn fill_block(steps: &mut Vec<Step>, lines: &[String], mut index: usize) -> usize {
    while index < lines.len() {
        let line = index + 1;
        let text = lines[index].trim_end();
        if text.trim_start().starts_with("```") {
            return index;
        }
        if let Some(command) = text.strip_prefix("$ ") {
            let (command, exit) = split_exit(command.trim());
            assert!(
                !command.is_empty(),
                "docs/quickstart.md:{line}: a `$` line with no command on it"
            );
            let command = with_heredoc(&command, lines, &mut index);
            steps.push(Step {
                line,
                command,
                exit,
                printed: Vec::new(),
            });
            index += 1;
            continue;
        }
        if text.trim().is_empty() {
            index += 1;
            continue;
        }
        if let Some(marker) = text.trim().strip_prefix("# exit ") {
            let code = marker.trim().parse::<i32>().unwrap_or_else(|_| {
                panic!("docs/quickstart.md:{line}: `# exit {marker}` is not a number")
            });
            steps
                .last_mut()
                .expect("an `# exit` with no command above it")
                .exit = code;
            index += 1;
            continue;
        }
        let step = steps
            .last_mut()
            .unwrap_or_else(|| panic!("docs/quickstart.md:{line}: output before any `$` line"));
        step.printed.push(text.to_string());
        index += 1;
    }
    panic!("docs/quickstart.md: a console block was never closed");
}

/// A trailing `  # exit N` on a command line, if it has one.
fn split_exit(command: &str) -> (String, i32) {
    if let Some((command, code)) = command.rsplit_once("  # exit ")
        && let Ok(code) = code.trim().parse::<i32>()
    {
        return (command.to_string(), code);
    }
    (command.to_string(), 0)
}

/// The heredoc body belonging to a command, appended the way a shell reads it. On
/// return, `index` sits on the terminator line, so the caller's own step past it is the
/// line after the heredoc — skipping one more would silently delete a reader's next
/// command, which is exactly the bug this function exists to avoid.
fn with_heredoc(command: &str, lines: &[String], index: &mut usize) -> String {
    let Some(terminator) = heredoc_terminator(command) else {
        return command.to_string();
    };
    let mut text = command.to_string();
    *index += 1;
    while *index < lines.len() {
        let body = &lines[*index];
        text.push('\n');
        text.push_str(body);
        if body.trim_end() == terminator {
            return text;
        }
        *index += 1;
    }
    panic!("docs/quickstart.md: a heredoc was never terminated by `{terminator}`");
}

/// `<<WORD` or `<<'WORD'` at the end of a command, if it has one.
fn heredoc_terminator(command: &str) -> Option<String> {
    if !command.contains("<<") {
        return None;
    }
    let word = command.rsplit('<').next()?.trim();
    let word = word.strip_prefix('\'').unwrap_or(word);
    let word = word.strip_suffix('\'').unwrap_or(word);
    if word.is_empty() || !word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(word.to_string())
}

// ---------------------------------------------------------------------------
// the stage the page runs on
// ---------------------------------------------------------------------------

/// The page's temporary home. Nothing from the developer's machine is allowed to reach
/// in: a private config home, an empty git config, no ssh-agent, no inherited `$GITIUP_*`.
struct Stage {
    /// Held so the temporary home outlives the page that ran in it; `None` when the
    /// stage is a directory the environment named and this test must not delete.
    _dir: Option<tempfile::TempDir>,
    root: PathBuf,
    cwd: PathBuf,
}

impl Stage {
    /// A temporary home, unless `QS_KEEP_STAGE` names a directory to use and leave
    /// behind — which is how a failing line on the page gets debugged by hand instead of
    /// by re-running a test that deletes the scene of the crime.
    fn new() -> Stage {
        let (dir, root) = match std::env::var("QS_KEEP_STAGE") {
            Ok(keep) => {
                let path = PathBuf::from(keep);
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).expect("the named stage directory");
                (None, path)
            }
            Err(_) => {
                let temp = tempfile::tempdir().expect("a temp home");
                let path = temp.path().to_path_buf();
                (Some(temp), path)
            }
        };
        let cwd = root.clone();
        Stage {
            _dir: dir,
            root,
            cwd,
        }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    /// Follow the page from one directory to the next, as a reader's `cd` does.
    fn cd(&mut self, step: &Step, target: &str) {
        let target = target.trim();
        let next = if target.starts_with('/') {
            PathBuf::from(target)
        } else {
            self.cwd.join(target)
        };
        self.cwd = next.canonicalize().unwrap_or_else(|e| {
            panic!(
                "docs/quickstart.md:{}: `cd {target}` does not go anywhere: {e}",
                step.line
            )
        });
    }

    /// Run one documented line, verbatim, in a shell — with stderr merged into stdout, so
    /// the order the page prints things in is the order they came out.
    fn run(&mut self, step: &Step) -> Output {
        let binary = env!("CARGO_BIN_EXE_gitiup");
        let child = Command::new("bash")
            .arg("-c")
            // `exec 2>&1` first, so the page's line is handed to bash exactly as written
            // — nothing appended after it, which would break a heredoc — and whatever the
            // command writes to either stream arrives in one pipe, in order.
            .arg(format!("exec 2>&1\n{}", step.command))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dirname(binary),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("HOME", self.path())
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            // So that whatever the developer has in their git config cannot change what
            // the page's commits hash to — the shas the page prints are the shas this run
            // makes, on every machine and in every checkout.
            .env("GIT_CONFIG_GLOBAL", self.path().join("gitconfig"))
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Ada")
            .env("GIT_AUTHOR_EMAIL", "ada@example.com")
            .env("GIT_COMMITTER_NAME", "Ada")
            .env("GIT_COMMITTER_EMAIL", "ada@example.com")
            .env("GIT_AUTHOR_DATE", "@1760000000 +0000")
            .env("GIT_COMMITTER_DATE", "@1760000000 +0000")
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .env_remove("GITIUP_POLICY")
            .env_remove("GITIUP_REMOTE")
            .env_remove("GITIUP_COMMIT")
            .env_remove("GITIUP_IMAGE_DIGEST")
            .env_remove("GITIUP_UNSANDBOXED")
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("bash runs");
        child.wait_with_output().expect("the command finishes")
    }

    /// Run the whole page, step by step: every exit code and every printed line, in order.
    fn walk(&mut self) {
        for step in &steps() {
            if let Some(target) = step.command.strip_prefix("cd ") {
                self.cd(step, target);
                continue;
            }
            let output = self.run(step);
            if std::env::var("QS_KEEP_STAGE").is_ok() {
                eprintln!(
                    "[step {}] $ {}\n{}",
                    step.line,
                    step.command,
                    stdout(&output)
                );
            }
            let code = output.status.code().unwrap_or(-1);
            assert_eq!(
                code,
                step.exit,
                "docs/quickstart.md:{}: `{}` exited {code}, the page says {}\n{}",
                step.line,
                step.command,
                step.exit,
                stdout(&output)
            );
            self.check_printed(step, &output);
        }
    }

    /// Every line the page shows for this step has to appear in what the command printed,
    /// in order, with `…` standing for whatever the page could not promise.
    fn check_printed(&self, step: &Step, output: &Output) {
        let haystack: Vec<String> = stdout(output)
            .lines()
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
                .position(|line| claim_matches(printed, line))
                .unwrap_or_else(|| {
                    panic!(
                        "docs/quickstart.md:{} claims `{}` prints:\n    {printed}\n\
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
}

fn dirname(path: &str) -> &str {
    Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .expect("the binary has a parent directory")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Is the sandbox the page names usable here? `gitiup doctor --sandbox --json` answers
/// it, because that is the same question the page asks its reader.
fn sandbox_usable() -> bool {
    let output = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .args(["doctor", "--sandbox", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .output()
        .expect("gitiup doctor runs");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("`gitiup doctor --sandbox --json` prints JSON — that is what the page reads");
    report["backends"]
        .as_array()
        .unwrap_or_else(|| panic!("the sandbox report has no `backends` list"))
        .iter()
        .any(|backend| backend["name"] == SANDBOX && backend["available"] == true)
}

/// Run the page, or say plainly why this machine cannot.
fn the_page_runs() -> Option<Stage> {
    if !sandbox_usable() {
        eprintln!(
            "SKIPPING docs/quickstart.md: the page runs its jobs in the `{SANDBOX}` sandbox \
             because it is the one that needs no runtime, and this machine cannot use it. \
             `gitiup doctor --sandbox` says why; docs/sandbox.md says what to do about it. \
             Narrowing the run to another backend would be measuring a page the reader was \
             never given."
        );
        return None;
    }
    let mut stage = Stage::new();
    stage.walk();
    Some(stage)
}

// ---------------------------------------------------------------------------
// 1. the page runs
// ---------------------------------------------------------------------------

#[test]
fn every_documented_command_line_runs_and_prints_what_the_page_says() {
    let steps = steps();
    assert!(
        steps.len() >= 30,
        "docs/quickstart.md should document more commands than {} — a page with no commands \
         to run is a page this test proves nothing about",
        steps.len()
    );
    let printed: usize = steps.iter().map(|step| step.printed.len()).sum();
    assert!(
        printed >= 40,
        "docs/quickstart.md shows a reader {} lines of output; a page that prints this much \
         has to have it checked, and {} is too few lines to be the whole walkthrough",
        printed,
        printed
    );
    // Walking the page *is* the assertion: `walk` checks every exit code and every
    // printed line against the binary that made them.
    the_page_runs();
}

/// The story the page promises has to end where it said it would.
#[test]
fn the_page_ends_with_a_merged_change_and_a_gate_at_the_ref() {
    let Some(stage) = the_page_runs() else {
        return;
    };
    let store = stage.path().join("demo/store.git");
    assert!(store.is_dir(), "the page never made ./demo/store.git");
    let log = git(&store, &["log", "--format=%s", "refs/heads/main"]);
    assert!(
        log.contains("greeting: say hello"),
        "the change the page opened was never merged; main says: {log}"
    );
    assert!(
        log.contains("greeting: a second line"),
        "the push the page proved was never accepted; main says: {log}"
    );
    let attestations = git(&store, &["for-each-ref", "refs/attestations"]);
    assert!(
        attestations.lines().count() >= 3,
        "the page filed fewer proofs than it showed: {attestations}"
    );
    assert!(
        store.join("hooks/pre-receive").is_file(),
        "the page installed a pre-receive gate and then lost it"
    );
    let policy = git(&store, &["for-each-ref", "refs/gitiup/policy"]);
    assert!(
        policy.contains("refs/gitiup/policy/current"),
        "the page published a policy the store does not advertise: {policy}"
    );
}

// ---------------------------------------------------------------------------
// 2. what the page says
// ---------------------------------------------------------------------------

/// A newcomer is being handed words and numbers. Say which ones went missing.
#[test]
fn the_page_teaches_the_words_the_rest_of_the_docs_use() {
    let doc = doc_text();
    for word in [
        "**store**",
        "**attestation**",
        "**tier**",
        "**policy**",
        "**change**",
        "simulated",
        "`local`",
        "`quorum`",
        "RunDigest",
        "ResultDigest",
    ] {
        assert!(
            doc.contains(word),
            "docs/quickstart.md no longer teaches `{word}`, which the rest of the docs assume"
        );
    }
    for row in [
        "| 0 | yes",
        "| 6 | **refused**",
        "| 7 | a signature",
        "| 8 | digest mismatch",
        "| 9 | attempts exhausted",
    ] {
        assert!(
            doc.contains(row),
            "docs/quickstart.md's exit-code table lost `{row}`"
        );
    }
    // The claims a newcomer is most likely to get wrong, in the page's own words.
    for claim in [
        "the default is a simulation",
        "never infers whom to",
        "compare-and-swap",
        "Publish the policy *before*",
        "policy_history_missing",
    ] {
        assert!(
            doc.contains(claim),
            "docs/quickstart.md no longer says `{claim}`"
        );
    }
}

/// The page must not send a reader to a verb that does not exist.
#[test]
fn every_verb_the_page_tells_a_reader_to_type_is_a_verb() {
    let help = Command::new(env!("CARGO_BIN_EXE_gitiup"))
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("gitiup --help runs");
    let help = String::from_utf8_lossy(&help.stdout).to_lowercase();
    for step in steps() {
        let Some(rest) = step.command.strip_prefix("gitiup ") else {
            continue;
        };
        let verb = rest
            .split([' ', '\t'])
            .next()
            .filter(|verb| *verb != "help" && *verb != "version")
            .unwrap_or_default();
        if verb.is_empty() {
            continue;
        }
        assert!(
            help.contains(&format!(" {verb} ")),
            "docs/quickstart.md:{} tells a reader to run `gitiup {verb}`, which `gitiup \
             --help` has never heard of",
            step.line
        );
    }
}

/// A page that points at a document that is not there has failed the reader twice.
#[test]
fn every_document_the_page_links_to_exists() {
    let doc = doc_text();
    let mut checked = 0;
    for after in doc.split("](").skip(1) {
        let Some(target) = after.split(')').next() else {
            continue;
        };
        if target.is_empty() || target.starts_with("http") || target.starts_with('#') {
            continue;
        }
        let target = target.split('#').next().unwrap_or(target);
        let path = repo_root().join("docs").join(target);
        assert!(
            path.exists(),
            "docs/quickstart.md links to `{target}`, which is not there"
        );
        checked += 1;
    }
    assert!(
        checked >= 15,
        "docs/quickstart.md should point at the documents it depends on; only {checked} \
         links were found"
    );
}

/// Does a line the page claims describe this line of real output?
///
/// Without an ellipsis it is the same string, and that is the common case. With one, the
/// page is showing the *shape* of a line whose machine-specific parts it cannot promise —
/// a key fingerprint, a digest, a temporary path — and the honest check is that the parts
/// it did print are the parts that came out, in order, at the ends they were printed at.
/// A line of `…` alone therefore matches any line, which is what an elision means.
fn claim_matches(claimed: &str, line: &str) -> bool {
    let parts: Vec<&str> = claimed.split('…').collect();
    if parts.len() == 1 {
        return line == claimed;
    }
    let mut rest = line;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let found = match rest.find(part) {
            Some(found) => found,
            None => return false,
        };
        if index == 0 && found != 0 {
            return false;
        }
        if index + 1 == parts.len() && found + part.len() != rest.len() {
            return false;
        }
        rest = &rest[found + part.len()..];
    }
    true
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

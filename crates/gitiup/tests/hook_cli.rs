//! `gitiup hook install pre-receive` — the gate measured where it runs: a real `git push`
//! into a real repository, judged by the policy published in that repository.
//!
//! Every other verdict command in this crate is tested by running it and reading its
//! report. This one cannot be, because its whole claim is about an act performed by
//! somebody else: *a push that cannot prove itself does not move the ref, and the
//! repository is exactly as it was afterwards*. That is only measurable from the other end
//! of a transport, with git doing the pushing and git's own receive hooks deciding — so
//! this file does exactly that, and every assertion is about the repository after a push
//! that was refused.
//!
//! ```text
//! owner     gitiup policy publish --remote origin …        refs/gitiup/policy/current
//!           gitiup hook install pre-receive --repo repo.git --trust ada
//! stranger  git push origin main            → refused (no proof), every ref untouched
//!           git push origin X:refs/changes/…  → accepted: proposals are not gated
//!           gitiup attest push --sign --key ada --remote origin
//!           git push origin main            → accepted, and the branch moves
//! owner     gitiup hook status / doctor --hooks            which policy, read when
//!           gitiup hook install --no-proof-required         the opt-out, said out loud
//! ```
//!
//! Three things the tests insist on, because they are the ticket's acceptance criteria:
//! a refused push leaves `for-each-ref` byte-identical ([`a_branch_update_with_no_proof_is_refused_and_nothing_moves`]);
//! a *bad* proof is refused the same way and for a stated reason
//! ([`a_bad_proof_refuses_and_leaves_the_repository_exactly_as_it_was`]); and the
//! asymmetry — `refs/heads/**` guarded, everything a proposal lives in open — is a
//! property of the gate, stated in its own `--help`
//! ([`the_gate_states_its_own_asymmetry_in_help`],
//! [`the_namespaces_a_proposal_lives_in_stay_open_while_branches_are_gated`]).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::TimeUs;
use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The zero oid, git's spelling of "this ref does not exist yet" — and of a delete.
const ZERO: &str = "0000000000000000000000000000000000000000";

/// One repository, its gate, and the clone a stranger pushes from.
struct Gate {
    dir: tempfile::TempDir,
    /// The bare repository: the store, and the thing being gated.
    repo: PathBuf,
    /// The same path as an owned `String`, so an argument vector can borrow it without a
    /// temporary going away under it.
    repo_path: String,
    /// The stranger's clone, with `origin` pointed at the repository.
    work: PathBuf,
}

impl Gate {
    fn new() -> Gate {
        let dir = tempfile::tempdir().expect("a temp home");
        let repo = dir.path().join("repo.git");
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).expect("work dir");
        git(
            dir.path(),
            &["init", "-q", "--bare", &repo.display().to_string()],
        );
        git(
            dir.path(),
            &["init", "-q", "-b", "main", &work.display().to_string()],
        );
        for (key, value) in [
            ("user.email", "ada@example.org"),
            ("user.name", "Ada"),
            ("commit.gpgsign", "false"),
            ("receive.denyDeleteCurrent", "ignore"),
        ] {
            // `receive.denyDeleteCurrent` is git's own refusal of a branch delete; this
            // test is about *gitiup's* refusal, so git has to keep out of the way.
            git(&repo, &["config", key, value]);
            git(&work, &["config", key, value]);
        }
        std::fs::create_dir_all(work.join(".github/workflows")).expect("workflows");
        std::fs::write(
            work.join(".github/workflows/ci.yml"),
            "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: make\n",
        )
        .expect("workflow");
        std::fs::write(work.join("Makefile"), "all:\n\t@echo one\n").expect("makefile");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", "Add the build"]);
        git(
            &work,
            &["remote", "add", "origin", &repo.display().to_string()],
        );

        // The repository is a gitiup store because the remote says so, and the CLI reaches
        // it by name; the hook does not read this file at all (it builds its own remote for
        // the repository it was installed in), which is what makes the two halves of the
        // test independent.
        std::fs::write(
            dir.path().join("gitiup.toml"),
            format!(
                "schema-version = 1\ndefault-remote = \"origin\"\n\n[[remote]]\nname = \
                 \"origin\"\nurl = \"file://{}\"\n\n[remote.options]\nhost-type = \
                 \"git\"\nref-cache-ttl = \"0s\"\n",
                repo.display()
            ),
        )
        .expect("gitiup.toml");

        let gate = Gate {
            dir,
            repo: repo.clone(),
            repo_path: repo.display().to_string(),
            work,
        };
        gate.key("ada");
        gate.key("mallory");
        gate
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run `gitiup` in the harness directory (where `gitiup.toml` is), with stdin.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gitiup"))
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_POLICY")
            .env_remove("GIT_DIR")
            .env_remove("GIT_QUARANTINE_PATH")
            .current_dir(self.path())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("gitiup runs");
        if let Some(text) = stdin {
            use std::io::Write as _;
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("feed stdin");
        }
        child.wait_with_output().expect("wait")
    }

    fn key(&self, name: &str) {
        let out = self.run(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(out.status.success(), "`key gen {name}`: {}", stderr(&out));
    }

    fn key_id(&self, name: &str) -> String {
        let listed = self.run(&["key", "list", "--json"], None);
        let keys: Vec<Value> = serde_json::from_str(&stdout(&listed)).expect("key list");
        keys.iter()
            .find(|record| record["name"].as_str() == Some(name))
            .expect("the key is listed")["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }

    /// The owner's rule, published into the repository: a `local` proof from `ada`.
    fn publish_policy(&self, extra: &[&str]) {
        // `--effective-from` an hour ago, so the proof this test files a moment later is
        // judged by the revision in force when it ran (ADR-0004 D6) and is still fresh
        // against the reader's clock. Pinned to *now* rather than to a date so the test
        // cannot age out of its own fixture.
        let effective = TimeUs(TimeUs::now().0 - 3_600_000_000).to_rfc3339();
        let mut args = vec![
            "policy",
            "publish",
            "--remote",
            "origin",
            "--key",
            "ada",
            "--principal",
            "Ada",
            "--allow-tier",
            "local",
            "--trust",
            "ada",
            "--effective-from",
            &effective,
            "--json",
        ];
        args.extend_from_slice(extra);
        let out = self.run(&args, None);
        assert!(
            out.status.success(),
            "policy publish: {}{}",
            stdout(&out),
            stderr(&out)
        );
    }

    /// Install the gate, the way the repository's owner does it.
    fn install(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "hook",
            "install",
            "pre-receive",
            "--repo",
            &self.repo_path,
            "--trust",
            "ada",
        ];
        args.extend_from_slice(extra);
        self.run(&args, None)
    }

    fn status(&self, extra: &[&str]) -> Output {
        let mut args = vec!["hook", "status", "--repo", &self.repo_path];
        args.extend_from_slice(extra);
        self.run(&args, None)
    }

    fn doctor(&self) -> Output {
        self.run(&["doctor", "--hooks", "--repo", &self.repo_path], None)
    }

    /// The gate, run by hand: the same program the installed script execs, on lines of
    /// the same shape. `--repo` is what the script passes it.
    fn hook_run(&self, lines: &str, extra: &[&str]) -> Output {
        let mut args = vec!["hook", "run", "pre-receive", "--repo", &self.repo_path];
        args.extend_from_slice(extra);
        self.run(&args, Some(lines))
    }

    /// A fresh commit on `main`, as a stranger would make one.
    fn commit(&self, message: &str) -> String {
        std::fs::write(self.work.join(format!("{}.txt", message.len())), message).expect("file");
        git(&self.work, &["add", "."]);
        git(&self.work, &["commit", "-q", "-m", message]);
        git(&self.work, &["rev-parse", "HEAD"])
    }

    /// Push one refspec, as the stranger's `git` does it.
    fn push(&self, spec: &str) -> Output {
        let out = Command::new("git")
            .current_dir(&self.work)
            .args(["push", "origin", spec])
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git push")
            .wait_with_output()
            .expect("wait");
        // Every byte git relayed from the hook, in one string: the report a pusher reads.
        let said = said(&out);
        if out.status.success() {
            eprintln!("push {spec} accepted:\n{said}");
        }
        out
    }

    /// Sign one run report about `head` and file it in the repository — the proof, on
    /// record before the branch is pushed. `claimed_at` is *now*, because the gate runs on
    /// the real clock and a proof has to be fresh against it.
    fn attest(&self, key: &str, head: &str) -> Value {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-attest/tests/fixtures/runs/matrix-build/run.json");
        let text = std::fs::read_to_string(&source).expect("the fixture run report");
        let mut report: Value = serde_json::from_str(&text).expect("the fixture is JSON");
        report["commit"] = format!("sha1:{head}").into();
        report["claims"]["claimed_at_us"] = json!(TimeUs::now().0);
        let path = self.path().join(format!("run-{head}-{key}.json"));
        std::fs::write(&path, report.to_string()).expect("write the run report");
        let out = self.run(
            &[
                "attest",
                "push",
                "--run-report",
                &path.display().to_string(),
                "--sign",
                "--key",
                key,
                "--remote",
                "origin",
                "--json",
            ],
            None,
        );
        assert!(
            out.status.success(),
            "attest push: {}{}",
            stdout(&out),
            stderr(&out)
        );
        json(&out)
    }

    /// Every ref the repository holds, and where it points. This is the state a refused
    /// push must not have touched: not only the branch it tried to move, but the policy
    /// refs, the record chains and the store manifest too.
    fn refs(&self) -> String {
        git(
            &self.repo,
            &[
                "for-each-ref",
                "--sort=refname",
                "--format=%(refname) %(objectname) %(*objectname)",
            ],
        )
    }

    fn head(&self, reference: &str) -> String {
        git(&self.repo, &["rev-parse", reference])
    }

    fn script(&self) -> PathBuf {
        self.repo.join("hooks").join("pre-receive")
    }

    fn record(&self) -> PathBuf {
        self.repo
            .join("info")
            .join("gitiup")
            .join("pre-receive.json")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Everything a command said, for an assertion message a failing test can act on.
fn said(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

/// Run `git` and insist it worked, returning trimmed stdout.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository with the gate installed and the policy published, and `main` already on
/// the store from the owner's own push (a branch is the owner's act, so it goes in before
/// the gate exists — and the gate then guards every move after it).
fn setup() -> Gate {
    let gate = Gate::new();
    git(&gate.work, &["push", "-q", "origin", "main"]);
    gate.publish_policy(&[]);
    let installed = gate.install(&[]);
    assert!(installed.status.success(), "install: {}", said(&installed));
    gate
}

// ---------------------------------------------------------------------------
// the ticket's sentence: an unproven ref update does not happen
// ---------------------------------------------------------------------------

#[test]
fn a_branch_update_with_no_proof_is_refused_and_nothing_moves() {
    let gate = setup();
    let next = gate.commit("second");
    let before = gate.refs();

    let push = gate.push("main");
    assert!(
        !push.status.success(),
        "a branch whose new head has no proof must not move: {}",
        said(&push)
    );
    let said = said(&push);
    assert!(
        said.contains("pre-receive hook declined"),
        "git's own refusal is what the pusher sees: {said}"
    );
    // The report `gitiup policy check` prints, relayed through the transport: the verdict
    // line, the rule that decided it, and the ref it was about.
    assert!(said.contains("REFUSED"), "{said}");
    assert!(said.contains("refs/heads/main"), "{said}");
    assert!(said.contains(&next), "the report names the head: {said}");
    assert!(
        said.contains("no attestation"),
        "the reason is the missing proof, said in the library's own words: {said}"
    );
    assert!(
        said.contains("revision 1") || said.contains("policy"),
        "the policy that refused is named: {said}"
    );

    // The acceptance criterion, literally: the repository is exactly as it was. Not just
    // the branch that was refused — every ref, including the policy and the record chains
    // the gate read to reach its answer.
    assert_eq!(
        gate.refs(),
        before,
        "a refused push must change nothing at all"
    );
    assert_eq!(
        gate.head("refs/heads/main"),
        git(&gate.work, &["rev-parse", "HEAD~1"])
    );
}

#[test]
fn a_bad_proof_refuses_and_leaves_the_repository_exactly_as_it_was() {
    let gate = setup();
    let next = gate.commit("second");
    // A proof exists, is well-formed, is filed under the right commit — and is signed by a
    // key the published policy does not trust. The most common bad proof there is.
    let filed = gate.attest("mallory", &next);
    let before = gate.refs();

    let push = gate.push("main");
    assert!(
        !push.status.success(),
        "an untrusted proof proves nothing: {}",
        said(&push)
    );
    let told = said(&push);
    assert!(told.contains("REFUSED"), "{told}");
    assert!(
        told.contains("trust") || told.contains("trusted"),
        "the refusal should name the rule that failed: {told}"
    );
    assert!(
        told.contains(&filed["digest"].as_str().unwrap()[..8]),
        "the refused push names the attestation it refused: {told}"
    );
    assert_eq!(gate.refs(), before, "a refused push changes nothing");

    // …and the same answer from the gate itself, as a verdict: the code on stdout-land, the
    // report on stdout, stderr empty — the contract every verdict in this crate keeps, and
    // the one a hook has to be able to rely on.
    let direct = gate.hook_run(&format!("{ZERO} {next} refs/heads/main\n"), &[]);
    assert_eq!(code(&direct), 6, "refused: {}", said(&direct));
    assert_eq!(stderr(&direct), "", "a verdict is printed on stdout");
    let report = said(&direct);
    assert!(report.contains("refs/heads/main"), "{report}");
    assert_eq!(
        gate.refs(),
        before,
        "even run by hand, a refusal moves nothing"
    );

    // Adding a *good* proof does not rescue the commit, and that is deliberate rather than
    // a defect: `min_signatures` asks whether some set of proofs adds up, and the rule the
    // merge gate applies is that a proof the policy will not accept is a standing fact
    // about the commit — which is exactly the reasoning a reviewer needs when a commit has
    // been signed by a key nobody trusts. The way out is not more proofs; it is the open
    // namespace the bad one was filed in, which is why that namespace being writable is not
    // the hole it looks like.
    gate.attest("ada", &next);
    let settled = gate.refs();
    let push = gate.push("main");
    assert!(
        !push.status.success(),
        "one unaccepted proof is not cancelled by an accepted one: {}",
        said(&push)
    );
    assert_eq!(
        gate.refs(),
        settled,
        "and a refused push still moves nothing (only the proofs filed by hand moved)"
    );

    // Clearing it is an ordinary push to the open namespace, and then the branch moves.
    let reference = format!(
        "refs/attestations/{next}/{}",
        filed["digest"].as_str().expect("a digest")
    );
    let cleared = gate.push(&format!(":{reference}"));
    assert!(
        cleared.status.success(),
        "filing a proof is open, and so is withdrawing one: {}",
        said(&cleared)
    );
    let push = gate.push("main");
    assert!(push.status.success(), "{}", said(&push));
    assert_eq!(gate.head("refs/heads/main"), next);
    assert!(
        said(&push).contains("accepted"),
        "the accepted push says what it accepted: {}",
        said(&push)
    );
}

#[test]
fn the_gate_proves_the_same_verdict_the_owner_can_check_afterwards() {
    let gate = setup();
    let next = gate.commit("second");
    gate.attest("ada", &next);
    let push = gate.push("main");
    assert!(push.status.success(), "{}", said(&push));

    // The ref moved because the proof on record satisfied the policy — and the same
    // question, asked of the same store by `gitiup policy check`, agrees. Two answers
    // about one set of bytes is the failure ADR-0004 T15 names, so this test is the guard
    // against the hook becoming a second opinion.
    let check = gate.run(
        &[
            "policy",
            "check",
            "--commit",
            &next,
            "--ref",
            "refs/heads/main",
            "--remote",
            "origin",
            "--trust",
            "ada",
            "--json",
        ],
        None,
    );
    let value = json(&check);
    assert_eq!(code(&check), 0, "{}", said(&check));
    assert_eq!(value["satisfies"], true, "{value}");
}

// ---------------------------------------------------------------------------
// the asymmetry, which is the design
// ---------------------------------------------------------------------------

#[test]
fn the_namespaces_a_proposal_lives_in_stay_open_while_branches_are_gated() {
    let gate = setup();
    let next = gate.commit("second");

    // The branch is refused.
    let refused = gate.push("main");
    assert!(!refused.status.success(), "{}", said(&refused));

    // The same pusher, with the same rights, in the same minute, files a proposal and
    // whatever else lives under the open namespaces — no proof asked, because none is
    // *trusted* there. This is the sentence the whole design turns on.
    let proposal = gate.push(&format!("{next}:refs/changes/chg-1/head"));
    assert!(
        proposal.status.success(),
        "a proposal is not a trusted ref: {}",
        said(&proposal)
    );
    let offered = gate.push(&format!("{next}:refs/gitiup/rounds/open"));
    assert!(
        offered.status.success(),
        "quorum state is offered, not trusted: {}",
        said(&offered)
    );
    let proof = gate.push(&format!("{next}:refs/attestations/{}/deadbeef", next));
    assert!(
        proof.status.success(),
        "filing a proof must never need permission: {}",
        said(&proof)
    );
    // And the branch is *still* where it was: the open namespaces are not a way in to it.
    assert!(
        !gate.push("main").status.success(),
        "an open proposal namespace is not a path to a guarded ref"
    );
    assert_eq!(
        gate.head("refs/changes/chg-1/head"),
        next,
        "the proposal landed"
    );

    // The gate says so itself, on the push, per ref.
    let relayed = said(&proposal);
    assert!(relayed.contains("accepted"), "{relayed}");
    assert!(
        relayed.contains("not a guarded ref"),
        "the refusal to refuse is explained: {relayed}"
    );
}

#[test]
fn the_gate_states_its_own_asymmetry_in_help() {
    let gate = setup();
    // `gitiup hook run pre-receive --help`: what the installed script execs, and what it
    // prints when asked.
    let help = gate.run(&["hook", "run", "pre-receive", "--help"], None);
    assert!(help.status.success(), "{}", said(&help));
    let text = stdout(&help);
    for phrase in [
        "refs/heads/**",
        "GUARDED",
        "refs/changes/**",
        "refs/attestations/**",
        "refs/gitiup/**",
        "open",
        "asymmetry",
        "no --policy",
    ] {
        assert!(
            text.contains(phrase),
            "the hook's own --help must say {phrase}:\n{text}"
        );
    }

    // …and the installed script carries the same words, so the answer is in the file a
    // sysadmin finds, not only in a manual nobody has open.
    let script = std::fs::read_to_string(gate.script()).expect("the installed script");
    for phrase in [
        "refs/heads/**",
        "refs/changes/**",
        "refs/attestations/**",
        "asymmetry",
    ] {
        assert!(
            script.contains(phrase),
            "the script itself must state {phrase}:\n{script}"
        );
    }
    // The script answers --help on the box, which is how the sysadmin reads it.
    let on_the_box = Command::new(gate.script())
        .arg("--help")
        .env("GITIUP_CONFIG_HOME", gate.path().join("cfg"))
        .output()
        .expect("the script runs");
    assert!(on_the_box.status.success(), "{}", stderr(&on_the_box));
    assert!(
        String::from_utf8_lossy(&on_the_box.stdout).contains("refs/changes/**"),
        "the installed script prints its own help"
    );

    // The install surface says it too: nobody installs this without being told.
    let install_help = gate.run(&["hook", "install", "pre-receive", "--help"], None);
    assert!(install_help.status.success());
    assert!(
        stdout(&install_help).contains("refs/changes/**")
            || stdout(&install_help).contains("OPT OUT"),
        "{}",
        stdout(&install_help)
    );
}

// ---------------------------------------------------------------------------
// deletions, and failing closed
// ---------------------------------------------------------------------------

#[test]
fn deleting_a_guarded_branch_is_refused_and_the_branch_survives() {
    let gate = setup();
    let before = gate.refs();

    let push = gate.push(":main");
    assert!(
        !push.status.success(),
        "a guarded ref does not vanish because someone pushed its absence: {}",
        said(&push)
    );
    assert!(said(&push).contains("REFUSED"), "{}", said(&push));
    assert_eq!(gate.refs(), before, "a refused delete moves nothing");

    // The gate says why: a delete is a change to a trusted ref that nothing can prove.
    let direct = gate.hook_run(
        &format!("{} {ZERO} refs/heads/main\n", gate.head("refs/heads/main")),
        &[],
    );
    assert_eq!(code(&direct), 6, "{}", said(&direct));
    assert!(said(&direct).contains("vanishes"), "{}", said(&direct));
}

#[test]
fn the_gate_fails_closed_when_it_cannot_answer() {
    let gate = setup();
    let next = gate.commit("second");
    let before = gate.refs();

    // No record: no trust roots, no mirror, no answer. A gate that cannot answer is a gate
    // that says no, and says why.
    std::fs::remove_file(gate.record()).expect("remove the record");
    let direct = gate.hook_run(&format!("{ZERO} {next} refs/heads/main\n"), &[]);
    assert_eq!(
        code(&direct),
        6,
        "no record is a refusal: {}",
        said(&direct)
    );
    assert!(said(&direct).contains("missing"), "{}", said(&direct));
    assert_eq!(gate.refs(), before);

    // No policy either: uninstall the policy by publishing nothing… instead, prove the
    // same failure from a repository whose policy cannot be believed: a gate that trusts
    // nobody resolves nothing.
    let record = gate.record();
    std::fs::write(
        &record,
        json!({
            "record_type": "gitiup-hook-1",
            "hook": "pre-receive",
            "installed_at_us": TimeUs::now().0,
            "installed_by": "gitiup test",
            "program": std::env::current_exe().expect("this binary"),
            "proof_required": true,
            "trust_key_ids": [],
            "trust_from": "nothing at all, on purpose",
            "mirror": gate.repo.join("info").join("gitiup").join("mirror"),
            "script": gate.script(),
            "notes": [],
        })
        .to_string(),
    )
    .expect("write the record");
    let direct = gate.hook_run(&format!("{ZERO} {next} refs/heads/main\n"), &[]);
    assert_eq!(
        code(&direct),
        6,
        "a gate that trusts nobody refuses: {}",
        said(&direct)
    );
    assert!(
        said(&direct).contains("believe"),
        "and says that is why: {}",
        said(&direct)
    );
    assert_eq!(gate.refs(), before);
    // A guarded ref with an unparseable new value is refused too, not crashed on.
    let direct = gate.hook_run("0000 not-an-oid refs/heads/main\n", &[]);
    assert_eq!(code(&direct), 6, "{}", said(&direct));
}

// ---------------------------------------------------------------------------
// status, doctor, the opt-out, and uninstall
// ---------------------------------------------------------------------------

#[test]
fn status_names_the_policy_the_signer_and_when_it_was_read() {
    let gate = setup();
    let out = gate.status(&[]);
    assert_eq!(code(&out), 0, "the gate is working: {}", said(&out));
    assert_eq!(stderr(&out), "", "a verdict prints on stdout");
    let text = stdout(&out);
    assert!(text.contains("revision 1"), "{text}");
    assert!(
        text.contains(&gate.key_id("ada")),
        "status says whose signature this box believes:\n{text}"
    );
    assert!(
        text.contains("read"),
        "and when the policy was read:\n{text}"
    );
    assert!(text.contains("refs/heads/**"), "{text}");
    assert!(text.contains("GATED"), "{text}");

    let value = json(&gate.status(&["--json"]));
    assert_eq!(value["verdict"], "gated", "{value}");
    assert_eq!(value["exit"], 0);
    assert_eq!(value["installed"], true);
    assert_eq!(value["bare"], true);
    assert_eq!(value["policy_refused"], Value::Null, "{value}");
    assert_eq!(value["gates"].as_array().unwrap().len(), 1);
    assert_eq!(value["policy"]["min_signatures"], 1);
    assert_eq!(value["open_refs"].as_array().unwrap().len(), 3);
    assert!(value["read_at"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn an_unresolvable_policy_is_a_refusal_the_owner_is_told_about() {
    let gate = Gate::new();
    git(&gate.work, &["push", "-q", "origin", "main"]);
    // The gate first, the policy never: the natural order for a repository that has just
    // decided it wants proofs, and the state every guarded push gets refused in.
    let installed = gate.install(&[]);
    assert!(installed.status.success(), "{}", said(&installed));
    assert!(
        said(&installed).contains("no gate-eligible policy")
            || said(&installed).contains("REFUSED"),
        "installing a gate with no policy says so: {}",
        said(&installed)
    );

    let next = gate.commit("second");
    let push = gate.push("main");
    assert!(
        !push.status.success(),
        "no policy means no push to a guarded ref: {}",
        said(&push)
    );
    assert!(
        said(&push).contains("no_policy_published"),
        "the refusal keeps ADR-0004 D4's token: {}",
        said(&push)
    );
    assert_eq!(
        code(&gate.status(&[])),
        6,
        "status says the gate cannot gate: {}",
        said(&gate.status(&[]))
    );
    assert_eq!(code(&gate.doctor()), 6, "doctor does too");
    assert_eq!(
        gate.head("refs/heads/main"),
        git(&gate.work, &["rev-parse", "HEAD~1"])
    );
    let _ = next;
}

#[test]
fn the_opt_out_is_installed_announced_and_refused_by_doctor() {
    let gate = Gate::new();
    git(&gate.work, &["push", "-q", "origin", "main"]);
    gate.publish_policy(&[]);
    let installed = gate.install(&["--no-proof-required"]);
    assert!(installed.status.success(), "{}", said(&installed));
    // It prints what it is disabling, in the install output.
    let announced = said(&installed);
    assert!(announced.contains("NOT REQUIRED"), "{announced}");
    assert!(announced.contains("trust alone"), "{announced}");

    // The gate stays installed and says so on the push that would have been refused.
    let next = gate.commit("second");
    let push = gate.push("main");
    assert!(push.status.success(), "{}", said(&push));
    assert!(
        said(&push).contains("proof is not required"),
        "the push itself says the gate is off: {}",
        said(&push)
    );
    assert_eq!(gate.head("refs/heads/main"), next);

    // …and it is said out loud where an operator looks, at a code a script can branch on.
    let status = gate.status(&[]);
    assert_eq!(code(&status), 6, "{}", said(&status));
    assert!(said(&status).contains("NOT REQUIRED"), "{}", said(&status));
    let doctor = gate.doctor();
    assert_eq!(code(&doctor), 6, "{}", said(&doctor));
    let told = said(&doctor);
    assert!(told.contains("NOT REQUIRED"), "{told}");
    assert!(told.contains("opt-out"), "{told}");
    assert!(
        told.contains("put the gate back"),
        "and how to undo it: {told}"
    );
    let value = json(&gate.status(&["--json"]));
    assert_eq!(value["verdict"], "not-gated", "{value}");
    assert_eq!(value["record"]["proof_required"], false);

    // Putting it back is the same command without the flag.
    let back = gate.install(&[]);
    assert!(back.status.success(), "{}", said(&back));
    assert_eq!(
        code(&gate.hook_run(
            &format!(
                "{} {} refs/heads/main\n",
                gate.head("refs/heads/main"),
                gate.commit("third")
            ),
            &[]
        )),
        6,
        "the gate gates again"
    );
}

#[test]
fn uninstall_takes_the_gate_out_and_leaves_a_foreign_hook_alone() {
    let gate = setup();
    let out = gate.run(
        &[
            "hook",
            "uninstall",
            "pre-receive",
            "--repo",
            &gate.repo.display().to_string(),
        ],
        None,
    );
    assert!(out.status.success(), "{}", said(&out));
    assert!(!gate.script().exists(), "the script is gone");
    assert!(!gate.record().exists(), "the record is gone");
    assert_eq!(code(&gate.doctor()), 6, "and the repository says so");

    // Nothing is installed twice: idempotent, and it says so instead of failing.
    let again = gate.run(
        &[
            "hook",
            "uninstall",
            "pre-receive",
            "--repo",
            &gate.repo.display().to_string(),
        ],
        None,
    );
    assert!(again.status.success(), "{}", said(&again));
    assert!(said(&again).contains("nothing"), "{}", said(&again));

    // A `pre-receive` gitiup did not write is not gitiup's to overwrite or delete.
    std::fs::write(gate.script(), "#!/bin/sh\n# somebody else's hook\nexit 0\n")
        .expect("write a foreign hook");
    let refused = gate.install(&[]);
    assert_eq!(
        code(&refused),
        6,
        "install refuses to clobber: {}",
        said(&refused)
    );
    assert!(said(&refused).contains("--force"), "and names the way out");
    assert_eq!(
        code(&gate.run(
            &[
                "hook",
                "uninstall",
                "pre-receive",
                "--repo",
                &gate.repo.display().to_string()
            ],
            None,
        )),
        6,
        "and refuses to delete it either"
    );
    // With `--force` it is replaced, and the file it replaced is kept.
    let forced = gate.install(&["--force"]);
    assert!(forced.status.success(), "{}", said(&forced));
    assert!(
        said(&forced).contains("replaced"),
        "and says it replaced something: {}",
        said(&forced)
    );
    let kept = gate.repo.join("hooks").join("pre-receive.gitiup-replaced");
    assert!(kept.is_file(), "the replaced hook is kept");
    assert!(
        std::fs::read_to_string(&kept)
            .expect("the backup")
            .contains("somebody else's hook"),
        "kept unchanged"
    );
}

// ---------------------------------------------------------------------------
// the surface itself
// ---------------------------------------------------------------------------

#[test]
fn the_surface_is_where_the_other_verdicts_are() {
    let gate = Gate::new();
    // In `gitiup help`, so `gitiup hook` is discoverable.
    let help = gate.run(&["help"], None);
    let text = stdout(&help);
    assert!(help.status.success());
    for line in [
        "hook install pre-receive",
        "hook status",
        "hook uninstall",
        "doctor --hooks",
    ] {
        assert!(
            text.contains(line),
            "`{line}` is missing from `gitiup help`:\n{text}"
        );
    }
    // An unknown hook is a usage error, not a guess: `install post-receive` would install
    // nothing and promise something.
    assert_eq!(
        code(&gate.run(&["hook", "install", "post-receive", "--repo", "."], None)),
        2
    );
    assert_eq!(code(&gate.run(&["hook", "frobnicate"], None)), 2);
    // Installing needs a repository: a gate has to be installed somewhere in particular.
    assert_eq!(
        code(&gate.run(&["hook", "install", "pre-receive"], None)),
        6
    );
    // The gate refuses an override, and says why, instead of quietly ignoring it.
    let override_attempt = gate.run(
        &[
            "hook",
            "run",
            "pre-receive",
            "--repo",
            ".",
            "--policy",
            "somewhere-else.json",
        ],
        Some(""),
    );
    assert_eq!(code(&override_attempt), 2, "{}", said(&override_attempt));
}

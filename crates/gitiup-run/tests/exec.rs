//! The executed path: `tier: local`, earned through a sandbox that was probed.
//!
//! The confinement itself is a property of the host (and of giti-bgy.1), so these
//! tests cover what *this* build is responsible for: that a `local` report only
//! happens with a sandbox named and probed, that exit codes and output are the ones
//! the processes produced, that the step environment is built from nothing (so a
//! secret arrives only when it was named), and that a step this build cannot run is
//! refused instead of skipped.
//!
//! The sandbox here is a test double that confines nothing and says so: `Sandbox` is
//! an honest seam, and the double's `guarantees` text is the lie-detector — it lands
//! in the attestation's annotations, so a `local` attestation from a test double is
//! visibly one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use gitiup_attest::{GitOid, InputValue, Policy, Tier};
use gitiup_run::sandbox::{self, Sandbox};
use gitiup_run::{Execution, Plan, Selector, Workflow};

/// Every test here either mutates the process environment or spawns a process from
/// it. In Rust 2024 those two things race — `set_var` while another thread is forking
/// is exactly the UB the edition warns about, and it shows up as a step that exits 2
/// for no reason — so the file runs its tests one at a time on purpose.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The command a test double builds: the step's argv, the environment it was given, and
/// nothing else — the same shape a real backend produces, minus the confinement.
///
/// Writing it out is the point. A double that quietly skipped the environment would let
/// the executed path pass its tests while leaking the runner's environment into steps,
/// which is the property this file exists to hold.
fn bare_command(
    argv: &[String],
    environment: &BTreeMap<String, String>,
    workspace: &Path,
    _scratch: &Path,
) -> gitiup_attest::Result<std::process::Command> {
    let mut command = std::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.current_dir(workspace);
    command.env_clear();
    for (key, value) in environment {
        command.env(key, value);
    }
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    Ok(command)
}

/// A sandbox for tests: runs the command as-is and admits it.
#[derive(Debug)]
struct Bare;

impl Sandbox for Bare {
    fn name(&self) -> &'static str {
        "test-double"
    }

    fn guarantees(&self) -> &'static str {
        "nothing: this is a test double and says so"
    }

    fn probe(&self) -> gitiup_attest::Result<()> {
        Ok(())
    }

    fn command(
        &self,
        argv: &[String],
        environment: &BTreeMap<String, String>,
        workspace: &Path,
        scratch: &Path,
    ) -> gitiup_attest::Result<std::process::Command> {
        bare_command(argv, environment, workspace, scratch)
    }
}

fn plan_of(source: &str) -> Plan {
    let workflow = Workflow::parse(".github/workflows/ci.yml", source).unwrap();
    Plan::build(&workflow, &Selector::default()).unwrap()
}

fn run_at<'a>(workspace: &Path, runner: &'a str) -> Execution<'a> {
    let mut execution = Execution::new(
        GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
        gitiup_attest::run::WorkflowSource::from_text(".github/workflows/ci.yml", "on: push\n"),
        "test-double",
        workspace,
        runner,
    );
    execution.now_us = Some(1_793_092_502_500_000);
    execution.run_id = Some("0123456789abcdef".into());
    execution
}

/// A scratch workspace that outlives the assertion phase, dropped at process exit.
fn workspace(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gitiup-exec-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn an_executed_run_says_local_and_names_the_sandbox_that_ran_it() {
    let _serial = serial();
    let workspace = workspace("basic");
    let plan = plan_of(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Greet\n        run: echo hello from a real process\n",
    );
    let report = gitiup_run::execute(
        &plan,
        &plan.jobs[0],
        &Bare,
        &run_at(&workspace, "gitiup 0.1.0"),
    )
    .unwrap();
    assert_eq!(report.provenance.tier, Tier::Local);
    assert_eq!(report.provenance.sandbox.as_deref(), Some("test-double"));
    assert_eq!(report.environment.provider.as_deref(), Some("test-double"));
    assert_eq!(report.steps.len(), 1);
    assert_eq!(report.steps[0].exit_code, 0);

    let manifest = gitiup_run::manifest_for(&report).unwrap();
    manifest.validate().unwrap();
    // The default policy accepts a `local` attestation…
    Policy::default()
        .check_provenance(&manifest.result.provenance)
        .unwrap();
    // …and the plain-text log it recorded really is what the process printed.
    let stdout = match &report.steps[0].stdout {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => panic!("the runner hands over text to normalise, got {other:?}"),
    };
    assert!(stdout.contains("hello from a real process"), "{stdout}");
    // The double's confession travelled with it, where a reviewer will see it.
    assert!(report.claims.annotations["x_sandbox_guarantees"].contains("test double"));
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn observed_exit_codes_and_a_failure_stopping_the_run() {
    let _serial = serial();
    let workspace = workspace("exit");
    let plan = plan_of(
        "on: push\njobs:\n  build:\n    steps:\n      - id: ok\n        run: exit 0\n      - id: boom\n        run: exit 4\n      - id: never\n        run: exit 0\n",
    );
    let report = gitiup_run::execute(
        &plan,
        &plan.jobs[0],
        &Bare,
        &run_at(&workspace, "gitiup 0.1.0"),
    )
    .unwrap();
    let by_id: BTreeMap<_, _> = report
        .steps
        .iter()
        .map(|step| (step.id.clone().unwrap(), step))
        .collect();
    assert_eq!(by_id["ok"].exit_code, 0);
    assert_eq!(
        by_id["ok"].outcome,
        Some(gitiup_attest::StepOutcome::Success)
    );
    assert_eq!(by_id["boom"].exit_code, 4);
    assert_eq!(
        by_id["boom"].outcome,
        Some(gitiup_attest::StepOutcome::Failure)
    );
    assert_eq!(
        by_id["never"].outcome,
        Some(gitiup_attest::StepOutcome::Skipped),
        "a runner does not carry on past a failure, and the attestation says so"
    );
    // Timings are claims, so the result digest is unaffected by how long it took.
    assert!(!report.claims.timings.is_empty() || report.steps[0].timing.is_some());
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn a_step_this_build_cannot_run_is_refused_not_skipped() {
    let _serial = serial();
    let workspace = workspace("uses");
    let plan = plan_of("on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n");
    let err = gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &run_at(&workspace, "gitiup"))
        .unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("does not fetch"), "{err}");
    assert!(err.hint().unwrap().contains("simulate"), "{err}");
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn the_step_environment_is_built_from_nothing() {
    let _serial = serial();
    let workspace = workspace("env");
    // A variable the parent process really does have: if the runner inherited the
    // environment, the step would print its value.
    // One test file at a time touches the environment, and only with its own names.
    unsafe { std::env::remove_var("GITIUP_EXEC_TEST_ABSENT") };
    let plan = plan_of(
        "on: push\njobs:\n  a:\n    steps:\n      - id: probe\n        run: |\n          echo \"path=${PATH}\"\n          echo \"absent=[${GITIUP_EXEC_TEST_ABSENT}]\"\n          echo \"sha=${GITHUB_SHA}\"\n          echo \"ci=${CI}\"\n          echo \"out=${GITHUB_OUTPUT}\"\n          printf 'built=yes\\n' > \"$GITHUB_OUTPUT\"\n        with:\n          flavour: spicy\n",
    );
    let mut execution = run_at(&workspace, "gitiup");
    execution.inputs = vec![("jobs".into(), InputValue::Int(4))];
    let report = gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &execution).unwrap();
    let text = match &report.steps[0].stdout {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => panic!("expected text, got {other:?}"),
    };
    assert!(text.contains("absent=[]"), "the environment leaked: {text}");
    assert!(
        text.contains("path=/usr/bin:/bin"),
        "unexpected PATH: {text}"
    );
    assert!(text.contains("ci=true"), "{text}");
    assert!(text.contains(&"a".repeat(40)), "GITHUB_SHA: {text}");
    // `$GITHUB_OUTPUT` is the one channel a step has to say anything back.
    assert_eq!(
        report.steps[0].outputs.get("built").map(String::as_str),
        Some("yes")
    );
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn a_named_secret_is_passed_by_value_and_recorded_by_name_only() {
    let _serial = serial();
    let workspace = workspace("secret");
    let name = "GITIUP_EXEC_TEST_SECRET";
    let value = "s3cr3t-value-never-written-down";
    // Set only for this test process, and only by name into the step.
    unsafe { std::env::set_var(name, value) };

    let plan = plan_of("on: push\njobs:\n  a:\n    steps:\n      - run: echo running\n");
    let mut execution = run_at(&workspace, "gitiup");
    execution.secret_names = vec![name.to_string()];
    let report = gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &execution).unwrap();

    // The name is the record; the value is not, and never will be (giti-bgy.3).
    assert_eq!(report.secret_names, vec![name.to_string()]);
    let manifest = gitiup_run::manifest_for(&report).unwrap();
    let bytes = String::from_utf8(manifest.canonical_bytes().unwrap()).unwrap();
    assert!(
        bytes.contains(name),
        "the name should be in the record: {bytes}"
    );
    assert!(
        !bytes.contains(value),
        "the secret value reached the signed manifest"
    );

    // Asking for a secret that is not there is a refusal, not a silent omission.
    let mut missing = run_at(&workspace, "gitiup");
    missing.secret_names = vec!["GITIUP_EXEC_TEST_MISSING".into()];
    let err = gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &missing).unwrap_err();
    assert!(
        err.detail().contains("not set in this environment"),
        "{err}"
    );
    unsafe { std::env::remove_var(name) };
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn the_sandbox_is_probed_before_anything_runs() {
    let _serial = serial();
    #[derive(Debug)]
    struct Refused;
    impl Sandbox for Refused {
        fn name(&self) -> &'static str {
            "refused"
        }
        fn guarantees(&self) -> &'static str {
            "none"
        }
        fn probe(&self) -> gitiup_attest::Result<()> {
            Err(gitiup_attest::Error::new(
                gitiup_attest::ErrorKind::Policy,
                "sandbox",
                "user namespaces are disabled here",
            ))
        }
        // Never reached — `probe` is what refuses — but a backend that cannot say how
        // it would confine a step has not answered the question, so the double answers
        // it and the test proves the refusal happened first.
        fn command(
            &self,
            argv: &[String],
            environment: &BTreeMap<String, String>,
            workspace: &Path,
            scratch: &Path,
        ) -> gitiup_attest::Result<std::process::Command> {
            bare_command(argv, environment, workspace, scratch)
        }
    }
    let workspace = workspace("probe");
    let plan = plan_of("on: push\njobs:\n  a:\n    steps:\n      - run: echo must not run\n");
    let err = gitiup_run::execute(
        &plan,
        &plan.jobs[0],
        &Refused,
        &run_at(&workspace, "gitiup"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("user namespaces"), "{err}");
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn the_sandbox_vocabulary_is_honest_about_what_exists() {
    let _serial = serial();
    // `--sandbox none` is the most important refusal in this module: an unconfined
    // run may not attest as `local`.
    let err = sandbox::open("none").unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("unconfined"), "{err}");
    assert!(err.hint().unwrap().contains("--execute"), "{err}");

    // Every rung of the ladder is a name that opens, and each one states what it
    // denies. "Not built into this build" is no longer an honest answer for docker or
    // landlock: both are implemented, and whether either works is a question for the
    // probe, not for a list in a source file.
    let ladder = sandbox::implemented();
    assert!(
        ladder.iter().any(|name| name == "landlock"),
        "the in-process rung must be offered: {ladder:?}"
    );
    for name in &ladder {
        let backend = sandbox::open(name).unwrap_or_else(|why| panic!("{name}: {why}"));
        assert_eq!(backend.name(), name.as_str());
        assert!(
            !backend.guarantees().is_empty(),
            "{name} offers no sentence about what it denies"
        );
        assert!(
            !backend.guarantees().contains("sandboxed"),
            "{name} describes its guarantees as `sandboxed`, which says nothing"
        );
    }

    let err = sandbox::open("kvm").unwrap_err();
    assert!(err.detail().contains("kvm"), "{err}");
    assert!(
        ladder.iter().any(|name| err.hint().unwrap().contains(name)),
        "a refusal must name what *does* exist: {err}"
    );

    // `open` is case-insensitive because flags are typed by people.
    assert_eq!(sandbox::open(" LANDLOCK ").unwrap().name(), "landlock");

    // Detection reports the truth about this machine, and says why when it is no.
    let backends = sandbox::detect();
    assert_eq!(
        backends.len(),
        ladder.len(),
        "every rung must report, not only the ones that work"
    );
    for backend in &backends {
        assert!(
            backend.available || backend.note.len() > 20,
            "an unavailable backend must explain itself: {backend:?}"
        );
        assert!(!backend.note.is_empty(), "{backend:?}");
    }

    // And the gate the CLI depends on: a backend is offered by `best` only when it
    // probes clean, and its refusal is the actionable exit-6 kind wherever the
    // machine is.
    match sandbox::best() {
        Some(best) => {
            best.probe().expect("best offers only what probes clean");
        }
        None => {
            let err = sandbox::require_one().unwrap_err();
            assert_eq!(err.exit_code(), 6);
            assert!(err.hint().unwrap().contains("doctor"), "{err}");
        }
    }

    // A confined command keeps the argv it was given — the same guarantee `confine`
    // used to make by construction, now checked where it can be checked for any rung
    // this machine provides.
    let double = Bare;
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
    let command = double
        .command(&argv, &BTreeMap::new(), Path::new("/"), Path::new("/tmp"))
        .expect("the double builds a command");
    let args: Vec<_> = command.get_args().collect();
    assert_eq!(args.last().copied(), Some(std::ffi::OsStr::new("true")));
    assert_eq!(
        command.get_program(),
        std::ffi::OsStr::new("/bin/sh"),
        "the program must survive confinement"
    );
}

/// The step spec is the promise about writes: the workspace, and nothing else.
#[test]
fn a_step_writes_in_its_workspace_and_scratch_only() {
    let spec = sandbox::spec_for(Path::new("/work"), Path::new("/tmp/gitiup-run-1"));
    let writes = spec.write_paths();
    assert!(writes.contains(&PathBuf::from("/work")), "{writes:?}");
    assert!(
        writes.contains(&PathBuf::from("/tmp/gitiup-run-1")),
        "{writes:?}"
    );
    assert!(!writes.contains(&PathBuf::from("/")), "{writes:?}");
    assert!(
        spec.egress.is_denied(),
        "a step has no network until someone asks for it: {:?}",
        spec.egress.describe()
    );
    // And the ladder agrees about where the writable tree is, for the rung that
    // enforces it in the kernel rather than by a mount.
    let landlock = sandbox::open("landlock").unwrap();
    assert!(
        landlock.guarantees().contains("Reads are NOT isolated")
            || landlock.guarantees().contains("nothing"),
        "{}",
        landlock.guarantees()
    );
}

#[test]
fn a_script_is_staged_verbatim_including_quotes_and_dollar_signs() {
    let _serial = serial();
    let workspace = workspace("script");
    let source = "on: push\njobs:\n  a:\n    steps:\n      - id: s\n        run: |\n          printf '%s\\n' \"a $x 'q' \\\"d\\\"\"\n          echo 'single'\n";
    let plan = plan_of(source);
    let report =
        gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &run_at(&workspace, "gitiup")).unwrap();
    let text = match &report.steps[0].stdout {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => panic!("expected text, got {other:?}"),
    };
    assert!(text.contains(r#"a  'q' "d""#), "{text}");
    assert!(text.contains("single"), "{text}");
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn the_workflows_own_env_reaches_the_step_and_a_literal_secret_does_not() {
    let _serial = serial();
    let workspace = workspace("env-block");
    let source = "on: push\njobs:\n  a:\n    env:\n      JOB_VAR: from-job\n      WHICH: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [linux]\n    steps:\n      - id: probe\n        env:\n          JOB_VAR: overridden\n          STEP_VAR: from-step\n        run: echo \"$JOB_VAR/$STEP_VAR/$WHICH\"\n";
    let plan = plan_of(source);
    let report =
        gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &run_at(&workspace, "gitiup")).unwrap();
    let text = match &report.steps[0].stdout {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => panic!("expected text, got {other:?}"),
    };
    assert_eq!(text.trim(), "overridden/from-step/linux", "{text}");

    // A step whose env is a secret *template* is refused, not handed the literal:
    // a step that believes it holds a token when it holds `${{ secrets.X }}` is a
    // worse failure than one that never started.
    let templated = plan_of(
        "on: push\njobs:\n  a:\n    steps:\n      - run: exit 0\n        env:\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
    );
    let err = gitiup_run::execute(
        &templated,
        &templated.jobs[0],
        &Bare,
        &run_at(&workspace, "gitiup"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("TOKEN"), "{err}");
    assert!(err.hint().unwrap().contains("--secret-name"), "{err}");
    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn a_job_that_needs_a_service_container_is_refused_rather_than_run_alone() {
    let _serial = serial();
    let workspace = workspace("services");
    let plan = plan_of(
        "on: push\njobs:\n  a:\n    services:\n      postgres:\n        image: postgres:16\n    steps:\n      - run: psql -c 'select 1'\n",
    );
    let err = gitiup_run::execute(&plan, &plan.jobs[0], &Bare, &run_at(&workspace, "gitiup"))
        .unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("postgres"), "{err}");
    assert!(err.hint().unwrap().contains("--execute"), "{err}");
    std::fs::remove_dir_all(&workspace).unwrap();
}

//! The `act` engine, end to end (giti-ic0, ADR-0006).
//!
//! act needs a container runtime, and the CI matrix has none of the three it would
//! need, so the engine is driven here by a **stub that speaks act's protocol**: the
//! same `act version 0.2.94` line, the same `--json` log lines, the same exit code.
//! That is not a shortcut around the claim, it *is* the claim this crate owns — act
//! produces a log, and gitiup turns that log into an attestation whose every field is
//! something gitiup actually saw. What the stub cannot prove (that a real container ran)
//! is exactly what the engine refuses to claim: the report says `sandbox: act` and
//! annotates that act's containment was act's.
//!
//! The logs below are act 0.2.94's own output shape, captured from
//! `act push -j lint --json` and extended with the step lines a run with a runtime
//! would have printed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use gitiup_attest::run::WorkflowSource;
use gitiup_attest::{GitOid, Policy, Tier};
use gitiup_run::act::{self, Request};
use gitiup_run::{Plan, Selector, Workflow};

/// Env is mutated by the secret tests and read while act is spawned; serialise so the
/// edition-2024 race the `exec.rs` file documents cannot happen here either.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const WORKFLOW: &str = "\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Test
        run: make test
      - name: Package
        run: make package
";

/// The JSON act 0.2.94 prints for a job that ran three steps and passed.
const LOG_SUCCESS: &str = "\
{\"level\":\"info\",\"msg\":\"Starting action executor\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\u2b50 Run Set up job\",\"step\":\"Set up job\",\"stepid\":[\"--setup-job\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83d\\ude80  Start image=cat-the-planet/base@sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"step\":\"Set up job\",\"stepid\":[\"--setup-job\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Set up job\",\"step\":\"Set up job\",\"stepResult\":\"success\",\"executionTime\":\"1.02s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | Checking out the repository\",\"step\":\"Checkout\",\"stepid\":[\"co\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Checkout\",\"step\":\"Checkout\",\"stepResult\":\"success\",\"executionTime\":\"2.4s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | cargo test --all\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Test\",\"step\":\"Test\",\"stepResult\":\"success\",\"executionTime\":\"3.1s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Package\",\"step\":\"Package\",\"stepResult\":\"success\",\"executionTime\":\"0.5s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"success\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83c\\udf89  Job succeeded\"}
";

/// The same job with `Test` failing: act echoes the container's exit status in the
/// step's own lines and closes the step with `stepResult: failure`.
const LOG_FAILURE: &str = "\
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | cargo test --all\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"error\",\"matrix\":{},\"msg\":\"  | error: test failed\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"error\",\"matrix\":{},\"msg\":\"  | exit status 101\",\"step\":\"Test\",\"stepid\":[\"\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u274c  Failure - Test\",\"step\":\"Test\",\"stepResult\":\"failure\",\"executionTime\":\"3.1s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"failure\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83d\\udc4b  Job failed\"}
";

/// `Test` was skipped by an `if:` (act logs skips at debug level only), so it never
/// appears; `Checkout` ran.
const LOG_PARTIAL: &str = "\
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  | Checking out\",\"step\":\"Checkout\",\"stepid\":[\"co\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u2705  Success - Checkout\",\"step\":\"Checkout\",\"stepResult\":\"success\",\"executionTime\":\"1s\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"success\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83c\\udf89  Job succeeded\"}
";

/// The log of a run that never started: act could not reach its runtime, and the
/// workflow's own steps were never reached.
const LOG_NO_RUNTIME: &str = "\
{\"level\":\"warning\",\"msg\":\"Couldn't get a valid docker connection\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83d\\ude80  Start image=cat-the-planet/base:latest\",\"step\":\"Set up job\",\"stepid\":[\"--setup-job\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"error\",\"matrix\":{},\"msg\":\"failed to connect to the docker API at unix:///var/run/docker.sock\",\"step\":\"Set up job\",\"stepid\":[\"--setup-job\"]}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"level\":\"info\",\"matrix\":{},\"msg\":\"  \\u274c  Failure - Set up job\",\"step\":\"Set up job\",\"stepResult\":\"failure\"}
{\"job\":\"ci.yml/build\",\"jobID\":\"build\",\"jobResult\":\"failure\",\"level\":\"info\",\"matrix\":{},\"msg\":\"\\ud83d\\udc4b  Job failed\"}
";

/// A directory that holds the workflow and a stub `act` speaking `log`.
struct Stub {
    dir: PathBuf,
    binary: PathBuf,
}

impl Stub {
    fn with(tag: &str, log: &str, exit: i32) -> Stub {
        let dir = std::env::temp_dir().join(format!("gitiup-act-{tag}-{}", std::process::id()));
        let workflows = dir.join(".github/workflows");
        std::fs::create_dir_all(&workflows).expect("temp tree");
        std::fs::write(workflows.join("ci.yml"), WORKFLOW).expect("workflow written");
        let transcript = dir.join("transcript.json");
        std::fs::write(&transcript, log).expect("log written");
        let binary = dir.join("act");
        // A stub binary: `--version` in act's own format, then the recorded transcript,
        // then act's exit code. Nothing else: the argv it receives is asserted on.
        std::fs::write(
            &binary,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'act version 0.2.94'; exit 0; fi\ncat '{}'\nexit {exit}\n",
                transcript.display()
            ),
        )
        .expect("stub written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Stub { dir, binary }
    }

    fn workflow_file(&self) -> PathBuf {
        self.dir.join(".github/workflows/ci.yml")
    }

    fn engine(&self) -> act::Engine {
        act::Engine::discover(Some(&self.binary)).expect("the stub answers --version")
    }

    fn request(&self) -> Request {
        let mut request = Request::new(
            GitOid::from_sha1_hex(&"b".repeat(40)).unwrap(),
            WorkflowSource::from_text(".github/workflows/ci.yml", WORKFLOW),
            self.workflow_file(),
            &self.dir,
        );
        request.now_us = Some(1_793_092_502_500_000);
        request.run_id = Some("0123456789abcdef".into());
        request.images = vec![(
            "ubuntu-latest".to_string(),
            "cat-the-planet/base@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )];
        request
    }

    fn cleanup(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn plan() -> Plan {
    let workflow = Workflow::parse(".github/workflows/ci.yml", WORKFLOW).unwrap();
    Plan::build(
        &workflow,
        &Selector {
            job: Some("build".into()),
            matrix: BTreeMap::new(),
        },
    )
    .unwrap()
}

fn text_of(step: &gitiup_attest::run::StepReport) -> String {
    match &step.stdout {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn stderr_of(step: &gitiup_attest::run::StepReport) -> String {
    match &step.stderr {
        gitiup_attest::run::Material::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

#[test]
fn an_act_run_is_local_and_says_who_actually_ran_it() {
    let _serial = serial();
    let stub = Stub::with("success", LOG_SUCCESS, 0);
    let plan = plan();
    let report = act::run(&plan.jobs[0], &stub.engine(), &stub.request()).unwrap();

    assert_eq!(report.provenance.tier, Tier::Local);
    // Not `docker`, not `act-docker`: the name is the engine's, because the containment
    // is act's and a policy has to say so by name.
    assert_eq!(report.provenance.sandbox.as_deref(), Some("act"));
    assert_eq!(report.provenance.runner, "act 0.2.94");
    assert_eq!(report.environment.provider.as_deref(), Some("act"));

    // One entry per planned step, in plan order — the rule every gitiup path holds.
    let names: Vec<&str> = report.steps.iter().map(|step| step.name.as_str()).collect();
    assert_eq!(names, vec!["Checkout", "Test", "Package"]);
    assert!(
        report
            .steps
            .iter()
            .all(|step| step.outcome == Some(gitiup_attest::StepOutcome::Success)),
        "{:?}",
        report.steps
    );
    assert_eq!(report.steps[0].uses.as_deref(), Some("actions/checkout@v4"));
    assert!(text_of(&report.steps[1]).contains("cargo test --all"));
    assert_eq!(
        report.steps[1].timing.as_ref().and_then(|t| t.duration_us),
        Some(3_100_000),
        "act's own executionTime is the only timing there is"
    );

    let annotations = &report.claims.annotations;
    assert_eq!(annotations["x_engine_version"], "0.2.94");
    assert_eq!(annotations["x_engine_exit"], "0");
    assert!(
        annotations["x_engine_image"].starts_with("cat-the-planet/base@sha256:"),
        "{}",
        annotations["x_engine_image"]
    );
    assert!(annotations["x_sandbox_guarantees"].contains("host network"));
    // The action is fetched by a moving tag, which is what the workflow asked for and
    // what makes the run unreproducible; the report says so instead of waiting for a
    // reader to notice the `@v4`.
    assert!(
        annotations["x_run_notes"].contains("moving ref"),
        "{}",
        annotations["x_run_notes"]
    );
    assert!(annotations["x_run_mode"].contains("act 0.2.94"));
    // The exact command is recorded: a verifier can ask whether that is the run they
    // would have chosen, and does not have to trust a description of it.
    let command = &annotations["x_engine_command"];
    for flag in [
        "--json",
        "--container-daemon-socket -",
        "--container-options-policy restrict",
        "--use-gitignore",
        "-j build",
        "-P ubuntu-latest=cat-the-planet/base@sha256:",
    ] {
        assert!(command.contains(flag), "{command} is missing `{flag}`");
    }

    let manifest = gitiup_run::manifest_for(&report).unwrap();
    manifest.validate().unwrap();
    assert_eq!(manifest.result.provenance.sandbox.as_deref(), Some("act"));
    stub.cleanup();
}

#[test]
fn a_step_failure_keeps_the_number_act_printed() {
    let _serial = serial();
    let stub = Stub::with("failure", LOG_FAILURE, 1);
    let plan = plan();
    let report = act::run(&plan.jobs[0], &stub.engine(), &stub.request()).unwrap();
    let by_name: BTreeMap<_, _> = report
        .steps
        .iter()
        .map(|step| (step.name.clone(), step))
        .collect();
    assert_eq!(by_name["Test"].exit_code, 101);
    assert_eq!(
        by_name["Test"].outcome,
        Some(gitiup_attest::StepOutcome::Failure)
    );
    // Steps act never reached are skipped, not passed — and say why, in the stream a
    // reader looks at for a step that did not run.
    assert_eq!(
        by_name["Package"].outcome,
        Some(gitiup_attest::StepOutcome::Skipped)
    );
    assert!(stderr_of(by_name["Package"]).contains("no result"));
    assert!(stderr_of(by_name["Checkout"]).contains("no result"));
    assert!(
        report.claims.annotations["x_run_notes"].contains("Package"),
        "the absence is said out loud, not just encoded: {}",
        report.claims.annotations["x_run_notes"]
    );
    assert_eq!(report.provenance.tier, Tier::Local);
    assert_eq!(report.claims.annotations["x_engine_exit"], "1");
    gitiup_run::manifest_for(&report)
        .unwrap()
        .validate()
        .unwrap();
    stub.cleanup();
}

#[test]
fn a_step_act_skipped_silently_is_skipped_loudly() {
    let _serial = serial();
    let stub = Stub::with("partial", LOG_PARTIAL, 0);
    let plan = plan();
    let report = act::run(&plan.jobs[0], &stub.engine(), &stub.request()).unwrap();
    assert_eq!(
        report.steps[1].outcome,
        Some(gitiup_attest::StepOutcome::Skipped),
        "act logs `if:` skips at debug level only, so the absence is the observation"
    );
    let notes = &report.claims.annotations["x_run_notes"];
    assert!(notes.contains("no result"), "{notes}");
    assert!(
        notes.contains("Test") && notes.contains("Package"),
        "{notes}"
    );
    stub.cleanup();
}

#[test]
fn a_run_act_could_not_start_is_refused_rather_than_attested() {
    let _serial = serial();
    let stub = Stub::with("noruntime", LOG_NO_RUNTIME, 1);
    let plan = plan();
    let err = act::run(&plan.jobs[0], &stub.engine(), &stub.request()).unwrap_err();
    // Nothing of the workflow ran, so there is nothing to attest: the refusal quotes
    // act's own words rather than inventing a report.
    assert!(
        err.detail().contains("could not set the job up"),
        "{}",
        err.detail()
    );
    assert!(
        err.detail().contains("docker API"),
        "the reason has to be in the refusal: {}",
        err.detail()
    );
    stub.cleanup();
}

#[test]
fn secrets_are_names_on_the_command_line_and_values_only_in_the_environment() {
    let _serial = serial();
    // Set only for this test process, and only by name into act's environment; the
    // `serial()` lock above is what makes the edition-2024 `set_var` contract hold.
    unsafe { std::env::set_var("GITIUP_TEST_TOKEN", "a-value-nobody-must-see-in-argv") };
    let stub = Stub::with("secrets", LOG_SUCCESS, 0);
    let plan = plan();
    let mut request = stub.request();
    request.secret_names = vec!["GITIUP_TEST_TOKEN".to_string()];
    let engine = stub.engine();
    let report = act::run(&plan.jobs[0], &engine, &request).unwrap();
    let command = &report.claims.annotations["x_engine_command"];
    assert!(command.contains("-s GITIUP_TEST_TOKEN"), "{command}");
    assert!(
        !command.contains("a-value-nobody-must-see-in-argv"),
        "a secret value reached the argv: {command}"
    );
    assert_eq!(report.secret_names, vec!["GITIUP_TEST_TOKEN".to_string()]);
    unsafe { std::env::remove_var("GITIUP_TEST_TOKEN") };

    // And a named secret that is not set is a refusal, not a step that ran without it.
    let mut missing = stub.request();
    missing.secret_names = vec!["GITIUP_TEST_ABSENT".to_string()];
    let err = act::run(&plan.jobs[0], &engine, &missing).unwrap_err();
    assert!(err.detail().contains("GITIUP_TEST_ABSENT"), "{err}");
    stub.cleanup();
}

#[test]
fn the_engine_refuses_before_it_spawns() {
    let _serial = serial();
    let stub = Stub::with("refusals", LOG_SUCCESS, 0);
    let plan = plan();
    let engine = stub.engine();

    // act stops and asks a terminal which image to pull; a runner cannot answer, so
    // the refusal names the flag instead.
    let mut no_image = stub.request();
    no_image.images = Vec::new();
    let err = act::run(&plan.jobs[0], &engine, &no_image).unwrap_err();
    assert!(err.detail().contains("which"), "{err}");
    assert!(err.hint().unwrap().contains("--act-image"), "{err}");

    // A checkout that carries an `.actrc` can steer act; the engine will not run one.
    std::fs::write(stub.dir.join(".actrc"), "--privileged\n").unwrap();
    let err = act::run(&plan.jobs[0], &engine, &stub.request()).unwrap_err();
    assert!(err.detail().contains(".actrc"), "{err}");
    std::fs::remove_file(stub.dir.join(".actrc")).unwrap();

    // A missing workflow file is a refusal with a path in it.
    let mut ghost = stub.request();
    ghost.workflow_file = stub.dir.join("nowhere.yml");
    let err = act::run(&plan.jobs[0], &engine, &ghost).unwrap_err();
    assert!(err.detail().contains("nowhere.yml"), "{err}");

    // A job that runs on the host is nothing to attest.
    let host = Workflow::parse(
        "w.yml",
        "on: push\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n",
    )
    .unwrap();
    let host_plan = Plan::build(
        &host,
        &Selector {
            job: Some("build".into()),
            matrix: BTreeMap::new(),
        },
    )
    .unwrap();
    let err = act::run(&host_plan.jobs[0], &engine, &stub.request()).unwrap_err();
    assert!(err.detail().contains("self-hosted"), "{err}");

    // An unpinned action ref is not refused — it is what CI does — but it is said.
    let notes = act::check(&plan.jobs[0], WORKFLOW).unwrap();
    let _ = notes;
    stub.cleanup();
}

#[test]
fn the_sandbox_name_is_one_a_policy_has_to_choose() {
    // This is the whole safety argument for `sandbox: act`, checked where the code that
    // enforces it lives.
    let default = Policy::default();
    assert!(
        !gitiup_sandbox::policy::allows(&default, "act"),
        "a policy that named no sandbox must not be satisfied by an engine it never heard of"
    );
    assert!(gitiup_sandbox::policy::allows(&default, "docker"));
    let chosen = Policy {
        allowed_sandboxes: vec!["act".to_string()],
        ..Policy::default()
    };
    assert!(gitiup_sandbox::policy::allows(&chosen, "act"));
    // And a policy for stranger's jobs cannot list it at all: narrowing refuses a name
    // this build cannot open, so a quorum can never be satisfied by an act run.
    let err = gitiup_sandbox::policy::narrow(&chosen).unwrap_err();
    assert!(err.detail().contains("act"), "{err}");
}

#[test]
fn a_binary_that_is_not_act_is_refused() {
    let _serial = serial();
    let dir = std::env::temp_dir().join(format!("gitiup-act-notact-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let binary = dir.join("act");
    std::fs::write(&binary, "#!/bin/sh\necho 'not the act you meant'\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let err = act::Engine::discover(Some(&binary)).unwrap_err();
    assert!(err.detail().contains("did not look like act"), "{err}");
    let missing = act::Engine::discover(Some(Path::new("/nonexistent/act"))).unwrap_err();
    assert!(missing.detail().contains("did not run"), "{missing}");
    assert!(
        missing.hint().unwrap().contains("nektosact.com"),
        "the refusal has to say where the engine comes from"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

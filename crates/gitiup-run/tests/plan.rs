//! The plan: matrix expansion, one-job-per-attestation, and what the plan text is
//! allowed to contain.

use std::collections::BTreeMap;

use gitiup_run::{Plan, Selector, Workflow};

const MATRIX: &str = "\
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-14]
        profile: [debug, release]
    steps:
      - run: cargo test
";

fn plan(source: &str, selector: &Selector) -> Plan {
    let workflow = Workflow::parse(".github/workflows/ci.yml", source).unwrap();
    Plan::build(&workflow, selector).unwrap()
}

#[test]
fn a_matrix_expands_to_one_run_per_arm() {
    let plan = plan(MATRIX, &Selector::default());
    assert_eq!(plan.jobs.len(), 4, "2 × 2 arms");
    let arms: Vec<String> = plan.jobs.iter().map(|job| job.arm_text()).collect();
    assert_eq!(
        arms,
        vec![
            " [os=ubuntu-24.04, profile=debug]",
            " [os=ubuntu-24.04, profile=release]",
            " [os=macos-14, profile=debug]",
            " [os=macos-14, profile=release]",
        ]
    );
    assert_eq!(plan.step_count(), 4, "one step per arm");
}

#[test]
fn one_arm_can_be_selected_and_a_wrong_one_is_refused_actionably() {
    let selector = Selector {
        job: None,
        matrix: BTreeMap::from([("profile".to_string(), "release".to_string())]),
    };
    let plan = plan(MATRIX, &selector);
    assert_eq!(plan.jobs.len(), 2);
    assert!(
        plan.jobs
            .iter()
            .all(|job| job.matrix.get("profile").map(String::as_str) == Some("release"))
    );

    let workflow = Workflow::parse(".github/workflows/ci.yml", MATRIX).unwrap();
    let err = Plan::build(
        &workflow,
        &Selector {
            job: None,
            matrix: BTreeMap::from([("profile".to_string(), "ship".to_string())]),
        },
    )
    .unwrap_err();
    assert!(err.detail().contains("no matrix arm"), "{err}");
    assert!(err.hint().unwrap().contains("debug, release"), "{err}");
}

#[test]
fn an_attestation_is_about_one_job_and_says_so_when_it_is_not() {
    let workflow = Workflow::parse(
        "ci.yml",
        "on: push\njobs:\n  a:\n    steps:\n      - run: a\n  b:\n    steps:\n      - run: b\n",
    )
    .unwrap();
    let err = Plan::build(&workflow, &Selector::default()).unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("2 jobs"), "{err}");
    assert!(err.detail().contains("a, b"), "{err}");
    assert!(err.hint().unwrap().contains("--job"), "{err}");

    let plan = Plan::build(
        &workflow,
        &Selector {
            job: Some("b".into()),
            matrix: BTreeMap::new(),
        },
    )
    .unwrap();
    assert_eq!(plan.jobs.len(), 1);
    assert_eq!(plan.jobs[0].id, "b");

    let err = Plan::build(
        &workflow,
        &Selector {
            job: Some("c".into()),
            matrix: BTreeMap::new(),
        },
    )
    .unwrap_err();
    assert!(err.detail().contains("no job `c`"), "{err}");
}

#[test]
fn the_plan_text_says_what_would_run_and_what_was_assumed() {
    let source = "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n      - name: Test\n        if: github.event_name == 'pull_request'\n        run: make test\n        shell: bash\n";
    let plan = plan(source, &Selector::default());
    let text = plan.describe();
    for expected in [
        "gitiup run plan",
        "workflow   .github/workflows/ci.yml",
        "job build",
        "runs-on    ubuntu-24.04",
        "action   actions/checkout@v4 (ref not resolved",
        "script   make test",
        "if       github.event_name == 'pull_request' (not evaluated)",
        "assumed to run",
        "assumed success",
    ] {
        assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
    }
    // A plan is hashed, so nothing about the machine it was made on may appear.
    for forbidden in [
        std::env::temp_dir().display().to_string().as_str(),
        "/home/",
        "/Users/",
    ] {
        assert!(
            !text.contains(forbidden),
            "the plan leaked `{forbidden}`:\n{text}"
        );
    }
}

#[test]
fn a_long_script_is_summarised_not_dumped() {
    let source = format!(
        "on: push\njobs:\n  a:\n    steps:\n      - run: |\n{}\n",
        (1..=40)
            .map(|line| format!("        echo {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let plan = plan(&source, &Selector::default());
    let text = plan.describe();
    assert!(text.contains("echo 6"), "{text}");
    assert!(!text.contains("echo 7\n"), "the whole script was dumped");
    assert!(text.contains("more line(s)"), "{text}");
}

#[test]
fn an_explosion_of_arms_is_refused_before_it_prints() {
    let source = format!(
        "on: push\njobs:\n  a:\n    strategy:\n      matrix:\n        x: [{}]\n        y: [{}]\n    steps:\n      - run: x\n",
        (0..30)
            .map(|i| format!("a{i}"))
            .collect::<Vec<_>>()
            .join(", "),
        (0..30)
            .map(|i| format!("b{i}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    let workflow = Workflow::parse("ci.yml", &source).unwrap();
    let err = Plan::build(&workflow, &Selector::default()).unwrap_err();
    assert!(err.detail().contains("matrix arms"), "{err}");
    assert!(err.hint().unwrap().contains("--matrix"), "{err}");
}

#[test]
fn an_unpinned_container_image_is_reported_as_unpinnable() {
    let plan = plan(
        "on: push\njobs:\n  a:\n    container:\n      image: debian:trixie\n    steps:\n      - run: x\n",
        &Selector::default(),
    );
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("not digest-pinned")),
        "{:?}",
        plan.warnings
    );
}

#[test]
fn planning_the_same_workflow_twice_is_the_same_plan() {
    // The precondition for a plan being worth a digest: the planner adds nothing
    // that varies between runs or machines.
    let one = plan(MATRIX, &Selector::default());
    let two = plan(MATRIX, &Selector::default());
    assert_eq!(one, two);
    assert_eq!(one.describe(), two.describe());
}

#[test]
fn env_is_part_of_the_plan_because_a_step_without_it_is_a_different_step() {
    // `env:` is in almost every real workflow. Showing it is not decoration: a plan
    // that omitted it would describe a run the workflow would not produce — and a
    // standing "env ignored" note would train readers to ignore the notes that matter.
    let plan = plan(
        "on: push\njobs:\n  a:\n    env:\n      RUST_BACKTRACE: 1\n    steps:\n      - name: Test\n        env:\n          RUST_LOG: debug\n        run: cargo test\n",
        &Selector::default(),
    );
    let text = plan.describe();
    assert!(text.contains("env         RUST_BACKTRACE = 1"), "{text}");
    assert!(text.contains("env      RUST_LOG = debug"), "{text}");
    // And the plan no longer claims it dropped the block.
    assert!(
        !plan.warnings.iter().any(|w| w.contains("env")),
        "{:?}",
        plan.warnings
    );
}

#[test]
fn a_service_container_is_still_said_out_loud_because_the_planner_runs_none() {
    // The counterpart of the test above: what really is not modelled must not be
    // quietly accepted, or a plan reads as if the database were there.
    let plan = plan(
        "on: push\njobs:\n  a:\n    services:\n      postgres:\n        image: postgres\n    steps:\n      - run: psql --version\n",
        &Selector::default(),
    );
    let text = plan.describe();
    assert!(
        plan.warnings.iter().any(|warning| {
            warning.contains("service container(s) postgres")
                && warning.contains("--execute refuses")
        }),
        "{:?}",
        plan.warnings
    );
    // …and in the plan text itself, not only in a warning a caller might drop.
    assert!(
        text.contains("services    postgres (none of them started by a plan)"),
        "{text}"
    );
}

//! Reading a workflow file: what the planner accepts, and — more importantly — what
//! it refuses rather than guesses about.

use gitiup_run::Workflow;
use gitiup_run::yaml;

const CI: &str = "\
# The CI the ticket's example workflow: matrix, actions, a script, and a conditional.
name: CI
'on':
  push:
    branches: [main, 'release/**']
  pull_request:
  workflow_dispatch:
    inputs:
      jobs:
        description: how many
        default: 4
        required: true
      draft:
        default: false

env:
  CARGO_TERM_COLOR: always

jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Rustfmt
        run: cargo fmt --check

  test:
    name: Test suite
    needs: [lint]
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-24.04, macos-14]
        profile: [debug, release]
    env:
      RUST_BACKTRACE: 1
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Build and test
        run: |
          # two lines, one comment, one blank line: all of it is the script
          cargo build --profile ${{ matrix.profile }}

          cargo test --profile ${{ matrix.profile }}
        env:
          RUSTFLAGS: '-D warnings'
        if: github.event_name == 'pull_request'
      - run: >
          echo folded
          and folded again
      - name: Publish
        if: success()
        run: ./publish.sh
";

#[test]
fn a_real_workflow_parses_into_a_plan_shape() {
    let workflow = Workflow::parse(".github/workflows/ci.yml", CI).unwrap();
    assert_eq!(workflow.name.as_deref(), Some("CI"));
    // `on:` is a key, not YAML 1.1's `true`, and the mapping form lists triggers.
    assert_eq!(
        workflow.triggers,
        vec!["push", "pull_request", "workflow_dispatch"]
    );
    assert_eq!(workflow.jobs.len(), 2);

    let lint = &workflow.jobs[0];
    assert_eq!(lint.id, "lint");
    assert_eq!(lint.runs_on.as_deref(), Some("ubuntu-24.04"));
    assert_eq!(lint.steps.len(), 2);
    assert_eq!(lint.steps[0].uses.as_deref(), Some("actions/checkout@v4"));
    // A step with no `name:` is named by its `uses:`, as GitHub names it.
    assert_eq!(lint.steps[0].name, "actions/checkout@v4");
    assert_eq!(lint.steps[1].name, "Rustfmt");

    let test = &workflow.jobs[1];
    assert_eq!(test.name.as_deref(), Some("Test suite"));
    assert_eq!(test.needs, vec!["lint".to_string()]);
    assert_eq!(
        test.matrix,
        vec![
            (
                "os".to_string(),
                vec!["ubuntu-24.04".to_string(), "macos-14".to_string()]
            ),
            (
                "profile".to_string(),
                vec!["debug".to_string(), "release".to_string()]
            ),
        ]
    );
    assert_eq!(test.steps.len(), 4);
    assert_eq!(
        test.steps[0].inputs,
        vec![("fetch-depth".to_string(), "0".to_string())]
    );
    assert_eq!(test.steps[0].env, Vec::new());
    assert_eq!(
        test.steps[1].env,
        vec![("RUSTFLAGS".to_string(), "-D warnings".to_string())]
    );
    assert_eq!(
        test.steps[1].condition.as_deref(),
        Some("github.event_name == 'pull_request'")
    );
}

#[test]
fn a_block_scalar_is_the_script_including_its_comments_and_blanks() {
    // The regression this exists for: dropping a `#` line or a blank line out of a
    // `run:` body would change the script that gets executed, and nobody would see
    // it. Block scalars are content, not YAML trivia.
    let workflow = Workflow::parse("ci.yml", CI).unwrap();
    let script = workflow.jobs[1].steps[1]
        .run
        .as_deref()
        .expect("the build step runs a script");
    assert_eq!(
        script,
        "# two lines, one comment, one blank line: all of it is the script\n\
         cargo build --profile ${{ matrix.profile }}\n\
         \n\
         cargo test --profile ${{ matrix.profile }}\n"
    );
}

#[test]
fn a_folded_block_scalar_folds() {
    let workflow = Workflow::parse("ci.yml", CI).unwrap();
    assert_eq!(
        workflow.jobs[1].steps[2].run.as_deref(),
        Some("echo folded and folded again\n")
    );
}

#[test]
fn dispatch_input_defaults_are_collected_not_invented() {
    let workflow = Workflow::parse("ci.yml", CI).unwrap();
    assert_eq!(
        workflow.dispatch_input_names(),
        vec!["jobs".to_string(), "draft".to_string()]
    );
    use gitiup_attest::InputValue;
    assert_eq!(
        workflow.dispatch_inputs,
        vec![
            ("jobs".to_string(), InputValue::Int(4)),
            ("draft".to_string(), InputValue::Bool(false)),
        ]
    );
}

#[test]
fn a_reusable_workflow_call_is_a_job_with_no_steps() {
    let workflow = Workflow::parse(
        "release.yml",
        "on: push\njobs:\n  call:\n    uses: ./other.yml\n    with:\n      x: 1\n",
    )
    .unwrap();
    assert_eq!(workflow.jobs[0].uses.as_deref(), Some("./other.yml"));
    assert!(workflow.jobs[0].steps.is_empty());
    assert!(
        workflow
            .warnings
            .iter()
            .any(|warning| warning.contains("reusable workflow")),
        "{:?}",
        workflow.warnings
    );
}

// ---------------------------------------------------------------- refusals ---

fn refused(source: &str, needle: &str) {
    let err = Workflow::parse("ci.yml", source).unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Invalid);
    assert_eq!(err.exit_code(), 6);
    assert!(
        err.detail().contains(needle),
        "expected `{needle}` in: {err}"
    );
    assert!(err.hint().is_some(), "{err}: a refusal says what to do");
}

#[test]
fn a_step_must_do_something() {
    refused(
        "on: push\njobs:\n  a:\n    steps:\n      - name: nothing\n",
        "neither `uses:` nor `run:`",
    );
    refused(
        "on: push\njobs:\n  a:\n    steps:\n      - uses: x@v1\n        run: echo\n",
        "both `uses:` and `run:`",
    );
    refused("on: push\njobs:\n  a:\n    steps: []\n", "empty `steps:`");
}

#[test]
fn a_workflow_without_jobs_is_refused() {
    refused("name: nothing\non: push\n", "no `jobs:`");
    refused("name: nothing\non: push\njobs: {}\n", "`jobs:` is empty");
    refused(
        "name: no triggers\njobs:\n  a:\n    steps:\n      - run: x\n",
        "no `on:`",
    );
}

#[test]
fn yaml_features_beyond_the_subset_are_named_not_guessed() {
    refused("jobs:\n  a:\n    steps: *shared\n", "alias");
    refused("jobs:\n  base: &base\n    a: 1\n", "anchor");
    refused("jobs:\n  a:\n    x: !!str 1\n", "tag");
    refused("a: 'unterminated\n", "unterminated");
    refused("a:\n\tb: 1\n", "tab");
    refused("name: x\n---\nname: y\n", "more than one document");
    refused("a: 1\na: 2\n", "duplicate key");
    refused(
        "matrix:\n  os: [one,\n        two]\n",
        "spans more than one line",
    );
    refused(
        "on: push\njobs:\n  a:\n  b: 1\n   c: 2\n",
        "unexpected content",
    );
}

#[test]
fn quoted_scalars_keep_what_the_quotes_were_for() {
    let doc =
        yaml::parse("a: 'it''s here'\nb: \"tab\\there\"\nc: 0x10 # trailing\nd: 5\n").unwrap();
    let map = doc.as_map().unwrap();
    assert_eq!(map.str_field("a"), Some("it's here"));
    assert_eq!(map.str_field("b"), Some("tab\there"));
    assert_eq!(map.str_field("c"), Some("0x10"));
    assert_eq!(map.str_field("d"), Some("5"));
}

#[test]
fn a_list_of_labels_and_a_map_of_labels_both_reach_one_label() {
    // `runs-on` is written three ways in the wild; a plan that only read one would
    // silently drop the environment claim.
    for (source, want) in [
        ("runs-on: ubuntu-24.04", "ubuntu-24.04"),
        ("runs-on: [self-hosted, linux]", "self-hosted"),
    ] {
        let source = format!("on: push\njobs:\n  a:\n    {source}\n    steps:\n      - run: x\n");
        let workflow = Workflow::parse("ci.yml", &source).unwrap();
        assert_eq!(workflow.jobs[0].runs_on.as_deref(), Some(want));
    }
}

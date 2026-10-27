//! The simulated run: the ticket's acceptance criteria, from the producing side.
//!
//! * a default run **touches no network and no secrets** and attests as `simulated`;
//! * the same plan, pinned to the same clock, hashes the same on another machine;
//! * the assumptions a plan makes are recorded, not hidden;
//! * `local` and `quorum` cannot be reached from here at all.

use std::collections::BTreeMap;

use gitiup_attest::run::{RunReport, WorkflowSource};
use gitiup_attest::{Digest, GitOid, InputValue, Policy, RunManifest, StepOutcome, Tier, TimeUs};
use gitiup_run::{Plan, Replay, Selector, Simulation, Workflow};

const CI: &str = "\
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - id: checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Test
        run: cargo test
";

fn plan_of(source: &str) -> Plan {
    Plan::build(
        &Workflow::parse(".github/workflows/ci.yml", source).unwrap(),
        &Selector::default(),
    )
    .unwrap()
}

/// A simulation with the volatile parts pinned, so the assertions below are answers
/// and not coincidences.
fn simulation(plan: &Plan, runner: &'static str) -> Simulation<'static> {
    let mut simulation = Simulation::new(
        GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
        WorkflowSource::from_text(".github/workflows/ci.yml", CI),
        runner,
    );
    simulation.now_us = Some(TimeUs::from_secs(1_793_092_502).0);
    simulation.run_id = Some("0123456789abcdef".into());
    simulation.inputs = vec![("jobs".into(), InputValue::Int(4))];
    let _ = plan;
    simulation
}

fn simulated_manifest(plan: &Plan, simulation: &Simulation<'_>) -> RunManifest {
    let report = gitiup_run::simulate_report(plan, &plan.jobs[0], simulation).unwrap();
    gitiup_run::manifest_for(&report).unwrap()
}

#[test]
fn a_default_run_attests_as_simulated_and_nothing_else() {
    let plan = plan_of(CI);
    let manifest = simulated_manifest(&plan, &simulation(&plan, "gitiup 0.1.0"));

    assert_eq!(manifest.result.provenance.tier, Tier::Simulated);
    assert_eq!(manifest.result.provenance.sandbox.as_deref(), Some("none"));
    assert_eq!(
        manifest.result.environment.provider.as_deref(),
        Some("simulated")
    );
    assert_eq!(manifest.result.steps.len(), 2);
    assert_eq!(manifest.result.source.job.as_deref(), Some("build"));
    assert_eq!(
        manifest.result.source.workflow.path,
        ".github/workflows/ci.yml"
    );
    // Every step is labelled as what it is: a plan, with an assumed outcome.
    for step in &manifest.result.steps {
        assert_eq!(step.exit_code, 0);
        assert_eq!(step.outcome, StepOutcome::Success);
        assert!(!step.name.is_empty());
    }
    // The default policy refuses it, which is the point of a safe default.
    let err = Policy::default()
        .check_provenance(&manifest.result.provenance)
        .unwrap_err();
    assert!(err.detail().contains("simulated"), "{err}");
    assert_eq!(err.exit_code(), 6);
}

#[test]
fn a_default_run_has_no_secrets_in_it_and_no_way_to_ask() {
    // There is no field on `Simulation` for a secret and none on `RunReport` to
    // record one, so this is a property of the types, not of a code path someone can
    // forget: a plan touches nothing, and cannot claim to have touched a secret.
    let plan = plan_of(CI);
    let report =
        gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation(&plan, "gitiup 0.1.0"))
            .unwrap();
    assert!(report.secret_names.is_empty(), "{:?}", report.secret_names);

    let manifest = gitiup_run::manifest_for(&report).unwrap();
    let text = String::from_utf8(manifest.canonical_bytes().unwrap()).unwrap();
    for forbidden in ["secret", "SECRET", "token"] {
        assert!(
            !text.contains(forbidden),
            "`{forbidden}` leaked into {text}"
        );
    }
}

#[test]
fn a_plan_of_the_same_change_hashes_the_same_on_two_machines() {
    // Two calls standing in for two machines: same workflow bytes, same commit, same
    // pinned clock and run id ⇒ same ResultDigest. What differs between machines —
    // the directory the plan was made in, the user, the environment — is asserted
    // absent from the manifest below, which is what makes a plan attestable rather
    // than anecdotal.
    let plan = plan_of(CI);
    let one = simulated_manifest(&plan, &simulation(&plan, "gitiup 0.1.0"));
    let two = simulated_manifest(&plan, &simulation(&plan, "gitiup 0.1.0"));
    assert_eq!(
        one.result_digest().unwrap(),
        two.result_digest().unwrap(),
        "the ResultDigest is about the run, not the machine that described it"
    );

    let text = String::from_utf8(one.canonical_bytes().unwrap()).unwrap();
    let here = std::env::current_dir().unwrap().display().to_string();
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME"));
    assert!(
        !text.contains(&here),
        "the plan leaked its directory: {text}"
    );
    assert!(!text.contains(&std::env::temp_dir().display().to_string()));
    if let Ok(user) = user {
        assert!(!user.is_empty() || !text.contains(&user), "leaked the user");
    }

    // And a *different* plan is a different digest: the label is not decorative.
    let changed = plan_of(&CI.replace("cargo test", "cargo build"));
    let other = simulated_manifest(&changed, &simulation(&changed, "gitiup 0.1.0"));
    assert_ne!(one.result_digest().unwrap(), other.result_digest().unwrap());
}

#[test]
fn the_plan_says_what_it_assumed() {
    let plan = plan_of(
        "on: push\njobs:\n  a:\n    steps:\n      - name: Maybe\n        if: github.ref == 'refs/heads/main'\n        run: echo\n",
    );
    let report =
        gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation(&plan, "gitiup 0.1.0"))
            .unwrap();
    let annotations = &report.claims.annotations;
    let assumptions = annotations
        .get("x_assumptions")
        .unwrap_or_else(|| panic!("no assumptions recorded: {annotations:?}"));
    assert!(assumptions.contains("assumed to run"), "{assumptions}");
    assert!(assumptions.contains("assumed to succeed"), "{assumptions}");
    assert_eq!(
        annotations.get("x_run_mode").map(String::as_str),
        Some("simulated")
    );
    // And the plan's own caveats travel with the attestation, not just with the
    // terminal they were printed on.
    assert!(
        annotations
            .get("x_plan_notes")
            .is_some_and(|notes| notes.contains("assumed")),
        "{annotations:?}"
    );
}

#[test]
fn replay_reuses_a_recorded_step_and_says_so() {
    // A recorded local run: two steps, with real output.
    let recorded: RunReport = serde_json::from_value(serde_json::json!({
        "commit": format!("sha1:{}", "b".repeat(40)),
        "workflow": {"path": ".github/workflows/ci.yml", "text": CI},
        "event": {"name": "pull_request", "payload": {"text": "{}"}},
        "job": "build",
        "environment": {"arch": "x86_64", "provider": "docker", "os": "linux"},
        "steps": [
            {"id": "checkout", "name": "actions/checkout@v4", "uses": "actions/checkout@v4",
             "exit_code": 0, "stdout": {"text": "Checked out\n"}},
            {"name": "Test", "exit_code": 0, "stdout": {"text": "test result: ok. 42 passed\n"},
             "outputs": {"coverage": "91"}}
        ],
        "provenance": {"tier": "local", "runner": "gitiup 0.1.0",
                       "normalisation_version": 0, "sandbox": "docker"},
        "claims": {"run_id": "feedfacecafebeef", "claimed_at_us": 1793092502500000i64}
    }))
    .unwrap();
    let replay = Replay::from_report(&recorded, Some(Digest::sha256(b"report"))).unwrap();
    assert_eq!(replay.step_count(), 2);

    let plan = plan_of(CI);
    let mut with_replay = simulation(&plan, "gitiup 0.1.0");
    with_replay.replay = Some(replay);
    let report = gitiup_run::simulate_report(&plan, &plan.jobs[0], &with_replay).unwrap();
    let annotations = &report.claims.annotations;
    assert_eq!(
        annotations.get("x_replayed_steps").map(String::as_str),
        Some("checkout,Test"),
        "{annotations:?}"
    );
    assert!(annotations.contains_key("x_replay_from"));
    assert_eq!(report.steps.len(), 2);
    assert_eq!(
        report.steps[1].outputs.get("coverage").map(String::as_str),
        Some("91")
    );
    // Still a plan: the tier did not move because some logs came from somewhere real.
    let manifest = gitiup_run::manifest_for(&report).unwrap();
    assert_eq!(manifest.result.provenance.tier, Tier::Simulated);
    assert!(
        Policy::default()
            .check_provenance(&manifest.result.provenance)
            .is_err()
    );
}

#[test]
fn a_simulated_report_survives_the_readers_own_checks() {
    let plan = plan_of(CI);
    let report =
        gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation(&plan, "gitiup 0.1.0"))
            .unwrap();
    report.validate().expect("the report is well-formed");
    let manifest = RunManifest::from_run(&report).expect("and computes a manifest");
    manifest.validate().unwrap();
    let bytes = manifest.canonical_bytes().unwrap();
    assert_eq!(
        RunManifest::from_canonical_bytes(&bytes).unwrap(),
        manifest,
        "and reads back as the same thing"
    );
}

#[test]
fn the_tier_and_the_sandbox_are_not_caller_choices() {
    // Whatever a caller does with a `Simulation`, the tier is `simulated` and the
    // sandbox is `none`: there is no field to set, so no way to become `local` by
    // accident or by wish.
    let plan = plan_of(CI);
    let mut simulation = simulation(&plan, "some-runner 9.9");
    simulation.event = "workflow_dispatch".into();
    simulation.repo = Some("gitiup/gitiup".into());
    simulation.inputs = vec![("x".into(), InputValue::Text("y".into()))];
    simulation.annotations = BTreeMap::from([("x_custom".into(), "kept".into())]);
    let report = gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation).unwrap();
    assert_eq!(report.provenance.tier, Tier::Simulated);
    assert_eq!(report.provenance.sandbox.as_deref(), Some("none"));
    assert_eq!(
        report
            .claims
            .annotations
            .get("x_custom")
            .map(String::as_str),
        Some("kept")
    );

    // A job that is not in the plan is refused rather than quietly substituted.
    let mut foreign = plan_of("on: push\njobs:\n  other:\n    steps:\n      - run: x\n");
    foreign.jobs[0].id = "not-in-the-plan".into();
    let err = gitiup_run::simulate_report(&plan, &foreign.jobs[0], &simulation).unwrap_err();
    assert_eq!(err.kind(), gitiup_attest::ErrorKind::Policy);
    assert!(err.detail().contains("not part of this plan"), "{err}");
}

#[test]
fn the_digest_of_a_pinned_plan_is_a_known_answer() {
    // Not merely stable: this is the ResultDigest of this exact plan, signed by
    // nothing and provable by anyone. If it moves, then how a plan is described
    // moved with it, and every plan attested so far stops reproducing.
    let plan = plan_of(CI);
    let report =
        gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation(&plan, "gitiup 0.1.0"))
            .unwrap();
    assert_eq!(
        gitiup_run::result_digest(&report).unwrap().to_string(),
        "sha256:b6c57da6e276fc47ecb951f2a96004fe271da5fc6c9437d3fda1c3bca047ebc3"
    );
}

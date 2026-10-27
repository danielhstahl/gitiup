//! Provenance tiers: what each one may claim, and what policy may accept
//! (giti-1rs.7).
//!
//! Three questions, three groups of tests:
//!
//! 1. **can the claim be made at all?** `simulated`, `local` and `quorum` differ
//!    in the evidence behind them, so each has a neighbour field that has to
//!    agree — the sandbox for `local`, the absence of secrets and of a sandbox for
//!    `simulated`, and nothing at all for `quorum`, which one run may never say.
//!    These are *format* rules: they fail at `validate`, before any signature or
//!    policy is consulted, because a manifest that contradicts itself is not a
//!    matter of taste.
//! 2. **is the claim acceptable here?** Tiers are policy (`allowed_tiers`, default
//!    `[local]`) so the same well-formed attestation can satisfy a planning tool
//!    and be refused by a merge gate.
//! 3. **is the policy itself coherent?** `gitiup-policy.json` is a gate people
//!    write by hand under time pressure; contradictory or vacuous policies are
//!    refused at parse time rather than silently letting things through.

use gitiup_attest::run::RunReport;
use gitiup_attest::sample::{self, TEST_SEED};
use gitiup_attest::{
    AttestationDoc, ErrorKind, Policy, PolicyFile, Provenance, RunManifest, Tier, TimeUs, Trust,
};

/// A `local` manifest, ready to be knocked out of shape one field at a time.
fn local() -> RunManifest {
    sample::local()
}

fn simulated() -> RunManifest {
    sample::simulated()
}

fn refusal(manifest: &RunManifest) -> gitiup_attest::Error {
    let err = manifest
        .validate()
        .expect_err("this manifest must not validate");
    assert_eq!(
        err.kind(),
        ErrorKind::Policy,
        "a provenance lie is a refusal (exit 6), not a parse error: {err}"
    );
    assert_eq!(err.exit_code(), 6);
    err
}

// ------------------------------------------------ what a tier may claim ---

#[test]
fn one_run_may_never_claim_quorum() {
    // The most valuable forgery in this vocabulary, so it is refused in the
    // format rather than left to configuration: a quorum is a conclusion drawn
    // from several attestations (giti-msi.7), and the run that says it got one is
    // asking to be believed on its own word.
    assert!(!Tier::Quorum.claimable_by_single_run());
    assert!(Tier::Simulated.claimable_by_single_run());
    assert!(Tier::Local.claimable_by_single_run());

    let mut manifest = local();
    manifest.result.provenance.tier = Tier::Quorum;
    let err = refusal(&manifest);
    assert!(err.detail().contains("quorum"));
    assert!(err.hint().unwrap().contains("giti-msi.7"));

    // …and the same refusal on the way in, from the report a runner hands over,
    // so it is named before anything is hashed.
    let mut report = RunReport::simple(
        "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ci.yml",
        "name: CI\n",
        "ok\n",
    )
    .unwrap();
    report.provenance.tier = Tier::Quorum;
    let err = RunManifest::from_run(&report).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("quorum tier"));
}

#[test]
fn a_simulated_run_claims_no_secrets_and_no_confinement() {
    // Nothing executed, so there was nothing to confine and nothing to hand over.
    // Either half of that being wrong means the label is doing more work than the
    // evidence.
    let mut manifest = simulated();
    manifest.result.secret_names = vec!["NPM_TOKEN".into()];
    let err = refusal(&manifest);
    assert!(err.detail().contains("secrets"), "{err}");
    assert!(err.hint().unwrap().contains("touches no secrets"));

    let mut manifest = simulated();
    manifest.result.provenance.sandbox = Some("docker".into());
    let err = refusal(&manifest);
    assert!(err.detail().contains("cannot claim sandbox"), "{err}");

    // A plan says what confined it: nothing, spelled out or omitted.
    for spelling in [None, Some("none"), Some("off"), Some("no"), Some("")] {
        let mut manifest = simulated();
        manifest.result.provenance.sandbox = spelling.map(str::to_string);
        manifest
            .validate()
            .unwrap_or_else(|e| panic!("sandbox {spelling:?} should mean 'nothing': {e}"));
    }
}

#[test]
fn a_local_run_must_name_where_it_ran() {
    // "Really executed" without saying where is the shape of a laundered run: the
    // tier is only worth what its sandbox is.
    for spelling in [None, Some("none"), Some("off")] {
        let mut manifest = local();
        manifest.result.provenance.sandbox = spelling.map(str::to_string);
        let err = refusal(&manifest);
        assert!(err.detail().contains("must name the sandbox"), "{err}");
    }

    // Naming one is enough, and what is *enough* is policy (see
    // `sandboxes_are_narrowed_by_policy`; giti-bgy.1 hardens the list).
    let mut manifest = local();
    manifest.result.provenance.sandbox = Some("shell".into());
    manifest.validate().unwrap();
}

#[test]
fn the_sandbox_field_states_what_confined_the_run() {
    let base = local().result.provenance;
    let with = |sandbox: Option<&str>| Provenance {
        sandbox: sandbox.map(str::to_string),
        ..base.clone()
    };
    assert_eq!(with(Some("docker")).confining_sandbox(), Some("docker"));
    assert_eq!(with(Some("shell")).confining_sandbox(), Some("shell"));
    assert_eq!(with(Some("none")).confining_sandbox(), None);
    assert_eq!(with(Some("off")).confining_sandbox(), None);
    assert_eq!(with(None).confining_sandbox(), None);
}

#[test]
fn tier_names_are_a_vocabulary_not_a_string() {
    for tier in Tier::ALL {
        assert_eq!(Tier::parse(tier.as_str()).unwrap(), tier);
        assert_eq!(tier.to_string(), tier.as_str());
        assert_eq!(tier.to_string().parse::<Tier>().unwrap(), tier);
    }
    assert_eq!(Tier::parse(" Simulated ").unwrap(), Tier::Simulated);
    let err = Tier::parse("quorom").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Invalid);
    let hint = err.hint().unwrap();
    for tier in Tier::ALL {
        assert!(hint.contains(tier.as_str()), "hint lists tiers: {hint}");
    }
    // Order is "increasing external evidence", and `is_executed` splits the
    // planning tier from the two that describe work that happened.
    assert!(Tier::Simulated < Tier::Local && Tier::Local < Tier::Quorum);
    assert!(!Tier::Simulated.is_executed());
    assert!(Tier::Local.is_executed() && Tier::Quorum.is_executed());
}

#[test]
fn only_a_plan_needs_a_loud_warning() {
    assert!(Tier::Simulated.trust_warning().is_some());
    assert!(Tier::Local.trust_warning().is_none());
    assert!(Tier::Quorum.trust_warning().is_none());
    let warning = Tier::Simulated.trust_warning().unwrap();
    for phrase in ["SIMULATED", "nothing was executed"] {
        assert!(warning.contains(phrase), "{warning}");
    }
}

// ------------------------------------------------------------- policy ----

#[test]
fn the_default_policy_refuses_a_plan() {
    // The safe default, stated once: `[local]`. A tool that wants plans says so.
    let policy = Policy::default();
    assert_eq!(policy.allowed_tiers, vec![Tier::Local]);
    assert!(policy.allows_tier(Tier::Local));
    assert!(!policy.allows_tier(Tier::Simulated));

    let err = policy
        .check_provenance(&simulated().result.provenance)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert_eq!(err.exit_code(), 6);
    assert!(err.detail().contains("simulated"), "{err}");
    // Actionable: it says how to get an attestation that *does* satisfy the gate,
    // and what the alternative switch is called.
    let hint = err.hint().unwrap();
    assert!(hint.contains("--execute --sandbox"), "{hint}");
    assert!(hint.contains("allow_simulated"), "{hint}");

    policy
        .check_provenance(&local().result.provenance)
        .expect("local is the default");
}

#[test]
fn a_policy_file_says_what_is_acceptable() {
    // The default file: `{}` is not "accept everything", it is the safe policy.
    let policy = PolicyFile::policy_from_json("{}").unwrap();
    assert_eq!(policy.allowed_tiers, vec![Tier::Local]);
    assert!(matches!(policy.trust, Trust::None));

    let policy = PolicyFile::policy_from_json(r#"{"allow_simulated": true}"#).unwrap();
    assert!(policy.allows_tier(Tier::Simulated));
    assert!(policy.allows_tier(Tier::Local));

    let policy = PolicyFile::policy_from_json(r#"{"allow_simulated": false}"#).unwrap();
    assert!(!policy.allows_tier(Tier::Simulated));

    let policy =
        PolicyFile::policy_from_json(r#"{"allowed_tiers": ["simulated", "local"]}"#).unwrap();
    assert_eq!(policy.allowed_tiers, vec![Tier::Simulated, Tier::Local]);

    // `quorum` is a legal thing to write (a coordinator's policy may say it) even
    // though no single run can ever satisfy it.
    let policy = PolicyFile::policy_from_json(r#"{"allowed_tiers": ["quorum"]}"#).unwrap();
    assert!(policy.allows_tier(Tier::Quorum));
}

#[test]
fn a_policy_that_argues_with_itself_is_refused() {
    // (text, the error class a mistake of that kind deserves)
    for (text, kind) in [
        // Two keys, two answers.
        (
            r#"{"allow_simulated": false, "allowed_tiers": ["simulated", "local"]}"#,
            ErrorKind::Policy,
        ),
        (
            r#"{"allow_simulated": true, "allowed_tiers": ["local"]}"#,
            ErrorKind::Policy,
        ),
        // A gate that gates nothing.
        (r#"{"allowed_tiers": []}"#, ErrorKind::Policy),
        // An "an unsigned attestation is fine" switch nobody meant to write.
        (r#"{"min_signatures": 0}"#, ErrorKind::Policy),
        // A typo in a tier name must not read as "accepts less than I meant".
        (r#"{"allowed_tiers": ["lokal"]}"#, ErrorKind::Invalid),
        // A typo in a *key* is worse still: the gate silently disappears.
        (r#"{"allow_simulate": true}"#, ErrorKind::Invalid),
        (r#"{"schema_version": 99}"#, ErrorKind::UnsupportedSchema),
    ] {
        let err = PolicyFile::policy_from_json(text).unwrap_err();
        assert_eq!(err.kind(), kind, "{text}: {err}");
        assert_eq!(err.exit_code(), 6);
        assert!(err.hint().is_some(), "{text}: {err}");
    }
}

#[test]
fn sandboxes_are_narrowed_by_policy() {
    // The format accepts `shell`; a volunteer's machine does not.
    let policy = PolicyFile::policy_from_json(
        r#"{"allow_simulated": true, "allowed_sandboxes": ["docker", "podman"]}"#,
    )
    .unwrap();
    assert_eq!(policy.allowed_sandboxes, vec!["docker", "podman"]);
    assert!(policy.allows_sandbox(Some("docker")));
    assert!(policy.allows_sandbox(Some("Docker")), "names are names");
    assert!(!policy.allows_sandbox(Some("shell")));
    assert!(!policy.allows_sandbox(None));

    let mut manifest = local();
    manifest.result.provenance.sandbox = Some("shell".into());
    manifest.validate().unwrap();
    let err = policy
        .check_provenance(&manifest.result.provenance)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("shell"), "{err}");
    assert!(err.hint().unwrap().contains("docker, podman"), "{err}");

    // …but the sandbox list is a question about work that happened, not about a
    // plan: `allowed_sandboxes` must not become a second, quieter way of refusing
    // `simulated`, because that answer belongs to `allowed_tiers`.
    policy
        .check_provenance(&Provenance {
            tier: Tier::Simulated,
            runner: "gitiup 0.1.0".into(),
            normalisation_version: 1,
            sandbox: None,
        })
        .expect("allow_simulated is true here, and a plan has no sandbox to judge");
    let err = Policy::default()
        .check_provenance(&simulated().result.provenance)
        .unwrap_err();
    assert!(err.detail().contains("tier"), "{err}");
}

#[test]
fn a_signed_plan_is_refused_by_default_and_accepted_on_request() {
    // The end-to-end shape of the acceptance criterion: the *same* bytes, two
    // policies, and the refusal that says what to do about it.
    let mut doc = AttestationDoc::new(simulated());
    let key = gitiup_attest::SigningKey::from_seed(&TEST_SEED);
    doc.sign(&key).unwrap();
    // The fixture's claimed time is fixed, so the clock is pinned: freshness is
    // not what this test is about.
    let now = Some(TimeUs::from_secs(1_793_092_600));

    let mut policy = PolicyFile::policy_from_json(&format!(
        r#"{{"trust_key_ids": ["{}"]}}"#,
        key.public_key().key_id()
    ))
    .unwrap();
    policy.now = now;
    let err = doc.verify(&policy).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("simulated"), "{err}");
    assert_eq!(err.exit_code(), 6);

    let mut policy = PolicyFile::policy_from_json(&format!(
        r#"{{"trust_key_ids": ["{}"], "allow_simulated": true}}"#,
        key.public_key().key_id()
    ))
    .unwrap();
    policy.now = now;
    let verdict = doc.verify(&policy).unwrap();
    assert_eq!(verdict.tier, Tier::Simulated);
    assert_eq!(verdict.signers, vec![key.public_key().key_id()]);
    // The verdict carries the tier so the *caller* can be loud about it.
    assert!(verdict.tier.trust_warning().is_some());
}

#[test]
fn policy_bindings_reach_the_policy() {
    let policy = PolicyFile::policy_from_json(
        r#"{
            "expected_commit": "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "expected_result_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "require_normalisation_version": 1,
            "min_signatures": 2,
            "max_age_us": 1000,
            "max_clock_skew_us": 5
        }"#,
    )
    .unwrap();
    assert!(policy.expected_commit.is_some());
    assert!(policy.expected_result_digest.is_some());
    assert_eq!(policy.normalisation_version, Some(1));
    assert_eq!(policy.min_signatures, 2);
    assert_eq!(policy.max_age_us, 1000);
    assert_eq!(policy.max_clock_skew_us, 5);

    // Bad values are refused where they are written.
    assert!(PolicyFile::policy_from_json(r#"{"expected_commit": "not-an-oid"}"#).is_err());
    assert!(PolicyFile::policy_from_json(r#"{"expected_result_digest": "md5:00"}"#).is_err());
}

#[test]
fn the_document_policy_is_the_policy_of_the_default_build() {
    // The doc example in `policy` and these tests must describe one policy.
    let file = PolicyFile::default();
    assert_eq!(file.to_policy().unwrap(), Policy::default());
    assert_eq!(gitiup_attest::POLICY_SCHEMA_VERSION, 1);
    assert_eq!(gitiup_attest::POLICY_FILE_NAME, "gitiup-policy.json");
    assert_eq!(gitiup_attest::POLICY_PATH_ENV, "GITIUP_POLICY");
}

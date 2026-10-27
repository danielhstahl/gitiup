//! Environment fingerprinting and match enforcement (giti-1rs.4).
//!
//! Three things are pinned here, in the order the acceptance criteria name them:
//!
//! 1. every manifest carries an `EnvFingerprint`, and it is *derived*, so a
//!    manifest cannot describe one machine and name another;
//! 2. verification refuses an arm64 attestation for a change that requires amd64
//!    — with a sentence about architectures, not a digest nobody can diff;
//! 3. the `require-env-match = strict|major|off` knob behaves as documented, from
//!    the policy file all the way to `AttestationDoc::verify`.
//!
//! The subjects are the committed run fixtures (five real reports, five real
//! environments — two of them aarch64), so the refusals below are exercised on the
//! same bytes the digest goldens pin rather than on a manifest invented per test.

use std::path::{Path, PathBuf};

use gitiup_attest::key::SigningKey;
use gitiup_attest::run::RunReport;
use gitiup_attest::sample::TEST_SEED;
use gitiup_attest::{
    AttestationDoc, EnvMatch, EnvironmentRequirement, ErrorKind, Policy, PolicyFile, RunManifest,
    TimeUs,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runs")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The manifest a fixture computes to — the same pipeline `gitiup digest` runs.
fn manifest_for(case: &str) -> RunManifest {
    let bytes = read(&fixtures_dir().join(case).join("run.json"));
    let report: RunReport = serde_json::from_slice(&bytes).expect("fixture report");
    RunManifest::from_run(&report).expect("fixture computes a manifest")
}

/// A signed document over a fixture, so the whole `verify` path runs and not just
/// the policy check.
fn signed(case: &str) -> AttestationDoc {
    let mut doc = AttestationDoc::new(manifest_for(case));
    doc.sign(&SigningKey::from_seed(&TEST_SEED)).unwrap();
    doc.validate().unwrap();
    doc
}

fn policy_with(requirement: &str, mode: EnvMatch) -> Policy {
    Policy {
        require_env_match: mode,
        require_environment: Some(EnvironmentRequirement::parse(requirement).unwrap()),
        ..Policy::for_tests()
    }
}

#[test]
fn every_manifest_carries_a_derived_environment_fingerprint() {
    let mut checked = 0usize;
    for case in [
        "hello",
        "matrix-build",
        "image-build-skipped",
        "test-failure",
        "dispatch-release",
    ] {
        let manifest = manifest_for(case);
        manifest.validate().unwrap();
        let fingerprint = manifest.env_fingerprint();
        assert!(
            fingerprint.hex().len() == 64,
            "{case}: no environment fingerprint"
        );
        assert_eq!(
            *fingerprint,
            manifest.result.environment.compute_fingerprint().unwrap(),
            "{case}: the fingerprint is not the one the described environment hashes to"
        );
        checked += 1;
    }
    for manifest in [
        gitiup_attest::sample::minimal(),
        gitiup_attest::sample::simulated(),
        gitiup_attest::sample::local(),
        gitiup_attest::sample::quorum_member(),
        gitiup_attest::sample::full(),
    ] {
        manifest.validate().unwrap();
        assert_eq!(
            *manifest.env_fingerprint(),
            manifest.result.environment.compute_fingerprint().unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 10);
}

#[test]
fn a_fingerprint_cannot_describe_a_different_environment() {
    // The reason the fingerprint is derived: move a field, and the manifest that
    // keeps the old fingerprint is refused before policy ever runs.
    let mut manifest = manifest_for("matrix-build");
    manifest.result.environment.arch = "aarch64".into();
    let err = manifest.validate().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DigestMismatch);
    assert_eq!(err.exit_code(), 8);
    manifest.result.environment.fix_fingerprint().unwrap();
    manifest.validate().unwrap();
}

#[test]
fn an_arm64_attestation_is_refused_where_the_change_requires_amd64() {
    let arm = signed("image-build-skipped"); // arch: aarch64
    let amd = signed("matrix-build"); // arch: x86_64
    let policy = policy_with("arch=amd64", EnvMatch::Strict);

    // The amd64 run passes — and `amd64` is accepted as a spelling of `x86_64`.
    let verdict = amd.verify(&policy).unwrap();
    assert_eq!(verdict.environment_match, EnvMatch::Strict);
    assert_eq!(
        verdict.environment_fingerprint,
        amd.manifest.result.environment.fingerprint
    );

    let err = arm.verify(&policy).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert_eq!(
        err.exit_code(),
        6,
        "a refused machine is policy, not corruption"
    );
    assert!(
        err.detail().contains("aarch64") && err.detail().contains("amd64"),
        "{}",
        err.detail()
    );
}

#[test]
fn the_refusal_says_what_to_do_about_the_image_and_the_toolchain() {
    // A requirement the run cannot even answer has to say so, and name where the
    // runner gets the value from — otherwise the next engineer debugs a mystery.
    let arm = signed("image-build-skipped");
    let policy = policy_with("toolchain:rustc=1.99", EnvMatch::Major);
    let err = arm.verify(&policy).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("toolchain:rustc"), "{}", err.detail());
    assert!(err.hint().unwrap().contains("GITIUP_TOOLCHAIN"));
    assert!(
        err.hint().unwrap().contains("buildah"),
        "the hint should show what *was* there: {}",
        err.hint().unwrap()
    );

    let policy = policy_with(
        "image_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
        EnvMatch::Strict,
    );
    let err = arm.verify(&policy).unwrap_err();
    assert!(err.detail().contains("image_digest"), "{}", err.detail());

    let policy = policy_with("image_reference=ubuntu:24.04", EnvMatch::Major);
    let mut doc = AttestationDoc::new(manifest_for("test-failure")); // no image at all
    doc.sign(&SigningKey::from_seed(&TEST_SEED)).unwrap();
    let err = doc.verify(&policy).unwrap_err();
    assert!(err.detail().contains("image_reference"), "{}", err.detail());
}

#[test]
fn the_knob_is_a_real_switch_on_one_mismatch() {
    // One mismatched run, three settings: strict refuses it, major refuses it (an
    // architecture has no version to round), off looks the other way.
    let arm = signed("image-build-skipped");
    let policy = policy_with("arch=x86_64", EnvMatch::Strict);
    assert_eq!(arm.verify(&policy).unwrap_err().kind(), ErrorKind::Policy);
    let policy = policy_with("arch=x86_64", EnvMatch::Major);
    assert_eq!(arm.verify(&policy).unwrap_err().kind(), ErrorKind::Policy);
    let policy = policy_with("arch=x86_64", EnvMatch::Off);
    arm.verify(&policy).unwrap();
    // `off` still refuses a *broken* fingerprint: the gate is off, the format is not.
    let mut broken = arm.clone();
    broken.manifest.result.environment.arch = "riscv64".into();
    assert!(broken.verify(&policy).is_err());
}

#[test]
fn major_rounds_a_version_where_strict_demands_the_whole_string() {
    let amd = signed("matrix-build"); // rustc 1.99.1, image ghcr.io/gitiup/ci:ubuntu-24.04
    let coarse = policy_with("toolchain:rustc=1.99", EnvMatch::Major);
    amd.verify(&coarse).unwrap();
    assert_eq!(
        amd.verify(&policy_with("toolchain:rustc=1.99", EnvMatch::Strict))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy,
        "strict must not round a version it did not ask to round"
    );
    // A coarse `major` requirement of a whole major line still separates 1 from 2.
    amd.verify(&policy_with("toolchain:rustc=1", EnvMatch::Major))
        .unwrap();
    assert_eq!(
        amd.verify(&policy_with("toolchain:rustc=2", EnvMatch::Major))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    // The runner version lives in provenance and rounds the same way.
    amd.verify(&policy_with("runner=\"gitiup 0.1\"", EnvMatch::Major))
        .unwrap();
    assert_eq!(
        amd.verify(&policy_with("runner=\"gitiup 0.2\"", EnvMatch::Major))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
}

#[test]
fn a_fingerprint_requirement_pins_one_machine_class_and_says_what_was_seen() {
    let manifest = manifest_for("matrix-build");
    let blessed = manifest.result.environment.fingerprint.clone();
    let policy = Policy {
        require_environment: Some(EnvironmentRequirement {
            fingerprint: Some(blessed.clone()),
            ..EnvironmentRequirement::empty()
        }),
        ..Policy::for_tests()
    };
    let mut doc = AttestationDoc::new(manifest);
    doc.sign(&SigningKey::from_seed(&TEST_SEED)).unwrap();
    doc.verify(&policy).unwrap();

    let other = signed("dispatch-release");
    let err = other.verify(&policy).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("fingerprint"));
    // A hash cannot name the field that moved, so the refusal prints the machine.
    assert!(
        err.hint().unwrap().contains("x86_64"),
        "{}",
        err.hint().unwrap()
    );
}

#[test]
fn a_policy_file_publishes_the_requirement_the_repo_means() {
    let file = PolicyFile::from_json(
        r#"{
            "allow_simulated": false,
            "require_env_match": "major",
            "require_arch": "amd64",
            "require_os": "linux",
            "require_toolchain": {"rustc": "1.99"},
            "require_image_digest": "sha256:3cafcfa89b212a186c2c2d4be67c3f248aaada2fe78e45bc61c804c15dc8bc54"
        }"#,
    )
    .unwrap();
    let policy = file.to_policy().unwrap();
    assert_eq!(policy.require_env_match, EnvMatch::Major);
    let requirement = policy.require_environment.clone().unwrap();
    assert_eq!(requirement.arch.as_deref(), Some("amd64"));
    assert_eq!(
        requirement.toolchain.get("rustc").map(String::as_str),
        Some("1.99")
    );
    assert_eq!(
        requirement.named(),
        vec![
            "arch".to_string(),
            "image_digest".to_string(),
            "os".to_string(),
            "toolchain:rustc".to_string()
        ]
    );

    // And it gates the fixture it was written against.
    let mut doc = AttestationDoc::new(manifest_for("matrix-build"));
    doc.sign(&SigningKey::from_seed(&TEST_SEED)).unwrap();
    let policy = Policy {
        // A repo file names real keys; this fixture key is not in one, so borrow
        // the test trust root and keep the clock the fixtures claim.
        trust: gitiup_attest::Trust::AnyKeyForTests,
        now: Some(TimeUs::from_secs(1_793_092_600)),
        ..policy
    };
    let verdict = doc.verify(&policy).unwrap();
    assert!(verdict.environment_requirement.is_some());

    // The kebab-case spelling of the knob is accepted too, because the ticket
    // spells it that way and a policy file that refuses its own documentation is a
    // policy file nobody reads.
    let kebab =
        PolicyFile::from_json(r#"{"require-env-match": "strict", "require-arch": "amd64"}"#)
            .unwrap();
    let policy = kebab.to_policy().unwrap();
    assert_eq!(policy.require_env_match, EnvMatch::Strict);
    assert_eq!(
        policy.require_environment.unwrap().arch.as_deref(),
        Some("amd64")
    );
}

#[test]
fn a_policy_file_refuses_a_typo_and_a_policy_that_arguments_with_itself() {
    // A typo in a gate is a gate that quietly stopped gating.
    for bad in [
        r#"{"require_env_match": "strictish"}"#,
        r#"{"require_arch": ""}"#,
        r#"{"require_image_digest": "md5:00"}"#,
        r#"{"require_env_match": "strict", "require_nonsense": "x"}"#,
    ] {
        let err = PolicyFile::policy_from_json(bad).unwrap_err();
        assert_eq!(err.exit_code(), 6, "{bad} was accepted or miscategorised");
    }

    // A requirement published while matching is off has argued with itself: the
    // refusal is the same rule as `allow_simulated` vs `allowed_tiers`.
    let err =
        PolicyFile::policy_from_json(r#"{"require_env_match": "off", "require_arch": "amd64"}"#)
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    assert!(err.detail().contains("off"), "{}", err.detail());
    assert!(err.hint().unwrap().contains("drop the"));

    // Nothing published, nothing enforced: the default policy does not care what
    // machine a run happened on.
    let policy = PolicyFile::policy_from_json("{}").unwrap();
    assert!(policy.require_environment.is_none());
    assert!(policy.environment_requirement().is_none());
    assert_eq!(policy.require_env_match, EnvMatch::Strict);
    let manifest = manifest_for("image-build-skipped");
    policy
        .check_environment(&manifest.result.environment, &manifest.result.provenance)
        .unwrap();
}

#[test]
fn check_environment_is_callable_without_a_document() {
    // `gitiup run --policy` asks "would the owner accept what I am about to
    // produce?" before anything is signed, on exactly these rules.
    let policy = policy_with("arch=amd64", EnvMatch::Strict);
    let arm = manifest_for("image-build-skipped");
    let err = policy
        .check_environment(&arm.result.environment, &arm.result.provenance)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Policy);
    let amd = manifest_for("matrix-build");
    policy
        .check_environment(&amd.result.environment, &amd.result.provenance)
        .unwrap();
}

#[test]
fn an_os_version_requirement_rounds_only_under_major() {
    // The fixtures carry no os_version, so build the two runs this test needs:
    // one on 24.04, one on 24.10.
    let doc_on = |version: &str| {
        let mut manifest = manifest_for("matrix-build");
        manifest.result.environment.os_version = Some(version.into());
        manifest.result.environment.fix_fingerprint().unwrap();
        let mut doc = AttestationDoc::new(manifest);
        doc.sign(&SigningKey::from_seed(&TEST_SEED)).unwrap();
        doc
    };
    let dot4 = doc_on("24.04");
    let dot10 = doc_on("24.10");

    // `major` exists for exactly this: the same major release, a different point.
    dot10
        .verify(&policy_with("os_version=24", EnvMatch::Major))
        .unwrap();
    dot4.verify(&policy_with("os_version=24", EnvMatch::Major))
        .unwrap();
    assert_eq!(
        dot10
            .verify(&policy_with("os_version=24.04", EnvMatch::Major))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    // `strict` rounds nothing: a stated version is the whole version.
    dot4.verify(&policy_with("os_version=24.04", EnvMatch::Strict))
        .unwrap();
    assert_eq!(
        dot4.verify(&policy_with("os_version=24", EnvMatch::Strict))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
    // A run that never reported a version cannot satisfy a version requirement.
    let mute = signed("matrix-build");
    assert_eq!(
        mute.verify(&policy_with("os_version=24", EnvMatch::Major))
            .unwrap_err()
            .kind(),
        ErrorKind::Policy
    );
}

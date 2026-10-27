//! Deterministic sample manifests.
//!
//! These are the inputs to the committed golden fixtures, and the fixtures are
//! the cross-implementation contract ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)),
//! so everything here is fixed: no clock reads, no randomness, no paths that
//! depend on where the checkout lives. Other crates' tests should build their
//! fixtures from here rather than inventing a manifest per test.
//!
//! The sample signing key is derived from a documented seed — see
//! [`TEST_SEED`] — so the fixtures carry no private key material.

use std::collections::BTreeMap;

use crate::digest::Digest;
use crate::key::SigningKey;
use crate::manifest::*;
use crate::oid::{GitOid, OidAlgorithm};

/// Seed of the *only* key allowed to sign committed fixtures.
///
/// It is public, and that is the point: a private key in a repository is a
/// invitation to forge "signed" test data. A production trust policy must never
/// list [`test_key_id()`].
pub const TEST_SEED: [u8; 32] = *b"gitiup fixture key, not secret!!";

/// The fixture signing key.
pub fn test_key() -> SigningKey {
    SigningKey::from_seed(&TEST_SEED)
}

/// Key id of [`test_key`]. Pinned by a test so a trust policy can be written to
/// refuse it.
pub fn test_key_id() -> String {
    test_key().public_key().key_id()
}

/// A tiny run: one simulated step, no secrets, no artifacts.
pub fn simulated() -> RunManifest {
    let mut manifest = base_manifest(Tier::Simulated);
    manifest.result.steps = vec![Step {
        id: Some("plan".into()),
        name: "Plan the run".into(),
        uses: None,
        exit_code: 0,
        outcome: StepOutcome::Success,
        stdout: Digest::sha256(b"1 job: build\n"),
        stderr: Digest::sha256(b""),
        outputs: BTreeMap::new(),
        artifacts: Vec::new(),
    }];
    manifest.result.provenance = Provenance {
        tier: Tier::Simulated,
        runner: "gitiup 0.1.0".into(),
        normalisation_version: 1,
        sandbox: Some("none".into()),
    };
    manifest.finish()
}

/// A real local execution: pinned actions, secrets, artifacts, outputs.
pub fn local() -> RunManifest {
    let mut manifest = base_manifest(Tier::Local);
    manifest.result.inputs = BTreeMap::from([
        ("coverage".to_string(), InputValue::Bool(true)),
        ("jobs".to_string(), InputValue::Int(4)),
        ("toolchain".to_string(), InputValue::Text("1.99.1".into())),
    ]);
    manifest.result.secret_names = vec!["CODECOV_TOKEN".into(), "NPM_TOKEN".into()];
    manifest.result.pins = BTreeMap::from([
        (
            "actions/checkout@v4".to_string(),
            ActionPin {
                repo: "actions/checkout".into(),
                commit: GitOid::new(OidAlgorithm::Sha1, &[0xcd; 20]).unwrap(),
                reference: Some("v4".into()),
            },
        ),
        (
            "rust-actions/toolchain@v1".to_string(),
            ActionPin {
                repo: "rust-actions/toolchain".into(),
                commit: GitOid::new(OidAlgorithm::Sha1, &[0xab; 20]).unwrap(),
                reference: None,
            },
        ),
    ]);
    manifest.result.reusable_workflows = vec![WorkflowRef {
        path: ".github/workflows/_lint.yml".into(),
        oid: GitOid::new(OidAlgorithm::Sha1, &[0x21; 20]).unwrap(),
    }];
    manifest.result.environment = Environment {
        provider: Some("docker".into()),
        os: Some("linux".into()),
        arch: "x86_64".into(),
        image: Some(ImageRef {
            reference: Some("ghcr.io/gitiup/ci:ubuntu-24.04".into()),
            digest: Digest::sha256(b"ghcr.io/gitiup/ci@sha256:ubuntu-24.04"),
        }),
        toolchain: vec![
            ToolchainEntry {
                name: "cargo".into(),
                version: "1.99.1".into(),
            },
            ToolchainEntry {
                name: "rustc".into(),
                version: "1.99.1".into(),
            },
        ],
        fingerprint: Digest::sha256(b""),
    };
    manifest.result.steps = vec![
        Step {
            id: Some("checkout".into()),
            name: "Checkout".into(),
            uses: Some("actions/checkout@v4".into()),
            exit_code: 0,
            outcome: StepOutcome::Success,
            stdout: Digest::sha256(b"Checked out abc123\n"),
            stderr: Digest::sha256(b""),
            outputs: BTreeMap::from([("commit".to_string(), "abc123".into())]),
            artifacts: Vec::new(),
        },
        Step {
            id: Some("build".into()),
            name: "cargo test".into(),
            uses: None,
            exit_code: 0,
            outcome: StepOutcome::Success,
            stdout: Digest::sha256(b"test result: ok. 42 passed\n"),
            stderr: Digest::sha256(b""),
            outputs: BTreeMap::from([("coverage".to_string(), "91.5".into())]),
            artifacts: vec![Artifact {
                name: "coverage.lcov".into(),
                digest: Digest::sha256(b"lcov-bytes"),
                size_bytes: 81_920,
            }],
        },
    ];
    manifest.result.provenance = Provenance {
        tier: Tier::Local,
        runner: "gitiup 0.1.0".into(),
        normalisation_version: 1,
        sandbox: Some("docker".into()),
    };
    manifest.claims.timing = BTreeMap::from([
        (
            "checkout".to_string(),
            StepTiming {
                started_us: Some(claimed_at_us()),
                duration_us: Some(412_000),
            },
        ),
        (
            "build".to_string(),
            StepTiming {
                started_us: Some(claimed_at_us() + 412_000),
                duration_us: Some(3_900_000),
            },
        ),
    ]);
    manifest.finish()
}

/// A volunteer's run inside a quorum round: challenge-bound, with the
/// normalisation evidence a dispute would need.
pub fn quorum_member() -> RunManifest {
    let mut manifest = local();
    manifest.result.provenance.sandbox = Some("landlock".into());
    manifest.claims.run_id = "9f2c4e1b07a5d3c8".into();
    manifest.claims.verifier_challenge = Some(Digest::sha256(b"round-7731-challenge"));
    manifest.claims.normalisation_diffs = vec![
        NormalisationDiff {
            step: "build".into(),
            kind: "hostname".into(),
            before: "runner-7.internal".into(),
            after: "<host>".into(),
        },
        NormalisationDiff {
            step: "build".into(),
            kind: "path".into(),
            before: "/tmp/run-7731/target".into(),
            after: "<tmp>/target".into(),
        },
    ];
    manifest.claims.annotations =
        BTreeMap::from([("x_verifier".to_string(), "ci-sentinel.example".into())]);
    manifest.finish()
}

/// Every optional field present, every list non-empty.
///
/// Used by the schema drift test: whatever this serializes to *is* the set of
/// properties the schema must declare.
pub fn full() -> RunManifest {
    let mut manifest = quorum_member();
    manifest.claims.not_before_us = Some(claimed_at_us() - 60_000_000);
    manifest.claims.not_after_us = Some(claimed_at_us() + 60_000_000);
    manifest
}

/// Only the required fields, and nothing else.
///
/// The mirror image of [`full`]: whatever this serializes to *is* the set of
/// required properties the schema must declare.
pub fn minimal() -> RunManifest {
    let mut manifest = base_manifest(Tier::Simulated);
    manifest.result.environment = Environment {
        provider: None,
        os: None,
        arch: "x86_64".into(),
        image: None,
        toolchain: Vec::new(),
        fingerprint: Digest::sha256(b""),
    };
    manifest.result.source = Source {
        repo: None,
        commit: GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
        workflow: WorkflowRef {
            path: "ci.yml".into(),
            oid: GitOid::from_sha1_hex(&"b".repeat(40)).unwrap(),
        },
        event: EventContext {
            name: "push".into(),
            action: None,
            payload: Digest::sha256(b"event"),
        },
        job: None,
        matrix: BTreeMap::new(),
    };
    manifest.result.steps = vec![Step {
        id: None,
        name: "run".into(),
        uses: None,
        exit_code: 0,
        outcome: StepOutcome::Success,
        stdout: Digest::sha256(b"out"),
        stderr: Digest::sha256(b""),
        outputs: BTreeMap::new(),
        artifacts: Vec::new(),
    }];
    manifest.finish()
}

/// One place where the shared skeleton is built, so the three variants differ
/// only in the parts a verifier would compare.
fn base_manifest(tier: Tier) -> RunManifest {
    let environment = Environment {
        provider: Some("simulated".into()),
        os: Some("linux".into()),
        arch: "x86_64".into(),
        image: None,
        toolchain: Vec::new(),
        fingerprint: Digest::sha256(b""),
    };
    RunManifest {
        schema_version: SCHEMA_VERSION,
        attestation_type: RUN_MANIFEST_TYPE.into(),
        result: RunResult {
            source: Source {
                repo: Some("gitiup/gitiup".into()),
                commit: GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
                workflow: WorkflowRef {
                    path: ".github/workflows/ci.yml".into(),
                    oid: GitOid::from_sha1_hex(&"b".repeat(40)).unwrap(),
                },
                event: EventContext {
                    name: "pull_request".into(),
                    action: Some("synchronize".into()),
                    payload: Digest::sha256(b"{\"action\":\"synchronize\"}"),
                },
                job: Some("build".into()),
                matrix: BTreeMap::from([("os".to_string(), "ubuntu-24.04".into())]),
            },
            inputs: BTreeMap::new(),
            secret_names: Vec::new(),
            pins: BTreeMap::new(),
            reusable_workflows: Vec::new(),
            environment,
            steps: Vec::new(),
            provenance: Provenance {
                tier,
                runner: "gitiup 0.1.0".into(),
                normalisation_version: 1,
                sandbox: None,
            },
        },
        claims: Claims {
            run_id: "0123456789abcdef".into(),
            claimed_at_us: claimed_at_us(),
            not_before_us: None,
            not_after_us: None,
            verifier_challenge: None,
            timing: BTreeMap::new(),
            normalisation_diffs: Vec::new(),
            annotations: BTreeMap::new(),
        },
    }
}

/// The fixed "now" of every sample: 2026-10-27T09:15:02.500Z.
pub fn claimed_at_us() -> i64 {
    1_793_092_502_500_000
}

/// Convenience for the builders: normalize, derive the fingerprint, validate.
trait Finish {
    fn finish(&mut self) -> RunManifest;
}

impl Finish for RunManifest {
    fn finish(&mut self) -> RunManifest {
        self.normalize();
        self.result.environment.fix_fingerprint().unwrap();
        self.validate().expect("sample manifest must validate");
        self.clone()
    }
}

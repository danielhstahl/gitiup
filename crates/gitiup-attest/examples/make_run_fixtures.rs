//! Regenerate the golden *run* fixtures (`tests/fixtures/runs/`).
//!
//! ```sh
//! GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_run_fixtures
//! ```
//!
//! Where [`make_fixtures`](make_fixtures.rs) pins the *format* (one manifest per
//! shape, signed, byte-for-byte), this pins the *computation*: five
//! representative workflows as `run.json` reports, the canonical manifest bytes
//! they produce, and the two digests. Those are the numbers another
//! implementation of the runner must reproduce from a run report — the reason
//! `gitiup digest` is a claim a stranger can check rather than a promise.
//!
//! The cases are chosen to cover the digest recipe, not to look like real CI:
//!
//! | case | what it pins |
//!|------|--------------|
//!| `hello` | the floor: one simulated step, source and logs handed over in the clear |
//!| `matrix-build` | matrix vector, pins, inputs, secret names, reusable-workflow closure, a file-set artifact, timings |
//!| `image-build-skipped` | a digest-pinned image, toolchain inventory, a step that did not run |
//!| `test-failure` | a failing run still has a digest: exit codes, stderr, a skipped follow-on |
//!| `dispatch-release` | every input type, a sha256-format commit, a multipart payload, quorum-side claims |
//!
//! Like the format fixtures, these are frozen: adding a case is fine, editing one
//! is a format change and needs an ADR ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::collections::BTreeMap;
use std::path::PathBuf;

use gitiup_attest::manifest::{ActionPin, InputValue, NormalisationDiff, Provenance, Tier};
use gitiup_attest::oid::{GitOid, OidAlgorithm};
use gitiup_attest::run::{
    ArtifactReport, ClaimReport, EnvironmentReport, EventReport, Material,
    RAW_NORMALISATION_VERSION, RunReport, StepReport, TimingReport, WorkflowSource,
};
use gitiup_attest::{Digest, ImageRef, RunManifest, StepOutcome, StepTiming, ToolchainEntry};

/// The committed cases. New ones go here, and stay forever.
type Case = (&'static str, &'static str, fn() -> RunReport);

const CASES: [Case; 5] = [
    (
        "hello",
        "a simulated plan: one step, everything handed over in the clear",
        hello,
    ),
    (
        "matrix-build",
        "matrix arm of a real local run: pins, inputs, secrets, closure, artifacts",
        matrix_build,
    ),
    (
        "image-build-skipped",
        "digest-pinned image and toolchain inventory, with a conditional step that did not run",
        image_build_skipped,
    ),
    (
        "test-failure",
        "a failing run is still provable: exit codes, stderr, a skipped follow-on",
        test_failure,
    ),
    (
        "dispatch-release",
        "workflow_dispatch with every input type, a sha256 commit and quorum-side claims",
        dispatch_release,
    ),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runs");
    if std::env::var("GITIUP_UPDATE_FIXTURES").is_err() {
        eprintln!(
            "refusing to overwrite committed fixtures without GITIUP_UPDATE_FIXTURES=1\n\
             (tests/run_digest_golden.rs checks them on every run)"
        );
        std::process::exit(2);
    }
    std::fs::create_dir_all(&root)?;

    let mut index = serde_json::Map::new();
    index.insert(
        "comment".into(),
        json_text(
            "Golden run-digest vectors. Generated with:\n  \
             GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_run_fixtures\n\
             run.json is a run *report* (pretty-printed for humans; its layout carries no meaning). \
             manifest.json is the canonical manifest bytes it computes, exactly as signed and stored. \
             The digests are the contract.",
        ),
    );
    index.insert(
        "recipe".into(),
        json_text(
            "RunDigest = sha256(canonical(manifest)); ResultDigest = sha256(canonical(manifest.result)). \
             See ADR-0001 D2 and D4.",
        ),
    );

    let mut cases = Vec::new();
    for (name, note, build) in CASES {
        let report = build();
        report.validate().map_err(|e| format!("{name}: {e}"))?;
        let manifest = RunManifest::from_run(&report).map_err(|e| format!("{name}: {e}"))?;
        let manifest_bytes = manifest.encode().map_err(|e| format!("{name}: {e}"))?;

        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        // A report is a transport, so it is written pretty and may be reformatted
        // freely; the manifest is the signed payload and is written exactly.
        std::fs::write(
            dir.join("run.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&serde_json::to_value(&report)?)?
            ),
        )?;
        std::fs::write(dir.join("manifest.json"), &manifest_bytes)?;

        let mut case = serde_json::Map::new();
        case.insert("name".into(), json_text(name));
        case.insert("note".into(), json_text(note));
        case.insert("tier".into(), json_text(report.provenance.tier.as_str()));
        case.insert(
            "normalisation_version".into(),
            serde_json::Value::from(i64::from(report.provenance.normalisation_version)),
        );
        case.insert("steps".into(), serde_json::Value::from(report.steps.len()));
        case.insert(
            "run_digest".into(),
            json_text(manifest.digest()?.to_string()),
        );
        case.insert(
            "result_digest".into(),
            json_text(manifest.result_digest()?.to_string()),
        );
        cases.push(serde_json::Value::Object(case));
        println!(
            "wrote {name}: run {} result {}",
            &manifest.digest()?.hex()[..12],
            &manifest.result_digest()?.inner().hex()[..12]
        );
    }

    index.insert("cases".into(), serde_json::Value::Array(cases));
    std::fs::write(
        root.join("cases.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::Value::Object(index))?
        ),
    )?;
    println!("wrote {}", root.join("cases.json").display());
    Ok(())
}

fn json_text(text: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(text.into())
}

/// A committed workflow file, named by its git blob id.
fn committed(path: &str, seed: u8) -> WorkflowSource {
    WorkflowSource::committed(path, sha1(seed))
}

fn sha1(seed: u8) -> GitOid {
    GitOid::new(OidAlgorithm::Sha1, &[seed; 20]).unwrap()
}

fn claims(run_id: &str, claimed_at_us: i64) -> ClaimReport {
    ClaimReport {
        run_id: run_id.into(),
        claimed_at_us,
        not_before_us: None,
        not_after_us: None,
        verifier_challenge: None,
        timings: Vec::new(),
        normalisation_diffs: Vec::new(),
        annotations: BTreeMap::new(),
    }
}

fn local_provenance(normalisation_version: u32) -> Provenance {
    Provenance {
        tier: Tier::Local,
        runner: "gitiup 0.1.0".into(),
        normalisation_version,
        sandbox: Some("docker".into()),
    }
}

/// Case 1: the floor. A simulated plan, everything handed over in the clear.
fn hello() -> RunReport {
    RunReport {
        repo: Some("gitiup/gitiup".into()),
        commit: sha1(0xaa),
        workflow: WorkflowSource::from_text(
            ".github/workflows/hello.yml",
            "name: hello\non: push\njobs:\n  hi:\n    runs-on: ubuntu-24.04\n",
        ),
        event: EventReport {
            name: "push".into(),
            action: None,
            payload: Material::text(r#"{"ref":"refs/heads/main"}"#),
        },
        job: Some("hi".into()),
        matrix: BTreeMap::new(),
        inputs: BTreeMap::new(),
        secret_names: Vec::new(),
        pins: BTreeMap::new(),
        reusable_workflows: Vec::new(),
        environment: EnvironmentReport::arch("x86_64"),
        steps: vec![StepReport {
            id: Some("say".into()),
            stdout: Material::text("hello from a simulated run\n"),
            ..StepReport::run("Say hello", 0)
        }],
        provenance: Provenance {
            tier: Tier::Simulated,
            runner: "gitiup 0.1.0".into(),
            normalisation_version: RAW_NORMALISATION_VERSION,
            sandbox: Some("none".into()),
        },
        claims: claims("0a0b0c0d0e0f1011", 1_793_092_502_500_000),
    }
}

/// Case 2: a matrix arm of a real run, the whole `result` half populated.
fn matrix_build() -> RunReport {
    let mut report = RunReport {
        repo: Some("gitiup/gitiup".into()),
        commit: sha1(0xbb),
        workflow: committed(".github/workflows/ci.yml", 0xb1),
        event: EventReport {
            name: "pull_request".into(),
            action: Some("synchronize".into()),
            payload: Material::digest(Digest::sha256(
                b"{\"action\":\"synchronize\",\"number\":42}",
            )),
        },
        job: Some("build".into()),
        matrix: BTreeMap::from([
            ("os".to_string(), "ubuntu-24.04".into()),
            ("profile".to_string(), "release".into()),
        ]),
        inputs: BTreeMap::from([
            ("coverage".to_string(), InputValue::Bool(true)),
            ("jobs".to_string(), InputValue::Int(4)),
            ("toolchain".to_string(), InputValue::Text("1.99.1".into())),
        ]),
        secret_names: vec!["CODECOV_TOKEN".into(), "NPM_TOKEN".into()],
        pins: BTreeMap::from([
            (
                "actions/checkout@v4".to_string(),
                ActionPin {
                    repo: "actions/checkout".into(),
                    commit: sha1(0xcd),
                    reference: Some("v4".into()),
                },
            ),
            (
                "rust-actions/toolchain@v1".to_string(),
                ActionPin {
                    repo: "rust-actions/toolchain".into(),
                    commit: sha1(0xab),
                    reference: None,
                },
            ),
        ]),
        reusable_workflows: vec![
            committed(".github/workflows/_lint.yml", 0x21),
            committed(".github/workflows/_supply-chain.yml", 0x22),
        ],
        environment: EnvironmentReport {
            provider: Some("docker".into()),
            os: Some("linux".into()),
            os_version: None,
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
                    name: "git".into(),
                    version: "2.47.0".into(),
                },
                ToolchainEntry {
                    name: "rustc".into(),
                    version: "1.99.1".into(),
                },
            ],
        },
        steps: vec![
            StepReport {
                id: Some("checkout".into()),
                uses: Some("actions/checkout@v4".into()),
                stdout: Material::digest(Digest::sha256(b"Checked out b1b1b1\n")),
                ..StepReport::run("Checkout", 0)
            },
            StepReport {
                id: Some("build".into()),
                uses: Some("rust-actions/toolchain@v1".into()),
                stdout: Material::digest(Digest::sha256(
                    b"test result: ok. 128 passed; 0 failed\n",
                )),
                stderr: Material::digest(Digest::sha256(b"warning: 1 unused import\n")),
                outputs: BTreeMap::from([("coverage".to_string(), "91.4".into())]),
                ..StepReport::run("cargo test --release", 0)
            },
            StepReport {
                id: Some("upload".into()),
                // A directory artifact: hashed as a sorted file set, with
                // explicit lengths per entry (giti-1rs.3's "sort the manifest").
                artifacts: vec![ArtifactReport {
                    name: "coverage".into(),
                    content: Material::files([
                        ("cov/lcov.info".to_string(), Material::text("TN:\nDA:1,1\n")),
                        ("cov/summary.txt".to_string(), Material::text("91.4%\n")),
                    ]),
                    size_bytes: None,
                }],
                outputs: BTreeMap::from([("size".to_string(), "19".into())]),
                ..StepReport::run("Upload coverage", 0)
            },
        ],
        provenance: local_provenance(1),
        claims: claims("1b2c3d4e5f607182", 1_793_092_502_500_000),
    };
    // Every log arrived pre-hashed, so the declared version is the runner's claim
    // about the profile it used (giti-1rs.3), not the profile applied here.
    report.claims.timings = vec![
        TimingReport {
            step: "build".into(),
            started_us: Some(1_793_092_503_000_000),
            duration_us: Some(3_900_000),
        },
        TimingReport {
            step: "checkout".into(),
            started_us: Some(1_793_092_502_600_000),
            duration_us: Some(412_000),
        },
    ];
    report.claims.annotations = BTreeMap::from([
        ("x_matrix".to_string(), "ubuntu-24.04/release".into()),
        ("x_runner".to_string(), "gitiup-local".into()),
    ]);
    report
}

/// Case 3: an image build on a digest-pinned image, with a step that never ran.
fn image_build_skipped() -> RunReport {
    RunReport {
        repo: Some("gitiup/gitiup".into()),
        commit: sha1(0xcc),
        workflow: committed(".github/workflows/image.yml", 0x33),
        event: EventReport {
            name: "push".into(),
            action: None,
            payload: Material::digest(Digest::sha256(b"{\"ref\":\"refs/tags/v0.1.0\"}")),
        },
        job: Some("image".into()),
        matrix: BTreeMap::new(),
        inputs: BTreeMap::from([("push".to_string(), InputValue::Bool(false))]),
        secret_names: vec!["REGISTRY_TOKEN".into()],
        pins: BTreeMap::from([(
            "docker/build-push-action@v6".to_string(),
            ActionPin {
                repo: "docker/build-push-action".into(),
                commit: sha1(0xde),
                reference: Some("v6".into()),
            },
        )]),
        reusable_workflows: Vec::new(),
        environment: EnvironmentReport {
            provider: Some("docker".into()),
            os: Some("linux".into()),
            os_version: None,
            arch: "aarch64".into(),
            image: Some(ImageRef {
                reference: Some("docker.io/library/debian:trixie".into()),
                digest: Digest::sha256(b"docker.io/library/debian:trixie@sha256:aaaabbbbccccdddd"),
            }),
            toolchain: vec![ToolchainEntry {
                name: "buildah".into(),
                version: "1.38.0".into(),
            }],
        },
        steps: vec![
            StepReport {
                id: Some("build".into()),
                uses: Some("docker/build-push-action@v6".into()),
                stdout: Material::digest(Digest::sha256(b"STEP 1/4: FROM debian:trixie\n")),
                artifacts: vec![ArtifactReport {
                    name: "oci-image".into(),
                    content: Material::digest(Digest::sha256(b"oci-manifest-descriptor")),
                    size_bytes: Some(74_200_013),
                }],
                outputs: BTreeMap::from([("digest".to_string(), "sha256:1111222233334444".into())]),
                ..StepReport::run("Build the image", 0)
            },
            StepReport {
                id: Some("push".into()),
                name: "Push the image".into(),
                uses: Some("docker/build-push-action@v6".into()),
                // `if: inputs.push` was false: not a pass, not a failure.
                outcome: Some(StepOutcome::Skipped),
                ..StepReport::run("Push the image", 0)
            },
        ],
        provenance: local_provenance(1),
        claims: claims("2c3d4e5f60718293", 1_793_092_502_500_000),
    }
}

/// Case 4: a failing run is provable too, which is the point of an attestation.
fn test_failure() -> RunReport {
    RunReport {
        repo: Some("gitiup/gitiup".into()),
        commit: sha1(0xdd),
        workflow: WorkflowSource::from_text(
            ".github/workflows/ci.yml",
            "name: CI\non: pull_request\n",
        ),
        event: EventReport {
            name: "pull_request".into(),
            action: Some("opened".into()),
            payload: Material::text(r#"{"action":"opened","number":7}"#),
        },
        job: Some("test".into()),
        matrix: BTreeMap::from([("os".to_string(), "macos".into())]),
        inputs: BTreeMap::new(),
        secret_names: Vec::new(),
        pins: BTreeMap::from([(
            "actions/checkout@v4".to_string(),
            ActionPin {
                repo: "actions/checkout".into(),
                commit: sha1(0xcd),
                reference: Some("v4".into()),
            },
        )]),
        reusable_workflows: Vec::new(),
        environment: EnvironmentReport {
            provider: Some("shell".into()),
            os: Some("macos".into()),
            os_version: None,
            arch: "aarch64".into(),
            image: None,
            toolchain: vec![ToolchainEntry {
                name: "rustc".into(),
                version: "1.99.1".into(),
            }],
        },
        steps: vec![
            StepReport {
                id: Some("checkout".into()),
                uses: Some("actions/checkout@v4".into()),
                stdout: Material::text("Checked out dddddd\n"),
                ..StepReport::run("Checkout", 0)
            },
            StepReport {
                id: Some("test".into()),
                stdout: Material::text("running 3 tests\ntest slow_one ... FAILED\n"),
                // stderr is part of the digest: a run that hides its errors is not
                // reproducible, it is merely quiet.
                stderr: Material::text("error: test failed, to rerun pass `--lib`\n"),
                ..StepReport::run("cargo test", 101)
            },
            StepReport {
                id: Some("publish".into()),
                outcome: Some(StepOutcome::Skipped),
                ..StepReport::run("Publish", 0)
            },
        ],
        provenance: Provenance {
            tier: Tier::Local,
            runner: "gitiup 0.1.0".into(),
            normalisation_version: RAW_NORMALISATION_VERSION,
            sandbox: Some("landlock".into()),
        },
        claims: claims("3d4e5f60718293a4", 1_793_092_502_500_000),
    }
}

/// Case 5: a release triggered by hand. Every input type, a sha256-format
/// repository, a multipart event payload, and the claims a quorum round needs.
fn dispatch_release() -> RunReport {
    RunReport {
        repo: Some("gitiup/gitiup".into()),
        commit: GitOid::new(OidAlgorithm::Sha256, &[0x5a; 32]).unwrap(),
        workflow: committed(".github/workflows/release.yml", 0xee),
        event: EventReport {
            name: "workflow_dispatch".into(),
            action: Some("workflow_dispatch".into()),
            // Hashed as parts with explicit lengths: headers and body are
            // separate pieces of the thing that arrived.
            payload: Material::parts([
                "{\"ref\":\"refs/heads/main\",\"inputs\":{",
                "\"version\":\"0.1.0\",\"draft\":true,\"jobs\":8}}",
            ]),
        },
        job: Some("release".into()),
        matrix: BTreeMap::from([("target".to_string(), "x86_64-unknown-linux".into())]),
        inputs: BTreeMap::from([
            ("draft".to_string(), InputValue::Bool(true)),
            ("jobs".to_string(), InputValue::Int(8)),
            ("version".to_string(), InputValue::Text("0.1.0".into())),
        ]),
        secret_names: vec!["GITEA_TOKEN".into(), "SIGNING_PASSPHRASE".into()],
        pins: BTreeMap::from([(
            "gitiup/attest-action@v1".to_string(),
            ActionPin {
                repo: "gitiup/attest-action".into(),
                commit: sha1(0x77),
                reference: Some("v1".into()),
            },
        )]),
        reusable_workflows: vec![committed(".github/workflows/_release-lib.yml", 0xff)],
        environment: EnvironmentReport {
            provider: Some("podman".into()),
            os: Some("linux".into()),
            os_version: None,
            arch: "x86_64".into(),
            image: Some(ImageRef {
                reference: None,
                digest: Digest::sha256(b"quay.io/gitiup/release@sha256:001122334455"),
            }),
            toolchain: vec![ToolchainEntry {
                name: "gitiup".into(),
                version: "0.1.0".into(),
            }],
        },
        steps: vec![
            StepReport {
                id: Some("package".into()),
                stdout: Material::digest(Digest::sha256(b"built gitiup-0.1.0.tar.zst\n")),
                artifacts: vec![ArtifactReport {
                    name: "release-tar".into(),
                    content: Material::parts(["gitiup-0.1.0/".to_string(), "\0".repeat(4096)]),
                    size_bytes: Some(4103),
                }],
                outputs: BTreeMap::from([("version".to_string(), "0.1.0".into())]),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_502_500_000),
                    duration_us: Some(1_200_000),
                }),
                ..StepReport::run("Package", 0)
            },
            StepReport {
                id: Some("attest".into()),
                uses: Some("gitiup/attest-action@v1".into()),
                stdout: Material::digest(Digest::sha256(b"attested 1 artifact\n")),
                ..StepReport::run("Attest", 0)
            },
        ],
        provenance: local_provenance(1),
        claims: ClaimReport {
            run_id: "4e5f60718293a4b5".into(),
            claimed_at_us: 1_793_092_502_500_000,
            not_before_us: Some(1_793_092_500_000_000),
            not_after_us: Some(1_793_092_862_500_000),
            verifier_challenge: Some(Digest::sha256(b"round-7731-challenge")),
            timings: vec![TimingReport {
                step: "attest".into(),
                started_us: Some(1_793_092_503_700_000),
                duration_us: Some(90_000),
            }],
            normalisation_diffs: vec![NormalisationDiff {
                step: "package".into(),
                kind: "path".into(),
                before: "/var/tmp/run-7731/dist".into(),
                after: "<tmp>/dist".into(),
            }],
            annotations: BTreeMap::from([("x_verifier".to_string(), "ci-sentinel.example".into())]),
        },
    }
}

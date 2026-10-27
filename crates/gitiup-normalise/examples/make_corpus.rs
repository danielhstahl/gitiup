//! Generate the reproducibility corpus: one workflow, run on two machines.
//!
//! ```sh
//! GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-normalise --example make_corpus
//! ```
//!
//! This is the acceptance criterion for giti-1rs.3, written down as data. Two run
//! reports — the *same* workflow on the *same* commit on two machines of the same
//! architecture — that a naive digest of differs in every way real logs differ, and
//! that the profile converges to one `ResultDigest`.
//!
//! The two files disagree about, in one line each:
//!
//! | divergence | machine A | machine B |
//!|------------|-----------|-----------|
//!| timestamp spelling | `2026-10-27T09:11:12.481392Z` | `2026-10-27 09:11:12` |
//!| git committer date | `Mon Oct 27 09:11:13 2026 +0000` | `Mon, 27 Oct 2026 09:11:15 +0000` |
//!| durations | `in 41.283s` | `in 2.004s` |
//!| build root | `/home/runner/work/gitiup/gitiup` | `/tmp/build0a9f` |
//!| temp root | `$RUNNER_TEMP/dist` | `${TMPDIR}/x/dist` |
//!| host and user | `fv-az1024.internal`, `runner`, uid 1001 | `build-07.example`, `ci`, uid 1000 |
//!| terminal churn | ANSI colours, a progress bar, carriage redraws | plain text |
//!| number and size spelling | `1,234,567`, `1.5 MiB` | `1234567`, `1536 bytes` |
//!| decimal separator | `1.5 seconds` | `1,5 seconds` |
//!| size spelling | `1.5 KiB` | `1536 bytes` |
//!| line endings | LF | CRLF |
//!| listing order | whatever `find` returned | whatever the other filesystem returned |
//!| run identity | run id, clock, step durations | different ones |
//!
//! Everything that is *not* on that list is byte-identical, which is what makes the
//! converged digest meaningful rather than a coincidence: the profile is not
//! throwing the logs away, it is throwing away the rows of that table.
//!
//! Regenerating is deliberate: the digests in `expected.json` are the contract, and
//! `tests/corpus.rs` fails if they move
//! ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::collections::BTreeMap;
use std::path::PathBuf;

use gitiup_attest::manifest::{ActionPin, InputValue, Provenance, Tier};
use gitiup_attest::oid::GitOid;
use gitiup_attest::run::{
    ArtifactReport, ClaimReport, EnvironmentReport, EventReport, Material, RunReport, StepReport,
    TimingReport, WorkflowSource,
};
use gitiup_attest::{Digest, ImageRef, RunManifest, StepTiming, ToolchainEntry};
use gitiup_normalise::{PROFILE_VERSION, Profile};

/// Where the fixtures live.
fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus")
}

/// The commit both machines ran.
fn commit() -> GitOid {
    GitOid::from_sha1_hex(&"1".repeat(40)).unwrap()
}

/// The workflow source both machines read.
fn workflow() -> WorkflowSource {
    WorkflowSource::from_text(
        ".github/workflows/ci.yml",
        "name: CI\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-24.04\n",
    )
}

/// The environment: machine *class*, identical on both — same architecture, same
/// digest-pinned image, same toolchain. Two machines of two different classes are
/// not expected to agree, and the fingerprint is where that is recorded.
fn environment() -> EnvironmentReport {
    EnvironmentReport {
        provider: Some("docker".into()),
        os: Some("linux".into()),
        arch: "x86_64".into(),
        image: Some(ImageRef {
            reference: Some("ghcr.io/gitiup/ci:2026-10".into()),
            digest: Digest::sha256(b"ghcr.io/gitiup/ci@sha256:9f2c"),
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
    }
}

/// What both machines were asked to run, and what they resolved. Identical, because
/// the contract says pins are SHAs and images are digests.
fn common(report: &mut RunReport) {
    report.repo = Some("gitiup/gitiup".into());
    report.commit = commit();
    report.workflow = workflow();
    report.event = EventReport {
        name: "pull_request".into(),
        action: Some("synchronize".into()),
        payload: Material::text("{\"action\":\"synchronize\",\"number\":7}"),
    };
    report.job = Some("build".into());
    report.matrix = BTreeMap::from([("os".to_string(), "ubuntu-24.04".into())]);
    report.inputs = BTreeMap::from([
        ("jobs".to_string(), InputValue::Int(4)),
        ("coverage".to_string(), InputValue::Bool(true)),
        ("toolchain".to_string(), InputValue::Text("1.99.1".into())),
    ]);
    report.secret_names = vec!["CODECOV_TOKEN".into(), "NPM_TOKEN".into()];
    report.pins = BTreeMap::from([(
        "actions/checkout@v4".to_string(),
        ActionPin {
            repo: "actions/checkout".into(),
            commit: GitOid::from_sha1_hex(&"c".repeat(40)).unwrap(),
            reference: Some("v4".into()),
        },
    )]);
    report.reusable_workflows = vec![WorkflowSource::committed(
        ".github/workflows/_lint.yml",
        GitOid::from_sha1_hex(&"d".repeat(40)).unwrap(),
    )];
    report.environment = environment();
    report.provenance = Provenance {
        tier: Tier::Local,
        runner: "gitiup 0.1.0".into(),
        normalisation_version: PROFILE_VERSION,
        sandbox: Some("docker".into()),
    };
}

/// Machine A: a hosted runner. ISO timestamps with microseconds, ANSI output,
/// progress redraws, a comma-grouped count, SI-abbreviated sizes, LF line endings,
/// and the directory listing in the order `find` produced it.
fn machine_a() -> RunReport {
    let mut report = RunReport {
        steps: vec![
            StepReport {
                id: Some("checkout".into()),
                name: "Checkout".into(),
                uses: Some("actions/checkout@v4".into()),
                exit_code: 0,
                stdout: Material::text(
                    "Runner host: fv-az1024.internal\n\
                     uid=1001(runner) gid=1001(runner) groups=1001(runner)\n\
                     [2026-10-27T09:11:12.481392Z] Syncing repository gitiup/gitiup\n\
                     runner@fv-az1024:~$\n\
                     > git fetch --no-tags --prune --depth=1 origin +refs/pull/7/merge:\n\
                     HEAD is now at 1a2b3c4 Add the runner\n\
                     Date:   Mon Oct 27 09:11:13 2026 +0000\n",
                ),
                stderr: Material::text(""),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_272_481_392),
                    duration_us: Some(1_120_004),
                }),
                ..StepReport::run("Checkout", 0)
            },
            StepReport {
                id: Some("build".into()),
                name: "cargo build".into(),
                exit_code: 0,
                stdout: Material::text(
                    "\u{1b}[1m\u{1b}[32m   Compiling\u{1b}[0m gitiup v0.1.0 (/home/runner/work/gitiup/gitiup)\n\
                     warning: unused variable: `scratch`\n\
                     Finished dev [unoptimized + debuginfo] target(s) in 41.283s\n\
                     workspace /home/runner/work/gitiup/gitiup/target/debug/gitiup\n\
                     \r####---- 45%\n\
                     Downloading 12%\rDownloading 47%\rDownloading 100%\n\
                     size 1.5 KiB target/debug/gitiup\n",
                ),
                stderr: Material::text("warning: 1 warning emitted\n"),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_273_601_400),
                    duration_us: Some(41_283_002),
                }),
                ..StepReport::run("cargo build", 0)
            },
            StepReport {
                id: Some("test".into()),
                name: "cargo test".into(),
                exit_code: 0,
                stdout: Material::text(
                    "test result: ok. 118 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\
                     \u{1b}[32mok\u{1b}[0m coverage: 1,234,567 lines covered in 1.5 seconds\n\
                     drwxr-xr-x  4 runner runner 4096 Oct 27 09:11 target\n\
                     -rw-r--r--  1 runner runner 1536 Oct 27 09:12 README.md\n",
                ),
                stderr: Material::text(""),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_314_884_402),
                    duration_us: Some(903_011),
                }),
                ..StepReport::run("cargo test", 0)
            },
            StepReport {
                id: Some("package".into()),
                name: "Package".into(),
                exit_code: 0,
                stdout: Material::text(
                    "dist/gitiup-linux-x86_64.tar.gz\n\
                     dist/SHA256SUMS\n\
                     dist/coverage.lcov\n\
                     $RUNNER_TEMP/dist/gitiup.tar\n",
                ),
                stderr: Material::text(""),
                artifacts: vec![ArtifactReport {
                    name: "coverage".into(),
                    content: Material::files([("cov/lcov.info", Material::text("TN:\nDA:1,1\n"))]),
                    size_bytes: None,
                }],
                outputs: BTreeMap::from([("size".to_string(), "1536".into())]),
                ..StepReport::run("Package", 0)
            },
        ],
        claims: ClaimReport {
            run_id: "0a0b0c0d0e0f1011".into(),
            claimed_at_us: 1_793_092_315_848_417,
            not_before_us: None,
            not_after_us: None,
            verifier_challenge: None,
            timings: vec![TimingReport {
                step: "package".into(),
                started_us: None,
                duration_us: Some(61_004),
            }],
            normalisation_diffs: Vec::new(),
            annotations: BTreeMap::from([("x_ci".to_string(), "hosted".into())]),
        },
        ..blank()
    };
    common(&mut report);
    report
}

/// Machine B: a self-hosted container runner. Same workflow, same tools, same
/// result — different everything else. CRLF line endings, no colours, no progress
/// bar, a French locale for one number, a decimal comma, and the directory listing
/// in the other order.
fn machine_b() -> RunReport {
    let mut report = RunReport {
        steps: vec![
            StepReport {
                id: Some("checkout".into()),
                name: "Checkout".into(),
                uses: Some("actions/checkout@v4".into()),
                exit_code: 0,
                stdout: Material::text(
                    "Runner host: build-07.example\r\n\
                     uid=1000(ci) gid=1000(ci) groups=1000(ci),27(sudo)\r\n\
                     [2026-10-27 09:11:12] Syncing repository gitiup/gitiup\r\n\
                     ci@build-07:~$\r\n\
                     > git fetch --no-tags --prune --depth=1 origin +refs/pull/7/merge:\r\n\
                     HEAD is now at 1a2b3c4 Add the runner\r\n\
                     Date:   Mon, 27 Oct 2026 09:11:15 +0000\r\n",
                ),
                stderr: Material::text(""),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_400_000_000),
                    duration_us: Some(4_003_120),
                }),
                ..StepReport::run("Checkout", 0)
            },
            StepReport {
                id: Some("build".into()),
                name: "cargo build".into(),
                exit_code: 0,
                stdout: Material::text(
                    "   Compiling gitiup v0.1.0 (/tmp/build0a9f)\r\n\
                     warning: unused variable: `scratch`\r\n\
                     Finished dev [unoptimized + debuginfo] target(s) in 2.004s\r\n\
                     workspace /tmp/build0a9f/target/debug/gitiup\r\n\
                     Downloading 100%\r\n\
                     size 1536 bytes target/debug/gitiup\r\n",
                ),
                stderr: Material::text("warning: 1 warning emitted\r\n"),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_404_003_120),
                    duration_us: Some(2_004_000),
                }),
                ..StepReport::run("cargo build", 0)
            },
            StepReport {
                id: Some("test".into()),
                name: "cargo test".into(),
                exit_code: 0,
                stdout: Material::text(
                    "test result: ok. 118 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\r\n\
                     ok coverage: 1234567 lines covered in 1,5 seconds\r\n\
                     -rw-r--r--  1 ci ci 1536 Oct 27 09:15 README.md\r\n\
                     drwxr-xr-x  4 ci ci 4096 Oct 27 09:14 target\r\n",
                ),
                stderr: Material::text(""),
                timing: Some(StepTiming {
                    started_us: Some(1_793_092_406_007_120),
                    duration_us: Some(3_400_000),
                }),
                ..StepReport::run("cargo test", 0)
            },
            StepReport {
                id: Some("package".into()),
                name: "Package".into(),
                exit_code: 0,
                stdout: Material::text(
                    "dist/SHA256SUMS\r\n\
                     dist/coverage.lcov\r\n\
                     dist/gitiup-linux-x86_64.tar.gz\r\n\
                     ${TMPDIR}/x/dist/gitiup.tar\r\n",
                ),
                stderr: Material::text(""),
                artifacts: vec![ArtifactReport {
                    name: "coverage".into(),
                    content: Material::files([("cov/lcov.info", Material::text("TN:\nDA:1,1\n"))]),
                    size_bytes: None,
                }],
                outputs: BTreeMap::from([("size".to_string(), "1536".into())]),
                ..StepReport::run("Package", 0)
            },
        ],
        claims: ClaimReport {
            run_id: "ffeeddccbbaa0011".into(),
            claimed_at_us: 1_793_092_409_547_122,
            not_before_us: None,
            not_after_us: None,
            verifier_challenge: None,
            timings: vec![TimingReport {
                step: "package".into(),
                started_us: None,
                duration_us: Some(140_002),
            }],
            normalisation_diffs: Vec::new(),
            annotations: BTreeMap::from([("x_ci".to_string(), "self-hosted".into())]),
        },
        ..blank()
    };
    common(&mut report);
    report
}

/// A report with nothing but the fields `common` fills in.
fn blank() -> RunReport {
    RunReport {
        repo: None,
        commit: commit(),
        workflow: workflow(),
        event: EventReport {
            name: "push".into(),
            action: None,
            payload: Material::text("{}"),
        },
        job: None,
        matrix: BTreeMap::new(),
        inputs: BTreeMap::new(),
        secret_names: Vec::new(),
        pins: BTreeMap::new(),
        reusable_workflows: Vec::new(),
        environment: environment(),
        steps: Vec::new(),
        provenance: Provenance {
            tier: Tier::Local,
            runner: "gitiup 0.1.0".into(),
            normalisation_version: PROFILE_VERSION,
            sandbox: Some("docker".into()),
        },
        claims: ClaimReport {
            run_id: "0000000000000000".into(),
            claimed_at_us: 0,
            not_before_us: None,
            not_after_us: None,
            verifier_challenge: None,
            timings: Vec::new(),
            normalisation_diffs: Vec::new(),
            annotations: BTreeMap::new(),
        },
    }
}

fn main() {
    let force = std::env::var("GITIUP_UPDATE_FIXTURES").is_ok_and(|v| v == "1");
    let dir = corpus_dir();
    let profile = Profile::standard();

    let machines = [("machine-a", machine_a()), ("machine-b", machine_b())];
    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    let mut kinds: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, report) in &machines {
        let run = gitiup_normalise::manifest_for(report).expect("the corpus normalises");
        let digest = run.manifest.result_digest().unwrap().to_string();
        println!("{name}: ResultDigest {digest}");
        digests.insert((*name).into(), digest);
        let mut kinds_seen: Vec<String> = run.diffs.iter().map(|diff| diff.kind.clone()).collect();
        kinds_seen.sort();
        kinds_seen.dedup();
        kinds.insert((*name).into(), kinds_seen);
        // Debug aid while editing the corpus: what still disagrees.
        if name == &"machine-b" {
            let comparison = gitiup_normalise::compare_runs(&machines[0].1, report)
                .expect("the corpus compares");
            if !comparison.converged {
                eprintln!("--- NOT CONVERGED ---");
                for divergence in &comparison.divergences {
                    eprintln!(
                        "{:<12} {:<22} - {}",
                        divergence.step, divergence.kind, divergence.before
                    );
                    eprintln!("{:<12} {:<22} + {}", "", "", divergence.after);
                }
            }
        }
        if force {
            let path = dir.join(name).join("run.json");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                format!("{}\n", serde_json::to_string_pretty(report).unwrap()),
            )
            .unwrap();
            println!("wrote {}", path.display());
        }
    }

    // The naive digest, for the test that proves the corpus is not trivially equal.
    let naive: Vec<String> = machines
        .iter()
        .map(|(_, report)| {
            // The same reports, with the profile's rewrite taken back out: what a
            // build that normalised nothing would have hashed.
            let mut raw = report.clone();
            raw.provenance.normalisation_version = 0;
            raw.claims.timings = Vec::new();
            for step in raw.steps.iter_mut() {
                step.timing = None;
            }
            RunManifest::from_run(&raw)
                .map(|manifest| manifest.result_digest().unwrap().to_string())
                .unwrap_or_else(|error| format!("refused: {error}"))
        })
        .collect();
    assert_ne!(
        naive[0], naive[1],
        "if these match, the corpus has stopped exercising nondeterminism"
    );

    let expected = serde_json::json!({
        "comment": "One workflow, two machines. The ResultDigests are equal because gitiup-normalise rewrites what a log says about the machine; they are NOT equal without normalisation (see the `naive` digests below, and tests/corpus.rs). Regenerate with GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-normalise --example make_corpus.",
        "profile_version": profile.version(),
        "result_digest": digests.values().next().unwrap(),
        "result_digests": digests,
        "kinds": kinds,
        "naive_result_digests": naive,
    });
    if force {
        std::fs::write(
            dir.join("expected.json"),
            format!("{}\n", serde_json::to_string_pretty(&expected).unwrap()),
        )
        .unwrap();
        println!("wrote {}/expected.json", dir.display());
    } else {
        println!(
            "pass GITIUP_UPDATE_FIXTURES=1 to write the fixtures\n{}",
            serde_json::to_string_pretty(&expected).unwrap()
        );
    }
}

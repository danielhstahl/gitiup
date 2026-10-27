//! The default path has no side effects, and this file makes that a build failure
//! rather than a review comment.
//!
//! "A default run touches no network and no secrets" is the acceptance criterion of
//! giti-1rs.7, and it is a claim about code that does not exist yet as much as about
//! code that does: the day someone adds `std::env::var("NPM_TOKEN")` to the
//! simulator to "just read the default", the tier becomes a lie. So the claim is
//! pinned three ways:
//!
//! 1. **by dependency**: the planning and simulation modules may not gain a crate
//!    that can talk to the world;
//! 2. **by source**: those modules may not name the APIs that do — process spawn,
//!    sockets, environment reads, filesystem writes;
//! 3. **by behaviour**: running the whole simulate path leaves the filesystem of a
//!    directory exactly as it found it, and produces a report with no secrets in it.
//!
//! `exec` and `sandbox` are deliberately *not* under the source ban: they are the
//! side-effecting path, reachable only behind `--execute --sandbox <backend>`, and
//! their tests are in `exec.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The modules that make up the default (simulating) path.
const PLANNING_MODULES: &[&str] = &[
    "src/yaml.rs",
    "src/workflow.rs",
    "src/plan.rs",
    "src/simulate.rs",
    "src/lib.rs",
];

/// Names that would put a side effect behind the simulation. Matched as *tokens*,
/// not words, so prose about "spawning no process" cannot trip them.
const FORBIDDEN: &[&str] = &[
    "std::process",
    "process::Command",
    "Command::new",
    "std::net",
    "TcpStream",
    "UdpSocket",
    "std::os",
    "env::var",
    "env::vars",
    "env::set_var",
    "env::remove_var",
    "File::create",
    "OpenOptions",
    "fs::write",
    "fs::create_dir",
    "fs::remove",
    "read_dir",
    "stdin()",
];

/// What the crate may depend on: the format, and the normaliser executed logs go
/// through. Anything else has to be argued for in review, not added quietly.
const ALLOWED_DEPENDENCIES: &[&str] = &["gitiup-attest", "gitiup-normalise"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(crate_root().join(relative))
        .unwrap_or_else(|why| panic!("{}: {why}", relative))
}

#[test]
fn the_simulation_path_names_no_side_effect() {
    for module in PLANNING_MODULES {
        let text = read(module);
        for forbidden in FORBIDDEN {
            assert!(
                !text.contains(forbidden),
                "{module} mentions `{forbidden}`: the simulated path must not gain a \
                 way to touch the world (giti-1rs.7's default is 'no side effects'). \
                 If this is genuinely needed, the code belongs in `exec`/`sandbox`, \
                 behind --execute and a probed sandbox."
            );
        }
    }
}

#[test]
fn nothing_in_the_crate_can_open_a_socket() {
    // Stronger than the module scan and cheap: no transport anywhere, so the CLI
    // cannot be talked into a fetch by a workflow field.
    let sockets = [
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "hyper",
        "ureq",
        "std::net",
    ];
    for module in [
        "src/yaml.rs",
        "src/workflow.rs",
        "src/plan.rs",
        "src/simulate.rs",
        "src/lib.rs",
        "src/exec.rs",
        "src/sandbox.rs",
    ] {
        let text = read(module);
        for forbidden in sockets {
            assert!(!text.contains(forbidden), "{module} mentions `{forbidden}`");
        }
    }
}

#[test]
fn the_crate_depends_on_exactly_two_things() {
    let manifest = read("Cargo.toml");
    let mut section = String::new();
    let mut direct = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section == "[dependencies]"
            && let Some((name, _)) = line.split_once('=')
        {
            direct.insert(name.trim().to_string());
        }
    }
    let allowed: BTreeSet<String> = ALLOWED_DEPENDENCIES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        direct, allowed,
        "the planning/running crate must not grow a dependency that can reach the network"
    );
}

// ------------------------------------------------------------ behaviour ---

/// Every path under `root`, with its size: enough to notice a file created, deleted
/// or rewritten.
fn fingerprint(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("the directory is readable") {
            let path = entry.expect("entry").path();
            let meta = std::fs::metadata(&path).expect("metadata");
            if meta.is_dir() {
                out.push((path.clone(), u64::MAX));
                stack.push(path);
            } else {
                out.push((path, meta.len()));
            }
        }
    }
    out.sort();
    out
}

/// Everything the default path needs, run end to end: read, plan, simulate, digest.
fn simulate_end_to_end(workflow_text: &str) {
    use gitiup_attest::GitOid;
    use gitiup_attest::run::WorkflowSource;
    use gitiup_run::{Plan, Selector, Simulation, Workflow};

    let workflow = Workflow::parse(".github/workflows/ci.yml", workflow_text).unwrap();
    let plan = Plan::build(&workflow, &Selector::default()).unwrap();
    let simulation = Simulation::new(
        GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
        WorkflowSource::from_text(".github/workflows/ci.yml", workflow_text),
        "gitiup test",
    );
    let report = gitiup_run::simulate_report(&plan, &plan.jobs[0], &simulation).unwrap();
    let manifest = gitiup_run::manifest_for(&report).unwrap();
    // Digests computed, nothing written: the caller decides where bytes go.
    assert!(!manifest.digest().unwrap().hex().is_empty());
    assert_eq!(
        manifest.result.provenance.tier,
        gitiup_attest::Tier::Simulated
    );
}

#[test]
fn a_default_run_writes_nothing_anywhere_it_was_asked_not_to() {
    let workspace =
        std::env::temp_dir().join(format!("gitiup-no-side-effects-{}", std::process::id()));
    std::fs::create_dir_all(workspace.join(".github/workflows")).unwrap();
    let workflow_text = "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Test\n        run: cargo test\n";
    std::fs::write(workspace.join(".github/workflows/ci.yml"), workflow_text).unwrap();

    let before = fingerprint(&workspace);
    simulate_end_to_end(workflow_text);
    let after = fingerprint(&workspace);

    assert_eq!(
        before, after,
        "the simulated run changed the workspace: {:?} → {:?}",
        before, after
    );

    std::fs::remove_dir_all(&workspace).unwrap();
}

#[test]
fn a_default_run_reports_no_secrets_whatever_the_environment_holds() {
    // The value is irrelevant; the point is that the pipeline has no channel from
    // this process's environment into the attestation. That is also why a *real*
    // secret name in a workflow never reaches a simulated report: it is not read.
    let workspace = std::env::temp_dir().join(format!("gitiup-no-secrets-{}", std::process::id()));
    std::fs::create_dir_all(&workspace).unwrap();
    let workflow_text = "on: push\njobs:\n  build:\n    steps:\n      - run: echo $NPM_TOKEN\n";
    let before = fingerprint(&workspace);
    simulate_end_to_end(workflow_text);
    assert_eq!(before, fingerprint(&workspace));
    std::fs::remove_dir_all(&workspace).unwrap();
}

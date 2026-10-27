//! The shortest complete story: a workflow file in, a plan and its digest out, and
//! the warning that comes with a plan.
//!
//! ```console
//! $ cargo run -p gitiup-run --example plan
//! ```
//!
//! This is what `gitiup run` does with the flags sorted out. The example exists so the
//! claim "a simulated run produces an attestable plan without touching anything" can be
//! checked by running it, and so the tier rule is visible outside the test suite:
//! nothing here can ask for a tier.

use gitiup_attest::run::WorkflowSource;
use gitiup_attest::{GitOid, Tier};
use gitiup_run::{Plan, Selector, Simulation, Workflow};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default to the workflow shipped next to this example, so the tour works from
    // anywhere in the repository.
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/gitiup-run/examples/ci.yml".to_string());
    let text = std::fs::read_to_string(&path)?;

    let workflow = Workflow::parse(&path, &text)?;
    for warning in &workflow.warnings {
        eprintln!("note: {warning}");
    }
    // No selector: the workflow has one job, which is what an attestation covers.
    let plan = Plan::build(&workflow, &Selector::default())?;
    let job = &plan.jobs[0];
    print!("{}", plan.describe());

    let mut simulation = Simulation::new(
        GitOid::from_sha1_hex(&"a".repeat(40))?,
        WorkflowSource::from_text(&path, text),
        concat!("gitiup-run example ", env!("CARGO_PKG_VERSION")),
    );
    simulation.event = workflow.event_for(None)?;
    simulation.matrix = job.matrix.clone();
    let report = gitiup_run::simulate_report(&plan, job, &simulation)?;
    let manifest = gitiup_run::manifest_for(&report)?;

    println!();
    println!("tier           {}", manifest.result.provenance.tier);
    println!(
        "sandbox        {}",
        manifest
            .result
            .provenance
            .sandbox
            .as_deref()
            .unwrap_or("(none)")
    );
    println!("run            {}", manifest.digest()?);
    println!("result         {}", manifest.result_digest()?);
    // The warning is the format crate's, so an embedding caller and this command say
    // the same sentence.
    if let Some(warning) = gitiup_run::warning_for(manifest.result.provenance.tier) {
        eprintln!("\nWARNING: {warning}");
        eprintln!(
            "WARNING: to run it for real: gitiup run --execute --sandbox unshare \
             (`{}` is what that earns; `quorum` is a verdict of independent verifiers)",
            Tier::Local
        );
    }
    Ok(())
}

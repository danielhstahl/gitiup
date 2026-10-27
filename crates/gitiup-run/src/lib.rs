//! `gitiup-run` — planning, running, and the provenance tier that follows from which
//! of the two happened (giti-1rs.7).
//!
//! The epic's question is "what did this CI run produce?", and the answer starts one
//! step earlier: **what was the run going to do, and did it actually happen?** This
//! crate is where that distinction is made once, instead of in every caller.
//!
//! ```text
//!  workflow YAML ──► Workflow ──► Plan ──┬── simulate ──► RunReport ──► attestation
//!                                       │                  tier: simulated
//!                                       └── execute ────► RunReport    sandbox: none
//!                                                          tier: local
//!                                                          sandbox: <probed backend>
//! ```
//!
//! # The two paths, and why the default is the safe one
//!
//! | | [`simulate`] | [`exec`] |
//!|---|---|---|
//!| side effects | none: no process, no socket, no write, no secret | the steps run as processes, in a probed sandbox |
//!| step outcome | assumed, and labelled as assumed | observed exit codes |
//!| tier | `simulated` | `local` |
//!| `sandbox` | `none`, and may not be anything else | the backend that was found working |
//!| default | yes | only with `--execute --sandbox <name>` |
//!
//! Simulation is the default because it is the only path that can be *guaranteed*
//! harmless: it opens nothing, so it is safe on a laptop, in a CI job that has
//! secrets in the environment, and in a container with no sandbox available. A plan
//! is still worth signing — it pins the workflow bytes, the commit, the matrix, the
//! action refs and the input set, which is what a reviewer needs to see a change's
//! CI *shape* before anything executes — but it is never evidence that anything ran,
//! which is why the format refuses a plan's self-contradictions
//! ([`Provenance::check`]) and the default policy refuses the tier outright
//! ([`Policy::allowed_tiers`]).
//!
//! `quorum` is the third tier and is never produced here: a quorum is a verdict drawn
//! from several independent attestations (giti-msi.7), so a run that claimed one
//! would be grading its own homework. The format refuses it, in the report and in the
//! manifest, so no caller has to remember to.
//!
//! # The one call a CLI needs
//!
//! [`manifest_for`] turns a produced [`RunReport`] into a signable
//! [`RunManifest`], applying the normalisation profile only where the logs were
//! really produced (`local`) and hashing-as-handed-over where the text is our own
//! (`simulated`). Choosing per tier is not a shortcut: claiming a normalisation
//! version nothing performed would be the one kind of lie a digest cannot catch.
//!
//! # What is *not* here
//!
//! * **no file paths in the API** beyond the workspace directory the steps run in —
//!   reading the workflow and writing the attestation are the CLI's job, so this
//!   crate stays testable in-process;
//! * **no signing** — keys are giti-1rs.6, and `gitiup_attest::SigningKey` plugs in
//!   where a caller wants a signature;
//! * **no expression engine** — `if:` and `${{ … }}` are recorded as written and
//!   assumed to run, in the plan text and in the attestation's annotations, because
//!   a plan that guessed is a plan that lied quietly;
//! * **no action fetching** — `uses:` steps are planned, and refused at execution
//!   time (giti-bgy.4 owns pinning and fetching).
//!
//! ```
//! use gitiup_attest::{GitOid, run::WorkflowSource};
//! use gitiup_run::{Plan, Selector, Simulation, Workflow, simulate};
//!
//! let source = "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n      - run: cargo test\n";
//! let workflow = Workflow::parse(".github/workflows/ci.yml", source).unwrap();
//! let plan = Plan::build(&workflow, &Selector::default()).unwrap();
//! let simulation = Simulation::new(
//!     GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
//!     WorkflowSource::from_text(".github/workflows/ci.yml", "on: push\n"),
//!     "gitiup 0.1.0",
//! );
//! let report = simulate::report(&plan, &plan.jobs[0], &simulation).unwrap();
//!
//! // Two tiers, one sentence apart, and a digest that can never be confused.
//! assert_eq!(report.provenance.tier, gitiup_attest::Tier::Simulated);
//! let manifest = gitiup_run::manifest_for(&report).unwrap();
//! assert_eq!(manifest.result.steps.len(), 2);
//! assert!(manifest.result.secret_names.is_empty(), "a plan touches no secrets");
//! assert_eq!(
//!     manifest.result.provenance.sandbox.as_deref(),
//!     Some("none")
//! );
//! ```

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

pub mod exec;
pub mod plan;
pub mod sandbox;
pub mod simulate;
pub mod workflow;
pub mod yaml;

use gitiup_attest::run::RunReport;
use gitiup_attest::{Error, Result, RunManifest, Tier};

pub use exec::{Execution, execute};
pub use plan::{MAX_MATRIX_ARMS, Plan, PlannedJob, PlannedStep, Selector};
pub use sandbox::{Backend, NOT_IMPLEMENTED, Sandbox, detect, implemented, open};
pub use simulate::{
    Replay, SIMULATED_PROVIDER, Simulation, report as simulate_report, result_digest,
};

/// Re-exported so a caller has one path from a plan to a digest without naming a
/// second crate.
pub use gitiup_attest::ResultDigest;
pub use workflow::{Job, Step, Workflow};

/// The manifest of a produced report — one call, so a caller cannot pick the wrong
/// digest recipe.
///
/// * `tier: simulated` — the log text is this crate's own description, contains
///   nothing machine-specific, and is hashed exactly as written (version `0`: "no
///   rewrite happened", which is true).
/// * `tier: local` — the logs came off a process, so they go through the
///   reproducibility profile before hashing, and the version recorded is the
///   profile's, not this crate's ([`gitiup_normalise::manifest_for`]).
///
/// Anything else (a hand-written report, a `quorum`-tiered report that the format
/// will refuse anyway) is refused instead of guessed about: the digest recipe is not
/// a caller's preference.
pub fn manifest_for(report: &RunReport) -> Result<RunManifest> {
    match report.provenance.tier {
        Tier::Simulated => RunManifest::from_run(report),
        Tier::Local => gitiup_normalise::manifest_for(report).map(|done| done.manifest),
        Tier::Quorum => Err(Error::new(
            gitiup_attest::ErrorKind::Policy,
            "provenance",
            "a single run may not claim the quorum tier",
        )
        .with_hint("quorum is a verdict over several attestations (giti-msi.7)")),
    }
}

/// The loud sentence a trust-bearing use of a tier deserves, if any.
///
/// `None` for `local`: a warning printed every run is a warning nobody reads, and the
/// simulated tier is the one whose meaning is routinely over-read.
pub fn warning_for(tier: Tier) -> Option<&'static str> {
    tier.trust_warning()
}

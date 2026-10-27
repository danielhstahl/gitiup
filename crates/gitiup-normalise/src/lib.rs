//! `gitiup-normalise` — the output normalisation profile, and the reproducibility
//! contract that makes two independent runs hash alike.
//!
//! The digest of a CI run is only useful if a stranger's rerun produces it. Real
//! logs do not cooperate: they carry wall-clock time, durations, the temporary
//! directory this runner happened to get, the hostname, the uid of the build user,
//! the locale the tool was told to speak, a progress bar redrawn at whatever the
//! refresh rate was, and the line endings the shell wrote. Every one of those is a
//! *fact about the machine*, and none of them is a fact about the result. This crate
//! turns those into placeholders so that two honest reruns converge on one digest,
//! and — when they still do not — says which line, which field and both sides,
//! instead of leaving a hash mismatch to be argued about.
//!
//! ```
//! use gitiup_attest::run::RunReport;
//! use gitiup_attest::run::Normaliser;
//! use gitiup_normalise::{Profile, manifest_for};
//!
//! # fn main() -> Result<(), gitiup_attest::Error> {
//! let log = "2026-10-27T09:11:12.481392Z /tmp/build0a9f/target/debug/gitiup\n";
//! let normalised = Profile::standard().normalise(log);
//! assert_eq!(
//!     normalised,
//!     "<ts> <build>/target/debug/gitiup\n",
//!     "the timestamp and the machine's build root are not the result"
//! );
//!
//! // And the whole report, in one call: digests plus the record of what was rewritten.
//! let report = RunReport::simple(
//!     "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!     ".github/workflows/ci.yml",
//!     "name: CI\n",
//!     "Finished in 12.5s\n",
//! )?;
//! let run = manifest_for(&report)?;
//! assert_eq!(run.manifest.result.provenance.normalisation_version, 1);
//! assert!(
//!     run.diffs
//!         .iter()
//!         .any(|diff| diff.kind == "duration" && diff.after.contains("<dur>")),
//!     "the rewrite is recorded, not silent"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # The two halves of the contract
//!
//! Normalisation is half of reproducibility and the workflow is the other half, and
//! they are not interchangeable:
//!
//! | | who | what |
//!|---|-----|------|
//!| the **profile** | this crate | rewrites what a log says about *the machine*: time, durations, paths, identity, churn, formatting |
//!| the **contract** | the workflow ([`docs/reproducibility.md`](../../../docs/reproducibility.md)) | stops the build baking machine state into *its products*: pin actions by SHA, images by digest, sort manifests, honour `SOURCE_DATE_EPOCH`, no timestamps in artifacts |
//!
//! A normaliser cannot fix an artifact whose bytes contain a build timestamp, and it
//! should not try: the digest of an artifact is the point of the artifact. See
//! [`crate::grammar::Rule`] for exactly what is rewritten, and
//! [`crate::rewrite`] for how it is reported.
//!
//! # Where this plugs in
//!
//! [`gitiup_attest::run::Normaliser`] is the seam giti-1rs.2 left open; [`Profile`]
//! implements it, and [`RunManifest::from_run_with`] takes it. [`manifest_for`] is
//! the runner-side call that normalises a report's streams, records the version,
//! fills `claims.normalisation_diffs` and returns the manifest to sign.
//! [`compare_runs`] is the verifier-side call: two runs of one workflow in, a
//! converged flag and a structured list of what still differs.
//!
//! ```text
//! raw logs ──Profile::normalise──► normalised text ──sha256──► Step { stdout, stderr }
//!                                                                  │
//!   run report ──manifest_for──► RunManifest ──encode──► sha256 ──► RunDigest / ResultDigest
//! ```
//!
//! # The version is the contract
//!
//! Version `0` is "nothing was rewritten" ([`gitiup_attest::run::RawText`]); this
//! profile is version `1` ([`PROFILE_VERSION`]). Rule sets are not free to change
//! quietly: two results normalised by different rules are not comparable, so a rule
//! that changes an output is a new version, and a new version is a documented change
//! to the format (ADR-0001 D8), not a refactoring.
//!
//! [`RunManifest::from_run_with`]: gitiup_attest::RunManifest::from_run_with
//! [`docs/reproducibility.md`]: ../../../docs/reproducibility.md

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

mod grammar;
mod log;
mod manifest;
mod paths;
mod profile;
mod rewrite;
mod run;
mod term;
mod values;

pub use grammar::{PROFILE_NAME, PROFILE_VERSION, RULE_ORDER, Rule, Rules};
// The diff type is the format crate's: one record for "something was rewritten" and
// "two runs disagree", carried by the manifest, printed by the CLI, and defined once.
pub use gitiup_attest::NormalisationDiff;
pub use manifest::{NormalisedRun, manifest_for, manifest_for_with};
pub use profile::{MAX_REWRITES, Normalised, Profile};
pub use rewrite::{Divergences, Rewrite, Rewrites, Stream};
pub use run::{Comparison, RUN_STEP, compare_runs, compare_runs_with};

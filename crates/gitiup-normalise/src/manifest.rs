//! Report in, manifest out — with the rewrites recorded.
//!
//! [`manifest_for`] is the runner-side entry point: the call a runner makes when it
//! has a finished run and wants the manifest to sign. It is
//! [`gitiup_attest::RunManifest::from_run_with`] plus the two things a runner would
//! otherwise get wrong:
//!
//! * the log digests are the *normalised* bytes, and
//!   `provenance.normalisation_version` is the profile that produced them — not
//!   whatever the caller felt like writing;
//! * `claims.normalisation_diffs` says what was rewritten, which is what makes a
//!   later dispute debuggable instead of a mystery. That field lives in `claims`
//!   precisely because the `before` side is machine-specific and must never enter a
//!   digest (ADR-0001 D5).

use gitiup_attest::run::{Material, RunReport};
use gitiup_attest::{Digest, Error, NormalisationDiff, Result, RunManifest};

use crate::log;
use crate::profile::{MAX_REWRITES, Profile};
use crate::rewrite::{Rewrites, Stream};

/// A manifest and the record of what normalisation had to do to produce it.
#[derive(Debug, Clone)]
pub struct NormalisedRun {
    /// The manifest to sign: validated, normalized, fingerprint derived.
    pub manifest: RunManifest,
    /// What was rewritten — one per (step, kind, stream), and already in
    /// `manifest.claims.normalisation_diffs`.
    pub diffs: Vec<NormalisationDiff>,
    /// The full per-stream records, for `gitiup normalise` and for a runner's log.
    pub records: Vec<(String, Stream, Rewrites)>,
}

/// [`manifest_for_with`] with the standard profile.
pub fn manifest_for(report: &RunReport) -> Result<NormalisedRun> {
    manifest_for_with(report, &Profile::standard())
}

/// Normalise a report's log streams and compute its manifest.
///
/// A stream that arrives **pre-hashed** is left alone: somebody else normalised it,
/// under rules this build cannot see, so the declared `normalisation_version`
/// stands as their claim. A stream handed over **in the clear** is normalised here,
/// and the version is rewritten to say which profile produced the digest — which is
/// only honest if every log stream was produced the same way, so a report that
/// mixes the two is refused rather than averaged.
///
/// ```
/// use gitiup_attest::run::RunReport;
/// use gitiup_normalise::manifest_for;
/// # fn main() -> Result<(), gitiup_attest::Error> {
/// let report = RunReport::simple(
///     "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
///     ".github/workflows/ci.yml",
///     "name: CI\n",
///     "Finished in 12.5s\n",
/// )?;
/// let run = manifest_for(&report)?;
/// // The version says what happened, rather than being asserted by the caller.
/// assert_eq!(run.manifest.result.provenance.normalisation_version, 1);
/// // The rewrite is recorded, in the manifest a verifier will read.
/// assert!(run.diffs.iter().any(|diff| diff.kind == "duration"));
/// assert!(
///     run.manifest
///         .claims
///         .normalisation_diffs
///         .iter()
///         .any(|diff| diff.after.contains("<dur>"))
/// );
/// # Ok(())
/// # }
/// ```
pub fn manifest_for_with(report: &RunReport, profile: &Profile) -> Result<NormalisedRun> {
    report.validate()?;
    let mut rewritten = report.clone();
    let mut diffs: Vec<NormalisationDiff> = Vec::new();
    let mut records: Vec<(String, Stream, Rewrites)> = Vec::new();
    let mut normalised_here = false;
    let mut prehashed = false;

    for step in rewritten.steps.iter_mut() {
        let step_key = step.key();
        for (material, stream) in [
            (&mut step.stdout, Stream::Stdout),
            (&mut step.stderr, Stream::Stderr),
        ] {
            // A file set is a product, not a log: the workflow owns its ordering
            // (the contract says sort the artifact manifest), not the runner.
            if matches!(material, Material::Files(_)) {
                continue;
            }
            if material.is_prehashed() {
                if !material.is_empty() {
                    prehashed = true;
                }
                continue;
            }
            if material.is_empty() {
                // Every profile hashes nothing the same way, which is why an empty
                // stream needs no rules and no record.
                continue;
            }
            let parts: Vec<String> = match &*material {
                Material::Text(text) => vec![text.clone()],
                Material::Parts(parts) => parts.clone(),
                _ => continue,
            };
            let mut rewrites = Rewrites::with_cap(MAX_REWRITES);
            let normalised: Vec<String> = parts
                .iter()
                .map(|part| log::normalise(part, profile.rules(), stream, &mut rewrites))
                .collect();
            if !rewrites.is_empty() {
                normalised_here = true;
                diffs.extend(rewrites.aggregate(&step_key, stream.suffix()));
                records.push((step_key.clone(), stream, rewrites));
            }
            *material = match &*material {
                // The bytes are gone; the digest is the hand-off. This is also what
                // keeps megabytes of log out of a signed document.
                Material::Text(_) => Material::digest(Digest::sha256(normalised[0].as_bytes())),
                // Parts keep their explicit lengths — a split must not collide with
                // a concatenation — so they stay parts, the normalised ones.
                _ => Material::parts(normalised),
            };
        }
    }

    if normalised_here && prehashed {
        return Err(Error::invalid(
            "run report",
            "this report mixes pre-hashed log digests with raw log text",
        )
        .with_hint("normalise every stream or none: one manifest cannot describe two rule sets"));
    }
    if normalised_here {
        rewritten.provenance.normalisation_version = profile.version();
    }

    // The one sanctioned path, so nothing derivable is left to the caller: this
    // hashes, sorts, derives the environment fingerprint and validates.
    let mut manifest = RunManifest::from_run_with(&rewritten, profile)?;
    manifest.claims.normalisation_diffs.extend(diffs.clone());
    manifest.normalize();
    manifest.validate()?;
    Ok(NormalisedRun {
        manifest,
        diffs,
        records,
    })
}

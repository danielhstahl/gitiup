//! `gitiup-attest` — the attestation format.
//!
//! This crate answers one question: *what exactly are the bytes that make a CI
//! result provable?* Everything else in gitiup — the runner, the quorum network,
//! the merge gate, the S3 host — reads and writes them, so they are decided once,
//! in [ADR-0001](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md),
//! and implemented here once.
//!
//! ```text
//! canonical(manifest) ──sha256──► RunDigest ──┐
//!        │                                    │  ed25519 over PAE(payload_type, bytes)
//!        └──sha256(canonical(result))─► ResultDigest   │
//!                                                      ▼
//!                       AttestationDoc { manifest, signatures[] }
//!```
//!
//! # The decisions this crate encodes
//!
//! | decision | ADR | in code |
//!|----------|-----|---------|
//!| canonical JSON (RFC 8785 narrowed), DSSE PAE envelope | D1 | [`canon`], [`pae`] |
//!| `sha256:` digests, algorithm tagged in the string | D2 | [`digest::Digest`], [`oid::GitOid`] |
//!| raw Ed25519, SSH public keys, SSH fingerprints as key ids | D3 | [`key`] |
//!| `result` vs `claims` split; two digests | D4 | [`manifest`] |
//!| the run digest pipeline (report → manifest → digests) | D4, D5 | [`run`], [`run::RunReport`], [`RunManifest::from_run`] |
//!| the volatile-field register | D5 | [`manifest::Claims`], [`run::StepReport::timing`] |
//!| claimed time + policy freshness window | D6 | [`policy`], [`time`] |
//!| provenance tiers, and what each may claim | giti-1rs.7 | [`Tier`], [`Provenance::check`] |
//!| the environment fingerprint and its match enforcement | giti-1rs.4 | [`Environment`], [`EnvMatch`], [`EnvironmentRequirement`], [`Policy::check_environment`] |
//!| the verdict report: every check, every reason, one exit code | giti-1rs.8 | [`AttestationDoc::verify_report`], [`report::Check`], [`report::Reason`] |
//!| the policy file a repo writes (`gitiup-policy.json`) | giti-1rs.7 | [`PolicyFile`] |
//!| limits, and what a verifier may refuse | D7 | [`canon::MAX_ENCODED_BYTES`], [`RunManifest::validate`] |
//!| versioning and migration | D8 | [`schema`], [`error::ErrorKind::UnsupportedSchema`] |
//!| log anchoring as a separate record (intentionally *not* implemented yet) | D9 | the ADR only |
//!
//! # In one example
//!
//! ```
//! use gitiup_attest::{AttestationDoc, Policy, TimeUs, sample, key::SigningKey};
//!
//! let key = SigningKey::from_seed(&sample::TEST_SEED);
//! let mut doc = AttestationDoc::new(sample::local());
//! doc.sign(&key)?;
//!
//! // Bytes are only ever written and read in canonical form: what you store is
//! // byte-for-byte what was signed.
//! let bytes = doc.canonical_bytes()?;
//! let read_back = AttestationDoc::from_canonical_bytes(&bytes)?;
//!
//! // The fixture's claimed time is fixed, so verification pins the clock. Real
//! // callers leave `now` as `None` and let the freshness window do its job.
//! let policy = Policy {
//!     now: Some(TimeUs::from_secs(1_793_092_600)),
//!     ..Policy::trusting([key.public_key().key_id()])
//! };
//! let verdict = read_back.verify(&policy)?;
//! assert_eq!(verdict.signers, vec![key.public_key().key_id()]);
//! # Ok::<(), gitiup_attest::Error>(())
//! ```
//!
//! # What is *not* here
//!
//! Deliberately, so that the trust-critical code stays small and offline:
//!
//! * **no I/O** — storage is `gitiup-host`'s job (giti-1rs.5 writes these bytes to
//!   `kv/attestation/<hex>` and points `refs/attestations/<subject>/<digest>` at them); the
//!   `gitiup` CLI crate is the one place that reads a run report off disk;
//! * **no keystore** — key generation, encryption, ssh-agent and gpg live in
//!   giti-1rs.6 and plug in through [`key::Signer`] (the `Signer` trait itself, the
//!   canonicaliser and the exit-code taxonomy live in `gitiup-canon`, and this crate
//!   re-exports them: [ADR-0003 D11](../../../docs/adr/0003-change-record-format-and-merge-semantics.md));
//! * **no normalisation** — the digests in [`manifest::Step`] are of *normalised*
//!   output, produced by giti-1rs.3, which plugs into the digest computation
//!   through [`run::Normaliser`] rather than living here;
//! * **no network** — log anchoring is a separate signed *record* over a RunDigest
//!   (ADR-0001 D9), never a fetch inside verification, so verification works on a
//!   plane, in a pre-receive hook, and under DoS.
//!
//! # Errors are an API
//!
//! [`Error`] carries an [`ErrorKind`] whose
//! [`ErrorKind::exit_code`] is `gitiup verify attestation`'s documented exit code
//! (6 policy, 7 bad signature, 8 digest mismatch). Keep it that way: hooks branch
//! on those numbers.
//!
//! [`AttestationDoc::verify`] answers "may I accept this?" with the first thing
//! wrong; [`AttestationDoc::verify_report`] answers "tell me everything wrong with
//! it" with the same checks in the same order ([`report`]). One implementation,
//! two question shapes, so a printed verdict and a branched-on verdict cannot
//! disagree.

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

// The canonicaliser, the digest and key-id primitives and the error taxonomy are
// re-exports of `gitiup-canon`, not copies of them (ADR-0003 D11): a second
// implementation of either is a second digest, so `gitiup-host` — which stores and
// re-hashes signed records but must not depend on this crate — links the same code
// this one does. The paths below are the public surface of ADR-0001 and are unchanged
// by the move.
pub use gitiup_canon::{canon, digest, encoding, error, key};

pub mod envelope;
pub mod envreq;
pub mod manifest;
pub mod oid;
pub mod policy;
pub mod report;
pub mod run;
pub mod sample;
pub mod schema;
pub mod time;

pub use canon::{
    MAX_DEPTH, MAX_ENCODED_BYTES, from_bytes as from_canonical_bytes, is_canonical,
    require_canonical,
};
pub use digest::{Algorithm, Digest};
pub use envelope::{
    AttestationDoc, DOC_SCHEMA_VERSION, MAX_SIGNATURES, PAYLOAD_TYPE, Verdict, doc_from_dsse,
};
pub use envreq::{Arch, EnvMatch, EnvironmentRequirement, REQUIREMENT_FIELDS};
pub use error::{Error, ErrorKind, Result};
pub use gitiup_canon::pae;
pub use key::{PublicKey, Signature, SignatureAlgorithm, SignatureEntry, Signer, SigningKey};
pub use manifest::{
    ActionPin, Artifact, Claims, Environment, EventContext, ImageRef, InputValue, NO_SANDBOX,
    NO_SANDBOX_ALIASES, NormalisationDiff, Provenance, RUN_MANIFEST_TYPE, ResultDigest,
    RunManifest, RunResult, SCHEMA_VERSION, Source, Step, StepOutcome, StepTiming, Tier,
    ToolchainEntry, WorkflowRef,
};
pub use oid::{GitOid, OidAlgorithm};
pub use policy::{
    DEFAULT_MAX_AGE_US, DEFAULT_MAX_CLOCK_SKEW_US, Freshness, POLICY_FILE_NAME, POLICY_PATH_ENV,
    POLICY_SCHEMA_VERSION, Policy, PolicyFile, Trust, check_freshness,
};
pub use report::{CHECK_ORDER, Check, CheckOutcome, Reason, VerdictReport};
pub use run::{
    ArtifactReport, ClaimReport, EnvironmentReport, EventReport, Material, Normaliser, RawText,
    RunReport, StepReport, TimingReport, WorkflowSource, file_set_digest,
};
pub use time::{TimeUs, human_duration_us};

/// The fixture builders and the public fixture key id.
///
/// Public because other crates' tests need byte-identical manifests; production
/// code has no reason to reach for [`sample::test_key_id`], and a trust policy
/// that lists it is a bug.
pub use sample::TEST_SEED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_key_is_not_something_to_trust() {
        // Guards the guard: if a policy ever lists the fixture key by default,
        // tests would pass in production.
        let policy = Policy::default();
        assert!(!policy.trust.trusts(&sample::test_key_id()));
        assert!(!Trust::None.trusts(&sample::test_key_id()));
        assert!(sample::test_key_id().starts_with("SHA256:"));
    }

    #[test]
    fn end_to_end_round_trip() {
        let key = SigningKey::from_seed(&sample::TEST_SEED);
        let mut doc = AttestationDoc::new(sample::quorum_member());
        doc.sign(&key).unwrap();
        let bytes = doc.canonical_bytes().unwrap();
        assert!(is_canonical(&bytes));
        let read_back = AttestationDoc::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read_back, doc);
        let verdict = read_back.verify(&Policy::for_tests()).unwrap();
        assert_eq!(verdict.run_digest, doc.run_digest().unwrap());
        assert_eq!(doc.record_digest().unwrap().hex().len(), 64);
    }
}

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
//!| canonical JSON (RFC 8785 narrowed), DSSE PAE envelope | D1 | [`canon`], [`envelope::pae`] |
//!| `sha256:` digests, algorithm tagged in the string | D2 | [`digest::Digest`], [`oid::GitOid`] |
//!| raw Ed25519, SSH public keys, SSH fingerprints as key ids | D3 | [`key`] |
//!| `result` vs `claims` split; two digests | D4 | [`manifest`] |
//!| the volatile-field register | D5 | [`manifest::Claims`] |
//!| claimed time + policy freshness window | D6 | [`policy`], [`time`] |
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
//!   `kv/attestation/<hex>` and points `refs/attestations/<oid>` at them);
//! * **no keystore** — key generation, encryption, ssh-agent and gpg live in
//!   giti-1rs.6 and plug in through [`key::Signer`];
//! * **no normalisation** — the digests in [`manifest::Step`] are of *normalised*
//!   output, produced by giti-1rs.3;
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

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

pub mod canon;
pub mod digest;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod key;
pub mod manifest;
pub mod oid;
pub mod policy;
pub mod sample;
pub mod schema;
pub mod time;

pub use canon::{
    MAX_DEPTH, MAX_ENCODED_BYTES, from_bytes as from_canonical_bytes, is_canonical,
    require_canonical,
};
pub use digest::{Algorithm, Digest};
pub use envelope::{
    AttestationDoc, DOC_SCHEMA_VERSION, MAX_SIGNATURES, PAYLOAD_TYPE, Verdict, doc_from_dsse, pae,
};
pub use error::{Error, ErrorKind, Result};
pub use key::{PublicKey, Signature, SignatureAlgorithm, SignatureEntry, Signer, SigningKey};
pub use manifest::{
    ActionPin, Artifact, Claims, Environment, EventContext, ImageRef, InputValue,
    NormalisationDiff, Provenance, RUN_MANIFEST_TYPE, ResultDigest, RunManifest, RunResult,
    SCHEMA_VERSION, Source, Step, StepOutcome, StepTiming, Tier, ToolchainEntry, WorkflowRef,
};
pub use oid::{GitOid, OidAlgorithm};
pub use policy::{
    DEFAULT_MAX_AGE_US, DEFAULT_MAX_CLOCK_SKEW_US, Freshness, Policy, Trust, check_freshness,
};
pub use time::TimeUs;

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

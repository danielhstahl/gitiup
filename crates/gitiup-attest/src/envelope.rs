//! The attestation document: a manifest plus the signatures over it
//! ([ADR-0001 D1](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md),
//! [D3](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//!
//! ```text
//! signature message = PAE("application/vnd.gitiup.run-manifest+json", canonical(manifest))
//!                   = "DSSEv1" SP len(payload_type) SP payload_type SP len(payload) SP payload
//! RunDigest         = sha256(canonical(manifest))
//! ```
//!
//! PAE is in-toto DSSE's Pre-Authentication Encoding, verbatim. Using it costs
//! nothing and buys two things: a signature can never be replayed onto a
//! different payload type, and `gitiup` can emit a spec DSSE envelope whose
//! payload and signature bytes are *identical* to ours
//! ([`AttestationDoc::dsse_envelope`]) — so talking to Sigstore/Rekor-style tooling
//! is a transformation, not a re-decision.
//!
//! The envelope holds the manifest as a JSON *member*, not as base64 of it. That
//! is deliberate: attestations live in git-visible blobs and people review them,
//! and a base64 wall is unreadable and undiffable. The canonical bytes of the
//! `manifest` member are the signed payload either way, so nothing about the
//! signature changes.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::canon;
use crate::digest::Digest;
use crate::envreq::EnvMatch;
use crate::error::{Error, ErrorKind, Result};
use crate::key::{SignatureEntry, Signer};
use crate::manifest::{ResultDigest, RunManifest};
use crate::pae;
use crate::policy::{Freshness, Policy, check_freshness};
use crate::report::VerdictReport;

/// The DSSE payload type of a run manifest.
pub const PAYLOAD_TYPE: &str = "application/vnd.gitiup.run-manifest+json";

/// Schema version of the envelope itself.
pub const DOC_SCHEMA_VERSION: u32 = 1;

/// Largest number of signatures one document may carry.
///
/// A quorum is a handful of verifiers, not a crowd; the cap bounds the work a
/// verifier does (sixty-four Ed25519 checks is already a second of CPU) and stops
/// a "quorum" being flooded into uselessness
/// ([ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
pub const MAX_SIGNATURES: usize = 64;

// `pae` itself lives in `gitiup-canon` and is re-exported from this crate's root,
// so there is exactly one definition compiled into the format and ADR-0003's
// change records sign over the same bytes.

/// A signed attestation: manifest + signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationDoc {
    /// Envelope version; must be [`DOC_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Must be [`PAYLOAD_TYPE`]; recorded so a future v2 payload type cannot be
    /// checked with v1 rules.
    pub payload_type: String,
    /// The signed manifest.
    pub manifest: RunManifest,
    /// One entry per signer, sorted by `key_id`.
    pub signatures: Vec<SignatureEntry>,
}

/// What a successful verification established. Structured because giti-1rs.8 has
/// to print it *and* let scripts branch on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// `sha256(canonical(manifest))` as recomputed here.
    pub run_digest: Digest,
    /// `sha256(canonical(manifest.result))`.
    pub result_digest: ResultDigest,
    /// Trusted, distinct signers that verified.
    pub signers: Vec<String>,
    /// The provenance tier the producer claimed.
    pub tier: crate::manifest::Tier,
    /// How the claimed time measured up.
    pub freshness: Freshness,
    /// The environment fingerprint that was accepted.
    pub environment_fingerprint: Digest,
    /// The environment requirement that was applied, if any, and how strictly
    /// (giti-1rs.4). `Off` when the policy compared nothing.
    pub environment_match: EnvMatch,
    /// The requirement the environment was judged against, as published.
    pub environment_requirement: Option<crate::envreq::EnvironmentRequirement>,
}

impl AttestationDoc {
    /// An unsigned document over `manifest`.
    pub fn new(manifest: RunManifest) -> AttestationDoc {
        AttestationDoc {
            schema_version: DOC_SCHEMA_VERSION,
            payload_type: PAYLOAD_TYPE.into(),
            manifest,
            signatures: Vec::new(),
        }
    }

    /// Sign and record the signature. Callers pass the *document*, and get PAE
    /// framing for free, so no call site can accidentally sign the wrong bytes.
    pub fn sign(&mut self, signer: &dyn Signer) -> Result<SignatureEntry> {
        let message = self.signature_message()?;
        let entry = SignatureEntry::new(signer, &message)?;
        self.add_signature(entry.clone());
        Ok(entry)
    }

    /// Append a signature, keeping the list sorted and single-vote-per-key.
    pub fn add_signature(&mut self, entry: SignatureEntry) {
        self.signatures.retain(|s| s.key_id != entry.key_id);
        self.signatures.push(entry);
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    }

    /// Fold in the signatures of another document over the *same* manifest — the
    /// quorum aggregation step (giti-msi.7). Returns how many were new.
    ///
    /// Refuses anything whose manifest bytes differ: a "quorum" built by
    /// pooling signatures over two different results is the exact attack the
    /// commit-reveal protocol is there to defeat.
    pub fn merge_signatures(&mut self, other: &AttestationDoc) -> Result<usize> {
        if self.manifest.canonical_bytes()? != other.manifest.canonical_bytes()? {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "attestation",
                "refusing to pool signatures over two different manifests",
            ));
        }
        let mut added = 0usize;
        for entry in &other.signatures {
            if !self.signatures.iter().any(|s| s.key_id == entry.key_id) {
                self.signatures.push(entry.clone());
                added += 1;
            }
        }
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(added)
    }

    /// Canonical bytes of the manifest: the signed payload.
    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        self.manifest.canonical_bytes()
    }

    /// The exact byte string a signature is made over.
    pub fn signature_message(&self) -> Result<Vec<u8>> {
        Ok(pae(&self.payload_type, &self.payload_bytes()?))
    }

    /// Canonical bytes of the whole document — what goes into `kv/attestation/`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canon::to_bytes(self)
    }

    /// Read a document from storage, insisting on the canonical form.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<AttestationDoc> {
        let value = canon::require_canonical(bytes)?;
        let doc: AttestationDoc = serde_json::from_value(value)
            .map_err(|e| Error::invalid("attestation", e.to_string()))?;
        doc.validate()?;
        if doc.canonical_bytes()? != bytes {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "attestation",
                "the bytes received are not the canonical encoding of this document",
            ));
        }
        Ok(doc)
    }

    /// Structural checks: versions, payload type, signer list, and the manifest's
    /// own rules.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != DOC_SCHEMA_VERSION {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "attestation",
                format!(
                    "envelope schema_version {} is not understood",
                    self.schema_version
                ),
            ));
        }
        if self.payload_type != PAYLOAD_TYPE {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "attestation",
                format!("unknown payload type '{}'", self.payload_type),
            ));
        }
        self.manifest.validate()?;
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(Error::invalid(
                "attestation",
                format!(
                    "{} signatures exceeds the {MAX_SIGNATURES} limit",
                    self.signatures.len()
                ),
            ));
        }
        let mut ids: Vec<&str> = self.signatures.iter().map(|s| s.key_id.as_str()).collect();
        let claimed = ids.len();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != claimed {
            // Two signatures from one identity is one vote wearing two hats
            // (giti-msi.9), and here it is also a canonical-ordering bug.
            return Err(Error::invalid(
                "attestation",
                "two signatures from the same key id: one identity casts one vote",
            ));
        }
        let sorted = self
            .signatures
            .windows(2)
            .all(|w| w[0].key_id < w[1].key_id);
        if !sorted {
            return Err(Error::invalid(
                "attestation",
                "signatures must be sorted by key_id so the stored bytes are canonical",
            )
            .with_hint("call add_signature, which keeps the list sorted"));
        }
        Ok(())
    }

    /// The attestation's name: `sha256(canonical(manifest))`.
    ///
    /// Note what this does *not* cover: other signatures. Adding a co-signer
    /// changes the document's storage hash ([`Self::record_digest`]) but never
    /// the RunDigest, so a quorum's co-signing cannot invalidate the author's
    /// signature ([ADR-0001 D3](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
    pub fn run_digest(&self) -> Result<Digest> {
        self.manifest.digest()
    }

    /// Digest of the result core, for comparing independent runs.
    pub fn result_digest(&self) -> Result<ResultDigest> {
        self.manifest.result_digest()
    }

    /// CAS key of the stored document: `sha256(canonical(doc))`, used as
    /// `kv/attestation/<hex>`.
    pub fn record_digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// Verify against a policy: signature, digest, freshness, tier, environment
    /// match, bindings.
    ///
    /// The order is deliberate — cheap integrity checks first, then integrity of
    /// the signer claim, then policy — so the exit code a caller sees describes
    /// the first thing that is actually wrong ([`crate::error::ErrorKind::exit_code`]).
    ///
    /// This is [`Self::verify_report`] with the tail dropped — one set of checks,
    /// one order, two entry points — so the error returned here is always the
    /// *first* reason that report lists. A hook that branches on `verify` and a
    /// command that prints `verify_report` cannot tell different stories about the
    /// same bytes, which is the property a merge gate is built on.
    pub fn verify(&self, policy: &Policy) -> Result<Verdict> {
        let report = self.verify_report(policy);
        if let Some(verdict) = report.verdict {
            return Ok(verdict);
        }
        // Unreachable in practice: a report with no verdict always has a reason.
        // The fallback keeps the type honest rather than unwrapping in trust.
        Err(report.error().unwrap_or_else(|| {
            Error::new(
                ErrorKind::Policy,
                "attestation",
                "verification refused this document",
            )
        }))
    }

    /// Every check in the order [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
    /// fixes, with every reason found rather than only the first one.
    ///
    /// This is what *printing* a verdict needs: a log that says "refused" is a log
    /// nobody can act on, and an operator who is shown one complaint fixes one
    /// thing and re-runs. The exit code still comes from the first reason, so
    /// collecting the rest changes nobody's verdict.
    pub fn verify_report(&self, policy: &Policy) -> VerdictReport {
        let mut report = VerdictReport::new();

        // Structure first: if this is not a document this build speaks, nothing it
        // goes on to say is worth printing.
        if let Err(error) = self.validate() {
            report.stop("structure", error);
            return report;
        }
        report.pass("structure");

        // Then integrity of the bytes, before anything reads them.
        let payload = match self.payload_bytes() {
            Ok(payload) => payload,
            Err(error) => {
                report.stop("digest", error);
                return report;
            }
        };
        let run_digest = Digest::sha256(&payload);
        if let Err(error) = policy.check_digest(&run_digest) {
            report.stop("digest", error);
            return report;
        }
        let claimed = match self.manifest.digest() {
            Ok(digest) => digest,
            Err(error) => {
                report.stop("digest", error);
                return report;
            }
        };
        if claimed != run_digest {
            // Only reachable if a manifest were mutated in memory after building;
            // a re-encode of parsed bytes is checked in `from_canonical_bytes`.
            report.stop(
                "digest",
                Error::new(
                    ErrorKind::DigestMismatch,
                    "attestation",
                    "the manifest does not hash to its own claimed content",
                ),
            );
            return report;
        }
        let result_digest = match self.manifest.result_digest() {
            Ok(digest) => digest,
            Err(error) => {
                report.stop("digest", error);
                return report;
            }
        };
        report.pass("digest");

        // Expected bindings next: a wrong-commit attestation must not be able to
        // fail on freshness instead and be reported as "expired". Each one is a
        // separate code, because "wrong commit", "wrong result" and "wrong round"
        // are three different things for a human to go and fix.
        match &policy.expected_commit {
            Some(commit) if commit != &self.manifest.result.source.commit => report.fail(
                "commit",
                Error::new(
                    ErrorKind::DigestMismatch,
                    "attestation",
                    format!(
                        "attestation is bound to {}, not the expected {}",
                        self.manifest.result.source.commit, commit
                    ),
                )
                .with_hint("the change commit moved after the run; re-run it"),
            ),
            Some(_) => report.pass("commit"),
            None => report.not_asked("commit"),
        }
        match &policy.expected_result_digest {
            Some(expected) if expected != &result_digest => report.fail(
                "result",
                Error::new(
                    ErrorKind::DigestMismatch,
                    "attestation",
                    format!("result digest is {result_digest}, not the expected {expected}"),
                ),
            ),
            Some(_) => report.pass("result"),
            None => report.not_asked("result"),
        }
        match &policy.expected_challenge {
            Some(expected) => match &self.manifest.claims.verifier_challenge {
                Some(got) if got == expected => report.pass("challenge"),
                other => report.fail(
                    "challenge",
                    Error::new(
                        ErrorKind::DigestMismatch,
                        "attestation",
                        format!(
                            "verifier challenge is {}, not the expected {expected}",
                            other
                                .as_ref()
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "absent".into())
                        ),
                    ),
                ),
            },
            None => report.not_asked("challenge"),
        }
        match policy.normalisation_version {
            Some(version) if version != self.manifest.result.provenance.normalisation_version => {
                report.fail(
                    "normalisation",
                    Error::new(
                        ErrorKind::Policy,
                        "policy",
                        format!(
                            "normalisation version is {}, policy requires {version}",
                            self.manifest.result.provenance.normalisation_version
                        ),
                    ),
                )
            }
            Some(_) => report.pass("normalisation"),
            None => report.not_asked("normalisation"),
        }
        // The machine class (giti-1rs.4), alongside the other bindings: an
        // attestation from the wrong architecture is refused with a sentence about
        // architectures, and only then does anything else get a turn to complain.
        if policy.environment_requirement().is_some() {
            match policy.check_environment(
                &self.manifest.result.environment,
                &self.manifest.result.provenance,
            ) {
                Ok(()) => report.pass("environment"),
                Err(error) => report.fail("environment", error),
            }
        } else {
            report.not_asked("environment");
        }

        // Signatures. Every entry must be self-consistent (key id derived from the
        // key offered) before the trust list is consulted at all, and an entry that
        // failed that is not asked about trust — its identity is already a lie.
        let message = pae(&self.payload_type, &payload);
        let mut signers: Vec<String> = Vec::new();
        if self.signatures.is_empty() {
            // Nothing signed it: not a failed signature and not an untrusted
            // signer, just nobody. `min_signatures` is the check that says so.
            report.not_asked("signature");
            report.not_asked("trust");
        }
        for entry in &self.signatures {
            if let Err(error) = entry.verify(&message) {
                report.fail("signature", error);
                continue;
            }
            if !policy.trust.trusts(entry.claimed_key_id()) {
                report.fail(
                    "trust",
                    Error::new(
                        ErrorKind::Policy,
                        "policy",
                        format!(
                            "{} signed it, and that key is not trusted here",
                            entry.key_id
                        ),
                    )
                    .with_hint("add the key id to the owner's trust list (giti-1rs.6)"),
                );
                continue;
            }
            signers.push(entry.key_id.clone());
        }
        if !self.signatures.is_empty() {
            report.pass("signature");
            report.pass("trust");
        }
        if signers.len() < policy.min_signatures {
            report.fail(
                "min_signatures",
                Error::new(
                    ErrorKind::Policy,
                    "policy",
                    format!(
                        "{} trusted signature(s), policy requires {}",
                        signers.len(),
                        policy.min_signatures
                    ),
                ),
            );
        } else {
            report.pass("min_signatures");
        }

        // Provenance tier and sandbox, then freshness. Same call `gitiup run` makes
        // against its own unsigned manifest, so "what the gate will say" and "what
        // the gate says" cannot drift (giti-1rs.7).
        let provenance = &self.manifest.result.provenance;
        let tier = provenance.tier;
        match policy.check_provenance(provenance) {
            Ok(()) => {
                report.pass("tier");
                report.pass("sandbox");
            }
            Err(error) => {
                // One call answers both questions, because one implementation
                // should; the code says which of the two it was.
                if policy.allows_tier(tier) {
                    report.pass("tier");
                    report.fail("sandbox", error);
                } else {
                    report.fail("tier", error);
                    report.not_run("sandbox");
                }
            }
        }

        let freshness = check_freshness(self.manifest.claims.claimed_at_us, policy);
        match &freshness {
            Ok(_) => report.pass("freshness"),
            Err(error) => report.fail("freshness", error.clone()),
        }
        // The producer's own window, which may be tighter than the policy's.
        match self.manifest.claims.not_after_us {
            Some(not_after) => {
                if policy.now().0 > not_after {
                    report.fail(
                        "expiry",
                        Error::new(
                            ErrorKind::Policy,
                            "freshness",
                            "the attestation's own validity window has closed",
                        ),
                    );
                } else {
                    report.pass("expiry");
                }
            }
            None => report.not_asked("expiry"),
        }

        if !report.reasons.is_empty() {
            return report;
        }
        let freshness = freshness.expect("no reasons means freshness passed");
        report.accept(Verdict {
            run_digest,
            result_digest,
            signers,
            tier,
            freshness,
            environment_fingerprint: self.manifest.result.environment.fingerprint.clone(),
            environment_match: policy.require_env_match,
            environment_requirement: policy.environment_requirement().cloned(),
        });
        report
    }

    // ------------------------------------------------------ DSSE interop ---

    /// A spec in-toto DSSE envelope carrying these same payload and signature
    /// bytes (camelCase field names are DSSE's, not ours).
    pub fn dsse_envelope(&self) -> Result<Value> {
        let payload = crate::encoding::base64_encode(&self.payload_bytes()?);
        let signatures: Vec<Value> = self
            .signatures
            .iter()
            .map(|entry| {
                let mut map = Map::new();
                map.insert("keyid".into(), Value::String(entry.key_id.clone()));
                map.insert("sig".into(), Value::String(entry.sig.clone()));
                Value::Object(map)
            })
            .collect();
        let mut envelope = Map::new();
        envelope.insert(
            "payloadType".into(),
            Value::String(self.payload_type.clone()),
        );
        envelope.insert("payload".into(), Value::String(payload));
        envelope.insert("signatures".into(), Value::Array(signatures));
        Ok(Value::Object(envelope))
    }
}

/// Read a DSSE envelope back into an [`AttestationDoc`].
///
/// DSSE carries no public keys, so the caller supplies the lookup — in gitiup
/// that is the keystore and identity records from giti-1rs.6. Keeping it a
/// callback means this crate still does no I/O.
pub fn doc_from_dsse(
    envelope: &Value,
    resolve_key: &dyn Fn(&str) -> Result<String>,
) -> Result<AttestationDoc> {
    let payload_type = dsse_str(
        envelope
            .get("payloadType")
            .ok_or_else(|| bad("payloadType"))?,
    )?;
    if payload_type != PAYLOAD_TYPE {
        return Err(Error::new(
            ErrorKind::UnsupportedSchema,
            "dsse",
            format!("payload type '{payload_type}' is not a gitiup run manifest"),
        ));
    }
    let payload = crate::encoding::base64_decode(dsse_str(
        envelope.get("payload").ok_or_else(|| bad("payload"))?,
    )?)
    .map_err(|e| Error::invalid("dsse", format!("payload: {}", e.detail())))?;
    let manifest = RunManifest::from_canonical_bytes(&payload)?;
    let empty = Vec::new();
    let signatures = envelope
        .get("signatures")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let mut doc = AttestationDoc::new(manifest);
    for entry in signatures {
        let key_id = dsse_str(entry.get("keyid").ok_or_else(|| bad("keyid"))?)?.to_string();
        let sig = dsse_str(entry.get("sig").ok_or_else(|| bad("sig"))?)?.to_string();
        doc.add_signature(SignatureEntry {
            key_id: key_id.clone(),
            algorithm: crate::key::SignatureAlgorithm::Ed25519,
            public_key: resolve_key(&key_id)?,
            sig,
        });
    }
    doc.validate()?;
    if doc.payload_bytes()? != payload {
        return Err(Error::new(
            ErrorKind::DigestMismatch,
            "dsse",
            "the DSSE payload is not the canonical encoding of the manifest it carries",
        ));
    }
    Ok(doc)
}

fn bad(what: &str) -> Error {
    Error::invalid("dsse", format!("malformed envelope: missing {what}"))
}

/// A required string field of a DSSE envelope.
fn dsse_str(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| bad("a string field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SigningKey;
    use crate::manifest::SCHEMA_VERSION;
    use crate::policy::Trust;
    use crate::sample;
    use crate::time::TimeUs;

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        // The example in the in-toto DSSE spec's PAE description.
        let got = pae("text/plain; charset=utf-8", b"Hello, world!");
        assert_eq!(got, b"DSSEv1 25 text/plain; charset=utf-8 13 Hello, world!");
    }

    #[test]
    fn signed_sample_verifies_end_to_end() {
        let mut doc = AttestationDoc::new(sample::local());
        let key = SigningKey::from_seed(&sample::TEST_SEED);
        doc.sign(&key).unwrap();
        doc.validate().unwrap();

        let mut policy = Policy::for_tests();
        policy.now = Some(TimeUs::from_secs(1_793_092_600));
        let verdict = doc.verify(&policy).unwrap();
        assert_eq!(verdict.signers, vec![key.public_key().key_id()]);
        assert_eq!(verdict.run_digest, doc.run_digest().unwrap());
        assert_eq!(verdict.tier, crate::manifest::Tier::Local);
        assert!(verdict.freshness.age_us > 0);
    }

    #[test]
    fn unsigned_and_untrusted_fail_closed() {
        let doc = AttestationDoc::new(sample::local());
        // No signatures at all: nothing to trust, nothing to accept.
        let policy = Policy::for_tests();
        assert_eq!(doc.verify(&policy).unwrap_err().kind(), ErrorKind::Policy);
        // A valid signature from a key nobody vouched for is refused (exit 6),
        // not reported as a broken signature (exit 7).
        let mut doc = AttestationDoc::new(sample::local());
        doc.sign(&SigningKey::from_seed(&[4u8; 32])).unwrap();
        let policy = Policy::trusting(["SHA256:someone-else"]);
        let err = doc.verify(&policy).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("not trusted"));
        assert_eq!(err.exit_code(), 6);
        assert_eq!(Trust::None, Trust::None);
    }

    #[test]
    fn tampering_is_caught_as_integrity_not_policy() {
        let mut doc = AttestationDoc::new(sample::local());
        doc.sign(&SigningKey::from_seed(&sample::TEST_SEED))
            .unwrap();
        let mut tampered = doc.clone();
        tampered.manifest.result.steps[0].exit_code = 1;
        tampered.manifest.result.steps[0].outcome = crate::manifest::StepOutcome::Failure;
        let policy = Policy::for_tests();
        // Signature over the original bytes, manifest edited: exit 7.
        let err = tampered.verify(&policy).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Signature);
        assert_eq!(err.exit_code(), 7);
    }

    #[test]
    fn co_signing_keeps_the_run_digest() {
        let mut doc = AttestationDoc::new(sample::local());
        doc.sign(&SigningKey::from_seed(&sample::TEST_SEED))
            .unwrap();
        let before = doc.run_digest().unwrap();
        let record_before = doc.record_digest().unwrap();

        let mut other = doc.clone();
        other.sign(&SigningKey::from_seed(&[2u8; 32])).unwrap();
        let added = doc.merge_signatures(&other).unwrap();
        assert_eq!(added, 1);
        assert_eq!(
            doc.run_digest().unwrap(),
            before,
            "RunDigest must be signature-independent"
        );
        assert_ne!(
            doc.record_digest().unwrap(),
            record_before,
            "the stored record changed"
        );

        // Pooling over a different result is refused.
        let mut rival = AttestationDoc::new(sample::simulated());
        rival.sign(&SigningKey::from_seed(&[3u8; 32])).unwrap();
        assert_eq!(
            doc.merge_signatures(&rival).unwrap_err().kind(),
            ErrorKind::DigestMismatch
        );
    }

    #[test]
    fn tier_and_freshness_are_policy_not_format() {
        let mut doc = AttestationDoc::new(sample::simulated());
        doc.sign(&SigningKey::from_seed(&sample::TEST_SEED))
            .unwrap();
        let mut policy = Policy::for_tests();
        policy.allowed_tiers = vec![crate::manifest::Tier::Local];
        let err = doc.verify(&policy).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("simulated"));

        let mut policy = Policy::for_tests();
        policy.now = Some(TimeUs::from_secs(1_793_092_502 + 7 * 24 * 3600));
        let err = doc.verify(&policy).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("old"));
        // A clock that claims the future is refused too, within skew tolerance.
        policy.now = Some(TimeUs::from_secs(1_793_092_502 - 60));
        policy.allowed_tiers.push(crate::manifest::Tier::Simulated);
        doc.verify(&policy).unwrap();
        policy.now = Some(TimeUs::from_secs(1_793_092_502 - 3600));
        assert!(doc.verify(&policy).unwrap_err().detail().contains("future"));
    }

    #[test]
    fn dsse_round_trip_shares_the_signature_bytes() {
        let mut doc = AttestationDoc::new(sample::local());
        let key = SigningKey::from_seed(&sample::TEST_SEED);
        doc.sign(&key).unwrap();
        let envelope = doc.dsse_envelope().unwrap();
        assert_eq!(envelope["payloadType"], PAYLOAD_TYPE);
        let decoded =
            crate::encoding::base64_decode(envelope["payload"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, doc.payload_bytes().unwrap());
        assert_eq!(
            envelope["signatures"][0]["sig"].as_str().unwrap(),
            doc.signatures[0].sig
        );

        let back = doc_from_dsse(&envelope, &|_| Ok(key.public_key().to_openssh())).unwrap();
        assert_eq!(back, doc);
        assert!(back.verify(&Policy::for_tests()).is_ok());
    }

    #[test]
    fn envelope_shape_is_checked() {
        let mut doc = AttestationDoc::new(sample::local());
        doc.sign(&SigningKey::from_seed(&sample::TEST_SEED))
            .unwrap();
        doc.schema_version = 2;
        assert_eq!(
            doc.validate().unwrap_err().kind(),
            ErrorKind::UnsupportedSchema
        );
        let mut doc = AttestationDoc::new(sample::local());
        doc.payload_type = "application/vnd.gitiup.something+json".into();
        assert_eq!(
            doc.validate().unwrap_err().kind(),
            ErrorKind::UnsupportedSchema
        );
        assert_eq!(SCHEMA_VERSION, 1);
    }
}

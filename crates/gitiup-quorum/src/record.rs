//! The shape of a signed gitiup record: canonical bytes, and what a signature
//! covers.
//!
//! ADR-0001 fixes this for the run attestation (DSSE PAE over the canonical
//! payload). ADR-0002 D8 applies *the same framing* to the new document types —
//! roster, sign-up, revocation, round, verdict — so there is one rule to remember:
//!
//! > A signature covers `pae(payload_type, canonical_bytes(record with its own
//! > signature fields removed))`.
//!
//! Removing the signature list before hashing is what makes a signature
//! computable by someone who has not signed yet, and it is why a roster digest is
//! stable while unsigned (`signatures: []`, as the ADR-0002 fixtures are) and after
//! the owner signs it: the digest of the *body* never moves, so the pin in a round
//! record survives the signing step.

use gitiup_attest::{Digest, SignatureEntry, Signer, Trust, canon, pae};

use crate::error::{Error, Result};

/// `application/vnd.gitiup.<name>+json` — the DSSE payload type of a gitiup
/// document. Every signed record type in this crate has one, and it is inside the
/// signature so a roster can never be checked with verdict rules.
pub fn payload_type(name: &str) -> String {
    format!("application/vnd.gitiup.{name}+json")
}

/// The roster document's payload type ([ADR-0002 D8](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
pub const ROSTER_PAYLOAD_TYPE: &str = "application/vnd.gitiup.roster+json";
/// A roster entry's self-signature payload type (the key-ownership proof).
pub const ROSTER_ENTRY_PAYLOAD_TYPE: &str = "application/vnd.gitiup.roster-entry+json";
/// The `gitiup participant register` sign-up record.
pub const SIGNUP_PAYLOAD_TYPE: &str = "application/vnd.gitiup.signup+json";
/// A revocation record (D9).
pub const REVOCATION_PAYLOAD_TYPE: &str = "application/vnd.gitiup.revocation+json";
/// A withdrawal record (D8 rotation table).
pub const WITHDRAWAL_PAYLOAD_TYPE: &str = "application/vnd.gitiup.withdrawal+json";
/// A published round record (D11).
pub const ROUND_PAYLOAD_TYPE: &str = "application/vnd.gitiup.round+json";
/// A verdict record (giti-msi.7).
pub const VERDICT_PAYLOAD_TYPE: &str = "application/vnd.gitiup.verdict+json";
/// A `tier: quorum` attestation — the verdict, in an attestation's clothes (giti-zp1.5).
pub const QUORUM_ATTESTATION_PAYLOAD_TYPE: &str = "application/vnd.gitiup.quorum-attestation+json";
/// A job advertisement (giti-zp1.1): the round's invitation, published where a
/// volunteer looking for work can find it.
pub const ADVERTISEMENT_PAYLOAD_TYPE: &str = "application/vnd.gitiup.job-advertisement+json";
/// A TTL lease on one seat of one job (giti-zp1.1). Signed by the holder alone:
/// nothing about a lease is authorised by the owner, so nothing about it needs their
/// signature.
pub const LEASE_PAYLOAD_TYPE: &str = "application/vnd.gitiup.lease+json";
/// A phase-1 commitment in a sealed round (giti-zp1.6): one key's promise about the
/// bytes it is about to reveal. Signed by that key alone, like a lease.
pub const COMMITMENT_PAYLOAD_TYPE: &str = "application/vnd.gitiup.commitment+json";
/// A quarantine record (giti-zp1.8): an owner's decision to keep a key out of the
/// selection pool for N roster epochs. Owner-signed — a key quarantining itself is not a
/// check on anything.
pub const QUARANTINE_PAYLOAD_TYPE: &str = "application/vnd.gitiup.quarantine+json";
/// The record ending a quarantine early (giti-zp1.8). Also owner-signed, and it names the
/// quarantine it ends rather than "whichever one is current".
pub const QUARANTINE_LIFT_PAYLOAD_TYPE: &str = "application/vnd.gitiup.quarantine-lift+json";

/// The canonical bytes of `value`, with `signatures` and `self_signature` removed.
///
/// This is the *body*: what a signature covers and, for a roster, what the digest
/// that a round pins is taken over.
pub fn body_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    body_bytes_without(value, &["signatures", "self_signature"])
}

/// The canonical bytes of `value` with `fields` removed, one canonical encoding.
///
/// Separate because "what a signature covers" is the definition of the signature, and
/// two records in this crate remove different fields: a document drops its own signature
/// list, a roster entry also drops the owner's tier (see
/// [`RosterEntry::body_bytes`](crate::roster::RosterEntry::body_bytes)). Writing that as
/// a parameter keeps one canonicaliser instead of two.
pub fn body_bytes_without<T: serde::Serialize>(value: &T, fields: &[&str]) -> Result<Vec<u8>> {
    let mut body = serde_json::to_value(value)
        .map_err(|e| Error::invalid("record", format!("cannot serialise: {e}")))?;
    if let Some(map) = body.as_object_mut() {
        for field in fields {
            map.remove(*field);
        }
    }
    Ok(canon::to_value_bytes(&body)?)
}

/// Canonical bytes of a whole record, signature lists included.
///
/// What gets stored in the content-addressed store: the bytes on disk are always
/// the signed bytes, so a store cannot be asked "the signature was over what?".
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(canon::to_bytes(value)?)
}

/// Read canonical bytes back into a record type.
pub fn from_canonical_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = canon::require_canonical(bytes)
        .map_err(|e| Error::digest_mismatch("canonical form", e.detail()))?;
    serde_json::from_value(value).map_err(|e| Error::invalid("record", e.to_string()))
}

/// Verify that `bytes` are the canonical encoding of `value`.
pub fn require_same_bytes(value: &impl serde::Serialize, bytes: &[u8]) -> Result<()> {
    let again = canonical_bytes(value)?;
    if again.as_slice() != bytes {
        return Err(Error::digest_mismatch(
            "canonical form",
            "the bytes received are not the canonical encoding of this record",
        ));
    }
    Ok(())
}

/// Sign `body` with `key`, producing a [`SignatureEntry`] that carries the key and
/// the fingerprint derived from it (never the one the caller typed).
pub fn sign(payload_type: &str, body: &[u8], key: &dyn Signer) -> Result<SignatureEntry> {
    Ok(SignatureEntry::new(key, &pae(payload_type, body))?)
}

/// Verify one signature over `body`.
pub fn verify_one(entry: &SignatureEntry, payload_type: &str, body: &[u8]) -> Result<()> {
    Ok(entry.verify(&pae(payload_type, body))?)
}

/// Verify a whole signature list and report which signers the caller trusts.
///
/// Every signature must verify — a record carrying a broken signature is refused
/// rather than filtered, because "we ignored the one that did not work" is how a
/// bored attacker buys a second vote. Then at least one *trusted* signer is
/// required.
///
/// `max` bounds the list (the ADR-0001 D7 work bound), and `what` names the record
/// class in the message.
pub fn check_signatures(
    signatures: &[SignatureEntry],
    payload_type: &str,
    body: &[u8],
    trust: &Trust,
    what: &'static str,
    max: usize,
) -> Result<Vec<String>> {
    if signatures.len() > max {
        return Err(Error::invalid(
            what,
            format!(
                "{} signatures exceeds the {max} limit for one record",
                signatures.len()
            ),
        ));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(signatures.len());
    for entry in signatures {
        if seen.contains(&entry.key_id.as_str()) {
            return Err(Error::invalid(
                what,
                format!(
                    "two signatures from {}: one identity casts one vote",
                    entry.key_id
                ),
            ));
        }
        seen.push(entry.key_id.as_str());
        verify_one(entry, payload_type, body)?;
    }
    let trusted: Vec<String> = signatures
        .iter()
        .filter(|s| trust.trusts(&s.key_id))
        .map(|s| s.key_id.clone())
        .collect();
    if trusted.is_empty() {
        return Err(Error::policy(
            what,
            if signatures.is_empty() {
                format!("this {what} is unsigned: nothing about it is authorised yet")
            } else {
                format!(
                    "no signature on this {what} is from a key this policy trusts ({})",
                    names_of(signatures)
                )
            },
        )
        .with_hint(format!(
            "who is trusted for a {what} is a trust decision: add the key to the policy's \
             trusted set deliberately, or fetch the roster/selector key it should have been signed by"
        )));
    }
    Ok(trusted)
}

/// `SHA256:aaa…,SHA256:bbb…` — a short signer list for an error message.
pub fn names_of(signatures: &[SignatureEntry]) -> String {
    if signatures.is_empty() {
        return "none".to_string();
    }
    signatures
        .iter()
        .map(|s| short_key(&s.key_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A key id shortened for a terminal: `SHA256:abcd…wxyz`.
pub fn short_key(key_id: &str) -> String {
    let body = key_id.strip_prefix("SHA256:").unwrap_or(key_id);
    if body.len() <= 12 {
        key_id.to_string()
    } else {
        format!("SHA256:{}\u{2026}{}", &body[..4], &body[body.len() - 4..])
    }
}

/// A tagged digest in the `sha256:<64 hex>` form, checked for shape.
pub fn require_digest(text: &str, what: &'static str) -> Result<Digest> {
    text.parse::<Digest>().map_err(|e| {
        Error::invalid(what, format!("'{text}': {}", e.detail())).with_hint(
            "digests are written `sha256:<lower-case hex>` (ADR-0001 D2): the algorithm is part of the string",
        )
    })
}

/// A roster key id must look like an SSH fingerprint: it is the *derived* identity,
/// and a field that only looks like one is how a roster ends up voting for a
/// name instead of a key.
pub fn require_key_id_shape(key_id: &str, what: &'static str) -> Result<()> {
    let body = key_id.strip_prefix("SHA256:").ok_or_else(|| {
        Error::invalid(
            what,
            format!("'{key_id}' is not `SHA256:<base64>` — a key id is `ssh-keygen -lf` output"),
        )
    })?;
    // 32 bytes of SHA-256, unpadded base64: 43 characters, and no padding because
    // ADR-0001 D3 says byte-identical to what ssh-keygen prints.
    if body.len() != 43 || body.contains('=') || !body.bytes().all(is_b64) {
        return Err(Error::invalid(
            what,
            format!("'{key_id}' is not a 43-character unpadded base64 SHA-256 fingerprint"),
        ));
    }
    Ok(())
}

fn is_b64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

/// A record that knows how to load itself from storage.
///
/// Every one of them: canonical bytes first, then structural validation, then the
/// re-encode equality check. Bundling the three is deliberate — a reader that parses
/// and forgets to validate is a reader that will happily act on a record whose bytes
/// are not the bytes it claims to be.
///
/// Signature *trust* is not part of loading: who is trusted is the caller's policy, so
/// each type takes a [`Trust`] in its own `verify`/`from_canonical_bytes` call.
pub trait Record: Sized {
    /// Load from canonical bytes.
    fn load(bytes: &[u8]) -> crate::error::Result<Self>;
}

impl Record for crate::roster::Roster {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::roster::Roster::from_canonical_bytes(bytes)
    }
}

impl Record for crate::roster::SignUp {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::roster::SignUp::from_canonical_bytes(bytes)
    }
}

impl Record for crate::round::Round {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::round::Round::from_canonical_bytes(bytes)
    }
}

impl Record for crate::verdict::VerdictRecord {
    /// Loads and structurally validates; the caller still owes `verify` a trust list
    /// before believing the state. A verdict that was never checked is the classic
    /// "the store said so" bug, so `store::verdict_at` takes the trust and does it.
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        let record: crate::verdict::VerdictRecord = from_canonical_bytes(bytes)?;
        record.validate()?;
        require_same_bytes(&record, bytes)?;
        Ok(record)
    }
}

impl Record for crate::attestation::QuorumAttestation {
    /// Loads and structurally validates; the trust list is the caller's, as it is for
    /// a verdict.
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        let record: crate::attestation::QuorumAttestation = from_canonical_bytes(bytes)?;
        record.validate()?;
        require_same_bytes(&record, bytes)?;
        Ok(record)
    }
}

impl Record for crate::job::Advertisement {
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::job::Advertisement::from_canonical_bytes(bytes)
    }
}

impl Record for crate::job::Lease {
    /// Loads and structurally validates. The signature is checked by
    /// [`Lease::verify`](crate::job::Lease::verify), which needs no trust list because a
    /// lease is a key's claim about itself — but every reader in `store` owes that call,
    /// or the store could invent a holder.
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::job::Lease::from_canonical_bytes(bytes)
    }
}

impl Record for crate::commit::Commitment {
    /// Loads and structurally validates; [`crate::Commitment::verify`] is what checks the
    /// seat's own signature, and every reader in `store` owes it that call for the same
    /// reason a lease does.
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        crate::commit::Commitment::from_canonical_bytes(bytes)
    }
}

impl Record for gitiup_attest::AttestationDoc {
    /// Delegates to the format crate's own reader, which insists on canonical bytes
    /// *and* runs the envelope's structural checks.
    fn load(bytes: &[u8]) -> crate::error::Result<Self> {
        gitiup_attest::AttestationDoc::from_canonical_bytes(bytes)
            .map_err(crate::error::Error::from)
    }
}

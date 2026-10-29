//! `gitiup-canon` — the parts of [ADR-0001](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
//! that may have **exactly one implementation**.
//!
//! Two crates need byte-identical answers and neither may grow its own:
//!
//! * `gitiup-attest` is the attestation format. It owned the canonicaliser first.
//! * `gitiup-host` is a storage layer. It has to re-hash what it stores ("refuse
//!   anything that does not re-hash to the name it is filed under",
//!   [ADR-0003 D4](../../../docs/adr/0003-change-record-format-and-merge-semantics.md))
//!   and verify the signature on a change record, but it must not depend on the
//!   format crate, which carries freshness policy, trust and a clock in it.
//!
//! ADR-0003 D11 settled the argument: a second canonicaliser is a second digest,
//! which is a signature over bytes the verifier never saw. So the shared half lives
//! here and both sides depend on it — `gitiup_attest::canon` is a re-export of
//! [`canon`], not a copy.
//!
//! What counts as shared is precisely *what a digest or a signature depends on*:
//!
//! | module | ADR-0001 | what it decides |
//! |--------|----------|-----------------|
//! | [`canon`] | D1 | Gitiup Canonical JSON: one encoding per document, and a reader that *proves* bytes are canonical instead of assuming it |
//! | [`digest`] | D2 | `sha256:<lower hex>` — a digest that names its own algorithm |
//! | [`key`] | D3 | Ed25519, the SSH public-key form, `SHA256:…` key ids, PAE framing, and [`SignatureEntry::verify`] |
//! | [`error`] | D7 | the exit codes every gitiup tool answers with: 6 refused, 7 bad signature, 8 bytes that are not their own canonical form |
//! | [`encoding`] | — | the base64 and hex those need, with no third-party decoder |
//!
//! [`pae`] is here too because a signature is not portable across crates if the
//! bytes it covers are: one PAE, one payload-type rule, whatever document is being
//! signed.
//!
//! # What is *not* here
//!
//! No manifests, no verdicts, no trust, no freshness, no policy, no clock, no I/O,
//! no network and no C toolchain. This crate can tell you that bytes are canonical
//! and that a key signed them; it cannot tell you whether you should *believe* the
//! signer — that is a policy, and policies belong to the caller.
//!
//! ```
//! use gitiup_canon::{Digest, PublicKey, SigningKey, canon, pae};
//!
//! // One encoding per document: the keys come out sorted, whatever order they
//! // went in.
//! let value: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":"x"}"#).unwrap();
//! assert_eq!(canon::to_value_bytes(&value).unwrap(), br#"{"a":"x","b":1}"#);
//!
//! // A key id is what `ssh-keygen -lf` prints for the same key.
//! let key = SigningKey::from_seed(&[7u8; 32]);
//! let line = key.public_key().to_openssh();
//! assert_eq!(
//!     PublicKey::from_openssh(&line).unwrap().key_id(),
//!     key.public_key().key_id()
//! );
//!
//! // A digest names its algorithm, and a signature covers PAE bytes, never raw
//! // document text.
//! assert!(Digest::sha256(b"abc").to_string().starts_with("sha256:"));
//! assert!(pae("text/plain", b"hi").starts_with(b"DSSEv1 10 text/plain 2 "));
//! ```

pub mod canon;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod key;

pub use canon::{
    MAX_DEPTH, MAX_ENCODED_BYTES, from_bytes as from_canonical_bytes, is_canonical,
    require_canonical,
};
pub use digest::{Algorithm, Digest};
pub use error::{Error, ErrorKind, Result};
pub use key::{PublicKey, Signature, SignatureAlgorithm, SignatureEntry, Signer, SigningKey};

/// Pre-Authentication Encoding, exactly as in-toto DSSE defines it.
///
/// A signature covers `pae(payload_type, body)`, never bare document bytes, so the
/// same signature cannot be lifted from one document type into another
/// ([ADR-0001 D3](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
/// It lives here rather than in the attestation envelope because the change, merge
/// and abandon records of ADR-0003 — and rosters, rounds and verdicts of ADR-0002 —
/// all sign with this framing, and a second copy of it is a second format.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + payload_type.len() + payload.len());
    // The lengths are ASCII decimal counts of *bytes*, and the payload is not
    // parsed at all — that is the whole point of PAE.
    out.extend_from_slice(b"DSSEv1");
    out.push(b' ');
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_vector() {
        // The vector DSSE documents (and that `gitiup-attest` used to own): a
        // signature made over these bytes is the same signature in every crate.
        assert_eq!(
            pae("text/plain; charset=utf-8", b"Hello, world!"),
            b"DSSEv1 25 text/plain; charset=utf-8 13 Hello, world!"
        );
    }

    #[test]
    fn a_signature_here_verifies_there() {
        // The point of the crate: the key id, the canonical bytes and the
        // signature are one implementation, so a signer in one crate and a
        // verifier in another cannot disagree.
        let key = SigningKey::from_seed(&[0x11; 32]);
        let body = canon::to_value_bytes(&serde_json::json!({"a": 1})).unwrap();
        let entry = SignatureEntry::new(&key, &pae("application/vnd.gitiup.change+json", &body))
            .expect("sign");
        assert_eq!(entry.key_id, key.public_key().key_id());
        entry
            .verify(&pae("application/vnd.gitiup.change+json", &body))
            .expect("verifies");
        assert!(
            entry
                .verify(&pae("application/vnd.gitiup.merge+json", &body))
                .is_err(),
            "the payload type is inside the signature"
        );
    }
}

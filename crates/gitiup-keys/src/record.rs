//! The framing every signed gitiup record shares.
//!
//! ADR-0001 fixes it for the run attestation, and ADR-0002 D8 extends the same rule
//! to rosters, rounds and verdicts:
//!
//! > A signature covers `pae(payload_type, canonical_bytes(record with its own
//! > signature fields removed))`.
//!
//! This crate needs it for identity claims and endorsements, so it carries the same
//! four helpers rather than inventing a fifth framing. It is deliberately *not* a
//! general record framework: there is no trait to implement, no registry of types
//! and no storage. Storage is `gitiup-host`'s, trust is the caller's, and what is
//! here is the pair of things that must be byte-identical between whoever signs and
//! whoever checks — which bytes are hashed, and how.
//!
//! Removing the signature list before hashing is what makes a signature computable
//! by someone who has not signed yet, and it is why a claim's body digest is stable
//! while unsigned, after the owner signs, and after a third party adds an
//! endorsement.

use serde::Serialize;

use gitiup_attest::{canon, pae};

use crate::error::{Error, Result};

/// `application/vnd.gitiup.<name>+json` — the payload type of a gitiup document.
///
/// Inside the signature, so a claim can never be checked with endorsement rules.
pub fn payload_type(name: &str) -> String {
    format!("application/vnd.gitiup.{name}+json")
}

/// The canonical bytes of `value` with `fields` removed from the top level.
///
/// That removal is the whole trick: the signature list is part of the *document*
/// and cannot be part of what the signature covers.
pub fn body_bytes_with<T: Serialize>(value: &T, fields: &[&str]) -> Result<Vec<u8>> {
    let mut body = serde_json::to_value(value)
        .map_err(|e| Error::invalid("record", format!("cannot serialise: {e}")))?;
    if let Some(map) = body.as_object_mut() {
        for field in fields {
            map.remove(*field);
        }
    } else {
        return Err(Error::invalid(
            "record",
            "a signed record must serialise to a JSON object",
        ));
    }
    Ok(canon::to_value_bytes(&body)?)
}

/// Canonical bytes of a whole record, signature lists included: what gets stored,
/// so nobody has to ask "the signature was over what?".
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(canon::to_bytes(value)?)
}

/// Read canonical bytes into a record type, refusing non-canonical bytes.
///
/// A record whose bytes are not their own canonical re-encoding is a record with
/// two digests, and the second one is the attacker's.
pub fn from_canonical_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = canon::require_canonical(bytes).map_err(|error| {
        Error::new(
            gitiup_attest::ErrorKind::DigestMismatch,
            "record",
            format!("the bytes received are not canonical: {}", error.detail()),
        )
    })?;
    serde_json::from_value(value).map_err(|e| Error::invalid("record", e.to_string()))
}

/// Sign `body` with `key`, producing an entry whose key id is derived from the key
/// it came from — never the one the caller typed.
pub fn sign(
    payload_type: &str,
    body: &[u8],
    key: &dyn gitiup_attest::Signer,
) -> Result<gitiup_attest::SignatureEntry> {
    Ok(gitiup_attest::SignatureEntry::new(
        key,
        &pae(payload_type, body),
    )?)
}

/// Verify one signature over `body`.
pub fn verify_one(
    entry: &gitiup_attest::SignatureEntry,
    payload_type: &str,
    body: &[u8],
) -> Result<()> {
    Ok(entry.verify(&pae(payload_type, body))?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::{SignatureAlgorithm, SignatureEntry, SigningKey};
    use serde::Serialize;
    use serde_json::Value;

    #[derive(Serialize)]
    struct Sample {
        name: &'static str,
        signatures: Vec<SignatureEntry>,
    }

    #[test]
    fn the_signature_field_is_outside_what_is_signed() {
        let key = SigningKey::from_seed(&[21u8; 32]);
        let value = Sample {
            name: "one",
            signatures: vec![SignatureEntry {
                key_id: "SHA256:whatever".into(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: "ssh-ed25519 AAAA".into(),
                sig: "AA==".into(),
            }],
        };
        let body = body_bytes_with(&value, &["signatures"]).unwrap();
        assert_eq!(
            body,
            body_bytes_with(
                &Sample {
                    name: "one",
                    signatures: vec![]
                },
                &["signatures"]
            )
            .unwrap()
        );
        let entry = sign("application/vnd.gitiup.sample+json", &body, &key).unwrap();
        verify_one(&entry, "application/vnd.gitiup.sample+json", &body).unwrap();
        // A different payload type is a different signature, on purpose.
        assert!(verify_one(&entry, "application/vnd.gitiup.other+json", &body).is_err());
    }

    #[test]
    fn a_short_key_id_is_still_recognisable() {
        assert_eq!(short_key("SHA256:abcd"), "SHA256:abcd");
        assert!(short_key(&format!("SHA256:{}", "a".repeat(43))).contains('\u{2026}'));
    }

    #[test]
    fn a_scalar_is_not_a_record() {
        assert!(body_bytes_with(&Value::from(7), &["signatures"]).is_err());
    }
}

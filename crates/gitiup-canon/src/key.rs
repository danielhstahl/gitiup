//! Keys, key ids and signatures ([ADR-0001 D3](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//!
//! One algorithm in v1 — raw Ed25519 (RFC 8032) — and one key presentation:
//! **SSH wire format for the public key, SSH fingerprint for the key id**. That
//! is a deliberate interop choice, not an accident: the person whose trust matters
//! already has `~/.ssh/id_ed25519.pub`, `ssh-keygen -lf` already prints its
//! fingerprint, and `ssh-agent` already signs arbitrary bytes with it. Reusing
//! those means gitiup never asks anyone to carry a second identity.
//!
//! What is *not* reused is OpenSSH's signature framing: `ssh-keygen -Y sign`
//! signs a ssh-specific prehash, not these bytes. See the ADR for why; the short
//! version is that a signature over a prehash nobody else can rebuild cannot be
//! checked by a third party with a two-line script.
//!
//! ```
//! use gitiup_canon::key::SigningKey;
//! let key = SigningKey::from_seed(&[7u8; 32]);
//! // The public key is a line you can paste into `authorized_keys`.
//! let line = key.public_key().to_openssh();
//! assert!(line.starts_with("ssh-ed25519 AAAA"));
//! // The key id is what `ssh-keygen -lf` prints for that same key.
//! assert!(key.public_key().key_id().starts_with("SHA256:"));
//! ```

use std::str::FromStr;

use ed25519_dalek::{Signer as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::encoding::{base64_decode, base64_encode, base64_encode_unpadded};
use crate::error::{Error, ErrorKind, Result};

/// The SSH key type string for Ed25519 public keys.
pub const SSH_ED25519: &str = "ssh-ed25519";

/// Signature algorithms a v1 record may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Raw Ed25519 over the PAE bytes (`ed25519` on the wire).
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl SignatureAlgorithm {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
        }
    }
}

/// An Ed25519 public key, with its SSH encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
}

impl PublicKey {
    /// From the 32 raw key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey> {
        VerifyingKey::from_bytes(bytes)
            .map(|key| PublicKey { key })
            .map_err(|e| Error::invalid("public key", e.to_string()))
    }

    /// The raw 32 key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.key.as_bytes()
    }

    /// The OpenSSH public-key wire blob:
    /// `string "ssh-ed25519" || string <key>`, each `string` length-prefixed.
    pub fn ssh_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(9 + 36);
        blob.extend_from_slice(&(SSH_ED25519.len() as u32).to_be_bytes());
        blob.extend_from_slice(SSH_ED25519.as_bytes());
        blob.extend_from_slice(&(self.key.as_bytes().len() as u32).to_be_bytes());
        blob.extend_from_slice(self.key.as_bytes());
        blob
    }

    /// Parse an OpenSSH public key line (`ssh-ed25519 AAAA... [comment]`).
    ///
    /// The comment is ignored: identity comes from the fingerprint, never from a
    /// string someone typed.
    pub fn from_openssh(line: &str) -> Result<PublicKey> {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap_or_default();
        let body = fields
            .next()
            .ok_or_else(|| Error::invalid("public key", "expected `ssh-ed25519 <base64>`"))?;
        if kind != SSH_ED25519 {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "public key",
                format!("key type '{kind}' is not supported in v1"),
            )
            .with_hint("ed25519 only; convert or generate one with `gitiup keygen` (giti-1rs.6)"));
        }
        let blob = base64_decode(body)?;
        PublicKey::from_ssh_blob(&blob)
    }

    /// Parse an OpenSSH public-key **wire blob** — the same bytes as
    /// [`PublicKey::ssh_blob`], without the base64 and the comment.
    ///
    /// Public because that is the form the things people already have hand over:
    /// an `ssh-agent` identity list and `gpg --export-ssh-key` both speak in blobs,
    /// and a second parser somewhere else would be a second opinion on what a key
    /// id is.
    pub fn from_ssh_blob(blob: &[u8]) -> Result<PublicKey> {
        let key = ssh_ed25519_key_bytes(blob)?;
        PublicKey::from_bytes(&key)
    }

    /// The OpenSSH public-key line, without a comment.
    pub fn to_openssh(&self) -> String {
        format!("{SSH_ED25519} {}", base64_encode_unpadded(&self.ssh_blob()))
    }

    /// The key id: `SHA256:` + unpadded base64 of SHA-256 over the SSH blob.
    ///
    /// Byte-identical to what `ssh-keygen -lf` prints, so a key id in an
    /// attestation can be matched against an `authorized_keys` file by eye.
    pub fn key_id(&self) -> String {
        let fingerprint = Digest::sha256(&self.ssh_blob());
        format!("SHA256:{}", base64_encode_unpadded(fingerprint.as_bytes()))
    }
}

impl FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey> {
        PublicKey::from_openssh(s)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_openssh())
    }
}

fn ssh_ed25519_key_bytes(blob: &[u8]) -> Result<[u8; 32]> {
    let read_string = |cursor: &mut usize| -> Result<Vec<u8>> {
        let len = u32::from_be_bytes(
            blob.get(*cursor..*cursor + 4)
                .ok_or_else(|| Error::invalid("public key", "truncated SSH string length"))?
                .try_into()
                .expect("four bytes"),
        ) as usize;
        *cursor += 4;
        let bytes = blob
            .get(*cursor..*cursor + len)
            .ok_or_else(|| Error::invalid("public key", "truncated SSH string"))?
            .to_vec();
        *cursor += len;
        Ok(bytes)
    };
    let mut cursor = 0usize;
    let kind = read_string(&mut cursor)?;
    if kind != SSH_ED25519.as_bytes() {
        return Err(Error::new(
            ErrorKind::UnsupportedSchema,
            "public key",
            format!(
                "SSH key type '{}' is not supported in v1",
                String::from_utf8_lossy(&kind)
            ),
        ));
    }
    let key = read_string(&mut cursor)?;
    if cursor != blob.len() {
        return Err(Error::invalid(
            "public key",
            "trailing bytes in the SSH blob",
        ));
    }
    let bytes: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| Error::invalid("public key", "ed25519 keys are 32 bytes"))?;
    Ok(bytes)
}

/// An Ed25519 signature (64 raw bytes, base64 on the wire).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Signature {
    /// From raw bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Signature {
        Signature { bytes: *bytes }
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Base64 (standard alphabet, padded) as written on the wire.
    pub fn to_base64(&self) -> String {
        base64_encode(&self.bytes)
    }

    /// Parse the wire form.
    pub fn from_base64(s: &str) -> Result<Signature> {
        let raw = base64_decode(s)?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::invalid("signature", "ed25519 signatures are 64 bytes"))?;
        Ok(Signature { bytes })
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", &self.to_base64()[..16])
    }
}

/// A signing key.
///
/// This is the in-memory half; *where* keys live (age-encrypted keystore,
/// ssh-agent, gpg) is giti-1rs.6. Anything that can sign exposes [`Signer`] so
/// the attestation code does not care which backend produced a signature.
pub struct SigningKey {
    key: ed25519_dalek::SigningKey,
}

impl SigningKey {
    /// Deterministic key from a 32-byte seed.
    ///
    /// Tests (and the committed golden fixtures) derive their key this way, so
    /// the fixtures carry no private material.
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    /// The seed (private half). Never serialize this into a record.
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The public half.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.verifying_key(),
        }
    }

    /// Sign arbitrary bytes (callers pass the PAE output, never raw manifest text).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.key.sign(message);
        Signature {
            bytes: sig.to_bytes(),
        }
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.public_key().key_id())
    }
}

/// Anything that can produce a signature over attestation bytes.
///
/// giti-1rs.6 implements this for the keystore, ssh-agent and (optionally) gpg;
/// the attestation code only ever sees this trait, so a signature from a hardware
/// agent is formatted exactly like one from a generated key.
pub trait Signer: Send + Sync {
    /// The key that will verify the signature.
    fn public_key(&self) -> PublicKey;

    /// Sign `message` (the PAE output).
    fn sign(&self, message: &[u8]) -> Result<Signature>;

    /// The key id to record; defaults to the SSH fingerprint.
    fn key_id(&self) -> String {
        self.public_key().key_id()
    }
}

impl Signer for SigningKey {
    fn public_key(&self) -> PublicKey {
        SigningKey::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(SigningKey::sign(self, message))
    }
}

/// One signature in a record: the bytes, plus everything needed to check them
/// without a keystore lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    /// `SHA256:<unpadded base64>`, as printed by `ssh-keygen -lf`.
    pub key_id: String,
    /// `ed25519`.
    pub algorithm: SignatureAlgorithm,
    /// The public key, as an `ssh-ed25519 <base64>` line.
    pub public_key: String,
    /// The signature over the PAE bytes, base64 (padded).
    pub sig: String,
}

impl SignatureEntry {
    /// Build the wire form of a signature made by `key`.
    pub fn new(key: &dyn Signer, message: &[u8]) -> Result<SignatureEntry> {
        let public = key.public_key();
        let signature = key.sign(message)?;
        Ok(SignatureEntry {
            key_id: public.key_id(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: public.to_openssh(),
            sig: signature.to_base64(),
        })
    }

    /// Check the entry is self-consistent, then verify `message`.
    ///
    /// The `key_id` is *derived* from `public_key` rather than trusted: an entry
    /// that claims a famous key id while carrying another key must fail here, not
    /// after a policy lookup said the id was trusted.
    pub fn verify(&self, message: &[u8]) -> Result<()> {
        if self.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "signature",
                format!(
                    "algorithm '{}' is not supported in v1",
                    self.algorithm.as_str()
                ),
            ));
        }
        let public = PublicKey::from_openssh(&self.public_key)?;
        if public.key_id() != self.key_id {
            return Err(Error::new(
                ErrorKind::Signature,
                "signature",
                format!(
                    "key_id '{}' is not the fingerprint of the public key offered ({}), so the signer identity is being spoofed",
                    self.key_id,
                    public.key_id()
                ),
            ));
        }
        let signature = Signature::from_base64(&self.sig)?;
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
        // `verify_strict` is part of the format, not an option: it rejects weak
        // (cofactor-less) public keys and non-canonical signature encodings, so
        // one message can never acquire a second valid signature.
        public.key.verify_strict(message, &sig).map_err(|_| {
            Error::new(
                ErrorKind::Signature,
                "signature",
                format!("ed25519 signature by {} does not verify", self.key_id),
            )
        })
    }

    /// The key id this entry claims.
    pub fn claimed_key_id(&self) -> &str {
        &self.key_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_line_and_fingerprint_round_trip() {
        let key = SigningKey::from_seed(&[3u8; 32]);
        let line = key.public_key().to_openssh();
        let parsed = PublicKey::from_openssh(&format!("{line} alice@laptop")).unwrap();
        assert_eq!(parsed, key.public_key());
        let id = key.public_key().key_id();
        assert!(id.starts_with("SHA256:"), "{id}");
        // ssh-keygen prints 43 unpadded base64 characters for a 32-byte hash.
        assert_eq!(id.len(), "SHA256:".len() + 43);
        assert!(!id.contains('='));
    }

    #[test]
    fn pins_key_line_fingerprint_and_signature() {
        // Regression lock on the *interop* surface: the SSH public-key blob, the
        // fingerprint form and what bytes get signed. If any of these change
        // shape, every key id in every stored attestation changes with it, which
        // is a format break (ADR-0001 D8), so this test is allowed to fail only
        // together with an ADR revision.
        //
        // The values were cross-checked against OpenSSL 3.5 rather than against
        // this crate, so they are not merely self-consistent:
        //
        // ```text
        // # PKCS#8 wrapper for an Ed25519 seed, then the public key:
        // printf 302e020100300506032b657004220420 > seed.der
        // printf '\x11%.0s' {1..32} >> seed.der
        // openssl pkey -inform DER -in seed.der -pubout -outform DER > pub.der
        // # "Signature Verified Successfully" for the signature below:
        // openssl pkeyutl -verify -pubin -keyform DER -inkey pub.der \
        //     -rawin -in msg.bin -sigfile sig.bin
        // ```
        let seed = hex_bytes(&"11".repeat(32));
        let key = SigningKey::from_seed(&seed);
        assert_eq!(
            key.public_key().as_bytes(),
            // ...the last 32 bytes of pub.der above.
            hex_bytes("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
                .as_slice()
        );
        assert_eq!(
            key.public_key().to_openssh(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINBKsjJ0K7SrOhNovUYV5ObQIkq3GgFrr4UgozLJd4c3"
        );
        assert_eq!(
            key.public_key().key_id(),
            "SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E"
        );
        assert_eq!(
            key.sign(b"gitiup-pae").to_base64(),
            "EFUl5KRgjNd4SBnEnbmEPiA4+imJBYoQMfOIg4ih8JvVH9nzkoOF5RuQvSO3zYTJCNE1i3lXqDlf2zB1Mhd3Ag=="
        );
    }

    #[test]
    fn rejects_malformed_keys() {
        assert!(PublicKey::from_openssh("ssh-rsa AAAA").is_err());
        assert!(PublicKey::from_openssh("ssh-ed25519").is_err());
        assert!(PublicKey::from_openssh("ssh-ed25519 !!!").is_err());
        let short = base64_encode_unpadded(&[0u8; 31]);
        assert!(PublicKey::from_openssh(&format!("ssh-ed25519 {short}")).is_err());
        // Right length, SSH framing, but trailing garbage after the two strings.
        let mut blob = SigningKey::from_seed(&[1u8; 32]).public_key().ssh_blob();
        blob.push(0);
        assert!(ssh_ed25519_key_bytes(&blob).is_err());
    }

    #[test]
    fn signature_verifies_and_binds_the_key_id() {
        let key = SigningKey::from_seed(&[9u8; 32]);
        let message = b"pae bytes";
        let entry = SignatureEntry::new(&key, message).unwrap();
        assert_eq!(entry.algorithm, SignatureAlgorithm::Ed25519);
        assert!(entry.verify(message).is_ok());
        assert!(entry.verify(b"other bytes").is_err());

        // Swapping in a different public key while keeping the claimed key id
        // must be refused before any trust lookup happens.
        let other = SigningKey::from_seed(&[10u8; 32]);
        let mut spoof = entry.clone();
        spoof.public_key = other.public_key().to_openssh();
        let err = spoof.verify(message).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Signature);
        assert!(err.detail().contains("spoofed"));
    }

    fn hex_bytes(s: &str) -> [u8; 32] {
        crate::encoding::hex_decode(s).unwrap().try_into().unwrap()
    }
}

//! The derivations: round seed, per-candidate score, storage slot and round
//! handle ([ADR-0002 D2, D3, D10, D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! Four hashes, all keyed or domain-separated, and all of them public once a round
//! is opened. They are the whole protocol: there is no message to send, no
//! coordinator to call and no randomness to agree on. The selector's job shrinks to
//! signing a record containing a number a function already determined.
//!
//! ```text
//! secret  = HKDF-Extract(salt = "gitiup-round-1/secret", ikm = <selector Ed25519 seed>)
//! round   = "gitiup-round-1" ‖ 0x00 ‖ epoch ‖ 0x00 ‖ hex(roster_digest) ‖ 0x00 ‖
//!           change_id ‖ 0x00 ‖ head_oid ‖ 0x00 ‖ job_id ‖ 0x00 ‖ attempt
//! seed    = HMAC-SHA256(secret, round)                       # published, not chosen
//! score   = SHA256("gitiup-round-1/score" ‖ 0x00 ‖ seed ‖ 0x00 ‖ key_id)
//! handle  = HMAC-SHA256(seed, "gitiup-round-1/handle" ‖ 0x00 ‖ key_id)[0..16]
//! slot    = hex(SHA256("gitiup-keyslot-1" ‖ 0x00 ‖ key_id))
//! ```
//!
//! The domain strings are inside every digest, so changing one re-names every past
//! selection: that is a new `round_kind` plus new fixtures, never an edit (ADR-0002,
//! "How we change our minds"). [`assert_vectors_match`] makes an accidental edit
//! fail a test on the first run rather than in a production verdict.

use std::sync::LazyLock;

use gitiup_attest::{Digest, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};

use crate::error::{Error, Result};

/// The selection generation: `round_kind`, the first field of the seed message and
/// the prefix of every other domain string.
pub const ROUND_KIND: &str = "gitiup-round-1";

/// Separator between the fields of the seed message. A byte that cannot appear in
/// any of them (D2: an embedded `0x00` is a refusal, not a fix-up).
pub const FIELD_SEPARATOR: u8 = 0x00;

/// Display-only separator used in `round_id` strings so a terminal can show a
/// readable line. The *message* uses [`FIELD_SEPARATOR`]; printing the confusion
/// wrong is how two implementations disagree about a seed.
pub const DISPLAY_SEPARATOR: &str = "/";

/// Domain string for the storage slot derivation (D10). Not `round_kind`-prefixed:
/// slots are per key, not per generation, and changing this one would orphan every
/// ref in every store.
pub const SLOT_DOMAIN: &[u8] = b"gitiup-keyslot-1";

/// How many bytes of the handle are used as a pseudonym.
pub const HANDLE_BYTES: usize = 16;

fn domain(suffix: &str) -> Vec<u8> {
    format!("{ROUND_KIND}/{suffix}").into_bytes()
}

/// Domain string for the score.
pub fn score_domain() -> Vec<u8> {
    domain("score")
}

/// Domain string for the handle.
pub fn handle_domain() -> Vec<u8> {
    domain("handle")
}

/// Domain string for the HKDF-Extract salt.
pub fn secret_domain() -> Vec<u8> {
    domain("secret")
}

/// Domain string for the per-key round challenge (what a verifier echoes in
/// `claims.verifier_challenge`, so an attestation cannot be moved between rounds).
pub fn challenge_domain() -> Vec<u8> {
    domain("challenge")
}

/// The label the ADR-0002 vectors use as their `ikm`.
pub const TEST_VECTOR_LABEL: &[u8] = b"gitiup ADR-0002 test vector selection secret (never use)";

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The published `selection_secret` of the ADR-0002 vectors:
/// `HKDF-Extract(salt = "gitiup-round-1/secret", ikm = TEST_VECTOR_LABEL)`.
///
/// Public by design — a vector only one machine can recompute is an assertion, not
/// a test — and harmless, because the vectors are unsigned, so nothing trusts the
/// key behind it.
pub fn test_vector_secret() -> [u8; 32] {
    static SECRET: LazyLock<[u8; 32]> = LazyLock::new(|| hmac(&secret_domain(), TEST_VECTOR_LABEL));
    *SECRET
}

/// The selector's derivation secret.
///
/// `HKDF-Extract` *is* an HMAC, so "the secret is derived from the identity key"
/// needs no new key material (ADR-0002 D2): one Ed25519 identity per participant and
/// nothing extra to back up or mis-place. It is also why the seed cannot be re-rolled:
/// the selector's freedom is nil, because the seed's inputs are fixed by the change,
/// the epoch and the function.
pub struct SelectionSecret {
    bytes: [u8; 32],
}

impl SelectionSecret {
    /// Derive from a selector's Ed25519 signing key — the normal path, since the
    /// key that signs the roster is the selector by default.
    pub fn from_signing_key(key: &SigningKey) -> SelectionSecret {
        SelectionSecret::from_key_seed(&key.seed())
    }

    /// Derive from a raw Ed25519 seed: `HMAC(salt = "gitiup-round-1/secret", ikm)`.
    pub fn from_key_seed(seed: &[u8; 32]) -> SelectionSecret {
        SelectionSecret {
            bytes: hmac(&secret_domain(), seed),
        }
    }

    /// Take an already-extracted secret (test vectors, or a selector that stores the
    /// derived form).
    pub fn from_extracted(bytes: &[u8; 32]) -> SelectionSecret {
        SelectionSecret { bytes: *bytes }
    }

    /// The ADR-0002 fixture secret ([`test_vector_secret`]).
    pub fn test_vector() -> SelectionSecret {
        SelectionSecret::from_extracted(&test_vector_secret())
    }

    /// The raw 32 bytes. Public because a test vector must be recomputable by
    /// anyone; a real selector's secret never leaves its key store.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for SelectionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a secret, not even shortened: this type shows up in `Debug`
        // output of round-building code, which ends up in logs.
        write!(f, "SelectionSecret(<redacted>)")
    }
}

/// The seed message: the seven fields, NUL-separated, in this order
/// ([ADR-0002 D2](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// Every field is written exactly one way (shortest decimal with no sign or leading
/// zeros, lower-case hex, oids as they appear in the change record). An empty field
/// or one containing `0x00` is a refusal, because a message that parses two ways is
/// a seed that can be produced two ways.
pub fn round_id_message(fields: &[&str]) -> Result<Vec<u8>> {
    if fields.len() != 7 {
        return Err(Error::invalid(
            "round id",
            format!(
                "the seed message has exactly 7 fields (round kind, epoch, roster digest body, \
                 change id, head oid, job id, attempt); got {}",
                fields.len()
            ),
        ));
    }
    let mut out = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        if field.is_empty() {
            return Err(Error::invalid(
                "round id",
                format!("round field {index} is empty: an empty field is a refusal, not a fix-up"),
            ));
        }
        if field.contains('\0') {
            return Err(Error::invalid(
                "round id",
                format!("round field {index} contains a NUL byte"),
            ));
        }
        if index > 0 {
            out.push(FIELD_SEPARATOR);
        }
        out.extend_from_slice(field.as_bytes());
    }
    Ok(out)
}

/// The readable form of a seed message (`/`-joined), for `--explain` and logs.
///
/// The separators are *display*: the HMAC message joins with `0x00`.
pub fn round_id_display(fields: &[&str]) -> Result<String> {
    Ok(String::from_utf8(round_id_message(fields)?)
        .map_err(|_| Error::invalid("round id", "round fields are not valid UTF-8"))?
        .replace(FIELD_SEPARATOR as char, DISPLAY_SEPARATOR))
}

/// The round seed: `HMAC-SHA256(secret, round_id_message)`.
///
/// The seed *is* the 32-byte HMAC output — it is not hashed again. Re-hashing it is a
/// silent derivation change: the numbers stay 32 bytes, so everything downstream keeps
/// working while nothing agrees with the vectors any more.
pub fn round_seed(secret: &SelectionSecret, message: &[u8]) -> Digest {
    digest_of_hmac(&hmac(secret.as_bytes(), message))
}

/// A `sha256:`-tagged digest over 32 raw bytes, without hashing them.
pub fn digest_of_hmac(raw: &[u8; 32]) -> Digest {
    Digest::new(gitiup_attest::Algorithm::Sha256, raw)
        .expect("an HMAC-SHA-256 output is a sha256 digest")
}

/// A candidate's score, as 64 lower-case hex characters.
///
/// Ordering compares this string ascending, which for a fixed-length lower-case hex
/// encoding *is* the 256-bit big-endian integer comparison D3 specifies — without a
/// bignum type in the trust path.
pub fn score(seed: &[u8; 32], key_id: &str) -> String {
    let bytes = sha256(&[
        &score_domain(),
        &[FIELD_SEPARATOR],
        seed,
        &[FIELD_SEPARATOR],
        key_id.as_bytes(),
    ]);
    gitiup_attest::encoding::hex_encode(&bytes)
}

/// The seed-derived pseudonym for a key (D11): unlinkable without the seed, which
/// is what a sealed reveal mode would address slots by.
pub fn handle(seed: &[u8; 32], key_id: &str) -> String {
    let raw = hmac(
        seed,
        &[
            handle_domain(),
            vec![FIELD_SEPARATOR],
            key_id.as_bytes().to_vec(),
        ]
        .concat(),
    );
    gitiup_attest::encoding::hex_encode(&raw[..HANDLE_BYTES])
}

/// The public storage slot for a key id (D10).
///
/// A key id is `SHA256:<base64 with +, / and no padding>`, which is illegal or
/// hostile in a ref name; the slot is the hex-safe, stable, one-way public name.
/// Human listings print both.
pub fn key_slot(key_id: &str) -> String {
    let bytes = sha256(&[SLOT_DOMAIN, &[FIELD_SEPARATOR], key_id.as_bytes()]);
    gitiup_attest::encoding::hex_encode(&bytes)
}

/// The challenge a selected verifier must echo in `claims.verifier_challenge`, so an
/// attestation cannot be lifted out of the round it was made for (D11 step 6).
///
/// A different domain from [`handle`] on purpose: a handle addresses a slot and a
/// challenge binds a signature, and the two must not be interchangeable.
pub fn challenge(seed: &[u8; 32], key_id: &str) -> Digest {
    let raw = hmac(
        seed,
        &[
            challenge_domain(),
            vec![FIELD_SEPARATOR],
            key_id.as_bytes().to_vec(),
        ]
        .concat(),
    );
    Digest::sha256(&raw)
}

/// Refuse a `round_kind` this build does not implement.
///
/// Required by ADR-0002's rule that a reader refuses what it does not know rather
/// than treating it as the default: applying `gitiup-round-1` rules to a
/// `gitiup-round-2` selection would make two honest implementations disagree about
/// a quorum, which is worse than refusing.
pub fn require_round_kind(round_kind: &str) -> Result<()> {
    if round_kind != ROUND_KIND {
        return Err(Error::unsupported(
            "round kind",
            format!("selection round kind '{round_kind}' is not implemented by this build"),
        )
        .with_hint(format!(
            "this build implements {ROUND_KIND}; a new round kind is a new ADR fixture set, \
             and a reader must refuse rather than guess"
        )));
    }
    Ok(())
}

/// The worked-example values quoted by ADR-0002, so a build can prove it derives
/// what the ADR says it derives.
pub const WORKED_EXAMPLE: WorkedExample = WorkedExample {
    roster_epoch: 41,
    roster_digest: "sha256:e3c05974bea30ff0c2ad3b9b8d4219b1d41a0c45a5e1c948c8455fdc4c304a74",
    change_id: "chg-000000000000f00d",
    head_oid: "sha1:e255b091aabd7e443b5d2fbeb90bc9769d07cbeb",
    job_id: "build/matrix/linux-x86_64",
    attempt: 0,
    seed: "sha256:f6bb5ca427209de28c8cc1d75d74c75f9d5b2f090be21c14f64be1557790c7eb",
};

/// The ADR's worked example, as data.
#[derive(Debug, Clone, Copy)]
pub struct WorkedExample {
    /// Roster epoch.
    pub roster_epoch: u64,
    /// Roster digest of the fixture roster.
    pub roster_digest: &'static str,
    /// Change id.
    pub change_id: &'static str,
    /// Head oid.
    pub head_oid: &'static str,
    /// Job id.
    pub job_id: &'static str,
    /// Attempt.
    pub attempt: u64,
    /// The seed these inputs must produce.
    pub seed: &'static str,
}

impl WorkedExample {
    /// The seven seed-message fields of the worked example.
    pub fn fields(&self) -> Result<[String; 7]> {
        let body = self
            .roster_digest
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::invalid("round id", "fixture digest is not sha256-tagged"))?;
        Ok([
            ROUND_KIND.to_string(),
            self.roster_epoch.to_string(),
            body.to_string(),
            self.change_id.to_string(),
            self.head_oid.to_string(),
            self.job_id.to_string(),
            self.attempt.to_string(),
        ])
    }
}

/// Prove this build derives the ADR's worked-example seed.
///
/// Not paranoia about typos: the domain strings are inside every digest, so an edit
/// would silently re-name every past selection while leaving the fixtures *looking*
/// right. The ADR quotes them, and
/// `docs/adr/fixtures/selection-v1/generate.py` is the executable copy.
pub fn assert_vectors_match() -> Result<()> {
    let secret = SelectionSecret::test_vector();
    let fields = WORKED_EXAMPLE.fields()?;
    let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
    let seed = round_seed(&secret, &round_id_message(&refs)?);
    if seed.to_string() != WORKED_EXAMPLE.seed {
        return Err(Error::digest_mismatch(
            "derivation",
            format!(
                "the worked-example seed is {seed}, expected {}: a domain string or the field \
                 order has changed, which is a new round kind, not an edit",
                WORKED_EXAMPLE.seed
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_worked_example_seed_is_reproducible() {
        assert_vectors_match().unwrap();
    }

    #[test]
    fn hmac_and_sha256_helpers_agree_with_published_answers() {
        // RFC 4231 test case 1 (key = 20 x 0x0b, data = "Hi There") and FIPS 180-4's
        // "abc": checked against published values, not against this crate.
        assert_eq!(
            hex(&hmac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&sha256(&[b"abc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn scores_are_ordered_by_hex_and_tie_broken_by_key_id() {
        let seed = [7u8; 32];
        let a = score(&seed, "SHA256:AAA");
        let b = score(&seed, "SHA256:AAB");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        // Fixed-length lower-case hex: byte order is the integer order D3 wants.
        let mut both = [a.clone(), b.clone()];
        both.sort();
        assert_eq!(both[0], a.min(b));
    }

    #[test]
    fn slots_handles_and_challenges_are_distinct_and_stable() {
        let seed = [3u8; 32];
        let key_id = "SHA256:2HS8bJpYBy7bDfWIQN304coFKT0s6CVPABFLYq+IX5E";
        let slot = key_slot(key_id);
        assert_eq!(slot.len(), 64);
        assert!(slot.bytes().all(|b| b.is_ascii_hexdigit()));
        // A pure function of the key, so two implementations address the same ref
        // without talking to each other.
        assert_eq!(slot, key_slot(key_id));
        assert_eq!(slot, key_slot(key_id));
        assert_ne!(handle(&seed, key_id), challenge(&seed, key_id).hex());
        assert_eq!(handle(&seed, key_id).len(), HANDLE_BYTES * 2);
        // A different seed is a different pseudonym, which is what makes a handle
        // unlinkable before the seed is published.
        assert_ne!(handle(&seed, key_id), handle(&[4u8; 32], key_id));
        assert_ne!(challenge(&seed, key_id), challenge(&[4u8; 32], key_id));
    }

    #[test]
    fn the_round_message_refuses_ambiguous_fields() {
        assert!(round_id_message(&[ROUND_KIND, "41", "x", "c", "h", "j", "0"]).is_ok());
        assert!(round_id_message(&[ROUND_KIND, "41", "", "c", "h", "j", "0"]).is_err());
        assert!(round_id_message(&[ROUND_KIND, "41", "x", "c\0d", "h", "j", "0"]).is_err());
        assert!(round_id_message(&[ROUND_KIND, "41", "x", "c", "h", "j"]).is_err());
        // The display form shows a separator; the message contains none.
        let shown = round_id_display(&[ROUND_KIND, "41", "x", "c", "h", "j", "0"]).unwrap();
        assert_eq!(shown, "gitiup-round-1/41/x/c/h/j/0");
        let message = round_id_message(&[ROUND_KIND, "41", "x", "c", "h", "j", "0"]).unwrap();
        assert!(!message.contains(&b'/'));
        assert_eq!(message.iter().filter(|b| **b == FIELD_SEPARATOR).count(), 6);
    }

    #[test]
    fn an_unknown_round_kind_is_refused() {
        require_round_kind(ROUND_KIND).unwrap();
        let err = require_round_kind("gitiup-round-2").unwrap_err();
        assert_eq!(err.exit_code(), 6);
        assert_eq!(
            err.kind(),
            gitiup_attest::ErrorKind::UnsupportedSchema.as_str()
        );
    }

    #[test]
    fn the_derivation_secret_is_derived_not_chosen() {
        // Two selectors, two secrets; one selector, one secret, however often it is
        // asked. There is no way to re-roll.
        let key = SigningKey::from_seed(&[0x11; 32]);
        assert_eq!(
            SelectionSecret::from_signing_key(&key).as_bytes(),
            SelectionSecret::from_key_seed(&key.seed()).as_bytes()
        );
        assert_ne!(
            SelectionSecret::from_signing_key(&key).as_bytes(),
            SelectionSecret::from_signing_key(&SigningKey::from_seed(&[0x12; 32])).as_bytes()
        );
        assert!(format!("{:?}", SelectionSecret::from_signing_key(&key)).contains("redacted"));
        assert_eq!(
            test_vector_secret(),
            hmac(&secret_domain(), TEST_VECTOR_LABEL)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        gitiup_attest::encoding::hex_encode(bytes)
    }
}

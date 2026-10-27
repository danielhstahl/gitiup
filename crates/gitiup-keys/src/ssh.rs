//! The sliver of SSH this crate needs: a wire buffer and the OpenSSH *private*
//! key file format.
//!
//! Two separate jobs, deliberately kept apart:
//!
//! * the [`Wire`] / [`WireReader`] pair is the SSH string/u32 framing used by the
//!   agent protocol ([`crate::agent`]) and by public-key blobs;
//! * [`parse_openssh_private`] reads `~/.ssh/id_ed25519` so an existing key can be
//!   imported into the keystore.
//!
//! Public *keys* are not re-parsed here: `gitiup_attest::key::PublicKey` owns the
//! SSH public-key line, the SSH wire blob and the fingerprint, and reusing it is
//! what makes a key id mean one thing in this workspace (ADR-0001 D3).
//!
//! What is deliberately **not** implemented is OpenSSH's signature framing
//! (`ssh-keygen -Y sign`): ADR-0001 D3 rejects it as a format, and a client that
//! can make those bytes is a client that will be asked to verify them.

use gitiup_attest::encoding::base64_decode;
use gitiup_attest::key::PublicKey;

use crate::error::{Error, Result};

/// The magic that opens every OpenSSH private key file (with its NUL).
pub const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
/// The PEM armour line that opens an OpenSSH private key.
pub const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// The PEM armour line that closes it.
pub const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// An Ed25519 private half in an OpenSSH file: seed (32) then public (32).
const ED25519_SK_BYTES: usize = 64;
/// The public key in an OpenSSH ed25519 private section: 32 raw bytes.
const ED25519_PK_BYTES: usize = 32;

/// Builds an SSH wire message: `uint32` big-endian and `string` = length-prefixed
/// bytes, which is the whole of the encoding the agent protocol uses.
#[derive(Debug, Default)]
pub struct Wire(Vec<u8>);

impl Wire {
    /// An empty message.
    pub fn new() -> Wire {
        Wire(Vec::new())
    }

    /// Append a `uint32`.
    pub fn u32(&mut self, value: u32) -> &mut Wire {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append a `byte`.
    pub fn byte(&mut self, value: u8) -> &mut Wire {
        self.0.push(value);
        self
    }

    /// Append a `string`.
    pub fn string(&mut self, bytes: &[u8]) -> &mut Wire {
        self.u32(bytes.len() as u32);
        self.0.extend_from_slice(bytes);
        self
    }

    /// Append raw bytes (used for the magic and for the framing header).
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Wire {
        self.0.extend_from_slice(bytes);
        self
    }

    /// The message so far.
    pub fn finish(&self) -> &[u8] {
        &self.0
    }
}

/// Reads an SSH wire message, refusing to run past the end.
///
/// The agent protocol answers with a length-prefixed message off a socket, so a
/// reader that trusts its own offsets is a reader that will panic — or index into
/// the *next* message — on a hostile or buggy agent. Every read here is
/// bounds-checked and returns an error instead.
#[derive(Debug, Clone, Copy)]
pub struct WireReader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> WireReader<'a> {
    /// Read from `data`.
    pub fn new(data: &'a [u8]) -> WireReader<'a> {
        WireReader { data, at: 0 }
    }

    /// Start `at` bytes in (used to step over the OpenSSH magic).
    pub fn skipped(data: &'a [u8], at: usize) -> Result<WireReader<'a>> {
        if at > data.len() {
            return Err(Error::invalid(
                "ssh wire",
                "message is shorter than its header",
            ));
        }
        Ok(WireReader { data, at })
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    /// A `byte`.
    pub fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.at)
            .ok_or_else(|| Error::invalid("ssh wire", "message ended at a byte"))?;
        self.at += 1;
        Ok(byte)
    }

    /// A `uint32`.
    pub fn u32(&mut self) -> Result<u32> {
        let four: [u8; 4] = self
            .data
            .get(self.at..self.at + 4)
            .ok_or_else(|| Error::invalid("ssh wire", "message ended at a uint32"))?
            .try_into()
            .expect("four bytes");
        self.at += 4;
        Ok(u32::from_be_bytes(four))
    }

    /// A `string`, borrowed.
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| Error::invalid("ssh wire", "string length overflows"))?;
        let bytes = self
            .data
            .get(self.at..end)
            .ok_or_else(|| Error::invalid("ssh wire", "string runs past the message"))?;
        self.at = end;
        Ok(bytes)
    }

    /// Require that everything was consumed.
    ///
    /// A message with trailing bytes is a message this build does not understand,
    /// not a message to be lenient about: leniency in a protocol reader is where
    /// parsers and parsers' bugs meet.
    pub fn require_end(&self) -> Result<()> {
        if self.at != self.data.len() {
            return Err(Error::invalid(
                "ssh wire",
                format!(
                    "{} bytes left over after the message",
                    self.data.len() - self.at
                ),
            ));
        }
        Ok(())
    }
}

/// An OpenSSH private key that was read off disk.
#[derive(Clone)]
pub struct OpensshPrivate {
    /// The public half.
    pub public: PublicKey,
    /// The 32-byte Ed25519 seed.
    pub seed: [u8; 32],
    /// The comment field (`alice@laptop` by convention), if any.
    ///
    /// Carried for display only: identity comes from the fingerprint, never from a
    /// string somebody typed.
    pub comment: String,
}

impl std::fmt::Debug for OpensshPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Debug` is what a `{:?}` in a log or a panic prints; a private key must
        // not be in either.
        f.debug_struct("OpensshPrivate")
            .field("key_id", &self.public.key_id())
            .field("seed", &"<redacted>")
            .field("comment", &self.comment)
            .finish()
    }
}

impl Drop for OpensshPrivate {
    fn drop(&mut self) {
        // Not a guarantee — the caller may have copied it — but the cost is zero
        // and the alternative is that a seed sits in memory until the allocator
        // reuses the page.
        for byte in self.seed.iter_mut() {
            // A plain write would be a candidate for the optimiser to remove, which
            // is precisely the case that matters.
            // SAFETY: a volatile write through a live `&mut u8`; it cannot be optimised
            // away, which is the entire point.
            unsafe { std::ptr::write_volatile(byte, 0u8) };
        }
    }
}

/// Parse an OpenSSH private key file (`~/.ssh/id_ed25519`), unencrypted only.
///
/// A key whose `cipher` is not `none` is **refused rather than decrypted**: doing
/// that means implementing `bcrypt-pbkdf` plus AES-CTR and, worse, inventing a
/// second answer to "what does a wrong passphrase mean" (the check integers only
/// disagree *after* decryption). The supported paths for a protected key both keep
/// the private half where it already is: `ssh-agent` ([`crate::agent`]), or
/// `ssh-keygen -p` if the owner really wants it unencrypted.
pub fn parse_openssh_private(text: &[u8]) -> Result<OpensshPrivate> {
    let body = strip_armour(text)?;
    if !body.starts_with(OPENSSH_MAGIC) {
        return Err(
            Error::invalid("openssh private key", "missing the `openssh-key-v1` magic").with_hint(
                "this is not an OpenSSH private key file (PEM); a PuTTY `.ppk` or a PKCS#8 file \
             is a different format",
            ),
        );
    }
    let mut reader = WireReader::skipped(&body, OPENSSH_MAGIC.len())?;
    let cipher = reader.string()?;
    let kdf = reader.string()?;
    let _kdf_options = reader.string()?;
    if cipher != b"none" || kdf != b"none" {
        return Err(Error::refused(
            "openssh private key",
            format!(
                "this key is encrypted (cipher `{}`, kdf `{}`)",
                String::from_utf8_lossy(cipher),
                String::from_utf8_lossy(kdf)
            ),
        )
        .with_hint(
            "gitiup does not decrypt OpenSSH key files. Add the key to ssh-agent and use \
             `gitiup key import --ssh-agent`, or re-save it with `ssh-keygen -p` if it \
             really should be unencrypted",
        ));
    }
    let nkeys = reader.u32()?;
    if nkeys != 1 {
        return Err(
            Error::refused("openssh private key", format!("{nkeys} keys in one file")).with_hint(
                "one key per file is what gitiup imports; split them or import one at a time",
            ),
        );
    }
    let public_blob = reader.string()?;
    let private_section = reader.string()?;
    reader.require_end()?;

    let public = PublicKey::from_ssh_blob(public_blob)?;
    let mut private = WireReader::new(private_section);
    let check1 = private.u32()?;
    let check2 = private.u32()?;
    if check1 != check2 {
        return Err(Error::invalid(
            "openssh private key",
            "the two check integers disagree, so the private section is corrupt",
        ));
    }
    let pk = private.string()?;
    let sk = private.string()?;
    if pk.len() != ED25519_PK_BYTES || sk.len() != ED25519_SK_BYTES {
        return Err(Error::new(
            gitiup_attest::ErrorKind::UnsupportedSchema,
            "openssh private key",
            format!(
                "a {}-byte public / {}-byte private pair is not ed25519",
                pk.len(),
                sk.len()
            ),
        )
        .with_hint(
            "only Ed25519 is supported (ADR-0001 D3); make one with `ssh-keygen -t ed25519`",
        ));
    }
    if pk != &public.as_bytes()[..] || sk[ED25519_PK_BYTES..] != pk[..] {
        return Err(Error::invalid(
            "openssh private key",
            "the private section does not match the public blob in the same file",
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..ED25519_PK_BYTES]);
    let comment = String::from_utf8_lossy(private.string()?).to_string();
    Ok(OpensshPrivate {
        public,
        seed,
        comment,
    })
}

/// The base64 payload of a PEM block, armour lines and whitespace removed.
fn strip_armour(text: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(text)
        .map_err(|e| Error::invalid("openssh private key", format!("not UTF-8: {e}")))?;
    let begin = text
        .find(OPENSSH_BEGIN)
        .ok_or_else(|| Error::invalid("openssh private key", "no BEGIN line"))?;
    let rest = &text[begin + OPENSSH_BEGIN.len()..];
    let end = rest
        .find(OPENSSH_END)
        .ok_or_else(|| Error::invalid("openssh private key", "no END line"))?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&body).map_err(|e| {
        Error::invalid(
            "openssh private key",
            format!("the base64 body is not decodable: {}", e.detail()),
        )
    })
}

/// Armour a private key body — the inverse of [`strip_armour`].
///
/// Test-only on purpose. It is the one place this crate can produce an armour, and
/// the tests need it to build real fixtures rather than fixtures shaped like this
/// crate's own assumptions; a non-test caller wanting a plaintext key file should
/// not find one here, and `tests/secret_hygiene.rs` is the thing that keeps it so.
#[cfg(test)]
pub(crate) fn armour(body: &[u8]) -> Vec<u8> {
    let encoded = gitiup_attest::encoding::base64_encode(body);
    let mut out = String::from(OPENSSH_BEGIN);
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(OPENSSH_END);
    out.push('\n');
    out.into_bytes()
}

/// Serialise an unencrypted OpenSSH private key file.
///
/// The one place a plaintext private key is ever produced by this crate, and it is
/// test-only: nothing in the public API writes a plaintext key, and
/// `tests/secret_hygiene.rs` is what keeps that true. If a future ticket adds "move
/// this key out of the keystore", it must call this — one implementation, one place
/// to audit — and must update that test to say where the plaintext may go.
#[cfg(test)]
pub(crate) fn build_openssh_private(seed: &[u8; 32], comment: &str) -> Vec<u8> {
    let key = gitiup_attest::key::SigningKey::from_seed(seed);
    let mut section = Wire::new();
    section.u32(0x5e11_2026);
    section.u32(0x5e11_2026);
    let mut sk = Vec::with_capacity(ED25519_SK_BYTES);
    sk.extend_from_slice(seed);
    sk.extend_from_slice(key.public_key().as_bytes());
    section.string(key.public_key().as_bytes());
    section.string(&sk);
    section.string(comment.as_bytes());
    section.byte(1);

    let mut wire = Wire::new();
    wire.raw(OPENSSH_MAGIC);
    wire.string(b"none");
    wire.string(b"none");
    wire.string(b"");
    wire.u32(1);
    wire.string(&key.public_key().ssh_blob());
    wire.string(section.finish());
    armour(wire.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::key::SigningKey;

    /// A private key file with the check integers made to disagree — corrupt in the
    /// way only a real file can be.
    fn corrupt_checks(text: &[u8]) -> Vec<u8> {
        let mut body = strip_armour(text).unwrap();
        // Walk the header the way the parser does, then flip the *second* check
        // integer inside the private section.
        let mut reader = WireReader::skipped(&body, OPENSSH_MAGIC.len()).unwrap();
        reader.string().unwrap();
        reader.string().unwrap();
        reader.string().unwrap();
        reader.u32().unwrap();
        reader.string().unwrap();
        let section = reader.string().unwrap();
        let section_at = body.len() - section.len() - 4;
        body[section_at + 4] ^= 0xff;
        armour(&body)
    }

    #[test]
    fn reads_a_well_formed_ed25519_key() {
        let seed = [9u8; 32];
        let text = build_openssh_private(&seed, "ada@laptop");
        let parsed = parse_openssh_private(&text).unwrap();
        assert_eq!(parsed.seed, seed);
        assert_eq!(parsed.comment, "ada@laptop");
        assert_eq!(
            parsed.public.key_id(),
            SigningKey::from_seed(&seed).public_key().key_id()
        );
        // `Debug` must not print the seed: that assertion is the whole reason the
        // impl is hand-written rather than derived.
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!format!("{parsed:?}").contains(&hex));
    }

    #[test]
    fn refuses_what_it_will_not_do() {
        // Encrypted: refused, with the two supported ways round.
        let mut wire = Wire::new();
        wire.raw(OPENSSH_MAGIC);
        wire.string(b"aes256-ctr");
        wire.string(b"bcrypt");
        wire.string(b"");
        wire.u32(1);
        wire.string(b"");
        wire.string(b"");
        let error = parse_openssh_private(&armour(wire.finish())).unwrap_err();
        assert_eq!(error.exit_code(), 6);
        assert!(error.to_string().contains("ssh-agent"), "{error}");

        // Not a key at all.
        assert!(parse_openssh_private(b"ssh-ed25519 AAAA comment").is_err());
        assert!(parse_openssh_private(b"-----BEGIN OPENSSH PRIVATE KEY-----\nZZ\n").is_err());
        // Right armour, corrupt private section.
        let text = build_openssh_private(&[2u8; 32], "");
        assert!(parse_openssh_private(&corrupt_checks(&text)).is_err());
    }

    #[test]
    fn the_wire_reader_bounds_every_read() {
        let mut wire = Wire::new();
        wire.u32(7);
        wire.string(b"hello");
        let mut reader = WireReader::new(wire.finish());
        assert_eq!(reader.u32().unwrap(), 7);
        assert_eq!(reader.string().unwrap(), b"hello");
        reader.require_end().unwrap();

        // A length that lies about the end of the message.
        let mut lying = Wire::new();
        lying.u32(9999);
        let mut reader = WireReader::new(lying.finish());
        assert!(reader.string().is_err());

        // A string that stops short: the leftovers are a fault, not a shrug.
        let mut reader = WireReader::new(&[0, 0, 0, 1, 65, 66]);
        assert_eq!(reader.string().unwrap(), b"A");
        assert!(reader.require_end().is_err());

        // And a header longer than the message.
        assert!(WireReader::skipped(&[1, 2], 5).is_err());
    }
}

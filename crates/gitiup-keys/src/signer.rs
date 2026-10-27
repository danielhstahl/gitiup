//! The one signer API: attestation, change record, roster entry, merge record.
//!
//! This module is the seam the ticket is really about. Everything above it — the
//! attestation in `gitiup change submit`, the sign-up in `gitiup participant
//! register`, a roster entry's ownership proof — asks for a
//! [`gitiup_attest::Signer`] and gets one, and cannot tell whether the private half
//! is an age container in a keystore, a key inside an ssh agent, or an
//! authentication subkey in a gpg keyring. That is not incidental tidiness: the
//! moment a caller can tell, it can start *choosing*, and then a signature means
//! "made by whichever backend this code path happened to take" instead of "made by
//! this key".
//!
//! ```text
//! selector ("laptop", "ada@laptop", "SHA256:…,  "0xDEADBEEF" for gpg)
//!     │
//!     ├─ keystore record ──► passphrase ──► SigningKey           Backend::Keystore
//!     ├─ ssh-agent record ─► SSH_AUTH_SOCK ─► agent sign        Backend::SshAgent
//!     └─ gpg record ───────► gpg-agent ssh socket ─► agent sign Backend::Gpg
//! ```
//!
//! [`Key::probe`] is the self-test every acceptance question ends up wanting: *can
//! this key actually sign right now?* It is a real signature, verified on the way
//! back — not a `--dry-run` that checks a file exists and calls that good.

use gitiup_attest::{PublicKey, Signature, SignatureEntry, Signer, SigningKey, TimeUs};

use crate::agent::{Agent, AgentSigner};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::keystore::{Backend, KeyRecord, Keystore};
use crate::passphrase::PassphraseSource;

/// The bytes [`Key::probe`] signs. Fixed, because it proves a capability and records
/// nothing; saying so in the plaintext is so that nobody mistakes it for a claim.
pub const PROBE_MESSAGE: &[u8] =
    b"gitiup key probe: this signature proves a key can sign, nothing else";

/// A key you can sign with right now, whichever backend holds it.
///
/// Deliberately not `Clone`: a clone of a keystore key is a second copy of a
/// decrypted seed in memory, and nothing needs that. Take `&Key` (the `Signer`
/// trait is object-safe and takes `&self`).
pub enum Key {
    /// A keystore key, already decrypted.
    Sealed {
        /// Its public record.
        record: KeyRecord,
        /// The decrypted signing key.
        signing: SigningKey,
    },
    /// A key inside an agent (ssh-agent or gpg-agent — the same protocol).
    ViaAgent {
        /// Its public record.
        record: KeyRecord,
        /// The agent handle that signs.
        signer: AgentSigner,
    },
}

impl Key {
    /// Wrap a decrypted keystore key.
    pub fn sealed(record: KeyRecord, signing: SigningKey) -> Result<Key> {
        record.validate()?;
        if signing.public_key().key_id() != record.key_id {
            return Err(Error::refused(
                "key",
                "the signing key does not match the record it came with",
            ));
        }
        Ok(Key::Sealed { record, signing })
    }

    /// Wrap an agent-backed signer.
    pub fn via_agent(record: KeyRecord, signer: AgentSigner) -> Result<Key> {
        record.validate()?;
        if signer.key_id() != record.key_id {
            return Err(Error::refused(
                "key",
                format!(
                    "the agent offered {} but the record says {}",
                    signer.key_id(),
                    record.key_id
                ),
            ));
        }
        Ok(Key::ViaAgent { record, signer })
    }

    /// The public record behind this key.
    pub fn record(&self) -> &KeyRecord {
        match self {
            Key::Sealed { record, .. } | Key::ViaAgent { record, .. } => record,
        }
    }

    /// Which backend holds the private half.
    pub fn backend(&self) -> Backend {
        self.record().backend
    }

    /// A one-line description for a human: what kind of key, and where.
    pub fn where_about(&self) -> String {
        match self {
            Key::Sealed { record, .. } => format!(
                "keystore, age-encrypted at {}",
                record
                    .secret
                    .as_ref()
                    .map(|secret| secret.file.clone())
                    .unwrap_or_else(|| "<missing>".to_string())
            ),
            Key::ViaAgent { signer, .. } => format!(
                "{}: {} ({})",
                signer.agent().kind(),
                signer.identity().comment(),
                signer.agent().socket().display()
            ),
        }
    }

    /// Sign a fixed message and verify it, to answer "does this key work *now*?".
    ///
    /// Worth its cost (an agent round trip, and for gpg possibly a passphrase or a
    /// touch): it turns "I think my identity is usable" into a checked fact, which
    /// is what a script needs before it goes on to sign something that matters.
    pub fn probe(&self) -> Result<()> {
        let entry = SignatureEntry::new(self, PROBE_MESSAGE)
            .map_err(|e| Error::new(e.kind(), "key probe", e.detail().to_string()))?;
        entry
            .verify(PROBE_MESSAGE)
            .map_err(|e| Error::new(e.kind(), "key probe", e.detail().to_string()))?;
        if entry.key_id != self.key_id() {
            return Err(Error::refused(
                "key probe",
                "the signature's key id is not the key's own",
            ));
        }
        Ok(())
    }
}

impl Signer for Key {
    fn public_key(&self) -> PublicKey {
        match self {
            Key::Sealed { signing, .. } => signing.public_key(),
            Key::ViaAgent { signer, .. } => signer.public_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, gitiup_attest::Error> {
        match self {
            Key::Sealed { signing, .. } => Ok(SigningKey::sign(signing, message)),
            Key::ViaAgent { signer, .. } => signer.sign(message),
        }
    }

    fn key_id(&self) -> String {
        self.record().key_id.clone()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({} @ {})", self.key_id(), self.where_about())
    }
}

/// Open a key by selector: a record name, a key id, or a key-id prefix.
///
/// The passphrase source is consulted only if the record is a keystore one: a key
/// that lives in an agent must not make the user type a passphrase they do not need,
/// and `gitiup` uses that to keep `identity whoami` non-interactive.
pub fn open(keystore: &Keystore, selector: &str, passphrases: &PassphraseSource) -> Result<Key> {
    let record = keystore.find(selector)?;
    open_record(keystore, &record, passphrases)
}

/// Open a key from a record already in hand.
pub fn open_record(
    keystore: &Keystore,
    record: &KeyRecord,
    passphrases: &PassphraseSource,
) -> Result<Key> {
    match record.backend {
        Backend::Keystore => {
            let passphrase = passphrases.read()?;
            let signing = keystore.unlock(record, &passphrase)?;
            Key::sealed(record.clone(), signing)
        }
        Backend::SshAgent => {
            let agent = agent_for(record)?;
            let identity = agent.find(&record.key_id)?;
            Key::via_agent(record.clone(), AgentSigner::new(agent, identity))
        }
        Backend::Gpg => {
            let spec = record
                .gpg
                .as_ref()
                .map(|gpg| gpg.key_spec.clone())
                .ok_or_else(|| {
                    Error::refused("gpg key", format!("'{}' has no gpg key spec", record.name))
                })?;
            Key::via_agent(record.clone(), crate::gpg::signer(&spec)?)
        }
    }
}

/// The agent a record names: `$SSH_AUTH_SOCK` normally, an explicit socket if the
/// record was written with one.
fn agent_for(record: &KeyRecord) -> Result<Agent> {
    let Some(agent) = record.agent.as_ref() else {
        return Err(Error::refused(
            "ssh-agent key",
            format!("'{}' does not name an agent", record.name),
        ));
    };
    if agent.socket == format!("${}", crate::agent::AUTH_SOCK_ENV) {
        return Agent::from_env();
    }
    Ok(Agent::ssh(&agent.socket))
}

/// The key the current identity says to use.
///
/// Resolution order is the config's (`key`, then `key_name`, then `handle`), and a
/// config that names something that no longer exists is a refusal rather than a
/// silent fallback to "whichever key is first": signing with the wrong key is worse
/// than stopping.
pub fn current(
    keystore: &Keystore,
    config: &Config,
    passphrases: &PassphraseSource,
) -> Result<Key> {
    let selector = config.current_key_selector().ok_or_else(|| {
        Error::refused("identity", "no current identity is set")
            .with_hint("`gitiup identity use <handle>` picks one, or name a key: `--key <name>`")
    })?;
    open(keystore, selector, passphrases)
}

/// A clock, in one place, so "when was this claim made" is one decision.
pub fn now_us() -> i64 {
    TimeUs::now().as_us()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use gitiup_attest::Trust;

    #[test]
    fn a_keystore_key_probes_and_signs_like_any_other_signer() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(Paths::with_root(dir.path()));
        let passphrase = age::secrecy::SecretString::from("a passphrase worth eight");
        let record = keystore.generate(&Default::default(), &passphrase).unwrap();
        let key = open(
            &keystore,
            &record.name,
            &PassphraseSource::given("a passphrase worth eight"),
        )
        .unwrap();
        assert_eq!(key.key_id(), record.key_id);
        assert_eq!(key.backend(), Backend::Keystore);
        key.probe().unwrap();
        // And through the format's own record type, which is what attestations use.
        let entry = SignatureEntry::new(&key, b"payload").unwrap();
        assert!(entry.verify(b"payload").is_ok());
        let trust = Trust::KeyIds([record.key_id.clone()].into_iter().collect());
        assert!(trust.trusts(&entry.key_id));
        assert_eq!(
            key.where_about(),
            format!("keystore, age-encrypted at {}.secret.age", record.name)
        );
    }

    #[test]
    fn a_missing_passphrase_source_stops_a_keystore_key_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(Paths::with_root(dir.path()));
        let passphrase = age::secrecy::SecretString::from("a passphrase worth eight");
        let record = keystore.generate(&Default::default(), &passphrase).unwrap();
        let error = open(
            &keystore,
            &record.name,
            &PassphraseSource::scripted().no_env(),
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(error.to_string().contains("passphrase"), "{error}");
    }

    #[test]
    fn no_current_identity_is_a_refusal_with_a_command_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(Paths::with_root(dir.path()));
        let error =
            current(&keystore, &Config::default(), &PassphraseSource::scripted()).unwrap_err();
        assert_eq!(error.exit_code(), 6);
        assert!(error.to_string().contains("identity use"), "{error}");
    }
}

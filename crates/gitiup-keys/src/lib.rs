//! `gitiup-keys` — signing key management: one [`Signer`] API, three places a
//! private key may live, and a signed identity claim to say whose key it is.
//!
//! The premise is ADR-0001's C6: *everyone in the trust story already owns a key, so
//! do not make them carry a second one.* So gitiup does not mint identities. It
//! borrows yours, in the way your machine already knows how to hold a key:
//!
//! | backend | where the private half stays | what gitiup writes |
//!|---------|----------------------------|--------------------|
//!| [`Backend::Keystore`] | `<keys>/<name>.secret.age` — age, scrypt, passphrase required | the encrypted container + a public record |
//!| [`Backend::SshAgent`] | your `ssh-agent`, or a token behind it | a record naming the agent and the key |
//!| [`Backend::Gpg`] | your gpg keyring, via gpg-agent's **ssh** socket | a record naming the gpg key |
//!
//! All three hand back the same [`gitiup_attest::Signer`], and so produce
//! byte-identical signatures: raw Ed25519 over DSSE PAE, keyed by an SSH fingerprint
//! (ADR-0001 D3). There is no per-backend signature format, and that is the property
//! that lets `gitiup verify attestation` (giti-1rs.8) work with no idea who signed or
//! with what.
//!
//! # In one example
//!
//! ```
//! use age::secrecy::{ExposeSecret, SecretString};
//! use gitiup_attest::{SignatureEntry, Trust};
//! use gitiup_keys::identity::{IdentityClaim, Profile};
//! use gitiup_keys::keystore::{Generate, Keystore};
//! use gitiup_keys::paths::Paths;
//! use gitiup_keys::signer;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = tempfile::tempdir()?;
//! let paths = Paths::with_root(dir.path());
//! paths.ensure()?;
//! let store = Keystore::new(paths.clone());
//! let passphrase = SecretString::from("four random words, in order");
//!
//! // A key is generated into the keystore; nothing about it is plaintext.
//! let record = store.generate(
//!     &Generate { name: Some("laptop".into()), ..Default::default() },
//!     &passphrase,
//! )?;
//!
//! // One API, whichever backend holds the key.
//! let key = signer::open(&store, "laptop", &gitiup_keys::passphrase_from(&passphrase))?;
//! let entry = SignatureEntry::new(&key, b"pae bytes")?;
//! assert_eq!(entry.key_id, record.key_id);
//! entry.verify(b"pae bytes")?;
//!
//! // And an identity claim: key id, name, and the owner's self-signature.
//! let profile = Profile {
//!     handle: "ada".into(),
//!     display_name: "Ada Lovelace".into(),
//!     email: None,
//!     url: None,
//!     annotations: Default::default(),
//! };
//! let claim = IdentityClaim::new(&key, &profile, 1_793_092_600_000_000)?;
//! let verified = claim.verify(&Trust::KeyIds(
//!     [record.key_id.clone()].into_iter().collect(),
//! ))?;
//! assert!(verified.self_trusted);
//! # Ok(()) }
//! ```
//!
//! # What is *not* here
//!
//! * **the format of what gets signed** — `gitiup-attest` owns that, and this crate
//!   only ever implements its [`Signer`] trait;
//! * **storage of records** — `gitiup-host` owns refs and a content-addressed store.
//!   This crate writes a handful of files in one configuration directory, and the
//!   published claim is *meant* to be copied somewhere public;
//! * **trust** — who believes which key is `gitiup_attest::Trust`, supplied by the
//!   caller. Nothing here has an opinion of its own, and `verify` refuses with an
//!   empty trust list rather than accepting by default;
//! * **a network** — the ssh-agent protocol is a unix socket and gpg is a child
//!   process. Signing works on a plane.
//!
//! # The rule the tests enforce
//!
//! Private key material is never written outside the encrypted keystore. Not by
//! import, not by a public-only record, not by a log line (`Debug` impls redact), and
//! not by a temp file: `tests/secret_hygiene.rs` generates a key, then walks the
//! entire directory tree looking for the seed in *every* file — including the
//! encrypted one, where it must not appear either.

#![doc(issue_tracker_base_url = "https://github.com/gitiup/gitiup/issues/")]

use age::secrecy::ExposeSecret;

pub mod agent;
pub mod config;
pub mod error;
pub mod gpg;
pub mod identity;
pub mod keystore;
pub mod passphrase;
pub mod paths;
pub mod record;
pub mod signer;
pub mod ssh;

pub use agent::{Agent, AgentSigner, Identity as AgentIdentity};
pub use config::Config;
pub use error::{Error, Result};
pub use identity::{Endorsement, IdentityClaim, Profile};
pub use keystore::{Backend, Generate, Import, KeyRecord, Keystore};
pub use passphrase::{PASSPHRASE_ENV, PassphraseSource, SecretString, no_passphrase};
pub use paths::Paths;
pub use signer::Key;

/// Re-exported so a caller can implement [`gitiup_attest::Signer`] without naming a
/// second crate in its dependency list.
pub use gitiup_attest::{PublicKey, Signature, SignatureEntry, Signer, SigningKey};

/// A [`PassphraseSource`] for a passphrase already in hand.
///
/// Lives here because the example in these docs reads better with it than the
/// equivalent two lines at the call site.
pub fn passphrase_from(passphrase: &SecretString) -> PassphraseSource {
    PassphraseSource::given(passphrase.expose_secret())
}

/// The things a caller uses constantly, in one import.
///
/// ```
/// use gitiup_keys::prelude::*;
/// let backend = Backend::Keystore;
/// assert_eq!(backend.as_str(), "keystore");
/// ```
pub mod prelude {
    pub use crate::agent::{Agent, AgentSigner};
    pub use crate::config::Config;
    pub use crate::error::Error;
    pub use crate::identity::{Endorsement, IdentityClaim, Profile};
    pub use crate::keystore::{Backend, Generate, Import, KeyRecord, Keystore};
    pub use crate::passphrase::PassphraseSource;
    pub use crate::passphrase_from;
    pub use crate::paths::Paths;
    pub use crate::signer::Key;
    pub use age::secrecy::{ExposeSecret, SecretString};
    pub use gitiup_attest::{SignatureEntry, Signer, Trust};
}

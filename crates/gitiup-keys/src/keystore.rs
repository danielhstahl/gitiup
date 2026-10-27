//! The keystore: one directory, age-encrypted secrets, and public records that say
//! where the private half actually is.
//!
//! A key in gitiup is a *record* (`<name>.json`) plus — only for a generated key —
//! an encrypted container (`<name>.secret.age`). The record holds nothing secret:
//! key id, public key, when it was made, and which backend can sign with it. That
//! split is what makes the acceptance criterion testable:
//!
//! > private key material is never written outside the encrypted keystore
//!
//! — because there is exactly one writer of secret bytes ([`write_secret`]), it
//! takes a passphrase, and every file it produces is checked to start with the age
//! armour header. `tests/secret_hygiene.rs` walks a whole configuration tree and
//! fails if the seed appears in *any* file, including the encrypted one.
//!
//! Three backends, one record type:
//!
//! | backend | where the private half lives | what the record holds |
//!|---------|------------------------------|-----------------------|
//!| [`Backend::Keystore`] | `<name>.secret.age`, scrypt + age, passphrase-required | a pointer to that file |
//!| [`Backend::SshAgent`] | the running ssh-agent, or a token behind it | the socket and the agent comment |
//!| [`Backend::Gpg`] | the gpg keyring, reached through gpg-agent's ssh socket | the gpg key spec and keygrips |
//!
//! The last two never have a secret file at all — importing an ssh or gpg key
//! records *where to ask*, which is the whole point of C6 in ADR-0001: nobody is
//! asked to carry a second copy of a key they already own.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use gitiup_attest::encoding::{hex_decode, hex_encode};
use gitiup_attest::{ErrorKind, PublicKey, SigningKey, TimeUs};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::{Paths, is_slug, slugify};

/// The record format version this crate writes.
pub const RECORD_VERSION: u32 = 1;
/// The version of the plaintext inside an encrypted container.
pub const SECRET_VERSION: u32 = 1;
/// The age armour header a secret file must start with.
pub const AGE_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// Suffix of an encrypted container.
pub const SECRET_SUFFIX: &str = "secret.age";
/// Suffix of a public record.
pub const RECORD_SUFFIX: &str = "json";
/// Refuse absurdly large inputs rather than buffer them.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Which backend holds the private half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// A generated key, encrypted in this keystore with a passphrase.
    Keystore,
    /// An existing ssh key: the agent signs, the key never moves.
    SshAgent,
    /// An existing gpg key (with an `auth` subkey), via gpg-agent's ssh socket.
    Gpg,
}

impl Backend {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Keystore => "keystore",
            Backend::SshAgent => "ssh-agent",
            Backend::Gpg => "gpg",
        }
    }
}

/// A pointer to the encrypted container. Nothing here is secret; the file name is
/// deliberately awkward (`<name>.secret.age`) so that a careless `cp *` says what it
/// is copying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// File name, relative to the keystore directory — a name, never a path, so a
    /// record cannot point outside the keystore.
    pub file: String,
    /// `age-armor`: passphrase-based age, ASCII-armoured.
    pub format: String,
    /// `scrypt`, as recorded in the age header.
    pub kdf: String,
}

/// A pointer to an ssh-agent identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRef {
    /// `$SSH_AUTH_SOCK` (the usual case: whatever agent the user already has) or an
    /// absolute socket path.
    pub socket: String,
    /// The agent's comment for the key, used only as a label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A pointer to a gpg key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpgRef {
    /// What to hand `gpg --export-ssh-key`: a fingerprint or user id.
    pub key_spec: String,
    /// The keygrips listed in gpg-agent's `sshcontrol`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keygrips: Vec<String>,
}

/// One key's public record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    /// Record format version ([`RECORD_VERSION`]).
    pub version: u32,
    /// The name in the file name: a slug, unique in the keystore.
    pub name: String,
    /// `SHA256:<unpadded base64>` — **derived** from `public_key` and checked on
    /// read, never trusted (ADR-0001 D3).
    pub key_id: String,
    /// The OpenSSH public-key line.
    pub public_key: String,
    /// Who can sign with it.
    pub backend: Backend,
    /// When this record was created, in microseconds since the epoch.
    pub created_at_us: i64,
    /// A human label (`ada@laptop`), display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Set only for [`Backend::Keystore`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRef>,
    /// Set only for [`Backend::SshAgent`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentRef>,
    /// Set only for [`Backend::Gpg`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg: Option<GpgRef>,
}

impl KeyRecord {
    /// Parse and check the record's own consistency.
    ///
    /// The important check is the boring one: `key_id` must be the fingerprint of
    /// `public_key`. A record that could claim a different key id than the key it
    /// carries is a record that turns a filename into an identity forgery.
    pub fn validate(&self) -> Result<()> {
        if self.version != RECORD_VERSION {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "key record",
                format!("version {} is not version {RECORD_VERSION}", self.version),
            ));
        }
        if !is_slug(&self.name) {
            return Err(Error::invalid(
                "key record",
                format!("'{}' is not a key name", self.name),
            ));
        }
        let public = self.public_key()?;
        if public.key_id() != self.key_id {
            return Err(Error::new(
                ErrorKind::Signature,
                "key record",
                format!(
                    "key id '{}' is not the fingerprint of the key in this record ({})",
                    self.key_id,
                    public.key_id()
                ),
            )
            .with_hint(
                "the key id is derived, not declared: edit the record's `public_key`, \
                        not its `key_id`, or delete the record and import the key again",
            ));
        }
        match self.backend {
            Backend::Keystore if self.secret.is_none() => return Err(self.incomplete()),
            Backend::SshAgent if self.agent.is_none() => return Err(self.incomplete()),
            Backend::Gpg if self.gpg.is_none() => return Err(self.incomplete()),
            _ => {}
        }
        if self.secret.is_some() && self.backend != Backend::Keystore {
            return Err(Error::invalid(
                "key record",
                format!(
                    "a `{}` record must not point at a secret file",
                    self.backend.as_str()
                ),
            ));
        }
        if self.secret.is_some() && self.agent.is_some() {
            return Err(Error::invalid(
                "key record",
                "a record cannot point at both a secret file and an agent",
            ));
        }
        if self.agent.is_some() && self.gpg.is_some() {
            return Err(Error::invalid(
                "key record",
                "a record cannot point at both an ssh agent and a gpg key",
            ));
        }
        Ok(())
    }

    fn incomplete(&self) -> Error {
        Error::invalid(
            "key record",
            format!(
                "a `{}` record must say where the private half is",
                self.backend.as_str()
            ),
        )
    }

    /// The parsed public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_openssh(&self.public_key)
            .map_err(|e| Error::new(e.kind(), "key record", e.detail().to_string()))
    }

    /// The `ssh-ed25519 AAAA…` line, which is what a user is asked to paste
    /// somewhere else.
    pub fn ssh_line(&self) -> String {
        match &self.comment {
            Some(comment) if !comment.is_empty() => format!("{} {comment}", self.public_key),
            _ => self.public_key.clone(),
        }
    }
}

/// What `generate` was asked for.
#[derive(Debug, Clone, Default)]
pub struct Generate {
    /// The name to give the key; derived from the comment, or `key-N`, if absent.
    pub name: Option<String>,
    /// A label for the record.
    pub comment: Option<String>,
    /// Replace an existing record of the same name.
    ///
    /// A *record* is replaced, never a secret file that belongs to another key: a
    /// seed is destroyed only when the record that points at it is destroyed too.
    pub force: bool,
    /// A caller-supplied seed. Used by import (an OpenSSH key moved into the
    /// keystore is the same key, not a new one), and by the tests, which is why it
    /// is an array of bytes rather than a string anyone could type into a shell and
    /// leak through `ps`.
    pub seed: Option<[u8; 32]>,
}

/// What `import` was asked for.
#[derive(Debug, Clone)]
pub enum Import {
    /// An unencrypted OpenSSH private key file: the seed moves into the keystore.
    Openssh {
        /// The file to read.
        path: PathBuf,
    },
    /// A raw 32-byte seed, read from a file or stdin (`-`). For scripts that
    /// generate a key elsewhere; never on the command line, where `ps` would see it.
    Seed {
        /// Path, or `-` for stdin.
        path: PathBuf,
    },
    /// A key already in the running ssh-agent: no private material is read at all.
    SshAgent {
        /// Key id, prefix or agent comment; `None` means "the agent's only key".
        selector: Option<String>,
        /// An agent socket to use instead of `$SSH_AUTH_SOCK` — for a key held by an
        /// agent other than the one this shell points at, and the only way to import
        /// from an agent in a test.
        socket: Option<PathBuf>,
    },
    /// A gpg key, offered by gpg-agent's ssh socket.
    Gpg {
        /// The gpg key specification.
        key_spec: String,
    },
}

/// The keystore itself: a directory and the rules for it.
#[derive(Debug, Clone)]
pub struct Keystore {
    paths: Paths,
}

impl Keystore {
    /// Open a keystore at `paths` (nothing is created until a write happens).
    pub fn new(paths: Paths) -> Keystore {
        Keystore { paths }
    }

    /// The directory layout in use.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Generate a new key: 32 bytes from the OS CSPRNG, encrypted with `passphrase`.
    ///
    /// There is no code path that writes a seed unencrypted, and no way to ask for
    /// one: a passphrase is a parameter, not a prompt the caller can decline.
    pub fn generate(&self, request: &Generate, passphrase: &SecretString) -> Result<KeyRecord> {
        check_passphrase(passphrase)?;
        let seed = match request.seed {
            Some(seed) => seed,
            None => random_seed()?,
        };
        let signing = SigningKey::from_seed(&seed);
        self.check_not_already_present(&signing.public_key().key_id(), request.force)?;
        let name = self.unique_name(
            request.name.as_deref(),
            request.comment.as_deref(),
            request.force,
        )?;
        self.clear_for_force(&name, request.force)?;
        let record = self.seal_record(&name, &signing, request.comment.clone())?;
        self.write_secret(
            &format!("{name}.{SECRET_SUFFIX}"),
            &seed,
            request.comment.as_deref(),
            passphrase,
        )?;
        self.write_record(&record, request.force)?;
        Ok(record)
    }

    /// Import an existing key.
    pub fn import(
        &self,
        import: &Import,
        name: Option<&str>,
        passphrase: &SecretString,
        force: bool,
    ) -> Result<Imported> {
        match import {
            Import::Openssh { path } => {
                check_passphrase(passphrase)?;
                let text = std::fs::read(path)
                    .map_err(|e| Error::io("read key file", format!("{}: {e}", path.display())))?;
                let parsed = crate::ssh::parse_openssh_private(&text)?;
                self.check_not_already_present(
                    &SigningKey::from_seed(&parsed.seed).public_key().key_id(),
                    force,
                )?;
                let name = self.unique_name(name, Some(&parsed.comment), force)?;
                let comment = (!parsed.comment.is_empty()).then(|| parsed.comment.clone());
                self.clear_for_force(&name, force)?;
                let record =
                    self.seal_record(&name, &SigningKey::from_seed(&parsed.seed), comment)?;
                self.write_secret(
                    &format!("{name}.{SECRET_SUFFIX}"),
                    &parsed.seed,
                    Some("imported from an OpenSSH key file"),
                    passphrase,
                )?;
                self.write_record(&record, force)?;
                Ok(Imported {
                    record,
                    moved: true,
                    notes: vec![
                        "the original key file was not modified or deleted: it still works, \
                         and now has a second copy in the keystore"
                            .to_string(),
                    ],
                })
            }
            Import::Seed { path } => {
                check_passphrase(passphrase)?;
                let seed = read_seed_file(path)?;
                let signing = SigningKey::from_seed(&seed);
                self.check_not_already_present(
                    &SigningKey::from_seed(&seed).public_key().key_id(),
                    force,
                )?;
                let name = self.unique_name(name, None, force)?;
                self.clear_for_force(&name, force)?;
                let record = self.seal_record(&name, &signing, None)?;
                self.write_secret(&format!("{name}.{SECRET_SUFFIX}"), &seed, None, passphrase)?;
                self.write_record(&record, force)?;
                Ok(Imported {
                    record,
                    moved: true,
                    notes: Vec::new(),
                })
            }
            Import::SshAgent { selector, socket } => {
                let (agent, socket_name) = match socket {
                    Some(path) => (
                        crate::agent::Agent::ssh(path),
                        path.to_string_lossy().into_owned(),
                    ),
                    None => (
                        crate::agent::Agent::from_env()?,
                        format!("${}", crate::agent::AUTH_SOCK_ENV),
                    ),
                };
                let selector = selector.clone().unwrap_or_default();
                let identity = if selector.is_empty() {
                    let identities = agent.identities()?;
                    match identities.len() {
                        1 => identities.into_iter().next().expect("one identity"),
                        0 => {
                            return Err(Error::unreachable("ssh-agent", "the agent holds no keys")
                                .with_hint("`ssh-add <path>` adds one, or name the key you mean"));
                        }
                        n => {
                            return Err(Error::refused(
                                "key selection",
                                format!("the agent holds {n} keys"),
                            )
                            .with_hint(
                                "name one: `gitiup key import --ssh-agent <key-id-or-comment>`",
                            ));
                        }
                    }
                } else {
                    agent.find(&selector)?
                };
                let public = identity.public_key()?;
                self.check_not_already_present(&public.key_id(), force)?;
                let name = self.unique_name(name, Some(identity.comment()), force)?;
                self.clear_for_force(&name, force)?;
                let record = KeyRecord {
                    version: RECORD_VERSION,
                    name,
                    key_id: public.key_id(),
                    public_key: public.to_openssh(),
                    backend: Backend::SshAgent,
                    created_at_us: TimeUs::now().as_us(),
                    comment: (!identity.comment().is_empty())
                        .then(|| identity.comment().to_string()),
                    secret: None,
                    agent: Some(AgentRef {
                        socket: socket_name,
                        comment: (!identity.comment().is_empty())
                            .then(|| identity.comment().to_string()),
                    }),
                    gpg: None,
                };
                record.validate()?;
                self.write_record(&record, force)?;
                Ok(Imported {
                    record,
                    moved: false,
                    notes: vec![
                        "no private key material was read: the agent keeps signing with the \
                         key it already holds"
                            .to_string(),
                    ],
                })
            }
            Import::Gpg { key_spec } => {
                let (public, _) = crate::gpg::ssh_public_key(key_spec)?;
                // gpg-agent will not sign with a key that is not in `sshcontrol`, so
                // importing a key that could never sign would be a trap set for later.
                // Doing it here is also the honest place: this is the command that
                // decides "this key is one gitiup signs with".
                let keygrips = crate::gpg::ensure_offered(key_spec)?;
                let offered = keygrips.len();
                self.check_not_already_present(&public.key_id(), force)?;
                let name = self.unique_name(name, Some(key_spec), force)?;
                self.clear_for_force(&name, force)?;
                let record = KeyRecord {
                    version: RECORD_VERSION,
                    name,
                    key_id: public.key_id(),
                    public_key: public.to_openssh(),
                    backend: Backend::Gpg,
                    created_at_us: TimeUs::now().as_us(),
                    comment: Some(key_spec.clone()),
                    secret: None,
                    agent: None,
                    gpg: Some(GpgRef {
                        key_spec: key_spec.clone(),
                        keygrips,
                    }),
                };
                record.validate()?;
                self.write_record(&record, force)?;
                Ok(Imported {
                    record,
                    moved: false,
                    notes: vec![
                        "gpg keeps the key: signing goes through gpg-agent's ssh socket, so \
                         the signature is the same shape as every other gitiup signature"
                            .to_string(),
                        format!("{offered} keygrip(s) were listed in gpg-agent's sshcontrol"),
                    ],
                })
            }
        }
    }

    /// Every record in the keystore, by name.
    pub fn list(&self) -> Result<Vec<KeyRecord>> {
        let dir = self.paths.keys_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(Error::io(
                    "read keystore",
                    format!("{}: {error}", dir.display()),
                ));
            }
        };
        let mut records = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == RECORD_SUFFIX) {
                records.push(self.read_record(&path)?);
            }
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    /// Find one key by name, key id, or key-id prefix (at least four characters of
    /// the fingerprint body).
    pub fn find(&self, selector: &str) -> Result<KeyRecord> {
        let records = self.list()?;
        let matches: Vec<KeyRecord> = records
            .into_iter()
            .filter(|record| record_matches(record, selector))
            .collect();
        match matches.len() {
            0 => Err(Error::not_found("key", format!("'{selector}'"))
                .with_hint("`gitiup key list` shows what this keystore holds")),
            1 => Ok(matches.into_iter().next().expect("one match")),
            n => Err(Error::refused(
                "key selection",
                format!(
                    "'{selector}' matches {n} keys: {}",
                    matches
                        .iter()
                        .map(|r| format!("{} ({})", r.name, r.key_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .with_hint("use a key name or a whole key id")),
        }
    }

    /// Decrypt a record's container and return the signing key.
    ///
    /// Only meaningful for a [`Backend::Keystore`] record: asking for the secret of
    /// a key that lives in an agent is a confusion this refuses rather than papers
    /// over, because the caller would then believe it holds a key it cannot hold.
    pub fn unlock(&self, record: &KeyRecord, passphrase: &SecretString) -> Result<SigningKey> {
        let secret = record.secret.as_ref().ok_or_else(|| {
            Error::refused(
                "unlock",
                format!(
                    "'{}' is a `{}` key: its private half is not in this keystore",
                    record.name,
                    record.backend.as_str()
                ),
            )
            .with_hint(match record.backend {
                Backend::SshAgent => "sign with it directly: the agent is the keystore".to_string(),
                Backend::Gpg => "sign with it directly: gpg-agent is the keystore".to_string(),
                Backend::Keystore => "this record has no secret file".to_string(),
            })
        })?;
        if secret.format != "age-armor" || secret.kdf != "scrypt" {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "keystore",
                format!(
                    "{} declares format `{}` / kdf `{}`",
                    secret.file, secret.format, secret.kdf
                ),
            ));
        }
        let path = self.secret_path(&secret.file)?;
        let bytes = std::fs::read(&path)
            .map_err(|error| Error::io("read secret", format!("{}: {error}", path.display())))?;
        let plaintext = age_open(passphrase, &bytes, &path)?;
        let secret: SecretFile = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::invalid("secret file", format!("{}: {e}", path.display())))?;
        if secret.version != SECRET_VERSION || secret.kind != "ed25519-seed" {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "secret file",
                format!(
                    "{} is version {} of `{}`",
                    path.display(),
                    secret.version,
                    secret.kind
                ),
            ));
        }
        let raw = hex_decode(&secret.seed).map_err(|e| {
            Error::invalid("secret file", format!("{}: {}", path.display(), e.detail()))
        })?;
        let seed: [u8; 32] = raw.try_into().map_err(|_| {
            Error::invalid(
                "secret file",
                format!("{}: an ed25519 seed is 32 bytes", path.display()),
            )
        })?;
        let signing = SigningKey::from_seed(&seed);
        // The last line of defence before a key is handed back: the container must
        // contain the key the record claims it contains.
        if signing.public_key().key_id() != record.key_id {
            return Err(Error::new(
                ErrorKind::Signature,
                "keystore",
                format!(
                    "{} decrypts to {}, but the record says {}",
                    path.display(),
                    signing.public_key().key_id(),
                    record.key_id
                ),
            )
            .with_hint(
                "the container and the record disagree; do not sign with either until \
                        you know which one was edited",
            ));
        }
        Ok(signing)
    }

    /// Delete a record and, if it has one, its container.
    ///
    /// Both files go together or neither does: a secret with no record is an orphan
    /// nobody can account for, and a record with no secret is a key that cannot sign.
    pub fn remove(&self, selector: &str) -> Result<Removed> {
        let record = self.find(selector)?;
        let record_path = self.record_path(&record.name);
        let secret_path = match &record.secret {
            Some(secret) => Some(self.secret_path(&secret.file)?),
            None => None,
        };
        if let Some(path) = &secret_path {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Error::io(
                        "remove secret",
                        format!("{}: {error}", path.display()),
                    ));
                }
            }
        }
        std::fs::remove_file(&record_path).map_err(|error| {
            Error::io(
                "remove record",
                format!("{}: {error}", record_path.display()),
            )
        })?;
        Ok(Removed {
            name: record.name,
            key_id: record.key_id,
            backend: record.backend,
            secret_removed: secret_path.is_some(),
        })
    }

    /// The public key line for a selector, without touching the secret.
    pub fn export_public(&self, selector: &str) -> Result<String> {
        Ok(self.find(selector)?.ssh_line())
    }

    fn seal_record(
        &self,
        name: &str,
        signing: &SigningKey,
        comment: Option<String>,
    ) -> Result<KeyRecord> {
        let public = signing.public_key();
        let record = KeyRecord {
            version: RECORD_VERSION,
            name: name.to_string(),
            key_id: public.key_id(),
            public_key: public.to_openssh(),
            backend: Backend::Keystore,
            created_at_us: TimeUs::now().as_us(),
            comment,
            secret: Some(SecretRef {
                file: format!("{name}.{SECRET_SUFFIX}"),
                format: "age-armor".to_string(),
                kdf: "scrypt".to_string(),
            }),
            agent: None,
            gpg: None,
        };
        record.validate()?;
        Ok(record)
    }

    /// Choose a name: the caller's, else the comment's, else `key-N`.
    /// Refuse to add a second record for a key this store already holds.
    ///
    /// Worth a check because it is so easy to do by accident — importing the same
    /// seed twice, or importing a key that was already moved in — and two records for
    /// one key is what makes `--key <key-id>` stop meaning one thing. `find` would
    /// already refuse the ambiguity with a list; refusing at import time is the
    /// earlier and kinder version of the same message.
    fn check_not_already_present(&self, key_id: &str, force: bool) -> Result<()> {
        if force {
            return Ok(());
        }
        if let Some(existing) = self
            .list()?
            .into_iter()
            .find(|record| record.key_id == key_id)
        {
            return Err(Error::refused(
                "key import",
                format!("this key is already in the keystore as '{}'", existing.name),
            )
            .with_hint("two records for one key means a key id no longer names one thing"));
        }
        Ok(())
    }

    /// Carry out a `--force` replacement: the old record and its container go first.
    ///
    /// Deliberately a removal and not an overwrite. `write_secret` refuses to replace
    /// a container in place (a half-written secret file is the worst thing this code
    /// could produce), and a key is two files: replacing one and not the other would
    /// leave a record pointing at a seed that no longer matches it. Removing both
    /// first means a forced replacement is one atomic-ish act instead of a mix.
    fn clear_for_force(&self, name: &str, force: bool) -> Result<()> {
        if force && self.record_path(name).exists() {
            self.remove(name)?;
        }
        Ok(())
    }

    fn unique_name(
        &self,
        name: Option<&str>,
        comment: Option<&str>,
        force: bool,
    ) -> Result<String> {
        if let Some(name) = name {
            let slug = slugify(name)?;
            if self.record_path(&slug).exists() && !force {
                return Err(Error::refused(
                    "key name",
                    format!("'{}' already exists in this keystore", slug),
                )
                .with_hint("choose another name, or say `--force` to replace it"));
            }
            return Ok(slug);
        }
        if let Some(comment) = comment.filter(|c| !c.trim().is_empty())
            && let Ok(slug) = slugify(comment)
            && !self.record_path(&slug).exists()
        {
            return Ok(slug);
        }
        let taken: Vec<String> = self.list()?.into_iter().map(|record| record.name).collect();
        for index in 1..=9999usize {
            let candidate = format!("key-{index}");
            if !taken.contains(&candidate) {
                return Ok(candidate);
            }
        }
        Err(Error::refused(
            "key name",
            "the keystore is full in the only way this code counts",
        ))
    }

    /// Record a key whose private half stays where it is (an agent or gpg key).
    ///
    /// Public because the caller may have discovered the key itself — through an
    /// agent it was handed, or a smartcard reader — and because writing the record is
    /// the same four lines whichever discovery path got here. Validation is not
    /// skipped: a record that would not read back is not written.
    pub fn register(&self, record: &KeyRecord, force: bool) -> Result<()> {
        if record.secret.is_some() {
            return Err(Error::refused(
                "keystore",
                "a record with a secret file must come from `generate` or `import`, which \
                 are the only paths that encrypt the seed",
            ));
        }
        record.validate()?;
        self.clear_for_force(&record.name, force)?;
        self.write_record(record, force)
    }

    /// The path a record name maps to.
    pub fn record_path(&self, name: &str) -> PathBuf {
        self.paths
            .keys_dir()
            .join(format!("{name}.{RECORD_SUFFIX}"))
    }

    /// The path a secret file name maps to, refusing anything that would escape the
    /// keystore directory.
    pub fn secret_path(&self, file: &str) -> Result<PathBuf> {
        if file.is_empty()
            || file.contains('/')
            || file.contains('\\')
            || file.contains("..")
            || file.starts_with('.')
        {
            return Err(Error::invalid(
                "keystore",
                format!("secret file '{file}' must be a plain name inside the keystore"),
            ));
        }
        Ok(self.paths.keys_dir().join(file))
    }

    fn read_record(&self, path: &Path) -> Result<KeyRecord> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::io("read key record", format!("{}: {e}", path.display())))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::refused(
                "key record",
                format!("{} is {} bytes", path.display(), bytes.len()),
            ));
        }
        let record: KeyRecord = serde_json::from_slice(&bytes)
            .map_err(|e| Error::invalid("key record", format!("{}: {e}", path.display())))?;
        record.validate().map_err(|e| {
            Error::refused("key record", format!("{}: {}", path.display(), e.detail())).with_hint(
                "a record is read-only metadata; if the key it describes changed, remove it \
                 and import the key again",
            )
        })?;
        Ok(record)
    }

    fn write_record(&self, record: &KeyRecord, force: bool) -> Result<()> {
        self.paths.ensure()?;
        record.validate()?;
        let path = self.record_path(&record.name);
        if path.exists() && !force {
            return Err(
                Error::refused("key record", format!("{} already exists", path.display()))
                    .with_hint("`--force` replaces it"),
            );
        }
        let text = serde_json::to_string_pretty(record)
            .map_err(|e| Error::io("encode key record", e.to_string()))?;
        // The record is public, so ordinary permissions; it is pretty-printed
        // because `cat ~/.config/gitiup/keys/laptop.json` is how people read it, and
        // it is not a signed document (only signed records are canonical).
        write_private_atomically(&path, text.as_bytes(), 0o600)?;
        Ok(())
    }

    /// The only place private material is written.
    fn write_secret(
        &self,
        file: &str,
        seed: &[u8; 32],
        comment: Option<&str>,
        passphrase: &SecretString,
    ) -> Result<()> {
        let plaintext = serde_json::to_vec(&SecretFile {
            version: SECRET_VERSION,
            kind: "ed25519-seed".to_string(),
            seed: hex_encode(seed),
            comment: comment.map(str::to_string),
        })
        .map_err(|e| Error::io("encode secret", e.to_string()))?;
        self.seal(file, &plaintext, passphrase)
    }

    /// Encrypt `plaintext` with `passphrase` and write it to `file`, `0600`.
    fn seal(&self, file: &str, plaintext: &[u8], passphrase: &SecretString) -> Result<()> {
        self.paths.ensure()?;
        let path = self.secret_path(file)?;
        if path.exists() {
            return Err(
                Error::refused("keystore", format!("{} already exists", path.display()))
                    .with_hint("a secret file is never overwritten in place: remove the key first"),
            );
        }
        let sealed = age_seal(passphrase, plaintext);
        let text = String::from_utf8(sealed).expect("age armour is ASCII");
        if !text.starts_with(AGE_HEADER) {
            return Err(Error::io(
                "keystore",
                "the encrypted output does not carry the age armour header",
            ));
        }
        write_private_atomically(&path, text.as_bytes(), 0o600)
    }
}

/// What `import` did.
#[derive(Debug, Clone)]
pub struct Imported {
    /// The record written.
    pub record: KeyRecord,
    /// Whether private material was read and re-encrypted (a seed or an OpenSSH
    /// file), as opposed to a key that stayed where it was.
    pub moved: bool,
    /// Anything the operator should know: what was touched, and what was not.
    pub notes: Vec<String>,
}

/// What `remove` did.
#[derive(Debug, Clone)]
pub struct Removed {
    /// The record's name.
    pub name: String,
    /// The key id it carried.
    pub key_id: String,
    /// Which backend held the private half.
    pub backend: Backend,
    /// Whether an encrypted container was deleted with it.
    pub secret_removed: bool,
}

/// The plaintext inside a container.
#[derive(Debug, Serialize, Deserialize)]
struct SecretFile {
    version: u32,
    /// Discriminator, so a container that is not a seed is not silently misread.
    #[serde(rename = "type")]
    kind: String,
    /// The seed, hex.
    seed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

/// A passphrase short enough to be a bad idea, said out loud.
fn check_passphrase(passphrase: &SecretString) -> Result<()> {
    let length = passphrase.expose_secret().chars().count();
    if length < 8 {
        return Err(Error::refused(
            "passphrase",
            format!("{length} characters is not a passphrase"),
        )
        .with_hint(
            "age uses scrypt, so a long passphrase costs nothing at runtime; four random words \
             is the shortest thing worth protecting a signing key with",
        ));
    }
    Ok(())
}

fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| Error::io("random seed", format!("the operating system said no: {e}")))?;
    Ok(seed)
}

fn read_seed_file(path: &Path) -> Result<[u8; 32]> {
    let bytes = if path == Path::new("-") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer)
            .map_err(|e| Error::io("read seed from stdin", e.to_string()))?;
        buffer
    } else {
        std::fs::read(path)
            .map_err(|e| Error::io("read seed file", format!("{}: {e}", path.display())))?
    };
    let text: String = bytes
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| *b as char)
        .collect();
    let raw = hex_decode(&text)
        .map_err(|e| Error::invalid("seed file", format!("{}: {}", path.display(), e.detail())))?;
    let length = raw.len();
    raw.try_into().map_err(|_| {
        Error::invalid(
            "seed file",
            format!(
                "{} holds {length} bytes; an ed25519 seed is 32",
                path.display()
            ),
        )
    })
}

/// age-encrypt with a passphrase (scrypt), ASCII-armoured.
pub fn age_seal(passphrase: &SecretString, plaintext: &[u8]) -> Vec<u8> {
    use age::armor::{ArmoredWriter, Format};
    let encryptor = age::Encryptor::with_user_passphrase(clone_secret(passphrase));
    let mut output = Vec::new();
    let armored = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
        .expect("in-memory armouring cannot fail");
    let mut writer = encryptor
        .wrap_output(armored)
        .expect("in-memory encryption cannot fail");
    writer
        .write_all(plaintext)
        .expect("in-memory encryption cannot fail");
    writer
        .finish()
        .and_then(|armored| armored.finish())
        .expect("in-memory encryption cannot fail");
    output
}

/// age-decrypt with a passphrase.
///
/// A wrong passphrase is a refusal (`6`) with the one hint that matters: an age
/// container gives no other signal, so "which passphrase did I use" is the question
/// to answer, and quietly deleting a container that "looks corrupt" is not.
pub fn age_open(passphrase: &SecretString, sealed: &[u8], path: &Path) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(sealed);
    if !text.starts_with(AGE_HEADER) {
        return Err(Error::refused(
            "keystore",
            format!("{} is not an age container", path.display()),
        )
        .with_hint(
            "gitiup refuses a plaintext secret file on purpose: if you have an unencrypted key \
             you want in the keystore, `gitiup key import --openssh <path>`",
        ));
    }
    // `ArmoredReader` is what makes an armoured container readable: without it the
    // armour text is fed to the binary header parser and the failure is
    // "Header is invalid", which looks like corruption and is not.
    let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(sealed))
        .map_err(|e| Error::invalid("keystore", format!("{}: {e}", path.display())))?;
    let identity = age::scrypt::Identity::new(clone_secret(passphrase));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| {
            Error::refused("keystore", format!("{}: {e}", path.display())).with_hint(
                "this is what a wrong passphrase looks like: the container gives no other \
                 signal, and the key is unrecoverable without it",
            )
        })?;
    let mut plaintext = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut plaintext)
        .map_err(|e| Error::io("decrypt secret", e.to_string()))?;
    Ok(plaintext)
}

fn clone_secret(secret: &SecretString) -> SecretString {
    SecretString::from(secret.expose_secret().to_string())
}

/// Write a non-secret file the same way secrets are written: atomically, and `0600`.
///
/// `0600` even though a key record and a published claim are public data, because the
/// directory is the only thing standing between "this machine's key list" and the
/// other accounts on a shared box, and a record that lists which keys exist is worth
/// more to a stranger than any one of them.
pub(crate) fn write_file_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_atomically(path, bytes, 0o600)
}

/// Write `bytes` to `path` with mode `mode`, atomically.
///
/// Atomic because the alternative is worse: a keystore interrupted between open and
/// write leaves a truncated secret that looks like a wrong passphrase, and a record
/// half-written leaves a key that cannot be listed.
fn write_private_atomically(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let temp = path.with_extension(format!(
        "{}-{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("part"),
        std::process::id()
    ));
    {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(mode);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| Error::io("create file", format!("{}: {e}", temp.display())))?;
        file.write_all(bytes)
            .map_err(|e| Error::io("write file", format!("{}: {e}", temp.display())))?;
        file.flush()
            .map_err(|e| Error::io("flush file", format!("{}: {e}", temp.display())))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // `create_new` honours the umask for the mode it *reports* but not always for
        // the mode it applies; setting it explicitly is the only way to be sure a
        // secret file is 0600 on a machine with a permissive umask.
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io("chmod", format!("{}: {e}", temp.display())))?;
    }
    std::fs::rename(&temp, path)
        .map_err(|e| Error::io("replace file", format!("{}: {e}", path.display())))?;
    Ok(())
}

fn record_matches(record: &KeyRecord, selector: &str) -> bool {
    // A key *name* is a slug somebody typed, so its case is an accident and is
    // ignored. A key *id* is base64, where case is part of the value: comparing that
    // case-insensitively would be a fingerprint collision waiting to happen.
    if record.name.eq_ignore_ascii_case(selector) || record.key_id == selector {
        return true;
    }
    if let Some(body) = selector.strip_prefix("SHA256:")
        && body.len() >= 4
        && let Some(full) = record.key_id.strip_prefix("SHA256:")
    {
        return full.starts_with(body);
    }
    false
}

/// The keystore directory's file name for debugging messages.
pub fn describe_paths(paths: &Paths) -> String {
    format!("{}", paths.keys_dir().display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_round_trips_through_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::new(Paths::with_root(dir.path()));
        let passphrase = SecretString::from("correct horse battery staple");
        let record = store
            .generate(
                &Generate {
                    name: Some("laptop".into()),
                    comment: Some("ada@laptop".into()),
                    ..Default::default()
                },
                &passphrase,
            )
            .unwrap();
        assert_eq!(record.name, "laptop");
        assert_eq!(record.backend, Backend::Keystore);
        assert_eq!(store.list().unwrap().len(), 1);
        let unlocked = store.unlock(&record, &passphrase).unwrap();
        assert_eq!(unlocked.public_key().key_id(), record.key_id);
        let wrong = SecretString::from("not the passphrase, sorry");
        assert_eq!(store.unlock(&record, &wrong).unwrap_err().exit_code(), 6);
        // And a second key cannot take the first key's name.
        assert!(
            store
                .generate(
                    &Generate {
                        name: Some("laptop".into()),
                        ..Default::default()
                    },
                    &passphrase
                )
                .is_err()
        );
    }

    #[test]
    fn a_record_that_claims_another_keys_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::new(Paths::with_root(dir.path()));
        let passphrase = SecretString::from("four honest words!");
        let record = store.generate(&Generate::default(), &passphrase).unwrap();
        let path = store.record_path(&record.name);
        let text = std::fs::read_to_string(&path).unwrap();
        // Swap in a different key id — the classic "rename who signed this" edit.
        let other = SigningKey::from_seed(&[8u8; 32]).public_key().key_id();
        std::fs::write(&path, text.replace(&record.key_id, &other)).unwrap();
        let error = store.list().unwrap_err();
        assert_eq!(error.exit_code(), 6, "{error}");
        assert!(error.to_string().contains("fingerprint"), "{error}");
    }

    #[test]
    fn a_secret_file_name_cannot_escape_the_keystore() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::new(Paths::with_root(dir.path()));
        for bad in [
            "../outside.age",
            "/etc/passwd",
            "nested/deep.age",
            ".hidden",
        ] {
            assert!(store.secret_path(bad).is_err(), "{bad}");
        }
    }
}

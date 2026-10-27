//! Identity claims: "this key is mine, and here is who says so".
//!
//! An identity in gitiup is a *signed claim*, not an account. It is the smallest
//! record that answers three questions a stranger needs:
//!
//! 1. **which key** — `key_id`, re-derived from `public_key` exactly as every other
//!    gitiup record does, so a claim cannot borrow a famous fingerprint;
//! 2. **what to call them** — a handle (machine-usable, the value a roster entry's
//!    `identity` field names) and a display name;
//! 3. **who else vouches** — [`Endorsement`]s: signatures by *other* keys over this
//!    claim's digest, which is the web-of-trust part, and the only part that turns a
//!    self-declared name into something a policy can weigh.
//!
//! Same framing as every other signed record (ADR-0001 D1/D3, ADR-0002 D8):
//!
//! ```text
//! signature = ed25519 over pae("application/vnd.gitiup.identity+json",
//!                               canonical(claim without `signatures` and `endorsements`))
//! ```
//!
//! The signature list and the endorsement list are both outside the signed body,
//! and that is what makes endorsements work at all: a third party can add one to a
//! published claim without invalidating the owner's self-signature, because the
//! endorsement signs the *body digest* instead of being embedded in it. An
//! endorsement that did not do that would require the owner to re-publish after
//! every vouch, which in practice means nobody gets vouched for.
//!
//! What is deliberately absent: an identity registry, a directory, and any network
//! call. A claim is a file you publish somewhere you already control (a bucket, a
//! repo, an attachment to a change) and a verifier checks it with a key they already
//! trust. *Who* is trusted is [`gitiup_attest::Trust`], which stays the caller's
//! policy.

use std::collections::BTreeMap;
use std::path::PathBuf;

use gitiup_attest::{Digest, ErrorKind, PublicKey, SignatureEntry, Signer, Trust, pae};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::{Paths, is_slug};
use crate::record::{body_bytes_with, canonical_bytes, from_canonical_bytes, short_key};

/// The claim type this crate writes.
pub const IDENTITY_TYPE: &str = "gitiup-identity-1";
/// The claim schema version this crate writes.
pub const IDENTITY_SCHEMA_VERSION: u32 = 1;
/// The DSSE payload type of a claim's self-signature.
pub const IDENTITY_PAYLOAD_TYPE: &str = "application/vnd.gitiup.identity+json";
/// The DSSE payload type of an endorsement.
pub const ENDORSEMENT_PAYLOAD_TYPE: &str = "application/vnd.gitiup.endorsement+json";

/// Endorsements per claim. Beyond this a "web of trust" is a scraping target.
pub const MAX_ENDORSEMENTS: usize = 64;
/// Signatures per claim (self-signatures; more than one is for a key rotation).
pub const MAX_CLAIM_SIGNATURES: usize = 8;
/// Bytes in a display name, an email, or a URL.
pub const MAX_TEXT_BYTES: usize = 256;
/// Bytes in an annotation value (the same bound ADR-0001 D7 puts on free text).
pub const MAX_ANNOTATION_BYTES: usize = 1024;

/// The name and contact details a claim publishes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// Machine-usable handle: the value a roster entry's `identity` field uses.
    pub handle: String,
    /// What to show a human.
    pub display_name: String,
    /// Optional contact address.
    pub email: Option<String>,
    /// Optional page that explains the identity.
    pub url: Option<String>,
    /// Extension fields, `x_<producer>_<name>` (ADR-0001 D8's escape hatch).
    pub annotations: BTreeMap<String, String>,
}

/// A signed identity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityClaim {
    /// Schema version ([`IDENTITY_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// `gitiup-identity-1`: inside the signed body, so a v2 claim cannot be checked
    /// with v1 rules.
    #[serde(rename = "type")]
    pub record_type: String,
    /// `SHA256:<unpadded base64>` — derived from `public_key` and re-checked.
    pub key_id: String,
    /// The OpenSSH public-key line.
    pub public_key: String,
    /// The handle.
    pub handle: String,
    /// The display name.
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional contact address.
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional page about this identity.
    pub url: Option<String>,
    /// When this claim was made, in microseconds since the epoch.
    pub created_at_us: i64,
    /// Set when the identity is retired: the claim stays published, with an end.
    ///
    /// A retirement is a claim, not a deletion — deleting the file would be an
    /// unprovable edit to history, and the whole point of a claim is that it can be
    /// checked later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at_us: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    /// `x_<producer>_<name>` extension fields.
    pub annotations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Third-party vouches. Outside the signed body, by design.
    pub endorsements: Vec<Endorsement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The owner's self-signature(s).
    pub signatures: Vec<SignatureEntry>,
}

impl IdentityClaim {
    /// Build and self-sign a claim for `key`.
    ///
    /// `key` may be any [`Signer`] — a keystore key, an ssh-agent identity, a gpg
    /// key — which is the point: the identity is the key's, not a keystore's.
    pub fn new(key: &dyn Signer, profile: &Profile, created_at_us: i64) -> Result<IdentityClaim> {
        let public = key.public_key();
        let claim = IdentityClaim {
            schema_version: IDENTITY_SCHEMA_VERSION,
            record_type: IDENTITY_TYPE.to_string(),
            key_id: public.key_id(),
            public_key: public.to_openssh(),
            handle: profile.handle.clone(),
            display_name: profile.display_name.clone(),
            email: profile.email.clone(),
            url: profile.url.clone(),
            created_at_us,
            retired_at_us: None,
            annotations: profile.annotations.clone(),
            endorsements: Vec::new(),
            signatures: Vec::new(),
        };
        claim.validate()?;
        let mut claim = claim;
        claim.sign(key)?;
        Ok(claim)
    }

    /// The canonical bytes a signature covers: everything except the signature and
    /// endorsement lists.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes_with(self, &["signatures", "endorsements"])
    }

    /// `sha256:` over [`IdentityClaim::body_bytes`] — what endorsements bind to, so
    /// they survive being added.
    pub fn body_digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.body_bytes()?))
    }

    /// The claim's digest in its wire form, `sha256:<hex>` — the algorithm prefix is
    /// part of every gitiup digest string (ADR-0001 D2), and an endorsement stores
    /// exactly this.
    pub fn body_digest_string(&self) -> Result<String> {
        let digest = self.body_digest()?;
        Ok(format!("{}:{}", digest.algorithm().as_str(), digest.hex()))
    }

    /// Add (or replace) this key's self-signature.
    pub fn sign(&mut self, key: &dyn Signer) -> Result<()> {
        let entry = SignatureEntry::new(key, &pae(IDENTITY_PAYLOAD_TYPE, &self.body_bytes()?))?;
        if entry.key_id != self.key_id {
            return Err(Error::refused(
                "identity",
                format!(
                    "the key offered ({}) is not the key this claim is about ({})",
                    short_key(&entry.key_id),
                    short_key(&self.key_id)
                ),
            )
            .with_hint("only the key a claim names can self-sign it; endorse it instead"));
        }
        self.signatures
            .retain(|existing| existing.key_id != entry.key_id);
        self.signatures.push(entry);
        self.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        if self.signatures.len() > MAX_CLAIM_SIGNATURES {
            return Err(Error::refused(
                "identity",
                format!("more than {MAX_CLAIM_SIGNATURES} self-signatures"),
            ));
        }
        Ok(())
    }

    /// Add an endorsement, checking it first.
    ///
    /// An endorsement is *verified when it arrives*, not when the file is read:
    /// accepting a vouch that does not verify would let anybody append a
    /// "everyone trusts this" line to somebody else's published claim.
    pub fn with_endorsement(mut self, endorsement: Endorsement) -> Result<IdentityClaim> {
        endorsement.verify_against(&self)?;
        if self
            .endorsements
            .iter()
            .any(|existing| existing.endorser_key_id == endorsement.endorser_key_id)
        {
            return Err(Error::refused(
                "endorsement",
                format!(
                    "{} has already endorsed this claim",
                    short_key(&endorsement.endorser_key_id)
                ),
            )
            .with_hint("one endorsement per key: a second vouch is a new claim, not a copy"));
        }
        self.endorsements.push(endorsement);
        self.endorsements
            .sort_by(|a, b| a.endorser_key_id.cmp(&b.endorser_key_id));
        self.validate()?;
        Ok(self)
    }

    /// Canonical bytes of the whole claim, signatures included.
    ///
    /// What gets written and published: the bytes stored are the bytes signed, so a
    /// reader never has to ask "over what?".
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_bytes(self)
    }

    /// Read canonical bytes, structurally validate, and re-encode to prove the
    /// bytes are the bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<IdentityClaim> {
        let claim: IdentityClaim = from_canonical_bytes(bytes)?;
        claim.validate()?;
        let again = claim.canonical_bytes()?;
        if again.as_slice() != bytes {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "identity claim",
                "the bytes received are not the canonical encoding of the claim they decode to",
            ));
        }
        Ok(claim)
    }

    /// Structural checks, run on every read.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDENTITY_SCHEMA_VERSION {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "identity claim",
                format!(
                    "schema version {} is not {IDENTITY_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        if self.record_type != IDENTITY_TYPE {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "identity claim",
                format!("type '{}' is not '{IDENTITY_TYPE}'", self.record_type),
            ));
        }
        if !is_slug(&self.handle) {
            return Err(Error::invalid(
                "identity claim",
                format!("handle '{}' is not a handle", self.handle),
            )
            .with_hint("a handle is letters, digits, '.', '_' or '-', starting with a letter"));
        }
        for (field, value) in [
            ("display name", Some(self.display_name.as_str())),
            ("email", self.email.as_deref()),
            ("url", self.url.as_deref()),
        ] {
            let value = value.unwrap_or_default();
            if !value.is_empty() && value.len() > MAX_TEXT_BYTES {
                return Err(Error::invalid(
                    "identity claim",
                    format!("{field} is {} bytes", value.len()),
                ));
            }
        }
        if self.display_name.trim().is_empty() {
            return Err(Error::invalid(
                "identity claim",
                "a claim with no display name is a key id with a wrapper",
            ));
        }
        if let Some(email) = &self.email {
            // Not a validator's opinion of RFC 5322: one `@`, no spaces, no control
            // characters. Enough to stop a display name being smuggled in as an
            // address, and not enough to reject a domain this code has never heard of.
            if !email.contains('@')
                || email.split('@').count() != 2
                || email.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(Error::invalid(
                    "identity claim",
                    format!("'{email}' is not an address"),
                ));
            }
        }
        if let Some(url) = &self.url
            && !(url.starts_with("http://") || url.starts_with("https://"))
        {
            return Err(
                Error::invalid("identity claim", format!("url '{url}' must be http(s)")).with_hint(
                    "a URL is fetched by someone someday; a scheme-less string is a prompt",
                ),
            );
        }
        for (name, value) in &self.annotations {
            if !name.starts_with("x_") || name.len() < 4 {
                return Err(Error::invalid(
                    "identity claim",
                    format!("annotation '{name}' must be named x_<producer>_<name>"),
                ));
            }
            if value.len() > MAX_ANNOTATION_BYTES {
                return Err(Error::invalid(
                    "identity claim",
                    format!("annotation '{name}' is {} bytes", value.len()),
                ));
            }
        }
        if self.created_at_us <= 0 {
            return Err(Error::invalid(
                "identity claim",
                "created_at_us must be a positive microsecond count",
            ));
        }
        if let Some(retired) = self.retired_at_us
            && retired < self.created_at_us
        {
            return Err(Error::invalid(
                "identity claim",
                "a claim cannot retire before it was made",
            ));
        }
        let public = PublicKey::from_openssh(&self.public_key)
            .map_err(|e| Error::new(e.kind(), "identity claim", e.detail().to_string()))?;
        if public.key_id() != self.key_id {
            return Err(Error::new(
                ErrorKind::Signature,
                "identity claim",
                format!(
                    "key id '{}' is not the fingerprint of the public key in this claim ({})",
                    self.key_id,
                    public.key_id()
                ),
            ));
        }
        if self.endorsements.len() > MAX_ENDORSEMENTS {
            return Err(Error::refused(
                "identity claim",
                format!(
                    "{} endorsements exceeds {MAX_ENDORSEMENTS}",
                    self.endorsements.len()
                ),
            ));
        }
        if self.signatures.len() > MAX_CLAIM_SIGNATURES {
            return Err(Error::refused(
                "identity claim",
                format!(
                    "{} self-signatures exceeds {MAX_CLAIM_SIGNATURES}",
                    self.signatures.len()
                ),
            ));
        }
        let mut seen: Vec<&str> = Vec::new();
        for endorsement in &self.endorsements {
            if endorsement.endorser_key_id == self.key_id {
                return Err(Error::refused(
                    "identity claim",
                    "a key may not endorse its own identity claim",
                )
                .with_hint("that is what the self-signature is for"));
            }
            if seen.contains(&endorsement.endorser_key_id.as_str()) {
                return Err(Error::invalid(
                    "identity claim",
                    format!("{} endorses twice", short_key(&endorsement.endorser_key_id)),
                ));
            }
            seen.push(endorsement.endorser_key_id.as_str());
        }
        Ok(())
    }

    /// Check the self-signature and every endorsement, and report which endorsers
    /// `trust` accepts.
    ///
    /// Order matters, and it is ADR-0001 D7's: structure, then signatures for
    /// self-consistency, then the trust list. Every signature must verify — a claim
    /// carrying one broken vouch is refused rather than filtered, because "we
    /// ignored the one that did not work" is how a bored attacker buys a
    /// reputation.
    pub fn verify(&self, trust: &Trust) -> Result<Verified> {
        self.validate()?;
        let body = self.body_bytes()?;
        if self.signatures.is_empty() {
            return Err(Error::new(
                ErrorKind::Policy,
                "identity claim",
                "this claim is unsigned: nobody has said this key is theirs",
            ));
        }
        for signature in &self.signatures {
            signature
                .verify(&pae(IDENTITY_PAYLOAD_TYPE, &body))
                .map_err(|e| Error::new(e.kind(), "identity claim", e.detail().to_string()))?;
        }
        if !self.signatures.iter().any(|s| s.key_id == self.key_id) {
            return Err(Error::new(
                ErrorKind::Policy,
                "identity claim",
                format!(
                    "no self-signature by {}: the claim is signed by someone else's key",
                    short_key(&self.key_id)
                ),
            )
            .with_hint(
                "a claim asserts the holder controls the key; only that key's signature counts",
            ));
        }
        let mut endorsers = Vec::new();
        for endorsement in &self.endorsements {
            endorsement.verify_against(self)?;
            endorsers.push(endorsement.endorser_key_id.clone());
        }
        let trusted_endorsers: Vec<String> = endorsers
            .iter()
            .filter(|key_id| trust.trusts(key_id))
            .cloned()
            .collect();
        let self_trusted = trust.trusts(&self.key_id);
        Ok(Verified {
            key_id: self.key_id.clone(),
            handle: self.handle.clone(),
            endorsers,
            trusted_endorsers,
            self_trusted,
        })
    }

    /// The key this claim is about.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_openssh(&self.public_key)
            .map_err(|e| Error::new(e.kind(), "identity claim", e.detail().to_string()))
    }
}

/// One third-party vouch.
///
/// It repeats `identity_key_id` and `handle` rather than pointing at them: an
/// endorsement must be un-verifiable if moved to another claim, and the way to be
/// sure of that is for the bytes it signs to name what it vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endorsement {
    /// The endorser's key id, derived from `endorser_public_key`.
    pub endorser_key_id: String,
    /// The endorser's OpenSSH public-key line, so a verifier needs no lookup.
    pub endorser_public_key: String,
    /// The claim's body digest (`sha256:<hex>`) — the binding.
    pub claim_digest: String,
    /// The key being vouched for.
    pub identity_key_id: String,
    /// The handle being vouched for.
    pub handle: String,
    /// Optional human sentence ("we work together", "signed at the keysigning").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// When the vouch was made.
    pub claimed_at_us: i64,
    /// The signature over `pae(endorsement payload type, body without this field)`.
    pub signature: SignatureEntry,
}

impl Endorsement {
    /// Vouch for `claim` with `endorser`.
    pub fn make(
        claim: &IdentityClaim,
        endorser: &dyn Signer,
        statement: Option<String>,
        claimed_at_us: i64,
    ) -> Result<Endorsement> {
        if endorser.key_id() == claim.key_id {
            return Err(Error::refused(
                "endorsement",
                "a key cannot endorse its own identity claim",
            )
            .with_hint("that is what `gitiup identity publish` is for"));
        }
        let public = endorser.public_key();
        let statement = statement.filter(|s| !s.trim().is_empty());
        if let Some(statement) = &statement
            && statement.len() > MAX_TEXT_BYTES
        {
            return Err(Error::invalid(
                "endorsement",
                format!("the statement is {} bytes", statement.len()),
            ));
        }
        let endorsement = Endorsement {
            endorser_key_id: public.key_id(),
            endorser_public_key: public.to_openssh(),
            claim_digest: claim.body_digest_string()?,
            identity_key_id: claim.key_id.clone(),
            handle: claim.handle.clone(),
            statement,
            claimed_at_us,
            // Placeholder, filled immediately below; the body excludes this field.
            signature: SignatureEntry {
                key_id: String::new(),
                algorithm: gitiup_attest::SignatureAlgorithm::Ed25519,
                public_key: String::new(),
                sig: String::new(),
            },
        };
        let message = pae(ENDORSEMENT_PAYLOAD_TYPE, &endorsement.body_bytes()?);
        let signature = SignatureEntry::new(endorser, &message)?;
        Ok(Endorsement {
            signature,
            ..endorsement
        })
    }

    /// The canonical bytes this endorsement signs.
    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        body_bytes_with(self, &["signature"])
    }

    /// Check a vouch against `claim`: the bindings first, then the signature.
    ///
    /// Bindings before the signature because that is where an attack lives. A valid
    /// signature over a real endorsement of a *different* claim must fail here, and
    /// a verifier that checked the signature first would have to remember to
    /// compare the digest afterwards — which is the kind of "and then" rule that
    /// outlives its author.
    pub fn verify_against(&self, claim: &IdentityClaim) -> Result<()> {
        if self.identity_key_id != claim.key_id {
            return Err(Error::new(
                ErrorKind::Policy,
                "endorsement",
                format!(
                    "this endorsement vouches for {}, not for the claim it was found in",
                    short_key(&self.identity_key_id)
                ),
            ));
        }
        if self.handle != claim.handle {
            return Err(Error::new(
                ErrorKind::Policy,
                "endorsement",
                format!(
                    "this endorsement vouches for '{}', not '{}'",
                    self.handle, claim.handle
                ),
            ));
        }
        let digest: Digest = self
            .claim_digest
            .parse()
            .map_err(|e: gitiup_attest::Error| {
                Error::new(
                    ErrorKind::Invalid,
                    "endorsement",
                    format!("claim_digest '{}': {}", self.claim_digest, e.detail()),
                )
            })?;
        if digest != claim.body_digest()? {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "endorsement",
                format!(
                    "this endorsement is over {} but the claim's body digests to {}",
                    digest.hex(),
                    claim.body_digest_string()?
                ),
            )
            .with_hint("the claim changed after the vouch — the endorser must vouch again"));
        }
        let public = PublicKey::from_openssh(&self.endorser_public_key)
            .map_err(|e| Error::new(e.kind(), "endorsement", e.detail().to_string()))?;
        if public.key_id() != self.endorser_key_id {
            return Err(Error::new(
                ErrorKind::Signature,
                "endorsement",
                format!(
                    "endorser key id '{}' is not the fingerprint of the key offered",
                    self.endorser_key_id
                ),
            ));
        }
        if self.endorser_key_id == claim.key_id {
            return Err(Error::new(
                ErrorKind::Policy,
                "endorsement",
                "a key endorsed its own identity",
            ));
        }
        self.signature
            .verify(&pae(ENDORSEMENT_PAYLOAD_TYPE, &self.body_bytes()?))
            .map_err(|e| Error::new(e.kind(), "endorsement", e.detail().to_string()))
    }
}

/// What a verified claim says about trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The key the claim is about.
    pub key_id: String,
    /// The handle it publishes.
    pub handle: String,
    /// Every endorser whose vouch verified.
    pub endorsers: Vec<String>,
    /// The subset `trust` accepts.
    pub trusted_endorsers: Vec<String>,
    /// Whether the claim's own key is in `trust`.
    pub self_trusted: bool,
}

/// Where published claims live: `identities/<handle>.identity.json`.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    paths: Paths,
}

/// Suffix of a published claim file.
pub const CLAIM_SUFFIX: &str = "identity.json";

impl IdentityStore {
    /// Open the store at `paths`.
    pub fn new(paths: Paths) -> IdentityStore {
        IdentityStore { paths }
    }

    /// The layout in use.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// The path a handle maps to.
    pub fn path_for(&self, handle: &str) -> PathBuf {
        self.paths
            .identities_dir()
            .join(format!("{handle}.{CLAIM_SUFFIX}"))
    }

    /// Publish canonical claim bytes: write, then re-read and check.
    ///
    /// The re-read is not paranoia about the filesystem; it is the only way to prove
    /// that what is stored is a claim this build would accept, which is the property
    /// every later reader depends on.
    pub fn publish(&self, claim: &IdentityClaim, force: bool) -> Result<PathBuf> {
        claim.validate()?;
        if claim.signatures.is_empty() {
            return Err(Error::refused(
                "identity claim",
                "refusing to publish an unsigned claim",
            ));
        }
        self.paths.ensure()?;
        let path = self.path_for(&claim.handle);
        if path.exists() && !force {
            return Err(Error::refused(
                "identity claim",
                format!("{} already exists", path.display()),
            )
            .with_hint("`--force` replaces it, or publish under a new handle"));
        }
        let bytes = claim.canonical_bytes()?;
        crate::keystore::write_file_private(&path, &bytes)?;
        let read_back = IdentityClaim::from_canonical_bytes(
            &std::fs::read(&path)
                .map_err(|e| Error::io("read back claim", format!("{}: {e}", path.display())))?,
        )?;
        if &read_back != claim {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "identity claim",
                format!("{} did not read back as written", path.display()),
            ));
        }
        Ok(path)
    }

    /// Every published claim, by handle.
    pub fn list(&self) -> Result<Vec<IdentityClaim>> {
        let dir = self.paths.identities_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(Error::io(
                    "read identities",
                    format!("{}: {error}", dir.display()),
                ));
            }
        };
        let mut claims = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if name.is_some_and(|n| n.ends_with(&format!(".{CLAIM_SUFFIX}"))) {
                let bytes = std::fs::read(&path)
                    .map_err(|e| Error::io("read claim", format!("{}: {e}", path.display())))?;
                let claim = IdentityClaim::from_canonical_bytes(&bytes).map_err(|e| {
                    Error::refused(
                        "identity claim",
                        format!("{}: {}", path.display(), e.detail()),
                    )
                })?;
                claims.push(claim);
            }
        }
        claims.sort_by(|a, b| a.handle.cmp(&b.handle));
        Ok(claims)
    }

    /// Find a claim by handle, key id or key-id prefix.
    pub fn find(&self, selector: &str) -> Result<IdentityClaim> {
        let claims = self.list()?;
        let matches: Vec<IdentityClaim> = claims
            .into_iter()
            .filter(|claim| {
                claim.handle == selector
                    || claim.key_id == selector
                    || selector
                        .strip_prefix("SHA256:")
                        .filter(|body| body.len() >= 4)
                        .and_then(|body| {
                            claim
                                .key_id
                                .strip_prefix("SHA256:")
                                .and_then(|full| full.starts_with(body).then_some(()))
                        })
                        .is_some()
            })
            .collect();
        match matches.len() {
            0 => Err(Error::not_found("identity", format!("'{selector}'"))
                .with_hint("`gitiup identity list` shows what is published here")),
            1 => Ok(matches.into_iter().next().expect("one match")),
            n => Err(Error::refused(
                "identity selection",
                format!("'{selector}' matches {n} claims"),
            )),
        }
    }

    /// Append an endorsement to a published claim, in place.
    ///
    /// This is the operation the signature scheme exists to allow: the owner does
    /// not re-sign, because the endorsement does not touch the signed body.
    pub fn endorse(&self, handle: &str, endorsement: Endorsement) -> Result<PathBuf> {
        let claim = self.find(handle)?;
        let updated = claim.with_endorsement(endorsement)?;
        self.publish(&updated, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::SigningKey;

    fn profile(handle: &str) -> Profile {
        Profile {
            handle: handle.to_string(),
            display_name: "Ada Lovelace".to_string(),
            email: Some("ada@example.com".to_string()),
            url: Some("https://example.com/ada".to_string()),
            annotations: BTreeMap::new(),
        }
    }

    #[test]
    fn a_claim_signs_round_trips_and_verifies() {
        let key = SigningKey::from_seed(&[11u8; 32]);
        let claim = IdentityClaim::new(&key, &profile("ada"), 1_793_092_600_000_000).unwrap();
        let bytes = claim.canonical_bytes().unwrap();
        let read = IdentityClaim::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read, claim);
        let trust = Trust::KeyIds([key.public_key().key_id()].into_iter().collect());
        let verified = read.verify(&trust).unwrap();
        assert!(verified.self_trusted);
        assert!(verified.endorsers.is_empty());
        assert!(gitiup_attest::is_canonical(&bytes));
    }

    #[test]
    fn an_endorsement_survives_and_binds() {
        let ada = SigningKey::from_seed(&[12u8; 32]);
        let grace = SigningKey::from_seed(&[13u8; 32]);
        let claim = IdentityClaim::new(&ada, &profile("ada"), 1_793_092_600_000_000).unwrap();
        let before = claim.canonical_bytes().unwrap();

        let endorsement = Endorsement::make(
            &claim,
            &grace,
            Some("colleagues".into()),
            1_793_092_700_000_000,
        )
        .unwrap();
        let claim = claim.with_endorsement(endorsement.clone()).unwrap();
        // The body did not move, so the owner's signature is still valid: this is the
        // property that makes endorsements possible at all.
        assert_eq!(
            claim.body_bytes().unwrap(),
            IdentityClaim::from_canonical_bytes(&before)
                .unwrap()
                .body_bytes()
                .unwrap()
        );
        assert!(claim.signatures.len() == 1);

        let trust = Trust::KeyIds([grace.public_key().key_id()].into_iter().collect());
        let verified = claim.verify(&trust).unwrap();
        assert_eq!(verified.endorsers, vec![grace.public_key().key_id()]);
        assert_eq!(
            verified.trusted_endorsers,
            vec![grace.public_key().key_id()]
        );
        assert!(!verified.self_trusted);

        // A vouch cannot be moved to another claim, even though its signature is
        // perfectly valid over its own body.
        let other = IdentityClaim::new(&ada, &profile("ada2"), 1_793_092_600_000_000).unwrap();
        let error = endorsement.verify_against(&other).unwrap_err();
        assert_eq!(error.exit_code(), 6, "{error}");
    }

    #[test]
    fn a_claim_that_edits_what_it_claims_about_is_refused() {
        let key = SigningKey::from_seed(&[14u8; 32]);
        let mut claim = IdentityClaim::new(&key, &profile("ada"), 1_793_092_600_000_000).unwrap();
        let other = SigningKey::from_seed(&[15u8; 32]).public_key();
        claim.public_key = other.to_openssh();
        // Exit 7, not 6: ADR-0001 D7 puts "key_id does not match the key offered"
        // with the bad-signature class, because it is an integrity failure and not a
        // policy the verifier chose.
        assert_eq!(
            IdentityClaim::from_canonical_bytes(&claim.canonical_bytes().unwrap())
                .unwrap_err()
                .exit_code(),
            7
        );
        // And an unsigned claim is not a claim: a refusal (6), not an integrity
        // failure — nothing is wrong with the bytes, they just assert nothing.
        let mut unsigned =
            IdentityClaim::new(&key, &profile("ada"), 1_793_092_600_000_000).unwrap();
        unsigned.signatures.clear();
        assert_eq!(
            unsigned
                .verify(&Trust::AnyKeyForTests)
                .unwrap_err()
                .exit_code(),
            6
        );
    }
}

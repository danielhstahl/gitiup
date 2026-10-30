//! The published policy: what a repository demands, who said so, and since when
//! ([ADR-0004](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md)).
//!
//! This module is the code half of ADR-0004. Before it, the rules a merge gate
//! applied were whatever file somebody remembered to pass with `--policy`, so a
//! fresh clone could not answer "what will be demanded of this change, and who said
//! so?" — and the four tickets downstream of this one (`.3`'s `policy show`, `.4`'s
//! `verify change`, `.5`'s hook, `giti-zp1.2`'s round numbers) were each about to
//! invent their own answer. There is one answer here, and every caller calls it.
//!
//! ```text
//! kv/policy/<hex(record_digest)>           the signed bytes, immutable
//! refs/gitiup/policy/current               the policy in force (moved under CAS)
//! refs/gitiup/policy/history/<rev:06>      every revision ever published, create-only
//! ```
//!
//! # The document, and its two digests
//!
//! A published policy is one `gitiup-policy-1` record in Gitiup Canonical JSON
//! ([ADR-0001 D1](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)), signed
//! in place with exactly one signature — the fourth record type to use
//! [`record::body_bytes`](crate::record::body_bytes), after the attestation, the
//! roster and the change. Two digests, with the two jobs ADR-0003 D4 assigns them:
//!
//! | digest | over | used for |
//!|--------|------|----------|
//!| `body_digest` | the document with `signatures` removed | what a verdict cites, what `previous_digest` names, what `ChangeRecord::policy_digest` holds |
//!| `record_digest` | the stored bytes, signature included | the `kv/policy/<hex>` key — the bytes a reader actually fetched |
//!
//! `body_digest` is computable before anybody signs, which is what lets
//! `gitiup policy publish --dry-run` print what it is about to commit to (D8).
//!
//! # A policy cannot certify itself
//!
//! Three checks, all refusals, in this order (D3): the document is signed at all
//! (`unsigned`, 6 — not applied-with-a-warning, because the dangerous failure is the
//! silent one); the signature verifies and the identity is *derived* (`bad_signature`
//! / `key_id_derivation`, 7); and the signer is in the verifier's own trust roots
//! (`signer_untrusted`, 6). Those roots are local configuration — `--owner`, else this
//! machine's keystore — never the document's own `rules.trust_key_ids`, which answer a
//! different question entirely: who may sign a *proof*, as opposed to who may set the
//! rules. The [`personal` vector](../../../docs/adr/fixtures/policy-v1/README.md) is
//! that distinction made concrete: Ada signs the rules, the CI runner signs the proofs,
//! and a reader that conflated the two could not express that repository at all.
//!
//! # One validation order, one token per refusal
//!
//! [`validate`] runs D9's seven steps in D9's order — bytes, structure, trust, rules,
//! quorum, chain, normalisation — and every refusal carries a named token beside the
//! exit code: 6 refused, 7 bad signature, 8 not-its-own-bytes. The token is the
//! interface, not a string: `policies/*.json` and the 32-row table in
//! `cases.json:refusals` are reproduced token-for-token by
//! `crates/gitiup-quorum/tests/policy_vectors.rs`, so `.3`, `.4` and `.5` refuse the
//! same documents for the same reasons rather than each in its own idiom.
//!
//! # Resolution, and what a verdict has to say about it
//!
//! [`resolve`] answers D4's ladder: `--policy`/`$GITIUP_POLICY`, then the
//! store-published record (walked to the revision in force at the run's timestamp,
//! D6), then a `gitiup-policy.json` found in the checkout, then this build's default —
//! with a line drawn after the second: the first two are *gate-eligible*, the last two
//! are local-only, and a gate with nothing gate-eligible refuses (`no_policy_published`,
//! 6) instead of quietly deciding a merge by a default nobody chose. Every answer
//! carries [`PolicyProvenance`]: which source, both digests, which revision, which key
//! signed it, and the timestamp the walk used.
//!
//! ```
//! use gitiup_attest::{PolicyFile, TimeUs, Trust};
//! use gitiup_host::FsHost;
//! use gitiup_quorum::policy::{self, NewPolicy, PolicyOwner};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join("gitiup-policy-example");
//! let _ = std::fs::remove_dir_all(&dir);
//! let host = FsHost::create(&dir)?;
//! let key = gitiup_attest::SigningKey::from_seed(&[7u8; 32]);
//! let trust: Trust = Trust::KeyIds([key.public_key().key_id()].into_iter().collect());
//!
//! let rules = PolicyFile::from_json(
//!     r#"{"allowed_tiers": ["local"], "trust_key_ids":
//!        ["SHA256:kHe5CTrcfnmORAqMoE3KPhY+IjO+b4k1l7fkv3mQ+aQ"]}"#,
//! )?;
//! let mut document = NewPolicy {
//!     owner: PolicyOwner {
//!         key_id: key.public_key().key_id(),
//!         principal: "Ada Hale".into(),
//!     },
//!     protects: vec!["refs/heads/**".into()],
//!     rules,
//!     effective_from_us: 1_793_092_800_000_000,
//!     // The chain position is part of the document, so a first policy says so: revision
//!     // 1, and the zero digest for a predecessor that does not exist (D6).
//!     revision: 1,
//!     previous_digest: policy::GENESIS_PREVIOUS.into(),
//!     ..Default::default()
//! }
//! .build();
//! document.sign(&key)?;
//! let context = policy::Context::new(&trust, TimeUs(1_793_092_800_000_000));
//! let published = policy::publish(&host, &document, &context, None)?;
//! assert_eq!(published.revision, 1);
//! assert_eq!(published.kv, format!("kv/policy/{}", published.record_digest.split(':').nth(1).unwrap()));
//!
//! let resolved = policy::resolve_store(
//!     &host,
//!     &trust,
//!     policy::At::run_claim(TimeUs(1_793_092_800_000_000)),
//! )?;
//! assert_eq!(resolved.provenance.revision, Some(1));
//! assert_eq!(resolved.provenance.signed_by.as_deref(), Some(key.public_key().key_id().as_str()));
//! # let _ = std::fs::remove_dir_all(&dir);
//! # Ok(()) }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use gitiup_attest::{
    DEFAULT_MAX_CLOCK_SKEW_US, EnvMatch, Policy, PolicyFile, SignatureEntry, Signer, Tier, TimeUs,
    Trust, canon, pae,
};
use gitiup_host::{Actor, Host, Namespace, Oid, RefName, RefQuery, RefUpdate};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::capability::{Requirements, RosterTier};
use crate::select::SelectionPolicy;

// --------------------------------------------------------------------------
// The format's constants (ADR-0004 D2, D5, D6, D10)
// --------------------------------------------------------------------------

/// `type` of a published policy document (D2).
pub const POLICY_TYPE: &str = "gitiup-policy-1";
/// `schema_version` this module writes, and the only one it reads (D10).
pub const POLICY_SCHEMA_VERSION: u32 = 1;
/// The DSSE payload type inside every policy signature (D2). Inside the signature
/// means inside the format: a policy can never be checked with a roster's rules.
pub const POLICY_PAYLOAD_TYPE: &str = "application/vnd.gitiup.policy+json";
/// The `previous_digest` of the first policy a store ever advertised (D6).
///
/// A zero digest rather than an absent field, because canonical JSON forbids
/// `null` and "there was no predecessor" is a fact.
pub const GENESIS_PREVIOUS: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Largest published policy a reader will parse: 32 KiB (D10).
///
/// Far below ADR-0001's 1 MiB document ceiling, because every clone fetches one and
/// a human reads it. The biggest fixture is 1638 bytes; a policy that needed more
/// was writing prose into `annotations`.
pub const MAX_POLICY_BYTES: usize = 32 * 1024;
/// Most annotations, and the largest one (D10, ADR-0001 D5's hatch).
pub const MAX_ANNOTATIONS: usize = 16;
/// Largest annotation value, in bytes.
pub const MAX_ANNOTATION_BYTES: usize = 512;
/// Most `protects` globs, and the longest one (D10).
pub const MAX_PROTECTS: usize = 32;
/// Largest `protects` glob, in bytes.
pub const MAX_PROTECT_BYTES: usize = 128;
/// Most `quorum.by_job` globs (D10): a matrix with more arms is more than one
/// repository.
pub const MAX_BY_JOB: usize = 64;
/// Largest `owner.principal`, in bytes: it is printed, and it is not a free text body.
pub const MAX_PRINCIPAL_BYTES: usize = 128;
/// Most sandbox names, or image digests, in one list (D10).
pub const MAX_LIST_ITEMS: usize = 32;
/// How many links of the chain a reader will walk (D6): bounds the work a volunteer
/// signs up for.
pub const MAX_CHAIN_WALK: usize = 64;
/// The sandbox rung a policy may not demand less of (D5).
///
/// Rung 0 is "nothing confined this", and no repository gets to require that of
/// somebody else's machine.
pub const MIN_SANDBOX_LEVEL: u8 = 1;
/// A week, in microseconds: the bound behind two of D8's warnings.
pub const WEEK_US: i64 = 7 * 24 * 60 * 60 * 1_000_000;
/// Warn when the policy expires sooner than this (D8).
pub const EXPIRY_WARNING_US: i64 = WEEK_US;
/// Warn when the freshness window is longer than this (D8): it is how long a policy
/// change can be dodged with an old proof (D6).
pub const MAX_AGE_WARNING_US: i64 = WEEK_US;

/// The `kv/` namespace a policy is filed under (D7).
///
/// Shared with quorum verdicts on purpose — the host documents `Namespace::POLICY`
/// as "quorum verdicts and policy documents", and a policy is told apart from a
/// verdict by its `type`, not by its key.
pub const POLICY_NAMESPACE: Namespace = Namespace::POLICY;

/// The ref naming the policy in force (D7).
pub const CURRENT_REF: &str = "policy/current";
/// The ref prefix carrying every revision, one ref each (D7).
pub const HISTORY_REF_ROOT: &str = "policy/history";
/// How many digits a history ref's revision is padded to (D7): a listing is then
/// in order.
pub const HISTORY_REVISION_DIGITS: usize = 6;

/// The fields a `gitiup-policy-1` document may carry, in canonical order — which is
/// also the order a person reads one in (D2).
pub const POLICY_FIELDS: &[&str] = &[
    "annotations",
    "effective_from_us",
    "expires_at_us",
    "owner",
    "previous_digest",
    "protects",
    "quorum",
    "revision",
    "rules",
    "schema_version",
    "signatures",
    "type",
];

/// The fields a document must carry. `signatures` is absent rather than empty in a
/// document nobody signed, and the refusal that names it is `unsigned`, so it is not
/// here (D9).
pub const REQUIRED_POLICY_FIELDS: &[&str] = &[
    "effective_from_us",
    "owner",
    "previous_digest",
    "protects",
    "revision",
    "rules",
    "schema_version",
    "type",
];

/// The members of the `quorum` block (D5).
pub const QUORUM_FIELDS: &[&str] = &[
    "by_job",
    "default",
    "max_attempts",
    "requirements",
    "reveal_mode",
];
/// The members of one selection: `SelectionPolicy` verbatim (D2).
pub const SELECTION_FIELDS: &[&str] = &[
    "max_per_identity",
    "n",
    "required_agree",
    "reserves",
    "tier_caps",
    "tier_floor",
];
/// The members of `quorum.requirements`: `Requirements` verbatim (D2).
pub const REQUIREMENTS_FIELDS: &[&str] = &[
    "arch",
    "disk_mb",
    "image_digests",
    "min_sandbox_level",
    "ram_mb",
    "sandboxes",
];

/// The two spellings of one machine, resolved the way `Arch` canonicalises them
/// (D5's `arch_conflict` row: `amd64` and `x86_64` are one machine).
pub const ARCH_ALIASES: &[(&str, &str)] = &[
    ("x86_64", "x86_64"),
    ("amd64", "x86_64"),
    ("x64", "x86_64"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
];

/// Sandbox names that mean "nothing confined this", and may never be demanded (D5).
///
/// A superset of [`gitiup_attest::NO_SANDBOX_ALIASES`]: `plain` and `inprocess` are
/// the names the sandbox crate uses for rung 0, and a policy that demands them is
/// demanding the absence of confinement under a different spelling.
pub const FORBIDDEN_SANDBOXES: &[&str] = &["", "none", "off", "no", "plain", "inprocess"];

// --------------------------------------------------------------------------
// The refusal: a token, a detail, and the exit code the token decides
// --------------------------------------------------------------------------

/// The named refusals of ADR-0004 D9.
///
/// One constant per token so a test can compare against the name and not against a
/// string typed twice. The table is the 32 rows of
/// `cases.json:refusals`; the last three are refusals of the *resolution* or of the
/// publish step, which D4 and D8 place outside the document table but inside the same
/// exit-code taxonomy.
pub mod token {
    /// The document is not signed at all (D3 step 1).
    pub const UNSIGNED: &str = "unsigned";
    /// Zero or more than one signature (D2: exactly one).
    pub const SIGNATURE_COUNT: &str = "signature_count";
    /// The signer is not the `owner` the document names (D3).
    pub const OWNER_MISMATCH: &str = "owner_mismatch";
    /// The signature does not verify (D9 step 2).
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// A `key_id` that is not the fingerprint of the key offered (D9 step 2).
    pub const KEY_ID_DERIVATION: &str = "key_id_derivation";
    /// The signer is not one of the verifier's trust roots (D3 step 3).
    pub const SIGNER_UNTRUSTED: &str = "signer_untrusted";
    /// `--trust-any-key` reached a policy decision (D3: it may not).
    pub const TRUST_ANY_KEY: &str = "trust_any_key";
    /// The bytes are over [`MAX_POLICY_BYTES`] (D10).
    pub const SIZE_EXCEEDED: &str = "size_exceeded";
    /// The bytes are not their own canonical form (D9 step 1).
    pub const NOT_CANONICAL: &str = "not_canonical";
    /// A stored object is not the bytes its `kv/` key promises (D7).
    pub const DIGEST_MISMATCH: &str = "digest_mismatch";
    /// An unknown field, at any level (D2: unknown fields are the version negotiation).
    pub const FIELD_UNKNOWN: &str = "field_unknown";
    /// A required field is absent (D2).
    pub const FIELD_MISSING: &str = "field_missing";
    /// A field is present but not of the shape the format requires (D2).
    pub const FIELD_SHAPE: &str = "field_shape";
    /// `type` or `schema_version` this build does not speak (D10).
    pub const UNKNOWN_SCHEMA: &str = "unknown_schema";
    /// `revision` is not a positive integer (D6).
    pub const REVISION_INVALID: &str = "revision_invalid";
    /// `previous_digest` is not a `sha256:` digest (D6).
    pub const PREVIOUS_DIGEST_SHAPE: &str = "previous_digest_shape";
    /// `effective_from_us` is not an integer (D6).
    pub const EFFECTIVE_FROM_SHAPE: &str = "effective_from_shape";
    /// `expires_at_us <= effective_from_us`: dead on arrival (D6).
    pub const EXPIRES_BEFORE_EFFECTIVE: &str = "expires_before_effective";
    /// The policy has already expired on the read path (D6).
    pub const EXPIRED: &str = "expired";
    /// The policy takes effect further in the future than the skew allowance (D6).
    pub const FUTURE_DATED: &str = "future_dated";
    /// `owner` is not `{key_id, principal}`, or a part of it is malformed (D2).
    pub const OWNER_SHAPE: &str = "owner_shape";
    /// `protects` is empty, too long, or a glob too long (D5).
    pub const PROTECTS_SHAPE: &str = "protects_shape";
    /// A `protects` glob outside `refs/heads/**` (D1, D5: a policy gates what is
    /// trusted, never what is merely offered).
    pub const PROTECTS_OUT_OF_SCOPE: &str = "protects_out_of_scope";
    /// The annotation bag is bigger than the hatch allows (D10).
    pub const ANNOTATION_SHAPE: &str = "annotation_shape";
    /// An annotation key is not `x_<producer>_<name>` (D10).
    pub const ANNOTATION_KEY_SHAPE: &str = "annotation_key_shape";
    /// No trust anchors: a policy that trusts nobody can never be satisfied (D3).
    pub const NO_TRUST_ANCHORS: &str = "no_trust_anchors";
    /// A trust anchor is not shaped like a key id (D3).
    pub const ANCHOR_KEY_SHAPE: &str = "anchor_key_shape";
    /// A rules list is not sorted and deduplicated (D2: readers refuse, they do not
    /// re-normalise).
    pub const NOT_NORMALISED: &str = "not_normalised";
    /// `allowed_tiers` is empty (D5).
    pub const EMPTY_TIERS: &str = "empty_tiers";
    /// A tier outside `simulated`/`local`/`quorum` (D5).
    pub const TIER_UNKNOWN: &str = "tier_unknown";
    /// `min_signatures: 0` — unsigned proofs, smuggled in through a field (D5).
    pub const MIN_SIGNATURES_ZERO: &str = "min_signatures_zero";
    /// A roster tier that does not exist, as a floor or a cap (D5).
    pub const TIER_FLOOR_UNKNOWN: &str = "tier_floor_unknown";
    /// A `tier_caps` tier that does not exist (D5).
    pub const TIER_CAPS_UNKNOWN: &str = "tier_caps_unknown";
    /// `quorum.default.required_agree` is 0 (D5).
    pub const REQUIRED_AGREE_ZERO: &str = "required_agree_zero";
    /// `required_agree > n`: can never complete (D5).
    pub const REQUIRED_AGREE_UNREACHABLE: &str = "required_agree_unreachable";
    /// `n` of 0, or `max_per_identity` of 0 (D5).
    pub const SELECTION_SHAPE: &str = "selection_shape";
    /// The `quorum` block carries a member that is not one of
    /// `default`/`by_job`/`requirements`/`reveal_mode`/`max_attempts`.
    pub const QUORUM_SHAPE: &str = "quorum_shape";
    /// `quorum.reveal_mode` names a reveal mode this build cannot enforce (giti-zp1.6).
    pub const QUORUM_REVEAL_MODE: &str = "quorum_reveal_mode";
    /// `quorum.max_attempts` is not a number of attempts this build will run (giti-zp1.7):
    /// 0 would allow no attempt, and a value above [`crate::escalate::MAX_MAX_ATTEMPTS`]
    /// is a way of saying "never stop" in the one field that exists to say "stop".
    pub const QUORUM_ATTEMPTS: &str = "quorum_attempts";
    /// `quorum` is an allowed tier with nothing to decide it (D5).
    pub const QUORUM_WITHOUT_RULES: &str = "quorum_without_rules";
    /// Quorum numbers published while the tier refuses quorum (D5).
    pub const TIER_NOT_ALLOWED: &str = "tier_not_allowed";
    /// No sandbox can satisfy the requirement: empty set, or a zero resource floor
    /// (D5).
    pub const REQUIREMENTS_UNSATISFIABLE: &str = "requirements_unsatisfiable";
    /// `quorum.requirements.sandboxes` and `rules.allowed_sandboxes` have nothing in
    /// common: the policy argues with itself (D5).
    pub const SANDBOX_DISJOINT: &str = "sandbox_disjoint";
    /// A sandbox rung below [`MIN_SANDBOX_LEVEL`] demanded (D5).
    pub const SANDBOX_FLOOR: &str = "sandbox_floor";
    /// An unconfined sandbox demanded by name (`none`, `plain`, …) (D5).
    pub const SANDBOX_FORBIDDEN: &str = "sandbox_forbidden";
    /// `require_env_match: "off"` with an environment requirement published (D5).
    pub const ENV_MATCH_OFF: &str = "env_match_off";
    /// `require_env_match` is not `strict`/`major`/`off` (D5).
    pub const ENV_MATCH_UNKNOWN: &str = "env_match_unknown";
    /// `allow_simulated` contradicts `allowed_tiers` (D2, D5).
    pub const SIMULATED_CONTRADICTION: &str = "simulated_contradiction";
    /// The two arches in one document name different machines (D5).
    pub const ARCH_CONFLICT: &str = "arch_conflict";
    /// An arch that is not spelled the way `Arch` canonicalises it (D5).
    pub const ARCH_NOT_CANONICAL: &str = "arch_not_canonical";
    /// `previous_digest` names a document the reader cannot find (D6).
    pub const CHAIN_BROKEN: &str = "chain_broken";
    /// `revision` skips, or genesis is not revision 1 (D6).
    pub const REVISION_GAP: &str = "revision_gap";
    /// A predecessor takes effect no earlier than its successor (D6).
    pub const EFFECTIVE_FROM_BACKWARDS: &str = "effective_from_backwards";
    /// Nothing in the chain had taken effect at the run's timestamp (D6).
    pub const POLICY_HISTORY_MISSING: &str = "policy_history_missing";
    /// The policy selected by the walk had already expired at the run's timestamp (D6).
    pub const EXPIRED_HISTORY: &str = "expired_history";
    /// The chain is longer than [`MAX_CHAIN_WALK`] (D10).
    pub const CHAIN_TOO_LONG: &str = "chain_too_long";
    /// A gate found nothing gate-eligible (D4).
    pub const NO_POLICY_PUBLISHED: &str = "no_policy_published";
    /// A per-decision binding (`expected_commit`, `expected_result_digest`) was
    /// offered for publication (D5: publish refuses them, the vocabulary does not).
    pub const PER_DECISION_BINDING: &str = "per_decision_binding";
    /// The store advertises a policy whose bytes it cannot return (D7).
    pub const MISSING_BLOB: &str = "missing_blob";
}

/// The exit code a token maps to: ADR-0001 D7's taxonomy, unchanged (D9).
///
/// Everything is 6 — "refused, and this build understands what you asked" — except
/// the two identity-class failures (7) and the two "these are not the bytes" failures
/// (8). `key_id_derivation` is 7 for ADR-0003 D11's reason: the bytes are fine and
/// the identity claim is not.
pub fn exit_code_of(token: &str) -> u8 {
    match token {
        token::BAD_SIGNATURE | token::KEY_ID_DERIVATION => 7,
        token::NOT_CANONICAL | token::DIGEST_MISMATCH => 8,
        _ => 6,
    }
}

/// A refusal of a published policy: the token, the detail, and the exit code the
/// token decides.
///
/// The token is the interface (D9). `.3`, `.4` and `.5` render these refusals in
/// their own output, and a script branches on the code while a human reads the token
/// and the detail, so both are carried and neither is derived from a message string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// One of [`token`]'s names.
    pub token: &'static str,
    /// What specifically was wrong, for a human.
    pub detail: String,
    /// What to do about it, if there is anything to do.
    pub hint: Option<String>,
}

impl PolicyError {
    /// A refusal naming `token`.
    pub fn new(token: &'static str, detail: impl Into<String>) -> PolicyError {
        PolicyError {
            token,
            detail: detail.into(),
            hint: None,
        }
    }

    /// Attach a hint (printed by the CLI on its own line).
    pub fn with_hint(mut self, hint: impl Into<String>) -> PolicyError {
        self.hint = Some(hint.into());
        self
    }

    /// The token name.
    pub fn token(&self) -> &'static str {
        self.token
    }

    /// The exit code this refusal carries (6, 7 or 8).
    pub fn exit_code(&self) -> u8 {
        exit_code_of(self.token)
    }

    /// The process exit code, spelled for call sites that want the word.
    pub fn code(&self) -> u8 {
        self.exit_code()
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.token, self.detail)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyError {}

/// The crate's error, for a refusal that came from somewhere else (a store failure,
/// an attestation primitive) and a policy refusal that carries its token.
pub type PolicyResult<T> = std::result::Result<T, PolicyError>;

/// A policy refusal is a refusal in the crate's own taxonomy too: the exit code is
/// already decided by the token, so wrapping it must not change it.
impl From<PolicyError> for crate::error::Error {
    fn from(error: PolicyError) -> crate::error::Error {
        use gitiup_attest::{Error as AttestError, ErrorKind};
        let kind = match error.exit_code() {
            7 => ErrorKind::Signature,
            8 => ErrorKind::DigestMismatch,
            // `unsigned`, `signer_untrusted`, every incoherence: a refusal this build
            // understands, which is what 6 already means.
            _ => ErrorKind::Policy,
        };
        let detail = format!("{}: {}", error.token, error.detail);
        let wrapped = AttestError::new(kind, "policy", detail);
        let wrapped = match error.hint {
            Some(hint) => wrapped.with_hint(hint),
            None => wrapped,
        };
        crate::error::Error::from(wrapped)
    }
}

/// A canonicaliser or format-crate failure, converted to the policy's own taxonomy.
///
/// The canonicaliser's size limit is `size_exceeded` and not `not_canonical`: an
/// oversized document is refused (6), it is not a mis-hash (8).
impl From<gitiup_attest::Error> for PolicyError {
    fn from(error: gitiup_attest::Error) -> PolicyError {
        let detail = format!("{}: {}", error.context(), error.detail());
        if error.detail().contains("limit") {
            PolicyError::new(token::SIZE_EXCEEDED, detail)
        } else {
            match error.kind() {
                gitiup_attest::ErrorKind::DigestMismatch => {
                    PolicyError::new(token::NOT_CANONICAL, detail)
                }
                _ => PolicyError::new(token::FIELD_SHAPE, detail),
            }
        }
    }
}

/// Fail with a token, in the style of the ADR's `require(...)`.
macro_rules! refuse {
    ($name:expr, $detail:expr) => {
        return Err(PolicyError::new($name, $detail))
    };
}

// --------------------------------------------------------------------------
// The document (ADR-0004 D2)
// --------------------------------------------------------------------------

/// Who set these rules: the identity whose signature is required and whose key id a
/// report prints (D2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOwner {
    /// `SHA256:…`, derived from a key and never typed (D3).
    pub key_id: String,
    /// Display name, at most [`MAX_PRINCIPAL_BYTES`] bytes; printed, not checked.
    pub principal: String,
}

/// The `quorum` block: the numbers that decide a round, and what a repository may
/// demand of a verifier (D5).
///
/// `default` and each `by_job` entry are [`SelectionPolicy`] and `requirements` is
/// [`Requirements`] — the same types ADR-0002 defines, with no translation, which *is*
/// the decision D5 makes: a field added to `SelectionPolicy` appears in published
/// policies automatically and refuses the same way in both places. `giti-zp1.2` reads
/// a round's numbers out of here rather than out of a flag, so the tier a repository
/// demands is data the owner signed and not something the caller chose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumBlock {
    /// The numbers for any job that does not match a `by_job` glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<SelectionPolicy>,
    /// Per-job overrides, keyed by glob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_job: Option<BTreeMap<String, SelectionPolicy>>,
    /// What a verifier must be able to do to be seated at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Requirements>,
    /// How the rounds this policy opens are submitted: `"open"` (the default) or
    /// `"sealed"`, where every seat publishes `H(attestation bytes ‖ slot ‖ challenge)`
    /// before it publishes the bytes ([giti-zp1.6](../../../README.md),
    /// [`crate::commit`]).
    ///
    /// It belongs to the *owner's* signed rules rather than to a flag for the same reason
    /// `n` and `required_agree` do: the person submitting a change must not get to choose
    /// how much independence its verification has, and a fork must not be able to un-seal
    /// an upstream's rounds. Absent means `open`, and the field is skipped when absent so
    /// every policy published before it exists keeps its bytes and its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reveal_mode: Option<String>,
    /// How many attempts one job may have: `1` is the first round alone, `3` (the default)
    /// is the first round plus two retries, and exhausting the cap is terminal
    /// ([`crate::escalate`], giti-zp1.7).
    ///
    /// Owner-signed for the same reason as every other number here: the person re-running a
    /// flaky test at midnight must not be the one who decides how many times it may be
    /// re-run, because the cost of each attempt is paid by a roster of volunteers. Absent
    /// means [`crate::escalate::DEFAULT_MAX_ATTEMPTS`], and the field is skipped when
    /// absent so every policy published before it exists keeps its bytes and its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<u32>,
}

impl QuorumBlock {
    /// Whether the block decides nothing: no default and no per-job numbers.
    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.by_job.as_ref().is_none_or(|m| m.is_empty())
    }

    /// The reveal mode the rounds this block opens must use: the block's, or `open`
    /// when it says nothing.
    ///
    /// The default is a literal, not a fall-through to `SelectionPolicy`: an absent field
    /// has to mean exactly what an absent field meant before this one existed.
    pub fn effective_reveal_mode(&self) -> &str {
        self.reveal_mode
            .as_deref()
            .unwrap_or(crate::round::REVEAL_MODE_OPEN)
    }

    /// How many attempts a job of this policy may have: the block's, or
    /// [`crate::escalate::DEFAULT_MAX_ATTEMPTS`] when it says nothing.
    ///
    /// An absent field means the default and nothing else; a value that was checked on the
    /// way in ([`crate::escalate::validate_max_attempts`], which `publish` runs) is used
    /// verbatim.
    pub fn effective_max_attempts(&self) -> u32 {
        self.max_attempts
            .unwrap_or(crate::escalate::DEFAULT_MAX_ATTEMPTS)
    }

    /// The selection for a job id: the longest `by_job` glob that matches, else the
    /// default. Glob matching is the same `*`-suffix style `protects` uses, and is
    /// deliberately dull: a round must be able to explain its own numbers.
    pub fn selection_for(&self, job: &str) -> Option<&SelectionPolicy> {
        let mut best: Option<(&str, &SelectionPolicy)> = None;
        for (glob, policy) in self.by_job.iter().flatten() {
            if glob_matches(glob, job) && best.is_none_or(|(g, _)| glob.len() > g.len()) {
                best = Some((glob.as_str(), policy));
            }
        }
        best.map(|(_, policy)| policy).or(self.default.as_ref())
    }
}

/// A `gitiup-policy-1` document: twelve members, one signature, one canonical form.
///
/// This is what a verdict cites and what a report prints. Build one with
/// [`NewPolicy`], sign it, publish it with [`publish`]; read one back with
/// [`verify_bytes`] (which is the only way to get one, because a policy that was
/// never checked is the "the store said so" bug).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Must be [`POLICY_TYPE`].
    #[serde(rename = "type")]
    pub record_type: String,
    /// Must be [`POLICY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Whose rules these are (D3).
    pub owner: PolicyOwner,
    /// ≥ 1, exactly one more than its predecessor (D6).
    pub revision: u32,
    /// The predecessor's `body_digest`, or [`GENESIS_PREVIOUS`] (D6).
    pub previous_digest: String,
    /// The first microsecond these rules count (D6).
    pub effective_from_us: i64,
    /// When they stop counting; absent means "until superseded" (D6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_us: Option<i64>,
    /// 1–32 globs, all inside `refs/heads/**` (D1, D5).
    pub protects: Vec<String>,
    /// The proof-acceptance rules: [`PolicyFile`] verbatim (D2).
    pub rules: PolicyFile,
    /// The tier-`quorum` block, when the policy has one (D5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<QuorumBlock>,
    /// The sanctioned hatch: `x_<producer>_<name>` only (D10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
    /// Exactly one entry, by `owner` (D2). Empty means unsigned, and an unsigned
    /// policy is a refusal (`unsigned`), never a policy with a warning (D3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SignatureEntry>,
}

/// Everything needed to make one, except the chain position (which comes from the
/// store) and the signature (which comes from a key).
#[derive(Debug, Clone, Default)]
pub struct NewPolicy {
    /// Who is signing.
    pub owner: PolicyOwner,
    /// What the policy gates.
    pub protects: Vec<String>,
    /// The proof rules.
    pub rules: PolicyFile,
    /// The quorum block, if the policy names one.
    pub quorum: Option<QuorumBlock>,
    /// When the rules start counting.
    pub effective_from_us: i64,
    /// When they stop, if ever.
    pub expires_at_us: Option<i64>,
    /// The hatch.
    pub annotations: Option<BTreeMap<String, String>>,
    /// Which revision this is (D6): 1 for a store's first.
    pub revision: u32,
    /// The predecessor's body digest (D6): [`GENESIS_PREVIOUS`] for the first.
    pub previous_digest: String,
}

impl NewPolicy {
    /// The genesis position: revision 1, no predecessor.
    pub fn genesis() -> NewPolicy {
        NewPolicy {
            revision: 1,
            previous_digest: GENESIS_PREVIOUS.to_string(),
            ..Default::default()
        }
    }

    /// The document, unsigned.
    pub fn build(&self) -> PolicyDocument {
        PolicyDocument {
            record_type: POLICY_TYPE.to_string(),
            schema_version: POLICY_SCHEMA_VERSION,
            owner: self.owner.clone(),
            revision: self.revision,
            previous_digest: self.previous_digest.clone(),
            effective_from_us: self.effective_from_us,
            expires_at_us: self.expires_at_us,
            protects: self.protects.clone(),
            rules: self.rules.clone(),
            quorum: self.quorum.clone(),
            annotations: self.annotations.clone(),
            signatures: Vec::new(),
        }
    }
}

/// A body digest, or a record digest: always `sha256:<64 lower-case hex>`.
fn hex_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", gitiup_attest::Digest::sha256(bytes).hex())
}

impl PolicyDocument {
    /// The document as a JSON value, at the one place it is serialised.
    pub fn value(&self) -> PolicyResult<Value> {
        serde_json::to_value(self)
            .map_err(|e| PolicyError::new(token::FIELD_SHAPE, format!("cannot serialise: {e}")))
    }

    /// The stored bytes: canonical, signature included (D2).
    pub fn canonical_bytes(&self) -> PolicyResult<Vec<u8>> {
        let bytes = canon::to_value_bytes(&self.value()?)?;
        check_size(&bytes)?;
        Ok(bytes)
    }

    /// The signed body: canonical bytes with `signatures` removed (D2).
    ///
    /// Computable before anybody signs, which is what `--dry-run` prints and what
    /// keeps a chain link stable across a re-encode of the signature list.
    pub fn body_bytes(&self) -> PolicyResult<Vec<u8>> {
        let mut value = self.value()?;
        if let Some(map) = value.as_object_mut() {
            map.remove("signatures");
        }
        let bytes = canon::to_value_bytes(&value)?;
        check_size(&bytes)?;
        Ok(bytes)
    }

    /// `sha256(body_bytes)`: **the policy's identity** — what a verdict cites, what
    /// `previous_digest` names, what `ChangeRecord::policy_digest` holds (D2, D4).
    pub fn body_digest(&self) -> PolicyResult<String> {
        Ok(hex_digest(&self.body_bytes()?))
    }

    /// `sha256(stored bytes)`: the `kv/policy/<hex>` key (D2, D7).
    pub fn record_digest(&self) -> PolicyResult<String> {
        Ok(hex_digest(&self.canonical_bytes()?))
    }

    /// The record digest as a host oid, for `kv/` work.
    pub fn record_oid(&self) -> PolicyResult<Oid> {
        let hex = self.record_digest()?;
        Oid::from_hex(hex.split_once(':').map(|(_, h)| h).unwrap_or(&hex))
            .map_err(|e| PolicyError::new(token::FIELD_SHAPE, format!("{e}")))
    }

    /// The bare hex of the record digest, as `cases.json` writes it in `kv/`.
    pub fn record_hex(&self) -> PolicyResult<String> {
        Ok(self.record_oid()?.hex().to_string())
    }

    /// Sign with `key`: one signature, over `PAE(payload type, body bytes)`.
    ///
    /// The `key_id` in the entry is derived from the key offered, never supplied:
    /// a typed fingerprint is `key_id_derivation` on the way back in (D3).
    pub fn sign(&mut self, key: &dyn Signer) -> PolicyResult<()> {
        if !self.signatures.is_empty() {
            refuse!(
                token::SIGNATURE_COUNT,
                "this document already carries a signature; a policy has exactly one signer"
            );
        }
        let message = pae(POLICY_PAYLOAD_TYPE, &self.body_bytes()?);
        self.signatures
            .push(SignatureEntry::new(key, &message).map_err(|e| {
                PolicyError::new(token::BAD_SIGNATURE, format!("cannot sign: {e}"))
            })?);
        Ok(())
    }

    /// The one signature, if there is exactly one (D2).
    pub fn signature(&self) -> Option<&SignatureEntry> {
        self.signatures
            .first()
            .filter(|_| self.signatures.len() == 1)
    }

    /// Which refs this policy gates (D1: only what is trusted).
    pub fn protects(&self) -> &[String] {
        &self.protects
    }

    /// Does this policy name `reference` at all? A glob like `refs/heads/**` covers
    /// the branch a push updates, and a policy that does not cover it is not in force
    /// for it (`.4` and `.5` both need this question and must ask it the same way).
    pub fn protects_ref(&self, reference: &str) -> bool {
        self.protects
            .iter()
            .any(|glob| glob_matches(glob, reference))
    }

    /// The proof-acceptance rules as a [`Policy`], i.e. what
    /// `gitiup verify attestation` was given with `--policy` before any of this
    /// existed (D2: one vocabulary, two authorities).
    ///
    /// `at_us` pins the clock so a run is judged by the freshness window of the
    /// policy that was in force when it happened (D6).
    pub fn to_policy(&self, at_us: Option<i64>) -> PolicyResult<Policy> {
        reject_bindings(&self.rules)?;
        let mut policy = self
            .rules
            .to_policy()
            .map_err(|e| PolicyError::new(token::FIELD_SHAPE, e.detail().to_string()))?;
        if let Some(at) = at_us {
            policy.now = Some(TimeUs(at));
        }
        Ok(policy)
    }

    /// The publish-time warnings (D8): legitimate, frequently a mistake, never a
    /// refusal.
    ///
    /// The four are exactly the rows of D8's table, and `cases.json:policies[*].warnings`
    /// pins their order and wording for the fixtures.
    pub fn warnings(&self, roots: &Trust, now: TimeUs) -> Vec<String> {
        let mut out = Vec::new();
        let anchors: BTreeSet<String> = self.rules.trust_key_ids.iter().cloned().collect();
        if anchors.is_empty() || !anchors.iter().any(|id| roots.trusts(id)) {
            out.push(
                "none of the trust anchors is a key this machine holds: correct when a CI \
                 runner signs and the owner publishes, a mistake if you meant to sign yourself"
                    .to_string(),
            );
        }
        if let Some(expires) = self.expires_at_us
            && expires - now.0 < EXPIRY_WARNING_US
        {
            out.push(
                "the policy expires within a week; a policy that expires silently stops a \
                 merge gate the same day"
                    .to_string(),
            );
        }
        if let Some(quorum) = &self.quorum {
            let mut entries: Vec<(String, &SelectionPolicy)> = Vec::new();
            if let Some(default) = &quorum.default {
                entries.push(("quorum.default".to_string(), default));
            }
            for (glob, selection) in quorum.by_job.iter().flatten() {
                entries.push((format!("quorum.by_job[{glob}]"), selection));
            }
            for (where_, selection) in entries {
                if selection.required_agree == selection.n {
                    out.push(format!(
                        "{where_} demands unanimity: one verifier that is offline is no \
                         verdict, and the escalation round asks for more"
                    ));
                }
            }
        }
        if self
            .rules
            .max_age_us
            .is_some_and(|age| age > MAX_AGE_WARNING_US)
        {
            out.push(
                "the freshness window is over a week: how long a policy change can be \
                 dodged with an old proof (D6)"
                    .to_string(),
            );
        }
        out
    }
}

/// Refuse the two fields that are decisions, not rules (D5).
///
/// `expected_commit` and `expected_result_digest` stay in the vocabulary — one
/// vocabulary for "what a proof must satisfy" is D2's whole point — but a
/// *published* rule that pinned a commit could only ever be satisfied by that one
/// commit, so `gitiup policy publish` refuses to write them. This is a publish-side
/// refusal, not a reader refusal: the reader of an old document is not the party
/// that made the decision.
pub fn reject_bindings(rules: &PolicyFile) -> PolicyResult<()> {
    for (field, present) in [
        ("expected_commit", rules.expected_commit.is_some()),
        (
            "expected_result_digest",
            rules.expected_result_digest.is_some(),
        ),
    ] {
        if present {
            return Err(PolicyError::new(
                token::PER_DECISION_BINDING,
                format!("`rules.{field}` is a per-decision input, not a published rule"),
            )
            .with_hint(
                "the caller supplies it on the command line, for one decision; a policy \
             that pinned a commit could only ever be satisfied by that commit (ADR-0004 D5)",
            ));
        }
    }
    Ok(())
}

/// A `*`-suffix glob, matched the way `protects` and `by_job` are written:
/// `refs/heads/**` covers everything under it, `arm-*` covers one segment prefix.
pub fn glob_matches(glob: &str, value: &str) -> bool {
    if let Some(prefix) = glob.strip_suffix("**") {
        return value.starts_with(prefix);
    }
    if let Some(prefix) = glob.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    glob == value
}

/// The bound every gitiup record shares, applied to a policy at the tighter value D10
/// fixes (and checked before the bytes are parsed: an oversized document is refused,
/// it is not a mis-hash).
fn check_size(bytes: &[u8]) -> PolicyResult<()> {
    if bytes.len() > MAX_POLICY_BYTES {
        refuse!(
            token::SIZE_EXCEEDED,
            format!(
                "{} bytes exceeds the {MAX_POLICY_BYTES} byte limit for a published policy",
                bytes.len()
            )
        );
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Validation (ADR-0004 D5, D6, D9) — the order D9 fixes
// --------------------------------------------------------------------------

/// The policies a reader can consult by `body_digest`, so a chain link can be checked
/// instead of believed (D6).
#[derive(Debug, Clone, Default)]
pub struct History {
    entries: BTreeMap<String, PolicyDocument>,
}

impl History {
    /// An empty history: only a genesis policy can be validated against it.
    pub fn new() -> History {
        History::default()
    }

    /// Index documents by their body digest.
    pub fn from_docs<I, D>(docs: I) -> PolicyResult<History>
    where
        I: IntoIterator<Item = D>,
        D: std::borrow::Borrow<PolicyDocument>,
    {
        let mut history = History::default();
        for doc in docs {
            history.insert(doc.borrow())?;
        }
        Ok(history)
    }

    /// Add one document, keyed by the digest a successor names.
    pub fn insert(&mut self, doc: &PolicyDocument) -> PolicyResult<()> {
        self.entries.insert(doc.body_digest()?, doc.clone());
        Ok(())
    }

    /// The predecessor a `previous_digest` names.
    pub fn get(&self, body_digest: &str) -> Option<&PolicyDocument> {
        self.entries.get(body_digest)
    }

    /// How many documents are known.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is known (the common case for a genesis policy).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every document known, oldest revision first.
    pub fn iter(&self) -> impl Iterator<Item = &PolicyDocument> {
        self.entries.values()
    }

    /// The union with another history: what the reader had, plus what the store
    /// turned out to carry (D6's walk needs all of it).
    pub fn merged_with(&self, other: &History) -> History {
        let mut entries = self.entries.clone();
        entries.extend(other.entries.clone());
        History { entries }
    }
}

/// What a reader brings to a policy check: the roots it trusts, the history it
/// happens to have, and the clock.
///
/// All three are *the reader's*, which is the point: the trust roots are local
/// configuration (D3), the clock is pinned by the run being judged (D6), and the
/// history is whatever the store carried (D7). A policy document cannot supply any of
/// them to itself.
#[derive(Debug)]
pub struct Context<'a> {
    /// Whose signature counts as the owner's.
    pub trust: &'a Trust,
    /// Predecessors, for the chain.
    pub history: &'a History,
    /// The clock the dates are judged against.
    pub now: TimeUs,
}

impl<'a> Context<'a> {
    /// A context with no history: enough for a genesis policy, and a refusal for any
    /// other revision (which is correct — an unverifiable predecessor means "which
    /// rules were in force then?" has no answer).
    pub fn new(trust: &'a Trust, now: TimeUs) -> Context<'a> {
        Context {
            trust,
            history: &EMPTY_HISTORY,
            now,
        }
    }

    /// With a history attached.
    pub fn with_history(mut self, history: &'a History) -> Context<'a> {
        self.history = history;
        self
    }
}

/// A clock for a context that has no history to consult.
static EMPTY_HISTORY: std::sync::LazyLock<History> = std::sync::LazyLock::new(History::new);

/// Check canonical bytes and return the document they describe: every step of D9, in
/// D9's order, and the typed read at the end.
///
/// This is the only honest way to obtain a [`PolicyDocument`] from bytes, which is why
/// it is a function and not a method: a policy that was never trusted-checked is not a
/// policy.
pub fn verify_bytes(bytes: &[u8], ctx: &Context<'_>) -> PolicyResult<PolicyDocument> {
    let (value, document) = check_self_contained(bytes, ctx)?;
    // Steps 3–7, once the container and the fields have been believed.
    validate_with(&value, ctx)?;
    // Last, and a property of the bytes like step 7: what the document *says* must be
    // what the bytes *say*, or a re-publish of the same rules could move a digest a
    // verdict already cited (D2).
    require_one_spelling(&document, bytes)?;
    Ok(document)
}

/// The mechanical half of "one spelling per fact": re-encoding the typed document must
/// reproduce the bytes it came from.
///
/// An empty list where an absent field belongs is the case that gets caught — which is
/// the right answer for the same reason `not_normalised` is: the canonical spelling of
/// "no sandboxes named" is to not name any.
fn require_one_spelling(document: &PolicyDocument, bytes: &[u8]) -> PolicyResult<()> {
    let again = document.canonical_bytes()?;
    if again != bytes {
        return Err(PolicyError::new(
            token::NOT_NORMALISED,
            "the document is not in the canonical spelling this build writes",
        )
        .with_hint(
            "an empty list where an absent field belongs, or a field a reader would drop: \
             publish the tree file again with `gitiup policy publish`, which normalises (ADR-0004 D2)",
        ));
    }
    Ok(())
}

/// Steps 1–2 only: the bytes are their own canonical form, the fields are the fields,
/// the signature verifies and the identity is derived.
///
/// Split out because a store reader needs it for *history*: the blob behind
/// `refs/gitiup/policy/history/000003` must be a real signed policy before it is
/// believed as a predecessor, but whether its signer is somebody you trust is a
/// question about the policy in force, not about every document the store happens to
/// carry (D3). Returns the parsed value too, so the caller can finish the check
/// without re-encoding.
pub fn check_self_contained(
    bytes: &[u8],
    ctx: &Context<'_>,
) -> PolicyResult<(Value, PolicyDocument)> {
    // Step 1: the container, before the contents.
    check_size(bytes)?;
    let value = canon::read_canonical(bytes).map_err(|e| {
        PolicyError::new(
            token::NOT_CANONICAL,
            format!("{}: {}", e.context(), e.detail()),
        )
        .with_hint(
            "a published policy must be the canonical encoding byte for byte; a store that \
             re-serialises JSON has broken the signature it was holding",
        )
    })?;
    check_structure(&value, ctx)?;
    let document: PolicyDocument = match serde_json::from_value(value.clone()) {
        Ok(document) => document,
        Err(e) => {
            // The typed read failed, which means some field is not of the shape the
            // Rust types insist on. Run the named checks first when one of them can
            // say *which* field and why — `tier_floor: "famous"` is
            // `tier_floor_unknown`, not a serde message about an enum — and only fall
            // back to the generic shape refusal when none of them objects.
            if let Some(rules) = value.get("rules") {
                check_rules(rules)?;
                check_quorum(&value, rules)?;
            }
            return Err(PolicyError::new(
                token::FIELD_SHAPE,
                format!("cannot be read as a policy: {e}"),
            ));
        }
    };
    Ok((value, document))
}

/// Steps 2–7 of D9 on an already-parsed document: structure, trust, rules, quorum,
/// chain, normalisation.
///
/// The order is normative for the reason ADR-0001 D7 and ADR-0002 D7 give theirs: a
/// document that fails two checks must always report the same one, or two honest
/// implementations disagree about a document a human is auditing. A typo in a policy
/// prints the typo, not "bad signature" — which is why structure precedes trust.
pub fn validate(value: &Value, ctx: &Context<'_>) -> PolicyResult<()> {
    validate_with(value, ctx)
}

fn validate_with(value: &Value, ctx: &Context<'_>) -> PolicyResult<()> {
    check_structure(value, ctx)?;
    check_trust(value, ctx)?;
    let rules = value
        .get("rules")
        .ok_or_else(|| PolicyError::new(token::FIELD_MISSING, "`rules` is absent"))?;
    check_rules(rules)?;
    check_quorum(value, rules)?;
    check_chain(value, ctx)?;
    require_normalised(value)
}

/// Step 2: the fields, the dates, the derivation, the signature.
fn check_structure(value: &Value, ctx: &Context<'_>) -> PolicyResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| PolicyError::new(token::FIELD_SHAPE, "a policy is a JSON object"))?;
    let unknown = unknown_keys(object, POLICY_FIELDS);
    if !unknown.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_UNKNOWN,
            format!("unknown field(s): {}", unknown.join(", ")),
        )
        .with_hint(format!(
            "a v1 reader refuses what it does not know, so a new field is a version bump and \
             not a quiet change of rules; a policy may carry {}",
            POLICY_FIELDS.join(", ")
        )));
    }
    // The rule body is a schema too, refused here (and not after the signature) so a
    // typo prints the typo.
    let rules = object
        .get("rules")
        .ok_or_else(|| PolicyError::new(token::FIELD_MISSING, "`rules` is absent"))?;
    let rules = rules.as_object().ok_or_else(|| {
        PolicyError::new(
            token::FIELD_SHAPE,
            "`rules` must be an object of rule fields",
        )
    })?;
    let unknown_rules = unknown_keys(rules, PolicyFile::KEYS);
    if !unknown_rules.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_UNKNOWN,
            format!("unknown rule field(s): {}", unknown_rules.join(", ")),
        )
        .with_hint(format!(
            "the rule body is `gitiup-attest`'s `PolicyFile` verbatim; it accepts {}",
            PolicyFile::KEYS.join(", ")
        )));
    }
    let missing: Vec<&str> = REQUIRED_POLICY_FIELDS
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_MISSING,
            format!("missing field(s): {}", missing.join(", ")),
        ));
    }
    if value["type"] != POLICY_TYPE || value["schema_version"] != POLICY_SCHEMA_VERSION {
        refuse!(
            token::UNKNOWN_SCHEMA,
            format!(
                "type `{}` / schema_version {} is not a policy this build reads",
                value["type"].as_str().unwrap_or("?"),
                value["schema_version"]
            )
        );
    }
    let revision = value
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|r| *r >= 1)
        .ok_or_else(|| {
            PolicyError::new(
                token::REVISION_INVALID,
                "`revision` must be an integer >= 1 (ADR-0004 D6)",
            )
        })? as u32;
    let previous = string_field(value, "previous_digest").ok_or_else(|| {
        PolicyError::new(
            token::PREVIOUS_DIGEST_SHAPE,
            "`previous_digest` must be a `sha256:` digest",
        )
    })?;
    if digest_shape(previous).is_err() {
        return Err(PolicyError::new(
            token::PREVIOUS_DIGEST_SHAPE,
            format!("`previous_digest` '{previous}' is not `sha256:<64 lower-case hex>`"),
        ));
    }
    let effective_from = value
        .get("effective_from_us")
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            PolicyError::new(
                token::EFFECTIVE_FROM_SHAPE,
                "`effective_from_us` must be integer microseconds (ADR-0001 D6)",
            )
        })?;
    // The skew allowance is the rule's own, when it names one: the clock-quality
    // bound ADR-0001 D6 already accepts, not a new number (D6).
    let skew = object
        .get("rules")
        .and_then(|r| r.get("max_clock_skew_us"))
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_MAX_CLOCK_SKEW_US);
    if let Some(expires) = value.get("expires_at_us").and_then(Value::as_i64) {
        if expires <= effective_from {
            return Err(PolicyError::new(
                token::EXPIRES_BEFORE_EFFECTIVE,
                format!(
                    "`expires_at_us` {expires} is not after `effective_from_us` {effective_from}: \
                     a document that is dead on arrival"
                ),
            ));
        }
        if expires <= ctx.now.0 {
            return Err(PolicyError::new(
                token::EXPIRED,
                format!(
                    "this policy expired {} ago (ADR-0004 D6)",
                    gitiup_attest::human_duration_us(ctx.now.0 - expires)
                ),
            )
            .with_hint(
                "a published-but-expired policy is a broken gate, and a gate that says \
                 nothing is better than one that quietly stopped",
            ));
        }
    }
    if effective_from > ctx.now.0 + skew {
        return Err(PolicyError::new(
            token::FUTURE_DATED,
            format!(
                "this policy takes effect {} from now, which is more than the {} clock-skew allowance",
                gitiup_attest::human_duration_us(effective_from - ctx.now.0),
                gitiup_attest::human_duration_us(skew)
            ),
        )
        .with_hint("a policy cannot be in force before it exists"));
    }

    // owner: who set these rules. `principal` is display only, and length-bounded
    // because it is printed.
    let owner = object
        .get("owner")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            PolicyError::new(token::OWNER_SHAPE, "`owner` must be {{key_id, principal}}")
        })?;
    let owner_unknown = unknown_keys(owner, &["key_id", "principal"]);
    if !owner_unknown.is_empty() || owner.len() != 2 {
        return Err(PolicyError::new(
            token::OWNER_SHAPE,
            format!(
                "`owner` is exactly `key_id` and `principal`{}",
                if owner_unknown.is_empty() {
                    String::new()
                } else {
                    format!(", not {}", owner_unknown.join(", "))
                }
            ),
        ));
    }
    let owner_key = string_field(&value["owner"], "key_id").unwrap_or_default();
    if key_id_shape(owner_key).is_err() {
        return Err(PolicyError::new(
            token::OWNER_SHAPE,
            format!("`owner.key_id` '{owner_key}' is not `SHA256:<43 base64 characters>`"),
        ));
    }
    let principal = string_field(&value["owner"], "principal").unwrap_or_default();
    if principal.is_empty() || principal.len() > MAX_PRINCIPAL_BYTES {
        return Err(PolicyError::new(
            token::OWNER_SHAPE,
            format!(
                "`owner.principal` must be 1..{MAX_PRINCIPAL_BYTES} bytes; it is printed, and it is not a free text body"
            ),
        ));
    }

    // protects: what this policy gates — and it gates only what is trusted (D1).
    let protects = object
        .get("protects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PolicyError::new(
                token::PROTECTS_SHAPE,
                "`protects` must be an array of globs",
            )
        })?;
    if protects.is_empty() || protects.len() > MAX_PROTECTS {
        return Err(PolicyError::new(
            token::PROTECTS_SHAPE,
            format!(
                "`protects` holds 1..{MAX_PROTECTS} globs and this one holds {}",
                protects.len()
            ),
        ));
    }
    for glob in protects {
        let Some(glob) = glob.as_str() else {
            return Err(PolicyError::new(
                token::PROTECTS_SHAPE,
                "`protects` entries are strings",
            ));
        };
        if glob.is_empty() || glob.len() > MAX_PROTECT_BYTES {
            return Err(PolicyError::new(
                token::PROTECTS_SHAPE,
                format!("the glob '{glob}' is not 1..{MAX_PROTECT_BYTES} bytes"),
            ));
        }
        if !glob.starts_with("refs/heads/") {
            return Err(PolicyError::new(
                token::PROTECTS_OUT_OF_SCOPE,
                format!("`protects` names '{glob}', which is outside `refs/heads/**`"),
            )
            .with_hint(
                "a policy gates what is *trusted*, never what is merely offered: \
                 refs/changes/** and refs/gitiup/** stay open to anyone the transport admits, \
                 and a policy that could gate its own ref could fence off the way it is \
                 replaced (ADR-0004 D1)",
            ));
        }
    }

    if let Some(notes) = object.get("annotations").and_then(Value::as_object) {
        if notes.len() > MAX_ANNOTATIONS {
            return Err(PolicyError::new(
                token::ANNOTATION_SHAPE,
                format!(
                    "{} annotations exceeds the {MAX_ANNOTATIONS} the hatch allows",
                    notes.len()
                ),
            ));
        }
        for (key, note) in notes {
            if !annotation_key_ok(key) {
                return Err(PolicyError::new(
                    token::ANNOTATION_KEY_SHAPE,
                    format!("annotation key '{key}' is not `x_<producer>_<name>`"),
                ));
            }
            let length = note.as_str().map(str::len).unwrap_or(usize::MAX);
            if length == 0 || length > MAX_ANNOTATION_BYTES {
                return Err(PolicyError::new(
                    token::ANNOTATION_SHAPE,
                    format!(
                        "the value of annotation '{key}' is 1..{MAX_ANNOTATION_BYTES} bytes of text"
                    ),
                ));
            }
        }
    }

    // Exactly one signature, by the owner, derived and verified (D3 steps 1–2).
    let signatures = object
        .get("signatures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if signatures.is_empty() {
        refuse!(
            token::UNSIGNED,
            "this policy is unsigned: nothing about it is authorised yet"
        );
    }
    if signatures.len() != 1 {
        return Err(PolicyError::new(
            token::SIGNATURE_COUNT,
            format!(
                "a policy carries exactly one signature and this one carries {}",
                signatures.len()
            ),
        )
        .with_hint(
            "\"two owners had to agree to change the rules\" is a roster question, not a \
             document-shape one (ADR-0004 D2)",
        ));
    }
    let entry: SignatureEntry = serde_json::from_value(signatures[0].clone()).map_err(|e| {
        PolicyError::new(
            token::FIELD_SHAPE,
            format!("the signature cannot be read: {e}"),
        )
    })?;
    if entry.key_id != owner_key {
        return Err(PolicyError::new(
            token::OWNER_MISMATCH,
            format!(
                "the policy is owned by {owner_key} and signed by {}",
                entry.key_id
            ),
        ));
    }
    let offered = gitiup_attest::key::PublicKey::from_openssh(&entry.public_key).map_err(|e| {
        PolicyError::new(
            token::KEY_ID_DERIVATION,
            format!("the public key offered does not parse: {}", e.detail()),
        )
    })?;
    if offered.key_id() != entry.key_id {
        return Err(PolicyError::new(
            token::KEY_ID_DERIVATION,
            format!(
                "key_id {} is not the fingerprint of the key offered ({}): a key id is derived, never typed",
                entry.key_id,
                offered.key_id()
            ),
        ));
    }
    let body = body_bytes_of(value)?;
    entry
        .verify(&pae(POLICY_PAYLOAD_TYPE, &body))
        .map_err(|e| {
            PolicyError::new(token::BAD_SIGNATURE, format!("{e}")).with_hint(
                "the bytes signed are the bytes with `signatures` removed, over the \
             `application/vnd.gitiup.policy+json` framing; a body edited afterwards is what \
             this refusal means",
            )
        })?;
    let _ = revision;
    Ok(())
}

/// Step 3: the signature is valid *and* the signer is somebody.
///
/// Note what is **not** checked here. The policy's own `trust_key_ids` are who may sign
/// an *attestation*; a repository whose owner publishes rules and whose CI runner signs
/// proofs is the normal case, not a mismatch (`personal` is that repository). The
/// verifier's trust roots decide who may set the rules, and the anchors decide who may
/// supply a proof — conflating them is the subtlest way to break this design (D3).
fn check_trust(value: &Value, ctx: &Context<'_>) -> PolicyResult<()> {
    if matches!(ctx.trust, Trust::AnyKeyForTests) {
        refuse!(
            token::TRUST_ANY_KEY,
            "a verdict about the rules cannot rest on \"any key that was lying around\""
        );
    }
    let signer = value
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(|entry| entry.get("key_id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !ctx.trust.trusts(signer) {
        return Err(PolicyError::new(
            token::SIGNER_UNTRUSTED,
            format!("this policy is signed by {signer}, which is not a key you trust"),
        )
        .with_hint(
            "the signer must be one of your trust roots (--owner, else this machine's \
             keystore). A fork's weaker policy signed with its own key is refused here, and \
             that is the whole inheritance mechanism (ADR-0004 D3)",
        ));
    }
    let anchors = string_array(value.get("rules").and_then(|r| r.get("trust_key_ids")));
    if anchors.is_empty() {
        return Err(PolicyError::new(
            token::NO_TRUST_ANCHORS,
            "`rules.trust_key_ids` is empty, so this policy trusts nobody and can never be satisfied",
        )
        .with_hint("name the keys that may sign a proof; an empty list is a gate that is always shut"));
    }
    for anchor in &anchors {
        if key_id_shape(anchor).is_err() {
            return Err(PolicyError::new(
                token::ANCHOR_KEY_SHAPE,
                format!("trust anchor '{anchor}' is not `SHA256:<43 base64 characters>`"),
            ));
        }
    }
    Ok(())
}

/// Step 4: the proof rules, so a *published* policy cannot say something the local
/// file parser would refuse (D2's one vocabulary, enforced in both directions).
fn check_rules(rules: &Value) -> PolicyResult<()> {
    let object = rules
        .as_object()
        .ok_or_else(|| PolicyError::new(token::FIELD_SHAPE, "`rules` must be an object"))?;
    if let Some(version) = object.get("schema_version")
        && version != &Value::from(POLICY_SCHEMA_VERSION)
    {
        return Err(PolicyError::new(
            token::UNKNOWN_SCHEMA,
            format!("`rules.schema_version` {version} is not understood"),
        ));
    }
    let tiers = match object.get("allowed_tiers") {
        Some(Value::Null) | None => vec!["local".to_string()],
        Some(list) => string_array(Some(list)),
    };
    if tiers.is_empty() {
        return Err(PolicyError::new(
            token::EMPTY_TIERS,
            "a policy that accepts no tier accepts no proof",
        )
        .with_hint("name at least one tier, usually `local`"));
    }
    for tier in &tiers {
        if Tier::parse(tier).is_err() {
            return Err(PolicyError::new(
                token::TIER_UNKNOWN,
                format!("'{tier}' is not a provenance tier"),
            )
            .with_hint("tiers are simulated, local and quorum; `cloud` is not a gitiup tier"));
        }
    }
    // The coherence rule `PolicyFile::from_json` already enforces, applied to a
    // published document: a policy that argues with itself is refused, not resolved by
    // a precedence nobody remembers.
    if let Some(allow) = object.get("allow_simulated").and_then(Value::as_bool)
        && object.contains_key("allowed_tiers")
        && allow != tiers.contains(&"simulated".to_string())
    {
        return Err(PolicyError::new(
            token::SIMULATED_CONTRADICTION,
            format!("`allow_simulated` is {allow} but `allowed_tiers` does not agree"),
        )
        .with_hint("say it once: drop `allow_simulated`, or make the two agree"));
    }
    if object
        .get("min_signatures")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        == 0
    {
        return Err(PolicyError::new(
            token::MIN_SIGNATURES_ZERO,
            "`min_signatures: 0` would accept an unsigned attestation, smuggled in through a field",
        ));
    }
    if let Some(match_) = object.get("require_env_match").and_then(Value::as_str)
        && EnvMatch::parse(match_).is_err()
    {
        return Err(PolicyError::new(
            token::ENV_MATCH_UNKNOWN,
            format!("`require_env_match` '{match_}' is not one of strict, major, off"),
        ));
    }
    let published: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| {
            key.starts_with("require_")
                && !matches!(*key, "require_env_match" | "require_normalisation_version")
        })
        .collect();
    let off = object
        .get("require_env_match")
        .and_then(Value::as_str)
        .is_some_and(|m| EnvMatch::parse(m).is_ok_and(|m| !m.is_enforced()));
    if off && !published.is_empty() {
        return Err(PolicyError::new(
            token::ENV_MATCH_OFF,
            format!(
                "`require_env_match` is `off` while a requirement is published ({})",
                published.join(", ")
            ),
        )
        .with_hint(
            "publishing a requirement and switching the comparison off is the silent failure \
             one level down: drop the require_* keys you no longer want enforced",
        ));
    }
    if let Some(list) = object.get("allowed_sandboxes").and_then(Value::as_array) {
        if list.len() > MAX_LIST_ITEMS {
            return Err(PolicyError::new(
                token::FIELD_SHAPE,
                format!("`rules.allowed_sandboxes` holds at most {MAX_LIST_ITEMS} names"),
            ));
        }
        for name in list.iter().filter_map(Value::as_str) {
            if FORBIDDEN_SANDBOXES.contains(&name) {
                return Err(PolicyError::new(
                    token::SANDBOX_FORBIDDEN,
                    format!("'{name}' means nothing was confined, which no repository may demand"),
                ));
            }
        }
    }
    Ok(())
}

/// Step 5: the quorum block — the numbers that decide a round, and what the
/// repository may ask of a verifier (D5).
///
/// Every refusal here is a demand that cannot be met, refused when it is written
/// rather than after a volunteer has fetched a repository, booted a container and
/// produced nothing. The same table is applied at selection time, so a round that
/// cannot be filled is never seated.
fn check_quorum(value: &Value, rules: &Value) -> PolicyResult<()> {
    let Some(quorum) = value.get("quorum") else {
        return Ok(());
    };
    if quorum.is_null() {
        return Ok(());
    }
    let object = quorum
        .as_object()
        .ok_or_else(|| PolicyError::new(token::QUORUM_SHAPE, "`quorum` must be an object"))?;
    let unknown = unknown_keys(object, QUORUM_FIELDS);
    if !unknown.is_empty() {
        return Err(PolicyError::new(
            token::QUORUM_SHAPE,
            format!(
                "unknown quorum field(s): {} (a quorum block carries {})",
                unknown.join(", "),
                QUORUM_FIELDS.join(", ")
            ),
        ));
    }
    if let Some(mode) = object.get("reveal_mode").filter(|v| !v.is_null()) {
        let mode = mode.as_str().ok_or_else(|| {
            PolicyError::new(
                token::QUORUM_REVEAL_MODE,
                "`quorum.reveal_mode` is a string: \"open\" or \"sealed\"",
            )
        })?;
        if !crate::round::REVEAL_MODES.contains(&mode) {
            return Err(PolicyError::new(
                token::QUORUM_REVEAL_MODE,
                format!(
                    "`quorum.reveal_mode` is '{mode}', which this build cannot enforce; it \
                     implements {}",
                    crate::round::REVEAL_MODES.join(", ")
                ),
            )
            .with_hint(
                "a policy may not ask for a submission rule this build cannot check: refuse \
                 the policy and let the selector decide whether to upgrade, rather than \
                 opening rounds that quietly run as \"open\"",
            ));
        }
    }
    if let Some(default) = object.get("default") {
        check_selection("quorum.default", default)?;
    }
    // The attempt cap, checked when it is written: a policy that says `0` or `10^9` is a
    // policy that does not mean what its owner typed, and finding that out after a hundred
    // volunteer-builds is not checking it.
    if let Some(attempts) = object.get("max_attempts").filter(|v| !v.is_null()) {
        let attempts = attempts.as_u64().ok_or_else(|| {
            PolicyError::new(
                token::QUORUM_ATTEMPTS,
                "`quorum.max_attempts` is a whole number of attempts (1 means \"no retry\")",
            )
        })?;
        let attempts = u32::try_from(attempts).map_err(|_| {
            PolicyError::new(
                token::QUORUM_ATTEMPTS,
                format!("`quorum.max_attempts` is {attempts}, which is not a count of anything"),
            )
        })?;
        crate::escalate::validate_max_attempts(attempts).map_err(|error| {
            PolicyError::new(
                token::QUORUM_ATTEMPTS,
                format!("`quorum.max_attempts`: {}", error.message()),
            )
        })?;
    }
    let by_job = object.get("by_job").filter(|v| !v.is_null());
    if let Some(by_job) = by_job {
        let map = by_job.as_object().ok_or_else(|| {
            PolicyError::new(
                token::QUORUM_SHAPE,
                "`quorum.by_job` is a map of glob to selection",
            )
        })?;
        if map.len() > MAX_BY_JOB {
            return Err(PolicyError::new(
                token::QUORUM_SHAPE,
                format!("`quorum.by_job` holds at most {MAX_BY_JOB} globs"),
            ));
        }
        for (glob, selection) in map {
            if glob.is_empty() || glob.len() > MAX_PROTECT_BYTES {
                return Err(PolicyError::new(
                    token::QUORUM_SHAPE,
                    format!("the `by_job` glob '{glob}' is not 1..{MAX_PROTECT_BYTES} bytes"),
                ));
            }
            check_selection(&format!("quorum.by_job[{glob}]"), selection)?;
        }
    }
    let tiers = string_array(rules.get("allowed_tiers"));
    let tiers = if tiers.is_empty() {
        vec!["local".to_string()]
    } else {
        tiers
    };
    let decides_anything = object.contains_key("default")
        || by_job
            .and_then(Value::as_object)
            .is_some_and(|map| !map.is_empty());
    if tiers.contains(&"quorum".to_string()) && !decides_anything {
        return Err(PolicyError::new(
            token::QUORUM_WITHOUT_RULES,
            "`quorum` is an allowed tier but nothing decides the quorum",
        )
        .with_hint(
            "a gate that can never be satisfied is not a stricter gate: give `quorum.default` \
             (or a `by_job` entry) the numbers ADR-0002 D5 defines",
        ));
    }
    if !tiers.contains(&"quorum".to_string()) && object.contains_key("default") {
        return Err(PolicyError::new(
            token::TIER_NOT_ALLOWED,
            "`quorum.default` says one thing and `allowed_tiers` says another",
        )
        .with_hint("either allow the `quorum` tier or drop the quorum numbers"));
    }
    let Some(requirements) = object.get("requirements").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    check_requirements(requirements, rules)
}

/// One selection block, with the tokens D5 names (`n`, `required_agree`, the floor and
/// the caps).
fn check_selection(where_: &str, selection: &Value) -> PolicyResult<()> {
    let object = selection.as_object().ok_or_else(|| {
        PolicyError::new(
            token::SELECTION_SHAPE,
            format!("{where_} must be an object"),
        )
    })?;
    let unknown = unknown_keys(object, SELECTION_FIELDS);
    if !unknown.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_UNKNOWN,
            format!(
                "unknown field(s) in {where_}: {} (a selection carries {})",
                unknown.join(", "),
                SELECTION_FIELDS.join(", ")
            ),
        ));
    }
    let missing: Vec<&str> = SELECTION_FIELDS
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_MISSING,
            format!("{where_} is missing {}", missing.join(", ")),
        )
        .with_hint(
            "a published selection is `SelectionPolicy` verbatim and writes every field, \
             so two policies that mean the same thing say it the same way",
        ));
    }
    let n = object
        .get("n")
        .and_then(Value::as_u64)
        .filter(|n| *n >= 1)
        .ok_or_else(|| {
            PolicyError::new(
                token::SELECTION_SHAPE,
                format!("{where_}.n must be at least 1"),
            )
        })?;
    let agree = object
        .get("required_agree")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PolicyError::new(
                token::SELECTION_SHAPE,
                format!("{where_}.required_agree must be an integer"),
            )
        })?;
    if agree == 0 {
        return Err(PolicyError::new(
            token::REQUIRED_AGREE_ZERO,
            format!("{where_}.required_agree is 0, which certifies anything, including nothing"),
        ));
    }
    if agree > n {
        return Err(PolicyError::new(
            token::REQUIRED_AGREE_UNREACHABLE,
            format!("{where_} asks for {agree} agreements from {n} seats"),
        )
        .with_hint("a threshold above the seat count can never complete"));
    }
    if object
        .get("max_per_identity")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        == 0
    {
        return Err(PolicyError::new(
            token::SELECTION_SHAPE,
            format!("{where_}.max_per_identity 0 would seat nobody"),
        ));
    }
    let floor = object
        .get("tier_floor")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if RosterTier::parse(floor).is_err() {
        return Err(PolicyError::new(
            token::TIER_FLOOR_UNKNOWN,
            format!("{where_}.tier_floor '{floor}' is not a roster tier"),
        )
        .with_hint("the roster tiers are anonymous, endorsed and trusted; a fourth is a typo"));
    }
    if let Some(caps) = object.get("tier_caps").and_then(Value::as_object) {
        for tier in caps.keys() {
            if RosterTier::parse(tier).is_err() {
                return Err(PolicyError::new(
                    token::TIER_CAPS_UNKNOWN,
                    format!("{where_}.tier_caps names '{tier}', which is not a roster tier"),
                ));
            }
        }
    }
    Ok(())
}

/// What a verifier must be able to do, per D5's table of demands a repository may not
/// make.
fn check_requirements(requirements: &Value, rules: &Value) -> PolicyResult<()> {
    let object = requirements.as_object().ok_or_else(|| {
        PolicyError::new(
            token::FIELD_SHAPE,
            "`quorum.requirements` must be an object",
        )
    })?;
    let unknown = unknown_keys(object, REQUIREMENTS_FIELDS);
    if !unknown.is_empty() {
        return Err(PolicyError::new(
            token::FIELD_UNKNOWN,
            format!(
                "unknown field(s) in `quorum.requirements`: {} (it carries {})",
                unknown.join(", "),
                REQUIREMENTS_FIELDS.join(", ")
            ),
        ));
    }
    let sandboxes = string_array(object.get("sandboxes"));
    if sandboxes.is_empty() {
        return Err(PolicyError::new(
            token::REQUIREMENTS_UNSATISFIABLE,
            "no sandbox backend is acceptable, so no verifier can ever be seated",
        ));
    }
    if sandboxes.len() > MAX_LIST_ITEMS {
        return Err(PolicyError::new(
            token::FIELD_SHAPE,
            format!("`quorum.requirements.sandboxes` holds at most {MAX_LIST_ITEMS} names"),
        ));
    }
    let images = string_array(object.get("image_digests"));
    if images.len() > MAX_LIST_ITEMS {
        return Err(PolicyError::new(
            token::FIELD_SHAPE,
            format!("`quorum.requirements.image_digests` holds at most {MAX_LIST_ITEMS} digests"),
        ));
    }
    for image in &images {
        if digest_shape(image).is_err() {
            return Err(PolicyError::new(
                token::FIELD_SHAPE,
                format!("image digest '{image}' is not `sha256:<64 hex>`"),
            ));
        }
    }
    for field in ["ram_mb", "disk_mb"] {
        if object.get(field).and_then(Value::as_u64).unwrap_or(1) == 0 {
            return Err(PolicyError::new(
                token::REQUIREMENTS_UNSATISFIABLE,
                format!("`quorum.requirements.{field}` of 0 selects any box and proves nothing"),
            ));
        }
    }
    let level = object
        .get("min_sandbox_level")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if level < MIN_SANDBOX_LEVEL as u64 {
        return Err(PolicyError::new(
            token::SANDBOX_FLOOR,
            format!(
                "a policy may not demand less confinement than the verifier's own floor \
                 (rung {MIN_SANDBOX_LEVEL}); rung 0 is \"nothing confined this\""
            ),
        ));
    }
    let allowed = string_array(rules.get("allowed_sandboxes"));
    if !allowed.is_empty() {
        let disjoint: Vec<&str> = sandboxes
            .iter()
            .filter(|name| !allowed.iter().any(|a| a == *name))
            .map(String::as_str)
            .collect();
        if !disjoint.is_empty() {
            return Err(PolicyError::new(
                token::SANDBOX_DISJOINT,
                format!(
                    "`quorum.requirements.sandboxes` ({}) and `rules.allowed_sandboxes` ({}) \
                     have nothing in common",
                    disjoint.join(", "),
                    allowed.join(", ")
                ),
            )
            .with_hint(
                "the policy would seat a verifier that its own proof rules then refuse — \
                 an argument with itself, resolved by nobody",
            ));
        }
    }
    let arch = string_field(requirements, "arch").unwrap_or_default();
    let required_arch = string_field(rules, "require_arch");
    if let Some(other) = required_arch.filter(|_| !arch.is_empty())
        && canonical_arch(arch) != canonical_arch(other)
    {
        return Err(PolicyError::new(
            token::ARCH_CONFLICT,
            format!("`quorum.requirements.arch` is '{arch}' and `rules.require_arch` is '{other}'"),
        )
        .with_hint("`amd64` and `x86_64` are one machine; two spellings in one document is how an arm64 round satisfies an amd64 rule"));
    }
    if canonical_arch(arch).is_none() {
        return Err(PolicyError::new(
            token::ARCH_NOT_CANONICAL,
            format!("'{arch}' is not a machine class this build knows"),
        )
        .with_hint("spell it the way `Arch` canonicalises it, once: x86_64 or aarch64"));
    }
    Ok(())
}

/// Step 6 on the read path: the chain has to be *continuous*, or "which rules were in
/// force then?" has no answer (D6).
fn check_chain(value: &Value, ctx: &Context<'_>) -> PolicyResult<()> {
    let previous = string_field(value, "previous_digest").unwrap_or_default();
    let revision = value.get("revision").and_then(Value::as_u64).unwrap_or(0) as u32;
    let effective_from = value
        .get("effective_from_us")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if previous == GENESIS_PREVIOUS {
        if revision != 1 {
            return Err(PolicyError::new(
                token::REVISION_GAP,
                format!("a genesis policy is revision 1 and this one claims {revision}"),
            ));
        }
        return Ok(());
    }
    let Some(parent) = ctx.history.get(previous) else {
        return Err(PolicyError::new(
            token::CHAIN_BROKEN,
            format!("`previous_digest` {previous} names a document this store does not have"),
        )
        .with_hint(
            "the chain is the only evidence of what came before, so a reader that cannot walk \
             it cannot say which rules were in force. Policy history is never pruned (ADR-0004 D6, D7)",
        ));
    };
    if parent.revision != revision - 1 {
        return Err(PolicyError::new(
            token::REVISION_GAP,
            format!(
                "revision {revision} claims to follow {}, which is not one before it",
                parent.revision
            ),
        ));
    }
    if parent.effective_from_us >= effective_from {
        return Err(PolicyError::new(
            token::EFFECTIVE_FROM_BACKWARDS,
            format!(
                "revision {revision} takes effect at {effective_from}, which is not after its \
                 predecessor's {}",
                parent.effective_from_us
            ),
        )
        .with_hint("time-traveling predecessors make the walk ambiguous"));
    }
    Ok(())
}

/// Step 7: every list is sorted and deduplicated (D2).
///
/// A reader refuses rather than re-normalises, which is the opposite of what a lenient
/// parser does and deliberately so: the bytes signed are the bytes read, so normality
/// is a property of the signed bytes. The payoff is that two authors who wrote the same
/// rules in a different order publish byte-identical bytes, and a re-publish that
/// changed nothing cannot move a digest a verdict already cited.
fn require_normalised(value: &Value) -> PolicyResult<()> {
    let mut lists: Vec<(&str, Vec<String>)> = Vec::new();
    if let Some(rules) = value.get("rules") {
        lists.push((
            "rules.allowed_tiers",
            string_array(rules.get("allowed_tiers")),
        ));
        lists.push((
            "rules.allowed_sandboxes",
            string_array(rules.get("allowed_sandboxes")),
        ));
    }
    lists.push(("protects", string_array(value.get("protects"))));
    if let Some(requirements) = value.get("quorum").and_then(|q| q.get("requirements")) {
        lists.push((
            "quorum.requirements.sandboxes",
            string_array(requirements.get("sandboxes")),
        ));
        lists.push((
            "quorum.requirements.image_digests",
            string_array(requirements.get("image_digests")),
        ));
    }
    for (where_, list) in lists {
        let mut sorted = list.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != list {
            return Err(PolicyError::new(
                token::NOT_NORMALISED,
                format!("`{where_}` is not sorted and deduplicated"),
            )
            .with_hint(
                "`gitiup policy publish` normalises before it signs; a reader that \"fixed\" \
                 the order would be recomputing a digest over bytes nobody signed (ADR-0004 D2)",
            ));
        }
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Small readers for the checks above
// --------------------------------------------------------------------------

/// The fields of `object` that are not in `allowed`, sorted for a stable message.
fn unknown_keys(object: &Map<String, Value>, allowed: &[&str]) -> Vec<String> {
    let mut unknown: Vec<String> = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect();
    unknown.sort();
    unknown
}

/// A string field, absent or wrong-typed as `None`.
fn string_field<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

/// A string array, ignoring non-strings (which other checks refuse on shape).
fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// `sha256:<64 lower-case hex>`.
fn digest_shape(text: &str) -> Result<(), ()> {
    let hex = text.strip_prefix("sha256:").ok_or(())?;
    if hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(())
    }
}

/// `SHA256:<43 unpadded base64>` — an SSH fingerprint, the only key id shape gitiup
/// uses (ADR-0001 D3).
fn key_id_shape(key_id: &str) -> Result<(), ()> {
    let body = key_id.strip_prefix("SHA256:").ok_or(())?;
    if body.len() != 43
        || body.contains('=')
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(());
    }
    Ok(())
}

/// `x_<producer>_<name>`, lower-case, at least two segments after the `x` (D10).
fn annotation_key_ok(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("x_") else {
        return false;
    };
    let mut parts = rest.split('_');
    let (Some(first), Some(second)) = (parts.next(), parts.next()) else {
        return false;
    };
    if first.is_empty() || second.is_empty() {
        return false;
    }
    for part in std::iter::once(first).chain(parts) {
        if part.is_empty()
            || !part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return false;
        }
    }
    true
}

/// The canonical spelling of a machine class, or `None` for a name this build does not
/// know (D5's `arch_conflict` row: two spellings of one machine in one document).
fn canonical_arch(text: &str) -> Option<&'static str> {
    ARCH_ALIASES
        .iter()
        .find(|(spelling, _)| *spelling == text)
        .map(|(_, canonical)| *canonical)
}

/// The bytes a policy signature covers: canonical bytes with `signatures` removed.
pub fn body_bytes_of(value: &Value) -> PolicyResult<Vec<u8>> {
    let mut body = value.clone();
    if let Some(map) = body.as_object_mut() {
        map.remove("signatures");
    }
    let bytes = canon::to_value_bytes(&body)?;
    check_size(&bytes)?;
    Ok(bytes)
}

// --------------------------------------------------------------------------
// The history walk (ADR-0004 D6)
// --------------------------------------------------------------------------

/// What the walk picked, and how far it had to go to pick it (D6).
#[derive(Debug, Clone)]
pub struct InForce<'a> {
    /// The document that was in force.
    pub policy: &'a PolicyDocument,
    /// How many links of the chain were considered to find it, for the report's
    /// "the chain was walked n links" note (D4).
    pub links: usize,
}

/// The policy in force at `at_us`: the newest one that had taken effect.
///
/// `chain` is every policy reachable from the advertised one by walking
/// `previous_digest` — the order does not matter, this sorts. Nothing here consults a
/// live service: the whole question is answerable from bytes already fetched, which is
/// what lets a `pre-receive` hook judge a year-old run without anybody's uptime (C6).
///
/// Refusing rather than falling back is the decision (D6): judging a run made before any
/// policy existed by today's rules would be a verdict that is neither "no rules applied"
/// nor "these applied", and it would be *true about today and useless about the run*.
pub fn in_force_at<'a>(chain: &'a [PolicyDocument], at_us: TimeUs) -> PolicyResult<InForce<'a>> {
    let mut ordered: Vec<&PolicyDocument> = chain.iter().collect();
    ordered.sort_by_key(|policy| std::cmp::Reverse(policy.effective_from_us));
    for (index, policy) in ordered.iter().enumerate() {
        if policy.effective_from_us > at_us.0 {
            continue;
        }
        if policy
            .expires_at_us
            .is_some_and(|expires| expires < at_us.0)
        {
            return Err(PolicyError::new(
                token::EXPIRED_HISTORY,
                format!(
                    "the policy in force at {} (revision {}) had already expired",
                    at_us.to_rfc3339(),
                    policy.revision
                ),
            )
            .with_hint("the rules stopped counting before the run happened; \"there were no rules then\" is the truth"));
        }
        return Ok(InForce {
            policy,
            links: index + 1,
        });
    }
    Err(PolicyError::new(
        token::POLICY_HISTORY_MISSING,
        format!(
            "nothing in the policy chain had taken effect at {}",
            at_us.to_rfc3339()
        ),
    )
    .with_hint(
        "there was no policy yet, and inventing one is not the same as having none (ADR-0004 D6). \
         A run made before the first published policy is refused, not judged by rules that did not exist",
    ))
}

// --------------------------------------------------------------------------
// Storage: keys, refs, write order, and what a fetch carries (ADR-0004 D7)
// --------------------------------------------------------------------------

/// `refs/gitiup/policy/current` — the policy in force (D7).
pub fn current_ref() -> RefName {
    // A fixed, valid ref name.
    RefName::gitiup(CURRENT_REF).expect("refs/gitiup/policy/current is a valid ref name")
}

/// `refs/gitiup/policy/history/<revision>` — one revision, create-only (D7).
///
/// Zero-padded, so a listing is in order, and individually addressable by number, so
/// one `git fetch` of `refs/gitiup/policy/history/*` carries the whole chain and a
/// clone can judge a year-old run with no listing and no pagination.
pub fn history_ref(revision: u32) -> PolicyResult<RefName> {
    RefName::gitiup(&format!(
        "{HISTORY_REF_ROOT}/{:0width$}",
        revision,
        width = HISTORY_REVISION_DIGITS
    ))
    .map_err(|e| PolicyError::new(token::FIELD_SHAPE, format!("history ref: {e}")))
}

/// The `kv/policy/<hex>` key a policy is filed under (D7).
pub fn kv_key(record_hex: &str) -> String {
    format!("kv/policy/{record_hex}")
}

/// Where a policy lives, spelled the way `cases.json` spells it: the `kv/` key and the
/// refs that advertise it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// `kv/policy/<hex(record_digest)>`.
    pub kv: String,
    /// `refs/gitiup/policy/current` (plus the history ref, when it has one).
    pub refs: Vec<String>,
}

/// What [`publish`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The stored bytes' digest: the `kv/` key (D4).
    pub record_digest: String,
    /// The rules' digest — what a verdict cites (D2).
    pub body_digest: String,
    /// Which revision was published.
    pub revision: u32,
    /// `kv/policy/<hex>`.
    pub kv: String,
    /// The create-only history ref written for it.
    pub history_ref: String,
    /// The ref moved under compare-and-swap.
    pub current_ref: String,
    /// The body digest `current` advertised before this publish, if any (D8's
    /// lost-update guard names it when it disagrees).
    pub previous_body_digest: Option<String>,
    /// Whether the store already held exactly this (a retry, not a change).
    pub already: bool,
    /// Bytes stored.
    pub size: u64,
}

impl Filed {
    /// Where `document` is filed, given what the store advertises.
    pub fn of(document: &PolicyDocument) -> PolicyResult<Filed> {
        Ok(Filed {
            kv: kv_key(&document.record_hex()?),
            refs: vec![current_ref().as_str().to_string()],
        })
    }
}

/// The `kv/` key of a policy, from its record digest string.
fn oid_of_digest(digest: &str) -> PolicyResult<Oid> {
    let hex = digest.split_once(':').map(|(_, hex)| hex).unwrap_or(digest);
    Oid::from_hex(hex).map_err(|e| {
        PolicyError::new(
            token::PREVIOUS_DIGEST_SHAPE,
            format!("`{digest}` is not a usable content digest: {e}"),
        )
    })
}

/// Fetch a blob and insist it re-hashes to the key it was filed under (D7).
///
/// A `current` whose bytes the store cannot return is a **refusal**, never a silent
/// fall back to an older policy: a reader that quietly used the last policy it
/// understood is a gate that stopped and said nothing.
fn fetch_blob(host: &dyn Host, oid: &Oid) -> PolicyResult<Vec<u8>> {
    let bytes = host
        .get(oid)
        .map_err(|e| {
            PolicyError::new(
                token::MISSING_BLOB,
                format!("the store could not answer: {e}"),
            )
        })?
        .ok_or_else(|| {
            PolicyError::new(
                token::MISSING_BLOB,
                format!(
                    "the store advertises {} but cannot return those bytes",
                    oid.hex()
                ),
            )
            .with_hint(
                "bytes before refs is the write order for exactly this reason (ADR-0004 D7); \
                 re-publish the revision, which is idempotent",
            )
        })?;
    let hashed = gitiup_attest::Digest::sha256(&bytes);
    if hashed.hex() != oid.hex() {
        return Err(PolicyError::new(
            token::DIGEST_MISMATCH,
            format!(
                "the object at kv/policy/{} is {} bytes that hash to something else",
                oid.hex(),
                bytes.len()
            ),
        )
        .with_hint("a store that lies about bytes is caught at the digest, not assumed away"));
    }
    Ok(bytes)
}

/// The `current` ref's oid, if the store has one.
pub fn current_oid(host: &dyn Host) -> PolicyResult<Option<Oid>> {
    host.get_ref(&current_ref())
        .map(|found| found.map(|r| r.oid))
        .map_err(|e| PolicyError::new(token::MISSING_BLOB, format!("reading the policy ref: {e}")))
}

/// The policy the store advertises right now, structurally sound but not yet
/// trusted-checked (that is [`current_policy`], or [`resolve`]).
pub fn current_bytes(host: &dyn Host) -> PolicyResult<Option<(Oid, Vec<u8>)>> {
    match current_oid(host)? {
        None => Ok(None),
        Some(oid) => Ok(Some((oid, fetch_blob(host, &oid)?))),
    }
}

/// The policy in force, fully checked against `ctx` (trust, history, clock).
pub fn current_policy(host: &dyn Host, ctx: &Context<'_>) -> PolicyResult<Option<PolicyDocument>> {
    let Some((_, bytes)) = current_bytes(host)? else {
        return Ok(None);
    };
    Ok(Some(verify_bytes(&bytes, ctx)?))
}

/// Every policy the store advertises under `refs/gitiup/policy/history/**`, oldest
/// revision first, each one self-consistent (steps 1–2).
///
/// This is the fetch D6's walk needs, and it is one `git fetch` of one glob on a
/// git-backed host. A history ref whose bytes are gone is a refusal, not a skipped
/// link: a hole in the history is a hole in the audit (D6).
pub fn history_policies(host: &dyn Host, ctx: &Context<'_>) -> PolicyResult<Vec<PolicyDocument>> {
    let refs = host
        .list_refs(&RefQuery::prefix(format!(
            "{}/{}",
            gitiup_host::refs::ns::GITIUP,
            HISTORY_REF_ROOT
        )))
        .map_err(|e| {
            PolicyError::new(token::MISSING_BLOB, format!("listing policy history: {e}"))
        })?;
    let mut out = Vec::new();
    for reference in refs {
        let bytes = fetch_blob(host, &reference.oid)?;
        let (_, document) = check_self_contained(&bytes, ctx)?;
        out.push(document);
    }
    out.sort_by_key(|document| document.revision);
    Ok(out)
}

/// The whole chain: the advertised policy and every predecessor found by walking
/// `previous_digest`, newest first (D6).
///
/// The walk is bounded by [`MAX_CHAIN_WALK`] so a volunteer's work is finite. A
/// predecessor that cannot be found is `chain_broken`, and that refusal is the point:
/// "which rules were in force then?" must have an answer or the verdict must say it
/// does not (policy history is therefore never pruned, D7).
pub fn fetch_chain(host: &dyn Host, ctx: &Context<'_>) -> PolicyResult<Vec<PolicyDocument>> {
    let Some((_, head_bytes)) = current_bytes(host)? else {
        return Ok(Vec::new());
    };
    let head_value = canon::read_canonical(&head_bytes).map_err(|e| {
        PolicyError::new(
            token::NOT_CANONICAL,
            format!("the advertised policy: {}", e.detail()),
        )
    })?;
    let head: PolicyDocument = serde_json::from_value(head_value).map_err(|e| {
        PolicyError::new(
            token::FIELD_SHAPE,
            format!("the advertised policy: cannot be read: {e}"),
        )
    })?;
    let mut known: Vec<PolicyDocument> = history_policies(host, ctx)?;
    let mut chain = vec![head.clone()];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(head.body_digest()?);
    let mut cursor = head;
    while cursor.previous_digest != GENESIS_PREVIOUS {
        if chain.len() > MAX_CHAIN_WALK {
            return Err(PolicyError::new(
                token::CHAIN_TOO_LONG,
                format!(
                    "the policy chain is longer than the {MAX_CHAIN_WALK} links a reader walks"
                ),
            )
            .with_hint("a store with more history than this should have squashed a release train, and says so"));
        }
        let want = cursor.previous_digest.clone();
        let Some(found) = known
            .iter()
            .find(|candidate| candidate.body_digest().is_ok_and(|digest| digest == want))
            .cloned()
        else {
            return Err(PolicyError::new(
                token::CHAIN_BROKEN,
                format!(
                    "revision {} names a predecessor this store does not carry ({})",
                    cursor.revision, cursor.previous_digest
                ),
            )
            .with_hint("fetch refs/gitiup/policy/history/** with refs/gitiup/policy/current; a policy that cannot be walked cannot say which rules were in force (ADR-0004 D6)"));
        };
        if !seen.insert(found.body_digest()?) {
            return Err(PolicyError::new(
                token::CHAIN_BROKEN,
                "the policy chain contains a cycle, which means it is not a chain",
            ));
        }
        chain.push(found.clone());
        cursor = found;
    }
    // The predecessors are part of the answer whether or not the walk needed them.
    for policy in known.drain(..) {
        if !chain.iter().any(|c| c.revision == policy.revision) {
            chain.push(policy);
        }
    }
    chain.sort_by_key(|policy| std::cmp::Reverse(policy.revision));
    Ok(chain)
}

/// Publish a signed policy (D7's write order, D8's guard).
///
/// Four steps, in this order: the bytes in the CAS, the create-only history ref, then
/// `current` moved under compare-and-swap. A crash between the history ref and the
/// `current` move leaves a revision that exists and is not current — safe, printable,
/// and repaired by re-publishing — while a `current` whose bytes the store cannot
/// return is the state a reader cannot repair, so it is prevented instead.
///
/// The document is validated in full before a byte is written, including the trust
/// check: a publish by a key nobody trusts fails here rather than becoming a policy
/// that every reader refuses.
///
/// `previous_body_digest` is what the caller believes `current` advertised (the lost-update
/// guard, D8): two owners publishing at once must produce one loser with a clear message,
/// not a policy that silently drops a revision. Pass `None` to mean "whatever it says now",
/// which is what `gitiup policy publish` does after reading the store itself.
pub fn publish(
    host: &dyn Host,
    document: &PolicyDocument,
    ctx: &Context<'_>,
    previous_body_digest: Option<&str>,
) -> PolicyResult<Published> {
    publish_with(host, document, ctx, previous_body_digest, false)
}

/// What [`publish`] would do, checked in full and written nowhere: `--dry-run` (D9).
///
/// This is not a shortcut past the checks. A `--dry-run` that skipped the chain position
/// or the trust step would tell an owner their policy is publishable and then refuse it
/// five seconds later, which is worse than not asking.
pub fn plan_publish(
    host: &dyn Host,
    document: &PolicyDocument,
    ctx: &Context<'_>,
    previous_body_digest: Option<&str>,
) -> PolicyResult<Published> {
    publish_with(host, document, ctx, previous_body_digest, true)
}

fn publish_with(
    host: &dyn Host,
    document: &PolicyDocument,
    ctx: &Context<'_>,
    previous_body_digest: Option<&str>,
    dry_run: bool,
) -> PolicyResult<Published> {
    let bytes = document.canonical_bytes()?;
    let value = document.value()?;
    reject_bindings(&document.rules)?;

    let body_digest = document.body_digest()?;
    let record_digest = document.record_digest()?;
    let oid = oid_of_digest(&record_digest)?;
    let advertised_oid = current_oid(host)?;
    // Re-publishing exactly what the store already advertises is an idempotent success,
    // not a second revision and not a chain complaint.
    let already = advertised_oid == Some(oid);
    // Refuse before touching the store: a policy that cannot stand up to a reader should
    // never be half-published (D9). The chain step of that validation runs against the
    // history the store actually carries, because that is the only history a reader will
    // have either (D6).
    let self_checked = Context::new(ctx.trust, ctx.now);
    let mut known = history_policies(host, &self_checked)?;
    if let Some((_, head_bytes)) = current_bytes(host)?
        && let Ok((_, head)) = check_self_contained(&head_bytes, &self_checked)
    {
        known.push(head);
    }
    let history = ctx.history.merged_with(&History::from_docs(known)?);
    let context = Context {
        trust: ctx.trust,
        history: &history,
        now: ctx.now,
    };
    validate_with(&value, &context)?;

    // D8's lost-update guard, and D6's chain position: `previous_digest` must name
    // what `current` advertises, and `revision` must be one past it.
    let advertised = if already {
        None
    } else {
        current_position(host, ctx.now)?
    };
    let expected_previous = advertised
        .as_ref()
        .map(|existing| existing.body_digest())
        .transpose()?;
    if let Some(claimed) = previous_body_digest
        && expected_previous.as_deref() != Some(claimed)
    {
        return Err(PolicyError::new(
            token::CHAIN_BROKEN,
            format!(
                "this publish expects `current` to advertise {}, and it advertises {}",
                claimed,
                expected_previous.as_deref().unwrap_or("nothing at all")
            ),
        )
        .with_hint(
            "fetch, re-sign against the digest the store actually advertises, and publish \
             again: two owners publishing at once produces one loser, not a dropped revision (ADR-0004 D8)",
        ));
    }
    if let Some(existing) = &advertised {
        if document.previous_digest != existing.body_digest()? {
            return Err(PolicyError::new(
                token::CHAIN_BROKEN,
                format!(
                    "`previous_digest` is {} but the policy in force is {}",
                    document.previous_digest,
                    existing.body_digest()?
                ),
            )
            .with_hint("a policy change is a new signed document that follows what is in force (ADR-0004 D6)"));
        }
        if document.revision != existing.revision + 1 {
            return Err(PolicyError::new(
                token::REVISION_GAP,
                format!(
                    "revision {} follows revision {}, which is not {}",
                    document.revision,
                    existing.revision,
                    existing.revision + 1
                ),
            ));
        }
    } else if document.previous_digest != GENESIS_PREVIOUS || document.revision != 1 {
        return Err(PolicyError::new(
            token::REVISION_GAP,
            "this store has no policy yet, so the first one is revision 1 with the zero `previous_digest`",
        ));
    }

    if dry_run {
        return Ok(Published {
            record_digest,
            body_digest,
            revision: document.revision,
            kv: kv_key(&oid.hex()),
            history_ref: history_ref(document.revision)?.as_str().to_string(),
            current_ref: current_ref().as_str().to_string(),
            previous_body_digest: expected_previous.or_else(|| {
                (document.previous_digest != GENESIS_PREVIOUS)
                    .then(|| document.previous_digest.clone())
            }),
            already,
            size: bytes.len() as u64,
        });
    }

    // 1. bytes.
    host.put_cas(&POLICY_NAMESPACE, &bytes)
        .map_err(|e| PolicyError::new(token::MISSING_BLOB, format!("storing the policy: {e}")))?;
    // 2. the create-only history ref. Same bytes again is an idempotent success;
    //    *different* bytes at a revision that exists is a conflict (a revision is
    //    immutable by the transport, not by convention).
    let history_ref = history_ref(document.revision)?;
    let history_update = RefUpdate::create(history_ref.clone(), oid)
        .with_actor(actor("policy"))
        .with_message(format!("policy revision {}", document.revision));
    if let Err(error) = host.update_ref_cas(&history_update)
        && error.kind() != gitiup_host::HostErrorKind::Conflict
    {
        return Err(PolicyError::new(
            token::MISSING_BLOB,
            format!("advertising revision {}: {error}", document.revision),
        ));
    }
    // 3. `current`, moved under CAS: a lost update here is a lost policy.
    match advertised_oid {
        Some(existing) if existing == oid => {}
        Some(existing) => {
            host.update_ref_cas(
                &RefUpdate::replace(current_ref(), existing, oid)
                    .with_actor(actor("policy"))
                    .with_message(format!("policy revision {} is in force", document.revision)),
            )
            .map_err(|e| {
                PolicyError::new(token::MISSING_BLOB, format!("moving the policy ref: {e}"))
                    .with_hint(
                        "someone else published in between: re-read refs/gitiup/policy/current, \
                         re-sign against its digest, and publish again (ADR-0004 D8)",
                    )
            })?;
        }
        None => {
            host.update_ref_cas(
                &RefUpdate::create(current_ref(), oid)
                    .with_actor(actor("policy"))
                    .with_message(format!("first policy: revision {}", document.revision)),
            )
            .map_err(|e| {
                PolicyError::new(token::MISSING_BLOB, format!("setting the policy ref: {e}"))
            })?;
        }
    }
    Ok(Published {
        record_digest,
        body_digest,
        revision: document.revision,
        kv: kv_key(&oid.hex()),
        history_ref: history_ref.as_str().to_string(),
        current_ref: current_ref().as_str().to_string(),
        previous_body_digest: expected_previous.or_else(|| {
            (document.previous_digest != GENESIS_PREVIOUS).then(|| document.previous_digest.clone())
        }),
        already,
        size: bytes.len() as u64,
    })
}

/// The actor recorded on a policy ref write.
fn actor(what: &str) -> Actor {
    Actor::new(format!("gitiup {what}")).unwrap_or_else(|_| Actor::unknown())
}

// --------------------------------------------------------------------------
// Resolution: the ladder, and the provenance a verdict must carry (ADR-0004 D4)
// --------------------------------------------------------------------------

/// Which of D4's four sources a policy came from.
///
/// The line runs after [`Source::Store`]: the first three are gate-eligible, the last
/// two are local-only. A merge decision may rest on the first three and never on the
/// last two, because a fork's unsigned edit to a file and a build that nobody configured
/// are both questions and neither is an authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--policy <file>`: an operator's act, ahead of anything published (D4).
    PolicyFlag,
    /// `$GITIUP_POLICY`, which is the same act spelled in the environment.
    PolicyEnvironment,
    /// `refs/gitiup/policy/current`, signed, verified, walked to the revision in force.
    Store,
    /// A `gitiup-policy.json` found in the checkout: a draft, not a rule (D1).
    TreeFile,
    /// This build's `Policy::default()`, which trusts nobody.
    BuiltInDefault,
}

impl Source {
    /// The name a report prints (D4's `source` field).
    pub fn as_str(self) -> &'static str {
        match self {
            Source::PolicyFlag => "--policy",
            Source::PolicyEnvironment => "$GITIUP_POLICY",
            Source::Store => "store",
            Source::TreeFile => "tree-file",
            Source::BuiltInDefault => "built-in-default",
        }
    }

    /// May a merge decision rest on this source (D4)?
    pub fn gate_eligible(self) -> bool {
        matches!(
            self,
            Source::PolicyFlag | Source::PolicyEnvironment | Source::Store
        )
    }
}

/// The timestamp the walk used, and how it was obtained (D4).
///
/// A producer controls a run's claimed time, so the bound on trusting it is not this
/// walk's: it is the freshness window, which is why `max_age_us` is a *policy* field
/// with a 24 h default (D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct At {
    /// The instant.
    pub us: TimeUs,
    /// `run-claim`, `merge-record` or `now`.
    pub from: &'static str,
}

impl At {
    /// The wall clock, for "what would happen now?".
    pub fn now() -> At {
        At {
            us: TimeUs::now(),
            from: "now",
        }
    }

    /// A pinned clock that still says `now` in the provenance: what a replay uses, so a
    /// re-run of an old run reports the same thing the original did.
    pub fn now_at(us: TimeUs) -> At {
        At { us, from: "now" }
    }

    /// An attestation's claimed time: the rules in force when the run happened.
    pub fn run_claim(us: TimeUs) -> At {
        At {
            us,
            from: "run-claim",
        }
    }

    /// A merge record's time.
    pub fn merge_record(us: TimeUs) -> At {
        At {
            us,
            from: "merge-record",
        }
    }
}

/// Why a policy is being resolved (D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Purpose {
    /// A merge decision: only a gate-eligible source will do, and nothing gate-eligible
    /// is a refusal (`no_policy_published`), not a silent default.
    Gate,
    /// A question, not a verdict: `policy show`, `policy check --dry-run`, `gitiup run`'s
    /// pre-flight, a human poking around.
    #[default]
    Advisory,
}

/// The provenance every report carries (D4).
///
/// "A merge gate that cannot say where its rules came from is undebuggable" — so
/// nothing here is optional decoration: which source, both digests, which revision,
/// which key, which timestamp, and the notes that explain anything surprising.
#[derive(Debug, Clone, Default)]
pub struct PolicyProvenance {
    /// Which of the four sources won.
    pub source: Option<Source>,
    /// The file it came from, for the three local sources (D4 prints `file` or `ref`).
    pub file: Option<String>,
    /// `refs/gitiup/policy/current`, for the store source.
    pub reference: Option<String>,
    /// The `kv/policy/<hex>` key the bytes came from.
    pub kv: Option<String>,
    /// **The policy's identity**: what a verdict cites and what `previous_digest` names.
    pub body_digest: Option<String>,
    /// The stored bytes' digest.
    pub record_digest: Option<String>,
    /// Which link of the chain was applied.
    pub revision: Option<u32>,
    /// `owner.key_id`.
    pub signed_by: Option<String>,
    /// `owner.principal`, next to the key id in human output.
    pub owner: Option<String>,
    /// When these rules started counting.
    pub effective_from_us: Option<i64>,
    /// The timestamp the walk used, and how it was obtained.
    pub at_us: Option<i64>,
    /// `run-claim` · `merge-record` · `now`.
    pub at_from: Option<String>,
    /// Whether a merge decision may rest on this answer (D4).
    pub gate_eligible: bool,
    /// Why anything surprising happened: an override, a tree file ignored, a chain
    /// walked n links, a chain that could not be walked.
    pub notes: Vec<String>,
    /// Publish-style advice (D8), repeated on a read so `policy show` can print it.
    pub warnings: Vec<String>,
}

impl PolicyProvenance {
    /// The provenance as the `policy` object a `--json` report prints (D4).
    pub fn json(&self) -> Value {
        let mut map = Map::new();
        if let Some(source) = self.source {
            map.insert("source".into(), source.as_str().into());
        }
        if let Some(file) = &self.file {
            map.insert("file".into(), file.clone().into());
        }
        if let Some(reference) = &self.reference {
            map.insert("ref".into(), reference.clone().into());
        }
        if let Some(kv) = &self.kv {
            map.insert("kv".into(), kv.clone().into());
        }
        if let Some(digest) = &self.body_digest {
            map.insert("body_digest".into(), digest.clone().into());
        }
        if let Some(digest) = &self.record_digest {
            map.insert("record_digest".into(), digest.clone().into());
        }
        if let Some(revision) = self.revision {
            map.insert("revision".into(), revision.into());
        }
        if let Some(key_id) = &self.signed_by {
            map.insert("signed_by".into(), key_id.clone().into());
        }
        if let Some(owner) = &self.owner {
            map.insert("owner_principal".into(), owner.clone().into());
        }
        if let Some(us) = self.effective_from_us {
            map.insert("effective_from_us".into(), us.into());
        }
        if let Some(us) = self.at_us {
            map.insert("at_us".into(), us.into());
        }
        if let Some(from) = &self.at_from {
            map.insert("at_from".into(), from.clone().into());
        }
        map.insert("gate_eligible".into(), self.gate_eligible.into());
        if !self.notes.is_empty() {
            map.insert(
                "notes".into(),
                Value::Array(
                    self.notes
                        .iter()
                        .map(|note| Value::String(note.clone()))
                        .collect(),
                ),
            );
        }
        if !self.warnings.is_empty() {
            map.insert(
                "warnings".into(),
                Value::Array(
                    self.warnings
                        .iter()
                        .map(|warning| Value::String(warning.clone()))
                        .collect(),
                ),
            );
        }
        Value::Object(map)
    }
}

/// A resolved policy: the rules to apply, and the story of where they came from.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// What to hand `gitiup verify attestation`'s machinery (D2: same rules, different
    /// authority).
    pub policy: Policy,
    /// The signed document, when the answer came from one. `None` for the local-only
    /// sources, which have no signature to cite.
    pub document: Option<PolicyDocument>,
    /// What the report prints (D4).
    pub provenance: PolicyProvenance,
}

impl ResolvedPolicy {
    /// Whether this answer may decide a merge.
    pub fn gate_eligible(&self) -> bool {
        self.provenance.gate_eligible
    }

    /// The policy's identity as a verdict cites it: the body digest (D4).
    pub fn citation(&self) -> Option<&str> {
        self.provenance.body_digest.as_deref()
    }
}

/// What a caller asks [`resolve`] for: a store (optional), trust roots, a clock, and
/// the local overrides it was given.
pub struct Request<'a> {
    /// The store to read a published policy from, if there is one to read from.
    pub host: Option<&'a dyn Host>,
    /// The trust roots: `--owner`, else this machine's keystore (D3).
    pub trust: &'a Trust,
    /// The run's timestamp for the walk. `None` means now.
    pub at: Option<At>,
    /// The reader's own clock, which is what makes a policy expired or future-dated.
    /// `None` means now; a replay pins it, so a re-run says the same thing a year on.
    pub now: Option<TimeUs>,
    /// `--policy <file>`.
    pub policy_file: Option<std::path::PathBuf>,
    /// `$GITIUP_POLICY`, which the CLI reads and passes in.
    pub policy_env: Option<std::path::PathBuf>,
    /// A `gitiup-policy.json` discovered in the checkout.
    pub tree_file: Option<std::path::PathBuf>,
    /// Whether the answer is a merge decision.
    pub purpose: Purpose,
}

impl<'a> Request<'a> {
    /// Nothing but trust roots: the ladder falls through to the local-only sources.
    pub fn advisory(trust: &'a Trust) -> Request<'a> {
        Request {
            host: None,
            trust,
            at: None,
            now: None,
            policy_file: None,
            policy_env: None,
            tree_file: None,
            purpose: Purpose::Advisory,
        }
    }

    /// A gate with no store yet: the ladder still runs, and a gate that lands on a
    /// local-only source is refused (D4).
    pub fn gate(trust: &'a Trust) -> Request<'a> {
        Request::advisory(trust).for_purpose(Purpose::Gate)
    }

    /// The minimal request: a store, roots, and a clock. Gate-eligible by construction.
    pub fn store(host: &'a dyn Host, trust: &'a Trust, at: At) -> Request<'a> {
        Request {
            host: Some(host),
            trust,
            at: Some(at),
            now: None,
            policy_file: None,
            policy_env: None,
            tree_file: None,
            purpose: Purpose::Gate,
        }
    }

    /// `--policy <file>`, which replaces everything published (D4).
    pub fn with_policy_file(mut self, path: impl Into<std::path::PathBuf>) -> Request<'a> {
        self.policy_file = Some(path.into());
        self
    }

    /// `$GITIUP_POLICY`.
    pub fn with_policy_env(mut self, path: impl Into<std::path::PathBuf>) -> Request<'a> {
        self.policy_env = Some(path.into());
        self
    }

    /// A `gitiup-policy.json` found in the checkout: local-only, and reported as such.
    pub fn with_tree_file(mut self, path: impl Into<std::path::PathBuf>) -> Request<'a> {
        self.tree_file = Some(path.into());
        self
    }

    /// What the answer is for.
    pub fn for_purpose(mut self, purpose: Purpose) -> Request<'a> {
        self.purpose = purpose;
        self
    }
}

/// Read, verify and resolve the policy a store publishes — D4's source 2, on its own.
///
/// This is what `.4`'s merge gate and `.5`'s hook call: no `--policy`, no tree file, no
/// default. The hook in particular must reach the same verdict from a clone as the box
/// that accepted the push, and an override in a hook script on one machine destroys that.
pub fn resolve_store_at(
    host: &dyn Host,
    trust: &Trust,
    at: At,
    now: TimeUs,
) -> PolicyResult<ResolvedPolicy> {
    // Pass 1, with no history: every advertised document has to be a real signed
    // policy on its own terms before any of them can be believed as a predecessor.
    //
    // Note the two clocks. `now` is the reader's: it is what makes a policy expired or
    // future-dated *today*. `at` is the run's: it is what the walk picks by (D6). They
    // differ in the ordinary case — judging last month's run today, in a store that has
    // gained a revision since — and conflating them would refuse a history that is
    // perfectly well-formed.
    let self_checked = Context::new(trust, now);
    let chain = fetch_chain(host, &self_checked)?;
    let Some(head) = chain.first() else {
        return Err(PolicyError::new(
            token::NO_POLICY_PUBLISHED,
            "this store publishes no policy at refs/gitiup/policy/current",
        )
        .with_hint(
            "the owner publishes one with `gitiup policy publish`; a gate with nothing \
             gate-eligible refuses rather than deciding a merge by a default nobody chose \
             (ADR-0004 D4)",
        ));
    };
    // Pass 2: the walk, then the full check with the predecessors in hand — D9's step 6
    // cannot run before they are, which is why this reads the store in two passes.
    let history = History::from_docs(chain.iter().cloned())?;
    let ctx = Context {
        trust,
        history: &history,
        now,
    };
    let found = in_force_at(&chain, at.us)?;
    let bytes = fetch_blob(host, &oid_of_digest(&found.policy.record_digest()?)?)?;
    let document = verify_bytes(&bytes, &ctx)?;
    let notes = if found.links > 1 {
        vec![format!(
            "the chain was walked {} links to revision {}",
            found.links, document.revision
        )]
    } else {
        Vec::new()
    };
    let provenance = PolicyProvenance {
        source: Some(Source::Store),
        reference: Some(current_ref().as_str().to_string()),
        kv: Some(kv_key(&document.record_hex()?)),
        body_digest: Some(document.body_digest()?),
        record_digest: Some(document.record_digest()?),
        revision: Some(document.revision),
        signed_by: Some(document.owner.key_id.clone()),
        owner: Some(document.owner.principal.clone()),
        effective_from_us: Some(document.effective_from_us),
        at_us: Some(at.us.0),
        at_from: Some(at.from.to_string()),
        gate_eligible: Source::Store.gate_eligible(),
        notes,
        warnings: document.warnings(trust, now),
        file: None,
    };
    let _ = head;
    let policy = document.to_policy(Some(at.us.0))?;
    Ok(ResolvedPolicy {
        policy,
        document: Some(document),
        provenance,
    })
}

/// What the store advertises as the policy right now, checked but **not trusted**.
///
/// A publisher needs this for one thing: the chain position — which revision is current,
/// and what its body digest is — and whose key signed the previous revision is not the
/// publisher's business (D3 makes trust the *reader's* configuration, and a new owner
/// taking over a policy chain would otherwise be unable to see what they are following).
/// The bytes are still verified as a policy: a store advertising garbage is refused, not
/// ignored, and the new revision that gets published on top of it will be trusted or
/// refused on its own signature.
pub fn current_position(host: &dyn Host, now: TimeUs) -> PolicyResult<Option<PolicyDocument>> {
    let Some((_, bytes)) = current_bytes(host)? else {
        return Ok(None);
    };
    let context = Context::new(&Trust::None, now);
    let (_, document) = check_self_contained(&bytes, &context)?;
    Ok(Some(document))
}

/// [`resolve_store_at`] with this machine's wall clock as the reader's clock.
pub fn resolve_store(host: &dyn Host, trust: &Trust, at: At) -> PolicyResult<ResolvedPolicy> {
    resolve_store_at(host, trust, at, TimeUs::now())
}

/// Resolve the policy for a store, a clock and a set of trust roots: D4's whole ladder.
///
/// The order is the decision and the split down the middle is the point:
///
/// ```text
/// 1. --policy <file> / $GITIUP_POLICY   explicit, operator-supplied   ┐ gate-eligible
/// 2. the store-published record, walked to the run's timestamp       ┘
/// 3. gitiup-policy.json in the checkout  unsigned, unverified         ┐ local-only
/// 4. this build's built-in default       nothing published anywhere   ┘
/// ```
///
/// The first two replace, they never merge: two documents that disagree are two policies
/// and one of them is in force. A published policy that fails to verify is a refusal and
/// not a fall-through — the ladder goes *past a broken published policy* only in the
/// sense that it does not; a store whose policy is unsigned stops everything rather than
/// quietly applying a draft.
pub fn resolve(request: &Request<'_>) -> PolicyResult<ResolvedPolicy> {
    let at = request.at.unwrap_or_else(At::now);
    let now = request.now.unwrap_or_else(TimeUs::now);
    // Best effort, and only for the note: a broken published policy is refused by
    // `resolve_store` when the ladder actually lands there, and an operator's `--policy`
    // replaces it rather than arguing with it (D4).
    let published = request
        .host
        .and_then(|host| current_policy(host, &Context::new(request.trust, now)).ok())
        .flatten();
    // 1 and 2: an explicit file, then the environment's. Both are operator acts and
    // both *replace* what is published — and say so, in the notes.
    for (path, source) in [
        (request.policy_file.as_ref(), Source::PolicyFlag),
        (request.policy_env.as_ref(), Source::PolicyEnvironment),
    ] {
        let Some(path) = path else {
            continue;
        };
        let text = std::fs::read_to_string(path).map_err(|e| {
            PolicyError::new(
                token::FIELD_SHAPE,
                format!("{}: cannot be read: {e}", path.display()),
            )
        })?;
        let rules = PolicyFile::from_json(&text).map_err(|e| {
            PolicyError::new(
                token::FIELD_SHAPE,
                format!("{}: {}", path.display(), e.detail()),
            )
            .with_hint(e.hint().unwrap_or_default())
        })?;
        let mut provenance = PolicyProvenance {
            source: Some(source),
            file: Some(path.display().to_string()),
            gate_eligible: source.gate_eligible(),
            at_us: Some(at.us.0),
            at_from: Some(at.from.to_string()),
            notes: vec![format!(
                "the gate was run with an override nobody published ({}); the store-published \
                 policy was ignored",
                source.as_str()
            )],
            ..Default::default()
        };
        if let Some(existing) = &published {
            provenance.notes.push(format!(
                "it overrode the published policy {}",
                existing.body_digest().unwrap_or_default()
            ));
        }
        if let Some(tree) = &request.tree_file {
            provenance.notes.push(format!(
                "the checkout's {} was not consulted",
                tree.display()
            ));
        }
        let policy = rules.to_policy().map_err(|e| {
            PolicyError::new(
                token::FIELD_SHAPE,
                format!("{}: {}", path.display(), e.detail()),
            )
        })?;
        return Ok(ResolvedPolicy {
            policy,
            document: None,
            provenance,
        });
    }
    // 3: the store, if there is one to read.
    if let Some(host) = request.host {
        let resolved = resolve_store_at(host, request.trust, at, now)?;
        if let Some(tree) = &request.tree_file {
            let note = tree_file_note(tree, resolved.document.as_ref());
            if let Some(note) = note {
                let mut resolved = resolved;
                resolved.provenance.notes.push(note);
                return Ok(resolved);
            }
        }
        return Ok(resolved);
    }
    // 4 and 5: the two local-only sources, and a gate refuses rather than using them.
    let (policy, file, source) = match &request.tree_file {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                PolicyError::new(
                    token::FIELD_SHAPE,
                    format!("{}: cannot be read: {e}", path.display()),
                )
            })?;
            let rules = PolicyFile::from_json(&text).map_err(|e| {
                PolicyError::new(
                    token::FIELD_SHAPE,
                    format!("{}: {}", path.display(), e.detail()),
                )
            })?;
            (
                rules.to_policy().map_err(|e| {
                    PolicyError::new(
                        token::FIELD_SHAPE,
                        format!("{}: {}", path.display(), e.detail()),
                    )
                })?,
                Some(path.display().to_string()),
                Source::TreeFile,
            )
        }
        None => (Policy::default(), None, Source::BuiltInDefault),
    };
    if request.purpose == Purpose::Gate {
        return Err(PolicyError::new(
            token::NO_POLICY_PUBLISHED,
            "no policy is published in this store and none was named with --policy; \
             refusing rather than deciding a merge by a default nobody chose",
        )
        .with_hint(if source == Source::TreeFile {
            "editing a file is not publishing a policy: `gitiup policy publish` signs the \
             rules and puts them in the store, which is the copy a gate is allowed to use"
                .to_string()
        } else {
            "the owner publishes one with `gitiup policy publish`, or an operator names one \
             with --policy (which is gate-eligible because it is an explicit act)"
                .to_string()
        }));
    }
    let mut notes = vec![match source {
        Source::TreeFile => format!(
            "the checkout's {} is a draft: it is not signed, it is not versioned, and it is \
             not in force for a merge (ADR-0004 D1)",
            file.as_deref().unwrap_or("gitiup-policy.json")
        ),
        _ => "nothing is published anywhere and no file was named, so this is this build's \
              built-in default: it trusts nobody, which is the safe direction to be wrong in"
            .to_string(),
    }];
    if let (Some(tree), Some(published)) = (&request.tree_file, &published)
        && let Some(note) = tree_file_note(tree, Some(published))
    {
        notes.push(note);
    }
    Ok(ResolvedPolicy {
        policy,
        document: None,
        provenance: PolicyProvenance {
            source: Some(source),
            file,
            gate_eligible: source.gate_eligible(),
            at_us: Some(at.us.0),
            at_from: Some(at.from.to_string()),
            notes,
            ..Default::default()
        },
    })
}

/// The one line that answers "why didn't my change obey the rule I just edited" (D1).
fn tree_file_note(tree: &std::path::Path, published: Option<&PolicyDocument>) -> Option<String> {
    let published = published?;
    let text = std::fs::read_to_string(tree).ok()?;
    let draft = PolicyFile::from_json(&text).ok()?;
    // Compared after normalisation, because "the same rules written differently" is the
    // case D2 made normalisation for; only a real difference deserves the line.
    let same = serde_json::to_value(normalise_rules(&draft))
        .ok()
        .zip(serde_json::to_value(&published.rules).ok())
        .is_some_and(|(draft, current)| draft == current);
    if same {
        return None;
    }
    let file_digest = format!(
        "sha256:{}",
        gitiup_attest::Digest::sha256(text.as_bytes()).hex()
    );
    let published_body = published.body_digest().ok()?;
    Some(format!(
        "the checkout's {} ({file_digest}) is not the published policy ({published_body}) and \
         is not in force: editing a file is not publishing a policy (ADR-0004 D1)",
        tree.display()
    ))
}

// --------------------------------------------------------------------------
// Normalisation: what `policy publish` does to a tree file before signing (D2, D8)
// --------------------------------------------------------------------------

/// Resolve the `allow_simulated` shorthand and sort every list, so two authors who
/// wrote the same rules in a different order publish **byte-identical** bytes and a
/// re-publish that changed nothing cannot move the digest a verdict cites (D2).
///
/// The reader's side of this rule is [`token::NOT_NORMALISED`]: a reader refuses what
/// is not already normalised rather than normalising what it reads, because the bytes
/// signed are the bytes read and `body_digest` has to mean "whatever the owner signed",
/// not "whatever you computed".
pub fn normalise_rules(rules: &PolicyFile) -> PolicyFile {
    let mut out = rules.clone();
    let shorthand = out.allow_simulated.take();
    let tiers = match &out.allowed_tiers {
        Some(tiers) => tiers.clone(),
        None => {
            let mut tiers = vec!["local".to_string()];
            if shorthand == Some(true) {
                tiers.push("simulated".to_string());
            }
            tiers
        }
    };
    out.allowed_tiers = Some(sorted_unique(&tiers));
    if let Some(sandboxes) = &out.allowed_sandboxes {
        out.allowed_sandboxes = Some(sorted_unique(sandboxes));
    }
    out
}

/// Normalise a whole document the way publish does: the rules block, the `protects`
/// globs and the quorum's lists.
pub fn normalise_document(document: &mut PolicyDocument) {
    document.rules = normalise_rules(&document.rules);
    document.protects = sorted_unique(&document.protects);
    if let Some(quorum) = &mut document.quorum
        && let Some(requirements) = &mut quorum.requirements
    {
        requirements.sandboxes = sorted_unique(&requirements.sandboxes);
        requirements.image_digests = sorted_unique(&requirements.image_digests);
    }
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = values.to_vec();
    out.sort();
    out.dedup();
    out
}

//! The digest computation: a finished run in, a signable manifest out.
//!
//! This is where the epic's headline formula lives:
//!
//! ```text
//! RunDigest = sha256(canonical(RunManifest {
//!     source      : commit, workflow source oid, event payload digest, job, matrix,
//!     inputs      : declared input values,
//!     secrets     : secret *names* only,
//!     pins        : resolved `uses:` map (repo + commit sha),
//!     closure     : reusable-workflow closure,
//!     environment : machine-class fingerprint (image digest, toolchain, arch),
//!     steps       : id, name, exit code, outcome, normalised stdout/stderr digest,
//!                   outputs map, artifact digests,
//!     provenance  : tier, runner, normalisation version,
//! }))
//! ```
//!
//! [`RunReport`] is what a runner (or a test, or a hand-written fixture) hands
//! over; [`RunManifest::from_run`] does the deriving — every hash the formula
//! names, the environment fingerprint, the mandated sort orders — and then
//! normalizes, fixes the fingerprint and validates, so a half-built manifest
//! cannot escape into a signature.
//!
//! # The recipe, in the order it is applied
//!
//! | # | step | why it is in this order |
//!|---|------|-------------------------|
//!| 1 | parse the report | the report is an *input format*, not a signed document: valid JSON and no unknown fields is all that is asked of its layout |
//!| 2 | check the report's shape ([`RunReport::validate`]) | a typo must say "unknown field `toochain`", not "the digest is different" |
//!| 3 | hash the *material* the report handed over ([`Material`]) | hashing happens once, here, so "the digest of a log" is not a caller's option |
//!| 4 | assemble `result` + `claims`, sorting every list the format mandates | [`RunManifest::normalize`] |
//!| 5 | derive `environment.fingerprint` | it is derived ([`Environment::fix_fingerprint`]), never asserted |
//!| 6 | [`RunManifest::validate`] | the checks a verifier will run, run once at production time |
//!
//! # What a report may hand over
//!
//! Anything hashable can arrive either **pre-hashed** or **in the clear**
//! ([`Material`]). Pre-hashed is the normal production path — logs are
//! megabytes, and giti-1rs.3 normalises them *before* anything hashes them. In
//! the clear is what makes this computation checkable: a fixture (and a
//! reviewer) can see that a given run really does hash to a given digest instead
//! of taking the runner's word for it.
//!
//! Normalisation reaches **step log streams only**. An event payload, a workflow
//! source and an artifact are hashed as handed over: those are inputs and
//! products, not logs. A runner that normalises an artifact manifest hands over
//! the digest it computed and declares the version that produced it (see
//! [`Normaliser`]).
//!
//! # Order and whitespace
//!
//! The report is never encoded, so its own formatting carries no meaning: two
//! reports describing the same run hash identically however their JSON is laid
//! out, and however their maps and lists are ordered. The manifest is the
//! opposite — exactly one encoding ([`crate::canon`]). Both directions are
//! pinned by tests:
//!
//! * `tests/run_digest_golden.rs` — five representative workflows, pinned
//!   digests and pinned canonical bytes;
//! * `tests/run_digest_properties.rs` — reordering, reformatting, idempotence,
//!   and a mutation per field so nothing can be silently dropped.
//!
//! ```
//! use gitiup_attest::RunManifest;
//! use gitiup_attest::run::RunReport;
//! use gitiup_attest::StepOutcome;
//! # fn main() -> Result<(), gitiup_attest::Error> {
//! let report = RunReport::simple(
//!     "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!     ".github/workflows/ci.yml",
//!     "name: CI\non: push\n",
//!     "test result: ok. 42 passed\n",
//! )?;
//! let manifest = RunManifest::from_run(&report)?;
//! assert_eq!(manifest.result.steps[0].outcome, StepOutcome::Success);
//! // The digest is a function of the run, not of the moment it was measured:
//! assert_eq!(manifest.digest()?, manifest.digest()?);
//! assert_eq!(manifest.encode()?, manifest.canonical_bytes()?);
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::error::{Error, ErrorKind, Result};
use crate::manifest::{
    ActionPin, Artifact, Claims, Environment, EventContext, ImageRef, InputValue,
    NormalisationDiff, Provenance, RUN_MANIFEST_TYPE, RunManifest, RunResult, SCHEMA_VERSION,
    Source, Step, StepOutcome, StepTiming, Tier, ToolchainEntry, WorkflowRef,
};
use crate::oid::GitOid;

/// The normalisation version that means "nothing was rewritten".
///
/// A digest produced by [`RawText`] must never be mistaken for one a real
/// normalisation profile produced, so the version is not free to float.
pub const RAW_NORMALISATION_VERSION: u32 = 0;

/// The seam giti-1rs.3 (output normalisation) plugs into.
///
/// The digest computation does not know what a timestamp looks like. It knows
/// that some component rewrites logs so independent reruns converge, and that
/// the rules used must be recorded, because two results normalised by different
/// rules are not comparable
/// ([ADR-0001 D4](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
pub trait Normaliser {
    /// Value recorded in `provenance.normalisation_version`.
    fn version(&self) -> u32;

    /// Name used in diagnostics.
    fn name(&self) -> &str {
        "normaliser"
    }

    /// Rewrite one log stream. Called once per stream, on the whole text.
    fn normalise(&self, text: &str) -> String;
}

/// The default normaliser: hash exactly what the runner wrote.
///
/// Honest, and the right default for a report that hands over raw text — it
/// makes no promise that another machine would reproduce the digest. giti-1rs.3's
/// profile replaces it through [`RunManifest::from_run_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RawText;

impl Normaliser for RawText {
    fn version(&self) -> u32 {
        RAW_NORMALISATION_VERSION
    }

    fn name(&self) -> &str {
        "raw"
    }

    fn normalise(&self, text: &str) -> String {
        text.to_string()
    }
}

// ------------------------------------------------------------- material ---

/// Something hashable, handed over either pre-hashed or in the clear.
///
/// The tagging is explicit (`{"text": …}` vs `{"digest": …}`) rather than
/// inferred from the string's shape on purpose: sniffing "does this look like a
/// digest?" would let a log whose entire content happens to be `sha256:…` be
/// recorded as *claiming* that digest instead of the hash of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Material {
    /// `{"digest":"sha256:…"}` — already hashed by whoever produced it.
    Digest(Digest),
    /// `{"text":"…"}` — the bytes themselves, as UTF-8 text.
    Text(String),
    /// `{"parts":["…","…"]}` — several blobs hashed together with explicit
    /// lengths, so a split cannot collide with a concatenation
    /// ([`Digest::sha256_parts`]).
    Parts(Vec<String>),
    /// `{"files":{"path":{"text":"…"}, …}}` — a set of files treated as one
    /// artifact, hashed by [`file_set_digest`].
    Files(BTreeMap<String, Material>),
}

impl Default for Material {
    fn default() -> Self {
        Material::Text(String::new())
    }
}

impl Material {
    /// Text given in the clear.
    pub fn text(text: impl Into<String>) -> Material {
        Material::Text(text.into())
    }

    /// A digest the caller computed.
    pub fn digest(digest: Digest) -> Material {
        Material::Digest(digest)
    }

    /// Several blobs hashed as one, with explicit lengths.
    pub fn parts<I, S>(parts: I) -> Material
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Material::Parts(parts.into_iter().map(Into::into).collect())
    }

    /// A set of files given in the clear.
    pub fn files<I, S, M>(files: I) -> Material
    where
        I: IntoIterator<Item = (S, M)>,
        S: Into<String>,
        M: Into<Material>,
    {
        Material::Files(
            files
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }

    /// True when the caller hashed this itself, so normalisation already happened
    /// somewhere this crate cannot see.
    pub fn is_prehashed(&self) -> bool {
        matches!(self, Material::Digest(_))
    }

    /// True when there is nothing here at all.
    ///
    /// An empty stream hashes the same under every normalisation profile, so it
    /// never needs one — which is what lets a report omit a step's empty stderr
    /// without claiming a particular normalisation version.
    pub fn is_empty(&self) -> bool {
        match self {
            Material::Digest(_) => false,
            Material::Text(text) => text.is_empty(),
            Material::Parts(parts) => parts.iter().all(String::is_empty),
            Material::Files(files) => files.values().all(Material::is_empty),
        }
    }

    /// True when a [`Normaliser`] still has work to do on it.
    pub fn needs_normalising(&self) -> bool {
        !self.is_prehashed() && !self.is_empty()
    }

    /// Hash this as handed over, rewriting nothing.
    ///
    /// Used for event payloads, workflow sources and artifacts: those are inputs
    /// and products, not logs.
    pub fn hash(&self) -> Result<Digest> {
        match self {
            Material::Digest(digest) => Ok(digest.clone()),
            Material::Text(text) => Ok(Digest::sha256(text.as_bytes())),
            Material::Parts(parts) => Ok(Digest::sha256_parts(
                &parts.iter().map(|part| part.as_bytes()).collect::<Vec<_>>(),
            )),
            Material::Files(files) => {
                let mut digests: BTreeMap<String, Digest> = BTreeMap::new();
                for (path, material) in files {
                    if matches!(material, Material::Files(_)) {
                        return Err(Error::invalid(
                            "run report",
                            format!("artifact file '{path}' is itself a file set"),
                        )
                        .with_hint("flatten the tree: one entry per file"));
                    }
                    digests.insert(path.clone(), material.hash()?);
                }
                Ok(file_set_digest(&digests))
            }
        }
    }

    /// Hash a **log stream** after normalisation.
    pub fn hash_with(&self, normaliser: &dyn Normaliser) -> Result<Digest> {
        match self {
            Material::Digest(digest) => Ok(digest.clone()),
            Material::Text(text) => Ok(Digest::sha256(normaliser.normalise(text).as_bytes())),
            Material::Parts(parts) => {
                let parts: Vec<String> = parts
                    .iter()
                    .map(|part| normaliser.normalise(part))
                    .collect();
                Ok(Digest::sha256_parts(
                    &parts.iter().map(|part| part.as_bytes()).collect::<Vec<_>>(),
                ))
            }
            // A file set is an artifact, not a log: normalisation does not reach
            // inside it.
            Material::Files(_) => self.hash(),
        }
    }

    /// Byte size, when it can be known without lying.
    ///
    /// `None` for anything pre-hashed: a digest does not tell you how big the
    /// bytes were, and a guessed size inside a signed document is worse than an
    /// explicit one.
    pub fn size(&self) -> Option<i64> {
        match self {
            Material::Digest(_) => None,
            Material::Text(text) => Some(text.len() as i64),
            Material::Parts(parts) => Some(parts.iter().map(|part| part.len() as i64).sum()),
            Material::Files(files) => {
                let mut total: i64 = 0;
                for material in files.values() {
                    total += material.size()?;
                }
                Some(total)
            }
        }
    }
}

impl From<String> for Material {
    fn from(text: String) -> Self {
        Material::Text(text)
    }
}

impl From<&str> for Material {
    fn from(text: &str) -> Self {
        Material::Text(text.to_string())
    }
}

impl From<Digest> for Material {
    fn from(digest: Digest) -> Self {
        Material::Digest(digest)
    }
}

/// The digest of a *set* of files treated as one artifact.
///
/// Paths come from a [`BTreeMap`] (sorted by construction) and each
/// `(path, content digest)` pair is hashed with explicit lengths, so neither the
/// order a directory was walked in nor a rename can produce a collision. This is
/// the "sort artifact manifests" half of the reproducibility contract
/// (giti-1rs.3) written down as one function.
pub fn file_set_digest(entries: &BTreeMap<String, Digest>) -> Digest {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(entries.len() * 2);
    for (path, digest) in entries {
        parts.push(path.as_bytes());
        parts.push(digest.as_bytes());
    }
    Digest::sha256_parts(&parts)
}

// --------------------------------------------------------------- report ---

/// Where a workflow file came from: its path, plus its source as a git object id
/// or as the bytes to hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSource {
    /// Repository-relative path, e.g. `.github/workflows/ci.yml`.
    pub path: String,
    /// The committed file's object id (`sha1:…`, or `sha256:…` in a sha256
    /// repository). Mutually exclusive with `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid: Option<GitOid>,
    /// The file's contents, for a source that is not a git blob. The resulting
    /// oid is [`GitOid::content_sha256`] — always the raw bytes, never a
    /// normalised form, because this is a *source* identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl WorkflowSource {
    /// A workflow file that is a git blob.
    pub fn committed(path: impl Into<String>, oid: GitOid) -> WorkflowSource {
        WorkflowSource {
            path: path.into(),
            oid: Some(oid),
            text: None,
        }
    }

    /// A workflow file whose contents are handed over.
    pub fn from_text(path: impl Into<String>, text: impl Into<String>) -> WorkflowSource {
        WorkflowSource {
            path: path.into(),
            oid: None,
            text: Some(text.into()),
        }
    }

    /// Resolve to the manifest's [`WorkflowRef`], hashing the source when the
    /// report did not name it.
    pub fn resolve(&self) -> Result<WorkflowRef> {
        let oid = match (&self.oid, &self.text) {
            (Some(oid), None) => oid.clone(),
            (None, Some(text)) => GitOid::content_sha256(text.as_bytes()),
            (Some(_), Some(_)) => {
                return Err(Error::invalid(
                    "run report",
                    format!("workflow '{}' gives both an oid and text", self.path),
                )
                .with_hint("give one: the committed object id, or the contents"));
            }
            (None, None) => {
                return Err(Error::invalid(
                    "run report",
                    format!("workflow '{}' gives neither an oid nor text", self.path),
                ));
            }
        };
        Ok(WorkflowRef {
            path: self.path.clone(),
            oid,
        })
    }
}

/// The triggering event, with the payload handed over or already digested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReport {
    /// `pull_request`, `push`, `workflow_dispatch`, …
    pub name: String,
    /// Optional action qualifier (`opened`, `synchronize`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The payload as received. Hashed **unnormalised**: it is an input, and the
    /// digest has to pin what actually arrived.
    pub payload: Material,
}

/// The environment as a machine *class* — the fields giti-1rs.4 owns, minus the
/// fingerprint, which is derived here and cannot be asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentReport {
    /// Runner backend: `docker`, `podman`, `containerd`, `shell`, `simulated`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// OS id (`linux`, `macos`), lowercase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// CPU architecture (`x86_64`, `aarch64`). Required: an arm64 attestation
    /// must not be accepted against an amd64 requirement (giti-1rs.4).
    pub arch: String,
    /// Image the job ran in, digest-pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageRef>,
    /// Toolchain inventory; order irrelevant, sorted during normalization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub toolchain: Vec<ToolchainEntry>,
}

impl EnvironmentReport {
    /// Just an `arch` and nothing else — enough for a simulated plan.
    pub fn arch(arch: impl Into<String>) -> EnvironmentReport {
        EnvironmentReport {
            provider: None,
            os: None,
            arch: arch.into(),
            image: None,
            toolchain: Vec::new(),
        }
    }

    /// Build the manifest's [`Environment`] with a placeholder fingerprint;
    /// [`RunManifest::from_run`] fixes it, because the fingerprint is derived.
    pub fn to_environment(&self) -> Environment {
        Environment {
            provider: self.provider.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            image: self.image.clone(),
            toolchain: self.toolchain.clone(),
            fingerprint: Digest::sha256(b""),
        }
    }
}

/// One artifact as reported by a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReport {
    /// Artifact name as declared.
    pub name: String,
    /// Content: hashed here, or already hashed by the runner.
    pub content: Material,
    /// Size in bytes. Required when `content` is pre-hashed, derived from the
    /// bytes otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
}

impl ArtifactReport {
    fn to_artifact(&self) -> Result<Artifact> {
        let digest = self.content.hash()?;
        let Some(size_bytes) = self.size_bytes.or_else(|| self.content.size()) else {
            return Err(Error::invalid(
                "run report",
                format!(
                    "artifact '{}' is pre-hashed and has no size_bytes",
                    self.name
                ),
            )
            .with_hint("give size_bytes, or hand over the content"));
        };
        Ok(Artifact {
            name: self.name.clone(),
            digest,
            size_bytes,
        })
    }
}

/// One executed step as reported by the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepReport {
    /// `id:` as written, when the workflow gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `name:` as written, or the `uses:` string.
    pub name: String,
    /// The `uses:` value as written, if the step had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    /// Process exit code (0 for a skipped step).
    pub exit_code: i64,
    /// How the runner classified the step. Omit it to derive it from
    /// `exit_code`: 0 → `success`, anything else → `failure`. A `skipped` step
    /// has to say so, because a skipped step is not a step that passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<StepOutcome>,
    /// Normalised stdout — or the raw text, to be hashed as handed over.
    #[serde(default)]
    pub stdout: Material,
    /// Normalised stderr.
    #[serde(default)]
    pub stderr: Material,
    /// Step outputs, by value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, String>,
    /// Uploaded artifacts; order irrelevant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactReport>,
    /// Wall-clock evidence for this step; lands in `claims.timing` and never in
    /// `result` ([ADR-0001 D5](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<StepTiming>,
}

impl StepReport {
    /// A step with no id, no outputs and empty logs.
    pub fn run(name: impl Into<String>, exit_code: i64) -> StepReport {
        StepReport {
            id: None,
            name: name.into(),
            uses: None,
            exit_code,
            outcome: None,
            stdout: Material::default(),
            stderr: Material::default(),
            outputs: BTreeMap::new(),
            artifacts: Vec::new(),
            timing: None,
        }
    }

    /// The key `claims.timing` is indexed by: the id when there is one, the name
    /// otherwise.
    pub fn key(&self) -> String {
        self.id.clone().unwrap_or_else(|| self.name.clone())
    }

    /// The outcome the manifest records, derived when the runner did not say.
    fn outcome(&self) -> Result<StepOutcome> {
        match (self.outcome, self.exit_code) {
            (Some(StepOutcome::Skipped), code) if code != 0 => Err(Error::invalid(
                "run report",
                format!(
                    "step '{}' is skipped but reports exit code {code}",
                    self.name
                ),
            )
            .with_hint("a skipped step did not run, so it has no exit status: use 0")),
            (Some(outcome), _) => Ok(outcome),
            (None, 0) => Ok(StepOutcome::Success),
            (None, _) => Ok(StepOutcome::Failure),
        }
    }

    fn to_step(&self, normaliser: &dyn Normaliser) -> Result<Step> {
        Ok(Step {
            id: self.id.clone(),
            name: self.name.clone(),
            uses: self.uses.clone(),
            exit_code: self.exit_code,
            outcome: self.outcome()?,
            stdout: self.stdout.hash_with(normaliser)?,
            stderr: self.stderr.hash_with(normaliser)?,
            outputs: self.outputs.clone(),
            artifacts: self
                .artifacts
                .iter()
                .map(ArtifactReport::to_artifact)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

/// One step's timing, named by step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingReport {
    /// Step id, or step name when it has no id.
    pub step: String,
    /// Start, microseconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_us: Option<i64>,
    /// Duration in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<i64>,
}

/// The volatile half of a report: who ran it, when, and the evidence they kept.
///
/// Everything here is signed and stored but never compared for equality, so it
/// may name a clock, a hostname and a run id
/// ([ADR-0001 D4/D5](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReport {
    /// Unique per run, 16–64 lower-case hex characters.
    pub run_id: String,
    /// Claimed creation time, microseconds since the Unix epoch.
    pub claimed_at_us: i64,
    /// Optional lower bound on validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_us: Option<i64>,
    /// Optional upper bound, for short-lived grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_us: Option<i64>,
    /// Quorum challenge the verifier handed out (giti-msi.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_challenge: Option<Digest>,
    /// Per-step timings, in any order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timings: Vec<TimingReport>,
    /// What normalisation rewrote (giti-1rs.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalisation_diffs: Vec<NormalisationDiff>,
    /// Third-party extension fields (`x_*` by convention).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// A finished run, as handed to the digest computation.
///
/// Field order and JSON formatting are irrelevant: the report is a transport,
/// not a signed document. Only the manifest it produces has one encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    /// Human-facing repository identity. Not trusted for anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// The commit the run is bound to.
    pub commit: GitOid,
    /// The workflow that started the run.
    pub workflow: WorkflowSource,
    /// The event that triggered it.
    pub event: EventReport,
    /// Job id, when the workflow has more than one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    /// Matrix vector for this job.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub matrix: BTreeMap<String, String>,
    /// Declared job inputs, by value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, InputValue>,
    /// Names of the secrets that were made available — **names only**, never
    /// values (giti-bgy.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    /// Resolved pin for every `uses:`: the `uses:` string as written → repo +
    /// commit. This is the supply-chain record giti-bgy.4 checks.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pins: BTreeMap<String, ActionPin>,
    /// The reusable-workflow closure, in any order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reusable_workflows: Vec<WorkflowSource>,
    /// Where it ran, as a machine class.
    pub environment: EnvironmentReport,
    /// The steps, **in execution order** — the one order in a report that means
    /// something.
    pub steps: Vec<StepReport>,
    /// How the result came about. `normalisation_version` must match the
    /// [`Normaliser`] that produced (or is about to produce) the log digests.
    pub provenance: Provenance,
    /// Who claims it, and when.
    pub claims: ClaimReport,
}

impl RunReport {
    /// The smallest honest report: one simulated step with a log line.
    ///
    /// For tests, doc examples and smoke checks of `gitiup digest`.
    pub fn simple(
        commit: &str,
        workflow_path: &str,
        workflow_source: &str,
        log: &str,
    ) -> Result<RunReport> {
        Ok(RunReport {
            repo: None,
            commit: GitOid::from_str(commit)?,
            workflow: WorkflowSource::from_text(workflow_path, workflow_source),
            event: EventReport {
                name: "workflow_dispatch".into(),
                action: None,
                payload: Material::text("{}"),
            },
            job: None,
            matrix: BTreeMap::new(),
            inputs: BTreeMap::new(),
            secret_names: Vec::new(),
            pins: BTreeMap::new(),
            reusable_workflows: Vec::new(),
            environment: EnvironmentReport::arch("x86_64"),
            steps: vec![StepReport {
                stdout: Material::text(log),
                ..StepReport::run("run", 0)
            }],
            provenance: Provenance {
                tier: Tier::Simulated,
                runner: "gitiup 0.1.0".into(),
                normalisation_version: RAW_NORMALISATION_VERSION,
                sandbox: Some("none".into()),
            },
            claims: ClaimReport {
                run_id: "0000000000000000".into(),
                claimed_at_us: 1_793_092_502_500_000,
                not_before_us: None,
                not_after_us: None,
                verifier_challenge: None,
                timings: Vec::new(),
                normalisation_diffs: Vec::new(),
                annotations: BTreeMap::new(),
            },
        })
    }

    /// Checks a caller can run *before* hashing anything, with errors that name
    /// the field. Cheap, and called by [`RunManifest::from_run`] anyway.
    pub fn validate(&self) -> Result<()> {
        self.workflow.resolve()?;
        let mut closure_paths: Vec<&str> = Vec::with_capacity(self.reusable_workflows.len());
        for workflow in &self.reusable_workflows {
            workflow.resolve()?;
            if closure_paths.contains(&workflow.path.as_str()) {
                return Err(Error::invalid(
                    "run report",
                    format!(
                        "'{}' appears twice in the reusable-workflow closure",
                        workflow.path
                    ),
                ));
            }
            closure_paths.push(&workflow.path);
        }
        if self.event.name.is_empty() {
            return Err(Error::invalid("run report", "event.name is empty"));
        }
        if self.environment.arch.is_empty() {
            return Err(Error::invalid("run report", "environment.arch is empty"));
        }
        if self.steps.is_empty() {
            return Err(Error::invalid(
                "run report",
                "no steps: a run that did nothing proves nothing",
            ));
        }
        let mut keys: Vec<String> = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            step.outcome()?;
            if keys.contains(&step.key()) {
                return Err(Error::invalid(
                    "run report",
                    format!("step '{}' is reported twice", step.key()),
                ));
            }
            keys.push(step.key());
            for artifact in &step.artifacts {
                if artifact.name.is_empty() {
                    return Err(Error::invalid(
                        "run report",
                        format!("step '{}' reports an artifact with no name", step.name),
                    ));
                }
                // Hashing refuses the one thing size and name checks cannot see: a
                // file set nested inside a file set.
                artifact.content.hash()?;
            }
        }
        if self.provenance.tier == Tier::Quorum {
            return Err(Error::new(
                ErrorKind::Policy,
                "run report",
                "a single run may not claim the quorum tier",
            )
            .with_hint(
                "quorum is a verdict over several attestations (giti-msi.7); one run says local",
            ));
        }
        let mut timings: Vec<&str> = Vec::new();
        for timing in &self.claims.timings {
            if timings.contains(&timing.step.as_str()) {
                return Err(Error::invalid(
                    "run report",
                    format!("two timings reported for step '{}'", timing.step),
                ));
            }
            timings.push(&timing.step);
        }
        if self.pins.keys().any(String::is_empty) {
            return Err(Error::invalid("run report", "a pin has an empty alias"));
        }
        Ok(())
    }

    /// `claims.timing`, collected from the per-step timings and the explicit
    /// list, and keyed by step.
    fn timings(&self) -> Result<BTreeMap<String, StepTiming>> {
        let mut out: BTreeMap<String, StepTiming> = BTreeMap::new();
        for step in &self.steps {
            if let Some(timing) = &step.timing {
                out.insert(step.key(), timing.clone());
            }
        }
        for timing in &self.claims.timings {
            if out.contains_key(&timing.step) {
                return Err(Error::invalid(
                    "run report",
                    format!("step '{}' reports timing twice", timing.step),
                ));
            }
            out.insert(
                timing.step.clone(),
                StepTiming {
                    started_us: timing.started_us,
                    duration_us: timing.duration_us,
                },
            );
        }
        Ok(out)
    }

    /// Whether any log still has to be hashed here, rather than having arrived
    /// pre-hashed.
    fn has_raw_logs(&self) -> bool {
        self.steps
            .iter()
            .any(|step| step.stdout.needs_normalising() || step.stderr.needs_normalising())
    }
}

// -------------------------------------------------------------- digest ---

impl RunManifest {
    /// Compute the manifest of a finished run: the epic's `RunDigest` in one call.
    ///
    /// Everything derivable is derived — workflow source oid, event payload
    /// digest, per-step log digests (with [`RawText`], i.e. unchanged), artifact
    /// digests, the environment fingerprint, every mandated sort order — and the
    /// result is validated before it is returned, so a caller cannot sign a
    /// manifest that a verifier would refuse.
    ///
    /// ```
    /// use gitiup_attest::RunManifest;
    /// use gitiup_attest::run::RunReport;
    /// # fn main() -> Result<(), gitiup_attest::Error> {
    /// let report: RunReport = serde_json::from_str(
    ///     r#"{"commit":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ///         "workflow":{"path":"ci.yml","text":"name: CI"},
    ///         "event":{"name":"push","payload":{"text":"{}"}},
    ///         "environment":{"arch":"x86_64"},
    ///         "steps":[{"name":"run","exit_code":0}],
    ///         "provenance":{"tier":"simulated","runner":"gitiup 0.1.0",
    ///                       "normalisation_version":0},
    ///         "claims":{"run_id":"0000000000000000","claimed_at_us":1793092502500000}}"#,
    /// )
    /// .unwrap();
    /// let manifest = RunManifest::from_run(&report)?;
    /// assert_eq!(manifest.encode()?, manifest.canonical_bytes()?);
    /// assert_eq!(manifest.digest()?.hex().len(), 64);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_run(report: &RunReport) -> Result<RunManifest> {
        RunManifest::from_run_with(report, &RawText)
    }

    /// [`Self::from_run`] with a normalisation profile (giti-1rs.3).
    ///
    /// A report that hands over raw log text must declare the profile's
    /// [`Normaliser::version`] as its `normalisation_version`: the rules that
    /// produced a digest are a property of the digest, not something a caller
    /// gets to assert separately. A report whose logs arrived pre-digested keeps
    /// the version it declared, because those digests were produced elsewhere.
    pub fn from_run_with(report: &RunReport, normaliser: &dyn Normaliser) -> Result<RunManifest> {
        report.validate()?;
        if report.has_raw_logs() && report.provenance.normalisation_version != normaliser.version()
        {
            return Err(Error::invalid(
                "run report",
                format!(
                    "the report hands over raw log text but declares normalisation_version {}; the {} profile is version {}",
                    report.provenance.normalisation_version,
                    normaliser.name(),
                    normaliser.version()
                ),
            )
            .with_hint("declare the version of the profile that will normalise it, or hand over the digests"));
        }

        let mut manifest = RunManifest {
            schema_version: SCHEMA_VERSION,
            attestation_type: RUN_MANIFEST_TYPE.into(),
            result: RunResult {
                source: Source {
                    repo: report.repo.clone(),
                    commit: report.commit.clone(),
                    workflow: report.workflow.resolve()?,
                    event: EventContext {
                        name: report.event.name.clone(),
                        action: report.event.action.clone(),
                        payload: report.event.payload.hash()?,
                    },
                    job: report.job.clone(),
                    matrix: report.matrix.clone(),
                },
                inputs: report.inputs.clone(),
                secret_names: report.secret_names.clone(),
                pins: report.pins.clone(),
                reusable_workflows: report
                    .reusable_workflows
                    .iter()
                    .map(WorkflowSource::resolve)
                    .collect::<Result<Vec<_>>>()?,
                environment: report.environment.to_environment(),
                steps: report
                    .steps
                    .iter()
                    .map(|step| step.to_step(normaliser))
                    .collect::<Result<Vec<_>>>()?,
                provenance: report.provenance.clone(),
            },
            claims: Claims {
                run_id: report.claims.run_id.clone(),
                claimed_at_us: report.claims.claimed_at_us,
                not_before_us: report.claims.not_before_us,
                not_after_us: report.claims.not_after_us,
                verifier_challenge: report.claims.verifier_challenge.clone(),
                timing: report.timings()?,
                normalisation_diffs: report.claims.normalisation_diffs.clone(),
                annotations: report.claims.annotations.clone(),
            },
        };
        // The production steps, in one place so a producer cannot skip one:
        // sort what must be sorted, derive the fingerprint, then check the
        // manifest against the same rules a verifier will apply.
        manifest.normalize();
        manifest.result.environment.fix_fingerprint()?;
        manifest.validate()?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn report() -> RunReport {
        RunReport {
            repo: Some("gitiup/gitiup".into()),
            commit: GitOid::from_sha1_hex(&"a".repeat(40)).unwrap(),
            workflow: WorkflowSource::from_text(".github/workflows/ci.yml", "name: CI\non: push\n"),
            event: EventReport {
                name: "pull_request".into(),
                action: Some("synchronize".into()),
                payload: Material::text("{\"action\":\"synchronize\"}"),
            },
            job: Some("build".into()),
            matrix: BTreeMap::from([("os".to_string(), "ubuntu-24.04".into())]),
            inputs: BTreeMap::from([("jobs".to_string(), InputValue::Int(4))]),
            secret_names: vec!["NPM_TOKEN".into()],
            pins: BTreeMap::from([(
                "actions/checkout@v4".to_string(),
                ActionPin {
                    repo: "actions/checkout".into(),
                    commit: GitOid::from_sha1_hex(&"c".repeat(40)).unwrap(),
                    reference: Some("v4".into()),
                },
            )]),
            reusable_workflows: vec![WorkflowSource::committed(
                ".github/workflows/_lint.yml",
                GitOid::from_sha1_hex(&"d".repeat(40)).unwrap(),
            )],
            environment: EnvironmentReport {
                provider: Some("docker".into()),
                os: Some("linux".into()),
                arch: "x86_64".into(),
                image: Some(ImageRef {
                    reference: Some("ubuntu:24.04".into()),
                    digest: Digest::sha256(b"ubuntu-24.04"),
                }),
                toolchain: vec![
                    ToolchainEntry {
                        name: "git".into(),
                        version: "2.47.0".into(),
                    },
                    ToolchainEntry {
                        name: "rustc".into(),
                        version: "1.99.1".into(),
                    },
                ],
            },
            steps: vec![
                StepReport {
                    id: Some("checkout".into()),
                    stdout: Material::text("Checked out\n"),
                    timing: Some(StepTiming {
                        started_us: Some(1_793_092_500_000_000),
                        duration_us: Some(5),
                    }),
                    ..StepReport::run("Checkout", 0)
                },
                StepReport {
                    id: Some("build".into()),
                    uses: Some("actions/checkout@v4".into()),
                    stdout: Material::text("test result: ok\n"),
                    outputs: BTreeMap::from([("coverage".to_string(), "91".into())]),
                    artifacts: vec![ArtifactReport {
                        name: "coverage.lcov".into(),
                        content: Material::text("TN:\nDA:1,1\n"),
                        size_bytes: None,
                    }],
                    ..StepReport::run("cargo test", 0)
                },
            ],
            provenance: Provenance {
                tier: Tier::Local,
                runner: "gitiup 0.1.0".into(),
                normalisation_version: RAW_NORMALISATION_VERSION,
                sandbox: Some("docker".into()),
            },
            claims: ClaimReport {
                run_id: "0123456789abcdef".into(),
                claimed_at_us: 1_793_092_502_500_000,
                not_before_us: None,
                not_after_us: None,
                verifier_challenge: None,
                timings: Vec::new(),
                normalisation_diffs: Vec::new(),
                annotations: BTreeMap::from([("x_ci".to_string(), "local".into())]),
            },
        }
    }

    fn digest_of(report: &RunReport) -> String {
        RunManifest::from_run(report)
            .unwrap()
            .digest()
            .unwrap()
            .to_string()
    }

    fn result_digest_of(report: &RunReport) -> String {
        RunManifest::from_run(report)
            .unwrap()
            .result_digest()
            .unwrap()
            .to_string()
    }

    #[test]
    fn a_report_produces_a_valid_manifest() {
        let manifest = RunManifest::from_run(&report()).unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.result.steps.len(), 2);
        assert_eq!(manifest.result.steps[1].artifacts.len(), 1);
        assert_eq!(manifest.result.steps[1].artifacts[0].size_bytes, 11);
        assert_eq!(
            manifest.result.environment.fingerprint,
            manifest.result.environment.compute_fingerprint().unwrap()
        );
        // The mandated sorts happened: toolchain ordered by name, and the
        // environment fingerprint covers it.
        let names: Vec<&str> = manifest
            .result
            .environment
            .toolchain
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(names, vec!["git", "rustc"]);
        assert!(
            manifest.result.steps[1]
                .artifacts
                .iter()
                .all(|a| a.size_bytes > 0)
        );
    }

    #[test]
    fn encode_is_the_canonical_bytes_and_is_stable() {
        let manifest = RunManifest::from_run(&report()).unwrap();
        assert_eq!(manifest.digest().unwrap(), manifest.digest().unwrap());
        let encoded = manifest.encode().unwrap();
        assert_eq!(encoded, manifest.canonical_bytes().unwrap());
        assert!(crate::canon::is_canonical(&encoded));
        // Reading back the bytes the producer wrote yields the same manifest, so
        // "what was stored" and "what was signed" cannot drift apart.
        assert_eq!(
            RunManifest::from_canonical_bytes(&encoded).unwrap(),
            manifest
        );
    }

    #[test]
    fn reordering_report_lists_cannot_move_the_digest() {
        let base = report();
        let mut shuffled = report();
        shuffled.secret_names = vec!["NPM_TOKEN".into(), "CODECOV_TOKEN".into()];
        let mut reordered = report();
        reordered.secret_names = vec!["CODECOV_TOKEN".into(), "NPM_TOKEN".into()];
        assert_eq!(
            result_digest_of(&shuffled),
            result_digest_of(&{
                let mut c = shuffled.clone();
                c.secret_names.reverse();
                c
            })
        );
        // … and the lists are not being ignored: one extra name moves it.
        assert_ne!(result_digest_of(&base), result_digest_of(&shuffled));
        assert_ne!(result_digest_of(&base), result_digest_of(&reordered));

        let mut toolchains = base.clone();
        toolchains.environment.toolchain.reverse();
        assert_eq!(result_digest_of(&base), result_digest_of(&toolchains));

        let mut closure = base.clone();
        closure.reusable_workflows.push(WorkflowSource::committed(
            ".github/workflows/_extra.yml",
            GitOid::from_sha1_hex(&"e".repeat(40)).unwrap(),
        ));
        let mut closure_reordered = closure.clone();
        closure_reordered.reusable_workflows.reverse();
        assert_eq!(
            result_digest_of(&closure),
            result_digest_of(&closure_reordered)
        );
        assert_ne!(result_digest_of(&base), result_digest_of(&closure));
    }

    #[test]
    fn report_formatting_cannot_move_the_digest() {
        let compact = serde_json::to_string(&report()).unwrap();
        let pretty = serde_json::to_string_pretty(&report()).unwrap();
        assert_ne!(compact, pretty, "the two renderings must differ");
        let a: RunReport = serde_json::from_str(&compact).unwrap();
        let b: RunReport = serde_json::from_str(&pretty).unwrap();
        assert_eq!(a, b);
        assert_eq!(digest_of(&a), digest_of(&b));
        assert_eq!(result_digest_of(&a), result_digest_of(&b));
    }

    #[test]
    fn volatile_claims_move_the_run_digest_only() {
        let mut other = report();
        other.claims.run_id = "9999999999999999".into();
        other.claims.claimed_at_us += 1_000_000;
        other.claims.timings.push(TimingReport {
            step: "build".into(),
            started_us: None,
            duration_us: Some(12),
        });
        let base = RunManifest::from_run(&report()).unwrap();
        let other = RunManifest::from_run(&other).unwrap();
        assert_eq!(
            base.result_digest().unwrap(),
            other.result_digest().unwrap()
        );
        assert_ne!(base.digest().unwrap(), other.digest().unwrap());
    }

    #[test]
    fn material_hashes_are_what_they_claim() {
        assert_eq!(
            Material::text("abc").hash().unwrap(),
            Digest::sha256(b"abc")
        );
        // Explicit lengths: one blob is not the same as two.
        assert_ne!(
            Material::parts(["ab", "c"]).hash().unwrap(),
            Material::text("abc").hash().unwrap()
        );
        // A file set is sorted by path and hashed per entry.
        let set_a = Material::files([
            ("b.txt", Material::text("2")),
            ("a.txt", Material::text("1")),
        ]);
        let set_b = Material::files([
            ("a.txt", Material::text("1")),
            ("b.txt", Material::text("2")),
        ]);
        assert_eq!(set_a.hash().unwrap(), set_b.hash().unwrap());
        assert_eq!(set_a.size(), Some(2));
        // A rename is a different artifact, and nesting is refused.
        let renamed = Material::files([
            ("c.txt", Material::text("2")),
            ("a.txt", Material::text("1")),
        ]);
        assert_ne!(set_a.hash().unwrap(), renamed.hash().unwrap());
        let nested = Material::files([("dir", Material::files([("a", Material::text("1"))]))]);
        assert!(nested.hash().is_err());
    }

    #[test]
    fn a_prehashed_digest_is_taken_as_given() {
        let claimed = Digest::sha256(b"someone else's normalisation");
        let manifest = RunManifest::from_run(&RunReport {
            steps: vec![StepReport {
                stdout: Material::digest(claimed.clone()),
                ..StepReport::run("normalised", 0)
            }],
            provenance: Provenance {
                normalisation_version: 7,
                ..report().provenance
            },
            ..report()
        })
        .unwrap();
        assert_eq!(manifest.result.steps[0].stdout, claimed);
        assert_eq!(manifest.result.provenance.normalisation_version, 7);
    }

    #[test]
    fn raw_logs_must_declare_the_profile_that_is_about_to_touch_them() {
        struct Shout;
        impl Normaliser for Shout {
            fn version(&self) -> u32 {
                3
            }
            fn name(&self) -> &str {
                "shout"
            }
            fn normalise(&self, text: &str) -> String {
                text.to_uppercase()
            }
        }
        let claimed_otherwise = RunReport {
            provenance: Provenance {
                normalisation_version: 5,
                ..report().provenance
            },
            ..report()
        };
        let err = RunManifest::from_run(&claimed_otherwise).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert!(err.detail().contains("normalisation_version"));
        // A profile that matches takes them over, and the version is recorded.
        let with_profile = RunManifest::from_run_with(&claimed_otherwise, &Shout);
        assert!(with_profile.is_err(), "version 5 is not the shout profile");
        let mut declared = claimed_otherwise.clone();
        declared.provenance.normalisation_version = 3;
        let with_profile = RunManifest::from_run_with(&declared, &Shout).unwrap();
        assert_eq!(with_profile.result.provenance.normalisation_version, 3);
        assert_ne!(
            with_profile.result_digest().unwrap(),
            RunManifest::from_run(&report())
                .unwrap()
                .result_digest()
                .unwrap()
        );
    }

    #[test]
    fn normalisation_reaches_logs_and_nothing_else() {
        struct Shout;
        impl Normaliser for Shout {
            fn version(&self) -> u32 {
                0
            }
            fn normalise(&self, text: &str) -> String {
                text.to_uppercase()
            }
        }
        let rewritten = RunManifest::from_run_with(&report(), &Shout).unwrap();
        let plain = RunManifest::from_run(&report()).unwrap();
        assert_ne!(
            rewritten.result.steps[1].stdout, plain.result.steps[1].stdout,
            "logs are the normaliser's business"
        );
        assert_eq!(
            rewritten.result.source.event.payload, plain.result.source.event.payload,
            "the event payload pins what arrived"
        );
        assert_eq!(
            rewritten.result.source.workflow.oid, plain.result.source.workflow.oid,
            "a source identity is never rewritten"
        );
        assert_eq!(
            rewritten.result.steps[1].artifacts[0].digest,
            plain.result.steps[1].artifacts[0].digest,
            "an artifact is a product, not a log"
        );
    }

    #[test]
    fn workflow_and_event_sources_are_hashed_as_received() {
        let manifest = RunManifest::from_run(&report()).unwrap();
        assert_eq!(
            manifest.result.source.workflow.oid,
            GitOid::content_sha256(b"name: CI\non: push\n")
        );
        assert_eq!(
            manifest.result.source.event.payload,
            Digest::sha256(b"{\"action\":\"synchronize\"}")
        );
    }

    #[test]
    fn outcome_is_derived_unless_the_runner_says_otherwise() {
        let mut report = report();
        report.steps = vec![
            StepReport::run("passed", 0),
            StepReport::run("failed", 3),
            StepReport {
                outcome: Some(StepOutcome::Skipped),
                ..StepReport::run("skipped", 0)
            },
        ];
        let manifest = RunManifest::from_run(&report).unwrap();
        assert_eq!(
            manifest
                .result
                .steps
                .iter()
                .map(|step| step.outcome)
                .collect::<Vec<_>>(),
            vec![
                StepOutcome::Success,
                StepOutcome::Failure,
                StepOutcome::Skipped
            ]
        );
        // A skipped step that claims an exit status contradicts itself.
        report.steps[2].exit_code = 1;
        assert!(RunManifest::from_run(&report).is_err());
    }

    #[test]
    fn an_empty_stream_needs_no_profile() {
        // The same empty log under every profile: a report may omit it whatever
        // the declared normalisation version, which keeps hand-written reports
        // honest instead of forcing a placeholder digest per absent stream.
        let mut quiet = report();
        quiet.steps = vec![StepReport::run("silent", 0)];
        quiet.provenance.normalisation_version = 11;
        let manifest = RunManifest::from_run(&quiet).unwrap();
        assert_eq!(manifest.result.steps[0].stdout, Digest::sha256(b""));
        assert_eq!(manifest.result.provenance.normalisation_version, 11);
    }

    #[test]
    fn reports_that_lie_are_refused_before_anything_is_hashed() {
        let sha_b = GitOid::from_sha1_hex(&"b".repeat(40)).unwrap();
        let cases: Vec<(&str, RunReport, &str)> = vec![
            (
                "both oid and text",
                RunReport {
                    workflow: WorkflowSource {
                        path: "ci.yml".into(),
                        oid: Some(sha_b.clone()),
                        text: Some("name: CI".into()),
                    },
                    ..report()
                },
                "both an oid and text",
            ),
            (
                "neither oid nor text",
                RunReport {
                    workflow: WorkflowSource {
                        path: "ci.yml".into(),
                        oid: None,
                        text: None,
                    },
                    ..report()
                },
                "neither an oid nor text",
            ),
            (
                "no steps",
                RunReport {
                    steps: Vec::new(),
                    ..report()
                },
                "no steps",
            ),
            (
                "duplicate step",
                RunReport {
                    steps: vec![StepReport::run("x", 0), StepReport::run("x", 0)],
                    ..report()
                },
                "reported twice",
            ),
            (
                "quorum tier",
                RunReport {
                    provenance: Provenance {
                        tier: Tier::Quorum,
                        ..report().provenance
                    },
                    ..report()
                },
                "quorum tier",
            ),
            (
                "empty arch",
                RunReport {
                    environment: EnvironmentReport::arch(""),
                    ..report()
                },
                "arch",
            ),
            (
                "duplicate closure path",
                RunReport {
                    reusable_workflows: vec![
                        WorkflowSource::committed("a.yml", sha_b.clone()),
                        WorkflowSource::committed("a.yml", sha_b),
                    ],
                    ..report()
                },
                "twice in the reusable-workflow closure",
            ),
            (
                "prehashed artifact without a size",
                RunReport {
                    steps: vec![StepReport {
                        artifacts: vec![ArtifactReport {
                            name: "out".into(),
                            content: Material::digest(Digest::sha256(b"x")),
                            size_bytes: None,
                        }],
                        ..StepReport::run("build", 0)
                    }],
                    ..report()
                },
                "size_bytes",
            ),
            (
                "raw logs with someone else's normalisation version",
                RunReport {
                    provenance: Provenance {
                        normalisation_version: 1,
                        ..report().provenance
                    },
                    ..report()
                },
                "normalisation_version",
            ),
            (
                "empty event name",
                RunReport {
                    event: EventReport {
                        name: String::new(),
                        action: None,
                        payload: Material::text("{}"),
                    },
                    ..report()
                },
                "event.name",
            ),
        ];
        for (what, bad, because) in cases {
            let err = RunManifest::from_run(&bad).unwrap_err();
            assert!(
                err.detail().contains(because),
                "{what}: expected a complaint about {because:?}, got {err}"
            );
        }
    }

    #[test]
    fn unknown_fields_in_a_report_are_named() {
        let text = serde_json::to_string(&report()).unwrap();
        let typo = text.replace("\"toolchain\"", "\"toochain\"");
        assert_ne!(text, typo, "the fixture must contain a toolchain");
        let err = serde_json::from_str::<RunReport>(&typo).unwrap_err();
        assert!(
            err.to_string().contains("toochain"),
            "the error should name the typo, got {err}"
        );
    }

    #[test]
    fn floats_are_refused_not_rounded() {
        // `"duration_us": 5.5` is a bug in whatever wrote it, and truncating it
        // silently would be worse: the manifest allows integers only.
        let text = serde_json::to_string(&report()).unwrap();
        let floaty = text.replace("\"duration_us\":5", "\"duration_us\":5.5");
        assert_ne!(text, floaty, "the fixture must contain duration_us");
        assert!(serde_json::from_str::<RunReport>(&floaty).is_err());
    }

    #[test]
    fn from_run_is_idempotent_and_survives_a_round_trip() {
        let once = RunManifest::from_run(&report()).unwrap();
        let bytes = once.encode().unwrap();
        assert_eq!(once, RunManifest::from_run(&report()).unwrap());
        let read_back = RunManifest::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(read_back, once);
        assert_eq!(read_back.encode().unwrap(), bytes);
        // Re-running the production steps changes nothing: a manifest is a fixed
        // point of its own production.
        let mut remade = once.clone();
        remade.normalize();
        remade.result.environment.fix_fingerprint().unwrap();
        remade.validate().unwrap();
        assert_eq!(remade, once);
    }
}

//! The run manifest: the thing that gets signed.
//!
//! Shape ([ADR-0001 D4](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md),
//! normative schema in [`schema`](crate::schema)):
//!
//! ```text
//! { schema_version, type, result {…}, claims {…} }
//! ```
//!
//! The split into `result` and `claims` is the most important thing on this page.
//! A quorum works by N volunteers reaching *the same digest* for the same change
//! ([`giti-msi`](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)),
//! and two honest runs never agree on the accidental parts: when each ran, how
//! long step 3 took, which hostname stripped the paths, which random run id was
//! chosen. If those lived in the same object as the run's outcome, digests would
//! differ forever and the quorum would report disagreement on runs that agreed.
//! So:
//!
//! * **`result`** — everything a re-run reproduces: source, pins, inputs,
//!   environment, per-step outcome, provenance. Its digest ([`ResultDigest`]) is
//!   what verifiers compare. Nothing in here may vary between two runs of the same
//!   change on equivalent machines; [ADR-0001 D5](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
//!   keeps the register of what counts as volatile.
//! * **`claims`** — who/when/where, plus debugging evidence. Signed, stored and
//!   policy-checked (freshness lives here), but never compared for equality.
//!
//! ```text
//! RunDigest    = sha256(canonical(the whole manifest))   ← signed, stored, the attestation's name
//! ResultDigest = sha256(canonical(the `result` member)) ← what two verifiers compare
//! ```
//!
//! Because `ResultDigest` is a digest over part of the signed document, a
//! verifier that agrees on `ResultDigest` still has a signature over the whole
//! thing: agreeing on the outcome and proving who claimed it are the same act.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canon;
use crate::digest::Digest;
use crate::error::{Error, ErrorKind, Result};
use crate::oid::GitOid;

/// The `type` value of a v1 run manifest. Inside the signed payload on purpose:
/// it is what stops a v2 document being passed off as v1.
pub const RUN_MANIFEST_TYPE: &str = "https://gitiup.dev/attestation/run/1";

/// The `schema_version` this crate writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest number of steps a manifest may describe.
pub const MAX_STEPS: usize = 4096;

/// Largest accepted length of any single string field.
pub const MAX_STRING_LEN: usize = 16 * 1024;

/// Largest number of entries in any one list or map.
pub const MAX_ENTRIES: usize = 4096;

/// A manifest: `result` (reproducible) plus `claims` (volatile), both signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    /// Format version; must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// [`RUN_MANIFEST_TYPE`]. Called `type` on the wire.
    #[serde(rename = "type")]
    pub attestation_type: String,
    /// The reproducible outcome.
    pub result: RunResult,
    /// The volatile claims.
    pub claims: Claims,
}

/// Everything a faithful re-run reproduces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    /// What was run, and on what change.
    pub source: Source,
    /// Declared job inputs, by value. Composite values are flattened to the
    /// string the runner actually passed to the action.
    #[serde(default, skip_serializing_if = "with_map")]
    pub inputs: BTreeMap<String, InputValue>,
    /// Names of the secrets that were made available — never their values
    /// (giti-bgy.3). Sorted and de-duplicated.
    #[serde(default, skip_serializing_if = "with_vec")]
    pub secret_names: Vec<String>,
    /// Resolved pin for every `uses:` in the run: alias → repo + commit.
    #[serde(default, skip_serializing_if = "with_map")]
    pub pins: BTreeMap<String, ActionPin>,
    /// The reusable-workflow closure, sorted by `path`.
    #[serde(default, skip_serializing_if = "with_vec")]
    pub reusable_workflows: Vec<WorkflowRef>,
    /// Where it ran, as a machine *class*, not a machine identity.
    pub environment: Environment,
    /// Per-step outcomes, in execution order (the one order that is meaningful).
    pub steps: Vec<Step>,
    /// How this result came about.
    pub provenance: Provenance,
}

impl RunResult {
    fn sorted_lists_are_stable(&self) -> bool {
        is_sorted_unique(&self.secret_names, |s: &String| s.clone())
            && is_sorted_unique(&self.reusable_workflows, |w: &WorkflowRef| w.path.clone())
            && self.environment.is_toolchain_sorted()
            && self.steps.iter().all(|s| {
                is_sorted_by(
                    s.artifacts
                        .iter()
                        .map(|a| (a.name.as_str(), a.digest.to_string())),
                )
            })
    }

    /// Sort the spec-mandated lists so two producers converge. Called by
    /// producers (giti-1rs.2) after building a manifest; cheap and idempotent.
    pub fn normalize(&mut self) {
        sort_dedup(&mut self.secret_names);
        sort_dedup_by(&mut self.reusable_workflows, |w| w.path.clone());
        sort_dedup_by(&mut self.environment.toolchain, |t| {
            (t.name.clone(), t.version.clone())
        });
        for step in &mut self.steps {
            sort_dedup_by(&mut step.artifacts, |a| {
                (a.name.clone(), a.digest.to_string())
            });
        }
    }

    /// Digest of just this member: the value two independent verifiers compare
    /// ([`ResultDigest`]).
    pub fn digest(&self) -> Result<ResultDigest> {
        Ok(ResultDigest(Digest::sha256(&canon::to_bytes(self)?)))
    }
}

/// Digest of the `result` member. Distinct newtype so two digests can never be
/// confused in a function signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResultDigest(pub Digest);

impl ResultDigest {
    /// The wrapped digest.
    pub fn inner(&self) -> &Digest {
        &self.0
    }
}

impl std::fmt::Display for ResultDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What was run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Human-facing repository identity (URL or host-relative name). Not trusted
    /// for anything: the commit and the signature are what matter.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub repo: Option<String>,
    /// The commit the run is bound to. An attestation whose commit does not match
    /// the change it is offered for is worthless (giti-kd4.3 refuses exactly that).
    pub commit: GitOid,
    /// The workflow file that started the run.
    pub workflow: WorkflowRef,
    /// The event that triggered it.
    pub event: EventContext,
    /// Job id, when the workflow has more than one.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub job: Option<String>,
    /// Matrix vector for this job, sorted by construction (`BTreeMap`).
    #[serde(default, skip_serializing_if = "with_map")]
    pub matrix: BTreeMap<String, String>,
}

/// A workflow file: its path plus the source that was executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRef {
    /// Repository-relative path, e.g. `.github/workflows/ci.yml`.
    pub path: String,
    /// The source that was executed. A git blob id when the file is committed
    /// (`sha1:…`); otherwise the SHA-256 of the file bytes (`sha256:…`), which is
    /// why the algorithm is part of the string.
    pub oid: GitOid,
}

/// The triggering event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContext {
    /// `pull_request`, `push`, `workflow_dispatch`, …
    pub name: String,
    /// Optional action qualifier (`opened`, `synchronize`, …).
    #[serde(default, skip_serializing_if = "with_opt")]
    pub action: Option<String>,
    /// Digest of the event payload as received. The payload itself stays out of
    /// the manifest: it is large, full of volatile ids, and a digest pins it.
    pub payload: Digest,
}

/// A resolved `uses:` pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionPin {
    /// `actions/checkout`, or a full URL for a third-party action.
    pub repo: String,
    /// The immutable commit that was checked out — the supply-chain pin
    /// (giti-bgy.4 refuses a run whose pins are floating refs).
    pub commit: GitOid,
    /// The ref the user *wrote* (`v4`, `main`), kept only as evidence of what the
    /// pin resolved from. Verification never trusts it.
    #[serde(default, skip_serializing_if = "with_opt")]
    #[serde(rename = "ref")]
    pub reference: Option<String>,
}

/// Where the run happened: a machine *class*.
///
/// `fingerprint` is *derived*, not asserted (see [`Environment::compute_fingerprint`]),
/// so it cannot be used to describe one environment while claiming another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    /// Runner provider/backend: `docker`, `podman`, `containerd`, `shell`, `simulated`.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub provider: Option<String>,
    /// OS id (`linux`, `macos`), lowercase.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub os: Option<String>,
    /// OS version as the OS reports it (`24.04` from `/etc/os-release`).
    ///
    /// Separate from [`Self::os`] because a policy asks the two questions
    /// separately: "is this Linux?" and "how much may it move?" — the version is
    /// the field `require-env-match = major` rounds, the id never moves.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub os_version: Option<String>,
    /// CPU architecture as Rust reports it (`x86_64`, `aarch64`).
    ///
    /// Stored in Rust's spelling and compared through [`crate::Arch`], so a policy
    /// that says `amd64` is not refused for spelling it the Debian way
    /// (giti-1rs.4).
    pub arch: String,
    /// Image the job ran in, digest-pinned.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub image: Option<ImageRef>,
    /// Toolchain inventory, sorted by `(name, version)`.
    #[serde(default, skip_serializing_if = "with_vec")]
    pub toolchain: Vec<ToolchainEntry>,
    /// Digest over the fields above.
    pub fingerprint: Digest,
}

/// A container image reference pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRef {
    /// What was asked for (`ubuntu:24.04`), evidence only.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub reference: Option<String>,
    /// What was actually pulled (`sha256:…`). A floating tag is not a pin.
    pub digest: Digest,
}

/// One toolchain entry (`rustc` 1.99.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainEntry {
    /// Tool name, lowercase.
    pub name: String,
    /// Version string as the tool reports it.
    pub version: String,
}

impl Environment {
    /// The version recorded for `tool`, if the run reported that tool at all.
    pub fn find_tool(&self, tool: &str) -> Option<&str> {
        self.toolchain
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(tool.trim()))
            .map(|entry| entry.version.as_str())
    }

    /// The machine class in one line, for a refusal or a status print.
    ///
    /// Deliberately the fields a human compares by eye: a fingerprint mismatch with
    /// this beside it is a diagnosis instead of a puzzle (giti-1rs.4).
    pub fn describe(&self) -> String {
        let image = self.image.as_ref().map(|image| {
            image
                .reference
                .clone()
                .unwrap_or_else(|| image.digest.to_string())
        });
        let mut parts = Vec::new();
        for (label, value) in [
            ("os", self.os.as_deref()),
            ("version", self.os_version.as_deref()),
            ("arch", Some(self.arch.as_str())),
            ("image", image.as_deref()),
            ("provider", self.provider.as_deref()),
        ] {
            if let Some(value) = value {
                parts.push(format!("{label} {value}"));
            }
        }
        parts.join(" · ")
    }

    /// The toolchain inventory as `name version` pairs.
    pub fn describe_toolchain(&self) -> String {
        if self.toolchain.is_empty() {
            return "no toolchain inventory".to_string();
        }
        self.toolchain
            .iter()
            .map(|entry| format!("{} {}", entry.name, entry.version))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The fingerprint of the fields above, computed the one sanctioned way:
    /// SHA-256 over the canonical bytes of this environment with `fingerprint`
    /// cleared.
    pub fn compute_fingerprint(&self) -> Result<Digest> {
        let mut bare = self.clone();
        bare.fingerprint = Digest::sha256(b"");
        Ok(Digest::sha256(&canon::to_bytes(&bare)?))
    }

    /// Set `fingerprint` to [`Self::compute_fingerprint`].
    pub fn fix_fingerprint(&mut self) -> Result<()> {
        let fp = self.compute_fingerprint()?;
        self.fingerprint = fp;
        Ok(())
    }

    fn is_toolchain_sorted(&self) -> bool {
        is_sorted_by(
            self.toolchain
                .iter()
                .map(|t| (t.name.as_str(), t.version.as_str())),
        )
    }
}

/// One executed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// `id:` as written, when the workflow gave one.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub id: Option<String>,
    /// `name:` as written, or the `uses:` string.
    pub name: String,
    /// The `uses:` value as written, if the step had one.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub uses: Option<String>,
    /// Process exit code (0 for a skipped step).
    pub exit_code: i64,
    /// How the runner classified the step.
    pub outcome: StepOutcome,
    /// Digest of the **normalised** stdout (giti-1rs.3 normalises; the raw log is
    /// not part of the attestation).
    pub stdout: Digest,
    /// Digest of the **normalised** stderr.
    pub stderr: Digest,
    /// Step outputs, by value.
    #[serde(default, skip_serializing_if = "with_map")]
    pub outputs: BTreeMap<String, String>,
    /// Uploaded artifacts, sorted by `(name, digest)`.
    #[serde(default, skip_serializing_if = "with_vec")]
    pub artifacts: Vec<Artifact>,
}

/// How a step ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// Ran and succeeded.
    Success,
    /// Ran and failed.
    Failure,
    /// Did not run (`if:` false, or a previous step failed).
    Skipped,
}

/// An artifact produced by a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Artifact name as declared.
    pub name: String,
    /// Digest of the artifact content (or of the manifest, for a directory).
    pub digest: Digest,
    /// Uncompressed size in bytes — kept for humans and for `--json` consumers.
    pub size_bytes: i64,
}

/// How the result came about (giti-1rs.7 owns the meanings; the vocabulary is
/// fixed here because the digest depends on it).
///
/// The three fields are one claim, not three, and [`Provenance::check`] checks
/// them together: a tier is only believable next to the sandbox and the secrets
/// it implies. That is why `local` requires a named sandbox and `simulated`
/// forbids one — see [the tier table](../../../docs/provenance-tiers.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Provenance tier. A run executed by a selected volunteer says `local`: the
    /// `quorum` tier is a *verdict over several attestations*, recorded separately
    /// (giti-msi.7), never self-asserted by one run.
    pub tier: Tier,
    /// Runner implementation and version, e.g. `gitiup 0.1.0`.
    pub runner: String,
    /// Version of the normalisation rules that produced the digests
    /// (giti-1rs.3). Two results with different versions are not comparable.
    pub normalisation_version: u32,
    /// Sandbox backend that confined the run, if any (`docker`, `landlock`, …).
    ///
    /// [`NO_SANDBOX`] (or absent) means "nothing confined this", which is honest
    /// for a plan and not honest for a run. Policy narrows the list further
    /// ([`crate::Policy::allowed_sandboxes`]); this field only states the fact.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub sandbox: Option<String>,
}

/// The `sandbox` value that means "nothing confined this run".
///
/// Spelled, not `None`, so a producer states the absence rather than forgetting
/// the field — and so a plan says out loud that it never executed.
pub const NO_SANDBOX: &str = "none";

/// Names that mean the same as [`NO_SANDBOX`], however a producer writes it.
pub const NO_SANDBOX_ALIASES: [&str; 4] = ["none", "off", "no", ""];

impl Provenance {
    /// The backend that confined the run, or `None` when nothing did.
    ///
    /// [`NO_SANDBOX`] and its aliases are all read as "nothing", so a producer
    /// cannot write `"off"` where a gate expects an absent field.
    pub fn confining_sandbox(&self) -> Option<&str> {
        match self.sandbox.as_deref() {
            Some(name) if !NO_SANDBOX_ALIASES.contains(&name) => Some(name),
            _ => None,
        }
    }

    /// The consistency rules that make a tier unforgable, given the secret names
    /// the run had access to.
    ///
    /// Checked when a manifest is produced *and* when one is verified, by
    /// [`RunManifest::validate`] and by [`crate::run::RunReport::validate`], so a
    /// lie is refused at the first moment it is knowable rather than at the merge
    /// gate. Three rules, one per tier:
    ///
    /// | tier | rule | why |
    ///|------|------|-----|
    ///| `quorum` | never in a run manifest | quorum is a verdict *over* attestations (giti-msi.7); one run cannot vote for the others |
    ///| `simulated` | no secrets, no confining sandbox | nothing ran, so there was nothing to confine and nothing to hand it |
    ///| `local` | a sandbox must be named | "really executed" without saying *where* is the shape of a laundered run |
    pub fn check(&self, secret_names: &[String]) -> crate::Result<()> {
        let sandbox = self.confining_sandbox();
        match self.tier {
            Tier::Quorum => Err(Error::new(
                ErrorKind::Policy,
                "provenance",
                "a single run may not claim the quorum tier",
            )
            .with_hint(
                "quorum is a verdict over several attestations (giti-msi.7); one run says local",
            )),
            Tier::Simulated => {
                if let Some(name) = sandbox {
                    return Err(Error::new(
                        ErrorKind::Policy,
                        "provenance",
                        format!(
                            "a simulated run cannot claim sandbox '{name}': nothing executed, so nothing needed confining"
                        ),
                    )
                    .with_hint(format!("a plan says \"sandbox\": \"{NO_SANDBOX}\", or omits the field")));
                }
                if let Some(first) = secret_names.first() {
                    return Err(Error::new(
                        ErrorKind::Policy,
                        "provenance",
                        format!(
                            "a simulated run cannot claim secrets were available ('{first}' and {} more)",
                            secret_names.len().saturating_sub(1)
                        ),
                    )
                    .with_hint("a simulated run touches no secrets; drop secret_names, or execute for real"));
                }
                Ok(())
            }
            Tier::Local => {
                if sandbox.is_none() {
                    return Err(Error::new(
                        ErrorKind::Policy,
                        "provenance",
                        "tier 'local' asserts real execution, which must name the sandbox that confined it",
                    )
                    .with_hint(format!(
                        "name what confined it — a container or namespace backend (docker, podman, unshare, landlock), or \"shell\" if it truly ran on the host; \"{NO_SANDBOX}\" belongs to a simulated run, not to an execution nobody can locate"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Provenance tiers, in increasing order of external evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Planned and replayed from declared outputs; no side effects, no network,
    /// no secrets. The safe default, and never enough to satisfy a merge gate
    /// that asks for execution.
    Simulated,
    /// Really executed, by whoever signed it.
    Local,
    /// Confirmed by a quorum of independent runs. Not valid in a run manifest:
    /// present so policy, gates and logs share one vocabulary.
    Quorum,
}

impl Tier {
    /// Every tier, lowest evidence first.
    pub const ALL: [Tier; 3] = [Tier::Simulated, Tier::Local, Tier::Quorum];

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Simulated => "simulated",
            Tier::Local => "local",
            Tier::Quorum => "quorum",
        }
    }

    /// Parse a tier name, tolerating case and surrounding whitespace because
    /// these come from hand-written policy files.
    ///
    /// The error lists the vocabulary: a typo in `allowed_tiers` must not read as
    /// "your policy silently accepts less than you meant".
    pub fn parse(text: &str) -> Result<Tier> {
        let trimmed = text.trim().to_ascii_lowercase();
        Tier::ALL
            .iter()
            .find(|tier| tier.as_str() == trimmed)
            .copied()
            .ok_or_else(|| {
                Error::invalid("provenance", format!("'{text}' is not a provenance tier"))
                    .with_hint(format!(
                        "tiers are {}",
                        Tier::ALL
                            .iter()
                            .map(|t| t.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
            })
    }

    /// Can one run honestly claim this about itself?
    ///
    /// Only [`Tier::Quorum`] fails, because a quorum is a conclusion drawn from
    /// several signed attestations and never a property of one run — that is the
    /// single most abusable claim in this vocabulary, so it is refused in the
    /// format rather than left to policy
    /// ([`Provenance::check`]).
    pub const fn claimable_by_single_run(self) -> bool {
        !matches!(self, Tier::Quorum)
    }

    /// Did anything actually execute?
    ///
    /// The question a merge gate asks: `simulated` proves what a run *would*
    /// have done; the other two describe work that happened.
    pub const fn is_executed(self) -> bool {
        !matches!(self, Tier::Simulated)
    }

    /// The loud warning a trust-bearing use of this tier deserves, if any.
    ///
    /// Kept here rather than in the CLI so every consumer — `gitiup run`,
    /// `gitiup verify attestation`, a merge gate printing a verdict — says the
    /// same uncomfortable sentence. `local` is silent: it is what a normal run
    /// claims, and a warning nobody has read since Tuesday is noise that hides
    /// the one that matters.
    pub fn trust_warning(self) -> Option<&'static str> {
        match self {
            Tier::Simulated => Some(
                "SIMULATED: nothing was executed. This attestation describes a plan \
                 and proves intent, not behaviour: no code ran, no network was used, \
                 no artifact was produced.",
            ),
            Tier::Local | Tier::Quorum => None,
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Tier {
    type Err = Error;

    fn from_str(text: &str) -> Result<Tier> {
        Tier::parse(text)
    }
}

/// The volatile half: who claimed this, when, and the evidence they kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Unique per run, 8–32 bytes as lower-case hex. Stops two runs of the same
    /// commit producing one identical attestation ([ADR-0001 D6](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
    pub run_id: String,
    /// Claimed creation time, microseconds since the Unix epoch. An integer, not
    /// an RFC 3339 string, so there is exactly one encoding; the CLI formats it.
    pub claimed_at_us: i64,
    /// Optional lower bound on validity (defaults to `claimed_at_us`).
    #[serde(default, skip_serializing_if = "with_opt")]
    pub not_before_us: Option<i64>,
    /// Optional upper bound, used for short-lived grants (a quorum lease).
    #[serde(default, skip_serializing_if = "with_opt")]
    pub not_after_us: Option<i64>,
    /// Commit-reveal binding for quorum selection (giti-msi.6): the challenge the
    /// verifier was handed, so a submission cannot be moved between rounds.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub verifier_challenge: Option<Digest>,
    /// Per-step wall-clock evidence. Deliberately outside `result`: durations
    /// never agree between machines, and a digest must.
    #[serde(default, skip_serializing_if = "with_map")]
    pub timing: BTreeMap<String, StepTiming>,
    /// What normalisation had to rewrite (giti-1rs.3). Evidence for a dispute,
    /// so it lives with the claims: the `before` side is machine-specific by
    /// definition and would poison a digest.
    #[serde(default, skip_serializing_if = "with_vec")]
    pub normalisation_diffs: Vec<NormalisationDiff>,
    /// Extension point for third-party fields (`x_*` by convention). Free-form
    /// *strings* only, so a custom field can never change the meaning of a typed
    /// one by being richer than it.
    #[serde(default, skip_serializing_if = "with_map")]
    pub annotations: BTreeMap<String, String>,
}

/// Wall-clock evidence for one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepTiming {
    /// Start, microseconds since the epoch.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub started_us: Option<i64>,
    /// Wall-clock duration in microseconds.
    #[serde(default, skip_serializing_if = "with_opt")]
    pub duration_us: Option<i64>,
}

/// One normalisation rewrite, as reported by the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalisationDiff {
    /// Step id or name the rewrite happened in.
    pub step: String,
    /// Normalisation kind (`timestamp`, `path`, `hostname`, `locale`, …).
    pub kind: String,
    /// Text before rewriting.
    pub before: String,
    /// Text after rewriting.
    pub after: String,
}

/// A job input value. Scalars only: the runner hands actions scalars, and a
/// composite value would mean two ways to encode one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InputValue {
    /// Free text.
    Text(String),
    /// Integer (never a float — see [`canon`]).
    Int(i64),
    /// Boolean.
    Bool(bool),
}

// -------------------------------------------------------------- digests ---

impl RunManifest {
    /// Canonical bytes of the whole manifest: the signed payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canon::to_bytes(self)
    }

    /// The bytes to sign and to store: the canonical encoding, per
    /// [ADR-0001 D1](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md).
    ///
    /// The producer-facing name for [`Self::canonical_bytes`], spelled out
    /// because "encode" is the step giti-1rs.2's pipeline talks about (*build →
    /// normalize → encode → digest → sign*) and because there is exactly one
    /// answer: no pretty-printing, no second encoding, no leniency. Bytes written
    /// by anything else are a different attestation of the same run.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.canonical_bytes()
    }

    /// Re-parse bytes that claim to be a canonical manifest, then check them.
    ///
    /// This is the only sanctioned way to read a manifest from storage: bytes that
    /// are merely *valid JSON* are refused rather than silently re-encoded.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<RunManifest> {
        let value = canon::require_canonical(bytes)?;
        let manifest: RunManifest =
            serde_json::from_value(value).map_err(|e| Error::invalid("manifest", e.to_string()))?;
        manifest.validate()?;
        let again = manifest.canonical_bytes()?;
        if again != bytes {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "manifest",
                "the bytes received are not the canonical encoding of the manifest they hold",
            )
            .with_hint("transport must not reformat the signed payload"));
        }
        Ok(manifest)
    }

    /// `sha256(canonical(manifest))` — the attestation's name
    /// ([ADR-0001 D2](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::sha256(&self.canonical_bytes()?))
    }

    /// `sha256(canonical(result))` — what independent verifiers compare.
    pub fn result_digest(&self) -> Result<ResultDigest> {
        self.result.digest()
    }

    /// The environment fingerprint this manifest carries — giti-1rs.4's
    /// `EnvFingerprint`, the digest that identifies the machine class the run
    /// happened in.
    ///
    /// Every valid manifest carries one: it is a required field and
    /// [`Self::validate`] re-derives it, so there is no such thing as a manifest
    /// whose environment is unidentified.
    pub fn env_fingerprint(&self) -> &Digest {
        &self.result.environment.fingerprint
    }

    /// Sort every list the spec mandates a sort order for, including the claim-side
    /// ones. Producers (giti-1rs.2) call this once, after building the manifest:
    /// it is what makes two honest runs hash the same bytes.
    pub fn normalize(&mut self) {
        self.result.normalize();
        sort_dedup_by(&mut self.claims.normalisation_diffs, |d| {
            (d.step.clone(), d.kind.clone())
        });
    }

    /// Semantic checks that the type system cannot express. Cheap; always run
    /// before trusting a manifest, including one just built in memory.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "manifest",
                format!(
                    "schema_version {} is not understood by this build",
                    self.schema_version
                ),
            )
            .with_hint(format!("this build writes schema_version {SCHEMA_VERSION}")));
        }
        if self.attestation_type != RUN_MANIFEST_TYPE {
            return Err(Error::new(
                ErrorKind::UnsupportedSchema,
                "manifest",
                format!("unknown attestation type '{}'", self.attestation_type),
            ));
        }

        self.check_run_id()?;
        self.check_time()?;
        self.check_sizes()?;

        let result = &self.result;
        if result.steps.is_empty() {
            return Err(Error::invalid(
                "manifest",
                "no steps: a run that did nothing proves nothing",
            ));
        }
        if result.steps.len() > MAX_STEPS {
            return Err(Error::invalid(
                "manifest",
                format!("{} steps exceeds the {MAX_STEPS} limit", result.steps.len()),
            ));
        }
        let mut ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for step in &result.steps {
            check_string("step name", &step.name)?;
            if let Some(id) = &step.id {
                check_string("step id", id)?;
                if !ids.insert(id.as_str()) {
                    return Err(Error::invalid(
                        "manifest",
                        format!("duplicate step id '{id}'"),
                    ));
                }
            }
            if step.exit_code < 0 && step.outcome == StepOutcome::Success {
                return Err(Error::invalid(
                    "manifest",
                    format!(
                        "step '{}' claims success with a negative exit code",
                        step.name
                    ),
                ));
            }
            if step.artifacts.len() > MAX_ENTRIES {
                return Err(Error::invalid(
                    "manifest",
                    format!("step '{}' has too many artifacts", step.name),
                ));
            }
        }

        self.result.provenance.check(&result.secret_names)?;

        if !result.sorted_lists_are_stable() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "manifest",
                "secret_names, reusable_workflows, toolchain and artifacts must be sorted and unique, so that two producers hash the same bytes",
            )
            .with_hint("call RunResult::normalize() after building the manifest"));
        }

        if !is_sorted_by(
            self.claims
                .normalisation_diffs
                .iter()
                .map(|d| (d.step.as_str(), d.kind.as_str())),
        ) {
            return Err(Error::new(
                ErrorKind::Invalid,
                "manifest",
                "claims.normalisation_diffs must be sorted by (step, kind)",
            )
            .with_hint("call RunManifest::normalize()"));
        }

        let expected = result.environment.compute_fingerprint()?;
        if expected != result.environment.fingerprint {
            return Err(Error::new(
                ErrorKind::DigestMismatch,
                "environment",
                format!(
                    "claimed fingerprint {} is not the fingerprint of the environment described ({expected})",
                    result.environment.fingerprint
                ),
            )
            .with_hint("the fingerprint is derived: call Environment::fix_fingerprint()"));
        }
        if result.environment.arch.is_empty() {
            return Err(Error::invalid("manifest", "environment.arch is required"));
        }
        if let Some(os) = &result.environment.os {
            check_string("environment.os", os)?;
        }
        if let Some(version) = &result.environment.os_version {
            check_string("environment.os_version", version)?;
        }
        for entry in &result.environment.toolchain {
            check_string("toolchain name", &entry.name)?;
            check_string("toolchain version", &entry.version)?;
        }

        for (name, pin) in &result.pins {
            check_string("pin alias", name)?;
            check_string("pin repo", &pin.repo)?;
        }
        for workflow in &result.reusable_workflows {
            check_string("workflow path", &workflow.path)?;
        }
        check_string("workflow path", &result.source.workflow.path)?;
        check_string("event name", &result.source.event.name)?;
        if let Some(repo) = &result.source.repo {
            check_string("repo", repo)?;
        }
        for (key, value) in &self.claims.annotations {
            check_string("annotation key", key)?;
            check_string("annotation value", value)?;
        }
        for diff in &self.claims.normalisation_diffs {
            check_string("diff step", &diff.step)?;
            check_string("diff kind", &diff.kind)?;
        }
        Ok(())
    }

    fn check_run_id(&self) -> Result<()> {
        let id = &self.claims.run_id;
        let ok = (16..=64).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(Error::invalid(
                "manifest",
                format!("run_id '{id}' must be 16-64 lower-case hex characters"),
            )
            .with_hint("16 random bytes as hex is the usual choice"));
        }
        Ok(())
    }

    fn check_time(&self) -> Result<()> {
        if self.claims.claimed_at_us <= 0 {
            return Err(Error::invalid(
                "manifest",
                "claimed_at_us must be a positive microsecond timestamp",
            ));
        }
        if let Some(start) = self.claims.not_before_us
            && start > self.claims.claimed_at_us
        {
            return Err(Error::invalid(
                "manifest",
                "not_before_us is after the claimed creation time",
            ));
        }
        if let Some(end) = self.claims.not_after_us
            && end <= self.claims.claimed_at_us
        {
            return Err(Error::invalid(
                "manifest",
                "not_after_us is not after the claimed creation time",
            ));
        }
        Ok(())
    }

    fn check_sizes(&self) -> Result<()> {
        let result = &self.result;
        if result.inputs.len() > MAX_ENTRIES
            || result.pins.len() > MAX_ENTRIES
            || result.source.matrix.len() > MAX_ENTRIES
            || self.claims.annotations.len() > MAX_ENTRIES
            || self.claims.timing.len() > MAX_ENTRIES
            || self.claims.normalisation_diffs.len() > MAX_ENTRIES
            || result.secret_names.len() > MAX_ENTRIES
            || result.reusable_workflows.len() > MAX_ENTRIES
            || result.environment.toolchain.len() > MAX_ENTRIES
        {
            return Err(Error::invalid(
                "manifest",
                format!("a collection exceeds the {MAX_ENTRIES} entry limit"),
            ));
        }
        for value in result.inputs.values() {
            if let InputValue::Text(text) = value {
                check_string("input value", text)?;
            }
        }
        for (key, value) in &result.source.matrix {
            check_string("matrix key", key)?;
            check_string("matrix value", value)?;
        }
        for step in &result.steps {
            for (key, value) in &step.outputs {
                check_string("output name", key)?;
                check_string("output value", value)?;
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------- helpers ----

fn check_string(what: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::invalid("manifest", format!("{what} is empty")));
    }
    if value.len() > MAX_STRING_LEN {
        return Err(Error::invalid(
            "manifest",
            format!("{what} is longer than {MAX_STRING_LEN} bytes"),
        ));
    }
    if value.chars().any(|c| (c as u32) < 0x20 && c != '\t') {
        return Err(Error::invalid(
            "manifest",
            format!("{what} contains control characters"),
        ));
    }
    Ok(())
}

fn is_sorted_by<I, T>(items: I) -> bool
where
    I: IntoIterator<Item = T>,
    T: Ord,
{
    let mut previous: Option<T> = None;
    for item in items {
        if let Some(prev) = &previous
            && *prev >= item
        {
            return false;
        }
        previous = Some(item);
    }
    true
}

fn is_sorted_unique<T, K>(items: &[T], key: fn(&T) -> K) -> bool
where
    K: Ord,
{
    let mut previous: Option<K> = None;
    for item in items {
        let k = key(item);
        if let Some(prev) = &previous
            && *prev >= k
        {
            return false;
        }
        previous = Some(k);
    }
    true
}

fn sort_dedup(items: &mut Vec<String>) {
    items.sort();
    items.dedup();
}

fn sort_dedup_by<T, K: Ord>(items: &mut Vec<T>, key: fn(&T) -> K) {
    items.sort_by_key(&key);
    items.dedup_by(|a, b| key(a) == key(b));
}

/// `skip_serializing_if` hooks, named so the field attributes stay readable.
mod skip {
    use super::*;

    pub fn map<V>(map: &BTreeMap<String, V>) -> bool {
        map.is_empty()
    }

    pub fn vec<T>(vec: &[T]) -> bool {
        vec.is_empty()
    }

    pub fn opt<T>(opt: &Option<T>) -> bool {
        opt.is_none()
    }
}
use skip::{map as with_map, opt as with_opt, vec as with_vec};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample;

    #[test]
    fn sample_is_valid_and_canonical() {
        let manifest = sample::simulated();
        manifest.validate().expect("sample validates");
        let bytes = manifest.canonical_bytes().unwrap();
        assert!(canon::is_canonical(&bytes));
        assert_eq!(RunManifest::from_canonical_bytes(&bytes).unwrap(), manifest);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let manifest = sample::simulated();
        let mut value: serde_json::Value = serde_json::to_value(&manifest).unwrap();
        value["result"]["steps"][0]["surprise"] = serde_json::json!(1);
        let bytes = canon::to_value_bytes(&value).unwrap();
        let err = RunManifest::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Invalid);
        // … and a re-encode that drops the unknown field is caught too, so a
        // reader cannot quietly "fix" bytes that were signed.
        let mut stripped = value.clone();
        stripped["result"]["steps"][0]
            .as_object_mut()
            .unwrap()
            .remove("surprise");
        assert_eq!(
            RunManifest::from_canonical_bytes(&canon::to_value_bytes(&stripped).unwrap()).unwrap(),
            manifest
        );
    }

    #[test]
    fn version_and_type_are_binding() {
        let mut manifest = sample::simulated();
        manifest.schema_version = 2;
        assert_eq!(
            manifest.validate().unwrap_err().kind(),
            ErrorKind::UnsupportedSchema
        );
        let mut manifest = sample::simulated();
        manifest.attestation_type = "https://gitiup.dev/attestation/run/2".into();
        assert_eq!(
            manifest.validate().unwrap_err().kind(),
            ErrorKind::UnsupportedSchema
        );
    }

    #[test]
    fn result_and_run_digests_differ_and_track_the_split() {
        let mut a = sample::simulated();
        let mut b = sample::simulated();
        b.claims.run_id = "22".repeat(16);
        b.claims.claimed_at_us += 1_000_000;
        assert_eq!(
            a.result_digest().unwrap(),
            b.result_digest().unwrap(),
            "different runs of the same result must agree on the result digest"
        );
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());

        // A real change to the outcome moves both.
        b = sample::simulated();
        b.result.steps[0].exit_code = 1;
        b.result.steps[0].outcome = StepOutcome::Failure;
        b.result.environment.fix_fingerprint().unwrap();
        a.result.steps[0].exit_code = 0;
        assert_ne!(a.result_digest().unwrap(), b.result_digest().unwrap());
    }

    #[test]
    fn fingerprint_is_derived() {
        let mut manifest = sample::simulated();
        manifest.result.environment.toolchain.push(ToolchainEntry {
            name: "zig".into(),
            version: "0.14".into(),
        });
        manifest.result.normalize();
        let err = manifest.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DigestMismatch);
        manifest.result.environment.fix_fingerprint().unwrap();
        manifest.validate().unwrap();
    }

    #[test]
    fn lists_must_be_sorted() {
        let mut manifest = sample::local();
        manifest.result.secret_names = vec!["z".into(), "a".into()];
        let err = manifest.validate().unwrap_err();
        assert!(err.detail().contains("sorted"));
        manifest.result.normalize();
        manifest.validate().unwrap();
    }

    #[test]
    fn claims_are_shape_checked() {
        let bad_run_ids = [
            String::new(),
            "abc".into(),
            "AB".repeat(8),
            "z".repeat(16),
            "a".repeat(65),
        ];
        for bad_run_id in &bad_run_ids {
            let mut manifest = sample::simulated();
            manifest.claims.run_id = bad_run_id.into();
            assert!(
                manifest.validate().is_err(),
                "run_id {bad_run_id:?} accepted"
            );
        }
        let mut manifest = sample::simulated();
        manifest.claims.not_after_us = Some(manifest.claims.claimed_at_us - 1);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn null_is_never_emitted() {
        let bytes = sample::local().canonical_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("null"), "a null leaked into {text}");
    }
}

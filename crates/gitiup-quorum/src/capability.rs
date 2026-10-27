//! Roster tiers, claimed capabilities, and the ordered eligibility filter
//! ([ADR-0002 D5, D7](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! Two things live here, and they are different in kind:
//!
//! * [`RosterTier`] is the owner's answer to "do I vouch for this box?". It is
//!   *owned by the roster*, never self-declared, and it is used in exactly two
//!   places: the floor filter and the per-tier caps. It is not a vote weight and
//!   it does not appear in a score.
//! * [`Capabilities`] is a *claim* about a machine, and [`Requirements`] is what a
//!   job needs. The filter that compares them runs in a fixed order so the reason
//!   printed for a near-miss is part of the contract, not a coincidence of the
//!   implementation.
//!
//! Claims are cheap to make before selection and checked after the run
//! (D7): a verifier that claims `x86_64` and reports `aarch64` in its signed
//! [`Environment`](gitiup_attest::Environment) has its attestation refused by the
//! verdict engine, not by this module.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A roster tier: the owner's vouch for a machine ([ADR-0002 D5](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// Distinct from [`gitiup_attest::Tier`], which is a *provenance* tier about how a
/// result was produced. A roster tier says who the owner trusts to be selected; a
/// provenance tier says what a signature is evidence of. Conflating them is the
/// mistake this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RosterTier {
    /// Self-signed, no vouch. The cheap on-ramp, and the tier the caps are there
    /// to limit.
    #[serde(rename = "anonymous")]
    Anonymous,
    /// Vouched: an endorsement, an organisation member, a clean history the owner
    /// actually checked.
    #[serde(rename = "endorsed")]
    Endorsed,
    /// The owner's own keys and first-party CI. Capped at one seat by default so
    /// a quorum cannot become the owner's laptop plus four strangers' opinions.
    #[serde(rename = "trusted")]
    Trusted,
}

impl RosterTier {
    /// Every tier, lowest vouch first.
    pub const ALL: [RosterTier; 3] = [
        RosterTier::Anonymous,
        RosterTier::Endorsed,
        RosterTier::Trusted,
    ];

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RosterTier::Anonymous => "anonymous",
            RosterTier::Endorsed => "endorsed",
            RosterTier::Trusted => "trusted",
        }
    }

    /// The numeric rank used by the `tier_floor` filter. Explicit, so a reordering
    /// of [`RosterTier::ALL`] cannot silently change who is eligible.
    pub fn rank(self) -> u8 {
        match self {
            RosterTier::Anonymous => 0,
            RosterTier::Endorsed => 1,
            RosterTier::Trusted => 2,
        }
    }

    /// Parse a tier name; tolerant of case and padding because these come from
    /// hand-written files, and loud about the vocabulary when wrong.
    pub fn parse(text: &str) -> Result<RosterTier> {
        let trimmed = text.trim().to_ascii_lowercase();
        RosterTier::ALL
            .iter()
            .find(|t| t.as_str() == trimmed)
            .copied()
            .ok_or_else(|| {
                Error::invalid("roster tier", format!("'{text}' is not a roster tier")).with_hint(
                    format!(
                        "tiers are {}",
                        RosterTier::ALL
                            .iter()
                            .map(|t| t.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                )
            })
    }
}

impl std::fmt::Display for RosterTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RosterTier {
    type Err = Error;
    fn from_str(text: &str) -> Result<RosterTier> {
        RosterTier::parse(text)
    }
}

/// What a machine claims it can run ([ADR-0002 D7](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// Self-attested, and deliberately not cheap to lie about *afterwards*: the
/// signature on a roster entry proves who claimed it, which is what makes a lie a
/// attributable event rather than a free upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Architectures this box can run (`x86_64`, `aarch64`). Non-empty.
    pub arch: Vec<String>,
    /// RAM in megabytes.
    pub ram_mb: u64,
    /// Usable disk in megabytes.
    pub disk_mb: u64,
    /// Digest-pinned images already in the local cache.
    #[serde(default)]
    pub image_cache: Vec<String>,
    /// Whether the box can pull an image it does not have. `false` means the
    /// `images` filter applies.
    #[serde(default)]
    pub can_pull: bool,
    /// Sandbox backends available (`docker`, `podman`, `unshare`, `landlock`).
    pub sandboxes: Vec<String>,
    /// Strength of the strongest sandbox available: `0` none, `1` user namespace,
    /// `2` container, `3` container plus egress proxy. Compared against
    /// [`Requirements::min_sandbox_level`].
    pub sandbox_level: u8,
}

impl Capabilities {
    /// Structural checks: the claim has to be readable before it can be filtered.
    pub fn validate(&self) -> Result<()> {
        if self.arch.is_empty() || self.arch.iter().any(|a| a.is_empty()) {
            return Err(Error::invalid(
                "capabilities",
                "arch must be a non-empty list of non-empty names",
            ));
        }
        if self.sandboxes.is_empty() || self.sandboxes.iter().any(|s| s.is_empty()) {
            return Err(Error::invalid(
                "capabilities",
                "sandboxes must be a non-empty list; a box with no sandbox may not join a roster",
            )
            .with_hint(
                "giti-bgy.1 owns the backends; volunteer mode refuses to serve without one",
            ));
        }
        if self.ram_mb == 0 || self.disk_mb == 0 {
            return Err(Error::invalid(
                "capabilities",
                "ram_mb and disk_mb must be positive (a zero claim never matches a real job)",
            ));
        }
        if self.arch.len() > 32 || self.sandboxes.len() > 32 || self.image_cache.len() > 512 {
            return Err(Error::invalid(
                "capabilities",
                "capability lists are bounded (32 arches, 32 sandboxes, 512 cached images)",
            ));
        }
        for image in &self.image_cache {
            digest_shape(image)?;
        }
        Ok(())
    }
}

/// What a job needs. Derived from the job, never chosen by the verifier — that
/// direction is the whole point of the filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirements {
    /// The one architecture this round selects for. A matrix with two arches is
    /// two rounds, each with its own seed (D7).
    pub arch: String,
    /// RAM in megabytes.
    pub ram_mb: u64,
    /// Disk in megabytes.
    pub disk_mb: u64,
    /// Digest-pinned images the job needs.
    #[serde(default)]
    pub image_digests: Vec<String>,
    /// Acceptable sandbox backends; a candidate must offer at least one.
    pub sandboxes: Vec<String>,
    /// Minimum sandbox strength.
    pub min_sandbox_level: u8,
}

impl Requirements {
    /// Structural checks.
    pub fn validate(&self) -> Result<()> {
        if self.arch.is_empty() {
            return Err(Error::invalid("requirements", "arch is required"));
        }
        if self.sandboxes.is_empty() || self.sandboxes.iter().any(|s| s.is_empty()) {
            return Err(Error::invalid(
                "requirements",
                "sandboxes must name at least one acceptable backend",
            ));
        }
        if self.ram_mb == 0 || self.disk_mb == 0 {
            return Err(Error::invalid(
                "requirements",
                "ram_mb and disk_mb must be positive: a zero requirement selects every box and proves nothing",
            ));
        }
        for image in &self.image_digests {
            digest_shape(image)?;
        }
        Ok(())
    }
}

/// The reason a roster entry was not eligible, in the order the filters run.
///
/// The order is normative ([ADR-0002 D7](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)):
/// an entry that fails two filters must always print the same one, or two honest
/// `--explain` implementations disagree about a document a human is supposed to
/// audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exclusion {
    /// The entry is not valid for this roster epoch.
    Window,
    /// Below the policy's `tier_floor`.
    TierFloor,
    /// The key id, or its principal's identity, is excluded (proposer family,
    /// quarantine, escalation).
    Excluded,
    /// Cannot run the required architecture.
    Arch,
    /// Not enough RAM.
    Ram,
    /// Not enough disk.
    Disk,
    /// Missing a pinned image and cannot pull.
    Images,
    /// No sandbox backend in common with the job.
    Sandboxes,
    /// Sandbox weaker than the job demands.
    SandboxLevel,
}

impl Exclusion {
    /// Wire name, and the sort key: the position in D7's order.
    pub fn as_str(self) -> &'static str {
        match self {
            Exclusion::Window => "window",
            Exclusion::TierFloor => "tier_floor",
            Exclusion::Excluded => "excluded",
            Exclusion::Arch => "arch",
            Exclusion::Ram => "ram",
            Exclusion::Disk => "disk",
            Exclusion::Images => "images",
            Exclusion::Sandboxes => "sandboxes",
            Exclusion::SandboxLevel => "sandbox_level",
        }
    }

    /// Every exclusion, in filter order.
    pub const ALL: [Exclusion; 9] = [
        Exclusion::Window,
        Exclusion::TierFloor,
        Exclusion::Excluded,
        Exclusion::Arch,
        Exclusion::Ram,
        Exclusion::Disk,
        Exclusion::Images,
        Exclusion::Sandboxes,
        Exclusion::SandboxLevel,
    ];
}

impl std::fmt::Display for Exclusion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The first failing filter for one entry, if any ([ADR-0002 D7](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
///
/// Pure, ordered and total: every entry gets either `None` or the *first* reason,
/// which is what makes the audit table reproducible.
pub fn exclusion_of(
    entry: &crate::roster::RosterEntry,
    epoch: u64,
    requirements: &Requirements,
    exclusions: &std::collections::BTreeSet<String>,
    tier_floor: RosterTier,
) -> Option<Exclusion> {
    let caps = &entry.capabilities;
    if !(entry.epochs_valid.from <= epoch && epoch <= entry.epochs_valid.to) {
        return Some(Exclusion::Window);
    }
    if entry.tier.rank() < tier_floor.rank() {
        return Some(Exclusion::TierFloor);
    }
    if exclusions.contains(&entry.key_id) || exclusions.contains(&entry.identity) {
        return Some(Exclusion::Excluded);
    }
    if !caps.arch.iter().any(|a| a == &requirements.arch) {
        return Some(Exclusion::Arch);
    }
    if caps.ram_mb < requirements.ram_mb {
        return Some(Exclusion::Ram);
    }
    if caps.disk_mb < requirements.disk_mb {
        return Some(Exclusion::Disk);
    }
    if !caps.can_pull
        && requirements
            .image_digests
            .iter()
            .any(|d| !caps.image_cache.iter().any(|c| c == d))
    {
        return Some(Exclusion::Images);
    }
    if !caps
        .sandboxes
        .iter()
        .any(|s| requirements.sandboxes.iter().any(|r| r == s))
    {
        return Some(Exclusion::Sandboxes);
    }
    if caps.sandbox_level < requirements.min_sandbox_level {
        return Some(Exclusion::SandboxLevel);
    }
    None
}

/// A digest string in the tagged form (`sha256:<hex>`); capability fields use it.
fn digest_shape(text: &str) -> Result<()> {
    text.parse::<gitiup_attest::Digest>()
        .map_err(|_| Error::invalid("capabilities", format!("'{text}' is not a tagged digest")))
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tier: RosterTier, level: u8) -> crate::roster::RosterEntry {
        crate::roster::RosterEntry {
            key_id: "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            identity: "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            tier,
            capabilities: Capabilities {
                arch: vec!["x86_64".into()],
                ram_mb: 8192,
                disk_mb: 51200,
                image_cache: vec![],
                can_pull: true,
                sandboxes: vec!["docker".into()],
                sandbox_level: level,
            },
            epochs_valid: crate::roster::EpochWindow {
                from: 0,
                to: crate::roster::EpochWindow::NO_EXPIRY,
            },
            self_signature: None,
        }
    }

    fn requirements() -> Requirements {
        Requirements {
            arch: "x86_64".into(),
            ram_mb: 8192,
            disk_mb: 51200,
            image_digests: vec![],
            sandboxes: vec!["docker".into()],
            min_sandbox_level: 1,
        }
    }

    #[test]
    fn filter_order_decides_the_reason_printed() {
        // An entry that fails both `excluded` and `sandbox_level` must print
        // `excluded`, because D7 puts it first. Two implementations that disagree
        // about this disagree about an audit record.
        let mut e = entry(RosterTier::Endorsed, 0);
        let exclusions: std::collections::BTreeSet<String> =
            [e.identity.clone()].into_iter().collect();
        assert_eq!(
            exclusion_of(&e, 1, &requirements(), &exclusions, RosterTier::Anonymous),
            Some(Exclusion::Excluded)
        );
        // Without the exclusion, the weak sandbox is what got it.
        assert_eq!(
            exclusion_of(
                &e,
                1,
                &requirements(),
                &Default::default(),
                RosterTier::Anonymous
            ),
            Some(Exclusion::SandboxLevel)
        );
        e.capabilities.sandbox_level = 2;
        assert_eq!(
            exclusion_of(
                &e,
                1,
                &requirements(),
                &Default::default(),
                RosterTier::Trusted
            ),
            Some(Exclusion::TierFloor)
        );
        assert_eq!(
            exclusion_of(
                &e,
                1,
                &requirements(),
                &Default::default(),
                RosterTier::Endorsed
            ),
            None
        );
    }

    #[test]
    fn windows_are_inclusive_and_identity_exclusion_covers_a_family() {
        let e = entry(RosterTier::Endorsed, 2);
        let empty = Default::default();
        assert_eq!(
            exclusion_of(&e, 0, &requirements(), &empty, RosterTier::Anonymous),
            None
        );
        let mut e = e;
        e.epochs_valid = crate::roster::EpochWindow { from: 5, to: 9 };
        assert_eq!(
            exclusion_of(&e, 4, &requirements(), &empty, RosterTier::Anonymous),
            Some(Exclusion::Window)
        );
        assert_eq!(
            exclusion_of(&e, 5, &requirements(), &empty, RosterTier::Anonymous),
            None
        );
        assert_eq!(
            exclusion_of(&e, 9, &requirements(), &empty, RosterTier::Anonymous),
            None
        );
        assert_eq!(
            exclusion_of(&e, 10, &requirements(), &empty, RosterTier::Anonymous),
            Some(Exclusion::Window)
        );
        // Naming the principal once excludes every box of theirs.
        let by_identity: std::collections::BTreeSet<String> =
            [e.identity.clone()].into_iter().collect();
        assert_eq!(
            exclusion_of(&e, 7, &requirements(), &by_identity, RosterTier::Anonymous),
            Some(Exclusion::Excluded)
        );
        let by_key: std::collections::BTreeSet<String> = [e.key_id.clone()].into_iter().collect();
        assert_eq!(
            exclusion_of(&e, 7, &requirements(), &by_key, RosterTier::Anonymous),
            Some(Exclusion::Excluded)
        );
    }

    #[test]
    fn tiers_parse_and_rank() {
        assert!(RosterTier::Anonymous < RosterTier::Endorsed);
        assert!(RosterTier::Endorsed < RosterTier::Trusted);
        assert_eq!(RosterTier::parse(" TRUSTED ").unwrap(), RosterTier::Trusted);
        assert!(RosterTier::parse("legendary").is_err());
    }

    #[test]
    fn claims_are_checked_before_filtering() {
        let mut caps = entry(RosterTier::Endorsed, 2).capabilities;
        assert!(caps.validate().is_ok());
        caps.sandboxes = vec![];
        assert!(caps.validate().is_err());
        caps.sandboxes = vec!["docker".into()];
        caps.image_cache = vec![format!("sha256:{}", "ab".repeat(32))];
        assert!(caps.validate().is_ok());
        caps.image_cache = vec!["deadbeef".into()];
        assert!(caps.validate().is_err());
    }
}

//! Deterministic fixture builders for tests, doc examples and the demo.
//!
//! Everything here is a function of its index, so a roster, its keys and its
//! attestations are reproducible in a second process (which is exactly what a quorum
//! test needs: five *independent* runs, no shared memory). The seeds are published, so
//! these keys are not secrets and a policy that trusts them outside a test is a bug —
//! the same rule `gitiup_attest::sample` states for its key.
//!
//! Production code has no reason to call any of this.

use std::collections::BTreeMap;

use gitiup_attest::{
    AttestationDoc, Digest, GitOid, RunManifest, RunReport, SigningKey, Tier, TimeUs,
    run::{ClaimReport, EnvironmentReport, EventReport, RAW_NORMALISATION_VERSION, StepReport},
};

use crate::capability::{Capabilities, Requirements, RosterTier};
use crate::derive::ROUND_KIND;
use crate::roster::{EpochWindow, Roster, RosterEntry};
use crate::round::Round;
use crate::select::{RoundInputs, SELECTION_SCHEMA_VERSION, SelectionPolicy};

/// The fixture clock: a fixed microsecond time, so freshness is a fact of the fixture
/// and not of the machine running the test.
pub const T0: i64 = 1_792_771_200_000_000;

/// The fixture epoch interval (7 days).
pub const EPOCH_INTERVAL_US: i64 = 604_800_000_000;

/// The owner/selector key.
pub fn owner_key() -> SigningKey {
    SigningKey::from_seed(&[1u8; 32])
}

/// A volunteer's machine key, derived from its index.
pub fn verifier_key(index: u8) -> SigningKey {
    SigningKey::from_seed(&[100u8.saturating_add(index); 32])
}

/// A volunteer's principal key (a person, not a box). A family is one of these, so
/// giving two boxes the same principal is how "one identity, one vote" gets tested.
pub fn principal_key(index: u8) -> SigningKey {
    SigningKey::from_seed(&[200u8.saturating_add(index); 32])
}

/// The fixture head oid, as a git sha1 commit.
pub fn head() -> GitOid {
    GitOid::from_sha1_hex(&"e".repeat(40)).expect("40 hex chars")
}

/// A `sha256:` digest of a fixture image.
pub fn image_digest() -> String {
    format!("sha256:{}", Digest::sha256(b"gitiup fixture image").hex())
}

/// A default requirement set the fixture roster can satisfy.
pub fn requirements() -> Requirements {
    Requirements {
        arch: "x86_64".into(),
        ram_mb: 8192,
        disk_mb: 51200,
        image_digests: vec![],
        sandboxes: vec!["docker".into(), "unshare".into()],
        min_sandbox_level: 1,
    }
}

/// An entry for volunteer `index`, self-signed, one principal per box.
///
/// `tier` cycles deterministically (`endorsed`, `endorsed`, `trusted`, `anonymous`) so a
/// fixture roster exercises the caps without anyone writing twelve literals.
pub fn entry(index: u8, epoch: u64, tier: RosterTier) -> RosterEntry {
    entry_with(index, index, epoch, tier)
}

/// An entry whose *principal* is a different index — two boxes, one identity.
pub fn entry_with(box_index: u8, principal_index: u8, epoch: u64, tier: RosterTier) -> RosterEntry {
    let key = verifier_key(box_index);
    let mut entry = RosterEntry {
        key_id: key.public_key().key_id(),
        public_key: key.public_key().to_openssh(),
        identity: principal_key(principal_index).public_key().key_id(),
        tier,
        capabilities: Capabilities {
            arch: vec!["x86_64".into()],
            ram_mb: 32768,
            disk_mb: 262_144,
            image_cache: vec![image_digest()],
            can_pull: true,
            sandboxes: vec!["docker".into(), "unshare".into()],
            sandbox_level: 2,
        },
        epochs_valid: EpochWindow::open_from(epoch.saturating_sub(3)),
        self_signature: None,
    };
    entry.sign(&key).expect("self-signature");
    entry
}

/// The tier a fixture index gets, cycling so caps and floors are exercised.
pub fn tier_at(index: u8) -> RosterTier {
    match index % 4 {
        0 | 1 => RosterTier::Endorsed,
        2 => RosterTier::Trusted,
        _ => RosterTier::Anonymous,
    }
}

/// A signed roster of `count` volunteers, one identity per box.
pub fn roster_of(owner: &SigningKey, count: u8, epoch: u64) -> Roster {
    let entries: Vec<RosterEntry> = (0..count)
        .map(|index| entry(index, epoch, tier_at(index)))
        .collect();
    roster_of_entries(owner, entries, epoch)
}

/// A signed roster from hand-picked entries.
pub fn roster_of_entries(owner: &SigningKey, entries: Vec<RosterEntry>, epoch: u64) -> Roster {
    let prev = Digest::sha256(format!("roster epoch {}", epoch.saturating_sub(1)).as_bytes());
    let mut roster =
        Roster::new(epoch, prev, T0, EPOCH_INTERVAL_US, entries).expect("fixture roster is valid");
    roster.sign(owner).expect("fixture roster signs");
    roster
}

/// The fixture head, for callers that want it without naming the module.
pub fn head_oid() -> GitOid {
    head()
}

/// Round inputs pinned to `roster`, with the default policy.
pub fn round_inputs(roster: &Roster, change_id: &str, job_id: &str) -> RoundInputs {
    round_inputs_with(roster, change_id, job_id, SelectionPolicy::default())
}

/// Round inputs with a chosen policy.
pub fn round_inputs_with(
    roster: &Roster,
    change_id: &str,
    job_id: &str,
    policy: SelectionPolicy,
) -> RoundInputs {
    RoundInputs {
        schema_version: SELECTION_SCHEMA_VERSION,
        kind: None,
        round_kind: ROUND_KIND.to_string(),
        roster_epoch: roster.epoch,
        roster_digest: roster.digest().expect("fixture roster digests"),
        change_id: change_id.to_string(),
        head_oid: head(),
        job_id: job_id.to_string(),
        attempt: 0,
        required_capabilities: requirements(),
        exclusions: Default::default(),
        policy,
    }
}

/// The unsigned manifest of one volunteer's honest rerun.
///
/// `diverge` replaces the step output, which changes the `ResultDigest` and nothing
/// else: the shape a real disagreement has (a different compiler, a flaky step, a
/// lying verifier) without touching anything the digest ignores.
pub fn manifest_for(round: &Round, index: u8, now_us: i64, diverge: Option<&str>) -> RunManifest {
    let seat = round
        .selected
        .iter()
        .find(|seat| seat.key_id == verifier_key(index).public_key().key_id())
        .expect("fixture: the volunteer holds a seat");
    let log = diverge
        .unwrap_or("test result: ok. 42 passed, 0 failed")
        .to_string();
    let report = RunReport {
        repo: Some("gitiup/example".into()),
        commit: round.inputs.head_oid.clone(),
        workflow: gitiup_attest::run::WorkflowSource::from_text(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n",
        ),
        event: EventReport {
            name: "pull_request".into(),
            action: Some("synchronize".into()),
            payload: gitiup_attest::run::Material::text("{}"),
        },
        job: Some(round.inputs.job_id.clone()),
        matrix: BTreeMap::from([("target".to_string(), "linux-x86_64".to_string())]),
        inputs: BTreeMap::new(),
        secret_names: vec![],
        pins: BTreeMap::new(),
        reusable_workflows: vec![],
        environment: EnvironmentReport {
            provider: Some("docker".into()),
            os: Some("linux".into()),
            arch: round.inputs.required_capabilities.arch.clone(),
            image: Some(gitiup_attest::manifest::ImageRef {
                reference: Some("ghcr.io/example/rust:1.83".to_string()),
                digest: Digest::sha256(b"gitiup fixture image"),
            }),
            toolchain: vec![],
        },
        steps: vec![StepReport {
            stdout: gitiup_attest::run::Material::text(log),
            ..StepReport::run("test", 0)
        }],
        provenance: gitiup_attest::manifest::Provenance {
            tier: Tier::Local,
            runner: "gitiup 0.1.0".into(),
            normalisation_version: RAW_NORMALISATION_VERSION,
            sandbox: Some("docker".into()),
        },
        claims: ClaimReport {
            run_id: format!("{:016x}", 0x5eed0000u64 + index as u64),
            claimed_at_us: now_us,
            not_before_us: None,
            not_after_us: Some(now_us + 3_600_000_000),
            verifier_challenge: Some(crate::derive::challenge(
                round
                    .seed
                    .as_bytes()
                    .try_into()
                    .expect("a seed is 32 bytes"),
                &seat.key_id,
            )),
            timings: vec![],
            normalisation_diffs: vec![],
            annotations: BTreeMap::new(),
        },
    };
    let mut manifest = RunManifest::from_run(&report).expect("fixture manifest");
    manifest.normalize();
    manifest
}

/// The attestations of the volunteers named by `indexes`, each signed by its own key.
///
/// `diverge` is asked once per volunteer (by position in `indexes`) and returns `Some`
/// to make that one disagree.
pub fn attest(
    round: &Round,
    indexes: &[u8],
    now_us: i64,
    diverge: impl Fn(usize) -> Option<String>,
) -> Vec<AttestationDoc> {
    indexes
        .iter()
        .enumerate()
        .map(|(position, &index)| {
            let key = verifier_key(index);
            let manifest = manifest_for(round, index, now_us, diverge(position).as_deref());
            let mut doc = AttestationDoc::new(manifest);
            doc.sign(&key).expect("fixture attestation signs");
            doc
        })
        .collect()
}

/// Which fixture volunteer indices hold a seat in `round`.
///
/// A round selects by score, not by index, so a test that names its verifiers by index
/// has to look them up — and that lookup is a useful assertion in itself.
pub fn indices_of(round: &Round) -> Vec<u8> {
    round
        .selected
        .iter()
        .map(|seat| {
            (0u8..64)
                .find(|index| verifier_key(*index).public_key().key_id() == seat.key_id)
                .expect("fixture: every seat is a fixture volunteer")
        })
        .collect()
}

/// Every fixture volunteer index that holds a seat, plus the first reserve.
pub fn reserve_indices(roster: &Roster, round: &Round) -> Vec<u8> {
    let _ = roster;
    round
        .reserves
        .iter()
        .filter_map(|reserve| {
            (0u8..64).find(|index| verifier_key(*index).public_key().key_id() == reserve.key_id)
        })
        .collect()
}

/// The claimed time a fixture attestation carries (a few minutes after the roster was
/// issued, well inside the freshness window).
pub fn claimed_at_us() -> i64 {
    T0 + 60_000_000
}

/// The clock a fixture verdict should use.
pub fn clock() -> TimeUs {
    TimeUs(claimed_at_us() + 1_000_000)
}

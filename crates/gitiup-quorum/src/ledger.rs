//! The roster anti-rollback ledger
//! ([ADR-0002 D8](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)).
//!
//! A verifier remembers the highest roster epoch it has accepted *per store*, and
//! refuses a lower one for new rounds. The guard never blocks a legitimate move — an
//! owner with a valid key can always sign a higher epoch — so what it costs to enforce
//! is a small local file, and what it prevents is forking: replaying an old, friendlier
//! roster to the one verifier that has already moved on. That is the difference between
//! "the roster is a list" and "the roster is a list the operator can rewrite per
//! audience".
//!
//! The same record makes an epoch-number collision detectable: an epoch reused with
//! different content has a different digest, and the ledger has one digest per epoch.

use std::collections::BTreeMap;
use std::path::Path;

use gitiup_attest::Digest;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::roster::Roster;

/// Schema version of the ledger file.
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

/// What a verifier remembers about a store's rosters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterLedger {
    /// Must be [`LEDGER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Which store this ledger is about. Per-store on purpose: a ledger shared between
    /// two repositories would let one repo's epoch stop another's.
    pub store: String,
    /// The highest epoch ever accepted here.
    pub highest_epoch: u64,
    /// One digest per epoch ever seen, so a reused epoch number is a fork and not a
    /// coincidence.
    pub epochs: BTreeMap<u64, Digest>,
}

impl RosterLedger {
    /// An empty ledger for one store.
    pub fn new(store: impl Into<String>) -> RosterLedger {
        RosterLedger {
            schema_version: LEDGER_SCHEMA_VERSION,
            store: store.into(),
            highest_epoch: 0,
            epochs: BTreeMap::new(),
        }
    }

    /// Check a roster against what has already been accepted, without recording it.
    ///
    /// Two refusals, both about the past being rewritten:
    ///
    /// * an epoch *lower* than the highest accepted — the store is showing an older
    ///   world to this verifier;
    /// * an epoch already seen with a *different* digest — the epoch number was reused,
    ///   which the round's digest pin alone would only make unexplainable.
    pub fn check(&self, roster: &Roster) -> Result<()> {
        if self.schema_version != LEDGER_SCHEMA_VERSION {
            return Err(Error::unsupported(
                "roster ledger",
                format!("ledger schema_version {}", self.schema_version),
            ));
        }
        if roster.epoch < self.highest_epoch {
            return Err(Error::policy(
                "roster ledger",
                format!(
                    "this store has already offered roster epoch {}, and it is now offering \
                     epoch {}: an older roster is not a smaller world, it is a different one",
                    self.highest_epoch, roster.epoch
                ),
            )
            .with_hint(
                "fetch refs/gitiup/roster again; if the store insists, stop and check \
                        the store's identity — this is what a roster fork looks like",
            ));
        }
        if let Some(seen) = self.epochs.get(&roster.epoch) {
            let digest = roster.digest()?;
            if seen != &digest {
                return Err(Error::digest_mismatch(
                    "roster ledger",
                    format!(
                        "roster epoch {} was previously {seen} and is now {digest}: the same \
                         epoch number with different content is a fork, not an update",
                        roster.epoch
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Record a roster that has been accepted.
    pub fn record(&mut self, roster: &Roster) -> Result<()> {
        self.check(roster)?;
        self.epochs.insert(roster.epoch, roster.digest()?);
        self.highest_epoch = self.highest_epoch.max(roster.epoch);
        Ok(())
    }

    /// Read a ledger file. A missing file is an empty ledger: forgetting what you saw
    /// is a weaker guarantee, not a different one, and it is stated here so nobody
    /// mistakes "no file" for "no history".
    pub fn load(path: &Path, store: impl Into<String>) -> Result<RosterLedger> {
        match std::fs::read(path) {
            Ok(bytes) => gitiup_attest::from_canonical_bytes::<RosterLedger>(&bytes)
                .map_err(|e| Error::invalid("roster ledger", e.detail())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(RosterLedger::new(store))
            }
            Err(error) => Err(Error::invalid(
                "roster ledger",
                format!("{}: {error}", path.display()),
            )),
        }
    }

    /// Write the ledger, canonically, so two runs produce the same bytes.
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = gitiup_attest::canon::to_bytes(self)
            .map_err(|e| Error::invalid("roster ledger", e.detail()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::invalid("roster ledger", format!("{}: {e}", parent.display()))
            })?;
        }
        std::fs::write(path, bytes)
            .map_err(|e| Error::invalid("roster ledger", format!("{}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capabilities, RosterTier};
    use crate::roster::{EpochWindow, RosterEntry};
    use gitiup_attest::SigningKey;

    const T0: i64 = 1_792_771_200_000_000;

    fn roster(epoch: u64, seed: u8) -> Roster {
        let owner = SigningKey::from_seed(&[seed; 32]);
        let mut entry = RosterEntry {
            key_id: owner.public_key().key_id(),
            public_key: owner.public_key().to_openssh(),
            identity: owner.public_key().key_id(),
            tier: RosterTier::Endorsed,
            capabilities: Capabilities {
                arch: vec!["x86_64".into()],
                ram_mb: 8192,
                disk_mb: 51200,
                image_cache: vec![],
                can_pull: true,
                sandboxes: vec!["docker".into()],
                sandbox_level: 2,
            },
            epochs_valid: EpochWindow::open_from(1),
            self_signature: None,
        };
        entry.sign(&owner).unwrap();
        let mut roster = Roster::new(epoch, Digest::sha256(b"prev"), T0, 1, vec![entry]).unwrap();
        roster.sign(&owner).unwrap();
        roster
    }

    #[test]
    fn epochs_move_forward_and_a_fork_is_caught() {
        let mut ledger = RosterLedger::new("s3://bucket/repo");
        let first = roster(41, 1);
        ledger.record(&first).unwrap();
        assert_eq!(ledger.highest_epoch, 41);
        // The same epoch again is fine (idempotent), a higher one is fine, a lower one
        // is a refusal.
        ledger.record(&first).unwrap();
        ledger.record(&roster(42, 2)).unwrap();
        let err = ledger.check(&first).unwrap_err();
        assert_eq!(err.exit_code(), 6);
        assert!(err.to_string().contains("older roster"), "{err}");
        // Same epoch number, different content: the round pin would only have made this
        // unexplainable, the ledger makes it detectable.
        let mut fork = roster(42, 3);
        fork.epoch = 42;
        let err = ledger.check(&fork).unwrap_err();
        assert_eq!(err.exit_code(), 8);
    }

    #[test]
    fn a_ledger_round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = RosterLedger::load(&path, "fs").unwrap();
        assert_eq!(ledger.highest_epoch, 0, "a missing file is an empty ledger");
        ledger.record(&roster(7, 4)).unwrap();
        ledger.save(&path).unwrap();
        let again = RosterLedger::load(&path, "fs").unwrap();
        assert_eq!(again, ledger);
        assert!(again.check(&roster(7, 4)).is_ok());
    }
}

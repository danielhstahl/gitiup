//! What a copy is worth, printed where it is read
//! ([ADR-0005 D5](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
//!
//! [Super::copy] decides what a mirror may *carry*; this module decides what a reader is
//! told about the copy it is reading. The split is the whole of D5, and it exists because
//! the tempting place to mark staleness is the artifact:
//!
//! * writing a `stale` field into the record changes its bytes, so its digest, so its
//!   blob name and its ref leaf — and a copy that re-hashes is not a copy (C4, exit 8);
//! * having the mirror sign the mark needs a mirror key, which is the second path to
//!   "this is fine" that D3 refuses (C8).
//!
//! So marking lives in the **reading** — a [`Block`] in a verify report — and in the
//! importing store's own `kv/import/<digest>` ([`super::Arrival`]), which is local by
//! construction and grants nothing.
//!
//! # The one prohibition that makes the rest of it work
//!
//! Age is computed from `claims.claimed_at_us` and from nothing else. A mirror cannot
//! make a proof fresher, because the only input is a signed field it cannot touch; the
//! only way it *could* make one look fresher is a reader that measures from arrival. So
//! no gitiup code path may compute age from `arrived_at_us`, `mtime`, a pack timestamp or
//! a bucket's `Last-Modified` — and rather than make that a cultural rule, [`Block`]
//! carries `age_basis: "claimed_at_us"` as a printed field, so a report that measured
//! some other way is visibly wrong and a test can assert the literal.
//!
//! # What a policy may demand
//!
//! Because a copy can only ever be as old as its claim or older, the residual risk is not
//! a forged proof but a stale one: a gate accepting a proof from a mirror that happens to
//! be the freshest copy this reader can reach while the origin has moved on. A policy may
//! therefore say how much it believes a copy ([`Demand`], published as ADR-0004's
//! optional `provenance` member), and the two refusals are [`super::REFUSALS`]'s
//! `origin_provenance_required` and `unlisted_mirror`. Absent the member — what every
//! policy signed today looks like — a copy gates a merge exactly as an origin does:
//! federation is on by default and demanding provenance is the opt-in.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Host;
use crate::error::HostResult;
use crate::oid::Oid;
use crate::time::Timestamp;

use super::AGE_BASIS;
use super::copy::{Arrival, CLOSURE_COMPLETE, CLOSURE_NOT_WALKED, arrivals};

/// The store that made the claim is the store that served it.
pub const STORE_ORIGIN: &str = "origin";
/// The bytes arrived from somewhere else: this store is a mirror of somebody.
pub const STORE_COPY: &str = "copy";
/// The closure of a document nobody imported: there was no walk, because nothing
/// arrived. Distinct from [`CLOSURE_NOT_WALKED`], which is a copy whose copier admits
/// it did not check.
pub const CLOSURE_NATIVE: &str = "not-imported";

/// Which store a read happened at, in the two words a report may print.
///
/// A store never *declares* this. It is derived from whether this store can name where
/// each digest came from ([`super::has_refetch_source`]), which is the same evidence D8
/// rule 2 uses to decide what a store may prune: a store that can say where it got a
/// thing is a mirror, and one that cannot is an origin — for that digest, at least.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// What the operator typed (`remote 'upstream'`, `fs store ./mirror`).
    pub label: String,
    /// The store's url as configured, or its path. Empty when the read had no store
    /// (a document handed over as a file), which is `origin` by definition: nothing
    /// arrived from anywhere.
    pub url: String,
}

impl Identity {
    /// A store the reader reached.
    pub fn new(label: impl Into<String>, url: impl Into<String>) -> Identity {
        Identity {
            label: label.into(),
            url: url.into(),
        }
    }

    /// Every name this store answers to: its url and its label. A mirror named in a
    /// policy is matched against both, because `mirrors` is a list an owner types and a
    /// reader must be able to spell a store the way it spells it in `gitiup.toml`.
    pub fn names(&self) -> [&str; 2] {
        [self.url.as_str(), self.label.as_str()]
    }
}

/// The `provenance` block of a verify, verify-change or import report (D5 clause 2).
///
/// Field-for-field the ADR's block, plus the two members the arrival record already
/// carries (`verified_by`, `verify_exit`) because a reader asking "how did this get
/// here" also wants "who checked it, and what did the check say". They are an audit
/// note about a machine and never an input to a verdict: a reader believes what it
/// re-checks, not what its neighbour reports having believed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// `origin` | `copy`.
    pub store: String,
    /// Where the bytes were read from, this run.
    pub store_url: String,
    /// The clock this reading used — the one `age_us` was measured against.
    pub read_at_us: i64,
    /// The store the copy came from, `None` when `store` is `origin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrived_from: Option<String>,
    /// When they arrived. **Metadata only**: eviction and human audit, never a verdict
    /// input (clause 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrived_at_us: Option<i64>,
    /// Was this digest read from the origin itself? True when this store made the claim
    /// rather than copying it.
    pub origin_seen: bool,
    /// `read_at_us - claimed_at_us`: the age, from the signed claim alone.
    pub age_us: i64,
    /// Always [`AGE_BASIS`]. Printed, not implied: clause 1's rule as an assertion.
    pub age_basis: String,
    /// `"complete"`, `"not-walked"`, `"not-imported"`, or the list of missing edges.
    pub closure: Value,
    /// Who checked this copy here (`gitiup attest import` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
    /// The verdict that check produced, as an exit code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_exit: Option<u8>,
}

impl Block {
    /// The block for reading `digest` at `store`, aged from `claimed_at_us`.
    ///
    /// `None` arrival means this store made it: `origin`, and `origin_seen`.
    pub fn read(
        host: &dyn Host,
        store: &Identity,
        digest: &Oid,
        claimed_at_us: i64,
        read_at_us: i64,
    ) -> HostResult<Block> {
        Ok(match arrival_for(host, digest)?.as_ref() {
            None => Block {
                store: STORE_ORIGIN.to_string(),
                store_url: store.url.clone(),
                read_at_us,
                arrived_from: None,
                arrived_at_us: None,
                origin_seen: true,
                age_us: age(read_at_us, claimed_at_us),
                age_basis: AGE_BASIS.to_string(),
                closure: Value::String(CLOSURE_NATIVE.to_string()),
                verified_by: None,
                verify_exit: None,
            },
            Some(arrival) => Block {
                store: STORE_COPY.to_string(),
                store_url: store.url.clone(),
                read_at_us,
                arrived_from: Some(arrival.arrived_from.clone()),
                arrived_at_us: Some(arrival.arrived_at_us),
                origin_seen: false,
                // Clause 1, in one line: the arrival stamp is printed below and is not
                // used here at all.
                age_us: age(read_at_us, claimed_at_us),
                age_basis: AGE_BASIS.to_string(),
                closure: closure_of(arrival),
                verified_by: arrival.verified_by.clone(),
                verify_exit: arrival.verify_exit,
            },
        })
    }

    /// Whether these bytes arrived from another store.
    pub fn is_copy(&self) -> bool {
        self.store == STORE_COPY
    }

    /// The block as JSON, for a report that has a map to put it in.
    pub fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// One line for a human report: what a reader needs first when the bytes are a copy.
    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("store {}", self.store),
            format!("age {} ({} basis)", human_age(self.age_us), self.age_basis),
        ];
        if let Some(from) = &self.arrived_from {
            parts.push(format!("arrived from {from}"));
        }
        match &self.closure {
            Value::String(closure) => parts.push(format!("closure {closure}")),
            Value::Array(edges) => parts.push(format!(
                "closure missing {}",
                edges
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ => {}
        }
        if let Some(verifier) = &self.verified_by {
            parts.push(format!(
                "checked here by {verifier}{}",
                self.verify_exit
                    .map(|code| format!(" (exit {code})"))
                    .unwrap_or_default()
            ));
        }
        parts.join(" · ")
    }
}

/// The age a copy is, in microseconds, from the signed claim alone.
///
/// A claim made in the future (inside the policy's skew allowance) ages as zero rather
/// than as a negative number: a negative age is not "fresher than now", it is a clock
/// problem, and the freshness check is the place that says so.
fn age(read_at_us: i64, claimed_at_us: i64) -> i64 {
    (read_at_us - claimed_at_us).max(0)
}

/// The closure an arrival record states, as JSON: the words a walk produced, or the
/// edges it named. A hand-made record whose `closure` is a list is reported as the list
/// it holds rather than laundered into `"complete"`.
fn closure_of(arrival: &Arrival) -> Value {
    match arrival.closure.as_str() {
        CLOSURE_COMPLETE => Value::String(CLOSURE_COMPLETE.to_string()),
        CLOSURE_NOT_WALKED => Value::String(CLOSURE_NOT_WALKED.to_string()),
        other => {
            if other.split(',').any(|edge| !edge.trim().is_empty()) {
                Value::Array(
                    other
                        .split(',')
                        .map(str::trim)
                        .filter(|edge| !edge.is_empty())
                        .map(|edge| Value::String(edge.to_string()))
                        .collect(),
                )
            } else {
                Value::String(other.to_string())
            }
        }
    }
}

/// The arrival record naming `digest`, if this store has one.
///
/// Read from `kv/import/**` every time, never cached: the record is small, the answer
/// must be this run's, and a cache of "where did this come from" is one more place a
/// store could believe something it did not re-read.
pub fn arrival_for(host: &dyn Host, digest: &Oid) -> HostResult<Option<Arrival>> {
    let mut records = arrivals(host)?;
    Ok(records.remove(&digest.hex()))
}

/// What a policy demands about where a proof came from (D5 clause 3).
///
/// The `mirrors` list is **not** a trust list and **not** an access-control list: naming
/// a mirror says only that the owner believes that store serves copies as fresh as its
/// own, which is the whole of what a mirror can offer. Keys and policy decide whether a
/// proof is believed; nothing here is a secret, and a store not listed may still fetch
/// and still serve.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Demand {
    /// A proof may only gate a merge if it was read from the origin itself.
    pub require_origin_seen: bool,
    /// Stores the owner names as equally fresh. `None` — the default, and every policy
    /// signed before this member existed — says nothing about mirrors at all.
    pub mirrors: Option<Vec<String>>,
}

impl Demand {
    /// Whether this demand would refuse anything.
    pub fn is_empty(&self) -> bool {
        !self.require_origin_seen && self.mirrors.is_none()
    }

    /// Tighten this demand with another one, and only ever tighten.
    ///
    /// Local config may demand provenance the owner did not; it may never waive a demand
    /// the owner made (ADR-0004 D4's precedence argument, re-used: the signed document is
    /// a floor, not a ceiling). So `require_origin_seen` is an `||`, and a `mirrors` list
    /// on either side becomes the union — a list from the reader can never remove an
    /// entry the owner signed.
    ///
    /// No command sets a local demand yet, so today the signed document is the only
    /// [`Demand`] in use; this is the shape the rule takes when one does, and the test
    /// below is why it is here rather than a sentence in a comment.
    pub fn tighten_with(&mut self, other: &Demand) {
        self.require_origin_seen |= other.require_origin_seen;
        match (&mut self.mirrors, &other.mirrors) {
            (None, Some(list)) => self.mirrors = Some(list.clone()),
            (Some(mine), Some(theirs)) => {
                for entry in theirs {
                    if !mine.iter().any(|have| equal(have, entry)) {
                        mine.push(entry.clone());
                    }
                }
            }
            (Some(_), None) | (None, None) => {}
        }
    }

    /// Judge a reading against the demand: `None` means the demand is satisfied.
    ///
    /// `names` adds whatever else the serving store answers to (an operator's label, a
    /// remote's name) beyond `store_url`; a `mirrors` entry is matched against all of
    /// them, case-insensitively, because the owner is typing a store's name from memory.
    pub fn refusal(&self, block: &Block, names: &[&str]) -> Option<Refusal> {
        if !self.is_empty() && !block.is_copy() && block.origin_seen {
            // Read at the origin: every demand this member can express is satisfied.
            return None;
        }
        if self.require_origin_seen && !block.origin_seen {
            return Some(Refusal {
                token: "origin_provenance_required",
                detail: format!(
                    "the policy requires a proof to have been read from the origin store, and \
                     this one arrived from {} and is {} old (measured from claimed_at_us)",
                    block.arrived_from.as_deref().unwrap_or("an unnamed store"),
                    human_age(block.age_us)
                ),
                hint:
                    "read the proof where it was made: point at the origin with --store/--remote \
                       (or `gitiup fetch` the proofs from the origin and re-verify them there) — \
                       a mirror keeps a copy available, it cannot make one fresher, which is why \
                       a policy that must not act on a stale proof says so"
                        .to_string(),
            });
        }
        if let Some(mirrors) = &self.mirrors {
            let mut candidates: Vec<&str> = vec![block.store_url.as_str()];
            candidates.extend(names.iter().copied());
            if let Some(from) = &block.arrived_from {
                candidates.push(from.as_str());
            }
            let named = mirrors.iter().any(|entry| {
                candidates
                    .iter()
                    .any(|candidate| !candidate.is_empty() && equal(entry, candidate))
            });
            if !named {
                return Some(Refusal {
                    token: "unlisted_mirror",
                    detail: format!(
                        "the policy names {} as the stores it considers as fresh as itself, and \
                         this copy came from '{}' ({})",
                        mirror_list(mirrors),
                        block
                            .arrived_from
                            .as_deref()
                            .or(Some(block.store_url.as_str()))
                            .unwrap_or("an unnamed store"),
                        block.store
                    ),
                    hint: "either read the proof from a store the owner named, or ask the owner \
                           to add this one to the policy's `provenance.mirrors` — naming a mirror \
                           there says it is kept as fresh, it says nothing about whom to trust"
                        .to_string(),
                });
            }
        }
        None
    }
}

/// A reading a policy's provenance demand refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The token: `origin_provenance_required` or `unlisted_mirror`.
    pub token: &'static str,
    /// What was refused, in the report's own sentence.
    pub detail: String,
    /// What to do about it.
    pub hint: String,
}

/// Two store names are the same store when they differ only in case and spacing.
fn equal(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Whether a store may prune proofs by age or count ([ADR-0005 D8 rule 2](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneAuthority {
    /// It holds write authority over the namespace, and at least one of these proofs
    /// arrived here by being *made* here rather than by being copied.
    Own,
    /// It cannot write the namespace it is being asked to prune (`--max-age` against a
    /// read-only store, or a forge that answers anonymously and denies every write).
    ReadOnly(String),
    /// Every candidate arrived by copy: this store is a mirror of somebody else's
    /// claims, and "proofs older than this no longer matter" is not its sentence to
    /// say. It may still evict for capacity, among what it can fetch back.
    Mirror {
        /// How many candidates arrived by copy.
        copies: usize,
        /// How many there are in all.
        total: usize,
    },
}

/// Decide [`PruneAuthority`] for a set of digests, from the store's own evidence.
///
/// There is no `mirror` flag anywhere, and there never will be: what a store *is* is
/// derived from what it can show. Here that is `kv/import/**` — a store that can name
/// where every one of these proofs came from is a mirror of them, and one that cannot
/// may not prune like one.
pub fn prune_authority(host: &dyn Host, candidates: &[Oid]) -> HostResult<PruneAuthority> {
    if let Err(why) = host.require(crate::capability::Capability::Cas) {
        return Ok(PruneAuthority::ReadOnly(why.to_string()));
    }
    let records = arrivals(host)?;
    let total = candidates.len();
    let copies = candidates
        .iter()
        .filter(|digest| records.contains_key(&digest.hex()))
        .count();
    Ok(if total > 0 && copies == total {
        PruneAuthority::Mirror { copies, total }
    } else {
        PruneAuthority::Own
    })
}

/// A named list, in the report's voice: `a, b and c`.
fn mirror_list(mirrors: &[String]) -> String {
    match mirrors {
        [] => "no mirrors at all".to_string(),
        [one] => one.clone(),
        many => format!(
            "{} and {}",
            many[..many.len() - 1].join(", "),
            many[many.len() - 1]
        ),
    }
}

/// A day/week/hour rendering of a microsecond duration, for a provenance line.
pub fn human_age(micros: i64) -> String {
    crate::attest::human_age(micros)
}

/// The clock a reading should use: this machine's, right now.
///
/// There is exactly one call site per command, and the value goes into every [`Block`]
/// that command prints, so a report cannot hold two proofs aged against two clocks.
pub fn now_us() -> i64 {
    crate::attest::MICROS * Timestamp::now().as_unix() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(store: &str, from: Option<&str>) -> Block {
        Block {
            store: store.to_string(),
            store_url: "s3://gitiup-project/repo".to_string(),
            read_at_us: 1_793_347_200_000_000,
            arrived_from: from.map(str::to_string),
            arrived_at_us: Some(1_793_343_600_000_000),
            origin_seen: store == STORE_ORIGIN,
            age_us: 7_200 * 1_000_000,
            age_basis: AGE_BASIS.to_string(),
            closure: Value::String(CLOSURE_COMPLETE.to_string()),
            verified_by: None,
            verify_exit: None,
        }
    }

    #[test]
    fn an_origin_reading_satisfies_every_demand_there_is() {
        let origin = block(STORE_ORIGIN, None);
        let demand = Demand {
            require_origin_seen: true,
            mirrors: Some(vec![]),
        };
        assert_eq!(demand.refusal(&origin, &[]), None);
    }

    #[test]
    fn no_demand_refuses_nothing() {
        let copy = block(STORE_COPY, Some("https://mirror.example.org/repo.git"));
        assert_eq!(Demand::default().refusal(&copy, &[]), None);
        assert!(
            Demand::default().is_empty(),
            "an absent member demands nothing"
        );
    }

    #[test]
    fn a_copy_is_refused_when_the_policy_will_only_gate_on_an_origin_proof() {
        let copy = block(STORE_COPY, Some("https://mirror.example.org/repo.git"));
        let refusal = Demand {
            require_origin_seen: true,
            mirrors: None,
        }
        .refusal(&copy, &[])
        .expect("a copy may not gate a merge under this demand");
        assert_eq!(refusal.token, "origin_provenance_required");
        assert!(
            refusal.detail.contains("mirror.example.org"),
            "{}",
            refusal.detail
        );
    }

    #[test]
    fn a_mirror_the_owner_named_satisfies_the_mirrors_demand() {
        let mut copy = block(STORE_COPY, Some("https://mirror.example.org/repo.git"));
        copy.store_url = "https://mirror.example.org/repo.git".to_string();
        let demand = Demand {
            require_origin_seen: false,
            mirrors: Some(vec!["https://MIRROR.example.org/repo.git".to_string()]),
        };
        assert_eq!(demand.refusal(&copy, &[]), None);
    }

    #[test]
    fn a_mirror_the_owner_did_not_name_is_refused_by_name() {
        let copy = block(STORE_COPY, Some("https://stranger.example.org/repo.git"));
        let demand = Demand {
            require_origin_seen: false,
            mirrors: Some(vec![
                "https://mirror.example.org/repo.git".to_string(),
                "s3://elsewhere/repo".to_string(),
            ]),
        };
        let refusal = demand.refusal(&copy, &[]).expect("not named, not accepted");
        assert_eq!(refusal.token, "unlisted_mirror");
        assert!(refusal.detail.contains("stranger.example.org"));
    }

    /// The rule a future `--require-origin-provenance` on `verify` will have to obey, and
    /// the reason it is code and not a paragraph: an operator may demand more than the
    /// owner signed, and may never waive what the owner demanded.
    #[test]
    fn a_store_may_tighten_a_demand_and_may_never_loosen_one() {
        let signed = Demand {
            require_origin_seen: true,
            mirrors: Some(vec!["https://mirror.example.org/repo.git".to_string()]),
        };
        let local = Demand {
            require_origin_seen: false,
            mirrors: Some(vec!["s3://local/trust-me".to_string()]),
        };
        let mut together = signed.clone();
        together.tighten_with(&local);
        assert!(
            together.require_origin_seen,
            "the reader cannot waive what the owner signed"
        );
        assert_eq!(
            together.mirrors.as_ref().map(Vec::len),
            Some(2),
            "the reader can add a mirror, not remove one: {:?}",
            together.mirrors
        );
    }

    #[test]
    fn age_is_the_claim_not_the_arrival() {
        // The arrival stamp is three hours before the read; the claim is two hours
        // before it. Age is the claim's distance from now, which is the only basis a
        // mirror cannot inflate (clause 1).
        assert_eq!(age(100, 40), 60);
        assert_eq!(
            age(40, 100),
            0,
            "a future claim ages as zero, not as a negative"
        );
    }
}

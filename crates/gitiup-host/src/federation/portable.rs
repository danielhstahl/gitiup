//! Which refs and records a copy may carry, and which it must refuse (ADR-0005 D1, D2).
//!
//! This is [ADR-0005's D1 table](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! as code, and the same table as data in
//! [`docs/adr/fixtures/federation-v1/portable.json`](../../../../docs/adr/fixtures/federation-v1/portable.json).
//! Two tickets have to agree about it — `gitiup fetch|push` (this module) and
//! `gitiup attest import` — and a Rust table plus a generated JSON table plus a test that
//! compares them is the only way that agreement survives a third ticket. The ADR's own
//! `generate.py --check-ad` checks the prose against the JSON; `tests/federation_vectors.rs`
//! checks the JSON against this table; so prose, data and code are one fact with three
//! spellings.
//!
//! The rule behind the rows is not "these namespaces are allowed": it is
//! **a record is portable when a reader needs it in order to re-verify something this
//! store serves, and is not portable otherwise**. Everything that fails that test is
//! either *arbitration state* or a statement about *now*, and a copy of a statement about
//! now is a lie the moment it is made:
//!
//! ```text
//! portable   refs/attestations/<subject>/<digest>   the proof
//!            refs/changes/<id>/attempt/<n>          an attempt, immutable
//!            refs/gitiup/roster/<epoch>             a signed epoch, immutable
//!            refs/gitiup/{round,verdict,reveal,commit,…}  the evidence a proof leans on
//! refused    refs/changes/<id>/head                 which attempt is current *now*
//!            refs/gitiup/roster, policy/current     which epoch/rules are live *now*
//!            refs/gitiup/lease/**, job/**, signup/**  someone holds this for 15 minutes
//!            refs/gitiup/kv/**, kv/import/**, kv/gc/**  this store's own history
//!            trust roots, keystore, gitiup.toml     who *I* believe; never a payload
//! ```
//!
//! Every refusal is *named*, because "we did not copy that" has to be a report and never
//! a silence ([`Decision::token`]).

use serde::{Deserialize, Serialize};

use crate::blob::Namespace;
use crate::refs::RefName;

/// Which of D1/D2's categories a ref or record falls in.
///
/// The names are the fixture's, so a report and `portable.json` use one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// A signed record: the unit of copying is the record **plus** the ref that
    /// advertises it, never one without the other.
    Proof,
    /// A store's live pointer (`head`, `roster`, `policy/current`). A reader may
    /// *resolve* one; it may never copy one.
    Pointer,
    /// Arbitration state whose whole meaning is *"as of now"*: leases, job
    /// advertisements, sign-ups awaiting a human.
    State,
    /// This store's own audit trail or furniture: its kv commit chain, its import
    /// and gc records, its ref cache, its trust roots.
    Local,
    /// git's own business (`refs/heads/**`), out of this ADR's scope: code travels
    /// by git, and a merge is a fast-forward only the base's owner can perform.
    Foreign,
}

impl Class {
    /// The fixture's spelling of this class.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Proof => "proof",
            Class::Pointer => "pointer",
            Class::State => "state",
            Class::Local => "local",
            Class::Foreign => "foreign",
        }
    }
}

/// One row of the portability table.
///
/// `display` is the first cell of the ADR's D1 table **verbatim**, which is what lets
/// the vector test match a row against `portable.json` without a second key that could
/// drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// The ADR's row label, verbatim.
    pub display: &'static str,
    /// The class the row belongs to.
    pub class: Class,
    /// The record kind, using `portable.json`'s kind names; `None` for rows that are
    /// not records (pointers, furniture, git's branches).
    pub kind: Option<&'static str>,
    /// Whether a copy may carry it.
    pub portable: bool,
    /// The token that names the refusal, when it is refused.
    pub token: Option<&'static str>,
    /// Why, in the ADR's own short form.
    pub note: &'static str,
}

/// D1 and D2 as data. Rows are in the ADR's order.
pub const TABLE: &[Row] = &[
    Row {
        display: "`refs/attestations/<subject>/<digest>` → `kv/attestation/<hex>`",
        class: Class::Proof,
        kind: Some("attestation"),
        portable: true,
        token: None,
        note: "the proof itself; its subject must be reachable or excused",
    },
    Row {
        display: "`refs/changes/<id>/attempt/<n>` → `kv/change/<hex>`",
        class: Class::Proof,
        kind: Some("change"),
        portable: true,
        token: None,
        note: "immutable, create-only, and `chg-…` re-derives identically anywhere",
    },
    Row {
        display: "`refs/changes/<id>/head`",
        class: Class::Pointer,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "the current attempt is an as-of-now fact; resolve it, do not copy it",
    },
    Row {
        display: "`refs/changes/<id>/{merged,abandoned}` → `kv/merge\\|abandon/<hex>`",
        class: Class::Proof,
        kind: Some("merge"),
        portable: true,
        token: None,
        note: "a state that is a signed record plus one create-only ref",
    },
    Row {
        display: "`refs/heads/**`",
        class: Class::Foreign,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "code travels by git; a merge is the base owner's CAS and cannot happen at a mirror",
    },
    Row {
        display: "`refs/gitiup/roster/<epoch:08x>`",
        class: Class::Proof,
        kind: Some("roster"),
        portable: true,
        token: None,
        note: "immutable epoch; a round is auditable only against the epoch it pinned",
    },
    Row {
        display: "`refs/gitiup/roster` (no epoch)",
        class: Class::Pointer,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "which epoch is live now is live state; the anti-rollback guard is a live-store rule",
    },
    Row {
        display: "`refs/gitiup/signup/<slot>`",
        class: Class::State,
        kind: Some("signup"),
        portable: false,
        token: Some("not_portable"),
        note: "a request awaiting a human; anyone approved is already inside an epoch",
    },
    Row {
        display: "`refs/gitiup/withdrawal/<slot>`, `refs/gitiup/revocation/<slot>`",
        class: Class::Proof,
        kind: Some("revocation"),
        portable: true,
        token: None,
        note: "must travel with the epoch they affect, or the mirror serves an uncompromised-looking roster",
    },
    Row {
        display: "`refs/gitiup/round/<change>/<job>/<attempt>`",
        class: Class::Proof,
        kind: Some("round"),
        portable: true,
        token: None,
        note: "evidence only: the record travels, the arbitration does not",
    },
    Row {
        display: "`refs/gitiup/job/<change>/<job>`",
        class: Class::State,
        kind: Some("advertisement"),
        portable: false,
        token: Some("not_portable"),
        note: "an invitation to arbitrate at a store that cannot seat anyone",
    },
    Row {
        display: "`refs/gitiup/lease/<change>/<job>/<slot>`",
        class: Class::State,
        kind: Some("lease"),
        portable: false,
        token: Some("not_portable"),
        note: "the purest as-of-now record in the system; there is no honest copy of it",
    },
    Row {
        display: "`refs/gitiup/commit/…`, `refs/gitiup/reveal/…`",
        class: Class::Proof,
        kind: Some("reveal"),
        portable: true,
        token: None,
        note: "a reveal without its commitment is worth nothing, so both travel or neither",
    },
    Row {
        display: "`refs/gitiup/verdict/<change>/<job>`",
        class: Class::Proof,
        kind: Some("verdict"),
        portable: true,
        token: None,
        note: "with the round, epoch, reveals, commitments and policy it cites",
    },
    Row {
        display: "`refs/gitiup/policy/history/<rev>`",
        class: Class::Proof,
        kind: Some("policy"),
        portable: true,
        token: None,
        note: "the chain walk answers which rules were in force, from bytes in hand",
    },
    Row {
        display: "`refs/gitiup/policy/current`",
        class: Class::Pointer,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "which rules are live now; D6 of ADR-0004 already refuses to guess a history",
    },
    Row {
        display: "`refs/gitiup/kv/**` (the chain commits)",
        class: Class::Local,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "one store's private topology; the mirror appends the records to its own chain",
    },
    Row {
        display: "`kv/import/<digest>`, `kv/gc/<digest>`",
        class: Class::Local,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "how *this* store got and dropped what it has; evidence to a human, never an instruction",
    },
    Row {
        display: "ref caches, tombstones, pack layout, `host.json`, trust roots, `gitiup.toml`",
        class: Class::Local,
        kind: None,
        portable: false,
        token: Some("not_portable"),
        note: "transport furniture and local authority; a trust root that arrives over a wire is an attack",
    },
];

/// What the classifier decided about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The row that answered.
    pub row: &'static Row,
    /// Whether this thing may travel.
    pub portable: bool,
    /// The token that names the refusal (`None` when it may travel).
    pub token: Option<&'static str>,
    /// A legacy single-level attestation ref: read, and re-spelled on arrival, never
    /// re-created in the old shape (D7).
    pub respell: bool,
    /// True when the ref addresses one specific round, so a refusal is about
    /// arbitration and not about scope (D6: `no_arbitration_here` rather than
    /// `not_portable`).
    pub round_specific: bool,
}

impl Decision {
    fn of(row: &'static Row) -> Decision {
        Decision {
            row,
            portable: row.portable,
            token: row.token,
            respell: false,
            round_specific: false,
        }
    }

    /// The class the row gave.
    pub fn class(&self) -> Class {
        self.row.class
    }

    /// The record kind, for a report and for choosing the destination namespace.
    pub fn kind(&self) -> Option<&'static str> {
        self.row.kind
    }

    /// The token to report: the row's, upgraded to `no_arbitration_here` when the ref
    /// was addressed at a specific round (D6's table: "a lease, a sign-up, a job
    /// advertisement: `not_portable`, and `no_arbitration_here` if addressed at a
    /// specific round").
    pub fn refusal(&self) -> Option<&'static str> {
        match (self.token, self.round_specific) {
            (Some(_), true) => Some("no_arbitration_here"),
            (token, _) => token,
        }
    }

    /// The row index in [`TABLE`], for a report that wants a stable id.
    pub fn row_index(&self) -> usize {
        TABLE
            .iter()
            .position(|r| std::ptr::eq(r, self.row))
            .unwrap_or(usize::MAX)
    }
}

/// Find a row by its ADR label.
pub fn row(display: &str) -> Option<&'static Row> {
    TABLE.iter().find(|row| row.display == display)
}

fn rows_of(class: Class, kind: Option<&str>, note: &str) -> &'static Row {
    // Every literal below is one of TABLE's displays, so this is a lookup with a
    // panic-free contract only the table itself can break; a wrong literal is a
    // programming error, and the vector test covers all of them.
    TABLE
        .iter()
        .find(|row| row.class == class && row.kind == kind && row.note == note)
        .expect("every classify() row lookup names a TABLE row")
}

/// Decide what a copy may do with the ref `name`.
///
/// Total: every name gets an answer, including names this build does not recognise —
/// an unrecognised name is `Local` and refused, because the portable set is a list of
/// what was *decided* and an invention is not in it. A store that holds a ref this
/// cannot name is not broken; the copy just says so and moves on.
pub fn classify(name: &RefName) -> Decision {
    let parts: Vec<&str> = name.segments().collect();
    let Some(first) = parts.first().copied() else {
        return Decision::of(furniture());
    };
    if first != "refs" {
        // `HEAD`, a remote's ref, a path: not a namespace gitiup files records in.
        return Decision::of(furniture());
    }
    match parts.get(1).copied().unwrap_or("") {
        "attestations" => classify_attestation(&parts),
        "changes" => classify_change(&parts),
        "gitiup" => classify_gitiup(&parts),
        "heads" | "tags" => Decision::of(rows_of(
            Class::Foreign,
            None,
            "code travels by git; a merge is the base owner's CAS and cannot happen at a mirror",
        )),
        _ => Decision::of(furniture()),
    }
}

/// `refs/attestations/**`: `<subject>/<digest>` is the layout, `<subject>` alone is
/// the legacy spelling that is read and re-spelled, and anything deeper is not ours.
fn classify_attestation(parts: &[&str]) -> Decision {
    let row = rows_of(
        Class::Proof,
        Some("attestation"),
        "the proof itself; its subject must be reachable or excused",
    );
    match parts.len() {
        3 => {
            // `refs/attestations/<subject>`: portable, and re-spelled on arrival (D7).
            let mut decision = Decision::of(row);
            decision.respell = true;
            decision
        }
        4 => Decision::of(row),
        _ => Decision::of(furniture()),
    }
}

/// `refs/changes/**`, using the same parse [`crate::change`] publishes with.
fn classify_change(parts: &[&str]) -> Decision {
    if parts.len() < 4 {
        return Decision::of(furniture());
    }
    let leaf = parts[3..].join("/");
    let row = if leaf == "head" {
        rows_of(
            Class::Pointer,
            None,
            "the current attempt is an as-of-now fact; resolve it, do not copy it",
        )
    } else if leaf == "merged" || leaf == "abandoned" {
        rows_of(
            Class::Proof,
            Some("merge"),
            "a state that is a signed record plus one create-only ref",
        )
    } else if leaf.starts_with("attempt/") && leaf["attempt/".len()..].parse::<u32>().is_ok() {
        rows_of(
            Class::Proof,
            Some("change"),
            "immutable, create-only, and `chg-…` re-derives identically anywhere",
        )
    } else {
        // A leaf ADR-0003 does not define is somebody else's data under our prefix.
        return Decision::of(furniture());
    };
    Decision::of(row)
}

/// `refs/gitiup/**`: rosters, rounds, verdicts, evidence — and the three kinds of
/// thing that must never leave the store that made them.
fn classify_gitiup(parts: &[&str]) -> Decision {
    // (row lookup, extra flags) per third segment.
    let Some(third) = parts.get(2).copied() else {
        // `refs/gitiup` on its own holds nothing.
        return Decision::of(furniture());
    };
    let proof =
        |kind: &'static str, note: &str| Decision::of(rows_of(Class::Proof, Some(kind), note));
    match third {
        "roster" => {
            if parts.len() == 3 {
                Decision::of(rows_of(
                    Class::Pointer,
                    None,
                    "which epoch is live now is live state; the anti-rollback guard is a live-store rule",
                ))
            } else {
                proof(
                    "roster",
                    "immutable epoch; a round is auditable only against the epoch it pinned",
                )
            }
        }
        "signup" => state(
            "signup",
            "a request awaiting a human; anyone approved is already inside an epoch",
        ),
        "withdrawal" | "revocation" => proof(
            "revocation",
            "must travel with the epoch they affect, or the mirror serves an uncompromised-looking roster",
        ),
        "round" => {
            let mut decision = proof(
                "round",
                "evidence only: the record travels, the arbitration does not",
            );
            decision.round_specific = parts.len() >= 5;
            decision
        }
        "job" => {
            let mut decision = state(
                "advertisement",
                "an invitation to arbitrate at a store that cannot seat anyone",
            );
            decision.round_specific = parts.len() >= 5;
            decision
        }
        "lease" => {
            let mut decision = state(
                "lease",
                "the purest as-of-now record in the system; there is no honest copy of it",
            );
            decision.round_specific = parts.len() >= 6;
            decision
        }
        "commit" | "reveal" => {
            let mut decision = proof(
                "reveal",
                "a reveal without its commitment is worth nothing, so both travel or neither",
            );
            decision.round_specific = parts.len() >= 6;
            decision
        }
        "verdict" => {
            let mut decision = proof(
                "verdict",
                "with the round, epoch, reveals, commitments and policy it cites",
            );
            decision.round_specific = parts.len() >= 5;
            decision
        }
        "policy" => match parts.get(3).copied().unwrap_or("") {
            "current" => Decision::of(rows_of(
                Class::Pointer,
                None,
                "which rules are live now; D6 of ADR-0004 already refuses to guess a history",
            )),
            "history" if parts.len() >= 5 => proof(
                "policy",
                "the chain walk answers which rules were in force, from bytes in hand",
            ),
            _ => Decision::of(furniture()),
        },
        // The per-store commit chain: one store's private topology (D7).
        "kv" => Decision::of(rows_of(
            Class::Local,
            None,
            "one store's private topology; the mirror appends the records to its own chain",
        )),
        // Anything else under `refs/gitiup` — an endorsement, a job queue a newer
        // build invented — is this store's own business until a D1 row says otherwise.
        _ => Decision::of(rows_of(
            Class::Local,
            None,
            "how *this* store got and dropped what it has; evidence to a human, never an instruction",
        )),
    }
}

fn state(kind: &'static str, note: &str) -> Decision {
    Decision::of(rows_of(Class::State, Some(kind), note))
}

fn furniture() -> &'static Row {
    rows_of(
        Class::Local,
        None,
        "transport furniture and local authority; a trust root that arrives over a wire is an attack",
    )
}

/// Whether a content-addressed record *named by namespace* may ever travel.
///
/// Records never travel on their own — the unit is record plus advertisement (D1) — so
/// the only namespaces this has to answer for are the two that are local by
/// construction: this store's arrival records and its gc records. Anything else is
/// filed at whichever namespace its advertisement names.
pub fn namespace_travels(namespace: &Namespace) -> bool {
    namespace != &IMPORT && namespace != &GC
}

/// The namespace an arrival record is filed under (`gitiup-import-1`, ADR-0005 D5).
pub const IMPORT: Namespace = Namespace::const_new("import");
/// The namespace a retention run's record is filed under (the same one `attest::gc`
/// uses; named here so the refusal above has one spelling).
pub const GC: Namespace = crate::attest::GC_NAMESPACE;

/// Decide about a thing that is neither a ref nor a CAS record: `host.json`,
/// `gitiup.toml`, a ref cache, a pack index, a keystore.
///
/// They are refused rather than ignored, so that a `--include`-style flag added in some
/// future ticket has one function to ask and one token to print.
pub fn classify_local(what: &str) -> Decision {
    let _ = what;
    Decision::of(furniture())
}

/// The budgets a copy runs under (D10).
///
/// A budget is a *refusal*, never a truncation: an import that hit one says which one
/// it hit, and a caller can tell "stopped" apart from "found nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budgets {
    /// Records per run.
    pub records: usize,
    /// Closure hops (used by `gitiup attest import`; carried here so one table serves
    /// both verbs).
    pub depth: usize,
    /// `previous_digest` revisions walked.
    pub policy_chain: usize,
    /// New bytes per run.
    pub bytes: u64,
}

impl Default for Budgets {
    fn default() -> Budgets {
        Budgets {
            records: 4096,
            depth: 8,
            policy_chain: 64,
            bytes: 1024 * 1024 * 1024,
        }
    }
}

impl Budgets {
    /// The ADR's defaults, spelled as a constructor so a caller never writes the
    /// literals.
    pub fn standard() -> Budgets {
        Budgets::default()
    }

    /// The one-line description a report prints.
    pub fn describe(&self) -> String {
        format!(
            "{} records · {} hops · {} policy revisions · {} MiB",
            self.records,
            self.depth,
            self.policy_chain,
            self.bytes / (1024 * 1024)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("test ref name")
    }

    #[test]
    fn portable_rows_are_portable_and_refusals_name_their_token() {
        for row in TABLE {
            if row.portable {
                assert!(row.token.is_none(), "{} must not name a token", row.display);
            } else {
                assert!(
                    row.token.is_some(),
                    "{} must name the token that refuses it",
                    row.display
                );
            }
        }
        assert_eq!(TABLE.iter().filter(|r| r.portable).count(), 9);
        assert_eq!(TABLE.iter().filter(|r| !r.portable).count(), 10);
    }

    #[test]
    fn classification_follows_the_rows() {
        let portable = [
            "refs/attestations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "refs/changes/chg-6a6a8eab778ba4d0/attempt/0",
            "refs/changes/chg-6a6a8eab778ba4d0/merged",
            "refs/changes/chg-6a6a8eab778ba4d0/abandoned",
            "refs/gitiup/roster/00000007",
            "refs/gitiup/revocation/0000000000000001",
            "refs/gitiup/withdrawal/0000000000000001",
            "refs/gitiup/round/chg-1/build/linux/0",
            "refs/gitiup/reveal/chg-1/build/0000000000000001",
            "refs/gitiup/commit/chg-1/build/0000000000000001",
            "refs/gitiup/verdict/chg-1/build",
            "refs/gitiup/policy/history/000002",
        ];
        for ref_name in portable {
            let decision = classify(&name(ref_name));
            assert!(
                decision.portable,
                "{ref_name} must be portable: {decision:?}"
            );
            assert_eq!(decision.class(), Class::Proof, "{ref_name}");
            assert_eq!(decision.refusal(), None, "{ref_name}");
        }
        let refused = [
            ("refs/changes/chg-6a6a8eab778ba4d0/head", Class::Pointer),
            ("refs/heads/main", Class::Foreign),
            ("refs/gitiup/roster", Class::Pointer),
            ("refs/gitiup/signup/0000000000000001", Class::State),
            ("refs/gitiup/policy/current", Class::Pointer),
            ("refs/gitiup/kv/attestation", Class::Local),
            ("refs/gitiup/endorsement/0000000000000001", Class::Local),
            ("refs/attestations/not-hex/deeper/still", Class::Local),
            ("HEAD", Class::Local),
        ];
        for (ref_name, class) in refused {
            let decision = classify(&name(ref_name));
            assert!(!decision.portable, "{ref_name} must not be portable");
            assert_eq!(decision.class(), class, "{ref_name}");
            assert_eq!(decision.refusal(), Some("not_portable"), "{ref_name}");
        }
        // A refusal addressed at one round is about arbitration, which is a different
        // word for a different repair (D6).
        for ref_name in [
            "refs/gitiup/job/chg-1/build",
            "refs/gitiup/lease/chg-1/build/0000000000000001",
        ] {
            let decision = classify(&name(ref_name));
            assert!(!decision.portable, "{ref_name}");
            assert_eq!(decision.class(), Class::State, "{ref_name}");
            assert_eq!(
                decision.refusal(),
                Some("no_arbitration_here"),
                "{ref_name}"
            );
        }
    }

    #[test]
    fn a_round_specific_refusal_is_about_arbitration() {
        // D6: the same record class is `not_portable` in general and
        // `no_arbitration_here` when it is addressed at a specific round.
        assert_eq!(
            classify(&name("refs/gitiup/lease/chg-1/build")).refusal(),
            Some("not_portable")
        );
        assert_eq!(
            classify(&name("refs/gitiup/lease/chg-1/build/0000000000000001")).refusal(),
            Some("no_arbitration_here")
        );
        assert_eq!(
            classify(&name("refs/gitiup/job/chg-1/build")).refusal(),
            Some("no_arbitration_here")
        );
    }

    #[test]
    fn a_legacy_attestation_ref_is_read_and_respelled() {
        let legacy = classify(&name(
            "refs/attestations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        assert!(legacy.portable);
        assert!(legacy.respell);
        assert!(
            !classify(&name(
                "refs/attestations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbb"
            ))
            .respell
        );
    }

    #[test]
    fn import_and_gc_namespaces_never_travel() {
        assert!(!namespace_travels(&IMPORT));
        assert!(!namespace_travels(&GC));
        assert!(namespace_travels(&Namespace::ATTESTATION));
    }
}

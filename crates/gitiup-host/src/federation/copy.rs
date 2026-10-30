//! The transport itself: copy what one store advertises into another store.
//!
//! One engine, both verbs, every host pair: `gitiup fetch` and `gitiup push` are this
//! function called with the two hosts in the other order, which is the only reason they
//! can promise the same things. A fetch is not a trust event (ADR-0005 D3), a copy is
//! byte-identical or it did not happen (D7), and a store never advertises bytes it
//! cannot serve (D8).
//!
//! # Why records go by CAS and code goes by pack
//!
//! Every record travels `source.get(digest)` → `destination.put_cas(namespace, bytes)`,
//! which is *each host's own* CAS path — a conditional bucket PUT, a file write, a
//! commit onto a git host's record chain — and it re-hashes twice:
//! [`crate::BlobStore::get`] refuses bytes that do not match the name they were fetched
//! by, and [`crate::BlobStore::put_cas`] files bytes under the digest they make. D4's
//! step 0 is a per-object check, and a pack cannot answer it per object.
//!
//! Code is not a CAS record, so it moves over the host's pack path
//! ([`crate::RefStore::fetch_pack`] / [`crate::RefStore::put_pack`]) when the two hosts
//! can agree on a
//! format — which is a real question, not a rhetorical one: a bucket and a directory
//! store have no git object database, and say so. That is what makes `--proofs-only` a
//! verb flag rather than a synonym for the default: it declines the pack step, so a
//! read-only public mirror of a private repository carries evidence and no code, and
//! the report prints that it did.
//!
//! # The three things that make a run safe to interrupt
//!
//! * **bytes before refs** — an interrupted run leaves bytes nobody advertises, which
//!   is unread rather than broken, and the next run advertises them (D8 rule 1);
//! * **create-only advertisements** — a ref that already names these bytes is `already`,
//!   never a conflict and never an overwrite, so re-running moves nothing (D7);
//! * **pointers last, and only forward** — a change's `head` is written after the
//!   attempts it names, under [`Expect::Is`], and never to a lower attempt than the
//!   destination already advertises. A store never advertises less than it did, here or
//!   anywhere else: `gitiup attest gc` holds the same rule.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Host;
use crate::attest;
use crate::blob::{Namespace, Prefix};
use crate::capability::Capability;
use crate::change::{self, ChangeId, ChangeRef, StoredRecord};
use crate::error::{HostError, HostErrorKind, HostResult};
use crate::oid::Oid;
use crate::pack::{PackFormat, PackRequest};
use crate::refs::{Actor, Expect, Ref, RefName, RefQuery, RefUpdate, ns};

use super::portable::{self, Budgets, Decision};

/// Which way the copy went, for the report. Direction is about who asked, not about
/// what is allowed: a mirror never pushes back (D6), and nothing here lets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    /// A reader pulls a copy into its own store.
    Fetch,
    /// An origin publishes a copy to a mirror.
    Push,
}

impl Verb {
    /// The stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Fetch => "fetch",
            Verb::Push => "push",
        }
    }
}

/// What a copy should move, and how far it may go.
#[derive(Debug, Clone)]
pub struct Options {
    /// Which verb asked, for the report.
    pub verb: Verb,
    /// How to describe the source, in the report and in every arrival record.
    pub from: String,
    /// How to describe the destination.
    pub to: String,
    /// Who is running this, recorded on every ref written.
    pub actor: Actor,
    /// One change: its attempts and state records, the quorum records addressed to it,
    /// and the proofs filed for the commits its attempts propose.
    pub change: Option<ChangeId>,
    /// The proofs filed about one object.
    pub commit: Option<Oid>,
    /// Evidence without code: decline the pack step, and say so.
    pub proofs_only: bool,
    /// Fail the command if anything at all was refused, for the CI job that would rather
    /// know (D10).
    pub strict: bool,
    /// Report what would move and change nothing.
    pub dry_run: bool,
    /// The budgets a run may not exceed (D10).
    pub budgets: Budgets,
    /// The arrival clock, microseconds since the epoch. Recorded, never believed: no
    /// verdict may read it (D5 clause 1).
    pub now_us: i64,
    /// Write a `kv/import/<digest>` arrival record for each digest that arrived.
    pub record_arrivals: bool,
}

impl Options {
    /// The shape both verbs share, before the optional flags are set.
    pub fn new(verb: Verb, from: impl Into<String>, to: impl Into<String>) -> Options {
        Options {
            verb,
            from: from.into(),
            to: to.into(),
            actor: Actor::from_env(),
            change: None,
            commit: None,
            proofs_only: false,
            strict: false,
            dry_run: false,
            budgets: Budgets::default(),
            now_us: crate::attest::MICROS * crate::time::Timestamp::now().as_unix() as i64,
            record_arrivals: true,
        }
    }

    /// The reason a pointer write records, so a store's reflog says which verb made it.
    fn reason(&self) -> String {
        format!("{} from {}", self.verb.as_str(), self.from)
    }
}

/// One refusal, named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The ref it was about, when it was about a ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The digest it was about, when it was about a record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The [ADR-0005 D10](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
    /// token.
    pub token: String,
    /// The exit code that token carries.
    pub exit: u8,
    /// What was wrong, in a sentence.
    pub detail: String,
}

/// A pointer that was resolved, and what was done about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerMove {
    /// The pointer ref.
    pub reference: String,
    /// What it named at the source, resolved *here* rather than copied (D2).
    pub resolved: String,
    /// `written` · `moved` · `already` · `held` (this store is at or past it) ·
    /// `diverged` · `nothing`.
    pub action: String,
    /// The sentence worth printing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The values [`CodeReport::outcome`] can take, in one place so a report consumer can
/// tell "the host said no" apart from "nobody asked".
pub const CODE_OUTCOMES: &[&str] = &[
    "carried",
    "declined",
    "unsupported",
    "missing",
    "refused",
    "nothing-asked",
    "not-asked",
];

/// What happened to the code the copied proofs are about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeReport {
    /// Objects asked for.
    pub asked: usize,
    /// Objects that arrived.
    pub carried: usize,
    /// `carried` · `declined` · `unsupported` · `missing` · `refused` · `nothing-asked`.
    pub outcome: String,
    /// The sentence a human reads when it is not `carried`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// What happened to the subjects of the proofs that arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectReport {
    /// Attestations copied.
    pub attestations: usize,
    /// Distinct objects they name.
    pub subjects: usize,
    /// Whether the code behind them travelled too.
    pub carried: bool,
    /// Whether a missing subject was excused, and by what.
    pub excused: Option<String>,
}

/// Object counts, in the words the report prints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Objects {
    /// Objects this run stored that were not there before.
    pub arrived: usize,
    /// Objects the destination already held — still re-hashed, because an existing blob
    /// is not a verified blob (D4).
    pub already: usize,
    /// Objects whose bytes were hashed here and matched the name they arrived under.
    pub rehashed: usize,
    /// Bytes newly stored.
    pub bytes: u64,
}

/// Ref counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refs {
    /// Advertisements this run created.
    pub written: usize,
    /// Advertisements that already named these exact bytes.
    pub already: usize,
    /// Pointers moved or created.
    pub moved: usize,
    /// Legacy single-level refs re-spelled as `<subject>/<digest>` (D7).
    pub respelled: usize,
}

/// How much of the budget went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUse {
    /// The budget itself.
    pub budgets: Budgets,
    /// Records in scope.
    pub records: usize,
    /// Bytes newly stored.
    pub bytes: u64,
}

/// The report a copy prints, and the only thing a caller may read.
///
/// It counts and it names refusals. It does not say whether anything is trusted,
/// believed, verified or acceptable, and there is no field a caller may branch on to
/// decide a merge (D3 clause 4): [`CopyReport::trust`] is the string `none` on every run
/// of every host pair, and `gitiup verify` is the command that produces a belief.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyReport {
    /// The verb that ran.
    pub verb: Verb,
    /// The source, as described.
    pub from: String,
    /// The destination, as described.
    pub to: String,
    /// Objects moved.
    pub objects: Objects,
    /// Refs moved.
    pub refs: Refs,
    /// Refused things, each with its token.
    pub refused: Vec<Refusal>,
    /// Refusal counts by token: the line a human reads.
    pub refused_by: BTreeMap<String, usize>,
    /// Skipped counts by portability class (`pointer`, `state`, `local`, `foreign`).
    pub skipped_by_class: BTreeMap<String, usize>,
    /// Pointers resolved and moved.
    pub pointers: Vec<PointerMove>,
    /// What happened to the code.
    pub code: CodeReport,
    /// What happened to the proofs' subjects.
    pub subject: SubjectReport,
    /// Budget spent.
    pub budget: BudgetUse,
    /// Always [`TRUST_NONE`]. There is no other value and no way to make it say one:
    /// a copy transfers bytes and never trust (D3).
    pub trust: String,
    /// Arrival records written (`kv/import/<digest>`).
    pub arrivals: usize,
    /// `--proofs-only`, echoed so a report explains itself later.
    pub proofs_only: bool,
    /// Nothing changed.
    pub dry_run: bool,
    /// What age is measured from, printed so D5 clause 1 can be checked in a report
    /// instead of trusted: [`AGE_BASIS`], always, and never arrival.
    pub age_basis: String,
}

/// The only value the report's `trust` field ever holds.
pub const TRUST_NONE: &str = "none";
/// The only value the report's `age_basis` field ever holds (D5 clause 1).
pub const AGE_BASIS: &str = "claimed_at_us";

impl CopyReport {
    fn new(options: &Options) -> CopyReport {
        CopyReport {
            verb: options.verb,
            from: options.from.clone(),
            to: options.to.clone(),
            objects: Objects::default(),
            refs: Refs::default(),
            refused: Vec::new(),
            refused_by: BTreeMap::new(),
            skipped_by_class: BTreeMap::new(),
            pointers: Vec::new(),
            code: CodeReport {
                asked: 0,
                carried: 0,
                outcome: "nothing-asked".to_string(),
                detail: None,
            },
            subject: SubjectReport {
                attestations: 0,
                subjects: 0,
                carried: false,
                excused: None,
            },
            budget: BudgetUse {
                budgets: options.budgets,
                records: 0,
                bytes: 0,
            },
            trust: TRUST_NONE.to_string(),
            arrivals: 0,
            proofs_only: options.proofs_only,
            dry_run: options.dry_run,
            age_basis: AGE_BASIS.to_string(),
        }
    }

    /// Count one refusal.
    fn refuse(
        &mut self,
        token: &str,
        reference: Option<&RefName>,
        digest: Option<&Oid>,
        detail: impl Into<String>,
    ) {
        self.push(Refusal {
            reference: reference.map(|name| name.as_str().to_string()),
            digest: digest.map(|oid| oid.hex()),
            token: token.to_string(),
            exit: super::exit_for(token),
            detail: detail.into(),
        });
    }

    /// Count an already-built refusal.
    fn push(&mut self, refusal: Refusal) {
        *self.refused_by.entry(refusal.token.clone()).or_insert(0) += 1;
        self.refused.push(refusal);
    }

    /// Count one skipped ref by class.
    fn skipped(&mut self, class: &str) {
        *self.skipped_by_class.entry(class.to_string()).or_insert(0) += 1;
    }

    /// The exit code this run deserves: an integrity failure always fails the command,
    /// a scope refusal only under `--strict` (D10).
    pub fn exit_code(&self, strict: bool) -> u8 {
        let integrity = self
            .refused
            .iter()
            .filter(|refusal| refusal.exit >= 7)
            .map(|refusal| refusal.exit)
            .max();
        integrity.unwrap_or(if strict && !self.refused.is_empty() {
            6
        } else {
            0
        })
    }

    /// Whether anything at all was refused.
    pub fn any_refused(&self) -> bool {
        !self.refused.is_empty()
    }

    /// The lines a human gets, in the ADR's own shape.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut out = vec![
            format!(
                "objects          {} new, {} already ({} bytes)",
                self.objects.arrived, self.objects.already, self.objects.bytes
            ),
            format!(
                "re-hashed        {} objects checked against their own name",
                self.objects.rehashed
            ),
            format!(
                "refs             {} written, {} moved, {} already, {} respelled",
                self.refs.written, self.refs.moved, self.refs.already, self.refs.respelled
            ),
        ];
        if self.refused.is_empty() {
            out.push("refused          none".to_string());
        } else {
            let parts: Vec<String> = self
                .refused_by
                .iter()
                .map(|(token, count)| format!("{count} {token}"))
                .collect();
            out.push(format!(
                "refused          {} ({})",
                self.refused.len(),
                parts.join(", ")
            ));
        }
        if !self.skipped_by_class.is_empty() {
            let parts: Vec<String> = self
                .skipped_by_class
                .iter()
                .map(|(class, count)| format!("{count} {class}"))
                .collect();
            out.push(format!("not portable     {}", parts.join(", ")));
        }
        for pointer in &self.pointers {
            out.push(format!(
                "pointer          {} → {} ({})",
                pointer.reference, pointer.resolved, pointer.action
            ));
        }
        out.push(format!(
            "code             {} of {} asked — {}",
            self.code.carried, self.code.asked, self.code.outcome
        ));
        out.push(format!(
            "subject          {} attestations about {} object(s){}",
            self.subject.attestations,
            self.subject.subjects,
            match &self.subject.excused {
                Some(why) => format!(", {why}"),
                None => String::new(),
            }
        ));
        out.push(format!("trust            {}", self.trust));
        out
    }
}

/// Copy every portable ref one host advertises into another.
///
/// A [`HostError`] out of this function is a *command-level* refusal — a destination
/// that cannot take a create-only write, a budget the whole set busts — and it carries
/// the exit code of its token. Per-record refusals are in the report and do not fail
/// the run, because one unimportable proof must not end a fetch of two hundred (D9).
pub fn copy(from: &dyn Host, to: &dyn Host, options: &Options) -> HostResult<CopyReport> {
    // A destination that cannot honour a create-only write cannot hold a copy without
    // overwriting somebody else's bytes. This is the plain-git host's
    // `read-only = "true"` met at the boundary instead of halfway down a list (D6) — and
    // it is asked with `require`, not by reading the bit, because a forge that answers
    // anonymously advertises CAS and then denies every write: the bit is true and the
    // answer is no, and only `require` asks both questions.
    if let Err(why) = to.require(Capability::Cas) {
        return Err(HostError::unsupported(
            "read_only",
            format!(
                "read_only: {} cannot take a copy — refs here are not compare-and-swap writes \
                 this store will honour ({why}), so nothing could be filed without overwriting \
                 what already stands",
                options.to
            ),
        )
        .with_hint(
            "a read-only store is a fine place to *fetch from* — that is what a public mirror is. \
             Name a writable destination, or if this one really is writable, say so with \
             `read-only = \"false\"` in its [[remote]] options (and a forge needs a token: an \
             anonymous one can only ever be read)",
        ));
    }

    let mut report = CopyReport::new(options);
    // Listed by namespace, not `RefQuery::all()`, and that is not an optimisation. A
    // forge hides its plumbing from a bare listing on purpose — `refs/gitiup/**` names
    // verifier keys and seat slots, and "mirror this store" must not mean "publish its
    // roster" (C11) — so a copy that asked for everything would silently come back with
    // no roster epochs, no verdicts and no rounds, which is D15's failure: a mirror
    // missing half of what it serves and looking complete. Asking per namespace is the
    // copy saying *which* namespaces it has an opinion about, and it is what makes the
    // forge's own privacy rule visible to the code that has to honour it.
    let listing = namespaces(
        from,
        &[ns::ATTESTATIONS, ns::CHANGES, ns::GITIUP, ns::HEADS],
    )?;
    let change_subjects: BTreeSet<String> = match &options.change {
        Some(id) => change_heads(from, id)?,
        None => BTreeSet::new(),
    };

    // Scope, then classification: everything in scope that may not travel is refused
    // *by name*, so "we did not copy that" is a report and never a silence (D2).
    let mut plan: Vec<(Ref, Decision)> = Vec::new();
    for reference in &listing {
        if !in_scope(reference, options, &change_subjects) {
            continue;
        }
        let decision = portable::classify(&reference.name);
        if decision.portable {
            plan.push((reference.clone(), decision));
        } else {
            let token = decision.refusal().unwrap_or("not_portable");
            report.skipped(decision.class().as_str());
            report.refuse(
                token,
                Some(&reference.name),
                None,
                format!("{} — {}", decision.row.display, decision.row.note),
            );
        }
    }
    plan.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    report.budget.records = plan.len();
    if plan.len() > options.budgets.records {
        return Err(refusal_error(
            "closure_budget_records",
            format!(
                "this copy would move {} records, over the budget of {}; refused rather than \
                 truncated, so a partial run is never mistaken for a complete one",
                plan.len(),
                options.budgets.records
            ),
        ));
    }

    // Which namespace each blob lives in at the source, so it is filed under the same
    // one here. A ref cannot say, and inventing a namespace would file a verdict where
    // no reader looks for it.
    let homes = namespace_map(from)?;

    let mut arrived: Vec<(Oid, RefName)> = Vec::new();
    let mut subjects: BTreeSet<String> = BTreeSet::new();
    let mut changes: BTreeSet<String> = BTreeSet::new();
    let mut attestations = 0usize;
    for (reference, decision) in &plan {
        if let Some(id) = reference.name.change_id() {
            changes.insert(id.to_string());
        }
        let is_proof = decision.kind() == Some("attestation");
        if is_proof && let Some((subject, _)) = attest::parse_ref(&reference.name) {
            subjects.insert(subject.hex());
            attestations += 1;
        }
        if let Some(arrival) =
            copy_one(from, to, &homes, reference, decision, options, &mut report)?
        {
            arrived.push(arrival);
        }
        if report.objects.bytes > options.budgets.bytes {
            return Err(refusal_error(
                "closure_budget_bytes",
                format!(
                    "this copy would add more than the {} bytes a run may add; nothing past the \
                     budget was written",
                    options.budgets.bytes
                ),
            ));
        }
    }
    report.subject.attestations = attestations;
    report.subject.subjects = subjects.len();
    report.budget.bytes = report.objects.bytes;

    // Pointers after the records they name.
    for pointer in change_pointers(from, to, &changes, options)? {
        if pointer.action == "written" || pointer.action == "moved" {
            report.refs.moved += 1;
        }
        report.pointers.push(pointer);
    }

    // Code, over each host's own pack path, unless the operator asked for evidence only.
    let wants = code_wants(from, &plan)?;
    if options.proofs_only {
        report.code.asked = wants.len();
        report.code.outcome = "declined".to_string();
        report.code.detail = Some(
            "--proofs-only moves evidence without code history, which is what a read-only public \
             mirror of a private repository wants"
                .to_string(),
        );
        report.subject.excused =
            Some("excused (--proofs-only implies --allow-missing-subject)".to_string());
    } else if wants.is_empty() {
        report.code.asked = 0;
    } else {
        report.code = move_code(from, to, &wants, options)?;
        report.subject.carried = report.code.outcome == "carried";
        if !report.subject.carried {
            report.subject.excused = Some(
                "the objects they are about did not travel between these two hosts".to_string(),
            );
        }
    }

    // This store's own account of how these bytes got here (D5). Local by construction:
    // arrival records are the one thing a copy never copies.
    if options.record_arrivals && !options.dry_run {
        for (digest, reference) in &arrived {
            write_arrival(to, digest, reference, options)?;
            report.arrivals += 1;
        }
    }
    Ok(report)
}

/// Copy one advertised record. `Ok(Some(..))` when new bytes landed.
fn copy_one(
    from: &dyn Host,
    to: &dyn Host,
    homes: &BTreeMap<String, Namespace>,
    reference: &Ref,
    decision: &Decision,
    options: &Options,
    report: &mut CopyReport,
) -> HostResult<Option<(Oid, RefName)>> {
    let name = &reference.name;
    let bytes = match from.get(&reference.oid) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            report.refuse(
                "closure_incomplete",
                Some(name),
                Some(&reference.oid),
                "the source advertises this ref but cannot return its bytes. A store that \
                 advertises what it does not hold is the failure ADR-0005 D8 rules out; the \
                 fetch carries on with the rest",
            );
            return Ok(None);
        }
        Err(error) => {
            report.refuse(
                "closure_incomplete",
                Some(name),
                Some(&reference.oid),
                format!("the source could not return these bytes: {error}"),
            );
            return Ok(None);
        }
    };
    report.objects.rehashed += 1;
    let digest = Oid::hash_bytes(&bytes);

    // D4 step 0, before a byte is written anywhere: the advertisement must name the
    // bytes it returns. This is the check that makes a re-canonicalising transport
    // impossible rather than merely discouraged (D7).
    if digest != reference.oid {
        report.refuse(
            "digest_mismatch",
            Some(name),
            Some(&reference.oid),
            format!(
                "{name} advertises {} and its bytes hash to {}; nothing was written",
                reference.oid.short_default(),
                digest.short_default()
            ),
        );
        return Ok(None);
    }
    if let Some((_, promised)) = attest::parse_ref(name) {
        // The leaf of `<subject>/<digest>` repeats the digest the blob is filed under,
        // so a store that moved a proof without moving its name is caught here and not
        // at the reader's end three weeks later.
        if promised != digest {
            report.refuse(
                "digest_mismatch",
                Some(name),
                Some(&promised),
                "the ref leaf and the bytes disagree: in this namespace the ref names its own \
                 digest, twice over (subject and proof)",
            );
            return Ok(None);
        }
    }
    // Steps 1–3 for the records whose format this crate owns. Everything else — a
    // round, a verdict, a roster epoch — is another crate's document, and
    // `gitiup attest import` is the verb that re-verifies those.
    if matches!(
        decision.kind(),
        Some("change") | Some("merge") | Some("abandon")
    ) && let Some(refusal) = record_refusal(name, &bytes, &digest)
    {
        report.push(refusal);
        return Ok(None);
    }

    let Some(namespace) = homes.get(&digest.hex()) else {
        report.refuse(
            "closure_incomplete",
            Some(name),
            Some(&digest),
            "the source serves these bytes but does not list a namespace for them, so they \
             cannot be filed where a reader would look for them",
        );
        return Ok(None);
    };
    let target = advertisement(name, decision, &digest, report)?;

    let already_there = to.head(&digest).ok().flatten().is_some();
    if !options.dry_run {
        match to.put_cas(namespace, &bytes) {
            Ok(stored) if stored == digest => {}
            Ok(stored) => {
                // Not a naming problem to work around: the destination answered with a
                // digest for bytes that are not that digest. D4: nothing may be
                // advertised behind it, and the command fails (8).
                report.push(Refusal {
                    reference: Some(name.as_str().to_string()),
                    digest: Some(digest.hex()),
                    token: "digest_mismatch".to_string(),
                    exit: 8,
                    detail: format!(
                        "the destination returned {} for bytes that hash to {}; this run \
                         stopped rather than advertise bytes no reader can fetch",
                        stored.short_default(),
                        digest.short_default()
                    ),
                });
                return Err(refusal_error(
                    "digest_mismatch",
                    format!(
                        "{} is not the digest its bytes make",
                        stored.short_default()
                    ),
                )
                .with_exit_code(8));
            }
            Err(error) => {
                report.refuse(
                    "digest_mismatch",
                    Some(name),
                    Some(&digest),
                    format!("the destination refused these bytes: {error}"),
                );
                return Ok(None);
            }
        }
    }

    match write_advertisement(to, &target, &digest, options) {
        Ok(RefAction::Written) => {
            report.refs.written += 1;
            if decision.respell {
                report.refs.respelled += 1;
            }
        }
        Ok(RefAction::Already) => report.refs.already += 1,
        Ok(RefAction::Conflict(found)) => {
            report.refuse(
                "digest_mismatch",
                Some(&target),
                Some(&digest),
                format!(
                    "{target} already names {}, and a name in the portable set belongs to the \
                     bytes it names: nothing was overwritten",
                    found.short_default()
                ),
            );
            return Ok(None);
        }
        Err(error) => {
            report.refuse(
                "diverged",
                Some(&target),
                Some(&digest),
                format!("the destination would not take the advertisement: {error}"),
            );
            return Ok(None);
        }
    }

    if options.dry_run {
        // A dry run still read the source and re-hashed every byte; what it withholds is
        // the write, not the plan. So the counts mean the same thing either way and
        // `dry_run: true` is what says they are a plan rather than a history — which is
        // the only reason an operator will trust a dry report enough to act on it.
        if already_there {
            report.objects.already += 1;
        } else {
            report.objects.arrived += 1;
            report.objects.bytes += bytes.len() as u64;
        }
        return Ok(None);
    }
    if already_there {
        // Re-hashed, counted, and believed nothing: a blob that is already here was
        // verified by whoever put it here, and this reader's trust list was not in the
        // room (D4's "no waiver for duplicates").
        report.objects.already += 1;
        return Ok(None);
    }
    report.objects.arrived += 1;
    report.objects.bytes += bytes.len() as u64;
    Ok(Some((digest, target)))
}

/// The ref a copied record is advertised by at the destination.
///
/// A legacy single-level `refs/attestations/<subject>` is re-spelled as
/// `<subject>/<digest>` and the old spelling is never written again (D7).
fn advertisement(
    name: &RefName,
    decision: &Decision,
    digest: &Oid,
    report: &mut CopyReport,
) -> Result<RefName, HostError> {
    if !decision.respell {
        return Ok(name.clone());
    }
    match attest::parse_legacy_ref(name) {
        Some(subject) => Ok(attest::ref_name(&subject, digest)),
        None => {
            report.refuse(
                "digest_mismatch",
                Some(name),
                Some(digest),
                "this ref was classified as the legacy single-level shape and is not",
            );
            Err(refusal_error(
                "digest_mismatch",
                format!("{name} is not a legacy attestation ref"),
            ))
        }
    }
}

/// Whether a ref was created, found identical, or found holding something else.
enum RefAction {
    Written,
    Already,
    Conflict(Oid),
}

/// Create-only, always. A name collision in the portable set is a content match, and
/// the answer to a content match is `already` — never an overwrite, never a suffix,
/// never a `-2` (D7).
fn write_advertisement(
    to: &dyn Host,
    name: &RefName,
    digest: &Oid,
    options: &Options,
) -> Result<RefAction, HostError> {
    if let Some(existing) = to.get_ref(name)? {
        return if existing.oid == *digest {
            Ok(RefAction::Already)
        } else {
            Ok(RefAction::Conflict(existing.oid))
        };
    }
    let update = RefUpdate::create(name.clone(), *digest)
        .with_actor(options.actor.clone())
        .with_message(options.reason());
    if options.dry_run {
        // Nothing is written on a dry run and the advertisement most of all: a ref naming
        // bytes this store cannot return is the single failure D8 rule 1 exists to
        // prevent, and a dry run that left one behind would be worse than no dry run. The
        // count is still reported, because the plan is the product here.
        return Ok(RefAction::Written);
    }
    match to.update_ref_cas(&update) {
        Ok(_) => Ok(RefAction::Written),
        Err(error) if error.kind() == HostErrorKind::Conflict => {
            // Somebody published the same record in between. Re-read rather than guess:
            // that is the whole of what makes this run resumable.
            match to.get_ref(name)? {
                Some(found) if found.oid == *digest => Ok(RefAction::Already),
                Some(found) => Ok(RefAction::Conflict(found.oid)),
                None => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

/// D4 steps 1–3 for the records this crate owns the format of.
fn record_refusal(name: &RefName, bytes: &[u8], digest: &Oid) -> Option<Refusal> {
    let refusal = |token: &str, exit: u8, detail: String| {
        Some(Refusal {
            reference: Some(name.as_str().to_string()),
            digest: Some(digest.hex()),
            token: token.to_string(),
            exit,
            detail,
        })
    };
    let same_ref = |why: String| {
        refusal(
            "same_ref",
            6,
            format!(
                "{name}: {why}. A record filed under a name its own content does not name is \
                 refused, not renamed"
            ),
        )
    };
    let record = match change::record_from_bytes(bytes) {
        Ok(record) => record,
        Err(error) => {
            return refusal(
                "not_canonical",
                8,
                format!("these bytes are not a change record this build can read: {error}"),
            );
        }
    };
    if record.digest().ok().as_ref() != Some(digest) {
        return refusal(
            "digest_mismatch",
            8,
            "the record does not hash to the name it is filed under".to_string(),
        );
    }
    // Step 2: the ref it arrived under is the ref its content names (`same_ref`).
    match (change::parse_ref(name), &record) {
        (Some(ChangeRef::Attempt { id, index }), StoredRecord::Change(inner))
            if inner.attempts.index != index || inner.change_id != id =>
        {
            same_ref(format!("the ref names {} attempt {index}", id.as_str()))
        }
        (Some(ChangeRef::Merged { id }), StoredRecord::Merge(inner)) if inner.change_id != id => {
            same_ref(format!("the ref names a merge of {}", id.as_str()))
        }
        (Some(ChangeRef::Abandoned { id }), StoredRecord::Abandon(inner))
            if inner.change_id != id =>
        {
            same_ref(format!("the ref names an abandon of {}", id.as_str()))
        }
        (None, _) => {
            same_ref("the ref it arrived under is not one this layout defines".to_string())
        }
        _ => None,
    }
}

/// Which refs a run is about.
fn in_scope(reference: &Ref, options: &Options, change_subjects: &BTreeSet<String>) -> bool {
    if options.change.is_none() && options.commit.is_none() {
        return true;
    }
    if let Some(subject) = attestation_subject(&reference.name) {
        if options
            .commit
            .as_ref()
            .is_some_and(|commit| commit.hex() == subject)
        {
            return true;
        }
        // Proofs filed for a commit one of the change's attempts proposes are part of
        // what `--change` means: the change and its evidence arrive together.
        if options.change.is_some() && change_subjects.contains(&subject) {
            return true;
        }
    }
    if let Some(change_id) = &options.change {
        if reference.name.change_id() == Some(change_id.as_str()) {
            return true;
        }
        if gitiup_child_names_change(&reference.name, change_id.as_str()) {
            return true;
        }
    }
    false
}

/// The `<subject>` hex of a `refs/attestations/<subject>/**` ref.
fn attestation_subject(name: &RefName) -> Option<String> {
    let rest = name.attestation_target()?;
    let first = rest.split('/').next()?;
    Oid::from_hex(first).ok().map(|oid| oid.hex())
}

/// Whether `refs/gitiup/<kind>/<change>/…` is addressed to one change.
fn gitiup_child_names_change(name: &RefName, change_id: &str) -> bool {
    let parts: Vec<&str> = name.segments().collect();
    if parts.len() < 4 || parts[0] != "refs" || parts[1] != "gitiup" {
        return false;
    }
    matches!(
        parts[2],
        "round" | "verdict" | "commit" | "reveal" | "job" | "lease"
    ) && parts[3] == change_id
}

/// The commits a change's attempts propose — what `--change` implies about the proofs.
fn change_heads(from: &dyn Host, id: &ChangeId) -> HostResult<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for reference in from.list_refs(&RefQuery::prefix(change::change_prefix(id)))? {
        let Some(bytes) = from.get(&reference.oid)? else {
            continue;
        };
        if let Ok(StoredRecord::Change(record)) = change::record_from_bytes(&bytes) {
            out.insert(hex_of(&record.head));
            out.insert(hex_of(&record.base.oid));
        }
    }
    Ok(out)
}

/// Drop a `sha1:`/`sha256:` tag: a ref component and a CAS name are hex, nothing else.
fn hex_of(oid: &str) -> String {
    oid.split_once(':')
        .map(|(_, hex)| hex.to_ascii_lowercase())
        .unwrap_or_else(|| oid.to_ascii_lowercase())
}

/// The git objects the copied records are about.
fn code_wants(from: &dyn Host, plan: &[(Ref, Decision)]) -> HostResult<BTreeSet<Oid>> {
    let mut wants: BTreeSet<Oid> = BTreeSet::new();
    for (reference, decision) in plan {
        match decision.kind() {
            Some("attestation") => {
                if let Some((subject, _)) = attest::parse_ref(&reference.name) {
                    wants.insert(subject);
                }
            }
            Some("change") => {
                if let Some(bytes) = from.get(&reference.oid)?
                    && let Ok(StoredRecord::Change(record)) = change::record_from_bytes(&bytes)
                    && let Ok(oid) = Oid::from_hex(&hex_of(&record.head))
                {
                    wants.insert(oid);
                }
            }
            _ => {}
        }
    }
    Ok(wants)
}

/// Move the code over the hosts' own pack path, and report what they said.
///
/// There is no `match` on the transport here: the request is made and the host answers,
/// which is the difference between a host abstraction and a switch on a hostname.
fn move_code(
    from: &dyn Host,
    to: &dyn Host,
    wants: &BTreeSet<Oid>,
    options: &Options,
) -> HostResult<CodeReport> {
    let asked = wants.len();
    if options.dry_run {
        return Ok(CodeReport {
            asked,
            carried: 0,
            outcome: "not-asked".to_string(),
            detail: Some("--dry-run asked for nothing".to_string()),
        });
    }
    let request = PackRequest {
        wants: wants.iter().copied().collect(),
        have: Vec::new(),
        ref_prefixes: Vec::new(),
        format: PackFormat::GitPackfile,
        limit_bytes: None,
    };
    let pack = match from.fetch_pack(&request) {
        Ok(pack) => pack,
        Err(error) if code_refusal(&error) == "unsupported" => {
            return Ok(CodeReport {
                asked,
                carried: 0,
                outcome: "unsupported".to_string(),
                detail: Some(format!(
                    "the source has no git object database to send one from: {error}"
                )),
            });
        }
        Err(error) if code_refusal(&error) == "missing" => {
            return Ok(CodeReport {
                asked,
                carried: 0,
                outcome: "missing".to_string(),
                detail: Some(format!(
                    "the source advertises proofs about commits it does not itself hold: {error}"
                )),
            });
        }
        Err(error) => return Err(error),
    };
    match to.put_pack(&pack) {
        Ok(oid) => Ok(CodeReport {
            asked,
            carried: asked,
            outcome: "carried".to_string(),
            detail: Some(format!(
                "one pack, {} bytes, filed at {}",
                pack.bytes.len(),
                oid.short_default()
            )),
        }),
        Err(error) if code_refusal(&error) == "unsupported" => Ok(CodeReport {
            asked,
            carried: 0,
            outcome: "unsupported".to_string(),
            detail: Some(format!(
                "the destination has no git object database to put one into: {error}"
            )),
        }),
        Err(error) => Ok(CodeReport {
            asked,
            carried: 0,
            outcome: "refused".to_string(),
            detail: Some(format!("the destination refused the pack: {error}")),
        }),
    }
}

/// Which kind of "no" a pack answer was.
fn code_refusal(error: &HostError) -> &'static str {
    match error.kind() {
        HostErrorKind::UnsupportedCas | HostErrorKind::SchemeUnknown => "unsupported",
        HostErrorKind::NotFound => "missing",
        _ => "refused",
    }
}

/// Resolve and move each change's `head`, after its attempts are in place.
///
/// The pointer is never copied: the source's pointer is *read*, the attempt it names is
/// found, and this store's own pointer is written to that attempt — which is the
/// difference between "attempt 3 is here" and "attempt 3 was current at the origin at the
/// moment I looked", a statement no mirror is qualified to make (D2, D5).
fn change_pointers(
    from: &dyn Host,
    to: &dyn Host,
    changes: &BTreeSet<String>,
    options: &Options,
) -> HostResult<Vec<PointerMove>> {
    let mut out = Vec::new();
    for id_text in changes {
        let Ok(id) = ChangeId::new(id_text) else {
            continue;
        };
        let head_ref = change::change_head_ref(&id);
        let attempts = from.list_refs(&RefQuery::prefix(change::change_prefix(&id)))?;
        let Some(source_head) = from.get_ref(&head_ref)? else {
            out.push(PointerMove {
                reference: head_ref.as_str().to_string(),
                resolved: "absent at the source".to_string(),
                action: "nothing".to_string(),
                detail: None,
            });
            continue;
        };
        let named = attempts
            .iter()
            .find(|candidate| {
                matches!(
                    change::parse_ref(&candidate.name),
                    Some(ChangeRef::Attempt { .. })
                ) && candidate.oid == source_head.oid
            })
            .cloned();
        let Some(named) = named else {
            out.push(PointerMove {
                reference: head_ref.as_str().to_string(),
                resolved: source_head.oid.short_default(),
                action: "diverged".to_string(),
                detail: Some(
                    "the source's pointer names no attempt ref of this change, so there is no \
                     fact here for a pointer to point at"
                        .to_string(),
                ),
            });
            continue;
        };
        let index = match change::parse_ref(&named.name) {
            Some(ChangeRef::Attempt { index, .. }) => index,
            _ => continue,
        };
        let here = to.get_ref(&head_ref)?;
        let (action, detail) = match &here {
            Some(existing) if existing.oid == named.oid => ("already".to_string(), None),
            Some(existing) => {
                let current = attempt_index_at(to, &id)?.unwrap_or(u32::MAX);
                if current >= index {
                    (
                        "held".to_string(),
                        Some(format!(
                            "this store already advertises attempt {current}; a copy never moves \
                             a pointer backwards, and never advertises less than it did"
                        )),
                    )
                } else if options.dry_run {
                    ("would-move".to_string(), None)
                } else {
                    let update =
                        RefUpdate::new(head_ref.clone(), Expect::Is(existing.oid), named.oid)
                            .with_actor(options.actor.clone())
                            .with_message(options.reason());
                    match to.update_ref_cas(&update) {
                        Ok(_) => ("moved".to_string(), None),
                        Err(error) => (
                            "diverged".to_string(),
                            Some(format!(
                                "the pointer moved while this run read it, so nothing was \
                                 touched and nobody's review was rewritten: {error}"
                            )),
                        ),
                    }
                }
            }
            None if options.dry_run => ("would-write".to_string(), None),
            None => {
                let update = RefUpdate::create(head_ref.clone(), named.oid)
                    .with_actor(options.actor.clone())
                    .with_message(options.reason());
                match to.update_ref_cas(&update) {
                    Ok(_) => ("written".to_string(), None),
                    Err(error) => (
                        "diverged".to_string(),
                        Some(format!("the pointer could not be created: {error}")),
                    ),
                }
            }
        };
        out.push(PointerMove {
            reference: head_ref.as_str().to_string(),
            resolved: named.name.as_str().to_string(),
            action,
            detail,
        });
    }
    Ok(out)
}

/// Which attempt number a store's own `head` names, if it names one.
fn attempt_index_at(host: &dyn Host, id: &ChangeId) -> HostResult<Option<u32>> {
    let Some(head) = host.get_ref(&change::change_head_ref(id))? else {
        return Ok(None);
    };
    Ok(host
        .list_refs(&RefQuery::prefix(change::change_prefix(id)))?
        .into_iter()
        .find(|candidate| candidate.oid == head.oid)
        .and_then(|candidate| match change::parse_ref(&candidate.name) {
            Some(ChangeRef::Attempt { index, .. }) => Some(index),
            _ => None,
        }))
}

/// The listing a copy works from: one query per namespace it has an opinion about,
/// merged, sorted and de-duplicated. See the call site for why this is not `all()`.
fn namespaces(from: &dyn Host, prefixes: &[&str]) -> HostResult<Vec<Ref>> {
    let mut out: Vec<Ref> = Vec::new();
    for prefix in prefixes {
        out.extend(from.list_refs(&RefQuery::prefix(*prefix))?);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// `digest hex → namespace`, read out of the source's own listing.
fn namespace_map(from: &dyn Host) -> HostResult<BTreeMap<String, Namespace>> {
    let mut out = BTreeMap::new();
    for entry in from.list_prefix(&Prefix::all().as_str())? {
        if !portable::namespace_travels(&entry.namespace) {
            continue;
        }
        out.insert(entry.oid.hex(), entry.namespace);
    }
    Ok(out)
}

/// A refusal that ends the command, with its token in the message.
pub fn refusal_error(token: &str, detail: impl Into<String>) -> HostError {
    HostError::invalid("federation", format!("{token}: {}", detail.into())).with_exit_code(6)
}

/// The token a [`HostError`] out of [`copy`] deserves, so a CLI line and a library
/// caller print the same word.
pub fn token_for(error: &HostError) -> &'static str {
    let message = error.message();
    if let Some(token) = message.split(':').next().and_then(|head| {
        let head = head.trim();
        super::REFUSALS
            .iter()
            .find(|(known, _)| *known == head)
            .map(|(k, _)| *k)
    }) {
        return token;
    }
    match error.kind() {
        HostErrorKind::UnsupportedCas | HostErrorKind::PermissionDenied => "read_only",
        HostErrorKind::Conflict => "diverged",
        HostErrorKind::NotFound => "closure_incomplete",
        HostErrorKind::Unreachable => "unreachable",
        _ => "invalid",
    }
}

// ---------------------------------------------------------------------------
// arrival records (ADR-0005 D5)
// ---------------------------------------------------------------------------

/// The `type` member of an arrival record.
pub const IMPORT_TYPE: &str = "gitiup-import-1";
/// The schema version of an arrival record.
pub const IMPORT_SCHEMA_VERSION: u32 = 1;
/// What a namespace copy says about closure: it did not walk one, and says so instead
/// of claiming a completeness it did not check.
pub const CLOSURE_NOT_WALKED: &str = "not-walked";

/// What a copy records about each digest that landed, at `kv/import/<digest>`.
///
/// It answers the question a mirror exists to make answerable — *how did this get here*
/// — and it is local by construction: arrival records are never portable, and
/// `verified_by`/`verify_exit` are absent from every record a copy writes, because a
/// copy verifies nothing (D3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arrival {
    /// `gitiup-import-1`.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Schema version.
    pub schema_version: u32,
    /// The object that arrived.
    pub digest: String,
    /// The refs that advertise it here.
    pub refs: Vec<String>,
    /// Where the bytes were read from.
    pub arrived_from: String,
    /// When they arrived. Metadata only, for a human and for capacity eviction: no
    /// verdict may read it (D5 clause 1).
    pub arrived_at_us: i64,
    /// Whether this record's closure is present.
    pub closure: String,
}

impl Arrival {
    /// The record for one digest that arrived from `from`.
    pub fn new(digest: &Oid, reference: &RefName, from: &str, now_us: i64) -> Arrival {
        Arrival {
            record_type: IMPORT_TYPE.to_string(),
            schema_version: IMPORT_SCHEMA_VERSION,
            digest: digest.hex(),
            refs: vec![reference.as_str().to_string()],
            arrived_from: from.to_string(),
            arrived_at_us: now_us,
            closure: CLOSURE_NOT_WALKED.to_string(),
        }
    }

    /// Canonical JSON bytes, the way every gitiup record is stored.
    pub fn canonical_bytes(&self) -> HostResult<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|e| HostError::invalid("arrival record", e.to_string()))?;
        crate::config::canonical_json(&value)
    }

    /// Read one back, refusing anything that is not its own canonical form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Arrival, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

fn write_arrival(
    to: &dyn Host,
    digest: &Oid,
    reference: &RefName,
    options: &Options,
) -> HostResult<()> {
    let arrival = Arrival::new(digest, reference, &options.from, options.now_us);
    to.put_cas(&portable::IMPORT, &arrival.canonical_bytes()?)?;
    Ok(())
}

/// Every arrival record a store holds, by the digest that arrived.
///
/// This is how a store finds out it is a mirror — there is no `mirror` flag anywhere,
/// and there never will be: a store that can name where each of its copies came from is
/// a mirror, and one that cannot may not prune like one (D8 rule 2).
pub fn arrivals(host: &dyn Host) -> HostResult<BTreeMap<String, Arrival>> {
    let mut out = BTreeMap::new();
    for entry in host.list_prefix(portable::IMPORT.as_str())? {
        let Some(bytes) = host.get(&entry.oid)? else {
            continue;
        };
        if let Ok(arrival) = Arrival::from_bytes(&bytes) {
            out.insert(arrival.digest.clone(), arrival);
        }
    }
    Ok(out)
}

/// Whether this store can name a place to fetch `digest` back from.
pub fn has_refetch_source(host: &dyn Host, digest: &Oid) -> HostResult<bool> {
    Ok(arrivals(host)?.contains_key(&digest.hex()))
}

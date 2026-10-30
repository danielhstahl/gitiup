//! `gitiup attest import` — re-verify a proof *here* before it is filed *here*.
//!
//! [`gitiup fetch`](crate::fetch) moves a namespace; this moves a **closure** and, unlike
//! a copy, it **believes** something — or refuses to. That is the whole ticket
//! ([ADR-0005 D4 and D9](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)):
//!
//! ```text
//! gitiup attest import --from upstream --to ./store --commit $(git rev-parse HEAD) --apply
//! gitiup attest import --from https-mirror --to ./store --proofs-only --dry-run
//! ```
//!
//! # Why a copy is not enough
//!
//! A copy answers "are these the bytes their names promise" and stops there, because a
//! store cannot answer anything else and stay a store. A reader who then runs
//! [`gitiup verify`] against that copy is asking a question the copy never claimed to
//! answer, and a store that has ever served a proof nobody checked has taught every client
//! that checking is optional — because for the last nine proofs, checking found nothing
//! (D4, "*File it now, let readers check*", the rejected alternative).
//!
//! So this verb runs the **same ordered checks `gitiup verify attestation` runs** — it
//! calls [`AttestationDoc::verify_report`] and
//! [`gitiup_quorum::attestation::rederive`] with a policy built by the same flag
//! machinery ([`crate::verify::policy_spec`]), which is the only reason the two commands
//! cannot drift into disagreeing about what a signature or a freshness window means —
//! and then bolts two federation steps onto the ends of that ladder:
//!
//! * **closure** (D9): everything the ladder needed is *present at the source*, walked
//!   through the digest citations the records already carry — `round_digest`,
//!   `roster_digest`, `policy_digest`, `previous_digest`, `counted[]`, `proofs[]`. An
//!   edge with no foot is `closure_incomplete`, naming the record type and the edge, and
//!   the record is **not** filed: a partial closure is a photo of a proof.
//! * **subject** (D4 step 9): the object the proof is about is present, or the operator
//!   excused its absence out loud (`--allow-missing-subject`, implied by `--proofs-only`).
//!   "Deliberately not here" and "lost" are different sentences and a mirror that cannot
//!   tell them apart is a rumour.
//!
//! A `tier: quorum` attestation is the case the ticket names: it is a verdict restated,
//! and a verdict without its round, its roster epoch and its policy revision is a rumour
//! in a proof's clothing. The ladder refuses it for the same reason
//! [`gitiup verify attestation`] does — nothing here can re-derive what it states — and
//! the walk refuses it one step earlier when the source never had the records at all.
//!
//! # What a failure costs
//!
//! A document that fails is **reported and skipped**, and the rest of the import goes
//! ahead: one unimportable proof must not end an import of two hundred (D9, D10). The one
//! exception is an integrity failure — a bad signature (7) or bytes that are not the
//! bytes their name promises (8) — which is reported, skipped, *and* decides the exit
//! code, because a command that "succeeded" past one is a store that now contains one.
//! A scope refusal (6) exits 0 unless `--strict` is set, which is for the CI job that
//! would rather know something was skipped.
//!
//! # Nothing is filed behind a refusal, and nothing is overwritten
//!
//! Verification happens before the write, and the write is the same write
//! [`gitiup fetch`] uses — bytes before refs, create-only, re-hashed at both ends — so a
//! name that already stands against the same digest is `already` and a name that stands
//! against *different* bytes is `digest_mismatch` with nothing written (D7). There is no
//! second copy path here to get the ordering wrong in; the only thing this module decides
//! is *which* records the copy may take.
//!
//! # What the importing store then knows
//!
//! Every digest that lands gets a `kv/import/<digest>` record (D5) naming where it came
//! from, when, that its closure was walked, and — the part a namespace copy cannot say —
//! `verified_by` and `verify_exit`: who checked it here and what the ladder said. That is
//! the audit answer a mirror exists to make possible (*how did this get here*), and it
//! grants nothing: a later reader re-checks and does not inherit this run's belief, and
//! arrival time is never an input to a verdict (D5 clause 1).
//!
//! # Exit codes
//!
//! The same table as everywhere else (ADR-0001 D7): 0 ok · 2 usage · 3 I/O or an
//! unreachable store · 6 refused (a scope refusal under `--strict`, a read-only
//! destination, a busted budget, a policy that trusts nobody) · 7 a signature that does
//! not verify · 8 bytes that are not the bytes their name promises.

use std::collections::{BTreeMap, BTreeSet};

use gitiup_attest::{AttestationDoc, VerdictReport};
use gitiup_host::federation::{self, Arrival, Options, Verb, portable};
use gitiup_host::{Host, Oid};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;

/// Help for `gitiup attest import`.
pub const IMPORT_HELP: &str = "\
gitiup attest import — copy proofs from another store, and re-verify each one on arrival

USAGE:
    gitiup attest import --from <name|dir> --to <name|dir> [OPTIONS]

An import is a copy that checks. `gitiup fetch` moves a namespace and grants nothing;
`import` walks each attestation's own citations, runs every check `gitiup verify
attestation` would run — canonical bytes, digest, signature, trust, tier, environment,
freshness evaluated *here and now* — and files only what passes, together with the
evidence its verdict leans on. A document that fails is reported and skipped; the rest
of the import still lands.

BETWEEN WHICH STORES:
    --from <name|dir>          the store being imported from: a [[remote]] in gitiup.toml
                                   or a directory (see `gitiup doctor --remotes`)
    --to <name|dir>            the store being written to (aliases: --store <dir>,
                                   --remote <name>). An import writes, so it has to be
                                   named: a typo must not file proofs somewhere else
    --actor <name>             who the ref writes are recorded as

WHAT TO IMPORT:
    (nothing)                  every attestation the source advertises
    --commit <oid>             the proofs filed about one object (40 or 64 hex, or
                                   sha1:/sha256:)
    --change <id>              the proofs for the commits one change proposes, and the
                                   quorum records addressed to it
    --allow-missing-subject    import a proof whose subject object is not present in the
                                   destination, and say so in the report and in
                                   kv/import/ — which is the difference between an
                                   object that is deliberately not here and one that is
                                   lost
    --proofs-only              implies --allow-missing-subject: evidence without code
                                   history, which is what a public mirror of a private
                                   repository carries

HOW THE VERDICT IS JUDGED (the same flags `gitiup verify attestation` takes):
    --policy <path>            gitiup-policy.json (default: $GITIUP_POLICY)
    --trust <key>              repeatable: a SHA256:… key id or a keystore name. With
                                   none of these the trust list is this machine's
                                   keystore, and it says which
    --trust-any-key            check the mechanics and nobody's identity. Diagnosis only
    --tier <tier>              repeatable: provenance tiers to allow (default: local;
                                   `quorum` needs its verdict, round and epoch present)
    --allow-simulated          shorthand for adding `simulated`
    --sandbox <name>           repeatable: sandbox backends a `local` run may name
    --min-signatures <n>       distinct trusted signers required
    --max-age <age>            freshness window: 90s, 24h, 30d, 2w, never
    --max-skew <age>           how far a claimed time may run ahead of now
    --normalisation-version <n>  require the producer's normalisation rules
    --require <field=value>    repeatable environment requirement
    --require-env-match <m>    strict | major | off
    --expect-result <digest>   refuse unless the ResultDigest is exactly this
    --expect-challenge <digest> refuse unless this quorum challenge is the one named
    --now <time>               pin the clock (RFC 3339 or integer microseconds)

WHAT COMES WITH EACH PROOF (ADR-0005 D9):
    A record is imported with the evidence its own citations name, or not at all. The
    citations are read out of the documents — an attestation's subject, a verdict's round,
    roster and policy, a round's roster, reveals and (for a sealed round) commitments, a
    roster's revocations, a policy's predecessor chain — and every one of them must be
    advertised by the source, or the document is refused with `closure_incomplete` and the
    edge that has no foot is named.

    Two citations are answered by derivation rather than by a copy, and the report says so
    instead of assuming it: a round's `policy_digest` names the selection policy that sits
    inside the round record under the selector's signature, and a `tier: quorum`
    attestation's `verdict_digest` names a verdict this command recomputes from the round,
    the roster epoch and the reveals it just took — with the code `gitiup quorum verdict`
    runs, refusing the document unless the recomputed verdict matches. A quorum
    attestation whose round, roster or reveals are not offered is a rumour, and is refused.

HOW FAR TO GO:
    --dry-run                  read, verify, plan, and write nothing; prints the refusals
    --apply                    do it. Without --apply and without --dry-run nothing is
                                   written: the plan is printed first, like `attest gc`
    --strict                   any refusal at all fails the command (exit 6)
    --max-records <n>          records per run (default 4096) — a refusal, never a truncation
    --max-depth <n>            closure hops (default 8): attestation → verdict → round →
                                   epoch → revocation → policy, with room
    --max-policy-chain <n>     policy revisions walked (default 64)
    --max-bytes <size>         new bytes per run (default 1 GiB; 500m, 4g, or bytes)

OUTPUT:
    -j, --json                 the whole report as JSON: candidates, what was filed and
                                   with which verdict, every refusal with its token and
                                   exit code, the closure each import carried, and what
                                   was recorded in kv/import/

A COPY MOVES BYTES AND NEVER TRUST, AND AN IMPORT MOVES BELIEF ABOUT BYTES — nothing more.
The verdict printed here is this machine's, computed from this machine's trust roots and
this machine's clock; it is recorded at kv/import/<digest> as an audit note about a box,
and the next reader recomputes it rather than inheriting it. There is no flag here that
makes an imported proof count as one you witnessed, because there is no such thing.

Exit codes: 0 ok · 2 usage · 3 I/O or unreachable · 6 refused (scope under --strict, a
read-only destination, a busted budget, nothing trusted) · 7 a signature that does not
verify · 8 bytes that are not the bytes their name promises. A per-record refusal does
not fail the run; an integrity failure does, and nothing was filed behind either.

Try:
    gitiup attest import --from upstream --to ./store --dry-run
    gitiup attest import --from upstream --to ./store --commit $(git rev-parse HEAD) --apply
    gitiup attest import --from mirror --to ./store --proofs-only --trust ada --json
";

/// Valued flags `gitiup attest import` accepts.
const VALUED: &[&str] = &[
    "--from",
    "--to",
    "--store",
    "--remote",
    "--actor",
    "--commit",
    "--change",
    "--policy",
    "--trust",
    "--tier",
    "--sandbox",
    "--min-signatures",
    "--max-age",
    "--max-skew",
    "--normalisation-version",
    "--require",
    "--require-env-match",
    "--now",
    "--expect-result",
    "--expect-challenge",
    "--max-records",
    "--max-depth",
    "--max-policy-chain",
    "--max-bytes",
];

/// Switches `gitiup attest import` accepts. There is no trust flag in this list beyond
/// the ones `gitiup verify attestation` already has, and adding a store-shaped one is
/// the refusal ADR-0005 D3 exists to prevent.
const SWITCHES: &[&str] = &[
    "--apply",
    "--dry-run",
    "--strict",
    "--proofs-only",
    "--allow-missing-subject",
    "--trust-any-key",
    "--allow-simulated",
    "--json",
];

/// `gitiup attest import …`
pub fn import(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.help(IMPORT_HELP).is_some() || args.positional.iter().any(|word| word == "help") {
        print!("{IMPORT_HELP}");
        return Ok(());
    }
    if args.on("--apply") && args.on("--dry-run") {
        return Err(CliError::usage(
            "--apply and --dry-run are opposite answers to the same question: read the \
             plan with --dry-run, then run it with --apply",
        ));
    }
    // `--dry-run` is the default and `--apply` is the exception that writes, which is the
    // `attest gc` convention: an import moves signed evidence and the operator reads the
    // list first.
    let plan_only = !args.on("--apply") || args.on("--dry-run");

    let run = Run::open(&args)?;
    run.execute(plan_only, args.on("--strict"))
}

// ---------------------------------------------------------------------------
// the run: two stores, one policy, one budget
// ---------------------------------------------------------------------------

use crate::fetch;
use crate::verify;

/// One import: the two stores, the policy the verdicts are judged by, and the bounds.
pub(crate) struct Run {
    /// The store the bytes come from.
    from: Box<dyn Host>,
    from_what: String,
    /// The store they are filed in.
    to: Box<dyn Host>,
    to_what: String,
    /// The policy the ladder judges by, built by `gitiup verify attestation`'s own flag
    /// machinery — which is the one line in this file that matters most, because it is
    /// why an import and a verify cannot disagree about the same document.
    spec: verify::PolicySpec,
    /// What the walk may not exceed (D10).
    budgets: portable::Budgets,
    /// Who the ref writes are recorded as.
    actor: gitiup_host::Actor,
    /// The arrival clock. Recorded, never believed (D5 clause 1).
    now_us: i64,
    /// Why a missing subject is excused, in the operator's own words, if it is excused
    /// at all (D9: the excuse is printed and recorded, never a silent blank).
    excuse: Option<String>,
    /// Everything the source advertises, indexed for the walk.
    index: Index,
    /// The starting points: attestation refs, after `--commit`/`--change`.
    candidates: Vec<Found>,
    /// `--change`, when one was named.
    change: Option<String>,
    /// `--json`: the report as data, and nothing else on stdout.
    json: bool,
    /// The commits a named change's attempts propose.
    heads: BTreeSet<String>,
}

impl Run {
    /// Read the flags, open both stores, and work out what could be imported.
    fn open(args: &Args) -> Result<Run, CliError> {
        let config = gitiup_host::Config::load_default()
            .map_err(|e| CliError::io(format!("gitiup.toml: {e}")))?;
        let from_name = args.get("--from").ok_or_else(|| {
            CliError::refused(
                "no source was named",
                "say where the proofs come from: --from <name|dir> — a [[remote]] in \
                 gitiup.toml or a directory (`gitiup doctor --remotes` lists the remotes)",
            )
        })?;
        // The destination may be spelled three ways because every other write verb
        // spells it at least one of them, but it may not be *omitted*: an import files
        // signed evidence somewhere, and "somewhere" must not be a guess.
        let to_name = args
            .get("--to")
            .or_else(|| args.get("--store"))
            .or_else(|| args.get("--remote"))
            .ok_or_else(|| {
                CliError::refused(
                    "no destination was named",
                    "an import writes, so name the store: --to <name|dir> (or --store / \
                     --remote). Nothing was read and nothing was written",
                )
            })?;
        let from = fetch::open_side(from_name, &config)?;
        let to = fetch::open_side(to_name, &config)?;
        if from.what == to.what {
            return Err(CliError::refused(
                format!(
                    "the source and the destination are the same store ({})",
                    from.what
                ),
                "an import into the store it reads from would only prove that a store can \
                 read its own listing",
            ));
        }

        let mut budgets = portable::Budgets::standard();
        if let Some(text) = args.get("--max-records") {
            budgets.records = text
                .parse()
                .map_err(|_| CliError::usage(format!("--max-records '{text}' is not a count")))?;
        }
        if let Some(text) = args.get("--max-depth") {
            budgets.depth = text
                .parse()
                .map_err(|_| CliError::usage(format!("--max-depth '{text}' is not a count")))?;
        }
        if let Some(text) = args.get("--max-policy-chain") {
            budgets.policy_chain = text.parse().map_err(|_| {
                CliError::usage(format!("--max-policy-chain '{text}' is not a count"))
            })?;
        }
        if let Some(text) = args.get("--max-bytes") {
            budgets.bytes = fetch::human_bytes(text)?;
        }
        let actor = match args.get("--actor") {
            Some(name) => gitiup_host::Actor::new(name)
                .map_err(|e| CliError::usage(format!("--actor '{name}': {e}")))?,
            None => gitiup_host::Actor::from_env(),
        };
        // The excuse, if there is one, and whose words it is in. `--proofs-only` implies
        // it because evidence-without-code *is* the use case D9 excuses for.
        let excuse = if args.on("--proofs-only") {
            Some("--proofs-only implies --allow-missing-subject".to_string())
        } else if args.on("--allow-missing-subject") {
            Some("--allow-missing-subject".to_string())
        } else {
            None
        };

        let spec = verify::policy_spec(args)?;
        let index = Index::scan(&*from.host)?;
        let commit = match args.get("--commit") {
            Some(text) => Some(subject(text)?),
            None => None,
        };
        let change = args.get("--change").map(|text| text.to_string());
        let heads = match &change {
            Some(id) => change_heads(&*from.host, id)?,
            None => BTreeSet::new(),
        };
        let candidates: Vec<Found> = index
            .refs
            .iter()
            .filter(|found| found.kind == Kind::Attestation)
            .filter(|found| match &commit {
                Some(oid) => subject_of(&found.reference).is_some_and(|hex| hex == oid.hex()),
                None => true,
            })
            .cloned()
            .collect();
        Ok(Run {
            from: from.host,
            from_what: from.what,
            to: to.host,
            to_what: to.what,
            spec,
            budgets,
            actor,
            now_us: gitiup_attest::TimeUs::now().as_us(),
            excuse,
            index,
            candidates,
            change,
            heads,
            json: args.json(),
        })
    }
}

/// The object an attestation is about, in any spelling a shell produces.
fn subject(text: &str) -> Result<Oid, CliError> {
    let text = text.trim();
    let hex = match text.split_once(':') {
        Some((_, hex)) => hex,
        None => text,
    };
    Oid::from_hex(hex).map_err(|e| CliError::usage(format!("--commit '{text}' is not an oid: {e}")))
}

/// The `<subject>` hex of a `refs/attestations/<subject>/<digest>` ref, if it has one.
fn subject_of(reference: &str) -> Option<String> {
    let rest = reference.strip_prefix("refs/attestations/")?;
    let first = rest.split('/').next()?;
    Oid::from_hex(first).ok().map(|oid| oid.hex())
}

/// The commits one change's attempts propose, which is what `--change` means for proofs:
/// the change and the evidence filed for the commits it proposes arrive together.
fn change_heads(host: &dyn Host, id: &str) -> Result<BTreeSet<String>, CliError> {
    use gitiup_host::RefQuery;
    use gitiup_host::change::{ChangeId, ChangeRef, record_from_bytes};
    let id = ChangeId::new(id).map_err(|e| CliError::usage(format!("--change '{id}': {e}")))?;
    let prefix = format!("refs/changes/{}", id.as_str());
    let mut out = BTreeSet::new();
    for reference in host
        .list_refs(&RefQuery::prefix(&prefix))
        .map_err(|e| CliError::io(format!("list {prefix}: {e}")))?
    {
        if !matches!(
            gitiup_host::change::parse_ref(&reference.name),
            Some(ChangeRef::Attempt { .. })
        ) {
            continue;
        }
        let Some(bytes) = host
            .get(&reference.oid)
            .map_err(|e| CliError::io(format!("read {}: {e}", reference.name)))?
        else {
            continue;
        };
        if let Ok(gitiup_host::change::StoredRecord::Change(record)) = record_from_bytes(&bytes) {
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

// ---------------------------------------------------------------------------
// what the source advertises, indexed by digest
// ---------------------------------------------------------------------------

/// What kind of record a portable ref advertises.
///
/// The kinds are the portable table's (`portable.json`'s `kind` column), split where the
/// table groups two record types that the closure has to tell apart: a commitment and the
/// reveal it promises are one row and two edges, and a withdrawal and a revocation are one
/// row and two reasons (D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Attestation,
    Change,
    Merge,
    Abandon,
    Roster,
    Revocation,
    Withdrawal,
    Round,
    Reveal,
    Commitment,
    Verdict,
    Policy,
}

impl Kind {
    /// The word a report prints.
    fn as_str(self) -> &'static str {
        match self {
            Kind::Attestation => "attestation",
            Kind::Change => "change",
            Kind::Merge => "merge",
            Kind::Abandon => "abandon",
            Kind::Roster => "roster_epoch",
            Kind::Revocation => "revocation",
            Kind::Withdrawal => "withdrawal",
            Kind::Round => "round",
            Kind::Reveal => "reveal",
            Kind::Commitment => "commitment",
            Kind::Verdict => "verdict",
            Kind::Policy => "policy_revision",
        }
    }

    /// Which row of the portable table this ref sits in, refined by namespace.
    ///
    /// `None` is an answer too: the ref is not in the portable set, so it is not a
    /// candidate, not an edge, and not this verb's business.
    fn of(reference: &str) -> Option<Kind> {
        let name = gitiup_host::RefName::new(reference).ok()?;
        let decision = portable::classify(&name);
        if !decision.portable {
            return None;
        }
        // Two rows of the table cover two record types each, and the walk needs them
        // apart, so the namespace decides and the table's kind is only the coarse answer.
        let path = reference.strip_prefix("refs/gitiup/").unwrap_or(reference);
        let kind = match decision.kind()? {
            "attestation" => Kind::Attestation,
            "change" => Kind::Change,
            "merge" => Kind::Merge,
            "abandon" => Kind::Abandon,
            "roster" => Kind::Roster,
            "round" => Kind::Round,
            "verdict" => Kind::Verdict,
            "policy" => Kind::Policy,
            "revocation" => {
                if path.starts_with("withdrawal/") {
                    Kind::Withdrawal
                } else {
                    Kind::Revocation
                }
            }
            "reveal" => {
                if path.starts_with("commit/") {
                    Kind::Commitment
                } else {
                    Kind::Reveal
                }
            }
            _ => return None,
        };
        Some(kind)
    }
}

/// One portable record the source advertises.
#[derive(Debug, Clone)]
struct Found {
    /// The ref advertising it, as the source spells it.
    reference: String,
    /// The digest the ref names — which is the digest its bytes hash to, checked on the
    /// way in by the copy this feeds and checked again here before anything is trusted.
    digest: Oid,
    kind: Kind,
}

/// The source's own advertisement, indexed by digest.
///
/// This is what a citation is answered with: a `round_digest` is only an edge if some ref
/// at the source names those bytes, and "no ref names them" is `closure_incomplete`,
/// which is a different fact — and a different repair — from "the bytes are not there".
struct Index {
    /// Every portable ref the source advertises, sorted by name.
    refs: Vec<Found>,
    /// digest → the refs naming it.
    by_digest: BTreeMap<String, Vec<Found>>,
}

impl Index {
    fn scan(host: &dyn Host) -> Result<Index, CliError> {
        use gitiup_host::RefQuery;
        // Listed one namespace at a time, exactly like the copy does, for the same reason:
        // a forge hides `refs/gitiup/**` from a bare listing on purpose, and a walk that
        // asked for everything would silently find no rounds, no verdicts and no epochs
        // and then report that the source had none (ADR-0005 D15).
        let mut refs = Vec::new();
        for prefix in ["refs/attestations/", "refs/changes/", "refs/gitiup/"] {
            let listing = host
                .list_refs(&RefQuery::prefix(prefix))
                .map_err(|e| CliError::io(format!("list {prefix}: {e}")))?;
            for reference in listing {
                let text = reference.name.as_str().to_string();
                let Some(kind) = Kind::of(&text) else {
                    continue;
                };
                refs.push(Found {
                    reference: text,
                    digest: reference.oid,
                    kind,
                });
            }
        }
        refs.sort_by(|a, b| a.reference.cmp(&b.reference));
        let mut by_digest: BTreeMap<String, Vec<Found>> = BTreeMap::new();
        for found in &refs {
            by_digest
                .entry(found.digest.hex())
                .or_default()
                .push(found.clone());
        }
        Ok(Index { refs, by_digest })
    }

    /// The refs advertising one digest, if any.
    fn named(&self, digest: &Oid) -> Option<&Vec<Found>> {
        self.by_digest.get(&digest.hex())
    }

    /// Whether anything is advertised under a prefix — how a "this must not be empty"
    /// edge (a round's reveals) is answered without parsing the name.
    fn under(&self, prefix: &str) -> Vec<Found> {
        self.refs
            .iter()
            .filter(|found| found.reference.starts_with(prefix))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// the closure walk (ADR-0005 D9)
// ---------------------------------------------------------------------------

/// The sentence for a policy digest that is answered by the round that pins it.
pub(crate) const POLICY_INSIDE_ROUND: &str = "the selection policy is inside the round record that cites it, under the selector's \
     signature";
/// The sentence for a verdict the import recomputes rather than copies.
pub(crate) const VERDICT_REDERIVED: &str = "the verdict is recomputed here from the round, the roster epoch and the reveals in \
     this closure, by the code `gitiup quorum verdict` runs";

/// One citation a record carries.
enum Edge {
    /// A record, cited by digest. `name` is D9's edge name, printed when it has no foot.
    Record { name: &'static str, digest: Oid },
    /// A digest the citing document accounts for without a ref naming it.
    ///
    /// There are exactly two of these, and each is only honest because of the sentence in
    /// `satisfied`:
    ///
    /// * a round's `policy_digest` names the selection policy, which is *inside* the round
    ///   record and covered by the selector's signature — `Round::verify` refuses a round
    ///   whose `policy_digest` is not the digest of the policy in its own inputs;
    /// * a `tier: quorum` attestation's `verdict_digest` names a verdict, and a verdict is
    ///   a pure function of the round, the roster epoch and the reveals this closure
    ///   already carries. The judge step re-derives it with the same code `gitiup quorum
    ///   verdict` runs and refuses the document unless the answer matches — so the verdict
    ///   is not assumed, it is recomputed here (its own `issued_at_us` is why its *bytes*
    ///   cannot be expected to match a digest across a clock change, and why the check is
    ///   of what it concludes and not of its hash).
    ///
    /// Where the source does advertise such a record it is carried like any other, so a
    /// store that filed its verdicts gets the filed one copied. `satisfied: None` means
    /// there is no such account to give, and the edge is then a hard one.
    Derived {
        name: &'static str,
        digest: Oid,
        satisfied: Option<&'static str>,
    },
    /// A set of refs that must not be empty: a round's reveals, a sealed round's
    /// commitments. Named by prefix because a job id is not one path segment.
    Group {
        name: &'static str,
        prefix: String,
        /// The token to refuse with when the set is empty, which is `no_commitment` for
        /// one specific edge and `closure_incomplete` for every other.
        token: &'static str,
    },
    /// The object a proof is about. Not a record, and the only edge with an excuse (D9).
    Subject { name: &'static str, digest: Oid },
}

/// A refusal that stops one record's import, and nothing else.
#[derive(Debug, Clone)]
struct Refusal {
    /// The ref this refusal is about, when one was named. Boxed so the `Err` half of the
    /// many `Result`s in this module stays small — the workspace keeps clippy clean, and a
    /// 152-byte error inside every `Result<Vec<_>, Refusal>` is how a hot path starts
    /// copying a refusal it was only going to discard.
    reference: Option<Box<str>>,
    digest: Option<Box<str>>,
    token: String,
    exit: u8,
    detail: String,
    hint: Option<Box<str>>,
}

impl Refusal {
    fn new(token: &str, exit: u8, detail: impl Into<String>) -> Refusal {
        Refusal {
            reference: None,
            digest: None,
            token: token.to_string(),
            exit,
            detail: detail.into(),
            hint: None,
        }
    }

    fn with_reference(mut self, reference: &str) -> Refusal {
        self.reference = Some(reference.into());
        self
    }

    fn with_digest(mut self, digest: &Oid) -> Refusal {
        self.digest = Some(digest.hex().into());
        self
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Refusal {
        self.hint = Some(hint.into().into_boxed_str());
        self
    }

    /// A refusal that outranks a scope refusal: an integrity failure always fails the
    /// command, because a store that "succeeded" past one now contains it (D10).
    fn integrity(&self) -> bool {
        self.exit >= 7
    }
}

// ---------------------------------------------------------------------------
// the walk
// ---------------------------------------------------------------------------

/// What one closure established: the records that must travel together, and what was
/// excused on the way.
struct Closure {
    /// Every record the start cites, transitively, start included.
    records: Vec<Found>,
    /// How many hops it took (D10's `--max-depth`).
    depth: usize,
    /// Subjects that were absent and excused, each with the edge that asked for it.
    excused: Vec<String>,
    /// Subjects that were present, in the report's words.
    subjects: usize,
    /// Edges with no ref in the source that were satisfied by derivation instead, each
    /// with the sentence that says what that means (D9: the report says how the closure
    /// closed; it does not merely conclude that it did).
    derived: Vec<String>,
}

impl Run {
    /// The verification closure of one record (D9): follow the citations the records
    /// themselves carry, and refuse the moment an edge has no foot.
    ///
    /// The unit is *record plus its closure*: a walk that ended in a partial import would
    /// produce a store where a `tier: quorum` attestation is filed and its verdict is not,
    /// which is the state the ADR calls "a mirror missing half of what it serves while
    /// looking complete".
    fn closure(&self, start: &Found) -> Result<Closure, Refusal> {
        let mut queue: std::collections::VecDeque<(Found, usize)> =
            std::collections::VecDeque::from([(start.clone(), 0usize)]);
        let mut taken: BTreeMap<String, Found> = BTreeMap::new();
        taken.insert(start.reference.clone(), start.clone());
        let mut seen: BTreeSet<String> = BTreeSet::new();
        seen.insert(start.digest.hex());
        let mut bytes: u64 = 0;
        let mut depth = 0usize;
        let mut excused: Vec<String> = Vec::new();
        let mut subjects = 0usize;
        let mut derived: Vec<String> = Vec::new();

        while let Some((node, hop)) = queue.pop_front() {
            depth = depth.max(hop);
            let body = self.read(&node)?;
            bytes += body.len() as u64;
            if bytes > self.budgets.bytes {
                return Err(Refusal::new(
                    "closure_budget_bytes",
                    6,
                    format!(
                        "this closure would read more than the {} bytes an import may read; \
                         refused rather than truncated",
                        self.budgets.bytes
                    ),
                )
                .with_hint(
                    "`--max-bytes 500m` raises the bound; a budget is a refusal, never \
                           a truncation, so a stopped import is never mistaken for a \
                           complete one",
                ));
            }
            for edge in self.edges(&node, &body)? {
                match edge {
                    Edge::Record { name, digest } => {
                        let Some(found) =
                            self.index.named(&digest).and_then(|v| v.first().cloned())
                        else {
                            return Err(closure_incomplete(&node, name, &digest, &self.from_what));
                        };
                        if seen.insert(digest.hex()) {
                            self.admit(&mut taken, &mut queue, found, hop)?;
                        }
                    }
                    Edge::Derived {
                        name,
                        digest,
                        satisfied,
                    } => {
                        if let Some(found) =
                            self.index.named(&digest).and_then(|v| v.first().cloned())
                        {
                            if seen.insert(digest.hex()) {
                                self.admit(&mut taken, &mut queue, found, hop)?;
                            }
                            continue;
                        }
                        if let Some(because) = satisfied {
                            derived.push(format!("{name} — {because}"));
                            continue;
                        }
                        return Err(closure_incomplete(&node, name, &digest, &self.from_what));
                    }
                    Edge::Group {
                        name,
                        prefix,
                        token,
                    } => {
                        let founds = self.index.under(&prefix);
                        if founds.is_empty() {
                            return Err(Refusal::new(
                                token,
                                6,
                                format!(
                                    "{} cites {name} under {prefix} and the source advertises \
                                     nothing there",
                                    node.reference
                                ),
                            )
                            .with_reference(&node.reference)
                            .with_digest(&node.digest)
                            .with_hint(match token {
                                "no_commitment" => {
                                    "a sealed round is only believed with the \
                                                    promises it opens; carry refs/gitiup/commit/** \
                                                    with its reveals, or do not import the reveals"
                                }
                                _ => {
                                    "fetch the namespace the citation names; a proof whose \
                                                     evidence is absent is a rumour (ADR-0005 D9)"
                                }
                            }));
                        }
                        for found in founds {
                            if seen.insert(found.digest.hex()) {
                                self.admit(&mut taken, &mut queue, found, hop)?;
                            }
                        }
                    }
                    Edge::Subject { name, digest } => {
                        if self.subject_present(&digest) {
                            subjects += 1;
                            continue;
                        }
                        match &self.excuse {
                            Some(why) => excused.push(format!("{name} {} ({why})", digest.hex())),
                            None => {
                                return Err(Refusal::new(
                                    "subject_missing",
                                    6,
                                    format!(
                                        "{} is about {name} {}, which {} cannot name",
                                        node.reference,
                                        digest.short_default(),
                                        self.to_what
                                    ),
                                )
                                .with_reference(&node.reference)
                                .with_digest(&digest)
                                .with_hint(
                                    "code travels by `gitiup fetch`, which carries a pack; an \
                                     attestation about an object you have not imported is a \
                                     claim about nothing — or say so out loud with \
                                     --allow-missing-subject",
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(Closure {
            records: taken.into_values().collect(),
            depth,
            excused,
            subjects,
            derived,
        })
    }

    /// Put one more record in the closure, under the budgets (D10).
    fn admit(
        &self,
        taken: &mut BTreeMap<String, Found>,
        queue: &mut std::collections::VecDeque<(Found, usize)>,
        found: Found,
        hop: usize,
    ) -> Result<(), Refusal> {
        if hop + 1 > self.budgets.depth {
            return Err(Refusal::new(
                "closure_budget_depth",
                6,
                format!(
                    "the closure reaches past {} hops at {}",
                    self.budgets.depth, found.reference
                ),
            )
            .with_hint(
                "a proof's evidence is a short chain, not a graph; `--max-depth` raises \
                        the bound and a refusal is not a truncation",
            ));
        }
        if taken.len() + 1 > self.budgets.records {
            return Err(Refusal::new(
                "closure_budget_records",
                6,
                format!(
                    "this import would take more than the {} records a run may take",
                    self.budgets.records
                ),
            )
            .with_hint("`--max-records` raises the bound"));
        }
        taken.insert(found.reference.clone(), found.clone());
        queue.push_back((found, hop + 1));
        Ok(())
    }

    /// The citations one record carries, read out of the record itself.
    ///
    /// Nothing here invents an edge: every one of them is a signed field of a document
    /// (`round_digest`, `roster_digest`, `policy_digest`, `previous_digest`, `proofs[]`),
    /// which is what makes the closure auditable by somebody who was not there.
    fn edges(&self, node: &Found, body: &[u8]) -> Result<Vec<Edge>, Refusal> {
        let bad = |what: &str| {
            Refusal::new(
                "not_canonical",
                8,
                format!(
                    "{} is advertised as a {} and its bytes are not a {} this build can read: {what}",
                    node.reference,
                    node.kind.as_str(),
                    node.kind.as_str()
                ),
            )
            .with_reference(&node.reference)
            .with_digest(&node.digest)
        };
        Ok(match node.kind {
            Kind::Attestation => self.attestation_edges(node, body)?,
            Kind::Verdict => {
                let record: gitiup_quorum::verdict::VerdictRecord =
                    gitiup_quorum::record::from_canonical_bytes(body)
                        .map_err(|e| bad(&e.to_string()))?;
                vec![
                    Edge::Record {
                        name: "round_digest",
                        digest: oid(&record.round_digest),
                    },
                    Edge::Record {
                        name: "roster_digest",
                        digest: oid(&record.roster_digest),
                    },
                    Edge::Derived {
                        name: "policy_digest",
                        digest: oid(&record.policy_digest),
                        satisfied: self
                            .round_names_policy(&record.round_digest, &record.policy_digest)
                            .then_some(POLICY_INSIDE_ROUND),
                    },
                ]
            }
            Kind::Round => {
                let round: gitiup_quorum::round::Round =
                    gitiup_quorum::record::from_canonical_bytes(body)
                        .map_err(|e| bad(&e.to_string()))?;
                let mut edges = vec![
                    Edge::Record {
                        name: "roster_digest",
                        digest: oid(&round.inputs.roster_digest),
                    },
                    // The selection policy the round pins is inside the round, covered by
                    // the selector's signature, so it is evidence in hand and not a ref to
                    // chase. A store that *also* advertises those bytes gets them carried.
                    Edge::Derived {
                        name: "policy_digest",
                        digest: oid(&round.policy_digest),
                        satisfied: round
                            .inputs
                            .policy
                            .digest()
                            .is_ok_and(|digest| digest == round.policy_digest)
                            .then_some(POLICY_INSIDE_ROUND),
                    },
                ];
                edges.extend(self.round_evidence(&node.reference, &round)?);
                edges
            }
            Kind::Reveal => {
                // A slot's ref is `<change>/<job>/<slot>`; the attempt is not in it, so the
                // round a reveal answers is not nameable from the reveal alone — and does
                // not need to be, because a reveal only ever enters a closure through the
                // round that cites it, and that round is already in here by construction.
                // What a reveal still owes, when the round seals, is the promise it opens:
                // a reveal with no commitment behind it is the evidence sealing exists to
                // catch, and an import that copied one without the other would be filing
                // half of a discrepancy.
                let address = sibling(&node.reference, "reveal")?;
                let address = address.split('/').take(2).collect::<Vec<_>>().join("/");
                let slot = node.reference.rsplit('/').next().unwrap_or_default();
                let sealed = self
                    .index
                    .under(&format!("refs/gitiup/round/{address}/"))
                    .into_iter()
                    .filter_map(|found| {
                        let body = self.read(&found).ok()?;
                        let round: gitiup_quorum::round::Round =
                            gitiup_quorum::record::from_canonical_bytes(&body).ok()?;
                        Some(round.is_sealed())
                    })
                    .any(|sealed| sealed);
                if sealed {
                    vec![Edge::Group {
                        name: "the commitment it opens",
                        prefix: format!("refs/gitiup/commit/{address}/{slot}"),
                        token: "no_commitment",
                    }]
                } else {
                    Vec::new()
                }
            }
            Kind::Commitment => {
                // A promise is a leaf: it opens onto nothing but the reveal it matches,
                // which is only in the closure when there is one, and whose absence the
                // verdict itself records.
                Vec::new()
            }
            Kind::Roster => {
                let roster: gitiup_quorum::roster::Roster =
                    gitiup_quorum::record::from_canonical_bytes(body)
                        .map_err(|e| bad(&e.to_string()))?;
                let keys: BTreeSet<String> = roster
                    .entries
                    .iter()
                    .map(|entry| entry.key_id.clone())
                    .collect();
                let mut edges = Vec::new();
                for kind in [Kind::Revocation, Kind::Withdrawal] {
                    for found in self.index.refs.iter().filter(|f| f.kind == kind) {
                        let Ok(body) = self.read(found) else { continue };
                        let key = match kind {
                            Kind::Revocation => gitiup_quorum::record::from_canonical_bytes::<
                                gitiup_quorum::roster::Revocation,
                            >(&body)
                            .ok()
                            .map(|r| r.key_id),
                            _ => gitiup_quorum::record::from_canonical_bytes::<
                                gitiup_quorum::roster::Withdrawal,
                            >(&body)
                            .ok()
                            .map(|w| w.key_id),
                        };
                        // Only the ones this epoch's keys are entangled with: a mirror is
                        // not obliged to carry a stranger's whole revocation log (D9 names
                        // "the revocations naming any seated key").
                        if key.is_some_and(|key| keys.contains(&key)) {
                            edges.push(Edge::Record {
                                name: if kind == Kind::Revocation {
                                    "revocation"
                                } else {
                                    "withdrawal"
                                },
                                digest: found.digest,
                            });
                        }
                    }
                }
                edges
            }
            Kind::Policy => {
                let document: gitiup_quorum::policy::PolicyDocument =
                    gitiup_quorum::record::from_canonical_bytes(body)
                        .map_err(|e| bad(&e.to_string()))?;
                self.policy_chain(node, &document)?
            }
            Kind::Change => {
                let record = gitiup_host::change::record_from_bytes(body)
                    .map_err(|e| bad(&e.to_string()))?;
                let gitiup_host::change::StoredRecord::Change(change) = record else {
                    return Err(bad(
                        "the ref says attempt, the bytes are not a change record",
                    ));
                };
                let mut edges = vec![
                    Edge::Subject {
                        name: "base",
                        digest: subject_digest(&change.base.oid)?,
                    },
                    Edge::Subject {
                        name: "head",
                        digest: subject_digest(&change.head)?,
                    },
                ];
                if let Some(previous) = &change.attempts.previous {
                    edges.push(Edge::Record {
                        name: "attempts.previous",
                        digest: subject_digest(previous)?,
                    });
                }
                edges
            }
            Kind::Merge => {
                let record = gitiup_host::change::record_from_bytes(body)
                    .map_err(|e| bad(&e.to_string()))?;
                let gitiup_host::change::StoredRecord::Merge(merge) = record else {
                    return Err(bad("the ref says merged, the bytes are not a merge record"));
                };
                let mut edges = vec![Edge::Record {
                    name: "the change merged",
                    digest: subject_digest(&merge.change_digest)?,
                }];
                for proof in &merge.proofs {
                    edges.push(Edge::Record {
                        name: "the proof it says it believed",
                        digest: subject_digest(proof)?,
                    });
                }
                edges
            }
            // A revocation or a withdrawal names a *key*, and the epoch that key sits in
            // is reached from the roster side (D9's roster row), so these are leaves: they
            // carry no citation of their own to follow.
            Kind::Revocation | Kind::Withdrawal => Vec::new(),
            Kind::Abandon => {
                let record = gitiup_host::change::record_from_bytes(body)
                    .map_err(|e| bad(&e.to_string()))?;
                let gitiup_host::change::StoredRecord::Abandon(abandon) = record else {
                    return Err(bad(
                        "the ref says abandoned, the bytes are not an abandon record",
                    ));
                };
                vec![Edge::Record {
                    name: "the change closed",
                    digest: subject_digest(&abandon.change_digest)?,
                }]
            }
        })
    }

    /// Read the round record a digest names, if the source advertises one.
    fn round_of(&self, digest: &Oid) -> Option<gitiup_quorum::round::Round> {
        let found = self.index.named(digest)?.first()?.clone();
        let body = self.read(&found).ok()?;
        gitiup_quorum::record::from_canonical_bytes(&body).ok()
    }

    /// Whether a round pins the policy a verdict cites it on — the case where the policy
    /// is evidence in hand (inside the round) rather than a ref to chase.
    fn round_names_policy(
        &self,
        round: &gitiup_attest::Digest,
        policy: &gitiup_attest::Digest,
    ) -> bool {
        self.round_of(&oid(round))
            .is_some_and(|round| round.policy_digest == *policy)
    }

    /// The reveals and commitments filed for one round, by the ref it sits under.
    ///
    /// Taken as a set rather than seat by seat: the losing ballots are evidence too — a
    /// verdict prints its `divergent[]` results, and a mirror that carried only the
    /// winning seats has edited the record it claims to copy.
    fn round_evidence(
        &self,
        reference: &str,
        round: &gitiup_quorum::round::Round,
    ) -> Result<Vec<Edge>, Refusal> {
        // `refs/gitiup/round/<change>/<job>/<attempt>`, and the slots hang off the first
        // two of those: a reveal is `<change>/<job>/<slot>`, with no attempt segment, so
        // the attempt has to come off before the prefix is built.
        let rest = sibling(reference, "round")?;
        let address = rest.split('/').take(2).collect::<Vec<_>>().join("/");
        let mut edges = vec![Edge::Group {
            name: "the seats that voted",
            prefix: format!("refs/gitiup/reveal/{address}/"),
            token: "closure_incomplete",
        }];
        // Only a sealed round made promises. An open round's seats revealed straight away,
        // and demanding a `commit` ref that was never written would refuse every open round
        // in existence — which is a rule about the format, not about this copy.
        if round.is_sealed() {
            edges.push(Edge::Group {
                name: "the promises the seats made",
                prefix: format!("refs/gitiup/commit/{address}/"),
                token: "no_commitment",
            });
        }
        Ok(edges)
    }

    /// A policy's own chain: linear, its own budget, and a missing predecessor is
    /// ADR-0004 D6's `policy_history_missing` and not a closure gap, because the two have
    /// different repairs (one is "this store was copied badly", the other is "nobody ever
    /// published the predecessor").
    fn policy_chain(
        &self,
        node: &Found,
        document: &gitiup_quorum::policy::PolicyDocument,
    ) -> Result<Vec<Edge>, Refusal> {
        let mut edges = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        seen.insert(node.digest.hex());
        let mut previous = document.previous_digest.clone();
        let mut chain = 1usize;
        while previous != gitiup_quorum::policy::GENESIS_PREVIOUS {
            let hex = hex_of(&previous);
            let Ok(digest) = Oid::from_hex(&hex) else {
                return Err(Refusal::new(
                    "policy_history_missing",
                    6,
                    format!(
                        "{} names a predecessor that is not a digest ({previous})",
                        node.reference
                    ),
                )
                .with_reference(&node.reference));
            };
            if !seen.insert(digest.hex()) {
                return Err(Refusal::new(
                    "policy_history_missing",
                    6,
                    format!(
                        "{}'s chain walks back into itself at {}",
                        node.reference,
                        digest.short_default()
                    ),
                )
                .with_reference(&node.reference));
            }
            if self.index.named(&digest).is_none() {
                return Err(Refusal::new(
                    "policy_history_missing",
                    6,
                    format!(
                        "{} is revision {} and its predecessor {previous} is not advertised at {}",
                        node.reference, document.revision, self.from_what
                    ),
                )
                .with_reference(&node.reference)
                .with_hint(
                    "which rules were in force then has no answer without the chain \
                     (ADR-0004 D6); carry refs/gitiup/policy/history/** with the current policy",
                ));
            }
            if chain + 1 > self.budgets.policy_chain {
                return Err(Refusal::new(
                    "policy_chain_too_long",
                    6,
                    format!(
                        "the policy chain is longer than the {} revisions an import walks",
                        self.budgets.policy_chain
                    ),
                )
                .with_hint(
                    "`--max-policy-chain` raises the bound; a chain that outlives its \
                            own verifiability is the thing this budget refuses",
                ));
            }
            chain += 1;
            edges.push(Edge::Record {
                name: "previous_digest",
                digest,
            });
            // Keep walking: the predecessor's own predecessor is the next question.
            let found = self
                .index
                .named(&digest)
                .and_then(|v| v.first().cloned())
                .expect("presence was just checked above");
            let body = self.read(&found)?;
            let Ok(next) = gitiup_quorum::record::from_canonical_bytes::<
                gitiup_quorum::policy::PolicyDocument,
            >(&body) else {
                break;
            };
            previous = next.previous_digest.clone();
        }
        Ok(edges)
    }

    /// Read one record's bytes, and refuse anything that is not what its name says.
    ///
    /// The re-hash is not paranoia about this particular host: it is the step that makes a
    /// *transport* that re-canonicalises impossible rather than merely discouraged (D7),
    /// and it happens before the bytes are parsed into anything.
    fn read(&self, node: &Found) -> Result<Vec<u8>, Refusal> {
        let bytes = match self.from.get(&node.digest) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(Refusal::new(
                    "closure_incomplete",
                    6,
                    format!(
                        "{} advertises {} and the source cannot return its bytes",
                        node.reference,
                        node.digest.short_default()
                    ),
                )
                .with_reference(&node.reference)
                .with_digest(&node.digest)
                .with_hint(
                    "a ref naming bytes its store cannot return is the failure \
                           ADR-0005 D8 rule 1 exists to prevent",
                ));
            }
            Err(error) => {
                return Err(Refusal::new(
                    "closure_incomplete",
                    6,
                    format!(
                        "the source could not return {}: {error}",
                        node.digest.short_default()
                    ),
                )
                .with_reference(&node.reference)
                .with_digest(&node.digest));
            }
        };
        let hashed = Oid::hash_bytes(&bytes);
        if hashed != node.digest {
            return Err(Refusal::new(
                "digest_mismatch",
                8,
                format!(
                    "{} advertises {} and its bytes hash to {}",
                    node.reference,
                    node.digest.short_default(),
                    hashed.short_default()
                ),
            )
            .with_reference(&node.reference)
            .with_digest(&node.digest)
            .with_hint("nothing is written behind a digest mismatch, and nothing was"));
        }
        Ok(bytes)
    }

    /// Whether the importing store can name the object a proof is about.
    ///
    /// Deliberately humble: this asks *this store*, not the federation, and a store with
    /// no git object database honestly answers "no" — which is why the excuse is the
    /// operator's sentence and not this code's guess. Code travels by
    /// [`gitiup fetch`]'s pack step, and the hint says so.
    fn subject_present(&self, digest: &Oid) -> bool {
        if self.index.named(digest).is_some() {
            // The subject is itself a portable record, so the walk is carrying it.
            return true;
        }
        self.to.head(digest).ok().flatten().is_some()
    }
}

/// The digest of a citation, as the store names it.
fn oid(digest: &gitiup_attest::Digest) -> Oid {
    // A `Digest`'s hex is already the store's spelling: bare, lower-case, and the same
    // bytes the ref leaf repeats.
    Oid::from_hex(&digest.hex())
        .expect("a digest's own hex is by construction a digest this store can name")
}

/// A digest spelled `sha256:…`, `sha1:…` or bare hex, as a store object id.
fn subject_digest(text: &str) -> Result<Oid, Refusal> {
    Oid::from_hex(&hex_of(text)).map_err(|e| {
        Refusal::new(
            "binding_mismatch",
            8,
            format!("a record cited '{text}' as an object, which is not an object id: {e}"),
        )
    })
}

/// `<kind>/<change>/<job>/<tail…>` with the first component swapped, for the edges that
/// live beside a record rather than being named by it (a round and its reveals share a
/// change and a job, and a job id is not one path segment).
fn sibling(reference: &str, from: &str) -> Result<String, Refusal> {
    let prefix = format!("refs/gitiup/{from}/");
    let rest = reference.strip_prefix(&prefix).ok_or_else(|| {
        Refusal::new(
            "closure_incomplete",
            6,
            format!("{reference} is not under {prefix}, so its sibling refs cannot be named"),
        )
        .with_reference(reference)
    })?;
    Ok(rest.to_string())
}

/// The refusal every absent edge makes, in D9's own words: the record type and the edge.
fn closure_incomplete(node: &Found, edge: &str, digest: &Oid, from: &str) -> Refusal {
    Refusal::new(
        "closure_incomplete",
        6,
        format!(
            "{} is a {} that cites {edge} at {}; {} advertises no ref for those bytes",
            node.reference,
            node.kind.as_str(),
            digest.short_default(),
            from
        ),
    )
    .with_reference(&node.reference)
    .with_digest(digest)
    .with_hint(
        "a record is imported with its closure or not at all (ADR-0005 D9): fetch the \
         namespace the citation names, or import the record that cites it from a store that \
         has it",
    )
}

// ---------------------------------------------------------------------------
// the attestation edges, and the verdict
// ---------------------------------------------------------------------------

use gitiup_attest::{ErrorKind, Tier};
use gitiup_quorum::attestation::{QuorumAttestation, rederive};
use gitiup_quorum::record::Record as _;

impl Run {
    /// What one attestation cites.
    ///
    /// A run attestation cites its subject and, if the store publishes a policy history,
    /// the revision that was in force when it was claimed; a `tier: quorum` attestation
    /// cites the verdict it restates and, through it, everything the verdict leans on.
    fn attestation_edges(&self, node: &Found, body: &[u8]) -> Result<Vec<Edge>, Refusal> {
        if QuorumAttestation::looks_like(body) {
            let quorum = QuorumAttestation::load(body).map_err(|error| {
                Refusal::new(
                    "not_canonical",
                    6,
                    format!(
                        "{} looks like a `tier: quorum` attestation and is not one this build \
                         can read: {error}",
                        node.reference
                    ),
                )
                .with_reference(&node.reference)
                .with_digest(&node.digest)
            })?;
            return Ok(vec![
                Edge::Derived {
                    name: "verdict_digest",
                    digest: oid(&quorum.verdict_digest),
                    // A bare `gitiup fetch --commit <oid>` copies this document and not the
                    // verdict it belongs to, and it copies neither the round nor the
                    // reveals either — which is the case the rule is about. The round, the
                    // roster and the reveals are hard edges; a verdict this build can
                    // recompute from them is not a rumour, and one it cannot is refused by
                    // the judge step that follows this walk.
                    satisfied: Some(VERDICT_REDERIVED),
                },
                Edge::Record {
                    name: "round_digest",
                    digest: oid(&quorum.round_digest),
                },
                Edge::Record {
                    name: "roster_digest",
                    digest: oid(&quorum.roster_digest),
                },
                Edge::Derived {
                    name: "policy_digest",
                    digest: oid(&quorum.policy_digest),
                    satisfied: self
                        .round_of(&oid(&quorum.round_digest))
                        .is_some_and(|round| round.policy_digest == quorum.policy_digest)
                        .then_some(POLICY_INSIDE_ROUND),
                },
            ]);
        }
        let doc = AttestationDoc::from_canonical_bytes(body).map_err(|error| {
            Refusal::new(
                "not_canonical",
                error.kind().exit_code(),
                format!(
                    "{} is not an attestation this build can read: {error}",
                    node.reference
                ),
            )
            .with_reference(&node.reference)
            .with_digest(&node.digest)
        })?;
        let mut edges = vec![Edge::Subject {
            name: "the object it is about",
            digest: subject_digest(&doc.manifest.result.source.commit.to_string())?,
        }];
        if let Some(policy) = self.policy_in_force(doc.manifest.claims.claimed_at_us) {
            edges.push(Edge::Record {
                name: "the policy revision in force",
                digest: policy,
            });
        }
        Ok(edges)
    }

    /// The published policy revision that was in force at `at`, if this store publishes a
    /// policy history at all.
    ///
    /// A store with no published policy has no answer to "which rules were in force", and
    /// the reader's own `--policy` is a different thing entirely (it is what *this* verdict
    /// was judged by, not what the project published), so the absence is no edge rather
    /// than an invented one.
    fn policy_in_force(&self, at: i64) -> Option<Oid> {
        let mut best: Option<(i64, Oid)> = None;
        for found in self
            .index
            .refs
            .iter()
            .filter(|found| found.kind == Kind::Policy)
        {
            let Ok(body) = self.read(found) else { continue };
            let Ok(document) = gitiup_quorum::record::from_canonical_bytes::<
                gitiup_quorum::policy::PolicyDocument,
            >(&body) else {
                continue;
            };
            let live = document.effective_from_us <= at
                && document.expires_at_us.is_none_or(|until| at < until);
            if live && best.is_none_or(|(from, _)| document.effective_from_us >= from) {
                best = Some((document.effective_from_us, found.digest));
            }
        }
        best.map(|(_, digest)| digest)
    }

    /// Whether a candidate is in scope for `--change`.
    fn relevant(&self, node: &Found, body: &[u8]) -> bool {
        let Some(change) = &self.change else {
            return true;
        };
        if self
            .change_heads_for(node)
            .is_some_and(|hex| self.heads.contains(&hex))
        {
            return true;
        }
        // A `tier: quorum` attestation names its change in the document, and is filed
        // under the head the round was drawn against — which is usually one of the
        // attempt heads anyway, but "usually" is not a filter.
        QuorumAttestation::looks_like(body)
            && QuorumAttestation::load(body).is_ok_and(|quorum| &quorum.change_id == change)
    }

    /// The `<subject>` hex a ref is filed under, which is where a proof about a commit
    /// says which commit it is about.
    fn change_heads_for(&self, node: &Found) -> Option<String> {
        subject_of(&node.reference)
    }

    /// Run the ladder. This is the ticket's headline: **the same checks
    /// `gitiup verify attestation` runs**, from the same code, with a policy built by the
    /// same flags — and the *only* thing in this module that produces a belief.
    fn judge(&self, node: &Found, body: &[u8]) -> Result<Judgement, Refusal> {
        if QuorumAttestation::looks_like(body) {
            let quorum = QuorumAttestation::load(body).map_err(|error| {
                Refusal::new(
                    "not_canonical",
                    6,
                    format!(
                        "{} looks like a `tier: quorum` attestation and is not one this build \
                         can read: {error}",
                        node.reference
                    ),
                )
                .with_reference(&node.reference)
                .with_digest(&node.digest)
            })?;
            let evaluation = verify::quorum_evaluation(&self.spec.policy);
            let derivation =
                match rederive(&*self.from, &quorum, &self.spec.policy.trust, &evaluation) {
                    Ok(rederived) => verify::Derivation::Done(Box::new(rederived)),
                    Err(error) => verify::Derivation::Failed(error),
                };
            let (report, _rows, json) = verify::quorum_ladder(
                &quorum,
                &verify::QuorumLadder {
                    tier_allowed: self.spec.policy.allowed_tiers.contains(&Tier::Quorum),
                    trust: &self.spec.policy.trust,
                    min_signatures: self.spec.policy.min_signatures,
                    freshness: &self.spec.policy,
                    derivation,
                    store: Some(self.from_what.clone()),
                },
            );
            return Ok(Judgement {
                tier: quorum.tier.as_str().to_string(),
                signers: quorum
                    .signatures
                    .iter()
                    .map(|entry| entry.key_id.clone())
                    .collect(),
                claimed_at_us: quorum.claimed_at_us,
                quorum: Some(json),
                report,
            });
        }
        let doc = AttestationDoc::from_canonical_bytes(body).map_err(|error| {
            // The bytes were not a document. That is not a verdict about a proof; it is the
            // store or the transport having mangled it, and the class the library gives
            // says which: 8 is "not the bytes it claims", 6 is "not a document at all".
            let token = match error.kind() {
                ErrorKind::DigestMismatch => "digest_mismatch",
                ErrorKind::UnsupportedSchema => "unsupported_schema",
                _ => "not_canonical",
            };
            Refusal::new(
                token,
                error.kind().exit_code(),
                format!(
                    "{} is not an attestation this build can read: {error}",
                    node.reference
                ),
            )
            .with_reference(&node.reference)
            .with_digest(&node.digest)
            .with_hint(error.hint().unwrap_or(
                "the bytes stored must be the canonical bytes \
                                               that were signed; anything else is a broken \
                                               store, not a weaker proof",
            ))
        })?;
        let report = doc.verify_report(&self.spec.policy);
        Ok(Judgement {
            tier: doc.manifest.result.provenance.tier.as_str().to_string(),
            signers: doc
                .signatures
                .iter()
                .map(|entry| entry.key_id.clone())
                .collect(),
            claimed_at_us: doc.manifest.claims.claimed_at_us,
            quorum: None,
            report,
        })
    }
}

/// What the ladder said about one document.
struct Judgement {
    tier: String,
    signers: Vec<String>,
    #[allow(dead_code)]
    claimed_at_us: i64,
    quorum: Option<Value>,
    report: VerdictReport,
}

impl Judgement {
    /// The refusal a failed ladder implies, in the report's vocabulary.
    ///
    /// Where an ADR-0005 D10 token names the same event it is used (`bad_signature`,
    /// `signer_untrusted`, `tier_not_allowed`, `expired`, …); where it does not, the
    /// verify check code *is* the token, because re-inventing a word for `environment`
    /// would be a second vocabulary for one fact. The exit code always comes from the
    /// ladder, never from this mapping.
    fn refusal(&self, node: &Found) -> Refusal {
        let code = self
            .report
            .primary()
            .map(|reason| reason.code)
            .unwrap_or("structure");
        let detail = self
            .report
            .primary()
            .map(|reason| reason.detail().to_string())
            .unwrap_or_else(|| "the ladder refused this document".to_string());
        let hint = self
            .report
            .primary()
            .and_then(|reason| reason.hint())
            .map(|hint| hint.to_string().into_boxed_str());
        Refusal {
            reference: Some(node.reference.clone().into_boxed_str()),
            digest: Some(node.digest.hex().into_boxed_str()),
            token: token_for_check(code).to_string(),
            exit: self.report.exit_code(),
            detail,
            hint,
        }
    }
}

/// The D10 token for a verify-ladder check code, where D10 names one.
///
/// The fallback is the check code itself: `environment` and `normalisation` are refusals
/// with no federation word, and inventing one (or stretching `signer_untrusted` to cover
/// them) would be a second vocabulary for a fact the verify report already spells.
pub(crate) fn token_for_check(code: &str) -> std::borrow::Cow<'static, str> {
    match code {
        "structure" => std::borrow::Cow::Borrowed("not_canonical"),
        "digest" => std::borrow::Cow::Borrowed("digest_mismatch"),
        "commit" | "result" | "challenge" => std::borrow::Cow::Borrowed("binding_mismatch"),
        "signature" => std::borrow::Cow::Borrowed("bad_signature"),
        "trust" | "min_signatures" => std::borrow::Cow::Borrowed("signer_untrusted"),
        "revocation" => std::borrow::Cow::Borrowed("revoked_key"),
        "tier" | "sandbox" => std::borrow::Cow::Borrowed("tier_not_allowed"),
        "freshness" | "expiry" => std::borrow::Cow::Borrowed("expired"),
        "policy" => std::borrow::Cow::Borrowed("policy_history_missing"),
        _ => std::borrow::Cow::Owned(code.to_string()),
    }
}

/// One document that passed, and what came with it.
struct Imported {
    reference: String,
    digest: Oid,
    tier: String,
    signers: Vec<String>,
    verify_exit: u8,
    /// Every record this import files: the document and its closure.
    records: Vec<Found>,
    depth: usize,
    subjects: usize,
    excused: Vec<String>,
    /// Edges with nothing to copy, and what closed them instead.
    derived: Vec<String>,
    quorum: Option<Value>,
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

impl Run {
    /// Verify everything that can be verified, file what passed, record what arrived.
    fn execute(self, plan_only: bool, strict: bool) -> Result<(), CliError> {
        let mut imported: Vec<Imported> = Vec::new();
        let mut refusals: Vec<Refusal> = Vec::new();
        let mut filing: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut in_scope = 0usize;

        for candidate in &self.candidates {
            let body = match self.read(candidate) {
                Ok(body) => body,
                Err(refusal) => {
                    refusals.push(refusal);
                    continue;
                }
            };
            if !self.relevant(candidate, &body) {
                continue;
            }
            in_scope += 1;
            let closure = match self.closure(candidate) {
                Ok(closure) => closure,
                Err(refusal) => {
                    refusals.push(refusal.with_reference(&candidate.reference));
                    continue;
                }
            };
            let judged = match self.judge(candidate, &body) {
                Ok(judged) => judged,
                Err(refusal) => {
                    refusals.push(refusal.with_reference(&candidate.reference));
                    continue;
                }
            };
            if !judged.report.accepted() {
                // The ladder refused it. It is reported and skipped, and the rest of the
                // import goes ahead — one stale proof must not end an import of two
                // hundred — but a bad signature or a bad digest also decides the exit.
                refusals.push(judged.refusal(candidate));
                continue;
            }
            let verify_exit = judged.report.exit_code();
            for found in &closure.records {
                allow(&mut filing, found);
            }
            imported.push(Imported {
                reference: candidate.reference.clone(),
                digest: candidate.digest,
                tier: judged.tier,
                signers: judged.signers,
                verify_exit,
                records: closure.records,
                depth: closure.depth,
                subjects: closure.subjects,
                excused: closure.excused,
                derived: closure.derived,
                quorum: judged.quorum,
            });
        }

        // Everything that passed, in one copy: bytes before refs, create-only, re-hashed
        // at both ends — the same write `gitiup fetch` uses, so there is one place where
        // "never overwrite, never advertise what you cannot return" lives (D7).
        let mut notes: Vec<String> = Vec::new();
        let digests: BTreeSet<String> = filing.keys().cloned().collect();
        let before: BTreeSet<String> = digests
            .iter()
            .filter(|hex| self.knows(hex))
            .cloned()
            .collect();
        let copy = if digests.is_empty() {
            None
        } else {
            let mut options = Options::new(Verb::Fetch, &self.from_what, &self.to_what);
            options.actor = self.actor.clone();
            // An import carries proof, never code: the pack step is `gitiup fetch`'s, and
            // the subject rule below says so out loud instead of failing quietly.
            options.proofs_only = true;
            options.dry_run = plan_only;
            options.strict = strict;
            // This verb writes its own arrival records, with the verdict in them.
            options.record_arrivals = false;
            options.only = Some(digests.clone());
            options.reason = Some(format!("import from {}", self.from_what));
            options.budgets = self.budgets;
            options.now_us = self.now_us;
            Some(
                federation::copy(&*self.from, &*self.to, &options).map_err(|error| {
                    CliError::scored(
                        error.exit_code(),
                        error.message().to_string(),
                        error.hint().map(str::to_string),
                    )
                })?,
            )
        };
        let mut objects = federation::Objects::default();
        let mut refs = federation::Refs::default();
        let mut moved = 0usize;
        if let Some(report) = &copy {
            objects = report.objects.clone();
            refs = report.refs.clone();
            moved = report.pointers.len();
            for refusal in &report.refused {
                // "This ref is deliberately not portable" is a notice about the copy, not
                // a judgement about a document: `refs/gitiup/roster` names which epoch is
                // live, and a copy that carried it would be handing over live state. It is
                // reported, and it is not a refusal of the proof the reader came for.
                if refusal.token == "not_portable" {
                    notes.push(format!(
                        "{} — {}",
                        refusal.reference.as_deref().unwrap_or("-"),
                        one_line(&refusal.detail)
                    ));
                    continue;
                }
                refusals.push(Refusal {
                    reference: refusal
                        .reference
                        .as_deref()
                        .map(<str>::to_owned)
                        .map(String::into_boxed_str),
                    digest: refusal
                        .digest
                        .as_deref()
                        .map(<str>::to_owned)
                        .map(String::into_boxed_str),
                    token: refusal.token.clone(),
                    exit: refusal.exit,
                    detail: refusal.detail.clone(),
                    hint: None,
                });
            }
        }

        // The store's own account of how these bytes got here (D5). Only for digests that
        // were not already here: an arrival record is a statement about an arrival, and
        // writing one about a blob that was already on the shelf would be writing a lie
        // into the one place a reader trusts to be the truth.
        let mut records = 0usize;
        if !plan_only {
            let verified_by = self.spec.trust_source.clone();
            for (hex, references) in &filing {
                if before.contains(hex) {
                    continue;
                }
                let Ok(digest) = Oid::from_hex(hex) else {
                    continue;
                };
                let owner = imported
                    .iter()
                    .find(|item| item.records.iter().any(|f| f.digest.hex() == *hex));
                let exit = owner.map_or(0, |item| item.verify_exit);
                // The document's own record names every ref that came with it, not just the
                // one it is filed under: the closure is the unit that arrived, and a record
                // describing a lone attestation would be describing the exact state D9
                // forbids a store to end up in. A record about a piece of evidence says what
                // that piece is, and points at nothing it did not itself carry.
                let refs = match owner.filter(|item| item.digest.hex() == *hex) {
                    Some(item) => {
                        let mut all: Vec<String> = item
                            .records
                            .iter()
                            .map(|found| found.reference.clone())
                            .collect();
                        all.extend(references.iter().cloned());
                        all.sort();
                        all.dedup();
                        all
                    }
                    None => references.clone(),
                };
                let mut arrival = Arrival::walked(
                    &digest,
                    refs,
                    &self.from_what,
                    self.now_us,
                    &verified_by,
                    exit,
                );
                arrival.subject_excused = self.excuse.clone();
                federation::record(&*self.to, &arrival)
                    .map_err(|e| CliError::io(format!("kv/import/{hex}: {e}")))?;
                records += 1;
            }
        }

        let report = Report {
            from: self.from_what.clone(),
            to: self.to_what.clone(),
            plan_only,
            strict,
            policy: self.spec.summary(),
            trust: self.spec.trust_source.clone(),
            budgets: self.budgets,
            offered: self.candidates.len(),
            in_scope,
            excuse: self.excuse.clone(),
            imported,
            refusals,
            notes,
            objects,
            refs,
            pointers: moved,
            records,
        };
        report.finish(self.json);
        report.exit()
    }

    /// Whether the destination can already name one digest.
    fn knows(&self, hex: &str) -> bool {
        Oid::from_hex(hex)
            .ok()
            .and_then(|oid| self.to.head(&oid).ok().flatten())
            .is_some()
    }
}

/// Add one record's digest to the selection.
fn allow(filing: &mut BTreeMap<String, Vec<String>>, found: &Found) {
    filing
        .entry(found.digest.hex())
        .or_default()
        .push(destination_ref(found));
}

/// The ref a record is advertised by at the destination.
///
/// Everything travels under the name it arrived under, with one exception the copy
/// already enforces: a legacy single-level `refs/attestations/<subject>` is re-spelled as
/// `<subject>/<digest>` and the old spelling is never written again (D7).
fn destination_ref(found: &Found) -> String {
    let rest = found.reference.strip_prefix("refs/attestations/");
    match rest {
        Some(rest) if !rest.contains('/') && Oid::from_hex(rest).is_ok() => {
            format!("{}/{}", found.reference, found.digest.hex())
        }
        _ => found.reference.clone(),
    }
}

// ---------------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------------

/// What one import run did, in the shape both `--json` and a human read.
struct Report {
    from: String,
    to: String,
    plan_only: bool,
    strict: bool,
    policy: String,
    trust: String,
    budgets: portable::Budgets,
    offered: usize,
    in_scope: usize,
    excuse: Option<String>,
    imported: Vec<Imported>,
    refusals: Vec<Refusal>,
    /// Refs the copy layer would not carry, with the sentence why — live pointers and
    /// anything else ADR-0005 keeps out of a copy. Notice, not verdict.
    notes: Vec<String>,
    objects: federation::Objects,
    refs: federation::Refs,
    pointers: usize,
    records: usize,
}

impl Report {
    /// The lines a human gets, in the order the questions come: what was asked, what
    /// passed, what was refused and why, and what the store now knows.
    fn lines(&self) -> Vec<String> {
        let present: usize = self.imported.iter().map(|item| item.subjects).sum();
        let excused: usize = self.imported.iter().map(|item| item.excused.len()).sum();
        let deepest = self
            .imported
            .iter()
            .map(|item| item.depth)
            .max()
            .unwrap_or(0);
        let records: usize = self.imported.iter().map(|item| item.records.len()).sum();
        let mut out = vec![
            format!(
                "import         {} → {}{}",
                self.from,
                self.to,
                if self.plan_only {
                    "  (plan only: nothing written)"
                } else {
                    ""
                }
            ),
            format!("policy         {}", self.policy),
            format!("budget         {}", self.budgets.describe()),
            format!(
                "offered        {} attestation(s) advertised by the source, {} in scope",
                self.offered, self.in_scope
            ),
            format!(
                "imported       {} attestation(s) with their closure{} · {} record(s) deep to {} hops",
                self.imported.len(),
                if self.plan_only { " (planned)" } else { "" },
                records,
                deepest
            ),
            format!(
                "objects        {} new, {} already ({} bytes), {} re-hashed",
                self.objects.arrived,
                self.objects.already,
                self.objects.bytes,
                self.objects.rehashed
            ),
            format!(
                "refs           {} written, {} already, {} moved, {} respelled",
                self.refs.written, self.refs.already, self.refs.moved, self.refs.respelled
            ),
            if self.refusals.is_empty() {
                "refused        none".to_string()
            } else {
                let mut by_token: BTreeMap<String, usize> = BTreeMap::new();
                for refusal in &self.refusals {
                    *by_token.entry(refusal.token.clone()).or_insert(0) += 1;
                }
                let parts: Vec<String> = by_token
                    .iter()
                    .map(|(token, count)| format!("{count} {token}"))
                    .collect();
                format!(
                    "refused        {} ({})",
                    self.refusals.len(),
                    parts.join(", ")
                )
            },
            format!(
                "subject        {present} present{}{}",
                if excused == 0 {
                    String::new()
                } else {
                    format!(", {excused} excused")
                },
                match &self.excuse {
                    Some(why) => format!(" ({why})"),
                    None => String::new(),
                }
            ),
            format!(
                "records        {} kv/import/<digest> written{} · closure walked, subject \
                 presence {} — recorded, and never an input to a later verdict",
                if self.plan_only { 0 } else { self.records },
                if self.plan_only { " (planned)" } else { "" },
                if self.excuse.is_some() {
                    "excused"
                } else {
                    "required"
                }
            ),
            "trust          none: what was checked is written down, and the next reader \
             recomputes it"
                .to_string(),
        ];
        if self.pointers > 0 {
            out.push(format!("pointers       {} resolved", self.pointers));
        }
        out
    }

    /// Per-document lines: one per import and one per refusal, so the summary above is
    /// never the only thing a reader has.
    fn details(&self) -> Vec<String> {
        let mut out = Vec::new();
        for item in &self.imported {
            out.push(format!(
                "  imported   {:<14} {:<9} {:>3} record(s){} · signed by {}",
                short(&item.digest.hex()),
                item.tier,
                item.records.len(),
                if item.verify_exit == 0 {
                    String::new()
                } else {
                    format!(" · verify exit {}", item.verify_exit)
                },
                if item.signers.is_empty() {
                    "nobody".to_string()
                } else {
                    item.signers
                        .iter()
                        .map(|key| short(key))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            for excuse in &item.excused {
                out.push(format!("             subject excused: {excuse}"));
            }
            for derived in &item.derived {
                out.push(format!("             closed by derivation: {derived}"));
            }
        }
        for note in &self.notes {
            out.push(format!("  not carried  {note}"));
        }
        for refusal in &self.refusals {
            out.push(format!(
                "  refused    {}{} [{}] (exit {}) {}",
                refusal.token,
                refusal
                    .reference
                    .as_ref()
                    .map(|reference| format!(" · {reference}"))
                    .unwrap_or_default(),
                refusal
                    .digest
                    .as_deref()
                    .map(short)
                    .unwrap_or_else(|| "-".into()),
                refusal.exit,
                one_line(&refusal.detail)
            ));
        }
        out
    }

    fn json(&self) -> Value {
        json!({
            "verb": "import",
            "from": self.from,
            "to": self.to,
            // `dry_run` is the key `gitiup fetch` and `gitiup push` use for the same fact;
            // `plan_only` is what this verb calls it in prose, and both are printed so a
            // script reading either verb reads the same field.
            "dry_run": self.plan_only,
            "plan_only": self.plan_only,
            "strict": self.strict,
            "policy": self.policy,
            "trust": "none",
            "verified_by": self.trust,
            "budgets": self.budgets.describe(),
            "offered": self.offered,
            "in_scope": self.in_scope,
            "imported": self.imported.iter().map(|item| json!({
                "reference": item.reference,
                "digest": item.digest.hex(),
                "tier": item.tier,
                "signers": item.signers,
                "verify_exit": item.verify_exit,
                "records": item.records.iter().map(|found| json!({
                    "reference": found.reference,
                    "digest": found.digest.hex(),
                    "kind": found.kind.as_str(),
                })).collect::<Vec<Value>>(),
                "depth": item.depth,
                "subjects": item.subjects,
                "excused": item.excused,
                "derived": item.derived,
                "quorum": item.quorum.clone(),
            })).collect::<Vec<Value>>(),
            "refused": self.refusals.iter().map(|refusal| json!({
                "reference": refusal.reference,
                "digest": refusal.digest,
                "token": refusal.token,
                "exit": refusal.exit,
                "detail": refusal.detail,
                "hint": refusal.hint,
            })).collect::<Vec<Value>>(),
            "not_carried": self.notes,
            "objects": {
                "arrived": self.objects.arrived,
                "already": self.objects.already,
                "rehashed": self.objects.rehashed,
                "bytes": self.objects.bytes,
            },
            "refs": {
                "written": self.refs.written,
                "already": self.refs.already,
                "moved": self.refs.moved,
                "respelled": self.refs.respelled,
            },
            "pointers": self.pointers,
            "subject": {
                "excused_by": self.excuse,
            },
            "records": if self.plan_only { 0 } else { self.records },
        })
    }

    /// Print it, in whichever shape was asked for, and say what can be said on stderr.
    ///
    /// A per-record refusal does not fail the run — one unimportable proof must not end an
    /// import of two hundred — and an integrity failure always does (D10). `--strict` makes
    /// the first category behave like the second, for the CI job that would rather know.
    fn finish(&self, json: bool) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&self.json()).unwrap_or_else(|_| "{}".into())
            );
        } else {
            for line in self.lines() {
                println!("{line}");
            }
            for line in self.details() {
                println!("{line}");
            }
        }
        for refusal in self.refusals.iter().filter_map(|r| r.hint.as_deref()) {
            eprintln!("hint: {}", one_line(refusal));
        }
        if self.plan_only {
            eprintln!("plan only: nothing was written. Add --apply to import these.");
        }
    }

    fn exit(&self) -> Result<(), CliError> {
        let integrity = self
            .refusals
            .iter()
            .filter(|refusal| refusal.integrity())
            .map(|refusal| refusal.exit)
            .max();
        let code = integrity.unwrap_or(if self.strict && !self.refusals.is_empty() {
            6
        } else {
            0
        });
        if code == 0 {
            return Ok(());
        }
        Err(CliError::verdict(code))
    }
}

/// Collapse a wrapped sentence onto one line, for a report that is a table.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shorten a long hex or key id for a table column, keeping its front and back.
fn short(text: &str) -> String {
    crate::attest::short(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_string()).collect()
    }

    fn parse(args: &[&str]) -> Result<Args, CliError> {
        Args::parse_with(&arg(args), VALUED, SWITCHES)
    }

    /// The rule the whole surface exists to keep: nothing in this flag list may turn a
    /// store into a trust root.
    #[test]
    fn no_flag_can_be_read_as_trusting_the_source() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            let name = flag.to_ascii_lowercase();
            assert!(
                !name.contains("trust-remote")
                    && !name.contains("trusted-store")
                    && !name.contains("from-trusted")
                    && !(name.contains("trust") && name != "--trust" && name != "--trust-any-key"),
                "`{flag}` reads like a grant from the source, which ADR-0005 D3 forbids"
            );
        }
        assert!(
            IMPORT_HELP.contains("no flag here") || IMPORT_HELP.contains("nothing more"),
            "the help has to say what the flag list refuses"
        );
    }

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts_and_the_codes_it_exits_with() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                IMPORT_HELP.contains(flag),
                "{flag} is accepted by `gitiup attest import` and undocumented in its help"
            );
        }
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(IMPORT_HELP.contains(code), "exit {code} is missing");
        }
        assert!(IMPORT_HELP.contains("attest import"));
    }

    #[test]
    fn apply_and_dry_run_are_opposites() {
        let error =
            crate::import::import(&arg(&["--from", "a", "--to", "b", "--apply", "--dry-run"]))
                .unwrap_err();
        assert_eq!(error.code, 2, "{error:?}");
    }

    #[test]
    fn both_stores_have_to_be_named() {
        assert_eq!(
            crate::import::import(&arg(&["--from", "a"]))
                .unwrap_err()
                .code,
            6
        );
        assert_eq!(
            crate::import::import(&arg(&["--to", "b"]))
                .unwrap_err()
                .code,
            6
        );
    }

    #[test]
    fn a_missing_subject_is_excused_only_by_being_excused_out_loud() {
        let args = parse(&["--from", "a", "--to", "b", "--proofs-only"]).unwrap();
        assert!(args.on("--proofs-only"));
        for flag in ["--allow-missing-subject", "--proofs-only"] {
            assert!(
                IMPORT_HELP.contains(flag),
                "{flag} is the sanctioned excuse and has to be documented"
            );
        }
    }

    #[test]
    fn the_token_for_a_check_is_the_word_d10_uses_when_d10_has_one() {
        assert_eq!(token_for_check("signature"), "bad_signature");
        assert_eq!(token_for_check("trust"), "signer_untrusted");
        assert_eq!(token_for_check("tier"), "tier_not_allowed");
        assert_eq!(token_for_check("freshness"), "expired");
        assert_eq!(token_for_check("structure"), "not_canonical");
        assert_eq!(token_for_check("digest"), "digest_mismatch");
        assert_eq!(token_for_check("commit"), "binding_mismatch");
        // And a check D10 has no word for keeps the word the ladder uses, rather than
        // being stretched into a token that means something else.
        assert_eq!(token_for_check("environment"), "environment");
        assert_eq!(token_for_check("min_signatures"), "signer_untrusted");
    }

    #[test]
    fn a_legacy_attestation_ref_is_spelled_the_new_way_at_the_destination() {
        let subject = "a".repeat(40);
        let digest = "b".repeat(64);
        let legacy = Found {
            reference: format!("refs/attestations/{subject}"),
            digest: Oid::from_hex(&digest).unwrap(),
            kind: Kind::Attestation,
        };
        assert_eq!(
            destination_ref(&legacy),
            format!("refs/attestations/{subject}/{digest}")
        );
        let current = Found {
            reference: format!("refs/attestations/{subject}/{digest}"),
            digest: Oid::from_hex(&digest).unwrap(),
            kind: Kind::Attestation,
        };
        assert_eq!(destination_ref(&current), current.reference);
        // Not an attestation ref at all: the name travels unchanged.
        let verdict = Found {
            reference: "refs/gitiup/verdict/chg-1/build".to_string(),
            digest: Oid::from_hex(&digest).unwrap(),
            kind: Kind::Verdict,
        };
        assert_eq!(destination_ref(&verdict), verdict.reference);
    }

    #[test]
    fn kinds_come_from_the_portable_table_and_are_split_where_the_walk_needs_them() {
        let hex = "a".repeat(40);
        assert_eq!(
            Kind::of(&format!("refs/attestations/{hex}/{}", "b".repeat(64))),
            Some(Kind::Attestation)
        );
        assert_eq!(
            Kind::of("refs/gitiup/commit/chg-1/build/0000000000000001"),
            Some(Kind::Commitment)
        );
        assert_eq!(
            Kind::of("refs/gitiup/reveal/chg-1/build/0000000000000001"),
            Some(Kind::Reveal)
        );
        assert_eq!(
            Kind::of("refs/gitiup/withdrawal/0000000000000001"),
            Some(Kind::Withdrawal)
        );
        assert_eq!(
            Kind::of("refs/gitiup/policy/history/000002"),
            Some(Kind::Policy)
        );
        // A pointer is not a record, so it is not an edge either: `head` and `current`
        // are resolved, never copied (D2).
        assert_eq!(Kind::of("refs/changes/chg-1/head"), None);
        assert_eq!(Kind::of("refs/gitiup/policy/current"), None);
        assert_eq!(Kind::of("refs/heads/main"), None);
        assert_eq!(
            Kind::of("refs/gitiup/lease/chg-1/build/0000000000000001"),
            None
        );
    }

    #[test]
    fn a_sibling_ref_is_named_by_swapping_the_namespace_it_lives_in() {
        let reveal = "refs/gitiup/reveal/chg-1/build/matrix/linux/0000000000000001";
        assert_eq!(
            sibling(reveal, "reveal").unwrap(),
            "chg-1/build/matrix/linux/0000000000000001"
        );
        assert!(sibling("refs/gitiup/round/chg-1/build/0", "reveal").is_err());
    }

    #[test]
    fn a_digest_a_record_cites_is_a_store_object_in_any_spelling() {
        let hex = "c".repeat(64);
        assert_eq!(subject_digest(&format!("sha256:{hex}")).unwrap().hex(), hex);
        assert_eq!(subject_digest(&hex).unwrap().hex(), hex);
        assert_eq!(hex_of("SHA256:AB"), "ab");
        assert!(subject_digest("not a digest").is_err());
    }

    #[test]
    fn budgets_read_the_way_the_help_promises() {
        let args = parse(&[
            "--from",
            "a",
            "--to",
            "b",
            "--max-records",
            "17",
            "--max-depth",
            "3",
            "--max-policy-chain",
            "4",
            "--max-bytes",
            "2m",
        ])
        .unwrap();
        assert_eq!(args.get("--max-records"), Some("17"));
        assert_eq!(args.get("--max-bytes"), Some("2m"));
        assert_eq!(crate::fetch::human_bytes("2m").unwrap(), 2 * 1024 * 1024);
    }
}

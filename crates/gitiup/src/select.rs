//! `gitiup select` — who is asked to verify one job, and why (giti-msi.3).
//!
//! The algorithm is not here: it is [`gitiup_quorum::select`], pinned to the ADR-0002
//! vectors. What lives here is the two command lines the ticket asks for — the selector's
//! and everybody else's — and the rule that they are *different commands*:
//!
//! ```text
//! gitiup select --change X --head sha1:… --job build/matrix/linux-x86_64 \
//!     --proposer ada --require-arch x86_64 --store ./store --explain
//!                                            │
//!        derives the seed from the selector's key, excludes the proposer's whole
//!        key family, signs the round record, and (--publish) puts it in the store
//!
//! gitiup select --change X --store ./store --explain
//!        re-derives the same ordered selection from the published round record and
//!        the roster epoch it pinned — no key, no secret, no trust root required
//! ```
//!
//! # The rules this surface keeps
//!
//! * **Deriving needs a key; auditing needs nothing.** The seed is
//!   `HMAC-SHA256(HKDF-Extract(selector's Ed25519 seed), round_id)` (ADR-0002 D2), so only
//!   the selector can open a round — and *anybody* can re-check one, which is the
//!   acceptance criterion. An auditor with an empty keystore gets the same selection as the
//!   owner who made it, plus an explicit note about which check could not run.
//! * **The proposer is excluded, and then checked.** `--proposer` is required to derive a
//!   round, is closed over the proposer's whole identity family before the seed is derived,
//!   and is re-checked against the result ([`ProposerExclusion`]). "Always excluded" cannot
//!   mean "always remembered by the caller".
//! * **A published round is not re-specified.** In audit mode the inputs come from the
//!   record: passing `--n`, `--head`, `--require-arch` or friends is refused, not silently
//!   ignored, because a flag that quietly changes a re-derivation is how two auditors end up
//!   with two quorums.
//! * **The audit trail is the round record.** `--out` writes its canonical bytes and
//!   `--publish` CAS-writes it into the store, at which point the seed is public
//!   ([ADR-0002 D11](../../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md)):
//!   unguessable before publication, public after, and this command never pretends a public
//!   store can hide a jury from the people it is addressed to.
//! * **Insufficient is an answer, not a failure to print.** If the caps and filters leave
//!   fewer than `n` seats the command prints what it found with `sufficient: false` and
//!   exits 0: deciding what that *means* is the verdict engine's job (giti-msi.7).
//! * **Exit codes are the same table as everywhere else** (ADR-0001 D7): 2 usage ·
//!   3 I/O or store unreachable · 6 refused (no store, no proposer, an expired epoch, a
//!   round that let the proposer in, a policy that cannot fill its seats) · 7 a signature
//!   that does not verify · 8 a record whose bytes are not their canonical form, or a
//!   published selection that does not match its own derivation.

use std::collections::BTreeSet;

use gitiup_attest::{GitOid, Signer as _, TimeUs, Trust};
use gitiup_quorum::prelude::*;
use gitiup_quorum::{Round, SelectionSecret, store};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{
    self, KeystoreHere, Opened, Sink, key_id_of, only_bytes, print_json, read_maybe_stdin,
    requirements_from, short, signing_key, store_from, write_out,
};

/// Help for `gitiup select`.
pub const SELECT_HELP: &str = "\
gitiup select — who verifies one change, and the proof of why they were chosen

USAGE:
    gitiup select --change <id> [OPTIONS]

Two commands in one, told apart by whether the round already exists:

  AUDIT (what runs when a round is published, or when --round names one)
    reads the round record, the roster epoch it pinned and the published seed, and
    re-derives the ordered selection. No key and no trust root is needed: a stranger gets
    the same answer as the owner who made it, and is told which checks could not run.

  DERIVE (what runs when no round exists yet)
    needs the selector's signing key, because the seed is keyed on it (ADR-0002 D2), and
    writes the round record that makes the selection auditable.

THE ROUND
    --change <id>            required
    --job <id>               the matrix vector; omit it when the change has exactly one
    --attempt <n>            0 is the first round; >=1 are escalations (default 0)
    --round <path|->         audit this round record (bytes, or a pipe) instead of a store's
    --store <dir>            the store to read (and to publish into)
    --remote <name>          a remote from gitiup.toml
    --roster <path|->        the roster document, when it is not a store's current epoch
    --epoch <n>              audit one published roster epoch rather than the current one

DERIVE — inputs (refused in audit mode, where the record already carries them)
    --head <sha1:…>          required · the change's head oid
    --proposer <key>         required, repeatable · the author: a key id or a keystore
                             name. Their whole identity family is excluded — every other
                             box registered under the same principal — and the exclusion
                             is checked afterwards, not assumed
    --exclude <key>          repeatable · quarantined or escalated keys
    --require-arch <a>       required · one round selects for one architecture, so a
    --require-ram-mb <n>     matrix with two arches is two rounds with two seeds
    --require-disk-mb <n> --require-sandbox <s> --require-min-sandbox-level <n>
    --require-image <digest>

POLICY (derive mode; a published round carries its own)
    --policy <path|->        a SelectionPolicy document
    --n <n>                  seats (default 5)      --required-agree <n>  (default 4)
    --reserves <n>           listed reserves (default 2)
    --max-per-identity <n>   seats per principal (default 1)
    --tier-floor <tier>      anonymous | endorsed | trusted
    --tier-cap <tier>=<n>    repeatable · a CAP on seats per tier, never a weight
    --reveal-mode <mode>     open (default) | sealed: a sealed round asks each seat to
                             commit to H(attestation bytes ‖ slot ‖ challenge) before it
                             reveals the bytes (giti-zp1.6); `gitiup change submit` takes
                             this from the published policy, not from a flag

SIGNING (derive mode)
    --key <selector>         the selector (default: this machine's current identity); the
                             seed comes from this key, so an agent-held key cannot derive
                             one — see --seed-file
    --seed-file <path|->     32 raw bytes (or 64 hex characters) as the selection secret,
                             for a delegated selector whose Ed25519 seed no one holds
    --passphrase-file <p>    or GITIUP_KEY_PASSPHRASE, as everywhere

OUTPUT
    --explain                the audit table: one row per roster entry with its score,
                             what excluded it and what the greedy pass decided
    --owner <key>            repeatable · whose roster signature counts (default: this
                             machine's keystore; none is legal for an auditor)
    --out <path|->           write the round record's canonical bytes
    --publish                publish the round record (derive mode; CAS, never overwrite)
    -j, --json               machine-readable output

Examples:
    gitiup select --change chg-1 --store ./store --explain
    gitiup select --change chg-1 --store ./store --json | jq .selection
    gitiup select --change chg-1 --job build/matrix/linux-x86_64 \\
        --head sha1:$(git rev-parse HEAD) --proposer ada --require-arch x86_64 \\
        --store ./store --publish

Exit codes: 0 ok · 2 usage · 3 I/O, store unreachable · 6 refused (no proposer, no store,
expired epoch, a proposer that was not excluded, a policy that cannot fill its seats) ·
7 a signature that does not verify · 8 the bytes are not the record's canonical form, or
the published seats are not the derived ones.
";

/// The switches `gitiup select` accepts.
const SWITCHES: &[&str] = &["--explain", "--publish"];

/// Valued flags for `gitiup select`.
const VALUED: &[&str] = &[
    "--change",
    "--job",
    "--attempt",
    "--round",
    "--store",
    "--remote",
    "--roster",
    "--epoch",
    "--head",
    "--proposer",
    "--exclude",
    "--policy",
    "--n",
    "--required-agree",
    "--reserves",
    "--max-per-identity",
    "--tier-floor",
    "--tier-cap",
    "--reveal-mode",
    "--key",
    "--seed-file",
    "--passphrase",
    "--passphrase-file",
    "--owner",
    "--out",
    "--require-arch",
    "--require-ram-mb",
    "--require-disk-mb",
    "--require-sandbox",
    "--require-min-sandbox-level",
    "--require-image",
];

/// Flags that only make sense while a round is being *opened*.
///
/// In audit mode they are refused rather than ignored: an auditor who could re-state the
/// policy would not be auditing the published selection, they would be proposing a new one.
const DERIVE_ONLY: &[&str] = &[
    "--head",
    "--exclude",
    "--policy",
    "--n",
    "--required-agree",
    "--reserves",
    "--max-per-identity",
    "--tier-floor",
    "--tier-cap",
    "--reveal-mode",
    "--seed-file",
    "--require-arch",
    "--require-ram-mb",
    "--require-disk-mb",
    "--require-sandbox",
    "--require-min-sandbox-level",
    "--require-image",
];

/// `gitiup select …`
pub fn select(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.help(SELECT_HELP).is_some()
        || args.positional.first().is_some_and(|first| first == "help")
    {
        print!("{SELECT_HELP}");
        return Ok(());
    }
    let change = args
        .get("--change")
        .ok_or_else(|| CliError::usage("--change <id> names the change to select for"))?
        .to_string();
    let attempt = match args.get("--attempt") {
        Some(text) => text
            .parse::<u64>()
            .map_err(|_| CliError::usage(format!("--attempt wants a number, got '{text}'")))?,
        None => 0,
    };
    let here = participant::keystore()?;
    let now = TimeUs::now();
    let opened = store_from(&args)?;
    let trust = trust_for(&args, &here)?;

    // Whether a round already exists for this change is what decides the mode: an owner who
    // runs `select` again after publishing gets an audit, not a second and slightly
    // different quorum for the same change.
    let published = find_round(&args, opened.as_ref(), &change, attempt)?;
    let outcome = match published {
        Some((round, source)) => audit(
            &args,
            &here,
            trust.as_ref(),
            opened.as_ref(),
            round,
            source,
            now,
        )?,
        None => derive(
            &args,
            &here,
            trust.as_ref(),
            opened.as_ref(),
            &change,
            attempt,
            now,
        )?,
    };
    report(&args, &outcome)
}

/// The roster to select against, believed as far as this machine can believe it.
struct RosterAt {
    roster: Roster,
    /// Where it came from, for the audit record.
    source: String,
    /// How its signatures were believed — `None` means none were.
    trusted_via: Option<String>,
    notes: Vec<String>,
}

/// What the command decided, before anyone prints it.
struct Outcome {
    /// `"audit"` or `"derive"`.
    mode: &'static str,
    /// The round record: read back (audit) or just derived (derive).
    round: Round,
    /// Where the round came from, or where it will go.
    round_source: String,
    roster: Roster,
    roster_source: String,
    /// How the signatures were believed, if anybody's were.
    trusted_via: Option<String>,
    selection: Selection,
    /// The proposer(s) the exclusion rule was checked against (empty = not checked).
    proposer: Vec<String>,
    check: ProposerExclusion,
    /// A sentence about where the seed came from, for the audit record.
    seed_source: String,
    /// The selector keys whose signatures were believed on the round record.
    selectors: Option<Vec<String>>,
    notes: Vec<String>,
}

impl Outcome {
    /// The envelope `--json` prints.
    ///
    /// `selection` is the ADR-0002 selection document verbatim — `jq .selection` gives a
    /// file with `selection.json`'s shape — and everything needed to reproduce it
    /// (`inputs`, `seed`, the roster's epoch and digest) sits beside it. Environment names
    /// (which store, which keystore) are kept out of `selection`, so two auditors' output
    /// differs only in provenance and never in the answer.
    fn json(&self, explain: Option<&str>, where_: &Value) -> Value {
        json!({
            "kind": "selection",
            "mode": self.mode,
            "change_id": self.round.inputs.change_id,
            "job_id": self.round.inputs.job_id,
            "attempt": self.round.inputs.attempt,
            "roster": {
                "epoch": self.roster.epoch,
                "digest": self.roster.digest().ok(),
                "entries": self.roster.entries.len(),
                "identities": self.roster.identities().len(),
                "source": self.roster_source,
                "trusted_via": self.trusted_via,
            },
            "policy": self.round.inputs.policy,
            "policy_digest": self.round.policy_digest,
            "inputs": self.round.inputs,
            "seed": self.round.seed,
            "seed_source": self.seed_source,
            "proposer": {
                "principals": &self.proposer,
                "family": &self.check.family,
                "not_excluded": &self.check.missing,
                "seated": &self.check.seated,
                "excluded": self.check.held(),
            },
            "round": {
                "source": self.round_source,
                "digest": self.round.digest().ok(),
                "selectors": &self.selectors,
                "published_seats_are_derived": true,
                "reveal_mode": self.round.reveal_mode,
            },
            "eligible": self.selection.eligible,
            "sufficient": self.selection.sufficient,
            "selected": self.selection.selected,
            "reserves": self.selection.reserves,
            "candidates": self.selection.candidates,
            "selection": self.selection,
            "explain": explain,
            "notes": self.notes,
            "where": where_,
        })
    }

    fn text(&self, explain: Option<&str>) {
        println!(
            "{} — change {} · job {} · attempt {}",
            if self.mode == "audit" {
                "audit of a published selection"
            } else {
                "derived a new selection"
            },
            self.round.inputs.change_id,
            self.round.inputs.job_id,
            self.round.inputs.attempt,
        );
        println!(
            "  roster   epoch {} · {} entries · {} identities · {}",
            self.roster.epoch,
            self.roster.entries.len(),
            self.roster.identities().len(),
            self.roster
                .digest()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
        );
        println!(
            "           from {}{}",
            self.roster_source,
            match &self.trusted_via {
                Some(via) => format!(" · signatures believed via {via}"),
                None => " · NO trust root: no signature was believed".to_string(),
            }
        );
        let policy = &self.round.inputs.policy;
        println!(
            "  policy   n={} · agree {} · reserves {} · floor {} · {} seat(s) per identity · \
             caps {}",
            policy.n,
            policy.required_agree,
            policy.reserves,
            policy.tier_floor,
            policy.max_per_identity,
            policy
                .tier_caps
                .iter()
                .map(|(tier, cap)| format!("{tier}≤{cap}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        println!("  seed     {} — {}", self.round.seed, self.seed_source);
        println!("  {}", self.check.describe());
        println!(
            "  seats    {} of {} filled · {} of {} roster entries eligible",
            self.selection.selected.len(),
            policy.n,
            self.selection.eligible,
            self.roster.entries.len(),
        );
        for seat in &self.selection.selected {
            println!(
                "    {} {:<20} {:<10} {}",
                seat.rank,
                short(&seat.key_id),
                seat.tier.as_str(),
                self.selection
                    .candidates
                    .iter()
                    .find(|row| row.key_id == seat.key_id)
                    .map(|row| short_hex(&row.score))
                    .unwrap_or_default(),
            );
        }
        let listed: Vec<String> = self
            .selection
            .reserves
            .iter()
            .take(policy.reserves)
            .map(|reserve| short(&reserve.key_id))
            .collect();
        println!(
            "  reserves {} eligible (first {}; a listing, not a decision — promotion is a \
             re-run with a longer exclusion list)",
            self.selection.reserves.len(),
            if listed.is_empty() {
                "none".to_string()
            } else {
                listed.join(", ")
            }
        );
        if !self.selection.sufficient {
            println!(
                "  note: the seats were NOT filled. That is `Insufficient`, not a smaller \
                 quorum: {} eligible, {} seats required.",
                self.selection.eligible, policy.n
            );
        }
        for note in &self.notes {
            println!("  note: {note}");
        }
        if let Some(table) = explain {
            println!();
            print!("{table}");
        }
    }
}

/// Shorten a hex digest for a terminal line; display only.
fn short_hex(hex: &str) -> String {
    if hex.len() <= 12 {
        hex.to_string()
    } else {
        format!("{}\u{2026}", &hex[..12])
    }
}

/// Whose signature makes a roster or round a trust root, if anybody's does here.
///
/// `--owner` is a hard requirement when given: a mistyped trust root must not degrade into
/// "believed nobody". Without it this machine's keystore is the trust root — and an empty
/// keystore is *not* an error, because the auditor the acceptance criterion is about is a
/// stranger with the published bytes and no keys of their own.
fn trust_for(args: &Args, here: &KeystoreHere) -> Result<Option<(Trust, String)>, CliError> {
    if !args.all("--owner").is_empty() {
        return Ok(Some(participant::owner_trust(args, here)?));
    }
    Ok(participant::owner_trust(args, here).ok())
}

/// The roster to select against.
///
/// `want` is the epoch a published round pins: ADR-0002 C9 is that a past selection stays
/// checkable *against the roster it selected from*, so an audit fetches that epoch rather
/// than today's. A derive has no opinion and takes the store's current one.
fn roster_at(
    args: &Args,
    trust: Option<&(Trust, String)>,
    opened: Option<&Opened>,
    want: Option<u64>,
    now: TimeUs,
) -> Result<RosterAt, CliError> {
    let mut notes = Vec::new();
    let (roster, source) = match args.get("--roster") {
        Some(path) => (
            Roster::from_canonical_bytes(&read_maybe_stdin(path)?)?,
            format!("file {path}"),
        ),
        None => {
            let opened = opened.ok_or_else(|| {
                CliError::refused(
                    "no roster was named and no store was found",
                    "--roster <path|->, --store <dir> or --remote <name> \
                     (see `gitiup doctor --remotes`)",
                )
            })?;
            let epoch = match (args.get("--epoch"), want) {
                (Some(text), _) => text.parse::<u64>().map_err(|_| {
                    CliError::usage(format!("--epoch wants a number, got '{text}'"))
                })?,
                (None, Some(epoch)) => epoch,
                (None, None) => current_roster(opened)?.epoch,
            };
            let found = if args.get("--epoch").is_some() || want.is_some() {
                store::roster_at(&*opened.host, epoch)?.ok_or_else(|| {
                    CliError::refused(
                        format!("the store has no roster epoch {epoch}"),
                        "a round is auditable only against the epoch it pinned, so that epoch \
                         has to still be published (ADR-0002 D8 keeps them ≥ 90 days)",
                    )
                })?
            } else {
                current_roster(opened)?
            };
            (found, opened.what.clone())
        }
    };
    let trusted_via = match trust {
        Some((trust, via)) => {
            roster.verify(trust, now)?;
            Some(via.clone())
        }
        None => {
            // Structural, not signature: the epoch is usable as the *input* to a
            // re-derivation without anybody vouching for it, and the note below is what
            // stops that from being mistaken for an endorsement.
            roster.validate()?;
            notes.push(
                "no trust root was configured (--owner, or keys in this machine's keystore), \
                 so the roster's owner signature was not believed; the selection is \
                 reproducible without it, the authority is not"
                    .to_string(),
            );
            None
        }
    };
    if now.as_us() > roster.valid_until_us {
        notes.push(format!(
            "roster epoch {} expired at {}; an expired epoch may not open a new round",
            roster.epoch,
            TimeUs(roster.valid_until_us).to_rfc3339()
        ));
    }
    Ok(RosterAt {
        roster,
        source,
        trusted_via,
        notes,
    })
}

/// The store's current roster, or the refusal that tells the owner how to make one.
fn current_roster(opened: &Opened) -> Result<Roster, CliError> {
    store::current_roster(&*opened.host)?.ok_or_else(|| {
        CliError::refused(
            format!("{} has no roster at refs/gitiup/roster", opened.what),
            "the owner publishes one with `gitiup participant approve --publish`",
        )
    })
}

/// The round already published for this change, if any.
///
/// `--round` reads one from disk or a pipe (the offline audit: bytes handed over on a stick
/// are checked exactly as bytes fetched from a store). Otherwise the store is asked for the
/// change's rounds: `--job` picks one, and without `--job` a change with exactly one round
/// needs no more spelling than that.
fn find_round(
    args: &Args,
    opened: Option<&Opened>,
    change: &str,
    attempt: u64,
) -> Result<Option<(Round, String)>, CliError> {
    if let Some(path) = args.get("--round") {
        let round = Round::from_canonical_bytes(&read_maybe_stdin(path)?)?;
        if round.inputs.change_id != change {
            return Err(CliError::refused(
                format!(
                    "the round in {path} is for change {}, not {change}",
                    round.inputs.change_id
                ),
                "pass the change id the record carries, or name a different record",
            ));
        }
        return Ok(Some((round, format!("file {path}"))));
    }
    let Some(opened) = opened else {
        return Ok(None);
    };
    if let Some(job) = args.get("--job") {
        let name = store::round_ref(change, job, attempt)?;
        let found = store::round_at(&*opened.host, change, job, attempt)?;
        return Ok(found.map(|round| (round, format!("{} · {}", opened.what, name.as_str()))));
    }
    let matching: Vec<Round> = store::rounds_for(&*opened.host, change)?
        .into_iter()
        .filter(|round| round.inputs.attempt == attempt)
        .collect();
    match matching.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some((
            only.clone(),
            format!(
                "{} · {}",
                opened.what,
                store::round_ref(change, &only.inputs.job_id, attempt)?.as_str()
            ),
        ))),
        many => Err(CliError::refused(
            format!(
                "change {change} has {} rounds at attempt {attempt}: {}",
                many.len(),
                many.iter()
                    .map(|round| round.inputs.job_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "name one with --job <id>: a matrix is one round per arm, each with its own seed",
        )),
    }
}

/// Re-derive a published selection from the round, the roster and the published seed.
///
/// This is the acceptance criterion, run as a command: same published bytes, same ordered
/// list, whoever runs it.
fn audit(
    args: &Args,
    here: &KeystoreHere,
    trust: Option<&(Trust, String)>,
    opened: Option<&Opened>,
    round: Round,
    source: String,
    now: TimeUs,
) -> Result<Outcome, CliError> {
    for flag in DERIVE_ONLY {
        if !args.all(flag).is_empty() {
            return Err(CliError::refused(
                format!("{flag} cannot be used against a published round"),
                "the round record carries its own inputs, policy and requirements, and a \
                 re-derivation that took a second opinion about them would not be an audit; \
                 {flag} belongs to `gitiup select` before the round is published",
            ));
        }
    }
    if args.on("--publish") {
        return Err(CliError::refused(
            "this round is already published",
            "a round is one signed statement, not a mutable row; re-running a settled round \
             is an escalation (attempt + 1, giti-msi.8)",
        ));
    }
    round.validate()?;
    let found = roster_at(args, trust, opened, Some(round.inputs.roster_epoch), now)?;
    let RosterAt {
        roster,
        source: roster_source,
        trusted_via,
        mut notes,
    } = found;
    // The record has to be the derived one before anything else about it is believed: the
    // seats, the eligible count and the sufficiency are recomputed from the published seed
    // here, and a round whose seats were edited is exit 8 wherever it was found.
    let (selection, selectors) = match trust {
        Some((trust, _)) => {
            let facts = round.verify(trust, &roster)?;
            (facts.selection, Some(facts.selectors))
        }
        None => (round.verify_selection(&roster)?, None),
    };
    if selectors.is_none() {
        notes.push(
            "the round's selector signature was not checked (no trust root); the published \
             seats were re-derived from the published seed and matched"
                .to_string(),
        );
    }
    let proposer = proposers(args, here)?;
    let check = ProposerExclusion::check(&roster, &round.inputs, &selection, &proposer);
    if proposer.is_empty() {
        notes.push(
            "no --proposer was named, so the proposer-exclusion rule was not checked; a round \
             that lets its own author referee their own change is worth refusing"
                .to_string(),
        );
    } else if !check.held() {
        return Err(CliError::refused(
            format!(
                "{} · change {} job {}",
                check.describe(),
                round.inputs.change_id,
                round.inputs.job_id
            ),
            "this round is not a legitimate selection for that proposer. The exclusion set is \
             part of the round record, so the round is refused rather than re-derived with a \
             better opinion (a new attempt is giti-msi.8's escalation)",
        ));
    }
    Ok(Outcome {
        mode: "audit",
        selectors,
        seed_source: "published in the round record (anybody can re-derive the scores from it)"
            .to_string(),
        round_source: source,
        roster,
        roster_source,
        trusted_via,
        selection,
        proposer,
        check,
        notes,
        round,
    })
}

/// The proposer(s) to exclude, resolved to key ids.
///
/// Both spellings are accepted (a `SHA256:…` fingerprint or a keystore name) because the
/// two people who type this are a reviewer with a change record and a CI job holding the
/// proposer's fingerprint and nothing else.
fn proposers(args: &Args, here: &KeystoreHere) -> Result<Vec<String>, CliError> {
    args.all("--proposer")
        .iter()
        .map(|value| key_id_of(here, value))
        .collect()
}

/// Open a round: derive the seed from the selector's key, exclude the proposer, sign.
fn derive(
    args: &Args,
    here: &KeystoreHere,
    trust: Option<&(Trust, String)>,
    opened: Option<&Opened>,
    change: &str,
    attempt: u64,
    now: TimeUs,
) -> Result<Outcome, CliError> {
    let head: GitOid = args
        .get("--head")
        .ok_or_else(|| {
            CliError::refused(
                "no round is published for this change, and --head is required to open one",
                "the head oid is a seed input (ADR-0002 D2): it is what stops an author \
                 shopping for a friendly jury by pushing a new commit. If a round does \
                 exist, name its store with --store or --remote",
            )
        })?
        .parse()
        .map_err(CliError::from)?;
    let job = args.get("--job").ok_or_else(|| {
        CliError::refused(
            "--job <id> is required to open a round",
            "one round is one matrix vector; a job id that is not stable and store-assigned \
             gives one run two seeds",
        )
    })?;
    let requirements = requirements_from(args)?.ok_or_else(|| {
        CliError::refused(
            "no job requirements were given",
            "eligibility is scored against what the job needs: --require-arch x86_64 at \
             minimum (one round per architecture), plus --require-ram-mb, --require-disk-mb, \
             --require-sandbox, --require-min-sandbox-level, --require-image",
        )
    })?;
    let proposer = proposers(args, here)?;
    if proposer.is_empty() {
        return Err(CliError::refused(
            "--proposer <key> is required: a round has to say who may not referee their own \
             change",
            "name the proposer's key id or keystore name; their whole identity family is \
             excluded with it (ADR-0002 D4) and the result is checked before it prints",
        ));
    }
    let policy = policy_from(args)?;
    let found = roster_at(args, trust, opened, None, now)?;
    let RosterAt {
        roster,
        source: roster_source,
        trusted_via,
        mut notes,
    } = found;
    if now.as_us() > roster.valid_until_us {
        return Err(CliError::refused(
            format!(
                "roster epoch {} has expired; a new round may not pin it",
                roster.epoch
            ),
            "the owner publishes a fresh epoch with `gitiup participant approve` \
             (valid_until_us is issued_at plus two epochs, ADR-0002 D8)",
        ));
    }
    let selector = signing_key(args, here)?;
    let secret = selection_secret(args, &selector)?;
    let mut exclusions: BTreeSet<String> = args
        .all("--exclude")
        .iter()
        .map(|value| key_id_of(here, value))
        .collect::<Result<_, _>>()?;
    // The owner's quarantines, read through the one door they have (giti-zp1.8): the names
    // join the exclusion set the round signs, and the roster is not touched. A selector
    // with no store or no trust root simply has nothing to apply, and says which it has.
    let kept = match (opened, trust) {
        (Some(opened), Some((trust, _))) => {
            crate::quarantine::kept_out(opened, trust, roster.epoch, now)?
        }
        _ => crate::quarantine::Kept::empty(),
    };
    notes.extend(kept.notes.iter().cloned());
    exclusions.extend(kept.names.iter().cloned());
    let inputs = RoundInputs {
        schema_version: gitiup_quorum::select::SELECTION_SCHEMA_VERSION,
        kind: None,
        round_kind: gitiup_quorum::derive::ROUND_KIND.to_string(),
        roster_epoch: roster.epoch,
        roster_digest: roster.digest()?,
        change_id: change.to_string(),
        head_oid: head,
        job_id: job.to_string(),
        attempt,
        required_capabilities: requirements,
        exclusions,
        policy,
    }
    // The proposer rule, applied before the seed is derived so the audit record says
    // `excluded` for every one of the proposer's boxes instead of leaving it to whichever
    // filter happened to bite first.
    .excluding(&roster, &proposer)?;
    let mut round = Round::open(&inputs, &roster, &secret)?;
    // Before the signature, because the mode is inside what the selector signs.
    if let Some(mode) = args.get("--reveal-mode") {
        round.set_reveal_mode(mode).map_err(|error| {
            CliError::refused(
                format!("--reveal-mode {mode}: {error}"),
                format!(
                    "this build enforces \"{}\" and \"{}\"; a mode it cannot check is refused \
                     rather than opened as \"open\"",
                    gitiup_quorum::round::REVEAL_MODE_OPEN,
                    gitiup_quorum::round::REVEAL_MODE_SEALED,
                ),
            )
        })?;
    }
    let entry = round.sign(&selector)?;
    let selection = round.selection(&roster)?;
    let check = ProposerExclusion::check(&roster, &inputs, &selection, &proposer);
    if !check.held() {
        return Err(CliError::refused(
            check.describe(),
            "the exclusion was applied and this round still lets the proposer's box into the \
             pool; that is a bug in the exclusion, not a policy to negotiate",
        ));
    }
    notes.push(format!(
        "the seed is keyed on the selector key {}; it is secret until this round is \
         published and public from then on (ADR-0002 D11)",
        short(&entry.key_id)
    ));
    Ok(Outcome {
        mode: "derive",
        selectors: Some(vec![entry.key_id]),
        seed_source: format!(
            "derived from the selector key {} (ADR-0002 D2)",
            short(&selector.key_id())
        ),
        round_source: store::round_ref(change, job, attempt)?.as_str().to_string(),
        roster,
        roster_source,
        trusted_via,
        selection,
        proposer,
        check,
        notes,
        round,
    })
}

/// The selection secret: derived from the selector's Ed25519 seed (ADR-0002 D2) or, for a
/// selector who holds no seed to derive from, read from `--seed-file`.
///
/// An agent-backed key cannot be a selector *by derivation*, and that is not a limitation
/// to paper over: `HKDF-Extract(salt, ikm = seed)` needs the seed, and an agent — correctly
/// — will not hand it out. The explicit alternative is a delegated selector with its own
/// 32-byte secret, which is what `--seed-file` is for and what the ADR allows for a selector
/// who is not the roster signer.
pub(crate) fn selection_secret(
    args: &Args,
    selector: &gitiup_keys::signer::Key,
) -> Result<SelectionSecret, CliError> {
    if let Some(path) = args.get("--seed-file") {
        return read_secret_file(path);
    }
    match selector {
        gitiup_keys::signer::Key::Sealed { signing, .. } => {
            Ok(SelectionSecret::from_signing_key(signing))
        }
        gitiup_keys::signer::Key::ViaAgent { .. } => Err(CliError::refused(
            format!(
                "the selector key {} is held by an agent, which will not give up its seed",
                short(&selector.key_id())
            ),
            "the round seed is HKDF-Extract over the selector's Ed25519 seed (ADR-0002 D2). \
             Choose a keystore key with --key <name>, import one with `gitiup key import \
             seed`, or give a delegated selector's secret with --seed-file <path|->",
        )),
    }
}

/// 32 raw bytes, or 64 hex characters, from a file or a pipe.
pub(crate) fn read_secret_file(path: &str) -> Result<SelectionSecret, CliError> {
    let bytes = read_maybe_stdin(path)?;
    secret_from_bytes(&bytes).map_err(|error| {
        CliError::refused(
            format!("--seed-file '{path}' is neither 32 raw bytes nor 64 hex characters"),
            error
                .hint
                .unwrap_or_else(|| "it is the selector's 32-byte secret".to_string()),
        )
    })
}

/// The same rule without the file: 32 raw bytes, or 64 hex characters (trailing whitespace
/// allowed, because a hex secret that arrives through a pipe usually has a newline).
///
/// The two spellings exist because the secret will be copied out of a password manager in
/// one and written by a provisioning script in the other. Neither gets a third form: a
/// secret that is silently zero-padded to 32 bytes is a different secret, and a selector
/// with a different secret derives a different seed and a different jury.
fn secret_from_bytes(bytes: &[u8]) -> Result<SelectionSecret, CliError> {
    if let Ok(exactly) = <[u8; 32]>::try_from(bytes) {
        return Ok(SelectionSecret::from_extracted(&exactly));
    }
    let text = String::from_utf8_lossy(bytes).trim().to_ascii_lowercase();
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("checked hex");
        }
        return Ok(SelectionSecret::from_extracted(&out));
    }
    Err(CliError::refused(
        "a selection secret is 32 raw bytes or 64 hex characters",
        "it is the `ikm` of HKDF-Extract (ADR-0002 D2) for a delegated selector: 32 bytes, \
         held like a passphrase, and never printed",
    ))
}

/// The policy the flags describe.
fn policy_from(args: &Args) -> Result<SelectionPolicy, CliError> {
    let mut policy = match args.get("--policy") {
        Some(path) => {
            serde_json::from_slice::<SelectionPolicy>(&read_maybe_stdin(path)?).map_err(|e| {
                CliError::refused(
                    format!("{path}: {e}"),
                    "`gitiup select help` lists the fields; a policy document is the same \
                     object a round record carries",
                )
            })
        }
        None => Ok(SelectionPolicy::default()),
    }?;
    let number = |flag: &str, text: &str| -> Result<usize, CliError> {
        text.parse::<usize>()
            .map_err(|_| CliError::usage(format!("{flag} wants a whole number, got '{text}'")))
    };
    if let Some(text) = args.get("--n") {
        policy.n = number("--n", text)?;
    }
    if let Some(text) = args.get("--required-agree") {
        policy.required_agree = number("--required-agree", text)?;
    }
    if let Some(text) = args.get("--reserves") {
        policy.reserves = number("--reserves", text)?;
    }
    if let Some(text) = args.get("--max-per-identity") {
        policy.max_per_identity = number("--max-per-identity", text)? as u32;
    }
    if let Some(text) = args.get("--tier-floor") {
        policy.tier_floor = RosterTier::parse(text)?;
    }
    for pair in args.all("--tier-cap") {
        let Some((tier, cap)) = pair.split_once('=') else {
            return Err(CliError::usage(format!(
                "--tier-cap wants tier=n (for example endorsed=4), got '{pair}'"
            )));
        };
        let cap = cap
            .parse::<u32>()
            .map_err(|_| CliError::usage(format!("--tier-cap wants tier=n, got '{pair}'")))?;
        policy.tier_caps.insert(tier.trim().to_string(), cap);
    }
    // The library's own check, wrapped so the advice is the CLI's: the defaults are a
    // 4-of-5 quorum with a 4-seat endorsed cap, and those numbers have to come down
    // together with `--n`. Refusing to lower them silently is the point; refusing to say
    // which knob to turn is just a wall.
    policy.validate().map_err(|error| {
        CliError::refused(
            format!("policy: {error}"),
            "a cap or threshold above the seat count says nothing new, so shrink it with the \
             seat count: `--n 3 --required-agree 2 --tier-cap endorsed=3`, or pass the whole \
             policy in `--policy`.",
        )
    })?;
    Ok(policy)
}

/// Print, write, and (in derive mode) publish.
fn report(args: &Args, outcome: &Outcome) -> Result<(), CliError> {
    let bytes = outcome.round.canonical_bytes()?;
    let written = match args.get("--out") {
        Some(path) => {
            write_out(path, &bytes)?;
            Some(if path == "-" {
                "stdout".to_string()
            } else {
                path.to_string()
            })
        }
        None => None,
    };
    let published = if args.on("--publish") {
        let opened = participant::need_store(args)?;
        let oid = store::publish_round(&*opened.host, &outcome.round)?;
        Some(format!(
            "{} · {} ({} in kv/round)",
            opened.what,
            outcome.round_source,
            oid.hex()
        ))
    } else {
        None
    };
    let sink = Sink { written, published };
    let explain = args
        .on("--explain")
        .then(|| outcome.selection.explain(&outcome.roster));
    if only_bytes(args) {
        return Ok(());
    }
    if args.json() {
        print_json(outcome.json(explain.as_deref(), &sink.json()));
        return Ok(());
    }
    outcome.text(explain.as_deref());
    for line in sink.lines() {
        println!("{line}");
    }
    if sink.published.is_none() && outcome.mode == "derive" {
        println!(
            "not published: --publish writes the round record to the store, and until it does \
             the seed is secret and nobody else can check this selection"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags the audit path refuses, and the flags the command actually has.
    ///
    /// A `DERIVE_ONLY` flag that is not in the parser's vocabulary would be refused for a
    /// rule nobody can type, and — the one that matters — a policy flag added later without
    /// adding it here would quietly let an auditor restate a published round.
    #[test]
    fn every_derive_only_flag_is_a_flag_the_command_has() {
        for flag in DERIVE_ONLY {
            assert!(
                VALUED.contains(flag) || SWITCHES.contains(flag),
                "{flag} is refused in audit mode but is not a flag `select` parses"
            );
        }
        for flag in [
            "--head",
            "--n",
            "--required-agree",
            "--reserves",
            "--max-per-identity",
            "--tier-floor",
            "--tier-cap",
            "--policy",
            "--exclude",
            "--require-arch",
            "--require-ram-mb",
            "--require-disk-mb",
            "--require-sandbox",
            "--require-min-sandbox-level",
            "--require-image",
        ] {
            assert!(
                DERIVE_ONLY.contains(&flag),
                "{flag} decides a selection, so an audit must refuse it"
            );
        }
    }

    #[test]
    fn a_selection_secret_is_32_bytes_or_64_hex_and_nothing_else() {
        assert!(secret_from_bytes(&[0x42u8; 32]).is_ok());
        let hex = "ab".repeat(32);
        assert!(secret_from_bytes(hex.as_bytes()).is_ok());
        // A pipe adds a newline; that does not change the secret.
        assert_eq!(
            secret_from_bytes(format!("{hex}\n").as_bytes())
                .unwrap()
                .as_bytes(),
            secret_from_bytes(hex.as_bytes()).unwrap().as_bytes()
        );
        // A truncated file is a truncation, not a secret to be padded out: 31 bytes and a
        // 63-character hex string are both refused with the refusal code.
        assert_eq!(secret_from_bytes(&[1u8; 31]).unwrap_err().code, 6);
        assert_eq!(secret_from_bytes(b"abcd").unwrap_err().code, 6);
        assert!(secret_from_bytes(format!("{}zz", &hex[..62]).as_bytes()).is_err());
    }

    #[test]
    fn policy_flags_meet_the_document_and_the_library_validates_the_result() {
        let args = Args::parse_with(
            &[
                "--n".to_string(),
                "3".to_string(),
                "--required-agree".to_string(),
                "2".to_string(),
                "--tier-cap".to_string(),
                "endorsed=3".to_string(),
            ],
            VALUED,
            SWITCHES,
        )
        .expect("parses");
        let policy = policy_from(&args).expect("three seats needing two agreements is valid");
        assert_eq!(policy.n, 3);
        assert_eq!(policy.required_agree, 2);
        assert_eq!(policy.cap_for(RosterTier::Endorsed), 3);
        // A flag that does not mention a knob leaves the default alone — the default the
        // crate quotes in docs and config templates, not a private literal.
        assert_eq!(policy.reserves, gitiup_quorum::defaults::RESERVES);
        assert_eq!(policy.max_per_identity, 1);
        // Asking for more agreement than there are seats is refused before a round record
        // is ever built, with the refusal code.
        let impossible = Args::parse_with(
            &[
                "--n".to_string(),
                "3".to_string(),
                "--required-agree".to_string(),
                "5".to_string(),
                "--tier-cap".to_string(),
                "endorsed=3".to_string(),
            ],
            VALUED,
            SWITCHES,
        )
        .expect("parses");
        assert_eq!(policy_from(&impossible).unwrap_err().code, 6);
        // And a half-lowered policy — fewer seats, but the old 4-of-5 threshold and the old
        // 4-seat endorsed cap — is refused with the advice that fixes it, rather than
        // quietly keeping a cap that can no longer bind.
        let half = Args::parse_with(&["--n".to_string(), "3".to_string()], VALUED, SWITCHES)
            .expect("parses");
        let error = policy_from(&half).unwrap_err();
        assert_eq!(error.code, 6);
        assert!(
            error.hint.unwrap().contains("--tier-cap"),
            "the refusal has to say which knob to lower"
        );
    }

    #[test]
    fn a_score_is_shortened_for_a_terminal_and_not_for_a_record() {
        assert_eq!(short_hex("0123456789abcdef"), "0123456789ab\u{2026}");
        assert_eq!(short_hex("short"), "short");
    }
}

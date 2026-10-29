//! Where attestations live in a store, and how long they stay there (giti-1rs.5).
//!
//! An attestation is *signed bytes*, so the two jobs of this module are to keep
//! those bytes verbatim and to make them findable. Everything else — what the
//! manifest says, whether a signature checks out, who to trust — is
//! [`gitiup-attest`](https://crates.io/crates/gitiup-attest)'s, and this module
//! deliberately never parses an attestation: it stores bytes, names refs and
//! applies a retention policy to plain data the caller extracts from the signed
//! document. That split is what lets the same code serve a store that must not
//! parse what it holds.
//!
//! ```text
//! kv/attestation/<digest>                    sha256(canonical attestation bytes)
//! refs/attestations/<subject>/<digest>       the advertisement: one ref per proof
//! kv/gc/<digest>                             one record per retention run
//! ```
//!
//! The ref is *keyed by the subject first* — the digest of the thing attested —
//! because "give me the proof about this object" is the question every consumer
//! asks, and on a git-backed host a `git fetch 'refs/attestations/<subject>/*'`
//! then arrives with every proof for that commit in one packfile. The attestation's
//! own digest is the leaf, so a commit may carry many attestations (several signers,
//! several runs, several tiers) instead of the one a single-level ref could hold,
//! and each is individually create-only: two contributors publishing the same proof
//! cannot overwrite each other, and two publishing different proofs both land.
//!
//! # What retirement means, and what it does not
//!
//! `plan` decides, [`apply`] acts, and the two are separate so a `gc` can be read
//! before it is run. Applying a plan removes *advertisements*: the ref goes with a
//! compare-and-swap, and a record of the run is written to `kv/gc/` so the store can
//! still answer "where did that proof go, and why".
//!
//! The bytes themselves are only un-written where the host can honestly forget
//! ([`BlobStore::purge_cas`]) and the operator asked for it. A git store's record
//! chain is append-only and a versioned bucket keeps history by contract, so on
//! those hosts gc unpublishes and says so instead of pretending to reclaim space —
//! which is the same refusal the rest of the crate makes when a host cannot promise
//! something.
//!
//! # The two shapes, and how one becomes the other
//!
//! Older gitiup filed one proof per subject at `refs/attestations/<subject>` — legal,
//! readable, and unable to hold a second signer, a second run or a second tier. That
//! shape is [`legacy_ref_name`], it is still *read* (a listing flags it `legacy`), and
//! nothing in this build writes it. [`migrate`] moves the ones a store already has:
//! it re-publishes each under `<subject>/<digest>` and only then retires the old ref,
//! so a proof is never advertised by less than it was before, and it reports what it
//! refused to move instead of quietly leaving it behind. `publish` will not silently
//! take over a subject whose legacy ref is in the way — a ref cannot be both a leaf
//! and a directory — it says so and names `migrate`.
//!
//! # The rule that is not a policy knob
//!
//! **An object a live ref still points at is never pruned.** [`referenced`] collects
//! the digests refs outside the attestation namespace point at, and that covers the
//! case that matters most without any special knowledge of it: a quorum keeps each
//! verifier's submission in this same content-addressed store and advertises it under
//! `refs/gitiup/reveal/<change>/<job>/<slot>`, so sweeping a finished round's evidence
//! out from under a published verdict is impossible, and there is no flag that forces
//! it. A pinned digest is reported as `pinned`, never as pruned.
//!
//! What a ref scan cannot see is a digest named *inside* some other record — a merge
//! record's `attestation` field, a verdict's contributing list — because a string in a
//! document is a claim about that document, not an advertisement of an object. That
//! gap is closed by the caller that reads the record: [`pin`] adds the digest to the
//! pin set, and `gitiup attest gc --keep <digest>` is the same thing from the command
//! line. Inventing a scanner that guessed which strings in which records meant "do not
//! delete this" would be a rule an operator could not predict, which is worse than an
//! explicit one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Host;
use crate::blob::Namespace;
use crate::error::{HostError, HostErrorExt, HostResult};
use crate::oid::Oid;
use crate::refs::{Actor, Expect, RefDeletion, RefName, RefQuery, RefUpdate, ns};
use crate::time::Timestamp;

/// Schema version of the records this module writes (`kv/gc/…`).
pub const SCHEMA_VERSION: u32 = 1;

/// Namespace of the records a retention run leaves behind.
pub const GC_NAMESPACE: Namespace = Namespace::const_new("gc");

/// Microseconds in a second, day and week: the units a retention policy is written
/// in, kept here so `gc` and a policy file agree on what `90d` costs.
pub const MICROS: i64 = 1_000_000;
/// Microseconds in a day.
pub const MICROS_PER_DAY: i64 = 86_400 * MICROS;
/// Microseconds in a week.
pub const MICROS_PER_WEEK: i64 = 7 * MICROS_PER_DAY;

// --------------------------------------------------------------------------
// naming
// --------------------------------------------------------------------------

/// `refs/attestations/<subject>/<digest>` — the ref that publishes one proof.
pub fn ref_name(subject: &Oid, digest: &Oid) -> RefName {
    // Both components are hex, which is always a legal ref component.
    RefName::attestation(subject)
        .join(digest.hex().as_str())
        .expect("hex component")
}

/// `refs/attestations/<subject>/` — the prefix every proof for one subject lives
/// under, and what a fetch of a commit's proof asks for.
///
/// The trailing separator is part of the answer, not decoration: a ref listing is a
/// string match, and without it a subject would match any longer name that happens to
/// start with its hex.
pub fn prefix(subject: &Oid) -> String {
    format!("{}/", RefName::attestation(subject).as_str())
}

/// The `(subject, digest)` a `refs/attestations/**` ref names, when it is shaped
/// like this layout.
///
/// Returns `None` for anything else — a deeper name, garbage, or the single-level
/// spelling [`legacy_ref_name`] still finds in older stores. Those are *not* a
/// mystery and are not skipped either: [`parse_legacy_ref`] reads them, and a
/// listing reports what it cannot read at all. A caller that is listing
/// attestations has to be able to tell the two shapes apart rather than mis-read
/// one as the other.
pub fn parse_ref(name: &RefName) -> Option<(Oid, Oid)> {
    let rest = name.attestation_target()?;
    let (subject, digest) = rest.split_once('/')?;
    if digest.contains('/') {
        return None;
    }
    Some((Oid::from_hex(subject).ok()?, Oid::from_hex(digest).ok()?))
}

/// `refs/attestations/<subject>` — the *legacy* single-level spelling of this
/// namespace, which is what gitiup filed before a subject needed more than one
/// proof.
///
/// It is legal git and it is still *read*: it advertises exactly one attestation
/// per subject, which is the whole reason it was replaced (a second signer, a
/// second run or a second tier would have to overwrite the first). It is never
/// written by anything in this build, and [`migrate`] moves ones that exist.
pub fn legacy_ref_name(subject: &Oid) -> RefName {
    RefName::attestation(subject)
}

/// The subject a legacy single-level ref advertises a proof about, when the name
/// is one (`refs/attestations/<hex-of-the-commit>`, nothing deeper).
///
/// The *name* is the subject and the ref's *value* is the attestation digest — the
/// opposite way round from a listing caller's intuition, and worth stating: this
/// shape can only say "about this commit", so the digest has nowhere to live but
/// in the value.
pub fn parse_legacy_ref(name: &RefName) -> Option<Oid> {
    let rest = name.attestation_target()?;
    if rest.contains('/') {
        return None;
    }
    Oid::from_hex(rest).ok()
}

/// Parse a duration for a retention limit: `45d`, `2w`, `36h`, `90m`, `30s`, or a
/// bare number of seconds. `never`, `off`, `none` and `0` mean "no limit".
///
/// Returns microseconds, because that is the unit every timestamp in a manifest is
/// in; the conversion happens once, here, so a `gc` cannot be off by a factor of a
/// million in either direction.
pub fn parse_age(text: &str) -> HostResult<Option<i64>> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() || matches!(text.as_str(), "never" | "off" | "none" | "0" | "0s") {
        return Ok(None);
    }
    let unit_micros = match text.chars().last() {
        Some('s') => (MICROS, &text[..text.len() - 1]),
        Some('m') => (60 * MICROS, &text[..text.len() - 1]),
        Some('h') => (3_600 * MICROS, &text[..text.len() - 1]),
        Some('d') => (MICROS_PER_DAY, &text[..text.len() - 1]),
        Some('w') => (MICROS_PER_WEEK, &text[..text.len() - 1]),
        _ => (MICROS, text.as_str()),
    };
    let (micros, digits) = unit_micros;
    let digits = digits.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            HostError::invalid("retention", format!("'{text}' is not an age"))
                .with_hint("use 90s, 24h, 30d, 2w, or a number of seconds; 'never' for no limit"),
        );
    }
    let count: i64 = digits.parse().map_err(|_| {
        HostError::invalid("retention", format!("'{text}' is too large to be an age"))
    })?;
    count
        .checked_mul(micros)
        .ok_or_else(|| HostError::invalid("retention", format!("'{text}' overflows a timestamp")))
        .map(Some)
}

// --------------------------------------------------------------------------
// publishing and reading
// --------------------------------------------------------------------------

/// What [`publish`] did, in the terms the caller needs to report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Published {
    /// `sha256(bytes)`: the key the bytes are stored under.
    pub digest: Oid,
    /// The ref that advertises them.
    pub reference: RefName,
    /// Whether the proof was already published here (a re-push, not a change).
    pub already: bool,
    /// Size of the bytes stored.
    pub size: u64,
}

/// Publish one attestation: the bytes first, then the ref that points at them.
///
/// The order is the whole point of the function and must not be reordered: a ref
/// that names bytes no reader can fetch is a broken proof, while bytes nobody has
/// advertised yet are only unread. It is also what a git-backed host needs — the
/// ref write wraps the record into a pointer commit, and it can only do that from
/// the object the previous line stored.
///
/// Both writes are create-only ([`Expect::Absent`]), so publishing the same bytes
/// twice is `already = true` rather than a conflict, and publishing *different*
/// bytes for the same subject is a second ref rather than a lost update.
pub fn publish(
    host: &dyn Host,
    subject: &Oid,
    bytes: &[u8],
    actor: impl Into<Actor>,
) -> HostResult<Published> {
    // A ref cannot be both a leaf and a directory. The single-level spelling of this
    // namespace is legal git and an older gitiup wrote it; say so rather than let the
    // store answer with a transport-level name-conflict error. `migrate` is the way
    // out, and it is the one caller allowed past this guard.
    let leaf = legacy_ref_name(subject);
    if let Some(existing) = host.get_ref(&leaf)? {
        return Err(HostError::invalid(
            "attestation ref",
            format!(
                "{leaf} already exists as a single ref ({}), so attestations for this subject \
                 cannot be published under {leaf}/…",
                existing.oid.short_default()
            ),
        )
        .with_hint(
            "this store holds one attestation ref for this subject in the old single-ref shape; \
             move it with `gitiup attest migrate` (or gitiup_host::attest::migrate), which \
             reads the proof, files it under <subject>/<digest> and only then retires the old ref",
        ));
    }
    publish_new(host, subject, bytes, actor)
}

/// The two writes of a publish, without the legacy-leaf guard.
///
/// This is what [`migrate`] files the moved proof with: the ref standing in the way
/// is the one the migration is about to retire, and the new advertisement still goes
/// down before that one is removed.
pub(crate) fn publish_new(
    host: &dyn Host,
    subject: &Oid,
    bytes: &[u8],
    actor: impl Into<Actor>,
) -> HostResult<Published> {
    let actor = actor.into();
    let digest = Oid::hash_bytes(bytes);
    let reference = ref_name(subject, &digest);

    let stored = host.put_cas(&Namespace::ATTESTATION, bytes)?;
    if stored != digest {
        // A store that returns a digest other than the bytes' own cannot be
        // trusted to hold them verbatim, and a signature over bytes the store
        // rewrote is worthless. Refuse loudly rather than publish a broken proof.
        return Err(HostError::invalid(
            "attestation store",
            format!(
                "the store filed {} bytes under {} instead of {}",
                bytes.len(),
                stored.short_default(),
                digest.short_default()
            ),
        )
        .with_hint("this host is not storing blobs verbatim; nothing signed can be trusted here"));
    }

    let update = RefUpdate::create(reference.clone(), digest)
        .with_actor(actor.clone())
        .with_message(format!("attest {}", digest.short_default()));
    match host.update_ref_cas(&update) {
        Ok(_) => Ok(Published {
            digest,
            reference,
            already: false,
            size: bytes.len() as u64,
        }),
        Err(error) if error.kind() == crate::HostErrorKind::Conflict => {
            let found = host.get_ref(&reference)?;
            match found {
                // Same bytes, same ref: idempotent, which is what a retry after a
                // dropped connection needs to be.
                Some(reference) if reference.oid == digest => Ok(Published {
                    digest,
                    reference: reference.name,
                    already: true,
                    size: bytes.len() as u64,
                }),
                _ => Err(error.with_hint(format!(
                    "{} is already published under this subject and points elsewhere; a second \
                     proof gets its own ref, it never overwrites one",
                    digest.short_default()
                ))),
            }
        }
        Err(error) => Err(error),
    }
}

/// One published attestation as the store sees it: names, digests and metadata,
/// with no claim to know what the bytes mean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The object the attestation is about (the ref's first component).
    pub subject: Oid,
    /// `sha256(attestation bytes)`: also the blob key.
    pub digest: Oid,
    /// The ref advertising it.
    pub reference: RefName,
    /// Who published it, when the host records actors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Actor>,
    /// When it was published, when the host records times.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// Size in bytes, when the store would say so without a fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Whether this proof is filed in the legacy single-level shape (`legacy: true`,
    /// omitted otherwise, so the JSON a script reads is unchanged for current
    /// layouts). The proof is just as valid; what it lacks is room for a second one
    /// about the same subject, and [`migrate`] moves it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy: bool,
}

/// What a listing found, plus what it refused to guess about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    /// The attestations this module's layout describes, sorted by `(subject, digest)`.
    /// Legacy single-level proofs are here too, flagged `legacy`.
    pub entries: Vec<Entry>,
    /// `refs/attestations/**` names that are neither layout — a directory someone
    /// invented, or a single-level ref whose hex is its own value (a digest
    /// advertised by digest, which names no subject at all). Reported rather than
    /// skipped: a listing that silently drops a ref is how "there is no proof"
    /// becomes a lie.
    pub unexpected: Vec<String>,
}

impl Catalog {
    /// Nothing found.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.unexpected.is_empty()
    }

    /// The proofs filed in the legacy single-level shape, in the same order as
    /// [`Catalog::entries`] — the ones `gitiup attest migrate` would move.
    pub fn legacy(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|entry| entry.legacy).collect()
    }
}

/// Every attestation published for one subject.
pub fn list_for(host: &dyn Host, subject: &Oid) -> HostResult<Catalog> {
    scan(host, Some(subject))
}

/// Every attestation in the store.
pub fn list_all(host: &dyn Host) -> HostResult<Catalog> {
    scan(host, None)
}

fn scan(host: &dyn Host, subject: Option<&Oid>) -> HostResult<Catalog> {
    let query = match subject {
        Some(subject) => RefQuery::prefix(prefix(subject)),
        None => RefQuery::prefix(ns::ATTESTATIONS),
    };
    let refs = host.list_refs(&query)?;
    let mut catalog = Catalog::default();
    for reference in refs {
        match parse_ref(&reference.name) {
            Some((parsed_subject, digest)) => catalog.entries.push(Entry {
                subject: parsed_subject,
                digest,
                reference: reference.name,
                updated_by: reference.updated_by,
                updated_at: reference.updated_at,
                size: None,
                legacy: false,
            }),
            None => match parse_legacy_ref(&reference.name) {
                Some(subject) if reference.oid.hex() != subject.hex() => {
                    catalog.entries.push(Entry {
                        subject,
                        digest: reference.oid,
                        reference: reference.name,
                        updated_by: reference.updated_by,
                        updated_at: reference.updated_at,
                        size: None,
                        legacy: true,
                    })
                }
                // Either not a hex name at all, or a ref named by the digest it
                // points at: it advertises a proof without naming what the proof
                // is about, so no reading of it is honest. Say so; do not guess.
                _ => catalog.unexpected.push(reference.name.as_str().to_string()),
            },
        }
    }
    catalog.entries.sort_by(|a, b| {
        a.subject
            .hex()
            .cmp(&b.subject.hex())
            .then(a.digest.hex().cmp(&b.digest.hex()))
    });
    Ok(catalog)
}

/// Fetch the attestation bytes a digest names. `Ok(None)` when absent.
///
/// The bytes come back exactly as stored — that is the contract the signature is
/// checked against — so a caller verifying one should hand these to
/// `AttestationDoc::from_canonical_bytes` and let the digest say whether the store
/// was honest.
pub fn fetch(host: &dyn Host, digest: &Oid) -> HostResult<Option<Vec<u8>>> {
    host.get(digest)
}

/// Size of a stored attestation without transferring it, when the host can say.
pub fn size(host: &dyn Host, digest: &Oid) -> HostResult<Option<u64>> {
    Ok(host.head(digest)?.map(|entry| entry.size))
}

// --------------------------------------------------------------------------
// pinning
// --------------------------------------------------------------------------

/// Every object a live ref still points at, *outside* `refs/attestations/**`,
/// mapped to the first ref that pins it.
///
/// This is the store's own answer to "is anything still using this?". A quorum seat
/// submission is a ref (`refs/gitiup/reveal/…`), a verdict is a ref, a change's
/// merge record is a ref, so anything those point at is pinned without the store
/// knowing what a quorum or a merge is — and without the operator remembering to
/// pass a flag.
pub fn referenced(host: &dyn Host) -> HostResult<BTreeMap<Oid, String>> {
    let mut pins = BTreeMap::new();
    for reference in host.list_refs(&RefQuery::all())? {
        if reference.name.is_attestation() {
            continue;
        }
        pins.entry(reference.oid)
            .or_insert_with(|| reference.name.as_str().to_string());
    }
    Ok(pins)
}

/// A caller-side pin: a digest that must survive because something the store cannot
/// see still references it — a merge record's `attestation` field, a verdict's
/// contributing list, an operator's `--keep`.
///
/// This is the deliberate answer to what [`referenced`] cannot see: a digest named
/// inside another record is not a ref, so whoever read that record has to say so here.
/// Guessing instead — treating every hex string in every blob as a reference — would
/// make retention unpredictable, and an unpredictable retention rule is one that gets
/// turned off.
pub fn pin(pins: &mut BTreeMap<Oid, String>, digest: Oid, why: impl Into<String>) {
    pins.entry(digest).or_insert_with(|| why.into());
}

// --------------------------------------------------------------------------
// reconciling the two shapes
// --------------------------------------------------------------------------

/// Namespace of the records [`migrate`] leaves behind.
pub const MIGRATE_NAMESPACE: Namespace = Namespace::const_new("migrate");

/// One legacy single-level ref, and the proof it advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyProof {
    /// The object the legacy ref names — the subject.
    pub subject: Oid,
    /// The digest the legacy ref points at: the attestation itself.
    pub digest: Oid,
    /// The legacy ref's own name.
    pub reference: String,
}

/// Every legacy single-level attestation ref in the store.
///
/// These are read like any other proof and are never silently rewritten: [`migrate`]
/// moves one only when it is asked to, and refuses when it cannot first put a better
/// advertisement in place.
pub fn legacy_proofs(host: &dyn Host) -> HostResult<Vec<LegacyProof>> {
    Ok(list_all(host)?
        .legacy()
        .into_iter()
        .map(|entry| LegacyProof {
            subject: entry.subject,
            digest: entry.digest,
            reference: entry.reference.as_str().to_string(),
        })
        .collect())
}

/// What [`migrate`] should do, beyond finding the refs.
#[derive(Debug, Clone)]
pub struct MigrationOptions {
    /// Who is running this, recorded in the new ref and the deleted one.
    pub actor: Actor,
    /// Decide and report, change nothing. The default, because the thing being moved
    /// is a signed proof and the operator should read the list first.
    pub apply: bool,
    /// Write the `kv/migrate/…` record of this run (only when it applied and moved
    /// something).
    pub record: bool,
}

impl Default for MigrationOptions {
    fn default() -> MigrationOptions {
        MigrationOptions {
            actor: Actor::from_env(),
            apply: false,
            record: true,
        }
    }
}

/// One proof that moved (or would move).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovedProof {
    /// What it attests to.
    pub subject: Oid,
    /// The attestation's digest, unchanged: moving a ref never re-writes bytes.
    pub digest: Oid,
    /// The single-level ref it was filed under.
    pub from: String,
    /// The `<subject>/<digest>` ref it is filed under (or would be).
    pub to: String,
    /// Whether the old ref is gone. `false` in a dry run, always.
    pub retired: bool,
}

/// One proof that could not be moved, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProof {
    /// The legacy ref.
    pub reference: String,
    /// The digest it advertises, when the name said so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Oid>,
    /// Why it stays where it is, in the caller's own words.
    pub why: String,
}

/// A migration run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Schema of this record.
    pub schema_version: u32,
    /// The clock it ran against (microseconds since the epoch).
    pub now_us: i64,
    /// Who ran it.
    pub actor: String,
    /// Whether anything was changed.
    pub dry_run: bool,
    /// Every proof that moved, or would have.
    pub moved: Vec<MovedProof>,
    /// Every proof that stayed, and the reason.
    pub blocked: Vec<BlockedProof>,
    /// Proofs a *previous* run left with no advertisement — a crash between retiring
    /// the old ref and filing the new one — that this run re-filed. Repair is part of
    /// every applying run, so a half-finished move heals on the next invocation
    /// instead of waiting for someone to notice bytes with no ref.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repaired: Vec<MovedProof>,
    /// How many single-level refs are left after this run (in a dry run, how many
    /// would be: the blocked ones, since every movable ref moves).
    pub remaining: usize,
    /// The `kv/migrate/…` record of this run, when one was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Oid>,
}

impl MigrationReport {
    /// One line for a human.
    pub fn summary_line(&self) -> String {
        let verb = if self.dry_run { "would move" } else { "moved" };
        if self.moved.is_empty() && self.blocked.is_empty() {
            return "no legacy attestation refs".to_string();
        }
        let mut line = format!("{verb} {} legacy attestation ref(s)", self.moved.len());
        if !self.blocked.is_empty() {
            line.push_str(&format!("; {} blocked", self.blocked.len()));
        }
        if self.remaining > 0 {
            line.push_str(&format!("; {} left single-level", self.remaining));
        }
        line
    }
}

/// Move every legacy single-level attestation ref to `<subject>/<digest>`.
///
/// The order per proof is: note the intent, retire the old advertisement, file the
/// new one, and put it back if filing it failed. That is the reverse of [`publish`]'s
/// bytes-then-ref order, and it has to be: a ref cannot be a leaf and a directory at
/// once, so on a git-backed store the old name has to go before the new one can
/// exist. The intent record written first is what makes that window recoverable —
/// every applying run starts by re-filing the proofs a previous run's records say it
/// was mid-way through, so a crash between the two ref writes is repaired by the next
/// `migrate` rather than discovered by an audit.
///
/// A proof whose bytes the store cannot return is `blocked`, not deleted: the legacy
/// ref may be the only thing that proves those bytes were ever published, and
/// retiring the advertisement of a document that cannot be read is a second,
/// unrelated act that retention (`gc`) gets to decide.
pub fn migrate(host: &dyn Host, options: &MigrationOptions) -> HostResult<MigrationReport> {
    let now_us = Timestamp::now().as_unix() as i64 * MICROS;
    let repaired = if options.apply {
        repair(host, &options.actor)?
    } else {
        Vec::new()
    };
    let mut moved = Vec::new();
    let mut blocked = Vec::new();
    for proof in legacy_proofs(host)? {
        let target = ref_name(&proof.subject, &proof.digest);
        let bytes = match fetch(host, &proof.digest) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                blocked.push(BlockedProof {
                    reference: proof.reference,
                    digest: Some(proof.digest),
                    why: format!(
                        "the store cannot return the bytes {} advertises, so there is nothing \
                         to advertise under {target}",
                        proof.digest.short_default()
                    ),
                });
                continue;
            }
            Err(error) => {
                blocked.push(BlockedProof {
                    reference: proof.reference,
                    digest: Some(proof.digest),
                    why: error.message(),
                });
                continue;
            }
        };
        let old_ref = RefName::new(&proof.reference)?;
        if options.apply {
            // 1. Say what is about to happen, in the store, before it happens.
            let intent = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "now_us": now_us,
                "actor": options.actor.as_str(),
                "in_flight": [{
                    "subject": proof.subject.hex(),
                    "digest": proof.digest.hex(),
                    "from": proof.reference,
                    "to": target.as_str(),
                }],
            });
            host.put_json(&MIGRATE_NAMESPACE, &intent)?;
            // 2. Retire the old advertisement (the name has to be free before the
            //    directory form can exist).
            let deletion = RefDeletion::new(old_ref.clone(), Expect::Is(proof.digest))
                .with_actor(options.actor.clone());
            match host.delete_ref_cas(&deletion) {
                Ok(()) => {}
                Err(error) => {
                    let gone = ref_gone(host, &old_ref)?;
                    if !gone {
                        blocked.push(BlockedProof {
                            reference: proof.reference.clone(),
                            digest: Some(proof.digest),
                            why: format!("{} could not be retired: {error}", proof.reference),
                        });
                        continue;
                    }
                }
            }
            // 3. File the new one; put the old one back if that fails.
            if let Err(error) = publish_new(host, &proof.subject, &bytes, options.actor.clone()) {
                let restore = RefUpdate::create(old_ref, proof.digest)
                    .with_actor(options.actor.clone())
                    .with_message("migrate rolled back".to_string());
                let restored = host.update_ref_cas(&restore).is_ok();
                blocked.push(BlockedProof {
                    reference: proof.reference,
                    digest: Some(proof.digest),
                    why: format!(
                        "could not be filed under {target}: {error}{}",
                        if restored {
                            "; the old ref was put back"
                        } else {
                            ", and the old ref could not be put back either — the bytes are \
                             still in the store and a later migrate can re-file them"
                        }
                    ),
                });
                continue;
            }
        }
        moved.push(MovedProof {
            subject: proof.subject,
            digest: proof.digest,
            from: proof.reference,
            to: target.as_str().to_string(),
            retired: options.apply,
        });
    }
    let mut report = MigrationReport {
        schema_version: SCHEMA_VERSION,
        now_us,
        actor: options.actor.as_str().to_string(),
        dry_run: !options.apply,
        remaining: blocked.len(),
        repaired,
        moved,
        blocked,
        record: None,
    };
    if options.record && options.apply && (!report.moved.is_empty() || !report.repaired.is_empty())
    {
        let value = serde_json::to_value(&report)
            .map_err(|e| HostError::invalid("migrate record", format!("cannot encode: {e}")))?;
        let oid = host.put_json(&MIGRATE_NAMESPACE, &value)?;
        report.record = Some(oid);
    }
    Ok(report)
}

/// Re-file the proofs previous migration records say were moved but that no ref now
/// advertises.
///
/// This is the repair half of the crash window: the old ref was retired, the new one
/// was never written (or was deleted since), and the bytes are sitting in the store
/// with nothing pointing at them. Nothing but the record knows they were meant to be
/// findable, which is why the record is written before the swap rather than after.
fn repair(host: &dyn Host, actor: &Actor) -> HostResult<Vec<MovedProof>> {
    let mut repaired = Vec::new();
    for entry in host.list(&MIGRATE_NAMESPACE)? {
        let Some(bytes) = host.get(&entry.oid)? else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(items) = record.get("in_flight").and_then(|v| v.as_array()) else {
            continue;
        };
        for item in items {
            let (Some(subject), Some(digest), Some(to)) = (
                item.get("subject").and_then(|v| v.as_str()),
                item.get("digest").and_then(|v| v.as_str()),
                item.get("to").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let (Ok(subject), Ok(digest)) = (Oid::from_hex(subject), Oid::from_hex(digest)) else {
                continue;
            };
            let Ok(reference) = RefName::new(to) else {
                continue;
            };
            if host.get_ref(&reference)?.is_some() {
                continue; // it was filed after all: nothing to repair
            }
            if let Some(bytes) = fetch(host, &digest)? {
                // Whether this ref is the legacy one or the target, the point is that
                // the proof is advertised again under the shape that holds many.
                let _ = publish_new(host, &subject, &bytes, actor.clone());
                if host.get_ref(&reference)?.is_some() {
                    repaired.push(MovedProof {
                        subject,
                        digest,
                        from: item
                            .get("from")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        to: reference.as_str().to_string(),
                        retired: true,
                    });
                }
            }
        }
    }
    Ok(repaired)
}

// --------------------------------------------------------------------------
// retention
// --------------------------------------------------------------------------

/// The retention policy a `gc` applies.
///
/// Both limits are optional and both are *about the published set*: what they prune
/// is advertisements, and what they never touch is anything pinned (see
/// [`referenced`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Retention {
    /// Prune attestations whose claimed time is older than this. `None` = no age
    /// limit. Age is measured against the *claimed* time inside the signed
    /// document, not the ref's write time, because the store's clock is not the
    /// runner's and a proof must not outlive its own claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_us: Option<i64>,
    /// Keep at most this many attestations per subject, newest first. `None` = no
    /// cap. Position is counted after age, so an expired proof does not consume a
    /// slot a fresh one needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_subject: Option<usize>,
}

impl Retention {
    /// No limits at all: a plan that prunes nothing but pins and reports.
    pub fn none() -> Retention {
        Retention::default()
    }

    /// Parse `--max-age` / `--max-per-commit` into a policy.
    pub fn new(max_age: Option<&str>, max_per_subject: Option<usize>) -> HostResult<Retention> {
        Ok(Retention {
            max_age_us: match max_age {
                Some(text) => parse_age(text)?,
                None => None,
            },
            max_per_subject,
        })
    }

    /// Whether this policy would prune anything at all.
    pub fn is_unbounded(&self) -> bool {
        self.max_age_us.is_none() && self.max_per_subject.is_none()
    }

    /// The policy as one line, for a report or a log.
    pub fn describe(&self) -> String {
        if self.is_unbounded() {
            return "no age or count limit (pinned attestations only)".to_string();
        }
        let mut parts = Vec::new();
        parts.push(match self.max_age_us {
            Some(age) => format!("max age {}", human_age(age)),
            None => "no age limit".to_string(),
        });
        parts.push(match self.max_per_subject {
            Some(max) => format!("keep {max} per subject"),
            None => "no per-subject cap".to_string(),
        });
        parts.join(" · ")
    }
}

/// A day/week/hour rendering of a microsecond duration, for humans.
pub fn human_age(micros: i64) -> String {
    for (unit, micros_per) in [
        ("w", MICROS_PER_WEEK),
        ("d", MICROS_PER_DAY),
        ("h", 3_600 * MICROS),
    ] {
        if micros >= micros_per && micros % micros_per == 0 {
            return format!("{}{unit}", micros / micros_per);
        }
    }
    if micros % (60 * MICROS) == 0 {
        return format!("{}m", micros / (60 * MICROS));
    }
    format!("{}s", micros / MICROS)
}

/// One attestation, reduced to what a retention policy can reason about.
///
/// The caller — the CLI, a store frontend — reads these out of the *signed*
/// document, which is the only trustworthy source for "when was this claimed".
/// `label` is a free-text note for the report (a tier, a signer); a policy never
/// looks at it, so a store that lies about it cannot steer a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationItem {
    /// `sha256(attestation bytes)`.
    pub digest: Oid,
    /// The object it attests to.
    pub subject: Oid,
    /// `claims.claimed_at_us` from the signed manifest.
    pub claimed_at_us: i64,
    /// Size on disk, for a report that adds up to something.
    pub size: u64,
    /// Free text for the report; never an input to a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The ref this item was found under. A caller that read the store will have
    /// it; a caller with a hand-built list may leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Why an attestation survived or went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Inside every limit, and referenced by nothing that would mind.
    Kept,
    /// Kept because something still points at it: a quorum seat, a verdict, a
    /// recorded merge, an explicit keep. Carries what pointed.
    Pinned {
        /// What references it, in the words of whoever pinned it.
        why: String,
    },
    /// Pruned: older than the policy's maximum age.
    Expired {
        /// How old it was, in microseconds.
        age_us: i64,
        /// The limit it missed.
        max_age_us: i64,
    },
    /// Pruned: outside the newest `max` for its subject.
    OverQuota {
        /// Its rank among the subject's freshest proofs (1 is the newest kept).
        position: usize,
        /// The cap.
        max: usize,
    },
}

impl Verdict {
    /// Whether this verdict means "remove the advertisement".
    pub fn is_prune(&self) -> bool {
        matches!(self, Verdict::Expired { .. } | Verdict::OverQuota { .. })
    }

    /// Stable name for `--json` consumers and for sorting.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Kept => "kept",
            Verdict::Pinned { .. } => "pinned",
            Verdict::Expired { .. } => "expired",
            Verdict::OverQuota { .. } => "over-quota",
        }
    }

    /// One line of prose for a human report.
    pub fn describe(&self) -> String {
        match self {
            Verdict::Kept => "within policy".to_string(),
            Verdict::Pinned { why } => format!("pinned: {why}"),
            Verdict::Expired { age_us, max_age_us } => format!(
                "older than the policy's {}: it claimed {} ago",
                human_age(*max_age_us),
                human_age(*age_us)
            ),
            Verdict::OverQuota { position, max } => {
                format!("rank {position} for its commit, over the cap of {max}")
            }
        }
    }
}

/// One item's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanItem {
    /// The attestation this decision is about.
    #[serde(flatten)]
    pub item: AttestationItem,
    /// What was decided, and why.
    pub verdict: Verdict,
}

/// A retention decision: every item, and what happens to each.
///
/// A plan is a pure function of its inputs ([`plan`]), so `gitiup attest gc
/// --dry-run --json` and the run that follows cannot disagree, and a policy can be
/// reviewed as data before anything is deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The clock the plan was computed against (microseconds since the epoch).
    pub now_us: i64,
    /// The policy that produced it.
    pub retention: Retention,
    /// Every item considered, sorted by `(subject, claimed time descending, digest)`
    /// — the order a human reads a store in.
    pub items: Vec<PlanItem>,
}

impl Plan {
    /// The items this plan would prune.
    pub fn pruned(&self) -> Vec<&PlanItem> {
        self.items
            .iter()
            .filter(|item| item.verdict.is_prune())
            .collect()
    }

    /// The items this plan keeps.
    pub fn kept(&self) -> Vec<&PlanItem> {
        self.items
            .iter()
            .filter(|item| !item.verdict.is_prune())
            .collect()
    }

    /// How much is pinned, and so untouchable by any policy.
    pub fn pinned_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| matches!(item.verdict, Verdict::Pinned { .. }))
            .count()
    }

    /// Bytes the pruned items occupy.
    pub fn pruned_bytes(&self) -> u64 {
        self.pruned().iter().map(|item| item.item.size).sum()
    }

    /// Refuse to continue? A plan that prunes nothing is not an error, but a
    /// `gc` that prunes nothing when asked to is worth explaining.
    pub fn reasons_nothing_to_prune(&self) -> Option<String> {
        if !self.pruned().is_empty() {
            return None;
        }
        if self.items.is_empty() {
            return Some("the store holds no attestations".to_string());
        }
        if self.pinned_count() == self.items.len() {
            return Some(format!(
                "all {} are still referenced by a quorum, a merge or a keep",
                self.items.len()
            ));
        }
        Some(format!(
            "nothing is over the policy's limits ({} considered)",
            self.items.len()
        ))
    }
}

/// Decide a retention policy against a set of attestations. Pure: same inputs,
/// same plan, no clock, no store.
///
/// `pinned` is honoured first and cannot be overridden: a digest anything still
/// references is kept no matter how old it is or how many fresher ones exist.
pub fn plan(
    retention: &Retention,
    now_us: i64,
    items: &[AttestationItem],
    pins: &BTreeMap<Oid, String>,
) -> Plan {
    let mut ordered: Vec<&AttestationItem> = items.iter().collect();
    ordered.sort_by(|a, b| {
        a.subject
            .hex()
            .cmp(&b.subject.hex())
            .then(b.claimed_at_us.cmp(&a.claimed_at_us))
            .then(a.digest.hex().cmp(&b.digest.hex()))
    });

    let mut out = Vec::with_capacity(ordered.len());
    let mut subject: Option<Oid> = None;
    let mut kept_for_subject = 0usize;
    for item in ordered {
        if subject != Some(item.subject) {
            subject = Some(item.subject);
            kept_for_subject = 0;
        }
        let verdict = if let Some(why) = pins.get(&item.digest) {
            Verdict::Pinned { why: why.clone() }
        } else if let Some(max_age) = retention.max_age_us {
            let age = now_us - item.claimed_at_us;
            if age > max_age {
                Verdict::Expired {
                    age_us: age,
                    max_age_us: max_age,
                }
            } else {
                kept_for_subject += 1;
                over_quota(item, retention, kept_for_subject)
            }
        } else {
            kept_for_subject += 1;
            over_quota(item, retention, kept_for_subject)
        };
        out.push(PlanItem {
            item: item.clone(),
            verdict,
        });
    }
    Plan {
        now_us,
        retention: *retention,
        items: out,
    }
}

/// The per-subject cap, applied to the `position`-th freshest kept item.
fn over_quota(item: &AttestationItem, retention: &Retention, position: usize) -> Verdict {
    match retention.max_per_subject {
        Some(max) if position > max => Verdict::OverQuota { position, max },
        _ => {
            let _ = item;
            Verdict::Kept
        }
    }
}

/// What [`apply`] should do, beyond the plan itself.
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Who is running this, recorded in the ref deletion and the gc record.
    pub actor: Actor,
    /// Also ask the host to forget the bytes. The host may refuse, and says so in
    /// the report rather than in a silently smaller disk usage.
    pub purge_blobs: bool,
    /// Decide and report, change nothing.
    pub dry_run: bool,
    /// Write the `kv/gc/…` record of this run.
    pub record: bool,
}

impl Default for GcOptions {
    fn default() -> GcOptions {
        GcOptions {
            actor: Actor::from_env(),
            purge_blobs: false,
            dry_run: true,
            record: true,
        }
    }
}

/// What happened to one blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlobAction {
    /// The host forgot the bytes.
    Removed,
    /// Nothing was asked: the ref is gone, the bytes stay (the default, and the
    /// honest description of most stores).
    NotAttempted,
    /// Asked and refused: the host cannot forget an object.
    Refused {
        /// What the host said, close to its own words.
        why: String,
    },
    /// A dry run: this is what would have happened.
    WouldAttempt,
}

impl BlobAction {
    /// Whether the bytes are gone.
    pub fn is_gone(&self) -> bool {
        matches!(self, BlobAction::Removed)
    }
}

/// One attestation this run retired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedItem {
    /// The proof's digest.
    pub digest: Oid,
    /// What it attested to.
    pub subject: Oid,
    /// The ref that was removed.
    pub reference: String,
    /// Bytes it occupied.
    pub size: u64,
    /// Why it went.
    pub verdict: Verdict,
    /// What happened to the bytes.
    pub blob: BlobAction,
}

/// What a retention run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Schema of this record.
    pub schema_version: u32,
    /// The clock it ran against.
    pub now_us: i64,
    /// Who ran it.
    pub actor: String,
    /// The policy applied.
    pub retention: Retention,
    /// Whether anything was actually changed.
    pub dry_run: bool,
    /// Everything retired.
    pub pruned: Vec<PrunedItem>,
    /// How many were kept, and how many of those because they are pinned.
    pub kept: usize,
    /// See `kept`.
    pub pinned: usize,
    /// Bytes the retired items occupied.
    pub pruned_bytes: u64,
    /// The `kv/gc/…` record of this run, when one was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Oid>,
}

impl Report {
    /// One line for a human.
    pub fn summary_line(&self) -> String {
        let verb = if self.dry_run {
            "would retire"
        } else {
            "retired"
        };
        format!(
            "{verb} {} attestation(s) ({} bytes); kept {} of {} ({} pinned)",
            self.pruned.len(),
            self.pruned_bytes,
            self.kept,
            self.kept + self.pruned.len(),
            self.pinned
        )
    }

    /// Why a run pruned nothing, in the sentence an operator can act on.
    ///
    /// `gc` returning success while deleting nothing is the failure mode a
    /// retention cron cannot see for itself, so the empty case gets its own
    /// explanation rather than a silent zero.
    pub fn explain_nothing_pruned(&self) -> Option<String> {
        if !self.pruned.is_empty() {
            return None;
        }
        let considered = self.kept + self.pruned.len();
        if considered == 0 {
            return Some("the store holds no published attestations".to_string());
        }
        if self.pinned == considered {
            return Some(format!(
                "all {considered} are still referenced by a quorum, a merge or a keep, which no \
                 policy may prune"
            ));
        }
        Some(format!(
            "nothing is over the policy's limits ({considered} considered: {})",
            self.retention.describe()
        ))
    }
}

/// Carry out a plan: remove the advertised refs, ask the host about the bytes, and
/// leave a record of the run.
///
/// Every ref removal is a compare-and-swap on the digest it names, so a proof that
/// moved since the plan was made is left alone rather than deleted on stale
/// information. Pinned items are never touched, whatever the plan said: the pin set
/// is re-read here, at the moment of deletion, because the thing that changed
/// between a plan and its application is exactly whether a quorum started using this
/// proof.
pub fn apply(
    host: &dyn Host,
    plan: &Plan,
    pins: &BTreeMap<Oid, String>,
    options: &GcOptions,
) -> HostResult<Report> {
    let mut pruned = Vec::new();
    let mut kept = 0usize;
    let mut pinned = 0usize;
    let actor = options.actor.clone();

    for item in &plan.items {
        // Re-check the pin set here, not just in the plan: a quorum round that
        // started after `plan` ran is a real reference, and a ref is cheap to read.
        if pins.contains_key(&item.item.digest) {
            kept += 1;
            pinned += 1;
            continue;
        }
        if !item.verdict.is_prune() {
            kept += 1;
            continue;
        }
        let reference = match item.item.reference.as_ref() {
            Some(name) => RefName::new(name)?,
            // A hand-built plan without a ref cannot be applied: this module
            // deletes advertisements, and an advertisement it cannot name is not
            // one it may remove.
            None => {
                kept += 1;
                continue;
            }
        };
        if options.dry_run {
            pruned.push(PrunedItem {
                digest: item.item.digest,
                subject: item.item.subject,
                reference: reference.as_str().to_string(),
                size: item.item.size,
                verdict: item.verdict.clone(),
                blob: if options.purge_blobs {
                    BlobAction::WouldAttempt
                } else {
                    BlobAction::NotAttempted
                },
            });
            continue;
        }
        let deletion = RefDeletion::new(reference.clone(), Expect::Is(item.item.digest))
            .with_actor(actor.clone());
        match host.delete_ref_cas(&deletion) {
            Ok(()) => {}
            // A ref that is already absent is the state we asked for: another `gc`
            // or a re-publish-and-retire beat us to it. Anything else is an error
            // and stops the run, because a half-applied plan must not be reported
            // as a finished one.
            Err(error) => {
                if !ref_gone(host, &reference)? {
                    return Err(error);
                }
            }
        }
        let blob = if options.purge_blobs {
            match host.purge_cas(&item.item.digest) {
                Ok(true) => BlobAction::Removed,
                Ok(false) => BlobAction::NotAttempted,
                Err(error) if error.is_unsupported() => BlobAction::Refused {
                    why: error.message(),
                },
                Err(error) => return Err(error),
            }
        } else {
            BlobAction::NotAttempted
        };
        pruned.push(PrunedItem {
            digest: item.item.digest,
            subject: item.item.subject,
            reference: reference.as_str().to_string(),
            size: item.item.size,
            verdict: item.verdict.clone(),
            blob,
        });
    }

    let report = Report {
        schema_version: SCHEMA_VERSION,
        now_us: plan.now_us,
        actor: actor.as_str().to_string(),
        retention: plan.retention,
        dry_run: options.dry_run,
        pruned_bytes: pruned.iter().map(|item| item.size).sum(),
        kept,
        pinned,
        pruned,
        record: None,
    };
    if options.record && !options.dry_run && !report.pruned.is_empty() {
        let oid = publish_record(host, &report)?;
        return Ok(Report {
            record: Some(oid),
            ..report
        });
    }
    Ok(report)
}

/// Whether a ref is absent, with the error carried through if asking fails.
fn ref_gone(host: &dyn Host, name: &RefName) -> HostResult<bool> {
    match host.get_ref(name) {
        Ok(None) => Ok(true),
        Ok(Some(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Write the `kv/gc/…` record of a retention run.
///
/// Content addressed, immutable and cheap to list, because "what did the last
/// retention run delete, and under which policy" is a question with an audit answer
/// in every store, not one only the operator's terminal scrollback has.
pub fn publish_record(host: &dyn Host, report: &Report) -> HostResult<Oid> {
    let value = serde_json::to_value(report)
        .map_err(|e| HostError::invalid("gc record", format!("cannot encode: {e}")))?;
    host.put_json(&GC_NAMESPACE, &value)
}

/// Every retention record the store holds, newest first.
pub fn records(host: &dyn Host) -> HostResult<Vec<(Oid, serde_json::Value)>> {
    let mut out = Vec::new();
    for entry in host.list(&GC_NAMESPACE)? {
        if let Some(bytes) = host.get(&entry.oid)?
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            out.push((entry.oid, value));
        }
    }
    // `now_us` is inside the document, so sorting needs the parse above. Records
    // with a missing field sort oldest, which is the safe direction: a caller sees
    // the odd ones last, not first.
    let ran_at = |record: &(Oid, serde_json::Value)| {
        record
            .1
            .get("now_us")
            .and_then(|value| value.as_i64())
            .unwrap_or(i64::MIN)
    };
    out.sort_by_key(|entry| std::cmp::Reverse(ran_at(entry)));
    Ok(out)
}

/// The set of digests a `gc` on this store must not touch, read from the store.
pub fn pin_set(host: &dyn Host) -> HostResult<BTreeSet<Oid>> {
    Ok(referenced(host)?.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::fs::FsHost;
    use crate::{BlobStore, RefStore};

    fn digest_of(text: &str) -> Oid {
        Oid::hash_bytes(text.as_bytes())
    }

    #[test]
    fn ref_names_round_trip() {
        let subject = digest_of("a commit");
        let digest = digest_of("an attestation");
        let name = ref_name(&subject, &digest);
        assert_eq!(
            name.as_str(),
            format!("refs/attestations/{subject}/{digest}")
        );
        assert_eq!(parse_ref(&name), Some((subject, digest)));
        assert_eq!(
            prefix(&subject),
            format!("refs/attestations/{subject}/"),
            "the listing prefix carries its separator, so a subject cannot match a longer name"
        );
        assert!(name.is_attestation());
    }

    #[test]
    fn a_single_level_ref_is_not_this_layout() {
        let subject = digest_of("a commit");
        assert_eq!(parse_ref(&RefName::attestation(&subject)), None);
        assert_eq!(
            parse_ref(&ref_name(&subject, &digest_of("x")).join("extra").unwrap()),
            None
        );
    }

    #[test]
    fn ages_parse_in_the_units_a_policy_is_written_in() {
        assert_eq!(parse_age("90s").unwrap(), Some(90 * MICROS));
        assert_eq!(parse_age("2h").unwrap(), Some(2 * 3_600 * MICROS));
        assert_eq!(parse_age("30d").unwrap(), Some(30 * MICROS_PER_DAY));
        assert_eq!(parse_age("2w").unwrap(), Some(2 * MICROS_PER_WEEK));
        assert_eq!(parse_age("45").unwrap(), Some(45 * MICROS));
        for none in ["never", "off", "none", "0", ""] {
            assert_eq!(parse_age(none).unwrap(), None, "{none}");
        }
        for bad in ["10x", "d", "-1d", "1.5d", "a week"] {
            assert!(parse_age(bad).is_err(), "{bad} should be refused");
        }
        assert_eq!(human_age(30 * MICROS_PER_DAY), "30d");
        assert_eq!(human_age(2 * MICROS_PER_WEEK), "2w");
        assert_eq!(human_age(90 * MICROS), "90s");
    }

    fn item(subject: &str, digest: &str, claimed_at_us: i64) -> AttestationItem {
        AttestationItem {
            digest: digest_of(digest),
            subject: digest_of(subject),
            claimed_at_us,
            size: 100,
            label: None,
            reference: Some(format!(
                "refs/attestations/{}/{}",
                digest_of(subject),
                digest_of(digest)
            )),
        }
    }

    #[test]
    fn age_policy_prunes_the_old_and_keeps_the_fresh() {
        let now = 1_000 * MICROS_PER_DAY * 1_000;
        let items = vec![
            item("c1", "old", now - 40 * MICROS_PER_DAY),
            item("c1", "fresh", now - 2 * MICROS_PER_DAY),
        ];
        let retention = Retention {
            max_age_us: Some(30 * MICROS_PER_DAY),
            max_per_subject: None,
        };
        let plan = plan(&retention, now, &items, &BTreeMap::new());
        let pruned = plan.pruned();
        assert_eq!(pruned.len(), 1, "{plan:?}");
        assert_eq!(pruned[0].item.digest, digest_of("old"));
        assert!(matches!(pruned[0].verdict, Verdict::Expired { .. }));
        assert_eq!(plan.kept().len(), 1);
        assert_eq!(plan.pruned_bytes(), 100);
    }

    #[test]
    fn a_cap_keeps_the_newest_and_counts_after_age() {
        let now = 100 * MICROS_PER_DAY;
        // Three for one commit, one of them already expired: the cap must not spend
        // a slot on the expired one, or a fresh proof is lost for nothing.
        let mut items = vec![
            item("c1", "newest", now - MICROS_PER_DAY),
            item("c1", "middle", now - 5 * MICROS_PER_DAY),
            item("c1", "stale", now - 90 * MICROS_PER_DAY),
            item("c2", "other", now - MICROS_PER_DAY),
        ];
        items.sort_by_key(|item| item.digest.hex());
        let retention = Retention {
            max_age_us: Some(30 * MICROS_PER_DAY),
            max_per_subject: Some(2),
        };
        let plan = plan(&retention, now, &items, &BTreeMap::new());
        let verdict = |label: &str| {
            plan.items
                .iter()
                .find(|p| p.item.digest == digest_of(label))
                .unwrap()
                .verdict
                .clone()
        };
        assert_eq!(verdict("newest"), Verdict::Kept);
        assert_eq!(verdict("middle"), Verdict::Kept);
        assert!(matches!(verdict("stale"), Verdict::Expired { .. }));
        assert_eq!(verdict("other"), Verdict::Kept);

        // No age limit: now the cap is what drops one, at rank 3.
        let capped = super::plan(
            &Retention {
                max_age_us: None,
                max_per_subject: Some(2),
            },
            now,
            &items,
            &BTreeMap::new(),
        );
        assert_eq!(
            capped
                .items
                .iter()
                .find(|p| p.item.digest == digest_of("stale"))
                .unwrap()
                .verdict,
            Verdict::OverQuota {
                position: 3,
                max: 2
            }
        );
    }

    #[test]
    fn pinned_survives_every_policy() {
        let now = 100 * MICROS_PER_DAY;
        let items = vec![
            item("c1", "ancient", now - 99 * MICROS_PER_DAY),
            item("c1", "fresh", now),
        ];
        let mut pins = BTreeMap::new();
        pin(
            &mut pins,
            digest_of("ancient"),
            "refs/gitiup/reveal/chg/build/ab12cd34",
        );
        let retention = Retention {
            max_age_us: Some(MICROS),
            max_per_subject: Some(1),
        };
        let plan = plan(&retention, now, &items, &pins);
        assert_eq!(plan.pruned().len(), 0, "{plan:?}");
        assert_eq!(plan.pinned_count(), 1);
        // The pinned one is the *oldest* item, so it is not first in the sorted plan:
        // a policy that rescued it by ordering rather than by pinning would prove
        // nothing.
        let ancient = plan
            .items
            .iter()
            .find(|item| item.item.digest == digest_of("ancient"))
            .expect("the ancient attestation is in the plan");
        let why = match &ancient.verdict {
            Verdict::Pinned { why } => why.clone(),
            other => panic!("expected a pinned verdict, got {other:?}"),
        };
        assert!(why.starts_with("refs/gitiup/reveal/"));
    }

    #[test]
    fn publish_list_and_fetch_round_trip_on_a_filesystem_store() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("the commit that was built");
        let bytes = b"{signed:bytes}".to_vec();

        let published = publish(&host, &subject, &bytes, "ada").expect("publish");
        assert!(!published.already);
        assert_eq!(published.digest, Oid::hash_bytes(&bytes));
        let fetched = fetch(&host, &published.digest)
            .expect("fetch")
            .expect("the attestation is there");
        assert_eq!(
            fetched.as_slice(),
            bytes.as_slice(),
            "the bytes come back verbatim: a signature is only ever over these"
        );

        let again = publish(&host, &subject, &bytes, "ada").expect("re-publish");
        assert!(again.already, "a retry is not a conflict");

        // A second attestation for the same commit, from a different signer.
        let other_bytes = b"{signer:bruno}".to_vec();
        let other = publish(&host, &subject, &other_bytes, "bruno").expect("second attestation");
        let catalog = list_for(&host, &subject).expect("list");
        assert_eq!(catalog.entries.len(), 2);
        assert!(catalog.unexpected.is_empty());
        assert!(
            catalog
                .entries
                .iter()
                .any(|entry| entry.digest == other.digest)
        );
        assert!(list_all(&host).expect("list all").entries.len() >= 2);

        // A subject with nothing published is an empty listing, not an error.
        assert!(
            list_for(&host, &digest_of("somewhere else"))
                .unwrap()
                .entries
                .is_empty()
        );
    }

    #[test]
    fn a_single_level_ref_blocks_the_directory_form_instead_of_corrupting_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let legacy = digest_of("legacy bytes");
        host.put_cas(&Namespace::ATTESTATION, b"legacy").unwrap();
        host.update_ref_cas(&RefUpdate::create(RefName::attestation(&subject), legacy))
            .expect("legacy single-level ref");
        let err = publish(&host, &subject, b"new bytes", "ada").unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::Invalid);
        assert!(err.to_string().contains("single ref"), "{err}");
    }

    #[test]
    fn a_retired_attestation_is_unpublished_but_nothing_else_moves() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let bytes = b"attestation bytes".to_vec();
        let published = publish(&host, &subject, &bytes, "ada").expect("publish");
        let quorum_bytes = b"a seat's submission".to_vec();
        let quorum = publish(&host, &subject, &quorum_bytes, "verifier").expect("publish");
        // A quorum ref pins one of the two.
        host.update_ref_cas(&RefUpdate::create(
            RefName::gitiup("reveal/chg/build/slot").unwrap(),
            quorum.digest,
        ))
        .expect("a quorum seat points at it");
        let pins = referenced(&host).expect("pins");
        assert!(pins.contains_key(&quorum.digest));
        assert!(!pins.contains_key(&published.digest));

        let items = vec![
            AttestationItem {
                digest: published.digest,
                subject,
                claimed_at_us: 0,
                size: bytes.len() as u64,
                label: None,
                reference: Some(published.reference.as_str().to_string()),
            },
            AttestationItem {
                digest: quorum.digest,
                subject,
                claimed_at_us: 0,
                size: quorum_bytes.len() as u64,
                label: None,
                reference: Some(quorum.reference.as_str().to_string()),
            },
        ];
        let retention = Retention {
            max_age_us: Some(MICROS),
            max_per_subject: None,
        };
        let plan = plan(&retention, 10 * MICROS, &items, &pins);
        let report = apply(
            &host,
            &plan,
            &pins,
            &GcOptions {
                dry_run: false,
                record: true,
                ..GcOptions::default()
            },
        )
        .expect("apply");
        assert_eq!(report.pruned.len(), 1, "{report:?}");
        assert_eq!(report.pruned[0].digest, published.digest);
        assert_eq!(report.pinned, 1);
        assert!(report.record.is_some(), "the run is recorded");

        let remaining = list_for(&host, &subject).expect("list");
        assert_eq!(remaining.entries.len(), 1);
        assert_eq!(remaining.entries[0].digest, quorum.digest);
        // The bytes of the retired attestation are still there (nothing was asked
        // to purge them) and still verbatim.
        assert_eq!(fetch(&host, &published.digest).unwrap().unwrap(), bytes);
        // And the record of the run says what it retired.
        let records = records(&host).expect("records");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].1["pruned"][0]["digest"].as_str(),
            Some(published.digest.hex().as_str())
        );
    }

    #[test]
    fn a_dry_run_changes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let published = publish(&host, &subject, b"bytes", "ada").unwrap();
        let items = vec![AttestationItem {
            digest: published.digest,
            subject,
            claimed_at_us: 0,
            size: 5,
            label: None,
            reference: Some(published.reference.as_str().to_string()),
        }];
        let retention = Retention {
            max_age_us: Some(1),
            max_per_subject: None,
        };
        let plan = plan(&retention, 10, &items, &BTreeMap::new());
        let report = apply(&host, &plan, &BTreeMap::new(), &GcOptions::default()).expect("dry run");
        assert!(report.dry_run);
        assert_eq!(report.pruned.len(), 1);
        assert_eq!(
            report.pruned[0].blob,
            BlobAction::NotAttempted,
            "a dry run that was not told to purge says so rather than implying the bytes go"
        );
        let purging = apply(
            &host,
            &plan,
            &BTreeMap::new(),
            &GcOptions {
                purge_blobs: true,
                ..GcOptions::default()
            },
        )
        .expect("dry run with purge");
        assert_eq!(purging.pruned[0].blob, BlobAction::WouldAttempt);
        assert_eq!(list_for(&host, &subject).unwrap().entries.len(), 1);
        assert!(
            records(&host).unwrap().is_empty(),
            "a dry run leaves no record"
        );
    }

    #[test]
    fn the_filesystem_host_can_forget_a_blob_and_the_plan_reports_it() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let published = publish(&host, &subject, b"bytes", "ada").unwrap();
        let items = vec![AttestationItem {
            digest: published.digest,
            subject,
            claimed_at_us: 0,
            size: 5,
            label: None,
            reference: Some(published.reference.as_str().to_string()),
        }];
        let plan = plan(
            &Retention {
                max_age_us: Some(1),
                max_per_subject: None,
            },
            10,
            &items,
            &BTreeMap::new(),
        );
        let report = apply(
            &host,
            &plan,
            &BTreeMap::new(),
            &GcOptions {
                dry_run: false,
                purge_blobs: true,
                ..GcOptions::default()
            },
        )
        .expect("apply with purge");
        assert_eq!(report.pruned[0].blob, BlobAction::Removed);
        assert!(
            fetch(&host, &published.digest).unwrap().is_none(),
            "the bytes are gone, which is what --purge-blobs buys"
        );
    }

    #[test]
    fn an_unnamed_advertisement_is_left_alone() {
        // A plan built by hand, without a ref to remove: nothing may be deleted,
        // because there is nothing this module is allowed to name.
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let items = vec![AttestationItem {
            digest: digest_of("bytes"),
            subject: digest_of("a commit"),
            claimed_at_us: 0,
            size: 5,
            label: None,
            reference: None,
        }];
        let plan = plan(
            &Retention {
                max_age_us: Some(1),
                max_per_subject: None,
            },
            10,
            &items,
            &BTreeMap::new(),
        );
        let report = apply(&host, &plan, &BTreeMap::new(), &GcOptions::default()).unwrap();
        assert!(report.pruned.is_empty());
        assert_eq!(report.kept, 1);
    }

    #[test]
    fn retention_describes_itself_in_words_a_human_can_refuse() {
        assert!(Retention::none().is_unbounded());
        assert!(Retention::none().describe().contains("no age"));
        let policy = Retention::new(Some("30d"), Some(5)).unwrap();
        assert_eq!(policy.max_age_us, Some(30 * MICROS_PER_DAY));
        assert!(policy.describe().contains("30d"));
        assert!(policy.describe().contains("keep 5"));
        assert!(Retention::new(Some("never"), None).unwrap().is_unbounded());
    }

    // -- the two shapes ----------------------------------------------------

    #[test]
    fn a_legacy_ref_names_its_subject_and_nothing_else() {
        let subject = digest_of("a commit");
        let legacy = legacy_ref_name(&subject);
        assert_eq!(legacy.as_str(), format!("refs/attestations/{subject}"));
        assert_eq!(parse_legacy_ref(&legacy), Some(subject));
        // A two-level ref is not legacy, and neither is a name that is not hex.
        assert_eq!(
            parse_legacy_ref(&ref_name(&subject, &digest_of("proof"))),
            None
        );
        assert_eq!(
            parse_legacy_ref(&RefName::new("refs/attestations/not-hex").unwrap()),
            None
        );
        assert_eq!(
            parse_ref(&legacy),
            None,
            "and the two readings do not overlap"
        );
    }

    /// File one proof the old way: `refs/attestations/<subject>` -> digest.
    fn file_legacy(host: &dyn Host, subject: &Oid, bytes: &[u8]) -> Oid {
        let digest = host
            .put_cas(&Namespace::ATTESTATION, bytes)
            .expect("store the bytes");
        host.update_ref_cas(&RefUpdate::create(legacy_ref_name(subject), digest))
            .expect("the legacy ref");
        digest
    }

    #[test]
    fn a_legacy_proof_is_listed_as_a_proof_and_flagged_as_legacy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let digest = file_legacy(&host, &subject, b"an old attestation");

        let catalog = list_for(&host, &subject).expect("list");
        assert!(catalog.unexpected.is_empty(), "{:?}", catalog.unexpected);
        assert_eq!(catalog.entries.len(), 1);
        let entry = &catalog.entries[0];
        assert_eq!(entry.subject, subject);
        assert_eq!(entry.digest, digest, "the ref's value is the attestation");
        assert!(entry.legacy);
        assert_eq!(catalog.legacy().len(), 1);
        // It is findable by the same question a modern proof is found by.
        assert_eq!(
            fetch(&host, &digest).unwrap().unwrap(),
            b"an old attestation"
        );
        assert!(list_all(&host).expect("list all").legacy().len() == 1);
    }

    #[test]
    fn a_ref_that_names_its_own_digest_advertises_no_subject() {
        // A digest filed under its own hex proves nothing about a commit, so no
        // reading of it is honest; it is reported, never guessed at.
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let digest = digest_of("a proof");
        host.put_cas(&Namespace::ATTESTATION, b"a proof").unwrap();
        host.update_ref_cas(&RefUpdate::create(RefName::attestation(&digest), digest))
            .unwrap();
        let catalog = list_all(&host).expect("list");
        assert!(catalog.entries.is_empty());
        assert_eq!(catalog.unexpected.len(), 1);
    }

    #[test]
    fn publishing_beside_a_legacy_ref_says_so_and_names_the_way_out() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        file_legacy(&host, &subject, b"an old attestation");
        let error = publish(&host, &subject, b"a new attestation", "ada").unwrap_err();
        assert_eq!(error.kind(), crate::HostErrorKind::Invalid);
        assert!(error.to_string().contains("single ref"), "{error}");
        assert!(
            error.hint().unwrap_or_default().contains("attest migrate"),
            "the refusal has to say what to do: {}",
            error.hint().unwrap_or_default()
        );
    }

    #[test]
    fn migrate_moves_a_legacy_proof_and_then_the_subject_holds_many() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let old = file_legacy(&host, &subject, b"an old attestation");

        // A dry run reads and reports, and changes nothing a later command could
        // mistake for progress.
        let planned = migrate(&host, &MigrationOptions::default()).expect("plan");
        assert!(planned.dry_run);
        assert_eq!(planned.moved.len(), 1);
        assert!(!planned.moved[0].retired);
        assert_eq!(planned.remaining, 0);
        assert!(planned.record.is_none());
        assert!(
            legacy_proofs(&host).unwrap().len() == 1,
            "nothing moved yet"
        );
        assert!(!planned.summary_line().contains("would move 0"));

        let options = MigrationOptions {
            actor: Actor::from("ada"),
            apply: true,
            record: true,
        };
        let report = migrate(&host, &options).expect("migrate");
        assert!(!report.dry_run);
        assert_eq!(report.moved.len(), 1);
        assert!(report.moved[0].retired);
        assert_eq!(report.moved[0].digest, old);
        assert!(report.record.is_some(), "and the move is recorded");
        assert!(legacy_proofs(&host).unwrap().is_empty());
        assert!(
            host.get_ref(&legacy_ref_name(&subject)).unwrap().is_none(),
            "the old ref is gone"
        );

        let catalog = list_for(&host, &subject).expect("list");
        assert_eq!(catalog.entries.len(), 1);
        assert!(!catalog.entries[0].legacy);
        assert_eq!(
            catalog.entries[0].digest, old,
            "the same digest, not a re-write"
        );
        assert_eq!(
            fetch(&host, &old).unwrap().unwrap(),
            b"an old attestation",
            "the signed bytes were never touched"
        );

        // The point of the move: a second proof can now be filed beside the first.
        publish(&host, &subject, b"a second signer", "bob").expect("publish");
        assert_eq!(list_for(&host, &subject).unwrap().entries.len(), 2);
    }

    #[test]
    fn a_move_interrupted_between_the_two_ref_writes_heals_on_the_next_run() {
        // The one window this design cannot close: the old ref is retired, the new
        // one was never written, and the process died in between. The intent record
        // is what makes that state findable, and `migrate` looks for it before it
        // looks for anything else.
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let bytes = b"an old attestation";
        let digest = Oid::hash_bytes(bytes);
        host.put_cas(&Namespace::ATTESTATION, bytes).unwrap();
        let target = ref_name(&subject, &digest);
        host.put_json(
            &MIGRATE_NAMESPACE,
            &serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "in_flight": [{
                    "subject": subject.hex(),
                    "digest": digest.hex(),
                    "from": legacy_ref_name(&subject).as_str(),
                    "to": target.as_str(),
                }],
            }),
        )
        .unwrap();
        assert!(
            host.get_ref(&target).unwrap().is_none(),
            "the crash left nothing advertising these bytes"
        );
        assert!(
            list_all(&host).unwrap().is_empty(),
            "and no listing can see them"
        );

        let report = migrate(
            &host,
            &MigrationOptions {
                actor: Actor::from("ada"),
                apply: true,
                record: false,
            },
        )
        .expect("migrate");
        assert_eq!(report.repaired.len(), 1, "{}", report.summary_line());
        assert_eq!(report.repaired[0].digest, digest);
        assert!(host.get_ref(&target).unwrap().is_some(), "re-advertised");
        assert_eq!(list_all(&host).unwrap().entries.len(), 1);
    }

    #[test]
    fn migrate_refuses_to_retire_the_advertisement_of_bytes_it_cannot_read() {
        let dir = tempfile::tempdir().expect("temp dir");
        let host = FsHost::create(dir.path().join("store")).expect("fs host");
        let subject = digest_of("a commit");
        let bytes = b"bytes that will not be here";
        let digest = Oid::hash_bytes(bytes);
        // The ref exists; the object it names does not. That is a broken store, and
        // the migration's job is not to make it more broken by forgetting the ref.
        host.update_ref_cas(&RefUpdate::create(legacy_ref_name(&subject), digest))
            .unwrap();
        let report = migrate(
            &host,
            &MigrationOptions {
                actor: Actor::from("ada"),
                apply: true,
                record: false,
            },
        )
        .expect("migrate");
        assert!(report.moved.is_empty());
        assert_eq!(report.blocked.len(), 1);
        assert!(report.blocked[0].why.contains("cannot return"));
        assert_eq!(report.remaining, 1);
        assert!(
            host.get_ref(&legacy_ref_name(&subject)).unwrap().is_some(),
            "the only advertisement of those bytes survives"
        );
    }
}

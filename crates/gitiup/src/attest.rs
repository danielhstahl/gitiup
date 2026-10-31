//! `gitiup attest …` — publish a proof, find it again, and keep the store honest
//! about how long it keeps one (giti-1rs.5).
//!
//! Five commands, and the whole of gitiup's attestation *storage* surface:
//!
//! ```text
//! gitiup attest push       file a signed attestation: kv/attestation/<digest> + refs/attestations/…
//! gitiup attest list       what a commit (or the whole store) has, read back from the store
//! gitiup attest show       one attestation, parsed, checked, and printable as JSON
//! gitiup attest gc         retire the ones a retention policy says are old, keep what's referenced
//! gitiup attest migrate    move an old store's single-level refs to <subject>/<digest>
//! ```
//!
//! The bytes are never invented here. An attestation is a signed document and a
//! signature is only ever over the exact canonical bytes
//! ([ADR-0001](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)),
//! so `push` takes those bytes (or a run report it turns into a manifest through the
//! one sanctioned pipeline, [`RunManifest::from_run`]) and stores them verbatim;
//! `list` and `show` re-read them and let the digest say whether the store was
//! honest. A store that could reformat a record on the way in would be a store that
//! destroys signatures, so every read here goes through
//! [`AttestationDoc::from_canonical_bytes`] and refuses anything that is merely
//! valid JSON. The one input that is not already a document is the unsigned manifest
//! `gitiup run --out` writes, which is wrapped before it is signed — see
//! [`document_from_bytes`].
//!
//! # What is checked here, and what is not
//!
//! * **Shape, always.** Canonical bytes, a manifest that validates, a digest that
//!   matches its own content. A record the store holds that does not re-hash is a
//!   bug in the store and `show` says so (exit 8).
//! * **That it is signed, before storing.** An unsigned attestation is a rumour:
//!   `push` refuses to file one unless it signs it first with a key from this
//!   machine's keystore (`--sign`, or the default identity). Co-signing an existing
//!   document is a different act — pooling signatures over *the same* manifest is
//!   [`AttestationDoc::merge_signatures`], and it belongs to the quorum (giti-msi.7),
//!   where the point of pooling is what a verdict is made of.
//! * **Whether the signature verifies: not here.** That is `gitiup verify attestation`
//!   (giti-1rs.8), which owns the trust question — which key ids an owner vouched
//!   for, how fresh a claim has to be, which tiers a gate accepts. Listing an
//!   attestation must not require a trust root, or a store could not be inventoried;
//!   `list` therefore reports *who signed* and leaves *whether that counts* to the
//!   command whose whole job is that.
//!
//! # Retention, and the one rule a flag cannot turn off
//!
//! `gc` prunes advertisements, newest-first, by age and by a per-commit cap — and
//! never prunes anything another ref still points at. That is what keeps a quorum's
//! evidence safe without anyone configuring it: a round's submissions live in this
//! store and each seat holds a ref (`refs/gitiup/reveal/…`) pointing at its own
//! attestation, so deleting them would make a published verdict unauditable, and there
//! is no flag that forces it. What a ref cannot show is a digest named *inside* another
//! record — a merge record's `attestation` field, a verdict's contributing list — and
//! `--keep <digest>` is the explicit spelling of that: whoever read the record says so,
//! rather than the tool guessing which strings in which blobs meant "keep". Run it
//! without `--apply` and nothing changes: a plan is printed as data, so a policy can be
//! reviewed before it deletes anything.
//!
//! ```text
//! gitiup attest gc --store ./store --max-age 90d --max-per-commit 5          # the plan
//! gitiup attest gc --store ./store --max-age 90d --max-per-commit 5 --apply  # the change
//! ```
//!
//! # Moving an old store up to date
//!
//! `gc` answers "how long do I keep this"; `migrate` answers "this store predates the
//! `<subject>/<digest>` layout". A single-level `refs/attestations/<subject>` ref is
//! still read and still listed (flagged `legacy`), but it can hold exactly one proof,
//! so a second signer or a second tier has nowhere to go. `migrate` re-files each one
//! under the current layout and retires the old ref only once the new one exists — same
//! digest, same bytes, signature untouched — and, like `gc`, prints its report and
//! changes nothing without `--apply`. A run interrupted between the two ref writes is
//! repaired by the next one, because the intent was written down first.
//!
//! # Exit codes
//!
//! The same table as the rest of `gitiup` (ADR-0001 D7): 0 ok · 2 usage · 3 I/O or
//! an unreachable store · 6 refused (nothing to sign with, no store named, an
//! unsigned document, a policy that would prune nothing) · 7 a signature that does
//! not verify · 8 bytes that are not the document's own canonical form.

use std::collections::BTreeMap;
use std::io::Write as _;

use gitiup_attest::{AttestationDoc, GitOid, RunManifest, RunReport, Tier, TimeUs};
use gitiup_host::attest::{self, AttestationItem, GcOptions, Retention};
use gitiup_host::federation::{
    self,
    provenance::{self, PruneAuthority},
};
use gitiup_host::{Oid, Timestamp};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::{self, Args};
use crate::participant::{self, Opened};

/// Help for `gitiup attest`.
pub const ATTEST_HELP: &str = "\
gitiup attest — file signed attestations in a host, read them back, and retire old ones

USAGE:
    gitiup attest push [DOC|-] [OPTIONS]
    gitiup attest list [OPTIONS]
    gitiup attest show [DIGEST|ARGS] [OPTIONS]
    gitiup attest import [OPTIONS]        (see `gitiup attest import help`)
    gitiup attest gc [OPTIONS]
    gitiup attest migrate [OPTIONS]

An attestation is signed bytes, and a signature is only ever over the exact canonical
form (ADR-0001). `push` stores those bytes verbatim at kv/attestation/<digest> and
points refs/attestations/<subject>/<digest> at them, so on a git-backed host a plain
`git fetch 'refs/attestations/<subject>/*'` arrives carrying the proof in the same
packfile as the ref. See docs/host-abstraction.md.

WHERE IT GOES (every command):
    --store <dir>            a directory as the store (the fs host)
    --remote <name>          a remote from gitiup.toml (default: the configured one)
                             `list` and `show` may read the default remote; anything that
                             writes has to name its store, so a typo cannot file a proof
                             somewhere else

push — file one attestation:
    DOC                      an attestation document in canonical form, or - for stdin.
                             The unsigned manifest `gitiup run --out` wrote is accepted
                             too: it is the same attestation one step earlier, and
                             --sign is what turns it into a document
    --run-report <path|->    build the manifest from a run report (docs/run-report.md)
                             instead of handing over a document
    --sign                   sign it with this machine's key first; required when the
                             document carries no signature, because an unsigned
                             attestation proves nothing
    --key <selector>         which key signs (default: the current identity)
    --subject <oid>          what it attests to; default: the commit named in the
                             manifest (sha1:…, sha256:… or bare hex)
    --out <path|->           also write the exact bytes that were stored

list — what a store holds:
    --commit <oid>           one commit's attestations (sha1:…, sha256:…, or bare hex)
    --all                    every commit's, oldest subject first
    --json                   one line, sorted keys: for every attestation its digest,
                             tier, signers, claimed time and both digests

show — one attestation, parsed:
    DIGEST | --digest <hex>  which one; or --commit <oid> for its newest
    --json                   the stored document plus its digests and metadata
    --bytes                  the exact stored bytes, and nothing else
    --dsse                   a spec in-toto DSSE envelope over the same bytes

gc — retention:
    --max-age <age>          90d, 2w, 36h, 90s, or seconds; `never` for no limit
                             an authority limit: refused against a store whose attestations
                             all arrived by import (`mirror_may_not_prune_by_age`)
    --max-per-commit <n>     keep the newest n per commit (an authority limit, same rule)
    --max-bytes <size>       free space instead of time: 500m, 4g, or bytes. The mirror's
                             limit — it evicts only copies this store can name a re-fetch
                             source for (a kv/import/ record saying where it got them) and
                             says so about every digest it could not touch
    --evidence <path>        read a retention record somebody handed over, and refuse to
                             act on it: `gc_record_not_instruction`
    --keep <digest>          never prune this digest (repeatable: a merge record's, a
                             verdict's; refs that still point at an object already pin it
                             without being told)
    --commit <oid>           limit the run to one commit
    --purge-blobs            also ask the host to forget the bytes (the fs host can; a git
                             store and a versioned bucket refuse and say why)
    --apply                  do it. Without this flag nothing changes: the plan is printed
                             and you can read it first

migrate — move a store's old single-level attestation refs to <subject>/<digest>:
    Old gitiup filed one proof per commit at refs/attestations/<commit>, a shape that
    cannot hold a second signer, run or tier. `migrate` re-files each one under the
    current layout — the same digest, the same bytes, a ref that leaves room for more —
    and retires the old ref only once the new one exists. A proof whose bytes the store
    cannot return is reported and left exactly where it is. Like `gc`, it changes
    nothing without --apply, and a move interrupted between the two ref writes is
    repaired by the next run.
    --apply                  do it

All: -j, --json on anything a script reads. Passphrases follow `gitiup key`:
--passphrase-file <path|-> or GITIUP_KEY_PASSPHRASE, never a prompt a script cannot
answer.

import — copy proofs out of another store, and re-verify every one on arrival:
    It is the ladder of `gitiup verify attestation` run at the boundary: canonical bytes,
    digest, signature, trust, tier, environment, and freshness evaluated *here and now*,
    plus the evidence each record cites (its verdict, round, roster epoch, policy chain).
    A document that fails is reported and skipped, and the rest still lands; a `tier:
    quorum` attestation without its round and verdict is a rumour and is refused; nothing
    is overwritten; `--dry-run` writes nothing. Every digest that arrives is recorded at
    kv/import/<digest> with where it came from and what the check said. Full flags:
    `gitiup attest import help`.

Exit codes: 0 ok · 2 usage · 3 I/O, store unreachable · 6 refused (no key, no store,
an unsigned document, nothing over the policy's limits) · 7 a signature that does not
verify · 8 the bytes are not the document's canonical form.
";

/// Switches `gitiup attest …` accepts.
const SWITCHES: &[&str] = &[
    "--sign",
    "--all",
    "--apply",
    "--purge-blobs",
    "--bytes",
    "--dsse",
];

/// Valued flags `gitiup attest …` accepts.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--out",
    "--key",
    "--subject",
    "--commit",
    "--digest",
    "--run-report",
    "--max-age",
    "--max-per-commit",
    "--max-bytes",
    "--evidence",
    "--keep",
    "--passphrase",
    "--passphrase-file",
];

/// `gitiup attest …`
pub fn attest(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{ATTEST_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{ATTEST_HELP}");
            Ok(())
        }
        "push" => push(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "list" | "ls" => list(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "show" => show(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "gc" => gc(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "migrate" => migrate(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        // `import` parses its own flags: it takes the whole `gitiup verify attestation`
        // vocabulary (it *is* that ladder, run at the boundary) plus its own two-store
        // flags, and sharing one flag list with `push`/`list` would mean one flag meaning
        // two things.
        "import" => crate::import::import(&args[1..]),
        other => Err(CliError::usage(format!(
            "unknown `gitiup attest` command '{other}'; `gitiup attest help` lists push, list, \
             show, import, gc and migrate"
        ))),
    }
}

// ---------------------------------------------------------------------------
// the store and the subject
// ---------------------------------------------------------------------------

/// The store, required: a listing of nowhere is not a listing.
fn read_store(args: &Args) -> Result<Opened, CliError> {
    participant::store_from(args)?.ok_or_else(|| {
        CliError::refused(
            "no store was named",
            "say where to look: --store <dir> or --remote <name> (see `gitiup doctor --remotes`)",
        )
    })
}

/// A subject — the object an attestation is about — in any of the three spellings a
/// human has.
///
/// `sha1:<hex>` and `sha256:<hex>` are what a manifest and `git rev-parse --object-format`
/// use; bare hex is what a shell has after `$(git rev-parse HEAD)`. The ref component is
/// always the bare hex, because a ref name may not contain `:` and the length already says
/// which algorithm it is.
pub(crate) fn subject(text: &str) -> Result<Oid, CliError> {
    let text = text.trim();
    let hex = if text.contains(':') {
        // The algorithm prefix is case-folded because `git rev-parse` output is hex
        // but a policy file that says `SHA1:` is not a typo worth failing over.
        text.to_ascii_lowercase()
            .parse::<GitOid>()
            .map_err(|e| {
                CliError::usage(format!(
                    "'{text}' is not an object id: {}: {}",
                    e.context(),
                    e.detail()
                ))
            })?
            .hex()
    } else {
        text.to_ascii_lowercase()
    };
    Oid::from_hex(&hex).map_err(|e| CliError::usage(format!("'{text}' is not a commit id: {e}")))
}

/// The subject an attestation is about, as the store keys it: the manifest's commit,
/// hex without the algorithm prefix.
fn manifest_subject(doc: &AttestationDoc) -> Result<Oid, CliError> {
    let commit = &doc.manifest.result.source.commit;
    Oid::from_hex(&commit.hex())
        .map_err(|e| CliError::io(format!("the manifest's commit is not a store oid: {e}")))
}

// ---------------------------------------------------------------------------
// push
// ---------------------------------------------------------------------------

/// The two shapes `push` accepts, and why both are the same object at two moments.
///
/// A signed *document* (`{schema_version, payload_type, manifest, signatures}`) is what
/// a store holds and what `verify` reads. A bare *manifest* — the file `gitiup run
/// --out` writes, before anybody has signed it — is the same attestation one step
/// earlier: signing it is the next thing anyone does with it, and `push --sign` is
/// exactly the command that does it. Accepting only the first shape meant the obvious
/// two commands in a row (`run --out`, then `push --sign`) did not compose, so a runner
/// could produce a proof its own tool would not file.
///
/// Wrapping is only ever a step towards a signature: a bare manifest that arrives
/// without `--sign` still falls into the "an unsigned attestation is a rumour" refusal
/// below, and bytes that are neither shape are refused with the *document* error — the
/// more useful of the two messages, and its own exit code, because a malformed document
/// and a malformed manifest are one event to a caller.
fn document_from_bytes(bytes: &[u8]) -> Result<AttestationDoc, gitiup_attest::Error> {
    match AttestationDoc::from_canonical_bytes(bytes) {
        Ok(doc) => Ok(doc),
        Err(document_error) => match RunManifest::from_canonical_bytes(bytes) {
            Ok(manifest) => Ok(AttestationDoc::new(manifest)),
            Err(_) => Err(document_error),
        },
    }
}

fn push(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(ATTEST_HELP) {
        return Ok(());
    }
    let store = participant::need_store(args)?;
    let mut doc = match args.get("--run-report") {
        Some(source) => {
            let report = participant::read_maybe_stdin(source)?;
            let report: RunReport = serde_json::from_slice(&report)
                .map_err(|e| CliError::usage(format!("the run report could not be read: {e}")))?;
            AttestationDoc::new(RunManifest::from_run(&report)?)
        }
        None => {
            let path = match args.positional.first() {
                Some(path) => path.clone(),
                None => {
                    return Err(CliError::usage(
                        "an attestation document is required (a path, or - for stdin; or \
                         --run-report to build one from a run report)",
                    ));
                }
            };
            let bytes = participant::read_maybe_stdin(&path)?;
            document_from_bytes(&bytes)?
        }
    };

    if args.on("--sign") {
        if !doc.signatures.is_empty() {
            return Err(CliError::refused(
                format!(
                    "this attestation is already signed by {}",
                    doc.signatures[0].key_id
                ),
                "drop --sign to store it as it is; pooling a second signature over the same \
                 manifest is co-signing (giti-msi), not filing",
            ));
        }
        let here = participant::keystore()?;
        let key = participant::signing_key(args, &here)?;
        doc.sign(&key)?;
    }
    if doc.signatures.is_empty() {
        return Err(CliError::refused(
            "this attestation carries no signature",
            "an unsigned attestation is a rumour: add --sign to sign it with this machine's \
             key, or file one that was signed where the key lives",
        ));
    }
    // Re-derive the canonical bytes after signing: the signature is over these exact
    // bytes, and so is everything downstream, so the bytes stored and the bytes
    // signed must be the same buffer.
    let bytes = doc.canonical_bytes()?;
    let subject = match args.get("--subject") {
        Some(text) => subject(text)?,
        None => manifest_subject(&doc)?,
    };

    let written = match args.get("--out") {
        Some(path) => {
            participant::write_out(path, &bytes)?;
            Some(if path == "-" { "stdout" } else { path })
        }
        None => None,
    };
    let published = attest::publish(&*store.host, &subject, &bytes, actor(&doc))
        .map_err(|e| CliError::io(format!("{}: {e}", store.what)))?;
    let digest = doc.run_digest()?;
    let result_digest = doc.result_digest()?;
    let tier = doc.manifest.result.provenance.tier;

    if let Some(path) = written {
        eprintln!("wrote {path}");
    }
    if args.json() {
        print_json(json!({
            "store": store.what,
            "subject": subject.hex(),
            "digest": published.digest.hex(),
            "reference": published.reference.as_str(),
            "already": published.already,
            "size": published.size,
            "run_digest": digest.to_string(),
            "result_digest": result_digest.to_string(),
            "tier": tier.as_str(),
            "signers": doc.signatures.iter().map(|s| s.key_id.clone()).collect::<Vec<_>>(),
            "claimed_at": rfc3339(doc.manifest.claims.claimed_at_us),
            "warning": tier.trust_warning(),
        }));
    } else {
        // Headline names the attestation by the digest `list` and `show` take it
        // back as, and mentions the run it proves second: two digests that look
        // identical in a terminal and answer different questions.
        println!(
            "{} {} for {}",
            if published.already {
                "already filed"
            } else {
                "filed"
            },
            short(&published.digest.hex()),
            subject.short_default(),
        );
        println!("  store    {}", store.what);
        println!("  ref      {}", published.reference);
        println!("  blob     kv/attestation/{}", published.digest);
        println!("  run      {digest}");
        println!(
            "  tier     {} · signed by {}",
            tier,
            doc.signatures
                .iter()
                .map(|s| short(&s.key_id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if let Some(warning) = tier.trust_warning() {
            eprintln!("  warning  {warning}");
        }
    }
    Ok(())
}

/// The actor to record on the ref: the first signer if there is one, else the
/// environment's idea of who is running.
fn actor(doc: &AttestationDoc) -> gitiup_host::Actor {
    match doc.signatures.first() {
        Some(entry) => gitiup_host::Actor::from(short(&entry.key_id)),
        None => gitiup_host::Actor::from_env(),
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// One row of a listing, in the shape both the table and `--json` read from.
struct Row {
    entry: attest::Entry,
    /// What the signed document says, or why it could not be read.
    detail: Result<Parsed, CliError>,
}

/// The parts of an attestation a listing shows — read out of the *signed* document,
/// so a store that lied about a tier or a date could not steer a listing or a gc.
struct Parsed {
    tier: Tier,
    signers: Vec<String>,
    claimed_at_us: i64,
    run_digest: String,
    result_digest: String,
    runner: String,
    sandbox: Option<String>,
    size: u64,
}

fn rows(store: &dyn gitiup_host::Host, wanted: Option<&Oid>) -> Result<Vec<Row>, CliError> {
    let catalog = match wanted {
        Some(subject) => attest::list_for(store, subject),
        None => attest::list_all(store),
    }
    .map_err(|e| CliError::io(format!("list attestations: {e}")))?;
    let mut out = Vec::with_capacity(catalog.entries.len());
    for entry in catalog.entries {
        out.push(Row {
            detail: parse(store, &entry),
            entry,
        });
    }
    // Newest first: the question a listing answers is "what is the proof about this
    // commit now", and the newest claim is the one a gate wants.
    out.sort_by(|a, b| match (&a.detail, &b.detail) {
        (Ok(newest), Ok(older)) => older
            .claimed_at_us
            .cmp(&newest.claimed_at_us)
            .then(a.entry.digest.hex().cmp(&b.entry.digest.hex())),
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => a.entry.digest.hex().cmp(&b.entry.digest.hex()),
    });
    Ok(out)
}

fn unexpected(
    store: &dyn gitiup_host::Host,
    wanted: Option<&Oid>,
) -> Result<Vec<String>, CliError> {
    let catalog = match wanted {
        Some(subject) => attest::list_for(store, subject),
        None => attest::list_all(store),
    }
    .map_err(|e| CliError::io(format!("list attestations: {e}")))?;
    Ok(catalog.unexpected)
}

fn parse(store: &dyn gitiup_host::Host, entry: &attest::Entry) -> Result<Parsed, CliError> {
    let bytes = attest::fetch(store, &entry.digest)
        .map_err(|e| CliError::io(format!("fetch {}: {e}", entry.digest)))?
        .ok_or_else(|| {
            CliError::new(
                gitiup_attest::ErrorKind::DigestMismatch,
                format!(
                    "{} is advertised by {} but the store cannot return its bytes",
                    entry.digest.short_default(),
                    entry.reference
                ),
                Some("a ref that names a missing object is a broken store, not a missing proof"),
            )
        })?;
    if gitiup_quorum::attestation::QuorumAttestation::looks_like(&bytes) {
        let quorum =
            <gitiup_quorum::attestation::QuorumAttestation as gitiup_quorum::record::Record>::load(
                &bytes,
            )
            .map_err(|e| CliError::io(format!("{}: {}", entry.digest.short_default(), e)))?;
        // It is a proof about proofs: its own digest stands where a `RunDigest` would,
        // and the result the quorum agreed on is the `ResultDigest` a reader cares about.
        return Ok(Parsed {
            tier: quorum.tier,
            signers: quorum
                .signatures
                .iter()
                .map(|signature| signature.key_id.clone())
                .collect(),
            claimed_at_us: quorum.claimed_at_us,
            run_digest: quorum
                .digest()
                .map(|digest| digest.to_string())
                .unwrap_or_default(),
            result_digest: quorum.result_digest.to_string(),
            runner: quorum.runner.clone(),
            sandbox: None,
            size: bytes.len() as u64,
        });
    }
    let doc = AttestationDoc::from_canonical_bytes(&bytes)?;
    Ok(Parsed {
        tier: doc.manifest.result.provenance.tier,
        signers: doc
            .signatures
            .iter()
            .map(|entry| entry.key_id.clone())
            .collect(),
        claimed_at_us: doc.manifest.claims.claimed_at_us,
        run_digest: doc.run_digest()?.to_string(),
        result_digest: doc.result_digest()?.to_string(),
        runner: doc.manifest.result.provenance.runner.clone(),
        sandbox: doc.manifest.result.provenance.sandbox.clone(),
        size: bytes.len() as u64,
    })
}

fn list(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(ATTEST_HELP) {
        return Ok(());
    }
    let store = read_store(args)?;
    let wanted = match args.get("--commit") {
        Some(text) => Some(subject(text)?),
        None => None,
    };
    if wanted.is_none() && !args.on("--all") {
        return Err(CliError::usage(
            "say what to list: --commit <oid> for one commit, or --all for the whole store",
        ));
    }
    let rows = rows(&*store.host, wanted.as_ref())?;
    let odd = unexpected(&*store.host, wanted.as_ref())?;

    if args.json() {
        let attestations: Vec<Value> = rows.iter().map(row_json).collect();
        print_json(json!({
            "store": store.what,
            "commit": wanted.map(|oid| oid.hex()),
            "count": attestations.len(),
            "attestations": attestations,
            "unexpected_refs": odd,
        }));
        return Ok(());
    }
    if rows.is_empty() {
        match wanted {
            Some(oid) => println!("no attestation for {} in {}", oid.hex(), store.what),
            None => println!("no attestations in {}", store.what),
        }
    }
    for row in &rows {
        match &row.detail {
            Ok(parsed) => println!(
                "{}  {}  {:<9} {:>19}  {}",
                row.entry.digest.short_default(),
                short(&parsed.run_digest),
                parsed.tier.to_string(),
                rfc3339(parsed.claimed_at_us),
                parsed
                    .signers
                    .iter()
                    .map(String::as_str)
                    .map(short)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Err(error) => println!(
                "{}  UNREADABLE  {}",
                row.entry.digest.short_default(),
                error.message
            ),
        }
    }
    for name in &odd {
        eprintln!("note: {name} is in the attestation namespace but not this layout");
    }
    let legacy = rows.iter().filter(|row| row.entry.legacy).count();
    if legacy > 0 {
        eprintln!(
            "note: {legacy} of them are filed in the old single-level shape; `gitiup attest \
             migrate` re-files them where a second proof can sit beside them"
        );
    }
    Ok(())
}

fn row_json(row: &Row) -> Value {
    let entry = &row.entry;
    let base = json!({
        "digest": entry.digest.hex(),
        "subject": entry.subject.hex(),
        "reference": entry.reference.as_str(),
        "shape": if entry.legacy { "legacy" } else { "current" },
        "published_at": entry.updated_at.map(|at| rfc3339(at.as_unix() as i64 * 1_000_000)),
        "published_by": entry.updated_by.as_ref().map(|actor| actor.as_str().to_string()),
    });
    match &row.detail {
        Ok(parsed) => json!({
            "digest": base["digest"],
            "subject": base["subject"],
            "reference": base["reference"],
            "shape": base["shape"],
            "published_at": base["published_at"],
            "published_by": base["published_by"],
            "run_digest": parsed.run_digest,
            "result_digest": parsed.result_digest,
            "tier": parsed.tier.as_str(),
            "runner": parsed.runner,
            "sandbox": parsed.sandbox,
            "signers": parsed.signers,
            "claimed_at": rfc3339(parsed.claimed_at_us),
            "claimed_at_us": parsed.claimed_at_us,
            "size": parsed.size,
            "warning": parsed.tier.trust_warning(),
        }),
        Err(error) => json!({
            "digest": base["digest"],
            "subject": base["subject"],
            "reference": base["reference"],
            "shape": base["shape"],
            "error": error.message,
        }),
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn show(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(ATTEST_HELP) {
        return Ok(());
    }
    let store = read_store(args)?;
    let wanted: Option<String> = args
        .get("--digest")
        .map(str::to_string)
        .or_else(|| args.positional.first().cloned());
    let subject = match args.get("--commit") {
        Some(text) => Some(subject(text)?),
        None => None,
    };
    let digest = match (wanted, subject) {
        (Some(hex), _) => {
            Oid::from_hex(&hex).map_err(|e| CliError::usage(format!("{hex}: {e}")))?
        }
        (None, Some(subject)) => {
            let rows = rows(&*store.host, Some(&subject))?;
            rows.first()
                .and_then(|row| row.detail.as_ref().ok().map(|_| row.entry.digest))
                .ok_or_else(|| {
                    CliError::refused(
                        format!("no attestation for {} in {}", subject.hex(), store.what),
                        "`gitiup attest list --all` shows what the store holds",
                    )
                })?
        }
        (None, None) => {
            return Err(CliError::usage(
                "say which attestation: a digest, --digest <hex>, or --commit <oid> for the \
                 newest for that commit",
            ));
        }
    };
    let entry = find(&*store.host, &digest)?;
    let bytes = attest::fetch(&*store.host, &digest)
        .map_err(|e| CliError::io(format!("fetch: {e}")))?
        .ok_or_else(|| {
            CliError::new(
                gitiup_attest::ErrorKind::DigestMismatch,
                format!("{digest} is not in the store"),
                Some("list what is: `gitiup attest list --all`"),
            )
        })?;
    // The store's honesty is checked here, not assumed: if these bytes do not re-hash
    // to the digest the ref names, the store is broken and every downstream
    // verification would be checking something other than what was signed.
    if Oid::hash_bytes(&bytes) != digest {
        return Err(CliError::new(
            gitiup_attest::ErrorKind::DigestMismatch,
            format!(
                "the bytes returned for {} hash to {}, not to the name they are stored under",
                digest.short_default(),
                Oid::hash_bytes(&bytes).short_default()
            ),
            Some("this host is not storing blobs verbatim"),
        ));
    }
    // A `tier: quorum` attestation lives in this namespace too, and it is not a run's
    // proof: it has no manifest, no steps and no DSSE payload of its own. Say what it is
    // and where it is read, rather than failing to parse it.
    if gitiup_quorum::attestation::QuorumAttestation::looks_like(&bytes) {
        if args.on("--bytes") && !args.on("--dsse") {
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|e| CliError::io(format!("write stdout: {e}")))?;
            return Ok(());
        }
        return Err(CliError::refused(
            format!(
                "{} is a `tier: quorum` attestation: a verdict about other attestations, \
                 not a run's own proof",
                short(&digest.hex())
            ),
            "read it with `gitiup verify attestation <digest> --tier quorum --store <dir>`, \
             which re-derives the verdict it states; `--bytes` still hands over the exact \
             signed bytes",
        ));
    }
    let doc = AttestationDoc::from_canonical_bytes(&bytes)?;

    if args.on("--bytes") {
        if args.on("--dsse") {
            return Err(CliError::usage(
                "--bytes and --dsse are different renderings",
            ));
        }
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::io(format!("write stdout: {e}")))?;
        return Ok(());
    }
    if args.on("--dsse") {
        print_json(doc.dsse_envelope()?);
        return Ok(());
    }
    let stored_subject = match &entry {
        Some(found) => found.subject.hex(),
        // Shown from a digest that no ref advertises (an unadvertised record is still
        // readable, and worth being able to look at): the manifest's own commit is
        // the best answer, and it is the one the signature covers.
        None => manifest_subject(&doc)?.hex(),
    };
    let reference = entry.as_ref().map(|found| found.reference.to_string());
    if args.json() {
        let document: Value = serde_json::from_slice(&bytes)
            .map_err(|e| CliError::io(format!("the stored bytes are not JSON: {e}")))?;
        print_json(json!({
            "store": store.what,
            "digest": digest.hex(),
            "subject": stored_subject,
            "reference": reference,
            "size": bytes.len(),
            "canonical": true,
            "run_digest": doc.run_digest()?.to_string(),
            "result_digest": doc.result_digest()?.to_string(),
            "commit": doc.manifest.result.source.commit.to_string(),
            "workflow": doc.manifest.result.source.workflow.path,
            "event": doc.manifest.result.source.event.name,
            "tier": doc.manifest.result.provenance.tier.as_str(),
            "runner": doc.manifest.result.provenance.runner,
            "sandbox": doc.manifest.result.provenance.sandbox,
            "normalisation_version": doc.manifest.result.provenance.normalisation_version,
            "signers": doc.signatures.iter().map(|s| json!({
                "key_id": s.key_id,
                "algorithm": s.algorithm.as_str(),
            })).collect::<Vec<_>>(),
            "claimed_at": rfc3339(doc.manifest.claims.claimed_at_us),
            "claimed_at_us": doc.manifest.claims.claimed_at_us,
            "steps": doc.manifest.result.steps.len(),
            "environment": doc.manifest.result.environment.describe(),
            "age": age(doc.manifest.claims.claimed_at_us),
            "warning": doc.manifest.result.provenance.tier.trust_warning(),
            "document": document,
        }));
        return Ok(());
    }
    println!("attestation {}", digest.hex());
    println!("  store     {}", store.what);
    if let Some(entry) = &entry {
        println!("  ref       {}", entry.reference);
    }
    println!("  subject   {stored_subject}");
    println!(
        "  commit    {} · workflow {} · event {}",
        doc.manifest.result.source.commit,
        doc.manifest.result.source.workflow.path,
        doc.manifest.result.source.event.name
    );
    println!(
        "  tier      {} · runner {} · sandbox {} · normalisation v{}",
        doc.manifest.result.provenance.tier,
        doc.manifest.result.provenance.runner,
        doc.manifest
            .result
            .provenance
            .sandbox
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        doc.manifest.result.provenance.normalisation_version
    );
    println!("  env       {}", doc.manifest.result.environment.describe());
    println!("  steps     {}", doc.manifest.result.steps.len());
    for signature in &doc.signatures {
        println!(
            "  signed    {} ({})",
            short(&signature.key_id),
            signature.algorithm.as_str()
        );
    }
    println!(
        "  claimed   {} ({})",
        rfc3339(doc.manifest.claims.claimed_at_us),
        age(doc.manifest.claims.claimed_at_us)
    );
    println!("  run       {}", doc.run_digest()?);
    println!("  result    {}", doc.result_digest()?);
    if let Some(warning) = doc.manifest.result.provenance.tier.trust_warning() {
        eprintln!("  warning   {warning}");
    }
    println!(
        "  note      verification (is any of the above *trusted*?) is `gitiup verify \
         attestation` (giti-1rs.8); this command prints what the store holds"
    );
    Ok(())
}

/// The listing entry a digest is advertised by, if any.
fn find(store: &dyn gitiup_host::Host, digest: &Oid) -> Result<Option<attest::Entry>, CliError> {
    Ok(attest::list_all(store)
        .map_err(|e| CliError::io(format!("list attestations: {e}")))?
        .entries
        .into_iter()
        .find(|entry| entry.digest == *digest))
}

// ---------------------------------------------------------------------------
// gc
// ---------------------------------------------------------------------------

fn gc(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(ATTEST_HELP) {
        return Ok(());
    }
    // D8 rule 3, answered before a store is even opened: a retention record from
    // somewhere else is evidence about *that* store, and an instruction from a stranger
    // is the one thing a deletion tool must never read.
    if let Some(path) = args.get("--evidence") {
        return evidence(path, args.json());
    }
    let store = participant::need_store(args)?;
    let max_per_commit =
        match args.get("--max-per-commit") {
            Some(text) => Some(text.parse::<usize>().map_err(|_| {
                CliError::usage(format!("--max-per-commit '{text}' is not a count"))
            })?),
            None => None,
        };
    let mut policy = Retention::new(args.get("--max-age"), max_per_commit)
        .map_err(|e| CliError::usage(format!("--max-age: {e}")))?;
    if let Some(text) = args.get("--max-bytes") {
        policy.max_bytes = Some(crate::fetch::human_bytes(text)?);
    }
    if policy.is_unbounded() {
        return Err(CliError::refused(
            "this policy could not prune anything",
            "give it a limit: --max-age 90d, --max-per-commit 5 or --max-bytes 500m (see \
             `gitiup attest gc --help`)",
        ));
    }
    let apply = args.on("--apply");
    let subject = match args.get("--commit") {
        Some(text) => Some(subject(text)?),
        None => None,
    };

    // What must survive, read from the store: every ref outside the attestation
    // namespace that points at an object. A quorum seat, a verdict, a merge record —
    // they all arrive as refs, so nothing here needs to know what a quorum is.
    let mut pins = attest::referenced(&*store.host)
        .map_err(|e| CliError::io(format!("what is still referenced: {e}")))?;
    // …plus the one thing a ref cannot show: a merge cites its proofs as digests *inside*
    // its record, and a digest inside a record is not a ref. Without this the evidence a
    // merge was made on is exactly what a retention policy would retire (ADR-0003 D8).
    for (digest, why) in gitiup_host::change::proof_pins(&*store.host)
        .map_err(|e| CliError::io(format!("what a merge cited: {e}")))?
    {
        attest::pin(&mut pins, digest, why);
    }
    for keep in args.all("--keep") {
        let oid = Oid::from_hex(keep.trim())
            .map_err(|e| CliError::usage(format!("--keep '{keep}' is not a digest: {e}")))?;
        attest::pin(&mut pins, oid, "--keep");
    }

    let rows = rows(&*store.host, subject.as_ref())?;
    let mut items = Vec::new();
    let mut undatable = Vec::new();
    for row in rows {
        match &row.detail {
            Ok(parsed) => items.push(AttestationItem {
                digest: row.entry.digest,
                subject: row.entry.subject,
                claimed_at_us: parsed.claimed_at_us,
                size: parsed.size,
                label: Some(parsed.tier.to_string()),
                reference: Some(row.entry.reference.as_str().to_string()),
            }),
            // An attestation whose claimed time cannot be read is not "very old": it
            // is unreadable, and deleting the unreadable ones is how a corrupt store
            // silently loses its newest proofs. They are reported and left alone.
            Err(error) => undatable.push(json!({
                "digest": row.entry.digest.hex(),
                "reference": row.entry.reference.as_str(),
                "error": error.message,
            })),
        }
    }
    // Retention authority, asked before anything is planned (ADR-0005 D8 rule 2).
    //
    // "Proofs older than this no longer matter" is an authority claim, not a housekeeping
    // preference, and the store entitled to make it is the one that gates merges on its
    // own proofs and can write the namespace it is pruning. Every copy here arrived by
    // import? Then this store is a mirror, and a mirror keeps a proof available — it does
    // not decide when one stops mattering. Capacity is the other story: "this disk is
    // full" is a fact about the box, so a mirror may answer that, among the copies it can
    // go and get again.
    if policy.by_authority() {
        let candidates: Vec<Oid> = attest::list_all(&*store.host)
            .map_err(|e| CliError::io(format!("list attestations: {e}")))?
            .entries
            .iter()
            .map(|entry| entry.digest)
            .collect();
        match provenance::prune_authority(&*store.host, &candidates)
            .map_err(|e| CliError::io(format!("what this store may prune: {e}")))?
        {
            PruneAuthority::Own => {}
            PruneAuthority::ReadOnly(why) => {
                return Err(CliError::refused(
                    format!(
                        "mirror_may_not_prune_by_age: {store} cannot write the namespace it is \
                         being asked to prune: {why}",
                        store = store.what
                    ),
                    "age and count are the origin's decisions. A read-only store may still \
                     evict for capacity — --max-bytes frees space among the copies it can \
                     fetch back — and if this store really is writable, say so in its \
                     [[remote]] options (`read-only = \"false\"`).",
                ));
            }
            PruneAuthority::Mirror { copies, total } => {
                return Err(CliError::refused(
                    format!(
                        "mirror_may_not_prune_by_age: all {copies} of the {total} attestations \
                         in {store} arrived by copy — every one has a kv/import/ record naming \
                         where it came from",
                        store = store.what
                    ),
                    "this store is a mirror, and age is not its decision to make: the origin's \
                     --max-age fires at the same instant on every copy anyway, because \
                     claimed_at_us is identical on all of them, so a mirror pruning by age \
                     only deletes early. Evict for capacity instead with --max-bytes, which \
                     touches only copies this store can name a re-fetch source for.",
                ));
            }
        }
    }

    // Which digests may be evicted for capacity: exactly the ones with an arrival record
    // saying where they came from. Everything else stays, however badly the limit is
    // missed, and is reported (`eviction_needs_source`).
    let sources: BTreeMap<Oid, String> = federation::arrivals(&*store.host)
        .map_err(|e| CliError::io(format!("what arrived here: {e}")))?
        .into_values()
        .filter_map(|arrival| {
            Oid::from_hex(&arrival.digest)
                .ok()
                .map(|digest| (digest, arrival.arrived_from))
        })
        .collect();
    let plan = attest::plan_with_sources(&policy, TimeUs::now().as_us(), &items, &pins, &sources);
    let report = attest::apply(
        &*store.host,
        &plan,
        &pins,
        &GcOptions {
            actor: gitiup_host::Actor::from_env(),
            // A capacity limit is about bytes on a disk, so the bytes are what this run
            // is after; a host that cannot forget them says so in the report instead of
            // the run quietly freeing nothing.
            purge_blobs: args.on("--purge-blobs") || policy.max_bytes.is_some(),
            dry_run: !apply,
            record: apply,
        },
    )
    .map_err(|e| CliError::io(format!("retention: {e}")))?;

    if args.json() {
        let value =
            serde_json::to_value(&report).map_err(|e| CliError::io(format!("report: {e}")))?;
        print_json(json!({
            "store": store.what,
            "report": value,
            "undatable": undatable,
            "note": if apply { "applied" } else { "dry run: nothing changed; add --apply" },
        }));
        // The report is printed first, then the refusal: a script that asked for JSON
        // gets the blocked list either way, and the exit code is the part a cron reads.
        return blocked_refusal(&report).map_or(Ok(()), Err);
    }
    println!("store    {}", store.what);
    println!("policy   {}", policy.describe());
    if policy.max_bytes.is_some() {
        println!(
            "note     a capacity eviction asks the host to forget the bytes too; a git store \
             and a versioned bucket will refuse and say why"
        );
    }
    println!("{}", report.summary_line());
    for pruned in &report.pruned {
        println!(
            "  {}  {:<10} {}",
            pruned.digest.short_default(),
            pruned.verdict.as_str(),
            pruned.verdict.describe()
        );
        if let attest::BlobAction::Refused { why } = &pruned.blob {
            println!("     bytes stay: {why}");
        }
    }
    for blocked in &report.blocked {
        println!(
            "  {}  {:<16} {}",
            blocked.digest.short_default(),
            blocked.token,
            attest::human_bytes(blocked.size)
        );
    }
    if let Some(line) = report.explain_nothing_pruned() {
        println!("  nothing to do: {line}");
    }
    if !undatable.is_empty() {
        eprintln!(
            "note: {} attestation(s) could not be read and were left alone (their digests \
             are in --json)",
            undatable.len()
        );
    }
    if let Some(error) = blocked_refusal(&report) {
        return Err(error);
    }
    if !apply {
        eprintln!("dry run: nothing changed. Add --apply to retire these.");
    } else if let Some(record) = report.record {
        println!("record   kv/gc/{record}");
    }
    Ok(())
}

/// The refusal a capacity eviction owes the operator when it could not make room
/// ([`gitiup_host::attest::Verdict::NeedsSource`], ADR-0005 D8 rule 2).
///
/// A line inside a report is not enough: a retention cron that exits 0 while the disk
/// stays full is the failure nobody notices. The blocked items are in the report either
/// way, so the refusal adds the exit code and names the way out.
fn blocked_refusal(report: &attest::Report) -> Option<CliError> {
    if report.blocked.is_empty() {
        return None;
    }
    Some(CliError::refused(
        format!(
            "eviction_needs_source: {} copy(ies) ({}) could not be evicted because no \
             kv/import/ record names where to fetch them back, and the store is still over \
             its capacity limit",
            report.blocked.len(),
            attest::human_bytes(report.blocked_bytes)
        ),
        "a mirror may only forget what it can go and get again. Either raise --max-bytes, \
         or re-copy these digests with `gitiup fetch` (without --no-records) so this store \
         knows where they came from.",
    ))
}

// ---------------------------------------------------------------------------
// gc --evidence: a retention record from another store
// ---------------------------------------------------------------------------

/// Read somebody else's retention record, and refuse to be instructed by it
/// ([ADR-0005 D8 rule 3](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
///
/// A `kv/gc/<digest>` record is the account a store gave of what it deleted and why. It
/// is worth carrying to a human — it is how you find out an origin has been pruning — and
/// it is worth precisely nothing to a machine, because two stores with the same bytes and
/// different retention policies are two healthy stores. The moment one store's deletion
/// could authorise another's, the most cautious mirror in the federation becomes the one
/// that deletes everything, on the day its policy is buggy and its owner is on holiday.
///
/// So this prints the record, in full, and exits 6 with `gc_record_not_instruction`.
fn evidence(path: &str, json: bool) -> Result<(), CliError> {
    let bytes = std::fs::read(path).map_err(|e| CliError::io(format!("{path}: {e}")))?;
    let record = attest::read_record(&bytes).map_err(|e| {
        CliError::refused(
            format!("{path}: {e}"),
            "the shape is the one `gitiup attest gc --apply` writes at kv/gc/<digest>; \
             `gitiup attest show` prints what a store holds",
        )
    })?;
    if json {
        print_json(json!({
            "record_type": "gc-evidence",
            "path": path,
            "says": record.evidence_line(),
            "record": serde_json::to_value(&record).unwrap_or(Value::Null),
            "token": attest::GC_EVIDENCE_NOT_INSTRUCTION,
            "acted": false,
        }));
    } else {
        println!("record   {path}");
        println!("says     {}", record.evidence_line());
        for pruned in &record.pruned {
            println!(
                "  {}  {:<12} {}",
                pruned.digest.short_default(),
                pruned.verdict.as_str(),
                pruned.verdict.describe()
            );
        }
        if let Some(line) = record.explain_nothing_pruned() {
            println!("  nothing was pruned: {line}");
        }
    }
    Err(CliError::refused(
        format!(
            "{}: the record above is {}'s account of what *that* store deleted; it is \
             evidence to a human and never an instruction to this one",
            attest::GC_EVIDENCE_NOT_INSTRUCTION,
            record.actor
        ),
        "nothing here was changed, and nothing will be because a stranger pruned something. \
         If this store has the same bytes and needs its own decision, run your own policy: \
         `gitiup attest gc --store <dir> --max-age <age> --apply`.",
    ))
}

// ---------------------------------------------------------------------------
// migrate
// ---------------------------------------------------------------------------

/// Move the store's legacy single-level attestation refs to `<subject>/<digest>`.
///
/// Same shape as `gc`: the run is a report first and a change only under `--apply`,
/// because what it moves is signed evidence and the operator should be able to read
/// the list before anything is rewritten.
fn migrate(args: &Args) -> Result<(), CliError> {
    if let Some(()) = args.help(ATTEST_HELP) {
        return Ok(());
    }
    let store = participant::need_store(args)?;
    let apply = args.on("--apply");
    let report = attest::migrate(
        &*store.host,
        &attest::MigrationOptions {
            actor: gitiup_host::Actor::from_env(),
            apply,
            record: apply,
        },
    )
    .map_err(|e| CliError::io(format!("migrate: {e}")))?;

    if args.json() {
        let value =
            serde_json::to_value(&report).map_err(|e| CliError::io(format!("report: {e}")))?;
        print_json(json!({
            "store": store.what,
            "report": value,
            "note": if apply { "applied" } else { "dry run: nothing changed; add --apply" },
        }));
        return Ok(());
    }
    println!("store  {}", store.what);
    println!("{}", report.summary_line());
    for moved in &report.moved {
        println!(
            "  {}  {} -> {}",
            moved.digest.short_default(),
            moved.from,
            moved.to
        );
    }
    for repaired in &report.repaired {
        println!(
            "  {}  re-filed after an interrupted move: {}",
            repaired.digest.short_default(),
            repaired.to
        );
    }
    for blocked in &report.blocked {
        println!("  {}  left alone: {}", blocked.reference, blocked.why);
    }
    if report.moved.is_empty() && report.repaired.is_empty() && report.blocked.is_empty() {
        println!("  nothing in the old single-level shape: this store is already current");
    }
    if !apply && !report.moved.is_empty() {
        eprintln!("dry run: nothing changed. Add --apply to move these.");
    } else if let Some(record) = report.record {
        println!("record kv/migrate/{record}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn print_json(value: Value) {
    keys::print_json(value);
}

/// A microsecond timestamp as RFC 3339 seconds, the unit humans read.
pub(crate) fn rfc3339(micros: i64) -> String {
    Timestamp::from_unix(micros.div_euclid(1_000_000).max(0) as u64).to_rfc3339()
}

/// "3d old", "12h old", "from the future" — a claim's age in the words a human
/// checks it against.
fn age(claimed_at_us: i64) -> String {
    let now = TimeUs::now().as_us();
    let delta = now - claimed_at_us;
    if delta < 0 {
        return format!("claimed {:.1}h in the future", -delta as f64 / 3.6e9);
    }
    let micros_per = [
        ("d", 86_400i64 * 1_000_000),
        ("h", 3_600 * 1_000_000),
        ("m", 60 * 1_000_000),
    ];
    for (unit, micros) in micros_per {
        if delta >= micros {
            return format!("{}{} old", delta / micros, unit);
        }
    }
    "moments old".to_string()
}

/// Shorten a long hex or key id for a table column, keeping its front and back.
///
/// Only long things are shortened: a short hex digest is easier read whole, and a
/// `SHA256:` fingerprint is exactly the case where the middle is the part nobody
/// compares.
pub(crate) fn short(text: &str) -> String {
    let trimmed = text.strip_prefix("sha256:").unwrap_or(text);
    let trimmed = trimmed.strip_prefix("SHA256:").unwrap_or(trimmed);
    if trimmed.len() <= 20 {
        return trimmed.to_string();
    }
    format!("{}…{}", &trimmed[..8], &trimmed[trimmed.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subject_is_a_subject_in_any_spelling() {
        let sha1 = "e255b091aabd7e443b5d2fbeb90bc9769d07cbeb";
        let direct = subject(sha1).unwrap();
        assert_eq!(direct.hex(), sha1);
        assert_eq!(subject(&format!("sha1:{sha1}")).unwrap(), direct);
        assert_eq!(subject(&format!("SHA1:{sha1}")).unwrap(), direct);
        for bad in ["", "nonsense", "sha1:zz", "sha512:11", "sha1:00"] {
            assert!(subject(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn the_shortener_keeps_what_identifies() {
        // Short enough to read whole stays whole; a long digest or fingerprint keeps
        // its front and back, which is what a human compares by eye.
        assert_eq!(short("sha256:0123456789abcdef"), "0123456789abcdef");
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(&"f".repeat(64)), "ffffffff…ffff");
        assert_eq!(short("SHA256:abcdefghijklmnopqrstuvwxyz"), "abcdefgh…wxyz");
    }

    #[test]
    fn ages_read_in_the_unit_they_are() {
        let now = TimeUs::now().as_us();
        assert!(age(now).contains("moments"), "{}", age(now));
        assert!(age(now - 3 * 86_400 * 1_000_000).contains("3d"));
        assert!(age(now - 7_200 * 1_000_000).contains("h"));
        assert!(age(now + 60 * 60 * 1_000_000).contains("future"));
    }

    #[test]
    fn the_help_text_names_every_subcommand_and_the_exit_table() {
        for word in [
            "push",
            "list",
            "show",
            "gc",
            "--commit",
            "--apply",
            "--max-age",
        ] {
            assert!(
                ATTEST_HELP.contains(word),
                "{word} is missing from the help"
            );
        }
        for code in ["0 ok", "2 usage", "3 I/O", "6 refused", "7", "8"] {
            assert!(ATTEST_HELP.contains(code), "{code} is missing");
        }
    }
}

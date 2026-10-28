//! `gitiup participant …` — volunteering to verify, and approving who may.
//!
//! This is the command-line half of giti-msi.2. The records and their rules live in
//! [`gitiup_quorum`]; what is here is argv, the keystore, and the two things a roster
//! needs that a library cannot supply: a human decision, and a store to put the signed
//! documents in.
//!
//! The plumbing below — where the store is, which keys can sign, whose signature makes a
//! roster a trust root, and how a record gets to `--out`/`--publish` — is `pub(crate)`,
//! because `gitiup select` (giti-msi.3) reads the same roster from the same store and
//! must not grow a second, slightly different answer to those questions. Two definitions
//! of "the current epoch" in one binary is exactly the bug this crate exists to avoid.
//!
//! ```text
//! gitiup participant register        a volunteer's self-signed sign-up
//! gitiup participant withdraw        a signed tombstone naming the epoch you leave at
//! gitiup participant list            who is on the roster, what they claimed, who is queued
//! gitiup participant verify-roster   check one epoch before you believe it
//! gitiup participant approve         the owner's act: a new signed epoch
//! gitiup participant revoke          kill a key, with a reason that decides what it voids
//! ```
//!
//! # The rules this surface keeps
//!
//! * **A sign-up proves a key and claims nothing about trust.** `register` signs the
//!   entry with the key it registers — that *is* the ownership proof — and files it at
//!   the lowest tier. The tier is the owner's vouch and the owner sets it when approving;
//!   a volunteer that could declare itself `trusted` would be a roster with no owner in
//!   it.
//! * **A claim must be measured.** `register` refuses to guess RAM, disk or the sandbox:
//!   those numbers are what selection filters on, and a default that flatters the box is
//!   a claim somebody else pays for. `gitiup env` and `gitiup doctor --sandbox` print what
//!   belongs here.
//! * **Nothing is published unless you say so.** Every command writes its record to
//!   `--out` and only `--publish` touches a store. An owner that approves by accident has
//!   changed a trust root.
//! * **A roster is only believed once it has been checked.** `list` and `verify-roster`
//!   run [`gitiup_quorum::Roster::verify`] first — canonical bytes, ownership proofs, a
//!   trusted owner signature, not expired — against owners named by `--owner`, which
//!   defaults to this machine's own keys and says so in the output.
//! * **Exit codes are the same table as everywhere else** (ADR-0001 D7): 2 usage ·
//!   3 I/O, no such key, store unreachable · 6 refused (unsigned or untrusted roster, an
//!   entry that cannot be taken at its word) · 7 a signature that does not verify ·
//!   8 a record whose bytes are not its own canonical form.
//!
//! # The round trip, in four commands
//!
//! ```text
//! volunteer$ gitiup participant register --ram-mb 32768 --disk-mb 262144 \
//!              --sandbox docker --sandbox-level 2 --out signup.json
//! owner$     gitiup participant approve --from signup.json --tier endorsed \
//!              --store ./store --publish
//! volunteer$ gitiup participant list --store ./store --json | jq '.entries[].capabilities'
//! owner$     gitiup participant verify-roster --store ./store --json
//! ```

use std::collections::BTreeSet;
use std::io::Read as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use gitiup_attest::{Signer as _, TimeUs, Trust};
use gitiup_host::{Config as HostConfig, FsHost, Host};
use gitiup_keys::config::Config as KeyConfig;
use gitiup_keys::keystore::Keystore;
use gitiup_quorum::prelude::*;
use gitiup_quorum::{Exclusion, exclusion_of, store};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::{self, Args};
use crate::remotes;

/// Help for `gitiup participant`.
pub const PARTICIPANT_HELP: &str = "\
gitiup participant — volunteering to verify a change, and approving who may

USAGE:
    gitiup participant register [OPTIONS]
    gitiup participant withdraw [OPTIONS]
    gitiup participant list [OPTIONS]
    gitiup participant verify-roster [PATH|-] [OPTIONS]
    gitiup participant approve [OPTIONS]              (the owner)
    gitiup participant revoke <KEY-ID> [OPTIONS]      (the owner)

A roster is one signed document per epoch: entries whose keys proved they own them, the
owner's tier for each, and the owner's signature as the approval. There is no protocol
and no directory — a volunteer publishes a sign-up, the owner carries it into the next
epoch or does not. See docs/quorum.md and ADR-0002.

WHERE RECORDS GO (every command):
    --store <dir>            a directory as the store (the fs host: kv/… and refs/…)
    --remote <name>          a remote from gitiup.toml (default: the configured one)
    --out <path|->           write the record's canonical bytes instead (or as well)
    --publish                publish into the store; without it, nothing is published

    --roster <path|->        any command: read “the epoch” from this document (or -, from
                             a pipe) instead of from a store — the file is verified the
                             same way, and nothing is fetched

register — claim what your box can do, signed by the key you are registering:
    --ram-mb <n>             required · usable RAM a job may have
    --disk-mb <n>            required · usable disk a job may have
    --sandbox <name>         required, repeatable · docker, podman, unshare, landlock…
    --sandbox-level <0..=3>  required · 0 none, 1 user-ns, 2 container, 3 + egress proxy
    --arch <name>            repeatable; default: the architecture of this build
    --image <digest>         repeatable · digest-pinned images already in the cache
    --can-pull               this box may pull an image it does not have
    --identity <key>         the principal anchor: a key id or a keystore name
                             (default: the signing key itself: one box, one identity)
    --key <selector>         which key signs (default: the current identity)

withdraw — leave, from an epoch you name:
    --effective-epoch <n>    first epoch to stay out of; default: the next one, because a
                             withdrawal that voids a round in flight looks like an attack
    --roster <path|->        the epoch you are leaving, when it is not a store's current one

list — who is on the epoch, and what they claimed:
    --pending                also show sign-ups waiting for the owner
    --require-arch <a> --require-ram-mb <n> --require-disk-mb <n>
    --require-sandbox <s> (repeatable) --require-min-sandbox-level <n>
    --require-image <digest> (repeatable)
                             score every entry against one job's requirements

verify-roster — believe it, then use it:
    --owner <key>            repeatable: key id or keystore name whose signature counts
                             (default: this machine's own keys, and the output says so)
    --epoch <n>              with a store: verify one published epoch, not the current

approve — the owner's act: build, sign and publish the next epoch:
    --from <path|->          repeatable: a sign-up file to admit
    --slot <hex>             repeatable: admit one queued sign-up by its slot
    --all                    admit every queued sign-up (say it; do not assume it)
    --tier <tier>            the vouch for what you admit: anonymous, endorsed, trusted
    --drop <key>             repeatable: leave this key out of the new epoch
    --keep <key>             repeatable: ignore this key's withdrawal for now
    --roster <path>          the epoch to succeed, from disk (default: the store's current)

revoke — a key is dead, and the reason says what that means:
    --reason <r>             required: retired, compromised, removed, superseded
    --roster <path|->        the current epoch, when it is not a store's
    --effective-epoch <n>    default: this epoch for `compromised`, the next one otherwise
    --bad-faith              with `removed`: void what this key already signed too
    --note <text>            free text for the record (never trusted)

All: -j, --json on anything a script reads. Passphrases follow `gitiup key`:
--passphrase-file <path|-> or GITIUP_KEY_PASSPHRASE, never a prompt a script cannot answer.

Exit codes: 0 ok · 2 usage · 3 I/O, no such key, store unreachable · 6 refused (unsigned
roster, untrusted owner, expired epoch, nothing to approve) · 7 a signature that does not
verify · 8 the bytes are not the record's canonical form.
";

/// The switches `gitiup participant …` accepts.
const SWITCHES: &[&str] = &[
    "--publish",
    "--can-pull",
    "--pending",
    "--all",
    "--bad-faith",
];

/// Valued flags for `gitiup participant …`.
const VALUED: &[&str] = &[
    "--key",
    "--arch",
    "--ram-mb",
    "--disk-mb",
    "--sandbox",
    "--sandbox-level",
    "--image",
    "--identity",
    "--out",
    "--store",
    "--remote",
    "--roster",
    "--owner",
    "--epoch",
    "--effective-epoch",
    "--from",
    "--slot",
    "--tier",
    "--drop",
    "--keep",
    "--reason",
    "--note",
    "--passphrase",
    "--passphrase-file",
    "--require-arch",
    "--require-ram-mb",
    "--require-disk-mb",
    "--require-sandbox",
    "--require-min-sandbox-level",
    "--require-image",
];

/// `gitiup participant …`
pub fn participant(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{PARTICIPANT_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{PARTICIPANT_HELP}");
            Ok(())
        }
        "register" => register(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "withdraw" => withdraw(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "list" => list(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "verify-roster" | "verify_roster" => {
            verify_roster(&Args::parse_with(&args[1..], VALUED, SWITCHES)?)
        }
        "approve" => approve(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "revoke" => revoke(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        other => Err(CliError::usage(format!(
            "unknown `gitiup participant` command '{other}'; `gitiup participant help` lists \
             register, withdraw, list, verify-roster, approve and revoke"
        ))),
    }
}

// ---------------------------------------------------------------------------
// the store, the keys, and the trust
// ---------------------------------------------------------------------------

/// A store the flags named, with a description of it for the output.
pub(crate) struct Opened {
    pub(crate) host: Box<dyn Host>,
    pub(crate) what: String,
}

/// The store `--store`/`--remote` names, if either does.
///
/// Read-only commands may fall back to the configured default remote — there is nothing
/// to damage by reading — while anything that writes requires the store to have been
/// named, so a mistyped remote cannot turn into a roster published somewhere else.
pub(crate) fn store_from(args: &Args) -> Result<Option<Opened>, CliError> {
    if let Some(dir) = args.get("--store") {
        let host =
            FsHost::open_or_create(dir).map_err(|e| CliError::io(format!("store '{dir}': {e}")))?;
        return Ok(Some(Opened {
            host: Box::new(host),
            what: format!("fs store {}", Path::new(dir).display()),
        }));
    }
    let named = args.get("--remote");
    if named.is_none() && args.get("--roster").is_some() {
        // The epoch came from disk: no store is needed, and opening one would be a
        // network round trip in a command that asked for a file.
        return Ok(None);
    }
    let Some((_path, config)) =
        HostConfig::load_default().map_err(|e| CliError::io(format!("gitiup.toml: {e}")))?
    else {
        return if named.is_some() {
            Err(CliError::refused(
                "no gitiup.toml was found, so no remote is configured",
                "point --store at a directory, or write a gitiup.toml \
                 (see `gitiup doctor --remotes`)",
            ))
        } else {
            Ok(None)
        };
    };
    let remote = config.remote_or_default(named).map_err(|e| {
        CliError::refused(
            format!("gitiup.toml: {e}"),
            "name a remote that exists, or use --store <dir>",
        )
    })?;
    let host = remotes::open(remote, config.credential_profile(remote))
        .map_err(|e| CliError::io(format!("remote '{}': {e}", remote.name)))?;
    let what = if named.is_some() {
        format!("remote '{}'", remote.name)
    } else {
        format!("remote '{}' (the configured default)", remote.name)
    };
    Ok(Some(Opened { host, what }))
}

/// The store, required: writing a record somewhere needs an explicit somewhere.
pub(crate) fn need_store(args: &Args) -> Result<Opened, CliError> {
    store_from(args)?.ok_or_else(|| {
        CliError::refused(
            "no store was named",
            "say where: --store <dir> or --remote <name> (see `gitiup doctor --remotes`)",
        )
    })
}

/// The keystore and the identity config: who can sign here, and who signs by default.
pub(crate) struct KeystoreHere {
    pub(crate) keys: Keystore,
    pub(crate) config: KeyConfig,
}

pub(crate) fn keystore() -> Result<KeystoreHere, CliError> {
    let keys = Keystore::new(keys::paths()?);
    let config = KeyConfig::load(keys.paths())?;
    Ok(KeystoreHere { keys, config })
}

/// The key to sign with — the same rules as `gitiup identity` (see [`keys::signing_key`]).
pub(crate) fn signing_key(
    args: &Args,
    here: &KeystoreHere,
) -> Result<gitiup_keys::signer::Key, CliError> {
    keys::signing_key(args, &here.keys, &here.config)
}

/// The epoch to treat as *current*: `--roster` if one was given, else the store's.
///
/// `--roster` is accepted by every command here, so on the two that need a current epoch
/// to default against — a withdrawal's `effective_epoch`, a revocation's — it has to mean
/// what it means on `list`: the epoch in question. Silently preferring a store the operator
/// did not name would be the same mistake as guessing one.
pub(crate) fn current_epoch(args: &Args) -> Result<Option<Roster>, CliError> {
    if let Some(path) = args.get("--roster") {
        return Ok(Some(Roster::from_canonical_bytes(&read_maybe_stdin(
            path,
        )?)?));
    }
    match store_from(args)? {
        Some(opened) => Ok(store::current_roster(&*opened.host)?),
        None => Ok(None),
    }
}

/// A key id, spelled either way: a `SHA256:…` fingerprint, or a name in the keystore.
///
/// Both spellings are accepted wherever a key is named, because the two people who type
/// one are a volunteer with their own `ssh-keygen -lf` output and an owner with a name
/// they gave a key last week.
pub(crate) fn key_id_of(here: &KeystoreHere, value: &str) -> Result<String, CliError> {
    let trimmed = value.trim();
    if trimmed.starts_with("SHA256:") {
        // Shape is checked by the library when the record is built; the prefix is the
        // signal that this is a fingerprint and not a name to look up.
        return Ok(trimmed.to_string());
    }
    let record = here.keys.find(trimmed).map_err(|e| {
        CliError::refused(
            format!("no key '{trimmed}' in the keystore: {e}"),
            "`gitiup key list` names them",
        )
    })?;
    Ok(record.key_id)
}

/// The owner trust: whose signature makes a roster a trust root.
///
/// `--owner` if given; otherwise this machine's own keys — the same local-trust rule
/// `gitiup identity verify` uses, and reported in every output, because a roster
/// believed because of a file listing is a roster believed by accident.
pub(crate) fn owner_trust(args: &Args, here: &KeystoreHere) -> Result<(Trust, String), CliError> {
    let named = args.all("--owner");
    if !named.is_empty() {
        let mut ids = BTreeSet::new();
        for value in &named {
            ids.insert(key_id_of(here, value)?);
        }
        return Ok((
            Trust::KeyIds(ids.clone()),
            format!("--owner, {} key(s)", ids.len()),
        ));
    }
    let records = here.keys.list()?;
    if records.is_empty() {
        return Err(CliError::refused(
            "nothing is trusted for rosters: no --owner was given and the keystore is empty",
            "`gitiup key gen` makes a key, or name one with --owner <key-id>",
        ));
    }
    let ids: BTreeSet<String> = records.iter().map(|r| r.key_id.clone()).collect();
    Ok((
        Trust::KeyIds(ids.clone()),
        format!("this machine's keystore, {} key(s)", ids.len()),
    ))
}

/// The roster to believe: from a file or from the store, already fully checked.
///
/// `--roster <path|->` wins over a store so an epoch can be audited offline, and the
/// checks are [`Roster::verify`]'s and not a subset of them: canonical bytes, structural
/// validity, every key-ownership proof, a trusted owner signature, and not expired.
fn roster_here(args: &Args, trust: &Trust, now: TimeUs) -> Result<(Roster, String), CliError> {
    if let Some(path) = args.get("--roster") {
        let roster = Roster::from_canonical_bytes(&read_maybe_stdin(path)?)?;
        roster.verify(trust, now)?;
        return Ok((roster, format!("file {path}")));
    }
    let opened = need_store(args)?;
    let roster = match args.get("--epoch") {
        Some(text) => {
            let epoch = text
                .parse::<u64>()
                .map_err(|_| CliError::usage(format!("--epoch wants a number, got '{text}'")))?;
            store::roster_at(&*opened.host, epoch)?.ok_or_else(|| {
                CliError::refused(
                    format!("the store has no roster epoch {epoch}"),
                    "`gitiup participant list` shows what is published",
                )
            })?
        }
        None => store::current_roster(&*opened.host)?.ok_or_else(|| {
            CliError::refused(
                format!("{} has no roster at refs/gitiup/roster", opened.what),
                "the owner publishes one with `gitiup participant approve --publish`",
            )
        })?,
    };
    roster.verify(trust, now)?;
    Ok((roster, opened.what))
}

/// A key id shortened for a terminal: `SHA256:abcd…wxyz`.
pub(crate) fn short(key_id: &str) -> String {
    let body = key_id.strip_prefix("SHA256:").unwrap_or(key_id);
    if body.len() <= 12 {
        key_id.to_string()
    } else {
        format!("SHA256:{}\u{2026}{}", &body[..4], &body[body.len() - 4..])
    }
}

pub(crate) fn read_maybe_stdin(path: &str) -> Result<Vec<u8>, CliError> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::io(format!("reading stdin: {e}")))?;
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| CliError::io(format!("reading '{path}': {e}")))
}

pub(crate) fn write_out(path: &str, bytes: &[u8]) -> Result<(), CliError> {
    if path == "-" {
        // The bytes and nothing else: `gitiup participant register --out - | …` is a
        // pipe, and a pipe does not want a progress line in it.
        std::io::stdout()
            .write_all(bytes)
            .map_err(|e| CliError::io(format!("writing stdout: {e}")))?;
        return Ok(());
    }
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::io(format!("creating {}: {e}", parent.display())))?;
    }
    std::fs::write(&path, bytes)
        .map_err(|e| CliError::io(format!("writing '{}': {e}", path.display())))?;
    Ok(())
}

/// Where a record went: `--out` writes bytes, `--publish` writes to the store, and a
/// command with neither has produced a record that exists only in this process — which
/// is worth saying out loud, because it is the state a human mistakes for "submitted".
pub(crate) struct Sink {
    pub(crate) written: Option<String>,
    pub(crate) published: Option<String>,
}

impl Sink {
    pub(crate) fn json(&self) -> Value {
        json!({ "written": self.written, "published": self.published })
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(path) = &self.written {
            out.push(format!("wrote {path}"));
        }
        if let Some(where_) = &self.published {
            out.push(format!("published to {where_}"));
        }
        if out.is_empty() {
            out.push(
                "not written: --out <path|-> to keep the record, --publish to offer it to a \
                 store"
                    .to_string(),
            );
        }
        out
    }
}

/// Hand one record to the places the flags named.
///
/// `--out` gets the exact canonical bytes — the same bytes a store would hold, so a
/// record handed over on a stick and a record read from a store verify identically — and
/// `publish` is called only when `--publish` was given.
pub(crate) fn emit(
    args: &Args,
    bytes: &[u8],
    publish: impl FnOnce(&dyn Host) -> Result<String, CliError>,
) -> Result<Sink, CliError> {
    let written = match args.get("--out") {
        Some(path) => {
            write_out(path, bytes)?;
            Some(if path == "-" {
                "stdout".to_string()
            } else {
                path.to_string()
            })
        }
        None => None,
    };
    let published = if args.on("--publish") {
        let opened = need_store(args)?;
        Some(format!("{} · {}", opened.what, publish(&*opened.host)?))
    } else {
        None
    };
    Ok(Sink { written, published })
}

/// The bytes are already on stdout, so the human summary would corrupt them.
pub(crate) fn only_bytes(args: &Args) -> bool {
    args.get("--out").is_some_and(|path| path == "-")
}

pub(crate) fn print_json(value: Value) {
    keys::print_json(value);
}

/// One roster entry as a script sees it.
///
/// The ticket's acceptance criterion is *claimed capabilities visible in
/// `gitiup participant list --json`*, so every claimed field is here under the name
/// [`Capabilities`] gives it, plus the slot a store keys it under and the eligibility
/// answer for the requirements that were asked about (if any).
fn entry_json(entry: &RosterEntry, epoch: u64, requirements: Option<&Requirements>) -> Value {
    let exclusion: Option<Exclusion> = requirements.and_then(|requirements| {
        exclusion_of(
            entry,
            epoch,
            requirements,
            &BTreeSet::new(),
            RosterTier::Anonymous,
        )
    });
    json!({
        "key_id": entry.key_id,
        "slot": gitiup_quorum::derive::key_slot(&entry.key_id),
        "identity": entry.identity,
        "tier": entry.tier.as_str(),
        "capabilities": entry.capabilities,
        "epochs_valid": { "from": entry.epochs_valid.from, "to": entry.epochs_valid.to },
        "ownership_proof": entry.has_ownership_proof(),
        "eligible": exclusion.is_none(),
        "excluded_by": exclusion.map(|exclusion| exclusion.as_str()),
    })
}

/// The requirements the `--require-*` flags describe, if any was given.
pub(crate) fn requirements_from(args: &Args) -> Result<Option<Requirements>, CliError> {
    let asked = [
        "--require-arch",
        "--require-ram-mb",
        "--require-disk-mb",
        "--require-sandbox",
        "--require-min-sandbox-level",
        "--require-image",
    ]
    .iter()
    .any(|flag| !args.all(flag).is_empty());
    if !asked {
        return Ok(None);
    }
    let megabytes = |flag: &str| -> Result<u64, CliError> {
        match args.all(flag).last() {
            Some(text) => text.parse::<u64>().map_err(|_| {
                CliError::usage(format!(
                    "{flag} wants a whole number of megabytes, got '{text}'"
                ))
            }),
            None => Ok(1),
        }
    };
    let level = args
        .get("--require-min-sandbox-level")
        .map(|text| {
            text.parse::<u8>().map_err(|_| {
                CliError::usage(format!(
                    "--require-min-sandbox-level wants 0..=3, got '{text}'"
                ))
            })
        })
        .transpose()?
        .unwrap_or(0);
    let sandboxes = args.all("--require-sandbox");
    let requirements = Requirements {
        // One architecture per round is the rule (ADR-0002 D7): a matrix with two is
        // two rounds, each with its own seed. A repeat means the later one won, which is
        // what every other `--require-*` flag here already does.
        arch: args
            .all("--require-arch")
            .last()
            .cloned()
            .unwrap_or_default(),
        ram_mb: megabytes("--require-ram-mb")?,
        disk_mb: megabytes("--require-disk-mb")?,
        image_digests: args.all("--require-image"),
        // Nothing named means "any backend the job would accept", which for a display
        // filter is every backend this build knows.
        sandboxes: if sandboxes.is_empty() {
            vec![
                String::from("docker"),
                String::from("podman"),
                String::from("unshare"),
                String::from("landlock"),
            ]
        } else {
            sandboxes
        },
        min_sandbox_level: level,
    };
    requirements.validate().map_err(|error| {
        CliError::refused(
            error.message(),
            "eligibility is scored against one job's requirements, and a job always names an \
             architecture: --require-arch says which one",
        )
    })?;
    Ok(Some(requirements))
}

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

fn register(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let key = signing_key(args, &here)?;
    let measured = |flag: &str, why: &str| -> Result<u64, CliError> {
        let text = args.get(flag).ok_or_else(|| {
            CliError::refused(
                format!("{flag} is required: {why}"),
                "`gitiup env` reports this machine's fingerprint; `gitiup doctor --sandbox` \
                 says what it can confine",
            )
        })?;
        text.parse::<u64>()
            .map_err(|_| CliError::usage(format!("{flag} wants a whole number, got '{text}'")))
    };
    let sandboxes = args.all("--sandbox");
    if sandboxes.is_empty() {
        return Err(CliError::refused(
            "--sandbox is required: a box with no sandbox may not join a roster",
            "`gitiup doctor --sandbox` says what this machine really provides",
        ));
    }
    let level = args
        .get("--sandbox-level")
        .map(|text| {
            text.parse::<u8>().map_err(|_| {
                CliError::usage(format!(
                    "--sandbox-level wants 0 (none), 1 (user namespace), 2 (container) or 3 \
                     (container plus egress proxy), got '{text}'"
                ))
            })
        })
        .transpose()?
        .ok_or_else(|| {
            CliError::refused(
                "--sandbox-level is required: a backend name is not a strength",
                "0 none · 1 user namespace · 2 container · 3 container plus egress proxy \
                 (see `gitiup doctor --sandbox --json`)",
            )
        })?;
    let entry = RosterEntry {
        key_id: key.key_id(),
        public_key: key.public_key().to_openssh(),
        // One box, one identity unless the operator says "this box belongs to that
        // principal": the anchor is what one-vote-per-identity counts, so guessing it
        // wrong is a vote-weight bug, not a cosmetic one.
        identity: match args.get("--identity") {
            Some(value) => key_id_of(&here, value)?,
            None => key.key_id(),
        },
        // The owner's vouch, so a sign-up may only claim the absence of one.
        tier: RosterTier::Anonymous,
        capabilities: Capabilities {
            arch: if args.all("--arch").is_empty() {
                // The one claim worth defaulting: the architecture is what this binary
                // was compiled for, so the default is a fact rather than a guess.
                vec![std::env::consts::ARCH.to_string()]
            } else {
                args.all("--arch")
            },
            ram_mb: measured(
                "--ram-mb",
                "a capability you did not measure is a claim selection trusts",
            )?,
            disk_mb: measured(
                "--disk-mb",
                "a job that runs out of disk diverges, it does not stretch",
            )?,
            image_cache: args.all("--image"),
            can_pull: args.on("--can-pull"),
            sandboxes,
            sandbox_level: level,
        },
        // A volunteer proposes no window: when an entry becomes eligible is the owner's
        // decision, taken in `approve`.
        epochs_valid: EpochWindow::open_from(0),
        self_signature: None,
    };
    let signup = SignUp::new(entry, &key)?;
    let bytes = signup.canonical_bytes()?;
    let slot = signup.slot();
    let sink = emit(&without_publish(args), &bytes, |host| {
        let oid = store::publish_signup(host, &signup)?;
        Ok(format!(
            "refs/gitiup/signup/{slot} ({} in kv/signup)",
            oid.hex()
        ))
    })?;

    if only_bytes(args) {
        return Ok(());
    }
    if args.json() {
        print_json(json!({
            "type": "signup",
            "key_id": signup.entry.key_id,
            "identity": signup.entry.identity,
            "slot": slot,
            "ref": format!("refs/gitiup/signup/{slot}"),
            "tier": signup.entry.tier.as_str(),
            "capabilities": signup.entry.capabilities,
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!("registered {}", short(&signup.entry.key_id));
    println!("  identity  {}", short(&signup.entry.identity));
    println!("  arch      {}", signup.entry.capabilities.arch.join(","));
    println!(
        "  ram/disk  {} MB / {} MB",
        signup.entry.capabilities.ram_mb, signup.entry.capabilities.disk_mb
    );
    println!(
        "  sandbox   {} (level {}){}",
        signup.entry.capabilities.sandboxes.join(","),
        signup.entry.capabilities.sandbox_level,
        if signup.entry.capabilities.can_pull {
            " · may pull"
        } else {
            " · cached images only"
        }
    );
    if !signup.entry.capabilities.image_cache.is_empty() {
        println!(
            "  cache     {} pinned image(s)",
            signup.entry.capabilities.image_cache.len()
        );
    }
    println!("  tier      anonymous — the owner decides (`gitiup participant approve`)");
    println!("  slot      {slot}");
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

/// A copy of the flags with `--publish` removed.
///
/// `emit` reads `--publish` from the flag set, and every command here writes its record
/// *before* it prints a summary; passing the same args to a second `emit` would publish
/// twice. This is not that — it is the guard that makes "publish once" structural rather
/// than a comment.
fn without_publish(args: &Args) -> Args {
    let mut copy = Args {
        positional: args.positional.clone(),
        values: args.values.clone(),
        repeats: args.repeats.clone(),
        annotations: args.annotations.clone(),
        switches: args.switches.clone(),
    };
    copy.switches.remove("--publish");
    copy
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------

fn withdraw(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let key = signing_key(args, &here)?;
    let now = TimeUs::now();
    let key_id = key.key_id();
    // The default is the *next* epoch: a withdrawal that voids a round already in flight
    // is indistinguishable from an attack on it, so leaving is a forward step
    // (ADR-0002 D8's rotation table).
    let effective_epoch = match args.get("--effective-epoch") {
        Some(text) => text.parse::<u64>().map_err(|_| {
            CliError::usage(format!(
                "--effective-epoch wants a whole number, got '{text}'"
            ))
        })?,
        None => {
            let roster = current_epoch(args)?.ok_or_else(|| {
                CliError::refused(
                    "no epoch is published, so there is nothing to withdraw from",
                    "name one with --effective-epoch, or point --roster at the epoch you are \
                     leaving",
                )
            })?;
            Roster::next_epoch(roster.epoch, now.as_us(), roster.epoch_interval_us)?
        }
    };
    let mut withdrawal = Withdrawal::new(key_id.clone(), effective_epoch, now.as_us());
    withdrawal.sign(&key)?;
    withdrawal.verify()?;
    let bytes = withdrawal.canonical_bytes()?;
    let slot = withdrawal.slot();
    let sink = emit(args, &bytes, |host| {
        let oid = store::publish_withdrawal(host, &withdrawal)?;
        Ok(format!(
            "refs/gitiup/withdrawal/{slot} ({} in kv/withdrawal)",
            oid.hex()
        ))
    })?;
    if only_bytes(args) {
        return Ok(());
    }
    if args.json() {
        print_json(json!({
            "type": "withdrawal",
            "key_id": key_id,
            "slot": slot,
            "effective_epoch": effective_epoch,
            "issued_at_us": now.as_us(),
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!(
        "withdrew {} from epoch {effective_epoch} onward",
        short(&key_id)
    );
    println!(
        "  the owner applies it with `gitiup participant approve`; until then this key is \
         still on the current epoch, and a round already pinned to it still counts"
    );
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn list(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let (trust, trust_source) = owner_trust(args, &here)?;
    let now = TimeUs::now();
    let (roster, source) = roster_here(args, &trust, now)?;
    let requirements = requirements_from(args)?;
    let entries: Vec<Value> = roster
        .entries
        .iter()
        .map(|entry| entry_json(entry, roster.epoch, requirements.as_ref()))
        .collect();
    let identities = roster.identities().len();
    let expired = now.as_us() > roster.valid_until_us;
    let pending: Vec<Value> = if args.on("--pending") {
        match store_from(args)? {
            Some(opened) => store::list_signups(&*opened.host)?
                .iter()
                .map(|signup| {
                    json!({
                        "key_id": signup.entry.key_id,
                        "slot": signup.slot(),
                        "identity": signup.entry.identity,
                        "tier": signup.entry.tier.as_str(),
                        "capabilities": signup.entry.capabilities,
                        "already_on_the_epoch": roster.entry(&signup.entry.key_id).is_some(),
                    })
                })
                .collect(),
            // A roster read from disk has no queue beside it, and inventing a store to
            // look in would be a fetch nobody asked for.
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    if args.json() {
        print_json(json!({
            "source": source,
            "trusted_via": trust_source,
            "epoch": roster.epoch,
            "digest": roster.digest()?,
            "previous_digest": roster.prev_roster_digest,
            "issued_at_us": roster.issued_at_us,
            "valid_until_us": roster.valid_until_us,
            "epoch_interval_us": roster.epoch_interval_us,
            "expired": expired,
            "requirements": requirements,
            "entries": entries,
            "summary": {
                "entries": roster.entries.len(),
                "identities": identities,
                "seats_required": gitiup_quorum::defaults::N,
                "can_field_a_quorum": identities >= gitiup_quorum::defaults::N,
            },
            "pending": pending,
        }));
        return Ok(());
    }
    println!(
        "roster epoch {} — {source} · {} entries · {identities} identities",
        roster.epoch,
        roster.entries.len()
    );
    println!("  digest  {}", roster.digest()?);
    println!(
        "  valid   until {}{}",
        TimeUs(roster.valid_until_us).to_rfc3339(),
        if expired {
            " — EXPIRED: no new round may pin this epoch"
        } else {
            ""
        }
    );
    println!("  trusted via {trust_source}");
    if let Some(requirements) = &requirements {
        println!(
            "  against {} · {} MB ram · {} MB disk · sandbox {} · level {}{}",
            requirements.arch,
            requirements.ram_mb,
            requirements.disk_mb,
            requirements.sandboxes.join("|"),
            requirements.min_sandbox_level,
            if requirements.image_digests.is_empty() {
                String::new()
            } else {
                format!(" · {} pinned image(s)", requirements.image_digests.len())
            }
        );
    }
    for entry in &roster.entries {
        let exclusion = requirements.as_ref().and_then(|requirements| {
            exclusion_of(
                entry,
                roster.epoch,
                requirements,
                &BTreeSet::new(),
                RosterTier::Anonymous,
            )
        });
        println!(
            "\n  {} · {} · {}",
            short(&entry.key_id),
            entry.tier.as_str(),
            match exclusion {
                None => "eligible".to_string(),
                Some(reason) => format!("not eligible ({reason})"),
            }
        );
        println!(
            "    slot  {}",
            gitiup_quorum::derive::key_slot(&entry.key_id)
        );
        println!(
            "    caps  {} · {} MB ram · {} MB disk · sandbox {} level {} · {}",
            entry.capabilities.arch.join("+"),
            entry.capabilities.ram_mb,
            entry.capabilities.disk_mb,
            entry.capabilities.sandboxes.join("/"),
            entry.capabilities.sandbox_level,
            if entry.capabilities.can_pull {
                "pulls"
            } else {
                "cache only"
            }
        );
        if !entry.capabilities.image_cache.is_empty() {
            println!("    cache {}", entry.capabilities.image_cache.join(", "));
        }
        println!(
            "    epochs {}..={} · identity {}",
            entry.epochs_valid.from,
            entry.epochs_valid.to,
            short(&entry.identity)
        );
    }
    if identities < gitiup_quorum::defaults::N {
        println!(
            "\nnote: {identities} identities cannot field the default {}-seat quorum; a round \
             here will report `seats not filled` until the roster grows",
            gitiup_quorum::defaults::N
        );
    }
    if args.on("--pending") {
        println!("\nsign-ups waiting for the owner: {}", pending.len());
        for signup in &pending {
            println!(
                "  {} · slot {} · {}",
                signup["key_id"].as_str().map(short).unwrap_or_default(),
                signup["slot"].as_str().unwrap_or_default(),
                if signup["already_on_the_epoch"].as_bool().unwrap_or(false) {
                    "already on this epoch"
                } else {
                    "new"
                },
            );
        }
        if !pending.is_empty() {
            println!("admit one with `gitiup participant approve --slot <hex> --tier <tier>`");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify-roster
// ---------------------------------------------------------------------------

/// One line of the report: a check, its verdict, and the sentence.
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

enum Status {
    Ok,
    Warn,
    Fail,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            name,
            status: Status::Ok,
            detail: detail.into(),
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "check": self.name,
            "status": match self.status {
                Status::Ok => "ok",
                Status::Warn => "warn",
                Status::Fail => "fail",
            },
            "detail": self.detail,
        })
    }
}

fn verify_roster(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let (trust, trust_source) = owner_trust(args, &here)?;
    let now = TimeUs::now();
    // The checks are collected rather than short-circuited: the question a reviewer asks
    // is "what is wrong with this roster", in full, not "what is the first thing wrong".
    let (roster, source) = match roster_here(args, &trust, now) {
        Ok(found) => found,
        Err(error) => {
            // `roster_here` *is* the trust check, so a refusal there is the whole answer:
            // there is no eligibility to explain about a roster that is not a trust root.
            let checks = vec![Check {
                name: "roster",
                status: Status::Fail,
                detail: error.message.clone(),
            }];
            report(args, &checks, None, "unknown", &trust_source)?;
            return Err(error);
        }
    };
    let trusted = roster.verify(&trust, now)?;
    let proofs = roster
        .entries
        .iter()
        .filter(|entry| entry.has_ownership_proof())
        .count();
    let expected = roster.expected_epoch(now.as_us())?;
    let mut checks = vec![
        Check::ok(
            "canonical",
            "the bytes are this record's canonical encoding and re-encode identically",
        ),
        Check::ok(
            "owner-signature",
            format!(
                "{} trusted owner signature(s), via {trust_source}: {}",
                trusted.len(),
                trusted
                    .iter()
                    .map(|k| short(k))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Check {
            name: "ownership-proofs",
            status: if proofs == roster.entries.len() {
                Status::Ok
            } else {
                Status::Fail
            },
            detail: format!(
                "{proofs} of {} entries carry a key-ownership proof",
                roster.entries.len()
            ),
        },
        Check::ok(
            "entries",
            format!(
                "{} entries, {} distinct identities, unique and sorted by key id",
                roster.entries.len(),
                roster.identities().len()
            ),
        ),
        Check {
            name: "epoch-is-current",
            status: if roster.epoch >= expected {
                Status::Ok
            } else {
                Status::Warn
            },
            detail: if roster.epoch >= expected {
                format!(
                    "epoch {} is what the clock expects (interval {} days)",
                    roster.epoch,
                    roster.epoch_interval_us / (24 * 60 * 60 * 1_000_000)
                )
            } else {
                format!(
                    "the clock says epoch {expected} should exist; this is epoch {}, so a \
                     store offering it is behind or rolling back",
                    roster.epoch
                )
            },
        },
    ];
    // With a store, the epoch's own ref is the audit trail: a stranger re-deriving a
    // past selection has to be able to fetch *that* roster, not just the current one.
    if let Some(opened) = store_from(args)? {
        let published = store::roster_at(&*opened.host, roster.epoch)?;
        let agrees = match (&published, roster.digest()) {
            (Some(found), Ok(digest)) => found.digest()? == digest,
            _ => false,
        };
        checks.push(Check {
            name: "published",
            status: if agrees { Status::Ok } else { Status::Warn },
            detail: if agrees {
                format!(
                    "refs/gitiup/roster/{:08x} in {} holds this digest",
                    roster.epoch, opened.what
                )
            } else {
                format!(
                    "this epoch is not at refs/gitiup/roster/{:08x} in {}; a round that pins \
                     it cannot be audited against it",
                    roster.epoch, opened.what
                )
            },
        });
    }
    let failed = checks
        .iter()
        .any(|check| matches!(check.status, Status::Fail));
    report(args, &checks, Some(&roster), &source, &trust_source)?;
    if failed {
        return Err(CliError::refused(
            "a check failed above",
            "fix the roster: a trust root that half-checks is a trust root that lies",
        ));
    }
    Ok(())
}

fn report(
    args: &Args,
    checks: &[Check],
    roster: Option<&Roster>,
    source: &str,
    trust: &str,
) -> Result<(), CliError> {
    let failed = checks
        .iter()
        .any(|check| matches!(check.status, Status::Fail));
    if args.json() {
        let body = json!({
            "source": source,
            "trusted_via": trust,
            "epoch": roster.map(|roster| roster.epoch),
            "digest": roster.map(|roster| roster.digest()).transpose()?,
            "entries": roster.map(|roster| roster.entries.len()).unwrap_or(0),
            "checks": checks.iter().map(Check::as_json).collect::<Vec<_>>(),
            "ok": !failed,
        });
        print_json(body);
        return Ok(());
    }
    println!("verify-roster — {source}");
    if let Some(roster) = roster {
        println!(
            "  epoch {} · {} entries · digest {}",
            roster.epoch,
            roster.entries.len(),
            roster.digest()?
        );
    }
    for check in checks {
        let mark = match check.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        };
        println!("  [{mark}] {:<17} {}", check.name, check.detail);
    }
    if failed {
        println!("refused: a check above failed (exit 6)");
    } else {
        println!("this epoch is a trust root: approved, unexpired, and every key proved");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// approve (the owner)
// ---------------------------------------------------------------------------

fn approve(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let owner = signing_key(args, &here)?;
    let now = TimeUs::now();
    let opened = store_from(args)?;
    // The epoch being succeeded. Without a predecessor there is nothing to bump, so the
    // first epoch is built on a genesis digest: epochs are a chain from the start, and a
    // first epoch with no parent is how a rollback becomes visible.
    let previous: Option<Roster> = match args.get("--roster") {
        Some(path) => Some(Roster::from_canonical_bytes(&read_maybe_stdin(path)?)?),
        None => match &opened {
            Some(opened) => store::current_roster(&*opened.host)?,
            None => None,
        },
    };
    let interval = previous
        .as_ref()
        .map(|roster| roster.epoch_interval_us)
        .unwrap_or(gitiup_quorum::roster::DEFAULT_EPOCH_INTERVAL_US);
    let epoch = Roster::next_epoch(
        previous.as_ref().map(|roster| roster.epoch).unwrap_or(0),
        now.as_us(),
        interval,
    )?;

    // What goes in: sign-ups named by file or by queue slot, and nothing else. `--all`
    // is its own flag on purpose — admitting "everything in the queue" should be something
    // the owner typed, not what happens when they forgot to say.
    let mut additions: Vec<RosterEntry> = Vec::new();
    for path in args.all("--from") {
        additions.push(SignUp::from_canonical_bytes(&read_maybe_stdin(&path)?)?.entry);
    }
    let wanted = args.all("--slot");
    let queued = if wanted.is_empty() && !args.on("--all") {
        Vec::new()
    } else {
        let opened = opened.as_ref().ok_or_else(|| {
            CliError::refused(
                "--slot and --all read the store's queue of sign-ups",
                "name a store, or admit a file with --from <signup>",
            )
        })?;
        store::list_signups(&*opened.host)?
    };
    for slot in &wanted {
        let signup = queued
            .iter()
            .find(|signup| signup.slot() == *slot)
            .ok_or_else(|| {
                CliError::refused(
                    format!("no sign-up is published at slot {slot}"),
                    "`gitiup participant list --pending --json` lists what is queued",
                )
            })?;
        additions.push(signup.entry.clone());
    }
    if args.on("--all") {
        additions.extend(queued.iter().map(|signup| signup.entry.clone()));
    }
    let tier = match args.get("--tier") {
        Some(text) => RosterTier::parse(text)?,
        // The vouch has to be typed at least once: defaulting to `trusted` would let a
        // flag nobody passes inflate a tier, which is the opposite of a vouch.
        None => RosterTier::Anonymous,
    };
    for entry in &mut additions {
        entry.tier = tier;
    }

    // What comes out: what the owner drops, and every withdrawal whose epoch has
    // arrived — a key that asked to leave at epoch 40 is not in epoch 41.
    let mut removals: BTreeSet<String> = args
        .all("--drop")
        .iter()
        .map(|value| key_id_of(&here, value))
        .collect::<Result<_, _>>()?;
    let kept: BTreeSet<String> = args
        .all("--keep")
        .iter()
        .map(|value| key_id_of(&here, value))
        .collect::<Result<_, _>>()?;
    if let Some(opened) = &opened {
        for withdrawal in store::list_withdrawals(&*opened.host)? {
            if withdrawal.effective_epoch <= epoch && !kept.contains(&withdrawal.key_id) {
                removals.insert(withdrawal.key_id.clone());
            }
        }
    }
    if additions.is_empty() && removals.is_empty() {
        return Err(CliError::refused(
            "nothing to approve: no sign-up was named and nothing is being dropped",
            "--from <signup>, --slot <hex> or --all admits; --drop <key> removes",
        ));
    }
    let base = match &previous {
        Some(roster) => roster.clone(),
        None => Roster::new(
            epoch,
            gitiup_attest::Digest::sha256(b"gitiup-roster-1 genesis"),
            now.as_us(),
            interval,
            Vec::new(),
        )?,
    };
    let mut next = Roster::next_epoch_from(&base, now.as_us(), additions, &removals)?;
    next.sign(&owner)?;
    // Sign it, then believe it: an owner that cannot verify its own new epoch has
    // published a document its own policy will refuse.
    let (trust, _) = owner_trust(args, &here)?;
    next.verify(&trust, now)?;
    let bytes = next.canonical_bytes()?;
    let sink = emit(args, &bytes, |host| {
        let oid = store::publish_roster(host, &next)?;
        Ok(format!("refs/gitiup/roster ({} in kv/roster)", oid.hex()))
    })?;
    let added: BTreeSet<String> = next
        .entries
        .iter()
        .filter(|entry| {
            !previous
                .as_ref()
                .is_some_and(|p| p.entry(&entry.key_id).is_some())
        })
        .map(|entry| entry.key_id.clone())
        .collect();
    if args.json() {
        print_json(json!({
            "epoch": next.epoch,
            "previous_digest": next.prev_roster_digest,
            "digest": next.digest()?,
            "valid_until_us": next.valid_until_us,
            "signed_by": next.signatures.iter().map(|s| s.key_id.clone()).collect::<Vec<_>>(),
            "entries": next.entries.iter().map(|e| entry_json(e, next.epoch, None)).collect::<Vec<_>>(),
            "added": added.iter().cloned().collect::<Vec<_>>(),
            "removed": removals.iter().cloned().collect::<Vec<_>>(),
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!(
        "epoch {} — {} entries ({} added, {} removed)",
        next.epoch,
        next.entries.len(),
        added.len(),
        removals.len()
    );
    println!("  digest  {}", next.digest()?);
    println!("  prev    {}", next.prev_roster_digest);
    println!(
        "  valid   until {}",
        TimeUs(next.valid_until_us).to_rfc3339()
    );
    println!("  signed  {}", short(&owner.key_id()));
    for key_id in &added {
        println!("  + {key_id}");
    }
    for key_id in &removals {
        println!("  - {key_id}");
    }
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// revoke (the owner)
// ---------------------------------------------------------------------------

fn revoke(args: &Args) -> Result<(), CliError> {
    if args.help(PARTICIPANT_HELP).is_some() {
        return Ok(());
    }
    let here = keystore()?;
    let key = signing_key(args, &here)?;
    let now = TimeUs::now();
    let target = key_id_of(&here, args.need("the key id to revoke")?)?;
    let reason = RevocationReason::parse(args.get("--reason").ok_or_else(|| {
        CliError::refused(
            "--reason is required: the reason decides what the revocation voids",
            "retired · compromised · removed · superseded (ADR-0002 D9)",
        )
    })?)?;
    let epoch = current_epoch(args)?.map(|roster| roster.epoch).unwrap_or(0);
    // A compromised key stops *now*, because a thief signs tomorrow with yesterday's
    // key; everything else is a forward step, so that a rotation or a retirement does
    // not retroactively distrust honest work.
    let effective_epoch = match args.get("--effective-epoch") {
        Some(text) => text.parse::<u64>().map_err(|_| {
            CliError::usage(format!(
                "--effective-epoch wants a whole number, got '{text}'"
            ))
        })?,
        None if reason == RevocationReason::Compromised => epoch,
        None => epoch + 1,
    };
    let mut revocation = Revocation::new(target.clone(), reason, effective_epoch, now.as_us());
    revocation.bad_faith = args.on("--bad-faith");
    revocation.note = args.get("--note").map(str::to_string);
    revocation.sign(&key)?;
    let (trust, _) = owner_trust(args, &here)?;
    revocation.verify(&trust)?;
    let bytes = revocation.canonical_bytes()?;
    let slot = revocation.slot();
    let sink = emit(args, &bytes, |host| {
        let oid = store::publish_revocation(host, &revocation)?;
        Ok(format!(
            "refs/gitiup/revocation/{slot} ({} in kv/revocation)",
            oid.hex()
        ))
    })?;
    if only_bytes(args) {
        return Ok(());
    }
    if args.json() {
        print_json(json!({
            "type": "revocation",
            "key_id": target,
            "slot": slot,
            "reason": reason.as_str(),
            "effective_epoch": effective_epoch,
            "bad_faith": revocation.bad_faith,
            "issuer": revocation.issuer,
            "voids_current_epoch": revocation.voids(epoch),
            "where": sink.json(),
        }));
        return Ok(());
    }
    println!("revoked {target}");
    println!("  reason    {reason}");
    println!("  effective epoch {effective_epoch}");
    println!(
        "  voids     {}",
        if revocation.voids(epoch) {
            "rounds pinned to the current epoch too"
        } else {
            "only rounds opened from a later epoch"
        }
    );
    println!(
        "  next      a revocation is always accompanied by an epoch bump: `gitiup participant \
         approve --drop {target}`"
    );
    for line in sink.lines() {
        println!("{line}");
    }
    Ok(())
}

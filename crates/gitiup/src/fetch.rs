//! `gitiup fetch` and `gitiup push` — move attestation and change namespaces between
//! hosts ([ADR-0005](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
//!
//! Both verbs are [`gitiup_host::federation::copy`] with the two hosts in the other
//! order, and that identity is the point: there is one set of rules about what may
//! travel, and it does not depend on which end you happened to type the command at.
//!
//! ```text
//! gitiup fetch --remote upstream --store ./store --change chg-6a6a8eab778ba4d0
//! gitiup push  --remote mirror   --store ./store --proofs-only
//! ```
//!
//! # What a copy is, and what it is not
//!
//! A copy moves **bytes**. It cannot move a trust decision, and this module is where that
//! becomes visible in a flag list: there is no `--trust-remote`, no `--from-trusted`, no
//! `--owner` that would let a store URL reach a trust list. `gitiup verify` is the
//! command that produces a belief, and it takes trust roots from *this* machine's
//! config, never from wherever the bytes came from (D3). The report says `trust none` on
//! every run of every host pair; there is no value of any flag that changes it.
//!
//! What travels is the portable set — attestations, change attempts and merge records,
//! roster epochs, rounds, verdicts, commitments, reveals, the policy history — and what
//! does not is everything whose meaning is *now*: a lease, a job advertisement, a pending
//! sign-up, the live `roster`/`policy/current`/`change … /head` pointers, this store's
//! own arrival and gc records, its `refs/heads/**`. Every omission is named in the
//! report by its token, because "we did not copy that" has to be a sentence and not a
//! silence (D2).
//!
//! # Resumable, idempotent, and boring about it
//!
//! Bytes before refs, create-only refs, pointers moved last and only forward: re-running
//! a fetch moves nothing and reports `already`, and a run that dies halfway leaves bytes
//! nobody advertises rather than an advertisement nobody can satisfy. `gitiup attest gc`
//! holds the same rule from the other end: a store never advertises less than it did.
//!
//! # Exit codes
//!
//! The same table as the rest of `gitiup`: 0 ok · 2 usage · 3 I/O or an unreachable
//! store · 6 refused (a read-only destination, a budget busted, a pointer that had
//! diverged, or — with `--strict` — any refusal at all) · 8 bytes that are not the bytes
//! their name promises. A per-record refusal does not fail the run, because one
//! unimportable proof must not end a fetch of two hundred; `--strict` is for the CI job
//! that would rather know (D10).

use std::path::{Path, PathBuf};

use crate::CliError;
use crate::keys::Args;
use crate::remotes;
use gitiup_host::change::ChangeId;
use gitiup_host::federation::{self, Options, Verb};
use gitiup_host::{Config as HostConfig, FsHost, Host, Oid, RemoteConfig};

/// Help for both verbs: one surface, two directions.
pub const TRANSPORT_HELP: &str = "\
gitiup fetch | push — move attestations, changes and their evidence between two stores

USAGE:
    gitiup fetch [OPTIONS]
    gitiup push  [OPTIONS]

`fetch` pulls a copy into a store; `push` publishes a copy out to one. They are the same
operation seen from the two ends, and they move the same set either way.

BETWEEN WHICH STORES:
    --remote <name>          the far side: the store being fetched from, or pushed to
    --store <dir>            the near side, when it is a directory store
    --from <name|dir>        say the source explicitly (overrides --remote/--store)
    --to <name|dir>          say the destination explicitly
                             with neither --from nor --to, the near side is --store, or
                             the configured default remote; the far side is --remote, and
                             one of them has to be named. A remote is a [[remote]] in
                             gitiup.toml (see `gitiup doctor --remotes`), so fs, a bucket,
                             a served repository and a forge adapter can each stand on
                             either side

WHAT TO MOVE:
    --change <id>            one change: its attempts, its merge or abandon record, the
                                 quorum records addressed to it, and the proofs filed for
                                 the commits its attempts propose
    --commit <oid>           the proofs filed about one object (40 or 64 hex, or sha1:/sha256:)
    (no filter)              every portable ref the source advertises
    --proofs-only            evidence without code history — what a read-only public mirror
                                 of a private repository wants. It declines the pack step
                                 outright, so the subject objects an attestation is about
                                 are excused, in the report, on purpose

HOW FAR TO GO:
    --dry-run                report what would move and write nothing
    --strict                 any refusal at all fails the command (exit 6), not just an
                                 integrity failure
    --no-records             do not write the kv/import/<digest> arrival record for each
                                 digest that lands (they answer 'how did this get here', and
                                 a store that has them is what may evict for capacity)
    --max-records <n>        records per run (default 4096): a refusal, never a truncation
    --max-bytes <size>       new bytes per run (default 1 GiB; 500m, 4g, or bytes)
    --actor <name>           who the ref writes are recorded as

HOW IT ENDS:
    --json                   the whole report as JSON: objects arrived, objects re-hashed,
                                 refs written and moved, every refusal with its token,
                                 pointers resolved, code, and trust: none

A COPY MOVES BYTES AND NEVER TRUST (ADR-0005 D3). There is no flag here that makes a
mirror's proofs acceptable, because there is no such thing: keys and the policy that names
them do that, in the reader, from the reader's own config. Run `gitiup verify change`
against the copy if you want to know what it proves.

A store never advertises less than it did: a re-run writes nothing new, and a run that was
interrupted leaves bytes nobody advertises rather than an advertisement nobody can satisfy.

Exit codes: 0 ok · 2 usage · 3 I/O or unreachable · 6 refused (read-only destination, a
budget busted, a diverged pointer, or any refusal under --strict) · 8 bytes that are not
the bytes their name promises.

Try:
    gitiup fetch --remote upstream --store ./mirror --proofs-only --json
    gitiup fetch --remote upstream --store ./store --change chg-6a6a8eab778ba4d0
    gitiup push  --remote mirror   --store ./store --dry-run
    gitiup fetch --remote origin   --to s3-bucket --commit $(git rev-parse HEAD)
";

/// Valued flags for both verbs.
const VALUED: &[&str] = &[
    "--remote",
    "--store",
    "--from",
    "--to",
    "--change",
    "--commit",
    "--max-records",
    "--max-bytes",
    "--actor",
];

/// Switches for both verbs. There is no trust flag in this list, and adding one is the
/// refusal ADR-0005 D3 exists to prevent.
const SWITCHES: &[&str] = &[
    "--proofs-only",
    "--strict",
    "--dry-run",
    "--no-records",
    "--json",
];

/// `gitiup fetch …`
pub fn fetch(args: &[String]) -> Result<(), CliError> {
    transport(args, Verb::Fetch)
}

/// `gitiup push …`
pub fn push(args: &[String]) -> Result<(), CliError> {
    transport(args, Verb::Push)
}

/// One endpoint of a copy, opened and described.
pub(crate) struct Side {
    pub(crate) host: Box<dyn Host>,
    pub(crate) what: String,
}

fn transport(args: &[String], verb: Verb) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    // `gitiup fetch help` the way `gitiup change help` works — and a bare word, not any
    // word, so `--actor help` means an actor called help and not the manual.
    if args.help(TRANSPORT_HELP).is_some() || args.positional.iter().any(|word| word == "help") {
        print!("{TRANSPORT_HELP}");
        return Ok(());
    }
    let config =
        HostConfig::load_default().map_err(|e| CliError::io(format!("gitiup.toml: {e}")))?;
    let (source, destination) = match verb {
        Verb::Fetch => (
            far_or_near(&args, "--from", args.get("--remote"), true, &config)?,
            near_or_far(&args, "--to", args.get("--store"), false, &config)?,
        ),
        Verb::Push => (
            near_or_far(&args, "--from", args.get("--store"), true, &config)?,
            far_or_near(&args, "--to", args.get("--remote"), false, &config)?,
        ),
    };
    if source.what == destination.what {
        return Err(CliError::refused(
            format!(
                "the source and the destination are the same store ({})",
                source.what
            ),
            "a copy into itself would only prove that a store can read its own listing",
        ));
    }

    let mut options = Options::new(verb, &source.what, &destination.what);
    options.actor = match args.get("--actor") {
        Some(name) => gitiup_host::Actor::new(name)
            .map_err(|e| CliError::usage(format!("--actor '{name}': {e}")))?,
        None => gitiup_host::Actor::from_env(),
    };
    options.change = match args.get("--change") {
        Some(text) => Some(
            ChangeId::new(text).map_err(|e| CliError::usage(format!("--change '{text}': {e}")))?,
        ),
        None => None,
    };
    options.commit = match args.get("--commit") {
        Some(text) => Some(subject(text)?),
        None => None,
    };
    options.proofs_only = args.on("--proofs-only");
    options.strict = args.on("--strict");
    options.dry_run = args.on("--dry-run");
    options.record_arrivals = !args.on("--no-records");
    if let Some(text) = args.get("--max-records") {
        options.budgets.records = text
            .parse::<usize>()
            .map_err(|_| CliError::usage(format!("--max-records '{text}' is not a count")))?;
    }
    if let Some(text) = args.get("--max-bytes") {
        options.budgets.bytes = human_bytes(text)?;
    }

    let report = match federation::copy(&*source.host, &*destination.host, &options) {
        Ok(report) => report,
        Err(error) => {
            // A command-level refusal: the token is already in the message, and the exit
            // code came with it.
            return Err(CliError::scored(
                error.exit_code(),
                error.message().to_string(),
                error.hint().map(str::to_string),
            ));
        }
    };

    if args.json() {
        let value =
            serde_json::to_value(&report).map_err(|e| CliError::io(format!("report: {e}")))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!(
            "{}  {} → {}{}",
            options.verb.as_str(),
            source.what,
            destination.what,
            if options.dry_run {
                "  (dry run: nothing written)"
            } else {
                ""
            }
        );
        for line in report.summary_lines() {
            println!("{line}");
        }
        for refusal in &report.refused {
            // The summary aggregates; this is the list a human goes down. A store with
            // forty branches is forty lines of `not_portable`, which is why the JSON is
            // the machine-readable form.
            eprintln!(
                "  {} {} {}",
                refusal.token,
                refusal.reference.as_deref().unwrap_or("-"),
                refusal.detail
            );
        }
        if report.any_refused() && !options.strict {
            eprintln!(
                "note: refusals above are scope, not damage — nothing was written that should \
                 not have been. --strict makes any of them fail the command."
            );
        }
    }
    let code = report.exit_code(options.strict);
    if code != 0 {
        return Err(CliError::verdict(code));
    }
    Ok(())
}

/// The endpoint named by an explicit flag, else by the verb's far flag, else refused.
fn far_or_near(
    args: &Args,
    explicit: &str,
    fallback: Option<&str>,
    source: bool,
    config: &Option<(PathBuf, HostConfig)>,
) -> Result<Side, CliError> {
    let named = args.get(explicit).or(fallback);
    let which = if source { "source" } else { "destination" };
    match named {
        Some(value) => open_side(value, config),
        None => Err(CliError::refused(
            format!("no {which} store was named"),
            format!(
                "name one: --remote <name> (a [[remote]] in gitiup.toml), --store <dir>, or \
                 {explicit} <name|dir> — `gitiup doctor --remotes` says what is configured"
            ),
        )),
    }
}

/// The endpoint named by an explicit flag, else by the verb's near flag, else the
/// configured default remote.
fn near_or_far(
    args: &Args,
    explicit: &str,
    fallback: Option<&str>,
    source: bool,
    config: &Option<(PathBuf, HostConfig)>,
) -> Result<Side, CliError> {
    let which = if source { "source" } else { "destination" };
    if let Some(value) = args.get(explicit).or(fallback) {
        return open_side(value, config);
    }
    let Some((_path, config)) = config else {
        return Err(CliError::refused(
            format!("no {which} store was named"),
            "name one with --store <dir> or --remote <name>, or write a gitiup.toml whose \
             default remote is the store you mean (see `gitiup doctor --remotes`)",
        ));
    };
    let remote = config
        .remote_or_default(None)
        .map_err(|e| CliError::refused(format!("gitiup.toml: {e}"), "name a remote explicitly"))?;
    let what = format!("remote '{}' (the configured default)", remote.name);
    open_remote(remote, config).map(|host| Side { host, what })
}

/// `dir` for a directory store, `name` for a remote; a name is a name first, and a path
/// is a path second.
///
/// In that order on purpose: a working directory that happens to contain a directory
/// called `mirror` must not silently stop meaning the remote called `mirror`.
pub(crate) fn open_side(
    value: &str,
    config: &Option<(PathBuf, HostConfig)>,
) -> Result<Side, CliError> {
    if let Some((_, host_config)) = config
        && let Ok(remote) = host_config.remote(value)
    {
        let what = format!("remote '{value}'");
        return open_remote(remote, host_config).map(|host| Side { host, what });
    }
    if looks_like_path(value) {
        let path = Path::new(value);
        if remotes::git_repository(path) {
            return Err(CliError::refused(
                format!("store '{value}' is a git repository, not a gitiup directory store"),
                "a repository is served by the plain-git host: give it a [[remote]] with \
                 url = \"file://…\" and host-type = \"git\", then name that remote — the two \
                 layouts cannot share a path",
            ));
        }
        let host = FsHost::open_or_create(value)
            .map_err(|e| CliError::io(format!("store '{value}': {e}")))?;
        return Ok(Side {
            host: Box::new(host),
            what: format!("fs store {}", path.display()),
        });
    }
    let Some((_path, host_config)) = config else {
        return Err(CliError::refused(
            format!(
                "'{value}' is not a directory and there is no gitiup.toml to say it is a remote"
            ),
            format!(
                "write a gitiup.toml with a [[remote]] of that name, or point at a directory (--store {value})"
            ),
        ));
    };
    let remote = host_config.remote(value).map_err(|e| {
        CliError::refused(
            format!("gitiup.toml: {e}"),
            format!("name a remote that exists, or a directory that does (--store {value})"),
        )
    })?;
    let what = format!("remote '{value}'");
    open_remote(remote, host_config).map(|host| Side { host, what })
}

/// Open a configured remote, refusing a forge this build cannot serve by name.
fn open_remote(remote: &RemoteConfig, config: &HostConfig) -> Result<Box<dyn Host>, CliError> {
    if let Err(why) = remotes::classify(remote) {
        let hint = why
            .hint()
            .unwrap_or("the message above names the feature to build with")
            .to_string();
        return Err(CliError::scored(
            why.exit_code(),
            format!("remote '{}': {why}", remote.name),
            Some(hint),
        ));
    }
    remotes::open(remote, config.credential_profile(remote))
        .map_err(|e| CliError::io(format!("remote '{}': {e}", remote.name)))
}

/// Whether a value should be read as a path rather than as the name of a remote.
fn looks_like_path(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('.')
        || value.starts_with('/')
        || value.starts_with('~')
        || value.starts_with("\\\\")
        || value.contains('/')
        || Path::new(value).is_dir()
}

/// The object an attestation is about, in any of the spellings a shell produces.
fn subject(text: &str) -> Result<Oid, CliError> {
    let text = text.trim();
    let hex = match text.split_once(':') {
        Some((_, hex)) => hex,
        None => text,
    };
    Oid::from_hex(hex).map_err(|e| CliError::usage(format!("--commit '{text}' is not an oid: {e}")))
}

/// Parse a byte size for a budget: `4g`, `500m`, `1k`, or a number of bytes.
pub(crate) fn human_bytes(text: &str) -> Result<u64, CliError> {
    let text = text.trim().to_ascii_lowercase();
    let bad = || CliError::usage(format!("'{text}' is not a size"));
    if text.is_empty() {
        return Err(bad());
    }
    let (digits, multiplier) = match text.as_bytes()[text.len() - 1] {
        b'k' => (&text[..text.len() - 1], 1024u64),
        b'm' => (&text[..text.len() - 1], 1024 * 1024),
        b'g' => (&text[..text.len() - 1], 1024 * 1024 * 1024),
        b'b' => (&text[..text.len() - 1], 1),
        _ => (text.as_str(), 1),
    };
    let digits = digits.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let count: u64 = digits.parse().map_err(|_| bad())?;
    count
        .checked_mul(multiplier)
        .ok_or_else(|| CliError::usage(format!("'{text}' is too large a size")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule this whole surface exists to keep, checked where somebody would add the
    /// flag: not one letter of the flag vocabulary may spell trust.
    #[test]
    fn no_flag_in_either_verb_can_be_read_as_trust() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            let name = flag.to_ascii_lowercase();
            assert!(
                !name.contains("trust") && !name.contains("verify") && !name.contains("accept"),
                "`{flag}` reads like a trust decision, which ADR-0005 D3 forbids this command from having"
            );
        }
        assert!(
            TRANSPORT_HELP.contains("no flag here"),
            "the help has to say out loud what the flag list refuses, because the absence is easy to 'fix'"
        );
    }

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts_and_the_codes_it_exits_with() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                TRANSPORT_HELP.contains(flag),
                "{flag} is accepted by `gitiup fetch`/`push` and undocumented in their help"
            );
        }
        assert!(
            TRANSPORT_HELP.contains("--json"),
            "--json is parsed, so it is documented"
        );
        for code in ["0", "2", "3", "6", "8"] {
            assert!(
                TRANSPORT_HELP.contains(code),
                "exit {code} is missing from the transport help"
            );
        }
        // A fetch re-hashes; it does not verify signatures. That ladder is
        // `gitiup attest import`'s (ADR-0005 D4), and printing a 7 here would promise a
        // check this command does not run.
        assert!(
            !TRANSPORT_HELP.contains("\u{00b7} 7 "),
            "the transport has no seventh code"
        );
        assert!(
            TRANSPORT_HELP.contains("gitiup fetch"),
            "the text is printed by `gitiup fetch help`, and should say so"
        );
    }

    #[test]
    fn a_size_is_a_size() {
        assert_eq!(human_bytes("4096").unwrap(), 4096);
        assert_eq!(human_bytes("1k").unwrap(), 1024);
        assert_eq!(human_bytes(" 500M ").unwrap(), 500 * 1024 * 1024);
        assert_eq!(human_bytes("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        for bad in ["", "abc", "1.5g", "g", "-4", "1e9", "4kb"] {
            assert!(human_bytes(bad).is_err(), "'{bad}' is not a size");
        }
    }

    #[test]
    fn a_commit_is_an_oid_in_any_shape_a_shell_hands_over() {
        let sha1 = "0123456789012345678901234567890123456789";
        assert_eq!(subject(sha1).unwrap().hex(), sha1);
        assert_eq!(subject(&format!("sha1:{sha1}")).unwrap().hex(), sha1);
        let sha256 = "a".repeat(64);
        assert_eq!(subject(&format!("sha256:{sha256}")).unwrap().hex(), sha256);
        for bad in ["", "nope", "sha1:xyz", sha1.repeat(2).as_str()] {
            assert!(subject(bad).is_err(), "'{bad}' is not an oid");
        }
    }

    #[test]
    fn a_path_and_a_remote_name_are_told_apart() {
        assert!(looks_like_path("./store"));
        assert!(looks_like_path("/srv/gitiup/store"));
        assert!(looks_like_path("~/store"));
        assert!(looks_like_path("a/b"));
        assert!(!looks_like_path("origin"));
        assert!(!looks_like_path("mirror"));
    }
}

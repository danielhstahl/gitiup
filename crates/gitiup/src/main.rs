//! `gitiup` — the command line.
//!
//! The binary is deliberately thin: every decision about *what a digest is* lives
//! in [`gitiup_attest`](gitiup_attest), and this crate only reads, calls and
//! prints. That matters because the same computation has to happen in a
//! `pre-receive` hook and in a volunteer's own tool; if the CLI were the only
//! place it existed, "trust me, the digest matches" would be the story.
//!
//! ```text
//! gitiup run [OPTIONS] [JOB]            plan a workflow job (nothing is run)
//! gitiup run --execute --sandbox <name> run it for real, and attest as `local`
//! gitiup env [OPTIONS]                  this machine's environment fingerprint, and
//!                                      whether a policy would accept it
//! gitiup doctor --sandbox               what this machine can confine, and whether it
//!                                      may serve a stranger's job at all
//! gitiup digest [OPTIONS] [REPORT]      RunDigest of a local run
//! gitiup attest push|list|show|gc        file signed attestations in a host, read them
//!                                      back, and retire the ones a retention policy
//!                                      says are old
//! gitiup verify attestation [DOC]       may this attestation be acted on? one exit
//!                                      code (0/6/7/8) and a report of every check
//! gitiup normalise [OPTIONS] [REPORT]   what normalisation rewrote; --compare two runs
//! gitiup key …                          signing keys: gen, import (file, seed, agent, gpg)
//! gitiup identity …                     who this machine signs as: publish, use, whoami
//! gitiup participant …                  volunteering to verify: register, withdraw, list
//! gitiup select …                       who verifies one change, and why: derive or audit
//! gitiup help                           this text
//! gitiup version                        version this build reports
//! ```
//!
//! # Exit codes
//!
//! The digest and verify commands keep [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)'s
//! taxonomy, because a merge gate branches on these numbers and must get the same
//! verdict from the library and from here:
//!
//! | exit | meaning |
//!|------|---------|
//!| 0 | digest computed (and it is the one we were told to expect); attestation accepted |
//!| 2 | usage: unknown flag, missing argument |
//!| 3 | I/O: the report could not be read |
//!| 6 | refused: not a valid run report or attestation, disallowed tier, wrong machine, untrusted signer, too few signatures, stale |
//!| 7 | a signature that does not verify |
//!| 8 | digest mismatch: `--expect` did not match, or an attestation that is not the bytes it claims |

use std::process::ExitCode;

mod attest;
mod digest;
mod doctor;
mod env;
mod keys;
mod normalise;
mod participant;
mod remotes;
mod run;
mod select;
mod verify;

/// The top-level usage text, also printed on `gitiup help`.
pub const USAGE: &str = "\
gitiup — run GitHub Actions locally, and contribute without a forge.

USAGE:
    gitiup <COMMAND> [OPTIONS] [ARGS]

COMMANDS:
    run [OPTIONS] [JOB]            plan a workflow job; --execute to run it
    env [OPTIONS]                  this machine's environment fingerprint, and whether
                                   a policy requirement accepts it
    doctor --sandbox [--json]      report the isolation this machine actually provides
    digest [OPTIONS] [REPORT]      compute the RunDigest of a local run
    attest [COMMAND] [OPTIONS]     attestations in a host: push, list, show, gc
    verify attestation [DOC|-] [OPTIONS]
                                   is this attestation good enough to act on?
                                   (0 accepted · 6 refused · 7 bad signature ·
                                    8 digest mismatch)
    normalise [OPTIONS] [REPORT]   show what normalisation rewrote, or --compare two runs
    key [COMMAND] [OPTIONS]        the signing keys this machine can use (gen, import,
                                   list, show, delete, probe)
    identity [COMMAND] [OPTIONS]   who this machine signs as (publish, list, show,
                                   verify, endorse, use, whoami, import)
    participant [COMMAND] [OPTS]   the quorum roster: register, withdraw, list,
                                   verify-roster, approve, revoke
    select [OPTIONS]               who verifies one change: re-derive a published
                                   selection, or open a new round and exclude the author
    help                        print this text
    version                     print the version of this build

REPORT is a run-report JSON file (see docs/run-report.md), or `-` for stdin.
`env` probes the machine (a handful of `--version` calls) and gates it against
`require_arch` / `require-env-match` in a policy file; see docs/environment.md.

Exit codes for `run`, `digest`, `env` and `normalise`: 0 ok · 2 usage · 3 I/O ·
6 refused (bad run report, disallowed tier, no sandbox, wrong machine class) ·
8 digest mismatch or divergence (ADR-0001 D7: 6 refused/unsupported, 8 digest
mismatch — the codes `gitiup verify attestation` uses too, plus 7 for a signature
that does not verify).

`key` and `identity` keep the same table and add one code: 7, a signature that does
not verify — a claim whose self-signature is broken is a different event from a
claim you merely cannot parse. `gitiup key help` and `gitiup identity help` list
their flags; both are scriptable end to end, with `--passphrase-file -` for a
passphrase and `--json` on anything a script reads.

`participant` is the roster side of the optional quorum network (docs/quorum.md):
`register` publishes what your machine can honestly do, `withdraw` leaves at an epoch you
name, `list` and `verify-roster` read the epoch the owner signed, and `approve` and
`revoke` are the owner's acts. Same exit table, same passphrase rules as `key`.

`select` is the other half: who is asked about one change, and the proof. Run it with apublished round and it re-derives the ordered selection from the round record, the roster
epoch it pinned and the published seed — no key, no secret, no trust root. Run it before
the round exists and it derives the seed from the selector's key, excludes the change
author and every other key of theirs, and writes the round record that makes the choice
auditable. `--explain` prints the audit table; ADR-0002 D3 is what it explains.

`attest` is where a proof lives after it is signed. `push` files the exact canonical
bytes at kv/attestation/<digest> and points refs/attestations/<subject>/<digest> at them,
so on a git-backed host a plain `git fetch` of that namespace carries the attestation in
the same packfile as the ref. `list --commit` and `show` read them back from any host —
fs, a bare repo, a bucket — and refuse anything that does not re-hash to its own name.
`gc` applies a retention policy (`--max-age`, `--max-per-commit`) to the published set and
never touches an attestation another ref still points at, which is what keeps a quorum's
seat submissions and a merge's recorded proof safe. Without --apply it only prints the plan.

`verify attestation` is the question the whole format exists to answer: may this proof be
acted on? It checks the canonical bytes re-hash to the digest they claim, that every
signature verifies and belongs to a key the policy trusts, that enough of them did, that
the provenance tier and sandbox are allowed, that the run happened on a machine the change
accepts, and that the claim is fresh — in the fixed order ADR-0001 D7 sets, so the first
thing wrong is what the exit code says (0 accepted · 6 refused · 7 bad signature · 8 digest
mismatch). Every failure found is reported, not just the first, and `--json` prints the
verdict, each check's outcome and the reasons as data, which is what makes it the line a
merge gate or a `pre-receive` hook runs: `gitiup verify attestation proof.json --policy
gitiup-policy.json --json`. A verdict is not an error: it is printed on stdout and carried
in the exit code, so a hook reads one thing. `gitiup verify attestation help` lists the
flags for tiers, trust, freshness, the environment requirement and the clock.

`run` never runs anything unless you say `--execute`, and what it plans attests as
`simulated` — a plan, not evidence. Policies say which tiers they accept; the
default accepts `local` only. There is no way to ask for `quorum`: a single run
cannot earn it.

Try:
    gitiup doctor --sandbox                  # what confines a job here, if anything
    gitiup env                                 # what a run here would attest as
    gitiup env --require arch=amd64            # …and whether that satisfies the change
    gitiup run                                 # plan the only job in the workflow
    gitiup run --execute --sandbox unshare     # run it for real: tier `local`
    gitiup digest run.json
    gitiup digest --json run.json
    gitiup digest --expect sha256:… run.json   # exit 8 if the rerun disagrees
    gitiup attest push attestation.json --store ./store --json
    gitiup attest list --commit $(git rev-parse HEAD) --store ./store
    gitiup attest show --digest <hex> --store ./store --json
    gitiup attest gc --store ./store --max-age 90d --max-per-commit 5   # the plan
    gitiup verify attestation proof.json --policy gitiup-policy.json     # the verdict
    gitiup verify attestation --store ./store --commit $(git rev-parse HEAD) --json
    gitiup normalise run.json                  # what was rewritten, and why
    gitiup normalise --compare run-a.json run-b.json   # exit 8 if they diverge
    gitiup participant list --store ./store --json
    gitiup select --change chg-1 --store ./store --explain
    gitiup select --change chg-1 --job build/matrix/linux-x86_64 --head sha1:… \
        --proposer ada --require-arch x86_64 --store ./store --publish
    gitiup key gen --comment ada@laptop         # a new key, in the age-encrypted keystore
    gitiup identity publish ada --email ada@example.com
    gitiup identity whoami --check              # proves this machine can still sign
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !error.quiet {
                eprintln!("gitiup: {}", error.message);
                if let Some(hint) = error.hint {
                    eprintln!("hint: {hint}");
                }
            }
            ExitCode::from(error.code)
        }
    }
}

/// An error with the exit code already decided, so `main` cannot contradict the
/// taxonomy above.
#[derive(Debug)]
pub(crate) struct CliError {
    code: u8,
    message: String,
    hint: Option<String>,
    /// True when the command already said everything it has to say on stdout — a
    /// *verdict*, which is a result and not a fault. `main` still exits with the
    /// code and stays off stderr.
    quiet: bool,
}

impl CliError {
    fn usage(message: impl Into<String>) -> CliError {
        CliError {
            code: 2,
            message: message.into(),
            hint: Some("run `gitiup help` for the whole surface".into()),
            quiet: false,
        }
    }

    fn io(message: impl Into<String>) -> CliError {
        CliError {
            code: 3,
            message: message.into(),
            hint: None,
            quiet: false,
        }
    }

    /// 6 — refused: a policy, a tier, a sandbox, or a selection this command will
    /// not guess on the user's behalf. The same code the library uses for the same
    /// kind of "we will not accept this", so a merge gate cannot tell them apart.
    fn refused(message: impl Into<String>, hint: impl Into<String>) -> CliError {
        CliError {
            code: 6,
            message: message.into(),
            hint: Some(hint.into()),
            quiet: false,
        }
    }

    /// An error whose exit code is already decided by the library's taxonomy.
    fn new(
        kind: gitiup_attest::ErrorKind,
        message: impl Into<String>,
        hint: Option<&str>,
    ) -> CliError {
        CliError {
            code: kind.exit_code(),
            message: message.into(),
            hint: hint.map(str::to_string),
            quiet: false,
        }
    }

    /// An error that arrived already carrying its own exit code, from a library
    /// whose taxonomy is this same table (`gitiup-keys`, `gitiup-quorum`).
    pub(crate) fn scored(code: u8, message: impl Into<String>, hint: Option<String>) -> CliError {
        CliError {
            code,
            message: message.into(),
            hint,
            quiet: false,
        }
    }

    /// A verdict that has already been printed as a report: the exit code *is* the
    /// verdict (0 accepted · 6 refused · 7 bad signature · 8 digest mismatch), and
    /// repeating it on stderr would only give a hook two places to read the same
    /// decision — and one of them is a log line nobody parses.
    fn verdict(code: u8) -> CliError {
        CliError {
            code,
            message: String::new(),
            hint: None,
            quiet: true,
        }
    }
}

/// Library errors keep their own exit code: `gitiup digest` and a merge gate
/// calling the same check must disagree about nothing.
impl From<gitiup_attest::Error> for CliError {
    fn from(error: gitiup_attest::Error) -> CliError {
        // `Display` for the library's error already appends the hint; the message
        // and the hint are printed on separate lines here, so take the two parts
        // rather than the rendered string.
        CliError {
            code: error.exit_code(),
            message: format!("{}: {}", error.context(), error.detail()),
            hint: error.hint().map(str::to_string),
            quiet: false,
        }
    }
}

/// The same rule for the quorum: a roster refused by the library is refused with the
/// library's code (6 refused, 7 bad signature, 8 bytes that are not their canonical
/// form, 3 an unreachable store), so `gitiup participant verify-roster` and a merge gate
/// calling `Roster::verify` cannot disagree about the same document.
impl From<gitiup_quorum::Error> for CliError {
    fn from(error: gitiup_quorum::Error) -> CliError {
        CliError {
            code: error.exit_code(),
            message: error.message(),
            hint: error.hint().map(str::to_string),
            quiet: false,
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), CliError> {
    let Some(command) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(());
    };
    match command {
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("gitiup {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "run" => run::run(&args[1..]),
        "doctor" => doctor::run(&args[1..]),
        "digest" => digest::run(&args[1..]),
        "attest" => attest::attest(&args[1..]),
        "verify" => verify::verify(&args[1..]),
        "env" => env::run(&args[1..]),
        "normalise" => normalise::run(&args[1..]),
        "key" => keys::key(&args[1..]),
        "identity" => keys::identity(&args[1..]),
        "participant" => participant::participant(&args[1..]),
        "select" => select::select(&args[1..]),
        other => Err(CliError::usage(format!("unknown command '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usage_text_documents_the_exit_codes_it_uses() {
        // The table in this module's docs and the text users see must not drift.
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(
                USAGE.contains(code),
                "exit code {code} is missing from the usage text"
            );
        }
        assert!(USAGE.contains("digest"));
        assert!(
            USAGE.contains("run [OPTIONS] [JOB]"),
            "the ticket's own command must be in the usage text"
        );
        assert!(
            USAGE.contains("verify attestation"),
            "the verdict command must be in the usage text"
        );
    }

    #[test]
    fn an_unknown_command_is_a_usage_error() {
        let err = dispatch(&["nonsense".into()]).unwrap_err();
        assert_eq!(err.code, 2);
    }
}

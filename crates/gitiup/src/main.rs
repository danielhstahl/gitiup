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
//! gitiup digest [OPTIONS] [REPORT]      RunDigest of a local run
//! gitiup normalise [OPTIONS] [REPORT]   what normalisation rewrote; --compare two runs
//! gitiup help                           this text
//! gitiup version                        version this build reports
//! ```
//!
//! # Exit codes
//!
//! The digest command keeps [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)'s
//! taxonomy, because a merge gate branches on these numbers and must get the same
//! verdict from the library and from here:
//!
//! | exit | meaning |
//!|------|---------|
//!| 0 | digest computed (and it is the one we were told to expect) |
//!| 2 | usage: unknown flag, missing argument |
//!| 3 | I/O: the report could not be read |
//!| 6 | the report is not a valid run report, or this build cannot read it |
//!| 8 | digest mismatch: `--expect` did not match, i.e. a rerun disagreed |

use std::process::ExitCode;

mod digest;
mod normalise;
mod run;

/// The top-level usage text, also printed on `gitiup help`.
pub const USAGE: &str = "\
gitiup — run GitHub Actions locally, and contribute without a forge.

USAGE:
    gitiup <COMMAND> [OPTIONS] [ARGS]

COMMANDS:
    run [OPTIONS] [JOB]            plan a workflow job; --execute to run it
    digest [OPTIONS] [REPORT]      compute the RunDigest of a local run
    normalise [OPTIONS] [REPORT]   show what normalisation rewrote, or --compare two runs
    help                        print this text
    version                     print the version of this build

REPORT is a run-report JSON file (see docs/run-report.md), or `-` for stdin.

Exit codes for `run`, `digest` and `normalise`: 0 ok · 2 usage · 3 I/O · 6 refused
(bad run report, disallowed tier, no sandbox) · 8 digest mismatch or divergence
(ADR-0001 D7: 6 refused/unsupported, 8 digest mismatch — the same codes
`gitiup verify attestation` will use).

`run` never runs anything unless you say `--execute`, and what it plans attests as
`simulated` — a plan, not evidence. Policies say which tiers they accept; the
default accepts `local` only. There is no way to ask for `quorum`: a single run
cannot earn it.

Try:
    gitiup run                                 # plan the only job in the workflow
    gitiup run --execute --sandbox unshare     # run it for real: tier `local`
    gitiup digest run.json
    gitiup digest --json run.json
    gitiup digest --expect sha256:… run.json   # exit 8 if the rerun disagrees
    gitiup normalise run.json                  # what was rewritten, and why
    gitiup normalise --compare run-a.json run-b.json   # exit 8 if they diverge
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gitiup: {}", error.message);
            if let Some(hint) = error.hint {
                eprintln!("hint: {hint}");
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
}

impl CliError {
    fn usage(message: impl Into<String>) -> CliError {
        CliError {
            code: 2,
            message: message.into(),
            hint: Some("run `gitiup help` for the whole surface".into()),
        }
    }

    fn io(message: impl Into<String>) -> CliError {
        CliError {
            code: 3,
            message: message.into(),
            hint: None,
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
        "digest" => digest::run(&args[1..]),
        "normalise" => normalise::run(&args[1..]),
        other => Err(CliError::usage(format!("unknown command '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usage_text_documents_the_exit_codes_it_uses() {
        // The table in this module's docs and the text users see must not drift.
        for code in ["0", "2", "3", "6", "8"] {
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
    }

    #[test]
    fn an_unknown_command_is_a_usage_error() {
        let err = dispatch(&["nonsense".into()]).unwrap_err();
        assert_eq!(err.code, 2);
    }
}

//! `gitiup digest` — a run report in, the digests out.
//!
//! This is the acceptance surface of giti-1rs.2: the command that proves the
//! digest computation is not a library curiosity. It reads a run report (the
//! runner's record of a finished run, `docs/run-report.md`), hands it to
//! [`RunManifest::from_run`], and prints what came out — no signing, no storage,
//! no network. Those are later tickets; what is decisive here is that the number
//! printed on a terminal is the same number a verifier will recompute, because
//! both come from the same function in `gitiup-attest`.
//!
//! ```text
//! gitiup digest [OPTIONS] [REPORT]
//!
//!     REPORT                 run-report JSON, or - for stdin (the default)
//!     --json                 one machine-readable line, keys sorted
//!     --quiet, -q            the RunDigest and nothing else
//!     --expect <digest>      exit 8 unless the RunDigest is exactly this
//!     --expect-result <d>    exit 8 unless the ResultDigest is exactly this
//!     --help, -h             this text
//! ```
//!
//! `--expect` is the reproducibility check in one flag: run a job twice, or on
//! two machines, and compare digests without eyeballing hex. A refusal with exit
//! 8 is the same verdict `gitiup verify attestation` will give later
//! ([ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;

use gitiup_attest::run::RunReport;
use gitiup_attest::{Digest, Error as AttestError, ErrorKind, RunManifest, StepOutcome};
use serde_json::Value;

use crate::CliError;

/// The `digest`-specific help, kept next to the flags it documents.
pub const HELP: &str = "\
gitiup digest — compute the RunDigest of a local run

USAGE:
    gitiup digest [OPTIONS] [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)

OPTIONS:
    --json                 machine-readable output (keys sorted, one line)
    -q, --quiet            print the RunDigest and nothing else
    --expect <digest>      exit 8 unless the RunDigest equals this
    --expect-result <d>    exit 8 unless the ResultDigest equals this
    -h, --help             print this text

The report is ordinary JSON (see docs/run-report.md): field order and whitespace
do not change the digest, which is the point of a canonical manifest.

Exit codes: 0 ok · 2 usage · 3 I/O · 6 invalid run report · 8 digest mismatch
";

/// What to print. Three shapes because three readers exist: a human, a script,
/// and a shell substitution.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Format {
    #[default]
    Text,
    Json,
    Quiet,
}

#[derive(Debug, Default)]
struct Options {
    source: Option<String>,
    format: Format,
    expect_run: Option<Digest>,
    expect_result: Option<Digest>,
    help: bool,
}

/// The value of a flag, from `--flag=value`, `--flag value`, or nothing.
fn flag_value(
    name: &str,
    args: &[String],
    index: &mut usize,
    inline: Option<String>,
) -> Result<String, CliError> {
    if let Some(value) = inline {
        return Ok(value);
    }
    if *index < args.len() {
        let value = args[*index].clone();
        *index += 1;
        return Ok(value);
    }
    Err(CliError::usage(format!("{name} needs a value")))
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, CliError> {
        let mut options = Options::default();
        let mut index = 0usize;
        while index < args.len() {
            let arg = args[index].clone();
            index += 1;
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) => (name.to_string(), Some(value.to_string())),
                None => (arg.clone(), None),
            };
            match name.as_str() {
                "-h" | "--help" | "help" => options.help = true,
                "--json" => options.format = Format::Json,
                "-q" | "--quiet" => options.format = Format::Quiet,
                "--expect" => {
                    let value = flag_value("--expect", args, &mut index, inline)?;
                    options.expect_run = Some(value.parse()?);
                }
                "--expect-result" => {
                    let value = flag_value("--expect-result", args, &mut index, inline)?;
                    options.expect_result = Some(value.parse()?);
                }
                // A lone `-` is "stdin", the usual convention; anything else that
                // starts with a dash is a flag we do not have.
                _ if name.starts_with('-') && name != "-" => {
                    return Err(CliError::usage(format!("unknown option '{name}'")));
                }
                _ => {
                    if let Some(previous) = &options.source {
                        return Err(CliError::usage(format!(
                            "two reports given ('{previous}' and '{name}')"
                        )));
                    }
                    options.source = Some(name.clone());
                }
            }
        }
        Ok(options)
    }
}

/// What the digest computation produced, in the shape the CLI prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    run_digest: Digest,
    result_digest: Digest,
    tier: String,
    runner: String,
    normalisation_version: u32,
    commit: String,
    workflow: String,
    workflow_oid: String,
    event: String,
    job: Option<String>,
    arch: String,
    fingerprint: Digest,
    steps: usize,
    succeeded: usize,
    failed: usize,
    skipped: usize,
}

impl Summary {
    /// The whole point: a report's bytes in, the two digests (plus enough context
    /// to recognise which run they describe) out.
    pub(crate) fn compute(report_bytes: &[u8]) -> Result<Summary, AttestError> {
        // Lenient by design: a run report is a transport, not a signed document.
        // Only the manifest it computes to has one legal encoding.
        let report: RunReport = serde_json::from_slice(report_bytes)
            .map_err(|e| AttestError::invalid("run report", e.to_string()))?;
        let manifest = RunManifest::from_run(&report)?;
        Ok(Summary::from(&manifest))
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "run            {}", self.run_digest);
        let _ = writeln!(out, "result         {}", self.result_digest);
        let _ = writeln!(out, "tier           {}", self.tier);
        let _ = writeln!(out, "runner         {}", self.runner);
        let _ = writeln!(out, "commit         {}", self.commit);
        let _ = writeln!(
            out,
            "workflow       {} {}",
            self.workflow, self.workflow_oid
        );
        let _ = writeln!(out, "event          {}", self.event);
        if let Some(job) = &self.job {
            let _ = writeln!(out, "job            {job}");
        }
        let _ = writeln!(
            out,
            "environment    {} · fingerprint {}",
            self.arch, self.fingerprint
        );
        let _ = writeln!(
            out,
            "steps          {} ({} succeeded, {} failed, {} skipped)",
            self.steps, self.succeeded, self.failed, self.skipped
        );
        let _ = writeln!(out, "normalisation  v{}", self.normalisation_version);
        out
    }

    fn to_json(&self) -> String {
        // Sorted keys, because `gitiup digest --json | jq` is part of the
        // interface and diffing unsorted output is miserable.
        let mut map: BTreeMap<&str, Value> = BTreeMap::new();
        map.insert("run_digest", Value::String(self.run_digest.to_string()));
        map.insert(
            "result_digest",
            Value::String(self.result_digest.to_string()),
        );
        map.insert("tier", Value::String(self.tier.clone()));
        map.insert("runner", Value::String(self.runner.clone()));
        map.insert(
            "normalisation_version",
            Value::from(u64::from(self.normalisation_version)),
        );
        map.insert("commit", Value::String(self.commit.clone()));
        map.insert("workflow", Value::String(self.workflow.clone()));
        map.insert("workflow_oid", Value::String(self.workflow_oid.clone()));
        map.insert("event", Value::String(self.event.clone()));
        if let Some(job) = &self.job {
            map.insert("job", Value::String(job.clone()));
        }
        map.insert("arch", Value::String(self.arch.clone()));
        map.insert(
            "environment_fingerprint",
            Value::String(self.fingerprint.to_string()),
        );
        map.insert("steps", Value::from(self.steps as u64));
        map.insert("succeeded", Value::from(self.succeeded as u64));
        map.insert("failed", Value::from(self.failed as u64));
        map.insert("skipped", Value::from(self.skipped as u64));
        serde_json::to_string(&map).unwrap_or_else(|_| "{}".into())
    }

    /// The reproducibility check. A mismatch is exit 8 — the same class as "these
    /// are not the bytes that were signed", because operationally it is the same
    /// disappointment: a digest was expected and another one arrived.
    fn check_against(&self, options: &Options) -> Result<(), AttestError> {
        if let Some(expected) = &options.expect_run
            && *expected != self.run_digest
        {
            return Err(AttestError::new(
                ErrorKind::DigestMismatch,
                "digest",
                format!(
                    "expected RunDigest {expected}, computed {}",
                    self.run_digest
                ),
            )
            .with_hint(
                "a rerun that disagrees is a normalisation problem (giti-1rs.3), not a typo",
            ));
        }
        if let Some(expected) = &options.expect_result
            && *expected != self.result_digest
        {
            return Err(AttestError::new(
                ErrorKind::DigestMismatch,
                "digest",
                format!(
                    "expected ResultDigest {expected}, computed {}",
                    self.result_digest
                ),
            )
            .with_hint(
                "the run's outcome differs from the one expected; compare the two manifests",
            ));
        }
        Ok(())
    }
}

impl From<&RunManifest> for Summary {
    fn from(manifest: &RunManifest) -> Summary {
        let count = |outcome: StepOutcome| {
            manifest
                .result
                .steps
                .iter()
                .filter(|step| step.outcome == outcome)
                .count()
        };
        Summary {
            run_digest: manifest
                .digest()
                .expect("a manifest that just computed is hashable"),
            result_digest: manifest
                .result_digest()
                .map(|digest| digest.0.clone())
                .expect("a manifest that just computed is hashable"),
            tier: manifest.result.provenance.tier.as_str().to_string(),
            runner: manifest.result.provenance.runner.clone(),
            normalisation_version: manifest.result.provenance.normalisation_version,
            commit: manifest.result.source.commit.to_string(),
            workflow: manifest.result.source.workflow.path.clone(),
            workflow_oid: manifest.result.source.workflow.oid.to_string(),
            event: match &manifest.result.source.event.action {
                Some(action) => format!("{} ({action})", manifest.result.source.event.name),
                None => manifest.result.source.event.name.clone(),
            },
            job: manifest.result.source.job.clone(),
            arch: manifest.result.environment.arch.clone(),
            fingerprint: manifest.result.environment.fingerprint.clone(),
            steps: manifest.result.steps.len(),
            succeeded: count(StepOutcome::Success),
            failed: count(StepOutcome::Failure),
            skipped: count(StepOutcome::Skipped),
        }
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), CliError> {
    let options = Options::parse(args)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let report = read_report(options.source.as_deref())?;
    let summary = Summary::compute(&report)?;
    summary.check_against(&options)?;
    match options.format {
        Format::Text => print!("{}", summary.to_text()),
        Format::Json => println!("{}", summary.to_json()),
        Format::Quiet => println!("{}", summary.run_digest),
    }
    Ok(())
}

pub(crate) fn read_report(source: Option<&str>) -> Result<Vec<u8>, CliError> {
    match source.unwrap_or("-") {
        "-" => {
            let mut buffer = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buffer)
                .map_err(|e| CliError::io(format!("read stdin: {e}")))?;
            if buffer.iter().all(u8::is_ascii_whitespace) {
                return Err(CliError::usage(
                    "no run report on stdin (give a path, or pipe one in)",
                ));
            }
            Ok(buffer)
        }
        path => std::fs::read(path).map_err(|e| CliError::io(format!("read {path}: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn report_json() -> String {
        r#"{
            "repo": "gitiup/gitiup",
            "commit": "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "workflow": {"path": ".github/workflows/ci.yml", "text": "name: CI\n"},
            "event": {"name": "push", "payload": {"text": "{}"}},
            "job": "build",
            "environment": {"arch": "x86_64", "provider": "shell"},
            "steps": [
                {"id": "one", "name": "Build", "exit_code": 0, "stdout": {"text": "ok\n"}},
                {"id": "two", "name": "Test", "exit_code": 3, "stderr": {"text": "boom\n"}},
                {"id": "three", "name": "Deploy", "exit_code": 0, "outcome": "skipped"}
            ],
            "provenance": {"tier": "local", "runner": "gitiup 0.1.0",
                           "normalisation_version": 0, "sandbox": "shell"},
            "claims": {"run_id": "0123456789abcdef", "claimed_at_us": 1793092502500000}
        }"#
        .to_string()
    }

    fn zero() -> Digest {
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap()
    }

    fn arg(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn a_report_computes_both_digests() {
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        assert_eq!(summary.steps, 3);
        assert_eq!(
            (summary.succeeded, summary.failed, summary.skipped),
            (1, 1, 1)
        );
        assert_eq!(summary.tier, "local");
        assert_eq!(summary.arch, "x86_64");
        assert_eq!(summary.job.as_deref(), Some("build"));
        assert_eq!(
            summary.run_digest.algorithm(),
            summary.result_digest.algorithm()
        );
        assert_ne!(
            summary.run_digest, summary.result_digest,
            "the two digests must not be the same value"
        );
    }

    #[test]
    fn text_output_names_both_digests_and_the_run() {
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        let text = summary.to_text();
        assert!(text.contains(&format!("run            {}", summary.run_digest)));
        assert!(text.contains(&format!("result         {}", summary.result_digest)));
        assert!(text.contains("job            build"));
        assert!(text.contains("1 failed, 1 skipped"));
    }

    #[test]
    fn json_output_is_sorted_and_complete() {
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        let json = summary.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["steps"], 3);
        assert_eq!(parsed["run_digest"], summary.run_digest.to_string());
        assert_eq!(parsed["result_digest"], summary.result_digest.to_string());
        let keys: Vec<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "--json keys must be sorted for diffable output"
        );
    }

    #[test]
    fn the_digest_is_a_known_answer() {
        // Not merely stable: this is the RunDigest of the report above, and a
        // third party rebuilding the canonical manifest must print the same thing.
        // (Re-pinned when the fixture grew `provenance.sandbox`: a `local` run that
        // does not name where it ran is no longer a well-formed manifest, so the
        // bytes — and therefore the digest — of a fixture that omitted it moved.)
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        assert_eq!(
            summary.run_digest.to_string(),
            "sha256:9461381cbf27127102a64b69090ff7c18ea186f82dade68b4d1c283c7c91ff5e"
        );
    }

    #[test]
    fn an_expected_digest_mismatch_is_exit_8() {
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        let options = Options {
            expect_run: Some(zero()),
            ..Default::default()
        };
        let err = summary.check_against(&options).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DigestMismatch);
        assert_eq!(err.exit_code(), 8);

        let options = Options {
            expect_result: Some(zero()),
            ..Default::default()
        };
        assert_eq!(summary.check_against(&options).unwrap_err().exit_code(), 8);
    }

    #[test]
    fn matching_expectations_pass() {
        let summary = Summary::compute(report_json().as_bytes()).unwrap();
        let options = Options {
            expect_run: Some(summary.run_digest.clone()),
            expect_result: Some(summary.result_digest.clone()),
            ..Default::default()
        };
        summary.check_against(&options).unwrap();
    }

    #[test]
    fn flags_are_parsed_in_either_spelling() {
        let one = Options::parse(&arg(&[
            "--json",
            "--expect",
            &zero().to_string(),
            "run.json",
        ]))
        .unwrap();
        assert_eq!(one.format, Format::Json);
        assert_eq!(one.expect_run, Some(zero()));
        assert_eq!(one.source.as_deref(), Some("run.json"));

        let two = Options::parse(&arg(&["--expect", &zero().to_string(), "-q", "-"])).unwrap();
        assert_eq!(two.format, Format::Quiet);
        assert_eq!(two.source.as_deref(), Some("-"));

        let three = Options::parse(&arg(&["--expect", &zero().to_string(), "--quiet"]))
            .or_else(|_| Options::parse(&arg(&["--quiet", "--expect", &zero().to_string()])))
            .unwrap();
        assert_eq!(three.format, Format::Quiet);
    }

    #[test]
    fn bad_flags_are_usage_errors() {
        for args in [
            vec!["--nonsense"],
            vec!["--expect"],
            vec!["--expect-result"],
            vec!["a.json", "b.json"],
            vec!["-", "-"],
        ] {
            let err = Options::parse(&arg(&args)).unwrap_err();
            assert_eq!(err.code, 2, "{args:?} should be a usage error");
        }
    }

    #[test]
    fn an_unparsable_digest_is_the_librarys_complaint() {
        // Digests are the library's type: a bad one is its error, exit 6, so the
        // CLI cannot be more lenient than a verifier.
        let err = Options::parse(&arg(&["--expect", "not-a-digest"])).unwrap_err();
        assert_eq!(err.code, 6);
    }

    #[test]
    fn a_broken_report_says_what_is_wrong() {
        let missing = Summary::compute(br#"{"commit":"sha1:00"}"#).unwrap_err();
        assert_eq!(missing.kind(), ErrorKind::Invalid);
        let typo = report_json().replace("\"run_id\"", "\"runid\"");
        let err = Summary::compute(typo.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("runid"),
            "the error should name the unknown field, got {err}"
        );
    }
}

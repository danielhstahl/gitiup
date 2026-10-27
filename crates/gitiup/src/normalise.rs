//! `gitiup normalise` — what a normaliser did, and what still differs.
//!
//! This is the acceptance surface of giti-1rs.3. The library decides everything
//! (the rules, the record, the digests); this command exists because the two
//! questions a reproducibility failure actually poses are asked by a person at a
//! terminal:
//!
//! * *“what did you change about my log?”* — one run in, the per-line record out,
//!   which is also the answer to a later `--expect` mismatch; and
//! * *“did these two runs agree?”* — two runs in, a verdict, and if not, which
//!   step, which field and both sides ([`docs/reproducibility.md`](../../../docs/reproducibility.md)).
//!
//! ```text
//! gitiup normalise [OPTIONS] [REPORT]
//!
//!     REPORT                 run-report JSON, or - for stdin (the default)
//!     --compare <REPORT>     compare a second run instead of describing one
//!     --rules <LIST>         restrict the rewrite rules (diagnosis, not policy)
//!     --text                 print the normalised log text as well
//!     --json                 machine-readable output, keys sorted
//!     --expect-result <d>    exit 8 unless the ResultDigest is exactly this
//!     --help, -h             this text
//! ```
//!
//! Exit codes are the same table as `gitiup digest`
//! ([ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)):
//! divergence is the same class of verdict as a digest mismatch, so a merge gate
//! branches on one number rather than two.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use gitiup_attest::run::{Material, RunReport};
use gitiup_attest::{Digest, Error as AttestError, ErrorKind};
use gitiup_normalise::{NormalisedRun, Profile, Rewrite, Rules, Stream, compare_runs_with};
use serde_json::Value;

use crate::CliError;
use crate::digest::read_report;

/// The `normalise`-specific help, kept next to the flags it documents.
pub const HELP: &str = "\
gitiup normalise — show what normalisation changed, and whether two runs agree

USAGE:
    gitiup normalise [OPTIONS] [REPORT]
    gitiup normalise [OPTIONS] --compare <OTHER> [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)

OPTIONS:
    --compare <REPORT>     compare two runs instead of describing one
    --rules <LIST>         comma-separated rule names to apply (see below)
    --text                 print the normalised log text too
    --json                 machine-readable output (keys sorted, one line)
    --expect-result <d>    exit 8 unless the ResultDigest equals this
    -h, --help             print this text

RULES:
    line-ending, ansi, progress, path, identity, timestamp, duration, percent,
    number, size, spacing, listing
    (the full list and what each rule does is docs/reproducibility.md)

Exit codes: 0 ok / converged · 2 usage · 3 I/O · 6 invalid run report · 8 divergence
";

/// Why a rule list was refused: a typo must not silently mean "rewrite nothing".
fn parse_rules(value: &str) -> Result<Rules, CliError> {
    Rules::parse_list(value).map_err(|error| {
        CliError::usage(format!(
            "{error} (known rules: {})",
            gitiup_normalise::RULE_ORDER
                .iter()
                .map(|rule| rule.name())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

#[derive(Debug, Default)]
struct Options {
    source: Option<String>,
    compare: Option<String>,
    rules: Option<Rules>,
    text: bool,
    json: bool,
    expect_result: Option<Digest>,
    help: bool,
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
            let mut value = |flag: &str| -> Result<String, CliError> {
                if let Some(inline) = inline.clone() {
                    return Ok(inline);
                }
                if index < args.len() {
                    let value = args[index].clone();
                    index += 1;
                    return Ok(value);
                }
                Err(CliError::usage(format!("{flag} needs a value")))
            };
            match name.as_str() {
                "-h" | "--help" | "help" => options.help = true,
                "--json" => options.json = true,
                "--text" => options.text = true,
                "--compare" => options.compare = Some(value("--compare")?),
                "--rules" => options.rules = Some(parse_rules(&value("--rules")?)?),
                "--expect-result" => {
                    options.expect_result = Some(value("--expect-result")?.parse()?);
                }
                _ if name.starts_with('-') && name != "-" => {
                    return Err(CliError::usage(format!("unknown option '{name}'")));
                }
                _ => {
                    if let Some(previous) = &options.source {
                        return Err(CliError::usage(format!(
                            "two reports given ('{previous}' and '{name}'); a second \
                             run goes after --compare"
                        )));
                    }
                    options.source = Some(name.clone());
                }
            }
        }
        Ok(options)
    }

    /// The profile the whole run will use, named the way a manifest names it.
    fn profile(&self) -> Profile {
        match self.rules {
            Some(rules) => Profile::with_rules(rules),
            None => Profile::standard(),
        }
    }
}

/// One run, described: the manifest that will be signed, and the normalised text.
struct Described {
    run: NormalisedRun,
    normalised: Vec<(String, Stream, String)>,
}

fn describe(report: &RunReport, profile: &Profile) -> Result<Described, AttestError> {
    // The text is normalised separately from the manifest because the manifest keeps
    // only the digest: `--text` is the one place a human still wants the words.
    let mut normalised: Vec<(String, Stream, String)> = Vec::new();
    for step in &report.steps {
        for (stream, material) in [
            (Stream::Stdout, &step.stdout),
            (Stream::Stderr, &step.stderr),
        ] {
            let text = match material {
                Material::Text(text) => profile.normalise_stream(text, stream),
                Material::Parts(parts) => parts
                    .iter()
                    .map(|part| profile.normalise_stream(part, stream))
                    .collect::<Vec<_>>()
                    .join(""),
                _ => continue,
            };
            normalised.push((step.key(), stream, text));
        }
    }
    Ok(Described {
        run: gitiup_normalise::manifest_for_with(report, profile)?,
        normalised,
    })
}

/// The one-run text report: header, then every rewrite under the step it happened in.
fn describe_text(described: &Described, options: &Options, profile: &Profile) -> String {
    let mut out = String::new();
    let rewrites: usize = described
        .run
        .records
        .iter()
        .map(|(_, _, record)| record.items().len())
        .sum();
    let dropped: usize = described
        .run
        .records
        .iter()
        .map(|(_, _, record)| record.dropped_lines())
        .sum();
    let _ = writeln!(
        out,
        "profile        {} v{}{}",
        profile.name(),
        profile.version(),
        if options.rules.is_some() {
            " (restricted rule set: not a standard normalisation)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "result         {}",
        described
            .run
            .manifest
            .result_digest()
            .expect("a manifest that just computed is hashable")
    );
    let _ = writeln!(
        out,
        "rewritten      {rewrites} rewrites · {} · {} streams",
        if dropped == 0 {
            "no progress lines dropped".to_string()
        } else {
            format!(
                "{dropped} progress {}",
                if dropped == 1 { "line" } else { "lines" }
            )
        },
        described.run.records.len()
    );
    for (step, stream, record) in &described.run.records {
        let _ = writeln!(
            out,
            "\n{step} {}: {} rewrites",
            stream.name(),
            record.items().len()
        );
        for rewrite in record.items() {
            out.push_str(&rewrite_text(rewrite));
        }
    }
    if options.text {
        for (step, stream, text) in &described.normalised {
            let _ = write!(
                out,
                "\n--- {step} {} (normalised) ---\n{text}",
                stream.name()
            );
        }
    }
    out
}

/// One recorded rewrite: the kind and line, then both sides.
fn rewrite_text(rewrite: &Rewrite) -> String {
    let mut out = String::new();
    if rewrite.line == 0 {
        let _ = writeln!(out, "  {:<12} (stream)", rewrite.rule.name());
    } else {
        let _ = writeln!(out, "  {:<12} line {}", rewrite.rule.name(), rewrite.line);
    }
    for (marker, text) in [("-", &rewrite.before), ("+", &rewrite.after)] {
        for line in text.split("\\n") {
            let _ = writeln!(out, "    {marker} {line}");
        }
    }
    out
}

fn described_json(described: &Described, profile: &Profile) -> String {
    let mut rewrites: Vec<Value> = Vec::new();
    for (step, stream, record) in &described.run.records {
        for rewrite in record.items() {
            let mut entry = BTreeMap::new();
            entry.insert("step".into(), Value::String(step.clone()));
            entry.insert("stream".into(), Value::String(stream.name().to_string()));
            entry.insert(
                "kind".into(),
                Value::String(rewrite.rule.name().to_string()),
            );
            entry.insert("line".into(), Value::from(rewrite.line as u64));
            entry.insert("before".into(), Value::String(rewrite.before.clone()));
            entry.insert("after".into(), Value::String(rewrite.after.clone()));
            rewrites.push(Value::Object(entry.into_iter().collect()));
        }
    }
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("profile".into(), Value::String(profile.name().to_string()));
    map.insert(
        "normalisation_version".into(),
        Value::from(u64::from(profile.version())),
    );
    map.insert(
        "result_digest".into(),
        Value::String(
            described
                .run
                .manifest
                .result_digest()
                .expect("a manifest that just computed is hashable")
                .to_string(),
        ),
    );
    map.insert("rewrites".into(), Value::Array(rewrites));
    map.insert(
        "diffs".into(),
        Value::Array(
            described
                .run
                .diffs
                .iter()
                .map(diff_value)
                .collect::<Vec<_>>(),
        ),
    );
    Value::Object(map.into_iter().collect()).to_string()
}

fn diff_value(diff: &gitiup_normalise::NormalisationDiff) -> Value {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("step".into(), Value::String(diff.step.clone()));
    map.insert("kind".into(), Value::String(diff.kind.clone()));
    map.insert("before".into(), Value::String(diff.before.clone()));
    map.insert("after".into(), Value::String(diff.after.clone()));
    Value::Object(map.into_iter().collect())
}

/// A run report is a transport, not a signed document: parsed leniently, exactly as
/// `gitiup digest` parses it.
fn parse_report(bytes: &[u8]) -> Result<RunReport, AttestError> {
    serde_json::from_slice(bytes).map_err(|e| AttestError::invalid("run report", e.to_string()))
}

fn divergence_error(step: &str, kind: &str, before: &str, after: &str) -> AttestError {
    AttestError::new(
        ErrorKind::DigestMismatch,
        "normalise",
        format!("{step} {kind}\n  - {before}\n  + {after}"),
    )
    .with_hint("docs/reproducibility.md: what still differs after normalisation")
}

pub(crate) fn run(args: &[String]) -> Result<(), CliError> {
    let options = Options::parse(args)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let profile = options.profile();
    let report = parse_report(&read_report(options.source.as_deref())?)?;
    match &options.compare {
        None => {
            let described = describe(&report, &profile)?;
            if let Some(expected) = &options.expect_result {
                let actual = &described
                    .run
                    .manifest
                    .result_digest()
                    .expect("a manifest that just computed is hashable")
                    .0;
                if expected != actual {
                    return Err(AttestError::new(
                        ErrorKind::DigestMismatch,
                        "normalise",
                        format!("expected ResultDigest {expected}, computed {actual}"),
                    )
                    .with_hint("the same run normalised differently; check --rules")
                    .into());
                }
            }
            if options.json {
                println!("{}", described_json(&described, &profile));
            } else {
                print!("{}", describe_text(&described, &options, &profile));
            }
            Ok(())
        }
        Some(other) => {
            let second = parse_report(&read_report(Some(other))?)?;
            let comparison = compare_runs_with(&report, &second, &profile)?;
            if options.json {
                let mut map: BTreeMap<String, Value> = BTreeMap::new();
                map.insert("converged".into(), Value::from(comparison.converged));
                map.insert(
                    "result_a".into(),
                    Value::String(comparison.result_a.to_string()),
                );
                map.insert(
                    "result_b".into(),
                    Value::String(comparison.result_b.to_string()),
                );
                map.insert(
                    "divergences".into(),
                    Value::Array(comparison.divergences.iter().map(diff_value).collect()),
                );
                println!("{}", Value::Object(map.into_iter().collect()));
            } else if comparison.converged {
                println!(
                    "converged      yes\nresult         {}\nprofile        {} v{}",
                    comparison.result_a,
                    profile.name(),
                    profile.version()
                );
            } else {
                println!(
                    "converged      no ({} divergences)\nresult A       {}\nresult B       {}",
                    comparison.divergences.len(),
                    comparison.result_a,
                    comparison.result_b
                );
                for line in comparison.lines() {
                    println!("{line}");
                }
            }
            if !comparison.converged {
                let first = &comparison.divergences[0];
                return Err(divergence_error(
                    &first.step,
                    &first.kind,
                    &first.before,
                    &first.after,
                )
                .into());
            }
            Ok(())
        }
    }
}

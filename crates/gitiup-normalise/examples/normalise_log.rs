//! Normalise a log file and print what the profile did to it.
//!
//! ```sh
//! cargo run -p gitiup-normalise --example normalise_log -- some.log
//! ```
//!
//! The useful half is the diff list: "why do these two logs hash differently" is
//! answered by what was rewritten and what was left alone. `gitiup normalise` is the
//! same thing on the command line; this example exists so the crate can be exercised
//! without building the CLI.

use std::io::Read as _;

use gitiup_attest::run::RunReport;
use gitiup_normalise::{Profile, manifest_for};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut text = String::new();
    match args.first().map(String::as_str) {
        None | Some("-") => {
            std::io::stdin().read_to_string(&mut text)?;
        }
        Some(path) => text = std::fs::read_to_string(path)?,
    }

    // Two modes, because two questions get asked: "what does this log normalise to"
    // and "what does the run this log belongs to digest to".
    if args.get(1).is_some_and(|arg| arg == "--report") {
        let report: RunReport = serde_json::from_str(&text)?;
        let run = manifest_for(&report)?;
        println!("run    {}", run.manifest.digest()?);
        println!("result {}", run.manifest.result_digest()?);
        println!(
            "normalisation v{}",
            run.manifest.result.provenance.normalisation_version
        );
        for diff in &run.diffs {
            println!("{:<12} {:<22} - {}", diff.step, diff.kind, diff.before);
            println!("{:<12} {:<22} + {}", "", "", diff.after);
        }
        return Ok(());
    }

    let normalised = Profile::standard().normalise_recorded(&text);
    if text.contains("\"normalisation_version\"") {
        eprintln!(
            "note: this looks like a run report; pass --report to digest it instead of \
             normalising it as a log (or use `gitiup normalise`)"
        );
    }
    print!("{}", normalised.text);
    eprintln!("--- {} rewrites ---", normalised.rewrites.items().len());
    for rewrite in normalised.rewrites.items() {
        eprintln!(
            "{:>4} {:<12} - {}",
            rewrite.line,
            rewrite.rule.name(),
            rewrite.before
        );
        eprintln!("{:>4} {:<12} + {}", "", "", rewrite.after);
    }
    for (rule, count) in normalised.rewrites.counts() {
        eprintln!("{rule:?}: {count}");
    }
    Ok(())
}

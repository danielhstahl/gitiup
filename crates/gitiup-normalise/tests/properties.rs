//! Properties: the invariants that make a normaliser trustworthy rather than
//! merely busy.
//!
//! The one that matters most is **idempotence**: `normalise(normalise(x)) ==
//! normalise(x)`. A profile that was not a projection would make
//! `provenance.normalisation_version` meaningless, because the digest would depend
//! on how many times someone happened to pipe a log through. Everything else here
//! is a smaller version of the same worry: that the rules rewrite only what they
//! mean to, and say so when they do.

use std::path::PathBuf;

use gitiup_attest::run::{Material, RunReport};
use gitiup_normalise::{
    MAX_REWRITES, Profile, RULE_ORDER, Rule, Rules, compare_runs_with, manifest_for_with,
};

/// A log with one example of every rule, and a few things that must *not* match.
fn kitchen_sink() -> &'static str {
    concat!(
        "2026-10-27T09:11:12.481392Z started\n",
        "Mon Oct 27 09:11:13 2026 +0000\n",
        "Date:   Mon, 27 Oct 2026 09:11:15 +0000\n",
        "took 1m 2s and 3 ms\n",
        "Finished release [optimized] target(s) in 41.283s\n",
        "elapsed 12:34\n",
        "progress 45%\n",
        "Progress [#######---] 60%\n",
        "\r#####----- 25%\n",
        "size 1.5 KiB, 4.0K, 1,024 bytes, 2G\r\n",
        "count 1,234,567 and 1 234 567\n",
        "uid=1001(runner) gid=1001(runner) groups=1001(runner),27(sudo)\n",
        "runner@build-07.internal:~$ cargo build\n",
        "host: runner-7.internal\n",
        "path /home/runner/work/gitiup/gitiup/target/debug/gitiup\n",
        "temp $RUNNER_TEMP/dist/x and /tmp/tmp.Ab12Cd/logs/out.log\n",
        "drwxr-xr-x  4 runner runner 4096 Oct 27 09:11 target\n",
        "-rw-r--r--  1 runner runner 1536 Oct 27 09:12 README.md\n",
        "dist/z.tar.gz\n",
        "dist/a.tar.gz\n",
        "\u{1b}[1m\u{1b}[32mcolour\u{1b}[0m done\r\n",
        "rustc 1.99.1 built for x86_64-unknown-linux-gnu\n",
        "test a1b2c3d4e5 sha256:0000000000000000000000000000000000000000000000000000000000000000 ok\n",
        "v0.1.0 shipped 100 tests in python3.11\n"
    )
}

fn corpus_report(machine: &str) -> RunReport {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/corpus")
        .join(machine)
        .join("run.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{machine}: {e}"))
}

/// Every log stream in the corpus, plus the kitchen sink.
fn every_log() -> Vec<String> {
    let mut logs = vec![kitchen_sink().to_string()];
    for machine in ["machine-a", "machine-b"] {
        for step in corpus_report(machine).steps {
            for material in [step.stdout, step.stderr] {
                if let Material::Text(text) = material
                    && !text.is_empty()
                {
                    logs.push(text.clone());
                }
            }
        }
    }
    logs
}

#[test]
fn normalising_is_idempotent() {
    let profile = Profile::standard();
    for (index, log) in every_log().iter().enumerate() {
        let once = profile.normalise(log);
        let twice = profile.normalise(&once);
        assert_eq!(
            once, twice,
            "log {index} is not a fixed point:\n{once}\n---\n{twice}"
        );
    }
}

#[test]
fn every_rule_is_idempotent_on_its_own() {
    // Idempotence per rule, not just per profile: a rule that only settles on the
    // second pass would be a rule that rewrites its own placeholders.
    for rule in RULE_ORDER {
        let profile = Profile::with_rules(Rules::all().without(rule));
        for (index, log) in every_log().iter().enumerate() {
            let once = profile.normalise(log);
            assert_eq!(
                once,
                profile.normalise(&once),
                "log {index} with the `{}` rule off is not a fixed point",
                rule.name()
            );
        }
    }
}

#[test]
fn the_kitchen_sink_exercises_every_rule() {
    // A checklist that cannot rot: if a rule is added, it has to fire here or say
    // why in the kitchen sink.
    let recorded = Profile::standard().normalise_recorded(kitchen_sink());
    let fired: Vec<Rule> = recorded
        .rewrites
        .counts()
        .into_iter()
        .map(|(rule, _)| rule)
        .collect();
    for rule in RULE_ORDER {
        assert!(
            fired.contains(&rule),
            "the `{}` rule never fired on the kitchen sink",
            rule.name()
        );
    }
}

#[test]
fn output_that_says_nothing_about_the_machine_is_left_alone() {
    // The mirror image of idempotence: normalisation must not be a lossy filter.
    // Ordinary compiler and test output survives untouched, versions, hashes and
    // target triples included.
    for line in [
        "rustc 1.99.1 built for x86_64-unknown-linux-gnu\n",
        "test a1b2c3d4e5 sha256:0000000000000000000000000000000000000000000000000000000000000000 ok\n",
        "warning: unused variable: `scratch`\n",
        "v0.1.0 shipped 100 tests in python3.11\n",
        "src/main.rs\n",
        "no punctuation here at all\n",
    ] {
        assert_eq!(
            Profile::standard().normalise(line),
            line,
            "normalisation changed output that had nothing machine-specific in it"
        );
    }
}

#[test]
fn an_empty_stream_is_empty_in_every_spelling() {
    for spelling in ["", "\n", "\n\n\n", "   \n\t\n", "\u{feff}"] {
        assert_eq!(Profile::standard().normalise(spelling), "");
    }
}

#[test]
fn carriage_and_bar_churn_leaves_the_line_it_redrew() {
    let profile = Profile::standard();
    assert_eq!(
        profile.normalise("Downloading 12%\rDownloading 47%\rDownloading 100%\n"),
        "Downloading <pct>\n"
    );
    assert_eq!(profile.normalise("#####----- 25%\n"), "");
    assert_eq!(profile.normalise("deleted\r\n"), "deleted\n");
    assert_eq!(profile.normalise("abc\u{8}\u{8}XY\n"), "aXY\n");
}

#[test]
fn a_thousand_rewrites_say_so_instead_of_truncating_silently() {
    let noisy = "took 1s\n".repeat(MAX_REWRITES + 40);
    let recorded = Profile::standard().normalise_recorded(&noisy);
    assert_eq!(recorded.rewrites.items().len(), MAX_REWRITES);
    let total: usize = recorded.rewrites.dropped().values().sum();
    assert_eq!(total, 40, "the record must know how much it dropped");
    let diffs = recorded.rewrites.aggregate("noisy", "");
    assert!(
        diffs.iter().any(|diff| diff.kind.ends_with(":truncated")),
        "{diffs:?}"
    );
}

#[test]
fn rules_can_be_selected_by_name() {
    // `gitiup normalise --rules` and any future config depend on this round trip.
    let names: Vec<&str> = RULE_ORDER.iter().map(|rule| rule.name()).collect();
    assert_eq!(
        Rules::parse_list(&names.join(",")).unwrap(),
        Rules::all(),
        "every rule name must parse back"
    );
    assert_eq!(
        Rules::parse_list("timestamp").unwrap(),
        Rules::none().with(Rule::Timestamp),
        "a named list selects exactly that set, not the default plus it"
    );
    assert!(
        Rules::parse_list("timestamp , duration")
            .unwrap()
            .contains(Rule::Duration)
    );
    assert!(
        Rules::parse_list("nonsense").is_err(),
        "a typo must not silently mean 'nothing'"
    );
}

#[test]
fn the_rules_the_corpus_depends_on_earn_their_place() {
    // Each of these rules is the *only* thing standing between the two machines and
    // a different digest. If a rule stops mattering, that is either a corpus bug or
    // a rule that stopped working — both worth a failing test.
    for rule in [
        Rule::LineEndings,
        Rule::Ansi,
        Rule::Timestamp,
        Rule::Duration,
        Rule::Path,
        Rule::Identity,
        Rule::Size,
        Rule::Number,
        Rule::Listing,
        Rule::Progress,
    ] {
        let profile = Profile::without(rule);
        let comparison = compare_runs_with(
            &corpus_report("machine-a"),
            &corpus_report("machine-b"),
            &profile,
        )
        .unwrap();
        assert!(
            !comparison.converged,
            "without the `{}` rule the two machines still converge — either the rule does nothing or the corpus stopped testing it",
            rule.name()
        );
    }
}

#[test]
fn a_profile_that_rewrites_nothing_hashes_what_arrived() {
    // The version-0 semantics, expressed as a rule set: with no rules the profile is
    // the identity, which is what `RawText` promises.
    let profile = Profile::with_rules(Rules::none());
    let log = "2026-10-27T09:11:12Z took 1s\n";
    assert_eq!(profile.normalise(log), log);
    let report = corpus_report("machine-a");
    let manifest = manifest_for_with(&report, &profile).unwrap();
    assert_eq!(
        manifest.manifest.result.steps[0].stdout,
        gitiup_attest::Digest::sha256(log_bytes(&report).as_bytes()),
        "with no rules the digest is the digest of the bytes handed over"
    );
}

fn log_bytes(report: &RunReport) -> String {
    match &report.steps[0].stdout {
        Material::Text(text) => text.clone(),
        _ => String::new(),
    }
}

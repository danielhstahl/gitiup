//! `gitiup quorum dispute` — the report a disagreement deserves (giti-zp1.7).
//!
//! `gitiup quorum verdict` answers the merge gate's question — one state, one exit code —
//! and in doing so it necessarily leaves out the part a human needs: the losing digests
//! are named and counted, and the logs that produced them stay in the volunteers'
//! terminals. The owner's question is the other one. When five machines disagree, the
//! evidence has to be laid out:
//!
//! ```text
//!  refs/gitiup/round/<change>/<job>/<attempt> ──► the round, its seats, its threshold
//!  refs/gitiup/reveal/<change>/<job>/<slot>   ──► each seat's attestation:
//!                                                   · the ResultDigest it signed
//!                                                   · the sandbox that confined it, and
//!                                                     what that sandbox promised
//!                                                   · the environment fingerprint
//!  the logs a caller hands over (--logs)     ──► the raw text, and the same text after
//!                                                   `gitiup-normalise`
//!                      │
//!    distinct digests × count · seats · rungs · fingerprints · raw ⟂ normalised diffs
//!                      │
//!                stdout, one report · exit 0 · 6 · 7 · 8
//! ```
//!
//! # Why the two diffs are printed together
//!
//! A divergence that survives normalisation is a fact about the build: a test that ran
//! differently, a version that moved, an artifact that changed size. A divergence that
//! does not survive it is a fact about the machine — a timestamp, a temp directory, a
//! duration — and it proves only that two machines exist. Both kinds make the digests
//! differ, and they need opposite responses, so the report prints the raw diff and the
//! normalised diff and says, per hunk, which kind it is. A dispute whose every hunk
//! normalises away is a normalisation bug and not a broken change, and saying so is
//! cheaper than five more attempts.
//!
//! # The logs are evidence, and evidence is checked
//!
//! An attestation carries the digest of each step's *normalised* stdout and stderr, not
//! the bytes: the raw log lives wherever the volunteer left it. So `--logs` hands the
//! report those files, and the first thing it does with one is hash it the way the seat
//! hashed it — with the normalisation version that attestation declares — and refuse it
//! if it does not match. A log that fails that check is not this seat's log, and a dispute
//! argued from somebody else's log is worse than no report at all: it is a confident wrong
//! answer about a change somebody is trying to merge.
//!
//! # What this command will not do
//!
//! * **decide anything.** The state and the exit code are `gitiup quorum verdict`'s,
//!   computed by the same call on the same records; this is the tally read out loud.
//! * **open, retry or void a round.** That is [`crate::retry`], and the separation is not
//!   cosmetic: reading the evidence and spending five volunteers on it again are two acts,
//!   and a tool that does both cannot be run nervously.
//! * **invent the logs.** Without `--logs` the report is the digests, seats, rungs and
//!   fingerprints the store can give it, and it says plainly that the log comparison is
//!   missing rather than printing nothing and letting the reader notice.

use std::collections::BTreeMap;
use std::path::Path;

use gitiup_attest::run::{Material, RawText, RunReport};
use gitiup_attest::{AttestationDoc, Digest, Normaliser};
use gitiup_normalise::{Change, Profile, Rules, TextDiff, diff_text};
use gitiup_quorum::prelude::*;
use gitiup_quorum::verdict::Evaluation;
use gitiup_quorum::{store, verdict};
use serde_json::{Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{self, Opened};
use crate::verdict as verdict_cli;

/// Help for `gitiup quorum dispute`.
pub const DISPUTE_HELP: &str = "\
gitiup quorum dispute — the report a disagreement deserves

USAGE:
    gitiup quorum dispute <CHANGE> [OPTIONS]

<CHANGE> is a change id (`chg-…`), a 4+ hex prefix of one, or the change id the
rounds name. Every round tallied is reported: the distinct ResultDigests and their
counts, the seats, the sandbox each run used and what it promised, each machine's
environment fingerprint, and — for logs handed over with --logs — the raw diff
and the same diff after gitiup-normalise, side by side, with a verdict per hunk.

WHERE TO LOOK
    --store <dir> | --remote <name>   the store (required: a dispute is a fact about a store)
    --job <id>                        only this job (a matrix arm is its own job)
    --attempt <n>                     this attempt, not the latest one the store has
    --owner <key|id>                  repeatable: whose signature counts (default: this
                                      machine's own keys, and the report says which)

WHEN, AND HOW STRICT — the same knobs `gitiup quorum verdict` takes, so the dispute is
about exactly the evidence a verdict would count
    --now <time>                      pin the clock (µs or RFC 3339)
    --tier <tier>                     repeatable: provenance tiers accepted (default: local)
    --sandbox <name>                  repeatable: sandbox backends accepted (default: any)
    --max-age <age>                   freshness window: 90s, 24h, 30d, `never`
    --max-skew <age>                  clock skew allowed (default: 5m)

THE LOGS
    --logs <dir>                      run-report JSON (or plain log text) named after the
                                      seat's slot: <slot>.json. Each is hashed the way its
                                      seat hashed it and refused if it does not match, so
                                      a mis-pairing cannot slip into the report
    --log <slot>=<path>               repeatable, and wins over --logs; `-` reads stdin
    --rules <list>                    normalisation rules to apply (diagnosis, not policy:
                                      `gitiup normalise help` lists the names)

OUTPUT
    --width <n>                       side-by-side width in columns (default 100)
    --context <n>                     unchanged lines kept around each hunk (default 1)
    -j, --json                        one line: every group, seat, hunk and fingerprint
    -h, --help                        this text

The exit code is the verdict's, because a dispute is the verdict read out loud: 0 nothing
to dispute · 6 `failed` or `insufficient`, or no rounds · 7 a signature in the evidence
that does not verify · 8 a digest that is not what it names — including a --logs file that
does not hash to what its seat signed. Usage is 2 and an unreachable store is 3, and
neither is a verdict.

Try:
    gitiup quorum dispute chg-6a6a8eab778ba4d0 --store ./store
    gitiup quorum dispute chg-6a6a --store ./store --job build --logs ./logs
    gitiup quorum dispute chg-6a6a --store ./store --log <slot>=./eve.json --json
";

/// Valued flags.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--job",
    "--attempt",
    "--owner",
    "--now",
    "--tier",
    "--sandbox",
    "--max-age",
    "--max-skew",
    "--logs",
    "--log",
    "--rules",
    "--width",
    "--context",
];

/// Switches.
const SWITCHES: &[&str] = &["--json"];

/// The default side-by-side width: wide enough for two readable columns of a build-log
/// line, narrow enough for the terminal a surprised owner is already in.
const DEFAULT_WIDTH: usize = 100;

/// Unchanged lines kept around each hunk by default.
const DEFAULT_CONTEXT: usize = 1;

/// `gitiup quorum dispute <CHANGE> …`.
pub fn dispute(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if args.wants_help() || args.positional.first().is_some_and(|first| first == "help") {
        print!("{DISPUTE_HELP}");
        return Ok(());
    }
    let Some(handle) = args.positional.first().map(String::as_str) else {
        return Err(CliError::usage(
            "`gitiup quorum dispute` needs a change: `gitiup quorum dispute <CHANGE> --store \
             <dir> [--logs <dir>]`",
        ));
    };
    if args.positional.len() > 1 {
        return Err(CliError::usage(format!(
            "unexpected extra argument '{}'; the change is the only positional",
            args.positional[1]
        )));
    }
    let number = |flag: &str, text: &str| -> Result<usize, CliError> {
        text.parse::<usize>()
            .map_err(|_| CliError::usage(format!("{flag} wants a whole number, got '{text}'")))
    };
    let layout = Layout {
        width: match args.get("--width") {
            Some(text) => number("--width", text)?,
            None => DEFAULT_WIDTH,
        },
        context: match args.get("--context") {
            Some(text) => number("--context", text)?,
            None => DEFAULT_CONTEXT,
        },
    };
    let profile = profile_from(&args)?;

    let opened = participant::need_store(&args)?;
    let here = participant::keystore()?;
    let (trust, trusted_by) = participant::owner_trust(&args, &here)?;
    let evaluation = verdict_cli::evaluation_from(&args)?;
    let change = verdict_cli::change_id(&*opened.host, handle)?;
    let published = store::rounds_for(&*opened.host, &change)?;
    let rounds = verdict_cli::select_rounds(&args, &published)?;
    if rounds.is_empty() {
        return Err(CliError::refused(
            format!(
                "{} has no round for change {change}{}",
                opened.what,
                match args.get("--job") {
                    Some(job) => format!(" / job {job}"),
                    None => String::new(),
                }
            ),
            "a dispute is about a round that ran: `gitiup quorum verdict <id>` says what a \
             store holds, and `gitiup select --change <id> … --publish` opens one",
        ));
    }
    let logs = load_logs(&args)?;
    let mut runner = Runner {
        opened: &opened,
        trust: &trust,
        evaluation: &evaluation,
        profile: &profile,
        logs: &logs,
        revocations: None,
        rosters: BTreeMap::new(),
        notes: Vec::new(),
        rounds: Vec::new(),
    };
    runner.run(&rounds)?;
    let report = Report {
        store: opened.what.clone(),
        handle: handle.to_string(),
        change,
        trusted_by,
        evaluation: &evaluation,
        profile: &profile,
        layout,
        provided: logs.len(),
        rounds: runner.rounds,
        notes: runner.notes,
    };
    if args.on("--json") {
        participant::print_json(report.json());
    } else {
        report.print();
    }
    report.exit()
}

/// The two knobs about how wide a window of log text to print.
struct Layout {
    width: usize,
    context: usize,
}

/// The normalisation profile the report displays with, and names in its output.
fn profile_from(args: &Args) -> Result<Profile, CliError> {
    match args.get("--rules") {
        Some(list) => Rules::parse_list(list)
            .map(Profile::with_rules)
            .map_err(|error| CliError::usage(format!("--rules: {error}"))),
        None => Ok(Profile::standard()),
    }
}

// ---------------------------------------------------------------------------
// the logs a caller hands over
// ---------------------------------------------------------------------------

/// One log file, read and flattened to text, keyed by the slot its name names.
#[derive(Debug)]
struct ProvidedLog {
    /// Where it came from, for the report and the refusal.
    path: String,
    /// The raw text, step by step.
    raw: String,
    /// The same text after the display profile.
    normalised: String,
    /// The step digests, recomputed the way an attestation computes them, for the check
    /// against what the seat actually signed. `None` for a plain-text log: one stream, no
    /// step structure to pair.
    steps: Option<Vec<StepDigests>>,
}

/// One step's two streams, recomputed from the report that was handed over.
#[derive(Debug)]
struct StepDigests {
    /// Step id, or name when it has no id — the same key the manifest uses.
    key: String,
    /// stdout hashed with the report's own normalisation version.
    stdout: Digest,
    /// stderr, likewise.
    stderr: Digest,
}

/// `--logs <dir>` and `--log <slot>=<path>`, read once before any round is tallied.
///
/// Keyed by slot because the slot is the seat's public name everywhere else in the store
/// (`refs/gitiup/reveal/<change>/<job>/<slot>`), and because a key id — `SHA256:<base64>`
/// — is hostile in a filename.
fn load_logs(args: &Args) -> Result<BTreeMap<String, ProvidedLog>, CliError> {
    let mut out: BTreeMap<String, ProvidedLog> = BTreeMap::new();
    if let Some(dir) = args.get("--logs") {
        let entries =
            std::fs::read_dir(dir).map_err(|e| CliError::io(format!("reading '{dir}': {e}")))?;
        let mut files: Vec<std::path::PathBuf> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for path in files {
            let Some(slot) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| stem.trim().to_ascii_lowercase())
            else {
                continue;
            };
            if slot.is_empty() {
                continue;
            }
            out.insert(slot.clone(), read_log(&slot, &path)?);
        }
    }
    for pair in args.all("--log") {
        let Some((slot, path)) = pair.split_once('=') else {
            return Err(CliError::usage(format!(
                "--log wants <slot>=<path>, got '{pair}'"
            )));
        };
        let slot = slot.trim().to_ascii_lowercase();
        let bytes = participant::read_maybe_stdin(path)?;
        let display = if path == "-" { "stdin" } else { path };
        out.insert(slot.clone(), parse_log(display, &bytes)?);
    }
    Ok(out)
}

fn read_log(slot: &str, path: &Path) -> Result<ProvidedLog, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::io(format!("reading '{}': {e}", path.display())))?;
    parse_log(&path.display().to_string(), &bytes).map_err(|error| with_slot(slot, error))
}

/// Prefix a refusal about one file with the file's slot, so a directory of thirty logs
/// says which one it is complaining about.
fn with_slot(slot: &str, error: CliError) -> CliError {
    CliError::io(format!("slot {slot}: {}", error.message))
}

/// Parse a handed-over log: a run report if it is one, plain text otherwise.
///
/// A run report is preferred because it carries step structure, which is what lets the log
/// be checked step by step against the attestation. A plain file is one stream, and a seat
/// whose run had several steps cannot be checked against it — said out loud in the report
/// rather than passed off as a match.
fn parse_log(display: &str, bytes: &[u8]) -> Result<ProvidedLog, CliError> {
    if let Ok(report) = serde_json::from_slice::<RunReport>(bytes) {
        return described_from_report(display, &report);
    }
    Ok(ProvidedLog {
        path: display.to_string(),
        raw: String::from_utf8_lossy(bytes).to_string(),
        normalised: Profile::standard().normalise(&String::from_utf8_lossy(bytes)),
        steps: None,
    })
}

/// Flatten a run report to raw text, plus the step digests its own normalisation gives.
fn described_from_report(display: &str, report: &RunReport) -> Result<ProvidedLog, CliError> {
    // Hashed with the *report's* rules: `normalisation_version` 0 means the bytes were
    // hashed as handed over, which is what the manifest did with them, and a v1 report
    // normalised with anything else would not reproduce the digests the seat signed.
    let raw_profile = RawText;
    let standard = Profile::standard();
    let mut raw = String::new();
    let mut steps = Vec::with_capacity(report.steps.len());
    for step in &report.steps {
        let stdout = material_text(&step.stdout)?;
        let stderr = material_text(&step.stderr)?;
        raw.push_str(&format!("--- {} (stdout) ---\n{stdout}", step.key()));
        if !stderr.is_empty() {
            raw.push_str(&format!("\n--- {} (stderr) ---\n{stderr}", step.key()));
        }
        if !raw.ends_with('\n') {
            raw.push('\n');
        }
        let normaliser: &dyn Normaliser = match report.provenance.normalisation_version {
            0 => &raw_profile,
            _ => &standard,
        };
        steps.push(StepDigests {
            key: step.key(),
            stdout: step.stdout.hash_with(normaliser)?,
            stderr: step.stderr.hash_with(normaliser)?,
        });
    }
    Ok(ProvidedLog {
        path: display.to_string(),
        normalised: standard.normalise(&raw),
        raw,
        steps: Some(steps),
    })
}

/// The text of one stream, or the refusal that says the report carried digests instead.
fn material_text(material: &Material) -> Result<String, CliError> {
    match material {
        Material::Text(text) => Ok(text.clone()),
        Material::Parts(parts) => Ok(parts.join("")),
        Material::Digest(digest) => Err(CliError::refused(
            format!(
                "a log handed to `quorum dispute` has to carry its text; this stream is a \
                 digest only ({})",
                short_digest(&digest.to_string())
            ),
            "hand over the run report the runner produced, or the log text itself: a digest \
             cannot be diffed",
        )),
        Material::Files(_) => Err(CliError::refused(
            "a log handed to `quorum dispute` has to be a stream, not a file set",
            "hand over the run report the runner produced, or the log text itself",
        )),
    }
}

// ---------------------------------------------------------------------------
// one round's report
// ---------------------------------------------------------------------------

/// Everything one round contributes.
struct RoundReport {
    job: String,
    attempt: u64,
    round_digest: String,
    roster_epoch: u64,
    roster_digest: String,
    reveal_mode: String,
    required_agree: usize,
    n: usize,
    verdict: verdict::VerdictRecord,
    /// The distinct result digests, most-voted first.
    groups: Vec<Group>,
    seats: Vec<SeatRow>,
    /// The log comparisons, one per losing seat that had a log *and* an agreeing log to
    /// be compared against.
    comparisons: Vec<Comparison>,
    /// Losing seats whose logs were not handed over.
    waiting: Vec<String>,
    /// Notes about this round's logs specifically.
    log_notes: Vec<String>,
}

/// One distinct `ResultDigest` and the seats that signed it.
struct Group {
    result: Option<Digest>,
    keys: Vec<String>,
    /// The side the verdict counted.
    winning: bool,
    /// Whether this group alone reaches the threshold.
    reached: bool,
}

/// One seat, as the store and its attestation describe it.
struct SeatRow {
    rank: u32,
    slot: String,
    key_id: String,
    identity: String,
    tier: String,
    /// What confined the run, from the attestation (`provenance.sandbox`).
    sandbox: Option<String>,
    /// What that sandbox promised, from the attestation's annotations.
    guarantees: Option<String>,
    /// The rung the box is registered at, and the rung the round demanded.
    roster_level: Option<u8>,
    required_level: u8,
    /// The machine class the run reported, and its fingerprint.
    environment: Option<String>,
    fingerprint: Option<Digest>,
    result: Option<Digest>,
    normalisation_version: Option<u32>,
    rewrites: Option<usize>,
    status: &'static str,
    /// The verdict's token, when this seat was refused.
    refusal: Option<String>,
}

/// One losing seat's log, compared with the agreeing side's.
struct Comparison {
    slot: String,
    key_id: String,
    versus_slot: String,
    versus_key: String,
    /// The sentence saying the log was checked against what the seat signed.
    verified: String,
    /// The same sentence about the agreeing side's log, which is the yardstick.
    versus_verified: String,
    raw: TextDiff,
    normalised: TextDiff,
    /// Hunks whose difference the profile cannot erase.
    surviving: usize,
    /// Total hunks in the raw diff.
    hunks: usize,
}

impl Comparison {
    /// The one-line answer the whole comparison exists to give.
    fn verdict(&self) -> &'static str {
        if self.hunks == 0 {
            "the two logs are the same text"
        } else if self.surviving == 0 {
            "does not survive normalisation \u{2014} machine noise, not a different build"
        } else {
            "survives normalisation \u{2014} a real disagreement about the build"
        }
    }

    fn json(&self, profile: &Profile) -> Value {
        json!({
            "slot": self.slot,
            "key_id": self.key_id,
            "versus_slot": self.versus_slot,
            "versus_key": self.versus_key,
            "verified": self.verified,
            "versus_verified": self.versus_verified,
            "verdict": self.verdict(),
            "hunks": self.hunks,
            // How many of those hunks the normalisation profile cannot erase: 0 of ≥1 is
            // machine noise, ≥1 is a disagreement about the build.
            "surviving": self.surviving,
            "profile": format!("{} v{}", profile.name(), profile.version()),
            "raw": &self.raw,
            "normalised": &self.normalised,
        })
    }

    fn render(&self, layout: &Layout, profile: &Profile) -> Vec<String> {
        let raw = self.raw.stats();
        let normalised = self.normalised.stats();
        let mut out = vec![
            format!(
                "    slot {} \u{b7} {} \u{b7} against slot {} \u{b7} {}",
                short_digest(&self.slot),
                self.key_id,
                short_digest(&self.versus_slot),
                self.versus_key,
            ),
            format!("    evidence    this seat: {}", self.verified),
            format!("    evidence    agreeing: {}", self.versus_verified),
            format!(
                "    raw         {} line(s) differ in {} hunk(s) ({} only the agreeing side \
                 has, {} only this seat has)",
                raw.added + raw.removed,
                raw.changes,
                raw.removed,
                raw.added,
            ),
            format!(
                "    normalised  {} line(s) still differ under {} v{} \u{b7} {}",
                normalised.added + normalised.removed,
                profile.name(),
                profile.version(),
                self.verdict(),
            ),
        ];
        if self.hunks > 0 {
            out.push(
                "    side by side (left \u{2261} the agreeing side · right \u{2261} this seat):"
                    .to_string(),
            );
            let annotated = self.raw.side_by_side_annotated(
                layout.width.saturating_sub(8),
                layout.context,
                &annotator(profile),
            );
            for line in annotated.lines() {
                out.push(format!("      {line}"));
            }
            out.push(format!(
                "      ({} of {} hunk(s) survive normalisation; the rest are facts about the \
                 machine, not the build)",
                self.surviving, self.hunks
            ));
        }
        out
    }
}

/// Per-hunk annotation: does the profile erase this difference, or not?
fn annotator<'a>(profile: &'a Profile) -> impl Fn(&Change) -> Option<String> + 'a {
    move |change: &Change| {
        Some(if change.survives_normalisation(profile) {
            "\u{2262} survives normalisation \u{2014} about the build".to_string()
        } else {
            "\u{2261} erased by normalisation \u{2014} about the machine".to_string()
        })
    }
}

impl Group {
    fn json(&self) -> Value {
        json!({
            "result_digest": self.result.as_ref().map(|digest| digest.to_string()),
            "count": self.keys.len(),
            "keys": self.keys,
            "winning": self.winning,
            "reached_threshold": self.reached,
        })
    }

    fn line(&self) -> String {
        let digest = self
            .result
            .as_ref()
            .map(|digest| short_digest(&digest.to_string()))
            .unwrap_or_else(|| "no usable result".to_string());
        format!(
            "    {:<16} \u{d7}{:<3} {:<22} {}",
            digest,
            self.keys.len(),
            if self.winning {
                "counted"
            } else if self.reached {
                "would have reached"
            } else {
                "losing"
            },
            self.keys
                .iter()
                .map(|key| participant::short(key))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

impl SeatRow {
    fn json(&self) -> Value {
        json!({
            "rank": self.rank,
            "slot": self.slot,
            "key_id": self.key_id,
            "identity": self.identity,
            "tier": self.tier,
            "sandbox": self.sandbox,
            "sandbox_guarantees": self.guarantees,
            "roster_sandbox_level": self.roster_level.map(u64::from),
            "required_sandbox_level": u64::from(self.required_level),
            "environment": self.environment,
            "environment_fingerprint": self.fingerprint.as_ref().map(|d| d.to_string()),
            "result_digest": self.result.as_ref().map(|d| d.to_string()),
            "normalisation_version": self.normalisation_version,
            "normalisation_rewrites": self.rewrites,
            "status": self.status,
            "refusal": self.refusal,
        })
    }

    /// The sandbox column: what confined the run, and what that rung is worth.
    fn sandbox(&self) -> String {
        match (&self.sandbox, &self.guarantees) {
            (Some(name), Some(guarantees)) => format!("{name} \u{b7} {guarantees}"),
            (Some(name), None) => match self.roster_level {
                Some(level) => format!("{name} \u{b7} rung L{level}"),
                None => name.clone(),
            },
            (None, _) => "nothing confined it".to_string(),
        }
    }

    fn line(&self) -> String {
        format!(
            "    #{:<2} {:<16} {:<9} {:<11} {:<34} env {} \u{b7} {}{}",
            self.rank,
            participant::short(&self.key_id),
            self.tier,
            self.status,
            self.sandbox(),
            self.fingerprint
                .as_ref()
                .map(|digest| short_digest(&digest.to_string()))
                .unwrap_or_else(|| "\u{2014}".to_string()),
            self.result
                .as_ref()
                .map(|digest| format!("result {}", short_digest(&digest.to_string())))
                .unwrap_or_else(|| "no result".to_string()),
            match &self.refusal {
                Some(code) => format!(" \u{b7} {code}"),
                None => String::new(),
            },
        )
    }
}

impl RoundReport {
    fn json(&self, profile: &Profile) -> Value {
        // The verdict record is nested rather than flattened: it is a signed record with
        // its own field names (`seats` is a count there, and a list of rows here), and a
        // reader who knows `gitiup quorum verdict --json` should find those fields under
        // the same names in this report.
        let mut out = serde_json::Map::new();
        out.insert("job".into(), json!(self.job));
        out.insert("attempt".into(), json!(self.attempt));
        out.insert("round_digest".into(), json!(self.round_digest));
        out.insert("roster_epoch".into(), json!(self.roster_epoch));
        out.insert("roster_digest".into(), json!(self.roster_digest));
        out.insert("reveal_mode".into(), json!(self.reveal_mode));
        out.insert("n".into(), json!(self.n));
        out.insert("required_agree".into(), json!(self.required_agree));
        out.insert(
            "verdict_digest".into(),
            json!(self.verdict.digest().map(|digest| digest.to_string()).ok()),
        );
        out.insert(
            "verdict".into(),
            serde_json::to_value(&self.verdict).unwrap_or(Value::Null),
        );
        out.insert(
            "results".into(),
            Value::Array(self.groups.iter().map(Group::json).collect()),
        );
        out.insert(
            "seats".into(),
            Value::Array(self.seats.iter().map(SeatRow::json).collect()),
        );
        out.insert(
            "logs".into(),
            Value::Array(
                self.comparisons
                    .iter()
                    .map(|comparison| comparison.json(profile))
                    .collect(),
            ),
        );
        out.insert(
            "logs_missing_for".into(),
            Value::Array(
                self.waiting
                    .iter()
                    .map(|slot| json!({ "slot": slot }))
                    .collect(),
            ),
        );
        out.insert(
            "notes".into(),
            Value::Array(self.log_notes.iter().map(|note| json!(note)).collect()),
        );
        Value::Object(out)
    }

    fn print(&self, layout: &Layout, profile: &Profile) {
        println!(
            "{}  {} \u{b7} attempt {} \u{b7} {} of {} identities agree on {}",
            self.verdict.state,
            self.job,
            self.attempt,
            self.verdict.agreeing,
            self.verdict.required_agree,
            self.short_result(),
        );
        println!("  {}", one_line(&self.verdict.detail));
        println!(
            "  round {} \u{b7} roster epoch {} ({}) \u{b7} {} seats \u{b7} agree {} \u{b7} reveal {}",
            short_digest(&self.round_digest),
            self.roster_epoch,
            short_digest(&self.roster_digest),
            self.n,
            self.required_agree,
            self.reveal_mode,
        );
        println!("  results ({} distinct):", self.groups.len());
        for group in &self.groups {
            println!("{}", group.line());
        }
        println!("  seats:");
        for seat in &self.seats {
            println!("{}", seat.line());
        }
        if !self.verdict.missing.is_empty() {
            println!(
                "  silent ({}): {}",
                self.verdict.missing.len(),
                self.verdict
                    .missing
                    .iter()
                    .map(|key| participant::short(key))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !self.comparisons.is_empty() {
            println!("  losing logs:");
            for comparison in &self.comparisons {
                for line in comparison.render(layout, profile) {
                    println!("{line}");
                }
            }
        }
        for note in &self.log_notes {
            println!("  note: {note}");
        }
    }

    fn short_result(&self) -> String {
        self.verdict
            .result_digest
            .as_ref()
            .map(|digest| short_digest(&digest.to_string()))
            .unwrap_or_else(|| "nothing".to_string())
    }
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

struct Runner<'a> {
    opened: &'a Opened,
    trust: &'a Trust,
    evaluation: &'a Evaluation,
    profile: &'a Profile,
    logs: &'a BTreeMap<String, ProvidedLog>,
    revocations: Option<Vec<Revocation>>,
    rosters: BTreeMap<u64, Roster>,
    notes: Vec<String>,
    rounds: Vec<RoundReport>,
}

impl<'a> Runner<'a> {
    fn run(&mut self, rounds: &[&Round]) -> Result<(), CliError> {
        // Read once: who is dead *now* is a property of the store, not of a round.
        self.revocations = Some(store::list_revocations(&*self.opened.host, self.trust)?);
        for round in rounds {
            let report = self.one(round)?;
            self.rounds.push(report);
        }
        Ok(())
    }

    fn roster(&mut self, epoch: u64) -> Result<Roster, CliError> {
        if let Some(roster) = self.rosters.get(&epoch) {
            return Ok(roster.clone());
        }
        let roster = store::roster_at(&*self.opened.host, epoch)?.ok_or_else(|| {
            CliError::refused(
                format!("{} holds no roster epoch {epoch}", self.opened.what),
                "a round is only meaningful against the epoch it pinned, so that epoch has \
                 to still be published",
            )
        })?;
        roster.verify(self.trust, self.evaluation.now)?;
        self.rosters.insert(epoch, roster.clone());
        Ok(roster)
    }

    fn one(&mut self, round: &Round) -> Result<RoundReport, CliError> {
        let roster = self.roster(round.inputs.roster_epoch)?;
        // The round before anything in it, under a trusted selector signature: a record
        // whose seats were hand-picked would otherwise produce a dispute report about a
        // jury that never existed.
        round.verify(self.trust, &roster)?;
        let attestations = store::submissions(&*self.opened.host, round)?;
        let record = store::tally(
            &*self.opened.host,
            round,
            &roster,
            self.revocations.as_deref().unwrap_or_default(),
            self.evaluation,
        )?;
        let by_key: BTreeMap<String, &AttestationDoc> = attestations
            .iter()
            .filter(|doc| doc.signatures.len() == 1)
            .map(|doc| (doc.signatures[0].key_id.clone(), doc))
            .collect();

        let mut groups: Vec<Group> = Vec::new();
        if !record.counted.is_empty() {
            groups.push(Group {
                result: record.result_digest.clone(),
                keys: record
                    .counted
                    .iter()
                    .map(|vote| vote.key_id.clone())
                    .collect(),
                winning: true,
                reached: record.counted.len() >= record.required_agree,
            });
        }
        for divergent in &record.divergent {
            groups.push(Group {
                result: Some(divergent.result_digest.clone()),
                keys: divergent.keys.clone(),
                winning: false,
                reached: divergent.keys.len() >= record.required_agree,
            });
        }
        // Most votes first, then by digest: the report's order is a function of the
        // evidence, not of the order the store happened to return.
        groups.sort_by(|a, b| {
            b.keys
                .len()
                .cmp(&a.keys.len())
                .then_with(|| a.result.cmp(&b.result))
        });

        let seats: Vec<SeatRow> = round
            .selected
            .iter()
            .map(|seat| {
                seat_row(
                    seat,
                    by_key.get(&seat.key_id).copied(),
                    roster.entry(&seat.key_id),
                    round,
                    &record,
                )
            })
            .collect();

        let mut log_notes = Vec::new();
        let comparisons = self.comparisons(round, &record, &by_key, &mut log_notes)?;
        let waiting: Vec<String> = record
            .divergent
            .iter()
            .flat_map(|group| group.keys.iter())
            .filter_map(|key| {
                round
                    .seat(key)
                    .filter(|seat| !self.logs.contains_key(&seat.slot))
                    .map(|seat| seat.slot.clone())
            })
            .collect();
        let losing = record
            .divergent
            .iter()
            .map(|group| group.keys.len())
            .sum::<usize>();
        if losing > 0 && comparisons.is_empty() && self.logs.is_empty() {
            self.notes.push(format!(
                "job {}: {losing} seat(s) disagreed and no logs were handed over, so the \
                 report cannot say whether the difference survives normalisation \
                 (`--logs <dir>`, each seat's run report named <slot>.json)",
                round.inputs.job_id
            ));
        }
        Ok(RoundReport {
            job: round.inputs.job_id.clone(),
            attempt: round.inputs.attempt,
            round_digest: record.round_digest.to_string(),
            roster_epoch: roster.epoch,
            roster_digest: record.roster_digest.to_string(),
            reveal_mode: round.reveal_mode.clone(),
            required_agree: record.required_agree,
            n: round.inputs.policy.n,
            groups,
            seats,
            comparisons,
            waiting,
            log_notes,
            verdict: record,
        })
    }

    /// Compare every losing seat's log with the agreeing side's.
    fn comparisons(
        &self,
        round: &Round,
        record: &verdict::VerdictRecord,
        by_key: &BTreeMap<String, &AttestationDoc>,
        notes: &mut Vec<String>,
    ) -> Result<Vec<Comparison>, CliError> {
        let losing: Vec<String> = record
            .divergent
            .iter()
            .flat_map(|group| group.keys.iter().cloned())
            .collect();
        if losing.is_empty() {
            return Ok(Vec::new());
        }
        let Some(winner_key) = record.counted.first().map(|vote| vote.key_id.clone()) else {
            return Ok(Vec::new());
        };
        let winner_slot = round
            .seat(&winner_key)
            .map(|seat| seat.slot.clone())
            .unwrap_or_default();
        let Some(agreeing) = self.logs.get(&winner_slot) else {
            notes.push(format!(
                "the agreeing side's log (slot {winner_slot}, key {winner_key}) was not \
                 handed over, so the losing logs have nothing to be compared against. \
                 --logs wants one file per seat named after its slot; this one is \
                 `{winner_slot}.*`, or name it directly: --log {winner_slot}=<path>",
            ));
            return Ok(Vec::new());
        };
        // The agreeing side's log is the yardstick every losing log is measured against, so
        // it gets the same check: a file filed under a winner's slot that is not that
        // winner's run would otherwise bend every comparison at once, and bend them
        // convincingly.
        let agreeing_doc = by_key.get(&winner_key).copied().ok_or_else(|| {
            mismatch(
                format!(
                    "the agreeing side (key {winner_key}) has no attestation in {} to check its \
                 log against",
                    self.opened.what
                ),
                "the side a dispute is measured from has to be attested; re-run the tally after \
             the submissions are in",
            )
        })?;
        let versus_verified = check_log(agreeing, agreeing_doc, &winner_slot)?;
        let mut out = Vec::new();
        for key in &losing {
            let Some(seat) = round.seat(key) else {
                continue;
            };
            let Some(log) = self.logs.get(&seat.slot) else {
                continue;
            };
            // Evidence before argument: a log that does not hash to what the seat signed
            // is not this seat's log, and the report refuses rather than diffing bytes
            // nobody attested to.
            // Evidence before argument: a log that does not hash to what the seat signed
            // is not this seat's log, and the report refuses rather than diffing bytes
            // nobody attested to.
            let verified = match by_key.get(key).copied() {
                Some(doc) => check_log(log, doc, &seat.slot)?,
                None => "this seat's attestation is not in the store to check its log \
                         against, so its log is shown unverified"
                    .to_string(),
            };
            let raw = diff_text(&agreeing.raw, &log.raw);
            let normalised = diff_text(&agreeing.normalised, &log.normalised);
            let hunks = raw.changes().len();
            let surviving = raw.surviving(self.profile).len();
            out.push(Comparison {
                slot: seat.slot.clone(),
                key_id: key.clone(),
                versus_slot: winner_slot.clone(),
                versus_key: winner_key.clone(),
                verified,
                versus_verified: versus_verified.clone(),
                raw,
                normalised,
                surviving,
                hunks,
            });
        }
        Ok(out)
    }
}

/// Build one seat's row from its seat, its attestation and its roster entry.
fn seat_row(
    seat: &gitiup_quorum::select::Seat,
    doc: Option<&AttestationDoc>,
    entry: Option<&gitiup_quorum::roster::RosterEntry>,
    round: &Round,
    record: &verdict::VerdictRecord,
) -> SeatRow {
    let status = if record.counted.iter().any(|vote| vote.key_id == seat.key_id) {
        "counted"
    } else if record
        .divergent
        .iter()
        .any(|group| group.keys.contains(&seat.key_id))
    {
        "diverging"
    } else if record
        .rejected
        .iter()
        .any(|rejection| rejection.key_id == seat.key_id)
    {
        "rejected"
    } else {
        "silent"
    };
    let refusal = record
        .rejected
        .iter()
        .find(|rejection| rejection.key_id == seat.key_id)
        .map(|rejection| {
            format!(
                "{} (exit {})",
                rejection.code,
                rejection.exit_code.unwrap_or(6)
            )
        });
    let manifest = doc.map(|doc| &doc.manifest);
    SeatRow {
        rank: seat.rank,
        slot: seat.slot.clone(),
        key_id: seat.key_id.clone(),
        identity: entry
            .map(|entry| entry.identity.clone())
            .unwrap_or_else(|| seat.identity.clone()),
        tier: seat.tier.as_str().to_string(),
        sandbox: manifest.and_then(|m| m.result.provenance.sandbox.clone()),
        guarantees: manifest
            .and_then(|m| m.claims.annotations.get("x_sandbox_guarantees").cloned()),
        roster_level: entry.map(|entry| entry.capabilities.sandbox_level),
        required_level: round.inputs.required_capabilities.min_sandbox_level,
        environment: manifest.map(|m| m.result.environment.describe()),
        fingerprint: manifest.map(|m| m.env_fingerprint().clone()),
        result: manifest
            .and_then(|m| m.result_digest().ok())
            .map(|digest| digest.inner().clone()),
        normalisation_version: manifest.map(|m| m.result.provenance.normalisation_version),
        rewrites: manifest.map(|m| m.claims.normalisation_diffs.len()),
        status,
        refusal,
    }
}

/// 8 — the digest is not what it names (ADR-0001 D7), which is what a log that is not the
/// run its seat signed is.
fn mismatch(message: impl Into<String>, hint: impl Into<String>) -> CliError {
    CliError::scored(8, message, Some(hint.into()))
}

/// Check a handed-over log against the attestation its slot names.
///
/// Returns the sentence saying what was checked. A mismatch is a refusal: the log is not
/// the one the seat signed, and a report argued from somebody else's log is an opinion
/// about the wrong build.
fn check_log(log: &ProvidedLog, doc: &AttestationDoc, slot: &str) -> Result<String, CliError> {
    let Some(steps) = &log.steps else {
        // A plain-text log is one stream: it can be checked against a single-stream run,
        // and against nothing else.
        let whole = Digest::sha256(log.raw.as_bytes());
        let wanted: Vec<&Digest> = doc
            .manifest
            .result
            .steps
            .iter()
            .flat_map(|step| [&step.stdout, &step.stderr])
            .collect();
        if wanted.contains(&&whole) {
            return Ok(format!(
                "one plain-text log, and it hashes to a stream this seat signed ({})",
                short_digest(&whole.to_string())
            ));
        }
        return Err(mismatch(
            format!(
                "the log at {} claimed for slot {} is not a run report, and its hash {} is \
                 not one of the stream digests this seat signed",
                log.path,
                short_digest(slot),
                short_digest(&whole.to_string())
            ),
            "name the seat by its slot (`--log <slot>=<path>`) and hand over the run report \
             (`gitiup run --report <path>`) so each step can be checked: a single log file \
             cannot be matched to a run that had several steps",
        ));
    };
    let signed = &doc.manifest.result.steps;
    if steps.len() != signed.len() {
        return Err(mismatch(
            format!(
                "the log handed over for slot {} has {} step(s); this seat attested {}",
                short_digest(slot),
                steps.len(),
                signed.len()
            ),
            "that is not the run this seat attested — the step list is part of what it signed",
        ));
    }
    let mut checked = 0usize;
    for (given, signed) in steps.iter().zip(signed.iter()) {
        let wanted = signed.id.clone().unwrap_or_else(|| signed.name.clone());
        if given.key != wanted {
            return Err(mismatch(
                format!(
                    "step {} is `{}` in the log for slot {} and `{}` in what the seat signed",
                    checked + 1,
                    given.key,
                    short_digest(slot),
                    wanted
                ),
                "the log handed over is a different run; a dispute argued from it would be \
                 an opinion about the wrong build",
            ));
        }
        for (stream, mine, theirs) in [
            ("stdout", &given.stdout, &signed.stdout),
            ("stderr", &given.stderr, &signed.stderr),
        ] {
            if mine != theirs {
                return Err(mismatch(
                    format!(
                        "the log at {} claimed for slot {} is not what this seat signed: \
                         step `{}` {stream} hashes to {} in the log and {} in the \
                         attestation",
                        log.path,
                        short_digest(slot),
                        given.key,
                        short_digest(&mine.to_string()),
                        short_digest(&theirs.to_string())
                    ),
                    "either this is not that run's log, or it was normalised differently \
                     (check the run's `normalisation_version`, and `--rules`); the report \
                     refuses rather than diffing bytes nobody signed",
                ));
            }
            checked += 1;
        }
    }
    Ok(format!(
        "this is the run this seat signed: {checked} stream(s) recomputed and matching, \
         normalisation v{}",
        doc.manifest.result.provenance.normalisation_version
    ))
}

/// The whole report.
struct Report<'a> {
    store: String,
    handle: String,
    change: String,
    trusted_by: String,
    evaluation: &'a Evaluation,
    profile: &'a Profile,
    layout: Layout,
    provided: usize,
    rounds: Vec<RoundReport>,
    notes: Vec<String>,
}

impl Report<'_> {
    /// The worst code across the rounds, using the verdict's own precedence.
    fn code(&self) -> u8 {
        self.rounds
            .iter()
            .map(|round| verdict_cli::code_of(&round.verdict))
            .fold(0, verdict_cli::worst)
    }

    fn json(&self) -> Value {
        json!({
            "kind": "dispute",
            "change": self.change,
            "handle": self.handle,
            "store": self.store,
            "trusted": self.trusted_by,
            "now": self.evaluation.now.to_rfc3339(),
            "allowed_tiers": self
                .evaluation
                .allowed_tiers
                .iter()
                .map(|tier| tier.as_str())
                .collect::<Vec<_>>(),
            "normalisation_profile": format!("{} v{}", self.profile.name(), self.profile.version()),
            "logs_provided": self.provided,
            "exit": u64::from(self.code()),
            "jobs": self
                .rounds
                .iter()
                .map(|round| round.json(self.profile))
                .collect::<Vec<Value>>(),
            "notes": self.notes,
        })
    }

    fn print(&self) {
        println!(
            "dispute report \u{b7} change {}{} \u{b7} read from {} \u{b7} trusted: {}",
            self.change,
            if self.handle == self.change {
                String::new()
            } else {
                format!(" (named {})", self.handle)
            },
            self.store,
            self.trusted_by,
        );
        println!(
            "  clock {} \u{b7} tiers {} \u{b7} normalisation {} v{} \u{b7} {} log(s) provided",
            self.evaluation.now.to_rfc3339(),
            self.evaluation
                .allowed_tiers
                .iter()
                .map(|tier| tier.as_str())
                .collect::<Vec<_>>()
                .join("/"),
            self.profile.name(),
            self.profile.version(),
            self.provided,
        );
        for round in &self.rounds {
            println!();
            round.print(&self.layout, self.profile);
        }
        println!();
        println!("  exit {}", self.code());
        for note in &self.notes {
            println!("  note: {note}");
        }
    }

    /// The report is on stdout and the code is the answer; stderr stays empty.
    fn exit(self) -> Result<(), CliError> {
        let code = self.code();
        if code == 0 {
            return Ok(());
        }
        Err(CliError::verdict(code))
    }
}

/// A digest, shortened for a terminal. Display only, never a record.
fn short_digest(digest: &str) -> String {
    let body = digest.strip_prefix("sha256:").unwrap_or(digest);
    if body.len() <= 12 {
        return digest.to_string();
    }
    format!("sha256:{}\u{2026}{}", &body[..4], &body[body.len() - 4..])
}

/// A detail that may have been written across ten lines by an error message.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::GitOid;

    #[test]
    fn every_flag_the_command_accepts_is_in_the_help() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                DISPUTE_HELP.contains(flag),
                "{flag} is accepted but not documented"
            );
        }
    }

    #[test]
    fn a_digest_is_shortened_for_a_terminal_only() {
        assert_eq!(short_digest("sha256:short"), "sha256:short");
        assert_eq!(
            short_digest(&format!("sha256:{}", "a".repeat(64))),
            "sha256:aaaa\u{2026}aaaa"
        );
    }

    #[test]
    fn a_detail_is_one_line() {
        assert_eq!(one_line("a \n b   c"), "a b c");
    }

    /// A run report with one step, for the parser tests below.
    fn report(step: &str, text: &str) -> RunReport {
        RunReport {
            repo: None,
            commit: GitOid::from_sha1_hex(&"0".repeat(40)).expect("a fixture commit"),
            workflow: gitiup_attest::run::WorkflowSource::from_text("ci.yml", "on: push\n"),
            event: gitiup_attest::run::EventReport {
                name: "pull_request".into(),
                action: None,
                payload: Material::text("{}"),
            },
            job: None,
            matrix: Default::default(),
            inputs: Default::default(),
            secret_names: vec![],
            pins: Default::default(),
            reusable_workflows: vec![],
            environment: gitiup_attest::run::EnvironmentReport {
                provider: None,
                os: None,
                os_version: None,
                arch: "x86_64".into(),
                image: None,
                toolchain: vec![],
            },
            steps: vec![gitiup_attest::run::StepReport {
                stdout: Material::text(text),
                ..gitiup_attest::run::StepReport::run(step, 0)
            }],
            provenance: gitiup_attest::manifest::Provenance {
                tier: gitiup_attest::Tier::Local,
                runner: "gitiup 0.1.0".into(),
                normalisation_version: gitiup_attest::run::RAW_NORMALISATION_VERSION,
                sandbox: Some("docker".into()),
            },
            claims: gitiup_attest::run::ClaimReport {
                run_id: "000000000000beef".into(),
                claimed_at_us: 1,
                not_before_us: None,
                not_after_us: None,
                verifier_challenge: None,
                timings: vec![],
                normalisation_diffs: vec![],
                annotations: Default::default(),
            },
        }
    }

    #[test]
    fn a_run_report_is_flattened_to_text_and_step_digests() {
        let bytes = serde_json::to_vec(&report("test", "hello\n")).unwrap();
        let log = parse_log("seat.json", &bytes).expect("a run report parses");
        assert!(log.steps.is_some());
        assert!(log.raw.contains("hello"));
        assert!(log.path == "seat.json");
    }

    #[test]
    fn a_plain_file_is_one_stream_with_no_step_structure() {
        let log = parse_log("seat.log", b"just a log\n").expect("plain text parses");
        assert!(log.steps.is_none());
        assert_eq!(log.raw, "just a log\n");
    }

    #[test]
    fn a_stream_that_is_only_a_digest_cannot_be_diffed_and_says_so() {
        let mut report = report("test", "hello\n");
        report.steps[0].stdout = Material::Digest(Digest::sha256(b"hello\n"));
        let error = described_from_report("seat.json", &report).unwrap_err();
        assert_eq!(error.code, 6);
        assert!(error.message.contains("digest only"));
    }
}

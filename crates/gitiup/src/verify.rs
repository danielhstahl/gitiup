//! `gitiup verify attestation` — the verdict, in one exit code and one report.
//!
//! This is the primitive a merge gate, a `pre-receive` hook and a shell script all
//! call, and the reason the whole format exists: an attestation is a claim, and
//! `verify` is the moment somebody decides whether to act on it.
//!
//! ```text
//! gitiup verify attestation [DOC|-] [OPTIONS]     # a document on disk or on a pipe
//! gitiup verify attestation --store ./store --commit $(git rev-parse HEAD)
//! ```
//!
//! # What is checked, and in which order
//!
//! The checks are
//! [`AttestationDoc::verify_report`](gitiup_attest::AttestationDoc::verify_report)'s
//! — they are not re-implemented here, because a CLI with its own idea of "close
//! enough" is a CLI that quietly moved the goalposts — and they run in the order
//! [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
//! fixes:
//!
//! | check | what it establishes |
//! |-------|---------------------|
//! | `structure` | the bytes are a document this build speaks: canonical form, known schema, no unknown fields |
//! | `digest` | the manifest re-hashes to the digest it claims, and the algorithm is allowed |
//! | `commit` / `result` / `challenge` | it is about the commit, the result and the round you asked about |
//! | `normalisation` | the producer's normalisation rules are the version the change requires |
//! | `environment` | the run happened on a machine the change accepts (giti-1rs.4) |
//! | `signature` | each signature verifies against the key offered, and its key id is that key's fingerprint |
//! | `trust` | every signer is one the policy trusts |
//! | `min_signatures` | enough distinct trusted signers signed it |
//! | `tier` / `sandbox` | the provenance is a tier, in a sandbox, this policy accepts (giti-1rs.7) |
//! | `freshness` / `expiry` | the claimed time is inside the window, and inside the document's own |
//!
//! The **first** failure decides the exit code. The rest are printed alongside it,
//! because a log that says "refused" and nothing else is a log nobody can act on.
//!
//! # Exit codes
//!
//! | exit | meaning |
//! |------|---------|
//! | 0 | accepted |
//! | 2 | usage: unknown flag, no document named |
//! | 3 | I/O: the file could not be read, the store could not be reached |
//! | 6 | refused: untrusted signer, too few signatures, disallowed tier or sandbox, stale or future-dated, wrong machine class, unreadable document |
//! | 7 | a signature does not verify, or a key id is not its key's fingerprint |
//! | 8 | digest mismatch: not the canonical bytes, not the manifest it claims, wrong commit, or a store that returned bytes other than the ones it names |
//!
//! 2 and 3 are not verdicts: nothing was decided, so a message goes to stderr and
//! no report is printed. 0, 6, 7 and 8 are verdicts, and a verdict is not an error
//! — the report goes to stdout (with `--json`, the JSON on stdout and nothing else)
//! and the verdict is in the exit code. That is what makes it drop into a hook:
//!
//! ```sh
//! gitiup verify attestation proof.json --policy gitiup-policy.json --json || exit 1
//! ```
//!
//! # Who is trusted
//!
//! In order of precedence: `--trust` (a `SHA256:` fingerprint or a name in this
//! machine's keystore, repeatable), then the `trust_key_ids` of `--policy` /
//! `$GITIUP_POLICY`, then this machine's own keystore — the same local-trust rule
//! `gitiup identity verify` and `gitiup participant` use, and named in every
//! output, because a proof accepted because of a keyring nobody mentioned is a
//! proof accepted by accident. `--trust-any-key` checks the mechanics and nothing
//! else, and says so in the output; it is for diagnosis, never for a gate.

use std::collections::BTreeSet;

use gitiup_attest::{
    AttestationDoc, CheckOutcome, Digest, Error as AttestError, ErrorKind, GitOid, OidAlgorithm,
    POLICY_PATH_ENV, Policy, PolicyFile, Reason, ResultDigest, Tier, TimeUs, Trust, VerdictReport,
    human_duration_us,
};
use gitiup_host::Oid;
use gitiup_host::attest::{self, Entry};
use gitiup_host::{HostError, HostErrorKind};
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::env::resolve_requirement;
use crate::keys::Args;
use crate::participant::{self, Opened};

/// Help for `gitiup verify`.
pub const VERIFY_HELP: &str = "\
gitiup verify — is this attestation good enough to act on?

USAGE:
    gitiup verify attestation [DOC|-] [OPTIONS]
    gitiup verify change      <ID> [OPTIONS]   (the merge gate over a whole change)

`verify attestation` answers a question about one document. `verify change` answers the
merge question about a change: every attestation the store advertises for its head, plus
the quorum verdict, judged by the policy that was in force when each run happened. Same
exit taxonomy, same report shape, one document per decision — `gitiup verify change help`
lists its flags.

DOC is an attestation document in canonical form — the bytes `gitiup attest push`
stored — or - for stdin. A document that is merely valid JSON is refused: a
signature is over the exact canonical bytes, so a transport that re-serialised the
file has already broken it (exit 8).

WHERE THE DOCUMENT COMES FROM:
    DOC | -                      a file, or a pipe
    --store <dir>                read it from a host instead
    --remote <name>              …or from a remote in gitiup.toml
    --digest <hex>               which attestation, with --store/--remote
    --commit <oid>               the attestation for that commit (sha1:<hex>,
                                 sha256:<hex> or bare hex). It is also the commit
                                 binding: a proof about another commit is refused.
                                 A commit with several attestations names them and
                                 asks which one you meant
    --expect-result <digest>     refuse unless the ResultDigest is exactly this
    --expect-challenge <digest>  refuse unless this quorum challenge is the one named

WHO TO TRUST:
    --trust <key>                repeatable: a SHA256:… key id or a keystore name
    --policy <path>              gitiup-policy.json: tiers, trust_key_ids, freshness,
                                 environment requirement (default: $GITIUP_POLICY)
    --trust-any-key              any key whose signature verifies. Diagnosis only: it
                                 answers \"is this self-consistent?\", never \"may I
                                 merge?\", and says so in the output
    --min-signatures <n>         distinct trusted signers required (default: the policy's)

WHAT THE POLICY MUST ACCEPT:
    --tier <tier>                repeatable: provenance tiers to allow (default: local)
    --allow-simulated            shorthand for adding `simulated`
    --sandbox <name>             repeatable: sandbox backends a `local` run may name
    --max-age <age>              freshness window: 90s, 24h, 30d, 2w, `never`
    --max-skew <age>             how far a claimed time may run ahead of now
    --normalisation-version <n>  require the producer's normalisation rules
    --require <field=value>      repeatable environment requirement, e.g.
                                 --require arch=amd64 --require 'toolchain:rustc=1.99'
    --require-env-match <m>      strict | major | off (default: strict, or the policy's)
    --now <time>                 pin the clock: RFC 3339 UTC or integer microseconds.
                                 For replaying an old decision, not for cheating freshness

OUTPUT:
    -j, --json                   one line, keys sorted: the verdict, every check with
                                 its outcome, every reason, and what it was checked
                                 against
    -q, --quiet                  one word: `ok`, or the code that decided the verdict
    -h, --help                   this text

Checks run in a fixed order (ADR-0001 D7) and the first failure decides the exit
code; every other failure is reported too, so one run tells you everything wrong.

Exit codes: 0 accepted · 2 usage · 3 I/O, store unreachable · 6 refused (untrusted
signer, too few signatures, tier or sandbox not allowed, stale or future-dated,
wrong machine class, unreadable document) · 7 a signature that does not verify ·
8 digest mismatch (non-canonical bytes, a manifest that does not hash to its own
digest, wrong commit, a store that returned bytes other than the ones it names).

Try:
    gitiup verify attestation proof.json --policy gitiup-policy.json
    gitiup verify attestation --store ./store --commit $(git rev-parse HEAD) --json
    gitiup verify attestation proof.json --trust ada --tier local --max-age 24h -q
";

/// Valued flags `gitiup verify attestation` accepts.
const VALUED: &[&str] = &[
    "--policy",
    "--trust",
    "--min-signatures",
    "--tier",
    "--sandbox",
    "--max-age",
    "--max-skew",
    "--normalisation-version",
    "--expect-result",
    "--expect-challenge",
    "--commit",
    "--digest",
    "--store",
    "--remote",
    "--require",
    "--require-env-match",
    "--now",
];

/// Switches `gitiup verify attestation` accepts.
const SWITCHES: &[&str] = &["--trust-any-key", "--allow-simulated", "-q", "--quiet"];

/// `gitiup verify …`
pub fn verify(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{VERIFY_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{VERIFY_HELP}");
            Ok(())
        }
        "attestation" | "attest" | "doc" => attestation(&args[1..]),
        "change" => crate::verify_change::change(&args[1..]),
        other => Err(CliError::usage(format!(
            "unknown `gitiup verify` command '{other}'; `gitiup verify help` lists attestation and change"
        ))),
    }
}

// ---------------------------------------------------------------------------
// the policy the flags describe
// ---------------------------------------------------------------------------

/// The policy, plus the things a verdict has to say about itself.
///
/// A verdict is only interpretable next to the question it answered: "accepted"
/// under a policy that trusted every key on the box is not the same fact as
/// "accepted" against the owner's list — so how the trust list was decided is part
/// of the output, not an implementation detail.
struct PolicySpec {
    policy: Policy,
    /// Where the policy file came from, if one did.
    file: Option<String>,
    /// How the trust list was decided, in the words the output prints.
    trust_source: String,
    /// The trusted key ids, unless any key was accepted (then empty, and
    /// [`PolicySpec::any_key`] says why).
    trusted: Vec<String>,
    /// True when nothing about the signer's identity was trusted.
    any_key: bool,
    /// Flags that narrowed the policy beyond the file, so a re-read says which.
    notes: Vec<String>,
}

impl PolicySpec {
    fn json(&self) -> Value {
        let policy = &self.policy;
        let mut out = Map::new();
        insert(&mut out, "file", self.file.clone().map(Value::String));
        insert(
            &mut out,
            "trust",
            Some(Value::String(self.trust_source.clone())),
        );
        out.insert(
            "trusted_key_ids".into(),
            Value::Array(
                self.trusted
                    .iter()
                    .map(|id| Value::String(id.clone()))
                    .collect(),
            ),
        );
        out.insert(
            "tiers".into(),
            Value::Array(
                policy
                    .allowed_tiers
                    .iter()
                    .map(|tier| Value::String(tier.as_str().to_string()))
                    .collect(),
            ),
        );
        out.insert(
            "sandboxes".into(),
            Value::Array(
                policy
                    .allowed_sandboxes
                    .iter()
                    .map(|name| Value::String(name.clone()))
                    .collect(),
            ),
        );
        out.insert(
            "min_signatures".into(),
            Value::from(policy.min_signatures as u64),
        );
        insert(
            &mut out,
            "max_age",
            Some(Value::String(human_age(policy.max_age_us))),
        );
        out.insert("max_age_us".into(), Value::from(policy.max_age_us));
        out.insert(
            "max_clock_skew_us".into(),
            Value::from(policy.max_clock_skew_us),
        );
        insert(
            &mut out,
            "normalisation_version",
            policy
                .normalisation_version
                .map(|version| Value::from(version as u64)),
        );
        insert(
            &mut out,
            "expected_commit",
            policy
                .expected_commit
                .as_ref()
                .map(|commit| Value::String(commit.to_string())),
        );
        insert(
            &mut out,
            "expected_result_digest",
            policy
                .expected_result_digest
                .as_ref()
                .map(|digest| Value::String(digest.to_string())),
        );
        insert(
            &mut out,
            "expected_challenge",
            policy
                .expected_challenge
                .as_ref()
                .map(|digest| Value::String(digest.to_string())),
        );
        insert(
            &mut out,
            "require_env_match",
            Some(Value::String(policy.require_env_match.as_str().to_string())),
        );
        insert(
            &mut out,
            "environment_requirement",
            policy
                .environment_requirement()
                .map(|requirement| Value::String(requirement.describe())),
        );
        insert(
            &mut out,
            "now",
            Some(Value::String(policy.now().to_rfc3339())),
        );
        if !self.notes.is_empty() {
            out.insert(
                "notes".into(),
                Value::Array(
                    self.notes
                        .iter()
                        .map(|note| Value::String(note.clone()))
                        .collect(),
                ),
            );
        }
        Value::Object(out)
    }

    /// The one-line summary the table prints under the document's own facts.
    fn summary(&self) -> String {
        let policy = &self.policy;
        let mut parts = vec![
            format!("trust: {}", self.trust_source),
            format!(
                "tiers {}",
                policy
                    .allowed_tiers
                    .iter()
                    .map(|tier| tier.as_str())
                    .collect::<Vec<_>>()
                    .join("+")
            ),
            format!("min {} signature(s)", policy.min_signatures),
            format!("max age {}", human_age(policy.max_age_us)),
        ];
        parts.push(match policy.environment_requirement() {
            Some(requirement) => {
                format!("env {requirement} ({})", policy.require_env_match.as_str())
            }
            None => "env nothing required".to_string(),
        });
        parts.join(" · ")
    }
}

/// Insert into a JSON map only when there is something to say.
pub(crate) fn insert(out: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        out.insert(key.to_string(), value);
    }
}

/// Where the policy file is, if the flags or the environment name one.
fn policy_path(args: &Args) -> Option<String> {
    if let Some(path) = args.get("--policy") {
        return Some(path.to_string());
    }
    std::env::var(POLICY_PATH_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
}

/// Build the policy: the file first, then every flag, then the trust fallback.
fn policy_spec(args: &Args) -> Result<PolicySpec, CliError> {
    let file = policy_path(args);
    let mut policy = match &file {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| CliError::io(format!("{path}: {e}")))?;
            PolicyFile::policy_from_json(&text)?
        }
        None => Policy::default(),
    };
    // What the file said about trust, remembered before the flags get a turn.
    let trusted_by_file: Option<Vec<String>> = match &policy.trust {
        Trust::KeyIds(ids) if !ids.is_empty() => Some(ids.iter().cloned().collect()),
        _ => None,
    };
    let mut notes: Vec<String> = Vec::new();

    if let Some(tiers) = nonempty(&args.all("--tier")) {
        policy.allowed_tiers = tiers
            .iter()
            .map(|tier| Tier::parse(tier))
            .collect::<Result<Vec<_>, _>>()?;
        notes.push(format!("--tier {}", tiers.join(",")));
    }
    if args.on("--allow-simulated") {
        if !policy.allowed_tiers.contains(&Tier::Simulated) {
            policy.allowed_tiers.push(Tier::Simulated);
        }
        notes.push("--allow-simulated".to_string());
    }
    if let Some(sandboxes) = nonempty(&args.all("--sandbox")) {
        policy.allowed_sandboxes = sandboxes;
    }
    if let Some(text) = args.get("--min-signatures") {
        let min: usize = text
            .parse()
            .map_err(|_| CliError::usage(format!("--min-signatures '{text}' is not a count")))?;
        if min == 0 {
            return Err(CliError::refused(
                "--min-signatures 0 would accept an unsigned attestation",
                "the smallest sane value is 1",
            ));
        }
        policy.min_signatures = min;
    }
    if let Some(text) = args.get("--max-age") {
        policy.max_age_us = window(text, "--max-age")?.unwrap_or(i64::MAX);
        notes.push(format!("--max-age {text}"));
    }
    if let Some(text) = args.get("--max-skew") {
        policy.max_clock_skew_us = window(text, "--max-skew")?.unwrap_or(0);
    }
    if let Some(text) = args.get("--normalisation-version") {
        policy.normalisation_version = Some(text.parse().map_err(|_| {
            CliError::usage(format!(
                "--normalisation-version '{text}' is not a version number"
            ))
        })?);
    }
    if let Some(text) = args.get("--expect-result") {
        let digest: Digest = text.parse()?;
        policy.expected_result_digest = Some(ResultDigest(digest));
    }
    if let Some(text) = args.get("--expect-challenge") {
        policy.expected_challenge = Some(text.parse()?);
    }
    if let Some(text) = args.get("--commit") {
        policy.expected_commit = Some(commit_id(text)?);
    }
    if let Some(text) = args.get("--now") {
        policy.now = Some(TimeUs::parse(text)?);
        notes.push(format!("--now {text} (the clock was pinned)"));
    }

    // The machine-class requirement, through the same resolver `gitiup env` and
    // `gitiup digest` use, so one spelling of "the change wants amd64" means one
    // thing everywhere it is written.
    if let Some((requirement, mode)) = resolve_requirement(
        file.as_deref(),
        &args.all("--require"),
        args.get("--require-env-match"),
    )? {
        policy.require_environment = Some(requirement);
        policy.require_env_match = mode;
    }

    let (trust, trust_source, trusted, any_key) = resolve_trust(args, trusted_by_file, &file)?;
    policy.trust = trust;

    Ok(PolicySpec {
        policy,
        file,
        trust_source,
        trusted,
        any_key,
        notes,
    })
}

/// Whose signature counts, and in whose words that gets reported.
fn resolve_trust(
    args: &Args,
    from_file: Option<Vec<String>>,
    file: &Option<String>,
) -> Result<(Trust, String, Vec<String>, bool), CliError> {
    let named = args.all("--trust");
    if !named.is_empty() && args.on("--trust-any-key") {
        return Err(CliError::usage(
            "--trust and --trust-any-key answer different questions; say the one you mean",
        ));
    }
    if !named.is_empty() {
        let here = participant::keystore()?;
        let mut ids = BTreeSet::new();
        for value in &named {
            ids.insert(participant::key_id_of(&here, value)?);
        }
        let ids: Vec<String> = ids.into_iter().collect();
        return Ok((
            Trust::KeyIds(ids.iter().cloned().collect()),
            format!("--trust, {} key(s)", ids.len()),
            ids,
            false,
        ));
    }
    if args.on("--trust-any-key") {
        return Ok((
            Trust::AnyKeyForTests,
            "--trust-any-key: ANY key whose signature verifies, which is not a decision \
             to trust anyone"
                .to_string(),
            Vec::new(),
            true,
        ));
    }
    if let Some(ids) = from_file {
        let source = match file {
            Some(path) => format!("{path}, {} key(s)", ids.len()),
            None => format!("{} key(s)", ids.len()),
        };
        return Ok((
            Trust::KeyIds(ids.iter().cloned().collect()),
            source,
            ids,
            false,
        ));
    }
    // Nothing was named: fall back to this machine's own keys, and say so in every
    // output. A box that keeps the owner's keys is a box whose owner vouches for
    // what they sign — but a verdict resting on a keystore nobody mentioned has to
    // admit it out loud.
    let here = participant::keystore()?;
    let ids: Vec<String> = here
        .keys
        .list()?
        .iter()
        .map(|record| record.key_id.clone())
        .collect();
    if ids.is_empty() {
        return Err(CliError::refused(
            "nothing is trusted here: no --trust, no trust_key_ids in a policy, and no \
             key in the keystore",
            "`gitiup verify attestation doc --trust <key-id>` names one, or write them \
             into gitiup-policy.json",
        ));
    }
    Ok((
        Trust::KeyIds(ids.iter().cloned().collect()),
        format!("this machine's keystore, {} key(s)", ids.len()),
        ids,
        false,
    ))
}

/// A duration flag: `90s`, `24h`, `30d`, `2w`, `never`.
fn window(text: &str, flag: &str) -> Result<Option<i64>, CliError> {
    attest::parse_age(text).map_err(|e| CliError::usage(format!("{flag}: {e}")))
}

/// Flags that were given with a real value, or `None` when all of them were blank.
fn nonempty(values: &[String]) -> Option<Vec<String>> {
    let values: Vec<String> = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect();
    (!values.is_empty()).then_some(values)
}

/// A commit id in whichever spelling the caller has: `sha1:<hex>`, `sha256:<hex>`,
/// or bare hex whose length says the algorithm.
pub(crate) fn commit_id(text: &str) -> Result<GitOid, CliError> {
    let text = text.trim();
    if text.contains(':') {
        return Ok(text.to_ascii_lowercase().parse::<GitOid>()?);
    }
    let hex = text.to_ascii_lowercase();
    match hex.len() {
        40 => Ok(GitOid::from_sha1_hex(&hex)?),
        64 => {
            let digest: Digest = format!("sha256:{hex}").parse()?;
            Ok(GitOid::new(OidAlgorithm::Sha256, digest.as_bytes())?)
        }
        _ => Err(CliError::usage(format!(
            "'{text}' is not a commit id: write sha1:<hex>, sha256:<hex>, or bare hex"
        ))),
    }
}

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

/// What was read, and from where.
///
/// `doc` and `failure` are alternatives: bytes that are not a document produce a
/// reason (and so an exit code) rather than a panic, because "I cannot read this"
/// is a verdict a script can branch on and a line on stderr is not.
struct Input {
    doc: Option<AttestationDoc>,
    source: String,
    /// The store's name for the record, when it came from a store.
    stored: Option<String>,
    failure: Option<(&'static str, AttestError)>,
}

impl Input {
    fn refused(
        code: &'static str,
        error: AttestError,
        source: String,
        stored: Option<String>,
    ) -> Input {
        Input {
            doc: None,
            source,
            stored,
            failure: Some((code, error)),
        }
    }

    fn read_or_refuse(
        bytes: &[u8],
        source: String,
        stored: Option<String>,
    ) -> Result<Input, CliError> {
        match AttestationDoc::from_canonical_bytes(bytes) {
            Ok(doc) => Ok(Input {
                doc: Some(doc),
                source,
                stored,
                failure: None,
            }),
            Err(error) => Ok(Input::refused("structure", error, source, stored)),
        }
    }
}

/// Read the document from wherever the flags point.
///
/// The order is deliberate, because the common case is a merge gate: a repository
/// that has a `gitiup.toml` (so a default remote exists, so `store_from` answers
/// `Some` for anyone) and a document handed over on the command line.
///
/// * a store named explicitly with `--store`/`--remote` wins: the caller said where;
/// * otherwise a positional document (a path, or `-` for stdin) is read: this is
///   `gitiup verify attestation proof.json`, run in a working copy, and the default
///   remote has nothing to do with the question;
/// * otherwise fall back to the configured remote, which is how a hook verifies "the
///   attestation this commit has" without being told its digest twice.
///
/// Reading a file the caller named and then verifying something fetched from a remote
/// instead is the kind of helpfulness that gates the wrong commit.
fn read(args: &Args) -> Result<Input, CliError> {
    let named_store = args.get("--store").is_some() || args.get("--remote").is_some();
    if !named_store && !args.positional.is_empty() {
        return from_file(args);
    }
    match participant::store_from(args)? {
        Some(store) => from_store(args, &store),
        None => from_file(args),
    }
}

/// A file, or stdin.
fn from_file(args: &Args) -> Result<Input, CliError> {
    let path = match args.positional.first() {
        Some(path) => path.clone(),
        None => {
            return Err(CliError::usage(
                "say what to verify: a document (a path, or - for stdin), or --store \
                 with --digest/--commit",
            ));
        }
    };
    let bytes = participant::read_maybe_stdin(&path)?;
    if path == "-" && bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(CliError::usage(
            "no attestation on stdin (give a path, or pipe one in)",
        ));
    }
    let source = if path == "-" {
        "stdin".to_string()
    } else {
        format!("file {path}")
    };
    Input::read_or_refuse(&bytes, source, None)
}

/// From a host: by digest, or the single attestation a commit has.
fn from_store(args: &Args, store: &Opened) -> Result<Input, CliError> {
    let wanted = args
        .get("--digest")
        .map(|text| {
            Oid::from_hex(text.trim().trim_start_matches("sha256:"))
                .map_err(|e| CliError::usage(format!("--digest '{text}': {e}")))
        })
        .transpose()?;
    let commit = args.get("--commit").map(commit_id).transpose()?;
    let digest = match (wanted, &commit) {
        (Some(digest), _) => digest,
        (None, Some(commit)) => {
            let catalog = attest::list_for(&*store.host, &store_oid(commit)?)
                .map_err(|e| CliError::io(format!("list attestations: {e}")))?;
            match catalog.entries.as_slice() {
                [] => {
                    return Ok(Input::refused(
                        "commit",
                        AttestError::new(
                            ErrorKind::Policy,
                            "store",
                            format!("{} has no attestation in {}", commit, store.what),
                        )
                        .with_hint("`gitiup attest list --all` shows what the store holds"),
                        store.what.clone(),
                        None,
                    ));
                }
                // One attestation is an answer; two are a question. `show` may print
                // the newest, because printing is harmless; verifying one and silently
                // ignoring the other would decide a merge on half the evidence.
                [only] => only.digest,
                many => {
                    return Err(CliError::refused(
                        format!(
                            "{} has {} attestations in {}; name one",
                            commit,
                            many.len(),
                            store.what
                        ),
                        format!(
                            "--digest <hex>, one of {}",
                            many.iter()
                                .map(|entry| short(&entry.digest.hex()))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
        (None, None) => {
            return Err(CliError::usage(
                "a store was named, so say which attestation: --digest <hex>, or --commit \
                 <oid> when that commit has exactly one",
            ));
        }
    };
    let entry: Option<Entry> = attest::list_all(&*store.host)
        .map_err(|e| CliError::io(format!("list attestations: {e}")))?
        .entries
        .into_iter()
        .find(|found| found.digest == digest);
    let source = format!("{} · kv/attestation/{}", store.what, digest);
    // Reading the bytes can fail three ways, and a merge gate needs to tell them
    // apart: the store did not answer (3, nothing was decided), it advertised bytes
    // it cannot produce (8), or it refused to hand over bytes that do not re-hash
    // to their own name (8 — corruption is a digest mismatch, not an I/O nuisance).
    let bytes = match attest::fetch(&*store.host, &digest) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Ok(Input::refused(
                "stored",
                AttestError::new(
                    ErrorKind::DigestMismatch,
                    "store",
                    format!(
                        "{} is advertised in {} but the store cannot return its bytes",
                        short(&digest.hex()),
                        store.what
                    ),
                )
                .with_hint("a ref naming a missing object is a broken store, not a missing proof"),
                source,
                Some(digest.hex()),
            ));
        }
        Err(error) if corrupt(&error) => {
            return Ok(Input::refused(
                "stored",
                AttestError::new(
                    ErrorKind::DigestMismatch,
                    "store",
                    format!(
                        "{} would not return {} as stored: {error}",
                        store.what,
                        short(&digest.hex())
                    ),
                )
                .with_hint(
                    "the bytes filed under a digest must hash to it; anything built on this \
                     proof is built on nothing",
                ),
                source,
                Some(digest.hex()),
            ));
        }
        Err(error) => return Err(CliError::io(format!("fetch {}: {error}", digest.hex()))),
    };

    if let Some(entry) = &entry {
        // The ref is part of the evidence: a digest filed under a commit it was
        // never advertised for is a different claim from the one asked about.
        if let Some(commit) = &commit {
            let advertised = store_oid(commit)?;
            if entry.subject != advertised {
                return Ok(Input::refused(
                    "commit",
                    AttestError::new(
                        ErrorKind::DigestMismatch,
                        "store",
                        format!(
                            "{} is advertised for {}, not for {}",
                            short(&digest.hex()),
                            entry.subject.short_default(),
                            commit
                        ),
                    )
                    .with_hint(
                        "the ref namespace and the manifest's commit disagree; check \
                                 which commit was proved",
                    ),
                    source,
                    Some(digest.hex()),
                ));
            }
        }
    }
    // The store's honesty is part of the verdict: bytes that do not hash to the
    // name they are filed under mean nothing downstream can be trusted, so that
    // refusal outranks whatever the document inside them would have scored.
    if Oid::hash_bytes(&bytes) != digest {
        let hashed = Oid::hash_bytes(&bytes);
        let error = AttestError::new(
            ErrorKind::DigestMismatch,
            "store",
            format!(
                "the bytes returned for {} hash to {}, not to the name they are filed under",
                short(&digest.hex()),
                short(&hashed.hex())
            ),
        )
        .with_hint("this host is not storing blobs verbatim");
        let doc = AttestationDoc::from_canonical_bytes(&bytes).ok();
        let mut input = Input::refused("stored", error, source, Some(digest.hex()));
        input.doc = doc;
        return Ok(input);
    }
    Input::read_or_refuse(&bytes, source, Some(digest.hex()))
}

/// A manifest commit is a store object id: the same bytes, minus the prefix.
pub(crate) fn store_oid(commit: &GitOid) -> Result<Oid, CliError> {
    Oid::from_hex(&commit.hex()).map_err(|e| CliError::io(format!("commit is not an oid: {e}")))
}

/// Did the store fail because what it holds is not what its name says?
///
/// `Storage` and `Invalid` are the kinds a host uses for "I found it and it is
/// wrong" — the fs and bucket hosts both say so when a blob does not re-hash to
/// its content address. Everything else (unreachable, refused, no such scheme) is
/// the store not answering, which is I/O and no verdict.
pub(crate) fn corrupt(error: &HostError) -> bool {
    matches!(
        error.kind(),
        HostErrorKind::Storage | HostErrorKind::Invalid
    )
}

// ---------------------------------------------------------------------------
// the facts, printed next to the verdict
// ---------------------------------------------------------------------------

/// What the document says, independent of whether it was accepted.
///
/// A refusal is exactly when a human needs these: the point of printing the tier,
/// the signers and the age of a *rejected* attestation is that the reader can see
/// what they are holding.
///
/// `pub(crate)` because `gitiup verify change` prints one section per attestation and
/// must print *this* one: two renderings of "what the document says" is two chances
/// for them to disagree about what a tier or a signer looks like.
pub(crate) struct Facts {
    run_digest: Option<String>,
    result_digest: Option<String>,
    record: Option<String>,
    commit: String,
    workflow: String,
    event: String,
    job: Option<String>,
    tier: String,
    runner: String,
    sandbox: Option<String>,
    normalisation_version: u32,
    environment: String,
    fingerprint: String,
    signers: Vec<(String, String)>,
    claimed_at_us: i64,
    not_after_us: Option<i64>,
    steps: usize,
    warning: Option<String>,
}

impl Facts {
    /// The `ResultDigest` as the string the report prints, when the document has one.
    pub(crate) fn result_digest(&self) -> Option<&str> {
        self.result_digest.as_deref()
    }

    /// The job this attestation is about, as the document spells it.
    pub(crate) fn job(&self) -> Option<&str> {
        self.job.as_deref()
    }

    pub(crate) fn of(doc: &AttestationDoc) -> Facts {
        let manifest = &doc.manifest;
        Facts {
            run_digest: doc.run_digest().ok().map(|digest| digest.to_string()),
            result_digest: doc.result_digest().ok().map(|digest| digest.to_string()),
            record: doc.record_digest().ok().map(|digest| digest.to_string()),
            commit: manifest.result.source.commit.to_string(),
            workflow: manifest.result.source.workflow.path.clone(),
            event: manifest.result.source.event.name.clone(),
            job: manifest.result.source.job.clone(),
            tier: manifest.result.provenance.tier.as_str().to_string(),
            runner: manifest.result.provenance.runner.clone(),
            sandbox: manifest.result.provenance.sandbox.clone(),
            normalisation_version: manifest.result.provenance.normalisation_version,
            environment: manifest.result.environment.describe(),
            fingerprint: manifest.result.environment.fingerprint.to_string(),
            signers: doc
                .signatures
                .iter()
                .map(|entry| (entry.key_id.clone(), entry.algorithm.as_str().to_string()))
                .collect(),
            claimed_at_us: manifest.claims.claimed_at_us,
            not_after_us: manifest.claims.not_after_us,
            steps: manifest.result.steps.len(),
            warning: manifest
                .result
                .provenance
                .tier
                .trust_warning()
                .map(str::to_string),
        }
    }

    pub(crate) fn json(&self) -> Value {
        let mut out = Map::new();
        insert(
            &mut out,
            "run_digest",
            self.run_digest.clone().map(Value::String),
        );
        insert(
            &mut out,
            "result_digest",
            self.result_digest.clone().map(Value::String),
        );
        insert(
            &mut out,
            "record_digest",
            self.record.clone().map(Value::String),
        );
        insert(&mut out, "commit", Some(Value::String(self.commit.clone())));
        insert(
            &mut out,
            "workflow",
            Some(Value::String(self.workflow.clone())),
        );
        insert(&mut out, "event", Some(Value::String(self.event.clone())));
        insert(&mut out, "job", self.job.clone().map(Value::String));
        insert(&mut out, "tier", Some(Value::String(self.tier.clone())));
        insert(&mut out, "runner", Some(Value::String(self.runner.clone())));
        insert(&mut out, "sandbox", self.sandbox.clone().map(Value::String));
        insert(
            &mut out,
            "normalisation_version",
            Some(Value::from(u64::from(self.normalisation_version))),
        );
        insert(
            &mut out,
            "environment",
            Some(Value::String(self.environment.clone())),
        );
        insert(
            &mut out,
            "environment_fingerprint",
            Some(Value::String(self.fingerprint.clone())),
        );
        out.insert(
            "signers".into(),
            Value::Array(
                self.signers
                    .iter()
                    .map(|(key_id, algorithm)| json!({"key_id": key_id, "algorithm": algorithm}))
                    .collect(),
            ),
        );
        out.insert("steps".into(), Value::from(self.steps as u64));
        out.insert(
            "claimed_at".into(),
            Value::String(crate::attest::rfc3339(self.claimed_at_us)),
        );
        out.insert("claimed_at_us".into(), Value::from(self.claimed_at_us));
        insert(
            &mut out,
            "not_after",
            self.not_after_us
                .map(|us| Value::String(crate::attest::rfc3339(us))),
        );
        insert(&mut out, "warning", self.warning.clone().map(Value::String));
        Value::Object(out)
    }

    /// The table rows, in the order a reader checks them.
    pub(crate) fn rows(&self, now: TimeUs, out: &mut Vec<Row>) {
        out.push(Row::new("run", self.run_digest.as_deref().unwrap_or("?")));
        out.push(Row::new(
            "result",
            self.result_digest.as_deref().unwrap_or("?"),
        ));
        out.push(Row::new(
            "commit",
            format!(
                "{}{}",
                self.commit,
                self.job
                    .as_ref()
                    .map(|job| format!(" · job {job}"))
                    .unwrap_or_default()
            ),
        ));
        out.push(Row::new(
            "workflow",
            format!("{} · {}", self.workflow, self.event),
        ));
        out.push(Row::new(
            "tier",
            format!(
                "{} · runner {} · sandbox {} · normalisation v{}",
                self.tier,
                self.runner,
                self.sandbox.clone().unwrap_or_else(|| "none".to_string()),
                self.normalisation_version
            ),
        ));
        out.push(Row::new(
            "environment",
            format!("{} · fingerprint {}", self.environment, self.fingerprint),
        ));
        out.push(Row::new(
            "claimed",
            format!(
                "{} ({} old){}",
                crate::attest::rfc3339(self.claimed_at_us),
                human_age((now.0 - self.claimed_at_us).max(0)),
                self.not_after_us
                    .map(|us| format!(" · closes {}", crate::attest::rfc3339(us)))
                    .unwrap_or_default()
            ),
        ));
        if self.signers.is_empty() {
            out.push(Row::new(
                "signed",
                "nobody: the document carries no signature",
            ));
        }
        for (key_id, algorithm) in &self.signers {
            out.push(Row::new(
                "signed",
                format!("{} ({})", participant::short(key_id), algorithm),
            ));
        }
        out.push(Row::new("steps", self.steps.to_string()));
        if let Some(warning) = &self.warning {
            out.push(Row::new("warning", warning.clone()));
        }
    }
}

/// One `label  value` line of the table.
pub(crate) struct Row {
    label: String,
    value: String,
}

impl Row {
    pub(crate) fn new(label: &str, value: impl Into<String>) -> Row {
        Row {
            label: label.to_string(),
            value: value.into(),
        }
    }

    pub(crate) fn render(&self) -> String {
        format!("{:<14}{}\n", self.label, self.value)
    }
}

/// `24h`, `3d14h`, `never`, `moments` — a window or an age in the unit a human
/// reads it in.
///
/// The library's formatter does the arithmetic (it is the same one the freshness
/// refusal quotes, so "the window" and "how old it is" cannot be spelled two
/// ways); this adds the two words only a *policy* needs: `never` for a window with
/// no limit, and `moments` for an age too small to matter.
pub(crate) fn human_age(micros: i64) -> String {
    if micros >= i64::MAX / 2 {
        return "never".to_string();
    }
    if micros < 1_000_000 {
        return "moments".to_string();
    }
    human_duration_us(micros)
}

// ---------------------------------------------------------------------------
// the command
// ---------------------------------------------------------------------------

fn attestation(args: &[String]) -> Result<(), CliError> {
    let args = Args::parse_with(args, VALUED, SWITCHES)?;
    if let Some(()) = args.help(VERIFY_HELP) {
        return Ok(());
    }
    let spec = policy_spec(&args)?;
    let input = read(&args)?;
    let report = match (&input.doc, &input.failure) {
        // A store that returned the wrong bytes has said something the verdict has
        // to lead with, whatever the document inside them would have scored.
        (_, Some((code, error))) => VerdictReport::refusing(code, error.clone()),
        (Some(doc), None) => doc.verify_report(&spec.policy),
        (None, None) => VerdictReport::refusing(
            "structure",
            AttestError::invalid("attestation", "no document was read"),
        ),
    };
    let facts = input.doc.as_ref().map(Facts::of);

    if args.on("--quiet") || args.on("-q") {
        // One word a shell can test; the exit code does the rest.
        println!(
            "{}",
            report
                .primary()
                .map_or("ok".to_string(), |reason| reason.code.to_string())
        );
        return verdict(&report);
    }
    if args.json() {
        let mut shape = report_shape(&report);
        insert(
            &mut shape,
            "source",
            Some(Value::String(input.source.clone())),
        );
        // Always present, `null` when the document did not come from a store: a script
        // that reads this shape must find the key whether or not there was a store.
        shape.insert(
            "stored".into(),
            input
                .stored
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        shape.insert("policy".into(), spec.json());
        shape.insert(
            "attestation".into(),
            facts.as_ref().map(Facts::json).unwrap_or(Value::Null),
        );
        println!(
            "{}",
            serde_json::to_string(&Value::Object(shape)).unwrap_or_else(|_| "{}".into())
        );
        return verdict(&report);
    }

    let now = spec.policy.now();
    let mut out: Vec<Row> = Vec::new();
    out.push(Row::new("source", input.source.clone()));
    if let Some(stored) = &input.stored {
        out.push(Row::new("stored", stored.clone()));
    }
    match &facts {
        Some(facts) => facts.rows(now, &mut out),
        None => out.push(Row::new(
            "document",
            report
                .primary()
                .map_or("nothing was read".to_string(), |reason| {
                    format!("[{}] {}", reason.code, one_line(reason.detail()))
                }),
        )),
    }
    out.push(Row::new("policy", spec.summary()));

    let mut text = String::new();
    for row in &out {
        text.push_str(&row.render());
    }
    text.push_str("\nchecks\n");
    text.push_str(&render_checks(&report));
    text.push('\n');
    text.push_str(
        &Row::new(
            "verdict",
            format!(
                "{} (exit {})",
                if report.accepted() {
                    "ACCEPTED".to_string()
                } else {
                    report.verdict().to_uppercase()
                },
                report.exit_code()
            ),
        )
        .render(),
    );
    for (index, reason) in report.reasons.iter().enumerate() {
        let label = if index == 0 { "reason" } else { "also" };
        text.push_str(
            &Row::new(
                label,
                format!("[{}] {}", reason.code, one_line(reason.detail())),
            )
            .render(),
        );
        if let Some(hint) = reason.hint() {
            text.push_str(&Row::new("", format!("hint: {}", one_line(hint))).render());
        }
    }
    if spec.any_key {
        text.push_str(
            &Row::new(
                "note",
                "--trust-any-key was given: the signatures were checked, and nobody's \
                 identity. Not a decision to trust.",
            )
            .render(),
        );
    }
    print!("{text}");
    verdict(&report)
}

/// The report in its machine-readable shape: `verdict`, `exit`, `accepted`, `reasons`,
/// `checks`.
///
/// These are the keys a gate parses, so they are one function and not two: `gitiup
/// verify change` prints one of these per attestation and one for the change as a
/// whole, and a script that reads `gitiup verify attestation --json` must be able to
/// read those sections with the same code and the same vocabulary.
///
/// Extra keys are the caller's to add — which is why this hands back an object rather
/// than a printed line.
pub(crate) fn report_shape(report: &VerdictReport) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert(
        "verdict".into(),
        Value::String(report.verdict().to_string()),
    );
    out.insert("exit".into(), Value::from(u64::from(report.exit_code())));
    out.insert("accepted".into(), report.accepted().into());
    out.insert(
        "reasons".into(),
        Value::Array(reasons_json(&report.reasons)),
    );
    out.insert(
        "checks".into(),
        Value::Array(
            report
                .checks
                .iter()
                .map(|check| json!({"code": check.code, "outcome": check.outcome.as_str()}))
                .collect::<Vec<Value>>(),
        ),
    );
    out
}

/// Every reason, in the order they were found: the first decides the exit code and all
/// of them are printed, because a report that says "refused" and nothing else is a
/// report nobody can act on.
pub(crate) fn reasons_json(reasons: &[Reason]) -> Vec<Value> {
    reasons
        .iter()
        .map(|reason| {
            let mut one = Map::new();
            one.insert("code".into(), Value::String(reason.code.to_string()));
            one.insert(
                "class".into(),
                Value::String(reason.class().as_str().to_string()),
            );
            one.insert("detail".into(), Value::String(reason.detail().to_string()));
            insert(
                &mut one,
                "hint",
                reason.hint().map(|hint| Value::String(hint.to_string())),
            );
            one.insert("exit".into(), Value::from(u64::from(reason.exit_code())));
            Value::Object(one)
        })
        .collect()
}

/// The human rendering of the ladder: one line per check, with the reason that made it
/// fail on the same line.
pub(crate) fn render_checks(report: &VerdictReport) -> String {
    let mut text = String::new();
    for check in &report.checks {
        let detail = report
            .reasons
            .iter()
            .find(|reason| reason.code == check.code && check.outcome.is_failure())
            .map_or(String::new(), |reason| {
                format!(" \u{b7} {}", one_line(reason.detail()))
            });
        let line = format!(
            "  {:<15} {:<10}{}",
            check.code,
            state_word(check.outcome),
            detail
        );
        text.push_str(line.trim_end());
        text.push('\n');
    }
    text
}

/// The word one check's outcome prints as.
pub(crate) fn state_word(outcome: CheckOutcome) -> &'static str {
    match outcome {
        CheckOutcome::Passed => "ok",
        CheckOutcome::Failed => "REFUSED",
        CheckOutcome::NotAsked => "not asked",
        CheckOutcome::NotRun => "not run",
    }
}

/// A refusal is a verdict, not a crash: the report is already printed, so all that
/// is left is the number a hook branches on.
pub(crate) fn verdict(report: &VerdictReport) -> Result<(), CliError> {
    if report.accepted() {
        return Ok(());
    }
    Err(CliError::verdict(report.exit_code()))
}

/// Collapse a multi-line detail: a library hint can carry a wrapped paragraph.
pub(crate) fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Shorten a stored digest for a message, keeping what identifies it.
pub(crate) fn short(hex: &str) -> String {
    crate::attest::short(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_string()).collect()
    }

    fn parse(args: &[&str]) -> Result<PolicySpec, CliError> {
        policy_spec(&Args::parse_with(&arg(args), VALUED, SWITCHES)?)
    }

    /// The error the flags produce, so a test can assert on the code without
    /// needing the whole policy to be printable.
    fn fail(args: &[&str]) -> CliError {
        parse(args).map(|_| ()).unwrap_err()
    }

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts() {
        for flag in VALUED.iter().chain(SWITCHES.iter()) {
            assert!(
                VERIFY_HELP.contains(flag),
                "{flag} is accepted but not documented"
            );
        }
        for code in ["0", "2", "3", "6", "7", "8"] {
            assert!(
                VERIFY_HELP.contains(code),
                "exit {code} is missing from the help"
            );
        }
        assert!(VERIFY_HELP.contains("verify attestation"));
    }

    #[test]
    fn a_commit_id_is_a_commit_id_in_any_spelling() {
        let sha1 = GitOid::from_sha1_hex(&"a".repeat(40)).unwrap();
        assert_eq!(commit_id(&"a".repeat(40)).unwrap(), sha1);
        assert_eq!(
            commit_id(&format!("sha1:{}", "a".repeat(40))).unwrap(),
            sha1
        );
        assert_eq!(
            commit_id(&format!("SHA1:{}", "a".repeat(40))).unwrap(),
            sha1
        );
        let sha256 = commit_id(&"b".repeat(64)).unwrap();
        assert_eq!(sha256.algorithm(), OidAlgorithm::Sha256);
        assert_eq!(
            commit_id(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            sha256
        );
        for bad in ["", "nonsense", "sha1:00", &"c".repeat(41)] {
            assert!(commit_id(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn the_flags_write_the_policy_the_verdict_is_judged_by() {
        let spec = parse(&[
            "--tier",
            "simulated",
            "--trust",
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--now",
            "2026-10-27T00:00:00Z",
            "--max-age",
            "2h",
            "--min-signatures",
            "2",
            "--require",
            "arch=amd64",
        ])
        .unwrap();
        assert_eq!(spec.policy.allowed_tiers, vec![Tier::Simulated]);
        assert_eq!(spec.policy.max_age_us, 2 * 3_600 * 1_000_000);
        assert_eq!(spec.policy.min_signatures, 2);
        assert_eq!(
            spec.policy.now,
            Some(TimeUs::parse("2026-10-27T00:00:00Z").unwrap())
        );
        assert_eq!(spec.trusted.len(), 1);
        assert!(spec.trust_source.starts_with("--trust"));
        assert!(spec.summary().contains("arch=amd64"), "{}", spec.summary());
        // The JSON block says the same thing, because it is what a script reads.
        let json = spec.json();
        assert_eq!(json["tiers"], Value::Array(vec!["simulated".into()]));
        assert_eq!(json["min_signatures"], 2);
        assert_eq!(json["max_age"], "2h");
        assert_eq!(json["trusted_key_ids"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn any_key_is_reported_as_not_a_trust_decision() {
        let spec = parse(&["--trust-any-key"]).unwrap();
        assert!(spec.any_key);
        assert!(spec.trusted.is_empty());
        assert!(spec.trust_source.contains("ANY key"));
        assert!(spec.json()["trust"].as_str().unwrap().contains("ANY key"));
    }

    #[test]
    fn naming_trust_two_ways_is_a_usage_error() {
        assert_eq!(fail(&["--trust", "x", "--trust-any-key"]).code, 2);
    }

    #[test]
    fn a_zero_quorum_is_refused_rather_than_silently_satisfied() {
        assert_eq!(fail(&["--min-signatures", "0"]).code, 6);
    }

    #[test]
    fn a_bad_window_is_usage_not_a_verdict() {
        assert_eq!(fail(&["--max-age", "tomorrow"]).code, 2);
        assert_eq!(fail(&["--normalisation-version", "v1"]).code, 2);
    }

    #[test]
    fn windows_read_the_way_retention_reads_them() {
        assert_eq!(window("24h", "--max-age").unwrap(), Some(86_400_000_000));
        assert_eq!(window("never", "--max-age").unwrap(), None);
        assert!(window("tomorrow", "--max-age").is_err());
        assert_eq!(human_age(i64::MAX), "never");
        assert_eq!(human_age(86_400_000_000), "1d");
        assert_eq!(human_age(86_400_000_000 + 3_600_000_000), "1d1h");
        assert_eq!(human_age(500_000), "moments");
        assert_eq!(human_age(90_000_000), "1m30s");
    }

    #[test]
    fn a_report_without_a_verdict_has_a_reason_and_a_code() {
        let mut report = VerdictReport::default();
        report.add_reason(
            "tier",
            AttestError::invalid("policy", "simulated is not allowed"),
        );
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.verdict(), "invalid");
        assert_eq!(report.reason_codes(), vec!["tier"]);
        assert!(!report.accepted());
    }

    #[test]
    fn a_row_is_a_label_and_a_value() {
        assert_eq!(Row::new("tier", "local").render(), "tier          local\n");
    }
}

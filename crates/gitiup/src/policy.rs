//! `gitiup policy …` — publish a policy, and ask which policy is in force (giti-91m.2).
//!
//! Two commands, and they are the two ends of [ADR-0004](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md):
//!
//! ```text
//! gitiup policy publish [POLICY] --store <store>    sign it, check it, put it in the store
//! gitiup policy show             --store <store>    which policy is in force, and how it was picked
//! ```
//!
//! # Why `publish` is a command and not a file copy
//!
//! A policy is the thing that decides whether a merge happens, so the way it arrives has
//! to be at least as strong as the way a proof does. Writing `gitiup-policy.json` into a
//! checkout is not publishing it (D1): a fork edits the file and its own rules apply to
//! its own refs, and nobody can tell. `publish` is the act that makes a policy an
//! authority, and it is an act for the same three reasons a signature is:
//!
//! * **it signs** — `owner.key_id` is a claim and the signature is the proof, so the
//!   owner is a fingerprint and not a field somebody typed;
//! * **it checks before it writes** — every incoherence in D5 (a quorum with nobody to
//!   serve it, an `n` of 200, a `reserves` that starves the reserve, a policy that takes
//!   effect in the future) is refused here rather than discovered by the first merge that
//!   tries to satisfy it. A gate nobody can satisfy is not a strict gate, it is a broken
//!   one, and an owner cannot test it against their own repository because proving *no*
//!   set satisfies a predicate is a different problem from proving one does;
//! * **it is in the store** — `refs/gitiup/policy/current` plus the history refs, which
//!   is what makes the policy resolvable from a clone, from a hook, from a bucket, from
//!   a build agent that has never seen this checkout (D7).
//!
//! The order of the writes is not negotiable and is the library's, not this file's:
//! bytes → create-only history ref → `current` under compare-and-swap ([`policy::publish`]).
//! A refusal writes nothing, so there is no half-published policy to reason about.
//!
//! # Whose signature makes a policy believed
//!
//! Not the publisher's alone. `--trust` names the key ids whose policies *this*
//! configuration will apply (D3), and it is the same list a verifier trusts to sign a
//! proof for — because a policy is one more signed thing a stranger may present. A policy
//! signed by a key nobody listed is refused (`signer_untrusted`), which is what stops a
//! fork from publishing its own weakened policy and having a sync apply it. With no
//! `--trust`, `publish` trusts the key it just signed with and says so: a first policy
//! bootstraps its own trust root, and the second one has to be signed by it.
//!
//! # Exit codes
//!
//! The same table as the rest of `gitiup` (ADR-0001 D7), and the tokens are the
//! library's, mapped by [ADR-0004 D9](../../../docs/adr/0004-published-policy-format-signing-and-resolution.md):
//! 0 ok · 2 usage · 3 I/O or an unreachable store · 6 refused (unsigned, untrusted signer,
//! any D5 incoherence, a broken chain, no policy published, expired) · 7 a signature that
//! does not verify or a key id that is not its key's fingerprint · 8 bytes that are not
//! their own canonical form, or a digest that does not match its name.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use gitiup_attest::{PolicyFile, TimeUs, Trust};
use gitiup_host::attest::parse_age;
use gitiup_quorum::policy::{
    self, Context, GENESIS_PREVIOUS, NewPolicy, PolicyDocument, PolicyError, PolicyOwner, Purpose,
    ResolvedPolicy, Source,
};
use serde_json::{Map, Value, json};

use crate::CliError;
use crate::keys::Args;
use crate::participant::{self, Opened};

/// Help for `gitiup policy`.
pub const POLICY_HELP: &str = "\
gitiup policy — the policy that decides, published to the store and signed

USAGE:
    gitiup policy publish [POLICY] --store <store> [OPTIONS]
    gitiup policy show             [OPTIONS]      (alias: resolve)
    gitiup policy check   --commit <oid>  [OPTIONS]
    gitiup policy explain attestation <DOC|-> [OPTIONS]
    gitiup policy explain change <ID>     [OPTIONS]

A policy is the rule a merge gate applies, and it lives in the store, not in a
checkout: `refs/gitiup/policy/current` and its history (ADR-0004 D7). Editing
`gitiup-policy.json` in a tree changes what *this checkout* would ask for, which is a
question, not a rule — a fork could edit it, and a sync would apply it (D1).

PUBLISH:
    POLICY                     the policy document to publish (JSON, or `-` for stdin).
                               With no POLICY, one is built from the flags below, which
                               is how a repository gets its first policy.
    --store <dir>              where to publish (required; a policy is published
                               *somewhere*, so the default remote is not enough here)
    --remote <name>            a remote from gitiup.toml
    --key <name>               which keystore key signs it — the policy's owner
    --principal <name>         display name for the owner (default: this identity)
    --trust <key|id>           repeatable: key ids that count as trusted here. A policy
                               signed by anything else is refused, so this is what makes
                               upstream's policy upstream's (D3). Default: --key itself.
    --allow-tier <tier>        repeatable, to build one: local · simulated · quorum
    --protect <glob>           repeatable, to build one: what it gates, inside
                               refs/heads/** (default: refs/heads/**)
    --max-age <age>            freshness rule for the built policy: 24h, 30d, `never`
    --min-signatures <n>       distinct trusted signatures the built policy requires
    --effective-from <time>    when the rules start counting: µs or RFC 3339 (default: now)
    --expires-at <time>        when they stop counting (default: until superseded)
    --revision <n>             default: one past what the store advertises
    --previous <digest>        default: the body digest the store advertises (or the
                               zero digest for a store's first policy)
    --expect-current <digest>  fail unless `current` advertises exactly this: two owners
                               publishing at once produces one loser, not a lost revision
    --out <path>               also write the exact bytes that were signed to a file
    --dry-run                  everything publish does except write: refuses what
                               publish would refuse, and changes nothing
    --json                     machine-readable output

SHOW (which policy is in force):
    --store <dir> / --remote <name> / --roster <file>
                               read the published policy from here; without one the
                               ladder falls through to the local sources
    --policy <path>            the operator's act: wins over anything published (D4)
    --tree-file <path>         default ./gitiup-policy.json when present: a draft, and
                               never gate-eligible
    --at <time>                judge the policy as of then: the walk picks the revision
                               that was in force (D6). Default: now
    --gate                     answer as a merge gate would: a policy that is not
                               gate-eligible is a refusal (exit 6), not an answer
    --trust <key|id>           repeatable; default: this keystore's own keys

Resolution order (D4): --policy · $GITIUP_POLICY · the store · the tree file · this
build's default. The answer always says which one won, and a merge may rest only on the
first three.

CHECK AND EXPLAIN (does a thing satisfy it, and why):
    --commit <oid>             check: the commit to judge. With a document, the commit it
                               has to be about instead.
    --store <dir> / --remote   where the proofs and the published policy live. For
      <name>                   `explain attestation <file>` the store is only where the
                               policy comes from — the file is the subject.
    --ref <ref>                the ref a push or a merge would land on. `protects` is
                               only answerable when one is named: a commit is not a ref,
                               and a gate that guessed would be applying rules nobody
                               signed.
    --change <ID> --attempt <n> --expect-result <digest>
                               `explain change`, exactly as `verify change` takes them
    --gate / --advisory        which ladder to walk. Default: the gate's.
    --now <time> / --at <time> the reader's clock, and the revision's moment (D6)
    --json                     the rule document: one entry per rule with `rule`,
                               `outcome`, `evidence.policy`, `evidence.claim` and — where
                               it failed — `detail`, `hint`, `exit`; plus `checks` (the
                               compact projection), `attestations`, `accepts`, `reasons`
    --quiet                    one word: `satisfied`, or the code that refused

`check` is the hook's question in one command: do the attestations this store holds about
a commit satisfy the policy in force? `explain` is the same verdict with the asking
printed: every rule, passed, refused or not asked, in ADR-0001 D7's order, so the first
failure *is* the exit code and a CI job can post the list without re-deriving anything.
`explain change` prints `gitiup verify change`'s own assessment — not a second opinion
beside it, which is why the two cannot disagree and exit the same.

Examples:
    gitiup policy publish --store ./store --allow-tier local --trust ada --json
    gitiup policy publish policy.json --store ./store --dry-run
    gitiup policy show --store ./store
    gitiup policy show --store ./store --at 2026-10-01T00:00:00Z --json
    gitiup policy check --commit \"$newrev\" --store ./store --ref refs/heads/main --json
    gitiup policy explain attestation proof.json --store ./store
    gitiup policy explain change chg-6a6a8eab778ba4d0 --store ./store --json

Exit codes: 0 ok · 2 usage · 3 I/O, store unreachable · 6 refused (unsigned, untrusted
signer, a policy that contradicts itself, a broken chain, none published, expired) ·
7 a signature that does not verify · 8 bytes that are not their own canonical form.
";

/// Valued flags for both subcommands.
const VALUED: &[&str] = &[
    "--store",
    "--remote",
    "--roster",
    "--key",
    "--principal",
    "--trust",
    "--protect",
    "--allow-tier",
    "--policy",
    "--tree-file",
    "--at",
    "--effective-from",
    "--expires-at",
    "--revision",
    "--previous",
    "--expect-current",
    "--out",
    "--max-age",
    "--min-signatures",
    "--passphrase",
    "--passphrase-file",
];

/// Switches for both subcommands.
const SWITCHES: &[&str] = &[
    "--json",
    "-j",
    "--dry-run",
    "--gate",
    "--advisory",
    "--allow-simulated",
];

/// `gitiup policy …`
pub fn policy(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{POLICY_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{POLICY_HELP}");
            Ok(())
        }
        "publish" => publish(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        "show" | "resolve" => show(&Args::parse_with(&args[1..], VALUED, SWITCHES)?),
        // The asking half of this surface. `show` says what the rules are; these say
        // whether one thing satisfies them, and print the asking.
        "check" => crate::policy_ask::check(&args[1..]),
        "explain" => crate::policy_ask::explain(&args[1..]),
        other => Err(CliError::usage(format!(
            "unknown `gitiup policy` command '{other}'; `gitiup policy help` lists publish, \
             show, check and explain"
        ))),
    }
}

// ---------------------------------------------------------------------------
// publish
// ---------------------------------------------------------------------------

/// The keystore identity that signs: the owner of the policy about to be published.
struct Publisher {
    key: gitiup_keys::signer::Key,
    key_id: String,
    principal: String,
}

impl Publisher {
    fn here(args: &Args) -> Result<Publisher, CliError> {
        let keystore = participant::keystore()?;
        let key = participant::signing_key(args, &keystore)?;
        let record = key.record();
        let principal = args
            .get("--principal")
            .map(str::to_string)
            .or_else(|| keystore.config.identity.handle.clone())
            .or_else(|| record.comment.clone())
            .unwrap_or_else(|| record.name.clone());
        Ok(Publisher {
            // A display string, not an authority: one line, cut to the format's byte
            // limit. Who owns a policy is `key_id`, and that is a fingerprint.
            principal: principal
                .chars()
                .filter(|c| !c.is_control())
                .take(80)
                .collect(),
            key_id: record.key_id.clone(),
            key,
        })
    }
}

fn publish(args: &Args) -> Result<(), CliError> {
    if args.help(POLICY_HELP).is_some() {
        return Ok(());
    }
    let store = participant::need_store(args)?;
    let publisher = Publisher::here(args)?;
    let now = TimeUs::now();
    let roots = publish_trust(args, &publisher)?;
    let context = Context::new(&roots, now);

    // The chain position comes from the store, because that is the only thing that makes
    // a revision a link: what `current` advertises now is what this one has to name as its
    // predecessor (D6, D8). And it is read without trusting it: whose key signed the revision in
    // force is that revision's business, and a publisher needs only to know what to name
    // as its predecessor (D3, D6, D8). Whether *this* policy is believed is decided below,
    // by its own signature against `--trust`.
    let in_force = policy::current_position(store.host.as_ref(), now).map_err(refused)?;
    let (revision, previous) = match &in_force {
        Some(existing) => (
            existing.revision + 1,
            existing.body_digest().map_err(refused)?,
        ),
        None => (1, GENESIS_PREVIOUS.to_string()),
    };
    let revision = match args.get("--revision") {
        Some(text) => text.parse::<u32>().map_err(|_| {
            CliError::usage(format!("--revision '{text}' is not a positive integer"))
        })?,
        None => revision,
    };
    let previous = args.get("--previous").unwrap_or(&previous).to_string();

    let mut document = match args.positional.first() {
        Some(path) => read_document(path)?,
        None => built(args, &publisher, &roots)?,
    };
    // The owner is who signs. A document that names somebody else and is signed here is
    // two different answers to "who owns this", so it is refused rather than corrected:
    // `owner.key_id` is what the trust check is about to consult (D3).
    if document.owner.key_id.is_empty() {
        document.owner = PolicyOwner {
            key_id: publisher.key_id.clone(),
            principal: publisher.principal.clone(),
        };
    } else if document.owner.key_id != publisher.key_id {
        return Err(CliError::refused(
            format!(
                "this document's owner is {}, but the key signing it is {}",
                document.owner.key_id, publisher.key_id
            ),
            "publish it with the owner's key, or re-draft it with `--key` naming the owner \
             (ADR-0004 D3: the owner is a signature, not a field)",
        ));
    }
    // Is what we were handed *already* what the store advertises? Checked here, before the
    // chain position is filled in, because filling it in is what would change the bytes:
    // re-publishing the same signed document is an idempotent retry, and quietly
    // renumbering it into a new revision would turn "nothing happened" into "the policy
    // changed" — the difference a verdict's citation depends on (D4, D8).
    let already_there = in_force
        .as_ref()
        .and_then(|existing| existing.record_digest().ok())
        .zip(document.record_digest().ok())
        .is_some_and(|(stored, given)| stored == given);
    if !already_there || args.get("--revision").is_some() || args.get("--previous").is_some() {
        document.revision = revision;
        document.previous_digest = previous;
    }
    if let Some(text) = args.get("--effective-from") {
        document.effective_from_us = at(text, "--effective-from")?.0;
    } else if document.effective_from_us == 0 {
        document.effective_from_us = now.0;
    }
    if let Some(text) = args.get("--expires-at") {
        document.expires_at_us = Some(at(text, "--expires-at")?.0);
    }
    // D2: a policy with no signatures is a refusal, and the ticket's own wording is that
    // `publish` requires them. So this signs, and refuses when it has no key to sign with
    // — which is the same fact as "there is no owner", said before anything is written.
    if document.signatures.is_empty() {
        document.sign(&publisher.key).map_err(refused)?;
    }
    policy::normalise_document(&mut document);
    let bytes = document.canonical_bytes().map_err(refused)?;
    if let Some(out) = args.get("--out") {
        std::fs::write(out, &bytes).map_err(|e| CliError::io(format!("writing '{out}': {e}")))?;
    }

    let outcome = if args.on("--dry-run") {
        policy::plan_publish(
            store.host.as_ref(),
            &document,
            &context,
            args.get("--expect-current"),
        )
    } else {
        policy::publish(
            store.host.as_ref(),
            &document,
            &context,
            args.get("--expect-current"),
        )
    };
    let plan = match outcome {
        Ok(plan) => plan,
        Err(error) => {
            // A refusal is still a result, and a script that asked for JSON should not
            // have to parse prose to learn which of D9's tokens it got. The token is the
            // interface; the exit code is already the library's.
            if args.json() {
                println!(
                    "{}",
                    json!({
                        "record_type": "policy-publish-plan",
                        "dry_run": args.on("--dry-run"),
                        "store": store.what,
                        "refused": { "token": error.token(), "detail": error.detail, "hint": error.hint },
                        "exit_code": error.exit_code(),
                    })
                );
            }
            return Err(refused(error));
        }
    };

    if args.json() {
        let quorum = document.quorum.clone().map_or(Value::Null, |q| {
            serde_json::to_value(q).unwrap_or(Value::Null)
        });
        let report = json!({
            "record_type": "policy-publish-plan",
            "dry_run": args.on("--dry-run"),
            "store": store.what,
            "revision": plan.revision,
            "body_digest": plan.body_digest,
            "record_digest": plan.record_digest,
            "kv": plan.kv,
            "ref": plan.current_ref,
            "history_ref": plan.history_ref,
            "previous_body_digest": plan.previous_body_digest,
            "already": plan.already,
            "size": plan.size,
            "owner": { "key_id": document.owner.key_id, "principal": document.owner.principal },
            "effective_from": TimeUs(document.effective_from_us).to_rfc3339(),
            "expires_at": document.expires_at_us.map(|us| TimeUs(us).to_rfc3339()),
            "protects": document.protects,
            "trusted_key_ids": sorted(&roots),
            "rules": document.rules,
            "quorum": quorum,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
        return Ok(());
    }
    let verb = if args.on("--dry-run") {
        "would publish"
    } else if plan.already {
        "already published"
    } else {
        "published"
    };
    println!(
        "{verb} revision {}: {} (body {})",
        plan.revision, plan.record_digest, plan.body_digest
    );
    println!("  store   {}", store.what);
    println!("  files   {}", plan.kv);
    println!(
        "  refs    {} -> {}, {} -> same",
        plan.current_ref, plan.record_digest, plan.history_ref
    );
    println!(
        "  owner   {} ({})",
        document.owner.key_id, document.owner.principal
    );
    println!(
        "  from    {}{}",
        TimeUs(document.effective_from_us).to_rfc3339(),
        document
            .expires_at_us
            .map(|us| format!(" until {}", TimeUs(us).to_rfc3339()))
            .unwrap_or_default()
    );
    println!("  protects {}", document.protects.join(", "));
    if args.on("--dry-run") {
        println!("nothing was written: this was --dry-run");
    } else {
        println!(
            "trusted here: {} — a verifier applies this policy only if its own trust list \
             names that key",
            sorted(&roots).join(", ")
        );
        println!(
            "next: anyone reading this store asks with `gitiup policy show --store {}`",
            args.get("--store").unwrap_or(".")
        );
    }
    Ok(())
}

/// The document from a file (or `-`), parsed into the format's own type.
///
/// A pretty-printed file is accepted and re-encoded, because a human wrote it; the bytes
/// that get *stored* are the canonical ones, and the signature is over the body of those
/// (D2). The strictness is in the parser: an unknown key is a refusal with the vocabulary
/// named, because a rule silently ignored is a policy that says one thing and does another.
fn read_document(path: &str) -> Result<PolicyDocument, CliError> {
    let text = if path == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| CliError::io(format!("reading stdin: {e}")))?;
        buffer
    } else {
        std::fs::read_to_string(path).map_err(|e| CliError::io(format!("reading '{path}': {e}")))?
    };
    let value: Value = serde_json::from_str(&text).map_err(|e| {
        CliError::refused(
            format!("'{path}' is not JSON: {e}"),
            "a policy document is the ADR-0004 shape: record_type, owner, revision, rules",
        )
    })?;
    if let Some(kind) = value.get("type").and_then(Value::as_str)
        && kind != policy::POLICY_TYPE
    {
        return Err(CliError::refused(
            format!("'{path}' says type '{kind}', not '{}'", policy::POLICY_TYPE),
            "`gitiup policy publish` publishes a policy; a change or an attestation has its \
             own command, and reading one as the other would apply rules to the wrong thing",
        ));
    }
    serde_json::from_value(value).map_err(|e| {
        CliError::refused(
            format!("'{path}' is not a policy document: {e}"),
            "`gitiup policy publish help` lists the fields; every one of them is checked \
             before anything is written (ADR-0004 D2, D5)",
        )
    })
}

/// A policy built from flags, for the bootstrap case: a repository that has no policy
/// yet and one operator with a key.
fn built(args: &Args, publisher: &Publisher, roots: &Trust) -> Result<PolicyDocument, CliError> {
    let tiers = args.all("--allow-tier");
    if tiers.is_empty() {
        return Err(CliError::usage(
            "nothing to publish: give a POLICY file, or say what the policy allows with \
             --allow-tier (local, simulated, quorum)",
        ));
    }
    let mut rules = PolicyFile {
        allowed_tiers: Some(sorted_text(tiers)),
        trust_key_ids: sorted(roots),
        ..Default::default()
    };
    if args.on("--allow-simulated") {
        rules.allow_simulated = Some(true);
    }
    if let Some(text) = args.get("--max-age") {
        let window = parse_age(text).map_err(|e| CliError::usage(format!("--max-age: {e}")))?;
        // `never` in a policy document is the absence of a window, and the absence of a
        // window means the format's default, so it is refused rather than silently
        // meaning something other than what was typed.
        rules.max_age_us = Some(window.ok_or_else(|| {
            CliError::usage(
                "--max-age never means no freshness rule, which a policy has to state as a \
                 number; name a window (30d) instead",
            )
        })?);
    }
    if let Some(text) = args.get("--min-signatures") {
        rules.min_signatures =
            Some(text.parse::<usize>().map_err(|_| {
                CliError::usage(format!("--min-signatures '{text}' is not a number"))
            })?);
    }
    let protects = if args.all("--protect").is_empty() {
        vec!["refs/heads/**".to_string()]
    } else {
        args.all("--protect")
    };
    let mut document = NewPolicy {
        owner: PolicyOwner {
            key_id: publisher.key_id.clone(),
            principal: publisher.principal.clone(),
        },
        protects,
        rules,
        quorum: None,
        effective_from_us: 0,
        expires_at_us: None,
        annotations: None,
        revision: 1,
        previous_digest: GENESIS_PREVIOUS.to_string(),
    }
    .build();
    policy::normalise_document(&mut document);
    Ok(document)
}

/// Trust roots for a publish: `--trust`, or the key that just signed.
///
/// The default is not laziness. A store's first policy defines who owns it, and the only
/// evidence available at that moment is the key that signed it — so publish trusts that
/// key *for this check* and says which roots it used. Everything after the first
/// revision has to be signed by a key the earlier ones already made trusted, which is
/// what D3's "a fork cannot publish its own policy and have it applied" rests on.
fn publish_trust(args: &Args, publisher: &Publisher) -> Result<Trust, CliError> {
    let named = args.all("--trust");
    if named.is_empty() {
        return Ok(Trust::KeyIds(
            [publisher.key_id.clone()].into_iter().collect(),
        ));
    }
    let here = participant::keystore()?;
    let mut ids = BTreeSet::new();
    for value in named {
        ids.insert(participant::key_id_of(&here, &value)?);
    }
    Ok(Trust::KeyIds(ids))
}

// ---------------------------------------------------------------------------
// show / resolve
// ---------------------------------------------------------------------------

fn show(args: &Args) -> Result<(), CliError> {
    if args.help(POLICY_HELP).is_some() {
        return Ok(());
    }
    let store = participant::store_from(args)?;
    let roots = show_trust(args)?;
    let at = match args.get("--at") {
        Some(text) => policy::At::run_claim(TimeUs(at(text, "--at")?.0)),
        None => policy::At::now(),
    };
    let purpose = if args.on("--gate") {
        Purpose::Gate
    } else {
        Purpose::Advisory
    };
    let mut request = match &store {
        Some(opened) => policy::Request::store(opened.host.as_ref(), &roots, at),
        None => policy::Request::advisory(&roots).for_purpose(purpose),
    };
    request.purpose = purpose;
    request.at = Some(at);
    // The two clocks are different things and the CLI is where they are said apart:
    // `--at` is when the run happened, and this machine's clock is what makes a policy
    // expired or future-dated *now* (D6).
    request.now = Some(TimeUs::now());
    request.policy_file = args.get("--policy").map(PathBuf::from);
    request.policy_env = std::env::var("GITIUP_POLICY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from);
    request.tree_file = Some(match args.get("--tree-file") {
        Some(text) => PathBuf::from(text),
        None => Path::new("gitiup-policy.json").to_path_buf(),
    });
    if let Some(file) = &request.tree_file
        && !file.exists()
        && args.get("--tree-file").is_none()
    {
        request.tree_file = None;
    }

    match policy::resolve(&request) {
        Ok(resolved) => {
            if args.json() {
                println!("{}", report(&resolved, store.as_ref()));
            } else {
                print_report(&resolved, store.as_ref());
            }
            Ok(())
        }
        // A refusal is a verdict here, not a fault: `policy show --gate` is what a hook
        // asks, and the exit code is the answer. The token is printed, because D9 made
        // the tokens an interface on purpose.
        Err(error) => {
            if args.json() {
                println!(
                    "{}",
                    json!({
                        "record_type": "policy-provenance",
                        "refused": { "token": error.token(), "detail": error.detail, "hint": error.hint },
                        "exit_code": error.exit_code(),
                    })
                );
            }
            Err(refused(error))
        }
    }
}

/// The trust roots `policy show` applies: `--trust`, else this keystore's own keys.
///
/// The same local-trust rule as `verify attestation`, for the same reason: the machine
/// answering has to say *whose* policy it was willing to apply, and "whoever's store this
/// is" is not an answer — a fork's store would otherwise be its own authority (D3).
/// `gitiup verify change` applies the identical rule, so the two commands cannot disagree
/// about whose policy they were willing to read.
pub(crate) fn show_trust(args: &Args) -> Result<Trust, CliError> {
    let here = participant::keystore()?;
    let named = args.all("--trust");
    if !named.is_empty() {
        let mut ids = BTreeSet::new();
        for value in named {
            ids.insert(participant::key_id_of(&here, &value)?);
        }
        return Ok(Trust::KeyIds(ids));
    }
    let records = here
        .keys
        .list()
        .map_err(|e| CliError::io(format!("reading the keystore: {e}")))?;
    Ok(Trust::KeyIds(
        records.into_iter().map(|record| record.key_id).collect(),
    ))
}

/// The `--json` form of an answer: the provenance, plus what was decided.
fn report(resolved: &ResolvedPolicy, store: Option<&Opened>) -> Value {
    let mut map = Map::new();
    map.insert("record_type".into(), "policy-provenance".into());
    map.insert("policy".into(), resolved.provenance.json());
    map.insert(
        "purpose".into(),
        if resolved.gate_eligible() {
            "gate-eligible"
        } else {
            "not gate-eligible"
        }
        .into(),
    );
    if let Some(opened) = store {
        map.insert("store".into(), opened.what.clone().into());
    }
    map.insert("rules".into(), rules(resolved));
    Value::Object(map)
}

/// The rules that will actually be applied, in the shape the checks consume.
///
/// This is the *resolved* policy, not the file: a flag, a tree file and a published
/// document all end up here as one answer, which is the point of resolving at all (D4).
pub(crate) fn rules(resolved: &ResolvedPolicy) -> Value {
    let policy = &resolved.policy;
    let mut map = Map::new();
    map.insert(
        "allowed_tiers".into(),
        policy
            .allowed_tiers
            .iter()
            .map(|tier| tier.as_str().to_string().into())
            .collect::<Vec<Value>>()
            .into(),
    );
    map.insert("min_signatures".into(), policy.min_signatures.into());
    map.insert("max_age_us".into(), policy.max_age_us.into());
    map.insert("max_clock_skew_us".into(), policy.max_clock_skew_us.into());
    if !policy.allowed_sandboxes.is_empty() {
        map.insert(
            "allowed_sandboxes".into(),
            policy
                .allowed_sandboxes
                .iter()
                .map(|name| name.clone().into())
                .collect::<Vec<Value>>()
                .into(),
        );
    }
    if let Some(commit) = &policy.expected_commit {
        map.insert("expected_commit".into(), commit.to_string().into());
    }
    let trusted: Vec<String> = match &policy.trust {
        Trust::KeyIds(ids) => ids.iter().cloned().collect(),
        Trust::None => Vec::new(),
        // Not a list, and printing an empty one would read as "nobody", which is a
        // different claim from "this run is not a production gate".
        Trust::AnyKeyForTests => vec!["<any key: diagnosis only>".to_string()],
    };
    map.insert("trust_key_ids".into(), trusted.into());
    Value::Object(map)
}

/// The provenance, in the words D4 asks for: source, why, and the digests a verdict cites.
fn print_report(resolved: &ResolvedPolicy, store: Option<&Opened>) {
    let provenance = &resolved.provenance;
    let source = provenance.source.map(Source::as_str).unwrap_or("nothing");
    match provenance.source {
        Some(Source::Store) => println!(
            "policy: {source} revision {} ({})",
            provenance
                .revision
                .map(|revision| revision.to_string())
                .unwrap_or_default(),
            provenance.reference.clone().unwrap_or_default()
        ),
        Some(Source::PolicyFlag) | Some(Source::PolicyEnvironment) | Some(Source::TreeFile) => {
            println!(
                "policy: {source} ({})",
                provenance.file.clone().unwrap_or_default()
            )
        }
        Some(Source::BuiltInDefault) => println!("policy: {source} — nobody configured one"),
        None => println!("policy: none"),
    }
    if let Some(opened) = store {
        println!("  store   {opened}", opened = opened.what);
    }
    if let Some(kv) = &provenance.kv {
        println!("  files   {kv}");
    }
    if let Some(digest) = &provenance.body_digest {
        println!("  body    {digest}  (what a verdict cites)");
    }
    if let Some(digest) = &provenance.record_digest {
        println!("  record  {digest}");
    }
    if let Some(owner) = &provenance.owner {
        println!(
            "  owner   {} ({owner})",
            provenance.signed_by.clone().unwrap_or_default()
        );
    }
    if let Some(us) = provenance.effective_from_us {
        println!("  from    {}", TimeUs(us).to_rfc3339());
    }
    if let Some(us) = provenance.at_us {
        println!(
            "  judged  {} ({})",
            TimeUs(us).to_rfc3339(),
            provenance.at_from.clone().unwrap_or_default()
        );
    }
    println!(
        "  gate    {}",
        if provenance.gate_eligible {
            "yes: a merge may rest on this"
        } else {
            "no: this answers a question, it does not decide a merge"
        }
    );
    for note in &provenance.notes {
        println!("  note    {note}");
    }
    for warning in &provenance.warnings {
        println!("  warning {warning}");
    }
}

// ---------------------------------------------------------------------------
// small shared pieces
// ---------------------------------------------------------------------------

/// A refusal keeps the library's taxonomy: the token is printed, the code is the code,
/// and a hook reading `$?` gets what ADR-0004 D9 says it gets.
pub(crate) fn refused(error: PolicyError) -> CliError {
    CliError::scored(
        error.exit_code(),
        format!("{}: {}", error.token(), error.detail),
        error.hint.clone(),
    )
}

/// A time flag: microseconds or RFC 3339, and the µs that comes out.
fn at(text: &str, flag: &str) -> Result<(i64, String), CliError> {
    let parsed = TimeUs::parse(text).map_err(|e| CliError::usage(format!("{flag}: {e}")))?;
    Ok((parsed.0, parsed.to_rfc3339()))
}

fn sorted(trust: &Trust) -> Vec<String> {
    match trust {
        Trust::KeyIds(ids) => ids.iter().cloned().collect(),
        // `None` trusts nobody and `AnyKeyForTests` trusts whatever is offered: neither
        // is a list, and printing an empty list as if it were the answer would be a lie.
        Trust::None | Trust::AnyKeyForTests => Vec::new(),
    }
}

fn sorted_text(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

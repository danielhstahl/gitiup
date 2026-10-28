//! `gitiup key …` and `gitiup identity …` — who is signing, and with what.
//!
//! This is the command-line half of giti-1rs.6. The decisions live in
//! [`gitiup_keys`]; what is here is parsing, printing, and the two things a human
//! should never be asked to type by hand: a passphrase and a key id.
//!
//! ```text
//! gitiup key gen                       a new ed25519 key, in the age-encrypted keystore
//! gitiup key import file ~/.ssh/id_ed25519
//! gitiup key import ssh-agent          a key already loaded in $SSH_AUTH_SOCK
//! gitiup key import gpg --key 0xF00D…  a gpg subkey, via gpg-agent's ssh socket
//! gitiup identity publish ada --email ada@example.com
//! gitiup identity use ada
//! ```
//!
//! # The rules this surface keeps
//!
//! * **Every command works from a script.** Anything interactive has a flag or an
//!   environment equivalent: `--passphrase-file <path|->` (a file or a pipe, never a
//!   command line where `ps` would read it), `GITIUP_KEY_PASSPHRASE`, `--key <selector>`
//!   instead of a prompt, `--json` on everything that prints anything a script may
//!   want. There is no command that *requires* a terminal.
//! * **Exit codes are ADR-0001 D7's**, unchanged, because a merge gate cannot tell
//!   "the keystore refused" from "the signature is wrong" if this CLI invents its own
//!   numbers: 2 usage · 3 I/O/not found/unreachable agent · 6 refused or invalid ·
//!   7 bad signature · 8 integrity mismatch (a file that did not read back).
//! * **The passphrase is never a value on the command line** unless the user insists
//!   (`--passphrase` exists for the person who knows their own process table); the
//!   documented way in is `--passphrase-file -` with a pipe.
//! * **Nothing here decides what a signature is.** Every key handed to a claim is a
//!   [`gitiup_attest::Signer`] from `gitiup-keys`, so the key behind a keystore
//!   entry, an ssh-agent identity and a gpg subkey produce byte-identical
//!   `SignatureEntry` values.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::io::Write as _;

use gitiup_attest::Signer as _;
use gitiup_attest::Trust;
use gitiup_keys::config::Config;
use gitiup_keys::identity::{Endorsement, IdentityClaim, IdentityStore, Profile};
use gitiup_keys::keystore::{Backend, Generate, Import, Keystore};
use gitiup_keys::passphrase::PassphraseSource;
use gitiup_keys::paths::Paths;
use gitiup_keys::signer;
use serde_json::{Value, json};

use crate::CliError;

/// Help for `gitiup key`, kept next to the flags it documents.
pub const KEY_HELP: &str = "\
gitiup key — the signing keys this machine can use

USAGE:
    gitiup key gen [OPTIONS]
    gitiup key import file <PATH> [OPTIONS]
    gitiup key import seed <PATH|-> [OPTIONS]
    gitiup key import ssh-agent [OPTIONS]
    gitiup key import gpg --key <spec> [OPTIONS]
    gitiup key list [--json]
    gitiup key show <NAME> [--json] [--public-line]
    gitiup key delete <NAME> [--json]
    gitiup key probe [NAME] [--json]

WHAT IS STORED WHERE:
    gen, import file, import seed   a new age-encrypted container (scrypt + age,
                                    armour) under <config>/keys/, and a public record
                                    beside it. The seed never touches disk in clear.
    import ssh-agent, import gpg    a public record only. The private half stays in
                                    the agent; gitiup holds a pointer to it.

OPTIONS:
    --name <name>            what to call the key (default: from the comment, or key-N)
    --comment <text>         label for the record; also the ssh key comment
    --passphrase <text>      the passphrase, on the command line (visible in `ps`; the
                             documented form is --passphrase-file)
    --passphrase-file <p>    read the passphrase from a file's first line, or - for
                             stdin; with no flag and a terminal, you are prompted twice
    --key <selector>         which key: a name, a key id, or a ≥4-char prefix of one
    --socket <path>          ssh-agent socket to use instead of $SSH_AUTH_SOCK
    --force                  replace an existing record of the same name
    --public-line            print only the `ssh-ed25519 AAAA…` line
    -j, --json               machine-readable output
    -h, --help               this text

Environment: GITIUP_KEY_PASSPHRASE is used when no passphrase flag is given (a scripted
fallback; a file or pipe is better), and GITIUP_CONFIG_HOME moves the keystore.

Exit codes: 0 ok · 2 usage · 3 I/O, no such key, or no agent reachable · 6 refused
(duplicate name, a secret you cannot unlock, a key that cannot sign) · 7 bad signature
(`probe` signed and could not be checked)
";

/// Help for `gitiup identity`.
pub const IDENTITY_HELP: &str = "\
gitiup identity — who this machine signs as

USAGE:
    gitiup identity publish <HANDLE> [OPTIONS]
    gitiup identity list [--json]
    gitiup identity show <HANDLE> [--json] [--canonical]
    gitiup identity verify <HANDLE> [--json]
    gitiup identity endorse <HANDLE> [--key <selector>] [--statement <text>] [--json]
    gitiup identity use <HANDLE> [--key <name>]
    gitiup identity whoami [--json] [--check]
    gitiup identity import <PATH|-> [--force] [--json]

An identity claim is a signed statement that a named person controls a key: the key
id is derived from the public key, the self-signature is the assertion, and an
endorsement is somebody else's signature over this claim's digest. The bytes that
are signed are canonical JSON (ADR-0001 D1) — the same for every implementation.

Claims live in <config>/identities/<handle>.identity.json. Pushing them somewhere
strangers can find them is `gitiup push` (a later ticket); this command is what it
will push.

OPTIONS:
    --name <display name>    how to show this identity (default: the handle)
    --email <address>        contact address
    --url <url>              a page about this identity (http or https)
    --annotate <k=v>         extension field, repeatable; keys must be x_<who>_<what>
    --key <selector>         which keystore key to sign with (default: the current one)
    --statement <text>       what the endorsement says, in the endorser's words
    --canonical              print the exact canonical bytes the signature covers
    --check                  with whoami: sign and verify something, to prove the key
                             still works (this may prompt for a passphrase)
    --force                  replace a claim that already exists
    -j, --json               machine-readable output
    -h, --help               this text

Exit codes: 0 ok · 2 usage · 3 I/O/not found/agent unreachable · 6 refused (unsigned,
wrong key, handle exists) · 7 a signature on the claim does not verify ·
8 the stored file is not what was written
";

/// `gitiup key …`
pub fn key(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{KEY_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{KEY_HELP}");
            Ok(())
        }
        "gen" | "generate" => generate(&Args::parse(&args[1..], VALUED)?),
        "import" => import(&args[1..]),
        "list" => list(&Args::parse(&args[1..], VALUED)?),
        "show" => show(&Args::parse(&args[1..], VALUED)?),
        "delete" | "remove" => delete(&Args::parse(&args[1..], VALUED)?),
        "probe" => probe(&Args::parse(&args[1..], VALUED)?),
        other => Err(CliError::usage(format!(
            "unknown `gitiup key` command '{other}'"
        ))),
    }
}

/// `gitiup identity …`
pub fn identity(args: &[String]) -> Result<(), CliError> {
    let Some(sub) = args.first().map(String::as_str) else {
        print!("{IDENTITY_HELP}");
        return Ok(());
    };
    match sub {
        "help" | "--help" | "-h" => {
            print!("{IDENTITY_HELP}");
            Ok(())
        }
        "publish" => publish(&Args::parse(&args[1..], VALUED)?),
        "list" => identity_list(&Args::parse(&args[1..], VALUED)?),
        "show" => identity_show(&Args::parse(&args[1..], VALUED)?),
        "verify" => identity_verify(&Args::parse(&args[1..], VALUED)?),
        "endorse" => endorse(&Args::parse(&args[1..], VALUED)?),
        "use" => use_identity(&Args::parse(&args[1..], VALUED)?),
        "whoami" => whoami(&Args::parse(&args[1..], VALUED)?),
        "import" => identity_import(&Args::parse(&args[1..], VALUED)?),
        other => Err(CliError::usage(format!(
            "unknown `gitiup identity` command '{other}'"
        ))),
    }
}

/// Flags that take a value; everything else is a switch, and anything else that
/// starts with a dash is a mistake.
const VALUED: &[&str] = &[
    "--name",
    "--comment",
    "--passphrase",
    "--passphrase-file",
    "--key",
    "--socket",
    "--email",
    "--url",
    "--statement",
    "--annotate",
];

/// The switches `gitiup key` and `gitiup identity` accept. `--json`/`-j` are accepted
/// by the parser itself, because every sub-surface has them.
const KEY_SWITCHES: &[&str] = &[
    "--force",
    "--public-line",
    "--canonical",
    "--check",
    "--quiet",
];

/// A second pass over argv, in the same hand-rolled style as `digest`: a map of
/// valued flags, a set of switches, and the positionals in order.
#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) positional: Vec<String>,
    pub(crate) values: BTreeMap<String, String>,
    /// Every valued flag in the order it appeared, including repeats.
    ///
    /// `values` keeps the last (which is what a single-valued flag means); this keeps
    /// all of them, which is what a repeatable one means.
    pub(crate) repeats: Vec<(String, String)>,
    pub(crate) annotations: Vec<String>,
    pub(crate) switches: BTreeSet<String>,
}

impl Args {
    pub(crate) fn parse(args: &[String], valued: &[&str]) -> Result<Args, CliError> {
        Self::parse_with(args, valued, KEY_SWITCHES)
    }

    /// The parser, with the vocabulary supplied by the caller.
    ///
    /// A flag is either valued or a switch, and the pair is what makes a typo an error
    /// instead of a silently ignored word — so each sub-surface names its own switches,
    /// rather than sharing one list that accepts everything every command understands.
    pub(crate) fn parse_with(
        args: &[String],
        valued: &[&str],
        switches: &[&str],
    ) -> Result<Args, CliError> {
        let mut out = Args::default();
        let mut index = 0usize;
        while index < args.len() {
            let arg = args[index].clone();
            index += 1;
            let (name, inline) = match arg.split_once('=') {
                Some((name, value)) => (name.to_string(), Some(value.to_string())),
                None => (arg.clone(), None),
            };
            if valued.contains(&name.as_str()) {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        let Some(value) = args.get(index) else {
                            return Err(CliError::usage(format!("{name} needs a value")));
                        };
                        index += 1;
                        value.clone()
                    }
                };
                if name == "--annotate" {
                    out.annotations.push(value.clone());
                } else {
                    out.values.insert(name.clone(), value.clone());
                }
                out.repeats.push((name, value));
                continue;
            }
            if switches.contains(&name.as_str()) || name == "--json" || name == "-j" {
                out.switches.insert(name);
                continue;
            }
            match name.as_str() {
                "-h" | "--help" => {
                    out.switches.insert(name);
                }
                _ if name.starts_with('-') && name != "-" => {
                    return Err(CliError::usage(format!("unknown option '{name}'")));
                }
                _ => out.positional.push(name),
            }
        }
        Ok(out)
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// Every value given for a repeatable flag, in order, de-duplicated.
    pub(crate) fn all(&self, name: &str) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for (key, value) in &self.repeats {
            if key == name && !seen.contains(value) {
                seen.push(value.clone());
            }
        }
        seen
    }

    pub(crate) fn on(&self, name: &str) -> bool {
        self.switches.contains(name)
    }

    /// `--help`, `-h` anywhere: print the help the caller passes and stop.
    pub(crate) fn wants_help(&self) -> bool {
        self.on("--help") || self.on("-h")
    }

    /// Print `help` and return true when `--help` was given, so each command reads
    /// as `if help(args, KEY_HELP) { return Ok(()); }`.
    pub(crate) fn help(&self, text: &str) -> Option<()> {
        self.wants_help().then(|| {
            print!("{text}");
        })
    }

    pub(crate) fn json(&self) -> bool {
        self.on("--json") || self.on("-j")
    }

    pub(crate) fn force(&self) -> bool {
        self.on("--force")
    }

    /// The first positional, or a usage error naming the command.
    pub(crate) fn need(&self, what: &str) -> Result<&str, CliError> {
        self.positional
            .first()
            .map(String::as_str)
            .ok_or_else(|| CliError::usage(format!("a {what} is required")))
    }
}

/// Where the keystore and the identity claims live for this run.
pub(crate) fn paths() -> Result<Paths, CliError> {
    Ok(Paths::from_env()?)
}

/// The passphrase source the flags describe.
///
/// Note the order, and that a *prompt* is the last resort: a file or a pipe is the
/// documented scripted route precisely because a passphrase on the command line is
/// visible in `ps` to every user on the machine.
pub(crate) fn passphrase_source(args: &Args) -> PassphraseSource {
    if let Some(text) = args.get("--passphrase") {
        return PassphraseSource::given(text);
    }
    if let Some(path) = args.get("--passphrase-file") {
        return PassphraseSource::new().file(path);
    }
    PassphraseSource::new()
}

/// Turn `--annotate k=v` strings into the annotation map the claim expects.
fn annotations(args: &Args) -> Result<BTreeMap<String, String>, CliError> {
    let mut out = BTreeMap::new();
    for pair in &args.annotations {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(CliError::usage(format!(
                "--annotate wants key=value, and got '{pair}'"
            )));
        };
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

/// The key to sign with: `--key` if given, else what the config says.
///
/// With no current identity yet — the state right after `gitiup key gen`, before the
/// first `identity publish` — a keystore holding exactly one key is unambiguous, so
/// it is used. With two keys it is a refusal, not a guess: choosing the wrong key to
/// publish a claim with is the mistake this whole area exists to make impossible.
pub(crate) fn signing_key(
    args: &Args,
    keystore: &Keystore,
    config: &Config,
) -> Result<gitiup_keys::signer::Key, CliError> {
    let source = passphrase_source(args);
    if let Some(selector) = args.get("--key") {
        return Ok(signer::open(keystore, selector, &source)?);
    }
    if config.identity.handle.is_some() || config.current_key_selector().is_some() {
        return Ok(signer::current(keystore, config, &source)?);
    }
    let records = keystore.list()?;
    match records.as_slice() {
        [only] => Ok(signer::open_record(keystore, only, &source)?),
        [] => Err(CliError::refused(
            "this keystore is empty",
            "`gitiup key gen` makes a key, or point at one with --key <name>",
        )),
        many => Err(CliError::refused(
            format!(
                "no current identity, and the keystore holds {} keys",
                many.len()
            ),
            "say which one: --key <name> (see `gitiup key list`)",
        )),
    }
}

pub(crate) fn print_json(value: Value) {
    // One line, keys sorted: `gitiup key list --json | jq` is the script's view, and
    // serde_json's default map ordering is already sorted for `Map`.
    println!("{}", serde_json::to_string(&value).unwrap_or_default());
}

/// A record as a script sees it.
fn record_json(record: &gitiup_keys::keystore::KeyRecord) -> Value {
    json!({
        "name": record.name,
        "key_id": record.key_id,
        "backend": record.backend.as_str(),
        "public_key": record.public_key,
        "comment": record.comment,
        "created_at_us": record.created_at_us,
        "secret": record.secret.as_ref().map(|secret| json!({
            "file": secret.file, "format": secret.format, "kdf": secret.kdf,
        })),
        "agent": record.agent.as_ref().map(|agent| json!({
            "socket": agent.socket, "comment": agent.comment,
        })),
        "gpg": record.gpg.as_ref().map(|gpg| json!({
            "key_spec": gpg.key_spec, "keygrips": gpg.keygrips,
        })),
    })
}

fn claim_json(claim: &IdentityClaim) -> Result<Value, CliError> {
    Ok(serde_json::to_value(claim)?)
}

/// The trust policy `verify` uses here: every claim this machine has is a possible
/// endorser. That is deliberately local — what a *change* should trust is a policy
/// question owned by the repository (ADR-0001 D6), not by a laptop's file listing.
fn local_trust(store: &IdentityStore) -> Result<Trust, CliError> {
    Ok(Trust::KeyIds(
        store
            .list()?
            .into_iter()
            .map(|claim| claim.key_id)
            .collect::<BTreeSet<String>>(),
    ))
}

// ---------------------------------------------------------------------------
// key
// ---------------------------------------------------------------------------

fn generate(args: &Args) -> Result<(), CliError> {
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let keystore = Keystore::new(paths()?);
    let record = keystore.generate(
        &Generate {
            name: args.get("--name").map(str::to_string),
            comment: Some(args.get("--comment").unwrap_or("gitiup").to_string()),
            force: args.force(),
            seed: None,
        },
        &passphrase_source(args).read()?,
    )?;
    if args.json() {
        print_json(record_json(&record));
    } else {
        println!("created {}", record.name);
        println!("  key id  {}", record.key_id);
        println!("  public  {}", record.public_key);
        println!(
            "  secret  encrypted with age (scrypt) in {}",
            keystore.paths().keys_dir().display()
        );
    }
    Ok(())
}

fn import(args: &[String]) -> Result<(), CliError> {
    let Some(kind) = args.first().map(String::as_str) else {
        print!("{KEY_HELP}");
        return Ok(());
    };
    let args = Args::parse(&args[1..], VALUED)?;
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let keystore = Keystore::new(paths()?);
    let name = args.get("--name");
    let import = match kind {
        "file" => Import::Openssh {
            path: std::path::PathBuf::from(args.need("key file")?),
        },
        "seed" => Import::Seed {
            path: std::path::PathBuf::from(args.need("seed file (or - for stdin)")?),
        },
        "ssh-agent" | "agent" => Import::SshAgent {
            selector: args.get("--key").map(str::to_string),
            socket: args.get("--socket").map(std::path::PathBuf::from),
        },
        "gpg" => Import::Gpg {
            key_spec: args
                .get("--key")
                .ok_or_else(|| {
                    CliError::usage("`gitiup key import gpg` needs --key <fingerprint>")
                })?
                .to_string(),
        },
        other => {
            return Err(CliError::usage(format!(
                "unknown import source '{other}' (file, seed, ssh-agent, gpg)"
            )));
        }
    };
    // Ask for a passphrase only when something will be decrypted. An agent- or
    // gpg-backed import reads no secret at all, so demanding a passphrase for it
    // would be a prompt with no purpose — and in a script, a prompt with no purpose
    // is a hang.
    let passphrase = match &import {
        Import::Openssh { .. } | Import::Seed { .. } => passphrase_source(&args).read()?,
        Import::SshAgent { .. } | Import::Gpg { .. } => gitiup_keys::passphrase::no_passphrase(),
    };
    let imported = keystore.import(&import, name, &passphrase, args.force())?;
    if args.json() {
        print_json(json!({
            "name": imported.record.name,
            "key_id": imported.record.key_id,
            "backend": imported.record.backend.as_str(),
            "secret_stored_in_keystore": imported.moved,
            "notes": imported.notes,
        }));
    } else {
        println!("imported {}", imported.record.name);
        println!("  key id  {}", imported.record.key_id);
        println!("  backend {}", imported.record.backend.as_str());
        println!(
            "  secret  {}",
            if imported.moved {
                "re-encrypted in the keystore (age)"
            } else {
                "left where it was: the agent holds it"
            }
        );
        for note in &imported.notes {
            println!("  note    {note}");
        }
    }
    Ok(())
}

fn list(args: &Args) -> Result<(), CliError> {
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let keystore = Keystore::new(paths()?);
    let records = keystore.list()?;
    if args.json() {
        print_json(Value::Array(
            records.iter().map(record_json).collect::<Vec<Value>>(),
        ));
        return Ok(());
    }
    if records.is_empty() {
        println!("no keys yet: `gitiup key gen` makes one");
        return Ok(());
    }
    println!("{:<18} {:<10} KEY ID", "NAME", "BACKEND");
    for record in &records {
        println!(
            "{:<18} {:<10} {}",
            record.name,
            record.backend.as_str(),
            record.key_id
        );
    }
    Ok(())
}

fn show(args: &Args) -> Result<(), CliError> {
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let keystore = Keystore::new(paths()?);
    let selector = args.need("key name or key id")?;
    let record = keystore.find(selector)?;
    if args.on("--public-line") {
        println!("{}", record.ssh_line());
        return Ok(());
    }
    if args.json() {
        print_json(record_json(&record));
        return Ok(());
    }
    println!("{} ({})", record.name, record.backend.as_str());
    println!("  key id   {}", record.key_id);
    println!("  public   {}", record.public_key);
    if let Some(comment) = &record.comment {
        println!("  comment  {comment}");
    }
    println!(
        "  record   {}",
        keystore.record_path(&record.name).display()
    );
    match (record.backend, &record.secret) {
        (Backend::Keystore, Some(secret)) => println!(
            "  secret   {} ({} / {})",
            keystore.secret_path(&secret.file)?.display(),
            secret.format,
            secret.kdf
        ),
        (Backend::SshAgent, _) => println!(
            "  secret   in the ssh-agent at {}",
            record
                .agent
                .as_ref()
                .map(|agent| agent.socket.clone())
                .unwrap_or_else(|| "$SSH_AUTH_SOCK".to_string())
        ),
        (Backend::Gpg, _) => println!(
            "  secret   in gpg: {}",
            record
                .gpg
                .as_ref()
                .map(|gpg| gpg.key_spec.clone())
                .unwrap_or_default()
        ),
        (Backend::Keystore, None) => {
            return Err(CliError::refused(
                "keystore",
                format!("'{}' is a keystore key with no container", record.name),
            ));
        }
    }
    Ok(())
}

fn delete(args: &Args) -> Result<(), CliError> {
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let keystore = Keystore::new(paths()?);
    let removed = keystore.remove(args.need("key name or key id")?)?;
    if args.json() {
        print_json(json!({
            "name": removed.name, "key_id": removed.key_id,
            "backend": removed.backend.as_str(), "secret_removed": removed.secret_removed,
        }));
    } else {
        println!("deleted {} ({})", removed.name, removed.key_id);
        println!(
            "  {}",
            if removed.secret_removed {
                "the encrypted container was deleted with it"
            } else {
                "the private half was never here: it stays in the agent"
            }
        );
        println!(
            "  anything already signed with this key still verifies; a claim that named \
             it does not disappear"
        );
    }
    Ok(())
}

/// Sign something and check it, with the key the user is about to trust.
///
/// This is the command that turns "the file is there" into "this machine can
/// actually produce a signature a stranger will accept" — and the reason `probe`
/// exists as a verb is that the failure modes are quiet: a gpg subkey that gpg-agent
/// will not offer, an ssh-agent that has been restarted, a passphrase that changed.
fn probe(args: &Args) -> Result<(), CliError> {
    if args.help(KEY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let keystore = Keystore::new(paths.clone());
    let config = Config::load(&paths)?;
    let key = signing_key(args, &keystore, &config)?;
    key.probe()?;
    if args.json() {
        print_json(json!({
            "name": key.record().name,
            "key_id": key.key_id(),
            "backend": key.backend().as_str(),
            "signs_and_verifies": true,
            "where": key.where_about(),
        }));
    } else {
        println!(
            "{} ({}) signs and verifies: {}",
            key.record().name,
            key.backend().as_str(),
            key.key_id()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

fn publish(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let keystore = Keystore::new(paths.clone());
    let store = IdentityStore::new(paths.clone());
    let config = Config::load(&paths)?;
    let key = signing_key(args, &keystore, &config)?;
    let handle = args.need("handle (a short slug like `ada`)")?.to_string();
    let profile = Profile {
        handle: handle.clone(),
        display_name: args.get("--name").unwrap_or(&handle).to_string(),
        email: args.get("--email").map(str::to_string),
        url: args.get("--url").map(str::to_string),
        annotations: annotations(args)?,
    };
    let claim = IdentityClaim::new(&key, &profile, signer::now_us())?;
    let path = store.publish(&claim, args.force())?;

    // A machine with no current identity gets one, because the alternative is a
    // first-time user publishing a claim and then being told `whoami` does not know
    // who they are. Once one is set, publishing does not steal it.
    let mut config = config;
    let mut became_current = false;
    if config.identity.handle.is_none() {
        config.set_current(&handle, &key.key_id());
        config.save(&paths)?;
        became_current = true;
    }

    if args.json() {
        print_json(json!({
            "handle": handle,
            "key_id": key.key_id(),
            "path": path.display().to_string(),
            "became_current": became_current,
            "claim": claim_json(&claim)?,
        }));
    } else {
        println!("published {handle}");
        println!("  key id  {}", key.key_id());
        println!(
            "  signed  by {} ({})",
            key.record().name,
            key.backend().as_str()
        );
        println!("  file    {}", path.display());
        if became_current {
            println!("  this is now the current identity");
        }
    }
    Ok(())
}

fn identity_list(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let store = IdentityStore::new(paths.clone());
    let config = Config::load(&paths)?;
    let claims = store.list()?;
    if args.json() {
        let mut out = Vec::new();
        for claim in &claims {
            out.push(json!({
                "handle": claim.handle,
                "display_name": claim.display_name,
                "key_id": claim.key_id,
                "email": claim.email,
                "url": claim.url,
                "endorsements": claim.endorsements.len(),
                "current": config.identity.handle.as_deref() == Some(claim.handle.as_str()),
            }));
        }
        print_json(Value::Array(out));
        return Ok(());
    }
    if claims.is_empty() {
        println!("no identities published: `gitiup identity publish <handle> --key <name>`");
        return Ok(());
    }
    println!("{:<18} {:<18} ENDORSE  CURRENT", "HANDLE", "KEY ID");
    for claim in &claims {
        println!(
            "{:<18} {:<18} {:<9} {}",
            claim.handle,
            short(&claim.key_id),
            claim.endorsements.len(),
            if config.identity.handle.as_deref() == Some(claim.handle.as_str()) {
                "yes"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn identity_show(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let store = IdentityStore::new(paths()?);
    let claim = store.find(args.need("handle")?)?;
    if args.on("--canonical") {
        // The exact bytes the self-signature covers, so a second implementation can
        // diff its own canonicalisation against ours byte for byte.
        let bytes = claim.canonical_bytes()?;
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::io(format!("write: {e}")))?;
        println!();
        return Ok(());
    }
    if args.json() {
        print_json(claim_json(&claim)?);
        return Ok(());
    }
    println!("{} — {}", claim.handle, claim.display_name);
    println!("  key id     {}", claim.key_id);
    println!("  public     {}", claim.public_key);
    if let Some(email) = &claim.email {
        println!("  email      {email}");
    }
    if let Some(url) = &claim.url {
        println!("  url        {url}");
    }
    for (key, value) in &claim.annotations {
        println!("  {key} = {value}");
    }
    println!("  made       {} us", claim.created_at_us);
    if let Some(retired) = claim.retired_at_us {
        println!("  retired    {retired} us");
    }
    println!("  signatures {}", claim.signatures.len());
    for endorsement in &claim.endorsements {
        println!(
            "  endorsed by {} {}",
            short(&endorsement.endorser_key_id),
            endorsement
                .statement
                .as_deref()
                .map(|s| format!("— {s}"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

fn identity_verify(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let store = IdentityStore::new(paths.clone());
    let claim = store.find(args.need("handle")?)?;
    // The trust set is every claim we hold; see `local_trust` for why that is a
    // laptop's answer and not a repository's.
    let verified = claim.verify(&local_trust(&store)?)?;
    if args.json() {
        print_json(json!({
            "handle": verified.handle,
            "key_id": verified.key_id,
            "self_signature": "ok",
            "self_trusted": verified.self_trusted,
            "endorsers": verified.endorsers,
            "trusted_endorsers": verified.trusted_endorsers,
        }));
    } else {
        println!(
            "{} checks out: the claim is signed by {} itself",
            verified.handle,
            short(&verified.key_id)
        );
        if verified.endorsers.is_empty() {
            println!("  no endorsements yet — nobody else has said they know this key");
        }
        for endorsement in &claim.endorsements {
            println!(
                "  endorsed by {}{}",
                short(&endorsement.endorser_key_id),
                if verified
                    .trusted_endorsers
                    .contains(&endorsement.endorser_key_id)
                {
                    " (trusted here)"
                } else {
                    " (not in this machine's trust set)"
                }
            );
        }
    }
    Ok(())
}

fn endorse(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let keystore = Keystore::new(paths.clone());
    let store = IdentityStore::new(paths.clone());
    let config = Config::load(&paths)?;
    let claim = store.find(args.need("the handle to endorse")?)?;
    let key = signing_key(args, &keystore, &config)?;
    let endorsement = Endorsement::make(
        &claim,
        &key,
        args.get("--statement").map(str::to_string),
        signer::now_us(),
    )?;
    let path = store.endorse(&claim.handle, endorsement)?;
    if args.json() {
        print_json(json!({
            "handle": claim.handle,
            "endorsed_by_key_id": key.key_id(),
            "path": path.display().to_string(),
        }));
    } else {
        println!(
            "endorsed {} with {} ({})",
            claim.handle,
            key.record().name,
            key.backend().as_str()
        );
        println!("  {}", path.display());
    }
    Ok(())
}

fn use_identity(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let store = IdentityStore::new(paths.clone());
    let claim = store.find(args.need("handle")?)?;
    let handle = claim.handle.clone();
    let mut config = Config::load(&paths)?;
    config.set_current(&handle, &claim.key_id);
    // `--key` is the keystore name to sign with, when the claim's key lives under a
    // different name locally (or when a person has several machines and wants this
    // one to use the one it holds).
    if let Some(name) = args.get("--key") {
        let keystore = Keystore::new(paths.clone());
        let record = keystore.find(name)?;
        if record.key_id != claim.key_id {
            return Err(CliError::refused(
                format!(
                    "key '{}' is {} but {handle} is claimed by {}",
                    record.name,
                    short(&record.key_id),
                    short(&claim.key_id)
                ),
                "that key cannot sign for this identity; publish the other key instead",
            ));
        }
        config.identity.key_name = Some(record.name.clone());
    }
    config.save(&paths)?;
    if args.json() {
        print_json(json!({
            "handle": claim.handle, "key_id": claim.key_id,
            "key_name": config.identity.key_name,
            "config": paths.config_file().display().to_string(),
        }));
    } else {
        println!("you are now {handle} ({})", short(&claim.key_id));
        println!("  {}", paths.config_file().display());
    }
    Ok(())
}

fn whoami(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let config = Config::load(&paths)?;
    let store = IdentityStore::new(paths.clone());
    let handle = config.identity.handle.clone().ok_or_else(|| {
        CliError::refused(
            "no current identity is set",
            "`gitiup identity use <handle>` picks one; `gitiup identity list` shows what exists",
        )
    })?;
    let claim = store.find(&handle)?;
    // Report a mismatch between "who I say I am" and "what config says I sign with"
    // as the error it is: signing with the wrong key is the mistake this whole area
    // exists to make impossible.
    if let Some(key_id) = &config.identity.key
        && key_id != &claim.key_id
    {
        return Err(CliError::refused(
            format!(
                "the config names {} but the {handle} claim is {}",
                short(key_id),
                short(&claim.key_id)
            ),
            format!("`gitiup identity use {handle}` re-points it"),
        ));
    }
    let keystore = Keystore::new(paths.clone());
    let opened = signer::current(&keystore, &config, &passphrase_source(args));
    let (key_name, backend, where_about) = match &opened {
        Ok(key) => (
            Some(key.record().name.clone()),
            Some(key.backend().as_str()),
            Some(key.where_about()),
        ),
        // Reporting who you are must not require unlocking a key: an unopenable key
        // is reported, and `--check` turns it into the error.
        Err(_) => (None, None, None),
    };
    let check = if args.on("--check") {
        opened?.probe()?;
        Some("signs and verifies")
    } else {
        None
    };
    if args.json() {
        print_json(json!({
            "handle": claim.handle,
            "display_name": claim.display_name,
            "key_id": claim.key_id,
            "key_name": key_name,
            "backend": backend,
            "where": where_about,
            "check": check,
            "endorsements": claim.endorsements.len(),
        }));
        return Ok(());
    }
    println!("{} — {}", claim.handle, claim.display_name);
    println!("  key id  {}", claim.key_id);
    match (&key_name, &backend) {
        (Some(name), Some(backend)) => println!("  key     {name} ({backend})"),
        _ => println!(
            "  key     the keystore record for {} cannot be opened here",
            short(&claim.key_id)
        ),
    }
    if let Some(where_about) = where_about {
        println!("  where   {where_about}");
    }
    if let Some(check) = check {
        println!("  check   {check}");
    }
    Ok(())
}

/// Read a claim somebody else produced: a file, or `-` for stdin.
///
/// This is the interchange path, so it is deliberately lenient about *formatting*
/// (any JSON that parses into a claim) and strict about *substance* (`validate`,
/// which is what `publish` re-runs): a pretty-printed claim from another
/// implementation is an ordinary thing, a claim with a broken signature is not.
fn identity_import(args: &Args) -> Result<(), CliError> {
    if args.help(IDENTITY_HELP).is_some() {
        return Ok(());
    }
    let paths = paths()?;
    let store = IdentityStore::new(paths.clone());
    let source = args.need("a claim file, or - for stdin")?;
    let bytes = if source == "-" {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| CliError::io(format!("read stdin: {e}")))?;
        buffer
    } else {
        std::fs::read(source).map_err(|e| CliError::io(format!("read {source}: {e}")))?
    };
    let claim: IdentityClaim = serde_json::from_slice(&bytes).map_err(|e| {
        CliError::refused(
            format!("{source}: {e}"),
            "this is a claim as JSON; `gitiup identity show --canonical` writes the exact bytes",
        )
    })?;
    let path = store.publish(&claim, args.force())?;
    // Verified after storing, so a claim that does not check out is a refusal and not
    // a file that now sits in the identities directory.
    let verified = claim.verify(&local_trust(&store)?)?;
    if args.json() {
        print_json(json!({
            "handle": verified.handle, "key_id": verified.key_id,
            "path": path.display().to_string(),
            "endorsers": verified.endorsers,
            "trusted_endorsers": verified.trusted_endorsers,
        }));
    } else {
        println!("imported {} ({})", verified.handle, short(&verified.key_id));
        println!("  {}", path.display());
        println!(
            "  {} endorsement(s), {} of them trusted here",
            verified.endorsers.len(),
            verified.trusted_endorsers.len()
        );
    }
    Ok(())
}

/// `SHA256:xxxx…xxxx` for a line of terminal, with the middle kept: the ends are
/// what a person recognises, and the prefix is what tells you which kind of id it is.
fn short(key_id: &str) -> String {
    let body = key_id.strip_prefix("SHA256:").unwrap_or(key_id);
    if body.chars().count() <= 16 {
        return key_id.to_string();
    }
    let head: String = body.chars().take(8).collect();
    let tail: String = body.chars().skip(body.chars().count() - 8).collect();
    format!("SHA256:{head}…{tail}")
}

// Any error from the keys library already knows its exit code: the CLI passes it
// through, so a script sees the same number here as from the library.
impl From<gitiup_keys::Error> for CliError {
    fn from(error: gitiup_keys::Error) -> CliError {
        // `detail()` already carries the context prefix; adding it again would
        // print `keystore: keystore: …`.
        CliError::scored(
            error.exit_code(),
            error.detail(),
            error.hint().map(str::to_string),
        )
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> CliError {
        CliError::new(
            gitiup_attest::ErrorKind::Invalid,
            format!("json: {error}"),
            None,
        )
    }
}

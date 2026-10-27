//! `gitiup env` — what machine class this is, and whether a policy would take it.
//!
//! The environment fingerprint is in every manifest and is checked at verification
//! time (giti-1rs.4), so the two questions people actually ask deserve answers that
//! do not require running a job first:
//!
//! * *what would a run here claim?* — OS and version, architecture, container image
//!   digest if one is discoverable, and the toolchain inventory;
//! * *would the repo accept it?* — the requirement published in `gitiup-policy.json`
//!   (or spelled out with `--require`) compared against that, at the setting the
//!   policy chose.
//!
//! The second question is answered by the same
//! [`Policy::check_environment`](gitiup_attest::Policy::check_environment) that a
//! verifier runs, so "what my laptop says" and "what the gate will say" cannot
//! drift. A refusal is exit 6: the machine is fine, it is just not the machine the
//! requirement describes.
//!
//! Nothing here is on the *digesting* path: this command probes the machine because
//! the user asked it to, which is the same reason `gitiup doctor --sandbox` probes.
//! `gitiup run`'s simulated default still touches nothing (see
//! `gitiup-run/tests/no_side_effects.rs`).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use gitiup_attest::{
    EnvMatch, Environment, EnvironmentRequirement, NO_SANDBOX, POLICY_PATH_ENV, PolicyFile,
    Provenance, Tier,
};
use gitiup_run::env::Probe;
use serde_json::Value;

use crate::CliError;

/// The `env`-specific help, kept next to the flags it documents.
pub const HELP: &str = "\
gitiup env — this machine's environment fingerprint, and whether a policy takes it

USAGE:
    gitiup env [OPTIONS]

OPTIONS:
    --json                     machine-readable output (keys sorted, one line)
    -q, --quiet                print the environment fingerprint and nothing else
    --require <field=value>    require one environment field (repeatable), e.g.
                               --require arch=amd64 --require toolchain:rustc=1.99
    --require-env-match <m>    strict | major | off (default: strict, or the policy's)
    --policy <path>            read the requirement from a policy file
                               (default: $GITIUP_POLICY, else no requirement)
    --no-inventory             report OS and architecture only: probe no tools
    -h, --help                 print this text

Fields a requirement may name: arch, os, os_version, image_digest, image_reference,
provider, runner, fingerprint, toolchain:NAME. A value containing a space needs
quoting: --require 'runner=gitiup 0.1'.

Exit codes: 0 the machine matches (or nothing was required) · 2 usage ·
6 refused: this is not the machine the requirement describes
";

/// What the user asked for.
#[derive(Debug, Default)]
struct Options {
    json: bool,
    quiet: bool,
    require: Vec<String>,
    env_match: Option<String>,
    policy: Option<String>,
    no_inventory: bool,
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
            let value = || -> Result<String, CliError> {
                match inline {
                    Some(value) => Ok(value),
                    None => {
                        let value = args
                            .get(index)
                            .ok_or_else(|| CliError::usage(format!("{name} needs a value")))?
                            .clone();
                        index += 1;
                        Ok(value)
                    }
                }
            };
            match name.as_str() {
                "-h" | "--help" | "help" => options.help = true,
                "--json" => options.json = true,
                "-q" | "--quiet" => options.quiet = true,
                "--require" => options.require.push(value()?),
                "--require-env-match" => options.env_match = Some(value()?),
                "--policy" => options.policy = Some(value()?),
                "--no-inventory" => options.no_inventory = true,
                other => return Err(CliError::usage(format!("unknown option '{other}'"))),
            }
        }
        Ok(options)
    }
}

/// The requirement to check this machine against, and how strictly — or `None` when
/// nothing was published, which is the common case and prints as such.
///
/// Two sources and one knob: the policy file (named, or `$GITIUP_POLICY`), the
/// command line's `--require` flags, and `--require-env-match`. File and command
/// line are *merged* field by field, so a policy that says `arch=amd64` plus a
/// `--require toolchain:rustc=1.99` describes everything this invocation asks —
/// which is what makes the command usable before a repo has written its file.
fn requirement(options: &Options) -> Result<Option<(EnvironmentRequirement, EnvMatch)>, CliError> {
    let path = policy_path(options).and_then(|path| path.into_os_string().into_string().ok());
    resolve_requirement(
        path.as_deref(),
        &options.require,
        options.env_match.as_deref(),
    )
}

/// The shared half of "what is the requirement, and how strictly": one policy file,
/// a list of `--require` specs, one knob. `gitiup env` and `gitiup digest` both need
/// exactly this, and must not disagree about it.
///
/// `policy_path` is already resolved: who consults `$GITIUP_POLICY` is the one
/// difference between the two callers, and it belongs to them.
pub(crate) fn resolve_requirement(
    policy_path: Option<&str>,
    requires: &[String],
    env_match: Option<&str>,
) -> Result<Option<(EnvironmentRequirement, EnvMatch)>, CliError> {
    let mut merged = EnvironmentRequirement::empty();
    let mut mode: Option<EnvMatch> = None;

    if let Some(path) = policy_path {
        let text =
            std::fs::read_to_string(path).map_err(|e| CliError::io(format!("{path}: {e}")))?;
        let file = PolicyFile::from_json(&text)?;
        if let Some(text) = &file.require_env_match {
            mode = Some(EnvMatch::parse(text)?);
        }
        if let Some(published) = file.environment_requirement()? {
            merged.merge(&published);
        }
    }

    for spec in requires {
        merged.merge(&EnvironmentRequirement::parse(spec)?);
    }
    if let Some(text) = env_match {
        mode = Some(EnvMatch::parse(text)?);
    }
    let mode = mode.unwrap_or(EnvMatch::Strict);

    if merged.is_empty() {
        return Ok(None);
    }
    if !mode.is_enforced() {
        // The same self-contradiction a policy file refuses: a requirement that is
        // not enforced is a requirement nobody reviewed.
        return Err(CliError::refused(
            format!(
                "require-env-match is '{}' but a requirement is published ({merged})",
                mode.as_str()
            ),
            "say it once: use strict or major, or drop the requirements you no longer want enforced",
        ));
    }
    Ok(Some((merged, mode)))
}

/// Where the policy file is, if one is configured.
///
/// Not implicit beyond `$GITIUP_POLICY`: an environment probe should not be gated
/// by a file that happens to sit in whatever directory it was run from.
fn policy_path(options: &Options) -> Option<PathBuf> {
    if let Some(path) = &options.policy {
        return Some(path.into());
    }
    std::env::var(POLICY_PATH_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

pub(crate) fn run(args: &[String]) -> Result<(), CliError> {
    let options = Options::parse(args)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let probe = if options.no_inventory {
        Probe::bare(std::env::consts::ARCH)
    } else {
        Probe::collect()
    };
    let mut environment: Environment = probe.environment.to_environment();
    environment.fix_fingerprint()?;
    let applied = requirement(&options)?;

    if let Some((requirement, mode)) = &applied {
        // The same call the verifier makes, so this command can never promise what
        // the gate would refuse.
        requirement.check(&environment, &this_build(), *mode)?;
    }

    if options.quiet {
        println!("{}", environment.fingerprint);
        return Ok(());
    }
    if options.json {
        println!("{}", json(&probe, &environment, applied.as_ref()));
    } else {
        print!("{}", render(&probe, &environment, applied.as_ref()));
    }
    Ok(())
}

/// The provenance of *this build*, for the one requirement field that lives outside
/// `environment` — `runner`, the runner implementation and version.
///
/// `gitiup env` is not judging a run, so the runner it names is this build's, and
/// `--require 'runner=gitiup 0.1'` means "does this build satisfy the version the
/// change asks for?" — the only form of that question available before a run exists.
fn this_build() -> Provenance {
    Provenance {
        tier: Tier::Simulated,
        runner: format!("gitiup {}", env!("CARGO_PKG_VERSION")),
        normalisation_version: 0,
        sandbox: Some(NO_SANDBOX.to_string()),
    }
}

/// The human view: one line per field, in the order they matter.
fn render(
    probe: &Probe,
    environment: &Environment,
    applied: Option<&(EnvironmentRequirement, EnvMatch)>,
) -> String {
    let mut out = String::new();
    let runner = this_build().runner;
    let os = match (&environment.os, &environment.os_version) {
        (Some(os), Some(version)) => format!("{os} {version}"),
        (Some(os), None) => os.clone(),
        (None, _) => "unknown".to_string(),
    };
    let _ = writeln!(out, "os             {os}");
    let _ = writeln!(out, "arch           {}", environment.arch);
    let _ = writeln!(
        out,
        "image          {}",
        match &environment.image {
            Some(image) => format!(
                "{}{}",
                image.digest,
                image
                    .reference
                    .as_ref()
                    .map(|reference| format!(" ({reference})"))
                    .unwrap_or_default()
            ),
            None => "none (no container image digest was discoverable)".to_string(),
        }
    );
    let _ = writeln!(
        out,
        "toolchain      {}",
        if environment.toolchain.is_empty() {
            "nothing inventoried".to_string()
        } else {
            environment.describe_toolchain()
        }
    );
    let _ = writeln!(out, "runner         {}", runner);
    let _ = writeln!(out, "fingerprint    {}", environment.fingerprint);
    for note in &probe.notes {
        let _ = writeln!(out, "note           {note}");
    }
    match applied {
        Some((requirement, mode)) => {
            let _ = writeln!(out, "requirement    {requirement} ({mode}) — matched");
        }
        None => {
            let _ = writeln!(out, "requirement    none published");
        }
    }
    out
}

/// The machine view: sorted keys, one line.
fn json(
    probe: &Probe,
    environment: &Environment,
    applied: Option<&(EnvironmentRequirement, EnvMatch)>,
) -> String {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    let runner = this_build().runner;
    for (key, value) in [
        ("os", environment.os.as_ref().map(|v| v.to_string())),
        (
            "os_version",
            environment.os_version.as_ref().map(|v| v.to_string()),
        ),
        ("arch", Some(environment.arch.to_string())),
        (
            "provider",
            environment.provider.as_ref().map(|v| v.to_string()),
        ),
        (
            "image_reference",
            environment
                .image
                .as_ref()
                .and_then(|image| image.reference.as_ref())
                .map(|v| v.to_string()),
        ),
        ("runner", Some(runner.clone())),
        ("fingerprint", Some(environment.fingerprint.to_string())),
    ] {
        if let Some(value) = value {
            map.insert(key.to_string(), Value::String(value));
        }
    }
    if let Some(image) = &environment.image {
        map.insert(
            "image_digest".into(),
            Value::String(image.digest.to_string()),
        );
    }
    map.insert(
        "toolchain".into(),
        Value::Array(
            environment
                .toolchain
                .iter()
                .map(|entry| Value::String(format!("{} {}", entry.name, entry.version)))
                .collect(),
        ),
    );
    map.insert(
        "notes".into(),
        value_array(probe.notes.iter().map(|note| Value::String(note.clone()))),
    );
    if let Some((requirement, mode)) = applied {
        map.insert("requirement".into(), Value::String(requirement.describe()));
        map.insert(
            "require_env_match".into(),
            Value::String(mode.as_str().to_string()),
        );
    }
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".into())
}

/// Shorthand for an array of values.
fn value_array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(values.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_parse_without_surprises() {
        let options = Options::parse(&[
            "--require".to_string(),
            "arch=amd64".to_string(),
            "--require-env-match=major".to_string(),
            "--json".to_string(),
        ])
        .unwrap();
        assert_eq!(options.require, vec!["arch=amd64".to_string()]);
        assert_eq!(options.env_match.as_deref(), Some("major"));
        assert!(options.json);
        assert!(Options::parse(&["--nope".to_string()]).is_err());
        assert!(Options::parse(&["--require".to_string()]).is_err());
    }

    #[test]
    fn nothing_published_is_not_a_refusal() {
        let options = Options::default();
        assert!(requirement(&options).unwrap().is_none());
    }

    #[test]
    fn a_requirement_off_is_refused_rather_than_ignored() {
        let options = Options {
            require: vec!["arch=amd64".into()],
            env_match: Some("off".into()),
            ..Options::default()
        };
        let err = requirement(&options).unwrap_err();
        assert_eq!(err.code, 6);
    }

    #[test]
    fn rendering_names_every_field_a_policy_can_ask_about() {
        let probe = Probe::bare("x86_64");
        let mut environment = probe.environment.to_environment();
        environment.fix_fingerprint().unwrap();
        let requirement = EnvironmentRequirement::parse("arch=amd64").unwrap();
        let text = render(&probe, &environment, Some(&(requirement, EnvMatch::Strict)));
        for line in [
            "os ",
            "arch           x86_64",
            "image",
            "toolchain",
            "fingerprint",
            "requirement",
        ] {
            assert!(text.contains(line), "{text}");
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&json(&probe, &environment, None)).unwrap();
        assert_eq!(parsed["arch"], "x86_64");
        assert!(
            parsed["fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(parsed.get("requirement").is_none());
        let _ = value_array(Vec::<Value>::new());
    }
}

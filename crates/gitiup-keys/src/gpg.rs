//! The optional gpg backend: a key you already have in a keyring, signing through
//! gpg-agent's ssh socket.
//!
//! The trick that makes this cheap is that there is no second signing format.
//! gpg-agent, started with `enable-ssh-support`, listens on its own ssh socket and
//! speaks the agent protocol ([`crate::agent`]) for any key with an authentication
//! subkey — so the signature is raw Ed25519 over exactly the bytes ADR-0001 D3
//! specifies, and `gpg --export-ssh-key` hands over the public half as an
//! `ssh-ed25519` line. That is the whole backend:
//!
//! ```text
//! gpgconf --list-dirs agent-ssh-socket   →  where to connect
//! gpg --export-ssh-key KEYID            →  the public key, and so the key id
//! gpg --with-keygrip --list-keys KEYID  →  the keygrips gpg-agent needs in sshcontrol
//! ```
//!
//! ADR-0001 rejects OpenPGP *detached signatures* as a format ("armored text is not
//! canonical … a signature format that needs `gpg --verify` in the trust path is a
//! dependency on someone else's defaults"), and this path honours that: nothing here
//! produces or consumes an OpenPGP signature. gpg is a **backend**, and the record
//! it signs is byte-identical to one signed by a generated key.
//!
//! gpg is optional in every sense: every function here refuses with exit 3 if the
//! binaries are missing, and nothing else in the crate or the CLI links against
//! anything gpg-shaped.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use gitiup_attest::key::PublicKey;

use crate::agent::{Agent, AgentSigner};
use crate::error::{Error, Result};

/// Override the `gpg` binary (a test harness, or a keyring that lives with a
/// non-default build of gpg).
pub const GPG_ENV: &str = "GITIUP_GPG";
/// Override the `gpgconf` binary.
pub const GPGCONF_ENV: &str = "GITIUP_GPGCONF";

/// Is gpg usable at all here? Used to decide whether to offer the backend, not to
/// refuse a keyring-shaped selector.
pub fn available() -> bool {
    program(GPG_ENV, "gpg")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|output| output.status.success())
}

/// gpg-agent's ssh socket, or a refusal naming the two configuration steps.
pub fn agent_socket() -> Result<PathBuf> {
    let output = run(GPGCONF_ENV, "gpgconf", &["--list-dirs", "agent-ssh-socket"])?;
    let socket = PathBuf::from(output.trim());
    if socket.as_os_str().is_empty() {
        return Err(Error::unreachable(
            "gpg-agent",
            "`gpgconf --list-dirs agent-ssh-socket` printed nothing",
        )
        .with_hint(
            "add `enable-ssh-support` to gpg-agent.conf, then `gpgconf --reload gpg-agent`",
        ));
    }
    if !socket.exists() {
        return Err(Error::unreachable(
            "gpg-agent",
            format!("{} does not exist", socket.display()),
        )
        .with_hint(
            "`gpgconf --launch gpg-agent` starts it; `enable-ssh-support` in gpg-agent.conf \
             is what makes the ssh socket exist at all",
        ));
    }
    Ok(socket)
}

/// The public half of a gpg key, as an SSH key.
///
/// `key_spec` is whatever `gpg` accepts — a fingerprint, a key id, a user id — and
/// is passed as one argv element, never through a shell.
pub fn ssh_public_key(key_spec: &str) -> Result<(PublicKey, String)> {
    let spec = check_spec(key_spec)?;
    let output = run(
        GPG_ENV,
        "gpg",
        &["--batch", "--quiet", "--export-ssh-key", &spec],
    )?;
    // `ssh-ed25519 AAAA… openpgp:0x1234ABCD` — possibly with blank lines around it.
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            Error::not_found(
                "gpg key",
                format!("`gpg --export-ssh-key {spec}` printed nothing"),
            )
        })?;
    let public = PublicKey::from_openssh(line).map_err(|error| {
        Error::new(
            gitiup_attest::ErrorKind::UnsupportedSchema,
            "gpg key",
            format!(
                "`gpg --export-ssh-key {spec}` gave something that is not an ssh-ed25519 key: {}",
                error.detail()
            ),
        )
        .with_hint(
            "gpg-agent's ssh support only exposes Ed25519 keys; add one with \
             `gpg --quick-add-key <FPR> ed25519 auth`",
        )
    })?;
    let comment = line.split_whitespace().nth(2).unwrap_or("gpg").to_string();
    Ok((public, comment))
}

/// The keygrips gpg-agent needs in `sshcontrol` for `key_spec`.
pub fn keygrips(key_spec: &str) -> Result<Vec<String>> {
    let spec = check_spec(key_spec)?;
    let output = run(
        GPG_ENV,
        "gpg",
        &[
            "--batch",
            "--quiet",
            "--with-keygrip",
            "--with-colons",
            "--list-keys",
            &spec,
        ],
    )?;
    let grips = parse_keygrips(&output);
    if grips.is_empty() {
        return Err(Error::not_found(
            "gpg key",
            format!("no keygrip for '{spec}'"),
        ));
    }
    Ok(grips)
}

/// The keygrips in `gpg --with-keygrip --with-colons` output.
///
/// The `grp:` record is `grp:` followed by empty fields and then the grip, with a
/// trailing colon — so "the field after the prefix" is empty and the grip is the
/// *last* non-empty field. Parsing this by field index is what the format invites;
/// parsing it by "last thing that is not a colon" is what survives gpg adding a
/// field, which it has done before.
fn parse_keygrips(colon_output: &str) -> Vec<String> {
    let mut grips: Vec<String> = colon_output
        .lines()
        .filter_map(|line| line.strip_prefix("grp:"))
        .filter_map(|rest| rest.split(':').rev().find(|field| !field.is_empty()))
        .map(|grip| grip.trim().to_string())
        .filter(|grip| !grip.is_empty())
        .collect();
    grips.dedup();
    grips
}

/// gpg-agent's `sshcontrol` file: the list of keygrips it will offer over the ssh
/// socket.
pub fn sshcontrol_path() -> Result<PathBuf> {
    let home = run(GPGCONF_ENV, "gpgconf", &["--list-dirs", "homedir"])?;
    Ok(PathBuf::from(home.trim()).join("sshcontrol"))
}

/// Make sure gpg-agent offers `key_spec` over its ssh socket.
///
/// Returns the keygrips that had to be added to `sshcontrol` (empty if the key was
/// already offered). Writing that file is exactly what the documented manual
/// procedure does — gpg will not offer a key over ssh until its keygrip is listed —
/// and it is done here so that `gitiup key import --gpg` is one command instead of
/// four, but it is reported to the user rather than done silently: it is their
/// keyring, and a file that decides which keys can sign is not a scratch file.
pub fn ensure_offered(key_spec: &str) -> Result<Vec<String>> {
    let grips = keygrips(key_spec)?;
    let path = sshcontrol_path()?;
    let existing: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let missing: Vec<String> = grips
        .iter()
        .filter(|grip| !existing.contains(grip))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let mut contents = String::new();
    if let Ok(existing) = std::fs::read_to_string(&path) {
        contents = existing;
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
    }
    for grip in &missing {
        contents.push_str(grip);
        contents.push('\n');
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::io("create gnupg home", format!("{}: {e}", parent.display())))?;
    }
    std::fs::write(&path, contents)
        .map_err(|e| Error::io("write sshcontrol", format!("{}: {e}", path.display())))?;
    // gpg-agent caches the file; without a reload the new entry is invisible.
    reload_agent()?;
    Ok(missing)
}

/// Tell a running gpg-agent to re-read its configuration.
pub fn reload_agent() -> Result<()> {
    // A failure here is not fatal to the import: the entry is written, and the next
    // agent start picks it up. The caller prints what it did either way.
    run(GPGCONF_ENV, "gpgconf", &["--reload", "gpg-agent"]).map(|_| ())
}

/// A signer for a gpg key, through gpg-agent's ssh socket.
///
/// The returned type is the same [`AgentSigner`] an ssh key uses, because the
/// protocol — and therefore the signature — is the same.
pub fn signer(key_spec: &str) -> Result<AgentSigner> {
    let (public, _) = ssh_public_key(key_spec)?;
    let agent = Agent::gpg_agent(agent_socket()?);
    let key_id = public.key_id();
    let identity = agent.find(&key_id).map_err(|error| match error {
        Error::NotFound { .. } => Error::refused(
            "gpg key",
            format!(
                "gpg-agent will not sign with {key_id} ({key_spec}) even though it can be \
                 exported as an ssh key"
            ),
        )
        .with_hint(
            "gpg-agent offers only keys with an `auth` capability whose keygrip is listed in \
             sshcontrol; `gitiup key import --gpg` adds the entry, or run `gpg-connect-agent \
             /bye` after editing it by hand",
        ),
        other => other,
    })?;
    Ok(AgentSigner::new(agent, identity))
}

/// A key spec is passed to gpg as one argument, never through a shell — but a value
/// that starts with `-` would still be read as an option, and control characters in
/// a filename argument accomplish nothing except to confuse whatever logs this.
fn check_spec(spec: &str) -> Result<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(Error::refused("gpg key", "an empty key specification"));
    }
    if spec.starts_with('-') {
        return Err(Error::refused(
            "gpg key",
            format!("'{spec}' would be read as an option by gpg"),
        )
        .with_hint(
            "name the key by fingerprint or by user id, e.g. `0x1234ABCD` or `ada@example.com`",
        ));
    }
    if spec.chars().any(|c| c.is_control()) {
        return Err(Error::refused(
            "gpg key",
            "the key specification contains control characters",
        ));
    }
    Ok(spec.to_string())
}

fn program(from: &str, default: &str) -> Command {
    let path = std::env::var_os(from).unwrap_or_else(|| std::ffi::OsString::from(default));
    let mut command = Command::new(path);
    // `--batch`/`--no-tty` are added per call: a gpg that wants interactive
    // confirmation is a gpg that hangs a CI job.
    command.stdin(Stdio::null());
    command
}

/// Run a gpg-shaped binary and return stdout as text.
fn run(from: &str, default: &'static str, args: &[&str]) -> Result<String> {
    run_command(program(from, default), default, args)
}

/// The half that does not resolve the binary from the environment, so the failure
/// message is testable without mutating global state.
fn run_command(mut command: Command, default: &'static str, args: &[&str]) -> Result<String> {
    let output: Output = command
        .args(args)
        .output()
        .map_err(|error| {
            Error::unreachable(default, format!("cannot run `{default}`: {error}")).with_hint(
                format!(
                    "if gpg lives somewhere unusual, set {GPG_ENV} to its full path; if you do \
                     not use gpg at all, this backend is optional — `gitiup keygen` needs none of it"
                ),
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail: String = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no explanation")
            .to_string();
        return Err(Error::refused(
            default,
            format!("`{default} {}` failed: {}", args.join(" "), detail.trim()),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The path of a `gpg`-shaped binary, for diagnostics.
pub fn describe() -> String {
    match std::env::var_os(GPG_ENV) {
        Some(value) => value.to_string_lossy().into_owned(),
        None => "gpg (on PATH)".to_string(),
    }
}

/// Is `path` a plausible gpg-agent ssh socket? Used only for a nicer message.
pub fn looks_like_gpg_socket(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".gpg-agent.ssh"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygrips_are_the_last_field_of_a_grp_record() {
        // A real (trimmed) `gpg --with-keygrip --with-colons --list-keys` excerpt:
        // a primary and two subkeys, and the trap in every `grp:` line — the grip is
        // the last non-empty field, not the one after the prefix.
        let listing = "tru:o:1:1793119159:0:3:1:5\n\
pub:u:255:22:D5930176D05E5699:1793119159:::u:::scESCA:::::ed25519:::0:\n\
fpr:::::::::8A6A82444999602D9F840AF5D5930176D05E5699:\n\
grp:::::::::274D6BDA0F26D1F894E5F6C2A05DF48C9EC7A31F:\n\
sub:u:255:22:C5C81926A0F60170:1793119159::::::a:::::ed25519::\n\
grp:::::::::BB2A1403CB44B706CA831F0DE55147CE3B63D979:\n";
        assert_eq!(
            parse_keygrips(listing),
            vec![
                "274D6BDA0F26D1F894E5F6C2A05DF48C9EC7A31F",
                "BB2A1403CB44B706CA831F0DE55147CE3B63D979"
            ]
        );
        assert!(parse_keygrips("pub:u:255:22:\n").is_empty());
    }

    #[test]
    fn a_spec_that_would_be_an_option_is_refused() {
        // Not a theoretical worry: `--homedir` is a gpg option, and a user id that
        // starts with a dash is a plausible thing to paste.
        assert_eq!(check_spec("--homedir=/tmp/x").unwrap_err().exit_code(), 6);
        assert_eq!(check_spec("  ").unwrap_err().exit_code(), 6);
        assert_eq!(check_spec("a\nb").unwrap_err().exit_code(), 6);
        assert_eq!(check_spec(" 0x1234ABCD ").unwrap().len(), 10);
    }

    #[test]
    fn a_missing_gpg_is_exit_three_and_names_the_way_out() {
        // Point it at something that is not gpg: the failure must be the "gpg is
        // optional" message, not a panic or a hang.
        let error = run_command(
            Command::new("/nonexistent/gpg-not-here"),
            "gpg",
            &["--export-ssh-key", "0xDEADBEEF"],
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 3, "{error}");
        assert!(error.to_string().contains("keygen"), "{error}");
    }
}

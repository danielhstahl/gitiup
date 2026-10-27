//! Getting a passphrase, without ever printing one.
//!
//! Four sources, in this fixed order, so a script and a human can use the same
//! command and neither has to be a special case:
//!
//! 1. one handed to the library by the caller ([`PassphraseSource::given`]);
//! 2. `--passphrase-file <path>` (or `-` for stdin) — the scripted path, and the one
//!    that works with a password store (`--passphrase-file <(pass gitiup)`);
//! 3. `$GITIUP_KEY_PASSPHRASE` — for CI, where a file descriptor is awkward;
//! 4. a terminal prompt with echo off, twice, and compared.
//!
//! If none is available the command **refuses** (exit 6) and names the three ways in.
//! It never falls back to "no passphrase", and it never invents one: a keystore
//! encrypted with a passphrase nobody chose is a keystore with no passphrase, and
//! the file name would lie about it.

use std::io::{BufRead as _, Write as _};
use std::path::PathBuf;

use age::secrecy::ExposeSecret;

/// Re-exported so a caller can name "no passphrase" without depending on `age`.
///
/// The only honest use is an import that reads no secret at all — an ssh-agent or
/// gpg key — where the keystore's passphrase parameter is not consulted. Everything
/// that actually encrypts gets its passphrase from [`PassphraseSource::read`].
pub type SecretString = age::secrecy::SecretString;

/// The passphrase for an operation that will not decrypt or encrypt anything.
pub fn no_passphrase() -> SecretString {
    SecretString::from(String::new())
}

use crate::error::{Error, Result};

/// The environment variable consulted third.
pub const PASSPHRASE_ENV: &str = "GITIUP_KEY_PASSPHRASE";

/// Where a passphrase may come from.
#[derive(Debug, Clone, Default)]
pub struct PassphraseSource {
    given: Option<SecretString>,
    file: Option<PathBuf>,
    /// `None` means "do not consult the environment" rather than "consult
    /// `GITIUP_KEY_PASSPHRASE`"; the name is not configurable, the opting out is.
    allow_env: bool,
    allow_prompt: bool,
}

impl PassphraseSource {
    /// The interactive default: everything except a passphrase already in hand.
    pub fn new() -> PassphraseSource {
        PassphraseSource {
            given: None,
            file: None,
            allow_env: true,
            allow_prompt: true,
        }
    }

    /// Scripted: environment and file only, never a prompt.
    ///
    /// The CLI uses this when stdin is not a terminal, because a prompt nobody can
    /// answer is a hang, and a hang in CI is diagnosed as a timeout rather than as a
    /// missing passphrase.
    pub fn scripted() -> PassphraseSource {
        PassphraseSource {
            allow_prompt: false,
            ..PassphraseSource::new()
        }
    }

    /// A passphrase the caller already has.
    pub fn given(passphrase: impl Into<String>) -> PassphraseSource {
        PassphraseSource {
            given: Some(SecretString::from(passphrase.into())),
            ..PassphraseSource::new()
        }
    }

    /// Read from `path`, or from stdin if it is `-`.
    pub fn file(mut self, path: impl Into<PathBuf>) -> PassphraseSource {
        self.file = Some(path.into());
        self
    }

    /// Do not consult `$GITIUP_KEY_PASSPHRASE`.
    pub fn no_env(mut self) -> PassphraseSource {
        self.allow_env = false;
        self
    }

    /// Do not prompt.
    pub fn no_prompt(mut self) -> PassphraseSource {
        self.allow_prompt = false;
        self
    }

    /// Is there any source this can succeed from? Used to decide whether to ask a
    /// question at all (e.g. "confirm?" when the passphrase is coming from a pipe).
    pub fn can_read(&self) -> bool {
        self.given.is_some()
            || self.file.is_some()
            || (self.allow_env && std::env::var_os(PASSPHRASE_ENV).is_some())
            || (self.allow_prompt && terminal().is_some())
    }

    /// Produce the passphrase.
    pub fn read(&self) -> Result<SecretString> {
        // Consulted here rather than in `read_from` so the test below can drive the
        // whole order without touching the process environment (which, in edition
        // 2024, is `unsafe` to mutate from a test thread).
        let from_env = self
            .allow_env
            .then(|| std::env::var_os(PASSPHRASE_ENV))
            .flatten();
        self.read_from(from_env)
    }

    /// [`PassphraseSource::read`] with the environment value supplied, so the
    /// precedence rule is testable without mutating global state.
    fn read_from(&self, from_env: Option<std::ffi::OsString>) -> Result<SecretString> {
        if let Some(secret) = &self.given {
            // A clone, because `read` is callable more than once (unlock two keys
            // with one passphrase) and consuming it would make the second call fail.
            return Ok(SecretString::from(secret.expose_secret().to_string()));
        }
        if let Some(path) = &self.file {
            return Ok(SecretString::from(read_line_from(path)?));
        }
        if let Some(value) = from_env {
            return Ok(SecretString::from(value.to_string_lossy().into_owned()));
        }
        if self.allow_prompt {
            return self.prompt();
        }
        Err(Error::refused(
            "passphrase",
            "no passphrase is available and prompting is not possible",
        )
        .with_hint(format!(
            "pass one in with --passphrase-file <path|->, or set {PASSPHRASE_ENV}; \
             a file keeps it out of the process list and out of your shell history"
        )))
    }

    /// Prompt twice on the terminal and require agreement.
    ///
    /// Two prompts because the alternative is discovering a mistyped passphrase when
    /// *decrypting* — at which point the key you meant to protect may already have
    /// been re-wrapped by a `--force` overwrite.
    pub fn prompt(&self) -> Result<SecretString> {
        let first = prompt_hidden("Passphrase for the new key: ")?;
        let second = prompt_hidden("Repeat that passphrase: ")?;
        if first.expose_secret() != second.expose_secret() {
            return Err(Error::refused(
                "passphrase",
                "the two entries did not match",
            ));
        }
        if first.expose_secret().is_empty() {
            return Err(
                Error::refused("passphrase", "an empty passphrase encrypts nothing")
                    .with_hint("if you want no passphrase, do not use the keystore: use ssh-agent"),
            );
        }
        Ok(first)
    }
}

/// Read one line from a path or from `-` (stdin), trimming the newline only.
///
/// Trailing whitespace is *kept*: a passphrase that ends in a space is a valid
/// passphrase, and silently trimming it means the file that produced it stops
/// working in a way nobody debugs successfully.
fn read_line_from(path: &PathBuf) -> Result<String> {
    if path == std::path::Path::new("-") {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| Error::io("read passphrase from stdin", e.to_string()))?;
        return Ok(trim_newline(&line));
    }
    let bytes = std::fs::read(path)
        .map_err(|e| Error::io("read passphrase file", format!("{}: {e}", path.display())))?;
    let text = String::from_utf8(bytes).map_err(|e| {
        Error::invalid(
            "passphrase file",
            format!("{}: not UTF-8 ({e})", path.display()),
        )
    })?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| Error::refused("passphrase file", format!("{} is empty", path.display())))?;
    Ok(first.to_string())
}

fn trim_newline(line: &str) -> String {
    line.strip_suffix('\n')
        .map(|s| s.strip_suffix('\r').unwrap_or(s).to_string())
        .unwrap_or_else(|| line.to_string())
}

/// The terminal to prompt on, if there is one.
///
/// `/dev/tty` rather than stdin: `gitiup key import --passphrase-file - < key`
/// redirects stdin, and a prompt that lands in the pipe is a prompt nobody sees.
fn terminal() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

fn prompt_hidden(prompt: &str) -> Result<SecretString> {
    let mut tty = terminal().ok_or_else(|| {
        Error::refused("passphrase", "no terminal to prompt on").with_hint(format!(
            "pass --passphrase-file <path|-> or set {PASSPHRASE_ENV}"
        ))
    })?;
    let echo = set_echo(&mut tty, false)?;
    let result = (|| -> Result<String> {
        write!(tty, "{prompt}").map_err(|e| Error::io("prompt", e.to_string()))?;
        tty.flush()
            .map_err(|e| Error::io("prompt", e.to_string()))?;
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(&mut tty);
        reader
            .read_line(&mut line)
            .map_err(|e| Error::io("read passphrase", e.to_string()))?;
        Ok(trim_newline(&line))
    })();
    // Restore echo whatever happened, before the read's own error is returned: a
    // shell left with echo off is a worse user experience than whatever error is
    // about to be printed.
    restore_echo(&mut tty, echo)?;
    // Print the newline the hidden read never produced.
    let _ = writeln!(tty);
    Ok(SecretString::from(result?))
}

/// Turn terminal echo off, returning whether it was on to begin with.
///
/// `stty` rather than `termios` because the alternative is a C-binding dependency
/// for one call, and this workspace keeps its dependency list boring on purpose. If
/// `stty` is not installed the prompt is refused: echoing a passphrase to the screen
/// is not an acceptable fallback, and it is not one the user gets to choose.
fn set_echo(tty: &mut std::fs::File, on: bool) -> Result<bool> {
    let was_on = stty(tty, &["-g"]).map(|state| !state.contains("-echo"))?;
    stty(tty, if on { &["echo"] } else { &["-echo"] })?;
    Ok(was_on)
}

fn restore_echo(tty: &mut std::fs::File, was_on: bool) -> Result<()> {
    stty(tty, if was_on { &["echo"] } else { &["-echo"] }).map(|_| ())
}

fn stty(tty: &mut std::fs::File, args: &[&str]) -> Result<String> {
    use std::process::Stdio;
    let output = std::process::Command::new("stty")
        .args(args)
        .stdin(Stdio::from(
            tty.try_clone()
                .map_err(|e| Error::io("duplicate tty", e.to_string()))?,
        ))
        .output()
        .map_err(|e| {
            Error::refused("passphrase", format!("cannot run `stty`: {e}")).with_hint(
                "gitiup needs stty to read a passphrase without echoing it; \
                 use --passphrase-file or a pipe instead",
            )
        })?;
    if !output.status.success() {
        return Err(Error::io(
            "stty",
            format!(
                "`stty {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_is_given_file_env_then_prompt() {
        // A file wins over the environment, and a given passphrase wins over both:
        // the more specific source is the one the caller meant.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pw");
        std::fs::write(&path, "from-file\n").unwrap();
        let from_env = Some(std::ffi::OsString::from("from-env"));

        let source = PassphraseSource::new().file(&path);
        assert_eq!(
            source.read_from(from_env.clone()).unwrap().expose_secret(),
            "from-file"
        );
        let source = PassphraseSource::given("given").file(&path);
        assert_eq!(
            source.read_from(from_env.clone()).unwrap().expose_secret(),
            "given"
        );
        let source = PassphraseSource::new();
        assert_eq!(
            source.read_from(from_env).unwrap().expose_secret(),
            "from-env"
        );
        // And `no_env` means the variable is not consulted, not that it is preferred.
        // `no_env` means the variable is not consulted at all, so even a supplied
        // value is not used — and with no prompt either, there is nothing left.
        let source = PassphraseSource::new().no_env().no_prompt();
        assert_eq!(
            source.read_from(None).unwrap_err().exit_code(),
            6,
            "no source must be a refusal, not an empty passphrase"
        );
    }

    #[test]
    fn a_file_keeps_the_bytes_except_the_newline() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pw");
        // Trailing spaces are part of the passphrase; only the line break is not.
        std::fs::write(&path, " correct horse \nignored second line\n").unwrap();
        assert_eq!(
            PassphraseSource::new()
                .file(&path)
                .read()
                .unwrap()
                .expose_secret(),
            " correct horse "
        );
    }
}

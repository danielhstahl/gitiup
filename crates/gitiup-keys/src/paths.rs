//! Where gitiup keeps its own state: one directory, resolved one way.
//!
//! The whole of it is `$GITIUP_CONFIG_HOME`, else `$XDG_CONFIG_HOME/gitiup`, else
//! `$HOME/.config/gitiup`, and the environment is consulted *once*, in
//! [`Paths::from_env`], so a test can point the entire crate at a temp directory by
//! setting one variable — which is exactly what `tests/keystore.rs` and the CLI
//! tests do, and what makes "private key material never escapes the keystore" a
//! checkable claim instead of an assertion about real dotfiles.
//!
//! The directory is `0700`, not `0755`. Everything under it is either a private key
//! container or a public record, and "the public ones are world-readable, the
//! private ones are not" is a rule that eventually gets broken; a directory nobody
//! else can enter is the rule that does not need policing every time.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The environment variable that wins over everything else.
pub const CONFIG_HOME_ENV: &str = "GITIUP_CONFIG_HOME";
/// The XDG variable used when that one is unset.
pub const XDG_CONFIG_ENV: &str = "XDG_CONFIG_HOME";
/// The fallback home.
pub const HOME_ENV: &str = "HOME";

/// The subdirectory holding key records and their encrypted containers.
pub const KEYS_DIR: &str = "keys";
/// The subdirectory holding published identity claims.
pub const IDENTITIES_DIR: &str = "identities";
/// The user-editable config (`[identity]` …).
pub const CONFIG_FILE: &str = "config.toml";

/// gitiup's own state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// Resolve from the environment.
    ///
    /// An empty variable counts as unset (a CI job that writes `GITIUP_CONFIG_HOME=`
    /// means "not set", not "the current directory"), and a relative value is
    /// refused: a keystore whose location depends on the caller's cwd is a keystore
    /// that will be found in the wrong place.
    pub fn from_env() -> Result<Paths> {
        if let Some(value) = non_empty(CONFIG_HOME_ENV) {
            return Paths::parse_root(CONFIG_HOME_ENV, &value);
        }
        if let Some(xdg) = non_empty(XDG_CONFIG_ENV) {
            let xdg = PathBuf::from(&xdg);
            if !xdg.is_absolute() {
                return Err(Error::refused(
                    "config home",
                    format!("{XDG_CONFIG_ENV}={}", xdg.display()),
                )
                .with_hint(format!("`{XDG_CONFIG_ENV}` must be an absolute path")));
            }
            return Ok(Paths {
                root: xdg.join("gitiup"),
            });
        }
        let home = non_empty(HOME_ENV).ok_or_else(|| {
            Error::refused(
                "config home",
                format!("none of {CONFIG_HOME_ENV}, {XDG_CONFIG_ENV} or {HOME_ENV} is set"),
            )
            .with_hint(format!(
                "set {CONFIG_HOME_ENV} to an absolute directory, or run from a login shell \
                 that sets HOME"
            ))
        })?;
        Ok(Paths {
            root: PathBuf::from(home).join(".config").join("gitiup"),
        })
    }

    /// An explicit root, for tests and for a caller that has its own opinion.
    pub fn with_root(root: impl Into<PathBuf>) -> Paths {
        Paths { root: root.into() }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `keys/`: key records and `.secret.age` containers.
    pub fn keys_dir(&self) -> PathBuf {
        self.root.join(KEYS_DIR)
    }

    /// `identities/`: published identity claims, one canonical JSON file each.
    pub fn identities_dir(&self) -> PathBuf {
        self.root.join(IDENTITIES_DIR)
    }

    /// `config.toml`: which identity is current.
    pub fn config_file(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    /// Create the root and its subdirectories, `0700`.
    ///
    /// Idempotent, and it does not soften the mode of a directory it did not
    /// create: if the operator has made `keys/` group-readable on purpose, that is
    /// their call, and silently `chmod`ing a directory the user configured is a
    /// surprise of its own. A directory that exists but is *not* private is reported
    /// as the problem it is ([`Paths::warn_if_world_readable`]).
    pub fn ensure(&self) -> Result<()> {
        for dir in [self.root.clone(), self.keys_dir(), self.identities_dir()] {
            match std::fs::create_dir_all(&dir) {
                Ok(()) => set_private(&dir)?,
                Err(error) => {
                    return Err(Error::io(
                        "create config directory",
                        format!("{dir:?}: {error}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// `Some(message)` when a directory that holds key material is readable by
    /// anybody who is not the owner.
    ///
    /// Not an error: a shared build box with an odd group setup is a defensible
    /// choice, and refusing to run there would only push people to `--force` a
    /// louder warning elsewhere. Every caller that writes a secret prints this.
    pub fn warn_if_world_readable(&self) -> Option<String> {
        let mut warnings = Vec::new();
        for dir in [self.root.clone(), self.keys_dir()] {
            if let Some(mode) = mode_of(&dir)
                && mode & 0o077 != 0
            {
                warnings.push(format!(
                    "{} is mode {:04o}: key material and identity records live under it",
                    dir.display(),
                    mode
                ));
            }
        }
        if warnings.is_empty() {
            None
        } else {
            Some(warnings.join("; "))
        }
    }

    fn parse_root(from: &str, value: &str) -> Result<Paths> {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(Error::refused("config home", format!("{from}={value}"))
                .with_hint(format!("`{from}` must be an absolute path")));
        }
        Ok(Paths { root: path })
    }
}

/// The permission bits of a path, or `None` if it cannot be stat'd or the platform
/// has no such thing.
fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        std::fs::metadata(path)
            .ok()
            .map(|meta| std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Force `0700` on a directory we just created (unix only; elsewhere the concept
/// does not exist and the keystore's per-file checks still apply).
fn set_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| Error::io("chmod 700", format!("{}: {error}", path.display())))?;
    }
    let _ = path;
    Ok(())
}

fn non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Turn a human name into something safe to use as a file name.
///
/// Lower-cased, `[a-z0-9._-]` only, capped at 64 bytes, never empty. Deliberately
/// strict: these names end up in paths built from user input, and a `name` of
/// `../../etc/x` must not be expressible.
pub fn slugify(name: &str) -> Result<String> {
    let mut out = String::with_capacity(name.len());
    let mut pending_dash = false;
    for byte in name.trim().bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => {
                if pending_dash && !out.is_empty() {
                    out.push('-');
                }
                pending_dash = false;
                out.push(byte as char);
            }
            b'A'..=b'Z' => {
                if pending_dash && !out.is_empty() {
                    out.push('-');
                }
                pending_dash = false;
                out.push((byte + 32) as char);
            }
            b' ' | b'_' | b'.' | b'-' | b'@' => {
                pending_dash = !out.is_empty();
            }
            other => {
                return Err(Error::refused(
                    "name",
                    format!(
                        "'{name}' cannot be used as a key name ('{}' is not allowed)",
                        other as char
                    ),
                )
                .with_hint(
                    "a key name is letters, digits, spaces, '.', '_' or '-', e.g. `laptop`",
                ));
            }
        }
        if out.len() >= 64 {
            break;
        }
    }
    let slug = out.trim_matches('-').to_string();
    if slug.is_empty() {
        return Err(
            Error::refused("name", format!("'{name}' has nothing to be named after"))
                .with_hint("a key name is letters, digits, spaces, '.', '_' or '-', e.g. `laptop`"),
        );
    }
    Ok(slug)
}

/// Is `slug` a name this crate will accept verbatim (rather than slugify)?
///
/// `[a-z0-9._-]`, at most 64 bytes, starting and ending with a letter or digit, no
/// doubled separator. Stricter than a file system and looser than [`slugify`]: the
/// point is that a name read back from disk, or typed as a selector, is a name this
/// crate wrote.
pub fn is_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !slug.contains("--")
        && !slug.contains("..")
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_slugified_and_injection_free() {
        assert_eq!(slugify("  Ada Lovelace ").unwrap(), "ada-lovelace");
        assert_eq!(slugify("laptop_2").unwrap(), "laptop-2");
        // A separator is a separator: `_`, `.`, `@` and a space all become `-`, so a
        // name typed two ways is one file, not two.
        assert_eq!(slugify("ada@example.com").unwrap(), "ada-example-com");
        assert_eq!(slugify("Ci.Key-1").unwrap(), "ci-key-1");
        // The one that matters: a name is never pasted into a path unchecked. A
        // slash is refused outright, and a name that is only separators has nothing
        // to be named after, so `..` cannot arrive by accident either.
        for bad in [
            "../../etc/passwd",
            "ke/y",
            "ключ",
            " ",
            "",
            "..",
            "/",
            "...",
            "-",
        ] {
            let error = slugify(bad).unwrap_err();
            assert_eq!(error.exit_code(), 6, "{bad} must be refused: {error}");
        }
        assert!(!is_slug("../.."));
        assert!(!is_slug(""));
        assert!(!is_slug("A"));
        assert!(!is_slug(&"a-".repeat(40)));
        assert!(is_slug(&slugify(&"a".repeat(200)).unwrap()));
    }

    #[test]
    fn a_relative_config_home_is_refused_not_guessed() {
        // A keystore in `./keys`, found relative to whatever the cwd happens to be,
        // is a keystore that silently moves.
        let err = Paths::parse_root(CONFIG_HOME_ENV, "relative/path").unwrap_err();
        assert_eq!(err.exit_code(), 6);
        assert!(err.to_string().contains("absolute"));
        assert!(Paths::parse_root(CONFIG_HOME_ENV, "/tmp/x").is_ok());
    }
}

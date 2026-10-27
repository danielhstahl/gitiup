//! `config.toml`: which identity this machine is currently using.
//!
//! One `[identity]` section, two fields, and a rule: the file is *preferred* state,
//! never authoritative state. It says "when someone says `gitiup identity publish`
//! without naming a key, use this one"; the key itself still has to exist in the
//! keystore and the claim still has to be published.
//!
//! It is TOML and not canonical JSON for one reason: it is edited by hand. Signed
//! records are canonical JSON because they must be re-encodable byte for byte; a
//! local preference has no such requirement, and a human-editable file with comments
//! is worth more than a format symmetry nobody uses.
//!
//! A file that does not parse is a **refusal**, not a reset. Silently treating a typo
//! as "no current identity" is how someone ends up signing with a different key than
//! they thought, and the whole value of `whoami` is that it can be trusted.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths::Paths;

/// The version of the config file shape. Written so a future reader can tell `0`
/// from "never set".
pub const CONFIG_VERSION: u32 = 1;

/// Everything gitiup remembers between commands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `1`.
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    /// The current identity.
    pub identity: IdentitySection,
}

/// `[identity]` — what `gitiup identity use` writes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// The handle, as published in the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// The key id, so the choice survives a handle being republished by someone else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// A name for the keystore key to use, if it differs from the claim's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
}

impl Config {
    /// Read the config, or the default when the file does not exist.
    pub fn load(paths: &Paths) -> Result<Config> {
        let path = paths.config_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<Config>(&text).map_err(|e| {
                Error::refused("config", format!("{}: {e}", path.display())).with_hint(
                    "fix the file rather than deleting it: it names which key you think \
                            you are signing with",
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(error) => Err(Error::io(
                "read config",
                format!("{}: {error}", path.display()),
            )),
        }
    }

    /// Write it, `0600` — not because it is secret, but because it names the keys
    /// this machine holds.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.ensure()?;
        let path = paths.config_file();
        let text =
            toml::to_string_pretty(self).map_err(|e| Error::io("encode config", e.to_string()))?;
        let header = "# gitiup: this machine's current identity. Edit freely; `gitiup identity\n\
                      # use <handle>` writes it for you.\n";
        crate::keystore::write_file_private(&path, format!("{header}{text}").as_bytes())?;
        Ok(())
    }

    /// The selector for the current key: the key id if it is known, else the key
    /// name, else the handle.
    ///
    /// In that order deliberately: a key id cannot be re-used by somebody else, a
    /// handle can.
    pub fn current_key_selector(&self) -> Option<&str> {
        self.identity
            .key
            .as_deref()
            .or(self.identity.key_name.as_deref())
            .or(self.identity.handle.as_deref())
    }

    /// Point the config at a published claim.
    pub fn set_current(&mut self, handle: &str, key_id: &str) {
        self.version = CONFIG_VERSION;
        self.identity.handle = Some(handle.to_string());
        self.identity.key = Some(key_id.to_string());
        self.identity.key_name = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_config_is_the_default_and_a_broken_one_is_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path());
        assert_eq!(Config::load(&paths).unwrap(), Config::default());

        std::fs::create_dir_all(paths.root()).unwrap();
        std::fs::write(
            paths.config_file(),
            "[identity]\nhandle = \"ada\"\nkey = \"SHA256:x\"\n",
        )
        .unwrap();
        let config = Config::load(&paths).unwrap();
        assert_eq!(config.identity.handle.as_deref(), Some("ada"));
        assert_eq!(config.current_key_selector(), Some("SHA256:x"));

        std::fs::write(paths.config_file(), "[identity]\nhandle = 42\n").unwrap();
        assert_eq!(Config::load(&paths).unwrap_err().exit_code(), 6);
        // An unknown key is refused too: a typo that silently does nothing is worse
        // than a typo that says so.
        std::fs::write(paths.config_file(), "[identity]\nhanle = \"ada\"\n").unwrap();
        assert!(Config::load(&paths).is_err());
    }

    #[test]
    fn set_current_names_the_key_and_not_only_the_handle() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path());
        let mut config = Config::default();
        config.set_current("ada", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        config.save(&paths).unwrap();
        let read = Config::load(&paths).unwrap();
        assert_eq!(read, config);
        assert_eq!(
            read.current_key_selector().unwrap(),
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
    }
}

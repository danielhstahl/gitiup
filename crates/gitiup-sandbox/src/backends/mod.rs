//! The backends, in the order [`crate::backend::backends`] prefers them.
//!
//! Each one is small on purpose. A backend is: how to notice it exists, what it
//! actually denies, how to wrap a command, and how strongly it enforces the network
//! policy. Anything more complicated than that belongs in `egress`, `linux`, or
//! `probe`, where it can be tested on its own.

pub mod bwrap;
pub mod container;
pub mod inprocess;
pub mod plain;
pub mod unshare;

use std::path::Path;

use gitiup_attest::{Error, ErrorKind, Result};

/// A container or bind-mount backend needs absolute paths: `-v` and `--ro-bind` have
/// no useful meaning relative to a working directory that is itself inside the
/// sandbox.
pub(crate) fn require_absolute(what: &str, path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::Policy,
        "sandbox",
        format!(
            "`{}` must be an absolute path for this backend (`{}` is relative)",
            what,
            path.display()
        ),
    )
    .with_hint("pass --workdir with an absolute path, or `cd` into the directory first"))
}

/// The witness port used by the egress canary, and the note every backend writes when
/// nothing arrived at it.
pub(crate) const WITNESS_NOTE: &str = "no connection arrived at the witness port";

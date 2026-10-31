//! The build's failures, with the path that caused them.
//!
//! A site builder has exactly one interesting error — a file could not be read or
//! written, by whom and where — and one non-error: a link in a doc that goes
//! nowhere. That one is a *finding*, reported by `check` in a list, not an
//! [`Error`] that aborts the run, because a builder that stops at the first dead
//! link reports one problem per run and the operator makes ten runs.

use std::fmt;
use std::path::{Path, PathBuf};

/// Anything that stopped the build.
#[derive(Debug)]
pub enum Error {
    /// The filesystem said no. Carrying the path is the whole point: `Os { code: 2, kind: NotFound }`
    /// on its own tells nobody which of forty files it was.
    Io {
        /// The file or directory that could not be read or written.
        path: PathBuf,
        /// The OS's own account of it.
        source: std::io::Error,
    },
    /// The inputs do not describe a site: no `docs/`, an empty checkout, a `--root`
    /// that names a file.
    Config(String),
}

impl Error {
    /// An I/O failure against `path`.
    pub(crate) fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Error::Config(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Config(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::Io {
            path: PathBuf::from("."),
            source,
        }
    }
}

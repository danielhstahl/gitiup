//! Errors, with ADR-0001 D7's exit-code taxonomy kept intact.
//!
//! A script branches on numbers, and it must get the same number from
//! `gitiup identity publish` that it gets from `gitiup verify attestation`. So
//! this error is a wrapper, not a new vocabulary:
//!
//! | kind | exit | meaning |
//!|------|------|---------|
//!| [`Error::Attest`] | 6 / 7 / 8 | whatever the format crate decided — a bad signature stays a 7 here |
//!| [`Error::Io`] | 3 | nothing could be read or written: the file is not there, the socket is not there, the agent is not running |
//!| [`Error::NotFound`] | 3 | a named key or identity does not exist (nothing to read is an I/O answer, not a refusal) |
//!| [`Error::Refused`] | 6 | everything reachable *said no*: wrong passphrase, unsupported key type, ambiguous selector, a claim that will not verify |
//!
//! The line between 3 and 6 is drawn on purpose. "The agent is not listening" is an
//! I/O failure the operator can fix by starting something; "the agent will not sign
// with this key" is an answer, and an answer is a refusal.

use std::fmt;

use gitiup_attest::Error as AttestError;

/// Everything in this crate that can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A format problem — a key id that is not a fingerprint, a signature that
    /// does not verify, bytes that are not canonical. Carries the format crate's
    /// own kind, so the exit code is ADR-0001's and not one invented here.
    Attest(AttestError),
    /// A file could not be read or written, or a socket could not be reached.
    Io {
        /// What was being attempted.
        context: &'static str,
        /// The specifics.
        detail: String,
        /// What to do about it.
        hint: Option<String>,
    },
    /// A key, identity or record the caller named does not exist.
    NotFound {
        /// What was looked for (`key`, `identity`, …).
        what: &'static str,
        /// The name that was not found, and where.
        detail: String,
        /// How to find out what *is* there.
        hint: Option<String>,
    },
    /// A refusal: the thing was reachable and well-formed and the answer is no.
    Refused {
        /// What was being attempted.
        context: &'static str,
        /// The specifics.
        detail: String,
        /// What to do about it.
        hint: Option<String>,
    },
}

impl Error {
    /// A format-crate `Invalid` (exit 6): the bytes are not what they claim to be.
    pub fn invalid(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::invalid(context, detail))
    }

    /// A format-crate error of `kind`, so the exit code stays ADR-0001 D7's.
    pub fn new(
        kind: gitiup_attest::ErrorKind,
        context: &'static str,
        detail: impl Into<String>,
    ) -> Error {
        Error::Attest(AttestError::new(kind, context, detail))
    }

    /// A format-crate error, keeping its kind and exit code.
    pub fn attest(error: AttestError) -> Error {
        Error::Attest(error)
    }

    /// An I/O failure (`3`).
    pub fn io(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Io {
            context,
            detail: detail.into(),
            hint: None,
        }
    }

    /// Something could not be reached: a socket that is not there, a binary that is
    /// not installed, an agent that is not running. Still `3`: it is an I/O answer.
    pub fn unreachable(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Io {
            context,
            detail: detail.into(),
            hint: Some(
                "is the agent running? `ssh-add -l` (ssh-agent) or `gpgconf --list-dirs \
                 agent-ssh-socket` (gpg-agent) answer the same question by hand"
                    .to_string(),
            ),
        }
    }

    /// A named thing does not exist (`3`).
    pub fn not_found(what: &'static str, detail: impl Into<String>) -> Error {
        Error::NotFound {
            what,
            detail: detail.into(),
            hint: None,
        }
    }

    /// A refusal (`6`).
    pub fn refused(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Refused {
            context,
            detail: detail.into(),
            hint: None,
        }
    }

    /// Attach or replace the hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Error {
        let hint = hint.into();
        match &mut self {
            Error::Io { hint: slot, .. } | Error::NotFound { hint: slot, .. } => {
                *slot = Some(hint.clone());
            }
            Error::Refused { hint: slot, .. } => *slot = Some(hint.clone()),
            // The format crate's errors carry their own hint; keep it rather than
            // silently dropping it, because that hint is the actionable part.
            Error::Attest(inner) => {
                if inner.hint().is_none() {
                    let rebuilt =
                        AttestError::new(inner.kind(), inner.context(), inner.detail().to_string());
                    *inner = rebuilt.with_hint(hint);
                }
            }
        }
        self
    }

    /// The exit code: ADR-0001's for format errors, `3` for I/O, `6` for a refusal.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Attest(inner) => inner.exit_code(),
            Error::Io { .. } | Error::NotFound { .. } => 3,
            Error::Refused { .. } => 6,
        }
    }

    /// Stable short name for `--json` output and logs.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Error::Attest(inner) => inner.kind().as_str(),
            Error::Io { .. } => "io",
            Error::NotFound { .. } => "not_found",
            Error::Refused { .. } => "refused",
        }
    }

    /// The hint, if there is one.
    pub fn hint(&self) -> Option<&str> {
        match self {
            Error::Attest(inner) => inner.hint(),
            Error::Io { hint, .. } | Error::NotFound { hint, .. } | Error::Refused { hint, .. } => {
                hint.as_deref()
            }
        }
    }

    /// The specifics, without the context prefix or the hint.
    pub fn detail(&self) -> String {
        match self {
            Error::Attest(inner) => format!("{}: {}", inner.context(), inner.detail()),
            Error::Io {
                context, detail, ..
            }
            | Error::Refused {
                context, detail, ..
            } => {
                format!("{context}: {detail}")
            }
            Error::NotFound { what, detail, .. } => format!("{what}: {detail}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail())?;
        if let Some(hint) = self.hint() {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<AttestError> for Error {
    fn from(error: AttestError) -> Error {
        Error::Attest(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::Io {
            context: "file",
            detail: error.to_string(),
            hint: None,
        }
    }
}

/// The result type used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_format_error_keeps_the_formats_exit_code() {
        // The whole point of the wrapper: `gitiup identity publish` and
        // `gitiup verify attestation` must not disagree about what a bad signature
        // costs.
        let signature = gitiup_attest::Error::new(
            gitiup_attest::ErrorKind::Signature,
            "signature",
            "does not verify",
        );
        let wrapped: Error = signature.into();
        assert_eq!(wrapped.exit_code(), 7);
        assert_eq!(wrapped.kind_name(), "bad_signature");
        assert_eq!(Error::refused("key", "no").exit_code(), 6);
        assert_eq!(Error::io("key", "gone").exit_code(), 3);
        assert_eq!(Error::not_found("key", "missing").exit_code(), 3);
    }

    #[test]
    fn a_hint_reaches_the_cli() {
        let error = Error::refused("keystore", "wrong passphrase").with_hint("try again");
        assert_eq!(error.hint(), Some("try again"));
        assert!(error.to_string().contains("try again"));
        // And a format error that already has a hint keeps its own.
        let attest =
            gitiup_attest::Error::invalid("key", "short").with_hint("the format's own advice");
        let mut wrapped: Error = attest.into();
        wrapped = wrapped.with_hint("ignored");
        assert_eq!(wrapped.hint(), Some("the format's own advice"));
    }
}

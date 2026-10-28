//! Errors, with the exit-code taxonomy of ADR-0001 D7 preserved.
//!
//! A merge gate branches on numbers (`6` refused, `7` bad signature, `8` digest
//! mismatch, `3` I/O), and it must get the same number from a quorum check that it
//! gets from `gitiup verify attestation`. So this error is a *wrapper*, not a new
//! vocabulary: an attestation problem keeps its kind and code, and only the
//! store-shaped failures get a code assigned here.

use std::fmt;

use gitiup_attest::{Error as AttestError, ErrorKind};
use gitiup_host::HostError;

/// Everything in this crate that can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A record (roster, round, verdict) is malformed, untrusted, or disagrees
    /// with a digest. Carries the format crate's kind, so the exit code is
    /// decided by ADR-0001 and not by this crate.
    Attest(AttestError),
    /// The store refused or failed. Split out because "the bucket was unreachable"
    /// is an I/O exit (`3`) and "the bucket says that ref already exists" is a
    /// refusal (`6`), and a caller must not conflate them.
    Store(StoreError),
}

/// A store failure, with the exit code already decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    /// The [`gitiup_host::HostErrorKind`] name, kept as a string so this error
    /// stays `Clone + PartialEq` without depending on host internals.
    pub kind: String,
    /// What was attempted.
    pub context: String,
    /// The store's own words.
    pub detail: String,
    /// What to do about it.
    pub hint: Option<String>,
}

impl StoreError {
    /// Wrap a host error that occurred while doing `context`.
    pub fn new(context: impl Into<String>, error: &HostError) -> StoreError {
        StoreError {
            kind: error.kind().as_str().to_string(),
            context: context.into(),
            detail: error.to_string(),
            hint: error.hint().map(str::to_string),
        }
    }

    /// A CAS conflict: someone else won the race for this ref.
    pub fn conflict(context: impl Into<String>, detail: impl Into<String>) -> StoreError {
        StoreError {
            kind: "conflict".to_string(),
            context: context.into(),
            detail: detail.into(),
            hint: Some(
                "one submission (and one roster epoch) per slot is the rule; re-read the ref \
                 before writing again"
                    .to_string(),
            ),
        }
    }

    /// The exit code: `3` for unreachable/storage, `6` for every refusal.
    pub fn exit_code(&self) -> u8 {
        match self.kind.as_str() {
            "unreachable" | "storage" | "not-found" => 3,
            _ => 6,
        }
    }
}

impl Error {
    /// A refusal that is a policy decision (`6`).
    pub fn policy(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::new(ErrorKind::Policy, context, detail))
    }

    /// A record that does not parse, or whose digests do not line up.
    pub fn invalid(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::invalid(context, detail))
    }

    /// A record this build does not understand (unknown `type`, `round_kind`,
    /// `reveal_mode`). Refusing is mandatory: guessing is how a v2 roster gets
    /// read as a v1 one.
    pub fn unsupported(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::new(
            ErrorKind::UnsupportedSchema,
            context,
            detail,
        ))
    }

    /// A published record that does not match its own re-derivation.
    pub fn digest_mismatch(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::new(ErrorKind::DigestMismatch, context, detail))
    }

    /// A signature that does not verify, or names a key that is not there.
    pub fn signature(context: &'static str, detail: impl Into<String>) -> Error {
        Error::Attest(AttestError::new(ErrorKind::Signature, context, detail))
    }

    /// A store failure. The context is the operation ("publish round", "fetch roster"),
    /// because a store error without the verb that failed is not actionable.
    pub fn store(context: impl Into<String>, error: &HostError) -> Error {
        Error::Store(StoreError::new(context, error))
    }

    /// The kind name for `--json` output and logs.
    pub fn kind(&self) -> String {
        match self {
            Error::Attest(e) => e.kind().as_str().to_string(),
            Error::Store(s) => s.kind.clone(),
        }
    }

    /// `context: detail`, with no hint appended.
    ///
    /// `Display` renders the hint inline because a library user printing one line wants
    /// the whole answer; a CLI prints the message and the hint on separate lines, and
    /// needs the two parts to stay apart.
    pub fn message(&self) -> String {
        match self {
            Error::Attest(e) => format!("{}: {}", e.context(), e.detail()),
            Error::Store(s) => format!("{}: {}: {}", s.context, s.kind, s.detail),
        }
    }

    /// The process exit code (`3` I/O, `6` refused, `7` bad signature, `8` digest
    /// mismatch).
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Attest(e) => e.exit_code(),
            Error::Store(s) => s.exit_code(),
        }
    }

    /// The hint, if there is one (the CLI prints it on its own line).
    pub fn hint(&self) -> Option<&str> {
        match self {
            Error::Attest(e) => e.hint(),
            Error::Store(s) => s.hint.as_deref(),
        }
    }

    /// Attach a hint (format-carrying errors only; a store error already has one).
    pub fn with_hint(self, hint: impl Into<String>) -> Error {
        match self {
            Error::Attest(e) => Error::Attest(e.with_hint(hint)),
            other => other,
        }
    }
}

impl From<AttestError> for Error {
    fn from(error: AttestError) -> Error {
        Error::Attest(error)
    }
}

impl From<HostError> for Error {
    fn from(error: HostError) -> Error {
        Error::Store(StoreError::new("store", &error))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Attest(e) => write!(f, "{e}"),
            Error::Store(s) => {
                write!(f, "{}: {}: {}", s.context, s.kind, s.detail)?;
                if let Some(hint) = &s.hint {
                    write!(f, "; {hint}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, Error>;

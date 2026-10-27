//! The error taxonomy of the format.
//!
//! `gitiup verify attestation` (giti-1rs.8) exits with a code that scripts and
//! merge gates branch on, so the mapping from error to exit code lives *here*,
//! next to the thing that raises it, and not in the CLI: a library user running
//! the same checks must get the same verdict. See
//! [ADR-0001 D7](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md).

use std::error::Error as StdError;
use std::fmt;

/// Anything that can go wrong reading, checking or verifying an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    context: &'static str,
    detail: String,
    hint: Option<String>,
}

/// What class of failure this is; drives the `gitiup verify` exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The bytes are not a well-formed record of this version: bad canonical
    /// encoding, unknown field, missing field, out-of-range value.
    Invalid,
    /// Well-formed, but from a format version this build does not speak
    /// (`schema_version` / `type` we do not know).
    UnsupportedSchema,
    /// The received manifest is not byte-identical to its own canonical
    /// re-encoding, or the claimed digest is not the digest of the bytes.
    DigestMismatch,
    /// A signature does not verify, or names a key that is not present.
    Signature,
    /// The record is well-formed and authentic but policy refuses it: untrusted
    /// signer, expired or too-fresh clock claim, disallowed provenance tier,
    /// too few signatures.
    Policy,
}

impl ErrorKind {
    /// The `gitiup verify attestation` exit code for this class
    /// (0 = ok, 6 = refused by policy, 7 = bad signature, 8 = digest mismatch).
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorKind::Policy | ErrorKind::Invalid | ErrorKind::UnsupportedSchema => 6,
            ErrorKind::Signature => 7,
            ErrorKind::DigestMismatch => 8,
        }
    }

    /// Stable short name for `--json` output and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Policy => "policy",
            ErrorKind::Invalid => "invalid",
            ErrorKind::UnsupportedSchema => "unsupported_schema",
            ErrorKind::DigestMismatch => "digest_mismatch",
            ErrorKind::Signature => "bad_signature",
        }
    }
}

impl Error {
    /// A new error of [`ErrorKind::Invalid`].
    pub fn invalid(context: &'static str, detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, context, detail)
    }

    /// A new error of `kind`.
    pub fn new(kind: ErrorKind, context: &'static str, detail: impl Into<String>) -> Self {
        Error {
            kind,
            context,
            detail: detail.into(),
            hint: None,
        }
    }

    /// Attach a human hint (printed by the CLI, ignored by `--json`).
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The failure class.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// What was being read when the failure happened.
    pub fn context(&self) -> &'static str {
        self.context
    }

    /// The specifics.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The suggested fix, if there is one.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// The exit code this error maps to.
    pub fn exit_code(&self) -> u8 {
        self.kind.exit_code()
    }

    /// True when the failure means "the bytes are not what they claim to be"
    /// (as opposed to "we refuse to accept them").
    pub fn is_integrity_failure(&self) -> bool {
        matches!(self.kind, ErrorKind::DigestMismatch | ErrorKind::Signature)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.detail)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

impl StdError for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

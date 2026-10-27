//! The host error taxonomy.
//!
//! Every fallible operation in this crate returns [`HostError`]. The five
//! variants named in the host design are the ones call sites branch on:
//!
//! | variant              | meaning                                                        |
//! |----------------------|----------------------------------------------------------------|
//! | [`HostError::Unreachable`]      | the host could not be talked to (network, DNS, socket, timeout, missing directory) |
//! | [`HostError::UnsupportedCas`]   | the host cannot honour a CAS/atomicity requirement, a capability is missing, or an operation/format is not implemented by this host |
//! | [`HostError::Conflict`]         | a compare-and-swap did not match: the ref (or object state) moved underneath us |
//! | [`HostError::PermissionDenied`] | we reached the host but are not allowed to do this             |
//! | [`HostError::SchemeUnknown`]    | a remote URI uses a scheme no host handles; the message lists what is supported |
//!
//! The remaining variants ([`HostError::NotFound`], [`HostError::Invalid`],
//! [`HostError::Storage`]) are plumbing: they are answerable by the user but
//! rarely branched on.
//!
//! Matching is stable: new variants are added only with a ticket that teaches
//! every call site about them, and [`HostError::kind`] gives a string-ish
//! discriminator for `--json` output and logs.

use std::error::Error;
use std::fmt;
use std::io;

use crate::oid::Oid;

/// Convenience alias for everything in this crate.
pub type HostResult<T> = Result<T, HostError>;

/// String-ish discriminator for the error taxonomy, used by `--json` output and
/// log lines (see the table in the [module docs](crate::error)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostErrorKind {
    /// Host could not be reached.
    Unreachable,
    /// Capability/CAS/operation not supported by this host.
    UnsupportedCas,
    /// Compare-and-swap mismatch.
    Conflict,
    /// Authenticated but not permitted.
    PermissionDenied,
    /// URI scheme is not handled by any host.
    SchemeUnknown,
    /// Object or ref does not exist.
    NotFound,
    /// Malformed input, config or stored data.
    Invalid,
    /// Low-level storage failure.
    Storage,
}

impl HostErrorKind {
    /// Stable kebab-case name (used in machine-readable output).
    pub fn as_str(self) -> &'static str {
        match self {
            HostErrorKind::Unreachable => "unreachable",
            HostErrorKind::UnsupportedCas => "unsupported-cas",
            HostErrorKind::Conflict => "conflict",
            HostErrorKind::PermissionDenied => "permission-denied",
            HostErrorKind::SchemeUnknown => "scheme-unknown",
            HostErrorKind::NotFound => "not-found",
            HostErrorKind::Invalid => "invalid",
            HostErrorKind::Storage => "storage",
        }
    }
}

impl fmt::Display for HostErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error type shared by all host operations.
#[derive(Debug)]
pub enum HostError {
    /// The host could not be talked to.
    Unreachable(Box<Unreachable>),
    /// The host (or this build) cannot honour the request.
    UnsupportedCas(Box<UnsupportedCas>),
    /// A CAS precondition failed: the stored state is not what we expected.
    Conflict(Box<Conflict>),
    /// The host reached us but refuses the operation.
    PermissionDenied(Box<PermissionDenied>),
    /// Nobody handles this URI scheme.
    SchemeUnknown(Box<SchemeUnknown>),
    /// A ref, blob or pack is not there.
    NotFound(Box<NotFound>),
    /// Caller gave us something malformed (URI, config, ref name, pack...).
    Invalid(Box<Invalid>),
    /// Raw storage failure (I/O) with context.
    Storage(Box<StorageError>),
}

impl HostError {
    /// The taxonomy discriminator.
    pub fn kind(&self) -> HostErrorKind {
        match self {
            HostError::Unreachable(_) => HostErrorKind::Unreachable,
            HostError::UnsupportedCas(_) => HostErrorKind::UnsupportedCas,
            HostError::Conflict(_) => HostErrorKind::Conflict,
            HostError::PermissionDenied(_) => HostErrorKind::PermissionDenied,
            HostError::SchemeUnknown(_) => HostErrorKind::SchemeUnknown,
            HostError::NotFound(_) => HostErrorKind::NotFound,
            HostError::Invalid(_) => HostErrorKind::Invalid,
            HostError::Storage(_) => HostErrorKind::Storage,
        }
    }

    /// Whether retrying the same call could plausibly succeed (transient
    /// transport trouble or a CAS race, as opposed to bad input or a refusal).
    pub fn is_retryable(&self) -> bool {
        match self {
            HostError::Unreachable(e) => e.retryable,
            HostError::Conflict(_) => true,
            HostError::Storage(_) => false,
            _ => false,
        }
    }

    /// Shorthand for [`HostError::Unreachable`].
    pub fn unreachable(message: impl Into<String>) -> Self {
        HostError::Unreachable(Box::new(Unreachable {
            endpoint: None,
            message: message.into(),
            retryable: true,
            hint: None,
            source: None,
        }))
    }

    /// Shorthand for [`HostError::UnsupportedCas`]: `capability` is what the
    /// caller needed (e.g. `"cas"`, `"atomic-multi-write"`, `"pack-format:git"`).
    pub fn unsupported(capability: impl Into<String>, message: impl Into<String>) -> Self {
        HostError::UnsupportedCas(Box::new(UnsupportedCas {
            capability: capability.into(),
            message: message.into(),
            hint: None,
        }))
    }

    /// Shorthand for [`HostError::PermissionDenied`].
    pub fn denied(action: impl Into<String>) -> Self {
        HostError::PermissionDenied(Box::new(PermissionDenied {
            action: action.into(),
            actor: None,
            hint: None,
        }))
    }

    /// Shorthand for [`HostError::NotFound`].
    pub fn not_found(what: impl Into<String>, key: impl Into<String>) -> Self {
        HostError::NotFound(Box::new(NotFound {
            what: what.into(),
            key: key.into(),
            hint: None,
        }))
    }

    /// Shorthand for [`HostError::Invalid`].
    pub fn invalid(what: impl Into<String>, message: impl Into<String>) -> Self {
        HostError::Invalid(Box::new(Invalid {
            what: what.into(),
            message: message.into(),
            hint: None,
            location: None,
            source: None,
        }))
    }

    /// Shorthand for [`HostError::Conflict`] from a CAS expectation failure.
    pub fn conflict(name: impl Into<String>, expected: Option<Oid>, found: Option<Oid>) -> Self {
        HostError::Conflict(Box::new(Conflict {
            name: name.into(),
            expected,
            found,
            actor: None,
            hint: None,
        }))
    }

    /// Wrap an [`io::Error`] with the path it happened on, mapping "missing"
    /// onto [`HostError::NotFound`] and everything else onto
    /// [`HostError::Storage`].
    pub fn from_io(what: impl Into<String>, path: &std::path::Path, err: io::Error) -> Self {
        let key = path.display().to_string();
        match err.kind() {
            io::ErrorKind::NotFound => HostError::not_found(what, key),
            io::ErrorKind::PermissionDenied => {
                HostError::denied(format!("accessing {} ({err})", path.display()))
            }
            _ => HostError::Storage(Box::new(StorageError {
                what: what.into(),
                key,
                message: err.to_string(),
                retryable: matches!(
                    err.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ),
                source: Some(Box::new(err)),
            })),
        }
    }

    /// Attach a hint to any error (builder-style).
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        let hint = Some(hint.into());
        match &mut self {
            HostError::Unreachable(e) => e.hint = hint,
            HostError::UnsupportedCas(e) => e.hint = hint,
            HostError::Conflict(e) => e.hint = hint,
            HostError::PermissionDenied(e) => e.hint = hint,
            HostError::SchemeUnknown(e) => e.hint = hint,
            HostError::NotFound(e) => e.hint = hint,
            HostError::Invalid(e) => e.hint = hint,
            HostError::Storage(_) => {}
        }
        self
    }

    /// The hint, if any.
    pub fn hint(&self) -> Option<&str> {
        match self {
            HostError::Unreachable(e) => e.hint.as_deref(),
            HostError::UnsupportedCas(e) => e.hint.as_deref(),
            HostError::Conflict(e) => e.hint.as_deref(),
            HostError::PermissionDenied(e) => e.hint.as_deref(),
            HostError::SchemeUnknown(e) => e.hint.as_deref(),
            HostError::NotFound(e) => e.hint.as_deref(),
            HostError::Invalid(e) => e.hint.as_deref(),
            HostError::Storage(_) => None,
        }
    }

    /// Human-readable "what went wrong" without the taxonomy prefix; used by the
    /// CLI so `gitiup` can print `error: <message>` + `hint: <hint>`.
    pub fn message(&self) -> String {
        match self {
            HostError::Unreachable(e) => e.message.clone(),
            HostError::UnsupportedCas(e) => format!("{}: {}", e.capability, e.message),
            HostError::Conflict(e) => format!(
                "ref {} did not match the expected value (expected {}, found {})",
                e.name,
                e.expected.map(oid_label).unwrap_or_else(|| "absent".into()),
                e.found.map(oid_label).unwrap_or_else(|| "absent".into()),
            ),
            HostError::PermissionDenied(e) => format!("not allowed to {}", e.action),
            HostError::SchemeUnknown(e) => e.to_string(),
            HostError::NotFound(e) => format!("{} {} not found", e.what, e.key),
            HostError::Invalid(e) => e.message.clone(),
            HostError::Storage(e) => e.message.clone(),
        }
    }
}

/// View a boxed source error as a plain `&dyn Error`.
fn boxed_source<'a>(
    slot: &'a Option<Box<dyn Error + Send + Sync + 'static>>,
) -> Option<&'a (dyn Error + 'static)> {
    slot.as_ref().map(|b| &**b as &(dyn Error + 'static))
}

fn oid_label(oid: Oid) -> String {
    format!("{}", oid)
}

fn write_hint(f: &mut fmt::Formatter<'_>, hint: Option<&str>) -> fmt::Result {
    if let Some(hint) = hint {
        write!(f, " (hint: {hint})")?;
    }
    Ok(())
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind(), self.message())?;
        write_hint(f, self.hint())
    }
}

impl Error for HostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HostError::Unreachable(e) => boxed_source(&e.source),
            HostError::Invalid(e) => boxed_source(&e.source),
            HostError::Storage(e) => boxed_source(&e.source),
            _ => None,
        }
    }
}

impl From<io::Error> for HostError {
    fn from(err: io::Error) -> Self {
        HostError::from_io("storage operation", std::path::Path::new(""), err)
    }
}

/// The host could not be talked to.
#[derive(Debug)]
pub struct Unreachable {
    /// Endpoint we tried to reach (`s3://bucket`, `https://host/repo`, a path...).
    pub endpoint: Option<String>,
    /// What went wrong.
    pub message: String,
    /// Whether a retry may help (connection reset vs. DNS NXDOMAIN).
    pub retryable: bool,
    /// Actionable next step.
    pub hint: Option<String>,
    /// Underlying error, if any.
    pub source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl Unreachable {
    /// Builder: record the endpoint.
    pub fn at(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
}

/// A required capability, CAS guarantee or operation is not available here.
///
/// Also used for "this host does not implement that format/operation": pass the
/// feature as `capability` (e.g. `"pack-format:git"`).
#[derive(Debug)]
pub struct UnsupportedCas {
    /// Capability or feature that was required, e.g. `cas`, `immutable`,
    /// `atomic-multi-write`, `pack-format:git`.
    pub capability: String,
    /// What went wrong.
    pub message: String,
    /// Actionable next step for the user.
    pub hint: Option<String>,
}

/// A compare-and-swap precondition failed.
#[derive(Debug)]
pub struct Conflict {
    /// Ref or object name that moved.
    pub name: String,
    /// What we asked for (`None` = "must not exist").
    pub expected: Option<Oid>,
    /// What the host actually had (`None` = absent).
    pub found: Option<Oid>,
    /// Actor that moved it, when the host records that.
    pub actor: Option<crate::refs::Actor>,
    /// Actionable next step.
    pub hint: Option<String>,
}

/// Reached the host, but not permitted.
#[derive(Debug)]
pub struct PermissionDenied {
    /// The action we attempted.
    pub action: String,
    /// Identity we tried to act as.
    pub actor: Option<crate::refs::Actor>,
    /// Actionable next step (e.g. which credentials profile was used).
    pub hint: Option<String>,
}

/// No host implementation handles this URI scheme.
#[derive(Debug)]
pub struct SchemeUnknown {
    /// The scheme seen (without `://`), or the rejected URI when there was no
    /// parseable scheme at all.
    pub scheme: String,
    /// Schemes this build can talk to, e.g. `["s3", "https", "ssh", "file"]`.
    pub supported: Vec<String>,
    /// Actionable next step, e.g. "plain http:// is not supported, use https://".
    pub hint: Option<String>,
}

impl fmt::Display for SchemeUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported remote scheme '{}' (supported: {})",
            self.scheme,
            self.supported.join(", ")
        )
    }
}

/// A ref, blob or pack is absent.
#[derive(Debug)]
pub struct NotFound {
    /// What kind of thing was missing ("ref", "blob", "pack").
    pub what: String,
    /// Its name or digest.
    pub key: String,
    /// Actionable next step.
    pub hint: Option<String>,
}

/// Malformed input, configuration or stored data.
#[derive(Debug)]
pub struct Invalid {
    /// What was being parsed ("remote url", "gitiup.toml", "ref name", "pack").
    pub what: String,
    /// What is wrong.
    pub message: String,
    /// Actionable next step.
    pub hint: Option<String>,
    /// Where the problem is, e.g. `gitiup.toml:12:5`.
    pub location: Option<String>,
    /// Underlying error, if any.
    pub source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl Invalid {
    /// Builder: record the location of the problem.
    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.what, self.message)?;
        if let Some(location) = &self.location {
            write!(f, " [{location}]")?;
        }
        Ok(())
    }
}

/// Low-level storage failure.
#[derive(Debug)]
pub struct StorageError {
    /// What we were doing ("write ref file", "read blob").
    pub what: String,
    /// Path or key involved.
    pub key: String,
    /// Raw failure text.
    pub message: String,
    /// Whether a retry may help.
    pub retryable: bool,
    /// Underlying error, if any.
    pub source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.key)
    }
}

/// Convenience for turning "host says no" into a message the CLI prints.
pub trait HostErrorExt {
    /// Whether this is a capability refusal.
    fn is_unsupported(&self) -> bool;
    /// Whether this is a CAS conflict.
    fn is_conflict(&self) -> bool;
    /// Whether this is a reachability problem.
    fn is_unreachable(&self) -> bool;
    /// Whether this is a permission refusal.
    fn is_denied(&self) -> bool;
}

impl HostErrorExt for HostError {
    fn is_unsupported(&self) -> bool {
        matches!(self, HostError::UnsupportedCas(_))
    }
    fn is_conflict(&self) -> bool {
        matches!(self, HostError::Conflict(_))
    }
    fn is_unreachable(&self) -> bool {
        matches!(self, HostError::Unreachable(_))
    }
    fn is_denied(&self) -> bool {
        matches!(self, HostError::PermissionDenied(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_stable_strings() {
        assert_eq!(HostErrorKind::UnsupportedCas.as_str(), "unsupported-cas");
        assert_eq!(HostErrorKind::SchemeUnknown.as_str(), "scheme-unknown");
        assert_eq!(
            HostError::denied("push").kind(),
            HostErrorKind::PermissionDenied
        );
    }

    #[test]
    fn conflict_message_shows_both_sides() {
        let expected = Oid::from_hex("aabb").unwrap();
        let found = Oid::from_hex("bbcc").unwrap();
        let err = HostError::conflict("refs/heads/main", Some(expected), Some(found));
        let text = err.to_string();
        assert!(text.starts_with("conflict:"), "{text}");
        assert!(text.contains("refs/heads/main"), "{text}");
        assert!(text.contains("aabb") && text.contains("bbcc"), "{text}");
        assert!(err.is_retryable());
    }

    #[test]
    fn scheme_unknown_lists_supported_schemes() {
        let err = HostError::SchemeUnknown(Box::new(SchemeUnknown {
            scheme: "git".into(),
            supported: vec!["s3".into(), "https".into(), "ssh".into(), "file".into()],
            hint: Some("use ssh:// for git-over-ssh".into()),
        }));
        let text = err.to_string();
        assert!(text.contains("s3, https, ssh, file"), "{text}");
        assert!(text.contains("hint:"), "{text}");
    }

    #[test]
    fn io_not_found_maps_to_not_found() {
        let err = io::Error::new(io::ErrorKind::NotFound, "nope");
        let mapped = HostError::from_io("blob", std::path::Path::new("/tmp/x"), err);
        assert_eq!(mapped.kind(), HostErrorKind::NotFound);
    }
}

//! What a host registration says about itself: how to make one, how to make a
//! second, what it may skip, and what it must never quietly skip.
//!
//! A [`Registration`] is deliberately a plain `const`: it is written by the host's
//! author, read by the [`test_host!`](crate::test_host!) macro, and audited by
//! `tests/coverage.rs`. Everything in it is data the CI can reason about without
//! running anything — which is what makes a skip a statement rather than an
//! excuse.

use std::any::Any;
use std::fmt;

use gitiup_host::{Host, HostKind, HostResult};

/// One host, plus whatever has to stay alive for it to keep working.
///
/// A scratch directory, a spawned web server, a bucket provisioning call: each
/// host needs something held open, and the runner needs to drop it after the
/// body finishes rather than at process exit. So the factory hands it over as an
/// opaque guard.
pub struct Session {
    /// The host under test.
    host: Box<dyn Host>,
    /// Dropped when the session is dropped, in the order they were added.
    _guards: Vec<Box<dyn Any + Send>>,
}

impl Session {
    /// A host with nothing to hold open.
    pub fn new(host: impl Host + 'static) -> Session {
        Session {
            host: Box::new(host),
            _guards: Vec::new(),
        }
    }

    /// A host plus one guard (a `TempDir`, a `Child`, a bucket handle).
    pub fn with<G: Any + Send + 'static>(mut self, guard: G) -> Session {
        self._guards.push(Box::new(guard));
        self
    }

    /// A host plus several guards.
    pub fn with_all(mut self, guards: Vec<Box<dyn Any + Send>>) -> Session {
        self._guards.extend(guards);
        self
    }

    /// The host to hand a body.
    pub fn host(&self) -> &dyn Host {
        self.host.as_ref()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Session({} [{} guard(s)])",
            self.host.describe().summary_line(),
            self._guards.len()
        )
    }
}

/// Builds one fresh store and hands back a host for it.
///
/// Called once per body, so "fresh" means genuinely fresh: a body may count what
/// it just wrote. A store that cannot be made is a `HostError`, which the runner
/// turns into a failure (or, when the registration is not
/// [`available`](Registration::available), a skip).
pub type Make = fn() -> HostResult<Session>;

/// Whether a registration can stand up its store right now.
///
/// Returns `true` when it can; `false` means the suite prints why and moves on.
/// This is for the environment (no MinIO configured, no `git` binary), never for
/// "this host is inconvenient".
pub type Available = fn() -> bool;

/// The secret a denial must not repeat, if there is one.
///
/// For a live bucket this is the real secret access key: a host that prints it in
/// an error is a leak, and the denial body checks exactly that.
pub type DeniedSecret = fn() -> Option<String>;

/// Stands up one decoy run: a host whose endpoint answers every request with a redirect
/// to a second origin, plus the credential that must never arrive there.
///
/// A separate `Make` shape rather than a plain one because the run needs to hand back
/// more than a host: the body has to know which token to look for and which slice of the
/// shared decoy's log is this run's.
pub type DecoyMake = fn() -> HostResult<Decoy>;

/// How heavy the two size-shaped bodies should be for this host.
///
/// Defaults are tuned for a laptop run; CI raises them (a bucket's LIST pages
/// are 1 000 keys, and its multipart threshold is 8 MiB, so a suite that never
/// crosses those numbers has not tested either).
#[derive(Debug, Clone, Copy)]
pub struct Knobs {
    /// Total bytes in the "huge pack" body's pack.
    pub pack_bytes: usize,
    /// Blobs to store for the listing/pagination body.
    pub list_count: usize,
    /// Refs to publish for the listing/pagination body.
    pub ref_count: usize,
    /// Threads contending for one ref in the concurrency body.
    pub writers: usize,
}

impl Default for Knobs {
    fn default() -> Knobs {
        Knobs {
            pack_bytes: 2 * 1024 * 1024,
            list_count: 96,
            ref_count: 32,
            writers: 6,
        }
    }
}

impl Knobs {
    /// Everything at one number, for a host that wants a cheap or a heavy run
    /// across the board.
    pub fn scaled(pack_bytes: usize, list_count: usize, ref_count: usize) -> Knobs {
        Knobs {
            pack_bytes,
            list_count,
            ref_count,
            ..Default::default()
        }
    }
}

/// How a host reacted to credentials it does not have.
#[derive(Debug)]
pub enum DenialOutcome {
    /// The host refused before it could be built (the usual case: the first call
    /// out is the one that fails).
    Refused {
        /// The refusal, which must be a `PermissionDenied`.
        error: gitiup_host::HostError,
    },
    /// The host built and every operation refuses. Some transports only find out
    /// on the first real call, so both shapes have to be accepted — but "accepted
    /// and then worked" is not one of them.
    Built {
        /// The built session, every entry point of which must deny.
        session: Session,
    },
}

/// A host's answer to refused credentials, plus what the body needs to know
/// about how that answer was rendered.
#[derive(Debug)]
pub struct Denial {
    /// What the registration said this denial is (`"minio with a revoked key"`).
    pub label: &'static str,
    /// The answer itself.
    pub outcome: DenialOutcome,
    /// The credential value no message may print.
    pub secret: Option<String>,
    /// Error text the body collected while poking every entry point.
    messages: std::sync::Mutex<Vec<String>>,
}

impl Denial {
    /// One denial, as the runner built it.
    pub fn new(label: &'static str, outcome: DenialOutcome, secret: Option<String>) -> Denial {
        Denial {
            label,
            outcome,
            secret,
            messages: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Whether `secret` appears anywhere a caller might see it.
    pub fn leaks(&self, secret: &str) -> bool {
        let mut texts: Vec<String> = match &self.outcome {
            DenialOutcome::Refused { error } => vec![error.to_string()],
            DenialOutcome::Built { session } => vec![
                session.host().describe().summary_line(),
                format!("{:?}", session.host().capabilities()),
            ],
        };
        texts.extend(self.messages.lock().unwrap().iter().cloned());
        texts.iter().any(|text| text.contains(secret))
    }

    /// Error text the body collected while poking every entry point; kept so the
    /// leak check covers the messages a user would actually read.
    pub fn record(&self, message: String) {
        self.messages.lock().unwrap().push(message);
    }
}

/// How a host reacted when its endpoint redirected to a decoy origin while a credential
/// was configured for it.
///
/// Same two shapes as a denial, for the same reason: some transports find out on the
/// first call and some refuse at open. What is not a shape is "it worked, and the token
/// went along" — that is the failure the body exists to catch.
#[derive(Debug)]
pub enum DecoyOutcome {
    /// The host refused to be built at all (the usual honest answer: a credential this
    /// host cannot scope is refused before a byte moves).
    Refused {
        /// The refusal.
        error: gitiup_host::HostError,
    },
    /// The host built; every call it makes is under the redirect's shadow.
    Built {
        /// The session to poke.
        session: Session,
    },
}

/// One decoy run, as the registration set it up.
///
/// The body needs four facts and cannot rediscover any of them: which token must not
/// arrive, where it was configured to go, where the redirect pointed, and which slice of
/// the shared decoy's log belongs to this run (`probe` — a unique path fragment, because
/// the decoy is process-wide and other registrations may be redirecting over it at the
/// same time).
#[derive(Debug)]
pub struct Decoy {
    /// What the registration called this variant.
    pub label: &'static str,
    /// What the host answered.
    pub outcome: DecoyOutcome,
    /// The credential value that must never reach the decoy.
    pub token: String,
    /// The origin the credential was configured for.
    pub configured: String,
    /// The decoy origin the redirect pointed at.
    pub target: String,
    /// The unique path fragment this run's requests carry.
    pub probe: String,
}

impl Decoy {
    /// Everything this run did that either port saw.
    ///
    /// `None` when the endpoint could not be asked at all (a broken fixture — say so, do
    /// not read it as an empty list). The list is normally empty on the decoy side and
    /// non-empty on the origin side, and both halves of that matter: an origin with no
    /// arrival means the run never made the request, which would make "nothing reached the
    /// decoy" true for the wrong reason.
    pub fn arrivals(&self) -> Option<Vec<crate::fixtures::Arrival>> {
        crate::fixtures::decoy_pair()?.arrivals(&self.probe)
    }
}

/// One host the suite covers.
///
/// `make` is called once per body; `skips` is the audit trail; `denied` and
/// `degraded` are the two shapes a host can only be asked about by standing up a
/// second, deliberately broken variant of itself.
pub struct Registration {
    /// Stable name, used in test names and CI output (`fs`, `s3-minio`, ...).
    pub name: &'static str,
    /// Which kind of host this claims to be.
    pub kind: HostKind,
    /// Make one fresh store.
    pub make: Make,
    /// Can this host be stood up in this environment at all?
    pub available: Available,
    /// What to print when it cannot.
    pub unavailable: &'static str,
    /// Sizes for the size-shaped bodies.
    pub knobs: Knobs,
    /// Bodies this host does not run, each with the reason it does not.
    ///
    /// A body listed here with an empty reason is an error, and a body *not*
    /// listed here that this host cannot run is an error too — see
    /// [`crate::account`].
    pub skips: &'static [(&'static str, &'static str)],
    /// A variant whose credentials are refused (expired, revoked, wrong).
    pub denied: Option<Make>,
    /// Whether this host can produce that variant here (default: yes whenever it
    /// declares one). A bucket needs CI's cooperation to be handed revoked
    /// credentials; that is an environment fact, not a judgement about the host.
    pub denied_available: Available,
    /// What to print when the refused-credentials variant cannot be produced.
    pub denied_unavailable: &'static str,
    /// The credential value `denied` plays with, which no error may print.
    pub denied_secret: DeniedSecret,
    /// A variant reached as a **stranger**: no credential of any kind, on a store that
    /// has content in it. `None` where there is no such thing — a directory's credential
    /// is the filesystem.
    pub anonymous: Option<Make>,
    /// Whether that variant can be produced here.
    pub anonymous_available: Available,
    /// What to print when it cannot.
    pub anonymous_unavailable: &'static str,
    /// A variant whose endpoint redirects a **configured credential** to a decoy origin
    /// (giti-g5c.5). `None` where the transport has no origin to redirect from.
    pub decoy: Option<DecoyMake>,
    /// Whether that variant can be produced here.
    pub decoy_available: Available,
    /// What to print when it cannot.
    pub decoy_unavailable: &'static str,
    /// A variant that reports `cas = false`.
    pub degraded: Option<Make>,
    /// Whether that variant can be produced here.
    pub degraded_available: Available,
    /// What to print when it cannot.
    pub degraded_unavailable: &'static str,
}

impl Registration {
    /// Why this host is not running in this environment, if it is not.
    pub fn skip_note(&self) -> Option<&'static str> {
        if (self.available)() {
            None
        } else {
            Some(self.unavailable)
        }
    }

    /// Why the refused-credentials variant is not available, if it is not.
    pub fn denial_skip_note(&self) -> Option<&'static str> {
        if self.denied.is_none() {
            return Some("this host declares no refused-credentials variant");
        }
        if (self.denied_available)() {
            None
        } else {
            Some(self.denied_unavailable)
        }
    }

    /// Why the stranger (no-credential) variant is not available, if it is not.
    pub fn anonymous_skip_note(&self) -> Option<&'static str> {
        if self.anonymous.is_none() {
            return Some("this host declares no no-credential variant");
        }
        if (self.anonymous_available)() {
            None
        } else {
            Some(self.anonymous_unavailable)
        }
    }

    /// Why the redirect-to-decoy variant is not available, if it is not.
    pub fn decoy_skip_note(&self) -> Option<&'static str> {
        if self.decoy.is_none() {
            return Some("this host declares no redirect-to-decoy variant");
        }
        if (self.decoy_available)() {
            None
        } else {
            Some(self.decoy_unavailable)
        }
    }

    /// Why the `cas = false` variant is not available, if it is not.
    pub fn degradation_skip_note(&self) -> Option<&'static str> {
        if self.degraded.is_none() {
            return Some("this host declares no cas=false variant");
        }
        if (self.degraded_available)() {
            None
        } else {
            Some(self.degraded_unavailable)
        }
    }

    /// The declared reason for skipping `body`, if any.
    pub fn skip_reason(&self, body: &str) -> Option<&'static str> {
        self.skips
            .iter()
            .find(|(name, _)| *name == body)
            .map(|(_, reason)| *reason)
    }

    /// Whether this registration declares a body without explaining it.
    pub fn is_silent_skip(&self, body: &str) -> bool {
        self.skips
            .iter()
            .any(|(name, reason)| *name == body && reason.trim().is_empty())
    }
}

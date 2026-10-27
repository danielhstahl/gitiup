//! Running one body against one host, and accounting for every body a host did
//! not run.
//!
//! Two paths, because there are two questions.
//!
//! [`require_body`] is the `#[test]` path: it decides whether the body applies,
//! builds the stores, and then *lets the body's own panic escape*, so a failure
//! shows up as the assertion that failed — its message, its file, its line — with
//! a backtrace if you ask for one. Catching a panic to rethrow a summary loses
//! exactly the information a failing host needs you to have.
//!
//! [`report`] is the report path: it catches, and hands back one line per failure
//! for a human who wants the whole matrix at once. It captures the panic message
//! through a panic hook, because that is the only place the rendered text is
//! guaranteed to be reachable.
//!
//! And because "we did not run that" is the failure mode a conformance suite is
//! most likely to hide, [`account`] turns an unexplained skip into a failing test.
//!
//! Environment knobs:
//!
//! * `GITIUP_CONFORMANCE_REQUIRE_HOSTS` — comma-separated host names that must be
//!   available here. CI sets it, so a MinIO service that failed to start fails
//!   the build instead of quietly skipping the bucket.
//! * `GITIUP_CONFORMANCE_REQUIRE_CAS` — `1` turns "this host has no CAS, skipping
//!   the CAS bodies" from a note into a failure.
//! * `GITIUP_CONFORMANCE_PACK_BYTES`, `GITIUP_CONFORMANCE_LIST_COUNT`,
//!   `GITIUP_CONFORMANCE_REF_COUNT` — raise the sizes without recompiling.

use std::cell::RefCell;

use crate::bodies::{Body, Ctx, Shape};
use crate::registration::{Denial, DenialOutcome, Knobs, Registration, Session};

/// Where CI names the hosts that must be running.
pub const REQUIRE_HOSTS: &str = "GITIUP_CONFORMANCE_REQUIRE_HOSTS";
/// Where CI says a host may not be allowed to lack CAS.
pub const REQUIRE_CAS: &str = "GITIUP_CONFORMANCE_REQUIRE_CAS";

/// Whether the environment demands this host be running.
pub fn required_in_ci(registration: &Registration) -> bool {
    std::env::var(REQUIRE_HOSTS)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .any(|name| !name.is_empty() && name == registration.name)
}

/// Whether a missing CAS is allowed to be a skip.
pub fn cas_is_required() -> bool {
    std::env::var(REQUIRE_CAS)
        .map(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// The stores a body was handed, kept alive for as long as the body runs.
pub struct Setup {
    /// The store under test. Absent only for the denied shape, where the answer is
    /// the refusal itself.
    host: Option<Session>,
    peer: Option<Session>,
    degraded: Option<Session>,
    denial: Option<Denial>,
    knobs: Knobs,
}

/// What the runner decided about one (host, body) pair.
pub enum Plan {
    /// The body does not apply, and the reason a human must see.
    Skip(&'static str),
    /// The host could not be made to answer at all: a failure, not a skip.
    Fail(String),
    /// Ready: here are the stores.
    Run(Box<Setup>),
}

/// Decide what to do, and build whatever is needed — without catching anything.
pub fn plan(body: &Body, registration: &'static Registration) -> Plan {
    if let Some(reason) = registration.skip_reason(body.name) {
        return Plan::Skip(reason);
    }

    // The refused-credentials variant is asked even when the host itself cannot be
    // stood up, because in a revoked-credential run that is the entire point: the
    // environment says "this endpoint refuses these credentials", and what is under
    // test is the shape of the refusal, not the store behind it.
    if body.shape == Shape::Denied {
        return match registration.denial_skip_note() {
            Some(note) => Plan::Skip(note),
            None => match make_denial(registration) {
                Ok(denial) => Plan::Run(Box::new(Setup {
                    host: None,
                    peer: None,
                    degraded: None,
                    denial: Some(denial),
                    knobs: Knobs::default(),
                })),
                Err(why) => Plan::Fail(why),
            },
        };
    }

    if let Some(note) = registration.skip_note() {
        return if required_in_ci(registration) {
            Plan::Fail(format!(
                "{REQUIRE_HOSTS} names this host, but it is not available here: {note}"
            ))
        } else {
            Plan::Skip(note)
        };
    }

    let host = match (registration.make)() {
        Ok(session) => session,
        Err(err) => {
            return Plan::Fail(format!("cannot make a {} store: {err}", registration.name));
        }
    };
    if body.requires_cas && !host.host().capabilities().cas {
        return if cas_is_required() {
            Plan::Fail(format!(
                "{REQUIRE_CAS} is set and this host reports cas = false, so every \
                 CAS-dependent body would have been skipped"
            ))
        } else {
            Plan::Skip("the host reports cas = false, so CAS-dependent bodies do not apply")
        };
    }

    let peer = match body.shape {
        Shape::Pair => match (registration.make)() {
            Ok(session) => Some(session),
            Err(err) => {
                return Plan::Fail(format!(
                    "cannot make a second {} store: {err}",
                    registration.name
                ));
            }
        },
        _ => None,
    };

    if body.shape == Shape::Degraded
        && let Some(note) = registration.degradation_skip_note()
    {
        return Plan::Skip(note);
    }
    let degraded = match body.shape {
        Shape::Degraded => {
            let make = registration
                .degraded
                .expect("degradation_skip_note says a variant was declared");
            match make() {
                Ok(session) => Some(session),
                Err(err) => {
                    return Plan::Fail(format!(
                        "cannot make the cas=false variant of {}: {err}",
                        registration.name
                    ));
                }
            }
        }
        _ => None,
    };

    Plan::Run(Box::new(Setup {
        host: Some(host),
        peer,
        degraded,
        denial: None,
        knobs: Knobs::from_environment(registration.knobs),
    }))
}

/// Run one body against one host and let the assertions speak for themselves.
///
/// This is what every `#[test]` generated by [`test_host!`](crate::test_host!)
/// calls. A skip is printed, never silent.
pub fn require_body(body: &str, registration: &'static Registration) {
    let Some(body) = crate::bodies::body(body) else {
        panic!(
            "the suite has no body called {body}: the macro and the registry have drifted, \
             and tests/coverage.rs is the guard for exactly that"
        );
    };
    match plan(body, registration) {
        Plan::Skip(note) => eprintln!("skip [{}] {}: {note}", registration.name, body.name),
        Plan::Fail(why) => panic!("[{}] {why}", registration.name),
        Plan::Run(setup) => execute(body, &setup),
    }
}

/// Hand the body its stores and call it. Panics escape untouched.
fn execute(body: &Body, setup: &Setup) {
    // For the denied shape the "store" is whatever the refusal left behind: a host
    // that built and refuses every call, or nothing at all when the host would not
    // build. Both are answers the body is written to judge.
    let host: Option<&dyn gitiup_host::Host> = match &setup.denial {
        Some(denial) => match &denial.outcome {
            DenialOutcome::Built { session } => Some(session.host()),
            DenialOutcome::Refused { .. } => None,
        },
        None => Some(
            setup
                .host
                .as_ref()
                .expect("plan: a body that is not the denial shape always gets a store")
                .host(),
        ),
    };
    let ctx = Ctx {
        host,
        peer: setup.peer.as_ref().map(Session::host),
        denial: setup.denial.as_ref(),
        degraded: setup.degraded.as_ref().map(Session::host),
        knobs: setup.knobs,
    };
    (body.run)(&ctx);
}

/// Build the refused-credentials variant: a session, or the refusal that stands in
/// for it. Both are answers; "it worked" would be the failure.
fn make_denial(registration: &'static Registration) -> Result<Denial, String> {
    let make = registration
        .denied
        .ok_or_else(|| "no refused-credentials variant declared".to_string())?;
    let outcome = match make() {
        Ok(session) => DenialOutcome::Built { session },
        Err(error) => DenialOutcome::Refused { error },
    };
    Ok(Denial::new(
        registration.name,
        outcome,
        (registration.denied_secret)(),
    ))
}

/// What running one body produced, for the report path.
pub enum Run {
    /// The body's assertions held.
    Passed,
    /// The body did not apply, and why.
    Skipped(&'static str),
    /// Something to report.
    Failed(String),
}

/// Run one body and catch its panic, for [`report`].
fn run_catching(body: &Body, registration: &'static Registration) -> Run {
    match plan(body, registration) {
        Plan::Skip(note) => Run::Skipped(note),
        Plan::Fail(why) => Run::Failed(why),
        Plan::Run(setup) => catch(|| execute(body, &setup)),
    }
}

thread_local! {
    /// Where the panic currently unwinding came from. `catch_unwind` hands back a
    /// payload and nothing else, so the hook is the only place the site — and the
    /// rendered message — can be recorded.
    static LAST_PANIC: RefCell<Option<(String, Option<String>)>> = const { RefCell::new(None) };
}

fn catch(body: impl FnOnce()) -> Run {
    // A conformance report that prints twelve backtraces is not a report, but it
    // has to say *where* and *what*: the bodies are shared code, so the site and the
    // assertion's own message are the only thing that identifies which host promise
    // broke.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        LAST_PANIC.with(|last| {
            *last.borrow_mut() = Some((
                panic_message(info.payload()),
                info.location().map(|where_| where_.to_string()),
            ));
        });
    }));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    std::panic::set_hook(hook);
    let recorded = LAST_PANIC.with(|last| last.borrow_mut().take());
    match (outcome, recorded) {
        (Ok(()), _) => Run::Passed,
        (_, Some((message, Some(where_)))) if !message.is_empty() => {
            Run::Failed(format!("{message} (at {where_})"))
        }
        (_, Some((message, _))) if !message.is_empty() => Run::Failed(message),
        (_, Some((_, Some(where_)))) => {
            Run::Failed(format!("panicked with no message at {where_}"))
        }
        (_, Some((_, None))) => Run::Failed("panicked with no message".to_string()),
        (Err(panic), None) => Run::Failed(panic_message(&panic)),
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = panic.downcast_ref::<String>() {
        return text.trim().to_string();
    }
    if let Some(text) = panic.downcast_ref::<&str>() {
        return (*text).trim().to_string();
    }
    String::new()
}

impl Knobs {
    /// CI (and anyone debugging a size-shaped failure) can raise the sizes
    /// without recompiling: a bucket's LIST page is 1 000 keys and its multipart
    /// threshold is 8 MiB, and those are exactly the numbers worth crossing in CI
    /// rather than on a laptop.
    pub fn from_environment(base: Knobs) -> Knobs {
        let number = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .filter(|value| *value > 0)
        };
        Knobs {
            pack_bytes: number("GITIUP_CONFORMANCE_PACK_BYTES").unwrap_or(base.pack_bytes),
            list_count: number("GITIUP_CONFORMANCE_LIST_COUNT").unwrap_or(base.list_count),
            ref_count: number("GITIUP_CONFORMANCE_REF_COUNT").unwrap_or(base.ref_count),
            writers: base.writers,
        }
    }
}

/// Every body for this host, in one pass, reporting rather than panicking.
///
/// Returns one line per body that did not pass: `"<body>: <message>"`, with skips
/// marked `SKIP`. An empty list means the host conforms and ran everything.
pub fn report(registration: &'static Registration) -> Vec<String> {
    each(|body| match run_catching(body, registration) {
        Run::Passed => None,
        Run::Skipped(why) => Some(format!("{}: SKIP ({why})", body.name)),
        Run::Failed(why) => Some(format!("{}: {why}", body.name)),
    })
}

/// Only the failures from [`report`], without the skips.
pub fn failures(registration: &'static Registration) -> Vec<String> {
    each(|body| match run_catching(body, registration) {
        Run::Failed(why) => Some(format!("{}: {why}", body.name)),
        _ => None,
    })
}

fn each(on_body: impl FnMut(&Body) -> Option<String>) -> Vec<String> {
    crate::bodies::bodies().iter().filter_map(on_body).collect()
}

/// The drift guard: is every body of the suite either run by this host or
/// explained?
///
/// One problem per thing wrong with the registration. A name in `skips` that is
/// not a body is a typo hiding a test; a body neither run nor explained is a
/// silent gap; a skip without a reason is not a reason.
pub fn account(registration: &'static Registration) -> Vec<String> {
    let mut problems = Vec::new();
    let known = crate::bodies::bodies();

    for (name, reason) in registration.skips {
        let Some(found) = known.iter().find(|body| body.name == *name) else {
            problems.push(format!(
                "`{name}` is not a body of the suite, so the skips list has drifted; the \
                 bodies are {:?}",
                known.iter().map(|body| body.name).collect::<Vec<_>>()
            ));
            continue;
        };
        if reason.trim().is_empty() {
            problems.push(format!("`{name}` is skipped without a reason"));
        }
        let offered = match found.shape {
            Shape::Denied => registration.denied.is_some(),
            Shape::Degraded => registration.degraded.is_some(),
            Shape::Single | Shape::Pair => false,
        };
        if offered {
            problems.push(format!(
                "`{name}` is both skipped and offered by a variant of this host: drop one"
            ));
        }
    }

    for body in known {
        let offered = match body.shape {
            Shape::Single | Shape::Pair => true,
            Shape::Denied => registration.denied.is_some(),
            Shape::Degraded => registration.degraded.is_some(),
        };
        if !offered && registration.skip_reason(body.name).is_none() {
            problems.push(format!(
                "{} does not run `{}` and does not say why: either stand up the variant or \
                 record the reason in `skips`",
                registration.name, body.name
            ));
        }
    }

    if registration.knobs.list_count < 2 {
        problems.push(format!(
            "list_count must be at least 2 ({}), or the pagination body proves nothing",
            registration.knobs.list_count
        ));
    }
    if registration.knobs.ref_count < 2 {
        problems.push(format!(
            "ref_count must be at least 2 ({}), or the ref listing body proves nothing",
            registration.knobs.ref_count
        ));
    }
    if registration.skips.len() > known.len() {
        problems.push("more skips than bodies: the suite has shrunk around this host".to_string());
    }
    problems
}

/// One line per host for the CI summary: what it offers and what it declines.
pub fn summary(registration: &'static Registration) -> String {
    let known = crate::bodies::bodies();
    let offered = known
        .iter()
        .filter(|body| match body.shape {
            Shape::Single | Shape::Pair => true,
            Shape::Denied => registration.denied.is_some(),
            Shape::Degraded => registration.degraded.is_some(),
        })
        .count();
    format!(
        "{:<12} {:<7} {:>2}/{} bodies offered, {} skipped by registration{}",
        registration.name,
        registration.kind,
        offered,
        known.len(),
        registration.skips.len(),
        match registration.skip_note() {
            Some(note) => format!("  [not available here: {note}]"),
            None => String::new(),
        }
    )
}

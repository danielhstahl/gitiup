//! The other half of the acceptance criterion: when nothing isolates, no job runs.
//!
//! The escape suite checks that a sandbox holds. This file checks what happens when
//! there is no sandbox to be had — which is the case that actually bites a volunteer,
//! because it is the case where the tempting answer ("just run it, the user asked") is
//! also the unsafe one.
//!
//! The rule under test: [`admit`](gitiup_sandbox::backend::admit) is the gate, and it
//! refuses *before* anything is spawned. A refusal that arrives after the first step
//! has run is not a refusal.

use std::sync::Mutex;

use gitiup_sandbox::backend::{self, Admitted, Sandbox, UNSANDBOXED_ENV};
use gitiup_sandbox::backends::plain::Plain;
use gitiup_sandbox::egress::Egress;
use gitiup_sandbox::policy;
use gitiup_sandbox::spec::{Enforcement, Purpose, Spec};

/// The environment is process-wide state, and two of these tests change it. Without
/// this lock they race, and the loser sees the other's variable value — which in a
/// suite about whether an opt-in was given is exactly the wrong kind of flaky.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn spec_for(workspace: &std::path::Path, purpose: Purpose) -> Spec {
    let scratch = workspace.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    Spec::new(workspace, &scratch).with_purpose(purpose)
}

/// A backend that this machine cannot run is refused by name, with the reason, and
/// nothing is spawned on the way to saying so.
#[test]
fn a_backend_that_does_not_work_here_is_refused_with_a_reason() {
    for candidate in backend::backends() {
        let home = tempfile::tempdir().unwrap();
        let spec = spec_for(home.path(), Purpose::Local);
        match admit_local(candidate.as_ref(), &spec) {
            Ok(admitted) => println!(
                "{} admitted: {}",
                candidate.name(),
                admitted.probe.summary()
            ),
            Err(why) => {
                assert_eq!(
                    why.exit_code(),
                    6,
                    "{} refused with the wrong exit code: {why}",
                    candidate.name()
                );
                assert!(
                    !why.detail().is_empty(),
                    "{} refused without saying why",
                    candidate.name()
                );
            }
        }
    }
}

/// A stranger's job needs more than a promise: every backend whose denial is only the
/// proxy's, or nothing at all, must be refused for it.
#[test]
fn a_strangers_job_needs_kernel_enforced_isolation() {
    for candidate in backend::backends() {
        // A backend that is not installed here refuses for that reason, which the test
        // above covers; this one is about the policy gate.
        if candidate.probe().is_err() {
            continue;
        }
        let home = tempfile::tempdir().unwrap();
        let spec = spec_for(home.path(), Purpose::Quorum);
        let enforcement = candidate.enforcement(&spec.egress);
        let outcome = backend::admit(candidate.as_ref(), &spec);
        match outcome {
            Ok(Admitted { backend: name, .. }) => {
                assert!(
                    enforcement >= Enforcement::Kernel,
                    "`{name}` served a quorum job with egress {} enforced",
                    enforcement.label()
                );
            }
            Err(why) => {
                assert_eq!(why.exit_code(), 6, "{why}");
                assert!(
                    enforcement < Enforcement::Kernel || !candidate.serves_quorum(),
                    "{} refused a quorum job it should have served: {why}",
                    candidate.name()
                );
            }
        }
    }
}

/// The opt-in backend may never serve a quorum job, and the refusal must not be
/// softenable by setting the opt-in variable.
#[test]
fn the_unsandboxed_backend_never_serves_a_quorum_job() {
    let _serial = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let spec = spec_for(home.path(), Purpose::Quorum);
    // Even in the friendliest possible environment.
    unsafe { std::env::set_var(UNSANDBOXED_ENV, "1") };
    let err = backend::admit(&Plain, &spec).unwrap_err();
    unsafe { std::env::remove_var(UNSANDBOXED_ENV) };
    assert_eq!(err.exit_code(), 6);
    assert!(err.detail().contains("quorum"), "{err}");
    assert!(
        !err.detail().contains("opted into"),
        "the refusal is about the purpose, not the switch: {err}"
    );
}

/// A local job in the plain backend is allowed only with the opt-in set, and the banner
/// comes with it — a permission that prints nothing is a permission nobody notices.
#[test]
fn the_unsandboxed_backend_is_opt_in_and_shouts_when_used() {
    let _serial = ENV_LOCK.lock().unwrap();
    let home = tempfile::tempdir().unwrap();
    let spec = spec_for(home.path(), Purpose::Local);
    unsafe { std::env::remove_var(UNSANDBOXED_ENV) };
    let err = backend::admit(&Plain, &spec).unwrap_err();
    assert!(err.detail().contains("opted into"), "{err}");

    unsafe { std::env::set_var(UNSANDBOXED_ENV, "1") };
    let admitted = backend::admit(&Plain, &spec).expect("opted in, as asked");
    unsafe { std::env::remove_var(UNSANDBOXED_ENV) };
    assert!(
        admitted
            .warnings
            .iter()
            .any(|warning| warning.contains("UNSANDOXED")),
        "{:?}",
        admitted.warnings
    );
    assert_eq!(admitted.enforcement, Enforcement::None);
}

/// An allowlist that is only audited is not enough for a quorum job, on the backends
/// where a job could walk around the proxy.
#[test]
fn an_audited_allowlist_is_refused_for_a_quorum_job() {
    let egress = Egress::allow_registries().unwrap();
    for candidate in backend::backends() {
        if !candidate.serves_quorum() {
            continue;
        }
        if candidate.enforcement(&egress) >= Enforcement::Kernel {
            continue;
        }
        let home = tempfile::tempdir().unwrap();
        let scratch = home.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let spec = Spec::new(home.path(), &scratch)
            .with_egress(egress.clone())
            .quorum();
        let err = backend::admit(candidate.as_ref(), &spec).unwrap_err();
        assert!(
            err.detail().contains("audited") || err.detail().contains("proxy-enforced"),
            "{} should refuse an audited-only egress policy: {err}",
            candidate.name()
        );
    }
}

/// The list a policy owner should be shown: the rungs that may serve a stranger.
#[test]
fn the_quorum_list_names_only_backends_that_deny_in_the_kernel() {
    let list = policy::quorum_sandboxes();
    println!("quorum-eligible: {}", list.join(", "));
    assert!(!list.contains(&"plain"));
    for name in &list {
        let candidate = backend::open(name).unwrap();
        assert!(candidate.serves_quorum());
        assert_eq!(
            candidate.enforcement(&Egress::deny_all()),
            Enforcement::Kernel,
            "{name} claims quorum service without a kernel-enforced denial"
        );
    }
}

/// The egress endpoints a job is told about are the same ones the proxy listens on:
/// a plan that points at a dead port is a plan that fails in a confusing way.
#[test]
fn a_job_with_an_allowlist_is_told_the_real_proxy_address() {
    let egress = Egress::allow_registries().unwrap();
    let endpoint = egress.proxy().unwrap().endpoint();
    let home = tempfile::tempdir().unwrap();
    let scratch = home.path().join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let spec = Spec::new(home.path(), &scratch).with_egress(egress);
    for candidate in backend::backends() {
        let Ok(launch) = candidate.plan(&spec, &backend::Env::new()) else {
            continue;
        };
        let expected = format!("http://{endpoint}");
        let matches = launch
            .env
            .iter()
            .filter(|(_, value)| *value == &expected)
            .count();
        assert!(
            matches > 0,
            "{} planned without the proxy address {expected}: {:?}",
            candidate.name(),
            launch.env
        );
    }
}

/// The refusal a daemon acts on: no backend, no job.
#[test]
fn nothing_available_means_nothing_runs() {
    // `best()` is the whole decision a serving daemon makes, so the test is that it
    // agrees with the per-backend probes it is built from — and that a refusal is
    // always the exit code a supervisor can branch on.
    let best = backend::best();
    match best {
        Some(backend) => {
            let home = tempfile::tempdir().unwrap();
            let spec = spec_for(home.path(), Purpose::Local);
            let admitted =
                backend::admit(&*backend, &spec).expect("the best backend admits a local job");
            println!("best: {} — {}", admitted.backend, admitted.probe.summary());
        }
        None => {
            println!("no backend available: gitiup must refuse to execute anything here");
            for candidate in backend::backends() {
                let home = tempfile::tempdir().unwrap();
                let spec = spec_for(home.path(), Purpose::Local);
                assert!(
                    backend::admit(candidate.as_ref(), &spec).is_err() || candidate.opt_in_only(),
                    "{} was unavailable to `best` but admits a job",
                    candidate.name()
                );
            }
        }
    }
}

/// `admit` for a local job, with the opt-in state normalised so the test does not
/// depend on the environment it happens to run in.
fn admit_local(candidate: &dyn Sandbox, spec: &Spec) -> gitiup_attest::Result<Admitted> {
    if candidate.opt_in_only() {
        // Do not set the variable: the plain backend's local admission is covered by
        // its own test, and here it must not be selected implicitly.
        return Err(gitiup_attest::Error::new(
            gitiup_attest::ErrorKind::Policy,
            "sandbox",
            "skipped: the plain backend is not selected implicitly",
        ));
    }
    backend::admit(candidate, spec)
}

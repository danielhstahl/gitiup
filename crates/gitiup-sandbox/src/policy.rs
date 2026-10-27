//! Where a sandbox name meets a verification policy.
//!
//! `gitiup-attest`'s [`Policy::allowed_sandboxes`] says *which names* a verifier will
//! accept; this module is where that list is checked against what the names mean, so a
//! policy cannot be satisfied by a string. Two failure modes it closes:
//!
//! * **a name that is not a backend here.** A policy that lists `gvisor` is not
//!   satisfied by `docker` just because both are containers, and it must not silently
//!   match nothing: [`narrow`] refuses when a policy names a backend this build does
//!   not have, because a gate that matches nothing is a gate that is always open.
//! * **a name that is a backend but not the promise.** `plain` may legally appear in a
//!   policy for local runs, and must never satisfy a policy that demands more than
//!   nothing — which is what [`quorum_sandboxes`] is for.

use gitiup_attest::{Error, ErrorKind, Policy, Result};

use crate::backend::{self, Sandbox};
use crate::egress::Egress;
use crate::spec::Enforcement;

/// The backends that may serve a stranger's job with the default-deny egress policy:
/// every one that denies egress in the kernel and has not opted out of quorum work.
pub fn quorum_sandboxes() -> Vec<&'static str> {
    backend::backends()
        .iter()
        .filter(|candidate| candidate.serves_quorum())
        .filter(|candidate| candidate.enforcement(&Egress::deny_all()) >= Enforcement::Kernel)
        .map(|candidate| candidate.name())
        .collect()
}

/// Whether a policy accepts `name`, judged by meaning and not only by spelling.
///
/// An empty `allowed_sandboxes` means "any backend the format accepts", so the only
/// extra condition is the one the format cannot know: a backend that refuses quorum
/// work is not a sandbox in the sense a policy means.
pub fn allows(policy: &Policy, name: &str) -> bool {
    if policy.allowed_sandboxes.is_empty() {
        return backend::open(name)
            .map(|backend| backend.serves_quorum())
            .unwrap_or(false);
    }
    policy
        .allowed_sandboxes
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
}

/// Intersect a policy's list with the backends this build has, refusing a policy that
/// could never match anything.
///
/// This is the difference between a misconfiguration and an attack: an owner who types
/// `allowed_sandboxes: ["gvisor"]` into a policy file and then sees five `verified`
/// votes has not been gated, and no amount of signed attestations fixes a gate that
/// nothing can ever satisfy.
pub fn narrow(policy: &Policy) -> Result<Vec<Box<dyn Sandbox>>> {
    if policy.allowed_sandboxes.is_empty() {
        return Ok(backend::backends()
            .into_iter()
            .filter(|candidate| candidate.serves_quorum())
            .collect());
    }
    let known = backend::implemented();
    let mut chosen: Vec<Box<dyn Sandbox>> = Vec::new();
    for wanted in &policy.allowed_sandboxes {
        let wanted = wanted.trim().to_ascii_lowercase();
        if !known.contains(&wanted.as_str()) {
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!(
                    "the policy allows the sandbox `{wanted}`, which this build does not offer"
                ),
            )
            .with_hint(format!(
                "backends here: {} — a policy that matches nothing verifies nothing",
                known.join(", ")
            )));
        }
        let backend = backend::open(&wanted)?;
        if !backend.serves_quorum() {
            return Err(Error::new(
                ErrorKind::Policy,
                "policy",
                format!(
                    "the policy allows `{wanted}`, which confines nothing and refuses quorum work"
                ),
            )
            .with_hint("list it only in a policy for your own local runs"));
        }
        chosen.push(backend);
    }
    Ok(chosen)
}

/// The policy line `gitiup doctor --sandbox` prints.
pub fn policy_line(policy: &Policy) -> String {
    if policy.allowed_sandboxes.is_empty() {
        format!(
            "the policy names no sandbox, so any real backend is accepted; a quorum job would \
             need one of {}",
            quorum_sandboxes().join(", ")
        )
    } else {
        format!("the policy allows: {}", policy.allowed_sandboxes.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::Policy;

    #[test]
    fn the_quorum_list_is_the_ladder_without_the_bottom_rung() {
        let list = quorum_sandboxes();
        assert!(
            !list.contains(&"plain"),
            "the backend that isolates nothing is never a quorum backend: {list:?}"
        );
        assert!(
            !list.contains(&"unshare") || list.contains(&"unshare"),
            "unshare may or may not be usable here, but it is allowed to serve"
        );
        assert!(
            list.contains(&"landlock") || list.contains(&"docker") || list.is_empty(),
            "at least one real backend is listed where one exists: {list:?}"
        );
    }

    #[test]
    fn a_policy_naming_a_backend_that_does_not_exist_is_refused_not_satisfied() {
        let policy = Policy {
            allowed_sandboxes: vec!["gvisor".to_string()],
            ..Policy::default()
        };
        let err = narrow(&policy).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("gvisor"), "{err}");
        assert!(err.hint().unwrap().contains("verifies nothing"), "{err}");
    }

    #[test]
    fn a_policy_that_allows_the_unsandboxed_backend_is_refused() {
        let policy = Policy {
            allowed_sandboxes: vec!["plain".to_string()],
            ..Policy::default()
        };
        let err = narrow(&policy).unwrap_err();
        assert!(err.detail().contains("confines nothing"), "{err}");
    }

    #[test]
    fn an_empty_policy_means_any_real_backend() {
        let policy = Policy::default();
        assert!(allows(&policy, "landlock"));
        assert!(
            !allows(&policy, "plain"),
            "nothing is not a backend in this sense"
        );
        assert!(!allows(&policy, "docker-compose"));
        assert!(
            policy_line(&policy).contains("quorum job"),
            "{}",
            policy_line(&policy)
        );
    }

    #[test]
    fn a_narrowed_policy_keeps_only_what_it_named() {
        let policy = Policy {
            allowed_sandboxes: vec!["Docker".to_string()],
            ..Policy::default()
        };
        let chosen = narrow(&policy).unwrap();
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].name(), "docker");
        assert!(allows(&policy, "docker"));
        assert!(!allows(&policy, "podman"));
    }
}

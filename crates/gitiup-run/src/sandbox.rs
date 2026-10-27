//! The sandbox seam: a `local` attestation is only as good as the confinement claim
//! beside it, so this module exists to make that claim *checkable* (giti-1rs.7, and
//! the backends themselves are giti-bgy.1).
//!
//! # The rule this module enforces
//!
//! `--execute` means "really run it", and the resulting attestation says
//! `tier: local, sandbox: <name>`. That name must come from a backend that was
//! **probed and found working**, never from a string someone typed. A run whose
//! sandbox was assumed would be the one forgery that matters: an unconfined
//! execution of untrusted CI code, attested as though it were contained.
//!
//! So [`open`] resolves a name to a backend, [`Sandbox::probe`] asks the machine
//! whether it is really there, and a refusal explains what to do instead. This is
//! why `gitiup run --execute` can fail on a machine that has no sandbox: the honest
//! answer is "I cannot promise you confinement, so I will not sign for it" — and
//! the default (simulate) needed none of it.
//!
//! # Backends in this build
//!
//! | name | state |
//!|------|-------|
//!| `unshare` | implemented: a new user and network namespace, probed by running it. No egress; the filesystem is *not* isolated. |
//!| `docker`, `podman`, `containerd`, `bwrap`, `landlock` | named but not implemented here; giti-bgy.1 owns them. Asking for one is refused with that pointer, not silently downgraded. |
//!
//! ```
//! use gitiup_run::sandbox;
//!
//! // The vocabulary is public, so `--help` and the error message agree.
//! assert!(sandbox::implemented().contains(&"unshare"));
//! assert!(sandbox::NOT_IMPLEMENTED.contains(&"docker"));
//!
//! // An unknown backend is refused, and the refusal lists what is real.
//! let err = sandbox::open("kvm").unwrap_err();
//! assert!(err.detail().contains("kvm"), "{err}");
//! assert!(err.hint().unwrap().contains("unshare"), "{err}");
//! ```

use std::process::{Command, Stdio};

use gitiup_attest::{Error, ErrorKind, NO_SANDBOX_ALIASES, Result};

/// A sandbox backend that exists in this build and can be probed.
pub trait Sandbox: std::fmt::Debug {
    /// The name recorded in `provenance.sandbox`. One word, lowercase, stable: it
    /// ends up inside signed digests.
    fn name(&self) -> &'static str;

    /// What it actually denies, in the sentence a reviewer needs. Never "sandboxed".
    fn guarantees(&self) -> &'static str;

    /// The argv to spawn instead of the command's own, so the command runs confined.
    fn confine(&self, argv: &[String]) -> Vec<String>;

    /// Ask the machine whether this works *right now* — permission denied, no
    /// binary, disabled namespaces, seccomp in a container.
    fn probe(&self) -> Result<()>;
}

/// A backend that is a known name in this ecosystem but is not built here.
pub const NOT_IMPLEMENTED: &[&str] = &["docker", "podman", "containerd", "bwrap", "landlock"];

/// Backends this build can actually run, in preference order.
pub fn implemented() -> Vec<&'static str> {
    vec![Unshare::NAME]
}

/// Open a backend by name.
///
/// Unknown names and known-but-unbuilt names are both refused with the list of what
/// *is* available: the commonest mistake here is typing `docker` because that is
/// what CI uses, and the answer must say what to do instead of exit(1).
pub fn open(name: &str) -> Result<Box<dyn Sandbox>> {
    let name = name.trim().to_ascii_lowercase();
    if NO_SANDBOX_ALIASES.contains(&name.as_str()) {
        return Err(Error::new(
            ErrorKind::Policy,
            "sandbox",
            "`--sandbox none` asks for an unconfined execution",
        )
        .with_hint(
            "an unconfined run may not attest as `local`: pick a backend, or drop \
             --execute and get a simulated attestation instead",
        ));
    }
    if name == Unshare::NAME {
        return Ok(Box::new(Unshare));
    }
    if NOT_IMPLEMENTED.contains(&name.as_str()) {
        return Err(Error::new(
            ErrorKind::UnsupportedSchema,
            "sandbox",
            format!("sandbox backend `{name}` is not built into this build"),
        )
        .with_hint(format!(
            "backends available here: {} (giti-bgy.1 adds the container backends)",
            implemented().join(", ")
        )));
    }
    Err(Error::new(
        ErrorKind::Invalid,
        "sandbox",
        format!("`{name}` is not a sandbox backend"),
    )
    .with_hint(format!(
        "choose one of {} — or name a backend giti-bgy.1 has not shipped yet: {}",
        implemented().join(", "),
        NOT_IMPLEMENTED.join(", ")
    )))
}

/// Every implemented backend, with whether the machine allows it right now.
///
/// Reported by `gitiup run --sandboxes` and quoted in every refusal, because "no
/// sandbox" is a fact about *this* host, not a permanent property of the tool.
pub fn detect() -> Vec<Backend> {
    vec![Backend::of(&Unshare)]
}

/// One backend's status on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// Backend name.
    pub name: String,
    /// Whether a run would be confined here.
    pub available: bool,
    /// Why not, or what it guarantees. Printed verbatim.
    pub note: String,
}

impl Backend {
    fn of(sandbox: &dyn Sandbox) -> Backend {
        // One probe per backend: `detect` runs on `--sandboxes`, and a probe is a
        // process spawn.
        let probe = sandbox.probe();
        Backend {
            name: sandbox.name().to_string(),
            available: probe.is_ok(),
            note: match &probe {
                Ok(()) => sandbox.guarantees().to_string(),
                // The hint is advice for `--execute`; a status line carries the reason.
                Err(error) => error.detail().to_string(),
            },
        }
    }

    /// `unshare: available — no egress …` for one-line printing.
    pub fn describe(&self) -> String {
        format!("{}: {} — {}", self.name, self.status(), self.note)
    }

    /// `available` / `unavailable`.
    pub fn status(&self) -> &'static str {
        if self.available {
            "available"
        } else {
            "unavailable"
        }
    }
}

/// Linux user + network namespaces via the `unshare(1)` utility.
///
/// This is a real, checkable sandbox for the one property the local runner cannot
/// fake: **no network**. It runs the step in a new user namespace (mapped to root
/// inside, so it cannot use the host's uids) and a new network namespace, where the
/// only interface is a down `lo`. The mount namespace is *not* unshared, so the
/// workspace stays writable and the filesystem is not isolated — a fact stated in
/// [`Sandbox::guarantees`] rather than glossed, because the attestation says this
/// name.
#[derive(Debug, Clone, Copy)]
pub struct Unshare;

impl Unshare {
    /// The name recorded in provenance.
    pub const NAME: &'static str = "unshare";

    fn argv(&self) -> Vec<String> {
        vec![
            "unshare".to_string(),
            "--user".to_string(),
            "--net".to_string(),
            "--map-root-user".to_string(),
            // `--map-root-user` needs the mapping to be set up by a parent, which is
            // exactly what --fork does.
            "--fork".to_string(),
        ]
    }
}

impl Sandbox for Unshare {
    fn name(&self) -> &'static str {
        Unshare::NAME
    }

    fn guarantees(&self) -> &'static str {
        "no network egress (new network namespace); runs as mapped root in a new user \
         namespace; the filesystem is NOT isolated (giti-bgy.1 adds mount isolation)"
    }

    fn confine(&self, argv: &[String]) -> Vec<String> {
        let mut confined = self.argv();
        confined.push("--".to_string());
        confined.extend(argv.iter().cloned());
        confined
    }

    fn probe(&self) -> Result<()> {
        match try_probe(&self.argv()) {
            Ok(()) => Ok(()),
            Err(why) => Err(Error::new(
                ErrorKind::Policy,
                "sandbox",
                format!("the `unshare` sandbox is not usable here: {why}"),
            )
            .with_hint(
                "user namespaces may be disabled (try `sysctl kernel.unprivileged_userns_clone`); \
                 until a sandbox works, gitiup run will only simulate — which is the safe default",
            )),
        }
    }
}

/// Run `<backend> -- /bin/true` and say what happened.
fn try_probe(prefix: &[String]) -> std::result::Result<(), String> {
    let mut command = Command::new(&prefix[0]);
    command.args(&prefix[1..]);
    command.arg("--");
    command.arg("/bin/true");
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|why| format!("`{}` could not be run: {why}", prefix[0]))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if detail.is_empty() {
        format!("`{} …` exited {}", prefix[0], output.status)
    } else {
        detail
    })
}

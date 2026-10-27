# gitiup-sandbox

The isolation ladder: which backend can confine a stranger's job on *this* machine,
what each one actually denies, and what `gitiup` does when the answer is "none".

The prose is [docs/sandbox.md](../../docs/sandbox.md). The ticket was
`giti-bgy.1`; the attestation vocabulary this feeds is
[docs/provenance-tiers.md](../../docs/provenance-tiers.md), and the seam the runner
uses is [`gitiup_run::sandbox`](../gitiup-run/src/sandbox.rs).

Volunteers run code they did not write, on a machine that holds their keys, so this
crate is the security floor of the federation. Three rules hold it together:

* **Probed, never assumed.** Every backend runs a probe that tries the escape on the
  real confinement path and records what it *observed*. A backend that could not check
  a property says so (`unchecked: tcp-egress`) instead of claiming it, and a probe that
  fails is a refusal with a fix — not a warning, and not a fallback to a weaker rung.
* **Nothing runs unsandboxed by default.** `plain` exists, prints a banner, needs
  `GITIUP_UNSANDBOXED=1`, and is refused outright for any job whose result leaves the
  machine. When no rung probes clean, the answer is exit 6 and a simulated plan.
* **A verdict is observed, not asserted.** The escape suite decides from what the host
  saw — did the file appear, did the connection arrive, did `ptrace` succeed, what cap
  was the confined process given — never from what the confined process reported.

```rust,ignore
use gitiup_sandbox::backend::{self, Sandbox, Purpose};
use gitiup_sandbox::spec::{Limits, Spec};

// What does this machine offer, in preference order?
for candidate in backend::backends() {
    println!("{}", candidate.name());
}

// The ladder's default choice, if any, and what it enforces for this job.
let Some(backend) = backend::best() else {
    // Nothing may run here. Plan and simulate instead; do not spawn.
    return;
};
let spec = Spec::new("/work/checkout", "/var/tmp/gitiup-run")
    .with_limits(Limits::tight())
    .with_purpose(Purpose::Quorum);
let admitted = backend::admit(&*backend, &spec).expect("a quorum job needs kernel-enforced isolation");
println!("{}: {}", admitted.backend, admitted.probe.summary());
for warning in &admitted.warnings {
    println!("warning: {warning}");
}
```

## Modules

| module | what it decides |
|--------|-----------------|
| [`backend`](src/backend.rs) | the `Sandbox` trait, the preference order, `open`/`detect`/`best`, and `admit` — the gate that refuses before anything spawns |
| [`backends`](src/backends/mod.rs) | `docker`, `podman`, `bwrap`, `landlock`, `unshare`, `plain` |
| [`spec`](src/spec.rs) | what a job may read, write, reach and consume; `Purpose::{Local,Quorum}` and the `Enforcement` ladder |
| [`egress`](src/egress.rs) | default-deny, the allowlist, the loopback HTTP/CONNECT proxy, and the audit record of every decision |
| [`dns`](src/dns.rs) | the allowlist-only resolver: a disallowed name is `NXDOMAIN`, not a leak |
| [`linux`](src/linux.rs) | the Landlock ruleset, the seccomp filter, `no_new_privs`, privilege drop and rlimits |
| [`kernel`](src/kernel.rs) | the kernel survey the probes are built on: Landlock ABI, seccomp usability, user namespaces, LSM list |
| [`probe`](src/probe.rs) | observed / failed / unchecked, and the rule that unchecked is always said out loud |
| [`escape`](src/escape.rs) | the four escape attempts, and the host-side observations that decide them |
| [`canary`](src/canary.rs) | `gitiup-sandbox-canary`, the program that runs the attempts from inside the confinement |
| [`policy`](src/policy.rs) | narrowing a `gitiup-attest` policy's allowed sandboxes, and refusing a policy that names the rung that verifies nothing |
| [`doctor`](src/doctor.rs) | the `gitiup doctor --sandbox` report, in text and JSON |

## Tests

```console
$ cargo test -p gitiup-sandbox                 # unit, escape and serving tests
$ cargo test -p gitiup-sandbox --test escape -- --nocapture
```

`tests/escape.rs` is the acceptance criterion as code; `tests/serves.rs` is the other
half of it — that a machine with no isolation refuses to run anything instead of
running it anyway.

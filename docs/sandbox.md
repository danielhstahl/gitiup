# The sandbox

A `local` attestation says `provenance.sandbox: <name>`. That word is a claim about the
machine, not about the code, and it is the claim a forger would most like to fake: a run
report that says `sandbox: docker` on a host with no docker is indistinguishable, from
the bytes alone, from a real one. So the rule this document is about is short:

> **the sandbox named in a report is one that was probed on that machine, moments
> before the step, and if nothing probes clean, nothing runs.**

Implementation: [`crates/gitiup-sandbox`](../crates/gitiup-sandbox). The seam the
runner uses is [`gitiup_run::sandbox`](../crates/gitiup-run/src/sandbox.rs), and the
command-line face is `gitiup doctor --sandbox` and `gitiup run --sandboxes`.

## The ladder

Backends are listed in the order `gitiup` prefers them. The first one that probes clean
is what a run gets, and the name that lands in the signed bytes is the name of the one
that probed.

| backend    | what does the isolating | what it denies | what it does **not** deny |
|------------|-------------------------|----------------|---------------------------|
| `docker`   | a container runtime     | writes outside the mounts, all egress (`--network=none`), every capability, setuid, new privileges; resources via `--memory`/`--pids-limit` | reads of what is mounted in; a job that can reach the docker socket (it never can) |
| `podman`   | as `docker`, rootless where possible | as `docker` | as `docker` |
| `bwrap`    | `bubblewrap` namespaces | the filesystem except the binds (workspace read-only, scratch read-write, `/proc`, sized `/tmp`), all egress unless an allowlist was asked for, `--dev-bind /` never | nothing outside the namespaces, but the user namespace means root inside is not root outside |
| `landlock` | Landlock + seccomp + rlimits applied to the child before `execve` | writes outside the scratch, every TCP port the job was not given (ABI 4+), `ptrace`/`process_vm_readv`, `mount`/`unshare`/`setns`/module loading/`open_by_handle_at`, the privilege syscalls, installing a seccomp filter of one's own, core dumps, cpu/address/process/file rlimits | **reads** — anything the runner's uid can read is readable; the process table is still this machine's |
| `unshare`  | `unshare(1)` user + network namespaces | all egress (only a down `lo` exists), the host's uids | the filesystem: the mount namespace is not unshared, so the workspace and everything else reachable stays writable |
| `plain`    | nothing | only the rlimits and the core-dump ban | everything else; it is the rung that says "I am not a sandbox" out loud |

Two of these sentences matter more than the others. The in-process rungs do not isolate
**reads**, which is why a local run is not a place to hand a job a secret; and `plain`
is not a sandbox, which is why it is opt-in by environment variable and printed in
caps:

```console
$ GITIUP_UNSANDBOXED=1 gitiup run --execute --sandbox plain
…
UNSANDOXED: the `plain` backend runs the job as this user, with this user's files,
this user's network and no confinement at all.
…
```

## What a step may touch

`gitiup run --execute` runs each step under one spec
([`gitiup_run::sandbox::spec_for`](../crates/gitiup-run/src/sandbox.rs)):

* **writable:** the checkout, and the scratch directory the step's script and output
  files were staged in. Everything else is read-only or invisible, depending on rung.
* **readable:** the system directories every build needs (`/usr`, `/bin`, `/lib`,
  `/etc`, …) plus the workspace. Granting the tool directory is explicit
  (`Spec::with_tool`) rather than guessed, because a confined process cannot execute a
  program it has no execute right on — the failure to grant it looks like `EACCES` on
  `execve`, which is why `Spec::tool_dirs` exists.
* **egress:** none. No host, no port, no DNS. A job that needs the network needs an
  explicit allowlist, and the allowlist comes with a loopback proxy and an
  allowlist-only resolver
  ([`Egress`](../crates/gitiup-sandbox/src/egress.rs)): `HTTP_PROXY`/`HTTPS_PROXY` and
  `GITIUP_DNS` are pointed at them, and every decision is recorded for the audit. Every
  `connect` to a port that was not granted fails at the syscall under Landlock ABI 4+
  and in a container with `--network=none`; on a rung where the proxy is the only thing
  standing between the job and the internet, the policy is reported as **audited**, not
  enforced, and a quorum job is refused on that rung rather than trusted to a proxy.
* **resources:** cpu seconds, address space, processes (an `RLIMIT_NPROC` computed as
  "what this uid is already running, plus the slack the job asked for"), file size, no
  core dumps, and a wall-clock deadline enforced by the runner.

## Probes, refusals, and `doctor`

`gitiup doctor --sandbox` prints the kernel facts, every backend's probe, and a verdict.
It is built from the same probe calls the runner makes, so it cannot describe a machine
the next command then contradicts. Its exit code **is** the verdict: 0 may serve, 6 may
not, which is what a supervisor branches on.

```console
$ gitiup doctor --sandbox
active backend   landlock
ok   landlock            ABI 8 (filesystem and TCP port rights available)
ok   seccomp             a filter can be installed in a child (the syscall denials are in force)
warn user namespaces     unshare --user was refused: unshare: unshare failed: Operation not permitted
                              fix: set `sysctl kernel.unprivileged_userns_clone=1` …
…
verdict          this machine may serve stranger's jobs, in `landlock`
```

A probe that fails is a refusal with `exit 6`, raised **before** anything is spawned:

```console
$ gitiup run --execute --sandbox docker      # no docker on this host
gitiup: sandbox: the `docker` sandbox is not usable here: runtime failed — no `docker` binary on PATH
hint: … `gitiup doctor --sandbox` says what to change about this machine
$ gitiup run --execute --sandbox none
gitiup: sandbox: `--sandbox none` asks for an unconfined execution
hint: an unconfined run may not attest as `local` …
```

A policy may name the rungs it will accept
(`Policy::allowed_sandboxes`, narrowed by
[`gitiup_sandbox::policy`](../crates/gitiup-sandbox/src/policy.rs)). A policy that names
`plain` is refused: a list of allowed sandboxes that includes the one that verifies
nothing is not a list, and reading it as one is the mistake the whole ticket exists to
make impossible.

## Strangers' jobs

A job whose result is offered to others — a quorum seat — needs a rung whose egress
denial the job cannot walk around, i.e. one that denies in the **kernel**
([`Purpose::Quorum`](../crates/gitiup-sandbox/src/spec.rs)). `plain` is excluded by
definition; a namespace rung with an allowlist-only (audited) egress policy is excluded
too, because a job that can open a socket can ignore a proxy. That gate is
[`backend::admit`](../crates/gitiup-sandbox/src/backend.rs), and it is the difference
between "this volunteer is careful" and "the protocol will not let them".

## The escape suite

`cargo test -p gitiup-sandbox --test escape` runs four attempts against every backend
this machine can actually run, and each verdict is **observed on the host**, not
reported by the confined process:

| check | the attempt | what decides it |
|-------|-------------|-----------------|
| `fs-write-outside` | create a file in a host directory the job was not given | whether the file appeared |
| `tcp-egress` | connect to a port the runner is listening on | whether a connection arrived |
| `ptrace` | `ptrace` the runner and read its memory | whether either succeeded |
| `fork-bomb` | exceed the process cap | the cap the confined process was *given*, read from inside it |

Three properties keep it honest, and they are the reason it is worth the process
spawns:

* a check that could not be attempted is reported as unchecked and **named** in the
  probe, so `landlock: available` never quietly means `landlock: assumed`;
* the canary runs through the same `plan` → `command` path a real step takes, so
  nothing is tested that production does not use;
* the fork check judges the limit, not the load: `RLIMIT_NPROC` is per-uid, so on a
  busy machine a hundred forks can succeed under a cap of thirty-two, and a suite that
  called that an escape would be reporting on the host rather than the sandbox.

On a machine with no isolation backend at all — a locked-down container, a kernel
without Landlock — the suite says so rather than passing silently, and the matching
behaviour (refusal to serve) is covered by `tests/serves.rs`.

## What is deliberately not claimed

* **Reads are not isolated** on the in-process rungs. Landlock restricts writes and
  execution; `ptrace` is refused but the filesystem the uid can read stays readable.
  Local runs are not a secret store, and the guarantees sentence says so rather than
  leaving the reader to infer it.
* **No cgroup controller use.** Process and memory caps are `RLIMIT_*`, which are
  per-uid and per-process rather than per-job. A pid namespace or cgroup is the strong
  version, and the container rungs give it.
* **A filesystem that accepts Landlock grants but does not honour them** exists: a
  workspace bind-mounted from a host machine behaved that way during development —
  a rule was added, and `execve` of a program under it was still refused. The canary is
  staged in the scratch for exactly this reason, and a refusal that smells like this
  says so instead of leaving someone to debug seccomp.

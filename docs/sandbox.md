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
| `docker`   | a container runtime     | writes outside the mounts, all egress (`--network=none`), every capability, setuid, new privileges; resources via `--memory`/`--pids-limit` | reads of what is mounted in; a job that can reach the docker socket (it never can). Its **own** filesystem is the point: the image, not the host, provides `/usr`, `/bin`, `/lib` and `/etc` |
| `podman`   | as `docker`, rootless where possible | as `docker` | as `docker` |
| `bwrap`    | `bubblewrap` namespaces | the filesystem except the binds (workspace read-only, scratch read-write, `/proc`, sized `/tmp`), all egress unless an allowlist was asked for, `--dev-bind /` never | nothing outside the namespaces, but the user namespace means root inside is not root outside |
| `landlock` | Landlock + seccomp + rlimits applied to the child before `execve` | writes outside the scratch, every TCP port the job was not given (ABI 4+), `ptrace`/`process_vm_readv`, `mount`/`unshare`/`setns`/module loading/`open_by_handle_at`, the privilege syscalls, installing a seccomp filter of one's own, core dumps, cpu/address/process/file rlimits | **reads** — anything the runner's uid can read is readable; the process table is still this machine's |
| `seatbelt` | an XNU kernel sandbox profile, applied by `sandbox-exec` at `execve` | writes outside the scratch *and* a list of credential trees (`~/.ssh`, the keychains, the gitiup keystore), every socket the job was not given, cpu/process/file rlimits applied in the child | reads outside that credential list, Mach and IOKit, anything a profile cannot express — and the kernel is still this machine's |
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

The ladder is **per-OS**, because the mechanisms are: `bwrap`, `landlock` and `unshare`
are Linux mechanisms, and the macOS ladder is `docker`, `podman`, `seatbelt`, `plain`.
A rung the OS cannot provide is not offered at all — asking a Mac for `--sandbox
landlock` is refused with the list of what exists — and [macOS](macos.md) is the page
about what a Mac can promise, why the container rungs lead both ladders, and what a
`seatbelt` attestation is worth.

### The `act` engine is not a rung

`gitiup run --engine act` hands a job to [nektos/act](https://nektosact.com) and attests
what act reported. It is listed under *engines*, never here: no rung of the ladder is
built by somebody else's flags, and the name that lands in a report has to be a name this
build can open and probe. An act run therefore says `sandbox: act` — a name that is not
in any list above, that a policy has to accept by naming it, and that no quorum policy can
list at all. [Running a workflow with `act`](act.md) says what it does promise;
[ADR-0006](adr/0006-running-workflows-with-act.md) is the decision.

## What a step may touch

`gitiup run --execute` runs each step under one spec
([`gitiup_run::sandbox::spec_for`](../crates/gitiup-run/src/sandbox.rs)):

* **writable:** the checkout, and the scratch directory the step's script and output
  files were staged in. Everything else is read-only or invisible, depending on rung.
* **mounted once:** the checkout is on both lists, and a container keys its mounts by
  destination — two mounts at one destination is `Duplicate mount point: '/work'` and a
  refused run. So the mounts are worked out before the command line is built, one mount
  per destination, writable winning over read-only and the resolution printed
  ([`mounts`](../crates/gitiup-sandbox/src/mounts.rs), [`macOS`](macos.md#duplicate-mount-point-work)).
* **readable:** the system directories every build needs (`/usr`, `/bin`, `/lib`,
  `/etc`, …) plus the workspace — **for a job that runs on this machine's filesystem**.
  A container is the exception, and it is the one place the distinction saves the run:
  its job has a root filesystem of its own, out of the image, so the host's are not
  mounted ([`SystemDirs`](../crates/gitiup-sandbox/src/mounts.rs)). Binding them in was
  a read-only copy of one OS laid over the toolchain the image was built for, and on a
  Mac a `Mounts denied` refusal for paths the desktop app does not share
  ([`macOS`](macos.md#a-write-was-refused-because-the-filesystem-is-read-only)).
  Granting a tool directory is explicit (`Spec::with_tool`) rather than guessed, because
  a confined process cannot execute a program it has no execute right on — the failure
  to grant it looks like `EACCES` on `execve`, which is why `Spec::tool_dirs` exists.
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

All of that is decided before the first step, and said there too: `gitiup run --execute`
prints the confinement's own sentences on stderr — the mounts it will ask for and in which
mode, where the job's `/usr` comes from, what the network may do — before anything is
spawned, because a mount a runtime will not make and a tool an image does not carry both
look like a broken build from the inside
([`macOS`](macos.md#exec--e-executable-file-not-found-in-path)).

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
$ gitiup run --execute --sandbox docker      # docker, but the job's image is not in it
gitiup: sandbox: the `docker` sandbox is not usable here: image failed — `alpine:3.20` is not
        present locally in `docker`, and gitiup does not pull an image while running a job …
hint: put the image where the runtime can see it first: `docker pull alpine:3.20` …
$ gitiup run --execute --sandbox none
gitiup: sandbox: `--sandbox none` asks for an unconfined execution
hint: an unconfined run may not attest as `local` …
```

The middle one is worth dwelling on, because a container's image is an **input**. Every
`docker`/`podman` run carries `--pull never`: the job's network is denied, an image that
can move between runs is not something a report should be quiet about, and a runtime that
fetches an image mid-job is a tool making the operator's decision. So the image is
pulled by whoever set `GITIUP_SANDBOX_IMAGE`, and `gitiup doctor --sandbox` and
`gitiup run --sandboxes` both say so — with the command, not just the fact.
([docs/macos.md](macos.md) is the longer version, including the
`error getting credentials` message a missing image used to turn into.)

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
| `fork-bomb` | exceed the process cap | the cap the confined process was *given*, read from inside it, judged against the process count the runner had when it set the limit |

Three properties keep it honest, and they are the reason it is worth the process
spawns:

* a check that could not be attempted is reported as unchecked and **named** in the
  probe, so `landlock: available` never quietly means `landlock: assumed`;
* the canary runs through the same `plan` → `command` path a real step takes, so
  nothing is tested that production does not use;
* the fork check judges the limit, not the load: `RLIMIT_NPROC` is per-uid, so on a
  busy machine a hundred forks can succeed under a cap of thirty-two, and a suite that
  called that an escape would be reporting on the host rather than the sandbox. The
  limit is installed as "this uid's processes right now, plus the slack the job asked
  for", so the reading of the cap is compared against **that** count — the runner's, not
  one taken inside the sandbox. A sandbox can hide processes from a count and cannot
  invent them: a pid namespace (`bwrap`, `docker`, `podman`, `unshare`) shows only its
  own tree, and Landlock's filesystem rules refuse `/proc/*` reads, so a confined
  process can count none. Subtracting a number that is too small manufactures slack the
  sandbox never granted and reports every busy container as an escape — a refusal of
  the machine, not a finding about the sandbox. Both counts are printed, and the larger
  is what binds ([`escape::cap_is_as_asked`](../crates/gitiup-sandbox/src/escape.rs)).

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

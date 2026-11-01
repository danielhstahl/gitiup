# macOS

Everything about this tool's isolation is Linux-shaped: Landlock, seccomp filters, user
and network namespaces, `--network=none` in a container runtime whose daemon shares your
kernel. The question this page answers is the blunt one: **the machine most contributors
have is a Mac — what can it actually promise, and what does `gitiup` do there?**

The short answer, in the order a person should try them:

1. **Run `gitiup` inside a Linux container** ([`docker/Dockerfile`](../docker/Dockerfile))
   using Docker Desktop, OrbStack, Colima or Podman machine. This works today, with the
   full `landlock` rung, and it is the path this repository develops against. It is what
   [the sandbox](sandbox.md) calls *the kernel that runs the job is not your kernel*,
   which is a stronger property than any in-process cage.
2. **Run `gitiup` natively and let a container do the isolating** — `gitiup run
   --execute --sandbox docker`, where `docker` is the desktop app's CLI talking to its
   Linux VM. Strongest native option; the mounts become the contract, and there is a
   probe for that ([mounts that are not shared mount empty](#mounts-that-are-not-shared-mount-empty)).
3. **Run `gitiup` natively with the `seatbelt` rung** — the XNU kernel sandbox that
   `sandbox-exec(1)` applies. This is the in-process rung for macOS, the equivalent of
   Landlock: no daemon, no root, no VM. It denies writes, egress and a specific list of
   credential reads in the kernel, and its probe observes each of those.
4. **Do nothing, and be told.** With no backend that probes clean, `gitiup run` plans and
   simulates, the attestation says `tier: simulated`, and `gitiup doctor --sandbox`
   exits 6 saying what to change. That is a supported state, not a failure of the tool.

## The rule that does not bend

[The sandbox](sandbox.md) states it: the sandbox named in a signed report is one that was
**probed on that machine, moments before the step**, and if nothing probes clean, nothing
runs. A Mac changes which rungs exist, not that rule:

* a rung whose mechanism the OS does not have is **not offered at all** — asking a Mac for
  `--sandbox landlock` is the same class of mistake as asking it for a syscall its kernel
  has never had, and it is refused with the list of what *does* exist;
* a rung that is offered has to earn it by **observing a denial**, on this machine, in
  the same plan→command path a job uses;
* a property a rung cannot express on this OS is printed as unchecked, with the reason,
  rather than being quietly assumed. `seatbelt: available · unchecked: ptrace` is a
  sentence a reviewer is allowed to distrust, which is the point of printing it.

The ladder is therefore **per-OS**, and `gitiup doctor --sandbox` prints the one this
machine has under `ladder`:

| OS | the ladder, strongest first |
|----|-----------------------------|
| Linux | `docker`, `podman`, `bwrap`, `landlock`, `unshare`, `plain` |
| macOS | `docker`, `podman`, `seatbelt`, `plain` |
| anything else unix | `docker`, `podman`, `plain` |
| Windows | not supported; [not one of the options below](#windows-is-not-an-option-yet) |

`plain` is last everywhere, is opt-in only, prints the `UNSANDBOXED` banner every time,
and refuses a stranger's job whatever the policy says. Nothing about macOS softens that;
there is simply one more real rung above it than there was.

## Option 1 — run the whole tool inside a Linux container

This is the option the ticket's Docker container was reaching for, and the answer to "will
sandboxing work there?" is **yes, and it was checked rather than reasoned about**. The
following is the real `gitiup doctor --sandbox`, run inside a Linux container on Docker
Desktop for Mac on Apple silicon — kernel `7.0.14-linuxkit`, which is the LinuxKit kernel
the desktop app boots — against a binary built from this checkout:

```console
$ gitiup doctor --sandbox
active backend   landlock

info kernel                   Linux 7.0.14-linuxkit (aarch64) — uid 100; 7 processes already owned by this uid
info ladder                   docker, podman, bwrap, landlock, unshare, plain
ok   landlock                 ABI 8 (filesystem and TCP port rights available)
ok   seccomp                  a filter can be installed in a child (the syscall denials are in force)
warn user namespaces          unshare --user was refused: unshare: unshare failed: Operation not permitted
                              fix: … inside a container, the runtime's default seccomp/AppArmor profile
                                     commonly refuses this until you pass --security-opt seccomp=unconfined
info backend docker           the `docker` sandbox is not usable here: runtime failed — no
                              `docker` binary on PATH
info backend bwrap            the `bwrap` sandbox is not usable here: … no `bwrap` binary on PATH
ok   backend landlock         kernel-enforced — Landlock refuses writes outside the scratch …
info backend unshare          the `unshare` sandbox is not usable here: user-namespaces failed
                              — unshare: unshare failed: Operation not permitted

backends, in the order gitiup prefers them:
  …
  landlock: available (in-process, kernel-enforced) — Landlock refuses writes outside the
      scratch and refuses every TCP port the job was not given (ABI 4+) …
      observed: landlock-abi, seccomp, fs-write-outside, tcp-egress, ptrace, fork-bomb, writable-root

verdict          this machine may serve stranger's jobs, in `landlock`
```

Read that as three facts, in order of how much they matter:

* **Landlock works.** `CONFIG_SECURITY_LANDLOCK=y`, `landlock` is in
  `/sys/kernel/security/lsm`, the ABI is 8, and the escape suite observed all four checks
  — `fs-write-outside`, `tcp-egress`, `ptrace`, `fork-bomb` — from inside the container.
  The rung that a quorum job needs is present, egress denial and all.
* **seccomp works**, so the syscall denials (`ptrace`, `mount`, `unshare`, the privilege
  syscalls) are in force in the child. The container's own default seccomp profile did not
  stop its guest from installing a stricter one.
* **user namespaces do not**, because the *outer* runtime refuses them. That kills the
  `unshare` rung and `bwrap` inside a default container — not because LinuxKit lacks
  them, but because Docker's default seccomp/AppArmor combination says so. If you want
  `bwrap` in there, either install `bubblewrap` and run the outer container with
  `--security-opt seccomp=unconfined` (your judgement, not a default), or do not: the
  `landlock` rung already observed every check.

Two things about the image itself are load-bearing and easy to get wrong, and both are in
[`docker/Dockerfile`](../docker/Dockerfile):

* **the runtime stage needs a shell.** A `FROM scratch` image holding one static binary
  cannot run a CI step, because a step is a `/bin/sh` script and there is no `/bin/sh`.
  It also cannot talk to an HTTPS store without CA certificates. The image gitiup *runs*
  is not the image a *job* runs in (`GITIUP_SANDBOX_IMAGE` is the job's), but `gitiup
  run --execute --sandbox plain` and every diagnostic need a shell too.
* **the mounted checkout has to be a path the desktop app shares** — see
  [mounts that are not shared mount empty](#mounts-that-are-not-shared-mount-empty).

The shape of the command, once, for the repo:

```sh
docker build -f docker/Dockerfile -t gitiup .
docker run --rm -v "$PWD:/work" -w /work gitiup doctor --sandbox
docker run --rm -v "$PWD:/work" -w /work gitiup run --execute --workflow .github/workflows/ci.yml
```

Inside that container the *job* gets `landlock` confinement by default, its network
refused by the kernel rather than by a proxy, and an attestation that says `sandbox:
landlock` because a probe on that machine saw the denial happen.

## Option 2 — native `gitiup`, container for the job

`gitiup run --execute --sandbox docker` on macOS runs the desktop app's CLI, which runs
the job in the app's Linux VM. In one respect this is the **strongest** rung available on
a Mac: the job is not confined by your kernel at all, it is on a different kernel, so a
write outside the mounts, a `ptrace` of your process, or a socket to anywhere is not
*restricted* — it is unreachable. `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--network=none` and `--pids-limit` mean the same thing there as on Linux.

It is ranked above `seatbelt` in the ladder for that reason, and it comes with one debt
that does not exist on Linux.

### Mounts that are not shared mount empty

A container runtime on macOS has no access to your filesystem except through the
directories the desktop app has agreed to *share*. Bind-mount a path outside that list
and the runtime does not fail: it mounts an **empty directory**, and the job cannot find
its own checkout. It also makes the write-outside check vacuous — a write to a host path
the VM cannot see was never a write to the host — which is the kind of green light this
crate is written not to print.

So the container probe checks it, by observation: write a file, mount its directory
read-only, ask a container to read it back (`mount-visibility`). If that fails, the write
check is reported as **unchecked** rather than as a denial, and the refusal names the fix:

```console
$ gitiup doctor --sandbox
…
backends, in the order gitiup prefers them:
  docker: available (container, kernel-enforced) — the job runs in a container with no
      capabilities, no new privileges, its own pid namespace and its own filesystem …
      observed: runtime, daemon, image, container-starts, tcp-egress
      unchecked: mount-visibility — a container could not read a file the host just wrote
                     into a directory it was given as `-v`: the job would not find its own
                     checkout. On macOS this means the directory is not in the runtime's
                     file-sharing list (Docker Desktop: Settings → Resources → File
                     sharing); or run gitiup inside the VM, where mounts are not involved
                     at all
                 fs-write-outside — the runtime could not see a host directory at all, so
                     a write that did not arrive is a fact about file sharing and not
                     about the sandbox
```

The same warning is in the plan notes for a macOS run, printed by `gitiup run --plan
--json`, because a reviewer should see it before the job runs rather than in a
`no such file` at step three.

### "Duplicate mount point: '/work'"

The other mount-shaped failure on a Mac — and it is not Mac-specific, the Mac is just
where it was found. A container runtime keys its mounts by **destination**, and refuses
the whole container when two want one address:

```text
Error response from daemon: Duplicate mount point: '/work'
```

The spec a step runs in asks for exactly that. The checkout is on the read list because
every workspace is mounted read-only, and on the write list because a build writes where
it is checked out ([What a step may touch](sandbox.md#what-a-step-may-touch)). Two
grants, one destination, one refused run — and the message names neither grant, which is
how a spec bug ends up looking like a mystery about Docker on macOS.

The mounts are now worked out before any `docker run` is built
([`mounts`](../crates/gitiup-sandbox/src/mounts.rs)), under one destination, one mount:

* **a tree named twice is mounted once, and writable wins.** The only way a read-only
  and a writable grant meet at one destination is a spec that named the tree writable,
  and an explicit `with_writable` is what the read-only default is traded against. That
  trade is said out loud, in the plan notes and in `doctor`, because "read-only
  workspace" just stopped being true:

  ```console
  $ gitiup doctor --sandbox
  ok   mount points             10 mounts for a workflow step, each at its own destination: a
                                container keys its mounts by destination and refuses a run that
                                puts two there (`Duplicate mount point: '<path>'`, which names
                                neither of the grants that collided), so a tree named twice is
                                mounted once and the scratch cap keeps /tmp to itself —
                                /tmp/gitiup-doctor-1975 is named as a readable tree and as a
                                writable one: it is mounted read-write, so the read-only
                                promise does not cover it
  ```

* **a destination the tool already claimed is a refusal that names the fix.** The
  scratch cap is a size-capped tmpfs at `/tmp`, so a job whose scratch *is* `/tmp` —
  common, because `TMPDIR` is `/tmp` in a great many containers — wants that address.
  gitiup refuses it before the runtime does, and says to name `/tmp/gitiup-scratch`
  instead, which keeps its cap.
* **one directory spelled two ways is flagged when the two spellings get different
  grants.** On macOS `/tmp`, `/var` and `/etc` are symlinks into `/private`, so
  `/var/folders/…/T` and `/private/var/folders/…/T` are one place: a read-only grant
  spelled one way is writable spelled the other. The host is asked (`realpath`), not the
  spelling guessed at — which is also what catches `/bin` and `/usr/bin` being one
  directory on a merged-usr Linux.

Nothing is relocated to make a clash go away. Every tree is mounted at its own absolute
path — that is what keeps the paths in the job's environment true inside the container —
so a destination that two different directories want stays a refusal, with both of them
named. `crates/gitiup-sandbox/tests/mount_points.rs` runs the whole thing against a
runtime that enforces the daemon's one rule, so the case is a reproduction rather than
an assertion about a data structure.

### The uid, and the image

`--user $(id -u):$(id -g)` is passed on every platform: the job runs as the uid that
started gitiup, not as root and not as the daemon. Inside a Mac's VM that uid is a name
nobody knows, which is fine — ownership of bind-mounted files follows the host uid through
the sharing layer — but it does mean a job cannot `chown` its way out of anything, which
was the point.

The job's image is `GITIUP_SANDBOX_IMAGE` (default `alpine:3.20`), and on Apple silicon
it has to be an `arm64` image.

### The image is an input, and pulling it is your job

Every container gitiup starts carries `--pull never`. That is a decision, not an
omission: the job's network is denied by default, so a pull could not be relied on
anyway; an image that can move between two runs is not the reproducible input a signed
report claims to describe; and a runtime that fetches someone's tag halfway through a
job is the tool making a decision the operator should have made. So the image is
expected where it can be seen, and the tool says so **before** the run rather than in
the middle of it:

```console
$ gitiup run --execute --sandbox docker --workflow .github/workflows/build.yml
gitiup: sandbox: the `docker` sandbox is not usable here: image failed — `alpine:3.20` is not
        present locally in `docker`, and gitiup does not pull an image while running a job: …
hint: put the image where the runtime can see it first: `docker pull alpine:3.20` — gitiup will
      not pull it during a run; or set GITIUP_SANDBOX_IMAGE to an image that is already here
```

The same sentence is in `gitiup doctor --sandbox`, under the backend it belongs to, and
in `gitiup run --sandboxes` — which is the answer to "how would I have known before
trying?":

```console
$ gitiup doctor --sandbox
…
warn backend docker           the `docker` sandbox is not usable here: image failed —
                              `alpine:3.20` is not present locally in `docker`, …
                              fix: put the image where the runtime can see it first:
                                    `docker pull alpine:3.20` — gitiup will not pull it
                                    during a run; or set GITIUP_SANDBOX_IMAGE to an image
                                    that is already here
```

A refusal is a refusal: `docker` counts as unavailable until its image exists, and the
ladder falls through to the next rung. That is deliberate — a backend that cannot start
a container cannot confine one.

### "Unable to find image 'alpine:3.20' locally"

That message, followed by

```text
error getting credentials - err: exit status 1, out: ``
```

is the second-most-common thing wrong with a container sandbox on a Mac, and it fooled
everyone who saw it because both lines are about something other than the problem. The
first says the image is not here. The second is the runtime CLI failing to ask its
credential helper (`docker-credential-osxkeychain`, or `docker-credential-desktop`) for
docker.io credentials — which it cannot do when it was started without a `PATH` to find
the helper in or a `HOME` to find `~/.docker/config.json` in. It is a sentence about a
keychain, produced by a stripped environment, caused by a missing image.

Both halves are closed. The CLI gets a small allowlist of its own variables — `PATH`,
`HOME`, `USER`, `LOGNAME`, `TMPDIR`, `XDG_RUNTIME_DIR`, `XDG_CONFIG_HOME`, and the
`DOCKER_*` / `CONTAINER_*` names that say which daemon to talk to — because the
runtime's CLI has a different environment from the job's, and the job's is still built
from nothing and passed as `-e` arguments. And with `--pull never` the pull that
produced the message is never attempted: gitiup's own refusal, naming
`docker pull alpine:3.20`, is what arrives instead.

One more trap on the same path, and a Mac-shaped one: an image that *is* present but
cannot be booted — an `amd64`-only tag on Apple silicon, or a `FROM scratch` image with
no `/bin/sh` — looks exactly like a sandbox that denies everything to a probe made of
denials, because nothing gets written and nothing gets reached. So the container probe
starts one container that has to print a marker before either canary is believed, and
reports `container-starts` failed rather than green.

## Option 3 — the `seatbelt` rung, native and in-process

macOS has no Landlock, no seccomp, no user namespaces. What it does have is the kernel
sandbox that `sandbox-exec(1)` and `sandbox_init(3)` drive — the same mechanism every App
Store app lives inside, reachable by an unprivileged process that wants to restrict
*itself*. That is the macOS rung, and it is what `--sandbox seatbelt` (or
`--sandbox sandbox-exec`) means.

The profile gitiup builds is `(allow default)` and then denials, which is the shape that
keeps an ordinary build working:

| clause | what it refuses |
|--------|-----------------|
| `(deny file-write*)`, then an `allow` per granted tree | every write outside the scratch (the workspace stays read-only, as on every other rung) |
| `(allow file-write-data …)` for `/dev/null`, the `std*` literals, the tty family | nothing — these are the holes that let a job `printf` |
| `(deny network*)`, then one `allow network-outbound` per allowlisted proxy | every socket, including loopback; with an allowlist, everything except the proxy's own address |
| `(deny file-read* …)` for the credential list | reads of `~/.ssh`, `~/.gnupg`, `~/Library/Keychains`, `~/.aws`, `~/.docker`, `~/.kube`, `~/.netrc`, `~/.config/gh`, and **the gitiup keystore itself** |
| `(deny process-trace)` and friends, *only if this macOS parses them* | tracing the runner, where the operation exists |

The credential list is the interesting row: on Linux the in-process rung cannot refuse a
read at all, which is why the runner passes secret *names* and never values. On macOS it
can refuse the `open`, so it does, and the check that a job can still read a key would be
a finding rather than a footnote.

Two things it does **not** do, because a reviewer has to be able to see them:

* **Mach and IOKit are outside what an SBPL profile covers.** A sandboxed job can still
  talk to launchd services. The escape checks are about filesystem, network, tracing and
  process count because those are what a profile — and this tool — can prove.
* **Deprecation is a real possibility, so it is probed rather than assumed.** `sandbox_init`
  has been marked deprecated in the headers for over a decade and is present in every
  release since; a profile that will not parse on a future macOS makes `sandbox-exec`
  refuse to start the job at all. `probe` therefore parses the exact profile it will use,
  and each version-dependent denial individually, before the backend offers itself. If the
  profile is refused, `seatbelt` is unavailable and the message says so — that is a
  refusal with an exit code, not a silent downgrade to nothing.

The denials a given macOS does not recognise are dropped from the profile (an unknown
operation makes the whole profile fail to parse, which would break the job rather than
weaken it), and the property they underwrite is reported as unchecked:

```console
  seatbelt: available (in-process, kernel-enforced) — an XNU kernel sandbox profile refuses
      every write outside the scratch, refuses the credential directories the runner keeps
      …
      observed: runtime, profile, fs-write-outside, tcp-egress, fork-bomb,
                tcp-egress-allowlisted, writable-root
      unchecked: ptrace — this macOS's SBPL accepts no tracing denial that gitiup knows,
                     so the backend claims nothing about ptrace; a container rung has its
                     own answer (a pid namespace) and is preferred for a stranger's job
```

Why a wrapper binary instead of `sandbox_init` in a `pre_exec` hook: `sandbox-exec -p
'<profile>' <command>` is **argv**, so `gitiup run --plan` prints the exact confinement a
reviewer can copy, paste and read; and calling `sandbox_init` between `fork` and `execve`
means doing `malloc` there, which is exactly what a `pre_exec` hook must not do. The
rlimits that have no SBPL equivalent (process count, file size, cpu seconds, no core
dumps) are still applied in the child.

`seatbelt` claims `kernel` enforcement for egress — including with an allowlist, where the
one hole is a kernel rule about one address — and the probe earns the claim twice: the
witness-port connect must fail under the plain profile **and** under the allowlisted one
(`tcp-egress-allowlisted`). A quorum job is admitted on the strength of that observation,
not on the strength of the sentence.

## Option 4 — a Linux VM you run yourself

Lima, OrbStack, Tart, UTM, Vagrant, `multipass`: any of them gives a Linux guest where
the *whole* ladder exists, `bwrap` and `unshare` included, because nothing between the
job and that kernel is refusing namespaces. If you want to develop the sandbox crate
itself on a Mac — to run `cargo test -p gitiup-sandbox --test escape` against a kernel
where all four checks can be attempted natively — this is the option, and it is also the
one to use for a volunteer that wants a machine whose only job is serving quorum rounds.

It is option 1 with a different lifecycle: a container you start per command versus a VM
you keep, with a real filesystem (so no sharing layer), a real init, and the ability to
grant it its own disk and its own CPU quota.

## Windows is not an option yet

Nothing in this crate pretends otherwise: there is no Windows rung, and `gitiup` on
Windows has no backend to offer, so it plans, simulates and refuses to execute. Windows
Subsytem for Linux *is* option 1 or option 4 with extra steps, and that is the honest
answer for a Windows machine today.

## Choosing, in one table

| what you are doing | use | why |
|--------------------|-----|-----|
| running your own CI steps locally, on a laptop | option 1, or option 2 | a kernel that enforces egress, a shell for the steps, and no new habits |
| contributing to gitiup, including this crate | option 1 | the escape suite reaches every check, so a green run means something |
| serving quorum rounds from a machine you also use | option 2, or option 4 | a stranger's job wants a kernel between it and your machine, not a list of denials inside your kernel |
| the fastest possible loop on a Mac with nothing installed | option 3 | no daemon, no VM, no image; the profile is printed with the command |
| "can I trust `sandbox: seatbelt` in a report someone sent me?" | [verification](verification.md) | the name is only as good as the probe that ran on the machine that made it — which is why the probe's properties travel with the run |

## What this page does not claim

* **A container on macOS is not a security boundary against the VM.** It is a stronger
  boundary than an in-process cage, and it is still a kernel shared with every other
  container the desktop app runs. A quorum volunteer who wants a hard boundary wants
  option 4 on a machine that does nothing else.
* **`seatbelt` does not isolate reads in general.** It refuses a list of credential
  directories and leaves the rest of what your user can read readable, which is more than
  Landlock can say and less than a container.
* **Nothing here was tested on a Mac by the person who wrote it being kind about it.** The
  Linux-container results above are printed from a real Docker Desktop on Apple silicon.
  The macOS-native paths are compile-verified on both `aarch64-apple-darwin` and
  `x86_64-apple-darwin` and exercised by `cargo test -p gitiup-sandbox --test escape` on
  the `macos-latest` runner in [`.github/workflows/build.yml`](../.github/workflows/build.yml);
  where a check cannot be attempted there, `doctor` prints that it was not attempted.

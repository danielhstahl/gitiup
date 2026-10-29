# gitiup (CLI)

The command line. Thin on purpose: every rule about *what a digest is* lives in
[`gitiup-attest`](../gitiup-attest/README.md) and — since normalisation — in
[`gitiup-normalise`](../gitiup-normalise/README.md), and this crate only reads a run
report, calls those crates and prints. Two reasons to insist on that:

* the number printed here and the number a stranger recomputes must be the same
  number, so there is exactly one implementation of the computation;
* the format crate does no I/O (so it can run in a `pre-receive hook` and in a
  test), and the host crate owns storage — reading a report off disk belongs to
  neither, so it belongs here.

## `gitiup digest`

```console
$ gitiup digest crates/gitiup-attest/tests/fixtures/runs/hello/run.json
run            sha256:5b71fcfdccb72830d84e1423292ede463d2216fe72c2a4cab2e3b354b8deb819
result         sha256:28c73827c9a5506837c179128bca275f7f0ef42d84375f1b408573cfd62e82e4
tier           simulated
runner         gitiup 0.1.0
commit         sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
workflow       .github/workflows/hello.yml sha256:cc8c24530e48…
event          push
job            hi
environment    x86_64 · fingerprint sha256:b3bad75a23bc…
image          none
toolchain      no toolchain inventory
steps          1 (1 succeeded, 0 failed, 0 skipped)
normalisation  v0
```

```text
gitiup digest [OPTIONS] [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)
    --json                 machine-readable output (keys sorted, one line)
    -q, --quiet            print the RunDigest and nothing else
    --expect <digest>      exit 8 unless the RunDigest equals this
    --expect-result <d>    exit 8 unless the ResultDigest equals this
    --policy <path>        gate the run's environment against a policy file
    --require <field=value>  require one environment field (repeatable)
    --require-env-match <m>  strict | major | off (default: strict)
```

The input is a **run report** — the runner's record of a finished job; the format
is [documented here](../../docs/run-report.md). The two digests are the epic's
claim: `RunDigest` names the attestation, `ResultDigest` is what two independent
runs of the same change are supposed to agree on.

`--expect` is the reason this is a command and not just a library call:

```sh
# Re-run a job and prove it converged:
gitiup digest --expect "$(cat expected-digest)" run.json || echo "rerun disagrees (exit 8)"
```

`--require` is the other question you ask of a run you already have — not *did it
converge* but *is this the machine we asked for* — and it gets its own exit code, 6,
because the fix is different too. The requirement, the `strict|major|off` knob and what
the refusal says are [documented here](../../docs/environment.md):

```sh
gitiup digest --require arch=amd64 --require toolchain:rustc=1.99 \
        --require-env-match major run.json || echo "wrong machine (exit 6)"
```

## `gitiup env`

What a run *here* would attest as, and whether a policy would accept it — the same
`Policy::check_environment` a verifier runs, before any run exists:

```console
$ gitiup env
os             linux 24.04
arch           x86_64
image          none (no container image digest was discoverable)
toolchain      git 2.43.0, make 4.3, python 3.12.3, rustc 1.88.0
runner         gitiup 0.1.0
fingerprint    sha256:9c0a…
note           distribution: ubuntu
note           no version reported by node (absent from this machine, so absent from the inventory)
requirement    none published

$ gitiup env --policy gitiup-policy.json ; echo $?
gitiup: environment: this run's arch is 'x86_64', which does not match what this change requires: arm64
6
```

`--json` for scripts, `-q` for the fingerprint alone, `--no-inventory` to answer
without spawning a single tool. The inventory itself is probed by
[`gitiup_run::env`](../gitiup-run/src/env.rs) and can be declared instead of guessed
with `GITIUP_TOOLCHAIN` / `GITIUP_IMAGE_DIGEST`.

## `gitiup normalise`

The other half of the claim: what did normalisation do to my logs, and did two runs
agree. The rules live in
[`gitiup-normalise`](../gitiup-normalise/README.md) and the contract they sit inside
is [documented here](../../docs/reproducibility.md); this prints them.

```console
$ gitiup normalise crates/gitiup-normalise/tests/fixtures/corpus/machine-b/run.json
profile        repro v1
result         sha256:00bf7ddb547f5fc3fdfde522206566b3efb8e8b65ca66464069bfd5f22ab1f0b
rewritten      24 rewrites · no progress lines dropped · 5 streams

checkout stdout: 7 rewrites
  line-ending  (stream)
    - stdout: CRLF line endings
    + stdout: LF line endings
  identity     line 1
    - Runner host: build-07.example
    + Runner host: <host>
```

```text
gitiup normalise [OPTIONS] [REPORT]
gitiup normalise [OPTIONS] --compare <OTHER> [REPORT]

    REPORT                 run-report JSON file, or - for stdin (default: stdin)
    --compare <REPORT>     compare two runs instead of describing one
    --rules <LIST>         comma-separated rule names to apply (diagnosis, not policy)
    --text                 print the normalised log text too
    --json                 machine-readable output (keys sorted, one line)
    --expect-result <d>    exit 8 unless the ResultDigest equals this
```

`--compare` is the question a reproducibility failure asks. Two runs that still
disagree produce a structured divergence — step, field, both sides, with the log
line number — and exit `8`:

```console
$ gitiup normalise broken.json --compare good.json; echo "exit $?"
converged      no (3 divergences)
result A       sha256:ee4e6946df04e79e71dae24c72fea5dd4361c4aae0b10aa0a92ab0fc5090c518
result B       sha256:00bf7ddb547f5fc3fdfde522206566b3efb8e8b65ca66464069bfd5f22ab1f0b
test             exit-code                - 101
                                          + 0
test             outcome                  - "failure"
                                          + "success"
exit 8
```

Exit codes follow [ADR-0001 D7](../../docs/adr/0001-attestation-encoding-hash-and-signature.md)
where they overlap, because gates branch on the numbers:

| exit | meaning |
|------|---------|
| 0 | digest computed (and it was the one we were told to expect) |
| 2 | usage: unknown flag, missing value, no report on stdin |
| 3 | I/O: the report could not be read |
| 6 | the report is not a valid run report, or this build cannot read it |
| 8 | digest mismatch: the rerun disagreed with `--expect`, or two runs did not converge |

## `gitiup attest`

Put a signed attestation *in* a host store, read it back out, and keep the store from
filling up. A `gitiup run` that proves something is worth nothing if the proof lives
on the laptop that made it, so the unit of storage is the same on every host: the
attestation's canonical bytes at `kv/attestation/<digest>`, advertised by
`refs/attestations/<subject>/<digest>` so that on a git-backed host a plain
`git fetch 'refs/attestations/<subject>/*'` arrives carrying the proof.

```console
$ gitiup attest push --run-report crates/gitiup-attest/tests/fixtures/runs/hello/run.json --sign --store ./store
filed 42ea717b…3aae for aaaaaaaaaaaa
  store    fs store ./store
  ref      refs/attestations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/42ea717b0674b91db76bc2b1640b613617c7fe2cb4100e5cebca862d758d3aae
  blob     kv/attestation/42ea717b0674b91db76bc2b1640b613617c7fe2cb4100e5cebca862d758d3aae
  run      sha256:5b71fcfdccb72830d84e1423292ede463d2216fe72c2a4cab2e3b354b8deb819
  tier     simulated · signed by Lds7upm9…Ns7s
  warning  SIMULATED: nothing was executed. This attestation describes a plan and proves intent, not behaviour: no code ran, no network was used, no artifact was produced.

$ gitiup attest list --commit sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --store ./store
42ea717b0674  5b71fcfd…b819  simulated 2026-10-27T09:15:02Z  Lds7upm9…Ns7s

$ gitiup attest show 42ea717b0674b91db76bc2b1640b613617c7fe2cb4100e5cebca862d758d3aae --store ./store
attestation 42ea717b0674b91db76bc2b1640b613617c7fe2cb4100e5cebca862d758d3aae
  store     fs store ./store
  ref       refs/attestations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/42ea717b0674b91db76bc2b1640b613617c7fe2cb4100e5cebca862d758d3aae
  subject   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  commit    sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa · workflow .github/workflows/hello.yml · event push
  tier      simulated · runner gitiup 0.1.0 · sandbox none · normalisation v0
  env       arch x86_64
  steps     1
  signed    Lds7upm9…Ns7s (ed25519)
  claimed   2026-10-27T09:15:02Z (17h old)
  run       sha256:5b71fcfdccb72830d84e1423292ede463d2216fe72c2a4cab2e3b354b8deb819
  result    sha256:28c73827c9a5506837c179128bca275f7f0ef42d84375f1b408573cfd62e82e4
  note      verification (is any of the above *trusted*?) is `gitiup verify attestation`; this command prints what the store holds
  warning   SIMULATED: nothing was executed. This attestation describes a plan and proves intent, not behaviour: no code ran, no network was used, no artifact was produced.
```

```text
gitiup attest push [OPTIONS] [ATTESTATION]
    --run-report <file|->   build the document from a run report instead of a file
    --sign                  sign it with this machine's key (`--key`/`--issuer` to choose)
    --subject <oid>         what it attests to (default: the commit the run is bound to)
    --store | --remote      where to file it (see `gitiup doctor --remotes`)
gitiup attest list   --commit <oid> | --all [--json]
gitiup attest show   <digest> | --commit <oid> [--json | --bytes | --dsse]
gitiup attest gc     --max-age <dur> --max-per-commit <n> [--keep <digest>] [--apply] [--purge-blobs]
```

Three things are deliberate:

* **The bytes are stored verbatim, and the store is checked on the way back.** A
  signature is only valid over exact bytes, so `push` files the buffer the signature
  covers, and `show` re-hashes what it reads and exits `8` if the bytes no longer hash
  to the digest they are filed under — an integrity failure on the *store*, not a
  missing file.
* **An unsigned attestation is refused.** `push` wants `--sign` (or a document that
  already carries a signature), because filing a proof nobody signed grows a store of
  rumours. Whether a signature *counts* is `gitiup verify attestation`;
  these commands print signers and the tier's trust warning and claim nothing.
* **`gc` plans before it prunes, and never prunes what something still points at.**
  It prints the plan and changes nothing without `--apply`, refuses a policy with no
  limits (exit `6`), and an attestation another live ref still targets — a quorum
  seat's submission at `refs/gitiup/reveal/…`, which is where a round's ballots live in
  this same store — is reported `pinned` and survives with no flag to force it. A digest
  named *inside* some other record (a merge record's `attestation` field) is not a ref,
  so `--keep <digest>` is how the caller that read that record says so. Retiring means
  un-advertising: the ref goes, a `kv/gc/<digest>` record says why, and the bytes are
  only deleted where the host can honestly forget (`--purge-blobs`, the `fs` host; git
  and bucket hosts report `retained`, because an append-only store cannot forget one
  object).

The full rules, including what retention cannot do, are in
[docs/host-abstraction.md](../../docs/host-abstraction.md#attestations-in-the-store).

## `gitiup change`

The contributor's half of contributing without a forge: a **change** is one signed
record in a content-addressed store, advertised by a ref, naming the commit it
proposes, the branch it is proposed against and the oid that branch was at where the
work forked. `who proposed this` is a signature and not a username, so a directory, a
bucket and a bare repository all say the same thing about it. All three hosts answer
`--store`/`--remote`, and the store has to be named: a typo cannot publish a change
somewhere else.

```console
$ gitiup change new --base main --out change.json
change chg-8a4f0932daec33f2
  attempt  0 · anchor sha1:2d394df0…7e86
  base     refs/heads/main @ sha1:1b1cfe58…d9f5 (1 commits)
  head     sha1:2d394df0…7e86
  title    Fix the ref parser for peeled refs
  jobs     build, test (workflow .github/workflows/ci.yml)
  author   KgCqW9kg…AgNQ (gitiup) · signed
  digests  change sha256:21cb95bb…a6fd · record sha256:cc9147d1…90ef
  written  change.json
  next     gitiup change submit --record change.json --store <dir>

$ gitiup change submit --record change.json --store ../store
submitted chg-8a4f0932daec33f2 attempt 0
  store    fs store ../store
  base     refs/heads/main @ sha1:1b1cfe58…d9f5 [the store agrees]
  head     sha1:2d394df0…7e86 (5 objects, 523 bytes, as gitiup raw objects)
  ref      refs/changes/chg-8a4f0932daec33f2/attempt/0
  head ref refs/changes/chg-8a4f0932daec33f2/head -> sha256:cc9147d1…90ef
  record   kv/change/cc9147d14075631660af262973b62415dedca83cca08916bffdf1e7c4a2990ef (831 bytes)

$ gitiup change list --store ../store
chg-8a4f0932daec33f2  open      a1   sha1:2d394df0…7e86   KgCqW9kg…AgNQ  Fix the ref parser for peeled refs

$ gitiup change show chg-8a4f --store ../store --json | jq '.attempt, .base_check, .fetch'
0
"ok"
"git fetch <remote> 'refs/changes/chg-8a4f0932daec33f2/*'"
```

What each one promises, in the order the promises matter:

* `new` reads a repository with git plumbing and *signs where it drafts*: an unsigned
  change is a rumour, and the format refuses one, so there is no unsigned intermediate to
  leak. `--base` is required; a change with nothing on top of the branch is refused rather
  than filed.
* `submit` pushes the commits, then the record bytes, then the refs — in that order, so a
  ref never promises bytes the store cannot return (ADR-0003 D5). On a git store the
  commits go as a git packfile, so a reviewer's plain `git fetch` of the change carries
  the proposed work and the record in one transfer; on a store with no git object database
  it says so out loud instead of letting the gap surface as a missing object.
* A base that has moved is a refusal (exit `6`) naming **both** oids and the store's own
  spelling of them, because a change whose base has moved is a change that cannot be
  merged. `list` and `show` re-check it on every read and print `[stale base]`.
* A re-submit is an attempt, never an overwrite: attempt *n*'s ref is create-only and its
  bytes never move, `head` moves under compare-and-swap, and continuing a change is said
  with `--change <id>` because an amended commit cannot recompute its own change id.
* `show` reads the record **through the ref that advertises it**, so the store-binding
  checks (bytes hash to the name they are filed under, the record is about the change its
  ref says, `head` names the newest attempt) happen on the way in and not as an extra
  command.

The rules, the refusal table and the exit codes are in
[docs/changes.md](../../docs/changes.md); the record format itself is
[ADR-0003](../../docs/adr/0003-change-record-format-and-merge-semantics.md). Merging and
checking out (`gitiup change merge`, `gitiup change checkout`) are separate tickets and
not here yet.

## `gitiup verify attestation`

The question the format exists to answer, in one exit code: *may this proof be acted
on?* It re-hashes the manifest, checks every signature and whether the signer is
trusted, counts distinct trusted signers, checks the tier and sandbox, the environment
requirement, and the freshness window — in ADR-0001 D7's fixed order, so the first
thing wrong is what the exit code says, and prints every other thing wrong too.

```console
$ gitiup verify attestation --store ./store --commit "$(git rev-parse HEAD)" --policy gitiup-policy.json --json
{"accepted":false,"attestation":{…},"checks":[…],"exit":6,"policy":{…},"reasons":[{"class":"policy","code":"environment","detail":"this run's arch is 'aarch64', which does not match what this change requires: amd64 (canonical x86_64)","exit":6}],"source":"fs store ./store · kv/attestation/f01a…","stored":"f01a8261…","verdict":"policy"}

$ gitiup verify attestation proof.json --trust ada --max-age 1d
source        file proof.json
run           sha256:994698a11e4cbe855aedf227980bc75f74342b470e611c519dbe45bb864f1b1f
result        sha256:fee3b8e9194ff042b5725fd200f3b2360a9ab2b8c57a9b121e1aebb74d2ed88f
commit        sha1:dddddddddddddddddddddddddddddddddddddddd · job test
workflow      .github/workflows/ci.yml · pull_request
tier          local · runner gitiup 0.1.0 · sandbox landlock · normalisation v0
environment   os macos · arch aarch64 · provider shell · fingerprint sha256:d32af993…
claimed       2026-10-27T09:15:02Z (1d44m old)
signed        SHA256:3l7Z…QG3g (ed25519)
steps         3
policy        trust: --trust, 1 key(s) · tiers local · min 1 signature(s) · max age 1d · env nothing required

checks
  structure       ok
  digest          ok
  commit          not asked
  result          not asked
  challenge       not asked
  normalisation   not asked
  environment     not asked
  signature       ok
  trust           ok
  min_signatures  ok
  tier            ok
  sandbox         ok
  freshness       REFUSED    · attestation is 1d44m old, which exceeds the 1d window
  expiry          not asked

verdict       POLICY (exit 6)
reason        [freshness] attestation is 1d44m old, which exceeds the 1d window
              hint: re-run the job, or widen the owner's freshness policy deliberately
```

| exit | meaning |
|------|---------|
| 0 | accepted |
| 2 | usage (no verdict) |
| 3 | I/O, store unreachable (no verdict) |
| 6 | refused: untrusted signer, too few signatures, tier or sandbox not allowed, stale or future-dated, wrong machine class, unreadable document |
| 7 | a signature that does not verify |
| 8 | digest mismatch: non-canonical bytes, wrong commit, wrong result digest, a store that returned bytes other than the ones it names |

A verdict is printed on stdout and carried in the exit code — a refusal is a result, not
a fault, so stdout stays parseable and stderr stays empty. `--policy` reads the
`gitiup-policy.json` a repo commits; `--trust` names a key (a `SHA256:` fingerprint or
a keystore name) and, when nothing else names one, this machine's keystore is trusted
and says so in the output. `--json` is stable: the keys, the check ladder and the
reason shape are pinned by `tests/verify_cli.rs`. The whole contract — ladder,
reasons, where trust comes from, what is deliberately not checked — is
[docs/verification.md](../../docs/verification.md).

## `gitiup key` and `gitiup identity`

```console
$ gitiup key gen --comment ada@laptop
created ada-laptop
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  public  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwrkrGZ+b40H+pDMpSvxdldmwJeXj9YS/bF9U9DoFUQ
  secret  encrypted with age (scrypt) in /home/ada/.config/gitiup/keys

$ gitiup identity publish ada --email ada@example.com
published ada
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  signed  by ada-laptop (keystore)
  file    /home/ada/.config/gitiup/identities/ada.identity.json
  this is now the current identity

$ gitiup identity whoami --check
ada — ada
  key id  SHA256:jNV4N28TJ7ytCrDmXBu8snKgGktlHRmyR0TbXq5gHsQ
  key     ada-laptop (keystore)
  where   keystore, age-encrypted at ada-laptop.secret.age
  check   signs and verifies
```

The commands, the passphrase rules and the claim format are
[documented here](../../docs/signing-keys.md); the decisions behind them are
[`gitiup-keys`](../gitiup-keys/README.md). Everything works from a script —
`--passphrase-file -`, `--key`, `--json` — and nothing here requires a terminal.

| exit | `key` and `identity` |
|------|----------------------|
| 0 | done |
| 2 | usage |
| 3 | I/O, no such key or identity, or an agent that cannot be reached |
| 6 | refused: wrong passphrase, name taken, a claim that is unsigned or malformed |
| 7 | a signature does not verify (a tampered claim, a broken endorsement) |

## `gitiup select`

Who verifies one change, and the proof of why they were chosen. One command, two jobs,
told apart by whether the round already exists — the selector's and everybody else's.

```console
$ gitiup select --change chg-1 --job build/matrix/linux-x86_64 \
      --head sha1:e255b091aabd7e443b5d2fbeb90bc9769d07cbeb \
      --proposer ada --require-arch x86_64 --store ./store --explain --publish
derived a new selection — change chg-1 · job build/matrix/linux-x86_64 · attempt 0
  roster   epoch 29631 · 8 entries · 7 identities · sha256:…
  policy   n=5 · agree 4 · reserves 2 · floor anonymous · 1 seat(s) per identity · caps …
  seed     sha256:… — derived from the selector key SHA256:own… (ADR-0002 D2)
  proposer: 2 family box(es) excluded (SHA256:ada…, SHA256:ada…)
  seats    5 of 5 filled · 6 of 8 roster entries eligible
  …
```

```console
$ gitiup select --change chg-1 --store ./store --json | jq '.selected | length'
5
```

The audit path needs no key: it reads the round record, the roster epoch it pinned and
the published seed, and re-derives the same ordered list
([ADR-0002](../../docs/adr/0002-roster-verifier-selection-and-sybil-resistance.md) D3).
`--explain` prints the audit table — every roster entry, its score, the first eligibility
filter that failed it, and what the greedy pass decided — and `--json` puts the ADR's
selection document at `.selection`. Opening a round is the other half: it requires
`--proposer`, excludes that author's whole identity family before the seed is derived, and
refuses the round afterwards if the check says the author got in anyway. See
[docs/quorum.md](../../docs/quorum.md).

## What is deliberately *not* here yet

The merge gate itself (giti-kd4.5) — `verify attestation` answers "is this attestation
good enough?" and exits; deciding that a *merge* may proceed (how many proofs, from
which quorum, recorded where) is that gate's job, and it adds its own reasons to the
same report. `gitiup pull` (giti-kd4.4), which fetches a stranger's change and
verifies its attestation before applying it, is the other open half. Both call the
checks that are already here rather than adding new ones.

## Tests

* `tests/digest_cli.rs` — runs the built binary: both digests, stdin, `--json`,
  `--quiet`, `--expect` both ways, every exit code, and the committed golden
  fixtures (so the CLI cannot drift from the pinned vectors).
* `tests/normalise_cli.rs` — the same for `normalise`: the rewrite record, `--json`
  agreeing with the library, two machines converging, a real divergence as exit `8`
  naming step, field and both sides, `--rules`, and every exit code.
* `tests/keys_cli.rs` — `gitiup key` and `gitiup identity` as command lines, with a
  temp `GITIUP_CONFIG_HOME` each: generate, import a real OpenSSH file, publish,
  endorse, use, whoami, verify, move a claim between two config homes — all driven
  through stdin and `--json`, no terminal; exit `3` for a missing agent, `6` for a
  wrong passphrase or a duplicate name, `7` for a tampered claim; and nothing on disk
  but the age container.
* `tests/select_cli.rs` — `gitiup select` as command lines: five seats filled under the
  default policy, the author and their second box excluded and *seen* to be excluded, a
  second harness with an empty keystore reproducing the published selection byte for byte
  (from a store, and from two files with no store at all), a round that let an author in
  refused on audit, one round per architecture, a change with two rounds refusing to guess
  which, and a pool too small for five saying `Insufficient` instead of shrinking.
* `tests/participant_cli.rs` — the roster round trip: register, approve, list, revoke, and
  a published epoch that re-verifies from the store's own bytes.
* `tests/attest_cli.rs` — `gitiup attest` as command lines, each in a fresh process with a
  temp home and store: push → list → show with digests that match `gitiup digest` for the
  same report, an unsigned document refused (`6`), a re-push reported idempotent, `gc`
  pruning over a per-commit cap and by age (with the run recorded), a `--keep` surviving,
  an empty policy refused, and — over loopback smart HTTP with nothing but `git` on the
  reading side — a plain `git clone` + `fetch refs/attestations/*` ending up holding the
  exact signed bytes.
* `tests/change_cli.rs` — `gitiup change` as command lines, against a real local
  repository and three stores: a draft naming its commits, its author and the merge-base it
  forked from; submit → list → show round-tripping the *same bytes* (`--bytes` returns what
  `new` wrote, because a signature covers canonical bytes); a re-submit becoming attempt 1
  with attempt 0's ref and record unmoved; a stale base refused with both oids in the
  message and nothing written; a store with branches and none of them yours, refused by
  name; an unsigned record, an unnamed store, an unknown handle and a 3-hex handle each
  refused with the right exit code; and — over loopback smart HTTP, with nothing but `git`
  on the reading side — a change that reaches a plain git remote so that `git fetch` of
  `refs/changes/<id>/*` brings the record *and* every commit it proposes.
* `tests/verify_cli.rs` — `gitiup verify attestation` as command lines, each in a fresh
  process, every one with the clock pinned: the acceptance path and the ladder's
  outcome for each check; exit `6` for an untrusted signer (signature `passed`, so the
  two are never confused), a disallowed tier, staleness, too few signatures, an
  unsigned document, an environment the change will not take, and a policy file that
  argues with itself; exit `7` for a manifest edited after signing and for a key id
  that is not its key's fingerprint; exit `8` for pretty-printed bytes, a wrong commit
  binding, a wrong expected `ResultDigest`, and a corrupted CAS blob; the store paths
  (`--commit`, `--digest`, two attestations refusing to be guessed between); the `--json`
  shape pinned (top-level keys, the ladder in D7 order, `{code, detail}` reasons) and
  the table's verdict on stdout with nothing on stderr, while usage and I/O errors are
  the reverse.
* `tests/doc_examples.rs` — the worked report in `docs/run-report.md`, parsed and
  digested: the documentation example is the pinned example.
* `tests/cli_hygiene.rs` — the dependency list stays at three crates, no network or
  forge client is reachable from here, and the documented exit codes are the ones
  the code uses.

## Building

```sh
cargo build -p gitiup
cargo test -p gitiup
```

Dependencies: `gitiup-attest`, `gitiup-normalise`, `gitiup-keys`, `serde_json`. No
argument parser, no HTTP client, no C toolchain.

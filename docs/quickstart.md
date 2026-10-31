# Quickstart

*Every `$` line on this page is run, in this order, by
[`quickstart_doc_cli.rs`](../crates/gitiup/tests/quickstart_doc_cli.rs) — in a temporary
directory, against the binary under test, with an empty keystore and no network. A line
shown as `…` means output elided here; `# exit N` means the command above it exits with N.
Like every other page here, this one is executed rather than eyeballed, because a
quickstart that has never been followed is a list of guesses.*

gitiup does two things, and they are the same thing:

1. it runs a GitHub Actions job **on your own machine, inside a sandbox it probed first**,
   and turns what came out into a **signed attestation** whose digests anyone can
   recompute from the same starting point;
2. it moves those attestations and **signed change records** between **stores** — a
   directory, an S3 bucket, a plain git repository — so work can be proposed, proved and
   merged with no forge in the middle.

By the end of this page you will have planned a job, run it for real, signed the result,
filed it in a store, read it back as a stranger who trusts nothing, published the rule a
merge applies, opened a change against a repository nobody hosts, merged it, and watched
a push be refused because it could not prove anything.

Fifteen minutes, one machine. This page plays the contributor and the owner with one key
on one box, and says out loud where a real project would split them into different
machines with different keys.

## Before you start

* **Linux** for the parts that run a job. Sandboxing is kernel-enforced (Landlock,
  bubblewrap, a container runtime); elsewhere `--execute` is refused and the only tier on
  offer is `simulated`, which is a plan and not evidence. See
  [the sandbox](sandbox.md) for what is available where you are.
* **`git`** (2.28 or newer) on `PATH`. The store here is a bare repository and the
  plain-git host drives your `git`.
* **Rust 1.88+** to build.

## 1. Build it

```sh
cargo build --release --locked -p gitiup
# then put target/release/gitiup on your PATH, or:
cargo install --path crates/gitiup --locked
```

```console
$ gitiup version
gitiup 0.1.0
```

`gitiup help` is the whole command table, and every verb has its own page:
`gitiup run help`, `gitiup attest help`, `gitiup change help`, `gitiup policy help`.
Read those before you guess a flag; the flags mean something specific here.

## 2. Ask what this machine can promise

```sh
gitiup doctor --sandbox     # what, if anything, confines a job here
gitiup env                  # what a run here would say about this machine
```

Two lines of that report matter to a newcomer. `active backend` names what a real run
would be confined by — on the machine this page was written on, `landlock`, which needs
no runtime at all. And `verdict`: **exit 0** means this box may serve somebody else's
job, **exit 6** means nothing here confines a job, so `gitiup run --execute` will refuse
and every attestation you can produce says `simulated`. `gitiup env` is the other half:
the fingerprint a run here writes into its own attestation, which is how a reviewer
notices your "build" happened on a machine with a different toolchain than the change
asked for ([the environment fingerprint](environment.md)).

## 3. Five words, then the commands

| word | what it is |
|------|------------|
| **store** | where refs and content-addressed objects live: a directory, a bucket, or a git repository. Every command that touches one names it with `--store <dir>` or `--remote <name>`. There is no invisible default database. |
| **attestation** | one signed, canonically-encoded JSON record: what ran, on what, with what inputs, and what came out. Its digest is its name. [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md). |
| **tier** | what a run is entitled to be believed as: `simulated` (a plan), `local` (it ran, in your sandbox), `quorum` (independent verifiers agreed). [Provenance tiers](provenance-tiers.md). |
| **policy** | the rule a merge applies, published *in the store* and signed by the repository's owner — not in a checkout, where a fork could edit it. [The published policy](policy.md). |
| **change** | the thing a stranger publishes when there is no pull request: one signed record naming a commit, a branch and the oid that branch was at. [Contributing without a forge](changes.md). |

`quorum` — the optional network of volunteers who re-run the job and agree — is the one
subject this page only points at, in [the quorum tour](quorum.md).

## 4. A project, and a store to put it in

Make a directory that holds both a repository and the store that receives it:

```text
demo/
├── gitiup.toml     ← names the store, found from any directory under demo/
├── store.git/      ← the store: a bare repository. This is the "owner".
└── proj/           ← your repository, with .github/workflows/ci.yml
```

```console
$ mkdir -p demo
$ cd demo
$ mkdir -p proj/.github/workflows
$ cat > proj/.github/workflows/ci.yml <<'YAML'
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: Check the tree
        run: echo "on $(uname -s)"
YAML
$ echo 'fn main() {}' > proj/main.rs
$ git init -q -b main proj
$ git -C proj add -A
$ git -C proj commit -q -m "add the thing and its workflow"
$ git init -q --bare store.git
```

The store is a git repository, so the git host has to be told so — a path is a
directory store until a remote says otherwise. Write `gitiup.toml` here, in `demo/`;
gitiup looks in the current directory and every parent, so commands in `proj/` find it.
The `file://` URL has to be absolute (that is what `$PWD` is for, and the heredoc is
unquoted so it expands). Then give the store a branch, and check that gitiup agrees with
you about what `origin` is:

```console
$ cat > gitiup.toml <<EOF
[[remote]]
name = "origin"
url = "file://$PWD/store.git"

[remote.options]
host-type = "git"
EOF
$ git -C proj push -q "$PWD/store.git" main
$ gitiup doctor --remotes
…
```

The report names the file it read and then `origin [git] — <url>`: one remote, served by
the plain-git host. `gitiup doctor --remotes` is the command to reach for when a store is
not the store you thought it was.

Now work in the repository:

```console
$ cd proj
$ gitiup run
WARNING: SIMULATED: nothing was executed. This attestation describes a plan and proves intent, not behaviour: no code ran, no network was used, no artifact was produced.
WARNING: do not merge, publish, or release on the strength of a simulated attestation.
…
gitiup run plan
  workflow   .github/workflows/ci.yml
  name       CI
  triggers   pull_request
  runs       1

  job build
    runs-on    ubuntu-24.04
SIMULATED step 1 'Check the tree' — nothing executed
  script   echo "on $(uname -s)"
  outcome  assumed success (exit 0): assumed, not observed

  note       a simulated run executes nothing: exit codes below are assumed, never measured
…
tier           simulated
normalisation  v0
```

## 5. The first run runs nothing, on purpose

Read that output twice, because this is the design decision the rest of the tool is
built on: **the default is a simulation**. Nothing was spawned, no network was touched,
no secret was read, the step's `exit 0` was *assumed*, and the attestation it produced
says `tier: simulated` — a plan, not evidence. gitiup will not let you mistake a
workflow's intentions for an observation.

You can see the gate close if you try to keep one:

```console
$ gitiup run --out plan.json  # exit 6
…
gitiup: policy: provenance tier 'simulated' is not accepted here
hint: a simulated run plans but does not execute; run it for real (`gitiup run --execute --sandbox <backend>`) to satisfy this gate, or set `"allow_simulated": true` in the policy only if a plan is genuinely what you want to record
```

The built-in policy allows `local` and nothing else, and asking to *write* the
attestation is where the policy applies. That is deliberate: a simulated attestation
looks exactly like a real one, so keeping one is the step that has to be refused by
default rather than warned about.

## 6. Run it for real

```console
$ gitiup run --execute --sandbox landlock --out build.attestation.json
ran job build in landlock
   1. Check the tree — exit 0
commit         sha1:68e58f5bc4fe70a905070fdfb0a7136531872f51
sandbox        landlock
…
tier           local
normalisation  v0
wrote        build.attestation.json
```

Use whatever backend `gitiup doctor --sandbox` names as active — `--sandbox docker`,
`--sandbox bwrap`, `--sandbox unshare`. `landlock` is used here because it needs no
runtime. `gitiup run --sandboxes` lists what this build offers and why each of the
others is not available on this machine; `none` is refused, because an unconfined run
earns no tier.

Now the tier moved to `local`, and the two elided lines are the point of the whole tool:

* `run` — the **RunDigest**: the hash of the whole manifest, including the clock and the
  run id. It identifies *this occurrence*; it will not survive a rerun and does not try to.
* `result` — the **ResultDigest**: the hash of the `result` half only — source, pins,
  inputs, environment fingerprint, per-step outcomes. This is the number a second honest
  run on a different machine is supposed to reproduce, and it is what a verifier compares.

Confusing the two is the most common way to decide reproducibility "does not work".
[Provable CI output](provable-output.md) is the long version.

## 7. A key, so the proof is somebody's

```console
$ gitiup key gen --comment ada@laptop
created ada-laptop
…
```

An unsigned attestation is a rumour, so before filing one you need a signing key. The
keystore holds it in an age container encrypted with a scrypt-derived key
([signing keys and identities](signing-keys.md)); gitiup asks for the passphrase on the
terminal, or takes `GITIUP_KEY_PASSPHRASE` / `--passphrase-file -` when there is no
terminal, which is what this page's test does. A `gitiup key gen` key becomes the
current identity when it is the only one; with several, pass `--key <name>` — the tools
refuse to guess which of your keys signed something.

A real project's contributor and owner are different machines with different keys. Here
they are one box, and every step that says "the owner" is the step where that would be
somebody else's keyboard.

## 8. File the proof, and read it back

```console
$ gitiup attest push build.attestation.json --sign --remote origin --out proof.json
wrote proof.json
…
  store    remote 'origin'
  ref      refs/attestations/68e58f5bc4fe70a905070fdfb0a7136531872f51/…
…
  tier     local · signed by …
```

`--sign` because the file `gitiup run --out` wrote is the attestation *before* anybody
signed it; `--out proof.json` keeps the exact bytes that were stored, which is the file
you will hand to a stranger or a hook. The store now advertises it by a ref, and that is
worth seeing with plain git:

```console
$ git ls-remote ../store.git 'refs/attestations/*' | wc -l
1
```

One ref, on a plain git repository. `git fetch 'refs/attestations/<commit>/*'` brings
the signed bytes across in the same packfile as the branch, with no gitiup on the
transport ([host abstraction](host-abstraction.md)).

Read it back out of the store rather than from the file you kept:

```console
$ gitiup attest list --commit "$(git rev-parse HEAD)" --remote origin
…
```

And ask the question the format exists to answer:

```console
$ gitiup verify attestation proof.json
source        file proof.json
…
commit        sha1:68e58f5bc4fe70a905070fdfb0a7136531872f51 · job build
…
policy        trust: this machine's keystore, 1 key(s) · tiers local · min 1 signature(s) · max age 1d · env nothing required

checks
  structure       ok
  digest          ok
…
  signature       ok
  trust           ok
  min_signatures  ok
  tier            ok
  sandbox         ok
  freshness       ok
  expiry          not asked

verdict       ACCEPTED (exit 0)
```

Every check in that ladder runs, in a fixed order, and the first failure is what the
exit code means: **0 accepted · 6 refused · 7 bad signature · 8 digest mismatch**.
`--json` prints the same verdict as data, which is what a merge gate reads.

The trust line is the one to notice: on this machine the key that signed the proof is in
this machine's keystore, so it is trusted. Copy the file to a box with no keys and the
same command refuses:

```console
$ GITIUP_CONFIG_HOME=/tmp/empty-keystore gitiup verify attestation proof.json  # exit 6
gitiup: nothing is trusted here: no --trust, no trust_key_ids in a policy, and no key in the keystore
hint: `gitiup verify attestation doc --trust <key-id>` names one, or write them into gitiup-policy.json
```

That is the whole security story in miniature: **verification never infers whom to
believe**. You tell it — `--trust <key-id>`, or a published policy's trust list — and
[verification](verification.md) explains the order it checks in and what it refuses to
do.

## 9. Publish the rule a merge will apply

Be the owner for a minute. A store with no policy refuses every gated merge rather than
deciding by a default nobody chose, so publish one:

```console
$ gitiup policy publish --remote origin --allow-tier local
…
  store   remote 'origin'
…
  protects refs/heads/**
trusted here: SHA256:… — a verifier applies this policy only if its own trust list names that key
next: anyone reading this store asks with `gitiup policy show --store .`
```

`--allow-tier local` says a run inside the submitter's own sandbox is evidence enough
here — true for a personal repository, not for a project. `--trust` defaults to the
signing key, `--min-signatures`, `--max-age` and `--allow-tier quorum` are how you raise
it to "four of five volunteers must agree". `gitiup policy show --remote origin` prints
what is in force; [the published policy](policy.md) has three worked examples.

Publish the policy *before* you run the job you want it to judge: the ladder resolves
which policy was in force **when the run happened**, and an attestation older than every
policy revision is refused with `policy_history_missing` rather than judged by a rule
that did not exist yet.

## 10. Contribute without a forge

Now the contributor's four commands, on a branch:

```console
$ git checkout -q -b fix/greeting
$ echo 'hello, world' > greeting.txt
$ git add greeting.txt
$ git commit -q -m "greeting: say hello"
$ gitiup run --execute --sandbox landlock --out greeting.attestation.json
ran job build in landlock
   1. Check the tree — exit 0
…
tier           local
normalisation  v0
wrote        greeting.attestation.json
$ gitiup attest push greeting.attestation.json --sign --remote origin
…
  tier     local · signed by …
$ gitiup change new --base main --out change.json
change chg-…
  attempt  0 · anchor sha1:…
  base     refs/heads/main @ sha1:68e58f5b…2f51 (1 commits)
  head     sha1:…
  title    greeting: say hello
  jobs     build (workflow .github/workflows/ci.yml)
  author   … (ada@laptop) · signed
  digests  change sha256:… · record sha256:…
  written  change.json
  next     gitiup change submit --record change.json --store <dir>
$ gitiup change submit --record change.json --remote origin
submitted chg-… attempt 0
  store    remote 'origin'
  base     refs/heads/main @ sha1:68e58f5b…2f51 [the store agrees]
…
  ref      refs/changes/chg-…/attempt/0
…
  quorum   not asked for: the published policy (rev 1, …) allows local and not `quorum`
$ gitiup change list --remote origin
chg-…  open      a1   sha1:…   …  greeting: say hello
$ CID=$(gitiup change list --remote origin | head -1 | cut -d ' ' -f1); gitiup change show "$CID" --remote origin
change  chg-…  ·  open
  store     remote 'origin'
…
  fetch     git fetch <remote> 'refs/changes/chg-…/*'
```

The change's id is the first field of the listing; `show` is the audit view, so it prints
full digests where `new` and `submit` shorten them — the line you paste into an issue
should be one a stranger can check. The commands below ask the store for the id instead
of making you copy a hex string out of a terminal.

Four things worth naming in that output:

* `change new` **requires** `--base` and refuses a change that proposes nothing: which
  branch work is *for* is not guessable, and a wrong guess merges into the wrong place.
* The record is signed where it is drafted. `author` is a key, not a username, so a
  mirror, a bucket and a forge all say the same thing about who proposed it.
* `submit` pushes the commits, files the record at `kv/change/<digest>` and moves
  `refs/changes/<id>/head` **under compare-and-swap**. A re-submit is attempt 1, never an
  overwrite; a base the store no longer has is exit 6 naming both oids.
* Because the store publishes a policy, `submit` also asks for the quorum rounds that
  policy demands — here none, because the policy accepts `local`.

`gitiup change checkout <id>` is the same door from the reviewer's side: one fetch
brings the commits *and* every proof filed for them into a clone as one thin pack, and
nothing is written back to the store.

## 11. May it merge? Then merge it

The owner's question, before touching the branch:

```console
$ CID=$(gitiup change list --remote origin | head -1 | cut -d ' ' -f1); gitiup verify change "$CID" --remote origin
verdict       MAY MERGE  ·  attestations: sha256:…  ·  from SHA256:…  (1 distinct signer(s) of 1; result sha256:…)
change        chg-…  ·  open  ·  attempt 0
store         remote 'origin'
…
checks
  change          ok
  policy          ok
  protects        ok
  attestations    ok
  quorum          not asked
  min_signatures  ok

accepted      attestations: sha256:…  ·  from SHA256:…  (1 distinct signer(s) of 1; result sha256:…)
```

Exit 0 means *may merge* under the policy in force; 6, 7 and 8 mean it may not, and say
which. Then merge it:

```console
$ CID=$(gitiup change list --remote origin | head -1 | cut -d ' ' -f1); gitiup change merge "$CID" --remote origin
merged  chg-… attempt 0
  store    remote 'origin'
  branch   refs/heads/main sha1:68e58f5b…2f51 → sha1:…
  via      store (gitiup moved the ref under CAS)
…
  signed   … (ada@laptop)
$ git --git-dir ../store.git log --oneline main | head -1
… greeting: say hello
```

The branch moved because a signed proof said it could, and the merge wrote its own
signed record saying which proofs it believed — cite them with `--proof <full digest>`
(the full form is what `attest list --json` prints) and retention will pin them so
`gc` cannot sweep the evidence a merge rested on. Run the merge with `--dry-run` first
whenever you are learning what it will say; it does everything except write.

## 12. Make the rule refuse at the ref itself

So far the gate is a command you remembered to run. Put it on the repository:

```console
$ gitiup hook install pre-receive --repo ../store.git
…
  proves    required — a refs/heads/** update needs an attestation set the published policy accepts
…
  undo it:  gitiup hook uninstall pre-receive --repo …
$ gitiup hook status --repo ../store.git
…

GATED — a refs/heads/** update whose new head has no policy-satisfying proof set is refused here
```

Now an ordinary `git push` of an unproven commit is refused, by the store, in words:

```console
$ echo 'and again' >> greeting.txt
$ git commit -qam "greeting: a second line"
$ git push ../store.git HEAD:refs/heads/main  # exit 1
…
remote: gitiup: REFUSED  refs/heads/main …  [attestations] sha1:… has no attestation in repository …; nothing is proved about it
…
 ! [remote rejected] HEAD -> main (pre-receive hook declined)
error: failed to push some refs to '../store.git'
```

Do it properly — run the job, file the proof, push again:

```console
$ gitiup run --execute --sandbox landlock --out second.attestation.json
…
$ gitiup attest push second.attestation.json --sign --remote origin
…
$ git push ../store.git HEAD:refs/heads/main
…
   …  HEAD -> main
```

`gitiup doctor --hooks --repo ../store.git` is the same answer as an exit code, which is
what a check on the store itself runs. `refs/changes/**`, `refs/attestations/**` and
`refs/gitiup/**` stay open on
purpose — a stranger has to be able to publish a change and its proofs somewhere before
anything can be judged.

## 13. The exit codes, once

| code | means | where |
|------|-------|-------|
| 0 | yes: accepted, may merge, ran | everything |
| 2 | usage: a flag was wrong or missing | everything |
| 3 | I/O, or a store that could not be reached | everything |
| 6 | **refused**: a tier not allowed, a signature not trusted, a base moved, a policy missing, a change that proposes nothing | `verify`, `policy`, `change`, `attest`, `run` |
| 7 | a signature that does not verify | `verify`, `key`, `identity` |
| 8 | digest mismatch: the bytes are not what their own name says, a rerun diverged | `verify`, `digest`, `normalise --compare` |
| 9 | attempts exhausted: the quorum ran out of escalations, and asking again is what just ran | `quorum retry` |

`6` and `9` are the pair worth remembering: 6 says *something about the evidence or the
policy would have to change*, 9 says *there is nothing left to retry*. A caller that
retried on 6 loops forever, which is what the cap exists to prevent.

## 14. What this page did not touch

* **A matrix or several jobs.** One attestation is one result, so a matrix job needs
  `--matrix k=v` (or a job name) to say which arm it describes; ambiguity is exit 6
  rather than a coin flip. `gitiup run help`.
* **Secrets.** `--secret NAME` names one for `--execute` and nothing reads it in a
  simulated run; a name is not a value and the attestation records the name only.
* **Normalisation and reproducibility.** Independent runs converge because
  `gitiup-normalise` rewrites the machine-specific parts of a log into placeholders —
  `gitiup normalise --compare a.json b.json` is exit 8 when they diverge.
  [Reproducibility — the contract](reproducibility.md).
* **The quorum.** `gitiup participant register`, `gitiup select`, `gitiup work` (the
  volunteer's loop: poll for rounds addressed to your key, lease a seat, run it in a
  sandbox, sign it, publish it), `gitiup quorum verdict | dispute | retry`.
  [The quorum verification network](quorum.md) is the tour.
* **Federation.** `gitiup fetch | push` and `gitiup attest import` move proofs between
  stores and refuse to move trust with them; `gitiup migrate repo` leaves a forge.
  [Federation](federation.md).
* **Buckets and forges.** A store is a directory, a bare repository, a bucket or a
  GitHub remote; the same three flags find all of them.
  [Host abstraction](host-abstraction.md) and the
  [`gitiup-host` README](../crates/gitiup-host/README.md).

## 15. Where to read next

| you want to know | read |
|------------------|------|
| what a run is allowed to be believed as | [provenance tiers](provenance-tiers.md) |
| what `verify` checks, in what order, and what it refuses to decide | [verification](verification.md) |
| how a policy is signed, published and resolved | [the published policy](policy.md) |
| how to run a job so its bytes come out the same twice | [reproducibility](reproducibility.md), [the run report](run-report.md) |
| what the sandbox does and does not isolate | [the sandbox](sandbox.md) |
| how a change is stored, and what a merge records | [contributing without a forge](changes.md), [ADR-0003](adr/0003-change-record-format-and-merge-semantics.md) |
| where the decisions that several tickets depend on are kept | [the ADR index](adr/README.md) |

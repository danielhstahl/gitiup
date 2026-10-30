# Contributing without a forge — the change workflow

*Tickets: the `giti-b2z` epic — `giti-b2z.3` (`gitiup change new|submit|list|show`),
`.4` (`change merge|reconcile`), `.5` (`change checkout`), `.6` (the change-workflow
conformance suite), `.7` (GitHub parity) — and the epic's own sequence, run against a
directory store and a bare repository in
[`change_bare_repo_cli.rs`](../crates/gitiup/tests/change_bare_repo_cli.rs). Format
decision: [ADR-0003](adr/0003-change-record-format-and-merge-semantics.md). Host
contract: [host abstraction](host-abstraction.md). Proofs about a change:
[verification](verification.md).*

> A change is the object a stranger publishes when there is no forge. Not a pull request,
> not a patch email: one signed record in a content-addressed store, advertised by a ref,
> whose merge is a compare-and-swap a bucket can honour. This document is both halves — the
> contributor's four commands, the owner's merge, what each one promises, and the refusals
> that are refusals rather than advice.

```text
gitiup change new    --base main          draft a signed record from local commits
gitiup change submit --record … --remote …   publish one attempt of it
gitiup change list   [--state open] [--json]  what a store advertises
gitiup change show   <id> [--attempt n]    one change, read back through its ref
gitiup change checkout <id> [--for job]    bring it, and its proofs, into a clone
                                           — and read that job's quorum while at it
gitiup change merge     <id> [--expected-oid OID] [--proof DIGEST]   merge it, or --dry-run
gitiup change reconcile <id>              write the merge record for a move that happened
```

## The whole path, in one screen

```console
$ gitiup key gen --name ada                          # once (docs/signing-keys.md)
$ cd my-repo && git checkout -b fix-ref-parser …     # the work, as usual

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
  objects  a fs store has no git object database: the objects are filed as gitiup records,
           so `git fetch` of the change will not carry them
  title    Fix the ref parser for peeled refs
  jobs     build, test
  author   KgCqW9kg…AgNQ (gitiup)
  ref      refs/changes/chg-8a4f0932daec33f2/attempt/0
  head ref refs/changes/chg-8a4f0932daec33f2/head -> sha256:cc9147d1…90ef
  record   kv/change/cc9147d14075631660af262973b62415dedca83cca08916bffdf1e7c4a2990ef (831 bytes)
  digests  change sha256:21cb95bb…a6fd · record sha256:cc9147d1…90ef

$ gitiup change list --store ../store
chg-8a4f0932daec33f2  open      a1   sha1:2d394df0…7e86   KgCqW9kg…AgNQ  Fix the ref parser for peeled refs

$ gitiup change show chg-8a4f --store ../store
change  chg-8a4f0932daec33f2  ·  open
  store     fs store ../store
  ref       refs/changes/chg-8a4f0932daec33f2/head
  record    sha256:1e5e67d05cb0401f1e100b5dab20d743bd7378ec6f42500f3e252e5888e69d16 (831 bytes)
  digests   change sha256:0349f71181f2ef8ac187745280c1b4f1dedd2308f9d5216571a30fc5c59e64ea · record sha256:1e5e67d05cb0401f1e100b5dab20d743bd7378ec6f42500f3e252e5888e69d16
  attempt   0 of 1 · anchor sha1:2d394df050ee55b98700d879e9d4b4b8ded87e86
  head      sha1:2d394df050ee55b98700d879e9d4b4b8ded87e86
  base      refs/heads/main @ sha1:1b1cfe58e0a276a3c18eb9de20be20e1f4eed9f5 [the store has this base]
  title     Fix the ref parser for peeled refs
  jobs      build, test
  author    SHA256:KgCqW9kgRmaPcRdfcLQEoua6tsnuRDTsHeqgEsKAgNQ (gitiup)
  signed    KgCqW9kg…AgNQ (ed25519)
  created   2026-10-29T03:40:14Z (1793245214590132 µs)
  attempts  1
  * a0   sha1:2d3…7e86        KgCqW9kg…AgNQ  Fix the ref parser for peeled refs
  fetch     git fetch <remote> 'refs/changes/chg-8a4f0932daec33f2/*'
```

Two things in that screen are load-bearing. `--store ../store` and `--remote origin` are
the only ways a store is chosen — exactly as `gitiup attest push` chooses one, and the
same three hosts answer all of them: a directory, a bare repository, a bucket (a remote
named neither falls back to `default-remote`, and the output says so in those words, so
the store that was written to is never a mystery). And
`show` printed the author as a fingerprint with a signature behind it, because that is
the only form of "who proposed this" that a mirror can also confirm.

`show` prints digests in full on purpose (it is the audit view, and the line you paste into
an issue should be the line a stranger can check); `new` and `submit` shorten them, and
`--json` always carries the whole value.

## What `new` decides, and what it refuses to guess

`new` reads a local repository with git's plumbing (`rev-parse`, `merge-base`, `rev-list`,
`log --format=%s`) and mints the record:

| field | where it comes from |
|-------|---------------------|
| `head` | `--head`, else `HEAD` |
| `base.ref` | `--base`, resolved to the canonical `refs/heads/<branch>` |
| `base.oid` | `git merge-base head base` — *the point the work forked from*, which is the oid a merge later compares against |
| `title` | `--title`, else the head commit's subject line, cut at the format's 512-byte limit |
| `workflow.jobs` | `--job` repeated, else the job ids of the repository's workflow file, else empty — which means *no re-run requested*, not "run everything" and not "nothing is required" (ADR-0003 D9) |
| `author.key_id`, `signatures` | this machine's signing identity (`--key`, else `gitiup identity`), and the record is signed there and then |
| `change_id`, `attempts` | derived: `chg-` + 16 hex over author, base branch and anchor (D3) |

Two refusals are deliberate:

* **`--base` is required**, because "which branch is this for" is not guessable and a wrong
  guess is a change that merges into the wrong place.
* **a change that proposes nothing is refused** (exit 6). If `merge-base(head, base)`
  equals the head there is nothing on top of the branch; publishing an empty attempt would
  only give a reviewer a record to read.

A record is always signed where it is drafted. `from_canonical_bytes` refuses an unsigned
record — that is the format's rule, not this CLI's — so there is no such thing as a draft
that "will be signed later": the author *is* the signature. `submit --record` repeats the
whole verification (shape, digests, id re-derivation, signature) before it writes, so a
record handed over from elsewhere is checked by the same code a reader would use, in
D11's order, and nothing half-published ever reaches the store.

## What `submit` writes, in the order it writes it

ADR-0003 D5, and the order is the contract:

```text
1. put_pack             the commits and objects this change introduces
2. put_cas              kv/change/<record_digest>            (idempotent by content)
3. update_ref_cas       refs/changes/<id>/attempt/<n>  Expect::Absent
4. update_ref_cas       refs/changes/<id>/head         Expect::Is(what step 3 read)
5. publish_round        refs/changes/<id>/round/<job>/<attempt>  (one per job, per arm)
6. advertise_round      refs/gitiup/job/<change>/<job>           (the rounds that filled)
```

Steps 5 and 6 are the quorum ([`quorum`](../crates/gitiup/src/quorum.rs),
[docs/quorum.md](quorum.md)): they happen only when the store's published policy asks for a
`quorum` tier on the branch this change merges into, they take their seats and eligibility
floor from that policy and never from a flag, and everything they need is derived *before*
step 1 runs — so a round that would have left the author's own key family in the pool is a
refusal that wrote nothing, not a bad round sitting in the store. `--no-quorum` stops at
step 4 and prints what that costs.

Objects before bytes before refs, so a ref never promises bytes the store cannot return.
The pack is `git rev-list --objects <head> --not <base.oid>` — exactly the objects the
store cannot already have, because the base check has just proved it holds `base.oid`; a
force-push therefore costs a force-push rather than a re-upload of history.

A git store gets a git packfile, and a stranger's `git fetch` of the change carries the
proposed commits in the same packfile as the record — the ref's gitiup value is a small
pointer commit whose first parent is the proposed commit ([ADR-0003
D5](adr/0003-change-record-format-and-merge-semantics.md)). That promise is asserted
against a real `git-http-backend` in
[`change_cli.rs`](../crates/gitiup/tests/change_cli.rs), not asserted in prose. A store
with no git object database — an fs directory, a bucket — gets the same objects as a gitiup
raw pack, and `submit` says so in `objects.note` rather than letting the difference surface
as a reviewer's missing object. `--no-objects` says "the store already has them" out loud.

`--out <path|->` writes the exact bytes that were published, which are byte-identical to
the drafted ones: a signature covers the canonical bytes, so `show --bytes` after a submit
returns the file `new` wrote.

## The base must be the base the store has

This is the rule that turns "rebase your change" from a review comment into an exit code:

```console
$ gitiup change submit --record change.json --store ../store
gitiup: refs/heads/main is sha1:1b1cfe58e0a276a3c18eb9de20be20e1f4eed9f5 in this record and
sha1:380d0492ab9cf3c3af722c03d493b95f67926199 in the store
hint: stale base: rebase onto sha1:380d0492ab9cf3c3af722c03d493b95f67926199 (or re-draft from
it) and submit again as a new attempt — a change whose base has moved is a change that cannot
be merged (ADR-0003 D8 step 3)
$ echo $?
6
```

Both oids are always in the message, spelled the same way, because a person reading it has
to decide which of the two is the surprise. Two variants, both exit 6:

* **the store has branch refs and none of them is yours** — the refusal names your branch
  and lists the ones the store has, because a change proposed against a branch the store
  does not have is a change with no merge target;
* **the store has no branch refs at all** — there is nothing to be stale against, so the
  change is published and the output says `base.check: "absent"` and what that means,
  rather than pretending a check happened. (Publishing branches is the owner's act, done
  with plain `git push`; `gitiup` does not invent branches for a store. See
  [host abstraction](host-abstraction.md).)

`list` and `show` recompute the same comparison on every read and print `[stale base]`
beside a change whose base has moved:

```console
$ gitiup change list --store ../store
chg-8a4f0932daec33f2  open      a1   sha1:2d394df0…7e86   KgCqW9kg…AgNQ  Fix the ref parser for peeled refs  [stale base]
```

Staleness is a property of an attempt, not a state: it is cured by a new attempt, not by an
edit (D7).

## A re-submit is an attempt, never an overwrite

`change_id` is `SHA-256(author key ‖ base ref ‖ anchor)[0..16]`, and the **anchor is
attempt 0's head**. Amending a commit changes your head, so a re-push cannot recompute its
own name — which is why continuing a change is something you *say*, not something the tool
infers:

```console
$ git commit --amend …
$ gitiup change new --base main --change chg-8a4f --store ../store --out a1.json
attempt chg-8a4f0932daec33f2
  attempt  1 · anchor sha1:2d394df0…7e86
  …
$ gitiup change submit --record a1.json --store ../store --json | jq '.attempt, .previous'
1
"sha256:0349f71181f2ef8ac187745280c1b4f1dedd2308f9d5216571a30fc5c59e64ea"

$ gitiup change show chg-8a4f --store ../store
change  chg-8a4f0932daec33f2  ·  open
  …
  attempt   1 of 2 · anchor sha1:2d394df050ee55b98700d879e9d4b4b8ded87e86
  previous  sha256:0349f71181f2ef8ac187745280c1b4f1dedd2308f9d5216571a30fc5c59e64ea
  …
    a0   sha1:2d3…7e86        KgCqW9kg…AgNQ  Fix the ref parser for peeled refs
  * a1   sha1:a15…6288        KgCqW9kg…AgNQ  Fix the ref parser for peeled refs
```

The anchor and `attempts.previous` come from the store, and the attempt number is "one past
the highest attempt *present*" (D6) — recomputed at submit time rather than trusted from the
draft, so a submit that died between step 3 and step 4 is finished by the next one instead of
needing an operator. What that buys, and what it costs:

| situation | what happens |
|-----------|--------------|
| the same bytes again (a re-run of `submit`) | idempotent: `already: true`, no second write, `attempt` unchanged |
| the same head, different bytes | **refused, exit 6**: attempt *n* already proposes this commit. Restating a record (a title, the job hint) is attempt *n+1* and has to be said with `--new-attempt`, because the old attempt's attestations must stay where they are |
| a different head | attempt *n+1*: a new record, a new create-only ref, `head` moved under CAS. Attempt *n*'s ref and bytes never move — `show` lists both, and `show --attempt 0` returns the original bytes and signature |
| a different key, or a different base branch, for `--change` | **refused, exit 6**, naming the id your own key would produce: a change's name is derived, so only the key that opened it can write its next attempt |
| someone else moved `head` in between | `HostError::Conflict` → exit 6 with both digests. Nothing here force-pushes |

And the trap the anchor rule exists for, caught after the fact rather than before:
publishing attempt 0 of a change when your key already has *another* open change against the
same branch prints the sibling ids and says that if this was a re-push, next time say
`--change`.

## `list` and `show`: read it back, and check the store while doing it

`list` is one `refs/changes/**` listing wide (D7 — state is derived from which refs exist:
`merged` > `abandoned` > `open`), then one record fetch per change, because the listing's
author, title and jobs come out of the **signed record** and not a ref label: a store that
mislabelled a change could not then steer a listing. Refs in the change namespace that are
not this layout are reported as `unexpected_refs` rather than dropped silently.
`--state open|merged|abandoned|all` filters (default `open`).

`show <id>` accepts a full id or any unambiguous prefix of at least 4 hex, and reads the
record **through the ref that advertises it**, which is where the store-binding checks live
(D11 step 6): the bytes must re-hash to the name the ref files them under (exit 8), a record
must be about the change its ref says (6), an `attempt/<n>` ref must hold a record that
claims to be attempt *n* (6), and `head` must name the newest attempt (6 — a submit that
died mid-write, with the retry that finishes it in the hint). `--attempt <n>` shows an older
attempt; `--bytes` prints the exact stored bytes.

| field (`--json`) | what it answers |
|-------|-----------------|
| `change_digest` | the identity of the proposal — what a merge record, a verdict and `attempts.previous` cite; it does not move when a signature is added |
| `record_digest` | the CAS key: `kv/change/<hex>` is this record's own bytes, so "immutable" means something on a store with no database |
| `base_check` / `stale` | `ok` · `stale` · `absent`, computed against the store right now |
| `head_tracks_newest` | whether `head` names the newest attempt, or a half-finished submit left it behind |
| `fetch` | the refspec a reviewer fetches: one `git fetch` on a git host brings the record and every commit it proposes |

## Against a forge remote: the same verbs, one database more

A `https://github.com/owner/repo` remote served by
[`gitiup-host-github`](../crates/gitiup-host-github) (the `hosts-github` feature, on by
default) answers `new`, `submit`, `list`, `show` and `merge` with the same rules, the same
refusals and the same exit codes as a bucket. The difference is that a forge has a second
database of proposed work — pull requests — and three things it will not promise. Every row
of `list` and `show` therefore says which database it came from and what that means:

| `source` | what the store holds | what the forge holds | what a caller may do with it |
|----------|----------------------|----------------------|------------------------------|
| `ref` | the record, its refs, its proofs | nothing | everything a bucket allows: verify, merge under CAS |
| `both` | the record | a pull request over the same commit | the forge's merge instead of a ref write (D10) |
| `pull` | **nothing** | a title and a body | list it, show it, label it: nothing in it is signed, so nothing in it can be verified |

A pull request with no record behind it is **listed**, not skipped: `recorded: false`, an
`error` naming what is missing, and `change show gh-<n>` prints the forge's answer and says
outright that there is no record to check. A ref with no pull is the mirror case, and is
`source: ref` rather than an absence — the question was asked, and no is the answer.

The three limits, and the field each one is reported through:

| what the forge will not promise | the field that says so |
|---------------------------------|------------------------|
| the record and the pull are **two calls**: the store has the change before the forge is asked, and the second can fail alone | `pull not opened` and the forge's own reason on `submit`, then `source: ref` until a pull exists. A change with refs and no pull is an outcome, not a failure, and `merge` falls back to the store's CAS because that is all there is |
| there is **no ref transaction**: ref+ref and ref+blob are separate writes (`atomic_multi_write = false`) | `caveats[]` on every forge row (`CAVEAT_TWO_CALLS`, `CAVEAT_CAS`), `atomicity` in `merge --json`, and `gitiup doctor --remotes` |
| the forge **truncates what it holds**, including a change's own body | `copy_truncated: true`, with the cut written into the copy: the bytes of record are in the store, so a cut copy loses the discussion and not the proof |

## Checking it out: one fetch, the change and its proofs (`checkout`)

`submit` answers "how does work get in". `checkout` is the same door from the other side,
and it exists because a reviewer otherwise has to know three things — which ref to fetch,
which ref the proofs live under, and whether the bytes they name actually came — and get
all three right in one `git fetch` before `verify` can be run at all.

```console
$ cd my-repo && gitiup change checkout chg-422b13f7e1972adb --remote origin
checkout chg-422b13f7e1972adb attempt 0 · open
  store    remote 'origin'
  ref      refs/changes/chg-422b13f7e1972adb/head -> record sha256:dfd5393f…0376
  head     sha1:b23903d9…34ca · propose
  base     refs/heads/main @ sha1:cd9ee8fe…7c87 [held here]
  fetched  14 objects, 2823 bytes as a git packfile · 3 of the clone's refs were already
           in the store and were not fetched twice
           refs/changes/chg-422b13f7e1972adb/*
           refs/attestations/b23903d97740c06dd4f934fb111897f020c734ca/*
  proofs   1 arrived with the pack, for sha1:b23903d9…34ca
           sha256:7003c357…996d  simulated 1PQUtCVY…ek6Q · 2026-10-27T09:15:02Z
  worktree checked out on branch chg-422b13f7e1972adb at sha1:b23903d9…34ca
  next     gitiup verify change chg-422b13f7e1972adb --remote origin
           the tally is `gitiup quorum verdict … --job <job>`'s exit code, not this one's
```

**One fetch, two prefixes, one pack.** The wants are `refs/changes/<id>/*` and
`refs/attestations/<head>/*` in a single request, which is the promise
[host-abstraction](host-abstraction.md) advertises: on a git host a proof's canonical bytes
are a blob, its ref is a commit pointing at that blob, and so the ref cannot arrive without
the bytes. The clone's own ref tips are sent as haves, so what comes back is bounded by what
the change introduces and not by the repository's history. If a store will not honour the
haves the fetch is retried without them and says so (`degraded: true`) rather than failing.

**A counted proof is a proof that is here.** Every attestation the store lists for the head
is checked against the clone afterwards — the blob its ref names, present in this object
database, at the length the record claimed. A ref that arrived *without* its bytes exits 8;
printing a proof nobody could produce is worse than printing none. That is why this command
needs a git-backed store: an fs store or a bucket holds the change's commits as gitiup
records and has no way to hand over git objects, and it is refused **by name** with the
verbs that do work against it (`change show`, `verify change`, `git fetch` of the refspec
`show` prints) rather than half-succeeding.

**Nothing is written to the remote, ever.** Not a ref, not a record, not a pack pushed back
"to be helpful" — which is what lets a remote configured `read-only = "true"` serve a
checkout, and what the test suite asserts both ways
([`tests/change_checkout_cli.rs`](../crates/gitiup/tests/change_checkout_cli.rs)).

What it refuses, and why:

| exit | when |
|------|------|
| 6 | a dirty worktree — *named path by path*, because folding your work into a stranger's change makes `git status` useless afterwards (untracked files do not count: `git` itself refuses one it would overwrite) · a bare repository, which has no worktree to move · a store with no git objects, named as such · a local ref the change cannot fast-forward, with **both** oids and where to go instead · `--for <job>` with no round for that job, naming the jobs that have one · `--for <job>` whose live round was drawn against a different head: the evidence is about other bytes |
| 8 | a proof ref that arrived without the bytes it names |
| 2 | no id given, a handle shorter than 4 hex, `--detach` with `--ref` or with `--no-checkout` |

The change lands on `refs/heads/<change-id>` unless `--ref <name>` names another branch;
`--detach` looks at it without making a branch, and `--no-checkout` writes the ref and
leaves the worktree alone — which is the one case a dirty worktree is allowed, because
nothing touches it. A ref already at that commit is left alone (`unchanged`), a ref the
change *can* fast-forward is moved, and this is the same ancestor question `merge` asks
above: after a checkout, this clone is the local repository that can prove the
fast-forward.

```
  round    build/matrix/linux-x86_64 attempt 1 · 5 seats · 4 must agree · 6 eligible
           attempts held: 0, 1 (1 is the live one)
           sha256:a67a67cc…3317 · roster epoch 2968 (sha256:083200b7…7adf)
  seats    0 of 5 submitted
    s1  vyB4Bkj7…wE9I  -         silent
    s2  4Kr8N+NB…3M7I  -         silent
  verdict  none filed for build/matrix/linux-x86_64 yet · `gitiup quorum verdict … --publish' signs one
```

`--for <job>` adds that arm of the quorum to the same fetch — `refs/gitiup/round/<change>/
<job>/*`, the seat submissions under `refs/gitiup/reveal/…` and the verdict at
`refs/gitiup/verdict/<change>/<job>` if one has been signed — and prints it, because a
reviewer staring at a green change with no idea whether anybody checked it is the failure
mode worth designing against. A verdict that no key this machine trusts signed is reported
as refused rather than dropped, and a job with several attempts reads the highest one (the
live round) and says which attempts the store holds. It is display: the tally's exit code
belongs to `gitiup quorum verdict`, and the hint says so.

## Merging: a compare-and-swap, then a signed record of it

`merge` is the owner's command, and it is two writes in a fixed order (ADR-0003 D8). First
the fact: `refs/heads/<base>` moves from the oid the merge expected to the attempt's head,
under compare-and-swap, which is the whole of what "merged" means on a store with no
merge button and no locking — a bucket can do it, a git host does it with
`--force-with-lease`, and a host that can do neither is refused rather than force-pushed
through. Then the record of the fact: a signed `gitiup-merge-1` naming the **attempt** by
its `change_digest` (not the change id, which moves between attempts), the branch, both
oids, `via`, who merged, and which proofs were believed — filed at `kv/merge/<digest>` and
advertised by `refs/changes/<id>/merged`, which is what makes *merged* a state a mirror can
see (D7).

The branch moves first and the record second, deliberately. A crash in between leaves a
branch that moved without a record, which is a **detectable** silence with a retry
(`change reconcile`, below); the reverse order would leave a signed record asserting a merge
that never happened — a false statement by an honest key, and invisible from the store.

```console
$ gitiup change merge chg-786c8cc2698531c5 --store ../store --dry-run
plan    merge · nothing written (--dry-run)
  store   fs store /tmp/docdemo/store
  change  chg-786c8cc2698531c5 attempt 0 · Fix the ref parser for peeled refs
  branch  refs/heads/main 19c6b71b…28b4 → 672f77f9…228f
  check   19c6b71b…28b4 [fast-forward] a fast-forward: no commits would be dropped
  record  kv/merge/<digest of the signed record>, advertised by refs/changes/chg-786c8cc2698531c5/merged
  proofs  none — the record will say the merge believed nothing
  signed  PKtAbJYt…INU4 (gitiup)

$ gitiup change merge chg-786c8cc2698531c5 --store ../store
merged  chg-786c8cc2698531c5 attempt 0
  store    fs store /tmp/docdemo/store
  branch   refs/heads/main sha1:19c6b71b…28b4 → sha1:672f77f9…228f  [cas sha1:19c6b71b…28b4]
  via      store (gitiup moved the ref under CAS)
  head     sha1:672f77f9…228f · Fix the ref parser for peeled refs
  record   kv/merge/5d9675a2e122f1517fc4ecab80ff02f2a757d8c907c9e59f20ee0f87ecb1a824 (768 bytes) · refs/changes/chg-786c8cc2698531c5/merged
  digests  change sha256:bbc980ca…2d29 · merge sha256:5d9675a2…a824
  proofs   none believed — the record says so
  signed   PKtAbJYt…INU4 (gitiup)
```

`--dry-run` is `gitiup attest gc --dry-run`'s promise: the whole comparison, including the
fresh read of the branch, and nothing written. Its `--json` says `"dry_run": true` and
`"would_write"`, and the one case where a dry run *fails* is the refusal it would have hit —
a plan that claims a merge is available when the base has moved is worse than no plan.

### What is checked, in which order, and why not D8's order

| refusal | exit |
|---------|------|
| the store cannot compare-and-swap a ref | 6, and nothing is force-pushed |
| the record does not re-hash, re-derive or verify | 8, 7, 6 — read through its ref before anything is touched |
| the store has no such branch | 6, naming the branch: publishing one is the owner's act, done with plain `git push` |
| the change is already merged or abandoned | 6 — *most specific fact first* |
| the branch already is the change's head | 6, pointing at `change reconcile` |
| the branch is not the expected oid | 6, naming **both** oids — "pull first" |
| the branch is not an ancestor of the head | 6 — a merge would drop commits |
| a proof digest cited cannot be returned by the store | 6 |

The two middle rows are in that order because D8's failure window produces both at once: a
branch sitting at the change's head has by definition left its base. Telling someone who is
*already merged, with the record missing* to "pull first and rebase" would send them to
re-do work that is done.

```console
$ gitiup change merge chg-297e5eade7a8a99f --store ../store
gitiup: refs/heads/main is sha1:bdb67584f952d9d9c1424176d193ae4dbfcd2f9d in this record and sha1:26528a3d2b4159862498a0727e78da24b30d7b2c in the store
hint: pull first: the branch moved, and merging this attempt would drop whatever moved it.
      Rebase onto sha1:26528a3d2b4159862498a0727e78da24b30d7b2c (or re-draft from it) and
      submit a new attempt, or name the oid you are really standing on with --expected-oid
```

Both oids, in the same spelling, every time: a refusal that says "stale" without saying
which of the two moved is advice nobody can act on.

**The fast-forward is proved, not assumed.** Whether `base` is an ancestor of `head` is a
question about parents, and a store keeps commits as opaque bytes and refs as numbers, so
the answer comes from a local repository that holds both oids — `change checkout`
(`giti-b2z.5`) is what guarantees one exists for a change read out of a store. With neither
oid present, `merge` refuses: that is the reason it will not "just try it" from a directory
that is not a checkout. gitiup merges by fast-forward only, which is also why it does not
produce a merge commit — a merge commit exists only *after* the merge, so no attestation can
ever have covered it.

**`--expected-oid`** is the owner overriding the base the author signed, and it is a decision
rather than a bypass: the CAS moves to the same place either way, and the override is printed
as a note and recorded in the merge record's `base.from`. The honest default is the signed
base — that is the oid the author could actually have merged, and the one they could not have
expected to land on top of anything else.

```console
$ gitiup change merge chg-297e5eade7a8a99f --store ../store --expected-oid sha1:26528a3d2b4159862498a0727e78da24b30d7b2c
merged  chg-297e5eade7a8a99f attempt 0
  branch   refs/heads/main sha1:26528a3d…7b2c → sha1:7bf3a084…fffb  [cas sha1:26528a3d…7b2c]
  …
note: the base was named by the caller: the author signed sha1:bdb67584…2f9d and the CAS expects sha1:26528a3d…7b2c
```

### Proofs a merge says it believed

`--proof <digest>` (repeatable) cites attestations in the merge record — as digests, never
as copies, because a copy in the record could be edited and a digest cannot (D8). Two things
follow. The store must be able to **return** each digest, so a citation nobody can fetch is
refused; and a digest inside a record is not a ref, so `attest gc` cannot see it the way it
sees a quorum submission — the merge writes the citation as a pin (`merge record of
chg-…`), which is why a retired-proof policy keeps what a merge was made on. `gc --json`
counts them in `report.pinned`; the same policy on the same store, before the merge, prunes
the identical attestation.

`--proof-required` is refused, on purpose, before a store is opened or a key is touched.
Whether a merge is *allowed* is Epic 2's policy engine, which is deliberately not a field of
the change record (D9: a contributor who could write "no checks needed" into the object being
merged has written their own gate), and "no policy found, merged anyway" is not an answer
anyone wants in a log. The engine is
[`gitiup verify change <id>`](verification.md#the-merge-question-gitiup-verify-change):
it resolves the change, reads
every attestation and verdict the store advertises for its head, applies the published
policy, and exits 0/6/7/8 — the same taxonomy `gitiup verify attestation <file>` gives for
one proof. Cite what you believed with `--proof`; the gate's answer is not stored in the
merge record, because a record that recorded its own gate could edit it.

### When the record does not land

```console
$ gitiup change merge chg-34b2879bb78dfb84 --store ../store
gitiup: refs/heads/main already is sha1:13f49cfee1f14277339cff82e0b4bbd429f33fd6, so there is nothing to merge
hint: if this change was merged and its record did not land, `gitiup change reconcile
      chg-34b2879bb78dfb84` writes the record for the move the store already has

$ gitiup change reconcile chg-34b2879bb78dfb84 --store ../store
recorded  chg-34b2879bb78dfb84 attempt 0
  store    fs store ../store
  branch   refs/heads/main sha1:ad20d36a…3a1b → sha1:6648bac3…848d  [untouched by this call]
  via      store (the move had already happened; this is its record)
  head     sha1:6648bac3…848d · Drop the Mac-only path
  record   kv/merge/4bb218e17940561b15c6a48dc3a45aef17dcb342d2b1789fd86be7f71dfc6727 (768 bytes) · refs/changes/chg-34b2879bb78dfb84/merged
  digests  change sha256:4a3835ef…fbcd · merge sha256:4bb218e1…6727
  proofs   none believed — the record says so
  signed   PKtAbJYt…INU4 (gitiup)
note: the branch had already moved; this record describes a merge that happened without one
```
Reported exactly as a merge is, because after it there is no difference between them.

`reconcile` writes no branch move: the fact already happened, and a record that moved the
branch it was only meant to describe would be a record about something that did not happen
the way it says. If the branch has *not* moved it refuses and sends the operator to
`change merge` — a merge record may only describe a move the store shows.

### On a forge, the forge merges

A change carried by a pull request is merged by the forge, whose merge is atomic, reviewed
and governed by its own protection rules — more than a conditional ref write can promise,
and therefore not something gitiup should imitate (ADR-0003 D10). gitiup asks the forge to
merge, then records what it reports with `via: "forge"`, and `--json` distinguishes the two
kinds of merge instead of leaving a script to infer the weaker guarantee from the transport.
A forge merge lands whatever the forge builds — its own merge commit, usually — so the
record names that commit as `to` (`--landed`, cross-checked against the store) rather than
pretending the attempt's head is what moved. `--merge-method ff|merge|squash|rebase` defaults
to `ff`, which is gitiup's own rule restated in the forge's vocabulary: the commits a proof
covers are the commits that end up on the branch.

| field (`--json`) | what it answers |
|-------|-----------------|
| `from` / `to` | the two ends of the move: what the CAS expected (the signed base, or the oid named with `--expected-oid`) and the attempt's head it wrote |
| `moved` | whether this call moved the branch. `false` means the branch already stood where the change wanted and only the record was missing |
| `via` + `atomicity` | which kind of merge this was — `store` (a conditional write) or `forge` (atomic and reviewed) — spelled out, because they are not the same guarantee and a script should not infer the weaker one from the transport |
| `merged_ref`, `kv`, `record_digest` | where the record is: the create-only ref that makes it a state, the content-addressed key it is filed under, and the digest both name |
| `proofs`, `proofs_pinned` | what the merge said it believed, and how many digests retention now owes a pin |
| `notes` | the remarks that are only true sometimes: a base override, a reconcile |
| `merger` | who signed the merge record — the merger, not the change's author (D7) |

## Exit codes

The same table as the rest of `gitiup` (ADR-0001 D7, ADR-0003 D11) — a script does not
branch on the transport and does not branch on the verb either:

| exit | when |
|------|------|
| 0 | published, listed, shown, merged, reconciled (including the idempotent `already: true`) |
| 2 | usage: unknown verb or flag, missing `--base`, a handle shorter than 4 hex, a `--proof` or `--expected-oid` that cannot mean anything to the store, a `host-type` in `gitiup.toml` that is not a store gitiup knows or that its URL contradicts |
| 3 | I/O, an unreachable store, git failing — and a refusal the **store** owns, passed through in the store's own taxonomy (a credential that may not write `refs/heads/**` stays `permission denied`, never retold as an I/O error or a generic 6) |
| 6 | refused: no store named, no key, stale base (both oids), the store has no such branch, an attempt that already exists with a different head, a conflict, a change id your key cannot sign for, nothing to propose, a handle that matches nothing in this store or matches two — and for a merge: not a fast-forward, an ancestry the tool cannot check, a branch that has already moved (reconcile instead), a change already merged or abandoned, a proof the store cannot return, `--proof-required` with no policy engine — and for a checkout: a dirty worktree (paths named), a bare repository, a store with no git objects, a local ref the change cannot fast-forward, no round for `--for`, a `--for` round drawn against another head — and for any of them, a store named that cannot hold this kind of store (a git repository given to `--store`, or a `file://` remote at one with nothing said about it: the hint names `host-type`) |
| 7 | a signature that does not verify, or a `key_id` that is not the fingerprint of the key offered |
| 8 | bytes that are not their own canonical form, a record that does not re-hash to the name it is filed under, a `change_id` that does not re-derive — and for a checkout, a proof ref that arrived without the bytes it names |

## Composition, and what a forge has to do with it

Every store is named through `gitiup.toml` or `--store`, never by a URL scheme typed at the
command line: the composition root ([`src/remotes.rs`](../crates/gitiup/src/remotes.rs))
decides which host serves a remote, and a remote that needs a forge adapter this binary was
not compiled with is refused **by name**, with `hosts-github` in the hint, before anything
is drafted. Accepting such a remote and then "helpfully" driving it with the plain-git host
would let `submit` succeed against a remote whose change database the build cannot read.

The URL says the transport, and `host-type` says the store: `fs`, `git`, `s3` or `github`
([Choosing a host](host-abstraction.md#choosing-a-host)). The one case that bites is a
repository on a local path — `file://` means *directory* to gitiup, and the two layouts
cannot share a path — so a `file://` remote at a repository is refused with the fix in the
hint (`host-type = "git"`), and so is `--store /srv/git/repo.git`. A declared host kind
that is off the list, or that the URL contradicts, is exit 2 with the list: a declaration
nobody recognises is exactly the moment a write could land in the wrong kind of store.

An adapter — `gitiup change merge`, and GitHub's PR-backed parity (`giti-b2z.7`, written
up above) — has the same verbs against a forge, and the same rules behind them. What a pull
request cannot carry (a signature, a microsecond timestamp, a 256-bit digest) is listed in
[ADR-0003 D10](adr/0003-change-record-format-and-merge-semantics.md); the short version is
that a pull request is an advertisement of a record, and `origin: {kind:"pull"}` says so
inside the record rather than leaving it to be inferred from where you read it. The
command line reaches a forge through one seam and one only
([`remotes::Forge`](../crates/gitiup/src/remotes.rs)): which changes it carries, how to ask
it to carry one, which of its branches hold a commit, and how to ask it to merge. No forge
type crosses into `change.rs`, which is what
`crates/gitiup/tests/no_forge_calls.rs` exists to keep true.

## Where this is measured

The verbs are tested as a CLI in
[`crates/gitiup/tests/change_cli.rs`](../crates/gitiup/tests/change_cli.rs), but the
promise that decides whether any of it is safe — *every host means the same thing by
this* — is measured in the host conformance suite, against every host and against real
backends ([`gitiup-host-tests`](../crates/gitiup-host-tests)):

| body | what every host must do |
|------|-------------------------|
| `a_change_goes_from_proposal_to_merge_and_merges_once` | propose, re-attempt, list, show, merge — and refuse the second merge with a conflict naming the change |
| `a_stale_base_merge_is_refused_the_same_way_everywhere` | refuse a merge whose base moved with `invalid`/exit 6, both oids named, nothing written — one kind on the fs host, the plain-git host over `file://` and over `git-http-backend`, the bucket host, a live bucket and the forge adapter |
| `tests/change_across_hosts.rs` | publish on the bucket, read and merge through the plain-git host, and get the same `kv/change/<hex>` digest, the same `change_digest` and the same `change list` from both — hermetically, and again across a live MinIO and a real `git-http-backend` |

The sequence, as opposed to the verbs, is measured in
[`crates/gitiup/tests/change_bare_repo_cli.rs`](../crates/gitiup/tests/change_bare_repo_cli.rs):
one script — propose, publish, re-attempt, merge, refuse the second merge, refuse the stale
base — run against a directory store and against a bare repository reached over `file://`,
with every exit code compared between the two, plus the reviewer's one fetch and the two
refusals that tell someone they have named a repository where a directory store was meant.

The CI job that runs them (`.github/workflows/host-conformance.yml`, or
`./ci/host-conformance.sh --live` on your own machine) demands both services: a bucket
or a served repository that failed to start fails the job instead of quietly narrowing
what was measured.

## Not here

Whether a change *may* be merged is not this document. `change merge` is the mechanical
compare-and-swap, and `--proof-required` stays refused on purpose: the answer to "is this
merge allowed" belongs to the published policy (`giti-91m`,
[ADR-0004](adr/0004-published-policy-format-signing-and-resolution.md)) and the quorum
verdict (`giti-zp1`, [quorum](quorum.md)), and the command that gives it is
[`gitiup verify change`](verification.md#the-merge-question-gitiup-verify-change) — exit
0/6/7/8, reading exactly the bytes written here: the record, the refs, the attempt and the
proof digests. A gate that lives beside the merge would be a gate the person being gated
could write, which is why `change merge` takes `--proof` citations and no verdict. There
is no UI and no review thread either: a change is a record and a ref, and anything a human
reads is printed by the CLI.

What the epic had to get right for all of those is the byte identity of the record, the ref
names, the attempt rule and the refusal table — each of those is asserted in
[`crates/gitiup/tests/change_cli.rs`](../crates/gitiup/tests/change_cli.rs), and the record
bytes again against the [golden vectors](adr/fixtures/change-v1/).

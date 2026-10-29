# Contributing without a forge — the change workflow

*Ticket: `giti-b2z.3` (`gitiup change new|submit|list|show`). Format decision:
[ADR-0003](adr/0003-change-record-format-and-merge-semantics.md). Host contract:
[host abstraction](host-abstraction.md). Proofs about a change:
[verification](verification.md).*

> A change is the object a stranger publishes when there is no forge. Not a pull request,
> not a patch email: one signed record in a content-addressed store, advertised by a ref,
> whose merge is a compare-and-swap a bucket can honour. This document is the contributor's
> half — the four commands, what each one promises, and the refusals that are refusals
> rather than advice.

```text
gitiup change new    --base main          draft a signed record from local commits
gitiup change submit --record … --remote …   publish one attempt of it
gitiup change list   [--state open] [--json]  what a store advertises
gitiup change show   <id> [--attempt n]    one change, read back through its ref
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
same three hosts answer all of them: a directory, a bare repository, a bucket. And
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
```

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

## Exit codes

The same table as the rest of `gitiup` (ADR-0001 D7, ADR-0003 D11) — a script does not
branch on the transport and does not branch on the verb either:

| exit | when |
|------|------|
| 0 | published, listed, shown (including the idempotent `already: true`) |
| 2 | usage: unknown verb or flag, missing `--base`, a handle shorter than 4 hex |
| 3 | I/O, an unreachable store, git failing |
| 6 | refused: no store named, no key, stale base (both oids), the store has no such branch, an attempt that already exists with a different head, a conflict, a change id your key cannot sign for, nothing to propose, an ambiguous handle |
| 7 | a signature that does not verify, or a `key_id` that is not the fingerprint of the key offered |
| 8 | bytes that are not their own canonical form, a record that does not re-hash to the name it is filed under, a `change_id` that does not re-derive |

## Composition, and what a forge has to do with it

Every store is named through `gitiup.toml` or `--store`, never by a URL scheme typed at the
command line: the composition root ([`src/remotes.rs`](../crates/gitiup/src/remotes.rs))
decides which host serves a remote, and a remote that needs a forge adapter this binary was
not compiled with is refused **by name**, with `hosts-github` in the hint, before anything
is drafted. Accepting such a remote and then "helpfully" driving it with the plain-git host
would let `submit` succeed against a remote whose change database the build cannot read.

An adapter — `gitiup change merge`, and GitHub's PR-backed parity in `giti-b2z.7` — has the
same four verbs against a forge, and the same rules behind them. What a pull request cannot
carry (a signature, a microsecond timestamp, a 256-bit digest) is listed in
[ADR-0003 D10](adr/0003-change-record-format-and-merge-semantics.md); the short version is
that a pull request is an advertisement of a record, and `origin: {kind:"pull"}` says so
inside the record rather than leaving it to be inferred from where you read it.

## Not this ticket

Merging (`gitiup change merge`, `giti-b2z.4`), checking a change out (`giti-b2z.5`), the
change-workflow conformance suite run against MinIO and `git-http-backend` (`giti-b2z.6`),
GitHub adapter parity for these verbs (`giti-b2z.7`), opening quorum rounds on submit
(`giti-zp1.2`) and `gitiup verify change` (`giti-91m.4`). What this ticket had to get right
for all of them is the byte identity of the record, the ref names, the attempt rule and the
refusal table — each of those is asserted in
[`crates/gitiup/tests/change_cli.rs`](../crates/gitiup/tests/change_cli.rs).

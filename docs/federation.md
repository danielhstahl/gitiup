# Federation — moving proofs between stores

*Tickets: `giti-g5c.2` and `giti-g5c.3` (epic `giti-g5c`, *federation — proofs and changes
travel between repositories*). Decision:
[ADR-0005](adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md) — D1 (the portable
set), D2 (the register of what may not be copied), D5 (arrival records), D6 (direction),
D7 (collision semantics), D8 rule 1 (advertisement ⊆ possession), D9 (the closure an import
must carry), D10 (budgets and exit codes). Implementation:
[`crates/gitiup/src/fetch.rs`](../crates/gitiup/src/fetch.rs) and
[`crates/gitiup/src/import.rs`](../crates/gitiup/src/import.rs) for the verbs and
[`gitiup-host::federation`](../crates/gitiup-host/src/federation.rs) for the rules; the
proofs are [`gitiup-host/tests/federation.rs`](../crates/gitiup-host/tests/federation.rs),
[`tests/federation_vectors.rs`](../crates/gitiup-host/tests/federation_vectors.rs),
[`gitiup-host-github/tests/federation.rs`](../crates/gitiup-host-github/tests/federation.rs)
(the forge as a destination and a source, over the mock forge),
[`gitiup/tests/fetch_cli.rs`](../crates/gitiup/tests/fetch_cli.rs) and
[`gitiup/tests/import_cli.rs`](../crates/gitiup/tests/import_cli.rs).*

> A mirror is the easiest feature in this product to build and the easiest to build wrong.
> The bytes are signed, the names are content-derived, and git moves packs for a living —
> so a `for` loop over a ref listing and a `put_cas` per object *works*, and launders trust
> in about twenty lines. These two verbs are that loop plus everything that makes it
> honest: what may travel, what must be refused out loud, what a copy is worth to a reader
> who did not witness it, and the write order that makes an interrupted run harmless.

```text
gitiup fetch --remote upstream --store ./store        pull a copy into one of your stores
gitiup push  --remote mirror   --store ./store       publish a copy out to one
gitiup attest import --from upstream --to ./store    pull proofs, and re-verify each one
```

Both verbs run the same function with its arguments swapped
([`federation::copy`](../crates/gitiup-host/src/federation/copy.rs)), which is the
structural reason the rules cannot drift between directions: there is one portability
table, one refusal list, one write path, and it does not matter which end you typed the
command at. A *mirror* is not a kind of store; it is a store you did not witness.

## Which two stores

```text
--remote <name>          the far side: fetched from, or pushed to — a [[remote]] in
                         gitiup.toml (`gitiup doctor --remotes` lists them)
--store <dir>            the near side, when it is a directory store
--from <name|dir>        say the source explicitly
--to <name|dir>          say the destination explicitly
```

A name is a configured remote and a path is a path, in that order, so a working directory
that happens to contain a directory called `mirror` never silently stops meaning the
remote called `mirror`. Any host may stand on either side — a directory store, a bucket, a
bare repository (local or served over smart HTTP), a forge adapter — and each side uses
*its own* pack and content-addressed paths. There is no `if source_is_git` anywhere in the
copy, because a copy that special-cased a transport would eventually special-case its way
into a different set of rules for that transport.

## What to move

| flag | meaning |
|---|---|
| (nothing) | every portable ref the source advertises |
| `--change <id>` | one change: its attempts, its merge or abandon record, the quorum records addressed to it, and the proofs filed for the commits its attempts propose |
| `--commit <oid>` | the proofs filed about one object (`40` or `64` hex, or `sha1:`/`sha256:`) |
| `--proofs-only` | evidence without code history — what a read-only public mirror of a private repository wants. It declines the pack step outright, so the subject objects an attestation is about are *excused*, in the report, on purpose |
| `--dry-run` | read the source, re-hash everything it would take, write **nothing** — the counts in the report are then a plan, and `dry_run: true` is what says so |
| `--strict` | any refusal at all fails the command, not just an integrity failure |
| `--no-records` | do not write the `kv/import/<digest>` arrival record for each digest that lands |
| `--max-records`, `--max-bytes` | budgets: `4096` records and `1 GiB` by default. A budget is a **refusal**, never a truncation |
| `--actor <name>` | who the ref writes are recorded as |

## What travels, and what stays home

The portable set is the *verification closure* — the records a reader needs in order to
re-verify what it took — and the register of what may not is everything whose meaning is
*"as of now"*:

| | travels | token if it does not |
|---|---|---|
| `refs/attestations/**` | yes | |
| `refs/changes/<id>/attempt/<n>`, `…/merged`, `…/abandoned` | yes | |
| `refs/changes/<id>/head` | no — it is a **pointer** | `not_portable`, and it is *resolved* instead |
| `refs/gitiup/roster/<epoch>`, `revocation/**`, `withdrawal/**` | yes | |
| `refs/gitiup/round/**`, `verdict/**`, `commit/**`, `reveal/**` | yes, as evidence only | `no_arbitration_here` if addressed at a live round |
| `refs/gitiup/policy/history/**` | yes | |
| `refs/gitiup/roster`, `policy/current` | no — pointers | `not_portable` |
| `refs/gitiup/lease/**`, `job/**`, `signup/**` | no | `not_portable` |
| `refs/gitiup/kv/**` (one store's commit chain) | no | `not_portable` |
| `kv/import/**`, `kv/gc/**` | no — they describe *this* store | `not_portable` |
| `refs/heads/**` | out of scope; code travels by pack, not by ref copy | `not_portable` |

The table above is [ADR-0005's](adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
D1 table, and it is not hand-copied: `federation/portable.rs` and the generated
[`fixtures/federation-v1/portable.json`](adr/fixtures/federation-v1/portable.json) are
asserted against each other by `federation_vectors.rs`, and the ADR's own tables are
re-derived by `generate.py --check-ad` in CI. Two implementations of the table, one of
which is a stdlib Python script, is the point — a single table in one language is a
single place to be quietly wrong.

**A forge hides its plumbing from a stranger, and the copy asks anyway — on purpose.**
`refs/gitiup/**` names verifier keys and seat slots, so a forge adapter answers a bare
listing without it: "mirror this store" must not silently mean "publish its roster". A
copy therefore lists one namespace at a time — `refs/attestations`, `refs/changes`,
`refs/gitiup`, and `refs/heads` only so it can be reported as out of scope — because a
copy that asked for everything would come back with no roster epochs, no verdicts and no
rounds and still report success. A mirror missing half of what it serves while looking
complete is the failure this rule exists to prevent (D15).

**A pointer is resolved, never copied.** Fetching a change resolves the source's
`refs/changes/<id>/head` to the attempt it names, takes *that* record, and moves the
destination's own pointer forward to it — `Expect::Is`, never backwards, and a
non-fast-forward is the report `diverged` rather than a mirror's decision. That is what
makes the copy point at a fact instead of at a moving part.

## A copy moves bytes and never trust

This is the whole design in one line, so it is enforced in three places a reviewer can
grep:

* **no flag.** `gitiup fetch --trust-remote` is an unknown option, exit 2. So are
  `--trust-mirror`, `--trusted-store` and `--from-trusted`; `fetch_cli.rs` asserts each
  one, because an absent flag is easy for a well-meaning contributor to "fix".
* **no bit.** `Capabilities` grew no `trusted`, `authoritative` or `mirror_of`.
* **no field to branch on.** The report's only trust field is the constant
  `"trust": "none"`, and `age_basis` is the constant `"claimed_at_us"` — a mirror cannot
  make a proof fresher, and the report says which clock it used so a test can prove it.

`gitiup verify` is the command that produces a belief, and it takes trust roots from
*this* machine's config, never from wherever the bytes came from. Fetch, then verify; the
two steps are not mergeable and that is the design.

## A run, end to end

```console
$ gitiup fetch --remote upstream --store ./mirror2
fetch  remote 'upstream' → fs store ./mirror2
objects          2 new, 0 already (4536 bytes)
re-hashed        2 objects checked against their own name
refs             2 written, 0 moved, 0 already, 0 respelled
refused          none
code             0 of 2 asked — unsupported
subject          2 attestations about 2 object(s), the objects they are about did not travel between these two hosts
trust            none
```

Reading those lines: *objects* is the content-addressed payload, and every one of them was
re-hashed on the way in and refused if it did not match the name its ref advertised
(`digest_mismatch`, exit 8, nothing written). *code* is the git history the attestations
are about: a directory store has no git object database, so a directory-to-directory copy
declines the pack step and the subject objects are reported as not having travelled —
which is a sentence about scope, not a warning about corruption. Between a repository and
a store, code does travel, and `carried` says so.

Running the same command again writes nothing and says `already`:

```console
$ gitiup fetch --remote upstream --store ./mirror2
objects          0 new, 2 already (0 bytes)
…
```

…because every write in the portable set is create-only, and a name that already stands
against the same digest is not a conflict — it is the same content arriving again. If a
name stands against *different* bytes, that is a digest collision or a defect, and it is
`digest_mismatch` with nothing written: never a suffix, never `-2`, never an overwrite.

And a run that was interrupted leaves bytes nobody advertises, never an advertisement
nobody can satisfy. Bytes first, then the ref; a store never advertises a digest it cannot
itself return, and never advertises less than it did a moment ago (D8 rule 1). That is also
why `gitiup attest gc` retires refs before it purges: the invariant holds from both ends.

## The report

`--json` prints the machine-readable form, and it is the same shape across every host
pair:

| field | meaning |
|---|---|
| `verb`, `from`, `to` | which operation and which two stores, described rather than typed |
| `objects` | `arrived`, `already`, `bytes`, and `rehashed` — how many were checked against their own name, which is all of them |
| `refs` | `written`, `moved`, `already`, `respelled` (a legacy single-level attestation ref is read and re-spelled as `<subject>/<digest>`, never re-created in the old shape) |
| `refused[]` | one entry per skipped ref: `token`, `class`, `reference`, `detail` |
| `refused_by`, `skipped_by_class` | the same refusals tallied by token and by class, which is what a log line fits |
| `pointers[]` | each pointer resolved: `reference`, `resolved`, `action` (`written` · `moved` · `already` · `held` · `diverged` · `nothing`) |
| `code` | `asked`, `carried`, `outcome` (`carried` · `declined` · `unsupported` · `failed` · `nothing-asked`) |
| `subject` | how many attestations, about how many objects, and whether the missing ones were excused |
| `budget` | what was allowed and what was used |
| `arrivals` | how many `kv/import/<digest>` records were written |
| `trust`, `age_basis` | `none` and `claimed_at_us`, always, for every host pair, whatever you pass |

Every digest that arrives gets an arrival record in the *importing* store at
`kv/import/<digest>` — `gitiup-import-1`, naming `arrived_from`, `arrived_at_us` and the
refs it was advertised under, with `closure: "not-walked"` from `fetch` and
`closure: "complete"` from an import, which records the whole closure it carried, the
verifier that checked it here and the exit code that check produced. It answers the
question a mirror exists to make answerable — *how did this get here* — and it is local by
construction: the one thing a copy never copies is another store's account of itself.

## Import: a copy that checks

`gitiup fetch` answers *what does the source advertise*; `gitiup attest import` answers
*what do these bytes lean on*. That is a different question, and it is why the verb is not
a flag on `fetch`:

```console
$ gitiup attest import --from ./upstream --to ./down --allow-missing-subject --dry-run
import         fs store ./upstream → fs store ./down  (plan only: nothing written)
policy         trust: this machine's keystore, 1 key(s) · tiers local · min 1 signature(s) · max age never · env nothing required
budget         4096 records · 8 hops · 64 policy revisions · 1024 MiB
offered        1 attestation(s) advertised by the source, 1 in scope
imported       1 attestation(s) with their closure (planned) · 1 record(s) deep to 0 hops
objects        1 new, 0 already (3200 bytes), 1 re-hashed
refs           1 written, 0 already, 0 moved, 0 respelled
refused        none
subject        0 present, 1 excused (--allow-missing-subject)
records        0 kv/import/<digest> written (planned) · closure walked, subject presence excused — recorded, and never an input to a later verdict
trust          none: what was checked is written down, and the next reader recomputes it
  imported   876e4f02…201c  local       1 record(s) · signed by ItVqc+Vz…5VfM
             subject excused: the object it is about bbbbbbbb…bbbb (--allow-missing-subject)
plan only: nothing was written. Add --apply to import these.
```

For each attestation the source advertises, in this order:

1. **Walk its citations** — an attestation's subject, a verdict's round, roster and policy,
   a round's roster, reveals and (for a sealed round) its commitments, a roster's
   revocations, a policy's predecessor chain. Every edge must be a ref the source
   advertises, or the document is refused with `closure_incomplete` naming the edge that
   has no foot (D9). Two edges are answered by derivation instead of by a copy, and the
   report says so out loud rather than assuming it: a round's `policy_digest` names the
   selection policy *inside* the round record under the selector's signature, and a
   `tier: quorum` attestation's `verdict_digest` names a verdict this command recomputes
   from the round, the roster epoch and the reveals it just took.
2. **Run the ladder** — the same checks `gitiup verify attestation` runs, from the same
   code, with a policy built by the same flags: canonical bytes, digest, signature, trust,
   tier, sandbox, environment, and freshness against *this* clock. A proof the source was
   happy with is refused here if this machine's policy does not take it, and `--tier`,
   `--max-age`, `--trust`, `--allow-simulated` and `--now` behave exactly as they do on
   `verify`.
3. **File it, or report it.** A document that fails is reported and skipped and the rest of
   the import goes ahead; an integrity failure fails the command. Then the whole set that
   passed goes through `federation::copy` — the same write path `fetch` uses, restricted to
   the digests the walk admitted — so bytes before refs, create-only, re-hashed at both
   ends, with one place in the workspace that decides what "never overwrite" means.
4. **Record the arrival**, with the closure, the verifier and the verdict in it.

Nothing is written without `--apply`; a bare run is the plan. `--proofs-only` and
`--allow-missing-subject` excuse a subject this store cannot name, *in the report and in the
arrival record*, so "deliberately not here" and "lost" stay two sentences. And the rule
that gives the verb its reason for existing: a `tier: quorum` attestation whose round,
roster or reveals are not offered is a rumour, and an import is what turns it into evidence
— after an import that carried the closure, `gitiup verify attestation --store ./store
--tier quorum` accepts the document with no reference to where it came from
(`import_cli.rs` asserts exactly that).

There is no flag here that makes an imported proof count as one you witnessed, and there
never will be: `"trust": "none"` is a constant in this verb too.

## Leaving a forge: `gitiup migrate repo`

Everything above moves between two stores gitiup is already talking to. A forge is not one
of those: its refs are an API answer, its pull requests are not refs, and its history is a
`git` endpoint with a rate limit in front of it. `gitiup migrate repo` is the one command
that crosses that boundary, once, idempotently, and leaves an account of itself behind:

```console
$ gitiup migrate repo --from github:o/r --to s3://bucket/repo --with-proofs
migrate        github:o/r → s3://bucket/repo
refs           12 written, 3 already, 0 diverged (9 branch(es), 6 tag(s))
changes        41 published, 0 already · 28 merge record(s)
history        41883 bytes, as gitiup records, 41883 object(s) — this store has no git
               object database: `gitiup` can return any of them and `git fetch` cannot
proofs         6 carried, 0 already, 3 dropped
verify         6 re-hashed from the destination, 6 matched · basis claimed_at_us
refusals       2× check_run_copy_truncated, 1× pull_closed_unmerged
forge          84 call(s) · 4902/5000 left on core, resets at unix 1793379710
journal        .gitiup/migrate/github-o-r-s3-bucket-repo-05fe6da6.json
account        refs/gitiup/migrate/github-o-r-s3-bucket-repo-05fe6da6 → 0ee8ed012fe1
code           0
```

**What travels.** Branches and tags become ordinary refs. Every open and merged pull request
becomes a change record with `origin: pull <n>`, its head under `refs/changes/…`, and a
merged one also gets a merge record with `via: forge` — the forge's merge commit is the
fact, and gitiup records it rather than pretending it did the merge. The history is fetched
from the forge's own git endpoint into a bare mirror under `.gitiup/migrate/` and handed to
the destination: as a packfile to a git store, as `git-object` records to a store with no
git object database, which the report says out loud because it changes what `git fetch` of
that destination will do later.

**What does not.** A check run is an advertisement. Its output becomes an attestation only
when the copy in it re-hashes to the digest the run claims, which makes it the signed
document itself and not a reconstruction of one; anything else — truncated output, a run
that never finished, somebody's build log — is a line in `dropped` with a token, and there
is no flag that says *carry it anyway* (D3). A pull closed without merging is dropped: no
branch will ever take that head, so advertising it would be a ref that lies. The forge's
title, body, author and labels come across as `x_gitiup_pull_*` annotations, because nobody
at the forge signed them and a field of a gitiup record is a claim somebody signed.

**Nothing confers trust.** The transcribed changes are signed by *this* machine's key — the
one `--key` names — because no signature at the forge covered them, and the report's `trust`
field is `none` whatever you pass.

**It is resumable because it is create-only.** Every step is journaled in
`.gitiup/migrate/<slug>.json` before the next one starts, so a run that dies 30 GB into a
clone picks up where it stopped, and a run of a finished migration moves nothing and says
`already`. The forge's rate budget is checked before each listing and the run stops, with
exit 6 and a token, rather than being cut off mid-step by the API. A journal written by a
newer gitiup is refused rather than half-read: skipping a step it does not understand would
mean reporting a migration as complete that is not.

**And it checks itself at the end.** For every commit that arrived with a proof, the bytes
are read back out of the *destination* — not out of the mirror that carried them, which
would prove nothing — and re-hashed. `verify` prints how many matched; `basis` names the
clock a proof's age is told from. A commit that hashes to something other than the name its
proof gives is exit 8, and that is the one outcome this command refuses to describe as a
success. A ref the destination cannot produce the bytes for is refused
(`ref_without_history`) instead of being written into nowhere, and a ref standing at a
different commit than the forge has is `diverged`, exit 6, and never an overwrite: two
histories claiming one name is a decision for a person.

The account of the run is filed in the store it built, at
`refs/gitiup/migrate/<slug>`, in the same class of provenance as the `kv/import/<digest>`
records `gitiup fetch` writes: *how did this get here*, answerable from inside the store,
granting nothing.

## Exit codes

`0` ok · `2` usage · `3` I/O or an unreachable store · `6` refused (a read-only
destination, a budget busted, a pointer that had diverged, an unfinished migration, or any
refusal at all under `--strict`) · `8` bytes that are not the bytes their name promises.

A per-record refusal does **not** fail the run: one unimportable proof must not end a
fetch of two hundred, so it is reported and counted and the rest arrives. An integrity
failure always does fail it, because a command that "succeeded" past a bad digest is a
store that now contains one. `--strict` is for the CI job that would rather know that
something was skipped.

## What is not here yet

* **`provenance` in a verify report, and the `provenance` policy member** (`origin_provenance_required`,
  `unlisted_mirror`) — D5's policy half, waiting on `giti-91m`'s policy readers. The
  arrival records an import writes are the data that rule will read.
* **mirror eviction** — a store can now tell it is a mirror, because it has arrival
  records, so `mirror_may_not_prune_by_age` and capacity eviction (`eviction_needs_source`)
  are now buildable (D8 rule 2).
* **anonymous read scoping** (`.5`), which is a credential question and has no code here.

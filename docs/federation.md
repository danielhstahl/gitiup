# Federation — moving proofs between stores

*Ticket: `giti-g5c.2` (epic `giti-g5c`, *federation — proofs and changes travel between
repositories*). Decision: [ADR-0005](adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
— D1 (the portable set), D2 (the register of what may not be copied), D6 (direction), D7
(collision semantics), D8 rule 1 (advertisement ⊆ possession). Implementation:
[`crates/gitiup/src/fetch.rs`](../crates/gitiup/src/fetch.rs) for the two verbs and
[`gitiup-host::federation`](../crates/gitiup-host/src/federation.rs) for the rules; the
proofs are [`gitiup-host/tests/federation.rs`](../crates/gitiup-host/tests/federation.rs),
[`tests/federation_vectors.rs`](../crates/gitiup-host/tests/federation_vectors.rs),
[`gitiup-host-github/tests/federation.rs`](../crates/gitiup-host-github/tests/federation.rs)
(the forge as a destination and a source, over the mock forge) and
[`gitiup/tests/fetch_cli.rs`](../crates/gitiup/tests/fetch_cli.rs).*

> A mirror is the easiest feature in this product to build and the easiest to build wrong.
> The bytes are signed, the names are content-derived, and git moves packs for a living —
> so a `for` loop over a ref listing and a `put_cas` per object *works*, and launders trust
> in about twenty lines. These two verbs are that loop plus everything that makes it
> honest: what may travel, what must be refused out loud, what a copy is worth to a reader
> who did not witness it, and the write order that makes an interrupted run harmless.

```text
gitiup fetch --remote upstream --store ./store        pull a copy into one of your stores
gitiup push  --remote mirror   --store ./store       publish a copy out to one
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
`kv/import/<digest>` — `gitiup-import-1`, naming `arrived_from`, `arrived_at_us`, the refs
it was advertised under, and `closure: "not-walked"` until
`gitiup attest import` (`giti-g5c.3`) walks it. It answers the question a mirror exists to
make answerable — *how did this get here* — and it is local by construction: the one thing
a copy never copies is another store's account of itself.

## Exit codes

`0` ok · `2` usage · `3` I/O or an unreachable store · `6` refused (a read-only
destination, a budget busted, a pointer that had diverged, or any refusal at all under
`--strict`) · `8` bytes that are not the bytes their name promises.

A per-record refusal does **not** fail the run: one unimportable proof must not end a
fetch of two hundred, so it is reported and counted and the rest arrives. An integrity
failure always does fail it, because a command that "succeeded" past a bad digest is a
store that now contains one. `--strict` is for the CI job that would rather know that
something was skipped.

## What is not here yet

* **the closure walk** — `gitiup attest import` (`giti-g5c.3`) follows a record's own
  citations (`round_digest`, `roster_digest`, `policy_digest`, `previous_digest`) instead
  of listing a namespace, re-verifies everything on arrival, and refuses a record whose
  edges are absent with `closure_incomplete`. These verbs copy *scope*; `.3` is the verb
  that copies *closure* and belief.
* **`provenance` in a verify report, and the `provenance` policy member** (`origin_provenance_required`,
  `unlisted_mirror`) — D5, landing with `.3` and `giti-91m`'s policy readers.
* **mirror eviction** — a store can now tell it is a mirror, because it has arrival
  records, so `mirror_may_not_prune_by_age` and capacity eviction (`eviction_needs_source`)
  are now buildable (D8 rule 2).
* **`gitiup migrate repo`** (`.4`), which is one fat push, and **anonymous read scoping**
  (`.5`), which is a credential question and has no code here.

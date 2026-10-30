# ADR-0005 federation vectors (portability and closure)

The golden vectors for [ADR-0005](../../0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md):
the equivalent, for *what a copy may contain*, of
[`policy-v1/`](../policy-v1/) for
[ADR-0004](../../0004-published-policy-format-signing-and-resolution.md). Two tickets —
`giti-g5c.2` (`gitiup fetch|push`) and `giti-g5c.3` (`gitiup attest import`) — have to
agree on which namespaces travel, which never do, and what "the closure of a proof" means.
Left to themselves they will not: one will copy `refs/gitiup/**` because it is one prefix,
the other will import an attestation without its verdict because that is the ref it was
asked for. A `fetch` that imports a rumour and an `import` that refuses one are the same
bug seen from two ends, and this table is the only thing that makes them the same bug.

**There is no crypto here, on purpose.** Byte identity, signatures and digests are already
decided and already have their own vectors
([`change-v1/`](../change-v1/), [`selection-v1/`](../selection-v1/),
[`policy-v1/`](../policy-v1/)). What is checked here is *scope*: which records a copy must
contain, which it must refuse, and with which token. Records are named by short ids
(`att:quorum`, `ros:7`, `pol:2`) rather than by real digests, and their citations are given
as plain fields — the same citations the real records carry as signed members
(`round_digest`, `roster_digest`, `policy_digest`, `previous_digest`, `attempts.previous`).

| file | what it is |
|------|------------|
| `generate.py` | the reference implementation *and* the generator: stdlib-only, no clock (the clock is `cases.json:clock_us`), no network, no crypto. It implements the portability rule (D1/D2), the closure walk with its edges (D9), the budgets (D10), the age rule (D5), pointer resolution and collision rules (D7), and the retention-authority rules (D8) |
| `portable.json` | D1/D2 as data: every row with its `class`, whether it is `portable`, the refusal token that names its omission, the record kinds, and the budget table |
| `cases.json` | D9's closure cases (source store, start refs, destination contents → what a copy may contain), the refusal table with the exit code each token must produce, and the fixed clock |

## Portability (D1, D2)

`portable.json:rows` is the table from D1, one row per ref namespace, each carrying a
`class`:

| class | meaning | portable |
|-------|---------|----------|
| `proof` | a signed record: the unit of copying is record **plus** advertisement | yes |
| `pointer` | a store's live state (`head`, `roster`, `policy/current`): a reader may *resolve* one, never copy one | no |
| `state` | arbitration state whose meaning is *"as of now"* (leases, job advertisements, pending sign-ups) | no |
| `local` | this store's own audit trail or furniture (`kv/import`, `kv/gc`, the kv commit chain, tombstones, trust roots) | no |
| `code` | a git object: a proof's subject, portable only along with the code | conditional |
| `foreign` | git's own business (`refs/heads/**`), out of this ADR's scope | no |

Nine rows portable, ten refused, and **every refusal names its token** — "we did not copy
that" is always a report, never a silence.

The property `--selftest` proves rather than asserts: *no portable record's closure reaches
a non-portable class*. That is what makes D1 a rule instead of a list, and why a record type
invented in 2028 either fits the closure rule or is refused by it.

## The closure cases (D9)

The edges are not invented here: they are the digest citations the real records already
carry, so the closure is a citation graph and a missing edge is a named refusal.

| case | what it teaches |
|------|-----------------|
| `local-attestation` | even the smallest proof is three objects: the attestation, the policy revision in force, its subject |
| `quorum-attestation-complete` | sixteen objects for one `tier: quorum` attestation — verdict, round, epoch, revocation, two policy revisions, four reveals and their four commitments. This is why `--proofs-only` is a closure and not a namespace |
| `missing-policy-revision`, `stale-roster-epoch`, `revocation-carried`, `verdict-only-rumour`, `reveal-without-commitment` | each absent edge is `closure_incomplete` (or `no_commitment`) naming the edge, and the record is **not** imported: complete for what it took, or nothing |
| `policy-chain-broken` | a *present* revision whose predecessor is missing is ADR-0004 D6's `policy_history_missing`, not a closure gap — two different refusals because the two have different repairs |
| `missing-subject`, `subject-excused` | a proof about an absent object is refused unless the operator said so (`--allow-missing-subject`, implied by `--proofs-only`) |
| `non-portable-in-listing` | a listing that offers a lease, a pending sign-up and a job advertisement skips all three by token and says so |
| `already-imported` | re-running a fetch writes nothing: names are content-derived, so a collision *is* a content match (D7) |
| `head-resolves`, `head-diverged` | a pointer is resolved on the reader's side and moved under CAS; a non-fast-forward is reported and left alone |
| `legacy-ref-respelled` | the old one-level attestation ref is re-spelled on import and never re-created |
| `age-gc-on-a-mirror`, `age-gc-at-the-origin` | age-based pruning is refused at a mirror and allowed at the origin — `claimed_at_us` is identical on every copy, so correlated pruning, not a greedy mirror, is the last-copy hazard (D8) |
| `evict-without-source`, `evict-with-source` | a cache may forget only what it can name a place to fetch again |
| `copy-is-fine-by-default`, `origin-provenance-required`, `unlisted-mirror`, `listed-mirror` | a copy is fully usable unless the owner asked for more; and the fixture's age from the claim (2 h) differs from its age from arrival (1 h), which is the laundering D5 forbids |

## The refusal table

`cases.json:refusals` is every token D10 names, with the exit code it must produce. No new
exit codes: 6 refused (scope, policy, absence), 7 a signature that does not verify, 8 bytes
that are not the bytes their name promises. Every token this file can emit is in that table
and every token in the table is one this file can emit — in both directions, because a
refusal nobody can reach is a token that drifts.

```console
$ python3 generate.py            # print the tables, rewrite the vectors
$ python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
$ python3 generate.py --selftest # closure properties, budgets, the age rule, every refusal
$ python3 generate.py --check-ad  # fail if the ADR's own tables and this data disagree
```

`--check-ad` is the reason this set exists in this shape. It parses
[the ADR](../../0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md), reads D1's
namespace table and D10's token table, and fails if a row was edited in the prose without
editing the data (or the reverse). `docs/adr/README.md`: *prose that nothing checks is a
suggestion.*

## Reproduced in Rust

**Not yet.** That is an honest row, not a gap in the vectors: the transport does not exist
yet, which is the ticket's entire argument for writing the rules first. Until they do,
somebody owes CI a line that runs all three of `--check`, `--check-ad` and `--selftest`
against this directory: an unrun vector rots, and a rotted vector is worse than none
because it is believed. When the transport lands it inherits:

* `giti-g5c.2` reads `portable.json` in a test that fetches between two hosts and asserts
  that every ref the transport took is a row marked portable, and that every ref it skipped
  was skipped for the token the row names — on `fs`, `git`, `s3` and the forge adapter,
  because C10 says a rule that holds on one host is not a rule;
* `giti-g5c.3` reads `cases.json` and reproduces each case from **those files alone** —
  never from a Rust constant — reaching the same `imported` set and the same token and exit
  code per refusal. The budgets are exercised at a scaled value in the fixture and at the
  real value in the Rust, so the bound is tested where it is written;
* the retention rules get a store test: `--max-age` refused at a store with import records,
  allowed at one without, and eviction refused for a digest with no `kv/import/` record.

If a vector and the Rust ever disagree, the vector is the rule: fix the Rust, and do not
edit `portable.json`, `cases.json` or `generate.py` to match a build.

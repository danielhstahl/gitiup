# Architecture decision records

Short documents for decisions that **more than one ticket depends on**. If a decision
only affects the code in one ticket, put the reasoning in that ticket's code comment
instead; if it affects the shape of several tickets' work, it belongs here, because
otherwise every ticket re-decides it a little differently.

Anything a later ticket has to code against without re-litigating is fair game:
wire formats, ref namespaces, error taxonomies, trust models, dependency policy.

## Index

| id | title | status | decided by | implemented by |
|----|-------|--------|------------|----------------|
| [0001](0001-attestation-encoding-hash-and-signature.md) | Attestation encoding, hash and signature format | accepted | `giti-1rs.1` | [`gitiup-attest`](../../crates/gitiup-attest/README.md) |
| [0002](0002-roster-verifier-selection-and-sybil-resistance.md) | Roster, verifiable selection and sybil resistance | accepted | `giti-msi.1` | [`gitiup-quorum`](../../crates/gitiup-quorum/README.md) and `gitiup participant` / `select` / `work` / `quorum verdict\|dispute\|retry` — **D6 is not built**; D5's reputation half landed as an *exclusion* only (`participant quarantine`), and the rate limits it defers were never written |
| [0003](0003-change-record-format-and-merge-semantics.md) | The change record: bytes, identity, states and what a merge is | accepted | `giti-b2z.1` | `ChangeRecord` in [`gitiup-host`](../../crates/gitiup-host/README.md), `gitiup change new\|submit\|list\|show\|merge\|reconcile\|checkout`, and the forge adapter's PR parity |
| [0004](0004-published-policy-format-signing-and-resolution.md) | The published policy: where it lives, who signs it, and which one was in force | accepted | `giti-91m.1` | [`gitiup_quorum::policy`](../../crates/gitiup-quorum/src/policy.rs) behind `gitiup policy publish\|show\|check\|explain`, `gitiup verify change` and `gitiup hook install pre-receive` |
| [0005](0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md) | What a mirror may carry, and what a copy is worth | accepted | `giti-g5c.1` | **nothing yet, on purpose** — it is written before the transport so the transport does not decide it. `giti-g5c.2` (`gitiup fetch\|push`) and `giti-g5c.3` (`gitiup attest import`) are the code; the invariants it extends (`attest::publish`'s bytes-then-ref, `referenced` as an un-prunable pin, `put_cas`'s re-hash, `same_ref`) already hold |
| — | Host abstraction: CAS ref updates, `kv/` namespaces, store layout | *written up as [design notes](../host-abstraction.md), predates this directory* | `giti-xdw.1/.2` | [`gitiup-host`](../../crates/gitiup-host/README.md) |

When you write one of the placeholders above, add a row here in the same commit.

**Status and implementation are different columns on purpose.** *Status* is about the
decision — is it the one to code against, or has it been superseded. *Implemented by* is
about the build, and it rots: an ADR can be accepted, code against, and still have
half of it unwritten (ADR-0002 has). A ticket that lands the code an ADR decided names
the crate here and, where a decision is only part-built, says so in the ADR itself —
not silently, and not by editing the decision.

## Conventions

* **One file per decision**, `NNNN-short-slug.md`, numbered in the order they were
  accepted — numbers are never reused, even for rejected proposals.
* **Status** is one of `proposed`, `accepted`, `superseded by NNNN`, `deprecated`.
* **Implementation is stated, not implied.** A header carries an `Implemented by` bullet
  naming the crate, the commands and — where the code stopped short — the decisions that
  are still only paper, and the index row says the same in one line. "Accepted" means the
  decision is the one to code against; it does not mean anything exists yet, and a reader
  should not have to find out by grepping.
* Structure: *Context* (the forces, ideally as a constraint table), *Decision at a
  glance* (a table, with the rejected option named in the same row), one section per
  decision with **why not the alternative**, then *Consequences*.
* Say what the decision **blocks** and what it leaves open, by ticket id. A reader with
  a ticket in hand should be able to tell in thirty seconds whether this ADR answers
  their question.
* A decision that changes the bytes on disk, the meaning of a ref, or what a
  verification exit code means is a *compatibility* decision: name the migration path
  (or state, as ADR-0001 D8 does, that there is none and the format version must move
  instead).
* Reference them from code. `ADR-0001 D3` in a doc comment beats a paragraph that
  restates it and drifts.
* A decision that several tickets must *reimplement* carries **reference vectors**: a
  generator and its output, committed next to the ADR under `fixtures/<name>/` (as
  [ADR-0002](0002-roster-verifier-selection-and-sybil-resistance.md) does) or in the
  crate it describes (as ADR-0001 does with `crates/gitiup-attest/tests/fixtures/v1/`).
  Prose that nothing checks is a suggestion.

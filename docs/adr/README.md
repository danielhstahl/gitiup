# Architecture decision records

Short documents for decisions that **more than one ticket depends on**. If a decision
only affects the code in one ticket, put the reasoning in that ticket's code comment
instead; if it affects the shape of several tickets' work, it belongs here, because
otherwise every ticket re-decides it a little differently.

Anything a later ticket has to code against without re-litigating is fair game:
wire formats, ref namespaces, error taxonomies, trust models, dependency policy.

## Index

| id | title | status | decided by |
|----|-------|--------|------------|
| [0001](0001-attestation-encoding-hash-and-signature.md) | Attestation encoding, hash and signature format | accepted | `giti-1rs.1` |
| [0002](0002-roster-verifier-selection-and-sybil-resistance.md) | Roster, verifiable selection and sybil resistance | accepted | `giti-msi.1` |
| — | Host abstraction: CAS ref updates, `kv/` namespaces, store layout | *written up as [design notes](../host-abstraction.md), predates this directory* | `giti-xdw.1/.2` |

When you write one of the placeholders above, add a row here in the same commit.

## Conventions

* **One file per decision**, `NNNN-short-slug.md`, numbered in the order they were
  accepted — numbers are never reused, even for rejected proposals.
* **Status** is one of `proposed`, `accepted`, `superseded by NNNN`, `deprecated`.
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

# ADR-0002 selection vectors (`gitiup-round-1`)

These are the golden vectors for verifier selection, the equivalent of
`crates/gitiup-attest/tests/fixtures/v1/` for [ADR-0002](../0002-roster-verifier-selection-and-sybil-resistance.md).
`gitiup select` (`giti-msi.3`) must reproduce `selection.json` from `roster.json` +
`round.json` exactly; if it cannot, one of the two is wrong and the ADR says which.

| file | what it is |
|------|------------|
| `generate.py` | the reference implementation *and* the generator: stdlib-only Python, no clock, no network. Also the normative worked example (its `--table` output is the ADR's table) |
| `roster.json` | roster epoch 41: 12 entries, 9 principals, mixed tiers/arch/ram. Canonical Gitiup JSON (ADR-0001 D1); `roster_digest` is SHA-256 of these exact bytes |
| `round.json` | the round inputs — change id, head oid, job id, attempt, required capabilities, exclusions, policy — including `roster_digest` |
| `selection.json` | the expected output: seed, per-entry score and exclusion reason, ordered selection with handles and slots, reserves, and two promotion cases (one that fills a voided seat, one where no substitute exists) |

```console
$ python3 generate.py            # print the table, rewrite the three vectors
$ python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
$ python3 generate.py --uniform  # chi-square over 100000 rounds on a homogeneous roster
```

`generate.py --check` must pass in CI from the moment `giti-msi.3` exists, and its
Rust test should assert the same three-way equality (vectors in, `selection.json` out).

## Notes that bite

* **Separators are `0x00`.** `selection.json`'s `round_id` field is a display form with
  the field separators shown as `/`; the actual HMAC message joins the seven fields
  with a single NUL byte (ADR-0002 D2).
* **These keys have no private half.** `key_id` is still derived from `public_key`'s SSH
  wire blob exactly as ADR-0001 D3 requires, so a test can re-derive the fingerprint —
  but nothing here is a signing vector. The roster is *unsigned* (`signatures: []`, no
  per-entry `self_signature`), which is legal for a selection vector and illegal for a
  real roster.
* **`selection.json` is an output, not a signed document**, so it uses `null` where a
  field does not apply. Signed records never do (ADR-0001 D1 rule 5).
* **Scores are shown truncated** in the ADR table; `selection.json` holds the full
  32-byte digest, and the ordering is over the whole 256-bit value with `key_id`
  ascending as the tie-break.
* **The uniformity check runs with caps off.** Tier and identity caps are *meant* to make
  selection non-uniform across a heterogeneous roster; χ² applies to the ordering, not
  to the policy. The homogeneous roster used by `--uniform` (12 identical `endorsed`
  principals, `n=5`) is what the test is about.

## Regenerating

Edit `generate.py` (and the ADR in the same commit — the domain strings, the filter
order and the caps are quoted there), then run `python3 generate.py` and commit the
three files with it. Changing a domain string is a new `round_kind`, not a fix:
see ADR-0002 "How we change our minds".

## Reproduced in Rust

`crates/gitiup-quorum` reproduces these files exactly:
`crates/gitiup-quorum/tests/selection_vectors.rs` loads `roster.json` and `round.json`,
runs the selection, and compares the whole document — seed, scores, greedy reasons,
seats, reserves, both promotion cases and the policy digest — against `selection.json`.
The uniform case (`--uniform`) is
`crates/gitiup-quorum/tests/selection_properties.rs`, which runs 200 rounds and checks
χ² over the wins rather than one published number.

Two things the Rust discovered while reproducing this set, both recorded so a later
reader does not rediscover them:

* the roster's `sha256:` digest is over the **re-encoded** document, and the round pins
  that; a signature list is part of the body, so signing a roster changes its digest —
  the ADR's `roster_digest` is the *unsigned* fixture's digest.
* the fixture keys are well-formed SSH blobs but not curve points, so `key_id`
  re-derivation from the blob is a shape check, not a `VerifyingKey` parse. Rosters that
  actually authorise votes additionally require a curve-valid key, because a key that
  cannot verify a signature is not an identity.

# ADR-0003 change vectors (`gitiup-change-1`)

The golden vectors for [ADR-0003](../0003-change-record-format-and-merge-semantics.md):
the equivalent, for changes, of `crates/gitiup-attest/tests/fixtures/v1/` for
[ADR-0001](../0001-attestation-encoding-hash-and-signature.md) and of
[`selection-v1/`](../selection-v1/) for [ADR-0002](../0002-roster-verifier-selection-and-sybil-resistance.md).
A Rust `ChangeRecord` that cannot reproduce these files is wrong, however reasonable
it looks: four tickets (`giti-b2z.2`, `.3`, `.4`, `giti-91m.4`) otherwise invent four
formats that all claim to be "the change record".

| file | what it is |
|------|------------|
| `generate.py` | the reference implementation *and* the generator: stdlib-only Python, no clock, no network, and its own RFC 8032 Ed25519 |
| `cases.json` | the index: per case, the record's `kind`, `change_id`, `body_digest`, `record_digest`, author key id, signature, and every ref and `kv/` key it is filed under |
| `records/<case>.json` | the record bytes **exactly**: Gitiup Canonical JSON (ADR-0001 D1), no whitespace, no trailing newline, signed in place |

| case | what it teaches |
|------|-----------------|
| `open-first` | attempt 0 of ada's change: store origin, two jobs, `refs/changes/<id>/{head,attempt/0}` |
| `open-second` | a force-push: **same `change_id`**, new `head`, `attempts.previous` names `open-first`'s `change_digest` (D3, D6) |
| `merged` | what a merge *is*: `base.from → base.to`, the attempt merged, the proof digests believed (D7, D8) |
| `pull-backed` | `origin.pull`, a non-ASCII title, and the `x_<producer>_<name>` annotation hatch (D2, D10) |
| `abandoned` | closing a change is a signed record and a create-only ref, not a deleted ref (D7) |
| `wide` | escapes (`"`, `\`), raw UTF-8, eight jobs: the reader's limits in one record (D11) |

```console
$ python3 generate.py            # print the table, rewrite the vectors
$ python3 generate.py --check    # fail (exit 1) if the committed vectors are stale
$ python3 generate.py --selftest # primitives: ed25519, canonical JSON, change_id derivation
$ python3 generate.py --verify   # re-derive every committed record from its own bytes
```

## Reproduced in Rust

Two tests, in two crates, because these vectors are both a byte contract and a
ref-layout contract:

* [`crates/gitiup-attest/tests/change_vectors.rs`](../../../../crates/gitiup-attest/tests/change_vectors.rs)
  proves the **bytes** against the primitives that own them: `canon` (the one
  canonicaliser `gitiup-host` must share, ADR-0003 D11), `SignatureEntry::verify`
  (Ed25519 `verify_strict` over the PAE bytes, `key_id` re-derived from the key
  offered), both digests, the `kv/` key spelling, the attempt chain, and the fact
  that a tampered record and a wrong payload type both fail. This one runs today in
  `cargo test`; it is why the Python is not checking itself.
* `crates/gitiup-host/tests/change_vectors.rs` (`giti-b2z.2`) adds the **store** side:
  `change_id` re-derived from `author.key_id` + `base.ref` + `attempts.anchor`, every
  ref name in `cases.json` produced by the crate's own ref helpers, and a
  publish/fetch round trip through a real store. The comparison is the whole document
  rather than a digest of it: cross-implementation agreement is the point.

`--selftest` adds a third opinion at generation time: it verifies the signatures with
OpenSSL in both directions, so nothing here is checked only against itself.

## Notes that bite

* **`body_digest` is not `record_digest`.** The first is SHA-256 over the record with
  `signatures` removed (D4); the second is SHA-256 over the file you are looking at.
  For a *change* record the first is what the format calls `change_digest`, and the
  index uses the neutral name on purpose: a merge record has a body digest of its own
  *and* a `change_digest` field citing an attempt, and letting one JSON file call both
  `change_digest` is how a merge ends up citing itself (the Rust test asserts it does
  not). What a merge record, a verdict and `attempts.previous` cite is the digest of
  the change; what `kv/change/<hex>` is keyed by is the whole file — which is why
  `refs` in `cases.json` shows one and the digest columns show the other.
* **The canonical order is the sorted order.** `cases.json` is *pretty-printed and
  key-sorted by `json.dumps`; the record files are canonical. Only the record files
  are signed, so a reformatted `cases.json` is cosmetic and a reformatted record is
  a different change.
* **These keys have no secrecy and no production standing.** Each seed is
  `SHA256("gitiup ADR-0003 change-v1 fixture key: " || label)` for the labels `ada`,
  `lin` and `owner`, so the private halves are public by construction. A trust policy
  that lists one of these key ids is a bug, exactly as with ADR-0001's `TEST_SEED`.
* **The signature is over the body, and the body is the record minus its signature
  lists** — the rule `gitiup_quorum::record::body_bytes` already applies to rosters,
  rounds and verdicts (D1). `signatures` is inside the stored bytes and inside
  `record_digest`, and adding a signature therefore changes the storage key while
  leaving `change_digest` alone.
* **`merged`'s `proofs` are opaque digests.** They are not attestations that ship
  here: they are placeholders with the right shape, because a merge record names
  proofs rather than carrying copies (D8). An end-to-end test must supply real ones
  and pass each to `gitiup_host::attest::pin` so retention cannot retire cited
  evidence.
* **`change_id` is 64 bits of a digest**, deliberately (D3): it is a name, not an
  integrity claim, and the thing that must not be forgeable is the record digest.
* **Nothing here is a clock.** `created_at_us` and `merged_at_us` are fixed
  instants, so `generate.py` is reproducible and `--check` is meaningful in CI.

## Regenerating

Edit `generate.py` and the ADR in the same commit (the field table, the derivation,
the limits and the ref names are all quoted there), run `python3 generate.py`, and
commit the six records with it. A domain string or a payload type is not editable
in place: that is a new record type, with a new fixture directory, per
[ADR-0003 D11](../0003-change-record-format-and-merge-semantics.md).

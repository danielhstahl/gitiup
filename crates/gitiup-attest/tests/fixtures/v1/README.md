# Golden attestation vectors, v1

These bytes are the contract. Another implementation of gitiup — or a shell script
improvising a check with `openssl` — must be able to reproduce them, so they are
committed and `tests/golden.rs` refuses to let them drift.

## Layout

```text
cases.json                 index: expected digests + signatures, per case (pretty-printed, not signed)
minimal/manifest.json      canonical bytes of the signed payload, smallest valid manifest
minimal/doc.json           canonical bytes of the envelope (manifest + signature)
simulated/…                a simulated-tier run
local/…                    a real local run: pins, secrets, artifacts, outputs, timings
quorum-member/…            a volunteer's run: challenge-bound, with normalisation diffs
```

`manifest.json` and `doc.json` hold the payload **exactly**: canonical JSON, no
whitespace, no trailing newline. Hand-editing them cannot keep the signature valid,
which is the point.

## What `cases.json` pins

| field | meaning |
|-------|---------|
| `run_digest` | `sha256(canonical(manifest))` — the attestation's name |
| `result_digest` | `sha256(canonical(manifest.result))` — what independent verifiers compare |
| `record_digest` | `sha256(canonical(doc))` — the `kv/attestation/<hex>` storage key |
| `signatures[]` | the `key_id` and base64 signature for each case |
| `signing_key` | the public key line and fingerprint, which follow from the public `TEST_SEED` |

## Regenerating

```sh
GITIUP_UPDATE_FIXTURES=1 cargo run -p gitiup-attest --example make_fixtures
```

Only ever with an ADR saying why — [ADR-0001 D8](../../../../../docs/adr/0001-attestation-encoding-hash-and-signature.md).
New cases go in `examples/make_fixtures.rs::CASES` and stay forever; an old fixture
directory is never edited, because old attestations in other people's buckets have to
keep verifying.

## Checking them with no gitiup code at all

```sh
python3 ../verify_fixtures.py        # from this directory; needs openssl on PATH
```

The script recomputes both digests from the raw bytes, re-derives the key id as an SSH
fingerprint, re-canonicalises the JSON with Python's own serializer and verifies the
signature with OpenSSL — i.e. it checks this format against *other people's*
implementations rather than against itself. That independence is the acceptance
argument for ADR-0001, so it is kept runnable rather than left as a claim in prose.

## About the key

The fixtures are signed with a key derived from the public, documented
`gitiup_attest::sample::TEST_SEED`. No private key material is committed — a private
key in a repository is an invitation to forge "signed" test data — and a production
trust policy that lists this key id is a bug (a test asserts the default policy refuses
it).

# gitiup-attest

The attestation format. One crate answers "what exactly are the bytes that make a CI
result provable", and every other part of gitiup — runner, quorum, merge gate, host
storage — reads and writes them.

The decisions are in
[ADR-0001](../../docs/adr/0001-attestation-encoding-hash-and-signature.md);
this README is the API tour. The crate does **no I/O at all** — no network, no
filesystem, no subprocess, no clock except through `Policy::now` — and
`tests/dependency_hygiene.rs` enforces it, so verification works offline, in a
`pre-receive` hook, on a plane, and in a test.

```rust,ignore
use gitiup_attest::{AttestationDoc, Policy, TimeUs, sample, key::SigningKey};

let key = SigningKey::from_seed(&sample::TEST_SEED);
let mut doc = AttestationDoc::new(sample::local());
doc.sign(&key)?;

// Only the canonical form is ever written or read: stored bytes are signed bytes.
let bytes = doc.canonical_bytes()?;
let read_back = AttestationDoc::from_canonical_bytes(&bytes)?;

let policy = Policy {
    now: Some(TimeUs::from_secs(1_793_092_600)),
    ..Policy::trusting([key.public_key().key_id()])
};
let verdict = read_back.verify(&policy)?;
assert_eq!(verdict.signers, vec![key.public_key().key_id()]);
```

## The shape

```text
manifest = { schema_version, type, result {…}, claims {…} }
RunDigest    = sha256(canonical(manifest))            ← signed, stored, the attestation's name
ResultDigest = sha256(canonical(manifest.result))     ← what two verifiers compare
signature    = ed25519( PAE("application/vnd.gitiup.run-manifest+json", canonical(manifest)) )
doc          = { schema_version, payload_type, manifest, signatures[] }   → kv/attestation/<hex>
```

`result` is what a faithful re-run reproduces; `claims` is who said so and when. The
split is what lets five volunteers re-running one change converge on one
`ResultDigest` while their clocks, hostnames and step durations all differ — see
ADR-0001 D4/D5 for the register of what may never enter `result`.

## Modules

| module | what lives there |
|--------|------------------|
| [`canon`](src/canon.rs) | the canonicaliser: narrowed RFC 8785 writer **and** a strict reader that refuses whitespace, duplicate keys, floats, `\u0041`, `\/`, `null` and anything else that would be a second encoding of one document |
| [`manifest`](src/manifest.rs) | `RunManifest` and friends, `canonical_bytes()`, `digest()`, `result_digest()`, `normalize()`, `validate()` |
| [`digest`](src/digest.rs), [`oid`](src/oid.rs) | `sha256:<hex>` digests and `sha1:<hex>` / `sha256:<hex>` git object ids — algorithm in the string, so a new digest is a policy change, not a format break |
| [`key`](src/key.rs) | Ed25519 keys in SSH wire form, `SHA256:…` fingerprints as key ids, `SignatureEntry`, and the `Signer` trait ssh-agent/keystore backends plug into |
| [`envelope`](src/envelope.rs) | `AttestationDoc`, PAE framing, signing, co-signing (`merge_signatures`), `verify`, DSSE import/export |
| [`policy`](src/policy.rs) | what a verifier is willing to accept: trust list, freshness window, allowed tiers, expected commit / result digest / challenge |
| [`error`](src/error.rs) | the taxonomy behind `gitiup verify attestation`'s exit codes: 6 policy, 7 bad signature, 8 digest mismatch |
| [`time`](src/time.rs) | microsecond timestamps, RFC 3339 for display only |
| [`schema`](src/schema.rs) | the committed JSON Schemas, embedded |
| [`sample`](src/sample.rs) | deterministic fixtures and the public test key (test code only — never trust that key id) |

## Using it

**Producing** (the runner, giti-1rs.2):

```rust,ignore
let mut manifest = RunManifest { … };
manifest.normalize();                          // sorts the spec-sorted lists
manifest.result.environment.fix_fingerprint()?;// the fingerprint is derived, never asserted
manifest.validate()?;
let mut doc = AttestationDoc::new(manifest);
doc.sign(&signer)?;                            // signer: impl gitiup_attest::Signer
host.put_cas(&Namespace::ATTESTATION, &doc.canonical_bytes()?)?;   // kv/attestation/<hex>
```

**Verifying** (giti-1rs.8, a merge gate, a quorum coordinator):

```rust,ignore
let doc = AttestationDoc::from_canonical_bytes(&bytes)?;   // non-canonical bytes → exit 8
let policy = Policy {
    expected_commit: Some(commit),
    expected_result_digest: Some(their_digest),            // the quorum comparison
    allowed_tiers: vec![Tier::Local],
    max_age_us: 60 * 60 * 1_000_000,
    ..Policy::trusting(owner_key_ids)
};
match doc.verify(&policy) {
    Ok(verdict) => { /* verdict.run_digest, .result_digest, .signers, .freshness */ }
    Err(error) => std::process::exit(error.exit_code().into()),   // 6 / 7 / 8
}
```

`Policy::default()` fails closed: no trusted keys, and only `local` runs accepted —
`simulated` is a plan, not an execution, and `quorum` is a verdict over several
attestations rather than something one run may claim about itself.

## Interop

`AttestationDoc::dsse_envelope()` emits a spec in-toto DSSE envelope with byte-identical
payload and signature, and `doc_from_dsse()` reads one back (the caller supplies the
key lookup, because this crate does no I/O). Mapping to in-toto/SLSA vocabulary: our
`type` ↔ `_type`, `result.source` ↔ `subject`, `result` ↔ `predicate`, envelope ↔
DSSE envelope. Log anchoring (Rekor-style) is a separate signed record over a
`RunDigest` — never embedded, never required (ADR-0001 D9).

## Schema and fixtures

* `schema/gitiup-run-manifest-1.schema.json`, `schema/gitiup-attestation-doc-1.schema.json`
  — draft 2020-12, `additionalProperties: false` throughout, `x-gitiup-sorted` marking
  the lists that must be sorted (JSON Schema cannot say so, `validate()` does).
* `tests/fixtures/v1/` — committed canonical bytes plus their digests and signatures,
  for four cases. `tests/golden.rs` fails if they move.
* `tests/verify_fixtures.py` — re-verifies those fixtures using only Python's stdlib and
  `openssl`: digests, the SSH fingerprint derivation, and the signature. Independent
  proof of the primitives, not a second copy of this crate's logic.
* `tests/schema_drift.rs` — walks the schema and the Rust types in lockstep, so the two
  specifications cannot drift.
* `tests/format_properties.rs` — order independence, idempotent encoding, "no second
  encoding", and a mutation of **every field** proving it moves the digest.

## Building

```sh
cargo test -p gitiup-attest
cargo run -p gitiup-attest --example make_fixtures   # prints how to regenerate fixtures
```

Dependencies: `serde`, `serde_json`, `sha2`, `ed25519-dalek` — all pure Rust, all pinned
by a test.

## What lives elsewhere

storage and refs (`.5`, `gitiup-host`), output normalisation (`.3`), environment
fingerprint inventory (`.4`), key storage/ssh-agent/gpg (`.6`), the CLI surface
(`.5`, `.8`), quorum selection and vote counting (`giti-msi.*`).

# Provable CI output — the whole path, end to end

This is the document giti-1rs exists to leave behind: the one place that says how a
run turns into something a stranger can check, and where each part of that claim lives
in the code and in the tests. Every other document here covers one component; this one
covers why the components are worth having together.

The claim, in one sentence:

> A run produces a `RunDigest` that any third party can independently recompute and
> whose signature verifies; attestations are stored with the repo and readable via an
> ordinary `git fetch`; the provenance tier (`simulated` / `local` / `quorum`) is
> always explicit.

A CI result is normally a green tick on a page nobody can re-derive. In a federated
setup — where the "owner" may be an S3 bucket, and the party merging may have to trust
the results of actions they did not run — the tick is worthless. What can be trusted is
a small, stable, signed object that says what ran, on what, with what inputs, and what
came out, and that anyone can rebuild from the same starting point and compare byte for
byte.

## The path

```text
workflow + event + inputs + matrix        environment fingerprint
        │                                        │
        ▼                                        ▼
  gitiup run ──────────────► RunReport ────────────────► EnvFingerprint
 (simulated by default;          │  (gitiup-run)              (giti-1rs.4)
  --execute to earn `local`)     │
                                  ▼
                        gitiup-normalise          reproducibility contract
                        (giti-1rs.3)              (docs/reproducibility.md)
                                  │
                                  ▼
                     RunManifest::from_run        canonical bytes, ADR-0001
                     + RunManifest::encode        (giti-1rs.1, giti-1rs.2)
                                  │
                    ┌─────────────┴──────────────┐
                    ▼                            ▼
              RunDigest                     ResultDigest
        (the whole manifest)             (the `result` half only:
         changes with the clock           what a correct rerun
         and the run id)                  reproduces exactly)
                    │
                    ▼
        Signer: keystore / ssh-agent / gpg        (giti-1rs.6, gitiup-keys)
                    │
                    ▼
        AttestationDoc ──► gitiup attest push ──► kv/attestation/<digest>
        { manifest,                        │      refs/attestations/<subject>/<digest>
          signatures[] }                   │      (giti-1rs.5, gitiup-host)
                                           ▼
                              an ordinary `git fetch` carries it
                                           │
                                           ▼
                       gitiup verify attestation ──► verdict, exit 0/6/7/8
                        (giti-1rs.8, docs/verification.md)
```

Two digests, and only one of them is expected to survive a rerun on another machine
([ADR-0001 D4](adr/0001-attestation-encoding-hash-and-signature.md)). Confusing them is
the most common way to conclude that reproducibility "does not work": the `RunDigest`
covers the event, the clock, the run id and the normalisation record, all of which are
facts about *one occurrence*. The `ResultDigest` covers the source, the pins, the
inputs, the environment fingerprint and the steps — which is what a second honest run
is supposed to reproduce. A verifier compares `ResultDigest`; a dispute is argued about
`claims`, where the normalisation diffs live.

## Who does what

| step | crate / command | the ticket that made it exist |
|------|-----------------|-------------------------------|
| the encoding, the hash, the signature format, what is in scope for which digest | [`gitiup-attest`](../crates/gitiup-attest), [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md) | giti-1rs.1 |
| computing the digests over workflow source, pins, closure, event, job, matrix, inputs, secret *names*, environment fingerprint and per-step results | `RunManifest::from_run`, `gitiup digest` | giti-1rs.2 |
| making independent reruns converge, and reporting what did not | [`gitiup-normalise`](../crates/gitiup-normalise), `gitiup normalise --compare` | giti-1rs.3 |
| saying what machine a run happened on, and refusing a mismatch | `EnvFingerprint`, `--require`, `require-env-match` | giti-1rs.4, [environment.md](environment.md) |
| storing a proof so a `git fetch` carries it, and keeping the store honest about how long it keeps one | `gitiup_host::attest`, `gitiup attest push/list/show/gc/migrate` | giti-1rs.5, [host-abstraction.md](host-abstraction.md) |
| holding keys and identities so a signature means somebody | [`gitiup-keys`](../crates/gitiup-keys), `gitiup key`, `gitiup identity` | giti-1rs.6, [signing-keys.md](signing-keys.md) |
| declaring what a run actually did, and refusing to pretend | `Provenance`, `Tier`, policy `allow_simulated` | giti-1rs.7, [provenance-tiers.md](provenance-tiers.md) |
| deciding whether a proof may be acted on, in words and in an exit code | `gitiup verify attestation` | giti-1rs.8, [verification.md](verification.md) |

## The rules that make it hold

**A signature is only ever over exact bytes.** The store holds the canonical encoding
byte for byte, refuses to file bytes that do not hash to the key they are filed under,
and `gitiup verify attestation` refuses anything that is merely valid JSON (exit 8). A
host that pretty-prints on the way in has destroyed every signature it stores, which is
why that is a hard failure rather than a warning.

**A proof is found by the question a gate asks.** `refs/attestations/<subject>/<digest>`
is keyed by the digest of the thing attested, so "what proves this commit?" is a ref
prefix read on every host, and the attestation's own digest is the leaf so a commit can
carry several proofs — several signers, several runs, several tiers — instead of the one
a single-level ref could hold. The older single-level shape is still *read* (flagged
`legacy`), is never written, and `gitiup attest migrate` moves it. See
[host-abstraction.md](host-abstraction.md#attestations-in-the-store).

**Tier is a field, never an assumption.** `simulated` is the default and means nothing
ran; `local` means it ran in the invoking user's sandbox, which had to be probed to
exist; `quorum` can only be set by the quorum path and a plain run refuses to claim it.
A policy that allows only `local` rejects a simulated proof with an actionable message
rather than a shrug. See [provenance-tiers.md](provenance-tiers.md).

**Verification re-derives; it never trusts what it is told.** The verdict ladder
(ADR-0001 D7) checks structure, then digests, then signature, then trust, then policy,
and reports *every* failure while the first one decides the exit code. `--json` is a
stable contract for a merge gate, and the document's own `exit` field always agrees with
the process's exit status. See [verification.md](verification.md).

**A pinned object is never swept.** Retention retires advertisements; it does not touch
anything another live ref points at, which is what keeps a quorum's ballots alive
without any operator remembering a flag.

## Where the claim is executed

Not one of the sentences above is only documented. Each is a test:

| claim | test |
|-------|------|
| the digests are stable, recomputable, and independent of field order | `gitiup-attest/tests/run_digest_golden.rs`, `run_digest_properties.rs`, and `verify_fixtures.py` — an *independent* Python implementation that checks the committed golden fixtures |
| the canonical form and signature format are what ADR-0001 says | `gitiup-attest/tests/format_properties.rs`, `schema_drift.rs`, `docs/adr/fixtures/` |
| two independent runs of one corpus converge on one `ResultDigest` | `gitiup-normalise/tests/corpus.rs`, `divergence.rs`, `properties.rs` |
| every manifest carries an environment fingerprint and a mismatch is refused | `gitiup-attest/tests/env_match.rs`, `gitiup/tests/environment_cli.rs` |
| attestations are stored in the host and survive a real `git clone` / smart-HTTP fetch | `gitiup-host/tests/attest_store.rs`, `gitiup-host/tests/host_git.rs`, `gitiup/tests/attest_cli.rs` |
| every host — filesystem, bare git, bucket, forge — agrees about two proofs about one commit | `gitiup-host-tests`: `attestations_about_one_subject_are_found_by_subject`, run against all four kinds in CI |
| old stores can be brought up to date without touching a signed byte | `gitiup-host/src/attest.rs` (migrate), `gitiup/tests/attest_cli.rs` |
| a signature is verified, and every way it can fail has its own exit code | `gitiup/tests/verify_cli.rs`, `gitiup-attest/tests/provenance_tiers.rs` |
| the whole composition, from the third party's side: recompute the digest from the run, fetch the proof with plain `git`, check the signature, refuse a tampered proof, and insist on an explicit tier | [`gitiup/tests/provable.rs`](../crates/gitiup/tests/provable.rs) |

`gitiup/tests/provable.rs` is the one to read first if you want to see the epic rather
than its parts: two machines that share nothing but a repository URL and a public key,
one `git clone`, and the whole ladder run from the receiving side.

## The honest limits

* **`simulated` proves intent, not behaviour.** The default run plans; the attestation
  says so, loudly, and no gate should accept it by accident. That is a feature: the
  alternative is a green tick that means nothing.
* **Reproducibility is a contract the workflow has to keep.**
  [reproducibility.md](reproducibility.md) lists what that means (pin by SHA, images by
  digest, sorted manifests, `SOURCE_DATE_EPOCH`). The normaliser rewrites the parts of a
  *log* that describe the machine; it cannot and must not fix an artifact whose own
  bytes contain a timestamp.
* **Environment fingerprints are as good as what a run can observe.** A toolchain that
  is not in the inventory is not in the fingerprint; a `strict` match is the default
  because a false match is worse than an honest failure.
* **`quorum` is not this epic's promise.** A single run can never attest itself quorum;
  that is the verifier-selection and round work (`giti-msi.*`), which consumes exactly
  the attestation format described here rather than inventing a second one.
* **Key distribution is elsewhere.** Verification trusts key ids you give it —
  `--trust`, a policy's `trust_key_ids`, or this machine's keystore. Getting a
  stranger to the right set of public keys is the roster and identity work, not this.

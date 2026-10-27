# ADR-0001 — Attestation encoding, hash and signature format

* **Status**: accepted
* **Decides**: the wire format of a gitiup attestation — payload encoding, canonicalisation, digest algorithm, signature scheme, key identity, timestamps, freshness, limits, versioning, and optional log anchoring
* **Ticket**: `giti-1rs.1` (parent epic `giti-1rs`, *Canonical action results and signed attestations*)
* **Blocks**: `giti-1rs.2` (RunDigest), `.3` (normalisation), `.4` (environment fingerprint), `.5` (storage), `.6` (keys), `.7` (provenance tiers), `.8` (`gitiup verify attestation`), `giti-kd4.3/.4/.5` (submit / pull / merge gate), `giti-msi.*` (quorum)
* **Implementation**: [`crates/gitiup-attest`](../../crates/gitiup-attest/README.md)
* **Schemas**: [`gitiup-run-manifest-1.schema.json`](../../crates/gitiup-attest/schema/gitiup-run-manifest-1.schema.json), [`gitiup-attestation-doc-1.schema.json`](../../crates/gitiup-attest/schema/gitiup-attestation-doc-1.schema.json)
* **Fixtures**: [`crates/gitiup-attest/tests/fixtures/v1`](../../crates/gitiup-attest/tests/fixtures/v1)

> Every other ticket in the attestation epic codes against this document. Changing a
> decision here means changing tickets, not just code — which is the whole reason it
> is written down.

---

## Context

gitiup's trust story is that a stranger can be told "this change passed CI" and can
*check that themselves*, on their own machine, without a forge. The object that makes
that claim is small, and it is the only one: an attestation is a signature over a
content-addressed description of a CI run. If it is not re-derivable, nothing above
it is trustworthy.

The constraints that any format has to satisfy:

| # | constraint | who forces it |
|---|------------|---------------|
| C1 | A third party must be able to rebuild the **exact signed bytes** from what they were handed, in a language nobody has written yet, three years from now. | `.8`, quorum |
| C2 | Verification must run offline, in a `pre-receive` hook, on a volunteer's laptop, in under a second: no network round trip in the trust path. | `.8`, `giti-kd4.5` |
| C3 | The bytes must travel with the repo — stored in `kv/attestation/<digest>`, pointed at by `refs/attestations/<oid>`, so an ordinary `git fetch` carries proof. | `giti-xdw.1/.2`, `.5` |
| C4 | N volunteers re-running the same change must **converge on one digest** even though their machines, clocks and hostnames differ. | `giti-msi.3/.7/.9` |
| C5 | A human reviewing a change must be able to read the attestation and diff it. Reviewing base64 is not reviewing. | all |
| C6 | People already own an SSH key; asking them to carry a second identity is asking for a trust story nobody uses. | `.6` |
| C7 | The format must bound what a verifier has to buffer, parse and trust: a volunteer runs strangers' claims on their own machine. | `giti-bgy.*` |

Two things were *not* in tension and are worth saying so: speed of hashing (the
manifest is a few kilobytes) and cryptographic strength (every candidate algorithm
here is fine). The decisions below were made on interop, reviewability and the
difficulty of being wrong — not on performance.

## Decision at a glance

| id | question | decision | rejected |
|----|----------|----------|----------|
| D1 | payload encoding | JSON, canonicalised with a narrowed RFC 8785; signed through DSSE PAE; envelope is our own JSON document, DSSE-exportable | plain `serde_json`, canonical CBOR, JCS-as-spec, protobuf, raw in-toto `Statement` |
| D2 | digest | SHA-256, written algorithm-tagged as `sha256:<lowercase hex>` | bare hex, blake3, multi-hash prefix |
| D3 | signature & keys | raw Ed25519 (RFC 8032, `verify_strict`) over the PAE bytes; public keys in SSH wire form; key ids are SSH fingerprints (`SHA256:…`) | `ssh-keygen -Y` signature framing, PGP detached signatures, cosign/x509 chains as the default |
| D4 | document shape | manifest = `result` + `claims`; **two digests**: `RunDigest` over the whole manifest, `ResultDigest` over the `result` member | one flat signed object, "strip volatile fields before hashing" |
| D5 | volatile fields | a closed register of what must never enter `result` (times, durations, host identity, normalisation "before" text) | leaving it to the runner author's taste |
| D6 | time | integer microseconds `claimed_at_us` **inside** the signed payload; freshness is a *policy* (`max_age` 24 h, `max_clock_skew` 300 s); optional `not_before_us` / `not_after_us` | RFC 3339 strings in the payload, trusting the producer's window, mandatory TSA |
| D7 | verification & limits | error taxonomy with fixed `gitiup verify` exit codes (6/7/8), hard size and count limits, fail-closed defaults | "best effort" validation, unlimited documents |
| D8 | versioning | `schema_version` + `type` URI inside the signed payload; additive-only within v1, `annotations` as the extension point; committed golden vectors as the conformance contract | in-band negotiation by leniency, unknown-field tolerance by default |
| D9 | transparency log | optional, separate signed **record** over a RunDigest; never inside the manifest, never required by default | mandatory Rekor, embedding the log response in the payload |

---

## D1 — Payload encoding: canonical JSON, DSSE PAE signature framing

**Decision.** The payload is a JSON document. Its wire form is *Gitiup Canonical
JSON*: [RFC 8785 (JSON Canonicalization Scheme)](https://datatracker.ietf.org/doc/html/rfc8785)
restricted to the subset the format actually uses:

1. object keys sorted ascending by Unicode scalar value, no whitespace anywhere;
2. **integers only** (`i64`), no `-0`, no fraction, no exponent, no `NaN`;
3. duplicate object keys are an error, not "last one wins";
4. escapes limited to `\" \\ \b \t \n \f \r` and `\u00xx` (lower-case hex) for the
   remaining control characters; everything else is raw UTF-8;
5. **no `null` anywhere** — an absent field is an omitted key;
6. keys strictly ascending, so the reader refuses both duplicates and mis-ordering;
7. depth ≤ 32 containers, size ≤ 1 MiB, no BOM, no `\/`, no trailing whitespace.

Rules 2 and 5 are *narrowings* of RFC 8785, and they are the point: the RFC inherits
ECMAScript number rendering, which is exactly where independent implementations
part company. Rule 7 is what a volunteer needs to bound its work (C7).

The signed message is the in-toto DSSE **Pre-Authentication Encoding**:

```text
message      = "DSSEv1" SP len(payload_type) SP payload_type SP len(payload) SP payload
payload_type = "application/vnd.gitiup.run-manifest+json"
payload      = canonical_bytes(manifest)
```

The stored document is our own envelope, with the manifest as a JSON *member*
rather than base64 of it:

```json
{"schema_version":1,"payload_type":"application/vnd.gitiup.run-manifest+json","manifest":{…},"signatures":[…]}
```

`AttestationDoc::dsse_envelope()` exports a spec DSSE envelope whose `payload` and
`sig` bytes are **identical** to ours, and `doc_from_dsse()` reads one back, so
interop with Sigstore/Rekor-style tooling is a transformation of the same bytes
rather than a second signature.

**Why this and not the alternatives.**

* **Plain `serde_json` (or "JSON, we'll be careful")** — rejected, and this is the
  decision that the rest of the ADR depends on. `serde_json` preserves map order,
  accepts duplicate keys (silently keeping the last), writes `1.0` for a float and
  accepts `{"a":"A"}` as `{"a":"A"}`. Each of those is a *second encoding of one
  document*, hence a second digest, hence a signature that verifies against bytes
  the verifier never saw. C1 is unsatisfiable without a canonicaliser, and a
  canonicaliser you do not enforce is a comment.
* **JCS, taken as spec rather than as a baseline** — the RFC's number model is
  ECMAScript doubles. Fine for JWTs, dangerous when the digest is the trust anchor.
  We keep the parts that are portable and forbid the rest (and note that RFC 8785's
  UTF-16-code-unit key ordering and UTF-8 byte ordering agree for every well-formed
  string; the strings that would differ are lone surrogates, which cannot be built
  in Rust and are refused on read).
* **Canonical CBOR (RFC 8949 deterministic encoding)** — rejected on reviewability
  and reach, not on merit. Attestations are read by humans reviewing a change (C5),
  grepped in logs, checked in a pinch with `jq` and `openssl`. CBOR makes all of that
  worse, and its own canonical form has traps of its own (three encodings of one
  integer, indefinite-length items, tags) that a *reader* must police. Size was never
  the constraint: these documents are a few kilobytes and live in a git object store
  that compresses them anyway.
* **Protocol Buffers** — a schema compiler in the verification path, and "the bytes
  you signed" become a property of one encoder version's field ordering. Fails C1 in
  spirit and C5 in practice.
* **In-toto `Statement` / SLSA predicate as our storage format** — attractive for
  interop and *half-adopted* here on purpose (PAE, a `_type`-style discriminator, a
  subject-bound payload). Rejected as the format because `Statement` leaves the
  predicate body's canonicalisation undefined — it punts the one hard problem — and
  because the Rust stack around it drags in a network dependency we refuse in C2.
  Mapping is mechanical and lossless: our `type` ↔ `_type`, `result.source` ↔
  `subject`, `result` ↔ `predicate`, envelope ↔ DSSE envelope.
* **Storing the manifest base64-encoded inside the envelope (as DSSE does)** — the
  bytes are the same, but nobody reviews base64. We keep the raw member and pay one
  transformation for DSSE export.

**Consequences.** The canonicaliser is a first-class, tested component
(`gitiup_attest::canon`, ~350 lines with a strict reader that *proves* canonical form
rather than assuming it), and every write path must use it. Bytes received from a
host are refused unless they are canonical — see D7's exit code 8. `serde_json` is
still used for parsing canonical bytes and for non-signed files; it is simply not
allowed to decide what a signed document looks like.

## D2 — Digest: SHA-256, algorithm-tagged string form

**Decision.** Every digest is SHA-256, written as `sha256:<64 lowercase hex>`. Git
object ids use the same shape with their own algorithm: `sha1:<40 hex>` for today's
git, `sha256:<64 hex>` for `--object-format=sha256` repositories and for workflow
sources that are not git blobs at all. Digests are stored in the host as
`kv/attestation/<bare hex>` (the namespace already says what was hashed).

**Why SHA-256 over blake3.** blake3 is faster, and irrelevant here: we hash
kilobyte manifests, not multi-gigabyte trees, and the two digests that matter
(`RunDigest`, `ResultDigest`) are computed once per verification. Meanwhile every
constraint in the table above favours SHA-256 — `sha256sum`, OpenSSL, Python's
`hashlib`, OCI digests, Rekor, Sigstore and every artifact registry speak it, so a
stranger can check an attestation with tools they already have (C1, C5). blake3
would make step one of verification "install a dependency".

**Why the algorithm in the string.** It costs nine bytes and buys hash agility
without ambiguity: admitting `blake3:` later for *large artifact* digests is a policy
change, and a reader that cannot check a digest must say so rather than compare a
byte string it does not understand. `sha1:` in a commit id is a name, not a collision
claim — the integrity claim is the signature over the manifest.

**Rejected.** *Bare hex* (the form git refs use) — digests of different algorithms
would be indistinguishable, and half the fields are git ids while the other half are
content hashes. *Multihash / CID prefixes* (`1220…`) — self-describing but
unreadable, and pulls IPFS conventions into a git-shaped system. *blake3 as primary*
— as above. *sha512* — longer for no benefit at this security level.

## D3 — Signature: raw Ed25519 over PAE, SSH keys and SSH fingerprints

**Decision.** Ed25519 (RFC 8032), raw 64-byte signature, base64 (standard alphabet,
padded) on the wire, verified with `verify_strict` — the strict path that rejects
weak public keys and non-canonical signature encodings, so one message can never
acquire a second valid signature. The signer is identified by a `keyid` that is the
**SSH fingerprint**: `SHA256:` + unpadded base64 of SHA-256 over the SSH public-key
wire blob, byte-identical to what `ssh-keygen -lf` prints. The public key travels
alongside as an `ssh-ed25519 <base64>` line. The envelope holds a *set* of
signatures, sorted by key id, one entry per key.

Two mechanical consequences are part of the format, not implementation details:
`key_id` is **re-derived** from `public_key` at verification time and a mismatch is
an error (an entry cannot claim a famous key id while carrying another key), and the
signature list is signature-order-canonical so co-signing does not reshuffle bytes.

**Why SSH-shaped keys.** C6 is a product requirement: the people whose trust matters
already have `~/.ssh/id_ed25519.pub`, `authorized_keys` files and ssh-agent sessions.
`ssh-agent`'s `SSH2_AGENT_SIGN_REQUEST` signs *arbitrary bytes*, which is precisely
what we need — so `.6` gets hardware-and-agent signing with no new format, and gitiup
never mints a parallel identity. Pinning the derivation as a fingerprint form also
means an owner's trust list is a list of strings they can copy out of
`ssh-keygen -lf` output.

**Rejected.**
* **SSH key *signatures*** (`ssh-keygen -Y sign`, `sshsig`) — rejected while the
  *keys* are kept. ssh signs its own framing (namespace, hash algorithm, preamble),
  not our PAE bytes; a signature over a prehash that third parties cannot reconstruct
  breaks C1 and C2 (verification needs ssh's exact framing rules). We accept
  ssh *keys* + ssh-agent, not ssh's signature message.
* **PGP/GPG detached signatures** — armored text is not canonical, key hygiene is a
  research project, expiry/revocation semantics differ from gitiup's, and a signature
  format that needs `gpg --verify` in the trust path is a dependency on someone else's
  defaults. Optional in `.6` as a *backend* producing a tagged non-default signature
  type, never as the format.
* **cosign / x509 certificate chains as the default** — real, but it puts a CA (or a
  Fulcio-style OIDC issuer) in the middle of a system whose premise is that there is
  no middle. gitiup's trust starts as "key id X is in the owner's list", which is what
  a federated owner can actually operate from a bucket. The signature type field is
  an enum, so a `cert` variant (key plus chain, policy decides) is additive in the
  envelope without touching the manifest or the digests.
* **ECDSA/P-256** — nothing wrong with it, but it adds DER-vs-fixed-width encoding
  questions and a second verification path for no gain here.
* **Treat `key_id` as authoritative** — see above; derived, always.

**Thresholds.** Multiple signatures over the same payload are the normal case, not an
extra: the quorum epic appends signatures to the envelope. Because
`RunDigest = sha256(canonical(manifest))` covers the manifest only, co-signing can
never invalidate an earlier signature (see `co_signing_keeps_the_run_digest`).
Aggregating signatures over *different* manifests is refused outright
(`merge_signatures`) — that is the exact attack commit-reveal exists to stop.

## D4 — Document shape: `result` + `claims`, and two digests

**Decision.** The manifest has exactly two top-level members besides its identity:

```text
{ schema_version, type, result: {…}, claims: {…} }

RunDigest    = sha256(canonical(the whole manifest))   ← signed, stored, the attestation's name
ResultDigest = sha256(canonical(the `result` member)) ← what two verifiers compare
```

`result` holds everything a faithful re-run reproduces: source (commit, workflow
source, event digest, job, matrix), inputs and secret *names*, resolved action pins,
the reusable-workflow closure, the environment fingerprint, per-step outcome and
digests of normalised output, and provenance. `claims` holds who asserted it and
when: `run_id`, `claimed_at_us`, optional validity bounds, a quorum challenge,
per-step timings, the normalisation diffs, and free-form annotations.

**Why.** C4. N volunteers re-running one change must hash to the same value, and two
honest runs never agree on the incidental parts — wall-clock time, step durations,
which hostname got rewritten out of a log line, which random run id was chosen. If
those live in the same object as the outcome, digests differ forever and a quorum
reports disagreement about runs that actually agreed. The split makes the two
questions — *what did the run produce* and *who says so, and when* — separately
addressable while keeping a single signature: a verifier that agrees on
`ResultDigest` still holds a signature over the whole manifest, because
`ResultDigest` is a digest over part of the signed document.

**Rejected.**
* **One flat signed object, with "strip the volatile fields before hashing"** — a
  field-list-driven hash is a permanent footgun: every new field needs a ruling, and
  a forgotten ruling is a silent interop break. Nesting makes the boundary a
  structural fact.
* **Two documents (result, then a claims document signed separately)** — two
  signatures, two storage records, and a new class of "which claims belong to which
  result" bugs, for no benefit.
* **Hashing only what a policy happens to compare** — then the *policy* decides the
  digest, and two policies produce incomparable attestations.
* **Putting timings in `result` and asking verifiers to ignore them** — that is
  "disagreement by default", which is the failure mode the quorum cannot afford.

**Consequences.** `.2` builds both digests and never chooses fields to omit; `.3`
knows which of its rewrites are digest-visible; `.7`'s provenance tier lives in
`result` (it is a property of how the run happened) with the `quorum` tier reserved
for a verdict *over* attestations, so no single run can claim quorum about itself.

## D5 — The volatile-field register

Certain values are poison inside `result`, because at least one honest machine
produces a different one. They are named so no ticket has to re-litigate them:

| value | where it goes | why it cannot be in `result` |
|-------|---------------|------------------------------|
| wall-clock time of the run | `claims.claimed_at_us` | two runs never share a start time |
| step durations / start times | `claims.timing` | durations differ by machine and load |
| hostname, uid/gid, username | nowhere, or normalised out entirely | machine identity is not machine class |
| `$RUNNER_TEMP` / `$TMPDIR` / build paths | normalised placeholders (`.3`) | path-dependent digests |
| normalisation diff *before* text | `claims.normalisation_diffs` | by definition the per-machine side |
| runner log file names, pids, ports | nowhere | nondeterministic |
| git committer dates in checked-out files | digests only, never text | they are not the workflow's output |
| `EnvFingerprint` identity parts | `result.environment`, but only machine *class* fields (image digest, arch, os, toolchain versions) | `.4` must not fingerprint the machine, only its kind |

`run_id` is deliberately *not* in `result`: it exists to stop two runs of the same
commit producing one identical attestation (D6, replay), and per D4 that makes it a
claim. The register is enforced where it can be — `environment.fingerprint` is
**derived** from the environment it describes (a mismatch is a validation error, so
no one can describe one environment and claim another) — and by review everywhere
else.

## D6 — Time: claimed microseconds, freshness is policy

**Decision.** The signed manifest carries `claimed_at_us`: **integer microseconds
since the Unix epoch, UTC**, plus optional `not_before_us` / `not_after_us` for
short-lived grants. Nothing else. Freshness is not a property of the document; it is
a policy the verifier applies:

| policy knob | default | meaning |
|-------------|---------|---------|
| `max_age_us` | 24 h | refuse an attestation older than this |
| `max_clock_skew_us` | 300 s | refuse one claiming to be more than this far in the future |
| `not_after_us` | — | the document's own window always wins if tighter |

`Policy::now` can be pinned by the caller, which is what makes the golden fixtures
and every replay test deterministic.

**Why integers.** RFC 3339 strings have a dozen encodings (offset vs `Z`, three or
six fraction digits, `,` vs `.`), and a timestamp that can be written two ways
inside a signed payload is a digest that can be produced two ways. Microseconds fit
comfortably in `i64`, and the display layer (`gitiup attest show`) formats whatever
the human wants. Leap seconds: this is a POSIX-style epoch count, insertions are
ignored — an attestation describes a run, not an astronomical event.

**Why freshness is policy and not payload.** The producer cannot know the consumer's
risk appetite: a merge gate wants an hour, a public archive wants a year. Putting the
window in the document means re-signing to change it.

**The limit of a self-claimed time, stated plainly.** A `claimed_at_us` proves what
the signer *said*, not what the clock *was*. So: the default window is short; a claim
in the future beyond skew is refused rather than forgiven; and long-horizon claims
("this was signed before the key was compromised") cannot be made from v1 alone —
they need either the anchor of D9 or the trusted moment of the merge record, which
records "at merge time this attestation was fresh and this key was trusted". Key
revocation is therefore a first-class need for `.6`/`.8` (a key-id revocation list in
owner config), not an afterthought.

**Rejected.** *RFC 3339 in the payload* (above). *Producer-chosen expiry as the only
window* (a producer can only make an attestation stricter, and a verifier still needs
its own ceiling). *Mandatory RFC 3161 TSA* (a network dependency in the trust path,
against C2; available later as an anchor under D9). *Clock-free design with no
timestamp at all* — then a leaked key can backdate a CI result onto old commits with
no freshness signal to catch it.

## D7 — Verification order, error taxonomy and limits

**Decision.** Verification is ordered so the first thing wrong decides the verdict,
and the classes are fixed because scripts branch on them
(`giti_attest::ErrorKind::exit_code`, used by `gitiup verify attestation` in `.8`):

| exit | class | examples |
|------|-------|----------|
| 0 | accepted | — |
| 6 | refused by policy, or not a document this build understands | untrusted signer, expired/future timestamp, disallowed tier, too few signatures, unknown `schema_version`, normalisation-version mismatch |
| 7 | bad signature | signature does not verify, `key_id` does not match the key offered |
| 8 | digest mismatch | received bytes are not canonical, claimed digest ≠ recomputed digest, wrong bound commit, `ResultDigest` differs from the expected one |

Order: structural validity → canonical form and digests → expected bindings →
signatures (self-consistency before the trust list) → tier → freshness. Signature
verification is always over the **received** bytes, and the bytes must equal their
own re-canonicalisation, so an attacker cannot add a field without breaking a
signature and an honest reader cannot quietly "fix up" formatting (exit 8 instead).

Limits are part of the format, because a volunteer parses strangers' claims (C7):
1 MiB per canonical document, 32 containers of nesting, 4096 entries per list/map,
4096 steps, 16 KiB per string, 64 signatures per document. Unknown fields are refused
(`deny_unknown_fields`); `claims.annotations` is the sanctioned extension point, and
its values are strings so an extension can never be richer than a typed field.

Defaults fail closed: `Policy::default().trust` is `Trust::None`, `allowed_tiers` is
`[local]` (a `simulated` run is a plan, never an execution — `.7`), and
`min_signatures` is 1.

## D8 — Versioning, conformance and the migration story

**Decision.**

* The document self-describes *inside the signed payload*: `schema_version: 1` and
  `type: "https://gitiup.dev/attestation/run/1"`, and the envelope adds
  `payload_type: "application/vnd.gitiup.run-manifest+json"`. A v2 document cannot be
  checked with v1 rules, because it cannot be made to look like a v1 document.
* **v1 is additive-only.** New optional fields may appear (a v1 reader sees an unknown
  field and refuses it — loud, not lenient), so a field that must be understood by
  everyone *is* a version bump. Third-party fields use `claims.annotations` with
  `x_<producer>_<name>` names.
* The **canonical encoding is not versioned**. It is the invariant the digests
  depend on; changing it (a different escape set, admitting floats, reordering keys)
  changes every digest in existence and is therefore a new `type`, not a new field.
* **Committed golden vectors are the contract**:
  `crates/gitiup-attest/tests/fixtures/v1/` holds canonical `manifest.json` and
  `doc.json` bytes plus their `run_digest`, `result_digest`, `record_digest` and
  signatures for four cases (`minimal`, `simulated`, `local`, `quorum-member`),
  signed with a key derived from a documented public seed — no private key material is
  committed. `tests/golden.rs` fails if the bytes, digests or signatures move;
  `tests/format_properties.rs` proves every field affects the digest and that
  ordering cannot; `tests/schema_drift.rs` proves the Rust types and the committed
  JSON Schemas still describe the same document. Another implementation is expected
  to consume the same fixtures.
* The digest's algorithm tag and the signature's algorithm enum are the two places a
  later cryptographic change can be expressed **without** a format break: admitting
  `blake3:` artifact digests, or a `cert` signer variant, is a policy decision.

**How we change our minds.**

1. Write an ADR that supersedes this one (or amends the numbered decision), and say
   what it invalidates.
2. If bytes for existing versions change shape: new `type` URI, new schema file
   (`*-2.schema.json`), new fixture directory `fixtures/v2/`; `fixtures/v1/` stays
   forever, because old attestations in old buckets must keep verifying.
3. Readers accept a set of types, not one; policy (`allowed_types`, `min_schema_version`)
   decides what a given merge gate accepts, and both versions can be accepted during
   a window. Producers write only the newest.
4. The one thing never done in place: changing the canonicaliser, the PAE framing, the
   key-id derivation or the field meaning of anything already in `result` — those
   silently re-name every existing digest. `key::tests::pins_key_line_fingerprint_and_signature`
   and `tests/golden.rs` exist to make that impossible to do by accident; the key pins
   were cross-checked against OpenSSL rather than against this crate.
5. Emergency invalidation (a broken canonicaliser, a bad key) is an *operational*
   act: revocation lists and a policy bump (`min_schema_version`), not a rewrite of
   history.

## D9 — Transparency-log anchoring: optional, separate, additive

**Decision.** Log anchoring (Rekor-style, or a `note`-style signed tree head) is an
**optional add-on**, expressed as its own signed record that references a `RunDigest`:

```text
anchor record = { type: "https://gitiup.dev/attestation/anchor/1",
                  anchored_run_digest, log: { url, kind, entry_index, integrated_at_us, … },
                  signatures: […] }     → kv/anchor/<hex>, policy-configured, not embedded
```

Adding an anchor cannot change a `RunDigest`, so anchoring never invalidates the
author's signature and — crucially — **signing never requires the network**. A
verifier that is told to require an anchor fetches it by digest as a separate step
(another component's I/O, never this crate's) and checks the inclusion proof against
the log's key. `require_log_anchor` defaults to false; a protected-branch gate may
turn it on later. This is also the one place where a *trusted* creation time can come
from, which is what D6 cannot do on its own.

**Rejected.** *Mandatory log* — a network dependency and a third-party CA in the
trust path, which contradicts the premise (C2) and makes air-gapped and self-hosted
setups second-class. *Embedding the log response inside the manifest* — the payload
would have to be signed twice (before and after anchoring), the digest would change
under the author's feet, and offline verification would break. *Treating an anchor as
proof of correctness* — it proves only "this digest existed at time T".

---

## Consequences

**Unblocked.** `.2` can compute digests without deciding anything (`RunManifest`,
`normalize()`, `digest()`, `result_digest()` all exist); `.3` gets a clean
digest-visible/digest-invisible boundary and a `NormalisationDiff` slot that cannot
poison a digest; `.5` has storage keys (`kv/attestation/<hex>`) and a ref shape; `.6`
plugs key backends into one `Signer` trait and inherits the SSH identity for free;
`.8` gets the exit-code taxonomy; `giti-msi.*` gets the co-signing and challenge
primitives (`merge_signatures`, `claims.verifier_challenge`, one-signature-per-key).

**Costs.** A hand-written canonicaliser and its strict reader must stay correct —
covered by tests, including RFC 8785 escape vectors and a refusal list for every
lenient shortcut a JSON parser might forgive. The JSON Schema is a second
specification of the same thing, so a drift test (`tests/schema_drift.rs`) is
mandatory rather than nice. And `ResultDigest` must be explained to every reader of
the quorum code: it is why verification says "results agree" while signatures still
prove who claimed what.

**Explicitly out of scope, decided elsewhere.** Output normalisation rules (`.3`),
the environment fingerprint's exact inventory (`.4`, bounded by D5), key storage and
revocation (`giti-1rs.6`), attestation retention and GC (`.5`), quorum selection and
vote counting (`giti-msi.*`), and how a merge gate *uses* a verdict (`giti-kd4.5`).

**References.** Implementation and tests:
[`crates/gitiup-attest`](../../crates/gitiup-attest/README.md). Host-side storage and
namespaces: [host abstraction](../host-abstraction.md). Registry of ADRs:
[`docs/adr/README.md`](README.md).

# Host abstraction

How gitiup talks to "where the repo lives", and the promises every host owes the
code above it. This is the contract the later tickets code against; changing it
means changing the tickets, not just the code.

Implementation: [`crates/gitiup-host`](../crates/gitiup-host/README.md).

## Why a host trait at all

GitHub is a normal git remote plus a workflow engine plus a review database. The
goal is that none of those three are *required*: an owner with an S3 bucket, or a
bare repo on a box they ssh into, must be able to propose changes, run actions,
publish signed attestations and gate merges. So every forge interaction is
rewritten as one of:

* read/write **refs** (with compare-and-swap),
* move **packs** of objects,
* put/get/list **content-addressed records**.

Anything a forge does that is not one of those three is a policy question the
host cannot answer, and it becomes owner-side logic (`gitiup change`,
`gitiup verify`) rather than an API call.

## The traits

```text
RefStore   list_refs  get_ref  update_ref_cas  cas_ref  update_refs_cas  delete_ref_cas
           fetch_pack  put_pack
BlobStore  put_cas  put_json  get  head  exists  list_prefix  list
Host       RefStore + BlobStore + capabilities() + describe() + require()
```

Design decisions, so nobody re-litigates them mid-ticket:

* **Synchronous traits.** gitiup is a CLI; blocking calls in `spawn_blocking`
  are simpler than an async runtime in the core. An async-backed host (S3) owns
  its runtime inside its own methods and still presents `&dyn Host`.
* **Object safe.** `Box<dyn Host>` / `Arc<dyn Host>` must keep working, and trait
  upcasting gives `&dyn RefStore` / `&dyn BlobStore` for free — a test harness or
  a verifier that only reads refs should not need the whole host.
* **`Send + Sync`.** Verification runs read several hosts on threads.
* **`describe()` and `capabilities()` are cheap.** They are called before
  operations to fail early, and by `gitiup remote doctor` to print a matrix.

## The compare-and-swap contract

Every ref write states what the writer believes is there:

| expectation       | meaning                       | S3                        | git                          |
|-------------------|-------------------------------|---------------------------|------------------------------|
| `Expect::Absent`  | create only                   | `If-None-Match: *`        | `--create-only`              |
| `Expect::Is(oid)` | only if it still holds `oid`  | `If-Match: <etag>`        | `--force-with-lease=<ref>:<oid>` |
| `Expect::Any`     | unconditional                 | plain `PUT`               | `--force`                    |

A mismatch is `HostError::Conflict` carrying `expected` and `found`; the host
must not have changed anything. `Expect::Any` is available but gitiup code that
gates a merge must never use it — a lost update there is a lost merge.

Hosts that cannot offer CAS say so with `capabilities.cas = false`; writes that
depend on it then fail with `UnsupportedCas` and a hint (this is exactly the
"buckets without conditional writes refuse owner-side merges" rule).

`update_refs_cas` applies a batch atomically. The `fs` host rewrites its single
ref file under one lock and can promise it; the inherited default implementation
applies updates in order and rolls back applied ones on failure, so a host that
inherits it sets `atomic_multi_write = false` and callers know a crash between
the rollback writes can leave a partial change.

## Ref namespaces

Shared by every host, so a change or an attestation is found the same way
wherever the repo lives:

```text
refs/heads/**            real branches (owner writes)
refs/changes/<id>/head   proposed change head
refs/attestations/<oid>  attestations for a commit, so `git fetch` carries proof
refs/gitiup/**           roster, job/lease records, quorum state
```

`RefName` validates names git-style (no `..`, no `~^:?*[\\`, no `.lock` suffix,
no empty components) so a bad name fails at parse time rather than as a weird
key in a bucket.

## Store layout

Derived in one place — `RemoteConfig` — and mirrored by every host:

```text
<root>/host.json            what this store is (schema, kind, store-prefix)
<root>/refs/<name>          ref -> { oid, updated_by, updated_at, schema }
<root>/kv/<kind>/<hash>     change records, attestations, rosters, job records
<root>/packs/<oid>.pack     packs, content addressed
```

with `<root> = <url path>/<store-prefix>` (default store prefix `gitiup`). For a
git-backed host the same content is stored as git refs and objects instead, and
for the `fs` host it is literally directories:

```text
<host>/gitiup-host.toml     schema-version, kind, store-prefix, created-at
<host>/refs                 <oid>\t<name>\t<actor>\t<updated-at> per line
<host>/cas/<ns>/<xx>/<hex>  blobs
<host>/packs/<oid>.pack     packs
```

Blob digests are SHA-256 of the exact bytes; `put_cas` is idempotent; nothing in
this crate overwrites or deletes an object, and the `fs` host verifies a blob
re-hashes to its name on read. Retention and tombstoning are host policy and
belong to the attestation ticket (giti-1rs.5), not to this trait.

For signed records the bytes are not chosen by the host: [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)
decides that `kv/attestation/<hex>` holds the *canonical* encoding of an
attestation document, and that the hex is SHA-256 of exactly those bytes. A host
that re-serializes a record on the way to storage — pretty-printing it, reordering
keys, adding a trailing newline — has silently broken the signature, so hosts store
and return blobs verbatim and `gitiup-attest` refuses bytes that are not canonical
(`gitiup verify attestation` exits 8).

## The bucket-as-forge host (`s3`)

`S3Host` makes a plain bucket — S3, MinIO, anything that speaks the S3 API — the
forge: refs are objects, merges are conditional writes, and there is no
server-side code to trust. The layout is the one above plus a manifest, and the
keys are exactly what `aws s3 ls` shows:

```text
<root>/host.json            { schema, kind: "s3", store-prefix, created-at }
<root>/refs/<name>          { oid, updated_by, updated_at, schema } or a tombstone
<root>/kv/<kind>/<hash>     records, one object each
<root>/packs/<oid>.pack     packs, multipart above the threshold
```

**A ref is a small JSON object and moving it is a conditional write.**
`Expect::Absent` is `If-None-Match: *`; `Expect::Is(oid)` re-reads the object and
sends `If-Match: <etag>`; `Expect::Any` is a plain `PUT`. A 412 that a re-read
explains is `HostError::Conflict` with both sides filled in, so the caller can
rebuild the update. A 412 a re-read does *not* explain is retried with
exponential backoff (`cas-attempts`, `cas-backoff`, `cas-backoff-cap`), because
on a real bucket that is a flinch, not a lost race.

**Deleting a ref tombstones it.** The object is overwritten with
`{ ..., deleted: true, deleted_by, deleted_at }` and `get_ref` answers `None`.
Nothing is ever `DELETE`d: on an unversioned bucket a delete is an irreversible
loss and on a versioned one it buys nothing. A tombstone still occupies its key,
so re-creating a ref is a CAS like any other — which is what two clones pushing
the same branch name need.

**Versioning is required, Object Lock is recommended, and both are checked
rather than assumed.** At connect time the host reads the bucket's versioning
state and Object Lock configuration and probes conditional writes by *doing one*
(write the same key twice with `If-None-Match: *`; if it lands twice, this bucket
is not doing CAS). An unversioned bucket is refused with the `aws s3api` command
that fixes it, unless the operator sets `require-versioning = "false"`, in which
case `capabilities.immutable` goes false and `advice()` keeps saying so. A bucket
that cannot do conditional writes reports `capabilities.cas = false` and refuses
CAS-dependent ref writes with `UnsupportedCas` — it never quietly overwrites a
ref, which is exactly why owner-side merges are refused there. `Expect::Any`
stays available: it is not CAS-dependent, and refusing it would be the host
making the operator's decision for them.

**Listings are cached for a moment; point lookups are not.** `list_refs` is an
advertisement ("what I saw `ref-cache-ttl` ago", default 2 s), so a fetch loop
costs one LIST rather than one GET per ref, while `get_ref` always reads the
object. Any write invalidates the cache. A stale listing can be wrong but can
never lose an update, because every write re-reads the ref it is about to
replace.

Options live in `[remote.options]` (or the URL query string). Unknown keys are
not an error but appear in `advice()`, so a typo surfaces in
`gitiup remote doctor` instead of silently disabling a safety setting:

| option | default | meaning |
|--------|---------|---------|
| `region` | AWS chain | override the resolved region |
| `endpoint` | AWS | MinIO/gateway URL, e.g. `http://127.0.0.1:9000` |
| `profile` | `AWS_PROFILE`/chain | shared-config profile to use |
| `force-path-style` | `false` | what most S3-compatible servers expect |
| `require-versioning` | `true` | refuse buckets that do not keep history |
| `conditional-writes` | `auto` | `auto` probes, `on` demands, `off` accepts a dumb bucket |
| `multipart-threshold-mib` | 8 | objects at least this big go up as multipart |
| `part-size-mib` | 8 | part size (S3's own minimum is 5) |
| `ref-cache-ttl` | `2s` | advertisement TTL; `0s`/`off` turns the cache off |
| `cas-attempts` | 4 | retries after an unexplained 412 |
| `cas-backoff` / `cas-backoff-cap` | `20ms` / `2s` | the backoff for those retries |

**Credentials come from the AWS chain and nowhere else**: environment (access
keys or a web identity/IRSA), a shared-config profile, SSO — whatever `aws sts
get-caller-identity` would use. A `gitiup.toml` credentials profile that names a
token for an `s3://` remote is refused outright by
`S3Host::check_credentials`: it would be useless here and is a leak waiting to
happen. `describe()` names the endpoint, region and which chain member is in
play, and never a credential value.

**The transport is a trait, so the host is testable without a bucket.** Every
bucket call goes through `hosts::s3::bucket::Bucket` (`facts`, `info`, `get`,
`head`, `put`, `list`, `put_large` — synchronous, because the host traits are).
`MemoryBucket` is a second, in-process implementation with real etags, real 412s,
paged LISTs and staged multipart uploads, plus fault hooks
(`fail_next_conditionals`, `lose_next_races`, `fail_writes_after`);
`tests/host_s3.rs` runs the whole host against it, so the CAS paths are covered
with no network and no credentials. The `s3` cargo feature adds the `aws-sdk-s3`
transport used by `S3Host::from_remote` (async lives entirely inside that
module); without it the host still compiles and answers "this build has no S3
transport, feature `s3`" — which keeps the default build free of HTTP and AWS
code, as `tests/no_forge_deps.rs` checks. `tests/host_s3_live.rs` runs the same
bodies against a real endpoint and is `#[ignore]`d so the default suite stays
hermetic.

## Pack format

`PackFormat::Raw` ("gitiup pack") is the transport for CAS-style hosts:

```text
"GPK1"        magic
u8   version = 1
u8   flags (reserved, 0)
u32  object count (big endian)
  repeated: u8 namespace length, namespace bytes, u32 content length, content
[32]          sha256 of everything above
```

Limits (200 000 objects, 64 MiB per object, 512 MiB per pack) are enforced on
both encode and decode. The trailer is verified, so a truncated or tampered pack
is rejected instead of half-imported. `PackFormat::GitPackfile` bytes are opaque
here: git-backed hosts (giti-xdw.3) accept them, everything else answers
`UnsupportedCas` with `capability = "pack-format:git-packfile"`.

## Error taxonomy

| variant            | branch on it when                                    | retry? |
|--------------------|------------------------------------------------------|--------|
| `Unreachable`      | back off and retry the whole command                 | yes    |
| `UnsupportedCas`   | the host cannot promise this; refuse and explain     | no     |
| `Conflict`         | re-read the ref, rebuild the update, retry           | yes    |
| `PermissionDenied` | stop; print the credential profile that was used     | no     |
| `SchemeUnknown`    | stop; the message lists `s3, https, ssh, file`       | no     |
| `NotFound`         | treat as absent, or report the missing object        | no     |
| `Invalid`          | user/config/data is wrong; show `location` + `hint`  | no     |
| `Storage`          | local I/O trouble                                    | maybe  |

Every variant may carry a `hint`; the CLI prints `error: <message>` and
`hint: <hint>`. `HostError::kind()` is the stable kebab-case name for
`--json`. New variants need a commit that teaches the call sites, since the
taxonomy is a public contract.

## `gitiup.toml`

Schema-versioned (`schema-version = 1`), discovered by walking up from the
working directory, overridable with `GITIUP_CONFIG`. Full reference:
`crates/gitiup-host/examples/gitiup.toml`.

Versioning policy: a file with a `schema-version` above this build's maximum is
refused with an instruction to upgrade gitiup; a lower-but-supported version is
read as-is; adding a field means bumping the version, and unknown fields are
errors so typos surface instead of silently disabling a safety setting
(`store-prefix`, `credentials-profile`, `timeout`).

## Writing a new host — checklist

1. Decide the four capability bits **truthfully**, then implement
   `capabilities()`/`describe()` first so refusals work before the happy path.
2. Implement `list_refs`, `get_ref`, `update_ref_cas`, `delete_ref_cas`; map
   transport failures onto the taxonomy (`Unreachable` for transport,
   `PermissionDenied` for 401/403, `Conflict` for a 412/lease failure,
   `NotFound` for 404).
3. Implement `put_cas`/`get`/`list_prefix` with the key helpers on
   `RemoteConfig`; never overwrite an existing object.
4. Implement `fetch_pack`/`put_pack` (or answer `UnsupportedCas` for formats you
   cannot serve) and honour `have` so clients do not re-download.
5. Re-run the `tests/host_fs.rs` bodies against your host (they take `&dyn Host`
   precisely so they can be lifted into the giti-xdw.5 conformance suite), plus
   the two adversarial ones: concurrent create-only CAS writes, and a batch whose
   last update conflicts.
6. Keep the crate forge-free: `cargo test -p gitiup-host --test no_forge_deps`.
   Adapters for actual forges go behind a non-default feature (giti-xdw.4).

# gitiup-host

The host abstraction gitiup codes against: everything gitiup needs from "where
the repo lives" goes through three traits instead of a forge client, so a plain
S3 bucket, a bare git repo on a colocation box and GitHub are all just hosts.

This crate has **zero forge dependencies** — no HTTP client, no GraphQL, no
GitHub SDK. `tests/no_forge_deps.rs` enforces it.

```rust,ignore
let host = FsHost::create("/srv/git/my-repo")?;          // the reference host
let oid  = host.put_cas(&Namespace::ATTESTATION, attestation)?;
host.update_ref_cas(&RefUpdate::create(RefName::attestation(&oid), oid))?;
```

## The trait set

| trait       | methods                                                                       | what it is for |
|-------------|-------------------------------------------------------------------------------|----------------|
| `RefStore`  | `list_refs`, `get_ref`, `update_ref_cas`, `cas_ref`, `update_refs_cas`, `delete_ref_cas`, `fetch_pack`, `put_pack` | refs, and the pack transport |
| `BlobStore` | `put_cas`, `get`, `head`, `exists`, `list_prefix`, `list`, `put_json`          | change records, attestations, rosters, job records |
| `Host`      | `capabilities`, `describe`, `require` + both traits above                       | "may I do this here?" |

Every write to a ref is a **compare-and-swap**: the caller states what it
believes the ref holds (`Expect::Absent`, `Expect::Is(oid)`, `Expect::Any`) and
the host either applies the write or answers `HostError::Conflict` with both
sides filled in. That single rule is what lets a bucket with conditional writes
and a git repo with `--force-with-lease` replace a forge's merge logic.

`Expect::Absent` is "create only"; the `Option`-shaped convenience
`cas_ref(name, expected, new)` treats `None` as *no opinion*, so guarded
creation always goes through `RefUpdate::create`.

`update_refs_cas` applies a batch all-or-nothing. The `fs` host does that for
real (one lock, one atomic rewrite of the ref file); hosts that cannot override
nothing and inherit the default implementation, which applies the batch and
rolls back on failure. Ask first:

```rust,ignore
host.require(Capability::AtomicMultiWrite)?;   // UnsupportedCas if not
```

### Capability model

`Capabilities { cas, immutable, atomic_multi_write, auth }`, with
`AuthModel::{Anonymous, Filesystem, Token, SshKey, CloudRole, Helper}`. A host
that cannot CAS reports `cas = false` and every write that gates a merge fails
early with `UnsupportedCas` and a hint, instead of losing a ref later. Suggested
shapings: `fs` = all three (`auth: filesystem`), S3 = `cas + immutable` without
multi-write (`auth: cloud-role`, or `anonymous` for a bucket declared
public-read), git over ssh = `cas + immutable` via force-with-lease
(`auth: ssh-key`), git over http = the same guarantees with `auth: anonymous`
because the credential that authorises a private repository there is git's, not
gitiup's — see the scope note below.

## Ref namespaces (shared by every host)

```text
refs/heads/**                        real branches (owner writes)
refs/changes/<id>/head               proposed change head        (giti-kd4.1)
refs/attestations/<subject>/<digest> attestations for a commit, so `git fetch` carries proof (giti-1rs.5)
refs/gitiup/**                       roster, job/lease records, quorum state
```

## Attestations (`attest`)

An attestation is signed bytes, so storing one is two writes in a fixed order and one
rule that is not a policy knob:

* **bytes first, then the ref** — a ref naming bytes no reader can fetch is a broken
  proof, while un-advertised bytes are merely unread; on a git host the ref write is
  what wraps the record into a pointer commit, and it needs the blob to exist already.
  Both writes are create-only, so a re-publish is idempotent and a second proof about
  the same commit gets its own ref instead of overwriting the first.
* **a listing is a prefix read** — `list_for(subject)` lists
  `refs/attestations/<subject>/*` and nothing else, so answering "what proves this
  commit?" does not cost more as the store fills. Refs in that namespace that are not
  this shape come back as `unexpected` rather than being skipped.
* **an object another live ref points at is never pruned** — `referenced()` collects
  the digests live refs *outside* `refs/attestations/**` point at, which is where a
  quorum keeps its evidence: each seat's submission is a blob in this same CAS, held by
  `refs/gitiup/reveal/<change>/<job>/<slot>`. So “keep the round's ballots” is not a
  setting; it is what the store does, and `plan` reports such a digest as `Pinned` with
  the ref that holds it. A digest named inside another record is not a ref, so
  `pin()`/`--keep` is how a caller declares that one — see
  [docs/host-abstraction.md](../../docs/host-abstraction.md#retention).

`plan` / `apply` are separate so a `gc` is reviewable before it is destructive, and
retiring means *un-advertising*: the ref goes, a record lands in `kv/gc/<digest>`
saying what was removed, what was pinned and what each decision was based on, and the
bytes are only deleted where the host can honestly forget (`BlobStore::purge_cas`,
which the `fs` host implements and a git or versioned-bucket store refuses — an
append-only store cannot forget one object). The full rules, and the reasons, are in
[docs/host-abstraction.md](../../docs/host-abstraction.md#attestations-in-the-store).

## Store layout

`RemoteConfig` is the single source of truth for the key shape, so every host
lays the same objects out (`fs` mirrors it as directories):

| helper                    | key                                       |
|---------------------------|-------------------------------------------|
| `root_prefix()`           | `<url path>/<store-prefix>`               |
| `ref_key(name)`           | `<root>/refs/<name without leading refs/>` |
| `kv_key(namespace, oid)`  | `<root>/kv/<kind>/<hash>`                 |
| `pack_key(oid)`           | `<root>/packs/<oid>.pack`                 |

`fs` writes exactly that under its directory:

```text
<root>/gitiup-host.toml     schema-version, kind = "fs", store-prefix, created-at
<root>/refs                 <oid>\t<name>\t<actor>\t<updated-at>, rewritten atomically
<root>/cas/<ns>/<xx>/<hex>  content-addressed records
<root>/packs/<oid>.pack     packs
```

CAS digests are SHA-256 over the exact bytes handed to `put_cas`; `put_cas` is
idempotent and nothing in this crate overwrites or deletes a stored object. The one
exception is deliberate and reported: `BlobStore::purge_cas` forgets one object where
the host honestly can (the `fs` host), and everywhere else says so instead of
pretending — see [Attestations](#attestations-attest).

## Packs

`fetch_pack` / `put_pack` move objects between hosts. Two formats:

* `PackFormat::Raw` — "gitiup pack", a checksummed container of
  `(namespace, bytes)` records; CAS hosts store it directly and it is what
  bundle-style proposals (giti-kd4.2) ship around.
* `PackFormat::GitPackfile` — opaque bytes for git-backed hosts (giti-xdw.3).
  Hosts that cannot parse one answer `UnsupportedCas` naming the format.

Byte layout of a raw pack: `GPK1`, version `1`, flags `u8`, `count: u32be`,
then per record `ns_len: u8`, `ns`, `len: u32be`, `bytes`, and a trailing
32-byte SHA-256 of everything before it. The digest is verified on decode, so a
truncated or edited pack is rejected rather than half-imported.

## Hosts

| host | remote URL | what it is |
|------|------------|------------|
| `FsHost` | `file:///srv/git/my-repo` | the reference host: refs, packs and a CAS blob store on a directory |
| `S3Host` | `s3://bucket/prefix` | bucket-as-forge: refs are JSON objects, merges are conditional writes |
| `GitHost` | `file://`, `ssh://`, `https://`, loopback `http://` | the repo is just a git repo: a bare repository driven with the `git` binary |

`S3Host` stores `refs/<name>`, `kv/<kind>/<hash>` and `packs/<oid>.pack` under the
store root and moves a ref with `If-None-Match` / `If-Match`, so two clones
pushing at once cannot lose a ref. It requires object versioning (and says so
with the command that turns it on), recommends Object Lock, tombstones ref
deletions instead of deleting, caches ref listings for `ref-cache-ttl` (default
2 s), and takes its credentials from the AWS chain — a token in `gitiup.toml` is
refused, because it would be useless here and is a leak waiting to happen. The
full design notes are in
[`docs/host-abstraction.md`](../../docs/host-abstraction.md).

```rust,ignore
let bucket = MemoryBucket::forge("gitiup-forge");     // or: transport::connect(&remote)?
let remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo")?;
let host = S3Host::open_or_init(Arc::new(bucket), &remote)?;
let oid = host.put_cas(&Namespace::CHANGE, record)?;
host.update_ref_cas(&RefUpdate::create(RefName::change_head("c1")?, oid))?;
```

`cargo run -p gitiup-host --example s3_tour` walks through it — refs, CAS
conflicts, two clones converging, packs, tombstones — against `MemoryBucket`, an
in-process bucket with real etags, real 412s, paged listings and staged
multipart uploads, so the whole host is exercised with no network and no
credentials.

The `s3` cargo feature links the `aws-sdk-s3` transport used by
`S3Host::from_remote`; without it the host still compiles (and answers *"this
build has no S3 transport, feature `s3`"*), which keeps the default build free of
HTTP and AWS code.

`GitHost` needs no transport crate at all — it runs the `git` binary, so whatever
git can reach is a host: a directory (`file://`), a box you ssh into (`ssh://`, or
the scp-style `git@host:path`), `git-http-backend` over `https://`, or a static
web server over plain `http://`, read-only.

```rust,ignore
let remote = RemoteConfig::new("origin", "ssh://git@box/srv/git/repo.git")?;
let host = GitHost::open_or_init(&remote)?;              // writes refs/gitiup/host
let oid = host.put_cas(&Namespace::CHANGE, record)?;
host.update_ref_cas(&RefUpdate::create(RefName::change_head("c1")?, oid))?;
```

A ref whose value is a gitiup record points at a small *pointer commit* carrying
`gitiup-ref.json` and the record bytes, which is what makes *`git fetch` carries
proof* literal: the attestation arrives in the same packfile as the ref. Records
themselves live in append-only chains at `refs/gitiup/kv/<namespace>`, the CAS is
`git push --force-with-lease` plus a `--dry-run` probe, a batch is one
`git push --atomic`, and a reviewer with nothing but plain `git` can fetch
`refs/changes/**` and read the whole story. `cargo run -p gitiup-host --example
git_tour` walks through all of it against a throwaway bare repository. Design
notes: [`docs/host-abstraction.md`](../../docs/host-abstraction.md#the-plain-git-host-git).

## `gitiup.toml`

Schema-versioned config, discovered by walking up from the working directory
(`GITIUP_CONFIG` overrides):

```toml
schema-version = 1
default-remote = "origin"

[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"   # s3:// https:// ssh:// file://, git@host:owner/repo.git,
                     # and http:// for a server on this machine only
store-prefix = "store"              # optional, default "gitiup"
credentials-profile = "owner"       # optional, names a [credentials.*] block
timeout = "45s"                     # optional, 250ms/30s/5m/1h or bare seconds, max 1h

[remote.options]                    # free-form passthrough (region, endpoint, ...)
region = "eu-central-1"

[credentials.owner]
auth = "cloud-role"                 # anonymous|filesystem|token|ssh-key|cloud-role|helper
token-env = "GITIUP_TOKEN"          # tokens come from the environment, never the file
key-path = "~/.ssh/id_ed25519"
```

Unknown keys, duplicate remote names, a `default-remote` that does not exist, a
`credentials-profile` that is not defined, out-of-range timeouts and newer
schema versions are all hard errors with a hint about the fix;
`Config::warnings()` carries the non-fatal advice (no remotes yet, very long
timeouts, credentials embedded in a URL). `Config::to_toml` writes the file back
losslessly, `Config::to_json` renders it for `--json` output with secrets
redacted. See `examples/` and `crates/gitiup-host/examples/gitiup.toml`.

## Credential scope (`scope`)

`Origin` is scheme + host + port, normalised (`https://h`, `https://h:443`, `H` and
`h.` are one origin; `http` and `https` are not). `Scope` is the one origin a
token may be sent to — the one its own remote names — and `Breach` names the three
ways a client finds out it is about to talk to another: a **redirect** to a
different host, a **URL rewrite** between the config and the socket (`insteadOf`,
a pointer record that moved), and a host **introduced** by bytes that came out of
the first store (a `gitiup.toml` that arrived with a mirror). All three raise
`PermissionDenied` — exit **3** — with **both hosts named**, because "which two?"
is the question an operator has to answer and a refusal that omits them is a
mystery rather than a fix. `Config::credentials_for_target` and
`credentials_for_introduced` are the two doors a call site goes through, and a
host named by foreign bytes gets a credential only if *this* machine's own
`gitiup.toml` independently names that origin.

The transports decide this, not the call sites: `curl` runs `--no-location`, and
`git` is never handed a token — which is why `GitHost::check_credentials` refuses
`token-env` on a plain-git remote (exit 6: nothing ever left for it to be refused
about) and why an `http(s)` git remote reports `auth: anonymous`. The mirror
half of the property — a public store reads with no credential, and "empty" is an
`Ok` with nothing in it rather than a refusal — is measured alongside its opposite
in [`gitiup-host-tests`](../gitiup-host-tests/README.md):
`a_public_store_reads_with_no_credential` and
`a_credential_never_arrives_at_the_redirect_target`, which drives a real token at
an endpoint that redirects to a second origin reporting what it was sent.

## Error taxonomy

`HostError` is what later tickets branch on:

| variant           | when                                                       |
|-------------------|------------------------------------------------------------|
| `Unreachable`     | could not talk to the host (DNS, socket, timeout, missing directory) |
| `UnsupportedCas`  | a capability, CAS guarantee, pack format or operation is not available here |
| `Conflict`        | a compare-and-swap did not match (`expected`/`found` filled in) |
| `PermissionDenied`| reached the host, refused the action                       |
| `SchemeUnknown`   | nobody handles that URI scheme; the message lists what is supported |
| `NotFound`        | a ref, blob or pack is absent                              |
| `Invalid`         | malformed input, config or stored data (with location)     |
| `Storage`         | raw I/O failure                                            |

Each carries `hint` where there is something to do about it, `HostError::kind()`
gives the stable kebab-case name for `--json` output, and `is_retryable()` says
whether another attempt makes sense (transport trouble and conflicts yes,
refusals and bad input no).

## Tests

```sh
cargo test -p gitiup-host                        # unit + integration + doc tests
cargo clippy -p gitiup-host --all-targets
cargo test -p gitiup-host --features s3          # same, with the AWS transport linked
```

`tests/host_fs.rs`, `tests/host_s3.rs` and `tests/host_git.rs` drive the traits
through `&dyn Host` (shared bodies in `tests/support/`). Those are this crate's
own tests; the cross-host contract — the thing that has to be the same for every
host, forge included — is in [`gitiup-host-tests`](../gitiup-host-tests/README.md),
which runs one set of bodies against every host in the workspace (and in CI,
against a real MinIO and a real `git-http-backend`). `tests/host_s3.rs`
covers the bucket promises on `MemoryBucket`: conditional writes on the wire, 412
retry with backoff, two clones converging, tombstones instead of deletes, the
degraded `cas = false` path, multipart packs and the ref cache.

`tests/host_git.rs` runs against a real bare repository and checks what only a
git-backed host can be asked: that a reviewer with plain `git` sees the change and
the attestation in one packfile, that a stale lease is actually refused (twice —
client-side and, when the race is too close for the advertisement, by the server),
that a record chain survives two concurrent appenders, and that `refs/gitiup/**`
stays out of the listing. `tests/host_git_http.rs` runs the same store through
`git-http-backend` (a CGI shim in `tests/fixtures/`, no web server installed) and
through a static file server, which is where the read-only promise gets tested.
Both skip themselves if `python3` or `git-http-backend` is missing.

`tests/attest_store.rs` runs the attestation store (`attest::publish`, listing,
retention, retirement) against the two hosts a test can stand up without
credentials — `FsHost` and a bucket host on an in-process bucket — and asserts the
promise the hosts share but the transports do not: the same bytes, ref and answer
from both, and a git store's *refusal* to delete signed proof it cannot honestly
forget.

`tests/host_s3_live.rs` runs the same bodies against a real endpoint. It is
`#[ignore]`d so the default suite needs no network:

```sh
pip install "moto[server]" && moto_server -H 127.0.0.1 -p 5500 &
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test GITIUP_S3_LIVE_ALLOW_UNVERSIONED=1 \
  cargo test -p gitiup-host --features s3 --test host_s3_live -- --ignored
```

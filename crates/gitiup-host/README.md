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
multi-write (`auth: cloud-role`), git = `cas + immutable` via force-with-lease
(`auth: ssh-key`).

## Ref namespaces (shared by every host)

```text
refs/heads/**            real branches (owner writes)
refs/changes/<id>/head   proposed change head        (giti-kd4.1)
refs/attestations/<oid>  attestations for a commit, so `git fetch` carries proof (giti-1rs.5)
refs/gitiup/**           roster, job/lease records, quorum state
```

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
idempotent and nothing in this crate overwrites or deletes a stored object.

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

## `gitiup.toml`

Schema-versioned config, discovered by walking up from the working directory
(`GITIUP_CONFIG` overrides):

```toml
schema-version = 1
default-remote = "origin"

[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"   # s3:// https:// ssh:// file:// or git@host:owner/repo.git
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
cargo test -p gitiup-host        # unit + integration + doc tests
cargo clippy -p gitiup-host --all-targets
```

`tests/host_fs.rs` drives the traits through `&dyn Host`, so the same bodies are
the starting point for the shared conformance suite (giti-xdw.5).

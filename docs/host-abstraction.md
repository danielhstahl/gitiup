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
refs/heads/**                        real branches (owner writes)
refs/changes/<id>/head               proposed change head (the current attempt)
refs/changes/<id>/attempt/<n>        attempt n, immutable, create-only
refs/changes/<id>/{merged,abandoned} the record that moved the change out of `open`
refs/attestations/<subject>/<digest>  attestations for a commit, so `git fetch` carries proof
refs/gitiup/**                       roster, job/lease records, quorum state
```

The change refs, their record format and what a merge is are decided in
[ADR-0003](adr/0003-change-record-format-and-merge-semantics.md); the shape above is
repeated here because every host has to honour it, and because `<id>` is a
content-derived `chg-…` name rather than a number a server handed out (D3 there).

`RefName` validates names git-style (no `..`, no `~^:?*[\\`, no `.lock` suffix,
no empty components) so a bad name fails at parse time rather than as a weird
key in a bucket.

Each namespace is written by somebody specific, and each host stores the same name
in its own idiom:

| namespace | who writes it | on a git host | on a bucket / directory host |
|-----------|---------------|---------------|------------------------------|
| `refs/heads/**` | the owner, with plain `git push` | a branch, left exactly as git made it | one ref object, `refs/heads/main` |
| `refs/changes/<id>/head` | gitiup, for a contributor | a ref pointing at the change record (via a pointer commit, so the bytes travel with it) | a ref object plus `kv/change/<hash>` |
| `refs/changes/<id>/attempt/<n>` | gitiup, once per attempt, never again | the same, and the pointer commit's parents make `git log` the attempt history | a ref object plus the same `kv/change/<hash>` |
| `refs/attestations/<subject>/<digest>` | gitiup, after a run verifies (or `gitiup attest push`) | a ref pointing at the attestation (via a pointer commit, so the bytes travel with it) | a ref object plus `kv/attestation/<hash>` |
| `refs/gitiup/**` | gitiup only | the store manifest and the record chains; never listed | `host.json` and `kv/**` |

Two things follow from that table and both are load-bearing. `refs/attestations/**`
is named by the digest of the thing *attested* first, so "give me the proof about
this object" is a ref prefix read on every host, and on a git host it is a
`git fetch 'refs/attestations/<subject>/*'` that arrives with every proof for that
commit in the same packfile. And `refs/gitiup/**` is reserved: a host keeps its
bookkeeping there and hides it from an ordinary ref listing, so `gitiup change list`
never has to know which host it is talking to.

The attestation's own digest is the *leaf* of the ref rather than its only component
so that a commit can carry several proofs — several signers, several runs, several
tiers — where a single-level ref could hold exactly one and publishing a second would
be an overwrite. A ref named by one digest cannot be both a leaf and a directory, so
where the older single-level spelling occupies a subject, gitiup says so rather than
losing the ref or reporting "no attestation".

The single-level form (`refs/attestations/<subject>`, one ref, so one proof, per
subject) is the shape older gitiup — and the forge adapter before it — filed. It is
still *read*: a listing returns those proofs too, flagged `legacy` (`"shape":
"legacy"` in `--json`), because refusing to read a proof because of the spelling of
its ref would strand evidence a merge gate already relied on. Nothing writes it any
more, including the github adapter, which now publishes through the same
`gitiup_host::attest::publish` as every other host.

Moving what is already there is `gitiup attest migrate`, dry run by default like `gc`.
Per proof it notes the intent in `kv/migrate/<digest>`, retires the single-level ref,
filing it under `<subject>/<digest>`, and puts the old ref back if that filing fails.
The order looks backwards next to `publish`'s "bytes first, then ref" and has to be: a
ref cannot be a leaf and a directory at once, so on a git-backed store the old name
must free the name before the new one can exist. The intent record is what makes the
window between the two writes safe: every applying run re-files the proofs its own
earlier records say were mid-move, so a crash leaves a store that the next `migrate`
fixes rather than one only an audit finds. A proof whose bytes the store cannot return
is reported `blocked` and left exactly where it was — retiring the only advertisement
of unreadable bytes is retention's decision, not a migration's.

One spelling no reader can attribute is a ref in this namespace whose hex *is* its own
value: a digest advertised by digest, which names no subject. It is listed under
`unexpected_refs` — with a legacy ref that self-references, and with anything else in
the namespace that is neither shape, because a listing that quietly drops a ref is how
"there is no proof here" becomes a lie.

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
re-hashes to its name on read. Retention is a policy decision on top of that, not a
change to it — see [Attestations in the store](#attestations-in-the-store).

For signed records the bytes are not chosen by the host: [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md)
decides that `kv/attestation/<hex>` holds the *canonical* encoding of an
attestation document, and that the hex is SHA-256 of exactly those bytes. A host
that re-serializes a record on the way to storage — pretty-printing it, reordering
keys, adding a trailing newline — has silently broken the signature, so hosts store
and return blobs verbatim and `gitiup-attest` refuses bytes that are not canonical
(`gitiup verify attestation` exits 8).

## Attestations in the store

An attestation is signed bytes, so storing one is two acts: keep the bytes verbatim,
and make them findable. `gitiup_host::attest` does both, and `gitiup attest` is the
same three verbs on every host:

```bash
gitiup attest push attestation.json --store <store>   # or --run-report <run.json>, --sign
gitiup attest list --commit <oid> --store <store>     # or --all
gitiup attest show <digest> --store <store>           # --json, --bytes, --dsse
```

Publishing writes in one order and it is not an implementation detail: **the bytes
first, then the ref**. A ref naming bytes no reader can fetch is a broken proof, while
bytes nobody has advertised yet are merely unread. On a git host that order is also
what the host needs — the ref write wraps the record into a pointer commit, which it
can only build from the blob the previous line stored. Both writes are create-only:
re-publishing the same bytes reports `already`, and two people publishing *different*
proofs about one commit get two refs instead of a lost update.

Because a signature is only valid over exact bytes, the store holds the canonical
encoding byte for byte, and a host that files bytes under a digest they do not hash
to is refused rather than trusted (`BlobStore::return_preserves_digest` says which
hosts are exempt because they cannot compute it; `gitiup attest show` re-hashes
whatever it reads back and exits 8 on a mismatch).

A listing is a ref prefix read — it never fetches the whole namespace — and it reports
attestation refs it cannot parse under `unexpected_refs` rather than skipping them:
a listing that quietly drops a ref is how "there is no proof here" becomes a lie.

### Retention

A bucket that keeps every attestation forever is a bucket somebody has to pay for and
somebody will eventually delete wholesale. Three limits, all optional, all checked in
this order:

| limit | flag | what it means |
|-------|------|---------------|
| **referenced** | none — not a knob | an object any other live ref points at is never pruned |
| `max_age_us` | `--max-age 90d` | age of the *claim* (the attestation's own `claimed_at`), falling back to when this host published it |
| `max_per_subject` | `--max-per-commit 10` | newest N survive per subject; the rest are retired even if young |

The first row is not a setting because it cannot be. `attest::referenced` collects the
digests that live refs *outside* `refs/attestations/**` point at, and that is exactly
where a quorum keeps its evidence: each verifier's submission is a blob in this same
content-addressed store, advertised by `refs/gitiup/reveal/<change>/<job>/<slot>`, so a
policy that would sweep a finished round would be deleting the ballots a published
verdict was counted from. That is why it is a property of the store rather than a knob:
there is no flag that forces a pinned attestation away.

The scan reads refs, not record bodies, and says so: a digest named *inside* another
record — a merge record's `attestation` field, a verdict's contributing list — is a
claim about that document, not an advertisement of the object, so the caller that read
the record adds the pin (`attest::pin`, or `gitiup attest gc --keep <digest>` from the
command line). Guessing which strings in which blobs meant "do not delete this" would
make retention impossible to predict, and an unpredictable retention rule is one that
gets switched off. Expired attestations are also not counted against the per-subject
quota: an hour-old store with a month of expired proof in it reduces to the quota
question once the age has been applied.

`plan` is pure and `apply` is separate, so `gitiup attest gc` is reviewable before it
is destructive — it prints the plan and changes nothing unless told `--apply`, and
exits 6 when given no limit at all rather than guessing a retention policy for a
vault of signed evidence. Each applied run writes a `kv/gc/<digest>` record: what was
removed, what was pinned, and what each decision was *based on* (the timestamp and the
limit it missed), because "the gc job ran and things disappeared" is not an audit trail.

Retiring an advertisement is not the same as forgetting bytes, and a tool that
conflates the two is lying about provenance. A git store's record chain is
append-only, a versioned bucket keeps history by contract, and a `packs/*.pack`
copy is a second copy of the bytes gc does not own: on those hosts the report says
`retained`, and only `BlobStore::purge_cas` on a host that can honestly forget (the
`fs` host today) removes the object — and only when asked (`--purge-blobs`). Every
removed ref is reported by name, so a host that stores a second public copy can
report what still needs deleting there instead of pretending the packfile was the
whole store.

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

## The plain-git host (`git`)

`GitHost` makes an ordinary bare repository the forge: a directory on a box you
ssh into, a repo nginx serves with `git-http-backend`, or a pile of files a
static web server exposes. There is no API and no server-side code to trust —
only the four namespaces above and the transport git already speaks. The
implementation shells out to the `git` binary (floor: 1.8, because that is where
`--force-with-lease` and `--atomic` appear), so whatever git can reach, gitiup
can host on:

```text
file:///srv/git/repo.git          a directory (tests, a shared mount, a USB stick)
ssh://git@host/srv/git/repo.git   the colocation box; scp-style git@host:path too
https://host/repo.git             smart HTTP (git-http-backend behind a web server)
http://127.0.0.1:8080/repo.git    plain HTTP, accepted for a loopback server only
```

Plain `http://` is accepted only for a loopback host (an ephemeral server in a
test, a local mirror). Anywhere else it is refused with a hint to use `https://`,
so a credential never goes out unencrypted by accident.

**A ref that names a gitiup record points at a pointer commit.** A git ref can
only name a git object, but a change or an attestation is addressed by the
SHA-256 of its record bytes. So `refs/changes/c1/head` points at a small commit
holding `gitiup-ref.json` (the digest promised, the actor, the time) and the
record bytes as `record`. That is what makes *`git fetch` carries proof* true in
the literal sense: fetching the ref brings the attestation in the same packfile,
with no second protocol and nothing to download afterwards. Refs whose value is
already a git commit — branches, a change head that is a real commit — stay
exactly what they look like: plain git, untouched.

**The CAS is emulated the only way git allows**, and the sequence matters, so it
is written out in [`hosts/git.rs`](../crates/gitiup-host/src/hosts/git.rs) and
followed to the letter: fresh `ls-remote` of the one ref → compare with
`Expect` → `--dry-run` probe → `git push --force-with-lease=<ref>:<what we just
read>` → `ls-remote` again to check the server did what it said. Two details are
what make it a real lease rather than a gesture: `--force` is *never* passed
alongside a named lease (git ignores the lease then, which would silently disable
the safety net), and `Expect::Absent` is spelled as the all-zero expected value,
which is git's own "this ref must not exist". Batches go out as one
`git push --atomic`, which the receiving side applies as a transaction, so
`atomic_multi_write` is true here for real. Record appends — two contributors
publishing into the same namespace at once — retry with a jittered backoff
(`cas-attempts`, `cas-backoff`) because the loser's commit has to be rebuilt on
the winner's tip.

**The store's own machinery is refs too**, under `refs/gitiup/**`, and stays out
of every listing: `refs/gitiup/host` is the store manifest (schema, kind, url,
store-prefix) and `refs/gitiup/kv/<namespace>` is one append-only commit chain
per namespace whose tree holds one file per record, named by its SHA-256. That
chain is the content-addressed store: `put_cas` appends to it with a lease, so an
append either lands or reports that someone else appended first. A repository can
therefore be inspected, mirrored, backed up and `git fsck`'d with no gitiup
anywhere in sight.

**Reads go through a local mirror** (`work-dir`, default
`~/.cache/gitiup/host/<remote>-<hash>`): one `git fetch --prune +refs/*:refs/*`
populates it and everything after that is local object reads. The ref
advertisement is cached for `ref-cache-ttl` (default 2 s) the way the bucket host
caches its ref listing — a stale advertisement can be wrong but can never lose an
update, because a write re-reads the ref it is about to move. Blob *listings* are
not cached: "what records are in this store" has to include the one that landed a
second ago. Transport calls on one handle are serialised, so threads sharing a
handle cannot make each other's fetch fail with a lock error.

**Smart HTTP and dumb HTTP are different promises.** Smart HTTP
(`git-http-backend`) is a full host — pushes, leases, atomic batches — and needs
what any git server needs for an anonymous push (`http.receivepack = true` in the
repository, a user that may push otherwise). Dumb HTTP — a static file server and
`git update-server-info` — answers reads only, and gitiup says so: either you set
`read-only = "true"` in `[remote.options]` and it refuses writes up front, or it
tries, the transport refuses the push, and that comes back as
`HostError::UnsupportedCas` (never `Unreachable`), with `cas = false` from then
on. A static web server is thus a legitimate release mirror: anyone can clone a
change and its attestation from it, nobody can move a ref.

| `[remote.options]` | meaning (default) |
|--------------------|-------------------|
| `git-binary` | which `git` to run (`git` on `PATH`) |
| `work-dir` | where the local mirror lives (`~/.cache/gitiup/host`) |
| `ref-cache-ttl` | how long an advertisement is trusted (`2s`) |
| `cas-attempts` | retries when another writer wins a record append (`6`) |
| `cas-backoff`, `cas-backoff-cap` | first pause before that retry, and its ceiling (`10ms`, `500ms`) |
| `push-probe` | `on`/`off`: the `--dry-run` before the real push (`on`) |
| `read-only` | refuse writes up front, for a dumb-HTTP or anonymous-fetch endpoint (`false`) |
| `ssh-command`, `key-path` | `GIT_SSH_COMMAND`, and a key for git to use |
| `pack-threads` | `-c pack.threads`, for cold mirrors of big repositories |
| `git-config.<key>` | passed as `git -c <key>=<value>` to every call |

An option none of these reads is not ignored: it comes back as config advice
("the plain-git host does not read `region`"), because a silently unused setting
is how a CI job ends up pushing somewhere nobody meant.

What this host cannot do is server-side policy: it cannot tell you a branch is
protected until the push is refused, cannot revoke a key, and cannot make a
reviewer's `+1` mean anything. Those stay owner-side, which is the same answer the
bucket host gives.

## The github adapter (`github`, feature `hosts-github`)

Everything that is *GitHub* — the REST API, token auth, pagination, rate limits,
the pull request database, check runs — lives in
[`crates/gitiup-host-github`](../crates/gitiup-host-github/src/lib.rs), a separate
crate that implements `Host`/`RefStore`/`BlobStore` and that the core does not know
exists. `gitiup-host` still compiles with zero forge imports (its own
`tests/no_forge_deps.rs` enforces it), and `gitiup` reaches the adapter only through
the traits, from one place: `src/remotes.rs`, the composition root, which is also
where a forge remote is refused when the adapter is not compiled in.

The feature is `hosts-github`, on by default:

```text
cargo build                          has the adapter
cargo build --no-default-features    no forge code in the binary at all
```

With the feature off a `https://github.com/owner/repo` remote is not silently
downgraded to the plain-git host — the plain-git host can read its refs, and that
would let a submit "succeed" against a remote whose change database it cannot read.
It is refused by name, with the flag to turn on in the message, and
`gitiup doctor --remotes` prints that refusal instead of pretending.

**What a forge has is translated, not leaked.** The two traits are the whole
vocabulary, so a forge's own nouns have to become gitiup's:

| the forge's thing | becomes | and the translation is honest about |
|-------------------|---------|-------------------------------------|
| the pull request database | `ChangeRecord`, like a bucket's `refs/changes/**` | `origin: Pull { number }`, plus base/head as `RefName`/`Oid`, never a `base.ref` string |
| a change gitiup wrote | the same `ChangeRecord`, `origin: Ref { name }` | a pull and a ref over the same commit are one change, listed once |
| check runs, CI status | `AttestationRecord`, like `refs/attestations/<subject>/<digest>` anywhere else | `source: Store | CheckRun | Both` and `copy_truncated`: a check run's copy is an advertisement, not the bytes a signature covers |
| webhooks, `github.event.*` | `poll_changes(cursor)` | "what is new" is one conditional read of existing state; a workflow's event context comes from the runner that started it, not from a delivery |
| opening a change | the ref first, then the pull request | the ref is the part the contributor owns; the forge's merge is used rather than imitated |

**Inside the repository, gitiup stores the same thing it stores anywhere else**:
`refs/gitiup/kv` as an append-only chain of pointer commits whose trees hold one
file per record (a git ref cannot name a SHA-256 record, so the ref names a commit
that carries `gitiup-ref.json` and the record bytes — same trick as the plain-git
host, same audit trail in the forge's own UI), `refs/changes/**` and
`refs/attestations/**` as usual, and blobs in the object database. `gitiup fetch`
brings the proof with the ref here too.

**Where a forge genuinely promises less, the adapter says so** rather than
emulating a guarantee it does not have. `capabilities()` reports
`cas = true, immutable = true, atomic_multi_write = false`, and `advice()` — printed
by `gitiup doctor --remotes` — states the four caveats a caller needs: a multi-ref
write is applied one ref at a time with best-effort rollback (no ref transaction
exists on the API); a CAS is checked before it is sent and verified after, and a
*rewind* is the one move the forge will not make conditionally, which gitiup refuses
to force silently; a delete is check-then-delete, so a write racing the delete is not
caught; a 404 conflict is reported as a conflict without the forge's "expected value",
because the API does not say what it had.

| `[remote.options]` | meaning (default) |
|--------------------|-------------------|
| `api-base` | the API root, for GitHub Enterprise (`https://github.com/api/v3` off-host, `https://api.github.com` on github.com) |
| `token-env` | which environment variable holds the token (before the profile's `token-env`, before `GITIUP_GITHUB_TOKEN`/`GITHUB_TOKEN`) |
| `accept-host` | `true`: this host really is GitHub although the URL does not say so |
| `host-type` | `github`: the explicit spelling of the same thing |
| `per-page`, `max-pages` | listing page size and the ceiling on pages (`100`, `200`) |
| `rate-reserve`, `rate-wait` | requests to keep back, and the longest wait for a quota reset (`3`, `60s`) |
| `ref-cache-ttl` | how long the ref advertisement is trusted (`2s`) |
| `read-only` | refuse writes up front, for a token that may only read (`false`) |

A token is never put in a URL — it is an `Authorization` header, sent only to the
API host the remote names, and a redacted `Secret` everywhere it might be printed.

Testing: the mock forge in `src/testing.rs` implements the *semantics* of the
endpoints (create-only refusal, fast-forward refusal, `Link` pagination, primary and
secondary rate limits), the shared conformance suite in
[`gitiup-host-tests`](../crates/gitiup-host-tests/README.md) runs against it (plus
recorded HTTP in `tests/fixtures/`), and `tests/live_forge.rs` asks the
real forge — read-only, `#[ignore]`d, and the only thing that can catch a shape the
mock and the code agree on but the forge does not.

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
here: the plain-git host accepts them — it hands them to `git index-pack` and they
become ordinary git objects, so a pack from a clone and a pack from gitiup are the
same thing — and every other host answers `UnsupportedCas` with
`capability = "pack-format:git-packfile"`.

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
5. Register the host with the conformance suite:
   [`gitiup-host-tests`](../crates/gitiup-host-tests/README.md) holds the bodies
   every host owes — empty store, CAS conflict, pack round-trip, huge pack, paged
   listings, ref deletion, refused credentials, unsupported operations, forgetting
   one object, the `cas = false` degradation, the change workflow from proposal to
   merge, and the stale-base refusal that must be the *same kind* on every host — and
   one `test_host!` line runs all of them against your host. Changes are also measured
   *between* hosts: `tests/change_across_hosts.rs` publishes on a bucket and merges
   through a plain-git repository, and CI runs that pair again against a live MinIO and
   a real `git-http-backend`. Anything that genuinely does not apply has to be *said* in the
   registration, and a body neither run nor explained fails `tests/coverage.rs`.
   The host is not finished when it passes on your machine: it is finished when CI
   runs it against the backend you claim to be (`.github/workflows/host-conformance.yml`).
6. Keep the crate forge-free: `cargo test -p gitiup-host --test no_forge_deps`, and
   `cargo test -p gitiup --test no_forge_calls` for the CLI side. An adapter for an
   actual forge is its own crate, reached only through these traits, and it is
   optional in the binary: `hosts-github` is on by default so the ordinary build
   serves a forge, and `--no-default-features` produces one that contains no forge
   code and refuses forge remotes by name. Which host serves which remote is decided
   in exactly one place, `gitiup/src/remotes.rs`.

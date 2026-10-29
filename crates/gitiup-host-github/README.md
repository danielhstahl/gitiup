# gitiup-host-github

The github adapter: every forge call in the workspace, in one crate the core does
not know exists. It implements [`gitiup-host`]'s `Host` + `RefStore` + `BlobStore`
over the GitHub REST API, and the CLI reaches it only through those traits — behind
the `hosts-github` feature, which is on by default and which `--no-default-features`
removes completely.

```text
cargo build                          has the adapter
cargo build --no-default-features    no forge code in the binary at all
```

A `https://github.com/owner/repo` remote in a build without the feature is refused by
name, with the flag to turn on in the message. It is *not* quietly served by the
plain-git host: that host can read the refs, and a `submit` that "worked" against a
remote whose change database it could not read is a worse failure than a refusal.

## The translation

A forge is not a host; a forge is a *translation* onto a host. Nothing outside this
crate sees a `PullRequest`, a `CheckRun`, an `html_url` or an `X-GitHub-Api-Version`
header, and `cargo test -p gitiup --test no_forge_calls` fails the build if one
appears.

| the forge's thing | becomes |
|-------------------|---------|
| the pull request database | `ChangeRecord`, `origin: Pull { number }` — same shape as a bucket's `refs/changes/**` |
| a change gitiup wrote | the same `ChangeRecord`, `origin: Ref { name }`; a pull and a ref over one commit are listed once |
| which database a change came from | `source`: `ref` (a change ref, no pull), `pull` (a pull, no record), `both` — the same three-way answer an attestation's `source` gives, asked of the other forge database |
| the forge's body limit | `copy_truncated: true`, with the cut written into the copy itself: the bytes of record are in the store, so a cut copy loses the discussion and not the proof |
| check runs, CI status | `AttestationRecord`, with `source: Store \| CheckRun \| Both` and `copy_truncated` — a check run's copy is an advertisement, not the bytes a signature covers |
| webhooks, `github.event.*` | `poll_changes(cursor)`: one conditional read of state that already exists, no endpoint to register and no delivery to retry |
| closing / merging | the forge's own merge, used rather than imitated — the one place being on a forge beats a bucket |

## The change verbs, on a forge

`gitiup change new|submit|list|show|merge` run against a github remote unchanged, and the
bucket's answers are the ones they give. What is different is said in fields rather than
glossed over:

| verb | the store does | the forge adds | what is reported when the forge cannot promise it |
|------|----------------|----------------|---------------------------------------------------|
| `submit` | objects, record, attempt ref, `head` — in that order, each under CAS | then `POST /pulls`, which is a **second call** made after the first is already durable | `pull not opened` with the forge's reason, and `source: ref` on the row until a pull exists. A change with refs and no pull is a state this host can be in, not a failed submit |
| `list` | `refs/changes/**`, one row per change | the pull database too, and the two are joined by the commit they name | `source` per row (`ref` · `pull` · `both`), `pull`, `url`, `copy_truncated`, and `caveats[]` naming the limit that applies. A pull with no record is `recorded: false` and is **listed**, because skipping it is how "nothing here" becomes a lie |
| `show` | read the record back through its own ref | annotates it with the pull that carries it; `gh-<n>` shows a pull the store has no record of | the same fields, plus the forge's answer labelled as the forge's answer: "nothing here is signed" |
| `merge` | CAS the branch, then write the merge record | `PUT /pulls/<n>/merge` when a pull carries the change — atomic, reviewed, and not something a ref write should imitate (ADR-0003 D10) | `via: forge` versus `via: store`, and `atomicity` spelling out which promise was made. Two open pulls over one head is refused, not guessed |

The join between the two databases is the commit and nothing else: `origin: Pull { number }`
if the record signed one (a claim the signature covers), otherwise the one open pull whose
head is the change's head. A title match would be a guess dressed up as a join, so it is
not done, and two pulls over one commit is reported as an ambiguity for a person to
resolve.

## What lives in the repository

The same thing every host keeps, so `git fetch` brings the proof with the ref:

| where | what |
|-------|------|
| `refs/gitiup/kv` | an append-only chain of pointer commits; each tree holds `gitiup-ref.json` (the SHA-256 promised, the actor, the time) and the record bytes. A git ref cannot name a SHA-256 record, so it names a commit that carries it — and that commit is the only audit trail a reviewer sees in the forge's own UI |
| `refs/changes/<id>/head` | a change, resolved through its pointer commit back to the digest the caller asked for |
| `refs/attestations/<digest>` | an attestation, keyed by its own digest exactly as on the `fs` and `s3` hosts |
| the object database | blobs and packs, written through the API's blob/tree/commit endpoints |
| a check run per attestation | the advertisement on the commit, marked as a copy, and cut short (and said to be) when it exceeds the forge's output limit |

## What a forge admits it cannot promise

`capabilities()` says `cas = true`, `immutable = true`, `atomic_multi_write = false`,
and `advice()` — printed by `gitiup doctor --remotes` — states the caveats instead of
emulating them away. Every one of them has a field a caller can read, because an
apology in a README is not a report:

| what the forge will not promise | where the caller reads it |
|--------------------------------|---------------------------|
| **no ref transaction.** A multi-ref write is applied one ref at a time with best-effort rollback; `submit` is idempotent, so re-running repairs a half-applied change | `capabilities.atomic_multi_write = false`, and `CAVEAT_TWO_CALLS` on every row of a change the forge carries |
| **CAS is checked before and verified after.** The forge enforces create-only and forward moves conditionally; a *rewind* is the one move it will not do conditionally, and gitiup refuses to force one silently | the last caveat on every change row (`CAVEAT_CAS`), and `advice()` |
| **delete is check-then-delete.** A write racing a delete is not caught. Nothing that gates a merge deletes a ref | `advice()` |
| **the ref and the pull are two calls.** The change is durable before the forge is asked to carry it, so a ref without a pull is reachable and permanent until somebody asks again | `source: ref`, `pull not opened`, and the forge's own refusal verbatim |
| **a refused CAS does not say what the forge expected.** It is reported as a conflict naming the ref, not as a 422 with the server's prose in it | the error the store returns, in `store_says`' words |
| **the forge can hold a change gitiup has no record of** | `source: pull`, `recorded: false`, and an `error` on the row saying what is missing |
| **the forge truncates what it holds** — a body over `MAX_PULL_BODY_CHARS` (65 536 characters), a check run's output over its own ceiling | `copy_truncated: true` on the change and on the attestation, plus a sentence inside the copy itself saying it was cut |
| **a 404 is two different questions.** "No such ref" and "no such repository" are the same answer on the wire, so the first miss of a session asks once | `advice()`, and a typo'd remote reading as a missing repository rather than an empty store |

Rate limits are read off every response and reported: a wait inside `rate-wait` is
taken, a longer one refuses with the reset time in the message, and a spent quota is
never reported as an empty listing.

## Options (`[remote.options]`)

| option | meaning (default) |
|--------|-------------------|
| `api-base` | API root, for GitHub Enterprise (`https://<host>/api/v3`) |
| `token-env` | which variable holds the token, before the profile's `token-env` and before `GITIUP_GITHUB_TOKEN`/`GITHUB_TOKEN` |
| `host-type`, `accept-host` | "this really is GitHub", for a host whose URL does not say so |
| `per-page`, `max-pages` | listing page size and page ceiling (`100`, `200`) |
| `rate-reserve`, `rate-wait` | requests held back, longest wait for a quota reset (`3`, `60s`) |
| `ref-cache-ttl` | how long the ref advertisement is trusted (`2s`) |
| `read-only` | refuse writes up front, for a read-only token (`false`) |

A token is an `Authorization` header sent only to the API host the remote names, never
part of a URL, and a redacted `Secret` wherever it might print. `curl` is the default
transport (feature `curl`); without it the build refuses a forge remote naming the
missing feature, exactly as the absent adapter does.

## Testing

* `src/testing.rs` is a mock forge that implements the *semantics* of the endpoints
  this adapter drives — create-only refusal, fast-forward refusal, `Link`
  pagination, primary and secondary rate limits, a `422` that means "already exists"
  and a `422` that means "your JSON is wrong".
* `tests/conformance.rs` runs the shared suite (`gitiup_host::conformance`) against
  it, plus the forge-specific promises: pointer commits, a rewind needing force, a
  missing repository not reading as a missing ref, the token never in a URL.
* `tests/fixtures/*.jsonl` are recorded HTTP sessions, replayed by the same
  adapter: `tests/fixtures.rs` runs the shared conformance suite against recorded
  answers and fails loudly, naming the call, when the adapter asks for something the
  session never contained. Refresh with
  `GITIUP_RECORDED_SESSIONS=1 cargo test -p gitiup-host-github --test fixtures`.
* `tests/live_forge.rs` asks the real forge — read-only, `#[ignore]`d, and the only
  thing that can catch a shape the mock and the code agree on but the forge does not.

[`gitiup-host`]: ../gitiup-host/README.md

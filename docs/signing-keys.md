# Signing keys and identities

Status: **implemented** (`gitiup key`, `gitiup identity`), for
[giti-1rs.6](../crates/gitiup-keys). The format every signature here is made of is
decided by [ADR-0001](adr/0001-attestation-encoding-hash-and-signature.md);
this document is the part ADR-0001 leaves open — where a private key lives on a real
machine, and how an identity claim says "this key is mine".

A signing key is not a config value. It is the thing that makes an attestation mean
something, so the rules below are mostly about not losing it, not leaking it, and not
mistaking one key for another.

```text
                       ┌──────────────────────────────────────────┐
   gitiup key gen ───► │ keystore: <config>/keys/<name>.secret.age│  age + scrypt
                       └──────────────────────────────────────────┘
   gitiup key import ─┬─ file / seed ──► the same container (re-encrypted)
    ssh-agent         ├─ ssh-agent ────► a public record only; $SSH_AUTH_SOCK signs
    gpg (subkey)      └─ gpg ──────────► a public record only; gpg-agent signs
                                              │
   gitiup identity publish ───────────────────┤ self-signature
   gitiup identity endorse ───────────────────┘ endorsement
                                              ▼
                     <config>/identities/<handle>.identity.json
                     (canonical JSON: what a stranger downloads and checks)
```

## One API, three places a key can live

Everything that signs — an attestation, a change record, a roster, a merge record —
takes `gitiup_attest::Signer`. `gitiup-keys` implements that trait over three
backends, and the signatures they produce are the same bytes for the same key,
because none of them does any signing of its own: each hands the same
`pae(payload_type, body)` to ed25519 and wraps the result in a `SignatureEntry`.

| backend | where the private half is | on disk in the keystore | fails with |
|---------|---------------------------|-------------------------|------------|
| `keystore` | an age container this machine holds | `<name>.json` + `<name>.secret.age` | `6` wrong passphrase, `3` file missing |
| `ssh-agent` | the running `ssh-agent` (or any agent speaking the ssh agent protocol) | `<name>.json` only, naming a socket and a key id | `3` agent unreachable, `6` agent refuses |
| `gpg` | `gpg-agent`, over its **ssh** socket | `<name>.json` only, naming a gpg key spec and its keygrips | `3` gpg-agent not running, `6` key not in `sshcontrol` |

The gpg route is the deliberate one: [ADR-0001 D3](adr/0001-attestation-encoding-hash-and-signature.md)
rejects OpenPGP detached signatures as a format, so gpg is used the way ssh uses it —
gpg-agent offers the key over an ssh-agent socket and the result is an ordinary
`ssh-ed25519` signature. `tests/gpg_agent.rs` runs the whole thing with real `gpg`
and real `gpg-agent` and then verifies the signature with nothing but the public key,
which is the only proof that "gpg is a backend" is true and not just plausible.

An agent-backed record holds no secret, so a passphrase is never asked for: `gitiup
identity whoami` with an agent key is non-interactive by construction.

## What is on disk

```text
<config>/                          GITIUP_CONFIG_HOME, else $XDG_CONFIG_HOME/gitiup,
                                   else $HOME/.config/gitiup
├── config.toml                    0600 — which identity is current, which key signs
├── keys/<name>.json               0600 — the public record (below)
├── keys/<name>.secret.age         0600 — age armour, scrypt KDF; absent for agent keys
└── identities/<handle>.identity.json  0600 — the published claim
```

Directories are `0700`; `gitiup` warns if the config home is world-readable rather
than refusing, because the files themselves are the ones that matter. Names are
slugs (`[a-z0-9._-]`, ≤ 64 bytes) so a key name is safe in a path, a URL and a shell.

The public record is JSON, one object, and it is validated on read — a record whose
`key_id` does not match its `public_key` is refused, because that single edit is how
a file would be rewritten to claim somebody else signed something:

| field | meaning |
|-------|---------|
| `version` | `1` |
| `name` | the slug `--key` and `find` use |
| `key_id` | `SHA256:<unpadded base64>` — derived from `public_key`, re-checked on read |
| `public_key` | the `ssh-ed25519 AAAA…` line, exactly as `ssh-keygen` would print it |
| `backend` | `keystore` \| `ssh-agent` \| `gpg` |
| `created_at_us` | when this machine took the key, microseconds |
| `comment` | the label the user typed (and the ssh key comment on import) |
| `secret` | `{file, format: "age-armor", kdf: "scrypt"}` for a keystore key |
| `agent` | `{socket, comment}` for an ssh-agent key; `socket` may be the literal `$SSH_AUTH_SOCK` |
| `gpg` | `{key_spec, keygrips}` for a gpg key |

A key is **two files**, and every operation treats them as one unit: `--force`
removes the old record *and* its container before writing the new pair (a container
is never overwritten in place — a half-written secret file is the worst thing this
code could produce), and `delete` takes both or neither. An import refuses to add a
key whose `key_id` is already present: two records for one key is what makes `--key
<key-id>` stop meaning one thing.

## The passphrase, and what is never written

The seed is generated with the OS CSPRNG and sealed immediately; there is no code
path that writes it unencrypted, and the audit is a test rather than a promise
(`tests/secret_hygiene.rs` searches every file the crate writes for the seed in raw,
hex, base64 and OpenSSH-concatenated form, and greps the sources for plaintext
writing paths).

Sources are consulted in one order, and a script always has a way in that does not
need a terminal:

1. `--passphrase <text>` — exists, and is documented as visible in `ps`
2. `--passphrase-file <path|->` — first line of a file, or stdin with `-`; the
   documented scripted form
3. `GITIUP_KEY_PASSPHRASE`
4. the terminal, `stty -echo`, prompted twice with agreement required

`age` with scrypt means a long passphrase costs nothing at run time and a short one is
loudly refused (fewer than eight characters is a refusal, not a warning): the
keystore's job is to make a lazy choice safe.

## The identity claim

An identity is a signed statement that a named person controls a key. It is not a
username in a database, and it needs no server: the claim is a file, it is self-signed
by the key it is about, and anyone else's belief in it is a separate signature over
its digest.

```jsonc
{"annotations": {}, "created_at_us": 1793120174421953, "display_name": "Ada",
 "email": "ada@example.com", "endorsements": [ … ], "handle": "ada",
 "key_id": "SHA256:…", "public_key": "ssh-ed25519 AAAA…", "schema_version": 1,
 "signatures": [ … ], "type": "gitiup-identity-1", "url": "https://ada.example"}
```

| rule | why |
|------|-----|
| the signed body is canonical JSON (ADR-0001 D1) with `signatures` and `endorsements` excluded | two implementations must be able to agree byte for byte; `gitiup identity show --canonical` prints exactly those bytes for diffing |
| `key_id` is derived from `public_key`, never taken on trust | the claim has to be about a key, not about a string |
| the payload types are `application/vnd.gitiup.identity+json` and `…endorsement+json` | domain separation: a signature over a claim can never be replayed as one over a change record |
| a claim must carry a self-signature **by the key it names** | "somebody signed this" is not the assertion an identity makes |
| an endorsement signs the *claim body's digest* and repeats `identity_key_id`, `handle` and `endorser_*` | an endorsement must be unusable if moved to another claim, and the bytes it signs have to name what it vouches for |
| every endorsement must verify, or the claim is refused | "we ignored the one that did not work" is how a bored attacker buys reputation |
| retirement is a field (`retired_at_us`), never a deletion | deleting a claim would be an unprovable edit to history |
| limits: 8 self-signatures, 64 endorsements, 256-byte texts | a claim is fetched by strangers; a bounded record is a checkable record |

Verifying is ADR-0001 D7's order — structure, then signatures, then trust — and
*trust is always supplied by the caller* (`gitiup_attest::Trust`). The CLI's local
policy is "every claim on this machine may vouch", which is a laptop's opinion; what a
*change* should trust is the repository's decision, and lives in a policy file
somewhere else.

## Exit codes

Same table as everywhere else in gitiup (ADR-0001 D7), plus the one code signing
adds:

| exit | meaning |
|------|---------|
| 0 | done |
| 2 | usage |
| 3 | I/O, no such key or identity, **or an agent that cannot be reached** |
| 6 | refused: wrong passphrase, name taken, key cannot sign for this identity, a claim that is unsigned or malformed, a policy limit exceeded |
| 7 | a signature does not verify — a tampered claim, a broken endorsement |
| 8 | integrity: a file that did not read back as written |

3 versus 6 matters to scripts: an agent that is not running is an environment
problem, while an agent that says no is an answer.

## Interoperability notes

* **The key id is `ssh-keygen`'s fingerprint.** `SHA256:<unpadded base64 sha256 of the
  ssh wire blob>` — `tests/agent_live.rs` asserts equality with what `ssh-keygen -lf`
  prints, so a bucket policy can be a list of fingerprints copied out of an
  `authorized_keys` file.
* **The agent protocol is the ssh one, on a unix socket, with a timeout.** Requests
  are length-prefixed; `SSH2_AGENTC_REQUEST_IDENTITIES`/`_SIGN_REQUEST` only. An
  agent that counts more identities than it sends is understood rather than rejected:
  gpg-agent 2.4.7 counts every keyring key and then offers only the ssh-usable ones,
  so trusting the count over the bytes breaks a real agent, and an agent that hides a
  key forges nothing — the signature still names the key that signed.
* **Only ed25519.** An rsa/ecdsa agent key is refused by name (6), never silently
  skipped, because "my key does not work here" needs a reason attached.
* **`import file` reads an unencrypted OpenSSH key file.** The parser does not
  implement OpenSSH's `bcrypt-pbkdf` + AES wrapper on purpose: re-implementing a
  second KDF to unwrap a key we are about to re-wrap in age is risk bought for
  convenience. `ssh-keygen -p -m RFC4716` first, or `gitiup key import seed`.
* **`import gpg` writes `sshcontrol`.** gpg-agent signs only keygrips listed there, so
  importing a key that could never sign would be a trap set for later; the import adds
  the keygrips, reloads the agent, and says in its output that it did.

## Scripting contract

Every command has a non-interactive form and a `--json` form; nothing requires a
terminal.

```bash
gitiup key gen --name laptop --comment ada@laptop --passphrase-file - < "$SECRETS/age.pass"
gitiup key import ssh-agent --key ada@laptop
gitiup identity publish ada --email ada@example.com --key laptop --passphrase-file -
gitiup identity endorse grace --key laptop --statement "worked together for two years"
gitiup identity use ada --key laptop
gitiup identity whoami --check --json | jq -e '."check" == "signs and verifies"'
gitiup key probe --json                       # sign-and-verify self-test
gitiup identity import ./ada.identity.json    # someone else's claim, verified on the way in
```

`--json` output is one line, keys sorted, so `| jq` sees a value and not a paragraph.

## Tests that hold this down

| file | what it proves |
|------|----------------|
| `crates/gitiup-keys/tests/secret_hygiene.rs` | **the ticket's third criterion**: a generated seed appears nowhere on disk in raw, hex, base64 or OpenSSH form; containers are age armour; permissions are 0600/0700; no source path can write a plaintext key |
| `crates/gitiup-keys/tests/keystore_lifecycle.rs` | a key is two files: `--force` replaces both or neither, a replaced key stops being findable, an adopted agent record leaves no orphan container, delete takes both, a duplicate key id is refused |
| `crates/gitiup-keys/tests/agent_protocol.rs` | a mock agent (unix socket, real wire format): listing, signing, signatures that verify, and every hostile reply — failure, nonsense, short write, hang-up, a count that overstates the list |
| `crates/gitiup-keys/tests/gpg_agent.rs` | real `gpg` + real `gpg-agent`: auth subkey, `sshcontrol`, signature over the PAE, verified with the public key alone; skips itself where gpg is not installed |
| `crates/gitiup-keys/tests/agent_live.rs` | real `ssh-agent` (when installed): the key id equals `ssh-keygen -lf`'s fingerprint; the `ssh-agent -s` parsing is tested unconditionally |
| `crates/gitiup/tests/keys_cli.rs` | the acceptance criteria as command lines: gen, import (file), publish, endorse, use, whoami, verify, import between two config homes — all driven with stdin and `--json`, no terminal; exit 3 for a missing agent, 6 for a wrong passphrase, 7 for a tampered claim; nothing but an age container on disk |
| `crates/gitiup-keys/src/*.rs` (unit) | canonicalisation of the claim body, key-id derivation, slug rules, `sshcontrol` parsing, the `grp:` record's last-field trap, the passphrase precedence order without touching the environment |

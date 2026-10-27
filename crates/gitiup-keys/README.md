# gitiup-keys

Signing keys and identities: where a private key lives on a real machine, how an
existing ssh or gpg key gets used without being copied, and how a key says whose it
is. The signature bytes themselves are
[`gitiup-attest`](../gitiup-attest/README.md)'s (ADR-0001); this crate is everything
between a user's `ssh-agent` and that `Signer` trait.

The prose is [docs/signing-keys.md](../../docs/signing-keys.md); the command line is
`gitiup key` and `gitiup identity` in [the CLI](../gitiup/README.md).

Three rules hold the crate together:

* **The private key is never written outside the container it was made in.** A
  generated seed goes straight into an age (scrypt) container; there is no code path
  that writes it in the clear, and `tests/secret_hygiene.rs` searches every file the
  crate writes for the seed in raw, hex, base64 and OpenSSH-concatenated form rather
  than trusting that one exists. An imported key that stays in an agent is *not*
  copied at all: the record is public and the agent keeps signing.
* **A key's origin never changes the signature.** keystore, ssh-agent and gpg-agent
  are three implementations of `gitiup_attest::Signer` and nothing more, so an
  attestation, a change record, a roster entry or a merge record takes `&dyn Signer`
  and cannot tell where the key came from. `gpg` is used the way ssh uses it —
  gpg-agent's ssh socket — because ADR-0001 D3 refuses OpenPGP detached signatures as
  a format, and `tests/gpg_agent.rs` proves that claim with real `gpg`.
* **Exit codes are ADR-0001 D7's, unchanged.** `3` unreachable (an agent that is not
  running), `6` refused (wrong passphrase, a name taken, a claim that is unsigned),
  `7` a signature that does not verify, `8` a file that did not read back as written.
  A merge gate must not have to learn a second taxonomy to tell those apart.

## What is where

| module | the decision it implements |
|--------|----------------------------|
| [`keystore`](src/keystore.rs) | the records and the containers: `generate`, `import`, `list`, `find`, `unlock`, `remove`, and the rule that a key is two files replaced or deleted together |
| [`agent`](src/agent.rs) | the ssh agent protocol on a unix socket: identities, signing, timeouts, and the framing failures (`3`) distinguished from an agent that says no (`6`) |
| [`gpg`](src/gpg.rs) | gpg-agent as an ssh agent: `gpgconf` for the socket, `--export-ssh-key` for the public half, keygrips and `sshcontrol` for what the agent will actually sign with |
| [`ssh`](src/ssh.rs) | the ssh wire format and the OpenSSH private-key parser (unencrypted only, and loud about why) |
| [`passphrase`](src/passphrase.rs) | the precedence order — given, file or stdin, `GITIUP_KEY_PASSPHRASE`, terminal — and the refusal to prompt where there is no terminal |
| [`identity`](src/identity.rs) | the claim: canonical body, self-signature, endorsements bound to the claim's digest, retirement, and the limits that keep a claim checkable |
| [`signer`](src/signer.rs) | the seam: a `KeyRecord` plus a passphrase source becomes a `Signer`, whichever backend it names, plus `probe()` — sign something and check it |
| [`paths`](src/paths.rs), [`config`](src/config.rs) | where things live (`GITIUP_CONFIG_HOME`, XDG, `$HOME`), with what permissions, and which identity is current |

## In short

```rust,ignore
let keystore = Keystore::new(Paths::from_env()?);
let record = keystore.generate(&Generate { comment: Some("ada@laptop".into()), ..Default::default() }, &passphrase)?;
let key = signer::open(&keystore, &record.name, &PassphraseSource::new())?;
let claim = IdentityClaim::new(&key, &Profile { handle: "ada".into(), ..Default::default() }, signer::now_us())?;
IdentityStore::new(Paths::from_env()?).publish(&claim, false)?;
```

## Tests

| file | what it proves |
|------|----------------|
| `tests/secret_hygiene.rs` | no plaintext seed anywhere on disk, in four encodings; containers are age armour; 0600/0700 permissions; no source path can write a plaintext key |
| `tests/keystore_lifecycle.rs` | a key is two files: `--force` replaces both or neither, a replaced key stops being findable, an adopted agent record leaves no orphan container, a duplicate key id is refused |
| `tests/agent_protocol.rs` | a mock agent speaking the real wire format, plus every hostile reply: failure, nonsense, short write, hang-up, an identity count that overstates the list |
| `tests/agent_live.rs` | real `ssh-agent`, when installed: the key id equals `ssh-keygen -lf`'s fingerprint |
| `tests/gpg_agent.rs` | real `gpg` + `gpg-agent`: an auth subkey, `sshcontrol`, a signature verified with the public key alone |
| unit tests | canonicalisation, key-id derivation, slug rules, `sshcontrol` and `grp:` parsing, the passphrase order without touching the environment |

```sh
cargo test -p gitiup-keys
```

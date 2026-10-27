//! Signing with a key that never leaves an agent: the SSH agent protocol.
//!
//! ADR-0001 D3 exists for this moment. The format accepts *SSH keys and SSH
//! fingerprints* rather than SSH *signature framing* precisely so that
//! `SSH2_AGENT_SIGN_REQUEST` — which signs arbitrary bytes with raw Ed25519 — is
//! enough: an agent, a hardware token behind an agent, or
//! [gpg-agent's ssh socket](crate::gpg) can produce exactly the signature a gitiup
//! record needs, with no new format and no copy of the private key.
//!
//! The protocol is small enough to own: 4-byte length, one opcode, SSH `string` and
//! `uint32` fields ([`crate::ssh`]). Four opcodes in total are used —
//! request-identities, identities-answer, sign-request, sign-response — plus the
//! failure code. What is *not* attempted: `ADD_IDENTITY` (gitiup has no business
//! loading someone's key into their agent), extensions, or the obsolete SSH1 agent
//! protocol.
//!
//! The reason this is worth a hand-written client instead of a dependency is that
//! the failure modes have to be words a user can act on: "the agent is not running"
//! (exit 3, start it) is a different answer from "the agent refused this key"
//! (exit 6, your key is locked or the agent disallows it), and a dependency that
//! returns `EPERM` for both loses the difference.

use std::path::{Path, PathBuf};
use std::time::Duration;

use gitiup_attest::key::{PublicKey, Signature, Signer};

use crate::error::{Error, Result};
use crate::ssh::{Wire, WireReader};

/// Ask the agent which keys it holds.
pub const REQUEST_IDENTITIES: u8 = 11;
/// The agent's answer: a count and `(blob, comment)` pairs.
pub const IDENTITIES_ANSWER: u8 = 12;
/// Ask the agent to sign bytes with one of them.
pub const SIGN_REQUEST: u8 = 13;
/// The signature, as an SSH signature blob.
pub const SIGN_RESPONSE: u8 = 14;
/// The agent's generic "no".
pub const FAILURE: u8 = 5;
/// A generic yes (not used by the two requests here, checked for anyway).
pub const SUCCESS: u8 = 6;

/// How many identities one agent may claim. A generous cap that is still small
/// enough to bound what a stranger on a socket can make this process buffer.
pub const MAX_AGENT_IDENTITIES: usize = 1024;

/// The environment variable that names a running ssh-agent's socket.
pub const AUTH_SOCK_ENV: &str = "SSH_AUTH_SOCK";

/// How long to wait for an agent that is waiting for a human (a passphrase prompt,
/// a touch-the-token request) before giving up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// Override for [`DEFAULT_TIMEOUT`], in seconds.
pub const TIMEOUT_ENV: &str = "GITIUP_AGENT_TIMEOUT_SECS";

/// A connection to a running agent.
///
/// Cheap to clone and stateless: each request opens its own connection, which is
/// what `ssh-add` does and what makes a long-lived handle (with a socket the agent
/// has since closed) impossible to hold by accident.
#[derive(Debug, Clone)]
pub struct Agent {
    socket: PathBuf,
    /// What to call this thing in an error message: `ssh-agent` or `gpg-agent`.
    kind: &'static str,
    timeout: Duration,
}

impl Agent {
    /// Connect to the agent in `$SSH_AUTH_SOCK`.
    pub fn from_env() -> Result<Agent> {
        let socket = std::env::var_os(AUTH_SOCK_ENV)
            .filter(|value| !value.as_os_str().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                Error::unreachable("ssh-agent", format!("{AUTH_SOCK_ENV} is not set")).with_hint(
                    "start one with `eval \"$(ssh-agent -s)\"` and add a key with `ssh-add`, \
                     or point gitiup at gpg-agent's ssh socket with `gitiup key import --gpg`",
                )
            })?;
        Ok(Agent::ssh(socket))
    }

    /// An ssh-agent at a specific socket.
    pub fn ssh(socket: impl Into<PathBuf>) -> Agent {
        Agent {
            socket: socket.into(),
            kind: "ssh-agent",
            timeout: timeout(),
        }
    }

    /// gpg-agent's ssh socket — the same protocol, a different thing to name in an
    /// error message (see [`crate::gpg`]).
    pub fn gpg_agent(socket: impl Into<PathBuf>) -> Agent {
        Agent {
            socket: socket.into(),
            kind: "gpg-agent",
            timeout: timeout(),
        }
    }

    /// The socket this agent talks to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// What to call this backend in a message.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Override the wait for a slow agent (one that is waiting for a human).
    pub fn with_timeout(mut self, timeout: Duration) -> Agent {
        self.timeout = timeout;
        self
    }

    /// The keys the agent will sign with.
    ///
    /// Blobs are returned as-is, including key types this format cannot use: listing
    /// everything is honest, and [`Identity::public_key`] is where a limitation gets
    /// said out loud.
    pub fn identities(&self) -> Result<Vec<Identity>> {
        let reply = self.request(&[REQUEST_IDENTITIES])?;
        let mut reader = WireReader::new(&reply);
        let code = reader.byte()?;
        if code == FAILURE {
            return Err(Error::refused(
                "ssh-agent",
                "the agent refused to list its keys",
            ));
        }
        if code != IDENTITIES_ANSWER {
            return Err(Error::invalid(
                "ssh-agent",
                format!("expected an identities answer ({IDENTITIES_ANSWER}), got code {code}"),
            ));
        }
        let claimed = reader.u32()? as usize;
        if claimed > MAX_AGENT_IDENTITIES {
            return Err(Error::refused(
                "ssh-agent",
                format!("the agent claims {claimed} keys, which is not credible"),
            ));
        }
        // The list is parsed from the bytes, not from the count, and the two
        // disagreements are handled differently. *More* than claimed is a lie about
        // the message and is refused. *Fewer* is something a real agent does:
        // gpg-agent counts every key in the keyring and then offers only the ones ssh
        // can carry, so insisting on the count would break gpg (verified against
        // 2.4.7, which says 3 and sends 2). An agent that hides a key cannot forge
        // anything — the signature still names who signed — so the useful answer is
        // the keys that are actually there.
        let mut identities = Vec::new();
        while reader.remaining() > 0 {
            if identities.len() >= claimed {
                return Err(Error::invalid(
                    "ssh-agent",
                    "the agent sent more identities than it counted",
                ));
            }
            let blob = reader.string()?.to_vec();
            let comment = String::from_utf8_lossy(reader.string()?).into_owned();
            identities.push(Identity { blob, comment });
        }
        reader.require_end()?;
        Ok(identities)
    }

    /// Find one key by key id, key-id prefix (at least 4 characters of the
    /// fingerprint body) or agent comment.
    ///
    /// Ambiguity is a refusal, never a first match: signing with the wrong key is
    /// how a change gets attributed to the wrong person, and "did gitiup mean my
    /// laptop or my YubiKey" must never be answered by an ordering.
    pub fn find(&self, selector: &str) -> Result<Identity> {
        let identities = self.identities()?;
        let matches: Vec<Identity> = identities
            .into_iter()
            .filter(|identity| identity.matches(selector))
            .collect();
        match matches.len() {
            0 => Err(
                Error::not_found("key in the agent", format!("'{selector}'")).with_hint(format!(
                    "`{} -l` lists what the agent holds",
                    if self.kind == "gpg-agent" {
                        "gpgconf --list-dirs agent-ssh-socket; ssh-add -l"
                    } else {
                        "ssh-add"
                    }
                )),
            ),
            1 => Ok(matches.into_iter().next().expect("one match")),
            n => {
                let names: Vec<String> = matches
                    .iter()
                    .map(|identity| match identity.public_key() {
                        Ok(key) => format!("{} ({})", key.key_id(), identity.comment),
                        Err(_) => format!("<unsupported key> ({})", identity.comment),
                    })
                    .collect();
                Err(Error::refused(
                    "key selection",
                    format!(
                        "'{selector}' matches {n} keys in the agent: {}",
                        names.join(", ")
                    ),
                )
                .with_hint("use a whole key id, or the agent comment, to name one of them"))
            }
        }
    }

    /// Ask the agent to sign `message` with `identity`.
    ///
    /// The agent returns an SSH signature blob (`string "ssh-ed25519" || string
    /// <64 bytes>`); the inner 64 bytes are the raw Ed25519 signature ADR-0001 D3
    /// specifies, so nothing has to be re-encoded, and the algorithm string is
    /// checked rather than assumed.
    pub fn sign(&self, identity: &Identity, message: &[u8]) -> Result<Signature> {
        // Prove the key is one this format can use *before* waking the agent: a
        // request that pops a passphrase prompt for a key we would then reject is a
        // bad user experience and a denial of service on the user's patience.
        identity.public_key()?;
        let mut request = Wire::new();
        request.byte(SIGN_REQUEST);
        request.string(&identity.blob);
        request.string(message);
        request.u32(0); // flags: no RSA-sha2 extensions, and ed25519 needs none
        let reply = self.request(request.finish())?;
        let mut reader = WireReader::new(&reply);
        let code = reader.byte()?;
        if code == FAILURE {
            return Err(Error::refused(
                "ssh-agent",
                format!(
                    "the agent refused to sign with {} ({})",
                    identity
                        .public_key()
                        .map(|key| key.key_id())
                        .unwrap_or_else(|_| "an unusable key".to_string()),
                    identity.comment
                ),
            )
            .with_hint(
                "the key may be locked, or the agent may disallow signing arbitrary bytes; \
                 `ssh-add -D` and re-adding the key is the usual fix for a stuck agent",
            ));
        }
        if code != SIGN_RESPONSE {
            return Err(Error::invalid(
                "ssh-agent",
                format!("expected a sign response ({SIGN_RESPONSE}), got code {code}"),
            ));
        }
        let blob = reader.string()?;
        reader.require_end()?;
        let mut blob = WireReader::new(blob);
        let algorithm = blob.string()?;
        let signature = blob.string()?;
        // The blob names the *SSH key type* (`ssh-ed25519`), which is not the same
        // string as the signature algorithm a record names (`ed25519`) — the first is
        // what an agent speaks, the second is ADR-0001 D3's wire name.
        if algorithm != gitiup_attest::key::SSH_ED25519.as_bytes() {
            return Err(Error::new(
                gitiup_attest::ErrorKind::UnsupportedSchema,
                "ssh-agent",
                format!(
                    "the agent signed with `{}`; this format signs with ed25519 only",
                    String::from_utf8_lossy(algorithm)
                ),
            ));
        }
        let bytes: [u8; 64] = signature.try_into().map_err(|_| {
            Error::invalid(
                "ssh-agent",
                format!("an ed25519 signature is 64 bytes, got {}", signature.len()),
            )
        })?;
        Ok(Signature::from_bytes(&bytes))
    }

    /// One request, one reply, one connection.
    fn request(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.request_transport(payload)
    }

    #[cfg(unix)]
    fn request_transport(&self, payload: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        if !self.socket.exists() {
            return Err(Error::unreachable(
                self.kind,
                format!("{} does not exist", self.socket.display()),
            ));
        }
        let stream = UnixStream::connect(&self.socket).map_err(|error| {
            Error::unreachable(self.kind, format!("{}: {error}", self.socket.display()))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| Error::io("agent socket timeout", error.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| Error::io("agent socket timeout", error.to_string()))?;
        let mut stream = stream;

        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        stream
            .write_all(&frame)
            .map_err(|error| Error::io("write to agent", error.to_string()))?;

        let mut length = [0u8; 4];
        read_exact_or_timeout(&mut stream, &mut length, self.kind)?;
        let length = u32::from_be_bytes(length) as usize;
        // A bounded read: the agent is a stranger on a socket as far as this crate
        // is concerned, and `read_to_end` on a hostile length prefix is an
        // allocation the stranger gets to choose.
        const MAX_REPLY: usize = 1 << 20;
        if length == 0 || length > MAX_REPLY {
            return Err(Error::refused(
                self.kind,
                format!("the agent announced a {length}-byte reply, which is not credible"),
            ));
        }
        let mut reply = vec![0u8; length];
        read_exact_or_timeout(&mut stream, &mut reply, self.kind)?;
        Ok(reply)
    }

    #[cfg(not(unix))]
    fn request_transport(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        Err(Error::refused(
            self.kind,
            "the agent protocol gitiup speaks is a unix socket, and this is not a unix system",
        )
        .with_hint(
            "export the public key and use the keystore instead: \
                    `gpg --export-ssh-key` or `ssh-keygen -y`",
        ))
    }
}

fn read_exact_or_timeout(
    stream: &mut impl std::io::Read,
    buf: &mut [u8],
    kind: &'static str,
) -> Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::unreachable(
                    kind,
                    "the agent closed the connection mid-message",
                ));
            }
            Ok(read) => filled += read,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(Error::unreachable(
                    kind,
                    "the agent did not answer in time (it may be waiting for you)",
                )
                .with_hint(format!(
                    "raise {TIMEOUT_ENV} (seconds) if this agent legitimately takes that long"
                )));
            }
            Err(error) => return Err(Error::io("read from agent", error.to_string())),
        }
    }
    Ok(())
}

fn timeout() -> Duration {
    std::env::var(TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_TIMEOUT)
}

/// One key the agent holds.
#[derive(Debug, Clone)]
pub struct Identity {
    blob: Vec<u8>,
    comment: String,
}

impl Identity {
    /// The SSH public-key blob, exactly as the agent offered it.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The agent's comment (usually `alice@laptop`, often a smartcard serial).
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// The public key, or a refusal if the agent holds a key type this format does
    /// not speak.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_ssh_blob(&self.blob).map_err(|error| match error.kind() {
            gitiup_attest::ErrorKind::UnsupportedSchema => Error::new(
                gitiup_attest::ErrorKind::UnsupportedSchema,
                "key in the agent",
                format!(
                    "{} ({}) is not an ed25519 key",
                    short_blob(&self.blob),
                    self.comment
                ),
            ),
            _ => Error::from(error),
        })
    }

    fn matches(&self, selector: &str) -> bool {
        if selector == self.comment {
            return true;
        }
        match self.public_key() {
            Ok(key) => {
                let key_id = key.key_id();
                if key_id == selector {
                    return true;
                }
                // A fingerprint prefix, long enough not to collide by accident:
                // typing `gitiup identity use SHA256:2HS8` is how people actually
                // refer to a key.
                if let Some(body) = selector.strip_prefix("SHA256:")
                    && body.len() >= 4
                    && let Some(full) = key_id.strip_prefix("SHA256:")
                {
                    return full.starts_with(body);
                }
                false
            }
            Err(_) => false,
        }
    }
}

/// A `Signer` whose private half lives in an agent.
///
/// This is the type the rest of the workspace signs with (`gitiup_attest::Signer`),
/// and it is deliberately indistinguishable from a keystore-backed signer at the
/// call site: an attestation carries no hint about which kind of thing held the key.
#[derive(Debug, Clone)]
pub struct AgentSigner {
    agent: Agent,
    identity: Identity,
}

impl AgentSigner {
    /// Sign with `identity` through `agent`.
    pub fn new(agent: Agent, identity: Identity) -> AgentSigner {
        AgentSigner { agent, identity }
    }

    /// The agent identity being used.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Which agent.
    pub fn agent(&self) -> &Agent {
        &self.agent
    }
}

impl Signer for AgentSigner {
    fn public_key(&self) -> PublicKey {
        // `sign` checks this before contacting the agent; `public_key` is the
        // infallible half of the trait, so an unusable key degrades to zero bytes
        // rather than panicking — and `sign` is where the refusal is actually said.
        self.identity
            .public_key()
            .unwrap_or_else(|_| PublicKey::from_bytes(&[0u8; 32]).expect("32 zero bytes parse"))
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, gitiup_attest::Error> {
        self.agent
            .sign(&self.identity, message)
            .map_err(attest_side)
    }

    fn key_id(&self) -> String {
        self.identity
            .public_key()
            .map(|key| key.key_id())
            .unwrap_or_else(|_| "SHA256:<unsupported key>".to_string())
    }
}

/// Carve an attest-side failure out of this crate's error, because the `Signer`
/// trait speaks the format crate's error type.
fn attest_side(error: Error) -> gitiup_attest::Error {
    match error {
        Error::Attest(inner) => inner,
        other => {
            gitiup_attest::Error::new(gitiup_attest::ErrorKind::Policy, "sign", other.detail())
                .with_hint(
                    other
                        .hint()
                        .unwrap_or("the key is not usable right now")
                        .to_string(),
                )
        }
    }
}

/// `ed25519 …` / `ssh-rsa …` from a blob, for a message that must not assume the
/// blob is parseable.
fn short_blob(blob: &[u8]) -> String {
    if blob.len() < 4 {
        return "<malformed key blob>".to_string();
    }
    let length = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let Some(name) = blob.get(4..4 + length) else {
        return "<malformed key blob>".to_string();
    };
    String::from_utf8_lossy(name).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_attest::key::{SignatureEntry, SigningKey};

    #[test]
    fn short_blob_names_the_key_type_or_says_it_cannot_tell() {
        let key = SigningKey::from_seed(&[4u8; 32]);
        assert_eq!(short_blob(&key.public_key().ssh_blob()), "ssh-ed25519");
        assert_eq!(short_blob(&[]), "<malformed key blob>");
        assert_eq!(short_blob(&[0, 0, 255, 0]), "<malformed key blob>");
    }

    #[test]
    fn a_selector_matches_id_prefix_or_comment() {
        let key = SigningKey::from_seed(&[5u8; 32]);
        let identity = Identity {
            blob: key.public_key().ssh_blob(),
            comment: "ada@laptop".to_string(),
        };
        let key_id = key.public_key().key_id();
        assert!(identity.matches(&key_id));
        assert!(identity.matches("ada@laptop"));
        assert!(identity.matches(&key_id[.."SHA256:".len() + 6]));
        assert!(
            !identity.matches(&key_id[.."SHA256:".len() + 2]),
            "a two-character fingerprint prefix is too short to name a key"
        );
        assert!(!identity.matches("SHA256:nomatch"));
        // A key the format cannot use is still *found* (by comment or fingerprint):
        // the refusal belongs to the moment it would be used, where there is a
        // message to explain it — not to the search.
        let mut rsaish = Wire::new();
        rsaish.string(b"ssh-rsa");
        rsaish.string(b"junk");
        let identity = Identity {
            blob: rsaish.finish().to_vec(),
            comment: "old key".to_string(),
        };
        assert!(identity.matches("old key"));
        assert_eq!(
            identity.public_key().unwrap_err().kind_name(),
            "unsupported_schema"
        );
    }

    #[test]
    fn a_signature_from_the_agent_is_the_formats_signature() {
        // The framing round trip without a socket: sign with a local key, wrap the
        // bytes the way an agent wraps them, and check `SignatureEntry::verify` is
        // happy — i.e. an agent signature and a keystore signature are the same
        // thing, which is the claim ADR-0001 D3 makes.
        let key = SigningKey::from_seed(&[6u8; 32]);
        let message = b"pae bytes";
        let raw = key.sign(message);
        let mut blob = Wire::new();
        blob.string(b"ssh-ed25519");
        blob.string(raw.as_bytes());
        let mut reply = Wire::new();
        reply.string(blob.finish());
        let mut reader = WireReader::new(reply.finish());
        let outer = reader.string().unwrap();
        let mut inner = WireReader::new(outer);
        assert_eq!(inner.string().unwrap(), b"ssh-ed25519");
        let signature = Signature::from_bytes(inner.string().unwrap().try_into().unwrap());
        reader.require_end().unwrap();
        let entry = SignatureEntry::new(&key, message).unwrap();
        assert_eq!(entry.sig, signature.to_base64());
    }

    #[test]
    fn an_absent_agent_is_an_io_answer() {
        // Exit 3, not 6: "start the agent" is an operator action, not a refusal.
        let error = Agent::ssh("/nonexistent/ssh-agent-socket")
            .identities()
            .unwrap_err();
        assert_eq!(error.exit_code(), 3, "{error}");
        assert!(error.to_string().contains("does not exist"));
    }
}

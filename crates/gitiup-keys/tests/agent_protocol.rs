//! The agent protocol, tested against a server that is not an ssh-agent.
//!
//! Why a mock instead of `ssh-agent`: the point of this test is not "does OpenSSH
//! work" (it does), it is *which answer gitiup gives for each way an agent can
//! fail*. A real agent will not, on command, reply with code 99, hold an RSA key,
//! close the connection mid-message, or announce a four-gigabyte reply — and those
//! cases are exactly where the exit codes 3 and 6 are earned or lost. So the agent
//! here is a thread with a unix socket and a five-line brain; the real thing is
//! exercised in `agent_live.rs` and `gpg_agent.rs` when those binaries exist.
//!
//! The check that matters most is in the first test: a signature made through the
//! agent verifies with `SignatureEntry::verify`, using nothing but the public key
//! and the fingerprint — i.e. an agent signature *is* the format's signature, which
//! is the claim ADR-0001 D3 makes and this crate is built on.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use gitiup_attest::key::{SignatureEntry, SigningKey};
use gitiup_keys::Key;
use gitiup_keys::agent::{Agent, AgentSigner};
use gitiup_keys::keystore::{AgentRef, Backend, KeyRecord, RECORD_VERSION};
use gitiup_keys::ssh::{Wire, WireReader};

/// How the mock should behave, so each failure mode has a name at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// List the keys and sign with the one asked for.
    Normal,
    /// Answer a sign request with `SSH_AGENT_FAILURE`.
    RefuseToSign,
    /// Answer with an opcode that is not in the protocol.
    Nonsense,
    /// Accept the connection and close it without answering.
    HangUp,
    /// Announce a reply length that is not credible.
    HugeLength,
    /// Announce a plausible length and then write less.
    ShortWrite,
    /// Count more identities than it sends, the way gpg-agent does when the keyring
    /// holds keys ssh cannot carry.
    OvercountedIdentities,
}

/// One identity the mock holds: a seed (when gitiup can use it), the blob it lists,
/// and the comment it advertises.
type Identity = (Option<[u8; 32]>, Vec<u8>, String);

/// An agent that is a thread.
struct MockAgent {
    socket: PathBuf,
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockAgent {
    fn spawn(dir: &Path, name: &str, identities: Vec<Identity>, behaviour: Behaviour) -> MockAgent {
        // One socket per mock: a test that tries several behaviours needs one agent
        // per behaviour, and they cannot share a name.
        let socket = dir.join(format!("agent-{name}.sock"));
        let listener = UnixListener::bind(&socket).expect("bind the mock agent socket");
        listener
            .set_nonblocking(true)
            .expect("non-blocking mock agent");
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        loop {
                            let mut length = [0u8; 4];
                            if stream.read_exact(&mut length).is_err() {
                                break;
                            }
                            let request_length = u32::from_be_bytes(length) as usize;
                            let mut request = vec![0u8; request_length];
                            if stream.read_exact(&mut request).is_err() {
                                break;
                            }
                            let Some(reply) = answer(&request, &identities, behaviour) else {
                                break;
                            };
                            if reply.is_empty() {
                                // Hang up mid-message: nothing written, connection closed.
                                break;
                            }
                            // The two lying behaviours lie about the framing, and
                            // `HugeLength` is used on the listing while `ShortWrite` is
                            // used on the signature, so each has to know which request it
                            // is answering or the test would only ever exercise the first
                            // one.
                            let is_sign = request.first().is_some_and(|byte| *byte == 13);
                            let framing = match behaviour {
                                Behaviour::HugeLength => vec![0xff, 0xff, 0xff, 0xff],
                                Behaviour::ShortWrite if is_sign => vec![0, 0, 0x01, 0x00],
                                _ => (reply.len() as u32).to_be_bytes().to_vec(),
                            };
                            if stream
                                .write_all(&framing)
                                .and_then(|()| stream.write_all(&reply))
                                .is_err()
                            {
                                break;
                            }
                            if matches!(behaviour, Behaviour::Nonsense | Behaviour::HangUp) {
                                break;
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            }
        });
        MockAgent {
            socket,
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        }
    }

    fn agent(&self) -> Agent {
        Agent::ssh(&self.socket).with_timeout(Duration::from_secs(5))
    }
}

impl Drop for MockAgent {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The mock's whole brain.
fn answer(request: &[u8], identities: &[Identity], behaviour: Behaviour) -> Option<Vec<u8>> {
    let mut reader = WireReader::new(request);
    let opcode = reader.byte().ok()?;
    // SSH2_AGENTC_REQUEST_IDENTITIES
    if opcode == 11 {
        let mut reply = Wire::new();
        reply.byte(12); // SSH_AGENT_IDENTITIES_ANSWER
        reply.u32(if behaviour == Behaviour::OvercountedIdentities {
            identities.len() as u32 + 1
        } else {
            identities.len() as u32
        });
        for (_, blob, comment) in identities {
            reply.string(blob);
            reply.string(comment.as_bytes());
        }
        return Some(reply.finish().to_vec());
    }
    // SSH2_AGENTC_SIGN_REQUEST
    if opcode != 13 {
        let mut reply = Wire::new();
        reply.byte(5); // SSH_AGENT_FAILURE
        return Some(reply.finish().to_vec());
    }
    // A hang-up pretends to be interested, then drops the connection on the way to
    // the signature — the listing still works, because that is what a half-dead agent
    // looks like.
    if behaviour == Behaviour::HangUp {
        return Some(Vec::new());
    }
    if behaviour == Behaviour::Nonsense {
        let mut reply = Wire::new();
        reply.byte(99);
        return Some(reply.finish().to_vec());
    }
    let blob = reader.string().ok()?.to_vec();
    let message = reader.string().ok()?.to_vec();
    reader.u32().ok()?; // flags
    if behaviour == Behaviour::RefuseToSign {
        let mut reply = Wire::new();
        reply.byte(5);
        return Some(reply.finish().to_vec());
    }
    let (seed, _, _) = identities
        .iter()
        .find(|(_, candidate, _)| candidate == &blob)
        .expect("the mock only signs keys it listed");
    let seed = seed.expect("an unsupported key was asked for");
    let signature = SigningKey::from_seed(&seed).sign(&message);
    let mut blob_reply = Wire::new();
    blob_reply.string(b"ssh-ed25519");
    blob_reply.string(signature.as_bytes());
    let mut reply = Wire::new();
    reply.byte(14); // SSH_AGENT_SIGN_RESPONSE
    reply.string(blob_reply.finish());
    Some(reply.finish().to_vec())
}

fn ed25519_identity(seed: [u8; 32], comment: &str) -> Identity {
    let key = SigningKey::from_seed(&seed);
    (Some(seed), key.public_key().ssh_blob(), comment.to_string())
}

fn foreign_identity() -> Identity {
    let mut blob = Wire::new();
    blob.string(b"ssh-rsa");
    blob.string(&[0u8; 64]);
    (None, blob.finish().to_vec(), "old rsa key".to_string())
}

#[test]
fn an_agent_identity_lists_signs_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let seed = [42u8; 32];
    let agent_server = MockAgent::spawn(
        dir.path(),
        "list",
        vec![ed25519_identity(seed, "ada@laptop"), foreign_identity()],
        Behaviour::Normal,
    );
    let agent = agent_server.agent();
    let identities = agent.identities().unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[1].comment(), "old rsa key");
    assert_eq!(
        identities[1].public_key().unwrap_err().kind_name(),
        "unsupported_schema"
    );

    let key = SigningKey::from_seed(&seed);
    let identity = agent.find(&key.public_key().key_id()).unwrap();
    assert_eq!(identity.comment(), "ada@laptop");
    assert_eq!(agent.find("ada@laptop").unwrap().comment(), "ada@laptop");

    // The signature is the format's signature: verified with the public key alone,
    // by code that has no idea an agent was involved.
    let signer = AgentSigner::new(agent.clone(), identity);
    let message = b"pae bytes over a run manifest";
    let entry = SignatureEntry::new(&signer, message).unwrap();
    assert_eq!(entry.key_id, key.public_key().key_id());
    entry.verify(message).unwrap();
    assert!(entry.verify(b"other bytes").is_err());

    // A selector that names nothing is exit 3: there is nothing there to use.
    assert_eq!(agent.find("SHA256:zzzz").unwrap_err().exit_code(), 3);
}

#[test]
fn every_way_an_agent_can_fail_has_its_own_answer() {
    let dir = tempfile::tempdir().unwrap();
    let identities = vec![ed25519_identity([7u8; 32], "ada@laptop")];
    let key = SigningKey::from_seed(&[7u8; 32]);
    let message = b"bytes";

    for (behaviour, expected, why) in [
        (
            Behaviour::RefuseToSign,
            6,
            "the key is there and the answer is no — a refusal",
        ),
        (
            Behaviour::Nonsense,
            6,
            "an opcode outside the protocol is not a signature",
        ),
        (
            Behaviour::HangUp,
            3,
            "a socket that closes is I/O: the operator can restart it",
        ),
        (Behaviour::ShortWrite, 3, "a truncated reply is I/O too"),
    ] {
        let mock = MockAgent::spawn(
            dir.path(),
            &format!("{behaviour:?}"),
            identities.clone(),
            behaviour,
        );
        let agent = mock.agent();
        let identity = match agent.find(&key.public_key().key_id()) {
            Ok(identity) => identity,
            Err(error) => panic!("{behaviour:?}: the listing should work: {error}"),
        };
        let error = agent.sign(&identity, message).unwrap_err();
        assert_eq!(
            error.exit_code(),
            expected,
            "{behaviour:?} ({why}) should be exit {expected}: {error}"
        );
    }

    // A reply length that is not credible is refused, not buffered — checked on the
    // listing, because that is the first thing an agent is asked.
    let huge = MockAgent::spawn(
        dir.path(),
        "huge",
        identities.clone(),
        Behaviour::HugeLength,
    );
    let error = huge.agent().identities().unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(error.to_string().contains("not credible"), "{error}");

    // A socket that is not there at all: 3, and the message says what is missing.
    let missing = Agent::ssh(dir.path().join("nope.sock"));
    let error = missing.identities().unwrap_err();
    assert_eq!(error.exit_code(), 3);
    assert!(error.to_string().contains("does not exist"), "{error}");
}

#[test]
fn a_record_backed_key_probes_through_the_agent() {
    // The `Key` API over an agent-backed record: this is what `gitiup identity
    // whoami --probe` runs and what `identity publish` signs with when the key is an
    // existing ssh key.
    let dir = tempfile::tempdir().unwrap();
    let seed = [55u8; 32];
    let agent_server = MockAgent::spawn(
        dir.path(),
        "record",
        vec![ed25519_identity(seed, "ada@laptop")],
        Behaviour::Normal,
    );
    let public = SigningKey::from_seed(&seed).public_key();
    let record = KeyRecord {
        version: RECORD_VERSION,
        name: "ssh-key".to_string(),
        key_id: public.key_id(),
        public_key: public.to_openssh(),
        backend: Backend::SshAgent,
        created_at_us: 1_793_092_600_000_000,
        comment: Some("ada@laptop".to_string()),
        secret: None,
        agent: Some(AgentRef {
            socket: agent_server.socket.display().to_string(),
            comment: Some("ada@laptop".to_string()),
        }),
        gpg: None,
    };
    record.validate().unwrap();
    let agent = agent_server.agent();
    let identity = agent.find(&record.key_id).unwrap();
    let key = Key::via_agent(record.clone(), AgentSigner::new(agent, identity)).unwrap();
    assert_eq!(key.backend(), Backend::SshAgent);
    assert!(
        key.where_about().contains("ssh-agent"),
        "{:?}",
        key.where_about()
    );
    key.probe().unwrap();

    // A record naming a key the agent does not hold is refused (6): opening it would
    // produce a signer that signs with a *different* key than the record claims.
    let stranger = SigningKey::from_seed(&[9u8; 32]).public_key();
    let other = KeyRecord {
        key_id: stranger.key_id(),
        public_key: stranger.to_openssh(),
        ..record.clone()
    };
    let mismatched = AgentSigner::new(
        agent_server.agent(),
        agent_server.agent().find("ada@laptop").unwrap(),
    );
    assert_eq!(
        Key::via_agent(other, mismatched).unwrap_err().exit_code(),
        6
    );
}

#[test]
fn an_agent_that_counts_more_keys_than_it_sends_is_still_understood() {
    // gpg-agent 2.4.7 counts every key in the keyring and then offers only the ones
    // ssh can carry, so it says 3 and sends 2. A client that trusted the count breaks
    // a real agent; a client that trusts the bytes works, and cannot be fooled by it
    // either, because an agent that hides a key forges nothing — the signature still
    // names the key that signed.
    let dir = tempfile::tempdir().unwrap();
    let seed = [3u8; 32];
    let mock = MockAgent::spawn(
        dir.path(),
        "miscount",
        vec![ed25519_identity(seed, "ada@laptop")],
        Behaviour::OvercountedIdentities,
    );
    let agent = mock.agent();
    let identities = agent.identities().expect("the identities that are there");
    assert_eq!(identities.len(), 1);
    let key = SigningKey::from_seed(&seed);
    assert_eq!(
        agent.find(&key.public_key().key_id()).unwrap().comment(),
        "ada@laptop"
    );
}

#[test]
fn an_unsupported_key_never_wakes_the_agent() {
    // Asking gpg-agent or a hardware token to sign with a key gitiup would then
    // reject means a passphrase prompt or a touch for nothing. The type check comes
    // first, so the mock must see no sign request at all — it is started with the RSA
    // identity and would answer normally if asked.
    let dir = tempfile::tempdir().unwrap();
    let agent_server = MockAgent::spawn(
        dir.path(),
        "rsa",
        vec![foreign_identity()],
        Behaviour::Normal,
    );
    let agent = agent_server.agent();
    let identity = agent.find("old rsa key").unwrap();
    let error = agent.sign(&identity, b"anything").unwrap_err();
    assert_eq!(error.exit_code(), 6, "{error}");
    assert!(
        error.to_string().contains("ssh-rsa"),
        "the message should name the key type: {error}"
    );
}

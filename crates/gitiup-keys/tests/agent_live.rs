//! Signing with a **real** ssh-agent, when one is installed.
//!
//! `agent_protocol.rs` proves the protocol implementation is right; this proves the
//! interop claim in ADR-0001 D3 is true rather than plausible: that a key
//! `ssh-keygen` made, in an agent `ssh-add` loaded, produces a gitiup signature whose
//! key id is byte-identical to what `ssh-keygen -lf` prints. That equivalence is what
//! lets a bucket policy be written as a list of fingerprints copied out of an
//! `authorized_keys` file, so it deserves a test against the tools people actually
//! have.
//!
//! It skips itself when the binaries are missing — the keystore path needs none of
//! them, and a CI image without openssh-clients is a normal thing.

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use gitiup_attest::key::SignatureEntry;
use gitiup_keys::agent::Agent;
use gitiup_keys::keystore::{AgentRef, Backend, KeyRecord, Keystore, RECORD_VERSION};
use gitiup_keys::passphrase::PassphraseSource;
use gitiup_keys::paths::Paths;
use gitiup_keys::signer;

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("-h")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Read one `NAME=value; export NAME;` line out of `ssh-agent -s` output.
fn shell_var(output: &str, name: &str) -> Option<String> {
    let line = output
        .lines()
        .find(|line| line.starts_with(&format!("{name}=")))?;
    let (_, rest) = line.split_once('=')?;
    let value = rest.split(';').next()?;
    (!value.is_empty()).then(|| value.to_string())
}

#[test]
fn ssh_agent_startup_output_is_readable_without_ssh_agent() {
    // The conformance test below skips itself when openssh-clients are missing (they
    // are, in this image), so the part of it that is pure parsing is tested here
    // against the real output format: sh prints `SSH_AUTH_SOCK=/x; export
    // SSH_AUTH_SOCK;`, csh prints `setenv SSH_AUTH_SOCK /x;`.
    let sample = "SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.1234; export SSH_AUTH_SOCK;\n\
                  SSH_AGENT_PID=1235; export SSH_AGENT_PID;\n\
                  echo Agent pid 1235;\n";
    assert_eq!(
        shell_var(sample, "SSH_AUTH_SOCK").as_deref(),
        Some("/tmp/ssh-XXXXXX/agent.1234")
    );
    assert_eq!(shell_var(sample, "SSH_AGENT_PID").as_deref(), Some("1235"));
    assert_eq!(shell_var(sample, "SSHAgentPID"), None);
    assert_eq!(
        shell_var("SSH_AUTH_SOCK=; export SSH_AUTH_SOCK;", "SSH_AUTH_SOCK"),
        None
    );
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn a_key_in_a_real_ssh_agent_signs_and_is_named_by_its_fingerprint() {
    let _serial = lock();
    if !have("ssh-keygen") || !have("ssh-agent") || !have("ssh-add") {
        eprintln!(
            "skipping: openssh-clients are not installed; the agent path is tested with a mock"
        );
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let key_path = dir.path().join("id_ed25519");
    // An unencrypted key: the point is the agent, not the passphrase, and a
    // passphrase here would make the test depend on a terminal.
    run(
        "ssh-keygen",
        &[
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "gitiup-conformance",
            "-f",
            &key_path.display().to_string(),
        ],
    )
    .expect("ssh-keygen");

    let agent_output = run("ssh-agent", &["-s"]).expect("ssh-agent");
    let socket =
        shell_var(&agent_output, "SSH_AUTH_SOCK").expect("ssh-agent -s prints SSH_AUTH_SOCK");
    let pid: i32 = shell_var(&agent_output, "SSH_AGENT_PID")
        .expect("ssh-agent -s prints SSH_AGENT_PID")
        .parse()
        .expect("the agent pid is a number");

    // SAFETY: one test in this binary, the lock is held, and the variable is removed
    // again below; nothing else in this process reads SSH_AUTH_SOCK.
    unsafe { std::env::set_var("SSH_AUTH_SOCK", &socket) };
    let result = (|| -> Result<(), String> {
        run("ssh-add", &[&key_path.display().to_string()])?;

        // What the format claims: gitiup's key id for this key is what `ssh-keygen
        // -lf` prints for it. Not "equivalent", not "the same modulo padding".
        let agent = Agent::from_env().map_err(|e| e.to_string())?;
        let identities = agent.identities().map_err(|e| e.to_string())?;
        let identity = identities
            .iter()
            .find(|candidate| candidate.comment() == "gitiup-conformance")
            .ok_or("the key ssh-add loaded is not in the list")?;
        let public = identity.public_key().map_err(|e| e.to_string())?;
        let printed = run("ssh-keygen", &["-lf", &key_path.display().to_string()])?;
        let printed_id = printed
            .lines()
            .find_map(|line| line.trim().strip_prefix("SHA256:"))
            .map(|rest| rest.split_whitespace().next().unwrap_or(rest))
            .ok_or("`ssh-keygen -lf` printed no SHA256: fingerprint")?
            .to_string();
        assert_eq!(
            format!("SHA256:{printed_id}"),
            public.key_id(),
            "gitiup's key id must be what ssh-keygen prints (ADR-0001 D3)"
        );

        // A signature, and a verification that touches only the public key.
        let message = b"gitiup-pae-over-a-change-record";
        let entry = SignatureEntry::new(
            &gitiup_keys::agent::AgentSigner::new(agent.clone(), identity.clone()),
            message,
        )
        .map_err(|e| e.to_string())?;
        entry.verify(message).map_err(|e| format!("verify: {e}"))?;

        // And the record-backed path a later ticket uses, with no passphrase asked
        // for and no secret file written: the agent is the keystore.
        let store_dir = tempfile::tempdir().expect("config dir");
        let keystore = Keystore::new(Paths::with_root(store_dir.path()));
        let record = KeyRecord {
            version: RECORD_VERSION,
            name: "agent".to_string(),
            key_id: public.key_id(),
            public_key: public.to_openssh(),
            backend: Backend::SshAgent,
            created_at_us: 1_793_092_600_000_000,
            comment: Some("gitiup-conformance".to_string()),
            secret: None,
            agent: Some(AgentRef {
                socket: "$SSH_AUTH_SOCK".to_string(),
                comment: Some("gitiup-conformance".to_string()),
            }),
            gpg: None,
        };
        keystore
            .register(&record, false)
            .map_err(|e| e.to_string())?;
        let key = signer::open(&keystore, "agent", &PassphraseSource::scripted().no_env())
            .map_err(|e| format!("open: {e}"))?;
        key.probe().map_err(|e| format!("probe: {e}"))?;
        assert_no_secret_files(store_dir.path());
        Ok(())
    })();

    // SAFETY: paired with the set above.
    unsafe { std::env::remove_var("SSH_AUTH_SOCK") };
    // Leave no agent behind.
    let _ = Command::new("kill")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .status();
    if let Err(error) = result {
        panic!("the ssh-agent path failed: {error}");
    }
}

fn assert_no_secret_files(dir: &Path) {
    let offenders: Vec<String> = walk(dir)
        .iter()
        .filter(|path| path.to_string_lossy().ends_with(".secret.age"))
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "an agent-backed key must not get a secret container: {offenders:?}"
    );
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    out.push(path);
                }
            }
        }
    }
    out
}

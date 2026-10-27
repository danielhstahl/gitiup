//! The gpg backend, against a real gpg and a real gpg-agent.
//!
//! This is the interop test the design rests on: ADR-0001 refuses OpenPGP detached
//! signatures as a format, and this crate's answer is "then use gpg the way ssh
//! does" — gpg-agent's ssh socket. The only way to know that claim is true rather
//! than plausible is to do the whole thing with the real programs:
//!
//! ```text
//! gpg --quick-generate-key                     (primary)
//! gpg --quick-add-key <fpr> ed25519 auth       (the subkey ssh may use)
//! gpg-agent with enable-ssh-support            (the socket)
//! sshcontrol                                   (which keygrips gpg may offer)
//! ```
//!
//! and then verify the resulting signature with nothing but the public key — which
//! is exactly what a stranger checking an attestation will do, and the moment at
//! which "gpg as a backend" either is or isn't the same format.
//!
//! It skips itself when gpg is not installed (the keystore and ssh-agent paths need
//! nothing of it), and it is the one test that touches the process environment, so it
//! is the only test in this binary and it holds a lock while it does.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use gitiup_attest::Signer as _;
use gitiup_attest::key::SignatureEntry;
use gitiup_keys::gpg;
use gitiup_keys::keystore::{Backend, GpgRef, KeyRecord, Keystore, RECORD_VERSION};
use gitiup_keys::passphrase::PassphraseSource;
use gitiup_keys::paths::Paths;
use gitiup_keys::signer;

/// The environment is process-global, and `set_var` is `unsafe` in edition 2024 for
/// exactly that reason. One test, one lock, and the variable is removed again.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
fn a_gpg_authentication_subkey_signs_a_gitiup_signature() {
    let _serial = lock();
    if !have("gpg") || !have("gpgconf") {
        eprintln!("skipping: gpg/gpgconf are not installed; the gpg backend is optional");
        return;
    }
    let home = tempfile::tempdir().expect("a temp GNUPGHOME");
    let home_path: &Path = home.path();
    #[cfg(unix)]
    std::fs::set_permissions(home_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: the only test in this binary, and it holds the lock while the variable
    // is set; nothing else in this process reads GNUPGHOME.
    unsafe { std::env::set_var("GNUPGHOME", home_path) };
    let result = run_the_test(home_path);
    // SAFETY: paired with the set above.
    unsafe { std::env::remove_var("GNUPGHOME") };
    if let Err(error) = result {
        panic!("the gpg backend failed: {error}");
    }
}

fn run_the_test(home: &Path) -> Result<(), String> {
    // 1. An agent that speaks ssh. `enable-ssh-support` is the whole configuration;
    //    `allow-loopback-pinentry` keeps an empty passphrase from wanting a terminal.
    std::fs::write(
        home.join("gpg-agent.conf"),
        "enable-ssh-support\nallow-loopback-pinentry\n",
    )
    .map_err(|e| format!("gpg-agent.conf: {e}"))?;

    // 2. A key, plus an authentication subkey: gpg-agent will not offer a pure-certify
    //    key over ssh, and pretending otherwise would be a test that passes by
    //        accident when a user's real key does the same.
    let name = "Gitiup Test <gitiup@example.com>";
    run(
        "gpg",
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            name,
            "default",
            "default",
            "never",
        ],
    )?;
    let listing = run("gpg", &["--batch", "--with-colons", "--list-keys"])?;
    // The `fpr:` record after the `pub:` record is the primary fingerprint. Taking
    // "the ninth field of the first line" would grab the trust row instead, which is
    // the kind of thing a colon-separated format teaches you to be careful about.
    let fpr = listing
        .lines()
        .filter(|line| line.starts_with("fpr:"))
        .find_map(|line| line.split(':').nth(9).filter(|value| value.len() >= 40))
        .ok_or("no primary key fingerprint in gpg's own output")?
        .to_string();
    run(
        "gpg",
        &[
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-add-key",
            &fpr,
            "ed25519",
            "auth",
            "never",
        ],
    )?;
    run("gpgconf", &["--launch", "gpg-agent"])?;

    // 3. The subkey, named the way gpg names a subkey for ssh use.
    let spec = format!("{fpr}!");

    // 4. gpg-agent offers only keygrips listed in sshcontrol. `ensure_offered` is what
    //    `gitiup key import --gpg` does about that, and the file is the receipt.
    let added = gpg::ensure_offered(&spec).map_err(|e| format!("ensure_offered: {e}"))?;
    assert!(!added.is_empty(), "the keygrips were already offered?");
    let sshcontrol = std::fs::read_to_string(gpg::sshcontrol_path().map_err(|e| e.to_string())?)
        .map_err(|e| format!("sshcontrol: {e}"))?;
    for grip in &added {
        assert!(
            sshcontrol.contains(grip),
            "{grip} was not written to sshcontrol"
        );
    }

    // 5. The public half, as an ssh key: this is what goes into a gitiup record.
    let (public, comment) = gpg::ssh_public_key(&spec).map_err(|e| format!("export: {e}"))?;
    assert!(public.to_openssh().starts_with("ssh-ed25519 AAAA"));
    assert!(comment.starts_with("openpgp:"), "comment was {comment}");

    // 6. Sign, through the agent, and verify with the public key and nothing else.
    let agent_signer = gpg::signer(&spec).map_err(|e| format!("signer: {e}"))?;
    assert_eq!(agent_signer.key_id(), public.key_id());
    let message = b"gitiup-pae-over-a-run-manifest";
    let entry = SignatureEntry::new(&agent_signer, message).map_err(|e| e.to_string())?;
    entry.verify(message).map_err(|e| format!("verify: {e}"))?;
    assert_eq!(entry.key_id, public.key_id());

    // 7. The same key through a record, which is how a later ticket signs an
    //    attestation with a gpg key: no passphrase is asked for (the agent holds the
    //    key), and `probe` — a real signature, checked — passes.
    let dir = tempfile::tempdir().expect("a temp config dir");
    let keystore = Keystore::new(Paths::with_root(dir.path()));
    let record = KeyRecord {
        version: RECORD_VERSION,
        name: "gpg-key".to_string(),
        key_id: public.key_id(),
        public_key: public.to_openssh(),
        backend: Backend::Gpg,
        created_at_us: 1_793_092_600_000_000,
        comment: Some(spec.clone()),
        secret: None,
        agent: None,
        gpg: Some(GpgRef {
            key_spec: spec.clone(),
            keygrips: added.clone(),
        }),
    };
    keystore
        .register(&record, false)
        .map_err(|e| format!("register: {e}"))?;
    let key = signer::open(
        &keystore,
        "gpg-key",
        // A source with no passphrase available at all: proving the gpg path never
        // reaches for one.
        &PassphraseSource::scripted().no_env(),
    )
    .map_err(|e| format!("open: {e}"))?;
    key.probe().map_err(|e| format!("probe: {e}"))?;
    assert_eq!(key.key_id(), public.key_id());
    assert!(
        key.where_about().contains("gpg-agent"),
        "{:?}",
        key.where_about()
    );
    Ok(())
}

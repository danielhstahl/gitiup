//! The pieces more than one `gitiup` CLI test needs, shared as a module rather than
//! copy-pasted: how to serve a bare repository over smart HTTP, and how to find the
//! binaries that makes possible.
//!
//! This is a module (`mod common;`), not its own test binary: cargo only builds
//! `tests/*.rs` as targets, and everything a test declares lives inside it.
//!
//! The server matters because of a claim no in-process fake can make. An attestation
//! is supposed to travel with the repository — `refs/attestations/**` is a ref like
//! any other, so a stranger with nothing but `git` ends up holding the signed bytes.
//! Proving that needs a real transport: a real `git-http-backend`, a real loopback
//! port, and a client that knows nothing about gitiup.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The CGI smart-HTTP server from `gitiup-host`'s fixtures, on an ephemeral
/// port. This is how a repo gets served without a forge, an sshd or nginx:
/// `git-http-backend` behind any CGI contract, which is exactly the transport the
/// "a `git fetch` carries proof" claim is about.
pub struct SmartHttp {
    child: std::process::Child,
    port: u16,
}

impl SmartHttp {
    /// Serve `root/*/<repo>.git` over smart HTTP, or `None` when python3 or
    /// `git-http-backend` is not on this box (the test then skips).
    pub fn serve(root: &Path) -> Option<SmartHttp> {
        let python = which("python3")?;
        let backend = git_http_backend()?;
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../gitiup-host/tests/fixtures/git-http-backend.py");
        let mut child = Command::new(python)
            .arg(&script)
            .arg("0")
            .env("GIT_HTTP_BACKEND", &backend)
            .env("GIT_PROJECT_ROOT", root)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        // The fixture prints the port it bound before it serves anything.
        use std::io::BufRead as _;
        let announced = std::io::BufReader::new(child.stdout.take()?)
            .lines()
            .next()?
            .ok()?;
        let port: u16 = announced.trim().parse().ok()?;
        for _ in 0..1_000 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(SmartHttp { child, port });
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }

    /// The URL of one repository under the served root.
    pub fn url(&self, repo: &str) -> String {
        format!("http://127.0.0.1:{}/{repo}.git", self.port)
    }
}

impl Drop for SmartHttp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether a program is on `PATH`, without a test failing because it is not.
pub fn which(program: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// `git-http-backend` is not on `PATH`; it lives beside the rest of git.
pub fn git_http_backend() -> Option<PathBuf> {
    let direct = Path::new("/usr/lib/git-core/git-http-backend");
    if direct.is_file() {
        return Some(direct.to_path_buf());
    }
    let out = Command::new("git").arg("--exec-path").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let exec_dir = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let candidate = exec_dir.join("git-http-backend");
    candidate.is_file().then_some(candidate)
}

/// Let anonymous clients receive, which is what a smart-HTTP endpoint gitiup pushes
/// to needs — exactly as it would on a real server.
pub fn allow_anonymous_receives(repo: &Path) {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(["config", "http.receivepack", "true"])
        .output()
        .expect("git config");
    assert!(
        output.status.success(),
        "git config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

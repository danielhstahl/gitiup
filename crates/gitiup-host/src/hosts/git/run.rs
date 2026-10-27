//! Running the `git` binary: one place that decides what a git failure *means*.
//!
//! The plain-git host does its transport work with the git binary rather than a
//! library, so every git fact this crate relies on (a lease refused, a read-only
//! dumb-HTTP endpoint, an unreachable host, a missing object) arrives as an exit
//! code plus stderr. Translating that onto gitiup's error taxonomy is the whole
//! job of this module, and it happens once, here:
//!
//! | git says                                          | [`HostError`] variant |
//! |---------------------------------------------------|-----------------------|
//! | `(stale info)`                                    | `Conflict` (the caller names both sides) |
//! | `git-http-push failed`, `Cannot access URL`       | `UnsupportedCas` — a dumb/static HTTP remote is read-only |
//! | `403`, `401`, `Permission denied (publickey)`, `hook declined` | `PermissionDenied` |
//! | `Could not resolve host`, `Empty reply`, timeouts | `Unreachable` (retryable) |
//! | `does not appear to be a git repository`, `not our ref` | `NotFound` |
//! | anything else                                     | `Storage`, with git's own words attached |

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::error::{HostError, HostResult};
use crate::oid::Oid;

/// Command timeout when the remote does not name one.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// How often a running git process is polled before its deadline.
const POLL: Duration = Duration::from_millis(5);

/// A git version, parsed from `git --version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl GitVersion {
    /// Parse `git version 2.47.3`, tolerating distro suffixes such as
    /// `2.39.5.windows.3`.
    pub fn parse(text: &str) -> Option<GitVersion> {
        let rest = text.trim().strip_prefix("git version")?;
        let mut parts = rest.trim().split(['.', '-']);
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(GitVersion {
            major,
            minor,
            patch,
        })
    }

    /// Whether this git is at least `major.minor`. The host needs
    /// `--force-with-lease` (1.8.5) for CAS and `--atomic` (1.8.4) for
    /// all-or-nothing multi-ref pushes, so the floor is 1.8.
    pub fn supports(self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }
}

impl fmt::Display for GitVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Why a git run counts as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The process exited non-zero.
    Exit,
    /// It never started.
    Spawn,
    /// It outlived its timeout and was killed.
    Timeout,
}

/// A git command that ran and refused.
#[derive(Clone)]
pub struct GitFailure {
    /// The argv that was run (short, and free of secrets).
    pub argv: String,
    /// Exit code, when the process exited.
    pub code: Option<i32>,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr — git writes its diagnostics here.
    pub stderr: Vec<u8>,
    /// Why this is a failure at all.
    pub why: FailureKind,
}

/// A git command that ran and was happy.
#[derive(Clone)]
pub struct GitOutput {
    /// The argv that was run.
    pub argv: String,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr (progress noise, mostly).
    pub stderr: Vec<u8>,
}

impl GitOutput {
    /// stdout as text.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// stdout, trimmed.
    pub fn trimmed(&self) -> String {
        self.stdout_text().trim().to_string()
    }
}

impl GitFailure {
    /// stderr as text.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }

    /// stdout as text.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    fn mentions(&self, needles: &[&str]) -> bool {
        let text = self.stderr_text().to_ascii_lowercase();
        needles.iter().any(|needle| text.contains(needle))
    }

    /// A lease did not hold, or the ref was not in the state the write assumed.
    ///
    /// This is the one failure a CAS caller must tell apart from a transport
    /// problem, so it is asked for explicitly instead of being hidden inside
    /// [`Into<HostError>`](GitFailure) — the ref-write paths need the ref name
    /// and both oids, which only they know.
    ///
    /// There are two shapes, and a CAS caller has to handle both:
    ///
    /// * git noticed locally that the advertisement no longer matches what the
    ///   lease expected: `(stale info)`;
    /// * the advertisement was still true when git checked, and the ref moved in
    ///   the milliseconds after: the *server* refuses, with `cannot lock ref`,
    ///   `reference already exists` (a create-only write that lost the race) or
    ///   `failed to update ref`.
    ///
    /// A refusal that is somebody else's policy — `pre-receive hook declined`, a
    /// protected branch — is deliberately not here: that is a permission answer,
    /// not a lost race, and retrying it is pointless.
    pub fn is_stale_lease(&self) -> bool {
        self.mentions(&[
            "stale info",
            "cannot lock ref",
            "reference already exists",
            "failed to update ref",
        ])
    }

    /// The remote can be read but not written: a static (dumb-HTTP) server, or a
    /// smart-HTTP endpoint that does not offer `git-receive-pack`.
    pub fn is_read_only_transport(&self) -> bool {
        self.mentions(&[
            "git-http-push failed",
            "cannot access url",
            "dumb http",
            "the requested url returned error: 405",
            "the requested url returned error: 501",
        ])
    }

    /// The remote reached us and said no.
    pub fn is_permission_denied(&self) -> bool {
        self.mentions(&[
            "returned error: 403",
            "returned error: 401",
            "authentication failed",
            "permission denied (publickey)",
            "you are not allowed",
            "protected branch",
            "pre-receive hook declined",
            "hook declined",
            "deny current branch",
        ])
    }

    /// Nothing answered, or nothing sensible: worth another try.
    ///
    /// The order inside matters more than the list. git's own wording for "the
    /// transport never started" overlaps its wording for "the repository is not
    /// there" — `ssh: ... Connection refused` ends with *"Could not read from
    /// remote repository"*, and a missing `ssh` binary says *"No such file or
    /// directory"* — so the transport-shaped phrases are matched first and the
    /// catch-all only counts when nothing more specific is present. Getting this
    /// backwards turns a network outage into a `NotFound` that tells the user their
    /// URL is wrong.
    pub fn is_unreachable(&self) -> bool {
        if matches!(self.why, FailureKind::Timeout) {
            return true;
        }
        if self.mentions(&[
            "could not resolve host",
            "connection refused",
            "connection timed out",
            "connection closed",
            "connection reset",
            "empty reply",
            "unable to access",
            "network is unreachable",
            "no route to host",
            "unexpected eof",
            "the remote end hung up unexpectedly",
            "ssh: connect to host",
            "kex_exchange_identification",
            "tls connect error",
            // git could not even start its ssh transport: no client on PATH, or it
            // refused to fork. A box without `ssh` is a common enough CI image.
            "cannot run ssh",
            "unable to fork",
        ]) {
            return true;
        }
        // git's generic "cannot talk to that remote" line, and nothing more
        // specific alongside it.
        self.mentions(&["could not read from remote repository"]) && !self.is_not_found()
    }

    /// The path is not a repository, or the object asked for is not there.
    pub fn is_not_found(&self) -> bool {
        self.mentions(&[
            "does not appear to be a git repository",
            "repository not found",
            "not our ref",
            "couldn't find remote ref",
            "bad object",
            "not a valid object name",
            "needed a single revision",
            "unknown object",
            "unknown revision",
            "does not exist",
            "no such file or directory",
        ])
    }

    /// A compact one-line rendering for error messages.
    pub fn summary(&self) -> String {
        let text = self.stderr_text();
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        match lines.last() {
            Some(last) => format!("{last} (git exited with {})", code_text(self.code)),
            None => format!("git exited with {}", code_text(self.code)),
        }
    }
}

fn code_text(code: Option<i32>) -> String {
    code.map(|c| c.to_string())
        .unwrap_or_else(|| "a signal".to_string())
}

impl fmt::Debug for GitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitFailure")
            .field("argv", &self.argv)
            .field("code", &self.code)
            .field("why", &self.why)
            .field("stderr", &self.summary())
            .finish()
    }
}

impl fmt::Display for GitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`git {}` failed: {}", self.argv, self.summary())
    }
}

impl From<GitFailure> for HostError {
    /// Map a git failure onto the taxonomy. A stale lease maps to `Conflict`
    /// with empty sides here; ref writes re-classify it themselves so they can
    /// name the ref and both oids.
    fn from(failure: GitFailure) -> HostError {
        if failure.is_stale_lease() {
            return HostError::conflict("ref", None::<Oid>, None).with_hint(
                "the ref moved under us: re-read it, rebuild the update and retry \
                     (a CAS write never clobbers a ref it did not read)",
            );
        }
        classify(&failure)
    }
}

/// The mapping that has no ref to name.
fn classify(failure: &GitFailure) -> HostError {
    if failure.is_read_only_transport() {
        return HostError::unsupported(
            "writable",
            format!(
                "this remote answers reads but refuses writes: {}",
                failure.summary()
            ),
        )
        .with_hint(
            "a static (dumb-HTTP) server can only be fetched from; serve the repository with \
             git-http-backend (smart HTTP) or ssh://, or set read-only = \"true\" on the remote \
             so gitiup says this before it tries",
        );
    }
    if failure.is_permission_denied() {
        return HostError::denied(format!("git: {}", failure.summary())).with_hint(
            "check the credentials for this remote: ssh remotes need a key git can find, \
             smart-HTTP needs a user that may push, and git-http-backend needs \
             http.receivepack = true to accept anonymous pushes",
        );
    }
    if failure.is_unreachable() {
        let because = match failure.why {
            FailureKind::Timeout => "it ran past its timeout and was killed; ",
            _ if failure.mentions(&["cannot run ssh", "unable to fork"]) => {
                "git could not start its own ssh transport (is `ssh` on PATH?); "
            }
            _ => "",
        };
        return HostError::unreachable(format!("git: {}", failure.summary())).with_hint(format!(
            "{because}check the URL, the network and the server, then retry (`git {}` said: {})",
            failure.argv,
            failure.summary()
        ));
    }
    if failure.is_not_found() {
        return HostError::not_found(format!("git {}", failure.argv), failure.summary()).with_hint(
            "the remote, or the object asked for, is not there: check the URL, and fetch the \
             objects a ref points at before moving a ref onto them",
        );
    }
    HostError::Storage(Box::new(crate::error::StorageError {
        what: format!("git {}", failure.argv),
        key: String::new(),
        message: failure.summary(),
        retryable: false,
        source: None,
    }))
}

/// A resolved `git` program plus the environment every command runs with.
///
/// Cloning is cheap, so a verification run can drive several repos on threads.
/// Every command runs with `--git-dir` pointed at the host's mirror repository:
/// one object database for plumbing, pushes and fetches, so an object written by
/// `hash-object` is available to the push that needs it.
#[derive(Clone)]
pub struct GitCli {
    program: PathBuf,
    git_dir: PathBuf,
    config: Vec<(String, String)>,
    env: Vec<(String, String)>,
    timeout: Duration,
    version: GitVersion,
}

impl fmt::Debug for GitCli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitCli")
            .field("program", &self.program)
            .field("git_dir", &self.git_dir)
            .field("version", &self.version)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl GitCli {
    /// Find `git`, and refuse a version that cannot do compare-and-swap pushes.
    pub fn discover(program: &str) -> HostResult<GitCli> {
        let out = run_raw(
            Command::new(program).arg("--version"),
            None,
            Some(DEFAULT_COMMAND_TIMEOUT),
        )
        .map_err(|why| {
            HostError::unsupported(
                "git-binary",
                format!("the plain-git host shells out to '{program}' and it did not run ({why})"),
            )
            .with_hint("install git, or point the git-binary option at it")
        })?;
        if !out.status.success() {
            return Err(HostError::unsupported(
                "git-binary",
                format!(
                    "'{program} --version' exited with {}",
                    code_text(out.status.code())
                ),
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let version = GitVersion::parse(&text).ok_or_else(|| {
            HostError::unsupported(
                "git-binary",
                format!(
                    "'{program} --version' said '{text}', which is not a git version gitiup \
                         recognises"
                ),
            )
        })?;
        // Without --force-with-lease there is no CAS, and a host that cannot CAS
        // cannot gate a merge, so this is a hard floor rather than advice.
        if !version.supports(1, 8) {
            return Err(HostError::unsupported(
                "cas",
                format!(
                    "git {version} predates --force-with-lease, so ref updates here could not be \
                     compare-and-swap"
                ),
            )
            .with_hint("the plain-git host needs git 1.8.5 or newer"));
        }
        Ok(GitCli {
            program: PathBuf::from(program),
            git_dir: PathBuf::from("."),
            config: vec![
                // The mirror is plumbing, not a developer's repo: no auto-gc
                // mid-command and no advice strings in captured stderr.
                ("gc.auto".into(), "0".into()),
                ("advice.detachedHead".into(), "false".into()),
                ("commit.gpgSign".into(), "false".into()),
            ],
            env: Vec::new(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
            version,
        })
    }

    /// The version of the binary we found.
    pub fn version(&self) -> GitVersion {
        self.version
    }

    /// The program path.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The repository commands run against.
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    /// A runner aimed at a different repository (the mirror).
    pub fn with_git_dir(&self, git_dir: impl AsRef<Path>) -> GitCli {
        let mut clone = self.clone();
        clone.git_dir = git_dir.as_ref().to_path_buf();
        clone
    }

    /// Add a `-c key=value` config override to every command.
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> GitCli {
        self.config.push((key.into(), value.into()));
        self
    }

    /// Set an environment variable for every command.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> GitCli {
        let key = key.into();
        self.env.retain(|(existing, _)| existing != &key);
        self.env.push((key, value.into()));
        self
    }

    /// Set the command timeout (zero means "keep the current one").
    pub fn with_timeout(mut self, timeout: Duration) -> GitCli {
        if !timeout.is_zero() {
            self.timeout = timeout;
        }
        self
    }

    /// The timeout in force.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    fn build(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.arg("--git-dir").arg(&self.git_dir);
        for (key, value) in &self.config {
            cmd.arg("-c").arg(format!("{key}={value}"));
        }
        cmd.args(args);
        // Never let git reach for a terminal: a CLI that blocks on a password
        // prompt is indistinguishable from a hung remote.
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.env("GIT_REF_PARANOIA", "1");
        cmd.env("GIT_LITERAL_PATHSPECS", "1");
        cmd.env("GIT_ADVICE", "0");
        for (key, value) in &self.env {
            cmd.env(key, value);
        }
        cmd
    }

    /// Run a command; `Err` carries git's own words for the caller to classify.
    pub fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<GitOutput, GitFailure> {
        let argv = describe(args);
        let mut cmd = self.build(args);
        let outcome = run_raw(&mut cmd, stdin, Some(self.timeout));
        match outcome {
            Ok(out) if out.status.success() => Ok(GitOutput {
                argv,
                stdout: out.stdout,
                stderr: out.stderr,
            }),
            Ok(out) => Err(GitFailure {
                argv,
                code: out.status.code(),
                stdout: out.stdout,
                stderr: out.stderr,
                why: FailureKind::Exit,
            }),
            Err(why) => Err(GitFailure {
                argv,
                code: None,
                stdout: Vec::new(),
                stderr: why.clone().into_bytes(),
                why: if why.starts_with("timed out") {
                    FailureKind::Timeout
                } else {
                    FailureKind::Spawn
                },
            }),
        }
    }

    /// Run a command that must succeed; stdout, trimmed, on success.
    pub fn must_run(&self, args: &[&str], stdin: Option<&[u8]>) -> HostResult<String> {
        self.run(args, stdin)
            .map(|out| out.trimmed())
            .map_err(HostError::from)
    }

    /// Whether `oid` names an object in this repository.
    pub fn has_object(&self, oid: &str) -> bool {
        self.run(&["cat-file", "-e", oid], None).is_ok()
    }
}

/// stdout and stderr of a finished process.
struct RawOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run a process with both output pipes drained on their own threads (a chatty
/// git must not deadlock on a full pipe) and killed if it outlives `timeout`.
fn run_raw(
    cmd: &mut Command,
    stdin: Option<&[u8]>,
    timeout: Option<Duration>,
) -> Result<RawOutput, String> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("cannot start git: {e}"))?;

    if let (Some(mut child_stdin), Some(bytes)) = (child.stdin.take(), stdin) {
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = child_stdin.write_all(&bytes);
            let _ = child_stdin.flush();
        });
    }

    let stdout = child.stdout.take().map(drain_pipe);
    let stderr = child.stderr.take().map(drain_pipe);
    let status = wait_with_timeout(&mut child, timeout)?;
    Ok(RawOutput {
        status,
        stdout: stdout
            .map(|join| join.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: stderr
            .map(|join| join.join().unwrap_or_default())
            .unwrap_or_default(),
    })
}

fn drain_pipe(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

fn wait_with_timeout(child: &mut Child, timeout: Option<Duration>) -> Result<ExitStatus, String> {
    let Some(deadline) = timeout.map(|timeout| Instant::now() + timeout) else {
        return child
            .wait()
            .map_err(|e| format!("cannot wait for git: {e}"));
    };
    loop {
        match child
            .try_wait()
            .map_err(|e| format!("cannot wait for git: {e}"))?
        {
            Some(status) => return Ok(status),
            None => {
                let now = Instant::now();
                if now >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let ran_for = deadline.duration_since(now - timeout.unwrap_or(Duration::ZERO));
                    return Err(format!(
                        "timed out after {}ms and was killed",
                        ran_for.as_millis()
                    ));
                }
                std::thread::sleep(POLL);
            }
        }
    }
}

fn describe(args: &[&str]) -> String {
    // Short enough to fit in an error line, complete enough to debug from.
    args.join(" ")
}

/// Create a bare repository at `path` — what `gitiup remote add --create` will
/// do, and what the tests and examples use. `program` comes from
/// [`super::git_program()`] so the caller's `git-binary` option is honoured.
pub fn init_bare_with(program: &str, path: &Path) -> HostResult<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| HostError::from_io("create repository directory", parent, e))?;
    }
    let out = run_raw(
        Command::new(program)
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg(path),
        None,
        Some(DEFAULT_COMMAND_TIMEOUT),
    )
    .map_err(|why| HostError::unsupported("git-binary", format!("cannot run git init: {why}")))?;
    if !out.status.success() {
        return Err(HostError::from_io(
            "init bare repository",
            path,
            std::io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        ));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        let v = GitVersion::parse("git version 2.47.3").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 47, 3));
        assert!(v.supports(1, 8));
        assert!(!v.supports(3, 0));
        assert_eq!(
            GitVersion::parse("git version 2.39.5.windows.3")
                .unwrap()
                .minor,
            39
        );
        assert!(GitVersion::parse("nonsense").is_none());
        assert!(GitVersion::parse("git version 2").is_none());
        assert_eq!(format!("{v}"), "2.47.3");
    }

    fn failure(stderr: &str) -> GitFailure {
        GitFailure {
            argv: "push".into(),
            code: Some(1),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            why: FailureKind::Exit,
        }
    }

    #[test]
    fn a_stale_lease_is_the_failure_a_cas_caller_must_see() {
        let failure = failure("! [rejected] abc123 -> refs/heads/main (stale info)");
        assert!(failure.is_stale_lease());
        let err: HostError = failure.into();
        assert_eq!(err.kind(), crate::HostErrorKind::Conflict);
        assert!(err.is_retryable(), "a conflict is retried, not fatal");
    }

    #[test]
    fn other_git_wordings_map_onto_the_taxonomy() {
        assert!(failure("fatal: git-http-push failed").is_read_only_transport());
        let err: HostError = failure("fatal: git-http-push failed").into();
        assert_eq!(err.kind(), crate::HostErrorKind::UnsupportedCas);
        assert!(err.hint().unwrap().contains("git-http-backend"), "{err}");

        let err: HostError = failure("error: The requested URL returned error: 403").into();
        assert_eq!(err.kind(), crate::HostErrorKind::PermissionDenied);
        let err: HostError = failure("git@h: Permission denied (publickey).").into();
        assert_eq!(err.kind(), crate::HostErrorKind::PermissionDenied);

        let err: HostError =
            failure("fatal: unable to access 'https://h/': Empty reply from server").into();
        assert_eq!(err.kind(), crate::HostErrorKind::Unreachable);
        assert!(err.is_retryable());

        let err: HostError =
            failure("fatal: '/srv/x' does not appear to be a git repository").into();
        assert_eq!(err.kind(), crate::HostErrorKind::NotFound);

        let err: HostError = failure("fatal: some brand new git complaint").into();
        assert_eq!(err.kind(), crate::HostErrorKind::Storage, "{err}");
        assert!(err.to_string().contains("brand new"), "{err}");
    }

    /// Three real situations that share git's generic complaint, told apart.
    #[test]
    fn ssh_trouble_is_not_confused_with_a_missing_repository() {
        // A refused connection: worth retrying, even though git ends with its
        // catch-all "could not read from remote repository".
        let refused = "ssh: connect to host 127.0.0.1 port 22: Connection refused\n\
                       fatal: Could not read from remote repository.\n\
                       \n\
                       Please make sure you have the correct access rights\n\
                       and the repository exists.";
        let err: HostError = failure(refused).into();
        assert_eq!(err.kind(), crate::HostErrorKind::Unreachable, "{err}");

        // No ssh client at all — a slim CI image — is the same answer, and the hint
        // names the missing piece instead of blaming the network.
        let no_ssh = "error: cannot run ssh: No such file or directory\nfatal: unable to fork";
        let err: HostError = failure(no_ssh).into();
        assert_eq!(err.kind(), crate::HostErrorKind::Unreachable, "{err}");
        assert!(err.hint().is_some_and(|h| h.contains("PATH")), "{err}");

        // And the repository genuinely is not there: the same catch-all line, but
        // with git's specific one beside it, so the answer is NotFound rather than
        // "your network is down" — which is why the catch-all is checked last.
        let missing = "fatal: '/srv/git/nope.git' does not appear to be a git repository\n\
                       fatal: Could not read from remote repository.";
        let err: HostError = failure(missing).into();
        assert_eq!(err.kind(), crate::HostErrorKind::NotFound, "{err}");

        // A branch the server protects is a refusal, not a lost race: retrying it
        // changes nothing.
        let err: HostError = failure("remote rejected: refs/heads/main (protected branch)").into();
        assert_eq!(err.kind(), crate::HostErrorKind::PermissionDenied, "{err}");
        assert!(!err.is_retryable(), "{err}");
    }

    #[test]
    fn the_timeout_is_reported_as_transient() {
        let failure = GitFailure {
            argv: "fetch".into(),
            code: None,
            stdout: Vec::new(),
            stderr: b"timed out after 50ms and was killed".to_vec(),
            why: FailureKind::Timeout,
        };
        assert!(failure.is_unreachable());
        let err: HostError = failure.into();
        assert_eq!(err.kind(), crate::HostErrorKind::Unreachable);
    }

    #[test]
    fn the_local_git_binary_is_drivable() {
        let Some(program) = super::super::git_program() else {
            eprintln!("skipped: no git binary on this box");
            return;
        };
        let cli = GitCli::discover(&program).expect("git --version");
        assert!(cli.version().supports(1, 8));
        let dir = std::env::temp_dir().join(format!("gitiup-gitcli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let repo = init_bare_with(&program, &dir).expect("init bare");
        let cli = cli.with_git_dir(&repo);
        assert_eq!(
            cli.must_run(&["rev-parse", "--is-bare-repository"], None)
                .unwrap(),
            "true"
        );
        assert!(!cli.has_object("0000000000000000000000000000000000000000"));
        // A command that refuses is classified, not swallowed.
        let err = cli
            .must_run(&["rev-parse", "--verify", "nope-nope"], None)
            .unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::NotFound, "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

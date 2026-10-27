//! Fixtures: the real things the suite measures itself against.
//!
//! A conformance suite that only ever talks to a fake learns what the fake does.
//! So the git hosts here are real bare repositories — one served by
//! `git-http-backend`, one by a static file server, one that only refuses — and
//! the S3 host has a live MinIO path that talks to a real bucket when CI points
//! it at one.
//!
//! Two kinds of helper live here:
//!
//! * **scratch** — throwaway directories and bare repositories, cleaned up when a
//!   body finishes; that is what a [`Session`](crate::Session) guard is for;
//! * **servers** — the git transports. A web server is far too expensive to start
//!   per body, so the smart-HTTP and refusing endpoints are started once per
//!   process and every body gets its own repository inside them; the static
//!   server is cheap enough to start per body, which is what lets a mirrored
//!   repository be torn down with the body that made it.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gitiup_host::{
    BucketError, BucketFacts, BucketInfo, HostError, HostResult, Object, ObjectMeta, PutCond,
};

/// A process-wide counter so concurrent bodies never share a name.
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The next unique suffix.
pub fn next() -> usize {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// A short token unique to this process.
///
/// A counter alone is unique within a run, which is not enough for a store that
/// outlives the run: a developer's MinIO keeps its objects, and a second run that
/// numbered its prefixes from zero would be measuring the first run's leftovers
/// and calling the result a conflict.
pub fn token() -> &'static str {
    static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or(0);
        format!("{:x}{:x}", std::process::id(), nanos)
    })
}

// ---------------------------------------------------------------------------
// Scratch space.
// ---------------------------------------------------------------------------

/// A throwaway directory, removed when the guard drops.
pub struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    /// Make one under the system temp directory, tagged so a leftover is
    /// attributable.
    pub fn new(tag: &str) -> Scratch {
        let dir = tempfile::Builder::new()
            .prefix(&format!(
                "gitiup-host-tests-{tag}-{}-{}",
                std::process::id(),
                next()
            ))
            .tempdir()
            .expect("scratch dir");
        Scratch { dir }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A path inside it.
    pub fn join(&self, tail: &str) -> PathBuf {
        self.dir.path().join(tail)
    }
}

/// A bare repository git can serve, configured the way a stranger's client needs.
pub struct BareRepo {
    /// The repository directory.
    pub path: PathBuf,
}

impl BareRepo {
    /// `git init --bare`, plus what an anonymous HTTP client needs to be allowed
    /// to fetch and push: `http.receivepack`, and an export marker.
    pub fn create(root: &Path, name: &str) -> HostResult<BareRepo> {
        let path = root.join(format!("{name}.git"));
        gitiup_host::hosts::git::init_bare(&path).map_err(|err| {
            HostError::invalid("bare repository", format!("{}: {err}", path.display()))
        })?;
        git_config(&path, "http.receivepack", "true")?;
        let _ = std::fs::write(path.join("git-daemon-export-ok"), b"");
        Ok(BareRepo { path })
    }

    /// Publish the refs for a dumb (static-file) server. Without this a static
    /// server has nothing to answer `git fetch` with.
    pub fn publish_for_static_server(&self) -> HostResult<()> {
        run_git(&self.path, &["update-server-info"]).map(|_| ())
    }
}

fn git_config(repo: &Path, key: &str, value: &str) -> HostResult<()> {
    run_git(repo, &["config", key, value]).map(|_| ())
}

fn run_git(repo: &Path, args: &[&str]) -> HostResult<String> {
    let program = gitiup_host::hosts::git::git_program()
        .ok_or_else(|| HostError::invalid("git", "no git binary on this box"))?;
    let output = Command::new(program)
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|err| {
            HostError::invalid(
                "git",
                format!("`git {}` could not run: {err}", args.join(" ")),
            )
        })?;
    if !output.status.success() {
        return Err(HostError::invalid(
            "git",
            format!(
                "`git {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ---------------------------------------------------------------------------
// The git servers.
// ---------------------------------------------------------------------------

/// A python fixture server: a child process that prints the port it bound.
pub struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn spawn(script: &str, args: &[&str], env: &[(&str, &Path)]) -> Option<Server> {
        let python = which("python3")?;
        let path = git_fixture_dir()?.join(script);
        let mut command = Command::new(python);
        command
            .arg(&path)
            .args(args)
            .envs(env.iter().copied::<(&str, &Path)>())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        let announced = BufReader::new(child.stdout.take()?).lines().next()?.ok()?;
        let port: u16 = announced.trim().parse().ok()?;
        wait_until_listening(port).then_some(Server { child, port })
    }

    /// Smart HTTP: `git-http-backend` behind a CGI contract, rooted at `root`.
    fn smart(root: &Path) -> Option<Server> {
        let backend = git_http_backend()?;
        Server::spawn(
            "git-http-backend.py",
            &["0"],
            &[
                ("GIT_HTTP_BACKEND", backend.as_path()),
                ("GIT_PROJECT_ROOT", root),
            ],
        )
    }

    /// Dumb HTTP: any static file server will do — that is the point.
    pub fn static_files(root: &Path) -> Option<Server> {
        Server::spawn(
            "git-static.py",
            &[root.to_str()?, "0"],
            &[("PYTHONUNBUFFERED", Path::new("1"))],
        )
    }

    /// A server that refuses every request: an expired credential, seen from the
    /// client's side.
    fn refusing() -> Option<Server> {
        Server::spawn("git-refused.py", &["0"], &[])
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn which(program: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {program}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!path.is_empty()).then_some(PathBuf::from(path))
}

fn git_http_backend() -> Option<PathBuf> {
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

fn wait_until_listening(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Where the shared git fixture servers live.
///
/// These are the same python fixtures `gitiup-host`'s own HTTP tests use, and
/// there is deliberately one copy of them: two implementations of "serve git over
/// HTTP" would drift, and then the suite would be measuring its own fixtures.
pub fn git_fixture_dir() -> Option<PathBuf> {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = here
        .parent()?
        .join("gitiup-host")
        .join("tests")
        .join("fixtures");
    candidate.is_dir().then_some(candidate)
}

/// Why the smart-HTTP host cannot run here, in one string shared with the
/// registration that needs it.
pub const NO_SMART_HTTP: &str = "no smart-HTTP git endpoint: set \
GITIUP_CONFORMANCE_GIT_HTTP_URL and GITIUP_CONFORMANCE_GIT_ROOT to point at one, or make \
python3 and git-http-backend available so the suite can start its own";

/// The smart-HTTP endpoint the plain-git host talks to.
pub enum GitServer {
    /// Supplied by the environment: CI's own web server, which is the honest
    /// thing to test against.
    External {
        /// The base URL, without a trailing slash.
        base: String,
        /// The directory it serves, on this machine.
        root: PathBuf,
    },
    /// Started here with the python CGI fixture, kept alive for the process.
    Own {
        /// The server.
        server: Server,
        /// The directory it serves.
        root: PathBuf,
    },
}

impl GitServer {
    /// Where bodies create the repositories they serve.
    pub fn root(&self) -> PathBuf {
        match self {
            GitServer::External { root, .. } => root.clone(),
            GitServer::Own { root, .. } => root.clone(),
        }
    }

    /// The URL base repositories are served at.
    pub fn base(&self) -> String {
        match self {
            GitServer::External { base, .. } => base.trim_end_matches('/').to_string(),
            GitServer::Own { server, .. } => server.base(),
        }
    }

    /// Whether a smart-HTTP endpoint can be had here at all.
    pub fn available() -> bool {
        if std::env::var("GITIUP_CONFORMANCE_GIT_HTTP_URL").is_ok() {
            return std::env::var_os("GITIUP_CONFORMANCE_GIT_ROOT").is_some();
        }
        which("python3").is_some() && git_http_backend().is_some() && git_fixture_dir().is_some()
    }

    /// What to print when it cannot.
    pub fn why_unavailable() -> &'static str {
        NO_SMART_HTTP
    }
}

/// The process-wide smart-HTTP endpoint, started on first use.
pub fn served_git_server() -> Option<&'static GitServer> {
    static SERVER: OnceLock<Option<GitServer>> = OnceLock::new();
    SERVER
        .get_or_init(|| {
            if let (Ok(base), Some(root)) = (
                std::env::var("GITIUP_CONFORMANCE_GIT_HTTP_URL"),
                std::env::var_os("GITIUP_CONFORMANCE_GIT_ROOT").map(PathBuf::from),
            ) {
                let root = if root.is_absolute() {
                    root
                } else {
                    std::env::current_dir().ok()?.join(root)
                };
                std::fs::create_dir_all(&root).ok()?;
                let base = base.trim_end_matches('/').to_string();
                // Prove it is actually there before claiming it is.
                let host_port = base.split("//").nth(1)?.trim_matches('/');
                let authority: Vec<&str> = host_port.splitn(2, ':').collect();
                let port: u16 = authority
                    .get(1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(80);
                return TcpStream::connect((authority[0], port))
                    .is_ok()
                    .then_some(GitServer::External { base, root });
            }
            let root = std::env::temp_dir()
                .join(format!("gitiup-host-tests-served-{}", std::process::id()));
            std::fs::create_dir_all(&root).ok()?;
            let server = Server::smart(&root)?;
            Some(GitServer::Own { server, root })
        })
        .as_ref()
}

/// The process-wide endpoint that refuses everything.
pub fn refused_server() -> Option<&'static Server> {
    static SERVER: OnceLock<Option<Server>> = OnceLock::new();
    SERVER.get_or_init(Server::refusing).as_ref()
}

/// A static file server for one directory: cheap enough to own per body, so a
/// mirrored repository can be deleted along with the body that made it.
pub fn static_server(root: &Path) -> Option<Server> {
    Server::static_files(root)
}

// ---------------------------------------------------------------------------
// The bucket seam a live endpoint cannot produce on demand.
// ---------------------------------------------------------------------------

/// A bucket that answers every call the way a bucket answers a request signed
/// with a revoked key: `403`, and nothing else.
///
/// The point of the denial body is the *host's* mapping — a 403 has to come back
/// as `PermissionDenied` from every entry point, not as an empty listing — and a
/// live bucket cannot be asked to revoke its own credentials mid-run, so this is
/// where that mapping is checked hermetically. The live check, with genuinely
/// refused credentials, runs as its own CI step.
#[derive(Debug, Clone, Default)]
pub struct DeniedBucket {
    /// The bucket name to report, so `describe()` looks like the store it stands
    /// in for.
    pub bucket: String,
}

impl DeniedBucket {
    /// A denying bucket with a realistic name.
    pub fn named(bucket: &str) -> DeniedBucket {
        DeniedBucket {
            bucket: bucket.to_string(),
        }
    }

    fn denied(&self, key: &str) -> BucketError {
        BucketError::Denied {
            key: key.to_string(),
            message: "AccessDenied: the access key id you provided does not exist in our \
                      records"
                .to_string(),
        }
    }
}

impl gitiup_host::Bucket for DeniedBucket {
    fn info(&self) -> BucketInfo {
        BucketInfo {
            bucket: self.bucket.clone(),
            endpoint: "in-memory".to_string(),
            region: "memory-1".to_string(),
            credentials: "none (in-process)".to_string(),
        }
    }

    fn facts(&self) -> Result<BucketFacts, BucketError> {
        Err(self.denied("the bucket"))
    }

    fn get(&self, key: &str) -> Result<Option<Object>, BucketError> {
        Err(self.denied(key))
    }

    fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BucketError> {
        Err(self.denied(key))
    }

    fn put(&self, key: &str, _bytes: &[u8], _cond: PutCond) -> Result<ObjectMeta, BucketError> {
        Err(self.denied(key))
    }

    fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, BucketError> {
        Err(self.denied(prefix))
    }
}

/// An `Arc` bucket handle from any concrete bucket.
pub fn shared<B: gitiup_host::Bucket + Clone + 'static>(bucket: &B) -> gitiup_host::SharedBucket {
    std::sync::Arc::new(bucket.clone())
}

/// A bucket whose endpoint does not do conditional writes: the old gateway, the
/// case that must degrade rather than pretend.
pub fn dumb_bucket(name: &str) -> gitiup_host::MemoryBucket {
    gitiup_host::MemoryBucket::without_conditional_writes(name)
}

/// A bucket with small LIST pages, so the pagination body paginates even with no
/// network available.
pub fn paged_bucket(name: &str, page_size: usize) -> gitiup_host::MemoryBucket {
    gitiup_host::MemoryBucket::new(
        gitiup_host::MemoryBucketConfig::default()
            .with_bucket(name)
            .with_page_size(page_size),
    )
}

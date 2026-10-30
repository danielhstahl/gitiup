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
    BucketError, BucketFacts, BucketInfo, HostError, HostResult, MemoryBucket, Object, ObjectMeta,
    PutCond,
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

// ---------------------------------------------------------------------------
// The redirect origin and its decoy (giti-g5c.5).
// ---------------------------------------------------------------------------

/// The redirect/redirect-target pair, started once per process.
///
/// One fixture, two ports: an origin that answers every request with a `302` at the
/// decoy, and the decoy itself, which records what arrived and refuses. The pair is
/// process-wide for the same reason the smart-HTTP server is — starting a web server is
/// far too expensive to do per body — and a body keeps its own space by putting a unique
/// path under the origin and asking the decoy only about arrivals at that path.
pub struct DecoyPair {
    origin: String,
    decoy: String,
    child: Child,
}

impl Drop for DecoyPair {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One request the decoy pair saw.
///
/// Four fields, all of them always present (the fixture prints `-` for an absent
/// credential), because the assertion a body makes on this is "no arrival under my path
/// carried a credential", and a parse that could silently drop a field would make that
/// assertion pass by accident.
#[derive(Debug, Clone)]
pub struct Arrival {
    /// `GET`, `POST`, \.
    pub method: String,
    /// Which of the pair was asked: `origin` or `decoy`.
    pub origin: String,
    /// The path it was asked for.
    pub path: String,
    /// The credential header it arrived with, or `-`.
    pub credential: String,
}

impl std::fmt::Display for Arrival {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.method, self.origin, self.path, self.credential
        )
    }
}

impl DecoyPair {
    /// The origin a credential is configured for, and which redirects to the decoy.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The decoy origin: the host that must never see a token.
    pub fn decoy(&self) -> &str {
        &self.decoy
    }

    /// The arrivals whose path or credential headers mention `needle`, parsed.
    ///
    /// `None` when the endpoint could not be asked at all — which is a broken fixture, and
    /// the caller must treat it as one rather than as an empty list.
    pub fn arrivals(&self, needle: &str) -> Option<Vec<Arrival>> {
        Some(
            self.find(needle)?
                .iter()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    Some(Arrival {
                        method: fields.next()?.to_string(),
                        origin: fields.next()?.to_string(),
                        path: fields.next()?.to_string(),
                        credential: fields.next()?.to_string(),
                    })
                })
                .collect(),
        )
    }

    /// The arrival lines whose path or credential headers mention `needle`.
    pub fn find(&self, needle: &str) -> Option<Vec<String>> {
        let body = http_get(&format!(
            "{}/__gitiup_arrivals__?find={}",
            self.decoy, needle
        ))?;
        Some(
            body.lines()
                .map(str::to_string)
                .filter(|line| !line.trim().is_empty())
                .collect(),
        )
    }

    /// Whether the decoy recorded its own control credential.
    ///
    /// This is asserted before anything else: "no token arrived" is only a fact about a
    /// decoy that demonstrably records one.
    pub fn control_seen(&self) -> bool {
        self.find("gitiup-control")
            .is_some_and(|lines| !lines.is_empty())
    }

    /// A path under the origin, for a body that wants its own namespace.
    pub fn url_under(&self, path: &str) -> String {
        format!("{}/{}", self.origin, path.trim_start_matches('/'))
    }
}

/// The pair, started on first use.
pub fn decoy_pair() -> Option<&'static DecoyPair> {
    static PAIR: OnceLock<Option<DecoyPair>> = OnceLock::new();
    PAIR.get_or_init(|| {
        let python = which("python3")?;
        let script = git_fixture_dir()?.join("git-decoy.py");
        let mut command = Command::new(python);
        command
            .arg(&script)
            .arg("0")
            .arg("0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        let announced = BufReader::new(child.stdout.take()?).lines().next()?.ok()?;
        let mut ports = announced.split_whitespace();
        let origin_port: u16 = ports.next()?.parse().ok()?;
        let decoy_port: u16 = ports.next()?.parse().ok()?;
        if !(wait_until_listening(origin_port) && wait_until_listening(decoy_port)) {
            return None;
        }
        Some(DecoyPair {
            origin: format!("http://127.0.0.1:{origin_port}"),
            decoy: format!("http://127.0.0.1:{decoy_port}"),
            child,
        })
    })
    .as_ref()
}

/// One plain HTTP `GET`, read to the end, with no HTTP library.
///
/// The suite asks a fixture a question and reads the answer; that is the whole use, and
/// linking an HTTP client into the conformance suite to make one request would drag in
/// a TLS stack to talk to `127.0.0.1`.
fn http_get(url: &str) -> Option<String> {
    use std::io::{Read as _, Write as _};
    let (_scheme, rest) = url.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, 80u16),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    let mut stream = TcpStream::connect((host, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).to_string();
    // The body starts after the blank line that ends the headers.
    let (_, body) = text.split_once("\r\n\r\n")?;
    Some(body.to_string())
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

/// A bucket that answers a stranger the way a bucket with a public-read policy does: every
/// object reads, listings work, and every write — and every bucket-admin question the
/// anonymous reader has no business asking — is refused.
///
/// The owner's handle is the inner [`MemoryBucket`], so a registration can seed the store
/// the way an owner would and then hand the *same* bucket to a host that has nothing to
/// authenticate with. That is the whole shape of a public mirror: the bytes are the same
/// bytes, and the difference is who is asking.
#[derive(Debug, Clone)]
pub struct PublicBucket {
    owner: MemoryBucket,
}

impl PublicBucket {
    /// A public-read bucket that starts empty (for the owner to fill).
    pub fn named(name: &str) -> PublicBucket {
        PublicBucket {
            owner: MemoryBucket::forge(name),
        }
    }

    /// The handle the owner writes with — what a credentials-bearing caller has.
    pub fn owner(&self) -> MemoryBucket {
        self.owner.clone()
    }

    fn denied(&self, key: &str) -> BucketError {
        BucketError::Denied {
            key: key.to_string(),
            message: format!(
                "AccessDenied: the request does not have 's3:GetObject' permission on {key} \\n                 (this bucket is public-read)"
            ),
        }
    }
}

impl gitiup_host::Bucket for PublicBucket {
    fn info(&self) -> BucketInfo {
        BucketInfo {
            credentials: "anonymous (public-read bucket policy)".to_string(),
            ..self.owner.info()
        }
    }

    fn facts(&self) -> Result<BucketFacts, BucketError> {
        // The bucket is versioned — that is a fact about it, not about the caller — but a
        // stranger cannot ask, cannot run the conditional-write probe, and cannot write,
        // so the only facts it may rely on are the ones that make it read-only.
        Ok(BucketFacts {
            versioning: gitiup_host::VersioningState::Enabled,
            object_lock: false,
            conditional_writes: false,
        })
    }

    fn get(&self, key: &str) -> Result<Option<Object>, BucketError> {
        self.owner.get(key)
    }

    fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BucketError> {
        self.owner.head(key)
    }

    fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, BucketError> {
        self.owner.list(prefix)
    }

    fn put(&self, key: &str, _bytes: &[u8], _cond: PutCond) -> Result<ObjectMeta, BucketError> {
        Err(self.denied(key))
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

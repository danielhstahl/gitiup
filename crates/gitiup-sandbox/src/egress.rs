//! Egress: default-deny, and the only way out is a proxy that keeps a log.
//!
//! A CI job that can reach the internet can exfiltrate a workspace, a credential file
//! or a signed artifact, and can pull in a dependency nobody pinned. So the default is
//! *no network at all* — not "a network with advice". When a job legitimately needs a
//! package registry, it gets it the same way a build farm does: through a proxy that
//! only speaks for hosts on an allowlist, and that writes down every decision it made
//! ([`Proxy::audit`]).
//!
//! Two honest limits, stated here because the difference matters to a reviewer:
//!
//! * **who enforces.** With [`Egress::deny_all`], enforcement is the kernel's: the
//!   job has no route, or no Landlock right, and cannot do anything about it. With an
//!   allowlist, the enforcement depends on the backend — the in-process backend can
//!   refuse every TCP port except the proxy's, while a container on a bridge network
//!   could in principle ignore `HTTP_PROXY` and dial out directly. That is exactly
//!   what [`Enforcement`](crate::spec::Enforcement) records, and a quorum job is
//!   refused when the answer is only "proxy-enforced and audited".
//! * **the proxy is not a content filter.** It matches hostnames and ports. It cannot
//!   tell a pinned artifact from a floating one (giti-bgy.4), and it does not
//!   terminate TLS, so it sees SNI-less `CONNECT` targets by name only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gitiup_attest::{Error, ErrorKind, Result};

use crate::dns::Resolver;

/// The default registries a volunteer's build is likely to need, and nothing else.
///
/// Deliberately a literal list: it is the answer to "what can a stranger's job
/// reach?" and that answer should be readable, not derived. A wildcard is only ever
/// used where a registry's CDN is inseparable from the registry.
pub const DEFAULT_REGISTRIES: [&str; 17] = [
    // git forges and the artefacts they serve (actions, release assets).
    "github.com",
    "githubusercontent.com",
    "*.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    // language package registries.
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "proxy.golang.org",
    "sum.golang.org",
    "rubygems.org",
    "gcr.io",
    "ghcr.io",
];

/// `IpAddr::is_link_local` is not stable, and `169.254.0.0/16` is exactly the range
/// this check exists for (the cloud metadata service), so it is spelled out.
fn is_link_local(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets()[..2] == [169, 254],
        std::net::IpAddr::V6(_) => false,
    }
}

/// The hostnames a job may reach, as `host` or `*.suffix`.
///
/// Matching is on the name the *job asked for*, not on a resolved address, because a
/// resolved address is what an attacker controls (a DNS name that points at
/// `169.254.169.254` is the classic). The proxy resolves only after the name is
/// allowed, and refuses a name that resolves to a link-local or loopback address
/// unless it was listed as such.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: Vec<String>,
}

impl Allowlist {
    /// Nothing allowed: every job's egress is denied.
    pub fn empty() -> Allowlist {
        Allowlist::default()
    }

    /// The package registries in [`DEFAULT_REGISTRIES`].
    pub fn registries() -> Allowlist {
        let mut list = Allowlist::default();
        for host in DEFAULT_REGISTRIES {
            // The defaults are known-good; a parse failure here is a bug in this file.
            list.push(host).expect("DEFAULT_REGISTRIES is valid");
        }
        list
    }

    /// Add the repository store's own origin, so a job can fetch from the forge it is
    /// being verified against (the "repo store" of the baseline policy).
    pub fn with_repo_store(mut self, origin: &str) -> Allowlist {
        // An origin is a URL (`https://git.example.com/repo`); the store is a host.
        let host = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        let host = host
            .split('/')
            .next()
            .unwrap_or_default()
            .split('@')
            .next_back()
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default();
        if !host.is_empty()
            && let Err(why) = self.push(host)
        {
            // A store on a nonsense host is worth a message, not a silent hole.
            eprintln!("warning: cannot allowlist repo store `{origin}`: {why}");
        }
        self
    }

    /// Parse and add one pattern.
    pub fn push(&mut self, pattern: &str) -> Result<()> {
        let pattern = pattern.trim().to_ascii_lowercase();
        let pattern = pattern
            .strip_prefix("https://")
            .or_else(|| pattern.strip_prefix("http://"))
            .map(str::to_string)
            .unwrap_or(pattern.clone());
        let pattern = pattern.split('/').next().unwrap_or_default().to_string();
        let bare = pattern.strip_prefix("*.").unwrap_or(&pattern).to_string();
        if pattern.is_empty() {
            return Err(
                Error::new(ErrorKind::Invalid, "egress", "an empty egress pattern")
                    .with_hint("write a host (`crates.io`) or a suffix (`*.npmjs.org`)"),
            );
        }
        if bare.is_empty() || bare == "*" {
            return Err(Error::new(
                ErrorKind::Policy,
                "egress",
                format!("`{pattern}` allows the whole internet, which is not an allowlist"),
            )
            .with_hint("name the hosts a job may reach; `*` defeats default-deny egress"));
        }
        if !bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
        {
            return Err(Error::new(
                ErrorKind::Invalid,
                "egress",
                format!("`{pattern}` is not a host, an IP address or a `*.suffix`"),
            )
            .with_hint("egress patterns are hostnames or IP addresses, not URLs or paths"));
        }
        if !self.entries.contains(&pattern) {
            self.entries.push(pattern);
        }
        Ok(())
    }

    /// Parse a comma or whitespace separated list (`GITIUP_EGRESS_ALLOW`).
    pub fn parse_list(text: &str) -> Result<Allowlist> {
        let mut list = Allowlist::empty();
        for item in text.split([',', ' ', '\n', '\t']) {
            if !item.trim().is_empty() {
                list.push(item)?;
            }
        }
        Ok(list)
    }

    /// Whether `host` may be reached.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return false;
        }
        self.entries.iter().any(|entry| {
            if let Some(suffix) = entry.strip_prefix("*.") {
                host == suffix || host.ends_with(&format!(".{suffix}"))
            } else {
                host == *entry
            }
        })
    }

    /// True when nothing is allowed — the default, and the mode every backend
    /// enforces hardest.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a *resolved* address may be dialled for an allowed name.
    ///
    /// This is the half of name matching that keeps `SSRF` out: a job that allows
    /// `example.com` must not get the host's own admin port because a hostile
    /// resolver answers `127.0.0.1`. Loopback and link-local addresses (the cloud
    /// metadata service lives at `169.254.169.254`) are only reachable if the
    /// allowlist names them explicitly.
    pub fn allows_address(&self, address: SocketAddr) -> bool {
        let ip = address.ip();
        if !(ip.is_loopback() || ip.is_unspecified() || is_link_local(ip)) {
            return true;
        }
        // The address has to be on the list in its own right: allowing `example.com`
        // must never become allowing `127.0.0.1:6379` because a hostile resolver
        // answered with it. The name the job asked for is irrelevant at this point —
        // it is already allowed, and it is the answer that is the problem.
        let address_text = ip.to_string();
        self.entries
            .iter()
            .any(|entry| entry == &address_text || (ip.is_loopback() && entry == "localhost"))
    }

    /// The patterns, as written.
    pub fn hosts(&self) -> &[String] {
        &self.entries
    }
}

/// What happened to one connection attempt at the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// When, in Unix seconds. `0` in a test that never had a clock.
    pub at_secs: u64,
    /// The host the job asked for, as asked.
    pub host: String,
    /// The port the job asked for.
    pub port: u16,
    /// `connect` (a `CONNECT`, i.e. usually TLS) or `http` (an absolute-form request).
    pub kind: &'static str,
    /// Whether it was allowed.
    pub allowed: bool,
    /// Bytes copied toward the job, once the connection closed (`0` while open).
    pub bytes_down: u64,
    /// Bytes copied away from the job.
    pub bytes_up: u64,
    /// Why: `allowlisted`, `not on the allowlist`, …
    pub reason: String,
}

impl Decision {
    /// One line, for the log a volunteer keeps and for `gitiup doctor`.
    pub fn describe(&self) -> String {
        let verdict = if self.allowed { "allow" } else { "deny" };
        let bytes = if self.bytes_down + self.bytes_up > 0 {
            format!("{} bytes down", self.bytes_down)
        } else {
            "no bytes".to_string()
        };
        format!(
            "{verdict} {}:{} {} {} ({})",
            self.kind, self.host, self.port, self.reason, bytes
        )
    }
}

/// Egress policy for one job: the allowlist, the DNS policy, and the local endpoints
/// a job is told about.
///
/// The proxy and resolver are owned by an [`Arc`] so a cloned `Spec` — one printed,
/// one used — keeps the same listener and the same audit log. Starting them is a side
/// effect, so it happens in [`Egress::via_proxy`], never in [`Egress::deny_all`].
#[derive(Debug, Clone)]
pub struct Egress {
    /// The hosts a job may reach.
    pub allow: Allowlist,
    /// The DNS policy.
    pub dns: DnsPolicy,
    proxy: Option<Arc<Proxy>>,
    resolver: Option<Arc<Resolver>>,
}

impl PartialEq for Egress {
    fn eq(&self, other: &Egress) -> bool {
        self.allow == other.allow
            && self.dns == other.dns
            && self.proxy.as_ref().map(|p| p.endpoint())
                == other.proxy.as_ref().map(|p| p.endpoint())
    }
}

impl Egress {
    /// Nothing out. The default, and the only mode every backend enforces in the
    /// kernel.
    pub fn deny_all() -> Egress {
        Egress {
            allow: Allowlist::empty(),
            dns: DnsPolicy::Denied,
            proxy: None,
            resolver: None,
        }
    }

    /// Route everything through a fresh local proxy that allows `allow`.
    ///
    /// This is the constructor that actually binds sockets: an allowlist of hosts
    /// with no proxy behind it would be a promise nothing kept.
    pub fn via_proxy(allow: Allowlist) -> Result<Egress> {
        if allow.is_empty() {
            return Err(Error::new(
                ErrorKind::Invalid,
                "egress",
                "an allowlist proxy with nothing on the allowlist",
            )
            .with_hint("use Egress::deny_all() — it needs no proxy, and is stricter"));
        }
        let proxy = Arc::new(Proxy::start(allow.clone())?);
        let resolver = Arc::new(Resolver::start(allow.clone())?);
        Ok(Egress {
            allow,
            dns: DnsPolicy::AllowlistOnly,
            proxy: Some(proxy),
            resolver: Some(resolver),
        })
    }

    /// The common case: the package registries, through a proxy, with DNS that only
    /// answers for them.
    pub fn allow_registries() -> Result<Egress> {
        Egress::via_proxy(Allowlist::registries())
    }

    /// True when nothing may be reached and no proxy is running.
    pub fn is_denied(&self) -> bool {
        self.allow.is_empty() && self.proxy.is_none()
    }

    /// The policy in one sentence, for a report or a refusal.
    ///
    /// The sentence says *how* it is enforced as well as what it allows, because
    /// "egress: allowlist" on its own is the kind of phrase that hides a proxy that
    /// only audited the job instead of stopping it.
    pub fn describe(&self) -> String {
        if self.is_denied() {
            return "no egress: the job may not open a connection to anything".to_string();
        }
        let hosts = if self.allow.is_empty() {
            "nothing".to_string()
        } else if self.allow.hosts().len() <= 4 {
            self.allow.hosts().join(", ")
        } else {
            format!("{} hosts", self.allow.hosts().len())
        };
        match self.proxy() {
            Some(proxy) => format!(
                "egress allowed to {hosts} through the loopback proxy at {}",
                proxy.endpoint()
            ),
            // An allowlist with no proxy behind it is a policy nothing can enforce, so
            // the sentence has to say so rather than imply a gate exists.
            None => format!(
                "egress allowlist of {hosts} with no proxy behind it: audited, not enforced"
            ),
        }
    }

    /// The proxy URL a job should be told about (`HTTP_PROXY`), if any.
    pub fn proxy_url(&self) -> Option<String> {
        self.proxy.as_ref().map(|proxy| proxy.url())
    }

    /// The resolver endpoint a job should be told about, if any.
    pub fn dns_endpoint(&self) -> Option<SocketAddr> {
        self.resolver.as_ref().map(|resolver| resolver.endpoint())
    }

    /// The proxy itself, for a backend that needs its address and port.
    pub fn proxy(&self) -> Option<&Proxy> {
        self.proxy.as_deref()
    }

    /// Every decision the proxy has made so far — the audit record.
    pub fn audit(&self) -> Vec<Decision> {
        self.proxy
            .as_ref()
            .map(|proxy| proxy.audit())
            .unwrap_or_default()
    }

    /// The environment a confined job is given so that well-behaved tooling uses the
    /// proxy without being rewritten.
    ///
    /// This is the "polite" half of egress control, and it is only half: a job that
    /// ignores these variables is exactly what
    /// [`Enforcement`](crate::spec::Enforcement) is for.
    pub fn proxy_env(&self) -> Vec<(String, String)> {
        let mut env = Vec::new();
        if let Some(url) = self.proxy_url() {
            for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "https_proxy"] {
                env.push((key.to_string(), url.clone()));
            }
            // Loopback must never go via the proxy, or `localhost` services in a test
            // become a proxy hop and a confusing failure.
            env.push((
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ));
        }
        if let Some(addr) = self.dns_endpoint() {
            // glibc's resolver honours this; a musl job will not, which is a fact the
            // backend's `guarantees` states rather than hides.
            env.push((
                "RES_OPTIONS".to_string(),
                "timeout:2 attempts:2".to_string(),
            ));
            env.push(("GITIUP_DNS".to_string(), addr.to_string()));
        }
        env
    }
}

/// Per-job DNS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicy {
    /// Nothing resolves: the job has no resolver to ask (it also has no route).
    Denied,
    /// A local resolver answers for allowlisted names and says `NXDOMAIN` to
    /// everything else, so a job's failure looks like a missing host rather than a
    /// firewall.
    AllowlistOnly,
}

/// The local allowlist proxy.
///
/// It is an HTTP/1.1 proxy in the narrow sense a build needs: `CONNECT` for TLS
/// (so `git`, `cargo`, `pip` and `npm` work through it) and absolute-form requests
/// for plain HTTP. It does not cache, does not rewrite, and does not terminate TLS —
/// it is a gatekeeper with a log, not a man in the middle.
///
/// It binds `127.0.0.1` on an ephemeral port and lives until the `Egress` that owns
/// it is dropped, which keeps the "one job, one policy, one audit trail" property:
/// a proxy cannot be reused to leak one job's allowance into another's.
#[derive(Debug)]
pub struct Proxy {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    allow: Allowlist,
    endpoint: SocketAddr,
    audit: Mutex<Vec<Decision>>,
    stop: AtomicBool,
    accept: Mutex<Option<JoinHandle<()>>>,
    listener: TcpListener,
}

impl Proxy {
    /// Bind `127.0.0.1:0` and start serving.
    pub fn start(allow: Allowlist) -> Result<Proxy> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|why| {
            Error::new(
                ErrorKind::Invalid,
                "egress",
                format!("could not bind the egress proxy on loopback: {why}"),
            )
        })?;
        let endpoint = listener
            .local_addr()
            .map_err(|why| Error::new(ErrorKind::Invalid, "egress", format!("{why}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|why| Error::new(ErrorKind::Invalid, "egress", format!("{why}")))?;
        let proxy = Proxy {
            inner: Arc::new(Inner {
                allow,
                endpoint,
                audit: Mutex::new(Vec::new()),
                stop: AtomicBool::new(false),
                accept: Mutex::new(None),
                listener,
            }),
        };
        let handle = {
            let inner = Arc::clone(&proxy.inner);
            std::thread::Builder::new()
                .name("gitiup-egress-proxy".to_string())
                .spawn(move || accept_loop(inner))
                .map_err(|why| {
                    Error::new(
                        ErrorKind::Invalid,
                        "egress",
                        format!("could not start the egress proxy thread: {why}"),
                    )
                })?
        };
        *proxy.inner.accept.lock().unwrap() = Some(handle);
        Ok(proxy)
    }

    /// Where to point `HTTP_PROXY`.
    pub fn endpoint(&self) -> SocketAddr {
        self.inner.endpoint
    }

    /// The same, as a URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.inner.endpoint)
    }

    /// The allowlist this proxy enforces.
    pub fn allowlist(&self) -> &Allowlist {
        &self.inner.allow
    }

    /// Every decision so far, oldest first.
    pub fn audit(&self) -> Vec<Decision> {
        self.inner.audit.lock().unwrap().clone()
    }

    /// Record one decision. Public because a backend that ends up enforcing the same
    /// policy in the kernel should still write to the same log.
    pub fn record(&self, decision: Decision) {
        self.inner.audit.lock().unwrap().push(decision);
    }

    fn decide(&self, host: &str, port: u16, kind: &'static str) -> bool {
        let allowed = self.allowlist().allows(host);
        self.record(Decision {
            at_secs: now_secs(),
            host: host.to_string(),
            port,
            kind,
            allowed,
            bytes_down: 0,
            bytes_up: 0,
            reason: if allowed {
                "allowlisted".to_string()
            } else {
                "not on the allowlist".to_string()
            },
        });
        allowed
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.inner.accept.lock().unwrap().take() {
            // The accept loop polls the stop flag, so this joins in milliseconds.
            let _ = handle.join();
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The accept loop: non-blocking, polled, so `Drop` can end it without a self-connect
/// or a signal.
fn accept_loop(inner: Arc<Inner>) {
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        match inner.listener.accept() {
            Ok((stream, _peer)) => {
                let inner = Arc::clone(&inner);
                // One thread per connection: a build makes a handful, and a pool
                // would need a queue to be worth the code.
                let _ = std::thread::Builder::new()
                    .name("gitiup-egress-conn".to_string())
                    .spawn(move || serve(stream, inner));
            }
            Err(would_block) if would_block.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(why) => {
                if why.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // A listener that has stopped working is not worth a hot loop.
                return;
            }
        }
    }
}

/// Serve one client connection.
fn serve(client: TcpStream, inner: Arc<Inner>) {
    let _ = handle_client(client, &inner);
}

/// The proxy's whole request-handling path, in one function because there is exactly
/// one path: read the request line, ask the allowlist, then either splice or refuse.
fn handle_client(mut client: TcpStream, inner: &Arc<Inner>) -> std::io::Result<()> {
    let proxy = Proxy {
        inner: Arc::clone(inner),
    };
    let mut reader = BufReader::new(client.try_clone()?);
    let Some(request_line) = read_line(&mut reader)? else {
        return Ok(());
    };
    let mut headers = Vec::new();
    while let Some(line) = read_line(&mut reader)? {
        if line.is_empty() {
            break;
        }
        headers.push(line);
    }
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return write_status(&mut client, 400, "bad request");
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443);
        if !proxy.decide(&host, port, "connect") {
            return write_status(
                &mut client,
                403,
                "gitiup: egress denied by the sandbox allowlist",
            );
        }
        let address = resolve(&host, port)?;
        if !proxy.allowlist().allows_address(address) {
            proxy.record(Decision {
                at_secs: now_secs(),
                host: host.clone(),
                port,
                kind: "connect",
                allowed: false,
                bytes_down: 0,
                bytes_up: 0,
                reason: format!("{address} is loopback or link-local, which is not allowed"),
            });
            return write_status(
                &mut client,
                403,
                "gitiup: egress target resolved to a local address",
            );
        }
        let mut origin = match TcpStream::connect(address) {
            Ok(origin) => origin,
            Err(why) => {
                proxy.record(Decision {
                    at_secs: now_secs(),
                    host: host.clone(),
                    port,
                    kind: "connect",
                    allowed: false,
                    bytes_down: 0,
                    bytes_up: 0,
                    reason: format!("connect failed: {why}"),
                });
                return write_status(&mut client, 502, "gitiup: egress target unreachable");
            }
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        let (down, up) = splice(&mut client, &mut origin)?;
        proxy.record(Decision {
            at_secs: now_secs(),
            host,
            port,
            kind: "connect",
            allowed: true,
            bytes_down: down,
            bytes_up: up,
            reason: "allowlisted".to_string(),
        });
        return Ok(());
    }

    // Absolute-form request: `GET http://host/path HTTP/1.1`, which is what an
    // HTTP proxy is asked for when `http_proxy` is set.
    let Some(absolute) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("http+unix://"))
    else {
        return write_status(
            &mut client,
            400,
            "gitiup: proxy needs an absolute URL or CONNECT",
        );
    };
    let (authority, path) = match absolute.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (absolute, "/".to_string()),
    };
    let (host, port) = split_host_port(authority, 80);
    if !proxy.decide(&host, port, "http") {
        return write_status(
            &mut client,
            403,
            "gitiup: egress denied by the sandbox allowlist",
        );
    }
    let address = resolve(&host, port)?;
    if !proxy.allowlist().allows_address(address) {
        proxy.record(Decision {
            at_secs: now_secs(),
            host,
            port,
            kind: "http",
            allowed: false,
            bytes_down: 0,
            bytes_up: 0,
            reason: format!("{address} is loopback or link-local, which is not allowed"),
        });
        return write_status(
            &mut client,
            403,
            "gitiup: egress target resolved to a local address",
        );
    }
    let mut origin = TcpStream::connect(address)?;
    // Origin-form request line for the upstream, and the `Host:` header the job
    // already sent is kept as it is: rewriting it would be a second opinion about
    // virtual hosting.
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    for header in &headers {
        let name = header
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name.starts_with("proxy-") || name == "connection" || name == "keep-alive" {
            continue;
        }
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("connection: close\r\n\r\n");
    origin.write_all(request.as_bytes())?;
    let _ = origin.flush();
    let (down, up) = splice(&mut client, &mut origin)?;
    proxy.record(Decision {
        at_secs: now_secs(),
        host,
        port,
        kind: "http",
        allowed: true,
        bytes_down: down,
        bytes_up: up,
        reason: "allowlisted".to_string(),
    });
    let _ = up;
    Ok(())
}

/// Copy bytes both ways until both sides close.
///
/// Two threads, each with its half of the pair: a single-threaded poll here would
/// need `poll(2)` and would still need to handle a half-close, which is what
/// `read_to_end` on a shutdown socket already does.
fn splice(client: &mut TcpStream, origin: &mut TcpStream) -> std::io::Result<(u64, u64)> {
    let mut to_client = client.try_clone()?;
    let mut from_client = client.try_clone()?;
    let mut to_origin = origin.try_clone()?;
    let mut from_origin = origin.try_clone()?;
    let up = std::thread::spawn(move || pump(&mut from_client, &mut to_origin).unwrap_or(0));
    let down = std::thread::spawn(move || pump(&mut from_origin, &mut to_client).unwrap_or(0));
    let (up, down) = (up.join().unwrap_or(0), down.join().unwrap_or(0));
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = origin.shutdown(std::net::Shutdown::Both);
    Ok((down, up))
}

/// Copy until EOF, counting bytes, then close the writing half so the reader sees the
/// end of the stream instead of waiting for a timeout.
///
/// `max` is not capped on purpose: the byte budget is giti-bgy.2's decision, and a
/// proxy that silently truncates a `git fetch` is worse than one that lets the cost
/// controller see it.
fn pump(reader: &mut TcpStream, writer: &mut TcpStream) -> std::io::Result<u64> {
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                writer.write_all(&buffer[..read])?;
                let _ = writer.flush();
                total += read as u64;
            }
            Err(why) if why.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    // A `shutdown` on a `try_clone`d socket affects the shared socket, which is what
    // closes *this* direction and lets the peer see EOF.
    let _ = writer.shutdown(std::net::Shutdown::Write);
    Ok(total)
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Some(line))
}

fn write_status(mut stream: impl Write, code: u16, reason: &str) -> std::io::Result<()> {
    let body = format!("gitiup sandbox proxy: {reason}\n");
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn resolve(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // A hostname that resolves to loopback is the SSRF shape to fear most: a job that
    // allows `example.com` and gets 127.0.0.1 out of a hostile resolver would be
    // reading the host's own services. So the proxy resolves and then checks.
    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other(format!("`{host}` resolved to nothing")))?;
    Ok(address)
}

/// `host:port`, with the port defaulted, and IPv6 brackets handled.
fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[')
        && let Some((host, port)) = rest.split_once(']')
    {
        let port = port
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }
    if let Some((host, port)) = target.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (target.to_string(), default_port)
}

#[test]
// The sentence a report prints has to distinguish "nothing" from "some, through a
// proxy" from "an allowlist nobody can enforce" — they are three different risks.
fn the_policy_describes_itself_in_one_line() {
    assert!(Egress::deny_all().describe().contains("may not open"));
    let allowed = Egress::allow_registries().unwrap();
    let text = allowed.describe();
    assert!(text.contains("loopback proxy"), "{text}");
    assert!(
        text.contains("github.com") || text.contains("hosts"),
        "{text}"
    );
    let unenforced = Egress {
        allow: Allowlist::registries(),
        dns: DnsPolicy::Denied,
        proxy: None,
        resolver: None,
    };
    assert!(unenforced.describe().contains("not enforced"));
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowlist_matches_hosts_and_suffixes() {
        let mut list = Allowlist::empty();
        list.push("crates.io").unwrap();
        list.push("*.npmjs.org").unwrap();
        assert!(list.allows("crates.io"));
        assert!(list.allows("CRATES.IO."), "hosts are typed by people");
        assert!(!list.allows("crates.io.evil.test"));
        assert!(list.allows("registry.npmjs.org"));
        assert!(list.allows("npmjs.org"), "a suffix covers the apex too");
        assert!(!list.allows("npmjs.org.evil.test"));
        assert!(!list.allows(""));
    }

    #[test]
    fn a_wildcard_for_everything_is_refused_not_ignored() {
        // The mistake this guard exists for is an operator "fixing" a failure by
        // writing `*`, which silently deletes the whole feature.
        for bad in ["*", "*.", "", "   ", "https://", "*."] {
            let err = Allowlist::empty().push(bad).unwrap_err();
            assert!(
                err.detail().contains("allowlist") || err.detail().contains("empty"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn a_url_or_path_in_a_pattern_is_a_refusal_with_a_shape_to_copy() {
        let err = Allowlist::empty()
            .push("git@github.com:o/r.git")
            .unwrap_err();
        assert!(err.hint().unwrap().contains("hostname"), "{err}");
        // A URL origin, though, is how a config file writes a store: take the host.
        let mut list = Allowlist::empty();
        list.push("https://ghcr.io/v2/").unwrap();
        assert!(list.allows("ghcr.io"));
    }

    #[test]
    fn the_repo_store_origin_becomes_a_host() {
        let list = Allowlist::registries().with_repo_store("https://git.example.com/team/repo");
        assert!(list.allows("git.example.com"));
        assert!(!list.allows("evil.test"));
        // An empty origin adds nothing rather than allowing everything.
        let list = Allowlist::empty().with_repo_store("");
        assert!(list.is_empty());
    }

    #[test]
    fn the_default_registries_list_is_a_list_and_not_a_wildcard() {
        let list = Allowlist::registries();
        assert_eq!(
            list.hosts().len(),
            DEFAULT_REGISTRIES.len(),
            "DEFAULT_REGISTRIES has duplicates: {:?}",
            list.hosts()
        );
        assert!(list.allows("static.crates.io"));
        assert!(!list.allows("example.com"), "the list is not a wildcard");
        assert!(
            !list.hosts().iter().any(|host| host == "*" || host == "*.*"),
            "no entry may mean \"everything\""
        );
    }

    #[test]
    fn allowing_a_name_never_allows_the_host_it_self_lives_on() {
        // The shape of the attack: a job allows a hostname whose DNS points at the
        // metadata service or at a service on the volunteer's own machine.
        let list = Allowlist::registries();
        let metadata: SocketAddr = "169.254.169.254:80".parse().unwrap();
        let looped: SocketAddr = "127.0.0.1:6379".parse().unwrap();
        assert!(list.allows("pypi.org"));
        assert!(
            !list.allows_address(metadata),
            "a link-local answer must not be dialled"
        );
        assert!(!list.allows_address(looped));
        assert!(list.allows_address("151.101.0.223:443".parse().unwrap()));
        // Unless the operator listed the local address deliberately.
        let mut list = Allowlist::empty();
        list.push("127.0.0.1").unwrap();
        assert!(list.allows_address(looped));
    }

    #[test]
    fn the_proxy_allows_what_is_on_the_list_and_refuses_what_is_not() {
        // A local origin so the "allowed" path can be proven end to end without a
        // network: the escape suite needs the same property.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = origin.accept().unwrap();
            let mut buf = [0u8; 512];
            let read = peer.read(&mut buf).unwrap_or(0);
            let _ = std::str::from_utf8(&buf[..read]);
            let body = "hello from the origin\n";
            let _ = peer.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        });

        let mut allow = Allowlist::empty();
        allow.push("127.0.0.1").unwrap();
        let egress = Egress::via_proxy(allow).unwrap();
        let proxy = egress.proxy().unwrap();

        // Allowed: an absolute-form GET through the proxy.
        let mut client = TcpStream::connect(proxy.endpoint()).unwrap();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}/x HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
                    origin_addr.port()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut text = String::new();
        client.read_to_string(&mut text).unwrap();
        assert!(text.contains("200 OK"), "{text}");
        assert!(text.contains("hello from the origin"), "{text}");

        // Denied: a name nobody listed — refused before any lookup.
        let mut client = TcpStream::connect(proxy.endpoint()).unwrap();
        client
            .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\nhost: evil.test:443\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        client.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("HTTP/1.1 403"), "{text}");
        server.join().unwrap();

        let audit = egress.audit();
        assert!(
            audit
                .iter()
                .any(|d| d.allowed && d.port == origin_addr.port()),
            "{audit:?}"
        );
        assert!(
            audit
                .iter()
                .any(|d| !d.allowed && d.host == "evil.test" && d.kind == "connect"),
            "{audit:?}"
        );
        assert!(
            audit
                .iter()
                .find(|d| d.host == "evil.test")
                .unwrap()
                .describe()
                .contains("deny"),
        );
    }

    #[test]
    fn deny_all_means_no_proxy_at_all() {
        let egress = Egress::deny_all();
        assert!(egress.proxy().is_none());
        assert!(egress.proxy_url().is_none());
        assert!(egress.audit().is_empty());
        assert_eq!(egress.dns, DnsPolicy::Denied);
        let err = Egress::via_proxy(Allowlist::empty()).unwrap_err();
        assert!(err.hint().unwrap().contains("deny_all"), "{err}");
    }

    #[test]
    fn the_proxy_env_points_at_the_proxy_and_never_at_loopback_through_it() {
        let mut allow = Allowlist::empty();
        allow.push("pypi.org").unwrap();
        let egress = Egress::via_proxy(allow).unwrap();
        let env = egress.proxy_env();
        let url = egress.proxy_url().unwrap();
        assert_eq!(env.iter().filter(|(k, _)| k == "HTTPS_PROXY").count(), 1);
        assert!(env.iter().any(|(k, v)| k == "HTTPS_PROXY" && *v == url));
        assert!(
            env.iter()
                .any(|(k, v)| k == "NO_PROXY" && v.contains("127.0.0.1"))
        );
        drop(egress);
    }

    #[test]
    fn a_proxy_lives_as_long_as_the_egress_that_started_it() {
        let mut allow = Allowlist::empty();
        allow.push("pypi.org").unwrap();
        let egress = Egress::via_proxy(allow).unwrap();
        let endpoint = egress.proxy().unwrap().endpoint();
        assert!(TcpStream::connect(endpoint).is_ok());
        drop(egress);
        // The listener is gone, so a new connection cannot be established. Poll because
        // the accept loop has to notice first.
        let mut refused = false;
        for _ in 0..50 {
            if TcpStream::connect_timeout(&endpoint, Duration::from_millis(50)).is_err() {
                refused = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(refused, "the proxy outlived its Egress");
    }
}

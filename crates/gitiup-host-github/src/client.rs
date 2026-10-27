//! The API client: identity, rate limits, pagination and the error mapping.
//!
//! Everything above this module talks in refs and records; everything below it is
//! `Request`/`Response`. What lives *here* is the forge-specific bookkeeping the
//! ticket named, because it is the part a naive implementation gets wrong:
//!
//! **Authentication.** One `Authorization: Bearer` header, from [`crate::auth`],
//! sent only to the host the remote named. Redirects are *not* followed: following
//! one would carry that header to a host nobody configured, and a forge API that
//! answers 301 is telling you your `api-base` is wrong, not asking you to try
//! another server.
//!
//! **Pagination.** GitHub paginates by `page`/`per_page` and announces the next
//! page in a `Link: rel="next"` header. [`Client::get_all`] follows that header
//! rather than counting pages, because the header is the answer and a page count is
//! a guess — but it also refuses to visit the same URL twice and stops at
//! `max-pages`, because a server that repeats its own `next` link would otherwise
//! spin here forever.
//!
//! **Rate limits.** Every response carries `x-ratelimit-remaining` and
//! `-reset`; a 403/429 *is* the rate limit most of the time, and `Retry-After`
//! comes with it when GitHub wants a specific pause. The client keeps a budget,
//! stops *before* spending the last of it (so a listing does not die halfway),
//! waits out a short reset rather than failing, and fails with the reset time in
//! the message when the wait would be longer than `rate-wait`. `gitiup doctor`
//! prints that budget.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gitiup_host::{HostError, HostResult, RemoteConfig, config::parse_timeout};

use crate::auth::Auth;
use crate::codec;
use crate::transport::{Method, Request, Response, Transport};

/// The GitHub API version this adapter speaks, sent as `X-GitHub-Api-Version`.
pub const API_VERSION: &str = "2022-11-28";

/// Largest `per_page` GitHub honours.
pub const MAX_PER_PAGE: usize = 100;

/// Which forge this is, and where its API lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    /// API root, e.g. `https://api.github.com` or `https://ghe.example.com/api/v3`.
    pub api_base: String,
    /// `owner`.
    pub owner: String,
    /// `repo`.
    pub repo: String,
    /// The forge's own host (`github.com`, `ghe.example.com`), for `describe()`.
    pub forge_host: String,
}

impl RepoRef {
    /// Derive the repository and API root from a configured remote.
    ///
    /// Both the clone URL (`https://github.com/o/r.git`,
    /// `git@github.com:o/r.git`) and the API URL (`https://api.github.com/repos/o/r`)
    /// are accepted, because users paste both. An enterprise server gets
    /// `https://<host>/api/v3` unless `api-base` says otherwise.
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<RepoRef> {
        let url = &remote.url;
        let host = url.host.clone();
        if host.is_empty() {
            return Err(HostError::invalid(
                "github remote",
                format!(
                    "remote '{}' has no host: {}",
                    remote.name,
                    remote.redacted_url()
                ),
            )
            .with_hint("a github remote looks like https://github.com/owner/repo.git"));
        }
        let path = url
            .path
            .trim_matches('/')
            .trim_end_matches(".git")
            .to_string();
        let (owner, repo) = match path.rsplit_once('/') {
            Some((owner, repo)) if !owner.is_empty() && !repo.is_empty() => {
                // Strip an enterprise `/scm/` prefix: `https://ghe.example.com/scm/o/r`.
                let owner = owner.trim_start_matches("scm/").trim_start_matches("api/");
                let owner = owner.rsplit('/').next().unwrap_or(owner);
                (owner.to_string(), repo.to_string())
            }
            _ => {
                return Err(HostError::invalid(
                    "github remote",
                    format!(
                        "remote '{}' points at '{}', which is not owner/repo",
                        remote.name,
                        remote.redacted_url()
                    ),
                )
                .with_hint("a github remote looks like https://github.com/owner/repo.git"));
            }
        };
        let api_base = match remote.option("api-base") {
            Some(base) => base.trim_end_matches('/').to_string(),
            None if host == "github.com" => "https://api.github.com".to_string(),
            None => format!("https://{host}/api/v3"),
        };
        Auth::check_base_url(&api_base)?;
        Ok(RepoRef {
            api_base,
            owner,
            repo,
            forge_host: host,
        })
    }

    /// `owner/repo`, as the API spells it.
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// The host the API lives on (used for the token's allow-list).
    pub fn api_host(&self) -> String {
        codec::url_host(&self.api_base)
    }

    /// `/repos/owner/repo` — the prefix almost every call starts with.
    pub fn repo_path(&self) -> String {
        format!("/repos/{}/{}/", self.owner, self.repo).to_string()
    }
}

impl fmt::Display for RepoRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.full_name(), self.api_base)
    }
}

/// Tunables, all read from `[remote.options]`.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Page size for listings (GitHub caps at 100).
    pub per_page: usize,
    /// Give up on a listing after this many pages (a runaway `Link` loop).
    pub max_pages: usize,
    /// Requests to keep in hand: the client stops before spending the last few.
    pub rate_reserve: u32,
    /// Longest wait for a rate-limit reset; beyond this the call fails instead.
    pub rate_wait: Duration,
    /// Attempts after a rate-limit or transport answer that says "later".
    pub attempts: usize,
    /// Refuse every write, up front (an anonymous mirror, a read-only CI token).
    pub read_only: bool,
    /// How long a ref listing is trusted.
    pub ref_cache_ttl: Duration,
    /// Retries for a record-append that lost a race.
    pub cas_attempts: usize,
    /// First pause before that retry.
    pub cas_backoff: Duration,
    /// Per-request timeout, from the remote.
    pub timeout: Duration,
    /// Options this build does not read, kept so `advice()` can name them.
    pub unread_options: Vec<String>,
}

impl Default for ClientOptions {
    fn default() -> ClientOptions {
        ClientOptions {
            per_page: MAX_PER_PAGE,
            max_pages: 50,
            rate_reserve: 3,
            rate_wait: Duration::from_secs(60),
            attempts: 3,
            read_only: false,
            ref_cache_ttl: Duration::from_secs(2),
            cas_attempts: 4,
            cas_backoff: Duration::from_millis(20),
            timeout: Duration::from_secs(30),
            unread_options: Vec::new(),
        }
    }
}

/// Option keys this adapter reads, so an unused one can be named out loud instead
/// of silently doing nothing.
pub const KNOWN_OPTIONS: [&str; 15] = [
    "api-base",
    "token-env",
    "token-host",
    "per-page",
    "max-pages",
    "rate-reserve",
    "rate-wait",
    "attempts",
    "read-only",
    "ref-cache-ttl",
    "cas-attempts",
    "cas-backoff",
    "timeout",
    "transport",
    "credentials-profile",
];

impl ClientOptions {
    /// Read the options off a remote, complaining about nothing here (advice comes
    /// later, once the host is open and can print it).
    pub fn from_remote(remote: &RemoteConfig) -> HostResult<ClientOptions> {
        let mut options = ClientOptions {
            timeout: remote.timeout,
            ..ClientOptions::default()
        };
        let mut read: Vec<String> = vec!["timeout".to_string()];
        if let Some(value) = remote.option("per-page") {
            options.per_page = parse_usize("per-page", value, MAX_PER_PAGE)?;
            read.push("per-page".into());
        }
        if let Some(value) = remote.option("max-pages") {
            options.max_pages = parse_usize("max-pages", value, usize::MAX)?;
            read.push("max-pages".into());
        }
        if let Some(value) = remote.option("rate-reserve") {
            options.rate_reserve = value.trim().parse().map_err(|_| {
                HostError::invalid("github option", format!("rate-reserve = '{value}'"))
            })?;
            read.push("rate-reserve".into());
        }
        for (key, target) in [
            ("rate-wait", &mut options.rate_wait),
            ("ref-cache-ttl", &mut options.ref_cache_ttl),
            ("cas-backoff", &mut options.cas_backoff),
        ] {
            if let Some(value) = remote.option(key) {
                *target = parse_timeout(value)?;
                read.push(key.to_string());
            }
        }
        for (key, target) in [
            ("attempts", &mut options.attempts),
            ("cas-attempts", &mut options.cas_attempts),
        ] {
            if let Some(value) = remote.option(key) {
                *target = parse_usize(key, value, 100)?;
                read.push(key.to_string());
            }
        }
        if let Some(value) = remote.option("read-only") {
            options.read_only = parse_bool("read-only", value)?;
            read.push("read-only".into());
        }
        let mut unread: Vec<String> = Vec::new();
        for key in remote.effective_options().keys() {
            let key = key.to_ascii_lowercase();
            if !read.contains(&key) && !KNOWN_OPTIONS.contains(&key.as_str()) {
                unread.push(key);
            }
        }
        options.unread_options = unread;
        Ok(options)
    }

    /// Warnings about how this host is configured.
    pub fn advice(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.unread_options.is_empty() {
            out.push(format!(
                "the github host does not read these remote options: {} — a typo in an \
                 option name is otherwise invisible",
                self.unread_options.join(", ")
            ));
        }
        if self.read_only {
            out.push(
                "read-only is on: every ref and record write will be refused before it \
                 reaches the network"
                    .to_string(),
            );
        }
        if self.rate_reserve > 0 && self.per_page * 2 > self.rate_reserve as usize {
            out.push(format!(
                "a single listing at per_page={} can cost more requests than the {} \
                 requests kept in reserve, so a long listing may stop early with a \
                 rate-limit error rather than a partial answer",
                self.per_page, self.rate_reserve
            ));
        }
        out
    }
}

fn parse_usize(name: &str, value: &str, max: usize) -> HostResult<usize> {
    let parsed: usize = value.trim().parse().map_err(|_| {
        HostError::invalid(
            "github option",
            format!("{name} = '{value}' is not a number"),
        )
    })?;
    if parsed == 0 || parsed > max {
        return Err(HostError::invalid(
            "github option",
            format!("{name} = '{value}' is out of range (1..={max})"),
        ));
    }
    Ok(parsed)
}

fn parse_bool(name: &str, value: &str) -> HostResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(HostError::invalid(
            "github option",
            format!("{name} = '{other}' is not a boolean"),
        )),
    }
}

/// What the forge last told us about its rate limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateBudget {
    /// The quota (`x-ratelimit-limit`).
    pub limit: Option<u32>,
    /// What is left (`x-ratelimit-remaining`).
    pub remaining: Option<u32>,
    /// When it refills, seconds since the epoch (`x-ratelimit-reset`).
    pub reset_unix: Option<u64>,
    /// Which quota this is (`core`, `search`, `graphql`).
    pub resource: Option<String>,
    /// Requests this process has made.
    pub requests: u64,
    /// Requests this process *paused* before making.
    pub waits: u64,
    /// Seconds the last refusal said to wait.
    pub last_wait_seconds: Option<u64>,
    /// Whether the last refusal was a rate limit (as opposed to a permission).
    pub throttled: bool,
}

impl RateBudget {
    /// Human summary for `gitiup doctor`.
    pub fn summary(&self) -> String {
        match (self.limit, self.remaining) {
            (Some(limit), Some(remaining)) => format!(
                "{remaining}/{limit} left on {}{}",
                self.resource.clone().unwrap_or_else(|| "core".into()),
                match self.reset_unix {
                    Some(reset) => format!(", resets at unix {reset}"),
                    None => String::new(),
                }
            ),
            _ => "no rate-limit headers seen yet".to_string(),
        }
    }
}

/// One client per remote: it owns the credential, the transport and the budget.
pub struct Client {
    repo: RepoRef,
    auth: Auth,
    transport: std::sync::Arc<dyn Transport>,
    options: ClientOptions,
    rate: Mutex<RateBudget>,
    clock: AtomicU64,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("repo", &self.repo)
            .field("auth", &self.auth.source())
            .field("transport", &self.transport.describe())
            .field("rate", &self.rate_budget())
            .finish()
    }
}

impl Client {
    /// Build a client.
    pub fn new(
        repo: RepoRef,
        auth: Auth,
        transport: std::sync::Arc<dyn Transport>,
        options: ClientOptions,
    ) -> Client {
        Client {
            repo,
            auth,
            transport,
            options,
            rate: Mutex::new(RateBudget::default()),
            clock: AtomicU64::new(0),
        }
    }

    /// The repository this client speaks for.
    pub fn repo(&self) -> &RepoRef {
        &self.repo
    }

    /// How this client authenticates (never the value).
    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    /// The resolved options.
    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// A snapshot of the rate budget.
    pub fn rate_budget(&self) -> RateBudget {
        self.rate.lock().expect("rate lock").clone()
    }

    /// A GET that returns a JSON object; `Ok(None)` for a 404.
    pub fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> HostResult<Option<T>> {
        let request = self.request(Method::Get, path, query);
        match self.send_allowing(request, &[404]) {
            Ok(response) if response.status == 404 => Ok(None),
            Ok(response) => Ok(Some(response.json::<T>().map_err(invalid_body)?)),
            Err(why) => Err(why),
        }
    }

    /// A GET that returns a JSON array; a 404 is an empty list.
    pub fn get_list<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> HostResult<Vec<T>> {
        let request = self.request(Method::Get, path, query);
        match self.send_allowing(request, &[404]) {
            Ok(response) if response.status == 404 => Ok(Vec::new()),
            Ok(response) => Ok(response.json::<Vec<T>>().map_err(invalid_body)?),
            Err(why) => Err(why),
        }
    }

    /// A GET that returns a JSON object, where a 404 is an error.
    pub fn get_required<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> HostResult<T> {
        self.get_json(path, query)?
            .ok_or_else(|| HostError::not_found("github resource", path.to_string()))
    }

    /// Every page of a paginated listing, following the `Link: rel="next"` header.
    ///
    /// `page` is only sent on the first request; after that the server's own link
    /// is followed verbatim, because that link is the server telling us where the
    /// next page is. A link we have already seen is a bug (or a hostile server) and
    /// stops the walk rather than looping in it.
    pub fn get_all<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> HostResult<Vec<T>> {
        let mut first = true;
        let mut cursor = format!("{}{}", path, codec::query(query));
        let mut seen: Vec<String> = Vec::new();
        let mut out: Vec<T> = Vec::new();
        for page in 0..self.options.max_pages {
            if first {
                let mut page_query: Vec<(&str, String)> = query.to_vec();
                page_query.push(("per_page", self.options.per_page.to_string()));
                let request = self.request(Method::Get, path, &page_query);
                first = false;
                // No `&[404]` here on purpose: a *listing* endpoint answers 404
                // only when the repository (or the path inside it) is not there —
                // a prefix that matches nothing is a 200 and `[]`. Reading the
                // first as the second is how a typo'd remote looks like an empty
                // store, which is the single worst failure a store can have.
                let response = self.send(request)?;
                out.extend(response.json::<Vec<T>>().map_err(invalid_body)?);
                cursor = match next_link(&response)? {
                    Some(next) => next,
                    None => return Ok(out),
                };
            } else {
                if seen.contains(&cursor) {
                    return Err(HostError::invalid(
                        "github pagination",
                        format!("the API offered '{cursor}' as a next page twice"),
                    )
                    .with_hint("the listing loop was stopped rather than looping in it"));
                }
                let mut request = Request::new(Method::Get, cursor.clone());
                request.timeout = self.options.timeout;
                let response = self.send(request)?;
                let items: Vec<T> = response.json().map_err(invalid_body)?;
                if items.is_empty() {
                    return Ok(out);
                }
                out.extend(items);
                seen.push(cursor.clone());
                cursor = match next_link(&response)? {
                    Some(next) => next,
                    None => return Ok(out),
                };
                let _ = page;
            }
        }
        Err(HostError::invalid(
            "github pagination",
            format!(
                "a listing under {path} ran past max_pages = {} and was stopped",
                self.options.max_pages
            ),
        )
        .with_hint("raise `max-pages`, or narrow the listing with a prefix"))
    }

    /// A POST whose body is JSON.
    pub fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> HostResult<T> {
        let response = self.send(self.with_body(self.request(Method::Post, path, &[]), body)?)?;
        response.json::<T>().map_err(invalid_body)
    }

    /// A POST whose answer is not read.
    pub fn post_empty(&self, path: &str, body: &serde_json::Value) -> HostResult<()> {
        self.send(self.with_body(self.request(Method::Post, path, &[]), body)?)?;
        Ok(())
    }

    /// A PATCH whose answer is not read.
    pub fn patch(&self, path: &str, body: &serde_json::Value) -> HostResult<()> {
        self.send(self.with_body(self.request(Method::Patch, path, &[]), body)?)?;
        Ok(())
    }

    /// A PATCH that may answer 404 (the caller decides what that means).
    pub fn patch_allowing(
        &self,
        path: &str,
        body: &serde_json::Value,
        allowed: &[u16],
    ) -> HostResult<Response> {
        let request = self.with_body(self.request(Method::Patch, path, &[]), body)?;
        self.send_allowing(request, allowed)
    }

    /// A POST that may answer one of `allowed` statuses (used for
    /// create-or-conflict).
    pub fn post_allowing(
        &self,
        path: &str,
        body: &serde_json::Value,
        allowed: &[u16],
    ) -> HostResult<Response> {
        let request = self.with_body(self.request(Method::Post, path, &[]), body)?;
        self.send_allowing(request, allowed)
    }

    /// A DELETE; `Ok(false)` when the target was already gone.
    pub fn delete(&self, path: &str) -> HostResult<bool> {
        let request = self.request(Method::Delete, path, &[]);
        match self.send_allowing(request, &[404]) {
            Ok(response) => Ok(response.status != 404),
            Err(why) => Err(why),
        }
    }

    /// Build a GET request (mostly for [`Client::send_allowing`] callers).
    pub fn request(&self, method: Method, path: &str, query: &[(&str, String)]) -> Request {
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{}{}", self.repo.api_base, path, codec::query(query))
        };
        Request::new(method, url).with_timeout(self.options.timeout)
    }

    /// Attach a canonical JSON body.
    pub fn with_body(&self, request: Request, body: &serde_json::Value) -> HostResult<Request> {
        Ok(request.with_body(codec::canonical_json(body)?))
    }

    /// Send a request, mapping every non-success status to the host taxonomy.
    pub fn send(&self, request: Request) -> HostResult<Response> {
        self.send_allowing(request, &[])
    }

    /// Send a request; statuses in `allowed` come back as `Ok(Response)` for the
    /// caller to interpret (a 404 on a ref is "absent", on a URL typo it is a bug,
    /// and only the caller knows which it asked for).
    pub fn send_allowing(&self, request: Request, allowed: &[u16]) -> HostResult<Response> {
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            self.wait_for_headroom()?;
            let prepared = self.prepare(&request)?;
            match self.transport.send(&prepared) {
                Ok(response) => {
                    self.record(&response);
                    if (200..300).contains(&response.status) || allowed.contains(&response.status) {
                        return Ok(response);
                    }
                    let action = prepared.summary();
                    match self.retry_plan(&response, attempt, prepared.method) {
                        Some(wait) => {
                            std::thread::sleep(wait);
                            continue;
                        }
                        None => return Err(self.error_for(response, &action)),
                    }
                }
                Err(why) => {
                    if attempt >= self.options.attempts.max(1) {
                        return Err(unreachable(
                            format!("{}: {why}", self.transport.describe()),
                            codec::split_url(&prepared.url).map(|(origin, _)| origin.to_string()),
                            why.retryable,
                            why.hint.unwrap_or_else(|| {
                                "check the remote's URL, your network and any proxy \
                                 between them"
                                    .to_string()
                            }),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50 * attempt as u64));
                }
            }
        }
    }

    /// Map a non-success answer onto the taxonomy, for the endpoint wrappers in
    /// [`crate::api`] — those need to look at a status themselves (a 422 on
    /// `POST /git/refs` is a conflict, on any other call it is bad input) and then
    /// hand the rest over here rather than inventing their own error text.
    pub fn refusal(&self, response: &Response, action: &str) -> HostError {
        self.error_for(response.clone(), action)
    }

    /// Add the identity headers. Split out so a test can look at what would be sent.
    fn prepare(&self, request: &Request) -> HostResult<Request> {
        let host = codec::url_host(&request.url);
        let mut prepared = request.clone();
        if let Some(userinfo) = codec::split_url(&request.url)
            .map(|(origin, _)| origin)
            .filter(|origin| origin.contains('@'))
        {
            // Belt and braces: the transport must never be handed a URL that could
            // carry a credential in it.
            return Err(HostError::invalid(
                "github request",
                format!("the request URL carries userinfo: {userinfo}"),
            ));
        }
        prepared.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("authorization")
                && !name.eq_ignore_ascii_case("accept")
                && !name.eq_ignore_ascii_case("user-agent")
                && !name.eq_ignore_ascii_case("x-github-api-version")
        });
        if let Some(header) = self.auth.header(&host)? {
            prepared.headers.push(("Authorization".into(), header));
        }
        prepared
            .headers
            .push(("Accept".into(), "application/vnd.github+json".into()));
        prepared
            .headers
            .push(("X-GitHub-Api-Version".into(), API_VERSION.to_string()));
        prepared.headers.push((
            "User-Agent".into(),
            format!("gitiup-host-github/{} (gitiup)", env!("CARGO_PKG_VERSION")),
        ));
        if prepared.body.is_some() {
            prepared
                .headers
                .push(("Content-Type".into(), "application/json".into()));
        }
        Ok(prepared)
    }

    /// Fold the rate-limit headers of a response into the budget.
    fn record(&self, response: &Response) {
        let mut budget = self.rate.lock().expect("rate lock");
        budget.requests += 1;
        if let Some(value) = header_u32(response, "x-ratelimit-limit") {
            budget.limit = Some(value);
        }
        if let Some(value) = header_u32(response, "x-ratelimit-remaining") {
            budget.remaining = Some(value);
        }
        if let Some(value) = header_u64(response, "x-ratelimit-reset") {
            budget.reset_unix = Some(value);
        }
        if let Some(resource) = response.header("x-ratelimit-resource") {
            budget.resource = Some(resource.to_string());
        }
        if is_rate_limited(response) {
            budget.throttled = true;
            budget.last_wait_seconds = retry_after(response).map(|wait| wait.as_secs());
        }
    }

    /// Pause before a request when the budget is nearly spent.
    ///
    /// The reserve exists so a listing cannot run out halfway: a paginated walk
    /// that dies on page 40 has cost 40 requests and produced nothing.
    fn wait_for_headroom(&self) -> HostResult<()> {
        let budget = self.rate_budget();
        let Some(remaining) = budget.remaining else {
            return Ok(());
        };
        if remaining > self.options.rate_reserve {
            return Ok(());
        }
        let now = unix_now();
        let Some(reset) = budget.reset_unix else {
            return Ok(());
        };
        if reset <= now {
            // The window has already rolled over; the next response tells us so.
            return Ok(());
        }
        let wait = Duration::from_secs((reset - now).saturating_add(1));
        if wait > self.options.rate_wait {
            return Err(rate_limit_error(&budget, wait, &self.options));
        }
        {
            let mut guard = self.rate.lock().expect("rate lock");
            guard.waits += 1;
        }
        self.clock.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(wait);
        Ok(())
    }

    /// Whether an answer is worth waiting out, and for how long.
    ///
    /// A rate limit is waited out when the wait is inside `rate-wait`. A 5xx is
    /// retried only for `GET`: a repeat of `POST /git/refs` is harmless in the
    /// abstract, but "harmless in the abstract" is how a double-merge gets
    /// written, so writes are reported and the caller decides.
    fn retry_plan(&self, response: &Response, attempt: usize, method: Method) -> Option<Duration> {
        if attempt >= self.options.attempts.max(1) {
            return None;
        }
        if is_rate_limited(response) {
            let wait = retry_after(response).unwrap_or_else(|| {
                let budget = self.rate_budget();
                match (budget.reset_unix, unix_now()) {
                    (Some(reset), now) if reset > now => Duration::from_secs(reset - now + 1),
                    _ => Duration::from_millis(200 * attempt as u64),
                }
            });
            if wait > self.options.rate_wait {
                return None;
            }
            return Some(wait);
        }
        if method == Method::Get && matches!(response.status, 500 | 502 | 503 | 504) {
            return Some(Duration::from_millis(100 * attempt as u64));
        }
        None
    }

    /// Turn an HTTP answer into the taxonomy every host speaks.
    fn error_for(&self, response: Response, action: &str) -> HostError {
        let message = response
            .api_message()
            .unwrap_or_else(|| format!("HTTP {}", response.status));
        if is_rate_limited(&response) {
            let budget = self.rate_budget();
            let wait =
                retry_after(&response).unwrap_or_else(|| match (budget.reset_unix, unix_now()) {
                    (Some(reset), now) if reset > now => Duration::from_secs(reset - now + 1),
                    _ => Duration::from_secs(60),
                });
            return rate_limit_error(&budget, wait, &self.options);
        }
        let document = format!(
            "see https://docs.github.com/rest for the status meanings; response: {message}"
        );
        match response.status {
            401 => HostError::denied(format!("{action}: the forge rejected the credential"))
                .with_hint(format!(
                    "the credential came from {}; a revoked, expired or mis-scoped token \
                     looks exactly like this",
                    self.auth.source().describe()
                )),
            403 => HostError::denied(format!("{action}: {message}")).with_hint(format!(
                "scopes, branch protection or an IP allow-list: {document}"
            )),
            404 => HostError::not_found("github resource", action)
                .with_hint("a private repository is a 404 to a token that cannot see it"),
            409 => HostError::conflict(action, None, None)
                .with_hint("the forge said the state moved; re-read and try again"),
            422 => HostError::invalid("github call", format!("{action}: {message}"))
                .with_hint(document),
            451 => HostError::denied(format!("{action}: the forge refuses this content (451)")),
            301 | 302 | 307 | 308 => HostError::invalid(
                "github api-base",
                format!(
                    "{action}: the forge answered {} and was not followed",
                    response.status
                ),
            )
            .with_hint(
                "a redirect is not followed because the Authorization header would go \
                 with it; fix `api-base` to the address the forge points at",
            ),
            status if (500..600).contains(&status) => unreachable(
                format!("the forge answered {status} to {action}"),
                None,
                true,
                "a forge-side failure: retry the command, and check githubstatus.com \
                 if it repeats",
            ),
            status => unreachable(
                format!("{action}: unexpected HTTP {status}"),
                None,
                false,
                "this is not a status the adapter knows how to read",
            ),
        }
    }
}

/// A ref move refused because the ref is not where we read it: the server's own
/// fast-forward check caught a writer we did not see.
///
/// The server does not say *what* it had, so `found` is `None` and the caller who
/// cares must re-read. That is a real gap against the `fs` and `s3` hosts and it is
/// documented in the crate docs rather than papered over.
pub fn ref_moved(name: &str, forge_words: Option<&str>) -> HostError {
    let mut hint = "the forge refused the move because the ref was not a fast-forward from what \
         we read: someone else moved it. Re-read the ref, rebuild on top of it, retry. \
         If the move you wanted is backwards (a rewind, a reset), that is a force-push \
         and gitiup will not do one silently: no gitiup flow needs it, and on this host \
         a forced ref is how an immutable history becomes a suggestable one."
        .to_string();
    if let Some(words) = forge_words {
        hint.push_str(&format!(" The forge's own words were: {words}"));
    }
    HostError::conflict(name.to_string(), None, None).with_hint(hint)
}

fn rate_limit_error(budget: &RateBudget, wait: Duration, options: &ClientOptions) -> HostError {
    unreachable(
        format!(
            "the forge's rate limit is spent ({}), so this call was not sent",
            budget.summary()
        ),
        None,
        true,
        format!(
            "it refills in about {}s; gitiup waits up to `rate-wait` = {}s and refuses \
             rather than sleeping a request away — with a token of your own the quota is \
             yours alone, and the workflow token is shared by everything in the run",
            wait.as_secs(),
            options.rate_wait.as_secs()
        ),
    )
}

/// Build an [`HostError::Unreachable`] with the endpoint and retryability spelled
/// out (the shorthand constructor leaves both at their defaults).
pub(crate) fn unreachable(
    message: impl Into<String>,
    endpoint: Option<String>,
    retryable: bool,
    hint: impl Into<String>,
) -> HostError {
    HostError::Unreachable(Box::new(gitiup_host::error::Unreachable {
        endpoint,
        message: message.into(),
        retryable,
        hint: Some(hint.into()),
        source: None,
    }))
}

/// Whether a response *is* a rate-limit answer.
///
/// GitHub uses 403 for the primary limit (with the headers to prove it), 429 for
/// the secondary limit, and 403 with a `Retry-After` for abuse detection — the
/// status alone cannot tell those from "you are not allowed here", and guessing
/// wrong turns a wait into a failure or a failure into a hang.
pub fn is_rate_limited(response: &Response) -> bool {
    if matches!(response.status, 403 | 429) {
        if response.header("retry-after").is_some() {
            return true;
        }
        if header_u32(response, "x-ratelimit-remaining") == Some(0) {
            return true;
        }
        return response.body_mentions(&[
            "rate limit",
            "secondary rate limit",
            "abuse detection",
            "use a small page count",
        ]);
    }
    false
}

/// How long the server asked us to wait.
pub fn retry_after(response: &Response) -> Option<Duration> {
    if let Some(seconds) = header_u64(response, "retry-after") {
        return Some(Duration::from_secs(seconds));
    }
    let reset = header_u64(response, "x-ratelimit-reset")?;
    let now = unix_now();
    Some(Duration::from_secs(
        reset.saturating_sub(now).saturating_add(1),
    ))
}

fn header_u64(response: &Response, name: &str) -> Option<u64> {
    response
        .header(name)
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn header_u32(response: &Response, name: &str) -> Option<u32> {
    header_u64(response, name).map(|value| value as u32)
}

/// Follow the `Link: rel="next"` header (RFC 5988, the shape GitHub sends).
fn next_link(response: &Response) -> HostResult<Option<String>> {
    let mut next: Option<String> = None;
    for value in response.headers_named("link") {
        for part in value.split(',') {
            let (target, rel) = match part.split_once(';') {
                Some(pair) => pair,
                None => continue,
            };
            let relates = rel
                .split(';')
                .any(|parameter| parameter.trim().eq_ignore_ascii_case("rel=\"next\""));
            if !relates {
                continue;
            }
            let target = target.trim();
            let target = target
                .strip_prefix('<')
                .and_then(|value| value.strip_suffix('>'))
                .or_else(|| Some(target.trim_matches('"')))
                .unwrap_or_default()
                .to_string();
            if target.is_empty() {
                return Err(HostError::invalid(
                    "github pagination",
                    format!("the Link header names a next page with no target: '{value}'"),
                ));
            }
            next = Some(target);
        }
    }
    Ok(next)
}

fn invalid_body(why: crate::transport::TransportError) -> HostError {
    HostError::invalid("github response", why.message).with_hint(
        why.hint
            .unwrap_or_else(|| "the API did not answer JSON".to_string()),
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitiup_host::HostErrorKind;

    #[test]
    fn a_github_url_becomes_a_repo_and_an_api_root() {
        let remote = RemoteConfig::new("origin", "https://github.com/gitiup/gitiup.git").unwrap();
        let repo = RepoRef::from_remote(&remote).unwrap();
        assert_eq!(repo.owner, "gitiup");
        assert_eq!(repo.repo, "gitiup");
        assert_eq!(repo.api_base, "https://api.github.com");
        assert_eq!(repo.api_host(), "api.github.com");

        let enterprise = RemoteConfig::new("ghe", "https://ghe.example.com/scm/team/tool.git")
            .unwrap()
            .with_option("api-base", "https://ghe.example.com/api/v3/");
        let repo = RepoRef::from_remote(&enterprise).unwrap();
        assert_eq!(repo.owner, "team");
        assert_eq!(repo.repo, "tool");
        assert_eq!(repo.api_base, "https://ghe.example.com/api/v3");

        {
            let bad = "https://github.com/onlyowner.git";
            let remote = RemoteConfig::new("origin", bad).unwrap();
            assert!(RepoRef::from_remote(&remote).is_err(), "{bad}");
        }
    }

    #[test]
    fn link_headers_are_followed_as_written() {
        let response = Response::new(200, b"[]".to_vec()).with_header(
            "Link",
            r#"<https://api.github.com/repos/o/r/pulls?page=2&per_page=100>; rel="next", <https://api.github.com/repos/o/r/pulls?page=9&per_page=100>; rel="last""#,
        );
        assert_eq!(
            next_link(&response).unwrap().unwrap(),
            "https://api.github.com/repos/o/r/pulls?page=2&per_page=100"
        );
        let last =
            Response::new(200, b"[]".to_vec()).with_header("Link", r#"<https://x/1>; rel="prev""#);
        assert_eq!(next_link(&last).unwrap(), None);
    }

    #[test]
    fn a_rate_limit_answer_is_recognised_three_ways() {
        let primary = Response::new(403, br#"{"message":"API rate limit exceeded"}"#.to_vec())
            .with_header("x-ratelimit-remaining", "0");
        assert!(is_rate_limited(&primary));
        let secondary = Response::new(
            429,
            br#"{"message":"You have exceeded a secondary rate limit"}"#.to_vec(),
        );
        assert!(is_rate_limited(&secondary));
        let abuse = Response::new(
            403,
            br#"{"message":"You have triggered an abuse detection mechanism"}"#.to_vec(),
        )
        .with_header("Retry-After", "30");
        assert!(is_rate_limited(&abuse));
        assert_eq!(retry_after(&abuse), Some(Duration::from_secs(30)));
        let forbidden = Response::new(
            403,
            br#"{"message":"Resource not accessible by integration"}"#.to_vec(),
        )
        .with_header("x-ratelimit-remaining", "4993");
        assert!(
            !is_rate_limited(&forbidden),
            "a real refusal must not be slept off"
        );
    }

    #[test]
    fn options_are_read_or_named_as_unused() {
        let remote = RemoteConfig::new("origin", "https://github.com/o/r.git")
            .unwrap()
            .with_option("per-page", "50")
            .with_option("rate-wait", "5s")
            .with_option("read-only", "true")
            .with_option("regIon", "eu-west-1");
        let options = ClientOptions::from_remote(&remote).unwrap();
        assert_eq!(options.per_page, 50);
        assert_eq!(options.rate_wait, Duration::from_secs(5));
        assert!(options.read_only);
        assert_eq!(options.unread_options, vec!["region"]);
        assert!(
            options
                .advice()
                .iter()
                .any(|line| line.contains("does not read")),
            "{:?}",
            options.advice()
        );
        assert!(
            ClientOptions::from_remote(
                &RemoteConfig::new("origin", "https://github.com/o/r.git")
                    .unwrap()
                    .with_option("per-page", "0")
            )
            .is_err()
        );
    }

    #[test]
    fn a_spent_budget_refuses_with_the_reset_time() {
        let repo = RepoRef {
            api_base: "https://api.github.com".into(),
            owner: "o".into(),
            repo: "r".into(),
            forge_host: "github.com".into(),
        };
        let options = ClientOptions {
            rate_reserve: 5,
            rate_wait: Duration::from_secs(1),
            ..Default::default()
        };
        let client = Client::new(
            repo,
            Auth::anonymous(),
            std::sync::Arc::new(crate::transport::RefusedTransport {
                reason: "unused".into(),
                hint: "unused".into(),
            }),
            options,
        );
        {
            let mut budget = client.rate.lock().unwrap();
            budget.remaining = Some(1);
            budget.reset_unix = Some(unix_now() + 3_600);
        }
        let err = client
            .send(client.request(Method::Get, "/", &[]))
            .unwrap_err();
        assert_eq!(err.kind(), HostErrorKind::Unreachable);
        assert!(err.to_string().contains("rate limit"), "{err}");
        assert!(err.hint().unwrap().contains("rate-wait"), "{err}");
    }
}

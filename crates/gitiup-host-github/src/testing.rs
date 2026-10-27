//! The test doubles: a forge that runs in this process, and the record/replay
//! transports that turn a session into fixtures.
//!
//! This module exists because the interesting behaviour of a forge adapter is not
//! the happy path. It is the *answers* a forge gives: a 422 that means "that ref
//! already exists" and a 422 that means "your JSON is wrong"; a 403 that is a spent
//! rate limit and a 403 that is a missing scope; page 2 of a listing; a secondary
//! rate limit with a `Retry-After`; a fast-forward refusal caused by a writer who
//! got there first. A live GitHub cannot be asked to produce those on demand, and a
//! test that needs them is not a test. So [`MockForge`] implements the *semantics*
//! of the endpoints this adapter drives — real create-only refusal, real
//! fast-forward checking over the commit graph it builds, real pagination with
//! `Link` headers, real rate-limit headers — and the adapter cannot tell it from
//! the forge.
//!
//! Object ids minted here are SHA-256 truncated to 20 bytes: git-shaped, stable,
//! and honestly not git's SHA-1, because this is a test double and not an object
//! database. Everything gitiup checks about content is still checked, because that
//! is what gitiup checks.
//!
//! [`Recorder`] wraps any transport and writes down what it sees; [`Fixtures`]
//! replays a recorded session and fails loudly, naming the call it did not expect,
//! when the adapter's requests drift. That pair is what "the adapter passes the
//! conformance suite against recorded HTTP fixtures" means in `tests/`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use gitiup_host::Oid;
use serde::{Deserialize, Serialize};

use crate::codec;
use crate::transport::{Request, Response, Transport, TransportError};

/// One recorded call and its answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interaction {
    /// `GET`, `POST`, …
    pub method: String,
    /// The full URL, exactly as sent (no credentials: the adapter never sends any
    /// in a URL).
    pub url: String,
    /// Request body, base64 (bodies are JSON today; base64 keeps binary safe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    /// Status received.
    pub status: u16,
    /// Headers received.
    #[serde(default)]
    pub response_headers: Vec<(String, String)>,
    /// Body received, base64.
    pub response_body: String,
}

impl Interaction {
    /// Record a call and its answer.
    pub fn new(request: &Request, response: &Response) -> Interaction {
        Interaction {
            method: request.method.as_str().to_string(),
            url: request.url.clone(),
            request_body: request.body.as_ref().map(|body| codec::encode_base64(body)),
            status: response.status,
            response_headers: response.headers.clone(),
            response_body: codec::encode_base64(&response.body),
        }
    }

    /// The answer this interaction would give.
    pub fn response(&self) -> Response {
        Response {
            status: self.status,
            headers: self.response_headers.clone(),
            body: codec::decode_base64(&self.response_body).unwrap_or_default(),
        }
    }

    /// One line of a fixture file.
    pub fn to_json_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_else(|_| "{}".into());
        line.push('\n');
        line
    }

    /// Parse one line of a fixture file.
    pub fn from_json_line(line: &str) -> Result<Interaction, String> {
        serde_json::from_str(line.trim()).map_err(|why| why.to_string())
    }
}

/// A transport that records everything passing through it.
#[derive(Clone)]
pub struct Recorder {
    inner: Arc<dyn Transport>,
    log: Arc<Mutex<Vec<Interaction>>>,
}

impl Recorder {
    /// Wrap a transport.
    pub fn new(inner: Arc<dyn Transport>) -> Recorder {
        Recorder {
            inner,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Everything recorded so far.
    pub fn interactions(&self) -> Vec<Interaction> {
        self.log.lock().expect("recorder lock").clone()
    }

    /// Write the recording into `dir` as a JSON-lines file.
    pub fn save(&self, dir: &Path, name: &str) -> std::io::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{name}.jsonl"));
        let mut file = std::fs::File::create(&path)?;
        for interaction in self.interactions() {
            file.write_all(interaction.to_json_line().as_bytes())?;
        }
        Ok(path)
    }
}

impl Transport for Recorder {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let response = self.inner.send(request)?;
        self.log
            .lock()
            .expect("recorder lock")
            .push(Interaction::new(request, &response));
        Ok(response)
    }

    fn describe(&self) -> String {
        format!("recording over {}", self.inner.describe())
    }
}

/// A transport that replays a recorded session.
///
/// Matching is *in order*, because a recorded session is a script: the run that
/// produced it made exactly these calls in this order. A call that does not match is
/// reported with both sides printed — a fixture that no longer matches the adapter
/// is a finding, and silently matching something else is how a fixture rots.
pub struct Fixtures {
    interactions: Vec<Interaction>,
    position: Mutex<usize>,
    /// Where the file came from, for the error message.
    pub source: String,
}

impl Fixtures {
    /// Load a fixture file (JSON lines).
    pub fn load(path: &Path) -> Result<Fixtures, String> {
        let text = std::fs::read_to_string(path).map_err(|why| format!("{path:?}: {why}"))?;
        let mut interactions = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            interactions.push(
                Interaction::from_json_line(line)
                    .map_err(|why| format!("{path:?}:{}: {why}", index + 1))?,
            );
        }
        if interactions.is_empty() {
            return Err(format!("{path:?}: no recorded interactions"));
        }
        Ok(Fixtures {
            interactions,
            position: Mutex::new(0),
            source: path.display().to_string(),
        })
    }

    /// A transport over interactions already in memory.
    pub fn new(interactions: Vec<Interaction>, source: impl Into<String>) -> Fixtures {
        Fixtures {
            interactions,
            position: Mutex::new(0),
            source: source.into(),
        }
    }

    /// How many were consumed.
    pub fn consumed(&self) -> usize {
        *self.position.lock().expect("fixture cursor")
    }

    /// How many there are.
    pub fn len(&self) -> usize {
        self.interactions.len()
    }

    /// Whether the file was empty.
    pub fn is_empty(&self) -> bool {
        self.interactions.is_empty()
    }
}

impl Transport for Fixtures {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let mut position = self.position.lock().expect("fixture cursor");
        let want = request.method.as_str();
        for index in *position..self.interactions.len() {
            let candidate = &self.interactions[index];
            if candidate.method == want && candidate.url == request.url {
                *position = index + 1;
                return Ok(candidate.response());
            }
        }
        let next = self.interactions.get(*position);
        Err(TransportError::new(format!(
            "{}: no recorded answer for {} ({} of {} consumed; next recorded: {})",
            self.source,
            request.summary(),
            *position,
            self.interactions.len(),
            next.map(|found| format!("{} {}", found.method, found.url))
                .unwrap_or_else(|| "nothing".to_string())
        ))
        .retryable(false)
        .with_hint(
            "the adapter's requests no longer match what was recorded: re-record the \
             session, and read the diff first — an unintended extra call is a bug in \
             the adapter, not in the fixture",
        ))
    }

    fn describe(&self) -> String {
        format!("recorded fixtures at {}", self.source)
    }
}

// ---------------------------------------------------------------------------
// the mock forge
// ---------------------------------------------------------------------------

/// The knobs a test turns on the forge.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Owner.
    pub owner: String,
    /// Repository.
    pub repo: String,
    /// Default branch name.
    pub default_branch: String,
    /// Whether a write without an `Authorization` header is refused (GitHub's
    /// answer is a 401, which the adapter must read as *credentials*, not as
    /// *unreachable*).
    pub require_token: bool,
    /// Quota per window.
    pub rate_limit: u32,
    /// Refuse with a rate-limit error from this request number on.
    pub rate_exhausted_from: Option<usize>,
    /// Answer the next write with a secondary rate limit and this `Retry-After`.
    pub secondary_retry_after: Option<u64>,
    /// What the credential may do.
    pub may_push: bool,
    /// Entries per page for paginated listings.
    pub per_page: usize,
}

impl Default for MockConfig {
    fn default() -> MockConfig {
        MockConfig {
            owner: "gitiup".into(),
            repo: "mock".into(),
            default_branch: "main".into(),
            require_token: true,
            rate_limit: 5_000,
            rate_exhausted_from: None,
            secondary_retry_after: None,
            may_push: true,
            per_page: 3,
        }
    }
}

/// The in-process forge.
pub struct MockForge {
    config: MockConfig,
    state: Mutex<State>,
    /// Answer the next `n` reads with a 500 (a flaky forge the client should retry
    /// once and then report).
    server_errors: AtomicUsize,
}

#[derive(Default)]
struct State {
    refs: BTreeMap<String, String>,
    blobs: BTreeMap<String, Vec<u8>>,
    trees: BTreeMap<String, Vec<StoredEntry>>,
    commits: BTreeMap<String, StoredCommit>,
    pulls: Vec<serde_json::Value>,
    check_runs: Vec<serde_json::Value>,
    remaining: u32,
    requests: usize,
    next_pull: u64,
    next_check: u64,
    secondary_pending: Option<u64>,
    rate_exhausted_from: Option<usize>,
    /// Every call answered, as `(method, path)`, for assertions.
    seen: Vec<(String, String)>,
}

/// A stored tree entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEntry {
    /// Path inside the tree.
    pub path: String,
    /// Mode, e.g. `100644`.
    pub mode: String,
    /// `blob` or `tree`.
    pub obj_type: String,
    /// The object id.
    pub sha: String,
    /// Byte size, for blobs.
    pub size: u64,
}

/// A stored commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommit {
    /// Its id.
    pub sha: String,
    /// The message.
    pub message: String,
    /// Its root tree.
    pub tree: String,
    /// Parents.
    pub parents: Vec<String>,
    /// Author name.
    pub author: String,
    /// Author date, as sent.
    pub date: String,
}

impl MockForge {
    /// A fresh forge.
    pub fn new() -> Arc<MockForge> {
        MockForge::configured(MockConfig::default())
    }

    /// A forge with the given configuration.
    pub fn configured(config: MockConfig) -> Arc<MockForge> {
        let remaining = config.rate_limit;
        let secondary_pending = config.secondary_retry_after;
        Arc::new(MockForge {
            config,
            state: Mutex::new(State {
                remaining,
                next_pull: 1,
                next_check: 1,
                secondary_pending,
                ..Default::default()
            }),
            server_errors: AtomicUsize::new(0),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &MockConfig {
        &self.config
    }

    /// Seed a branch with one commit holding `content`.
    pub fn seed_branch(&self, branch: &str, content: &[u8]) -> String {
        let mut state = self.state.lock().expect("mock state");
        let blob = put_blob(&mut state, content);
        let tree = put_tree(
            &mut state,
            None,
            vec![StoredEntry {
                path: "README.md".into(),
                mode: "100644".into(),
                obj_type: "blob".into(),
                sha: blob.clone(),
                size: content.len() as u64,
            }],
        );
        let commit = put_commit(
            &mut state,
            "initial commit",
            &tree,
            &[],
            "mock",
            "2026-01-01T00:00:00Z",
        );
        state
            .refs
            .insert(format!("refs/heads/{branch}"), commit.clone());
        commit
    }

    /// The commits the forge holds, newest minted last.
    pub fn commits(&self) -> Vec<StoredCommit> {
        self.state
            .lock()
            .expect("mock state")
            .commits
            .values()
            .cloned()
            .collect()
    }

    /// The refs the forge holds now.
    pub fn refs(&self) -> BTreeMap<String, String> {
        self.state.lock().expect("mock state").refs.clone()
    }

    /// Every call answered, as `(method, path)`.
    pub fn seen(&self) -> Vec<(String, String)> {
        self.state.lock().expect("mock state").seen.clone()
    }

    /// How many calls it answered.
    pub fn requests(&self) -> usize {
        self.state.lock().expect("mock state").requests
    }

    /// Answer the next `count` reads with a 500.
    pub fn set_server_errors(&self, count: usize) {
        self.server_errors.store(count, Ordering::SeqCst);
    }

    /// Refuse with a rate-limit error from this request number on (GitHub's primary
    /// limit is a 403 that says "rate limit" and carries `x-ratelimit-remaining: 0`,
    /// which is exactly the answer a client must not read as "no permission").
    pub fn exhaust_rate_limit_from(&self, request_number: usize) {
        let mut state = self.state.lock().expect("mock state");
        state.remaining = 0;
        state.rate_exhausted_from = Some(request_number);
    }

    /// Answer the next write with a secondary rate limit and this `Retry-After`.
    pub fn secondary_rate_limit(&self, retry_after: u64) {
        self.state.lock().expect("mock state").secondary_pending = Some(retry_after);
    }

    /// A transport over this forge.
    pub fn transport(self: &Arc<Self>) -> Arc<ForgeTransport> {
        ForgeTransport::new(Arc::clone(self))
    }

    /// Commit `content` on top of `parent` and return the new commit's id.
    ///
    /// Tests need to build real history (a forward move and a rewind are the two
    /// answers the adapter behaves differently for) without reaching inside the
    /// mock's state.
    pub fn commit_on(&self, parent: &str, content: &[u8]) -> String {
        let mut state = self.state.lock().expect("mock state");
        let blob = put_blob(&mut state, content);
        let tree = put_tree(
            &mut state,
            None,
            vec![StoredEntry {
                path: "README.md".into(),
                mode: "100644".into(),
                obj_type: "blob".into(),
                sha: blob,
                size: content.len() as u64,
            }],
        );
        put_commit(
            &mut state,
            "committed from a test",
            &tree,
            &[parent.to_string()],
            "tester",
            "2026-01-01T00:00:00Z",
        )
    }

    /// Open a pull request from the outside — what a contributor does in the
    /// browser, and what the change-feed tests need.
    pub fn open_pull(&self, number: u64, title: &str, head_sha: &str, updated_at: &str) {
        let mut state = self.state.lock().expect("mock state");
        state.pulls.push(serde_json::json!({
            "number": number,
            "state": "open",
            "title": title,
            "body": "",
            "draft": false,
            "user": {"login": "contributor"},
            "created_at": updated_at,
            "updated_at": updated_at,
            "merged_at": null,
            "html_url": format!("https://github.com/{}/{}/pull/{number}", self.config.owner, self.config.repo),
            "base": {"ref": self.config.default_branch, "sha": head_sha},
            "head": {
                "ref": format!("change-{number}"),
                "sha": head_sha,
                "repo": {"full_name": format!("contributor/{}", self.config.repo)},
            },
            "labels": [],
        }));
        state.next_pull = state.next_pull.max(number + 1);
    }

    /// Publish a check run from the outside: a runner that advertised an
    /// attestation and never got store access. With `truncate` the copy in the
    /// output is cut short, which is what a check run that ran past the forge's
    /// output limit looks like — the adapter must report that as *not* the bytes,
    /// never as a near miss.
    pub fn publish_check_run_only(&self, subject: &Oid, bytes: &[u8], truncate: bool) {
        let digest = Oid::hash_bytes(bytes);
        let mut encoded = codec::encode_base64(bytes);
        if truncate {
            // Half of it, on a boundary that is not a whole base64 group: that is
            // what a truncated output looks like — it does not decode cleanly.
            let keep = (encoded.len() / 2) | 1;
            encoded.truncate(keep.max(1));
        }
        let summary = format!("gitiup attestation copy\n\n```base64\n{encoded}\n```\n");
        let mut state = self.state.lock().expect("mock state");
        let id = state.next_check;
        state.next_check += 1;
        state.check_runs.push(serde_json::json!({
            "id": id,
            "name": "gitiup/attest",
            "head_sha": subject.hex(),
            "external_id": digest.hex(),
            "status": "completed",
            "conclusion": "success",
            "details_url": null,
            "output": {"summary": summary},
            "created_at": "2026-01-01T00:00:00Z",
        }));
    }

    /// The check runs the forge holds.
    pub fn check_runs(&self) -> Vec<serde_json::Value> {
        self.state.lock().expect("mock state").check_runs.clone()
    }

    /// The pull requests the forge holds.
    pub fn pulls(&self) -> Vec<serde_json::Value> {
        self.state.lock().expect("mock state").pulls.clone()
    }

    /// Answer one request. Everything the adapter sees of the forge comes through
    /// here.
    fn answer(&self, request: &Request) -> Response {
        let Some((_, path_and_query)) = codec::split_url(&request.url) else {
            return self.error(request, 400, "the mock only answers absolute URLs");
        };
        let (raw_path, raw_query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, query),
            None => (path_and_query, ""),
        };
        let query = parse_query(raw_query);
        let method = request.method.as_str().to_string();
        let mut state = self.state.lock().expect("mock state");
        state.requests += 1;
        state
            .seen
            .push((method.clone(), raw_path.trim_matches('/').to_string()));
        if state.remaining > 0 {
            state.remaining -= 1;
        }
        let reset = unix_now() + 3_600;
        let headers = |state: &State| {
            vec![
                (
                    "x-ratelimit-limit".to_string(),
                    self.config.rate_limit.to_string(),
                ),
                (
                    "x-ratelimit-remaining".to_string(),
                    state.remaining.to_string(),
                ),
                ("x-ratelimit-reset".to_string(), reset.to_string()),
                ("x-ratelimit-resource".to_string(), "core".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ]
        };
        let decorate = |response: Response, state: &State| {
            let mut response = response;
            for (name, value) in headers(state) {
                response.push_header(name, value);
            }
            response
        };

        // The failure modes a live forge produces and a test needs on demand.
        if let Some(from) = state
            .rate_exhausted_from
            .or(self.config.rate_exhausted_from)
            && state.requests >= from
        {
            state.remaining = 0;
            return decorate(
                Response::new(
                    403,
                    br#"{"message":"API rate limit exceeded for gitiup-mock."}"#.to_vec(),
                ),
                &state,
            );
        }
        if method != "GET" && self.server_errors.load(Ordering::SeqCst) == usize::MAX {
            return decorate(
                Response::new(500, br#"{"message":"boom"}"#.to_vec()),
                &state,
            );
        }
        if method != "GET"
            && let Some(after) = state.secondary_pending.take()
        {
            let mut response = Response::new(
                429,
                br#"{"message":"You have exceeded a secondary rate limit. Please wait a while."}"#
                    .to_vec(),
            );
            response.push_header("retry-after", after.to_string());
            return decorate(response, &state);
        }
        if method == "GET" && self.server_errors.load(Ordering::SeqCst) > 0 {
            self.server_errors.fetch_sub(1, Ordering::SeqCst);
            return decorate(
                Response::new(500, br#"{"message":"internal error (mock)"}"#.to_vec()),
                &state,
            );
        }
        if self.config.require_token
            && method != "GET"
            && !request
                .header("authorization")
                .is_some_and(|value| value.starts_with("Bearer ") && value.len() > 8)
        {
            return decorate(
                Response::new(401, br#"{"message":"Requires authentication"}"#.to_vec()),
                &state,
            );
        }
        if !self.config.may_push && method != "GET" {
            return decorate(
                Response::new(
                    403,
                    br#"{"message":"Resource not accessible by integration"}"#.to_vec(),
                ),
                &state,
            );
        }

        let response = self.route(
            &mut state,
            &method,
            raw_path.trim_matches('/'),
            &query,
            request,
        );
        decorate(response, &state)
    }

    fn route(
        &self,
        state: &mut State,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        request: &Request,
    ) -> Response {
        // `/rate_limit` is not repository-scoped.
        if path == "rate_limit" {
            return json(
                200,
                serde_json::json!({
                    "resources": {
                        "core": {
                            "limit": self.config.rate_limit,
                            "remaining": state.remaining,
                            "reset": unix_now() + 3_600,
                        }
                    }
                }),
            );
        }
        let prefix = format!("repos/{}/{}/", self.config.owner, self.config.repo);
        let Some(tail) = path.strip_prefix(&prefix) else {
            if path == prefix.trim_end_matches('/') {
                return json(
                    200,
                    serde_json::json!({
                        "full_name": format!("{}/{}", self.config.owner, self.config.repo),
                        "default_branch": self.config.default_branch,
                        "fork": false,
                        "private": false,
                        "permissions": {
                            "admin": false,
                            "push": self.config.may_push,
                            "pull": true,
                        },
                    }),
                );
            }
            return self.error(request, 404, &format!("mock forge has no route /{path}"));
        };
        let (head, rest) = tail.split_once('/').unwrap_or((tail, ""));
        match (method, head, rest) {
            ("GET", "git", rest) => self.git_get(state, rest, query),
            ("POST", "git", rest) => self.git_post(state, rest, request),
            ("PATCH", "git", rest) => self.git_patch(state, rest, request),
            ("DELETE", "git", rest) => self.git_delete(state, rest),
            ("GET", "pulls", "") => self.pulls_get(state, query, request),
            ("GET", "pulls", rest) => {
                let Ok(number) = rest.parse::<u64>() else {
                    return self.error(request, 404, "pull numbers are integers");
                };
                match state.pulls.iter().find(|pull| pull["number"] == number) {
                    Some(pull) => json(200, pull.clone()),
                    None => json(404, serde_json::json!({"message": "Not Found"})),
                }
            }
            ("GET", "check-runs", _) => self.check_runs_get(state, query),
            ("POST", "check-runs", _) => self.check_runs_post(state, request),
            ("POST", "pulls", _) => self.pulls_post(state, request),
            ("PATCH", "pulls", rest) => {
                let Some(number) = rest.parse::<u64>().ok() else {
                    return json(404, serde_json::json!({"message": "Not Found"}));
                };
                let Some(body) = body_json(request) else {
                    return json(
                        422,
                        serde_json::json!({"message": "Body does not look like JSON"}),
                    );
                };
                let Some(pull) = state.pulls.iter_mut().find(|pull| pull["number"] == number)
                else {
                    return json(404, serde_json::json!({"message": "Not Found"}));
                };
                if let Some(value) = body.get("state").and_then(|value| value.as_str()) {
                    // Closing is not merging: the forge sets `merged_at` only for a
                    // merge (`PUT /pulls/<n>/merge`), and a client that reads a
                    // closed change as a merged one reports work that never landed.
                    pull["state"] = serde_json::Value::String(value.to_string());
                }
                pull["updated_at"] = serde_json::Value::String("2026-01-01T00:00:00Z".into());
                json(200, pull.clone())
            }
            _ => json(
                404,
                serde_json::json!({"message": format!("mock forge: no route for {method} /{tail}")}),
            ),
        }
    }

    fn error(&self, request: &Request, status: u16, message: &str) -> Response {
        let _ = request;
        json(status, serde_json::json!({"message": message}))
    }

    fn git_get(&self, state: &State, rest: &str, query: &BTreeMap<String, String>) -> Response {
        // `git/matching-refs` with no prefix at all is how some clients ask for
        // every ref; the forge answers it the same as `matching-refs/`.
        let (kind, tail) = match rest.split_once('/') {
            Some(split) => split,
            None => (rest, ""),
        };
        match (kind, tail) {
            ("matching-refs", prefix) => {
                let prefix = percent_decode(prefix);
                let mut names: Vec<&String> = state
                    .refs
                    .keys()
                    .filter(|name| {
                        prefix.is_empty()
                            || **name == prefix
                            || name.starts_with(&format!("{prefix}/"))
                    })
                    .collect();
                names.sort();
                let items: Vec<serde_json::Value> = names
                    .iter()
                    .map(|name| {
                        serde_json::json!({
                            "ref": **name,
                            "object": {"sha": state.refs[*name], "type": "commit"},
                        })
                    })
                    .collect();
                self.page(
                    items,
                    query,
                    &format!(
                        "https://api.github.com/repos/{}/{}/git/matching-refs/{prefix}",
                        self.config.owner, self.config.repo
                    ),
                )
            }
            ("ref", name) => {
                let name = percent_decode(name);
                match state.refs.get(&name) {
                    Some(sha) => json(
                        200,
                        serde_json::json!({"ref": name, "object": {"sha": sha, "type": "commit"}}),
                    ),
                    None => json(
                        404,
                        serde_json::json!({"message": "Not Found", "documentation_url": "https://docs.github.com/rest/git/refs#get-a-reference"}),
                    ),
                }
            }
            ("blobs", sha) => match state.blobs.get(sha) {
                Some(content) => json(
                    200,
                    serde_json::json!({
                        "sha": sha,
                        "size": content.len(),
                        "encoding": "base64",
                        "content": codec::encode_base64(content),
                    }),
                ),
                None => json(404, serde_json::json!({"message": "Not Found"})),
            },
            ("trees", sha) => {
                let sha = sha.to_string();
                let tree_sha = match (state.trees.contains_key(&sha), state.commits.get(&sha)) {
                    (true, _) => Some(sha.clone()),
                    (false, Some(commit)) => Some(commit.tree.clone()),
                    _ => None,
                };
                match tree_sha {
                    None => json(404, serde_json::json!({"message": "Not Found"})),
                    Some(sha) => {
                        let entries = state.trees.get(&sha).cloned().unwrap_or_default();
                        json(
                            200,
                            serde_json::json!({
                                "sha": sha,
                                "truncated": false,
                                "tree": entries.iter().map(entry_json).collect::<Vec<_>>(),
                            }),
                        )
                    }
                }
            }
            ("commits", sha) => match state.commits.get(sha) {
                None => json(404, serde_json::json!({"message": "Not Found"})),
                Some(commit) => json(
                    200,
                    serde_json::json!({
                        "sha": commit.sha,
                        "commit": {
                            "message": commit.message,
                            "tree": {"sha": commit.tree},
                            "author": {"name": commit.author, "email": "mock@gitiup.invalid", "date": commit.date},
                        },
                        "parents": commit.parents.iter().map(|sha| serde_json::json!({"sha": sha})).collect::<Vec<_>>(),
                    }),
                ),
            },
            _ => json(404, serde_json::json!({"message": "Not Found"})),
        }
    }

    fn git_post(&self, state: &mut State, rest: &str, request: &Request) -> Response {
        let body = match body_json(request) {
            Some(body) => body,
            None => {
                return json(
                    422,
                    serde_json::json!({"message": "Body does not look like JSON", "documentation_url": "https://docs.github.com/rest"}),
                );
            }
        };
        match rest {
            // Create a ref: the one atomic write the forge offers.
            "refs" => {
                let Some(name) = body.get("ref").and_then(|value| value.as_str()) else {
                    return json(
                        422,
                        serde_json::json!({"message": "Invalid request: `ref` was not given"}),
                    );
                };
                let Some(sha) = body.get("sha").and_then(|value| value.as_str()) else {
                    return json(
                        422,
                        serde_json::json!({"message": "Invalid request: `sha` was not given"}),
                    );
                };
                if !state.commits.contains_key(sha) && !state.blobs.contains_key(sha) {
                    return json(
                        422,
                        serde_json::json!({"message": format!("object {sha} does not exist")}),
                    );
                }
                if state.refs.contains_key(name) {
                    return json(
                        422,
                        serde_json::json!({
                            "message": "Reference already exists",
                            "errors": [{"resource": "Git", "field": "ref", "code": "custom", "message": "ref already exists"}],
                        }),
                    );
                }
                state.refs.insert(name.to_string(), sha.to_string());
                json(
                    201,
                    serde_json::json!({"ref": name, "object": {"sha": sha, "type": "commit"}}),
                )
            }
            "blobs" => {
                let encoded = body
                    .get("content")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let bytes = match body
                    .get("encoding")
                    .and_then(|value| value.as_str())
                    .unwrap_or("base64")
                {
                    "base64" => codec::decode_base64(encoded).unwrap_or_default(),
                    "utf-8" => encoded.as_bytes().to_vec(),
                    other => {
                        return json(
                            422,
                            serde_json::json!({"message": format!("unknown encoding '{other}'")}),
                        );
                    }
                };
                let sha = put_blob(state, &bytes);
                json(201, serde_json::json!({"sha": sha}))
            }
            "trees" => {
                let base = body
                    .get("base_tree")
                    .and_then(|value| value.as_str())
                    .map(str::to_string);
                let base_entries = base
                    .as_deref()
                    .and_then(|sha| state.trees.get(sha))
                    .cloned()
                    .unwrap_or_default();
                if let Some(sha) = &base
                    && !state.trees.contains_key(sha)
                {
                    return json(
                        422,
                        serde_json::json!({"message": format!("base_tree {sha} does not exist")}),
                    );
                }
                let Some(entries) = body.get("tree").and_then(|value| value.as_array()) else {
                    return json(
                        422,
                        serde_json::json!({"message": "Invalid request: `tree` was not given"}),
                    );
                };
                let mut merged = base_entries;
                for entry in entries {
                    let path = entry
                        .get("path")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let (sha, size) = match entry.get("sha").and_then(|value| value.as_str()) {
                        Some(sha) => (
                            sha.to_string(),
                            state.blobs.get(sha).map_or(0, |bytes| bytes.len()) as u64,
                        ),
                        None => {
                            // Inline content: the forge makes the blob itself.
                            let text = entry
                                .get("content")
                                .and_then(|value| value.as_str())
                                .unwrap_or("");
                            let bytes = match entry.get("encoding").and_then(|value| value.as_str())
                            {
                                Some("base64") => codec::decode_base64(text).unwrap_or_default(),
                                _ => text.as_bytes().to_vec(),
                            };
                            let sha = put_blob(state, &bytes);
                            (sha, bytes.len() as u64)
                        }
                    };
                    merged.retain(|existing| existing.path != path);
                    merged.push(StoredEntry {
                        path: path.to_string(),
                        mode: entry
                            .get("mode")
                            .and_then(|value| value.as_str())
                            .unwrap_or("100644")
                            .to_string(),
                        obj_type: entry
                            .get("type")
                            .and_then(|value| value.as_str())
                            .unwrap_or("blob")
                            .to_string(),
                        sha,
                        size,
                    });
                }
                let sha = put_tree(state, None, merged);
                json(201, serde_json::json!({"sha": sha}))
            }
            "commits" => {
                let message = body
                    .get("message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let tree = body
                    .get("tree")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if !state.trees.contains_key(tree) {
                    return json(
                        422,
                        serde_json::json!({"message": format!("tree {tree} does not exist")}),
                    );
                }
                let parents: Vec<String> = body
                    .get("parents")
                    .and_then(|value| value.as_array())
                    .map(|array| {
                        array
                            .iter()
                            .filter_map(|parent| parent.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                for parent in &parents {
                    if !state.commits.contains_key(parent) {
                        return json(
                            422,
                            serde_json::json!({"message": format!("parent {parent} does not exist")}),
                        );
                    }
                }
                let author = &body["author"];
                let commit = put_commit(
                    state,
                    message,
                    tree,
                    &parents,
                    author
                        .get("name")
                        .and_then(|value| value.as_str())
                        .unwrap_or("gitiup"),
                    author
                        .get("date")
                        .and_then(|value| value.as_str())
                        .unwrap_or("1970-01-01T00:00:00Z"),
                );
                json(201, serde_json::json!({"sha": commit}))
            }
            _ => json(404, serde_json::json!({"message": "Not Found"})),
        }
    }

    fn git_patch(&self, state: &mut State, rest: &str, request: &Request) -> Response {
        let Some(("ref", name)) = rest.split_once('/') else {
            return json(404, serde_json::json!({"message": "Not Found"}));
        };
        let name = percent_decode(name);
        let Some(body) = body_json(request) else {
            return json(
                422,
                serde_json::json!({"message": "Body does not look like JSON"}),
            );
        };
        let Some(sha) = body.get("sha").and_then(|value| value.as_str()) else {
            return json(
                422,
                serde_json::json!({"message": "Invalid request: `sha` was not given"}),
            );
        };
        let force = body
            .get("force")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let Some(current) = state.refs.get(&name).cloned() else {
            return json(404, serde_json::json!({"message": "Not Found"}));
        };
        if !state.commits.contains_key(sha) {
            return json(
                422,
                serde_json::json!({"message": format!("object {sha} does not exist")}),
            );
        }
        if !force && !is_descendant(state, sha, &current) {
            // This is the refusal that makes `force = false` a compare-and-swap.
            return json(
                422,
                serde_json::json!({
                    "message": "Updating is only allowed with force set to true.",
                    "errors": [{"resource": "Ref", "code": "custom", "field": "force"}],
                }),
            );
        }
        state.refs.insert(name.clone(), sha.to_string());
        json(
            200,
            serde_json::json!({"ref": name, "object": {"sha": sha, "type": "commit"}}),
        )
    }

    fn git_delete(&self, state: &mut State, rest: &str) -> Response {
        let Some(("ref", name)) = rest.split_once('/') else {
            return json(404, serde_json::json!({"message": "Not Found"}));
        };
        let name = percent_decode(name);
        match state.refs.remove(&name) {
            Some(_) => Response::new(204, Vec::new()),
            None => json(404, serde_json::json!({"message": "Not Found"})),
        }
    }

    fn pulls_get(
        &self,
        state: &State,
        query: &BTreeMap<String, String>,
        _request: &Request,
    ) -> Response {
        let state_filter = query
            .get("state")
            .cloned()
            .unwrap_or_else(|| "open".to_string());
        let mut pulls: Vec<&serde_json::Value> = state
            .pulls
            .iter()
            .filter(|pull| match state_filter.as_str() {
                "all" => true,
                "open" => pull["state"] == "open",
                _ => pull["state"] != "open",
            })
            .collect();
        pulls.sort_by(|a, b| {
            b["updated_at"]
                .as_str()
                .unwrap_or("")
                .cmp(a["updated_at"].as_str().unwrap_or(""))
        });
        let items: Vec<serde_json::Value> = pulls.into_iter().cloned().collect();
        self.page(
            items,
            query,
            &format!(
                "https://api.github.com/repos/{}/{}/pulls",
                self.config.owner, self.config.repo
            ),
        )
    }

    fn pulls_post(&self, state: &mut State, request: &Request) -> Response {
        let Some(body) = body_json(request) else {
            return json(
                422,
                serde_json::json!({"message": "Body does not look like JSON"}),
            );
        };
        let title = body
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if title.is_empty() {
            return json(
                422,
                serde_json::json!({"message": "Validation Failed", "errors": [{"field": "title", "code": "missing_field"}]}),
            );
        }
        let number = state.next_pull;
        state.next_pull += 1;
        let head = body
            .get("head")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let base = body
            .get("base")
            .and_then(|value| value.as_str())
            .unwrap_or(&self.config.default_branch);
        let head_sha = mint_sha(head.as_bytes());
        let base_sha = state
            .refs
            .get(&format!("refs/heads/{base}"))
            .cloned()
            .unwrap_or_else(|| mint_sha(base.as_bytes()));
        let pull = serde_json::json!({
            "number": number,
            "state": "open",
            "title": title,
            "body": body.get("body").and_then(|value| value.as_str()).unwrap_or(""),
            "draft": body.get("draft").and_then(|value| value.as_bool()).unwrap_or(false),
            "user": {"login": "gitiup"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "merged_at": null,
            "html_url": format!("https://github.com/{}/{}/pull/{number}", self.config.owner, self.config.repo),
            "base": {"ref": base, "sha": base_sha},
            "head": {"ref": head, "sha": head_sha, "repo": {"full_name": format!("{}/{}", self.config.owner, self.config.repo)}},
            "labels": [],
        });
        state.pulls.push(pull.clone());
        json(201, pull)
    }

    fn check_runs_get(&self, state: &State, query: &BTreeMap<String, String>) -> Response {
        let wanted = query.get("check_name").cloned();
        let runs: Vec<serde_json::Value> = state
            .check_runs
            .iter()
            .filter(|run| match &wanted {
                Some(name) => run["name"] == name.as_str(),
                None => true,
            })
            .cloned()
            .collect();
        json(
            200,
            serde_json::json!({"total_count": runs.len(), "check_runs": runs}),
        )
    }

    fn check_runs_post(&self, state: &mut State, request: &Request) -> Response {
        let Some(body) = body_json(request) else {
            return json(
                422,
                serde_json::json!({"message": "Body does not look like JSON"}),
            );
        };
        let id = state.next_check;
        state.next_check += 1;
        let created = serde_json::json!({
            "id": id,
            "name": body.get("name").and_then(|value| value.as_str()).unwrap_or(""),
            "head_sha": body.get("head_sha").and_then(|value| value.as_str()).unwrap_or(""),
            "external_id": body.get("external_id").and_then(|value| value.as_str()),
            "status": body.get("status").and_then(|value| value.as_str()).unwrap_or("completed"),
            "conclusion": body.get("conclusion").and_then(|value| value.as_str()),
            "details_url": body.get("details_url").and_then(|value| value.as_str()),
            "html_url": format!("https://github.com/{}/{}/check-runs/{id}", self.config.owner, self.config.repo),
            "output": body.get("output").cloned().unwrap_or(serde_json::Value::Null),
            "created_at": "2026-01-01T00:00:00Z",
        });
        state.check_runs.push(created.clone());
        json(201, created)
    }

    /// Paginate a listing exactly as the forge does: `page`/`per_page` in, a
    /// `Link: rel="next"` out when there is a next page. The total is passed in
    /// because that is what the forge knows and the page does not.
    fn page(
        &self,
        items: Vec<serde_json::Value>,
        query: &BTreeMap<String, String>,
        base: &str,
    ) -> Response {
        let total = items.len();
        let per_page = query
            .get("per_page")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(self.config.per_page)
            .max(1);
        let page = query
            .get("page")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let start = (page - 1) * per_page;
        let slice: Vec<serde_json::Value> = items.into_iter().skip(start).take(per_page).collect();
        let mut response = json(200, serde_json::Value::Array(slice.clone()));
        if start + slice.len() < total {
            let next = format!("{base}?per_page={per_page}&page={}", page + 1);
            response.push_header(
                "Link",
                format!("<{next}>; rel=\"next\", <{next}>; rel=\"last\""),
            );
        }
        response
    }
}

/// Whether `candidate` descends from `ancestor` in the mock's commit graph.
fn is_descendant(state: &State, candidate: &str, ancestor: &str) -> bool {
    if candidate == ancestor {
        return true;
    }
    let mut queue: Vec<String> = state
        .commits
        .get(candidate)
        .map(|commit| commit.parents.clone())
        .unwrap_or_default();
    let mut seen: Vec<String> = vec![candidate.to_string()];
    while let Some(sha) = queue.pop() {
        if sha == ancestor {
            return true;
        }
        if seen.contains(&sha) {
            continue;
        }
        seen.push(sha.clone());
        if let Some(commit) = state.commits.get(&sha) {
            queue.extend(commit.parents.iter().cloned());
        }
    }
    false
}

fn entry_json(entry: &StoredEntry) -> serde_json::Value {
    serde_json::json!({
        "path": entry.path,
        "mode": entry.mode,
        "type": entry.obj_type,
        "sha": entry.sha,
        "size": entry.size,
    })
}

fn put_blob(state: &mut State, bytes: &[u8]) -> String {
    let sha = mint_sha(bytes);
    state.blobs.insert(sha.clone(), bytes.to_vec());
    sha
}

fn put_tree(state: &mut State, _base: Option<&str>, mut entries: Vec<StoredEntry>) -> String {
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let sha = mint_sha(
        entries
            .iter()
            .map(|entry| {
                format!(
                    "{} {} {} {}\n",
                    entry.mode, entry.obj_type, entry.sha, entry.path
                )
            })
            .collect::<String>()
            .as_bytes(),
    );
    state.trees.insert(sha.clone(), entries);
    sha
}

fn put_commit(
    state: &mut State,
    message: &str,
    tree: &str,
    parents: &[String],
    author: &str,
    date: &str,
) -> String {
    let sha = mint_sha(
        format!(
            "{tree}\u{0}{}\u{0}{message}\u{0}{author}\u{0}{date}",
            parents.join(",")
        )
        .as_bytes(),
    );
    state.commits.insert(
        sha.clone(),
        StoredCommit {
            sha: sha.clone(),
            message: message.to_string(),
            tree: tree.to_string(),
            parents: parents.to_vec(),
            author: author.to_string(),
            date: date.to_string(),
        },
    );
    sha
}

/// A git-shaped object id: 40 hex, content-derived, and honestly not git's SHA-1.
fn mint_sha(bytes: &[u8]) -> String {
    Oid::hash_bytes(bytes).hex().chars().take(40).collect()
}

fn json(status: u16, value: serde_json::Value) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(status, body);
    response.push_header("content-type", "application/json");
    response
}

fn body_json(request: &Request) -> Option<serde_json::Value> {
    let body = request.body.as_deref()?;
    serde_json::from_slice(body).ok()
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(
            percent_decode(key),
            percent_decode(&value.replace('+', " ")),
        );
    }
    out
}

/// Minimal percent-decoding (enough for ref names and query values).
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &text[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

/// A transport that answers from a [`MockForge`].
pub struct ForgeTransport {
    forge: Arc<MockForge>,
}

impl ForgeTransport {
    /// A transport over a forge.
    pub fn new(forge: Arc<MockForge>) -> Arc<ForgeTransport> {
        Arc::new(ForgeTransport { forge })
    }
}

impl Transport for ForgeTransport {
    fn describe(&self) -> String {
        "mock forge".to_string()
    }

    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        Ok(self.forge.answer(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mock_paginates_like_the_forge() {
        let forge = MockForge::configured(MockConfig {
            per_page: 2,
            require_token: false,
            ..Default::default()
        });
        for index in 0..5 {
            forge.open_pull(
                index + 1,
                &format!("change {index}"),
                "a",
                "2026-01-01T00:00:00Z",
            );
        }
        let first = forge.answer(&Request::new(
            crate::transport::Method::Get,
            "https://api.github.com/repos/gitiup/mock/pulls?state=all&per_page=2",
        ));
        assert_eq!(first.status, 200);
        let items: Vec<serde_json::Value> = first.json().unwrap();
        assert_eq!(items.len(), 2, "a page is a page");
        assert!(first.header("Link").unwrap().contains("rel=\"next\""));
        let second = forge.answer(&Request::new(
            crate::transport::Method::Get,
            "https://api.github.com/repos/gitiup/mock/pulls?state=all&per_page=2&page=2",
        ));
        assert_eq!(second.json::<Vec<serde_json::Value>>().unwrap().len(), 2);
        let third = forge.answer(&Request::new(
            crate::transport::Method::Get,
            "https://api.github.com/repos/gitiup/mock/pulls?state=all&per_page=2&page=3",
        ));
        assert_eq!(third.json::<Vec<serde_json::Value>>().unwrap().len(), 1);
        assert!(third.header("Link").is_none(), "the last page has no next");
    }

    #[test]
    fn a_ref_may_not_move_backwards_without_force() {
        let forge = MockForge::new();
        let first = forge.seed_branch("main", b"one");
        let second = forge.commit_on(&first, b"two");
        let move_it = |sha: &str, force: bool| {
            forge.answer(&{
                let mut request = Request::new(
                    crate::transport::Method::Patch,
                    "https://api.github.com/repos/gitiup/mock/git/ref/refs%2Fheads%2Fmain",
                )
                .with_header("Authorization", "Bearer mock-token");
                request.body = Some(
                    serde_json::to_vec(&serde_json::json!({"sha": sha, "force": force})).unwrap(),
                );
                request
            })
        };
        assert_eq!(
            move_it(&second, false).status,
            200,
            "a forward move is allowed"
        );
        assert_eq!(
            move_it(&first, false).status,
            422,
            "a rewind must be forced, which is what makes force=false a CAS"
        );
        assert_eq!(move_it(&first, true).status, 200);
    }

    #[test]
    fn a_write_without_a_token_is_a_401_not_a_mystery() {
        let forge = MockForge::new();
        let response = forge.answer(&Request::new(
            crate::transport::Method::Post,
            "https://api.github.com/repos/gitiup/mock/git/refs",
        ));
        assert_eq!(response.status, 401);
        assert!(response.body_mentions(&["requires authentication"]));
    }
}

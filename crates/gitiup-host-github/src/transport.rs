//! The transport seam: what an HTTP-looking request is, and who carries it.
//!
//! The adapter never opens a socket itself. It builds a [`Request`], hands it to a
//! [`Transport`], and gets a [`Response`] back — synchronously, because every
//! trait in `gitiup-host` is synchronous (see the design note in
//! `docs/host-abstraction.md`). Two things fall out of that seam and both are the
//! point of it:
//!
//! * **the live transport is not in this process.** [`crate::curl::CurlTransport`]
//!   drives the `curl` binary, so no TLS stack is linked into gitiup, the trust
//!   anchors are the system's, and any single call can be reproduced by a human
//!   with a copy-pasteable command line (see [`Request::curl_command`]).
//! * **the tests do not need a network.** The mock forge and the record/replay
//!   transports (feature `testing`) implement this same trait, so the whole
//!   adapter — pagination, rate limits, auth refusals, CAS races — is exercised
//!   hermetically against recorded HTTP fixtures.
//!
//! Errors here are *transport* errors: DNS failed, the socket closed, the timeout
//! expired. Everything with an HTTP status is a `Ok(Response)` and is classified
//! by [`crate::client`], because "403" is a policy answer, not a broken pipe.

use std::fmt;
use std::time::Duration;

/// The HTTP methods the GitHub API is actually driven with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Read.
    Get,
    /// Create.
    Post,
    /// Partial update.
    Patch,
    /// Replace.
    Put,
    /// Remove.
    Delete,
}

impl Method {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One API call, as data.
///
/// Headers are a list rather than a map because the API cares about order in the
/// rare `Accept` case, because a repeated header is legal, and because a recorded
/// fixture should be able to show exactly what was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Absolute URL, including scheme, host and query. Never carries credentials:
    /// the token is a header, and a token in a URL ends up in a proxy log.
    pub url: String,
    /// Request headers, in the order they will be sent.
    pub headers: Vec<(String, String)>,
    /// Request body, when the method carries one.
    pub body: Option<Vec<u8>>,
    /// Per-request timeout from the remote's configuration; a transport that
    /// cannot enforce one says so rather than ignoring it silently.
    pub timeout: Duration,
}

impl Request {
    /// Build a request.
    pub fn new(method: Method, url: impl Into<String>) -> Request {
        Request {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Request {
        self.timeout = timeout;
        self
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Request {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Attach a body.
    pub fn with_body(mut self, body: Vec<u8>) -> Request {
        self.body = Some(body);
        self
    }

    /// Read a header (first match, case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The URL with any userinfo removed, for logs and error text.
    pub fn redacted_url(&self) -> String {
        redact_url(&self.url)
    }

    /// One line naming this call, safe to print: no token, no body.
    pub fn summary(&self) -> String {
        format!("{} {}", self.method, self.redacted_url())
    }

    /// The `curl` command line that performs this request, with the body on
    /// stdin.
    ///
    /// This exists because "reproduce the call that failed" is the first thing an
    /// operator wants, and because a transport that cannot be written down is a
    /// transport that cannot be reviewed. Any `Authorization` header is replaced
    /// with a `$GITIUP_GITHUB_TOKEN` reference rather than the value, so pasting
    /// this into a shell is safe.
    pub fn curl_command(&self) -> String {
        let mut parts = vec![
            "curl".to_string(),
            "-sS".to_string(),
            "--compressed".to_string(),
            format!("--request {}", self.method.as_str()),
        ];
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("authorization") {
                parts.push("--header 'Authorization: Bearer $GITIUP_GITHUB_TOKEN'".to_string());
            } else {
                parts.push(format!("--header '{}: {}'", name, value));
            }
        }
        if self.body.is_some() {
            parts.push("--data-binary @-".to_string());
        }
        parts.push(format!("--url '{}'", self.redacted_url()));
        if self.body.is_some() {
            let body = String::from_utf8_lossy(self.body.as_deref().unwrap_or(&[]));
            format!(
                "cat <<'JSON' | {}\n{}\nJSON",
                parts.join(" "),
                body.trim_end()
            )
        } else {
            parts.join(" ")
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// One API answer, as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Response headers, as received.
    pub headers: Vec<(String, String)>,
    /// Response body, exactly the bytes received.
    pub body: Vec<u8>,
}

impl Response {
    /// Build a response.
    pub fn new(status: u16, body: Vec<u8>) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body,
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Response {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add a header to a response that is already built.
    pub fn push_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    /// First value of a header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value of a header.
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Parse the body as JSON, with a message that says what was received when it
    /// is not JSON (an HTML error page from a proxy is the usual culprit).
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, TransportError> {
        serde_json::from_slice(&self.body).map_err(|why| TransportError {
            message: format!(
                "the API answered {} with a body that is not JSON: {why}",
                self.status
            ),
            retryable: false,
            hint: proxy_hint(&self.body),
        })
    }

    /// The `message` field of a GitHub error body, when there is one.
    pub fn api_message(&self) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct Body {
            message: Option<String>,
        }
        let parsed: Body = self.json().ok()?;
        parsed.message.filter(|text| !text.is_empty())
    }

    /// Whether the body mentions any of `needles` (case-insensitive), which is how
    /// a few GitHub refusals have to be recognised: the status alone does not
    /// distinguish "rate limited" from "no permission", and the difference decides
    /// whether the caller should wait or stop.
    pub fn body_mentions(&self, needles: &[&str]) -> bool {
        let text = String::from_utf8_lossy(&self.body).to_ascii_lowercase();
        needles.iter().any(|needle| text.contains(needle))
    }
}

/// What to say when a body is HTML or something else unparseable.
fn proxy_hint(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let head: String = text.chars().take(120).collect();
    let head = head.trim().replace('\n', " ");
    if head.starts_with('<') {
        return Some(format!(
            "this looks like an HTML page, not the API: `{head}` — check `api-base` \
             and any enterprise path, and whether a proxy intercepted the call"
        ));
    }
    Some(format!("first bytes of the body: `{head}`"))
}

/// Strip `user:password@` from a URL so it can be printed.
pub fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rfind('@') {
        Some(at) => format!(
            "{scheme}***@{}{}",
            &authority[at + 1..],
            &rest[authority_end..]
        ),
        None => url.to_string(),
    }
}

/// A transport-level failure: no status code, because no answer arrived.
#[derive(Debug, Clone)]
pub struct TransportError {
    /// What went wrong.
    pub message: String,
    /// Whether trying again could plausibly help.
    pub retryable: bool,
    /// What to do about it.
    pub hint: Option<String>,
}

impl TransportError {
    /// A failure that a retry may clear.
    pub fn new(message: impl Into<String>) -> TransportError {
        TransportError {
            message: message.into(),
            retryable: true,
            hint: None,
        }
    }

    /// Say whether a retry may help.
    pub fn retryable(mut self, retryable: bool) -> TransportError {
        self.retryable = retryable;
        self
    }

    /// Attach a hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> TransportError {
        self.hint = Some(hint.into());
        self
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportError {}

/// Who carries a request to the forge and brings the answer back.
///
/// Implementations must be usable from several threads (a verification run reads
/// several hosts concurrently) and must not retry on their own: retries with
/// backoff are the client's job, so that rate-limit accounting sees every
/// attempt.
pub trait Transport: Send + Sync {
    /// Send one request.
    fn send(&self, request: &Request) -> Result<Response, TransportError>;

    /// What this transport is, for `gitiup doctor` and for error messages.
    fn describe(&self) -> String {
        "transport".to_string()
    }
}

/// A transport that always refuses, so a host can be constructed (and inspected,
/// and printed) by a build that cannot reach a forge.
///
/// `GitHubHost::open` uses this when the `curl` feature is off: the refusal names
/// the feature rather than pretending a network is there.
pub struct RefusedTransport {
    /// Why this transport exists, e.g. `this build has no GitHub transport`.
    pub reason: String,
    /// What to do about it.
    pub hint: String,
}

impl Transport for RefusedTransport {
    fn send(&self, _request: &Request) -> Result<Response, TransportError> {
        Err(TransportError::new(self.reason.clone())
            .retryable(false)
            .with_hint(self.hint.clone()))
    }

    fn describe(&self) -> String {
        self.reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_redacted_before_anything_prints_them() {
        assert_eq!(
            redact_url("https://user:sekret@api.github.com/repos/o/r"),
            "https://***@api.github.com/repos/o/r"
        );
        assert_eq!(
            redact_url("https://api.github.com/repos/o/r"),
            "https://api.github.com/repos/o/r"
        );
        assert_eq!(redact_url("not a url"), "not a url");
    }

    #[test]
    fn a_request_summary_never_carries_the_token() {
        let request = Request::new(
            Method::Get,
            "https://api.github.com/repos/o/r/git/ref/refs/heads/main",
        )
        .with_header("Authorization", "Bearer ghp_supersecret");
        assert!(!request.summary().contains("supersecret"));
        assert!(!request.curl_command().contains("supersecret"));
        assert!(request.curl_command().contains("$GITIUP_GITHUB_TOKEN"));
    }

    #[test]
    fn a_non_json_body_says_what_it_was() {
        let response = Response::new(502, b"<html><body>502 Bad Gateway</body></html>".to_vec());
        let err = response.json::<serde_json::Value>().unwrap_err();
        let hint = err.hint.unwrap();
        assert!(hint.contains("HTML"), "{hint}");
        assert!(!err.retryable, "a proxy page will not fix itself");
    }
}

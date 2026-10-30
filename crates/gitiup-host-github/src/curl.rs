//! The live transport: `curl`, driven as a binary.
//!
//! This is the same decision the plain-git host makes about `git` (giti-xdw.3),
//! for the same reasons:
//!
//! * **no TLS stack in our process.** gitiup runs in pre-receive hooks and on
//!   volunteers' machines; linking a TLS implementation means shipping one, and
//!   shipping it means the supply-chain ticket has to pin it and the escape suite
//!   has to care about it. The system's `curl` uses the system's trust store, which
//!   is where an operator can actually see and revoke what is trusted.
//! * **any call can be written down.** [`crate::transport::Request::curl_command`]
//!   prints the command that reproduces a failing request (token aside), which is
//!   what "the CLI is auditable" means in practice.
//! * **there is nothing else to link.** The adapter needs one synchronous
//!   request/response exchange, not a client library with a connection pool.
//!
//! What this gives up, and how it is paid for: no connection reuse (a forge
//! adapter that makes ten calls per command does not care), and no in-process
//! certificate pinning (so the plain-`http://` case is refused off loopback, and
//! redirects are not followed, in [`crate::client`]).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use gitiup_host::{HostError, HostResult, RemoteConfig};

use crate::codec::is_loopback_host;
use crate::transport::{Request, Response, Transport, TransportError};

/// The `curl` binary, if there is one.
///
/// Reported as `None` rather than panicking: `gitiup doctor` must be able to say
/// "this machine has no curl, so it has no forge transport" as a fact.
pub fn curl_program() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("GITIUP_CURL") {
        let path = PathBuf::from(explicit);
        return if path.exists() { Some(path) } else { None };
    }
    let name = if cfg!(windows) { "curl.exe" } else { "curl" };
    let path = which(name)?;
    Some(path)
}

fn which(program: &str) -> Option<PathBuf> {
    let separators = if cfg!(windows) { ';' } else { ':' };
    let suffixes = if cfg!(windows) {
        [".exe", ".cmd", ""].to_vec()
    } else {
        vec![""]
    };
    for directory in std::env::var("PATH").unwrap_or_default().split(separators) {
        for suffix in &suffixes {
            let candidate = Path::new(directory).join(format!("{program}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// A transport that drives `curl`.
#[derive(Debug, Clone)]
pub struct CurlTransport {
    /// Which binary to run.
    pub program: PathBuf,
    /// `--connect-timeout`.
    pub connect_timeout: Duration,
    /// Extra CA bundle, for an enterprise server with a private CA (`--cacert`).
    pub ca_bundle: Option<PathBuf>,
    /// A proxy to route through (`-x`), when the operator configured one.
    pub proxy: Option<String>,
}

impl CurlTransport {
    /// Build the default transport, or refuse when there is no `curl` to drive.
    pub fn new() -> HostResult<CurlTransport> {
        let program = curl_program().ok_or_else(|| {
            HostError::unsupported(
                "transport:curl",
                "this build reaches GitHub through the `curl` binary and none was found",
            )
            .with_hint(
                "install curl, or set GITIUP_CURL to its path; a build with the `curl` \
                 feature off does not try at all and says so at open time",
            )
        })?;
        Ok(CurlTransport {
            program,
            connect_timeout: Duration::from_secs(10),
            ca_bundle: std::env::var("GITIUP_CA_BUNDLE")
                .ok()
                .filter(|path| !path.is_empty())
                .map(PathBuf::from),
            proxy: std::env::var("GITIUP_HTTPS_PROXY")
                .ok()
                .filter(|value| !value.is_empty()),
        })
    }

    /// The argv this transport would run (one entry per argument, exactly as
    /// `curl` receives them), with the authorisation header replaced by a
    /// placeholder so the vector can be printed.
    pub fn argv(&self, request: &Request) -> Vec<String> {
        self.build_argv(request, Argv::Printed)
    }

    /// The argv `curl` is actually given: the same vector, with the credential the caller
    /// resolved in it.
    ///
    /// This used to be [`CurlTransport::argv`], and the request went out asking the server
    /// to accept the literal text `$GITIUP_GITHUB_TOKEN`: a placeholder meant for a
    /// printed command line, sent as if it were a secret. giti-g5c.5's decoy is what
    /// caught it — a body that checks "the credential never reaches the other origin"
    /// proves nothing while the credential reaches *no* origin, so the decoy was quietly
    /// being asked to agree with a client that had never authenticated at all.
    ///
    /// The trade-off, said out loud rather than left to be discovered: a header on a
    /// command line is visible in the process table to whoever can see processes on this
    /// machine, for as long as the request takes. curl's only alternative is a config file
    /// holding the same secret, which is on disk instead — and stays there if the process is
    /// killed. What stays redacted is the printed form, so the value cannot end up in a
    /// log, a run report or an issue attachment.
    fn send_argv(&self, request: &Request) -> Vec<String> {
        self.build_argv(request, Argv::Run)
    }

    fn build_argv(&self, request: &Request, purpose: Argv) -> Vec<String> {
        let host = crate::codec::url_host(&request.url);
        let mut argv = vec![
            self.program.display().to_string(),
            "--silent".into(),
            "--show-error".into(),
            "--no-location".into(),
            "--include".into(),
            "--compressed".into(),
            "--connect-timeout".into(),
            self.connect_timeout.as_secs().to_string(),
            "--max-time".into(),
            request.timeout.as_secs().max(1).to_string(),
            // Plain HTTP is only ever allowed to loopback (a local test server);
            // `--proto` is what makes that a curl refusal and not a suggestion.
            "--proto".into(),
            format!(
                "={}",
                if request.url.starts_with("https://") {
                    "https"
                } else if is_loopback_host(&host) {
                    "http"
                } else {
                    "https"
                }
            ),
            "--request".into(),
            request.method.as_str().to_string(),
        ];
        if let Some(bundle) = &self.ca_bundle {
            argv.push("--cacert".into());
            argv.push(bundle.display().to_string());
        }
        if let Some(proxy) = &self.proxy {
            argv.push("--proxy".into());
            argv.push(proxy.clone());
        }
        for (name, value) in &request.headers {
            let value =
                if name.eq_ignore_ascii_case("authorization") && matches!(purpose, Argv::Printed) {
                    "Bearer $GITIUP_GITHUB_TOKEN".to_string()
                } else {
                    value.clone()
                };
            argv.push("--header".into());
            argv.push(format!("{name}: {value}"));
        }
        if request.body.is_some() {
            argv.push("--data-binary".into());
            argv.push("@-".into());
        }
        argv.push("--url".into());
        argv.push(request.redacted_url());
        argv
    }
}

impl Default for CurlTransport {
    fn default() -> CurlTransport {
        CurlTransport::new().expect("curl transport")
    }
}

/// Which caller wants the argv: one that prints it, one that runs it.
#[derive(Clone, Copy)]
enum Argv {
    /// Redacted: safe to put in a message.
    Printed,
    /// Real: carries the credential, and is only ever handed to `Command`.
    Run,
}

impl Transport for CurlTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let argv = self.send_argv(request);
        // `argv` is built with `--header Name: value` pairs, so a value with a
        // newline could inject another header. Refuse rather than send it.
        for (name, value) in &request.headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                return Err(TransportError::new(format!(
                    "refusing to send a header with a newline in it ({name})"
                ))
                .retryable(false));
            }
        }
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|why| TransportError {
            message: format!("cannot run {}: {why}", self.program.display()),
            retryable: false,
            hint: Some("install curl or set GITIUP_CURL".to_string()),
        })?;
        {
            // The body goes in on stdin from this thread; a request body is small
            // (a JSON record), so a blocking write cannot deadlock against the
            // stdout read the way an unbounded stream would.
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| TransportError::new("curl had no stdin for the request body"))?;
            if let Some(body) = &request.body {
                stdin
                    .write_all(body)
                    .map_err(|why| TransportError::new(format!("writing the body: {why}")))?;
            }
            drop(stdin);
        }
        let output = child
            .wait_with_output()
            .map_err(|why| TransportError::new(format!("curl did not finish: {why}")))?;
        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let text = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(curl_error(code, &text, &request.url));
        }
        split_response(&output.stdout).map_err(|why| TransportError {
            message: format!("curl answered in a shape gitiup could not read: {why}"),
            retryable: false,
            hint: Some(format!(
                "the raw output started with `{}`",
                String::from_utf8_lossy(&output.stdout)
                    .chars()
                    .take(80)
                    .collect::<String>()
            )),
        })
    }

    fn describe(&self) -> String {
        format!("curl ({})", self.program.display())
    }
}

/// Map a `curl` exit code onto something a user can act on.
fn curl_error(code: i32, text: &str, url: &str) -> TransportError {
    let host = crate::codec::url_host(url);
    let (message, retryable, hint) = match code {
        3 | 4 => (
            format!("'{url}' is not a URL curl understands"),
            false,
            Some("check the remote's url in gitiup.toml".to_string()),
        ),
        5 | 6 => (
            format!("the host {host} could not be resolved"),
            true,
            Some("a VPN, a private resolver or a typo in the remote".to_string()),
        ),
        7 => (
            format!("{host} refused the connection"),
            true,
            Some("is the server up, and is a firewall between?".to_string()),
        ),
        28 => (
            "the request timed out".to_string(),
            true,
            Some("raise the remote's `timeout`, or check for a proxy that hangs".to_string()),
        ),
        35 | 60 | 77 | 83 => (
            format!("TLS failed against {host}: {text}"),
            false,
            Some(
                "for an enterprise server with a private CA, set GITIUP_CA_BUNDLE; \
                 gitiup has no insecure flag on purpose"
                    .to_string(),
            ),
        ),
        92 | 97 => (
            format!("the HTTP/2 exchange with {host} failed: {text}"),
            true,
            None,
        ),
        other => (format!("curl exited {other}: {text}"), false, None),
    };
    TransportError {
        message,
        retryable,
        hint,
    }
}

/// Split `curl --include` output into headers and body.
fn split_response(bytes: &[u8]) -> Result<Response, String> {
    let (boundary, length) = find_headers_end(bytes).ok_or("no blank line after the headers")?;
    let head = std::str::from_utf8(&bytes[..boundary]).map_err(|why| why.to_string())?;
    let body_offset = boundary + length;
    let body = bytes.get(body_offset..).unwrap_or(&[]).to_vec();
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("no status line")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(format!("'{status_line}' is not a status line"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Where the header block ends, and how long the blank line is: `\r\n\r\n`
/// normally, `\n\n` from a server (or a test server) that speaks bare LF.
fn find_headers_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    match (crlf, lf) {
        (Some(a), Some(b)) => Some((a.min(b), if a <= b { 4 } else { 2 })),
        (Some(a), None) => Some((a, 4)),
        (None, Some(b)) => Some((b, 2)),
        (None, None) => None,
    }
}

/// The transport a default build uses, or the refusal that names the feature.
#[cfg(feature = "curl")]
pub fn default_transport(_remote: &RemoteConfig) -> HostResult<std::sync::Arc<dyn Transport>> {
    Ok(std::sync::Arc::new(CurlTransport::new()?))
}

/// The transport a build without the `curl` feature has: none, and a message that
/// says which flag would have helped.
#[cfg(not(feature = "curl"))]
pub fn default_transport(_remote: &RemoteConfig) -> HostResult<std::sync::Arc<dyn Transport>> {
    Err(HostError::unsupported(
        "hosts-github",
        "this gitiup was built without a GitHub transport (feature `curl` of \
         gitiup-host-github is off), so it cannot reach any forge",
    )
    .with_hint(
        "build with --features hosts-github (it is on by default), or point the remote \
         at a host this build does have: an S3 bucket or any plain git server",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_is_present_in_this_environment_or_the_test_says_so() {
        // Not an assertion that curl exists: an assertion that the probe is honest.
        match curl_program() {
            Some(program) => assert!(program.is_file()),
            None => eprintln!("no curl on PATH: the live transport is unavailable here"),
        }
    }

    #[test]
    fn the_printed_argv_writes_down_every_call_but_the_token() {
        let transport = CurlTransport {
            program: PathBuf::from("curl"),
            connect_timeout: Duration::from_secs(5),
            ca_bundle: None,
            proxy: None,
        };
        let request = Request::new(
            crate::transport::Method::Get,
            "https://api.github.com/repos/o/r",
        )
        .with_header("Authorization", "Bearer nope-nope-nope");
        let argv = transport.argv(&request);
        let text = argv.join(" ");
        assert!(text.contains("api.github.com"), "{text}");
        assert!(!text.contains("nope-nope"), "{text}");
        assert!(argv.iter().any(|arg| arg == "--no-location"), "{text}");
        // One argument per element: curl does not parse `--flag value` as one word.
        assert!(
            argv.windows(2).any(|pair| pair == ["--proto", "=https"]),
            "{text}"
        );
        assert!(
            argv.windows(2).any(|pair| pair == ["--request", "GET"]),
            "{text}"
        );
        assert!(
            argv.windows(2)
                .any(|pair| pair[0] == "--header" && pair[1].starts_with("Authorization: Bearer $")),
            "{text}"
        );
    }

    #[test]
    fn the_run_argv_carries_the_credential_the_printed_one_hides() {
        let transport = CurlTransport {
            program: PathBuf::from("curl"),
            connect_timeout: Duration::from_secs(5),
            ca_bundle: None,
            proxy: None,
        };
        let request = Request::new(
            crate::transport::Method::Get,
            "https://api.github.com/repos/o/r",
        )
        .with_header("Authorization", "Bearer really-a-token");
        // The printed form is the one that goes into a message: no secret.
        let printed = transport.argv(&request);
        assert!(
            !printed.join(" ").contains("really-a-token"),
            "the printed argv must not carry the token"
        );
        // The argv handed to `curl` is the one that has to authenticate: if it does not
        // carry the token, every claim about where the token goes is a claim about a
        // request that never happened.
        let run = transport.send_argv(&request);
        assert!(
            run.windows(2)
                .any(|pair| pair[0] == "--header"
                    && pair[1] == "Authorization: Bearer really-a-token"),
            "curl has to be given the credential: {}",
            run.join(" ")
        );
        // And the two differ in that one argument and nothing else, so the audit trail
        // still describes the call that was made.
        assert_eq!(printed.len(), run.len());
        assert_eq!(
            printed
                .iter()
                .zip(run.iter())
                .filter(|(left, right)| left != right)
                .count(),
            1,
            "only the credential differs"
        );
    }

    #[test]
    fn a_response_is_split_on_the_blank_line() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ratelimit-remaining: 42\r\n\r\n{\"ok\":true}";
        let response = split_response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.header("x-ratelimit-remaining"), Some("42"));
        assert_eq!(response.body, br#"{"ok":true}"#);
        assert!(split_response(b"nonsense").is_err());
        let bare_lf = b"HTTP/1.1 204 No Content\nx-ratelimit-remaining: 1\n\nok\n";
        let response = split_response(bare_lf).unwrap();
        assert_eq!(response.status, 204);
        assert_eq!(response.body, b"ok\n");
    }

    #[test]
    fn curl_exit_codes_become_advice() {
        assert!(curl_error(6, "Could not resolve host", "https://x.invalid/").retryable);
        let tls = curl_error(60, "SSL certificate problem", "https://ghe.example/");
        assert!(!tls.retryable);
        assert!(tls.hint.unwrap().contains("GITIUP_CA_BUNDLE"));
    }
}

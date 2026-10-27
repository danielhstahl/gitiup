//! `gitiup.toml`: the schema-versioned repo config that names the remotes a
//! repo syncs with and how they are authenticated.
//!
//! ```toml
//! schema-version = 1
//! default-remote = "origin"
//!
//! [[remote]]
//! name = "origin"
//! url = "s3://gitiup-forge/my-repo"
//! store-prefix = "store"          # optional, default "gitiup"
//! credentials-profile = "owner"   # optional, names an entry below
//! timeout = "30s"                 # optional, per remote
//!
//! [remote.options]                # free-form passthrough (region, endpoint, ...)
//! region = "eu-central-1"
//!
//! [credentials.owner]
//! auth = "cloud-role"             # anonymous|filesystem|token|ssh-key|cloud-role|helper
//! token-env = "GITIUP_TOKEN"      # never put a token in the file
//! key-path = "~/.ssh/id_ed25519"
//! ```
//!
//! Accepted URL schemes are [`RemoteScheme::S3`] (`s3://bucket/prefix`),
//! [`RemoteScheme::Https`] (`https://host/path/repo.git`), [`RemoteScheme::Ssh`]
//! (`ssh://git@host/srv/git/repo.git`, plus the `git@host:path` scp form) and
//! [`RemoteScheme::File`] (`file:///srv/git/repo.git`). Anything else fails with
//! [`HostError::SchemeUnknown`] listing what is
//! supported.
//!
//! Every key is validated: unknown fields, duplicate remote names, a
//! `default-remote` that does not exist, out-of-range timeouts and newer schema
//! versions all produce actionable errors, and
//! [`Config::warnings`] collects the non-fatal advice.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::blob::Namespace;
use crate::capability::AuthModel;
use crate::error::{HostError, HostResult};
use crate::oid::Oid;
use crate::refs::RefName;

/// Name of the config file gitiup looks for.
pub const CONFIG_FILE_NAME: &str = "gitiup.toml";

/// Environment variable that overrides discovery with an explicit path.
pub const CONFIG_PATH_ENV: &str = "GITIUP_CONFIG";

/// Schema version this build writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Oldest schema version this build can read.
pub const MIN_SCHEMA_VERSION: u32 = 1;

/// Default per-remote timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest timeout we accept (misconfiguration guard).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Timeout above which [`Config::warnings`] complains.
pub const SLOW_TIMEOUT: Duration = Duration::from_secs(600);

/// Default store prefix inside a remote.
pub const DEFAULT_STORE_PREFIX: &str = "gitiup";

/// Serialize a value to the canonical JSON bytes used for CAS digests
/// (`serde_json`, key order = declaration order, no pretty printing).
pub fn canonical_json<T: Serialize>(value: &T) -> HostResult<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|e| HostError::invalid("payload", format!("cannot encode JSON: {e}")))
}

/// Parse a timeout value: `500ms`, `30s`, `5m`, `1h`, or a bare number of
/// seconds.
pub fn parse_timeout(text: &str) -> HostResult<Duration> {
    let text = text.trim();
    let bad = || {
        HostError::invalid("timeout", format!("'{text}' is not a timeout"))
            .with_hint("use a duration like 250ms, 30s, 5m or 1h (max 1h)")
    };
    let number = |digits: &str| digits.trim().parse::<u64>().map_err(|_| bad());
    let value = if let Some(digits) = text.strip_suffix("ms") {
        Duration::from_millis(number(digits)?)
    } else if let Some(digits) = text.strip_suffix('s') {
        Duration::from_secs(number(digits)?)
    } else if let Some(digits) = text.strip_suffix('m') {
        Duration::from_secs(number(digits)?.checked_mul(60).ok_or_else(bad)?)
    } else if let Some(digits) = text.strip_suffix('h') {
        Duration::from_secs(number(digits)?.checked_mul(3_600).ok_or_else(bad)?)
    } else {
        Duration::from_secs(number(text)?)
    };
    check_timeout(value, text)
}

fn check_timeout(value: Duration, text: &str) -> HostResult<Duration> {
    if value.is_zero() {
        return Err(HostError::invalid("timeout", format!("'{text}' is zero"))
            .with_hint("timeouts must be greater than 0"));
    }
    if value > MAX_TIMEOUT {
        return Err(HostError::invalid(
            "timeout",
            format!("'{text}' exceeds the {MAX_TIMEOUT:?} maximum"),
        )
        .with_hint("lower the timeout; long-running fetches should stream instead"));
    }
    Ok(value)
}

/// Render a duration the way `parse_timeout` accepts it.
pub fn format_timeout(d: Duration) -> String {
    if d.as_millis() < 1_000 {
        return format!("{}ms", d.as_millis());
    }
    if d.as_secs() >= 60 && d.as_secs().is_multiple_of(60) {
        return format!("{}m", d.as_secs() / 60);
    }
    format!("{}s", d.as_secs())
}

/// The URI schemes gitiup can talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteScheme {
    /// `s3://bucket/prefix` — a bucket used as the forge (giti-xdw.2).
    S3,
    /// `https://host/repo` — smart-HTTP or dumb-HTTP static hosting.
    Https,
    /// `ssh://git@host/repo` (and `git@host:repo`) — a bare repo over ssh.
    Ssh,
    /// `file:///path` — a local directory (tests, air-gapped setups).
    File,
}

impl RemoteScheme {
    /// All supported schemes, in the order they are advertised.
    pub const ALL: [RemoteScheme; 4] = [
        RemoteScheme::S3,
        RemoteScheme::Https,
        RemoteScheme::Ssh,
        RemoteScheme::File,
    ];

    /// The scheme text, without `://`.
    pub fn as_str(self) -> &'static str {
        match self {
            RemoteScheme::S3 => "s3",
            RemoteScheme::Https => "https",
            RemoteScheme::Ssh => "ssh",
            RemoteScheme::File => "file",
        }
    }

    /// `s3://` and friends.
    pub fn with_separator(self) -> String {
        format!("{}://", self.as_str())
    }

    /// Comma-separated list of supported schemes, for error messages.
    pub fn supported_list() -> String {
        RemoteScheme::ALL
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// A scheme we deliberately refuse, with the reason and the fix.
    fn rejection(scheme: &str) -> Option<HostError> {
        let (why, fix) = match scheme {
            "http" => (
                "plain http is not supported",
                "use https:// (or ssh://) so credentials and pack data are not sent in the clear",
            ),
            "git" => (
                "the git:// protocol is unauthenticated and anonymously writable in the open",
                "use ssh://git@host/path instead",
            ),
            "gs" | "s3a" | "s3n" | "s3+sso" => (
                "this is a cloud object-store alias gitiup does not implement",
                "use s3://bucket/prefix",
            ),
            "github" | "gh" => (
                "the forge is selected by the adapter, not by the URL",
                "use https://github.com/owner/repo.git with the github adapter (giti-xdw.4)",
            ),
            "ftp" | "ftps" => ("ftp is not a git transport", "use ssh:// or https://"),
            "ipfs" => ("ipfs remotes are not implemented", "use s3:// or ssh://"),
            "ssh+git" | "git+ssh" => ("combined scheme is not used", "use ssh://git@host/path"),
            other if other.contains("://") => (
                "not a gitiup remote URI",
                "expected s3://, https://, ssh:// or file://",
            ),
            _ => return None,
        };
        Some(HostError::SchemeUnknown(Box::new(
            crate::error::SchemeUnknown {
                scheme: scheme.to_string(),
                supported: RemoteScheme::ALL
                    .iter()
                    .map(|s| s.as_str().to_string())
                    .collect(),
                hint: Some(format!("{why}; {fix}")),
            },
        )))
    }
}

impl fmt::Display for RemoteScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RemoteScheme {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().trim_end_matches("://") {
            "s3" => Ok(RemoteScheme::S3),
            "https" => Ok(RemoteScheme::Https),
            "ssh" => Ok(RemoteScheme::Ssh),
            "file" => Ok(RemoteScheme::File),
            other => Err(RemoteScheme::rejection(other).unwrap_or_else(|| {
                HostError::SchemeUnknown(Box::new(crate::error::SchemeUnknown {
                    scheme: other.to_string(),
                    supported: RemoteScheme::ALL
                        .iter()
                        .map(|s| s.as_str().to_string())
                        .collect(),
                    hint: Some(format!(
                        "supported schemes: {}",
                        RemoteScheme::supported_list()
                    )),
                }))
            })),
        }
    }
}

/// A parsed remote URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUrl {
    /// Scheme.
    pub scheme: RemoteScheme,
    /// Userinfo (`ssh://git@host`), kept for ssh remotes.
    pub user: Option<String>,
    /// Bucket (s3) or host.
    pub host: String,
    /// Port, when given.
    pub port: Option<u16>,
    /// Path below the host/bucket, without a leading `/` (may be empty for s3).
    pub path: String,
    /// Query parameters, e.g. `?region=eu-central-1`.
    pub query: BTreeMap<String, String>,
    /// The string this was parsed from.
    pub raw: String,
}

impl RemoteUrl {
    /// Parse a remote URI, rejecting anything gitiup cannot serve.
    pub fn parse(input: &str) -> HostResult<RemoteUrl> {
        let input = input.trim();
        if input.is_empty() {
            return Err(
                HostError::invalid("remote url", "empty remote url").with_hint(format!(
                    "expected one of {}",
                    RemoteScheme::supported_list()
                )),
            );
        }
        for c in input.chars() {
            if c.is_control() || c.is_whitespace() {
                return Err(HostError::invalid(
                    "remote url",
                    format!("'{input}' contains whitespace or control characters"),
                )
                .with_hint("quote the URL in your shell if the path contains spaces"));
            }
        }

        // scp-ish form: git@host:owner/repo.git
        let (scheme_text, rest) = match input.split_once("://") {
            Some((scheme, rest)) => (scheme, rest),
            None => {
                if let Some((userinfo, path)) = input.split_once('@')
                    && let Some((host, path)) = path.split_once(':')
                {
                    let mut rewritten = format!("ssh://{userinfo}@{host}/{path}");
                    // `git@host:/abs/path` keeps its leading slash semantics.
                    if path.starts_with('/') {
                        rewritten = format!("ssh://{userinfo}@{host}{path}");
                    }
                    return RemoteUrl::parse(&rewritten);
                }
                return Err(
                    HostError::invalid("remote url", format!("'{input}' has no scheme")).with_hint(
                        format!(
                            "supported schemes: {} (or the scp-like git@host:owner/repo.git form)",
                            RemoteScheme::supported_list()
                        ),
                    ),
                );
            }
        };

        let scheme: RemoteScheme = scheme_text.trim().parse()?;
        let (authority_and_path, query) = split_query(rest);
        let (authority, path) = match authority_and_path.split_once('/') {
            Some((authority, path)) => (authority, path.trim_matches('/')),
            None => (authority_and_path, ""),
        };
        let (user, hostport) = match authority.rsplit_once('@') {
            Some((user, hostport)) => (Some(user.to_string()), hostport),
            None => (None, authority),
        };
        let (host, port) = split_host_port(hostport)?;

        let url = RemoteUrl {
            scheme,
            user,
            host,
            port,
            path: path.to_string(),
            query: parse_query(query),
            raw: input.to_string(),
        };
        url.validate()?;
        Ok(url)
    }

    /// A `file://` URL for a local path (used by `gitiup remote add`).
    pub fn from_path(path: &Path) -> HostResult<RemoteUrl> {
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| {
                    HostError::invalid(
                        "remote url",
                        format!("cannot resolve '{}': {e}", path.display()),
                    )
                })?
                .join(path)
        };
        let text = abs.to_string_lossy().replace('\\', "/");
        RemoteUrl::parse(&format!("file://{text}"))
    }

    fn validate(&self) -> HostResult<()> {
        match self.scheme {
            RemoteScheme::S3 => {
                validate_bucket(&self.host)?;
                validate_segments(&self.path, "bucket prefix")?;
            }
            RemoteScheme::Https | RemoteScheme::Ssh => {
                validate_host(&self.host)?;
                if self.path.is_empty() {
                    return Err(HostError::invalid(
                        "remote url",
                        format!("'{}' does not name a repository path", self.raw),
                    )
                    .with_hint("expected e.g. https://host/owner/repo.git"));
                }
                validate_segments(&self.path, "repository path")?;
            }
            RemoteScheme::File => {
                if self.path.is_empty() {
                    return Err(HostError::invalid(
                        "remote url",
                        format!("'{}' does not name a directory", self.raw),
                    )
                    .with_hint("expected e.g. file:///srv/git/repo.git"));
                }
                validate_segments(&self.path, "directory path")?;
            }
        }
        Ok(())
    }

    /// The absolute local path for a `file://` remote.
    pub fn file_path(&self) -> PathBuf {
        PathBuf::from(format!("/{}", self.path))
    }

    /// The URL with any userinfo/secret removed, safe for logs.
    pub fn redacted(&self) -> String {
        let user = match self.user {
            Some(_) => "***@",
            None => "",
        };
        let port = match self.port {
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        format!(
            "{}{}{}{}/{}",
            self.scheme.with_separator(),
            user,
            self.host,
            port,
            self.path
        )
    }

    /// A query parameter, e.g. `?region=...`.
    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }
}

impl fmt::Display for RemoteUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for RemoteUrl {
    type Err = HostError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RemoteUrl::parse(s)
    }
}

fn split_query(rest: &str) -> (&str, &str) {
    let rest = rest.split_once('#').map(|(r, _)| r).unwrap_or(rest);
    match rest.split_once('?') {
        Some((head, query)) => (head, query),
        None => (rest, ""),
    }
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(k.to_ascii_lowercase(), v.to_string());
    }
    out
}

fn split_host_port(text: &str) -> HostResult<(String, Option<u16>)> {
    if let Some((host, port)) = text.rsplit_once(':') {
        let port: u16 = port.parse().map_err(|_| {
            HostError::invalid("remote url", format!("'{port}' is not a valid port"))
        })?;
        Ok((host.to_string(), Some(port)))
    } else {
        Ok((text.to_string(), None))
    }
}

fn validate_host(host: &str) -> HostResult<()> {
    let bad = |why: &str| {
        Err(HostError::invalid(
            "remote url",
            format!("host '{host}' {why}"),
        ))
    };
    if host.is_empty() {
        return bad("is missing");
    }
    if host.len() > 253 {
        return bad("is longer than 253 characters");
    }
    for label in host.split('.') {
        if label.is_empty() {
            return bad("has an empty label");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return bad("has a label with illegal characters");
        }
    }
    Ok(())
}

fn validate_bucket(bucket: &str) -> HostResult<()> {
    let bad = |why: &str| {
        Err(
            HostError::invalid("remote url", format!("S3 bucket '{bucket}' {why}")).with_hint(
                "bucket names are 3-63 characters of lower-case letters, digits, dots and hyphens",
            ),
        )
    };
    if bucket.len() < 3 || bucket.len() > 63 {
        return bad("is not 3-63 characters long");
    }
    if !bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return bad("uses characters that S3 does not allow");
    }
    for label in bucket.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') || label == ".." {
            return bad("has an empty or hyphen-delimited label");
        }
    }
    Ok(())
}

fn validate_segments(path: &str, what: &str) -> HostResult<()> {
    if path.is_empty() {
        return Ok(());
    }
    for seg in path.split('/') {
        let bad = |why: &str| {
            Err(HostError::invalid(
                "remote url",
                format!("{what} segment '{seg}' {why}"),
            ))
        };
        if seg.is_empty() {
            return bad("is empty");
        }
        if seg == "." || seg == ".." {
            return bad("must not be '.' or '..'");
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'+'))
        {
            return bad("uses characters that are not allowed in a store path");
        }
    }
    Ok(())
}

/// Validate and normalise a store prefix (no leading/trailing slash).
pub fn normalize_store_prefix(prefix: &str) -> HostResult<String> {
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        return Err(
            HostError::invalid("store-prefix", "store prefix is empty").with_hint(format!(
                "use '{DEFAULT_STORE_PREFIX}' or a path like 'owner/repo/store'"
            )),
        );
    }
    validate_segments(prefix, "store prefix")?;
    Ok(prefix.to_string())
}

/// One `[[remote]]` entry: where the repo lives and how we authenticate to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    /// Name as the user refers to it (`origin`, `upstream`).
    pub name: String,
    /// The parsed URL.
    pub url: RemoteUrl,
    /// Where gitiup keeps its own objects inside the remote (`refs/**`,
    /// `packs/**`, `kv/**` live under this).
    pub store_prefix: String,
    /// Credential profile name from `[credentials.*]`.
    pub credentials_profile: Option<String>,
    /// Per-remote timeout for fetch/push/PUT operations.
    pub timeout: Duration,
    /// Free-form options (merged with the URL query string).
    pub options: BTreeMap<String, String>,
}

impl RemoteConfig {
    /// Build and validate a remote from a name and a URL string.
    pub fn new(name: &str, url: &str) -> HostResult<RemoteConfig> {
        Ok(RemoteConfig {
            name: validate_remote_name(name)?,
            url: RemoteUrl::parse(url)?,
            store_prefix: DEFAULT_STORE_PREFIX.to_string(),
            credentials_profile: None,
            timeout: DEFAULT_TIMEOUT,
            options: BTreeMap::new(),
        })
    }

    /// Set the store prefix (see [`normalize_store_prefix`]).
    pub fn with_store_prefix(mut self, prefix: &str) -> HostResult<RemoteConfig> {
        self.store_prefix = normalize_store_prefix(prefix)?;
        Ok(self)
    }

    /// Point at a `[credentials.*]` profile.
    pub fn with_credentials_profile(mut self, profile: impl Into<String>) -> Self {
        self.credentials_profile = Some(profile.into());
        self
    }

    /// Set the per-remote timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add an option.
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options
            .insert(key.into().to_ascii_lowercase(), value.into());
        self
    }

    /// The scheme shortcut.
    pub fn scheme(&self) -> RemoteScheme {
        self.url.scheme
    }

    /// Effective option: `options` table wins over the URL query string.
    pub fn option(&self, key: &str) -> Option<&str> {
        let key = key.to_ascii_lowercase();
        self.options
            .get(&key)
            .map(String::as_str)
            .or_else(|| self.url.query_param(&key))
    }

    /// All effective options (options table overlaid on the query string).
    pub fn effective_options(&self) -> BTreeMap<String, String> {
        let mut out = self.url.query.clone();
        out.extend(self.options.clone());
        out
    }

    /// The root gitiup's objects live under: the remote path plus the store
    /// prefix, e.g. `my-repo/gitiup`.
    pub fn root_prefix(&self) -> String {
        let url_path = self.url.path.trim_matches('/');
        if url_path.is_empty() {
            self.store_prefix.clone()
        } else {
            format!("{url_path}/{}", self.store_prefix)
        }
    }

    /// Key for a ref document: `<root>/refs/<name>` with the ref's own leading
    /// `refs/` folded into the store's `refs/` directory, so `refs/heads/main`
    /// lands at `<root>/refs/heads/main`.
    pub fn ref_key(&self, name: &RefName) -> String {
        let tail = name.as_str().strip_prefix("refs/").unwrap_or(name.as_str());
        format!("{}/refs/{}", self.root_prefix(), tail)
    }

    /// Root of the content-addressed records (`<root>/kv`).
    pub fn kv_root(&self) -> String {
        format!("{}/kv", self.root_prefix())
    }

    /// Key for a record (`<root>/kv/<kind>/<hash>`).
    pub fn kv_key(&self, namespace: &Namespace, oid: &Oid) -> String {
        format!("{}/{}/{}", self.kv_root(), namespace, oid.hex())
    }

    /// Key for a pack (`<root>/packs/<oid>.pack`).
    pub fn pack_key(&self, oid: &Oid) -> String {
        format!("{}/packs/{}.pack", self.root_prefix(), oid.hex())
    }

    /// Timeout in whole milliseconds (rounded up, never zero).
    pub fn timeout_ms(&self) -> u64 {
        self.timeout.as_millis().max(1) as u64
    }

    /// The URL with credentials redacted.
    pub fn redacted_url(&self) -> String {
        self.url.redacted()
    }
}

/// A `[credentials.<profile>]` block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CredentialProfile {
    /// Expected auth model; hosts use it to pick a credential resolver.
    #[serde(
        default,
        deserialize_with = "deserialize_auth",
        serialize_with = "serialize_auth"
    )]
    pub auth: Option<AuthModel>,
    /// Environment variable holding a token. Tokens never live in the file.
    pub token_env: Option<String>,
    /// Path to a private key (`ssh`, signing).
    pub key_path: Option<PathBuf>,
    /// Extra passthrough options for resolvers.
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

/// Credentials resolved for a remote (never print the token!).
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Resolved auth model.
    pub auth: AuthModel,
    /// Token, if one resolved from the environment.
    pub token: Option<String>,
    /// Key path, if configured.
    pub key_path: Option<PathBuf>,
    /// Human-readable provenance, e.g. `profile 'owner' (GITIUP_TOKEN)`.
    pub source: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("auth", &self.auth)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("key_path", &self.key_path)
            .field("source", &self.source)
            .finish()
    }
}

impl Credentials {
    /// Whether a token was resolved.
    pub fn has_token(&self) -> bool {
        self.token.as_deref().is_some_and(|t| !t.is_empty())
    }
}

fn deserialize_auth<'de, D>(deserializer: D) -> Result<Option<AuthModel>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(text) => AuthModel::parse(&text)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn serialize_auth<S>(value: &Option<AuthModel>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        None => serializer.serialize_none(),
        Some(auth) => serializer.serialize_some(auth.as_str()),
    }
}

fn validate_remote_name(name: &str) -> HostResult<String> {
    let name = name.trim();
    let bad = |why: &str| {
        Err(HostError::invalid("remote name", format!("'{name}' {why}"))
            .with_hint("remote names are 1-32 characters of [a-z0-9._-]"))
    };
    if name.is_empty() {
        return bad("is empty");
    }
    if name.len() > 32 {
        return bad("is longer than 32 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return bad("must be lower-case [a-z0-9._-]");
    }
    if !name.as_bytes()[0].is_ascii_alphanumeric() {
        return bad("must start with a letter or digit");
    }
    Ok(name.to_string())
}

/// Deserialization shape of `gitiup.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ConfigToml {
    schema_version: Option<u32>,
    default_remote: Option<String>,
    #[serde(default)]
    remote: Vec<RemoteToml>,
    #[serde(default)]
    credentials: BTreeMap<String, CredentialProfile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RemoteToml {
    name: String,
    url: String,
    #[serde(default)]
    store_prefix: Option<String>,
    #[serde(default)]
    credentials_profile: Option<String>,
    #[serde(default, deserialize_with = "deserialize_timeout_text")]
    timeout: Option<String>,
    #[serde(default)]
    options: BTreeMap<String, String>,
}

/// Accept `timeout = "45s"` and `timeout = 45` (seconds) alike, keeping the text
/// form so a round-trip through `to_toml` preserves what the user wrote.
fn deserialize_timeout_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Seconds(u64),
        Text(String),
    }
    Ok(match Option::<Repr>::deserialize(deserializer)? {
        None => None,
        Some(Repr::Seconds(n)) => Some(n.to_string()),
        Some(Repr::Text(text)) => Some(text),
    })
}

/// The parsed contents of a `gitiup.toml`.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Schema version of the file (defaults to [`SCHEMA_VERSION`] when absent).
    pub schema_version: u32,
    /// Remote used when none is named on the command line.
    pub default_remote: Option<String>,
    /// The remotes, in file order.
    pub remotes: Vec<RemoteConfig>,
    /// Credential profiles, referenced by `credentials-profile`.
    pub credentials: BTreeMap<String, CredentialProfile>,
    /// Where the file was read from, if it was read from disk.
    pub path: Option<PathBuf>,
    warnings: Vec<String>,
}

impl Config {
    /// Parse `gitiup.toml` text. `path` is only used to make errors actionable.
    pub fn parse(text: &str, path: Option<&Path>) -> HostResult<Config> {
        let source = path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| CONFIG_FILE_NAME.to_string());
        let raw: ConfigToml = toml::from_str(text).map_err(|e| {
            let mut err = HostError::invalid(
                CONFIG_FILE_NAME,
                format!("cannot parse {source}: {}", one_line(&e.to_string())),
            )
            .with_hint(format!(
                "see `gitiup remote add` for a valid {CONFIG_FILE_NAME} (schema-version {SCHEMA_VERSION})"
            ));
            err = err.with_location(&source, &e.to_string());
            err
        })?;

        let schema_version = match raw.schema_version {
            None => SCHEMA_VERSION,
            Some(0) => {
                return Err(HostError::invalid(
                    CONFIG_FILE_NAME,
                    "schema-version = 0 is not a schema version",
                )
                .with_location(&source, "")
                .with_hint(format!("use schema-version = {SCHEMA_VERSION}")));
            }
            Some(v) if v > crate::config::MAX_READ_SCHEMA_VERSION => {
                return Err(HostError::invalid(
                    CONFIG_FILE_NAME,
                    format!("schema-version {v} is newer than this gitiup understands"),
                )
                .with_location(&source, "")
                .with_hint(format!(
                    "upgrade gitiup (this build reads up to version {}), or rewrite {CONFIG_FILE_NAME} with schema-version = {SCHEMA_VERSION}",
                    crate::config::MAX_READ_SCHEMA_VERSION
                )));
            }
            Some(v) if v < MIN_SCHEMA_VERSION => {
                return Err(HostError::invalid(
                    CONFIG_FILE_NAME,
                    format!("schema-version {v} is no longer supported"),
                )
                .with_location(&source, "")
                .with_hint(format!("regenerate the file; supported range is {MIN_SCHEMA_VERSION}..={SCHEMA_VERSION}")));
            }
            Some(v) => v,
        };

        let mut remotes: Vec<RemoteConfig> = Vec::with_capacity(raw.remote.len());
        let mut warnings = Vec::new();
        for entry in raw.remote.iter() {
            let timeout = match entry.timeout.as_deref() {
                Some(text) => Some(parse_timeout(text).map_err(|e| {
                    e.with_location(&source, "")
                        .with_hint(format!("remote '{}' has an invalid timeout", entry.name))
                })?),
                None => None,
            };
            let mut remote = RemoteConfig {
                name: validate_remote_name(&entry.name)?,
                url: RemoteUrl::parse(&entry.url)?,
                store_prefix: match &entry.store_prefix {
                    Some(p) => {
                        normalize_store_prefix(p).map_err(|e| e.with_location(&source, ""))?
                    }
                    None => DEFAULT_STORE_PREFIX.to_string(),
                },
                credentials_profile: entry.credentials_profile.clone(),
                timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
                options: entry.options.clone(),
            };
            if remote.timeout > SLOW_TIMEOUT {
                warnings.push(format!(
                    "remote '{}' timeout {} is longer than {}: slow remotes stall every command",
                    remote.name,
                    format_timeout(remote.timeout),
                    format_timeout(SLOW_TIMEOUT)
                ));
            }
            if remote.url.user.is_some() && matches!(remote.scheme(), RemoteScheme::Https) {
                warnings.push(format!(
                    "remote '{}' embeds credentials in the URL: move them to a credentials-profile with token-env",
                    remote.name
                ));
            }
            if let Some(profile) = &remote.credentials_profile
                && !raw.credentials.contains_key(profile.as_str())
            {
                return Err(HostError::invalid(
                    CONFIG_FILE_NAME,
                    format!(
                        "remote '{}' refers to credentials-profile '{profile}', which is not defined",
                        remote.name
                    ),
                )
                .with_location(&source, "")
                .with_hint(format!(
                    "add [credentials.{profile}] or remove credentials-profile from the remote"
                )));
            }
            if let Some(existing) = remotes.iter().find(|r| r.name == remote.name) {
                return Err(HostError::invalid(
                    CONFIG_FILE_NAME,
                    format!("remote name '{}' is used twice", remote.name),
                )
                .with_location(&source, "")
                .with_hint(format!(
                    "rename one of them ('{}' -> '{}-2')",
                    existing.name, existing.name
                )));
            }
            // Store the raw URL string as written so `to_toml` round-trips.
            remote.url.raw = entry.url.trim().to_string();
            remotes.push(remote);
        }

        let default_remote = match raw.default_remote.as_deref().map(str::trim) {
            None => None,
            Some("") => None,
            Some(name) => {
                if !remotes.iter().any(|r| r.name == name) {
                    return Err(HostError::invalid(
                        CONFIG_FILE_NAME,
                        format!("default-remote '{name}' is not defined"),
                    )
                    .with_location(&source, "")
                    .with_hint(if remotes.is_empty() {
                        "add a [[remote]] with that name, or drop default-remote".to_string()
                    } else {
                        format!(
                            "defined remotes: {}",
                            remotes
                                .iter()
                                .map(|r| r.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }));
                }
                Some(name.to_string())
            }
        };

        if remotes.is_empty() {
            warnings.push(format!(
                "{CONFIG_FILE_NAME} has no [[remote]] entries; add one with `gitiup remote add <name> <url>`"
            ));
        }

        Ok(Config {
            schema_version,
            default_remote,
            remotes,
            credentials: raw.credentials,
            path: path.map(Path::to_path_buf),
            warnings,
        })
    }

    /// Read and parse a config file.
    pub fn load(path: &Path) -> HostResult<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            let err = HostError::from_io(CONFIG_FILE_NAME, path, e);
            if err.kind() == crate::error::HostErrorKind::NotFound {
                err.with_hint("create the file, or run `gitiup remote add` to start one")
            } else {
                err
            }
        })?;
        let mut config = Config::parse(&text, Some(path))?;
        config.path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Look for `gitiup.toml` in `start` and each parent directory. An explicit
    /// `GITIUP_CONFIG` wins over discovery.
    pub fn discover(start: &Path) -> HostResult<Option<(PathBuf, Config)>> {
        if let Ok(explicit) = std::env::var(CONFIG_PATH_ENV) {
            let path = PathBuf::from(explicit);
            return Config::load(&path).map(|c| Some((path, c)));
        }
        let mut dir = Some(start);
        while let Some(current) = dir {
            let candidate = current.join(CONFIG_FILE_NAME);
            if candidate.is_file() {
                return Config::load(&candidate).map(|c| Some((candidate, c)));
            }
            dir = current.parent();
        }
        Ok(None)
    }

    /// Discover from the current directory.
    pub fn load_default() -> HostResult<Option<(PathBuf, Config)>> {
        let cwd = std::env::current_dir()
            .map_err(|e| HostError::invalid("working directory", format!("{e}")))?;
        Config::discover(&cwd)
    }

    /// An empty, valid config with no remotes.
    pub fn empty() -> Config {
        Config {
            schema_version: SCHEMA_VERSION,
            ..Config::default()
        }
    }

    /// Render back to `gitiup.toml` text.
    pub fn to_toml(&self) -> HostResult<String> {
        let repr = ConfigToml {
            schema_version: Some(self.schema_version),
            default_remote: self.default_remote.clone(),
            remote: self
                .remotes
                .iter()
                .map(|r| RemoteToml {
                    name: r.name.clone(),
                    url: r.url.raw.clone(),
                    store_prefix: (r.store_prefix != DEFAULT_STORE_PREFIX)
                        .then(|| r.store_prefix.clone()),
                    credentials_profile: r.credentials_profile.clone(),
                    timeout: (r.timeout != DEFAULT_TIMEOUT).then(|| format_timeout(r.timeout)),
                    options: r.options.clone(),
                })
                .collect(),
            credentials: self.credentials.clone(),
        };
        toml::to_string_pretty(&repr).map_err(|e| {
            HostError::invalid("config", format!("cannot render {CONFIG_FILE_NAME}: {e}"))
        })
    }

    /// Render as JSON (`gitiup remote list --json`), with URLs redacted.
    pub fn to_json(&self) -> HostResult<serde_json::Value> {
        #[derive(Serialize)]
        struct RemoteJson {
            name: String,
            url: String,
            scheme: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            store_prefix: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            credentials_profile: Option<String>,
            timeout: String,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            options: BTreeMap<String, String>,
            root_prefix: String,
        }
        #[derive(Serialize)]
        struct ConfigJson {
            schema_version: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            default_remote: Option<String>,
            remote: Vec<RemoteJson>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            warnings: Vec<String>,
        }
        let value = ConfigJson {
            schema_version: self.schema_version,
            default_remote: self.default_remote.clone(),
            remote: self
                .remotes
                .iter()
                .map(|r| RemoteJson {
                    name: r.name.clone(),
                    url: r.redacted_url(),
                    scheme: r.scheme().as_str().to_string(),
                    store_prefix: (r.store_prefix != DEFAULT_STORE_PREFIX)
                        .then(|| r.store_prefix.clone()),
                    credentials_profile: r.credentials_profile.clone(),
                    timeout: format_timeout(r.timeout),
                    options: r.effective_options(),
                    root_prefix: r.root_prefix(),
                })
                .collect(),
            warnings: self.warnings.clone(),
        };
        serde_json::to_value(&value)
            .map_err(|e| HostError::invalid("config", format!("cannot render JSON: {e}")))
    }

    /// Write the file (atomically: temp file + rename).
    pub fn save(&self, path: &Path) -> HostResult<()> {
        let text = self.to_toml()?;
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|e| HostError::from_io("config directory", parent, e))?;
        let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        std::fs::write(&tmp, &text).map_err(|e| HostError::from_io("config write", &tmp, e))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            HostError::from_io("config rename", path, e)
        })
    }

    /// All remotes, in file order.
    pub fn remotes(&self) -> &[RemoteConfig] {
        &self.remotes
    }

    /// Look a remote up by name.
    pub fn remote(&self, name: &str) -> HostResult<&RemoteConfig> {
        self.remotes.iter().find(|r| r.name == name).ok_or_else(|| {
            HostError::not_found("remote", name).with_hint(if self.remotes.is_empty() {
                format!("no remotes are configured in {CONFIG_FILE_NAME}")
            } else {
                format!(
                    "configured remotes: {}",
                    self.remotes
                        .iter()
                        .map(|r| r.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        })
    }

    /// The default remote, or an error telling the user what to add.
    pub fn default_remote(&self) -> HostResult<&RemoteConfig> {
        match &self.default_remote {
            Some(name) => self.remote(name),
            None if self.remotes.len() == 1 => Ok(&self.remotes[0]),
            None if self.remotes.is_empty() => Err(HostError::not_found("remote", "default")
                .with_hint("add one with `gitiup remote add <name> <url>`")),
            None => Err(HostError::not_found("remote", "default").with_hint(format!(
                "set default-remote in {CONFIG_FILE_NAME}; candidates: {}",
                self.remotes
                    .iter()
                    .map(|r| r.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Resolve `name` (`None` = default).
    pub fn remote_or_default(&self, name: Option<&str>) -> HostResult<&RemoteConfig> {
        match name {
            Some(name) => self.remote(name),
            None => self.default_remote(),
        }
    }

    /// Add or replace a remote (used by `gitiup remote add`).
    pub fn add_remote(&mut self, remote: RemoteConfig) -> HostResult<()> {
        if let Some(existing) = self.remotes.iter_mut().find(|r| r.name == remote.name) {
            *existing = remote;
        } else {
            self.remotes.push(remote);
        }
        Ok(())
    }

    /// Remove a remote by name; returns the removed entry.
    pub fn remove_remote(&mut self, name: &str) -> HostResult<RemoteConfig> {
        let idx = self
            .remotes
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| HostError::not_found("remote", name))?;
        let removed = self.remotes.remove(idx);
        if self.default_remote.as_deref() == Some(removed.name.as_str()) {
            self.default_remote = self.remotes.first().map(|r| r.name.clone());
        }
        Ok(removed)
    }

    /// Set `default-remote`, validating that it exists.
    pub fn set_default_remote(&mut self, name: &str) -> HostResult<()> {
        self.remote(name)?;
        self.default_remote = Some(name.to_string());
        Ok(())
    }

    /// The credential profile referenced by a remote, if any.
    pub fn credential_profile(&self, remote: &RemoteConfig) -> Option<&CredentialProfile> {
        remote
            .credentials_profile
            .as_deref()
            .and_then(|name| self.credentials.get(name))
    }

    /// Resolve the credentials for a remote.
    ///
    /// Tokens are only ever read from the environment (`token-env`), never
    /// stored in the file, so a token-free path (ssh/cloud-role only) stays
    /// token-free.
    pub fn credentials_for(&self, remote: &RemoteConfig) -> HostResult<Credentials> {
        let profile = self.credential_profile(remote);
        let mut auth = AuthModel::Anonymous;
        let mut token = None;
        let mut key_path = None;
        let mut source = "no credentials configured".to_string();
        if let Some(name) = &remote.credentials_profile {
            let profile = profile.ok_or_else(|| {
                HostError::invalid(
                    CONFIG_FILE_NAME,
                    format!("credentials-profile '{name}' is not defined"),
                )
            })?;
            source = format!("profile '{name}'");
            if let Some(declared) = profile.auth {
                auth = declared;
                source.push_str(&format!(", auth = {}", declared.as_str()));
            }
            if let Some(env_key) = &profile.token_env {
                source.push_str(&format!(", {env_key}"));
                if let Ok(value) = std::env::var(env_key) {
                    if !value.trim().is_empty() {
                        token = Some(value);
                    }
                } else if auth.needs_credentials() && matches!(auth, AuthModel::Token) {
                    return Err(HostError::PermissionDenied(Box::new(
                        crate::error::PermissionDenied {
                            action: format!("authenticate to remote '{}'", remote.name),
                            actor: None,
                            hint: Some(format!(
                                "credentials-profile '{name}' reads {env_key}, which is not set",
                            )),
                        },
                    )));
                }
            }
            key_path = profile.key_path.clone();
        }
        // The scheme decides the default when the profile stays quiet.
        if profile.is_some_and(|p| p.auth.is_none()) {
            auth = match remote.scheme() {
                RemoteScheme::S3 => AuthModel::CloudRole,
                RemoteScheme::Ssh => AuthModel::SshKey,
                RemoteScheme::Https => AuthModel::Token,
                RemoteScheme::File => AuthModel::Filesystem,
            };
        }
        Ok(Credentials {
            auth,
            token,
            key_path,
            source,
        })
    }

    /// Where this config came from, for status and error lines.
    pub fn source(&self) -> String {
        self.path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<in-memory config>".to_string())
    }

    /// Non-fatal advice about the file.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Attach the config file location to an [`HostError::Invalid`].
trait WithLocation {
    fn with_location(self, source: &str, detail: &str) -> Self;
}

impl WithLocation for HostError {
    fn with_location(mut self, source: &str, detail: &str) -> Self {
        if let HostError::Invalid(inner) = &mut self {
            let mut location = source.to_string();
            if let Some(line) = detail.lines().find_map(|l| {
                l.split("line ")
                    .nth(1)
                    .map(|rest| rest.trim().trim_end_matches(','))
            }) {
                location.push(':');
                location.push_str(line);
            }
            inner.location = Some(location);
        }
        self
    }
}

/// Collapse a multi-line error into one line that keeps both the position
/// (first line) and the reason (last line).
pub(crate) fn one_line(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    match (lines.first(), lines.last()) {
        (Some(first), Some(last)) if first != last => {
            let at = first.strip_prefix("TOML parse error at ").unwrap_or(first);
            format!("{last} (at {})", at.trim_start_matches("error at "))
        }
        (Some(first), _) => first.to_string(),
        (None, _) => text.trim().to_string(),
    }
}

/// Highest schema version this build can read.
pub(crate) const MAX_READ_SCHEMA_VERSION: u32 = SCHEMA_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_parse_all_the_ways() {
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_timeout("45").unwrap(), Duration::from_secs(45));
        assert!(parse_timeout("0s").is_err());
        assert!(parse_timeout("2h").is_err());
        assert!(parse_timeout("soon").is_err());
        assert_eq!(format_timeout(Duration::from_millis(900)), "900ms");
        assert_eq!(format_timeout(Duration::from_secs(120)), "2m");
        assert_eq!(format_timeout(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn remote_names_are_validated() {
        assert_eq!(validate_remote_name(" origin ").unwrap(), "origin");
        for bad in ["", "-x", "Origin", "a b", &"z".repeat(33)] {
            assert!(validate_remote_name(bad).is_err(), "should reject {bad:?}");
        }
    }
}

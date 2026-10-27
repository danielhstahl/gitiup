//! Token auth: where a token comes from, where it may be sent, and what must never
//! happen to it.
//!
//! The rules, in order of how much trouble they prevent:
//!
//! 1. **a token is never in a URL.** GitHub accepts `https://user:token@host/…`;
//!    gitiup does not, because a URL is logged by proxies, shells, history files
//!    and bug reports, and a header is not. The transport asserts this on every
//!    request.
//! 2. **a token is only ever sent to the API host this remote was configured for**
//!    ([`Auth::may_send_to`]). An `api-base` that points somewhere else does not
//!    get the token unless the operator names that host in `token-host`. That is
//!    also why the client refuses redirects instead of following them.
//! 3. **a token is never printed.** [`Secret`] redacts in `Debug` and `Display`;
//!    error text names the *source* of the token, never the value.
//! 4. **plain `http://` is refused unless the host is loopback**, so a token cannot
//!    leave a machine unencrypted by accident.
//!
//! Resolution order — most explicit first — is in [`Auth::resolve`]. Nothing here
//! calls an OAuth flow: an OAuth app device flow is a *login*, and a CLI that logs
//! in on the user's behalf writes to a credential store, which is a decision this
//! ticket does not make. A token is something the user already has.

use std::fmt;

use gitiup_host::{AuthModel, CredentialProfile, HostError, HostResult, RemoteConfig};

use crate::codec::is_loopback_host;

/// Environment variables consulted for a token, in order.
///
/// `GITIUP_GITHUB_TOKEN` first because it is ours and cannot be inherited by
/// accident. `GH_TOKEN` next because it is what the `gh` CLI already sets, and a
/// user with `gh` logged in should not have to log in twice. `GITHUB_TOKEN` last
/// and with advice: it is the workflow's own token — scoped to one repository,
/// expires with the run, and any change opened with it is authored by
/// `github-actions[bot]`, which is rarely what a contributor meant.
pub const TOKEN_ENV_VARS: [&str; 3] = ["GITIUP_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];

/// The variable a build-in-the-workflow should use if it wants the workflow token.
pub const WORKFLOW_TOKEN_VAR: &str = "GITHUB_TOKEN";

/// Where tokens are read from.
///
/// A trait so that resolution can be tested without mutating a process-global
/// environment (which, in edition 2024, is `unsafe` to do from a test that runs
/// beside other tests).
pub trait Environment {
    /// Look up a variable; `None` when unset or blank.
    fn var(&self, name: &str) -> Option<String>;
}

/// The real environment. A variable set to whitespace counts as unset.
pub struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

/// A fixed set of variables, for tests and for a runner that was handed its
/// environment rather than inheriting one.
#[derive(Debug, Clone, Default)]
pub struct FixedEnvironment {
    /// The variables.
    pub values: std::collections::BTreeMap<String, String>,
}

impl FixedEnvironment {
    /// Build from an iterator of `(name, value)` pairs; blank values are dropped.
    pub fn new<const N: usize>(pairs: [(&str, &str); N]) -> FixedEnvironment {
        FixedEnvironment {
            values: pairs
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.trim().to_string()))
                .filter(|(_, value)| !value.is_empty())
                .collect(),
        }
    }
}

impl Environment for FixedEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }
}

/// A secret string that cannot accidentally print itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a value.
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }

    /// The value, for the one place that has to put it on the wire.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether anything is in here.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

/// Where a resolved token came from — the part that is safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// An environment variable (named).
    Env(String),
    /// The variable named by a `gitiup.toml` `[credentials.<name>]` profile.
    Profile {
        /// Profile name.
        profile: String,
        /// Variable it pointed at.
        variable: String,
    },
    /// The variable named by `[remote.options] token-env`.
    RemoteOption(String),
    /// No token found: anonymous reads only.
    Anonymous,
}

impl TokenSource {
    /// How to say it in a sentence.
    pub fn describe(&self) -> String {
        match self {
            TokenSource::Env(variable) => format!("environment variable {variable}"),
            TokenSource::Profile { profile, variable } => {
                format!("credentials profile '{profile}' ({variable})")
            }
            TokenSource::RemoteOption(variable) => {
                format!("remote option `token-env` ({variable})")
            }
            TokenSource::Anonymous => "no credentials (anonymous)".to_string(),
        }
    }

    /// Whether this is the ephemeral workflow token.
    pub fn is_workflow_token(&self) -> bool {
        match self {
            TokenSource::Env(variable) => variable == WORKFLOW_TOKEN_VAR,
            _ => false,
        }
    }
}

/// The credential this host will use: a token, or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    token: Option<Secret>,
    source: TokenSource,
    /// The only host the token may be sent to.
    allowed_host: String,
}

impl Auth {
    /// Resolve a token for `remote`.
    ///
    /// Order: `token-env` from the remote's options (most specific), then the
    /// profile's `token_env`, then [`TOKEN_ENV_VARS`]. An empty variable is treated
    /// as absent — CI systems set `GITHUB_TOKEN=""` more often than they leave it
    /// unset, and an empty bearer token is a 401 that explains nothing.
    pub fn resolve(
        remote: &RemoteConfig,
        profile: Option<&CredentialProfile>,
        api_host: &str,
    ) -> Auth {
        Auth::resolve_in(remote, profile, api_host, &ProcessEnvironment)
    }

    /// [`Auth::resolve`] against an explicit environment.
    pub fn resolve_in(
        remote: &RemoteConfig,
        profile: Option<&CredentialProfile>,
        api_host: &str,
        env: &dyn Environment,
    ) -> Auth {
        let mut candidates: Vec<(String, TokenSource)> = Vec::new();
        if let Some(variable) = remote.option("token-env") {
            candidates.push((
                variable.to_string(),
                TokenSource::RemoteOption(variable.to_string()),
            ));
        }
        if let Some(profile_name) = &remote.credentials_profile
            && let Some(variable) = profile.and_then(|profile| profile.token_env.as_ref())
        {
            candidates.push((
                variable.clone(),
                TokenSource::Profile {
                    profile: profile_name.clone(),
                    variable: variable.clone(),
                },
            ));
        }
        for variable in TOKEN_ENV_VARS {
            candidates.push((variable.to_string(), TokenSource::Env(variable.to_string())));
        }
        // The same variable may be named twice (a profile pointing at `GH_TOKEN`);
        // the first mention wins, so a more specific source is not shadowed.
        let mut seen: Vec<String> = Vec::new();
        for (variable, source) in candidates {
            if seen.contains(&variable) {
                continue;
            }
            seen.push(variable.clone());
            let Some(value) = env.var(&variable) else {
                continue;
            };
            return Auth {
                token: Some(Secret::new(value)),
                source,
                allowed_host: api_host.to_ascii_lowercase(),
            };
        }
        Auth {
            token: None,
            source: TokenSource::Anonymous,
            allowed_host: api_host.to_ascii_lowercase(),
        }
    }

    /// Anonymous, for a host that only reads.
    pub fn anonymous() -> Auth {
        Auth {
            token: None,
            source: TokenSource::Anonymous,
            allowed_host: String::new(),
        }
    }

    /// A token the caller already holds, for the given API host.
    pub fn from_token(token: Secret, api_host: &str) -> Auth {
        Auth {
            token: Some(token),
            source: TokenSource::Env("provided".into()),
            allowed_host: api_host.to_ascii_lowercase(),
        }
    }

    /// Whether a token was found.
    pub fn has_token(&self) -> bool {
        self.token.as_ref().is_some_and(|secret| !secret.is_empty())
    }

    /// The `Authorization` header value, or `None` when anonymous.
    ///
    /// `host` is the host the request is actually going to: sending a token to a
    /// host the operator did not name is the leak this exists to prevent, and a
    /// redirect is the usual way it would happen.
    pub fn header(&self, host: &str) -> HostResult<Option<String>> {
        let Some(secret) = &self.token else {
            return Ok(None);
        };
        let host = host.to_ascii_lowercase();
        if !self.allowed_host.is_empty() && host != self.allowed_host {
            return Err(HostError::denied(format!(
                "sending a token to {host} (it was resolved for {})",
                self.allowed_host
            ))
            .with_hint(
                "a token is only ever sent to the API host its remote names; if this \
                 enterprise server is genuinely the same forge, set `token-host` in the \
                 remote's options — and note that redirects are never followed for \
                 exactly this reason",
            ));
        }
        Ok(Some(format!("Bearer {}", secret.expose())))
    }

    /// Where the token came from (safe to print).
    pub fn source(&self) -> &TokenSource {
        &self.source
    }

    /// The auth model this maps to.
    pub fn model(&self) -> AuthModel {
        if self.has_token() {
            AuthModel::Token
        } else {
            AuthModel::Anonymous
        }
    }

    /// Things the operator should know about how we authenticated.
    pub fn advice(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.has_token() {
            out.push(
                "no token found: anonymous access only, so every ref write and every \
                 record write will be refused — set GITIUP_GITHUB_TOKEN (a fine-grained \
                 personal access token scoped to the one repository is enough)"
                    .to_string(),
            );
            return out;
        }
        if self.source.is_workflow_token() {
            out.push(format!(
                "the token came from {WORKFLOW_TOKEN_VAR}, the workflow's own token: it \
                 expires when the job ends, it cannot read outside this one repository, \
                 and a change opened with it is authored by the bot rather than by you — \
                 use it to read, and a token of your own to contribute"
            ));
        }
        if self.source.describe().contains("provided") {
            out.push("the token was passed in by the caller, not read from the environment".into());
        }
        out
    }

    /// Refuse a base URL that would put the token at risk.
    ///
    /// Called once, at open time, so a misconfigured remote fails before the first
    /// request rather than leaking on the way.
    pub fn check_base_url(url: &str) -> HostResult<()> {
        let Some((scheme, _)) = url.split_once("://") else {
            return Err(HostError::invalid(
                "github api-base",
                format!("'{url}' is not an absolute URL"),
            )
            .with_hint("expected https://api.github.com or https://ghe.example.com/api/v3"));
        };
        if !scheme.eq_ignore_ascii_case("https") {
            let host = crate::codec::url_host(url);
            if !is_loopback_host(&host) {
                return Err(HostError::invalid(
                    "github api-base",
                    format!("'{url}' is plain {scheme}:// to a non-loopback host"),
                )
                .with_hint(
                    "a bearer token must not cross a network unencrypted; use https:// \
                     (plain http is accepted for 127.0.0.1 only, for a local test server)",
                ));
            }
        }
        if url.contains('@') {
            return Err(HostError::invalid(
                "github api-base",
                "'…@…' in an API base URL is not used: credentials go in a header",
            )
            .with_hint("drop the userinfo from the URL and set GITIUP_GITHUB_TOKEN"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(url: &str) -> RemoteConfig {
        RemoteConfig::new("origin", url).unwrap()
    }

    #[test]
    fn a_secret_does_not_print_itself() {
        let secret = Secret::new("ghp_supersecret");
        let rendered = format!("{secret:?} {secret}");
        assert!(!rendered.contains("supersecret"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn a_token_only_goes_to_the_host_that_asked_for_it() {
        let auth = Auth::from_token(Secret::new("x"), "api.github.com");
        assert!(auth.header("api.github.com").unwrap().is_some());
        let err = auth.header("evil.example.com").unwrap_err();
        assert_eq!(err.kind(), gitiup_host::HostErrorKind::PermissionDenied);
        assert!(err.to_string().contains("evil.example.com"), "{err}");
        assert!(Auth::anonymous().header("anything").unwrap().is_none());
    }

    #[test]
    fn an_empty_environment_variable_is_no_token() {
        // CI sets these to "" constantly; treating that as a token produces a 401
        // that looks like a permission problem.
        let env = FixedEnvironment::new([("GITIUP_GITHUB_TOKEN", "   ")]);
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git"),
            None,
            "api.github.com",
            &env,
        );
        assert!(!auth.has_token());
        assert_eq!(auth.source(), &TokenSource::Anonymous);
        assert!(
            auth.advice()
                .iter()
                .any(|line| line.contains("GITIUP_GITHUB_TOKEN")),
            "{:?}",
            auth.advice()
        );
    }

    #[test]
    fn resolution_order_is_most_specific_first() {
        let env = FixedEnvironment::new([
            ("GH_TOKEN", "from-gh"),
            ("GITHUB_TOKEN", "from-workflow"),
            ("MINE", "from-profile"),
            ("REMOTE_OPTION", "from-remote-option"),
        ]);
        let profile = CredentialProfile {
            token_env: Some("MINE".into()),
            ..Default::default()
        };
        // Nothing more specific: the workspace variable wins over the workflow one.
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git"),
            None,
            "api.github.com",
            &env,
        );
        assert_eq!(auth.source(), &TokenSource::Env("GH_TOKEN".into()));
        // A profile for this remote is more specific than a global variable.
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git").with_credentials_profile("owner"),
            Some(&profile),
            "api.github.com",
            &env,
        );
        assert_eq!(
            auth.source(),
            &TokenSource::Profile {
                profile: "owner".into(),
                variable: "MINE".into()
            }
        );
        // The remote's own option beats the profile.
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git")
                .with_credentials_profile("owner")
                .with_option("token-env", "REMOTE_OPTION"),
            Some(&profile),
            "api.github.com",
            &env,
        );
        assert_eq!(
            auth.source(),
            &TokenSource::RemoteOption("REMOTE_OPTION".into())
        );
    }

    #[test]
    fn plain_http_to_a_real_host_is_refused_before_anything_is_sent() {
        assert!(Auth::check_base_url("https://api.github.com").is_ok());
        assert!(Auth::check_base_url("http://127.0.0.1:8099/api").is_ok());
        let err = Auth::check_base_url("http://api.internal/repo").unwrap_err();
        assert!(err.to_string().contains("unencrypted"), "{err}");
        assert!(Auth::check_base_url("https://user@host/").is_err());
        assert!(Auth::check_base_url("api.github.com").is_err());
    }

    #[test]
    fn the_workflow_token_comes_with_a_warning() {
        let env = FixedEnvironment::new([("GITHUB_TOKEN", "workflow-token")]);
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git"),
            None,
            "api.github.com",
            &env,
        );
        assert!(auth.source().is_workflow_token());
        assert!(
            auth.advice()
                .iter()
                .any(|line| line.contains("authored by the bot")),
            "{:?}",
            auth.advice()
        );
    }
}

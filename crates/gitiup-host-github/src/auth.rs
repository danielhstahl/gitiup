//! Token auth: where a token comes from, where it may be sent, and what must never
//! happen to it.
//!
//! The rules, in order of how much trouble they prevent:
//!
//! 1. **a token is never in a URL.** GitHub accepts `https://user:token@host/…`;
//!    gitiup does not, because a URL is logged by proxies, shells, history files
//!    and bug reports, and a header is not. The transport asserts this on every
//!    request.
//! 2. **a token is only ever sent to the API origin this remote was configured for**
//!    ([`Auth::header`], scoped by [`gitiup_host::scope`]). An `api-base` that points
//!    somewhere else does not get the token unless the operator names that host in
//!    `token-host`. That is also why the client refuses redirects instead of following
//!    them.
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

use gitiup_host::scope::{self, Breach, Origin};
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
    /// The only origins the token may be sent to: the API origin this remote names,
    /// plus any extra one the operator spelled out in `token-host`.
    allowed: Vec<Origin>,
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
        api_base: &str,
    ) -> Auth {
        Auth::resolve_in(remote, profile, api_base, &ProcessEnvironment)
    }

    /// [`Auth::resolve`] against an explicit environment.
    pub fn resolve_in(
        remote: &RemoteConfig,
        profile: Option<&CredentialProfile>,
        api_base: &str,
        env: &dyn Environment,
    ) -> Auth {
        let allowed = allowed_origins(remote, api_base);
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
                allowed,
            };
        }
        Auth {
            token: None,
            source: TokenSource::Anonymous,
            allowed,
        }
    }

    /// Anonymous, for a host that only reads.
    pub fn anonymous() -> Auth {
        Auth {
            token: None,
            source: TokenSource::Anonymous,
            allowed: Vec::new(),
        }
    }

    /// A token the caller already holds, for the given API host.
    pub fn from_token(token: Secret, api_host: &str) -> Auth {
        Auth {
            token: Some(token),
            source: TokenSource::Env("provided".into()),
            allowed: allowed_origins_no_options(api_host),
        }
    }

    /// Whether a token was found.
    pub fn has_token(&self) -> bool {
        self.token.as_ref().is_some_and(|secret| !secret.is_empty())
    }

    /// The `Authorization` header value, or `None` when anonymous.
    ///
    /// `target` is where the request is actually going — a full URL, or a bare
    /// `host[:port]` when that is all the caller knows. Sending a token to a host the
    /// operator did not name is the leak [`Auth`] exists to prevent, and a redirect is
    /// the usual way it would happen, so this is refused with
    /// [`gitiup_host::scope::refusal`]: exit **3**, both hosts named.
    pub fn header(&self, target: &str) -> HostResult<Option<String>> {
        let Some(secret) = &self.token else {
            return Ok(None);
        };
        let target = target.trim();
        let given = target.contains("://");
        let origin = Origin::parse(target)?;
        // A bare host is compared by host and port; a full URL is compared as an
        // origin, so an `https` API answered by an `http` host is a refusal even if the
        // name matches.
        let allowed = self.allowed.iter().any(|candidate| {
            if given {
                candidate.same_as(&origin)
            } else {
                candidate.host() == origin.host() && candidate.port() == origin.port()
            }
        });
        if allowed {
            return Ok(Some(format!("Bearer {}", secret.expose())));
        }
        let Some(configured) = self.allowed.first().cloned() else {
            return Err(HostError::denied(
                "there is no api-base for this token to belong to",
            ));
        };
        let refusal = scope::refusal(&configured, &origin, Breach::Plain);
        let advice = refusal.hint().unwrap_or_default().to_string();
        Err(refusal.with_hint(format!(
            "{advice} If this forge genuinely answers at two addresses, name the second one in \
             the remote's `token-host` option — and note that redirects are never followed for \
             exactly this reason."
        )))
    }

    /// The origins this token may be sent to, as labels. Safe to print, and worth
    /// printing: "which host would my token have gone to" is the first thing an
    /// operator wants after a refusal.
    pub fn allowed_hosts(&self) -> Vec<String> {
        self.allowed.iter().map(Origin::label).collect()
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
        // Where the token may go, printed rather than guessed at: after a refusal this is
        // the first question an operator has, and a scope nobody can see is a scope nobody
        // can check (giti-g5c.5).
        let allowed = self.allowed_hosts();
        if !allowed.is_empty() {
            out.push(format!(
                "the token from {} is sent to {} and nowhere else",
                self.source.describe(),
                allowed.join(", ")
            ));
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

/// The origins a token resolved for `remote` may be sent to.
///
/// The API origin the remote names, first and always; then whatever the operator added in
/// `token-host`, which exists for the one honest case — an enterprise forge that answers
/// at two addresses (the API host and a data host) and where the operator, and only the
/// operator, can say they are the same forge. A redirect never adds to this list: the
/// list is built from this machine's config, once, before anything is sent.
///
/// `token-host` is a comma-separated list, and the entries are checked by the same two
/// rules the API base is: it must name an origin, and it must not be a route out of TLS.
fn allowed_origins(remote: &RemoteConfig, api_base: &str) -> Vec<Origin> {
    /// Why a `token-host` entry that leaves TLS is refused.
    const CLEAR_TEXT: &str = "plain http:// to a host that is not this machine: a bearer \
                              token must not cross a network unencrypted";
    let mut origins = allowed_origins_no_options(api_base);
    // Split on commas only. Splitting on whitespace as well would turn one mistyped entry
    // into three — and `Origin::parse` reads a bare word as a hostname, so a sentence
    // typed into a host list would quietly *widen* the scope instead of being refused.
    for extra in remote
        .option("token-host")
        .into_iter()
        .flat_map(|value| value.split(','))
    {
        let extra = extra.trim();
        if extra.is_empty() {
            continue;
        }
        // The same rule as `api-base`, applied to the entry rather than to the base:
        // a `token-host` that says `http://` to a host off this machine is an instruction
        // to send the bearer token unencrypted, which is the leak this whole module is a
        // refusal of (see [`Auth::check_base_url`], which says it for the base URL).
        let origin = match Origin::parse(extra) {
            Ok(origin) => origin,
            // A `token-host` that does not parse is a typo, and a typo in a list of
            // places a token may go is the one thing this file may not guess about.
            Err(err) => {
                eprintln!(
                    "warning: ignoring token-host '{extra}' for remote '{}': {err}",
                    remote.name
                );
                continue;
            }
        };
        if origin.scheme() == "http" && !is_loopback_host(origin.host()) {
            eprintln!(
                "warning: ignoring token-host '{extra}' for remote '{}': {CLEAR_TEXT}",
                remote.name
            );
            continue;
        }
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    origins
}

/// [`allowed_origins`] with nothing in `token-host`: one origin, or none for a bare host
/// that cannot be parsed.
fn allowed_origins_no_options(api_base: &str) -> Vec<Origin> {
    Origin::parse(api_base)
        .map(|origin| vec![origin])
        .unwrap_or_default()
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

    #[test]
    fn the_advice_names_the_origins_a_token_may_reach() {
        // A scope nobody can see is a scope nobody can check, so `gitiup remote show`
        // prints it (giti-g5c.5) — and prints the origins, never the secret.
        let env = FixedEnvironment::new([("GH_TOKEN", "ghp_not_a_real_token")]);
        let extras = || {
            remote("https://github.com/o/r.git").with_option("token-host", "data.github.example")
        };
        for (what, config) in [
            ("a plain remote", remote("https://github.com/o/r.git")),
            ("a remote naming a second forge address", extras()),
        ] {
            let auth = Auth::resolve_in(&config, None, "https://api.github.com", &env);
            let joined = auth.advice().join("\n");
            assert!(
                joined.contains("https://api.github.com"),
                "{what}: the advice has to say where the token goes: {joined}"
            );
            assert!(
                !joined.contains("ghp_not_a_real_token"),
                "{what}: advice is printed, so it must not carry the secret: {joined}"
            );
        }
        let auth = Auth::resolve_in(&extras(), None, "https://api.github.com", &env);
        assert!(
            auth.allowed_hosts()
                .contains(&"https://data.github.example".to_string()),
            "`token-host` widens the scope the operator named: {:?}",
            auth.allowed_hosts()
        );
    }

    #[test]
    fn token_host_widens_the_scope_but_a_typo_does_not() {
        let env = FixedEnvironment::new([("GH_TOKEN", "x")]);
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git"),
            None,
            "https://api.github.com",
            &env,
        );
        // Without the option, only the API origin: the data host of a real enterprise
        // forge is a *different* origin until somebody says so.
        assert!(auth.header("https://github.githubassets.com/x").is_err());
        let widened = Auth::resolve_in(
            &remote("https://github.com/o/r.git")
                .with_option("token-host", "github.githubassets.com"),
            None,
            "https://api.github.com",
            &env,
        );
        assert!(widened.header("https://github.githubassets.com/x").is_ok());
        // Still not the rest of the internet, and the refusal still names both hosts.
        let err = widened.header("https://decoy.example/x").unwrap_err();
        assert_eq!(err.kind(), gitiup_host::HostErrorKind::PermissionDenied);
        let text = err.to_string();
        assert!(
            text.contains("api.github.com") && text.contains("decoy.example"),
            "{text}"
        );
        // An entry that is not an origin is a typo in the list of places a token may go,
        // and the safe reading of a typo is the narrower one: the good entry still works,
        // the junk one grants nothing.
        let typoed = Auth::resolve_in(
            &remote("https://github.com/o/r.git")
                .with_option("token-host", "not a url, api.github.com"),
            None,
            "https://api.github.com",
            &env,
        );
        assert_eq!(
            typoed.allowed_hosts(),
            vec!["https://api.github.com".to_string()]
        );
        assert!(typoed.header("https://api.github.com/repos/o/r").is_ok());
        // And an entry that would take the token out of TLS is refused the same way,
        // whatever the hostname it names: `token-host` widens *where* a token may go, not
        // whether it has to stay encrypted on the way (`Auth::check_base_url` says the
        // same thing about `api-base`).
        let downgrading = Auth::resolve_in(
            &remote("https://github.com/o/r.git")
                .with_option("token-host", "http://data.example.com"),
            None,
            "https://api.github.com",
            &env,
        );
        assert_eq!(
            downgrading.allowed_hosts(),
            vec!["https://api.github.com".to_string()],
            "a clear-text token-host grants nothing"
        );
        // Loopback is the exception it always was: the local test server, on http.
        let local = Auth::resolve_in(
            &remote("https://github.com/o/r.git")
                .with_option("token-host", "http://127.0.0.1:9999"),
            None,
            "https://api.github.com",
            &env,
        );
        assert!(
            local
                .allowed_hosts()
                .contains(&"http://127.0.0.1:9999".to_string()),
            "{:?}",
            local.allowed_hosts()
        );
    }

    #[test]
    fn a_full_url_target_is_compared_as_an_origin_not_as_a_hostname() {
        // The difference the ticket turns on: a caller that hands over the whole URL gets
        // a scheme check with it, because "same host, now speaking http" is the leak a
        // redirect is most often asking for. A caller that only knows a hostname still
        // gets the hostname compared.
        let env = FixedEnvironment::new([("GH_TOKEN", "x")]);
        let auth = Auth::resolve_in(
            &remote("https://github.com/o/r.git"),
            None,
            "https://api.github.com",
            &env,
        );
        assert!(auth.header("https://api.github.com:443/repos/o/r").is_ok());
        let err = auth.header("http://api.github.com/repos/o/r").unwrap_err();
        assert_eq!(
            err.kind(),
            gitiup_host::HostErrorKind::PermissionDenied,
            "{err}"
        );
        assert!(
            auth.header("API.GitHub.com").is_ok(),
            "a bare host is a bare host"
        );
        assert!(
            auth.header("").is_err(),
            "nothing to compare is not a match"
        );
    }
}

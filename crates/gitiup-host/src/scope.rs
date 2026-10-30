//! The credential scope: which origin a credential may travel to, and the refusal when it
//! would not.
//!
//! A public mirror — the thing [`docs/federation.md`](../../../docs/federation.md) exists
//! to serve — is read by a stranger with **no credential at all**, and read by the owner
//! with exactly one. This module is about the second half of that sentence, because the
//! first half is only safe while the second holds: a credential is good for *one* origin,
//! the one its remote names, and every way gitiup can end up talking to a different host
//! has to refuse rather than reuse it.
//!
//! # The three ways a credential walks out the door
//!
//! | way | how it happens | [`Breach`] |
//! |-----|----------------|-----------|
//! | **a redirect** | the endpoint answers `302` with `Location:` on another host, and the client — or the `git`/`curl` binary this project deliberately drives instead of linking a transport — follows it | [`Breach::Redirect`] |
//! | **a URL rewrite** | an `insteadOf`-style alias, a pointer record that names a different host, a `git config` rewrite on the box: the URL gitiup *asked for* is not the URL the bytes come from | [`Breach::Rewrite`] |
//! | **a host named by foreign bytes** | the second store's URL was read out of the first store — a `gitiup.toml` that came over with a mirror, a record naming a mirror of a mirror — and the credential configured for the first is sitting in the environment | [`Breach::Introduced`] |
//!
//! All three are refused the same way: [`HostError::PermissionDenied`], which is exit
//! **3**, and the message **names both hosts** — the one the credential was configured
//! for and the one it was about to reach — because "which two hosts?" is the whole
//! question an operator has to answer, and a refusal that does not say them is a
//! mystery to debug rather than a fixable configuration.
//!
//! # What is *not* a breach
//!
//! Two spellings of one origin are one origin: `https://host` and `https://host:443`,
//! `Host` and `host`, a redirect to a *path* on the same host (an `https` server that
//! lives behind `/git/` is a real thing). A scheme change **is** a breach: an `https`
//! endpoint that redirects to `http` is asking to send the token in clear text, and that
//! is a refusal even though the hostname did not move.
//!
//! # Anonymous read is the other half
//!
//! Nothing here is needed to *read a public store*, and that is the point: a store
//! reached with no credential has no credential to scope, so
//! [`crate::Credentials::has_token`] is false and every guard in this module passes
//! trivially. The failure a stranger
//! gets when the store is not public is a `PermissionDenied` from the host, and the
//! failure when the store is public and simply empty is an ordinary `Ok` with nothing in
//! it — two different kinds, which is what the conformance bodies assert
//! (`refused_credentials_are_denied_not_dropped` and `a_public_store_reads_with_no_credential`).
//!
//! ```
//! use gitiup_host::scope::Scope;
//!
//! let configured = Scope::parse("https://api.github.com").expect("an origin");
//! // Same origin, different spelling: fine.
//! assert!(configured.guard_url("https://api.github.com:443/repos/o/r").is_ok());
//! // A path-only redirect stays inside the scope.
//! assert!(configured.guard_redirect("/repos/o/r").is_ok());
//! // A second host does not.
//! let err = configured.guard_url("https://decoy.example.net/").unwrap_err();
//! assert_eq!(err.exit_code(), 3);
//! let text = err.to_string();
//! assert!(text.contains("api.github.com") && text.contains("decoy.example.net"), "{text}");
//! ```

use std::fmt;

use crate::config::RemoteConfig;
use crate::error::{HostError, HostResult};

/// The default port of a scheme, so `https://host` and `https://host:443` compare equal.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" | "s3" => Some(443),
        "http" => Some(80),
        "ssh" => Some(22),
        _ => None,
    }
}

/// An origin: scheme, host and port, normalised.
///
/// Deliberately *not* [`crate::RemoteUrl`]: that type is a validated gitiup remote (a
/// repository path, an accepted scheme, loopback-only `http`), and a `Location:` header
/// or a URL read out of somebody else's config file is none of those things. An origin is
/// the smallest thing two endpoints can be compared by, and it parses anything with a
/// scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin {
    /// Lowercased scheme, without `://`.
    scheme: String,
    /// Lowercased host, brackets stripped from an IPv6 literal.
    host: String,
    /// Port, `None` when the scheme's default was used or none was given.
    port: Option<u16>,
}

impl Origin {
    /// Parse an origin out of any URL-looking string.
    ///
    /// Tolerant by design: this parses answers (`Location:` headers) and second-hand
    /// URLs, not just the remotes this build would accept. It still refuses a string with
    /// no host in it, because an origin that cannot be named cannot be named in a refusal.
    pub fn parse(url: &str) -> HostResult<Origin> {
        let text = url.trim();
        let Some((scheme, rest)) = text.split_once("://") else {
            // A bare host is an origin too: `api.github.com`, `127.0.0.1:8080`.
            return Origin::parse_host_only(text)
                .ok_or_else(|| Origin::refuse(text, "it has no scheme and no host"));
        };
        let scheme = scheme.trim().to_ascii_lowercase();
        if scheme.is_empty() {
            return Err(Origin::refuse(text, "it has no scheme"));
        }
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        // Userinfo is dropped, not compared: the scope is about where a credential goes,
        // and a URL that smuggles one in is refused by the config layer anyway.
        let hostport = match authority.rsplit_once('@') {
            Some((_user, hostport)) => hostport,
            None => authority,
        };
        Origin::from_parts(scheme, hostport).ok_or_else(|| Origin::refuse(text, "it names no host"))
    }

    /// An origin from a scheme and an authority (`host`, `host:port`, `[::1]:8080`).
    fn from_parts(scheme: String, hostport: &str) -> Option<Origin> {
        let hostport = hostport.trim();
        let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
            let (address, tail) = rest.split_once(']')?;
            let port = match tail.strip_prefix(':') {
                Some(port) => Some(port.parse::<u16>().ok()?),
                None if tail.is_empty() => None,
                // `[::1]x` is not an address in brackets, it is a mistake.
                None => return None,
            };
            (address, port)
        } else {
            match hostport.split_once(':') {
                // A colon that is not followed by a port is a typo (`https://host:88888/`),
                // not a host called `host` on no port: silently dropping it would send the
                // credential to the wrong place while the label said the right one.
                Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
                None => (hostport, None),
            }
        };
        // A trailing dot is the same name as without it (FQDN form), and a case change is
        // no different host; both would otherwise make a same-host redirect look like a
        // scope breach.
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let port = match port {
            Some(port) if Some(port) == default_port(&scheme) => None,
            other => other,
        };
        Some(Origin { scheme, host, port })
    }

    /// A bare `host` or `host:port`, assumed `https`.
    fn parse_host_only(text: &str) -> Option<Origin> {
        if text.is_empty() || text.contains(char::is_whitespace) || text.contains('/') {
            return None;
        }
        Origin::from_parts("https".to_string(), text)
    }

    fn refuse(text: &str, why: &str) -> HostError {
        HostError::invalid("origin", format!("'{text}' {why}")).with_hint(
            "an origin is `scheme://host[:port]`; a URL with a path is fine, a path with no \
             URL is not",
        )
    }

    /// An origin from a `scheme`, `host` and optional port, as a host record holds them.
    pub fn new(scheme: &str, host: &str, port: Option<u16>) -> Origin {
        Origin {
            scheme: scheme.to_ascii_lowercase(),
            host: host.trim().trim_end_matches('.').to_ascii_lowercase(),
            port: match port {
                Some(port) if Some(port) == default_port(&scheme.to_ascii_lowercase()) => None,
                other => other,
            },
        }
    }

    /// The origin of a configured remote.
    pub fn of_remote(remote: &RemoteConfig) -> Origin {
        Origin::new(
            remote.url.scheme.as_str(),
            &remote.url.host,
            remote.url.port,
        )
    }

    /// The origin of a remote, as a `file://` or in-memory store has no network origin,
    /// `None` for those.
    pub fn maybe_of_remote(remote: &RemoteConfig) -> Option<Origin> {
        matches!(
            remote.url.scheme,
            crate::RemoteScheme::Https | crate::RemoteScheme::Http | crate::RemoteScheme::S3
        )
        .then(|| Origin::of_remote(remote))
    }

    /// The scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, when one was given and is not the scheme's default.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Whether a credential for one may be sent to the other.
    ///
    /// Scheme included: `http` is not `https`, whatever the hostname says.
    pub fn same_as(&self, other: &Origin) -> bool {
        self == other
    }

    /// The origin's label, for reports and doctor output: `https://host`, with the port
    /// only when it is not the scheme's default.
    pub fn label(&self) -> String {
        // An IPv6 address only parses inside brackets, and a label nobody can paste back
        // into a URL is not a label.
        let host = match self.host.contains(':') {
            true => format!("[{}]", self.host),
            false => self.host.clone(),
        };
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme, host, port),
            None => format!("{}://{}", self.scheme, host),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// How the client came to be about to talk to a host other than the one it was configured
/// for.
///
/// The rule and the refusal are the same in every case; the *clause* is what makes the
/// message actionable, because "don't send it there" has a different fix depending on
/// whether a server redirected, somebody rewrote a URL, or a fetched store named a
/// second host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Breach {
    /// The client was answering a redirect when it reached the other origin.
    Redirect {
        /// The `Location:` value, as received.
        location: String,
    },
    /// The URL was rewritten between the config and the socket: an alias, an `insteadOf`,
    /// a pointer record that named a different host.
    Rewrite {
        /// The URL as it was configured, before the rewrite.
        declared: String,
    },
    /// The second host was named by bytes that came from the first: a `gitiup.toml`
    /// fetched along with a mirror, a record pointing at another store.
    Introduced {
        /// Where the name was read from, e.g. `gitiup.toml in the mirror`.
        source: String,
    },
    /// Nothing more specific: the target is simply not the configured origin.
    Plain,
}

impl Breach {
    /// The clause appended to the refusal, naming how the host changed.
    fn clause(&self) -> String {
        match self {
            Breach::Redirect { location } => format!(" after a {} redirect", quote(location)),
            Breach::Rewrite { declared } => {
                format!(" after {} was rewritten", quote(declared))
            }
            Breach::Introduced { source } => format!(" (the host came from {source})"),
            Breach::Plain => String::new(),
        }
    }

    /// The fix, which differs by how the host changed.
    fn remedy(&self, target: &Origin) -> String {
        match self {
            Breach::Redirect { .. } => format!(
                "gitiup does not follow a cross-origin redirect with a credential attached: \
                 point the remote's url at {target} (or at whatever the forge really lives at) \
                 and configure the profile for *that* remote. curl is run with --no-location \
                 and git is not handed the token for exactly this reason."
            ),
            Breach::Rewrite { .. } => format!(
                "a rewrite between the configured URL and the socket means the credential \
                 named by one remote would be spent on another: drop the rewrite, or add a \
                 [[remote]] for {target} and give that remote its own credentials-profile."
            ),
            Breach::Introduced { source: _ } => format!(
                "a host named by bytes that arrived from somewhere else never gets a \
                 credential: only this machine's own gitiup.toml decides where a token goes. \
                 If {target} is genuinely a remote you use, add it to gitiup.toml yourself."
            ),
            Breach::Plain => {
                "the credential belongs to one origin; if this store lives at two of them, \
                 configure two remotes, each with its own credentials-profile."
                    .to_string()
            }
        }
    }
}

fn quote(text: &str) -> String {
    format!("'{text}'")
}

/// The refusal itself: exit **3**, both hosts named.
///
/// Public because call sites raise it directly when they already know the two origins and
/// the reason — the forge adapter, which sees a `Location:` header it chose not to
/// follow, is that call site.
pub fn refusal(configured: &Origin, target: &Origin, how: Breach) -> HostError {
    let from = configured.label();
    let to = target.label();
    HostError::denied(format!(
        "the credential configured for {from} would have gone to {to}{}",
        how.clause()
    ))
    .with_hint(format!(
        "{} {}",
        how.remedy(target),
        "A credential is only ever sent to the origin its own remote names."
    ))
}

/// A credential's scope: the one origin it may be sent to.
///
/// Cheap to build, cheap to carry, and the type that makes a call site read as what it
/// is: `scope.guard(target)?` before a request, rather than a hostname comparison that
/// someone has to remember to normalise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    configured: Origin,
}

impl Scope {
    /// The scope of a configured remote.
    pub fn for_remote(remote: &RemoteConfig) -> Scope {
        Scope {
            configured: Origin::of_remote(remote),
        }
    }

    /// A scope from an origin someone already parsed.
    pub fn for_origin(origin: Origin) -> Scope {
        Scope { configured: origin }
    }

    /// A scope from a URL.
    pub fn parse(url: &str) -> HostResult<Scope> {
        Ok(Scope {
            configured: Origin::parse(url)?,
        })
    }

    /// The origin this credential may be sent to.
    pub fn origin(&self) -> &Origin {
        &self.configured
    }

    /// The origin's label, for reports and doctor output.
    pub fn label(&self) -> String {
        self.configured.label()
    }

    /// Refuse unless `target` is this scope's origin.
    pub fn guard(&self, target: &Origin) -> HostResult<()> {
        self.guard_breach(target, Breach::Plain)
    }

    /// Refuse unless the URL's origin is this scope's origin, and say how the target
    /// differed.
    pub fn guard_breach(&self, target: &Origin, how: Breach) -> HostResult<()> {
        if self.configured.same_as(target) {
            return Ok(());
        }
        Err(refusal(&self.configured, target, how))
    }

    /// Refuse unless `url`'s origin is in scope, and hand back the origin that was
    /// checked (so a caller can name it in a report without parsing twice).
    pub fn guard_url(&self, url: &str) -> HostResult<Origin> {
        let target = Origin::parse(url)?;
        self.guard(&target)?;
        Ok(target)
    }

    /// Check a `Location:` header from this scope's origin.
    ///
    /// Relative locations — `/git/repo.git`, `next/path` — resolve to the same origin and
    /// pass; an absolute URL to another host is refused with [`Breach::Redirect`] and the
    /// header value quoted in the message, which is the sentence an operator needs when a
    /// server has moved.
    pub fn guard_redirect(&self, location: &str) -> HostResult<Origin> {
        let target = self.resolve_redirect(location)?;
        self.guard_breach(
            &target,
            Breach::Redirect {
                location: location.to_string(),
            },
        )?;
        Ok(target)
    }

    /// The origin a `Location:` header resolves to, against this scope's origin.
    fn resolve_redirect(&self, location: &str) -> HostResult<Origin> {
        let location = location.trim();
        if location.is_empty() {
            return Err(HostError::invalid(
                "redirect",
                "the endpoint answered a redirect with no Location",
            ));
        }
        if location.contains("://") {
            return Origin::parse(location);
        }
        // A location without a scheme is a path on the origin that sent it — same origin
        // by definition, and refusing it would break every server that lives behind a
        // path prefix.
        Ok(self.configured.clone())
    }

    /// Refuse because a URL that is not this scope's origin was named by somebody else's
    /// bytes.
    ///
    /// The `Introduced` case, spelled as a method because the caller has nothing else to
    /// say: it did not choose the target at all, which is precisely why it gets no
    /// credential.
    pub fn refuse_introduced(&self, target: &Origin, source: &str) -> HostError {
        refusal(
            &self.configured,
            target,
            Breach::Introduced {
                source: source.to_string(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_spellings_of_one_origin_are_one_origin() {
        let plain = Origin::parse("https://api.github.com").unwrap();
        assert_eq!(plain.port(), None, "443 is the scheme's own port");
        assert_eq!(
            Origin::parse("https://API.GitHub.com:443/repos/o/r").unwrap(),
            plain
        );
        assert_eq!(Origin::parse("https://api.github.com./x").unwrap(), plain);
        assert!(plain.same_as(&Origin::parse("https://api.github.com/repos/o/r").unwrap()));
    }

    #[test]
    fn a_port_that_is_not_the_default_makes_a_different_origin() {
        let a = Origin::parse("http://127.0.0.1:8080/repo.git").unwrap();
        let b = Origin::parse("http://127.0.0.1:9090/repo.git").unwrap();
        assert!(!a.same_as(&b));
        assert_eq!(a.label(), "http://127.0.0.1:8080");
        assert_eq!(
            Origin::parse("http://127.0.0.1:80/x").unwrap().label(),
            "http://127.0.0.1"
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_in_a_label() {
        let origin = Origin::parse("http://[::1]:8788/repo.git").unwrap();
        assert_eq!(origin.host(), "::1");
        assert_eq!(origin.label(), "http://[::1]:8788");
        assert_eq!(origin, Origin::parse("http://[::1]:8788/other").unwrap());
    }

    #[test]
    fn a_scheme_downgrade_is_a_breach_even_on_one_host() {
        let https = Scope::parse("https://git.example.net/repo.git").unwrap();
        let err = https
            .guard_url("http://git.example.net/repo.git")
            .expect_err("clear text is a different origin");
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("https://git.example.net"), "{err}");
        assert!(err.to_string().contains("http://git.example.net"), "{err}");
    }

    #[test]
    fn a_path_only_redirect_stays_inside_the_scope() {
        let scope = Scope::parse("https://git.example.net/repo.git").unwrap();
        assert_eq!(
            scope.guard_redirect("/git/repo.git").unwrap(),
            scope.origin().clone()
        );
        assert!(scope.guard_redirect("HEAD").is_ok());
        let err = scope.guard_redirect("").unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::Invalid, "{err}");
    }

    #[test]
    fn a_redirect_to_another_host_is_refused_naming_both() {
        let scope = Scope::parse("https://git.example.net/repo.git").unwrap();
        let err = scope
            .guard_redirect("https://decoy.example.org/repo.git")
            .unwrap_err();
        assert_eq!(err.kind(), crate::HostErrorKind::PermissionDenied);
        assert_eq!(err.exit_code(), 3, "a store refusal, not a bad request");
        let text = err.to_string();
        assert!(text.contains("https://git.example.net"), "{text}");
        assert!(text.contains("https://decoy.example.org"), "{text}");
        assert!(text.contains("redirect"), "{text}");
        assert!(
            err.hint()
                .is_some_and(|hint| hint.contains("point the remote's url at")),
            "the refusal says what to do: {text}"
        );
    }

    #[test]
    fn a_rewrite_names_the_url_it_started_from() {
        let scope = Scope::parse("https://git.example.net/repo.git").unwrap();
        let mirror = Origin::parse("https://mirror.example.net/repo.git").unwrap();
        let err = scope
            .guard_breach(
                &mirror,
                Breach::Rewrite {
                    declared: "https://git.example.net/repo.git".to_string(),
                },
            )
            .unwrap_err();
        assert_eq!(err.exit_code(), 3);
        let text = err.to_string();
        assert!(text.contains("rewritten"), "{text}");
        assert!(text.contains("mirror.example.net"), "{text}");
    }

    #[test]
    fn a_host_named_by_foreign_bytes_gets_no_credential() {
        let first = Scope::parse("https://store.example.net/repo.git").unwrap();
        let second = Origin::parse("https://elsewhere.example.org/repo.git").unwrap();
        let err = first.refuse_introduced(&second, "gitiup.toml fetched from the mirror");
        assert_eq!(err.kind(), crate::HostErrorKind::PermissionDenied);
        assert_eq!(err.exit_code(), 3);
        let text = err.to_string();
        assert!(text.contains("store.example.net"), "{text}");
        assert!(text.contains("elsewhere.example.org"), "{text}");
        assert!(
            text.contains("gitiup.toml fetched from the mirror"),
            "{text}"
        );
        assert!(
            err.hint()
                .is_some_and(|hint| hint.contains("this machine's own")),
            "and it says who decides where a token goes: {text}"
        );
    }

    #[test]
    fn an_unparsable_origin_is_a_usage_refusal_not_a_crash() {
        for bad in [
            "",
            "not a url",
            "://host/x",
            "https://",
            "https://host:80000/x/y",
            "https://host:notaport/x/y",
        ] {
            let err = Origin::parse(bad).expect_err("{bad} is not an origin");
            assert_eq!(err.kind(), crate::HostErrorKind::Invalid, "{bad}: {err}");
        }
    }

    #[test]
    fn a_bare_host_is_an_origin_because_a_config_names_one_that_way() {
        assert_eq!(
            Origin::parse("api.github.com").unwrap(),
            Origin::parse("https://api.github.com").unwrap()
        );
    }

    #[test]
    fn the_scope_of_a_remote_is_the_remote_itself() {
        let remote = RemoteConfig::new("origin", "https://git.example.net/owner/repo.git")
            .expect("a remote");
        let scope = Scope::for_remote(&remote);
        assert_eq!(scope.label(), "https://git.example.net");
        assert!(
            scope
                .guard_url("https://git.example.net/other/repo.git")
                .is_ok()
        );
        assert!(
            scope
                .guard_url("https://evil.example/owner/repo.git")
                .is_err()
        );
    }

    #[test]
    fn a_local_store_has_no_network_scope() {
        let local = RemoteConfig::new("here", "file:///srv/git/repo.git").expect("a remote");
        assert_eq!(Origin::maybe_of_remote(&local), None);
        let bucket = RemoteConfig::new("there", "s3://gitiup-forge/repo").expect("a remote");
        assert_eq!(
            Origin::maybe_of_remote(&bucket).map(|origin| origin.label()),
            Some("s3://gitiup-forge".to_string())
        );
    }
}

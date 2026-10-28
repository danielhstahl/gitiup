//! Which host serves which remote — and what happens when nothing does.
//!
//! This is the composition root's job, and only this crate may do it: `gitiup-host`
//! defines the traits and ships the hosts it ships (`fs`, a bucket, plain git), and
//! forge adapters live in their own crates behind their own features. The CLI is
//! where those two meet, so the CLI is also where "this remote is a forge and you
//! built the binary without the forge adapter" has to be answered — in those words,
//! naming the flag to turn on, rather than as an unknown scheme or a silent fallback
//! to a host that can only read refs.
//!
//! Nothing here talks to a forge. The only thing this file knows about GitHub is the
//! name of the adapter that serves it, which is what makes the refusal possible in a
//! build that cannot reach one.

use gitiup_host::{
    Config, CredentialProfile, FsHost, Host, HostError, HostErrorKind, RemoteConfig, RemoteScheme,
};

use crate::CliError;

/// The cargo feature that puts a github adapter in the binary. Named in every
/// refusal, because "not supported" without a fix is a dead end.
pub const FORGE_FEATURE: &str = "hosts-github";

/// The forge hosts this build can *name*, used only to explain a missing adapter —
/// never to talk to one. An adapter added later is recognised by its `host-type`
/// option, which is why that option wins when both are present.
const FORGE_HOSTS: &[&str] = &["github.com"];

/// Usage for `gitiup doctor --remotes`.
pub const USAGE: &str = "\
gitiup doctor --remotes — say which host serves each configured remote.

USAGE:
    gitiup doctor --remotes [--json]

Reads `gitiup.toml` and, for every `[[remote]]`, reports the host that would serve
it and what that host says about itself. Nothing is written and nothing is pushed.
A forge remote is asked for its own account of the repository; a bucket or a plain
git remote is classified only, because probing those needs credentials and a
network and a doctor nobody runs is a doctor that tells you nothing.

Exit codes: 0 every remote has a host (warnings possible) · 6 a remote has no host
this build can serve · 2 usage.
";

/// A host that serves a remote, described.
#[derive(Debug, Clone)]
pub struct Served {
    /// Short kind: `github`, `s3`, `git`, `fs`.
    pub kind: String,
    /// Which code implements it, version included.
    pub implemented_by: String,
    /// One line the host offers to a human.
    pub summary: String,
}

/// What `gitiup doctor --remotes` found about one remote.
#[derive(Debug)]
pub struct RemoteReport {
    /// The remote's name as the user typed it.
    pub name: String,
    /// The URL with any credential removed.
    pub url: String,
    /// The host that serves it, or the refusal that says why nothing does.
    pub served: Result<Served, String>,
    /// What the serving host says the caller should know (its caveats).
    pub advice: Vec<String>,
}

impl RemoteReport {
    /// Whether this remote has a host at all.
    pub fn is_served(&self) -> bool {
        self.served.is_ok()
    }

    /// The report as a human-readable paragraph.
    pub fn text(&self) -> String {
        let mut out = match &self.served {
            Ok(served) => format!("{} [{}] — {}", self.name, served.kind, self.url),
            Err(why) => format!("{} — {} ({})", self.name, self.url, why),
        };
        for line in &self.advice {
            out.push_str(&format!("\n    · {line}"));
        }
        out
    }

    /// The report as JSON: the same facts, the same spelling.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "url": self.url,
            "served": match &self.served {
                Ok(served) => serde_json::json!({
                    "host": served.kind,
                    "by": served.implemented_by,
                    "summary": served.summary,
                }),
                Err(why) => serde_json::json!({"error": why}),
            },
            "advice": self.advice,
        })
    }
}

/// Is this remote one that needs a forge adapter rather than a plain host?
///
/// `host-type = "github"` in `[remote.options]` is the explicit spelling; the
/// hostname is the convenience, because `https://github.com/owner/repo` is what
/// everyone types. A GitHub Enterprise remote has no github.com in its URL, so it
/// needs `api-base` or `host-type` — and saying so is this function's job.
pub fn wants_forge(remote: &RemoteConfig) -> bool {
    if let Some(declared) = remote.option("host-type") {
        return matches!(
            declared.trim().to_ascii_lowercase().as_str(),
            "github" | "gh"
        );
    }
    let host = remote.url.host.to_ascii_lowercase();
    FORGE_HOSTS
        .iter()
        .any(|forge| host == *forge || host.ends_with(&format!(".{forge}")))
        || remote.option("api-base").is_some()
}

#[cfg_attr(
    feature = "hosts-github",
    allow(
        dead_code,
        reason = "the adapter answers, so nothing needs the refusal"
    )
)]

/// The error a forge remote gets in a build without the adapter.
///
/// A `SchemeUnknown` naming the flag, because to such a build that is exactly what
/// it is: nothing in this binary serves that remote. The alternative — falling back
/// to the plain-git host because `https://` happens to work for `git fetch` — would
/// let `gitiup submit` "succeed" against a remote whose change database it cannot
/// read, which is a worse failure than refusing.
pub fn forge_without_adapter(remote: &RemoteConfig) -> HostError {
    HostError::SchemeUnknown(Box::new(gitiup_host::error::SchemeUnknown {
        scheme: "github".to_string(),
        supported: vec![
            "s3".into(),
            "https".into(),
            "ssh".into(),
            "file".into(),
            #[cfg(feature = "hosts-github")]
            "github".into(),
        ],
        hint: Some(format!(
            "'{}' points at a forge repository ({}), and this gitiup was built without \
             the `{FORGE_FEATURE}` feature. Rebuild with `--features {FORGE_FEATURE}` \
             (it is on by default), or point the remote at a host this build does serve.",
            remote.name,
            remote.redacted_url()
        )),
    }))
}

/// What can be said about a remote without opening anything.
///
/// Cheap enough for a doctor run on a machine with no network, which is the machine
/// where the answer matters most.
pub fn classify(remote: &RemoteConfig) -> Result<Served, HostError> {
    if wants_forge(remote) {
        #[cfg(feature = "hosts-github")]
        return Ok(Served {
            kind: "github".to_string(),
            implemented_by: format!("gitiup-host-github {}", env!("CARGO_PKG_VERSION")),
            summary: "the forge's own API, with gitiup's refs and records stored in the \
                      repository itself"
                .to_string(),
        });
        #[cfg(not(feature = "hosts-github"))]
        return Err(forge_without_adapter(remote));
    }
    let (kind, summary) = match remote.url.scheme {
        RemoteScheme::S3 => ("s3", "one bucket as a complete remote"),
        RemoteScheme::File => ("fs", "a local directory"),
        RemoteScheme::Https | RemoteScheme::Http | RemoteScheme::Ssh => (
            "git",
            "a plain git remote: refs and packs, no change database",
        ),
    };
    Ok(Served {
        kind: kind.to_string(),
        implemented_by: format!("gitiup-host {}", env!("CARGO_PKG_VERSION")),
        summary: summary.to_string(),
    })
}

/// The host that serves a remote, opened for real.
///
/// The composition root's other half: [`classify`] says what *would* serve a remote
/// without touching it, and this opens it. Every command that reads or writes a store
/// goes through here, so no command gets to invent its own storage or reach a forge
/// behind the host traits. `profile` is the credential profile named by the remote, if
/// any — the caller resolves it from the config, because only the config knows whether
/// a missing profile is an error.
pub fn open(
    remote: &RemoteConfig,
    profile: Option<&CredentialProfile>,
) -> Result<Box<dyn Host>, HostError> {
    if wants_forge(remote) {
        #[cfg(feature = "hosts-github")]
        {
            let transport = gitiup_host_github::curl::default_transport(remote)?;
            return Ok(Box::new(gitiup_host_github::GitHubHost::with_transport(
                remote, transport, profile,
            )?));
        }
        #[cfg(not(feature = "hosts-github"))]
        {
            let _ = profile;
            return Err(forge_without_adapter(remote));
        }
    }
    match remote.scheme() {
        RemoteScheme::File => Ok(Box::new(FsHost::open_or_create(remote.url.file_path())?)),
        RemoteScheme::S3 => Ok(Box::new(gitiup_host::S3Host::open_or_init_remote(remote)?)),
        RemoteScheme::Https | RemoteScheme::Http | RemoteScheme::Ssh => Ok(Box::new(
            gitiup_host::hosts::git::GitHost::open_or_init_remote(remote)?,
        )),
    }
}

/// The report for one remote: what serves it, and what that host warns about.
///
/// A forge remote is *opened*, because the adapter is the only thing that can read
/// what the forge says about the repository (may this credential push? is the
/// default branch there?) and because opening it is what proves the adapter is in
/// the build. The other hosts are classified only — see [`USAGE`].
pub fn report(remote: &RemoteConfig, profile: Option<&CredentialProfile>) -> RemoteReport {
    let mut report = RemoteReport {
        name: remote.name.clone(),
        url: remote.redacted_url(),
        served: classify(remote).map_err(|why| plain(&why)),
        advice: Vec::new(),
    };
    if !wants_forge(remote) {
        return report;
    }
    match forge_host(remote, profile) {
        Ok(opened) => {
            report.served = Ok(Served {
                kind: opened.kind,
                implemented_by: opened.implemented_by,
                summary: opened.summary,
            });
            report.advice = opened.advice;
        }
        Err(why) => report.served = Err(plain(&why)),
    }
    report
}

/// A refused error as one line, for a report that has room for exactly one string
/// per remote. The taxonomy's own `Display` already renders the hint (it is part of
/// the answer, not a footnote), so appending it here would print it twice.
fn plain(error: &HostError) -> String {
    error.to_string()
}

/// The adapter's own account of itself: its caveats, and the capability it cannot
/// promise. Empty when there is no adapter to ask.
#[allow(unused_variables)]
fn forge_host(
    remote: &RemoteConfig,
    profile: Option<&CredentialProfile>,
) -> Result<Opened, HostError> {
    #[cfg(feature = "hosts-github")]
    {
        let transport = gitiup_host_github::curl::default_transport(remote)?;
        let host = gitiup_host_github::GitHubHost::with_transport(remote, transport, profile)?;
        let info = host.describe();
        let summary = info.summary_line();
        Ok(Opened {
            kind: format!("{:?}", info.kind).to_ascii_lowercase(),
            implemented_by: info.implemented_by,
            summary,
            advice: host.advice(),
        })
    }
    #[cfg(not(feature = "hosts-github"))]
    {
        let _ = profile;
        Err(forge_without_adapter(remote))
    }
}

/// The parts of a host this command prints, held without a trait object so the
/// adapter-specific `advice()` call stays where it belongs.
struct Opened {
    kind: String,
    implemented_by: String,
    summary: String,
    advice: Vec<String>,
}

/// `gitiup doctor --remotes`.
pub fn run(args: &[String]) -> Result<(), CliError> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--remotes" => {}
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => {
                return Err(CliError::usage(format!(
                    "unknown doctor flag '{other}'; `gitiup doctor --help` lists what \
                     can be inspected"
                )));
            }
        }
    }
    let (path, config) = match Config::load_default() {
        Ok(Some(found)) => found,
        Ok(None) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"remotes": [], "note": "no gitiup.toml found"})
                );
            } else {
                println!(
                    "no gitiup.toml found, so no remotes are configured; the file lives \
                     at the top of the repository (or where `$GITIUP_CONFIG` points)"
                );
            }
            return Ok(());
        }
        Err(why) => {
            return Err(CliError::refused(
                format!("gitiup.toml could not be read: {}", plain(&why)),
                "fix the file; every remote must name a host this build can serve",
            ));
        }
    };
    let reports: Vec<RemoteReport> = config
        .remotes()
        .iter()
        .map(|remote| report(remote, config.credential_profile(remote)))
        .collect();
    let refused = reports.iter().any(|report| !report.is_served());
    if json {
        let body = serde_json::json!({
            "config": path.display().to_string(),
            "remotes": reports.iter().map(RemoteReport::json).collect::<Vec<_>>(),
            "warnings": config.warnings(),
        });
        println!("{body}");
    } else {
        println!("{} — {} remote(s)", path.display(), reports.len());
        for report in &reports {
            println!("{}", report.text());
        }
        for warning in config.warnings() {
            println!("warning: {warning}");
        }
        if refused {
            println!(
                "a remote above has no host this build can serve; the exit code is 6 so \
                 a script can branch on it"
            );
        }
    }
    if refused {
        return Err(CliError::refused(
            "a configured remote has no host in this build".to_string(),
            format!("the message above names the feature to build with (`{FORGE_FEATURE}`)"),
        ));
    }
    Ok(())
}

/// Keeps the taxonomy import honest: a report that cannot say *why* nothing serves a
/// remote has not answered anything.
#[allow(dead_code)]
fn kind_name(kind: HostErrorKind) -> &'static str {
    kind.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(url: &str) -> RemoteConfig {
        RemoteConfig::new("origin", url).expect("a remote")
    }

    #[test]
    fn a_forge_remote_is_recognised_from_the_url_and_from_the_option() {
        assert!(wants_forge(&remote("https://github.com/gitiup/gitiup.git")));
        assert!(wants_forge(&remote("https://www.github.com/gitiup/gitiup")));
        let declared =
            remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "github");
        assert!(wants_forge(&declared));
        let enterprise = remote("https://git.example.com/gitiup/gitiup")
            .with_option("api-base", "https://git.example.com/api/v3");
        assert!(wants_forge(&enterprise));
        assert!(
            !wants_forge(&remote("https://git.example.com/gitiup/gitiup")),
            "an ordinary git server is not a forge just because it is https"
        );
        assert!(!wants_forge(&remote("s3://gitiup-forge/my-repo")));
        let not_a_forge =
            remote("https://git.example.com/gitiup/gitiup").with_option("host-type", "git");
        assert!(!wants_forge(&not_a_forge));
    }

    #[test]
    fn every_ordinary_remote_classifies_itself() {
        assert_eq!(
            classify(&remote("s3://gitiup-forge/my-repo"))
                .expect("s3")
                .kind,
            "s3"
        );
        assert_eq!(
            classify(&remote("file:///srv/gitiup")).expect("fs").kind,
            "fs"
        );
        assert_eq!(
            classify(&remote("ssh://git@example.com/gitiup/gitiup.git"))
                .expect("git")
                .kind,
            "git"
        );
        let report = report(&remote("ssh://git@example.com/gitiup/gitiup.git"), None);
        assert!(report.is_served());
        assert!(report.text().contains("git"));
        assert_eq!(report.json()["served"]["host"], "git");
        assert!(
            report.json()["served"]["by"]
                .as_str()
                .unwrap()
                .starts_with("gitiup-host ")
        );
    }

    #[test]
    #[cfg(not(feature = "hosts-github"))]
    fn without_the_adapter_a_forge_remote_names_the_flag() {
        let github = remote("https://github.com/gitiup/gitiup");
        let error = forge_without_adapter(&github);
        assert_eq!(error.kind(), HostErrorKind::SchemeUnknown);
        let text = error.to_string();
        assert!(text.contains(FORGE_FEATURE), "{text}");
        assert!(text.contains("--features"), "and how to turn it on: {text}");
        let refused = classify(&github).expect_err("nothing serves it");
        assert!(refused.to_string().contains(FORGE_FEATURE));
        let report = report(&github, None);
        assert!(
            !report.is_served(),
            "and the doctor says so instead of pretending: {:?}",
            report.served
        );
    }

    #[test]
    #[cfg(feature = "hosts-github")]
    fn with_the_adapter_a_forge_remote_is_github() {
        let served = classify(&remote("https://github.com/gitiup/gitiup")).expect("github");
        assert_eq!(served.kind, "github");
        assert!(served.implemented_by.contains("gitiup-host-github"));
    }

    #[test]
    fn an_unknown_doctor_flag_is_a_usage_error() {
        let error = run(&["--squids".to_string()]).expect_err("usage");
        assert_eq!(error.code, 2);
    }
}

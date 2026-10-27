//! The environment fingerprint, *collected* (giti-1rs.4).
//!
//! [`gitiup_attest`] decides what an environment *means*: the fields, the derived
//! fingerprint, and what it takes for a run to match a requirement. Someone still
//! has to fill the fields in, and that someone is this module — the half that touches
//! the machine. It answers one question and answers it the same way every time:
//!
//! > what sort of machine was this?
//!
//! ```text
//! os + version ── std's OS family, VERSION_ID from /etc/os-release
//! arch ────────── std::env::consts::ARCH
//! image digest ── GITIUP_IMAGE_DIGEST, /run/.containerenv, or nothing at all
//! toolchain ───── rustc, node, python, git, make --version  (or GITIUP_TOOLCHAIN)
//! ──────────────► EnvironmentReport ──► Environment.fingerprint (derived, attest crate)
//! ```
//!
//! # The image *or* the toolchain, and why both anyway
//!
//! A run inside a digest-pinned container has already described itself completely:
//! the image digest *is* the toolchain, from the base layer up. A run on a bare
//! host has no such handle, and there the local toolchain inventory is all there
//! is — which is why a report with neither carries a fingerprint that identifies
//! nothing, and why the inventory is collected whether or not an image was found.
//! It costs a handful of `--version` calls, and it makes the difference between
//! "the digests differ" and "the digests differ because one machine had rustc
//! 1.88": a reviewer can read the second sentence.
//!
//! # Nothing here is guessed
//!
//! * **No image digest is invented.** Resolving `ubuntu:24.04` to a digest is a
//!   network operation; a runner that faked one would be forging the most
//!   load-bearing field in the manifest. If the runner was told (`GITIUP_IMAGE_DIGEST`)
//!   or the container runtime published it (`/run/.containerenv`), it is recorded;
//!   otherwise the report says nothing and the note says why.
//! * **A tool that is not installed is absent, not `unknown`.** An inventory entry
//!   has to be a version the tool reported, or nothing at all — `unknown` would
//!   match a requirement of `unknown` and read as a machine that has everything.
//! * **Every version is what the tool said**, first numeric token of `--version`,
//!   with the `v` of `v22.3.0` dropped. Rewriting versions into a tidier shape is
//!   normalisation's job (giti-1rs.3), not the probe's.
//!
//! ```
//! use gitiup_run::env::Probe;
//!
//! // What this machine is, as a manifest would record it.
//! let probe = Probe::collect();
//! assert_eq!(probe.environment.arch, std::env::consts::ARCH);
//! // Note: a plan that must not spawn anything asks for the bare minimum instead.
//! let quiet = Probe::bare(std::env::consts::ARCH);
//! assert!(quiet.environment.toolchain.is_empty());
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use gitiup_attest::{EnvironmentReport, ImageRef, ToolchainEntry};

/// The tools inventoried when the environment does not name others.
///
/// The set giti-1rs.4 names: a language, two runtimes, and the two tools a CI job
/// reaches for before anything else. It is deliberately small and stable — the
/// inventory is inside a signed digest, so a tool added here changes what honest
/// runs hash to.
pub const DEFAULT_TOOLS: [&str; 5] = ["rustc", "node", "python", "git", "make"];

/// Set to a `sha256:…` digest by whoever started the container: the only way a
/// runner learns what image it is in, short of the runtime publishing it.
pub const IMAGE_DIGEST_ENV: &str = "GITIUP_IMAGE_DIGEST";

/// Set to the reference that was asked for (`ubuntu:24.04`). Evidence only — the
/// digest is the pin — but the field a human reads first.
pub const IMAGE_REFERENCE_ENV: &str = "GITIUP_IMAGE_REFERENCE";

/// Comma-separated `name=version` pairs that *replace* the discovered inventory.
///
/// For the hermetic case: a build system that already knows exactly which tools its
/// steps saw (a pinned toolchain dir, a cross toolchain) should say so rather than
/// let this module ask `PATH`.
pub const TOOLCHAIN_ENV: &str = "GITIUP_TOOLCHAIN";

/// Set to `off` to skip the toolchain probe: a runner that wants the arithmetic of
/// a fingerprint without spawning five processes.
pub const ENV_PROBE_ENV: &str = "GITIUP_ENV_PROBE";

/// Podman publishes the image it started us in here; `IMAGE` is the reference and
/// `IMAGE_DIGEST` (or `IMAGE_ID`) the digest, as `KEY="value"` lines.
const CONTAINER_ENV_FILE: &str = "/run/.containerenv";

/// The OS release file, and its canonical fallback.
const OS_RELEASE_FILES: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

/// A shell-less command that prints a version and exits: the whole probe's reach.
///
/// Returns `None` for "this tool is not here" — the probe never invents, and an
/// absent tool is a fact about the machine rather than an error in the run.
pub type CommandRunner<'a> = &'a dyn Fn(&str) -> Option<String>;

/// What this machine looks like to a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The environment, as a report field: no fingerprint yet, because that is
    /// derived by the format when the manifest is built.
    pub environment: EnvironmentReport,
    /// Human-readable remarks: what could not be discovered, and why. Surfaced in
    /// `gitiup env`, and put on the attestation's annotations so a refusal can be
    /// read without re-running the probe.
    pub notes: Vec<String>,
}

impl Probe {
    /// Collect everything: OS, arch, image, and the toolchain inventory.
    pub fn collect() -> Probe {
        Probe::collect_with(&|tool| command_version(tool))
    }

    /// [`Self::collect`], with the process runner injected — so tests (and anyone
    /// probing a machine other than this one) decide what `--version` said.
    pub fn collect_with(run: CommandRunner<'_>) -> Probe {
        let mut notes = Vec::new();
        let os = os_release();
        if let Some(distro) = &os.distribution {
            // The distribution name is evidence, not identity: the manifest's `os`
            // field is the family a policy asks about, and a digest must not depend
            // on whether one image calls itself "ubuntu" and another "ubuntu-24".
            notes.push(format!("distribution: {distro}"));
        }
        if os.version.is_none() {
            notes.push("no VERSION_ID in the release file: this OS version is unclaimed".into());
        }
        let image = container_image(read_env, &mut notes);
        let toolchain = match std::env::var(ENV_PROBE_ENV) {
            Ok(value) if value.trim().eq_ignore_ascii_case("off") => {
                notes.push(format!(
                    "{ENV_PROBE_ENV}=off: no toolchain inventory was taken"
                ));
                Vec::new()
            }
            _ => toolchain(read_env, run, &mut notes),
        };
        Probe {
            environment: EnvironmentReport {
                provider: None,
                os: Some(os.os),
                os_version: os.version,
                arch: std::env::consts::ARCH.to_string(),
                image,
                toolchain,
            },
            notes,
        }
    }

    /// The bare minimum: this machine's architecture, and the silence that says so.
    ///
    /// For a path that must not spawn anything — a plan, a probe on behalf of
    /// somebody else's job. An empty inventory is honest as long as it is *labelled*
    /// as an absent one, which is what the notes are for.
    pub fn bare(arch: &str) -> Probe {
        Probe {
            environment: EnvironmentReport {
                provider: None,
                os: Some(std::env::consts::OS.to_string()),
                os_version: None,
                arch: arch.to_string(),
                image: None,
                toolchain: Vec::new(),
            },
            notes: vec![format!(
                "{ENV_PROBE_ENV}=off: architecture only, no toolchain inventory"
            )],
        }
    }

    /// Record the backend that ran (or would have run) the job, so `provider` and
    /// `provenance.sandbox` say the same word.
    pub fn with_provider(mut self, provider: &str) -> Probe {
        self.environment.provider = Some(provider.to_string());
        self
    }

    /// `x_env_*` annotations: the notes, made safe to put in a manifest.
    ///
    /// Annotations are strings only, and are part of `claims` — the volatile half —
    /// so saying "we could not find the image digest" here cannot move a result
    /// digest, and a verifier reads it without re-probing.
    pub fn annotations(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if self.notes.is_empty() {
            return out;
        }
        out.insert(
            "x_env_notes".to_string(),
            self.notes.join(" · ").chars().take(512).collect(),
        );
        out
    }

    /// One line for a terminal: the machine class and the inventory.
    pub fn describe(&self) -> String {
        self.environment.describe()
    }
}

/// Read an environment variable. Indirected so the container-image question can be
/// asked of anything, in tests and in a runner that carries a job's environment.
fn read_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// What the release file says about this OS, in the three shapes anyone cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    /// The family the manifest's `os` field documents: `linux`, `macos`, `windows`.
    pub os: String,
    /// `VERSION_ID` (`24.04`), when the image published one.
    pub version: Option<String>,
    /// `ID` (`ubuntu`), kept as evidence in the notes rather than as identity.
    pub distribution: Option<String>,
}

/// The OS a report should claim.
///
/// The *family* comes from `std` because that is the vocabulary the format
/// documents and the one the simulator already uses (`runs-on: ubuntu-24.04` ⇒
/// `linux`), so a policy that says `require_os = linux` reads the same on a plan and
/// on a run. The release file adds the version — the field `major` rounds — and the
/// distribution name, which is evidence and lives in the notes.
fn os_release() -> OsInfo {
    let mut info = OsInfo {
        os: std::env::consts::OS.to_string(),
        version: None,
        distribution: None,
    };
    for path in OS_RELEASE_FILES {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let fields = key_values(&text);
        info.distribution = fields
            .get("ID")
            .map(|id| id.to_ascii_lowercase())
            .filter(|id| !id.is_empty());
        info.version = fields
            .get("VERSION_ID")
            .filter(|version| !version.is_empty())
            .cloned();
        if info.version.is_some() || info.distribution.is_some() {
            break;
        }
    }
    info
}

/// The container image this process is inside, if the runner or the runtime said.
fn container_image(
    env: impl Fn(&str) -> Option<String>,
    notes: &mut Vec<String>,
) -> Option<ImageRef> {
    let digest = env(IMAGE_DIGEST_ENV)
        .or_else(|| container_env_file(digest_from))
        .and_then(|text| text.trim().parse::<gitiup_attest::Digest>().ok());
    let reference = env(IMAGE_REFERENCE_ENV).or_else(|| container_env_file(reference_from));
    if let Some(digest) = digest {
        return Some(ImageRef { reference, digest });
    }
    if reference.is_some() || inside_container() {
        // Say it out loud: "containerised, image unpinned" is a different fact from
        // "not in a container", and the policy refusal a run may be about to hit
        // depends on which of the two it is.
        notes.push(format!(
            "running in a container with no image digest: a runtime does not publish one \
             unless asked, so set {IMAGE_DIGEST_ENV} to the digest you pulled"
        ));
    }
    None
}

/// Is this a container we simply have no digest for?
fn inside_container() -> bool {
    if Path::new("/.dockerenv").exists() || Path::new(CONTAINER_ENV_FILE).exists() {
        return true;
    }
    std::env::var("container").is_ok()
}

/// Parse the containerenv file and ask `ask` about the fields we care about.
fn container_env_file<T>(ask: impl Fn(&BTreeMap<String, String>) -> Option<T>) -> Option<T> {
    let text = std::fs::read_to_string(CONTAINER_ENV_FILE).ok()?;
    ask(&key_values(&text))
}

/// The digest podman/bubblewrap wrote, preferring an algorithm-tagged one.
fn digest_from(fields: &BTreeMap<String, String>) -> Option<String> {
    ["IMAGE_DIGEST", "IMGDIGEST", "IMAGE_ID"]
        .iter()
        .filter_map(|key| fields.get(*key))
        .find(|value| value.starts_with("sha256:"))
        .cloned()
}

/// The reference the image was started from.
fn reference_from(fields: &BTreeMap<String, String>) -> Option<String> {
    ["IMAGE", "IMAGE_NAME", "IMGNAME"]
        .iter()
        .filter_map(|key| fields.get(*key))
        .find(|value| !value.is_empty())
        .cloned()
}

/// Parse `KEY=VALUE` lines, with or without quotes (`KEY="value"`), ignoring
/// comments. Used for both `/etc/os-release` and `/run/.containerenv`, which are
/// the same shape.
fn key_values(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        out.insert(key.trim().to_ascii_uppercase(), value);
    }
    out
}

/// The toolchain inventory: what the runner's `PATH` can report, and no more.
fn toolchain(
    env: impl Fn(&str) -> Option<String>,
    run: CommandRunner<'_>,
    notes: &mut Vec<String>,
) -> Vec<ToolchainEntry> {
    if let Some(declared) = env(TOOLCHAIN_ENV) {
        return match declared_inventory(&declared) {
            Ok(entries) => entries,
            Err(what) => {
                notes.push(format!("{TOOLCHAIN_ENV} ignored: {what}"));
                Vec::new()
            }
        };
    }
    let mut entries = Vec::new();
    let mut missing = Vec::new();
    for tool in DEFAULT_TOOLS {
        match run(tool) {
            Some(version) => entries.push(ToolchainEntry {
                name: tool.to_string(),
                version,
            }),
            None => missing.push(tool),
        }
    }
    if !missing.is_empty() {
        notes.push(format!(
            "no version reported by {} (absent from this machine, so absent from the \
             inventory)",
            missing.join(", ")
        ));
    }
    // The manifest requires the inventory sorted; do it here so a caller cannot
    // forget (and so `normalize()` is a no-op rather than a fix).
    entries.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    entries.dedup_by(|a, b| a.name == b.name);
    entries
}

/// Parse `GITIUP_TOOLCHAIN` (`name=version,name=version`).
fn declared_inventory(text: &str) -> Result<Vec<ToolchainEntry>, String> {
    let mut entries = Vec::new();
    for pair in text.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((name, version)) = pair.split_once('=') else {
            return Err(format!("'{pair}' is not name=version"));
        };
        let name = name.trim().to_ascii_lowercase();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            return Err(format!("'{pair}' has an empty name or version"));
        }
        entries.push(ToolchainEntry {
            name,
            version: version.to_string(),
        });
    }
    if entries.is_empty() {
        return Err("nothing in it".to_string());
    }
    entries.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });
    entries.dedup_by(|a, b| a.name == b.name);
    Ok(entries)
}

/// Ask one tool what version it is.
fn command_version(tool: &str) -> Option<String> {
    for program in candidate_programs(tool) {
        let Ok(output) = Command::new(program).arg("--version").output() else {
            continue;
        };
        let text = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(version) = version_in(&text) {
            return Some(version.to_string());
        }
    }
    None
}

/// The programs that can answer for a tool name.
///
/// Only `python` needs this: most images ship `python3` and no `python`, and a
/// machine that has Python should not report that it has none.
fn candidate_programs(tool: &str) -> Vec<&str> {
    match tool {
        "python" => vec!["python", "python3"],
        other => vec![other],
    }
}

/// The version inside a `--version` line.
///
/// The first token that begins with a digit or a `v` followed by a digit, trimmed at
/// the first character that cannot be part of a version:
///
/// | tool | line | version |
///|------|------|---------|
///| rustc | `rustc 1.88.0 (9b0095a15 2025-06-20)` | `1.88.0` |
///| node | `v22.3.0` | `22.3.0` |
///| git | `git version 2.47.0` | `2.47.0` |
///| python | `Python 3.12.3` | `3.12.3` |
///| make | `GNU Make 4.3` | `4.3` |
pub fn version_in(text: &str) -> Option<&str> {
    for token in text.split_whitespace() {
        let Some(start) = token.find(|c: char| c.is_ascii_digit()) else {
            continue;
        };
        let head = &token[start..];
        let body = head
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()
            .unwrap_or_default()
            .trim_matches('.');
        if body.len() >= 3
            && body.contains(|c: char| c.is_ascii_digit())
            && body.starts_with(|c: char| c.is_ascii_digit())
        {
            return Some(body);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_what_the_tool_reported() {
        for (line, expected) in [
            ("rustc 1.88.0 (9b0095a15 2025-06-20)", "1.88.0"),
            ("v22.3.0", "22.3.0"),
            ("git version 2.47.0", "2.47.0"),
            ("Python 3.12.3", "3.12.3"),
            ("GNU Make 4.3", "4.3"),
            ("go version go1.24.4 linux/amd64", "1.24.4"),
        ] {
            assert_eq!(version_in(line), Some(expected), "{line}");
        }
        assert_eq!(version_in("no numbers at all"), None);
        assert_eq!(version_in(""), None);
    }

    #[test]
    fn a_declared_inventory_is_parsed_and_sorted() {
        let entries = declared_inventory("make=4.3, rustc=1.88.0 ,git=2.47.0").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["git", "make", "rustc"]);
        assert!(declared_inventory("nonsense").is_err());
        assert!(declared_inventory("rustc=").is_err());
        assert!(declared_inventory("").is_err());
    }

    #[test]
    fn key_values_survive_quotes_and_comments() {
        let fields = key_values("# comment\nIMAGE=\"ubuntu:24.04\"\nVERSION_ID=24.04\n\nodd\n");
        assert_eq!(
            fields.get("IMAGE").map(String::as_str),
            Some("ubuntu:24.04")
        );
        assert_eq!(fields.get("VERSION_ID").map(String::as_str), Some("24.04"));
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn a_digest_wins_and_a_reference_without_one_is_only_a_note() {
        let mut notes = Vec::new();
        let image = container_image(
            |name| match name {
                IMAGE_DIGEST_ENV => Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                ),
                IMAGE_REFERENCE_ENV => Some("ghcr.io/example/ci:1".into()),
                _ => None,
            },
            &mut notes,
        );
        let image = image.expect("the runner told us the digest");
        assert_eq!(image.reference.as_deref(), Some("ghcr.io/example/ci:1"));
        assert!(image.digest.to_string().starts_with("sha256:aaaa"));
        assert!(notes.is_empty());

        // Not a digest? Then nothing is claimed, and the note says why.
        let mut notes = Vec::new();
        let image = container_image(
            |name| match name {
                IMAGE_DIGEST_ENV => Some("ubuntu:24.04".into()),
                _ => None,
            },
            &mut notes,
        );
        assert!(image.is_none());
    }

    #[test]
    fn toolchain_comes_from_the_environment_when_declared() {
        let mut notes = Vec::new();
        let entries = toolchain(
            |name| (name == TOOLCHAIN_ENV).then(|| "rustc=1.88.0".to_string()),
            &|_| Some("9.9.9".to_string()),
            &mut notes,
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version, "1.88.0");
        assert!(notes.is_empty(), "{notes:?}");

        // A bogus declaration is refused loudly, not quietly.
        let mut notes = Vec::new();
        let entries = toolchain(
            |name| (name == TOOLCHAIN_ENV).then(|| "not-a-pair".to_string()),
            &|_| None,
            &mut notes,
        );
        assert!(entries.is_empty());
        assert!(notes.iter().any(|note| note.contains(TOOLCHAIN_ENV)));
    }

    #[test]
    fn a_tool_that_is_not_installed_is_absent_not_unknown() {
        let mut notes = Vec::new();
        let entries = toolchain(|_| None, &|_| None, &mut notes);
        assert!(entries.is_empty());
        assert!(
            notes.iter().any(|note| note.contains("rustc")),
            "the note should name what was missing: {notes:?}"
        );
    }

    #[test]
    fn the_inventory_is_never_a_list_of_mismatches() {
        let mut notes = Vec::new();
        let entries = toolchain(|_| None, &|tool| Some(format!("9.9.{tool}")), &mut notes);
        assert_eq!(entries.len(), DEFAULT_TOOLS.len());
        assert!(entries.windows(2).all(|w| w[0].name < w[1].name));
    }

    #[test]
    fn collecting_on_this_machine_produces_a_valid_environment() {
        let probe = Probe::collect();
        assert_eq!(probe.environment.arch, std::env::consts::ARCH);
        assert!(!probe.environment.arch.is_empty());
        // Whatever else this machine is, the report must be usable as a manifest
        // field: non-empty names, non-empty versions, sorted.
        for entry in &probe.environment.toolchain {
            assert!(
                !entry.name.is_empty() && !entry.version.is_empty(),
                "{entry:?}"
            );
        }
        assert!(
            probe
                .environment
                .toolchain
                .windows(2)
                .all(|w| w[0].name < w[1].name)
        );
        let report = probe.environment.clone();
        let mut environment = report.to_environment();
        environment.fix_fingerprint().unwrap();
        assert!(!probe.describe().is_empty());
        assert!(
            probe
                .annotations()
                .get("x_env_notes")
                .map(String::len)
                .unwrap_or(0)
                <= 512
        );
    }

    #[test]
    fn bare_is_honest_about_being_empty() {
        let probe = Probe::bare("x86_64");
        assert!(probe.environment.toolchain.is_empty());
        assert!(probe.environment.image.is_none());
        assert!(probe.annotations().contains_key("x_env_notes"));
        assert!(probe.describe().contains("x86_64"));
    }
}

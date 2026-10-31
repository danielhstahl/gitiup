//! `seatbelt`: the macOS sandbox — the one in-process confinement XNU offers a process
//! that has not been granted anything special.
//!
//! macOS has no Landlock, no seccomp filter and no user namespaces. What it has is the
//! kernel sandbox that `sandbox-exec(1)` and `sandbox_init(3)` drive: the same
//! mechanism every App Store app runs inside, reachable by an unprivileged process that
//! wants to restrict *itself*, given a profile written in SBPL. It is
//! [deprecated in the headers](https://developer.apple.com/documentation/kernel/1587446-sandbox_init)
//! and it is still in every macOS release, still what Bazel uses to sandbox a build
//! action on a Mac, and still enforced by XNU rather than by good manners.
//!
//! What it denies, and therefore what this backend claims:
//!
//! * **writes** outside the trees the job was given — `(deny file-write*)` and then an
//!   allow for each grant. This is *stronger* than the Linux in-process rung: it is a
//!   write denial for a specific set of paths rather than a rlimit.
//! * **reads** of the credential-shaped directories the job has no business opening
//!   (`~/.ssh`, `~/Library/Keychains`, the gitiup keystore, …). Landlock cannot do this
//!   at all, so on macOS the sentence "reads are not isolated" has an asterisk.
//! * **egress** — `(deny network*)`, or that plus one `(allow network-outbound …)` per
//!   allowlisted proxy. Kernel-enforced either way, which is what lets a quorum job run
//!   here: a job that ignores `HTTP_PROXY` has nowhere to go.
//!
//! What it does not do, stated because a reviewer has to be able to see it:
//!
//! * **no new namespaces, and no filesystem of its own.** The job sees the host's
//!   `/Users`, `/tmp` and process table, minus the denials. A container is still the
//!   stronger rung, which is why the ladder prefers it.
//! * **SBPL covers filesystem, network and a set of process operations** — not
//!   Mach IPC, not IOKit. A job inside Seatbelt can still talk to launchd services.
//!   This is why the escape checks are run rather than skipped: the claim is the
//!   observation, and a check the profile cannot express is reported as unchecked.
//! * **the profile API is deprecated.** Every macOS release so far ships it, and this
//!   backend refuses the rung when the profile does not parse on *this* macOS instead
//!   of assuming the next release behaves like this one.
//!
//! # Why a wrapper binary and not `sandbox_init` in a `pre_exec` hook
//!
//! `sandbox-exec -p '<profile>' <command>` is argv, which means
//! [`plan`](Sandbox::plan) can print the exact confinement a reviewer will get, and
//! `--json` can show it before anything runs. `sandbox_init` in a child would also do
//! `malloc` between `fork` and `execve`, which is exactly what a `pre_exec` hook must
//! not do. The rlimits that have no SBPL equivalent are still applied in the child, in
//! [`tune`](crate::backend::Sandbox::tune).
//!
//! One wart of the wrapper, stated rather than hidden: `sandbox-exec` takes the command
//! as its own first non-option argument, so a job whose `argv[0]` begins with `-` is
//! parsed as a flag and the spawn fails. That is a refusal and not an escape — nothing
//! runs unconfined — and no runner this tool has produces such an argv.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::backend::{Env, Kind, Launch, Sandbox};
use crate::egress::Egress;
use crate::escape::{self, Outcome};
use crate::limits;
use crate::platform;
use crate::probe::Probe;
use crate::spec::{Enforcement, Spec};

/// The operations a Seatbelt profile is built from, in the order SBPL wants them.
///
/// Written as `(deny …)` lines; the file is `(allow default)` plus denials, and a
/// later rule wins over an earlier one, so every allow-grant has to come *after* the
/// blanket denial it is carving a hole in.
const VERSION: &str = "(version 1)";
const DEFAULT: &str = "(allow default)";

/// The writes that are not "the job wrote to a file": the device nodes a build tool
/// opens to throw output away, and the descriptors the runner already handed it.
///
/// Shaped the way Apple's own sandbox files shape them: `path` for a device that is a
/// real node, `literal` for the per-process `std*` symlinks, and a `subpath` for the
/// tty family. Denying these is not stricter, it is a job that cannot `printf`.
const DEVICE_WRITES: [&str; 9] = [
    "(allow file-write-data (path \"/dev/null\"))",
    "(allow file-write-data (path \"/dev/zero\"))",
    "(allow file-write-data (path \"/dev/random\"))",
    "(allow file-write-data (path \"/dev/urandom\"))",
    "(allow file-write-data (path \"/dev/dtracehelper\"))",
    "(allow file-write-data (subpath \"/dev/ttys\"))",
    "(allow file-write-data (literal \"/dev/stdin\"))",
    "(allow file-write-data (literal \"/dev/stdout\"))",
    "(allow file-write-data (literal \"/dev/stderr\"))",
];

/// Denials that a profile *would like* to make but that older SBPL parsers refuse as
/// unknown operations. Each one is tried on its own by
/// [`supported_denials`], so the profile only ever contains operations this macOS
/// accepts, and the checks they underwrite are named either as observed or as
/// unchecked — never as assumed.
const OPTIONAL_DENIALS: [&str; 3] = ["process-trace", "task-read", "file-write-xattr"];

/// The Seatbelt backend.
#[derive(Debug, Clone, Copy)]
pub struct Seatbelt;

impl Seatbelt {
    /// The wrapper binary, if this machine has one.
    pub fn binary() -> Option<PathBuf> {
        platform::binary("sandbox-exec")
    }
}

/// One built profile: the text, and what it is meant to deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The SBPL source, ready for `sandbox-exec -p`.
    pub text: String,
    /// The denial names this profile claims, for the probe and for `guarantees`.
    pub denies: Vec<&'static str>,
}

impl Profile {
    /// The profile text, one line per rule.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.text.lines().map(str::trim_end)
    }
}

/// The directories whose *contents* a confined job must never read.
///
/// The point is the runner's own secrets: a stranger's build script has no use for the
/// keys that sign attestations, and on Linux there is nothing that can stop it opening
/// them (see [`crate::backends::inprocess`]), which is why the runner passes secret
/// names and never values. Seatbelt can actually refuse the open, so it does.
///
/// Everything here is under the *user's* home; system directories stay readable because
/// a build needs them.
pub fn credential_paths() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let Some(home) = home else {
        return Vec::new();
    };
    let candidates = [
        ".ssh",
        ".gnupg",
        ".aws",
        ".docker",
        ".kube",
        ".netrc",
        ".config/gh",
        ".config/gitiup",
        ".local/share/gitiup",
        "Library/Keychains",
        "Library/Application Support/Code/User",
    ];
    let mut paths: Vec<PathBuf> = Vec::new();
    for relative in candidates {
        let path = home.join(relative);
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    }
    // XDG_DATA_HOME, if it is set, is where the keystore actually lives.
    if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
        let path = PathBuf::from(data).join("gitiup");
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

/// Resolve a path the way the sandbox matches it.
///
/// On macOS `/var`, `/tmp` and `/etc` are symlinks into `/private`, and an SBPL rule
/// about `/var/folders/…` would match nothing at all because the kernel sees the
/// resolved path. Canonicalising the grants is not cosmetic: it is the difference
/// between a profile that confines and a profile that only looks like it does — and
/// the escape check for the scratch being writable is what notices when it is wrong.
fn grant_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Quote a path as an SBPL string.
fn quote(path: &Path) -> String {
    let text = path.display().to_string();
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Build the profile for one job.
///
/// `denials` is the subset of [`OPTIONAL_DENIALS`] this macOS's SBPL parser accepts,
/// as established by [`supported_denials`]; anything else is left out and reported as
/// unchecked rather than silently weakening the file.
pub fn profile_for(spec: &Spec, denials: &[&'static str]) -> Profile {
    let mut lines: Vec<String> = vec![VERSION.into(), DEFAULT.into()];
    let mut claims: Vec<&'static str> = vec!["fs-write-outside", "tcp-egress"];

    // --- writes: nothing, then the job's own trees.
    lines.push("".into());
    lines.push("; writes: only the trees this job was given".into());
    lines.push("(deny file-write*)".into());
    for rule in DEVICE_WRITES {
        lines.push((*rule).to_string());
    }
    // A tmpdir the job was not given is still a write target the sandbox must refuse;
    // the scratch is the only writable place, and it is named exactly.
    for path in spec.write_paths() {
        lines.push(format!(
            "(allow file-write* (subpath {}))",
            quote(&grant_path(&path))
        ));
    }

    // --- egress: nothing, or one hole for the proxy and nothing else.
    lines.push("".into());
    lines.push("; egress: default-deny, or the proxy alone".into());
    lines.push("(deny network*)".into());
    if let Some(proxy) = spec.egress.proxy() {
        let endpoint = proxy.endpoint();
        // SBPL wants `host:port`, and an IPv6 literal needs its brackets or the rule
        // does not parse.
        let remote = match endpoint {
            std::net::SocketAddr::V6(_) => format!("[{}]:{}", endpoint.ip(), endpoint.port()),
            _ => format!("{}:{}", endpoint.ip(), endpoint.port()),
        };
        lines.push(format!(
            "(allow network-outbound (remote tcp \"{remote}\"))"
        ));
    }

    // --- reads a stranger's build script has no business making.
    let credentials = credential_paths();
    if !credentials.is_empty() {
        lines.push("".into());
        lines.push("; credentials: the runner's own secrets are not the job's".into());
        for path in &credentials {
            lines.push(format!(
                "(deny file-read* (subpath {}))",
                quote(&grant_path(path))
            ));
        }
        claims.push("credential-reads");
    }

    // --- the optional, version-dependent denials. Each is claimed under its own name,
    // so a property is never credited to a rule this macOS did not accept.
    for denial in denials {
        lines.push(format!("(deny {denial})"));
        claims.push(match *denial {
            "process-trace" | "task-read" => "ptrace",
            other => other,
        });
    }

    Profile {
        text: lines.join("\n") + "\n",
        denies: claims,
    }
}

/// Whether the profile a job gets can express a refusal to trace another process.
///
/// This is the one property the ladder may not be able to claim on a given macOS, so it
/// gets its own question: when the answer is no, the backend says it claims nothing and
/// the escape check is reported as unchecked rather than as a denial that happened to
/// come from macOS's own debugger policy.
pub fn claims_against_tracing(denials: &[&'static str]) -> bool {
    denials
        .iter()
        .any(|denial| matches!(*denial, "process-trace" | "task-read"))
}

/// Which of the optional denials this machine's SBPL parser accepts.
///
/// Established by trying, once per process, in the only way that is certain: parse the
/// operation in a throwaway profile against `/usr/bin/true`. A profile that will not
/// parse is a *hard* failure — `sandbox-exec` refuses to run the command at all — so a
/// profile is never allowed to contain an operation this macOS does not know, and a
/// denial that cannot be expressed becomes an unchecked property rather than a
/// surprise at run time.
pub fn supported_denials() -> &'static [&'static str] {
    static DENIALS: OnceLock<&'static [&'static str]> = OnceLock::new();
    DENIALS.get_or_init(|| {
        if Seatbelt::binary().is_none() {
            return &[];
        }
        OPTIONAL_DENIALS
            .into_iter()
            .filter(|operation| parses(&format!("{VERSION}\n{DEFAULT}\n(deny {operation})\n")))
            .collect::<Vec<_>>()
            .leak_slice()
    })
}

/// Hand a `&'static` slice out of a cached `Vec`.
trait LeakSlice {
    fn leak_slice(self) -> &'static [&'static str];
}

impl LeakSlice for Vec<&'static str> {
    fn leak_slice(self) -> &'static [&'static str] {
        Box::leak(self.into_boxed_slice())
    }
}

/// Whether this machine's Seatbelt accepts one profile.
pub fn parses(profile: &str) -> bool {
    parse_failure(profile).is_none()
}

/// Why this machine's Seatbelt refuses a profile, in `sandbox-exec`'s own words.
///
/// The test runs `/usr/bin/true` under the profile: a profile that does not parse makes
/// `sandbox-exec` fail without ever execing the command, and a profile that parses and
/// lets an ordinary process run is the thing a job needs anyway. The refusal text is the
/// parser's complaint (`unknown operation`, a mismatched parenthesis, a filter it does
/// not know), which is the only useful thing to put in a probe that has just refused to
/// offer its own backend.
pub fn parse_failure(profile: &str) -> Option<String> {
    let binary = Seatbelt::binary()?;
    let program = platform::binary("true").unwrap_or_else(|| PathBuf::from("/usr/bin/true"));
    let output = Command::new(&binary)
        .args(["-p", profile])
        .arg(&program)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    if output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Some(if text.is_empty() {
        format!("sandbox-exec exited {} without saying why", output.status)
    } else {
        text
    })
}

impl Sandbox for Seatbelt {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn kind(&self) -> Kind {
        // Confinement applied to the child before its first instruction, like the
        // Linux in-process rung; the wrapper is only how the profile reaches it.
        Kind::InProcess
    }

    fn guarantees(&self) -> &'static str {
        "an XNU kernel sandbox profile refuses every write outside the scratch, refuses \
         the credential directories the runner keeps (ssh, gpg, keychains, the gitiup \
         keystore), and refuses every network route the job was not given, including the \
         proxy's; rlimits on process count, file size, cpu seconds and core dumps are \
         applied in the child. Reads outside the credential list are NOT isolated, there \
         is no filesystem of the job's own, and Mach and IOKit are outside what a profile \
         covers"
    }

    fn probe(&self) -> Result<Probe> {
        let mut probe = Probe::builder(self.name());
        let Some(binary) = Seatbelt::binary() else {
            probe.failed(
                "runtime",
                "no `sandbox-exec` on this machine, which is not a Mac, or it has been removed; \
                 use the docker or podman backend (docs/macos.md says how)",
            );
            return probe.finish();
        };
        probe.observed("runtime", format!("`{}` is present", binary.display()));

        // The scratch the canaries run in, exactly as a job would get one.
        let scratch = escape::probe_scratch("seatbelt")?;
        let workspace = scratch.join("workspace");
        let sandboxed = scratch.join("scratch");
        std::fs::create_dir_all(&workspace).ok();
        std::fs::create_dir_all(&sandboxed).ok();
        let spec = Spec::new(&workspace, &sandboxed).with_scratch_cap(64 << 20);

        let denials = supported_denials();
        let tracing = claims_against_tracing(denials);
        let profile = profile_for(&spec, denials);
        if let Some(why) = parse_failure(&profile.text) {
            probe.failed(
                "profile",
                format!(
                    "this macOS refused the profile gitiup builds, so a job would not start at \
                     all: {why}"
                ),
            );
            return probe.finish();
        }
        probe.observed(
            "profile",
            format!(
                "{} rules parse; writes outside the scratch{}, every socket and the rlimits \
                 below are what the job is given",
                profile.lines().filter(|line| line.starts_with('(')).count(),
                if profile.denies.contains(&"credential-reads") {
                    ", the credential list,"
                } else {
                    ""
                }
            ),
        );
        if !tracing {
            probe.skipped(
                "ptrace",
                "this macOS's SBPL accepts no tracing denial that gitiup knows, so the backend \
                 claims nothing about ptrace; a container rung has its own answer (a pid \
                 namespace) and is preferred for a stranger's job",
            );
        }

        // The four checks, through the real plan→command path. Where the profile cannot
        // express a refusal to trace, the ptrace check is dropped rather than mapped:
        // the `skipped` line above already says why in full, and a property reported
        // twice with two notes is a property a reader cannot count.
        let results = escape::all(self, &spec);
        let results: Vec<(&'static str, Outcome)> = results
            .into_iter()
            .filter(|(check, _)| tracing || *check != "ptrace")
            .collect();
        escape::probe_from(&mut probe, &results);

        // The same claim, with an allowlist in the profile: the proxy's port is the one
        // hole in `(deny network*)`, so this is where "kernel-enforced even with an
        // allowlist" is either true or not.
        match Egress::allow_registries() {
            Ok(egress) => {
                let allowed = spec.clone().with_egress(egress);
                match escape::outbound_connect(self, &allowed) {
                    Ok(Outcome::Denied(note)) => probe.observed(
                        "tcp-egress-allowlisted",
                        format!("with a proxy allowlisted, {note}"),
                    ),
                    Ok(Outcome::Escaped(note)) => {
                        probe.failed("tcp-egress-allowlisted", note);
                    }
                    Ok(Outcome::Unavailable(note)) => probe.skipped("tcp-egress-allowlisted", note),
                    Err(why) => probe.skipped("tcp-egress-allowlisted", why.detail().to_string()),
                }
            }
            Err(why) => probe.skipped(
                "tcp-egress-allowlisted",
                format!("no default allowlist to try: {}", why.detail()),
            ),
        }

        probe.observed(
            "writable-root",
            format!("only {} may be written", sandboxed.display()),
        );
        probe.finish()
    }

    fn enforcement(&self, _egress: &Egress) -> Enforcement {
        // `(deny network*)` is a kernel rule, and the one allow that an allowlist adds
        // is a kernel rule about one address; `probe` checks both, which is the only
        // reason this is allowed to say `Kernel` at all.
        Enforcement::Kernel
    }

    fn plan(&self, spec: &Spec, _env: &Env) -> Result<Launch> {
        let binary = Seatbelt::binary().ok_or_else(|| {
            Error::new(
                ErrorKind::Policy,
                "sandbox",
                "no `sandbox-exec` binary to apply a Seatbelt profile with",
            )
        })?;
        for path in spec.write_paths() {
            std::fs::create_dir_all(&path).map_err(|why| {
                Error::new(
                    ErrorKind::Invalid,
                    "sandbox",
                    format!(
                        "could not create the writable directory {}: {why}",
                        path.display()
                    ),
                )
            })?;
        }
        let profile = profile_for(spec, supported_denials());
        let mut launch = Launch {
            prefix: vec![
                binary.display().to_string(),
                "-p".to_string(),
                profile.text.clone(),
            ],
            ..Launch::default()
        };
        launch.env.insert(
            "PATH".to_string(),
            limits::default_path().to_string_lossy().into_owned(),
        );
        launch
            .env
            .insert("HOME".to_string(), spec.scratch.display().to_string());
        launch
            .env
            .insert("TMPDIR".to_string(), spec.scratch.display().to_string());
        launch.env.extend(spec.egress.proxy_env());
        launch.notes.push(format!(
            "seatbelt profile: {} rules, denies {} and the credential list",
            profile.lines().filter(|line| line.starts_with('(')).count(),
            if spec.egress.is_denied() {
                "all egress"
            } else {
                "all egress except the proxy"
            }
        ));
        launch.notes.push(format!(
            "writable {} (cap {} bytes)",
            spec.scratch.display(),
            spec.scratch_bytes
        ));
        Ok(launch)
    }

    fn tune(&self, command: &mut std::process::Command, spec: &Spec) -> Result<()> {
        // rlimits have no SBPL equivalent, so they are applied the portable way. The
        // profile itself is applied by `sandbox-exec`, which is a child of nobody
        // important: nothing here allocates after the fork.
        let limits_applied = spec.limits.clone();
        let scratch_bytes = spec.scratch_bytes;
        unsafe {
            command.pre_exec(move || {
                limits::apply_limits(
                    limits_applied.cpu_seconds,
                    limits_applied.address_bytes,
                    limits_applied.processes,
                    limits_applied.file_bytes.or(Some(scratch_bytes)),
                );
                Ok(())
            });
        }
        Ok(())
    }
}

/// A confined `PATH`, for the runner's environment builder.
pub fn confined_path() -> BTreeMap<String, String> {
    let mut env = Env::new();
    env.insert(
        "PATH".to_string(),
        limits::default_path().to_string_lossy().into_owned(),
    );
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Spec) {
        let home = tempfile::tempdir().unwrap();
        let workspace = home.path().join("workspace");
        let scratch = home.path().join("scratch");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        (
            home,
            Spec::new(&workspace, &scratch).with_scratch_cap(1 << 20),
        )
    }

    #[test]
    fn a_profile_opens_wide_then_refuses_writes_and_egress() {
        let (_home, spec) = fixture();
        let profile = profile_for(&spec, &[]);
        let text = profile.text;
        assert!(text.starts_with("(version 1)\n(allow default)"), "{text}");
        assert!(text.contains("(deny file-write*)"), "{text}");
        assert!(text.contains("(deny network*)"), "{text}");
        // The scratch is writable, and named by its resolved path.
        let scratch = grant_path(&spec.scratch).display().to_string();
        assert!(
            text.contains(&format!("(allow file-write* (subpath \"{scratch}\"))")),
            "the scratch grant is the one thing a build needs: {text}"
        );
        // The workspace is *not* writable by default: it is mounted read-only in the
        // container backends for the same reason.
        let workspace = grant_path(&spec.workspace).display().to_string();
        assert!(
            !text.contains(&format!("(allow file-write* (subpath \"{workspace}\"))")),
            "{text}"
        );
        // Rule order is the whole semantics: the blanket deny must precede its holes.
        let deny = text.find("(deny file-write*)").unwrap();
        let allow = text.find("(allow file-write* (subpath").unwrap();
        assert!(deny < allow, "SBPL takes the last match: {text}");
    }

    #[test]
    fn a_profile_names_the_proxy_and_nothing_else() {
        let (_home, mut spec) = fixture();
        spec = spec.with_egress(Egress::allow_registries().unwrap());
        let profile = profile_for(&spec, &[]);
        let proxy = spec.egress.proxy().unwrap().endpoint();
        assert!(
            profile.text.contains(&format!(
                "(allow network-outbound (remote tcp \"{}:{}\"))",
                proxy.ip(),
                proxy.port()
            )),
            "{}",
            profile.text
        );
        assert!(profile.text.contains("(deny network*)"));
    }

    #[test]
    fn the_optional_denials_are_added_only_when_asked_for() {
        let (_home, spec) = fixture();
        assert!(
            !profile_for(&spec, &[])
                .text
                .contains("(deny process-trace)")
        );
        assert!(
            profile_for(&spec, &["process-trace"])
                .text
                .contains("(deny process-trace)")
        );
        assert!(
            profile_for(&spec, &["process-trace"])
                .denies
                .contains(&"ptrace")
        );
        // A denial that is not about tracing is claimed under its own name, so the
        // ptrace property can never be credited to an unrelated rule.
        let xattr = profile_for(&spec, &["file-write-xattr"]);
        assert!(xattr.denies.contains(&"file-write-xattr"));
        assert!(!xattr.denies.contains(&"ptrace"));
        assert!(!claims_against_tracing(&[]));
        assert!(!claims_against_tracing(&["file-write-xattr"]));
        assert!(claims_against_tracing(&["task-read"]));
    }

    #[test]
    fn a_path_with_a_space_or_a_quote_survives_sbpl_quoting() {
        let quoted = quote(Path::new("/tmp/it's a \"test\""));
        assert_eq!(quoted, "\"/tmp/it's a \\\"test\\\"\"");
    }

    #[test]
    fn the_credential_list_is_the_runners_own_secrets() {
        let paths = credential_paths();
        // Whatever exists on this machine, nothing in the list is a system directory:
        // denying `/usr` would refuse the build rather than the escape.
        for path in &paths {
            assert!(
                path.starts_with(
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_default()
                ) || std::env::var_os("XDG_DATA_HOME")
                    .map(|data| path.starts_with(data))
                    .unwrap_or(false),
                "{} is not under the user's own directories",
                path.display()
            );
        }
    }

    #[test]
    fn a_backend_on_a_machine_without_sandbox_exec_refuses_instead_of_lying() {
        let backend = Seatbelt;
        if Seatbelt::binary().is_some() {
            // A real Mac: the probe's own checks decide, and the escape suite is the
            // test that reads them.
            return;
        }
        let err = backend.probe().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Policy);
        assert!(err.detail().contains("sandbox-exec"), "{err}");
        assert!(err.detail().contains("docker"), "{err}");
    }

    #[test]
    fn the_plan_wraps_the_command_in_the_profile_and_pins_a_tmp_inside_the_scratch() {
        if Seatbelt::binary().is_none() {
            // On Linux the wrapper does not exist, so the plan is a refusal — and the
            // refusal is the behaviour under test.
            let (_home, spec) = fixture();
            let err = Seatbelt.plan(&spec, &Env::new()).unwrap_err();
            assert!(err.detail().contains("sandbox-exec"), "{err}");
            return;
        }
        let (_home, spec) = fixture();
        let launch = Seatbelt.plan(&spec, &Env::new()).unwrap();
        assert_eq!(launch.prefix[0].rsplit('/').next().unwrap(), "sandbox-exec");
        assert_eq!(launch.prefix[1], "-p");
        assert!(launch.prefix[2].contains("(deny file-write*)"));
        assert_eq!(launch.env["TMPDIR"], spec.scratch.display().to_string());
        let argv = launch.argv(&["/bin/ls".into()], &Env::new());
        assert_eq!(argv.last().unwrap(), "/bin/ls");
        // No `--`: sandbox-exec takes the command directly, and a reviewer who copies
        // the printed line gets exactly what ran.
        assert!(!argv.iter().any(|argument| argument == "--"));
    }
}

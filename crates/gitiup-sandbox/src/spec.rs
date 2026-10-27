//! What a job asks to be given, and what it agrees to be confined by.
//!
//! A [`Spec`] is the whole contract between "I would like this command to run" and
//! "here is the cage it runs in". It is deliberately a *value*, not a builder that
//! touches the machine: [`Spec::new`] creates no directories and starts no
//! listeners, so a plan can be printed, hashed and reviewed before anything exists.
//! The side effects happen when a [`Backend`](crate::backend::Sandbox) prepares the
//! command, which is also where a refusal happens — a spec that cannot be honoured is
//! refused, never quietly downgraded.
//!
//! The baseline the epic asks for, field by field:
//!
//! | baseline | field |
//!|--------|-------|
//!| read-only workspace | [`Spec::read_only`] — the tree the job may read, and (except on `plain`) the kernel, not the job, enforces the read-only part |
//!| tmpfs scratch with a size cap | [`Spec::scratch`] + [`Spec::scratch_bytes`] |
//!| dropped capabilities, no new privileges | every backend sets `PR_SET_NO_NEW_PRIVS`; containers drop all capabilities, the in-process backend refuses the privilege syscalls |
//!| distinct unprivileged uid | [`Spec::unprivileged_uid`] (only honours-able as root — said out loud in [`guarantees`](crate::backend::Sandbox::guarantees)) |
//!| pid namespace, no mount escape | backend-specific, reported as probe properties |
//!| default-deny egress | [`Spec::egress`] — [`Egress::deny_all`] is the default |
//!| per-job DNS policy | [`Spec::egress`]'s [`DnsPolicy`](crate::egress::DnsPolicy) |
//!| why the job is being run | [`Spec::purpose`] — a quorum job is held to a higher rung of the ladder |

use serde::Serialize;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::egress::Egress;

/// Why this job is being run, which decides what may run it.
///
/// The distinction is not decorative. A job *I* asked for (`Local`) is my problem: if
/// I choose a weaker cage for code I wrote, that is a choice about my own machine. A
/// job I was *asked to run by a stranger* and whose result I will publish
/// (`Quorum`) is everybody's problem, so `admit` requires kernel-enforced isolation
/// and refuses the opt-in backends outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// My own run, on my own machine, attested as `local`.
    Local,
    /// A stranger's job, taken from a quorum round, whose attestation others will
    /// rely on (giti-msi.5).
    Quorum,
}

impl Purpose {
    /// The stable name used in logs and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Local => "local",
            Purpose::Quorum => "quorum",
        }
    }

    /// How strong the isolation has to be for this purpose.
    ///
    /// `Audited` is enough for a local job (the proxy logs what it allowed, and I
    /// chose the job); a stranger's job needs a denial the kernel enforces, because
    /// "the untrusted program was *asked politely* to use the proxy" is not a
    /// security property.
    pub fn minimum_enforcement(self) -> Enforcement {
        match self {
            Purpose::Local => Enforcement::None,
            Purpose::Quorum => Enforcement::Kernel,
        }
    }
}

/// How a denial is actually achieved. Ordered, so `>=` reads as "at least as strong".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Nothing is confined; the denial is a policy the job could ignore.
    None,
    /// Denials are enforced by the proxy and recorded, but a job that ignores the
    /// proxy could still reach a network the host allows.
    Audited,
    /// The kernel refuses: no route, no address, no syscall. A job cannot ignore it.
    Kernel,
}

impl Enforcement {
    /// The phrase for a status line. Never just a name: the point of this enum is
    /// that a reader learns *how much* to trust the word "sandboxed".
    pub fn label(self) -> &'static str {
        match self {
            Enforcement::None => "nothing enforced",
            Enforcement::Audited => "proxy-enforced and audited",
            Enforcement::Kernel => "kernel-enforced",
        }
    }
}

/// The resource knobs a backend can pass down.
///
/// Policy — what a volunteer *should* be given, admission control, cache eviction —
/// is giti-bgy.2. What lives here is the small set of limits that make a runaway job
/// cheap instead of fatal, because a sandbox with no process limit is a denial of
/// service with a nice attestation. The defaults are a floor, not a budget: they are
/// chosen to be survivable on a desktop (see each field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// `RLIMIT_CPU` soft limit, in CPU seconds. `None` = inherited.
    pub cpu_seconds: Option<u64>,
    /// `RLIMIT_AS` soft limit, in bytes. `None` = inherited; a Rust build needs
    /// gigabytes of address space, so the default is deliberately no cap.
    pub address_bytes: Option<u64>,
    /// How many *extra* processes the job may have (see `nproc_floor` in
    /// `backends::limits`: the limit is set relative to what the uid is already
    /// running, or a fork-bomb guard would kill an honest desktop session).
    pub processes: Option<u64>,
    /// `RLIMIT_FSIZE` soft limit, in bytes — the floor on the scratch size cap for
    /// backends that cannot mount a sized tmpfs.
    pub file_bytes: Option<u64>,
    /// Wall-clock deadline. Enforced by the spawner (a container gets
    /// `--stop-timeout`; a namespace gets `timeout(1)`; the in-process backend gets a
    /// self-armed timer), so `None` means "the caller watches the clock".
    pub wall_clock: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            // No CPU cap by default: a cached CI runner and a 40-minute build are both
            // legitimate, and giti-bgy.2 is where a budget gets decided. The process
            // and file caps are here because those are the two limits a *stranger's*
            // job can use to wreck a host today.
            cpu_seconds: None,
            address_bytes: None,
            processes: Some(256),
            file_bytes: Some(32 << 30),
            wall_clock: None,
        }
    }
}

impl Limits {
    /// The tight, explicit set the escape suite uses, so a canary can outgrow the cap
    /// rather than the host's own limits.
    pub fn tight() -> Limits {
        Limits {
            cpu_seconds: Some(20),
            address_bytes: None,
            processes: Some(32),
            file_bytes: Some(1 << 20),
            wall_clock: Some(Duration::from_secs(30)),
        }
    }
}

/// Where a job may read, write, and go.
#[derive(Debug, Clone)]
pub struct Spec {
    /// The tree the job is about. Mounted read-only where the backend can bind
    /// mounts; in the in-process backend it is the tree Landlock grants read rights
    /// to (Landlock restricts writes and execution, not reads — see the module docs
    /// of [`crate::backends::inprocess`], which says that out loud rather than
    /// implying it).
    pub workspace: PathBuf,
    /// The one place a job may write freely.
    pub scratch: PathBuf,
    /// The scratch size cap. Enforced by a sized tmpfs where the backend can mount
    /// one, and by `RLIMIT_FSIZE` where it cannot.
    pub scratch_bytes: u64,
    /// Extra read-only trees (toolchains, a pinned action cache).
    pub read_only: Vec<PathBuf>,
    /// Extra writable trees, e.g. a shared build cache the operator opted into.
    pub writable: Vec<PathBuf>,
    /// Resource knobs.
    pub limits: Limits,
    /// Network policy: default-deny unless the job named what it needs.
    pub egress: Egress,
    /// Why the job runs. Decides the rung of the ladder required.
    pub purpose: Purpose,
    /// Drop to this uid/gid. Honoured when the runner is root; said out loud (and
    /// *not* silently skipped) otherwise — see
    /// [`Sandbox::guarantees`](crate::backend::Sandbox::guarantees).
    pub unprivileged_uid: Option<u32>,
    /// The image a container backend should use. `None` means the backend's own
    /// default, which is `$GITIUP_SANDBOX_IMAGE`.
    pub image: Option<String>,
    /// The escape canary to run while probing. `None` means "find it beside this
    /// executable" ([`crate::canary::program`]), and a probe that could not find one
    /// says which properties it could not observe.
    /// Programs the job must be able to `exec` that no other granted tree covers.
    pub tools: Vec<PathBuf>,
    /// The escape canary to run while probing. `None` means "find it beside this
    /// executable" ([`crate::canary::program`]), and a probe that could not find one
    /// says which properties it could not observe.
    pub canary: Option<PathBuf>,
}

impl Spec {
    /// The minimal honest spec: `workspace` is the tree the job is about, `scratch`
    /// is the only place it may write, egress is denied, nothing else is writable.
    pub fn new(workspace: impl AsRef<Path>, scratch: impl AsRef<Path>) -> Spec {
        Spec {
            workspace: workspace.as_ref().to_path_buf(),
            scratch: scratch.as_ref().to_path_buf(),
            scratch_bytes: 2 << 30,
            read_only: Vec::new(),
            writable: Vec::new(),
            limits: Limits::default(),
            egress: Egress::deny_all(),
            purpose: Purpose::Local,
            unprivileged_uid: None,
            image: None,
            tools: Vec::new(),
            canary: None,
        }
    }

    /// A job taken from a stranger: the ladder rung and the egress requirement both
    /// go up (see [`Purpose`]).
    pub fn quorum(mut self) -> Spec {
        self.purpose = Purpose::Quorum;
        self
    }

    /// State the purpose explicitly, for a caller that has it as a value rather than
    /// as two code paths.
    pub fn with_purpose(mut self, purpose: Purpose) -> Spec {
        self.purpose = purpose;
        self
    }

    /// Replace the network policy, e.g. with [`Egress::allow_registries`].
    pub fn with_egress(mut self, egress: Egress) -> Spec {
        self.egress = egress;
        self
    }

    /// Replace the scratch size cap.
    pub fn with_scratch_cap(mut self, bytes: u64) -> Spec {
        self.scratch_bytes = bytes;
        self
    }

    /// Replace the resource knobs.
    pub fn with_limits(mut self, limits: Limits) -> Spec {
        self.limits = limits;
        self
    }

    /// Grant another writable tree.
    pub fn writable(mut self, path: impl AsRef<Path>) -> Spec {
        self.writable.push(path.as_ref().to_path_buf());
        self
    }

    /// Mount another tree read-only.
    pub fn read_only(mut self, path: impl AsRef<Path>) -> Spec {
        self.read_only.push(path.as_ref().to_path_buf());
        self
    }

    /// Pin the container image.
    pub fn with_image(mut self, image: impl Into<String>) -> Spec {
        self.image = Some(image.into());
        self
    }

    /// Name a program the confined job must be able to run, outside `/usr` and
    /// `/bin` — a toolchain the verifier installed itself, say. Its directory goes on
    /// the read list (see [`Spec::tool_dirs`]).
    pub fn with_tool(mut self, program: impl AsRef<Path>) -> Spec {
        let program = program.as_ref().to_path_buf();
        if !self.tools.contains(&program) {
            self.tools.push(program);
        }
        self
    }

    /// Name the canary program the probe should use.
    pub fn with_canary(mut self, program: impl AsRef<Path>) -> Spec {
        self.canary = Some(program.as_ref().to_path_buf());
        self
    }

    /// Another tree the job may read, granted exactly as named.
    pub fn with_read_path(mut self, path: impl AsRef<Path>) -> Spec {
        let path = path.as_ref().to_path_buf();
        if !self.read_only.contains(&path) {
            self.read_only.push(path);
        }
        self
    }

    /// Another tree the job may write.
    ///
    /// The scratch is writable by construction; this is for the second tree a real job
    /// has — a workflow step, for instance, writes in its checkout as well as in the
    /// directory its runner staged it in. Named rather than guessed, because a
    /// writable tree is the one grant an escape is measured against.
    pub fn with_writable(mut self, path: impl AsRef<Path>) -> Spec {
        let path = path.as_ref().to_path_buf();
        if !self.writable.contains(&path) {
            self.writable.push(path);
        }
        self
    }

    /// Everything the job may write, in the order a backend should grant it.
    pub fn write_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.scratch.clone()];
        paths.extend(self.writable.iter().cloned());
        paths
    }

    /// Everything the job may read: the workspace, the extra read-only trees and the
    /// system directories every build needs (`/usr`, `/bin`, `/lib`, …).
    ///
    /// The system list is not a courtesy — a build that cannot `exec` a compiler is
    /// not a sandbox, it is a refusal with extra steps. It is also why "the
    /// filesystem is isolated" is never a claim this crate makes: reads are wide on
    /// the in-process backends, narrow on the containers.
    pub fn read_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.workspace.clone()];
        paths.extend(self.read_only.iter().cloned());
        // The canary's directory too: a probe that cannot exec its own canary has not
        // observed anything, whatever it reports.
        paths.extend(self.tool_dirs());
        for system in SYSTEM_READ_ONLY {
            let path = Path::new(system);
            if !paths.contains(&path.to_path_buf()) {
                paths.push(path.to_path_buf());
            }
        }
        paths
    }

    /// The directories holding programs a confined job must be able to `exec`.
    ///
    /// A Landlock-confined process cannot execute a file it has no execute right on,
    /// so these are granted read and execute explicitly. Nothing is guessed from the
    /// filesystem: [`Spec::with_tool`] takes a program and grants the directory it
    /// names, [`Spec::with_read_path`] grants exactly what it names. When a caller has
    /// to name a tool directory that is the honest failure — the alternative is a child
    /// that dies with `EPERM` and looks like a broken sandbox.
    pub fn tool_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self.read_only.clone();
        let mut add = |program: &PathBuf| {
            let dir = program
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map_or_else(|| program.clone(), Path::to_path_buf);
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        };
        for program in &self.tools {
            add(program);
        }
        if let Some(canary) = &self.canary {
            add(canary);
        }
        dirs
    }

    /// Refuse a spec that cannot mean what it says, before a backend tries.
    pub fn check(&self) -> gitiup_attest::Result<()> {
        let empty = |what: &str, path: &Path| -> gitiup_attest::Result<()> {
            Err(gitiup_attest::Error::new(
                gitiup_attest::ErrorKind::Invalid,
                "sandbox",
                format!("{what} is not set (`{}`)", path.display()),
            )
            .with_hint("name a directory the job may use; gitiup creates it"))
        };
        if self.workspace.as_os_str().is_empty() {
            empty("workspace", &self.workspace)?;
        }
        if self.scratch.as_os_str().is_empty() {
            empty("scratch", &self.scratch)?;
        }
        for path in &self.read_only {
            if path == Path::new("/") {
                return Err(gitiup_attest::Error::new(
                    gitiup_attest::ErrorKind::Invalid,
                    "sandbox",
                    "`/` is named as a readable tree",
                )
                .with_hint(
                    "name the tool's own directory instead: granting `/` read access                      hands the job every file the runner can read, including keys",
                ));
            }
        }
        if self.scratch_bytes == 0 {
            return Err(gitiup_attest::Error::new(
                gitiup_attest::ErrorKind::Invalid,
                "sandbox",
                "the scratch size cap is 0 bytes, which no job can use",
            )
            .with_hint("raise the cap, or plan the job instead of running it"));
        }
        Ok(())
    }
}

/// The directories a build needs to read and execute, so a sandbox is a cage and not
/// a brick wall.
pub const SYSTEM_READ_ONLY: [&str; 8] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/libexec", "/etc", "/opt",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_spec_denies_egress_and_writes_nothing_but_scratch() {
        let spec = Spec::new("/work", "/work/.scratch");
        assert_eq!(spec.egress, Egress::deny_all());
        assert!(spec.egress.is_denied());
        assert_eq!(
            spec.write_paths(),
            vec![PathBuf::from("/work/.scratch")],
            "the scratch is the only writable place a job starts with"
        );
        assert_eq!(spec.purpose, Purpose::Local);
        assert_eq!(
            spec.purpose.minimum_enforcement(),
            Enforcement::None,
            "a local job may be run in a weaker cage, as long as it is told"
        );
        assert_eq!(
            Purpose::Quorum.minimum_enforcement(),
            Enforcement::Kernel,
            "a stranger's job needs a denial the kernel enforces"
        );
    }

    #[test]
    fn a_spec_that_cannot_mean_what_it_says_is_refused() {
        let err = Spec::new("", "/tmp/s").check().unwrap_err();
        assert_eq!(err.kind(), gitiup_attest::ErrorKind::Invalid);
        assert!(err.detail().contains("workspace"), "{err}");

        let mut spec = Spec::new("/work", "/tmp/s");
        spec.scratch_bytes = 0;
        let err = spec.check().unwrap_err();
        assert!(err.detail().contains("0 bytes"), "{err}");

        Spec::new("/work", "/tmp/s").check().unwrap();
    }

    #[test]
    // The read list must contain the compiler paths, or the sandbox is a brick wall.
    fn a_build_can_still_start() {
        let spec = Spec::new("/work", "/tmp/s");
        let reads = spec.read_paths();
        for needed in [
            Path::new("/usr"),
            Path::new("/bin"),
            Path::new("/etc"),
            Path::new("/work"),
        ] {
            assert!(
                reads.contains(&needed.to_path_buf()),
                "{:?} missing",
                needed
            );
        }
        assert!(
            !reads.contains(&Path::new("/home").to_path_buf()),
            "the whole home directory is not on the read list by default"
        );
    }

    #[test]
    // A tool outside `/usr` has to be named, or a confined job cannot exec it.
    fn a_named_tool_directory_is_on_the_read_list() {
        // A read path is granted exactly as named; a *tool* is granted by the
        // directory it lives in, which is what "the job has to be able to run this"
        // means. No guessing from what happens to exist.
        let spec = Spec::new("/work", "/tmp/s").with_read_path("/opt/gitiup/bin");
        assert!(
            spec.read_paths()
                .contains(&Path::new("/opt/gitiup/bin").to_path_buf()),
            "{:?}",
            spec.read_paths()
        );
        assert!(
            spec.tool_dirs()
                .contains(&Path::new("/opt/gitiup/bin").to_path_buf()),
            "{:?}",
            spec.tool_dirs()
        );
        // Naming it twice does not double-grant it.
        let twice = spec.clone().with_read_path("/opt/gitiup/bin");
        assert_eq!(twice.read_only.len(), 1);

        let spec = Spec::new("/work", "/tmp/s").with_tool("/opt/gitiup/bin/cargo");
        assert!(
            spec.tool_dirs()
                .contains(&Path::new("/opt/gitiup/bin").to_path_buf()),
            "{:?}",
            spec.tool_dirs()
        );
        assert_eq!(spec.tools.len(), 1);
    }

    #[test]
    // A canary must be executable by the process probing with it, or the probe is
    // reporting on nothing.
    fn the_canary_directory_is_granted() {
        let spec = Spec::new("/work", "/tmp/s").with_canary("/usr/local/bin/gitiup-canary");
        assert!(
            spec.read_paths()
                .contains(&Path::new("/usr/local/bin").to_path_buf()),
            "{:?}",
            spec.read_paths()
        );
    }

    #[test]
    // Naming `/` as a tool directory is not a widened sandbox, it is no sandbox.
    fn the_whole_filesystem_is_not_a_tool_directory() {
        let spec = Spec::new("/work", "/tmp/s").with_read_path("/");
        let err = spec.check().unwrap_err();
        assert!(err.detail().contains("`/`"), "{err}");
        assert!(err.to_string().contains("keys"), "{err}");
    }
}

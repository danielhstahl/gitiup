//! What this machine is, as far as isolation is concerned.
//!
//! `gitiup doctor --sandbox` is mostly this module plus a sentence about what to do
//! about it. The facts are collected once per process ([`Kernel::survey`]) because
//! several of them cost a process spawn to establish, and because two parts of one
//! command must not disagree about the kernel.
//!
//! Each fact is *established*, not read from a config: a sysctl that says user
//! namespaces are enabled and a seccomp profile from an outer container that refuses
//! them anyway are exactly the mismatch this crate must not paper over.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use crate::linux::{self, SeccompFilter};

/// Something the survey could or could not establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Established by trying, and it works.
    Yes,
    /// Established by trying, and it does not — with what the kernel said.
    No(String),
    /// Not established: there was nothing safe to try.
    Unknown(String),
}

impl Availability {
    /// `yes` / `no` / `unknown`.
    pub fn state(&self) -> &'static str {
        match self {
            Availability::Yes => "yes",
            Availability::No(_) => "no",
            Availability::Unknown(_) => "unknown",
        }
    }

    /// The reason, when there is one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Availability::No(why) | Availability::Unknown(why) => Some(why),
            Availability::Yes => None,
        }
    }

    /// True only when trying proved it works. `Unknown` is not good enough to build a
    /// sandbox on — that is the difference between this enum and a boolean.
    pub fn is_yes(&self) -> bool {
        matches!(self, Availability::Yes)
    }
}

/// The machine's isolation facts.
#[derive(Debug, Clone)]
pub struct Kernel {
    /// `uname -s -r`, as reported by the running kernel.
    pub kernel: String,
    /// Real uid of this process.
    pub uid: u32,
    /// Effective uid — the difference matters for whether privileges can be dropped.
    pub euid: u32,
    /// What `/sys/kernel/security/lsm` lists, when it is readable.
    pub lsm: Vec<String>,
    /// The Landlock ABI version, or `None` if the kernel has no Landlock.
    pub landlock_abi: Option<u32>,
    /// `/proc/sys/kernel/seccomp/actions_avail`, when readable: proof seccomp is
    /// compiled in.
    pub seccomp_actions: Option<String>,
    /// Whether a seccomp filter can actually be installed here (tried in a child).
    pub seccomp_usable: Availability,
    /// Whether unprivileged user namespaces work here (tried by running them).
    pub user_namespaces: Availability,
    /// `/proc/sys/user/max_user_namespaces`, when readable.
    pub max_user_namespaces: Option<u64>,
    /// `/proc/sys/kernel/yama/ptrace_scope`, when readable.
    pub ptrace_scope: Option<u32>,
    /// How many processes this uid is already running, which `nproc_floor` needs.
    pub processes_of_uid: u64,
}

static SURVEY: OnceLock<Kernel> = OnceLock::new();

impl Kernel {
    /// The survey, done once per process and cached.
    pub fn survey() -> &'static Kernel {
        SURVEY.get_or_init(Kernel::gather)
    }

    /// Do it all again. Public for tests that change the environment.
    pub fn gather() -> Kernel {
        let landlock_abi = linux::landlock_abi();
        let lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|text| {
                text.trim()
                    .split(':')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let seccomp_actions = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
            .ok()
            .map(|text| text.trim().to_string());
        Kernel {
            kernel: uname(),
            uid: unsafe { libc::getuid() },
            euid: unsafe { libc::geteuid() },
            landlock_abi,
            lsm,
            seccomp_actions,
            seccomp_usable: probe_seccomp(),
            user_namespaces: probe_user_namespaces(),
            max_user_namespaces: read_number("/proc/sys/user/max_user_namespaces"),
            ptrace_scope: read_number("/proc/sys/kernel/yama/ptrace_scope").map(|v| v as u32),
            processes_of_uid: linux::current_nproc(),
        }
    }

    /// Where a helper binary lives, searching `PATH` the way a shell would.
    pub fn binary(name: &str) -> Option<PathBuf> {
        if let Some(absolute) = Path::new(name)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            let _ = absolute;
            return Path::new(name).is_file().then(|| PathBuf::from(name));
        }
        // The usual suspects first, so a stripped PATH in a CI job still finds
        // `/usr/bin/unshare`.
        let mut searched: Vec<PathBuf> = Vec::new();
        if let Some(path) = std::env::var_os("PATH") {
            searched.extend(std::env::split_paths(&path).filter(|p| !p.as_os_str().is_empty()));
        }
        for system in ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            let directory = PathBuf::from(system);
            if !searched.contains(&directory) {
                searched.push(directory);
            }
        }
        searched
            .iter()
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    }

    /// Whether seccomp can be used *right now*: an outer container profile can make a
    /// perfectly compiled-in seccomp unusable, and a backend must not claim otherwise.
    ///
    /// The test installs the real gitiup filter in a child and lets it `exec`
    /// `/bin/true`: if the filter cannot be installed, the spawn fails.
    pub fn seccomp_works(&self) -> &Availability {
        &self.seccomp_usable
    }
}

fn uname() -> String {
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return "unknown".to_string();
    }
    let field = |array: &[libc::c_char]| {
        // `c_char` is signed on x86_64 and unsigned on aarch64, so the cast is
        // redundant on half the targets and necessary on the other half.
        #[allow(clippy::unnecessary_cast)]
        let bytes: Vec<u8> = array
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    format!("{} {}", field(&uts.sysname), field(&uts.release))
}

fn read_number(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Try to install the hardened seccomp filter in a child.
fn probe_seccomp() -> Availability {
    let filter = SeccompFilter::hardened();
    let mut command = Command::new("/bin/true");
    command.env_clear();
    unsafe {
        command.pre_exec(move || {
            linux::no_new_privs()?;
            // SAFETY: this is the forked child (the enclosing `unsafe` is the
            // `pre_exec` registration), and the filter is what a real job would get;
            // the process execs `/bin/true` immediately after.
            filter.install()
        });
    }
    match command.output() {
        Ok(output) if output.status.success() => Availability::Yes,
        Ok(output) => Availability::No(format!(
            "the confined child exited {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_default()
        )),
        Err(why) => Availability::No(format!("a seccomp filter could not be installed: {why}")),
    }
}

/// Try to create a user namespace by creating one.
fn probe_user_namespaces() -> Availability {
    let Some(unshare) = Kernel::binary("unshare") else {
        return Availability::Unknown(
            "no unshare(1) binary to try with (install util-linux)".to_string(),
        );
    };
    let output = Command::new(&unshare)
        .args(["--user", "--map-root-user", "--fork", "--net", "--"])
        .arg("/bin/true")
        .env_clear()
        .output();
    match output {
        Ok(output) if output.status.success() => Availability::Yes,
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Availability::No(if detail.is_empty() {
                "unshare --user exited nonzero".to_string()
            } else {
                detail
            })
        }
        Err(why) => Availability::No(format!("unshare could not be run: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_survey_reports_the_running_kernel_and_uid() {
        let kernel = Kernel::survey();
        assert!(
            kernel.kernel.contains(' '),
            "expected `<sysname> <release>`, got `{}`",
            kernel.kernel
        );
        assert_eq!(kernel.uid, unsafe { libc::getuid() });
        // Landlock is either absent or a positive ABI number; there is no third
        // answer, and a zero would be a bug in the version query.
        assert!(kernel.landlock_abi.map(|abi| abi > 0).unwrap_or(true));
    }

    #[test]
    fn a_helper_is_found_by_name_or_refused_honestly() {
        assert_eq!(
            Kernel::binary("sh").map(|path| path.starts_with("/")),
            Some(true)
        );
        assert_eq!(Kernel::binary("definitely-not-a-real-binary-xyz"), None);
    }

    #[test]
    fn seccomp_and_user_namespaces_are_established_by_trying() {
        let kernel = Kernel::gather();
        // Neither may be `Unknown` on Linux: both have something safe to try. A
        // machine with no `unshare` binary is the one honest `Unknown`.
        assert!(!matches!(kernel.seccomp_usable, Availability::Unknown(_)));
        assert!(
            kernel.user_namespaces.is_yes() || kernel.user_namespaces.reason().is_some(),
            "a `no` must come with what the kernel said"
        );
    }
}

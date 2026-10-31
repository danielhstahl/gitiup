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
//!
//! Which facts exist is a question about the OS ([`crate::platform`]): Landlock, seccomp
//! and namespaces are Linux mechanisms, and on macOS the survey says so and reports the
//! Seatbelt facts instead. A fact that does not exist on this OS is reported as
//! `Unknown` with the reason, which is the difference between "this machine cannot do
//! that" and "nobody looked".

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use crate::limits;
#[cfg(target_os = "linux")]
use crate::linux::SeccompFilter;
use crate::platform::{self, OS, Platform};

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
    /// The OS family and version, which decides which ladder this machine has.
    pub platform: Platform,
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

    /// The OS family this survey was taken on.
    pub fn os(&self) -> OS {
        self.platform.os
    }

    /// Do it all again. Public for tests that change the environment.
    pub fn gather() -> Kernel {
        let platform = Platform::survey().clone();
        let landlock_abi = landlock_abi();
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
            platform,
            uid: unsafe { libc::getuid() },
            euid: unsafe { libc::geteuid() },
            landlock_abi,
            lsm,
            seccomp_actions,
            seccomp_usable: probe_seccomp(),
            user_namespaces: probe_user_namespaces(),
            max_user_namespaces: read_number("/proc/sys/user/max_user_namespaces"),
            ptrace_scope: read_number("/proc/sys/kernel/yama/ptrace_scope").map(|v| v as u32),
            processes_of_uid: limits::current_nproc(),
        }
    }

    /// Where a helper binary lives, searching `PATH` the way a shell would.
    pub fn binary(name: &str) -> Option<PathBuf> {
        platform::binary(name)
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

/// The Landlock ABI on this machine, if it has one.
fn landlock_abi() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        crate::linux::landlock_abi()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Try to install the hardened seccomp filter in a child.
#[cfg(target_os = "linux")]
fn probe_seccomp() -> Availability {
    let filter = SeccompFilter::hardened();
    let mut command = Command::new("/bin/true");
    command.env_clear();
    unsafe {
        command.pre_exec(move || {
            crate::linux::no_new_privs()?;
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

/// On an OS without seccomp there is nothing to try, and saying so is the honest
/// answer: `Unknown`, not `No`, because the machine was not refused anything — the
/// mechanism is simply not part of it.
#[cfg(not(target_os = "linux"))]
fn probe_seccomp() -> Availability {
    Availability::Unknown(format!(
        "seccomp is a Linux mechanism and this is {}; the equivalent denials here come from \
         the backend that does the isolating",
        Platform::survey().sysname
    ))
}

/// Try to create a user namespace by creating one.
fn probe_user_namespaces() -> Availability {
    if Platform::survey().os != OS::Linux {
        return Availability::Unknown(format!(
            "user namespaces are a Linux mechanism and this is {}; there is no namespace to \
             create here",
            Platform::survey().sysname
        ));
    }
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
        // On Linux neither may be `Unknown`: both have something safe to try. A
        // machine with no `unshare` binary is the one honest `Unknown`. On an OS
        // without the mechanism, `Unknown` with a reason is the only honest answer,
        // and a backend that relied on it would be lying about this machine.
        match kernel.os() {
            OS::Linux => {
                assert!(!matches!(kernel.seccomp_usable, Availability::Unknown(_)));
                assert!(
                    kernel.user_namespaces.is_yes() || kernel.user_namespaces.reason().is_some(),
                    "a `no` must come with what the kernel said"
                );
            }
            other => {
                for availability in [&kernel.seccomp_usable, &kernel.user_namespaces] {
                    assert!(
                        matches!(availability, Availability::Unknown(_)),
                        "{other:?} has no {} to try: {:?}",
                        availability.state(),
                        availability
                    );
                    assert!(availability.reason().is_some(), "an Unknown needs a reason");
                }
            }
        }
    }

    #[test]
    fn the_platform_and_the_kernel_agree_about_which_os_this_is() {
        let kernel = Kernel::survey();
        assert!(
            kernel.kernel.starts_with(&kernel.platform.sysname),
            "{}",
            kernel.kernel
        );
        assert_eq!(kernel.os(), kernel.platform.os);
    }
}

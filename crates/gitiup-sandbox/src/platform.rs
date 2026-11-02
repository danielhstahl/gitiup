//! Which operating system this is, established rather than assumed.
//!
//! The ladder is not the same on every OS, and the honest order of the rungs follows
//! what the kernel actually offers: Linux has Landlock, seccomp, `unshare` and
//! bubblewrap; macOS has the Seatbelt sandbox and nothing else in-process; neither has
//! the other's. So every per-OS decision in this crate goes through one small place,
//! and `gitiup doctor` can say which place it looked at.
//!
//! The rule the crate keeps everywhere applies here too: a fact about the machine is
//! *established* (`uname`, the plist, a binary being on `PATH`), not read from a
//! compile-time hope. The `cfg!` checks pick the code path; this module reports the
//! reality the code path then has to survive.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The operating systems this crate knows the difference between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    /// Linux: Landlock, seccomp, namespaces.
    Linux,
    /// macOS (Darwin): the Seatbelt sandbox, and the container rungs.
    MacOS,
    /// Anything else unix-like. Only the container rungs and `plain` are on offer.
    Other,
}

impl OS {
    /// The stable lowercase name, for reports and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            OS::Linux => "linux",
            OS::MacOS => "macos",
            OS::Other => "other",
        }
    }

    /// Whether the Linux in-process backend can exist here at all.
    pub fn has_landlock(self) -> bool {
        self == OS::Linux
    }

    /// Whether the Seatbelt backend can exist here at all.
    pub fn has_seatbelt(self) -> bool {
        self == OS::MacOS
    }
}

/// The machine's OS facts, gathered once.
#[derive(Debug, Clone)]
pub struct Platform {
    /// Which OS family this is.
    pub os: OS,
    /// `uname -s`, e.g. `Linux`, `Darwin`.
    pub sysname: String,
    /// `uname -r`, e.g. `6.12.4-linuxkit`, `24.3.0`.
    pub release: String,
    /// The product version a human recognises: the macOS version for Darwin, the
    /// kernel release for Linux.
    pub version: String,
    /// The instruction set as `uname -m`, e.g. `aarch64`, `x86_64`.
    pub machine: String,
}

static PLATFORM: OnceLock<Platform> = OnceLock::new();

impl Platform {
    /// The platform facts, gathered once per process.
    pub fn survey() -> &'static Platform {
        PLATFORM.get_or_init(Platform::gather)
    }

    /// Gather them again (for tests, and for a long-lived daemon that wants a fresh
    /// line in its log).
    pub fn gather() -> Platform {
        let (sysname, release, machine) = uname();
        let os = match sysname.as_str() {
            "Linux" => OS::Linux,
            "Darwin" => OS::MacOS,
            _ => OS::Other,
        };
        let version = match os {
            OS::MacOS => macos_product_version().unwrap_or_else(|| release.clone()),
            _ => release.clone(),
        };
        Platform {
            os,
            sysname,
            release,
            version,
            machine,
        }
    }

    /// The one-line description `doctor` prints: `Linux 6.12.4-linuxkit (aarch64)`.
    pub fn describe(&self) -> String {
        if self.version == self.release {
            format!("{} {} ({})", self.sysname, self.release, self.machine)
        } else {
            format!(
                "{} {} — {} ({})",
                self.sysname, self.release, self.version, self.machine
            )
        }
    }

    /// Which OS family this is.
    pub fn os(&self) -> OS {
        self.os
    }
}

fn uname() -> (String, String, String) {
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return (
            "unknown".to_string(),
            "unknown".to_string(),
            "unknown".to_string(),
        );
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
    (
        field(&uts.sysname),
        field(&uts.release),
        field(&uts.machine),
    )
}

/// The macOS product version, e.g. `15.3`.
///
/// Read from `/System/Library/CoreServices/SystemVersion.plist`, which every macOS
/// has and which `sw_vers` reads too — reading the plist avoids a process spawn and
/// works with an empty `PATH`, both of which matter to a probe.
pub fn macos_product_version() -> Option<String> {
    let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist").ok()?;
    product_version_of(&plist)
}

/// Pull `ProductVersion` out of a `SystemVersion.plist`. Split out so the parsing is
/// testable on any platform with a fixture rather than only on a Mac.
fn product_version_of(plist: &str) -> Option<String> {
    let line_after = |key: &str| {
        plist
            .split('\n')
            .skip_while(|line| !line.contains(&format!("<key>{key}</key>")))
            .nth(1)
    };
    line_after("ProductVersion").and_then(|line| {
        let (_, rest) = line.split_once("<string>")?;
        rest.split_once("</string>")
            .map(|(value, _)| value.trim().to_string())
    })
}

/// Find a helper binary, searching `PATH` the way a shell would.
///
/// `PATH` in a CI job, a launchd agent or a container is often nothing like a
/// login shell's, so the system directories are appended rather than trusted to be
/// present: `/usr/bin/unshare` and `/usr/bin/sandbox-exec` have to be findable from an
/// environment that does not mention them.
pub fn binary(name: &str) -> Option<PathBuf> {
    if Path::new(name)
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return Path::new(name).is_file().then(|| PathBuf::from(name));
    }
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

/// The directories a build needs to read and execute on this OS.
///
/// Declaring them per-OS is what lets a confined job `exec` a compiler on either
/// platform instead of dying with `EACCES` and looking like a broken sandbox. macOS
/// has no `/lib` or `/lib64` (the shared libraries live under the SDK and in
/// `/usr/lib`), and its `/etc` is a symlink into `/private/etc` — which is why the
/// grants are made on canonical paths by the backends that need exact matching.
///
/// **This is the list for a job that runs on this machine's filesystem.** It is not a
/// list of things to bind-mount into a container: that job has a root filesystem of its
/// own out of its image, and the host's `/usr`, `/bin`, `/Library` or `/Applications`
/// landing read-only on top of the image's buries the toolchain the image was built for
/// — and, on a Mac, gets the whole run refused for a directory the desktop app does not
/// share (giti-ej2). See [`crate::mounts::SystemDirs`] for which backend grants what.
pub fn system_read_only() -> &'static [&'static str] {
    match Platform::survey().os {
        OS::MacOS => &[
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/etc",
            "/private",
            "/Applications",
            "/Library",
            "/opt/homebrew",
            "/opt/local",
            "/dev",
        ],
        _ => &[
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/libexec", "/etc", "/opt",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_is_the_running_one_and_says_so_in_one_line() {
        let platform = Platform::survey();
        assert!(
            !platform.sysname.is_empty() && !platform.release.is_empty(),
            "{platform:?}"
        );
        let line = platform.describe();
        assert!(line.contains(&platform.sysname), "{line}");
        assert!(line.contains(&platform.machine), "{line}");
        // The compile-time truth and the runtime truth must agree, or every `cfg`
        // gate in the crate is describing a machine this process is not on.
        #[cfg(target_os = "linux")]
        assert_eq!(platform.os, OS::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(platform.os, OS::MacOS);
    }

    #[test]
    fn the_plist_parser_reads_a_product_version() {
        // The fixture is the real file's shape: a plist is a key on one line and the
        // value on the next, so the parser is "the line after the key".
        let plist = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\">
<dict>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>15.3.1</string>
	<key>BuildVersion</key>
	<string>24D70</string>
</dict>
</plist>
";
        assert_eq!(product_version_of(plist).as_deref(), Some("15.3.1"));
        assert_eq!(product_version_of("<plist></plist>"), None);
    }

    #[test]
    fn a_helper_is_found_by_name_or_refused_honestly() {
        assert_eq!(binary("sh").map(|path| path.starts_with("/")), Some(true));
        assert_eq!(binary("definitely-not-a-real-binary-xyz"), None);
        // An absolute path is honoured only if it is a file.
        assert_eq!(binary("/bin/sh").is_some(), Path::new("/bin/sh").is_file());
    }

    #[test]
    fn the_system_read_list_is_absolute_and_names_the_directories_a_build_needs() {
        let list = system_read_only();
        for directory in list {
            assert!(
                directory.starts_with('/'),
                "{directory} is not absolute: a grant relative to a working directory inside \
                 the sandbox means nothing"
            );
        }
        // The two a build cannot start without. The rest of the list is deliberately
        // wider than any one machine: `/lib64`, `/libexec`, `/opt/homebrew` and
        // `/opt/local` exist on some hosts and not others, and a grant for a directory
        // that is not there is not a security problem (see `LandlockOutcome::skipped`).
        for essential in ["/usr", "/bin"] {
            assert!(
                list.contains(&essential) && Path::new(essential).exists(),
                "{essential} is on the list because nothing builds without it"
            );
        }
    }
}

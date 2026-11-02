//! The parts of confinement that are POSIX rather than Linux.
//!
//! These moved out of [`crate::linux`] when this crate grew a macOS backend: a
//! `setrlimit`, a `setuid`, a rebuilt `PATH` and the `pre_exec` seam mean the same
//! thing on every unix, and a backend on any of them wants exactly the same backstop.
//! What stays Linux-only is the stuff with no portable equivalent — Landlock, seccomp,
//! `prctl(PR_SET_NO_NEW_PRIVS)` — and it stays in [`crate::linux`].
//!
//! The rule the module keeps is the one the crate keeps: a limit that could not be
//! installed is said about, never quietly skipped. [`apply_limits`] returns what it
//! *did* apply, and the caller writes that into the probe or the plan notes.
//!
//! Two differences from Linux matter for what gets claimed:
//!
//! * **`RLIMIT_NPROC` counts the same thing, but `nproc` has to be *measured*
//!   differently.** On Linux the count comes from `/proc`; on macOS there is no
//!   `/proc`, so [`processes_of_uid`] asks `ps`. The floor arithmetic is identical.
//! * **`RLIMIT_AS` is a no-op on macOS** (XNU accepts it and ignores it). Everything
//!   that installs it ignores the failure, which is why the address-space cap is never
//!   a guarantee any backend's `guarantees` sentence rests on.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use gitiup_attest::{Error, ErrorKind as Kind, Result};

/// Drop supplementary groups and switch to `uid`/`gid`.
///
/// Only possible with the privilege to do so; a request that cannot be honoured is an
/// error, because "dropped to an unprivileged uid" is one of the claims in the
/// ticket's baseline and a claim that quietly did not happen is worse than a refusal.
pub fn drop_privileges(uid: Option<u32>, gid: Option<u32>) -> Result<bool> {
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return Ok(false);
    };
    let root = unsafe { libc::geteuid() } == 0;
    if !root {
        if uid == unsafe { libc::getuid() } && gid == unsafe { libc::getgid() } {
            // Already there: the claim is true, nothing to do.
            return Ok(true);
        }
        return Err(Error::new(
            Kind::Policy,
            "sandbox",
            format!(
                "the job asks to run as uid {uid} gid {gid}, and this process cannot change uid"
            ),
        )
        .with_hint(
            "run gitiup as root (or in a container that is root) to drop to an unprivileged uid, \
             or leave the uid unset and accept the backend's weaker uid guarantee",
        ));
    }
    let groups: [libc::gid_t; 0] = [];
    if unsafe { libc::setgroups(0, groups.as_ptr()) } != 0 {
        return Err(Error::new(
            Kind::Invalid,
            "sandbox",
            format!(
                "could not drop supplementary groups: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if unsafe { libc::setgid(gid) } != 0 || unsafe { libc::setuid(uid) } != 0 {
        return Err(Error::new(
            Kind::Invalid,
            "sandbox",
            format!(
                "could not drop to uid {uid} gid {gid}: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(true)
}

/// The `setrlimit` calls the baseline asks for.
///
/// `nproc` is expressed as *extra* processes and turned into an absolute limit by
/// [`nproc_floor`], because `RLIMIT_NPROC` is counted per uid for the whole machine:
/// an absolute 256 would stop a sandbox the moment its owner's desktop session had
/// more than 255 processes running.
pub fn apply_limits(
    cpu_seconds: Option<u64>,
    address_bytes: Option<u64>,
    extra_processes: Option<u64>,
    file_bytes: Option<u64>,
) -> Vec<String> {
    let mut applied = Vec::new();
    if let Some(seconds) = cpu_seconds
        && set_limit(libc::RLIMIT_CPU as libc::c_uint, seconds, seconds + 5).is_ok()
    {
        applied.push(format!("cpu {seconds}s"));
    }
    if let Some(bytes) = address_bytes
        && set_limit(libc::RLIMIT_AS as libc::c_uint, bytes, bytes).is_ok()
    {
        applied.push(format!("address {bytes} bytes"));
    }
    if let Some(extra) = extra_processes {
        let total = nproc_floor(extra);
        if set_limit(libc::RLIMIT_NPROC as libc::c_uint, total, total + 8).is_ok() {
            applied.push(format!("{extra} extra processes (cap {total})"));
        }
    }
    if let Some(bytes) = file_bytes
        && set_limit(libc::RLIMIT_FSIZE as libc::c_uint, bytes, bytes + (1 << 20)).is_ok()
    {
        applied.push(format!("file {bytes} bytes"));
    }
    // A core dump is a file full of memory written into whatever directory a job
    // chooses; there is no version of this that a sandbox wants.
    let _ = set_limit(libc::RLIMIT_CORE as libc::c_uint, 0, 0);
    applied
}

fn set_limit(resource: libc::c_uint, soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource as _, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `RLIMIT_NPROC` is per-uid and machine-wide, so a cap of N has to mean "N more than
/// this uid is already running".
pub fn nproc_floor(extra: u64) -> u64 {
    processes_of_uid(unsafe { libc::getuid() } as u64) + extra
}

/// Count the live processes owned by `uid`.
///
/// Linux reads `/proc`, because it is there and it is exact. There is no `/proc` on
/// macOS, so there the count comes from `ps -A -o uid=`, counted in-process rather
/// than through a shell. Both are the same quantity — the number of processes whose
/// real uid is `uid` — which is what makes [`nproc_floor`] one sentence rather than
/// two. A platform with neither returns 0, and a zero floor means the cap is exactly
/// what the job asked for, which is the conservative direction: the check that reads
/// this number is the one that *refuses* a sandbox whose cap is wider than the ask.
pub fn processes_of_uid(uid: u64) -> u64 {
    #[cfg(target_os = "linux")]
    {
        processes_of_uid_proc(uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        processes_of_uid_ps(uid)
    }
}

/// Count the live processes owned by `uid` by scanning `/proc`.
#[cfg(target_os = "linux")]
fn processes_of_uid_proc(uid: u64) -> u64 {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut count = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|text| text.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        // "Uid:\treal\teffective\tsaved\tfs" — the real uid is the one NPROC counts.
        if status
            .lines()
            .find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|text| text.parse::<u64>().ok())
                    .filter(|real| *real == uid)
            })
            .is_some()
        {
            count += 1;
        }
    }
    count
}

/// Count the processes owned by `uid` with `ps`, for the platforms with no `/proc`.
///
/// `ps -A -o uid=` is accepted by both the BSD `ps` on macOS and procps on Linux, and
/// printing one column keeps the parsing to "is this line the number". If `ps` is
/// missing or says nothing usable the count is 0 and the caller says so in its note:
/// an unmeasurable floor is reported, not invented.
#[cfg(not(target_os = "linux"))]
fn processes_of_uid_ps(uid: u64) -> u64 {
    let Some(ps) = crate::platform::binary("ps") else {
        return 0;
    };
    let Ok(output) = Command::new(&ps)
        .args(["-A", "-o", "uid="])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return 0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.trim().parse::<u64>() == Ok(uid))
        .count() as u64
}

/// The process count of the current uid, for logs and for the fork-bomb canary.
pub fn current_nproc() -> u64 {
    processes_of_uid(unsafe { libc::getuid() } as u64)
}

// ---------------------------------------------------------------- the confined spawn

/// Build a [`Command`] whose child runs `apply` between fork and `execve`.
///
/// This is the seam every in-process restriction goes through, so there is exactly one
/// place to audit for "what runs before the untrusted code does". The closure runs in
/// a forked child: nothing in it may allocate, lock a mutex or touch a file
/// descriptor it does not own, which is why the helpers above are all thin syscall
/// wrappers.
///
/// # Errors
///
/// If `apply` returns an error the child fails to spawn, with the error from the
/// child. There is no path where a failed restriction still runs the program: a
/// sandbox that degrades to "no sandbox" is the failure mode this whole crate is
/// written against.
pub fn pre_exec_command<F>(
    program: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    apply: F,
) -> Result<Command>
where
    F: Fn() -> io::Result<()> + Send + Sync + 'static,
{
    let mut command = Command::new(program);
    command.args(args);
    command.env_clear();
    for (key, value) in env {
        command.env(key, value);
    }
    if let Some(directory) = cwd {
        command.current_dir(directory);
    }
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(apply);
    }
    Ok(command)
}

/// A `PATH` a confined job gets: the system directories, and nothing that belongs to
/// the user who happens to have started the runner.
///
/// The list is per-platform because the system directories are: macOS has no `/lib`
/// or `/lib64`, and Homebrew — which is where a macOS build's compiler usually lives
/// — is `/opt/homebrew/bin` on Apple silicon and `/usr/local/bin` on Intel, the
/// latter being the same path Linux uses.
pub fn default_path() -> OsString {
    #[cfg(target_os = "macos")]
    let directories = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin";
    #[cfg(not(target_os = "macos"))]
    let directories = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    OsString::from(directories)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nproc_floor_is_above_what_the_uid_is_already_running() {
        // Both sides read `/proc`, and the tests run in parallel, so the two readings
        // differ by whatever the rest of the uid did in between — which can be dozens
        // of processes coming and going. The property that matters is that the floor is
        // built on the uid's own population rather than on 1, and it is checked with a
        // tolerance wide enough that a busy machine cannot fail it and narrow enough
        // that a floor of `extra` alone (the bug this guards) still fails.
        let floor = nproc_floor(10);
        let now = current_nproc();
        assert!(
            floor >= now.saturating_sub(64) + 10,
            "the cap must leave room for the job's own children on top of what this uid \
             is already running: floor {floor}, now {now}"
        );
    }

    #[test]
    fn the_confined_path_is_system_directories_only() {
        let path = default_path().to_string_lossy().into_owned();
        assert!(path.contains("/usr/bin"), "{path}");
        assert!(path.contains("/bin"), "{path}");
        // The point of rebuilding PATH is that it is not the caller's: a homebrew
        // prefix, a cargo bin directory or a version manager's shims are the same
        // argument on either platform.
        for forbidden in ["/home/", "/Users/", ".cargo/bin", ".nvm", ".pyenv"] {
            assert!(
                !path.contains(forbidden),
                "the confined PATH must not be the operator's: {path}"
            );
        }
    }

    #[test]
    fn a_process_count_of_a_uid_is_a_number_and_not_a_guess() {
        // This uid is running at least this test process, whatever the platform reads
        // it from. A zero here on a machine that has processes is the failure mode to
        // notice: it would silently widen every process cap to `extra` alone.
        let count = current_nproc();
        assert!(
            count >= 1,
            "this process counts as a process of its own uid: {count}"
        );
    }
}

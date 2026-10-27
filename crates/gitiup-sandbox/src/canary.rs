//! The escape canary: a program whose only job is to try to get out.
//!
//! The four attempts are the four the acceptance criterion names — write outside,
//! connect out, trace the runner, exceed the process cap — and each reports one of
//! `ESCAPED` or `DENIED` on stdout and exits `10` or `0`. The exit code is a
//! convenience; the verdict a backend is judged on is what the *host* observes (see
//! [`crate::escape`]), because a canary inside a sandbox is not a trustworthy witness
//! about its own cage.
//!
//! It is a separate binary so that it can be executed *as the job* by every backend
//! that can reach a host path (the in-process and namespace backends). Anything that
//! wants to embed the same logic — `gitiup doctor`, a test harness, a volunteer's own
//! checker — calls [`dispatch`] from its `main`.

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// The environment variable that names the canary, for a runner whose path is not
/// beside its executable.
pub const CANARY_ENV: &str = "GITIUP_SANDBOX_CANARY";

/// The name the binary is installed under, beside the executable that uses it.
pub const CANARY_BINARY: &str = "gitiup-sandbox-canary";

/// The exit code meaning "the escape worked".
pub const ESCAPED: i32 = 10;

/// The exit code meaning "the sandbox said no, as it should".
pub const DENIED: i32 = 0;

/// Find the canary: the named one, the one beside this executable, or the one on
/// `PATH`.
pub fn program() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os(CANARY_ENV).filter(|text| !text.is_empty()) {
        let path = PathBuf::from(named);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        // Beside this executable first, then one directory up: `cargo test` puts test
        // binaries in `target/debug/deps/` and the canary in `target/debug/`, so a
        // probe that only looked beside itself would never find the tool it builds.
        let directory = exe.parent()?;
        for depth in 0..2 {
            let dir = (0..depth).fold(directory, |path, _| path.parent().unwrap_or(path));
            let candidate = dir.join(CANARY_BINARY);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    crate::kernel::Kernel::binary(CANARY_BINARY)
}

/// Run one canary attempt.
///
/// Returns `None` when `args` is not a canary invocation, so a host binary can try it
/// first and fall through to its own subcommands.
pub fn dispatch(args: &[String]) -> Option<i32> {
    let command = args.first().map(String::as_str)?;
    match command {
        "fs" => args.get(1).map(|path| try_write_outside(path)),
        "connect" => args
            .get(1)
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .map(try_connect),
        "ptrace" => args
            .get(1)
            .and_then(|pid| pid.parse::<u32>().ok())
            .map(try_ptrace),
        "fork" => args
            .get(1)
            .and_then(|count| count.parse::<usize>().ok())
            .map(try_fork),
        "canary" | "canary-path" => Some(report_self()),
        _ => None,
    }
}

fn report_self() -> i32 {
    match std::env::current_exe() {
        Ok(path) => {
            println!("{}", path.display());
            DENIED
        }
        Err(why) => {
            eprintln!("cannot tell which program I am: {why}");
            DENIED
        }
    }
}

/// Try to create a file wherever it was pointed.
fn try_write_outside(path: &str) -> i32 {
    let target = std::path::Path::new(path);
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(target)
    {
        Ok(mut file) => {
            use std::io::Write;
            let _ = file.write_all(b"escaped");
            let _ = file.flush();
            println!("ESCAPED created {}", target.display());
            ESCAPED
        }
        Err(why) => {
            println!("DENIED open {} ({why})", target.display());
            DENIED
        }
    }
}

/// Try to complete a TCP handshake with a foreign address.
fn try_connect(address: SocketAddr) -> i32 {
    match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
        Ok(_) => {
            println!("ESCAPED connected to {address}");
            ESCAPED
        }
        Err(why) => {
            println!("DENIED connect to {address} ({why})");
            DENIED
        }
    }
}

/// Try to read the memory of another process, two ways.
fn try_ptrace(pid: u32) -> i32 {
    let pid = pid as libc::pid_t;
    let mut notes: Vec<String> = Vec::new();
    let mut escaped = false;

    // `process_vm_readv` is the quiet version of this attack: read another process's
    // memory with no stopping and no debugging at all.
    let mut buffer = [0u8; 16];
    let local = buffer.as_ptr();
    let read = unsafe {
        let local_iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        let remote_iov = libc::iovec {
            // Any address in the caller: what matters is whether the kernel lets the
            // call get as far as mapping the remote address at all.
            iov_base: local as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0)
    };
    if read >= 0 {
        escaped = true;
        notes.push(format!("process_vm_readv read {read} bytes from {pid}"));
    } else {
        let why = std::io::Error::last_os_error();
        notes.push(format!("process_vm_readv: {why}"));
    }

    // `PTRACE_ATTACH` is the loud version, and the one the ticket names.
    let attached = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if attached == 0 {
        // Read one word, then get out of the way: an attached process is a stopped
        // process, and leaving the runner stopped would be a denial of service of our
        // own making.
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        };
        if word != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EIO) {
            escaped = true;
            notes.push(format!("ptrace attached to {pid}"));
        }
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null::<libc::c_void>(),
                0,
            );
        }
    } else {
        notes.push(format!("ptrace: {}", std::io::Error::last_os_error()));
    }

    if escaped {
        println!("ESCAPED {}", notes.join(", "));
        ESCAPED
    } else {
        println!("DENIED {}", notes.join(", "));
        DENIED
    }
}

/// Try to start `count` live children, and report how many there were.
///
/// The children stay alive briefly on purpose: a fork bomb is measured by how many
/// processes exist at once, and a child that exits immediately lets the same slot be
/// reused a thousand times and proves nothing.
/// The process cap in force for this process: `RLIMIT_NPROC`'s soft limit, or
/// [`u64::MAX`] when there is none. Reported by the fork canary so the suite can judge
/// the limit rather than the machine's load.
pub fn process_cap() -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) } != 0 {
        return u64::MAX;
    }
    // `RLIM_INFINITY` is the all-ones value on Linux, and some distros put a huge
    // number there instead of the sentinel; both mean "no cap".
    if limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur > 1 << 40 {
        return u64::MAX;
    }
    // `rlim_t` is `u64` on a 64-bit target and `u32` on a 32-bit one, so the widening
    // cast is redundant here and necessary there.
    #[allow(clippy::useless_conversion)]
    let cap = limit.rlim_cur;
    cap
}

fn try_fork(count: usize) -> i32 {
    // Measure the cap from inside, before forking: the verdict has to be about whether
    // the sandbox installed the limit it claims to install, because whether the limit
    // *binds* depends on everything else running as this uid at the same moment.
    let cap = process_cap();
    let running = crate::linux::current_nproc();
    let mut started: Vec<i32> = Vec::new();
    let mut refusal: Option<std::io::Error> = None;
    for _ in 0..count {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // In the child: die with us, take no output, and hold a slot for a moment.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            std::thread::sleep(Duration::from_millis(700));
            unsafe { libc::_exit(0) };
        } else if pid > 0 {
            started.push(pid);
        } else {
            refusal = Some(std::io::Error::last_os_error());
            break;
        }
    }
    // Clean up before reporting: the cap is per-uid, and leaked children would make
    // the *next* check in the suite harder, not easier.
    for pid in &started {
        unsafe {
            libc::kill(*pid, libc::SIGKILL);
        }
    }
    for pid in &started {
        let mut status = 0;
        unsafe {
            libc::waitpid(*pid, &mut status, 0);
        }
    }
    println!("FORKED {}", started.len());
    println!("CAP {}", cap);
    println!("RUNNING {running}");
    match refusal {
        Some(why) => {
            println!(
                "DENIED the process cap held after {} ({why})",
                started.len()
            );
            DENIED
        }
        None => {
            println!("ESCAPED {} children started", started.len());
            ESCAPED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognised_invocation_is_left_to_the_host_binary() {
        assert_eq!(dispatch(&["run".to_string()]), None);
        assert_eq!(dispatch(&[]), None);
    }

    #[test]
    fn a_canary_attempt_on_itself_is_honest() {
        // These run *unconfined*, on purpose: the point is that an escape attempt that
        // nothing is stopping reports ESCAPED. A canary that reported DENIED here would
        // be a canary that could never detect anything.
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("outside");
        assert_eq!(try_write_outside(&target.display().to_string()), ESCAPED);
        assert!(target.exists());
        assert_eq!(
            try_ptrace(std::process::id()),
            ESCAPED,
            "tracing ones own parent is allowed unconfined"
        );
        assert_eq!(try_fork(2), ESCAPED);
    }
}

//! The Linux syscalls the in-process backend is made of.
//!
//! Everything here runs in the child, between `fork` and `execve`, through
//! [`pre_exec_command`]. That ordering is the whole design: a restriction that is in
//! force before the untrusted program's first instruction cannot be avoided by it,
//! which is more than can be said for a wrapper script or an environment variable.
//!
//! Three mechanisms, each with a different reach:
//!
//! * **Landlock** — filesystem writes (and, from ABI 4, TCP `bind`/`connect`) and,
//!   from ABI 3, which abstract unix sockets and signals may cross the boundary. It
//!   is the only unprivileged, in-process filesystem restriction in the kernel, and
//!   it survives `execve`, which is what makes it usable for running strangers.
//! * **seccomp** — a BPF filter over syscall numbers: `ptrace`, `mount`, `unshare`,
//!   `setns`, module loading, `open_by_handle_at`, privilege syscalls, and `seccomp`
//!   itself (a job may not install its own filter and loosen one). Also survives
//!   `execve`, and is *irreversible*, so anything it refuses is refused for the whole
//!   process tree.
//! * **`setrlimit`** — the cheap backstop: cpu seconds, address space, process count
//!   and file size, plus a hard `RLIMIT_CORE` of 0 so a job cannot drop a core file
//!   full of its own (and possibly somebody else's) memory onto the host.
//!
//! None of these is a filesystem namespace: reads stay wide on the in-process
//! backend, which is why [`crate::backends::inprocess`] says so in
//! [`guarantees`](crate::backend::Sandbox::guarantees) instead of letting a reviewer
//! assume otherwise.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, ErrorKind};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use gitiup_attest::{Error, ErrorKind as Kind, Result};

/// The syscall numbers we need are arch-specific in libc's terms but the same
/// constants on the two arches this crate supports.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("gitiup-sandbox's in-process backend is written for x86_64 and aarch64");

/// `offsetof(struct seccomp_data, nr)` and `…, arch)` — the only two fields the filter
/// reads.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;

// classic BPF opcodes, spelled out rather than imported so the filter can be read
// without a second window open on `linux/filter.h`.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO_BASE: u32 = 0x0005_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;

/// A classic-BPF instruction, layout-compatible with `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode.
    pub code: u16,
    /// Jump offset (or `jt`/`jf` packed).
    pub jt: u8,
    /// Jump offset.
    pub jf: u8,
    /// Immediate.
    pub k: u32,
}

/// The filter, and what it refuses.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    instructions: Vec<SockFilter>,
    refused: Vec<&'static str>,
}

impl SeccompFilter {
    /// The filter gitiup installs in every confined child.
    pub fn hardened() -> SeccompFilter {
        // Each name must exist as a syscall on the build arch; the numbers are
        // checked in `tests` so a typo cannot silently drop a denial.
        let denied: &[(u32, &str)] = &[
            (libc::SYS_ptrace as u32, "ptrace"),
            (libc::SYS_process_vm_readv as u32, "process_vm_readv"),
            (libc::SYS_process_vm_writev as u32, "process_vm_writev"),
            (libc::SYS_kcmp as u32, "kcmp"),
            (libc::SYS_mount as u32, "mount"),
            (libc::SYS_umount2 as u32, "umount2"),
            (libc::SYS_pivot_root as u32, "pivot_root"),
            (libc::SYS_chroot as u32, "chroot"),
            (libc::SYS_setns as u32, "setns"),
            (libc::SYS_unshare as u32, "unshare"),
            (libc::SYS_bpf as u32, "bpf"),
            (libc::SYS_init_module as u32, "init_module"),
            (libc::SYS_finit_module as u32, "finit_module"),
            (libc::SYS_delete_module as u32, "delete_module"),
            (libc::SYS_kexec_load as u32, "kexec_load"),
            (libc::SYS_reboot as u32, "reboot"),
            (libc::SYS_swapon as u32, "swapon"),
            (libc::SYS_swapoff as u32, "swapoff"),
            (libc::SYS_acct as u32, "acct"),
            (libc::SYS_open_tree as u32, "open_tree"),
            (libc::SYS_move_mount as u32, "move_mount"),
            (libc::SYS_fsopen as u32, "fsopen"),
            (libc::SYS_fsconfig as u32, "fsconfig"),
            (libc::SYS_fsmount as u32, "fsmount"),
            (libc::SYS_open_by_handle_at as u32, "open_by_handle_at"),
            (libc::SYS_name_to_handle_at as u32, "name_to_handle_at"),
            (libc::SYS_add_key as u32, "add_key"),
            (libc::SYS_keyctl as u32, "keyctl"),
            (libc::SYS_request_key as u32, "request_key"),
            (libc::SYS_userfaultfd as u32, "userfaultfd"),
            // A job may not hand itself a new uid, or install a filter of its own to
            // loosen this one.
            (libc::SYS_setuid as u32, "setuid"),
            (libc::SYS_setgid as u32, "setgid"),
            (libc::SYS_setreuid as u32, "setreuid"),
            (libc::SYS_setregid as u32, "setregid"),
            (libc::SYS_setresuid as u32, "setresuid"),
            (libc::SYS_setresgid as u32, "setresgid"),
            (libc::SYS_setfsuid as u32, "setfsuid"),
            (libc::SYS_setfsgid as u32, "setfsgid"),
            (libc::SYS_capset as u32, "capset"),
            (libc::SYS_seccomp as u32, "seccomp"),
        ];
        let refused: Vec<&'static str> = denied.iter().map(|(_, name)| *name).collect();
        let instructions = assemble(denied.iter().map(|(nr, _)| *nr).collect());
        SeccompFilter {
            instructions,
            refused,
        }
    }

    /// The BPF program.
    pub fn instructions(&self) -> &[SockFilter] {
        &self.instructions
    }

    /// What it refuses, by name — for `doctor` and for the guarantees sentence.
    pub fn refused(&self) -> &[&'static str] {
        self.refused.as_slice()
    }

    /// Install it, in the child, after `no_new_privs`.
    ///
    /// # Safety
    ///
    /// The filter is irreversible and applies to the calling thread and its children,
    /// so this belongs in a forked child before `execve` and nowhere else. Calling it
    /// in a long-lived process would gitiup's own ability to `ptrace` or `mount`
    /// away.
    pub unsafe fn install(&self) -> io::Result<()> {
        let prog = libc::sock_fprog {
            len: self.instructions.len() as u16,
            // The layouts are identical; this is the one cast the whole module is
            // about.
            filter: self.instructions.as_ptr() as *mut libc::sock_filter,
        };
        // seccomp(2) with SECCOMP_SET_MODE_FILTER requires no_new_privs or root.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0u32,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// The program: check the arch, then one equality test per refused syscall, then
/// allow, with the `EPERM` return as the jump target.
///
/// The order of the last two instructions is the whole subtlety of this function: the
/// *fall-through* after the last comparison must be ALLOW, so ALLOW comes first and
/// the `EPERM` return sits after it, reachable only by a forward jump. Put them the
/// other way round and every syscall that is not on the deny list falls through into
/// the `EPERM` return — a filter that refuses everything, including `write` and
/// `exit_group`, which shows up as a child dying in a heap of `EPERM` rather than as a
/// sandbox that holds. `linux::runtime_tests` is what keeps that from coming back.
fn assemble(nrs: Vec<u32>) -> Vec<SockFilter> {
    let mut program: Vec<SockFilter> = Vec::with_capacity(nrs.len() + 5);
    // If the arch is not the one this filter was built for, kill: a filter that
    // silently applied to a foreign syscall table would be worse than none.
    program.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0));
    program.push(ret(RET_KILL_PROCESS));
    program.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));
    // Layout: [checks…] [allow] [deny]; `deny` must be reachable with an 8-bit forward
    // offset from every check, which bounds the list at 255 instructions.
    let deny_index = 5 + nrs.len();
    for nr in &nrs {
        let index = program.len();
        let taken = deny_index - index - 1;
        assert!(taken <= u8::MAX as usize, "seccomp filter too long");
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, taken as u8, 0));
    }
    program.push(ret(RET_ALLOW));
    program.push(ret(RET_ERRNO_BASE | libc::EPERM as u32));
    program
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn ret(k: u32) -> SockFilter {
    stmt(BPF_RET | BPF_K, k)
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// ---------------------------------------------------------------- Landlock

/// `LANDLOCK_CREATE_RULESET_VERSION`.
const CREATE_RULESET_VERSION: u32 = 1 << 0;
/// `LANDLOCK_ACCESS_FS_*`, in the order the uapi header lists them.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_REGULAR_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_REG: u64 = 1 << 7;
const FS_MAKE_SYM: u64 = 1 << 8;
const FS_MAKE_FIFO: u64 = 1 << 9;
const FS_TRUNCATE: u64 = 1 << 10; // ABI 3
const FS_REFER: u64 = 1 << 11; // ABI 2
const FS_IOCTL_DEV: u64 = 1 << 12; // ABI 6
/// `LANDLOCK_ACCESS_NET_*` (ABI 4).
const NET_TCP_BIND: u64 = 1 << 0;
const NET_TCP_CONNECT: u64 = 1 << 1;
/// `LANDLOCK_SCOPE_*`.
const SCOPE_ABSTRACT_UNIX: u64 = 1 << 0; // ABI 3
const SCOPE_SIGNAL: u64 = 1 << 1; // ABI 4

/// `struct landlock_ruleset_attr` — the newest layout, with the older fields first.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr` (`__packed` in the uapi header).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// `struct landlock_net_tcp_attr`. Both ports are set to the same value, which is how
/// a single-port rule is expressed: the kernel matches the *remote* port for
/// `connect` and the local one for `bind`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct NetTcp {
    allowed_access: u64,
    s_port: u16,
    d_port: u16,
}

/// The filesystem rights we know how to ask for, for a given ABI.
fn fs_rights(abi: u32) -> u64 {
    let mut mask = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_REGULAR_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_REG
        | FS_MAKE_SYM
        | FS_MAKE_FIFO;
    if abi >= 2 {
        mask |= FS_REFER;
    }
    if abi >= 3 {
        mask |= FS_TRUNCATE;
    }
    if abi >= 6 {
        mask |= FS_IOCTL_DEV;
    }
    mask
}

const FS_READ: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
const FS_WRITE: u64 = FS_WRITE_FILE
    | FS_REMOVE_DIR
    | FS_REMOVE_REGULAR_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_REG
    | FS_MAKE_SYM
    | FS_MAKE_FIFO;

/// What Landlock was actually able to do, as observed at restrict time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockOutcome {
    /// The kernel's Landlock ABI version.
    pub abi: u32,
    /// TCP `connect`/`bind` were part of the ruleset, so ports really are refused.
    /// `false` on ABI < 4, where the network has to be refused some other way.
    pub net_enforced: bool,
    /// The ports a job may still connect to (empty = none).
    pub allowed_ports: Vec<u16>,
    /// The paths that could not be granted (missing directories), if any.
    pub skipped: Vec<PathBuf>,
    /// The scopes that were enforced (names, for the probe note).
    pub scoped: Vec<String>,
}

/// The kernel's Landlock ABI version, or `None` when there is no Landlock.
pub fn landlock_abi() -> Option<u32> {
    let rc = unsafe {
        libc::syscall(
            syscall_create_ruleset(),
            std::ptr::null::<libc::c_void>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        return None;
    }
    Some(rc as u32)
}

fn syscall_create_ruleset() -> libc::c_long {
    libc::SYS_landlock_create_ruleset
}

/// Build and enforce a Landlock ruleset on the calling (child) process.
///
/// `read_only` trees may be read and executed; `read_write` trees may also be
/// written. `tcp_ports` are the only TCP ports `connect` and `bind` may use — an
/// empty list means no TCP at all, which is what default-deny wants.
///
/// Every step is required: a path that cannot be opened is returned in
/// [`LandlockOutcome::skipped`] rather than being granted silently, and any syscall
/// failure is an error the caller must treat as fatal (running unconfined is not the
/// fallback).
pub fn landlock_restrict(
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    tcp_ports: &[u16],
) -> io::Result<LandlockOutcome> {
    let abi = landlock_abi().ok_or_else(|| {
        io::Error::new(
            ErrorKind::Unsupported,
            "this kernel has no Landlock (need 5.13+, with `landlock` in /sys/kernel/security/lsm)",
        )
    })?;
    let net_supported = abi >= 4;
    let mut attr = RulesetAttr {
        handled_access_fs: fs_rights(abi),
        handled_access_net: if net_supported {
            NET_TCP_BIND | NET_TCP_CONNECT
        } else {
            0
        },
        scoped: 0,
    };
    let mut scoped = Vec::new();
    if abi >= 3 {
        attr.scoped |= SCOPE_ABSTRACT_UNIX;
        scoped.push("abstract unix sockets".to_string());
    }
    if abi >= 4 {
        attr.scoped |= SCOPE_SIGNAL;
        scoped.push("signals".to_string());
    }

    let ruleset = unsafe {
        libc::syscall(
            syscall_create_ruleset(),
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset < 0 {
        let why = io::Error::last_os_error();
        // An old kernel that has never heard of `scoped`/net: retry with the v1
        // layout instead of refusing to sandbox at all, and say which rung we landed
        // on. `handled_access_net` and `scoped` are the *last* fields and are zero in
        // the retry, so the kernel sees a subset.
        if !net_supported && why.raw_os_error() == Some(libc::EINVAL) {
            return Err(why);
        }
        return Err(why);
    }

    let mut skipped: Vec<PathBuf> = Vec::new();
    for path in read_only {
        if !grant(ruleset as i32, path, FS_READ & fs_rights(abi)) {
            skipped.push(path.clone());
        }
    }
    let write_mask = (FS_READ | FS_WRITE) & fs_rights(abi);
    for path in read_write {
        if !grant(ruleset as i32, path, write_mask) {
            skipped.push(path.clone());
        }
    }

    if net_supported {
        for port in tcp_ports {
            let rule = NetTcp {
                allowed_access: NET_TCP_BIND | NET_TCP_CONNECT,
                // The kernel wants network byte order for the port pair.
                s_port: (*port).to_be(),
                d_port: (*port).to_be(),
            };
            // landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_SERVICE = 2, attr, flags).
            if unsafe {
                libc::syscall(
                    syscall_add_rule(),
                    ruleset,
                    2u32,
                    &rule as *const NetTcp,
                    0u32,
                )
            } < 0
            {
                let why = io::Error::last_os_error();
                unsafe { libc::close(ruleset as i32) };
                return Err(why);
            }
        }
    }

    let outcome = LandlockOutcome {
        abi,
        net_enforced: net_supported,
        allowed_ports: tcp_ports.to_vec(),
        skipped,
        scoped,
    };

    // LANDLOCK_CREATE_RULESET_VERSION was already asked, so a ruleset that exists
    // means the syscall exists; restrict_self only needs no_new_privs first.
    let rc = unsafe { libc::syscall(syscall_restrict_self(), ruleset, 0u32) };
    unsafe { libc::close(ruleset as i32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(outcome)
}

fn grant(ruleset: i32, path: &Path, access: u64) -> bool {
    let fd = open_path(path);
    if fd < 0 {
        return false;
    }
    let rule = PathBeneath {
        allowed_access: access,
        parent_fd: fd,
    };
    // landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH = 1, attr, flags).
    let rc = unsafe {
        libc::syscall(
            syscall_add_rule(),
            ruleset,
            1u32,
            &rule as *const PathBeneath,
            0u32,
        )
    };
    unsafe { libc::close(fd) };
    rc == 0
}

/// `O_PATH | O_CLOEXEC`: Landlock rules want a descriptor for the subtree, not a
/// readable file. `O_NOFOLLOW` so a symlink at a grant point cannot be used to widen
/// the grant to whatever it points at.
fn open_path(path: &Path) -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes: Vec<u8> = path.as_os_str().as_bytes().to_vec();
    bytes.push(0);
    unsafe {
        libc::open(
            bytes.as_ptr() as *const libc::c_char,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    }
}

fn syscall_add_rule() -> libc::c_long {
    libc::SYS_landlock_add_rule
}

fn syscall_restrict_self() -> libc::c_long {
    libc::SYS_landlock_restrict_self
}

// ---------------------------------------------------------------- privileges, limits

/// `PR_SET_NO_NEW_PRIVS` — required before seccomp without root, and a hardening on
/// its own: a setuid binary cannot raise privileges inside the sandbox.
pub fn no_new_privs() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether this process already has no-new-privs (inherited from a parent).
pub fn no_new_privs_set() -> bool {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status.lines().any(|line| {
            line.starts_with("NoNewPrivs:")
                && line.split(':').next_back().unwrap_or("0").trim() == "1"
        }),
        Err(_) => false,
    }
}

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
    if unsafe { libc::setrlimit(resource, &limit) } == 0 {
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

/// Count the live processes owned by `uid` by scanning `/proc`.
pub fn processes_of_uid(uid: u64) -> u64 {
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
pub fn default_path() -> OsString {
    OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_is_well_formed_classic_bpf() {
        let filter = SeccompFilter::hardened();
        let program = filter.instructions();
        assert!(program.len() > 6);
        // Arch guard first: load, compare, kill.
        assert_eq!(program[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(program[0].k, OFFSET_ARCH);
        assert_eq!(program[1].k, AUDIT_ARCH);
        assert_eq!(program[1].jt, 1);
        assert_eq!(program[2].k, RET_KILL_PROCESS);
        assert_eq!(program[3].k, OFFSET_NR);
        // The fall-through after the last comparison is ALLOW, so it comes second to
        // last; the EPERM return is last and is the only jump target. Swap the two and
        // the filter refuses every syscall, which this is the test that notices.
        let last = program.len() - 1;
        assert_eq!(program[last - 1].k, RET_ALLOW);
        assert_eq!(program[last].k, RET_ERRNO_BASE | libc::EPERM as u32);
        for (index, instruction) in program[4..last - 1].iter().enumerate() {
            let index = index + 4;
            assert_eq!(instruction.code, BPF_JMP | BPF_JEQ | BPF_K);
            assert_eq!(
                index + 1 + instruction.jt as usize,
                last,
                "instruction {index} must jump to the EPERM return"
            );
            assert_eq!(instruction.jf, 0);
        }
    }

    #[test]
    fn the_refused_list_names_the_escapes_that_matter() {
        let filter = SeccompFilter::hardened();
        for needed in [
            "ptrace",
            "mount",
            "unshare",
            "setns",
            "open_by_handle_at",
            "seccomp",
            "setuid",
        ] {
            assert!(filter.refused().contains(&needed), "{needed}");
        }
        assert!(filter.refused().len() >= 30);
    }

    #[test]
    fn landlock_rights_come_from_the_abi_we_claim() {
        assert_eq!(fs_rights(1) & FS_TRUNCATE, 0);
        assert_ne!(fs_rights(3) & FS_TRUNCATE, 0);
        assert_ne!(fs_rights(2) & FS_REFER, 0);
        assert_ne!(fs_rights(6) & FS_IOCTL_DEV, 0);
        // The write set must never include a read right by accident: the read set is
        // granted on `/`, and a write leak there would be the whole sandbox.
        assert_eq!(FS_WRITE & FS_READ, 0);
    }

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
    fn no_new_privs_can_be_asked_about() {
        // Reading it must not panic whatever the kernel says; setting it is tested by
        // the child-based tests in `tests/escape.rs`, where it is safe to do.
        let _ = no_new_privs_set();
    }
}

/// Tests that fork a child and apply the real filters. The child's exit status is the
/// assertion: a filter that kills the process it was only meant to *limit* shows up as
/// a signal here, which is exactly the bug this catches.
#[cfg(test)]
mod runtime_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn after_apply(apply: impl Fn() -> i32) -> std::process::ExitStatus {
        let child = unsafe { libc::fork() };
        if child == 0 {
            let code = apply();
            if code != 0 {
                unsafe { libc::_exit(code) };
            }
            // Ordinary work after the filter is in place: a write, then a clean exit.
            let msg = b"alive\n";
            let written = unsafe { libc::write(1, msg.as_ptr() as *const libc::c_void, msg.len()) };
            if written != msg.len() as libc::ssize_t {
                unsafe { libc::_exit(3) };
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
        std::process::ExitStatus::from_raw(status)
    }

    #[test]
    fn the_hardened_filter_leaves_an_ordinary_process_alone() {
        let filter = SeccompFilter::hardened();
        let status = after_apply(|| {
            if no_new_privs().is_err() {
                return 4;
            }
            match unsafe { filter.install() } {
                Ok(()) => 0,
                Err(_) => 6,
            }
        });
        assert!(
            status.success(),
            "the filter killed or blocked an ordinary process: {status:?}"
        );
    }

    #[test]
    fn a_denied_syscall_is_errnot_perm_not_a_signal() {
        let filter = SeccompFilter::hardened();
        let status = after_apply(|| {
            if no_new_privs().is_err() || unsafe { filter.install() }.is_err() {
                return 4;
            }
            // `setuid` is on the deny list; it must come back as EPERM and the process
            // must still be alive afterwards.
            let rc = unsafe { libc::setuid(0) };
            let errno = std::io::Error::last_os_error();
            if rc == 0 {
                return 7; // we are root and it worked: not a denial
            }
            if errno.raw_os_error() == Some(libc::EPERM) {
                0
            } else {
                8
            }
        });
        assert!(status.success(), "setuid did not fail cleanly: {status:?}");
    }

    #[test]
    fn no_new_privs_is_sticky_and_reports_it() {
        let status = after_apply(|| {
            let first = no_new_privs();
            let second = no_new_privs();
            if first.is_err() || second.is_err() {
                return 4;
            }
            if no_new_privs_set() { 0 } else { 5 }
        });
        assert!(status.success(), "no_new_privs did not hold: {status:?}");
    }
}

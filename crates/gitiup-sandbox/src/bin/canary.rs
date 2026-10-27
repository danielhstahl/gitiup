//! `gitiup-sandbox-canary` — the escape attempts, as a program a sandbox can run.
//!
//! The binary is deliberately the dumbest thing in the crate: it parses one
//! subcommand, tries it, prints the verdict, and exits. That is the whole reason it
//! exists as a binary at all — a confinement check has to be performed by a process
//! that is *inside* the confinement, and the only way to be inside is to be exec'd
//! there.
//!
//! ```text
//! gitiup-sandbox-canary fs /path/outside       try to create a file there
//! gitiup-sandbox-canary connect 127.0.0.1:1    try to complete a TCP handshake
//! gitiup-sandbox-canary ptrace <pid>           try to trace and read <pid>
//! gitiup-sandbox-canary fork 128               try to start 128 live children
//! gitiup-sandbox-canary canary                 print this program's path
//! ```
//!
//! Exit code `10` means the escape worked, `0` means the sandbox refused it.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match gitiup_sandbox::canary::dispatch(&args) {
        Some(code) => ExitCode::from(code as u8),
        None => {
            eprintln!(
                "usage: gitiup-sandbox-canary <fs PATH | connect ADDR:PORT | ptrace PID | fork N | canary>"
            );
            // A usage error is not an escape, and must not be reported as one.
            ExitCode::from(2)
        }
    }
}

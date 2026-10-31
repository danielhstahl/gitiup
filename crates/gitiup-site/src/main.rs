//! `gitiup-site`, the binary: read `docs/`, write a site.
//!
//! The whole of `main` is argument parsing and exit codes — the decisions are in
//! [`gitiup_site`], so the same pipeline runs from a test in-process and from a CI
//! job as a subprocess, which is how every other command in this workspace is
//! arranged.
//!
//! ```text
//! $ cargo run --locked --release -p gitiup-site -- build --out _site
//! $ python3 -m http.server -d _site
//! ```

use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let code = gitiup_site::cli::run(&args, &mut out, &mut err);
    let _ = out.flush();
    let _ = err.flush();
    std::process::exit(code);
}

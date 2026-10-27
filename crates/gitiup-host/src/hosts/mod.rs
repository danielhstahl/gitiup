//! Host implementations. Every host is one `impl Host` over the same trait set:
//! [`fs`] (the reference host), [`s3`] (bucket-as-forge, giti-xdw.2), the
//! plain-git host [`git`] (a bare repo over ssh, smart-HTTP or dumb-HTTP,
//! giti-xdw.3). A forge adapter is *not* in this crate: the github adapter
//! (`gitiup-host-github`, behind the CLI's `hosts-github` feature) hangs off the
//! same traits from its own crate, which is what keeps this one's "no forge
//! imports" promise enforceable instead of aspirational.

pub mod fs;
pub mod git;
pub mod s3;

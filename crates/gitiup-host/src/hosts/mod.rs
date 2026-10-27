//! Host implementations. Every host is one `impl Host` over the same trait set:
//! [`fs`] (the reference host), [`s3`] (bucket-as-forge, giti-xdw.2), the
//! plain-git host [`git`] (a bare repo over ssh, smart-HTTP or dumb-HTTP,
//! giti-xdw.3), and the github adapter (giti-xdw.4, feature-gated) which hangs
//! off the same traits.

pub mod fs;
pub mod git;
pub mod s3;

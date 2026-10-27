//! Host implementations. Only [`fs`] lives here for now; the S3 host
//! (giti-xdw.2), plain-git host (giti-xdw.3) and the github adapter
//! (giti-xdw.4, feature-gated) hang off the same traits.

pub mod fs;

//! The host conformance bodies now live in the crate itself —
//! [`gitiup_host::conformance`] — so a host that lives in another crate (the
//! github adapter of giti-xdw.4, and anything downstream) can run the same
//! bodies instead of copying them.
//!
//! This file is kept as a thin re-export so the existing host test files read
//! the same way they always did, and so a rename of the module cannot quietly
//! drop a host from the suite.

pub use gitiup_host::conformance::*;

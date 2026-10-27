//! The plain-git host against the shared suite, in the three shapes a bare
//! repository is actually deployed in:
//!
//! * `file://` — the box you ssh into, a shared mount, a scratch directory;
//! * smart HTTP — a repository served by `git-http-backend`, where a lease has to
//!   survive a network and a web server;
//! * dumb HTTP — a static file server, which is a legitimate release mirror and
//!   the `cas = false` case the suite must see from the inside.
//!
//! CI may supply the HTTP endpoints (see `ci/host-conformance.sh` and the
//! workflow); otherwise the suite starts the python fixtures itself, and skips
//! those two hosts out loud if it cannot.

// A bare repository on a local path.
gitiup_host_tests::test_host!(git_file, gitiup_host_tests::hosts::GIT_FILE);

// The same repository served by `git-http-backend`, plus the refused-credential
// and read-only-mirror shapes.
gitiup_host_tests::test_host!(git_http, gitiup_host_tests::hosts::GIT_HTTP);

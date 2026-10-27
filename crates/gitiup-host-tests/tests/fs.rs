//! The `fs` reference host against the shared suite.
//!
//! This is the host every other host is measured against, so a failure here is
//! never "just the fs host": it means a body is wrong or the reference
//! implementation regressed, and every host below would fail the same way.

// The reference host: a directory with a refs file and a content-addressed tree.
gitiup_host_tests::test_host!(fs, gitiup_host_tests::hosts::FS);

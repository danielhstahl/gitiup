//! The github adapter, measured like any other host — with a mock forge, so it
//! runs anywhere.
//!
//! The point is not to re-test the adapter's API mapping (its own suite does that);
//! it is to catch the moment the forge-backed host quietly means something
//! different from the bucket and the bare repository.
#![cfg(feature = "github")]

gitiup_host_tests::test_host!(github, gitiup_host_tests::hosts::GITHUB);

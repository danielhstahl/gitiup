//! The bucket-as-forge host over the in-process bucket: real etags, real 412s,
//! paged LISTs and staged multipart uploads with no network, so the CAS and
//! degradation paths run on every machine.
//!
//! `tests/s3_minio.rs` runs the same bodies over the real transport; this file is
//! what catches a regression when there is no bucket to point at.

// The bucket-as-forge host over the in-process bucket, including its
// refused-credentials and cas=false variants (the denial mapping deserves a named
// test in CI output, and it gets one here and one inside the host's own bodies).
gitiup_host_tests::test_host!(s3_memory, gitiup_host_tests::hosts::S3_MEMORY);

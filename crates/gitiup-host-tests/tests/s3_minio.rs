//! The live bucket: the same bodies over the real `aws-sdk-s3` transport,
//! against MinIO in CI or whatever the AWS chain points at elsewhere.
//!
//! Skipped (loudly) when there are no credentials; `GITIUP_CONFORMANCE_REQUIRE_HOSTS=s3-minio`
//! in CI turns that skip into a failure, so a service that failed to start cannot
//! be mistaken for a pass. See [`gitiup_host_tests::hosts::live`] for the knobs.
#![cfg(feature = "s3")]

gitiup_host_tests::test_host!(s3_minio, gitiup_host_tests::hosts::S3_MINIO);

//! Getting from a `gitiup.toml` remote to a live bucket — and being honest about
//! which build can do it.
//!
//! Credentials are never read out of `gitiup.toml`. The bucket is authenticated
//! by the standard AWS chain, in the documented order:
//!
//! 1. environment (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`)
//! 2. the shared config (`~/.aws/config`, `~/.aws/credentials`) — static keys,
//!    `credential_process`, and SSO sessions
//! 3. web identity / IRSA (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`), which
//!    is what a pod on EKS uses
//! 4. whatever the SDK's default resolver ends up with
//!
//! With the `s3` feature compiled in, [`connect`] builds that chain through
//! `aws-config` and hands back a [`Bucket`] backed by `aws-sdk-s3`. Without it —
//! the default, so a plain `cargo build` links no HTTP or AWS code at all —
//! [`connect`] refuses with [`HostError::UnsupportedCas`] naming the feature, and
//! callers pass a bucket they constructed themselves to
//! [`S3Host::open`](super::S3Host::open) instead. That is what `tests/host_s3.rs`
//! and the conformance suite (giti-xdw.5) do, over
//! [`MemoryBucket`](super::bucket::MemoryBucket).

use crate::config::{RemoteConfig, RemoteScheme};
use crate::error::{HostError, HostResult};

use super::bucket::SharedBucket;

/// Connect to the bucket named by an `s3://` remote.
pub fn connect(remote: &RemoteConfig) -> HostResult<SharedBucket> {
    if remote.scheme() != RemoteScheme::S3 {
        return Err(HostError::SchemeUnknown(Box::new(
            crate::error::SchemeUnknown {
                scheme: remote.scheme().as_str().to_string(),
                supported: vec![RemoteScheme::S3.as_str().to_string()],
                hint: Some(format!(
                    "the S3 host only dials s3:// remotes; '{}' points at {}",
                    remote.name,
                    remote.redacted_url()
                )),
            },
        )));
    }
    #[cfg(feature = "s3")]
    {
        Ok(aws::connect(remote)?)
    }
    #[cfg(not(feature = "s3"))]
    {
        Err(missing_feature(remote))
    }
}

/// How this build would reach a remote, for `gitiup remote show` and
/// `gitiup remote doctor`. Never includes a secret.
pub fn describe(remote: &RemoteConfig) -> String {
    let (options, _) = super::S3Options::from_remote(remote).unwrap_or_default();
    let endpoint = options.endpoint.clone().unwrap_or_else(|| {
        format!(
            "the default S3 endpoint{}",
            options
                .region
                .as_deref()
                .map(|region| format!(" for {region}"))
                .unwrap_or_default()
        )
    });
    // An explicit endpoint still needs its region named: MinIO ignores it, but
    // "why is this talking to us in another region" is a real question.
    let region = options
        .endpoint
        .as_deref()
        .and(options.region.as_deref())
        .map(|region| format!(", region {region}"))
        .unwrap_or_default();
    let profile = options
        .profile
        .clone()
        .or_else(|| remote.credentials_profile.clone())
        .unwrap_or_else(|| "the default chain".to_string());
    format!(
        "s3://{} via {endpoint}{region}, credentials from the AWS chain ({profile})",
        remote.url.host
    )
}

/// The error a build without the `s3` feature answers with.
pub fn missing_feature(remote: &RemoteConfig) -> HostError {
    HostError::unsupported(
        "s3-transport",
        format!(
            "this build of gitiup has no S3 transport, so remote '{}' ({}) cannot be dialled",
            remote.name,
            remote.redacted_url()
        ),
    )
    .with_hint(
        "build with the `s3` feature (`cargo build --features gitiup-host/s3`) to link the AWS \
         SDK, or hand a bucket you built yourself to S3Host::open — tests/host_s3.rs does that \
         with the in-process MemoryBucket",
    )
}

#[cfg(feature = "s3")]
mod aws {
    //! The `aws-sdk-s3` transport. Everything async lives in here: the host
    //! traits are synchronous (see `docs/host-abstraction.md`), so each call is
    //! driven on a small runtime owned by the bucket.

    use std::sync::Arc;

    use aws_sdk_s3::error::ProvideErrorMetadata;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::types::{
        BucketVersioningStatus, CompletedMultipartUpload, CompletedPart, ObjectLockEnabled,
    };
    use aws_sdk_s3::{Client, Config as SdkConfig};

    use crate::config::RemoteConfig;
    use crate::error::{HostError, HostResult};
    use crate::time::Timestamp;

    use super::super::S3Options;
    use super::super::bucket::{
        Bucket, BucketError, BucketFacts, BucketInfo, Object, ObjectMeta, PutCond, VersioningState,
    };

    /// S3's own minimum part size; smaller parts are rejected at complete time.
    const MIN_PART: usize = 5 * 1024 * 1024;

    /// A bucket reached over the AWS SDK, with the AWS credential chain behind
    /// it — never a token from `gitiup.toml`.
    pub struct AwsBucket {
        runtime: tokio::runtime::Runtime,
        client: Client,
        info: BucketInfo,
        bucket: String,
        facts: BucketFacts,
    }

    /// Build the client from the standard chain and ask the bucket the three
    /// questions that become the host's capabilities.
    pub fn connect(remote: &RemoteConfig) -> HostResult<Arc<AwsBucket>> {
        let (options, _) = S3Options::from_remote(remote)?;
        if options.anonymous {
            // Say it here rather than let the SDK sign with whatever the chain found,
            // because "public-read" and "signed as the owner" are different requests and
            // only one of them is what the operator asked for. An anonymous `GET` is an
            // unsigned one; the SDK in this build always signs, so this transport cannot
            // make the request the declaration describes — and a read that succeeded
            // under the owner's own credentials would look like a working public mirror
            // while proving nothing about it.
            return Err(HostError::unsupported(
                "anonymous",
                format!(
                    "remote '{}' is declared anonymous (public-read), and this build's S3 \"
                     transport signs every request",
                    remote.name
                ),
            )
            .with_hint(
                "drop anonymous from [remote.options] to read this bucket as yourself; a \
                 public mirror that needs no credential is served today over `git+https://` \
                 or a plain HTTPS endpoint, where there is nothing to sign",
            ));
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|err| HostError::unreachable(format!("cannot start the S3 runtime: {err}")))?;
        let bucket = remote.url.host.clone();
        let root = remote.root_prefix();
        let (config, region) = runtime.block_on(sdk_config(remote, &options))?;
        let client = Client::from_conf(config);
        let facts = runtime.block_on(probe(&client, &bucket, &root, &options))?;
        let info = BucketInfo {
            bucket: bucket.clone(),
            endpoint: options.endpoint.clone().unwrap_or_else(|| {
                region
                    .as_deref()
                    .map(|region| format!("s3.{region}.amazonaws.com"))
                    .unwrap_or_else(|| "the default S3 endpoint".to_string())
            }),
            region: region.unwrap_or_else(|| "not resolved".to_string()),
            credentials: credential_source(&options),
        };
        Ok(Arc::new(AwsBucket {
            runtime,
            client,
            info,
            bucket,
            facts,
        }))
    }

    /// The SDK config: region, profile and endpoint from the remote's options,
    /// falling back to the environment, exactly like the `aws` CLI.
    async fn sdk_config(
        remote: &RemoteConfig,
        options: &S3Options,
    ) -> Result<(SdkConfig, Option<String>), BucketError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = from_option_or_env(
            options.region.as_deref(),
            &["AWS_REGION", "AWS_DEFAULT_REGION"],
        ) {
            loader = loader.region(aws_sdk_s3::config::Region::new(region));
        }
        if let Some(profile) = from_option_or_env(options.profile.as_deref(), &["AWS_PROFILE"]) {
            // The same profile the `aws` CLI would pick, from the shared config.
            loader = loader.profile_name(profile);
        }
        let shared = loader.load().await;
        let region = shared.region().map(|region| region.to_string());
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        // An explicit endpoint is how MinIO and Friends are addressed; path-style
        // is what most of them expect.
        if let Some(endpoint) = options.endpoint.as_deref() {
            builder = builder.endpoint_url(endpoint);
        }
        if options.force_path_style {
            builder = builder.force_path_style(true);
        }
        // S3-compatible servers close idle keep-alive connections whenever they
        // feel like it, which shows up as a dispatch failure on the next call.
        // Those are exactly the failures a retry fixes, and the SDK's policy
        // never retries a write whose condition did not hold.
        builder = builder
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(4));
        let _ = remote;
        Ok((builder.build(), region))
    }

    /// Where the credentials came from — variable *names* and the profile name
    /// only, never a value. Printing a resolved key would be the leak this whole
    /// design exists to avoid.
    fn credential_source(options: &S3Options) -> String {
        let mut from: Vec<String> = Vec::new();
        for name in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_BEARER_TOKEN_OS_CLOUD",
        ] {
            if std::env::var_os(name).is_some() {
                from.push(name.to_string());
            }
        }
        if let Some(profile) = from_option_or_env(options.profile.as_deref(), &["AWS_PROFILE"]) {
            from.push(format!("shared-config profile '{profile}'"));
        }
        if from.is_empty() {
            from.push("the default chain (SSO, instance or task role, shared config)".to_string());
        }
        format!("AWS credential chain: {}", from.join(", "))
    }

    fn from_option_or_env(value: Option<&str>, vars: &[&str]) -> Option<String> {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            return Some(value.to_string());
        }
        vars.iter().find_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
    }

    /// Versioning, Object Lock and whether conditional writes really work.
    async fn probe(
        client: &Client,
        bucket: &str,
        root: &str,
        options: &S3Options,
    ) -> Result<BucketFacts, BucketError> {
        let versioning = match versioning(client, bucket).await {
            Ok(state) => state,
            // An endpoint that will not answer is only fatal if we need the fact.
            // With `require-versioning = false` the operator has already accepted
            // that overwrites are not recoverable, so this degrades to unknown
            // (and `BucketFacts::advice` still says so on every `remote doctor`).
            Err(_) if !options.require_versioning => VersioningState::Unknown,
            Err(err) => return Err(err),
        };
        let object_lock = object_lock(client, bucket).await;
        let conditional_writes = match options.conditional_writes {
            super::super::ConditionalWrites::Off => false,
            super::super::ConditionalWrites::Auto | super::super::ConditionalWrites::On => {
                conditional_writes(client, bucket, root).await?
            }
        };
        Ok(BucketFacts {
            versioning,
            object_lock,
            conditional_writes,
        })
    }

    /// Object versioning state, which is the fact gitiup most needs.
    ///
    /// A failure to ask is reported rather than swallowed: the host has to
    /// refuse a bucket it cannot prove is versioned, and "the endpoint refused
    /// GetBucketVersioning" is a very different answer from "versioning is off".
    async fn versioning(client: &Client, bucket: &str) -> Result<VersioningState, BucketError> {
        match client.get_bucket_versioning().bucket(bucket).send().await {
            Ok(out) => Ok(match out.status() {
                Some(BucketVersioningStatus::Enabled) => VersioningState::Enabled,
                Some(BucketVersioningStatus::Suspended) => VersioningState::Suspended,
                // A variant this SDK build does not know: not proof of anything.
                Some(_) => VersioningState::Unknown,
                // A bucket that never switched versioning on answers with no status.
                None => VersioningState::Disabled,
            }),
            Err(err) => Err(classify(
                "get_bucket_versioning",
                bucket,
                err.code(),
                &err.to_string(),
            )),
        }
    }

    async fn object_lock(client: &Client, bucket: &str) -> bool {
        match client
            .get_object_lock_configuration()
            .bucket(bucket)
            .send()
            .await
        {
            Ok(out) => {
                out.object_lock_configuration()
                    .and_then(|configuration| configuration.object_lock_enabled())
                    == Some(&ObjectLockEnabled::Enabled)
            }
            Err(_) => false,
        }
    }

    /// Probe conditional writes the only way that counts: try one.
    ///
    /// A `PUT` with `If-None-Match: *` twice in a row must fail the second time.
    /// An endpoint that answers "OK" twice is overwriting, and a host that
    /// believed it would silently lose ref updates.
    async fn conditional_writes(
        client: &Client,
        bucket: &str,
        root: &str,
    ) -> Result<bool, BucketError> {
        // Unique per process so a previous probe (or a crash) cannot make a
        // capable bucket look incapable.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or(0);
        let key = format!("{root}/gitiup-conditional-probe-{nonce}");
        let first = client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(ByteStream::from_static(b"gitiup"))
            .if_none_match("*")
            .send()
            .await;
        if let Err(err) = first {
            // Not-implemented means the gateway does not do conditional writes;
            // anything else is a real error we should hear about.
            if is_refused_conditions(&err) {
                return Ok(false);
            }
            return Err(classify(
                "conditional-write probe",
                &key,
                err.code(),
                &err.to_string(),
            ));
        }
        let outcome = match client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(ByteStream::from_static(b"gitiup"))
            .if_none_match("*")
            .send()
            .await
        {
            // It wrote over the object: conditional writes are not honoured.
            Ok(_) => Ok(false),
            Err(err) if is_precondition_failed(&err) => Ok(true),
            Err(err) if is_refused_conditions(&err) => Ok(false),
            Err(err) => Err(classify(
                "conditional-write probe",
                &key,
                err.code(),
                &err.to_string(),
            )),
        };
        // The probe object is transport litter; removing it is best effort (a
        // locked bucket may refuse, which changes nothing).
        let _ = client.delete_object().bucket(bucket).key(&key).send().await;
        outcome
    }

    /// Classify an SDK failure by error code first (the one thing S3 and
    /// S3-compatible servers agree on) and by the rendered message second.
    fn classify(what: &str, key: &str, code: Option<&str>, text: &str) -> BucketError {
        let code = code.unwrap_or_default();
        let lowered = text.to_lowercase();
        match code {
            "NoSuchKey" | "NoSuchVersion" | "NotFound" => BucketError::NotFound { key: key.into() },
            "NoSuchBucket" => BucketError::Unreachable {
                message: format!("{what}: bucket '{key}' does not exist ({text})"),
                retryable: false,
            },
            "PreconditionFailed" | "IfConditionFalse" => BucketError::PreconditionFailed {
                key: key.into(),
                condition: text.to_string(),
            },
            "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" | "ExpiredToken" => {
                BucketError::Denied {
                    key: key.into(),
                    message: text.to_string(),
                }
            }
            "NotImplemented" | "MethodNotAllowed" | "NotSupported" | "MalformedXML" => {
                BucketError::Unsupported {
                    feature: "s3-operation".into(),
                    message: format!("{what}: {text}"),
                }
            }
            _ if is_timeout_text(&lowered) => BucketError::Unreachable {
                message: format!("{what}: {text}"),
                retryable: true,
            },
            _ => BucketError::Other {
                key: key.into(),
                message: format!("{what}: {text}"),
            },
        }
    }

    fn is_timeout_text(lowered: &str) -> bool {
        [
            "dispatch",
            "connection",
            "dns",
            "timed out",
            "timeout",
            "reset",
            "tls",
            "unreachable",
        ]
        .iter()
        .any(|needle| lowered.contains(needle))
    }

    /// A last-modified timestamp, when the endpoint reports one; the SDK's own
    /// datetime type never leaks into the transport contract.
    fn stamp(when: Option<&aws_sdk_s3::primitives::DateTime>) -> Option<Timestamp> {
        let secs = when?.secs();
        u64::try_from(secs).ok().map(Timestamp::from_unix)
    }

    /// A 412: the precondition did not hold.
    fn is_precondition_failed(err: &(impl ProvideErrorMetadata + std::fmt::Display)) -> bool {
        matches!(
            err.code(),
            Some("PreconditionFailed") | Some("IfConditionFalse") | Some("412")
        ) || err.to_string().contains("412")
    }

    /// The endpoint refused to even consider a conditional write.
    fn is_refused_conditions(err: &(impl ProvideErrorMetadata + std::fmt::Display)) -> bool {
        let text = err.to_string().to_lowercase();
        matches!(
            err.code(),
            Some("NotImplemented") | Some("MethodNotAllowed") | Some("NotSupported")
        ) || (text.contains("if-none-match")
            || text.contains("if-match")
            || text.contains("conditional"))
            && !text.contains("precondition")
    }

    impl Bucket for AwsBucket {
        fn info(&self) -> BucketInfo {
            self.info.clone()
        }

        fn facts(&self) -> Result<BucketFacts, BucketError> {
            Ok(self.facts)
        }

        fn get(&self, key: &str) -> Result<Option<Object>, BucketError> {
            let key = key.to_string();
            self.runtime.block_on(async {
                match self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send()
                    .await
                {
                    Ok(out) => {
                        let etag = out.e_tag().unwrap_or_default().to_string();
                        // `collect` consumes the streaming body: this is the
                        // only way to get the bytes out of the response.
                        let aggregated =
                            out.body.collect().await.map_err(|err| BucketError::Other {
                                key: key.clone(),
                                message: format!("reading the body failed: {err}"),
                            })?;
                        let bytes = aggregated.into_bytes();
                        Ok(Some(Object {
                            key,
                            bytes: bytes.to_vec(),
                            etag,
                        }))
                    }
                    Err(err)
                        if err.code() == Some("NoSuchKey") || err.to_string().contains("404") =>
                    {
                        Ok(None)
                    }
                    Err(err) => Err(classify("get_object", &key, err.code(), &err.to_string())),
                }
            })
        }

        fn head(&self, key: &str) -> Result<Option<ObjectMeta>, BucketError> {
            let key = key.to_string();
            self.runtime.block_on(async {
                match self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send()
                    .await
                {
                    Ok(out) => Ok(Some(ObjectMeta {
                        key: key.clone(),
                        size: out.content_length().unwrap_or_default().max(0) as u64,
                        etag: out.e_tag().unwrap_or_default().to_string(),
                        modified: stamp(out.last_modified()),
                    })),
                    Err(err)
                        if err.code() == Some("NotFound") || err.to_string().contains("404") =>
                    {
                        Ok(None)
                    }
                    Err(err) => Err(classify("head_object", &key, err.code(), &err.to_string())),
                }
            })
        }

        fn put(&self, key: &str, bytes: &[u8], cond: PutCond) -> Result<ObjectMeta, BucketError> {
            let key = key.to_string();
            let body = ByteStream::from(bytes.to_vec());
            let describe = cond.describe();
            self.runtime.block_on(async {
                let mut request = self
                    .client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .body(body)
                    .content_length(bytes.len() as i64);
                match cond {
                    PutCond::Unconditional => {}
                    PutCond::CreateOnly => request = request.if_none_match("*"),
                    PutCond::IfMatch(etag) => request = request.if_match(etag),
                }
                match request.send().await {
                    Ok(out) => Ok(ObjectMeta {
                        key,
                        size: bytes.len() as u64,
                        etag: out.e_tag().unwrap_or_default().to_string(),
                        modified: None,
                    }),
                    Err(err) if is_precondition_failed(&err) => {
                        Err(BucketError::PreconditionFailed {
                            key,
                            condition: describe,
                        })
                    }
                    Err(err) if is_refused_conditions(&err) => Err(BucketError::Unsupported {
                        feature: "conditional-writes".into(),
                        message: format!("{describe} was refused: {err}"),
                    }),
                    Err(err) => Err(classify("put_object", &key, err.code(), &err.to_string())),
                }
            })
        }

        fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, BucketError> {
            let prefix = prefix.to_string();
            self.runtime.block_on(async {
                let mut out: Vec<ObjectMeta> = Vec::new();
                let mut token: Option<String> = None;
                loop {
                    let mut request = self
                        .client
                        .list_objects_v2()
                        .bucket(&self.bucket)
                        .prefix(&prefix)
                        .max_keys(1000);
                    if let Some(token) = &token {
                        request = request.continuation_token(token);
                    }
                    let page = request.send().await.map_err(|err| {
                        classify("list_objects_v2", &prefix, err.code(), &err.to_string())
                    })?;
                    for object in page.contents() {
                        out.push(ObjectMeta {
                            key: object.key().unwrap_or_default().to_string(),
                            size: object.size().unwrap_or_default().max(0) as u64,
                            etag: object.e_tag().unwrap_or_default().to_string(),
                            modified: stamp(object.last_modified()),
                        });
                    }
                    if page.is_truncated() == Some(true) {
                        token = page.next_continuation_token().map(str::to_string);
                        if token.is_none() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                out.sort_by(|left, right| left.key.cmp(&right.key));
                Ok(out)
            })
        }

        fn put_large(
            &self,
            key: &str,
            bytes: &[u8],
            part_size: usize,
            cond: PutCond,
        ) -> Result<ObjectMeta, BucketError> {
            let part = part_size.max(MIN_PART);
            if bytes.len() < part {
                return self.put(key, bytes, cond);
            }
            let key = key.to_string();
            let describe = cond.describe();
            self.runtime.block_on(async {
                let upload = self
                    .client
                    .create_multipart_upload()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send()
                    .await
                    .map_err(|err| {
                        classify(
                            "create_multipart_upload",
                            &key,
                            err.code(),
                            &err.to_string(),
                        )
                    })?;
                let upload_id = upload.upload_id().unwrap_or_default().to_string();
                let mut parts: Vec<CompletedPart> = Vec::new();
                let mut number = 1i32;
                let mut cursor = 0usize;
                while cursor < bytes.len() {
                    let stop = (cursor + part).min(bytes.len());
                    let chunk = bytes[cursor..stop].to_vec();
                    cursor = stop;
                    match self
                        .client
                        .upload_part()
                        .bucket(&self.bucket)
                        .key(&key)
                        .upload_id(&upload_id)
                        .part_number(number)
                        .content_length(chunk.len() as i64)
                        .body(ByteStream::from(chunk))
                        .send()
                        .await
                    {
                        Ok(part) => parts.push(
                            CompletedPart::builder()
                                .e_tag(part.e_tag().unwrap_or_default())
                                .part_number(number)
                                .build(),
                        ),
                        Err(err) => {
                            // A half-finished upload must not sit in the bucket
                            // billing us for staged parts.
                            let _ = self
                                .client
                                .abort_multipart_upload()
                                .bucket(&self.bucket)
                                .key(&key)
                                .upload_id(&upload_id)
                                .send()
                                .await;
                            return Err(classify(
                                "upload_part",
                                &key,
                                err.code(),
                                &err.to_string(),
                            ));
                        }
                    }
                    number += 1;
                }
                // S3 applies the condition at completion, which is the moment the
                // object appears.
                let mut complete = self
                    .client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .multipart_upload(
                        CompletedMultipartUpload::builder()
                            .set_parts(Some(parts))
                            .build(),
                    );
                complete = match &cond {
                    PutCond::Unconditional => complete,
                    PutCond::CreateOnly => complete.if_none_match("*"),
                    PutCond::IfMatch(etag) => complete.if_match(etag),
                };
                match complete.send().await {
                    Ok(out) => Ok(ObjectMeta {
                        key,
                        size: bytes.len() as u64,
                        etag: out.e_tag().unwrap_or_default().to_string(),
                        modified: None,
                    }),
                    Err(err) if is_precondition_failed(&err) => {
                        Err(BucketError::PreconditionFailed {
                            key,
                            condition: describe,
                        })
                    }
                    Err(err) => Err(classify(
                        "complete_multipart_upload",
                        &key,
                        err.code(),
                        &err.to_string(),
                    )),
                }
            })
        }

        fn min_part_size(&self) -> usize {
            MIN_PART
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HostErrorKind;

    fn remote(url: &str) -> RemoteConfig {
        RemoteConfig::new("origin", url).expect("a valid remote url")
    }

    #[test]
    fn a_non_s3_remote_is_not_dialled() {
        let mirror = remote("ssh://git@build.example.net/srv/git/mirror.git");
        let err = match connect(&mirror) {
            Ok(_) => panic!("the S3 host has no business dialling ssh"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), HostErrorKind::SchemeUnknown);
        assert!(err.to_string().contains("mirror.git"), "{err}");
    }

    #[test]
    fn a_build_without_the_feature_says_which_feature_is_missing() {
        let err = missing_feature(&remote("s3://gitiup-forge/my-repo"));
        assert_eq!(err.kind(), HostErrorKind::UnsupportedCas);
        let text = err.to_string();
        assert!(text.contains("no S3 transport"), "{text}");
        let hint = err.hint().unwrap();
        assert!(hint.contains("s3"), "{hint}");
        assert!(hint.contains("features"), "{hint}");
    }

    #[test]
    fn describe_names_the_endpoint_and_profile_but_no_secret() {
        let minio = remote("s3://gitiup-forge/my-repo")
            .with_option("endpoint", "https://git.minio.internal")
            .with_option("region", "eu-central-1")
            .with_option("profile", "ci-writer");
        let text = describe(&minio);
        assert!(text.contains("git.minio.internal"), "{text}");
        assert!(text.contains("eu-central-1"), "{text}");
        assert!(text.contains("ci-writer"), "{text}");
        assert!(text.contains("AWS chain"), "{text}");
        assert!(text.contains("gitiup-forge"), "{text}");
        for never in ["secret", "token", "password", "AKIA"] {
            assert!(
                !text.to_lowercase().contains(never),
                "describe() must never print a credential ({never}): {text}"
            );
        }
    }
}

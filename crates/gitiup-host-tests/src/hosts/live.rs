//! The live bucket: the same [`S3Host`] over the real `aws-sdk-s3` transport,
//! pointed at MinIO in CI or at any endpoint an operator names.
//!
//! Environment:
//!
//! * `GITIUP_S3_LIVE_ENDPOINT` — the endpoint URL, e.g. `http://127.0.0.1:9000`.
//!   Unset means the real AWS endpoint, so the credentials decide.
//! * `GITIUP_S3_LIVE_BUCKET` — a disposable bucket (default `gitiup-conformance`);
//!   created and versioned if it is not there, exactly as an operator would.
//! * `GITIUP_S3_LIVE_REGION` — region (default `us-east-1`).
//! * `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (or any other member of the
//!   AWS chain). The suite will not accept a token from `gitiup.toml` because the
//!   host will not either.
//! * `GITIUP_S3_LIVE_ALLOW_UNVERSIONED=1` — accept a bucket whose versioning the
//!   SDK cannot confirm (moto needs this; MinIO and real buckets do not).
//! * `GITIUP_CONFORMANCE_S3_DENIED=1` — says "the credentials in this process are
//!   the ones the endpoint refuses". CI sets it in one job, alongside a revoked
//!   key, which is the only honest way to test an expired credential against a
//!   real endpoint.
//!
//! The registration is unavailable — not failing, but skipped and printed — when
//! no credentials are present. `GITIUP_CONFORMANCE_REQUIRE_HOSTS=s3-minio` in CI
//! turns that skip into a failure, so a service that did not start cannot hide.

use gitiup_host::{Host, HostKind, HostResult, RemoteConfig, S3Host};

use crate::registration::{Knobs, Registration, Session};

fn endpoint() -> Option<String> {
    std::env::var("GITIUP_S3_LIVE_ENDPOINT")
        .ok()
        .map(|value| value.trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

fn bucket() -> String {
    std::env::var("GITIUP_S3_LIVE_BUCKET").unwrap_or_else(|_| "gitiup-conformance".to_string())
}

fn region() -> String {
    std::env::var("GITIUP_S3_LIVE_REGION").unwrap_or_else(|_| "us-east-1".to_string())
}

/// Whether the AWS chain has anything to try. A live-bucket run with no
/// credentials is a misconfiguration, but the hermetic suite must not fail
/// because someone ran `cargo test --all-features` on a laptop.
fn credentials_present() -> bool {
    [
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_BEARER_TOKEN_BEDROCK",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

/// Whether this registration can run here at all.
pub fn minio_configured() -> bool {
    credentials_present()
}

/// Whether the environment says the credentials in play are the refused ones.
pub fn minio_denial_configured() -> bool {
    minio_configured() && denied_mode()
}

/// `GITIUP_CONFORMANCE_S3_DENIED=1`: the credentials in this process are the ones
/// the endpoint refuses.
///
/// That is a statement about the *process*, not about one store, so it takes the
/// ordinary live registration out of the run: a bucket you cannot authenticate to
/// is not a bucket to measure conformance against. What remains — and what the
/// CI step that sets this variable is there to check — is the refusal itself, which
/// has to arrive as a denial rather than as an empty listing.
fn denied_mode() -> bool {
    std::env::var("GITIUP_CONFORMANCE_S3_DENIED")
        .map(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// A fresh store prefix per call: bodies run in parallel, and two of them sharing
/// a prefix would turn each other's create-only writes into real conflicts —
/// which is a conflict, not a bug, and exactly what the suite must not mistake for
/// one. The process token is in there too, so a run cannot inherit the last one's
/// leftovers from a bucket that outlived it; and `provision` sweeps what is there,
/// because everything under this prefix is the suite's own rubbish.
/// The escape hatch for an endpoint that cannot answer `GetBucketVersioning` the
/// way the SDK expects (moto is one: it replies with a root element the SDK
/// rejects, and gitiup — rightly — refuses a bucket whose versioning it cannot
/// confirm). Against MinIO or a real bucket, leave this unset and the strict path
/// is what runs.
fn allow_unversioned() -> bool {
    std::env::var("GITIUP_S3_LIVE_ALLOW_UNVERSIONED")
        .map(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Whether the live bucket can be measured as a store in this process: there are
/// credentials, and they are not the refused ones.
pub fn minio_live_available() -> bool {
    minio_configured() && !denied_mode()
}

fn remote(tag: &str) -> RemoteConfig {
    let url = format!(
        "s3://{}/conformance-{tag}-{}-{}",
        bucket(),
        crate::fixtures::token(),
        crate::fixtures::next()
    );
    let mut remote = RemoteConfig::new("minio", &url).expect("a valid bucket url");
    if let Some(endpoint) = endpoint() {
        remote = remote.with_option("endpoint", &endpoint);
        // A literal address cannot carry a bucket subdomain, so virtual-host
        // addressing would ask DNS for `gitiup-conformance.127.0.0.1`.
        remote = remote.with_option("force-path-style", "true");
    }
    let remote = remote.with_option("region", region());
    if allow_unversioned() {
        remote.with_option("require-versioning", "false")
    } else {
        remote
    }
}

/// Everything the suite writes lives under this prefix.
const SCRATCH: &str = "conformance-";

/// Delete what the last run left. A bucket that outlives its run would otherwise
/// hand `a_fresh_store_is_empty_then_writable` a store with refs in it, and a
/// listing body an object it never wrote — the falsest drift of all: a suite that
/// fails because of its own last run.
///
/// This also states the contract: the bucket named by `GITIUP_S3_LIVE_BUCKET` is
/// the suite's to own. Point two runs at it at once and they will sweep each other.
async fn sweep(client: &aws_sdk_s3::Client, bucket: &str) -> Result<(), String> {
    let mut token: Option<String> = None;
    loop {
        let mut page_request = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(SCRATCH)
            .max_keys(1_000);
        if let Some(token) = &token {
            page_request = page_request.continuation_token(token);
        }
        let page = page_request
            .send()
            .await
            .map_err(|err| format!("cannot list the scratch prefix: {err}"))?;
        let keys: Vec<String> = page
            .contents()
            .iter()
            .map(|object| object.key().unwrap_or_default().to_string())
            .collect();
        if !keys.is_empty() {
            let mut batch = aws_sdk_s3::types::Delete::builder().quiet(true);
            for key in keys {
                batch = batch.objects(
                    aws_sdk_s3::types::ObjectIdentifier::builder()
                        .key(key)
                        .build()
                        .expect("every key this listing returned is an object"),
                );
            }
            client
                .delete_objects()
                .bucket(bucket)
                .delete(
                    batch
                        .build()
                        .expect("the batch has at least one object in it"),
                )
                .send()
                .await
                .map_err(|err| format!("cannot clear the scratch prefix: {err}"))?;
        }
        if page.is_truncated() != Some(true) {
            return Ok(());
        }
        token = page
            .next_continuation_token()
            .map(str::to_string)
            .filter(|value| !value.is_empty());
        if token.is_none() {
            return Ok(());
        }
    }
}

/// Create the bucket and turn versioning on, because that is the configuration
/// gitiup requires and `mb` plus `versioning put` is what an operator types.
fn provision() -> Result<(), gitiup_host::HostError> {
    static DONE: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let outcome = DONE.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?;
        runtime.block_on(async {
            let mut builder = aws_sdk_s3::Config::builder()
                .behavior_version(aws_config::BehaviorVersion::latest())
                .region(aws_sdk_s3::config::Region::new(region()));
            if let Some(endpoint) = endpoint() {
                builder = builder.endpoint_url(endpoint).force_path_style(true);
            }
            let client = aws_sdk_s3::Client::from_conf(builder.build());
            // Already exists, already ours, no permission to create: all fine, as
            // long as the versioning call afterwards works.
            let _ = client.create_bucket().bucket(bucket()).send().await;
            client
                .put_bucket_versioning()
                .bucket(bucket())
                .versioning_configuration(
                    aws_sdk_s3::types::VersioningConfiguration::builder()
                        .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                        .build(),
                )
                .send()
                .await
                .map_err(|err| err.to_string())?;
            sweep(&client, &bucket()).await
        })
    });
    match outcome {
        Ok(()) => Ok(()),
        Err(why) => Err(gitiup_host::HostError::unreachable(format!(
            "cannot prepare s3://{}: {why}",
            bucket()
        ))),
    }
}

/// Ask for CAS rather than accepting a quiet downgrade: a bucket that cannot do
/// conditional writes cannot gate a merge, and a CI run that measures a
/// CAS-less bucket while believing it measured a real one is the drift this file
/// exists to prevent. Use `GITIUP_CONFORMANCE_REQUIRE_CAS=0` to opt out.
fn demands_cas() -> bool {
    std::env::var("GITIUP_CONFORMANCE_REQUIRE_CAS")
        .map(|value| !matches!(value.trim(), "0" | "false" | "no" | "off"))
        .unwrap_or(true)
}

fn make_minio(tag: &str) -> HostResult<Session> {
    provision()?;
    let remote = remote(tag);
    let bucket = gitiup_host::hosts::s3::transport::connect(&remote)?;
    let host = S3Host::open_or_init(bucket, &remote)?;
    if demands_cas() && !host.capabilities().cas {
        return Err(gitiup_host::HostError::unsupported(
            "conditional-writes",
            format!(
                "{} refused conditional writes, and this run demands CAS: {:?}",
                remote.redacted_url(),
                host.advice()
            ),
        ));
    }
    Ok(Session::new(host))
}

fn make_minio_denied() -> HostResult<Session> {
    // Best effort: provisioning needs the credentials this run does not have. The
    // CI step that sets the refused-credential mode runs after the one that made
    // the bucket, and either way the answer under test is what the endpoint says to
    // a request it will not honour.
    let _ = provision();
    let remote = remote("revoked");
    let bucket = gitiup_host::hosts::s3::transport::connect(&remote)?;
    let host = S3Host::open_or_init(bucket, &remote)?;
    Ok(Session::new(host))
}

/// A real bucket — MinIO in CI, whatever `AWS_*` points at otherwise — driven
/// through exactly the same bodies as the in-memory one.
pub const S3_MINIO: Registration = Registration {
    name: "s3-minio",
    kind: HostKind::S3,
    make: || make_minio("host"),
    available: minio_live_available,
    unavailable: "no AWS credentials in the environment: set GITIUP_S3_LIVE_ENDPOINT and the \
                  AWS_* chain to measure a real bucket (see this module's documentation)",
    knobs: Knobs {
        // Over the multipart threshold (8 MiB by default) and over one LIST page
        // (1 000 keys): the two numbers a bucket changes its behaviour at, and
        // the reason this registration exists in addition to the in-memory one.
        pack_bytes: 12 * 1024 * 1024,
        list_count: 1_005,
        ref_count: 40,
        writers: 6,
    },
    skips: &[],
    denied: Some(make_minio_denied),
    denied_available: minio_denial_configured,
    denied_unavailable: "a refused-credential run needs GITIUP_CONFORMANCE_S3_DENIED=1 \
                         alongside credentials the endpoint refuses",
    denied_secret: || {
        std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|value| !value.is_empty())
    },
    degraded: Some(make_minio_degraded),
    degraded_available: minio_live_available,
    degraded_unavailable: "the cas=false variant needs the same endpoint as the live host",
};

/// The same endpoint with conditional writes declared unavailable — which is what
/// a gateway that strips `If-Match` is, as far as a client can tell.
fn make_minio_degraded() -> HostResult<Session> {
    provision()?;
    let remote = remote("nocas").with_option("conditional-writes", "off");
    let bucket = gitiup_host::hosts::s3::transport::connect(&remote)?;
    let host = S3Host::open_or_init(bucket, &remote)?;
    Ok(Session::new(host))
}

//! The live transport: the same [`S3Host`] against a real S3 endpoint, over the
//! `aws-sdk-s3` client instead of the in-process bucket.
//!
//! These tests are `#[ignore]`d, because a test suite that needs the network is
//! a test suite that fails in a sealed build box. To run them, point them at a
//! throwaway endpoint — [moto](https://docs.getmoto.org) is enough and needs no
//! AWS account:
//!
//! ```text
//! pip install "moto[server]"
//! moto_server -H 127.0.0.1 -p 5500 &
//! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
//!   cargo test --features s3 --test host_s3_live -- --ignored
//! ```
//!
//! Environment:
//!
//! * `GITIUP_S3_LIVE_ENDPOINT` — endpoint URL (default `http://127.0.0.1:5500`).
//! * `GITIUP_S3_LIVE_BUCKET` — bucket to use; created if missing (default
//!   `gitiup-live-test`). It must be disposable: the tests write and version
//!   objects under `gitiup-live/`.
//! * `GITIUP_S3_LIVE_REGION` — region (default `us-east-1`).
//!
//! `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (or any other member of the
//! AWS chain) must be set: gitiup resolves credentials through the chain and
//! will not accept a token from `gitiup.toml`, so neither will the test.
//!
//! moto note: moto answers `GetBucketVersioning` with a
//! `<GetBucketVersioningResponse>` root where `aws-sdk-s3` expects
//! `<VersioningConfiguration>`, so the SDK rejects the response and gitiup
//! (rightly) refuses a bucket whose versioning it cannot confirm. Against moto,
//! set `GITIUP_S3_LIVE_ALLOW_UNVERSIONED=1` to run the transport assertions
//! anyway; against MinIO or a real bucket, leave it unset and the versioning
//! assertions run for real.

#![cfg(feature = "s3")]

use gitiup_host::hosts::s3::transport;
use gitiup_host::{
    BlobStore, Capability, Host, HostErrorExt, HostKind, Namespace, Pack, PackFormat, PackRequest,
    RefName, RefQuery, RefStore, RefUpdate, RemoteConfig, S3Host,
};

mod support;
use support::conformance;

fn endpoint() -> String {
    std::env::var("GITIUP_S3_LIVE_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:5500".to_string())
}

fn bucket() -> String {
    std::env::var("GITIUP_S3_LIVE_BUCKET").unwrap_or_else(|_| "gitiup-live-test".to_string())
}

fn region() -> String {
    std::env::var("GITIUP_S3_LIVE_REGION").unwrap_or_else(|_| "us-east-1".to_string())
}

/// Skip (not fail) when the environment was not asked for this: the default
/// suite must stay hermetic.
fn credentials_present() -> bool {
    std::env::var_os("AWS_ACCESS_KEY_ID").is_some()
        || std::env::var_os("AWS_PROFILE").is_some()
        || std::env::var_os("AWS_WEB_IDENTITY_TOKEN_FILE").is_some()
}

/// Fresh per process run, because a live bucket keeps what last run left and a
/// create-only ref write against a leftover is a real conflict, not a bug.
fn nonce() -> u64 {
    static NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *NONCE.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.subsec_nanos() as u64)
            .unwrap_or(1);
        nanos + u64::from(std::process::id()) * 1_000_000
    })
}

/// One store per test: they run in parallel, and a shared prefix would have them
/// fighting over the same ref names (which is a real CAS conflict, not a bug).
fn remote(tag: &str) -> RemoteConfig {
    let url = format!("s3://{}/gitiup-live-{tag}-{}", bucket(), nonce());
    let remote = RemoteConfig::new("live", &url)
        .expect("a valid bucket url")
        .with_option("endpoint", endpoint())
        .with_option("region", region())
        // A literal address cannot carry a bucket subdomain, so virtual-host
        // addressing would ask DNS for `gitiup-live-test.127.0.0.1`.
        .with_option("force-path-style", "true");
    with_versioning_policy(remote)
}

/// The escape hatch for endpoints that cannot answer `GetBucketVersioning` (see
/// the module docs). Off by default: the strict path is the one being tested.
fn with_versioning_policy(remote: RemoteConfig) -> RemoteConfig {
    if std::env::var_os("GITIUP_S3_LIVE_ALLOW_UNVERSIONED").is_some() {
        remote.with_option("require-versioning", "false")
    } else {
        remote
    }
}

/// Create the bucket if it is missing and put versioning on, because that is the
/// configuration gitiup requires and `mb`+`versioning put` is what an operator
/// would type.
fn provision() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime to provision with");
    runtime.block_on(async move {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region()))
            .endpoint_url(endpoint())
            .force_path_style(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "gitiup-live-test",
            ))
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        // Already exists, already owned by us, no permissions to create: all of
        // those are fine as long as the versioning call works afterwards.
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
        Ok(())
    })
}

fn connected(tag: &str) -> Option<S3Host> {
    if !credentials_present() {
        eprintln!("skipping: no AWS credentials in the environment (see the module docs)");
        return None;
    }
    if let Err(why) = provision() {
        eprintln!("skipping: cannot provision s3://{}: {why}", bucket());
        return None;
    }
    let bucket_ref = match transport::connect(&remote(tag)) {
        Ok(bucket_ref) => bucket_ref,
        Err(err) => {
            eprintln!(
                "skipping: cannot reach {}: {err}",
                remote(tag).redacted_url()
            );
            return None;
        }
    };
    // A live bucket is a fresh bucket on every CI box, so initialise on demand.
    match S3Host::open_or_init(bucket_ref, &remote(tag)) {
        Ok(host) => Some(host),
        Err(err) => {
            eprintln!(
                "skipping: cannot open {}: {err}",
                remote(tag).redacted_url()
            );
            None
        }
    }
}

#[test]
#[ignore = "needs a live S3 endpoint (moto or MinIO); see the module docs"]
fn the_live_bucket_answers_the_transport_probe() {
    let Some(host) = connected("probe") else {
        return;
    };
    assert_eq!(host.kind(), HostKind::S3);
    let caps = host.capabilities();
    assert!(
        caps.cas,
        "this endpoint must support conditional writes: {:?}",
        host.advice()
    );
    if host.facts().versioning.protects_history() {
        assert!(caps.immutable, "{:?}", host.advice());
    } else {
        assert!(
            !caps.immutable,
            "a bucket that does not protect history may not claim immutability"
        );
    }
    assert!(!caps.atomic_multi_write, "S3 has no multi-object write");
    assert!(host.require(Capability::Cas).is_ok());
    // `describe()` names the endpoint and where credentials came from, and never
    // a secret — including the ones the test itself set.
    let shown = transport::describe(&remote("probe"));
    assert!(shown.contains(&bucket()), "{shown}");
    // The access key the test set is literally "test"; a quoted secret in this
    // string would mean describe() printed a credential value.
    assert!(
        !shown.contains('\"') && !shown.to_lowercase().contains("secret"),
        "describe() must not print credential values: {shown}"
    );
}

#[test]
#[ignore = "needs a live S3 endpoint (moto or MinIO); see the module docs"]
fn the_same_conformance_bodies_hold_over_the_real_transport() {
    // One store per body: they all write the same fixed ref names, and on a
    // bucket a leftover create-only ref is a genuine conflict, not a bug.
    type Body = fn(&dyn Host);
    let bodies: [(&str, Body); 4] = [
        ("refs", conformance::refs_round_trip),
        ("blobs", conformance::blobs_round_trip),
        ("cas", conformance::cas_conflicts_are_reported),
        ("batch", conformance::multi_ref_writes_are_all_or_nothing),
    ];
    for (tag, body) in bodies {
        let Some(host) = connected(tag) else { return };
        body(&host);
    }

    // Layout on the wire is the layout in the design note, and `list_refs` reads
    // it back through real (paged) LISTs.
    let Some(host) = connected("layout") else {
        return;
    };
    conformance::describe_and_capabilities(&host);
    let oid = host
        .put_cas(&Namespace::JOB, b"{\"job\":\"live\"}")
        .expect("store a record");
    let branch = RefName::branch("live").unwrap();
    host.update_ref_cas(&RefUpdate::create(branch.clone(), oid).with_actor("live-test"))
        .expect("publish the branch");
    let refs = host.list_refs(&RefQuery::prefix("refs/heads")).unwrap();
    assert!(
        refs.iter()
            .any(|reference| reference.name == branch && reference.oid == oid),
        "{refs:?}"
    );
    assert_eq!(
        host.ref_key(&branch),
        format!("{}/refs/heads/live", remote("layout").root_prefix())
    );

    // A pack written here is readable from another store prefix in the same
    // bucket: that is how a proposal crosses from a clone to the forge.
    let sink_remote = with_versioning_policy(
        RemoteConfig::new(
            "sink",
            &format!("s3://{}/gitiup-sink-{}", bucket(), nonce()),
        )
        .expect("a valid bucket url")
        .with_option("endpoint", endpoint())
        .with_option("region", region())
        .with_option("force-path-style", "true"),
    );
    let sink = S3Host::open_or_init(
        transport::connect(&sink_remote).expect("a second store prefix"),
        &sink_remote,
    )
    .expect("open the second store prefix");
    conformance::pack_round_trip(&host, &sink);
}

#[test]
#[ignore = "needs a live S3 endpoint (moto or MinIO); see the module docs"]
fn big_packs_use_real_multipart_uploads() {
    let Some(host) = connected("multipart") else {
        return;
    };
    // 9 MiB: over the default 8 MiB threshold, so it must go up as multipart.
    let body: Vec<u8> = (0u8..=255).cycle().take(9 * 1024 * 1024).collect();
    let pack = Pack::from_raw_objects([(Namespace::ATTESTATION, body.clone())]).unwrap();
    let oid = host
        .put_pack(&pack)
        .expect("put a 9 MiB pack over the wire");
    assert_eq!(pack.oid(), oid);
    let back = host
        .fetch_pack(&PackRequest::new([oid]))
        .expect("fetch it back");
    let records = back.raw_objects().expect("parses as a raw pack");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, body, "byte for byte, through multipart");
    assert_eq!(back.format, PackFormat::Raw);
}

#[test]
#[ignore = "needs a live S3 endpoint (moto or MinIO); see the module docs"]
fn two_clients_cannot_both_move_one_ref() {
    let Some(host) = connected("race") else {
        return;
    };
    let base = host.put_cas(&Namespace::RECORD, b"base").unwrap();
    let branch = RefName::branch("race").unwrap();
    host.update_ref_cas(&RefUpdate::create(branch.clone(), base))
        .unwrap();
    let a = host.put_cas(&Namespace::RECORD, b"a").unwrap();
    let b = host.put_cas(&Namespace::RECORD, b"b").unwrap();

    // Two independent clients, both believing they saw `base`.
    let first = S3Host::open_or_init(
        transport::connect(&remote("race")).unwrap(),
        &remote("race"),
    )
    .expect("second client");
    assert!(first.cas_ref(&branch, Some(base), a).is_ok());
    let second = S3Host::open_or_init(
        transport::connect(&remote("race")).unwrap(),
        &remote("race"),
    )
    .expect("third client");
    let err = second
        .cas_ref(&branch, Some(base), b)
        .expect_err("the ref moved and the endpoint said so");
    assert!(err.is_conflict(), "{err}");
    assert_eq!(host.get_ref(&branch).unwrap().unwrap().oid, a);
}

#[test]
#[ignore = "needs a live S3 endpoint (moto or MinIO); see the module docs"]
fn an_unversioned_bucket_is_refused_by_the_real_host_too() {
    if !credentials_present() {
        eprintln!("skipping: no AWS credentials in the environment");
        return;
    }
    let loose_url = format!("s3://{}/gitiup-unversioned-{}", loose_bucket(), nonce());
    let unversioned = RemoteConfig::new("loose", &loose_url)
        .expect("a valid bucket url")
        .with_option("endpoint", endpoint())
        .with_option("region", region())
        .with_option("force-path-style", "true");
    provision_unversioned();
    let err = match S3Host::from_remote(&unversioned) {
        Ok(host) => {
            // The only acceptable "success" is a bucket that reports versioning
            // but is not immutable — gitiup never assumes history is safe.
            assert!(
                !host.capabilities().immutable,
                "an unversioned bucket may not claim immutability"
            );
            return;
        }
        Err(err) => err,
    };
    // Either gitiup refused because versioning is off, or it refused because the
    // endpoint would not say — both are the safe answer. What must not happen is
    // a successful open that promises immutability.
    assert!(
        err.is_unsupported() || err.to_string().contains("get_bucket_versioning"),
        "unexpected refusal: {err}"
    );
    assert!(err.to_string().contains("version"), "{err}");
    // ...and the way an operator accepts it anyway.
    let accepting = RemoteConfig::new("loose", &loose_url)
        .expect("a valid bucket url")
        .with_option("endpoint", endpoint())
        .with_option("region", region())
        .with_option("force-path-style", "true")
        .with_option("require-versioning", "false");
    // The loose bucket holds no store yet, so this is the initialise path.
    let bucket_ref = transport::connect(&accepting).expect("connect the loose bucket");
    match S3Host::open_or_init(bucket_ref, &accepting) {
        Ok(host) => assert!(!host.capabilities().immutable, "no versioning, no promise"),
        Err(err) => panic!("the operator said this bucket is fine: {err}"),
    }
}

/// A second bucket, left as it was created: no versioning at all. That is the
/// configuration gitiup must refuse, so the test needs it to exist.
fn loose_bucket() -> String {
    std::env::var("GITIUP_S3_LOOSE_BUCKET").unwrap_or_else(|_| "gitiup-loose-test".to_string())
}

/// Make sure the second bucket exists with versioning *off*, which is the
/// default for a freshly created bucket on moto and MinIO alike.
fn provision_unversioned() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime to provision with");
    runtime.block_on(async move {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region()))
            .endpoint_url(endpoint())
            .force_path_style(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "gitiup-live-test",
            ))
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        let _ = client
            .create_bucket()
            .bucket(loose_bucket())
            .send()
            .await
            .ok();
    });
}

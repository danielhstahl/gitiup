//! `gitiup.toml` parsing: the four supported schemes, defaults, the store-key
//! layout every host mirrors, the credential-profile plumbing and the
//! actionable errors for everything a human gets wrong.

use std::path::Path;
use std::time::Duration;

use gitiup_host::{
    AuthModel, Host as _, HostErrorKind, Namespace, Oid, RefName, RemoteConfig, RemoteScheme,
    RemoteUrl,
};

const FULL: &str = r#"
schema-version = 1
default-remote = "origin"

[[remote]]
name = "origin"
url = "s3://gitiup-forge/my-repo"
store-prefix = "store"
credentials-profile = "owner"
timeout = "45s"

[remote.options]
region = "eu-central-1"

[[remote]]
name = "mirror"
url = "https://git.example.com/owner/repo.git"
timeout = 120

[[remote]]
name = "colo"
url = "ssh://git@build.example.net:2222/srv/git/repo.git"
credentials-profile = "deploy"

[[remote]]
name = "scratch"
url = "file:///srv/git/repo.git"

[credentials.owner]
auth = "cloud-role"

[credentials.deploy]
auth = "ssh-key"
key-path = "~/.ssh/id_ed25519"
"#;

fn parse(text: &str) -> gitiup_host::Config {
    gitiup_host::Config::parse(text, Some(Path::new("gitiup.toml")))
        .unwrap_or_else(|e| panic!("should parse: {e}"))
}

#[test]
fn every_supported_scheme_parses_with_its_parts() {
    let config = parse(FULL);
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.default_remote.as_deref(), Some("origin"));
    assert_eq!(config.remotes().len(), 4);
    assert!(config.warnings().is_empty(), "{:?}", config.warnings());

    let origin = config.remote("origin").unwrap();
    assert_eq!(origin.scheme(), RemoteScheme::S3);
    assert_eq!(origin.url.host, "gitiup-forge");
    assert_eq!(origin.url.path, "my-repo");
    assert_eq!(origin.store_prefix, "store");
    assert_eq!(origin.credentials_profile.as_deref(), Some("owner"));
    assert_eq!(origin.timeout, Duration::from_secs(45));
    assert_eq!(origin.option("region"), Some("eu-central-1"));

    let mirror = config.remote("mirror").unwrap();
    assert_eq!(mirror.scheme(), RemoteScheme::Https);
    assert_eq!(mirror.url.host, "git.example.com");
    assert_eq!(mirror.url.path, "owner/repo.git");
    assert_eq!(mirror.timeout, Duration::from_secs(120));
    assert_eq!(mirror.store_prefix, "gitiup", "default store prefix");

    let colo = config.remote("colo").unwrap();
    assert_eq!(colo.scheme(), RemoteScheme::Ssh);
    assert_eq!(colo.url.user.as_deref(), Some("git"));
    assert_eq!(colo.url.host, "build.example.net");
    assert_eq!(colo.url.port, Some(2222));
    assert_eq!(colo.url.path, "srv/git/repo.git");

    let scratch = config.remote("scratch").unwrap();
    assert_eq!(scratch.scheme(), RemoteScheme::File);
    assert_eq!(scratch.url.file_path(), Path::new("/srv/git/repo.git"));
}

#[test]
fn defaults_apply_when_omitted() {
    let config = parse("[[remote]]\nname = \"origin\"\nurl = \"file:///tmp/repo\"\n");
    let remote = config.remote("origin").unwrap();
    assert_eq!(
        remote.store_prefix,
        gitiup_host::config::DEFAULT_STORE_PREFIX
    );
    assert_eq!(remote.timeout, gitiup_host::config::DEFAULT_TIMEOUT);
    assert_eq!(remote.credentials_profile, None);
    assert!(remote.options.is_empty());
    assert_eq!(config.schema_version, gitiup_host::config::SCHEMA_VERSION);
    // A lone remote becomes the default even without default-remote.
    assert_eq!(config.default_remote().unwrap().name, "origin");
}

#[test]
fn store_keys_match_the_documented_host_layout() {
    // giti-xdw.2 promises refs/<name>, packs/<oid>.pack and kv/<kind>/<hash>
    // under the store prefix; the helpers are the single source of that shape.
    let remote = RemoteConfig::new("origin", "s3://gitiup-forge/my-repo").unwrap();
    assert_eq!(remote.root_prefix(), "my-repo/gitiup");
    assert_eq!(
        remote.ref_key(&RefName::change_head("a1b2").unwrap()),
        "my-repo/gitiup/refs/changes/a1b2/head"
    );
    let oid = Oid::from_hex("aabbccddeeff00112233445566778899aabbccdd").unwrap();
    assert_eq!(
        remote.kv_key(&Namespace::ATTESTATION, &oid),
        "my-repo/gitiup/kv/attestation/aabbccddeeff00112233445566778899aabbccdd"
    );
    assert_eq!(
        remote.pack_key(&oid),
        "my-repo/gitiup/packs/aabbccddeeff00112233445566778899aabbccdd.pack"
    );

    // A store prefix that duplicates the URL path does not double up.
    let remote = RemoteConfig::new("origin", "s3://bucket")
        .unwrap()
        .with_store_prefix("my-repo/store")
        .unwrap();
    assert_eq!(remote.root_prefix(), "my-repo/store");
    assert_eq!(remote.kv_root(), "my-repo/store/kv");
    let remote = RemoteConfig::new("origin", "s3://bucket/deep/nest")
        .unwrap()
        .with_store_prefix("/store/")
        .unwrap();
    assert_eq!(remote.root_prefix(), "deep/nest/store");
}

#[test]
fn url_query_and_options_merge() {
    let remote = RemoteConfig::new(
        "origin",
        "s3://bucket/repo?region=us-east-1&force_path_style=true",
    )
    .unwrap()
    .with_option("region", "eu-west-1");
    assert_eq!(remote.option("region"), Some("eu-west-1"), "options win");
    assert_eq!(remote.option("force_path_style"), Some("true"));
    assert_eq!(remote.option("nope"), None);
    assert_eq!(
        remote.effective_options().get("region").map(String::as_str),
        Some("eu-west-1")
    );
}

#[test]
fn scp_like_urls_are_ssh() {
    let url = RemoteUrl::parse("git@github.com:owner/repo.git").unwrap();
    assert_eq!(url.scheme, RemoteScheme::Ssh);
    assert_eq!(url.user.as_deref(), Some("git"));
    assert_eq!(url.host, "github.com");
    assert_eq!(url.path, "owner/repo.git");
    let url = RemoteUrl::parse("git@host:/srv/git/repo.git").unwrap();
    assert_eq!(url.path, "srv/git/repo.git");
}

#[test]
fn unknown_schemes_are_rejected_actionably() {
    for (uri, scheme) in [
        ("gs://bucket/repo", "gs"),
        ("git://host/repo.git", "git"),
        ("sftp://host/repo", "sftp"),
        ("git+ssh://host/repo", "git+ssh"),
        ("hub://owner/repo", "hub"),
    ] {
        let err = RemoteUrl::parse(uri).expect_err(&format!("{uri} must be rejected"));
        assert_eq!(err.kind(), HostErrorKind::SchemeUnknown, "{uri}: {err}");
        let text = err.to_string();
        for supported in ["s3", "https", "ssh", "file"] {
            assert!(text.contains(supported), "{uri}: {text}");
        }
        assert_eq!(
            match &err {
                gitiup_host::HostError::SchemeUnknown(why) => why.scheme.as_str(),
                other => panic!("{other:?}"),
            },
            scheme
        );
    }
}

#[test]
fn schemes_we_refuse_on_purpose_explain_themselves() {
    let err = RemoteUrl::parse("http://ci.example.com/repo.git").unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::SchemeUnknown);
    let hint = err.hint().unwrap_or_default();
    assert!(hint.contains("https"), "{err}");

    let err = RemoteUrl::parse("git://host/repo.git").unwrap_err();
    assert!(err.hint().unwrap_or_default().contains("ssh"), "{err}");

    let err = RemoteUrl::parse("github.com/owner/repo").unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid, "no scheme at all");
    assert!(err.hint().unwrap_or_default().contains("s3"), "{err}");
}

#[test]
fn malformed_urls_get_specific_errors() {
    for (uri, needle) in [
        ("s3://tooShortBucketNameWithUPPER/repo", "bucket"),
        ("s3:///repo", "bucket"),
        ("https://", "host"),
        ("file://", "directory"),
        ("https://host/../etc/passwd", "'..'"),
        ("ssh://host:99999/repo", "port"),
        ("s3://bucket/repo?x=1#frag", ""),
        ("", "empty"),
        ("file:///srv/git /repo", "whitespace"),
    ] {
        let result = RemoteUrl::parse(uri);
        if needle.is_empty() {
            assert!(result.is_ok(), "{uri}: {:?}", result.err());
            continue;
        }
        let err = result.expect_err(&format!("{uri} must be rejected"));
        assert!(
            err.to_string().contains(needle) || err.hint().unwrap_or_default().contains(needle),
            "{uri}: {err}"
        );
    }
}

#[test]
fn urls_redact_credentials_for_logs() {
    let url = RemoteUrl::parse("https://user:s3cr3t-token@git.example.com/o/r.git").unwrap();
    let text = url.redacted();
    assert!(!text.contains("s3cr3t-token"), "{text}");
    assert!(!text.contains("user"), "{text}");
    assert!(text.contains("git.example.com"), "{text}");
}

#[test]
fn schema_version_is_enforced() {
    let err = gitiup_host::Config::parse("schema-version = 9\n", None).unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    let text = err.to_string();
    assert!(text.contains("9"), "{text}");
    assert!(
        text.to_lowercase().contains("newer") || text.to_lowercase().contains("upgrade"),
        "a newer file must say how to proceed: {text}"
    );

    let err = gitiup_host::Config::parse("schema-version = 0\n", None).unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid);

    // Absent means version 1, which keeps hand-written files friendly.
    let config =
        gitiup_host::Config::parse("[[remote]]\nname = \"x\"\nurl = \"file:///a\"\n", None)
            .unwrap();
    assert_eq!(config.schema_version, gitiup_host::config::SCHEMA_VERSION);
}

#[test]
fn unknown_keys_are_flagged_with_the_location() {
    let err = gitiup_host::Config::parse(
        "schema-version = 1\n[[remote]]\nname = \"origin\"\nurl = \"file:///r\"\ncolour = \"red\"\n",
        Some(Path::new("gitiup.toml")),
    )
    .unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::Invalid);
    let text = err.to_string();
    assert!(text.contains("colour"), "{text}");
    assert!(text.contains("gitiup.toml"), "{text}");
}

#[test]
fn duplicate_remotes_and_dangling_references_are_errors() {
    let err = gitiup_host::Config::parse(
        "[[remote]]\nname = \"origin\"\nurl = \"file:///a\"\n[[remote]]\nname = \"origin\"\nurl = \"file:///b\"\n",
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("twice"), "{err}");

    let err = gitiup_host::Config::parse(
        "default-remote = \"nope\"\n[[remote]]\nname = \"origin\"\nurl = \"file:///a\"\n",
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("nope"), "{err}");
    assert!(err.to_string().contains("origin"), "{err}");

    let err = gitiup_host::Config::parse(
        "[[remote]]\nname = \"origin\"\nurl = \"file:///a\"\ncredentials-profile = \"ghost\"\n",
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("ghost"), "{err}");
    assert!(err.to_string().contains("not defined"), "{err}");
}

#[test]
fn timeouts_are_validated() {
    let ok = parse(
        "[[remote]]\nname = \"a\"\nurl = \"file:///a\"\ntimeout = \"250ms\"\n[[remote]]\nname = \"b\"\nurl = \"file:///b\"\ntimeout = 30\n",
    );
    assert_eq!(ok.remote("a").unwrap().timeout, Duration::from_millis(250));
    assert_eq!(ok.remote("b").unwrap().timeout, Duration::from_secs(30));

    for bad in ["\"5 parsecs\"", "\"0s\"", "\"2h\"", "0"] {
        let err = gitiup_host::Config::parse(
            &format!("[[remote]]\nname = \"a\"\nurl = \"file:///a\"\ntimeout = {bad}\n"),
            None,
        )
        .expect_err(&format!("{bad} must be rejected"));
        assert_eq!(err.kind(), HostErrorKind::Invalid, "{bad}: {err}");
    }
    assert_eq!(ok.remote("a").unwrap().timeout_ms(), 250);
}

#[test]
fn credentials_profiles_resolve_without_tokens_in_the_file() {
    let config = parse(FULL);
    let owner = config.remote("origin").unwrap();
    let creds = config.credentials_for(owner).unwrap();
    assert_eq!(creds.auth, AuthModel::CloudRole);
    assert!(!creds.has_token());
    assert!(creds.source.contains("owner"), "{}", creds.source);

    let deploy = config.remote("colo").unwrap();
    let creds = config.credentials_for(deploy).unwrap();
    assert_eq!(creds.auth, AuthModel::SshKey);
    assert_eq!(
        creds.key_path.as_deref(),
        Some(Path::new("~/.ssh/id_ed25519"))
    );

    // A token profile reads the environment, never the file.
    let config = parse(
        "[[remote]]\nname = \"origin\"\nurl = \"https://host/r.git\"\ncredentials-profile = \"ci\"\n[credentials.ci]\nauth = \"token\"\ntoken-env = \"GITIUP_IT_TEST_TOKEN\"\n",
    );
    let remote = config.remote("origin").unwrap();
    let missing = config.credentials_for(remote).unwrap_err();
    assert_eq!(missing.kind(), HostErrorKind::PermissionDenied);
    assert!(
        missing.to_string().contains("GITIUP_IT_TEST_TOKEN"),
        "{missing}"
    );

    // With the variable set, the token resolves — and stays out of Debug output.
    const SECRET: &str = "a-very-secret-token";
    // SAFETY: no other test in this binary touches this variable.
    unsafe { std::env::set_var("GITIUP_IT_TEST_TOKEN", SECRET) };
    let creds = config.credentials_for(remote).unwrap();
    assert!(creds.has_token());
    assert_eq!(creds.auth, AuthModel::Token);
    let rendered = format!("{creds:?}");
    assert!(!rendered.contains(SECRET), "Debug must not print the token");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(creds.source.contains("GITIUP_IT_TEST_TOKEN"));
    unsafe { std::env::remove_var("GITIUP_IT_TEST_TOKEN") };
}

#[test]
fn warnings_are_advice_not_errors() {
    let empty = parse("schema-version = 1\n");
    assert!(
        empty.warnings().iter().any(|w| w.contains("no [[remote]]")),
        "{:?}",
        empty.warnings()
    );

    let slow =
        parse("[[remote]]\nname = \"origin\"\nurl = \"https://host/r.git\"\ntimeout = \"20m\"\n");
    assert!(
        slow.warnings().iter().any(|w| w.contains("timeout")),
        "{:?}",
        slow.warnings()
    );

    let leaky =
        parse("[[remote]]\nname = \"origin\"\nurl = \"https://tok@git.example.com/r.git\"\n");
    assert!(
        leaky
            .warnings()
            .iter()
            .any(|w| w.contains("credentials-profile")),
        "{:?}",
        leaky.warnings()
    );
}

#[test]
fn files_round_trip_through_toml_and_json() {
    let config = parse(FULL);
    let text = config.to_toml().unwrap();
    let again = parse(&text);
    assert_eq!(again.remotes().len(), config.remotes().len());
    for (a, b) in config.remotes().iter().zip(again.remotes().iter()) {
        assert_eq!(a, b, "round trip must be lossless for {a:?}");
    }
    assert_eq!(again.default_remote, config.default_remote);
    assert_eq!(again.credentials, config.credentials);
    assert!(text.contains("s3://gitiup-forge/my-repo"), "{text}");
    assert!(text.contains("schema-version = 1"), "{text}");

    let json = config.to_json().unwrap();
    let rendered = json.to_string();
    assert!(rendered.contains("\"scheme\":\"s3\""), "{rendered}");
    assert!(rendered.contains("root_prefix"), "{rendered}");
}

#[test]
fn discovery_walks_up_and_load_writes_back() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let nested = root.join("work/checkout/src");
    std::fs::create_dir_all(&nested).unwrap();
    let file = root.join(gitiup_host::config::CONFIG_FILE_NAME);
    std::fs::write(&file, FULL).unwrap();

    let (found, config) = gitiup_host::Config::discover(&nested)
        .unwrap()
        .expect("config found by walking up");
    assert_eq!(found, file);
    assert_eq!(config.remotes().len(), 4);
    assert_eq!(config.path.as_deref(), Some(file.as_path()));

    // Nothing above an empty tree.
    let lonely = tempfile::tempdir().unwrap();
    assert!(
        gitiup_host::Config::discover(lonely.path().join("nowhere").as_path())
            .unwrap()
            .is_none()
    );

    // Editing through the API and saving re-reads cleanly.
    let mut config = config;
    config
        .add_remote(RemoteConfig::new("second", "file:///srv/second").unwrap())
        .unwrap();
    config.set_default_remote("second").unwrap();
    config.save(&file).unwrap();
    let reloaded = gitiup_host::Config::load(&file).unwrap();
    assert_eq!(
        reloaded.remote("second").unwrap().scheme(),
        RemoteScheme::File
    );
    assert_eq!(reloaded.default_remote().unwrap().name, "second");
    assert_eq!(reloaded.remotes().len(), 5);

    let removed = config.remove_remote("second").unwrap();
    assert_eq!(removed.name, "second");
    let err = reloaded.remote("missing").unwrap_err();
    assert_eq!(err.kind(), HostErrorKind::NotFound);
    assert!(err.to_string().contains("origin"), "{err}");

    // GITIUP_CONFIG wins over discovery. This is the only place in the suite
    // that touches the process environment, and it stays in one test so the
    // parallel tests never see it.
    let chosen = root.join("chosen.toml");
    std::fs::write(
        &chosen,
        "[[remote]]\nname = \"from-env\"\nurl = \"file:///srv/env\"\n",
    )
    .unwrap();
    // SAFETY: no other test in this binary mutates the environment.
    unsafe { std::env::set_var(gitiup_host::config::CONFIG_PATH_ENV, &chosen) };
    let found = gitiup_host::Config::discover(root)
        .unwrap()
        .expect("env-named config is used");
    unsafe { std::env::remove_var(gitiup_host::config::CONFIG_PATH_ENV) };
    assert_eq!(found.0, chosen);
    assert_eq!(found.1.remotes()[0].name, "from-env");
}

#[test]
fn file_remotes_wire_straight_into_the_fs_host() {
    let dir = tempfile::tempdir().unwrap();
    let remote = RemoteConfig::new("scratch", &format!("file://{}", dir.path().display())).unwrap();
    let host = gitiup_host::FsHost::from_remote(&remote).unwrap();
    assert_eq!(
        host.root().canonicalize().unwrap(),
        dir.path().canonicalize().unwrap()
    );
    assert_eq!(host.describe().name, "scratch");
    let oid = gitiup_host::BlobStore::put_cas(&host, &Namespace::RECORD, b"via remote").unwrap();
    assert!(dir.path().join("cas").exists());
    assert_eq!(
        gitiup_host::BlobStore::get(&host, &oid).unwrap().unwrap(),
        b"via remote"
    );
}

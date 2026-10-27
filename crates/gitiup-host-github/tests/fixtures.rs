//! Recorded HTTP fixtures: the same adapter, driven by a session that already
//! happened.
//!
//! `tests/fixtures/*.jsonl` files are JSON lines written by [`Recorder`] — one
//! object per call, with the method, the full URL, the request body, the status,
//! the response headers and the response body. They are the answer to the
//! acceptance question "the adapter passes the shared conformance suite against
//! recorded HTTP fixtures", and they earn their keep in four ways:
//!
//! * a failure to replay names the call the adapter made that was not recorded,
//!   which is how an unintended extra request (a missing cache, a lost `Link`
//!   header) becomes a test failure instead of a surprise in production;
//! * they prove the adapter needs nothing it does not record — no side channel, no
//!   live network, no credentials;
//! * they carry no credential and never can: a recording stores the URL and the
//!   response, never a request header, and the token is a request header;
//! * they are read offline in CI on a machine with no network at all.
//!
//! To refresh them (after an intentional change to what the adapter sends):
//!
//! ```text
//! GITIUP_RECORDED_SESSIONS=1 cargo test -p gitiup-host-github --test fixtures -- --nocapture
//! ```
//!
//! Read the diff before committing it. An adapter that suddenly makes more calls
//! is usually broken, not the fixture being stale.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use gitiup_host::{
    BlobStore, Host, HostErrorKind, Namespace, RefName, RefQuery, RefStore, RefUpdate,
    RemoteConfig, conformance,
};
use gitiup_host_github::GitHubHost;
use gitiup_host_github::testing::{Fixtures, Interaction, MockForge, Recorder};

const TOKEN_ENV: &str = "GITIUP_HOST_GITHUB_FIXTURE_TEST_TOKEN";
const TOKEN: &str = "fixture-session-token-do-not-use";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn session_file(name: &str) -> PathBuf {
    fixtures_dir().join(format!("{name}.jsonl"))
}

fn remote() -> RemoteConfig {
    // SAFETY: this variable is named for this binary; every test here sets it to
    // the same value before anything reads it.
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    let mut remote =
        RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("a github remote");
    remote
        .options
        .insert("token-env".to_string(), TOKEN_ENV.to_string());
    remote
}

/// A fresh forge with a seeded `main`, exactly as each recording started.
fn forge() -> Arc<MockForge> {
    let forge = MockForge::new();
    forge.seed_branch("main", b"# gitiup\n");
    forge
}

fn load(name: &str) -> Arc<Fixtures> {
    let path = session_file(name);
    Arc::new(
        Fixtures::load(&path).unwrap_or_else(|why| {
            panic!("{}: {why} — is the recording committed?", path.display())
        }),
    )
}

fn write_recording(name: &str, interactions: &[Interaction]) {
    std::fs::create_dir_all(fixtures_dir()).expect("the fixtures directory");
    let path = session_file(name);
    let mut file = std::fs::File::create(&path).expect("the recording is writable");
    for interaction in interactions {
        file.write_all(interaction.to_json_line().as_bytes())
            .expect("the recording is writable");
    }
    println!(
        "recorded {} calls into {}",
        interactions.len(),
        path.display()
    );
}

/// Whether the recordings should be rewritten (see the module docs).
fn recording() -> bool {
    std::env::var("GITIUP_RECORDED_SESSIONS").is_ok()
}

/// Recorded once per test binary, however many tests ask for it (they run in
/// parallel, and three writers to one file is a corrupt fixture).
static RECORD_LOCK: Mutex<()> = Mutex::new(());
static RECORDED: AtomicBool = AtomicBool::new(false);
static RECORDED_SIMPLE: AtomicBool = AtomicBool::new(false);

/// Record the shared conformance suite, one fresh forge per body.
///
/// The bodies count what they just wrote ("this store holds exactly one roster"),
/// which is why [`conformance::run_all_with`] makes a new host for each one — so
/// each body gets its own forge and its own recorder, and the recordings are
/// concatenated in body order and read back in that same order.
fn record_conformance() {
    if !recording() {
        return;
    }
    let _guard = RECORD_LOCK.lock().expect("recording is serialised");
    if RECORDED.load(Ordering::SeqCst) {
        return;
    }
    let recorders: Mutex<Vec<Recorder>> = Mutex::new(Vec::new());
    let failures = conformance::run_all_with(|| {
        let recorder = Recorder::new(forge().transport());
        recorders
            .lock()
            .expect("recorder list")
            .push(recorder.clone());
        Box::new(
            GitHubHost::with_transport(&remote(), Arc::new(recorder), None)
                .expect("the host opens over the recording transport"),
        ) as Box<dyn Host>
    });
    assert!(
        failures.is_empty(),
        "the session being recorded does not itself conform:\n{}",
        failures.join("\n")
    );
    let interactions: Vec<Interaction> = recorders
        .lock()
        .expect("recorder list")
        .iter()
        .flat_map(|recorder| recorder.interactions())
        .collect();
    write_recording("conformance", &interactions);
    RECORDED.store(true, Ordering::SeqCst);
}

fn record_roundtrip() {
    if !recording() {
        return;
    }
    let _guard = RECORD_LOCK.lock().expect("recording is serialised");
    if RECORDED_SIMPLE.load(Ordering::SeqCst) {
        return;
    }
    let recorder = Recorder::new(forge().transport());
    let host = GitHubHost::with_transport(&remote(), Arc::new(recorder.clone()), None)
        .expect("the host opens");
    write_and_read(&host);
    write_recording("roundtrip", &recorder.interactions());
    RECORDED_SIMPLE.store(true, Ordering::SeqCst);
}

#[test]
fn a_recorded_session_replays_the_shared_host_contract() {
    record_conformance();
    let fixtures = load("conformance");
    let total = fixtures.len();
    let failures = conformance::run_all_with(|| {
        let host = GitHubHost::with_transport(&remote(), fixtures.clone(), None)
            .expect("the host opens over recorded HTTP");
        Box::new(host) as Box<dyn Host>
    });
    assert!(
        failures.is_empty(),
        "the adapter does not conform when driven by recorded HTTP — either it \
         changed what it sends, or the recorded answers no longer describe a \
         conforming forge:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        fixtures.consumed(),
        total,
        "the replay stopped early: {} of {total} recorded calls were used",
        fixtures.consumed()
    );
}

#[test]
fn a_recording_names_the_call_it_cannot_answer() {
    record_conformance();
    let fixtures = load("conformance");
    let host = GitHubHost::with_transport(&remote(), fixtures.clone(), None).expect("host");
    // Drain the session, then ask for something it never contained: the answer must
    // be a refusal that names the call, not an invented empty listing.
    let _ = conformance::run_all_with(|| {
        Box::new(GitHubHost::with_transport(&remote(), fixtures.clone(), None).expect("host"))
            as Box<dyn Host>
    });
    let error = host
        .list_refs(&RefQuery::prefix("refs/never/recorded/"))
        .expect_err("the session is exhausted");
    assert_eq!(error.kind(), HostErrorKind::Unreachable, "{error}");
    let text = error.to_string();
    assert!(
        text.contains("no recorded answer") && text.contains("matching-refs"),
        "it says which call was unexpected: {text}"
    );
}

#[test]
fn a_recording_carries_no_credential_and_no_request_headers() {
    record_conformance();
    let path = session_file("conformance");
    let text = std::fs::read_to_string(&path).expect("the recorded session is committed");
    assert!(
        !text.contains(TOKEN) && !text.to_lowercase().contains("authorization"),
        "a recording that carries a credential is a leaked credential: it gets \
         committed, copied into bug reports and pasted into chat"
    );
    assert!(
        !text.to_lowercase().contains("cookie") && !text.to_lowercase().contains("bearer"),
        "{path:?}"
    );
    // And it is readable: one JSON object per line, each with what a reader needs
    // to see what the adapter asked for and what the forge answered.
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(lines.len() > 10, "a session this short proves nothing");
    for line in &lines {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("one JSON object per line");
        for key in ["method", "url", "status", "response_body"] {
            assert!(
                value.get(key).is_some(),
                "a recorded call without {key}: {line}"
            );
        }
        assert!(
            !value["url"].as_str().unwrap_or_default().contains('@'),
            "userinfo in a recorded URL would be a credential: {}",
            value["url"]
        );
    }
}

#[test]
fn a_read_back_through_recorded_http_is_the_same_bytes() {
    // A cheap end-to-end check on the codecs: what went into the forge comes out
    // again byte for byte when the forge's answers are the ones it really gave.
    record_roundtrip();
    let fixtures = load("roundtrip");
    let host = GitHubHost::with_transport(&remote(), fixtures, None).expect("host");
    write_and_read(&host);
}

fn write_and_read(host: &GitHubHost) {
    let payload = b"{\"id\":\"c1\",\"subject\":\"a recorded change\"}".to_vec();
    // The record goes first: a ref that promises a digest the store does not hold
    // is a broken promise on every host, not just this one.
    let digest = host
        .put_cas(&Namespace::CHANGE, &payload)
        .expect("store the record");
    let change_ref = RefName::change_head("c1").expect("change ref");
    host.update_ref_cas(&RefUpdate::create(change_ref.clone(), digest))
        .expect("create the change ref");
    let read = host
        .get_ref(&change_ref)
        .expect("read it back")
        .expect("it is there");
    assert_eq!(read.oid, digest, "the ref promises the digest it was given");
    assert_eq!(
        host.get(&digest).expect("read the record").as_deref(),
        Some(&payload[..]),
        "and the record comes back byte for byte"
    );
}

//! The forge, translated: pull requests become changes, check runs become
//! attestations, and the change feed needs no webhook.
//!
//! The rule this file exists to enforce is the one in the ticket: *translate, do
//! not leak*. Nowhere below does a GitHub JSON shape reach the caller, and nothing
//! above this crate has to know what a "pull request", a "check run" or a
//! `html_url` is — they are `ChangeRecord` and `AttestationRecord`, the same
//! shapes a bucket-as-forge produces.

use std::sync::Arc;

use gitiup_host::{
    Actor, BlobStore, Host, HostErrorExt, HostErrorKind, Namespace, Oid, RefName, RefStore,
    RefUpdate, RemoteConfig,
};
use gitiup_host_github::testing::MockForge;
use gitiup_host_github::{ChangeOrigin, ChangeState, GitHubHost};

const TOKEN_ENV: &str = "GITIUP_HOST_GITHUB_FORGE_TEST_TOKEN";

fn remote() -> RemoteConfig {
    // SAFETY: a name this specific belongs to this test binary alone.
    unsafe { std::env::set_var(TOKEN_ENV, "forge-test-token") };
    let mut remote =
        RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("a github remote");
    remote
        .options
        .insert("token-env".to_string(), TOKEN_ENV.to_string());
    remote
}

fn forge() -> Arc<MockForge> {
    let forge = MockForge::new();
    forge.seed_branch("main", b"# gitiup\n");
    forge
}

fn hosted(forge: &Arc<MockForge>) -> GitHubHost {
    GitHubHost::with_transport(&remote(), forge.transport(), None).expect("the host opens")
}

/// A git-shaped id for a commit the mock holds.
fn head_oid(forge: &Arc<MockForge>, branch: &str) -> Oid {
    let sha = forge
        .refs()
        .get(format!("refs/heads/{branch}").as_str())
        .unwrap_or_else(|| panic!("the mock has no branch {branch}"))
        .clone();
    Oid::from_hex(&sha).expect("the mock mints git-shaped ids")
}

#[test]
fn a_pull_request_is_a_change_not_a_pull_request() {
    let forge = forge();
    let head = forge.refs()["refs/heads/main"].clone();
    forge.open_pull(
        7,
        "Teach the host adapter to translate",
        &head,
        "2026-01-05T10:00:00Z",
    );
    let host = hosted(&forge);

    let changes = host.changes("all").expect("the change list");
    let change = changes
        .iter()
        .find(|change| change.id == "gh-7")
        .unwrap_or_else(|| panic!("the pull is in the change list: {changes:?}"));
    assert_eq!(change.title, "Teach the host adapter to translate");
    assert_eq!(change.state, ChangeState::Open);
    assert_eq!(
        change.base.as_ref().map(RefName::as_str),
        Some("refs/heads/main"),
        "the base is a ref name, not a `base.ref` string"
    );
    assert_eq!(change.head.expect("head").len(), 20, "a git-shaped digest");
    assert_eq!(
        change.origin,
        ChangeOrigin::Pull { number: 7 },
        "where a change came from is recorded, because it decides what is possible"
    );
    assert!(change.mergeable_via_forge());
    assert_eq!(
        change.author.as_deref(),
        Some("contributor"),
        "the author comes through, since a reviewer wants to know whose change it is"
    );

    // And nothing github-shaped is still attached to it.
    let rendered = format!("{change:?}");
    for leaked in ["html_url", "draft", "base", "user"] {
        assert!(
            !rendered.contains(&format!("\"{leaked}\"")),
            "the raw API document rode along into the record: {rendered}"
        );
    }
}

#[test]
fn the_pull_list_and_the_change_refs_are_one_list() {
    // A change gitiup wrote (`refs/changes/<id>/head`) and a pull request about the
    // same commit are the same change seen twice: `changes()` must show it once,
    // and prefer the one that knows more.
    let forge = forge();
    let host = hosted(&forge);
    let commit = head_oid(&forge, "main");

    // A ref with no pull request at all is still a change.
    host.update_ref_cas(
        &RefUpdate::create(RefName::change_head("77").expect("ref"), commit)
            .with_actor(Actor::new("ada").expect("actor")),
    )
    .expect("publish the change ref");
    let only_refs = host.changes("all").expect("changes");
    assert_eq!(only_refs.len(), 1, "{only_refs:?}");
    assert_eq!(only_refs[0].id, "77");
    assert_eq!(
        only_refs[0].origin,
        ChangeOrigin::Ref {
            name: "refs/changes/77/head".to_string()
        },
        "a change with no pull is still a change, and says where it lives"
    );
    assert!(
        !only_refs[0].mergeable_via_forge(),
        "with no pull there is nothing for the forge to merge; landing it is the \
         host-neutral path, exactly as on a bucket"
    );

    // Now the pull request for the same commit arrives.
    forge.open_pull(
        7,
        "the same work, proposed",
        &commit.hex(),
        "2026-01-05T10:00:00Z",
    );
    let both = host.changes("all").expect("changes");
    assert_eq!(
        both.len(),
        1,
        "the pull and the ref are the same change: {both:?}"
    );
    assert_eq!(both[0].id, "gh-7", "the pull wins: it knows the state");
    assert_eq!(both[0].origin, ChangeOrigin::Pull { number: 7 });
}
#[test]
fn opening_a_change_writes_the_ref_and_asks_the_forge_to_merge_it() {
    let forge = forge();
    let host = hosted(&forge);
    let change = host
        .open_change(
            "Add the github adapter",
            "gitiup/change-1",
            "main",
            "It translates.",
            false,
        )
        .expect("open the change");
    assert_eq!(change.state, ChangeState::Open);
    assert!(change.mergeable_via_forge());
    assert_eq!(forge.pulls().len(), 1, "the forge really was asked");
    assert!(
        host.changes("open")
            .expect("open changes")
            .iter()
            .any(|found| found.id == change.id)
    );

    // Closing it is the forge's business too — and closing is not merging.
    let number = match change.origin {
        ChangeOrigin::Pull { number } => number,
        other => panic!("a change opened through the forge has a number: {other:?}"),
    };
    host.close_change(number).expect("close");
    assert_eq!(
        host.changes("open")
            .expect("open")
            .iter()
            .filter(|found| found.id == change.id)
            .count(),
        0,
        "a closed change is out of the open list"
    );
    let closed = host
        .changes("all")
        .expect("all")
        .iter()
        .find(|found| found.id == change.id)
        .expect("still listed under all")
        .clone();
    assert_eq!(closed.state, ChangeState::Closed);
    assert!(
        !closed.mergeable_via_forge(),
        "a closed change is not a change a gate may merge"
    );
    assert!(
        closed.merged_at.is_none(),
        "closing is not merging, and reading it as a merge reports work that never \
         landed: {closed:?}"
    );
}

#[test]
fn a_change_feed_needs_no_webhook() {
    // "What is new since I last looked" is one conditional read of state that
    // already exists. There is no endpoint to register, no secret to share with the
    // forge, and no delivery to retry — so nothing here can be missed because a
    // server on someone else's network was down.
    let forge = forge();
    let host = hosted(&forge);
    let head = forge.refs()["refs/heads/main"].clone();
    forge.open_pull(1, "first", &head, "2026-01-05T10:00:00Z");
    forge.open_pull(2, "second", &head, "2026-01-05T11:00:00Z");

    let (fresh, cursor) = host.poll_changes(None).expect("first poll");
    assert_eq!(fresh.len(), 2, "a cold poll sees what is there: {fresh:?}");
    assert_eq!(cursor.highest_number, 2);
    assert!(cursor.updated_after.is_some());

    let (again, _) = host
        .poll_changes(Some(&cursor))
        .expect("poll with the cursor");
    assert!(
        again.is_empty(),
        "the same cursor must not report the same changes twice: {again:?}"
    );

    forge.open_pull(3, "third", &head, "2026-01-05T12:00:00Z");
    let (fresh, next) = host.poll_changes(Some(&cursor)).expect("third arrives");
    assert_eq!(
        fresh
            .iter()
            .map(|change| change.id.clone())
            .collect::<Vec<_>>(),
        vec!["gh-3".to_string()],
        "exactly the new one"
    );
    assert_eq!(next.highest_number, 3);
}

#[test]
fn a_check_run_is_an_attestation() {
    let forge = forge();
    let host = hosted(&forge);
    let subject = head_oid(&forge, "main");
    let bytes = b"signed-quorum-blob".to_vec();
    let published = host
        .publish_attestation(&subject, &bytes, Some("https://ci.example/job/1"))
        .expect("publish");

    assert_eq!(
        published.digest,
        Oid::hash_bytes(&bytes),
        "the digest is the point"
    );
    assert_eq!(published.subject, subject);
    assert!(
        published.verbatim(),
        "a publish that cannot be read back byte for byte has published nothing"
    );

    // The forge was told as well, so a stranger browsing the commit sees it.
    let runs = forge.check_runs();
    assert_eq!(runs.len(), 1, "one check run published: {runs:?}");
    assert_eq!(runs[0]["head_sha"], serde_json::json!(subject.hex()));
    assert_eq!(runs[0]["conclusion"], serde_json::json!("success"));

    // And reading it back goes through a second host with nothing cached, which is
    // the only reader that matters: a different process, later.
    let reader = hosted(&forge);
    let found = reader.attestations_for(&subject).expect("attestations");
    assert_eq!(
        found.len(),
        1,
        "the store's copy and the check run's are one attestation, not two: {found:?}"
    );
    assert_eq!(found[0].bytes.as_deref(), Some(&bytes[..]));
    assert_eq!(found[0].digest, published.digest);
    assert_eq!(
        found[0].source,
        gitiup_host_github::AttestationSource::Both,
        "found by the forge's advertisement *and* read back verbatim from the store"
    );
}

#[test]
fn an_attestation_only_the_check_run_has_is_reported_as_such() {
    // The case the translation earns its keep for: a runner published a check run
    // but never got store access. The gate must be able to see that it is looking
    // at a copy, not at the thing a signature covers.
    let forge = forge();
    let host = hosted(&forge);
    let subject = head_oid(&forge, "main");
    let bytes = b"check-run-only-attestation-payload".to_vec();
    forge.publish_check_run_only(&subject, &bytes, true);

    let found = host.attestations_for(&subject).expect("attestations");
    let record = found
        .first()
        .unwrap_or_else(|| panic!("the check run alone is still reported: {found:?}"));
    assert_eq!(
        record.digest,
        Oid::hash_bytes(&bytes),
        "the digest is still the promise"
    );
    assert!(record.copy_truncated, "and it says the copy is cut short");
    assert!(
        !record.verbatim(),
        "a truncated copy is never the thing a signature covers"
    );
    assert_eq!(
        record.source,
        gitiup_host_github::AttestationSource::CheckRun,
        "and it says where it came from"
    );
    if let Some(copy) = record.bytes.as_deref() {
        assert!(
            copy.len() < bytes.len(),
            "the copy is a piece of it, and the record admits it"
        );
    }
    assert_eq!(
        found.iter().filter(|record| record.verbatim()).count(),
        0,
        "nothing here may be used as proof"
    );
}

#[test]
fn an_attestation_ref_is_the_same_mechanism_any_host_uses() {
    // Nothing about the attestation path is github-specific: it is
    // `refs/attestations/<subject>/<digest>` pointing at a record, exactly as on the
    // bucket host, filed by the same `gitiup_host::attest::publish` call.
    let forge = forge();
    let host = hosted(&forge);
    let subject = head_oid(&forge, "main");
    let bytes = b"quorum".to_vec();
    host.publish_attestation(&subject, &bytes, None)
        .expect("publish");
    let digest = Oid::hash_bytes(&bytes);
    assert_eq!(
        host.get(&digest).expect("read the store").as_deref(),
        Some(&bytes[..]),
        "the bytes live in the content-addressed store like any other record"
    );
    // `refs/attestations/<subject>/<digest>` — the same key the `fs` and bucket
    // hosts use, so a fetch of the ref carries the proof on any host, and a second
    // proof about the same commit has somewhere to go.
    let attestation_ref = gitiup_host::attest::ref_name(&subject, &digest);
    let read = host
        .get_ref(&attestation_ref)
        .expect("read the ref")
        .expect("the ref is there");
    assert_eq!(read.oid, digest);
    assert!(
        attestation_ref.as_str().starts_with("refs/attestations/")
            && attestation_ref.as_str().contains(&format!("{subject}/")),
        "{attestation_ref}"
    );
    // …and the shared listing reads it back as one of the commit's proofs, which is
    // what `gitiup attest list --commit` runs.
    let catalog = gitiup_host::attest::list_for(&host, &subject).expect("list");
    assert!(
        catalog.unexpected.is_empty(),
        "a proof this host filed is not a surprise to its own listing: {:?}",
        catalog.unexpected
    );
    assert_eq!(catalog.entries.len(), 1);
    assert_eq!(catalog.entries[0].digest, digest);
    assert!(!catalog.entries[0].legacy);
}

#[test]
fn a_second_proof_about_one_commit_sits_beside_the_first() {
    // The one-attestation-per-commit shape had to go for exactly this: two signers,
    // two runs or two tiers about one commit are the normal case, and neither may
    // overwrite the other.
    let forge = forge();
    let host = hosted(&forge);
    let subject = head_oid(&forge, "main");
    let first = b"signed by the proposer".to_vec();
    let second = b"signed by the owner".to_vec();
    host.publish_attestation(&subject, &first, None)
        .expect("publish the first");
    host.publish_attestation(&subject, &second, None)
        .expect("publish the second");
    let found = host.attestations_for(&subject).expect("read them back");
    let digests: Vec<String> = found
        .iter()
        .filter(|record| record.verbatim())
        .map(|record| record.digest.hex())
        .collect();
    for wanted in [Oid::hash_bytes(&first), Oid::hash_bytes(&second)] {
        assert!(
            digests.contains(&wanted.hex()),
            "{} is missing from {digests:?}",
            wanted.short_default()
        );
    }
    // …and publishing the same bytes twice is not a second proof.
    let again = host
        .publish_attestation(&subject, &first, None)
        .expect("re-publishing is not an error");
    assert_eq!(again.digest, Oid::hash_bytes(&first));
    assert_eq!(
        host.attestations_for(&subject)
            .expect("read them back again")
            .iter()
            .filter(|record| record.verbatim())
            .count(),
        2,
        "the same bytes are one proof, not two"
    );
}

#[test]
fn a_legacy_single_level_proof_is_still_read_by_the_host_that_filed_it() {
    // Old gitiup filed `refs/attestations/<subject>` -> digest. The bytes and the
    // ref are both real, so refusing to read them because of the spelling would lose
    // proofs a merge gate already relied on.
    let forge = forge();
    let host = hosted(&forge);
    let subject = head_oid(&forge, "main");
    let bytes = b"filed by an older build".to_vec();
    let digest = Oid::hash_bytes(&bytes);
    host.put_cas(&gitiup_host::Namespace::ATTESTATION, &bytes)
        .expect("store the bytes");
    host.update_ref_cas(&gitiup_host::RefUpdate::create(
        gitiup_host::attest::legacy_ref_name(&subject),
        digest,
    ))
    .expect("the legacy ref");
    let found = host.attestations_for(&subject).expect("read them back");
    assert!(
        found
            .iter()
            .any(|record| record.digest == digest && record.verbatim()),
        "the legacy proof is found by subject: {:?}",
        found
            .iter()
            .map(|record| (record.digest.hex(), record.verbatim()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_forge_remote_without_the_adapter_names_the_feature() {
    // The refusal a build without `hosts-github` must produce: it says which flag
    // to turn on, and it is the same shape as an unknown scheme, because to core
    // that is exactly what it is.
    let remote = RemoteConfig::new("origin", "https://github.com/gitiup/mock").expect("remote");
    let error = gitiup_host_github::forge_without_adapter(&remote);
    assert_eq!(error.kind(), HostErrorKind::SchemeUnknown);
    let text = error.to_string();
    assert!(text.contains("hosts-github"), "{text}");
    assert!(
        text.contains("--features"),
        "and it says how to get it: {text}"
    );
    assert!(error.is_unreachable() || text.contains("github"), "{text}");
}

#[test]
fn the_forge_merges_its_own_change_and_says_where_it_landed() {
    // ADR-0003 D10: on a forge the forge's merge *is* the merge. The adapter asks for it
    // and then reports only what the forge said — a state, a commit, a branch — because a
    // ref write here would be an imitation of a thing that is atomic and reviewed.
    let forge = forge();
    let host = hosted(&forge);
    let head = forge.refs()["refs/heads/main"].clone();
    forge.open_pull(7, "Teach the adapter to ask", &head, "2026-01-05T10:00:00Z");

    let merged = host
        .merge_change(7, &head_oid(&forge, "main"), "ff")
        .expect("the forge merged");
    assert_eq!(merged.state, ChangeState::Merged, "the forge's own answer");
    assert_eq!(
        merged.landed,
        Some(head_oid(&forge, "main")),
        "and the commit it put on the branch, which for a fast-forward is the head"
    );
    assert_eq!(merged.branch.as_deref(), Some("main"));
    assert_eq!(
        forge.refs()["refs/heads/main"],
        head,
        "the branch really moved: that is the fact the merge record will state"
    );
    let change = host
        .changes("all")
        .expect("changes")
        .into_iter()
        .find(|change| change.id == "gh-7")
        .expect("the pull is still listed");
    assert_eq!(
        change.state,
        ChangeState::Merged,
        "and the change is merged as a state the forge reports, not one gitiup asserted"
    );
}

#[test]
fn a_forge_that_will_not_merge_is_refused_rather_than_worked_around() {
    let forge = forge();
    let host = hosted(&forge);
    let head = head_oid(&forge, "main");
    forge.open_pull(
        7,
        "Teach the adapter to ask",
        &head.hex(),
        "2026-01-05T10:00:00Z",
    );

    // The forge re-checks the commit the caller believes is being merged. Naming the wrong
    // one is the forge's own compare-and-swap failing, and it is a refusal: 409.
    let other = {
        let mut hex = head.hex().to_string();
        hex.pop();
        hex.push(if hex.ends_with('a') { 'b' } else { 'a' });
        Oid::from_hex(&hex).expect("a same-shaped oid")
    };
    let stale = host
        .merge_change(7, &other, "ff")
        .expect_err("the forge will not merge a commit it does not have on top");
    assert_eq!(stale.exit_code(), 6, "{stale}");
    assert!(
        stale.to_string().contains("head") || stale.to_string().contains("conflict"),
        "and it says what the forge said: {stale}"
    );

    // Merged once, not mergeable twice: the forge's refusal survives as a refusal, in the
    // forge's words, rather than becoming a success or a silent no-op.
    host.merge_change(7, &head, "ff").expect("the merge");
    let twice = host
        .merge_change(7, &head, "ff")
        .expect_err("a merged pull is not mergeable");
    assert_eq!(twice.exit_code(), 6, "{twice}");
    assert!(
        twice.to_string().contains("will not merge pull 7"),
        "the forge's own sentence, not a rewrite: {twice}"
    );
}

#[allow(dead_code)]
fn unused(_: &dyn BlobStore, _: &Namespace, _: &dyn Host) {}

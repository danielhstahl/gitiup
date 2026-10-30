//! The published policy, measured against a store: publish it, read it back the way a
//! clone does, and refuse every way a transport can lose it (giti-91m).
//!
//! [`gitiup_quorum::policy`] already knows how to write a policy, and
//! `gitiup-quorum`'s own test files (`policy_store`, `policy_vectors`) prove the format
//! and the store semantics against the `fs` host. What those files cannot do is answer
//! the question this crate exists for — *do all the hosts answer it the same way?* —
//! because each of them is written against one host. That is not pedantry here: the epic
//! this file belongs to makes a claim about a **stranger with a fresh clone**, and a
//! stranger with a fresh clone is exactly a reader on a transport the publisher did not
//! choose. "A policy is readable from the store itself" is worth nothing on a host where
//! it is readable only from a directory.
//!
//! So everything here is written once, against `&dyn Host`, and run against every
//! registration: the bucket that cannot return the bytes its own ref names, the plain-git
//! host whose policy refs are pointer commits that must arrive in the same packfile as
//! the bytes, the forge that quietly accepts a ref write it cannot later list — each of
//! them fails a named body here instead of failing someone's merge gate.
//!
//! # What a body insists on
//!
//! The claim is ADR-0004 D7 read as a host contract:
//!
//! * **bytes then refs** — after a publish, every policy ref the store advertises names a
//!   blob the store can return, byte for byte, and the blob hashes to the name it is filed
//!   under. That invariant is what makes a torn publication impossible, and it is the one
//!   thing a transport can break by being asynchronous;
//! * **one read path** — `current`, the history glob, and the chain walk down `previous_
//!   digest` all work through the same calls the CLI makes, with the same digests;
//! * **the clock, not the listing** — the revision in force at a timestamp is answered
//!   from bytes already fetched, so a clone with one fetch can judge a year-old run;
//! * **refusals that write nothing** — a publish that is refused must leave the store
//!   exactly as it was, on a host where "exactly as it was" is a statement about a push
//!   that never happened and an object that never landed.

use std::collections::BTreeSet;

use gitiup_attest::{PolicyFile, SigningKey, TimeUs, Trust};
use gitiup_host::{Host, HostInfo, Namespace, Oid, RefName, RefQuery};
use gitiup_quorum::policy::{
    self, Context, GENESIS_PREVIOUS, PolicyDocument, PolicyError, PolicyOwner, Published, Source,
    token,
};

use crate::changes::fixture_key;

/// The clock every policy here is signed against, so two runs produce the same bytes and
/// a digest comparison means something.
///
/// The same instant the ADR-0004 vectors and [`docs/policy.md`](../../../docs/policy.md)
/// are pinned to: a digest that drifts between this file and the page is the failure mode
/// this epic exists to prevent, so there is one clock.
const CLOCK_US: i64 = 1_793_092_800_000_000;
/// One hour and one day, for the chain's effective-from spacing and the walk's probes.
const HOUR: i64 = 3_600_000_000;
const DAY: i64 = 24 * HOUR;
/// Revision 1 took effect a month ago; revision 2, an hour ago.
const FROM_1: i64 = CLOCK_US - 30 * DAY;
const FROM_2: i64 = CLOCK_US - HOUR;
/// A run made ten days ago: judged by revision 1, whatever is current now.
const RUN_LONG_AGO: i64 = CLOCK_US - 10 * DAY;
/// A run made before there was any policy at all.
const RUN_BEFORE: i64 = CLOCK_US - 60 * DAY;

/// The key a policy's `trust_key_ids` names: the runner that signs proofs.
///
/// Named deliberately, because the distinction is the one the page says trips everyone
/// once: this key signs *proofs*, and the owner's key signs the *rules*. They are
/// different keys here on purpose, so a body that confused them would fail.
fn runner() -> SigningKey {
    fixture_key("ci-runner")
}

/// The smallest rules block that is a policy: one tier, one anchor.
fn rules() -> PolicyFile {
    PolicyFile::from_json(&format!(
        "{{\"allowed_tiers\": [\"local\"], \"trust_key_ids\": [\"{}\"]}}",
        runner().public_key().key_id()
    ))
    .expect("a minimal rule set")
}

/// Whose signature this reader will act on (D3: local configuration, never the document).
fn trust_of(keys: &[&SigningKey]) -> Trust {
    Trust::KeyIds(
        keys.iter()
            .map(|key| key.public_key().key_id())
            .collect::<BTreeSet<String>>(),
    )
}

/// The `owner` block for a fixture identity. `principal` is display only, which is why it
/// is derived from the label and never checked.
fn owner_block(who: &str) -> PolicyOwner {
    PolicyOwner {
        key_id: fixture_key(who).public_key().key_id(),
        principal: format!("{who} at example.org"),
    }
}

/// Build and sign a policy at one chain position, the way `gitiup policy publish` does:
/// normalise, then sign.
///
/// One builder for every body, because a document that is only *nearly* well formed would
/// be refused by the validator before the store ever saw it, and the body would then be
/// measuring the format rather than the host.
pub fn document(
    owner: &str,
    revision: u32,
    previous_digest: &str,
    effective_from_us: i64,
) -> PolicyDocument {
    let mut document = policy::NewPolicy {
        owner: owner_block(owner),
        protects: vec!["refs/heads/**".to_string()],
        rules: rules(),
        quorum: None,
        effective_from_us,
        expires_at_us: None,
        annotations: None,
        revision,
        previous_digest: previous_digest.to_string(),
    }
    .build();
    policy::normalise_document(&mut document);
    document.sign(&fixture_key(owner)).expect("a policy signs");
    document
}

/// The predecessor `current` advertises, or [`GENESIS_PREVIOUS`] for a store with none.
///
/// Read the way a publisher reads it — position, not trust — so a body can chain a second
/// revision without assuming what the first one's digest turned out to be.
pub fn current_body_digest(host: &dyn Host) -> String {
    policy::current_position(host, TimeUs(CLOCK_US))
        .expect("the store can say what it advertises")
        .map(|existing| existing.body_digest().expect("a body digest"))
        .unwrap_or_else(|| GENESIS_PREVIOUS.to_string())
}

/// Publish one revision as its owner, and report what the store said.
pub fn publish(
    host: &dyn Host,
    owner: &str,
    revision: u32,
    effective_from_us: i64,
) -> Result<Published, PolicyError> {
    let roots = trust_of(&[&fixture_key(owner)]);
    let document = document(
        owner,
        revision,
        &current_body_digest(host),
        effective_from_us,
    );
    policy::publish(
        host,
        &document,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
}

/// Every ref under `refs/gitiup/policy/**`, sorted: the store's whole policy surface.
///
/// Sorted here rather than trusted from the host because listing order is another body's
/// claim (`listings_are_complete_across_pages`); what this file is asserting is *which*
/// refs a publication owes.
fn policy_refs(host: &dyn Host) -> Vec<String> {
    let mut refs: Vec<String> = host
        .list_refs(&RefQuery::prefix("refs/gitiup/policy"))
        .expect("listing policy refs")
        .into_iter()
        .map(|reference| reference.name.as_str().to_string())
        .collect();
    refs.sort();
    refs
}

/// Every policy object the store holds, sorted by digest.
fn policy_blobs(host: &dyn Host) -> Vec<String> {
    let mut blobs: Vec<String> = host
        .list(&Namespace::POLICY)
        .expect("listing policy blobs")
        .into_iter()
        .map(|entry| entry.oid.hex())
        .collect();
    blobs.sort();
    blobs
}

/// Read `reference` and hand back the blob it names, insisting the store can answer.
///
/// This is the invariant D7 exists for — *a ref naming bytes the store cannot return is
/// the one state a reader cannot repair* — and it is the one a transport can break out
/// from under the code: a push that carried the pointer commit but not the blob, a bucket
/// whose listing lagged its write, a forge that answered its own ref with a 404.
fn blob_behind(host: &dyn Host, reference: &str) -> (Oid, Vec<u8>) {
    let name = RefName::new(reference).expect("a policy ref name");
    let oid = host
        .get_ref(&name)
        .expect("reading a policy ref")
        .unwrap_or_else(|| panic!("{reference} should exist"))
        .oid;
    let bytes = host
        .get(&oid)
        .expect("fetching a policy blob")
        .unwrap_or_else(|| {
            panic!(
                "{reference} names {} and the store cannot return those bytes",
                oid.hex()
            )
        });
    (oid, bytes)
}

fn describe(host: &dyn Host) -> String {
    let info: HostInfo = host.describe();
    format!("{} host [{}]", info.kind, info.summary_line())
}

/// Publish, read back, walk, and refuse — the whole read path, on every host.
///
/// This is the body the epic's first sentence is about: *"a clone can read, from the store
/// itself, what will be demanded of a change."* Every step is the library's own read path
/// — the one `gitiup policy show` and `gitiup verify change` walk — so a host that passes
/// here is a host a stranger can actually ask.
pub fn workflow(host: &dyn Host) {
    let here = describe(host);
    let ada = fixture_key("ada");
    let roots = trust_of(&[&ada]);
    let ctx = Context::new(&roots, TimeUs(CLOCK_US));

    // ---- nothing published yet -----------------------------------------------------
    // A gate with nothing to rest on refuses, and says which token it refused with. This
    // is the state a fresh clone meets first, and "no answer" must not be readable as
    // "no rules".
    assert_eq!(
        policy::current_oid(host).expect("an empty store answers"),
        None,
        "{here}: a store nobody has published into says so"
    );
    let missing = policy::resolve_store_at(
        host,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("nothing is published, so a gate refuses");
    assert_eq!(
        missing.token,
        token::NO_POLICY_PUBLISHED,
        "{here}: an unpublished store is refused by name, not defaulted"
    );
    assert_eq!(missing.exit_code(), 6);

    // ---- revision 1 ----------------------------------------------------------------
    let first = document("ada", 1, GENESIS_PREVIOUS, FROM_1);
    let body_1 = first.body_digest().expect("a body digest");
    let record_1 = first.record_digest().expect("a record digest");
    let hex_1 = record_1
        .split_once(':')
        .expect("a sha256 digest")
        .1
        .to_string();
    let published = policy::publish(host, &first, &ctx, None)
        .unwrap_or_else(|e| panic!("{here}: publishing revision 1: {}", e.detail));
    assert_eq!(published.revision, 1);
    assert_eq!(published.body_digest, body_1);
    assert_eq!(published.record_digest, record_1);
    assert_eq!(published.kv, format!("kv/policy/{hex_1}"));
    assert_eq!(published.previous_body_digest, None, "genesis");
    assert!(!published.already, "the store had never seen it");

    // D7's four writes, in D7's order, and the bytes are the bytes.
    let oid_1 = Oid::from_hex(&hex_1).expect("a usable oid");
    assert_eq!(
        host.get(&oid_1).expect("the store can answer its own key"),
        Some(first.canonical_bytes().expect("canonical bytes")),
        "{here}: a published policy comes back byte for byte"
    );
    assert_eq!(
        blob_behind(host, "refs/gitiup/policy/current").0,
        oid_1,
        "{here}: `current` advertises what was published"
    );
    assert_eq!(
        blob_behind(host, "refs/gitiup/policy/history/000001").0,
        oid_1,
        "{here}: the revision is advertised create-only, so one fetch carries the chain"
    );
    assert_eq!(
        policy_refs(host),
        vec![
            "refs/gitiup/policy/current".to_string(),
            "refs/gitiup/policy/history/000001".to_string()
        ],
        "{here}: a publish writes two refs and no other"
    );
    assert_eq!(
        policy_blobs(host).len(),
        1,
        "{here}: one publish, one object"
    );

    // Re-publishing exactly what the store advertises is an idempotent success — the
    // retry a network drop deserves, and not a second revision.
    let again = policy::publish(host, &first, &ctx, None)
        .unwrap_or_else(|e| panic!("{here}: re-publishing must be idempotent: {}", e.detail));
    assert!(again.already, "{here}: the store already held exactly this");
    assert_eq!(
        policy_refs(host),
        vec![
            "refs/gitiup/policy/current".to_string(),
            "refs/gitiup/policy/history/000001".to_string()
        ],
        "{here}: an idempotent publish wrote nothing"
    );

    // What a reader learns, with nothing but the store and its own trust roots.
    let shown = policy::resolve_store_at(
        host,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .unwrap_or_else(|e| panic!("{here}: reading the policy back: {}", e.detail));
    assert_eq!(shown.provenance.source, Some(Source::Store));
    assert!(
        shown.gate_eligible(),
        "{here}: the store is a source a merge may rest on"
    );
    assert_eq!(
        shown.citation(),
        Some(body_1.as_str()),
        "a verdict cites the body"
    );
    assert_eq!(shown.provenance.revision, Some(1));
    assert_eq!(
        shown.provenance.record_digest.as_deref(),
        Some(record_1.as_str())
    );
    assert_eq!(
        shown.provenance.signed_by.as_deref(),
        Some(ada.public_key().key_id().as_str())
    );

    // ---- revision 2 ----------------------------------------------------------------
    // The same repository grown up: a new signed document, `previous_digest` naming
    // revision 1, the old one still in the store and still readable.
    let second = document("ada", 2, &body_1, FROM_2);
    let body_2 = second.body_digest().expect("a body digest");
    let published = policy::publish(host, &second, &ctx, Some(&body_1))
        .unwrap_or_else(|e| panic!("{here}: publishing revision 2: {}", e.detail));
    assert_eq!(published.revision, 2);
    assert_eq!(
        published.previous_body_digest.as_deref(),
        Some(body_1.as_str())
    );
    let oid_2 = Oid::from_hex(&second.record_hex().expect("a record hex")).expect("an oid");
    assert_eq!(
        blob_behind(host, "refs/gitiup/policy/current").0,
        oid_2,
        "{here}: `current` moved under compare-and-swap"
    );
    assert_eq!(
        policy_refs(host),
        vec![
            "refs/gitiup/policy/current".to_string(),
            "refs/gitiup/policy/history/000001".to_string(),
            "refs/gitiup/policy/history/000002".to_string()
        ],
        "{here}: history is never pruned, and every link is advertised"
    );
    assert_eq!(
        policy_blobs(host).len(),
        2,
        "{here}: two revisions, two objects"
    );

    // Every policy ref the store now advertises resolves to fetchable bytes — including
    // the one `current` no longer points at. On a git host this is the assertion that the
    // packfile that carried the pointer commit carried the blob too.
    for reference in policy_refs(host) {
        let (oid, bytes) = blob_behind(host, &reference);
        assert_eq!(
            gitiup_attest::Digest::sha256(&bytes).hex(),
            oid.hex(),
            "{here}: {reference} names bytes that are not those bytes"
        );
    }

    // The history glob and the chain walk: two ways for a clone to get the same two
    // documents, oldest-first for the glob and newest-first for the walk.
    let history = policy::history_policies(host, &ctx)
        .unwrap_or_else(|e| panic!("{here}: reading the history refs: {}", e.detail));
    assert_eq!(
        history
            .iter()
            .map(|document| document.revision)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "{here}: the history glob is the chain, oldest first"
    );
    let chain = policy::fetch_chain(host, &ctx)
        .unwrap_or_else(|e| panic!("{here}: walking the chain: {}", e.detail));
    assert_eq!(
        chain
            .iter()
            .map(|document| document.revision)
            .collect::<Vec<_>>(),
        vec![2, 1],
        "{here}: the walk starts at what is current"
    );

    // ---- the clock, not the listing ------------------------------------------------
    // The two clocks separate, which is the whole reason the chain exists: a run from ten
    // days ago is judged by the rules that were in force then, and the report says how far
    // it walked to get there.
    let then = policy::resolve_store_at(
        host,
        &roots,
        policy::At::run_claim(TimeUs(RUN_LONG_AGO)),
        TimeUs(CLOCK_US),
    )
    .unwrap_or_else(|e| panic!("{here}: judging an old run: {}", e.detail));
    assert_eq!(then.provenance.revision, Some(1));
    assert_eq!(then.citation(), Some(body_1.as_str()));
    assert_eq!(
        then.provenance.notes.first().map(String::as_str),
        Some("the chain was walked 2 links to revision 1"),
        "{here}: and the answer says how it was reached"
    );
    let now = policy::resolve_store_at(
        host,
        &roots,
        policy::At::run_claim(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .unwrap_or_else(|e| panic!("{here}: judging today's run: {}", e.detail));
    assert_eq!(now.provenance.revision, Some(2));
    assert_eq!(now.citation(), Some(body_2.as_str()));
    assert!(now.provenance.notes.is_empty(), "no walk, no note");

    // Before the first policy there were no rules, and the honest answer is a refusal —
    // the same token on every transport, because it is a statement about the chain and not
    // about the store that held it.
    let before = policy::resolve_store_at(
        host,
        &roots,
        policy::At::run_claim(TimeUs(RUN_BEFORE)),
        TimeUs(CLOCK_US),
    )
    .expect_err("a run from before the first policy has no rules to be judged by");
    assert_eq!(before.token, token::POLICY_HISTORY_MISSING, "{here}");
    assert_eq!(before.exit_code(), 6);

    // ---- trust is the reader's, not the store's ------------------------------------
    // A clone that does not know Ada gets a refusal, not the rules anyway. This is the
    // inheritance mechanism, and it is a property of the bytes rather than of the
    // transport — but say it on every transport, because the one that "helpfully"
    // re-served a policy is the one this catches.
    let stranger = policy::resolve_store_at(
        host,
        &trust_of(&[&fixture_key("sofia")]),
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("a signer nobody trusts is not a policy");
    assert_eq!(stranger.token, token::SIGNER_UNTRUSTED, "{here}");
    assert_eq!(stranger.exit_code(), 6);
    assert_eq!(
        policy::current_oid(host).expect("still there"),
        Some(oid_2),
        "{here}: a refusal read nothing up and changed nothing"
    );
}

/// A refused publish writes nothing, on every host.
///
/// The half of D7/D8 that a single-host test can only assume: that a refusal is *atomic*.
/// `gitiup policy publish` validates completely before it touches a store, and the claim
/// that follows is about the store — a refused publication leaves no object, no ref, and
/// no half-moved pointer, on a host where a write is a push, an upload, or an API call
/// rather than a `rename(2)`. A store where a failed publish left `current` pointing at
/// bytes nobody signed is a store whose merge gate is now reading garbage, and that is not
/// a state a warning recovers.
pub fn refused_publish_writes_nothing(host: &dyn Host) {
    let here = describe(host);
    let ada = fixture_key("ada");
    let roots = trust_of(&[&ada]);
    let ctx = Context::new(&roots, TimeUs(CLOCK_US));

    let first = document("ada", 1, GENESIS_PREVIOUS, FROM_1);
    let body_1 = first.body_digest().expect("a body digest");
    policy::publish(host, &first, &ctx, None)
        .unwrap_or_else(|e| panic!("{here}: publishing revision 1: {}", e.detail));
    let before_refs = policy_refs(host);
    let before_blobs = policy_blobs(host);
    assert_eq!(before_refs.len(), 2, "{here}: one revision, two refs");
    assert_eq!(before_blobs.len(), 1, "{here}: and one object");

    // Every refusal below is a different way for a publication to be a bad idea, chosen to
    // exercise a different check: the lost-update guard, the reader's trust, an
    // incoherence the validator refuses at write time, and a chain position that lies.
    // They are asserted as a set because the claim is not "one refusal is atomic"; it is
    // that *no* refusal leaves a trace.
    let cases: Vec<(&str, PolicyDocument, Option<String>, &str)> = vec![
        (
            "a lost update: this publish believes the wrong thing is current",
            document("ada", 2, &body_1, FROM_2),
            Some(format!("sha256:{}", "ab".repeat(32))),
            token::CHAIN_BROKEN,
        ),
        (
            "a predecessor that is not the one in force",
            document("ada", 2, &format!("sha256:{}", "cd".repeat(32)), FROM_2),
            None,
            token::CHAIN_BROKEN,
        ),
        (
            "a revision that skips its predecessor",
            document("ada", 7, &body_1, FROM_2),
            None,
            token::REVISION_GAP,
        ),
        (
            "a signature from a key this reader will not act on",
            document("sofia", 2, &body_1, FROM_2),
            None,
            token::SIGNER_UNTRUSTED,
        ),
        (
            "rules nobody can ever satisfy (`min_signatures: 0`)",
            {
                let mut document = document("ada", 2, &body_1, FROM_2);
                document.signatures.clear();
                let mut rules = rules();
                rules.min_signatures = Some(0);
                document.rules = rules;
                policy::normalise_document(&mut document);
                document.sign(&fixture_key("ada")).expect("signs");
                document
            },
            None,
            token::MIN_SIGNATURES_ZERO,
        ),
    ];
    for (what, document, claimed, expected) in cases {
        let error = policy::publish(host, &document, &ctx, claimed.as_deref())
            .expect_err(&format!("{here}: {what} must be refused"));
        assert_eq!(
            error.token, expected,
            "{here}: {what} was refused with `{}` and not `{expected}` — the token is the interface",
            error.token
        );
        assert_eq!(error.exit_code(), 6, "{here}: {what}");
        assert_eq!(
            policy_refs(host),
            before_refs,
            "{here}: {what} moved no ref"
        );
        assert_eq!(
            policy_blobs(host),
            before_blobs,
            "{here}: {what} filed no object"
        );
        // And the store still answers the question it answered before: not "partially",
        // not "error", but the policy that was really published.
        let still = policy::resolve_store_at(
            host,
            &roots,
            policy::At::now_at(TimeUs(CLOCK_US)),
            TimeUs(CLOCK_US),
        )
        .unwrap_or_else(|e| {
            panic!(
                "{here}: the store stopped answering after {what}: {}",
                e.detail
            )
        });
        assert_eq!(
            still.citation(),
            Some(body_1.as_str()),
            "{here}: {what} changed the answer"
        );
    }
}

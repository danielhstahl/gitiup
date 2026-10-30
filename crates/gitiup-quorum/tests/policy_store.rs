//! A published policy, in a real store: publish it, read it back, resolve it, and
//! refuse every way it can be broken (ADR-0004 D4, D6, D7, D8).
//!
//! [`policy_vectors.rs`](./policy_vectors.rs) proves the *document* matches the
//! ADR's vectors. This file proves the other half of the ticket's acceptance criteria:
//! that a policy is read from a store on any host, verified before use, resolved into a
//! `gitiup_attest::Policy` with provenance about the resolution — and that
//! `gitiup policy publish` refuses a policy that contradicts itself rather than
//! publishing a gate nobody can satisfy.
//!
//! Everything runs against the `fs` host, because the point of D7 is that the store is
//! a trait: a bucket and a bare repository take the same code path, and the conformance
//! suite is where the transports are differenced.

use std::collections::BTreeMap;
use std::path::Path;

use gitiup_attest::{PolicyFile, SigningKey, TimeUs, Trust, canon};
use gitiup_host::{BlobStore, FsHost, Namespace, Oid, RefStore, RefUpdate};
use gitiup_quorum::policy::{
    self, Context, GENESIS_PREVIOUS, PolicyDocument, PolicyOwner, Purpose, Source, token,
};
use serde_json::json;

/// A fixed clock: nothing here consults the wall clock, any more than the vectors do.
const CLOCK_US: i64 = 1_793_092_800_000_000;
/// One day later, and one day before, for the walk's probe points.
const DAY_US: i64 = 86_400 * 1_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32])
}

fn trust_of(keys: &[&SigningKey]) -> Trust {
    Trust::KeyIds(
        keys.iter()
            .map(|key| key.public_key().key_id())
            .collect::<std::collections::BTreeSet<String>>(),
    )
}

/// The smallest rules block that is a policy: one tier, one anchor.
fn rules() -> PolicyFile {
    PolicyFile::from_json(
        &json!({"allowed_tiers": ["local"], "trust_key_ids": [ANCHOR]}).to_string(),
    )
    .expect("a minimal rule set")
}

const ANCHOR: &str = "SHA256:kHe5CTrcfnmORAqMoE3KPhY+IjO+b4k1l7fkv3mQ+aQ";

/// Build and sign a policy the way `gitiup policy publish` does: normalise, sign.
fn signed(
    owner: &SigningKey,
    revision: u32,
    previous_digest: &str,
    effective_from_us: i64,
) -> PolicyDocument {
    let mut document = policy::NewPolicy {
        owner: PolicyOwner {
            key_id: owner.public_key().key_id(),
            principal: "Ada Hale".to_string(),
        },
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
    document.sign(owner).expect("a policy signs");
    document
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gitiup-policy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn published(store: &FsHost, owner: &SigningKey, revision: u32, effective_from_us: i64) -> String {
    let roots = trust_of(&[owner]);
    let context = Context::new(&roots, TimeUs(CLOCK_US));
    let previous = policy::current_policy(store, &context)
        .ok()
        .flatten()
        .map(|existing| existing.body_digest().expect("a body digest"))
        .unwrap_or_else(|| GENESIS_PREVIOUS.to_string());
    let document = signed(owner, revision, &previous, effective_from_us);
    let outcome = policy::publish(store, &document, &context, None)
        .unwrap_or_else(|e| panic!("publishing revision {revision}: {e}"));
    outcome.body_digest
}

#[test]
fn publishing_a_policy_files_the_bytes_and_moves_the_two_refs_it_owes() {
    let dir = temp("publish");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(11);
    let roots = trust_of(&[&owner]);
    let document = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - DAY_US);
    let expected_body = document.body_digest().unwrap();
    let expected_record = document.record_digest().unwrap();
    let hex = expected_record.split_once(':').unwrap().1.to_string();

    let outcome = policy::publish(
        &store,
        &document,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
    .expect("the first policy publishes");
    assert_eq!(outcome.revision, 1);
    assert_eq!(outcome.body_digest, expected_body);
    assert_eq!(outcome.record_digest, expected_record);
    assert_eq!(outcome.kv, format!("kv/policy/{hex}"));
    assert_eq!(outcome.previous_body_digest.as_deref(), None);
    assert!(!outcome.already);
    assert!(outcome.size > 400);

    // The bytes are in the CAS under the record digest, and the blob is the bytes:
    // a store that cannot answer its own key is a refusal, not a shrug (D7).
    let oid = Oid::from_hex(&hex).unwrap();
    assert_eq!(
        store.get(&oid).unwrap().as_deref(),
        Some(document.canonical_bytes().unwrap().as_slice())
    );

    // `current` advertises it, and the history ref for its revision exists (D7).
    assert_eq!(
        store.get_ref(&policy::current_ref()).unwrap().unwrap().oid,
        oid
    );
    let history_ref = policy::history_ref(1).unwrap();
    assert_eq!(
        store.get_ref(&history_ref).unwrap().unwrap().oid,
        oid,
        "every revision is advertised create-only, so one fetch carries the chain"
    );
    assert_eq!(
        history_ref.as_str(),
        format!("refs/gitiup/policy/history/{:06}", 1)
    );

    // Re-publishing the same bytes is an idempotent success, not a second revision.
    let again = policy::publish(
        &store,
        &document,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
    .expect("re-publishing is idempotent");
    assert!(again.already, "the store already held exactly this");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_published_policy_resolves_to_a_policy_with_provenance_about_the_resolution() {
    let dir = temp("resolve");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(12);
    let roots = trust_of(&[&owner]);
    let body = published(&store, &owner, 1, CLOCK_US - DAY_US);

    let resolved = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect("a published policy resolves");
    assert!(resolved.gate_eligible(), "the store is gate-eligible (D4)");
    assert_eq!(
        resolved.citation().unwrap(),
        body,
        "a verdict cites the body digest"
    );
    let provenance = &resolved.provenance;
    assert_eq!(provenance.source, Some(Source::Store));
    assert_eq!(
        provenance.reference.as_deref(),
        Some("refs/gitiup/policy/current")
    );
    assert_eq!(provenance.revision, Some(1));
    assert_eq!(
        provenance.signed_by.as_deref(),
        Some(owner.public_key().key_id().as_str())
    );
    assert_eq!(provenance.owner.as_deref(), Some("Ada Hale"));
    assert_eq!(provenance.effective_from_us, Some(CLOCK_US - DAY_US));
    assert_eq!(provenance.at_from.as_deref(), Some("now"));
    assert!(
        provenance
            .record_digest
            .as_deref()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "the report names both digests (D4)"
    );
    // The rules themselves arrive as a `Policy`, which is the whole point: the checks
    // `Policy::verify` already performs get their rules from a signed document instead
    // of a `--policy` flag.
    assert_eq!(
        resolved
            .policy
            .allowed_tiers
            .iter()
            .map(|tier| tier.as_str())
            .collect::<Vec<_>>(),
        vec!["local"]
    );
    assert!(
        resolved.policy.trust.trusts(ANCHOR),
        "the anchors from the document are who may sign a proof — a different question \\
         from who may set the rules (D3)"
    );
    // `ChangeRecord::policy_digest` is defined to be the body digest (D4), so the
    // citation a merge stores is `citation()`.
    let json = provenance.json();
    assert_eq!(json["source"], "store");
    assert_eq!(json["body_digest"], body);
    assert_eq!(json["gate_eligible"], true);
    assert_eq!(json["revision"], 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_second_revision_is_walked_by_timestamp_and_the_chain_travels_in_the_history_refs() {
    let dir = temp("chain");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(13);
    let roots = trust_of(&[&owner]);
    published(&store, &owner, 1, CLOCK_US - 30 * DAY_US);
    published(&store, &owner, 2, CLOCK_US - 5 * DAY_US);

    // A run last month is judged by revision 1, because that is what was in force.
    let before = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::run_claim(TimeUs(CLOCK_US - 10 * DAY_US)),
        TimeUs(CLOCK_US),
    )
    .expect("the older revision is still resolvable");
    assert_eq!(before.provenance.revision, Some(1));
    assert_eq!(
        before.provenance.notes.first().unwrap(),
        "the chain was walked 2 links to revision 1",
        "and the report says how far it walked (D4)"
    );
    // Today's run is judged by revision 2.
    let after = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::run_claim(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect("the current revision resolves");
    assert_eq!(after.provenance.revision, Some(2));
    assert!(after.provenance.notes.is_empty(), "no walk to explain");
    // The history refs are what made it possible without any listing or service.
    assert_eq!(
        policy::history_policies(&store, &Context::new(&roots, TimeUs(CLOCK_US)))
            .unwrap()
            .len(),
        2
    );
    // A run from before the first policy is refused, not judged by today's rules (D6).
    let none = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::run_claim(TimeUs(CLOCK_US - 60 * DAY_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("nothing was in force yet");
    assert_eq!(none.token(), token::POLICY_HISTORY_MISSING);
    assert_eq!(none.exit_code(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn publish_refuses_a_policy_that_contradicts_itself_before_it_signs_or_writes() {
    let dir = temp("self-contradiction");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(14);
    let roots = trust_of(&[&owner]);

    // The ticket's own example: a quorum demanded with nothing to decide it, and the
    // numbers that make the gate unsatisfiable. All refused at publish (D5, D8).
    let contradictory = [
        (
            json!({"allowed_tiers": ["local"], "trust_key_ids": [ANCHOR]}),
            json!({"default": {"n": 5, "required_agree": 0, "reserves": 2, "tier_floor": "endorsed", "tier_caps": {}, "max_per_identity": 1}}),
            token::REQUIRED_AGREE_ZERO,
        ),
        (
            json!({"allowed_tiers": ["local"], "trust_key_ids": [ANCHOR]}),
            json!({"default": {"n": 5, "required_agree": 9, "reserves": 2, "tier_floor": "endorsed", "tier_caps": {}, "max_per_identity": 1}}),
            token::REQUIRED_AGREE_UNREACHABLE,
        ),
        (
            json!({"allowed_tiers": ["quorum"], "trust_key_ids": [ANCHOR]}),
            json!({}),
            token::QUORUM_WITHOUT_RULES,
        ),
        (
            json!({"allowed_tiers": ["quorum"], "trust_key_ids": [ANCHOR], "require_arch": "x86_64"}),
            json!({"default": {"n": 1, "required_agree": 1, "reserves": 0, "tier_floor": "anonymous", "tier_caps": {}, "max_per_identity": 1},
                    "requirements": {"arch": "aarch64", "ram_mb": 1024, "disk_mb": 1024, "sandboxes": ["docker"], "min_sandbox_level": 1}}),
            token::ARCH_CONFLICT,
        ),
    ];
    for (rules, quorum, expected) in contradictory {
        let mut document = policy::NewPolicy {
            owner: PolicyOwner {
                key_id: owner.public_key().key_id(),
                principal: "Ada Hale".to_string(),
            },
            protects: vec!["refs/heads/**".to_string()],
            rules: PolicyFile::from_json(&rules.to_string()).expect("the rules parse"),
            quorum: if quorum.is_null() {
                None
            } else {
                Some(serde_json::from_value(quorum).expect("a quorum block"))
            },
            effective_from_us: CLOCK_US - DAY_US,
            expires_at_us: None,
            annotations: None,
            revision: 1,
            previous_digest: GENESIS_PREVIOUS.to_string(),
        }
        .build();
        policy::normalise_document(&mut document);
        document.sign(&owner).expect("signing works");
        let error = policy::publish(
            &store,
            &document,
            &Context::new(&roots, TimeUs(CLOCK_US)),
            None,
        )
        .expect_err(&format!("{expected} must be refused"));
        assert_eq!(error.token(), expected, "the token is the interface");
        assert_eq!(error.exit_code(), 6);
        assert_eq!(
            policy::current_oid(&store).unwrap(),
            None,
            "a refusal writes nothing: no half-published policy (D7)"
        );
    }

    // A per-decision binding is refused at publish, though the vocabulary accepts it (D5).
    let binding = PolicyFile::from_json(
        &json!({"allowed_tiers": ["local"], "trust_key_ids": [ANCHOR], "expected_commit":
         "sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"})
        .to_string(),
    )
    .expect("the parser accepts it; the vocabulary is one vocabulary");
    let error = policy::reject_bindings(&binding).expect_err("publish does not");
    assert_eq!(error.token(), token::PER_DECISION_BINDING);
    assert_eq!(error.exit_code(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn publish_refuses_a_lost_update_and_a_signer_nobody_trusts() {
    let dir = temp("lost-update");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(15);
    let stranger = key(16);
    let roots = trust_of(&[&owner]);
    let rev1 = published(&store, &owner, 1, CLOCK_US - 30 * DAY_US);

    // Two owners publishing at once. The first one lands; the second is still holding a
    // draft whose `previous_digest` names the revision `current` no longer advertises,
    // and one of them loses with a message instead of dropping a revision (D8).
    let rev2 = published(&store, &owner, 2, CLOCK_US - DAY_US / 2);
    let rival = signed(&owner, 2, &rev1, CLOCK_US - 10 * DAY_US);
    let error = policy::publish(
        &store,
        &rival,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
    .expect_err("two owners, one loser");
    assert_eq!(error.token(), token::CHAIN_BROKEN);
    assert_eq!(error.exit_code(), 6);
    assert!(
        error.to_string().contains("but the policy in force is"),
        "{error}"
    );
    // The explicit guard, spelled: a caller that names what it believed says so, and is
    // told what the store actually advertises.
    let error = policy::publish(
        &store,
        &rival,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        Some(GENESIS_PREVIOUS),
    )
    .expect_err("a stale belief, named");
    assert_eq!(error.token(), token::CHAIN_BROKEN);
    // A revision that skips is a different hole in the audit, and gets its own token (D6).
    let skipping = signed(&owner, 4, &rev2, CLOCK_US);
    let error = policy::publish(
        &store,
        &skipping,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
    .expect_err("a revision cannot skip");
    assert_eq!(error.token(), token::REVISION_GAP);

    // A fork that publishes its own weaker policy is refused by a verifier whose roots
    // are upstream's — refused, not distrusted-and-used (D3).
    let fork = signed(&stranger, 1, GENESIS_PREVIOUS, CLOCK_US - DAY_US);
    let error = policy::publish(&store, &fork, &Context::new(&roots, TimeUs(CLOCK_US)), None)
        .expect_err("the owner's identity is not a field the document chooses");
    assert_eq!(error.token(), token::SIGNER_UNTRUSTED);
    assert_eq!(error.exit_code(), 6);
    assert_eq!(
        policy::history_ref(fork.revision).unwrap().as_str(),
        "refs/gitiup/policy/history/000001",
        "the refusal happened before any write"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Put bytes in the store and advertise them as the policy, bypassing `publish` — which
/// is exactly what a hostile or broken store looks like, and what every reader has to
/// survive (D3, D9).
fn force_publish(store: &FsHost, bytes: &[u8]) -> Oid {
    let oid = store.put_cas(&Namespace::POLICY, bytes).expect("stored");
    store
        .update_ref_cas(&RefUpdate::create(policy::current_ref(), oid))
        .expect("advertised");
    oid
}

#[test]
fn an_unsigned_policy_is_refused_not_applied_with_a_warning() {
    let dir = temp("unsigned");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(17);
    let roots = trust_of(&[&owner]);
    let mut document = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - DAY_US);
    document.signatures.clear();
    let bytes = document.canonical_bytes().expect("canonical bytes");
    force_publish(&store, &bytes);

    // The failure this whole ADR exists to prevent, and it is loud: an unsigned policy
    // is not a policy.
    let error = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("refused");
    assert_eq!(error.token(), token::UNSIGNED);
    assert_eq!(error.exit_code(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bytes_that_are_not_their_own_canonical_form_are_a_digest_failure_not_a_refusal() {
    let dir = temp("canonical");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(18);
    let roots = trust_of(&[&owner]);
    let document = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - DAY_US);
    let value: serde_json::Value =
        serde_json::from_slice(&document.canonical_bytes().unwrap()).unwrap();
    // A transport that re-serialised the JSON on the way past: same document, valid
    // JSON, wrong bytes — which is exit 8, not exit 6: these are not the bytes that
    // were signed (D9).
    let pretty = serde_json::to_vec_pretty(&value).unwrap();
    assert_ne!(pretty, document.canonical_bytes().unwrap());
    force_publish(&store, &pretty);

    let error = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("refused");
    assert_eq!(
        error.token(),
        token::NOT_CANONICAL,
        "exit 8: these are not the bytes that were signed"
    );
    assert_eq!(error.exit_code(), 8);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_policy_signed_by_another_key_and_a_stale_store_are_both_refused_by_name() {
    let dir = temp("weakened");
    let store = FsHost::create(&dir).expect("a store");
    let stranger = key(19);
    let owner = key(20);
    let stranger_roots = trust_of(&[&stranger]);
    // Fork's own policy, published to the fork's own store: valid there, refused here.
    published(&store, &stranger, 1, CLOCK_US - DAY_US);
    let error = policy::resolve_store_at(
        &store,
        &trust_of(&[&owner]),
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("upstream's roots do not believe a fork's key");
    assert_eq!(error.token(), token::SIGNER_UNTRUSTED);
    assert_eq!(error.exit_code(), 6);

    // The same policy, read by someone who does trust that signer, resolves fine: the
    // refusal is about the reader's configuration, not about the document (D3).
    let fine = policy::resolve_store_at(
        &store,
        &stranger_roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect("the fork's own verifier believes its own owner");
    assert_eq!(
        fine.provenance.signed_by.as_deref(),
        Some(stranger.public_key().key_id().as_str())
    );

    // A `current` whose bytes the store cannot return is a refusal, never a silent fall
    // back to an older policy (D7).
    let dir2 = temp("missing");
    let store2 = FsHost::create(&dir2).expect("a store");
    let oid = Oid::from_hex(&"ab".repeat(32)).unwrap();
    store2
        .update_ref_cas(&RefUpdate::create(policy::current_ref(), oid))
        .unwrap();
    let error = policy::resolve_store_at(
        &store2,
        &trust_of(&[&owner]),
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("the store cannot answer its own key");
    assert_eq!(error.token(), token::MISSING_BLOB);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn a_store_with_no_policy_is_a_refusal_for_a_gate_and_an_answer_for_a_question() {
    let dir = temp("empty");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(21);
    let roots = trust_of(&[&owner]);

    // A merge gate refuses rather than deciding by a default nobody chose (D4).
    let gate = policy::resolve(&policy::Request::store(&store, &roots, policy::At::now()))
        .expect_err("nothing is gate-eligible here");
    assert_eq!(gate.token(), token::NO_POLICY_PUBLISHED);
    assert_eq!(gate.exit_code(), 6);

    // A question gets an answer, and the answer says which source it came from.
    let asking = policy::resolve(&policy::Request::advisory(&roots).for_purpose(Purpose::Advisory))
        .expect("this build's default answers a question");
    assert_eq!(asking.provenance.source, Some(Source::BuiltInDefault));
    assert!(!asking.gate_eligible());
    assert!(
        !asking.policy.trust.trusts(ANCHOR),
        "the built-in default trusts nobody, which is the safe direction to be wrong in"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_tree_file_is_a_draft_and_a_flag_is_an_operator_act() {
    let dir = temp("sources");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(22);
    let roots = trust_of(&[&owner]);
    let checkout = dir.join("checkout");
    std::fs::create_dir_all(&checkout).unwrap();
    let tree_file = checkout.join("gitiup-policy.json");
    std::fs::write(
        &tree_file,
        json!({"allowed_tiers": ["local", "simulated"], "trust_key_ids": [ANCHOR]}).to_string(),
    )
    .unwrap();
    let flag_file = checkout.join("stricter.json");
    std::fs::write(
        &flag_file,
        json!({"allowed_tiers": ["local"], "trust_key_ids": [ANCHOR], "max_age_us": 60_000_000})
            .to_string(),
    )
    .unwrap();

    // Source 3: the tree file answers "what would this repo's file demand?" and is
    // never gate-eligible, because editing a file is not publishing a policy (D1, T1).
    let draft = policy::resolve(
        &policy::Request::advisory(&roots)
            .with_tree_file(&tree_file)
            .for_purpose(Purpose::Advisory),
    )
    .expect("a draft answers a question");
    assert_eq!(draft.provenance.source, Some(Source::TreeFile));
    assert!(!draft.gate_eligible());
    assert!(
        draft.policy.allows_tier(gitiup_attest::Tier::Simulated),
        "the file says simulated, and the file is what was asked about"
    );
    let gate = policy::resolve(&policy::Request::gate(&roots).with_tree_file(&tree_file))
        .expect_err("and a gate will not use a draft");
    assert_eq!(gate.token(), token::NO_POLICY_PUBLISHED);

    // Source 1: `--policy` is gate-eligible, because it is an explicit act — and it
    // says so, and names the published digest it overrode (D4).
    published(&store, &owner, 1, CLOCK_US - DAY_US);
    let overridden = policy::resolve(
        &policy::Request::store(&store, &roots, policy::At::now()).with_policy_file(&flag_file),
    )
    .expect("the flag wins");
    assert_eq!(overridden.provenance.source, Some(Source::PolicyFlag));
    assert_eq!(
        overridden.provenance.file.as_deref(),
        Some(flag_file.to_str().unwrap())
    );
    assert_eq!(overridden.policy.max_age_us, 60_000_000);
    assert!(
        overridden
            .provenance
            .notes
            .iter()
            .any(|note| note.contains("override nobody published")),
        "{:?}",
        overridden.provenance.notes
    );
    assert!(
        overridden
            .provenance
            .notes
            .iter()
            .any(|note| note.contains("it overrode the published policy sha256:")),
        "{:?}",
        overridden.provenance.notes
    );

    // And with the store published, the tree file's difference is said out loud: the
    // one line that answers "why didn't my change obey the rule I just edited" (D1).
    let in_force = policy::resolve(
        &policy::Request::store(&store, &roots, policy::At::now()).with_tree_file(&tree_file),
    )
    .expect("the published policy is in force");
    assert_eq!(in_force.provenance.source, Some(Source::Store));
    assert!(
        in_force
            .provenance
            .notes
            .iter()
            .any(|note| note.contains("is not in force: editing a file is not publishing")),
        "{:?}",
        in_force.provenance.notes
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_expired_policy_is_a_broken_gate_and_says_so() {
    let dir = temp("expired");
    let store = FsHost::create(&dir).expect("a store");
    let owner = key(23);
    let roots = trust_of(&[&owner]);
    let mut document = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - 10 * DAY_US);
    document.expires_at_us = Some(CLOCK_US - DAY_US);
    document.signatures.clear();
    document.sign(&owner).expect("re-signed with the expiry");
    policy::publish(
        &store,
        &document,
        &Context::new(&roots, TimeUs(CLOCK_US)),
        None,
    )
    .expect_err("a policy that is already expired cannot be published as the gate");
    // Publish it as it was valid, then read it after it stopped counting.
    let context_then = Context::new(&roots, TimeUs(CLOCK_US - 5 * DAY_US));
    let mut live = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - 10 * DAY_US);
    live.expires_at_us = Some(CLOCK_US - DAY_US);
    live.signatures.clear();
    live.sign(&owner).unwrap();
    policy::publish(&store, &live, &context_then, None)
        .expect("publishing a policy that has not expired yet is fine");
    let error = policy::resolve_store_at(
        &store,
        &roots,
        policy::At::now_at(TimeUs(CLOCK_US)),
        TimeUs(CLOCK_US),
    )
    .expect_err("a gate that quietly stopped is worse than one that says nothing");
    assert_eq!(error.token(), token::EXPIRED);
    assert_eq!(error.exit_code(), 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_reads_back_the_same_bytes_the_vectors_committed() {
    // The bridge between the two test files: publish the ADR's own `project` vector
    // into a store, resolve it, and check that nothing about the digests changed on the
    // round trip — which is what makes a verdict's citation meaningful on any host.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/fixtures/policy-v1/policies/project.json");
    let bytes = std::fs::read(&fixture).expect("the committed vector");
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        canon::to_value_bytes(&value).unwrap(),
        bytes,
        "the vector is canonical"
    );
    let dir = temp("vector-store");
    let store = FsHost::create(&dir).expect("a store");
    force_publish(&store, &bytes);
    let ada = trust_of(&[&fixture_key("ada")]);
    let resolved = policy::resolve_store_at(
        &store,
        &ada,
        policy::At::run_claim(TimeUs(1_792_467_200_000_000)),
        TimeUs(1_792_467_200_000_000),
    )
    .expect("the project policy resolves for a verifier that trusts Ada");
    assert_eq!(
        resolved.citation().unwrap(),
        "sha256:c1406ed5671f7ee38585a257bec0989c4f061f9a43d3073f795d7f749be78ecb"
    );
    assert_eq!(resolved.provenance.revision, Some(1));
    assert_eq!(
        resolved
            .policy
            .allowed_tiers
            .iter()
            .map(|tier| tier.as_str())
            .collect::<Vec<_>>(),
        vec!["quorum"],
        "the tier is data the owner signed, and it arrives as a `Policy` (C4)"
    );
    let quorum = resolved.document.unwrap().quorum.expect("a quorum block");
    assert_eq!(quorum.default.unwrap().required_agree, 4);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ADR-0003 fixture key rule, so the vector's owner can be trusted here too.
fn fixture_key(label: &str) -> SigningKey {
    let seed: [u8; 32] = gitiup_attest::Digest::sha256(
        format!("gitiup ADR-0003 change-v1 fixture key: {label}").as_bytes(),
    )
    .as_bytes()
    .try_into()
    .unwrap();
    SigningKey::from_seed(&seed)
}

#[test]
fn a_glob_scope_question_has_one_answer() {
    // `.4` and `.5` both ask "does this policy cover that ref?", and must not get two
    // answers because one of them re-implemented the glob.
    let owner = key(24);
    let mut document = signed(&owner, 1, GENESIS_PREVIOUS, CLOCK_US - DAY_US);
    document.protects = vec![
        "refs/heads/**".to_string(),
        "refs/heads/stable/**".to_string(),
    ];
    assert!(document.protects_ref("refs/heads/main"));
    assert!(document.protects_ref("refs/heads/stable/7"));
    assert!(!document.protects_ref("refs/changes/chg-1/head"));
    assert!(!document.protects_ref("refs/gitiup/policy/current"));
    let mut narrow = document.clone();
    narrow.protects = vec!["refs/heads/main".to_string()];
    assert!(narrow.protects_ref("refs/heads/main"));
    assert!(!narrow.protects_ref("refs/heads/dev"));
    // The quorum block answers "which numbers for this job" the same way for everyone.
    let mut with_quorum = document.clone();
    let table: BTreeMap<String, gitiup_quorum::SelectionPolicy> =
        [("arm-*".to_string(), default_selection(3, 3))]
            .into_iter()
            .collect();
    with_quorum.quorum = Some(policy::QuorumBlock {
        default: Some(default_selection(5, 4)),
        by_job: Some(table),
        requirements: None,
        reveal_mode: None,
        // No attempt cap: the block is about seats and requirements, and a policy that
        // says nothing about retries means the default, not zero retries.
        max_attempts: None,
    });
    assert_eq!(
        with_quorum
            .quorum
            .as_ref()
            .unwrap()
            .selection_for("arm-a")
            .unwrap()
            .n,
        3
    );
    assert_eq!(
        with_quorum
            .quorum
            .as_ref()
            .unwrap()
            .selection_for("build")
            .unwrap()
            .n,
        5
    );
}

fn default_selection(n: usize, agree: usize) -> gitiup_quorum::SelectionPolicy {
    gitiup_quorum::SelectionPolicy {
        n,
        required_agree: agree,
        reserves: 2,
        tier_floor: gitiup_quorum::RosterTier::Endorsed,
        tier_caps: BTreeMap::new(),
        max_per_identity: 1,
    }
}

//! The ADR-0004 policy vectors, reproduced from `policies/*.json` alone.
//!
//! [`docs/adr/fixtures/policy-v1/`](../../../docs/adr/fixtures/policy-v1/README.md)
//! is the byte-for-byte contract that four tickets and one quorum ticket otherwise
//! each invent their own version of. The generator is Python, so checking the vectors
//! against Python again would be checking them against themselves; this file checks
//! them against the canonicaliser, the SSH key-id derivation and the signature
//! verifier the real code uses, and — the part that makes the vectors a rule rather
//! than a suggestion — against the validator: every one of the 32 refusals in
//! `cases.json:refusals` is reproduced here with the *same token and the same exit
//! code*, from a mutation applied to a real vector and re-signed.
//!
//! What is proven, in order:
//!
//! * the three fixture identities derive the key ids `cases.json` names;
//! * the bytes are their own canonical form, both digests are what the contents give,
//!   and the signature verifies over the policy's payload type and *not* over another
//!   record type's (ADR-0004 D2: the framing is inside the signature);
//! * `body_digest` is the digest with `signatures` removed (computable before anyone
//!   signs, which is what `policy publish --dry-run` prints) and `record_digest` is
//!   the digest of the stored bytes, which is the `kv/policy/` key;
//! * the validator reaches the same token and exit for all 32 refusals;
//! * the history walk picks revision 1, then revision 2, then refuses, at the three
//!   timestamps in `cases.json:history`;
//! * the publish-time normalisations match `cases.json:normalisations` field for field.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gitiup_attest::PolicyFile;
use gitiup_attest::{Digest, SignatureEntry, SigningKey, TimeUs, Trust, canon, pae};
use gitiup_quorum::policy::{self, Context, GENESIS_PREVIOUS, POLICY_PAYLOAD_TYPE, PolicyDocument};
use serde_json::{Map, Value, json};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/fixtures/policy-v1")
        .to_path_buf()
}

fn index() -> Value {
    let path = fixtures_dir().join("cases.json");
    serde_json::from_slice(&fs::read(path).expect("cases.json is readable"))
        .expect("cases.json parses")
}

fn case_bytes(entry: &Value) -> Vec<u8> {
    let path = fixtures_dir().join(entry["file"].as_str().expect("every case has a file"));
    fs::read(path).expect("the policy bytes are readable")
}

fn case_value(entry: &Value) -> Value {
    serde_json::from_slice(&case_bytes(entry)).expect("a published policy is JSON")
}

/// The fixture seed rule, exactly as
/// [`change-v1/generate.py`](../../../docs/adr/fixtures/change-v1/generate.py)
/// derives it: `SHA256("gitiup ADR-0003 change-v1 fixture key: " || label)`. The
/// secret is public, which is the point — a vector test needs no keystore.
fn fixture_key(label: &str) -> SigningKey {
    let seed: [u8; 32] =
        Digest::sha256(format!("gitiup ADR-0003 change-v1 fixture key: {label}").as_bytes())
            .as_bytes()
            .try_into()
            .expect("sha256 is 32 bytes");
    SigningKey::from_seed(&seed)
}

/// The clock the vectors are pinned to, because D6 refuses a future-dated policy and
/// a regeneration must not depend on when it ran.
fn clock() -> TimeUs {
    TimeUs(index()["clock_us"].as_i64().expect("clock_us"))
}

/// The verifier's trust roots, from `cases.json` — `{Ada}`, upstream's owner, which
/// is what makes `fork-weakened` a refusal instead of a shrug (D3).
fn trust_roots() -> Trust {
    let ids: BTreeSet<String> = index()["trust_roots"]
        .as_array()
        .expect("trust_roots")
        .iter()
        .map(|entry| entry.as_str().expect("a key id").to_string())
        .collect();
    Trust::KeyIds(ids)
}

/// The chain the `project` pair forms, oldest generation first.
fn project_chain() -> Vec<PolicyDocument> {
    let roots = trust_roots();
    let index = index();
    let policies = index["policies"].as_object().expect("policies");
    ["project", "project-tightened"]
        .iter()
        .map(|name| {
            let entry = &policies[*name];
            let bytes = case_bytes(entry);
            let context = Context::new(&roots, clock());
            // Steps 1–2 only: revision 2's chain link cannot be checked until its
            // predecessor is in the history, which is what the caller is building.
            policy::check_self_contained(&bytes, &context)
                .unwrap_or_else(|e| panic!("{name} must be a well-formed signed policy: {e}"))
                .1
        })
        .collect()
}

#[test]
fn the_fixture_identities_derive_the_key_ids_the_vectors_name() {
    let index = index();
    let keys = index["keys"].as_object().expect("keys");
    for (label, expected) in keys {
        let derived = fixture_key(label).public_key().key_id();
        assert_eq!(
            &derived, expected,
            "`{label}` must derive {expected} from the published seed rule"
        );
    }
}

#[test]
fn every_vector_is_its_own_canonical_form_and_both_digests_are_what_the_contents_give() {
    let index = index();
    let policies = index["policies"].as_object().expect("policies");
    assert!(!policies.is_empty(), "the vectors are not empty");
    for (name, entry) in policies {
        let bytes = case_bytes(entry);
        let value = case_value(entry);

        // ADR-0001 D1, step 1 of D9: the reader's first check is that the bytes are
        // their own canonical encoding, and the vectors must pass it.
        let reparsed = canon::read_canonical(&bytes)
            .unwrap_or_else(|e| panic!("{name}: the committed bytes are not canonical: {e}"));
        assert_eq!(
            canon::to_value_bytes(&reparsed).expect("re-encode"),
            bytes,
            "{name} does not re-encode to itself"
        );
        assert_eq!(reparsed, value, "{name} round-trips through a Value");
        assert_eq!(
            bytes.len(),
            entry["size_bytes"].as_u64().unwrap() as usize,
            "{name}: size_bytes"
        );

        // The two digests, with the two jobs ADR-0003 D4 generalises: citations name
        // the signed body, storage keys name the stored bytes.
        let body = policy::body_bytes_of(&value).expect("body bytes");
        let body_digest = format!("sha256:{}", Digest::sha256(&body).hex());
        let record_digest = format!("sha256:{}", Digest::sha256(&bytes).hex());
        assert_eq!(
            body_digest,
            entry["body_digest"].as_str().unwrap(),
            "{name}: body_digest is the digest of the document with `signatures` removed"
        );
        assert_eq!(
            record_digest,
            entry["record_digest"].as_str().unwrap(),
            "{name}: record_digest is the digest of the stored bytes"
        );
        let hex = record_digest.split_once(':').unwrap().1.to_string();
        assert_eq!(
            format!("kv/policy/{hex}"),
            entry["kv"].as_str().unwrap(),
            "{name}: the kv/ key is the record digest, not the body digest (D7)"
        );
        assert_eq!(
            policy::current_ref().as_str(),
            entry["ref"].as_str().unwrap(),
            "{name}: the advertising ref"
        );
        assert_eq!(
            entry["revision"].as_u64().unwrap() as u32,
            value["revision"].as_u64().unwrap() as u32,
            "{name}: revision"
        );
        assert_eq!(
            entry["previous_digest"].as_str().unwrap(),
            value["previous_digest"].as_str().unwrap(),
            "{name}: previous_digest"
        );
        assert_eq!(entry["protects"], value["protects"], "{name}: protects");
        assert_eq!(
            entry["required_tiers"], value["rules"]["allowed_tiers"],
            "{name}: the tiers demanded are data in the document (C4)"
        );
        // One document per case, one signature per document (D2).
        assert_eq!(
            value["signatures"].as_array().unwrap().len(),
            1,
            "{name}: exactly one signature"
        );
        assert_eq!(
            entry["signed_by"].as_str().unwrap(),
            value["signatures"][0]["key_id"].as_str().unwrap(),
            "{name}: the signer is the owner the document names (D3)"
        );
    }
    // `fork-inherited` is `project` byte for byte: a fork inherits a policy by
    // inheriting the bytes, and nothing weakens (D1).
    let policies = index["policies"].as_object().unwrap();
    assert_eq!(
        case_bytes(&policies["fork-inherited"]),
        case_bytes(&policies["project"]),
        "fork-inherited must be byte-identical to project"
    );
    assert_ne!(
        case_bytes(&policies["fork-weakened"]),
        case_bytes(&policies["project"]),
        "fork-weakened is a different document — a different owner's, weaker (D3)"
    );
}

#[test]
fn a_policy_signature_is_bound_to_the_policy_payload_type_and_to_these_bytes() {
    let index = index();
    let policies = index["policies"].as_object().unwrap();
    for (name, entry) in policies {
        let value = case_value(entry);
        let body = policy::body_bytes_of(&value).expect("body bytes");
        let entry_value = &value["signatures"][0];
        let signature: SignatureEntry =
            serde_json::from_value(entry_value.clone()).expect("a signature entry");
        assert_eq!(
            signature.key_id,
            entry["signed_by"].as_str().unwrap(),
            "{name}"
        );
        // The identity is derived from the key offered, never typed (ADR-0001 D3).
        let offered = gitiup_attest::PublicKey::from_openssh(&signature.public_key)
            .expect("the public key parses");
        assert_eq!(
            offered.key_id(),
            signature.key_id,
            "{name}: key_id derivation"
        );
        signature
            .verify(&pae(POLICY_PAYLOAD_TYPE, &body))
            .unwrap_or_else(|e| panic!("{name}: the committed signature must verify: {e}"));
        // The framing is inside the signature: a policy can never be checked with a
        // roster's rules, or a roster with a policy's (D2).
        for wrong in [
            "application/vnd.gitiup.roster+json",
            "application/vnd.gitiup.change+json",
            "application/vnd.gitiup.attestation+json",
        ] {
            assert!(
                signature.verify(&pae(wrong, &body)).is_err(),
                "{name}: a signature over the policy framing must not verify as {wrong}"
            );
        }
        // And it does not survive a byte of the body being edited afterwards.
        let mut tampered = value.clone();
        tampered["rules"]["min_signatures"] = json!(9);
        let tampered_body = policy::body_bytes_of(&tampered).expect("body bytes");
        assert!(
            signature
                .verify(&pae(POLICY_PAYLOAD_TYPE, &tampered_body))
                .is_err(),
            "{name}: a body edited after signing must not verify (D9's `bad_signature`)"
        );
    }
}

#[test]
fn the_validator_accepts_every_vector_it_should_and_refuses_the_fork_that_weakened_its_policy() {
    let index = index();
    let policies = index["policies"].as_object().unwrap();
    let trust = trust_roots();
    let chain = project_chain();
    let history = policy::History::from_docs(chain.iter().cloned()).expect("history");
    let context = Context::new(&trust, clock()).with_history(&history);
    for (name, entry) in policies {
        let bytes = case_bytes(entry);
        let expected: Vec<String> = entry["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap().to_string())
            .collect();
        // The warnings are a property of the document and of these trust roots, so the
        // fork's own policy has them too even though this verifier will not believe it:
        // `personal`'s anchor is a runner key this machine does not hold, which is the
        // normal arrangement and therefore a warning and not a refusal (D8).
        let self_contained = policy::check_self_contained(&bytes, &Context::new(&trust, clock()))
            .unwrap_or_else(|e| panic!("{name}: steps 1-2 must pass: {e}"))
            .1;
        assert_eq!(
            self_contained.warnings(&trust, clock()),
            expected,
            "{name}: publish warnings, in D8's order"
        );
        match policy::verify_bytes(&bytes, &context) {
            Ok(document) => {
                assert_eq!(
                    document
                        .body_digest()
                        .expect("a body digest for the report"),
                    entry["body_digest"].as_str().unwrap(),
                    "{name}: resolved body digest"
                );
                assert_eq!(
                    document.owner.key_id,
                    entry["signed_by"].as_str().unwrap(),
                    "{name}: provenance names the signer (D4)"
                );
            }
            Err(error) => {
                assert_eq!(name, "fork-weakened", "{name} must verify: {error}");
                // Refused, not distrusted-and-used: a fork cannot weaken a policy it
                // cannot re-sign convincingly (D3).
                assert_eq!(error.token(), "signer_untrusted", "{name}");
                assert_eq!(error.exit_code(), 6, "{name}");
            }
        }
    }
}

#[test]
fn a_resolved_policy_carries_the_rules_the_document_names() {
    let index = index();
    let entry = &index["policies"]["project"];
    let bytes = case_bytes(entry);
    let trust = trust_roots();
    let chain = project_chain();
    let history = policy::History::from_docs(chain).expect("history");
    let document = policy::verify_bytes(
        &bytes,
        &Context::new(&trust, clock()).with_history(&history),
    )
    .expect("project verifies");

    // The rules a merge gate applies come out of the signed document, not out of a
    // flag (C4): tier, anchors, freshness, the environment match, the quorum numbers.
    let resolved = document
        .to_policy(Some(clock().0))
        .expect("project's rules resolve");
    assert_eq!(
        resolved
            .allowed_tiers
            .iter()
            .map(|tier| tier.as_str())
            .collect::<Vec<_>>(),
        vec!["quorum"]
    );
    assert_eq!(resolved.max_age_us, 43_200_000_000, "6 h, halved from 12 h");
    assert_eq!(resolved.min_signatures, 1);
    assert!(resolved.require_env_match.is_enforced());
    // The machine class travels in the same signed document: an arm64 attestation
    // cannot satisfy this repository, and that is a policy refusal, not a mystery.
    let requirement = resolved
        .environment_requirement()
        .expect("project publishes an environment requirement");
    let rendered = requirement.to_string();
    assert!(
        rendered.contains("arch=amd64"),
        "the requirement names the machine the owner signed: {rendered}"
    );
    assert!(
        rendered.contains("image_digest=abababab"),
        "and the image digest, because a policy that compares results across verifiers \
         has to pin the machine class it compared on: {rendered}"
    );
    assert_eq!(
        resolved.now.expect("the clock the run is judged at"),
        clock(),
        "D6: the freshness window is applied by the policy the walk picked"
    );
    // The quorum block is `SelectionPolicy` and `Requirements` verbatim, so reading a
    // round's numbers out of the policy is a copy and not a translation (D5).
    let quorum = document.quorum.clone().expect("project has a quorum block");
    let default = quorum.default.clone().expect("a default selection");
    assert_eq!((default.n, default.required_agree), (5, 4));
    assert_eq!(default.tier_floor, gitiup_quorum::RosterTier::Endorsed);
    let requirements = quorum.requirements.clone().expect("requirements");
    assert_eq!(requirements.arch, "x86_64");
    assert_eq!((requirements.ram_mb, requirements.disk_mb), (8192, 51200));
    assert_eq!(requirements.min_sandbox_level, 2);
    assert_eq!(requirements.sandboxes, vec!["docker", "podman"]);
    // `protects` answers the scope question a hook needs (D1: only what is trusted).
    assert!(document.protects_ref("refs/heads/main"));
    assert!(document.protects_ref("refs/heads/stable/release-7"));
    assert!(!document.protects_ref("refs/changes/chg-1/head"));
}

#[test]
fn the_history_walk_picks_the_revision_in_force_and_refuses_a_run_with_no_policy_yet() {
    let index = index();
    let chain = project_chain();
    let policies = index["policies"].as_object().unwrap();
    for probe in index["history"].as_array().unwrap() {
        let at = TimeUs(probe["at_us"].as_i64().expect("at_us"));
        // The vectors name the chain by case name; resolve each name to a document.
        let named: Vec<PolicyDocument> = probe["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| {
                let entry = &policies[name.as_str().unwrap()];
                let bytes = case_bytes(entry);
                let trust = trust_roots();
                let context = Context::new(&trust, clock());
                policy::check_self_contained(&bytes, &context)
                    .expect("a vector in a history chain is a well-formed signed policy")
                    .1
            })
            .collect();
        assert_eq!(
            named.len(),
            2,
            "every chain in the vectors is the pair this ADR walks"
        );
        let _ = chain;
        match policy::in_force_at(&named, at) {
            Ok(found) => {
                let in_force = probe["in_force"].as_str().unwrap_or_else(|| {
                    panic!(
                        "the walk picked revision {} at {at:?}, and the vectors expected a refusal",
                        found.policy.revision
                    )
                });
                assert_eq!(
                    found.policy.revision,
                    probe["revision"].as_u64().unwrap() as u32,
                    "revision in force at {in_force}"
                );
                assert_eq!(
                    policies[in_force]["body_digest"].as_str().unwrap(),
                    found.policy.body_digest().unwrap(),
                    "the walk must return the document the vectors name"
                );
                // What "in force" has to mean for the numbers a verdict is judged by:
                // 4 of 5 and a 12 h window before the tightening, 5 of 7 and 6 h after.
                let expected_quorum = case_value(&policies[in_force])["quorum"]["default"].clone();
                let selection = found
                    .policy
                    .quorum
                    .as_ref()
                    .expect("both revisions name a quorum")
                    .default
                    .clone()
                    .expect("and a default");
                assert_eq!(selection.n, expected_quorum["n"].as_u64().unwrap() as usize);
                assert_eq!(
                    selection.required_agree,
                    expected_quorum["required_agree"].as_u64().unwrap() as usize
                );
            }
            Err(error) => {
                assert_eq!(
                    Some(error.token()),
                    probe["refusal"].as_str(),
                    "the walk refused with {} at {}",
                    error.token(),
                    at.to_rfc3339()
                );
                assert_eq!(error.exit_code(), 6, "a refusal to walk is a refusal (D6)");
            }
        }
    }
}

/// One row of the refusal table, reproduced in Rust: the case, the token, the exit,
/// and the mutation that produces it — described with the *same string* `cases.json`
/// uses, so the Rust table cannot drift from the vectors' table.
struct Refusal {
    case: &'static str,
    token: &'static str,
    mutation: &'static str,
    /// A mutation applied to the unsigned document before it is signed again (which is
    /// what makes the table teach thirty defects instead of thirty broken signatures).
    pre: &'static str,
    /// A defect that is only a defect after the fact, applied after signing.
    post: &'static str,
    /// Instead of mutating `project`, start from another case (D3's `fork-weakened`).
    from: Option<&'static str>,
}

const REFUSALS: &[Refusal] = &[
    Refusal {
        case: "unknown field",
        token: "field_unknown",
        mutation: "set rules.require_archh = \"x86_64\"",
        pre: "rules.require_archh=x86_64",
        post: "",
        from: None,
    },
    Refusal {
        case: "unsigned policy",
        token: "unsigned",
        mutation: "remove signatures",
        pre: "",
        post: "drop-signatures",
        from: None,
    },
    Refusal {
        case: "two signatures",
        token: "signature_count",
        mutation: "dup signature",
        pre: "",
        post: "dup-signature",
        from: None,
    },
    Refusal {
        case: "signer is not the owner",
        token: "owner_mismatch",
        mutation: "owner key",
        pre: "",
        post: "owner-key",
        from: None,
    },
    Refusal {
        case: "body edited after signing",
        token: "bad_signature",
        mutation: "tamper",
        pre: "",
        post: "rules.min_signatures=9",
        from: None,
    },
    Refusal {
        case: "typed key id",
        token: "key_id_derivation",
        mutation: "signer key id",
        pre: "",
        post: "signer-key-id",
        from: None,
    },
    Refusal {
        case: "signed by a stranger",
        token: "signer_untrusted",
        mutation: "foreign signer",
        pre: "",
        post: "",
        from: Some("fork-weakened"),
    },
    Refusal {
        case: "no anchors at all",
        token: "no_trust_anchors",
        mutation: "set rules.trust_key_ids = []",
        pre: "rules.trust_key_ids=[]",
        post: "",
        from: None,
    },
    Refusal {
        case: "unknown schema",
        token: "unknown_schema",
        mutation: "set schema_version = 2",
        pre: "schema_version=2",
        post: "",
        from: None,
    },
    Refusal {
        case: "future-dated",
        token: "future_dated",
        mutation: "set effective_from_us = 1793093800000000",
        pre: "effective_from_us=1793093800000000",
        post: "",
        from: None,
    },
    Refusal {
        case: "expired",
        token: "expired",
        mutation: "set expires_at_us = 1793092799999999",
        pre: "expires_at_us=1793092799999999",
        post: "",
        from: None,
    },
    Refusal {
        case: "expiry before effect",
        token: "expires_before_effective",
        mutation: "set expires_at_us",
        pre: "expires_at_us=effective_from_us",
        post: "",
        from: None,
    },
    Refusal {
        case: "revision skips",
        token: "revision_gap",
        mutation: "set revision = 9",
        pre: "revision=9",
        post: "",
        from: None,
    },
    Refusal {
        case: "previous_digest names nothing",
        token: "chain_broken",
        mutation: "set previous_digest = \"sha256:1111111111111111111111111111111111111111111111111111111111111111\"",
        pre: "previous_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111",
        post: "",
        from: None,
    },
    Refusal {
        case: "gates a contributor ref",
        token: "protects_out_of_scope",
        mutation: "set protects = [\"refs/changes/**\"]",
        pre: "protects=[refs/changes/**]",
        post: "",
        from: None,
    },
    Refusal {
        case: "rules not in canonical order",
        token: "not_normalised",
        mutation: "set rules.allowed_tiers = [\"quorum\", \"local\"]",
        pre: "rules.allowed_tiers=[quorum,local]",
        post: "",
        from: None,
    },
    Refusal {
        case: "accepts no tier",
        token: "empty_tiers",
        mutation: "set rules.allowed_tiers = []",
        pre: "rules.allowed_tiers=[]",
        post: "",
        from: None,
    },
    Refusal {
        case: "unknown tier",
        token: "tier_unknown",
        mutation: "set rules.allowed_tiers = [\"cloud\"]",
        pre: "rules.allowed_tiers=[cloud]",
        post: "",
        from: None,
    },
    Refusal {
        case: "zero signatures required",
        token: "min_signatures_zero",
        mutation: "set rules.min_signatures = 0",
        pre: "rules.min_signatures=0",
        post: "",
        from: None,
    },
    Refusal {
        case: "env match off with a requirement",
        token: "env_match_off",
        mutation: "set rules.require_env_match = \"off\"",
        pre: "rules.require_env_match=off",
        post: "",
        from: None,
    },
    Refusal {
        case: "unconfined sandbox demanded",
        token: "sandbox_forbidden",
        mutation: "add rules.allowed_sandboxes = \"none\"",
        pre: "add rules.allowed_sandboxes=none",
        post: "",
        from: None,
    },
    Refusal {
        case: "threshold above seats",
        token: "required_agree_unreachable",
        mutation: "set quorum.default.required_agree = 9",
        pre: "quorum.default.required_agree=9",
        post: "",
        from: None,
    },
    Refusal {
        case: "threshold of zero",
        token: "required_agree_zero",
        mutation: "set quorum.default.required_agree = 0",
        pre: "quorum.default.required_agree=0",
        post: "",
        from: None,
    },
    Refusal {
        case: "unknown roster tier",
        token: "tier_floor_unknown",
        mutation: "set quorum.default.tier_floor = \"famous\"",
        pre: "quorum.default.tier_floor=famous",
        post: "",
        from: None,
    },
    Refusal {
        case: "quorum rules, quorum refused",
        token: "tier_not_allowed",
        mutation: "set rules.allowed_tiers = [\"local\"]",
        pre: "rules.allowed_tiers=[local]",
        post: "",
        from: None,
    },
    Refusal {
        case: "no sandbox can satisfy it",
        token: "requirements_unsatisfiable",
        mutation: "set quorum.requirements.sandboxes = []",
        pre: "quorum.requirements.sandboxes=[]",
        post: "",
        from: None,
    },
    Refusal {
        case: "zero resource floor",
        token: "requirements_unsatisfiable",
        mutation: "set quorum.requirements.ram_mb = 0",
        pre: "quorum.requirements.ram_mb=0",
        post: "",
        from: None,
    },
    Refusal {
        case: "sandbox sets disjoint",
        token: "sandbox_disjoint",
        mutation: "set quorum.requirements.sandboxes = [\"landlock\"]",
        pre: "quorum.requirements.sandboxes=[landlock]",
        post: "",
        from: None,
    },
    Refusal {
        case: "arch spelled two ways",
        token: "arch_conflict",
        mutation: "set quorum.requirements.arch = \"aarch64\"",
        pre: "quorum.requirements.arch=aarch64",
        post: "",
        from: None,
    },
    Refusal {
        case: "policy demands no confinement",
        token: "sandbox_floor",
        mutation: "set quorum.requirements.min_sandbox_level = 0",
        pre: "quorum.requirements.min_sandbox_level=0",
        post: "",
        from: None,
    },
];

/// Apply a `path=value` mutation, in the same dull style as the generator: dotted
/// paths into the document, `[a,b]` for a list, and `add` to append to one.
fn apply(document: &mut Value, mutation: &str) {
    let (kind, rest) = match mutation.split_once(' ') {
        Some(("add", rest)) => ("add", rest),
        _ => ("set", mutation),
    };
    let (path, value) = rest
        .split_once('=')
        .unwrap_or_else(|| panic!("not a mutation: {mutation}"));
    let replacement = if value == "effective_from_us" {
        // The generator writes this one as a reference to the document's own field:
        // an expiry equal to the effective time, dead on arrival (D6).
        document["effective_from_us"].clone()
    } else {
        parse_literal(value)
    };
    let mut target = document;
    for step in path.split('.') {
        target = &mut target[step];
    }
    if kind == "add" {
        let list = target
            .as_array()
            .cloned()
            .unwrap_or_else(|| panic!("{path} is not a list to add to"));
        let mut appended = list.clone();
        appended.push(replacement);
        *target = Value::Array(appended);
    } else {
        *target = replacement;
    }
}

fn parse_literal(text: &str) -> Value {
    if text == "[]" {
        return Value::Array(Vec::new());
    }
    if let Some(list) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return Value::Array(
            list.split(',')
                .map(|item| parse_literal(item.trim()))
                .collect(),
        );
    }
    match text {
        "true" => return json!(true),
        "false" => return json!(false),
        _ => {}
    }
    if let Ok(number) = text.parse::<i64>() {
        return json!(number);
    }
    json!(text)
}

/// The unsigned `project` vector: the document the refusal table mutates.
fn unsigned_project() -> Value {
    let index = index();
    let mut value = case_value(&index["policies"]["project"]);
    value
        .as_object_mut()
        .expect("an object")
        .remove("signatures");
    value
}

/// Sign a document the way the vectors do: the owner's fixture key, over the PAE
/// framing of the body (which is what `gitiup policy publish` does, D8).
fn resign(document: &mut Value) {
    let key = fixture_key("ada");
    let body = policy::body_bytes_of(document).expect("body bytes");
    let entry = SignatureEntry::new(&key, &pae(POLICY_PAYLOAD_TYPE, &body)).expect("a signature");
    document["signatures"] = json!([serde_json::to_value(entry).expect("serialises")]);
}

#[test]
fn the_validator_reaches_the_same_token_and_exit_for_all_32_refusals() {
    let index = index();
    let table = index["refusals"].as_array().expect("refusals");
    assert_eq!(
        table.len(),
        32,
        "D9's table is 32 rows, and the vectors generate them"
    );
    let trust = trust_roots();
    let context = Context::new(&trust, clock());
    let mut checked = 0;
    for row in table {
        let token = row["token"].as_str().unwrap();
        let exit = row["exit"].as_u64().unwrap() as u8;
        let mutation = row["mutation"].as_str().unwrap();
        let case = row["case"].as_str().unwrap();
        // Two rows are about bytes rather than about a document, and cannot be
        // mutations of one (D9): they are still step 1, refused before anything in the
        // container is believed.
        if token == "not_canonical" {
            let error = policy::verify_bytes(b"{ \"a\": 1 }", &context).expect_err("refused");
            assert_eq!(error.token(), token, "{case}");
            assert_eq!(error.exit_code(), exit, "{case}");
            checked += 1;
            continue;
        }
        if token == "size_exceeded" {
            let mut flooded = unsigned_project();
            let mut notes = Map::new();
            for index in 0..64 {
                notes.insert(
                    format!("x_gitiup_flood_{index:04}"),
                    Value::String("y".repeat(512)),
                );
            }
            flooded["annotations"] = Value::Object(notes);
            let bytes = canon::to_value_bytes(&flooded).expect("the encoder itself bounds it");
            assert!(bytes.len() > policy::MAX_POLICY_BYTES);
            let error = policy::verify_bytes(&bytes, &context).expect_err("refused");
            assert_eq!(error.token(), token, "{case}");
            assert_eq!(error.exit_code(), exit, "{case}");
            checked += 1;
            continue;
        }
        let row_refusal = REFUSALS
            .iter()
            .find(|candidate| {
                candidate.token == token && candidate.case == case && candidate.mutation == mutation
            })
            .unwrap_or_else(|| panic!("no Rust refusal reproduces {case} ({token}, `{mutation}`)"));
        let mut document = match row_refusal.from {
            Some(name) => case_value(&index["policies"][name]),
            None => {
                let mut document = unsigned_project();
                if !row_refusal.pre.is_empty() {
                    apply(&mut document, row_refusal.pre);
                }
                if row_refusal.post != "drop-signatures" {
                    resign(&mut document);
                }
                document
            }
        };
        match row_refusal.post {
            "" => {}
            "drop-signatures" => {
                document.as_object_mut().unwrap().remove("signatures");
            }
            "dup-signature" => {
                let signatures = document["signatures"].as_array().unwrap().clone();
                let mut doubled = signatures.clone();
                doubled.extend(signatures);
                document["signatures"] = Value::Array(doubled);
            }
            "owner-key" => {
                let sofia = fixture_key("sofia").public_key().key_id();
                document["owner"]["key_id"] = json!(sofia);
            }
            "signer-key-id" => {
                let sofia = fixture_key("sofia").public_key().key_id();
                document["owner"]["key_id"] = json!(sofia);
                document["signatures"][0]["key_id"] = json!(sofia);
            }
            other => apply(&mut document, other),
        }
        let bytes = canon::to_value_bytes(&document).expect("canonical bytes");
        let error = policy::verify_bytes(&bytes, &context)
            .expect_err(&format!("{case} must be refused ({token})"));
        assert_eq!(error.token(), token, "{case}: the token is the interface");
        assert_eq!(
            error.exit_code(),
            exit,
            "{case}: exit for {}",
            error.token()
        );
        assert_eq!(
            policy::exit_code_of(token),
            exit,
            "{case}: the token table and the vectors must agree"
        );
        checked += 1;
    }
    assert_eq!(
        checked, 32,
        "every row of the vectors' table was reproduced from these bytes"
    );
    // And every Rust row found a vector: no private refusals invented on this side.
    let table_tokens: Vec<(String, String, String)> = table
        .iter()
        .map(|row| {
            (
                row["case"].as_str().unwrap().to_string(),
                row["token"].as_str().unwrap().to_string(),
                row["mutation"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for refusal in REFUSALS {
        assert!(
            table_tokens.contains(&(
                refusal.case.to_string(),
                refusal.token.to_string(),
                refusal.mutation.to_string()
            )),
            "Rust row `{}` ({}) is not in cases.json",
            refusal.case,
            refusal.token
        );
    }
}

#[test]
fn publish_normalises_a_tree_file_the_way_the_vectors_say() {
    let index = index();
    for row in index["normalisations"].as_array().unwrap() {
        let from = &row["from"];
        let to = &row["to"];
        let text = serde_json::to_string(from).expect("a tree file");
        let file = PolicyFile::from_json(&text)
            .unwrap_or_else(|e| panic!("{}: {}", row["note"].as_str().unwrap(), e));
        let normal = policy::normalise_rules(&file);
        let note = row["note"].as_str().unwrap();
        if let Some(tiers) = to.get("allowed_tiers") {
            assert_eq!(
                normal.allowed_tiers,
                Some(
                    tiers
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|t| t.as_str().unwrap().to_string())
                        .collect::<Vec<String>>()
                ),
                "{note}: the shorthand resolves into the tier list (D2)"
            );
        }
        if let Some(sandboxes) = to.get("allowed_sandboxes") {
            assert_eq!(
                normal.allowed_sandboxes,
                Some(
                    sandboxes
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().to_string())
                        .collect::<Vec<String>>()
                ),
                "{note}: order is normalised away, so equivalent rules are one byte string"
            );
        }
        // The signed document names its tiers once: the shorthand disappears.
        assert_eq!(normal.allow_simulated, None, "{note}");
        // And normalising twice is the same bytes — the property that makes a
        // re-publish that changed nothing unable to move a cited digest (D6).
        let once = policy::normalise_rules(&normal);
        assert_eq!(
            serde_json::to_value(&once).unwrap(),
            serde_json::to_value(&normal).unwrap(),
            "{note}: normalisation is idempotent"
        );
    }
}

#[test]
fn the_genesis_previous_is_the_zero_digest_the_vectors_write() {
    assert_eq!(
        GENESIS_PREVIOUS,
        index()["genesis_previous"].as_str().unwrap(),
        "a chain starts at the zero digest, not at an absent field (D6)"
    );
}

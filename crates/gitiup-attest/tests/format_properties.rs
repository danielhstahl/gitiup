//! Properties the format must hold, independent of any particular fixture.
//!
//! These are the guarantees the runner (giti-1rs.2) and the reproducibility work
//! (giti-1rs.3) get for free from ADR-0001 — and the reason their tickets can be
//! about *content* rather than about byte-fiddling:
//!
//! * **order independence**: after `normalize()`, the insertion order of anything
//!   spec-sorted cannot change the digest;
//! * **idempotence**: encoding, parsing and re-encoding is the identity;
//! * **no second encoding**: two byte strings that parse to one manifest are the
//!   same bytes;
//! * **tamper sensitivity**: every byte of the signed payload matters.

use gitiup_attest::canon;
use gitiup_attest::manifest::{StepOutcome, ToolchainEntry};
use gitiup_attest::{AttestationDoc, Digest, RunManifest, sample};

/// A tiny deterministic PRNG (xorshift64\*), so the "random" shuffles below are
/// reproducible without pulling in a dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

#[test]
fn insertion_order_cannot_change_the_digest() {
    let baseline = sample::full();
    let want = baseline.digest().unwrap();
    let want_result = baseline.result_digest().unwrap();

    let mut rng = Rng(0x5eed_1234_9abc_def0);
    for _ in 0..50 {
        let mut manifest = sample::full();
        rng.shuffle(&mut manifest.result.secret_names);
        rng.shuffle(&mut manifest.result.reusable_workflows);
        rng.shuffle(&mut manifest.result.environment.toolchain);
        for step in &mut manifest.result.steps {
            rng.shuffle(&mut step.artifacts);
        }
        rng.shuffle(&mut manifest.claims.normalisation_diffs);

        manifest.normalize();
        assert_eq!(
            manifest.digest().unwrap(),
            want,
            "RunDigest moved with ordering"
        );
        assert_eq!(
            manifest.result_digest().unwrap(),
            want_result,
            "ResultDigest moved with ordering"
        );
        manifest.validate().unwrap();
    }
}

#[test]
fn encoding_is_an_involution() {
    for manifest in [sample::minimal(), sample::simulated(), sample::local()] {
        let once = manifest.canonical_bytes().unwrap();
        let parsed = RunManifest::from_canonical_bytes(&once).unwrap();
        let twice = parsed.canonical_bytes().unwrap();
        assert_eq!(once, twice, "re-encoding changed the bytes");
        assert_eq!(parsed, manifest);
        assert!(canon::is_canonical(&twice));
    }
}

#[test]
fn two_encodings_of_one_manifest_is_a_bug_not_a_maybe() {
    // Any reformatting a lenient JSON writer might do must be refused rather than
    // silently producing a different digest for the same content.
    let manifest = sample::local();
    let canonical = manifest.canonical_bytes().unwrap();
    let text = String::from_utf8(canonical.clone()).unwrap();
    let reformattings = [
        text.replace("\":", "\": "),
        text.replace(",\"", ", \""),
        text.replace("}{", "} {"),
        format!("{text}\n"),
        format!("{text} "),
        // An escaped ASCII letter: legal JSON, a second encoding of the same text.
        text.replace("\"sha256:", "\"\\u0073ha256:"),
    ];
    for reformatted in reformattings {
        if reformatted.as_bytes() == canonical.as_slice() {
            continue;
        }
        let error = RunManifest::from_canonical_bytes(reformatted.as_bytes());
        if let Err(err) = error {
            // Refused outright, and classed as a digest problem rather than a
            // policy refusal, so `gitiup verify` exits 8 rather than 6.
            assert_eq!(
                err.kind(),
                gitiup_attest::ErrorKind::DigestMismatch,
                "reformatted bytes were {reformatted:?}, error was {err}"
            );
            continue;
        }
        // Accepted only if it re-encodes to the same bytes — which, since the
        // reader demands the canonical form, means it *was* the canonical form.
        panic!("non-canonical bytes accepted: {reformatted:?}");
    }
}

#[test]
fn every_field_participates_in_the_digest() {
    // Change one thing at a time, everywhere there is something to change, and the
    // RunDigest must move each time. A field that does not affect the digest is a
    // field an attacker can rewrite unnoticed.
    let base = sample::full();
    let base_digest = base.digest().unwrap();
    /// A named single-field change to try against the baseline manifest.
    type Mutation = (&'static str, fn(&mut RunManifest));
    let mutations: Vec<Mutation> = vec![
        ("schema_version", |m| m.schema_version = 1),
        ("run_id", |m| m.claims.run_id = "fe".repeat(8)),
        ("claimed_at_us", |m| m.claims.claimed_at_us += 1),
        ("not_before_us", |m| {
            m.claims.not_before_us = Some(m.claims.claimed_at_us)
        }),
        ("not_after_us", |m| {
            m.claims.not_after_us = Some(m.claims.claimed_at_us + 2)
        }),
        ("verifier_challenge", |m| {
            m.claims.verifier_challenge = Some(Digest::sha256(b"other"))
        }),
        ("annotation", |m| {
            m.claims.annotations.insert("x_note".into(), "added".into());
        }),
        ("timing", |m| {
            m.claims.timing.insert(
                "extra".into(),
                gitiup_attest::StepTiming {
                    started_us: Some(1),
                    duration_us: Some(2),
                },
            );
        }),
        ("normalisation_diff", |m| {
            m.claims
                .normalisation_diffs
                .push(gitiup_attest::NormalisationDiff {
                    step: "zz".into(),
                    kind: "zz".into(),
                    before: "a".into(),
                    after: "b".into(),
                })
        }),
        ("commit", |m| {
            m.result.source.commit = gitiup_attest::GitOid::from_sha1_hex(&"f".repeat(40)).unwrap()
        }),
        ("repo", |m| m.result.source.repo = Some("other/repo".into())),
        ("job", |m| m.result.source.job = Some("other".into())),
        ("matrix", |m| {
            m.result.source.matrix.insert("extra".into(), "1".into());
        }),
        ("workflow_path", |m| {
            m.result.source.workflow.path = "other.yml".into()
        }),
        ("event_name", |m| m.result.source.event.name = "push".into()),
        ("event_action", |m| m.result.source.event.action = None),
        ("event_payload", |m| {
            m.result.source.event.payload = Digest::sha256(b"other")
        }),
        ("input", |m| {
            m.result
                .inputs
                .insert("extra".into(), gitiup_attest::InputValue::Int(7));
        }),
        ("secret_name", |m| {
            m.result.secret_names.push("EXTRA".into())
        }),
        ("pin", |m| {
            m.result.pins.insert(
                "extra/action@v1".into(),
                gitiup_attest::ActionPin {
                    repo: "extra/action".into(),
                    commit: gitiup_attest::GitOid::from_sha1_hex(&"e".repeat(40)).unwrap(),
                    reference: None,
                },
            );
        }),
        ("reusable_workflow", |m| {
            m.result
                .reusable_workflows
                .push(gitiup_attest::WorkflowRef {
                    path: "zz.yml".into(),
                    oid: gitiup_attest::GitOid::from_sha1_hex(&"d".repeat(40)).unwrap(),
                })
        }),
        ("arch", |m| m.result.environment.arch = "aarch64".into()),
        ("os", |m| m.result.environment.os = None),
        ("provider", |m| m.result.environment.provider = None),
        ("image", |m| m.result.environment.image = None),
        ("toolchain", |m| {
            m.result.environment.toolchain.push(ToolchainEntry {
                name: "zzz".into(),
                version: "0".into(),
            })
        }),
        ("fingerprint", |m| {
            m.result.environment.fingerprint = Digest::sha256(b"other")
        }),
        ("step_name", |m| m.result.steps[0].name = "renamed".into()),
        ("step_id", |m| m.result.steps[0].id = None),
        ("step_uses", |m| m.result.steps[0].uses = None),
        ("step_exit_code", |m| m.result.steps[0].exit_code = 3),
        ("step_outcome", |m| {
            m.result.steps[0].outcome = StepOutcome::Skipped
        }),
        ("step_stdout", |m| {
            m.result.steps[0].stdout = Digest::sha256(b"other")
        }),
        ("step_stderr", |m| {
            m.result.steps[0].stderr = Digest::sha256(b"other")
        }),
        ("step_output", |m| {
            m.result.steps[0].outputs.insert("extra".into(), "1".into());
        }),
        ("artifact", |m| {
            m.result.steps[1].artifacts.push(gitiup_attest::Artifact {
                name: "zzz".into(),
                digest: Digest::sha256(b"zzz"),
                size_bytes: 1,
            })
        }),
        ("tier", |m| {
            m.result.provenance.tier = gitiup_attest::Tier::Quorum
        }),
        ("runner", |m| {
            m.result.provenance.runner = "other 1.0".into()
        }),
        ("normalisation_version", |m| {
            m.result.provenance.normalisation_version = 2
        }),
        ("sandbox", |m| m.result.provenance.sandbox = None),
    ];

    for (name, mutate) in mutations {
        let mut manifest = base.clone();
        mutate(&mut manifest);
        if manifest == base {
            // `schema_version = 1` is the one no-op mutation in the list: it proves
            // the field is present without changing anything.
            assert_eq!(name, "schema_version", "{name} did not change the manifest");
            continue;
        }
        manifest.normalize();
        // Keep the derived fingerprint honest so we are testing the *field*, not
        // the fingerprint check that guards it.
        if name != "fingerprint" {
            manifest.result.environment.fix_fingerprint().unwrap();
        }
        let digest = manifest.digest().unwrap();
        if name == "fingerprint" {
            // A fingerprint that disagrees with the environment described is not a
            // different manifest, it is an invalid one.
            assert!(manifest.validate().is_err(), "{name} was accepted");
        } else {
            assert_ne!(digest, base_digest, "{name} does not affect the RunDigest");
        }
    }
}

#[test]
fn signatures_bind_the_payload_and_nothing_else() {
    // Same manifest, different envelope framing: the signature is over the
    // payload, so a doc that re-uses a signature over a *different* manifest must
    // fail, and one over the same manifest must pass regardless of who else signed.
    let mut doc = AttestationDoc::new(sample::local());
    doc.sign(&sample::test_key()).unwrap();
    let signature = doc.signatures[0].clone();

    let mut swapped = AttestationDoc::new(sample::simulated());
    swapped.signatures.push(signature.clone());
    assert_eq!(
        swapped
            .verify(&gitiup_attest::Policy::for_tests())
            .unwrap_err()
            .kind(),
        gitiup_attest::ErrorKind::Signature
    );

    let mut copied = AttestationDoc::new(sample::local());
    copied.signatures.push(signature);
    assert_eq!(copied.run_digest().unwrap(), doc.run_digest().unwrap());
    copied.verify(&gitiup_attest::Policy::for_tests()).unwrap();
}

#[test]
fn a_payload_type_change_invalidates_every_signature() {
    // PAE is not decoration: changing the declared payload type changes the signed
    // bytes, so a v1 signature cannot be claimed over a differently-typed payload.
    let mut doc = AttestationDoc::new(sample::local());
    doc.sign(&sample::test_key()).unwrap();
    doc.verify(&gitiup_attest::Policy::for_tests()).unwrap();

    let mut retyped = doc.clone();
    retyped.payload_type = "application/vnd.gitiup.run-manifest+json; v=2".into();
    assert_eq!(
        retyped
            .verify(&gitiup_attest::Policy::for_tests())
            .unwrap_err()
            .kind(),
        gitiup_attest::ErrorKind::UnsupportedSchema
    );
}

#[test]
fn a_document_cannot_be_flooded_with_signatures() {
    // A quorum is a handful of verifiers, and one identity casts one vote
    // (ADR-0001 D7): both are enforced, and both bound the work a verifier does.
    let key = sample::test_key();
    let entry = |i: usize| gitiup_attest::SignatureEntry {
        key_id: format!("SHA256:{i:043}"),
        algorithm: gitiup_attest::SignatureAlgorithm::Ed25519,
        public_key: key.public_key().to_openssh(),
        sig: key.sign(b"whatever").to_base64(),
    };
    let mut doc = AttestationDoc::new(sample::local());
    for i in 0..gitiup_attest::MAX_SIGNATURES {
        doc.signatures.push(entry(i));
    }
    doc.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    doc.validate().expect("exactly at the limit is fine");

    doc.signatures.push(entry(gitiup_attest::MAX_SIGNATURES));
    assert!(
        doc.validate()
            .is_err_and(|e| e.detail().contains("signatures exceeds")),
        "the cap must bind"
    );

    // One identity, two entries: refused even though the count is now legal.
    let mut doc = AttestationDoc::new(sample::local());
    doc.signatures.push(entry(0));
    doc.signatures.push(entry(0));
    assert!(
        doc.validate()
            .is_err_and(|e| e.detail().contains("one identity casts one vote"))
    );
}

#[test]
fn digests_are_self_describing_and_bounded() {
    let digest = Digest::sha256(b"payload");
    assert_eq!(digest.to_string().len(), "sha256:".len() + 64);
    assert!(digest.is_allowed(&gitiup_attest::Algorithm::ALL));
    // The canonical size budget is generous but real, and far above honest use.
    const { assert!(gitiup_attest::MAX_ENCODED_BYTES >= 64 * 1024) };
    assert!(sample::full().canonical_bytes().unwrap().len() < 8 * 1024);
}

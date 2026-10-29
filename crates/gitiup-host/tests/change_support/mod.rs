//! The fixtures and builders the change tests share.
//!
//! The keys are the ADR-0003 fixture keys — derived from a public label exactly the way
//! [`docs/adr/fixtures/change-v1/generate.py`](../../../../docs/adr/fixtures/change-v1/generate.py)
//! derives them — so a test that signs with `fixture_key("ada")` produces the same
//! `key_id` the committed vectors name. A mistake then shows up as a digest that does
//! not match, rather than as two implementations that agree with each other and nobody
//! else.

#![allow(dead_code)]

use gitiup_canon::{Digest, SigningKey};
use gitiup_host::change::{Attempts, Author, Base, ChangeId, ChangeRecord, Origin, Workflow};

/// The fixture seed rule, from `cases.json`: `SHA256("gitiup ADR-0003 change-v1 fixture
/// key: " || label)`.
pub fn fixture_key(label: &str) -> SigningKey {
    let digest =
        Digest::sha256(format!("gitiup ADR-0003 change-v1 fixture key: {label}").as_bytes());
    let seed: [u8; 32] = digest.as_bytes().try_into().expect("sha256 is 32 bytes");
    SigningKey::from_seed(&seed)
}

/// The author entry for a fixture key. `principal` is display only (D2), so it is
/// derived from the label and never checked.
pub fn author(who: &str) -> Author {
    Author {
        key_id: fixture_key(who).public_key().key_id(),
        principal: format!("{who}@example.org"),
    }
}

/// The ADR's worked-example base: `refs/heads/main` at a fixed oid.
pub const BASE_REF: &str = "refs/heads/main";
pub const BASE_OID: &str = "sha1:5f3e0d0b1a6c4e8f9a7b3c2d1e0f4a6b8c9d0e1f";
pub const HEAD_ONE: &str = "sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
pub const HEAD_TWO: &str = "sha1:0b8e2c4a6f0123456789abcdef0123456789abcd";
pub const HEAD_THREE: &str = "sha1:c0ffee00deadbeef0123456789abcdef01234567";

/// A fixed instant: these tests have no clock, any more than the fixtures do.
pub const T0: i64 = 1_764_674_043_000_000;
pub const HOUR: i64 = 3_600_000_000;

/// An unsigned change record: attempt `index` of the change that started at `anchor`.
pub fn change_record(
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
) -> ChangeRecord {
    let author = author(who);
    let change_id = ChangeId::derive(&author.key_id, BASE_REF, anchor).expect("a derived id");
    ChangeRecord {
        annotations: None,
        attempts: Attempts {
            anchor: anchor.to_string(),
            index,
            previous,
        },
        base: Base {
            branch: BASE_REF.to_string(),
            oid: BASE_OID.to_string(),
        },
        author,
        change_id,
        created_at_us: T0 + index as i64 * HOUR,
        head: head.to_string(),
        origin: Origin::store(),
        schema_version: 1,
        signatures: Vec::new(),
        title: title.to_string(),
        record_type: gitiup_host::change::CHANGE_TYPE.to_string(),
        workflow: Workflow {
            jobs: vec!["build/linux-x86_64".to_string(), "test".to_string()],
        },
    }
}

/// The same record, signed by `who` — which is also when the shape gets checked, because
/// [`ChangeRecord::sign`] verifies what it produces.
pub fn signed_change(
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
) -> ChangeRecord {
    change_record(who, title, anchor, head, index, previous)
        .sign(&fixture_key(who))
        .expect("a signed, valid change record")
}

/// A well-formed digest string, for "some attestation the merge believed".
pub fn proof(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

//! Federation: what a store serves, moved between two stores
//! ([ADR-0005](../../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
//!
//! Three questions live here, and keeping them apart is the whole point of the ADR.
//!
//! * **What may travel** — [`portable`]: the portable set is the verification closure of
//!   what a store serves, and everything that is arbitration state or a statement about
//!   *now* never leaves the store that made it. The table is generated data
//!   ([`docs/adr/fixtures/federation-v1/portable.json`](../../../../docs/adr/fixtures/federation-v1/README.md))
//!   with a Rust copy, and a test that makes them disagree loudly.
//! * **How it travels** — [`copy`]: bytes first, then the advertisement; create-only, so
//!   a re-run is `already`; pointers resolved on the reader's side and moved only
//!   forward; code by whichever pack path the two hosts agree on, or not at all.
//! * **What the reader is told** — [`provenance`]: the block a verify report carries when
//!   the bytes it judged arrived from another store, aged from the signed claim alone, and
//!   the demand a policy may make about provenance (D5 clause 3).
//!
//! What is deliberately **not** here is trust. A copy moves a signature, and a signature
//! is believed by a reader's own policy, in the reader's own process, from the reader's
//! own root list — so this module has no `Trust` to pass, no `--trust-remote` to accept,
//! no capability bit to set and no report field a merge gate may branch on (D3). The
//! crate this lives in does not even link the code that decides trust; that is not a
//! layering preference, it is the refusal, made structural.
//!
//! ```text
//! gitiup fetch --remote upstream --store ./store --change chg-6a6a8eab778ba4d0
//! gitiup push  --remote mirror  --store ./store --proofs-only
//! ```
//!
//! Both are [`copy`] with the hosts in the other order. Direction is about who asked;
//! it is not about what is allowed, because a mirror never pushes back (D6) and nothing
//! in here gives it a way.

pub mod copy;
pub mod portable;
pub mod provenance;

pub use copy::{
    AGE_BASIS, Arrival, CLOSURE_COMPLETE, CLOSURE_NOT_WALKED, CODE_OUTCOMES, CodeReport,
    CopyReport, IMPORT_TYPE, Objects, Options, PointerMove, Refs, Refusal, SubjectReport,
    TRUST_NONE, Verb, arrivals, copy, has_refetch_source, record, token_for,
};
pub use portable::{Budgets, Class, Decision, Row, TABLE, classify, namespace_travels};
pub use provenance::Block as Provenance;
pub use provenance::{
    CLOSURE_NATIVE, Demand as ProvenanceDemand, Identity as StoreIdentity, STORE_COPY,
    STORE_ORIGIN, arrival_for,
};

/// Every federation refusal token and the exit code it carries (D10).
///
/// No new exit codes: 6 refused (scope, a store that cannot take a copy, a pointer that
/// moved), 7 a signature that does not verify, 8 bytes that are not the bytes their name
/// promises. The tokens are the fixture's
/// ([`cases.json`](../../../../docs/adr/fixtures/federation-v1/README.md)) and a test
/// fails if this table and that list part company.
pub const REFUSALS: &[(&str, u8)] = &[
    ("not_portable", 6),
    ("no_arbitration_here", 6),
    ("read_only", 6),
    ("diverged", 6),
    ("digest_mismatch", 8),
    ("not_canonical", 8),
    ("same_ref", 6),
    ("binding_mismatch", 8),
    ("bad_signature", 7),
    ("signer_untrusted", 6),
    ("revoked_key", 6),
    ("tier_not_allowed", 6),
    ("policy_history_missing", 6),
    ("expired", 6),
    ("closure_incomplete", 6),
    ("subject_missing", 6),
    ("no_commitment", 6),
    ("mirror_may_not_prune_by_age", 6),
    ("eviction_needs_source", 6),
    ("gc_record_not_instruction", 6),
    ("origin_provenance_required", 6),
    ("unlisted_mirror", 6),
    ("closure_budget_records", 6),
    ("closure_budget_depth", 6),
    ("closure_budget_bytes", 6),
    ("policy_chain_too_long", 6),
    ("field_unknown", 6),
];

/// The exit code a token carries; 6 for anything unknown, which is what "refused" means.
pub fn exit_for(token: &str) -> u8 {
    REFUSALS
        .iter()
        .find(|(known, _)| *known == token)
        .map(|(_, code)| *code)
        .unwrap_or(6)
}

/// Whether a token is one this module knows.
pub fn knows_token(token: &str) -> bool {
    REFUSALS.iter().any(|(known, _)| *known == token)
}

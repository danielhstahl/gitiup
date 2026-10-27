//! The committed JSON Schemas ([ADR-0001 D8](../../../docs/adr/0001-attestation-encoding-hash-and-signature.md)).
//!
//! The normative schema files live next to this crate's `src`:
//!
//! * `schema/gitiup-run-manifest-1.schema.json` — the signed manifest.
//! * `schema/gitiup-attestation-doc-1.schema.json` — the envelope.
//!
//! They are embedded with `include_str!` so a binary that links gitiup-attest can
//! print them (`gitiup attest schema`) and so a test can compare them against the
//! Rust types — a schema that nothing checks is a schema that lies within a
//! release. The in-tree check is deliberately not a JSON Schema *validator*: the
//! constraints that matter for signature integrity (no nulls, integers only,
//! sorted lists, derived fingerprints) are enforced by
//! [`crate::canon`] and [`crate::manifest::RunManifest::validate`] on the way in,
//! which is stricter than any validator and applies to bytes rather than to
//! documents someone thought to run the validator over. External tools
//! (`check-jsonschema`, `ajv`) can use these files directly.

use std::sync::OnceLock;

use serde_json::Value;

use crate::error::{Error, Result};

/// Path of the manifest schema, relative to the repository root.
pub const RUN_MANIFEST_SCHEMA_PATH: &str =
    "crates/gitiup-attest/schema/gitiup-run-manifest-1.schema.json";

/// Path of the envelope schema, relative to the repository root.
pub const ATTESTATION_DOC_SCHEMA_PATH: &str =
    "crates/gitiup-attest/schema/gitiup-attestation-doc-1.schema.json";

/// The manifest schema, as committed.
pub const RUN_MANIFEST_SCHEMA: &str = include_str!("../schema/gitiup-run-manifest-1.schema.json");

/// The envelope schema, as committed.
pub const ATTESTATION_DOC_SCHEMA: &str =
    include_str!("../schema/gitiup-attestation-doc-1.schema.json");

/// Both schemas, as `(path, text)`.
pub const SCHEMA_FILES: [(&str, &str); 2] = [
    (RUN_MANIFEST_SCHEMA_PATH, RUN_MANIFEST_SCHEMA),
    (ATTESTATION_DOC_SCHEMA_PATH, ATTESTATION_DOC_SCHEMA),
];

static RUN_MANIFEST_SCHEMA_VALUE: OnceLock<Value> = OnceLock::new();
static ATTESTATION_DOC_SCHEMA_VALUE: OnceLock<Value> = OnceLock::new();

/// The manifest schema, parsed.
///
/// Parsing is once per process; a committed schema that fails to parse is a bug
/// in the tree, surfaced by [`crate::schema::check_schemas_parse`].
pub fn run_manifest_schema() -> &'static Value {
    RUN_MANIFEST_SCHEMA_VALUE.get_or_init(|| parse(RUN_MANIFEST_SCHEMA))
}

/// The envelope schema, parsed.
pub fn attestation_doc_schema() -> &'static Value {
    ATTESTATION_DOC_SCHEMA_VALUE.get_or_init(|| parse(ATTESTATION_DOC_SCHEMA))
}

fn parse(text: &str) -> Value {
    check_schemas_parse(text).expect("committed schema must be valid JSON")
}

/// Parse one schema; used by the tests so a broken commit fails loudly.
pub fn check_schemas_parse(text: &str) -> Result<Value> {
    // The schemas are ours, and they are pretty-printed, so the lenient reader is
    // fine here: this is not the canonical form of a signed payload.
    serde_json::from_str(text).map_err(|e| Error::invalid("schema", e.to_string()))
}

/// Look up a `$defs` entry by name in either schema.
pub fn def(name: &str) -> Option<&'static Value> {
    for schema in [run_manifest_schema(), attestation_doc_schema()] {
        if let Some(found) = schema.get("$defs").and_then(|defs| defs.get(name)) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_schemas_parse_and_are_linked() {
        for (path, text) in SCHEMA_FILES {
            let value = check_schemas_parse(text).unwrap_or_else(|e| panic!("{path}: {e}"));
            let id = value["$id"].as_str().unwrap_or_default();
            assert!(
                id.starts_with("https://gitiup.dev/schema/"),
                "{path} → {id}"
            );
        }
        assert!(
            ATTESTATION_DOC_SCHEMA.contains("gitiup-run-manifest-1.schema.json"),
            "the envelope schema must reference the manifest schema, not restate it"
        );
    }

    #[test]
    fn defs_are_reachable() {
        for name in [
            "RunManifest",
            "RunResult",
            "Source",
            "Environment",
            "Step",
            "Claims",
            "SignatureEntry",
            "digest",
            "gitOid",
        ] {
            assert!(def(name).is_some(), "missing $defs/{name}");
        }
    }
}

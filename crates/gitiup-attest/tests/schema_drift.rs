//! The Rust types and the committed JSON Schema must not drift apart.
//!
//! There is no code generator here, and none is needed: the schema is walked in
//! lockstep with the serialized samples, at every level of the document, and the
//! property names are compared as a set per position. That catches drift in both
//! directions —
//!
//! * a Rust field the schema does not declare (external validators would reject
//!   honest gitiup output), and
//! * a schema property no Rust type ever emits (an external implementer would
//!   write a field gitiup then refuses as unknown).
//!
//! The rules asserted are the ones the Rust reader really enforces:
//! `additionalProperties: false` wherever a Rust struct says `deny_unknown_fields`,
//! `required` exactly the fields left standing when every optional field is
//! absent, and a pinned set of patterns so nothing is loosened quietly.

use std::collections::{BTreeMap, BTreeSet};

use gitiup_attest::canon;
use gitiup_attest::sample;
use gitiup_attest::schema::{
    ATTESTATION_DOC_SCHEMA, RUN_MANIFEST_SCHEMA, attestation_doc_schema, def, run_manifest_schema,
};
use gitiup_attest::{AttestationDoc, RunManifest};
use serde_json::Value;

/// Resolve a schema node, following `$ref` until it lands on something concrete.
fn resolve(node: &Value) -> Value {
    let mut current = node.clone();
    for _ in 0..16 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return current;
        };
        current = match reference {
            "#" => run_manifest_schema().clone(),
            other => match other.split_once('#').map(|(_, frag)| frag) {
                Some(fragment) => {
                    let name = fragment
                        .strip_prefix("/$defs/")
                        .unwrap_or_else(|| panic!("unsupported $ref fragment '{fragment}'"));
                    def(name)
                        .unwrap_or_else(|| panic!("schema $ref '{reference}' does not resolve"))
                        .clone()
                }
                // A whole-document reference: the envelope's `manifest` member.
                None => run_manifest_schema().clone(),
            },
        };
    }
    panic!("$ref loop in the schema");
}

fn string_set(values: Option<&Vec<Value>>) -> BTreeSet<String> {
    values
        .map(|values| {
            values
                .iter()
                .map(|v| v.as_str().expect("string").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// What a position in the document looks like, seen from the Rust side and from
/// the schema side.
#[derive(Default)]
struct Position {
    /// Property names the schema declares here.
    declared: BTreeSet<String>,
    /// Property names Rust actually emitted, unioned over every instance of this
    /// position (array elements, and optional fields that appear in only some).
    emitted: BTreeSet<String>,
    /// The schema's `required` here.
    required: BTreeSet<String>,
    /// Whether every instance had exactly `required`.
    minimal_exact: bool,
    path: String,
}

/// Walk sample and schema together, key by key.
///
/// `minimal` means "this sample contains no optional field", which turns the
/// comparison from a subset check into an exact one.
struct Walker {
    minimal: bool,
    positions: BTreeMap<String, Position>,
}

impl Walker {
    fn new(minimal: bool) -> Walker {
        Walker {
            minimal,
            positions: BTreeMap::new(),
        }
    }

    fn value(&mut self, path: &str, schema: &Value, sample: &Value) {
        let schema = resolve(schema);
        match sample {
            Value::Object(map) => {
                if schema.get("properties").is_some() {
                    self.object(path, &schema, map);
                } else if let Some(value_schema) = schema.get("additionalProperties") {
                    // A map of values (`inputs`, `pins`, `timing`, `annotations`).
                    if !value_schema.is_boolean() {
                        for value in map.values() {
                            self.value(&format!("{path}[key]"), value_schema, value);
                        }
                    }
                } else {
                    panic!("{path}: schema neither declares properties nor values");
                }
            }
            Value::Array(items) => {
                if let Some(items_schema) = schema.get("items") {
                    for item in items {
                        // Array elements share one position: indices are folded
                        // so `steps[0]` and `steps[1]` aggregate together.
                        self.value(&format!("{}[]", strip_indices(path)), items_schema, item);
                    }
                }
            }
            _ => {}
        }
    }

    fn object(&mut self, path: &str, schema: &Value, map: &serde_json::Map<String, Value>) {
        let properties = schema["properties"].as_object().unwrap();
        let declared: BTreeSet<String> = properties.keys().cloned().collect();
        let required = string_set(schema["required"].as_array());
        for (key, value) in map {
            let child_schema = properties
                .get(key)
                .unwrap_or_else(|| panic!("{path}: field '{key}' is emitted but not declared"));
            self.value(&format!("{path}.{key}"), child_schema, value);
        }
        let position = self.positions.entry(path.to_string()).or_default();
        position.declared = declared;
        position.required = required;
        position.minimal_exact = self.minimal;
        position.emitted.extend(map.keys().cloned());
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{path}: a struct with deny_unknown_fields must say additionalProperties: false"
        );
    }

    fn check(self, label: &str) {
        assert!(!self.positions.is_empty(), "{label}: nothing was walked");
        for position in self.positions.values() {
            let missing: BTreeSet<_> = position
                .emitted
                .difference(&position.declared)
                .cloned()
                .collect();
            assert!(
                missing.is_empty(),
                "{}: emitted by Rust, absent from the schema: {missing:?}",
                position.path
            );
            if self.minimal {
                assert_eq!(
                    position.required, position.emitted,
                    "{}: `required` must be exactly what survives when every option is absent",
                    position.path
                );
            } else {
                let unemitted: BTreeSet<_> = position
                    .declared
                    .difference(&position.emitted)
                    .cloned()
                    .collect();
                assert!(
                    unemitted.is_empty(),
                    "{}: declared in the schema but never emitted by Rust: {unemitted:?}",
                    position.path
                );
                let absent: BTreeSet<_> = position
                    .required
                    .difference(&position.emitted)
                    .cloned()
                    .collect();
                assert!(
                    absent.is_empty(),
                    "{}: schema-required fields never present: {absent:?}",
                    position.path
                );
            }
        }
    }
}

/// Fold array indices so all elements of one list share a position.
fn strip_indices(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            while let Some(&next) = chars.peek() {
                chars.next();
                if next == ']' {
                    break;
                }
            }
            out.push_str("[]");
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn rust_types_and_schema_agree_on_the_full_document() {
    let value = serde_json::to_value(sample::full()).unwrap();
    let mut walker = Walker::new(false);
    walker.value("manifest", run_manifest_schema(), &value);
    walker.check("full manifest");
}

#[test]
fn rust_types_and_schema_agree_on_required_fields() {
    let value = serde_json::to_value(sample::minimal()).unwrap();
    let mut walker = Walker::new(true);
    walker.value("manifest", run_manifest_schema(), &value);
    walker.check("minimal manifest");
}

#[test]
fn the_envelope_schema_matches_the_rust_envelope() {
    let value = serde_json::to_value(AttestationDoc::new(sample::full())).unwrap();
    let mut walker = Walker::new(false);
    walker.value("doc", attestation_doc_schema(), &value);
    walker.check("attestation document");
}

#[test]
fn patterns_are_pinned() {
    // Every `pattern` in both schemas, reviewed as a set: loosening one is a
    // compatibility decision and has to show up here.
    let mut found = BTreeSet::new();
    collect_patterns(run_manifest_schema(), &mut found);
    collect_patterns(attestation_doc_schema(), &mut found);
    let expected: BTreeSet<String> = [
        r"^sha256:[0-9a-f]{64}$",
        r"^(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$",
        r"^[0-9a-f]{16,64}$",
        r"^[a-z0-9_][a-z0-9_.]{0,63}$",
        r"^SHA256:[A-Za-z0-9+/]{43}$",
        r"^ssh-ed25519 [A-Za-z0-9+/]{68}$",
        r"^[A-Za-z0-9+/]{86}==$",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(found, expected, "schema patterns changed");

    assert!(RUN_MANIFEST_SCHEMA.contains(r"^sha256:[0-9a-f]{64}$"));
    assert!(ATTESTATION_DOC_SCHEMA.contains(r"^ssh-ed25519 "));
}

/// Paths of every non-integer number in a parsed document.
fn floats(value: &Value) -> Vec<String> {
    fn walk(value: &Value, path: &str, out: &mut Vec<String>) {
        match value {
            Value::Number(number) => {
                if number.as_i64().is_none() && number.as_u64().is_none() {
                    out.push(path.to_string());
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    walk(item, &format!("{path}.{key}"), out);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "$", &mut out);
    out
}

fn collect_patterns(node: &Value, out: &mut BTreeSet<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "pattern" {
                    if let Some(text) = value.as_str() {
                        out.insert(text.to_string());
                    }
                } else {
                    collect_patterns(value, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_patterns(item, out);
            }
        }
        _ => {}
    }
}

#[test]
fn the_sorted_list_rules_are_the_ones_validate_enforces() {
    // `x-gitiup-sorted` is documentation (JSON Schema cannot express ordering), so
    // it must name exactly the lists `RunManifest::validate()` refuses when
    // unsorted. Add a sorted list and both sides have to change together.
    let mut annotated = BTreeSet::new();
    collect_annotated(run_manifest_schema(), "manifest", &mut annotated);
    let enforced: BTreeSet<String> = [
        "manifest.result.secret_names",
        "manifest.result.reusable_workflows",
        "manifest.result.environment.toolchain",
        "manifest.result.steps[].artifacts",
        "manifest.claims.normalisation_diffs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(annotated, enforced, "sortedness annotations drifted");

    // And the enforcement is real, for each one.
    let mut manifest = sample::full();
    manifest.result.secret_names.reverse();
    assert!(manifest.validate().is_err());

    let mut manifest = sample::full();
    let dupe = manifest.result.reusable_workflows[0].clone();
    manifest.result.reusable_workflows.push(dupe);
    assert!(manifest.validate().is_err());

    let mut manifest = sample::full();
    manifest.result.environment.toolchain.reverse();
    assert!(manifest.validate().is_err());

    let mut manifest = sample::full();
    let dupe = manifest.result.steps[1].artifacts[0].clone();
    manifest.result.steps[1].artifacts.push(dupe);
    assert!(manifest.validate().is_err());

    let mut manifest = sample::full();
    manifest.claims.normalisation_diffs.reverse();
    assert!(manifest.validate().is_err());
}

/// Like [`resolve`], but keeps the path so annotations can be named by position.
fn collect_annotated(node: &Value, path: &str, out: &mut BTreeSet<String>) {
    let node = resolve(node);
    let Some(map) = node.as_object() else { return };
    if map.contains_key("x-gitiup-sorted") && !path.is_empty() {
        out.insert(path.to_string());
    }
    if let Some(properties) = map.get("properties").and_then(Value::as_object) {
        for (key, value) in properties {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            collect_annotated(value, &child, out);
        }
    }
    if let Some(items) = map.get("items") {
        let child = if path.is_empty() {
            "[]".to_string()
        } else {
            format!("{}[]", strip_indices(path))
        };
        collect_annotated(items, &child, out);
    }
}

#[test]
fn no_null_and_no_float_survive_a_round_trip() {
    // The schema forbids them; the canonicaliser cannot emit them. Both halves of
    // that claim are cheap to prove here.
    for manifest in [sample::minimal(), sample::simulated(), sample::full()] {
        let bytes = manifest.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("null"), "a null leaked: {text}");
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(floats(&value).is_empty(), "a float leaked: {text}");
        assert!(canon::is_canonical(&bytes));
        assert_eq!(RunManifest::from_canonical_bytes(&bytes).unwrap(), manifest);
    }
}

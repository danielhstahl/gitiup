//! [ADR-0005's federation vectors](../../../../docs/adr/fixtures/federation-v1/README.md),
//! run by the Rust side.
//!
//! [`generate.py`](../../../../docs/adr/fixtures/federation-v1/generate.py) is the
//! executable half of the ADR: it emits `portable.json` (which namespaces travel, which
//! are refused, by which token) and `cases.json` (the closure cases and the refusal
//! table), and its `--check-ad` proves the ADR's prose and those files say the same
//! thing. This file proves the third leg: that the Rust table the transport actually
//! uses — the one `gitiup fetch` and `gitiup push` consult for every ref they see — says
//! the same thing as the data.
//!
//! Without this, two tickets can ship two portability tables. The ADR's own reason for
//! existing is that they would: one copies `refs/gitiup/**` because it is one prefix, the
//! other imports an attestation without its verdict because that was the ref it was asked
//! for, and a `fetch` that ships a rumour and an `import` that refuses one are the same
//! bug seen from opposite ends of the wire.
//!
//! The closure cases themselves belong to `gitiup attest import` (the walk with its
//! edges and its budgets); what this file checks here is the *scope* half they and the
//! transport share, plus the budgets and the refusal vocabulary.

use std::collections::BTreeMap;
use std::path::PathBuf;

use gitiup_host::RefName;
use gitiup_host::blob::Namespace;
use gitiup_host::federation::{
    Budgets, Class, REFUSALS, classify, exit_for, knows_token, namespace_travels, portable,
};

/// Where the vectors live.
fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/fixtures/federation-v1")
        .canonicalize()
        .expect("the federation vectors are part of the repository")
}

/// Read one of the generated files.
fn read(name: &str) -> serde_json::Value {
    let path = fixtures().join(name);
    let text = std::fs::read_to_string(&path).expect("read the vector file");
    serde_json::from_str(&text).expect("the vector file is JSON")
}

/// An example ref name per ADR row, keyed by the row's `display` (which is the same
/// string in `portable.json`, so a row that changes there fails here too).
///
/// `Ref(name)` is classified as a ref, `Ns(kind)` as a content-addressed namespace, and
/// `Thing(name)` as store furniture — the three kinds of question the table answers.
enum Probe {
    Ref(&'static str),
    Ns(&'static str),
    Thing(&'static str),
}

/// Every row in the fixture, in the fixture's order.
const PROBES: &[(&str, Probe)] = &[
    (
        "`refs/attestations/<subject>/<digest>` → `kv/attestation/<hex>`",
        Probe::Ref(
            "refs/attestations/a1b2c3d4e5f60718293a4b5c6d7e8f9012345678/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ),
    ),
    (
        "`refs/changes/<id>/attempt/<n>` → `kv/change/<hex>`",
        Probe::Ref("refs/changes/chg-6a6a8eab778ba4d0/attempt/0"),
    ),
    (
        "`refs/changes/<id>/head`",
        Probe::Ref("refs/changes/chg-6a6a8eab778ba4d0/head"),
    ),
    (
        "`refs/changes/<id>/{merged,abandoned}` → `kv/merge\\|abandon/<hex>`",
        Probe::Ref("refs/changes/chg-6a6a8eab778ba4d0/merged"),
    ),
    ("`refs/heads/**`", Probe::Ref("refs/heads/main")),
    (
        "`refs/gitiup/roster/<epoch:08x>`",
        Probe::Ref("refs/gitiup/roster/00000007"),
    ),
    (
        "`refs/gitiup/roster` (no epoch)",
        Probe::Ref("refs/gitiup/roster"),
    ),
    (
        "`refs/gitiup/signup/<slot>`",
        Probe::Ref("refs/gitiup/signup/0000000000000001"),
    ),
    (
        "`refs/gitiup/withdrawal/<slot>`, `refs/gitiup/revocation/<slot>`",
        Probe::Ref("refs/gitiup/revocation/0000000000000001"),
    ),
    (
        "`refs/gitiup/round/<change>/<job>/<attempt>`",
        Probe::Ref("refs/gitiup/round/chg-6a6a8eab778ba4d0/build/0"),
    ),
    (
        "`refs/gitiup/job/<change>/<job>`",
        Probe::Ref("refs/gitiup/job/chg-6a6a8eab778ba4d0/build"),
    ),
    (
        "`refs/gitiup/lease/<change>/<job>/<slot>`",
        Probe::Ref("refs/gitiup/lease/chg-6a6a8eab778ba4d0/build/0000000000000001"),
    ),
    (
        "`refs/gitiup/commit/…`, `refs/gitiup/reveal/…`",
        Probe::Ref("refs/gitiup/reveal/chg-6a6a8eab778ba4d0/build/0000000000000001"),
    ),
    (
        "`refs/gitiup/verdict/<change>/<job>`",
        Probe::Ref("refs/gitiup/verdict/chg-6a6a8eab778ba4d0/build"),
    ),
    (
        "`refs/gitiup/policy/history/<rev>`",
        Probe::Ref("refs/gitiup/policy/history/000002"),
    ),
    (
        "`refs/gitiup/policy/current`",
        Probe::Ref("refs/gitiup/policy/current"),
    ),
    (
        "`refs/gitiup/kv/**` (the chain commits)",
        Probe::Ref("refs/gitiup/kv/attestation"),
    ),
    (
        "`kv/import/<digest>`, `kv/gc/<digest>`",
        Probe::Ns("import"),
    ),
    (
        "ref caches, tombstones, pack layout, `host.json`, trust roots, `gitiup.toml`",
        Probe::Thing("host.json"),
    ),
];

/// Ask the Rust side the question one fixture row asks, in whatever form it asked it.
fn rust_answer(probe: &Probe) -> (String, bool, Option<String>, Option<String>) {
    match probe {
        Probe::Ref(name) => {
            let decision = classify(&RefName::new(*name).expect("probe ref"));
            (
                decision.class().as_str().to_string(),
                decision.portable,
                decision.row.kind.map(str::to_string),
                decision.row.token.map(str::to_string),
            )
        }
        Probe::Ns(namespace) => {
            let namespace = Namespace::new(*namespace).expect("probe namespace");
            let portable = namespace_travels(&namespace);
            (
                if portable { "proof" } else { "local" }.to_string(),
                portable,
                None,
                if portable {
                    None
                } else {
                    Some("not_portable".to_string())
                },
            )
        }
        Probe::Thing(what) => {
            let decision = portable::classify_local(what);
            (
                decision.class().as_str().to_string(),
                decision.portable,
                None,
                decision.row.token.map(str::to_string),
            )
        }
    }
}

#[test]
fn every_row_in_the_fixture_has_a_probe() {
    // A row added to the generated table without a probe here is exactly the drift this
    // test exists to catch, so it fails rather than going unasked.
    let table = read("portable.json");
    let rows = table["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        PROBES.len(),
        "the fixture has {} rows and this test probes {}",
        rows.len(),
        PROBES.len()
    );
    for row in rows {
        let display = row["display"].as_str().expect("display");
        assert!(
            PROBES.iter().any(|(name, _)| *name == display),
            "`{display}` is in portable.json and has no probe in this test"
        );
    }
    for (display, _) in PROBES {
        assert!(
            rows.iter()
                .any(|row| row["display"].as_str() == Some(display)),
            "this test probes `{display}`, which portable.json has no row for"
        );
    }
}

#[test]
fn the_rust_table_and_the_generated_table_agree() {
    let table = read("portable.json");
    let mut checked = 0usize;
    for row in table["rows"].as_array().expect("rows") {
        let display = row["display"].as_str().expect("display");
        let probe = PROBES
            .iter()
            .find(|(name, _)| *name == display)
            .map(|(_, probe)| probe)
            .expect("probed by the test above");
        let (class, portable_row, kind, token) = rust_answer(probe);
        assert_eq!(
            class,
            row["class"].as_str().expect("class"),
            "class disagrees for `{display}`"
        );
        assert_eq!(
            portable_row,
            row["portable"].as_bool().expect("portable"),
            "portability disagrees for `{display}`"
        );
        let want_token = row["token"].as_str().map(str::to_string);
        assert_eq!(
            token, want_token,
            "the refusal token disagrees for `{display}`"
        );
        let want_kind = row["kind"].as_str().map(str::to_string);
        assert_eq!(kind, want_kind, "the record kind disagrees for `{display}`");
        checked += 1;
    }
    assert!(checked > 10, "the table was not really compared");
}

#[test]
fn the_kind_to_class_map_agrees_too() {
    // `portable.json:kinds` is the same rule one level up: a record kind and the class
    // it belongs to. `code` is the one kind no ref row uses — a proof's subject is a git
    // object, and it travels with the code or not at all.
    let table = read("portable.json");
    let kinds = table["kinds"].as_object().expect("kinds");
    for row in portable::TABLE {
        let Some(kind) = row.kind else { continue };
        let want = kinds
            .get(kind)
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("`{kind}` is a Rust row's kind and not a fixture kind"));
        assert_eq!(
            want,
            row.class.as_str(),
            "kind `{kind}` is class {} in Rust and {want} in the fixture",
            row.class.as_str()
        );
    }
}

#[test]
fn the_budgets_are_the_advertised_ones() {
    let table = read("portable.json");
    let budgets = &table["budgets"];
    let rust = Budgets::default();
    assert_eq!(rust.records, budgets["records"].as_u64().unwrap() as usize);
    assert_eq!(rust.depth, budgets["depth"].as_u64().unwrap() as usize);
    assert_eq!(
        rust.policy_chain,
        budgets["policy_chain"].as_u64().unwrap() as usize
    );
    assert_eq!(rust.bytes, budgets["bytes"].as_u64().unwrap());
}

#[test]
fn every_token_this_build_can_name_is_in_the_refusal_table() {
    // The reverse of the generator's own selftest, from this side: a token in the Rust
    // table that `cases.json` does not list is a refusal no tool knows how to read.
    let cases = read("cases.json");
    let listed: BTreeMap<String, u8> = cases["refusals"]
        .as_array()
        .expect("refusals")
        .iter()
        .map(|entry| {
            (
                entry["token"].as_str().expect("token").to_string(),
                entry["exit"].as_u64().expect("exit") as u8,
            )
        })
        .collect();
    for (token, exit) in REFUSALS {
        assert!(knows_token(token), "{token} is not registered");
        assert_eq!(exit_for(token), *exit, "{token}'s exit code");
        assert_eq!(
            listed.get(*token),
            Some(exit),
            "`{token}` is a Rust refusal the fixture's table does not carry"
        );
    }
}

#[test]
fn the_principle_and_the_unit_are_written_down_in_both_places() {
    // Cheap to check, and it is the sentence a reviewer who skips the tables needs.
    let table = read("portable.json");
    let principle = table["principle"].as_str().expect("principle");
    assert!(principle.contains("closure"));
    assert!(principle.contains("never travels"));
    assert_eq!(
        table["unit"].as_str().expect("unit"),
        "record + advertisement, bytes first (D1, D8)"
    );
    assert_eq!(table["adr"].as_str().expect("adr"), "ADR-0005");
}

#[test]
fn a_portable_closure_never_reaches_arbitration_state() {
    // The property `generate.py --selftest` proves for the fixture graph, restated over
    // this table: no *portable* row's kind is a state class. If a future row is portable
    // and its kind is one the fixture calls `state`, D1 has stopped being a rule.
    let kinds = read("portable.json")["kinds"]
        .as_object()
        .expect("kinds")
        .clone();
    let mut states: Vec<&str> = Vec::new();
    for (kind, class) in &kinds {
        if class.as_str() == Some("state") {
            states.push(kind.as_str());
        }
    }
    assert!(
        !states.is_empty(),
        "the fixture names no state kinds at all"
    );
    for row in portable::TABLE {
        if let Some(kind) = row.kind
            && states.contains(&kind)
        {
            assert!(
                !row.portable,
                "`{kind}` is arbitration state and row `{}` marks it portable",
                row.display
            );
            assert_eq!(row.class, Class::State, "`{kind}` is not a state row");
        }
    }
}

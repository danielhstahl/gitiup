//! `gitiup policy …`, run as the real binary (giti-91m.2).
//!
//! The acceptance criteria for this ticket are command lines — *publish a policy to a
//! store*, *read it back*, *`--dry-run` refuses to write anything*, *a policy that
//! contradicts itself is refused at publish* — so they are tested here as command lines
//! against the built executable: a temp config home and a temp store per harness, a real
//! keystore with a real key, and every assertion read from `--json`. Each command runs in
//! a new process, so what survives between them is what the **store** holds, which is the
//! whole claim of ADR-0004 D7 (and D4's provenance is the other half, which a library test
//! could only assert as "what a function returned").
//!
//! The `fs` host is enough here: the library tests (`gitiup-quorum`'s `policy_vectors`
//! and `policy_store`) cover the format and the store semantics; the CLI's own job is the
//! composition — keystore, store resolution, exit codes, and what gets printed.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

/// The passphrase every harness uses, supplied the only way a script can.
const PASSPHRASE: &str = "four random words";
/// The zero digest: a store's first policy has no predecessor (ADR-0004 D6).
const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A config home, a store directory, and the binary pointed at both.
struct Harness {
    dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            dir: tempfile::tempdir().expect("a temp home"),
        }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    fn store(&self) -> String {
        self.path()
            .join("store")
            .to_str()
            .expect("utf-8")
            .to_string()
    }

    /// Write a file in the working directory and return its path.
    fn write(&self, name: &str, body: &Value) -> String {
        let path = self.path().join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(body).expect("json"))
            .expect("write the file");
        path.to_str().expect("utf-8").to_string()
    }

    /// Run the binary with this home. The working directory is the temp dir, so a
    /// `gitiup-policy.json` is only found if the test wrote one, and `SSH_AUTH_SOCK`
    /// points where it cannot exist so no test can depend on the developer's agent.
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.run_env(args, stdin, &[])
    }

    fn run_env(&self, args: &[&str], stdin: Option<&str>, extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gitiup"));
        command
            .args(args)
            .env("GITIUP_CONFIG_HOME", self.path().join("cfg"))
            .env("GITIUP_KEY_PASSPHRASE", PASSPHRASE)
            .env("SSH_AUTH_SOCK", self.path().join("no-such-agent"))
            .env_remove("GITIUP_PASSPHRASE")
            .env_remove("GITIUP_CONFIG")
            .env_remove("GITIUP_POLICY")
            .env_remove("GITIUP_REMOTE")
            .current_dir(self.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra {
            command.env(key, value);
        }
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().expect("the binary runs");
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(text.as_bytes())
                .expect("write stdin");
        }
        child.wait_with_output().expect("wait")
    }

    fn key(&self, name: &str) {
        let output = self.run(
            &["key", "gen", "--name", name],
            Some(&format!("{PASSPHRASE}\n")),
        );
        assert!(
            output.status.success(),
            "`key gen {name}` failed: {}",
            stderr(&output)
        );
    }

    /// A key's fingerprint, as the keystore recorded it.
    fn key_id(&self, name: &str) -> String {
        let output = self.ok(&["key", "show", name, "--json"]);
        json(&output)["key_id"]
            .as_str()
            .expect("a key id")
            .to_string()
    }

    /// Run a command that must succeed, or fail loudly with everything it said.
    fn ok(&self, args: &[&str]) -> Output {
        let output = self.run(args, None);
        assert!(
            output.status.success(),
            "`gitiup {}` failed: {}{}",
            args.join(" "),
            stdout(&output),
            stderr(&output)
        );
        output
    }

    /// What the store advertises at `refs/gitiup/policy/current`, read straight off the
    /// store's own ref file: the point of D7 is that a policy is an ordinary ref in an
    /// ordinary store, so an ordinary tool can see whether the CLI wrote one — and
    /// whether it wrote it twice.
    fn advertised(&self, reference: &str) -> Option<String> {
        let refs = std::fs::read_to_string(Path::new(&self.store()).join("refs")).ok()?;
        for line in refs.lines() {
            if line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(oid), Some(name)) = (fields.next(), fields.next()) else {
                continue;
            };
            if name == reference {
                return Some(oid.to_string());
            }
        }
        None
    }

    fn policy_ref(&self) -> Option<String> {
        self.advertised("refs/gitiup/policy/current")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output)).expect("the --json output is JSON")
}

/// Every note the report carried, as one string, so an assertion can quote the sentence.
fn notes(provenance: &Value) -> String {
    provenance["notes"]
        .as_array()
        .map(|notes| {
            notes
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default()
}

/// The smallest document an operator would write: rules that mean something, and no
/// chain position or owner, because publish fills those in from the store and the key.
fn document(tiers: &[&str]) -> Value {
    json!({
        "type": "gitiup-policy-1",
        "schema_version": 1,
        "owner": { "key_id": "", "principal": "" },
        "revision": 1,
        "previous_digest": GENESIS,
        "effective_from_us": 1,
        "protects": ["refs/heads/**"],
        "rules": { "allowed_tiers": tiers, "trust_key_ids": [] },
    })
}

/// The first publish, in the order the ticket states it: sign, check, write the store,
/// and say where it landed.
#[test]
fn publish_signs_a_policy_files_it_in_the_store_and_says_where_it_landed() {
    let harness = Harness::new();
    harness.key("ada");
    let ada = harness.key_id("ada");
    let output = harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--key",
        "ada",
        "--principal",
        "Ada Hale",
        "--json",
    ]);
    let report = json(&output);
    assert_eq!(
        report["revision"], 1,
        "a store's first policy is revision 1"
    );
    assert_eq!(report["already"], false);
    assert_eq!(report["dry_run"], false);
    assert_eq!(
        report["owner"]["key_id"], ada,
        "the owner is who signed (D3)"
    );
    assert_eq!(report["owner"]["principal"], "Ada Hale");
    assert_eq!(report["trusted_key_ids"], json!([ada]));
    assert_eq!(report["previous_body_digest"], Value::Null);
    assert_eq!(report["protects"], json!(["refs/heads/**"]));
    for field in ["body_digest", "record_digest"] {
        assert!(
            report[field]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71),
            "{field}: {}",
            report[field]
        );
    }
    assert_ne!(
        report["body_digest"], report["record_digest"],
        "two digests, two questions: the signed body and the stored bytes (D2)"
    );
    assert_eq!(
        report["kv"],
        format!(
            "kv/policy/{}",
            report["record_digest"]
                .as_str()
                .unwrap()
                .split(':')
                .nth(1)
                .unwrap()
        ),
        "the bytes are filed under their own record digest (D7)"
    );
    assert_eq!(report["ref"], "refs/gitiup/policy/current");
    assert_eq!(report["history_ref"], "refs/gitiup/policy/history/000001");

    // The ref is really there, in the store, where a clone can fetch it — not in a
    // checkout, and not only in this process.
    let hex = report["record_digest"]
        .as_str()
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap();
    assert_eq!(harness.policy_ref().as_deref(), Some(hex));
}

/// Read it back: which policy is in force, from where, and whether a merge may rest on it.
#[test]
fn show_reports_which_policy_is_in_force_and_what_it_was_decided_from() {
    let harness = Harness::new();
    harness.key("ada");
    let ada = harness.key_id("ada");
    let published = json(&harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--allow-tier",
        "simulated",
        "--trust",
        "ada",
        "--json",
    ]));
    let output = harness.ok(&["policy", "show", "--store", &harness.store(), "--json"]);
    let report = json(&output);
    let provenance = &report["policy"];
    assert_eq!(provenance["source"], "store");
    assert_eq!(provenance["ref"], "refs/gitiup/policy/current");
    assert_eq!(provenance["revision"], 1);
    assert_eq!(provenance["body_digest"], published["body_digest"]);
    assert_eq!(provenance["record_digest"], published["record_digest"]);
    assert_eq!(provenance["kv"], published["kv"]);
    assert_eq!(provenance["signed_by"], ada);
    assert_eq!(provenance["at_from"], "now");
    assert_eq!(
        report["policy"]["gate_eligible"], true,
        "the store is the gate-eligible source (D4)"
    );
    assert_eq!(report["purpose"], "gate-eligible");
    // The rules arrived as rules, not as a blob: `allowed_tiers` is what a gate checks.
    assert_eq!(
        report["rules"]["allowed_tiers"],
        json!(["local", "simulated"])
    );
    assert_eq!(report["rules"]["trust_key_ids"], json!([ada]));

    // The text form says the same thing in words a person reads, because D4 requires the
    // provenance to be *printed*, not merely available.
    let text = harness.ok(&["policy", "show", "--store", &harness.store()]);
    let printed = stdout(&text);
    assert!(printed.contains("policy: store revision 1"), "{printed}");
    assert!(printed.contains("body"), "{printed}");
    assert!(
        printed.contains("gate    yes: a merge may rest on this"),
        "{printed}"
    );

    // And as a gate, which is how a hook asks the question: exit 0 here.
    let gate = harness.run(
        &["policy", "show", "--store", &harness.store(), "--gate"],
        None,
    );
    assert_eq!(code(&gate), 0, "{}{}", stdout(&gate), stderr(&gate));
}

/// Two revisions, and the walk: a run from before the second one is judged by the first.
#[test]
fn a_second_revision_chains_to_the_first_and_an_old_run_still_gets_the_old_rules() {
    let harness = Harness::new();
    harness.key("ada");
    let first = json(&harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--json",
    ]));
    let second = json(&harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--allow-tier",
        "simulated",
        "--trust",
        "ada",
        "--json",
    ]));
    assert_eq!(second["revision"], 2);
    assert_eq!(
        second["previous_body_digest"], first["body_digest"],
        "the chain is the point: each revision names the one before (D6)"
    );

    let today = json(&harness.ok(&["policy", "show", "--store", &harness.store(), "--json"]));
    assert_eq!(today["policy"]["revision"], 2);
    assert_eq!(
        today["rules"]["allowed_tiers"],
        json!(["local", "simulated"])
    );

    // Judged as of before revision 2 took effect, the answer is revision 1 — and the
    // answer says the chain was walked, because "which rules were in force" is a
    // question the report has to be able to defend (D4, D6).
    let before = harness.ok(&[
        "policy",
        "show",
        "--store",
        &harness.store(),
        "--at",
        first["effective_from"].as_str().unwrap(),
        "--json",
    ]);
    let before = json(&before);
    assert_eq!(before["policy"]["revision"], 1);
    assert_eq!(before["policy"]["at_from"], "run-claim");
    assert_eq!(before["policy"]["body_digest"], first["body_digest"]);
    assert!(
        before["policy"]["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|note| note.as_str().unwrap_or_default().contains("walked")),
        "{before}"
    );
    assert_eq!(
        before["rules"]["allowed_tiers"],
        json!(["local"]),
        "and the rules are the ones from that revision, not today's"
    );
}

/// `--dry-run` refuses what publish refuses and writes nothing (D9).
#[test]
fn dry_run_says_no_without_touching_the_store_and_yes_without_writing_either() {
    let harness = Harness::new();
    harness.key("ada");

    // A policy that cannot be satisfied is refused before anything is written, and the
    // store is untouched afterwards: no half-published gate to reason about (D7, D9).
    let binding = harness.write("binding.json", &document(&["local"]));
    let mut hostile = document(&["local"]);
    // The vocabulary accepts a per-decision binding, and publish refuses it: one
    // vocabulary, checked at the moment it becomes an authority (D5).
    hostile["rules"]["expected_commit"] = json!("sha1:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678");
    let hostile = harness.write("hostile.json", &hostile);
    let refused = harness.run(
        &["policy", "publish", &hostile, "--store", &harness.store()],
        None,
    );
    assert_eq!(code(&refused), 6, "{}", stdout(&refused));
    assert!(
        stderr(&refused).contains("per_decision_binding"),
        "{}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("hint"),
        "a refusal that does not say what to do is a dead end: {}",
        stderr(&refused)
    );
    assert_eq!(harness.policy_ref(), None, "a refusal writes nothing");
    let _ = binding;

    // A sound policy is *accepted* by --dry-run, and still writes nothing.
    let dry = json(&harness.ok(&[
        "policy",
        "publish",
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--store",
        &harness.store(),
        "--dry-run",
        "--json",
    ]));
    assert_eq!(dry["revision"], 1);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        harness.policy_ref(),
        None,
        "--dry-run that moved the ref would be the most expensive kind of lie"
    );

    // ...and the real publish after it works, and says the same digest: the dry run told
    // the truth about what would happen. `--out` keeps the exact bytes that were signed,
    // which is what makes a retry auditable instead of hopeful.
    let real = json(&harness.ok(&[
        "policy",
        "publish",
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--store",
        &harness.store(),
        "--out",
        "revision-1.json",
        "--effective-from",
        dry["effective_from"].as_str().unwrap(),
        "--json",
    ]));
    assert_eq!(real["dry_run"], false);
    assert_eq!(
        real["body_digest"], dry["body_digest"],
        "the same policy, named twice: the dry run's digest is the one that got filed"
    );
    assert!(harness.policy_ref().is_some());

    // Publishing *exactly what the store already advertises* is an idempotent retry, not
    // a new revision: the same signed document, named twice, changes nothing (D8). It
    // cannot be an error and it cannot silently be revision 2 — a verdict that cited this
    // digest would stop resolving otherwise.
    let republish = harness.run(
        &[
            "policy",
            "publish",
            "revision-1.json",
            "--store",
            &harness.store(),
            "--trust",
            "ada",
            "--json",
        ],
        None,
    );
    assert_eq!(
        code(&republish),
        0,
        "{}{}",
        stdout(&republish),
        stderr(&republish)
    );
    let again = json(&republish);
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(again["revision"], 1);
    assert_eq!(again["body_digest"], real["body_digest"]);
    let republish = harness.run(
        &[
            "policy",
            "publish",
            "revision-1.json",
            "--store",
            &harness.store(),
            "--trust",
            "ada",
            "--key",
            "ada",
            "--json",
        ],
        None,
    );
    assert_eq!(
        code(&republish),
        0,
        "{}{}",
        stdout(&republish),
        stderr(&republish)
    );
    let again = json(&republish);
    assert_eq!(again["already"], true, "{again}");
    assert_eq!(again["revision"], 1);
    assert_eq!(again["body_digest"], real["body_digest"]);
}

/// Every way a policy can be believed by the wrong person, refused by name (D3, D9).
#[test]
fn a_policy_is_only_as_trusted_as_the_roots_the_reader_brings() {
    let harness = Harness::new();
    harness.key("ada");
    harness.key("bob");
    let bob = harness.key_id("bob");
    harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--key",
        "ada",
        "--json",
    ]);

    // Bob's configuration does not believe Ada's key, so Ada's policy is not a rule
    // there. This is the exact attack D3 exists for: the policy is in the store, it is
    // well-formed, it is signed — and it is still refused, because trust is the
    // reader's, not the document's.
    let refused = harness.run(
        &[
            "policy",
            "show",
            "--store",
            &harness.store(),
            "--trust",
            "bob",
        ],
        None,
    );
    assert_eq!(code(&refused), 6);
    assert!(stderr(&refused).contains("signer_untrusted"));
    let report = harness.run(
        &[
            "policy",
            "show",
            "--store",
            &harness.store(),
            "--trust",
            "bob",
            "--json",
        ],
        None,
    );
    assert_eq!(json(&report)["refused"]["token"], "signer_untrusted");
    assert_eq!(json(&report)["exit_code"], 6);

    // Bob may publish his own, and then his own roots believe it: the refusal is about
    // who the reader trusts, and a fork gets exactly as much authority as its readers
    // gave it — never more, and never less.
    let forked = harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--key",
        "bob",
        "--trust",
        "bob",
        "--json",
    ]);
    assert_eq!(code(&forked), 0, "{}{}", stdout(&forked), stderr(&forked));
    let mine = harness.run(
        &[
            "policy",
            "show",
            "--store",
            &harness.store(),
            "--trust",
            "bob",
            "--json",
        ],
        None,
    );
    assert_eq!(json(&mine)["policy"]["signed_by"], bob);

    // The owner field and the signing key have to agree, or the trust check would be
    // consulting a claim instead of a fact.
    let mut named = document(&["local"]);
    named["owner"]["key_id"] = json!("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let named = harness.write("named.json", &named);
    let refused = harness.run(
        &[
            "policy",
            "publish",
            &named,
            "--store",
            &harness.store(),
            "--key",
            "ada",
        ],
        None,
    );
    assert_eq!(code(&refused), 6, "{}", stdout(&refused));
    assert!(stderr(&refused).contains("but the key signing it is"));
}

/// The local sources, and the line between an answer and an authority (D1, D4).
#[test]
fn a_tree_file_is_a_draft_a_flag_is_an_act_and_nothing_published_is_a_refusal_for_a_gate() {
    let harness = Harness::new();
    harness.key("ada");
    let ada = harness.key_id("ada");

    // Nothing published, asked as a question: this build's default answers, and says it
    // is only an answer.
    let nothing = harness.ok(&["policy", "show", "--json"]);
    let report = json(&nothing);
    assert_eq!(report["policy"]["source"], "built-in-default");
    assert_eq!(report["policy"]["gate_eligible"], false);
    assert_eq!(report["purpose"], "not gate-eligible");

    // Asked as a gate, the same situation is a refusal: no merge happens on a default
    // nobody chose (D4).
    let gate = harness.run(&["policy", "show", "--gate"], None);
    assert_eq!(code(&gate), 6);
    assert!(stderr(&gate).contains("no_policy_published"));

    // Source 3: the tree file. A draft: it answers, and it is never gate-eligible,
    // because editing a file is not publishing a policy — which is the whole of D1 and
    // the reason a fork's edit cannot become a rule by being committed.
    let draft = harness.write(
        "gitiup-policy.json",
        &json!({ "allowed_tiers": ["local", "simulated"], "trust_key_ids": [ada] }),
    );
    let draft_json = harness.ok(&["policy", "show", "--json"]);
    assert_eq!(
        json(&draft_json)["policy"]["source"],
        "tree-file",
        "{draft}"
    );
    assert_eq!(json(&draft_json)["policy"]["gate_eligible"], false);
    let gate = harness.run(&["policy", "show", "--gate"], None);
    assert_eq!(code(&gate), 6, "a draft does not make a gate");
    assert!(stderr(&gate).contains("no_policy_published"));

    // Sources 1 and 2: `--policy` and `$GITIUP_POLICY` are an operator's act, are
    // gate-eligible, and say they overrode what was published.
    let stricter = harness.write(
        "stricter.json",
        &json!({ "allowed_tiers": ["local"], "trust_key_ids": [ada], "max_age_us": 60_000_000 }),
    );
    harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--json",
    ]);
    let overridden = harness.ok(&[
        "policy",
        "show",
        "--store",
        &harness.store(),
        "--policy",
        &stricter,
        "--json",
    ]);
    let report = json(&overridden);
    assert_eq!(report["policy"]["source"], "--policy");
    assert_eq!(report["policy"]["gate_eligible"], true);
    assert_eq!(report["rules"]["max_age_us"], 60_000_000);
    let said = notes(&report["policy"]);
    assert!(said.contains("override nobody published"), "{said}");
    assert!(
        said.contains("it overrode the published policy sha256:"),
        "{said}"
    );

    // The environment spelling of the same act.
    let from_env = harness.run_env(
        &["policy", "show", "--store", &harness.store(), "--json"],
        None,
        &[("GITIUP_POLICY", &stricter)],
    );
    assert_eq!(code(&from_env), 0, "{}", stderr(&from_env));
    assert_eq!(json(&from_env)["policy"]["source"], "$GITIUP_POLICY");

    // And with a policy published, the tree file's difference is said out loud: the one
    // line that answers "why did my change not obey the rule I just edited?" (D1).
    let in_force = harness.ok(&["policy", "show", "--store", &harness.store(), "--json"]);
    let said = notes(&json(&in_force)["policy"]);
    assert!(said.contains("editing a file is not publishing"), "{said}");
    assert_eq!(json(&in_force)["policy"]["source"], "store");
}

/// Two owners, one publisher: the loser is told, and nothing is dropped (D8).
#[test]
fn two_owners_publishing_at_once_produce_one_loser_and_no_lost_revision() {
    let harness = Harness::new();
    harness.key("ada");
    let first = json(&harness.ok(&[
        "policy",
        "publish",
        "--store",
        &harness.store(),
        "--allow-tier",
        "local",
        "--trust",
        "ada",
        "--json",
    ]));
    // Someone else published in between: this publish believes `current` still advertises
    // the first digest, and it does not.
    let second_run = harness.run(
        &[
            "policy",
            "publish",
            "--allow-tier",
            "local",
            "--trust",
            "ada",
            "--store",
            &harness.store(),
            "--expect-current",
            first["body_digest"].as_str().unwrap(),
            "--json",
        ],
        None,
    );
    // The publish above is the *first* rival: it wins, because it is the second publish
    // and `current` still advertises revision 1 at the moment it reads. So the guard has
    // to be demonstrated with a belief that is already stale.
    assert_eq!(
        code(&second_run),
        0,
        "{}{}",
        stdout(&second_run),
        stderr(&second_run)
    );
    let second = json(&second_run);
    let stale = harness.run(
        &[
            "policy",
            "publish",
            "--allow-tier",
            "local",
            "--allow-tier",
            "simulated",
            "--trust",
            "ada",
            "--store",
            &harness.store(),
            "--expect-current",
            first["body_digest"].as_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert_eq!(code(&stale), 6, "{}", stdout(&stale));
    assert!(stderr(&stale).contains("chain_broken"));
    assert_eq!(json(&stale)["refused"]["token"], "chain_broken");
    // And the store says exactly what it holds, so the loser is not left guessing.
    let now = harness.ok(&["policy", "show", "--store", &harness.store(), "--json"]);
    assert_eq!(json(&now)["policy"]["revision"], 2);
    assert_eq!(
        json(&now)["policy"]["body_digest"],
        second["body_digest"],
        "the winner's bytes are what `current` advertises"
    );
}

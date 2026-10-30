//! The migration's own record: what this run has finished, so that the next run of the
//! same command continues instead of starting again.
//!
//! Everything the migration writes is create-only, so it is *already* idempotent in the
//! store — a re-run moves nothing and says `already`. What idempotence does not give you is
//! **resumption**: re-walking a 40 GB mirror's object lists to rediscover that the store has
//! them is slower than the original copy, and re-asking the forge for ten thousand check runs
//! after the quota reset has already been spent is the second half of the same mistake. So
//! the run keeps a journal, and the journal is what makes "resume from where it stopped"
//! mean *continue* rather than *repeat*.
//!
//! ```text
//! { "type": "gitiup-migrate-1", "from": "github:gitiup/mock", "to": "fs store ./store",
//!   "done": ["ref:refs/heads/main", "objects:refs/heads/main", "pull:12"], … }
//! ```
//!
//! Three rules keep it honest:
//!
//! * **A journal is a speed-up, never an authority.** Every step is still checked against
//!   the destination: a ref the journal claims is re-read and re-compared, so a journal that
//!   lies about a finished step cannot make a migration skip a ref that is not there.
//! * **Nothing is written to it that is not also in the report.** The journal at the end of a
//!   run is the manifest the run files in the destination, and the report is the same data
//!   formatted — three spellings of one account, not three accounts.
//! * **An unknown field is a refusal.** A journal written by a newer gitiup may describe
//!   steps this build cannot understand, and guessing which ones it may not skip is worse
//!   than asking for `--restart`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The document type, and the schema this build writes.
pub const JOURNAL_TYPE: &str = "gitiup-migrate-1";
/// The schema version.
pub const JOURNAL_SCHEMA: u32 = 1;

/// One thing that did not come, in the shape a journal and a JSON report can both hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropping {
    /// The token: `check_run_copy_truncated`, `pull_closed_unmerged`, …
    pub token: String,
    /// What kind of thing it is (`check-run`, `pull`, `ref`, `object`).
    pub class: String,
    /// Its name as the source spells it.
    pub name: String,
    /// Why, in the tool's own words.
    pub detail: String,
}

impl Dropping {
    /// One refusal, from a token constant.
    pub fn of(
        token: &str,
        class: &str,
        name: impl Into<String>,
        detail: impl Into<String>,
    ) -> Dropping {
        Dropping {
            token: token.to_string(),
            class: class.to_string(),
            name: name.into(),
            detail: detail.into(),
        }
    }

    /// The line a report prints.
    pub fn line(&self) -> String {
        format!("{:<28} {}  {}", self.token, self.name, self.detail)
    }
}

/// The counters a run keeps, so a resumed run's totals include the part it did not do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// Refs this migration wrote into the destination.
    pub refs_written: usize,
    /// Refs that already stood exactly where the source has them.
    pub refs_already: usize,
    /// Change records published.
    pub changes_published: usize,
    /// Merge records published (a merged pull's landing, recorded as `via: forge`).
    pub merges_published: usize,
    /// Attestations filed.
    pub proofs_carried: usize,
    /// Attestations the destination already held, byte for byte.
    pub proofs_already: usize,
    /// Git objects handed to the destination.
    pub objects: usize,
    /// Bytes those objects took.
    pub object_bytes: u64,
}

/// What a run has done, and where it stopped.
#[derive(Debug, Clone)]
pub struct Journal {
    /// `gitiup-migrate-1`.
    pub doc_type: String,
    /// The schema this build writes.
    pub schema_version: u32,
    /// The run this journal belongs to, in one line (`github:o/r → s3://bucket/repo`).
    pub spec: String,
    /// A filesystem-safe name for that spec, used for the default path and the store ref.
    pub slug: String,
    /// The source, described.
    pub from: String,
    /// The destination, described.
    pub to: String,
    /// The git endpoint the history came from, when history was asked for.
    pub git_url: Option<String>,
    /// Where this journal file lives (not part of the stored document).
    pub path: Option<String>,
    /// Microseconds the run started (first run, not this resumption).
    pub started_us: i64,
    /// Microseconds of the last write.
    pub updated_us: i64,
    /// Every finished step, by key (`ref:<name>`, `objects:<name>`, `pull:<n>`,
    /// `proof:<digest>`).
    pub done: BTreeSet<String>,
    /// Ref tips whose objects have been delivered — the `--not` set for the next unit.
    pub delivered: Vec<String>,
    /// Every ref this run wrote: name → oid.
    pub refs: BTreeMap<String, String>,
    /// Every commit whose bytes are in the destination: git oid → the store digest its
    /// bytes were filed under. This is what makes the verification a *read* and not a
    /// memory: the command asks the store for these bytes and re-hashes what comes back.
    pub commits: BTreeMap<String, String>,
    /// Every proof carried: attestation digest → the commit it is about.
    pub proofs: BTreeMap<String, String>,
    /// Everything that did not come, with its token.
    pub dropped: Vec<Dropping>,
    /// The tallies.
    pub counters: Counters,
    /// Whether a run finished the whole plan (a re-run of a finished migration is a check).
    pub finished: bool,
}

impl Journal {
    /// A fresh journal for one run.
    pub fn new(spec: String, slug: String, from: String, to: String, now_us: i64) -> Journal {
        Journal {
            doc_type: JOURNAL_TYPE.to_string(),
            schema_version: JOURNAL_SCHEMA,
            spec,
            slug,
            from,
            to,
            git_url: None,
            path: None,
            started_us: now_us,
            updated_us: now_us,
            done: BTreeSet::new(),
            delivered: Vec::new(),
            refs: BTreeMap::new(),
            commits: BTreeMap::new(),
            proofs: BTreeMap::new(),
            dropped: Vec::new(),
            counters: Counters::default(),
            finished: false,
        }
    }

    /// Read a journal, refusing one this build cannot fully understand.
    ///
    /// `None` means "no journal yet", which is the same as a fresh run. A file that does not
    /// parse, or parses into a newer schema, is an error with a sentence: silently starting
    /// over would throw away the only record of what already moved.
    pub fn load(path: &Path) -> Result<Option<Journal>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(why) if why.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(why) => {
                return Err(format!("cannot read {}: {why}", path.display()));
            }
        };
        let value: Value = serde_json::from_str(&text).map_err(|_| {
            format!(
                "{} is not JSON at all, let alone a migration journal; pass --journal <path> \
                 for another file or --restart to begin again",
                path.display()
            )
        })?;
        let journal = Journal::from_value(&value).map_err(|e| {
            format!(
                "{}: {e}; pass --journal <path> for another file or --restart to begin again",
                path.display()
            )
        })?;
        if journal.doc_type != JOURNAL_TYPE {
            return Err(format!(
                "{} says it is `{}`, not `{}`",
                path.display(),
                journal.doc_type,
                JOURNAL_TYPE
            ));
        }
        Ok(Some(journal))
    }

    /// Write it, atomically enough that an interrupted write cannot leave a journal that
    /// reads as a shorter list of finished steps than the one it had.
    pub fn save(&self) -> Result<(), String> {
        let Some(text) = self.path.as_ref() else {
            return Ok(());
        };
        let path = PathBuf::from(text);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let temp = path.with_extension("json.part");
        let body = serde_json::to_string_pretty(&self.to_value())
            .map_err(|e| format!("serialise the journal: {e}"))?;
        std::fs::write(&temp, body.as_bytes())
            .map_err(|e| format!("write {}: {e}", temp.display()))?;
        std::fs::rename(&temp, &path)
            .map_err(|e| format!("rename {} → {}: {e}", temp.display(), path.display()))?;
        Ok(())
    }

    /// Whether this step is already finished.
    pub fn done(&self, key: &str) -> bool {
        self.done.contains(key)
    }

    /// Finish a step.
    pub fn mark(&mut self, key: &str) {
        self.done.insert(key.to_string());
    }

    /// Record a ref this run moved.
    pub fn note_ref(&mut self, name: &str, oid: &str) {
        self.refs.insert(name.to_string(), oid.to_string());
        self.counters.refs_written += 1;
    }

    /// Record that a ref tip's objects are in the destination.
    pub fn note_objects(&mut self, tip: &str, objects: usize, bytes: u64) {
        if !self.delivered.iter().any(|held| held == tip) {
            self.delivered.push(tip.to_string());
        }
        self.counters.objects += objects;
        self.counters.object_bytes += bytes;
    }

    /// Record a commit's bytes and where the store filed them.
    pub fn note_commit(&mut self, oid: &str, digest: &str) {
        self.commits.insert(oid.to_string(), digest.to_string());
    }

    /// Record a proof.
    pub fn note_proof(&mut self, digest: &str, subject: &str, already: bool) {
        self.proofs.insert(digest.to_string(), subject.to_string());
        if already {
            self.counters.proofs_already += 1;
        } else {
            self.counters.proofs_carried += 1;
        }
    }

    /// Record something that did not come, without listing the same refusal twice.
    pub fn note_dropped(&mut self, dropped: Dropping) {
        if !self.dropped.contains(&dropped) {
            self.dropped.push(dropped);
        }
    }

    /// The refusal tally, sorted.
    pub fn dropped_by(&self) -> Vec<(String, usize)> {
        let mut tally: Vec<(String, usize)> = Vec::new();
        for dropped in &self.dropped {
            match tally.iter_mut().find(|(token, _)| *token == dropped.token) {
                Some((_, count)) => *count += 1,
                None => tally.push((dropped.token.clone(), 1)),
            }
        }
        tally.sort();
        tally
    }

    /// The same document the run files in the destination: this account, without the
    /// path it happens to be kept at locally.
    pub fn manifest(&self) -> String {
        let mut copy = self.clone();
        copy.path = None;
        copy.done = BTreeSet::new();
        copy.delivered.clear();
        copy.commits.clear();
        serde_json::to_string_pretty(&copy.to_value()).unwrap_or_else(|_| "{}".to_string())
    }

    /// The document as data.
    ///
    /// Written by hand rather than derived: the CLI's dependency list is `serde_json` and
    /// nothing else that could disagree with the format crate, and a derive would mean a
    /// dependency the hygiene test exists to keep out.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "type": self.doc_type,
            "schema_version": self.schema_version,
            "spec": self.spec,
            "slug": self.slug,
            "from": self.from,
            "to": self.to,
            "git_url": self.git_url,
            "path": self.path,
            "started_us": self.started_us,
            "updated_us": self.updated_us,
            "done": self.done.iter().cloned().collect::<Vec<String>>(),
            "delivered": self.delivered,
            "refs": self.refs,
            "commits": self.commits,
            "proofs": self.proofs,
            "dropped": self.dropped.iter().map(|d| serde_json::json!({
                "type": d.token, "class": d.class, "name": d.name, "detail": d.detail,
            })).collect::<Vec<Value>>(),
            "counters": {
                "refs_written": self.counters.refs_written,
                "refs_already": self.counters.refs_already,
                "changes_published": self.counters.changes_published,
                "merges_published": self.counters.merges_published,
                "proofs_carried": self.counters.proofs_carried,
                "proofs_already": self.counters.proofs_already,
                "objects": self.counters.objects,
                "object_bytes": self.counters.object_bytes,
            },
            "finished": self.finished,
        })
    }

    /// Read it back, refusing anything this build cannot fully account for.
    ///
    /// An unknown key is a refusal and not a shrug: a journal from a newer gitiup may be
    /// claiming that steps this build knows nothing about are finished, and skipping work on
    /// that evidence is how a migration quietly stops being complete.
    pub fn from_value(value: &Value) -> Result<Journal, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "the journal is not a JSON object".to_string())?;
        only_the_known_keys(object, JOURNAL_KEYS)?;
        let mut done = BTreeSet::new();
        for key in strings(value, "done")? {
            done.insert(key);
        }
        let counters = value
            .get("counters")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        let counter_object = counters
            .as_object()
            .ok_or_else(|| "`counters` is not an object".to_string())?;
        only_the_known_keys(counter_object, COUNTER_KEYS)?;
        let mut dropped = Vec::new();
        for entry in value
            .get("dropped")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let entry_object = entry
                .as_object()
                .ok_or_else(|| "a `dropped` entry is not an object".to_string())?;
            only_the_known_keys(entry_object, DROPPED_KEYS)?;
            dropped.push(Dropping {
                token: string(&entry, "type")?,
                class: string(&entry, "class")?,
                name: string(&entry, "name")?,
                detail: string(&entry, "detail")?,
            });
        }
        Ok(Journal {
            doc_type: string(value, "type")?,
            schema_version: number(value, "schema_version")? as u32,
            spec: string(value, "spec")?,
            slug: string(value, "slug")?,
            from: string(value, "from")?,
            to: string(value, "to")?,
            git_url: optional_string(value, "git_url"),
            path: optional_string(value, "path"),
            started_us: number(value, "started_us")?,
            updated_us: number(value, "updated_us")?,
            done,
            delivered: strings(value, "delivered")?,
            refs: pairs(value, "refs")?,
            commits: pairs(value, "commits")?,
            proofs: pairs(value, "proofs")?,
            dropped,
            counters: Counters {
                refs_written: number(&counters, "refs_written").unwrap_or(0) as usize,
                refs_already: number(&counters, "refs_already").unwrap_or(0) as usize,
                changes_published: number(&counters, "changes_published").unwrap_or(0) as usize,
                merges_published: number(&counters, "merges_published").unwrap_or(0) as usize,
                proofs_carried: number(&counters, "proofs_carried").unwrap_or(0) as usize,
                proofs_already: number(&counters, "proofs_already").unwrap_or(0) as usize,
                objects: number(&counters, "objects").unwrap_or(0) as usize,
                object_bytes: number(&counters, "object_bytes").unwrap_or(0) as u64,
            },
            finished: value
                .get("finished")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// The step key for a ref.
    pub fn ref_key(name: &str) -> String {
        format!("ref:{name}")
    }

    /// The step key for a ref's objects.
    pub fn object_key(name: &str) -> String {
        format!("objects:{name}")
    }

    /// The step key for a pull request.
    pub fn pull_key(number: u64) -> String {
        format!("pull:{number}")
    }

    /// The step key for a proof.
    pub fn proof_key(digest: &str) -> String {
        format!("proof:{digest}")
    }
}

impl Dropping {
    /// A refusal as data: token, kind, name, detail — the four facts ADR-0005 says a
    /// refusal owes the reader, and the same shape in the journal, the report and
    /// `--json`.
    pub fn json(&self) -> Value {
        serde_json::json!({
            "type": self.token,
            "kind": self.class,
            "name": self.name,
            "detail": self.detail,
        })
    }
}

/// The journal's home when the operator did not name one.
///
/// Under `.gitiup/` in the working directory, next to nothing else: it is state about one
/// run on one machine, and a destination that is a bucket has no directory to put it in.
pub fn default_path(slug: &str) -> PathBuf {
    Path::new(".gitiup")
        .join("migrate")
        .join(format!("{slug}.json"))
}

/// A filesystem-safe, stable name for one run, with a short digest of the full spec so two
/// runs that sanitize alike cannot share a journal.
pub fn slug(from: &str, to: &str) -> String {
    let joined = format!("{from}→{to}");
    let safe: String = joined
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let safe = safe.trim_matches('-').to_string();
    let safe = safe
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<&str>>()
        .join("-");
    let digest = gitiup_host::Oid::hash_bytes(joined.as_bytes());
    let short = digest.hex().chars().take(8).collect::<String>();
    let head: String = safe.chars().take(48).collect();
    format!("{head}-{short}")
}

/// The keys a journal document may have.
const JOURNAL_KEYS: &[&str] = &[
    "type",
    "schema_version",
    "spec",
    "slug",
    "from",
    "to",
    "git_url",
    "path",
    "started_us",
    "updated_us",
    "done",
    "delivered",
    "refs",
    "commits",
    "proofs",
    "dropped",
    "counters",
    "finished",
];

/// The keys one refusal may have.
const DROPPED_KEYS: &[&str] = &["type", "class", "name", "detail"];

/// The keys the tally may have.
const COUNTER_KEYS: &[&str] = &[
    "refs_written",
    "refs_already",
    "changes_published",
    "merges_published",
    "proofs_carried",
    "proofs_already",
    "objects",
    "object_bytes",
];

/// Refuse an object with keys this build has never heard of.
fn only_the_known_keys(
    object: &serde_json::Map<String, Value>,
    known: &[&str],
) -> Result<(), String> {
    let strange: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !known.contains(key))
        .collect();
    if strange.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "it has field(s) this gitiup does not understand: {} — a newer gitiup wrote this, \
             and pretending to understand it would mean skipping work it counted as done",
            strange.join(", ")
        ))
    }
}

/// One required string field.
fn string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("`{key}` is missing or is not a string"))
}

/// One optional string field.
fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

/// One required integer field.
fn number(value: &Value, key: &str) -> Result<i64, String> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("`{key}` is missing or is not a number"))
}

/// One required list of strings.
fn strings(value: &Value, key: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("`{key}` holds something that is not a string"))
        })
        .collect::<Result<Vec<String>, String>>()
}

/// One required map of string to string.
fn pairs(value: &Value, key: &str) -> Result<BTreeMap<String, String>, String> {
    let object = value
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    object
        .iter()
        .map(|(name, item)| {
            let value = item.as_str().ok_or_else(|| {
                format!("`{key}` holds `{name}` as something other than a string")
            })?;
            Ok((name.clone(), value.to_string()))
        })
        .collect::<Result<BTreeMap<String, String>, String>>()
}
#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> Journal {
        Journal::new(
            "github:o/r → fs store ./store".into(),
            "slug-1".into(),
            "github:o/r".into(),
            "fs store ./store".into(),
            1_700_000_000_000_000,
        )
    }

    #[test]
    fn a_journal_round_trips_and_names_its_type() {
        let mut journal = journal();
        journal.mark(&Journal::ref_key("refs/heads/main"));
        journal.note_ref("refs/heads/main", "aaaa");
        journal.note_proof("sha256:1", "bbbb", false);
        journal.note_dropped(Dropping::of(
            "check_run_not_gitiup",
            "check-run",
            "build",
            "log",
        ));
        let text = serde_json::to_string(&journal.to_value()).expect("serialise");
        let read = Journal::from_value(&serde_json::from_str::<Value>(&text).expect("parse"))
            .expect("read back");
        assert_eq!(read.doc_type, JOURNAL_TYPE);
        assert!(read.done(&Journal::ref_key("refs/heads/main")));
        assert_eq!(read.counters.refs_written, 1);
        assert_eq!(read.counters.proofs_carried, 1);
        assert_eq!(
            read.dropped_by(),
            vec![("check_run_not_gitiup".to_string(), 1)]
        );
    }

    #[test]
    fn a_journal_from_a_newer_build_is_refused_not_forgiven() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("j.json");
        // One field this build has never heard of: the honest answer is "I cannot read
        // this", because the field may describe a step this build must not skip.
        std::fs::write(
            &path,
            r#"{"type":"gitiup-migrate-1","schema_version":1,"spec":"x","slug":"s",
               "from":"a","to":"b","started_us":0,"updated_us":0,"done":[],"delivered":[],
               "refs":{},"commits":{},"proofs":{},"dropped":[],"counters":{},"finished":false,
               "steps_of_the_future":[]}"#,
        )
        .expect("write");
        let error = Journal::load(&path).expect_err("an unknown field is a refusal");
        assert!(error.contains("understand"), "{error}");
        assert!(
            error.contains("--restart"),
            "the refusal has to say what to do"
        );
    }

    #[test]
    fn no_journal_is_a_fresh_run_and_a_wrong_type_is_an_error() {
        let dir = tempfile::tempdir().expect("temp");
        let missing = dir.path().join("nothing.json");
        assert!(Journal::load(&missing).expect("absent is fine").is_none());
        let wrong = dir.path().join("wrong.json");
        std::fs::write(
            &wrong,
            r#"{"type":"gitiup-something-else","schema_version":1,"spec":"x","slug":"s",
               "from":"a","to":"b","started_us":0,"updated_us":0,"done":[],"delivered":[],
               "refs":{},"commits":{},"proofs":{},"dropped":[],"counters":{},"finished":false}"#,
        )
        .expect("write");
        assert!(
            Journal::load(&wrong)
                .expect_err("wrong type")
                .contains("says it is")
        );
    }

    #[test]
    fn a_saved_journal_is_the_one_that_comes_back() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("j.json");
        let mut journal = journal();
        journal.path = Some(path.display().to_string());
        journal.mark("ref:refs/heads/main");
        journal.save().expect("save");
        let read = Journal::load(&path)
            .expect("reads")
            .expect("it was written");
        assert!(read.done("ref:refs/heads/main"));
        assert!(!path.with_extension("json.part").exists());
    }

    #[test]
    fn two_runs_that_look_alike_get_two_journals() {
        let one = slug("github:o/r", "s3://bucket/repo");
        let two = slug("github:o/r", "s3://bucket/other");
        let three = slug("github:o/r", "s3://bucket/repo");
        assert_ne!(one, two, "different destinations are different runs");
        assert_eq!(one, three, "the same run gets the same name");
        for slug in [one, two] {
            assert!(
                slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{slug} is not a file name"
            );
            assert!(!slug.contains('.'), "{slug} could escape its directory");
        }
    }
}

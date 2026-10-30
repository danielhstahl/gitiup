//! Every open and merged pull request becomes a change, with the forge named as its
//! origin.
//!
//! A pull request is the forge's copy of a proposal: its title and body are unsigned, and no
//! signature in gitiup's format covers either. So a migration does not "convert a PR into a
//! change" — it **transcribes** one, signs the transcription as the machine that made it, and
//! records where it came from in the field ADR-0003 D10 reserved for exactly that:
//! `origin: {kind: "pull", number: n}`. The forge's author, labels, URL and body travel as
//! *annotations*, which a reader can read and no reader may authorise on.
//!
//! A merged pull gets a second record. `via: "forge"` exists in the merge format for the
//! merges a forge performed and gitiup is writing down afterwards, and the forge's own
//! `merge_commit_sha` is what makes that honest: `base.to` is the ref move the forge named,
//! not a guess that it was probably a fast-forward. A merged pull whose merge commit the forge
//! did not name still migrates as a change, and says it has no merge record.
//!
//! The ref layout is the one every other store uses — `refs/changes/<id>/attempt/0` created,
//! then `refs/changes/<id>/head` — because the point of carrying PRs out of a forge is that
//! the result is an ordinary gitiup store and not a forge-shaped one.

use gitiup_host::change::{self, CHANGE_TYPE, MERGE_TYPE, MergeBase, MergeRecord};
use gitiup_host::change::{Attempts, Author, Base, ChangeId, ChangeRecord, Origin, Workflow};
use gitiup_host::{Actor, Host, HostError, Oid};
use gitiup_host_github::ChangeState;
use gitiup_host_github::migrate::Pull;

use crate::CliError;

use super::journal::Dropping;

/// A change record's `head`, `base.oid` and `attempts.anchor` are algorithm-tagged oids
/// (ADR-0001 D2: an untagged oid is a guess about the hash function).
pub fn tagged(oid: &Oid) -> String {
    let algo = match oid.len() {
        20 => "sha1",
        32 => "sha256",
        _ => "git",
    };
    format!("{algo}:{}", oid.hex())
}

/// What a pull became, in the tallies.
#[derive(Debug, Default)]
pub struct Published {
    /// Change records written (attempt 0).
    pub changes: usize,
    /// Changes the store already held, byte for byte.
    pub already: usize,
    /// Merge records written for merged pulls.
    pub merges: usize,
    /// Pulls that did not become a change, with the reason.
    pub refused: Vec<Dropping>,
}

/// The annotations a transcribed record carries.
///
/// Every one of these is a fact *about the forge*, kept so a reader can go and look, and
/// none of it is signed by anybody at the forge — which is why it is an annotation and not a
/// field.
fn annotations(pull: &Pull) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    out.insert("x_gitiup_migrated_from".to_string(), "github".to_string());
    out.insert("x_gitiup_pull_number".to_string(), pull.number.to_string());
    out.insert(
        "x_gitiup_pull_state".to_string(),
        pull.state.as_str().to_string(),
    );
    if let Some(author) = &pull.author {
        out.insert("x_gitiup_pull_author".to_string(), author.clone());
    }
    if let Some(url) = &pull.url {
        out.insert("x_gitiup_pull_url".to_string(), url.clone());
    }
    if let Some(repo) = &pull.head_repo {
        out.insert("x_gitiup_pull_head_repo".to_string(), repo.clone());
    }
    if !pull.labels.is_empty() {
        out.insert("x_gitiup_pull_labels".to_string(), pull.labels.join(","));
    }
    if pull.draft {
        out.insert("x_gitiup_pull_draft".to_string(), "true".to_string());
    }
    if let Some(body) = &pull.summary {
        // An annotation is bounded, and a body that will not fit is *summarised as absent*
        // rather than cut: half a description with no mark saying it is half is a lie about
        // what the forge held.
        if body.len() <= 512 && !body.chars().any(char::is_control) {
            out.insert("x_gitiup_pull_body".to_string(), body.clone());
        } else {
            out.insert(
                "x_gitiup_pull_body".to_string(),
                "omitted (over the annotation limit)".to_string(),
            );
        }
    }
    // An empty annotation is refused by the store, and would say nothing anyway: a key
    // with no value is noise in a document that is read by a person.
    out.retain(|_, value| !value.is_empty());
    out
}

/// Build the change record for one pull, signed by `signer`.
pub fn record_for(
    pull: &Pull,
    signer: &dyn gitiup_attest::Signer,
    key_id: &str,
    principal: &str,
) -> Result<ChangeRecord, HostError> {
    let base_ref = format!("refs/heads/{}", pull.base_branch);
    let head = tagged(&pull.head);
    let anchor = head.clone();
    let record = ChangeRecord {
        annotations: Some(annotations(pull)),
        attempts: Attempts {
            anchor: anchor.clone(),
            index: 0,
            previous: None,
        },
        author: Author {
            key_id: key_id.to_string(),
            principal: principal.to_string(),
        },
        base: Base {
            branch: base_ref.clone(),
            oid: tagged(&pull.base_oid),
        },
        change_id: ChangeId::derive(key_id, &base_ref, &anchor)?,
        // The record is written now, by this machine: `created_at_us` is when this claim was
        // made, and the forge's own timestamps are annotations. Back-dating the claim to the
        // day the pull was opened would put a signature on a time it was not signed at.
        created_at_us: gitiup_attest::TimeUs::now().as_us(),
        head,
        // The one field the forge really does answer: this change is a pull request, number
        // *n*, and the forge's merge button is its merge (ADR-0003 D10).
        origin: Origin::pull(pull.number),
        schema_version: change::SCHEMA_VERSION,
        signatures: Vec::new(),
        title: title_of(pull),
        record_type: CHANGE_TYPE.to_string(),
        workflow: Workflow { jobs: Vec::new() },
    };
    record.sign(signer)
}

/// Build the merge record for a merged pull, when the forge named the merge commit.
pub fn merge_for(
    record: &ChangeRecord,
    pull: &Pull,
    signer: &dyn gitiup_attest::Signer,
    key_id: &str,
    principal: &str,
) -> Option<Result<MergeRecord, HostError>> {
    let merge = pull.merge_commit?;
    let merge_record = MergeRecord {
        change_digest: record.change_digest().ok()?,
        change_id: record.change_id.clone(),
        attempt: 0,
        base: MergeBase {
            branch: format!("refs/heads/{}", pull.base_branch),
            from: tagged(&pull.base_oid),
            // The forge's own answer, not an inference. This is the whole reason a merged
            // pull gets a record at all.
            to: tagged(&merge),
        },
        merged_at_us: pull.merged_at_us.unwrap_or(0),
        via: "forge".to_string(),
        proofs: Vec::new(),
        policy_digest: None,
        author: Author {
            key_id: key_id.to_string(),
            principal: principal.to_string(),
        },
        schema_version: change::SCHEMA_VERSION,
        record_type: MERGE_TYPE.to_string(),
        signatures: Vec::new(),
        annotations: Some(annotations(pull)),
    };
    Some(merge_record.sign(signer))
}

/// One line, as the record's title: the forge's title when it had one.
fn title_of(pull: &Pull) -> String {
    let title: String = pull
        .title
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let trimmed = title.trim();
    if trimmed.is_empty() {
        format!("pull #{} (untitled at the forge)", pull.number)
    } else {
        trimmed.to_string()
    }
}

/// Publish one pull as a change (and, if it merged, its merge record).
///
/// Errors are returned, not swallowed: the caller decides whether a refused change ends the
/// run or is a line in the report, and a per-record refusal must not look like an integrity
/// failure.
pub fn publish(
    to: &dyn Host,
    pull: &Pull,
    signer: &dyn gitiup_attest::Signer,
    key_id: &str,
    principal: &str,
    actor: &Actor,
) -> Result<(bool, Option<Dropping>), CliError> {
    let record = record_for(pull, signer, key_id, principal)
        .map_err(|e| CliError::io(format!("pull #{}: {e}", pull.number)))?;
    let published = change::publish_change(to, &record, actor.clone())
        .map_err(|e| store_said(&e, &format!("pull #{}", pull.number)))?;
    if pull.state == ChangeState::Merged {
        match merge_for(&record, pull, signer, key_id, principal) {
            Some(merge) => {
                let merge =
                    merge.map_err(|e| CliError::io(format!("pull #{}: {e}", pull.number)))?;
                change::publish_merge(to, &merge, actor.clone())
                    .map_err(|e| store_said(&e, &format!("pull #{} merge", pull.number)))?;
            }
            // The forge said the pull merged but never said which commit it merged *into*
            // the base branch. `base.to` is that commit, and a merge record guessed from
            // the head would be a record of a merge nobody performed, so the change is
            // published and the missing merge is a line in the report.
            None => {
                return Ok((
                    published.already,
                    Some(Dropping::of(
                        MERGE_UNKNOWN,
                        "merge",
                        format!("#{}", pull.number),
                        "the forge calls this pull merged but names no merge commit, and a \
                         merge record's `base.to` is the commit the base branch moved to: \
                         guessing it would record a merge that may not have happened",
                    )),
                ));
            }
        }
    }
    Ok((published.already, None))
}

/// A merged pull whose merge commit the forge never named.
const MERGE_UNKNOWN: &str = "pull_merge_commit_unknown";

/// A store's refusal, in the command's words.
fn store_said(error: &HostError, what: &str) -> CliError {
    CliError::refused(
        format!("{what}: {error}"),
        "the store refused this record; nothing was half-written, and the run carries on \
         with the rest",
    )
}

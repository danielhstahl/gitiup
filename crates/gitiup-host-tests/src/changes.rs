//! The change workflow, measured against a store: propose → re-attempt → list → show
//! → merge → and the second merge that must never happen (giti-b2z.6).
//!
//! [`gitiup_host::change`] already knows how to write a change record, and
//! `gitiup-host`'s own test files (`change_store`, `change_merge`, `change_git`) prove
//! the format against the fs host, the bucket host and a bare repository. What those
//! files cannot do is answer the question this crate exists for — *do all the hosts
//! answer it the same way?* — because each of them is written against one host.
//! Everything here is therefore written once, against `&dyn Host`, and run against every
//! registration: a bucket that merges a change the directory host would have refused
//! fails a named test here, before it is someone's lost merge.
//!
//! # The oids a store can name
//!
//! A change record names two commits: the point it branched from (`base.oid`) and the
//! commit it proposes (`head`). A merge is a compare-and-swap of a branch from the first
//! to the second, so the store has to be able to *hold* both — a plain-git host refuses a
//! branch pointing at a commit its object database cannot name, and a forge refuses a ref
//! pointing at an object it has never seen. So [`commits`] hands a body oids the store
//! can name rather than oids this file invented:
//!
//! * a git host gets **real commits**: a chain of them, packed with the `git` binary and
//!   handed over as one git packfile — the same ingestion path a submit uses, so a change
//!   that only works against a store which ignores object existence still fails here;
//! * every other host gets **record digests**: bytes actually stored under their own
//!   digest, so a change's head is a thing the store can return rather than a name made
//!   up. `sha256:` is a legal oid in ADR-0003 D2, and an ancestry claim about digests is
//!   exactly as true — or as false — as one about commits.
//!
//! That is the only host-specific decision in this file, and it is made once. Everything
//! else is the same code, run everywhere.

use std::path::Path;
use std::process::Command;

use gitiup_canon::{Digest, SigningKey};
use gitiup_host::change::{
    self, Ancestry, Attempts, Author, Base, ChangeId, ChangeRecord, Origin, State, StoredRecord,
    Workflow,
};
use gitiup_host::{
    Actor, Host, HostError, HostErrorExt, HostErrorKind, HostInfo, HostKind, HostResult, Namespace,
    Oid, Pack, PackRequest, RefName, RefQuery, RefUpdate,
};

// ---------------------------------------------------------------------------
// keys and records
// ---------------------------------------------------------------------------

/// The ADR-0003 fixture keys, derived from a public label exactly the way
/// `docs/adr/fixtures/change-v1/generate.py` derives them.
///
/// Not a random key per run: a body that signs with `fixture_key("ada")` produces the
/// `key_id` the committed vectors name, so a digest that drifts shows up as a mismatch
/// against the ADR rather than as two implementations agreeing only with each other.
pub fn fixture_key(label: &str) -> SigningKey {
    let digest =
        Digest::sha256(format!("gitiup ADR-0003 change-v1 fixture key: {label}").as_bytes());
    let seed: [u8; 32] = digest.as_bytes().try_into().expect("sha256 is 32 bytes");
    SigningKey::from_seed(&seed)
}

/// The `author` block for a fixture key. `principal` is display only (D2), which is why
/// it is derived from the label and never checked.
pub fn author(who: &str) -> Author {
    Author {
        key_id: fixture_key(who).public_key().key_id(),
        principal: format!("{who}@example.org"),
    }
}

/// Who wrote a ref. A short handle, because a forge puts it in a commit author.
fn actor(who: &str) -> Actor {
    Actor::new(who).expect("a valid actor")
}

/// The branch every conformance change is proposed against.
pub const BASE_BRANCH: &str = "refs/heads/main";

/// A fixed instant, so two runs produce the same bytes and a digest comparison means
/// something.
const T0: i64 = 1_764_674_043_000_000;
const HOUR: i64 = 3_600_000_000;

/// One unsigned attempt of the change that started at `anchor`.
///
/// One builder for every body, because a record that is only *nearly* well formed would
/// fail in [`ChangeRecord::verify`] before the store ever saw it, and the body would then
/// be measuring the format rather than the host.
fn unsigned(
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
    base_oid: &str,
) -> HostResult<ChangeRecord> {
    let author = author(who);
    let key_id = author.key_id.clone();
    Ok(ChangeRecord {
        annotations: None,
        attempts: Attempts {
            anchor: anchor.to_string(),
            index,
            previous,
        },
        author,
        base: Base {
            branch: BASE_BRANCH.to_string(),
            oid: base_oid.to_string(),
        },
        change_id: ChangeId::derive(&key_id, BASE_BRANCH, anchor)?,
        created_at_us: T0 + i64::from(index) * HOUR,
        head: head.to_string(),
        origin: Origin::store(),
        schema_version: change::SCHEMA_VERSION,
        signatures: Vec::new(),
        title: title.to_string(),
        record_type: change::CHANGE_TYPE.to_string(),
        workflow: Workflow {
            jobs: vec!["build/linux-x86_64".to_string(), "test".to_string()],
        },
    })
}

/// One signed attempt. Signing verifies, so an unusable record is caught here rather
/// than halfway through a publish.
#[allow(clippy::too_many_arguments)]
pub fn signed(
    who: &str,
    title: &str,
    anchor: &str,
    head: &str,
    index: u32,
    previous: Option<String>,
    base_oid: &str,
) -> HostResult<ChangeRecord> {
    unsigned(who, title, anchor, head, index, previous, base_oid)?.sign(&fixture_key(who))
}

/// Publish one attempt, the way a contributor's `gitiup change submit` does.
pub fn publish(host: &dyn Host, record: &ChangeRecord, who: &str) -> HostResult<change::Published> {
    change::publish_change(host, record, actor(who))
}

/// Read one change ref back the way `gitiup change show` does: through the ref, with
/// every binding of D11 step 6 checked against the store.
pub fn show(host: &dyn Host, reference: &RefName) -> HostResult<change::Fetched> {
    change::change_at(host, reference)
}

/// The change record one `refs/changes/**` ref advertises.
pub fn change_record(host: &dyn Host, reference: &RefName) -> HostResult<ChangeRecord> {
    match show(host, reference)?.record {
        StoredRecord::Change(record) => Ok(record),
        other => Err(HostError::invalid(
            "change record",
            format!(
                "{} holds a {}, not a change",
                reference,
                other.record_type()
            ),
        )),
    }
}

/// The owner's merge request: this attempt, signed by the owner's key, and the
/// fast-forward the caller is on the hook to have checked (ADR-0003 D8 step 4).
///
/// Every body passes [`Ancestry::FastForward`] because in every body it is true by
/// construction — the commits handed out by [`commits`] are one chain. The store cannot
/// check the claim itself (it holds records, not a commit graph), and the reason it is
/// still passed is that a merge *without* it is refused: `Unknown` is a refusal, not a
/// shrug, which the `gitiup-host` merge tests cover.
pub fn merge_request<'a>(
    record: &'a ChangeRecord,
    key: &'a SigningKey,
) -> change::MergeRequest<'a> {
    change::MergeRequest::new(record, key, author("owner"))
        .with_ancestry(Ancestry::FastForward)
        .with_actor(actor("owner"))
}

// ---------------------------------------------------------------------------
// the commits a store can name
// ---------------------------------------------------------------------------

/// Five oids this store can name, in one chain.
///
/// * `base` — where `refs/heads/main` stands before any of this;
/// * `first` — what attempt 0 proposes;
/// * `second` — what attempt 1 proposes (the re-attempt, and what the workflow body ends
///   up merging);
/// * `other` — what *someone else's* merge leaves the branch at: the stale-base case;
/// * `beyond` — a commit past that, so the rebuilt change has somewhere honest to go.
///
/// Held as `String` because that is what a record carries: an algorithm-tagged oid, and
/// the host's business is moving refs by value, not parsing them.
#[derive(Debug, Clone)]
pub struct Commits {
    /// Where the branch starts.
    pub base: String,
    /// Attempt 0's head.
    pub first: String,
    /// Attempt 1's head.
    pub second: String,
    /// The commit another owner's merge left the branch at.
    pub other: String,
    /// A commit past `other`.
    pub beyond: String,
    /// How these were made, so a failure message says what was really measured.
    pub shape: &'static str,
}

/// Hand out oids this store can name — see this module's documentation for why that is
/// not the same oids everywhere.
pub fn commits(host: &dyn Host) -> HostResult<Commits> {
    match host.kind() {
        HostKind::Git => git_commits(host),
        _ => record_commits(host),
    }
}

/// Publish `refs/heads/main` at the base commit.
///
/// That publish is the owner's act and this body's act, never gitiup's: ADR-0003 D8
/// step 2 says a merge needs a branch that is already there, and a store whose merge had
/// to create the branch it merged into would be a store where a stranger's change could
/// invent a branch.
pub fn publish_branch(host: &dyn Host, commits: &Commits) -> HostResult<()> {
    host.update_ref_cas(
        &RefUpdate::create(
            RefName::branch("main").expect("a branch name"),
            oid(&commits.base),
        )
        .with_actor(actor("owner"))
        .with_message("the branch a change is proposed against"),
    )
    .map(|_| ())
}

/// The branch tip.
pub fn branch(host: &dyn Host) -> HostResult<Option<Oid>> {
    Ok(host
        .get_ref(&RefName::branch("main").expect("a branch name"))?
        .map(|reference| reference.oid))
}

/// Move the branch the way another owner's merge would: from what it holds to somewhere
/// else, under the same promise a change's merge would use.
pub fn move_branch(host: &dyn Host, from: &Oid, to: &str) -> HostResult<()> {
    host.update_ref_cas(&RefUpdate::replace(
        RefName::branch("main").expect("a branch name"),
        *from,
        oid(to),
    ))
    .map(|_| ())
}

/// `sha1:…` / `sha256:…` → an [`Oid`].
pub fn oid(tagged: &str) -> Oid {
    let hex = tagged.split_once(':').map(|(_, hex)| hex).unwrap_or(tagged);
    Oid::from_hex(hex).unwrap_or_else(|err| panic!("'{tagged}' is not an oid: {err}"))
}

/// The bare hex of a tagged oid, which is how a refusal prints one.
pub fn oid_hex(tagged: &str) -> String {
    tagged
        .split_once(':')
        .map(|(_, hex)| hex.to_string())
        .unwrap_or_else(|| tagged.to_string())
}

/// The tagged spelling a record carries.
fn tagged(oid: &Oid) -> String {
    match oid.len() {
        20 => format!("sha1:{}", oid.hex()),
        _ => format!("sha256:{}", oid.hex()),
    }
}

/// Record digests, for the hosts that hold records and nothing else.
fn record_commits(host: &dyn Host) -> HostResult<Commits> {
    let steps = ["base", "first", "second", "other", "beyond"];
    let mut made = Vec::new();
    for step in steps {
        let digest = host.put_cas(
            &Namespace::RECORD,
            format!("{{\"commit\":\"the {step} commit of a conformance change\"}}").as_bytes(),
        )?;
        made.push(tagged(&digest));
    }
    let [base, first, second, other, beyond] = made.as_slice() else {
        unreachable!("five steps, five oids");
    };
    Ok(Commits {
        base: base.clone(),
        first: first.clone(),
        second: second.clone(),
        other: other.clone(),
        beyond: beyond.clone(),
        shape: "five records this store holds, addressed by sha256",
    })
}

/// Real commits, for the host that keeps a commit graph.
///
/// Built in a scratch repository with the `git` binary and handed over as one git
/// packfile — the same ingestion path `gitiup change submit` uses. The chain is linear,
/// so "the branch moved" and "the change is ahead of the branch" are facts the host can
/// check for itself rather than facts this file asserts.
fn git_commits(host: &dyn Host) -> HostResult<Commits> {
    let scratch = crate::fixtures::Scratch::new("git-commits");
    let work = scratch.join("work");
    std::fs::create_dir_all(&work).map_err(|err| {
        HostError::invalid(
            "git scratch",
            format!("cannot make a scratch repository: {err}"),
        )
    })?;
    git_in(&work, &["init", "-q", "-b", "main"])?;
    git_in(&work, &["config", "user.email", "conformance@gitiup.test"])?;
    git_in(&work, &["config", "user.name", "gitiup conformance"])?;
    for step in ["base", "first", "second", "other", "beyond"] {
        std::fs::write(work.join(step), format!("{step}\n")).map_err(|err| {
            HostError::invalid("git scratch", format!("cannot write a scratch file: {err}"))
        })?;
        git_in(&work, &["add", "."])?;
        git_in(
            &work,
            &["commit", "-q", "-m", &format!("the {step} commit")],
        )?;
    }
    let tips: Vec<String> = git_in(&work, &["rev-list", "HEAD"])?
        .lines()
        .map(str::to_string)
        .collect();
    if tips.len() != 5 {
        return Err(HostError::invalid(
            "git scratch",
            format!("expected five commits and got {}", tips.len()),
        ));
    }
    // `rev-list` is newest first, so the chain in order is the reverse.
    let chain: Vec<String> = tips.iter().rev().map(|sha| format!("sha1:{sha}")).collect();
    let objects = git_in(&work, &["rev-list", "--objects", "--all"])?;
    let pack = pack_objects(&work, objects.as_bytes())?;
    host.put_pack(&Pack::git_packfile(pack)?)?;
    let [base, first, second, other, beyond] = chain.as_slice() else {
        unreachable!("five commits, five oids");
    };
    Ok(Commits {
        base: base.clone(),
        first: first.clone(),
        second: second.clone(),
        other: other.clone(),
        beyond: beyond.clone(),
        shape: "five real commits, packed and ingested by the git host",
    })
}

/// `git` in a directory.
fn git_in(dir: &Path, args: &[&str]) -> HostResult<String> {
    let program = gitiup_host::hosts::git::git_program()
        .ok_or_else(|| HostError::invalid("git", "no git binary on this box"))?;
    let output = Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|err| {
            HostError::invalid(
                "git",
                format!("`git {}` could not run: {err}", args.join(" ")),
            )
        })?;
    if !output.status.success() {
        return Err(HostError::invalid(
            "git",
            format!(
                "`git {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// `git pack-objects --stdout`, with the object list on stdin.
fn pack_objects(dir: &Path, objects: &[u8]) -> HostResult<Vec<u8>> {
    let program = gitiup_host::hosts::git::git_program()
        .ok_or_else(|| HostError::invalid("git", "no git binary on this box"))?;
    let mut child = Command::new(program)
        .current_dir(dir)
        .args(["pack-objects", "--stdout", "--delta-base-offset"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| HostError::invalid("git", format!("pack-objects could not run: {err}")))?;
    // Write the list and drop stdin: `pack-objects` waits for the end of the list before
    // it writes a byte, so leaving the pipe open deadlocks the moment the pack is bigger
    // than the pipe buffer.
    use std::io::Write;
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        stdin
            .write_all(objects)
            .map_err(|err| HostError::invalid("git", format!("cannot feed pack-objects: {err}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|err| HostError::invalid("git", format!("pack-objects failed: {err}")))?;
    if !out.status.success() {
        return Err(HostError::invalid(
            "git",
            format!(
                "`git pack-objects` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    Ok(out.stdout)
}

// ---------------------------------------------------------------------------
// moving one store's contents into another
// ---------------------------------------------------------------------------

/// Copy every object, and then every ref under `prefix`, from one store to the other.
///
/// The order is the one ADR-0003 D5 makes a host keep for its own writes — bytes before
/// refs — because the alternative is a store advertising a record it cannot return, and
/// then a failure in the cross-host body would be this helper's lie rather than the
/// host's. Objects travel as one raw pack, which is all the contract offers for "give me
/// these digests"; refs are re-created, never force-moved, so a ref on the far side that
/// already holds something else is a conflict this body would rather see than paper over.
///
/// `prefix` is a ref prefix, and `""` means every ref. An object already there is not an
/// error (a digest is not a slot number), and neither is a ref that already stands at the
/// value being carried: this is convergence, not a first copy.
pub fn transfer(from: &dyn Host, to: &dyn Host, prefix: &str) -> HostResult<Transfer> {
    let entries = from.list_prefix(Namespace::ANY)?;
    if entries.is_empty() {
        return Err(HostError::invalid(
            "transfer",
            format!(
                "the {} store holds no objects, so there is nothing to carry",
                from.kind()
            ),
        ));
    }
    let wants: Vec<Oid> = entries.iter().map(|entry| entry.oid).collect();
    let pack = from.fetch_pack(&PackRequest::new(wants.clone()))?;
    let written = to.put_pack(&pack)?;

    let mut carried = Vec::new();
    let mut already = Vec::new();
    for reference in from.list_refs(&RefQuery::all())? {
        if !reference.name.as_str().starts_with(prefix) {
            continue;
        }
        match to.get_ref(&reference.name)? {
            Some(existing) if existing.oid == reference.oid => {
                already.push(reference.name);
            }
            _ => {
                to.update_ref_cas(
                    &RefUpdate::create(reference.name.clone(), reference.oid)
                        .with_message("carried across by the cross-host body"),
                )?;
                carried.push(reference.name);
            }
        }
    }
    Ok(Transfer {
        objects: wants.len(),
        pack: written,
        refs: carried,
        existing: already,
    })
}

/// What a [`transfer`] carried, for the assertion that says what was measured.
#[derive(Debug)]
pub struct Transfer {
    /// Objects read from the source and written to the target.
    pub objects: usize,
    /// The digest of the pack they travelled as.
    pub pack: Oid,
    /// Refs this call had to create on the target.
    pub refs: Vec<RefName>,
    /// Refs that already stood at the value being carried.
    pub existing: Vec<RefName>,
}

// ---------------------------------------------------------------------------
// the bodies
// ---------------------------------------------------------------------------

/// Every host proposes, re-attempts, lists, shows, merges — and then refuses to merge
/// twice.
///
/// This is the change workflow of `docs/changes.md` as one straight line through a store,
/// with the refusals that make it safe in the same body: the attempt ref that never
/// moves, the second set of bytes that cannot replace an attempt, the merge that happens
/// exactly once because a create-only ref says so, and the closed change that takes no
/// further attempts. Each step reads the store back rather than trusting what it just
/// wrote, because the promise gitiup makes to the *next* reader is about the store, not
/// about this call.
pub fn workflow(host: &dyn Host) {
    let here = describe(host);
    let commits = commits(host).expect("the host can hand out commits it can name");
    publish_branch(host, &commits).expect("the owner publishes the branch");

    // ---- propose ------------------------------------------------------------------
    // Attempt 0 anchors its own head (D3), so anchor and head are the same commit; that
    // is what makes a later force-push the same change rather than a different one.
    let proposal = signed(
        "ada",
        "Teach every host to carry a change",
        &commits.first,
        &commits.first,
        0,
        None,
        &commits.base,
    )
    .expect("a signed attempt 0");
    let proposed = publish(host, &proposal, "ada").expect("propose attempt 0");
    assert_eq!(proposed.attempt, Some(0), "this was attempt 0");
    assert!(!proposed.already, "the store had never seen it");
    assert_eq!(proposed.change_id, proposal.change_id);
    let id = proposal.change_id.clone();
    let attempt0 = change::attempt_ref(&id, 0);
    let head_ref = change::change_head_ref(&id);
    assert_eq!(
        proposed.reference, attempt0,
        "an attempt is advertised by its own ref"
    );
    assert_eq!(
        host.get_ref(&attempt0)
            .expect("read attempt 0")
            .expect("attempt 0 is there")
            .oid,
        proposed.record_digest,
        "the attempt ref holds the record's own digest ({here})"
    );
    assert_eq!(
        host.get_ref(&head_ref)
            .expect("read head")
            .expect("head is there")
            .oid,
        proposed.record_digest,
        "and so does head, which names the newest attempt"
    );
    let (stored, bytes) = change::read_stored(host, &proposed.record_digest)
        .expect("read the record")
        .expect("the record is filed under its own digest");
    assert_eq!(
        bytes,
        proposal.canonical_bytes().expect("canonical bytes"),
        "the stored bytes are exactly the canonical ones — a record rewritten on the way \
         in or out is a signature that no longer verifies ({here})"
    );
    assert_eq!(stored.change_id(), &id);

    // The same bytes again are a retry, not a second attempt and not a conflict.
    let retry = publish(host, &proposal, "ada").expect("re-publishing is idempotent");
    assert!(retry.already, "the store already held exactly this");
    assert_eq!(retry.record_digest, proposed.record_digest);

    // ---- list ---------------------------------------------------------------------
    let catalog = change::list_changes(host).expect("list the store");
    assert!(
        catalog.unexpected.is_empty(),
        "refs/changes/** holds names this layout cannot name: {:?}",
        catalog.unexpected
    );
    assert_eq!(catalog.changes.len(), 1, "one change is advertised");
    let listed = &catalog.changes[0];
    assert_eq!(listed.change_id, id);
    assert_eq!(listed.state, State::Open, "a proposal is open");
    assert_eq!(listed.attempts, vec![0]);
    assert_eq!(listed.head, Some(proposed.record_digest));
    assert!(listed.head_tracks_newest, "head names the newest attempt");
    assert!(listed.merged.is_none() && listed.abandoned.is_none());
    assert_eq!(
        catalog.resolve(&id.hex()[..6]).len(),
        1,
        "a short handle names exactly one change (D3)"
    );

    // ---- re-attempt ---------------------------------------------------------------
    // A force-push is attempt 1 of the same change (D6): same id, same anchor, one new
    // link in the `previous` chain.
    let first_digest = proposal.change_digest().expect("a change digest");
    let resubmitted = signed(
        "ada",
        "Teach every host to carry a change, take two",
        &commits.first,
        &commits.second,
        1,
        Some(first_digest.clone()),
        &commits.base,
    )
    .expect("a signed attempt 1");
    let published = publish(host, &resubmitted, "ada").expect("propose attempt 1");
    assert_eq!(
        published.change_id, id,
        "a re-attempt is the same change, not a new one"
    );
    assert_eq!(published.attempt, Some(1));
    assert_eq!(
        host.get_ref(&attempt0)
            .expect("attempt 0 again")
            .expect("attempt 0 is still there")
            .oid,
        proposed.record_digest,
        "an attempt ref never moves (D6)"
    );
    assert_eq!(
        host.get_ref(&head_ref)
            .expect("head again")
            .expect("head is still there")
            .oid,
        published.record_digest,
        "head moved to the new attempt, and only head"
    );

    // Different bytes at an attempt that exists are a refusal naming both sides: the
    // attempt is what attestations point at, so moving it would silently re-target them.
    let forged = signed(
        "ada",
        "A different attempt 1 entirely",
        &commits.first,
        &commits.second,
        1,
        Some(first_digest.clone()),
        &commits.base,
    )
    .expect("a second, different attempt 1");
    let err = publish(host, &forged, "ada").expect_err("attempt 1 already exists");
    assert!(err.is_conflict(), "{err}");
    match &err {
        HostError::Conflict(conflict) => {
            assert_eq!(conflict.name, published.reference.as_str());
            assert_eq!(
                conflict.found,
                Some(published.record_digest),
                "the conflict says what is really there"
            );
        }
        other => panic!("expected a conflict carrying both sides, got {other:?}"),
    }

    // The history is the two attempts, in order, each readable through its own ref.
    let history = change::change_history(host, &id).expect("the attempt history");
    assert_eq!(
        history
            .iter()
            .map(|attempt| attempt.index)
            .collect::<Vec<_>>(),
        vec![0, 1],
        "both attempts are in the history"
    );
    assert_eq!(
        history[1].previous.as_deref(),
        Some(first_digest.as_str()),
        "attempt 1 names the attempt it replaces"
    );
    assert_eq!(history[0].change_digest, first_digest);
    assert_eq!(history[1].head, commits.second);

    // ---- show ---------------------------------------------------------------------
    let shown = show(host, &head_ref).expect("show the change through its head ref");
    assert_eq!(shown.digest, published.record_digest);
    assert_eq!(
        shown.bytes,
        resubmitted.canonical_bytes().expect("canonical bytes")
    );
    let shown_record = match &shown.record {
        StoredRecord::Change(record) => record,
        other => panic!("head holds a {}, not a change", other.record_type()),
    };
    assert_eq!(shown_record.attempts.index, 1);
    assert_eq!(
        shown_record.head, commits.second,
        "show says what is proposed"
    );
    assert_eq!(
        shown_record.change_digest().expect("a digest"),
        resubmitted.change_digest().expect("a digest"),
        "the digest a verdict cites survives the round trip through the store"
    );
    assert_eq!(shown.metadata.name, head_ref);

    // ---- merge --------------------------------------------------------------------
    let key = fixture_key("owner");
    let request = merge_request(shown_record, &key);

    // The dry run first, and the dry run must be dry: a plan that wrote something would
    // make the rest of this body a description of a merge that already happened.
    let plan = change::plan_merge(host, &request).expect("plan the merge");
    assert_eq!(plan.change_id, id);
    assert_eq!(plan.attempt, 1);
    assert_eq!(plan.from, oid(&commits.base));
    assert_eq!(plan.to, oid(&commits.second));
    assert_eq!(
        plan.store_oid,
        oid(&commits.base),
        "the store is still at the base"
    );
    assert_eq!(
        plan.change_digest,
        shown_record.change_digest().expect("a digest")
    );
    assert!(!plan.via_forge, "nothing was merged by a forge here");
    assert_eq!(
        branch(host)
            .expect("the branch")
            .expect("the branch is there"),
        oid(&commits.base),
        "a dry run writes nothing"
    );
    assert!(
        host.get_ref(&change::merged_ref(&id))
            .expect("no merge ref yet")
            .is_none(),
        "and writes no record either"
    );

    let outcome = change::merge(host, &request).expect("merge attempt 1");
    assert!(outcome.moved, "this call moved the branch");
    assert_eq!(outcome.record_digest, outcome.record.digest().unwrap());
    assert_eq!(outcome.record.base.branch, BASE_BRANCH);
    assert_eq!(outcome.record.base.from, commits.base);
    assert_eq!(outcome.record.base.to, commits.second);
    assert_eq!(
        outcome.record.change_digest,
        resubmitted.change_digest().expect("a digest"),
        "a merge cites the attempt's change_digest, never its own body digest (D4)"
    );
    assert_ne!(
        outcome.record.change_digest, first_digest,
        "and it cites the attempt that was merged, not the one that came first"
    );
    assert_eq!(outcome.record.attempt, 1);
    assert_eq!(outcome.record.via, "store");
    assert_eq!(
        outcome.record.author.key_id,
        author("owner").key_id,
        "the merge record is signed by whoever moved the branch, not by the change's \
         author (D7)"
    );
    assert_eq!(
        branch(host)
            .expect("the branch after the merge")
            .expect("it is there"),
        oid(&commits.second),
        "the branch fast-forwarded to the attempt's head"
    );

    // The merge record is a record like any other: readable through a create-only ref,
    // verbatim, and what the listing now calls the change's state.
    let merged_ref = change::merged_ref(&id);
    let merged = show(host, &merged_ref).expect("show the merge record");
    assert_eq!(merged.digest, outcome.record_digest);
    match &merged.record {
        StoredRecord::Merge(record) => assert_eq!(record, &outcome.record),
        other => panic!("{} holds a {}", merged_ref, other.record_type()),
    }
    let catalog = change::list_changes(host).expect("list after the merge");
    assert_eq!(catalog.changes.len(), 1);
    assert_eq!(catalog.changes[0].state, State::Merged);
    assert_eq!(
        catalog.changes[0].merged,
        Some(outcome.record_digest),
        "the listing points at the merge record"
    );
    assert_eq!(catalog.changes[0].attempts, vec![0, 1]);

    // ---- merge again is refused ---------------------------------------------------
    // Not "is a no-op": a change is closed exactly once (D7), and the second call is a
    // refusal naming the merge that already happened.
    let again = change::merge(host, &request).expect_err("a change merges exactly once");
    assert!(
        again.is_conflict(),
        "the second merge must be a conflict: {again}"
    );
    assert_eq!(again.kind(), HostErrorKind::Conflict);
    assert_eq!(again.exit_code(), 6);
    assert!(
        again.to_string().contains(&id.hex()[..8]),
        "the refusal names the change it refused: {again}"
    );
    assert_eq!(
        branch(host)
            .expect("the branch after the refused merge")
            .expect("it is there"),
        oid(&commits.second),
        "a refused merge moved nothing"
    );
    assert_eq!(
        host.get_ref(&merged_ref)
            .expect("the merge ref")
            .expect("still the one merge ref")
            .oid,
        outcome.record_digest,
        "and wrote no second merge record"
    );
    // Planning it again says the same thing: the refusal is not an artefact of the write.
    let replanned = change::plan_merge(host, &request).expect_err("planning says so too");
    assert!(replanned.is_conflict(), "{replanned}");

    // And a closed change takes no new attempt: the state is derived from a create-only
    // ref, so "closed" is a fact about the store rather than a field somebody forgot to
    // set (D7).
    let too_late = signed(
        "ada",
        "An attempt that comes too late",
        &commits.first,
        &commits.beyond,
        2,
        Some(resubmitted.change_digest().expect("a digest")),
        &commits.base,
    )
    .expect("a signed attempt 2");
    let err = publish(host, &too_late, "ada").expect_err("a merged change is closed");
    assert_eq!(err.kind(), HostErrorKind::Invalid, "{err}");
    assert!(
        err.to_string().contains("merged"),
        "the refusal says why: {err}"
    );
    assert_eq!(
        change::list_changes(host)
            .expect("the listing is unchanged")
            .changes[0]
            .attempts,
        vec![0, 1],
        "and nothing was half-written on the way to the refusal"
    );
}

/// A merge against a branch that moved is refused — with the same kind, the same exit
/// code and the same advice on every host.
///
/// This is the refusal a forge, a bucket, a bare repository and a directory are *obliged*
/// to agree on, because it is the one that decides whether a stale merge silently drops
/// someone's work. The taxonomy is the contract: exit 6, `invalid`, both oids in the
/// message, nothing written. A host that answered `NotFound` here — the branch moved, so
/// "my base is not there" — would send the reader off to hunt for a branch that is plainly
/// present, and that is exactly the kind of drift only a shared body catches.
pub fn stale_base(host: &dyn Host) {
    let here = describe(host);
    let commits = commits(host).expect("the host can hand out commits it can name");
    publish_branch(host, &commits).expect("the owner publishes the branch");
    let proposal = signed(
        "ada",
        "A change that will find the branch has moved",
        &commits.first,
        &commits.first,
        0,
        None,
        &commits.base,
    )
    .expect("a signed attempt 0");
    publish(host, &proposal, "ada").expect("propose the change");
    let id = proposal.change_id.clone();

    // The record a merge gate uses is the one the store advertises, not the copy the
    // author kept — the same rule `gitiup change merge` follows.
    let record = change_record(host, &change::attempt_ref(&id, 0)).expect("read it back");
    let key = fixture_key("owner");
    let request = merge_request(&record, &key);

    // Someone else lands their work first. The branch moves under this change with a
    // legitimate compare-and-swap of its own.
    let base = oid(&commits.base);
    move_branch(host, &base, &commits.other).expect("another owner moves the branch");
    assert_eq!(
        branch(host).expect("the branch"),
        Some(oid(&commits.other)),
        "the branch really did move"
    );

    // The refusal, in the taxonomy, from both halves of the command.
    let planned = change::plan_merge(host, &request)
        .expect_err("a stale base is refused before anything is written");
    let performed = change::merge(host, &request)
        .expect_err("and it is refused by the merge itself, not only by its dry run");
    assert_eq!(
        planned.kind(),
        HostErrorKind::Invalid,
        "{here}: a stale base is `invalid`, so a script can branch on it ({planned})"
    );
    assert_eq!(
        performed.kind(),
        planned.kind(),
        "{here}: the dry run and the merge must refuse identically"
    );
    assert_eq!(planned.exit_code(), 6, "{here}: 6 is the refusal code");
    assert_eq!(performed.exit_code(), planned.exit_code());
    for message in [planned.to_string(), performed.to_string()] {
        assert!(
            message.contains(&oid_hex(&commits.base)) && message.contains(&oid_hex(&commits.other)),
            "the refusal must name both sides of the move — the only useful advice is \
             'pull first', and that needs both oids: {message}"
        );
        assert!(
            message.contains(BASE_BRANCH),
            "and name the branch that moved: {message}"
        );
    }
    assert!(
        planned.hint().is_some() && performed.hint().is_some(),
        "a refusal that does not say what to do is advice withheld: {planned}"
    );

    // Nothing moved on the way to saying no.
    assert_eq!(
        branch(host).expect("the branch"),
        Some(oid(&commits.other)),
        "a refused merge moved nothing"
    );
    assert!(
        host.get_ref(&change::merged_ref(&id))
            .expect("no merge ref")
            .is_none(),
        "and wrote no record"
    );
    let catalog = change::list_changes(host).expect("the change is untouched");
    assert_eq!(catalog.changes[0].state, State::Open, "still open");
    assert_eq!(catalog.changes[0].attempts, vec![0]);

    // The honest way out exists, and the body proves it rather than quoting the hint:
    // rebuild the change on the branch as it now stands — a *new* change, because a new
    // anchor is a new change (D3) — and it merges cleanly on the same store.
    // A new anchor is a new change (D3), and attempt 0 anchors its own head — so the
    // rebuilt change is anchored at the tip it now stands on and proposes one past it.
    let rebuilt = signed(
        "ada",
        "Rebuilt on the branch as it now stands",
        &commits.beyond,
        &commits.beyond,
        0,
        None,
        &commits.other,
    )
    .expect("a signed attempt 0 of the rebuilt change");
    let rebuilt_published = publish(host, &rebuilt, "ada").expect("propose the rebuilt change");
    let rebuilt_record = change_record(host, &change::attempt_ref(&rebuilt_published.change_id, 0))
        .expect("read the rebuilt change back");
    let merged = change::merge(host, &merge_request(&rebuilt_record, &key))
        .expect("a change whose base is the branch tip merges");
    assert!(merged.moved);
    assert_eq!(
        branch(host).expect("the branch after the rebuild"),
        Some(oid(&commits.beyond)),
        "the rebuilt change merged to its own head"
    );
}

/// Publish on one host, read and merge through another, and get the same digests from
/// both (the cross-host half of giti-b2z.6).
///
/// This is the claim the whole design rests on: a change is a ref, so *where* it lives is
/// not part of what it means. A contributor publishes to a bucket because that is what
/// they have credentials for; the owner merges from a repository because that is where
/// their branch lives. If the two hosts disagreed about a single byte of the record, the
/// merge would cite a digest nobody else could reproduce and every attestation that named
/// it would quietly be about nothing.
///
/// `publisher` and `merger` are two stores of two different kinds. The commits come from
/// whichever of them keeps a commit graph, so the record names objects the merging host
/// can actually name — which is what a real contributor would have fetched anyway.
pub fn across_hosts(publisher: &dyn Host, merger: &dyn Host) {
    let from = describe(publisher);
    let to = describe(merger);
    let commits = commits(if merger.kind() == HostKind::Git {
        merger
    } else {
        publisher
    })
    .expect("the merging host can name its commits");

    // The contributor's store: the branch they branched from, and their change.
    publish_branch(publisher, &commits).expect("the branch travels with the change");
    let proposal = signed(
        "ada",
        "Proposed on one host, merged on another",
        &commits.first,
        &commits.first,
        0,
        None,
        &commits.base,
    )
    .expect("a signed attempt 0");
    let published = publish(publisher, &proposal, "ada").expect("publish on the first host");
    let id = proposal.change_id.clone();
    assert_eq!(
        change::list_changes(publisher)
            .expect("the publishing store lists it")
            .changes
            .len(),
        1
    );

    // The owner's store knows nothing about it yet — and must not, or the transfer below
    // would be proving nothing.
    assert!(
        change::list_changes(merger)
            .expect("the merging store has no changes yet")
            .changes
            .is_empty(),
        "{to} started this test knowing nothing about {id}"
    );
    let carried = transfer(publisher, merger, "").expect("carry the change across");
    assert!(
        carried.objects > 0 && !carried.refs.is_empty(),
        "nothing crossed: {carried:?}"
    );

    // Same record, other host: same bytes, both digests, same listing.
    let head_ref = change::change_head_ref(&id);
    let here = show(merger, &head_ref).expect("the change reads back through the same ref");
    let shown = match &here.record {
        StoredRecord::Change(record) => record,
        other => panic!("head holds a {}, not a change", other.record_type()),
    };
    let there = show(publisher, &head_ref).expect("read the same ref on the far side");
    assert_eq!(
        here.bytes, there.bytes,
        "the record bytes are identical: a change is one document, not one per host \
         ({from} against {to})"
    );
    assert_eq!(
        here.digest, there.digest,
        "the stored digest — the `kv/change/<hex>` key — is the same in both stores"
    );
    assert_eq!(here.digest, published.record_digest);
    assert_eq!(
        shown.change_digest().expect("a digest"),
        proposal.change_digest().expect("a digest"),
        "and so is the digest every attestation and verdict cites"
    );
    assert_eq!(shown.attempts, proposal.attempts);
    assert_eq!(shown.head, commits.first);
    let listing = |host: &dyn Host| {
        let catalog = change::list_changes(host).expect("list changes");
        assert_eq!(
            catalog.changes.len(),
            1,
            "one change on {host}",
            host = describe(host)
        );
        let summary = &catalog.changes[0];
        (
            summary.change_id.as_str().to_string(),
            summary.state,
            summary.head.map(|digest| digest.hex()),
            summary.attempts.clone(),
        )
    };
    assert_eq!(
        listing(merger),
        listing(publisher),
        "both stores answer `change list` identically — id, state, head digest, attempts \
         ({from} against {to})"
    );

    // The owner merges, on their own host, with their own key.
    let key = fixture_key("owner");
    let outcome =
        change::merge(merger, &merge_request(shown, &key)).expect("merge on the other host");
    assert!(outcome.moved);
    assert_eq!(
        branch(merger)
            .expect("the merged branch")
            .expect("it is there"),
        oid(&commits.first)
    );
    assert_eq!(
        outcome.record.change_digest,
        proposal.change_digest().expect("a digest"),
        "the merge record cites the same change_digest the publishing store computes"
    );

    // And the publishing store agrees it was merged, once the merge record crosses back:
    // the same digest, read in the opposite direction. Only the change crosses back —
    // the branch is each store's own business, and the owner's host is now one commit
    // ahead by design.
    let home = change::change_prefix(&id);
    transfer(merger, publisher, &home).expect("carry the merge back");
    let back = show(publisher, &change::merged_ref(&id)).expect("the merge record, from home");
    assert_eq!(back.digest, outcome.record_digest);
    assert_eq!(back.bytes, outcome.record.canonical_bytes().unwrap());
    assert_eq!(
        change::list_changes(publisher)
            .expect("the publishing store sees the state too")
            .changes[0]
            .state,
        State::Merged,
        "merged is merged, whichever host you ask"
    );
}

/// A short, honest label for assertion messages: what kind of host this is and how it
/// says it is reachable.
fn describe(host: &dyn Host) -> String {
    let info: HostInfo = host.describe();
    format!("{} host [{}]", info.kind, info.summary_line())
}

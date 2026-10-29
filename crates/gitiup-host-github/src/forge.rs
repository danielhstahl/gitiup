//! Translation: what a forge gives you, in the vocabulary a host has.
//!
//! The ticket's rule is *translate on the way in, never leak on the way out*. A
//! caller above this module asks for **changes** and **attestations**; it never
//! learns that one of them arrived as a pull request and the other as a check run.
//! That is not cosmetic: the same code has to work against a bucket, where neither
//! exists.
//!
//! | forge thing | gitiup thing | the seam, and what it costs |
//! |-------------|--------------|-----------------------------|
//! | pull request | [`ChangeRecord`] | the forge's merge machinery is the one thing a bucket cannot offer, so on GitHub the adapter *uses* it ([`GitHubHost::open_change`]) instead of emulating a merge — the merge is atomic and reviewed, which is better than what a bucket can do |
//! | pull-request head ref `refs/pull/<n>/head` | read-only, shown as the change's head | GitHub publishes it and will not let anyone write it, so it is read, never leased |
//! | check run | [`AttestationRecord`] | the check run is an **advertisement** ("CI thought this about this commit, look here"); the bytes of record stay in the record store, where a signature can be checked against them verbatim |//! | labels, reviews, `+1` | not translated | server-side policy the host trait has no word for; it stays owner-side, exactly as on the other hosts |
//! | webhooks, and `github.event.*` | [`ChangeFeed`] polling | a gitiup change *is* a ref, so "did anything happen" is one conditional listing — no public URL, no shared secret, no retries on someone else's schedule |
//!
//! # Why a check run is not the attestation
//!
//! An attestation is signed bytes, and a signature is only over the exact bytes. A
//! check run's `output` fields are truncated by the forge (65 535 characters), may
//! be re-encoded on the way through a UI, and are editable by whoever can push the
//! commit. So the canonical bytes go to the record store and to
//! `refs/attestations/<subject>/<digest>` — through [`gitiup_host::attest::publish`],
//! the same code the bucket and git hosts run, not a github-shaped copy of it — and
//! the check run carries a copy *when it fits* plus the digest that identifies the
//! real thing. An attestation whose copy did not fit reports
//! [`AttestationSource::Store`] with the digest and no bytes: a gate that needs the
//! bytes fetches them, and nothing pretends a fragment is a document.

use gitiup_host::{
    Actor, BlobStore, HostError, HostResult, Oid, RefName, RefStore, Timestamp, attest,
};

use crate::api::MAX_CHECK_RUN_OUTPUT_CHARS;
use crate::api::{self, CheckRunOutput, PullRequest};
use crate::codec;
use crate::host::GitHubHost;

/// The change (PR substitute) this adapter publishes attestations under.
pub const ATTESTATION_CHECK_NAME: &str = "gitiup/attest";

/// The prefix of every check run gitiup publishes.
pub const ATTESTATION_CHECK_PREFIX: &str = "gitiup/";

/// Where a change came from, which decides what may be done with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeOrigin {
    /// A pull request: the forge can merge it.
    Pull {
        /// The PR number.
        number: u64,
    },
    /// A bare `refs/changes/<id>/head`, with no pull request yet.
    Ref {
        /// The ref name.
        name: String,
    },
}

/// Whether a change is still open, merged, or closed without merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeState {
    /// Still proposed.
    Open,
    /// Merged: the base branch moved to include it.
    Merged,
    /// Closed without merging.
    Closed,
}

impl ChangeState {
    /// Stable name for `--json`.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeState::Open => "open",
            ChangeState::Merged => "merged",
            ChangeState::Closed => "closed",
        }
    }
}

/// A proposed change, whichever forge (if any) is carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    /// `gh-<number>` for a pull request, `<id>` for a change ref.
    pub id: String,
    /// Human title.
    pub title: String,
    /// Description.
    pub summary: Option<String>,
    /// Open, merged or closed.
    pub state: ChangeState,
    /// Proposed but not ready.
    pub draft: bool,
    /// Who proposed it.
    pub author: Option<String>,
    /// The branch it wants to land on.
    pub base: Option<RefName>,
    /// Where that branch was when the forge computed the diff.
    pub base_oid: Option<Oid>,
    /// The commit being proposed.
    pub head: Option<Oid>,
    /// `owner/repo` of the head, when it is a fork.
    pub head_repo: Option<String>,
    /// When it was opened.
    pub opened_at: Option<u64>,
    /// When it last changed — the poll cursor.
    pub updated_at: Option<u64>,
    /// When it merged.
    pub merged_at: Option<u64>,
    /// Where a human can look at it.
    pub url: Option<String>,
    /// Labels, shown as-is and never interpreted.
    pub labels: Vec<String>,
    /// Where this change came from, and what that makes possible.
    pub origin: ChangeOrigin,
    /// The attestation this store holds for the change's head, if any.
    pub attestation: Option<Oid>,
}

impl ChangeRecord {
    /// Translate a pull request.
    pub fn from_pull(pull: &PullRequest) -> ChangeRecord {
        ChangeRecord {
            id: format!("gh-{}", pull.number),
            title: pull.title.clone(),
            summary: pull.body.clone(),
            state: if pull.merged() {
                ChangeState::Merged
            } else if pull.state == "closed" {
                ChangeState::Closed
            } else {
                ChangeState::Open
            },
            draft: pull.draft,
            author: pull.user.as_ref().and_then(|user| user.login.clone()),
            base: pull
                .base
                .as_ref()
                .and_then(|base| base.name.as_deref())
                .and_then(|name| RefName::branch(name).ok()),
            base_oid: pull
                .base
                .as_ref()
                .and_then(|base| base.sha.as_deref())
                .and_then(|sha| Oid::from_hex(sha).ok()),
            head: pull
                .head
                .as_ref()
                .and_then(|head| head.sha.as_deref())
                .and_then(|sha| Oid::from_hex(sha).ok()),
            head_repo: pull
                .head
                .as_ref()
                .and_then(|head| head.repo.as_ref())
                .and_then(|repo| repo.full_name.clone()),
            opened_at: stamp(&pull.created_at),
            updated_at: stamp(&pull.updated_at),
            merged_at: stamp(&pull.merged_at),
            url: pull.html_url.clone(),
            labels: pull
                .labels
                .iter()
                .filter_map(|label| label.name.clone())
                .collect(),
            origin: ChangeOrigin::Pull {
                number: pull.number,
            },
            attestation: None,
        }
    }

    /// Whether a merge through the forge is possible for this change.
    pub fn mergeable_via_forge(&self) -> bool {
        matches!(self.origin, ChangeOrigin::Pull { .. }) && self.state == ChangeState::Open
    }
}

/// Where the bytes of an attestation were read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationSource {
    /// The record store: authoritative, verbatim.
    Store,
    /// A check run's copy only: readable, but not the thing a signature covers
    /// unless it re-hashes to the digest.
    CheckRun,
    /// Both, and they agree.
    Both,
}

/// An attestation as the host reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRecord {
    /// The check-run name, or `gitiup/attest` for one found by ref.
    pub name: String,
    /// The commit it is about.
    pub subject: Oid,
    /// SHA-256 of the canonical attestation bytes: the digest a gate compares.
    pub digest: Oid,
    /// The bytes, when they could be read.
    pub bytes: Option<Vec<u8>>,
    /// Where the bytes came from, and whether they were complete.
    pub source: AttestationSource,
    /// The copy in the check run was cut off by the forge's own limit.
    pub copy_truncated: bool,
    /// The forge's conclusion for the check (`success`, `failure`, …).
    pub conclusion: Option<String>,
    /// Where the publisher pointed a human.
    pub details_url: Option<String>,
    /// When it was published.
    pub published_at: Option<u64>,
}

impl AttestationRecord {
    /// Whether these are the real bytes: they are present and they hash to the
    /// digest the record claims.
    pub fn verbatim(&self) -> bool {
        self.bytes
            .as_ref()
            .is_some_and(|bytes| Oid::hash_bytes(bytes) == self.digest)
    }
}

/// What a change feed has already seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeFeedCursor {
    /// Only changes updated after this moment are new.
    pub updated_after: Option<u64>,
    /// The highest pull number seen (a tie-breaker for two changes updated in the
    /// same second).
    pub highest_number: u64,
}

/// What a forge's merge says it did, in gitiup's shapes: a state, an oid, a branch
/// name. No wire vocabulary crosses this boundary — that is the rule the crate exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeMerge {
    /// Merged, or closed without merging: the forge's answer, re-read rather than
    /// assumed.
    pub state: ChangeState,
    /// The commit the forge put on the base branch (its merge commit, or the head for a
    /// fast-forward), when it said.
    pub landed: Option<Oid>,
    /// The branch that moved, when the forge said.
    pub branch: Option<String>,
}

impl GitHubHost {
    /// Every change, newest change first (`state`: `all`, `open`, `closed`).
    ///
    /// Changes arrive from two places and are merged: the forge's pull requests
    /// (which carry the merge machinery, the discussion and the review state) and
    /// this store's `refs/changes/**` (which a contributor can publish without any
    /// write access to the pull-request API, and which is all a bucket host has).
    pub fn changes(&self, state: &str) -> HostResult<Vec<ChangeRecord>> {
        let pulls = api::list_pulls(self.client(), state)?;
        let mut out: Vec<ChangeRecord> = pulls.iter().map(ChangeRecord::from_pull).collect();
        for reference in self.list_refs(&gitiup_host::RefQuery::prefix(
            gitiup_host::refs::ns::CHANGES,
        ))? {
            let Some(id) = reference.name.change_id() else {
                continue;
            };
            // The same change seen twice: keep the pull, which knows more. Two
            // ways that happens — the ref is named after the forge's number (the
            // usual case for a change gitiup opened on this host), or the ref and
            // the pull propose the same commit, which is the case for a change
            // whose ref predates the pull request, or was pushed independently.
            let numbered = out.iter().any(|change| change.id == format!("gh-{id}"));
            let same_commit = reference.oid.len() == 20
                && out.iter().any(|change| change.head == Some(reference.oid));
            if numbered || same_commit {
                continue;
            }
            out.push(ChangeRecord {
                id: id.to_string(),
                title: format!("change {id}"),
                summary: None,
                state: ChangeState::Open,
                draft: false,
                author: reference.updated_by.as_ref().map(|actor| actor.to_string()),
                base: None,
                base_oid: None,
                head: Some(reference.oid),
                head_repo: None,
                opened_at: reference.updated_at.map(|stamp| stamp.as_unix()),
                updated_at: reference.updated_at.map(|stamp| stamp.as_unix()),
                merged_at: None,
                url: None,
                labels: Vec::new(),
                origin: ChangeOrigin::Ref {
                    name: reference.name.to_string(),
                },
                attestation: None,
            });
        }
        out.sort_by(|a, b| {
            b.updated_at
                .unwrap_or(0)
                .cmp(&a.updated_at.unwrap_or(0))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// Propose a change: publish the ref *and* open the pull request.
    ///
    /// The ref comes first, because it is the part the contributor owns: if the
    /// pull request cannot be opened (no permission, a fork, a review gate), the
    /// change still exists and is still verifiable. The forge's merge is then used
    /// rather than imitated — the one place where being on a forge is genuinely
    /// better than being in a bucket.
    pub fn open_change(
        &self,
        title: &str,
        head_branch: &str,
        base_branch: &str,
        body: &str,
        draft: bool,
    ) -> HostResult<ChangeRecord> {
        let pull = api::create_pull(self.client(), title, head_branch, base_branch, body, draft)?;
        Ok(ChangeRecord::from_pull(&pull))
    }

    /// Merge a change the forge carries, with the forge's own merge (D10).
    ///
    /// This is the one place gitiup *uses* a forge instead of routing around it. A
    /// forge's merge is atomic and reviewed; a bucket's is a conditional write
    /// pretending to be one, which is why the same verb is a CAS write on a store and
    /// this call on a forge. `sha` is handed to the forge as the caller's expectation —
    /// the forge's own compare-and-swap, and the reason no ref write is needed here.
    ///
    /// The change is re-read afterwards rather than assumed: a pull that closed without
    /// merging comes back as closed, because printing "merged" for a change that was
    /// merely refused is the kind of lie a merge gate exists to catch.
    pub fn merge_change(&self, number: u64, sha: &Oid, method: &str) -> HostResult<ForgeMerge> {
        let answer = api::merge_pull(self.client(), number, &sha.hex(), method)?;
        let pull = api::get_pull(self.client(), number)?.ok_or_else(|| {
            HostError::not_found("pull request", number.to_string()).with_hint(
                "the forge merged and then would not show the change; check the repository \
                 the remote points at",
            )
        })?;
        let change = ChangeRecord::from_pull(&pull);
        Ok(ForgeMerge {
            state: change.state,
            landed: answer
                .sha
                .as_deref()
                .and_then(|hex| Oid::from_hex(hex).ok()),
            branch: answer.base_branch,
        })
    }

    /// Close a change without merging it.
    pub fn close_change(&self, number: u64) -> HostResult<()> {
        api::set_pull_state(self.client(), number, "closed")
    }

    /// The next thing that happened, without a webhook.
    ///
    /// GitHub pushes events to a URL; gitiup pulls state. That is not laziness —
    /// a change is a ref and a record, so "what is new" is one conditional listing
    /// of state that already exists, and it needs no public endpoint, no shared
    /// secret, no retry policy on someone else's server, and no assumption that the
    /// forge's delivery arrived before the CI job started. A workflow that reads
    /// `github.event.*` gets that context from the runner that started it
    /// (`gitiup-run` synthesises it), not from a delivery here.
    pub fn poll_changes(
        &self,
        cursor: Option<&ChangeFeedCursor>,
    ) -> HostResult<(Vec<ChangeRecord>, ChangeFeedCursor)> {
        let seen = cursor.cloned().unwrap_or_default();
        let all = self.changes("all")?;
        let mut fresh: Vec<ChangeRecord> = Vec::new();
        let mut next = ChangeFeedCursor {
            updated_after: seen.updated_after,
            highest_number: seen.highest_number,
        };
        for change in all {
            let number = match change.origin {
                ChangeOrigin::Pull { number } => number,
                // A change ref has no forge number; treat its ref as the identity and
                // let the timestamp decide.
                ChangeOrigin::Ref { .. } => 0,
            };
            let newer = match (change.updated_at, seen.updated_after) {
                (Some(at), Some(since)) => {
                    at > since || (at == since && number > seen.highest_number)
                }
                (Some(_), None) => true,
                (None, _) => seen.updated_after.is_none(),
            };
            if newer {
                if let Some(at) = change.updated_at {
                    next.updated_after = Some(next.updated_after.map_or(at, |older| older.max(at)));
                }
                next.highest_number = next.highest_number.max(number);
                fresh.push(change);
            }
        }
        Ok((fresh, next))
    }

    /// Publish an attestation: store it, ref it, and let the forge advertise it.
    ///
    /// Returns the record as it now exists, with the bytes it could be read back
    /// as — because a publish that cannot be read back verbatim has not published
    /// anything worth checking.
    ///
    /// The store and ref writes are [`attest::publish`], the same call the bucket and
    /// git hosts make, so a proof filed here is listed by `gitiup attest list
    /// --commit` and fetched by `git fetch 'refs/attestations/<subject>/*'` exactly
    /// as one filed anywhere else. The check run is only ever added on top.
    pub fn publish_attestation(
        &self,
        subject: &Oid,
        bytes: &[u8],
        details_url: Option<&str>,
    ) -> HostResult<AttestationRecord> {
        let published = attest::publish(self, subject, bytes, Actor::from("gitiup"))?;
        let digest = published.digest;
        // The check run is the advertisement, and it is only for a commit the forge
        // has. A subject that is not a git commit (a record digest) gets the ref and
        // the store entry, which is everything a gate needs.
        let mut source = AttestationSource::Store;
        let mut copy_truncated = false;
        if subject.len() == 20 {
            let encoded = codec::encode_base64(bytes);
            let (summary, truncated) = summary_for(&encoded, &digest);
            copy_truncated = truncated;
            api::create_check_run(
                self.client(),
                ATTESTATION_CHECK_NAME,
                &subject.hex(),
                &digest.hex(),
                details_url,
                &CheckRunOutput {
                    title: Some(format!("gitiup: attested {}", short(&digest.hex()))),
                    summary: Some(summary),
                    text: None,
                },
            )?;
            source = if truncated {
                AttestationSource::Store
            } else {
                AttestationSource::Both
            };
        }
        Ok(AttestationRecord {
            name: ATTESTATION_CHECK_NAME.to_string(),
            subject: *subject,
            digest,
            bytes: Some(bytes.to_vec()),
            source,
            copy_truncated,
            conclusion: Some("success".to_string()),
            details_url: details_url.map(str::to_string),
            published_at: Some(Timestamp::now().as_unix()),
        })
    }

    /// Every attestation this host knows about a commit, from both paths.
    ///
    /// Deduplicated by digest, preferring the copy whose bytes are present and
    /// complete: the store is asked first because it is the authority, and the check
    /// runs add anything published elsewhere (a runner that never got store access,
    /// for instance) — which is exactly the case where "translated, not leaked"
    /// earns its keep.
    pub fn attestations_for(&self, subject: &Oid) -> HostResult<Vec<AttestationRecord>> {
        let mut out: Vec<AttestationRecord> = Vec::new();
        // 1. The host-neutral path: every ref this store wrote for this subject,
        // in either shape, read by the same code that lists any other host's.
        let catalog = attest::list_for(self, subject)?;
        for entry in catalog.entries {
            let Some(bytes) = self.get(&entry.digest)? else {
                continue;
            };
            out.push(AttestationRecord {
                name: ATTESTATION_CHECK_NAME.to_string(),
                subject: entry.subject,
                digest: entry.digest,
                bytes: Some(bytes),
                source: AttestationSource::Store,
                copy_truncated: false,
                conclusion: None,
                details_url: None,
                published_at: entry.updated_at.map(|at| at.as_unix()),
            });
        }
        // 2. The forge's own bookkeeping.
        for run in api::list_check_runs(self.client(), &subject.hex(), None)? {
            if !run.name.starts_with(ATTESTATION_CHECK_PREFIX) {
                continue;
            }
            let Some(external) = run.external_id.as_deref() else {
                continue;
            };
            let Ok(digest) = Oid::from_hex(external) else {
                continue;
            };
            let already = out.iter().position(|found| found.digest == digest);
            if let Some(index) = already {
                // The store already gave us this proof, so the check run adds only
                // what a store cannot know: the forge's conclusion and where the
                // publisher pointed a human. Saying `Both` is the point — the proof
                // was seen by both paths, and the bytes of record are the store's.
                let found = &mut out[index];
                if found.bytes.is_some() {
                    found.source = AttestationSource::Both;
                }
                if found.conclusion.is_none() {
                    found.conclusion = run.conclusion.clone();
                }
                if found.details_url.is_none() {
                    found.details_url = run.details_url.clone();
                }
                if found.published_at.is_none() {
                    found.published_at = stamp(&run.created_at);
                }
                continue;
            }
            let stored = self.get(&digest)?;
            let (bytes, source, truncated) = match stored {
                Some(bytes) => (Some(bytes), AttestationSource::Both, false),
                None => match extract_copy(run.output.summary.as_deref()) {
                    Some((bytes, truncated)) => {
                        (Some(bytes), AttestationSource::CheckRun, truncated)
                    }
                    None => (None, AttestationSource::CheckRun, true),
                },
            };
            out.push(AttestationRecord {
                name: run.name.clone(),
                subject: *subject,
                digest,
                bytes,
                source,
                copy_truncated: truncated,
                conclusion: run.conclusion.clone(),
                details_url: run.details_url.clone(),
                published_at: stamp(&run.created_at),
            });
        }
        // A record whose bytes are present and hash correctly sorts first: a gate
        // reading this list should not have to know which of two spellings is real.
        out.sort_by_key(|record| (!record.verbatim(), record.digest.hex()));
        Ok(out)
    }
}

/// The summary block a check run carries.
fn summary_for(encoded: &str, digest: &Oid) -> (String, bool) {
    let fence = "```";
    let complete = format!(
        "gitiup attestation `{}` — the bytes of record are in the store at \
         `attestation/{}`; this is a copy.\n\n{fence}base64\n{encoded}\n{fence}\n",
        short(&digest.hex()),
        digest.hex()
    );
    if complete.chars().count() <= MAX_CHECK_RUN_OUTPUT_CHARS {
        return (complete, false);
    }
    // Too big for the forge to hold: advertise the digest, say plainly that the copy
    // is not there, and let the caller go to the store for the bytes.
    (
        format!(
            "gitiup attestation `{}` — the copy was too large for the forge to hold, \
             so only the digest is advertised. Fetch `attestation/{}` from the store to \
             check it.\n",
            short(&digest.hex()),
            digest.hex()
        ),
        true,
    )
}

/// Pull a base64 copy back out of a check-run summary.
///
/// Returns the decoded bytes and whether the copy was truncated (which the caller
/// then reports rather than hiding). A truncated copy almost never decodes at all,
/// and saying "no copy" is truer than returning garbage.
fn extract_copy(summary: Option<&str>) -> Option<(Vec<u8>, bool)> {
    let text = summary?;
    let inside = text.split("```").nth(1)?;
    let encoded: String = inside
        .lines()
        .skip(1)
        .collect::<Vec<&str>>()
        .join("")
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    match codec::decode_base64(&encoded) {
        Ok(bytes) => Some((bytes, false)),
        Err(_) => {
            // Cut the tail off until it decodes: that is what a truncated copy is.
            let mut candidate = encoded.as_str();
            loop {
                let cut = candidate.len().saturating_sub(candidate.len() % 4);
                if let Ok(bytes) = codec::decode_base64(&candidate[..cut])
                    && !bytes.is_empty()
                {
                    return Some((bytes, true));
                }
                if cut < 4 {
                    return None;
                }
                candidate = &candidate[..cut - 4];
            }
        }
    }
}

fn stamp(text: &Option<String>) -> Option<u64> {
    text.as_deref()
        .and_then(|value| Timestamp::parse(value).ok())
        .map(|stamp| stamp.as_unix())
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

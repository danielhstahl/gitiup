//! The forge side of `gitiup migrate repo` — what leaves a forge, and what honestly cannot.
//!
//! [ADR-0005](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)
//! decides what may travel between two stores, and [`gitiup_host::federation`] carries it.
//! A forge is a special case of "a store" for exactly one reason: it holds two databases
//! that no bucket has — the pull-request table and the check-run table — and neither is
//! expressed in refs. Leaving a forge therefore needs one more reader, and this module is
//! that reader: it asks the forge what it holds and answers in gitiup's shapes and nobody
//! else's. What it produces is *data and refusals*, never a write: writing belongs to
//! whichever store is on the other side, through the same [`RefStore`]/[`BlobStore`] calls
//! every other copy uses.
//!
//! ```text
//! branches and tags       → ordinary refs, names and oids unchanged
//! open and merged PRs     → a change whose origin is `pull <n>`, plus its head commit
//! check runs              → an attestation *when the bytes of record can be rebuilt*,
//!                           and a named refusal when they cannot
//! ```
//!
//! # The one thing this module exists to refuse
//!
//! A check run is an **advertisement**. The forge truncates its output at
//! [`MAX_CHECK_RUN_OUTPUT_CHARS`], re-renders it through a web UI, and whoever can push the
//! commit can edit the check run. So the only check run that becomes an attestation here is
//! one whose copy *re-hashes to the digest it claims* — which makes it the same document
//! that was signed, byte for byte, and not a reconstruction in any interesting sense.
//! Every other check run is reported as dropped with a token, and no token here means
//! "we made something up from it":
//!
//! | token | the check run it names |
//!|-------|----------------------|
//!| `check_run_not_gitiup` | not published by gitiup at all: somebody's build log |
//!| `check_run_no_digest` | carries no `external_id`, so there is no digest to check a copy against |
//!| `check_run_no_copy` | names a digest but holds no copy of the bytes |
//!| `check_run_copy_truncated` | the copy is cut short — a fragment of a signed document is not that document |
//!| `check_run_digest_mismatch` | the copy decoded and hashes to something else, so it is not the bytes the digest names |
//!| `check_run_not_completed` | still queued or in progress: an opinion that has not been formed yet |
//!
//! That last column is the ticket's "a check-run log is an advertisement, not a signature,
//! and the tool must not manufacture trust from it", turned into six strings a report can
//! print. Nothing here signs, re-signs, re-encodes or fills in a field, and nothing here
//! decides that a proof is acceptable: `gitiup verify` does that, in the reader, from the
//! reader's own trust roots ([ADR-0005 D3](../../../docs/adr/0005-what-a-mirror-may-carry-and-what-a-copy-is-worth.md)).
//!
//! # Rate limits, because leaving is a big call
//!
//! A repository with a few thousand refs and a year of check runs is a few thousand calls,
//! and the forge's quota is per-hour. [`inventory`] therefore checks the budget the client
//! is already keeping *before* each listing and stops with [`RATE_TOKEN`] when what is left
//! is under the caller's floor — a clean stop with a checkpoint, which a resumable command
//! can be re-run from, rather than a run that dies an hour into a sleep-until-reset.
//!
//! [`RefStore`]: gitiup_host::RefStore
//! [`BlobStore`]: gitiup_host::BlobStore

use std::collections::BTreeSet;

use gitiup_host::{HostError, HostResult, Oid};

use crate::api::{self, PullRequest};
use crate::client::RateBudget;
use crate::forge::{ATTESTATION_CHECK_PREFIX, ChangeState, extract_copy};
use crate::host::GitHubHost;

/// The forge's quota is at (or under) the caller's floor, so the run stopped itself.
///
/// Not a 3 (nothing is broken and nothing is unreachable) and not a 4 (the credential is
/// fine): the forge has nothing more to give this hour, which is a refusal to continue and
/// carries exit 6 with it. The report says where it stopped, and re-running picks up there.
pub const RATE_TOKEN: &str = "rate_budget_exhausted";

/// A check run somebody else's CI published: an advertisement with no gitiup document
/// behind it, and nothing in it that a signature would cover.
pub const NOT_GITIUP: &str = "check_run_not_gitiup";
/// A gitiup-prefixed check run with no `external_id`, so there is no digest to check a copy
/// against — and an unchecked copy is exactly the trust laundering ADR-0005 D3 forbids.
pub const NO_DIGEST: &str = "check_run_no_digest";
/// The check run names a digest but holds no copy of the bytes (it was too big for the
/// forge to hold, or the publisher only ever advertised).
pub const NO_COPY: &str = "check_run_no_copy";
/// The copy in the check run is cut short. A prefix of a signed document is not that
/// document, and filing the prefix under the digest would make the store the thing that
/// broke the signature.
pub const COPY_TRUNCATED: &str = "check_run_copy_truncated";
/// The copy decoded and hashes to something other than the digest the check run names.
pub const COPY_MISMATCH: &str = "check_run_digest_mismatch";
/// The check run has not finished, so its conclusion is a placeholder.
pub const NOT_COMPLETED: &str = "check_run_not_completed";
/// A pull request closed without merging: nothing landed and nothing was proposed to land
/// any more, and a `refs/changes/**` head that no branch will ever take is a ref that lies
/// about what is open.
pub const CLOSED_UNMERGED: &str = "pull_closed_unmerged";
/// The forge would not name a head commit for this pull request.
pub const NO_HEAD: &str = "pull_head_missing";
/// The forge would not name the commit the head was based on, so the record would have to
/// invent its `base.oid` (ADR-0003 D1: a merge compares against it).
pub const NO_BASE: &str = "pull_base_missing";
/// A merged pull request whose merge commit the forge did not name, so no merge record can
/// be written for it — the change still moves, without the record of its landing.
pub const MERGE_COMMIT_UNKNOWN: &str = "pull_merge_commit_unknown";
/// A ref under a prefix this command was not told to take. Everything the forge advertises
/// outside `refs/heads` and `refs/tags` is somebody's plumbing (`refs/pull/**`,
/// `refs/merge/**`, a forge's own bookkeeping) and is reported rather than dropped.
pub const REF_OUT_OF_SCOPE: &str = "ref_out_of_scope";

/// Every token this module can put in a report, with the exit code it carries.
pub const TOKENS: &[(&str, u8)] = &[
    (RATE_TOKEN, 6),
    (NOT_GITIUP, 6),
    (NO_DIGEST, 6),
    (NO_COPY, 6),
    (COPY_TRUNCATED, 6),
    (COPY_MISMATCH, 8),
    (NOT_COMPLETED, 6),
    (CLOSED_UNMERGED, 6),
    (NO_HEAD, 6),
    (NO_BASE, 6),
    (MERGE_COMMIT_UNKNOWN, 6),
    (REF_OUT_OF_SCOPE, 6),
];

/// The exit code a token carries (8 for a copy that is not the bytes its name promises, 6
/// for every other refusal here).
pub fn exit_for(token: &str) -> u8 {
    TOKENS
        .iter()
        .find(|(known, _)| *known == token)
        .map(|(_, code)| *code)
        .unwrap_or(6)
}

/// What to ask the forge for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Want {
    /// `refs/heads/**`.
    pub branches: bool,
    /// `refs/tags/**`.
    pub tags: bool,
    /// The pull-request table.
    pub pulls: bool,
    /// The check-run table. One call, so it is cheap; the flag is about *scope*, since a
    /// check-run table can be the largest listing a repository has.
    pub evidence: bool,
}

impl Want {
    /// Branches, tags and pull requests: everything that is a ref or becomes one.
    pub fn refs_and_changes() -> Want {
        Want {
            branches: true,
            tags: true,
            pulls: true,
            evidence: false,
        }
    }

    /// Everything, including the check-run table.
    pub fn everything() -> Want {
        Want {
            branches: true,
            tags: true,
            pulls: true,
            evidence: true,
        }
    }

    /// The scope as one line, for a report header.
    pub fn describe(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.branches {
            parts.push("branches");
        }
        if self.tags {
            parts.push("tags");
        }
        if self.pulls {
            parts.push("pulls");
        }
        if self.evidence {
            parts.push("check-runs");
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// A ref the forge advertises, in the two facts gitiup needs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeRef {
    /// The full ref name, exactly as the forge spells it (`refs/heads/main`).
    pub name: String,
    /// The object it names.
    pub oid: Oid,
    /// Whether the forge called it a commit or a tag object.
    pub kind: Option<String>,
}

/// A pull request, translated.
///
/// This is [`crate::forge::ChangeRecord`] narrowed to what a migration writes, plus the one
/// fact only a migration needs: the merge commit, which is what makes a *merge record*
/// honest. A pull with no head, or no base commit, cannot become a gitiup change at all
/// (both are fields a signed record must carry), and is reported instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull {
    /// The forge's number, which goes into the record's `origin: pull`.
    pub number: u64,
    /// One line, as the forge holds it.
    pub title: String,
    /// The body, as the forge holds it. Unsigned, and stays unsigned: it travels as an
    /// annotation, never as a claim.
    pub summary: Option<String>,
    /// `open` or `merged` — a closed-without-merge pull is dropped, not carried.
    pub state: ChangeState,
    /// Draft, kept as an annotation: a draft is a real proposal someone is working on.
    pub draft: bool,
    /// The login that opened it, as an annotation. Not an author: no signature covers it.
    pub author: Option<String>,
    /// Where a human can look.
    pub url: Option<String>,
    /// The commit proposed.
    pub head: Oid,
    /// The branch it lands on, without `refs/heads/`.
    pub base_branch: String,
    /// Where that branch stood when the forge computed the diff.
    pub base_oid: Oid,
    /// The head's repository, when the pull is a fork's.
    pub head_repo: Option<String>,
    /// The merge commit, when the forge named one.
    pub merge_commit: Option<Oid>,
    /// When it merged, in microseconds.
    pub merged_at_us: Option<i64>,
    /// Labels, verbatim.
    pub labels: Vec<String>,
}

impl Pull {
    /// Translate one pull request, or say why it cannot become a change.
    pub fn translate(pull: &PullRequest) -> Result<Pull, (&'static str, String)> {
        let Some(head_hex) = pull
            .head
            .as_ref()
            .and_then(|head| head.sha.as_deref())
            .filter(|sha| !sha.is_empty())
        else {
            return Err((NO_HEAD, "the forge named no head commit".to_string()));
        };
        let Some(base_hex) = pull
            .base
            .as_ref()
            .and_then(|base| base.sha.as_deref())
            .filter(|sha| !sha.is_empty())
        else {
            return Err((
                NO_BASE,
                "the forge named no commit for the base branch, and a change record's \
                 base.oid is what a merge compares against"
                    .to_string(),
            ));
        };
        let head = Oid::from_hex(head_hex).map_err(|e| (NO_HEAD, format!("{e}")))?;
        let base_oid = Oid::from_hex(base_hex).map_err(|e| (NO_BASE, format!("{e}")))?;
        let base_branch = pull
            .base
            .as_ref()
            .and_then(|base| base.name.clone())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                (
                    NO_BASE,
                    "the forge named no base branch for this pull request".to_string(),
                )
            })?;
        let merged = pull.merged();
        Ok(Pull {
            number: pull.number,
            title: pull.title.clone(),
            summary: pull.body.clone(),
            state: if merged {
                ChangeState::Merged
            } else {
                ChangeState::Open
            },
            draft: pull.draft,
            author: pull
                .user
                .as_ref()
                .and_then(|user| user.login.clone())
                .filter(|login| !login.is_empty()),
            url: pull.html_url.clone(),
            head,
            base_branch,
            base_oid,
            head_repo: pull
                .head
                .as_ref()
                .and_then(|head| head.repo.as_ref())
                .and_then(|repo| repo.full_name.clone()),
            merge_commit: pull
                .merge_commit_sha
                .as_deref()
                .filter(|sha| !sha.is_empty())
                .and_then(|sha| Oid::from_hex(sha).ok()),
            merged_at_us: pull
                .merged_at
                .as_deref()
                .and_then(|stamp| gitiup_host::Timestamp::parse(stamp).ok())
                .and_then(|stamp| i64::try_from(stamp.as_unix()).ok())
                .map(|secs| secs * 1_000_000),
            labels: pull
                .labels
                .iter()
                .filter_map(|label| label.name.clone())
                .collect(),
        })
    }
}

/// One check run, in the shapes gitiup has for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The check-run name (`gitiup/attest`, `build`, …).
    pub name: String,
    /// The commit it is about.
    pub subject: Oid,
    /// The digest it claims to be a copy of, when it claims one.
    pub claims: Option<Oid>,
    /// The copy's bytes, when the forge held any.
    pub bytes: Option<Vec<u8>>,
    /// Whether the copy was cut short by the forge's own limit.
    pub truncated: bool,
    /// The forge's conclusion, kept as an annotation and never as a proof.
    pub conclusion: Option<String>,
    /// Where the publisher pointed a human.
    pub details_url: Option<String>,
    /// Whether the run had finished.
    pub completed: bool,
}

impl Evidence {
    /// The bytes of record, or the token saying why there are none.
    ///
    /// `Ok` means one thing only: these bytes hash to the digest this check run names, so
    /// they are the document the digest was made from. It says nothing about whether a
    /// *reader* will accept the signature on them, which is not this command's question to
    /// answer (ADR-0005 D3).
    pub fn reconstructed(&self) -> Result<&[u8], (&'static str, String)> {
        if !self.name.starts_with(ATTESTATION_CHECK_PREFIX) {
            return Err((
                NOT_GITIUP,
                format!(
                    "`{}` is not a gitiup check run, so no signed document is behind it",
                    self.name
                ),
            ));
        }
        if !self.completed {
            return Err((
                NOT_COMPLETED,
                "the run had not finished, so it holds no conclusion".to_string(),
            ));
        }
        let Some(claims) = self.claims else {
            return Err((
                NO_DIGEST,
                "no external_id, so there is no digest to check a copy against".to_string(),
            ));
        };
        if !self.completed {
            return Err((NOT_COMPLETED, "the run had not finished".to_string()));
        }
        let Some(bytes) = self.bytes.as_deref() else {
            return Err((
                NO_COPY,
                format!(
                    "it names {} and holds no copy of it; the bytes of record are in the \
                     store it was published to, and this forge does not have them",
                    claims.short_default()
                ),
            ));
        };
        if self.truncated {
            return Err((
                COPY_TRUNCATED,
                "the copy is cut short by the forge's output limit, and a prefix of a \
                 signature is not a signature"
                    .to_string(),
            ));
        }
        let hashed = Oid::hash_bytes(bytes);
        if hashed != claims {
            return Err((
                COPY_MISMATCH,
                format!(
                    "the copy hashes to {}, not the {} the check run names",
                    hashed.short_default(),
                    claims.short_default()
                ),
            ));
        }
        Ok(bytes)
    }
}

/// One thing that did not come, and the sentence about why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// One of this module's tokens.
    pub token: &'static str,
    /// What kind of thing it is (`check-run`, `pull`, `ref`).
    pub class: &'static str,
    /// Its name or id, as the forge spells it.
    pub name: String,
    /// The reason, in the tool's own words.
    pub detail: String,
}

impl Dropped {
    /// The line a report prints.
    pub fn line(&self) -> String {
        format!("{}  {}  {}", self.token, self.name, self.detail)
    }
}

/// What the forge holds, as gitiup shapes, plus what it holds that will not come.
#[derive(Debug, Default)]
pub struct Inventory {
    /// `refs/heads/**`, sorted by name.
    pub branches: Vec<ForgeRef>,
    /// `refs/tags/**`, sorted by name.
    pub tags: Vec<ForgeRef>,
    /// Open and merged pull requests, sorted by number.
    pub pulls: Vec<Pull>,
    /// Every check run the forge would name, in the forge's order.
    pub evidence: Vec<Evidence>,
    /// Everything the forge has that this migration will not carry, by name and token.
    pub dropped: Vec<Dropped>,
    /// How many calls it took.
    pub calls: usize,
    /// What the forge last said about the quota.
    pub rate: RateBudget,
}

impl Inventory {
    /// Every ref the forge advertised in scope, branches first.
    pub fn refs(&self) -> impl Iterator<Item = &ForgeRef> {
        self.branches.iter().chain(self.tags.iter())
    }

    /// The commits this migration will move: every ref tip and every pull head.
    pub fn commits(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for reference in self.refs() {
            out.insert(reference.oid.hex().to_lowercase());
        }
        for pull in &self.pulls {
            out.insert(pull.head.hex().to_lowercase());
            if let Some(merge) = &pull.merge_commit {
                out.insert(merge.hex().to_lowercase());
            }
        }
        out
    }

    /// The refusal tally, as `(token, count)`, sorted.
    pub fn dropped_by(&self) -> Vec<(&'static str, usize)> {
        let mut tally: Vec<(&'static str, usize)> = Vec::new();
        for dropped in &self.dropped {
            match tally.iter_mut().find(|(token, _)| *token == dropped.token) {
                Some((_, count)) => *count += 1,
                None => tally.push((dropped.token, 1)),
            }
        }
        tally.sort();
        tally
    }
}

/// Ask the forge what it holds.
///
/// Every listing is checked against `floor` first: with fewer than `floor` calls left on
/// the quota, this stops with [`RATE_TOKEN`] rather than starting a listing it cannot
/// finish. That is the resumable shape — stop, checkpoint, come back — and the alternative
/// (sleep until the window resets, with an hour of work already half-done and nothing
/// written down) is what a bad link punishes.
pub fn inventory(host: &GitHubHost, want: &Want, floor: u32) -> HostResult<Inventory> {
    let mut out = Inventory::default();
    let mut calls = 0usize;
    // One call, and the first: it is the one that tells the client what the quota is, so a
    // run started against an exhausted token fails here rather than after three listings.
    check_budget(host, floor)?;
    calls += 1;
    let default_branch = host.default_branch().ok().flatten();

    if want.branches || want.tags {
        for (prefix, take) in [("refs/heads", want.branches), ("refs/tags", want.tags)] {
            if !take {
                continue;
            }
            check_budget(host, floor)?;
            calls += 1;
            for found in api::matching_refs(host.client(), prefix)? {
                let Some(oid) = oid_of(&found.object.sha) else {
                    out.dropped.push(Dropped {
                        token: REF_OUT_OF_SCOPE,
                        class: "ref",
                        name: found.name.clone(),
                        detail: "the forge named no commit for this ref".to_string(),
                    });
                    continue;
                };
                let entry = ForgeRef {
                    name: found.name.clone(),
                    oid,
                    kind: Some(found.object.obj_type.clone()),
                };
                if prefix == "refs/heads" {
                    out.branches.push(entry);
                } else {
                    out.tags.push(entry);
                }
            }
        }
        // Everything else the forge advertises is listed too — not to move, but to say so.
        check_budget(host, floor)?;
        calls += 1;
        for found in api::matching_refs(host.client(), "refs")? {
            let name = found.name.as_str();
            if name.starts_with("refs/heads") || name.starts_with("refs/tags") {
                continue;
            }
            out.dropped.push(Dropped {
                token: REF_OUT_OF_SCOPE,
                class: "ref",
                name: found.name.clone(),
                detail: format!(
                    "the forge advertises it and gitiup's ref namespaces do not have a place \
                     for it (the default branch here is {})",
                    default_branch
                        .as_ref()
                        .map(|name| name.to_string())
                        .unwrap_or_else(|| "unnamed".to_string())
                ),
            });
        }
    }

    if want.pulls {
        check_budget(host, floor)?;
        calls += 1;
        let mut closed = 0usize;
        for pull in api::list_pulls(host.client(), "all")? {
            let number = pull.number;
            if pull.state == "closed" && !pull.merged() {
                closed += 1;
                out.dropped.push(Dropped {
                    token: CLOSED_UNMERGED,
                    class: "pull",
                    name: format!("#{number} {}", pull.title),
                    detail: "closed without merging: no branch will ever take this head, so \
                             advertising it as an open change would be a ref that lies"
                        .to_string(),
                });
                continue;
            }
            match Pull::translate(&pull) {
                Ok(pull) => out.pulls.push(pull),
                Err((token, detail)) => out.dropped.push(Dropped {
                    token,
                    class: "pull",
                    name: format!("#{number} {}", pull.title),
                    detail,
                }),
            }
        }
        let _ = closed;
        out.pulls.sort_by_key(|pull| pull.number);
    }

    if want.evidence {
        check_budget(host, floor)?;
        calls += 1;
        for run in api::list_check_runs(host.client(), "", None)? {
            let Ok(subject) = Oid::from_hex(&run.head_sha) else {
                out.dropped.push(Dropped {
                    token: NOT_GITIUP,
                    class: "check-run",
                    name: run.name.clone(),
                    detail: format!(
                        "the forge named '{}' as its commit, which is not an oid",
                        run.head_sha
                    ),
                });
                continue;
            };
            let claims = run
                .external_id
                .as_deref()
                .filter(|hex| !hex.is_empty())
                .and_then(|hex| Oid::from_hex(hex).ok());
            let (bytes, truncated) = match extract_copy(run.output.summary.as_deref()) {
                Some((bytes, truncated)) => (Some(bytes), truncated),
                None => (None, false),
            };
            out.evidence.push(Evidence {
                name: run.name.clone(),
                subject,
                claims,
                bytes,
                truncated,
                conclusion: run.conclusion.clone(),
                details_url: run.details_url.clone(),
                completed: run
                    .status
                    .as_deref()
                    .is_none_or(|status| status == "completed"),
            });
        }
    }

    out.calls = calls;
    out.rate = host.rate_budget();
    Ok(out)
}

/// The git URL of this repository, which is *not* the API URL and is not derivable from it.
///
/// The forge names its own clone URL in the repository document, which is the answer to
/// use when it does; `https://<forge host>/<owner>/<repo>.git` is the fallback for an
/// enterprise server whose document omitted it. A loopback test forge gets nothing sensible
/// from either, which is why the caller may always say `--git-url` and be believed.
pub fn clone_url(host: &GitHubHost) -> Option<String> {
    if let Some(url) = host
        .facts()
        .ok()
        .and_then(|facts| facts.clone_url)
        .filter(|url| !url.is_empty())
    {
        return Some(url);
    }
    let repo = host.repo();
    if repo.forge_host == "github.com" {
        return Some(format!(
            "https://github.com/{}/{}.git",
            repo.owner, repo.repo
        ));
    }
    None
}

/// Stop, cleanly, when the forge has nothing left to give this window.
pub fn check_budget(host: &GitHubHost, floor: u32) -> HostResult<()> {
    let budget = host.rate_budget();
    stop_if_exhausted(&budget, floor)
}

/// The same rule, told without a host (for a caller holding only the budget).
pub fn stop_if_exhausted(budget: &RateBudget, floor: u32) -> HostResult<()> {
    match budget.remaining {
        Some(remaining) if remaining <= floor => Err(HostError::invalid(
            "migration",
            format!(
                "{RATE_TOKEN}: the forge says it has {remaining} call(s) left of its \
                 {}-call window and this run asked to keep a floor of {floor}",
                budget.limit.unwrap_or(0)
            ),
        )
        .with_exit_code(6)
        .with_hint(
            "the run is checkpointed: start it again after the window resets and it picks \
             up where it stopped",
        )),
        _ => Ok(()),
    }
}

/// Whether an error is this module's rate-limit stop (as opposed to some other refusal).
pub fn is_rate_stop(error: &HostError) -> bool {
    error.message().contains(RATE_TOKEN)
}

fn oid_of(hex: &str) -> Option<Oid> {
    if hex.is_empty() {
        None
    } else {
        Oid::from_hex(hex).ok()
    }
}

/// Translate one pull request straight out of the forge's own document (a convenience for
/// a caller that has a [`PullRequest`] and no inventory).
pub fn translate_pull(pull: &PullRequest) -> Result<Pull, (&'static str, String)> {
    Pull::translate(pull)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(
        name: &str,
        claims: Option<&str>,
        bytes: Option<Vec<u8>>,
        truncated: bool,
    ) -> Evidence {
        Evidence {
            name: name.to_string(),
            subject: Oid::hash_bytes(b"subject"),
            claims: claims.map(|hex| Oid::from_hex(hex).unwrap()),
            bytes,
            truncated,
            conclusion: Some("success".into()),
            details_url: None,
            completed: true,
        }
    }

    #[test]
    fn only_a_copy_that_re_hashes_to_its_own_digest_is_an_attestation() {
        let bytes = b"{\"type\":\"gitiup-attestation-1\"}".to_vec();
        let digest = Oid::hash_bytes(&bytes);
        let good = evidence(
            "gitiup/attest",
            Some(&digest.hex()),
            Some(bytes.clone()),
            false,
        );
        assert_eq!(good.reconstructed().unwrap(), bytes.as_slice());

        // Every other answer is a named refusal, and none of them says "close enough".
        let foreign = evidence("build", Some(&digest.hex()), Some(bytes.clone()), false);
        assert_eq!(foreign.reconstructed().unwrap_err().0, NOT_GITIUP);
        let no_digest = evidence("gitiup/attest", None, Some(bytes.clone()), false);
        assert_eq!(no_digest.reconstructed().unwrap_err().0, NO_DIGEST);
        let no_copy = evidence("gitiup/attest", Some(&digest.hex()), None, false);
        assert_eq!(no_copy.reconstructed().unwrap_err().0, NO_COPY);
        let cut = evidence(
            "gitiup/attest",
            Some(&digest.hex()),
            Some(bytes[..8].to_vec()),
            true,
        );
        assert_eq!(cut.reconstructed().unwrap_err().0, COPY_TRUNCATED);
        let wrong = evidence(
            "gitiup/attest",
            Some(&digest.hex()),
            Some(b"somebody else's document".to_vec()),
            false,
        );
        assert_eq!(wrong.reconstructed().unwrap_err().0, COPY_MISMATCH);
    }

    #[test]
    fn a_truncated_copy_is_never_accepted_however_it_decodes() {
        // The mock truncates a base64 copy so it does not decode whole; a caller that
        // repaired it would file bytes that are not the signed document.
        let bytes = b"a".repeat(64);
        let digest = Oid::hash_bytes(&bytes);
        let truncated = evidence(
            "gitiup/attest",
            Some(&digest.hex()),
            Some(bytes.clone()),
            true,
        );
        assert!(truncated.reconstructed().is_err());
    }

    #[test]
    fn a_rate_stop_names_the_token_and_carries_exit_six() {
        let budget = RateBudget {
            limit: Some(5000),
            remaining: Some(3),
            reset_unix: Some(1_800_000_000),
            resource: Some("core".into()),
            requests: 4997,
            waits: 0,
            last_wait_seconds: None,
            throttled: true,
        };
        let error = stop_if_exhausted(&budget, 50).expect_err("under the floor");
        assert!(is_rate_stop(&error));
        assert_eq!(error.exit_code(), 6);
        assert!(error.message().contains(RATE_TOKEN));
        // A budget the client has not seen yet is not an exhausted one.
        assert!(stop_if_exhausted(&RateBudget::default(), 50).is_ok());
        assert!(stop_if_exhausted(&budget, 0).is_ok());
    }

    #[test]
    fn every_token_is_registered_with_a_code() {
        for (token, code) in TOKENS {
            assert_eq!(exit_for(token), *code, "{token}");
            assert!(
                *code == 6 || *code == 8,
                "{token} carries {code}, which is not a refusal code"
            );
        }
        assert_eq!(exit_for("not_a_token"), 6);
    }

    #[test]
    fn a_pull_becomes_a_change_and_a_merged_pull_brings_its_merge_commit() {
        let open: PullRequest = serde_json::from_value(serde_json::json!({
            "number": 7, "state": "open", "title": "Propose", "draft": false,
            "base": {"ref": "main", "sha": base_sha()},
            "head": {"ref": "topic", "sha": head_sha()},
        }))
        .expect("an open pull");
        let open = Pull::translate(&open).expect("it is a change");
        assert_eq!(open.state, ChangeState::Open);
        assert_eq!(open.base_branch, "main");
        assert!(open.merge_commit.is_none(), "an open pull has no merge");

        let merged: PullRequest = serde_json::from_value(serde_json::json!({
            "number": 8, "state": "closed", "title": "Landed", "merged_at": "2026-01-02T03:04:05Z",
            "merge_commit_sha": head_sha(),
            "base": {"ref": "main", "sha": base_sha()},
            "head": {"ref": "topic", "sha": head_sha()},
        }))
        .expect("a merged pull");
        let merged = Pull::translate(&merged).expect("a merged pull is still a change");
        assert_eq!(merged.state, ChangeState::Merged);
        assert_eq!(merged.merge_commit.map(|oid| oid.hex()), Some(head_sha()));
        assert!(
            merged.merged_at_us.unwrap() > 0,
            "the forge's own timestamp, in microseconds"
        );

        // A pull the forge never gave a head for cannot become a change, and says which
        // fact was missing rather than being silently dropped by a caller.
        let headless: PullRequest = serde_json::from_value(serde_json::json!({
            "number": 9, "state": "open", "title": "Broken",
            "base": {"ref": "main", "sha": base_sha()}, "head": {"ref": "topic"},
        }))
        .expect("a pull with no head");
        assert_eq!(Pull::translate(&headless).unwrap_err().0, NO_HEAD);
    }

    fn base_sha() -> String {
        "aa".repeat(20)
    }

    fn head_sha() -> String {
        "bb".repeat(20)
    }

    #[test]
    fn a_scope_line_names_what_was_asked_for() {
        assert_eq!(Want::refs_and_changes().describe(), "branches, tags, pulls");
        assert_eq!(
            Want::everything().describe(),
            "branches, tags, pulls, check-runs"
        );
        assert_eq!(
            Want {
                branches: false,
                tags: false,
                pulls: false,
                evidence: false,
            }
            .describe(),
            "nothing"
        );
    }
}

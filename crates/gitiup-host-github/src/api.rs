//! The endpoints this adapter drives, typed.
//!
//! One function per endpoint, each returning plain structs: this module is the
//! only place in the workspace that knows what a GitHub JSON body looks like, and
//! nothing here knows about refs-as-records or attestations — that translation is
//! [`crate::store`] and [`crate::forge`].
//!
//! Two things are worth knowing before reading it:
//!
//! * **object ids are git SHA-1 hex (40 characters), and a ref can only hold one.**
//!   A gitiup record is addressed by SHA-256 over its bytes, so a ref that points
//!   at a record points at a *pointer commit* instead — see [`crate::store`].
//! * **the git data API creates objects; it does not modify them.** Blobs, trees
//!   and commits are immutable once made, which is what makes the content-addressed
//!   parts of this host honest, and which is also why writing anything is a
//!   three-step dance (blob → tree → commit) followed by one ref move.

use gitiup_host::{HostError, HostResult, Timestamp};
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::codec;
use crate::transport::Response;

/// Largest blob the git-data API will accept (GitHub's own limit is 100 MiB).
pub const MAX_BLOB_BYTES: usize = 100 * 1024 * 1024;

/// Largest check-run output text GitHub stores (65 535 characters).
pub const MAX_CHECK_RUN_OUTPUT_CHARS: usize = 65_535;

/// A ref as the git-data API reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefObject {
    /// Full name, e.g. `refs/heads/main`.
    #[serde(rename = "ref")]
    pub name: String,
    /// The object it points at.
    pub object: RefObjectValue,
}

/// The `{sha, type}` pair attached to a ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefObjectValue {
    /// Git SHA-1 hex.
    pub sha: String,
    /// `commit` or `tag` (`object_type` in some endpoints).
    #[serde(rename = "type", default)]
    pub obj_type: String,
}

/// A git author/committer, as the API spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    /// Display name.
    pub name: String,
    /// Email (GitHub requires one, even for a machine identity).
    pub email: String,
    /// ISO 8601 timestamp; set explicitly for pointer commits so the ref history
    /// says when gitiup moved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// A commit, as returned by `GET /git/commits/{sha}` (flattened).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Its id.
    pub sha: String,
    /// The commit message.
    pub message: String,
    /// Its root tree.
    pub tree_sha: String,
    /// Parents, oldest first.
    pub parents: Vec<String>,
    /// Author name.
    pub author_name: String,
    /// Author timestamp, when it parsed.
    pub author_unix: Option<u64>,
}

/// One entry in a tree listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Path, relative to the tree (recursive listings use `dir/file`).
    pub path: String,
    /// Mode, e.g. `100644`.
    #[serde(default)]
    pub mode: String,
    /// `blob` or `tree`.
    #[serde(rename = "type", default)]
    pub obj_type: String,
    /// The object's id (absent for an entry that is being created inline).
    #[serde(default)]
    pub sha: Option<String>,
    /// Byte size for blobs, when the listing carries it.
    #[serde(default)]
    pub size: Option<u64>,
}

/// A tree, as returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tree {
    /// Its id, when the answer carried one.
    pub sha: Option<String>,
    /// The entries.
    pub entries: Vec<TreeEntry>,
    /// Whether GitHub truncated the listing (it does, at 100 000 entries).
    pub truncated: bool,
}

/// A tree entry as *submitted* to `POST /git/trees`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TreeEntryInput {
    /// Path inside the tree.
    pub path: String,
    /// Mode (`100644` for a normal file).
    pub mode: String,
    /// `blob`.
    #[serde(rename = "type")]
    pub obj_type: String,
    /// An existing blob to point at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// Inline content, for text that does not exist as a blob yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl TreeEntryInput {
    /// Point at an existing blob.
    pub fn blob(path: impl Into<String>, sha: impl Into<String>) -> TreeEntryInput {
        TreeEntryInput {
            path: path.into(),
            mode: "100644".into(),
            obj_type: "blob".into(),
            sha: Some(sha.into()),
            content: None,
        }
    }

    /// Create the blob inline (the API accepts text content on the tree call,
    /// which saves a round trip when the bytes are valid UTF-8).
    pub fn inline(path: impl Into<String>, content: impl Into<String>) -> TreeEntryInput {
        TreeEntryInput {
            path: path.into(),
            mode: "100644".into(),
            obj_type: "blob".into(),
            sha: None,
            content: Some(content.into()),
        }
    }
}

impl Response {
    /// Whether this answer is the "already exists" refusal of `POST /git/refs`.
    pub fn is_already_exists(&self) -> bool {
        self.status == 422 && self.body_mentions(&["already exists", "reference already exists"])
    }

    /// Whether this answer is the "a ref may only move forward" refusal of
    /// `PATCH /git/ref/{ref}` with `force: false`.
    pub fn is_not_fast_forward(&self) -> bool {
        self.status == 422
            && self.body_mentions(&["force", "fast-forward", "fast forward", "non-fast-forward"])
    }
}

fn path(repo: &crate::client::RepoRef, tail: &str) -> String {
    // No `owner/repo//` — the forge answers that with a 404 that looks like a
    // missing repository, and a bare `/repos/owner/repo` is the documented URL for
    // the repository itself.
    if tail.is_empty() {
        return format!("/repos/{}/{}", repo.owner, repo.repo);
    }
    format!("/repos/{}/{}/{tail}", repo.owner, repo.repo)
}

// ---------------------------------------------------------------------------
// refs
// ---------------------------------------------------------------------------

/// Every ref under `prefix`, paginated (`GET /git/matching-refs/`).
pub fn matching_refs(client: &Client, prefix: &str) -> HostResult<Vec<RefObject>> {
    let prefix = prefix.trim_matches('/');
    // The trailing slash is not decoration: `/git/matching-refs` (no prefix at
    // all) is a 404 on the forge, and an empty listing read as "no refs" is how a
    // typo'd remote looks exactly like an empty repository. Every call names a
    // prefix, even if the prefix is the empty string.
    let tail = format!("git/matching-refs/{prefix}");
    match client.get_all::<RefObject>(&path(client.repo(), &tail), &[]) {
        Ok(refs) => Ok(refs),
        // A listing endpoint 404s when the *repository* is not there, never when
        // the prefix matches nothing (that is a 200 and `[]`).
        Err(why) if why.kind() == gitiup_host::HostErrorKind::NotFound => {
            Err(repository_missing(client, "listing refs", &why))
        }
        Err(why) => Err(why),
    }
}

/// The repository itself is not there (or the credential may not see it: a
/// private repository the token cannot read answers 404, not 403, deliberately).
pub fn repository_missing(client: &Client, what: &str, why: &gitiup_host::HostError) -> HostError {
    HostError::not_found(
        "repository",
        format!(
            "{} — gitiup could not {what}: {why}",
            client.repo().full_name()
        ),
    )
    .with_hint(
        "the forge answers 404 for a repository your credential cannot see, so this \
         is either a typo in the remote URL or a token without access to it; check \
         both with `gitiup remote show <name>`",
    )
}

/// One ref, or `None` when it does not exist.
pub fn get_ref(client: &Client, name: &str) -> HostResult<Option<RefObject>> {
    client.get_json(
        &path(
            client.repo(),
            &format!("git/ref/{}", codec::percent_encode(name)),
        ),
        &[],
    )
}

/// Create a ref.
///
/// This is the one ref write GitHub makes *atomic on the server*: creating a ref
/// that already exists is refused, so `Expect::Absent` needs no read first and
/// cannot lose a race.
pub fn create_ref(client: &Client, name: &str, sha: &str) -> HostResult<()> {
    let body = serde_json::json!({ "ref": format!("refs/{}", name.trim_start_matches("refs/")), "sha": sha });
    let response =
        client.post_allowing(&path(client.repo(), "git/refs"), &body, &[201, 422, 409])?;
    if response.status == 201 {
        return Ok(());
    }
    if response.status == 409 || response.is_already_exists() {
        return Err(conflict_ref(name, None));
    }
    Err(client.refusal(&response, &format!("create ref {name}")))
}

/// Move a ref.
///
/// `force: false` is what makes a move conditional: GitHub refuses a move that is
/// not a fast-forward, so a chain append cannot clobber a concurrent one. With
/// `force: true` GitHub moves the ref whatever the current value is, which the
/// adapter only ever does for an [`gitiup_host::Expect::Any`] write.
pub fn move_ref(client: &Client, name: &str, sha: &str, force: bool) -> HostResult<()> {
    let body = serde_json::json!({ "sha": sha, "force": force });
    let response = client.patch_allowing(
        &path(
            client.repo(),
            &format!("git/ref/{}", codec::percent_encode(name)),
        ),
        &body,
        &[200, 422, 409],
    )?;
    if response.status == 200 {
        return Ok(());
    }
    if response.is_not_fast_forward() {
        return Err(crate::client::ref_moved(name, None));
    }
    if response.status == 409 {
        return Err(crate::client::ref_moved(name, None));
    }
    Err(client.refusal(&response, &format!("move ref {name}")))
}

/// Delete a ref; `false` when it was already gone.
pub fn delete_ref(client: &Client, name: &str) -> HostResult<bool> {
    client.delete(&path(
        client.repo(),
        &format!("git/ref/{}", codec::percent_encode(name)),
    ))
}

// ---------------------------------------------------------------------------
// objects
// ---------------------------------------------------------------------------

/// Upload a blob and return its id.
pub fn create_blob(client: &Client, content: &[u8]) -> HostResult<String> {
    if content.len() > MAX_BLOB_BYTES {
        return Err(HostError::invalid(
            "record size",
            format!(
                "{} bytes is over the forge's blob limit of {MAX_BLOB_BYTES}",
                content.len()
            ),
        )
        .with_hint("a large artifact belongs in an artifact store, not in a record"));
    }
    #[derive(Deserialize)]
    struct Created {
        sha: String,
    }
    let body = serde_json::json!({
        "content": codec::encode_base64(content),
        "encoding": "base64",
    });
    let created: Created = client.post(&path(client.repo(), "git/blobs"), &body)?;
    Ok(created.sha)
}

/// Download a blob's bytes.
pub fn get_blob(client: &Client, sha: &str) -> HostResult<Option<Vec<u8>>> {
    #[derive(Deserialize)]
    struct Blob {
        #[serde(default)]
        content: Option<String>,
        #[serde(default)]
        encoding: Option<String>,
        #[serde(default)]
        size: Option<u64>,
        #[serde(default)]
        truncated: Option<bool>,
    }
    let Some(blob): Option<Blob> =
        client.get_json(&path(client.repo(), &format!("git/blobs/{sha}")), &[])?
    else {
        return Ok(None);
    };
    if blob.truncated.unwrap_or(false) {
        return Err(HostError::invalid(
            "stored blob",
            format!("the forge truncated blob {sha} instead of sending it"),
        )
        .with_hint(
            "the git-data API is not a transport for large objects; fetch the object \
             with plain git (this host's refs are ordinary git refs) or store the \
             artifact elsewhere",
        ));
    }
    let Some(content) = blob.content else {
        return Ok(Some(Vec::new()));
    };
    match blob.encoding.as_deref() {
        // `size` is the decoded length; a base64 payload that does not decode to it
        // means the answer is not what it claimed.
        Some("base64") | None => {
            let bytes = codec::decode_base64(&content)
                .map_err(|why| HostError::invalid("stored blob", format!("blob {sha}: {why}")))?;
            if let Some(size) = blob.size
                && size as usize != bytes.len()
            {
                return Err(HostError::invalid(
                    "stored blob",
                    format!(
                        "blob {sha} says it is {size} bytes and carried {} \
                         (the answer was mangled between here and the forge)",
                        bytes.len()
                    ),
                ));
            }
            Ok(Some(bytes))
        }
        Some(other) => Err(HostError::invalid(
            "stored blob",
            format!("blob {sha} arrived with an unknown encoding '{other}'"),
        )),
    }
}

/// Create a tree, optionally on top of `base_tree` (which the server merges, so an
/// append is one call rather than a rewrite of every entry).
pub fn create_tree(
    client: &Client,
    base_tree: Option<&str>,
    entries: &[TreeEntryInput],
) -> HostResult<String> {
    #[derive(Deserialize)]
    struct Created {
        sha: String,
    }
    let mut body = serde_json::json!({ "tree": entries });
    if let Some(base) = base_tree {
        body["base_tree"] = serde_json::Value::String(base.to_string());
    }
    let created: Created = client.post(&path(client.repo(), "git/trees"), &body)?;
    Ok(created.sha)
}

/// Read a tree by its own id or by a commit id (the API resolves either).
pub fn get_tree(client: &Client, sha: &str, recursive: bool) -> HostResult<Option<Tree>> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        sha: Option<String>,
        #[serde(default)]
        tree: Vec<TreeEntry>,
        #[serde(default)]
        truncated: bool,
    }
    let query = [(
        "recursive",
        if recursive {
            "1".to_string()
        } else {
            String::new()
        },
    )];
    let Some(raw): Option<Raw> =
        client.get_json(&path(client.repo(), &format!("git/trees/{sha}")), &query)?
    else {
        return Ok(None);
    };
    Ok(Some(Tree {
        sha: raw.sha,
        entries: raw.tree,
        truncated: raw.truncated,
    }))
}

/// Create a commit. An empty `parents` makes a root commit, which is what the
/// first pointer commit and the first record-chain commit are.
pub fn create_commit(
    client: &Client,
    message: &str,
    tree_sha: &str,
    parents: &[String],
    author: &Person,
) -> HostResult<String> {
    #[derive(Deserialize)]
    struct Created {
        sha: String,
    }
    let body = serde_json::json!({
        "message": message,
        "tree": tree_sha,
        "parents": parents,
        "author": { "name": author.name, "email": author.email, "date": author.date },
    });
    let created: Created = client.post(&path(client.repo(), "git/commits"), &body)?;
    Ok(created.sha)
}

/// Read a commit.
pub fn get_commit(client: &Client, sha: &str) -> HostResult<Option<Commit>> {
    #[derive(Deserialize)]
    struct Raw {
        sha: String,
        commit: RawCommit,
        /// `parents` in a commit answer is `[{"sha": "..."}]`.
        #[serde(default)]
        parents: Vec<RefObjectValue>,
    }
    #[derive(Deserialize)]
    struct RawCommit {
        message: String,
        tree: TreeRef,
        #[serde(default)]
        author: Option<RawPerson>,
    }
    #[derive(Deserialize)]
    struct TreeRef {
        sha: String,
    }
    #[derive(Deserialize)]
    struct RawPerson {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        date: Option<String>,
    }
    let Some(raw): Option<Raw> =
        client.get_json(&path(client.repo(), &format!("git/commits/{sha}")), &[])?
    else {
        return Ok(None);
    };
    let author_name = raw
        .commit
        .author
        .as_ref()
        .and_then(|author| author.name.clone())
        .unwrap_or_default();
    let author_unix = raw
        .commit
        .author
        .as_ref()
        .and_then(|author| author.date.as_deref())
        .and_then(|date| Timestamp::parse(date).ok())
        .map(|stamp| stamp.as_unix());
    Ok(Some(Commit {
        sha: raw.sha,
        message: raw.commit.message,
        tree_sha: raw.commit.tree.sha,
        parents: raw
            .parents
            .iter()
            .map(|parent| parent.sha.clone())
            .collect(),
        author_name,
        author_unix,
    }))
}

/// A GitHub pull request, as much of it as gitiup translates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequest {
    /// The PR number — also the change id, prefixed (`gh-123`).
    pub number: u64,
    /// `open`, `closed`, `merged` (folded by `state` + `merged_at`).
    pub state: String,
    /// Title.
    #[serde(default)]
    pub title: String,
    /// Body, if any.
    #[serde(default)]
    pub body: Option<String>,
    /// Draft flag.
    #[serde(default)]
    pub draft: bool,
    /// Who opened it (`user.login`; a deleted account has none).
    #[serde(default)]
    pub user: Option<PullUser>,
    /// `created_at`, verbatim.
    #[serde(default)]
    pub created_at: Option<String>,
    /// `updated_at`, verbatim — this is the poll cursor for the change feed.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// `merged_at` when merged.
    #[serde(default)]
    pub merged_at: Option<String>,
    /// Web address, for a human.
    #[serde(default)]
    pub html_url: Option<String>,
    /// The branch it wants to land on.
    #[serde(default)]
    pub base: Option<PullRef>,
    /// The branch and commit being proposed.
    #[serde(default)]
    pub head: Option<PullRef>,
    /// Labels, verbatim.
    #[serde(default)]
    pub labels: Vec<Label>,
}

/// A `user`/`actor` block: only the login is ever used, and it is optional because
/// a deleted or organisation account has none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullUser {
    /// The login.
    #[serde(default)]
    pub login: Option<String>,
}

/// The `base`/`head` of a pull request: a branch, a commit, and (for a fork) which
/// repository they are in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRef {
    /// The branch name (`base.ref`).
    #[serde(default, rename = "ref")]
    pub name: Option<String>,
    /// The commit it named when the forge computed the diff.
    #[serde(default)]
    pub sha: Option<String>,
    /// The repository, when the head is a fork's.
    #[serde(default)]
    pub repo: Option<PullRepo>,
}

/// The repository block inside `head`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRepo {
    /// `owner/repo`.
    #[serde(default)]
    pub full_name: Option<String>,
}

/// A label: `{"name": "ready"}`. Kept as the name, shown as it is read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// Its name.
    #[serde(default)]
    pub name: Option<String>,
}

impl PullRequest {
    /// Whether this PR was merged rather than closed.
    pub fn merged(&self) -> bool {
        self.merged_at.is_some()
    }
}

/// List pull requests (`state`: `open`, `closed`, `all`), newest change first.
pub fn list_pulls(client: &Client, state: &str) -> HostResult<Vec<PullRequest>> {
    let query = [
        ("state", state.to_string()),
        ("sort", "updated".to_string()),
        ("direction", "desc".to_string()),
    ];
    client.get_all(&path(client.repo(), "pulls"), &query)
}

/// One pull request.
pub fn get_pull(client: &Client, number: u64) -> HostResult<Option<PullRequest>> {
    client.get_json(&path(client.repo(), &format!("pulls/{number}")), &[])
}

/// Open a pull request (the forge's merge machinery is the one thing a bucket host
/// cannot offer, so on GitHub the adapter *uses* it instead of emulating it).
pub fn create_pull(
    client: &Client,
    title: &str,
    head: &str,
    base: &str,
    body: &str,
    draft: bool,
) -> HostResult<PullRequest> {
    let payload = serde_json::json!({
        "title": title, "head": head, "base": base, "body": body, "draft": draft,
    });
    client.post(&path(client.repo(), "pulls"), &payload)
}

/// Close or reopen a pull request.
pub fn set_pull_state(client: &Client, number: u64, state: &str) -> HostResult<()> {
    client.patch(
        &path(client.repo(), &format!("pulls/{number}")),
        &serde_json::json!({ "state": state }),
    )
}

/// A check run — the forge's own "what CI thought of this commit" record, which
/// gitiup translates into an attestation advertisement (see [`crate::forge`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRun {
    /// The forge's id for it.
    pub id: i64,
    /// Name, e.g. `gitiup/attest`.
    pub name: String,
    /// The commit it is about.
    pub head_sha: String,
    /// The digest gitiup put in here.
    #[serde(default)]
    pub external_id: Option<String>,
    /// `queued`, `in_progress`, `completed`.
    #[serde(default)]
    pub status: Option<String>,
    /// `success`, `failure`, `neutral`, `cancelled`, `timed_out`, `action_required`.
    #[serde(default)]
    pub conclusion: Option<String>,
    /// Where to look (a run report, a store browser).
    #[serde(default)]
    pub details_url: Option<String>,
    /// Web address.
    #[serde(default)]
    pub html_url: Option<String>,
    /// Output text.
    #[serde(default)]
    pub output: CheckRunOutput,
    /// When it was created, verbatim.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// The envelope the check-run listing answers with: `{"total_count": n,
/// "check_runs": [...]}`. Asking for a bare array here is the classic way to miss
/// every check run, because the API never answers with one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRunPage {
    /// The runs themselves.
    #[serde(default)]
    pub check_runs: Vec<CheckRun>,
}

/// The output block of a check run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRunOutput {
    /// Short title.
    #[serde(default)]
    pub title: Option<String>,
    /// Markdown summary — where the attestation copy goes.
    #[serde(default)]
    pub summary: Option<String>,
    /// Plain text body.
    #[serde(default)]
    pub text: Option<String>,
}

/// Check runs for a commit, newest first.
pub fn list_check_runs(
    client: &Client,
    head_sha: &str,
    name: Option<&str>,
) -> HostResult<Vec<CheckRun>> {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    if let Some(name) = name {
        pairs.push(("check_name", name.to_string()));
    }
    // `head_sha` is a filter on the per-commit endpoint; the repository-wide
    // listing used here is filtered locally instead, so both spellings work.
    let page: CheckRunPage = client.get_required(&path(client.repo(), "check-runs"), &pairs)?;
    let mut runs: Vec<CheckRun> = page.check_runs;
    if !head_sha.is_empty() {
        runs.retain(|run| run.head_sha == head_sha);
    }
    if let Some(name) = name {
        runs.retain(|run| run.name == name);
    }
    Ok(runs)
}

/// Publish a check run (completed: a check run that never finishes is worse than
/// none, because a merge gate would wait for it).
pub fn create_check_run(
    client: &Client,
    name: &str,
    head_sha: &str,
    external_id: &str,
    details_url: Option<&str>,
    output: &CheckRunOutput,
) -> HostResult<CheckRun> {
    let mut payload = serde_json::json!({
        "name": name,
        "head_sha": head_sha,
        "external_id": external_id,
        "status": "completed",
        "conclusion": "success",
        "output": {
            "title": output.title.clone().unwrap_or_else(|| "gitiup attestation".into()),
            "summary": output.summary.clone().unwrap_or_default(),
        },
    });
    if let Some(url) = details_url {
        payload["details_url"] = serde_json::Value::String(url.to_string());
    }
    client.post(&path(client.repo(), "check-runs"), &payload)
}

/// The rate-limit snapshot, read from the forge itself (`GET /rate_limit`), which
/// is how `gitiup doctor` can say something before any other call has been made.
pub fn rate_limit_document(client: &Client) -> HostResult<serde_json::Value> {
    #[derive(Deserialize)]
    struct Document {
        resources: serde_json::Value,
    }
    let document: Document = client.get_required("/rate_limit", &[])?;
    Ok(document.resources)
}

/// Repository facts, read once at open time: what the forge says this repository
/// is, and what the credential may do here.
pub fn repository(client: &Client) -> HostResult<Repository> {
    client.get_required(&path(client.repo(), ""), &[])
}

/// What `GET /repos/{owner}/{repo}` says.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Repository {
    /// `owner/repo`.
    pub full_name: String,
    /// Default branch name, without `refs/heads/`.
    #[serde(default)]
    pub default_branch: Option<String>,
    /// Whether this is a fork.
    #[serde(default)]
    pub fork: bool,
    /// Private repositories are invisible to a token that cannot see them, so this
    /// only ever reads true when we are allowed to look.
    #[serde(default)]
    pub private: bool,
    /// What the credential may do here, when the API chose to include it.
    #[serde(default)]
    pub permissions: Option<Permissions>,
}

/// The `permissions` block of a repository document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Permissions {
    /// May push.
    #[serde(default)]
    pub push: bool,
    /// May admin (and therefore rewrite refs).
    #[serde(default)]
    pub admin: bool,
    /// May open pull requests.
    #[serde(default)]
    pub pull: bool,
}

fn conflict_ref(name: &str, expected: Option<gitiup_host::Oid>) -> HostError {
    HostError::conflict(name.to_string(), expected, None).with_hint(
        "the forge already has this ref: re-read it, rebuild the change on top of \
         what is there, and try again",
    )
}
